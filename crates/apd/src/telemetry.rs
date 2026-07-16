//! OpenTelemetry integration: metrics + traces exported over OTLP/HTTP.
//!
//! Design notes:
//! - Instruments are always created against the **global** meter/tracer. When
//!   telemetry is disabled the global providers are the SDK's no-op default, so
//!   every `add()` / span call is a cheap no-op — handlers never branch on a
//!   flag. [`init`] installs real providers only when telemetry is enabled.
//! - The exporter uses the **blocking** reqwest client so the thread-based
//!   batch/periodic processors work without an ambient tokio runtime.
//! - Signals go to `{endpoint}/v1/traces` and `{endpoint}/v1/metrics`
//!   (OTLP/HTTP + protobuf), the standard OpenTelemetry Collector shape.

use std::time::Duration;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::trace::{Span, SpanKind, Status, Tracer};
use opentelemetry::KeyValue;
use opentelemetry_otlp::{MetricExporter, Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;

use crate::config::TelemetryConfig;

const DEFAULT_ENDPOINT: &str = "http://localhost:4318";
const SCOPE: &str = "apd";

/// Live provider handles, kept so telemetry can be flushed + shut down cleanly
/// at process exit. Dropping without `shutdown()` risks losing buffered spans.
pub struct Telemetry {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
}

impl Telemetry {
    /// Flush and stop the exporters. Best-effort; errors are logged, not fatal.
    pub fn shutdown(self) {
        if let Err(e) = self.tracer_provider.shutdown() {
            eprintln!("telemetry: tracer shutdown: {e}");
        }
        if let Err(e) = self.meter_provider.shutdown() {
            eprintln!("telemetry: meter shutdown: {e}");
        }
    }
}

/// Install OTLP metric + trace providers globally when enabled. Returns
/// `Ok(None)` when telemetry is disabled (the global no-op providers stay in
/// place). Fails fast on a malformed endpoint or exporter build error.
pub fn init(cfg: &TelemetryConfig, service_version: &str) -> Result<Option<Telemetry>, String> {
    if !cfg.enabled {
        return Ok(None);
    }
    let base = cfg
        .endpoint
        .as_deref()
        .unwrap_or(DEFAULT_ENDPOINT)
        .trim_end_matches('/')
        .to_string();
    let service_name = cfg
        .service_name
        .clone()
        .unwrap_or_else(|| SCOPE.to_string());

    let resource = Resource::builder()
        .with_service_name(service_name)
        .with_attribute(KeyValue::new(
            "service.version",
            service_version.to_string(),
        ))
        .build();

    // ---- traces ----
    let span_exporter = SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(format!("{base}/v1/traces"))
        .build()
        .map_err(|e| format!("OTLP span exporter: {e}"))?;
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(span_exporter)
        .build();
    global::set_tracer_provider(tracer_provider.clone());

    // ---- metrics ----
    let metric_exporter = MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(format!("{base}/v1/metrics"))
        .build()
        .map_err(|e| format!("OTLP metric exporter: {e}"))?;
    let interval = Duration::from_secs(cfg.metric_interval_secs.unwrap_or(30).max(1));
    let reader = PeriodicReader::builder(metric_exporter)
        .with_interval(interval)
        .build();
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();
    global::set_meter_provider(meter_provider.clone());

    Ok(Some(Telemetry {
        tracer_provider,
        meter_provider,
    }))
}

/// Application metric instruments. Bound to the global meter; no-ops when
/// telemetry is disabled. Cloneable/shareable via the `App`.
#[derive(Clone)]
pub struct Metrics {
    /// Enrollments, dimensioned by method + assurance + result.
    pub enroll: Counter<u64>,
    /// Agent-token issuance/refresh, dimensioned by result.
    pub agent_token: Counter<u64>,
    /// Sub-agent token issuance, dimensioned by result.
    pub subagent_token: Counter<u64>,
    /// HTTP-signature / assertion verification failures, by route.
    pub verify_fail: Counter<u64>,
    /// All requests, by route + status class.
    pub requests: Counter<u64>,
    /// Request duration seconds, by route.
    pub request_duration: Histogram<f64>,
}

impl Metrics {
    pub fn new() -> Metrics {
        let m = global::meter(SCOPE);
        Metrics {
            enroll: m
                .u64_counter("apd.enroll.total")
                .with_description("Agent enrollments accepted, by method/assurance/result")
                .build(),
            agent_token: m
                .u64_counter("apd.agent_token.total")
                .with_description("Agent tokens issued (refresh), by result")
                .build(),
            subagent_token: m
                .u64_counter("apd.subagent_token.total")
                .with_description("Sub-agent tokens issued, by result")
                .build(),
            verify_fail: m
                .u64_counter("apd.verify_fail.total")
                .with_description("Signature/assertion verification failures, by route")
                .build(),
            requests: m
                .u64_counter("apd.requests.total")
                .with_description("HTTP requests handled, by route and status class")
                .build(),
            request_duration: m
                .f64_histogram("apd.request.duration")
                .with_unit("s")
                .with_description("Request handling duration in seconds, by route")
                .build(),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics::new()
    }
}

/// Start a SERVER span for a request. No-op span when telemetry is disabled.
pub fn request_span(method: &str, route: &str) -> global::BoxedSpan {
    let tracer = global::tracer(SCOPE);
    let mut span = tracer
        .span_builder(format!("{method} {route}"))
        .with_kind(SpanKind::Server)
        .start(&tracer);
    span.set_attribute(KeyValue::new("http.request.method", method.to_string()));
    span.set_attribute(KeyValue::new("http.route", route.to_string()));
    span
}

/// Record the request outcome on the span and close it.
pub fn end_request_span(mut span: global::BoxedSpan, status: u16) {
    span.set_attribute(KeyValue::new("http.response.status_code", status as i64));
    if status >= 500 {
        span.set_status(Status::error("server error"));
    } else {
        span.set_status(Status::Ok);
    }
    span.end();
}

/// Collapse a concrete path to a low-cardinality route template so metric and
/// trace dimensions don't explode on per-agent identifiers.
pub fn route_template(path: &str) -> &'static str {
    match path {
        "/enroll" => "/enroll",
        "/agent-token" => "/agent-token",
        "/subagent-token" => "/subagent-token",
        "/subscribe" => "/subscribe",
        "/events" => "/events",
        "/inbox" => "/inbox",
        "/healthz" => "/healthz",
        "/.well-known/aauth-agent.json" => "/.well-known/aauth-agent.json",
        "/.well-known/jwks.json" => "/.well-known/jwks.json",
        "/admin/enrollment-tokens" => "/admin/enrollment-tokens",
        "/admin/agents" => "/admin/agents",
        "/admin/allowed-keys" => "/admin/allowed-keys",
        p if p.starts_with("/subscriptions/") => "/subscriptions/{eid}",
        p if p.starts_with("/admin/allowed-keys/") => "/admin/allowed-keys/{jkt}",
        p if p.starts_with("/admin/agents/") && p.ends_with("/revoke") => {
            "/admin/agents/{id}/revoke"
        }
        p if p.starts_with("/admin/agents/") && p.ends_with("/reinstate") => {
            "/admin/agents/{id}/reinstate"
        }
        p if p.starts_with("/admin/agents/") => "/admin/agents/{id}",
        _ => "other",
    }
}

/// Status class label ("2xx".."5xx") for a low-cardinality metric dimension.
pub fn status_class(status: u16) -> &'static str {
    match status / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}
