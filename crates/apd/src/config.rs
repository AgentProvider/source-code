//! Configuration: a JSON file plus environment overrides.
//!
//! Kept to JSON deliberately (serde_json is already a dependency; no TOML
//! parser needed). `apd example-config` prints a commented starting point.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The AP's server identifier, e.g. "https://ap.example".
    /// This exact URL must serve /.well-known/aauth-agent.json.
    pub issuer: String,

    /// Listen address, e.g. "127.0.0.1:8420" or "0.0.0.0:8420".
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Path to the signing keys file (see `apd keygen`).
    #[serde(default = "default_keys_file")]
    pub keys_file: String,

    #[serde(default)]
    pub storage: StorageConfig,

    /// Agent token lifetime in seconds (max 86400 per spec; default 1h).
    #[serde(default = "default_agent_token_ttl")]
    pub agent_token_ttl_secs: u64,

    /// Subscribe token registration-window lifetime (default 24h).
    #[serde(default = "default_subscribe_token_ttl")]
    pub subscribe_token_ttl_secs: u64,

    /// HTTP signature `created` validity window, seconds (default 60).
    #[serde(default = "default_signature_window")]
    pub signature_window_secs: u64,

    /// Maximum accepted naming-JWT lifetime (exp - iat), seconds.
    #[serde(default = "default_naming_jwt_max")]
    pub naming_jwt_max_lifetime_secs: u64,

    #[serde(default)]
    pub enrollment: EnrollmentConfig,

    /// Admin API bearer token. Prefer the APD_ADMIN_TOKEN env var.
    /// If neither this nor `admin_oidc` is set, the /admin API is disabled.
    #[serde(default)]
    pub admin_token: Option<String>,

    /// Enterprise SSO for the admin API: accept an OIDC access/ID token from
    /// the organisation's identity provider instead of (or alongside) the
    /// shared bearer token.
    ///
    /// A shared token has no operator identity — every action is
    /// indistinguishable, it cannot be revoked for one person, and offboarding
    /// means rotating it for everyone. An IdP token names who acted.
    #[serde(default)]
    pub admin_oidc: Option<AdminOidcConfig>,

    /// Allow the `ps` in a token request body to differ from the enrollment's.
    #[serde(default = "default_true")]
    pub allow_ps_override: bool,

    #[serde(default)]
    pub metadata: MetadataConfig,

    #[serde(default)]
    pub events: EventsConfig,

    /// DEVELOPMENT ONLY. Accepts an http:// issuer (and ports), allows
    /// outbound fetches over http and to private/loopback addresses.
    /// Never enable in production.
    #[serde(default)]
    pub insecure_dev_mode: bool,

    /// Maximum request body size in bytes.
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,

    /// Hosts explicitly admitted as cross-origin JWKS hosts when verifying
    /// foreign tokens (event deliveries): a resource's metadata may point
    /// `jwks_uri` at a different host than its issuer (e.g. a CDN). Empty
    /// (default) means same-origin JWKS only, per the Signature-Key draft's
    /// requirement that cross-origin JWKS URLs need explicit deployment
    /// admission. List bare hostnames, e.g. ["jwks.cdn.example"].
    #[serde(default)]
    pub jwks_cross_origin_hosts: Vec<String>,

    /// Append structured JSON audit events (enrollments, issuance, revocation,
    /// event deliveries) to this file, in addition to stderr.
    #[serde(default)]
    pub audit_log_file: Option<String>,

    #[serde(default)]
    pub telemetry: TelemetryConfig,

    #[serde(default)]
    pub revocation: RevocationConfig,

    /// The `@authority` value signed requests must carry. Defaults to the
    /// issuer's host (plus port when it is not the scheme default).
    ///
    /// Set this only when a TLS-terminating proxy rewrites the `Host` header
    /// and cannot be configured to preserve it — agents sign `@authority`, so
    /// it must match what the agent signed, not what the proxy forwarded.
    #[serde(default)]
    pub expected_authority: Option<String>,
}

/// OpenTelemetry (metrics + traces) exported over OTLP/HTTP. Disabled by
/// default. When enabled, signals are POSTed to `{endpoint}/v1/traces` and
/// `{endpoint}/v1/metrics` (OTLP/HTTP + protobuf), the standard Collector shape.
/// Enterprise SSO for the admin API.
///
/// The admin API is machine-facing — operators reach it with `curl`, a script,
/// or CI — so this is bearer-token validation, not a browser redirect flow.
/// The operator obtains a token from the IdP however their organisation
/// already does, and presents it as `Authorization: Bearer <jwt>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminOidcConfig {
    /// The IdP's issuer URL. Discovery resolves the JWKS from it, and the
    /// token's `iss` must equal it exactly.
    pub issuer: String,

    /// Required `aud`. Set it: a token minted for another application at the
    /// same IdP would otherwise be accepted here.
    pub audience: String,

    /// Claim path -> matcher, using the same syntax as trusted issuers
    /// (exact, array-of-allowed, or trailing-`*` prefix). This is the
    /// authorization gate — without at least one entry, every employee with an
    /// IdP account could administer the provider.
    #[serde(default)]
    pub required_claims: std::collections::BTreeMap<String, serde_json::Value>,

    /// Which claim names the operator in the audit log. Default `sub`, but
    /// `email` or `preferred_username` reads better in a review.
    #[serde(default = "default_principal_claim")]
    pub principal_claim: String,

    /// Explicit JWKS URL, skipping discovery. Rarely needed.
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

fn default_principal_claim() -> String {
    "sub".to_string()
}

/// Whether, and how, the AP tells a Person Server that an agent's tokens are
/// revoked (protocol spec, Token Revocation). Local revocation always happens;
/// this only controls the outbound notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationConfig {
    /// Call the agent's PS `revocation_endpoint` on revoke. Requires the
    /// enrollment to carry a `ps`. Default: true.
    #[serde(default = "default_true")]
    pub notify_ps: bool,
    /// Cap on outstanding token identifiers tracked per agent. Entries expire
    /// with their token, so this only bounds a pathological refresh loop.
    #[serde(default = "default_max_tracked")]
    pub max_tracked_tokens: usize,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        RevocationConfig {
            notify_ps: true,
            max_tracked_tokens: default_max_tracked(),
        }
    }
}

fn default_max_tracked() -> usize {
    64
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Master switch. Also settable via `APD_TELEMETRY_ENABLED=1`.
    #[serde(default)]
    pub enabled: bool,
    /// OTLP/HTTP base endpoint, e.g. "http://otel-collector:4318". Default
    /// "http://localhost:4318". Env: `OTEL_EXPORTER_OTLP_ENDPOINT`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// `service.name` in the emitted resource. Default "apd".
    /// Env: `OTEL_SERVICE_NAME`.
    #[serde(default)]
    pub service_name: Option<String>,
    /// Metric export interval in seconds (default 30).
    #[serde(default)]
    pub metric_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// "memory" (default), "file", or "redis".
    #[serde(default = "default_backend")]
    pub backend: String,
    /// File path for the "file" backend.
    #[serde(default)]
    pub path: Option<String>,
    /// Redis address "host:port" for the "redis" backend
    /// (plain TCP; run on a trusted network / localhost / TLS tunnel).
    #[serde(default)]
    pub redis_addr: Option<String>,
    /// Key prefix for the "redis" backend.
    #[serde(default = "default_prefix")]
    pub key_prefix: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            backend: default_backend(),
            path: None,
            redis_addr: None,
            key_prefix: default_prefix(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentConfig {
    /// Legacy single-method form: "token" or "open". Superseded by `methods`;
    /// still accepted for backwards compatibility.
    #[serde(default)]
    pub mode: Option<String>,
    /// Enabled enrollment methods, any of: "token", "federated", "allowlist",
    /// "open". Default: ["token"] (or the legacy `mode` when set).
    /// Evaluation order per request: a presented assertion, then a presented
    /// enrollment token, then the thumbprint allow-list, then open. A
    /// presented-but-invalid credential is a hard failure (no fall-through).
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    /// Default PS bound into agent tokens when the enrollment doesn't set one.
    #[serde(default)]
    pub default_ps: Option<String>,
    /// Trusted assertion issuers for the "federated" method.
    #[serde(default)]
    pub trusted_issuers: Vec<TrustedIssuer>,
    /// Predefined **static enrollment tokens** for the "token" method — a
    /// dev/staging convenience so agents can enroll with a known token
    /// (docker-compose, CI, local runs) without a runtime mint step. Unlike
    /// minted tokens they are REUSABLE and live as long as the config; treat
    /// them like any shared dev credential (≥16 chars enforced; a startup
    /// warning + audit event announce their presence). The
    /// `APD_STATIC_ENROLL_TOKEN` env var appends one entry.
    #[serde(default)]
    pub static_tokens: Vec<StaticEnrollToken>,
}

/// A predefined static enrollment token (dev/staging convenience).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticEnrollToken {
    /// The token value agents present as `enrollment_token`. Minimum 16 chars.
    pub token: String,
    /// PS bound into agent tokens for enrollments made with this token.
    #[serde(default)]
    pub ps: Option<String>,
    /// Label recorded on enrollments made with this token.
    #[serde(default)]
    pub label: Option<String>,
}

impl EnrollmentConfig {
    /// The effective method set (resolves the legacy `mode` field).
    pub fn effective_methods(&self) -> Vec<String> {
        if let Some(methods) = &self.methods {
            return methods.clone();
        }
        match self.mode.as_deref() {
            Some(m) => vec![m.to_string()],
            None => vec!["token".to_string()],
        }
    }

    pub fn method_enabled(&self, method: &str) -> bool {
        self.effective_methods().iter().any(|m| m == method)
    }
}

/// A trusted issuer of federated enrollment assertions.
///
/// Every field here narrows what an assertion may claim. The defaults are the
/// strict ones: an issuer with no `required_claims` still cannot mint agents
/// beyond its own `issuer`/`audience` pair, and `embed_claims` can never write
/// a claim the provider itself controls.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedIssuer {
    /// Unique operator-chosen name (used in logs/audit).
    pub name: String,
    /// Key-resolution type: "oidc" (OIDC discovery), "jwks_uri" (direct JWKS
    /// URL), "jwks_file" (JWKS loaded from disk), "jwks" (inline JWKS), or
    /// "x5c" (JWS header certificate chain validated to `ca_bundle_file`).
    #[serde(rename = "type")]
    pub issuer_type: String,
    /// The `iss` value assertions must carry (exact match). For OIDC this is
    /// the issuer URL (paths allowed, e.g. EKS issuers); for x5c it is an
    /// operator-chosen identifier the assertion payload must repeat.
    pub issuer: String,
    /// Required audience (`aud` must contain it). Default: apd's own issuer URL.
    #[serde(default)]
    pub audience: Option<String>,
    /// Direct JWKS URL ("jwks_uri" type; optional override for "oidc").
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Path to a JWKS file ("jwks_file" type). Loaded at startup.
    #[serde(default)]
    pub jwks_file: Option<String>,
    /// Inline JWKS ("jwks" type).
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// PEM bundle of trusted CA roots ("x5c" type). Loaded at startup.
    #[serde(default)]
    pub ca_bundle_file: Option<String>,
    /// Optional CRL file (PEM or DER, may contain several) for x5c revocation.
    #[serde(default)]
    pub crl_file: Option<String>,
    /// Patterns the leaf certificate's DNS/URI SANs must match (x5c type).
    /// Exact strings or a trailing `*` prefix wildcard. Any-of semantics.
    #[serde(default)]
    pub required_sans: Vec<String>,
    /// Claim requirements: claim path -> matcher (exact string, array of
    /// allowed strings, or string with trailing `*` prefix wildcard).
    #[serde(default)]
    pub required_claims: serde_json::Map<String, serde_json::Value>,
    /// Assertion claims copied into every agent token issued for enrollments
    /// from this issuer: assertion claim path -> agent-token claim name
    /// (lowercase [a-z0-9_], non-reserved).
    #[serde(default)]
    pub embed_claims: serde_json::Map<String, serde_json::Value>,
    /// Require the assertion to bind the enrolling key via cnf.jwk / cnf.jkt.
    #[serde(default)]
    pub require_cnf_binding: bool,
    /// Enforce single-use `jti`. Default: true when the assertion carries no
    /// cnf binding (bounds token exfiltration to first use), false when
    /// cnf-bound (replay is harmless).
    #[serde(default)]
    pub single_use_jti: Option<bool>,
    /// Pin the Person Server for enrollments from this issuer.
    #[serde(default)]
    pub ps: Option<String>,
    /// Label recorded on enrollments from this issuer.
    #[serde(default)]
    pub label: Option<String>,
    /// Allow http/private-network egress when fetching THIS issuer's keys
    /// (on-prem issuers). Explicit per-issuer opt-out of SSRF hardening.
    #[serde(default)]
    pub allow_insecure_egress: bool,
    /// SPIFFE trust domain for the "spiffe" type (JWT-SVID). Accepts
    /// "example.org" or "spiffe://example.org"; the assertion `sub` must be a
    /// SPIFFE ID under this domain. The bundle keys come from jwks / jwks_file
    /// / jwks_uri (the SPIFFE JWT bundle).
    #[serde(default)]
    pub trust_domain: Option<String>,
    /// Override the assurance tier stamped into agent tokens for enrollments
    /// from this issuer. Defaults by type: x5c/spiffe → "high", others →
    /// "medium". Lowercase [a-z0-9_], ≤32 chars.
    #[serde(default)]
    pub assurance: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub logo_dark_uri: Option<String>,
    #[serde(default)]
    pub documentation_uri: Option<String>,
    #[serde(default)]
    pub tos_uri: Option<String>,
    #[serde(default)]
    pub policy_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsConfig {
    /// Enable AAuth Events (subscribe tokens, /events endpoint, inbox).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How long undelivered inbox events are retained, seconds.
    #[serde(default = "default_inbox_ttl")]
    pub inbox_ttl_secs: u64,
    /// Max pending events per agent (oldest dropped beyond this).
    #[serde(default = "default_inbox_max")]
    pub max_pending_per_agent: usize,
    /// Max event payload size accepted at /events, bytes.
    #[serde(default = "default_max_payload")]
    pub max_payload_bytes: usize,
}

impl Default for EventsConfig {
    fn default() -> Self {
        serde_json::from_str("{}").unwrap()
    }
}

fn default_listen() -> String {
    "127.0.0.1:8420".into()
}
fn default_keys_file() -> String {
    "apd-keys.json".into()
}
fn default_backend() -> String {
    "memory".into()
}
fn default_prefix() -> String {
    "apd:".into()
}
fn default_agent_token_ttl() -> u64 {
    3600
}
fn default_subscribe_token_ttl() -> u64 {
    86400
}
fn default_signature_window() -> u64 {
    60
}
fn default_naming_jwt_max() -> u64 {
    300
}
fn default_inbox_ttl() -> u64 {
    7 * 24 * 3600
}
fn default_inbox_max() -> usize {
    1000
}
fn default_max_payload() -> usize {
    64 * 1024
}
fn default_max_body() -> usize {
    64 * 1024
}
fn default_true() -> bool {
    true
}

impl TrustedIssuer {
    /// Present the admin IdP as a trusted issuer, so key resolution reuses the
    /// runtime built for federated enrollment rather than duplicating OIDC
    /// discovery, egress admission and key caching for one extra caller.
    pub fn for_admin_idp(o: &AdminOidcConfig) -> TrustedIssuer {
        TrustedIssuer {
            name: "admin-idp".to_string(),
            issuer_type: "oidc".to_string(),
            issuer: o.issuer.clone(),
            audience: Some(o.audience.clone()),
            jwks_uri: o.jwks_uri.clone(),
            ..TrustedIssuer::default()
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read config {path}: {e}"))?;
        let mut cfg: Config =
            serde_json::from_str(&raw).map_err(|e| format!("invalid config {path}: {e}"))?;
        cfg.apply_env();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("APD_ISSUER") {
            self.issuer = v;
        }
        if let Ok(v) = std::env::var("APD_LISTEN") {
            self.listen = v;
        }
        if let Ok(v) = std::env::var("APD_KEYS_FILE") {
            self.keys_file = v;
        }
        if let Ok(v) = std::env::var("APD_ADMIN_TOKEN") {
            self.admin_token = Some(v);
        }
        if let Ok(v) = std::env::var("APD_REDIS_ADDR") {
            self.storage.backend = "redis".into();
            self.storage.redis_addr = Some(v);
        }
        if let Ok(v) = std::env::var("APD_STATIC_ENROLL_TOKEN") {
            self.enrollment.static_tokens.push(StaticEnrollToken {
                token: v,
                ps: None,
                label: Some("env".into()),
            });
        }
        if let Ok(v) = std::env::var("APD_TELEMETRY_ENABLED") {
            self.telemetry.enabled = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Ok(v) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
            self.telemetry.endpoint.get_or_insert(v);
        }
        if let Ok(v) = std::env::var("OTEL_SERVICE_NAME") {
            self.telemetry.service_name.get_or_insert(v);
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        aauth_core::ident::validate_server_identifier(&self.issuer, self.insecure_dev_mode)
            .map_err(|_| {
                format!(
                    "issuer '{}' is not a valid AAuth server identifier \
                     (https://host, lowercase, no port/path). \
                     Set insecure_dev_mode=true for local http development.",
                    self.issuer
                )
            })?;
        if let Some(o) = &self.admin_oidc {
            // An OIDC issuer is not an AAuth server identifier, and must not be
            // validated as one. AAuth requires a bare origin, but identity
            // providers routinely put the issuer on a path — an Okta custom
            // authorization server is `https://acme.okta.com/oauth2/default`,
            // Entra is `https://login.microsoftonline.com/<tenant>/v2.0`,
            // Keycloak is `https://host/realms/<realm>`. Requiring an origin
            // here would leave only Okta's *org* server, which is precisely the
            // one that cannot mint a token with our audience. So: same rule as
            // a trusted enrollment issuer — an https URL, and http only when
            // running in development mode.
            if !o.issuer.starts_with("https://")
                && !(self.insecure_dev_mode && o.issuer.starts_with("http://"))
            {
                return Err(format!(
                    "admin_oidc.issuer '{}' must be an https URL \
                     (set insecure_dev_mode=true for local http development)",
                    o.issuer
                ));
            }
            // Discovery appends to the issuer, and the token's `iss` is
            // compared to it exactly, so a trailing slash silently breaks both.
            if o.issuer.ends_with('/') {
                return Err(format!(
                    "admin_oidc.issuer '{}' must not end with a slash: it is compared to the \
                     token's iss exactly, and discovery is appended to it",
                    o.issuer
                ));
            }
            if o.audience.trim().is_empty() {
                return Err(
                    "admin_oidc.audience must be set: without it, a token the IdP \
                            minted for any other application would administer this provider"
                        .into(),
                );
            }
            // Authenticating against the company IdP proves employment, not
            // entitlement. An empty gate would make every account with a login
            // an administrator, which is almost never intended and is silent.
            if o.required_claims.is_empty() {
                return Err("admin_oidc.required_claims must not be empty: it is the \
                            authorization gate, and without it every account at the identity \
                            provider could administer this provider. Use a group or role \
                            claim, e.g. {\"groups\": \"apd-admins\"}"
                    .into());
            }
            for name in o.required_claims.keys() {
                if name.trim().is_empty() {
                    return Err("admin_oidc.required_claims has an empty claim name".into());
                }
            }
        }

        if self.agent_token_ttl_secs == 0
            || self.agent_token_ttl_secs > aauth_core::tokens::AGENT_TOKEN_MAX_TTL_SECS
        {
            return Err(format!(
                "agent_token_ttl_secs must be 1..={} (spec: agent tokens SHOULD NOT exceed 24h)",
                aauth_core::tokens::AGENT_TOKEN_MAX_TTL_SECS
            ));
        }
        match self.storage.backend.as_str() {
            "memory" => {}
            "file" => {
                if self.storage.path.is_none() {
                    return Err("storage.path is required for the file backend".into());
                }
            }
            "redis" => {
                if self.storage.redis_addr.is_none() {
                    return Err("storage.redis_addr is required for the redis backend".into());
                }
            }
            other => return Err(format!("unknown storage backend '{other}'")),
        }
        let methods = self.enrollment.effective_methods();
        if methods.is_empty() {
            return Err("enrollment.methods must not be empty".into());
        }
        for m in &methods {
            match m.as_str() {
                "token" | "open" | "federated" | "allowlist" => {}
                other => return Err(format!("unknown enrollment method '{other}'")),
            }
        }
        if methods.iter().any(|m| m == "federated") && self.enrollment.trusted_issuers.is_empty() {
            return Err(
                "enrollment method 'federated' requires at least one enrollment.trusted_issuers entry"
                    .into(),
            );
        }
        if !methods.iter().any(|m| m == "federated") && !self.enrollment.trusted_issuers.is_empty()
        {
            return Err(
                "enrollment.trusted_issuers is set but the 'federated' method is not enabled"
                    .into(),
            );
        }
        let mut names = std::collections::HashSet::new();
        for issuer in &self.enrollment.trusted_issuers {
            validate_trusted_issuer(issuer, self.insecure_dev_mode)?;
            if !names.insert(issuer.name.clone()) {
                return Err(format!("duplicate trusted issuer name '{}'", issuer.name));
            }
        }
        if !self.enrollment.static_tokens.is_empty() && !methods.iter().any(|m| m == "token") {
            return Err(
                "enrollment.static_tokens is set but the 'token' method is not enabled".into(),
            );
        }
        for st in &self.enrollment.static_tokens {
            if st.token.len() < 16 {
                return Err(
                    "enrollment.static_tokens entries must be at least 16 characters \
                     (they are reusable shared credentials — make them unguessable)"
                        .into(),
                );
            }
            if let Some(ps) = &st.ps {
                aauth_core::ident::validate_server_identifier(ps, self.insecure_dev_mode).map_err(
                    |_| "enrollment.static_tokens: ps is not a valid server identifier".to_string(),
                )?;
            }
        }
        if let Some(ps) = &self.enrollment.default_ps {
            aauth_core::ident::validate_server_identifier(ps, self.insecure_dev_mode).map_err(
                |_| "enrollment.default_ps is not a valid server identifier".to_string(),
            )?;
        }
        if self.telemetry.enabled {
            if let Some(ep) = &self.telemetry.endpoint {
                if !ep.starts_with("http://") && !ep.starts_with("https://") {
                    return Err("telemetry.endpoint must be an http(s) OTLP/HTTP URL, e.g. \
                         http://otel-collector:4318"
                        .into());
                }
            }
        }
        Ok(())
    }

    /// The domain part used in agent identifiers (issuer host).
    pub fn agent_domain(&self) -> String {
        aauth_core::ident::host_of(&self.issuer).expect("validated issuer")
    }

    /// The `@authority` a signed request must be addressed to.
    ///
    /// `@authority` is a mandated covered component because it "binds the
    /// signature to the target host, preventing cross-host replay". That only
    /// holds if the verifier checks the authority is its own: a verifier that
    /// merely rebuilds the signature base from the received `Host` will accept
    /// a signature bound to any host, because the base it builds matches.
    pub fn required_authority(&self) -> String {
        if let Some(a) = &self.expected_authority {
            return a.to_ascii_lowercase();
        }
        let https = self.issuer.starts_with("https://");
        let rest = self
            .issuer
            .strip_prefix("https://")
            .or_else(|| self.issuer.strip_prefix("http://"))
            .unwrap_or(&self.issuer);
        let hostport = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        let hostport = hostport.to_ascii_lowercase();
        // Normalize away the scheme default port, as RFC 9421 §2.2.3 signers do.
        let default = if https { ":443" } else { ":80" };
        hostport
            .strip_suffix(default)
            .map(|h| h.to_string())
            .unwrap_or(hostport)
    }
}

/// Claim names an issuer's `embed_claims` may not target (registered AAuth /
/// JWT claims the AP controls).
pub const RESERVED_TOKEN_CLAIMS: [&str; 10] = [
    "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "cnf", "dwk", "ps",
];

/// Assurance tier value policy: short lowercase token.
pub fn valid_assurance(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn valid_embed_target(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !RESERVED_TOKEN_CLAIMS.contains(&name)
        && name != "parent_agent"
}

fn validate_trusted_issuer(issuer: &TrustedIssuer, _insecure_dev: bool) -> Result<(), String> {
    let ctx = format!("trusted issuer '{}'", issuer.name);
    if issuer.name.is_empty() {
        return Err("trusted issuer name must not be empty".into());
    }
    if issuer.issuer.is_empty() {
        return Err(format!("{ctx}: issuer must not be empty"));
    }
    match issuer.issuer_type.as_str() {
        "oidc" => {
            if !issuer.issuer.starts_with("https://")
                && !(issuer.allow_insecure_egress && issuer.issuer.starts_with("http://"))
            {
                return Err(format!(
                    "{ctx}: oidc issuer must be an https URL \
                     (or http with allow_insecure_egress)"
                ));
            }
        }
        "jwks_uri" => {
            if issuer.jwks_uri.is_none() {
                return Err(format!("{ctx}: jwks_uri is required for type jwks_uri"));
            }
        }
        "jwks_file" => {
            if issuer.jwks_file.is_none() {
                return Err(format!("{ctx}: jwks_file is required for type jwks_file"));
            }
        }
        "jwks" => {
            if issuer.jwks.is_none() {
                return Err(format!("{ctx}: inline jwks is required for type jwks"));
            }
        }
        "x5c" => {
            if issuer.ca_bundle_file.is_none() {
                return Err(format!("{ctx}: ca_bundle_file is required for type x5c"));
            }
        }
        "spiffe" => {
            let td = issuer
                .trust_domain
                .as_deref()
                .ok_or_else(|| format!("{ctx}: trust_domain is required for type spiffe"))?;
            let domain = td.strip_prefix("spiffe://").unwrap_or(td);
            if domain.is_empty() || domain.contains('/') {
                return Err(format!(
                    "{ctx}: trust_domain must be a bare domain or spiffe://<domain> \
                     (no path), got '{td}'"
                ));
            }
            let sources = [
                issuer.jwks.is_some(),
                issuer.jwks_file.is_some(),
                issuer.jwks_uri.is_some(),
            ]
            .iter()
            .filter(|b| **b)
            .count();
            if sources != 1 {
                return Err(format!(
                    "{ctx}: type spiffe requires exactly one JWT-bundle source \
                     (jwks, jwks_file, or jwks_uri)"
                ));
            }
        }
        other => return Err(format!("{ctx}: unknown type '{other}'")),
    }
    if !issuer.required_sans.is_empty() && issuer.issuer_type != "x5c" {
        return Err(format!("{ctx}: required_sans only applies to type x5c"));
    }
    if issuer.trust_domain.is_some() && issuer.issuer_type != "spiffe" {
        return Err(format!("{ctx}: trust_domain only applies to type spiffe"));
    }
    if let Some(a) = &issuer.assurance {
        if !valid_assurance(a) {
            return Err(format!(
                "{ctx}: assurance '{a}' must be lowercase [a-z0-9_], 1..=32 chars"
            ));
        }
    }
    for (path, matcher) in &issuer.required_claims {
        if path.is_empty() {
            return Err(format!("{ctx}: empty required_claims path"));
        }
        let ok = matcher.is_string()
            || matcher
                .as_array()
                .map(|a| !a.is_empty() && a.iter().all(|v| v.is_string()))
                .unwrap_or(false);
        if !ok {
            return Err(format!(
                "{ctx}: required_claims['{path}'] must be a string or array of strings"
            ));
        }
    }
    for (path, target) in &issuer.embed_claims {
        if path.is_empty() {
            return Err(format!("{ctx}: empty embed_claims path"));
        }
        let target = target.as_str().unwrap_or("");
        if !valid_embed_target(target) {
            return Err(format!(
                "{ctx}: embed_claims['{path}'] target '{target}' must be lowercase \
                 [a-z0-9_], <=64 chars, and not a reserved claim name"
            ));
        }
    }
    if let Some(ps) = &issuer.ps {
        aauth_core::ident::validate_server_identifier(ps, _insecure_dev)
            .map_err(|_| format!("{ctx}: ps is not a valid server identifier"))?;
    }
    Ok(())
}

pub const EXAMPLE_CONFIG: &str = r#"{
  "issuer": "https://ap.example.com",
  "listen": "127.0.0.1:8420",
  "keys_file": "/var/lib/apd/apd-keys.json",
  "storage": { "backend": "file", "path": "/var/lib/apd/apd-state.json" },
  "agent_token_ttl_secs": 3600,
  "subscribe_token_ttl_secs": 86400,
  "signature_window_secs": 60,
  "enrollment": {
    "methods": ["token"],
    "trusted_issuers": []
  },
  "allow_ps_override": true,
  "metadata": {
    "name": "Example Agent Provider",
    "description": "Self-hosted AAuth agent provider.",
    "documentation_uri": "https://ap.example.com/docs"
  },
  "events": { "enabled": true },
  "telemetry": { "enabled": false, "endpoint": "http://localhost:4318" },
  "revocation": { "notify_ps": true },
  "insecure_dev_mode": false
}
"#;

/// A fuller example enabling federated enrollment.
pub const EXAMPLE_CONFIG_FEDERATED: &str = r#"{
  "issuer": "https://ap.example.com",
  "listen": "127.0.0.1:8420",
  "keys_file": "/var/lib/apd/apd-keys.json",
  "storage": { "backend": "redis", "redis_addr": "127.0.0.1:6379" },
  "enrollment": {
    "methods": ["token", "federated", "allowlist"],
    "trusted_issuers": [
      {
        "name": "prod-eks",
        "type": "oidc",
        "issuer": "https://oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLE",
        "audience": "https://ap.example.com",
        "required_claims": { "sub": "system:serviceaccount:agents:*" },
        "embed_claims": { "kubernetes.io.namespace": "k8s_namespace" },
        "label": "eks-prod"
      },
      {
        "name": "agent-operator",
        "type": "jwks_file",
        "issuer": "https://operator.internal.example",
        "jwks_file": "/etc/apd/operator-jwks.json",
        "require_cnf_binding": true,
        "embed_claims": { "tenant": "tenant" }
      },
      {
        "name": "corp-ca",
        "type": "x5c",
        "issuer": "https://ca.corp.example",
        "ca_bundle_file": "/etc/apd/corp-roots.pem",
        "required_sans": ["spiffe://corp.example/ns/agents/*"],
        "require_cnf_binding": true
      },
      {
        "name": "corp-spire",
        "type": "spiffe",
        "issuer": "corp-spire",
        "trust_domain": "corp.example",
        "jwks_file": "/etc/apd/spire-bundle.json",
        "required_claims": { "sub": "spiffe://corp.example/ns/agents/*" }
      }
    ]
  },
  "audit_log_file": "/var/log/apd/audit.jsonl",
  "events": { "enabled": true },
  "telemetry": { "enabled": true, "endpoint": "http://otel-collector:4318", "service_name": "apd" }
}
"#;
