//! In-process end-to-end tests driving the real handlers via `dispatch`,
//! including a mock resource server for the AAuth Events delivery path.

use std::sync::Arc;

use aauth_core::b64;
use aauth_core::jwk::{generate_signing_key, Jwk};
use aauth_core::jwt;
use aauth_core::now_unix;
use aauth_core::sig::sign_request;
use aauth_core::sigkey;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use hyper::{Method, StatusCode};

use crate::app::App;
use crate::config::Config;
use crate::keys::KeySet;
use crate::problem::Resp;
use crate::reqctx::ReqCtx;
use crate::{router, storage};

// ------------------------------------------------------------------ harness

fn test_config(issuer: &str, enroll_mode: &str) -> Config {
    let json = serde_json::json!({
        "issuer": issuer,
        "storage": { "backend": "memory" },
        "enrollment": { "mode": enroll_mode },
        "admin_token": "test-admin-token",
        "insecure_dev_mode": true,
        "events": { "enabled": true }
    });
    let cfg: Config = serde_json::from_value(json).unwrap();
    cfg.validate().unwrap();
    cfg
}

fn test_keyset() -> (KeySet, SigningKey) {
    let sk = generate_signing_key();
    let mut jwk = Jwk::from_verifying_key(&sk.verifying_key());
    jwk.kid = Some("ap-test-1".into());
    jwk.alg = Some("EdDSA".into());
    jwk.use_ = Some("sig".into());
    (
        KeySet {
            active_kid: "ap-test-1".into(),
            active_key: sk.clone(),
            public_jwks: vec![jwk],
        },
        sk,
    )
}

async fn build_app(issuer: &str, enroll_mode: &str) -> Arc<App> {
    let cfg = test_config(issuer, enroll_mode);
    let (keys, _) = test_keyset();
    let store = storage::open(&cfg.storage).await.unwrap();
    App::new(cfg, keys, store)
}

/// A test agent request: sign with the given Signature-Key value + key.
struct AgentReq {
    method: Method,
    authority: String,
    path: String,
    body: Vec<u8>,
    extra_covered: Vec<String>,
}

impl AgentReq {
    fn new(method: Method, authority: &str, path: &str) -> Self {
        AgentReq {
            method,
            authority: authority.into(),
            path: path.into(),
            body: Vec::new(),
            extra_covered: Vec::new(),
        }
    }
    fn json(mut self, v: serde_json::Value) -> Self {
        self.body = serde_json::to_vec(&v).unwrap();
        self
    }
    /// Sign and produce a ReqCtx. `sigkey_value` is the Signature-Key member
    /// value (without the leading label=); `signing` is the private key that
    /// actually signs the HTTP message.
    fn into_ctx(self, sigkey_value: &str, signing: &SigningKey, created: u64) -> ReqCtx {
        let lookup = |_: &str| None;
        let extra: Vec<&str> = self.extra_covered.iter().map(|s| s.as_str()).collect();
        let signed = sign_request(
            self.method.as_str(),
            &self.authority,
            &self.path,
            "",
            &extra,
            &lookup,
            sigkey_value,
            signing,
            created,
        )
        .unwrap();
        let mut headers = vec![
            ("host".to_string(), self.authority.clone()),
            ("signature-input".to_string(), signed.signature_input),
            ("signature".to_string(), signed.signature),
            ("signature-key".to_string(), signed.signature_key),
        ];
        if !self.body.is_empty() {
            headers.push(("content-type".to_string(), "application/json".to_string()));
        }
        ReqCtx {
            method: self.method.as_str().to_string(),
            authority: self.authority.clone(),
            path: self.path.clone(),
            query: String::new(),
            headers,
            body: self.body,
        }
    }
}

async fn body_json(resp: Resp) -> (StatusCode, serde_json::Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, val)
}

async fn call(
    app: &Arc<App>,
    method: Method,
    path: &str,
    ctx: ReqCtx,
) -> (StatusCode, serde_json::Value) {
    let resp = router::dispatch(&method, path, &ctx, app)
        .await
        .unwrap_or_else(|e| e.into_response());
    body_json(resp).await
}

// -------------------------------------------------- enroll + token (jkt-jwt)

const AUTH: &str = "ap.example";

async fn enroll_open(app: &Arc<App>, durable: &SigningKey) -> String {
    let durable_jwk = Jwk::from_verifying_key(&durable.verifying_key());
    let ctx = AgentReq::new(Method::POST, AUTH, "/enroll")
        .json(serde_json::json!({ "platform": "workload" }))
        .into_ctx(&sigkey::serialize_hwk(&durable_jwk), durable, now_unix());
    let (status, body) = call(app, Method::POST, "/enroll", ctx).await;
    assert_eq!(status, StatusCode::CREATED, "enroll failed: {body}");
    body["agent"].as_str().unwrap().to_string()
}

/// Two-key refresh: durable delegates to ephemeral via jkt-jwt.
async fn get_agent_token(
    app: &Arc<App>,
    durable: &SigningKey,
    ephemeral: &SigningKey,
    ps: Option<&str>,
) -> String {
    let eph_jwk = Jwk::from_verifying_key(&ephemeral.verifying_key());
    let naming = sigkey::build_naming_jwt(durable, &eph_jwk, now_unix(), 300);
    let body = match ps {
        Some(p) => serde_json::json!({ "ps": p }),
        None => serde_json::json!({}),
    };
    let ctx = AgentReq::new(Method::POST, AUTH, "/agent-token")
        .json(body)
        .into_ctx(&sigkey::serialize_jkt_jwt(&naming), ephemeral, now_unix());
    let (status, resp) = call(app, Method::POST, "/agent-token", ctx).await;
    assert_eq!(status, StatusCode::OK, "agent-token failed: {resp}");
    resp["agent_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn enroll_and_two_key_token() {
    let app = build_app("https://ap.example", "open").await;
    let durable = generate_signing_key();
    let ephemeral = generate_signing_key();

    let agent_id = enroll_open(&app, &durable).await;
    assert!(agent_id.starts_with("aauth:") && agent_id.ends_with("@ap.example"));

    let token = get_agent_token(&app, &durable, &ephemeral, Some("https://ps.example")).await;

    // The issued token verifies against the AP's own JWKS and carries the
    // ephemeral key in cnf, and the ps we asked for.
    let decoded = jwt::decode(&token).unwrap();
    let ap_key = app.keys.find_public("ap-test-1").unwrap();
    jwt::verify_with_jwk(&decoded, ap_key).unwrap();
    let claims = aauth_core::tokens::validate_agent_token(&decoded, now_unix(), true).unwrap();
    assert_eq!(claims.sub, agent_id);
    assert_eq!(claims.ps.as_deref(), Some("https://ps.example"));
    assert_eq!(
        claims.cnf.jwk.x,
        Jwk::from_verifying_key(&ephemeral.verifying_key()).x
    );
}

#[tokio::test]
async fn single_key_refresh_hwk() {
    let app = build_app("https://ap.example", "open").await;
    let durable = generate_signing_key();
    enroll_open(&app, &durable).await;

    let durable_jwk = Jwk::from_verifying_key(&durable.verifying_key());
    let ctx = AgentReq::new(Method::POST, AUTH, "/agent-token").into_ctx(
        &sigkey::serialize_hwk(&durable_jwk),
        &durable,
        now_unix(),
    );
    let (status, resp) = call(&app, Method::POST, "/agent-token", ctx).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let claims = {
        let d = jwt::decode(resp["agent_token"].as_str().unwrap()).unwrap();
        aauth_core::tokens::validate_agent_token(&d, now_unix(), true).unwrap()
    };
    // single-key: cnf is the durable key itself
    assert_eq!(claims.cnf.jwk.x, durable_jwk.x);
}

#[tokio::test]
async fn token_before_enroll_is_forbidden() {
    let app = build_app("https://ap.example", "open").await;
    let durable = generate_signing_key();
    let ephemeral = generate_signing_key();
    let eph_jwk = Jwk::from_verifying_key(&ephemeral.verifying_key());
    let naming = sigkey::build_naming_jwt(&durable, &eph_jwk, now_unix(), 300);
    let ctx = AgentReq::new(Method::POST, AUTH, "/agent-token").into_ctx(
        &sigkey::serialize_jkt_jwt(&naming),
        &ephemeral,
        now_unix(),
    );
    let (status, body) = call(&app, Method::POST, "/agent-token", ctx).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "not_enrolled");
}

#[tokio::test]
async fn naming_jwt_replay_rejected() {
    let app = build_app("https://ap.example", "open").await;
    let durable = generate_signing_key();
    enroll_open(&app, &durable).await;
    let ephemeral = generate_signing_key();
    let eph_jwk = Jwk::from_verifying_key(&ephemeral.verifying_key());
    let created = now_unix();
    let naming = sigkey::build_naming_jwt(&durable, &eph_jwk, created, 300);

    // First use succeeds.
    let ctx1 = AgentReq::new(Method::POST, AUTH, "/agent-token").into_ctx(
        &sigkey::serialize_jkt_jwt(&naming),
        &ephemeral,
        created,
    );
    let (s1, _) = call(&app, Method::POST, "/agent-token", ctx1).await;
    assert_eq!(s1, StatusCode::OK);

    // Reusing the same naming JWT (same jti) is rejected.
    let ctx2 = AgentReq::new(Method::POST, AUTH, "/agent-token").into_ctx(
        &sigkey::serialize_jkt_jwt(&naming),
        &ephemeral,
        created,
    );
    let (s2, body) = call(&app, Method::POST, "/agent-token", ctx2).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_jwt");
}

#[tokio::test]
async fn stale_created_rejected() {
    let app = build_app("https://ap.example", "open").await;
    let durable = generate_signing_key();
    let durable_jwk = Jwk::from_verifying_key(&durable.verifying_key());
    let ctx = AgentReq::new(Method::POST, AUTH, "/enroll").into_ctx(
        &sigkey::serialize_hwk(&durable_jwk),
        &durable,
        now_unix() - 3600,
    );
    let (status, body) = call(&app, Method::POST, "/enroll", ctx).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_signature", "{body}");
}

// ----------------------------------------------------- token-mode enrollment

#[tokio::test]
async fn token_mode_enrollment_requires_token() {
    let app = build_app("https://ap.example", "token").await;
    let durable = generate_signing_key();
    let durable_jwk = Jwk::from_verifying_key(&durable.verifying_key());

    // Without a token: forbidden.
    let ctx = AgentReq::new(Method::POST, AUTH, "/enroll").into_ctx(
        &sigkey::serialize_hwk(&durable_jwk),
        &durable,
        now_unix(),
    );
    let (status, _) = call(&app, Method::POST, "/enroll", ctx).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Mint an enrollment token via the admin API.
    let admin_ctx = ReqCtx {
        method: "POST".into(),
        authority: AUTH.into(),
        path: "/admin/enrollment-tokens".into(),
        query: String::new(),
        headers: vec![("authorization".into(), "Bearer test-admin-token".into())],
        body: serde_json::to_vec(&serde_json::json!({ "ps": "https://ps.example" })).unwrap(),
    };
    let (status, body) = call(&app, Method::POST, "/admin/enrollment-tokens", admin_ctx).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let enroll_token = body["enrollment_token"].as_str().unwrap().to_string();

    // With the token: success, and the bound ps flows into issued tokens.
    let ctx = AgentReq::new(Method::POST, AUTH, "/enroll")
        .json(serde_json::json!({ "enrollment_token": enroll_token }))
        .into_ctx(&sigkey::serialize_hwk(&durable_jwk), &durable, now_unix());
    let (status, body) = call(&app, Method::POST, "/enroll", ctx).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The consumed token can't be used again (a fresh durable key rules out
    // the idempotent-existing-enrollment path, isolating token reuse).
    let durable2 = generate_signing_key();
    let durable2_jwk = Jwk::from_verifying_key(&durable2.verifying_key());
    let ctx2 = AgentReq::new(Method::POST, AUTH, "/enroll")
        .json(serde_json::json!({ "enrollment_token": enroll_token }))
        .into_ctx(&sigkey::serialize_hwk(&durable2_jwk), &durable2, now_unix());
    let (status, body) = call(&app, Method::POST, "/enroll", ctx2).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "consumed token reuse: {body}"
    );
}

#[tokio::test]
async fn admin_revoke_blocks_refresh() {
    let app = build_app("https://ap.example", "open").await;
    let durable = generate_signing_key();
    let ephemeral = generate_signing_key();
    let agent_id = enroll_open(&app, &durable).await;
    let local = aauth_core::ident::local_part(&agent_id).to_string();

    // Works before revoke.
    let _ = get_agent_token(&app, &durable, &ephemeral, None).await;

    // Revoke.
    let admin_ctx = ReqCtx {
        method: "POST".into(),
        authority: AUTH.into(),
        path: format!("/admin/agents/{local}/revoke"),
        query: String::new(),
        headers: vec![("authorization".into(), "Bearer test-admin-token".into())],
        body: Vec::new(),
    };
    let path = format!("/admin/agents/{local}/revoke");
    let (status, _) = call(&app, Method::POST, &path, admin_ctx).await;
    assert_eq!(status, StatusCode::OK);

    // Refresh now fails.
    let eph2 = generate_signing_key();
    let eph2_jwk = Jwk::from_verifying_key(&eph2.verifying_key());
    let naming = sigkey::build_naming_jwt(&durable, &eph2_jwk, now_unix(), 300);
    let ctx = AgentReq::new(Method::POST, AUTH, "/agent-token").into_ctx(
        &sigkey::serialize_jkt_jwt(&naming),
        &eph2,
        now_unix(),
    );
    let (status, body) = call(&app, Method::POST, "/agent-token", ctx).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "enrollment_revoked", "{body}");
}

// ------------------------------------------------------------- sub-agents

#[tokio::test]
async fn subagent_token_issuance() {
    let app = build_app("https://ap.example", "open").await;
    let durable = generate_signing_key();
    let ephemeral = generate_signing_key();
    let parent_id = enroll_open(&app, &durable).await;
    let parent_token =
        get_agent_token(&app, &durable, &ephemeral, Some("https://ps.example")).await;

    // Sub-agent generates its own key; parent requests the token.
    let sub_key = generate_signing_key();
    let sub_jwk = Jwk::from_verifying_key(&sub_key.verifying_key());
    let ctx = AgentReq::new(Method::POST, AUTH, "/subagent-token")
        .json(serde_json::json!({ "discriminator": "search1", "cnf_jwk": sub_jwk }))
        .into_ctx(
            &sigkey::serialize_jwt(&parent_token),
            &ephemeral,
            now_unix(),
        );
    let (status, body) = call(&app, Method::POST, "/subagent-token", ctx).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sub_token = body["agent_token"].as_str().unwrap();
    let decoded = jwt::decode(sub_token).unwrap();
    let claims = aauth_core::tokens::validate_agent_token(&decoded, now_unix(), true).unwrap();
    let parent_local = aauth_core::ident::local_part(&parent_id);
    assert_eq!(
        claims.sub,
        format!("aauth:{parent_local}+search1@ap.example")
    );
    assert_eq!(claims.parent_agent.as_deref(), Some(parent_id.as_str()));
    assert_eq!(claims.cnf.jwk.x, sub_jwk.x);

    // A sub-agent cannot create sub-agents (single-level depth).
    let sub2 = generate_signing_key();
    let sub2_jwk = Jwk::from_verifying_key(&sub2.verifying_key());
    let ctx = AgentReq::new(Method::POST, AUTH, "/subagent-token")
        .json(serde_json::json!({ "discriminator": "deep", "cnf_jwk": sub2_jwk }))
        .into_ctx(&sigkey::serialize_jwt(sub_token), &sub_key, now_unix());
    let (status, body) = call(&app, Method::POST, "/subagent-token", ctx).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "nested_subagent");
}

// ------------------------------------------------- events: full delivery

/// Spawn a mock resource that serves its metadata + JWKS, returning
/// (issuer_url, resource signing key, join handle's abort).
async fn spawn_mock_resource(kid: &str) -> (String, SigningKey, tokio::task::JoinHandle<()>) {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let issuer = format!("http://127.0.0.1:{port}");
    let key = generate_signing_key();
    let mut jwk = Jwk::from_verifying_key(&key.verifying_key());
    jwk.kid = Some(kid.to_string());
    jwk.alg = Some("EdDSA".into());

    let issuer_c = issuer.clone();
    let jwks = serde_json::json!({ "keys": [jwk] }).to_string();
    let metadata = serde_json::json!({
        "issuer": issuer_c,
        "jwks_uri": format!("{issuer_c}/jwks.json"),
    })
    .to_string();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let jwks = jwks.clone();
            let metadata = metadata.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let jwks = jwks.clone();
                    let metadata = metadata.clone();
                    async move {
                        let body = match req.uri().path() {
                            "/.well-known/aauth-resource.json" => metadata,
                            "/jwks.json" => jwks,
                            _ => "{}".to_string(),
                        };
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Full::new(hyper::body::Bytes::from(body)),
                        ))
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    (issuer, key, handle)
}

#[tokio::test]
async fn events_subscribe_deliver_inbox() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let app = build_app("https://ap.example", "open").await;
    let durable = generate_signing_key();
    let ephemeral = generate_signing_key();
    let agent_id = enroll_open(&app, &durable).await;
    let agent_token = get_agent_token(&app, &durable, &ephemeral, Some("https://ps.example")).await;

    let (resource_iss, resource_key, _resource) = spawn_mock_resource("res-key-1").await;

    // 1. Agent subscribes (signed with its agent token / ephemeral key).
    let ctx = AgentReq::new(Method::POST, AUTH, "/subscribe")
        .json(serde_json::json!({ "resource": resource_iss, "max_uses": 1 }))
        .into_ctx(&sigkey::serialize_jwt(&agent_token), &ephemeral, now_unix());
    let (status, body) = call(&app, Method::POST, "/subscribe", ctx).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let eid = body["eid"].as_str().unwrap().to_string();

    // 2. Resource delivers an event token (aud = agent), signed by the
    //    resource key (dwk-without-cnf: same key verifies JWT + HTTP sig).
    let now = now_unix();
    let event_payload = serde_json::json!({
        "iss": resource_iss,
        "dwk": "aauth-resource.json",
        "aud": agent_id,
        "eid": eid,
        "iat": now,
        "exp": now + 300,
    });
    let event_token = jwt::sign(
        aauth_core::tokens::TYP_EVENT,
        Some("res-key-1"),
        None,
        &event_payload,
        &resource_key,
    );
    let ctx = AgentReq::new(Method::POST, AUTH, "/events")
        .json(serde_json::json!({ "event_type": "slot.available", "slot_time": "2026-07-15T10:00:00Z" }))
        .into_ctx(&sigkey::serialize_jwt(&event_token), &resource_key, now);
    // /events requires content-type + content-digest? No: only base four.
    let (status, body) = call(&app, Method::POST, "/events", ctx).await;
    assert_eq!(status, StatusCode::ACCEPTED, "delivery failed: {body}");
    assert_eq!(body["remaining_uses"], 0);

    // 3. Agent drains its inbox.
    let ctx = AgentReq::new(Method::GET, AUTH, "/inbox").into_ctx(
        &sigkey::serialize_jwt(&agent_token),
        &ephemeral,
        now_unix(),
    );
    let (status, body) = call(&app, Method::GET, "/inbox", ctx).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["eid"], eid);
    assert_eq!(events[0]["payload"]["event_type"], "slot.available");

    // 4. Second delivery is refused (max_uses=1 exhausted; subscription gone).
    let ctx = AgentReq::new(Method::POST, AUTH, "/events")
        .json(serde_json::json!({ "event_type": "slot.available" }))
        .into_ctx(
            &sigkey::serialize_jwt(&event_token),
            &resource_key,
            now_unix(),
        );
    let (status, _) = call(&app, Method::POST, "/events", ctx).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn events_wrong_resource_rejected() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let app = build_app("https://ap.example", "open").await;
    let durable = generate_signing_key();
    let ephemeral = generate_signing_key();
    let agent_id = enroll_open(&app, &durable).await;
    let agent_token = get_agent_token(&app, &durable, &ephemeral, Some("https://ps.example")).await;

    let (resource_iss, _rk, _r) = spawn_mock_resource("res-key-1").await;
    let (evil_iss, evil_key, _e) = spawn_mock_resource("evil-key-1").await;

    // Subscribe authorizing resource_iss only.
    let ctx = AgentReq::new(Method::POST, AUTH, "/subscribe")
        .json(serde_json::json!({ "resource": resource_iss }))
        .into_ctx(&sigkey::serialize_jwt(&agent_token), &ephemeral, now_unix());
    let (_, body) = call(&app, Method::POST, "/subscribe", ctx).await;
    let eid = body["eid"].as_str().unwrap().to_string();

    // A different resource tries to deliver for this eid.
    let now = now_unix();
    let event_payload = serde_json::json!({
        "iss": evil_iss, "dwk": "aauth-resource.json",
        "aud": agent_id, "eid": eid, "iat": now, "exp": now + 300,
    });
    let event_token = jwt::sign(
        aauth_core::tokens::TYP_EVENT,
        Some("evil-key-1"),
        None,
        &event_payload,
        &evil_key,
    );
    let ctx = AgentReq::new(Method::POST, AUTH, "/events")
        .json(serde_json::json!({ "x": 1 }))
        .into_ctx(&sigkey::serialize_jwt(&event_token), &evil_key, now);
    let (status, body) = call(&app, Method::POST, "/events", ctx).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "resource_mismatch");
}

// ------------------------------------------------------------- base64 dep

#[test]
fn b64_dep_is_reachable() {
    // sanity: the crate wiring compiles and b64 is usable
    assert_eq!(b64::encode(b"foo"), "Zm9v");
}
