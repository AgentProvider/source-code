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
    build_app_with(cfg).await
}

async fn build_app_with(cfg: Config) -> Arc<App> {
    let (keys, _) = test_keyset();
    let store = storage::open(&cfg.storage).await.unwrap();
    App::new(cfg, keys, store).unwrap()
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

// =================================================== federated enrollment

/// Build a JWS compact token with an arbitrary JSON header, signed EdDSA.
fn sign_jws_eddsa(
    header: serde_json::Value,
    payload: serde_json::Value,
    key: &SigningKey,
) -> String {
    use ed25519_dalek::Signer;
    let h = b64::encode(header.to_string().as_bytes());
    let p = b64::encode(payload.to_string().as_bytes());
    let input = format!("{h}.{p}");
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", b64::encode(&sig.to_bytes()))
}

/// Spawn a mock OIDC issuer serving discovery + JWKS for an Ed25519 key.
async fn spawn_mock_oidc(kid: &str, key: &SigningKey) -> (String, tokio::task::JoinHandle<()>) {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let issuer = format!("http://127.0.0.1:{port}");

    let mut jwk = Jwk::from_verifying_key(&key.verifying_key());
    jwk.kid = Some(kid.to_string());
    jwk.alg = Some("EdDSA".into());
    let jwks = serde_json::json!({ "keys": [jwk] }).to_string();
    let discovery = serde_json::json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/jwks.json"),
    })
    .to_string();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let jwks = jwks.clone();
            let discovery = discovery.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let jwks = jwks.clone();
                    let discovery = discovery.clone();
                    async move {
                        let body = match req.uri().path() {
                            "/.well-known/openid-configuration" => discovery,
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
    (issuer, handle)
}

fn federated_config(issuer_entries: serde_json::Value) -> Config {
    let json = serde_json::json!({
        "issuer": "https://ap.example",
        "storage": { "backend": "memory" },
        "enrollment": {
            "methods": ["token", "federated", "allowlist"],
            "trusted_issuers": issuer_entries
        },
        "admin_token": "test-admin-token",
        "insecure_dev_mode": true,
        "events": { "enabled": false }
    });
    let cfg: Config = serde_json::from_value(json).unwrap();
    cfg.validate().unwrap();
    cfg
}

/// Enroll with a federated assertion; returns (status, body).
async fn enroll_with_assertion(
    app: &Arc<App>,
    durable: &SigningKey,
    assertion: &str,
) -> (StatusCode, serde_json::Value) {
    let durable_jwk = Jwk::from_verifying_key(&durable.verifying_key());
    let ctx = AgentReq::new(Method::POST, AUTH, "/enroll")
        .json(serde_json::json!({ "enrollment_assertion": assertion }))
        .into_ctx(&sigkey::serialize_hwk(&durable_jwk), durable, now_unix());
    call(app, Method::POST, "/enroll", ctx).await
}

#[tokio::test]
async fn federated_oidc_end_to_end() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let issuer_key = generate_signing_key();
    let (oidc_issuer, _srv) = spawn_mock_oidc("op-1", &issuer_key).await;

    let app = build_app_with(federated_config(serde_json::json!([{
        "name": "test-k8s",
        "type": "oidc",
        "issuer": oidc_issuer,
        "allow_insecure_egress": true,
        "required_claims": { "sub": "system:serviceaccount:agents:*" },
        "embed_claims": { "kubernetes.io.namespace": "k8s_namespace" },
        "label": "k8s"
    }])))
    .await;

    // A k8s-projected-SA-token-shaped assertion (RS256 in real life; EdDSA here).
    let now = now_unix();
    let assertion = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": "op-1"}),
        serde_json::json!({
            "iss": oidc_issuer,
            "aud": ["https://ap.example"],
            "sub": "system:serviceaccount:agents:runner",
            "kubernetes.io": { "namespace": "agents" },
            "jti": "sa-token-1",
            "iat": now, "exp": now + 600,
        }),
        &issuer_key,
    );

    let durable = generate_signing_key();
    let (status, body) = enroll_with_assertion(&app, &durable, &assertion).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let agent_id = body["agent"].as_str().unwrap().to_string();

    // Agent-token issuance stamps the embedded claim.
    let ephemeral = generate_signing_key();
    let token = get_agent_token(&app, &durable, &ephemeral, None).await;
    let decoded = jwt::decode(&token).unwrap();
    assert_eq!(decoded.payload["k8s_namespace"], "agents");
    assert_eq!(decoded.payload["sub"], agent_id);

    // Admin listing shows the federated method + issuer + subject.
    let admin_ctx = ReqCtx {
        method: "GET".into(),
        authority: AUTH.into(),
        path: "/admin/agents".into(),
        query: String::new(),
        headers: vec![("authorization".into(), "Bearer test-admin-token".into())],
        body: Vec::new(),
    };
    let (_, listing) = call(&app, Method::GET, "/admin/agents", admin_ctx).await;
    let entry = &listing["agents"][0];
    assert_eq!(entry["agent"], agent_id);

    // Replay: the same (non-cnf) assertion with a DIFFERENT key is rejected.
    let thief = generate_signing_key();
    let (status, body) = enroll_with_assertion(&app, &thief, &assertion).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "invalid_assertion");

    // But an idempotent retry with the SAME key returns the existing agent.
    let (status, body) = enroll_with_assertion(&app, &durable, &assertion).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "existing");
}

#[tokio::test]
async fn federated_claim_and_aud_policy() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let issuer_key = generate_signing_key();
    let (oidc_issuer, _srv) = spawn_mock_oidc("op-1", &issuer_key).await;

    let app = build_app_with(federated_config(serde_json::json!([{
        "name": "test",
        "type": "oidc",
        "issuer": oidc_issuer,
        "allow_insecure_egress": true,
        "required_claims": { "sub": "system:serviceaccount:agents:*" }
    }])))
    .await;
    let now = now_unix();

    // Wrong namespace in sub → rejected.
    let bad_sub = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "kid": "op-1"}),
        serde_json::json!({
            "iss": oidc_issuer, "aud": "https://ap.example",
            "sub": "system:serviceaccount:evil:runner",
            "iat": now, "exp": now + 600,
        }),
        &issuer_key,
    );
    let durable = generate_signing_key();
    let (status, body) = enroll_with_assertion(&app, &durable, &bad_sub).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Wrong audience → rejected.
    let bad_aud = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "kid": "op-1"}),
        serde_json::json!({
            "iss": oidc_issuer, "aud": "https://other.example",
            "sub": "system:serviceaccount:agents:runner",
            "iat": now, "exp": now + 600,
        }),
        &issuer_key,
    );
    let (status, _) = enroll_with_assertion(&app, &durable, &bad_aud).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Expired → rejected.
    let expired = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "kid": "op-1"}),
        serde_json::json!({
            "iss": oidc_issuer, "aud": "https://ap.example",
            "sub": "system:serviceaccount:agents:runner",
            "iat": now - 1200, "exp": now - 600,
        }),
        &issuer_key,
    );
    let (status, _) = enroll_with_assertion(&app, &durable, &expired).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Untrusted issuer → rejected.
    let foreign = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "kid": "op-1"}),
        serde_json::json!({
            "iss": "http://unknown.example", "aud": "https://ap.example",
            "sub": "system:serviceaccount:agents:runner",
            "iat": now, "exp": now + 600,
        }),
        &issuer_key,
    );
    let (status, _) = enroll_with_assertion(&app, &durable, &foreign).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn federated_operator_cnf_binding() {
    // Operator-signed, cnf-bound assertions from a jwks_file issuer.
    let operator_key = generate_signing_key();
    let mut op_jwk = Jwk::from_verifying_key(&operator_key.verifying_key());
    op_jwk.kid = Some("operator-1".into());
    let jwks_path = format!(
        "{}/apd-test-operator-{}.json",
        std::env::temp_dir().display(),
        aauth_core::rand_id(8)
    );
    std::fs::write(
        &jwks_path,
        serde_json::json!({ "keys": [op_jwk] }).to_string(),
    )
    .unwrap();

    let app = build_app_with(federated_config(serde_json::json!([{
        "name": "operator",
        "type": "jwks_file",
        "issuer": "https://operator.internal",
        "jwks_file": jwks_path,
        "require_cnf_binding": true,
        "embed_claims": { "tenant": "tenant" },
        "ps": "https://ps.example"
    }])))
    .await;

    let durable = generate_signing_key();
    let durable_jwk = Jwk::from_verifying_key(&durable.verifying_key());
    let jkt = durable_jwk.thumbprint().unwrap();
    let now = now_unix();

    // cnf.jkt binds the enrolling key.
    let assertion = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "kid": "operator-1"}),
        serde_json::json!({
            "iss": "https://operator.internal",
            "aud": "https://ap.example",
            "sub": "pod-7f3c",
            "tenant": "acme",
            "cnf": { "jkt": jkt },
            "iat": now, "exp": now + 300,
        }),
        &operator_key,
    );
    let (status, body) = enroll_with_assertion(&app, &durable, &assertion).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The issuer's ps pin flows into issued tokens, as does the tenant claim.
    let ephemeral = generate_signing_key();
    let token = get_agent_token(&app, &durable, &ephemeral, None).await;
    let decoded = jwt::decode(&token).unwrap();
    assert_eq!(decoded.payload["tenant"], "acme");
    assert_eq!(decoded.payload["ps"], "https://ps.example");

    // An assertion bound to a DIFFERENT key must be rejected for this key.
    let other = generate_signing_key();
    let other_jkt = Jwk::from_verifying_key(&other.verifying_key())
        .thumbprint()
        .unwrap();
    let mismatched = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "kid": "operator-1"}),
        serde_json::json!({
            "iss": "https://operator.internal",
            "aud": "https://ap.example",
            "sub": "pod-9999",
            "cnf": { "jkt": other_jkt },
            "iat": now, "exp": now + 300,
        }),
        &operator_key,
    );
    let fresh = generate_signing_key();
    let (status, body) = enroll_with_assertion(&app, &fresh, &mismatched).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Missing cnf entirely violates require_cnf_binding.
    let unbound = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "kid": "operator-1"}),
        serde_json::json!({
            "iss": "https://operator.internal",
            "aud": "https://ap.example",
            "sub": "pod-0000",
            "iat": now, "exp": now + 300,
        }),
        &operator_key,
    );
    let fresh2 = generate_signing_key();
    let (status, _) = enroll_with_assertion(&app, &fresh2, &unbound).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    std::fs::remove_file(&jwks_path).ok();
}

#[tokio::test]
async fn federated_x5c_chain() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // CA (P-256) and an Ed25519 leaf whose key we control (PKCS#8 import).
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let leaf_signer = generate_signing_key();
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    pkcs8.extend_from_slice(&leaf_signer.to_bytes());
    let leaf_key = rcgen::KeyPair::try_from(pkcs8.as_slice()).unwrap();

    let mut leaf_params = rcgen::CertificateParams::new(vec![]).unwrap();
    leaf_params.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::Ia5String::try_from("spiffe://corp.example/ns/agents/runner".to_string()).unwrap(),
    ));
    leaf_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    let ca_path = format!(
        "{}/apd-test-ca-{}.pem",
        std::env::temp_dir().display(),
        aauth_core::rand_id(8)
    );
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();

    let app = build_app_with(federated_config(serde_json::json!([{
        "name": "corp-ca",
        "type": "x5c",
        "issuer": "https://ca.corp.example",
        "ca_bundle_file": ca_path,
        "required_sans": ["spiffe://corp.example/ns/agents/*"],
        "require_cnf_binding": true
    }])))
    .await;

    let durable = generate_signing_key();
    let jkt = Jwk::from_verifying_key(&durable.verifying_key())
        .thumbprint()
        .unwrap();
    let now = now_unix();
    let leaf_b64_std = b64::encode_std(leaf_cert.der());
    let assertion = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "x5c": [leaf_b64_std]}),
        serde_json::json!({
            "iss": "https://ca.corp.example",
            "aud": "https://ap.example",
            "sub": "spiffe://corp.example/ns/agents/runner",
            "cnf": { "jkt": jkt },
            "iat": now, "exp": now + 300,
        }),
        &leaf_signer,
    );
    let (status, body) = enroll_with_assertion(&app, &durable, &assertion).await;
    assert_eq!(status, StatusCode::CREATED, "x5c enroll failed: {body}");

    // A leaf signed by an UNTRUSTED CA is rejected.
    let rogue_ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut rogue_params = rcgen::CertificateParams::new(vec![]).unwrap();
    rogue_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let rogue_ca = rogue_params.self_signed(&rogue_ca_key).unwrap();

    let leaf2_signer = generate_signing_key();
    let mut pkcs8b = Vec::with_capacity(48);
    pkcs8b.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    pkcs8b.extend_from_slice(&leaf2_signer.to_bytes());
    let leaf2_key = rcgen::KeyPair::try_from(pkcs8b.as_slice()).unwrap();
    let mut leaf2_params = rcgen::CertificateParams::new(vec![]).unwrap();
    leaf2_params.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::Ia5String::try_from("spiffe://corp.example/ns/agents/x".to_string()).unwrap(),
    ));
    let leaf2 = leaf2_params
        .signed_by(&leaf2_key, &rogue_ca, &rogue_ca_key)
        .unwrap();
    let durable2 = generate_signing_key();
    let jkt2 = Jwk::from_verifying_key(&durable2.verifying_key())
        .thumbprint()
        .unwrap();
    let rogue_assertion = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "x5c": [b64::encode_std(leaf2.der())]}),
        serde_json::json!({
            "iss": "https://ca.corp.example",
            "aud": "https://ap.example",
            "cnf": { "jkt": jkt2 },
            "iat": now, "exp": now + 300,
        }),
        &leaf2_signer,
    );
    let (status, body) = enroll_with_assertion(&app, &durable2, &rogue_assertion).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // SAN outside policy is rejected (trusted CA, wrong SPIFFE path).
    let leaf3_signer = generate_signing_key();
    let mut pkcs8c = Vec::with_capacity(48);
    pkcs8c.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    pkcs8c.extend_from_slice(&leaf3_signer.to_bytes());
    let leaf3_key = rcgen::KeyPair::try_from(pkcs8c.as_slice()).unwrap();
    let mut leaf3_params = rcgen::CertificateParams::new(vec![]).unwrap();
    leaf3_params.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::Ia5String::try_from("spiffe://corp.example/ns/other/sa".to_string()).unwrap(),
    ));
    let leaf3 = leaf3_params
        .signed_by(&leaf3_key, &ca_cert, &ca_key)
        .unwrap();
    let durable3 = generate_signing_key();
    let jkt3 = Jwk::from_verifying_key(&durable3.verifying_key())
        .thumbprint()
        .unwrap();
    let bad_san = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "x5c": [b64::encode_std(leaf3.der())]}),
        serde_json::json!({
            "iss": "https://ca.corp.example",
            "aud": "https://ap.example",
            "cnf": { "jkt": jkt3 },
            "iat": now, "exp": now + 300,
        }),
        &leaf3_signer,
    );
    let (status, body) = enroll_with_assertion(&app, &durable3, &bad_san).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    std::fs::remove_file(&ca_path).ok();
}

#[tokio::test]
async fn spiffe_jwt_svid_enrollment_and_assurance() {
    // A SPIFFE JWT-SVID: signed by the trust-bundle JWKS, `sub` is a SPIFFE ID,
    // no x5c chain, no `iss`. It is routed by trust domain, and the resulting
    // enrollment carries the "high" assurance tier into issued agent tokens.
    let bundle_key = generate_signing_key();
    let mut bundle_jwk = Jwk::from_verifying_key(&bundle_key.verifying_key());
    bundle_jwk.kid = Some("spire-1".into());
    bundle_jwk.alg = Some("EdDSA".into());

    let app = build_app_with(federated_config(serde_json::json!([{
        "name": "corp-spire",
        "type": "spiffe",
        "issuer": "corp-spire",
        "trust_domain": "corp.example",
        "jwks": { "keys": [bundle_jwk] },
        "required_claims": { "sub": "spiffe://corp.example/ns/agents/*" },
    }])))
    .await;

    let now = now_unix();
    // JWT-SVID: SPIFFE mandates no `iss`; identity is the `sub`.
    let svid = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "kid": "spire-1"}),
        serde_json::json!({
            "aud": ["https://ap.example"],
            "sub": "spiffe://corp.example/ns/agents/runner",
            "iat": now, "exp": now + 300,
        }),
        &bundle_key,
    );

    let durable = generate_signing_key();
    let (status, body) = enroll_with_assertion(&app, &durable, &svid).await;
    assert_eq!(status, StatusCode::CREATED, "spiffe enroll failed: {body}");

    // Issued agent tokens carry assurance=high (spiffe default tier).
    let ephemeral = generate_signing_key();
    let token = get_agent_token(&app, &durable, &ephemeral, None).await;
    let decoded = jwt::decode(&token).unwrap();
    assert_eq!(decoded.payload["assurance"], "high");

    // A sub of a DIFFERENT trust domain is not routed to this issuer.
    let rogue = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "kid": "spire-1"}),
        serde_json::json!({
            "aud": ["https://ap.example"],
            "sub": "spiffe://evil.example/ns/agents/runner",
            "iat": now, "exp": now + 300,
        }),
        &bundle_key,
    );
    let (status, _) = enroll_with_assertion(&app, &generate_signing_key(), &rogue).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A sub outside the allowed workload path is rejected by required_claims.
    let off_path = sign_jws_eddsa(
        serde_json::json!({"alg": "EdDSA", "kid": "spire-1"}),
        serde_json::json!({
            "aud": ["https://ap.example"],
            "sub": "spiffe://corp.example/ns/other/x",
            "iat": now, "exp": now + 300,
        }),
        &bundle_key,
    );
    let (status, _) = enroll_with_assertion(&app, &generate_signing_key(), &off_path).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn allowlist_enrollment() {
    let app = build_app_with(federated_config(serde_json::json!([{
        "name": "unused", "type": "jwks", "issuer": "https://unused.example",
        "jwks": { "keys": [ { "kty": "OKP", "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "k" } ] }
    }])))
    .await;

    let durable = generate_signing_key();
    let durable_jwk = Jwk::from_verifying_key(&durable.verifying_key());
    let jkt = durable_jwk.thumbprint().unwrap();

    // Without pre-registration: denied (no token, no assertion, no allowlist hit).
    let ctx = AgentReq::new(Method::POST, AUTH, "/enroll").into_ctx(
        &sigkey::serialize_hwk(&durable_jwk),
        &durable,
        now_unix(),
    );
    let (status, _) = call(&app, Method::POST, "/enroll", ctx).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Orchestrator pre-registers the thumbprint via the admin API.
    let admin_ctx = ReqCtx {
        method: "POST".into(),
        authority: AUTH.into(),
        path: "/admin/allowed-keys".into(),
        query: String::new(),
        headers: vec![("authorization".into(), "Bearer test-admin-token".into())],
        body: serde_json::to_vec(
            &serde_json::json!({ "jkt": jkt, "ps": "https://ps.example", "label": "orch" }),
        )
        .unwrap(),
    };
    let (status, body) = call(&app, Method::POST, "/admin/allowed-keys", admin_ctx).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // Now the agent enrolls with only its key.
    let ctx = AgentReq::new(Method::POST, AUTH, "/enroll").into_ctx(
        &sigkey::serialize_hwk(&durable_jwk),
        &durable,
        now_unix(),
    );
    let (status, body) = call(&app, Method::POST, "/enroll", ctx).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The registration is consumed: a different key cannot ride it.
    let other = generate_signing_key();
    let other_jwk = Jwk::from_verifying_key(&other.verifying_key());
    let ctx = AgentReq::new(Method::POST, AUTH, "/enroll").into_ctx(
        &sigkey::serialize_hwk(&other_jwk),
        &other,
        now_unix(),
    );
    let (status, _) = call(&app, Method::POST, "/enroll", ctx).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The bound ps flows into issued tokens.
    let ephemeral = generate_signing_key();
    let token = get_agent_token(&app, &durable, &ephemeral, None).await;
    let decoded = jwt::decode(&token).unwrap();
    assert_eq!(decoded.payload["ps"], "https://ps.example");
}

#[test]
fn config_compat_and_validation() {
    // Legacy `mode` still works.
    let legacy: Config = serde_json::from_value(serde_json::json!({
        "issuer": "https://ap.example",
        "enrollment": { "mode": "open" }
    }))
    .unwrap();
    legacy.validate().unwrap();
    assert!(legacy.enrollment.method_enabled("open"));
    assert!(!legacy.enrollment.method_enabled("token"));

    // Default is token.
    let default: Config =
        serde_json::from_value(serde_json::json!({ "issuer": "https://ap.example" })).unwrap();
    assert!(default.enrollment.method_enabled("token"));

    // federated without issuers is rejected.
    let bad: Config = serde_json::from_value(serde_json::json!({
        "issuer": "https://ap.example",
        "enrollment": { "methods": ["federated"] }
    }))
    .unwrap();
    assert!(bad.validate().is_err());

    // Unknown method rejected.
    let bad2: Config = serde_json::from_value(serde_json::json!({
        "issuer": "https://ap.example",
        "enrollment": { "methods": ["telepathy"] }
    }))
    .unwrap();
    assert!(bad2.validate().is_err());

    // embed_claims may not target reserved names.
    let bad3: Config = serde_json::from_value(serde_json::json!({
        "issuer": "https://ap.example",
        "enrollment": { "methods": ["federated"], "trusted_issuers": [{
            "name": "x", "type": "jwks", "issuer": "https://x.example",
            "jwks": {"keys": []},
            "embed_claims": { "sub": "sub" }
        }]}
    }))
    .unwrap();
    assert!(bad3.validate().is_err());

    // The shipped federated example config parses and validates
    // (issuer file paths are not touched at validate time).
    let example: Config = serde_json::from_str(crate::config::EXAMPLE_CONFIG_FEDERATED).unwrap();
    example.validate().unwrap();
}

// ------------------------------------------------- static enrollment tokens

#[tokio::test]
async fn static_enrollment_token() {
    let json = serde_json::json!({
        "issuer": "https://ap.example",
        "storage": { "backend": "memory" },
        "enrollment": {
            "methods": ["token"],
            "static_tokens": [
                { "token": "dev-enroll-0123456789", "ps": "https://ps.example", "label": "dev" }
            ]
        },
        "admin_token": "test-admin-token",
        "insecure_dev_mode": true,
        "events": { "enabled": false }
    });
    let cfg: Config = serde_json::from_value(json).unwrap();
    cfg.validate().unwrap();
    let app = build_app_with(cfg).await;

    // The SAME static token enrolls multiple distinct agents (reusable).
    let mut agents = Vec::new();
    for _ in 0..2 {
        let durable = generate_signing_key();
        let durable_jwk = Jwk::from_verifying_key(&durable.verifying_key());
        let ctx = AgentReq::new(Method::POST, AUTH, "/enroll")
            .json(serde_json::json!({ "enrollment_token": "dev-enroll-0123456789" }))
            .into_ctx(&sigkey::serialize_hwk(&durable_jwk), &durable, now_unix());
        let (status, body) = call(&app, Method::POST, "/enroll", ctx).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        agents.push((durable, body["agent"].as_str().unwrap().to_string()));

        // The static token's ps flows into issued tokens.
        let (durable_ref, _) = agents.last().unwrap();
        let ephemeral = generate_signing_key();
        let token = get_agent_token(&app, durable_ref, &ephemeral, None).await;
        let decoded = jwt::decode(&token).unwrap();
        assert_eq!(decoded.payload["ps"], "https://ps.example");
    }
    assert_ne!(agents[0].1, agents[1].1, "distinct identities per key");

    // A wrong token is still rejected (no fall-through).
    let durable = generate_signing_key();
    let durable_jwk = Jwk::from_verifying_key(&durable.verifying_key());
    let ctx = AgentReq::new(Method::POST, AUTH, "/enroll")
        .json(serde_json::json!({ "enrollment_token": "wrong-token-0123456789" }))
        .into_ctx(&sigkey::serialize_hwk(&durable_jwk), &durable, now_unix());
    let (status, body) = call(&app, Method::POST, "/enroll", ctx).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "invalid_enrollment_token");
}

#[test]
fn static_token_validation() {
    // Too short is rejected.
    let short: Config = serde_json::from_value(serde_json::json!({
        "issuer": "https://ap.example",
        "enrollment": { "methods": ["token"],
                        "static_tokens": [{ "token": "short" }] }
    }))
    .unwrap();
    assert!(short.validate().is_err());

    // static_tokens without the token method is rejected.
    let mismatched: Config = serde_json::from_value(serde_json::json!({
        "issuer": "https://ap.example",
        "enrollment": { "methods": ["open"],
                        "static_tokens": [{ "token": "dev-enroll-0123456789" }] }
    }))
    .unwrap();
    assert!(mismatched.validate().is_err());

    // A valid entry passes.
    let ok: Config = serde_json::from_value(serde_json::json!({
        "issuer": "https://ap.example",
        "enrollment": { "methods": ["token"],
                        "static_tokens": [{ "token": "dev-enroll-0123456789" }] }
    }))
    .unwrap();
    ok.validate().unwrap();
}
