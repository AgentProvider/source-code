//! Admin API under `/admin/*`, gated by a bearer token (config/env).
//! Constant-time token comparison; disabled entirely when no token is set.

use std::sync::Arc;
use std::time::Duration;

use hyper::StatusCode;

use crate::app::App;
use crate::problem::{empty_status, json_ok, json_response, ApiError, Resp};
use crate::records::*;
use crate::reqctx::ReqCtx;

use crate::enrollment::constant_time_eq as ct_eq;

fn authorize(ctx: &ReqCtx, app: &App) -> Result<(), ApiError> {
    let configured = app.cfg.admin_token.as_deref().ok_or_else(|| {
        ApiError::not_found(
            "not_found",
            "admin API is disabled (no admin token configured)",
        )
    })?;
    let presented = ctx
        .header("authorization")
        .and_then(|h| h.strip_prefix("Bearer ").map(|s| s.to_string()))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing bearer token",
            )
        })?;
    if ct_eq(presented.as_bytes(), configured.as_bytes()) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid admin token",
        ))
    }
}

/// `POST /admin/enrollment-tokens` → mint a single-use enrollment token.
pub async fn mint_enrollment_token(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    authorize(ctx, app)?;
    let body = ctx.parse_json()?;
    let ps = body.get("ps").and_then(|v| v.as_str());
    if let Some(ps) = ps {
        aauth_core::ident::validate_server_identifier(ps, app.cfg.insecure_dev_mode).map_err(
            |_| ApiError::bad_request("invalid_request", "ps is not a valid server identifier"),
        )?;
    }
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let ttl_secs = body.get("ttl").and_then(|v| v.as_u64()).unwrap_or(3600);

    let token = aauth_core::rand_token(192);
    let record = EnrollTokenRecord {
        ps: ps.map(|s| s.to_string()),
        label,
        created_at: aauth_core::now_unix(),
    };
    app.store
        .put(
            &enroll_token_key(&token),
            &serde_json::to_vec(&record).unwrap(),
            Some(Duration::from_secs(ttl_secs)),
        )
        .await?;
    app.audit.emit(
        "enrollment_token_minted",
        serde_json::json!({ "ps": record.ps, "label": record.label, "ttl": ttl_secs }),
    );
    Ok(json_response(
        StatusCode::CREATED,
        &serde_json::json!({ "enrollment_token": token, "expires_in": ttl_secs }),
    ))
}

/// `POST /admin/allowed-keys` → pre-register a durable-key thumbprint so an
/// agent holding that key may enroll (the `allowlist` method). This is the
/// API-driven delegation path for orchestrators: register the key you just
/// provisioned, no secret travels to the workload.
pub async fn add_allowed_key(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    authorize(ctx, app)?;
    if !app.cfg.enrollment.method_enabled("allowlist") {
        return Err(ApiError::bad_request(
            "method_disabled",
            "the allowlist enrollment method is not enabled",
        ));
    }
    let body = ctx.parse_json()?;
    let jkt = body
        .get("jkt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("invalid_request", "jkt is required"))?;
    // A JWK SHA-256 thumbprint is 32 bytes base64url = 43 chars.
    if aauth_core::b64::decode(jkt).map(|b| b.len()) != Ok(32) {
        return Err(ApiError::bad_request(
            "invalid_request",
            "jkt must be a base64url SHA-256 JWK thumbprint (43 chars)",
        ));
    }
    let ps = body.get("ps").and_then(|v| v.as_str());
    if let Some(ps) = ps {
        aauth_core::ident::validate_server_identifier(ps, app.cfg.insecure_dev_mode).map_err(
            |_| ApiError::bad_request("invalid_request", "ps is not a valid server identifier"),
        )?;
    }
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let ttl = body.get("ttl").and_then(|v| v.as_u64());

    let record = AllowedKeyRecord {
        jkt: jkt.to_string(),
        ps: ps.map(|s| s.to_string()),
        label,
        created_at: aauth_core::now_unix(),
    };
    app.store
        .put(
            &allowed_key_key(jkt),
            &serde_json::to_vec(&record).unwrap(),
            ttl.map(Duration::from_secs),
        )
        .await?;
    app.audit.emit(
        "allowed_key_added",
        serde_json::json!({ "jkt": jkt, "ps": record.ps, "label": record.label, "ttl": ttl }),
    );
    Ok(json_response(
        StatusCode::CREATED,
        &serde_json::json!({ "jkt": jkt, "status": "allowed" }),
    ))
}

/// `GET /admin/allowed-keys` → list pending pre-registered keys.
pub async fn list_allowed_keys(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    authorize(ctx, app)?;
    let entries = app.store.scan_prefix("allowkey:").await?;
    let keys: Vec<serde_json::Value> = entries
        .iter()
        .filter_map(|(_, v)| serde_json::from_slice::<AllowedKeyRecord>(v).ok())
        .map(|r| serde_json::to_value(r).unwrap())
        .collect();
    Ok(json_ok(
        &serde_json::json!({ "allowed_keys": keys, "count": keys.len() }),
    ))
}

/// `DELETE /admin/allowed-keys/{jkt}` → withdraw a pre-registration.
pub async fn remove_allowed_key(ctx: &ReqCtx, app: &Arc<App>, jkt: &str) -> Result<Resp, ApiError> {
    authorize(ctx, app)?;
    let removed = app.store.delete(&allowed_key_key(jkt)).await?;
    if !removed {
        return Err(ApiError::not_found("not_found", "no such allowed key"));
    }
    app.audit
        .emit("allowed_key_removed", serde_json::json!({ "jkt": jkt }));
    Ok(empty_status(StatusCode::NO_CONTENT))
}

/// `GET /admin/agents` → list enrolled agents.
pub async fn list_agents(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    authorize(ctx, app)?;
    let entries = app.store.scan_prefix("agent:").await?;
    let agents: Vec<serde_json::Value> = entries
        .iter()
        .filter_map(|(_, v)| serde_json::from_slice::<AgentRecord>(v).ok())
        .map(|r| {
            serde_json::json!({
                "agent": format!("aauth:{}@{}", r.local, app.cfg.agent_domain()),
                "local": r.local,
                "durable_jkt": r.durable_jkt,
                "ps": r.ps,
                "platform": r.platform,
                "label": r.label,
                "status": r.status,
                "created_at": r.created_at,
                "last_issued_at": r.last_issued_at,
                "tokens_issued": r.tokens_issued,
            })
        })
        .collect();
    Ok(json_ok(
        &serde_json::json!({ "agents": agents, "count": agents.len() }),
    ))
}

/// `GET /admin/agents/{local}` → one agent.
pub async fn get_agent(ctx: &ReqCtx, app: &Arc<App>, local: &str) -> Result<Resp, ApiError> {
    authorize(ctx, app)?;
    let rec = load_agent(app, local).await?;
    Ok(json_ok(&serde_json::to_value(rec).unwrap()))
}

/// `POST /admin/agents/{local}/revoke` → refuse future token issuance, and
/// tell the agent's Person Server about the tokens already out there.
///
/// Local revocation is authoritative and happens first. The PS notification is
/// best effort (protocol spec, Token Revocation): its outcome is reported and
/// audited, but a PS we cannot reach never fails the operation — that access is
/// then bounded by the token lifetime, exactly as the spec describes.
pub async fn revoke_agent(ctx: &ReqCtx, app: &Arc<App>, local: &str) -> Result<Resp, ApiError> {
    authorize(ctx, app)?;
    let ps = persist_status(app, local, STATUS_REVOKED).await?;

    let outcome = crate::revocation::notify_ps(app, local, ps.as_deref()).await;
    app.audit.emit(
        "agent_revoked",
        serde_json::json!({ "local": local, "ps_notification": outcome }),
    );
    Ok(json_ok(&serde_json::json!({
        "local": local,
        "status": STATUS_REVOKED,
        "ps_notification": outcome,
    })))
}

/// `POST /admin/agents/{local}/reinstate`
pub async fn reinstate_agent(ctx: &ReqCtx, app: &Arc<App>, local: &str) -> Result<Resp, ApiError> {
    authorize(ctx, app)?;
    persist_status(app, local, STATUS_ACTIVE).await?;
    app.audit
        .emit("agent_reinstated", serde_json::json!({ "local": local }));
    Ok(json_ok(
        &serde_json::json!({ "local": local, "status": STATUS_ACTIVE }),
    ))
}

async fn load_agent(app: &App, local: &str) -> Result<AgentRecord, ApiError> {
    let raw = app
        .store
        .get(&agent_key(local))
        .await?
        .ok_or_else(|| ApiError::not_found("not_found", "no such agent"))?;
    serde_json::from_slice(&raw).map_err(|e| ApiError::server_error(format!("corrupt record: {e}")))
}

/// Set the enrollment's status and persist it. Returns the record's `ps`, which
/// the revoke path needs to reach the right Person Server. Callers emit their
/// own audit event, because revoke carries the notification outcome with it.
async fn persist_status(
    app: &Arc<App>,
    local: &str,
    status: &str,
) -> Result<Option<String>, ApiError> {
    let mut rec = load_agent(app, local).await?;
    rec.status = status.to_string();
    let ps = rec.ps.clone();
    app.store
        .put(&agent_key(local), &serde_json::to_vec(&rec).unwrap(), None)
        .await?;
    Ok(ps)
}
