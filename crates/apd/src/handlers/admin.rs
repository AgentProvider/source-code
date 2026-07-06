//! Admin API under `/admin/*`, gated by a bearer token (config/env).
//! Constant-time token comparison; disabled entirely when no token is set.

use std::sync::Arc;
use std::time::Duration;

use hyper::StatusCode;

use crate::app::App;
use crate::problem::{json_ok, json_response, ApiError, Resp};
use crate::records::*;
use crate::reqctx::ReqCtx;

/// Constant-time equality for the admin bearer token.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

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
    Ok(json_response(
        StatusCode::CREATED,
        &serde_json::json!({ "enrollment_token": token, "expires_in": ttl_secs }),
    ))
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

/// `POST /admin/agents/{local}/revoke` → refuse future token issuance.
pub async fn revoke_agent(ctx: &ReqCtx, app: &Arc<App>, local: &str) -> Result<Resp, ApiError> {
    authorize(ctx, app)?;
    set_status(app, local, STATUS_REVOKED).await
}

/// `POST /admin/agents/{local}/reinstate`
pub async fn reinstate_agent(ctx: &ReqCtx, app: &Arc<App>, local: &str) -> Result<Resp, ApiError> {
    authorize(ctx, app)?;
    set_status(app, local, STATUS_ACTIVE).await
}

async fn load_agent(app: &App, local: &str) -> Result<AgentRecord, ApiError> {
    let raw = app
        .store
        .get(&agent_key(local))
        .await?
        .ok_or_else(|| ApiError::not_found("not_found", "no such agent"))?;
    serde_json::from_slice(&raw).map_err(|e| ApiError::server_error(format!("corrupt record: {e}")))
}

async fn set_status(app: &Arc<App>, local: &str, status: &str) -> Result<Resp, ApiError> {
    let mut rec = load_agent(app, local).await?;
    rec.status = status.to_string();
    app.store
        .put(&agent_key(local), &serde_json::to_vec(&rec).unwrap(), None)
        .await?;
    Ok(json_ok(
        &serde_json::json!({ "local": local, "status": status }),
    ))
}
