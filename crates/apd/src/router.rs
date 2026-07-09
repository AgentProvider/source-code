//! Request routing. Dispatches method+path to handlers, catching panics into
//! 500s and normalizing all errors into problem+json.

use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Method, Request, StatusCode};

use crate::app::App;
use crate::handlers::{admin, agent, events, wellknown};
use crate::problem::{ApiError, Resp};
use crate::reqctx::ReqCtx;

pub async fn route(req: Request<Incoming>, app: Arc<App>) -> Resp {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Well-known documents are unsigned GETs; serve them before reading a body.
    match (&method, path.as_str()) {
        (&Method::GET, "/.well-known/aauth-agent.json") => return wellknown::agent_metadata(&app),
        (&Method::GET, "/.well-known/jwks.json") => return wellknown::jwks(&app),
        (&Method::GET, "/healthz") => {
            return crate::problem::json_ok(&serde_json::json!({
                "status": "ok",
                // TEMPORARY: "demo" while AAuth remains an Internet-Draft
                // (see the demo-mode notice in main.rs).
                "mode": "demo",
                "issuer": app.cfg.issuer,
                "uptime_secs": aauth_core::now_unix().saturating_sub(app.started_at),
            }));
        }
        _ => {}
    }

    let ctx = match ReqCtx::read(req, app.cfg.max_body_bytes).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let result = dispatch(&method, &path, &ctx, &app).await;
    match result {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

pub(crate) async fn dispatch(
    method: &Method,
    path: &str,
    ctx: &ReqCtx,
    app: &Arc<App>,
) -> Result<Resp, ApiError> {
    match (method, path) {
        (&Method::POST, "/enroll") => agent::enroll(ctx, app).await,
        (&Method::POST, "/agent-token") => agent::agent_token(ctx, app).await,
        (&Method::POST, "/subagent-token") => agent::subagent_token(ctx, app).await,

        (&Method::POST, "/subscribe") => events::subscribe(ctx, app).await,
        (&Method::POST, "/events") => events::deliver_event(ctx, app).await,
        (&Method::GET, "/inbox") => events::inbox(ctx, app).await,

        (&Method::POST, "/admin/enrollment-tokens") => admin::mint_enrollment_token(ctx, app).await,
        (&Method::GET, "/admin/agents") => admin::list_agents(ctx, app).await,
        (&Method::POST, "/admin/allowed-keys") => admin::add_allowed_key(ctx, app).await,
        (&Method::GET, "/admin/allowed-keys") => admin::list_allowed_keys(ctx, app).await,

        _ => {
            // Parameterized routes.
            if let Some(eid) = path.strip_prefix("/subscriptions/") {
                if method == Method::DELETE && !eid.is_empty() && !eid.contains('/') {
                    return events::cancel_subscription(ctx, app, eid).await;
                }
            }
            if let Some(jkt) = path.strip_prefix("/admin/allowed-keys/") {
                if method == Method::DELETE && !jkt.is_empty() && !jkt.contains('/') {
                    return admin::remove_allowed_key(ctx, app, jkt).await;
                }
            }
            if let Some(rest) = path.strip_prefix("/admin/agents/") {
                if let Some(local) = rest.strip_suffix("/revoke") {
                    if method == Method::POST {
                        return admin::revoke_agent(ctx, app, local).await;
                    }
                } else if let Some(local) = rest.strip_suffix("/reinstate") {
                    if method == Method::POST {
                        return admin::reinstate_agent(ctx, app, local).await;
                    }
                } else if method == Method::GET && !rest.is_empty() && !rest.contains('/') {
                    return admin::get_agent(ctx, app, rest).await;
                }
            }
            Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                format!("no route for {method} {path}"),
            ))
        }
    }
}
