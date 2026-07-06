//! AAuth Events: the AP as the agent's event inbox.
//!
//! - `POST /subscribe` (agent token)     → mint a subscribe token + eid
//! - `DELETE /subscriptions/{eid}`       → cancel a subscription
//! - `POST /events` (resource, event tok)→ resource delivers an event token
//! - `GET /inbox`   (agent token)        → drain pending events (long-poll)
//!
//! See `research/06-events.md` for the normative validation order.

use std::sync::Arc;
use std::time::Duration;

use aauth_core::jwt::{self, ClaimExt};
use aauth_core::sig::{self, RequestParts, SigError, SigErrorCode, VerifyPolicy};
use aauth_core::sigkey::SigKeyScheme;
use aauth_core::tokens;
use hyper::StatusCode;

use crate::app::App;
use crate::issue;
use crate::problem::{empty_status, json_ok, json_response, ApiError, Resp};
use crate::records::*;
use crate::reqctx::{verify_signature, ReqCtx, Signer};

fn require_events(app: &App) -> Result<(), ApiError> {
    if !app.cfg.events.enabled {
        return Err(ApiError::not_found(
            "not_found",
            "AAuth Events is not enabled on this provider",
        ));
    }
    Ok(())
}

/// `POST /subscribe` — an agent asks the AP to authorize a resource to deliver
/// events. Signed with the agent token.
pub async fn subscribe(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    require_events(app)?;
    let signer = verify_signature(ctx, app, &[]).await?;
    let (claims, signing_jwk) = match signer {
        Signer::AgentToken {
            claims,
            signing_jwk,
        } => (claims, signing_jwk),
        _ => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "subscribe must be signed with an agent token (jwt scheme)",
            ))
        }
    };

    let body = ctx.parse_json()?;
    let resource = body
        .get("resource")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("invalid_request", "resource is required"))?;
    aauth_core::ident::validate_server_identifier(resource, app.cfg.insecure_dev_mode).map_err(
        |_| {
            ApiError::bad_request(
                "invalid_request",
                "resource is not a valid server identifier",
            )
        },
    )?;
    let max_uses = body.get("max_uses").and_then(|v| v.as_u64());
    let ttl = body
        .get("ttl")
        .and_then(|v| v.as_u64())
        .unwrap_or(app.cfg.subscribe_token_ttl_secs)
        .min(app.cfg.subscribe_token_ttl_secs);

    let local = aauth_core::ident::local_part(&claims.sub).to_string();
    let eid = format!("evt_{}", aauth_core::rand_id(20));

    let record = SubscriptionRecord {
        eid: eid.clone(),
        agent_local: local.clone(),
        agent_id: claims.sub.clone(),
        resource: resource.to_string(),
        max_uses,
        created_at: aauth_core::now_unix(),
    };
    // eids are random and unique; store with a generous TTL beyond the token
    // registration window so late deliveries still route.
    let sub_ttl =
        Duration::from_secs(app.cfg.subscribe_token_ttl_secs + app.cfg.events.inbox_ttl_secs);
    app.store
        .put(
            &subscription_key(&eid),
            &serde_json::to_vec(&record).unwrap(),
            Some(sub_ttl),
        )
        .await?;

    let (token, exp) = issue::subscribe_token(
        app,
        &claims.sub,
        &signing_jwk,
        resource,
        &eid,
        max_uses,
        ttl,
    );
    Ok(json_ok(&serde_json::json!({
        "subscribe_token": token,
        "token_type": "aa-subscribe+jwt",
        "eid": eid,
        "expires_in": exp.saturating_sub(aauth_core::now_unix()),
    })))
}

/// `DELETE /subscriptions/{eid}` — cancel. Signed with the owning agent token.
pub async fn cancel_subscription(
    ctx: &ReqCtx,
    app: &Arc<App>,
    eid: &str,
) -> Result<Resp, ApiError> {
    require_events(app)?;
    let signer = verify_signature(ctx, app, &[]).await?;
    let claims = match signer {
        Signer::AgentToken { claims, .. } => claims,
        _ => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "must be signed with an agent token",
            ))
        }
    };
    let raw = app.store.get(&subscription_key(eid)).await?;
    match raw {
        None => Err(ApiError::not_found("not_found", "no such subscription")),
        Some(bytes) => {
            let rec: SubscriptionRecord = serde_json::from_slice(&bytes)
                .map_err(|e| ApiError::server_error(format!("corrupt subscription: {e}")))?;
            if rec.agent_id != claims.sub {
                return Err(ApiError::forbidden(
                    "forbidden",
                    "subscription belongs to another agent",
                ));
            }
            app.store.delete(&subscription_key(eid)).await?;
            app.store.delete(&sub_uses_key(eid)).await?;
            Ok(empty_status(StatusCode::NO_CONTENT))
        }
    }
}

/// `POST /events` — the resource-facing event delivery endpoint. The event
/// token is presented as the `Signature-Key` JWT; the same resource key
/// (discovered from its JWKS) verifies both the JWT and the HTTP signature
/// (the `dwk`-without-`cnf` extension).
pub async fn deliver_event(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    require_events(app)?;

    if ctx.body.len() > app.cfg.events.max_payload_bytes {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "event payload too large",
        ));
    }

    // 1. Parse the request signature to obtain the event-token JWT scheme.
    //    Scope the (non-Send) header closure so it drops before any `.await`.
    let parsed = {
        let lookup = |name: &str| ctx.header(name);
        let parts = RequestParts {
            method: &ctx.method,
            authority: &ctx.authority,
            path: &ctx.path,
            query: &ctx.query,
            header: &lookup,
        };
        let policy = VerifyPolicy {
            now: aauth_core::now_unix(),
            window_secs: app.cfg.signature_window_secs,
            extra_required: vec![],
        };
        sig::parse_request_signature(&parts, &policy).map_err(ApiError::from_sig_error)?
    };
    let event_jwt = match &parsed.scheme {
        SigKeyScheme::Jwt(token) => token.clone(),
        _ => {
            return Err(ApiError::from_sig_error(SigError::new(
                SigErrorCode::InvalidKey,
                "event delivery must present the event token via the jwt scheme",
            )))
        }
    };

    // 2. Decode + validate event-token claims.
    let decoded = jwt::decode(&event_jwt).map_err(|_| {
        ApiError::from_sig_error(SigError::new(
            SigErrorCode::InvalidJwt,
            "malformed event token",
        ))
    })?;
    if decoded.header.typ.as_deref() != Some(tokens::TYP_EVENT) {
        return Err(ApiError::from_sig_error(SigError::new(
            SigErrorCode::InvalidJwt,
            "typ is not aa-event+jwt",
        )));
    }
    let claims =
        tokens::validate_event_token(&decoded, aauth_core::now_unix(), app.cfg.insecure_dev_mode)
            .map_err(|e| {
            ApiError::from_sig_error(SigError::new(SigErrorCode::InvalidJwt, e.to_string()))
        })?;

    // 3. Resolve the resource key from its JWKS (egress-admitted) and verify
    //    the JWT signature, then the HTTP signature with the same key.
    let kid = decoded.header.kid.as_deref().ok_or_else(|| {
        ApiError::from_sig_error(SigError::new(
            SigErrorCode::InvalidJwt,
            "event token missing kid",
        ))
    })?;
    let resource_key = app
        .jwks_cache
        .get_key(&claims.iss, &claims.dwk, kid)
        .await
        .map_err(ApiError::from_sig_error)?;
    jwt::verify_with_jwk(&decoded, &resource_key).map_err(|_| {
        ApiError::from_sig_error(SigError::new(
            SigErrorCode::InvalidJwt,
            "event token signature invalid",
        ))
    })?;
    sig::verify_parsed(&parsed, &resource_key).map_err(ApiError::from_sig_error)?;

    // 4. Look up the subscription by eid.
    let sub_raw = app.store.get(&subscription_key(&claims.eid)).await?;
    let subscription: SubscriptionRecord = match sub_raw {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| ApiError::server_error(format!("corrupt subscription: {e}")))?,
        None => {
            return Err(ApiError::not_found(
                "unknown_subscription",
                "no active subscription for this eid",
            ))
        }
    };

    // 5. iss must match the subscription's authorized resource.
    if subscription.resource != claims.iss {
        return Err(ApiError::forbidden(
            "resource_mismatch",
            "event issuer is not the resource authorized for this subscription",
        ));
    }

    // 8. aud must match the subscribed agent (checked before mutating counters).
    if subscription.agent_id != claims.aud {
        return Err(ApiError::forbidden(
            "agent_mismatch",
            "event aud does not match the subscription's agent",
        ));
    }

    // 7. max_uses accounting (atomic).
    let mut remaining_uses: Option<u64> = None;
    if let Some(max) = subscription.max_uses {
        let used = app.store.incr(&sub_uses_key(&claims.eid)).await? as u64;
        if used > max {
            // roll back the over-count is unnecessary — subscription is done.
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "max_uses_exceeded",
                "subscription use limit reached",
            ));
        }
        remaining_uses = Some(max - used);
    }

    // Durably record for delivery BEFORE returning 202.
    let payload = ctx.parse_json().ok().filter(|v| !v.is_null());
    let item = InboxItem {
        event_token: event_jwt,
        payload,
        received_at: aauth_core::now_unix(),
        iss: claims.iss.clone(),
        eid: claims.eid.clone(),
    };
    app.store
        .list_push(
            &inbox_key(&subscription.agent_local),
            &serde_json::to_vec(&item).unwrap(),
            app.cfg.events.max_pending_per_agent,
        )
        .await?;

    // Exhausted subscription cleanup.
    if remaining_uses == Some(0) {
        app.store.delete(&subscription_key(&claims.eid)).await.ok();
        app.store.delete(&sub_uses_key(&claims.eid)).await.ok();
    }

    let body = match remaining_uses {
        Some(n) => serde_json::json!({ "remaining_uses": n }),
        None => serde_json::json!({}),
    };
    Ok(json_response(StatusCode::ACCEPTED, &body))
}

/// `GET /inbox` — the agent polls (optionally long-polls) for pending events.
/// Signed with the agent token.
pub async fn inbox(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    require_events(app)?;
    let signer = verify_signature(ctx, app, &[]).await?;
    let claims = match signer {
        Signer::AgentToken { claims, .. } => claims,
        _ => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "inbox must be signed with an agent token",
            ))
        }
    };
    let local = AgentId::local_of(&claims.sub);

    // Optional long-poll: honour Prefer: wait=N (capped).
    let wait = parse_prefer_wait(ctx).min(50);
    let deadline = std::time::Instant::now() + Duration::from_secs(wait);

    loop {
        let items = app.store.list_drain(&inbox_key(&local)).await?;
        if !items.is_empty() {
            let now = aauth_core::now_unix();
            let events: Vec<serde_json::Value> = items
                .iter()
                .filter_map(|b| serde_json::from_slice::<InboxItem>(b).ok())
                // drop events whose response window already closed
                .filter_map(|item| {
                    let decoded = jwt::decode(&item.event_token).ok()?;
                    let exp = decoded.payload.int_claim("exp").unwrap_or(0);
                    if (exp as u64) <= now {
                        return None;
                    }
                    Some(serde_json::json!({
                        "event_token": item.event_token,
                        "payload": item.payload,
                        "eid": item.eid,
                        "iss": item.iss,
                    }))
                })
                .collect();
            if !events.is_empty() {
                return Ok(json_ok(&serde_json::json!({ "events": events })));
            }
        }
        if std::time::Instant::now() >= deadline {
            return Ok(json_ok(&serde_json::json!({ "events": [] })));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn parse_prefer_wait(ctx: &ReqCtx) -> u64 {
    ctx.header("prefer")
        .and_then(|p| {
            p.split(',')
                .map(|s| s.trim())
                .find_map(|s| s.strip_prefix("wait=").and_then(|n| n.parse::<u64>().ok()))
        })
        .unwrap_or(0)
}

/// Small helper: extract the local part of an agent identifier without
/// re-validating (already validated when the token was accepted).
trait AgentIdLocal {
    fn local_of(id: &str) -> String;
}
struct AgentId;
impl AgentIdLocal for AgentId {
    fn local_of(id: &str) -> String {
        id.strip_prefix("aauth:")
            .and_then(|r| r.rsplit_once('@'))
            .map(|(l, _)| l.to_string())
            .unwrap_or_default()
    }
}
