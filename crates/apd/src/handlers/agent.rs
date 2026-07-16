//! Agent-facing ceremony endpoints: enrollment, agent-token issuance/refresh,
//! and sub-agent token issuance. See `research/02-agent-provider.md` §5 and
//! `research/04-connecting-agents.md`.

use std::sync::Arc;
use std::time::Duration;

use aauth_core::ident::AgentId;
use aauth_core::jwk::Jwk;
use hyper::StatusCode;

use crate::app::App;
use crate::enrollment::{verify_assertion, Authorized};
use crate::issue;
use crate::problem::{json_ok, json_response, ApiError, Resp};
use crate::records::*;
use crate::reqctx::{verify_signature, ReqCtx, Signer};

/// Validate a caller-supplied `ps` value against config and policy.
fn resolve_ps(
    app: &App,
    enrollment_ps: Option<&str>,
    requested: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let requested = match requested {
        Some(p) => {
            aauth_core::ident::validate_server_identifier(p, app.cfg.insecure_dev_mode).map_err(
                |_| ApiError::bad_request("invalid_request", "ps is not a valid server identifier"),
            )?;
            Some(p.to_string())
        }
        None => None,
    };
    match (enrollment_ps, requested) {
        (Some(e), Some(r)) => {
            if e != r && !app.cfg.allow_ps_override {
                return Err(ApiError::forbidden(
                    "ps_mismatch",
                    "requested ps differs from the enrollment's bound ps and override is disabled",
                ));
            }
            Ok(Some(r))
        }
        (Some(e), None) => Ok(Some(e.to_string())),
        (None, Some(r)) => Ok(Some(r)),
        (None, None) => Ok(app.cfg.enrollment.default_ps.clone()),
    }
}

/// Resolve which enabled enrollment method authorizes this request.
/// Order: presented assertion → presented token → allow-list → open.
/// A presented-but-invalid credential is a hard failure (no fall-through).
async fn authorize_enrollment(
    app: &Arc<App>,
    body: &serde_json::Value,
    durable_jwk: &Jwk,
    durable_jkt: &str,
) -> Result<Authorized, ApiError> {
    let enrollment = &app.cfg.enrollment;

    // 1. Federated assertion.
    if let Some(assertion) = body.get("enrollment_assertion").and_then(|v| v.as_str()) {
        if !enrollment.method_enabled("federated") {
            return Err(ApiError::forbidden(
                "method_disabled",
                "federated enrollment is not enabled on this provider",
            ));
        }
        let verdict = verify_assertion(
            &app.issuers,
            assertion,
            durable_jwk,
            aauth_core::now_unix(),
            &app.cfg.issuer,
        )
        .await
        .map_err(|reason| {
            app.audit.emit(
                "enroll_denied",
                serde_json::json!({ "method": "federated", "jkt": durable_jkt, "reason": reason }),
            );
            ApiError::forbidden("invalid_assertion", reason)
        })?;
        // Replay guard for single-use assertions (atomic; storage-backed so it
        // holds across instances).
        if let Some((jti, ttl)) = &verdict.consume_jti {
            let fresh = app
                .store
                .put_if_absent(
                    &assertion_jti_key(jti),
                    durable_jkt.as_bytes(),
                    Some(Duration::from_secs(*ttl)),
                )
                .await?;
            if !fresh {
                // Idempotent retry with the SAME key is fine; a different key
                // presenting the same jti is a replay.
                let holder = app.store.get(&assertion_jti_key(jti)).await?;
                if holder.as_deref() != Some(durable_jkt.as_bytes()) {
                    app.audit.emit(
                        "enroll_denied",
                        serde_json::json!({
                            "method": "federated", "jkt": durable_jkt,
                            "reason": "assertion jti replayed with a different key"
                        }),
                    );
                    return Err(ApiError::forbidden(
                        "invalid_assertion",
                        "assertion has already been used",
                    ));
                }
            }
        }
        return Ok(Authorized::Federated(verdict));
    }

    // 2. Enrollment token — a predefined static token (reusable,
    //    config-defined; dev/staging convenience) or a minted single-use one.
    if let Some(token) = body.get("enrollment_token").and_then(|v| v.as_str()) {
        if !enrollment.method_enabled("token") {
            return Err(ApiError::forbidden(
                "method_disabled",
                "token enrollment is not enabled on this provider",
            ));
        }
        if let Some(st) = enrollment
            .static_tokens
            .iter()
            .find(|st| crate::enrollment::constant_time_eq(st.token.as_bytes(), token.as_bytes()))
        {
            return Ok(Authorized::Token {
                ps: st.ps.clone(),
                label: st.label.clone(),
                static_token: true,
            });
        }
        let consumed = app.store.take(&enroll_token_key(token)).await?;
        let rec = consumed.ok_or_else(|| {
            app.audit.emit(
                "enroll_denied",
                serde_json::json!({ "method": "token", "jkt": durable_jkt,
                                    "reason": "unknown, expired, or already-used token" }),
            );
            ApiError::forbidden(
                "invalid_enrollment_token",
                "enrollment token is unknown, expired, or already used",
            )
        })?;
        let rec: Option<EnrollTokenRecord> = serde_json::from_slice(&rec).ok();
        return Ok(Authorized::Token {
            ps: rec.as_ref().and_then(|r| r.ps.clone()),
            label: rec.and_then(|r| r.label),
            static_token: false,
        });
    }

    // 3. Thumbprint allow-list.
    if enrollment.method_enabled("allowlist") {
        if let Some(raw) = app.store.take(&allowed_key_key(durable_jkt)).await? {
            let rec: Option<AllowedKeyRecord> = serde_json::from_slice(&raw).ok();
            return Ok(Authorized::Allowlist {
                ps: rec.as_ref().and_then(|r| r.ps.clone()),
                label: rec.and_then(|r| r.label),
            });
        }
    }

    // 4. Open.
    if enrollment.method_enabled("open") {
        return Ok(Authorized::Open);
    }

    app.audit.emit(
        "enroll_denied",
        serde_json::json!({ "method": "none", "jkt": durable_jkt,
                            "reason": "no credential presented and no permissive method enabled" }),
    );
    Err(ApiError::forbidden(
        "enrollment_required",
        "an enrollment_token or enrollment_assertion is required",
    ))
}

/// `POST /enroll` — establish an agent identity, keyed by the durable key
/// thumbprint. Signed with `hwk` (the durable key). Authorization is by any
/// enabled method: a federated assertion, an enrollment token, the key
/// allow-list, or open mode.
pub async fn enroll(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let signer = verify_signature(ctx, app, &[]).await?;
    let (durable_jwk, durable_jkt) = match &signer {
        Signer::Hwk { jwk } => {
            let jkt = jwk
                .thumbprint()
                .map_err(|_| ApiError::bad_request("invalid_key", "unsupported durable key"))?;
            (jwk.clone(), jkt)
        }
        _ => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "enrollment must be signed with the hwk scheme (durable key)",
            ))
        }
    };

    let body = ctx.parse_json()?;
    let ps_req = body.get("ps").and_then(|v| v.as_str());
    let platform = body
        .get("platform")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let body_label = body
        .get("label")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // If this durable key already enrolled, return the existing identity
    // (idempotent enrollment) BEFORE consuming any credential.
    if let Some(existing_local) = app.store.get(&jkt_key(&durable_jkt)).await? {
        let local = String::from_utf8_lossy(&existing_local).to_string();
        let agent_id = AgentId::new(&local, &app.cfg.agent_domain()).unwrap();
        return Ok(json_response(
            StatusCode::OK,
            &serde_json::json!({ "agent": agent_id.to_string(), "status": "existing" }),
        ));
    }

    let authorized = authorize_enrollment(app, &body, &durable_jwk, &durable_jkt).await?;

    // Resolve PS / label / federated metadata from the authorizing method.
    let (bound_ps, bound_label, issuer_name, assertion_iss, subject, embed_claims) =
        match &authorized {
            Authorized::Federated(v) => {
                // An issuer PS pin is authoritative: a conflicting request is an error.
                if let (Some(pin), Some(req)) = (&v.ps_pin, ps_req) {
                    if pin != req {
                        return Err(ApiError::forbidden(
                            "ps_mismatch",
                            "this issuer pins the Person Server; the requested ps conflicts",
                        ));
                    }
                }
                (
                    v.ps_pin.clone(),
                    v.label.clone(),
                    Some(v.issuer_name.clone()),
                    Some(v.issuer.clone()),
                    v.subject.clone(),
                    if v.embed.is_empty() {
                        None
                    } else {
                        Some(v.embed.clone())
                    },
                )
            }
            Authorized::Token { ps, label, .. } | Authorized::Allowlist { ps, label } => {
                (ps.clone(), label.clone(), None, None, None, None)
            }
            Authorized::Open => (None, None, None, None, None, None),
        };

    let ps = resolve_ps(app, bound_ps.as_deref(), ps_req)?;
    let label = bound_label.or(body_label);

    // Allocate a unique local part. We use a random opaque identifier
    // (draft-hardt-aauth-bootstrap-01 §6 permits any opaque scheme). Per §6,
    // if this is ever switched to a deterministic derivation it MUST key off
    // the *durable* key thumbprint (`durable_jkt`), never the ephemeral key —
    // the ephemeral key rotates on every refresh and is not a stable identity.
    let mut local = aauth_core::rand_id(16);
    for _ in 0..5 {
        if app
            .store
            .put_if_absent(
                &agent_key(&local),
                b"reserved",
                Some(Duration::from_secs(30)),
            )
            .await?
        {
            break;
        }
        local = aauth_core::rand_id(16);
    }

    let record = AgentRecord {
        local: local.clone(),
        durable_jkt: durable_jkt.clone(),
        ps: ps.clone(),
        platform,
        label,
        created_at: aauth_core::now_unix(),
        status: STATUS_ACTIVE.into(),
        last_issued_at: 0,
        tokens_issued: 0,
        method: authorized.method().to_string(),
        issuer: issuer_name.clone(),
        subject: subject.clone(),
        embed_claims,
    };
    app.store
        .put(
            &agent_key(&local),
            &serde_json::to_vec(&record).unwrap(),
            None,
        )
        .await?;
    app.store
        .put(&jkt_key(&durable_jkt), local.as_bytes(), None)
        .await?;

    let agent_id = AgentId::new(&local, &app.cfg.agent_domain()).unwrap();
    let token_kind = match &authorized {
        Authorized::Token { static_token, .. } => {
            Some(if *static_token { "static" } else { "minted" })
        }
        _ => None,
    };
    app.audit.emit(
        "enroll",
        serde_json::json!({
            "agent": agent_id.to_string(),
            "method": authorized.method(),
            "token_kind": token_kind,
            "issuer": issuer_name,
            "assertion_iss": assertion_iss,
            "subject": subject,
            "jkt": durable_jkt,
            "ps": ps,
        }),
    );
    Ok(json_response(
        StatusCode::CREATED,
        &serde_json::json!({ "agent": agent_id.to_string(), "status": "enrolled" }),
    ))
}

/// Load the active agent record for a durable key thumbprint.
async fn active_record_for_jkt(app: &App, jkt: &str) -> Result<AgentRecord, ApiError> {
    let local = app.store.get(&jkt_key(jkt)).await?.ok_or_else(|| {
        ApiError::forbidden("not_enrolled", "no enrollment for this key; enroll first")
    })?;
    let local = String::from_utf8_lossy(&local).to_string();
    let rec =
        app.store.get(&agent_key(&local)).await?.ok_or_else(|| {
            ApiError::server_error("enrollment index points to missing agent record")
        })?;
    let rec: AgentRecord = serde_json::from_slice(&rec)
        .map_err(|e| ApiError::server_error(format!("corrupt agent record: {e}")))?;
    if rec.status != STATUS_ACTIVE {
        return Err(ApiError::forbidden(
            "enrollment_revoked",
            "this enrollment has been revoked by the operator",
        ));
    }
    Ok(rec)
}

/// `POST /agent-token` — issue/refresh an agent token.
///
/// Two-key refresh: sign with `jkt-jwt` (durable delegates to ephemeral).
/// Single-key refresh: sign with `hwk` (durable key directly).
pub async fn agent_token(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let signer = verify_signature(ctx, app, &[]).await?;
    let (durable_jkt, ephemeral_jwk, jti): (String, Jwk, Option<String>) = match signer {
        Signer::JktJwt {
            durable_jkt,
            ephemeral_jwk,
            jti,
        } => (durable_jkt, ephemeral_jwk, jti),
        Signer::Hwk { jwk } => {
            let jkt = jwk
                .thumbprint()
                .map_err(|_| ApiError::bad_request("invalid_key", "unsupported key"))?;
            // single-key: the durable key is also the signing key
            (jkt, jwk, None)
        }
        Signer::AgentToken { .. } => return Err(ApiError::bad_request(
            "invalid_request",
            "agent-token requests must be signed with jkt-jwt or hwk, not an existing agent token",
        )),
    };

    // Replay-guard the naming JWT (two-key path).
    if let Some(jti) = &jti {
        let ttl = Duration::from_secs(app.cfg.naming_jwt_max_lifetime_secs.max(60));
        let fresh = app
            .store
            .put_if_absent(&jti_key(jti), b"1", Some(ttl))
            .await?;
        if !fresh {
            return Err(ApiError::from_sig_error(aauth_core::sig::SigError::new(
                aauth_core::sig::SigErrorCode::InvalidJwt,
                "naming JWT jti already used (replay)",
            )));
        }
    }

    let mut record = active_record_for_jkt(app, &durable_jkt).await?;

    // Refresh is the AP's policy re-evaluation point (bootstrap draft §8): a
    // future platform-attestation method (App Attest / Play Integrity, §8.3)
    // would gate here on a fresh, server-nominated, single-use nonce bound to
    // the attestation (§10.4). apd does not implement client attestation today;
    // federated-enrollment replay protection (assertion `jti`) is the analog.

    let body = ctx.parse_json()?;
    let ps_req = body.get("ps").and_then(|v| v.as_str());
    let ps = resolve_ps(app, record.ps.as_deref(), ps_req)?;

    let (token, exp) = issue::agent_token(
        app,
        &record.local,
        &ephemeral_jwk,
        ps.as_deref(),
        app.cfg.agent_token_ttl_secs,
        record.embed_claims.as_ref(),
    );

    // Best-effort issuance accounting.
    record.last_issued_at = aauth_core::now_unix();
    record.tokens_issued += 1;
    if let Some(p) = &ps {
        record.ps = Some(p.clone());
    }
    let _ = app
        .store
        .put(
            &agent_key(&record.local),
            &serde_json::to_vec(&record).unwrap(),
            None,
        )
        .await;

    let agent_id = AgentId::new(&record.local, &app.cfg.agent_domain()).unwrap();
    app.audit.emit(
        "agent_token_issued",
        serde_json::json!({ "agent": agent_id.to_string(), "jkt": durable_jkt }),
    );
    Ok(json_ok(&serde_json::json!({
        "agent_token": token,
        "token_type": "aa-agent+jwt",
        "expires_in": exp.saturating_sub(aauth_core::now_unix()),
        "agent": agent_id.to_string(),
    })))
}

/// `POST /subagent-token` — a parent mints a sub-agent identity.
/// Signed with the parent's *agent token* (jwt scheme).
pub async fn subagent_token(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let signer = verify_signature(ctx, app, &[]).await?;
    let parent_claims = match signer {
        Signer::AgentToken { claims, .. } => claims,
        _ => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "sub-agent requests must be signed with the parent's agent token (jwt scheme)",
            ))
        }
    };

    // Enforce single-level depth: the signer must be top-level.
    if parent_claims.parent_agent.is_some() {
        return Err(ApiError::forbidden(
            "nested_subagent",
            "a sub-agent may not create sub-agents (single-level delegation)",
        ));
    }
    let parent = AgentId::parse(&parent_claims.sub)
        .map_err(|_| ApiError::server_error("parent agent id invalid"))?;
    if parent.is_subagent_named() {
        return Err(ApiError::forbidden(
            "nested_subagent",
            "parent agent id is itself a sub-agent",
        ));
    }

    let body = ctx.parse_json()?;
    let discriminator = body
        .get("discriminator")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("invalid_request", "discriminator is required"))?;
    if !aauth_core::ident::valid_discriminator(discriminator) {
        return Err(ApiError::bad_request(
            "invalid_request",
            "discriminator must be non-empty, lowercase LDH/._, and contain no '+'",
        ));
    }
    let cnf_jwk_val = body.get("cnf_jwk").ok_or_else(|| {
        ApiError::bad_request(
            "invalid_request",
            "cnf_jwk (sub-agent public key) is required",
        )
    })?;
    let cnf_jwk: Jwk = serde_json::from_value(cnf_jwk_val.clone())
        .map_err(|_| ApiError::bad_request("invalid_request", "cnf_jwk is not a valid JWK"))?;
    cnf_jwk
        .verifying_key()
        .map_err(|_| ApiError::bad_request("invalid_key", "cnf_jwk is not a usable Ed25519 key"))?;

    // Sub-agents inherit the parent enrollment's embedded claims.
    let parent_embed = app
        .store
        .get(&agent_key(&parent.local))
        .await?
        .and_then(|raw| serde_json::from_slice::<AgentRecord>(&raw).ok())
        .and_then(|r| r.embed_claims);

    let (token, exp) = issue::subagent_token(
        app,
        &parent,
        discriminator,
        &cnf_jwk,
        parent_claims.ps.as_deref(),
        parent_claims.exp,
        parent_embed.as_ref(),
    )
    .map_err(|e| ApiError::bad_request("invalid_request", e))?;

    let sub_id = parent.subagent(discriminator).unwrap();
    app.audit.emit(
        "subagent_token_issued",
        serde_json::json!({ "agent": sub_id.to_string(), "parent": parent.to_string() }),
    );
    Ok(json_ok(&serde_json::json!({
        "agent_token": token,
        "token_type": "aa-agent+jwt",
        "expires_in": exp.saturating_sub(aauth_core::now_unix()),
        "agent": sub_id.to_string(),
        "parent_agent": parent.to_string(),
    })))
}
