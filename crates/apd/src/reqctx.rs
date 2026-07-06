//! Per-request context: buffers the body, exposes headers/target for RFC 9421
//! signature verification, and drives the AAuth Signature-Key schemes the AP
//! accepts on its endpoints.

use std::sync::Arc;

use aauth_core::jwk::Jwk;
use aauth_core::sig::{self, RequestParts, SigError, SigErrorCode, VerifyPolicy};
use aauth_core::sigkey::SigKeyScheme;
use aauth_core::tokens;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, StatusCode};

use crate::app::App;
use crate::problem::ApiError;

pub struct ReqCtx {
    pub method: String,
    pub authority: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ReqCtx {
    /// Read a request, enforcing the body size limit.
    pub async fn read(req: Request<Incoming>, max_body: usize) -> Result<ReqCtx, ApiError> {
        let (parts, body) = req.into_parts();
        let method = parts.method.as_str().to_string();
        let path = parts.uri.path().to_string();
        let query = parts
            .uri
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();

        // @authority: prefer Host header, lowercased.
        let authority = parts
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase())
            .or_else(|| {
                parts
                    .uri
                    .authority()
                    .map(|a| a.as_str().to_ascii_lowercase())
            })
            .unwrap_or_default();

        let mut headers = Vec::new();
        for (name, value) in parts.headers.iter() {
            if let Ok(v) = value.to_str() {
                headers.push((name.as_str().to_ascii_lowercase(), v.to_string()));
            }
        }

        let collected = http_body_util::Limited::new(body, max_body)
            .collect()
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "invalid_request",
                    "request body too large or unreadable",
                )
            })?;

        Ok(ReqCtx {
            method,
            authority,
            path,
            query,
            headers,
            body: collected.to_bytes().to_vec(),
        })
    }

    /// Canonical header lookup per RFC 9421 (comma-join repeats, trim OWS).
    pub fn header(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.trim())
            .collect();
        if values.is_empty() {
            None
        } else {
            Some(values.join(", "))
        }
    }

    pub fn parse_json(&self) -> Result<serde_json::Value, ApiError> {
        if self.body.is_empty() {
            return Ok(serde_json::json!({}));
        }
        serde_json::from_slice(&self.body).map_err(|e| {
            ApiError::bad_request("invalid_request", format!("invalid JSON body: {e}"))
        })
    }

    fn request_parts<'a>(&'a self, lookup: &'a dyn Fn(&str) -> Option<String>) -> RequestParts<'a> {
        RequestParts {
            method: &self.method,
            authority: &self.authority,
            path: &self.path,
            query: &self.query,
            header: lookup,
        }
    }

    fn verify_policy(&self, app: &App, extra_required: Vec<String>) -> VerifyPolicy {
        VerifyPolicy {
            now: aauth_core::now_unix(),
            window_secs: app.cfg.signature_window_secs,
            extra_required,
        }
    }
}

/// The successfully-verified signer of a request.
pub enum Signer {
    /// `hwk` scheme — a bare inline key (used at enrollment / single-key refresh).
    Hwk { jwk: Jwk },
    /// `jkt-jwt` scheme — durable key delegating to an ephemeral key.
    JktJwt {
        durable_jkt: String,
        ephemeral_jwk: Jwk,
        jti: Option<String>,
    },
    /// `jwt` scheme carrying one of our own agent tokens — verified locally.
    /// Boxed: `AgentTokenClaims` is much larger than the other variants.
    AgentToken {
        claims: Box<tokens::AgentTokenClaims>,
        signing_jwk: Jwk,
    },
}

/// Verify an HTTP Message Signature and resolve the signer, restricting to the
/// schemes valid for AP ceremony endpoints. `extra_required` names additional
/// covered components (e.g. `content-digest`) beyond the AAuth base four.
pub async fn verify_signature(
    ctx: &ReqCtx,
    app: &Arc<App>,
    extra_required: &[&str],
) -> Result<Signer, ApiError> {
    let lookup = |name: &str| ctx.header(name);
    let parts = ctx.request_parts(&lookup);
    let policy = ctx.verify_policy(app, extra_required.iter().map(|s| s.to_string()).collect());

    let parsed = sig::parse_request_signature(&parts, &policy).map_err(ApiError::from_sig_error)?;

    match &parsed.scheme {
        SigKeyScheme::Hwk(jwk) => {
            sig::verify_parsed(&parsed, jwk).map_err(ApiError::from_sig_error)?;
            Ok(Signer::Hwk { jwk: jwk.clone() })
        }
        SigKeyScheme::JktJwt(token) => {
            let verified = aauth_core::sigkey::verify_jkt_jwt(
                token,
                aauth_core::now_unix(),
                app.cfg.naming_jwt_max_lifetime_secs,
            )
            .map_err(ApiError::from_sig_error)?;
            // The HTTP signature is made by the ephemeral key.
            sig::verify_parsed(&parsed, &verified.ephemeral_jwk)
                .map_err(ApiError::from_sig_error)?;
            Ok(Signer::JktJwt {
                durable_jkt: verified.durable_jkt,
                ephemeral_jwk: verified.ephemeral_jwk,
                jti: verified.jti,
            })
        }
        SigKeyScheme::Jwt(token) => {
            // Must be one of *our* agent tokens (issued by this AP).
            let decoded = aauth_core::jwt::decode(token).map_err(|_| {
                ApiError::from_sig_error(SigError::new(
                    SigErrorCode::InvalidJwt,
                    "malformed agent token",
                ))
            })?;
            let claims = verify_local_agent_token(app, &decoded)?;
            // The HTTP signature is made by the agent-token's cnf.jwk.
            let signing_jwk = claims.cnf.jwk.clone();
            sig::verify_parsed(&parsed, &signing_jwk).map_err(ApiError::from_sig_error)?;
            Ok(Signer::AgentToken {
                claims: Box::new(claims),
                signing_jwk,
            })
        }
        other => Err(ApiError::from_sig_error(SigError::new(
            SigErrorCode::InvalidKey,
            format!("unsupported Signature-Key scheme for this endpoint: {other:?}"),
        ))),
    }
}

/// Verify that a JWT is an agent token this AP issued (signature against our
/// own JWKS by `kid`), and validate its claims.
pub fn verify_local_agent_token(
    app: &App,
    decoded: &aauth_core::jwt::DecodedJwt,
) -> Result<tokens::AgentTokenClaims, ApiError> {
    let kid = decoded.header.kid.as_deref().ok_or_else(|| {
        ApiError::from_sig_error(SigError::new(
            SigErrorCode::InvalidJwt,
            "agent token missing kid",
        ))
    })?;
    let key = app.keys.find_public(kid).ok_or_else(|| {
        ApiError::from_sig_error(SigError::new(
            SigErrorCode::UnknownKey,
            "agent token kid not issued by this provider",
        ))
    })?;
    aauth_core::jwt::verify_with_jwk(decoded, key).map_err(|_| {
        ApiError::from_sig_error(SigError::new(
            SigErrorCode::InvalidJwt,
            "agent token signature invalid",
        ))
    })?;
    tokens::validate_agent_token(decoded, aauth_core::now_unix(), app.cfg.insecure_dev_mode)
        .map_err(|e| {
            ApiError::from_sig_error(SigError::new(SigErrorCode::InvalidJwt, e.to_string()))
        })
}
