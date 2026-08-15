//! Who is calling the admin API.
//!
//! Two credentials are accepted, and the difference between them is the point
//! of this module. A shared bearer token proves only that the caller holds the
//! secret: every action looks identical afterwards, it cannot be withdrawn from
//! one person, and offboarding means rotating it for everyone at once. A token
//! from the organisation's identity provider names the operator, so a revoked
//! agent has someone's name against it and losing IdP access loses admin access.
//!
//! The admin API is machine-facing — operators reach it with `curl`, a script,
//! or CI — so this validates a bearer JWT rather than running a browser
//! redirect. The operator gets that token from their IdP however their
//! organisation already does.
//!
//! Verification reuses the machinery already here for federated enrollment:
//! the same issuer runtime resolves keys through OIDC discovery under the same
//! egress rules, the same multi-algorithm verifier handles the RS256 and ES256
//! that identity providers actually sign with, and the same claim matcher
//! decides authorization. Nothing about token verification is written twice.

use std::sync::Arc;

use hyper::StatusCode;

use crate::app::App;
use crate::config::AdminOidcConfig;
use crate::enrollment::assertion::claim_matches;
use crate::problem::ApiError;
use crate::reqctx::ReqCtx;

/// The authenticated caller, as it will appear in the audit log.
#[derive(Debug, Clone)]
pub struct AdminPrincipal {
    /// `oidc:alice@example.com`, or `static-token`.
    pub actor: String,
}

impl AdminPrincipal {
    fn static_token() -> Self {
        AdminPrincipal {
            // Deliberately not "admin": a reader of the audit log should be able
            // to tell at a glance that this action carried no operator identity.
            actor: "static-token".to_string(),
        }
    }
}

fn unauthorized(detail: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", detail)
}

/// Constant-time comparison, so a wrong token leaks nothing through timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Authenticate an admin request.
///
/// A JWT is tried against the IdP; anything else is compared against the shared
/// token. The shape of the credential selects the path, so an operator does not
/// have to say which they are using — and a JWT is never fed to a constant-time
/// string comparison against a secret, which would be meaningless.
pub async fn authenticate(ctx: &ReqCtx, app: &Arc<App>) -> Result<AdminPrincipal, ApiError> {
    if app.cfg.admin_token.is_none() && app.cfg.admin_oidc.is_none() {
        return Err(ApiError::not_found(
            "not_found",
            "admin API is disabled (configure admin_token or admin_oidc)",
        ));
    }

    let presented = ctx
        .header("authorization")
        .and_then(|h| h.strip_prefix("Bearer ").map(str::to_string))
        .ok_or_else(|| unauthorized("missing bearer credential"))?;

    // Three dot-separated segments is a compact JWS. Anything else cannot be an
    // IdP token, so it is only ever a candidate for the shared secret.
    let looks_like_jwt = presented.split('.').count() == 3;

    if looks_like_jwt {
        if let Some(oidc) = &app.cfg.admin_oidc {
            return verify_oidc(app, oidc, &presented).await;
        }
    }

    match &app.cfg.admin_token {
        Some(configured) if ct_eq(presented.as_bytes(), configured.as_bytes()) => {
            Ok(AdminPrincipal::static_token())
        }
        Some(_) => Err(unauthorized("invalid admin credential")),
        None => Err(unauthorized(
            "this provider accepts only an identity-provider token on the admin API",
        )),
    }
}

/// Verify an IdP-issued JWT and decide whether its subject may administer.
async fn verify_oidc(
    app: &Arc<App>,
    cfg: &AdminOidcConfig,
    token: &str,
) -> Result<AdminPrincipal, ApiError> {
    use aauth_core::jwt::{self, ClaimExt};

    let decoded = jwt::decode(token).map_err(|_| unauthorized("malformed admin token"))?;
    let alg = decoded.header.alg.clone();
    if !crate::enrollment::anyjwk::SUPPORTED_ALGS.contains(&alg.as_str()) {
        return Err(unauthorized(format!(
            "unsupported admin token algorithm '{alg}'"
        )));
    }

    // `iss` is checked before any key is fetched: the issuer decides which JWKS
    // we would go and read, so a token naming someone else's IdP must not cause
    // a request to it.
    let iss = decoded
        .payload
        .str_claim("iss")
        .ok_or_else(|| unauthorized("admin token has no iss"))?;
    if iss != cfg.issuer {
        return Err(unauthorized(
            "admin token was not issued by the trusted IdP",
        ));
    }

    // Audience. Without it, a token the IdP minted for an unrelated application
    // — a wiki, a dashboard — would administer this provider.
    let aud_ok = match decoded.payload.get("aud") {
        Some(serde_json::Value::String(a)) => a == &cfg.audience,
        Some(serde_json::Value::Array(v)) => {
            v.iter().any(|a| a.as_str() == Some(cfg.audience.as_str()))
        }
        _ => false,
    };
    if !aud_ok {
        return Err(unauthorized(
            "admin token audience does not name this provider",
        ));
    }

    let now = aauth_core::now_unix() as i64;
    match decoded.payload.int_claim("exp") {
        Some(exp) if exp > now => {}
        Some(_) => return Err(unauthorized("admin token expired")),
        None => return Err(unauthorized("admin token has no exp")),
    }
    if decoded
        .payload
        .int_claim("iat")
        .is_some_and(|i| i > now + 60)
    {
        return Err(unauthorized("admin token iat is in the future"));
    }

    let runtime = app
        .admin_idp
        .as_ref()
        .ok_or_else(|| ApiError::server_error("admin IdP configured but not loaded"))?;
    let keys = runtime
        .resolve_keys(decoded.header.kid.as_deref(), &alg)
        .await
        .map_err(|e| unauthorized(format!("cannot resolve admin IdP keys: {e}")))?;
    let verified = keys.iter().any(|k| {
        k.supports_alg(&alg)
            && k.verify(&alg, decoded.signing_input.as_bytes(), &decoded.signature)
                .is_ok()
    });
    if !verified {
        return Err(unauthorized("admin token signature verification failed"));
    }

    // Authorization. Authenticating against the company IdP proves employment,
    // not entitlement — without a claim gate every account could administer the
    // provider, so an empty gate is refused at config load rather than here.
    for (path, matcher) in &cfg.required_claims {
        let actual = crate::enrollment::assertion::lookup_claim(&decoded.payload, path);
        let ok = actual.map(|v| claim_matches(matcher, v)).unwrap_or(false);
        if !ok {
            return Err(ApiError::forbidden(
                "forbidden",
                format!("admin token does not satisfy required claim '{path}'"),
            ));
        }
    }

    let subject = decoded
        .payload
        .str_claim(&cfg.principal_claim)
        .or_else(|| decoded.payload.str_claim("sub"))
        .unwrap_or("unknown");
    Ok(AdminPrincipal {
        actor: format!("oidc:{subject}"),
    })
}
