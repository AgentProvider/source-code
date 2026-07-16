//! Token minting: agent tokens, sub-agent tokens, and subscribe tokens.
//! All are Ed25519 JWTs signed by the AP's active key.

use aauth_core::ident::AgentId;
use aauth_core::jwk::Jwk;
use aauth_core::jwt;
use aauth_core::now_unix;

use crate::app::App;

/// Claims that may never be overridden by issuer `embed_claims`
/// (defense-in-depth; also validated at config load).
const PROTECTED: [&str; 12] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "cnf",
    "dwk",
    "ps",
    "parent_agent",
    "assurance",
];

/// Mint an agent token for `local`, bound to `signing_jwk`. `embed_claims`
/// (from a federated enrollment's issuer policy) are stamped as additional
/// AP-attested claims — the AAuth spec permits AP-defined claims and requires
/// receivers to ignore unrecognized ones.
pub fn agent_token(
    app: &App,
    local: &str,
    signing_jwk: &Jwk,
    ps: Option<&str>,
    ttl_secs: u64,
    embed_claims: Option<&serde_json::Map<String, serde_json::Value>>,
    assurance: Option<&str>,
) -> (String, u64) {
    let now = now_unix();
    let exp = now + ttl_secs;
    let agent_id = AgentId::new(local, &app.cfg.agent_domain())
        .expect("validated local part")
        .to_string();
    let mut payload = serde_json::json!({
        "iss": app.cfg.issuer,
        "dwk": "aauth-agent.json",
        "sub": agent_id,
        "jti": aauth_core::rand_token(128),
        "cnf": { "jwk": signing_jwk.public_only() },
        "iat": now,
        "exp": exp,
    });
    if let Some(ps) = ps {
        payload["ps"] = ps.into();
    }
    if let Some(a) = assurance {
        payload["assurance"] = a.into();
    }
    if let Some(embed) = embed_claims {
        for (name, value) in embed {
            if !PROTECTED.contains(&name.as_str()) {
                payload[name] = value.clone();
            }
        }
    }
    let token = jwt::sign(
        aauth_core::tokens::TYP_AGENT,
        Some(&app.keys.active_kid),
        None,
        &payload,
        &app.keys.active_key,
    );
    (token, exp)
}

/// Mint a sub-agent token. `parent` must be a top-level agent id; the returned
/// token carries `parent_agent` and is capped to `parent_exp`.
#[allow(clippy::too_many_arguments)]
pub fn subagent_token(
    app: &App,
    parent: &AgentId,
    discriminator: &str,
    signing_jwk: &Jwk,
    ps: Option<&str>,
    parent_exp: u64,
    embed_claims: Option<&serde_json::Map<String, serde_json::Value>>,
    assurance: Option<&str>,
) -> Result<(String, u64), String> {
    let sub_id = parent
        .subagent(discriminator)
        .map_err(|_| "invalid discriminator".to_string())?;
    let now = now_unix();
    // Cap the sub-agent token to the parent token's expiry.
    let exp = (now + app.cfg.agent_token_ttl_secs).min(parent_exp);
    if exp <= now {
        return Err("parent token too close to expiry to mint a sub-agent token".into());
    }
    let mut payload = serde_json::json!({
        "iss": app.cfg.issuer,
        "dwk": "aauth-agent.json",
        "sub": sub_id.to_string(),
        "parent_agent": parent.to_string(),
        "jti": aauth_core::rand_token(128),
        "cnf": { "jwk": signing_jwk.public_only() },
        "iat": now,
        "exp": exp,
    });
    if let Some(ps) = ps {
        payload["ps"] = ps.into();
    }
    if let Some(a) = assurance {
        payload["assurance"] = a.into();
    }
    // Sub-agents inherit the parent enrollment's embedded claims so
    // downstream gating (tenant/group/namespace) applies to workers too.
    if let Some(embed) = embed_claims {
        for (name, value) in embed {
            if !PROTECTED.contains(&name.as_str()) {
                payload[name] = value.clone();
            }
        }
    }
    let token = jwt::sign(
        aauth_core::tokens::TYP_AGENT,
        Some(&app.keys.active_kid),
        None,
        &payload,
        &app.keys.active_key,
    );
    Ok((token, exp))
}

/// Mint a subscribe token (AAuth Events).
pub fn subscribe_token(
    app: &App,
    agent_id: &str,
    signing_jwk: &Jwk,
    resource: &str,
    eid: &str,
    max_uses: Option<u64>,
    ttl_secs: u64,
) -> (String, u64) {
    let now = now_unix();
    let exp = now + ttl_secs;
    let mut payload = serde_json::json!({
        "iss": app.cfg.issuer,
        "dwk": "aauth-agent.json",
        "sub": agent_id,
        "aud": resource,
        "cnf": { "jwk": signing_jwk.public_only() },
        "eid": eid,
        "iat": now,
        "exp": exp,
    });
    if let Some(max) = max_uses {
        payload["max_uses"] = max.into();
    }
    let token = jwt::sign(
        aauth_core::tokens::TYP_SUBSCRIBE,
        Some(&app.keys.active_kid),
        None,
        &payload,
        &app.keys.active_key,
    );
    (token, exp)
}
