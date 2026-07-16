//! Federated enrollment assertion verification: the uniform JWS pipeline.
//!
//! Order (fail cheap, no state mutated before full validity):
//! parse → route by `iss` → verify signature (issuer keys or x5c chain) →
//! `aud` / `exp` / `iat` / `nbf` → required claims → SANs (x5c) → `cnf`
//! binding. The `jti` replay guard runs in the handler (it needs storage).

use aauth_core::jwk::Jwk;
use aauth_core::jwt::{self, ClaimExt};

use super::issuer_keys::IssuerRuntime;
use super::x509;

/// Clock skew tolerated on iat/nbf.
const SKEW_SECS: i64 = 60;

/// Successful verification result, consumed by the enroll handler.
#[derive(Debug)]
pub struct FederatedVerdict {
    pub issuer_name: String,
    pub issuer: String,
    /// The assertion `sub`, recorded for audit.
    pub subject: Option<String>,
    /// Claims to stamp into every agent token for this enrollment
    /// (target claim name -> value).
    pub embed: serde_json::Map<String, serde_json::Value>,
    /// PS pinned by the issuer entry, if any.
    pub ps_pin: Option<String>,
    pub label: Option<String>,
    /// Present when the assertion carried a jti: (jti, remaining lifetime)
    /// and single-use enforcement applies.
    pub consume_jti: Option<(String, u64)>,
    /// Assurance tier for this enrollment (issuer override or type default).
    pub assurance: String,
}

/// Look up a claim by path. Handles dotted key names (e.g. the Kubernetes
/// `kubernetes.io` claim) by trying every split point, longest first-segment
/// last: for path `a.b.c` try key `a.b.c`, then `a.b`→`c`, then `a`→`b.c`,
/// recursively.
pub fn lookup_claim<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let obj = value.as_object()?;
    if let Some(v) = obj.get(path) {
        return Some(v);
    }
    // try each split point from the right (prefer longer top-level keys)
    let mut idx = path.len();
    while let Some(dot) = path[..idx].rfind('.') {
        let (head, tail) = (&path[..dot], &path[dot + 1..]);
        if let Some(inner) = obj.get(head) {
            if let Some(v) = lookup_claim(inner, tail) {
                return Some(v);
            }
            if let Some(v) = inner.get(tail) {
                return Some(v);
            }
        }
        idx = dot;
    }
    None
}

/// Match a claim value against a matcher: exact string, array-of-allowed, or
/// trailing-`*` prefix pattern.
pub fn claim_matches(matcher: &serde_json::Value, actual: &serde_json::Value) -> bool {
    let actual_str = match actual {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => return false,
    };
    match matcher {
        serde_json::Value::String(pattern) => match pattern.strip_suffix('*') {
            Some(prefix) => actual_str.starts_with(prefix),
            None => &actual_str == pattern,
        },
        serde_json::Value::Array(allowed) => {
            allowed.iter().filter_map(|v| v.as_str()).any(|pattern| {
                match pattern.strip_suffix('*') {
                    Some(prefix) => actual_str.starts_with(prefix),
                    None => actual_str == pattern,
                }
            })
        }
        _ => false,
    }
}

/// Is `sub` (a `spiffe://…` ID) within `domain` (normalized `spiffe://<td>`)?
/// True for the trust-domain root itself and any workload path beneath it.
fn sub_in_domain(sub: &str, domain: &str) -> bool {
    sub == domain || sub.starts_with(&format!("{domain}/"))
}

/// Does `aud` (string or array) contain `expected`?
fn aud_contains(payload: &serde_json::Value, expected: &str) -> bool {
    match payload.get("aud") {
        Some(serde_json::Value::String(s)) => s == expected,
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str())
            .any(|a| a == expected),
        _ => false,
    }
}

/// Verify an enrollment assertion against the configured trusted issuers.
/// `durable_jwk` is the key that signed the enrollment HTTP request; `now` is
/// Unix time; `default_audience` is apd's issuer URL.
pub async fn verify_assertion(
    issuers: &[IssuerRuntime],
    assertion: &str,
    durable_jwk: &Jwk,
    now: u64,
    default_audience: &str,
) -> Result<FederatedVerdict, String> {
    let decoded =
        jwt::decode(assertion).map_err(|_| "malformed enrollment assertion".to_string())?;
    let alg = decoded.header.alg.clone();
    if !super::anyjwk::SUPPORTED_ALGS.contains(&alg.as_str()) {
        return Err(format!("unsupported assertion algorithm '{alg}'"));
    }

    // Routing. A SPIFFE **JWT-SVID** is identified by a `sub` that is a SPIFFE
    // ID *and the absence of an x5c chain* (it is signed by the trust bundle
    // JWKS, not a cert). It is routed by trust domain, since SPIFFE does not
    // mandate an `iss`. An X.509-SVID also has a `spiffe://` sub but carries an
    // x5c chain and is routed by `iss` like any other x5c assertion. Everything
    // else routes by exact `iss` match.
    let has_x5c = decoded
        .header
        .x5c
        .as_ref()
        .map(|c| !c.is_empty())
        .unwrap_or(false);
    let sub_claim = decoded.payload.str_claim("sub").map(str::to_string);
    let (issuer, route_iss) = if let Some(sub) = sub_claim
        .as_deref()
        .filter(|s| !has_x5c && s.starts_with("spiffe://"))
    {
        let issuer = issuers
            .iter()
            .find(|i| i.is_spiffe() && i.spiffe_domain().is_some_and(|td| sub_in_domain(sub, &td)))
            .ok_or_else(|| {
                format!("SPIFFE assertion sub '{sub}' is not under a trusted trust domain")
            })?;
        (issuer, sub.to_string())
    } else {
        let iss = decoded
            .payload
            .str_claim("iss")
            .ok_or("assertion missing iss claim")?
            .to_string();
        let issuer = issuers
            .iter()
            .find(|i| !i.is_spiffe() && i.cfg.issuer == iss)
            .ok_or_else(|| format!("assertion issuer '{iss}' is not trusted"))?;
        (issuer, iss)
    };

    // ---- signature ----
    let mut sans: Vec<String> = Vec::new();
    if issuer.is_x5c() {
        let x5c = decoded
            .header
            .x5c
            .as_ref()
            .filter(|c| !c.is_empty())
            .ok_or("x5c issuer requires a certificate chain in the JWS header")?;
        let chain: Vec<Vec<u8>> = x5c
            .iter()
            .map(|c| aauth_core::b64::decode_std(c).map_err(|_| "invalid x5c encoding".to_string()))
            .collect::<Result<_, _>>()?;
        sans = x509::verify_x5c_jws(
            &chain,
            &issuer.ca_roots,
            &issuer.crls,
            now,
            &alg,
            decoded.signing_input.as_bytes(),
            &decoded.signature,
        )?;
    } else {
        let candidates = issuer
            .resolve_keys(decoded.header.kid.as_deref(), &alg)
            .await?;
        let verified = candidates.iter().any(|key| {
            key.verify(&alg, decoded.signing_input.as_bytes(), &decoded.signature)
                .is_ok()
        });
        if !verified {
            return Err(format!(
                "assertion signature verification failed for issuer '{}'",
                issuer.cfg.name
            ));
        }
    }

    // ---- temporal ----
    let now_i = now as i64;
    let exp = decoded
        .payload
        .int_claim("exp")
        .ok_or("assertion missing exp claim")?;
    if exp <= now_i {
        return Err("assertion expired".into());
    }
    if let Some(iat) = decoded.payload.int_claim("iat") {
        if iat > now_i + SKEW_SECS {
            return Err("assertion iat is in the future".into());
        }
    }
    if let Some(nbf) = decoded.payload.int_claim("nbf") {
        if nbf > now_i + SKEW_SECS {
            return Err("assertion not yet valid (nbf)".into());
        }
    }

    // ---- audience ----
    let expected_aud = issuer.cfg.audience.as_deref().unwrap_or(default_audience);
    if !aud_contains(&decoded.payload, expected_aud) {
        return Err(format!("assertion aud does not include '{expected_aud}'"));
    }

    // ---- required claims ----
    for (path, matcher) in &issuer.cfg.required_claims {
        let actual = lookup_claim(&decoded.payload, path)
            .ok_or_else(|| format!("assertion missing required claim '{path}'"))?;
        if !claim_matches(matcher, actual) {
            return Err(format!("assertion claim '{path}' does not satisfy policy"));
        }
    }

    // ---- SAN policy (x5c) ----
    if !issuer.cfg.required_sans.is_empty() {
        let ok = issuer
            .cfg
            .required_sans
            .iter()
            .any(|pattern| sans.iter().any(|san| x509::san_matches(pattern, san)));
        if !ok {
            return Err("leaf certificate SANs do not satisfy required_sans".into());
        }
    }

    // ---- cnf binding ----
    let cnf = decoded.payload.get("cnf");
    let has_binding = match cnf {
        Some(cnf) => {
            let durable_thumb = durable_jwk
                .thumbprint()
                .map_err(|_| "unsupported enrolling key".to_string())?;
            if let Some(jwk_val) = cnf.get("jwk") {
                let bound: Jwk = serde_json::from_value(jwk_val.clone())
                    .map_err(|_| "assertion cnf.jwk is not a supported key".to_string())?;
                let bound_thumb = bound
                    .thumbprint()
                    .map_err(|_| "assertion cnf.jwk is not a supported key".to_string())?;
                if bound_thumb != durable_thumb {
                    return Err("assertion cnf.jwk does not match the enrolling key".into());
                }
                true
            } else if let Some(jkt) = cnf.get("jkt").and_then(|v| v.as_str()) {
                if jkt != durable_thumb {
                    return Err("assertion cnf.jkt does not match the enrolling key".into());
                }
                true
            } else {
                false
            }
        }
        None => false,
    };
    if issuer.cfg.require_cnf_binding && !has_binding {
        return Err("issuer policy requires a cnf binding (cnf.jwk or cnf.jkt)".into());
    }

    // ---- embed claims ----
    let mut embed = serde_json::Map::new();
    for (path, target) in &issuer.cfg.embed_claims {
        let target = target.as_str().unwrap_or_default();
        if let Some(value) = lookup_claim(&decoded.payload, path) {
            match value {
                serde_json::Value::String(_)
                | serde_json::Value::Bool(_)
                | serde_json::Value::Number(_) => {
                    embed.insert(target.to_string(), value.clone());
                }
                _ => {
                    return Err(format!(
                        "embed claim '{path}' is not a scalar (string/bool/number)"
                    ))
                }
            }
        }
    }

    // ---- jti replay policy ----
    // Default: single-use when the assertion is NOT key-bound (bounds token
    // exfiltration to first use), reusable when cnf-bound (replay harmless).
    let single_use = issuer.cfg.single_use_jti.unwrap_or(!has_binding);
    let consume_jti = if single_use {
        decoded
            .payload
            .str_claim("jti")
            .map(|jti| (jti.to_string(), (exp - now_i).max(1) as u64))
    } else {
        None
    };

    let assurance = issuer
        .cfg
        .assurance
        .clone()
        .unwrap_or_else(|| default_assurance(&issuer.cfg.issuer_type).to_string());

    Ok(FederatedVerdict {
        issuer_name: issuer.cfg.name.clone(),
        issuer: route_iss,
        subject: decoded.payload.str_claim("sub").map(String::from),
        embed,
        ps_pin: issuer.cfg.ps.clone(),
        label: issuer.cfg.label.clone(),
        consume_jti,
        assurance,
    })
}

/// Default assurance tier by issuer type: certificate/attested chains rank
/// "high"; bearer-assertion issuers (OIDC / JWKS) rank "medium".
pub fn default_assurance(issuer_type: &str) -> &'static str {
    match issuer_type {
        "x5c" | "spiffe" => "high",
        _ => "medium",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_lookup_paths() {
        let payload = serde_json::json!({
            "sub": "system:serviceaccount:agents:runner",
            "kubernetes.io": {
                "namespace": "agents",
                "serviceaccount": { "name": "runner" }
            },
            "nested": { "a": { "b": "c" } }
        });
        assert_eq!(
            lookup_claim(&payload, "sub").unwrap(),
            "system:serviceaccount:agents:runner"
        );
        assert_eq!(
            lookup_claim(&payload, "kubernetes.io.namespace").unwrap(),
            "agents"
        );
        assert_eq!(
            lookup_claim(&payload, "kubernetes.io.serviceaccount.name").unwrap(),
            "runner"
        );
        assert_eq!(lookup_claim(&payload, "nested.a.b").unwrap(), "c");
        assert!(lookup_claim(&payload, "missing.claim").is_none());
    }

    #[test]
    fn claim_matchers() {
        let m = |m: serde_json::Value, a: serde_json::Value| claim_matches(&m, &a);
        assert!(m("exact".into(), "exact".into()));
        assert!(!m("exact".into(), "other".into()));
        assert!(m(
            "system:serviceaccount:agents:*".into(),
            "system:serviceaccount:agents:runner".into()
        ));
        assert!(!m(
            "system:serviceaccount:agents:*".into(),
            "system:serviceaccount:evil:x".into()
        ));
        assert!(m(serde_json::json!(["a", "b*"]), "a".into()));
        assert!(m(serde_json::json!(["a", "b*"]), "bcd".into()));
        assert!(!m(serde_json::json!(["a", "b*"]), "c".into()));
        assert!(m("true".into(), serde_json::Value::Bool(true)));
    }

    #[test]
    fn aud_forms() {
        assert!(aud_contains(&serde_json::json!({"aud": "x"}), "x"));
        assert!(aud_contains(&serde_json::json!({"aud": ["y", "x"]}), "x"));
        assert!(!aud_contains(&serde_json::json!({"aud": ["y"]}), "x"));
        assert!(!aud_contains(&serde_json::json!({}), "x"));
    }
}
