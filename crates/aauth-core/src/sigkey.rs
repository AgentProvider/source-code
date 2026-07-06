//! `Signature-Key` header schemes (`draft-hardt-httpbis-signature-key`):
//! parsing on the verifier side, serializing on the signer side, and the
//! `jkt-jwt` naming-JWT verification procedure.

use crate::jwk::Jwk;
use crate::jwt::{self, ClaimExt};
use crate::sfv::{self, BareItem, MemberValue, Params};
use crate::sig::{SigError, SigErrorCode};

/// A parsed `Signature-Key` dictionary member.
#[derive(Debug, Clone, PartialEq)]
pub enum SigKeyScheme {
    /// Inline public key (pseudonymous).
    Hwk(Jwk),
    /// Compact JWT carrying `cnf.jwk` (identity) — agent/auth/subscribe/event tokens.
    Jwt(String),
    /// Self-issued key delegation JWT (two-key refresh ceremony).
    JktJwt(String),
    /// Identified signer with JWKS discovery (used by PSes calling ASes).
    JwksUri {
        id: String,
        dwk: String,
        kid: String,
    },
    /// Registered but unsupported here (e.g. `x509`) or future schemes.
    Other(String),
}

fn str_param(params: &Params, key: &str) -> Result<String, SigError> {
    sfv::param(params, key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            SigError::new(
                SigErrorCode::InvalidKey,
                format!("missing or invalid '{key}' parameter"),
            )
        })
}

/// Parse one Signature-Key member value into a scheme.
pub fn parse_member(value: &MemberValue) -> Result<SigKeyScheme, SigError> {
    let (scheme_token, params) = match value {
        MemberValue::Item(BareItem::Token(t), params) => (t.as_str(), params),
        _ => {
            return Err(SigError::new(
                SigErrorCode::InvalidKey,
                "Signature-Key member is not a token",
            ))
        }
    };
    match scheme_token {
        "hwk" => {
            let kty = str_param(params, "kty")?;
            // alg MUST NOT be present on hwk
            if sfv::param(params, "alg").is_some() {
                return Err(SigError::new(
                    SigErrorCode::InvalidKey,
                    "hwk must not carry an alg parameter",
                ));
            }
            if kty != "OKP" {
                return Err(SigError::new(
                    SigErrorCode::UnsupportedAlgorithm,
                    "only OKP/Ed25519 keys are supported",
                ));
            }
            let crv = str_param(params, "crv")?;
            let x = str_param(params, "x")?;
            if crv != "Ed25519" {
                return Err(SigError::new(
                    SigErrorCode::UnsupportedAlgorithm,
                    "only Ed25519 keys are supported",
                ));
            }
            Ok(SigKeyScheme::Hwk(Jwk {
                kty,
                crv,
                x,
                kid: None,
                alg: None,
                use_: None,
            }))
        }
        "jwt" => Ok(SigKeyScheme::Jwt(str_param(params, "jwt")?)),
        "jkt-jwt" => Ok(SigKeyScheme::JktJwt(str_param(params, "jwt")?)),
        "jwks_uri" => Ok(SigKeyScheme::JwksUri {
            id: str_param(params, "id")?,
            dwk: str_param(params, "dwk")?,
            kid: str_param(params, "kid")?,
        }),
        other => Ok(SigKeyScheme::Other(other.to_string())),
    }
}

/// Serialize an `hwk` member value (Ed25519).
pub fn serialize_hwk(jwk: &Jwk) -> String {
    format!(
        "hwk;kty={};crv={};x={}",
        sfv::serialize_string(&jwk.kty),
        sfv::serialize_string(&jwk.crv),
        sfv::serialize_string(&jwk.x)
    )
}

/// Serialize a `jwt` member value.
pub fn serialize_jwt(token: &str) -> String {
    format!("jwt;jwt={}", sfv::serialize_string(token))
}

/// Serialize a `jkt-jwt` member value.
pub fn serialize_jkt_jwt(token: &str) -> String {
    format!("jkt-jwt;jwt={}", sfv::serialize_string(token))
}

/// Result of verifying a `jkt-jwt` naming JWT.
#[derive(Debug, Clone)]
pub struct JktJwtVerified {
    /// The durable (identity) key from the JWT header.
    pub durable_jwk: Jwk,
    /// RFC 7638 thumbprint of the durable key (the enrollment lookup key).
    pub durable_jkt: String,
    /// The delegated ephemeral key from `cnf.jwk` — verifies the HTTP signature.
    pub ephemeral_jwk: Jwk,
    pub jti: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

/// Verify a `jkt-jwt` naming JWT per the spec procedure
/// (see `research/03-http-signatures.md` §4). Only `jkt-s256+jwt` is
/// supported. `max_lifetime_secs` bounds `exp - iat` (0 = unbounded).
pub fn verify_jkt_jwt(
    token: &str,
    now: u64,
    max_lifetime_secs: u64,
) -> Result<JktJwtVerified, SigError> {
    let decoded = jwt::decode(token)
        .map_err(|_| SigError::new(SigErrorCode::InvalidJwt, "malformed naming JWT"))?;
    // 1-2. typ determines the thumbprint hash algorithm
    if decoded.header.typ.as_deref() != Some("jkt-s256+jwt") {
        return Err(SigError::new(
            SigErrorCode::InvalidJwt,
            "unsupported naming JWT typ (expected jkt-s256+jwt)",
        ));
    }
    // 3-4. extract header jwk
    let durable_jwk =
        decoded.header.jwk.clone().ok_or_else(|| {
            SigError::new(SigErrorCode::InvalidJwt, "naming JWT missing header jwk")
        })?;
    // 5-7. compute thumbprint, compare against iss by string equality
    let thumb = durable_jwk.thumbprint().map_err(|_| {
        SigError::new(
            SigErrorCode::UnsupportedAlgorithm,
            "unsupported durable key type",
        )
    })?;
    let expected_iss = format!("urn:jkt:sha-256:{thumb}");
    let iss = decoded
        .payload
        .str_claim("iss")
        .ok_or_else(|| SigError::new(SigErrorCode::InvalidJwt, "naming JWT missing iss"))?;
    if iss != expected_iss {
        return Err(SigError::new(
            SigErrorCode::InvalidJwt,
            "naming JWT iss does not match header jwk thumbprint",
        ));
    }
    // 8. verify JWT signature with the header jwk
    jwt::verify_with_jwk(&decoded, &durable_jwk).map_err(|e| match e {
        jwt::JwtError::UnsupportedAlgorithm => {
            SigError::new(SigErrorCode::UnsupportedAlgorithm, "naming JWT algorithm")
        }
        _ => SigError::new(SigErrorCode::InvalidJwt, "naming JWT signature invalid"),
    })?;
    // 9. iat / exp
    let iat = decoded
        .payload
        .int_claim("iat")
        .ok_or_else(|| SigError::new(SigErrorCode::InvalidJwt, "naming JWT missing iat"))?;
    let exp = decoded
        .payload
        .int_claim("exp")
        .ok_or_else(|| SigError::new(SigErrorCode::InvalidJwt, "naming JWT missing exp"))?;
    let now_i = now as i64;
    if exp <= now_i {
        return Err(SigError::new(
            SigErrorCode::ExpiredJwt,
            "naming JWT expired",
        ));
    }
    if iat > now_i + 60 {
        return Err(SigError::new(
            SigErrorCode::InvalidJwt,
            "naming JWT iat in the future",
        ));
    }
    if max_lifetime_secs > 0 && exp.saturating_sub(iat) > max_lifetime_secs as i64 {
        return Err(SigError::new(
            SigErrorCode::InvalidJwt,
            "naming JWT lifetime too long",
        ));
    }
    // 10. ephemeral key from cnf.jwk
    let ephemeral_jwk: Jwk = decoded
        .payload
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .and_then(|j| serde_json::from_value(j.clone()).ok())
        .ok_or_else(|| SigError::new(SigErrorCode::InvalidJwt, "naming JWT missing cnf.jwk"))?;
    let jti = decoded.payload.str_claim("jti").map(|s| s.to_string());
    Ok(JktJwtVerified {
        durable_jwk,
        durable_jkt: thumb,
        ephemeral_jwk,
        jti,
        iat,
        exp,
    })
}

/// Build a naming JWT (agent side of the two-key refresh ceremony).
pub fn build_naming_jwt(
    durable_key: &ed25519_dalek::SigningKey,
    ephemeral_public: &Jwk,
    now: u64,
    lifetime_secs: u64,
) -> String {
    let durable_jwk = Jwk::from_verifying_key(&durable_key.verifying_key());
    let thumb = durable_jwk.thumbprint().expect("OKP thumbprint");
    let payload = serde_json::json!({
        "iss": format!("urn:jkt:sha-256:{thumb}"),
        "iat": now,
        "exp": now + lifetime_secs,
        "jti": crate::rand_token(128),
        "cnf": { "jwk": ephemeral_public.public_only() },
    });
    jwt::sign(
        "jkt-s256+jwt",
        None,
        Some(&durable_jwk),
        &payload,
        durable_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::generate_signing_key;

    #[test]
    fn jkt_jwt_roundtrip() {
        let durable = generate_signing_key();
        let ephemeral = generate_signing_key();
        let eph_jwk = Jwk::from_verifying_key(&ephemeral.verifying_key());
        let now = 1_750_000_000u64;
        let token = build_naming_jwt(&durable, &eph_jwk, now, 300);
        let verified = verify_jkt_jwt(&token, now + 10, 300).unwrap();
        assert_eq!(verified.ephemeral_jwk.x, eph_jwk.x);
        assert_eq!(
            verified.durable_jkt,
            Jwk::from_verifying_key(&durable.verifying_key())
                .thumbprint()
                .unwrap()
        );
        assert!(verified.jti.is_some());
    }

    #[test]
    fn jkt_jwt_iss_mismatch_rejected() {
        let durable = generate_signing_key();
        let ephemeral = generate_signing_key();
        let eph_jwk = Jwk::from_verifying_key(&ephemeral.verifying_key());
        let now = 1_750_000_000u64;
        // Sign a naming JWT whose iss claims a *different* key's thumbprint.
        let other = generate_signing_key();
        let other_thumb = Jwk::from_verifying_key(&other.verifying_key())
            .thumbprint()
            .unwrap();
        let durable_jwk = Jwk::from_verifying_key(&durable.verifying_key());
        let payload = serde_json::json!({
            "iss": format!("urn:jkt:sha-256:{other_thumb}"),
            "iat": now, "exp": now + 300,
            "cnf": { "jwk": eph_jwk },
        });
        let token = crate::jwt::sign("jkt-s256+jwt", None, Some(&durable_jwk), &payload, &durable);
        let err = verify_jkt_jwt(&token, now, 300).unwrap_err();
        assert_eq!(err.code, SigErrorCode::InvalidJwt);
    }

    #[test]
    fn jkt_jwt_expired_rejected() {
        let durable = generate_signing_key();
        let eph = Jwk::from_verifying_key(&generate_signing_key().verifying_key());
        let now = 1_750_000_000u64;
        let token = build_naming_jwt(&durable, &eph, now - 1000, 300);
        let err = verify_jkt_jwt(&token, now, 300).unwrap_err();
        assert_eq!(err.code, SigErrorCode::ExpiredJwt);
    }

    #[test]
    fn parse_schemes() {
        let d = sfv::parse_dictionary(r#"sig=jwt;jwt="a.b.c""#).unwrap();
        assert_eq!(
            parse_member(&d[0].1.value).unwrap(),
            SigKeyScheme::Jwt("a.b.c".into())
        );
        let d = sfv::parse_dictionary(
            r#"sig=jwks_uri;id="https://ps.example";dwk="aauth-person.json";kid="k1""#,
        )
        .unwrap();
        match parse_member(&d[0].1.value).unwrap() {
            SigKeyScheme::JwksUri { id, dwk, kid } => {
                assert_eq!(id, "https://ps.example");
                assert_eq!(dwk, "aauth-person.json");
                assert_eq!(kid, "k1");
            }
            _ => panic!(),
        }
        let d = sfv::parse_dictionary(r#"sig=x509;x5u="https://x";x5t=:AA==:"#).unwrap();
        assert_eq!(
            parse_member(&d[0].1.value).unwrap(),
            SigKeyScheme::Other("x509".into())
        );
        // hwk with alg must be rejected
        let d =
            sfv::parse_dictionary(r#"sig=hwk;kty="OKP";crv="Ed25519";x="AA";alg="EdDSA""#).unwrap();
        assert!(parse_member(&d[0].1.value).is_err());
    }
}
