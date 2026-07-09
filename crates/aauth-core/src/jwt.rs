//! Compact JWT (JWS) signing and verification, EdDSA (Ed25519) only.
//!
//! `alg: none` and any non-EdDSA algorithm are rejected at verification, per
//! the AAuth requirement that implementations MUST NOT accept `none`.

use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::b64;
use crate::jwk::Jwk;

/// JOSE header members AAuth uses. Unknown members are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoseHeader {
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Embedded public key — used by the `jkt-jwt` naming JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    /// X.509 certificate chain (RFC 7515 §4.1.6): standard base64 DER,
    /// leaf first — used by x5c-type federated enrollment assertions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
}

/// A decoded-but-not-yet-verified JWT.
#[derive(Debug, Clone)]
pub struct DecodedJwt {
    pub header: JoseHeader,
    pub payload: serde_json::Value,
    /// `<b64 header>.<b64 payload>` — the signed bytes.
    pub signing_input: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtError {
    Malformed,
    UnsupportedAlgorithm,
    BadSignature,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Malformed => write!(f, "malformed JWT"),
            JwtError::UnsupportedAlgorithm => write!(f, "unsupported JWT algorithm"),
            JwtError::BadSignature => write!(f, "JWT signature verification failed"),
        }
    }
}
impl std::error::Error for JwtError {}

/// Split and decode a compact JWT without verifying it.
pub fn decode(token: &str) -> Result<DecodedJwt, JwtError> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(JwtError::Malformed),
    };
    let header_bytes = b64::decode(h).map_err(|_| JwtError::Malformed)?;
    let payload_bytes = b64::decode(p).map_err(|_| JwtError::Malformed)?;
    let signature = b64::decode(s).map_err(|_| JwtError::Malformed)?;
    let header: JoseHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::Malformed)?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| JwtError::Malformed)?;
    if !payload.is_object() {
        return Err(JwtError::Malformed);
    }
    Ok(DecodedJwt {
        header,
        payload,
        signing_input: format!("{h}.{p}"),
        signature,
    })
}

/// Verify a decoded JWT's signature against an Ed25519 JWK.
/// Enforces `alg == EdDSA`.
pub fn verify_with_jwk(jwt: &DecodedJwt, key: &Jwk) -> Result<(), JwtError> {
    if jwt.header.alg != "EdDSA" {
        return Err(JwtError::UnsupportedAlgorithm);
    }
    let vk = key.verifying_key().map_err(|_| JwtError::BadSignature)?;
    let sig_bytes: [u8; 64] = jwt
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| JwtError::BadSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(jwt.signing_input.as_bytes(), &sig)
        .map_err(|_| JwtError::BadSignature)
}

/// Sign a JWT with EdDSA. `typ` goes into the header; `kid`/`jwk` optional.
pub fn sign(
    typ: &str,
    kid: Option<&str>,
    header_jwk: Option<&Jwk>,
    payload: &serde_json::Value,
    key: &SigningKey,
) -> String {
    let header = JoseHeader {
        alg: "EdDSA".into(),
        typ: Some(typ.into()),
        kid: kid.map(|s| s.into()),
        jwk: header_jwk.cloned(),
        x5c: None,
    };
    let h = b64::encode(serde_json::to_string(&header).unwrap().as_bytes());
    let p = b64::encode(serde_json::to_string(payload).unwrap().as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64::encode(&sig.to_bytes()))
}

/// Convenience claim accessors for `serde_json::Value` payloads.
pub trait ClaimExt {
    fn str_claim(&self, name: &str) -> Option<&str>;
    fn int_claim(&self, name: &str) -> Option<i64>;
}

impl ClaimExt for serde_json::Value {
    fn str_claim(&self, name: &str) -> Option<&str> {
        self.get(name)?.as_str()
    }
    fn int_claim(&self, name: &str) -> Option<i64> {
        self.get(name)?.as_i64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::generate_signing_key;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let payload = serde_json::json!({"iss": "https://ap.example", "exp": 123});
        let token = sign("aa-agent+jwt", Some("k1"), None, &payload, &sk);
        let decoded = decode(&token).unwrap();
        assert_eq!(decoded.header.typ.as_deref(), Some("aa-agent+jwt"));
        assert_eq!(decoded.header.kid.as_deref(), Some("k1"));
        verify_with_jwk(&decoded, &jwk).unwrap();
    }

    #[test]
    fn tampered_rejected() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let token = sign("t", None, None, &serde_json::json!({"a": 1}), &sk);
        let parts: Vec<&str> = token.split('.').collect();
        let evil_payload = crate::b64::encode(br#"{"a":2}"#);
        let tampered = format!("{}.{}.{}", parts[0], evil_payload, parts[2]);
        let decoded = decode(&tampered).unwrap();
        assert_eq!(verify_with_jwk(&decoded, &jwk), Err(JwtError::BadSignature));
    }

    #[test]
    fn alg_none_rejected() {
        // hand-craft an alg=none token
        let h = crate::b64::encode(br#"{"alg":"none","typ":"aa-agent+jwt"}"#);
        let p = crate::b64::encode(br#"{"iss":"https://x.example"}"#);
        let token = format!("{h}.{p}.");
        // trailing empty signature part decodes to empty vec
        let decoded = decode(&token).unwrap();
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        assert_eq!(
            verify_with_jwk(&decoded, &jwk),
            Err(JwtError::UnsupportedAlgorithm)
        );
    }

    /// RFC 8037 A.4 test vector: Ed25519 signing of "Example of Ed25519 signing".
    #[test]
    fn rfc8037_signature_vector() {
        let seed: [u8; 32] =
            crate::b64::decode_fixed("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A").unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        assert_eq!(jwk.x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        // Compact JWS from RFC 8037 A.4
        let signing_input = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
        let sig = sk.sign(signing_input.as_bytes());
        assert_eq!(
            crate::b64::encode(&sig.to_bytes()),
            "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
        );
    }
}
