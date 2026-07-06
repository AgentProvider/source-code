//! JSON Web Keys (Ed25519 / OKP only), JWKS documents, and RFC 7638 thumbprints.
//!
//! AAuth mandates EdDSA (Ed25519) support and recommends it everywhere; this
//! implementation is deliberately Ed25519-only to keep the dependency and
//! attack surface minimal. See `research/03-http-signatures.md`.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::b64;

/// A public JWK. Only OKP/Ed25519 is supported; unknown members are ignored
/// on input and never emitted on output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    /// base64url public key (32 bytes for Ed25519)
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

impl Jwk {
    /// Public JWK for an Ed25519 verifying key.
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: b64::encode(vk.as_bytes()),
            kid: None,
            alg: None,
            use_: None,
        }
    }

    /// Parse into an Ed25519 verifying key. Fails on any non-Ed25519 key.
    pub fn verifying_key(&self) -> Result<VerifyingKey, JwkError> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(JwkError::UnsupportedKeyType);
        }
        let raw: [u8; 32] = b64::decode_fixed(&self.x).map_err(|_| JwkError::InvalidKey)?;
        VerifyingKey::from_bytes(&raw).map_err(|_| JwkError::InvalidKey)
    }

    /// RFC 7638 JWK thumbprint (SHA-256, base64url). For OKP keys the
    /// canonical form is `{"crv":...,"kty":...,"x":...}` — required members
    /// only, lexicographic order, no whitespace.
    pub fn thumbprint(&self) -> Result<String, JwkError> {
        if self.kty != "OKP" {
            return Err(JwkError::UnsupportedKeyType);
        }
        // crv and x are JSON strings under our control (validated base64url /
        // known curve names), but escape defensively via serde_json.
        let canonical = format!(
            "{{\"crv\":{},\"kty\":{},\"x\":{}}}",
            serde_json::to_string(&self.crv).unwrap(),
            serde_json::to_string(&self.kty).unwrap(),
            serde_json::to_string(&self.x).unwrap(),
        );
        Ok(b64::encode(&Sha256::digest(canonical.as_bytes())))
    }

    /// Copy with only the cryptographic members (for `cnf.jwk` embedding).
    pub fn public_only(&self) -> Jwk {
        Jwk {
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            kid: None,
            alg: None,
            use_: None,
        }
    }
}

/// A JWKS document (`{"keys":[...]}`). Unknown/unsupported keys are retained
/// as raw values so a document containing e.g. RSA keys still parses; lookup
/// only matches supported keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<serde_json::Value>,
}

impl Jwks {
    /// Find a supported (Ed25519) key by `kid`.
    pub fn find(&self, kid: &str) -> Option<Jwk> {
        self.keys.iter().find_map(|v| {
            let k: Jwk = serde_json::from_value(v.clone()).ok()?;
            if k.kid.as_deref() == Some(kid) && k.kty == "OKP" && k.crv == "Ed25519" {
                Some(k)
            } else {
                None
            }
        })
    }
}

/// Generate a fresh Ed25519 signing key from OS randomness.
pub fn generate_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    crate::rand_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwkError {
    UnsupportedKeyType,
    InvalidKey,
}

impl std::fmt::Display for JwkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwkError::UnsupportedKeyType => write!(f, "unsupported key type (Ed25519/OKP only)"),
            JwkError::InvalidKey => write!(f, "invalid key material"),
        }
    }
}
impl std::error::Error for JwkError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 appendix A key and its published thumbprint.
    #[test]
    fn rfc8037_thumbprint() {
        let jwk = Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
            kid: None,
            alg: None,
            use_: None,
        };
        assert_eq!(
            jwk.thumbprint().unwrap(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn thumbprint_ignores_optional_members() {
        let mut jwk = Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
            kid: Some("some-kid".into()),
            alg: Some("EdDSA".into()),
            use_: Some("sig".into()),
        };
        let t1 = jwk.thumbprint().unwrap();
        jwk.kid = None;
        assert_eq!(t1, jwk.thumbprint().unwrap());
    }

    #[test]
    fn roundtrip_key() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        assert_eq!(jwk.verifying_key().unwrap(), sk.verifying_key());
    }

    #[test]
    fn jwks_find_skips_unsupported() {
        let jwks: Jwks = serde_json::from_str(
            r#"{"keys":[
                {"kty":"RSA","n":"abc","e":"AQAB","kid":"k1"},
                {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1"}
            ]}"#,
        )
        .unwrap();
        assert!(jwks.find("k1").is_some());
        assert!(jwks.find("nope").is_none());
    }
}
