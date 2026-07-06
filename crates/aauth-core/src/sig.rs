//! RFC 9421 HTTP Message Signatures, profiled for AAuth
//! (see `research/03-http-signatures.md`).
//!
//! - Signing: [`sign_request`] produces `Signature-Input`, `Signature`, and
//!   `Signature-Key` headers with the mandated covered components.
//! - Verification: [`parse_request_signature`] does everything except key
//!   resolution and the final crypto; the caller resolves the key from the
//!   [`crate::sigkey::SigKeyScheme`] (possibly fetching a JWKS) and then
//!   calls [`verify_parsed`].

use ed25519_dalek::{Signature, Signer, SigningKey};

use crate::b64;
use crate::jwk::Jwk;
use crate::sfv::{self, BareItem, MemberValue};
use crate::sigkey::SigKeyScheme;

/// Covered components every AAuth request signature MUST include.
pub const REQUIRED_COMPONENTS: [&str; 4] = ["@method", "@authority", "@path", "signature-key"];

/// Machine-readable error codes for the `Signature-Error` response header
/// (`draft-hardt-httpbis-signature-key` §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigErrorCode {
    UnsupportedAlgorithm,
    InvalidSignature,
    InvalidInput,
    InvalidRequest,
    InvalidKey,
    UnknownKey,
    InvalidJwt,
    ExpiredJwt,
}

impl SigErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SigErrorCode::UnsupportedAlgorithm => "unsupported_algorithm",
            SigErrorCode::InvalidSignature => "invalid_signature",
            SigErrorCode::InvalidInput => "invalid_input",
            SigErrorCode::InvalidRequest => "invalid_request",
            SigErrorCode::InvalidKey => "invalid_key",
            SigErrorCode::UnknownKey => "unknown_key",
            SigErrorCode::InvalidJwt => "invalid_jwt",
            SigErrorCode::ExpiredJwt => "expired_jwt",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SigError {
    pub code: SigErrorCode,
    pub detail: String,
    /// For `invalid_input`: the components the verifier requires.
    pub required_input: Option<Vec<String>>,
}

impl SigError {
    pub fn new(code: SigErrorCode, detail: impl Into<String>) -> Self {
        SigError {
            code,
            detail: detail.into(),
            required_input: None,
        }
    }
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.detail)
    }
}
impl std::error::Error for SigError {}

/// The pieces of an HTTP request a verifier needs.
pub struct RequestParts<'a> {
    /// Method as sent (uppercase).
    pub method: &'a str,
    /// Host (+ optional port), lowercase — the `@authority` component.
    pub authority: &'a str,
    /// Target path without query.
    pub path: &'a str,
    /// Query string including leading `?`, or empty if none.
    pub query: &'a str,
    /// Lookup of a header by lowercase name, canonicalized per RFC 9421
    /// (values comma-joined, OWS trimmed).
    pub header: &'a dyn Fn(&str) -> Option<String>,
}

/// Verification policy.
pub struct VerifyPolicy {
    /// Unix time now.
    pub now: u64,
    /// Allowed skew for the `created` parameter (both directions), seconds.
    pub window_secs: u64,
    /// Header/derived components the endpoint requires **in addition to**
    /// [`REQUIRED_COMPONENTS`].
    pub extra_required: Vec<String>,
}

/// A parsed, structurally-validated signature; crypto not yet checked.
#[derive(Debug, Clone)]
pub struct ParsedSignature {
    pub label: String,
    pub covered: Vec<String>,
    pub created: i64,
    pub scheme: SigKeyScheme,
    /// The `alg` parameter from `Signature-Input`, if the signer included one.
    /// Optional per RFC 9421; when present it MUST be consistent with the key
    /// material (checked in [`verify_parsed`]).
    pub alg: Option<String>,
    /// The exact signature base string to verify.
    pub base: String,
    pub signature: Vec<u8>,
}

fn component_value(name: &str, parts: &RequestParts) -> Result<String, SigError> {
    if let Some(derived) = name.strip_prefix('@') {
        match derived {
            "method" => Ok(parts.method.to_string()),
            "authority" => Ok(parts.authority.to_string()),
            "path" => Ok(parts.path.to_string()),
            "query" => Ok(if parts.query.is_empty() {
                "?".to_string()
            } else {
                parts.query.to_string()
            }),
            _ => Err(SigError::new(
                SigErrorCode::InvalidInput,
                format!("unsupported derived component @{derived}"),
            )),
        }
    } else {
        (parts.header)(name).ok_or_else(|| {
            SigError::new(
                SigErrorCode::InvalidInput,
                format!("covered header field '{name}' not present"),
            )
        })
    }
}

/// Build the RFC 9421 signature base given covered component names, the raw
/// `Signature-Input` member text, and the request.
pub fn build_signature_base(
    covered: &[String],
    sig_params_raw: &str,
    parts: &RequestParts,
) -> Result<String, SigError> {
    let mut base = String::new();
    for name in covered {
        let value = component_value(name, parts)?;
        base.push_str(&sfv::serialize_string(name));
        base.push_str(": ");
        base.push_str(&value);
        base.push('\n');
    }
    base.push_str("\"@signature-params\": ");
    base.push_str(sig_params_raw);
    Ok(base)
}

/// Parse and structurally validate the signature on a request:
/// header correlation, covered-component requirements, `created` window,
/// `expires`. Returns the scheme so the caller can resolve the key, plus the
/// prepared base + signature bytes for [`verify_parsed`].
pub fn parse_request_signature(
    parts: &RequestParts,
    policy: &VerifyPolicy,
) -> Result<ParsedSignature, SigError> {
    let get = |h: &str| (parts.header)(h);
    // AAuth core profile, Verification step 1: if any of the three signature
    // headers is wholly absent, return `invalid_request` (distinct from
    // `invalid_signature`, which is for malformed/failed signatures). The AAuth
    // profile governs here over sigkey §5.4.2.
    let sig_input_hdr = get("signature-input").ok_or_else(|| {
        SigError::new(
            SigErrorCode::InvalidRequest,
            "missing Signature-Input header",
        )
    })?;
    let sig_hdr = get("signature")
        .ok_or_else(|| SigError::new(SigErrorCode::InvalidRequest, "missing Signature header"))?;
    let sig_key_hdr = get("signature-key").ok_or_else(|| {
        SigError::new(SigErrorCode::InvalidRequest, "missing Signature-Key header")
    })?;

    let inputs = sfv::parse_dictionary(&sig_input_hdr).map_err(|e| {
        SigError::new(
            SigErrorCode::InvalidSignature,
            format!("Signature-Input: {e}"),
        )
    })?;
    let sigs = sfv::parse_dictionary(&sig_hdr)
        .map_err(|e| SigError::new(SigErrorCode::InvalidSignature, format!("Signature: {e}")))?;
    let keys = sfv::parse_dictionary(&sig_key_hdr).map_err(|e| {
        SigError::new(
            SigErrorCode::InvalidSignature,
            format!("Signature-Key: {e}"),
        )
    })?;

    // Pick the first Signature-Key label that also appears in the other two
    // headers (single-signature deployments are the norm).
    let (label, key_member) = keys
        .iter()
        .find(|(label, _)| {
            inputs.iter().any(|(k, _)| k == label) && sigs.iter().any(|(k, _)| k == label)
        })
        .ok_or_else(|| {
            SigError::new(
                SigErrorCode::InvalidSignature,
                "no signature label present in Signature-Input, Signature, and Signature-Key",
            )
        })?;

    let scheme = crate::sigkey::parse_member(&key_member.value)?;

    let input_member = &inputs.iter().find(|(k, _)| k == label).unwrap().1;
    let (covered_items, params) = match &input_member.value {
        MemberValue::List(l) => (&l.items, &l.params),
        _ => {
            return Err(SigError::new(
                SigErrorCode::InvalidSignature,
                "Signature-Input member is not an inner list",
            ))
        }
    };

    let mut covered = Vec::with_capacity(covered_items.len());
    for (item, item_params) in covered_items {
        if !item_params.is_empty() {
            return Err(SigError::new(
                SigErrorCode::InvalidInput,
                "component parameters are not supported",
            ));
        }
        match item {
            BareItem::Str(s) => covered.push(s.clone()),
            _ => {
                return Err(SigError::new(
                    SigErrorCode::InvalidSignature,
                    "covered component is not a string",
                ))
            }
        }
    }

    // Required components
    let mut missing: Vec<String> = Vec::new();
    for req in REQUIRED_COMPONENTS
        .iter()
        .map(|s| s.to_string())
        .chain(policy.extra_required.iter().cloned())
    {
        if !covered.contains(&req) {
            missing.push(req);
        }
    }
    if !missing.is_empty() {
        let mut required: Vec<String> = REQUIRED_COMPONENTS.iter().map(|s| s.to_string()).collect();
        required.extend(policy.extra_required.iter().cloned());
        let mut err = SigError::new(
            SigErrorCode::InvalidInput,
            format!("missing covered components: {}", missing.join(", ")),
        );
        err.required_input = Some(required);
        return Err(err);
    }

    // created / expires
    let created = sfv::param(params, "created")
        .and_then(|v| v.as_int())
        .ok_or_else(|| {
            SigError::new(SigErrorCode::InvalidSignature, "missing created parameter")
        })?;
    let now = policy.now as i64;
    let window = policy.window_secs as i64;
    if created < now - window || created > now + window {
        return Err(SigError::new(
            SigErrorCode::InvalidSignature,
            "created timestamp outside validity window",
        ));
    }
    if let Some(expires) = sfv::param(params, "expires").and_then(|v| v.as_int()) {
        if expires < now {
            return Err(SigError::new(
                SigErrorCode::InvalidSignature,
                "signature expired",
            ));
        }
    }

    let signature = match &sigs.iter().find(|(k, _)| k == label).unwrap().1.value {
        MemberValue::Item(BareItem::Bytes(b), _) => b.clone(),
        _ => {
            return Err(SigError::new(
                SigErrorCode::InvalidSignature,
                "Signature member is not a byte sequence",
            ))
        }
    };

    let alg = sfv::param(params, "alg")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let base = build_signature_base(&covered, &input_member.raw, parts)?;

    Ok(ParsedSignature {
        label: label.clone(),
        covered,
        created,
        scheme,
        alg,
        base,
        signature,
    })
}

/// Verify the signature bytes against a resolved Ed25519 key.
pub fn verify_parsed(parsed: &ParsedSignature, key: &Jwk) -> Result<(), SigError> {
    if key.kty != "OKP" || key.crv != "Ed25519" {
        let mut err = SigError::new(
            SigErrorCode::UnsupportedAlgorithm,
            "only ed25519 signatures are supported",
        );
        err.required_input = None;
        return Err(err);
    }
    // RFC 9421 §6.4 / sigkey draft §6.4: the algorithm is derived from the key,
    // but if the signer included an `alg` parameter it MUST be consistent with
    // the key material. Our only key type is Ed25519 → `ed25519`.
    if let Some(alg) = &parsed.alg {
        if alg != "ed25519" {
            return Err(SigError::new(
                SigErrorCode::UnsupportedAlgorithm,
                format!("Signature-Input alg '{alg}' is inconsistent with the Ed25519 key"),
            ));
        }
    }
    let vk = key
        .verifying_key()
        .map_err(|_| SigError::new(SigErrorCode::InvalidKey, "unparseable public key"))?;
    let sig_bytes: [u8; 64] = parsed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| SigError::new(SigErrorCode::InvalidSignature, "bad signature length"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(parsed.base.as_bytes(), &sig).map_err(|_| {
        SigError::new(
            SigErrorCode::InvalidSignature,
            "signature verification failed",
        )
    })
}

/// The three headers produced by signing a request.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    pub signature_input: String,
    pub signature: String,
    pub signature_key: String,
}

/// Sign a request per the AAuth profile.
///
/// `signature_key_value` is the full `Signature-Key` member value (e.g.
/// `jwt;jwt="eyJ..."` — see [`crate::sigkey`] serializers). `extra_covered`
/// names additional headers to cover; their values must be resolvable via
/// `header`.
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    method: &str,
    authority: &str,
    path: &str,
    query: &str,
    extra_covered: &[&str],
    header: &dyn Fn(&str) -> Option<String>,
    signature_key_value: &str,
    key: &SigningKey,
    created: u64,
) -> Result<SignedHeaders, SigError> {
    let signature_key_header = format!("sig={signature_key_value}");
    let mut covered: Vec<String> = REQUIRED_COMPONENTS.iter().map(|s| s.to_string()).collect();
    covered.extend(extra_covered.iter().map(|s| s.to_string()));

    let covered_refs: Vec<&str> = covered.iter().map(|s| s.as_str()).collect();
    let sig_params_raw = format!(
        "{};created={created}",
        sfv::serialize_string_list(&covered_refs)
    );

    let skh = signature_key_header.clone();
    let header_with_sigkey = move |name: &str| -> Option<String> {
        if name == "signature-key" {
            Some(skh.clone())
        } else {
            header(name)
        }
    };
    let parts = RequestParts {
        method,
        authority,
        path,
        query,
        header: &header_with_sigkey,
    };
    let base = build_signature_base(&covered, &sig_params_raw, &parts)?;
    let sig = key.sign(base.as_bytes());
    Ok(SignedHeaders {
        signature_input: format!("sig={sig_params_raw}"),
        signature: format!("sig=:{}:", b64::encode_std(&sig.to_bytes())),
        signature_key: signature_key_header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::generate_signing_key;
    use crate::sigkey;
    use std::collections::HashMap;

    fn verify_roundtrip(extra: &[&str], headers: HashMap<String, String>) {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let now = 1_750_000_000u64;
        let hdrs = headers.clone();
        let lookup = move |name: &str| hdrs.get(name).cloned();
        let signed = sign_request(
            "POST",
            "ap.example",
            "/agent-token",
            "",
            extra,
            &lookup,
            &sigkey::serialize_hwk(&jwk),
            &sk,
            now,
        )
        .unwrap();

        let mut all = headers;
        all.insert("signature-input".into(), signed.signature_input);
        all.insert("signature".into(), signed.signature);
        all.insert("signature-key".into(), signed.signature_key);
        let lookup2 = move |name: &str| all.get(name).cloned();
        let parts = RequestParts {
            method: "POST",
            authority: "ap.example",
            path: "/agent-token",
            query: "",
            header: &lookup2,
        };
        let policy = VerifyPolicy {
            now,
            window_secs: 60,
            extra_required: extra.iter().map(|s| s.to_string()).collect(),
        };
        let parsed = parse_request_signature(&parts, &policy).unwrap();
        match &parsed.scheme {
            SigKeyScheme::Hwk(k) => assert_eq!(k.x, jwk.x),
            other => panic!("unexpected scheme {other:?}"),
        }
        verify_parsed(&parsed, &jwk).unwrap();
    }

    #[test]
    fn sign_verify_roundtrip_basic() {
        verify_roundtrip(&[], HashMap::new());
    }

    #[test]
    fn sign_verify_with_extra_headers() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        verify_roundtrip(&["content-type"], headers);
    }

    #[test]
    fn tampered_path_fails() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let now = 1_750_000_000u64;
        let lookup = |_: &str| None;
        let signed = sign_request(
            "POST",
            "ap.example",
            "/a",
            "",
            &[],
            &lookup,
            &sigkey::serialize_hwk(&jwk),
            &sk,
            now,
        )
        .unwrap();
        let mut all = HashMap::new();
        all.insert("signature-input".to_string(), signed.signature_input);
        all.insert("signature".to_string(), signed.signature);
        all.insert("signature-key".to_string(), signed.signature_key);
        let lookup2 = move |name: &str| all.get(name).cloned();
        let parts = RequestParts {
            method: "POST",
            authority: "ap.example",
            path: "/b", // tampered
            query: "",
            header: &lookup2,
        };
        let policy = VerifyPolicy {
            now,
            window_secs: 60,
            extra_required: vec![],
        };
        let parsed = parse_request_signature(&parts, &policy).unwrap();
        assert!(verify_parsed(&parsed, &jwk).is_err());
    }

    #[test]
    fn stale_created_rejected() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let now = 1_750_000_000u64;
        let lookup = |_: &str| None;
        let signed = sign_request(
            "GET",
            "ap.example",
            "/x",
            "",
            &[],
            &lookup,
            &sigkey::serialize_hwk(&jwk),
            &sk,
            now - 3600,
        )
        .unwrap();
        let mut all = HashMap::new();
        all.insert("signature-input".to_string(), signed.signature_input);
        all.insert("signature".to_string(), signed.signature);
        all.insert("signature-key".to_string(), signed.signature_key);
        let lookup2 = move |name: &str| all.get(name).cloned();
        let parts = RequestParts {
            method: "GET",
            authority: "ap.example",
            path: "/x",
            query: "",
            header: &lookup2,
        };
        let policy = VerifyPolicy {
            now,
            window_secs: 60,
            extra_required: vec![],
        };
        let err = parse_request_signature(&parts, &policy).unwrap_err();
        assert_eq!(err.code, SigErrorCode::InvalidSignature);
    }

    #[test]
    fn missing_required_component_reports_required_input() {
        // Hand-build a signature that omits signature-key from covered components.
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let now = 1_750_000_000u64;
        let raw = format!("(\"@method\" \"@authority\" \"@path\");created={now}");
        let parts_for_base = RequestParts {
            method: "GET",
            authority: "a.example",
            path: "/x",
            query: "",
            header: &|_| None,
        };
        let covered = vec![
            "@method".to_string(),
            "@authority".to_string(),
            "@path".to_string(),
        ];
        let base = build_signature_base(&covered, &raw, &parts_for_base).unwrap();
        use ed25519_dalek::Signer;
        let sig = sk.sign(base.as_bytes());

        let mut all = HashMap::new();
        all.insert("signature-input".to_string(), format!("sig={raw}"));
        all.insert(
            "signature".to_string(),
            format!("sig=:{}:", crate::b64::encode_std(&sig.to_bytes())),
        );
        all.insert(
            "signature-key".to_string(),
            format!("sig={}", sigkey::serialize_hwk(&jwk)),
        );
        let lookup = move |name: &str| all.get(name).cloned();
        let parts = RequestParts {
            method: "GET",
            authority: "a.example",
            path: "/x",
            query: "",
            header: &lookup,
        };
        let policy = VerifyPolicy {
            now,
            window_secs: 60,
            extra_required: vec![],
        };
        let err = parse_request_signature(&parts, &policy).unwrap_err();
        assert_eq!(err.code, SigErrorCode::InvalidInput);
        assert!(err
            .required_input
            .unwrap()
            .contains(&"signature-key".to_string()));
    }

    #[test]
    fn missing_signature_headers_are_invalid_request() {
        // AAuth core profile Verification step 1: absent headers → invalid_request.
        let lookup = |_: &str| None;
        let parts = RequestParts {
            method: "GET",
            authority: "a.example",
            path: "/x",
            query: "",
            header: &lookup,
        };
        let policy = VerifyPolicy {
            now: 1_750_000_000,
            window_secs: 60,
            extra_required: vec![],
        };
        let err = parse_request_signature(&parts, &policy).unwrap_err();
        assert_eq!(err.code, SigErrorCode::InvalidRequest);
    }

    #[test]
    fn alg_consistency_enforced() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        // An `alg` inconsistent with the Ed25519 key is rejected up front,
        // before signature bytes are even checked.
        let inconsistent = ParsedSignature {
            label: "sig".into(),
            covered: vec![],
            created: 0,
            scheme: SigKeyScheme::Hwk(jwk.clone()),
            alg: Some("ecdsa-p256-sha256".into()),
            base: "irrelevant".into(),
            signature: vec![0u8; 64],
        };
        assert_eq!(
            verify_parsed(&inconsistent, &jwk).unwrap_err().code,
            SigErrorCode::UnsupportedAlgorithm
        );

        // A consistent `alg` passes the consistency gate and proceeds to the
        // (here failing) signature check.
        let consistent = ParsedSignature {
            alg: Some("ed25519".into()),
            ..inconsistent
        };
        assert_eq!(
            verify_parsed(&consistent, &jwk).unwrap_err().code,
            SigErrorCode::InvalidSignature
        );
    }
}
