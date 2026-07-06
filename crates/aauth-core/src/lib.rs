//! # aauth-core
//!
//! Protocol primitives for AAuth (`draft-hardt-oauth-aauth-protocol`) and
//! HTTP Signature Keys (`draft-hardt-httpbis-signature-key`):
//!
//! - unpadded base64url ([`b64`])
//! - Ed25519 JWKs, JWKS documents and RFC 7638 thumbprints ([`jwk`])
//! - EdDSA JWT signing and verification ([`jwt`])
//! - agent (`aauth:local@domain`) and server identifiers ([`ident`])
//! - RFC 8941 Structured Fields, the subset AAuth uses ([`sfv`])
//! - RFC 9421 HTTP Message Signatures: signature base construction,
//!   request signing and verification per the AAuth profile ([`sig`])
//! - `Signature-Key` header schemes: `hwk`, `jwt`, `jkt-jwt`, `jwks_uri` ([`sigkey`])
//! - AAuth token claim types: agent, subscribe, event tokens ([`tokens`])
//!
//! This crate performs no I/O and has no async runtime: callers resolve keys
//! (e.g. fetch JWKS documents) and hand them in. It is usable by all AAuth
//! parties — agents signing requests, resources and servers verifying them.

pub mod b64;
pub mod ident;
pub mod jwk;
pub mod jwt;
pub mod sfv;
pub mod sig;
pub mod sigkey;
pub mod tokens;

/// Seconds since the Unix epoch.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fill `buf` with cryptographically secure random bytes.
pub fn rand_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS random source unavailable");
}

/// Random identifier over a lowercase, unambiguous alphabet
/// (Crockford base32 folded to lowercase), `len` characters.
pub fn rand_id(len: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut buf = vec![0u8; len];
    rand_bytes(&mut buf);
    buf.iter()
        .map(|b| ALPHABET[(b & 31) as usize] as char)
        .collect()
}

/// Random token with ~`bits` of entropy, base64url-encoded (for enrollment
/// tokens, jti values, pending identifiers).
pub fn rand_token(bits: usize) -> String {
    let mut buf = vec![0u8; bits.div_ceil(8)];
    rand_bytes(&mut buf);
    b64::encode(&buf)
}

/// Interaction-code style random string per the AAuth interaction code rules:
/// Crockford base32 alphabet (uppercase, no I/L/O/U), >= 40 bits of entropy.
pub fn rand_crockford(symbols: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut buf = vec![0u8; symbols];
    rand_bytes(&mut buf);
    buf.iter()
        .map(|b| ALPHABET[(b & 31) as usize] as char)
        .collect()
}
