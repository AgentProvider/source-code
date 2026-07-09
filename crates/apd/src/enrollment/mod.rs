//! Enrollment methods and orchestration. See
//! `docs/federated-enrollment-design.md` for the model and
//! `docs/federated-enrollment.md` for operator recipes.
//!
//! Methods (composable via `enrollment.methods`):
//! - `token`     — single-use admin-minted enrollment tokens, plus reusable
//!   **static tokens** predefined in config (dev/staging convenience)
//! - `federated` — trusted-issuer assertions (OIDC / static JWKS / x5c-PKI)
//! - `allowlist` — pre-registered durable-key thumbprints (admin API)
//! - `open`      — no gate (dev / trusted networks)

pub mod anyjwk;
pub mod assertion;
pub mod issuer_keys;
pub mod x509;

pub use assertion::{verify_assertion, FederatedVerdict};
pub use issuer_keys::IssuerRuntime;

/// Constant-time byte equality (secret comparisons: admin bearer, static
/// enrollment tokens).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// How an enrollment was authorized (recorded on the agent record + audit).
#[derive(Debug)]
pub enum Authorized {
    Token {
        ps: Option<String>,
        label: Option<String>,
        /// True when a predefined static token (reusable, config-defined)
        /// authorized the enrollment rather than a minted single-use token.
        static_token: bool,
    },
    Federated(FederatedVerdict),
    Allowlist {
        ps: Option<String>,
        label: Option<String>,
    },
    Open,
}

impl Authorized {
    pub fn method(&self) -> &'static str {
        match self {
            Authorized::Token { .. } => "token",
            Authorized::Federated(_) => "federated",
            Authorized::Allowlist { .. } => "allowlist",
            Authorized::Open => "open",
        }
    }
}
