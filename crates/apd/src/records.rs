//! Persistent records and their storage keys.
//!
//! Key layout (all under the configured prefix for the redis backend):
//!
//! - `agent:{local}`          → [`AgentRecord`]
//! - `jkt:{durable_jkt}`      → local part (enrollment lookup by key thumbprint)
//! - `enrolltok:{token}`      → [`EnrollTokenRecord`] (TTL'd, consumed atomically)
//! - `jti:{jti}`              → "1" (naming-JWT replay guard, TTL'd)
//! - `sub:{eid}`              → [`SubscriptionRecord`]
//! - `subuses:{eid}`          → integer use counter (atomic INCR)
//! - `inbox:{local}`          → list of [`InboxItem`]

use serde::{Deserialize, Serialize};

pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_REVOKED: &str = "revoked";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub local: String,
    pub durable_jkt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at: u64,
    pub status: String,
    /// Unix time of the most recent agent-token issuance.
    #[serde(default)]
    pub last_issued_at: u64,
    /// Count of agent tokens issued.
    #[serde(default)]
    pub tokens_issued: u64,
    /// How the enrollment was authorized: "token" | "federated" | "allowlist" | "open".
    #[serde(default = "default_method")]
    pub method: String,
    /// Trusted-issuer name (federated enrollments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Assertion subject (federated enrollments), for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Claims stamped into every agent token issued for this enrollment
    /// (from the issuer's embed_claims policy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embed_claims: Option<serde_json::Map<String, serde_json::Value>>,
}

fn default_method() -> String {
    "token".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollTokenRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at: u64,
}

/// A pre-registered durable-key thumbprint (the `allowlist` enrollment
/// method): an orchestrator registers the key it provisioned via the admin
/// API; the agent then enrolls with only that key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedKeyRecord {
    pub jkt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionRecord {
    pub eid: String,
    pub agent_local: String,
    /// Full agent identifier (`aauth:local@domain`).
    pub agent_id: String,
    /// The resource authorized to deliver events (subscribe token `aud`).
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxItem {
    pub event_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    pub received_at: u64,
    pub iss: String,
    pub eid: String,
}

pub fn agent_key(local: &str) -> String {
    format!("agent:{local}")
}
pub fn jkt_key(jkt: &str) -> String {
    format!("jkt:{jkt}")
}
pub fn enroll_token_key(token: &str) -> String {
    format!("enrolltok:{token}")
}
pub fn allowed_key_key(jkt: &str) -> String {
    format!("allowkey:{jkt}")
}
pub fn assertion_jti_key(jti: &str) -> String {
    format!("ajti:{jti}")
}
pub fn jti_key(jti: &str) -> String {
    format!("jti:{jti}")
}
pub fn subscription_key(eid: &str) -> String {
    format!("sub:{eid}")
}
pub fn sub_uses_key(eid: &str) -> String {
    format!("subuses:{eid}")
}
pub fn inbox_key(local: &str) -> String {
    format!("inbox:{local}")
}
