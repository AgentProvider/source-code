//! Configuration: a JSON file plus environment overrides.
//!
//! Kept to JSON deliberately (serde_json is already a dependency; no TOML
//! parser needed). `apd example-config` prints a commented starting point.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The AP's server identifier, e.g. "https://ap.example".
    /// This exact URL must serve /.well-known/aauth-agent.json.
    pub issuer: String,

    /// Listen address, e.g. "127.0.0.1:8420" or "0.0.0.0:8420".
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Path to the signing keys file (see `apd keygen`).
    #[serde(default = "default_keys_file")]
    pub keys_file: String,

    #[serde(default)]
    pub storage: StorageConfig,

    /// Agent token lifetime in seconds (max 86400 per spec; default 1h).
    #[serde(default = "default_agent_token_ttl")]
    pub agent_token_ttl_secs: u64,

    /// Subscribe token registration-window lifetime (default 24h).
    #[serde(default = "default_subscribe_token_ttl")]
    pub subscribe_token_ttl_secs: u64,

    /// HTTP signature `created` validity window, seconds (default 60).
    #[serde(default = "default_signature_window")]
    pub signature_window_secs: u64,

    /// Maximum accepted naming-JWT lifetime (exp - iat), seconds.
    #[serde(default = "default_naming_jwt_max")]
    pub naming_jwt_max_lifetime_secs: u64,

    #[serde(default)]
    pub enrollment: EnrollmentConfig,

    /// Admin API bearer token. Prefer the APD_ADMIN_TOKEN env var.
    /// If neither is set, the /admin API is disabled.
    #[serde(default)]
    pub admin_token: Option<String>,

    /// Allow the `ps` in a token request body to differ from the enrollment's.
    #[serde(default = "default_true")]
    pub allow_ps_override: bool,

    #[serde(default)]
    pub metadata: MetadataConfig,

    #[serde(default)]
    pub events: EventsConfig,

    /// DEVELOPMENT ONLY. Accepts an http:// issuer (and ports), allows
    /// outbound fetches over http and to private/loopback addresses.
    /// Never enable in production.
    #[serde(default)]
    pub insecure_dev_mode: bool,

    /// Maximum request body size in bytes.
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,

    /// Hosts explicitly admitted as cross-origin JWKS hosts when verifying
    /// foreign tokens (event deliveries): a resource's metadata may point
    /// `jwks_uri` at a different host than its issuer (e.g. a CDN). Empty
    /// (default) means same-origin JWKS only, per the Signature-Key draft's
    /// requirement that cross-origin JWKS URLs need explicit deployment
    /// admission. List bare hostnames, e.g. ["jwks.cdn.example"].
    #[serde(default)]
    pub jwks_cross_origin_hosts: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// "memory" (default), "file", or "redis".
    #[serde(default = "default_backend")]
    pub backend: String,
    /// File path for the "file" backend.
    #[serde(default)]
    pub path: Option<String>,
    /// Redis address "host:port" for the "redis" backend
    /// (plain TCP; run on a trusted network / localhost / TLS tunnel).
    #[serde(default)]
    pub redis_addr: Option<String>,
    /// Key prefix for the "redis" backend.
    #[serde(default = "default_prefix")]
    pub key_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentConfig {
    /// "token" (default): enrollment requires a single-use admin-minted
    /// enrollment token. "open": any key may enroll (dev / trusted networks).
    #[serde(default = "default_enroll_mode")]
    pub mode: String,
    /// Default PS bound into agent tokens when the enrollment doesn't set one.
    #[serde(default)]
    pub default_ps: Option<String>,
}

impl Default for EnrollmentConfig {
    fn default() -> Self {
        EnrollmentConfig {
            mode: default_enroll_mode(),
            default_ps: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub logo_dark_uri: Option<String>,
    #[serde(default)]
    pub documentation_uri: Option<String>,
    #[serde(default)]
    pub tos_uri: Option<String>,
    #[serde(default)]
    pub policy_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsConfig {
    /// Enable AAuth Events (subscribe tokens, /events endpoint, inbox).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How long undelivered inbox events are retained, seconds.
    #[serde(default = "default_inbox_ttl")]
    pub inbox_ttl_secs: u64,
    /// Max pending events per agent (oldest dropped beyond this).
    #[serde(default = "default_inbox_max")]
    pub max_pending_per_agent: usize,
    /// Max event payload size accepted at /events, bytes.
    #[serde(default = "default_max_payload")]
    pub max_payload_bytes: usize,
}

impl Default for EventsConfig {
    fn default() -> Self {
        serde_json::from_str("{}").unwrap()
    }
}

fn default_listen() -> String {
    "127.0.0.1:8420".into()
}
fn default_keys_file() -> String {
    "apd-keys.json".into()
}
fn default_backend() -> String {
    "memory".into()
}
fn default_prefix() -> String {
    "apd:".into()
}
fn default_enroll_mode() -> String {
    "token".into()
}
fn default_agent_token_ttl() -> u64 {
    3600
}
fn default_subscribe_token_ttl() -> u64 {
    86400
}
fn default_signature_window() -> u64 {
    60
}
fn default_naming_jwt_max() -> u64 {
    300
}
fn default_inbox_ttl() -> u64 {
    7 * 24 * 3600
}
fn default_inbox_max() -> usize {
    1000
}
fn default_max_payload() -> usize {
    64 * 1024
}
fn default_max_body() -> usize {
    64 * 1024
}
fn default_true() -> bool {
    true
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read config {path}: {e}"))?;
        let mut cfg: Config =
            serde_json::from_str(&raw).map_err(|e| format!("invalid config {path}: {e}"))?;
        cfg.apply_env();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("APD_ISSUER") {
            self.issuer = v;
        }
        if let Ok(v) = std::env::var("APD_LISTEN") {
            self.listen = v;
        }
        if let Ok(v) = std::env::var("APD_KEYS_FILE") {
            self.keys_file = v;
        }
        if let Ok(v) = std::env::var("APD_ADMIN_TOKEN") {
            self.admin_token = Some(v);
        }
        if let Ok(v) = std::env::var("APD_REDIS_ADDR") {
            self.storage.backend = "redis".into();
            self.storage.redis_addr = Some(v);
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        aauth_core::ident::validate_server_identifier(&self.issuer, self.insecure_dev_mode)
            .map_err(|_| {
                format!(
                    "issuer '{}' is not a valid AAuth server identifier \
                     (https://host, lowercase, no port/path). \
                     Set insecure_dev_mode=true for local http development.",
                    self.issuer
                )
            })?;
        if self.agent_token_ttl_secs == 0
            || self.agent_token_ttl_secs > aauth_core::tokens::AGENT_TOKEN_MAX_TTL_SECS
        {
            return Err(format!(
                "agent_token_ttl_secs must be 1..={} (spec: agent tokens SHOULD NOT exceed 24h)",
                aauth_core::tokens::AGENT_TOKEN_MAX_TTL_SECS
            ));
        }
        match self.storage.backend.as_str() {
            "memory" => {}
            "file" => {
                if self.storage.path.is_none() {
                    return Err("storage.path is required for the file backend".into());
                }
            }
            "redis" => {
                if self.storage.redis_addr.is_none() {
                    return Err("storage.redis_addr is required for the redis backend".into());
                }
            }
            other => return Err(format!("unknown storage backend '{other}'")),
        }
        match self.enrollment.mode.as_str() {
            "token" | "open" => {}
            other => return Err(format!("unknown enrollment mode '{other}'")),
        }
        if let Some(ps) = &self.enrollment.default_ps {
            aauth_core::ident::validate_server_identifier(ps, self.insecure_dev_mode).map_err(
                |_| "enrollment.default_ps is not a valid server identifier".to_string(),
            )?;
        }
        Ok(())
    }

    /// The domain part used in agent identifiers (issuer host).
    pub fn agent_domain(&self) -> String {
        aauth_core::ident::host_of(&self.issuer).expect("validated issuer")
    }
}

pub const EXAMPLE_CONFIG: &str = r#"{
  "issuer": "https://ap.example.com",
  "listen": "127.0.0.1:8420",
  "keys_file": "/var/lib/apd/apd-keys.json",
  "storage": { "backend": "file", "path": "/var/lib/apd/apd-state.json" },
  "agent_token_ttl_secs": 3600,
  "subscribe_token_ttl_secs": 86400,
  "signature_window_secs": 60,
  "enrollment": { "mode": "token" },
  "allow_ps_override": true,
  "metadata": {
    "name": "Example Agent Provider",
    "description": "Self-hosted AAuth agent provider.",
    "documentation_uri": "https://ap.example.com/docs"
  },
  "events": { "enabled": true },
  "insecure_dev_mode": false
}
"#;
