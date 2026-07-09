//! Shared application state and cross-cutting helpers used by handlers.

use std::sync::Arc;

use aauth_core::now_unix;

use crate::audit::Audit;
use crate::config::Config;
use crate::enrollment::IssuerRuntime;
use crate::httpc::EgressPolicy;
use crate::jwks_cache::JwksCache;
use crate::keys::KeySet;
use crate::storage::Store;

pub struct App {
    pub cfg: Config,
    pub keys: KeySet,
    pub store: Store,
    pub jwks_cache: JwksCache,
    /// Trusted federated-enrollment issuers (static material pre-loaded).
    pub issuers: Vec<IssuerRuntime>,
    pub audit: Audit,
    /// Pre-serialized bytes for the well-known metadata + JWKS documents.
    /// Verification traffic hammers these; serialize once at startup.
    pub agent_metadata_bytes: Vec<u8>,
    pub jwks_bytes: Vec<u8>,
    pub started_at: u64,
}

impl App {
    /// Build the application state. Fails fast on unloadable issuer material
    /// (JWKS files, CA bundles, CRLs) or an unopenable audit log.
    pub fn new(cfg: Config, keys: KeySet, store: Store) -> Result<Arc<App>, String> {
        let egress = EgressPolicy::from_config(cfg.insecure_dev_mode);
        let jwks_cache = JwksCache::new(egress.clone(), cfg.jwks_cross_origin_hosts.clone());
        let agent_metadata_bytes =
            serde_json::to_vec(&build_agent_metadata(&cfg)).expect("serialize metadata");
        let jwks_bytes = serde_json::to_vec(&keys.jwks_json()).expect("serialize jwks");
        let issuers = cfg
            .enrollment
            .trusted_issuers
            .iter()
            .map(|issuer| IssuerRuntime::load(issuer, cfg.insecure_dev_mode))
            .collect::<Result<Vec<_>, String>>()?;
        let audit = Audit::new(cfg.audit_log_file.as_deref())?;
        Ok(Arc::new(App {
            cfg,
            keys,
            store,
            jwks_cache,
            issuers,
            audit,
            agent_metadata_bytes,
            jwks_bytes,
            started_at: now_unix(),
        }))
    }
}

/// Build the `/.well-known/aauth-agent.json` document.
pub fn build_agent_metadata(cfg: &Config) -> serde_json::Value {
    let mut doc = serde_json::Map::new();
    doc.insert("issuer".into(), cfg.issuer.clone().into());
    doc.insert(
        "jwks_uri".into(),
        format!("{}/.well-known/jwks.json", cfg.issuer).into(),
    );
    if let Some(v) = &cfg.metadata.name {
        doc.insert("name".into(), v.clone().into());
    }
    if let Some(v) = &cfg.metadata.description {
        doc.insert("description".into(), v.clone().into());
    }
    if let Some(v) = &cfg.metadata.logo_uri {
        doc.insert("logo_uri".into(), v.clone().into());
    }
    if let Some(v) = &cfg.metadata.logo_dark_uri {
        doc.insert("logo_dark_uri".into(), v.clone().into());
    }
    if let Some(v) = &cfg.metadata.documentation_uri {
        doc.insert("documentation_uri".into(), v.clone().into());
    }
    if let Some(v) = &cfg.metadata.tos_uri {
        doc.insert("tos_uri".into(), v.clone().into());
    }
    if let Some(v) = &cfg.metadata.policy_uri {
        doc.insert("policy_uri".into(), v.clone().into());
    }
    if cfg.events.enabled {
        doc.insert(
            "event_endpoint".into(),
            format!("{}/events", cfg.issuer).into(),
        );
    }
    serde_json::Value::Object(doc)
}
