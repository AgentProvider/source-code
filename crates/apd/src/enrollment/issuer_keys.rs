//! Trusted-issuer runtime state and verification-key resolution.
//!
//! Static material (jwks_file / inline jwks / CA bundles / CRLs) is loaded
//! once at startup so misconfiguration fails fast. Remote JWKS (oidc /
//! jwks_uri types) are fetched on demand with the same discipline as all
//! outbound key fetches: egress admission, a once-per-minute per-issuer
//! floor, a 24 h cache ceiling, and refresh-on-unknown-kid.

use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::config::TrustedIssuer;
use crate::httpc::{self, EgressPolicy};

use super::anyjwk::AnyJwk;
use super::x509::pem_blocks;

const FETCH_FLOOR: Duration = Duration::from_secs(60);
const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

pub struct IssuerRuntime {
    pub cfg: TrustedIssuer,
    /// Static keys (jwks_file / jwks types).
    static_keys: Option<Vec<AnyJwk>>,
    /// Trusted roots + CRLs (x5c type), DER.
    pub ca_roots: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    /// Cache for remote keys (oidc / jwks_uri types).
    cache: Mutex<RemoteCache>,
    egress: EgressPolicy,
}

#[derive(Default)]
struct RemoteCache {
    keys: Option<(Vec<AnyJwk>, Instant)>,
    last_attempt: Option<Instant>,
}

impl IssuerRuntime {
    /// Load static material; fail fast on misconfiguration.
    pub fn load(cfg: &TrustedIssuer, global_insecure: bool) -> Result<IssuerRuntime, String> {
        let ctx = format!("trusted issuer '{}'", cfg.name);
        let mut static_keys = None;
        let mut ca_roots = Vec::new();
        let mut crls = Vec::new();

        match cfg.issuer_type.as_str() {
            "jwks" => {
                let value = cfg.jwks.as_ref().unwrap();
                let keys = AnyJwk::parse_jwks(value);
                if keys.is_empty() {
                    return Err(format!("{ctx}: inline jwks contains no supported keys"));
                }
                static_keys = Some(keys);
            }
            "jwks_file" => {
                let path = cfg.jwks_file.as_ref().unwrap();
                let raw = std::fs::read_to_string(path)
                    .map_err(|e| format!("{ctx}: cannot read jwks_file {path}: {e}"))?;
                let value: serde_json::Value = serde_json::from_str(&raw)
                    .map_err(|e| format!("{ctx}: invalid JWKS in {path}: {e}"))?;
                let keys = AnyJwk::parse_jwks(&value);
                if keys.is_empty() {
                    return Err(format!("{ctx}: {path} contains no supported keys"));
                }
                static_keys = Some(keys);
            }
            "x5c" => {
                let path = cfg.ca_bundle_file.as_ref().unwrap();
                let raw = std::fs::read(path)
                    .map_err(|e| format!("{ctx}: cannot read ca_bundle_file {path}: {e}"))?;
                ca_roots = pem_blocks(&raw, "CERTIFICATE");
                if ca_roots.is_empty() {
                    return Err(format!("{ctx}: {path} contains no certificates"));
                }
                if let Some(crl_path) = &cfg.crl_file {
                    let raw = std::fs::read(crl_path)
                        .map_err(|e| format!("{ctx}: cannot read crl_file {crl_path}: {e}"))?;
                    crls = pem_blocks(&raw, "X509 CRL");
                    if crls.is_empty() {
                        return Err(format!("{ctx}: {crl_path} contains no CRLs"));
                    }
                }
            }
            "oidc" | "jwks_uri" => {}
            _ => unreachable!("validated in config"),
        }

        let egress = if cfg.allow_insecure_egress || global_insecure {
            EgressPolicy::from_config(true)
        } else {
            EgressPolicy::from_config(false)
        };

        Ok(IssuerRuntime {
            cfg: cfg.clone(),
            static_keys,
            ca_roots,
            crls,
            cache: Mutex::new(RemoteCache::default()),
            egress,
        })
    }

    pub fn is_x5c(&self) -> bool {
        self.cfg.issuer_type == "x5c"
    }

    /// Resolve candidate verification keys for a token with the given
    /// `kid`/`alg`. Static types answer immediately; remote types consult the
    /// cache and fetch when needed.
    pub async fn resolve_keys(&self, kid: Option<&str>, alg: &str) -> Result<Vec<AnyJwk>, String> {
        if let Some(keys) = &self.static_keys {
            return Ok(select(keys, kid, alg));
        }
        if self.is_x5c() {
            return Err("x5c issuers resolve keys from the certificate chain".into());
        }

        // Remote: try cache first.
        {
            let cache = self.cache.lock().await;
            if let Some((keys, fetched_at)) = &cache.keys {
                if fetched_at.elapsed() < MAX_AGE {
                    let found = select(keys, kid, alg);
                    if !found.is_empty() {
                        return Ok(found);
                    }
                }
            }
        }
        // Miss or unknown kid: refresh under the per-issuer floor.
        {
            let mut cache = self.cache.lock().await;
            if let Some(last) = cache.last_attempt {
                if last.elapsed() < FETCH_FLOOR {
                    return Err(format!(
                        "no key for kid {kid:?} at issuer '{}' (fetch floor active)",
                        self.cfg.name
                    ));
                }
            }
            cache.last_attempt = Some(Instant::now());
        }
        let keys = self.fetch_remote().await?;
        let found = select(&keys, kid, alg);
        self.cache.lock().await.keys = Some((keys, Instant::now()));
        if found.is_empty() {
            Err(format!(
                "no key matching kid {kid:?} / alg {alg} at issuer '{}'",
                self.cfg.name
            ))
        } else {
            Ok(found)
        }
    }

    async fn fetch_remote(&self) -> Result<Vec<AnyJwk>, String> {
        let jwks_uri = match self.cfg.issuer_type.as_str() {
            "jwks_uri" => self.cfg.jwks_uri.clone().unwrap(),
            "oidc" => {
                if let Some(explicit) = &self.cfg.jwks_uri {
                    explicit.clone()
                } else {
                    // OIDC discovery. The discovery document's `issuer` MUST
                    // match the configured issuer (OIDC Core §4.3).
                    let base = self.cfg.issuer.trim_end_matches('/');
                    let url = format!("{base}/.well-known/openid-configuration");
                    let doc = httpc::get_json(&url, &self.egress)
                        .await
                        .map_err(|e| format!("OIDC discovery for '{}': {e}", self.cfg.name))?;
                    let doc_issuer = doc.get("issuer").and_then(|v| v.as_str());
                    if doc_issuer.map(|s| s.trim_end_matches('/')) != Some(base) {
                        return Err(format!(
                            "OIDC discovery issuer mismatch for '{}' (got {doc_issuer:?})",
                            self.cfg.name
                        ));
                    }
                    doc.get("jwks_uri")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            format!("no jwks_uri in OIDC discovery for '{}'", self.cfg.name)
                        })?
                        .to_string()
                }
            }
            _ => unreachable!(),
        };
        let jwks = httpc::get_json(&jwks_uri, &self.egress)
            .await
            .map_err(|e| format!("JWKS fetch for '{}': {e}", self.cfg.name))?;
        let keys = AnyJwk::parse_jwks(&jwks);
        if keys.is_empty() {
            return Err(format!(
                "JWKS for issuer '{}' contains no supported keys",
                self.cfg.name
            ));
        }
        Ok(keys)
    }
}

/// Key selection: prefer an exact `kid` match; otherwise all alg-compatible
/// keys (tried in order by the caller).
fn select(keys: &[AnyJwk], kid: Option<&str>, alg: &str) -> Vec<AnyJwk> {
    if let Some(kid) = kid {
        let by_kid: Vec<AnyJwk> = keys
            .iter()
            .filter(|k| k.kid.as_deref() == Some(kid) && k.supports_alg(alg))
            .cloned()
            .collect();
        if !by_kid.is_empty() {
            return by_kid;
        }
    }
    keys.iter()
        .filter(|k| k.supports_alg(alg))
        .cloned()
        .collect()
}
