//! Issuer JWKS discovery and caching per the AAuth rules
//! (`research/01-aauth-protocol-overview.md` §5.7):
//!
//! - `{iss}/.well-known/{dwk}` → metadata (whose `issuer` MUST equal `iss`)
//!   → `jwks_uri` → JWKS
//! - cache per issuer; never fetch the same issuer more than once per minute;
//!   discard after 24 h; refresh once on unknown `kid`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use aauth_core::jwk::{Jwk, Jwks};
use aauth_core::sig::{SigError, SigErrorCode};
use tokio::sync::Mutex;

use crate::httpc::{self, EgressPolicy};

const FETCH_FLOOR: Duration = Duration::from_secs(60);
const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

struct Entry {
    jwks: Jwks,
    fetched_at: Instant,
}

pub struct JwksCache {
    policy: EgressPolicy,
    entries: Mutex<HashMap<String, Entry>>,
    last_attempt: Mutex<HashMap<String, Instant>>,
}

impl JwksCache {
    pub fn new(policy: EgressPolicy) -> JwksCache {
        JwksCache {
            policy,
            entries: Mutex::new(HashMap::new()),
            last_attempt: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve a key for `iss` (a server identifier) + `dwk` document + `kid`.
    pub async fn get_key(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError> {
        let cache_key = format!("{iss}|{dwk}");

        // Fresh-enough cached JWKS with the kid?
        {
            let entries = self.entries.lock().await;
            if let Some(entry) = entries.get(&cache_key) {
                if entry.fetched_at.elapsed() < MAX_AGE {
                    if let Some(key) = entry.jwks.find(kid) {
                        return Ok(key);
                    }
                }
            }
        }

        // Unknown kid (or no cache): refresh, subject to the per-issuer floor.
        {
            let mut attempts = self.last_attempt.lock().await;
            if let Some(last) = attempts.get(&cache_key) {
                if last.elapsed() < FETCH_FLOOR {
                    return Err(SigError::new(
                        SigErrorCode::UnknownKey,
                        format!("kid '{kid}' not found for {iss} (fetch floor active)"),
                    ));
                }
            }
            attempts.insert(cache_key.clone(), Instant::now());
        }

        let jwks = self.fetch(iss, dwk).await?;
        let found = jwks.find(kid);
        self.entries.lock().await.insert(
            cache_key,
            Entry {
                jwks,
                fetched_at: Instant::now(),
            },
        );
        found.ok_or_else(|| {
            SigError::new(
                SigErrorCode::UnknownKey,
                format!("kid '{kid}' not in JWKS of {iss}"),
            )
        })
    }

    async fn fetch(&self, iss: &str, dwk: &str) -> Result<Jwks, SigError> {
        let meta_url = format!("{iss}/.well-known/{dwk}");
        let metadata = httpc::get_json(&meta_url, &self.policy)
            .await
            .map_err(|e| SigError::new(SigErrorCode::UnknownKey, format!("metadata fetch: {e}")))?;
        // Host-poisoning defense: the document must claim the issuer it was
        // fetched from.
        let issuer = metadata.get("issuer").and_then(|v| v.as_str());
        if issuer != Some(iss) {
            return Err(SigError::new(
                SigErrorCode::InvalidKey,
                format!("metadata issuer mismatch at {meta_url}"),
            ));
        }
        let jwks_uri = metadata
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                SigError::new(
                    SigErrorCode::UnknownKey,
                    format!("no jwks_uri in {meta_url}"),
                )
            })?;
        let jwks_val = httpc::get_json(jwks_uri, &self.policy)
            .await
            .map_err(|e| SigError::new(SigErrorCode::UnknownKey, format!("jwks fetch: {e}")))?;
        serde_json::from_value(jwks_val)
            .map_err(|e| SigError::new(SigErrorCode::InvalidKey, format!("invalid JWKS: {e}")))
    }
}
