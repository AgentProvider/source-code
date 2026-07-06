//! AP signing keys: generation, rotation, JWKS rendering.
//!
//! The keys file holds Ed25519 seeds. All instances of a deployment must
//! share the same file (or secret). Rotation appends a new key and marks it
//! active; old public keys stay published until every token signed with them
//! has expired (<= max agent token lifetime), then can be pruned with
//! `apd keygen --prune`.

use aauth_core::{b64, jwk::Jwk, now_unix};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub active: String,
    pub keys: Vec<KeyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub kid: String,
    /// base64url Ed25519 seed (32 bytes) — SECRET.
    pub d: String,
    pub created_at: u64,
}

pub struct KeySet {
    pub active_kid: String,
    pub active_key: SigningKey,
    /// All public keys, for the JWKS and for verifying tokens we issued
    /// (matched by `kid`), active first.
    pub public_jwks: Vec<Jwk>,
}

impl KeySet {
    pub fn load(path: &str) -> Result<KeySet, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read keys file {path}: {e} (run `apd keygen` first)"))?;
        let kf: KeyFile =
            serde_json::from_str(&raw).map_err(|e| format!("invalid keys file {path}: {e}"))?;
        if kf.keys.is_empty() {
            return Err("keys file contains no keys".into());
        }
        let mut public_jwks = Vec::new();
        let mut active_key = None;
        // active key's JWK first in the JWKS
        let mut ordered: Vec<&KeyEntry> = kf.keys.iter().collect();
        ordered.sort_by_key(|k| if k.kid == kf.active { 0 } else { 1 });
        for entry in ordered {
            let seed: [u8; 32] = b64::decode_fixed(&entry.d)
                .map_err(|e| format!("bad key seed for kid {}: {e}", entry.kid))?;
            let sk = SigningKey::from_bytes(&seed);
            let mut jwk = Jwk::from_verifying_key(&sk.verifying_key());
            jwk.kid = Some(entry.kid.clone());
            jwk.alg = Some("EdDSA".into());
            jwk.use_ = Some("sig".into());
            public_jwks.push(jwk);
            if entry.kid == kf.active {
                active_key = Some(sk.clone());
            }
        }
        let active_key =
            active_key.ok_or_else(|| format!("active kid '{}' not present in keys", kf.active))?;
        Ok(KeySet {
            active_kid: kf.active,
            active_key,
            public_jwks,
        })
    }

    pub fn find_public(&self, kid: &str) -> Option<&Jwk> {
        self.public_jwks
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid))
    }

    /// The JWKS document body.
    pub fn jwks_json(&self) -> serde_json::Value {
        serde_json::json!({ "keys": self.public_jwks })
    }
}

fn new_entry() -> KeyEntry {
    let mut seed = [0u8; 32];
    aauth_core::rand_bytes(&mut seed);
    KeyEntry {
        kid: format!("ap-{}", aauth_core::rand_id(10)),
        d: b64::encode(&seed),
        created_at: now_unix(),
    }
}

/// `apd keygen`: create the keys file, or rotate/prune an existing one.
pub fn keygen(
    path: &str,
    rotate: bool,
    prune_older_than_secs: Option<u64>,
) -> Result<String, String> {
    let existing = std::fs::read_to_string(path).ok();
    let mut kf: KeyFile = match existing {
        Some(raw) => serde_json::from_str(&raw).map_err(|e| format!("invalid keys file: {e}"))?,
        None => {
            let entry = new_entry();
            let kf = KeyFile {
                active: entry.kid.clone(),
                keys: vec![entry],
            };
            write_keyfile(path, &kf)?;
            return Ok(format!(
                "created {path} with new active key '{}'",
                kf.active
            ));
        }
    };
    let mut msg = String::new();
    if rotate {
        let entry = new_entry();
        msg = format!("rotated: new active key '{}'", entry.kid);
        kf.active = entry.kid.clone();
        kf.keys.push(entry);
    }
    if let Some(age) = prune_older_than_secs {
        let cutoff = now_unix().saturating_sub(age);
        let active = kf.active.clone();
        let before = kf.keys.len();
        kf.keys
            .retain(|k| k.kid == active || k.created_at >= cutoff);
        msg.push_str(&format!(" pruned {} old keys", before - kf.keys.len()));
    }
    if !rotate && prune_older_than_secs.is_none() {
        return Ok(format!(
            "keys file {path} exists (active '{}', {} keys). Use --rotate to rotate.",
            kf.active,
            kf.keys.len()
        ));
    }
    write_keyfile(path, &kf)?;
    Ok(msg.trim().to_string())
}

fn write_keyfile(path: &str, kf: &KeyFile) -> Result<(), String> {
    let tmp = format!("{path}.tmp");
    let data = serde_json::to_string_pretty(kf).unwrap();
    std::fs::write(&tmp, &data).map_err(|e| format!("cannot write {tmp}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot move {tmp} into place: {e}"))?;
    Ok(())
}
