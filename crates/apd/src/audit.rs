//! Structured audit logging: one JSON object per line, to stderr and
//! (optionally) an append-only file. Federated enrollment removes humans from
//! the issuance loop, so the audit stream is the review trail.
//!
//! Events: `enroll`, `enroll_denied`, `agent_token_issued`,
//! `subagent_token_issued`, `agent_revoked`, `agent_reinstated`,
//! `enrollment_token_minted`, `allowed_key_added`, `allowed_key_removed`,
//! `event_delivered`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

pub struct Audit {
    file: Option<Mutex<File>>,
}

impl Audit {
    pub fn new(path: Option<&str>) -> Result<Audit, String> {
        let file = match path {
            Some(p) => {
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .map_err(|e| format!("cannot open audit log {p}: {e}"))?;
                Some(Mutex::new(f))
            }
            None => None,
        };
        Ok(Audit { file })
    }

    /// Emit an audit event. `fields` must be a JSON object.
    pub fn emit(&self, event: &str, mut fields: serde_json::Value) {
        let obj = fields
            .as_object_mut()
            .expect("audit fields must be an object");
        obj.insert("ts".into(), aauth_core::now_unix().into());
        obj.insert("event".into(), event.into());
        let line = serde_json::Value::Object(std::mem::take(obj)).to_string();
        eprintln!("audit {line}");
        if let Some(file) = &self.file {
            if let Ok(mut f) = file.lock() {
                let _ = writeln!(f, "{line}");
            }
        }
    }
}
