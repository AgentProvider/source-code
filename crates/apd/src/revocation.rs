//! Notifying a Person Server that an agent's tokens are revoked.
//!
//! The protocol spec (Token Revocation): "On learning that an agent can no
//! longer be trusted, the agent provider calls the PS's revocation endpoint
//! with the agent token's `iss` and `jti`. The PS MUST deny subsequent requests
//! presenting that agent token, and SHOULD revoke the auth tokens it issued or
//! provided for that agent."
//!
//! Two properties of that rule shape this module:
//!
//! - **Revocation names a token, not an agent.** Recipients key revocation
//!   state by `(iss, jti)`, so the AP must name every outstanding token. Each
//!   issued `jti` is therefore recorded under its own key with a TTL equal to
//!   the token's remaining life: the index self-prunes exactly when revoking an
//!   entry would stop meaning anything, and needs no reaper.
//! - **It is best effort.** Local revocation — refusing to issue again — is the
//!   authoritative lever and always succeeds. A PS that is unreachable, has no
//!   `revocation_endpoint`, or rejects us MUST NOT fail the admin operation.
//!   The spec says as much: access that no revocation reaches is bounded by
//!   token lifetime alone.

use std::sync::Arc;
use std::time::Duration;

use aauth_core::{sig, sigkey};

use crate::app::App;
use crate::httpc;

/// Key for one outstanding agent-token `jti`.
fn jti_key(local: &str, jti: &str) -> String {
    format!("agent_jti:{local}:{jti}")
}

/// Prefix covering every outstanding `jti` for one agent.
fn jti_prefix(local: &str) -> String {
    format!("agent_jti:{local}:")
}

/// Record a freshly issued token's `jti` so a later revocation can name it.
/// The TTL matches the token, so nothing accumulates. Never fails issuance.
pub async fn record_issued_jti(app: &App, local: &str, jti: &str, exp: u64) {
    if !app.cfg.revocation.notify_ps {
        return; // Nothing will read the index; do not pay for it.
    }
    let ttl = exp.saturating_sub(aauth_core::now_unix());
    if ttl == 0 {
        return;
    }
    let _ = app
        .store
        .put(&jti_key(local, jti), b"1", Some(Duration::from_secs(ttl)))
        .await;
}

/// Outcome of a notification attempt. Recorded in the audit log and returned in
/// the admin response. None of these are errors the operator must act on — the
/// local revocation has already taken effect.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NotifyOutcome {
    /// `sent` | `disabled` | `no_ps` | `no_endpoint` | `failed`
    pub status: &'static str,
    /// How many outstanding tokens we named.
    pub tokens: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl NotifyOutcome {
    fn plain(status: &'static str) -> Self {
        NotifyOutcome {
            status,
            tokens: 0,
            ps: None,
            detail: None,
        }
    }
}

/// Tell the agent's PS that every outstanding token for `local` is revoked.
/// Best effort by construction: every path returns an outcome, never an error.
pub async fn notify_ps(app: &Arc<App>, local: &str, ps: Option<&str>) -> NotifyOutcome {
    if !app.cfg.revocation.notify_ps {
        return NotifyOutcome::plain("disabled");
    }
    let Some(ps) = ps else {
        return NotifyOutcome::plain("no_ps");
    };

    // Collect and clear the index: these tokens are being revoked, so a repeat
    // revoke should not re-send, and there is nothing to retry against later.
    let prefix = jti_prefix(local);
    let entries = app.store.scan_prefix(&prefix).await.unwrap_or_default();
    let jtis: Vec<String> = entries
        .iter()
        .filter_map(|(k, _)| k.strip_prefix(&prefix).map(str::to_string))
        .collect();
    for (k, _) in &entries {
        let _ = app.store.delete(k).await;
    }

    if jtis.is_empty() {
        return NotifyOutcome {
            status: "sent",
            tokens: 0,
            ps: Some(ps.to_string()),
            detail: Some("no outstanding tokens".into()),
        };
    }

    let endpoint = match discover_revocation_endpoint(app, ps).await {
        Ok(Some(url)) => url,
        Ok(None) => {
            return NotifyOutcome {
                status: "no_endpoint",
                tokens: jtis.len(),
                ps: Some(ps.to_string()),
                detail: Some("PS metadata publishes no revocation_endpoint".into()),
            }
        }
        Err(e) => {
            return NotifyOutcome {
                status: "failed",
                tokens: jtis.len(),
                ps: Some(ps.to_string()),
                detail: Some(e),
            }
        }
    };

    let mut sent = 0usize;
    let mut last_err = None;
    for jti in &jtis {
        match post_revocation(app, &endpoint, jti).await {
            // The spec defines 404 as a normal answer: the PS does not know the
            // pair, so there is nothing left to revoke.
            Ok(code) if (200..300).contains(&code) || code == 404 => sent += 1,
            Ok(code) => last_err = Some(format!("HTTP {code} from the PS")),
            Err(e) => last_err = Some(e),
        }
    }

    if sent == jtis.len() {
        NotifyOutcome {
            status: "sent",
            tokens: sent,
            ps: Some(ps.to_string()),
            detail: None,
        }
    } else {
        NotifyOutcome {
            status: "failed",
            tokens: jtis.len(),
            ps: Some(ps.to_string()),
            detail: last_err,
        }
    }
}

/// Read `revocation_endpoint` from `{ps}/.well-known/aauth-person.json`.
/// The document's `issuer` MUST equal the PS URL — the same host-poisoning
/// defence applied when verifying foreign tokens.
async fn discover_revocation_endpoint(app: &Arc<App>, ps: &str) -> Result<Option<String>, String> {
    let url = format!("{ps}/.well-known/aauth-person.json");
    let doc = httpc::get_json(&url, &app.egress).await?;
    let issuer = doc
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if issuer != ps {
        return Err(format!("PS metadata issuer '{issuer}' does not match {ps}"));
    }
    Ok(doc
        .get("revocation_endpoint")
        .and_then(|v| v.as_str())
        .map(str::to_string))
}

/// One signed `POST {revocation_endpoint}` with `{"iss", "jti"}`.
///
/// The AP signs as *itself* with the `jwks_uri` scheme: the PS resolves
/// `{id}/.well-known/{dwk}` → `jwks_uri` → `kid`, which lets it confirm the
/// caller is the `iss` of the token being revoked — exactly the authorization
/// rule the spec states for revocation recipients.
async fn post_revocation(app: &Arc<App>, endpoint: &str, jti: &str) -> Result<u16, String> {
    let body = serde_json::json!({ "iss": app.cfg.issuer, "jti": jti })
        .to_string()
        .into_bytes();
    let (authority, path) = httpc::signing_parts(endpoint)?;
    let sig_key =
        sigkey::serialize_jwks_uri(&app.cfg.issuer, "aauth-agent.json", &app.keys.active_kid);
    let no_headers = |_: &str| None;
    let signed = sig::sign_request(
        "POST",
        &authority,
        &path,
        "",
        &[],
        &no_headers,
        &sig_key,
        &app.keys.active_key,
        aauth_core::now_unix(),
    )
    .map_err(|e| format!("signing revocation request: {e}"))?;

    let headers = vec![
        ("signature-input".to_string(), signed.signature_input),
        ("signature".to_string(), signed.signature),
        ("signature-key".to_string(), signed.signature_key),
    ];
    httpc::post_json(endpoint, &body, &headers, &app.egress).await
}
