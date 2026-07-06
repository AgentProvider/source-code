//! AAuth identifiers: server identifiers (HTTPS URLs) and agent identifiers
//! (`aauth:local@domain`), with the exact validation rules from the protocol
//! spec (see `research/01-aauth-protocol-overview.md` §5.6).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentError {
    InvalidServerIdentifier,
    InvalidAgentIdentifier,
}

impl std::fmt::Display for IdentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentError::InvalidServerIdentifier => write!(f, "invalid server identifier"),
            IdentError::InvalidAgentIdentifier => write!(f, "invalid agent identifier"),
        }
    }
}
impl std::error::Error for IdentError {}

/// Validate a DNS host: lowercase LDH labels separated by dots.
fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

/// Validate an AAuth server identifier: `https` scheme, host only (no port,
/// path, query, fragment, userinfo, or trailing slash), lowercase.
///
/// With `insecure_dev`, `http://` and an explicit port are additionally
/// accepted (and `localhost`-style single-label hosts), so a development
/// deployment can run without TLS. Never enable outside development.
pub fn validate_server_identifier(s: &str, insecure_dev: bool) -> Result<(), IdentError> {
    let rest = if let Some(r) = s.strip_prefix("https://") {
        r
    } else if insecure_dev {
        s.strip_prefix("http://")
            .ok_or(IdentError::InvalidServerIdentifier)?
    } else {
        return Err(IdentError::InvalidServerIdentifier);
    };
    if rest.contains(['/', '?', '#', '@']) {
        return Err(IdentError::InvalidServerIdentifier);
    }
    let host = if insecure_dev {
        // allow :port in dev
        match rest.split_once(':') {
            Some((h, port)) => {
                if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(IdentError::InvalidServerIdentifier);
                }
                h
            }
            None => rest,
        }
    } else {
        if rest.contains(':') {
            return Err(IdentError::InvalidServerIdentifier);
        }
        rest
    };
    if valid_host(host) {
        Ok(())
    } else {
        Err(IdentError::InvalidServerIdentifier)
    }
}

/// Extract the host (without port) from a server identifier / origin URL.
pub fn host_of(server_id: &str) -> Option<String> {
    let rest = server_id
        .strip_prefix("https://")
        .or_else(|| server_id.strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.split(':').next()?;
    Some(host.to_string())
}

/// An agent identifier `aauth:local@domain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentId {
    pub local: String,
    pub domain: String,
}

/// Is `local` valid as a *top-level* local part (no `+`)?
pub fn valid_local_toplevel(local: &str) -> bool {
    valid_local_chars(local) && !local.contains('+')
}

/// Extract the local part of an already-validated `aauth:local@domain`
/// identifier without re-validating. Returns `""` if malformed.
pub fn local_part(agent_id: &str) -> &str {
    agent_id
        .strip_prefix("aauth:")
        .and_then(|r| r.rsplit_once('@'))
        .map(|(l, _)| l)
        .unwrap_or("")
}

fn valid_local_chars(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= 255
        && local.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || b == b'-'
                || b == b'_'
                || b == b'+'
                || b == b'.'
        })
}

/// Is `disc` valid as a sub-agent discriminator (non-empty, no `+`)?
pub fn valid_discriminator(disc: &str) -> bool {
    !disc.is_empty() && valid_local_chars(disc) && !disc.contains('+')
}

impl AgentId {
    pub fn new(local: &str, domain: &str) -> Result<AgentId, IdentError> {
        if !valid_local_chars(local) || !valid_host(domain) {
            return Err(IdentError::InvalidAgentIdentifier);
        }
        // '+' rules: at most one, neither first nor last (parent and
        // discriminator both non-empty)
        let plus_count = local.bytes().filter(|&b| b == b'+').count();
        if plus_count > 1 {
            return Err(IdentError::InvalidAgentIdentifier);
        }
        if plus_count == 1 {
            let (parent, disc) = local.split_once('+').unwrap();
            if parent.is_empty() || disc.is_empty() {
                return Err(IdentError::InvalidAgentIdentifier);
            }
        }
        Ok(AgentId {
            local: local.to_string(),
            domain: domain.to_string(),
        })
    }

    /// Parse `aauth:local@domain`. Case-sensitive; exact-match semantics.
    pub fn parse(s: &str) -> Result<AgentId, IdentError> {
        let rest = s
            .strip_prefix("aauth:")
            .ok_or(IdentError::InvalidAgentIdentifier)?;
        let (local, domain) = rest
            .rsplit_once('@')
            .ok_or(IdentError::InvalidAgentIdentifier)?;
        AgentId::new(local, domain)
    }

    /// The sub-agent naming convention: parent's local part visible before `+`.
    pub fn is_subagent_named(&self) -> bool {
        self.local.contains('+')
    }

    /// Construct the sub-agent id `parent+disc@domain`.
    pub fn subagent(&self, discriminator: &str) -> Result<AgentId, IdentError> {
        if self.is_subagent_named() || !valid_discriminator(discriminator) {
            return Err(IdentError::InvalidAgentIdentifier);
        }
        AgentId::new(&format!("{}+{}", self.local, discriminator), &self.domain)
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "aauth:{}@{}", self.local, self.domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_identifiers() {
        assert!(validate_server_identifier("https://agent.example", false).is_ok());
        assert!(validate_server_identifier("https://xn--nxasmq6b.example", false).is_ok());
        assert!(validate_server_identifier("http://agent.example", false).is_err());
        assert!(validate_server_identifier("https://Agent.Example", false).is_err());
        assert!(validate_server_identifier("https://agent.example:8443", false).is_err());
        assert!(validate_server_identifier("https://agent.example/v1", false).is_err());
        assert!(validate_server_identifier("https://agent.example/", false).is_err());
        assert!(validate_server_identifier("https://user@agent.example", false).is_err());
        // dev mode
        assert!(validate_server_identifier("http://localhost:8420", true).is_ok());
        assert!(validate_server_identifier("http://localhost:x", true).is_err());
    }

    #[test]
    fn agent_ids() {
        let ok = [
            "aauth:assistant-v2@agent.example",
            "aauth:planner.7f3c@vendor.example",
            "aauth:planner.7f3c+search1@vendor.example",
        ];
        for s in ok {
            let id = AgentId::parse(s).unwrap();
            assert_eq!(id.to_string(), s);
        }
        let bad = [
            "aauth:My Agent@agent.example",
            "aauth:@agent.example",
            "aauth:agent@http://agent.example",
            "aauth:a+b+c@agent.example",
            "aauth:+x@agent.example",
            "aauth:x+@agent.example",
            "acct:x@agent.example",
        ];
        for s in bad {
            assert!(AgentId::parse(s).is_err(), "{s} should be invalid");
        }
    }

    #[test]
    fn subagent_construction() {
        let parent = AgentId::parse("aauth:planner.7f3c@vendor.example").unwrap();
        let sub = parent.subagent("search1").unwrap();
        assert_eq!(sub.to_string(), "aauth:planner.7f3c+search1@vendor.example");
        assert!(sub.is_subagent_named());
        // no sub-sub-agents through naming
        assert!(sub.subagent("x").is_err());
        assert!(parent.subagent("").is_err());
        assert!(parent.subagent("a+b").is_err());
    }
}
