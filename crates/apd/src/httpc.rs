//! Minimal outbound HTTPS GET client with the egress admission rules the
//! Signature-Key draft requires of JWKS/metadata fetchers
//! (see `research/03-http-signatures.md` §9):
//!
//! - HTTPS only (plain HTTP allowed only in insecure_dev_mode)
//! - redirects are never followed
//! - private / loopback / link-local destinations rejected (unless dev mode)
//! - the resolved IP is pinned for the connection (DNS-rebinding defense)
//! - response size cap and timeout

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub struct EgressPolicy {
    pub allow_private: bool,
    pub allow_http: bool,
    pub max_response_bytes: usize,
    pub timeout: Duration,
}

impl EgressPolicy {
    pub fn from_config(insecure_dev: bool) -> EgressPolicy {
        EgressPolicy {
            allow_private: insecure_dev,
            allow_http: insecure_dev,
            max_response_bytes: 64 * 1024,
            timeout: Duration::from_secs(10),
        }
    }
}

fn ip_is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
                || (o[0] == 198 && (o[1] & 0xFE) == 18) // 198.18.0.0/15
                || o[0] >= 240) // 240.0.0.0/4
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xFE00) == 0xFC00 // fc00::/7 unique local
                || (seg[0] & 0xFFC0) == 0xFE80 // fe80::/10 link local
                || (seg[0] == 0x2001 && seg[1] == 0x0DB8)) // documentation
        }
    }
}

struct ParsedUrl {
    https: bool,
    host: String,
    port: u16,
    path_and_query: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("unsupported URL scheme".into());
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if hostport.contains('@') {
        return Err("userinfo in URL rejected".into());
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse::<u16>().map_err(|e| e.to_string())?)
        }
        _ => (hostport.to_string(), if https { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err("empty host".into());
    }
    Ok(ParsedUrl {
        https,
        host,
        port,
        path_and_query: path.to_string(),
    })
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// GET a URL and return the body bytes. Enforces the egress policy.
pub async fn get(url: &str, policy: &EgressPolicy) -> Result<Bytes, String> {
    tokio::time::timeout(policy.timeout, get_inner(url, policy))
        .await
        .map_err(|_| format!("timeout fetching {url}"))?
}

async fn get_inner(url: &str, policy: &EgressPolicy) -> Result<Bytes, String> {
    let parsed = parse_url(url)?;
    if !parsed.https && !policy.allow_http {
        return Err("plain http egress not allowed".into());
    }

    // Resolve and pin one admitted address.
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((parsed.host.as_str(), parsed.port))
        .await
        .map_err(|e| format!("dns error for {}: {e}", parsed.host))?
        .collect();
    let addr = addrs
        .iter()
        .find(|a| policy.allow_private || ip_is_public(&a.ip()))
        .ok_or_else(|| format!("no admissible address for {}", parsed.host))?;
    if !policy.allow_private && addrs.iter().any(|a| !ip_is_public(&a.ip())) {
        // Mixed public/private resolution smells like rebinding — refuse.
        return Err(format!(
            "host {} resolves to private addresses",
            parsed.host
        ));
    }

    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect {addr}: {e}"))?;
    stream.set_nodelay(true).ok();

    let response = if parsed.https {
        let server_name = rustls::pki_types::ServerName::try_from(parsed.host.clone())
            .map_err(|_| "invalid TLS server name".to_string())?;
        let tls = TlsConnector::from(tls_config())
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("tls handshake with {}: {e}", parsed.host))?;
        send_get(TokioIo::new(tls), &parsed).await?
    } else {
        send_get(TokioIo::new(stream), &parsed).await?
    };

    let (parts, body) = response.into_parts();
    if parts.status.is_redirection() {
        return Err(format!("redirect from {url} refused"));
    }
    if !parts.status.is_success() {
        return Err(format!("HTTP {} from {url}", parts.status));
    }
    let collected = http_body_util::Limited::new(body, policy.max_response_bytes)
        .collect()
        .await
        .map_err(|e| format!("body read from {url}: {e}"))?;
    Ok(collected.to_bytes())
}

async fn send_get<I>(
    io: I,
    parsed: &ParsedUrl,
) -> Result<hyper::Response<hyper::body::Incoming>, String>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("http handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let authority = if (parsed.https && parsed.port != 443) || (!parsed.https && parsed.port != 80)
    {
        format!("{}:{}", parsed.host, parsed.port)
    } else {
        parsed.host.clone()
    };
    let req = hyper::Request::builder()
        .method("GET")
        .uri(&parsed.path_and_query)
        .header("host", authority)
        .header("accept", "application/json")
        .header("user-agent", concat!("apd/", env!("CARGO_PKG_VERSION")))
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|e| e.to_string())?;
    sender.send_request(req).await.map_err(|e| e.to_string())
}

/// GET a URL and parse the body as JSON.
pub async fn get_json(url: &str, policy: &EgressPolicy) -> Result<serde_json::Value, String> {
    let body = get(url, policy).await?;
    serde_json::from_slice(&body).map_err(|e| format!("invalid JSON from {url}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        let u = parse_url("https://a.example/.well-known/x.json").unwrap();
        assert!(u.https);
        assert_eq!(u.host, "a.example");
        assert_eq!(u.port, 443);
        assert_eq!(u.path_and_query, "/.well-known/x.json");
        let u = parse_url("http://127.0.0.1:8081").unwrap();
        assert_eq!(u.port, 8081);
        assert_eq!(u.path_and_query, "/");
        assert!(parse_url("ftp://x").is_err());
        assert!(parse_url("https://user@x.example/").is_err());
    }

    #[test]
    fn ip_admission() {
        let public: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(ip_is_public(&public));
        for bad in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
        ] {
            let ip: IpAddr = bad.parse().unwrap();
            assert!(!ip_is_public(&ip), "{bad} must be rejected");
        }
        let v6_public: IpAddr = "2606:2800:220:1::1".parse().unwrap();
        assert!(ip_is_public(&v6_public));
    }
}
