//! HTTP responses: RFC 9457 problem+json errors with the AAuth `error`
//! member, `Signature-Error` headers, and JSON success responses.

use aauth_core::sig::{SigError, SigErrorCode};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Response, StatusCode};

pub type Body = Full<Bytes>;
pub type Resp = Response<Body>;

/// An API error that renders as problem+json (plus optional extra headers).
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub error: String,
    pub detail: String,
    pub headers: Vec<(&'static str, String)>,
}

impl ApiError {
    pub fn new(status: StatusCode, error: &str, detail: impl Into<String>) -> ApiError {
        ApiError {
            status,
            error: error.to_string(),
            detail: detail.into(),
            headers: Vec::new(),
        }
    }

    pub fn bad_request(error: &str, detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, error, detail)
    }
    pub fn forbidden(error: &str, detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::FORBIDDEN, error, detail)
    }
    pub fn not_found(error: &str, detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, error, detail)
    }
    pub fn server_error(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", detail)
    }

    /// A signature verification failure: 401 + `Signature-Error` header
    /// (the header is authoritative; the body mirrors it for humans).
    pub fn from_sig_error(err: SigError) -> ApiError {
        let mut header = format!("error={}", err.code.as_str());
        match err.code {
            SigErrorCode::UnsupportedAlgorithm => {
                header.push_str(", supported_algorithms=(\"ed25519\")");
            }
            SigErrorCode::InvalidInput => {
                if let Some(required) = &err.required_input {
                    let inner: Vec<String> = required
                        .iter()
                        .map(|c| aauth_core::sfv::serialize_string(c))
                        .collect();
                    header.push_str(&format!(", required_input=({})", inner.join(" ")));
                }
            }
            _ => {}
        }
        ApiError {
            status: StatusCode::UNAUTHORIZED,
            error: err.code.as_str().to_string(),
            detail: err.detail,
            headers: vec![("signature-error", header)],
        }
    }

    pub fn into_response(self) -> Resp {
        let body = serde_json::json!({
            "type": format!("urn:ietf:params:sig-error:{}", self.error),
            "error": self.error,
            "detail": self.detail,
            "status": self.status.as_u16(),
        });
        let mut builder = Response::builder()
            .status(self.status)
            .header("content-type", "application/problem+json")
            .header("cache-control", "no-store");
        for (name, value) in &self.headers {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                builder = builder.header(n, v);
            }
        }
        builder
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }
}

impl From<crate::storage::StorageError> for ApiError {
    fn from(e: crate::storage::StorageError) -> ApiError {
        ApiError::server_error(e.to_string())
    }
}

pub fn json_response(status: StatusCode, value: &serde_json::Value) -> Resp {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(value.to_string())))
        .unwrap()
}

pub fn json_ok(value: &serde_json::Value) -> Resp {
    json_response(StatusCode::OK, value)
}

/// Cacheable JSON (well-known documents).
pub fn json_cacheable(body: Bytes, max_age_secs: u32) -> Resp {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", format!("public, max-age={max_age_secs}"))
        .body(Full::new(body))
        .unwrap()
}

pub fn empty_status(status: StatusCode) -> Resp {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}
