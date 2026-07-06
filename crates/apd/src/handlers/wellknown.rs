//! Well-known metadata + JWKS. These are the hot verification-path endpoints;
//! they serve pre-serialized bytes with cache headers.

use std::sync::Arc;

use hyper::body::Bytes;

use crate::app::App;
use crate::problem::{json_cacheable, Resp};

/// `GET /.well-known/aauth-agent.json`
pub fn agent_metadata(app: &Arc<App>) -> Resp {
    json_cacheable(Bytes::from(app.agent_metadata_bytes.clone()), 300)
}

/// `GET /.well-known/jwks.json`
pub fn jwks(app: &Arc<App>) -> Resp {
    json_cacheable(Bytes::from(app.jwks_bytes.clone()), 300)
}
