//! aauthcheck — an AAuth conformance client built on `aauth-core`.
//!
//! Enrolls a throwaway agent at a live Agent Provider, then exercises a target
//! server the way a real agent would. Used to review `psd` (Person Server)
//! implementations against the draft.

use aauth_core::{jwk, jwt, now_unix, sig, sigkey};
use ed25519_dalek::SigningKey;

/// Split a URL into (@authority, @path). Handles http:// so a PS under
/// development on localhost can be graded without TLS.
fn url_parts(url: &str) -> (String, String) {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    }
}

/// Sign and send one AAuth request. `body` None => GET.
fn call(
    method: &str,
    url: &str,
    scheme: &str,
    key: &SigningKey,
    body: Option<&serde_json::Value>,
) -> (u16, String, Vec<(String, String)>) {
    let (authority, path) = url_parts(url);
    let no_headers = |_: &str| None;
    let signed = sig::sign_request(
        method,
        &authority,
        &path,
        "",
        &[],
        &no_headers,
        scheme,
        key,
        now_unix(),
    )
    .expect("sign");

    let mut req = ureq::request(method, url)
        .set("signature-input", &signed.signature_input)
        .set("signature", &signed.signature)
        .set("signature-key", &signed.signature_key);
    if body.is_some() {
        req = req.set("content-type", "application/json");
    }
    let resp = match body {
        Some(b) => req.send_string(&b.to_string()),
        None => req.call(),
    };
    let (code, r) = match resp {
        Ok(r) => (r.status(), Some(r)),
        Err(ureq::Error::Status(c, r)) => (c, Some(r)),
        Err(e) => return (0, format!("transport: {e}"), vec![]),
    };
    let r = r.unwrap();
    let hdrs: Vec<(String, String)> = r
        .headers_names()
        .iter()
        .filter_map(|n| r.header(n).map(|v| (n.to_lowercase(), v.to_string())))
        .collect();
    (code, r.into_string().unwrap_or_default(), hdrs)
}

fn get_json(url: &str) -> Result<serde_json::Value, String> {
    ureq::get(url)
        .call()
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())
}

fn check(ok: bool, label: &str, detail: &str) -> bool {
    println!(
        "  [{}] {label}{}",
        if ok { "PASS" } else { "FAIL" },
        if detail.is_empty() {
            String::new()
        } else {
            format!(" — {detail}")
        }
    );
    ok
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let ap = args
        .iter()
        .position(|a| a == "--ap")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "https://sandbox.agentprovider.dev".into());
    let target = args
        .iter()
        .position(|a| a == "--target")
        .and_then(|i| args.get(i + 1))
        .cloned();

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut t = |ok: bool| if ok { pass += 1 } else { fail += 1 };

    // ---------- 1. Enroll a throwaway agent at the AP ----------
    println!("\n== Agent Provider: {ap} ==");
    let durable = jwk::generate_signing_key();
    let durable_jwk = jwk::Jwk::from_verifying_key(&durable.verifying_key());
    let hwk = sigkey::serialize_hwk(&durable_jwk);

    let (code, body, _) = call(
        "POST",
        &format!("{ap}/enroll"),
        &hwk,
        &durable,
        Some(&serde_json::json!({})),
    );
    let enrolled: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let agent_id = enrolled["agent"].as_str().unwrap_or("").to_string();
    t(check(
        code == 201 || code == 200,
        "enroll",
        &format!("HTTP {code} {agent_id}"),
    ));

    let (code, body, _) = call(
        "POST",
        &format!("{ap}/agent-token"),
        &hwk,
        &durable,
        Some(&serde_json::json!({})),
    );
    let tok: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let agent_token = tok["agent_token"].as_str().unwrap_or("").to_string();
    t(check(
        code == 200 && !agent_token.is_empty(),
        "agent-token",
        &format!("HTTP {code}"),
    ));
    if agent_token.is_empty() {
        println!("\ncannot continue without an agent token");
        std::process::exit(1);
    }

    // The agent token's cnf.jwk must be our key, and alg must be fully specified.
    let decoded = jwt::decode(&agent_token).expect("decode agent token");
    t(check(
        decoded.header.alg == "Ed25519",
        "agent token alg is fully-specified",
        &decoded.header.alg,
    ));
    t(check(
        decoded.payload["dwk"] == "aauth-agent.json",
        "dwk",
        "",
    ));

    // ---------- 1b. Interop: does an independent resource accept our token? ----------
    println!("\n== Interop: whoami.aauth.dev (third-party resource) ==");
    {
        let scheme = sigkey::serialize_jwt(&agent_token);
        let (code, body, hdrs) = call("GET", "https://whoami.aauth.dev", &scheme, &durable, None);
        let sigerr = hdrs
            .iter()
            .find(|(n, _)| n == "signature-error")
            .map(|(_, v)| v.clone());
        t(check(
            code == 200,
            "third-party resource accepts our agent token",
            &format!(
                "HTTP {code}{}",
                sigerr.map(|e| format!("  [{e}]")).unwrap_or_default()
            ),
        ));
        if code == 200 {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let echoed = v.to_string();
            t(check(
                echoed.contains("aauth:"),
                "it echoed our agent identity",
                &echoed.chars().take(110).collect::<String>(),
            ));
        } else {
            println!(
                "       body: {}",
                body.chars().take(200).collect::<String>()
            );
        }
    }

    // ---------- 2. Target server under test ----------
    let Some(target) = target else {
        println!("\n(no --target given; AP checks only)\n{pass} passed, {fail} failed");
        return;
    };
    println!("\n== Target: {target} ==");

    // 2a. Metadata
    match get_json(&format!("{target}/.well-known/aauth-person.json")) {
        Ok(md) => {
            t(check(
                md["issuer"] == serde_json::json!(target.clone()),
                "metadata issuer matches the fetch URL",
                md["issuer"].as_str().unwrap_or("<missing>"),
            ));
            t(check(md["jwks_uri"].is_string(), "jwks_uri present", ""));
            t(check(
                md["person_token_endpoint"].is_string(),
                "person_token_endpoint present (REQUIRED)",
                "",
            ));
            t(check(
                md["auth_token_endpoint"].is_string(),
                "auth_token_endpoint present (REQUIRED, renamed in -11)",
                "",
            ));

            // 2b. JWKS: every key needs a fully-specified alg
            if let Some(j) = md["jwks_uri"].as_str() {
                match get_json(j) {
                    Ok(ks) => {
                        let keys = ks["keys"].as_array().cloned().unwrap_or_default();
                        let all_alg = !keys.is_empty() && keys.iter().all(|k| k["alg"].is_string());
                        let no_poly = keys.iter().all(|k| k["alg"] != "EdDSA");
                        t(check(
                            all_alg,
                            "every JWKS key carries alg",
                            &format!("{} keys", keys.len()),
                        ));
                        t(check(no_poly, "no polymorphic EdDSA in JWKS", ""));
                    }
                    Err(e) => t(check(false, "fetch jwks_uri", &e)),
                }
            }

            // 2c. Unsigned request must be refused
            let ep = md["person_token_endpoint"]
                .as_str()
                .unwrap_or("")
                .to_string();
            if !ep.is_empty() {
                let unsigned = ureq::post(&ep).send_string("{}");
                let code = match unsigned {
                    Ok(r) => r.status(),
                    Err(ureq::Error::Status(c, _)) => c,
                    Err(_) => 0,
                };
                t(check(
                    code == 401,
                    "unsigned person-token request refused",
                    &format!("HTTP {code}"),
                ));

                // 2d. Signed request with a real agent token
                let scheme = sigkey::serialize_jwt(&agent_token);
                let (code, body, hdrs) = call(
                    "POST",
                    &ep,
                    &scheme,
                    &durable,
                    Some(&serde_json::json!({ "resource": "https://whoami.aauth.dev" })),
                );
                let signed_ok = code == 200 || code == 202;
                t(check(
                    signed_ok,
                    "signed person-token request accepted",
                    &format!("HTTP {code}"),
                ));

                if code == 200 {
                    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                    if let Some(pt) = v["person_token"].as_str() {
                        match jwt::decode(pt) {
                            Ok(d) => {
                                t(check(
                                    d.header.typ.as_deref() == Some("aa-person+jwt"),
                                    "person token typ",
                                    &format!("{:?}", d.header.typ),
                                ));
                                t(check(
                                    d.header.alg == "Ed25519",
                                    "person token alg",
                                    &d.header.alg,
                                ));
                                t(check(d.payload["dwk"] == "aauth-person.json", "dwk", ""));
                                t(check(
                                    d.payload["aud"] == "https://whoami.aauth.dev",
                                    "aud echoes resource",
                                    "",
                                ));
                                for c in ["iss", "sub", "jti", "iat", "exp"] {
                                    t(check(!d.payload[c].is_null(), &format!("claim {c}"), ""));
                                }
                                t(check(
                                    d.payload["cnf"]["jwk"].is_object(),
                                    "cnf.jwk present",
                                    "",
                                ));
                                let life = d.payload["exp"].as_i64().unwrap_or(0)
                                    - d.payload["iat"].as_i64().unwrap_or(0);
                                t(check(
                                    life > 0 && life <= 3600,
                                    "lifetime <= 1 hour",
                                    &format!("{life}s"),
                                ));
                            }
                            Err(e) => t(check(false, "person token decodes", &format!("{e}"))),
                        }
                    } else {
                        t(check(false, "response carries person_token", &body));
                    }
                } else if code == 202 {
                    let has_req = hdrs.iter().any(|(n, _)| n == "aauth-requirement");
                    t(check(has_req, "202 carries AAuth-Requirement", ""));
                }
            }
        }
        Err(e) => t(check(false, "fetch /.well-known/aauth-person.json", &e)),
    }

    println!("\n{pass} passed, {fail} failed");
    if fail > 0 {
        std::process::exit(1);
    }
}
