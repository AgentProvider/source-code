//! aauthcheck — an AAuth conformance client built on `aauth-core`.
//!
//! Enrolls a throwaway agent at a live Agent Provider, then exercises a target
//! server the way a real agent would.
//!
//! The point is that nothing here is mocked: the agent identity is real, the
//! signatures are real, and a failure means an interoperability problem rather
//! than a disagreement between two of our own test doubles.

use aauth_core::{jwk, jwt, now_unix, sig, sigkey};
use ed25519_dalek::SigningKey;

/// Split a URL into (@authority, @path, query). Handles http:// so a PS under
/// development on localhost can be graded without TLS.
///
/// The query must come off the path. RFC 9421 defines `@path` as the absolute
/// path with no query string — signing `/?scope=openid` as `@path` produces a
/// signature the resource cannot reproduce, and the failure looks like a key
/// problem rather than a canonicalization one.
fn url_parts(url: &str) -> (String, String, String) {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let (authority, rest) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), &rest[i..]),
        None => (rest.to_string(), "/"),
    };
    match rest.find('?') {
        Some(i) => (authority, rest[..i].to_string(), rest[i..].to_string()),
        None => (authority, rest.to_string(), String::new()),
    }
}

/// Read one response header.
fn hdr<'a>(hdrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    hdrs.iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// Sign and send one AAuth request.
///
/// A body means a `Content-Digest` and the two extra covered components the
/// profile requires: "A request carrying a body to a PS or AS endpoint MUST
/// additionally sign `content-digest` and `content-type`." Omitting them is a
/// conformance bug in the *client*, and a correct server answers `401
/// invalid_input` naming what it required.
fn call(
    method: &str,
    url: &str,
    scheme: &str,
    key: &SigningKey,
    body: Option<&serde_json::Value>,
    prefer_wait: Option<u64>,
) -> (u16, String, Vec<(String, String)>) {
    use sha2::{Digest, Sha256};

    let (authority, path, query) = url_parts(url);
    let body_bytes = body.map(|b| b.to_string().into_bytes());

    // RFC 9530: sha-256=:<standard base64>:
    let digest = body_bytes.as_ref().map(|b| {
        format!(
            "sha-256=:{}:",
            aauth_core::b64::encode_std(&Sha256::digest(b))
        )
    });

    let extra: Vec<&str> = if digest.is_some() {
        vec!["content-type", "content-digest"]
    } else {
        vec![]
    };
    let digest_for_lookup = digest.clone();
    let lookup = move |name: &str| -> Option<String> {
        match name {
            "content-type" => Some("application/json".to_string()),
            "content-digest" => digest_for_lookup.clone(),
            _ => None,
        }
    };

    let signed = sig::sign_request(
        method,
        &authority,
        &path,
        &query,
        &extra,
        &lookup,
        scheme,
        key,
        now_unix(),
    )
    .expect("sign");

    let mut req = ureq::request(method, url)
        .set("signature-input", &signed.signature_input)
        .set("signature", &signed.signature)
        .set("signature-key", &signed.signature_key);
    if let Some(d) = &digest {
        req = req
            .set("content-type", "application/json")
            .set("content-digest", d);
    }
    if let Some(w) = prefer_wait {
        req = req.set("prefer", &format!("wait={w}"));
    }

    let resp = match &body_bytes {
        Some(b) => req.send_bytes(b),
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

/// A 401 always carries a machine-readable reason; surface it or debugging is
/// guesswork.
fn explain(code: u16, hdrs: &[(String, String)]) -> String {
    if code != 401 {
        return String::new();
    }
    hdrs.iter()
        .find(|(n, _)| n == "signature-error")
        .map(|(_, v)| format!("  [{v}]"))
        .unwrap_or_default()
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

/// The three-party flow against a live resource, reimplemented from a written
/// description rather than shared code — so that agreement between the two
/// clients is evidence about the protocol rather than about one implementation.
///
/// Legs 1 and 3–5 are automatic. Leg 2 needs a person to approve consent at the
/// Person Server, which is the point of the protocol and cannot be automated
/// away: the run prints the code and waits.
fn three_party(
    resource: &str,
    ps: &str,
    agent_token: &str,
    key: &SigningKey,
    interactive: bool,
    t: &mut impl FnMut(bool),
) {
    let probe = format!("{resource}/?scope=openid");
    println!("\n== Three-party: {resource} via {ps} ==");

    // --- Leg 1: the resource asks for a person token -----------------------
    // Only reachable with a `ps`-bearing agent token. Without one the resource
    // stays in agent-token mode, which is why probing it unauthenticated says
    // nothing about what it supports.
    let scheme = sigkey::serialize_jwt(agent_token);
    let (code, body, hdrs) = call("GET", &probe, &scheme, key, None, None);
    let req_hdr = hdr(&hdrs, "aauth-requirement").unwrap_or_default();
    t(check(
        code == 401 && req_hdr.contains("person-token"),
        "leg 1: resource challenges for a person token",
        &format!("HTTP {code} {req_hdr}"),
    ));
    t(check(
        body.contains("person_token_required"),
        "leg 1: body names the requirement",
        body.trim(),
    ));

    if !interactive {
        println!(
            "\n  leg 2 needs a person to approve consent at {ps}.\n  \
             Re-run with --interactive to continue past this point."
        );
        return;
    }

    // --- Leg 2: ask the Person Server for a person token -------------------
    let (code, body, hdrs) = call(
        "POST",
        &format!("{ps}/person"),
        &scheme,
        key,
        Some(&serde_json::json!({ "resource": resource })),
        None,
    );
    let location = hdr(&hdrs, "location").unwrap_or_default().to_string();
    let requirement = hdr(&hdrs, "aauth-requirement")
        .unwrap_or_default()
        .to_string();
    t(check(
        code == 202 && !location.is_empty(),
        "leg 2: person token request accepted",
        &format!("HTTP {code} {location}"),
    ));
    if location.is_empty() {
        println!(
            "       body: {}",
            body.chars().take(200).collect::<String>()
        );
        return;
    }
    println!("\n  >>> APPROVE THIS: {requirement}\n");

    // Poll. A 5xx or a transport error is the proxy timing out the long poll,
    // never an answer — treating it as one is how a run loses a token that was
    // in fact issued.
    let mut person_token = String::new();
    for _ in 0..40 {
        let (code, body, _) = call("GET", &location, &scheme, key, None, Some(20));
        if code == 200 {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            person_token = v["person_token"].as_str().unwrap_or("").to_string();
            break;
        }
        if code == 410 {
            println!("       pending request is gone (410)");
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    t(check(
        !person_token.is_empty(),
        "leg 2: person token issued",
        "",
    ));
    if person_token.is_empty() {
        return;
    }
    let pt = jwt::decode(&person_token).expect("decode person token");
    let directed_sub = pt.payload["sub"].as_str().unwrap_or("").to_string();
    t(check(
        pt.header.typ.as_deref() == Some("aa-person+jwt")
            && pt.payload["iss"].as_str() == Some(ps)
            && pt.payload["aud"].as_str() == Some(resource),
        "leg 2: person token is well-formed",
        &format!("aud={}", pt.payload["aud"]),
    ));

    // --- Leg 3: present the person token in place of the agent token -------
    let pscheme = sigkey::serialize_jwt(&person_token);
    let (code, body, hdrs) = call("GET", &probe, &pscheme, key, None, None);
    let requirement = hdr(&hdrs, "aauth-requirement")
        .unwrap_or_default()
        .to_string();
    t(check(
        code == 401 && requirement.contains("auth-token"),
        "leg 3: resource accepted the person token and asks for an auth token",
        &format!("HTTP {code}"),
    ));
    let resource_token = requirement
        .split("resource-token=")
        .nth(1)
        .map(|s| s.trim_matches('"').trim_end_matches(';').to_string())
        .unwrap_or_default();
    t(check(
        !resource_token.is_empty(),
        "leg 3: challenge carries a resource token",
        "",
    ));
    if resource_token.is_empty() {
        println!(
            "       body: {}",
            body.chars().take(200).collect::<String>()
        );
        return;
    }
    let rt = jwt::decode(&resource_token).expect("decode resource token");
    t(check(
        rt.payload["sub"].as_str() == Some(directed_sub.as_str()),
        "leg 3: directed sub is carried through unchanged",
        "",
    ));
    // The claim -11 renamed to `presented_jti`. A resource still emitting the
    // old name is the interop case a Person Server has to absorb.
    let legacy = rt.payload.get("person_token_jti").is_some();
    let current = rt.payload.get("presented_jti").is_some();
    println!(
        "       resource token jti claim: {}",
        if current {
            "presented_jti (AAuth-11)"
        } else if legacy {
            "person_token_jti (pre-11 name)"
        } else {
            "ABSENT — the PS cannot resolve this"
        }
    );

    // --- Leg 4: exchange it at the Person Server ---------------------------
    let (code, body, hdrs) = call(
        "POST",
        &format!("{ps}/token"),
        &scheme,
        key,
        Some(&serde_json::json!({
            "resource_token": resource_token,
            "justification": "aauthcheck three-party conformance run",
        })),
        None,
    );
    if code == 400 && body.contains("presented_jti") {
        t(check(
            false,
            "leg 4: PS rejects the resource token",
            "missing presented_jti — PS predates the alias, or the resource omits the claim",
        ));
        return;
    }
    let location = hdr(&hdrs, "location").unwrap_or_default().to_string();
    let requirement = hdr(&hdrs, "aauth-requirement")
        .unwrap_or_default()
        .to_string();
    t(check(
        code == 202 && !location.is_empty(),
        "leg 4: auth token request accepted",
        &format!("HTTP {code}"),
    ));
    if location.is_empty() {
        println!(
            "       body: {}",
            body.chars().take(200).collect::<String>()
        );
        return;
    }
    println!("\n  >>> APPROVE THIS: {requirement}\n");
    let mut auth_token = String::new();
    for _ in 0..40 {
        let (code, body, _) = call("GET", &location, &scheme, key, None, Some(20));
        if code == 200 {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            auth_token = v["auth_token"].as_str().unwrap_or("").to_string();
            break;
        }
        if code == 410 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    t(check(
        !auth_token.is_empty(),
        "leg 4: auth token issued",
        "",
    ));
    if auth_token.is_empty() {
        return;
    }

    // --- Leg 5: the auth token finally opens the resource ------------------
    let ascheme = sigkey::serialize_jwt(&auth_token);
    let (code, body, _) = call("GET", &probe, &ascheme, key, None, None);
    t(check(
        code == 200,
        "leg 5: resource served the request",
        &format!("HTTP {code}"),
    ));
    let echoed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    t(check(
        echoed["sub"].as_str() == Some(directed_sub.as_str()),
        "leg 5: the identity the resource sees is the one the PS asserted",
        &body.chars().take(140).collect::<String>(),
    ));
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
    let poll = args.iter().any(|a| a == "--poll");
    // Exercise the full three-party flow against a live resource.
    let three_party_resource = args
        .iter()
        .position(|a| a == "--three-party")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let interactive = args.iter().any(|a| a == "--interactive");
    // Bind the enrolled agent to a Person Server, so the issued agent token
    // carries `ps` and the AP knows where to send a revocation later.
    let ps = args
        .iter()
        .position(|a| a == "--ps")
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
        Some(&match &ps {
            Some(p) => serde_json::json!({ "ps": p }),
            None => serde_json::json!({}),
        }),
        None,
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
        None,
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
    println!(
        "       token kid={:?}  iss={}",
        decoded.header.kid,
        decoded.payload["iss"].as_str().unwrap_or("?")
    );

    // ---------- 1b. Interop: does an independent resource accept our token? ----------
    println!("\n== Interop: whoami.aauth.dev (third-party resource) ==");
    {
        let scheme = sigkey::serialize_jwt(&agent_token);
        let (code, body, hdrs) = call(
            "GET",
            "https://whoami.aauth.dev",
            &scheme,
            &durable,
            None,
            None,
        );
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

    // ---------- 1c. Three-party against a live resource ----------
    if let Some(resource) = &three_party_resource {
        match &ps {
            Some(ps_url) => three_party(
                resource.trim_end_matches('/'),
                ps_url.trim_end_matches('/'),
                &agent_token,
                &durable,
                interactive,
                &mut t,
            ),
            None => println!("\n--three-party needs --ps: the resource only asks for a person token when the agent token names one"),
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
                let (mut code, mut body, mut hdrs) = call(
                    "POST",
                    &ep,
                    &scheme,
                    &durable,
                    Some(&serde_json::json!({ "resource": "https://whoami.aauth.dev" })),
                    poll.then_some(20),
                );
                let signed_ok = code == 200 || code == 202;
                t(check(
                    signed_ok,
                    "signed person-token request accepted",
                    &format!("HTTP {code}{}", explain(code, &hdrs)),
                ));

                // A fresh agent has no consent on record, so a correct PS
                // defers. Follow the pending URL so the person-token claims are
                // actually graded once a person (or operator CLI) decides.
                if code == 202 && poll {
                    let loc = hdrs
                        .iter()
                        .find(|(n, _)| n == "location")
                        .map(|(_, v)| v.clone());
                    t(check(loc.is_some(), "202 carries Location", ""));
                    if let Some(loc) = loc {
                        let pending = if loc.starts_with("http") {
                            loc
                        } else {
                            format!("{}{}", target.trim_end_matches('/'), loc)
                        };
                        println!("       polling {pending} — approve it now (3 x 20s)");
                        for _ in 0..3 {
                            let (c, b, h) =
                                call("GET", &pending, &scheme, &durable, None, Some(20));
                            code = c;
                            body = b;
                            hdrs = h;
                            if code != 202 {
                                break;
                            }
                        }
                        t(check(
                            code == 200 || code == 403,
                            "pending resolved to a terminal state",
                            &format!("HTTP {code}"),
                        ));
                    }
                }

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
