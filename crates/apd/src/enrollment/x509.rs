//! X.509 support for `x5c`-type federated enrollment: PEM loading, chain
//! validation to configured roots (rustls-webpki, optional CRLs), JWS
//! signature verification with the leaf certificate's key, and a minimal DER
//! walker that extracts the leaf's DNS/URI Subject Alternative Names for
//! SPIFFE-style SAN policy.

use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};

/// Extract all blocks of the given PEM `kind` (e.g. "CERTIFICATE", "X509 CRL")
/// from a PEM bundle. DER input containing no PEM markers is returned as a
/// single block.
pub fn pem_blocks(data: &[u8], kind: &str) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(data);
    let begin = format!("-----BEGIN {kind}-----");
    let end = format!("-----END {kind}-----");
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let Some(stop) = after.find(&end) else { break };
        let b64: String = after[..stop]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if let Ok(der) = aauth_core::b64::decode_std(&b64) {
            out.push(der);
        }
        rest = &after[stop + end.len()..];
    }
    if out.is_empty() && !text.contains("-----BEGIN") && !data.is_empty() {
        out.push(data.to_vec()); // raw DER
    }
    out
}

/// The verification algorithms accepted for chain building and leaf JWS
/// verification.
static ALL_VERIFICATION_ALGS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
    webpki::ring::ED25519,
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
    webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
];

fn jws_alg_to_webpki(
    alg: &str,
) -> Option<&'static dyn rustls_pki_types::SignatureVerificationAlgorithm> {
    Some(match alg {
        "EdDSA" => webpki::ring::ED25519,
        "RS256" => webpki::ring::RSA_PKCS1_2048_8192_SHA256,
        "RS384" => webpki::ring::RSA_PKCS1_2048_8192_SHA384,
        "RS512" => webpki::ring::RSA_PKCS1_2048_8192_SHA512,
        "ES256" => webpki::ring::ECDSA_P256_SHA256,
        "ES384" => webpki::ring::ECDSA_P384_SHA384,
        _ => return None,
    })
}

/// Convert a JWS fixed-width ECDSA signature (r || s) into ASN.1 DER, which is
/// what X.509/webpki verification expects.
pub fn ecdsa_fixed_to_der(sig: &[u8]) -> Option<Vec<u8>> {
    if sig.len() % 2 != 0 || sig.is_empty() {
        return None;
    }
    let (r, s) = sig.split_at(sig.len() / 2);
    fn der_int(v: &[u8]) -> Vec<u8> {
        let mut v = v;
        while v.len() > 1 && v[0] == 0 {
            v = &v[1..];
        }
        let mut out = vec![0x02];
        if v[0] & 0x80 != 0 {
            out.push((v.len() + 1) as u8);
            out.push(0x00);
        } else {
            out.push(v.len() as u8);
        }
        out.extend_from_slice(v);
        out
    }
    let ri = der_int(r);
    let si = der_int(s);
    let content_len = ri.len() + si.len();
    let mut out = Vec::with_capacity(content_len + 3);
    out.push(0x30);
    if content_len < 128 {
        out.push(content_len as u8);
    } else {
        out.push(0x81);
        out.push(content_len as u8);
    }
    out.extend_from_slice(&ri);
    out.extend_from_slice(&si);
    Some(out)
}

/// Validate an x5c chain (leaf first, DER) against trusted roots at `now`,
/// with optional CRLs, then verify `signature` over `message` with the leaf
/// key using the JWS `alg`. On success returns the leaf's (dns, uri) SANs.
pub fn verify_x5c_jws(
    chain_der: &[Vec<u8>],
    roots_der: &[Vec<u8>],
    crls_der: &[Vec<u8>],
    now: u64,
    alg: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<Vec<String>, String> {
    if chain_der.is_empty() {
        return Err("empty x5c chain".into());
    }
    if roots_der.is_empty() {
        return Err("no trusted roots configured".into());
    }

    let leaf = CertificateDer::from(chain_der[0].as_slice());
    let intermediates: Vec<CertificateDer> = chain_der[1..]
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let root_certs: Vec<CertificateDer> = roots_der
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let anchors: Vec<_> = root_certs
        .iter()
        .map(|c| anchor_from_trusted_cert(c).map_err(|e| format!("bad CA root: {e:?}")))
        .collect::<Result<_, _>>()?;

    let end_entity = EndEntityCert::try_from(&leaf)
        .map_err(|e| format!("unparseable leaf certificate: {e:?}"))?;

    let time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(now));

    // Optional revocation checking.
    let parsed_crls: Vec<webpki::CertRevocationList> = crls_der
        .iter()
        .map(|d| {
            webpki::BorrowedCertRevocationList::from_der(d)
                .map(webpki::CertRevocationList::from)
                .map_err(|e| format!("bad CRL: {e:?}"))
        })
        .collect::<Result<_, _>>()?;
    let crl_refs: Vec<&webpki::CertRevocationList> = parsed_crls.iter().collect();
    let revocation = if crl_refs.is_empty() {
        None
    } else {
        Some(
            webpki::RevocationOptionsBuilder::new(&crl_refs)
                .map_err(|e| format!("CRL options: {e:?}"))?
                .build(),
        )
    };

    end_entity
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            time,
            KeyUsage::client_auth(),
            revocation,
            None,
        )
        .map_err(|e| format!("certificate chain validation failed: {e:?}"))?;

    // Verify the JWS signature with the leaf key.
    let webpki_alg =
        jws_alg_to_webpki(alg).ok_or_else(|| format!("unsupported x5c JWS alg {alg}"))?;
    let sig_for_cert: Vec<u8> = match alg {
        "ES256" | "ES384" => ecdsa_fixed_to_der(signature).ok_or("malformed ECDSA signature")?,
        _ => signature.to_vec(),
    };
    end_entity
        .verify_signature(webpki_alg, message, &sig_for_cert)
        .map_err(|_| "assertion signature does not verify with the leaf certificate".to_string())?;

    extract_sans(&chain_der[0])
}

// ------------------------------------------------------------------ DER SANs

struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Der<'a> {
        Der { data, pos: 0 }
    }
    fn done(&self) -> bool {
        self.pos >= self.data.len()
    }
    fn read(&mut self) -> Result<Tlv<'a>, String> {
        let err = || "truncated DER".to_string();
        let tag = *self.data.get(self.pos).ok_or_else(err)?;
        self.pos += 1;
        let first = *self.data.get(self.pos).ok_or_else(err)?;
        self.pos += 1;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err("unsupported DER length".into());
            }
            let mut len = 0usize;
            for _ in 0..n {
                let b = *self.data.get(self.pos).ok_or_else(err)?;
                self.pos += 1;
                len = (len << 8) | b as usize;
            }
            len
        };
        let end = self.pos.checked_add(len).ok_or_else(err)?;
        if end > self.data.len() {
            return Err(err());
        }
        let value = &self.data[self.pos..end];
        self.pos = end;
        Ok(Tlv { tag, value })
    }
}

/// Extract DNS (`dns:`-prefixed) and URI SAN entries from a DER certificate.
/// Returns entries as-is (URIs like `spiffe://…`, DNS names bare).
pub fn extract_sans(cert_der: &[u8]) -> Result<Vec<String>, String> {
    let mut top = Der::new(cert_der);
    let cert = top.read()?; // Certificate ::= SEQUENCE
    let mut cert_seq = Der::new(cert.value);
    let tbs = cert_seq.read()?; // tbsCertificate ::= SEQUENCE
    let mut tbs_seq = Der::new(tbs.value);

    // [0] version (optional), serial, sigAlg, issuer, validity, subject, SPKI
    let mut next = tbs_seq.read()?;
    if next.tag == 0xa0 {
        next = tbs_seq.read()?; // consumed version; next = serialNumber
    }
    let _serial = next;
    let _sig_alg = tbs_seq.read()?;
    let _issuer = tbs_seq.read()?;
    let _validity = tbs_seq.read()?;
    let _subject = tbs_seq.read()?;
    let _spki = tbs_seq.read()?;

    // Optional [1] issuerUniqueID, [2] subjectUniqueID, then [3] extensions.
    let mut sans = Vec::new();
    while !tbs_seq.done() {
        let field = tbs_seq.read()?;
        if field.tag != 0xa3 {
            continue; // skip [1]/[2]
        }
        // extensions ::= SEQUENCE OF Extension
        let mut exts_wrapper = Der::new(field.value);
        let exts = exts_wrapper.read()?;
        let mut exts_seq = Der::new(exts.value);
        while !exts_seq.done() {
            let ext = exts_seq.read()?; // Extension ::= SEQUENCE
            let mut ext_seq = Der::new(ext.value);
            let oid = ext_seq.read()?;
            if oid.tag != 0x06 {
                continue;
            }
            let mut inner = ext_seq.read()?;
            if inner.tag == 0x01 {
                inner = ext_seq.read()?; // skip `critical` BOOLEAN
            }
            // subjectAltName OID = 2.5.29.17 => 55 1D 11
            if oid.value != [0x55, 0x1d, 0x11] || inner.tag != 0x04 {
                continue;
            }
            // extnValue OCTET STRING wraps GeneralNames ::= SEQUENCE
            let mut gn_wrapper = Der::new(inner.value);
            let names = gn_wrapper.read()?;
            let mut names_seq = Der::new(names.value);
            while !names_seq.done() {
                let name = names_seq.read()?;
                match name.tag {
                    0x82 /* [2] dNSName */ => {
                        if let Ok(s) = std::str::from_utf8(name.value) {
                            sans.push(s.to_string());
                        }
                    }
                    0x86 /* [6] URI */ => {
                        if let Ok(s) = std::str::from_utf8(name.value) {
                            sans.push(s.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(sans)
}

/// Match a SAN value against a pattern: exact, or prefix with a trailing `*`.
pub fn san_matches(pattern: &str, san: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => san.starts_with(prefix),
        None => pattern == san,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_parsing() {
        let pem = "junk\n-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\nmore\n-----BEGIN CERTIFICATE-----\nAwQF\n-----END CERTIFICATE-----\n";
        let blocks = pem_blocks(pem.as_bytes(), "CERTIFICATE");
        assert_eq!(blocks, vec![vec![0, 1, 2], vec![3, 4, 5]]);
        // raw DER passthrough
        let raw = pem_blocks(&[0x30, 0x03, 0x01, 0x02, 0x03], "CERTIFICATE");
        assert_eq!(raw.len(), 1);
    }

    #[test]
    fn ecdsa_der_conversion() {
        // r with a high bit set gets a 0x00 pad; leading zeros stripped.
        let mut sig = vec![0u8; 64];
        sig[0] = 0x80;
        sig[32] = 0x01;
        let der = ecdsa_fixed_to_der(&sig).unwrap();
        assert_eq!(der[0], 0x30);
        // r: 02 21 00 80 ... ; s: 02 20 01 00...  (s keeps full 32 bytes since
        // only leading zeros are stripped and s[0]=0x01)
        assert_eq!(&der[2..5], &[0x02, 0x21, 0x00]);
    }

    #[test]
    fn san_pattern_matching() {
        assert!(san_matches(
            "spiffe://td/ns/agents/*",
            "spiffe://td/ns/agents/sa/runner"
        ));
        assert!(!san_matches(
            "spiffe://td/ns/agents/*",
            "spiffe://td/ns/other/sa/x"
        ));
        assert!(san_matches("agent.example.com", "agent.example.com"));
        assert!(!san_matches("agent.example.com", "evil.example.com"));
    }
}
