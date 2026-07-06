//! RFC 8941 Structured Field Values — the subset AAuth needs.
//!
//! Parses Dictionaries whose members are Items or Inner Lists, with
//! parameters; bare item types: Token, String, Integer, Byte Sequence,
//! Boolean (no Decimals or Dates). Each dictionary member records the **raw
//! source text** of its value: RFC 9421 requires the `@signature-params`
//! base line to reproduce the `Signature-Input` member exactly as received.
//!
//! Robustness rules per the drafts: unknown members and unknown parameters
//! are the *caller's* business to ignore; syntax errors are hard failures.

#[derive(Debug, Clone, PartialEq)]
pub enum BareItem {
    Token(String),
    Str(String),
    Int(i64),
    Bytes(Vec<u8>),
    Bool(bool),
}

impl BareItem {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            BareItem::Str(s) | BareItem::Token(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            BareItem::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            BareItem::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

pub type Params = Vec<(String, BareItem)>;

/// Look up a parameter by key. RFC 8941 §4.2.3.2: on a duplicate parameter
/// name the last value wins.
pub fn param<'a>(params: &'a Params, key: &str) -> Option<&'a BareItem> {
    params.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v)
}

#[derive(Debug, Clone, PartialEq)]
pub struct InnerList {
    pub items: Vec<(BareItem, Params)>,
    pub params: Params,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MemberValue {
    Item(BareItem, Params),
    List(InnerList),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub value: MemberValue,
    /// Exact source text of the member value (everything after `=` through
    /// the last parameter). Empty for bare-boolean members.
    pub raw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SfvError(pub &'static str);

impl std::fmt::Display for SfvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "structured field parse error: {}", self.0)
    }
}
impl std::error::Error for SfvError {}

struct Cursor<'a> {
    s: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }
    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
    }
    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ') | Some(b'\t')) {
            self.pos += 1;
        }
    }
    fn eof(&self) -> bool {
        self.pos >= self.s.len()
    }
}

fn is_key_start(c: u8) -> bool {
    c.is_ascii_lowercase() || c == b'*'
}
fn is_key_char(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-' | b'.' | b'*')
}
fn is_token_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'*'
}
fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
                | b':'
                | b'/'
        )
}

fn parse_key(c: &mut Cursor) -> Result<String, SfvError> {
    let start = c.pos;
    match c.peek() {
        Some(ch) if is_key_start(ch) => {
            c.pos += 1;
        }
        _ => return Err(SfvError("expected key")),
    }
    while let Some(ch) = c.peek() {
        if is_key_char(ch) {
            c.pos += 1;
        } else {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&c.s[start..c.pos]).into_owned())
}

fn parse_bare_item(c: &mut Cursor) -> Result<BareItem, SfvError> {
    match c.peek().ok_or(SfvError("unexpected end"))? {
        b'"' => {
            c.pos += 1;
            let mut out = String::new();
            loop {
                match c.bump().ok_or(SfvError("unterminated string"))? {
                    b'"' => return Ok(BareItem::Str(out)),
                    b'\\' => match c.bump().ok_or(SfvError("bad escape"))? {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        _ => return Err(SfvError("bad escape")),
                    },
                    ch if (0x20..=0x7e).contains(&ch) => out.push(ch as char),
                    _ => return Err(SfvError("bad string char")),
                }
            }
        }
        b':' => {
            c.pos += 1;
            let start = c.pos;
            while let Some(ch) = c.peek() {
                if ch == b':' {
                    break;
                }
                c.pos += 1;
            }
            let inner = std::str::from_utf8(&c.s[start..c.pos])
                .map_err(|_| SfvError("bad byte sequence"))?;
            if c.bump() != Some(b':') {
                return Err(SfvError("unterminated byte sequence"));
            }
            let bytes = crate::b64::decode_std(inner).map_err(|_| SfvError("bad base64"))?;
            Ok(BareItem::Bytes(bytes))
        }
        b'?' => {
            c.pos += 1;
            match c.bump() {
                Some(b'0') => Ok(BareItem::Bool(false)),
                Some(b'1') => Ok(BareItem::Bool(true)),
                _ => Err(SfvError("bad boolean")),
            }
        }
        ch if ch == b'-' || ch.is_ascii_digit() => {
            let start = c.pos;
            if ch == b'-' {
                c.pos += 1;
            }
            let digits_start = c.pos;
            while let Some(d) = c.peek() {
                if d.is_ascii_digit() {
                    c.pos += 1;
                } else {
                    break;
                }
            }
            if c.pos == digits_start || c.pos - digits_start > 15 {
                return Err(SfvError("bad integer"));
            }
            if c.peek() == Some(b'.') {
                return Err(SfvError("decimals not supported"));
            }
            let text = std::str::from_utf8(&c.s[start..c.pos]).unwrap();
            text.parse::<i64>()
                .map(BareItem::Int)
                .map_err(|_| SfvError("bad integer"))
        }
        ch if is_token_start(ch) => {
            let start = c.pos;
            c.pos += 1;
            while let Some(t) = c.peek() {
                if is_token_char(t) {
                    c.pos += 1;
                } else {
                    break;
                }
            }
            Ok(BareItem::Token(
                String::from_utf8_lossy(&c.s[start..c.pos]).into_owned(),
            ))
        }
        _ => Err(SfvError("unrecognized item")),
    }
}

fn parse_params(c: &mut Cursor) -> Result<Params, SfvError> {
    let mut params = Vec::new();
    while c.peek() == Some(b';') {
        c.pos += 1;
        c.skip_sp();
        let key = parse_key(c)?;
        let value = if c.peek() == Some(b'=') {
            c.pos += 1;
            parse_bare_item(c)?
        } else {
            BareItem::Bool(true)
        };
        params.push((key, value));
    }
    Ok(params)
}

fn parse_item_or_inner_list(c: &mut Cursor) -> Result<MemberValue, SfvError> {
    if c.peek() == Some(b'(') {
        c.pos += 1;
        let mut items = Vec::new();
        loop {
            c.skip_sp();
            if c.peek() == Some(b')') {
                c.pos += 1;
                let params = parse_params(c)?;
                return Ok(MemberValue::List(InnerList { items, params }));
            }
            if c.eof() {
                return Err(SfvError("unterminated inner list"));
            }
            let item = parse_bare_item(c)?;
            let params = parse_params(c)?;
            items.push((item, params));
            match c.peek() {
                Some(b' ') | Some(b')') => {}
                _ => return Err(SfvError("bad inner list separator")),
            }
        }
    } else {
        let item = parse_bare_item(c)?;
        let params = parse_params(c)?;
        Ok(MemberValue::Item(item, params))
    }
}

/// Parse a Structured Field Dictionary. Later members with a duplicate key
/// replace earlier ones (RFC 8941 §4.2).
pub fn parse_dictionary(input: &str) -> Result<Vec<(String, Member)>, SfvError> {
    if !input.is_ascii() {
        return Err(SfvError("non-ascii input"));
    }
    let mut c = Cursor {
        s: input.as_bytes(),
        pos: 0,
    };
    let mut out: Vec<(String, Member)> = Vec::new();
    c.skip_sp();
    if c.eof() {
        return Ok(out);
    }
    loop {
        let key = parse_key(&mut c)?;
        let member = if c.peek() == Some(b'=') {
            c.pos += 1;
            let raw_start = c.pos;
            let value = parse_item_or_inner_list(&mut c)?;
            let raw = String::from_utf8_lossy(&c.s[raw_start..c.pos]).into_owned();
            Member { value, raw }
        } else {
            let params = parse_params(&mut c)?;
            Member {
                value: MemberValue::Item(BareItem::Bool(true), params),
                raw: String::new(),
            }
        };
        out.retain(|(k, _)| k != &key);
        out.push((key, member));
        c.skip_ows();
        if c.eof() {
            return Ok(out);
        }
        if c.bump() != Some(b',') {
            return Err(SfvError("expected comma"));
        }
        c.skip_ows();
        if c.eof() {
            return Err(SfvError("trailing comma"));
        }
    }
}

/// Serialize an SF String (quoted, escaped).
pub fn serialize_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '\x20'..='\x7e' => out.push(ch),
            _ => out.push('?'), // callers must not put non-printable data in SF strings
        }
    }
    out.push('"');
    out
}

/// Serialize an inner list of SF Strings, e.g. `("@method" "@path")`.
pub fn serialize_string_list(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|s| serialize_string(s)).collect();
    format!("({})", inner.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_signature_input_style() {
        let d = parse_dictionary(
            r#"sig=("@method" "@authority" "@path" "signature-key");created=1730217600"#,
        )
        .unwrap();
        assert_eq!(d.len(), 1);
        let (key, member) = &d[0];
        assert_eq!(key, "sig");
        assert_eq!(
            member.raw,
            r#"("@method" "@authority" "@path" "signature-key");created=1730217600"#
        );
        match &member.value {
            MemberValue::List(l) => {
                let names: Vec<&str> = l.items.iter().filter_map(|(i, _)| i.as_str()).collect();
                assert_eq!(names, ["@method", "@authority", "@path", "signature-key"]);
                assert_eq!(
                    param(&l.params, "created").unwrap().as_int(),
                    Some(1730217600)
                );
            }
            _ => panic!("expected inner list"),
        }
    }

    #[test]
    fn parses_signature_key_style() {
        let d = parse_dictionary(r#"sig=jwt;jwt="eyJhbGc.payload.sig""#).unwrap();
        let member = &d[0].1;
        match &member.value {
            MemberValue::Item(BareItem::Token(t), params) => {
                assert_eq!(t, "jwt");
                assert_eq!(
                    param(params, "jwt").unwrap().as_str(),
                    Some("eyJhbGc.payload.sig")
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_hwk_style() {
        let d = parse_dictionary(r#"sig=hwk;kty="OKP";crv="Ed25519";x="JrQLj5P_89iXES9-vFgrIy""#)
            .unwrap();
        match &d[0].1.value {
            MemberValue::Item(BareItem::Token(t), params) => {
                assert_eq!(t, "hwk");
                assert_eq!(param(params, "kty").unwrap().as_str(), Some("OKP"));
                assert_eq!(param(params, "crv").unwrap().as_str(), Some("Ed25519"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_byte_sequence() {
        let d = parse_dictionary("sig=:aGVsbG8=:").unwrap();
        match &d[0].1.value {
            MemberValue::Item(BareItem::Bytes(b), _) => assert_eq!(b, b"hello"),
            _ => panic!(),
        }
    }

    #[test]
    fn multiple_members_and_dupes() {
        let d = parse_dictionary("a=1, b=2, a=3").unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d.iter().find(|(k, _)| k == "a").unwrap().1.raw, "3");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_dictionary("sig=").is_err());
        assert!(parse_dictionary("sig=(unclosed").is_err());
        assert!(parse_dictionary("sig=1,").is_err());
        assert!(parse_dictionary("Sig=1").is_err(), "uppercase key");
        assert!(parse_dictionary("a=1.5").is_err(), "decimals unsupported");
    }

    #[test]
    fn boolean_member() {
        let d = parse_dictionary("flag").unwrap();
        match &d[0].1.value {
            MemberValue::Item(BareItem::Bool(true), _) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn duplicate_param_last_wins() {
        // RFC 8941 §4.2.3.2: last value wins on a duplicate parameter name.
        let d = parse_dictionary("sig=1;created=100;created=200").unwrap();
        let params = match &d[0].1.value {
            MemberValue::Item(_, p) => p,
            _ => panic!(),
        };
        assert_eq!(param(params, "created").unwrap().as_int(), Some(200));
    }
}
