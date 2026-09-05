//! Minimal JSON subset for the pin store (§7.4): objects, strings, and
//! non-negative integers. Hand-rolled so the crate's dependency tree stays
//! at `age` + `sha2` (see README.md). Not a general JSON library.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Json {
    Str(String),
    /// Non-negative integer; the formats' 2^63-1 bounds keep every value
    /// inside the interoperable JSON integer range.
    Num(u64),
    Obj(Vec<(String, Json)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsonError(pub(crate) String);

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed pin JSON: {}", self.0)
    }
}

impl Json {
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        self.render_into(&mut out);
        out
    }

    fn render_into(&self, out: &mut String) {
        match self {
            Json::Str(s) => render_string(s, out),
            Json::Num(n) => out.push_str(&n.to_string()),
            Json::Obj(fields) => {
                out.push('{');
                for (i, (key, value)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    render_string(key, out);
                    out.push(':');
                    value.render_into(out);
                }
                out.push('}');
            }
        }
    }

    pub(crate) fn parse(text: &str) -> Result<Json, JsonError> {
        let mut p = Parser {
            bytes: text.as_bytes(),
            pos: 0,
        };
        p.skip_ws();
        let value = p.value()?;
        p.skip_ws();
        if p.pos != p.bytes.len() {
            return Err(JsonError("trailing data".into()));
        }
        Ok(value)
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_num(&self) -> Option<u64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }

    pub(crate) fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

fn render_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while matches!(
            self.bytes.get(self.pos),
            Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
        ) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, b: u8) -> Result<(), JsonError> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(JsonError(format!(
                "expected '{}' at byte {}",
                b as char, self.pos
            )))
        }
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'0'..=b'9') => self.number(),
            _ => Err(JsonError(format!("unexpected byte at {}", self.pos))),
        }
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.expect(b'{')?;
        let mut fields = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(fields));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            if fields.iter().any(|(k, _)| *k == key) {
                return Err(JsonError(format!("duplicate key {key:?}")));
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value()?;
            fields.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(fields));
                }
                _ => return Err(JsonError(format!("expected ',' or '}}' at {}", self.pos))),
            }
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while matches!(self.peek(), Some(b) if b != b'"' && b != b'\\' && b >= 0x20) {
                self.pos += 1;
            }
            let chunk = std::str::from_utf8(&self.bytes[start..self.pos])
                .map_err(|_| JsonError("invalid UTF-8".into()))?;
            out.push_str(chunk);
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"') => out.push('"'),
                        Some(b'\\') => out.push('\\'),
                        Some(b'/') => out.push('/'),
                        Some(b'n') => out.push('\n'),
                        Some(b'r') => out.push('\r'),
                        Some(b't') => out.push('\t'),
                        Some(b'u') => {
                            let hex = self
                                .bytes
                                .get(self.pos + 1..self.pos + 5)
                                .and_then(|h| std::str::from_utf8(h).ok())
                                .and_then(|h| u32::from_str_radix(h, 16).ok())
                                .ok_or_else(|| JsonError("bad \\u escape".into()))?;
                            let c = char::from_u32(hex)
                                .ok_or_else(|| JsonError("bad \\u code point".into()))?;
                            out.push(c);
                            self.pos += 4;
                        }
                        _ => return Err(JsonError("bad escape".into())),
                    }
                    self.pos += 1;
                }
                _ => return Err(JsonError("unterminated string".into())),
            }
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let digits = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| JsonError("invalid UTF-8".into()))?;
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(JsonError("leading zero in number".into()));
        }
        digits
            .parse::<u64>()
            .map(Json::Num)
            .map_err(|_| JsonError("number out of range".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_nested_objects() {
        let v = Json::Obj(vec![
            ("vault".into(), Json::Str("3f9a".into())),
            ("counter".into(), Json::Num(u64::MAX)),
            (
                "memory".into(),
                Json::Obj(vec![
                    ("1".into(), Json::Str("aa".into())),
                    ("2".into(), Json::Str("bb".into())),
                ]),
            ),
            ("empty".into(), Json::Obj(vec![])),
        ]);
        let text = v.render();
        assert_eq!(Json::parse(&text), Ok(v));
    }

    #[test]
    fn escapes_round_trip() {
        let v = Json::Str("a\"b\\c\nd\te\u{1}f/".into());
        assert_eq!(Json::parse(&v.render()), Ok(v));
    }

    #[test]
    fn parses_whitespace_and_unicode_escapes() {
        let v = Json::parse(" { \"a\" : \"\\u0041\" , \"b\" : 7 } ").expect("valid");
        assert_eq!(v.get("a").and_then(Json::as_str), Some("A"));
        assert_eq!(v.get("b").and_then(Json::as_num), Some(7));
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "{",
            "{\"a\"}",
            "{\"a\":}",
            "[1]",
            "{\"a\":1}x",
            "01",
            "{\"a\":1,\"a\":2}",
            "{\"a\":18446744073709551616}",
            "\"\\q\"",
        ] {
            assert!(Json::parse(bad).is_err(), "{bad:?}");
        }
    }
}
