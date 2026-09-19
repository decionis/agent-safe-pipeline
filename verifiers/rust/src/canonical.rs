//! "sha256:" and the hex SHA-256 over the RFC 8785 canonical form of a JSON
//! object, or a refusal when the text is not one that is I-JSON: not valid
//! UTF-8, not an object, a name repeated within one object, or a lone
//! surrogate escape, each of which another parser would read differently.
//!
//! The canonicaliser is this crate's own: object names sorted by UTF-16 code
//! unit, numbers as ECMAScript prints them (ryu-js), strings escaped the way
//! RFC 8785 section 3.2.2.2 lists, no whitespace.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Why a body has no canonical form a provider may digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotIJson {
    NotUtf8,
    NotJson,
    NotAnObject,
    RepeatedName,
    NotFinite,
}

/// The canonical digest of a JSON object body.
pub fn canonical_digest(body: &[u8]) -> Result<String, NotIJson> {
    let text = std::str::from_utf8(body).map_err(|_| NotIJson::NotUtf8)?;
    // serde_json refuses a lone surrogate escape and anything that is not
    // JSON; it keeps the last of a repeated name, which the walk refuses.
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| NotIJson::NotJson)?;
    if !value.is_object() {
        return Err(NotIJson::NotAnObject);
    }
    if has_repeated_name(text) {
        return Err(NotIJson::RepeatedName);
    }
    let canonical = canonical_json(&value)?;
    let sum = Sha256::digest(canonical.as_bytes());
    Ok(format!("sha256:{}", hex(&sum)))
}

/// The RFC 8785 canonical form of a value.
pub fn canonical_json(value: &serde_json::Value) -> Result<String, NotIJson> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &serde_json::Value, out: &mut String) -> Result<(), NotIJson> {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(true) => out.push_str("true"),
        serde_json::Value::Bool(false) => out.push_str("false"),
        serde_json::Value::Number(number) => {
            // Every JSON number is an IEEE double to RFC 8785; ES6 prints it.
            let double = number.as_f64().ok_or(NotIJson::NotFinite)?;
            if !double.is_finite() {
                return Err(NotIJson::NotFinite);
            }
            let mut buffer = ryu_js::Buffer::new();
            out.push_str(buffer.format_finite(double));
        }
        serde_json::Value::String(text) => write_string(text, out),
        serde_json::Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        serde_json::Value::Object(members) => {
            let mut sorted: Vec<(&String, &serde_json::Value)> = members.iter().collect();
            // RFC 8785 orders names by their UTF-16 code units.
            sorted.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (index, (name, member)) in sorted.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write_canonical(member, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for char in text.chars() {
        match char {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The tokens of a JSON text that serde_json accepted, in order: strings with
/// their escapes, punctuation, and a scalar as its first character, since
/// nothing reads a scalar's text; whitespace is nothing. One pass, no
/// backtracking. Only valid JSON is given to this.
struct Tokens<'a> {
    text: &'a [u8],
    index: usize,
}

impl<'a> Tokens<'a> {
    fn next_token(&mut self) -> Option<&'a [u8]> {
        loop {
            let char = *self.text.get(self.index)?;
            match char {
                b'"' => {
                    let start = self.index;
                    self.index += 1;
                    while self.text.get(self.index) != Some(&b'"') {
                        if self.text.get(self.index) == Some(&b'\\') {
                            self.index += 1;
                        }
                        self.index += 1;
                    }
                    self.index += 1;
                    return Some(&self.text[start..self.index]);
                }
                b'{' | b'}' | b'[' | b']' | b':' | b',' => {
                    self.index += 1;
                    return Some(&self.text[self.index - 1..self.index]);
                }
                b' ' | b'\n' | b'\r' | b'\t' => self.index += 1,
                _ => {
                    let start = self.index;
                    while let Some(next) = self.text.get(self.index) {
                        if matches!(
                            next,
                            b'{' | b'}'
                                | b'['
                                | b']'
                                | b':'
                                | b','
                                | b'"'
                                | b' '
                                | b'\n'
                                | b'\r'
                                | b'\t'
                        ) {
                            break;
                        }
                        self.index += 1;
                    }
                    return Some(&self.text[start..start + 1]);
                }
            }
        }
    }
}

/// True when some object in a syntactically valid JSON text repeats a name.
fn has_repeated_name(text: &str) -> bool {
    let mut tokens = Tokens {
        text: text.as_bytes(),
        index: 0,
    };
    match tokens.next_token() {
        Some(first) => value_has_repeated_name(&mut tokens, first),
        None => false,
    }
}

fn value_has_repeated_name(tokens: &mut Tokens<'_>, first: &[u8]) -> bool {
    match first {
        b"{" => {
            let mut names: std::collections::HashSet<String> = std::collections::HashSet::new();
            let Some(mut token) = tokens.next_token() else {
                return true;
            };
            while token != b"}" {
                // A name token is a JSON string; decode it so escapes spell the same name.
                let Ok(name): Result<String, _> = serde_json::from_slice(token) else {
                    return true;
                };
                if !names.insert(name) {
                    return true;
                }
                let Some(_colon) = tokens.next_token() else {
                    return true;
                };
                let Some(value) = tokens.next_token() else {
                    return true;
                };
                if value_has_repeated_name(tokens, value) {
                    return true;
                }
                let Some(next) = tokens.next_token() else {
                    return true;
                };
                token = next;
                if token == b"," {
                    let Some(next) = tokens.next_token() else {
                        return true;
                    };
                    token = next;
                }
            }
            false
        }
        b"[" => {
            // A comma between values is read as a value with nothing inside.
            let Some(mut token) = tokens.next_token() else {
                return true;
            };
            while token != b"]" {
                if value_has_repeated_name(tokens, token) {
                    return true;
                }
                let Some(next) = tokens.next_token() else {
                    return true;
                };
                token = next;
            }
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_what_other_parsers_read_differently() {
        for body in [
            r#"{"a":1,"a":2}"#,
            r#"{"x":{"a":1,"b":2,"a":3}}"#,
            r#"{"x":[1,{"a":1,"a":2}]}"#,
            r#"{"\u0061":1,"a":2}"#,
            r#"{"a":"\udc00"}"#,
            r#"{"a":"\ud83d"}"#,
            r#"{"a":"\ud83d\ud83d"}"#,
            r#"{"a":"\ud83dx"}"#,
            r#"{"a":1} {"b":2}"#,
            "not json",
            "",
            "5",
            r#""a""#,
            "[1]",
        ] {
            assert!(canonical_digest(body.as_bytes()).is_err(), "{body}");
        }
        assert_eq!(canonical_digest(&[0xff]), Err(NotIJson::NotUtf8));
        for body in [
            r#"{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}],"d":[],"e":{}}"#,
            r#"{"a":"\ud83d\ude80","b":"\\ud83d","c":"\\\\uDC00"}"#,
            r#"{"a":"\"","a2":"\\"}"#,
            r#" {"a":1}"#,
            "{\"a\" :\r\n[ 1 ,\t2 ] , \"b\" : { } }",
        ] {
            assert!(canonical_digest(body.as_bytes()).is_ok(), "{body}");
        }
    }

    #[test]
    fn digest_is_over_the_canonical_form() {
        let spaced = canonical_digest(b"{\n  \"b\": 1,\n  \"a\": [1.50, 1e21, -0]\n}").unwrap();
        let compact = canonical_digest(br#"{"a":[1.5,1e+21,0],"b":1}"#).unwrap();
        assert_eq!(spaced, compact);
        assert_eq!(
            spaced,
            format!(
                "sha256:{}",
                hex(&Sha256::digest(br#"{"a":[1.5,1e+21,0],"b":1}"#))
            )
        );
    }

    /// The RFC 8785 examples and the pipeline's own conformance notes: names
    /// by UTF-16 code unit, ES6 numbers, minimal escapes, no normalization.
    #[test]
    fn canonical_form_follows_rfc_8785() {
        let canonical = |text: &str| canonical_json(&serde_json::from_str(text).unwrap()).unwrap();
        assert_eq!(
            canonical(r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}"#),
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
        assert_eq!(
            canonical(r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\u000a":"Newline","1":"One","\u0080":"Control\u007f","\ud83d\ude02":"Smiley","\u00f6":"Latin Small Letter O With Diaeresis","\ufb33":"Hebrew Letter Dalet With Dagesh"}"#),
            "{\"\\n\":\"Newline\",\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\u{7f}\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f602}\":\"Smiley\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
        );
        assert_eq!(
            canonical(r#"{"Z":0,"za":0,"z\u00e9":0,"\u00c9clair":0}"#),
            "{\"Z\":0,\"za\":0,\"z\u{e9}\":0,\"\u{c9}clair\":0}"
        );
        assert_eq!(
            canonical(r#"[-0,1e21,1e-7,0.1,100,1e100,123456789012345680000,-1.5]"#),
            "[0,1e+21,1e-7,0.1,100,1e+100,123456789012345680000,-1.5]"
        );
    }
}
