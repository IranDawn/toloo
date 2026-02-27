use std::cmp::Ordering;
use std::fmt::Write as _;

use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::{Map, Number, Value};

/// Serialize any serde value into canonical JSON used by Toloo signatures/hashes.
pub fn canonical<T: Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)?;
    canonical_value(&value)
}

/// Canonical JSON as UTF-8 bytes.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(canonical(value)?.into_bytes())
}

/// Serialize a JSON value into canonical JSON.
pub fn canonical_value(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(v) => {
            if *v {
                out.push_str("true");
            } else {
                out.push_str("false");
            }
        }
        Value::Number(n) => out.push_str(&canonical_number(n)?),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_object(map, out)?,
    }
    Ok(())
}

fn write_object(map: &Map<String, Value>, out: &mut String) -> Result<()> {
    let mut entries: Vec<(&str, &Value)> = map.iter().map(|(k, v)| (k.as_str(), v)).collect();
    entries.sort_by(|(a, _), (b, _)| utf16_cmp(a, b));

    out.push('{');
    for (idx, (k, v)) in entries.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        write_string(k, out);
        out.push(':');
        write_value(v, out)?;
    }
    out.push('}');
    Ok(())
}

fn write_string(input: &str, out: &mut String) {
    out.push('"');
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) <= 0x1F => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn canonical_number(number: &Number) -> Result<String> {
    if let Some(v) = number.as_f64() {
        if !v.is_finite() {
            bail!("non-finite numbers are not valid JSON");
        }
    }
    Ok(number.to_string())
}

fn utf16_cmp(a: &str, b: &str) -> Ordering {
    let mut left = a.encode_utf16();
    let mut right = b.encode_utf16();
    loop {
        match (left.next(), right.next()) {
            (Some(x), Some(y)) if x == y => continue,
            (Some(x), Some(y)) => return x.cmp(&y),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use crate::types::DatumBody;

    use super::canonical;

    #[test]
    fn canonicalizes_known_readme_example() {
        let v = json!({
            "ts": 1,
            "n": "A",
            "v": "0.2",
            "t": "room.message"
        });
        let got = canonical(&v).expect("canonicalization should succeed");
        assert_eq!(got, r#"{"n":"A","t":"room.message","ts":1,"v":"0.2"}"#);
    }

    #[test]
    fn sorts_object_keys_by_utf16_units() {
        let v = json!({
            "\u{E000}": 1,
            "\u{10000}": 2
        });
        let got = canonical(&v).expect("canonicalization should succeed");
        let pos_u10000 = got.find('\u{10000}').expect("should contain U+10000");
        let pos_ue000 = got.find('\u{E000}').expect("should contain U+E000");
        assert!(pos_u10000 < pos_ue000);
    }

    #[test]
    fn omits_none_fields_when_struct_uses_skip_serializing_if() {
        let d = DatumBody {
            n: "A".to_owned(),
            v: "0.2".to_owned(),
            t: "room.message".to_owned(),
            ts: 1,
            r: None,
            to: None,
            c: None,
            env: None,
            tc: None,
            exp: None,
            nonce: None,

            extra: HashMap::new(),
        };

        let got = canonical(&d).expect("canonicalization should succeed");
        assert_eq!(got, r#"{"n":"A","t":"room.message","ts":1,"v":"0.2"}"#);
        assert!(!got.contains("null"));
    }
}
