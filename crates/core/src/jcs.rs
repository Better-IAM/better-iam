//! The JSON Canonicalization Scheme (RFC 8785) (`jcs.ts`): the single serialization of a JSON value that signers and
//! verifiers agree on. Object members are sorted by the UTF-16 code units of their names at every depth, numbers use
//! the ECMAScript shortest form and strings the escaping of `JSON.stringify`, and there is no whitespace. Unlike
//! [`crate::audit::canonical_json`], member order does not depend on how a JavaScript engine orders integer-like keys.
//!
//! The TypeScript function also accepts `undefined` members (left out), functions, `toJSON` and refuses non-finite
//! numbers, bigints and cycles; a `serde_json::Value` holds none of those, so the Rust function cannot fail.

use serde_json::Value;

use crate::js;

/// `canonicalizeJson(value)`.
pub fn canonicalize_json(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

fn write(value: &Value, out: &mut String) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| js::cmp_utf16(left, right));
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                js::quote_into(key, out);
                out.push(':');
                write(&map[key.as_str()], out);
            }
            out.push('}');
        }
        other => js::stringify_into(other, out),
    }
}
