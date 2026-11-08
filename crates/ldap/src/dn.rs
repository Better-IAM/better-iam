//! Port of `packages/ldap/src/dn.ts`: distinguished names (RFC 4514): parsing with escapes (`\,`, `\2C`), quoting of
//! values, and a normalized form for comparisons (attribute types and values lowercased, insignificant spaces
//! trimmed). Multi-valued RDNs (`+`) are kept in order.

use std::fmt;
use std::sync::LazyLock;

use better_iam_core::js;
use regex::Regex;

/// `DnError`: a malformed DN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnError(pub String);

impl DnError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DnError {}

/// One attribute type and value of an RDN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdn {
    pub kind: String,
    pub value: String,
}

const SPECIAL: [char; 8] = [',', '+', '"', '\\', '<', '>', ';', '='];

static ATTRIBUTE_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[a-zA-Z][a-zA-Z0-9-]*|[0-9]+(?:\.[0-9]+)*)$").unwrap());

/// Escapes an attribute value for use in a DN.
pub fn escape_dn_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::new();
    for (index, &c) in chars.iter().enumerate() {
        let code = c as u32;
        if SPECIAL.contains(&c) {
            out.push('\\');
            out.push(c);
        } else if code < 0x20 || code == 0x7f {
            out.push_str(&format!("\\{code:02x}"));
        } else if (index == 0 && (c == ' ' || c == '#')) || (index == chars.len() - 1 && c == ' ') {
            out.push('\\');
            out.push(c);
        } else {
            out.push(c);
        }
    }
    out
}

/// Parses a DN into RDNs (each a list of type/value pairs; most have one). The empty DN is the root.
pub fn parse_dn(dn: &str) -> Result<Vec<Vec<Rdn>>, DnError> {
    if js::utf16_len(dn) > 4096 {
        return Err(DnError::new("Invalid DN"));
    }
    let mut rdns = Vec::new();
    if js::trim(dn).is_empty() {
        return Ok(rdns);
    }
    let dn: Vec<char> = dn.chars().collect();
    let at = |index: usize| dn.get(index).copied();
    let mut index = 0;
    let mut current: Vec<Rdn> = Vec::new();
    let mut bytes: Vec<u8> = Vec::new();
    let flush = |bytes: &mut Vec<u8>| -> String {
        if bytes.is_empty() {
            return String::new();
        }
        let text = String::from_utf8_lossy(bytes).into_owned();
        bytes.clear();
        text
    };
    while index <= dn.len() {
        // Attribute type.
        while at(index) == Some(' ') {
            index += 1;
        }
        let Some(equals) = (index..dn.len()).find(|&position| dn[position] == '=') else {
            return Err(DnError::new("Missing = in DN"));
        };
        let raw_type: String = dn[index.min(equals)..equals].iter().collect();
        let kind = js::trim(&raw_type).to_owned();
        if !ATTRIBUTE_TYPE.is_match(&kind) {
            return Err(DnError::new("Invalid attribute type in DN"));
        }
        index = equals + 1;
        while at(index) == Some(' ') {
            index += 1;
        }
        // Attribute value.
        let mut value = String::new();
        if at(index) == Some('"') {
            index += 1;
            while index < dn.len() && dn[index] != '"' {
                if dn[index] == '\\' {
                    index += 1;
                }
                if let Some(c) = at(index) {
                    value.push(c);
                }
                index += 1;
            }
            if at(index) != Some('"') {
                return Err(DnError::new("Unterminated quoted value"));
            }
            index += 1;
            while at(index) == Some(' ') {
                index += 1;
            }
        } else {
            let mut trailing_spaces = 0;
            while index < dn.len() && dn[index] != ',' && dn[index] != '+' && dn[index] != ';' {
                let c = dn[index];
                if c == '\\' {
                    let hex: String = dn[(index + 1).min(dn.len())..(index + 3).min(dn.len())]
                        .iter()
                        .collect();
                    if hex.len() == 2 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        bytes.push(u8::from_str_radix(&hex, 16).unwrap_or_default());
                        index += 3;
                    } else if index + 1 < dn.len() {
                        value.push_str(&flush(&mut bytes));
                        value.push(dn[index + 1]);
                        index += 2;
                    } else {
                        return Err(DnError::new("Dangling escape in DN"));
                    }
                    trailing_spaces = 0;
                    continue;
                }
                value.push_str(&flush(&mut bytes));
                value.push(c);
                trailing_spaces = if c == ' ' { trailing_spaces + 1 } else { 0 };
                index += 1;
            }
            value.push_str(&flush(&mut bytes));
            if trailing_spaces > 0 {
                value.truncate(value.len() - trailing_spaces);
            }
        }
        current.push(Rdn { kind, value });
        let separator = at(index);
        index += 1;
        if separator == Some('+') {
            continue;
        }
        rdns.push(std::mem::take(&mut current));
        if separator.is_none() {
            break;
        }
    }
    Ok(rdns)
}

/// Formats RDNs as a DN string.
pub fn format_dn(rdns: &[Vec<Rdn>]) -> String {
    rdns.iter()
        .map(|rdn| {
            rdn.iter()
                .map(|part| format!("{}={}", part.kind, escape_dn_value(&part.value)))
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// `value.trim().replace(/\s+/g, ' ')`.
pub(crate) fn collapse_spaces(value: &str) -> String {
    let mut out = String::new();
    let mut in_space = false;
    for c in js::trim(value).chars() {
        if js::is_js_whitespace(c) {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.push(c);
            in_space = false;
        }
    }
    out
}

/// The comparison form of a DN: lowercased, re-escaped, spaces normalized. Fails on malformed DNs.
pub fn normalize_dn(dn: &str) -> Result<String, DnError> {
    Ok(parse_dn(dn)?
        .iter()
        .map(|rdn| {
            let mut parts: Vec<String> = rdn
                .iter()
                .map(|part| {
                    format!(
                        "{}={}",
                        js::to_lower(&part.kind),
                        escape_dn_value(&js::to_lower(&collapse_spaces(&part.value)))
                    )
                })
                .collect();
            parts.sort_by(|a, b| js::cmp_utf16(a, b));
            parts.join("+")
        })
        .collect::<Vec<_>>()
        .join(","))
}

/// The normalized RDN strings of a DN, leaf first.
fn normalized_rdns(dn: &str) -> Result<Vec<String>, DnError> {
    let normalized = normalize_dn(dn)?;
    if normalized.is_empty() {
        return Ok(Vec::new());
    }
    Ok(parse_dn(&normalized)?
        .into_iter()
        .map(|rdn| format_dn(&[rdn]))
        .collect())
}

/// Whether `dn` equals `base` or lies below it. Compared RDN by RDN, never as strings: `cn=a\,ou=people,dc=x` is not
/// under `ou=people,dc=x`.
pub fn is_under(dn: &str, base: &str) -> Result<bool, DnError> {
    let child = normalized_rdns(dn)?;
    let parent = normalized_rdns(base)?;
    if parent.len() > child.len() {
        return Ok(false);
    }
    let offset = child.len() - parent.len();
    Ok(parent
        .iter()
        .enumerate()
        .all(|(index, rdn)| child[offset + index] == *rdn))
}

/// How many RDNs `dn` has below `base` (-1 when it is not under it).
pub fn depth_below(dn: &str, base: &str) -> Result<i64, DnError> {
    Ok(if is_under(dn, base)? {
        normalized_rdns(dn)?.len() as i64 - normalized_rdns(base)?.len() as i64
    } else {
        -1
    })
}

/// The normalized parent of a normalized DN ('' for a single RDN).
pub fn parent_dn(dn: &str) -> Result<String, DnError> {
    let rdns = parse_dn(dn)?;
    if rdns.len() <= 1 {
        return Ok(String::new());
    }
    normalize_dn(&format_dn(&rdns[1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_escapes_and_quotes() {
        let rdns = parse_dn(r#"cn=Smith\, John+uid=js,ou=People\2C Inc,o="A, B""#).unwrap();
        assert_eq!(rdns.len(), 3);
        assert_eq!(rdns[0].len(), 2);
        assert_eq!(rdns[0][0].value, "Smith, John");
        assert_eq!(rdns[1][0].value, "People, Inc");
        assert_eq!(rdns[2][0].value, "A, B");
        assert_eq!(parse_dn("cn=caf\\c3\\a9").unwrap()[0][0].value, "café");
        assert!(parse_dn("cn").is_err());
        assert!(parse_dn("1x=a").is_err());
        assert!(parse_dn("cn=a\\").is_err());
        assert_eq!(parse_dn("  ").unwrap(), Vec::<Vec<Rdn>>::new());
    }

    #[test]
    fn normalizes_and_compares() {
        assert_eq!(
            normalize_dn("UID=Alice,  OU=People , DC=Acme,DC=Test").unwrap(),
            "uid=alice,ou=people,dc=acme,dc=test"
        );
        assert_eq!(escape_dn_value("Smith, John+1"), "Smith\\, John\\+1");
        assert_eq!(escape_dn_value(" #a "), "\\ #a\\ ");
        assert!(is_under("uid=a,ou=people,dc=acme,dc=test", "dc=acme,dc=test").unwrap());
        assert!(!is_under("dc=acme,dc=test", "ou=people,dc=acme,dc=test").unwrap());
        assert!(!is_under("cn=a\\,ou=people,dc=x", "ou=people,dc=x").unwrap());
        assert_eq!(depth_below("uid=a,ou=people,dc=x", "dc=x").unwrap(), 2);
        assert_eq!(depth_below("dc=y", "dc=x").unwrap(), -1);
        assert_eq!(parent_dn("uid=a,ou=People,dc=x").unwrap(), "ou=people,dc=x");
    }
}
