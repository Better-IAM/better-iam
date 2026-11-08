//! Port of `packages/ldap/src/filter.ts`: LDAP search filters (RFC 4511 §4.5.1): the BER form a search carries, the
//! string form of RFC 4515 (for clients and tests), and evaluation against an entry. Attribute names compare
//! case-insensitively; values compare as caseIgnore strings, except that `entryUUID` and DN-valued attributes are
//! normalized first by the caller's entry data.

use better_iam_core::js;
use indexmap::IndexMap;

use crate::ber::{self, BerElement, BerError};
use crate::dn::collapse_spaces;

/// `Filter`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    Equal {
        attribute: String,
        value: String,
    },
    Greater {
        attribute: String,
        value: String,
    },
    Less {
        attribute: String,
        value: String,
    },
    Approx {
        attribute: String,
        value: String,
    },
    Substrings {
        attribute: String,
        initial: Option<String>,
        any: Vec<String>,
        last: Option<String>,
    },
    Present {
        attribute: String,
    },
    Extensible {
        attribute: Option<String>,
        rule: Option<String>,
        value: String,
        dn_attributes: bool,
    },
}

const MAX_DEPTH: usize = 32;
const MAX_TERMS: usize = 256;

/// Decodes a BER filter. Deep or huge filters are refused (a search is evaluated against every entry).
pub fn decode_filter(item: &BerElement<'_>) -> Result<Filter, BerError> {
    let mut terms = 0;
    decode(item, 0, &mut terms)
}

fn utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn decode(item: &BerElement<'_>, depth: usize, terms: &mut usize) -> Result<Filter, BerError> {
    *terms += 1;
    if depth > MAX_DEPTH || *terms > MAX_TERMS {
        return Err(BerError::new("Filter too complex"));
    }
    let parts = || ber::children(item.value);
    match item.tag {
        0xa0 | 0xa1 => {
            let mut filters = Vec::new();
            for part in parts()? {
                filters.push(decode(&part, depth + 1, terms)?);
            }
            Ok(if item.tag == 0xa0 {
                Filter::And(filters)
            } else {
                Filter::Or(filters)
            })
        }
        0xa2 => {
            let parts = parts()?;
            let Some(inner) = parts.first() else {
                return Err(BerError::new("Empty not filter"));
            };
            Ok(Filter::Not(Box::new(decode(inner, depth + 1, terms)?)))
        }
        0xa3 | 0xa5 | 0xa6 | 0xa8 => {
            let parts = parts()?;
            let attribute = ber::read_string(parts.first(), ber::tag::OCTET_STRING)?;
            let value = ber::read_string(parts.get(1), ber::tag::OCTET_STRING)?;
            Ok(match item.tag {
                0xa3 => Filter::Equal { attribute, value },
                0xa5 => Filter::Greater { attribute, value },
                0xa6 => Filter::Less { attribute, value },
                _ => Filter::Approx { attribute, value },
            })
        }
        0xa4 => {
            let parts = parts()?;
            let attribute = ber::read_string(parts.first(), ber::tag::OCTET_STRING)?;
            let (mut initial, mut any, mut last) = (None, Vec::new(), None);
            let substrings = parts.get(1).filter(|item| item.tag == 0x30);
            let Some(substrings) = substrings else {
                return Err(BerError::new("Invalid substrings filter"));
            };
            for part in ber::children(substrings.value)? {
                let text = utf8(part.value);
                match part.tag {
                    0x80 => initial = Some(text),
                    0x81 => any.push(text),
                    0x82 => last = Some(text),
                    _ => return Err(BerError::new("Invalid substring")),
                }
            }
            Ok(Filter::Substrings {
                attribute,
                initial,
                any,
                last,
            })
        }
        0x87 => Ok(Filter::Present {
            attribute: utf8(item.value),
        }),
        0xa9 => {
            let (mut attribute, mut rule, mut value, mut dn_attributes) =
                (None, None, String::new(), false);
            for part in parts()? {
                match part.tag {
                    0x81 => rule = Some(utf8(part.value)),
                    0x82 => attribute = Some(utf8(part.value)),
                    0x83 => value = utf8(part.value),
                    0x84 => dn_attributes = ber::read_boolean(Some(&part), 0x84)?,
                    _ => {}
                }
            }
            Ok(Filter::Extensible {
                attribute,
                rule,
                value,
                dn_attributes,
            })
        }
        tag => Err(BerError::new(format!("Unknown filter choice 0x{tag:x}"))),
    }
}

/// The BER form of a filter.
pub fn encode_filter(filter: &Filter) -> Vec<u8> {
    use ber::{boolean, sequence, set, text};
    const OS: u8 = ber::tag::OCTET_STRING;
    match filter {
        Filter::And(filters) | Filter::Or(filters) => {
            let tag = if matches!(filter, Filter::And(_)) {
                0xa0
            } else {
                0xa1
            };
            set(&filters.iter().map(encode_filter).collect::<Vec<_>>(), tag)
        }
        Filter::Not(inner) => sequence(&[encode_filter(inner)], 0xa2),
        Filter::Equal { attribute, value }
        | Filter::Greater { attribute, value }
        | Filter::Less { attribute, value }
        | Filter::Approx { attribute, value } => {
            let tag = match filter {
                Filter::Equal { .. } => 0xa3,
                Filter::Greater { .. } => 0xa5,
                Filter::Less { .. } => 0xa6,
                _ => 0xa8,
            };
            sequence(&[text(attribute, OS), text(value, OS)], tag)
        }
        Filter::Substrings {
            attribute,
            initial,
            any,
            last,
        } => {
            let mut parts = Vec::new();
            if let Some(initial) = initial {
                parts.push(text(initial, 0x80));
            }
            parts.extend(any.iter().map(|part| text(part, 0x81)));
            if let Some(last) = last {
                parts.push(text(last, 0x82));
            }
            sequence(
                &[text(attribute, OS), sequence(&parts, ber::tag::SEQUENCE)],
                0xa4,
            )
        }
        Filter::Present { attribute } => text(attribute, 0x87),
        Filter::Extensible {
            attribute,
            rule,
            value,
            dn_attributes,
        } => {
            let mut parts = Vec::new();
            if let Some(rule) = rule.as_ref().filter(|rule| !rule.is_empty()) {
                parts.push(text(rule, 0x81));
            }
            if let Some(attribute) = attribute.as_ref().filter(|attribute| !attribute.is_empty()) {
                parts.push(text(attribute, 0x82));
            }
            parts.push(text(value, 0x83));
            if *dn_attributes {
                parts.push(boolean(true, 0x84));
            }
            sequence(&parts, 0xa9)
        }
    }
}

/// `\2a` escapes are bytes (possibly parts of one UTF-8 character); everything else is text.
fn unescape(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut bytes = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\\'
            && index + 2 < chars.len()
            && chars[index + 1].is_ascii_hexdigit()
            && chars[index + 2].is_ascii_hexdigit()
        {
            let hex: String = chars[index + 1..index + 3].iter().collect();
            bytes.push(u8::from_str_radix(&hex, 16).unwrap_or_default());
            index += 3;
            continue;
        }
        let mut buffer = [0u8; 4];
        bytes.extend_from_slice(chars[index].encode_utf8(&mut buffer).as_bytes());
        index += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Parses the RFC 4515 string form, e.g. `(&(objectClass=person)(|(uid=alice)(mail=*@acme.test)))`.
pub fn parse_filter(text: &str) -> Result<Filter, BerError> {
    let trimmed = js::trim(text);
    let wrapped = if trimmed.starts_with('(') {
        trimmed.to_owned()
    } else {
        format!("({trimmed})")
    };
    let chars: Vec<char> = wrapped.chars().collect();
    let mut index = 0;
    let result = parse_item(&chars, &mut index)?;
    if index != chars.len() {
        return Err(BerError::new("Trailing characters after the filter"));
    }
    Ok(result)
}

fn parse_item(text: &[char], index: &mut usize) -> Result<Filter, BerError> {
    if text.get(*index) != Some(&'(') {
        return Err(BerError::new("Expected ("));
    }
    *index += 1;
    let head = text.get(*index).copied();
    let filter = match head {
        Some(head @ ('&' | '|')) => {
            *index += 1;
            let mut filters = Vec::new();
            while text.get(*index) == Some(&'(') {
                filters.push(parse_item(text, index)?);
            }
            if head == '&' {
                Filter::And(filters)
            } else {
                Filter::Or(filters)
            }
        }
        Some('!') => {
            *index += 1;
            Filter::Not(Box::new(parse_item(text, index)?))
        }
        _ => {
            let Some(end) = (*index..text.len()).find(|&position| text[position] == ')') else {
                return Err(BerError::new("Expected )"));
            };
            let item: Vec<char> = text[*index..end].to_vec();
            *index = end;
            simple_item(&item)?
        }
    };
    if text.get(*index) != Some(&')') {
        return Err(BerError::new("Expected )"));
    }
    *index += 1;
    Ok(filter)
}

/// `/^([^=~<>:]+)(=|~=|>=|<=)(.*)$/s`.
fn simple_item(item: &[char]) -> Result<Filter, BerError> {
    let invalid = || BerError::new("Invalid filter item");
    let attribute_end = item
        .iter()
        .position(|c| matches!(c, '=' | '~' | '<' | '>' | ':'))
        .unwrap_or(item.len());
    if attribute_end == 0 {
        return Err(invalid());
    }
    let attribute: String = item[..attribute_end].iter().collect();
    let rest = &item[attribute_end..];
    let (operator, raw) = match rest {
        ['=', raw @ ..] => ("=", raw),
        ['~', '=', raw @ ..] => ("~=", raw),
        ['>', '=', raw @ ..] => (">=", raw),
        ['<', '=', raw @ ..] => ("<=", raw),
        _ => return Err(invalid()),
    };
    let raw: String = raw.iter().collect();
    if operator == "=" && raw == "*" {
        return Ok(Filter::Present { attribute });
    }
    if operator == "=" && raw.contains('*') {
        let pieces: Vec<String> = raw.split('*').map(unescape).collect();
        let initial = pieces.first().filter(|piece| !piece.is_empty()).cloned();
        let any = if pieces.len() > 2 {
            pieces[1..pieces.len() - 1]
                .iter()
                .filter(|piece| !piece.is_empty())
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        let last = pieces.last().filter(|piece| !piece.is_empty()).cloned();
        return Ok(Filter::Substrings {
            attribute,
            initial,
            any,
            last,
        });
    }
    let value = unescape(&raw);
    Ok(match operator {
        "=" => Filter::Equal { attribute, value },
        "~=" => Filter::Approx { attribute, value },
        ">=" => Filter::Greater { attribute, value },
        _ => Filter::Less { attribute, value },
    })
}

/// An entry's attributes, keyed by lowercased attribute name.
pub type EntryAttributes = IndexMap<String, Vec<String>>;

fn fold(value: &str) -> String {
    js::to_lower(&collapse_spaces(value))
}

/// Evaluates a filter (RFC 4511 three-valued logic collapsed: Undefined counts as false).
pub fn match_filter(filter: &Filter, attributes: &EntryAttributes) -> bool {
    let values = |name: &str| -> &[String] {
        attributes
            .get(&js::to_lower(name))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    };
    match filter {
        Filter::And(filters) => filters.iter().all(|item| match_filter(item, attributes)),
        Filter::Or(filters) => filters.iter().any(|item| match_filter(item, attributes)),
        Filter::Not(inner) => !match_filter(inner, attributes),
        Filter::Present { attribute } => {
            js::to_lower(attribute) == "objectclass" || !values(attribute).is_empty()
        }
        Filter::Equal { attribute, value } | Filter::Approx { attribute, value } => {
            let wanted = fold(value);
            values(attribute).iter().any(|item| fold(item) == wanted)
        }
        Filter::Greater { attribute, value } => {
            let wanted = fold(value);
            values(attribute)
                .iter()
                .any(|item| js::cmp_utf16(&fold(item), &wanted).is_ge())
        }
        Filter::Less { attribute, value } => {
            let wanted = fold(value);
            values(attribute)
                .iter()
                .any(|item| js::cmp_utf16(&fold(item), &wanted).is_le())
        }
        Filter::Substrings {
            attribute,
            initial,
            any,
            last,
        } => values(attribute).iter().any(|raw| {
            let value = fold(raw);
            let mut position = 0;
            if let Some(initial) = initial {
                let initial = fold(initial);
                if !value.starts_with(&initial) {
                    return false;
                }
                position = initial.len();
            }
            for part in any {
                let part = fold(part);
                let Some(found) = value.get(position..).and_then(|rest| rest.find(&part)) else {
                    return false;
                };
                position += found + part.len();
            }
            match last {
                None => true,
                Some(last) => {
                    let last = fold(last);
                    value.len() >= last.len() + position && value.ends_with(&last)
                }
            }
        }),
        Filter::Extensible {
            attribute,
            rule,
            value,
            ..
        } => {
            // Only the default equality rule on a named attribute is supported; other rules match nothing.
            rule.as_ref().is_none_or(String::is_empty)
                && attribute.as_ref().is_some_and(|attribute| {
                    let wanted = fold(value);
                    values(attribute).iter().any(|item| fold(item) == wanted)
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> EntryAttributes {
        let mut entry = EntryAttributes::new();
        entry.insert(
            "objectclass".into(),
            vec!["top".into(), "inetOrgPerson".into()],
        );
        entry.insert("mail".into(), vec!["alice@acme.test".into()]);
        entry.insert("cn".into(), vec!["Alice Liddell".into()]);
        entry
    }

    #[test]
    fn parses_and_matches() {
        let entry = entry();
        assert!(match_filter(
            &parse_filter("(&(objectClass=inetOrgPerson)(mail=ALICE@acme.test))").unwrap(),
            &entry
        ));
        assert!(!match_filter(
            &parse_filter("(|(cn=Bob*)(!(mail=*)))").unwrap(),
            &entry
        ));
        assert!(match_filter(&parse_filter("(cn=*Lid*)").unwrap(), &entry));
        assert!(match_filter(&parse_filter("cn=alice*ll").unwrap(), &entry));
        assert!(!match_filter(
            &parse_filter("(cn=alice*lll)").unwrap(),
            &entry
        ));
        assert!(!match_filter(&parse_filter("(title=*)").unwrap(), &entry));
        assert!(parse_filter("(cn=unbalanced").is_err());
        assert_eq!(
            parse_filter("(cn=a\\2a\\c3\\a9)").unwrap(),
            Filter::Equal {
                attribute: "cn".into(),
                value: "a*é".into()
            }
        );
    }

    #[test]
    fn ber_round_trip() {
        let filter =
            parse_filter("(&(objectClass=person)(|(uid=alice)(mail=*@acme.test))(!(cn>=b)))")
                .unwrap();
        let encoded = encode_filter(&filter);
        let item = ber::read_element(&encoded, 0, ber::DEFAULT_MAX_SIZE)
            .unwrap()
            .unwrap();
        assert_eq!(decode_filter(&item).unwrap(), filter);
    }
}
