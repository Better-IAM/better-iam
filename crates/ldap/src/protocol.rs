//! Port of `packages/ldap/src/protocol.ts`: LDAPv3 messages (RFC 4511) as the gateway reads and writes them, plus
//! client-side encoders and a response decoder for tests and programs that talk to an LDAP server.

use indexmap::IndexMap;

use crate::ber::{self, BerElement, BerError, tag};
use crate::filter::{Filter, decode_filter, encode_filter};

/// `ResultCode`.
pub mod result_code {
    pub const SUCCESS: i64 = 0;
    pub const OPERATIONS_ERROR: i64 = 1;
    pub const PROTOCOL_ERROR: i64 = 2;
    pub const TIME_LIMIT_EXCEEDED: i64 = 3;
    pub const SIZE_LIMIT_EXCEEDED: i64 = 4;
    pub const COMPARE_FALSE: i64 = 5;
    pub const COMPARE_TRUE: i64 = 6;
    pub const AUTH_METHOD_NOT_SUPPORTED: i64 = 7;
    pub const NO_SUCH_ATTRIBUTE: i64 = 16;
    pub const NO_SUCH_OBJECT: i64 = 32;
    pub const INVALID_DN_SYNTAX: i64 = 34;
    pub const INAPPROPRIATE_AUTHENTICATION: i64 = 48;
    pub const INVALID_CREDENTIALS: i64 = 49;
    pub const INSUFFICIENT_ACCESS_RIGHTS: i64 = 50;
    pub const BUSY: i64 = 51;
    pub const UNAVAILABLE: i64 = 52;
    pub const UNWILLING_TO_PERFORM: i64 = 53;
    pub const CONFIDENTIALITY_REQUIRED: i64 = 13;
    pub const OTHER: i64 = 80;
}

/// `OID`.
pub mod oid {
    pub const WHO_AM_I: &str = "1.3.6.1.4.1.4203.1.11.3";
    pub const START_TLS: &str = "1.3.6.1.4.1.1466.20037";
    pub const NOTICE_OF_DISCONNECTION: &str = "1.3.6.1.4.1.1466.20036";
    pub const PAGED_RESULTS: &str = "1.2.840.113556.1.4.319";
}

/// `SearchScope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    Base,
    One,
    Sub,
}

const SCOPES: [SearchScope; 3] = [SearchScope::Base, SearchScope::One, SearchScope::Sub];

impl SearchScope {
    fn index(self) -> i64 {
        match self {
            SearchScope::Base => 0,
            SearchScope::One => 1,
            SearchScope::Sub => 2,
        }
    }
}

/// `LdapRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapRequest {
    Bind {
        version: i64,
        name: String,
        password: Option<Vec<u8>>,
        sasl: Option<String>,
    },
    Unbind,
    Search {
        base: String,
        scope: SearchScope,
        size_limit: i64,
        time_limit: i64,
        types_only: bool,
        filter: Filter,
        attributes: Vec<String>,
    },
    Compare {
        entry: String,
        attribute: String,
        value: String,
    },
    Extended {
        name: String,
        value: Option<Vec<u8>>,
    },
    Abandon {
        id: i64,
    },
    /// A write or other operation the gateway refuses; `response_tag` is the tag its answer needs.
    Unsupported {
        name: String,
        response_tag: u8,
    },
}

/// `LdapControl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapControl {
    pub kind: String,
    pub critical: bool,
    pub value: Option<Vec<u8>>,
}

/// `LdapMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapMessage {
    pub id: i64,
    pub request: LdapRequest,
    pub controls: Vec<LdapControl>,
}

fn unsupported(op: u8) -> Option<(&'static str, u8)> {
    match op {
        0x66 => Some(("modify", 0x67)),
        0x68 => Some(("add", 0x69)),
        0x4a => Some(("delete", 0x6b)),
        0x6c => Some(("modifyDN", 0x6d)),
        _ => None,
    }
}

fn read_controls(element: Option<&BerElement<'_>>) -> Result<Vec<LdapControl>, BerError> {
    let mut controls = Vec::new();
    if let Some(element) = element.filter(|element| element.tag == 0xa0) {
        for control in ber::children(element.value)? {
            let parts = ber::children(control.value)?;
            let (kind, second, third) = (parts.first(), parts.get(1), parts.get(2));
            let critical = match second {
                Some(second) if second.tag == tag::BOOLEAN => {
                    ber::read_boolean(Some(second), tag::BOOLEAN)?
                }
                _ => false,
            };
            let value_item = if second.is_some_and(|second| second.tag == tag::OCTET_STRING) {
                second
            } else {
                third
            };
            controls.push(LdapControl {
                kind: ber::read_string(kind, tag::OCTET_STRING)?,
                critical,
                value: value_item
                    .filter(|item| item.tag == tag::OCTET_STRING)
                    .map(|item| item.value.to_vec()),
            });
        }
    }
    Ok(controls)
}

/// Decodes one LDAPMessage element.
pub fn decode_message(message: &BerElement<'_>) -> Result<LdapMessage, BerError> {
    if message.tag != tag::SEQUENCE {
        return Err(BerError::new("Expected an LDAPMessage"));
    }
    let parts = ber::children(message.value)?;
    let id = ber::read_integer(parts.first(), tag::INTEGER)?;
    if !(0..=2147483647).contains(&id) {
        return Err(BerError::new("Invalid message ID"));
    }
    let Some(op) = parts.get(1) else {
        return Err(BerError::new("Missing protocol operation"));
    };
    let controls = read_controls(parts.get(2))?;
    Ok(LdapMessage {
        id,
        request: decode_request(op)?,
        controls,
    })
}

fn decode_request(op: &BerElement<'_>) -> Result<LdapRequest, BerError> {
    const OS: u8 = tag::OCTET_STRING;
    match op.tag {
        0x60 => {
            let parts = ber::children(op.value)?;
            let Some(auth) = parts.get(2) else {
                return Err(BerError::new("Missing authentication"));
            };
            if auth.tag == 0x80 {
                return Ok(LdapRequest::Bind {
                    version: ber::read_integer(parts.first(), tag::INTEGER)?,
                    name: ber::read_string(parts.get(1), OS)?,
                    password: Some(auth.value.to_vec()),
                    sasl: None,
                });
            }
            if auth.tag == 0xa3 {
                let inner = ber::children(auth.value)?;
                return Ok(LdapRequest::Bind {
                    version: ber::read_integer(parts.first(), tag::INTEGER)?,
                    name: ber::read_string(parts.get(1), OS)?,
                    password: None,
                    sasl: Some(ber::read_string(inner.first(), OS)?),
                });
            }
            Err(BerError::new("Unknown authentication choice"))
        }
        0x42 => Ok(LdapRequest::Unbind),
        0x63 => {
            let parts = ber::children(op.value)?;
            let scope_value = ber::read_integer(parts.get(1), tag::ENUMERATED)?;
            let Some(scope) = usize::try_from(scope_value)
                .ok()
                .and_then(|index| SCOPES.get(index))
            else {
                return Err(BerError::new("Invalid search scope"));
            };
            let Some(filter) = parts.get(6) else {
                return Err(BerError::new("Missing filter"));
            };
            let base = ber::read_string(parts.first(), OS)?;
            let size_limit = ber::read_integer(parts.get(3), tag::INTEGER)?;
            let time_limit = ber::read_integer(parts.get(4), tag::INTEGER)?;
            let types_only = ber::read_boolean(parts.get(5), tag::BOOLEAN)?;
            let filter = decode_filter(filter)?;
            let attributes = match parts.get(7) {
                Some(attributes) => ber::children(attributes.value)?
                    .iter()
                    .map(|item| ber::read_string(Some(item), OS))
                    .collect::<Result<Vec<_>, _>>()?,
                None => Vec::new(),
            };
            Ok(LdapRequest::Search {
                base,
                scope: *scope,
                size_limit,
                time_limit,
                types_only,
                filter,
                attributes,
            })
        }
        0x6e => {
            let parts = ber::children(op.value)?;
            let Some(assertion) = parts.get(1) else {
                return Err(BerError::new("Expected an octet string"));
            };
            let inner = ber::children(assertion.value)?;
            Ok(LdapRequest::Compare {
                entry: ber::read_string(parts.first(), OS)?,
                attribute: ber::read_string(inner.first(), OS)?,
                value: ber::read_string(inner.get(1), OS)?,
            })
        }
        0x77 => {
            let parts = ber::children(op.value)?;
            let name = parts.iter().find(|part| part.tag == 0x80);
            let value = parts.iter().find(|part| part.tag == 0x81);
            let Some(name) = name else {
                return Err(BerError::new("Missing extended request name"));
            };
            Ok(LdapRequest::Extended {
                name: String::from_utf8_lossy(name.value).into_owned(),
                value: value.map(|value| value.value.to_vec()),
            })
        }
        0x50 => {
            let as_integer = BerElement {
                tag: tag::INTEGER,
                ..*op
            };
            Ok(LdapRequest::Abandon {
                id: ber::read_integer(Some(&as_integer), tag::INTEGER)?,
            })
        }
        other => match unsupported(other) {
            Some((name, response_tag)) => Ok(LdapRequest::Unsupported {
                name: name.into(),
                response_tag,
            }),
            None => Err(BerError::new(format!(
                "Unknown protocol operation 0x{other:x}"
            ))),
        },
    }
}

fn envelope(id: i64, op: Vec<u8>, controls: Option<Vec<u8>>) -> Vec<u8> {
    let mut items = vec![ber::integer(id, tag::INTEGER), op];
    if let Some(controls) = controls {
        items.push(controls);
    }
    ber::sequence(&items, tag::SEQUENCE)
}

fn result(
    tag_byte: u8,
    code: i64,
    matched_dn: &str,
    message: &str,
    extra: Vec<Vec<u8>>,
) -> Vec<u8> {
    let mut items = vec![
        ber::enumerated(code),
        ber::text(matched_dn, tag::OCTET_STRING),
        ber::text(message, tag::OCTET_STRING),
    ];
    items.extend(extra);
    ber::sequence(&items, tag_byte)
}

/// A BindResponse.
pub fn bind_response(id: i64, code: i64, message: &str) -> Vec<u8> {
    envelope(id, result(0x61, code, "", message, Vec::new()), None)
}

/// A SearchResultDone, with response controls.
pub fn search_done(
    id: i64,
    code: i64,
    message: &str,
    matched_dn: &str,
    controls: Option<Vec<u8>>,
) -> Vec<u8> {
    envelope(
        id,
        result(0x65, code, matched_dn, message, Vec::new()),
        controls,
    )
}

/// A CompareResponse.
pub fn compare_response(id: i64, code: i64, message: &str) -> Vec<u8> {
    envelope(id, result(0x6f, code, "", message, Vec::new()), None)
}

/// A result with another response tag (the answer to a refused write).
pub fn generic_response(id: i64, tag_byte: u8, code: i64, message: &str) -> Vec<u8> {
    envelope(id, result(tag_byte, code, "", message, Vec::new()), None)
}

/// An ExtendedResponse with an optional response name and value.
pub fn extended_response(
    id: i64,
    code: i64,
    message: &str,
    name: Option<&str>,
    value: Option<&[u8]>,
) -> Vec<u8> {
    let mut extra = Vec::new();
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        extra.push(ber::text(name, 0x8a));
    }
    if let Some(value) = value {
        extra.push(ber::octets(value, 0x8b));
    }
    envelope(id, result(0x78, code, "", message, extra), None)
}

/// The unsolicited notice sent before the server closes a connection (message ID 0).
pub fn notice_of_disconnection(code: i64, message: &str) -> Vec<u8> {
    extended_response(0, code, message, Some(oid::NOTICE_OF_DISCONNECTION), None)
}

/// One SearchResultEntry: attribute order kept, values as given (or types only).
pub fn search_entry(
    id: i64,
    dn: &str,
    attributes: &[(String, Vec<String>)],
    types_only: bool,
) -> Vec<u8> {
    let attributes: Vec<Vec<u8>> = attributes
        .iter()
        .map(|(name, values)| {
            let values: Vec<Vec<u8>> = if types_only {
                Vec::new()
            } else {
                values
                    .iter()
                    .map(|value| ber::text(value, tag::OCTET_STRING))
                    .collect()
            };
            ber::sequence(
                &[
                    ber::text(name, tag::OCTET_STRING),
                    ber::set(&values, tag::SET),
                ],
                tag::SEQUENCE,
            )
        })
        .collect();
    envelope(
        id,
        ber::sequence(
            &[
                ber::text(dn, tag::OCTET_STRING),
                ber::sequence(&attributes, tag::SEQUENCE),
            ],
            0x64,
        ),
        None,
    )
}

fn paged_value(size: i64, cookie: &[u8]) -> Vec<u8> {
    ber::sequence(
        &[ber::sequence(
            &[
                ber::text(oid::PAGED_RESULTS, tag::OCTET_STRING),
                ber::octets(
                    &ber::sequence(
                        &[
                            ber::integer(size, tag::INTEGER),
                            ber::octets(cookie, tag::OCTET_STRING),
                        ],
                        tag::SEQUENCE,
                    ),
                    tag::OCTET_STRING,
                ),
            ],
            tag::SEQUENCE,
        )],
        0xa0,
    )
}

/// The paged-results response control (RFC 2696): estimated size and the cookie for the next page.
pub fn paged_results_control(size: i64, cookie: &[u8]) -> Vec<u8> {
    paged_value(size, cookie)
}

/// A paged-results request control value: page size and cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagedResults {
    pub size: i64,
    pub cookie: Vec<u8>,
}

/// Reads a paged-results request control value: page size and cookie.
pub fn read_paged_results(value: Option<&[u8]>) -> Result<Option<PagedResults>, BerError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let outer = ber::children(value)?;
    let Some(outer) = outer.first() else {
        return Ok(None);
    };
    let parts = ber::children(outer.value)?;
    Ok(Some(PagedResults {
        size: ber::read_integer(parts.first(), tag::INTEGER)?,
        cookie: ber::read_octets(parts.get(1), tag::OCTET_STRING)?.to_vec(),
    }))
}

// Client-side encoders, for tests and for programs that talk to an LDAP server.

/// A simple BindRequest (LDAPv3).
pub fn encode_bind(id: i64, name: &str, password: &str) -> Vec<u8> {
    envelope(
        id,
        ber::sequence(
            &[
                ber::integer(3, tag::INTEGER),
                ber::text(name, tag::OCTET_STRING),
                ber::text(password, 0x80),
            ],
            0x60,
        ),
        None,
    )
}

/// An UnbindRequest.
pub fn encode_unbind(id: i64) -> Vec<u8> {
    envelope(id, vec![0x42, 0x00], None)
}

/// A SearchRequest.
#[derive(Debug, Clone)]
pub struct SearchOptions {
    pub base: String,
    pub scope: Option<SearchScope>,
    pub filter: Filter,
    pub attributes: Vec<String>,
    pub size_limit: Option<i64>,
    pub types_only: bool,
}

/// `encodeSearch(id, search, controls?)`.
pub fn encode_search(id: i64, search: &SearchOptions, controls: Option<Vec<u8>>) -> Vec<u8> {
    let attributes: Vec<Vec<u8>> = search
        .attributes
        .iter()
        .map(|name| ber::text(name, tag::OCTET_STRING))
        .collect();
    envelope(
        id,
        ber::sequence(
            &[
                ber::text(&search.base, tag::OCTET_STRING),
                ber::enumerated(search.scope.unwrap_or(SearchScope::Sub).index()),
                ber::enumerated(0),
                ber::integer(search.size_limit.unwrap_or(0), tag::INTEGER),
                ber::integer(0, tag::INTEGER),
                vec![tag::BOOLEAN, 1, if search.types_only { 0xff } else { 0 }],
                encode_filter(&search.filter),
                ber::sequence(&attributes, tag::SEQUENCE),
            ],
            0x63,
        ),
        controls,
    )
}

/// An ExtendedRequest.
pub fn encode_extended(id: i64, name: &str, value: Option<&[u8]>) -> Vec<u8> {
    let mut items = vec![ber::text(name, 0x80)];
    if let Some(value) = value {
        items.push(ber::octets(value, 0x81));
    }
    envelope(id, ber::sequence(&items, 0x77), None)
}

/// A CompareRequest.
pub fn encode_compare(id: i64, entry: &str, attribute: &str, value: &str) -> Vec<u8> {
    envelope(
        id,
        ber::sequence(
            &[
                ber::text(entry, tag::OCTET_STRING),
                ber::sequence(
                    &[
                        ber::text(attribute, tag::OCTET_STRING),
                        ber::text(value, tag::OCTET_STRING),
                    ],
                    tag::SEQUENCE,
                ),
            ],
            0x6e,
        ),
        None,
    )
}

/// The paged-results request control (RFC 2696).
pub fn paged_results_request(size: i64, cookie: &[u8]) -> Vec<u8> {
    paged_value(size, cookie)
}

/// A decoded server answer (client side).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LdapResponse {
    pub id: i64,
    pub tag: u8,
    pub code: Option<i64>,
    pub message: Option<String>,
    pub dn: Option<String>,
    pub attributes: Option<IndexMap<String, Vec<String>>>,
    pub response_name: Option<String>,
    pub response_value: Option<Vec<u8>>,
    pub controls: Option<Vec<LdapControl>>,
}

/// `decodeResponse(message)`.
pub fn decode_response(message: &BerElement<'_>) -> Result<LdapResponse, BerError> {
    let parts = ber::children(message.value)?;
    let id = ber::read_integer(parts.first(), tag::INTEGER)?;
    let Some(op) = parts.get(1) else {
        return Err(BerError::new("Missing protocol operation"));
    };
    let mut response = LdapResponse {
        id,
        tag: op.tag,
        ..LdapResponse::default()
    };
    let inner = ber::children(op.value)?;
    if op.tag == 0x64 {
        response.dn = Some(ber::read_string(inner.first(), tag::OCTET_STRING)?);
        let mut attributes = IndexMap::new();
        let Some(list) = inner.get(1) else {
            return Err(BerError::new("Missing attributes"));
        };
        for attribute in ber::children(list.value)? {
            let pair = ber::children(attribute.value)?;
            let name = ber::read_string(pair.first(), tag::OCTET_STRING)?;
            let Some(values) = pair.get(1) else {
                return Err(BerError::new("Missing attribute values"));
            };
            let values = ber::children(values.value)?
                .iter()
                .map(|value| String::from_utf8_lossy(value.value).into_owned())
                .collect();
            attributes.insert(name, values);
        }
        response.attributes = Some(attributes);
    } else {
        response.code = Some(ber::read_integer(inner.first(), tag::ENUMERATED)?);
        response.message = Some(ber::read_string(inner.get(2), tag::OCTET_STRING)?);
        if let Some(name) = inner.iter().find(|part| part.tag == 0x8a) {
            response.response_name = Some(String::from_utf8_lossy(name.value).into_owned());
        }
        if let Some(value) = inner.iter().find(|part| part.tag == 0x8b) {
            response.response_value = Some(value.value.to_vec());
        }
    }
    if parts.get(2).is_some_and(|element| element.tag == 0xa0) {
        response.controls = Some(read_controls(parts.get(2))?);
    }
    Ok(response)
}
