//! Port of `packages/ldap/src/directory.ts`: the entries a gateway serves, built from the directory data the server's
//! `ldap.directory` returns.

use std::collections::HashSet;
use std::sync::LazyLock;

use better_iam_core::js;
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::dn::{DnError, escape_dn_value, normalize_dn, parse_dn};
use crate::filter::EntryAttributes;

/// A person of the directory data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryPerson {
    pub id: String,
    pub uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub attributes: Map<String, Value>,
    #[serde(default)]
    pub group_ids: Vec<String>,
}

/// A group of the directory data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryGroup {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub member_ids: Vec<String>,
}

/// A service account or agent of the directory data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryService {
    pub id: String,
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub group_ids: Vec<String>,
}

/// The directory data the server's `ldap.directory` returns (see the server's `LdapDirectory`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryData {
    pub tenant_id: String,
    pub tenant_name: String,
    pub base_dn: String,
    /// `full` or `self`.
    pub scope: String,
    pub people: Vec<DirectoryPerson>,
    pub groups: Vec<DirectoryGroup>,
    pub services: Vec<DirectoryService>,
}

/// An attribute list in output order.
pub type AttributeList = Vec<(String, Vec<String>)>;

/// One entry of the tree: its DN, the normalized DN, and attributes (user and operational, in output order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub dn: String,
    pub normalized_dn: String,
    pub attributes: AttributeList,
    pub operational: AttributeList,
    /// Lowercased attribute names → values, for filters (user and operational attributes).
    pub index: EntryAttributes,
}

const STANDARD: [&str; 15] = [
    "objectclass",
    "uid",
    "cn",
    "sn",
    "givenname",
    "displayname",
    "mail",
    "memberof",
    "member",
    "ou",
    "o",
    "dc",
    "description",
    "entryuuid",
    "entrydn",
];

static EXTRA_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z][a-zA-Z0-9-]{0,63}$").unwrap());

fn entry(
    dn: &str,
    attributes: AttributeList,
    operational: AttributeList,
) -> Result<DirectoryEntry, DnError> {
    let kept: AttributeList = attributes
        .into_iter()
        .filter(|(_, values)| !values.is_empty())
        .collect();
    let mut extra = operational;
    extra.push(("entryDN".into(), vec![dn.to_owned()]));
    let mut index = EntryAttributes::new();
    for (name, values) in kept.iter().chain(extra.iter()) {
        index.insert(js::to_lower(name), values.clone());
    }
    Ok(DirectoryEntry {
        dn: dn.to_owned(),
        normalized_dn: normalize_dn(dn)?,
        attributes: kept,
        operational: extra,
        index,
    })
}

fn words(name: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in js::trim(name.unwrap_or_default()).chars() {
        if js::is_js_whitespace(c) {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => js::stringify(other),
    }
}

fn pair(name: &str, values: Vec<String>) -> (String, Vec<String>) {
    (name.to_owned(), values)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// Names can collide (two service accounts called "ci"): the first keeps its name, later ones are named by their ID.
fn named<'a>(
    items: impl Iterator<Item = (&'a str, &'a str)>,
    ou: &str,
    base: &str,
) -> IndexMap<String, String> {
    let mut taken = HashSet::new();
    let mut out = IndexMap::new();
    for (id, name) in items {
        let rdn = if taken.contains(&js::to_lower(name)) {
            id
        } else {
            name
        };
        taken.insert(js::to_lower(rdn));
        out.insert(
            id.to_owned(),
            format!("cn={},ou={ou},{base}", escape_dn_value(rdn)),
        );
    }
    out
}

/// The tree under the tenant's base DN: the base entry, `ou=people` (inetOrgPerson entries named `uid={uid}`),
/// `ou=groups` (groupOfNames named `cn={name}`, with `member` DNs) and `ou=services` (service accounts and agents,
/// named `cn={name}`). People and services carry `memberOf`; `entryUUID` is the Better IAM identity or group ID.
pub fn build_entries(data: &DirectoryData) -> Result<Vec<DirectoryEntry>, DnError> {
    let base = data.base_dn.as_str();
    let parsed = parse_dn(base)?;
    let naming = parsed.first().and_then(|top| top.first()).cloned();
    let naming_type = naming.as_ref().map(|naming| js::to_lower(&naming.kind));
    let base_classes = match naming_type.as_deref() {
        Some("dc") => strings(&["top", "dcObject", "organization"]),
        Some("ou") => strings(&["top", "organizationalUnit"]),
        _ => strings(&["top", "organization"]),
    };
    let mut base_attributes = vec![pair("objectClass", base_classes)];
    if let Some(naming) = &naming {
        base_attributes.push(pair(&naming.kind, vec![naming.value.clone()]));
    }
    if naming_type.as_deref() != Some("o") {
        base_attributes.push(pair("o", vec![data.tenant_name.clone()]));
    }
    let mut entries = vec![entry(base, base_attributes, Vec::new())?];
    let container = |ou: &str| {
        entry(
            &format!("ou={ou},{base}"),
            vec![
                pair("objectClass", strings(&["top", "organizationalUnit"])),
                pair("ou", vec![ou.to_owned()]),
            ],
            Vec::new(),
        )
    };
    entries.push(container("people")?);
    entries.push(container("groups")?);
    if !data.services.is_empty() || data.scope == "full" {
        entries.push(container("services")?);
    }
    let person_dn: IndexMap<String, String> = data
        .people
        .iter()
        .map(|person| {
            (
                person.id.clone(),
                format!("uid={},ou=people,{base}", escape_dn_value(&person.uid)),
            )
        })
        .collect();
    let service_dn = named(
        data.services
            .iter()
            .map(|item| (item.id.as_str(), item.name.as_str())),
        "services",
        base,
    );
    let group_dn = named(
        data.groups
            .iter()
            .map(|item| (item.id.as_str(), item.name.as_str())),
        "groups",
        base,
    );
    let member_of = |group_ids: &[String]| -> Vec<String> {
        group_ids
            .iter()
            .filter_map(|group_id| group_dn.get(group_id).cloned())
            .collect()
    };
    for person in &data.people {
        let parts = words(person.name.as_deref());
        let mut extra: AttributeList = Vec::new();
        for (name, value) in &person.attributes {
            if EXTRA_NAME.is_match(name)
                && !STANDARD.contains(&js::to_lower(name).as_str())
                && !value.is_null()
            {
                let values = match value {
                    Value::Array(items) => items.iter().map(text).collect(),
                    other => vec![text(other)],
                };
                extra.push((name.clone(), values));
            }
        }
        let mut attributes = vec![
            pair(
                "objectClass",
                strings(&["top", "person", "organizationalPerson", "inetOrgPerson"]),
            ),
            pair("uid", vec![person.uid.clone()]),
            pair(
                "cn",
                vec![
                    person
                        .name
                        .clone()
                        .or_else(|| person.email.clone())
                        .unwrap_or_else(|| person.uid.clone()),
                ],
            ),
            pair(
                "sn",
                vec![parts.last().cloned().unwrap_or_else(|| person.uid.clone())],
            ),
            pair(
                "givenName",
                if parts.len() > 1 {
                    vec![parts[0].clone()]
                } else {
                    Vec::new()
                },
            ),
            pair(
                "displayName",
                person
                    .name
                    .iter()
                    .filter(|name| !name.is_empty())
                    .cloned()
                    .collect(),
            ),
            pair(
                "mail",
                person
                    .email
                    .iter()
                    .filter(|email| !email.is_empty())
                    .cloned()
                    .collect(),
            ),
            pair("memberOf", member_of(&person.group_ids)),
        ];
        attributes.extend(extra);
        entries.push(entry(
            &person_dn[&person.id],
            attributes,
            vec![pair("entryUUID", vec![person.id.clone()])],
        )?);
    }
    for service in &data.services {
        let dn = &service_dn[&service.id];
        let uid = parse_dn(dn)?
            .first()
            .and_then(|rdn| rdn.first())
            .map(|part| part.value.clone())
            .unwrap_or_default();
        entries.push(entry(
            dn,
            vec![
                pair(
                    "objectClass",
                    strings(&["top", "account", "applicationProcess"]),
                ),
                pair("cn", vec![service.name.clone()]),
                pair("uid", vec![uid]),
                pair(
                    "description",
                    vec![
                        if service.kind == "agent" {
                            "AI agent"
                        } else {
                            "Service account"
                        }
                        .to_owned(),
                    ],
                ),
                pair("memberOf", member_of(&service.group_ids)),
            ],
            vec![pair("entryUUID", vec![service.id.clone()])],
        )?);
    }
    for group in &data.groups {
        entries.push(entry(
            &group_dn[&group.id],
            vec![
                pair("objectClass", strings(&["top", "groupOfNames"])),
                pair("cn", vec![group.name.clone()]),
                pair(
                    "description",
                    group
                        .description
                        .iter()
                        .filter(|text| !text.is_empty())
                        .cloned()
                        .collect(),
                ),
                pair(
                    "member",
                    group
                        .member_ids
                        .iter()
                        .filter_map(|member_id| {
                            person_dn
                                .get(member_id)
                                .or_else(|| service_dn.get(member_id))
                                .cloned()
                        })
                        .collect(),
                ),
            ],
            vec![pair("entryUUID", vec![group.id.clone()])],
        )?);
    }
    Ok(entries)
}

/// The attributes a search returns for an entry: all user attributes for none or `*`, operational ones for `+` or by
/// name, only the named ones otherwise, nothing for `1.1`.
pub fn select_attributes(target: &DirectoryEntry, requested: &[String]) -> AttributeList {
    let wanted: Vec<String> = requested.iter().map(|name| js::to_lower(name)).collect();
    if wanted.len() == 1 && wanted[0] == "1.1" {
        return Vec::new();
    }
    let all = wanted.is_empty() || wanted.iter().any(|name| name == "*");
    let operational = wanted.iter().any(|name| name == "+");
    target
        .attributes
        .iter()
        .filter(|(name, _)| all || wanted.contains(&js::to_lower(name)))
        .chain(
            target
                .operational
                .iter()
                .filter(|(name, _)| operational || wanted.contains(&js::to_lower(name))),
        )
        .cloned()
        .collect()
}
