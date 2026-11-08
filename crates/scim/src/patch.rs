//! Port of `packages/scim/src/patch.ts`: RFC 7644 §3.5.2 PatchOp application.

use better_iam_core::{IamError, IamResult, js as core_js};
use serde_json::Value;

use crate::filter::{FilterNode, attribute_path, evaluate_filter, parse_filter_expression};
use crate::types::{ENTERPRISE_SCHEMA, ObjectValue, ResourceType};

/// Canonical casing for every attribute PATCH may address; SCIM attribute names are case-insensitive.
const CANONICAL: [&str; 26] = [
    "userName",
    "displayName",
    "externalId",
    "active",
    "emails",
    "name",
    "title",
    "members",
    "formatted",
    "familyName",
    "givenName",
    "middleName",
    "honorificPrefix",
    "honorificSuffix",
    "value",
    "type",
    "primary",
    "display",
    "$ref",
    "employeeNumber",
    "costCenter",
    "organization",
    "division",
    "department",
    "manager",
    ENTERPRISE_SCHEMA,
];

fn canonical_name(segment: &str) -> Option<&'static str> {
    CANONICAL
        .iter()
        .find(|name| name.to_lowercase() == segment)
        .copied()
}

fn top_level(kind: ResourceType) -> &'static [&'static str] {
    match kind {
        ResourceType::Users => &[
            "userName",
            "displayName",
            "externalId",
            "active",
            "emails",
            "name",
            "title",
            ENTERPRISE_SCHEMA,
        ],
        ResourceType::Groups => &["displayName", "externalId", "members"],
    }
}

fn required(kind: ResourceType) -> &'static [&'static str] {
    match kind {
        ResourceType::Users => &["userName", "active"],
        ResourceType::Groups => &["displayName"],
    }
}

const BOOLEAN: [&str; 2] = ["active", "primary"];

/// A parsed PATCH path: `attrPath [ "[" valFilter "]" ] [ "." subAttr ]`.
#[derive(Debug, Clone, PartialEq)]
pub struct PatchPath {
    pub keys: Vec<String>,
    pub filter: Option<FilterNode>,
    pub sub: Option<String>,
}

fn invalid_path(message: impl Into<String>) -> IamError {
    IamError::new("invalidPath", message)
}

fn canonical(segments: &[String], kind: ResourceType) -> IamResult<Vec<String>> {
    let keys = segments
        .iter()
        .map(|segment| {
            canonical_name(segment)
                .map(str::to_owned)
                .ok_or_else(|| invalid_path(format!("Unsupported PATCH attribute \"{segment}\".")))
        })
        .collect::<IamResult<Vec<_>>>()?;
    let first = keys.first().cloned().unwrap_or_default();
    if !top_level(kind).contains(&first.as_str()) {
        return Err(invalid_path(format!(
            "\"{first}\" is not a mutable {} attribute.",
            kind.as_str()
        )));
    }
    Ok(keys)
}

fn valid_rest(rest: &str) -> bool {
    // /^\.[A-Za-z$][\w$-]*$/
    let mut chars = rest.chars();
    if chars.next() != Some('.') {
        return false;
    }
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '-'))
}

/// `parsePatchPath(path, type)`: `attrPath [ "[" valFilter "]" ] [ "." subAttr ]`, with schema-qualified names
/// (RFC 7644 §3.5.2).
pub fn parse_patch_path(path: &str, kind: ResourceType) -> IamResult<PatchPath> {
    let segments = |raw: &str| {
        attribute_path(raw).map_err(|_| invalid_path(format!("Invalid PATCH path \"{path}\".")))
    };
    let Some(open) = path.find('[') else {
        return Ok(PatchPath {
            keys: canonical(&segments(path)?, kind)?,
            filter: None,
            sub: None,
        });
    };
    let close = path.rfind(']');
    let Some(close) = close.filter(|close| *close >= open) else {
        return Err(invalid_path(format!("Invalid PATCH path \"{path}\".")));
    };
    let rest = &path[close + 1..];
    if !rest.is_empty() && !valid_rest(rest) {
        return Err(invalid_path(format!("Invalid PATCH path \"{path}\".")));
    }
    let keys = canonical(&segments(&path[..open])?, kind)?;
    if keys.len() != 1 || !["emails", "members"].contains(&keys[0].as_str()) {
        return Err(invalid_path(
            "Value filters apply only to multi-valued attributes.",
        ));
    }
    let filter = parse_filter_expression(&path[open + 1..close])?;
    let sub = if rest.is_empty() {
        None
    } else {
        let names = canonical(&[keys[0].to_lowercase(), rest[1..].to_lowercase()], kind)?;
        Some(names[1].clone())
    };
    Ok(PatchPath {
        keys,
        filter: Some(filter),
        sub,
    })
}

/// Entra ID sends booleans as "True"/"False" strings; accept exactly those spellings for boolean attributes.
fn coerce(key: &str, value: Option<&Value>) -> Option<Value> {
    match value {
        Some(Value::String(text))
            if BOOLEAN.contains(&key)
                && (text.eq_ignore_ascii_case("true") || text.eq_ignore_ascii_case("false")) =>
        {
            Some(Value::Bool(text.eq_ignore_ascii_case("true")))
        }
        other => other.cloned(),
    }
}

/// The attributes a simple `sub eq "x"` (optionally and-ed) filter pins, used to seed an added multi-valued entry.
fn seed(filter: &FilterNode) -> Option<ObjectValue> {
    match filter {
        FilterNode::Compare { path, op, value } if op == "eq" && path.len() == 1 => {
            let key = canonical_name(&path[0])?;
            let mut map = ObjectValue::new();
            if let Some(value) = value {
                map.insert(key.to_owned(), value.clone());
            }
            Some(map)
        }
        FilterNode::And(left, right) => {
            let mut left = seed(left)?;
            let right = seed(right)?;
            for (key, value) in right {
                left.insert(key, value);
            }
            Some(left)
        }
        _ => None,
    }
}

/// What an `undefined` member becomes where TypeScript assigns one (an operation without `value`). Top-level members
/// and members the later validation skips when undefined are left out; members it would reject (a sub-attribute no
/// schema allows there, or any `name` sub-attribute, which must be a string) become null, which the validation rejects
/// with the same error.
fn undefined_member(container: &[&str], leaf: &str) -> Option<Value> {
    let allowed: &[&str] = match container {
        [] => return None,
        ["name"] => return Some(Value::Null),
        ["emails"] => &["value", "type", "primary", "display"],
        ["members"] => &["value", "$ref", "display", "type"],
        [ENTERPRISE_SCHEMA] => &[
            "employeeNumber",
            "costCenter",
            "organization",
            "division",
            "department",
            "manager",
        ],
        [ENTERPRISE_SCHEMA, "manager"] => &["value", "displayName", "$ref"],
        _ => return None,
    };
    if allowed.contains(&leaf) {
        None
    } else {
        Some(Value::Null)
    }
}

/// `object[key] = value`, where a None `value` is TypeScript's `undefined` (see [`undefined_member`]).
fn assign(object: &mut ObjectValue, container: &[&str], key: &str, value: Option<Value>) {
    match value.or_else(|| undefined_member(container, key)) {
        Some(value) => {
            object.insert(key.to_owned(), value);
        }
        None => {
            object.shift_remove(key);
        }
    }
}

fn is_object(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Object(_)))
}

fn apply_filtered(
    document: &mut ObjectValue,
    operation: &str,
    path: &PatchPath,
    value: Option<&Value>,
) -> IamResult<()> {
    let key = path.keys[0].clone();
    let filter = path.filter.as_ref().expect("a filtered path has a filter");
    let mut items: Vec<Value> = match document.get(&key) {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    let prefix = [key.to_lowercase()];
    let matched: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| evaluate_filter(filter, item, &prefix))
        .map(|(index, _)| index)
        .collect();
    if operation == "remove" {
        match &path.sub {
            None => {
                let kept: Vec<Value> = items
                    .into_iter()
                    .enumerate()
                    .filter(|(index, _)| !matched.contains(index))
                    .map(|(_, item)| item)
                    .collect();
                document.insert(key, Value::Array(kept));
            }
            Some(sub) => {
                if matched.is_empty() {
                    return Ok(());
                }
                for index in &matched {
                    if let Value::Object(item) = &mut items[*index] {
                        item.shift_remove(sub);
                    }
                }
                document.insert(key, Value::Array(items));
            }
        }
        return Ok(());
    }
    if matched.is_empty() {
        let initial = seed(filter);
        let initial = match initial {
            Some(initial) if operation != "replace" => initial,
            _ => {
                return Err(IamError::new(
                    "noTarget",
                    "The value filter matched no values.",
                ));
            }
        };
        let mut entry = initial;
        match &path.sub {
            Some(sub) => assign(&mut entry, &[key.as_str()], sub, coerce(sub, value)),
            None => {
                if let Some(Value::Object(value)) = value {
                    for (name, item) in value {
                        entry.insert(name.clone(), item.clone());
                    }
                }
            }
        }
        items.push(Value::Object(entry));
        document.insert(key, Value::Array(items));
        return Ok(());
    }
    for index in matched {
        let Value::Object(item) = &mut items[index] else {
            continue;
        };
        match &path.sub {
            Some(sub) => assign(item, &[key.as_str()], sub, coerce(sub, value)),
            None => {
                let Some(Value::Object(value)) = value else {
                    return Err(IamError::new("invalidValue", "Expected an object value."));
                };
                if operation == "replace" {
                    item.clear();
                }
                for (name, member) in value {
                    item.insert(name.clone(), member.clone());
                }
            }
        }
    }
    document.insert(key, Value::Array(items));
    Ok(())
}

fn apply_at(
    document: &mut ObjectValue,
    kind: ResourceType,
    operation: &str,
    keys: &[String],
    input: Option<&Value>,
) -> IamResult<()> {
    let (leaf, parents) = keys.split_last().expect("a PATCH path has a key");
    let value = coerce(leaf, input);
    let mut parent = document;
    let mut container: Vec<&str> = Vec::new();
    for key in parents {
        let child = parent.get(key.as_str());
        if matches!(child, Some(Value::Array(_))) {
            return Err(invalid_path(format!(
                "Use a value filter to modify one value of {key}."
            )));
        }
        if !is_object(child) {
            if operation == "remove" {
                return Ok(());
            }
            parent.insert(key.clone(), Value::Object(ObjectValue::new()));
        }
        parent = match parent.get_mut(key.as_str()) {
            Some(Value::Object(map)) => map,
            _ => unreachable!("the parent is an object"),
        };
        container.push(key.as_str());
    }
    let current = parent.get(leaf.as_str()).cloned();
    if operation == "remove" {
        if keys.len() == 1 && required(kind).contains(&leaf.as_str()) {
            return Err(IamError::new(
                "mutability",
                "Required attribute cannot be removed.",
            ));
        }
        // Entra ID removes individual members as `{ op: "remove", path: "members", value: [{ value }] }`.
        if let (Some(Value::Array(current)), Some(Value::Array(removed))) = (&current, &value) {
            let identity = |item: &Value| -> Option<Value> {
                match item {
                    Value::Object(map) => map.get("value").cloned(),
                    other => Some(other.clone()),
                }
            };
            let removed: Vec<Option<Value>> = removed.iter().map(identity).collect();
            let same = |a: &Option<Value>, b: &Option<Value>| match (a, b) {
                (None, None) => true,
                (Some(a), Some(b)) => {
                    !matches!(a, Value::Object(_) | Value::Array(_)) && core_js::strict_equal(a, b)
                }
                _ => false,
            };
            let kept: Vec<Value> = current
                .iter()
                .filter(|item| {
                    let key = identity(item);
                    !removed.iter().any(|removed| same(removed, &key))
                })
                .cloned()
                .collect();
            parent.insert(leaf.clone(), Value::Array(kept));
        } else {
            parent.shift_remove(leaf.as_str());
        }
        return Ok(());
    }
    match (operation, &current, &value) {
        ("add", Some(Value::Array(current)), _) => {
            let mut merged = current.clone();
            match &value {
                Some(Value::Array(items)) => merged.extend(items.iter().cloned()),
                Some(other) => merged.push(other.clone()),
                // `[...current, ...[undefined].flat()]` appends an undefined element, which serializes as null.
                None => merged.push(Value::Null),
            }
            parent.insert(leaf.clone(), Value::Array(merged));
        }
        ("add", Some(Value::Object(current)), Some(Value::Object(value))) => {
            let mut merged = current.clone();
            for (name, item) in value {
                merged.insert(name.clone(), item.clone());
            }
            parent.insert(leaf.clone(), Value::Object(merged));
        }
        _ => assign(parent, &container, leaf, value),
    }
    Ok(())
}

/// `applyPatchOperation(document, type, operation, path, value, ignored)`: applies one PatchOp operation in place to
/// a resource's writable document. `ignored` names attributes the service drops instead of applying: a key of a
/// pathless value (`explicit_path` false) or a whole path (`explicit_path` true). An operation on one of them is
/// skipped. A None `value` is an operation without one.
pub fn apply_patch_operation(
    document: &mut ObjectValue,
    kind: ResourceType,
    operation: &str,
    path: Option<&str>,
    value: Option<&Value>,
    ignored: &dyn Fn(&str, bool) -> bool,
) -> IamResult<()> {
    let Some(path) = path else {
        if operation == "remove" {
            return Err(IamError::new("noTarget", "remove requires a path."));
        }
        let Some(Value::Object(value)) = value else {
            return Err(IamError::new(
                "invalidValue",
                "A PATCH without a path requires an object value.",
            ));
        };
        for (name, item) in value {
            if name == "schemas" || ignored(name, false) {
                continue;
            }
            let segments = attribute_path(name)
                .map_err(|_| invalid_path(format!("Invalid attribute \"{name}\".")))?;
            let keys = canonical(&segments, kind)?;
            // A whole extension object merges key by key so schema-qualified and nested forms behave alike.
            if keys.len() == 1
                && keys[0] == ENTERPRISE_SCHEMA
                && let Value::Object(members) = item
            {
                for (sub, sub_value) in members {
                    let mut nested = segments.clone();
                    nested.push(sub.to_lowercase());
                    let keys = canonical(&nested, kind)?;
                    apply_at(document, kind, operation, &keys, Some(sub_value))?;
                }
            } else {
                apply_at(document, kind, operation, &keys, Some(item))?;
            }
        }
        return Ok(());
    };
    if ignored(path, true) {
        return Ok(());
    }
    let parsed = parse_patch_path(path, kind)?;
    if parsed.filter.is_some() {
        apply_filtered(document, operation, &parsed, value)
    } else {
        apply_at(document, kind, operation, &parsed.keys, value)
    }
}
