//! Port of `packages/scim/src/filter.ts`: RFC 7644 §3.4.2.2 filters: `and`/`or`/`not(...)`, grouping, value paths
//! (`emails[type eq "work"]`), sub-attributes, schema-qualified names, and `eq ne co sw ew pr gt ge lt le`. The
//! grammar is bounded (length, depth, comparison count); anything outside it receives invalidFilter, never an
//! unfiltered result. Also sorting (§3.4.2.3) and attribute projection (§3.4.2.5).

use std::cmp::Ordering;

use better_iam_core::{IamError, IamResult, js as core_js};
use serde_json::{Map, Value, json};

use crate::js::{as_object, js_string, less_than};
use crate::types::{ENTERPRISE_SCHEMA, GROUP_SCHEMA, ObjectValue, USER_SCHEMA};

/// `FilterNode`.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterNode {
    And(Box<FilterNode>, Box<FilterNode>),
    Or(Box<FilterNode>, Box<FilterNode>),
    Not(Box<FilterNode>),
    /// `value` is None for `pr`.
    Compare {
        path: Vec<String>,
        op: String,
        value: Option<Value>,
    },
    ValuePath {
        path: Vec<String>,
        filter: Box<FilterNode>,
    },
}

impl FilterNode {
    /// The node as the TypeScript object (`{ kind, ... }`).
    pub fn to_json(&self) -> Value {
        match self {
            FilterNode::And(left, right) => {
                json!({ "kind": "and", "left": left.to_json(), "right": right.to_json() })
            }
            FilterNode::Or(left, right) => {
                json!({ "kind": "or", "left": left.to_json(), "right": right.to_json() })
            }
            FilterNode::Not(node) => json!({ "kind": "not", "node": node.to_json() }),
            FilterNode::Compare { path, op, value } => {
                let mut map = Map::new();
                map.insert("kind".into(), json!("compare"));
                map.insert("path".into(), json!(path));
                map.insert("op".into(), json!(op));
                if let Some(value) = value {
                    map.insert("value".into(), value.clone());
                }
                Value::Object(map)
            }
            FilterNode::ValuePath { path, filter } => {
                json!({ "kind": "valuePath", "path": path, "filter": filter.to_json() })
            }
        }
    }
}

const MAX_FILTER_LENGTH: usize = 2048;
const MAX_DEPTH: usize = 16;
const MAX_COMPARISONS: usize = 64;
const OPERATORS: [&str; 10] = ["eq", "ne", "co", "sw", "ew", "pr", "gt", "ge", "lt", "le"];
/// Case-exact attributes: identifiers compare byte-for-byte, everything else case-insensitively.
const CASE_EXACT: [&str; 3] = ["id", "externalid", "members.value"];
const BOOLEAN: [&str; 2] = ["active", "primary"];

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("invalidFilter", message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenType {
    Word,
    Str,
    Open,
    Close,
    OpenBracket,
    CloseBracket,
}

impl TokenType {
    fn label(self) -> &'static str {
        match self {
            TokenType::Word => "word",
            TokenType::Str => "string",
            TokenType::Open => "(",
            TokenType::Close => ")",
            TokenType::OpenBracket => "[",
            TokenType::CloseBracket => "]",
        }
    }
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenType,
    value: String,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.' | '$' | '+' | '-')
}

/// A JavaScript line terminator (what `.` does not match).
fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

fn tokenize(input: &str) -> IamResult<Vec<Token>> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if core_js::is_js_whitespace(c) {
            index += 1;
            continue;
        }
        let bracket = match c {
            '(' => Some(TokenType::Open),
            ')' => Some(TokenType::Close),
            '[' => Some(TokenType::OpenBracket),
            ']' => Some(TokenType::CloseBracket),
            _ => None,
        };
        if let Some(kind) = bracket {
            tokens.push(Token {
                kind,
                value: c.to_string(),
            });
            index += 1;
            continue;
        }
        if c == '"' {
            // /^"(?:[^"\\]|\\.)*"/
            let mut end = index + 1;
            let mut closed = false;
            while end < chars.len() {
                match chars[end] {
                    '"' => {
                        closed = true;
                        break;
                    }
                    '\\' => {
                        if end + 1 < chars.len() && !is_line_terminator(chars[end + 1]) {
                            end += 2;
                        } else {
                            break;
                        }
                    }
                    _ => end += 1,
                }
            }
            if !closed {
                return Err(invalid("Unterminated string in filter."));
            }
            tokens.push(Token {
                kind: TokenType::Str,
                value: chars[index..=end].iter().collect(),
            });
            index = end + 1;
            continue;
        }
        let mut end = index;
        while end < chars.len() && is_word_char(chars[end]) {
            end += 1;
        }
        if end == index {
            return Err(invalid(format!("Unexpected character \"{c}\" in filter.")));
        }
        tokens.push(Token {
            kind: TokenType::Word,
            value: chars[index..end].iter().collect(),
        });
        index = end;
    }
    Ok(tokens)
}

fn valid_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '$' | '-'))
}

/// `attributePath(raw)`: splits a (possibly schema-qualified) attribute path into lowercase segments; the enterprise
/// extension is one key.
pub fn attribute_path(raw: &str) -> IamResult<Vec<String>> {
    let lower = raw.to_lowercase();
    for schema in [ENTERPRISE_SCHEMA, USER_SCHEMA, GROUP_SCHEMA] {
        let prefix = format!("{}:", schema.to_lowercase());
        if !lower.starts_with(&prefix) {
            continue;
        }
        // The schema URNs are ASCII, so the prefix has the same length in `raw`.
        let rest = raw.get(prefix.len()..).unwrap_or_default();
        if rest.is_empty() {
            return Err(invalid("Attribute name is missing after the schema URN."));
        }
        return if schema == ENTERPRISE_SCHEMA {
            let mut path = vec![ENTERPRISE_SCHEMA.to_lowercase()];
            path.extend(attribute_path(rest)?);
            Ok(path)
        } else {
            attribute_path(rest)
        };
    }
    if lower == ENTERPRISE_SCHEMA.to_lowercase() {
        return Ok(vec![lower]);
    }
    if lower.starts_with("urn:") {
        return Err(invalid("Unsupported schema URN."));
    }
    let segments: Vec<String> = lower.split('.').map(str::to_owned).collect();
    if segments.len() > 3 || segments.iter().any(|segment| !valid_segment(segment)) {
        return Err(invalid(format!("Invalid attribute path \"{raw}\".")));
    }
    Ok(segments)
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
    comparisons: usize,
}

impl Parser {
    fn parse(&mut self) -> IamResult<FilterNode> {
        let node = self.or(0)?;
        if self.position != self.tokens.len() {
            return Err(invalid("Unexpected trailing filter content."));
        }
        Ok(node)
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn keyword(&mut self, word: &str) -> bool {
        if let Some(token) = self.peek()
            && token.kind == TokenType::Word
            && token.value.to_lowercase() == word
        {
            self.position += 1;
            return true;
        }
        false
    }

    fn expect(&mut self, kind: TokenType) -> IamResult<Token> {
        let token = self.tokens.get(self.position).cloned();
        self.position += 1;
        match token {
            Some(token) if token.kind == kind => Ok(token),
            _ => Err(invalid(format!("Expected \"{}\" in filter.", kind.label()))),
        }
    }

    fn or(&mut self, depth: usize) -> IamResult<FilterNode> {
        let mut node = self.and(depth)?;
        while self.keyword("or") {
            let right = self.and(depth)?;
            node = FilterNode::Or(Box::new(node), Box::new(right));
        }
        Ok(node)
    }

    fn and(&mut self, depth: usize) -> IamResult<FilterNode> {
        let mut node = self.unary(depth)?;
        while self.keyword("and") {
            let right = self.unary(depth)?;
            node = FilterNode::And(Box::new(node), Box::new(right));
        }
        Ok(node)
    }

    fn unary(&mut self, depth: usize) -> IamResult<FilterNode> {
        if depth > MAX_DEPTH {
            return Err(invalid("Filter is nested too deeply."));
        }
        let token = self.peek().cloned();
        if let Some(token) = &token
            && token.kind == TokenType::Word
            && token.value.to_lowercase() == "not"
            && self
                .tokens
                .get(self.position + 1)
                .is_some_and(|next| next.kind == TokenType::Open)
        {
            self.position += 2;
            let node = self.or(depth + 1)?;
            self.expect(TokenType::Close)?;
            return Ok(FilterNode::Not(Box::new(node)));
        }
        if token.is_some_and(|token| token.kind == TokenType::Open) {
            self.position += 1;
            let node = self.or(depth + 1)?;
            self.expect(TokenType::Close)?;
            return Ok(node);
        }
        self.comparison(depth)
    }

    fn comparison(&mut self, depth: usize) -> IamResult<FilterNode> {
        let attribute = self.expect(TokenType::Word)?;
        let path = attribute_path(&attribute.value)?;
        if self
            .peek()
            .is_some_and(|token| token.kind == TokenType::OpenBracket)
        {
            self.position += 1;
            let filter = self.or(depth + 1)?;
            self.expect(TokenType::CloseBracket)?;
            return Ok(FilterNode::ValuePath {
                path,
                filter: Box::new(filter),
            });
        }
        self.comparisons += 1;
        if self.comparisons > MAX_COMPARISONS {
            return Err(invalid("Filter has too many comparisons."));
        }
        let operator = self.expect(TokenType::Word)?.value.to_lowercase();
        if !OPERATORS.contains(&operator.as_str()) {
            return Err(invalid(format!(
                "Unsupported filter operator \"{operator}\"."
            )));
        }
        if operator == "pr" {
            return Ok(FilterNode::Compare {
                path,
                op: operator,
                value: None,
            });
        }
        let token = self.tokens.get(self.position).cloned();
        self.position += 1;
        let token = match token {
            Some(token) if token.kind == TokenType::Str || token.kind == TokenType::Word => token,
            _ => return Err(invalid("Filter comparison is missing a value.")),
        };
        let source = if token.kind == TokenType::Word {
            token.value.to_lowercase()
        } else {
            token.value.clone()
        };
        let value = core_js::parse(&source)
            .map_err(|_| invalid(format!("Invalid filter value {}.", token.value)))?;
        if matches!(value, Value::Object(_) | Value::Array(_)) {
            return Err(invalid(
                "Filter values must be strings, numbers, booleans or null.",
            ));
        }
        let leaf = path.last().cloned().unwrap_or_default();
        if BOOLEAN.contains(&leaf.as_str()) && !matches!(value, Value::Bool(_) | Value::Null) {
            return Err(invalid(format!("{leaf} requires a boolean comparison.")));
        }
        if matches!(value, Value::Bool(_)) && operator != "eq" && operator != "ne" {
            return Err(invalid("Booleans support only eq and ne."));
        }
        if ["co", "sw", "ew"].contains(&operator.as_str()) && !value.is_string() {
            return Err(invalid(format!("{operator} requires a string value.")));
        }
        Ok(FilterNode::Compare {
            path,
            op: operator,
            value: Some(value),
        })
    }
}

/// `parseFilterExpression(filter)`.
pub fn parse_filter_expression(filter: &str) -> IamResult<FilterNode> {
    if core_js::utf16_len(filter) > MAX_FILTER_LENGTH {
        return Err(invalid("Filter is too long."));
    }
    let tokens = tokenize(filter)?;
    if tokens.is_empty() {
        return Err(invalid("Filter is empty."));
    }
    Parser {
        tokens,
        position: 0,
        comparisons: 0,
    }
    .parse()
}

/// `property(value, key)`: case-insensitive member lookup, as SCIM attribute names are case-insensitive (`key` is
/// lowercase).
pub fn property<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    let record = as_object(value)?;
    if let Some(found) = record.get(key) {
        return Some(found);
    }
    record
        .iter()
        .find(|(name, _)| name.to_lowercase() == key)
        .map(|(_, value)| value)
}

/// `[value].flat()`: the elements of an array, else the value itself (`undefined` stays an element).
fn flat(value: Option<&Value>) -> Vec<Option<&Value>> {
    match value {
        Some(Value::Array(items)) => items.iter().map(Some).collect(),
        other => vec![other],
    }
}

fn nullish(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null))
}

/// `resolve(value, path)`: all leaf values at a path; multi-valued attributes fan out and a complex value compares by
/// its `value`.
fn resolve<'a>(value: &'a Value, path: &[String]) -> Vec<Option<&'a Value>> {
    let mut current: Vec<&Value> = vec![value];
    for segment in path {
        let mut next = Vec::new();
        for item in &current {
            for child in flat(property(Some(item), segment)) {
                if let Some(child) = child
                    && !child.is_null()
                {
                    next.push(child);
                }
            }
        }
        current = next;
    }
    current
        .into_iter()
        .map(|item| match item {
            Value::Object(_) => property(Some(item), "value"),
            other => Some(other),
        })
        .collect()
}

fn compare(actual: Option<&Value>, op: &str, expected: Option<&Value>, case_exact: bool) -> bool {
    let Some(actual) = actual.filter(|value| !value.is_null()) else {
        return op == "ne" && !matches!(expected, Some(Value::Null));
    };
    let normalize = |item: &Value| -> Value {
        match item {
            Value::String(text) if !case_exact => Value::String(text.to_lowercase()),
            other => other.clone(),
        }
    };
    let left = normalize(actual);
    let right = expected.map(normalize);
    let strict = |right: &Option<Value>| match right {
        Some(right) => core_js::strict_equal(&left, right),
        None => false,
    };
    match op {
        "eq" => strict(&right),
        "ne" => !strict(&right),
        "co" | "sw" | "ew" => {
            let (Value::String(left), Some(Value::String(right))) = (&left, &right) else {
                return false;
            };
            match op {
                "co" => left.contains(right.as_str()),
                "sw" => left.starts_with(right.as_str()),
                _ => left.ends_with(right.as_str()),
            }
        }
        _ => {
            let Some(right) = right else {
                return false;
            };
            let same = matches!(
                (&left, &right),
                (Value::String(_), Value::String(_)) | (Value::Number(_), Value::Number(_))
            );
            if !same {
                return false;
            }
            match op {
                "gt" => less_than(&right, &left),
                "ge" => !less_than(&left, &right) && ge_defined(&left, &right),
                "lt" => less_than(&left, &right),
                _ => !less_than(&right, &left) && ge_defined(&right, &left),
            }
        }
    }
}

/// For `a >= b` on same-typed strings or numbers: JavaScript answers false when a number is NaN.
fn ge_defined(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => {
            !core_js::number_value(a).is_nan() && !core_js::number_value(b).is_nan()
        }
        _ => true,
    }
}

/// `evaluateFilter(node, value, prefix)`.
pub fn evaluate_filter(node: &FilterNode, value: &Value, prefix: &[String]) -> bool {
    match node {
        FilterNode::And(left, right) => {
            evaluate_filter(left, value, prefix) && evaluate_filter(right, value, prefix)
        }
        FilterNode::Or(left, right) => {
            evaluate_filter(left, value, prefix) || evaluate_filter(right, value, prefix)
        }
        FilterNode::Not(node) => !evaluate_filter(node, value, prefix),
        FilterNode::ValuePath { path, filter } => {
            let mut items: Vec<&Value> = vec![value];
            for segment in path {
                items = items
                    .into_iter()
                    .flat_map(|item| flat(property(Some(item), segment)))
                    .filter_map(|item| item.filter(|item| crate::js::truthy(Some(item))))
                    .collect();
            }
            let mut nested = prefix.to_vec();
            nested.extend(path.iter().cloned());
            items
                .into_iter()
                .any(|item| evaluate_filter(filter, item, &nested))
        }
        FilterNode::Compare {
            path,
            op,
            value: expected,
        } => {
            let mut full = prefix.to_vec();
            full.extend(path.iter().cloned());
            let case_exact = CASE_EXACT.contains(&full.join(".").as_str());
            if op == "pr" {
                let mut items: Vec<Option<&Value>> = vec![Some(value)];
                for segment in path {
                    items = items
                        .into_iter()
                        .flat_map(|item| flat(property(item, segment)))
                        .collect();
                }
                return items.into_iter().any(|item| match item {
                    None | Some(Value::Null) => false,
                    Some(Value::String(text)) => !text.is_empty(),
                    Some(Value::Array(items)) => !items.is_empty(),
                    Some(_) => true,
                });
            }
            let values = resolve(value, path);
            if values.is_empty() {
                return compare(None, op, expected.as_ref(), case_exact);
            }
            if op == "ne" {
                values
                    .into_iter()
                    .all(|item| compare(item, "ne", expected.as_ref(), case_exact))
            } else {
                values
                    .into_iter()
                    .any(|item| compare(item, op, expected.as_ref(), case_exact))
            }
        }
    }
}

/// A predicate over rendered SCIM resources.
pub type ScimPredicate = Box<dyn Fn(&Value) -> bool + Send + Sync>;

/// `parseScimFilter(filter)`: parses a filter into a predicate over rendered SCIM resources; an absent filter matches
/// everything.
pub fn parse_scim_filter(filter: Option<&str>) -> IamResult<ScimPredicate> {
    match filter.filter(|filter| !filter.is_empty()) {
        None => Ok(Box::new(|_| true)),
        Some(filter) => {
            let node = parse_filter_expression(filter)?;
            Ok(Box::new(move |value| evaluate_filter(&node, value, &[])))
        }
    }
}

/// `sortKey(resource, path)`: multi-valued attributes sort by their primary (or first) value.
fn sort_key(resource: &Value, path: &[String]) -> Option<Value> {
    let mut current: Option<&Value> = Some(resource);
    for segment in path {
        let mut next = property(current, segment);
        if let Some(Value::Array(items)) = next {
            next = items
                .iter()
                .find(|item| property(Some(item), "primary") == Some(&Value::Bool(true)))
                .or_else(|| items.first());
        }
        current = next;
    }
    if let Some(Value::Object(_) | Value::Array(_)) = current {
        current = property(current, "value");
    }
    match current {
        Some(Value::String(text)) => Some(Value::String(text.to_lowercase())),
        other => other.cloned(),
    }
}

/// `sortResources(resources, sortBy, sortOrder)`.
pub fn sort_resources(
    resources: Vec<Value>,
    sort_by: Option<&str>,
    sort_order: Option<&str>,
) -> IamResult<Vec<Value>> {
    let Some(sort_by) = sort_by.filter(|value| !value.is_empty()) else {
        return Ok(resources);
    };
    let order = sort_order.unwrap_or("ascending").to_lowercase();
    if order != "ascending" && order != "descending" {
        return Err(IamError::new(
            "invalidValue",
            "sortOrder must be ascending or descending.",
        ));
    }
    let path = attribute_path(sort_by)?;
    let descending = order == "descending";
    let mut rows: Vec<(Value, Option<Value>)> = resources
        .into_iter()
        .map(|resource| {
            let key = sort_key(&resource, &path);
            (resource, key)
        })
        .collect();
    rows.sort_by(|(_, a), (_, b)| {
        // Unassigned values sort last in either direction.
        match (nullish(a.as_ref()), nullish(b.as_ref())) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => {
                let (a, b) = (
                    a.as_ref().unwrap_or(&Value::Null),
                    b.as_ref().unwrap_or(&Value::Null),
                );
                let ordering = if less_than(a, b) {
                    Ordering::Less
                } else if less_than(b, a) {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                };
                if descending {
                    ordering.reverse()
                } else {
                    ordering
                }
            }
        }
    });
    Ok(rows.into_iter().map(|(resource, _)| resource).collect())
}

/// The actual member name of `key` in `resource` (case-insensitive), else `key`.
fn matching_key(resource: &ObjectValue, key: &str) -> String {
    resource
        .keys()
        .find(|name| name.to_lowercase() == key)
        .cloned()
        .unwrap_or_else(|| key.to_owned())
}

/// `pick(item)` of an `attributes` projection with sub-attributes.
fn pick(item: &Value, rest: &[String]) -> Value {
    let mut picked = ObjectValue::new();
    // The path of members inside `picked` that `target` points at.
    let mut target_path: Vec<String> = Vec::new();
    let mut source: Option<Value> = Some(item.clone());
    for (index, segment) in rest.iter().enumerate() {
        let name = match &source {
            Some(Value::Object(map)) => matching_key(map, segment),
            _ => segment.clone(),
        };
        let Some(child) = property(source.as_ref(), segment).cloned() else {
            continue;
        };
        let mut target = &mut picked;
        for key in &target_path {
            target = match target.get_mut(key) {
                Some(Value::Object(map)) => map,
                _ => unreachable!("the projection target is an object"),
            };
        }
        if index == rest.len() - 1 {
            target.insert(name, child);
        } else {
            target.insert(name.clone(), Value::Object(ObjectValue::new()));
            target_path.push(name);
            source = Some(child);
        }
    }
    Value::Object(picked)
}

/// `projectResource(resource, attributes, excluded)`: attribute projection (§3.4.2.5); `id` and `schemas` are always
/// returned.
pub fn project_resource(
    resource: &ObjectValue,
    attributes: Option<&[String]>,
    excluded: Option<&[String]>,
) -> IamResult<ObjectValue> {
    let attributes = attributes.filter(|list| !list.is_empty());
    let excluded = excluded.filter(|list| !list.is_empty());
    if attributes.is_some() && excluded.is_some() {
        return Err(IamError::new(
            "invalidValue",
            "attributes and excludedAttributes are mutually exclusive.",
        ));
    }
    let always = ["id", "schemas"];
    if let Some(attributes) = attributes {
        let mut result = ObjectValue::new();
        if let Some(schemas) = resource.get("schemas") {
            result.insert("schemas".into(), schemas.clone());
        }
        if let Some(id) = resource.get("id") {
            result.insert("id".into(), id.clone());
        }
        for raw in attributes {
            let path = attribute_path(raw)?;
            let (top, rest) = path.split_first().expect("an attribute path has a segment");
            let key = matching_key(resource, top);
            let Some(value) = resource.get(&key) else {
                continue;
            };
            if always.contains(&key.as_str()) {
                continue;
            }
            if rest.is_empty() {
                result.insert(key, value.clone());
                continue;
            }
            let projected = match value {
                Value::Array(items) => {
                    Value::Array(items.iter().map(|item| pick(item, rest)).collect())
                }
                other => pick(other, rest),
            };
            let merged = match (result.get(&key), &projected) {
                (Some(Value::Object(existing)), Value::Object(projected)) => {
                    let mut merged = existing.clone();
                    for (name, item) in projected {
                        merged.insert(name.clone(), item.clone());
                    }
                    Value::Object(merged)
                }
                (Some(Value::Object(existing)), Value::Array(items)) => {
                    // `{ ...existing, ...array }` spreads the array's indexes.
                    let mut merged = existing.clone();
                    for (index, item) in items.iter().enumerate() {
                        merged.insert(index.to_string(), item.clone());
                    }
                    Value::Object(merged)
                }
                _ => projected,
            };
            result.insert(key, merged);
        }
        return Ok(result);
    }
    if let Some(excluded) = excluded {
        let mut result = resource.clone();
        for raw in excluded {
            let path = attribute_path(raw)?;
            let (top, rest) = path.split_first().expect("an attribute path has a segment");
            let key = matching_key(&result, top);
            if always.contains(&key.as_str()) {
                continue;
            }
            if rest.is_empty() {
                result.shift_remove(&key);
                continue;
            }
            let Some(container) = result.get_mut(&key) else {
                continue;
            };
            let items: Vec<&mut Value> = match container {
                Value::Array(items) => items.iter_mut().collect(),
                other => vec![other],
            };
            let (leaf, parents) = rest.split_last().expect("rest is not empty");
            for item in items {
                if !matches!(item, Value::Object(_) | Value::Array(_)) {
                    continue;
                }
                let mut parent: Option<&mut Value> = Some(item);
                for segment in parents {
                    parent = match parent {
                        Some(Value::Object(map)) => {
                            let name =
                                map.keys()
                                    .find(|name| **name == *segment)
                                    .cloned()
                                    .or_else(|| {
                                        map.keys()
                                            .find(|name| name.to_lowercase() == *segment)
                                            .cloned()
                                    });
                            name.and_then(move |name| map.get_mut(&name))
                        }
                        _ => None,
                    };
                }
                if let Some(Value::Object(map)) = parent
                    && let Some(name) = map
                        .keys()
                        .find(|name| name.to_lowercase() == *leaf)
                        .cloned()
                {
                    map.shift_remove(&name);
                }
            }
        }
        return Ok(result);
    }
    Ok(resource.clone())
}

/// `attributeList(value)`: splits a comma-separated `attributes` / `excludedAttributes` value.
pub fn attribute_list(value: Option<&Value>) -> IamResult<Option<Vec<String>>> {
    let list: Vec<Value> = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(text)) if text.is_empty() => return Ok(None),
        Some(Value::Array(items)) => items.clone(),
        Some(other) => js_string(Some(other))
            .split(',')
            .map(|item| Value::String(item.to_owned()))
            .collect(),
    };
    if list.len() > 50 || list.iter().any(|item| !item.is_string()) {
        return Err(IamError::new(
            "invalidValue",
            "Attribute lists hold at most 50 attribute names.",
        ));
    }
    Ok(Some(
        list.iter()
            .filter_map(Value::as_str)
            .map(|item| core_js::trim(item).to_owned())
            .filter(|item| !item.is_empty())
            .collect(),
    ))
}
