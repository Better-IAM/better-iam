//! Port of `packages/server/src/policy-lint.ts`: the policy linter. It validates a document as storage would, then
//! reports statements that grant more than intended, conditions that can never match or silently fail open, and
//! statements that are shadowed or duplicated.

use std::collections::HashMap;

use better_iam_core::{
    AttributeType, ConditionOperator, Effect, IamResult, PolicyDocument, PolicyStatement,
    match_pattern,
};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context_keys::{
    CLEARANCE_SERVER_KEYS, ContextKeyType, OPTIONAL_PRINCIPAL_SERVER_KEYS,
    OPTIONAL_RESOURCE_SERVER_KEYS, RESOURCE_SERVER_KEYS, SESSION_TAG_PREFIX, TENANT_SERVER_KEYS,
    principal_server_keys, session_tag_name,
};
use crate::js::{cmp_utf16, stringify, utf16_len};

/// What the linter may assume about the deployment beyond the keys the server always derives.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyLintContext {
    /// Declared identity attributes, exposed to policies as principal.{name}.
    #[serde(
        rename = "identityAttributes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_attributes: Option<IndexMap<String, better_iam_core::AttributeType>>,
    /// Known resource attribute names across resource types; when omitted, any resource.{name} key is accepted.
    #[serde(
        rename = "resourceAttributes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resource_attributes: Option<Vec<String>>,
    /// Keys the application supplies through resolveContext.
    #[serde(
        rename = "contextKeys",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub context_keys: Option<Vec<String>>,
    /// The deployment enables security clearances (`options.clearances`): the `principal.clearance*` keys and
    /// `resource.classification`, `resource.classificationRank`, `resource.compartments`, `resource.noforn` and
    /// `resource.releasableTo` are then the server's. Without it they are ordinary context keys and resource
    /// attributes.
    #[serde(
        rename = "clearances",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub clearances: Option<bool>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyLintResult {
    #[serde(rename = "valid")]
    pub valid: bool,
    /// Why the document was rejected; warnings are empty when validation fails.
    #[serde(rename = "error", default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    /// Sorted by statement index, then code.
    #[serde(rename = "warnings")]
    pub warnings: Vec<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a context key holds (`KeyType`): the registry's types.
type KeyType = ContextKeyType;

/// `KeyInfo`.
#[derive(Debug, Clone, Copy)]
struct KeyInfo {
    /// Set by the server, declared by configuration, or supplied by the application.
    known: bool,
    /// Missing from some decisions; every operator except Exists is then false.
    optional: bool,
    kind: Option<KeyType>,
}

/// `serverKeys`: every key the server derives, the shared principal and request registry plus the resource keys
/// decisions add.
fn server_key(key: &str) -> Option<KeyType> {
    if let Some(kind) = principal_server_keys().get(key) {
        return Some(*kind);
    }
    if let Some(kind) = TENANT_SERVER_KEYS.get(key) {
        return Some(*kind);
    }
    match key {
        "resource.tenantId" => Some(ContextKeyType::Identifier),
        "resource.relations" | "resource.parentRelations" => Some(ContextKeyType::List),
        _ => None,
    }
}

/// `optionalServerKeys`: server keys absent from some decisions.
fn optional_server_key(key: &str) -> bool {
    OPTIONAL_PRINCIPAL_SERVER_KEYS.contains(&key) || OPTIONAL_RESOURCE_SERVER_KEYS.contains(&key)
}

/// `resourceLinks`: links every managed resource may carry besides its declared attributes.
const RESOURCE_LINKS: [&str; 3] = ["ownerId", "parentId", "parentType"];

/// `missingKeyHints`: keys people commonly expect but the server never sets, with the usual alternative.
const MISSING_KEY_HINTS: [(&str, &str); 9] = [
    ("resource.type", "or match the type in the resource pattern"),
    ("resource.id", "or match the ID in the resource pattern"),
    ("principal.email", "or declare it as an identity attribute"),
    ("principal.name", "or declare it as an identity attribute"),
    (
        "principal.managerId",
        "or declare it as an identity attribute",
    ),
    (
        "request.ip",
        "or use request.sourceIp, which the server sets from the client address",
    ),
    ("principal.tokenIssuedAt", "or use principal.tokenIssueTime"),
    (
        "principal.risk",
        "or use principal.riskLevel (none, low, medium, high) or principal.riskScore (0-100)",
    ),
    (
        "principal.license",
        "or use principal.licenses (the keys of the products the person holds a seat for)",
    ),
];

fn missing_key_hint(key: &str) -> Option<&'static str> {
    MISSING_KEY_HINTS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, hint)| *hint)
}

/// `typeLabels`.
fn type_label(kind: KeyType) -> &'static str {
    match kind {
        ContextKeyType::Identifier => "a string",
        ContextKeyType::Timestamp => "a timestamp string",
        ContextKeyType::String => "a string",
        ContextKeyType::Number => "a number",
        ContextKeyType::Boolean => "a boolean",
        ContextKeyType::List => "a list",
    }
}

fn numeric_operator(operator: ConditionOperator) -> bool {
    matches!(
        operator,
        ConditionOperator::NumericEquals
            | ConditionOperator::NumericNotEquals
            | ConditionOperator::NumericLessThan
            | ConditionOperator::NumericLessThanEquals
            | ConditionOperator::NumericGreaterThan
            | ConditionOperator::NumericGreaterThanEquals
    )
}

fn date_operator(operator: ConditionOperator) -> bool {
    matches!(
        operator,
        ConditionOperator::DateBefore | ConditionOperator::DateAfter
    )
}

fn array_operator(operator: ConditionOperator) -> bool {
    matches!(
        operator,
        ConditionOperator::ArrayContains | ConditionOperator::ArrayContainsAll
    )
}

/// Negated string operators: an unresolved variable in their value makes the comparison true.
fn negated_string_operator(operator: ConditionOperator) -> bool {
    matches!(
        operator,
        ConditionOperator::StringNotEquals
            | ConditionOperator::StringNotEqualsIgnoreCase
            | ConditionOperator::StringNotLike
    )
}

/// `list(value)`: a scalar or a list of them, as a list.
fn list(value: &Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    }
}

fn variable_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
}

/// `variablesOf(value)`: the names `/\$\{([A-Za-z_][A-Za-z0-9_.:-]{0,127})\}/g` finds in a string value.
fn variables_in(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'$' && bytes[index + 1] == b'{' {
            let start = index + 2;
            if start < bytes.len() && (bytes[start].is_ascii_alphabetic() || bytes[start] == b'_') {
                let mut end = start + 1;
                while end < bytes.len() && end - start < 128 && variable_char(bytes[end]) {
                    end += 1;
                }
                if end < bytes.len() && bytes[end] == b'}' {
                    found.push(text[start..end].to_owned());
                    index = end + 1;
                    continue;
                }
            }
        }
        index += 1;
    }
    found
}

/// [`variables_in`] for a condition value (only strings hold variables).
fn variables_of(value: &Value) -> Vec<String> {
    match value {
        Value::String(text) => variables_in(text),
        _ => Vec::new(),
    }
}

fn attribute_key_type(kind: AttributeType) -> KeyType {
    match kind {
        AttributeType::String => ContextKeyType::String,
        AttributeType::Number => ContextKeyType::Number,
        AttributeType::Boolean => ContextKeyType::Boolean,
    }
}

/// `keyInfo(key, context)`.
fn key_info(key: &str, context: &PolicyLintContext) -> KeyInfo {
    let clearances = context.clearances == Some(true);
    // The clearance and classification keys are the server's only with security clearances (`context.clearances`);
    // without it they are ordinary keys the application may supply.
    let server = if !clearances && CLEARANCE_SERVER_KEYS.contains(key) {
        None
    } else {
        server_key(key).or_else(|| {
            if clearances {
                RESOURCE_SERVER_KEYS.get(key).copied()
            } else {
                None
            }
        })
    };
    if let Some(kind) = server {
        return KeyInfo {
            known: true,
            optional: optional_server_key(key),
            kind: Some(kind),
        };
    }
    // Session tags: a valid tag name is an optional server string; an invalid one can never be set.
    if let Some(name) = key.strip_prefix(SESSION_TAG_PREFIX) {
        return if session_tag_name(name).is_some() {
            KeyInfo {
                known: true,
                optional: true,
                kind: Some(ContextKeyType::String),
            }
        } else {
            KeyInfo {
                known: false,
                optional: true,
                kind: None,
            }
        };
    }
    // The bare family name is reserved and stripped from application context before every decision, so an
    // application listing it in contextKeys still never supplies it.
    if key == &SESSION_TAG_PREFIX[..SESSION_TAG_PREFIX.len() - 1] {
        return KeyInfo {
            known: false,
            optional: true,
            kind: None,
        };
    }
    if let Some(attribute) = key.strip_prefix("principal.")
        && let Some(kind) = context
            .identity_attributes
            .as_ref()
            .and_then(|attributes| attributes.get(attribute))
    {
        return KeyInfo {
            known: true,
            optional: true,
            kind: Some(attribute_key_type(*kind)),
        };
    }
    if let Some(name) = key.strip_prefix("resource.") {
        if RESOURCE_LINKS.contains(&name) {
            return KeyInfo {
                known: true,
                optional: true,
                kind: Some(ContextKeyType::Identifier),
            };
        }
        let declared = match &context.resource_attributes {
            Some(attributes) => attributes.iter().any(|attribute| attribute == name),
            None => missing_key_hint(key).is_none(),
        };
        if declared {
            return KeyInfo {
                known: true,
                optional: true,
                kind: None,
            };
        }
    }
    KeyInfo {
        known: context
            .context_keys
            .as_ref()
            .is_some_and(|keys| keys.iter().any(|known| known == key)),
        optional: true,
        kind: None,
    }
}

/// `typeMismatch(operator, key, type)`: why an operator can never match a key of this type, or None when the
/// pairing is sound.
fn type_mismatch(operator: ConditionOperator, key: &str, kind: KeyType) -> Option<String> {
    let name = operator.as_str();
    if operator == ConditionOperator::Exists || kind == ContextKeyType::List {
        return None;
    }
    if operator == ConditionOperator::Bool {
        return if kind == ContextKeyType::Boolean {
            None
        } else {
            Some(format!(
                "Bool never matches {key}, which holds {}.",
                type_label(kind)
            ))
        };
    }
    if kind == ContextKeyType::Boolean {
        return Some(format!(
            "{name} never matches {key}, which is a boolean; use Bool."
        ));
    }
    if numeric_operator(operator) {
        return if kind == ContextKeyType::Number {
            None
        } else {
            Some(format!(
                "{name} never matches {key}, which holds {}.",
                type_label(kind)
            ))
        };
    }
    if date_operator(operator) {
        return if kind == ContextKeyType::Timestamp || kind == ContextKeyType::String {
            None
        } else {
            Some(format!(
                "{name} compares timestamps, but {key} holds {}; only request.time, principal.tokenIssueTime, principal.authTime, principal.mfaTime, or a string attribute holding ISO timestamps works with date operators.",
                if kind == ContextKeyType::Number {
                    "a number"
                } else {
                    "an identifier"
                }
            ))
        };
    }
    if array_operator(operator) {
        return Some(format!(
            "{name} never matches {key}, which holds a single value; compare it with a String, Numeric, or Bool operator."
        ));
    }
    if kind == ContextKeyType::Number {
        Some(format!(
            "{name} never matches {key}, which is a number; use a Numeric operator."
        ))
    } else {
        None
    }
}

/// A set of statement positions, 32 per word (`Bits`).
type Bits = Vec<u32>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Actions,
    Resources,
}

impl Field {
    fn of(self, statement: &PolicyStatement) -> &[String] {
        match self {
            Field::Actions => &statement.actions,
            Field::Resources => &statement.resources,
        }
    }
}

fn bit_words(size: usize) -> usize {
    size.div_ceil(32).max(1)
}

fn add_bit(bits: &mut Bits, position: usize) {
    bits[position >> 5] |= 1 << (position & 31);
}

fn or_bits(target: &mut Bits, source: &Bits) {
    for (word, other) in target.iter_mut().zip(source) {
        *word |= *other;
    }
}

fn and_bits(target: &mut Bits, source: &Bits) {
    for (word, other) in target.iter_mut().zip(source) {
        *word &= *other;
    }
}

fn empty_bits(bits: &Bits) -> bool {
    bits.iter().all(|word| *word == 0)
}

fn subset_of(subset: &Bits, bits: &Bits) -> bool {
    subset.iter().zip(bits).all(|(a, b)| a & !b == 0)
}

/// The lowest position in both sets, or None (`firstCommon`'s -1).
fn first_common(a: &Bits, b: &Bits) -> Option<usize> {
    for (word, (x, y)) in a.iter().zip(b).enumerate() {
        let common = x & y;
        if common != 0 {
            return Some(word * 32 + common.trailing_zeros() as usize);
        }
    }
    None
}

/// Work one coverage index may spend, in rough character comparisons: far more than any realistic document needs,
/// and a bound of tens of milliseconds on a hostile one (up to 128 statements of 128 patterns each).
const COVERAGE_BUDGET: i64 = 2_000_000;

/// `Wildcard`.
struct Wildcard {
    pattern: String,
    /// The pattern is `{head}*`: it covers every value, wildcards included, that starts with the head.
    prefix_only: bool,
    /// Literal text before the first wildcard and after the last: every value the pattern matches has both.
    head: String,
    tail: String,
    /// Bounds matchPattern's comparisons per value character: the longest run between stars, plus one.
    factor: i64,
    holders: Bits,
}

/// The index of one field (actions or resources) of `coverage`.
struct FieldIndex {
    all: Bits,
    exact: HashMap<String, Bits>,
    wildcards: Vec<Wildcard>,
    resolved: HashMap<String, Bits>,
}

/// `/[*?]/.test(text)`.
fn has_wildcard(text: &str) -> bool {
    text.contains(['*', '?'])
}

/// `/^\*+$/.test(pattern)`.
fn all_stars(pattern: &str) -> bool {
    !pattern.is_empty() && pattern.chars().all(|c| c == '*')
}

impl FieldIndex {
    fn new(statements: &[&PolicyStatement], field: Field) -> Self {
        let words = bit_words(statements.len());
        let mut all = vec![0; words];
        let mut exact: HashMap<String, Bits> = HashMap::new();
        let mut wildcards: IndexMap<String, Wildcard> = IndexMap::new();
        for (position, statement) in statements.iter().enumerate() {
            for pattern in field.of(statement) {
                if all_stars(pattern) {
                    add_bit(&mut all, position);
                    continue;
                }
                add_bit(
                    exact
                        .entry(pattern.clone())
                        .or_insert_with(|| vec![0; words]),
                    position,
                );
                if pattern.contains("${") || !has_wildcard(pattern) {
                    continue;
                }
                let wildcard = wildcards.entry(pattern.clone()).or_insert_with(|| {
                    let first = pattern.find(['*', '?']).unwrap_or(0);
                    let head = pattern[..first].to_owned();
                    let last = pattern.rfind(['*', '?']).map_or(0, |index| index + 1);
                    Wildcard {
                        pattern: pattern.clone(),
                        prefix_only: *pattern == format!("{head}*"),
                        tail: pattern[last..].to_owned(),
                        head,
                        factor: pattern
                            .split('*')
                            .map(|run| utf16_len(run) as i64)
                            .max()
                            .unwrap_or(0)
                            + 1,
                        holders: vec![0; words],
                    }
                });
                add_bit(&mut wildcard.holders, position);
            }
        }
        Self {
            all,
            exact,
            wildcards: wildcards.into_values().collect(),
            resolved: HashMap::new(),
        }
    }
}

/// `coverage(statements)`: which of the statements cover an action or resource, as a set of their positions. A
/// pattern covers a value when it is all stars or the same text, when it matches the value as a literal (no
/// wildcards or variables), or when it is `prefix*` and the value starts with that prefix. Each distinct value is
/// resolved once against each distinct pattern; the lookup returns None once the matching work exceeds the budget.
struct Coverage {
    budget: i64,
    actions: FieldIndex,
    resources: FieldIndex,
}

impl Coverage {
    fn new(statements: &[&PolicyStatement]) -> Self {
        Self {
            budget: COVERAGE_BUDGET,
            actions: FieldIndex::new(statements, Field::Actions),
            resources: FieldIndex::new(statements, Field::Resources),
        }
    }

    fn lookup(&mut self, field: Field, value: &str) -> Option<Bits> {
        let index = match field {
            Field::Actions => &mut self.actions,
            Field::Resources => &mut self.resources,
        };
        if let Some(known) = index.resolved.get(value) {
            return Some(known.clone());
        }
        let mut covered = index.all.clone();
        if let Some(same) = index.exact.get(value) {
            or_bits(&mut covered, same);
        }
        let literal = !has_wildcard(value) && !value.contains("${");
        for wildcard in &index.wildcards {
            self.budget -= 4;
            if self.budget < 0 {
                return None;
            }
            if subset_of(&wildcard.holders, &covered) || !(literal || wildcard.prefix_only) {
                continue;
            }
            self.budget -= (utf16_len(&wildcard.head) + utf16_len(&wildcard.tail)) as i64;
            if !value.starts_with(&wildcard.head) || !value.ends_with(&wildcard.tail) {
                continue;
            }
            if !wildcard.prefix_only {
                self.budget -=
                    utf16_len(&wildcard.pattern) as i64 + utf16_len(value) as i64 * wildcard.factor;
                if self.budget < 0 {
                    return None;
                }
                if !match_pattern(&wildcard.pattern, value, None) {
                    continue;
                }
            }
            or_bits(&mut covered, &wildcard.holders);
        }
        index.resolved.insert(value.to_owned(), covered.clone());
        Some(covered)
    }
}

/// `absenceKey(statement)`: the key a deny tests for absence when that is its only condition (Exists false), so it
/// applies exactly then.
fn absence_key(statement: &PolicyStatement) -> Option<String> {
    if statement.effect != Effect::Deny {
        return None;
    }
    let conditions = statement.conditions.as_ref()?;
    if conditions.len() != 1 {
        return None;
    }
    let (operator, attributes) = conditions.first()?;
    if *operator != ConditionOperator::Exists || attributes.len() != 1 {
        return None;
    }
    let (key, value) = attributes.first()?;
    list(value)
        .contains(&Value::Bool(false))
        .then(|| key.clone())
}

/// `[...new Set(items)].sort()`.
fn sorted_unique(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut unique: Vec<String> = items
        .into_iter()
        .collect::<IndexSet<String>>()
        .into_iter()
        .collect();
    unique.sort_by(|a, b| cmp_utf16(a, b));
    unique
}

/// `fingerprint(statement)`: an order-insensitive fingerprint of a statement (its sid aside).
fn fingerprint(statement: &PolicyStatement) -> String {
    let mut conditions: Vec<(String, Value)> = statement
        .conditions
        .iter()
        .flatten()
        .map(|(operator, attributes)| {
            let mut keys: Vec<(String, Value)> = attributes
                .iter()
                .map(|(key, value)| {
                    let values = sorted_unique(list(value).iter().map(stringify));
                    (key.clone(), json!([key, values]))
                })
                .collect();
            keys.sort_by(|a, b| cmp_utf16(&a.0, &b.0));
            let name = operator.as_str().to_owned();
            let keys: Vec<Value> = keys.into_iter().map(|(_, pair)| pair).collect();
            (name.clone(), json!([name, keys]))
        })
        .collect();
    conditions.sort_by(|a, b| cmp_utf16(&a.0, &b.0));
    let conditions: Vec<Value> = conditions.into_iter().map(|(_, pair)| pair).collect();
    stringify(&json!([
        match statement.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
        },
        sorted_unique(statement.actions.iter().cloned()),
        sorted_unique(statement.resources.iter().cloned()),
        conditions,
    ]))
}

/// One observation about a policy document (`PolicyLintWarning`). `statement` is the zero-based statement index,
/// or -1 for the whole document.
struct Warning {
    code: &'static str,
    /// `warning`: the document likely does not do what it says; `info`: worth a look, often intended.
    severity: &'static str,
    statement: i64,
    sid: Option<String>,
    message: String,
}

impl Warning {
    fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("code".into(), Value::String(self.code.into()));
        out.insert("severity".into(), Value::String(self.severity.into()));
        out.insert("statement".into(), json!(self.statement));
        if let Some(sid) = &self.sid {
            out.insert("sid".into(), Value::String(sid.clone()));
        }
        out.insert("message".into(), Value::String(self.message.clone()));
        Value::Object(out)
    }
}

/// `new Set(items)`, borrowed, in insertion order.
fn unique_refs(items: &[String]) -> Vec<&str> {
    items
        .iter()
        .map(String::as_str)
        .collect::<IndexSet<&str>>()
        .into_iter()
        .collect()
}

/// Lints a policy document: validates it as storage would, then reports statements that grant more than intended,
/// conditions that can never match or silently fail open, and statements that are shadowed or duplicated. The
/// context tells the linter which identity attributes, resource attributes, and application keys exist. Pattern
/// comparisons are budgeted: past the budget, a `shadowed-allow-skipped` note replaces the rest of the shadow
/// check.
pub fn lint_policy(
    document: Option<&Value>,
    context: Option<&crate::policy_lint::PolicyLintContext>,
) -> IamResult<crate::policy_lint::PolicyLintResult> {
    let default_context = PolicyLintContext::default();
    let context = context.unwrap_or(&default_context);
    let document = match PolicyDocument::from_value(document.unwrap_or(&Value::Null)) {
        Ok(document) => document,
        Err(error) => {
            return Ok(PolicyLintResult {
                valid: false,
                error: Some(json!({ "code": error.code, "message": error.message })),
                warnings: Vec::new(),
                extra: Map::new(),
            });
        }
    };
    let mut cache: HashMap<String, KeyInfo> = HashMap::new();
    let mut info = |key: &str| -> KeyInfo {
        *cache
            .entry(key.to_owned())
            .or_insert_with(|| key_info(key, context))
    };
    let statements = &document.statements;
    let mut warnings: Vec<Warning> = Vec::new();
    let mut fingerprints: HashMap<String, usize> = HashMap::new();

    // Denies whose only condition is Exists false on one key. Such a deny makes another deny on that key safe when
    // it covers every action and resource of the other.
    let guards: Vec<&PolicyStatement> = statements
        .iter()
        .filter(|statement| absence_key(statement).is_some())
        .collect();
    let mut guards_by_key: HashMap<String, Bits> = HashMap::new();
    for (position, guard) in guards.iter().enumerate() {
        let key = absence_key(guard).unwrap_or_default();
        let bits = guards_by_key
            .entry(key)
            .or_insert_with(|| vec![0; bit_words(guards.len())]);
        add_bit(bits, position);
    }
    let mut guarding = Coverage::new(&guards);
    // Some deny for the missing-key case covers the whole statement; false when the check runs out of budget.
    let mut absence_guarded = |statement: &PolicyStatement, key: &str| -> bool {
        let Some(mut candidates) = guards_by_key.get(key).cloned() else {
            return false;
        };
        for field in [Field::Actions, Field::Resources] {
            for value in unique_refs(field.of(statement)) {
                let Some(covering) = guarding.lookup(field, value) else {
                    return false;
                };
                and_bits(&mut candidates, &covering);
                if empty_bits(&candidates) {
                    return false;
                }
            }
        }
        true
    };

    // Allows whose every action and resource pair an unconditional deny covers, with those denies' indexes.
    let deny_indexes: Vec<usize> = statements
        .iter()
        .enumerate()
        .filter(|(_, statement)| statement.effect == Effect::Deny && statement.conditions.is_none())
        .map(|(index, _)| index)
        .collect();
    let deny_statements: Vec<&PolicyStatement> = deny_indexes
        .iter()
        .map(|index| &statements[*index])
        .collect();
    let mut denying = Coverage::new(&deny_statements);
    let mut shadowing_denies = |statement: &PolicyStatement| -> Option<Vec<usize>> {
        let mut sides: Vec<Vec<Bits>> = Vec::new();
        for field in [Field::Actions, Field::Resources] {
            let mut side: Vec<Bits> = Vec::new();
            for value in unique_refs(field.of(statement)) {
                let covering = denying.lookup(field, value)?;
                if empty_bits(&covering) {
                    return Some(Vec::new());
                }
                side.push(covering);
            }
            sides.push(side);
        }
        let mut shadowing: IndexSet<usize> = IndexSet::new();
        for action in &sides[0] {
            for resource in &sides[1] {
                let Some(first) = first_common(action, resource) else {
                    return Some(Vec::new());
                };
                shadowing.insert(deny_indexes[first]);
            }
        }
        let mut shadowing: Vec<usize> = shadowing.into_iter().collect();
        shadowing.sort_unstable();
        Some(shadowing)
    };
    let mut shadowed: HashMap<usize, Vec<usize>> = HashMap::new();
    // The first allow the shadow check had no budget left for.
    let mut unchecked: Option<usize> = None;
    if !deny_indexes.is_empty() {
        for (index, statement) in statements.iter().enumerate() {
            if statement.effect != Effect::Allow {
                continue;
            }
            let Some(shadowing) = shadowing_denies(statement) else {
                unchecked = Some(index);
                break;
            };
            if !shadowing.is_empty() {
                shadowed.insert(index, shadowing);
            }
        }
    }

    for (index, statement) in statements.iter().enumerate() {
        let mut warn = |code: &'static str, severity: &'static str, message: String| {
            warnings.push(Warning {
                code,
                severity,
                statement: index as i64,
                sid: statement.sid.clone(),
                message,
            });
        };
        let mut once: IndexSet<String> = IndexSet::new();
        let mut first = |code: &str, subject: &str| once.insert(format!("{code}\u{0}{subject}"));
        let entries: Vec<(ConditionOperator, String, Vec<Value>)> = statement
            .conditions
            .iter()
            .flatten()
            .flat_map(|(operator, attributes)| {
                attributes
                    .iter()
                    .map(|(key, value)| (*operator, key.clone(), list(value)))
            })
            .collect();
        let empty_exists = IndexMap::new();
        let exists = statement
            .conditions
            .as_ref()
            .and_then(|conditions| conditions.get(&ConditionOperator::Exists))
            .unwrap_or(&empty_exists);
        let variables: Vec<String> = statement
            .resources
            .iter()
            .flat_map(|resource| variables_in(resource))
            .chain(
                entries
                    .iter()
                    .flat_map(|(_, _, values)| values.iter().flat_map(variables_of)),
            )
            .collect();

        if statement.effect == Effect::Allow && statement.conditions.is_none() {
            let everything = statement
                .actions
                .iter()
                .any(|action| action == "*" || action == "iam:*")
                && statement
                    .resources
                    .iter()
                    .any(|resource| all_stars(resource.strip_prefix("iam/").unwrap_or(resource)));
            let service_wide: Vec<&str> = statement
                .actions
                .iter()
                .filter(|action| *action != "*" && *action != "iam:*" && action.ends_with(":*"))
                .map(String::as_str)
                .collect();
            if everything {
                warn(
                    "unrestricted-admin",
                    "warning",
                    "An unconditional allow of every action on every resource makes each holder a full administrator. Scope the actions and resources, or add conditions such as principal.mfa.".into(),
                );
            } else if !service_wide.is_empty() {
                warn(
                    "service-wildcard",
                    "info",
                    format!(
                        "Unconditional {} also grants actions added to {} later. List the actions holders need.",
                        service_wide.join(", "),
                        if service_wide.len() == 1 {
                            "that service"
                        } else {
                            "those services"
                        }
                    ),
                );
            }
        }

        let condition_keys: Vec<String> = entries.iter().map(|(_, key, _)| key.clone()).collect();
        for (kind, keys) in [("Condition key", &condition_keys), ("Variable", &variables)] {
            for key in keys {
                if info(key).known || !first("unknown-context-key", key) {
                    continue;
                }
                let hint = missing_key_hint(key);
                warn(
                    "unknown-context-key",
                    "warning",
                    format!(
                        "{kind} {key} is never set by the server; supply it with resolveContext{}. {}",
                        hint.map(|hint| format!(", {hint}")).unwrap_or_default(),
                        if kind == "Variable" {
                            "Until then the variable never resolves."
                        } else {
                            "Until then every operator except Exists is false for it."
                        }
                    ),
                );
            }
        }

        if statement.effect == Effect::Deny {
            for (operator, key, _) in &entries {
                if *operator == ConditionOperator::Exists
                    || !info(key).optional
                    || exists.contains_key(key)
                    || !first("optional-key-deny", key)
                    || absence_guarded(statement, key)
                {
                    continue;
                }
                warn(
                    "optional-key-deny",
                    "warning",
                    format!(
                        "This deny tests {key}, which is missing from some requests; when it is missing the deny silently never applies. Add a deny whose only condition is Exists {{ \"{key}\": false }} over the same actions and resources for that case, or test Exists on the key here to make the intent explicit."
                    ),
                );
            }
        }

        for (operator, key, values) in &entries {
            let operator = *operator;
            let kind = info(key).kind;
            let variable_keys: Vec<String> = values.iter().flat_map(variables_of).collect();
            if negated_string_operator(operator) {
                for variable in &variable_keys {
                    let guarded = exists.get(variable).is_some_and(|value| {
                        list(value).iter().all(|item| *item == Value::Bool(true))
                    });
                    if !info(variable).optional || guarded || !first("negated-variable", variable) {
                        continue;
                    }
                    warn(
                        "negated-variable",
                        "warning",
                        format!(
                            "{} on {key} compares with ${{{variable}}}, which can be missing; an unresolved variable makes the negated comparison true. Add Exists {{ \"{variable}\": true }} to this statement.",
                            operator.as_str()
                        ),
                    );
                }
            }
            if operator == ConditionOperator::StringLikeIgnoreCase {
                for variable in &variable_keys {
                    if variable.bytes().any(|byte| byte.is_ascii_uppercase())
                        && first("ignorecase-variable", variable)
                    {
                        warn(
                            "ignorecase-variable",
                            "warning",
                            format!(
                                "StringLikeIgnoreCase lowercases its pattern, so ${{{variable}}} is looked up as ${{{}}} and does not resolve. Use StringLike or a lowercase key.",
                                variable.to_ascii_lowercase()
                            ),
                        );
                    }
                }
            }
            if kind == Some(ContextKeyType::List)
                && operator != ConditionOperator::Exists
                && !array_operator(operator)
                && first(
                    "array-key-string-operator",
                    &format!("{}:{key}", operator.as_str()),
                )
            {
                warn(
                    "array-key-string-operator",
                    "warning",
                    format!(
                        "{} never matches {key}, which holds a list. Use ArrayContains or ArrayContainsAll.",
                        operator.as_str()
                    ),
                );
            }
            if let Some(mismatch) = kind.and_then(|kind| type_mismatch(operator, key, kind))
                && first("type-mismatch", &format!("{}:{key}", operator.as_str()))
            {
                warn("type-mismatch", "warning", mismatch);
            }
            if (operator == ConditionOperator::Bool || operator == ConditionOperator::Exists)
                && values.contains(&Value::Bool(true))
                && values.contains(&Value::Bool(false))
            {
                warn(
                    "always-true-condition",
                    "info",
                    format!(
                        "{} lists both true and false for {key}, so it {}. Remove the condition or keep one value.",
                        operator.as_str(),
                        if operator == ConditionOperator::Exists {
                            "always holds"
                        } else {
                            "holds for any boolean value"
                        }
                    ),
                );
            }
        }

        for variable in &variables {
            if info(variable).kind == Some(ContextKeyType::List)
                && first("array-variable", variable)
            {
                warn(
                    "array-variable",
                    "warning",
                    format!(
                        "${{{variable}}} names a list, and variables only resolve to strings, numbers, and booleans, so it never resolves. Test the list with ArrayContains instead."
                    ),
                );
            }
        }

        let print = fingerprint(statement);
        match fingerprints.get(&print) {
            None => {
                fingerprints.insert(print, index);
            }
            Some(&earlier) => warn(
                "duplicate-statement",
                "info",
                format!(
                    "This statement repeats statement {earlier}{}; remove one of them.",
                    statements[earlier]
                        .sid
                        .as_ref()
                        .map(|sid| format!(" ({sid})"))
                        .unwrap_or_default()
                ),
            ),
        }

        if let Some(shadowing) = shadowed.get(&index) {
            warn(
                "shadowed-allow",
                "warning",
                format!(
                    "Every action and resource of this allow is also denied unconditionally (statement {}), so it never grants anything.",
                    shadowing
                        .iter()
                        .map(usize::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
    }

    if !statements
        .iter()
        .any(|statement| statement.effect == Effect::Allow)
    {
        warnings.push(Warning {
            code: "deny-only",
            severity: "info",
            statement: -1,
            sid: None,
            message: "The document has no allow statements, so it grants nothing; its denies still restrict every holder.".into(),
        });
    }
    if let Some(unchecked) = unchecked {
        warnings.push(Warning {
            code: "shadowed-allow-skipped",
            severity: "info",
            statement: -1,
            sid: None,
            message: format!(
                "The document has too many patterns to compare every allow with the unconditional denies; allows from statement {unchecked} on were not checked for shadowing."
            ),
        });
    }
    warnings.sort_by(|a, b| {
        a.statement
            .cmp(&b.statement)
            .then_with(|| cmp_utf16(a.code, b.code))
            .then_with(|| cmp_utf16(&a.message, &b.message))
    });
    Ok(PolicyLintResult {
        valid: true,
        error: None,
        warnings: warnings.iter().map(Warning::to_json).collect(),
        extra: Map::new(),
    })
}
