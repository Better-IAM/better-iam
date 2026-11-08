//! Port of `packages/server/src/package-rules.ts`.
//!
//! The rule language of automatic (birthright) access packages. Pure: no store, no server context. A rule is a list
//! of `include` clauses (any may match) and `exclude` clauses (any match denies), each exactly a policy statement's
//! `conditions` block, compiled into a policy document and evaluated by the core policy engine against a context
//! built from the identity alone.

use better_iam_core::{
    Conditions, Effect, EvaluationInput, IamError, IamResult, PolicyDocument, PolicyStatement,
    evaluate_policy, validate_policy,
};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context_keys::{SESSION_SCOPED_PRINCIPAL_KEYS, SESSION_TAG_PREFIX};
use crate::js::{entries, is_object, keys as js_keys, sort_strings, stringify, truthy, utf16_len};
use crate::validation::integer;

/// What an administrator writes: the rule without its runtime state (owner, authority, revision, approval).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoAssignInput {
    #[serde(rename = "include")]
    pub include: Vec<Value>,
    #[serde(rename = "exclude", default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<Value>>,
    #[serde(rename = "graceMs", default, skip_serializing_if = "Option::is_none")]
    pub grace_ms: Option<f64>,
    #[serde(rename = "maxGrants", default, skip_serializing_if = "Option::is_none")]
    pub max_grants: Option<f64>,
    #[serde(
        rename = "maxRemovals",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_removals: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl AutoAssignInput {
    /// The input as the JSON TypeScript holds (`{ include, exclude?, graceMs?, maxGrants?, maxRemovals? }`), numbers
    /// in JavaScript form.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("include".into(), Value::Array(self.include.clone()));
        if let Some(exclude) = &self.exclude {
            map.insert("exclude".into(), Value::Array(exclude.clone()));
        }
        if let Some(grace_ms) = self.grace_ms {
            map.insert("graceMs".into(), crate::js::number(grace_ms));
        }
        if let Some(max_grants) = self.max_grants {
            map.insert("maxGrants".into(), crate::js::number(max_grants));
        }
        if let Some(max_removals) = self.max_removals {
            map.insert("maxRemovals".into(), crate::js::number(max_removals));
        }
        for (key, value) in &self.extra {
            map.insert(key.clone(), value.clone());
        }
        Value::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleEnvironment {
    #[serde(rename = "identityAttributes")]
    pub identity_attributes: IndexMap<String, better_iam_core::AttributeType>,
    /// Valid identity.groups values (group IDs, or names in a configuration document); omitted = not checked.
    #[serde(rename = "groups", default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<IndexSet<String>>,
    /// The package's own groups, in the same form; identity.groups may not name them.
    #[serde(
        rename = "packagedGroups",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub packaged_groups: Option<IndexSet<String>>,
    /// The org structure keys `identity.teams` and `identity.departments` (org-rules.ts), offered only where the caller
    /// evaluates them (access packages, not onboarding flows). The sets hold the valid values (team and department IDs,
    /// or team slugs and department names in a configuration document); omitted = not checked.
    ///
    /// The JSON form is `{ teams?, departments?, licenses? }` with each set as an array of the valid values (what
    /// `org_rules::org_rule_environment` answers); a member that is absent (or not an array) is not checked.
    #[serde(rename = "org", default, skip_serializing_if = "Option::is_none")]
    pub org: Option<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A key a rule may test, with its type and the operators that apply to it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleKey {
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "operators")]
    pub operators: Vec<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleMatch {
    #[serde(rename = "matched")]
    pub matched: bool,
    #[serde(rename = "matchedBy")]
    pub matched_by: Vec<String>,
    #[serde(rename = "excludedBy")]
    pub excluded_by: Vec<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What `identity.teams` and `identity.departments` hold for one identity (see org-rules.ts).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleOrgFacts {
    #[serde(rename = "teams")]
    pub teams: Vec<String>,
    #[serde(rename = "departments")]
    pub departments: Vec<String>,
    /// `identity.licenses`: the keys of the license products the person holds an active seat for (licenses.ts).
    #[serde(rename = "licenses", default, skip_serializing_if = "Option::is_none")]
    pub licenses: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub const MAX_RULE_CLAUSES: usize = 10;
pub const MAX_RULE_BYTES: usize = 16_384;
pub const MAX_GRACE_MS: f64 = 90.0 * 86_400_000.0;
pub const DEFAULT_MAX_GRANTS: f64 = 100.0;
pub const DEFAULT_MAX_REMOVALS: f64 = 25.0;
pub const AUTOMATIC_JUSTIFICATION: &str = "Automatic: matches the package rule";
/// Synthetic action used only inside rule documents; never a catalog action, grants nothing.
pub const RULE_ACTION: &str = "auto-assign";

/// The rule keys that test the org structure, and what their values name.
pub static ORG_RULE_KEYS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"identity.teams":"team","identity.departments":"department","identity.licenses":"license"}),
);

/// `orgRuleKeys` in declaration order.
const ORG_RULE_KEY_LIST: [(&str, &str); 3] = [
    ("identity.teams", "team"),
    ("identity.departments", "department"),
    ("identity.licenses", "license"),
];

/// The noun of an org rule key (`isOrgRuleKey` and `orgRuleKeys[key]`).
fn org_rule_noun(key: &str) -> Option<&'static str> {
    ORG_RULE_KEY_LIST
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, noun)| *noun)
}

const STRING_OPS: [&str; 7] = [
    "StringEquals",
    "StringNotEquals",
    "StringEqualsIgnoreCase",
    "StringNotEqualsIgnoreCase",
    "StringLike",
    "StringNotLike",
    "StringLikeIgnoreCase",
];
const NUMERIC_OPS: [&str; 6] = [
    "NumericEquals",
    "NumericNotEquals",
    "NumericLessThan",
    "NumericLessThanEquals",
    "NumericGreaterThan",
    "NumericGreaterThanEquals",
];
const BOOL_OPS: [&str; 1] = ["Bool"];
const ARRAY_OPS: [&str; 2] = ["ArrayContains", "ArrayContainsAll"];

fn with_exists(operators: &[&str]) -> Vec<String> {
    operators
        .iter()
        .map(|operator| (*operator).to_owned())
        .chain(std::iter::once("Exists".to_owned()))
        .collect()
}

/// Keys that describe a session or a grant rather than the person, with the reason a rule cannot use them. The
/// session-derived keys (`sessionScopedPrincipalKeys`) belong here too, and so does every `principal.sessionTags.` key.
fn session_key(key: &str) -> bool {
    [
        "principal.mfa",
        "principal.sessionKind",
        "principal.authMethod",
        "principal.impersonated",
        "principal.impersonatorId",
        "principal.roles",
        "principal.tenantId",
        "principal.rootAdmin",
    ]
    .contains(&key)
        || SESSION_SCOPED_PRINCIPAL_KEYS
            .iter()
            .any(|candidate| candidate == key)
}

fn rule_key(key: &str, r#type: &str, operators: Vec<String>) -> RuleKey {
    RuleKey {
        key: key.to_owned(),
        r#type: r#type.to_owned(),
        operators,
        extra: Map::new(),
    }
}

fn attribute_type_name(attribute: &better_iam_core::AttributeType) -> &'static str {
    match attribute {
        better_iam_core::AttributeType::String => "string",
        better_iam_core::AttributeType::Number => "number",
        better_iam_core::AttributeType::Boolean => "boolean",
    }
}

/// Every key a rule may test, in a stable order: fixed keys first, then the declared identity attributes. `org`
/// adds `identity.teams` and `identity.departments` for callers that evaluate them.
pub fn rule_keys(
    identity_attributes: &IndexMap<String, better_iam_core::AttributeType>,
    options: Option<&Value>,
) -> IamResult<Vec<crate::package_rules::RuleKey>> {
    let org = truthy(crate::js::member(options, "org"));
    let mut keys = vec![
        rule_key("principal.id", "string", with_exists(&STRING_OPS)),
        rule_key("principal.kind", "string", with_exists(&STRING_OPS)),
        rule_key("principal.owner", "boolean", with_exists(&BOOL_OPS)),
        rule_key("identity.email", "string", with_exists(&STRING_OPS)),
        rule_key("identity.emailDomain", "string", with_exists(&STRING_OPS)),
        rule_key("identity.emailVerified", "boolean", with_exists(&BOOL_OPS)),
        rule_key("identity.managerId", "string", with_exists(&STRING_OPS)),
        rule_key("identity.groups", "array", with_exists(&ARRAY_OPS)),
        // Whether the person is a guest (guests.ts); a rule that never tests it does not match guests (see ruleMatch).
        rule_key("identity.guest", "boolean", with_exists(&BOOL_OPS)),
    ];
    if org {
        for (key, _) in ORG_RULE_KEY_LIST {
            keys.push(rule_key(key, "array", with_exists(&ARRAY_OPS)));
        }
    }
    let mut names: Vec<String> = identity_attributes.keys().cloned().collect();
    sort_strings(&mut names);
    for name in names {
        let attribute = &identity_attributes[&name];
        let r#type = attribute_type_name(attribute);
        let operators = match r#type {
            "string" => {
                let mut operators: Vec<&str> = STRING_OPS.to_vec();
                operators.extend(["DateBefore", "DateAfter"]);
                with_exists(&operators)
            }
            "number" => with_exists(&NUMERIC_OPS),
            _ => with_exists(&BOOL_OPS),
        };
        keys.push(rule_key(&format!("principal.{name}"), r#type, operators));
    }
    Ok(keys)
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// The valid values of an org rule key's noun (`env.org?.teams` ...): `None` when not checked.
fn org_values(env: &RuleEnvironment, noun: &str) -> Option<IndexSet<String>> {
    let member = match noun {
        "team" => "teams",
        "department" => "departments",
        _ => "licenses",
    };
    match env.org.as_ref().and_then(|org| org.get(member)) {
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect(),
        ),
        _ => None,
    }
}

/// Validates a rule against the deployment's declared attributes and (when known) the tenant's groups. Every error
/// message starts with `path`, so configuration documents point at the offending package. Values keep the scalar or
/// array form they were given, so export and plan compare canonically.
pub fn parse_auto_assign(
    value: Option<&Value>,
    env: &crate::package_rules::RuleEnvironment,
    path: Option<&str>,
) -> IamResult<crate::package_rules::AutoAssignInput> {
    let path = path.unwrap_or("autoAssign");
    let object = match value {
        Some(Value::Object(map)) if is_object(value) => map,
        _ => return Err(invalid(format!("{path} must be an object"))),
    };
    for key in js_keys(object) {
        if !["include", "exclude", "graceMs", "maxGrants", "maxRemovals"].contains(&key.as_str()) {
            return Err(invalid(format!("{path}: unknown field {key}")));
        }
    }
    let include = match object.get("include") {
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_RULE_CLAUSES => items,
        _ => {
            return Err(invalid(format!(
                "{path}.include must list 1-{MAX_RULE_CLAUSES} condition sets"
            )));
        }
    };
    let empty = Vec::new();
    let exclude = match object.get("exclude") {
        None => &empty,
        Some(Value::Array(items)) if items.len() <= MAX_RULE_CLAUSES => items,
        Some(_) => {
            return Err(invalid(format!(
                "{path}.exclude must list at most {MAX_RULE_CLAUSES} condition sets"
            )));
        }
    };
    let known_keys: IndexMap<String, RuleKey> = rule_keys(
        &env.identity_attributes,
        Some(&json!({ "org": env.org.is_some() })),
    )?
    .into_iter()
    .map(|key| (key.key.clone(), key))
    .collect();
    let mut declared: Vec<String> = env.identity_attributes.keys().cloned().collect();
    sort_strings(&mut declared);
    let clause = |item: &Value, clause_path: &str| -> IamResult<Value> {
        let map = match item {
            Value::Object(map) if is_object(Some(item)) && !map.is_empty() => map,
            _ => {
                return Err(invalid(format!(
                    "{clause_path} must be a nonempty condition set"
                )));
            }
        };
        validate_policy(&json!({
            "version": 1,
            "statements": [
                { "effect": "allow", "actions": [RULE_ACTION], "resources": ["identity/*"], "conditions": item },
            ],
        }))
        .map_err(|error| {
            IamError::new("INVALID_POLICY", format!("{clause_path}: {}", error.message))
        })?;
        for (operator, operator_entries) in entries(map) {
            let Value::Object(operator_entries) = operator_entries else {
                continue;
            };
            for (key, expected) in entries(operator_entries) {
                let Some(known) = known_keys.get(key.as_str()) else {
                    if key == "principal.groups" {
                        return Err(invalid(format!(
                            "{clause_path}: use identity.groups (memberships not created by access packages) instead of principal.groups"
                        )));
                    }
                    if session_key(key) || key.starts_with(SESSION_TAG_PREFIX) {
                        return Err(invalid(format!(
                            "{clause_path}: {key} describes a session or grant and is not available to package rules"
                        )));
                    }
                    if org_rule_noun(key).is_some() {
                        return Err(invalid(format!(
                            "{clause_path}: {key} is available to access package rules only"
                        )));
                    }
                    return Err(invalid(format!(
                        "{clause_path}: unknown key {key}; use principal.id, principal.kind, principal.owner, identity.email, identity.emailDomain, identity.emailVerified, identity.managerId, identity.groups, identity.guest, {}or principal.<declared attribute> ({})",
                        if env.org.is_some() {
                            "identity.teams, identity.departments, identity.licenses, "
                        } else {
                            ""
                        },
                        if declared.is_empty() {
                            "none declared".to_owned()
                        } else {
                            declared.join(", ")
                        }
                    )));
                };
                if !known
                    .operators
                    .iter()
                    .any(|candidate| candidate == operator)
                {
                    return Err(invalid(format!(
                        "{clause_path}: {operator} cannot test {key} ({}); use {}",
                        known.r#type,
                        known.operators.join(", ")
                    )));
                }
                let values: Vec<&Value> = match expected {
                    Value::Array(items) => items.iter().collect(),
                    single => vec![single],
                };
                if values
                    .iter()
                    .any(|entry| entry.as_str().is_some_and(|text| text.contains("${")))
                {
                    return Err(invalid(format!(
                        "{clause_path}: policy variables are not available in package rules"
                    )));
                }
                if key == "principal.kind"
                    && [
                        "StringEquals",
                        "StringNotEquals",
                        "StringEqualsIgnoreCase",
                        "StringNotEqualsIgnoreCase",
                    ]
                    .contains(&operator.as_str())
                    && values.iter().any(|entry| match entry.as_str() {
                        Some(text) => !["user", "service"].contains(&text.to_lowercase().as_str()),
                        None => true,
                    })
                {
                    return Err(invalid(format!(
                        "{clause_path}: principal.kind is 'user' or 'service'"
                    )));
                }
                if key == "identity.groups" && operator != "Exists" {
                    for entry in &values {
                        let Some(entry) = entry.as_str() else {
                            return Err(invalid(format!(
                                "{clause_path}: identity.groups lists groups"
                            )));
                        };
                        if env
                            .groups
                            .as_ref()
                            .is_some_and(|groups| !groups.contains(entry))
                        {
                            return Err(invalid(format!("{clause_path}: unknown group {entry}")));
                        }
                        if env
                            .packaged_groups
                            .as_ref()
                            .is_some_and(|groups| groups.contains(entry))
                        {
                            return Err(invalid(format!(
                                "{clause_path}: identity.groups cannot name {entry}, a group this package grants"
                            )));
                        }
                    }
                }
                if let Some(noun) = org_rule_noun(key).filter(|_| operator != "Exists") {
                    let valid = org_values(env, noun);
                    for entry in &values {
                        let Some(entry) = entry.as_str() else {
                            return Err(invalid(format!("{clause_path}: {key} lists {noun}s")));
                        };
                        if valid.as_ref().is_some_and(|valid| !valid.contains(entry)) {
                            return Err(invalid(format!("{clause_path}: unknown {noun} {entry}")));
                        }
                    }
                }
            }
        }
        Ok(item.clone())
    };
    let mut parsed_include = Vec::new();
    for (index, item) in include.iter().enumerate() {
        parsed_include.push(clause(item, &format!("{path}.include[{index}]"))?);
    }
    let mut parsed_exclude = Vec::new();
    for (index, item) in exclude.iter().enumerate() {
        parsed_exclude.push(clause(item, &format!("{path}.exclude[{index}]"))?);
    }
    let size = utf16_len(&stringify(&json!({
        "include": parsed_include,
        "exclude": parsed_exclude,
    })));
    if size > MAX_RULE_BYTES {
        return Err(invalid(format!(
            "{path} is larger than {MAX_RULE_BYTES} bytes"
        )));
    }
    let grace_ms = match object.get("graceMs") {
        None => None,
        Some(value) => Some(integer(
            Some(value),
            &format!("{path}.graceMs"),
            0.0,
            MAX_GRACE_MS,
        )?),
    };
    let max_grants = match object.get("maxGrants") {
        None => None,
        Some(value) => Some(integer(
            Some(value),
            &format!("{path}.maxGrants"),
            1.0,
            100_000.0,
        )?),
    };
    let max_removals = match object.get("maxRemovals") {
        None => None,
        Some(value) => Some(integer(
            Some(value),
            &format!("{path}.maxRemovals"),
            1.0,
            100_000.0,
        )?),
    };
    Ok(AutoAssignInput {
        include: parsed_include,
        exclude: (!parsed_exclude.is_empty()).then_some(parsed_exclude),
        grace_ms: grace_ms.filter(|grace| *grace != 0.0),
        max_grants,
        max_removals,
        extra: Map::new(),
    })
}

/// The clauses of a rule (`rule.include` and `rule.exclude ?? []`); members that are not arrays hold none.
fn clauses_of(rule: &Value) -> (Vec<&Value>, Vec<&Value>) {
    let list = |key: &str| -> Vec<&Value> {
        match rule.get(key) {
            Some(Value::Array(items)) => items.iter().collect(),
            _ => Vec::new(),
        }
    };
    (list("include"), list("exclude"))
}

/// The administrator-written part of a stored rule (or a rule input), without runtime state.
pub fn rule_input(rule: &Value) -> IamResult<crate::package_rules::AutoAssignInput> {
    let (include, exclude) = clauses_of(rule);
    let number = |key: &str| rule.get(key).and_then(crate::js::as_number);
    Ok(AutoAssignInput {
        include: include.into_iter().cloned().collect(),
        exclude: (!exclude.is_empty()).then(|| exclude.into_iter().cloned().collect()),
        grace_ms: number("graceMs").filter(|grace| *grace != 0.0 && !grace.is_nan()),
        max_grants: number("maxGrants"),
        max_removals: number("maxRemovals"),
        extra: Map::new(),
    })
}

/// The reason a stored rule no longer validates (an attribute declaration removed, a group gone), if any.
pub fn rule_problem(
    rule: &Value,
    env: &crate::package_rules::RuleEnvironment,
) -> IamResult<Option<String>> {
    let input = rule_input(rule)?.to_value();
    Ok(match parse_auto_assign(Some(&input), env, None) {
        Ok(_) => None,
        Err(error) => Some(error.message),
    })
}

/// `stableJson(value)`: JSON with object members sorted by key, so equal rules compare equal.
fn stable_json(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut members: Vec<(&String, &Value)> = map.iter().collect();
                members.sort_by(|a, b| crate::js::cmp_utf16(a.0, b.0));
                Value::Object(
                    members
                        .into_iter()
                        .map(|(key, item)| (key.clone(), sorted(item)))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    stringify(&sorted(value))
}

/// Whether two rules say the same thing (runtime state ignored).
pub fn same_rule_input(a: &Value, b: &Value) -> IamResult<bool> {
    Ok(stable_json(&rule_input(a)?.to_value()) == stable_json(&rule_input(b)?.to_value()))
}

fn conditions_of(item: &Value) -> IamResult<Conditions> {
    serde_json::from_value(item.clone()).map_err(|_| {
        IamError::with_status("STORAGE_CORRUPT", "Record does not match its type", 500)
    })
}

/// Include clauses become allow statements and exclude clauses deny statements of one policy document.
pub fn rule_document(rule: &Value) -> IamResult<better_iam_core::PolicyDocument> {
    let (include, exclude) = clauses_of(rule);
    let mut statements = Vec::new();
    for (index, conditions) in include.into_iter().enumerate() {
        statements.push(PolicyStatement {
            sid: Some(format!("include-{index}")),
            effect: Effect::Allow,
            actions: vec![RULE_ACTION.to_owned()],
            resources: vec!["identity/*".to_owned()],
            conditions: Some(conditions_of(conditions)?),
        });
    }
    for (index, conditions) in exclude.into_iter().enumerate() {
        statements.push(PolicyStatement {
            sid: Some(format!("exclude-{index}")),
            effect: Effect::Deny,
            actions: vec![RULE_ACTION.to_owned()],
            resources: vec!["identity/*".to_owned()],
            conditions: Some(conditions_of(conditions)?),
        });
    }
    Ok(PolicyDocument::new(statements))
}

/// The context a rule sees: the identity's declared attributes and fixed facts, and its group memberships that no
/// access package created (so rules never chain onto another package or keep themselves alive). No session,
/// request, or resource keys: a scheduler cannot replay them, and a preview must equal a reconcile. `org` supplies
/// `identity.teams` and `identity.departments` where the caller evaluates them, and `identity.licenses` with them.
pub fn rule_context(
    identity: &better_iam_core::Identity,
    direct_group_ids: &Value,
    org: Option<&crate::package_rules::RuleOrgFacts>,
) -> IamResult<Map<String, Value>> {
    let sorted_unique = |items: Vec<String>| -> Value {
        let mut items = crate::js::unique(items);
        sort_strings(&mut items);
        Value::Array(items.into_iter().map(Value::String).collect())
    };
    let mut context = Map::new();
    if let Some(attributes) = &identity.attributes {
        for (key, value) in entries(attributes) {
            context.insert(format!("principal.{key}"), value.clone());
        }
    }
    context.insert("principal.id".into(), Value::String(identity.id.clone()));
    context.insert(
        "principal.kind".into(),
        serde_json::to_value(identity.kind).unwrap_or(Value::Null),
    );
    context.insert("principal.owner".into(), Value::Bool(identity.owner));
    if let Some(email) = identity.email.as_deref().filter(|email| !email.is_empty()) {
        let email = email.to_lowercase();
        let domain = match email.rfind('@') {
            Some(at) => email[at + 1..].to_owned(),
            None => email.clone(),
        };
        context.insert("identity.email".into(), Value::String(email));
        context.insert("identity.emailDomain".into(), Value::String(domain));
    }
    context.insert(
        "identity.emailVerified".into(),
        Value::Bool(identity.email_verified),
    );
    if let Some(manager_id) = identity.manager_id.as_deref().filter(|id| !id.is_empty()) {
        context.insert(
            "identity.managerId".into(),
            Value::String(manager_id.to_owned()),
        );
    }
    let groups: Vec<String> = match direct_group_ids {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };
    context.insert("identity.groups".into(), sorted_unique(groups));
    context.insert(
        "identity.guest".into(),
        Value::Bool(identity.guest.is_some()),
    );
    if let Some(org) = org {
        context.insert("identity.teams".into(), sorted_unique(org.teams.clone()));
        context.insert(
            "identity.departments".into(),
            sorted_unique(org.departments.clone()),
        );
        context.insert(
            "identity.licenses".into(),
            sorted_unique(org.licenses.clone().unwrap_or_default()),
        );
    }
    Ok(context)
}

/// Whether any clause of a compiled rule tests `identity.guest`.
fn tests_guest(document: &PolicyDocument) -> bool {
    document.statements.iter().any(|statement| {
        statement.conditions.as_ref().is_some_and(|conditions| {
            conditions
                .values()
                .any(|entries| entries.contains_key("identity.guest"))
        })
    })
}

/// Evaluates a compiled rule for one identity; `matchedBy`/`excludedBy` name the clauses that held. Guests
/// (guests.ts) match only rules that test `identity.guest` somewhere: a rule written for members (`principal.kind:
/// user`) never reaches people from outside the organization.
pub fn rule_match(
    document: &better_iam_core::PolicyDocument,
    identity: &better_iam_core::Identity,
    context: &Map<String, Value>,
) -> IamResult<crate::package_rules::RuleMatch> {
    if identity.guest.is_some() && !tests_guest(document) {
        return Ok(RuleMatch {
            matched: false,
            matched_by: Vec::new(),
            excluded_by: Vec::new(),
            extra: Map::new(),
        });
    }
    let decision = evaluate_policy(&EvaluationInput {
        action: RULE_ACTION.to_owned(),
        resource: format!("identity/{}", identity.id),
        context: Some(context.clone()),
        grants: vec![document.clone()],
        boundaries: None,
    })?;
    let sids: Vec<String> = decision
        .matched
        .iter()
        .map(|entry| entry.split(':').skip(2).collect::<Vec<_>>().join(":"))
        .collect();
    Ok(RuleMatch {
        matched: decision.allowed,
        matched_by: sids
            .iter()
            .filter(|sid| sid.starts_with("include-"))
            .cloned()
            .collect(),
        excluded_by: sids
            .iter()
            .filter(|sid| sid.starts_with("exclude-"))
            .cloned()
            .collect(),
        extra: Map::new(),
    })
}

/// `operatorsOf(clause)`: the operator blocks of a clause in property order.
fn operators_of(clause: &Value) -> Vec<(&String, &Map<String, Value>)> {
    match clause {
        Value::Object(map) => entries(map)
            .into_iter()
            .filter_map(|(operator, block)| block.as_object().map(|block| (operator, block)))
            .collect(),
        _ => Vec::new(),
    }
}

/// Keys fixed when an identity is created (or moved only by an ownership transfer); other `principal.` keys are
/// attributes.
const FIXED_PRINCIPAL_KEYS: [&str; 3] = ["principal.id", "principal.kind", "principal.owner"];

/// Advice, not errors: rules that also match service accounts, email tests that accept unverified addresses, and
/// clauses on facts that callers with fewer rights than the rule's owner control. A rule grants under its owner's
/// authority to whoever matches, so whoever sets those facts picks the recipients: declared attributes and
/// identity.managerId (iam:identities:update), and memberships of groups without role bindings (iam:groups:update
/// alone; adding to a group with bindings needs their authorities). `bound_groups` holds the tenant's groups that
/// have role bindings; without it, groups are not checked.
pub fn rule_warnings(
    rule: &Value,
    bound_groups: Option<&IndexSet<String>>,
) -> IamResult<Vec<String>> {
    let mut warnings: Vec<String> = Vec::new();
    let controlled = |warnings: &mut Vec<String>, clause: &Value, path: &str, consequence: &str| {
        let mut keys: Vec<String> =
            crate::js::unique(operators_of(clause).into_iter().flat_map(|(_, block)| {
                js_keys(block)
                    .into_iter()
                    .filter(|key| {
                        key.as_str() == "identity.managerId"
                            || (key.starts_with("principal.")
                                && !FIXED_PRINCIPAL_KEYS.contains(&key.as_str()))
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            }));
        sort_strings(&mut keys);
        if !keys.is_empty() {
            warnings.push(format!(
                "{path} tests {}, which anyone holding iam:identities:update can set, so {consequence}",
                keys.join(", ")
            ));
        }
        let unbound: Vec<String> = match bound_groups {
            Some(bound) => clause_values(&[clause], "identity.groups")
                .into_iter()
                .filter(|group_id| !bound.contains(group_id))
                .collect(),
            None => Vec::new(),
        };
        if !unbound.is_empty() {
            warnings.push(format!(
                "{path} tests identity.groups for {}, {} without role bindings whose members anyone holding iam:groups:update can change, so {consequence}",
                unbound.join(", "),
                if unbound.len() == 1 { "a group" } else { "groups" }
            ));
        }
        // Seats follow license assignments (licenses.ts) and, for a product assigned to a group, that group's members:
        // the groups API asks for iam:licenses:assign there too, but a team's maintainers and directory sync change
        // members.
        if operators_of(clause)
            .iter()
            .any(|(_, block)| block.contains_key("identity.licenses"))
        {
            warnings.push(format!(
                "{path} tests identity.licenses, which anyone holding iam:licenses:assign can change, as can whoever manages the members of a group a product is assigned to without it (a team's maintainers, directory sync), so {consequence}"
            ));
        }
    };
    let (include, exclude) = clauses_of(rule);
    // Testing identity.guest anywhere lets guests match the whole rule (see ruleMatch), not only that clause.
    let guest_tested = include.iter().chain(exclude.iter()).any(|clause| {
        operators_of(clause)
            .iter()
            .any(|(_, block)| block.contains_key("identity.guest"))
    });
    for (index, clause) in include.iter().enumerate() {
        let tests = operators_of(clause);
        if guest_tested
            && !tests
                .iter()
                .any(|(_, block)| block.contains_key("identity.guest"))
        {
            warnings.push(format!(
                "include[{index}] does not test identity.guest while the rule does elsewhere, so it also matches guests"
            ));
        }
        if !tests.iter().any(|(operator, block)| {
            operator.starts_with("String") && block.contains_key("principal.kind")
        }) {
            warnings.push(format!(
                "include[{index}] does not test principal.kind, so it also matches service accounts"
            ));
        }
        let email = tests.iter().any(|(_, block)| {
            block.contains_key("identity.email") || block.contains_key("identity.emailDomain")
        });
        let verified = clause
            .get("Bool")
            .and_then(|block| block.get("identity.emailVerified"))
            == Some(&Value::Bool(true));
        if email && !verified {
            warnings.push(format!(
                "include[{index}] tests an email address without requiring Bool identity.emailVerified: true, so unverified addresses match (SCIM-provisioned and administrator-set addresses are unverified)"
            ));
        }
        controlled(
            &mut warnings,
            clause,
            &format!("include[{index}]"),
            "they choose who receives this package under its owner\u{2019}s authority",
        );
    }
    for (index, clause) in exclude.iter().enumerate() {
        controlled(
            &mut warnings,
            clause,
            &format!("exclude[{index}]"),
            "they can lift the exclusion",
        );
    }
    Ok(warnings)
}

/// The string values the clauses test an array key for (`ArrayContains` and `ArrayContainsAll`), first seen first.
fn clause_values(clauses: &[&Value], key: &str) -> Vec<String> {
    let mut found: IndexSet<String> = IndexSet::new();
    for clause in clauses {
        for (operator, block) in operators_of(clause) {
            if operator != "ArrayContains" && operator != "ArrayContainsAll" {
                continue;
            }
            match block.get(key) {
                Some(Value::Array(items)) => {
                    for value in items {
                        if let Some(value) = value.as_str() {
                            found.insert(value.to_owned());
                        }
                    }
                }
                Some(Value::String(value)) => {
                    found.insert(value.clone());
                }
                _ => {}
            }
        }
    }
    found.into_iter().collect()
}

/// The values a rule tests an array key (identity.groups, identity.teams, identity.departments) for.
pub fn rule_values(rule: Option<&Value>, key: &str) -> IamResult<Vec<String>> {
    let Some(rule) = rule else {
        return Ok(Vec::new());
    };
    let (include, exclude) = clauses_of(rule);
    let clauses: Vec<&Value> = include.into_iter().chain(exclude).collect();
    Ok(clause_values(&clauses, key))
}

/// The group IDs (or names) a rule tests with identity.groups.
pub fn rule_group_ids(rule: Option<&Value>) -> IamResult<Vec<String>> {
    rule_values(rule, "identity.groups")
}

/// A copy of a rule with the values it tests an array key for mapped (IDs to names for export, names to IDs for
/// apply).
pub fn map_rule_values(rule: &Value, key: &str, map: &dyn Fn(&str) -> String) -> IamResult<Value> {
    let mut clone = rule.clone();
    for list in ["include", "exclude"] {
        let Some(Value::Array(clauses)) = clone.get_mut(list) else {
            continue;
        };
        for clause in clauses {
            let Value::Object(operators) = clause else {
                continue;
            };
            for (operator, block) in operators.iter_mut() {
                if operator != "ArrayContains" && operator != "ArrayContainsAll" {
                    continue;
                }
                let Some(expected) = block.get_mut(key) else {
                    continue;
                };
                match expected {
                    Value::Array(items) => {
                        for item in items {
                            if let Value::String(value) = item {
                                *value = map(value);
                            }
                        }
                    }
                    Value::String(value) => *value = map(value),
                    _ => {}
                }
            }
        }
    }
    Ok(clone)
}

/// A copy of a rule with its identity.groups values mapped (IDs to names for export, names to IDs for apply).
pub fn map_rule_groups(rule: &Value, map: &dyn Fn(&str) -> String) -> IamResult<Value> {
    map_rule_values(rule, "identity.groups", map)
}
