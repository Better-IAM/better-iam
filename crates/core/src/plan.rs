//! Query planning (partial evaluation) (`plan.ts`): which resources of one type may a principal perform one action
//! on, as a filter over the resource's `id` and attributes that a database can apply. A resource passes the filter
//! exactly when [`crate::policy::evaluate_policy`] would allow it (except refusals for exceeding the evaluation work
//! budget, which a database has no equivalent of).

use std::cell::Cell;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::js;
use crate::policy::{
    ConditionOperator, Context, Effect, EvaluationInput, PolicyDocument, PolicyStatement,
    evaluate_policy, match_pattern, resolve_policy_value, validate_policy, variable_at,
};
use crate::{IamError, IamResult};

/// A value a filter compares with (`FilterValue`).
#[derive(Debug, Clone, PartialEq)]
pub enum FilterValue {
    String(String),
    Number(f64),
    Bool(bool),
}

impl FilterValue {
    pub fn to_value(&self) -> Value {
        match self {
            FilterValue::String(text) => Value::String(text.clone()),
            FilterValue::Number(number) => js::number(*number).unwrap_or(Value::Null),
            FilterValue::Bool(flag) => Value::Bool(*flag),
        }
    }

    pub fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::String(text) => Some(FilterValue::String(text.clone())),
            Value::Number(number) => Some(FilterValue::Number(js::number_value(number))),
            Value::Bool(flag) => Some(FilterValue::Bool(*flag)),
            _ => None,
        }
    }

    /// `===` between filter values (numbers as doubles).
    pub fn same(&self, other: &FilterValue) -> bool {
        match (self, other) {
            (FilterValue::String(a), FilterValue::String(b)) => a == b,
            (FilterValue::Number(a), FilterValue::Number(b)) => a == b,
            (FilterValue::Bool(a), FilterValue::Bool(b)) => a == b,
            _ => false,
        }
    }
}

/// The type a `type` filter tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterType {
    String,
    Number,
    Boolean,
    /// A string that is an IP address.
    Ip,
}

impl FilterType {
    pub fn as_str(self) -> &'static str {
        match self {
            FilterType::String => "string",
            FilterType::Number => "number",
            FilterType::Boolean => "boolean",
            FilterType::Ip => "ip",
        }
    }
}

/// A numeric comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOperator {
    Lt,
    Le,
    Gt,
    Ge,
}

impl CompareOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            CompareOperator::Lt => "lt",
            CompareOperator::Le => "le",
            CompareOperator::Gt => "gt",
            CompareOperator::Ge => "ge",
        }
    }
}

/// A date comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateOperator {
    Before,
    After,
}

impl DateOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            DateOperator::Before => "before",
            DateOperator::After => "after",
        }
    }
}

/// A filter over one resource: its `id` and its attributes by name (`ResourceFilter`). A field that is absent (or
/// SQL `NULL`) satisfies nothing but `not exists`.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceFilter {
    True,
    False,
    And(Vec<ResourceFilter>),
    Or(Vec<ResourceFilter>),
    Not(Box<ResourceFilter>),
    /// The field is present.
    Exists {
        field: String,
    },
    /// The field holds a value of this type.
    Type {
        field: String,
        kind: FilterType,
    },
    /// The field equals one of the values, compared with the value's type (strings optionally ignoring case).
    Equals {
        field: String,
        values: Vec<FilterValue>,
        ignore_case: bool,
    },
    /// A numeric comparison.
    Compare {
        field: String,
        operator: CompareOperator,
        value: f64,
    },
    /// A glob over a string field: `*` any run, `?` one character, `\` escapes the next character.
    Like {
        field: String,
        pattern: String,
        ignore_case: bool,
    },
    /// An ISO 8601 timestamp field before or after a moment.
    Date {
        field: String,
        operator: DateOperator,
        value: String,
    },
    /// An IP address field inside a network (an address or CIDR block).
    Ip {
        field: String,
        network: String,
    },
    /// An array field contains the value.
    Contains {
        field: String,
        value: FilterValue,
    },
}

impl ResourceFilter {
    /// The `kind` member.
    pub fn kind(&self) -> &'static str {
        match self {
            ResourceFilter::True => "true",
            ResourceFilter::False => "false",
            ResourceFilter::And(_) => "and",
            ResourceFilter::Or(_) => "or",
            ResourceFilter::Not(_) => "not",
            ResourceFilter::Exists { .. } => "exists",
            ResourceFilter::Type { .. } => "type",
            ResourceFilter::Equals { .. } => "equals",
            ResourceFilter::Compare { .. } => "compare",
            ResourceFilter::Like { .. } => "like",
            ResourceFilter::Date { .. } => "date",
            ResourceFilter::Ip { .. } => "ip",
            ResourceFilter::Contains { .. } => "contains",
        }
    }

    /// The filter as the TypeScript object, members in the order the TypeScript constructors write them.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("kind".into(), Value::String(self.kind().into()));
        let text = |value: &str| Value::String(value.to_owned());
        match self {
            ResourceFilter::True | ResourceFilter::False => {}
            ResourceFilter::And(filters) | ResourceFilter::Or(filters) => {
                map.insert(
                    "filters".into(),
                    Value::Array(filters.iter().map(Self::to_value).collect()),
                );
            }
            ResourceFilter::Not(filter) => {
                map.insert("filter".into(), filter.to_value());
            }
            ResourceFilter::Exists { field } => {
                map.insert("field".into(), text(field));
            }
            ResourceFilter::Type { field, kind } => {
                map.insert("field".into(), text(field));
                map.insert("type".into(), text(kind.as_str()));
            }
            ResourceFilter::Equals {
                field,
                values,
                ignore_case,
            } => {
                map.insert("field".into(), text(field));
                map.insert(
                    "values".into(),
                    Value::Array(values.iter().map(FilterValue::to_value).collect()),
                );
                if *ignore_case {
                    map.insert("ignoreCase".into(), Value::Bool(true));
                }
            }
            ResourceFilter::Compare {
                field,
                operator,
                value,
            } => {
                map.insert("field".into(), text(field));
                map.insert("operator".into(), text(operator.as_str()));
                map.insert("value".into(), js::number(*value).unwrap_or(Value::Null));
            }
            ResourceFilter::Like {
                field,
                pattern,
                ignore_case,
            } => {
                map.insert("field".into(), text(field));
                map.insert("pattern".into(), text(pattern));
                if *ignore_case {
                    map.insert("ignoreCase".into(), Value::Bool(true));
                }
            }
            ResourceFilter::Date {
                field,
                operator,
                value,
            } => {
                map.insert("field".into(), text(field));
                map.insert("operator".into(), text(operator.as_str()));
                map.insert("value".into(), text(value));
            }
            ResourceFilter::Ip { field, network } => {
                map.insert("field".into(), text(field));
                map.insert("network".into(), text(network));
            }
            ResourceFilter::Contains { field, value } => {
                map.insert("field".into(), text(field));
                map.insert("value".into(), value.to_value());
            }
        }
        Value::Object(map)
    }

    /// Reads the TypeScript object form; None for anything that is not a filter.
    pub fn from_value(value: &Value) -> Option<Self> {
        let field = || {
            value
                .get("field")
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let ignore_case = value
            .get("ignoreCase")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let list = || -> Option<Vec<ResourceFilter>> {
            value
                .get("filters")?
                .as_array()?
                .iter()
                .map(ResourceFilter::from_value)
                .collect()
        };
        Some(match value.get("kind")?.as_str()? {
            "true" => ResourceFilter::True,
            "false" => ResourceFilter::False,
            "and" => ResourceFilter::And(list()?),
            "or" => ResourceFilter::Or(list()?),
            "not" => {
                ResourceFilter::Not(Box::new(ResourceFilter::from_value(value.get("filter")?)?))
            }
            "exists" => ResourceFilter::Exists { field: field()? },
            "type" => ResourceFilter::Type {
                field: field()?,
                kind: match value.get("type")?.as_str()? {
                    "string" => FilterType::String,
                    "number" => FilterType::Number,
                    "boolean" => FilterType::Boolean,
                    "ip" => FilterType::Ip,
                    _ => return None,
                },
            },
            "equals" => ResourceFilter::Equals {
                field: field()?,
                values: value
                    .get("values")?
                    .as_array()?
                    .iter()
                    .map(FilterValue::from_value)
                    .collect::<Option<_>>()?,
                ignore_case,
            },
            "compare" => ResourceFilter::Compare {
                field: field()?,
                operator: match value.get("operator")?.as_str()? {
                    "lt" => CompareOperator::Lt,
                    "le" => CompareOperator::Le,
                    "gt" => CompareOperator::Gt,
                    "ge" => CompareOperator::Ge,
                    _ => return None,
                },
                value: js::as_number(value.get("value")?)?,
            },
            "like" => ResourceFilter::Like {
                field: field()?,
                pattern: value.get("pattern")?.as_str()?.to_owned(),
                ignore_case,
            },
            "date" => ResourceFilter::Date {
                field: field()?,
                operator: match value.get("operator")?.as_str()? {
                    "before" => DateOperator::Before,
                    "after" => DateOperator::After,
                    _ => return None,
                },
                value: value.get("value")?.as_str()?.to_owned(),
            },
            "ip" => ResourceFilter::Ip {
                field: field()?,
                network: value.get("network")?.as_str()?.to_owned(),
            },
            "contains" => ResourceFilter::Contains {
                field: field()?,
                value: FilterValue::from_value(value.get("value")?)?,
            },
            _ => return None,
        })
    }
}

impl Serialize for ResourceFilter {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResourceFilter {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        ResourceFilter::from_value(&value)
            .ok_or_else(|| serde::de::Error::custom("Invalid resource filter"))
    }
}

/// `ResourcePlan.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanKind {
    Always,
    Never,
    Conditional,
}

/// The planner's answer: every resource, none, or those that pass `filter` (`ResourcePlan`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourcePlan {
    pub kind: PlanKind,
    pub filter: ResourceFilter,
}

/// One way a principal holds grants: the grant documents and the ceilings that bound them (`PlanPath`).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PlanPath {
    pub grants: Vec<PolicyDocument>,
    pub boundaries: Vec<PolicyDocument>,
}

/// Relationship tuples the principal holds on one resource (`PlanRelation`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRelation {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub relations: Vec<String>,
}

/// `PlanInput`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanInput {
    pub action: String,
    /// The resource type planned for; `resource.type` of every candidate.
    pub resource_type: String,
    /// `resource.tenantId` of every candidate.
    pub tenant_id: String,
    /// Principal, request and tenant keys, as the decision's context holds them (no resource keys).
    pub context: Context,
    /// Deny statements that apply across grant paths.
    pub denies: Vec<PolicyDocument>,
    /// Ceilings over every path.
    pub boundaries: Vec<PolicyDocument>,
    /// Grant paths; a resource is allowed through any one of them.
    pub paths: Vec<PlanPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relations: Option<Vec<PlanRelation>>,
    /// Mandatory access control, AND-ed with the whole plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<ResourceFilter>,
    /// Resource keys the server derives per resource; a statement conditioning on one refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_resource_keys: Option<Vec<String>>,
}

// --- filter constructors -------------------------------------------------------------------------

/// The filter every resource passes (`trueFilter`).
pub const TRUE_FILTER: ResourceFilter = ResourceFilter::True;
/// The filter no resource passes (`falseFilter`).
pub const FALSE_FILTER: ResourceFilter = ResourceFilter::False;

fn key(filter: &ResourceFilter) -> String {
    js::stringify(&filter.to_value())
}

/// An insertion-ordered map keyed by string (`Map<string, ResourceFilter>`).
#[derive(Default)]
struct Kept {
    entries: Vec<(String, ResourceFilter)>,
}

impl Kept {
    fn set(&mut self, key: String, filter: ResourceFilter) {
        match self
            .entries
            .iter_mut()
            .find(|(existing, _)| *existing == key)
        {
            Some(entry) => entry.1 = filter,
            None => self.entries.push((key, filter)),
        }
    }
}

/// Conjunction, simplified (`andFilter`): nested ands flattened, `true` dropped, `false` absorbing, duplicates
/// removed.
pub fn and_filter(filters: Vec<ResourceFilter>) -> ResourceFilter {
    let mut kept = Kept::default();
    for filter in filters.into_iter().flat_map(|item| match item {
        ResourceFilter::And(items) => items,
        other => vec![other],
    }) {
        match filter {
            ResourceFilter::False => return ResourceFilter::False,
            ResourceFilter::True => continue,
            filter => kept.set(key(&filter), filter),
        }
    }
    let mut items: Vec<ResourceFilter> =
        kept.entries.into_iter().map(|(_, filter)| filter).collect();
    match items.len() {
        0 => ResourceFilter::True,
        1 => items.remove(0),
        _ => ResourceFilter::And(items),
    }
}

/// Disjunction, simplified (`orFilter`): nested ors flattened, `false` dropped, `true` absorbing, duplicates
/// removed, and `equals` on the same field (and case rule) merged into one value list.
pub fn or_filter(filters: Vec<ResourceFilter>) -> ResourceFilter {
    let mut kept = Kept::default();
    for filter in filters.into_iter().flat_map(|item| match item {
        ResourceFilter::Or(items) => items,
        other => vec![other],
    }) {
        match filter {
            ResourceFilter::True => return ResourceFilter::True,
            ResourceFilter::False => continue,
            ResourceFilter::Equals {
                field,
                values,
                ignore_case,
            } => {
                let slot = format!("equals:{field}\u{0}{}", if ignore_case { 1 } else { 0 });
                if let Some((_, ResourceFilter::Equals { values: merged, .. })) = kept
                    .entries
                    .iter_mut()
                    .find(|(existing, _)| *existing == slot)
                {
                    for value in values {
                        if !merged.iter().any(|item| item.same(&value)) {
                            merged.push(value);
                        }
                    }
                } else {
                    kept.set(
                        slot,
                        ResourceFilter::Equals {
                            field,
                            values,
                            ignore_case,
                        },
                    );
                }
            }
            filter => kept.set(key(&filter), filter),
        }
    }
    let mut items: Vec<ResourceFilter> =
        kept.entries.into_iter().map(|(_, filter)| filter).collect();
    match items.len() {
        0 => ResourceFilter::False,
        1 => items.remove(0),
        _ => ResourceFilter::Or(items),
    }
}

/// Negation, simplified (`notFilter`): constants flip and a double negation cancels.
pub fn not_filter(filter: ResourceFilter) -> ResourceFilter {
    match filter {
        ResourceFilter::True => ResourceFilter::False,
        ResourceFilter::False => ResourceFilter::True,
        ResourceFilter::Not(inner) => *inner,
        other => ResourceFilter::Not(Box::new(other)),
    }
}

fn exists(field: &str) -> ResourceFilter {
    ResourceFilter::Exists {
        field: field.to_owned(),
    }
}

fn typed(field: &str, kind: FilterType) -> ResourceFilter {
    ResourceFilter::Type {
        field: field.to_owned(),
        kind,
    }
}

fn equals_filter(field: &str, values: Vec<FilterValue>, ignore_case: bool) -> ResourceFilter {
    if values.is_empty() {
        return ResourceFilter::False;
    }
    let mut unique: Vec<FilterValue> = Vec::new();
    for value in values {
        if !unique.iter().any(|item| item.same(&value)) {
            unique.push(value);
        }
    }
    ResourceFilter::Equals {
        field: field.to_owned(),
        values: unique,
        ignore_case,
    }
}

// --- globs ---------------------------------------------------------------------------------------

/// One element of a glob (`GlobToken`): a star, a single-character wildcard, or a literal character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobToken {
    Star,
    Any,
    Char(char),
}

impl GlobToken {
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        match self {
            GlobToken::Star => {
                map.insert("kind".into(), Value::String("star".into()));
            }
            GlobToken::Any => {
                map.insert("kind".into(), Value::String("any".into()));
            }
            GlobToken::Char(c) => {
                map.insert("kind".into(), Value::String("char".into()));
                map.insert("value".into(), Value::String(c.to_string()));
            }
        }
        Value::Object(map)
    }
}

fn glob_tokens(pattern: &str, into: &mut Vec<GlobToken>) {
    for c in pattern.chars() {
        into.push(match c {
            '*' => GlobToken::Star,
            '?' => GlobToken::Any,
            c => GlobToken::Char(c),
        });
    }
}

const CONSTANT_RESOURCE_KEYS: [&str; 3] = [
    "resource.tenantId",
    "resource.relations",
    "resource.parentRelations",
];

/// A variable whose value is the resource's own: it differs from row to row.
fn row_variable(name: &str) -> bool {
    name.starts_with("resource.") && !CONSTANT_RESOURCE_KEYS.contains(&name)
}

/// Whether a pattern or condition value refers to a row-dependent variable (`${resource.owner}`).
fn has_row_variable(value: &str) -> bool {
    let mut search = 0;
    while let Some(found) = value[search..].find("${") {
        let index = search + found;
        match variable_at(value, index) {
            None => search = index + 2,
            Some((name, length)) => {
                if row_variable(name) {
                    return true;
                }
                search = index + length;
            }
        }
    }
    false
}

/// A pattern's tokens with variables substituted from context; None when unresolved. With `row_as_star`, a
/// row-dependent variable becomes a star.
fn tokenize(pattern: &str, context: &Context, row_as_star: bool) -> Option<Vec<GlobToken>> {
    let mut tokens = Vec::new();
    let mut cursor = 0;
    let mut search = 0;
    while let Some(found) = pattern[search..].find("${") {
        let index = search + found;
        let Some((name, length)) = variable_at(pattern, index) else {
            search = index + 2;
            continue;
        };
        glob_tokens(&pattern[cursor..index], &mut tokens);
        if row_as_star && row_variable(name) {
            tokens.push(GlobToken::Star);
        } else {
            let value = crate::policy::substitution(context.get(name))?;
            tokens.extend(value.chars().map(GlobToken::Char));
        }
        cursor = index + length;
        search = cursor;
    }
    glob_tokens(&pattern[cursor..], &mut tokens);
    Some(tokens)
}

/// Tokens as a filter glob: wildcards as `*` / `?`, literal `*`, `?` and `\` escaped with `\`.
fn glob_string(tokens: &[GlobToken]) -> String {
    let mut out = String::new();
    for token in tokens {
        match token {
            GlobToken::Star => out.push('*'),
            GlobToken::Any => out.push('?'),
            GlobToken::Char(c) => {
                if matches!(c, '*' | '?' | '\\') {
                    out.push('\\');
                }
                out.push(*c);
            }
        }
    }
    out
}

/// A filter glob back into tokens (`parseGlob`, the inverse of `globString`).
pub fn parse_glob(pattern: &str) -> Vec<GlobToken> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if c == '\\' && index + 1 < chars.len() {
            index += 1;
            tokens.push(GlobToken::Char(chars[index]));
        } else if c == '*' {
            tokens.push(GlobToken::Star);
        } else if c == '?' {
            tokens.push(GlobToken::Any);
        } else {
            tokens.push(GlobToken::Char(c));
        }
        index += 1;
    }
    tokens
}

/// Glob matching over code points, greedy with backtracking to the last star (`globMatches`).
pub fn glob_matches(tokens: &[GlobToken], value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    let (mut p, mut v, mut star, mut retry) = (0usize, 0usize, None::<usize>, 0usize);
    while v < chars.len() {
        match tokens.get(p) {
            Some(GlobToken::Any) => {
                p += 1;
                v += 1;
            }
            Some(GlobToken::Char(c)) if *c == chars[v] => {
                p += 1;
                v += 1;
            }
            Some(GlobToken::Star) => {
                star = Some(p);
                p += 1;
                retry = v;
            }
            _ => match star {
                Some(star) => {
                    p = star + 1;
                    retry += 1;
                    v = retry;
                }
                None => return false,
            },
        }
    }
    while tokens.get(p) == Some(&GlobToken::Star) {
        p += 1;
    }
    p == tokens.len()
}

/// A glob filter on a field, or plain equality when the glob has no wildcard.
fn glob_filter(field: &str, tokens: &[GlobToken], ignore_case: bool) -> ResourceFilter {
    if tokens
        .iter()
        .all(|token| matches!(token, GlobToken::Char(_)))
    {
        let text: String = tokens
            .iter()
            .filter_map(|token| {
                if let GlobToken::Char(c) = token {
                    Some(*c)
                } else {
                    None
                }
            })
            .collect();
        return equals_filter(field, vec![FilterValue::String(text)], ignore_case);
    }
    if !tokens.is_empty() && tokens.iter().all(|token| *token == GlobToken::Star) {
        return typed(field, FilterType::String);
    }
    ResourceFilter::Like {
        field: field.to_owned(),
        pattern: glob_string(tokens),
        ignore_case,
    }
}

/// The most work one plan may take (`planWorkLimit`).
pub const PLAN_WORK_LIMIT: u64 = 200_000;

struct Planner<'a> {
    input: &'a PlanInput,
    context: Context,
    ids_by_relation: Vec<(String, Vec<String>)>,
    parents_by_relation: Vec<(String, Vec<(String, String)>)>,
    work: Cell<u64>,
}

impl Planner<'_> {
    fn spend(&self, units: usize) -> IamResult<()> {
        self.work.set(self.work.get() + units as u64);
        if self.work.get() > PLAN_WORK_LIMIT {
            return Err(IamError::new(
                "UNSUPPORTED_FILTER",
                "These policies are too complex to plan as a filter; check the resources with authorize",
            ));
        }
        Ok(())
    }
}

/// The ids a resource pattern admits for a type.
fn id_filter(
    planner: &Planner<'_>,
    tokens: &[GlobToken],
    prefix: &str,
) -> IamResult<ResourceFilter> {
    let closure = |mut states: Vec<usize>| {
        let mut index = 0;
        while index < states.len() {
            let mut at = states[index];
            while tokens.get(at) == Some(&GlobToken::Star) {
                at += 1;
                if !states.contains(&at) {
                    states.push(at);
                }
            }
            index += 1;
        }
        states
    };
    let mut states = closure(vec![0]);
    for c in prefix.chars() {
        planner.spend(states.len())?;
        let mut next: Vec<usize> = Vec::new();
        for state in &states {
            let Some(token) = tokens.get(*state) else {
                continue;
            };
            let target = match token {
                GlobToken::Star => Some(*state),
                GlobToken::Any => Some(state + 1),
                GlobToken::Char(expected) if *expected == c => Some(state + 1),
                GlobToken::Char(_) => None,
            };
            if let Some(target) = target
                && !next.contains(&target)
            {
                next.push(target);
            }
        }
        states = closure(next);
        if states.is_empty() {
            return Ok(ResourceFilter::False);
        }
    }
    // Ids are nonempty strings: a residue that matches only the empty string admits none, one of stars alone all.
    let mut filters = Vec::new();
    for state in states {
        let rest = &tokens[state.min(tokens.len())..];
        planner.spend(rest.len() + 1)?;
        filters.push(if rest.is_empty() {
            ResourceFilter::False
        } else if rest.iter().all(|token| *token == GlobToken::Star) {
            ResourceFilter::True
        } else {
            glob_filter("id", rest, false)
        });
    }
    Ok(or_filter(filters))
}

// --- statements ----------------------------------------------------------------------------------

/// One condition entry evaluated by the engine itself, for keys the context holds.
fn concrete(
    operator: ConditionOperator,
    condition_key: &str,
    expected: &Value,
    context: &Context,
) -> IamResult<bool> {
    let mut attributes = indexmap::IndexMap::new();
    attributes.insert(condition_key.to_owned(), expected.clone());
    let mut conditions = indexmap::IndexMap::new();
    conditions.insert(operator, attributes);
    let document = PolicyDocument::new(vec![PolicyStatement {
        sid: None,
        effect: Effect::Allow,
        actions: vec!["*".into()],
        resources: vec!["*".into()],
        conditions: Some(conditions),
    }]);
    let decision = evaluate_policy(&EvaluationInput {
        action: "plan".into(),
        resource: "plan/plan".into(),
        context: Some(context.clone()),
        grants: vec![document],
        boundaries: None,
    })?;
    Ok(decision.allowed)
}

fn lower_case_context(context: &Context) -> Context {
    context
        .iter()
        .map(|(name, value)| {
            let value = match value {
                Value::String(text) => Value::String(js::to_lower(text)),
                other => other.clone(),
            };
            (name.clone(), value)
        })
        .collect()
}

/// A condition on a resource attribute, as a filter with the engine's semantics.
fn attribute_condition(
    operator: ConditionOperator,
    field: &str,
    expected: &[Value],
    context: &Context,
) -> ResourceFilter {
    use ConditionOperator::*;
    let strings = || -> Vec<FilterValue> {
        expected
            .iter()
            .filter_map(|value| value.as_str())
            .filter_map(|value| resolve_policy_value(value, Some(context)))
            .map(FilterValue::String)
            .collect()
    };
    let lowered_strings = || -> Vec<FilterValue> {
        strings()
            .into_iter()
            .map(|value| match value {
                FilterValue::String(text) => FilterValue::String(js::to_lower(&text)),
                other => other,
            })
            .collect()
    };
    let likes = |ignore_case: bool| -> Vec<ResourceFilter> {
        let lowered = if ignore_case {
            Some(lower_case_context(context))
        } else {
            None
        };
        expected
            .iter()
            .map(|value| {
                let Some(value) = value.as_str() else {
                    return ResourceFilter::False;
                };
                let tokens = match &lowered {
                    Some(lowered) => tokenize(&js::to_lower(value), lowered, false),
                    None => tokenize(value, context, false),
                };
                match tokens {
                    Some(tokens) => glob_filter(field, &tokens, ignore_case),
                    None => ResourceFilter::False,
                }
            })
            .collect()
    };
    let numbers = || -> Vec<FilterValue> {
        expected
            .iter()
            .filter_map(js::as_number)
            .map(FilterValue::Number)
            .collect()
    };
    let networks = || -> Vec<ResourceFilter> {
        expected
            .iter()
            .map(|value| match value.as_str() {
                Some(network) => ResourceFilter::Ip {
                    field: field.to_owned(),
                    network: network.to_owned(),
                },
                None => ResourceFilter::False,
            })
            .collect()
    };
    match operator {
        Exists => or_filter(
            expected
                .iter()
                .map(|value| {
                    if *value == Value::Bool(true) {
                        exists(field)
                    } else {
                        not_filter(exists(field))
                    }
                })
                .collect(),
        ),
        StringEquals => equals_filter(field, strings(), false),
        StringNotEquals => and_filter(vec![
            typed(field, FilterType::String),
            not_filter(equals_filter(field, strings(), false)),
        ]),
        StringEqualsIgnoreCase => equals_filter(field, lowered_strings(), true),
        StringNotEqualsIgnoreCase => and_filter(vec![
            typed(field, FilterType::String),
            not_filter(equals_filter(field, lowered_strings(), true)),
        ]),
        StringLike => or_filter(likes(false)),
        StringNotLike => and_filter(vec![
            typed(field, FilterType::String),
            not_filter(or_filter(likes(false))),
        ]),
        StringLikeIgnoreCase => or_filter(likes(true)),
        Bool => equals_filter(
            field,
            expected
                .iter()
                .filter_map(Value::as_bool)
                .map(FilterValue::Bool)
                .collect(),
            false,
        ),
        NumericEquals => equals_filter(field, numbers(), false),
        NumericNotEquals => and_filter(vec![
            typed(field, FilterType::Number),
            not_filter(equals_filter(field, numbers(), false)),
        ]),
        NumericLessThan | NumericLessThanEquals | NumericGreaterThan | NumericGreaterThanEquals => {
            let comparison = match operator {
                NumericLessThan => CompareOperator::Lt,
                NumericLessThanEquals => CompareOperator::Le,
                NumericGreaterThan => CompareOperator::Gt,
                _ => CompareOperator::Ge,
            };
            or_filter(
                expected
                    .iter()
                    .filter_map(js::as_number)
                    .map(|value| ResourceFilter::Compare {
                        field: field.to_owned(),
                        operator: comparison,
                        value,
                    })
                    .collect(),
            )
        }
        DateBefore | DateAfter => or_filter(
            expected
                .iter()
                .map(|value| match value.as_str() {
                    Some(value) => ResourceFilter::Date {
                        field: field.to_owned(),
                        operator: if operator == DateBefore {
                            DateOperator::Before
                        } else {
                            DateOperator::After
                        },
                        value: value.to_owned(),
                    },
                    None => ResourceFilter::False,
                })
                .collect(),
        ),
        IpAddress => or_filter(networks()),
        NotIpAddress => and_filter(vec![
            typed(field, FilterType::Ip),
            not_filter(or_filter(networks())),
        ]),
        ArrayContains | ArrayContainsAll => {
            let members: Vec<ResourceFilter> = expected
                .iter()
                .map(|value| {
                    let wanted = match value {
                        Value::String(text) => {
                            resolve_policy_value(text, Some(context)).map(FilterValue::String)
                        }
                        other => FilterValue::from_value(other),
                    };
                    match wanted {
                        Some(value) => ResourceFilter::Contains {
                            field: field.to_owned(),
                            value,
                        },
                        None => ResourceFilter::False,
                    }
                })
                .collect();
            if operator == ArrayContains {
                or_filter(members)
            } else {
                and_filter(members)
            }
        }
    }
}

/// Operators whose string values substitute variables.
fn substituting(operator: ConditionOperator) -> bool {
    use ConditionOperator::*;
    matches!(
        operator,
        StringEquals
            | StringNotEquals
            | StringEqualsIgnoreCase
            | StringNotEqualsIgnoreCase
            | StringLike
            | StringNotLike
            | StringLikeIgnoreCase
            | ArrayContains
            | ArrayContainsAll
    )
}

/// A condition on `resource.relations` or `resource.parentRelations`.
fn relation_condition(
    planner: &Planner<'_>,
    operator: ConditionOperator,
    condition_key: &str,
    expected: &[Value],
) -> IamResult<ResourceFilter> {
    let context = &planner.context;
    if operator != ConditionOperator::ArrayContains
        && operator != ConditionOperator::ArrayContainsAll
    {
        // Every other operator reads the list as a whole, and a list satisfies each one the same way.
        let mut with_list = context.clone();
        with_list.insert(condition_key.to_owned(), Value::Array(Vec::new()));
        return Ok(
            if concrete(
                operator,
                condition_key,
                &Value::Array(expected.to_vec()),
                &with_list,
            )? {
                ResourceFilter::True
            } else {
                ResourceFilter::False
            },
        );
    }
    let members: Vec<ResourceFilter> = expected
        .iter()
        .map(|value| {
            let wanted = match value {
                Value::String(text) => resolve_policy_value(text, Some(context)),
                _ => None,
            };
            let Some(wanted) = wanted else {
                return ResourceFilter::False;
            };
            if condition_key == "resource.relations" {
                let ids = planner
                    .ids_by_relation
                    .iter()
                    .find(|(relation, _)| *relation == wanted)
                    .map(|(_, ids)| ids.iter().cloned().map(FilterValue::String).collect())
                    .unwrap_or_default();
                return equals_filter("id", ids, false);
            }
            let parents = planner
                .parents_by_relation
                .iter()
                .find(|(relation, _)| *relation == wanted)
                .map(|(_, parents)| parents.clone())
                .unwrap_or_default();
            or_filter(
                parents
                    .into_iter()
                    .map(|(kind, id)| {
                        and_filter(vec![
                            equals_filter("parentType", vec![FilterValue::String(kind)], false),
                            equals_filter("parentId", vec![FilterValue::String(id)], false),
                        ])
                    })
                    .collect(),
            )
        })
        .collect();
    Ok(if operator == ConditionOperator::ArrayContains {
        or_filter(members)
    } else {
        and_filter(members)
    })
}

/// When the resource lacks an attribute, the evaluation context may still carry `resource.{name}`.
fn with_fallback(field: &str, present: ResourceFilter, fallback: Option<bool>) -> ResourceFilter {
    let Some(fallback) = fallback else {
        return present;
    };
    let mut items = vec![and_filter(vec![exists(field), present])];
    if fallback {
        items.push(not_filter(exists(field)));
    }
    or_filter(items)
}

/// When a statement matches the planned action on a resource of the planned type.
fn statement_filter(
    planner: &Planner<'_>,
    statement: &PolicyStatement,
) -> IamResult<ResourceFilter> {
    let input = planner.input;
    if !statement
        .actions
        .iter()
        .any(|pattern| match_pattern(pattern, &input.action, None))
    {
        return Ok(ResourceFilter::False);
    }
    let context = &planner.context;
    let prefix = format!("{}/", input.resource_type);
    let mut row_dependent = false;
    let mut resources = Vec::new();
    for pattern in &statement.resources {
        if has_row_variable(pattern) {
            if let Some(widest) = tokenize(pattern, context, true)
                && id_filter(planner, &widest, &prefix)? != ResourceFilter::False
            {
                row_dependent = true;
            }
            resources.push(ResourceFilter::False);
            continue;
        }
        resources.push(match tokenize(pattern, context, false) {
            Some(tokens) => id_filter(planner, &tokens, &prefix)?,
            None => ResourceFilter::False,
        });
    }
    let resource = or_filter(resources);
    if resource == ResourceFilter::False && !row_dependent {
        return Ok(ResourceFilter::False);
    }
    let mut conditions = vec![resource];
    let mut id_condition = false;
    let mut derived_key: Option<String> = None;
    for (operator, entries) in statement.conditions.iter().flatten() {
        let operator = *operator;
        for (condition_key, expected_value) in entries {
            let expected: Vec<Value> = match expected_value {
                Value::Array(items) => items.clone(),
                single => vec![single.clone()],
            };
            planner.spend(expected.len())?;
            if substituting(operator)
                && expected
                    .iter()
                    .any(|value| value.as_str().is_some_and(has_row_variable))
            {
                row_dependent = true;
                continue;
            }
            // The engine reads `resource.id` as an attribute named `id`, which a filter cannot tell from the id.
            if condition_key == "resource.id" {
                id_condition = true;
                continue;
            }
            // A key the server derives per resource (a classification label's) is no column of the row.
            if input
                .derived_resource_keys
                .as_ref()
                .is_some_and(|keys| keys.contains(condition_key))
            {
                derived_key.get_or_insert_with(|| condition_key.clone());
                continue;
            }
            let filter = if condition_key == "resource.tenantId" {
                if concrete(operator, condition_key, expected_value, context)? {
                    ResourceFilter::True
                } else {
                    ResourceFilter::False
                }
            } else if condition_key == "resource.relations"
                || condition_key == "resource.parentRelations"
            {
                relation_condition(planner, operator, condition_key, &expected)?
            } else if let Some(field) = condition_key.strip_prefix("resource.") {
                let inherited = input.context.get(condition_key);
                let fallback = match inherited {
                    None => None,
                    Some(_) => Some(concrete(operator, condition_key, expected_value, context)?),
                };
                with_fallback(
                    field,
                    attribute_condition(operator, field, &expected, context),
                    fallback,
                )
            } else if concrete(operator, condition_key, expected_value, context)? {
                ResourceFilter::True
            } else {
                ResourceFilter::False
            };
            if filter == ResourceFilter::False {
                return Ok(ResourceFilter::False);
            }
            conditions.push(filter);
        }
    }
    if row_dependent {
        return Err(IamError::new(
            "UNSUPPORTED_FILTER",
            "A policy compares a value with ${resource.…}, one of the resource’s own attributes, which a filter cannot express; check the resources with authorize",
        ));
    }
    if id_condition {
        return Err(IamError::new(
            "UNSUPPORTED_FILTER",
            "A policy has a condition on resource.id, which names an attribute called id rather than the resource’s id (match ids with the statement’s resources); check the resources with authorize",
        ));
    }
    if let Some(derived_key) = derived_key {
        return Err(IamError::new(
            "UNSUPPORTED_FILTER",
            format!(
                "A policy has a condition on {derived_key}, which the server derives for each resource rather than reading from the row; check the resources with authorize"
            ),
        ));
    }
    Ok(and_filter(conditions))
}

/// Resources some statement of `effect` in the documents matches.
fn any_statement(
    planner: &Planner<'_>,
    documents: &[&PolicyDocument],
    effect: Effect,
) -> IamResult<ResourceFilter> {
    let mut filters = Vec::new();
    for document in documents {
        for statement in document
            .statements
            .iter()
            .filter(|statement| statement.effect == effect)
        {
            filters.push(statement_filter(planner, statement)?);
        }
    }
    Ok(or_filter(filters))
}

/// Resources every document lets through: each has a matching allow statement (a boundary).
fn every_boundary(
    planner: &Planner<'_>,
    documents: &[PolicyDocument],
) -> IamResult<ResourceFilter> {
    let mut filters = Vec::new();
    for document in documents {
        filters.push(any_statement(planner, &[document], Effect::Allow)?);
    }
    Ok(and_filter(filters))
}

fn plan_of(filter: ResourceFilter) -> ResourcePlan {
    let kind = match filter {
        ResourceFilter::True => PlanKind::Always,
        ResourceFilter::False => PlanKind::Never,
        _ => PlanKind::Conditional,
    };
    ResourcePlan { kind, filter }
}

/// Plans the resources of `resource_type` the principal may perform `action` on (`planResources`).
pub fn plan_resources(input: &PlanInput) -> IamResult<ResourcePlan> {
    let documents = input.denies.iter().chain(&input.boundaries).chain(
        input
            .paths
            .iter()
            .flat_map(|path| path.grants.iter().chain(&path.boundaries)),
    );
    for document in documents {
        validate_policy(&document.to_value())?;
    }
    if input.resource_type.is_empty() || input.resource_type.contains('/') {
        return Err(IamError::new("INVALID_INPUT", "Invalid resource type"));
    }
    let mut ids_by_relation: Vec<(String, Vec<String>)> = Vec::new();
    let mut parents_by_relation: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for tuple in input.relations.iter().flatten() {
        for relation in &tuple.relations {
            if tuple.kind == input.resource_type {
                match ids_by_relation
                    .iter_mut()
                    .find(|(name, _)| name == relation)
                {
                    Some((_, ids)) => ids.push(tuple.id.clone()),
                    None => ids_by_relation.push((relation.clone(), vec![tuple.id.clone()])),
                }
            }
            match parents_by_relation
                .iter_mut()
                .find(|(name, _)| name == relation)
            {
                Some((_, parents)) => parents.push((tuple.kind.clone(), tuple.id.clone())),
                None => parents_by_relation.push((
                    relation.clone(),
                    vec![(tuple.kind.clone(), tuple.id.clone())],
                )),
            }
        }
    }
    let mut context = input.context.clone();
    context.insert(
        "resource.tenantId".into(),
        Value::String(input.tenant_id.clone()),
    );
    context.insert("resource.relations".into(), Value::Array(Vec::new()));
    context.insert("resource.parentRelations".into(), Value::Array(Vec::new()));
    let planner = Planner {
        input,
        context,
        ids_by_relation,
        parents_by_relation,
        work: Cell::new(0),
    };
    let mut parts = Vec::new();
    // Mandatory access control first: whatever the policies say, nothing above the principal's clearance.
    if let Some(mandatory) = &input.mandatory {
        parts.push(mandatory.clone());
    }
    let global: Vec<&PolicyDocument> = input.denies.iter().chain(&input.boundaries).collect();
    parts.push(not_filter(any_statement(&planner, &global, Effect::Deny)?));
    parts.push(every_boundary(&planner, &input.boundaries)?);
    let mut paths = Vec::new();
    for path in &input.paths {
        let own: Vec<&PolicyDocument> = path.grants.iter().chain(&path.boundaries).collect();
        let grants: Vec<&PolicyDocument> = path.grants.iter().collect();
        let denies = not_filter(any_statement(&planner, &own, Effect::Deny)?);
        let allows = any_statement(&planner, &grants, Effect::Allow)?;
        let ceilings = every_boundary(&planner, &path.boundaries)?;
        paths.push(and_filter(vec![denies, allows, ceilings]));
    }
    parts.push(or_filter(paths));
    Ok(plan_of(and_filter(parts)))
}

/// A plan that allows everything or nothing (`fixedPlan`).
pub fn fixed_plan(allowed: bool) -> ResourcePlan {
    if allowed {
        plan_of(ResourceFilter::True)
    } else {
        plan_of(ResourceFilter::False)
    }
}

/// Both plans at once: what each allows (`intersectPlans`).
pub fn intersect_plans(left: &ResourcePlan, right: &ResourcePlan) -> ResourcePlan {
    plan_of(and_filter(vec![left.filter.clone(), right.filter.clone()]))
}
