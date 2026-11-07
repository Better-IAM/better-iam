//! Port of `packages/server/src/features.ts`: feature flag records, settings validation, and evaluation along a
//! tenant's ancestry (kill switch, targets and overrides, rollouts, defaults).

use std::sync::LazyLock;

use better_iam_core::{Filter, FindOptions, IamResult};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::Store;
use crate::js::{invalid_input, number};
use crate::port::decode;
use crate::utils::hash;
use crate::validation::{integer, text};

/// A flag's value for one tenant, with the reason and where it was decided.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureEvaluation {
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "value")]
    pub value: bool,
    #[serde(rename = "reason")]
    pub reason: String,
    /// `platform` for flags the root tenant defines, `tenant` for flags of an organization or project.
    #[serde(rename = "scope")]
    pub scope: String,
    /// The defining tenant (absent for `UNKNOWN`).
    #[serde(rename = "definedBy", default, skip_serializing_if = "Option::is_none")]
    pub defined_by: Option<String>,
    /// The tenant whose target or override decided: the evaluated tenant or one of its ancestors.
    #[serde(rename = "decidedBy", default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    /// When the deciding target or override lapses.
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    /// A locked target at or above the tenant keeps overrides from applying.
    #[serde(rename = "locked")]
    pub locked: bool,
    /// Whether the evaluated tenant's administrators may set their own value now (`features.setOverride`).
    #[serde(rename = "overridable")]
    pub overridable: bool,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A feature flag. Flags the root tenant defines are platform flags and reach every tenant; flags another tenant
/// defines reach only that tenant and its descendants. Keys are unique per defining tenant (`uniqueKey` = key), and
/// when an ancestor defines the same key its flag wins, so a tenant can never shadow a platform flag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureFlag {
    #[serde(rename = "key")]
    pub key: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// The value when no target, override, or rollout decides.
    #[serde(rename = "defaultValue")]
    pub default_value: bool,
    /// 0-100: the share of branches directly below the defining tenant that get `true` (a whole organization, with its
    /// projects, lands on the same side). Requires `defaultValue: false`; raising it keeps earlier tenants enabled.
    #[serde(
        rename = "rolloutPercentage",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub rollout_percentage: Option<f64>,
    /// Tenants below the defining tenant may choose their own value (`features.setOverride`).
    #[serde(rename = "tenantOverridable")]
    pub tenant_overridable: bool,
    /// Off everywhere, whatever targets and overrides say: the incident switch.
    #[serde(rename = "killSwitch")]
    pub kill_switch: bool,
    /// Evaluated only by trusted code (`iam.features`) and policy conditions; hidden from `features.evaluate` and from
    /// the listings of tenants below the defining tenant. Internal flags cannot be tenant-overridable.
    #[serde(rename = "internal")]
    pub internal: bool,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureFlagSettings {
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// The value when no target, override, or rollout decides.
    #[serde(rename = "defaultValue")]
    pub default_value: bool,
    /// 0-100: the share of branches directly below the defining tenant that get `true` (a whole organization, with its
    /// projects, lands on the same side). Requires `defaultValue: false`; raising it keeps earlier tenants enabled.
    #[serde(
        rename = "rolloutPercentage",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub rollout_percentage: Option<f64>,
    /// Tenants below the defining tenant may choose their own value (`features.setOverride`).
    #[serde(rename = "tenantOverridable")]
    pub tenant_overridable: bool,
    /// Off everywhere, whatever targets and overrides say: the incident switch.
    #[serde(rename = "killSwitch")]
    pub kill_switch: bool,
    /// Evaluated only by trusted code (`iam.features`) and policy conditions; hidden from `features.evaluate` and from
    /// the listings of tenants below the defining tenant. Internal flags cannot be tenant-overridable.
    #[serde(rename = "internal")]
    pub internal: bool,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What evaluation needs about one tenant: its ancestry, the flags that reach it, and the pinned values along it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureState {
    /// The tenant and its ancestors, nearest first (`ctx.ancestry`).
    #[serde(rename = "chain")]
    pub chain: Vec<better_iam_core::Tenant>,
    /// The effective flag per key: the one defined closest to the root.
    #[serde(rename = "flags")]
    pub flags: IndexMap<String, crate::features::FeatureFlag>,
    /// Flags defined along the chain that an ancestor's flag of the same key overrides.
    #[serde(rename = "shadowed")]
    pub shadowed: Vec<crate::features::FeatureFlag>,
    /// Live (unexpired) targets and overrides along the chain, by flag id.
    #[serde(rename = "entries")]
    pub entries: IndexMap<String, Vec<crate::features::FeatureTarget>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A value pinned for one tenant and its descendants. `target` entries are set by the flag's managers in the
/// defining tenant (a `locked` target also keeps tenants in its subtree from overriding); `override` entries are a
/// tenant's own choice for a tenant-overridable flag. The record lives in the tenant it applies to (`uniqueKey`
/// `{flagId}:{source}`), so purging that tenant removes it; deleting the flag removes all of them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureTarget {
    #[serde(rename = "flagId")]
    pub flag_id: String,
    #[serde(rename = "key")]
    pub key: String,
    /// The flag's defining tenant.
    #[serde(rename = "definerId")]
    pub definer_id: String,
    #[serde(rename = "source")]
    pub source: String,
    #[serde(rename = "value")]
    pub value: bool,
    #[serde(rename = "locked", default, skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "note", default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "setAt")]
    pub set_at: f64,
    #[serde(rename = "setBy")]
    pub set_by: String,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `featureCollections.flags`.
pub const FEATURE_FLAGS: &str = "featureFlags";
/// `featureCollections.targets`.
pub const FEATURE_TARGETS: &str = "featureTargets";

/// Lowercase letters and digits in segments joined by `-`, `_`, or `.`, starting with a letter: `new-billing`,
/// `reports.v2`.
static KEY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$").expect("key pattern"));

/// The settings members a flag patch may name.
const SETTING_KEYS: [&str; 6] = [
    "description",
    "defaultValue",
    "rolloutPercentage",
    "tenantOverridable",
    "killSwitch",
    "internal",
];

impl FeatureEvaluation {
    /// The evaluation as the TypeScript object, in its member order (`unknownFeature` and `evaluateFlag` build
    /// different orders).
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("key".into(), Value::String(self.key.clone()));
        if self.defined_by.is_none() {
            out.insert("value".into(), Value::Bool(self.value));
            out.insert("reason".into(), Value::String(self.reason.clone()));
            out.insert("scope".into(), Value::String(self.scope.clone()));
        } else {
            out.insert("scope".into(), Value::String(self.scope.clone()));
            if let Some(defined_by) = &self.defined_by {
                out.insert("definedBy".into(), Value::String(defined_by.clone()));
            }
            out.insert("value".into(), Value::Bool(self.value));
            out.insert("reason".into(), Value::String(self.reason.clone()));
            if let Some(decided_by) = &self.decided_by {
                out.insert("decidedBy".into(), Value::String(decided_by.clone()));
            }
            if let Some(expires_at) = self.expires_at {
                out.insert("expiresAt".into(), number(expires_at));
            }
        }
        out.insert("locked".into(), Value::Bool(self.locked));
        out.insert("overridable".into(), Value::Bool(self.overridable));
        for (key, value) in &self.extra {
            out.insert(key.clone(), value.clone());
        }
        Value::Object(out)
    }
}

/// `evaluateFeatures` options: `keys` restricts the result; internal flags are included only with
/// `include_internal`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EvaluateFeaturesOptions {
    pub keys: Option<Vec<String>>,
    pub include_internal: bool,
}

/// The sorted keys of every flag (internal ones included) that is on for the tenant: the `tenant.features` context.
pub fn enabled_feature_keys(state: &crate::features::FeatureState) -> IamResult<Vec<String>> {
    Ok(evaluate_features(
        state,
        &EvaluateFeaturesOptions {
            keys: None,
            include_internal: true,
        },
    )?
    .into_iter()
    .filter(|evaluation| evaluation.value)
    .map(|evaluation| evaluation.key)
    .collect())
}

/// Evaluates the flags that reach a tenant, sorted by key. `keys` restricts the result (unknown keys evaluate to
/// `false` with reason `UNKNOWN`); internal flags are included only with `includeInternal`.
pub fn evaluate_features(
    state: &crate::features::FeatureState,
    options: &EvaluateFeaturesOptions,
) -> IamResult<Vec<crate::features::FeatureEvaluation>> {
    let own = state.chain.first().map(|realm| realm.id.as_str());
    let visible = |flag: &FeatureFlag| {
        options.include_internal
            || !flag.internal
            // Internal flags stay visible to the tenant that defines them.
            || Some(flag.tenant_id.as_str()) == own
    };
    if let Some(keys) = &options.keys {
        let mut keys = crate::js::unique(keys.iter().cloned());
        crate::js::sort_strings(&mut keys);
        return keys
            .into_iter()
            .map(|key| match state.flags.get(&key) {
                Some(flag) if visible(flag) => evaluate_flag(state, flag),
                _ => Ok(unknown_feature(&key)),
            })
            .collect();
    }
    let mut flags: Vec<&FeatureFlag> = state.flags.values().filter(|flag| visible(flag)).collect();
    flags.sort_by(|a, b| crate::js::cmp_utf16(&a.key, &b.key));
    flags
        .into_iter()
        .map(|flag| evaluate_flag(state, flag))
        .collect()
}

/// One flag's value for `state.chain[0]`. Precedence: the kill switch; then, walking from the tenant up to (not
/// including) the defining tenant, the nearest tenant with an override or a target, where a tenant's own override
/// beats a target on the same tenant and a locked target silences overrides at and below its tenant; then the
/// rollout; then the default.
pub fn evaluate_flag(
    state: &crate::features::FeatureState,
    flag: &crate::features::FeatureFlag,
) -> IamResult<crate::features::FeatureEvaluation> {
    let chain = &state.chain;
    let depth = chain.iter().position(|realm| realm.id == flag.tenant_id);
    let scope = if chain.last().map(|realm| realm.id.as_str()) == Some(flag.tenant_id.as_str()) {
        "platform"
    } else {
        "tenant"
    };
    // Only tenants strictly below the defining tenant carry targets and overrides for its flag.
    let below = match depth {
        Some(depth) => &chain[..depth],
        None => &chain[..0],
    };
    let entries: Vec<&FeatureTarget> = state
        .entries
        .get(&flag.id)
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| entry.definer_id == flag.tenant_id)
                .collect()
        })
        .unwrap_or_default();
    let at = |realm: &better_iam_core::Tenant, source: &str| {
        entries
            .iter()
            .find(|entry| entry.tenant_id == realm.id && entry.source == source)
            .copied()
    };
    let mut locked_at: i64 = -1;
    for (index, realm) in below.iter().enumerate() {
        if at(realm, "target").is_some_and(|entry| entry.locked == Some(true)) {
            locked_at = index as i64;
        }
    }
    let overrides_apply = flag.tenant_overridable && !flag.internal;
    let overridable = overrides_apply && depth.is_some_and(|depth| depth > 0) && locked_at < 0;
    let locked = locked_at >= 0;
    let evaluation =
        |value: bool, reason: &str, decided_by: Option<String>, expires_at: Option<f64>| {
            FeatureEvaluation {
                key: flag.key.clone(),
                value,
                reason: reason.to_owned(),
                scope: scope.to_owned(),
                defined_by: Some(flag.tenant_id.clone()),
                decided_by,
                expires_at,
                locked,
                overridable,
                extra: Map::new(),
            }
        };
    if flag.kill_switch {
        return Ok(evaluation(false, "KILL_SWITCH", None, None));
    }
    for (index, realm) in below.iter().enumerate() {
        let override_entry = if overrides_apply && index as i64 > locked_at {
            at(realm, "override")
        } else {
            None
        };
        if let Some(decided) = override_entry.or_else(|| at(realm, "target")) {
            return Ok(evaluation(
                decided.value,
                if decided.source == "override" {
                    "OVERRIDE"
                } else {
                    "TARGET"
                },
                Some(realm.id.clone()),
                decided.expires_at,
            ));
        }
    }
    if let Some(percentage) = flag.rollout_percentage {
        // The branch directly below the defining tenant, so an organization and its projects agree.
        let unit = below
            .last()
            .or_else(|| chain.first())
            .ok_or_else(crate::js::internal_error)?;
        return Ok(evaluation(
            rollout_bucket(&flag.key, &unit.id) < percentage,
            "ROLLOUT",
            None,
            None,
        ));
    }
    Ok(evaluation(flag.default_value, "DEFAULT", None, None))
}

/// The evaluation reported for a key no flag defines along the tenant's ancestry.
pub fn unknown_feature(key: &str) -> FeatureEvaluation {
    FeatureEvaluation {
        key: key.to_owned(),
        value: false,
        reason: "UNKNOWN".into(),
        scope: "platform".into(),
        defined_by: None,
        decided_by: None,
        expires_at: None,
        locked: false,
        overridable: false,
        extra: Map::new(),
    }
}

/// The rollout position (0 to 99.99) of a tenant branch for a flag: stable per key and tenant, so raising the
/// percentage only ever adds tenants, and different flags spread over different tenants.
pub fn rollout_bucket(key: &str, tenant_id: &str) -> f64 {
    let digest = hash(&format!("feature:{key}:{tenant_id}"));
    let prefix = u64::from_str_radix(&digest[..8], 16).unwrap_or(0);
    (prefix % 10_000) as f64 / 100.0
}

pub static FEATURE_COLLECTIONS: std::sync::LazyLock<Value> =
    std::sync::LazyLock::new(|| json!({"flags":"featureFlags","targets":"featureTargets"}));

/// The policy context key holding the sorted keys of every flag that is on for the decision's tenant.
pub const FEATURE_CONTEXT_KEY: &str = "tenant.features";

/// Validates a flag key: at most 64 characters matching `keyPattern`.
pub fn feature_key(value: Option<&Value>) -> IamResult<String> {
    let key = text(value, "key", 64)?;
    if !KEY_PATTERN.is_match(&key) {
        return Err(invalid_input(
            "Flag keys are lowercase letters and digits joined by \"-\", \"_\", or \".\", starting with a letter",
        ));
    }
    Ok(key)
}

/// Applies a settings patch to `current` (defaults for a new flag) and validates the result. `null` clears
/// `description` and `rolloutPercentage`; unknown fields are refused.
pub fn feature_settings(
    input: &Map<String, Value>,
    current: Option<&crate::features::FeatureFlagSettings>,
) -> IamResult<crate::features::FeatureFlagSettings> {
    let current = current.map(crate::port::encode);
    decode(feature_settings_map(input, current.as_ref())?)
}

/// [`feature_settings`] on JSON objects: `current` is the flag (or its settings), and the result keeps the member
/// order of the TypeScript object, so records built from it match the ones TypeScript writes.
pub fn feature_settings_map(
    input: &Map<String, Value>,
    current: Option<&Map<String, Value>>,
) -> IamResult<Map<String, Value>> {
    for field in crate::js::keys(input) {
        if !SETTING_KEYS.contains(&field.as_str()) && field != "tenantId" && field != "key" {
            return Err(invalid_input(format!("Unknown flag field {field}")));
        }
    }
    let mut next = Map::new();
    for name in [
        "defaultValue",
        "tenantOverridable",
        "killSwitch",
        "internal",
    ] {
        // A member the current flag lacks is `undefined` in TypeScript, which JSON leaves out.
        let value = match current {
            Some(current) => current.get(name).cloned(),
            None => Some(Value::Bool(false)),
        };
        if let Some(value) = value {
            next.insert(name.into(), value);
        }
    }
    if let Some(description) = current.and_then(|current| current.get("description")) {
        next.insert("description".into(), description.clone());
    }
    if let Some(rollout) = current.and_then(|current| current.get("rolloutPercentage")) {
        next.insert("rolloutPercentage".into(), rollout.clone());
    }
    for field in [
        "defaultValue",
        "tenantOverridable",
        "killSwitch",
        "internal",
    ] {
        match input.get(field) {
            None => continue,
            Some(Value::Bool(value)) => {
                next.insert(field.into(), Value::Bool(*value));
            }
            Some(_) => return Err(invalid_input(format!("{field} must be a boolean"))),
        }
    }
    match input.get("description") {
        Some(Value::Null) => {
            next.shift_remove("description");
        }
        Some(description) => {
            let description = text(Some(description), "description", 512)?;
            next.insert(
                "description".into(),
                Value::String(better_iam_core::js::trim(&description).to_owned()),
            );
        }
        None => {}
    }
    match input.get("rolloutPercentage") {
        Some(Value::Null) => {
            next.shift_remove("rolloutPercentage");
        }
        Some(rollout) => {
            let rollout = integer(Some(rollout), "rolloutPercentage", 0.0, 100.0)?;
            next.insert("rolloutPercentage".into(), number(rollout));
        }
        None => {}
    }
    if next.contains_key("rolloutPercentage") && crate::js::truthy(next.get("defaultValue")) {
        return Err(invalid_input(
            "A rollout turns a flag on gradually: set defaultValue to false or remove rolloutPercentage",
        ));
    }
    if crate::js::truthy(next.get("internal")) && crate::js::truthy(next.get("tenantOverridable")) {
        return Err(invalid_input("Internal flags cannot be tenant-overridable"));
    }
    Ok(next)
}

/// Reads the flags and pinned values along a tenant's ancestry (two lookups per tenant in the chain).
pub async fn feature_state(
    tx: &Store,
    chain: &[better_iam_core::Tenant],
    now: f64,
) -> IamResult<crate::features::FeatureState> {
    let mut flags: IndexMap<String, FeatureFlag> = IndexMap::new();
    let mut shadowed: Vec<FeatureFlag> = Vec::new();
    // Root first, so a flag defined closer to the root claims its key before a descendant's flag of the same key.
    for realm in chain.iter().rev() {
        for record in tx
            .find(
                FEATURE_FLAGS,
                &Filter::new().eq("tenantId", realm.id.clone()),
                &FindOptions::default(),
            )
            .await?
        {
            let flag: FeatureFlag = decode(record)?;
            if flags.contains_key(&flag.key) {
                shadowed.push(flag);
            } else {
                flags.insert(flag.key.clone(), flag);
            }
        }
    }
    let mut entries: IndexMap<String, Vec<FeatureTarget>> = IndexMap::new();
    for realm in chain {
        for record in tx
            .find(
                FEATURE_TARGETS,
                &Filter::new().eq("tenantId", realm.id.clone()),
                &FindOptions::default(),
            )
            .await?
        {
            let entry: FeatureTarget = decode(record)?;
            if entry.expires_at.is_none_or(|expires_at| expires_at > now) {
                entries
                    .entry(entry.flag_id.clone())
                    .or_default()
                    .push(entry);
            }
        }
    }
    Ok(FeatureState {
        chain: chain.to_vec(),
        flags,
        shadowed,
        entries,
        extra: Map::new(),
    })
}

/// Flags one tenant may define.
pub const MAX_FEATURE_FLAGS_PER_TENANT: f64 = 200.0;

/// Whether any statement of the documents names the `tenant.features` context key in a condition.
pub fn mentions_features(documents: &[&better_iam_core::PolicyDocument]) -> bool {
    documents.iter().any(|document| {
        document.statements.iter().any(|statement| {
            statement.conditions.as_ref().is_some_and(|conditions| {
                conditions.values().any(|block| {
                    [FEATURE_CONTEXT_KEY]
                        .iter()
                        .any(|key| block.contains_key(*key))
                })
            })
        })
    })
}
