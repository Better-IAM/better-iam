//! Port of `packages/server/src/sod.ts`: separation-of-duties rules (toxic role combinations), the violations they
//! report, and the prevent-rule check the operation envelope runs around granting operations.

use std::collections::HashMap;
use std::sync::Arc;

use better_iam_core::{Filter, FindOptions, IamError, IamResult, Record};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::js::as_number;

/// A separation-of-duties rule: nobody may hold two or more of these roles at once (directly, through groups, or as
/// eligible just-in-time bindings). `prevent` refuses grants that would create a conflict; `detect` only reports
/// it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SodRule {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "roleIds")]
    pub role_ids: Vec<String>,
    #[serde(rename = "mode")]
    pub mode: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
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

/// Every record of a find (no pagination).
fn all() -> FindOptions {
    FindOptions::default()
}

/// A string member of a stored record, "" when absent.
fn member_str<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// A numeric member of a stored record (NaN when absent or not a number: every comparison with it is false).
fn numeric(record: &Record, key: &str) -> f64 {
    record.get(key).and_then(as_number).unwrap_or(f64::NAN)
}

/// `ctx.expiredBinding(binding)` on a raw record.
fn expired_binding(ctx: &ServerContext, binding: &Record) -> bool {
    binding.get("expiresAt").is_some() && numeric(binding, "expiresAt") <= ctx.now()
}

/// `ctx.liveMembership(member)` on a raw record.
fn live_membership(ctx: &ServerContext, member: &Record) -> bool {
    member.get("expiresAt").is_none() || numeric(member, "expiresAt") > ctx.now()
}

/// Each role with every role it inherits, transitively (a role inheriting Approver holds Approver).
struct InheritedRoles {
    by_id: HashMap<String, Vec<String>>,
    cache: HashMap<String, Vec<String>>,
}

impl InheritedRoles {
    fn new(roles: &[Record]) -> Self {
        let mut by_id = HashMap::new();
        for role in roles {
            let inherits = role
                .get("inherits")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            by_id.insert(member_str(role, "id").to_owned(), inherits);
        }
        Self {
            by_id,
            cache: HashMap::new(),
        }
    }

    fn expand(&mut self, role_id: &str) -> Vec<String> {
        if let Some(cached) = self.cache.get(role_id) {
            return cached.clone();
        }
        let mut seen = IndexSet::new();
        let mut pending = vec![role_id.to_owned()];
        while let Some(next) = pending.pop() {
            if seen.contains(&next) {
                continue;
            }
            if let Some(inherits) = self.by_id.get(&next) {
                pending.extend(inherits.iter().cloned());
            }
            seen.insert(next);
        }
        let all: Vec<String> = seen.into_iter().collect();
        self.cache.insert(role_id.to_owned(), all.clone());
        all
    }
}

/// For flows outside the operation envelope (invitation acceptance): a newly granted identity must not conflict.
pub async fn sod_assert_identity(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
) -> IamResult<()> {
    let rules = prevent_rules(tx, tenant_id).await?;
    if !rules.is_empty() {
        let snapshot = SodSnapshot {
            rules,
            existing: IndexSet::new(),
        };
        sod_verify(
            ctx,
            tx,
            tenant_id,
            Some(&snapshot),
            Some(&[identity_id.to_owned()]),
        )
        .await?;
    }
    Ok(())
}

/// The tenant's rules in `prevent` mode.
async fn prevent_rules(tx: &Store, tenant_id: &str) -> IamResult<Vec<SodRule>> {
    let mut rules = Vec::new();
    for record in tx
        .find("sodRules", &Filter::new().eq("tenantId", tenant_id), &all())
        .await?
    {
        if record.get("mode").and_then(Value::as_str) == Some("prevent") {
            rules.push(crate::port::decode::<SodRule>(record)?);
        }
    }
    Ok(rules)
}

/// Before a granting operation: the prevent-rule conflicts that already exist, so a rule added after the fact never
/// blocks unrelated work. Undefined when the action cannot grant or the tenant has no prevent rules.
pub async fn sod_snapshot(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    action: &str,
) -> IamResult<Option<SodSnapshot>> {
    if !GRANTING_ACTIONS.contains(&action) {
        return Ok(None);
    }
    let rules = prevent_rules(tx, tenant_id).await?;
    if rules.is_empty() {
        return Ok(None);
    }
    let existing = sod_violations(ctx, tx, tenant_id, Some(&rules), None)
        .await?
        .iter()
        .map(violation_key)
        .collect();
    Ok(Some(SodSnapshot { rules, existing }))
}

/// `${violation.ruleId}:${violation.identityId}`.
fn violation_key(violation: &Value) -> String {
    format!(
        "{}:{}",
        violation
            .get("ruleId")
            .and_then(Value::as_str)
            .unwrap_or(""),
        violation
            .get("identityId")
            .and_then(Value::as_str)
            .unwrap_or("")
    )
}

/// Operations that can grant (`grantingActions`): separation-of-duties prevent rules are checked around them.
pub const GRANTING_ACTIONS: &[&str] = &[
    "iam:bindings:create",
    "iam:groups:update",
    "iam:identities:create",
    "iam:access-requests:review",
    "iam:config:apply",
    // Access packages materialize bindings and memberships on assignment and on approved requests.
    "iam:packages:assign",
    "iam:packages:approve",
    // Team membership fills the team's backing group, and a team created under a parent joins its members to it.
    "iam:teams:create",
    "iam:teams:update",
    // A role that gains `inherits` hands the inherited role to everyone who already holds it.
    "iam:roles:update",
];

/// What `sodSnapshot` returns: the prevent rules and the conflicts that already existed (`{ruleId}:{identityId}`).
#[derive(Debug, Clone)]
pub struct SodSnapshot {
    pub rules: Vec<SodRule>,
    pub existing: IndexSet<String>,
}

/// After the operation: refuses (rolling the transaction back) when it created a new prevent-rule conflict.
pub async fn sod_verify(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    snapshot: Option<&SodSnapshot>,
    identity_ids: Option<&[String]>,
) -> IamResult<()> {
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    let created = sod_violations(ctx, tx, tenant_id, Some(&snapshot.rules), identity_ids)
        .await?
        .into_iter()
        .find(|violation| !snapshot.existing.contains(&violation_key(violation)));
    let Some(created) = created else {
        return Ok(());
    };
    let mut names = Vec::new();
    for role_id in created
        .get("roleIds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let name = tx
            .get("roles", role_id)
            .await?
            .and_then(|role| role.get("name").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_else(|| role_id.to_owned());
        names.push(name);
    }
    Err(IamError::with_status(
        "SOD_CONFLICT",
        format!(
            "Separation of duties ({}): one person cannot hold {}",
            created
                .get("ruleName")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            names.join(" and ")
        ),
        409,
    ))
}

/// Every identity (optionally only `identityIds`) that holds two or more roles of a rule.
pub async fn sod_violations(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    rules: Option<&[crate::sod::SodRule]>,
    identity_ids: Option<&[String]>,
) -> IamResult<Vec<Value>> {
    let by_tenant = || Filter::new().eq("tenantId", tenant_id);
    let loaded;
    let active: &[SodRule] = match rules {
        Some(rules) => rules,
        None => {
            let mut found = Vec::new();
            for record in tx.find("sodRules", &by_tenant(), &all()).await? {
                found.push(crate::port::decode::<SodRule>(record)?);
            }
            loaded = found;
            &loaded
        }
    };
    if active.is_empty() {
        return Ok(Vec::new());
    }
    // Future-dated bindings count: a prevent rule must also stop a conflict that is scheduled to start.
    let bindings: Vec<Record> = tx
        .find("bindings", &by_tenant(), &all())
        .await?
        .into_iter()
        .filter(|binding| !expired_binding(ctx, binding))
        .collect();
    let mut groups_of: IndexMap<String, IndexSet<String>> = IndexMap::new();
    for member in tx.find("groupMembers", &by_tenant(), &all()).await? {
        if !live_membership(ctx, &member) {
            continue;
        }
        groups_of
            .entry(member_str(&member, "identityId").to_owned())
            .or_default()
            .insert(member_str(&member, "groupId").to_owned());
    }
    let subjects: Vec<String> = match identity_ids {
        Some(ids) => ids.to_vec(),
        None => tx
            .find("identities", &by_tenant(), &all())
            .await?
            .iter()
            .filter(|identity| identity.get("status").and_then(Value::as_str) != Some("deleted"))
            .map(|identity| member_str(identity, "id").to_owned())
            .collect(),
    };
    let mut expand = InheritedRoles::new(&tx.find("roles", &by_tenant(), &all()).await?);
    let empty = IndexSet::new();
    let mut violations = Vec::new();
    for identity_id in &subjects {
        let member_of = groups_of.get(identity_id).unwrap_or(&empty);
        let mut held = IndexSet::new();
        for binding in &bindings {
            let subject_id = member_str(binding, "subjectId");
            let applies = if binding.get("subjectType").and_then(Value::as_str) == Some("identity")
            {
                subject_id == identity_id
            } else {
                member_of.contains(subject_id)
            };
            if applies {
                held.extend(expand.expand(member_str(binding, "roleId")));
            }
        }
        for rule in active {
            let conflicting: Vec<&String> = rule
                .role_ids
                .iter()
                .filter(|role_id| held.contains(*role_id))
                .collect();
            if conflicting.len() >= 2 {
                violations.push(json!({
                    "ruleId": rule.id,
                    "ruleName": rule.name,
                    "mode": rule.mode,
                    "identityId": identity_id,
                    "roleIds": conflicting,
                }));
            }
        }
    }
    Ok(violations)
}
