//! Port of `packages/server/src/api/reports.ts`: the access-hygiene report of a tenant: what is about to end, what is
//! elevated right now, and what nobody uses. Sections the caller may not read are omitted and named in `omitted`.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamResult, Identity,
    IdentityStatus, Record, js as core_js,
};
use better_iam_types::api::reports;
use serde_json::{Map, Value, json};

use crate::api::service_accounts::credential_summary_json;
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::metrics::locale_compare;
use crate::models::{Binding, BindingActivation, GroupMember};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::decode;
use crate::validation::integer;

/// One day in milliseconds.
const DAY: f64 = 86_400_000.0;

/// The `reports` API group (`createReportsApi(ctx)`): one method per route `reports/{method}`.
pub struct ReportsApi {
    ctx: Arc<ServerContext>,
}

/// `createReportsApi(ctx)`.
pub fn create_reports_api(ctx: &Arc<ServerContext>) -> IamResult<ReportsApi> {
    Ok(ReportsApi { ctx: ctx.clone() })
}

/// `may(tx, principal, tenantId, action)`: whether the caller may perform `action` on the tenant.
async fn may(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    action: &str,
) -> IamResult<bool> {
    Ok(ctx
        .decisions()?
        .decide(
            tx,
            principal,
            &AuthorizationRequest {
                credential: CredentialInput::default(),
                tenant_id: tenant_id.to_owned(),
                action: action.to_owned(),
                resource: ResourceTarget {
                    kind: "iam".into(),
                    id: tenant_id.to_owned(),
                },
            },
            true,
        )
        .await?
        .allowed)
}

impl ReportsApi {
    /// `reports/access`: identities and bindings ending within `withinMs` (30 days by default), keys unused for
    /// `unusedForMs` (30 days) or ending soon, live activations, and pending activation requests. Requires
    /// iam:identities:read; the binding and credential sections additionally need iam:bindings:read and
    /// iam:credentials:read and are omitted otherwise.
    pub async fn access(
        &self,
        credential: &CredentialInput,
        input: Body<reports::AccessInput>,
    ) -> IamResult<Reply<reports::AccessOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let windows = report_windows(&Value::Object(body.raw().clone()))?;
                let bindings = may(ctx, &tx, &principal, &tenant_id, "iam:bindings:read").await?;
                let credentials =
                    may(ctx, &tx, &principal, &tenant_id, "iam:credentials:read").await?;
                let sections = json!({ "bindings": bindings, "credentials": credentials });
                Ok(build_access_report(ctx, &tx, &tenant_id, &windows, &sections).await?)
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:identities:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// A number member of a report window or record (`NaN` when absent).
fn number(value: &Value, key: &str) -> f64 {
    value
        .get(key)
        .and_then(core_js::as_number)
        .unwrap_or(f64::NAN)
}

/// `a - b || tie(a, b)` for a sort comparator: the sign of the difference, else the tie-breaker.
fn by_number_then(a: f64, b: f64, tie: impl FnOnce() -> Ordering) -> Ordering {
    let difference = a - b;
    if difference != 0.0 && !difference.is_nan() {
        return if difference < 0.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    tie()
}

/// `(a.id < b.id ? -1 : 1)`.
fn by_id(a: &str, b: &str) -> Ordering {
    if core_js::cmp_utf16(a, b) == Ordering::Less {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// Inserts `key: value` when `value` is a non-empty string (`...(value ? { key: value } : {})`).
fn insert_truthy(out: &mut Map<String, Value>, key: &str, value: Option<&String>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        out.insert(key.into(), Value::String(value.clone()));
    }
}

/// Builds the access report of one tenant inside a transaction. The API decides per caller which sections to
/// include; deployment operations (the digest) include every section. `windows` is `{ withinMs, unusedForMs }`
/// ([`report_windows`]); `sections` is `{ bindings, credentials }` (booleans).
pub async fn build_access_report(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    windows: &Value,
    sections: &Value,
) -> IamResult<Value> {
    let now = ctx.now();
    let within_ms = number(windows, "withinMs");
    let unused_for_ms = number(windows, "unusedForMs");
    let horizon = now + within_ms;
    let may = |section: &str| sections.get(section) == Some(&Value::Bool(true));
    let tenant_filter = || Filter::new().eq("tenantId", tenant_id);
    let all = FindOptions::default();

    let mut identities: Vec<(Identity, Record)> = Vec::new();
    for record in tx.find("identities", &tenant_filter(), &all).await? {
        let identity: Identity = decode(record.clone())?;
        if identity.status != IdentityStatus::Deleted {
            identities.push((identity, record));
        }
    }
    let names: HashMap<String, String> = identities
        .iter()
        .map(|(identity, _)| (identity.id.clone(), identity.name.clone()))
        .collect();
    let mut expiring: Vec<(&Identity, &Record, f64)> = identities
        .iter()
        .filter_map(|(identity, record)| {
            let expires_at = identity.expires_at?;
            // Past its deadline an identity is a finding only until the worker has disabled it.
            (expires_at <= horizon
                && (expires_at > now || identity.status == IdentityStatus::Active))
                .then_some((identity, record, expires_at))
        })
        .collect();
    expiring.sort_by(|a, b| by_number_then(a.2, b.2, || locale_compare(&a.0.name, &b.0.name)));
    let expiring: Vec<Value> = expiring
        .into_iter()
        .map(|(identity, record, expires_at)| {
            let mut out = Map::new();
            out.insert("id".into(), Value::String(identity.id.clone()));
            out.insert("name".into(), Value::String(identity.name.clone()));
            insert_truthy(&mut out, "email", identity.email.as_ref());
            out.insert(
                "kind".into(),
                record.get("kind").cloned().unwrap_or(Value::Null),
            );
            out.insert(
                "status".into(),
                record.get("status").cloned().unwrap_or(Value::Null),
            );
            out.insert("expiresAt".into(), crate::js::number(expires_at));
            out.insert("expired".into(), Value::Bool(expires_at <= now));
            Value::Object(out)
        })
        .collect();
    let mut report = Map::new();
    report.insert("generatedAt".into(), crate::js::number(now));
    report.insert("withinMs".into(), crate::js::number(within_ms));
    report.insert("unusedForMs".into(), crate::js::number(unused_for_ms));
    report.insert(
        "identities".into(),
        json!({
            "total": identities.len(),
            "disabled": identities
                .iter()
                .filter(|(identity, _)| identity.status == IdentityStatus::Disabled)
                .count(),
            "expiring": expiring,
        }),
    );
    let mut omitted: Vec<Value> = Vec::new();
    report.insert("omitted".into(), Value::Array(Vec::new()));

    if may("bindings") {
        let roles: HashMap<String, String> = tx
            .find("roles", &tenant_filter(), &all)
            .await?
            .iter()
            .map(|role| (string_member(role, "id"), string_member(role, "name")))
            .collect();
        let groups: HashMap<String, String> = tx
            .find("groups", &tenant_filter(), &all)
            .await?
            .iter()
            .map(|group| (string_member(group, "id"), string_member(group, "name")))
            .collect();
        let mut all_bindings: Vec<Binding> = Vec::new();
        for record in tx.find("bindings", &tenant_filter(), &all).await? {
            all_bindings.push(decode(record)?);
        }
        let bindings: Vec<&Binding> = all_bindings
            .iter()
            .filter(|binding| !ctx.expired_binding(binding))
            .collect();
        let mut memberships: Vec<GroupMember> = Vec::new();
        for record in tx.find("groupMembers", &tenant_filter(), &all).await? {
            memberships.push(decode(record)?);
        }
        // An activation or request counts only while it could grant: its binding is still live and eligible, its
        // holder is active, and (for a group binding) still a member.
        let active_ids: HashSet<&str> = identities
            .iter()
            .filter(|(identity, _)| identity.status == IdentityStatus::Active)
            .map(|(identity, _)| identity.id.as_str())
            .collect();
        let eligible_bindings: HashMap<&str, &Binding> = bindings
            .iter()
            .filter(|binding| binding.eligible == Some(true) && ctx.live_binding(binding))
            .map(|binding| (binding.id.as_str(), *binding))
            .collect();
        let applies = |activation: &BindingActivation| {
            let Some(binding) = eligible_bindings.get(activation.binding_id.as_str()) else {
                return false;
            };
            if !active_ids.contains(activation.identity_id.as_str()) {
                return false;
            }
            binding.subject_type == "identity"
                || memberships.iter().any(|member| {
                    member.group_id == binding.subject_id
                        && member.identity_id == activation.identity_id
                        && ctx.live_membership(member)
                })
        };
        let mut activations: Vec<BindingActivation> = Vec::new();
        for record in tx
            .find("bindingActivations", &tenant_filter(), &all)
            .await?
        {
            let activation: BindingActivation = decode(record)?;
            if applies(&activation) {
                activations.push(activation);
            }
        }
        let subject_name = |binding: &Binding| {
            if binding.subject_type == "identity" {
                names.get(&binding.subject_id)
            } else {
                groups.get(&binding.subject_id)
            }
        };
        let summarize = |binding: &Binding, at: f64| {
            let mut out = Map::new();
            out.insert("id".into(), Value::String(binding.id.clone()));
            out.insert("roleId".into(), Value::String(binding.role_id.clone()));
            insert_truthy(&mut out, "roleName", roles.get(&binding.role_id));
            out.insert(
                "subjectType".into(),
                Value::String(binding.subject_type.clone()),
            );
            out.insert(
                "subjectId".into(),
                Value::String(binding.subject_id.clone()),
            );
            insert_truthy(&mut out, "subjectName", subject_name(binding));
            out.insert("expiresAt".into(), crate::js::number(at));
            out.insert(
                "eligible".into(),
                Value::Bool(binding.eligible == Some(true)),
            );
            Value::Object(out)
        };
        let mut scheduled: Vec<(&Binding, f64)> = all_bindings
            .iter()
            .filter_map(|binding| {
                let starts_at = binding.starts_at?;
                (starts_at > now && starts_at <= horizon && !ctx.expired_binding(binding))
                    .then_some((binding, starts_at))
            })
            .collect();
        let mut ending: Vec<(&Binding, f64)> = bindings
            .iter()
            .filter_map(|binding| {
                let expires_at = binding.expires_at?;
                (expires_at <= horizon).then_some((*binding, expires_at))
            })
            .collect();
        ending.sort_by(|a, b| by_number_then(a.1, b.1, || by_id(&a.0.id, &b.0.id)));
        scheduled.sort_by(|a, b| by_number_then(a.1, b.1, || by_id(&a.0.id, &b.0.id)));
        let mut ending_memberships: Vec<(&GroupMember, f64)> = memberships
            .iter()
            .filter_map(|member| {
                let expires_at = member.expires_at?;
                (expires_at <= horizon && ctx.live_membership(member))
                    .then_some((member, expires_at))
            })
            .collect();
        ending_memberships.sort_by(|a, b| by_number_then(a.1, b.1, || by_id(&a.0.id, &b.0.id)));
        let mut live: Vec<&BindingActivation> = activations
            .iter()
            .filter(|activation| {
                activation.expires_at > now
                    && activation.status.as_deref() != Some("pending")
                    && activation.status.as_deref() != Some("denied")
            })
            .collect();
        live.sort_by(|a, b| by_number_then(a.expires_at, b.expires_at, || by_id(&a.id, &b.id)));
        let mut section = Map::new();
        section.insert("total".into(), json!(bindings.len()));
        section.insert(
            "eligible".into(),
            json!(
                bindings
                    .iter()
                    .filter(|binding| binding.eligible == Some(true))
                    .count()
            ),
        );
        section.insert(
            "windowed".into(),
            json!(
                bindings
                    .iter()
                    .filter(|binding| binding.window.is_some())
                    .count()
            ),
        );
        section.insert(
            "expiring".into(),
            Value::Array(
                ending
                    .iter()
                    .map(|(binding, at)| summarize(binding, *at))
                    .collect(),
            ),
        );
        section.insert(
            "starting".into(),
            Value::Array(
                scheduled
                    .iter()
                    .map(|(binding, at)| summarize(binding, *at))
                    .collect(),
            ),
        );
        section.insert(
            "expiringMemberships".into(),
            Value::Array(
                ending_memberships
                    .iter()
                    .map(|(member, expires_at)| {
                        let mut out = Map::new();
                        out.insert("groupId".into(), Value::String(member.group_id.clone()));
                        insert_truthy(&mut out, "groupName", groups.get(&member.group_id));
                        out.insert(
                            "identityId".into(),
                            Value::String(member.identity_id.clone()),
                        );
                        insert_truthy(&mut out, "identityName", names.get(&member.identity_id));
                        out.insert("expiresAt".into(), crate::js::number(*expires_at));
                        Value::Object(out)
                    })
                    .collect(),
            ),
        );
        section.insert(
            "activations".into(),
            Value::Array(
                live.iter()
                    .map(|activation| {
                        let mut out = Map::new();
                        out.insert("id".into(), Value::String(activation.id.clone()));
                        out.insert(
                            "identityId".into(),
                            Value::String(activation.identity_id.clone()),
                        );
                        insert_truthy(&mut out, "identityName", names.get(&activation.identity_id));
                        out.insert("roleId".into(), Value::String(activation.role_id.clone()));
                        insert_truthy(&mut out, "roleName", roles.get(&activation.role_id));
                        out.insert(
                            "activatedAt".into(),
                            crate::js::number(activation.activated_at),
                        );
                        out.insert("expiresAt".into(), crate::js::number(activation.expires_at));
                        insert_truthy(&mut out, "justification", activation.justification.as_ref());
                        Value::Object(out)
                    })
                    .collect(),
            ),
        );
        section.insert(
            "pendingRequests".into(),
            json!(
                activations
                    .iter()
                    .filter(|activation| activation.status.as_deref() == Some("pending")
                        && activation.expires_at > now)
                    .count()
            ),
        );
        report.insert("bindings".into(), Value::Object(section));
    } else {
        omitted.push(Value::String("bindings".into()));
    }

    if may("credentials") {
        let keys: Vec<Value> = tx
            .find("sessions", &tenant_filter().eq("kind", "api-key"), &all)
            .await?
            .iter()
            .map(|session| credential_summary_json(session, now))
            .filter(|key| key.get("expired") != Some(&Value::Bool(true)))
            .collect();
        let unused_since = now - unused_for_ms;
        let id_of = |key: &Value| {
            key.get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let mut unused: Vec<&Value> = keys
            .iter()
            .filter(|key| {
                let last_used = match key.get("lastUsedAt") {
                    None | Some(Value::Null) => number(key, "createdAt"),
                    Some(_) => number(key, "lastUsedAt"),
                };
                last_used <= unused_since
            })
            .collect();
        unused.sort_by(|a, b| {
            by_number_then(number(a, "createdAt"), number(b, "createdAt"), || {
                by_id(&id_of(a), &id_of(b))
            })
        });
        let mut ending: Vec<&Value> = keys
            .iter()
            .filter(|key| number(key, "expiresAt") <= horizon)
            .collect();
        ending.sort_by(|a, b| {
            by_number_then(number(a, "expiresAt"), number(b, "expiresAt"), || {
                by_id(&id_of(a), &id_of(b))
            })
        });
        report.insert(
            "credentials".into(),
            json!({ "total": keys.len(), "unused": unused, "expiring": ending }),
        );
    } else {
        omitted.push(Value::String("credentials".into()));
    }
    report.insert("omitted".into(), Value::Array(omitted));
    Ok(Value::Object(report))
}

/// Whether a report has anything worth telling someone about.
pub fn report_has_findings(report: &Value) -> IamResult<bool> {
    let non_empty = |value: Option<&Value>| {
        value
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
    };
    let identities = report.get("identities");
    if non_empty(identities.and_then(|section| section.get("expiring"))) {
        return Ok(true);
    }
    if let Some(bindings) = report.get("bindings")
        && (non_empty(bindings.get("expiring"))
            || non_empty(bindings.get("starting"))
            || non_empty(bindings.get("expiringMemberships"))
            || non_empty(bindings.get("activations"))
            || number(bindings, "pendingRequests") > 0.0)
    {
        return Ok(true);
    }
    if let Some(credentials) = report.get("credentials")
        && (non_empty(credentials.get("unused")) || non_empty(credentials.get("expiring")))
    {
        return Ok(true);
    }
    Ok(false)
}

/// Validates the report windows: 0 to ten years, 30 days by default. Answers `{ withinMs, unusedForMs }`.
pub fn report_windows(input: &Value) -> IamResult<Value> {
    let window = |key: &str| {
        let value = match input.get(key) {
            None | Some(Value::Null) => crate::js::number(30.0 * DAY),
            Some(value) => value.clone(),
        };
        integer(Some(&value), key, 0.0, 10.0 * 365.0 * DAY)
    };
    let within_ms = window("withinMs")?;
    let unused_for_ms = window("unusedForMs")?;
    Ok(json!({
        "withinMs": crate::js::number(within_ms),
        "unusedForMs": crate::js::number(unused_for_ms),
    }))
}
