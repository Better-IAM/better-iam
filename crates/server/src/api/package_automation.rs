//! Port of `packages/server/src/api/package-automation.ts`.
//!
//! The reconciler of automatic (birthright) access packages: plans, per package, which identities should gain,
//! keep, or lose the package under its rule, and applies each change in its own transaction under the rule owner's
//! grant authority. Runs after identity changes and rule saves (post-commit), on demand, and as a scheduler job.
//!
//! Trust: a rule grants under its owner's authority to whoever matches, so whoever can change the facts it tests
//! chooses the recipients, with no grant rights of their own. Declared attributes and managerId are set with
//! iam:identities:update, and members of a group without role bindings with iam:groups:update alone; rules keyed on
//! them are only as safe as those permissions (ruleWarnings says so on every such clause). Facts access packages
//! create never count: package memberships, and team memberships synced from them (identityFacts, org-rules.ts), so
//! rules never chain onto another package or keep themselves alive.

use std::cmp::Ordering;
use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, Filter, FindOptions, IamError, IamResult, IamStoreExt,
    Identity, IdentityStatus, PolicyDocument, Record, Tenant,
};
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::packages::{
    AutoAssignPreview, PackageReconcileResult, PublicAutoAssign, allow, assign_package,
    authorize_package, end_of, live_assignment, refresh_assignment, retime_assignment,
    revoke_assignment, rule_environment,
};
use crate::context::{ServerContext, Store};
use crate::invariants::{invariant_snapshot, invariant_verify};
use crate::js::{cmp_utf16, number, number_to_string, utf16_len};
use crate::licenses::reconcile_licenses_of;
use crate::metrics::locale_compare;
use crate::models::{
    AccessPackage, ApprovedChanges, AutoAssignRule, Binding, GrantAuthority, GroupMember,
    PackageAssignment, PackageRuleIssue,
};
use crate::org_rules::{TenantOrgFacts, load_org_facts, org_rule_environment};
use crate::package_rules::{
    DEFAULT_MAX_GRANTS, DEFAULT_MAX_REMOVALS, RuleEnvironment, RuleMatch, RuleOrgFacts,
    parse_auto_assign, rule_context, rule_document, rule_group_ids, rule_keys, rule_match,
    rule_problem, rule_warnings,
};
use crate::port::{decode, encode};
use crate::sod::{SodRule, SodSnapshot, sod_verify, sod_violations};
use crate::utils::id;
use crate::validation::{integer, text256};

/// Who confirmed a run (`ReconcileOptions.confirmedBy`).
#[derive(Debug, Clone)]
pub enum ConfirmedBy {
    Principal(Box<AuthenticatedPrincipal>),
    DeploymentOperator,
}

/// `ReconcileOptions`.
#[derive(Debug, Clone, Default)]
pub struct ReconcileOptions {
    pub tenant_id: Option<String>,
    pub package_id: Option<String>,
    pub identity_ids: Option<Vec<String>>,
    /// Write attempts per tenant; unlimited for identity-change runs.
    pub limit: Option<f64>,
    /// `'identity-change' | 'rule-change' | 'manual' | 'schedule'`.
    pub trigger: String,
    /// Approve the package's planned counts and exempt this run from brakes (needs packageId).
    pub confirmed_by: Option<ConfirmedBy>,
    /// The person whose call triggered the run, for audit metadata.
    pub requested_by: Option<String>,
}

impl ReconcileOptions {
    /// The options from their JSON form (`{ tenantId?, packageId?, identityIds?, limit?, trigger, confirmedBy?,
    /// requestedBy? }`). A principal cannot travel as JSON: `confirmedBy` there is only `'deployment-operator'`; callers
    /// confirming as a person build [`ReconcileOptions`] and call [`reconcile_package_rules_with`].
    pub fn from_value(options: &Value) -> Self {
        let string = |key: &str| options.get(key).and_then(Value::as_str).map(str::to_owned);
        Self {
            tenant_id: string("tenantId"),
            package_id: string("packageId"),
            identity_ids: options
                .get("identityIds")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect()
                }),
            limit: options.get("limit").and_then(crate::js::as_number),
            trigger: string("trigger").unwrap_or_default(),
            confirmed_by: (options.get("confirmedBy").and_then(Value::as_str)
                == Some("deployment-operator"))
            .then_some(ConfirmedBy::DeploymentOperator),
            requested_by: string("requestedBy"),
        }
    }
}

struct IdentityFacts {
    identity: Identity,
    /// Live memberships no access package owns, with team backing groups only through a team membership that counts:
    /// what a rule sees as identity.groups.
    direct_group_ids: Vec<String>,
    /// What a rule sees as identity.teams and identity.departments (org-rules.ts).
    org: RuleOrgFacts,
    memberships: Vec<GroupMember>,
    bindings: Vec<Binding>,
    assignment: Option<PackageAssignment>,
}

struct TenantFacts {
    identities: Vec<Identity>,
    memberships: IndexMap<String, Vec<GroupMember>>,
    bindings: IndexMap<String, Vec<Binding>>,
    assignments: IndexMap<String, PackageAssignment>,
    group_ids: IndexSet<String>,
    issues: IndexMap<String, PackageRuleIssue>,
    org: TenantOrgFacts,
}

#[derive(Debug, Clone)]
struct PlannedStep {
    package_id: String,
    package_name: String,
    identity_id: String,
    change: &'static str,
    reason: &'static str,
    rule_key: String,
    matched_by: Vec<String>,
    has_issue: bool,
}

#[derive(Debug, Default, Clone, Copy)]
struct PlanCounts {
    assign: f64,
    refresh: f64,
    restore: f64,
    ending: f64,
    revoke: f64,
    manual: f64,
    frozen: f64,
    keep: f64,
    matching: f64,
    excluded: f64,
    revoke_rule_cleared: f64,
}

impl PlanCounts {
    fn bump(&mut self, key: &str) {
        match key {
            "assign" => self.assign += 1.0,
            "refresh" => self.refresh += 1.0,
            "restore" => self.restore += 1.0,
            "ending" => self.ending += 1.0,
            "revoke" => self.revoke += 1.0,
            "manual" => self.manual += 1.0,
            "frozen" => self.frozen += 1.0,
            "keep" => self.keep += 1.0,
            _ => {}
        }
    }
}

struct PackagePlan {
    steps: Vec<PlannedStep>,
    counts: PlanCounts,
}

enum Health {
    Ok {
        principal: Box<AuthenticatedPrincipal>,
        authority: Box<GrantAuthority>,
    },
    Failed {
        reason: &'static str,
        detail: String,
    },
}

/// The rule owner's principal and authority a step applies under (absent for removals of a suspended rule).
#[derive(Clone, Default)]
struct StepState {
    principal: Option<Arc<AuthenticatedPrincipal>>,
    authority: Option<Arc<GrantAuthority>>,
}

/// What a run should do for one identity and package, or which bucket it falls into when nothing.
#[derive(Default)]
struct Decision {
    change: Option<&'static str>,
    reason: Option<&'static str>,
    bucket: Option<&'static str>,
    matched: Option<RuleMatch>,
}

fn additive(change: &str) -> bool {
    matches!(change, "assign" | "refresh" | "restore")
}

fn rule_key_of(rule: Option<&AutoAssignRule>) -> String {
    match rule {
        Some(rule) => format!(
            "{}:{}",
            number_to_string(rule.revision),
            number_to_string(rule.updated_at)
        ),
        None => "none".to_owned(),
    }
}

fn issue_key_failed(package_id: &str, identity_id: &str) -> String {
    format!("{package_id}:identity:{identity_id}")
}

fn issue_key_suspended(package_id: &str) -> String {
    format!("{package_id}:suspended")
}

fn issue_key_braked(package_id: &str, direction: &str) -> String {
    format!("{package_id}:braked:{direction}")
}

fn all() -> FindOptions {
    FindOptions::default()
}

fn by_tenant(tenant_id: &str) -> Filter {
    Filter::new().eq("tenantId", tenant_id)
}

async fn find_as<T: serde::de::DeserializeOwned>(
    reader: &Store,
    collection: &str,
    filter: Filter,
) -> IamResult<Vec<T>> {
    reader
        .find(collection, &filter, &all())
        .await?
        .into_iter()
        .map(decode)
        .collect()
}

async fn get_as<T: serde::de::DeserializeOwned>(
    reader: &Store,
    collection: &str,
    record_id: &str,
) -> IamResult<Option<T>> {
    reader
        .get(collection, record_id)
        .await?
        .map(decode)
        .transpose()
}

/// A rule as the JSON the rule functions read.
fn rule_value(rule: &AutoAssignRule) -> Value {
    serde_json::to_value(rule).unwrap_or(Value::Null)
}

/// `message.slice(0, max)` in UTF-16 code units.
fn slice_utf16(message: &str, max: usize) -> String {
    if utf16_len(message) <= max {
        return message.to_owned();
    }
    let mut units = 0;
    let mut out = String::new();
    for c in message.chars() {
        let width = c.len_utf16();
        if units + width > max {
            break;
        }
        units += width;
        out.push(c);
    }
    out
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// `{ ...a, ...b }` for JSON objects.
fn merged(base: &Map<String, Value>, extra: Map<String, Value>) -> Map<String, Value> {
    let mut out = base.clone();
    for (key, value) in extra {
        out.insert(key, value);
    }
    out
}

/// Everything the planner needs about a tenant, read once per collection (the store loads every row anyway).
async fn load_facts(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    tenant_id: &str,
    identity_ids: Option<&[String]>,
) -> IamResult<TenantFacts> {
    let wanted: Option<IndexSet<&String>> = identity_ids.map(|ids| ids.iter().collect());
    let mut identities: Vec<Identity> =
        find_as::<Identity>(reader, "identities", by_tenant(tenant_id))
            .await?
            .into_iter()
            .filter(|identity| {
                identity.status != IdentityStatus::Deleted
                    && wanted
                        .as_ref()
                        .is_none_or(|wanted| wanted.contains(&identity.id))
            })
            .collect();
    identities.sort_by(|a, b| {
        if cmp_utf16(&a.id, &b.id) == Ordering::Less {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    });
    let mut memberships: IndexMap<String, Vec<GroupMember>> = IndexMap::new();
    for member in find_as::<GroupMember>(reader, "groupMembers", by_tenant(tenant_id)).await? {
        memberships
            .entry(member.identity_id.clone())
            .or_default()
            .push(member);
    }
    let mut bindings: IndexMap<String, Vec<Binding>> = IndexMap::new();
    for binding in find_as::<Binding>(
        reader,
        "bindings",
        by_tenant(tenant_id).eq("subjectType", "identity"),
    )
    .await?
    {
        bindings
            .entry(binding.subject_id.clone())
            .or_default()
            .push(binding);
    }
    let assignments: IndexMap<String, PackageAssignment> =
        find_as::<PackageAssignment>(reader, "packageAssignments", by_tenant(tenant_id))
            .await?
            .into_iter()
            .map(|assignment| {
                (
                    assignment.unique_key.clone().unwrap_or_default(),
                    assignment,
                )
            })
            .collect();
    let group_ids: IndexSet<String> = reader
        .find("groups", &by_tenant(tenant_id), &all())
        .await?
        .iter()
        .map(|group| better_iam_core::record_id(group).to_owned())
        .collect();
    let issues: IndexMap<String, PackageRuleIssue> =
        find_as::<PackageRuleIssue>(reader, "packageRuleIssues", by_tenant(tenant_id))
            .await?
            .into_iter()
            .map(|issue| (issue.unique_key.clone().unwrap_or_default(), issue))
            .collect();
    let org = load_org_facts(reader, tenant_id, ctx.now()).await?;
    Ok(TenantFacts {
        identities,
        memberships,
        bindings,
        assignments,
        group_ids,
        issues,
        org,
    })
}

fn identity_facts(
    ctx: &ServerContext,
    memberships: &[GroupMember],
    bindings: &[Binding],
    assignment: Option<&PackageAssignment>,
    org: &TenantOrgFacts,
    identity: &Identity,
) -> IdentityFacts {
    let live: Vec<&GroupMember> = memberships
        .iter()
        .filter(|member| member.package_assignment_id.is_none() && ctx.live_membership(member))
        .collect();
    let ordinary: Vec<String> = live
        .iter()
        .filter(|member| member.team_id.is_none())
        .map(|member| member.group_id.clone())
        .collect();
    let org = org.of(&identity.id, &ordinary);
    // A team's backing group copies the team's members, and team sync copies package memberships of its source groups
    // into the team: the backing membership counts only while the team membership behind it does (org.teams holds the
    // counted teams and every team above them, exactly the teams whose backing groups that membership fills).
    let teams: IndexSet<&String> = org.teams.iter().collect();
    let mut direct_group_ids = ordinary.clone();
    direct_group_ids.extend(
        live.iter()
            .filter(|member| {
                member
                    .team_id
                    .as_ref()
                    .is_some_and(|team_id| teams.contains(team_id))
            })
            .map(|member| member.group_id.clone()),
    );
    IdentityFacts {
        identity: identity.clone(),
        memberships: memberships.to_vec(),
        direct_group_ids,
        org,
        bindings: bindings.to_vec(),
        assignment: assignment.cloned(),
    }
}

impl TenantFacts {
    fn identity_facts(
        &self,
        ctx: &ServerContext,
        identity: &Identity,
        package_id: &str,
    ) -> IdentityFacts {
        identity_facts(
            ctx,
            self.memberships
                .get(&identity.id)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            self.bindings
                .get(&identity.id)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            self.assignments
                .get(&format!("{package_id}:{}", identity.id)),
            &self.org,
            identity,
        )
    }
}

/// Whether an automatic assignment lacks something its package and rule call for (a role binding of its own under the
/// rule's authority, a membership lasting as long as it) or holds something they no longer call for. The same
/// predicate materialize satisfies, so a refresh converges in one pass.
fn incomplete(
    ctx: &ServerContext,
    pkg: &AccessPackage,
    rule: &AutoAssignRule,
    f: &IdentityFacts,
) -> IamResult<bool> {
    let Some(a) = f.assignment.as_ref() else {
        return Ok(false);
    };
    let own: Vec<&Binding> = f
        .bindings
        .iter()
        .filter(|binding| {
            binding.package_assignment_id.as_deref() == Some(a.id.as_str())
                && !ctx.expired_binding(binding)
        })
        .collect();
    for role_id in &pkg.role_ids {
        if !own
            .iter()
            .any(|binding| &binding.role_id == role_id && binding.authority_id == rule.authority_id)
        {
            return Ok(true);
        }
    }
    if own.iter().any(|binding| {
        !pkg.role_ids.contains(&binding.role_id) || binding.authority_id != rule.authority_id
    }) {
        return Ok(true);
    }
    for group_id in &pkg.group_ids {
        let member = f
            .memberships
            .iter()
            .find(|candidate| &candidate.group_id == group_id && ctx.live_membership(candidate));
        match member {
            None => return Ok(true),
            Some(member) => {
                if member.package_assignment_id.as_deref() != Some(a.id.as_str())
                    && end_of(member.expires_at)? < end_of(a.expires_at)?
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(f.memberships.iter().any(|member| {
        member.package_assignment_id.as_deref() == Some(a.id.as_str())
            && ctx.live_membership(member)
            && !pkg.group_ids.contains(&member.group_id)
    }))
}

/// What a run should do for one identity and package, or which bucket it falls into when nothing.
fn decide_change(
    ctx: &Arc<ServerContext>,
    pkg: &AccessPackage,
    doc: Option<&PolicyDocument>,
    f: &IdentityFacts,
) -> IamResult<Decision> {
    let a = f.assignment.as_ref();
    let live = match a {
        Some(a) => live_assignment(ctx, a)?,
        None => false,
    };
    let automatic = live && a.is_some_and(|a| a.rule_revision.is_some());
    let rule = pkg.auto_assign.as_ref();
    if live && !automatic {
        return Ok(Decision {
            bucket: Some("manual"),
            ..Decision::default()
        });
    }
    let (Some(rule), Some(doc)) = (rule, doc) else {
        return Ok(if automatic {
            Decision {
                change: Some("revoke"),
                reason: Some("rule-cleared"),
                ..Decision::default()
            }
        } else {
            Decision {
                bucket: Some("none"),
                ..Decision::default()
            }
        });
    };
    // Disabled and expired identities are frozen: never assigned or removed by a rule (offboarding handles leavers).
    if f.identity.status != IdentityStatus::Active || ctx.identity_expired(&f.identity) {
        return Ok(Decision {
            bucket: Some("frozen"),
            ..Decision::default()
        });
    }
    let group_ids = Value::Array(
        f.direct_group_ids
            .iter()
            .cloned()
            .map(Value::String)
            .collect(),
    );
    let matched = rule_match(
        doc,
        &f.identity,
        &rule_context(&f.identity, &group_ids, Some(&f.org))?,
    )?;
    let with = |change: Option<&'static str>,
                reason: Option<&'static str>,
                bucket: Option<&'static str>,
                matched: RuleMatch| Decision {
        change,
        reason,
        bucket,
        matched: Some(matched),
    };
    if !matched.matched {
        if !automatic {
            let bucket = if !matched.matched_by.is_empty() && !matched.excluded_by.is_empty() {
                "excluded"
            } else {
                "none"
            };
            return Ok(with(None, None, Some(bucket), matched));
        }
        if rule
            .grace_ms
            .is_none_or(|grace| grace == 0.0 || grace.is_nan())
        {
            return Ok(with(
                Some("revoke"),
                Some("no-longer-matches"),
                None,
                matched,
            ));
        }
        if a.is_some_and(|a| a.expires_at.is_some()) {
            return Ok(with(None, None, Some("ending"), matched));
        }
        return Ok(with(
            Some("ending"),
            Some("no-longer-matches"),
            None,
            matched,
        ));
    }
    if !live {
        return Ok(with(Some("assign"), Some("matches"), None, matched));
    }
    let a = a.expect("a live assignment");
    if a.expires_at.is_some() {
        return Ok(with(Some("restore"), Some("matches-again"), None, matched));
    }
    if a.rule_revision != Some(rule.revision) {
        return Ok(with(Some("refresh"), Some("revision"), None, matched));
    }
    if incomplete(ctx, pkg, rule, f)? {
        return Ok(with(Some("refresh"), Some("incomplete"), None, matched));
    }
    Ok(with(None, None, Some("keep"), matched))
}

fn plan_package(
    ctx: &Arc<ServerContext>,
    facts: &TenantFacts,
    pkg: &AccessPackage,
) -> IamResult<PackagePlan> {
    let doc = match &pkg.auto_assign {
        Some(rule) => Some(rule_document(&rule_value(rule))?),
        None => None,
    };
    let mut counts = PlanCounts::default();
    let mut steps = Vec::new();
    for identity in &facts.identities {
        let f = facts.identity_facts(ctx, identity, &pkg.id);
        // Orphans of a cleared rule: only identities still holding an automatic assignment matter.
        if pkg.auto_assign.is_none()
            && !f
                .assignment
                .as_ref()
                .is_some_and(|assignment| assignment.rule_revision.is_some())
        {
            continue;
        }
        let decision = decide_change(ctx, pkg, doc.as_ref(), &f)?;
        if decision.matched.as_ref().is_some_and(|m| m.matched) {
            counts.matching += 1.0;
        }
        if decision.bucket == Some("excluded") {
            counts.excluded += 1.0;
        }
        if let Some(bucket) = decision
            .bucket
            .filter(|bucket| *bucket != "excluded" && *bucket != "none")
        {
            counts.bump(if bucket == "ending" { "keep" } else { bucket });
        }
        let Some(change) = decision.change else {
            continue;
        };
        counts.bump(change);
        if change == "revoke" && decision.reason == Some("rule-cleared") {
            counts.revoke_rule_cleared += 1.0;
        }
        steps.push(PlannedStep {
            package_id: pkg.id.clone(),
            package_name: pkg.name.clone(),
            identity_id: identity.id.clone(),
            change,
            reason: decision.reason.unwrap_or_default(),
            rule_key: rule_key_of(pkg.auto_assign.as_ref()),
            matched_by: decision
                .matched
                .map(|matched| matched.matched_by)
                .unwrap_or_default(),
            has_issue: facts
                .issues
                .contains_key(&issue_key_failed(&pkg.id, &identity.id)),
        });
    }
    Ok(PackagePlan { steps, counts })
}

/// Whether the rule may add anything right now: its owner is active, their grant authority is intact and theirs, and
/// (with `rights`) they still hold everything assigning the package by hand needs. Runs outside a transaction.
async fn rule_health(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    pkg: &AccessPackage,
    rights: bool,
) -> IamResult<Health> {
    let rule = pkg.auto_assign.as_ref().expect("a package with a rule");
    let owner: Option<Identity> = get_as(reader, "identities", &rule.owner_id).await?;
    let owner = match owner {
        Some(owner) if owner.status == IdentityStatus::Active && !ctx.identity_expired(&owner) => {
            owner
        }
        owner => {
            let state = match &owner {
                None => "deleted",
                Some(owner) if owner.status == IdentityStatus::Deleted => "deleted",
                Some(owner) if owner.status != IdentityStatus::Active => "disabled",
                Some(_) => "expired",
            };
            return Ok(Health::Failed {
                reason: "owner-inactive",
                detail: format!(
                    "The rule owner {} is {state}",
                    owner
                        .as_ref()
                        .map(|owner| owner.name.clone())
                        .unwrap_or_else(|| rule.owner_id.clone())
                ),
            });
        }
    };
    let principal = ctx.decisions()?.simulated_principal(&owner, true);
    let authority = match ctx
        .granting_authority(reader, &principal, &pkg.tenant_id, Some(&rule.authority_id))
        .await
    {
        Ok(authority) => authority,
        Err(_) => {
            return Ok(Health::Failed {
                reason: "authority-revoked",
                detail: "The rule owner\u{2019}s grant authority is revoked or no longer theirs"
                    .to_owned(),
            });
        }
    };
    if rights {
        let checked: IamResult<()> = async {
            allow(
                ctx,
                reader,
                &principal,
                &pkg.tenant_id,
                "iam:packages:assign",
                &pkg.id,
                "assign this package",
            )
            .await?;
            authorize_package(
                ctx,
                reader,
                &principal,
                pkg,
                Some(&json!({ "groupAuthorities": true, "authorityId": rule.authority_id })),
            )
            .await?;
            Ok(())
        }
        .await;
        if let Err(error) = checked {
            return Ok(Health::Failed {
                reason: "owner-lacks-rights",
                detail: error.message,
            });
        }
    }
    Ok(Health::Ok {
        principal: Box::new(principal),
        authority: Box::new(authority),
    })
}

/// The problem `recordIssue` records.
struct IssueInput<'a> {
    kind: &'a str,
    identity_id: Option<&'a str>,
    code: &'a str,
    message: &'a str,
}

/// Records a problem once per transition (new, or a new code or revision): written and audited only then, so a
/// persistent failure retried every run neither grows the audit log nor the table. Own transaction; never throws.
async fn record_issue(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    pkg: &AccessPackage,
    issue: IssueInput<'_>,
    action: &str,
    metadata: Map<String, Value>,
) -> bool {
    let unique_key = match issue.kind {
        "failed" => issue_key_failed(&pkg.id, issue.identity_id.unwrap_or_default()),
        "suspended" => issue_key_suspended(&pkg.id),
        _ => issue_key_braked(&pkg.id, issue.code),
    };
    let revision = pkg
        .auto_assign
        .as_ref()
        .map(|rule| rule.revision)
        .unwrap_or(0.0);
    let unique_key = &unique_key;
    let issue = &issue;
    let metadata = &metadata;
    ctx.store
        .transaction(|tx| async move {
            let existing = tx
                .find(
                    "packageRuleIssues",
                    &by_tenant(tenant_id).eq("uniqueKey", unique_key.as_str()),
                    &all(),
                )
                .await?
                .into_iter()
                .next();
            if let Some(existing) = &existing {
                let same_code = existing.get("code").and_then(Value::as_str) == Some(issue.code);
                let same_revision =
                    existing.get("revision").and_then(crate::js::as_number) == Some(revision);
                if same_code && same_revision {
                    return Ok(false);
                }
            }
            let mut record = Record::new();
            record.insert(
                "id".into(),
                Value::String(
                    existing
                        .as_ref()
                        .map(|existing| better_iam_core::record_id(existing).to_owned())
                        .unwrap_or_else(id),
                ),
            );
            record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            record.insert("uniqueKey".into(), Value::String(unique_key.clone()));
            record.insert("packageId".into(), Value::String(pkg.id.clone()));
            record.insert("kind".into(), Value::String(issue.kind.to_owned()));
            if let Some(identity_id) = issue.identity_id.filter(|id| !id.is_empty()) {
                record.insert("identityId".into(), Value::String(identity_id.to_owned()));
            }
            record.insert("code".into(), Value::String(issue.code.to_owned()));
            record.insert(
                "message".into(),
                Value::String(slice_utf16(issue.message, 1024)),
            );
            record.insert("revision".into(), number(revision));
            record.insert("since".into(), number(ctx.now()));
            if existing.is_some() {
                tx.put("packageRuleIssues", &record).await?;
            } else {
                tx.insert("packageRuleIssues", &record).await?;
            }
            let mut event = Record::new();
            event.insert("id".into(), Value::String(id()));
            event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            event.insert(
                "actorId".into(),
                Value::String("deployment-operator".into()),
            );
            event.insert("action".into(), Value::String(action.to_owned()));
            event.insert("resourceId".into(), Value::String(pkg.id.clone()));
            event.insert("timestamp".into(), number(ctx.now()));
            event.insert("outcome".into(), Value::String("deny".into()));
            event.insert("metadata".into(), Value::Object(metadata.clone()));
            ctx.events()?.record_audit(&tx, &event).await?;
            Ok(true)
        })
        .await
        .unwrap_or(false)
}

/// Deletes stored issues (own transaction; never throws).
async fn clear_issues(ctx: &Arc<ServerContext>, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    // A failure is retried next run.
    let _ = ctx
        .store
        .transaction(|tx| async move {
            for issue_id in ids {
                if tx.get("packageRuleIssues", issue_id).await?.is_some() {
                    tx.delete("packageRuleIssues", issue_id).await?;
                }
            }
            Ok(())
        })
        .await;
}

fn system_event(
    ctx: &ServerContext,
    tenant_id: &str,
    action: &str,
    resource_id: &str,
    outcome: &str,
    metadata: Map<String, Value>,
) -> Record {
    let mut event = Record::new();
    event.insert("id".into(), Value::String(id()));
    event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    event.insert(
        "actorId".into(),
        Value::String("deployment-operator".into()),
    );
    event.insert("action".into(), Value::String(action.to_owned()));
    event.insert("resourceId".into(), Value::String(resource_id.to_owned()));
    event.insert("timestamp".into(), number(ctx.now()));
    event.insert("outcome".into(), Value::String(outcome.to_owned()));
    event.insert("metadata".into(), Value::Object(metadata));
    event
}

fn count_of(value: &Value) -> Value {
    match value {
        Value::Array(items) => number(items.len() as f64),
        _ => Value::Null,
    }
}

/// Applies one planned change in its own transaction, after re-deciding from fresh records: when the decision
/// changed since planning, nothing is written ('stale'). A separation-of-duties conflict, or a newly broken enforced
/// access invariant (INVARIANT_VIOLATION), that a grant would create rolls back only this change, which the caller
/// records as a failed issue.
async fn apply_step(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    step: &PlannedStep,
    state: &StepState,
    base: &Map<String, Value>,
) -> IamResult<&'static str> {
    ctx.store
        .transaction(|tx| async move {
            let Some(pkg) =
                get_as::<AccessPackage>(&tx, "accessPackages", &step.package_id).await?
            else {
                return Ok("stale");
            };
            if pkg.tenant_id != tenant_id || rule_key_of(pkg.auto_assign.as_ref()) != step.rule_key
            {
                return Ok("stale");
            }
            let Some(identity) = get_as::<Identity>(&tx, "identities", &step.identity_id).await?
            else {
                return Ok("stale");
            };
            if identity.tenant_id != tenant_id || identity.status == IdentityStatus::Deleted {
                return Ok("stale");
            }
            let memberships: Vec<GroupMember> = find_as(
                &tx,
                "groupMembers",
                by_tenant(tenant_id).eq("identityId", identity.id.as_str()),
            )
            .await?;
            let bindings: Vec<Binding> = find_as(
                &tx,
                "bindings",
                by_tenant(tenant_id)
                    .eq("subjectType", "identity")
                    .eq("subjectId", identity.id.as_str()),
            )
            .await?;
            let assignment: Option<PackageAssignment> = find_as::<PackageAssignment>(
                &tx,
                "packageAssignments",
                by_tenant(tenant_id).eq("uniqueKey", format!("{}:{}", pkg.id, identity.id)),
            )
            .await?
            .into_iter()
            .next();
            let org = load_org_facts(&tx, tenant_id, ctx.now()).await?;
            // The assignment of this package: the facts are keyed by `{packageId}:{identityId}`.
            let f = identity_facts(
                ctx,
                &memberships,
                &bindings,
                assignment.as_ref().filter(|assignment| {
                    assignment.unique_key.as_deref()
                        == Some(format!("{}:{}", pkg.id, identity.id).as_str())
                }),
                &org,
                &identity,
            );
            let doc = match &pkg.auto_assign {
                Some(rule) => Some(rule_document(&rule_value(rule))?),
                None => None,
            };
            let decision = decide_change(ctx, &pkg, doc.as_ref(), &f)?;
            if decision.change != Some(step.change) {
                return Ok("stale");
            }
            let rule = pkg.auto_assign.as_ref();
            let mut snapshot: Option<SodSnapshot> = None;
            if additive(step.change) {
                let rules: Vec<SodRule> = find_as::<SodRule>(&tx, "sodRules", by_tenant(tenant_id))
                    .await?
                    .into_iter()
                    .filter(|candidate| candidate.mode == "prevent")
                    .collect();
                let mut closure: IndexSet<String> = pkg.role_ids.iter().cloned().collect();
                for group_id in &pkg.group_ids {
                    for binding in find_as::<Binding>(
                        &tx,
                        "bindings",
                        by_tenant(tenant_id)
                            .eq("subjectType", "group")
                            .eq("subjectId", group_id.as_str()),
                    )
                    .await?
                    {
                        if !ctx.expired_binding(&binding) {
                            closure.insert(binding.role_id);
                        }
                    }
                }
                if rules.iter().any(|candidate| {
                    candidate
                        .role_ids
                        .iter()
                        .any(|role_id| closure.contains(role_id))
                }) {
                    let violations = sod_violations(
                        ctx,
                        &tx,
                        tenant_id,
                        Some(&rules),
                        Some(std::slice::from_ref(&identity.id)),
                    )
                    .await?;
                    let existing: IndexSet<String> = violations
                        .iter()
                        .map(|violation| {
                            format!(
                                "{}:{}",
                                crate::js::js_string(violation.get("ruleId")),
                                crate::js::js_string(violation.get("identityId"))
                            )
                        })
                        .collect();
                    snapshot = Some(SodSnapshot { rules, existing });
                }
            }
            // Enforced access invariants bind automatic grants as they bind a manual assign (whose operation checks
            // them): this reconcile runs outside any operation, so it checks them itself.
            let guardrails = if additive(step.change) {
                invariant_snapshot(ctx, &tx, tenant_id, "iam:packages:assign").await?
            } else {
                None
            };
            let now = ctx.now();
            let action: &str;
            let mut metadata = Map::new();
            match step.change {
                "assign" => {
                    let principal = state.principal.as_ref().expect("the rule owner");
                    let authority = state.authority.as_ref().expect("the rule authority");
                    let rule = rule.expect("a rule");
                    let created = assign_package(
                        ctx,
                        &tx,
                        principal,
                        &pkg,
                        &json!({ "identityId": identity.id }),
                        Some(&json!({
                            "authority": Value::Object(encode(authority.as_ref())),
                            "ruleRevision": number(rule.revision),
                        })),
                    )
                    .await?;
                    let assignment = created.get("assignment").cloned().unwrap_or(Value::Null);
                    action = "package:auto-assign";
                    metadata.insert("mode".into(), json!("assign"));
                    metadata.insert("reason".into(), json!(step.reason));
                    metadata.insert(
                        "bindings".into(),
                        count_of(assignment.get("bindingIds").unwrap_or(&Value::Null)),
                    );
                    metadata.insert(
                        "memberships".into(),
                        count_of(assignment.get("membershipIds").unwrap_or(&Value::Null)),
                    );
                    metadata.insert(
                        "skipped".into(),
                        created.get("skipped").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("matchedBy".into(), json!(step.matched_by));
                }
                "refresh" | "restore" => {
                    let principal = state.principal.as_ref().expect("the rule owner");
                    let authority = state.authority.as_ref().expect("the rule authority");
                    let mut current = assignment.clone().expect("an assignment");
                    if step.change == "restore" {
                        current = retime_assignment(ctx, &tx, &pkg, &current, None, None).await?;
                    }
                    let refreshed =
                        refresh_assignment(ctx, &tx, principal, &pkg, &current, authority).await?;
                    let member = |key: &str| refreshed.get(key).cloned().unwrap_or(Value::Null);
                    action = "package:auto-assign";
                    metadata.insert("mode".into(), json!(step.change));
                    metadata.insert("reason".into(), json!(step.reason));
                    metadata.insert("bindings".into(), member("bindings"));
                    metadata.insert("memberships".into(), member("memberships"));
                    metadata.insert("removedBindings".into(), member("removedBindings"));
                    metadata.insert("removedMemberships".into(), member("removedMemberships"));
                    metadata.insert("skipped".into(), member("skipped"));
                    metadata.insert("matchedBy".into(), json!(step.matched_by));
                }
                "ending" => {
                    let grace_ms = rule.and_then(|rule| rule.grace_ms).unwrap_or(f64::NAN);
                    let ends_at = now + grace_ms;
                    retime_assignment(
                        ctx,
                        &tx,
                        &pkg,
                        assignment.as_ref().expect("an assignment"),
                        Some(ends_at),
                        None,
                    )
                    .await?;
                    action = "package:auto-ending";
                    metadata.insert("endsAt".into(), number(ends_at));
                    metadata.insert("graceMs".into(), number(grace_ms));
                }
                _ => {
                    let counts =
                        revoke_assignment(ctx, &tx, assignment.as_ref().expect("an assignment"))
                            .await?;
                    action = "package:auto-revoke";
                    metadata.insert("reason".into(), json!(step.reason));
                    if let Value::Object(counts) = counts {
                        for (key, value) in counts {
                            metadata.insert(key, value);
                        }
                    }
                }
            }
            sod_verify(
                ctx,
                &tx,
                tenant_id,
                snapshot.as_ref(),
                Some(std::slice::from_ref(&identity.id)),
            )
            .await?;
            invariant_verify(ctx, &tx, tenant_id, guardrails.as_ref()).await?;
            let issue = tx
                .find(
                    "packageRuleIssues",
                    &by_tenant(tenant_id).eq("uniqueKey", issue_key_failed(&pkg.id, &identity.id)),
                    &all(),
                )
                .await?
                .into_iter()
                .next();
            if let Some(issue) = issue {
                tx.delete("packageRuleIssues", better_iam_core::record_id(&issue))
                    .await?;
            }
            let mut audit = base.clone();
            audit.insert("packageId".into(), Value::String(pkg.id.clone()));
            audit.insert("packageName".into(), Value::String(pkg.name.clone()));
            audit.insert(
                "revision".into(),
                number(rule.map(|rule| rule.revision).unwrap_or(0.0)),
            );
            if let Some(rule) = rule {
                audit.insert("ownerId".into(), Value::String(rule.owner_id.clone()));
            }
            audit.insert("identityId".into(), Value::String(identity.id.clone()));
            for (key, value) in metadata {
                audit.insert(key, value);
            }
            let mut event = system_event(ctx, tenant_id, action, &pkg.id, "allow", audit);
            event.insert("timestamp".into(), number(now));
            ctx.events()?.record_audit(&tx, &event).await?;
            Ok("applied")
        })
        .await
}

/// Writes the rule's approval: the grants and removals a run would make now, which unattended runs may then apply
/// for the next day without tripping the brakes. Called when a person saves a rule or confirms held-back changes.
/// Answers `{ pkg, grants, removals }`.
pub async fn approve_rule(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    pkg: &crate::models::AccessPackage,
) -> IamResult<Value> {
    let unchanged = || {
        json!({
            "pkg": Value::Object(encode(pkg)),
            "grants": 0,
            "removals": 0,
        })
    };
    let Some(rule) = pkg.auto_assign.as_ref() else {
        return Ok(unchanged());
    };
    let env = rule_environment(ctx, tx, &Value::Object(encode(pkg))).await?;
    if rule_problem(&rule_value(rule), &env)?.is_some() {
        return Ok(unchanged());
    }
    let plan = plan_package(ctx, &load_facts(ctx, tx, &pkg.tenant_id, None).await?, pkg)?;
    let grants = plan.counts.assign + plan.counts.refresh;
    let removals = plan.counts.ending + plan.counts.revoke - plan.counts.revoke_rule_cleared;
    let mut approved = pkg.clone();
    let mut approved_rule = rule.clone();
    approved_rule.approved = Some(ApprovedChanges {
        grants,
        removals,
        until: ctx.now() + 86_400_000.0,
    });
    approved.auto_assign = Some(approved_rule);
    let stored = tx.put("accessPackages", &encode(&approved)).await?;
    Ok(json!({
        "pkg": Value::Object(stored),
        "grants": number(grants),
        "removals": number(removals),
    }))
}

/// The tenant's groups with role bindings, for ruleWarnings: adding members to them needs the bindings' authorities,
/// not iam:groups:update alone. Read only when the rule tests identity.groups.
async fn bound_groups(
    reader: &Store,
    tenant_id: &str,
    rule: &Value,
) -> IamResult<IndexSet<String>> {
    if rule_group_ids(Some(rule))?.is_empty() {
        return Ok(IndexSet::new());
    }
    Ok(reader
        .find(
            "bindings",
            &by_tenant(tenant_id).eq("subjectType", "group"),
            &all(),
        )
        .await?
        .iter()
        .map(|binding| crate::js::js_string(binding.get("subjectId")))
        .collect())
}

/// A rule as administrators see it: owner, whether it runs, warnings, and the latest problems.
pub async fn auto_assign_view(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    pkg: &crate::models::AccessPackage,
    env: &crate::package_rules::RuleEnvironment,
) -> IamResult<crate::api::packages::PublicAutoAssign> {
    let rule = pkg
        .auto_assign
        .as_ref()
        .ok_or_else(crate::js::internal_error)?;
    let rule_json = rule_value(rule);
    let owner: Option<Identity> = get_as(reader, "identities", &rule.owner_id).await?;
    let mut issues: Vec<PackageRuleIssue> = find_as(
        reader,
        "packageRuleIssues",
        by_tenant(&pkg.tenant_id).eq("packageId", pkg.id.as_str()),
    )
    .await?;
    issues.sort_by(|a, b| b.since.partial_cmp(&a.since).unwrap_or(Ordering::Equal));
    let mut suspension: Option<(&'static str, String)> = None;
    if let Some(problem) = rule_problem(&rule_json, env)? {
        suspension = Some(("invalid-rule", problem));
    } else if !owner
        .as_ref()
        .is_some_and(|owner| owner.status == IdentityStatus::Active && !ctx.identity_expired(owner))
    {
        suspension = Some((
            "owner-inactive",
            format!(
                "The rule owner {} is not active",
                owner
                    .as_ref()
                    .map(|owner| owner.name.clone())
                    .unwrap_or_else(|| rule.owner_id.clone())
            ),
        ));
    } else {
        let authority: Option<GrantAuthority> =
            get_as(reader, "grantAuthorities", &rule.authority_id).await?;
        let broken = match &authority {
            None => true,
            Some(authority) => {
                authority.revoked
                    || (authority.identity_id != rule.owner_id
                        && !crate::js::truthy(authority.extra.get("rootIssued")))
                    || ctx.authority_chain(reader, &authority.id).await?.is_none()
            }
        };
        if broken {
            suspension = Some((
                "authority-revoked",
                "The rule owner\u{2019}s grant authority is revoked or no longer theirs".to_owned(),
            ));
        } else if let Some(stored) = issues
            .iter()
            .find(|issue| issue.kind == "suspended" && issue.code == "owner-lacks-rights")
        {
            suspension = Some(("owner-lacks-rights", stored.message.clone()));
        }
    }
    let mut names: IndexMap<String, String> = IndexMap::new();
    for issue in issues.iter().take(20) {
        if let Some(identity_id) = issue.identity_id.as_ref()
            && !names.contains_key(identity_id)
        {
            let identity: Option<Identity> = get_as(reader, "identities", identity_id).await?;
            names.insert(
                identity_id.clone(),
                identity
                    .map(|identity| identity.name)
                    .unwrap_or_else(|| identity_id.clone()),
            );
        }
    }
    let bound = bound_groups(reader, &pkg.tenant_id, &rule_json).await?;
    let warnings = rule_warnings(&rule_json, Some(&bound))?;
    let issue_views: Vec<Value> = issues
        .iter()
        .take(20)
        .map(|issue| {
            let mut view = Map::new();
            view.insert("kind".into(), Value::String(issue.kind.clone()));
            if let Some(identity_id) = &issue.identity_id {
                view.insert("identityId".into(), Value::String(identity_id.clone()));
                view.insert(
                    "identityName".into(),
                    Value::String(names.get(identity_id).cloned().unwrap_or_default()),
                );
            }
            view.insert("code".into(), Value::String(issue.code.clone()));
            view.insert("message".into(), Value::String(issue.message.clone()));
            view.insert("since".into(), number(issue.since));
            Value::Object(view)
        })
        .collect();
    let to_values = |clauses: &[better_iam_core::Conditions]| -> Vec<Value> {
        clauses
            .iter()
            .map(|clause| serde_json::to_value(clause).unwrap_or(Value::Null))
            .collect()
    };
    Ok(PublicAutoAssign {
        owner_name: owner
            .as_ref()
            .map(|owner| owner.name.clone())
            .unwrap_or_else(|| rule.owner_id.clone()),
        status: if suspension.is_some() {
            "suspended".into()
        } else {
            "active".into()
        },
        suspended_reason: suspension.as_ref().map(|(reason, _)| (*reason).to_owned()),
        suspended_detail: suspension.as_ref().map(|(_, detail)| detail.clone()),
        warnings,
        issue_count: issues.len() as f64,
        issues: issue_views,
        include: to_values(&rule.include),
        exclude: rule.exclude.as_deref().map(to_values),
        grace_ms: rule.grace_ms,
        max_grants: rule.max_grants,
        max_removals: rule.max_removals,
        owner_id: rule.owner_id.clone(),
        authority_id: rule.authority_id.clone(),
        revision: rule.revision,
        updated_at: rule.updated_at,
        approved: rule
            .approved
            .as_ref()
            .map(|approved| serde_json::to_value(approved).unwrap_or(Value::Null)),
        extra: rule.extra.clone(),
    })
}

/// The result before anything ran (`emptyResult(trigger)`).
struct RunResult {
    trigger: String,
    assigned: f64,
    refreshed: f64,
    restored: f64,
    ending: f64,
    revoked: f64,
    stale: f64,
    failed: Vec<Value>,
    suspended: Vec<Value>,
    braked: Vec<Value>,
    inactive_tenants: f64,
    failed_tenants: Vec<Value>,
    truncated: bool,
}

impl RunResult {
    fn new(trigger: &str) -> Self {
        Self {
            trigger: trigger.to_owned(),
            assigned: 0.0,
            refreshed: 0.0,
            restored: 0.0,
            ending: 0.0,
            revoked: 0.0,
            stale: 0.0,
            failed: Vec::new(),
            suspended: Vec::new(),
            braked: Vec::new(),
            inactive_tenants: 0.0,
            failed_tenants: Vec::new(),
            truncated: false,
        }
    }

    fn finish(self) -> PackageReconcileResult {
        PackageReconcileResult {
            trigger: Value::String(self.trigger),
            assigned: self.assigned,
            refreshed: self.refreshed,
            restored: self.restored,
            ending: self.ending,
            revoked: self.revoked,
            stale: self.stale,
            failed: self.failed,
            suspended: self.suspended,
            braked: self.braked,
            skipped: json!({
                "inactiveTenants": number(self.inactive_tenants),
                "failedTenants": self.failed_tenants,
            }),
            truncated: self.truncated,
            extra: Map::new(),
        }
    }
}

/// The reconciler. Plans from plain reads (no transaction), then applies each change in its own transaction under
/// the rule owner's authority, removals first. Never runs inside another transaction.
pub async fn reconcile_package_rules(
    ctx: &Arc<ServerContext>,
    options: &Value,
) -> IamResult<crate::api::packages::PackageReconcileResult> {
    reconcile_package_rules_with(ctx, &ReconcileOptions::from_value(options)).await
}

/// [`reconcile_package_rules`] with typed options (a person's confirmation carries their principal).
pub async fn reconcile_package_rules_with(
    ctx: &Arc<ServerContext>,
    options: &ReconcileOptions,
) -> IamResult<PackageReconcileResult> {
    let mut result = RunResult::new(&options.trigger);
    let tenants: Vec<Tenant> = match &options.tenant_id {
        Some(tenant_id) => vec![ctx.tenant(&ctx.store, tenant_id).await?],
        None => {
            let mut tenants: Vec<Tenant> =
                find_as(&ctx.store, "tenants", Filter::new().eq("status", "active")).await?;
            tenants.sort_by(|a, b| {
                if cmp_utf16(&a.id, &b.id) == Ordering::Less {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            });
            tenants
        }
    };
    for tenant in tenants {
        if tenant.status != better_iam_core::TenantStatus::Active {
            result.inactive_tenants += 1.0;
            continue;
        }
        if let Err(error) = reconcile_tenant(ctx, &tenant.id, options, &mut result).await {
            result.failed_tenants.push(json!({
                "tenantId": tenant.id,
                "code": error.code,
                "message": error.message,
            }));
        }
    }
    Ok(result.finish())
}

/// A queued change with the state it applies under.
struct Queued {
    step: PlannedStep,
    state: StepState,
}

fn change_rank(change: &str) -> u8 {
    match change {
        "revoke" => 0,
        "ending" => 1,
        "restore" => 2,
        "refresh" => 3,
        _ => 4,
    }
}

fn queue_order(a: &Queued, b: &Queued) -> Ordering {
    change_rank(a.step.change)
        .cmp(&change_rank(b.step.change))
        .then_with(|| a.step.has_issue.cmp(&b.step.has_issue))
        .then_with(|| locale_compare(&a.step.package_name, &b.step.package_name))
        .then_with(|| cmp_utf16(&a.step.identity_id, &b.step.identity_id))
}

async fn reconcile_tenant(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    options: &ReconcileOptions,
    result: &mut RunResult,
) -> IamResult<()> {
    let reader = &ctx.store;
    let now = ctx.now();
    let all_packages: Vec<AccessPackage> =
        find_as(reader, "accessPackages", by_tenant(tenant_id)).await?;
    let scoped: Vec<&AccessPackage> = match &options.package_id {
        Some(package_id) => all_packages
            .iter()
            .filter(|pkg| &pkg.id == package_id)
            .collect(),
        None => all_packages.iter().collect(),
    };
    let rule_packages = scoped
        .iter()
        .filter(|pkg| pkg.auto_assign.is_some())
        .count();
    if options.trigger == "identity-change" && rule_packages == 0 {
        return Ok(());
    }
    let mut facts = load_facts(ctx, reader, tenant_id, options.identity_ids.as_deref()).await?;
    let mut orphan_ids: IndexSet<String> = IndexSet::new();
    for assignment in facts.assignments.values() {
        if assignment.rule_revision.is_some() && live_assignment(ctx, assignment)? {
            orphan_ids.insert(assignment.package_id.clone());
        }
    }
    let mut packages: Vec<AccessPackage> = scoped
        .into_iter()
        .filter(|pkg| pkg.auto_assign.is_some() || orphan_ids.contains(&pkg.id))
        .cloned()
        .collect();
    packages.sort_by(|a, b| {
        locale_compare(&a.name, &b.name).then_with(|| {
            if cmp_utf16(&a.id, &b.id) == Ordering::Less {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        })
    });
    let mut base = Map::new();
    base.insert("trigger".into(), Value::String(options.trigger.clone()));
    if let Some(requested_by) = options.requested_by.as_ref().filter(|id| !id.is_empty()) {
        base.insert("requestedBy".into(), Value::String(requested_by.clone()));
    }
    // A confirmation approves the package's planned counts and exempts this run from the brakes.
    let mut confirmed = false;
    if let (Some(confirmer), Some(package_id)) = (&options.confirmed_by, &options.package_id) {
        let target = packages
            .iter()
            .position(|pkg| &pkg.id == package_id)
            .filter(|index| packages[*index].auto_assign.is_some());
        if let Some(index) = target {
            let target_id = packages[index].id.clone();
            let target_id = &target_id;
            let replaced: Option<AccessPackage> = ctx
                .store
                .transaction(|tx| async move {
                    let Some(fresh) = get_as::<AccessPackage>(&tx, "accessPackages", target_id)
                        .await?
                        .filter(|fresh| fresh.auto_assign.is_some())
                    else {
                        return Ok(None);
                    };
                    let approval = approve_rule(ctx, &tx, &fresh).await?;
                    let approved: AccessPackage =
                        decode(object(approval.get("pkg").cloned().unwrap_or(Value::Null)))?;
                    let until = approved
                        .auto_assign
                        .as_ref()
                        .and_then(|rule| rule.approved.as_ref())
                        .map(|approved| number(approved.until))
                        .unwrap_or(Value::Null);
                    let mut metadata = Map::new();
                    metadata.insert("packageId".into(), Value::String(fresh.id.clone()));
                    metadata.insert("packageName".into(), Value::String(fresh.name.clone()));
                    metadata.insert(
                        "grants".into(),
                        approval.get("grants").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert(
                        "removals".into(),
                        approval.get("removals").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("until".into(), until);
                    match confirmer {
                        ConfirmedBy::DeploymentOperator => {
                            let event = system_event(
                                ctx,
                                tenant_id,
                                "package:auto-confirm",
                                &fresh.id,
                                "allow",
                                metadata,
                            );
                            ctx.events()?.record_audit(&tx, &event).await?;
                        }
                        ConfirmedBy::Principal(principal) => {
                            ctx.events()?
                                .audit(
                                    &tx,
                                    principal,
                                    "package:auto-confirm",
                                    tenant_id,
                                    &fresh.id,
                                    AuditOutcome::Allow,
                                    false,
                                    Some(metadata),
                                )
                                .await?;
                        }
                    }
                    Ok(Some(approved))
                })
                .await?;
            if let Some(approved) = replaced {
                packages[index] = approved;
            }
            confirmed = true;
        }
    }
    let braked = (options.trigger == "schedule" || options.trigger == "manual") && !confirmed;
    let mut removals: Vec<Queued> = Vec::new();
    let mut additions: Vec<Queued> = Vec::new();
    let mut resolved_issues: Vec<String> = Vec::new();
    let mut attempted: IndexSet<String> = IndexSet::new();
    for pkg in &packages {
        let rule = pkg.auto_assign.as_ref();
        if let Some(rule) = rule {
            let env = RuleEnvironment {
                identity_attributes: ctx.catalog.identity_attributes.clone(),
                groups: Some(facts.group_ids.clone()),
                packaged_groups: Some(pkg.group_ids.iter().cloned().collect()),
                org: Some(json!({
                    "teams": facts.org.team_ids.iter().collect::<Vec<_>>(),
                    "departments": facts.org.department_ids.iter().collect::<Vec<_>>(),
                    "licenses": facts.org.license_keys.iter().collect::<Vec<_>>(),
                })),
                extra: Map::new(),
            };
            if let Some(problem) = rule_problem(&rule_value(rule), &env)? {
                // A rule that cannot be evaluated freezes everything: never "matches nobody, revoke everyone".
                result.suspended.push(json!({
                    "tenantId": tenant_id,
                    "packageId": pkg.id,
                    "reason": "invalid-rule",
                    "detail": problem,
                }));
                record_issue(
                    ctx,
                    tenant_id,
                    pkg,
                    IssueInput {
                        kind: "suspended",
                        identity_id: None,
                        code: "invalid-rule",
                        message: &problem,
                    },
                    "package:auto-suspended",
                    merged(
                        &base,
                        object(json!({
                            "packageId": pkg.id,
                            "packageName": pkg.name,
                            "reason": "invalid-rule",
                            "detail": problem,
                        })),
                    ),
                )
                .await;
                continue;
            }
        }
        let plan = plan_package(ctx, &facts, pkg)?;
        let mut steps = plan.steps.clone();
        let mut state = StepState::default();
        if rule.is_some() && steps.iter().any(|step| additive(step.change)) {
            let health = rule_health(ctx, reader, pkg, true).await?;
            let suspended_key = issue_key_suspended(&pkg.id);
            match health {
                Health::Failed { reason, detail } => {
                    // Removals continue: removing access needs no authority, so leavers still lose it when the owner
                    // has left.
                    steps.retain(|step| !additive(step.change));
                    result.suspended.push(json!({
                        "tenantId": tenant_id,
                        "packageId": pkg.id,
                        "reason": reason,
                        "detail": detail,
                    }));
                    record_issue(
                        ctx,
                        tenant_id,
                        pkg,
                        IssueInput {
                            kind: "suspended",
                            identity_id: None,
                            code: reason,
                            message: &detail,
                        },
                        "package:auto-suspended",
                        merged(
                            &base,
                            object(json!({
                                "packageId": pkg.id,
                                "packageName": pkg.name,
                                "reason": reason,
                                "detail": detail,
                            })),
                        ),
                    )
                    .await;
                }
                Health::Ok {
                    principal,
                    authority,
                } => {
                    state = StepState {
                        principal: Some(Arc::new(*principal)),
                        authority: Some(Arc::new(*authority)),
                    };
                    if let Some(stored) = facts.issues.get(&suspended_key).cloned() {
                        let stored = &stored;
                        let base = &base;
                        ctx.store
                            .transaction(|tx| async move {
                                if tx.get("packageRuleIssues", &stored.id).await?.is_some() {
                                    tx.delete("packageRuleIssues", &stored.id).await?;
                                }
                                let event = system_event(
                                    ctx,
                                    tenant_id,
                                    "package:auto-resumed",
                                    &pkg.id,
                                    "allow",
                                    merged(
                                        base,
                                        object(json!({
                                            "packageId": pkg.id,
                                            "packageName": pkg.name,
                                            "previousReason": stored.code,
                                        })),
                                    ),
                                );
                                ctx.events()?.record_audit(&tx, &event).await
                            })
                            .await?;
                        facts.issues.shift_remove(&suspended_key);
                    }
                }
            }
        }
        // Brakes: unattended runs hold back unusually large changes until a person confirms them.
        if let Some(rule) = rule.filter(|_| braked) {
            let approved = rule
                .approved
                .as_ref()
                .filter(|approved| approved.until > now);
            let grants_threshold = rule
                .max_grants
                .unwrap_or(DEFAULT_MAX_GRANTS)
                .max(approved.map(|approved| approved.grants).unwrap_or(0.0));
            let removals_threshold = rule
                .max_removals
                .unwrap_or(DEFAULT_MAX_REMOVALS)
                .max(approved.map(|approved| approved.removals).unwrap_or(0.0));
            fn is_grant(step: &PlannedStep) -> bool {
                step.change == "assign" || step.change == "refresh"
            }
            fn is_removal(step: &PlannedStep) -> bool {
                step.change == "ending"
                    || (step.change == "revoke" && step.reason == "no-longer-matches")
            }
            type StepTest = fn(&PlannedStep) -> bool;
            let directions: [(&str, StepTest, f64); 2] = [
                ("grants", is_grant, grants_threshold),
                ("removals", is_removal, removals_threshold),
            ];
            for (direction, test, threshold) in directions {
                let planned = steps.iter().filter(|step| test(step)).count() as f64;
                let key = issue_key_braked(&pkg.id, direction);
                if planned > threshold {
                    steps.retain(|step| !test(step));
                    result.braked.push(json!({
                        "tenantId": tenant_id,
                        "packageId": pkg.id,
                        "direction": direction,
                        "planned": number(planned),
                        "threshold": number(threshold),
                    }));
                    record_issue(
                        ctx,
                        tenant_id,
                        pkg,
                        IssueInput {
                            kind: "braked",
                            identity_id: None,
                            code: direction,
                            message: &format!(
                                "{} planned, threshold {}",
                                number_to_string(planned),
                                number_to_string(threshold)
                            ),
                        },
                        "package:auto-braked",
                        merged(
                            &base,
                            object(json!({
                                "packageId": pkg.id,
                                "packageName": pkg.name,
                                "direction": direction,
                                "planned": number(planned),
                                "threshold": number(threshold),
                            })),
                        ),
                    )
                    .await;
                } else if let Some(stored) = facts.issues.get(&key) {
                    resolved_issues.push(stored.id.clone());
                }
            }
        }
        for step in steps {
            let queued = Queued {
                state: state.clone(),
                step,
            };
            if additive(queued.step.change) {
                additions.push(queued);
            } else {
                removals.push(queued);
            }
        }
        // Failed issues whose pair needs nothing any more are resolved.
        let planned: IndexSet<&String> = plan.steps.iter().map(|step| &step.identity_id).collect();
        for issue in facts.issues.values() {
            if issue.kind == "failed"
                && issue.package_id == pkg.id
                && let Some(identity_id) = issue.identity_id.as_ref().filter(|id| !id.is_empty())
                && !planned.contains(identity_id)
                && facts
                    .identities
                    .iter()
                    .any(|identity| &identity.id == identity_id)
            {
                resolved_issues.push(issue.id.clone());
            }
        }
    }
    // Removals first (a mover's old access goes before their new access arrives), then additions; within each,
    // changes without a stored failure come first so persistent failures never starve fresh work.
    removals.sort_by(queue_order);
    additions.sort_by(queue_order);
    let mut budget = if options.trigger == "identity-change" {
        f64::INFINITY
    } else {
        options.limit.unwrap_or(1000.0)
    };
    let mut run_base = base.clone();
    if confirmed {
        run_base.insert("confirmed".into(), Value::Bool(true));
    }
    for Queued { step, state } in removals.into_iter().chain(additions) {
        if budget <= 0.0 {
            result.truncated = true;
            break;
        }
        budget -= 1.0;
        attempted.insert(format!("{}:{}", step.package_id, step.identity_id));
        match apply_step(ctx, tenant_id, &step, &state, &run_base).await {
            Ok("stale") => result.stale += 1.0,
            Ok(_) => match step.change {
                "assign" => result.assigned += 1.0,
                "refresh" => result.refreshed += 1.0,
                "restore" => result.restored += 1.0,
                "ending" => result.ending += 1.0,
                _ => result.revoked += 1.0,
            },
            Err(error) => {
                if error.code == "CONFLICT" && step.change == "assign" {
                    result.stale += 1.0;
                    continue;
                }
                let (code, message) = (error.code.clone(), error.message.clone());
                result.failed.push(json!({
                    "tenantId": tenant_id,
                    "packageId": step.package_id,
                    "identityId": step.identity_id,
                    "change": step.change,
                    "code": code,
                    "message": message,
                }));
                let Some(pkg) = packages
                    .iter()
                    .find(|candidate| candidate.id == step.package_id)
                else {
                    continue;
                };
                record_issue(
                    ctx,
                    tenant_id,
                    pkg,
                    IssueInput {
                        kind: "failed",
                        identity_id: Some(&step.identity_id),
                        code: &code,
                        message: &message,
                    },
                    "package:auto-failed",
                    merged(
                        &base,
                        object(json!({
                            "packageId": pkg.id,
                            "packageName": pkg.name,
                            "identityId": step.identity_id,
                            "change": step.change,
                            "code": code,
                            "message": message,
                        })),
                    ),
                )
                .await;
            }
        }
    }
    // Full-tenant runs also forget issues of identities or packages that are gone.
    if options.identity_ids.is_none() && options.package_id.is_none() {
        let present: IndexSet<&String> = facts
            .identities
            .iter()
            .map(|identity| &identity.id)
            .collect();
        let by_id: IndexMap<&String, &AccessPackage> =
            all_packages.iter().map(|pkg| (&pkg.id, pkg)).collect();
        for issue in facts.issues.values() {
            let pkg = by_id.get(&issue.package_id);
            let gone_identity = issue.identity_id.as_ref().is_some_and(|identity_id| {
                !identity_id.is_empty() && !present.contains(identity_id)
            });
            if pkg.is_none()
                || gone_identity
                || (issue.kind != "failed" && pkg.is_some_and(|pkg| pkg.auto_assign.is_none()))
            {
                resolved_issues.push(issue.id.clone());
            }
        }
    }
    let unique: Vec<String> = crate::js::unique(resolved_issues);
    let clearable: Vec<String> = unique
        .into_iter()
        .filter(|issue_id| {
            let issue = facts
                .issues
                .values()
                .find(|candidate| &candidate.id == issue_id);
            match issue {
                None => true,
                Some(issue) => match issue.identity_id.as_ref().filter(|id| !id.is_empty()) {
                    None => true,
                    Some(identity_id) => {
                        !attempted.contains(&format!("{}:{identity_id}", issue.package_id))
                    }
                },
            }
        })
        .collect();
    clear_issues(ctx, &clearable).await;
    Ok(())
}

/// Reconciles the license seats and package rules for identities an administrator just changed; never throws (the
/// schedules catch up).
pub async fn after_identity_change(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    identity_ids: &[String],
    result: &Value,
) -> IamResult<Value> {
    if !identity_ids.is_empty() {
        // License seats follow the change first (licenses.ts): rules on identity.licenses then see them, and people a
        // released seat moved off the waiting list are reconciled too. A failure is caught up by the scheduled
        // reconcile.
        if let Ok(seated) = reconcile_licenses_of(ctx, tenant_id, identity_ids, None).await {
            let ids = crate::js::unique(identity_ids.iter().cloned().chain(seated));
            let _ = reconcile_package_rules_with(
                ctx,
                &ReconcileOptions {
                    tenant_id: Some(tenant_id.to_owned()),
                    identity_ids: Some(ids),
                    trigger: "identity-change".into(),
                    ..ReconcileOptions::default()
                },
            )
            .await;
        }
    }
    Ok(result.clone())
}

/// What a rule matches (stored, candidate, or neither: keys only) and, for a package, what a run would change.
/// Read-only; requires iam:identities:read (checked here) to evaluate a rule over the directory.
pub async fn preview_rule(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    input: &Value,
) -> IamResult<crate::api::packages::AutoAssignPreview> {
    let sample_default = number(20.0);
    let sample = integer(
        Some(crate::js::defined(input.get("sample")).unwrap_or(&sample_default)),
        "sample",
        1.0,
        100.0,
    )? as usize;
    let tenant_id = crate::js::js_string(input.get("tenantId"));
    let tenant_id = tenant_id.as_str();
    let keys = rule_keys(
        &ctx.catalog.identity_attributes,
        Some(&json!({ "org": true })),
    )?;
    let pkg: Option<AccessPackage> = match input.get("packageId") {
        Some(package_id) => {
            let package_id = text256(Some(package_id), "packageId")?;
            Some(decode(
                ctx.scoped(
                    tx,
                    "accessPackages",
                    Some(&Value::String(package_id)),
                    tenant_id,
                )
                .await?,
            )?)
        }
        None => None,
    };
    let mut rule: Option<Value> = None;
    let mut candidate_input: Option<crate::package_rules::AutoAssignInput> = None;
    let mut kind = "none";
    if let Some(auto_assign) = input.get("autoAssign") {
        let groups: IndexSet<String> = tx
            .find("groups", &by_tenant(tenant_id), &all())
            .await?
            .iter()
            .map(|group| better_iam_core::record_id(group).to_owned())
            .collect();
        let env = RuleEnvironment {
            identity_attributes: ctx.catalog.identity_attributes.clone(),
            groups: Some(groups),
            packaged_groups: pkg
                .as_ref()
                .map(|pkg| pkg.group_ids.iter().cloned().collect()),
            org: Some(org_rule_environment(tx, tenant_id).await?),
            extra: Map::new(),
        };
        let parsed = parse_auto_assign(Some(auto_assign), &env, None)?;
        rule = Some(parsed.to_value());
        candidate_input = Some(parsed);
        kind = "candidate";
    } else if let Some(stored) = pkg.as_ref().and_then(|pkg| pkg.auto_assign.as_ref()) {
        rule = Some(rule_value(stored));
        kind = "stored";
    }
    let Some(rule) = rule else {
        return Ok(AutoAssignPreview {
            rule: kind.to_owned(),
            keys,
            warnings: Vec::new(),
            matching: 0.0,
            excluded: 0.0,
            frozen: 0.0,
            sample: Vec::new(),
            plan: None,
            changes: None,
            brake: None,
            status: None,
            extra: Map::new(),
        });
    };
    allow(
        ctx,
        tx,
        principal,
        tenant_id,
        "iam:identities:read",
        tenant_id,
        "list identities",
    )
    .await?;
    let facts = load_facts(ctx, tx, tenant_id, None).await?;
    let doc = rule_document(&rule)?;
    let mut matches: Vec<(String, String, Value)> = Vec::new();
    let mut excluded = 0.0;
    let mut frozen = 0.0;
    let package_id = pkg.as_ref().map(|pkg| pkg.id.clone()).unwrap_or_default();
    for identity in &facts.identities {
        if identity.status != IdentityStatus::Active || ctx.identity_expired(identity) {
            frozen += 1.0;
            continue;
        }
        let f = facts.identity_facts(ctx, identity, &package_id);
        let group_ids = Value::Array(
            f.direct_group_ids
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        );
        let matched = rule_match(
            &doc,
            identity,
            &rule_context(identity, &group_ids, Some(&f.org))?,
        )?;
        if matched.matched {
            let mut entry = Map::new();
            entry.insert("identityId".into(), Value::String(identity.id.clone()));
            entry.insert("name".into(), Value::String(identity.name.clone()));
            if let Some(email) = identity.email.as_ref().filter(|email| !email.is_empty()) {
                entry.insert("email".into(), Value::String(email.clone()));
            }
            entry.insert(
                "kind".into(),
                serde_json::to_value(identity.kind).unwrap_or(Value::Null),
            );
            entry.insert("matchedBy".into(), json!(matched.matched_by));
            matches.push((
                identity.name.clone(),
                identity.id.clone(),
                Value::Object(entry),
            ));
        } else if !matched.matched_by.is_empty() && !matched.excluded_by.is_empty() {
            excluded += 1.0;
        }
    }
    matches.sort_by(|a, b| {
        locale_compare(&a.0, &b.0).then_with(|| {
            if cmp_utf16(&a.1, &b.1) == Ordering::Less {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        })
    });
    let bound = bound_groups(tx, tenant_id, &rule).await?;
    let mut preview = AutoAssignPreview {
        rule: kind.to_owned(),
        keys,
        warnings: rule_warnings(&rule, Some(&bound))?,
        matching: matches.len() as f64,
        excluded,
        frozen,
        sample: matches
            .iter()
            .take(sample)
            .map(|(_, _, entry)| entry.clone())
            .collect(),
        plan: None,
        changes: None,
        brake: None,
        status: None,
        extra: Map::new(),
    };
    let Some(pkg) = pkg else {
        return Ok(preview);
    };
    // What a run would change: the package with the candidate (or stored) rule, planned against the directory.
    let candidate: AccessPackage = match &candidate_input {
        Some(parsed) => {
            let conditions = |clauses: &[Value]| -> IamResult<Vec<better_iam_core::Conditions>> {
                clauses
                    .iter()
                    .map(|clause| {
                        serde_json::from_value(clause.clone()).map_err(|_| {
                            IamError::new("INVALID_POLICY", "Invalid condition operator")
                        })
                    })
                    .collect()
            };
            let mut candidate = pkg.clone();
            candidate.auto_assign = Some(AutoAssignRule {
                include: conditions(&parsed.include)?,
                exclude: match &parsed.exclude {
                    Some(exclude) => Some(conditions(exclude)?),
                    None => None,
                },
                grace_ms: parsed.grace_ms,
                max_grants: parsed.max_grants,
                max_removals: parsed.max_removals,
                owner_id: pkg
                    .auto_assign
                    .as_ref()
                    .map(|rule| rule.owner_id.clone())
                    .unwrap_or_else(|| principal.identity.id.clone()),
                authority_id: pkg
                    .auto_assign
                    .as_ref()
                    .map(|rule| rule.authority_id.clone())
                    .unwrap_or_default(),
                revision: pkg
                    .auto_assign
                    .as_ref()
                    .map(|rule| rule.revision)
                    .unwrap_or(0.0)
                    + 1.0,
                updated_at: ctx.now(),
                approved: None,
                extra: Map::new(),
            });
            candidate
        }
        None => pkg.clone(),
    };
    let plan = plan_package(ctx, &facts, &candidate)?;
    let names: IndexMap<&String, &Identity> = facts
        .identities
        .iter()
        .map(|identity| (&identity.id, identity))
        .collect();
    preview.plan = Some(json!({
        "assign": number(plan.counts.assign),
        "refresh": number(plan.counts.refresh),
        "restore": number(plan.counts.restore),
        "ending": number(plan.counts.ending),
        "revoke": number(plan.counts.revoke),
        "manual": number(plan.counts.manual),
        "keep": number(plan.counts.keep),
    }));
    preview.changes = Some(
        plan.steps
            .iter()
            .take(sample)
            .map(|step| {
                let mut change = Map::new();
                change.insert("identityId".into(), Value::String(step.identity_id.clone()));
                let identity = names.get(&step.identity_id);
                change.insert(
                    "name".into(),
                    identity
                        .map(|identity| Value::String(identity.name.clone()))
                        .unwrap_or(Value::Null),
                );
                if let Some(email) = identity
                    .and_then(|identity| identity.email.as_ref())
                    .filter(|email| !email.is_empty())
                {
                    change.insert("email".into(), Value::String(email.clone()));
                }
                change.insert("change".into(), Value::String(step.change.to_owned()));
                Value::Object(change)
            })
            .collect(),
    );
    let stored = candidate
        .auto_assign
        .as_ref()
        .ok_or_else(crate::js::internal_error)?;
    let approved = stored
        .approved
        .as_ref()
        .filter(|approved| approved.until > ctx.now());
    let grants = plan.counts.assign + plan.counts.refresh;
    let removals = plan.counts.ending + plan.counts.revoke - plan.counts.revoke_rule_cleared;
    let grant_threshold = stored
        .max_grants
        .unwrap_or(DEFAULT_MAX_GRANTS)
        .max(approved.map(|approved| approved.grants).unwrap_or(0.0));
    let removal_threshold = stored
        .max_removals
        .unwrap_or(DEFAULT_MAX_REMOVALS)
        .max(approved.map(|approved| approved.removals).unwrap_or(0.0));
    preview.brake = Some(json!({
        "grants": {
            "planned": number(grants),
            "threshold": number(grant_threshold),
            "trips": grants > grant_threshold,
        },
        "removals": {
            "planned": number(removals),
            "threshold": number(removal_threshold),
            "trips": removals > removal_threshold,
        },
    }));
    if pkg.auto_assign.is_some() {
        let env = rule_environment(ctx, tx, &Value::Object(encode(&pkg))).await?;
        let view = auto_assign_view(ctx, tx, &pkg, &env).await?;
        let mut status = Map::new();
        status.insert("status".into(), Value::String(view.status.clone()));
        if let Some(reason) = view.suspended_reason.as_ref().filter(|r| !r.is_empty()) {
            status.insert("reason".into(), Value::String(reason.clone()));
            status.insert(
                "detail".into(),
                Value::String(view.suspended_detail.clone().unwrap_or_default()),
            );
        }
        preview.status = Some(Value::Object(status));
    }
    Ok(preview)
}
