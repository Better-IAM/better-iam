//! Port of `packages/server/src/api/certifications.ts`: access certification campaigns. An administrator snapshots
//! the tenant's role bindings (optionally for some roles or subject types); designated reviewers — or, in manager
//! mode, each person's manager — keep or revoke each one, never their own access, and closing the campaign removes the
//! revoked bindings under the closer's grant authority. Bindings the closer may not remove are reported as
//! `revocation-failed` for a higher administrator instead of being forced.

use std::sync::Arc;

use better_iam_auth::outbox::EnqueueInput;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Identity, OutboxKind, Record, SessionKind, js as core_js,
};
use better_iam_types::api::certifications;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::js::{defined, truthy};
use crate::metrics::locale_compare;
use crate::models::Binding;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::decode;
use crate::session_kinds::acts_in_own_right;
use crate::utils::{by_newest_records, id};
use crate::validation::{strings, text};

use super::bindings::delete_binding;

/// A periodic review of who holds which role: reviewers keep or revoke each binding, and closing applies it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificationCampaign {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "dueAt", default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<f64>,
    /// Only bindings of these roles are reviewed; unset reviews every non-protected role.
    #[serde(rename = "roleIds", default, skip_serializing_if = "Option::is_none")]
    pub role_ids: Option<Vec<String>>,
    #[serde(
        rename = "subjectType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub subject_type: Option<String>,
    /// Identities allowed to decide; empty lets anyone holding `iam:certifications:review` decide.
    #[serde(rename = "reviewerIds")]
    pub reviewer_ids: Vec<String>,
    /// `manager` assigns each person's items to their manager (`CertificationItem.reviewerId`); items without one fall
    /// back to `reviewerIds`. Absent on campaigns created before reviewer modes, which are `named`.
    #[serde(
        rename = "reviewerMode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reviewer_mode: Option<String>,
    /// The deployment worker (`closeOverdueCertifications`) closes the campaign once `dueAt` has passed.
    #[serde(rename = "autoClose", default, skip_serializing_if = "Option::is_none")]
    pub auto_close: Option<bool>,
    /// What closing does with items nobody decided.
    #[serde(rename = "undecided")]
    pub undecided: String,
    #[serde(rename = "closedAt", default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<f64>,
    /// Who closed the campaign; `deployment-operator` when the worker closed it.
    #[serde(rename = "closedBy", default, skip_serializing_if = "Option::is_none")]
    pub closed_by: Option<String>,
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

/// One binding as it stood when the campaign opened, with the reviewer's decision and the closing outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificationItem {
    #[serde(rename = "campaignId")]
    pub campaign_id: String,
    #[serde(rename = "bindingId")]
    pub binding_id: String,
    #[serde(rename = "roleId")]
    pub role_id: String,
    #[serde(rename = "roleName")]
    pub role_name: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "subjectName")]
    pub subject_name: String,
    #[serde(
        rename = "bindingExpiresAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub binding_expires_at: Option<f64>,
    #[serde(rename = "eligible", default, skip_serializing_if = "Option::is_none")]
    pub eligible: Option<bool>,
    /// Manager-mode campaigns: the person's manager, who reviews this item (administrators may still decide it).
    #[serde(
        rename = "reviewerId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reviewer_id: Option<String>,
    #[serde(rename = "decision", default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(rename = "decidedBy", default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(rename = "decidedAt", default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<f64>,
    #[serde(rename = "note", default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "outcome", default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(
        rename = "outcomeDetail",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub outcome_detail: Option<String>,
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

/// `CertificationOutcome`: `'kept' | 'revoked' | 'already-removed' | 'revocation-failed'`.
pub type CertificationOutcome = String;

/// `ApplyCampaignOptions`: how [`apply_campaign`] attributes the close.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyCampaignOptions {
    /// A deployment actor (such as `deployment-operator`) recorded as `closedBy` and as the actor of each
    /// revocation's `iam:bindings:delete` event (with the campaign ID) instead of the principal.
    pub operator: Option<String>,
}

const MAX_ITEMS: usize = 5000;
const DECISIONS: [&str; 2] = ["keep", "revoke"];

fn is_decision(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|decision| DECISIONS.contains(&decision))
}

fn str_of<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// `progress(items)`.
fn progress(items: &[Record]) -> Value {
    let decision = |item: &Record| item.get("decision").cloned();
    json!({
        "total": items.len(),
        "decided": items.iter().filter(|item| truthy(item.get("decision"))).count(),
        "keep": items.iter().filter(|item| decision(item) == Some(json!("keep"))).count(),
        "revoke": items.iter().filter(|item| decision(item) == Some(json!("revoke"))).count(),
    })
}

/// `byRoleAndSubject`.
fn by_role_and_subject(a: &Record, b: &Record) -> std::cmp::Ordering {
    let member = |record: &Record, key: &str| str_of(record, key).unwrap_or("").to_owned();
    locale_compare(&member(a, "roleName"), &member(b, "roleName"))
        .then_with(|| locale_compare(&member(a, "subjectName"), &member(b, "subjectName")))
        .then_with(|| locale_compare(&member(a, "id"), &member(b, "id")))
}

/// The groups an identity belongs to, for the rule that nobody certifies their own access.
async fn groups_of(tx: &Store, tenant_id: &str, identity_id: &str) -> IamResult<IndexSet<String>> {
    Ok(tx
        .find(
            "groupMembers",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", identity_id),
            &FindOptions::default(),
        )
        .await?
        .iter()
        .map(|member| str_of(member, "groupId").unwrap_or("").to_owned())
        .collect())
}

/// Whether an item certifies the identity's own access, directly or through one of its groups.
fn own_item(item: &Record, identity_id: &str, groups: &IndexSet<String>) -> bool {
    let subject_id = str_of(item, "subjectId").unwrap_or("");
    if str_of(item, "subjectType") == Some("identity") {
        subject_id == identity_id
    } else {
        groups.contains(subject_id)
    }
}

fn self_review() -> IamError {
    IamError::with_status(
        "SELF_REVIEW",
        "Reviewers cannot certify their own access; ask another reviewer",
        403,
    )
}

/// The item with a reviewer's decision (and optional note) recorded.
fn decided(
    item: &Record,
    entry: &Map<String, Value>,
    reviewer_id: &str,
    now: f64,
) -> IamResult<Record> {
    let mut updated = item.clone();
    updated.insert(
        "decision".into(),
        entry.get("decision").cloned().unwrap_or(Value::Null),
    );
    updated.insert("decidedBy".into(), Value::String(reviewer_id.to_owned()));
    updated.insert("decidedAt".into(), crate::js::number(now));
    match entry.get("note") {
        Some(note) => {
            let note = core_js::trim(&text(Some(note), "note", 500)?).to_owned();
            updated.insert("note".into(), Value::String(note));
        }
        None => {
            updated.shift_remove("note");
        }
    }
    Ok(updated)
}

/// Items per reviewer: manager-assigned items count for their manager, the others for every named reviewer. Named
/// reviewers of a manager-mode campaign are left out when nothing falls back to them.
fn review_load(campaign: &CertificationCampaign, items: &[Record]) -> IndexMap<String, f64> {
    let mut load: IndexMap<String, f64> = IndexMap::new();
    let mut unassigned = 0.0;
    for item in items {
        match item.get("reviewerId") {
            Some(reviewer) if truthy(Some(reviewer)) => {
                let reviewer_id = crate::js::js_string(Some(reviewer));
                *load.entry(reviewer_id).or_insert(0.0) += 1.0;
            }
            _ => unassigned += 1.0,
        }
    }
    if unassigned > 0.0 || campaign.reviewer_mode.as_deref() != Some("manager") {
        for reviewer_id in &campaign.reviewer_ids {
            *load.entry(reviewer_id.clone()).or_insert(0.0) += unassigned;
        }
    }
    load
}

/// Rejects credentials that are not an ordinary session of the tenant (self-service reviews act as oneself), including
/// role sessions, session tokens and unknown kinds.
fn require_tenant_session(principal: &AuthenticatedPrincipal, tenant_id: &str) -> IamResult<()> {
    if !acts_in_own_right(principal.session.kind) || principal.session.tenant_id != tenant_id {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Reviews are made from an ordinary session of the campaign tenant",
            403,
        ));
    }
    Ok(())
}

/// `principal.session.impersonatorId` is set (truthy).
fn impersonating(principal: &AuthenticatedPrincipal) -> bool {
    principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
}

fn review_while_impersonating() -> IamError {
    IamError::with_status(
        "IMPERSONATION_RESTRICTED",
        "Access cannot be reviewed while impersonating",
        403,
    )
}

fn campaign_closed() -> IamError {
    IamError::with_status("CONFLICT", "The campaign is closed", 409)
}

fn not_a_reviewer() -> IamError {
    IamError::with_status(
        "ACCESS_DENIED",
        "You are not a reviewer of this campaign",
        403,
    )
}

/// `ctx.options.authentication?.sendEmail` is configured.
fn sends_email(ctx: &ServerContext) -> bool {
    ctx.options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some())
}

/// `new Date(ms).toISOString()`; a date outside the JavaScript range throws (a RangeError, not an IamError).
fn iso(ms: f64) -> IamResult<String> {
    core_js::iso_string(ms).ok_or_else(crate::js::internal_error)
}

/// `campaignOf(tx, tenantId, campaignId)`: the campaign record and its typed view.
async fn campaign_of(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    campaign_id: Option<&Value>,
) -> IamResult<(Record, CertificationCampaign)> {
    let campaign_id = text(campaign_id, "campaignId", 256)?;
    let record = ctx
        .scoped(
            tx,
            "certificationCampaigns",
            Some(&Value::String(campaign_id)),
            tenant_id,
        )
        .await?;
    let campaign: CertificationCampaign = decode(record.clone())?;
    Ok((record, campaign))
}

/// `itemsOf(tx, tenantId, campaignId)`.
async fn items_of(tx: &Store, tenant_id: &str, campaign_id: &str) -> IamResult<Vec<Record>> {
    tx.find(
        "certificationItems",
        &Filter::new()
            .eq("tenantId", tenant_id)
            .eq("campaignId", campaign_id),
        &FindOptions::default(),
    )
    .await
}

/// `{ ...record, ...extra }`.
fn spread(record: &Record, extra: Vec<(&str, Value)>) -> Value {
    let mut out = record.clone();
    for (key, value) in extra {
        out.insert(key.to_owned(), value);
    }
    Value::Object(out)
}

fn records(list: Vec<Record>) -> Value {
    Value::Array(list.into_iter().map(Value::Object).collect())
}

/// The decision entries of `decide` and `review`: 1 to 200 of them.
fn decision_entries(value: Option<&Value>) -> IamResult<&Vec<Value>> {
    match value {
        Some(Value::Array(entries)) if !entries.is_empty() && entries.len() <= 200 => Ok(entries),
        _ => Err(IamError::new(
            "INVALID_INPUT",
            "decisions must contain 1 to 200 entries",
        )),
    }
}

/// `{ outcomes }` in the TypeScript member order.
fn outcome_counts(outcomes: &IndexMap<&'static str, f64>) -> Map<String, Value> {
    outcomes
        .iter()
        .map(|(key, count)| ((*key).to_owned(), crate::js::number(*count)))
        .collect()
}

/// [`apply_campaign`] over the raw campaign record.
pub(crate) async fn apply_campaign_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    record: &Record,
    principal: Option<&AuthenticatedPrincipal>,
    operator: Option<&str>,
) -> IamResult<Value> {
    let campaign: CertificationCampaign = decode(record.clone())?;
    let closed_by = match operator {
        Some(operator) => operator.to_owned(),
        None => match principal {
            Some(principal) => principal.identity.id.clone(),
            None => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "Closing a campaign needs a principal or an operator",
                ));
            }
        },
    };
    let tenant_id = campaign.tenant_id.clone();
    let mut outcomes: IndexMap<&'static str, f64> = IndexMap::new();
    for key in ["kept", "revoked", "already-removed", "revocation-failed"] {
        outcomes.insert(key, 0.0);
    }
    for item in items_of(tx, &tenant_id, &campaign.id).await? {
        let decision = match defined(item.get("decision")) {
            Some(decision) => decision.clone(),
            None => Value::String(campaign.undecided.clone()),
        };
        let revoke = decision.as_str() == Some("revoke");
        let binding_record = tx
            .get("bindings", str_of(&item, "bindingId").unwrap_or(""))
            .await?;
        let outcome: &'static str;
        let mut detail: Option<String> = None;
        let current = binding_record.filter(|binding| {
            str_of(binding, "tenantId") == Some(tenant_id.as_str())
                && binding.get("roleId") == item.get("roleId")
                && binding.get("subjectId") == item.get("subjectId")
        });
        match current {
            None => outcome = if revoke { "already-removed" } else { "kept" },
            Some(_) if decision.as_str() == Some("keep") => outcome = "kept",
            Some(_) if principal.is_none() => {
                outcome = "revocation-failed";
                detail = Some(
                    "The campaign creator no longer exists, so nothing is revoked under their authority"
                        .into(),
                );
            }
            Some(binding_record) => {
                let principal = principal.expect("a principal is present");
                let binding: Binding = decode(binding_record)?;
                // deleteBinding validates before it writes, so a refusal leaves nothing half-done.
                let attempt: IamResult<()> = async {
                    delete_binding(ctx, tx, principal, &binding).await?;
                    match operator {
                        Some(operator) => {
                            let mut event = Record::new();
                            event.insert("id".into(), Value::String(id()));
                            event.insert("tenantId".into(), Value::String(tenant_id.clone()));
                            event.insert("actorId".into(), Value::String(operator.to_owned()));
                            event.insert(
                                "action".into(),
                                Value::String("iam:bindings:delete".into()),
                            );
                            event.insert("resourceId".into(), Value::String(binding.id.clone()));
                            event.insert("timestamp".into(), crate::js::number(ctx.now()));
                            event.insert("outcome".into(), Value::String("allow".into()));
                            event.insert("metadata".into(), json!({ "campaignId": campaign.id }));
                            ctx.events()?.record_audit(tx, &event).await
                        }
                        None => {
                            ctx.events()?
                                .audit(
                                    tx,
                                    principal,
                                    "iam:bindings:delete",
                                    &tenant_id,
                                    &binding.id,
                                    AuditOutcome::Allow,
                                    false,
                                    None,
                                )
                                .await
                        }
                    }
                }
                .await;
                match attempt {
                    Ok(()) => outcome = "revoked",
                    // A module the Rust server has not ported yet is not a refusal of the revocation: surface it
                    // instead of recording it as the item's outcome (TypeScript never raises NOT_IMPLEMENTED here).
                    Err(error) if error.code == "NOT_IMPLEMENTED" => return Err(error),
                    Err(error) => {
                        outcome = "revocation-failed";
                        detail = Some(error.message.clone());
                    }
                }
            }
        }
        *outcomes.entry(outcome).or_insert(0.0) += 1.0;
        let mut updated = item.clone();
        updated.insert("outcome".into(), Value::String(outcome.to_owned()));
        if let Some(detail) = detail.filter(|detail| !detail.is_empty()) {
            updated.insert("outcomeDetail".into(), Value::String(detail));
        }
        tx.put("certificationItems", &updated).await?;
    }
    let mut closed = record.clone();
    closed.insert("status".into(), Value::String("closed".into()));
    closed.insert("closedAt".into(), crate::js::number(ctx.now()));
    closed.insert("closedBy".into(), Value::String(closed_by));
    let mut closed = tx.put("certificationCampaigns", &closed).await?;
    closed.insert("outcomes".into(), Value::Object(outcome_counts(&outcomes)));
    Ok(Value::Object(closed))
}

/// The `certifications` API group (`createCertificationsApi(ctx)`): one method per route `certifications/{method}`.
pub struct CertificationsApi {
    ctx: Arc<ServerContext>,
}

/// `createCertificationsApi(ctx)`.
pub fn create_certifications_api(ctx: &Arc<ServerContext>) -> IamResult<CertificationsApi> {
    Ok(CertificationsApi { ctx: ctx.clone() })
}

impl CertificationsApi {
    /// `certifications/close`: closes the campaign and applies it: revoked (and, with `undecided: 'revoke'`,
    /// undecided) bindings are removed under the caller's grant authority; each item records its outcome. Requires
    /// iam:certifications:manage and recent authentication.
    pub async fn close(
        &self,
        credential: &CredentialInput,
        input: Body<certifications::CloseInput>,
    ) -> IamResult<Reply<certifications::CloseOutput>> {
        let ctx = &self.ctx;
        let resource = format!(
            "certifications/{}",
            text(input.get("campaignId"), "campaignId", 256)?
        );
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let (record, campaign) =
                        campaign_of(ctx, &tx, &tenant.id, body.get("campaignId")).await?;
                    if campaign.status != "open" {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "The campaign is already closed",
                            409,
                        )
                        .into());
                    }
                    Ok(apply_campaign_record(ctx, &tx, &record, Some(&principal), None).await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:certifications:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `certifications/create`: opens a campaign over the current bindings. `reviewerMode: 'manager'` assigns each
    /// person's items to their active manager, the rest to the named reviewers; `autoClose` (which needs `dueAt`) lets
    /// the deployment worker close it when due. When email delivery is configured, each reviewer is emailed
    /// (`certification-review`) with their item count. Requires iam:certifications:manage.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<certifications::CreateInput>,
    ) -> IamResult<Reply<certifications::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let tenant_id = tenant.id.clone();
                    let name = core_js::trim(&text(body.get("name"), "name", 200)?).to_owned();
                    let subject_type = body.get("subjectType");
                    if let Some(subject_type) = subject_type
                        && !matches!(subject_type.as_str(), Some("identity" | "group"))
                    {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "subjectType must be identity or group",
                        )
                        .into());
                    }
                    let reviewer_mode = defined(body.get("reviewerMode"))
                        .cloned()
                        .unwrap_or_else(|| Value::String("named".into()));
                    if !matches!(reviewer_mode.as_str(), Some("named" | "manager")) {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "reviewerMode must be named or manager",
                        )
                        .into());
                    }
                    let undecided = defined(body.get("undecided"))
                        .cloned()
                        .unwrap_or_else(|| Value::String("keep".into()));
                    if !is_decision(Some(&undecided)) {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "undecided must be keep or revoke",
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let due_at = match body.get("dueAt") {
                        None => None,
                        Some(value) => match core_js::as_number(value) {
                            Some(due) if core_js::is_safe_integer(due) && due > now => Some(due),
                            _ => {
                                return Err(IamError::new(
                                    "INVALID_INPUT",
                                    "dueAt must be a future timestamp in milliseconds",
                                )
                                .into());
                            }
                        },
                    };
                    let auto_close = match body.get("autoClose") {
                        None => false,
                        Some(Value::Bool(flag)) => *flag,
                        Some(_) => {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "autoClose must be boolean",
                            )
                            .into());
                        }
                    };
                    if auto_close && due_at.is_none() {
                        return Err(
                            IamError::new("INVALID_INPUT", "autoClose requires dueAt").into()
                        );
                    }
                    let role_ids = match body.get("roleIds") {
                        None => None,
                        Some(value) => Some(crate::js::unique(strings(Some(value), "roleIds")?)),
                    };
                    let mut roles: IndexMap<String, Record> = IndexMap::new();
                    for role in tx
                        .find(
                            "roles",
                            &Filter::new().eq("tenantId", tenant_id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        roles.insert(str_of(&role, "id").unwrap_or("").to_owned(), role);
                    }
                    let protected = |role: &Record| truthy(role.get("protected"));
                    for role_id in role_ids.iter().flatten() {
                        if roles.get(role_id).is_none_or(protected) {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                format!("Role {role_id} cannot be certified"),
                            )
                            .into());
                        }
                    }
                    let reviewer_ids = crate::js::unique(strings(
                        Some(defined(body.get("reviewerIds")).unwrap_or(&json!([]))),
                        "reviewerIds",
                    )?);
                    for reviewer_id in &reviewer_ids {
                        ctx.active_identity(&tx, reviewer_id, &tenant_id).await?;
                    }

                    let mut bindings: Vec<(Record, Binding)> = Vec::new();
                    for record in tx
                        .find(
                            "bindings",
                            &Filter::new().eq("tenantId", tenant_id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        let binding: Binding = decode(record.clone())?;
                        if ctx.live_binding(&binding)
                            && roles
                                .get(&binding.role_id)
                                .is_some_and(|role| !protected(role))
                            && role_ids
                                .as_ref()
                                .is_none_or(|role_ids| role_ids.contains(&binding.role_id))
                            && subject_type.is_none_or(|subject_type| {
                                subject_type.as_str() == Some(binding.subject_type.as_str())
                            })
                        {
                            bindings.push((record, binding));
                        }
                    }
                    if bindings.len() > MAX_ITEMS {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!(
                                "A campaign covers at most {MAX_ITEMS} bindings; narrow it by role or subject type"
                            ),
                            409,
                        )
                        .into());
                    }
                    let mut campaign = Map::new();
                    campaign.insert("id".into(), Value::String(id()));
                    campaign.insert("tenantId".into(), Value::String(tenant_id.clone()));
                    campaign.insert("name".into(), Value::String(name.clone()));
                    campaign.insert("status".into(), Value::String("open".into()));
                    campaign.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    campaign.insert("createdAt".into(), crate::js::number(now));
                    campaign.insert(
                        "reviewerIds".into(),
                        Value::Array(reviewer_ids.iter().cloned().map(Value::String).collect()),
                    );
                    campaign.insert("reviewerMode".into(), reviewer_mode.clone());
                    campaign.insert("undecided".into(), undecided);
                    if let Some(due_at) = due_at {
                        campaign.insert("dueAt".into(), crate::js::number(due_at));
                    }
                    if auto_close {
                        campaign.insert("autoClose".into(), Value::Bool(true));
                    }
                    if let Some(role_ids) = &role_ids {
                        campaign.insert(
                            "roleIds".into(),
                            Value::Array(role_ids.iter().cloned().map(Value::String).collect()),
                        );
                    }
                    if let Some(subject_type) = subject_type.filter(|value| truthy(Some(value))) {
                        campaign.insert("subjectType".into(), subject_type.clone());
                    }
                    tx.insert("certificationCampaigns", &campaign).await?;
                    let campaign_id = str_of(&campaign, "id").unwrap_or("").to_owned();
                    let manager_mode = reviewer_mode.as_str() == Some("manager");
                    // Manager mode: a person's reviewer is their manager while that manager is an active member of
                    // the tenant.
                    let mut managers: IndexMap<String, bool> = IndexMap::new();
                    let mut items: Vec<Record> = Vec::new();
                    for (record, binding) in &bindings {
                        let subject = if binding.subject_type == "identity" {
                            tx.get("identities", &binding.subject_id).await?
                        } else {
                            tx.get("groups", &binding.subject_id).await?
                        };
                        let subject_name = subject
                            .as_ref()
                            .and_then(|subject| {
                                defined(subject.get("email"))
                                    .or_else(|| defined(subject.get("name")))
                            })
                            .cloned()
                            .unwrap_or_else(|| Value::String(binding.subject_id.clone()));
                        let mut item = Map::new();
                        item.insert("id".into(), Value::String(id()));
                        item.insert("tenantId".into(), Value::String(tenant_id.clone()));
                        item.insert("campaignId".into(), Value::String(campaign_id.clone()));
                        item.insert("bindingId".into(), Value::String(binding.id.clone()));
                        item.insert("roleId".into(), Value::String(binding.role_id.clone()));
                        item.insert(
                            "roleName".into(),
                            roles
                                .get(&binding.role_id)
                                .and_then(|role| role.get("name"))
                                .cloned()
                                .unwrap_or(Value::Null),
                        );
                        item.insert(
                            "subjectType".into(),
                            Value::String(binding.subject_type.clone()),
                        );
                        item.insert(
                            "subjectId".into(),
                            Value::String(binding.subject_id.clone()),
                        );
                        item.insert("subjectName".into(), subject_name);
                        if let Some(expires_at) = record.get("expiresAt") {
                            item.insert("bindingExpiresAt".into(), expires_at.clone());
                        }
                        if truthy(record.get("eligible")) {
                            item.insert("eligible".into(), Value::Bool(true));
                        }
                        // `reviewerFor(subject)`, for people only.
                        let mut reviewer_id: Option<String> = None;
                        if binding.subject_type == "identity"
                            && manager_mode
                            && let Some(subject) = &subject
                            && let Some(manager_id) = subject
                                .get("managerId")
                                .filter(|manager| truthy(Some(manager)))
                                .map(|manager| crate::js::js_string(Some(manager)))
                            && subject.get("id").and_then(Value::as_str)
                                != Some(manager_id.as_str())
                        {
                            if !managers.contains_key(&manager_id) {
                                let active = match tx.get("identities", &manager_id).await? {
                                    Some(manager)
                                        if str_of(&manager, "tenantId")
                                            == Some(tenant_id.as_str())
                                            && str_of(&manager, "status") == Some("active") =>
                                    {
                                        let manager: Identity = decode(manager)?;
                                        !ctx.identity_expired(&manager)
                                    }
                                    _ => false,
                                };
                                managers.insert(manager_id.clone(), active);
                            }
                            if managers.get(&manager_id).copied().unwrap_or(false) {
                                reviewer_id = Some(manager_id);
                            }
                        }
                        if let Some(reviewer_id) = reviewer_id {
                            item.insert("reviewerId".into(), Value::String(reviewer_id));
                        }
                        tx.insert("certificationItems", &item).await?;
                        items.push(item);
                    }
                    // Reviewers hear about the campaign through the outbox, in the same transaction.
                    if sends_email(ctx) {
                        let typed: CertificationCampaign = decode(campaign.clone())?;
                        for (reviewer_id, count) in review_load(&typed, &items) {
                            let Some(reviewer) = tx.get("identities", &reviewer_id).await? else {
                                continue;
                            };
                            let email = match reviewer.get("email") {
                                Some(email) if truthy(Some(email)) => {
                                    crate::js::js_string(Some(email))
                                }
                                _ => continue,
                            };
                            let mut payload = Map::new();
                            payload.insert("campaignId".into(), Value::String(campaign_id.clone()));
                            payload.insert("campaignName".into(), Value::String(name.clone()));
                            payload.insert(
                                "items".into(),
                                Value::String(core_js::number_to_string(count)),
                            );
                            if let Some(due_at) = due_at.filter(|due| *due != 0.0) {
                                payload.insert("dueAt".into(), Value::String(iso(due_at)?));
                            }
                            ctx.auth
                                .enqueue_delivery(
                                    &tx,
                                    EnqueueInput {
                                        tenant_id: tenant_id.clone(),
                                        kind: OutboxKind::Email,
                                        to: email,
                                        template: "certification-review".into(),
                                        payload,
                                        reference: None,
                                    },
                                )
                                .await?;
                        }
                    }
                    Ok(spread(
                        &campaign,
                        vec![
                            ("progress", progress(&[])),
                            ("items", json!(bindings.len())),
                        ],
                    ))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:certifications:manage",
                "certifications/*",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `certifications/decide`: records keep/revoke decisions (at most 200 per call). Reviewers must be listed on the
    /// campaign when it names reviewers, and nobody decides on their own access, directly or through a group. In
    /// manager mode an item assigned to a manager is theirs to decide, though holders of iam:certifications:manage
    /// may decide it too. Requires iam:certifications:review on the campaign. A role session holding it may decide
    /// (the decision records its source identity); a session token and an impersonation session never do.
    pub async fn decide(
        &self,
        credential: &CredentialInput,
        input: Body<certifications::DecideInput>,
    ) -> IamResult<Reply<certifications::DecideOutput>> {
        let ctx = &self.ctx;
        let resource = format!(
            "certifications/{}",
            text(input.get("campaignId"), "campaignId", 256)?
        );
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let tenant_id = tenant.id.clone();
                    // A decision is recorded in the reviewer's name. An administrator impersonating a member never
                    // records one for them, and neither does a session token or any other derived kind but an
                    // assumed role, which is an explicit, audited delegation that has always been able to review
                    // with the permission.
                    if impersonating(&principal) {
                        return Err(review_while_impersonating().into());
                    }
                    if !acts_in_own_right(principal.session.kind)
                        && principal.session.kind != SessionKind::Role
                    {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Reviews are made from an ordinary session of the campaign tenant",
                            403,
                        )
                        .into());
                    }
                    let (_, campaign) =
                        campaign_of(ctx, &tx, &tenant_id, body.get("campaignId")).await?;
                    if campaign.status != "open" {
                        return Err(campaign_closed().into());
                    }
                    let named = campaign.reviewer_ids.is_empty()
                        || campaign.reviewer_ids.contains(&principal.identity.id);
                    if !named && campaign.reviewer_mode.as_deref() != Some("manager") {
                        return Err(not_a_reviewer().into());
                    }
                    let entries = decision_entries(body.get("decisions"))?;
                    let member_of = groups_of(&tx, &tenant_id, &principal.identity.id).await?;
                    let mut manages: Option<bool> = None;
                    let now = ctx.now();
                    let mut recorded = 0usize;
                    let empty = Map::new();
                    for entry in entries {
                        // `entry.itemId` of null throws a TypeError; other primitives read as undefined.
                        if entry.is_null() {
                            return Err(crate::js::internal_error().into());
                        }
                        let entry = entry.as_object().unwrap_or(&empty);
                        let item_id = text(entry.get("itemId"), "itemId", 256)?;
                        let item = ctx
                            .scoped(
                                &tx,
                                "certificationItems",
                                Some(&Value::String(item_id)),
                                &tenant_id,
                            )
                            .await?;
                        if str_of(&item, "campaignId") != Some(campaign.id.as_str()) {
                            return Err(
                                IamError::with_status("NOT_FOUND", "Item not found", 404).into()
                            );
                        }
                        if !is_decision(entry.get("decision")) {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "decision must be keep or revoke",
                            )
                            .into());
                        }
                        if own_item(&item, &principal.identity.id, &member_of) {
                            return Err(self_review().into());
                        }
                        if let Some(reviewer) = item.get("reviewerId") {
                            if reviewer.as_str() != Some(principal.identity.id.as_str()) {
                                let may_manage = match manages {
                                    Some(manages) => manages,
                                    None => {
                                        let allowed = ctx
                                            .decisions()?
                                            .decide(
                                                &tx,
                                                &principal,
                                                &AuthorizationRequest {
                                                    credential: CredentialInput::default(),
                                                    tenant_id: tenant_id.clone(),
                                                    action: "iam:certifications:manage".into(),
                                                    resource: ResourceTarget {
                                                        kind: "iam".into(),
                                                        id: format!(
                                                            "certifications/{}",
                                                            campaign.id
                                                        ),
                                                    },
                                                },
                                                true,
                                            )
                                            .await?
                                            .allowed;
                                        manages = Some(allowed);
                                        allowed
                                    }
                                };
                                if !may_manage {
                                    return Err(IamError::with_status(
                                        "ACCESS_DENIED",
                                        "This item is assigned to the person's manager",
                                        403,
                                    )
                                    .into());
                                }
                            }
                        } else if !named {
                            return Err(not_a_reviewer().into());
                        }
                        tx.put(
                            "certificationItems",
                            &decided(&item, entry, &principal.identity.id, now)?,
                        )
                        .await?;
                        recorded += 1;
                    }
                    Ok(json!({ "recorded": recorded }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:certifications:review",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `certifications/delete`: deletes a closed campaign and its items. Requires iam:certifications:manage.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<certifications::DeleteInput>,
    ) -> IamResult<Reply<certifications::DeleteOutput>> {
        let ctx = &self.ctx;
        let resource = format!(
            "certifications/{}",
            text(input.get("campaignId"), "campaignId", 256)?
        );
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let (_, campaign) =
                    campaign_of(ctx, &tx, &tenant.id, body.get("campaignId")).await?;
                if campaign.status != "closed" {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "Close the campaign before deleting it",
                        409,
                    )
                    .into());
                }
                for item in items_of(&tx, &tenant.id, &campaign.id).await? {
                    tx.delete("certificationItems", str_of(&item, "id").unwrap_or(""))
                        .await?;
                }
                tx.delete("certificationCampaigns", &campaign.id).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:certifications:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `certifications/get`: one campaign and its items; `mine` limits items to those the caller may decide.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<certifications::GetInput>,
    ) -> IamResult<Reply<certifications::GetOutput>> {
        let ctx = &self.ctx;
        let resource = format!(
            "certifications/{}",
            text(input.get("campaignId"), "campaignId", 256)?
        );
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let (record, campaign) =
                        campaign_of(ctx, &tx, &tenant.id, body.get("campaignId")).await?;
                    let items = items_of(&tx, &tenant.id, &campaign.id).await?;
                    let member_of = groups_of(&tx, &tenant.id, &principal.identity.id).await?;
                    let mine = truthy(body.get("mine"));
                    let summary = progress(&items);
                    let mut shown: Vec<Record> = items
                        .into_iter()
                        .filter(|item| !mine || !own_item(item, &principal.identity.id, &member_of))
                        .collect();
                    shown.sort_by(by_role_and_subject);
                    Ok(spread(
                        &record,
                        vec![("progress", summary), ("items", records(shown))],
                    ))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:certifications:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `certifications/list`: campaigns with their progress, newest first. Requires iam:certifications:read.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<certifications::ListInput>,
    ) -> IamResult<Reply<certifications::ListOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                if let Some(status) = body.get("status").filter(|status| truthy(Some(status))) {
                    filter = filter.eq("status", status.clone());
                }
                let mut campaigns = tx
                    .find("certificationCampaigns", &filter, &FindOptions::default())
                    .await?;
                campaigns.sort_by(by_newest_records);
                let mut result: Vec<Value> = Vec::new();
                for campaign in campaigns {
                    let items =
                        items_of(&tx, &tenant.id, str_of(&campaign, "id").unwrap_or("")).await?;
                    result.push(spread(&campaign, vec![("progress", progress(&items))]));
                }
                Ok(Value::Array(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:certifications:read",
                "certifications/*",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `certifications/listMine`: the caller's review work: open campaigns with items assigned to them (manager mode),
    /// newest first, each with only those items and their progress. Needs no permission beyond an ordinary session of
    /// the tenant.
    pub async fn list_mine(
        &self,
        credential: &CredentialInput,
        input: Body<certifications::ListMineInput>,
    ) -> IamResult<Reply<certifications::ListMineOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let store = ctx.store.clone();
        let result = store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                require_tenant_session(&principal, &tenant_id)?;
                let mut campaigns = tx
                    .find(
                        "certificationCampaigns",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("status", "open"),
                        &FindOptions::default(),
                    )
                    .await?;
                campaigns.sort_by(by_newest_records);
                let mut result: Vec<Value> = Vec::new();
                for record in campaigns {
                    let campaign: CertificationCampaign = decode(record)?;
                    let mut mine = tx
                        .find(
                            "certificationItems",
                            &Filter::new()
                                .eq("tenantId", tenant_id.clone())
                                .eq("campaignId", campaign.id.clone())
                                .eq("reviewerId", principal.identity.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?;
                    if mine.is_empty() {
                        continue;
                    }
                    mine.sort_by(by_role_and_subject);
                    let summary = progress(&mine);
                    let mut entry = Map::new();
                    entry.insert("id".into(), Value::String(campaign.id.clone()));
                    entry.insert("name".into(), Value::String(campaign.name.clone()));
                    if let Some(due_at) = campaign.due_at {
                        entry.insert("dueAt".into(), crate::js::number(due_at));
                    }
                    entry.insert(
                        "reviewerMode".into(),
                        Value::String(
                            campaign
                                .reviewer_mode
                                .clone()
                                .unwrap_or_else(|| "named".into()),
                        ),
                    );
                    entry.insert("items".into(), records(mine));
                    entry.insert("progress".into(), summary);
                    result.push(Value::Object(entry));
                }
                Ok(Value::Array(result))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `certifications/remind`: emails a `certification-reminder` to every reviewer with undecided items: managers
    /// their assigned count, and the named reviewers the undecided items that fall back to them (nobody, when the
    /// campaign names no reviewers). Returns how many people were reminded and how many items are undecided. Requires
    /// iam:certifications:manage and an email delivery callback. Audited as `certification:remind`.
    pub async fn remind(
        &self,
        credential: &CredentialInput,
        input: Body<certifications::RemindInput>,
    ) -> IamResult<Reply<certifications::RemindOutput>> {
        let ctx = &self.ctx;
        let resource = format!(
            "certifications/{}",
            text(input.get("campaignId"), "campaignId", 256)?
        );
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    if !sends_email(ctx) {
                        return Err(IamError::new(
                            "DELIVERY_REQUIRED",
                            "Reminders require an email delivery callback",
                        )
                        .into());
                    }
                    let (_, campaign) =
                        campaign_of(ctx, &tx, &tenant.id, body.get("campaignId")).await?;
                    if campaign.status != "open" {
                        return Err(campaign_closed().into());
                    }
                    let undecided: Vec<Record> = items_of(&tx, &tenant.id, &campaign.id)
                        .await?
                        .into_iter()
                        .filter(|item| !truthy(item.get("decision")))
                        .collect();
                    let mut reminded = 0usize;
                    for (reviewer_id, pending) in review_load(&campaign, &undecided) {
                        if pending == 0.0 {
                            continue;
                        }
                        let Some(reviewer) = tx.get("identities", &reviewer_id).await? else {
                            continue;
                        };
                        if str_of(&reviewer, "status") != Some("active") {
                            continue;
                        }
                        let email = match reviewer.get("email") {
                            Some(email) if truthy(Some(email)) => crate::js::js_string(Some(email)),
                            _ => continue,
                        };
                        let mut payload = Map::new();
                        payload.insert("campaignId".into(), Value::String(campaign.id.clone()));
                        payload.insert("campaignName".into(), Value::String(campaign.name.clone()));
                        payload.insert(
                            "pending".into(),
                            Value::String(core_js::number_to_string(pending)),
                        );
                        if let Some(due_at) = campaign.due_at.filter(|due| *due != 0.0) {
                            payload.insert("dueAt".into(), Value::String(iso(due_at)?));
                        }
                        ctx.auth
                            .enqueue_delivery(
                                &tx,
                                EnqueueInput {
                                    tenant_id: tenant.id.clone(),
                                    kind: OutboxKind::Email,
                                    to: email,
                                    template: "certification-reminder".into(),
                                    payload,
                                    reference: None,
                                },
                            )
                            .await?;
                        reminded += 1;
                    }
                    let mut metadata = Map::new();
                    metadata.insert("reminded".into(), json!(reminded));
                    metadata.insert("pending".into(), json!(undecided.len()));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "certification:remind",
                            &tenant.id,
                            &campaign.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(json!({ "reminded": reminded, "pending": undecided.len() }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:certifications:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `certifications/review`: self-service for manager-mode reviewers: records keep/revoke decisions (at most 200
    /// per call) on items assigned to the caller, without needing iam:certifications:review. Requires an ordinary,
    /// non-impersonated session of the tenant; nobody decides on their own access. Audited as `certification:review`.
    pub async fn review(
        &self,
        credential: &CredentialInput,
        input: Body<certifications::ReviewInput>,
    ) -> IamResult<Reply<certifications::ReviewOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let campaign_id = text(input.get("campaignId"), "campaignId", 256)?;
        let mut entries: Vec<(String, Map<String, Value>)> = Vec::new();
        for entry in decision_entries(input.get("decisions"))? {
            let entry = match entry {
                Value::Object(entry) if is_decision(entry.get("decision")) => entry,
                _ => {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "decision must be keep or revoke",
                    ));
                }
            };
            let item_id = text(entry.get("itemId"), "itemId", 256)?;
            let mut normalized = entry.clone();
            normalized.insert("itemId".into(), Value::String(item_id.clone()));
            entries.push((item_id, normalized));
        }
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let store = ctx.store.clone();
        let result = store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                require_tenant_session(&principal, &tenant_id)?;
                if impersonating(&principal) {
                    return Err(review_while_impersonating());
                }
                let (_, campaign) = campaign_of(
                    &ctx,
                    &tx,
                    &tenant_id,
                    Some(&Value::String(campaign_id.clone())),
                )
                .await?;
                if campaign.status != "open" {
                    return Err(campaign_closed());
                }
                let member_of = groups_of(&tx, &tenant_id, &principal.identity.id).await?;
                let now = ctx.now();
                let (mut keep, mut revoke) = (0usize, 0usize);
                for (item_id, entry) in &entries {
                    let item = tx.get("certificationItems", item_id).await?;
                    let item = match item {
                        Some(item)
                            if str_of(&item, "tenantId") == Some(tenant_id.as_str())
                                && str_of(&item, "campaignId") == Some(campaign.id.as_str())
                                && str_of(&item, "reviewerId")
                                    == Some(principal.identity.id.as_str()) =>
                        {
                            item
                        }
                        _ => {
                            return Err(IamError::with_status(
                                "ACCESS_DENIED",
                                "This item is not assigned to you",
                                403,
                            ));
                        }
                    };
                    if own_item(&item, &principal.identity.id, &member_of) {
                        return Err(self_review());
                    }
                    tx.put(
                        "certificationItems",
                        &decided(&item, entry, &principal.identity.id, now)?,
                    )
                    .await?;
                    if entry.get("decision").and_then(Value::as_str) == Some("keep") {
                        keep += 1;
                    } else {
                        revoke += 1;
                    }
                }
                let mut metadata = Map::new();
                metadata.insert("recorded".into(), json!(entries.len()));
                metadata.insert("keep".into(), json!(keep));
                metadata.insert("revoke".into(), json!(revoke));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "certification:review",
                        &tenant_id,
                        &campaign.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({ "recorded": entries.len() }))
            })
            .await?;
        Ok(Reply::json(result))
    }
}

/// Applies an open campaign and closes it inside the caller's transaction: revoked (and, with `undecided:
/// 'revoke'`, undecided) bindings are removed under the principal's grant authority, and each item records its
/// outcome. Bindings the principal may not remove are reported as `revocation-failed`; without a principal (the
/// creator of an auto-closing campaign no longer exists) every revocation is. Returns the closed campaign with
/// `outcomes` (counts per [`CertificationOutcome`]).
pub async fn apply_campaign(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    campaign: &crate::api::certifications::CertificationCampaign,
    principal: Option<&better_iam_core::AuthenticatedPrincipal>,
    options: Option<&ApplyCampaignOptions>,
) -> IamResult<Value> {
    let record = crate::port::encode(campaign);
    let operator = options.and_then(|options| options.operator.as_deref());
    apply_campaign_record(ctx, tx, &record, principal, operator).await
}
