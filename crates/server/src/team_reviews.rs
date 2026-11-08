//! Port of `packages/server/src/team-reviews.ts`.
//!
//! Team membership reviews: an administrator opens a review of a team's manual members, the team's maintainers (or
//! those of a team above it, or administrators) decide `keep` or `remove` for each person, and completing the review
//! removes everyone decided `remove` and, by the review's `onUndecided` rule, those nobody decided on. Members team
//! sync manages are not reviewed (their source group is). A review past its `dueAt` is completed by the scheduler job
//! `closeOverdueTeamReviews`.

use std::sync::{Arc, LazyLock};

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, Filter, FindOptions, IamResult, IamStoreExt, Record,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::js::{member, number, truthy};
use crate::port::{decode, encode};
use crate::teams::{TEAM_MEMBERS, TEAMS, TeamMember, live_member, sync_team_groups_of};
use crate::utils::id;

/// The `teamReviews` collection.
pub const TEAM_REVIEWS: &str = "teamReviews";
/// The `teamReviewItems` collection.
pub const TEAM_REVIEW_ITEMS: &str = "teamReviewItems";

/// Team membership reviews (see the module documentation): the collections they own.
pub static TEAM_REVIEW_COLLECTIONS: LazyLock<Value> =
    LazyLock::new(|| json!({"reviews":"teamReviews","items":"teamReviewItems"}));

/// Shortest and longest time a review stays open.
pub const MIN_REVIEW_MS: f64 = 86400000.0;

pub const MAX_REVIEW_MS: f64 = 7776000000.0;

pub const DEFAULT_REVIEW_MS: f64 = 1209600000.0;

/// A review of one team's membership; at most one is open per team (uniqueKey `open:{teamId}` while open).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamReview {
    #[serde(rename = "teamId")]
    pub team_id: String,
    #[serde(rename = "status")]
    pub status: crate::team_reviews::TeamReviewStatus,
    /// What happens to people nobody decided on when the review completes.
    #[serde(rename = "onUndecided")]
    pub on_undecided: crate::team_reviews::TeamReviewDecision,
    #[serde(rename = "startedAt")]
    pub started_at: f64,
    #[serde(rename = "startedBy")]
    pub started_by: String,
    #[serde(rename = "dueAt")]
    pub due_at: f64,
    #[serde(rename = "note", default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<f64>,
    /// The person who completed or cancelled it, or `deployment-operator` for the scheduler job.
    #[serde(
        rename = "completedBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_by: Option<String>,
    #[serde(rename = "outcome", default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<crate::team_reviews::TeamReviewOutcome>,
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

/// TODO(port): a union or intersection type in TypeScript; JSON until ported.
pub type TeamReviewDecision = Value;

/// One person under review (uniqueKey `{reviewId}:{identityId}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamReviewItem {
    #[serde(rename = "reviewId")]
    pub review_id: String,
    #[serde(rename = "teamId")]
    pub team_id: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "role")]
    pub role: crate::teams::TeamRole,
    #[serde(rename = "decision", default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(rename = "decidedBy", default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(rename = "decidedAt", default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<f64>,
    #[serde(rename = "note", default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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
pub struct TeamReviewOutcome {
    #[serde(rename = "kept")]
    pub kept: f64,
    #[serde(rename = "removed")]
    pub removed: f64,
    /// People nobody decided on (they followed `onUndecided`).
    #[serde(rename = "undecided")]
    pub undecided: f64,
    /// People who had already left the team when the review completed.
    #[serde(rename = "gone")]
    pub gone: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// TODO(port): a union or intersection type in TypeScript; JSON until ported.
pub type TeamReviewStatus = Value;

/// What [`complete_team_review_of`] did: the completed review record, and the people removed from the team (for
/// re-evaluating their birthright packages after commit).
#[derive(Debug, Clone, PartialEq)]
pub struct TeamReviewCompletion {
    pub review: Record,
    pub removed: Vec<String>,
}

impl TeamReviewCompletion {
    /// `{ review, removed }` as TypeScript returns it.
    pub fn to_json(&self) -> Value {
        json!({ "review": Value::Object(self.review.clone()), "removed": self.removed })
    }
}

fn outcome_json(kept: f64, removed: f64, undecided: f64, gone: f64) -> Map<String, Value> {
    let mut outcome = Map::new();
    outcome.insert("kept".into(), number(kept));
    outcome.insert("removed".into(), number(removed));
    outcome.insert("undecided".into(), number(undecided));
    outcome.insert("gone".into(), number(gone));
    outcome
}

/// Completes an open review inside the caller's transaction: removes the people decided (or defaulted to) `remove`
/// who are still manual members, updates the backing groups, and audits every removal and the completion.
/// `principal` is the person completing it; without one the scheduler (`deployment-operator`) is the actor.
/// Answers `{ review, removed }` ([`complete_team_review_of`] answers it typed).
pub async fn complete_team_review(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    review: &crate::team_reviews::TeamReview,
    principal: Option<&better_iam_core::AuthenticatedPrincipal>,
) -> IamResult<Value> {
    Ok(complete_team_review_of(ctx, tx, review, principal)
        .await?
        .to_json())
}

async fn record_review_event(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    review: &TeamReview,
    principal: Option<&AuthenticatedPrincipal>,
    now: f64,
    action: &str,
    metadata: Map<String, Value>,
) -> IamResult<()> {
    let events = ctx.events()?;
    match principal {
        Some(principal) => {
            events
                .audit(
                    tx,
                    principal,
                    action,
                    &review.tenant_id,
                    &review.team_id,
                    AuditOutcome::Allow,
                    false,
                    Some(metadata),
                )
                .await
        }
        None => {
            let mut event = Record::new();
            event.insert("id".into(), Value::String(id()));
            event.insert("tenantId".into(), Value::String(review.tenant_id.clone()));
            event.insert(
                "actorId".into(),
                Value::String("deployment-operator".into()),
            );
            event.insert("action".into(), Value::String(action.to_owned()));
            event.insert("resourceId".into(), Value::String(review.team_id.clone()));
            event.insert("timestamp".into(), number(now));
            event.insert("outcome".into(), Value::String("allow".into()));
            event.insert("metadata".into(), Value::Object(metadata));
            events.record_audit(tx, &event).await
        }
    }
}

/// [`complete_team_review`] with a typed answer.
pub async fn complete_team_review_of(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    review: &TeamReview,
    principal: Option<&AuthenticatedPrincipal>,
) -> IamResult<TeamReviewCompletion> {
    let now = ctx.now();
    let (mut kept, mut removed_count, mut undecided, mut gone) = (0.0, 0.0, 0.0, 0.0);
    let mut removed: Vec<String> = Vec::new();
    let items = tx
        .find(
            TEAM_REVIEW_ITEMS,
            &Filter::new()
                .eq("tenantId", review.tenant_id.as_str())
                .eq("reviewId", review.id.as_str()),
            &FindOptions::default(),
        )
        .await?;
    for record in items {
        let item: TeamReviewItem = decode(record)?;
        if item.decision.is_none() {
            undecided += 1.0;
        }
        let member = match tx
            .find(
                TEAM_MEMBERS,
                &Filter::new().eq("tenantId", review.tenant_id.as_str()).eq(
                    "uniqueKey",
                    format!("{}:{}", review.team_id, item.identity_id),
                ),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            .next()
        {
            Some(record) => Some(decode::<TeamMember>(record)?),
            None => None,
        };
        // Someone who left, or whom team sync now manages, is outside the review.
        let Some(member) = member
            .filter(|member| live_member(member, now) && member.source.as_deref() != Some("sync"))
        else {
            gone += 1.0;
            continue;
        };
        let decision = match &item.decision {
            Some(decision) => Value::String(decision.clone()),
            None => review.on_undecided.clone(),
        };
        if decision == "keep" {
            kept += 1.0;
            continue;
        }
        tx.delete(TEAM_MEMBERS, &member.id).await?;
        removed.push(member.identity_id.clone());
        removed_count += 1.0;
        let mut metadata = Map::new();
        metadata.insert(
            "identityId".into(),
            Value::String(member.identity_id.clone()),
        );
        metadata.insert("role".into(), member.role.clone());
        metadata.insert("source".into(), Value::String("review".into()));
        metadata.insert("reviewId".into(), Value::String(review.id.clone()));
        if item.decision.is_none() {
            metadata.insert("undecided".into(), Value::Bool(true));
        }
        record_review_event(
            ctx,
            tx,
            review,
            principal,
            now,
            "team:member:remove",
            metadata,
        )
        .await?;
    }
    if !removed.is_empty() {
        sync_team_groups_of(
            tx,
            &review.tenant_id,
            std::slice::from_ref(&review.team_id),
            now,
        )
        .await?;
    }
    // The review as the caller loaded it (the stored record keeps its member order and unknown members).
    let mut completed = match tx.get(TEAM_REVIEWS, &review.id).await? {
        Some(record) => record,
        None => encode(review),
    };
    completed.shift_remove("uniqueKey");
    completed.insert("status".into(), Value::String("completed".into()));
    completed.insert("completedAt".into(), number(now));
    completed.insert(
        "completedBy".into(),
        Value::String(
            principal
                .map(|principal| principal.identity.id.clone())
                .unwrap_or_else(|| "deployment-operator".into()),
        ),
    );
    let outcome = outcome_json(kept, removed_count, undecided, gone);
    completed.insert("outcome".into(), Value::Object(outcome.clone()));
    let completed = tx.put(TEAM_REVIEWS, &completed).await?;
    let mut metadata = Map::new();
    metadata.insert("reviewId".into(), Value::String(review.id.clone()));
    for (key, value) in outcome {
        metadata.insert(key, value);
    }
    record_review_event(
        ctx,
        tx,
        review,
        principal,
        now,
        "team:review:complete",
        metadata,
    )
    .await?;
    Ok(TeamReviewCompletion {
        review: completed,
        removed,
    })
}

/// The scheduler job: completes every open team review past its due date (in active organizations), each in its own
/// transaction, then re-evaluates the birthright packages of the people it removed. `input` is
/// `{ tenantId?: string }`; answers `{ completed, removed, failed: [{ reviewId, message }] }`.
pub async fn close_overdue_team_reviews(
    ctx: &Arc<ServerContext>,
    input: Option<&Value>,
) -> IamResult<Value> {
    let now = ctx.now();
    let mut filter = Filter::new().eq("status", "open");
    let tenant = member(input, "tenantId");
    if truthy(tenant) {
        filter = filter.eq("tenantId", tenant.cloned().unwrap_or(Value::Null));
    }
    let due: Vec<Record> = ctx
        .store
        .find(TEAM_REVIEWS, &filter, &FindOptions::default())
        .await?
        .into_iter()
        .filter(|review| {
            review
                .get("dueAt")
                .and_then(better_iam_core::js::as_number)
                .is_some_and(|due_at| due_at <= now)
        })
        .collect();
    let mut completed = 0.0;
    let mut removed = 0.0;
    let mut failed: Vec<Value> = Vec::new();
    for candidate in due {
        let candidate_id = better_iam_core::record_id(&candidate).to_owned();
        let candidate_tenant = candidate
            .get("tenantId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let outcome: IamResult<()> = async {
            let id = candidate_id.clone();
            let done = ctx
                .store
                .transaction(|tx| async move {
                    let Some(record) = tx.get(TEAM_REVIEWS, &id).await? else {
                        return Ok(None);
                    };
                    let review: TeamReview = decode(record)?;
                    if review.status != "open" || review.due_at > ctx.now() {
                        return Ok(None);
                    }
                    let active =
                        tx.get("tenants", &review.tenant_id)
                            .await?
                            .is_some_and(|tenant| {
                                tenant.get("status").and_then(Value::as_str) == Some("active")
                            });
                    if !active {
                        return Ok(None);
                    }
                    if tx.get(TEAMS, &review.team_id).await?.is_none() {
                        return Ok(None);
                    }
                    complete_team_review_of(ctx, &tx, &review, None)
                        .await
                        .map(Some)
                })
                .await?;
            let Some(done) = done else {
                return Ok(());
            };
            completed += 1.0;
            removed += done.removed.len() as f64;
            crate::api::package_automation::after_identity_change(
                ctx,
                &candidate_tenant,
                &done.removed,
                &Value::Null,
            )
            .await?;
            Ok(())
        }
        .await;
        if let Err(error) = outcome {
            failed.push(json!({ "reviewId": candidate_id, "message": error.message }));
        }
    }
    Ok(json!({
        "completed": number(completed),
        "removed": number(removed),
        "failed": failed,
    }))
}
