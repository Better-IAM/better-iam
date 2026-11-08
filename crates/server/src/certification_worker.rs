//! Port of `packages/server/src/certification-worker.ts`: the deployment worker that closes overdue auto-closing
//! access certification campaigns. Not an HTTP endpoint.

use std::sync::Arc;

use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamResult, IamStoreExt, Identity,
    IdentityStatus, Record,
};
use serde_json::{Map, Value, json};

use crate::api::certifications::{CertificationCampaign, apply_campaign_record};
use crate::context::{ServerContext, Store};
use crate::js::{cmp_utf16, internal_error, member};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::decode;
use crate::utils::id;
use crate::validation::text;

/// Deployment worker for access certifications. Not an HTTP endpoint.
pub struct CertificationWorker {
    ctx: Arc<ServerContext>,
}

/// `createCertificationWorker(ctx)`.
pub fn create_certification_worker(ctx: &Arc<ServerContext>) -> IamResult<CertificationWorker> {
    Ok(CertificationWorker { ctx: ctx.clone() })
}

/// The creator as the principal revocations run under, only while they could still close the campaign themselves:
/// active, not expired, and allowed iam:certifications:manage on it. Offboarding (disabling, expiry, losing the
/// permission) ends their authority here too, as deletion does.
async fn acting_creator(
    ctx: &ServerContext,
    tx: &Store,
    campaign: &CertificationCampaign,
    creator: &Identity,
) -> IamResult<Option<AuthenticatedPrincipal>> {
    if creator.status != IdentityStatus::Active || ctx.identity_expired(creator) {
        return Ok(None);
    }
    let decisions = ctx.decisions()?;
    let principal = decisions.simulated_principal(creator, false);
    let decision = decisions
        .decide(
            tx,
            &principal,
            &AuthorizationRequest {
                credential: CredentialInput::default(),
                tenant_id: campaign.tenant_id.clone(),
                action: "iam:certifications:manage".into(),
                resource: ResourceTarget {
                    kind: "iam".into(),
                    id: format!("certifications/{}", campaign.id),
                },
            },
            true,
        )
        .await?;
    Ok(decision.allowed.then_some(principal))
}

impl CertificationWorker {
    /// Closes every open `autoClose` campaign whose `dueAt` has passed (or only those of `tenantId`), each in its own
    /// transaction. Revocations run under the campaign creator's grant authority; when the creator no longer exists, is
    /// disabled or expired, or no longer holds iam:certifications:manage on the campaign, the campaign still closes and
    /// every revocation is reported as `revocation-failed`. Audited as `certification:auto-close` (with the outcome
    /// counts) plus one `iam:bindings:delete` per removed binding, both by `deployment-operator`. A deployment
    /// operation for schedulers: no credential.
    pub async fn close_overdue_certifications(&self, input: Option<&Value>) -> IamResult<Value> {
        let ctx = &self.ctx;
        let store = &ctx.store;
        // `input = {}`: `null` is not defaulted, and reading a member of it throws.
        if matches!(input, Some(Value::Null)) {
            return Err(internal_error());
        }
        let tenant_id = match member(input, "tenantId") {
            None => None,
            Some(value) => Some(
                ctx.tenant(store, &text(Some(value), "tenantId", 256)?)
                    .await?
                    .id,
            ),
        };
        let mut filter = Filter::new().eq("status", "open").eq("autoClose", true);
        if let Some(tenant_id) = tenant_id.as_ref().filter(|id| !id.is_empty()) {
            filter = filter.eq("tenantId", tenant_id.clone());
        }
        let mut candidates: Vec<CertificationCampaign> = Vec::new();
        for record in store
            .find("certificationCampaigns", &filter, &FindOptions::default())
            .await?
        {
            candidates.push(decode(record)?);
        }
        candidates.sort_by(|a, b| {
            let (left, right) = (a.due_at.unwrap_or(0.0), b.due_at.unwrap_or(0.0));
            left.partial_cmp(&right)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| cmp_utf16(&a.id, &b.id))
        });
        let mut closed: Vec<Value> = Vec::new();
        let mut skipped = 0usize;
        for candidate in candidates {
            match candidate.due_at {
                Some(due_at) if due_at <= ctx.now() => {}
                _ => {
                    skipped += 1;
                    continue;
                }
            }
            let ctx = ctx.clone();
            let candidate_id = candidate.id.clone();
            let result: Option<Value> = store
                .transaction(move |tx| async move {
                    let Some(record) = tx.get("certificationCampaigns", &candidate_id).await?
                    else {
                        return Ok(None);
                    };
                    // An administrator may have closed or deleted it since the scan.
                    if record.get("status").and_then(Value::as_str) != Some("open") {
                        return Ok(None);
                    }
                    let campaign: CertificationCampaign = decode(record.clone())?;
                    let principal = match tx.get("identities", &campaign.created_by).await? {
                        Some(creator) => {
                            let creator: Identity = decode(creator)?;
                            acting_creator(&ctx, &tx, &campaign, &creator).await?
                        }
                        None => None,
                    };
                    let applied = apply_campaign_record(
                        &ctx,
                        &tx,
                        &record,
                        principal.as_ref(),
                        Some("deployment-operator"),
                    )
                    .await?;
                    let outcomes = applied
                        .get("outcomes")
                        .cloned()
                        .unwrap_or_else(|| Value::Object(Map::new()));
                    let mut event = Record::new();
                    event.insert("id".into(), Value::String(id()));
                    event.insert("tenantId".into(), Value::String(campaign.tenant_id.clone()));
                    event.insert(
                        "actorId".into(),
                        Value::String("deployment-operator".into()),
                    );
                    event.insert(
                        "action".into(),
                        Value::String("certification:auto-close".into()),
                    );
                    event.insert("resourceId".into(), Value::String(campaign.id.clone()));
                    event.insert("timestamp".into(), crate::js::number(ctx.now()));
                    event.insert("outcome".into(), Value::String("allow".into()));
                    event.insert("metadata".into(), outcomes.clone());
                    ctx.events()?.record_audit(&tx, &event).await?;
                    Ok(Some(json!({
                        "tenantId": campaign.tenant_id,
                        "campaignId": campaign.id,
                        "outcomes": outcomes,
                    })))
                })
                .await?;
            if let Some(result) = result {
                closed.push(result);
            }
        }
        Ok(json!({ "closed": closed, "skipped": skipped }))
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "closeOverdueCertifications" => {
                Some(self.close_overdue_certifications(args.first()).await)
            }
            _ => None,
        }
    }
}
