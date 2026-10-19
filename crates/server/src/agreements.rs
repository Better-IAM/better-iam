//! Port of `packages/server/src/agreements.ts`.
//!
//! Ported in full (kernel B: decisions reads `agreementContext`).
#![allow(
    unused_variables,
    unused_imports,
    dead_code,
    clippy::too_many_arguments,
    clippy::module_inception
)]

use std::sync::{Arc, Weak};

use better_iam_core::{IamError, IamResult};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::options::{HttpRequest, HttpResponse};
use crate::port::{Callback, not_ported};

/// A tenant's terms of use (acceptable-use policy, NDA, data-handling rules). Publishing a new version asks
/// everyone to accept again. Names are unique per tenant (uniqueKey `name:{lowercase}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Agreement {
    #[serde(rename = "name")]
    pub name: String,
    /// The text people accept (plain text or Markdown, at most 50 000 characters).
    #[serde(rename = "content")]
    pub content: String,
    /// Optional link to the canonical document.
    #[serde(rename = "url", default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(rename = "version")]
    pub version: f64,
    /// Required agreements count toward `principal.pendingAgreements` until accepted.
    #[serde(rename = "required")]
    pub required: bool,
    /// Acceptance lapses this many days after it was given (annual re-acceptance, for example).
    #[serde(
        rename = "reacceptAfterDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reaccept_after_days: Option<f64>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
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

/// One person's latest acceptance of one agreement; the ID is `{agreementId}:{identityId}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgreementAcceptance {
    #[serde(rename = "agreementId")]
    pub agreement_id: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "version")]
    pub version: f64,
    #[serde(rename = "acceptedAt")]
    pub accepted_at: f64,
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

/// Whether an acceptance covers the agreement's current version and has not lapsed.
pub fn acceptance_current(
    agreement: &crate::agreements::Agreement,
    acceptance: Option<&crate::agreements::AgreementAcceptance>,
    now: f64,
) -> bool {
    let Some(acceptance) = acceptance else {
        return false;
    };
    if acceptance.version != agreement.version {
        return false;
    }
    match agreement.reaccept_after_days {
        None => true,
        Some(days) => now - acceptance.accepted_at < days * 86_400_000.0,
    }
}

/// Policy context for a person in their own tenant: `principal.agreements` lists the names of agreements they have
/// accepted in their current version, and `principal.pendingAgreements` counts required ones they still owe.
/// Service accounts and agents cannot accept anything, so nothing is pending for them.
pub async fn agreement_context(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    kind: better_iam_core::IdentityKind,
    now: f64,
) -> IamResult<Map<String, Value>> {
    use better_iam_core::{Filter, FindOptions};
    let none = || {
        let mut keys = Map::new();
        keys.insert("principal.agreements".into(), Value::Array(Vec::new()));
        keys.insert("principal.pendingAgreements".into(), crate::js::number(0.0));
        keys
    };
    let agreements = tx
        .find(
            "agreements",
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions::default(),
        )
        .await?;
    if agreements.is_empty() {
        return Ok(none());
    }
    let mut acceptances: IndexMap<String, AgreementAcceptance> = IndexMap::new();
    for record in tx
        .find(
            "agreementAcceptances",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", identity_id),
            &FindOptions::default(),
        )
        .await?
    {
        let acceptance: AgreementAcceptance = crate::port::decode(record)?;
        acceptances.insert(acceptance.agreement_id.clone(), acceptance);
    }
    let mut accepted: Vec<String> = Vec::new();
    let mut pending = 0.0;
    for record in agreements {
        let agreement: Agreement = crate::port::decode(record)?;
        if acceptance_current(&agreement, acceptances.get(&agreement.id), now) {
            accepted.push(agreement.name.clone());
        } else if agreement.required && kind == better_iam_core::IdentityKind::User {
            pending += 1.0;
        }
    }
    crate::js::sort_strings(&mut accepted);
    let mut keys = Map::new();
    keys.insert(
        "principal.agreements".into(),
        Value::Array(accepted.into_iter().map(Value::String).collect()),
    );
    keys.insert(
        "principal.pendingAgreements".into(),
        crate::js::number(pending),
    );
    Ok(keys)
}
