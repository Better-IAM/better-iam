//! A `betterIam()` instance as the gate's [`McpIam`]: `authenticate`, `authorize`, `authorizeMany`, and the
//! `delegations` API for per-action confirmations.

use std::borrow::Borrow;
use std::sync::Arc;

use async_trait::async_trait;
use better_iam_core::{CredentialInput, IamResult};
use better_iam_server::BetterIam;
use better_iam_server::api::Body;
use better_iam_server::api::delegations::DelegationsApi;
use better_iam_server::options::{
    AuthorizationCheck, AuthorizationRequest, BatchAuthorizationRequest, ResourceTarget,
};
use serde_json::{Value, json};

use crate::{
    McpCheck, McpCheckResult, McpConfirmationInput, McpConfirmationRequest, McpDelegation,
    McpDelegationsApi, McpIam, McpIdentity, McpPrincipal, McpResourceRef, McpSession,
};

fn target(resource: &McpResourceRef) -> ResourceTarget {
    ResourceTarget {
        kind: resource.kind.clone(),
        id: resource.id.clone(),
    }
}

#[async_trait]
impl<B> McpIam for B
where
    B: Borrow<BetterIam> + Send + Sync,
{
    async fn authenticate(&self, credential: &CredentialInput) -> IamResult<McpPrincipal> {
        let iam: &BetterIam = self.borrow();
        let principal = iam.authenticate(credential).await?;
        let identity_kind = serde_json::to_value(principal.identity.kind)
            .ok()
            .and_then(|kind| kind.as_str().map(str::to_owned))
            .unwrap_or_default();
        Ok(McpPrincipal {
            identity: McpIdentity {
                id: principal.identity.id.clone(),
                tenant_id: principal.identity.tenant_id.clone(),
                kind: identity_kind,
                name: Some(principal.identity.name.clone()),
            },
            session: McpSession {
                id: principal.session.id.clone(),
                tenant_id: principal.session.tenant_id.clone(),
                kind: principal.session.kind.as_str().to_owned(),
                agent_id: principal.session.agent_id.clone(),
                delegation_id: principal.session.delegation_id.clone(),
            },
        })
    }

    async fn authorize(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        action: &str,
        resource: &McpResourceRef,
    ) -> IamResult<McpCheckResult> {
        let iam: &BetterIam = self.borrow();
        let decision = iam
            .authorize(&AuthorizationRequest {
                credential: credential.clone(),
                tenant_id: tenant_id.to_owned(),
                action: action.to_owned(),
                resource: target(resource),
            })
            .await?;
        Ok(McpCheckResult {
            allowed: decision.allowed,
            reason: decision.reason,
        })
    }

    async fn authorize_many(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        checks: &[McpCheck],
    ) -> IamResult<Vec<McpCheckResult>> {
        let iam: &BetterIam = self.borrow();
        let results = iam
            .authorize_many(&BatchAuthorizationRequest {
                credential: credential.clone(),
                tenant_id: tenant_id.to_owned(),
                checks: checks
                    .iter()
                    .map(|check| AuthorizationCheck {
                        action: check.action.clone(),
                        resource: target(&check.resource),
                    })
                    .collect(),
            })
            .await?;
        Ok(results
            .into_iter()
            .map(|result| McpCheckResult {
                allowed: result.allowed,
                reason: result.reason,
            })
            .collect())
    }

    fn delegations(&self) -> Option<Arc<dyn McpDelegationsApi>> {
        let iam: &BetterIam = self.borrow();
        Some(iam.api.delegations.clone())
    }
}

#[async_trait]
impl McpDelegationsApi for DelegationsApi {
    async fn get(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        delegation_id: &str,
    ) -> IamResult<McpDelegation> {
        let delegation = DelegationsApi::get(
            self,
            credential,
            Body::from_value(json!({ "tenantId": tenant_id, "delegationId": delegation_id })),
        )
        .await?
        .into_value()?;
        Ok(McpDelegation {
            confirm: delegation
                .get("confirm")
                .and_then(Value::as_array)
                .map(|patterns| {
                    patterns
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                }),
        })
    }

    async fn request_confirmation(
        &self,
        credential: &CredentialInput,
        input: &McpConfirmationInput,
    ) -> IamResult<McpConfirmationRequest> {
        let request = DelegationsApi::request_confirmation(
            self,
            credential,
            Body::from_value(json!({
                "tenantId": input.tenant_id,
                "action": input.action,
                "resource": { "type": input.resource.kind, "id": input.resource.id },
                "reason": input.reason,
            })),
        )
        .await?
        .into_value()?;
        Ok(McpConfirmationRequest {
            id: request
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            status: request
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            expires_at: request
                .get("expiresAt")
                .and_then(Value::as_f64)
                .unwrap_or(f64::NAN),
        })
    }
}
