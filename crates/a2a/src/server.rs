//! [`A2aIam`] for an in-process Better IAM instance (`better_iam(options)`): the gate takes a `betterIam()` instance
//! in TypeScript, whose `api.delegations` lets it ask a person to confirm an agent's request.

use std::sync::Arc;

use async_trait::async_trait;
use better_iam_core::CredentialInput;
use better_iam_server::BetterIam;
use better_iam_server::api::Body;
use better_iam_server::options::{
    AuthorizationCheck, AuthorizationRequest, BatchAuthorizationRequest, ResourceTarget,
};
use serde_json::{Map, Value, json};

use crate::error::A2aError;
use crate::gate::{
    A2aAuthorization, A2aCheck, A2aConfirmationRequest, A2aDelegation, A2aDelegations, A2aIam,
    A2aIdentity, A2aPrincipal, A2aResourceRef, A2aSession,
};

fn kind_of<T: serde::Serialize>(kind: &T) -> String {
    match serde_json::to_value(kind) {
        Ok(Value::String(kind)) => kind,
        _ => String::new(),
    }
}

fn target(resource: &A2aResourceRef) -> ResourceTarget {
    ResourceTarget {
        kind: resource.kind.clone(),
        id: resource.id.clone(),
    }
}

fn body<I>(value: Value) -> Body<I> {
    match value {
        Value::Object(map) => Body::new(map),
        _ => Body::new(Map::new()),
    }
}

#[async_trait]
impl A2aDelegations for BetterIam {
    async fn get(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        delegation_id: &str,
    ) -> Result<A2aDelegation, A2aError> {
        let delegation = self
            .api
            .delegations
            .get(
                credential,
                body(json!({ "tenantId": tenant_id, "delegationId": delegation_id })),
            )
            .await?
            .into_value()?;
        let confirm = delegation
            .get("confirm")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            });
        Ok(A2aDelegation { confirm })
    }

    async fn request_confirmation(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        action: &str,
        resource: &A2aResourceRef,
        reason: &str,
    ) -> Result<A2aConfirmationRequest, A2aError> {
        let request = self
            .api
            .delegations
            .request_confirmation(
                credential,
                body(json!({
                    "tenantId": tenant_id,
                    "action": action,
                    "resource": { "type": resource.kind, "id": resource.id },
                    "reason": reason,
                })),
            )
            .await?
            .into_value()?;
        let text = |name: &str| {
            request
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        Ok(A2aConfirmationRequest {
            id: text("id"),
            status: text("status"),
            expires_at: request
                .get("expiresAt")
                .and_then(Value::as_f64)
                .unwrap_or(f64::NAN),
        })
    }
}

#[async_trait]
impl A2aIam for BetterIam {
    async fn authenticate(&self, credential: &CredentialInput) -> Result<A2aPrincipal, A2aError> {
        let principal = BetterIam::authenticate(self, credential).await?;
        Ok(A2aPrincipal {
            identity: A2aIdentity {
                id: principal.identity.id,
                tenant_id: principal.identity.tenant_id,
                kind: kind_of(&principal.identity.kind),
            },
            session: A2aSession {
                id: principal.session.id,
                tenant_id: principal.session.tenant_id,
                kind: principal.session.kind.as_str().to_owned(),
                agent_id: principal.session.agent_id,
                delegation_id: principal.session.delegation_id,
            },
        })
    }

    async fn authorize(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        action: &str,
        resource: &A2aResourceRef,
    ) -> Result<A2aAuthorization, A2aError> {
        let decision = BetterIam::authorize(
            self,
            &AuthorizationRequest {
                credential: credential.clone(),
                tenant_id: tenant_id.to_owned(),
                action: action.to_owned(),
                resource: target(resource),
            },
        )
        .await?;
        Ok(A2aAuthorization {
            allowed: decision.allowed,
            reason: decision.reason,
        })
    }

    async fn authorize_many(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        checks: &[A2aCheck],
    ) -> Result<Vec<A2aAuthorization>, A2aError> {
        let results = BetterIam::authorize_many(
            self,
            &BatchAuthorizationRequest {
                credential: credential.clone(),
                tenant_id: tenant_id.to_owned(),
                checks: checks
                    .iter()
                    .map(|check| AuthorizationCheck {
                        action: check.action.clone(),
                        resource: target(&check.resource),
                    })
                    .collect(),
            },
        )
        .await?;
        Ok(results
            .into_iter()
            .map(|result| A2aAuthorization {
                allowed: result.allowed,
                reason: result.reason,
            })
            .collect())
    }

    fn delegations(&self) -> Option<&dyn A2aDelegations> {
        Some(self)
    }
}

/// [`A2aIam`] for a shared instance.
#[async_trait]
impl A2aIam for Arc<BetterIam> {
    async fn authenticate(&self, credential: &CredentialInput) -> Result<A2aPrincipal, A2aError> {
        A2aIam::authenticate(self.as_ref(), credential).await
    }

    async fn authorize(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        action: &str,
        resource: &A2aResourceRef,
    ) -> Result<A2aAuthorization, A2aError> {
        A2aIam::authorize(self.as_ref(), credential, tenant_id, action, resource).await
    }

    async fn authorize_many(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        checks: &[A2aCheck],
    ) -> Result<Vec<A2aAuthorization>, A2aError> {
        A2aIam::authorize_many(self.as_ref(), credential, tenant_id, checks).await
    }

    fn delegations(&self) -> Option<&dyn A2aDelegations> {
        Some(self.as_ref())
    }
}
