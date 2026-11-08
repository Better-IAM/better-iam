//! Mounting on a Better IAM server (feature `server`): the configurations TypeScript builds by spreading
//! `iam.protocolHost` (`createScimService({ ...iam.protocolHost })`, `createScimProvisioner({ ...iam.protocolHost,
//! encryptionKey })`), `ProtocolService` for both services (`iam.useProtocol(service)`), and `iam.events` as the
//! provisioner's event source.

use std::sync::Arc;

use better_iam_core::{CredentialInput, IamResult};
use better_iam_server::BetterIam;
use better_iam_server::federation::{Federation, create_federation};
use better_iam_server::http::ProtocolService;
use better_iam_server::options::{HttpRequest as ServerRequest, HttpResponse as ServerResponse};
use serde_json::{Map, Value, json};

use crate::outbound::{
    EventHandler, EventSource, ProvisioningConfig, ProvisioningEvent, ScimProvisioner, Unsubscribe,
};
use crate::service::ScimService;
use crate::types::{
    AuthenticateFn, AuthorizeFn, GroupDeletedFn, IdentityStatusChangedFn, RecordAuditFn,
    ScimConfig, SyncRoleMappingsFn, ValidateAttributesFn,
};

/// The server's protocol host (`iam.protocolHost`), shareable by the callbacks.
pub fn protocol_host(iam: &BetterIam) -> IamResult<Arc<Federation>> {
    Ok(Arc::new(create_federation(
        &iam.ctx,
        iam.api.bindings.clone(),
    )?))
}

/// A credential as JSON (`{ headers: [[name, value]], token }`), the form the protocol host's callbacks read.
fn credential_json(credential: &CredentialInput) -> Value {
    let mut map = Map::new();
    if let Some(headers) = &credential.headers {
        map.insert(
            "headers".into(),
            Value::Array(
                headers
                    .iter()
                    .map(|(name, value)| json!([name, value]))
                    .collect(),
            ),
        );
    }
    if let Some(token) = &credential.token {
        map.insert("token".into(), json!(token));
    }
    Value::Object(map)
}

fn authorize(host: &Arc<Federation>) -> AuthorizeFn {
    let host = host.clone();
    Arc::new(move |credential, action, resource| {
        let host = host.clone();
        Box::pin(async move { host.authorize(&credential, &action, &resource).await })
    })
}

fn authenticate(host: &Arc<Federation>) -> AuthenticateFn {
    let host = host.clone();
    Arc::new(move |credential| {
        let host = host.clone();
        Box::pin(async move {
            host.authenticate(&credential)
                .await
                .map(|principal| principal.identity.id)
        })
    })
}

fn record_audit(host: &Arc<Federation>) -> RecordAuditFn {
    let host = host.clone();
    Arc::new(move |tx, event| {
        let host = host.clone();
        Box::pin(async move { host.record_audit(&tx, &event).await })
    })
}

/// `{ ...iam.protocolHost }` as a SCIM service configuration: the server's store, authorization, authentication,
/// identity-attribute validation, audit fan-out, role-mapping sync, and the license callbacks.
pub fn scim_config(iam: &BetterIam) -> IamResult<ScimConfig> {
    let host = protocol_host(iam)?;
    let mut config = ScimConfig::new(iam.store.clone(), authorize(&host), authenticate(&host));
    let validate: ValidateAttributesFn = {
        let host = host.clone();
        Arc::new(move |attributes| {
            host.validate_identity_attributes(Some(&Value::Object(attributes.clone())))
        })
    };
    config.validate_identity_attributes = Some(validate);
    config.record_audit = Some(record_audit(&host));
    let sync: SyncRoleMappingsFn = {
        let host = host.clone();
        Arc::new(move |tx, input| {
            let host = host.clone();
            Box::pin(async move {
                let mut value = json!({
                    "tenantId": input.tenant_id,
                    "connectionId": input.connection_id,
                    "groupId": input.group_id,
                    "identityIds": input.identity_ids,
                    "roleIds": input.role_ids,
                });
                if let Some(credential) = &input.credential {
                    value
                        .as_object_mut()
                        .expect("an object")
                        .insert("credential".into(), credential_json(credential));
                }
                host.sync_role_mappings(&tx, &value).await
            })
        })
    };
    config.sync_role_mappings = Some(sync);
    let status: IdentityStatusChangedFn = {
        let host = host.clone();
        Arc::new(move |tx, input| {
            let host = host.clone();
            Box::pin(async move {
                host.identity_status_changed(
                    &tx,
                    &json!({
                        "tenantId": input.tenant_id,
                        "connectionId": input.connection_id,
                        "identityId": input.identity_id,
                    }),
                )
                .await
            })
        })
    };
    config.identity_status_changed = Some(status);
    let deleted: GroupDeletedFn = {
        let host = host.clone();
        Arc::new(move |tx, input| {
            let host = host.clone();
            Box::pin(async move {
                host.group_deleted(
                    &tx,
                    &json!({
                        "tenantId": input.tenant_id,
                        "connectionId": input.connection_id,
                        "groupId": input.group_id,
                    }),
                )
                .await
            })
        })
    };
    config.group_deleted = Some(deleted);
    Ok(config)
}

/// `{ ...iam.protocolHost, encryptionKey }` as an outbound provisioning configuration.
pub fn provisioning_config(
    iam: &BetterIam,
    encryption_key: impl Into<String>,
) -> IamResult<ProvisioningConfig> {
    let host = protocol_host(iam)?;
    let mut config = ProvisioningConfig::new(
        iam.store.clone(),
        authorize(&host),
        authenticate(&host),
        encryption_key,
    );
    config.record_audit = Some(record_audit(&host));
    Ok(config)
}

#[async_trait::async_trait]
impl ProtocolService for ScimService {
    fn base_path(&self) -> &str {
        ScimService::base_path(self)
    }

    async fn handler(&self, request: &ServerRequest) -> IamResult<Option<ServerResponse>> {
        Ok(ScimService::handler(self, request).await)
    }
}

#[async_trait::async_trait]
impl ProtocolService for ScimProvisioner {
    fn base_path(&self) -> &str {
        ScimProvisioner::base_path(self)
    }

    async fn handler(&self, request: &ServerRequest) -> IamResult<Option<ServerResponse>> {
        Ok(ScimProvisioner::handler(self, request).await)
    }
}

/// `iam.events` as an [`EventSource`].
pub struct ServerEvents<'a>(pub &'a BetterIam);

impl EventSource for ServerEvents<'_> {
    fn subscribe(&self, patterns: Vec<String>, handler: EventHandler) -> Unsubscribe {
        let Ok(events) = self.0.ctx.events() else {
            return Box::new(|| {});
        };
        let patterns: Vec<&str> = patterns.iter().map(String::as_str).collect();
        let subscriber: better_iam_server::context::SubscriberFn = Arc::new(move |event| {
            let text = |key: &str| {
                event
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            handler(ProvisioningEvent {
                tenant_id: text("tenantId"),
                action: text("action"),
            });
            Box::pin(async { Ok(()) })
        });
        match events.subscribe(&patterns, subscriber) {
            Ok(subscription) => Box::new(move || subscription.unsubscribe()),
            Err(_) => Box::new(|| {}),
        }
    }
}
