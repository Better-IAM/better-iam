//! `iam.protocolHost` as the callbacks the OAuth packages take (the `server` feature's `protocol_host`, for tests
//! built without the feature).

#![allow(dead_code)]

use std::sync::Arc;

use better_iam_core::{AuthenticatedPrincipal, CredentialInput, IamResult, IamStore, ResourceRef};
use better_iam_oauth::{AuthenticateIdFn, AuthorizeFn, Callback, LiveGrants};
use better_iam_server::BetterIam;
use better_iam_server::federation::create_federation;
use serde_json::Value;

#[derive(Clone)]
pub struct ProtocolHost {
    pub store: Arc<dyn IamStore>,
    pub authenticate: Callback<CredentialInput, AuthenticatedPrincipal>,
    pub authorize: Callback<(CredentialInput, String, ResourceRef), ()>,
    pub validate_session: Callback<String, ()>,
    pub live_grants: Callback<(String, String), LiveGrants>,
    pub client_allowed: Callback<(String, String, String), bool>,
}

impl ProtocolHost {
    pub fn ssf_authorize(&self) -> AuthorizeFn {
        let authorize = self.authorize.clone();
        Arc::new(move |credential, action, resource| authorize((credential, action, resource)))
    }

    pub fn ssf_authenticate(&self) -> AuthenticateIdFn {
        let authenticate = self.authenticate.clone();
        Arc::new(move |credential| {
            let authenticate = authenticate.clone();
            Box::pin(async move { Ok(authenticate(credential).await?.identity.id) })
        })
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub fn protocol_host(iam: &BetterIam) -> IamResult<ProtocolHost> {
    let federation = Arc::new(create_federation(&iam.ctx, iam.api.bindings.clone())?);
    let host = federation.clone();
    let authenticate: Callback<CredentialInput, AuthenticatedPrincipal> =
        Arc::new(move |credential: CredentialInput| {
            let host = host.clone();
            Box::pin(async move { host.authenticate(&credential).await })
        });
    let host = federation.clone();
    let authorize: Callback<(CredentialInput, String, ResourceRef), ()> = Arc::new(
        move |(credential, action, resource): (CredentialInput, String, ResourceRef)| {
            let host = host.clone();
            Box::pin(async move { host.authorize(&credential, &action, &resource).await })
        },
    );
    let host = federation.clone();
    let validate_session: Callback<String, ()> = Arc::new(move |session_id: String| {
        let host = host.clone();
        Box::pin(async move { host.validate_session(&session_id).await.map(|_| ()) })
    });
    let host = federation.clone();
    let live_grants: Callback<(String, String), LiveGrants> =
        Arc::new(move |(identity_id, tenant_id): (String, String)| {
            let host = host.clone();
            Box::pin(async move {
                let grants = host.live_grants(&identity_id, &tenant_id).await?;
                Ok(LiveGrants {
                    group_ids: strings(grants.get("groupIds")),
                    role_ids: strings(grants.get("roleIds")),
                })
            })
        });
    let host = federation;
    let client_allowed: Callback<(String, String, String), bool> = Arc::new(
        move |(identity_id, tenant_id, client_id): (String, String, String)| {
            let host = host.clone();
            Box::pin(async move {
                host.client_allowed(&identity_id, &tenant_id, &client_id)
                    .await
            })
        },
    );
    Ok(ProtocolHost {
        store: iam.store.clone(),
        authenticate,
        authorize,
        validate_session,
        live_grants,
        client_allowed,
    })
}
