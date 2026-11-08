//! Integration with `better-iam-server` (the `server` feature): the trusted host callbacks of `iam.protocolHost`
//! for the provider and the Shared Signals transmitter, and `ProtocolService` mounts (`iam.useProtocol`).

use std::sync::Arc;

use better_iam_core::{IamResult, IamStore};
use better_iam_server::BetterIam;
use better_iam_server::federation::{Federation, create_federation};
use better_iam_server::http::ProtocolService;
use better_iam_server::options::{HttpRequest, HttpResponse};
use serde_json::Value;

use crate::client::OAuthLogin;
use crate::provider::{Callback, LiveGrants, OAuthProvider};
use crate::ssf::{AuthenticateIdFn, AuthorizeFn};

/// The members of `iam.protocolHost` the OAuth packages read.
#[derive(Clone)]
pub struct ProtocolHost {
    pub store: Arc<dyn IamStore>,
    pub authenticate:
        Callback<better_iam_core::CredentialInput, better_iam_core::AuthenticatedPrincipal>,
    pub authorize: Callback<
        (
            better_iam_core::CredentialInput,
            String,
            better_iam_core::ResourceRef,
        ),
        (),
    >,
    pub validate_session: Callback<String, ()>,
    pub live_grants: Callback<(String, String), LiveGrants>,
    pub client_allowed: Callback<(String, String, String), bool>,
}

impl ProtocolHost {
    /// The transmitter's `authorize` callback.
    pub fn ssf_authorize(&self) -> AuthorizeFn {
        let authorize = self.authorize.clone();
        Arc::new(move |credential, action, resource| authorize((credential, action, resource)))
    }

    /// The transmitter's `authenticate` callback (the caller's identity ID).
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

/// `iam.protocolHost` as callbacks.
pub fn protocol_host(iam: &BetterIam) -> IamResult<ProtocolHost> {
    let federation: Arc<Federation> =
        Arc::new(create_federation(&iam.ctx, iam.api.bindings.clone())?);
    let host = federation.clone();
    let authenticate: Callback<_, _> = Arc::new(move |credential| {
        let host = host.clone();
        Box::pin(async move { host.authenticate(&credential).await })
    });
    let host = federation.clone();
    let authorize: Callback<_, _> = Arc::new(
        move |(credential, action, resource): (
            better_iam_core::CredentialInput,
            String,
            better_iam_core::ResourceRef,
        )| {
            let host = host.clone();
            Box::pin(async move { host.authorize(&credential, &action, &resource).await })
        },
    );
    let host = federation.clone();
    let validate_session: Callback<_, _> = Arc::new(move |session_id: String| {
        let host = host.clone();
        Box::pin(async move { host.validate_session(&session_id).await.map(|_| ()) })
    });
    let host = federation.clone();
    let live_grants: Callback<_, _> =
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
    let client_allowed: Callback<_, _> = Arc::new(
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

#[async_trait::async_trait]
impl ProtocolService for OAuthLogin {
    fn base_path(&self) -> &str {
        &self.base_path
    }

    async fn handler(&self, request: &HttpRequest) -> IamResult<Option<HttpResponse>> {
        Ok(OAuthLogin::handler(self, request).await)
    }
}

#[async_trait::async_trait]
impl ProtocolService for OAuthProvider {
    fn base_path(&self) -> &str {
        &self.base_path
    }

    /// The provider mount answers its own paths (under the issuer path, and its RFC 8414 metadata) only.
    async fn handler(&self, request: &HttpRequest) -> IamResult<Option<HttpResponse>> {
        if !self.owns(request) {
            return Ok(None);
        }
        Ok(Some(self.node_handler(request).await))
    }
}
