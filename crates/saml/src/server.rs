//! The `server` feature: the service as a `better_iam_server` protocol mount (`iam.use_protocol`), and its host
//! callbacks from `iam.protocol_host()` (`createSamlService({ ...iam.protocolHost, serviceProvider })`).

use std::sync::Arc;

use better_iam_core::{CredentialInput, IamResult, ResourceRef};
use better_iam_server::BetterIam;
use better_iam_server::federation::{Federation, create_federation};
use better_iam_server::http::ProtocolService;
use better_iam_server::options::{HttpRequest, HttpResponse};
use serde_json::{Value, json};

use crate::service::{SamlConfigOptions, SamlService};

#[async_trait::async_trait]
impl ProtocolService for SamlService {
    fn base_path(&self) -> &str {
        SamlService::base_path(self)
    }

    async fn handler(&self, request: &HttpRequest) -> IamResult<Option<HttpResponse>> {
        Ok(SamlService::handler(self, request).await)
    }
}

impl SamlConfigOptions {
    /// `{ ...iam.protocolHost }`: the store and the `authenticate`, `authorize`, `completeAuthentication` and
    /// `assertTrustChange` callbacks of a Better IAM instance.
    pub fn from_protocol_host(iam: &BetterIam) -> IamResult<SamlConfigOptions> {
        let host: Arc<Federation> =
            Arc::new(create_federation(&iam.ctx, iam.api.bindings.clone())?);
        let complete = host.clone();
        let mut options = SamlConfigOptions::new(
            iam.store.clone(),
            Arc::new(move |input: Value| {
                let host = complete.clone();
                Box::pin(async move { host.complete_authentication(&input).await })
            }),
        );
        let authenticate = host.clone();
        options.authenticate = Some(Arc::new(move |credential: CredentialInput| {
            let host = authenticate.clone();
            Box::pin(async move { host.authenticate(&credential).await })
        }));
        let authorize = host.clone();
        options.authorize = Some(Arc::new(
            move |credential: CredentialInput, action: String, resource: ResourceRef| {
                let host = authorize.clone();
                Box::pin(async move { host.authorize(&credential, &action, &resource).await })
            },
        ));
        let trust = host;
        options.assert_trust_change = Some(Arc::new(
            move |credential: CredentialInput, tenant_id: String, provider_id: String| {
                let host = trust.clone();
                Box::pin(async move {
                    host.assert_trust_change(
                        &credential,
                        &json!({ "tenantId": tenant_id, "providerId": provider_id }),
                    )
                    .await
                })
            },
        ));
        Ok(options)
    }
}
