//! [`LdapIam`] for a `better_iam_server::BetterIam` instance (the `server` feature): what `createLdapServer({ iam })`
//! reads from a `betterIam()` instance in TypeScript.

use std::sync::Arc;

use better_iam_auth::AuthService;
use better_iam_core::{CredentialInput, IamError, IamResult, SessionClientInfo};
use better_iam_server::BetterIam;
use better_iam_server::api::Body;
use better_iam_server::api::ldap::LdapApi;
use better_iam_server::context::ServerContext;
use better_iam_server::http::{AuthApi, AuthArgs};
use better_iam_server::ldap::{LdapRuntime, create_ldap_runtime};
use serde_json::{Value, json};

use crate::directory::DirectoryData;
use crate::server::{BindKind, BindName, ClientInfo, LdapIam, LdapPrincipal, LdapTenant};

/// The Better IAM instance a gateway serves (`createLdapServer({ iam })`).
pub struct ServerLdapIam {
    ctx: Arc<ServerContext>,
    auth: AuthService,
    auth_api: Arc<AuthApi>,
    ldap_api: Arc<LdapApi>,
    runtime: LdapRuntime,
}

impl ServerLdapIam {
    /// The gateway's view of `iam`.
    pub fn new(iam: &BetterIam) -> IamResult<Self> {
        Ok(Self {
            ctx: iam.ctx.clone(),
            auth: iam.auth.clone(),
            auth_api: iam.auth_api.clone(),
            ldap_api: iam.api.ldap.clone(),
            runtime: create_ldap_runtime(&iam.ctx)?,
        })
    }
}

fn session_client(client: &ClientInfo) -> SessionClientInfo {
    SessionClientInfo {
        ip: client.ip.clone(),
        user_agent: client.user_agent.clone(),
        ..SessionClientInfo::default()
    }
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn flag(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

#[async_trait::async_trait]
impl LdapIam for ServerLdapIam {
    async fn sign_in(&self, client: &ClientInfo, input: Value) -> IamResult<Value> {
        self.auth
            .with_client(
                Some(session_client(client)),
                self.auth_api.call("signIn", AuthArgs::Public(input)),
            )
            .await
    }

    async fn verify_mfa(&self, client: &ClientInfo, input: Value) -> IamResult<Value> {
        self.auth
            .with_client(
                Some(session_client(client)),
                self.auth_api.call("verifyMfa", AuthArgs::Public(input)),
            )
            .await
    }

    async fn sign_out(&self, credential: &CredentialInput) -> IamResult<Value> {
        self.auth_api
            .call(
                "signOut",
                AuthArgs::Authenticated(credential.clone(), json!({})),
            )
            .await
    }

    async fn directory(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
    ) -> IamResult<DirectoryData> {
        let value = self
            .ldap_api
            .directory(
                credential,
                Body::from_value(json!({ "tenantId": tenant_id })),
            )
            .await?
            .into_value()?;
        serde_json::from_value(value)
            .map_err(|_| IamError::with_status("INTERNAL_ERROR", "Internal server error", 500))
    }

    async fn authenticate(
        &self,
        client: &ClientInfo,
        credential: &CredentialInput,
    ) -> IamResult<LdapPrincipal> {
        let principals = self.ctx.principals()?;
        let principal = self
            .auth
            .with_client(
                Some(session_client(client)),
                principals.authenticate(credential),
            )
            .await?;
        let session = serde_json::to_value(principal.session.kind).unwrap_or(Value::Null);
        let identity = serde_json::to_value(principal.identity.kind).unwrap_or(Value::Null);
        Ok(LdapPrincipal {
            identity_id: principal.identity.id.clone(),
            identity_tenant_id: principal.identity.tenant_id.clone(),
            identity_kind: identity.as_str().unwrap_or_default().to_owned(),
            session_tenant_id: principal.session.tenant_id.clone(),
            session_kind: session.as_str().unwrap_or_default().to_owned(),
        })
    }

    async fn tenant_for_base(&self, normalized_base_dn: &str) -> IamResult<Option<LdapTenant>> {
        Ok(self
            .runtime
            .tenant_for_base(normalized_base_dn)
            .await?
            .map(|found| LdapTenant {
                tenant_id: text(&found, "tenantId"),
                base_dn: text(&found, "baseDn"),
                normalized_base_dn: text(&found, "normalizedBaseDn"),
                people_bind: flag(&found, "peopleBind"),
                service_bind: flag(&found, "serviceBind"),
                require_tls: flag(&found, "requireTls"),
                mfa_suffix: text(&found, "mfaSuffix"),
            }))
    }

    async fn resolve_bind_name(
        &self,
        tenant_id: &str,
        kind: BindKind,
        value: &str,
    ) -> IamResult<Option<BindName>> {
        Ok(self
            .runtime
            .resolve_bind_name(tenant_id, kind.as_str(), value)
            .await?
            .map(|found| BindName {
                identity_id: text(&found, "identityId"),
                email: found
                    .get("email")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                mfa: found.get("mfa").and_then(Value::as_str).map(str::to_owned),
            }))
    }
}
