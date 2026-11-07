//! Port of `packages/server/src/api/ldap.ts`: the `ldap` API group (each tenant's LDAP directory gateway).

use std::sync::{Arc, LazyLock};

use better_iam_core::{AuditOutcome, CredentialInput, IamError, IamResult, IamStoreExt};
use better_iam_types::api::ldap;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::ServerContext;
use crate::contracts::{Mutation, MutationContext};
use crate::ldap::{
    LdapSettings, build_ldap_directory, load_ldap_settings, normalize_base_dn, save_ldap_settings,
};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::validation::text;

static ATTRIBUTE_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z][a-zA-Z0-9-]{0,63}$").expect("valid attribute name pattern")
});

/// `LdapSettingsView`: the settings as the API returns them.
fn view(settings: &LdapSettings) -> Value {
    let mut out = Map::new();
    out.insert("tenantId".into(), Value::String(settings.tenant_id.clone()));
    out.insert("enabled".into(), Value::Bool(settings.enabled));
    out.insert("baseDn".into(), Value::String(settings.base_dn.clone()));
    out.insert("uid".into(), Value::String(settings.uid.clone()));
    out.insert("peopleBind".into(), Value::Bool(settings.people_bind));
    out.insert("serviceBind".into(), Value::Bool(settings.service_bind));
    out.insert("requireTls".into(), Value::Bool(settings.require_tls));
    out.insert(
        "mfaSuffix".into(),
        Value::String(settings.mfa_suffix.clone()),
    );
    out.insert(
        "includeServiceAccounts".into(),
        Value::Bool(settings.include_service_accounts),
    );
    out.insert("attributes".into(), json!(settings.attributes));
    out.insert("groups".into(), Value::String(settings.groups.clone()));
    out.insert("groupIds".into(), json!(settings.group_ids));
    if settings.updated_at != 0.0 && !settings.updated_at.is_nan() {
        out.insert("updatedAt".into(), crate::js::number(settings.updated_at));
        out.insert(
            "updatedBy".into(),
            Value::String(settings.updated_by.clone()),
        );
    }
    Value::Object(out)
}

/// `tenantOf(value)`: `text(value, 'tenantId')`.
fn tenant_of(value: Option<&Value>) -> IamResult<String> {
    text(value, "tenantId", 256)
}

/// The `ldap` API group: each tenant's LDAP directory gateway. Administrators turn it on under a base DN and choose
/// what it publishes (`iam:ldap:manage`, `iam:ldap:read`); the gateway (`@better-iam/ldap`) reads the directory as
/// the account that bound, which sees everyone with `iam:ldap:read` and otherwise only itself.
pub struct LdapApi {
    ctx: Arc<ServerContext>,
}

/// `createLdapApi(ctx)`.
pub fn create_ldap_api(ctx: &Arc<ServerContext>) -> IamResult<LdapApi> {
    Ok(LdapApi { ctx: ctx.clone() })
}

impl LdapApi {
    /// `ldap/directory`: the directory as the caller may read it: people, groups (with members) and, when published,
    /// service accounts. With iam:ldap:read on `iam/ldap/directory` the whole published directory (audited as
    /// `ldap:directory:read`), otherwise only the caller's own entry and groups. What the gateway serves searches from.
    pub async fn directory(
        &self,
        credential: &CredentialInput,
        input: Body<ldap::DirectoryInput>,
    ) -> IamResult<Reply<ldap::DirectoryOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let (tenant_id, authenticated) = (&tenant_id, &authenticated);
        let directory = ctx
            .store
            .transaction(|tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated)
                    .await?;
                let tenant = ctx.tenant(&tx, tenant_id).await?;
                let settings = load_ldap_settings(&tx, &tenant).await?;
                if !settings.enabled {
                    return Err(IamError::with_status(
                        "FEATURE_DISABLED",
                        "The LDAP gateway is off for this organization",
                        403,
                    ));
                }
                if principal.session.tenant_id != tenant.id
                    || principal
                        .session
                        .impersonator_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty())
                {
                    return Err(IamError::with_status("ACCESS_DENIED", "Access denied", 403));
                }
                let decision = ctx
                    .decisions()?
                    .decide(
                        &tx,
                        &principal,
                        &AuthorizationRequest {
                            credential: CredentialInput::default(),
                            tenant_id: tenant_id.clone(),
                            action: "iam:ldap:read".into(),
                            resource: ResourceTarget {
                                kind: "iam".into(),
                                id: "ldap/directory".into(),
                            },
                        },
                        true,
                    )
                    .await?;
                // The platform root override does not read an organization's directory over LDAP.
                let full = decision.allowed && decision.reason != "ROOT_OVERRIDE";
                let directory = build_ldap_directory(
                    ctx,
                    &tx,
                    &tenant,
                    &settings,
                    if full { None } else { Some(&principal) },
                )
                .await?;
                if full {
                    let mut metadata = Map::new();
                    metadata.insert(
                        "people".into(),
                        crate::js::number(directory.people.len() as f64),
                    );
                    metadata.insert(
                        "groups".into(),
                        crate::js::number(directory.groups.len() as f64),
                    );
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "ldap:directory:read",
                            tenant_id,
                            "ldap/directory",
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                }
                Ok(directory)
            })
            .await?;
        Ok(Reply::json(directory.to_json()))
    }

    /// `ldap/getSettings`: the tenant's gateway settings. Requires iam:ldap:read.
    pub async fn get_settings(
        &self,
        credential: &CredentialInput,
        input: Body<ldap::GetSettingsInput>,
    ) -> IamResult<Reply<ldap::GetSettingsOutput>> {
        let ctx = &self.ctx;
        let tenant_id = Value::String(tenant_of(input.get("tenantId"))?);
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move { Ok(view(&load_ldap_settings(&tx, &tenant).await?)) })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&tenant_id),
                "iam:ldap:read",
                "ldap/settings",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `ldap/updateSettings`: changes the gateway settings (fields left out keep their values). A base DN belongs to
    /// one organization (`LDAP_BASE_TAKEN`). Requires iam:ldap:manage.
    pub async fn update_settings(
        &self,
        credential: &CredentialInput,
        input: Body<ldap::UpdateSettingsInput>,
    ) -> IamResult<Reply<ldap::UpdateSettingsOutput>> {
        let ctx = &self.ctx;
        let tenant_id = Value::String(tenant_of(input.get("tenantId"))?);
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let current = load_ldap_settings(&tx, &tenant).await?;
                    let mut next = current.clone();
                    next.updated_at = ctx.now();
                    next.updated_by = principal.identity.id.clone();
                    if let Some(base_dn) = body.get("baseDn") {
                        let normalized = normalize_base_dn(Some(base_dn))?;
                        next.base_dn = normalized.base_dn;
                        next.normalized_base_dn = normalized.normalized;
                    }
                    for key in [
                        "enabled",
                        "peopleBind",
                        "serviceBind",
                        "requireTls",
                        "includeServiceAccounts",
                    ] {
                        let Some(value) = body.get(key) else {
                            continue;
                        };
                        let Value::Bool(flag) = value else {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                format!("{key} must be a boolean"),
                            )
                            .into());
                        };
                        match key {
                            "enabled" => next.enabled = *flag,
                            "peopleBind" => next.people_bind = *flag,
                            "serviceBind" => next.service_bind = *flag,
                            "requireTls" => next.require_tls = *flag,
                            _ => next.include_service_accounts = *flag,
                        }
                    }
                    if let Some(uid) = body.get("uid") {
                        match uid.as_str() {
                            Some(uid @ ("email" | "localPart" | "id")) => next.uid = uid.to_owned(),
                            _ => {
                                return Err(IamError::new(
                                    "INVALID_INPUT",
                                    "uid must be 'email', 'localPart' or 'id'",
                                )
                                .into());
                            }
                        }
                    }
                    if let Some(suffix) = body.get("mfaSuffix") {
                        match suffix.as_str() {
                            Some(suffix @ ("auto" | "never")) => {
                                next.mfa_suffix = suffix.to_owned()
                            }
                            _ => {
                                return Err(IamError::new(
                                    "INVALID_INPUT",
                                    "mfaSuffix must be 'auto' or 'never'",
                                )
                                .into());
                            }
                        }
                    }
                    if let Some(attributes) = body.get("attributes") {
                        let Some(attributes) =
                            attributes.as_array().filter(|list| list.len() <= 64)
                        else {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "attributes must list at most 64 identity attributes",
                            )
                            .into());
                        };
                        let names = crate::js::unique(
                            attributes
                                .iter()
                                .map(|name| text(Some(name), "attribute", 64))
                                .collect::<IamResult<Vec<_>>>()?,
                        );
                        for name in &names {
                            if !ctx.catalog.identity_attributes.contains_key(name)
                                || !ATTRIBUTE_NAME.is_match(name)
                            {
                                return Err(IamError::new(
                                    "INVALID_INPUT",
                                    format!(
                                        "{name} is not a declared identity attribute LDAP can publish"
                                    ),
                                )
                                .into());
                            }
                        }
                        next.attributes = names;
                    }
                    if let Some(groups) = body.get("groups") {
                        match groups.as_str() {
                            Some(groups @ ("all" | "selected")) => next.groups = groups.to_owned(),
                            _ => {
                                return Err(IamError::new(
                                    "INVALID_INPUT",
                                    "groups must be 'all' or 'selected'",
                                )
                                .into());
                            }
                        }
                    }
                    if let Some(group_ids) = body.get("groupIds") {
                        let Some(group_ids) = group_ids.as_array().filter(|list| list.len() <= 500)
                        else {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "groupIds must list at most 500 groups",
                            )
                            .into());
                        };
                        let ids = crate::js::unique(
                            group_ids
                                .iter()
                                .map(|group_id| text(Some(group_id), "groupId", 256))
                                .collect::<IamResult<Vec<_>>>()?,
                        );
                        for group_id in &ids {
                            ctx.scoped(
                                &tx,
                                "groups",
                                Some(&Value::String(group_id.clone())),
                                &tenant.id,
                            )
                            .await?;
                        }
                        next.group_ids = ids;
                    }
                    Ok(view(&save_ldap_settings(&tx, &next, Some(&current)).await?))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&tenant_id),
                "iam:ldap:manage",
                "ldap/settings",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}
