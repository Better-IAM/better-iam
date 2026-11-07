//! Port of `packages/server/src/api/hostnames.ts`: custom sign-in hostnames. An organization claims a hostname it
//! controls (`login.acme.com`), publishes the TXT record it is given, points the hostname at the deployment with a
//! CNAME, and verifies it. From then on the hostname resolves to the organization like its subdomain does: requests
//! there are pinned to it, its origin is trusted, and a primary hostname becomes the address in its sign-in URLs and
//! email links. Needs `hosts.customHostnames`.

use std::sync::Arc;

use better_iam_core::{CredentialInput, Filter, FindOptions, IamError, IamResult, Record, Tenant};
use better_iam_types::api::hostnames;
use serde_json::{Map, Value, json};

use crate::api::domains::{
    domain_name, permitted_ahead, record_name, txt_lookup, txt_matches, verification_token,
};
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::hosts::{HostnameOwner, TenantHostname};
use crate::options::ResolveTxtFn;
use crate::port::decode;
use crate::utils::{by_newest, id};
use crate::validation::text;

/// The most hostnames one organization may claim.
const MAX_HOSTNAMES: usize = 20;

/// The `hostnames` API group (`createHostnamesApi(ctx)`): one method per route `hostnames/{method}`.
pub struct HostnamesApi {
    ctx: Arc<ServerContext>,
    record_name: String,
    lookup: ResolveTxtFn,
}

/// `createHostnamesApi(ctx)`.
pub fn create_hostnames_api(ctx: &Arc<ServerContext>) -> IamResult<HostnamesApi> {
    Ok(HostnamesApi {
        ctx: ctx.clone(),
        record_name: record_name(ctx),
        lookup: txt_lookup(ctx),
    })
}

impl HostnamesApi {
    /// `enabled()`: FEATURE_DISABLED unless `hosts.customHostnames`.
    fn enabled(&self) -> IamResult<()> {
        if !self.ctx.config.hosts.custom_hostnames {
            return Err(IamError::new(
                "FEATURE_DISABLED",
                "Custom hostnames are not enabled on this deployment (hosts.customHostnames)",
            ));
        }
        Ok(())
    }

    /// The TXT record that proves control: `(name, value)`.
    fn verification(&self, record: &TenantHostname) -> (String, String) {
        (
            format!("{}.{}", self.record_name, record.hostname),
            format!("better-iam-hostname={}", record.verification_token),
        )
    }

    /// `present(record)`: a claimed hostname as the API returns it (`PublicHostname`).
    fn present(&self, record: &TenantHostname) -> Value {
        let hosts = &self.ctx.config.hosts;
        let protocol = format!("{}:", self.ctx.config.base_url.scheme());
        let (name, value) = self.verification(record);
        let mut out = Map::new();
        out.insert("id".into(), Value::String(record.id.clone()));
        out.insert("tenantId".into(), Value::String(record.tenant_id.clone()));
        out.insert("hostname".into(), Value::String(record.hostname.clone()));
        out.insert("status".into(), Value::String(record.status.clone()));
        out.insert("primary".into(), Value::Bool(record.primary == Some(true)));
        out.insert(
            "url".into(),
            Value::String(format!(
                "{protocol}//{}{}",
                record.hostname, hosts.sign_in_path
            )),
        );
        out.insert("createdAt".into(), crate::js::number(record.created_at));
        out.insert("createdBy".into(), Value::String(record.created_by.clone()));
        if let Some(verified_at) = record.verified_at {
            out.insert("verifiedAt".into(), crate::js::number(verified_at));
        }
        if let Some(checked) = record.last_checked_at {
            out.insert("lastCheckedAt".into(), crate::js::number(checked));
        }
        let mut records = Map::new();
        records.insert(
            "verification".into(),
            json!({ "type": "TXT", "name": name, "value": value }),
        );
        if let Some(target) = hosts
            .cname_target
            .as_ref()
            .filter(|target| !target.is_empty())
        {
            records.insert(
                "routing".into(),
                json!({ "type": "CNAME", "name": record.hostname, "value": target }),
            );
        }
        out.insert("dnsRecords".into(), Value::Object(records));
        Value::Object(out)
    }

    /// `present` of a stored record.
    fn present_record(&self, record: Record) -> IamResult<Value> {
        Ok(self.present(&decode(record)?))
    }

    /// Actions on a claim are authorized on `hostnames/{hostname}`, so a grant can name the hostname. The claim is
    /// read ahead only to pick that resource: an ID that is not one of this tenant's claims is authorized as
    /// `hostnames/{id}` and reported missing inside the operation, after authorization, so a caller it refuses
    /// cannot tell whether it exists.
    async fn claim_resource(&self, tenant_id: &str, hostname_id: &str) -> IamResult<String> {
        let record = self.ctx.store.get("tenantHostnames", hostname_id).await?;
        Ok(match record {
            Some(record) if record.get("tenantId").and_then(Value::as_str) == Some(tenant_id) => {
                format!("hostnames/{}", string_member(&record, "hostname"))
            }
            _ => format!("hostnames/{hostname_id}"),
        })
    }

    /// The claim inside an operation: this tenant's, and the one its authorized resource names.
    async fn authorized_claim(
        &self,
        tx: &Store,
        tenant_id: &str,
        hostname_id: &str,
        resource_id: &str,
    ) -> IamResult<(Record, TenantHostname)> {
        let raw = self
            .ctx
            .scoped(
                tx,
                "tenantHostnames",
                Some(&Value::String(hostname_id.to_owned())),
                tenant_id,
            )
            .await?;
        let record: TenantHostname = decode(raw.clone())?;
        if format!("hostnames/{}", record.hostname) != resource_id {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "Resource not found",
                404,
            ));
        }
        Ok((raw, record))
    }

    /// `hostnames/add`: claims a hostname for the organization and returns the DNS records to publish. Requires
    /// iam:hostnames:create. Hostnames the deployment uses itself (its base URL and its subdomain space) are
    /// refused.
    pub async fn add(
        &self,
        credential: &CredentialInput,
        input: Body<hostnames::AddInput>,
    ) -> IamResult<Reply<hostnames::AddOutput>> {
        let ctx = &self.ctx;
        self.enabled()?;
        let hostname = domain_name(input.get("hostname"))?;
        ctx.hosts()?.assert_claimable(&hostname)?;
        let resource_id = format!("hostnames/{hostname}");
        let hostname = &hostname;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let mut existing: Vec<TenantHostname> = Vec::new();
                    for record in tx
                        .find(
                            "tenantHostnames",
                            &Filter::new().eq("tenantId", tenant.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        existing.push(decode(record)?);
                    }
                    if existing.iter().any(|record| &record.hostname == hostname) {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "This organization already claimed the hostname",
                            409,
                        )
                        .into());
                    }
                    if existing.len() >= MAX_HOSTNAMES {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!("An organization can claim at most {MAX_HOSTNAMES} hostnames"),
                            409,
                        )
                        .into());
                    }
                    let owner = tx.get("hostnameOwners", hostname).await?;
                    if let Some(owner) = owner {
                        let owner: HostnameOwner = decode(owner)?;
                        if owner.tenant_id != tenant.id {
                            return Err(IamError::with_status(
                                "HOSTNAME_TAKEN",
                                "Another organization verified this hostname",
                                409,
                            )
                            .into());
                        }
                    }
                    let mut record = Record::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    record.insert("uniqueKey".into(), Value::String(hostname.clone()));
                    record.insert("hostname".into(), Value::String(hostname.clone()));
                    record.insert("status".into(), Value::String("pending".into()));
                    record.insert(
                        "verificationToken".into(),
                        Value::String(verification_token()),
                    );
                    record.insert("createdAt".into(), crate::js::number(ctx.now()));
                    record.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let record = tx.insert("tenantHostnames", &record).await?;
                    Ok(self.present_record(record)?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:hostnames:create",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `hostnames/list`: the organization's claimed hostnames with their DNS records, newest first. Requires
    /// iam:hostnames:read.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<hostnames::ListInput>,
    ) -> IamResult<Reply<hostnames::ListOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut records: Vec<TenantHostname> = Vec::new();
                for record in tx
                    .find(
                        "tenantHostnames",
                        &Filter::new().eq("tenantId", tenant.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    records.push(decode(record)?);
                }
                records.sort_by(|a, b| by_newest(a.created_at, &a.id, b.created_at, &b.id));
                Ok(Value::Array(
                    records.iter().map(|record| self.present(record)).collect(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:hostnames:read",
                "hostnames/*",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `hostnames/verify`: looks up the TXT record and, when it matches, marks the hostname verified so it starts
    /// resolving to the organization. DNS is queried before the transaction opens, and only for a caller allowed to
    /// verify the claim; `verified: false` means the record is not visible yet. Requires iam:hostnames:update.
    pub async fn verify(
        &self,
        credential: &CredentialInput,
        input: Body<hostnames::VerifyInput>,
    ) -> IamResult<Reply<hostnames::VerifyOutput>> {
        let ctx = &self.ctx;
        self.enabled()?;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let hostname_id = text(input.get("hostnameId"), "hostnameId", 256)?;
        let resource_id = self.claim_resource(&tenant_id, &hostname_id).await?;
        let mut found = false;
        if permitted_ahead(
            ctx,
            credential,
            &tenant_id,
            "iam:hostnames:update",
            &resource_id,
        )
        .await?
        {
            let record = ctx.store.get("tenantHostnames", &hostname_id).await?;
            if let Some(record) = record {
                let record: TenantHostname = decode(record)?;
                if record.tenant_id == tenant_id && record.status != "verified" {
                    ctx.hosts()?.assert_claimable(&record.hostname)?;
                    let (name, value) = self.verification(&record);
                    found = txt_matches(&self.lookup, &name, &value).await;
                }
            }
        }
        let (tenant_ref, hostname_ref, resource_ref) = (&tenant_id, &hostname_id, &resource_id);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let (raw, current) = self
                    .authorized_claim(&tx, tenant_ref, hostname_ref, resource_ref)
                    .await?;
                if current.status == "verified" {
                    return Ok(json!({ "verified": true, "hostname": self.present(&current) }));
                }
                let now = ctx.now();
                if !found {
                    let mut checked = raw;
                    checked.insert("lastCheckedAt".into(), crate::js::number(now));
                    let checked = tx.put("tenantHostnames", &checked).await?;
                    return Ok(
                        json!({ "verified": false, "hostname": self.present_record(checked)? }),
                    );
                }
                let owner = tx.get("hostnameOwners", &current.hostname).await?;
                let owner: Option<HostnameOwner> = owner.map(decode).transpose()?;
                if let Some(owner) = &owner
                    && &owner.tenant_id != tenant_ref
                {
                    return Err(IamError::with_status(
                        "HOSTNAME_TAKEN",
                        "Another organization verified this hostname",
                        409,
                    )
                    .into());
                }
                if owner.is_none() {
                    let mut claim = Record::new();
                    claim.insert("id".into(), Value::String(current.hostname.clone()));
                    claim.insert("tenantId".into(), Value::String(tenant_ref.clone()));
                    claim.insert("hostnameId".into(), Value::String(current.id.clone()));
                    claim.insert("verifiedAt".into(), crate::js::number(now));
                    tx.insert("hostnameOwners", &claim).await?;
                }
                let mut verified = raw;
                verified.insert("status".into(), Value::String("verified".into()));
                verified.insert("verifiedAt".into(), crate::js::number(now));
                verified.insert("lastCheckedAt".into(), crate::js::number(now));
                let verified = tx.put("tenantHostnames", &verified).await?;
                Ok(json!({ "verified": true, "hostname": self.present_record(verified)? }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id.clone())),
                "iam:hostnames:update",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `hostnames/setPrimary`: makes a verified hostname the organization's canonical address (sign-in URLs and
    /// email links use it), or with `hostnameId: null` goes back to the subdomain. Requires iam:hostnames:update.
    pub async fn set_primary(
        &self,
        credential: &CredentialInput,
        input: Body<hostnames::SetPrimaryInput>,
    ) -> IamResult<Reply<hostnames::SetPrimaryOutput>> {
        let ctx = &self.ctx;
        self.enabled()?;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let hostname_id = match input.get("hostnameId") {
            Some(Value::Null) => None,
            value => Some(text(value, "hostnameId", 256)?),
        };
        let resource_id = match &hostname_id {
            None => "hostnames/*".to_owned(),
            Some(hostname_id) => self.claim_resource(&tenant_id, hostname_id).await?,
        };
        let (tenant_ref, hostname_ref, resource_ref) = (&tenant_id, &hostname_id, &resource_id);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let target = match hostname_ref {
                    None => None,
                    Some(hostname_id) => Some(
                        self.authorized_claim(&tx, tenant_ref, hostname_id, resource_ref)
                            .await?
                            .1,
                    ),
                };
                if let Some(target) = &target
                    && target.status != "verified"
                {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "Verify the hostname before making it primary",
                    )
                    .into());
                }
                let records = tx
                    .find(
                        "tenantHostnames",
                        &Filter::new().eq("tenantId", tenant_ref.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                for mut record in records {
                    let primary = target.as_ref().is_some_and(|target| {
                        record.get("id").and_then(Value::as_str) == Some(target.id.as_str())
                    });
                    let was_primary = record.get("primary") == Some(&Value::Bool(true));
                    if was_primary == primary {
                        continue;
                    }
                    record.shift_remove("primary");
                    if primary {
                        record.insert("primary".into(), Value::Bool(true));
                    }
                    tx.put("tenantHostnames", &record).await?;
                }
                let realm = tx.get("tenants", tenant_ref).await?;
                let sign_in_url = match realm {
                    Some(realm) => {
                        let realm: Tenant = decode(realm)?;
                        ctx.hosts()?.sign_in_url_of(&realm, Some(&tx)).await?
                    }
                    None => None,
                };
                let mut out = Map::new();
                out.insert(
                    "primary".into(),
                    match target {
                        Some(mut target) => {
                            target.primary = Some(true);
                            target.status = "verified".into();
                            self.present(&target)
                        }
                        None => Value::Null,
                    },
                );
                out.insert(
                    "signInUrl".into(),
                    sign_in_url.map(Value::String).unwrap_or(Value::Null),
                );
                Ok(Value::Object(out))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id.clone())),
                "iam:hostnames:update",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `hostnames/delete`: releases a hostname; a verified one stops resolving to the organization at once.
    /// Requires iam:hostnames:delete.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<hostnames::DeleteInput>,
    ) -> IamResult<Reply<hostnames::DeleteOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let hostname_id = text(input.get("hostnameId"), "hostnameId", 256)?;
        let resource_id = self.claim_resource(&tenant_id, &hostname_id).await?;
        let (tenant_ref, hostname_ref, resource_ref) = (&tenant_id, &hostname_id, &resource_id);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let (_, current) = self
                    .authorized_claim(&tx, tenant_ref, hostname_ref, resource_ref)
                    .await?;
                let owner = tx.get("hostnameOwners", &current.hostname).await?;
                if owner
                    .as_ref()
                    .and_then(|owner| owner.get("tenantId"))
                    .and_then(Value::as_str)
                    == Some(tenant_ref.as_str())
                {
                    tx.delete("hostnameOwners", &current.hostname).await?;
                }
                tx.delete("tenantHostnames", &current.id).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id.clone())),
                "iam:hostnames:delete",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}
