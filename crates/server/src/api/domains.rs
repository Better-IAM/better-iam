//! Port of `packages/server/src/api/domains.ts`: verified email domains and home-realm discovery. An organization
//! claims a domain, publishes the TXT record it is given, and verifies it; a verified domain is owned by exactly one
//! tenant, and `discover` maps an email address to that tenant (and its sign-in requirements) so login screens need
//! neither a tenant ID nor a slug.

use std::collections::HashSet;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamResult, IamStoreExt, Record, Tenant,
    TenantStatus, js as core_js,
};
use better_iam_types::api::domains;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::options::{AuthorizationRequest, ResolveTxtFn, ResourceTarget};
use crate::port::decode;
use crate::utils::{by_newest, id};
use crate::validation::text;

pub use crate::options::DomainOptions;

/// `consumerDomains`: widely used consumer mailbox providers, which no organization may claim by default.
const CONSUMER_DOMAINS: [&str; 25] = [
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "ymail.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "gmx.com",
    "gmx.net",
    "mail.com",
    "yandex.com",
    "yandex.ru",
    "zoho.com",
    "fastmail.com",
    "hey.com",
    "qq.com",
    "163.com",
];

/// The default label under the domain that holds the TXT record.
pub(crate) const DEFAULT_RECORD_NAME: &str = "_better-iam-challenge";

/// A domain an organization claims; it becomes discoverable once a DNS TXT record proves control.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantDomain {
    #[serde(rename = "domain")]
    pub domain: String,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "verificationToken")]
    pub verification_token: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(
        rename = "verifiedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub verified_at: Option<f64>,
    #[serde(
        rename = "lastCheckedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_checked_at: Option<f64>,
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

/// `DomainOwner`: global ownership record (id = the domain), so one domain is verified by at most one tenant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DomainOwner {
    id: String,
    tenant_id: String,
    domain_id: String,
    verified_at: f64,
}

/// `label`: `/^(?!-)[a-z0-9-]{1,63}(?<!-)$/`.
fn is_label(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= 63
        && part
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !part.starts_with('-')
        && !part.ends_with('-')
}

/// `/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/`: an alphabetic or punycode top-level label.
fn is_top_level(part: &str) -> bool {
    let alphabetic = (2..=63).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_lowercase());
    let punycode = part.strip_prefix("xn--").is_some_and(|rest| {
        (1..=59).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    alphabetic || punycode
}

/// Normalizes and validates a registrable-looking DNS name: lowercase, no trailing dot, alphabetic TLD.
pub fn domain_name(value: Option<&Value>) -> IamResult<String> {
    let validated = text(value, "domain", 253)?;
    let lowered = core_js::to_lower(core_js::trim(&validated));
    let domain = lowered.strip_suffix('.').unwrap_or(&lowered).to_owned();
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2
        || core_js::utf16_len(&domain) > 253
        || !labels.iter().all(|part| is_label(part))
        || !is_top_level(labels.last().copied().unwrap_or(""))
    {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Enter a domain such as example.com",
        ));
    }
    Ok(domain)
}

/// The decision `operation` makes (`action` on `iam/{resourceId}`), taken ahead of work that must happen outside
/// its transaction, such as a DNS query, so that work is done only for a caller the operation will admit. A refusal
/// is not recorded here: the operation that follows refuses the caller again and records it.
pub async fn permitted_ahead(
    ctx: &Arc<ServerContext>,
    credential: &better_iam_core::CredentialInput,
    tenant_id: &str,
    action: &str,
    resource_id: &str,
) -> IamResult<bool> {
    let authenticated = ctx.principals()?.authenticate(credential).await?;
    ctx.store
        .transaction(|tx| {
            let authenticated = &authenticated;
            async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated)
                    .await?;
                let decision = ctx
                    .decisions()?
                    .decide(
                        &tx,
                        &principal,
                        &AuthorizationRequest {
                            credential: CredentialInput::default(),
                            tenant_id: tenant_id.to_owned(),
                            action: action.to_owned(),
                            resource: ResourceTarget {
                                kind: "iam".into(),
                                id: resource_id.to_owned(),
                            },
                        },
                        true,
                    )
                    .await?;
                Ok(decision.allowed)
            }
        })
        .await
}

/// `settings.recordName ?? '_better-iam-challenge'`.
pub(crate) fn record_name(ctx: &ServerContext) -> String {
    ctx.options
        .domains
        .as_ref()
        .and_then(|settings| settings.record_name.clone())
        .unwrap_or_else(|| DEFAULT_RECORD_NAME.to_owned())
}

/// `settings.resolveTxt ?? resolveTxt`: the injected TXT lookup, or the system resolver.
pub(crate) fn txt_lookup(ctx: &ServerContext) -> ResolveTxtFn {
    match ctx
        .options
        .domains
        .as_ref()
        .and_then(|settings| settings.resolve_txt.clone())
    {
        Some(lookup) => lookup,
        None => Arc::new(|hostname| Box::pin(system_resolve_txt(hostname))),
    }
}

/// `resolveTxt` of `node:dns/promises`: the TXT records of a name as their character-strings (read as Latin-1, as
/// Node decodes them), through the system's resolver configuration.
async fn system_resolve_txt(hostname: String) -> IamResult<Vec<Vec<String>>> {
    let failed = |_| IamError::new("DNS_LOOKUP_FAILED", "TXT lookup failed");
    let resolver = hickory_resolver::TokioResolver::builder_tokio()
        .map_err(failed)?
        .build();
    let lookup = resolver.txt_lookup(hostname).await.map_err(failed)?;
    Ok(lookup
        .iter()
        .map(|txt| {
            txt.txt_data()
                .iter()
                .map(|chunk| chunk.iter().map(|byte| char::from(*byte)).collect())
                .collect()
        })
        .collect())
}

/// `answers.some((chunks) => chunks.join('').trim() === expected)`; a failed lookup finds nothing.
pub(crate) async fn txt_matches(lookup: &ResolveTxtFn, name: &str, expected: &str) -> bool {
    match lookup(name.to_owned()).await {
        Ok(answers) => answers
            .iter()
            .any(|chunks| core_js::trim(&chunks.concat()) == expected),
        Err(_) => false,
    }
}

/// `randomBytes(18).toString('base64url')`.
pub(crate) fn verification_token() -> String {
    URL_SAFE_NO_PAD.encode(better_iam_auth::crypto::random_bytes(18))
}

/// The `domains` API group (`createDomainsApi(ctx)`): one method per route `domains/{method}`.
pub struct DomainsApi {
    ctx: Arc<ServerContext>,
    record_name: String,
    blocked: HashSet<String>,
    lookup: ResolveTxtFn,
}

/// `createDomainsApi(ctx)`.
pub fn create_domains_api(ctx: &Arc<ServerContext>) -> IamResult<DomainsApi> {
    let settings = ctx.options.domains.clone().unwrap_or_default();
    let record_name = record_name(ctx);
    if record_name.is_empty()
        || record_name.len() > 63
        || !record_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(IamError::new(
            "INVALID_CONFIG",
            "domains.recordName must be a single DNS label",
        ));
    }
    let blocked = match &settings.blocked_domains {
        Some(list) => list
            .iter()
            .map(|domain| core_js::to_lower(domain))
            .collect(),
        None => CONSUMER_DOMAINS
            .iter()
            .map(|domain| (*domain).to_owned())
            .collect(),
    };
    Ok(DomainsApi {
        ctx: ctx.clone(),
        record_name,
        blocked,
        lookup: txt_lookup(ctx),
    })
}

impl DomainsApi {
    /// `instructions(record)`: the TXT record that proves control.
    fn instructions(&self, record: &TenantDomain) -> (String, String) {
        (
            format!("{}.{}", self.record_name, record.domain),
            format!("better-iam-verification={}", record.verification_token),
        )
    }

    /// `present(record)`.
    fn present(&self, record: &TenantDomain) -> Value {
        let (name, value) = self.instructions(record);
        let mut out = Map::new();
        out.insert("id".into(), Value::String(record.id.clone()));
        out.insert("tenantId".into(), Value::String(record.tenant_id.clone()));
        out.insert("domain".into(), Value::String(record.domain.clone()));
        out.insert("status".into(), Value::String(record.status.clone()));
        out.insert("createdAt".into(), crate::js::number(record.created_at));
        out.insert("createdBy".into(), Value::String(record.created_by.clone()));
        if let Some(verified_at) = record.verified_at {
            out.insert("verifiedAt".into(), crate::js::number(verified_at));
        }
        if let Some(checked) = record.last_checked_at {
            out.insert("lastCheckedAt".into(), crate::js::number(checked));
        }
        out.insert(
            "dnsRecord".into(),
            json!({ "type": "TXT", "name": name, "value": value }),
        );
        Value::Object(out)
    }

    /// `present` of a stored record.
    fn present_record(&self, record: Record) -> IamResult<Value> {
        Ok(self.present(&decode(record)?))
    }

    /// Actions on a claim are authorized on `domains/{domain}`, so a grant can name the domain. The claim is read
    /// ahead only to pick that resource: an ID that is not one of this tenant's claims is authorized as
    /// `domains/{id}` and reported missing inside the operation, after authorization, so a caller it refuses cannot
    /// tell whether it exists.
    async fn claim_resource(&self, tenant_id: &str, domain_id: &str) -> IamResult<String> {
        let record = self.ctx.store.get("tenantDomains", domain_id).await?;
        Ok(match record {
            Some(record) if record.get("tenantId").and_then(Value::as_str) == Some(tenant_id) => {
                format!("domains/{}", string_member(&record, "domain"))
            }
            _ => format!("domains/{domain_id}"),
        })
    }

    /// The claim inside an operation: this tenant's, and the one its authorized resource names.
    async fn authorized_claim(
        &self,
        tx: &Store,
        tenant_id: &str,
        domain_id: &str,
        resource_id: &str,
    ) -> IamResult<(Record, TenantDomain)> {
        let raw = self
            .ctx
            .scoped(
                tx,
                "tenantDomains",
                Some(&Value::String(domain_id.to_owned())),
                tenant_id,
            )
            .await?;
        let record: TenantDomain = decode(raw.clone())?;
        if format!("domains/{}", record.domain) != resource_id {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "Resource not found",
                404,
            ));
        }
        Ok((raw, record))
    }

    /// `domains/add`: claims a domain for the tenant and returns the TXT record to publish. Requires
    /// iam:domains:create.
    pub async fn add(
        &self,
        credential: &CredentialInput,
        input: Body<domains::AddInput>,
    ) -> IamResult<Reply<domains::AddOutput>> {
        let ctx = &self.ctx;
        let domain = domain_name(input.get("domain"))?;
        let resource_id = format!("domains/{domain}");
        let domain = &domain;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    if self.blocked.contains(domain) {
                        return Err(IamError::new(
                            "DOMAIN_NOT_ALLOWED",
                            "Shared mailbox providers cannot be claimed by an organization",
                        )
                        .into());
                    }
                    let claimed = tx
                        .find(
                            "tenantDomains",
                            &Filter::new()
                                .eq("tenantId", tenant.id.clone())
                                .eq("domain", domain.clone()),
                            &FindOptions::default(),
                        )
                        .await?;
                    if !claimed.is_empty() {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "This organization already claimed the domain",
                            409,
                        )
                        .into());
                    }
                    let owner = tx.get("domainOwners", domain).await?;
                    if let Some(owner) = owner {
                        let owner: DomainOwner = decode(owner)?;
                        if owner.tenant_id != tenant.id {
                            return Err(IamError::with_status(
                                "DOMAIN_TAKEN",
                                "Another organization verified this domain",
                                409,
                            )
                            .into());
                        }
                    }
                    let mut record = Record::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    record.insert("uniqueKey".into(), Value::String(domain.clone()));
                    record.insert("domain".into(), Value::String(domain.clone()));
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
                    let record = tx.insert("tenantDomains", &record).await?;
                    Ok(self.present_record(record)?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:domains:create",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `domains/list`: the tenant's claimed domains with their verification records.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<domains::ListInput>,
    ) -> IamResult<Reply<domains::ListOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut records: Vec<TenantDomain> = Vec::new();
                for record in tx
                    .find(
                        "tenantDomains",
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
                "iam:domains:read",
                "domains/*",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `domains/verify`: looks up the TXT record and, when it matches, marks the domain verified. DNS is queried
    /// before the transaction opens, and only for a caller allowed to verify the claim; the result reports
    /// `verified: false` (and the expected record) while it is not yet visible.
    pub async fn verify(
        &self,
        credential: &CredentialInput,
        input: Body<domains::VerifyInput>,
    ) -> IamResult<Reply<domains::VerifyOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let domain_id = text(input.get("domainId"), "domainId", 256)?;
        let resource_id = self.claim_resource(&tenant_id, &domain_id).await?;
        let mut found = false;
        if permitted_ahead(
            ctx,
            credential,
            &tenant_id,
            "iam:domains:update",
            &resource_id,
        )
        .await?
        {
            let claimed = ctx.store.get("tenantDomains", &domain_id).await?;
            if let Some(claimed) = claimed {
                let claimed: TenantDomain = decode(claimed)?;
                if claimed.tenant_id == tenant_id && claimed.status != "verified" {
                    let (name, value) = self.instructions(&claimed);
                    found = txt_matches(&self.lookup, &name, &value).await;
                }
            }
        }
        let (tenant_ref, domain_ref, resource_ref) = (&tenant_id, &domain_id, &resource_id);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let (raw, record) = self
                    .authorized_claim(&tx, tenant_ref, domain_ref, resource_ref)
                    .await?;
                if record.status == "verified" {
                    return Ok(json!({ "verified": true, "domain": self.present(&record) }));
                }
                let now = ctx.now();
                if !found {
                    let mut checked = raw;
                    checked.insert("lastCheckedAt".into(), crate::js::number(now));
                    let checked = tx.put("tenantDomains", &checked).await?;
                    return Ok(
                        json!({ "verified": false, "domain": self.present_record(checked)? }),
                    );
                }
                let owner = tx.get("domainOwners", &record.domain).await?;
                let owner: Option<DomainOwner> = owner.map(decode).transpose()?;
                if let Some(owner) = &owner
                    && &owner.tenant_id != tenant_ref
                {
                    return Err(IamError::with_status(
                        "DOMAIN_TAKEN",
                        "Another organization verified this domain",
                        409,
                    )
                    .into());
                }
                if owner.is_none() {
                    let mut claim = Record::new();
                    claim.insert("id".into(), Value::String(record.domain.clone()));
                    claim.insert("tenantId".into(), Value::String(tenant_ref.clone()));
                    claim.insert("domainId".into(), Value::String(record.id.clone()));
                    claim.insert("verifiedAt".into(), crate::js::number(now));
                    tx.insert("domainOwners", &claim).await?;
                }
                let mut verified = raw;
                verified.insert("status".into(), Value::String("verified".into()));
                verified.insert("verifiedAt".into(), crate::js::number(now));
                verified.insert("lastCheckedAt".into(), crate::js::number(now));
                let verified = tx.put("tenantDomains", &verified).await?;
                Ok(json!({ "verified": true, "domain": self.present_record(verified)? }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id.clone())),
                "iam:domains:update",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `domains/delete`: releases a claim; a verified domain stops resolving to the tenant immediately. Requires
    /// iam:domains:delete.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<domains::DeleteInput>,
    ) -> IamResult<Reply<domains::DeleteOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let domain_id = text(input.get("domainId"), "domainId", 256)?;
        let resource_id = self.claim_resource(&tenant_id, &domain_id).await?;
        let (tenant_ref, domain_ref, resource_ref) = (&tenant_id, &domain_id, &resource_id);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let (_, record) = self
                    .authorized_claim(&tx, tenant_ref, domain_ref, resource_ref)
                    .await?;
                let owner = tx.get("domainOwners", &record.domain).await?;
                if owner
                    .as_ref()
                    .and_then(|owner| owner.get("tenantId"))
                    .and_then(Value::as_str)
                    == Some(tenant_ref.as_str())
                {
                    tx.delete("domainOwners", &record.domain).await?;
                }
                tx.delete("tenantDomains", &record.id).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id.clone())),
                "iam:domains:delete",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `domains/discover` (public: no credential): the active tenant that verified the email's domain, with its
    /// sign-in requirements. Unknown, unverified, and inactive domains are indistinguishable (404).
    pub async fn discover(
        &self,
        input: Body<domains::DiscoverInput>,
    ) -> IamResult<Reply<domains::DiscoverOutput>> {
        let ctx = &self.ctx;
        let email = input.get("email");
        let raw = match email {
            Some(email) => {
                let email = text(Some(email), "email", 320)?;
                let trimmed = core_js::trim(&email);
                Some(Value::String(
                    trimmed.rsplit('@').next().unwrap_or("").to_owned(),
                ))
            }
            None => input.get("domain").cloned(),
        };
        if let Some(Value::String(email)) = email
            && !email.contains('@')
        {
            return Err(IamError::new("INVALID_INPUT", "Enter an email address"));
        }
        let domain = domain_name(raw.as_ref())?;
        let result = ctx
            .store
            .transaction(|tx| {
                let domain = &domain;
                async move {
                    let not_found = || {
                        IamError::with_status("NOT_FOUND", "No organization uses this domain", 404)
                    };
                    let owner = tx.get("domainOwners", domain).await?;
                    let realm = match &owner {
                        Some(owner) => tx.get("tenants", &string_member(owner, "tenantId")).await?,
                        None => None,
                    };
                    let Some(raw_realm) = realm else {
                        return Err(not_found());
                    };
                    let realm: Tenant = decode(raw_realm.clone())?;
                    if realm.status != TenantStatus::Active {
                        return Err(not_found());
                    }
                    if ctx
                        .ancestry(&tx, &realm)
                        .await?
                        .iter()
                        .any(|item| item.status != TenantStatus::Active)
                    {
                        return Err(not_found());
                    }
                    // In a multi-region deployment, people of an organization homed elsewhere are sent to its
                    // region.
                    let hosts = ctx.hosts()?;
                    hosts.assert_served_here(&tx, &realm, None).await?;
                    let region = hosts.region_of(&tx, &realm).await?;
                    let sign_in_url = hosts.sign_in_url_of(&realm, Some(&tx)).await?;
                    let mut out = Map::new();
                    out.insert("domain".into(), Value::String(domain.clone()));
                    out.insert("tenantId".into(), Value::String(realm.id.clone()));
                    out.insert(
                        "name".into(),
                        raw_realm.get("name").cloned().unwrap_or(Value::Null),
                    );
                    out.insert(
                        "type".into(),
                        raw_realm.get("type").cloned().unwrap_or(Value::Null),
                    );
                    if let Some(slug) = realm.slug.as_ref().filter(|slug| !slug.is_empty()) {
                        out.insert("slug".into(), Value::String(slug.clone()));
                    }
                    let policy = raw_realm.get("authPolicy");
                    out.insert(
                        "allowedMethods".into(),
                        match policy.and_then(|policy| policy.get("allowedMethods")) {
                            None | Some(Value::Null) => Value::Null,
                            Some(methods) => methods.clone(),
                        },
                    );
                    out.insert(
                        "requireMfa".into(),
                        Value::Bool(
                            policy.and_then(|policy| policy.get("requireMfa"))
                                == Some(&Value::Bool(true)),
                        ),
                    );
                    if let Some(region) = region.filter(|region| !region.is_empty()) {
                        out.insert("region".into(), Value::String(region));
                    }
                    if let Some(url) = sign_in_url.filter(|url| !url.is_empty()) {
                        out.insert("signInUrl".into(), Value::String(url));
                    }
                    Ok(Value::Object(out))
                }
            })
            .await?;
        Ok(Reply::json(result))
    }
}
