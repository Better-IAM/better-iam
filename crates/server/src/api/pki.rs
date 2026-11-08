//! Port of `packages/server/src/api/pki.ts`: the `pki` API group (the private certificate authority of pki.rs) and
//! the server-side runtime `iam.pki` (public CRLs, trust bundles, chain verification for mutual TLS).
//!
//! Authorities are `iam/pki/{authorityId}`; issuing decides `iam:pki:issue` once for every name on the certificate
//! (the common name and each subject alternative name), with `resource.name` and `resource.nameType` (`commonName`,
//! `dns`, `wildcard`, `uri`, `ip`, `email`) plus the authority's attributes and `resource.usage`,
//! `resource.validitySeconds` and `resource.keyType`, so policies can say which names a caller may certify. Workload
//! certificates (`requestCertificate`) name the caller's own identity as a SPIFFE ID and need `iam:pki:request`.
//! Signing keys are KMS keys, pinned to one version per authority.

use std::sync::Arc;

use better_iam_core::js as core_js;
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError, IamResult, IamStoreExt,
    Record,
};
use better_iam_types::api::pki;
use bytes::Bytes;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::OperationDenied;
use crate::guarded::{Guard, GuardAction, GuardOptions, GuardTarget, Target, create_guard};
use crate::js::{internal_error, js_string, number};
use crate::kms::{
    KmsServiceUse, acts_in_own_right, alias_names, assert_unmanaged, assert_usable,
    create_service_key, find_key, key_attributes, key_spec as parse_key_spec, key_version,
    kms_actions, kms_sign_for,
};
use crate::options::HttpResponse;
use crate::pki::{
    CurrentCrl, MAX_AUTHORITIES_PER_TENANT, MAX_LEAF_VALIDITY_SECONDS, PkiAuthority,
    PkiCertificate, actions, algorithm_for_spec, assert_authority_usable, authority_attributes,
    authority_chain, authority_signer, base64_text, certificate_pem, crl_pem, current_crl,
    distinguished_name, find_authority, http_url, names_permitted, permitted_names, spki_of,
    summarize_authority, summarize_certificate, trust_domain as parse_trust_domain,
    verify_certificate_chain,
};
use crate::utils::id;
use crate::validation::{integer, text};
use crate::x509::{
    CaSpec, CertificateSpec, DistinguishedName, ParsedCertificateRequest, SubjectAltNames,
    X509Certificate, encode_name, key_identifier, node_base64, node_hex, parse_certificate_request,
    random_serial, revocation_reason_code, sha256_fingerprint, signed_structure, subject_alt_names,
    tbs_certificate,
};

const DAY_MS: f64 = 86_400_000.0;
const CLOCK_SKEW_MS: f64 = 60_000.0;

/// One name on a certificate, decided on its own.
#[derive(Debug, Clone, PartialEq)]
struct NameEntry {
    name_type: String,
    name: String,
}

/// `PkiTarget`: a guard target that carries the authority it names, and what locating it learned (the parsed
/// request and the names a certificate will carry, or the certificate a call is about).
#[derive(Debug, Clone, Default)]
struct PkiTarget {
    resource_id: String,
    attributes: Map<String, Value>,
    authority: Option<PkiAuthority>,
    request: Option<ParsedCertificateRequest>,
    names: Option<SubjectAltNames>,
    common_name: Option<String>,
    entries: Vec<NameEntry>,
    spiffe_id: String,
    validity_seconds: f64,
    certificate: Option<PkiCertificate>,
}

impl GuardTarget for PkiTarget {
    fn resource_id(&self) -> &str {
        &self.resource_id
    }
    fn attributes(&self) -> &Map<String, Value> {
        &self.attributes
    }
}

impl PkiTarget {
    fn authority(&self) -> IamResult<&PkiAuthority> {
        self.authority.as_ref().ok_or_else(internal_error)
    }
}

/// What `issue` returns (`IssuedCertificate`).
#[derive(Debug, Clone, PartialEq)]
struct IssuedCertificate {
    id: String,
    serial_number: String,
    certificate_pem: String,
    /// The issuing authority and those above it, below the root, leaf's issuer first.
    chain_pem: String,
    /// The root certificate to trust.
    root_pem: String,
    not_before: f64,
    not_after: f64,
    fingerprint: String,
    spiffe_id: Option<String>,
}

impl IssuedCertificate {
    fn to_value(&self) -> Value {
        let mut out = Map::new();
        out.insert("id".into(), json!(self.id));
        out.insert("serialNumber".into(), json!(self.serial_number));
        out.insert("certificatePem".into(), json!(self.certificate_pem));
        out.insert("chainPem".into(), json!(self.chain_pem));
        out.insert("rootPem".into(), json!(self.root_pem));
        out.insert("notBefore".into(), number(self.not_before));
        out.insert("notAfter".into(), number(self.not_after));
        out.insert("fingerprint".into(), json!(self.fingerprint));
        if let Some(spiffe_id) = &self.spiffe_id {
            out.insert("spiffeId".into(), json!(spiffe_id));
        }
        Value::Object(out)
    }
}

/// What `issue` signs.
struct IssueRequest {
    spki: Vec<u8>,
    key_type: String,
    common_name: Option<String>,
    names: SubjectAltNames,
    usage: String,
    validity_seconds: f64,
    identity_id: Option<String>,
    spiffe_id: Option<String>,
    /// The latest the certificate may be valid until (the credential or identity it stands for ends then).
    not_after_cap: Option<f64>,
    issued_by: String,
    principal: AuthenticatedPrincipal,
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn value_of<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// `value ?? fallback` for an optional JSON member.
fn or_default(value: Option<&Value>, fallback: Value) -> Value {
    match value {
        None | Some(Value::Null) => fallback,
        Some(value) => value.clone(),
    }
}

fn validity_days(value: Option<&Value>, fallback: f64, max: f64) -> IamResult<f64> {
    match value {
        None => Ok(fallback),
        Some(value) => integer(Some(value), "validityDays", 1.0, max),
    }
}

/// The names a certificate carries, each decided on its own. A wildcard DNS name (`*.internal`) is its own name
/// type, never `dns`: it covers hosts a policy may deny one by one, so policies allow wildcard certificates
/// explicitly.
fn name_entries(common_name: Option<&str>, names: &SubjectAltNames) -> Vec<NameEntry> {
    let mut entries = Vec::new();
    let entry = |name_type: &str, name: &str| NameEntry {
        name_type: name_type.to_owned(),
        name: name.to_owned(),
    };
    if let Some(common_name) = common_name.filter(|name| !name.is_empty()) {
        entries.push(entry("commonName", common_name));
    }
    for name in &names.dns_names {
        entries.push(entry(
            if name.starts_with("*.") {
                "wildcard"
            } else {
                "dns"
            },
            name,
        ));
    }
    entries.extend(names.uris.iter().map(|name| entry("uri", name)));
    entries.extend(names.ip_addresses.iter().map(|name| entry("ip", name)));
    entries.extend(names.emails.iter().map(|name| entry("email", name)));
    entries
}

fn usage_of(value: Option<&Value>) -> IamResult<String> {
    match value {
        None => Ok("both".into()),
        Some(Value::String(usage)) if ["server", "client", "both"].contains(&usage.as_str()) => {
            Ok(usage.clone())
        }
        Some(_) => Err(invalid("usage must be server, client or both")),
    }
}

/// `authorityTarget(tenantId, authorityId)(tx)`.
async fn authority_target(
    tx: &Store,
    tenant_id: Option<&Value>,
    authority_id: Option<&Value>,
) -> IamResult<PkiTarget> {
    let tenant_id = text(tenant_id, "tenantId", 256)?;
    let authority = find_authority(tx, &tenant_id, authority_id).await?;
    Ok(PkiTarget {
        resource_id: format!("pki/{}", authority.id),
        attributes: authority_attributes(&authority),
        authority: Some(authority),
        ..PkiTarget::default()
    })
}

fn leaf_validity(authority: &PkiAuthority, value: Option<&Value>) -> IamResult<f64> {
    match value {
        None => Ok(authority.default_validity_seconds),
        Some(value) => integer(
            Some(value),
            "validitySeconds",
            60.0,
            authority.max_validity_seconds,
        ),
    }
}

/// SPIFFE SVID rules: one URI per certificate, only in the authority's trust domain, and never in the paths
/// `/user/`, `/service/` and `/agent/`, which name identities and are issued only to those identities themselves
/// (`requestCertificate`).
fn spiffe_rules(authority: &PkiAuthority, names: &SubjectAltNames) -> IamResult<()> {
    let spiffe: Vec<&String> = names
        .uris
        .iter()
        .filter(|uri| core_js::to_lower(uri).starts_with("spiffe://"))
        .collect();
    let Some(first) = spiffe.first() else {
        return Ok(());
    };
    if names.uris.len() != 1 {
        return Err(invalid("A SPIFFE certificate carries exactly one URI"));
    }
    let parts: Vec<&str> = first.split('/').collect();
    let host = parts.get(2).copied().unwrap_or("");
    let segment = parts.get(3).copied().unwrap_or("");
    let domain = authority.trust_domain.as_deref().filter(|d| !d.is_empty());
    if domain != Some(host) {
        return Err(IamError::with_status(
            "NAME_NOT_PERMITTED",
            format!(
                "This authority issues SPIFFE IDs only in {}",
                authority
                    .trust_domain
                    .as_deref()
                    .unwrap_or("no trust domain")
            ),
            403,
        ));
    }
    if ["user", "service", "agent"].contains(&segment) {
        return Err(IamError::with_status(
            "NAME_NOT_PERMITTED",
            format!(
                "spiffe://{host}/{segment}/… names an identity; it is issued only to that identity (requestCertificate)"
            ),
            403,
        ));
    }
    Ok(())
}

/// `{ ...authorityAttributes(authority), usage, validitySeconds, keyType }`.
fn issue_base(
    authority: &PkiAuthority,
    usage: &str,
    validity_seconds: f64,
    key_type: &str,
) -> Map<String, Value> {
    let mut attributes = authority_attributes(authority);
    attributes.insert("usage".into(), json!(usage));
    attributes.insert("validitySeconds".into(), number(validity_seconds));
    attributes.insert("keyType".into(), json!(key_type));
    attributes
}

fn with_entry(mut attributes: Map<String, Value>, entry: &NameEntry) -> Map<String, Value> {
    attributes.insert("nameType".into(), json!(entry.name_type));
    attributes.insert("name".into(), json!(entry.name));
    attributes
}

/// `identity.kind` as its JSON name.
fn kind_name(principal: &AuthenticatedPrincipal) -> String {
    js_string(Some(&value_of(&principal.identity.kind)))
}

/// Sorts records by `createdAt` ascending, then id (`a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1)`).
fn by_created(a: &PkiAuthority, b: &PkiAuthority) -> std::cmp::Ordering {
    let difference = a.created_at - b.created_at;
    if difference != 0.0 && !difference.is_nan() {
        return difference
            .partial_cmp(&0.0)
            .unwrap_or(std::cmp::Ordering::Equal);
    }
    if core_js::cmp_utf16(&a.id, &b.id).is_lt() {
        std::cmp::Ordering::Less
    } else {
        std::cmp::Ordering::Greater
    }
}

/// Signs a leaf certificate for `spki` with `names` under an authority whose chain is usable.
async fn issue(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    authority: &PkiAuthority,
    request: IssueRequest,
) -> IamResult<IssuedCertificate> {
    let now = ctx.now();
    let chain = authority_chain(tx, authority).await?;
    assert_authority_usable(&chain, now)?;
    if !names_permitted(&chain, &request.names, request.common_name.as_deref())? {
        return Err(IamError::with_status(
            "NAME_NOT_PERMITTED",
            "A requested name is outside the authority's name constraints",
            403,
        ));
    }
    let not_after = (now + request.validity_seconds * 1000.0)
        .min(authority.not_after)
        .min(request.not_after_cap.unwrap_or(f64::INFINITY));
    if not_after <= now + 60_000.0 {
        return Err(invalid("The certificate would expire within a minute"));
    }
    let serial_number = random_serial();
    let common_name = request.common_name.clone().filter(|name| !name.is_empty());
    let tbs = tbs_certificate(
        &CertificateSpec {
            serial_number: serial_number.clone(),
            issuer: node_base64(&authority.subject_der),
            subject: match &common_name {
                Some(name) => DistinguishedName::common(name),
                None => DistinguishedName::default(),
            },
            spki: request.spki.clone(),
            not_before: now - CLOCK_SKEW_MS,
            not_after,
            names: Some(request.names.clone()),
            ca: None,
            usage: Some(request.usage.clone()),
            authority_key_id: Some(node_hex(&authority.subject_key_id)),
            crl_url: authority.crl_url.clone().filter(|url| !url.is_empty()),
            permitted: None,
        },
        &authority.algorithm,
    )?;
    let signature = authority_signer(ctx, tx, authority)
        .sign(&tbs, Some(&request.principal))
        .await?;
    let der = signed_structure(&tbs, &authority.algorithm, &signature);
    let pem_text = certificate_pem(&der);
    let fingerprint = sha256_fingerprint(&der);
    let record_id = id();
    let mut record = Record::new();
    record.insert("id".into(), json!(record_id));
    record.insert("tenantId".into(), json!(authority.tenant_id));
    record.insert("uniqueKey".into(), json!(format!("serial:{serial_number}")));
    record.insert("authorityId".into(), json!(authority.id));
    record.insert("serialNumber".into(), json!(serial_number));
    record.insert("names".into(), request.names.to_value());
    record.insert("keyType".into(), json!(request.key_type));
    record.insert("usage".into(), json!(request.usage));
    record.insert("notBefore".into(), number(now - CLOCK_SKEW_MS));
    record.insert("notAfter".into(), number(not_after));
    record.insert("certificatePem".into(), json!(pem_text));
    record.insert("fingerprint".into(), json!(fingerprint));
    record.insert("status".into(), json!("valid"));
    record.insert("issuedAt".into(), number(now));
    record.insert("issuedBy".into(), json!(request.issued_by));
    if let Some(name) = &common_name {
        record.insert("commonName".into(), json!(name));
    }
    if let Some(identity_id) = request.identity_id.as_deref().filter(|id| !id.is_empty()) {
        record.insert("identityId".into(), json!(identity_id));
    }
    if let Some(spiffe_id) = request.spiffe_id.as_deref().filter(|id| !id.is_empty()) {
        record.insert("spiffeId".into(), json!(spiffe_id));
    }
    tx.insert("pkiCertificates", &record).await?;
    let chain_pem: String = chain
        .iter()
        .filter(|link| link.r#type == "intermediate")
        .map(|link| link.certificate_pem.as_str())
        .collect();
    let root_pem = chain
        .last()
        .map(|link| link.certificate_pem.clone())
        .unwrap_or_default();
    Ok(IssuedCertificate {
        id: record_id,
        serial_number,
        certificate_pem: pem_text,
        chain_pem,
        root_pem,
        not_before: now - CLOCK_SKEW_MS,
        not_after,
        fingerprint,
        spiffe_id: request.spiffe_id.filter(|id| !id.is_empty()),
    })
}

/// A tenant's active, unexpired roots, oldest first.
async fn trust_anchors(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Vec<PkiAuthority>> {
    let mut anchors: Vec<PkiAuthority> = tx
        .find(
            "pkiAuthorities",
            &Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("state", "active")
                .eq("type", "root"),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .map(PkiAuthority::from_record)
        .collect::<IamResult<Vec<_>>>()?
        .into_iter()
        .filter(|authority| authority.not_after > ctx.now())
        .collect();
    anchors.sort_by(by_created);
    Ok(anchors)
}

async fn find_certificate(
    tx: &Store,
    tenant_id: Option<&Value>,
    serial_number: Option<&Value>,
) -> IamResult<PkiCertificate> {
    let serial = core_js::to_lower(&text(serial_number, "serialNumber", 64)?).replace(':', "");
    if serial.is_empty()
        || serial.len() > 40
        || !serial
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("serialNumber must be hexadecimal"));
    }
    let stripped = {
        let trimmed = serial.trim_start_matches('0');
        if trimmed.is_empty() { "0" } else { trimmed }
    };
    let tenant_id = text(tenant_id, "tenantId", 256)?;
    let found = tx
        .find(
            "pkiCertificates",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("uniqueKey", format!("serial:{stripped}")),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next();
    match found {
        Some(record) => PkiCertificate::from_record(record),
        None => Err(IamError::with_status(
            "NOT_FOUND",
            "Certificate not found",
            404,
        )),
    }
}

fn describe(target: &PkiTarget) -> Map<String, Value> {
    let mut out = Map::new();
    if let Some(authority) = &target.authority {
        out.insert("authorityId".into(), json!(authority.id));
    }
    out
}

/// The `pki` API group (`createPkiApi(ctx)`): one method per route `pki/{method}`.
pub struct PkiApi {
    ctx: Arc<ServerContext>,
    guard: Guard<PkiTarget>,
}

/// `createPkiApi(ctx)`.
pub fn create_pki_api(ctx: &Arc<ServerContext>) -> IamResult<PkiApi> {
    // Refusals after authorization are evidence too.
    let mut recorded_failures = IndexMap::new();
    for (code, reason) in [
        ("NAME_NOT_PERMITTED", "name-not-permitted"),
        ("INVALID_CSR", "invalid-csr"),
        ("INVALID_INPUT", "invalid-input"),
        ("AUTHORITY_UNAVAILABLE", "authority-unavailable"),
        ("KEY_STATE_INVALID", "key-state"),
    ] {
        recorded_failures.insert(code.to_owned(), reason.to_owned());
    }
    let guard = create_guard(
        ctx.clone(),
        "pki",
        GuardOptions {
            fallback: None,
            describe: Some(Arc::new(describe)),
            recorded_failures,
            hook_result: None,
        },
    );
    Ok(PkiApi {
        ctx: ctx.clone(),
        guard,
    })
}

impl PkiApi {
    /// `pki/bundle`: the tenant's trust anchors: every active, unexpired root certificate as one PEM bundle, which is
    /// what relying parties trust. Intermediates are never in it (many TLS stacks treat any certificate in a trust
    /// store as an anchor); servers send them in their chain (`chainPem`).
    pub async fn bundle(
        &self,
        credential: &CredentialInput,
        input: Body<pki::BundleInput>,
    ) -> IamResult<Reply<pki::BundleOutput>> {
        let ctx = self.ctx.clone();
        let authorities = self
            .guard
            .visible(
                credential,
                input.get("tenantId"),
                actions::READ,
                "pki",
                move |tx, tenant| {
                    Box::pin(async move {
                        Ok(trust_anchors(&ctx, &tx, &tenant.id)
                            .await?
                            .into_iter()
                            .map(|authority| {
                                let target = Target {
                                    resource_id: format!("pki/{}", authority.id),
                                    attributes: authority_attributes(&authority),
                                };
                                (authority, target)
                            })
                            .collect())
                    })
                },
            )
            .await?;
        let pem: String = authorities
            .iter()
            .map(|authority| authority.certificate_pem.as_str())
            .collect();
        Ok(Reply::json(json!({
            "pem": pem,
            "authorities": authorities.len(),
        })))
    }

    /// `pki/createAuthority`: creates a certificate authority: a self-signed root, or an intermediate signed by a
    /// `parentId` authority in the tenant (which needs iam:pki:update on the parent and respects its path length).
    /// The signing key is a new KMS key (`keySpec`, default `ecc-p256`) or an existing one the caller may sign with
    /// (`keyId`); its current version is pinned, so rotating the KMS key never changes the authority. Requires
    /// iam:pki:create on `iam/pki` and recent authentication.
    pub async fn create_authority(
        &self,
        credential: &CredentialInput,
        input: Body<pki::CreateAuthorityInput>,
    ) -> IamResult<Reply<pki::CreateAuthorityOutput>> {
        let name = core_js::trim(&text(input.get("name"), "name", 128)?).to_owned();
        let has_parent = input.get("parentId").is_some();
        let kind = match input.get("type") {
            None | Some(Value::Null) => {
                Value::String(if has_parent { "intermediate" } else { "root" }.into())
            }
            Some(value) => value.clone(),
        };
        let kind = match kind.as_str() {
            Some(kind @ ("root" | "intermediate")) => kind.to_owned(),
            _ => return Err(invalid("type must be root or intermediate")),
        };
        if (kind == "intermediate") != has_parent {
            return Err(invalid(
                "An intermediate authority needs a parentId; a root has none",
            ));
        }
        let subject = distinguished_name(input.get("subject"), true)?;
        let spec = match input.get("keyId") {
            None => {
                let spec =
                    parse_key_spec(Some(&or_default(input.get("keySpec"), json!("ecc-p256"))))?;
                Some(js_string(Some(&spec)))
            }
            Some(_) => None,
        };
        if let Some(spec) = &spec {
            algorithm_for_spec(spec)?;
        }
        let path_length = match input.get("pathLength") {
            None => None,
            Some(value) => Some(integer(Some(value), "pathLength", 0.0, 10.0)?),
        };
        let domain = parse_trust_domain(input.get("trustDomain"))?;
        let crl_url = http_url(input.get("crlUrl"), "crlUrl")?;
        let permitted = permitted_names(input.get("permitted"))?;
        let max_validity_seconds = match input.get("maxValiditySeconds") {
            None => 90.0 * 86_400.0,
            Some(value) => integer(
                Some(value),
                "maxValiditySeconds",
                60.0,
                MAX_LEAF_VALIDITY_SECONDS,
            )?,
        };
        let default_validity_seconds = match input.get("defaultValiditySeconds") {
            None => 86_400f64.min(max_validity_seconds),
            Some(value) => integer(
                Some(value),
                "defaultValiditySeconds",
                60.0,
                max_validity_seconds,
            )?,
        };
        let mut attributes = Map::new();
        attributes.insert("authorityType".into(), json!(kind));
        if let Some(spec) = &spec {
            attributes.insert("keySpec".into(), json!(spec));
        }
        if let Some(domain) = &domain {
            attributes.insert("trustDomain".into(), json!(domain));
        }
        let located = PkiTarget {
            resource_id: "pki".into(),
            attributes,
            ..PkiTarget::default()
        };
        let ctx = self.ctx.clone();
        let body = input.raw().clone();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(actions::CREATE.into()),
                move |_tx, _principal| Box::pin(async move { Ok(located) }),
                move |call, _target| {
                    Box::pin(async move {
                        let (tx, principal, tenant) =
                            (call.tx.clone(), call.principal.clone(), call.tenant.clone());
                        ctx.auth.require_recent(&principal)?;
                        let existing = tx
                            .find(
                                "pkiAuthorities",
                                &Filter::new().eq("tenantId", tenant.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?;
                        if existing.len() as f64 >= MAX_AUTHORITIES_PER_TENANT {
                            return Err(IamError::with_status(
                                "LIMIT_EXCEEDED",
                                "A tenant keeps at most 50 certificate authorities",
                                409,
                            )
                            .into());
                        }
                        let unique_key = format!("name:{}", core_js::to_lower(&name));
                        if !tx
                            .find(
                                "pkiAuthorities",
                                &Filter::new()
                                    .eq("tenantId", tenant.id.clone())
                                    .eq("uniqueKey", unique_key.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                            .is_empty()
                        {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                "A certificate authority with that name exists",
                                409,
                            )
                            .into());
                        }
                        // A SPIFFE trust domain names one organization's workloads: no other tenant may claim it.
                        if let Some(domain) = &domain {
                            let claimed = tx
                                .find(
                                    "pkiAuthorities",
                                    &Filter::new().eq("trustDomain", domain.clone()),
                                    &FindOptions::default(),
                                )
                                .await?
                                .iter()
                                .any(|other| {
                                    other.get("tenantId").and_then(Value::as_str)
                                        != Some(tenant.id.as_str())
                                });
                            if claimed {
                                return Err(IamError::with_status(
                                    "CONFLICT",
                                    "Another organization uses that trust domain",
                                    409,
                                )
                                .into());
                            }
                        }
                        let now = ctx.now();
                        let authority_id = id();
                        let mut parent: Option<PkiAuthority> = None;
                        let mut child_path_length = path_length;
                        if kind == "intermediate" {
                            let found = find_authority(&tx, &tenant.id, body.get("parentId")).await?;
                            let parent_chain = authority_chain(&tx, &found).await?;
                            assert_authority_usable(&parent_chain, now)?;
                            // Every authority above bounds how many authorities may sit below it: the new one is the
                            // (i+1)-th below the ancestor at index i, which leaves `pathLength - (i + 1)` levels for
                            // everything under it.
                            let mut remaining = f64::INFINITY;
                            for (index, ancestor) in parent_chain.iter().enumerate() {
                                if let Some(limit) = ancestor.path_length {
                                    remaining = remaining.min(limit - (index as f64 + 1.0));
                                }
                            }
                            if remaining < 0.0 {
                                return Err(invalid(
                                    "An authority above allows no more levels of subordinate authorities (path length)",
                                )
                                .into());
                            }
                            if let Some(path_length) = path_length
                                && path_length > remaining
                            {
                                return Err(invalid(
                                    "pathLength exceeds what the authorities above allow",
                                )
                                .into());
                            }
                            if child_path_length.is_none() && remaining != f64::INFINITY {
                                child_path_length = Some(remaining);
                            }
                            let target = Target {
                                resource_id: format!("pki/{}", found.id),
                                attributes: authority_attributes(&found),
                            };
                            if !call.allowed(actions::UPDATE, &target).await? {
                                return Err(OperationDenied::new(Some(
                                    "You may not add authorities under that parent",
                                )));
                            }
                            parent = Some(found);
                        }
                        // The signing key: a new KMS key, or an existing one the caller may sign with.
                        let key = match body.get("keyId") {
                            Some(reference) => {
                                let key = find_key(&tx, &tenant.id, Some(reference)).await?;
                                assert_usable(&key, &json!("sign"))?;
                                // One key, one authority; and a key others use cannot become a CA key without their
                                // knowing.
                                let key_json = value_of(&key);
                                assert_unmanaged(&key_json)?;
                                let algorithm =
                                    algorithm_for_spec(&js_string(Some(&key.key_spec)))?;
                                let aliases = alias_names(&tx, &key_json).await?;
                                let target = Target {
                                    resource_id: format!("kms/{}", key.id),
                                    attributes: key_attributes(
                                        &key_json,
                                        &aliases,
                                        Some(&json!({ "algorithm": algorithm })),
                                    )?,
                                };
                                let sign = js_string(kms_actions()?.get("sign"));
                                if !call.allowed(&sign, &target).await? {
                                    return Err(OperationDenied::new(Some(
                                        "You may not sign with that key",
                                    )));
                                }
                                // From now on the key signs only through this authority: raw KMS signatures could
                                // forge certificates.
                                let mut record = tx
                                    .get("kmsKeys", &key.id)
                                    .await?
                                    .unwrap_or_else(|| crate::port::encode(&key));
                                record.insert("managedBy".into(), json!("pki"));
                                record.insert("managedId".into(), json!(authority_id));
                                record.insert("updatedAt".into(), number(now));
                                tx.put("kmsKeys", &record).await?;
                                let mut key = key;
                                key.managed_by = Some("pki".into());
                                key.managed_id = Some(authority_id.clone());
                                key.updated_at = now;
                                key
                            }
                            // `Certificate authority: ${name}` and the tag value stay within their 512 and 256
                            // character limits: a name has at most 128.
                            None => {
                                create_service_key(
                                    &ctx,
                                    &tx,
                                    &json!({
                                        "tenantId": tenant.id,
                                        "keySpec": spec.clone().unwrap_or_default(),
                                        "keyUsage": "sign",
                                        "description": format!("Certificate authority: {name}"),
                                        "tags": { "pki-authority": name },
                                        "createdBy": principal.identity.id,
                                        "managedBy": "pki",
                                        "managedId": authority_id,
                                    }),
                                )
                                .await?
                            }
                        };
                        let key_json = value_of(&key);
                        let version = key_version(&tx, &key_json, key.current_version).await?;
                        let key_spec = js_string(Some(&key.key_spec));
                        let algorithm = algorithm_for_spec(&key_spec)?;
                        let spki = spki_of(version.public_key_pem.as_deref().ok_or_else(internal_error)?)?;
                        let subject_der = encode_name(&subject);
                        let subject_key_id = key_identifier(&spki)?;
                        let days = if kind == "root" {
                            validity_days(body.get("validityDays"), 3650.0, 10_950.0)?
                        } else {
                            validity_days(body.get("validityDays"), 1825.0, 10_950.0)?
                        };
                        let not_after = (now + days * DAY_MS).min(
                            parent
                                .as_ref()
                                .map(|parent| parent.not_after)
                                .unwrap_or(f64::INFINITY),
                        );
                        let serial_number = random_serial();
                        let tbs = tbs_certificate(
                            &CertificateSpec {
                                serial_number: serial_number.clone(),
                                issuer: match &parent {
                                    Some(parent) => node_base64(&parent.subject_der),
                                    None => subject_der.clone(),
                                },
                                subject: subject.clone(),
                                spki: spki.clone(),
                                not_before: now - CLOCK_SKEW_MS,
                                not_after,
                                names: None,
                                ca: Some(CaSpec {
                                    path_length: child_path_length,
                                }),
                                usage: None,
                                authority_key_id: parent
                                    .as_ref()
                                    .map(|parent| node_hex(&parent.subject_key_id)),
                                crl_url: parent
                                    .as_ref()
                                    .and_then(|parent| parent.crl_url.clone())
                                    .filter(|url| !url.is_empty()),
                                permitted: if parent.is_some() {
                                    permitted.clone()
                                } else {
                                    None
                                },
                            },
                            &algorithm,
                        )?;
                        let signature = match &parent {
                            Some(parent) => {
                                authority_signer(&ctx, &tx, parent)
                                    .sign(&tbs, Some(&principal))
                                    .await?
                            }
                            None => {
                                kms_sign_for(
                                    &ctx,
                                    &tx,
                                    &tenant.id,
                                    &key.id,
                                    version.version,
                                    &algorithm,
                                    &tbs,
                                    &KmsServiceUse {
                                        via: "pki".into(),
                                        principal: Some(principal.clone()),
                                    },
                                )
                                .await?
                            }
                        };
                        let der = signed_structure(&tbs, &algorithm, &signature);
                        let pem_text = certificate_pem(&der);
                        // The certificate reads back as a CA certificate, or the encoding is wrong: fail before
                        // storing anything.
                        match X509Certificate::from_pem(&pem_text) {
                            Some(parsed) if parsed.ca() => {}
                            Some(_) => {
                                return Err(IamError::with_status(
                                    "INTERNAL_ERROR",
                                    "The CA certificate is malformed",
                                    500,
                                )
                                .into());
                            }
                            None => return Err(internal_error().into()),
                        }
                        let mut record = Record::new();
                        record.insert("id".into(), json!(authority_id));
                        record.insert("tenantId".into(), json!(tenant.id));
                        record.insert("uniqueKey".into(), json!(unique_key));
                        record.insert("name".into(), json!(name));
                        record.insert("type".into(), json!(kind));
                        record.insert("subject".into(), value_of(&subject));
                        record.insert("subjectDer".into(), json!(base64_text(&subject_der)));
                        record.insert("subjectKeyId".into(), json!(hex::encode(&subject_key_id)));
                        record.insert("keyId".into(), json!(key.id));
                        record.insert("keyVersion".into(), number(version.version));
                        record.insert("algorithm".into(), json!(algorithm));
                        record.insert("certificatePem".into(), json!(pem_text));
                        record.insert("serialNumber".into(), json!(serial_number));
                        record.insert("notBefore".into(), number(now - CLOCK_SKEW_MS));
                        record.insert("notAfter".into(), number(not_after));
                        record.insert("state".into(), json!("active"));
                        record.insert("maxValiditySeconds".into(), number(max_validity_seconds));
                        record.insert(
                            "defaultValiditySeconds".into(),
                            number(default_validity_seconds),
                        );
                        record.insert("revision".into(), number(0.0));
                        record.insert("crlNumber".into(), number(0.0));
                        record.insert("createdAt".into(), number(now));
                        record.insert("createdBy".into(), json!(principal.identity.id));
                        record.insert("updatedAt".into(), number(now));
                        if let Some(parent) = &parent {
                            record.insert("parentId".into(), json!(parent.id));
                        }
                        if let Some(path_length) = child_path_length {
                            record.insert("pathLength".into(), number(path_length));
                        }
                        if let Some(domain) = &domain {
                            record.insert("trustDomain".into(), json!(domain));
                        }
                        if let Some(crl_url) = &crl_url {
                            record.insert("crlUrl".into(), json!(crl_url));
                        }
                        if let Some(permitted) = &permitted {
                            record.insert("permitted".into(), value_of(permitted));
                        }
                        let stored = tx.insert("pkiAuthorities", &record).await?;
                        let authority = PkiAuthority::from_record(stored)?;
                        if let Some(parent) = &parent {
                            let mut certificate = Record::new();
                            certificate.insert("id".into(), json!(id()));
                            certificate.insert("tenantId".into(), json!(tenant.id));
                            certificate.insert(
                                "uniqueKey".into(),
                                json!(format!("serial:{serial_number}")),
                            );
                            certificate.insert("authorityId".into(), json!(parent.id));
                            certificate.insert("serialNumber".into(), json!(serial_number));
                            if let Some(common_name) = &subject.common_name {
                                certificate.insert("commonName".into(), json!(common_name));
                            }
                            certificate.insert(
                                "names".into(),
                                json!({ "dnsNames": [], "uris": [], "ipAddresses": [], "emails": [] }),
                            );
                            certificate.insert("keyType".into(), json!(key_spec));
                            certificate.insert("usage".into(), json!("ca"));
                            certificate.insert("notBefore".into(), number(now - CLOCK_SKEW_MS));
                            certificate.insert("notAfter".into(), number(not_after));
                            certificate.insert("certificatePem".into(), json!(pem_text));
                            certificate
                                .insert("fingerprint".into(), json!(sha256_fingerprint(&der)));
                            certificate.insert("subordinateId".into(), json!(authority.id));
                            certificate.insert("status".into(), json!("valid"));
                            certificate.insert("issuedAt".into(), number(now));
                            certificate.insert("issuedBy".into(), json!(principal.identity.id));
                            tx.insert("pkiCertificates", &certificate).await?;
                        }
                        call.note("authorityId", json!(authority.id));
                        call.note("name", json!(name));
                        call.note("type", json!(kind));
                        call.note("keyId", json!(key.id));
                        call.note("serialNumber", json!(serial_number));
                        if let Some(parent) = &parent {
                            call.note("parentId", json!(parent.id));
                        }
                        if let Some(path_length) = child_path_length {
                            call.note("pathLength", number(path_length));
                        }
                        if let Some(domain) = &domain {
                            call.note("trustDomain", json!(domain));
                        }
                        if let Some(crl_url) = &crl_url {
                            call.note("crlUrl", json!(crl_url));
                        }
                        if let Some(permitted) = &permitted {
                            call.note("permitted", value_of(permitted));
                        }
                        Ok(value_of(&summarize_authority(&authority)))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `pki/crl`: the authority's current certificate revocation list (PEM), rebuilt after revocations and at least
    /// twice a day. CRLs are public by design: serve them to relying parties with `iam.pki.crlResponse`. Requires
    /// iam:pki:read.
    pub async fn crl(
        &self,
        credential: &CredentialInput,
        input: Body<pki::CrlInput>,
    ) -> IamResult<Reply<pki::CrlOutput>> {
        let ctx = self.ctx.clone();
        let (tenant_id, authority_id) = (
            input.get("tenantId").cloned(),
            input.get("authorityId").cloned(),
        );
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(actions::READ.into()),
                move |tx, _principal| {
                    Box::pin(async move {
                        authority_target(&tx, tenant_id.as_ref(), authority_id.as_ref()).await
                    })
                },
                move |call, target| {
                    Box::pin(async move {
                        let crl = current_crl(&ctx, &call.tx, target.authority()?).await?;
                        Ok(json!({
                            "pem": crl_pem(&crl.der),
                            "crlNumber": number(crl.crl_number),
                            "thisUpdate": number(crl.this_update),
                            "nextUpdate": number(crl.next_update),
                        }))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `pki/getAuthority`: one certificate authority. Requires iam:pki:read.
    pub async fn get_authority(
        &self,
        credential: &CredentialInput,
        input: Body<pki::GetAuthorityInput>,
    ) -> IamResult<Reply<pki::GetAuthorityOutput>> {
        let (tenant_id, authority_id) = (
            input.get("tenantId").cloned(),
            input.get("authorityId").cloned(),
        );
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(actions::READ.into()),
                move |tx, _principal| {
                    Box::pin(async move {
                        authority_target(&tx, tenant_id.as_ref(), authority_id.as_ref()).await
                    })
                },
                move |_call, target| {
                    Box::pin(async move { Ok(value_of(&summarize_authority(target.authority()?))) })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `pki/getCertificate`: one certificate by serial number (hex). Requires iam:pki:read on its authority.
    pub async fn get_certificate(
        &self,
        credential: &CredentialInput,
        input: Body<pki::GetCertificateInput>,
    ) -> IamResult<Reply<pki::GetCertificateOutput>> {
        let ctx = self.ctx.clone();
        let (tenant_id, serial_number) = (
            input.get("tenantId").cloned(),
            input.get("serialNumber").cloned(),
        );
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(actions::READ.into()),
                move |tx, _principal| {
                    Box::pin(async move {
                        let certificate =
                            find_certificate(&tx, tenant_id.as_ref(), serial_number.as_ref())
                                .await?;
                        let mut target = authority_target(
                            &tx,
                            tenant_id.as_ref(),
                            Some(&json!(certificate.authority_id)),
                        )
                        .await?;
                        target.certificate = Some(certificate);
                        Ok(target)
                    })
                },
                move |_call, target| {
                    Box::pin(async move {
                        let certificate = target.certificate.as_ref().ok_or_else(internal_error)?;
                        Ok(value_of(&summarize_certificate(certificate, ctx.now())))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `pki/issueCertificate`: issues a certificate for the key in a PEM PKCS#10 request (`csr`, which proves
    /// possession of the key). Names come from the request unless `commonName`, `dnsNames`, `uris`, `ipAddresses` or
    /// `emails` are given. Every name is decided separately (`iam:pki:issue` with `resource.name` /
    /// `resource.nameType`), and must fit the name constraints of the authority chain; a `spiffe://` URI must be the
    /// only URI and in the authority's trust domain. Validity defaults to the authority's `defaultValiditySeconds`,
    /// is capped at its `maxValiditySeconds`, and never outlasts the authority. Audited as `iam:pki:issue` with the
    /// serial number and names.
    pub async fn issue_certificate(
        &self,
        credential: &CredentialInput,
        input: Body<pki::IssueCertificateInput>,
    ) -> IamResult<Reply<pki::IssueCertificateOutput>> {
        let usage = usage_of(input.get("usage"))?;
        let ctx = self.ctx.clone();
        let body = input.raw().clone();
        let located_body = body.clone();
        let located_usage = usage.clone();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(actions::ISSUE.into()),
                move |tx, _principal| {
                    Box::pin(async move {
                        let body = located_body;
                        let mut target =
                            authority_target(&tx, body.get("tenantId"), body.get("authorityId"))
                                .await?;
                        // Parsed once the caller is known to belong to the tenant (inside the envelope), never for
                        // anonymous callers.
                        let request = parse_certificate_request(body.get("csr"))?;
                        let explicit = ["dnsNames", "uris", "ipAddresses", "emails"]
                            .iter()
                            .any(|key| body.get(*key).is_some());
                        let names = if explicit {
                            subject_alt_names(&Value::Object(body.clone()))?
                        } else {
                            request.names.clone()
                        };
                        let common_name = match body.get("commonName") {
                            Some(value) => Some(
                                core_js::trim(&text(Some(value), "commonName", 64)?).to_owned(),
                            ),
                            None => request.common_name.clone(),
                        };
                        let entries = name_entries(common_name.as_deref(), &names);
                        if entries.is_empty() {
                            return Err(invalid(
                                "A certificate needs a common name or at least one name",
                            ));
                        }
                        // With alternative names, the common name must be one of them (clients may fall back to it).
                        let alternatives: Vec<&String> = names
                            .dns_names
                            .iter()
                            .chain(&names.uris)
                            .chain(&names.ip_addresses)
                            .chain(&names.emails)
                            .collect();
                        if let Some(common_name) = &common_name
                            && !alternatives.is_empty()
                            && !alternatives
                                .iter()
                                .any(|name| **name == core_js::to_lower(common_name))
                            && !alternatives.contains(&common_name)
                        {
                            return Err(invalid(
                                "The common name must be one of the subject alternative names",
                            ));
                        }
                        let authority = target.authority()?.clone();
                        let validity_seconds =
                            leaf_validity(&authority, body.get("validitySeconds"))?;
                        target.attributes = with_entry(
                            issue_base(
                                &authority,
                                &located_usage,
                                validity_seconds,
                                &request.key_type,
                            ),
                            &entries[0],
                        );
                        target.request = Some(request);
                        target.names = Some(names);
                        target.common_name = common_name;
                        target.entries = entries;
                        Ok(target)
                    })
                },
                move |call, target| {
                    Box::pin(async move {
                        let authority = target.authority()?.clone();
                        let request = target.request.clone().ok_or_else(internal_error)?;
                        let names = target.names.clone().ok_or_else(internal_error)?;
                        let validity_seconds =
                            leaf_validity(&authority, body.get("validitySeconds"))?;
                        for entry in target.entries.iter().skip(1) {
                            let decided = Target {
                                resource_id: format!("pki/{}", authority.id),
                                attributes: with_entry(
                                    issue_base(
                                        &authority,
                                        &usage,
                                        validity_seconds,
                                        &request.key_type,
                                    ),
                                    entry,
                                ),
                            };
                            if !call.allowed(actions::ISSUE, &decided).await? {
                                return Err(OperationDenied::new(Some(&format!(
                                    "You may not certify {}",
                                    entry.name
                                ))));
                            }
                        }
                        spiffe_rules(&authority, &names)?;
                        let issued = issue(
                            &ctx,
                            &call.tx,
                            &authority,
                            IssueRequest {
                                spki: request.spki.clone(),
                                key_type: request.key_type.clone(),
                                common_name: target.common_name.clone(),
                                names,
                                usage: usage.clone(),
                                validity_seconds,
                                identity_id: None,
                                spiffe_id: None,
                                not_after_cap: None,
                                issued_by: call.principal.identity.id.clone(),
                                principal: call.principal.clone(),
                            },
                        )
                        .await?;
                        call.note("serialNumber", json!(issued.serial_number));
                        call.note(
                            "names",
                            json!(
                                target
                                    .entries
                                    .iter()
                                    .map(|entry| format!("{}:{}", entry.name_type, entry.name))
                                    .collect::<Vec<_>>()
                            ),
                        );
                        call.note("notAfter", number(issued.not_after));
                        call.note("usage", json!(usage));
                        Ok(issued.to_value())
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `pki/listAuthorities`: the tenant's certificate authorities the caller may read (`iam:pki:read`, per
    /// authority).
    pub async fn list_authorities(
        &self,
        credential: &CredentialInput,
        input: Body<pki::ListAuthoritiesInput>,
    ) -> IamResult<Reply<pki::ListAuthoritiesOutput>> {
        let items = self
            .guard
            .visible(
                credential,
                input.get("tenantId"),
                actions::READ,
                "pki",
                move |tx, tenant| {
                    Box::pin(async move {
                        let mut authorities: Vec<PkiAuthority> = tx
                            .find(
                                "pkiAuthorities",
                                &Filter::new().eq("tenantId", tenant.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                            .into_iter()
                            .map(PkiAuthority::from_record)
                            .collect::<IamResult<Vec<_>>>()?;
                        authorities.sort_by(by_created);
                        Ok(authorities
                            .iter()
                            .map(|authority| {
                                (
                                    value_of(&summarize_authority(authority)),
                                    Target {
                                        resource_id: format!("pki/{}", authority.id),
                                        attributes: authority_attributes(authority),
                                    },
                                )
                            })
                            .collect())
                    })
                },
            )
            .await?;
        Ok(Reply::json(Value::Array(items)))
    }

    /// `pki/listCertificates`: certificates the caller may read (`iam:pki:read` on each one's authority), newest
    /// first; filter by `authorityId`, `status` (`valid`, `revoked`, `expired`) or `identityId` (workload
    /// certificates).
    pub async fn list_certificates(
        &self,
        credential: &CredentialInput,
        input: Body<pki::ListCertificatesInput>,
    ) -> IamResult<Reply<pki::ListCertificatesOutput>> {
        let limit = integer(
            Some(&or_default(input.get("limit"), json!(100))),
            "limit",
            1.0,
            1000.0,
        )?;
        let offset = integer(
            Some(&or_default(input.get("offset"), json!(0))),
            "offset",
            0.0,
            1_000_000.0,
        )?;
        let ctx = self.ctx.clone();
        let body = input.raw().clone();
        let certificates = self
            .guard
            .visible(
                credential,
                input.get("tenantId"),
                actions::READ,
                "pki",
                move |tx, tenant| {
                    Box::pin(async move {
                        let authorities: IndexMap<String, PkiAuthority> = tx
                            .find(
                                "pkiAuthorities",
                                &Filter::new().eq("tenantId", tenant.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                            .into_iter()
                            .map(|record| {
                                PkiAuthority::from_record(record)
                                    .map(|authority| (authority.id.clone(), authority))
                            })
                            .collect::<IamResult<_>>()?;
                        let now = ctx.now();
                        let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                        if let Some(authority_id) = body.get("authorityId") {
                            filter = filter
                                .eq("authorityId", text(Some(authority_id), "authorityId", 256)?);
                        }
                        if let Some(identity_id) = body.get("identityId") {
                            filter = filter
                                .eq("identityId", text(Some(identity_id), "identityId", 256)?);
                        }
                        let status = body.get("status").cloned();
                        let mut summaries: Vec<_> = tx
                            .find("pkiCertificates", &filter, &FindOptions::default())
                            .await?
                            .into_iter()
                            .map(PkiCertificate::from_record)
                            .collect::<IamResult<Vec<_>>>()?
                            .iter()
                            .map(|certificate| summarize_certificate(certificate, now))
                            .filter(|summary| match &status {
                                None => true,
                                Some(status) => *status == Value::String(summary.status.clone()),
                            })
                            .collect();
                        summaries.sort_by(|a, b| {
                            let difference = b.issued_at - a.issued_at;
                            if difference != 0.0 && !difference.is_nan() {
                                return difference
                                    .partial_cmp(&0.0)
                                    .unwrap_or(std::cmp::Ordering::Equal);
                            }
                            if core_js::cmp_utf16(&a.id, &b.id).is_lt() {
                                std::cmp::Ordering::Less
                            } else {
                                std::cmp::Ordering::Greater
                            }
                        });
                        Ok(summaries
                            .into_iter()
                            .filter_map(|summary| {
                                let authority = authorities.get(&summary.authority_id)?;
                                let target = Target {
                                    resource_id: format!("pki/{}", authority.id),
                                    attributes: authority_attributes(authority),
                                };
                                Some((value_of(&summary), target))
                            })
                            .collect())
                    })
                },
            )
            .await?;
        let total = certificates.len();
        let start = (offset as usize).min(total);
        let end = (offset as usize + limit as usize).min(total);
        Ok(Reply::json(json!({
            "certificates": certificates[start..end],
            "total": total,
        })))
    }

    /// `pki/requestCertificate`: a workload certificate (SPIFFE X.509 SVID) for the caller's own identity: the only
    /// name is `spiffe://{trustDomain}/{user|service|agent}/{identityId}` (a critical subject alternative name, empty
    /// subject), valid for `validitySeconds` (default one hour, at most a day and the authority's maximum), and never
    /// past the end of the calling session or API key or of the identity itself. The authority needs a
    /// `trustDomain`. For user sessions and API keys acting in their own right; requires iam:pki:request on the
    /// authority, decided with `resource.name` (the SPIFFE ID), `resource.nameType` (`uri`) and
    /// `resource.identityKind`.
    pub async fn request_certificate(
        &self,
        credential: &CredentialInput,
        input: Body<pki::RequestCertificateInput>,
    ) -> IamResult<Reply<pki::RequestCertificateOutput>> {
        let ctx = self.ctx.clone();
        let body = input.raw().clone();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(actions::REQUEST.into()),
                move |tx, principal| {
                    Box::pin(async move {
                        let mut target =
                            authority_target(&tx, body.get("tenantId"), body.get("authorityId"))
                                .await?;
                        let authority = target.authority()?.clone();
                        if !acts_in_own_right(&principal)?
                            || principal.identity.tenant_id != authority.tenant_id
                        {
                            return Err(IamError::with_status(
                                "ACCESS_DENIED",
                                "Workload certificates are issued to your own identity, from your own session or API key",
                                403,
                            ));
                        }
                        let Some(domain) = authority.trust_domain.clone().filter(|d| !d.is_empty())
                        else {
                            return Err(invalid("This authority has no SPIFFE trust domain"));
                        };
                        let request = parse_certificate_request(body.get("csr"))?;
                        let kind = kind_name(&principal);
                        let spiffe_id =
                            format!("spiffe://{domain}/{kind}/{}", principal.identity.id);
                        let ceiling = 86_400f64.min(authority.max_validity_seconds);
                        let validity_seconds = match body.get("validitySeconds") {
                            None => 3600f64.min(ceiling),
                            Some(value) => integer(Some(value), "validitySeconds", 60.0, ceiling)?,
                        };
                        // The workload name is decided like any other: policies may narrow it by kind or trust domain.
                        target.attributes.insert("nameType".into(), json!("uri"));
                        target.attributes.insert("name".into(), json!(spiffe_id));
                        target.attributes.insert("identityKind".into(), json!(kind));
                        target
                            .attributes
                            .insert("validitySeconds".into(), number(validity_seconds));
                        target
                            .attributes
                            .insert("keyType".into(), json!(request.key_type));
                        target.request = Some(request);
                        target.spiffe_id = spiffe_id;
                        target.validity_seconds = validity_seconds;
                        Ok(target)
                    })
                },
                move |call, target| {
                    Box::pin(async move {
                        let principal = call.principal.clone();
                        let authority = target.authority()?.clone();
                        let request = target.request.clone().ok_or_else(internal_error)?;
                        let names = SubjectAltNames {
                            uris: vec![target.spiffe_id.clone()],
                            ..SubjectAltNames::default()
                        };
                        let issued = issue(
                            &ctx,
                            &call.tx,
                            &authority,
                            IssueRequest {
                                spki: request.spki.clone(),
                                key_type: request.key_type.clone(),
                                common_name: None,
                                names,
                                usage: "both".into(),
                                validity_seconds: target.validity_seconds,
                                identity_id: Some(principal.identity.id.clone()),
                                spiffe_id: Some(target.spiffe_id.clone()),
                                // Never outlives the credential that asked for it, or the identity it names.
                                not_after_cap: Some(
                                    principal.session.expires_at.min(
                                        principal.identity.expires_at.unwrap_or(f64::INFINITY),
                                    ),
                                ),
                                issued_by: principal.identity.id.clone(),
                                principal: principal.clone(),
                            },
                        )
                        .await?;
                        call.note("serialNumber", json!(issued.serial_number));
                        call.note("spiffeId", json!(target.spiffe_id));
                        call.note("notAfter", number(issued.not_after));
                        Ok(issued.to_value())
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `pki/revokeCertificate`: revokes a certificate (`reason`: `unspecified`, `keyCompromise`, `caCompromise`,
    /// `affiliationChanged`, `superseded`, `cessationOfOperation`, `privilegeWithdrawn`). It appears on the
    /// authority's next CRL and fails `iam.pki.verify` at once. Revoking a subordinate authority's certificate
    /// revokes the authority too. Requires iam:pki:revoke on the issuing authority.
    pub async fn revoke_certificate(
        &self,
        credential: &CredentialInput,
        input: Body<pki::RevokeCertificateInput>,
    ) -> IamResult<Reply<pki::RevokeCertificateOutput>> {
        let reason = or_default(input.get("reason"), json!("unspecified"));
        let reason = match reason.as_str() {
            Some(reason)
                if revocation_reason_code(reason).is_some() && reason != "certificateHold" =>
            {
                reason.to_owned()
            }
            _ => return Err(invalid("Unknown revocation reason")),
        };
        let ctx = self.ctx.clone();
        let (tenant_id, serial_number) = (
            input.get("tenantId").cloned(),
            input.get("serialNumber").cloned(),
        );
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(actions::REVOKE.into()),
                move |tx, _principal| {
                    Box::pin(async move {
                        let certificate =
                            find_certificate(&tx, tenant_id.as_ref(), serial_number.as_ref())
                                .await?;
                        let mut target = authority_target(
                            &tx,
                            tenant_id.as_ref(),
                            Some(&json!(certificate.authority_id)),
                        )
                        .await?;
                        target.certificate = Some(certificate);
                        Ok(target)
                    })
                },
                move |call, target| {
                    Box::pin(async move {
                        let tx = call.tx.clone();
                        let authority = target.authority()?.clone();
                        let certificate = target.certificate.clone().ok_or_else(internal_error)?;
                        if certificate.status == "revoked" {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                "The certificate is already revoked",
                                409,
                            )
                            .into());
                        }
                        let now = ctx.now();
                        let mut revoked = certificate.raw.clone();
                        revoked.insert("status".into(), json!("revoked"));
                        revoked.insert("revokedAt".into(), number(now));
                        revoked.insert("revocationReason".into(), json!(reason));
                        revoked.insert("revokedBy".into(), json!(call.principal.identity.id));
                        tx.put("pkiCertificates", &revoked).await?;
                        let mut bumped = authority.raw.clone();
                        bumped.insert("revision".into(), number(authority.revision + 1.0));
                        bumped.insert("updatedAt".into(), number(now));
                        tx.put("pkiAuthorities", &bumped).await?;
                        let revoked = PkiCertificate::from_record(revoked)?;
                        // A revoked authority certificate revokes the authority and every authority below it.
                        let mut cascaded = 0usize;
                        if let Some(subordinate_id) =
                            revoked.subordinate_id.clone().filter(|id| !id.is_empty())
                        {
                            let all: Vec<PkiAuthority> = tx
                                .find(
                                    "pkiAuthorities",
                                    &Filter::new().eq("tenantId", authority.tenant_id.clone()),
                                    &FindOptions::default(),
                                )
                                .await?
                                .into_iter()
                                .map(PkiAuthority::from_record)
                                .collect::<IamResult<Vec<_>>>()?;
                            let mut doomed: IndexSet<String> = IndexSet::new();
                            doomed.insert(subordinate_id.clone());
                            let mut grew = true;
                            while grew {
                                grew = false;
                                for candidate in &all {
                                    if let Some(parent_id) =
                                        candidate.parent_id.as_ref().filter(|id| !id.is_empty())
                                        && doomed.contains(parent_id)
                                        && !doomed.contains(&candidate.id)
                                    {
                                        doomed.insert(candidate.id.clone());
                                        grew = true;
                                    }
                                }
                            }
                            for candidate in &all {
                                if doomed.contains(&candidate.id) && candidate.state != "revoked" {
                                    let mut record = candidate.raw.clone();
                                    record.insert("state".into(), json!("revoked"));
                                    record.insert("updatedAt".into(), number(now));
                                    tx.put("pkiAuthorities", &record).await?;
                                    cascaded += 1;
                                }
                            }
                            call.note("serialNumber", json!(revoked.serial_number));
                            call.note("reason", json!(reason));
                            call.note("subordinateId", json!(subordinate_id));
                            call.note("authoritiesRevoked", json!(cascaded));
                        } else {
                            call.note("serialNumber", json!(revoked.serial_number));
                            call.note("reason", json!(reason));
                        }
                        Ok(value_of(&summarize_certificate(&revoked, now)))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `pki/updateAuthority`: disables or re-enables an authority (`state`; a disabled authority issues nothing and
    /// its certificates stop verifying), and changes the leaf validity limits or the CRL URL for future
    /// certificates (`crlUrl: null` clears it). Requires iam:pki:update.
    pub async fn update_authority(
        &self,
        credential: &CredentialInput,
        input: Body<pki::UpdateAuthorityInput>,
    ) -> IamResult<Reply<pki::UpdateAuthorityOutput>> {
        if let Some(state) = input.get("state")
            && state.as_str() != Some("active")
            && state.as_str() != Some("disabled")
        {
            return Err(invalid("state must be active or disabled"));
        }
        let ctx = self.ctx.clone();
        let body = input.raw().clone();
        let (tenant_id, authority_id) = (
            input.get("tenantId").cloned(),
            input.get("authorityId").cloned(),
        );
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(actions::UPDATE.into()),
                move |tx, _principal| {
                    Box::pin(async move {
                        authority_target(&tx, tenant_id.as_ref(), authority_id.as_ref()).await
                    })
                },
                move |call, target| {
                    Box::pin(async move {
                        let current = target.authority()?.clone();
                        if current.state == "revoked" {
                            return Err(IamError::with_status(
                                "AUTHORITY_UNAVAILABLE",
                                "A revoked authority cannot change",
                                409,
                            )
                            .into());
                        }
                        let mut next = current.raw.clone();
                        next.insert("updatedAt".into(), number(ctx.now()));
                        if let Some(state) = body.get("state") {
                            next.insert("state".into(), state.clone());
                        }
                        let mut max_validity_seconds = current.max_validity_seconds;
                        if let Some(value) = body.get("maxValiditySeconds") {
                            max_validity_seconds = integer(
                                Some(value),
                                "maxValiditySeconds",
                                60.0,
                                MAX_LEAF_VALIDITY_SECONDS,
                            )?;
                            next.insert("maxValiditySeconds".into(), number(max_validity_seconds));
                        }
                        let mut default_validity_seconds = current.default_validity_seconds;
                        if let Some(value) = body.get("defaultValiditySeconds") {
                            default_validity_seconds = integer(
                                Some(value),
                                "defaultValiditySeconds",
                                60.0,
                                max_validity_seconds,
                            )?;
                        }
                        default_validity_seconds =
                            default_validity_seconds.min(max_validity_seconds);
                        next.insert(
                            "defaultValiditySeconds".into(),
                            number(default_validity_seconds),
                        );
                        match body.get("crlUrl") {
                            Some(Value::Null) => {
                                next.shift_remove("crlUrl");
                            }
                            Some(value) => {
                                let url = http_url(Some(value), "crlUrl")?.unwrap_or_default();
                                next.insert("crlUrl".into(), json!(url));
                            }
                            None => {}
                        }
                        call.tx.put("pkiAuthorities", &next).await?;
                        if let Some(state) = body.get("state")
                            && crate::js::truthy(Some(state))
                        {
                            call.note("state", state.clone());
                        }
                        call.note("maxValiditySeconds", number(max_validity_seconds));
                        call.note("defaultValiditySeconds", number(default_validity_seconds));
                        if body.get("crlUrl").is_some() {
                            call.note("crlUrl", next.get("crlUrl").cloned().unwrap_or(Value::Null));
                        }
                        let next = PkiAuthority::from_record(next)?;
                        Ok(value_of(&summarize_authority(&next)))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// What `iam.pki.crl(authorityId)` returns: the current CRL (`{ ...current, pem }`).
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeCrl {
    pub current: CurrentCrl,
    pub pem: String,
}

impl RuntimeCrl {
    /// The tagged JSON of the conformance server (`der` as `{"$bytes": base64}`), members in TypeScript order.
    pub fn to_value(&self) -> Value {
        let mut out = Map::new();
        out.insert(
            "der".into(),
            json!({ "$bytes": base64_text(&self.current.der) }),
        );
        out.insert("thisUpdate".into(), number(self.current.this_update));
        out.insert("nextUpdate".into(), number(self.current.next_update));
        if let Some(revision) = self.current.revision {
            out.insert("revision".into(), number(revision));
        }
        out.insert("crlNumber".into(), number(self.current.crl_number));
        out.insert("pem".into(), json!(self.pem));
        Value::Object(out)
    }
}

/// `iam.pki`, server side: public CRLs for relying parties, trust bundles, and certificate chain verification for
/// servers that terminate mutual TLS.
pub struct PkiRuntime {
    ctx: Arc<ServerContext>,
}

/// `createPkiRuntime(ctx)`.
pub fn create_pki_runtime(ctx: &Arc<ServerContext>) -> IamResult<PkiRuntime> {
    Ok(PkiRuntime { ctx: ctx.clone() })
}

fn text_response(status: u16, body: &str) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", "text/plain;charset=UTF-8")
        .body(Bytes::from(body.to_owned()))
        .unwrap_or_default()
}

impl PkiRuntime {
    async fn crl_of(&self, authority_id: Option<&Value>) -> IamResult<RuntimeCrl> {
        let ctx = self.ctx.clone();
        let authority_id = authority_id.cloned();
        ctx.clone()
            .store
            .transaction(|tx| async move {
                let authority_id = text(authority_id.as_ref(), "authorityId", 256)?;
                let authority = match tx.get("pkiAuthorities", &authority_id).await? {
                    Some(record) => PkiAuthority::from_record(record)?,
                    None => {
                        return Err(IamError::with_status(
                            "NOT_FOUND",
                            "Certificate authority not found",
                            404,
                        ));
                    }
                };
                let current = current_crl(&ctx, &tx, &authority).await?;
                let pem = crl_pem(&current.der);
                Ok(RuntimeCrl { current, pem })
            })
            .await
    }

    /// An authority's current CRL (DER and PEM), with no credential: CRLs are public.
    pub async fn crl(&self, authority_id: &str) -> IamResult<RuntimeCrl> {
        self.crl_of(Some(&json!(authority_id))).await
    }

    async fn crl_response_of(&self, authority_id: Option<&Value>) -> IamResult<HttpResponse> {
        let ctx = &self.ctx;
        let respond = |der: Vec<u8>, next_update: f64| {
            let max_age = ((next_update - ctx.now()) / 2000.0).floor().max(0.0);
            http::Response::builder()
                .status(200)
                .header("content-type", "application/pkix-crl")
                .header(
                    "cache-control",
                    format!("public, max-age={}", crate::js::number_to_string(max_age)),
                )
                .body(Bytes::from(der))
                .unwrap_or_default()
        };
        match self.crl_of(authority_id).await {
            Ok(current) => Ok(respond(current.current.der, current.current.next_update)),
            Err(error) if error.code == "NOT_FOUND" => Ok(text_response(404, "Not found")),
            Err(_) => {
                let key = js_string(authority_id);
                let cached = ctx
                    .store
                    .transaction(|tx| async move { tx.get("pkiAuthorities", &key).await })
                    .await
                    .ok()
                    .flatten()
                    .and_then(|record| PkiAuthority::from_record(record).ok());
                if let Some(crl) = cached.and_then(|authority| authority.crl)
                    && crl.next_update > ctx.now()
                {
                    return Ok(respond(node_base64(&crl.der), crl.next_update));
                }
                Ok(text_response(503, "Revocation list unavailable"))
            }
        }
    }

    /// An HTTP response for an authority's CRL distribution point (`application/pkix-crl`). When a fresh CRL cannot be
    /// signed (the authority's KMS key is disabled), the last one is served while it is still valid; otherwise 503.
    pub async fn crl_response(&self, authority_id: &str) -> IamResult<HttpResponse> {
        self.crl_response_of(Some(&json!(authority_id))).await
    }

    async fn bundle_of(&self, tenant_id: Option<&Value>) -> IamResult<String> {
        let ctx = self.ctx.clone();
        let tenant_id = tenant_id.cloned();
        ctx.clone()
            .store
            .transaction(|tx| async move {
                let tenant_id = text(tenant_id.as_ref(), "tenantId", 256)?;
                Ok(trust_anchors(&ctx, &tx, &tenant_id)
                    .await?
                    .iter()
                    .map(|authority| authority.certificate_pem.as_str())
                    .collect())
            })
            .await
    }

    /// A tenant's trust anchors (active, unexpired roots) as one PEM bundle.
    pub async fn bundle(&self, tenant_id: &str) -> IamResult<String> {
        self.bundle_of(Some(&json!(tenant_id))).await
    }

    /// Verifies a presented certificate (leaf first; intermediates optional) against one tenant's stored chains:
    /// signatures, path lengths, validity, authority state and revocation, and for workload certificates the standing
    /// of the identity they name. Returns the SPIFFE ID and identity of workload certificates; throws
    /// `CERTIFICATE_INVALID` (401) otherwise. `tenantId` is required: trust is per organization.
    pub async fn verify(
        &self,
        chain: &Value,
        options: &Value,
    ) -> IamResult<crate::pki::CertificateVerification> {
        verify_certificate_chain(&self.ctx, chain, options).await
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let defined = |index: usize| {
            args.get(index)
                .filter(|value| value.get("$undefined").is_none())
        };
        match method {
            "crl" => Some(self.crl_of(defined(0)).await.map(|crl| crl.to_value())),
            // A Response travels as its tagged class name (FORMAT.md).
            "crlResponse" => Some(
                self.crl_response_of(defined(0))
                    .await
                    .map(|_| json!({ "$object": "Response" })),
            ),
            "bundle" => Some(self.bundle_of(defined(0)).await.map(Value::String)),
            "verify" => Some(
                self.verify(
                    defined(0).unwrap_or(&Value::Null),
                    defined(1).unwrap_or(&Value::Null),
                )
                .await
                .map(|verified| verified.to_value()),
            ),
            _ => None,
        }
    }
}
