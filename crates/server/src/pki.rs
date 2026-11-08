//! Port of `packages/server/src/pki.ts`.
//!
//! A private certificate authority for workload identity (like AWS Private CA, step-ca or a SPIFFE server): tenant
//! certificate authorities whose signing keys are KMS keys, certificates issued from PKCS#10 requests with every name
//! decided by policy, SPIFFE workload certificates (SVIDs) for the caller's own identity, revocation, CRLs and chain
//! verification for mTLS. The API lives in api/pki.rs; the X.509 encoding in x509.rs.
//!
//! Records are read into typed views ([`PkiAuthority`], [`PkiCertificate`]) that keep the stored JSON object
//! (`raw`), so a read-modify-write changes members in place and keeps member order and members this port does not
//! know (a mixed fleet shares the database with TypeScript).

use std::sync::{Arc, LazyLock};

use better_iam_core::js as core_js;
use better_iam_core::{
    AuthenticatedPrincipal, Filter, FindOptions, IamError, IamResult, IamStoreExt, IdentityStatus,
    Record,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::js::{js_string, number};
use crate::kms::{KmsServiceUse, kms_sign_for};
use crate::validation::text;
use crate::x509::{
    CertListSpec, DistinguishedName, PermittedNames, RevocationReason, RevokedEntry,
    SignatureAlgorithm, SubjectAltNames, X509Certificate, certificate_der, dns_name, node_base64,
    node_hex, pem, signed_structure, tbs_cert_list,
};

/// `'active' | 'disabled' | 'revoked'`.
pub type AuthorityState = String;

/// `'server' | 'client' | 'both'`.
pub type CertificateUsage = String;

/// The cached CRL of an authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedCrl {
    pub der: String,
    #[serde(rename = "thisUpdate")]
    pub this_update: f64,
    #[serde(rename = "nextUpdate")]
    pub next_update: f64,
    pub revision: f64,
    #[serde(rename = "crlNumber")]
    pub crl_number: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PkiAuthority {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// `name:{lowercase name}`, unique in the tenant.
    #[serde(rename = "uniqueKey")]
    pub unique_key: String,
    #[serde(rename = "name")]
    pub name: String,
    /// `root` or `intermediate`.
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "parentId", default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(rename = "subject")]
    pub subject: DistinguishedName,
    /// The subject name's DER (base64), reused byte for byte as the issuer of what this authority signs.
    #[serde(rename = "subjectDer")]
    pub subject_der: String,
    /// Hex SHA-1 key identifier of the authority's public key.
    #[serde(rename = "subjectKeyId")]
    pub subject_key_id: String,
    /// The KMS signing key and the version pinned for this authority (rotation never changes a CA's key).
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "keyVersion")]
    pub key_version: f64,
    #[serde(rename = "algorithm")]
    pub algorithm: SignatureAlgorithm,
    #[serde(rename = "certificatePem")]
    pub certificate_pem: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    #[serde(rename = "notBefore")]
    pub not_before: f64,
    #[serde(rename = "notAfter")]
    pub not_after: f64,
    #[serde(
        rename = "pathLength",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub path_length: Option<f64>,
    #[serde(rename = "state")]
    pub state: AuthorityState,
    /// SPIFFE trust domain for workload certificates (`spiffe://{trustDomain}/…`).
    #[serde(
        rename = "trustDomain",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub trust_domain: Option<String>,
    /// Written into issued certificates as their CRL distribution point.
    #[serde(rename = "crlUrl", default, skip_serializing_if = "Option::is_none")]
    pub crl_url: Option<String>,
    /// Names this authority (and everything below it) may certify: DNS suffixes and URI hosts.
    #[serde(rename = "permitted", default, skip_serializing_if = "Option::is_none")]
    pub permitted: Option<PermittedNames>,
    #[serde(rename = "maxValiditySeconds")]
    pub max_validity_seconds: f64,
    #[serde(rename = "defaultValiditySeconds")]
    pub default_validity_seconds: f64,
    /// Bumped on every revocation, so the cached CRL is rebuilt.
    #[serde(rename = "revision")]
    pub revision: f64,
    #[serde(rename = "crlNumber")]
    pub crl_number: f64,
    #[serde(rename = "crl", default, skip_serializing_if = "Option::is_none")]
    pub crl: Option<CachedCrl>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
    /// The stored record this view was read from.
    #[serde(skip)]
    pub raw: Record,
}

impl PkiAuthority {
    /// The typed view of a stored authority (STORAGE_CORRUPT for a malformed record).
    pub fn from_record(record: Record) -> IamResult<PkiAuthority> {
        let mut authority: PkiAuthority = crate::port::decode(record.clone())?;
        authority.raw = record;
        Ok(authority)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PkiCertificate {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// `serial:{hex}`.
    #[serde(rename = "uniqueKey")]
    pub unique_key: String,
    #[serde(rename = "authorityId")]
    pub authority_id: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    #[serde(
        rename = "commonName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub common_name: Option<String>,
    #[serde(rename = "names")]
    pub names: SubjectAltNames,
    #[serde(rename = "keyType")]
    pub key_type: String,
    /// `server`, `client`, `both` or `ca`.
    #[serde(rename = "usage")]
    pub usage: String,
    #[serde(rename = "notBefore")]
    pub not_before: f64,
    #[serde(rename = "notAfter")]
    pub not_after: f64,
    #[serde(rename = "certificatePem")]
    pub certificate_pem: String,
    #[serde(rename = "fingerprint")]
    pub fingerprint: String,
    /// Workload certificates: the identity the SPIFFE ID names.
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(rename = "spiffeId", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    /// A subordinate authority's own certificate.
    #[serde(
        rename = "subordinateId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub subordinate_id: Option<String>,
    /// `valid` or `revoked`.
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(
        rename = "revocationReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revocation_reason: Option<RevocationReason>,
    #[serde(rename = "revokedBy", default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(rename = "issuedAt")]
    pub issued_at: f64,
    #[serde(rename = "issuedBy")]
    pub issued_by: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
    /// The stored record this view was read from.
    #[serde(skip)]
    pub raw: Record,
}

impl PkiCertificate {
    /// The typed view of a stored certificate (STORAGE_CORRUPT for a malformed record).
    pub fn from_record(record: Record) -> IamResult<PkiCertificate> {
        let mut certificate: PkiCertificate = crate::port::decode(record.clone())?;
        certificate.raw = record;
        Ok(certificate)
    }
}

/// `AuthoritySummary`, its members in the order `summarizeAuthority` writes them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthoritySummary {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "subject")]
    pub subject: DistinguishedName,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "keyVersion")]
    pub key_version: f64,
    #[serde(rename = "algorithm")]
    pub algorithm: SignatureAlgorithm,
    #[serde(rename = "certificatePem")]
    pub certificate_pem: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    #[serde(rename = "notBefore")]
    pub not_before: f64,
    #[serde(rename = "notAfter")]
    pub not_after: f64,
    #[serde(rename = "state")]
    pub state: AuthorityState,
    #[serde(rename = "maxValiditySeconds")]
    pub max_validity_seconds: f64,
    #[serde(rename = "defaultValiditySeconds")]
    pub default_validity_seconds: f64,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "parentId", default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(
        rename = "pathLength",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub path_length: Option<f64>,
    #[serde(
        rename = "trustDomain",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub trust_domain: Option<String>,
    #[serde(rename = "crlUrl", default, skip_serializing_if = "Option::is_none")]
    pub crl_url: Option<String>,
    #[serde(rename = "permitted", default, skip_serializing_if = "Option::is_none")]
    pub permitted: Option<PermittedNames>,
}

/// `CertificateSummary`, its members in the order `summarizeCertificate` writes them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificateSummary {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "authorityId")]
    pub authority_id: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    #[serde(rename = "names")]
    pub names: SubjectAltNames,
    #[serde(rename = "keyType")]
    pub key_type: String,
    #[serde(rename = "usage")]
    pub usage: String,
    #[serde(rename = "notBefore")]
    pub not_before: f64,
    #[serde(rename = "notAfter")]
    pub not_after: f64,
    #[serde(rename = "fingerprint")]
    pub fingerprint: String,
    /// `valid`, `revoked` or `expired`.
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: f64,
    #[serde(rename = "issuedBy")]
    pub issued_by: String,
    #[serde(rename = "certificatePem")]
    pub certificate_pem: String,
    #[serde(
        rename = "commonName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub common_name: Option<String>,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(rename = "spiffeId", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    #[serde(
        rename = "subordinateId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub subordinate_id: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(
        rename = "revocationReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revocation_reason: Option<String>,
}

/// `CertificateVerification`, its members in the order `verifyCertificateChain` writes them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificateVerification {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "authorityId")]
    pub authority_id: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    #[serde(rename = "fingerprint")]
    pub fingerprint: String,
    #[serde(rename = "subject")]
    pub subject: String,
    #[serde(rename = "dnsNames")]
    pub dns_names: Vec<String>,
    #[serde(rename = "uris")]
    pub uris: Vec<String>,
    #[serde(rename = "notAfter")]
    pub not_after: f64,
    #[serde(rename = "spiffeId", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
}

impl CertificateVerification {
    /// The JSON the TypeScript function returns (JavaScript numbers).
    pub fn to_value(&self) -> Value {
        let mut out = Map::new();
        out.insert("tenantId".into(), json!(self.tenant_id));
        out.insert("authorityId".into(), json!(self.authority_id));
        out.insert("serialNumber".into(), json!(self.serial_number));
        out.insert("fingerprint".into(), json!(self.fingerprint));
        out.insert("subject".into(), json!(self.subject));
        out.insert("dnsNames".into(), json!(self.dns_names));
        out.insert("uris".into(), json!(self.uris));
        out.insert("notAfter".into(), number(self.not_after));
        if let Some(spiffe_id) = &self.spiffe_id {
            out.insert("spiffeId".into(), json!(spiffe_id));
        }
        if let Some(identity_id) = &self.identity_id {
            out.insert("identityId".into(), json!(identity_id));
        }
        Value::Object(out)
    }
}

/// `pkiActions`.
pub mod actions {
    pub const CREATE: &str = "iam:pki:create";
    pub const READ: &str = "iam:pki:read";
    pub const UPDATE: &str = "iam:pki:update";
    pub const ISSUE: &str = "iam:pki:issue";
    pub const REQUEST: &str = "iam:pki:request";
    pub const REVOKE: &str = "iam:pki:revoke";
}

/// `pkiActions` as the frozen object TypeScript exports.
pub fn pki_actions() -> Value {
    json!({
        "create": actions::CREATE,
        "read": actions::READ,
        "update": actions::UPDATE,
        "issue": actions::ISSUE,
        "request": actions::REQUEST,
        "revoke": actions::REVOKE,
    })
}

pub const MAX_AUTHORITIES_PER_TENANT: f64 = 50.0;
const DAY_SECONDS: f64 = 86_400.0;
/// Leaf certificates never outlive 825 days, the CA/Browser Forum's old ceiling.
pub const MAX_LEAF_VALIDITY_SECONDS: f64 = 825.0 * DAY_SECONDS;

pub fn summarize_authority(authority: &PkiAuthority) -> AuthoritySummary {
    AuthoritySummary {
        id: authority.id.clone(),
        tenant_id: authority.tenant_id.clone(),
        name: authority.name.clone(),
        r#type: authority.r#type.clone(),
        subject: authority.subject.clone(),
        key_id: authority.key_id.clone(),
        key_version: authority.key_version,
        algorithm: authority.algorithm.clone(),
        certificate_pem: authority.certificate_pem.clone(),
        serial_number: authority.serial_number.clone(),
        not_before: authority.not_before,
        not_after: authority.not_after,
        state: authority.state.clone(),
        max_validity_seconds: authority.max_validity_seconds,
        default_validity_seconds: authority.default_validity_seconds,
        created_at: authority.created_at,
        created_by: authority.created_by.clone(),
        parent_id: authority.parent_id.clone(),
        path_length: authority.path_length,
        trust_domain: authority.trust_domain.clone(),
        crl_url: authority.crl_url.clone(),
        permitted: authority.permitted.clone(),
    }
}

pub fn summarize_certificate(certificate: &PkiCertificate, now: f64) -> CertificateSummary {
    CertificateSummary {
        id: certificate.id.clone(),
        tenant_id: certificate.tenant_id.clone(),
        authority_id: certificate.authority_id.clone(),
        serial_number: certificate.serial_number.clone(),
        names: certificate.names.clone(),
        key_type: certificate.key_type.clone(),
        usage: certificate.usage.clone(),
        not_before: certificate.not_before,
        not_after: certificate.not_after,
        fingerprint: certificate.fingerprint.clone(),
        status: if certificate.status == "revoked" {
            "revoked"
        } else if certificate.not_after <= now {
            "expired"
        } else {
            "valid"
        }
        .to_owned(),
        issued_at: certificate.issued_at,
        issued_by: certificate.issued_by.clone(),
        certificate_pem: certificate.certificate_pem.clone(),
        common_name: certificate.common_name.clone(),
        identity_id: certificate.identity_id.clone(),
        spiffe_id: certificate.spiffe_id.clone(),
        subordinate_id: certificate.subordinate_id.clone(),
        revoked_at: certificate.revoked_at,
        revocation_reason: certificate.revocation_reason.clone(),
    }
}

/// The attributes an authority presents to policies (`resource.{name}`).
pub fn authority_attributes(authority: &PkiAuthority) -> Map<String, Value> {
    let mut attributes = Map::new();
    attributes.insert("authorityId".into(), json!(authority.id));
    attributes.insert("authorityName".into(), json!(authority.name));
    attributes.insert("authorityType".into(), json!(authority.r#type));
    attributes.insert("authorityState".into(), json!(authority.state));
    if let Some(domain) = authority.trust_domain.as_deref().filter(|d| !d.is_empty()) {
        attributes.insert("trustDomain".into(), json!(domain));
    }
    attributes
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// A distinguished name: `commonName` required for authorities, every part within X.520 bounds.
pub fn distinguished_name(
    value: Option<&Value>,
    require_common_name: bool,
) -> IamResult<DistinguishedName> {
    if value.is_none() && !require_common_name {
        return Ok(DistinguishedName::default());
    }
    let Some(Value::Object(input)) = value else {
        return Err(invalid("subject must be an object"));
    };
    let allowed = [
        "commonName",
        "organization",
        "organizationalUnit",
        "locality",
        "state",
        "country",
    ];
    for key in core_js::keys(input) {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid(format!("Unknown subject field {key}")));
        }
    }
    let part = |key: &str, max: usize| -> IamResult<Option<String>> {
        match input.get(key) {
            None => Ok(None),
            Some(value) => Ok(Some(
                core_js::trim(&text(Some(value), &format!("subject.{key}"), max)?).to_owned(),
            )),
        }
    };
    let filled = |value: Option<String>| value.filter(|text| !text.is_empty());
    let mut name = DistinguishedName::default();
    match filled(part("commonName", 64)?) {
        Some(common_name) => name.common_name = Some(common_name),
        None if require_common_name => {
            return Err(invalid("subject.commonName is required"));
        }
        None => {}
    }
    name.organization = filled(part("organization", 64)?);
    name.organizational_unit = filled(part("organizationalUnit", 64)?);
    name.locality = filled(part("locality", 128)?);
    name.state = filled(part("state", 128)?);
    if let Some(country) = filled(part("country", 2)?) {
        if !(country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase())) {
            return Err(invalid("subject.country must be a two-letter ISO code"));
        }
        name.country = Some(country);
    }
    Ok(name)
}

static TRUST_DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?$").expect("trust domain")
});

pub fn trust_domain(value: Option<&Value>) -> IamResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let domain = core_js::to_lower(&text(Some(value), "trustDomain", 255)?);
    if !TRUST_DOMAIN.is_match(&domain) {
        return Err(invalid(
            "trustDomain must be lowercase letters, digits, dots, hyphens or underscores",
        ));
    }
    Ok(Some(domain))
}

pub fn http_url(value: Option<&Value>, name: &str) -> IamResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let raw = text(Some(value), name, 2048)?;
    let url =
        url::Url::parse(&raw).map_err(|_| invalid(format!("{name} must be an http(s) URL")))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(invalid(format!("{name} must be an http(s) URL")));
    }
    Ok(Some(url.as_str().to_owned()))
}

static PERMITTED_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$").expect("permitted name")
});

/// Name constraints: DNS suffixes (`example.internal`, matching it and its subdomains) and URI hosts.
pub fn permitted_names(value: Option<&Value>) -> IamResult<Option<PermittedNames>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Value::Object(input) = value else {
        return Err(invalid("permitted must be an object"));
    };
    let list = |key: &str| -> IamResult<Option<Vec<String>>> {
        let Some(items) = input.get(key) else {
            return Ok(None);
        };
        let items = match items {
            Value::Array(items) if items.len() <= 50 => items,
            _ => {
                return Err(invalid(format!(
                    "permitted.{key} must list at most 50 names"
                )));
            }
        };
        items
            .iter()
            .map(|item| {
                let lowered =
                    core_js::to_lower(&text(Some(item), &format!("permitted.{key}"), 253)?);
                let name = lowered.strip_prefix('.').unwrap_or(&lowered).to_owned();
                if !PERMITTED_NAME.is_match(&name) {
                    return Err(invalid(format!("Invalid permitted name {name}")));
                }
                Ok(name)
            })
            .collect::<IamResult<Vec<_>>>()
            .map(Some)
    };
    let dns_names = list("dnsNames")?.filter(|names| !names.is_empty());
    let uri_hosts = list("uriHosts")?.filter(|names| !names.is_empty());
    if dns_names.is_none() && uri_hosts.is_none() {
        return Ok(None);
    }
    Ok(Some(PermittedNames {
        dns_names,
        uri_hosts,
    }))
}

fn within_suffix(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

/// Checks names against the name constraints of an authority and every authority above it. A constraint list
/// applies to its kind of name only: DNS names against `dnsNames`, URI hosts against `uriHosts`. A common name that
/// looks like a host name counts as a DNS name, because TLS clients still fall back to it.
pub fn names_permitted(
    chain: &[PkiAuthority],
    names: &SubjectAltNames,
    common_name: Option<&str>,
) -> IamResult<bool> {
    let host_like: Vec<String> = match common_name.filter(|name| !name.is_empty()) {
        Some(name) if dns_name().is_match(&core_js::to_lower(name)) => {
            vec![core_js::to_lower(name)]
        }
        _ => Vec::new(),
    };
    for authority in chain {
        let Some(permitted) = &authority.permitted else {
            continue;
        };
        if let Some(suffixes) = &permitted.dns_names {
            for name in names.dns_names.iter().chain(host_like.iter()) {
                let host = name.strip_prefix("*.").unwrap_or(name);
                if !suffixes.iter().any(|suffix| within_suffix(host, suffix)) {
                    return Ok(false);
                }
            }
        }
        if let Some(suffixes) = &permitted.uri_hosts {
            for uri in &names.uris {
                let parsed = url::Url::parse(uri).map_err(|_| crate::js::internal_error())?;
                let host = core_js::to_lower(parsed.host_str().unwrap_or(""));
                if !suffixes.iter().any(|suffix| within_suffix(&host, suffix)) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// The authority and its parents up to the root.
pub async fn authority_chain(tx: &Store, authority: &PkiAuthority) -> IamResult<Vec<PkiAuthority>> {
    let mut chain = vec![authority.clone()];
    let mut current = authority.clone();
    while let Some(parent_id) = current.parent_id.clone().filter(|id| !id.is_empty()) {
        let parent = match tx.get("pkiAuthorities", &parent_id).await? {
            Some(record) => Some(PkiAuthority::from_record(record)?),
            None => None,
        };
        let parent = match parent {
            Some(parent) if parent.tenant_id == authority.tenant_id && chain.len() <= 10 => parent,
            _ => {
                return Err(IamError::with_status(
                    "INVALID_HIERARCHY",
                    "The authority chain is broken",
                    500,
                ));
            }
        };
        chain.push(parent.clone());
        current = parent;
    }
    Ok(chain)
}

/// Usable for signing: active, within its validity, and every authority above it active too.
pub fn assert_authority_usable(chain: &[PkiAuthority], now: f64) -> IamResult<()> {
    for authority in chain {
        if authority.state != "active" {
            return Err(IamError::with_status(
                "AUTHORITY_UNAVAILABLE",
                format!(
                    "The certificate authority {} is {}",
                    authority.name, authority.state
                ),
                409,
            ));
        }
        if authority.not_after <= now {
            return Err(IamError::with_status(
                "AUTHORITY_UNAVAILABLE",
                format!("The certificate authority {} has expired", authority.name),
                409,
            ));
        }
    }
    Ok(())
}

pub async fn find_authority(
    tx: &Store,
    tenant_id: &str,
    authority_id: Option<&Value>,
) -> IamResult<PkiAuthority> {
    let authority_id = text(authority_id, "authorityId", 256)?;
    match tx.get("pkiAuthorities", &authority_id).await? {
        Some(record) => {
            let authority = PkiAuthority::from_record(record)?;
            if authority.tenant_id != tenant_id {
                return Err(not_found_authority());
            }
            Ok(authority)
        }
        None => Err(not_found_authority()),
    }
}

fn not_found_authority() -> IamError {
    IamError::with_status("NOT_FOUND", "Certificate authority not found", 404)
}

/// `authoritySigner(ctx, tx, authority)`: the signature an authority's KMS key makes over `data`, audited on the key
/// as used by `pki`.
#[derive(Clone)]
pub struct AuthoritySigner {
    ctx: Arc<ServerContext>,
    tx: Store,
    tenant_id: String,
    key_id: String,
    key_version: f64,
    algorithm: SignatureAlgorithm,
}

impl AuthoritySigner {
    /// `(data, principal?) => kmsSignFor(...)`.
    pub async fn sign(
        &self,
        data: &[u8],
        principal: Option<&AuthenticatedPrincipal>,
    ) -> IamResult<Vec<u8>> {
        kms_sign_for(
            &self.ctx,
            &self.tx,
            &self.tenant_id,
            &self.key_id,
            self.key_version,
            &self.algorithm,
            data,
            &KmsServiceUse {
                via: "pki".into(),
                principal: principal.cloned(),
            },
        )
        .await
    }
}

/// The signature an authority's KMS key makes over `data`, audited on the key as used by `pki`.
pub fn authority_signer(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    authority: &PkiAuthority,
) -> AuthoritySigner {
    AuthoritySigner {
        ctx: ctx.clone(),
        tx: tx.clone(),
        tenant_id: authority.tenant_id.clone(),
        key_id: authority.key_id.clone(),
        key_version: authority.key_version,
        algorithm: authority.algorithm.clone(),
    }
}

const CRL_LIFETIME_MS: f64 = 24.0 * 3_600_000.0;
const CRL_REFRESH_MS: f64 = 12.0 * 3_600_000.0;

/// What `currentCrl` returns: the DER, its validity and number, and (for a cached CRL, which is returned as stored)
/// the revision it was built at.
#[derive(Debug, Clone, PartialEq)]
pub struct CurrentCrl {
    pub der: Vec<u8>,
    pub this_update: f64,
    pub next_update: f64,
    pub revision: Option<f64>,
    pub crl_number: f64,
}

/// The authority's current CRL (DER), rebuilt when a certificate was revoked since the last one or half its
/// lifetime has passed. Lists every revoked certificate that has not expired yet.
pub async fn current_crl(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    authority: &PkiAuthority,
) -> IamResult<CurrentCrl> {
    let now = ctx.now();
    if let Some(cached) = &authority.crl
        && cached.revision == authority.revision
        && now < cached.this_update + CRL_REFRESH_MS
    {
        return Ok(CurrentCrl {
            der: node_base64(&cached.der),
            this_update: cached.this_update,
            next_update: cached.next_update,
            revision: Some(cached.revision),
            crl_number: cached.crl_number,
        });
    }
    let mut revoked: Vec<PkiCertificate> = tx
        .find(
            "pkiCertificates",
            &Filter::new()
                .eq("tenantId", authority.tenant_id.clone())
                .eq("authorityId", authority.id.clone())
                .eq("status", "revoked"),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .map(PkiCertificate::from_record)
        .collect::<IamResult<Vec<_>>>()?
        .into_iter()
        .filter(|certificate| certificate.not_after > now)
        .collect();
    revoked.sort_by(|a, b| {
        if core_js::cmp_utf16(&a.serial_number, &b.serial_number).is_lt() {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    let revoked: Vec<RevokedEntry> = revoked
        .into_iter()
        .map(|certificate| RevokedEntry {
            serial_number: certificate.serial_number,
            revoked_at: certificate.revoked_at.unwrap_or(now),
            reason: certificate
                .revocation_reason
                .filter(|reason| !reason.is_empty()),
        })
        .collect();
    let crl_number = authority.crl_number + 1.0;
    let tbs = tbs_cert_list(
        &CertListSpec {
            issuer: node_base64(&authority.subject_der),
            this_update: now,
            next_update: now + CRL_LIFETIME_MS,
            crl_number,
            authority_key_id: node_hex(&authority.subject_key_id),
            revoked,
        },
        &authority.algorithm,
    );
    let signature = authority_signer(ctx, tx, authority)
        .sign(&tbs, None)
        .await?;
    let der = signed_structure(&tbs, &authority.algorithm, &signature);
    let mut crl = Map::new();
    crl.insert("der".into(), json!(base64_text(&der)));
    crl.insert("thisUpdate".into(), number(now));
    crl.insert("nextUpdate".into(), number(now + CRL_LIFETIME_MS));
    crl.insert("revision".into(), number(authority.revision));
    crl.insert("crlNumber".into(), number(crl_number));
    let mut record = authority.raw.clone();
    record.insert("crlNumber".into(), number(crl_number));
    record.insert("crl".into(), Value::Object(crl));
    tx.put("pkiAuthorities", &record).await?;
    Ok(CurrentCrl {
        der,
        this_update: now,
        next_update: now + CRL_LIFETIME_MS,
        revision: None,
        crl_number,
    })
}

/// `der.toString('base64')`.
pub fn base64_text(der: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(der)
}

fn san_list(certificate: &X509Certificate, prefix: &str) -> Vec<String> {
    let text = certificate.subject_alt_name().unwrap_or_default();
    let marker = format!("{prefix}:");
    text.split(", ")
        .filter(|entry| entry.starts_with(&marker))
        .map(|entry| entry[marker.len()..].to_owned())
        .collect()
}

fn certificate_invalid(message: impl Into<String>) -> IamError {
    IamError::with_status("CERTIFICATE_INVALID", message, 401)
}

static CERTIFICATE_PEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----").expect("pem")
});

/// Verifies a client or server certificate chain (leaf first, PEM concatenated or as a list) against one tenant's
/// certificate authorities: every signature, path length, validity period, authority state and revocation, and for
/// a workload certificate the standing of the identity it names. For mTLS: a server that terminates TLS passes the
/// peer's certificate and gets the identity behind a workload certificate.
pub async fn verify_certificate_chain(
    ctx: &Arc<ServerContext>,
    chain: &Value,
    options: &Value,
) -> IamResult<CertificateVerification> {
    // Trust is per tenant: without a tenant, one organization's authority could vouch for another's names.
    let tenant_id = text(options.get("tenantId"), "tenantId", 256)?;
    let entries: Vec<&Value> = match chain {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    let mut pems: Vec<String> = Vec::new();
    for entry in entries {
        // `entry.match(...)` on something that is not a string is a TypeError.
        let Value::String(entry) = entry else {
            return Err(crate::js::internal_error());
        };
        pems.extend(
            CERTIFICATE_PEM
                .find_iter(entry)
                .map(|found| found.as_str().to_owned()),
        );
    }
    pems.truncate(10);
    let Some(first) = pems.first() else {
        return Err(certificate_invalid("No certificate was presented"));
    };
    let leaf = X509Certificate::from_pem(first)
        .ok_or_else(|| certificate_invalid("The certificate cannot be read"))?;
    let now = options
        .get("at")
        .and_then(core_js::as_number)
        .unwrap_or_else(|| ctx.now());
    let usage = options
        .get("usage")
        .filter(|usage| crate::js::truthy(Some(usage)))
        .cloned();
    let serial = core_js::to_lower(&leaf.serial_number());
    let serial_number = {
        let trimmed = serial.trim_start_matches('0');
        if trimmed.is_empty() && !serial.is_empty() {
            "0".to_owned()
        } else {
            trimmed.to_owned()
        }
    };
    let ctx = ctx.clone();
    ctx.clone()
        .store
        .transaction(|tx| async move {
            let records: Vec<PkiCertificate> = tx
                .find(
                    "pkiCertificates",
                    &Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("uniqueKey", format!("serial:{serial_number}")),
                    &FindOptions::default(),
                )
                .await?
                .into_iter()
                .map(PkiCertificate::from_record)
                .collect::<IamResult<Vec<_>>>()?
                .into_iter()
                .filter(|record| certificate_der(&record.certificate_pem) == leaf.raw)
                .collect();
            let Some(record) = records.into_iter().next() else {
                return Err(certificate_invalid("The certificate was not issued here"));
            };
            if record.status == "revoked" {
                return Err(certificate_invalid("The certificate has been revoked"));
            }
            if record.usage == "ca" {
                return Err(certificate_invalid("A CA certificate cannot authenticate"));
            }
            if let Some(usage) = &usage
                && record.usage != "both"
                && Value::String(record.usage.clone()) != *usage
            {
                return Err(certificate_invalid(format!(
                    "The certificate is not for {} use",
                    js_string(Some(usage))
                )));
            }
            if leaf.valid_from() > now || leaf.valid_to() <= now {
                return Err(certificate_invalid(
                    "The certificate is not valid at this time",
                ));
            }
            let authority = match tx.get("pkiAuthorities", &record.authority_id).await? {
                Some(found) => Some(PkiAuthority::from_record(found)?),
                None => None,
            };
            let authority = match authority {
                Some(authority) if authority.tenant_id == record.tenant_id => authority,
                _ => return Err(certificate_invalid("The issuing authority is gone")),
            };
            // Walk the stored chain (not whatever the client sent): each link must verify, be live, and allow the
            // number of authorities below it (its path length).
            let mut child = leaf.clone();
            for (index, link) in authority_chain(&tx, &authority).await?.iter().enumerate() {
                let issuer = X509Certificate::from_pem(&link.certificate_pem)
                    .ok_or_else(crate::js::internal_error)?;
                if !child.check_issued(&issuer) || !child.verify(issuer.public_key()) {
                    return Err(certificate_invalid("The certificate chain does not verify"));
                }
                if link.state != "active"
                    || link.not_after <= now
                    || link.not_before > now + 60_000.0
                {
                    return Err(certificate_invalid("An issuing authority is not active"));
                }
                if let Some(path_length) = link.path_length
                    && index as f64 > path_length
                {
                    return Err(certificate_invalid("The chain exceeds a path length"));
                }
                child = issuer;
            }
            if !child.verify(child.public_key()) {
                return Err(certificate_invalid("The root does not verify"));
            }
            // A workload certificate is only as good as the identity it names.
            if let Some(identity_id) = record.identity_id.as_deref().filter(|id| !id.is_empty()) {
                let identity = match tx.get("identities", identity_id).await? {
                    Some(found) => Some(crate::port::decode::<better_iam_core::Identity>(found)?),
                    None => None,
                };
                let standing = identity.is_some_and(|identity| {
                    identity.tenant_id == record.tenant_id
                        && identity.status == IdentityStatus::Active
                        && !ctx.identity_expired(&identity)
                        && !identity
                            .agent
                            .as_ref()
                            .is_some_and(|agent| agent.suspended.is_some())
                });
                if !standing {
                    return Err(certificate_invalid(
                        "The identity it names is no longer active",
                    ));
                }
            }
            Ok(CertificateVerification {
                tenant_id: record.tenant_id.clone(),
                authority_id: record.authority_id.clone(),
                serial_number: record.serial_number.clone(),
                fingerprint: record.fingerprint.clone(),
                subject: leaf.subject().unwrap_or_default(),
                dns_names: san_list(&leaf, "DNS"),
                uris: san_list(&leaf, "URI"),
                not_after: record.not_after,
                spiffe_id: record.spiffe_id.clone().filter(|id| !id.is_empty()),
                identity_id: record.identity_id.clone().filter(|id| !id.is_empty()),
            })
        })
        .await
}

/// The DER SubjectPublicKeyInfo of a KMS key version's public key (a PEM `PUBLIC KEY`).
pub fn spki_of(public_key_pem: &str) -> IamResult<Vec<u8>> {
    let body = public_key_pem
        .replacen("-----BEGIN PUBLIC KEY-----", "", 1)
        .replacen("-----END PUBLIC KEY-----", "", 1);
    let body: String = body
        .chars()
        .filter(|c| !core_js::is_js_whitespace(*c))
        .collect();
    let der = node_base64(&body);
    if crate::x509::PublicKey::from_spki(&der).is_none() {
        return Err(crate::js::internal_error());
    }
    Ok(der)
}

pub fn certificate_pem(der: &[u8]) -> String {
    pem("CERTIFICATE", der)
}

pub fn crl_pem(der: &[u8]) -> String {
    pem("X509 CRL", der)
}

/// The X.509 signature algorithm a KMS signing key uses for certificates.
pub fn algorithm_for_spec(spec: &str) -> IamResult<SignatureAlgorithm> {
    match spec {
        "ecc-p256" => Ok("ES256".into()),
        "ecc-p384" => Ok("ES384".into()),
        "ed25519" => Ok("EdDSA".into()),
        spec if spec.starts_with("rsa-") => Ok("RS256".into()),
        _ => Err(invalid(
            "A certificate authority needs an ECDSA, Ed25519 or RSA signing key",
        )),
    }
}
