//! Port of `packages/server/src/ssh.ts`.
//!
//! SSH certificate authority: people and machines get short-lived OpenSSH user certificates for exactly the hosts and
//! logins policies allow, hosts get certificates their clients trust, and hosts refuse revoked certificates through a
//! key revocation list. Each tenant has a user authority and a host authority (Ed25519, sealed with the deployment
//! secret). Access is an ordinary policy decision: `ssh:login` on `ssh-login/{host}/{login}` (attributes: the host's
//! labels plus `host` and `login`), and `ssh:port-forward` / `ssh:agent-forward` / `ssh:x11-forward` on
//! `ssh-host/{host}`. A certificate names each host it opens as the principal `{login}@{host}`, and every enrolled
//! host accepts, for each local login, only its own principal, so one certificate never opens a host it was not
//! issued for. A certificate lives only as long as the session that requested it and the grants that allowed it.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use better_iam_auth::crypto::{decrypt_secret, encrypt_secret};
use better_iam_auth::util::node_base64_decode;
use better_iam_core::{
    AttributeType, AuthenticatedPrincipal, Decision, Filter, FindOptions, IamError, IamPlugin,
    IamResult, IamStoreExt, Identity, IdentityStatus, OrderOptions, Record, ResourceTypeDefinition,
    Session, Tenant, TenantStatus, find_ordered, js as core_js, match_pattern,
};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::contracts::{PreparedDecision, decide_on, is_root_override};
use crate::decisions::module_resource_labels;
use crate::devices::with_device_key;
use crate::js::{internal_error, invalid_input, number, sort_strings, unique};
use crate::options::{BetterIamOptions, ResolvedResource, SshOptions, Toggle};
use crate::port::decode;
use crate::ssh_ca::{
    KrlAuthoritySection, SshKrlInput, build_ssh_krl, generate_ssh_authority_key, is_ip,
    parse_ssh_public_key, slice_utf16, ssh_fingerprint, ssh_key_line, ssh_login_principal,
    ssh_signing_key,
};
use crate::utils::id;

pub const SSH_LOGIN_RESOURCE_TYPE: &str = "ssh-login";
pub const SSH_HOST_RESOURCE_TYPE: &str = "ssh-host";
pub const SSH_LOGIN_ACTION: &str = "ssh:login";

/// Forwarding a certificate allows only when every host it names allows it (certificate extensions are global).
pub static SSH_FORWARDING_ACTIONS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"ssh:port-forward":"permit-port-forwarding","ssh:agent-forward":"permit-agent-forwarding","ssh:x11-forward":"permit-X11-forwarding"}),
);

/// [`SSH_FORWARDING_ACTIONS`] as pairs, in their order.
pub const SSH_FORWARDING_PAIRS: [(&str, &str); 3] = [
    ("ssh:port-forward", "permit-port-forwarding"),
    ("ssh:agent-forward", "permit-agent-forwarding"),
    ("ssh:x11-forward", "permit-X11-forwarding"),
];

const HOUR: f64 = 3_600_000.0;
const DAY: f64 = 86_400_000.0;
/// Certificates for agents acting for people (delegated sessions) are short: their confirmations are.
pub const DELEGATED_CERTIFICATE_MS: f64 = 600000.0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedSshOptions {
    #[serde(rename = "maxUserCertificateMs")]
    pub max_user_certificate_ms: f64,
    #[serde(rename = "hostCertificateMs")]
    pub host_certificate_ms: f64,
    #[serde(rename = "clockSkewMs")]
    pub clock_skew_ms: f64,
    #[serde(rename = "maxHostsPerCertificate")]
    pub max_hosts_per_certificate: f64,
    #[serde(rename = "recordRetentionMs")]
    pub record_retention_ms: f64,
    #[serde(rename = "joinTokenMs")]
    pub join_token_ms: f64,
    #[serde(rename = "issuanceLimit")]
    pub issuance_limit: f64,
}

fn bounded(value: Option<f64>, fallback: f64, min: f64, max: f64, name: &str) -> IamResult<f64> {
    let resolved = value.unwrap_or(fallback);
    if !core_js::is_safe_integer(resolved) || resolved < min || resolved > max {
        return Err(IamError::new(
            "INVALID_CONFIG",
            format!(
                "ssh.{name} must be an integer between {} and {}",
                core_js::number_to_string(min),
                core_js::number_to_string(max)
            ),
        ));
    }
    Ok(resolved)
}

/// Validates the `ssh` option; None when the module is off.
pub fn resolve_ssh_options(
    value: Option<&Toggle<SshOptions>>,
) -> IamResult<Option<ResolvedSshOptions>> {
    let options = match value {
        None | Some(Toggle::Flag(false)) => return Ok(None),
        Some(Toggle::Flag(true)) => SshOptions::default(),
        Some(Toggle::Options(options)) => options.clone(),
    };
    Ok(Some(ResolvedSshOptions {
        max_user_certificate_ms: bounded(
            options.max_user_certificate_ms,
            DAY,
            5.0 * 60_000.0,
            7.0 * DAY,
            "maxUserCertificateMs",
        )?,
        host_certificate_ms: bounded(
            options.host_certificate_ms,
            90.0 * DAY,
            DAY,
            365.0 * DAY,
            "hostCertificateMs",
        )?,
        clock_skew_ms: bounded(
            options.clock_skew_ms,
            5.0 * 60_000.0,
            0.0,
            HOUR,
            "clockSkewMs",
        )?,
        max_hosts_per_certificate: bounded(
            options.max_hosts_per_certificate,
            64.0,
            1.0,
            256.0,
            "maxHostsPerCertificate",
        )?,
        record_retention_ms: bounded(
            options.record_retention_days,
            90.0,
            1.0,
            3650.0,
            "recordRetentionDays",
        )? * DAY,
        join_token_ms: bounded(
            options.join_token_ms,
            DAY,
            5.0 * 60_000.0,
            30.0 * DAY,
            "joinTokenMs",
        )?,
        issuance_limit: bounded(
            options.issuance_limit,
            60.0,
            1.0,
            100_000.0,
            "issuanceLimit",
        )?,
    }))
}

/// The deployment's SSH settings, or None when `ssh` is off.
pub fn ssh_options(ctx: &ServerContext) -> IamResult<Option<ResolvedSshOptions>> {
    resolve_ssh_options(ctx.options.ssh.as_ref())
}

pub fn assert_ssh(ctx: &Arc<ServerContext>) -> IamResult<crate::ssh::ResolvedSshOptions> {
    ssh_options(ctx)?.ok_or_else(|| {
        IamError::with_status(
            "FEATURE_DISABLED",
            "The SSH certificate authority is not enabled on this deployment",
            403,
        )
    })
}

/// The `better-iam:ssh` plugin: the `ssh-login` and `ssh-host` resource types.
struct SshPlugin;

#[async_trait::async_trait]
impl IamPlugin for SshPlugin {
    fn id(&self) -> &str {
        "better-iam:ssh"
    }

    fn resource_types(&self) -> IndexMap<String, ResourceTypeDefinition> {
        let mut login_attributes = IndexMap::new();
        login_attributes.insert("host".to_owned(), AttributeType::String);
        login_attributes.insert("login".to_owned(), AttributeType::String);
        let mut host_attributes = IndexMap::new();
        host_attributes.insert("host".to_owned(), AttributeType::String);
        let mut types = IndexMap::new();
        types.insert(
            SSH_LOGIN_RESOURCE_TYPE.to_owned(),
            ResourceTypeDefinition {
                description: Some(
                    "Logging in to an enrolled SSH host as one local account: ssh-login/{host}/{login}"
                        .to_owned(),
                ),
                actions: Some(vec![SSH_LOGIN_ACTION.to_owned()]),
                attributes: Some(login_attributes),
                ..ResourceTypeDefinition::default()
            },
        );
        types.insert(
            SSH_HOST_RESOURCE_TYPE.to_owned(),
            ResourceTypeDefinition {
                description: Some(
                    "An enrolled SSH host, for the forwarding a certificate may allow: ssh-host/{host}"
                        .to_owned(),
                ),
                actions: Some(
                    SSH_FORWARDING_PAIRS
                        .iter()
                        .map(|(action, _)| (*action).to_owned())
                        .collect(),
                ),
                attributes: Some(host_attributes),
                ..ResourceTypeDefinition::default()
            },
        );
        types
    }
}

/// The catalog entries the module contributes when enabled: the `ssh-login` and `ssh-host` types and their actions.
pub fn ssh_plugins(options: &BetterIamOptions) -> IamResult<Vec<Arc<dyn IamPlugin>>> {
    if resolve_ssh_options(options.ssh.as_ref())?.is_none() {
        return Ok(Vec::new());
    }
    Ok(vec![Arc::new(SshPlugin)])
}

/// A tenant's SSH settings (collection `sshSettings`, one record per tenant, id = tenant ID).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshSettings {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// People must hold an MFA session to get a certificate (service accounts and agents are unaffected).
    #[serde(rename = "requireMfa")]
    pub require_mfa: bool,
    /// Only FIDO security keys (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`) are certified.
    #[serde(rename = "requireSecurityKey")]
    pub require_security_key: bool,
    /// Security-key certificates carry `verify-required`: the key must check its PIN or biometric at each login.
    #[serde(rename = "requireUserVerification")]
    pub require_user_verification: bool,
    /// Certificates carry `source-address` with the caller's IP, so they only work from where they were issued.
    #[serde(rename = "bindSourceAddress")]
    pub bind_source_address: bool,
    /// The lifetime when a request names none.
    #[serde(rename = "defaultCertificateMs")]
    pub default_certificate_ms: f64,
    /// The longest lifetime a request may ask for (never above the deployment's `maxUserCertificateMs`).
    #[serde(rename = "maxCertificateMs")]
    pub max_certificate_ms: f64,
    /// known_hosts patterns (`*.corp.example.com`, `10.20.*`, `!bastion.corp.example.com`) the host authority is
    /// trusted for; every host name and address must match them. Empty (the default): host names must be single labels,
    /// private addresses, or names under the organization's verified domains, and members' clients trust the authority
    /// for exactly the enrolled names.
    #[serde(rename = "hostPatterns")]
    pub host_patterns: Vec<String>,
    /// Increases with every revocation; the revocation lists' version.
    #[serde(rename = "revocationVersion")]
    pub revocation_version: f64,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    #[serde(rename = "updatedBy", default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `'user' | 'host'`.
pub type SshAuthorityKind = String;

/// An authority key. `active` signs; `pending` is published (trusted) ahead of a rotation so hosts and clients pick it
/// up before it signs; `previous` stays trusted after a rotation until its certificates have expired; `retired` is
/// trusted nowhere.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshAuthority {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    #[serde(rename = "kind")]
    pub kind: crate::ssh::SshAuthorityKind,
    /// `'pending' | 'active' | 'previous' | 'retired'`.
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "algorithm")]
    pub algorithm: String,
    /// The public key as an authorized_keys-style line.
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "fingerprint")]
    pub fingerprint: String,
    #[serde(rename = "keySealed")]
    pub key_sealed: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(
        rename = "activatedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub activated_at: Option<f64>,
    #[serde(rename = "rotatedAt", default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<f64>,
    #[serde(rename = "retiredAt", default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A server people SSH into. Its `name` is unique in the tenant and never changes; it is part of every principal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshHost {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// DNS names and addresses clients connect with; the host certificate names them (and `name`). Unique per tenant.
    #[serde(rename = "addresses")]
    pub addresses: Vec<String>,
    /// The local accounts people may be granted (`ssh-login/{name}/{login}`).
    #[serde(rename = "logins")]
    pub logins: Vec<String>,
    /// Free-form attributes for policies (`resource.environment`, ...).
    #[serde(rename = "labels")]
    pub labels: IndexMap<String, String>,
    /// `'pending' | 'enrolled' | 'disabled'`.
    #[serde(rename = "status")]
    pub status: String,
    #[serde(
        rename = "joinTokenHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub join_token_hash: Option<String>,
    #[serde(
        rename = "joinTokenExpiresAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub join_token_expires_at: Option<f64>,
    #[serde(
        rename = "renewalTokenHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub renewal_token_hash: Option<String>,
    /// The renewal token handed out before the current one, accepted until the host uses the new one.
    #[serde(
        rename = "previousRenewalTokenHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub previous_renewal_token_hash: Option<String>,
    /// The host's own public key once enrolled.
    #[serde(rename = "hostKey", default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    #[serde(
        rename = "hostKeyFingerprint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub host_key_fingerprint: Option<String>,
    #[serde(
        rename = "certificateId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_id: Option<String>,
    #[serde(
        rename = "certificateExpiresAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_expires_at: Option<f64>,
    #[serde(
        rename = "enrolledAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub enrolled_at: Option<f64>,
    #[serde(rename = "renewedAt", default, skip_serializing_if = "Option::is_none")]
    pub renewed_at: Option<f64>,
    /// Last enrollment or sync with this host's token.
    #[serde(
        rename = "lastSeenAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_seen_at: Option<f64>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `'revoked' | 'identity-revoked' | 'identity-inactive' | 'access-changed' | 'session-ended' | 'host-disabled' |
/// 'host-deleted' | 'addresses-changed' | 'superseded' | 'authority-retired' | 'tenant-revoked'`.
pub type SshRevocationReason = String;

/// One host a user certificate opens, with its logins.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshCertificateAccess {
    #[serde(rename = "host")]
    pub host: String,
    #[serde(rename = "logins")]
    pub logins: Vec<String>,
}

/// An issued certificate (collection `sshCertificates`); kept `recordRetentionDays` past its expiry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshCertificateRecord {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// `'user' | 'host'`.
    #[serde(rename = "kind")]
    pub kind: String,
    /// Decimal uint64.
    #[serde(rename = "serial")]
    pub serial: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "authorityId")]
    pub authority_id: String,
    /// User certificates: who it was issued to, the session it came from, and that session's MFA state.
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(
        rename = "sessionKind",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_kind: Option<String>,
    #[serde(rename = "mfa", default, skip_serializing_if = "Option::is_none")]
    pub mfa: Option<bool>,
    /// User certificates: the registered device key the issuing request proved (devices.ts), so the sweep judges device
    /// conditions by that device as it stands now; absent when the request proved none.
    #[serde(
        rename = "deviceKeyId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub device_key_id: Option<String>,
    /// Host certificates: the host.
    #[serde(rename = "hostId", default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(rename = "principals")]
    pub principals: Vec<String>,
    /// User certificates: the hosts and logins it opens.
    #[serde(rename = "access", default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Vec<SshCertificateAccess>>,
    #[serde(rename = "extensions")]
    pub extensions: Vec<String>,
    #[serde(
        rename = "sourceAddress",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_address: Option<String>,
    #[serde(rename = "keyType")]
    pub key_type: String,
    #[serde(rename = "publicKeyFingerprint")]
    pub public_key_fingerprint: String,
    /// Host certificates: the certified key, published as `@revoked` once the certificate is revoked.
    #[serde(rename = "publicKey", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(rename = "validAfter")]
    pub valid_after: f64,
    #[serde(rename = "validBefore")]
    pub valid_before: f64,
    #[serde(rename = "issuedAt")]
    pub issued_at: f64,
    #[serde(rename = "reason", default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedBy", default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(
        rename = "revocationReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revocation_reason: Option<String>,
    /// Host certificates: the certificate line, handed out again at each `syncHost`.
    #[serde(
        rename = "certificate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate: Option<String>,
    /// When the record itself is swept (retention.ts): `validBefore` plus the record retention.
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub const SSH_COLLECTIONS: [&str; 4] = [
    "sshSettings",
    "sshAuthorities",
    "sshHosts",
    "sshCertificates",
];

/// JSON numbers as JavaScript writes them: integral doubles become JSON integers.
fn normalize_numbers(value: Value) -> Value {
    match value {
        Value::Number(ref n) => match n.as_f64() {
            Some(float) if n.is_f64() => number(float),
            _ => value,
        },
        Value::Array(items) => Value::Array(items.into_iter().map(normalize_numbers).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, item)| (key, normalize_numbers(item)))
                .collect(),
        ),
        other => other,
    }
}

/// A typed record as the JSON object the store keeps.
fn to_record<T: Serialize>(value: &T) -> Record {
    match serde_json::to_value(value).map(normalize_numbers) {
        Ok(Value::Object(map)) => map,
        _ => Record::new(),
    }
}

fn decode_all<T: serde::de::DeserializeOwned>(records: Vec<Record>) -> IamResult<Vec<T>> {
    records.into_iter().map(decode).collect()
}

/// `{ ...filter }` of a JSON object as a store filter, in its member order.
fn filter_of(value: &Value) -> IamResult<Filter> {
    let Value::Object(map) = value else {
        return Err(internal_error());
    };
    let mut filter = Filter::new();
    for (key, item) in core_js::entries(map) {
        filter.set(key.clone(), Some(item.clone()));
    }
    Ok(filter)
}

pub fn default_ssh_settings(tenant_id: &str, options: &ResolvedSshOptions) -> SshSettings {
    SshSettings {
        id: tenant_id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        unique_key: None,
        require_mfa: false,
        require_security_key: false,
        require_user_verification: false,
        bind_source_address: false,
        default_certificate_ms: (8.0 * HOUR).min(options.max_user_certificate_ms),
        max_certificate_ms: (16.0 * HOUR).min(options.max_user_certificate_ms),
        host_patterns: Vec::new(),
        revocation_version: 0.0,
        updated_at: None,
        updated_by: None,
        extra: Map::new(),
    }
}

/// known_hosts pattern-list semantics (case-insensitive): some pattern matches and no negated (`!`) one does.
pub fn known_hosts_match(patterns: &[String], name: &str) -> bool {
    let value = core_js::to_lower(name);
    let mut matched = false;
    for raw in patterns {
        let pattern = core_js::to_lower(raw);
        let negated = pattern.starts_with('!');
        let glob = if negated { &pattern[1..] } else { &pattern[..] };
        if !match_pattern(glob, &value, None) {
            continue;
        }
        if negated {
            return false;
        }
        matched = true;
    }
    matched
}

/// The tenant's verified email/DNS domains (domains API), which bound the host names it may vouch for.
pub async fn verified_domains(tx: &Store, tenant_id: &str) -> IamResult<Vec<String>> {
    let records = tx
        .find(
            "tenantDomains",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("status", "verified"),
            &FindOptions::default(),
        )
        .await?;
    records
        .iter()
        .map(|record| match record.get("domain") {
            Some(Value::String(domain)) => Ok(core_js::to_lower(domain)),
            _ => Err(internal_error()),
        })
        .collect()
}

fn under_domain(name: &str, domains: &[String]) -> bool {
    domains
        .iter()
        .any(|domain| name == domain || name.ends_with(&format!(".{domain}")))
}

static IPV6_UNIQUE_LOCAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^f[cd][0-9a-f]{0,2}$").expect("regex"));
static IPV6_LINK_LOCAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^fe[89ab][0-9a-f]?$").expect("regex"));

/// Private, loopback, link-local and shared address space: never another organization's public address.
pub fn private_address(address: &str) -> bool {
    match is_ip(address) {
        4 => {
            let parts: Vec<f64> = address.split('.').map(core_js::string_to_number).collect();
            let (a, b) = (parts[0], parts[1]);
            a == 10.0
                || a == 127.0
                || (a == 172.0 && (16.0..=31.0).contains(&b))
                || (a == 192.0 && b == 168.0)
                || (a == 169.0 && b == 254.0)
                || (a == 100.0 && (64.0..=127.0).contains(&b))
        }
        6 => {
            let lowered = core_js::to_lower(address);
            let first = lowered.split(':').next().unwrap_or("");
            address == "::1" || IPV6_UNIQUE_LOCAL.is_match(first) || IPV6_LINK_LOCAL.is_match(first)
        }
        _ => false,
    }
}

static PATTERN_ITEM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^!?[a-zA-Z0-9.*?:_-]{1,253}$").expect("regex"));
static IPV4_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9.*?]*$").expect("regex"));
static IPV6_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f:*?]*$").expect("regex"));
static IPV6_PATTERN_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{1,4}:[0-9a-f]{1,4}:").expect("regex"));
static SHORT_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9*?-]+$").expect("regex"));
static HAS_ALNUM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9]").expect("regex"));

/// Validates `hostPatterns`: every positive pattern must pin a literal suffix the organization owns (a verified
/// domain such as `*.corp.example.com`) or a literal address prefix (`10.20.*`, `fd00:1:*`); `*` alone is refused.
pub fn host_pattern_list(value: Option<&Value>, domains: &[String]) -> IamResult<Vec<String>> {
    let items = match value {
        Some(Value::Array(items)) if items.len() <= 16 => items,
        _ => {
            return Err(invalid_input(
                "hostPatterns must list at most 16 known_hosts patterns",
            ));
        }
    };
    let mut lowered = Vec::new();
    for item in items {
        match item {
            Value::String(text) if PATTERN_ITEM.is_match(text) => {
                lowered.push(core_js::to_lower(text));
            }
            _ => {
                return Err(invalid_input(
                    "hostPatterns hold known_hosts patterns such as *.corp.example.com",
                ));
            }
        }
    }
    let patterns = unique(lowered);
    let positive: Vec<&String> = patterns
        .iter()
        .filter(|pattern| !pattern.starts_with('!'))
        .collect();
    if !patterns.is_empty() && positive.is_empty() {
        return Err(invalid_input(
            "hostPatterns needs at least one pattern that is not negated",
        ));
    }
    for pattern in positive {
        let wildcard = match (pattern.rfind('*'), pattern.rfind('?')) {
            (None, None) => None,
            (a, b) => a.max(b),
        };
        let ipv4 = IPV4_PATTERN.is_match(pattern);
        let ipv6 = IPV6_PATTERN.is_match(pattern);
        let suffix = match wildcard {
            None => &pattern[..],
            Some(at) => &pattern[at + 1..],
        };
        let dns = (wildcard.is_none() || suffix.starts_with('.'))
            && under_domain(suffix.strip_prefix('.').unwrap_or(suffix), domains);
        let literal_private = wildcard.is_none() && is_ip(pattern) > 0 && private_address(pattern);
        // Short (single-label) names such as `web-*` mean nothing outside the organization's network; `*` alone is
        // refused.
        let short_name =
            SHORT_NAME.is_match(pattern) && HAS_ALNUM.is_match(pattern) && pattern != "localhost";
        if !ipv4 && !ipv6 && !dns && !literal_private && !short_name {
            return Err(IamError::with_status(
                "HOST_OUTSIDE_PATTERNS",
                format!(
                    "Pattern {} must end in a verified domain of this organization or fix an address prefix",
                    slice_utf16(pattern, 64)
                ),
                400,
            ));
        }
    }
    Ok(patterns)
}

/// Refuses host names or addresses the organization cannot vouch for: outside its `hostPatterns` when it has any;
/// otherwise anything but single labels, private addresses, and names under its verified domains.
pub fn assert_vouchable(
    settings: &crate::ssh::SshSettings,
    domains: &[String],
    names: &[String],
) -> IamResult<()> {
    let patterns = &settings.host_patterns;
    // Patterns only narrow: `*` crosses dots, so a pattern alone never makes a foreign name vouchable.
    let ip_pattern = |name: &str| {
        patterns.iter().any(|pattern| {
            !pattern.starts_with('!')
                && (IPV4_PATTERN.is_match(pattern) || IPV6_PATTERN_PREFIX.is_match(pattern))
                && match_pattern(pattern, name, None)
        })
    };
    let outside: Vec<&String> = names
        .iter()
        .filter(|name| {
            if !patterns.is_empty() && !known_hosts_match(patterns, name) {
                return true;
            }
            if is_ip(name) != 0 {
                return !private_address(name) && !ip_pattern(name);
            }
            if !name.contains('.') {
                return name.as_str() == "localhost";
            }
            !under_domain(name, domains)
        })
        .collect();
    if !outside.is_empty() {
        return Err(IamError::with_status(
            "HOST_OUTSIDE_PATTERNS",
            format!(
                "{} is outside the names this organization can vouch for (verify its domain or set hostPatterns)",
                outside
                    .iter()
                    .take(5)
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            400,
        ));
    }
    Ok(())
}

async fn tenant_hosts(tx: &Store, tenant_id: &str) -> IamResult<Vec<SshHost>> {
    decode_all(
        tx.find(
            "sshHosts",
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions::default(),
        )
        .await?,
    )
}

/// Refuses names or addresses another host of the tenant already uses (any status).
pub async fn assert_names_free(
    tx: &Store,
    tenant_id: &str,
    names: &[String],
    host_id: Option<&str>,
) -> IamResult<()> {
    let wanted: IndexSet<&str> = names.iter().map(String::as_str).collect();
    for host in tenant_hosts(tx, tenant_id).await? {
        if Some(host.id.as_str()) == host_id {
            continue;
        }
        let taken = std::iter::once(&host.name)
            .chain(host.addresses.iter())
            .find(|name| wanted.contains(name.as_str()));
        if let Some(taken) = taken {
            return Err(IamError::with_status(
                "HOST_NAME_TAKEN",
                format!("Host {} already uses {taken}", host.name),
                409,
            ));
        }
    }
    Ok(())
}

/// Refuses a host key that is a tenant authority key or another host's key (a revocation of it would hit them).
pub async fn assert_host_key_free(
    tx: &Store,
    tenant_id: &str,
    host_id: &str,
    key: &crate::ssh_ca::SshPublicKey,
) -> IamResult<()> {
    if key.security_key {
        return Err(invalid_input("Host keys cannot be security keys"));
    }
    if tenant_authorities(tx, tenant_id, None)
        .await?
        .iter()
        .any(|authority| authority.fingerprint == key.fingerprint)
    {
        return Err(invalid_input("An authority key cannot be a host key"));
    }
    let other = tenant_hosts(tx, tenant_id).await?.into_iter().find(|host| {
        host.id != host_id && host.host_key_fingerprint.as_deref() == Some(&key.fingerprint)
    });
    if let Some(other) = other {
        return Err(IamError::with_status(
            "HOST_KEY_IN_USE",
            format!("Host {} already uses this key", other.name),
            409,
        ));
    }
    Ok(())
}

/// `Math.min` over JavaScript numbers (NaN wins).
fn js_min(values: &[f64]) -> f64 {
    values.iter().fold(f64::INFINITY, |result, value| {
        if result.is_nan() || value.is_nan() {
            f64::NAN
        } else {
            result.min(*value)
        }
    })
}

/// A stored member as a JavaScript number (`undefined` is NaN).
fn stored_number(record: &Record, key: &str) -> f64 {
    record.get(key).map(core_js::to_number).unwrap_or(f64::NAN)
}

pub async fn load_ssh_settings(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<crate::ssh::SshSettings> {
    let options = assert_ssh(ctx)?;
    let stored = tx.get("sshSettings", tenant_id).await?;
    let defaults = default_ssh_settings(tenant_id, &options);
    let Some(stored) =
        stored.filter(|stored| stored.get("tenantId").and_then(Value::as_str) == Some(tenant_id))
    else {
        return Ok(defaults);
    };
    // A deployment that lowered its maximum caps what tenants stored earlier.
    let stored_max = stored_number(&stored, "maxCertificateMs");
    let stored_default = stored_number(&stored, "defaultCertificateMs");
    let mut merged = to_record(&defaults);
    for (key, value) in stored {
        merged.insert(key, value);
    }
    merged.insert(
        "maxCertificateMs".into(),
        number(js_min(&[stored_max, options.max_user_certificate_ms])),
    );
    merged.insert(
        "defaultCertificateMs".into(),
        number(js_min(&[
            stored_default,
            stored_max,
            options.max_user_certificate_ms,
        ])),
    );
    decode(merged)
}

/// Stores a tenant's settings (the record exists once anything was changed or revoked).
pub async fn save_ssh_settings(
    tx: &Store,
    settings: &crate::ssh::SshSettings,
) -> IamResult<crate::ssh::SshSettings> {
    let record = to_record(settings);
    let saved = if tx.get("sshSettings", &settings.id).await?.is_some() {
        tx.put("sshSettings", &record).await?
    } else {
        tx.insert("sshSettings", &record).await?
    };
    decode(saved)
}

/// Bumps the revocation list version after a revocation.
pub async fn bump_revocation_version(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<()> {
    let settings = load_ssh_settings(ctx, tx, tenant_id).await?;
    let revocation_version = settings.revocation_version + 1.0;
    save_ssh_settings(
        tx,
        &SshSettings {
            revocation_version,
            ..settings
        },
    )
    .await?;
    Ok(())
}

fn authority_context(authority_id: &str) -> String {
    format!("ssh-authority:{authority_id}")
}

pub async fn tenant_authorities(
    tx: &Store,
    tenant_id: &str,
    kind: Option<&str>,
) -> IamResult<Vec<crate::ssh::SshAuthority>> {
    let mut filter = Filter::new().eq("tenantId", tenant_id);
    if let Some(kind) = kind.filter(|kind| !kind.is_empty()) {
        filter = filter.eq("kind", kind);
    }
    let mut found: Vec<SshAuthority> = decode_all(
        tx.find("sshAuthorities", &filter, &FindOptions::default())
            .await?,
    )?;
    // User authorities first, then oldest first.
    found.sort_by(|a, b| {
        let by_kind = if a.kind == b.kind {
            0.0
        } else if a.kind == "user" {
            -1.0
        } else {
            1.0
        };
        let order = if by_kind != 0.0 {
            by_kind
        } else {
            let by_age = a.created_at - b.created_at;
            if by_age != 0.0 && !by_age.is_nan() {
                by_age
            } else if core_js::cmp_utf16(&a.id, &b.id) == std::cmp::Ordering::Less {
                -1.0
            } else {
                1.0
            }
        };
        order.partial_cmp(&0.0).unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(found)
}

/// Creates an authority key, sealed under the deployment secret.
pub async fn create_authority(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    kind: &str,
    status: &str,
    actor_id: &str,
) -> IamResult<crate::ssh::SshAuthority> {
    let key = generate_ssh_authority_key();
    let authority_id = id();
    let mut record = Record::new();
    record.insert("id".into(), Value::String(authority_id.clone()));
    record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    record.insert("kind".into(), Value::String(kind.to_owned()));
    record.insert("status".into(), Value::String(status.to_owned()));
    record.insert("algorithm".into(), Value::String("ssh-ed25519".into()));
    record.insert(
        "publicKey".into(),
        Value::String(ssh_key_line(
            &key.public_blob,
            Some(&format!("better-iam-{kind}-ca")),
        )?),
    );
    record.insert(
        "fingerprint".into(),
        Value::String(ssh_fingerprint(&key.public_blob)),
    );
    record.insert("keySealed".into(), Value::String(String::new()));
    record.insert("createdAt".into(), number(ctx.now()));
    record.insert("createdBy".into(), Value::String(actor_id.to_owned()));
    if status == "active" {
        record.insert("activatedAt".into(), number(ctx.now()));
    }
    record.insert(
        "keySealed".into(),
        Value::String(encrypt_secret(
            &key.private_pkcs8,
            &ctx.options.secret,
            &authority_context(&authority_id),
        )),
    );
    decode(tx.insert("sshAuthorities", &record).await?)
}

/// The authorities [`ensure_authorities`] returns: the active ones, and the kinds it had to create.
#[derive(Debug, Clone, PartialEq)]
pub struct EnsuredAuthorities {
    pub user: SshAuthority,
    pub host: SshAuthority,
    pub created: Vec<SshAuthorityKind>,
}

/// Creates the tenant's user and host authorities when missing; returns the active ones.
pub async fn ensure_authorities(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    actor_id: &str,
) -> IamResult<EnsuredAuthorities> {
    let mut created = Vec::new();
    let mut active = Vec::new();
    for kind in ["user", "host"] {
        let existing = tenant_authorities(tx, tenant_id, Some(kind))
            .await?
            .into_iter()
            .find(|item| item.status == "active");
        match existing {
            Some(existing) => active.push(existing),
            None => {
                created.push(kind.to_owned());
                active.push(create_authority(ctx, tx, tenant_id, kind, "active", actor_id).await?);
            }
        }
    }
    let host = active.pop().ok_or_else(internal_error)?;
    let user = active.pop().ok_or_else(internal_error)?;
    Ok(EnsuredAuthorities {
        user,
        host,
        created,
    })
}

/// The active authority of a kind, or SSH_NOT_CONFIGURED.
pub async fn active_authority(
    tx: &Store,
    tenant_id: &str,
    kind: &str,
) -> IamResult<crate::ssh::SshAuthority> {
    tenant_authorities(tx, tenant_id, Some(kind))
        .await?
        .into_iter()
        .find(|item| item.status == "active")
        .ok_or_else(|| {
            IamError::with_status(
                "SSH_NOT_CONFIGURED",
                "Set up the SSH certificate authority first (ssh.setup)",
                409,
            )
        })
}

/// The authority's public key blob (`publicBlobOf`).
pub fn public_blob_of(public_key: &str) -> IamResult<Vec<u8>> {
    // `Buffer.from(undefined, 'base64')` throws a TypeError.
    let data = public_key.split(' ').nth(1).ok_or_else(internal_error)?;
    Ok(node_base64_decode(data))
}

/// Opens an authority's signing key.
pub fn open_authority(
    ctx: &Arc<ServerContext>,
    authority: &crate::ssh::SshAuthority,
) -> IamResult<crate::ssh_ca::SshSigningKey> {
    let mut secrets = vec![ctx.options.secret.clone()];
    secrets.extend(ctx.options.previous_secrets.iter().flatten().cloned());
    ssh_signing_key(
        &public_blob_of(&authority.public_key)?,
        &decrypt_secret(
            &authority.key_sealed,
            &secrets,
            &authority_context(&authority.id),
        )?,
    )
}

/// Keys hosts and clients trust: pending (ahead of a rotation), active, and previous (until retired).
pub const TRUSTED_STATUSES: [&str; 3] = ["pending", "active", "previous"];

static HOST_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$").expect("regex"));

/// Host names: lowercase letters, digits, dots and hyphens (no `/`, `@` or wildcards, so they can sit in
/// principals).
pub fn ssh_host_name(value: Option<&Value>) -> IamResult<String> {
    let Some(Value::String(value)) = value else {
        return Err(invalid_input("Invalid host name"));
    };
    let name = core_js::to_lower(core_js::trim(value));
    let last = name.split('.').next_back().unwrap_or("");
    if !HOST_NAME.is_match(&name)
        || name.contains("..")
        // A dotted name ending in digits would read as an address (`127.1`).
        || (name.contains('.') && !last.is_empty() && last.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(invalid_input(
            "Host names use 1-128 lowercase letters, digits, \".\" or \"-\"",
        ));
    }
    Ok(name)
}

const RESERVED_LABELS: [&str; 10] = [
    "host",
    "login",
    "tenantId",
    "name",
    "status",
    "id",
    "type",
    "ownerId",
    "parentId",
    "parentType",
];

/// `/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/`.
fn label_name(key: &str) -> bool {
    let bytes = key.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

/// Host labels: at most 32 `name: value` pairs; the names policies read as `resource.{name}`.
pub fn ssh_labels(value: Option<&Value>) -> IamResult<IndexMap<String, String>> {
    let map = match value {
        None => return Ok(IndexMap::new()),
        Some(Value::Object(map)) => map,
        Some(_) => return Err(invalid_input("labels must be an object of strings")),
    };
    let entries = core_js::entries(map);
    if entries.len() > 32 {
        return Err(invalid_input("A host has at most 32 labels"));
    }
    let mut labels = IndexMap::new();
    for (key, item) in entries {
        if !label_name(key) || RESERVED_LABELS.contains(&key.as_str()) {
            return Err(invalid_input(format!(
                "Invalid or reserved label name {}",
                slice_utf16(key, 64)
            )));
        }
        match item {
            Value::String(text)
                if core_js::utf16_len(text) <= 256 && !text.chars().any(|c| (c as u32) < 0x20) =>
            {
                labels.insert(key.clone(), text.clone());
            }
            _ => {
                return Err(invalid_input(format!(
                    "Label {key} must be a string of at most 256 characters"
                )));
            }
        }
    }
    Ok(labels)
}

pub async fn host_by_name(
    tx: &Store,
    tenant_id: &str,
    name: &str,
) -> IamResult<Option<crate::ssh::SshHost>> {
    let found = tx
        .find(
            "sshHosts",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("uniqueKey", name),
            &FindOptions::default(),
        )
        .await?;
    found.into_iter().next().map(decode).transpose()
}

fn label_attributes(host: &SshHost) -> Map<String, Value> {
    host.labels
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect()
}

/// What policies see for `ssh-login/{host}/{login}`.
pub fn login_resource(host: &crate::ssh::SshHost, login: &str) -> crate::options::ResolvedResource {
    let mut attributes = label_attributes(host);
    attributes.insert("host".into(), Value::String(host.name.clone()));
    attributes.insert("login".into(), Value::String(login.to_owned()));
    ResolvedResource {
        tenant_id: host.tenant_id.clone(),
        kind: SSH_LOGIN_RESOURCE_TYPE.to_owned(),
        id: format!("{}/{login}", host.name),
        attributes: Some(attributes),
        classification: None,
    }
}

/// What policies see for `ssh-host/{host}`.
pub fn host_resource(host: &crate::ssh::SshHost) -> crate::options::ResolvedResource {
    let mut attributes = label_attributes(host);
    attributes.insert("host".into(), Value::String(host.name.clone()));
    ResolvedResource {
        tenant_id: host.tenant_id.clone(),
        kind: SSH_HOST_RESOURCE_TYPE.to_owned(),
        id: host.name.clone(),
        attributes: Some(attributes),
        classification: None,
    }
}

/// Resolves `ssh-login/{host}/{login}` and `ssh-host/{host}` for the decision engine (so `authorize`, `whoCan` and
/// `simulate` work on them); undefined for other types. Unknown hosts and logins are NOT_FOUND.
pub async fn resolve_ssh_resource(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    reference: &better_iam_core::ResourceRef,
) -> IamResult<Option<crate::options::ResolvedResource>> {
    if reference.kind != SSH_LOGIN_RESOURCE_TYPE && reference.kind != SSH_HOST_RESOURCE_TYPE {
        return Ok(None);
    }
    if ssh_options(ctx)?.is_none() {
        return Ok(None);
    }
    let slash = reference.id.find('/').filter(|slash| *slash > 0);
    let name = if reference.kind == SSH_HOST_RESOURCE_TYPE {
        reference.id.as_str()
    } else {
        slash.map(|slash| &reference.id[..slash]).unwrap_or("")
    };
    let host = if name.is_empty() {
        None
    } else {
        host_by_name(tx, &reference.tenant_id, name).await?
    };
    let Some(host) = host else {
        return Err(IamError::with_status("NOT_FOUND", "Unknown SSH host", 404));
    };
    if reference.kind == SSH_HOST_RESOURCE_TYPE {
        return Ok(Some(host_resource(&host)));
    }
    let login = slash.map(|slash| &reference.id[slash + 1..]).unwrap_or("");
    if !host.logins.iter().any(|item| item == login) {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Unknown login on this host",
            404,
        ));
    }
    Ok(Some(login_resource(&host, login)))
}

/// The per-host principals file lines: one file per login holding `{login}@{host}`.
pub fn principal_files(host: &crate::ssh::SshHost) -> IndexMap<String, String> {
    host.logins
        .iter()
        .map(|login| {
            (
                login.clone(),
                format!("{}\n", ssh_login_principal(login, &host.name)),
            )
        })
        .collect()
}

/// Whether the tenant and every ancestor are active.
pub async fn tenant_active(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    tenant: &better_iam_core::Tenant,
) -> IamResult<bool> {
    Ok(ctx
        .ancestry(reader, tenant)
        .await?
        .iter()
        .all(|item| item.status == TenantStatus::Active))
}

/// `line.split(' ').slice(0, 2).join(' ')`.
fn first_two_words(line: &str) -> String {
    line.split(' ').take(2).collect::<Vec<_>>().join(" ")
}

/// Host keys clients must refuse: the current key of disabled hosts and the keys of unexpired revoked host
/// certificates that no enrolled host uses any more (a rebuilt or deleted host's old key). Never an authority key.
async fn revoked_host_keys(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    tenant_id: &str,
) -> IamResult<Vec<String>> {
    let now = ctx.now();
    let hosts = tenant_hosts(reader, tenant_id).await?;
    let in_use: IndexSet<&str> = hosts
        .iter()
        .filter(|host| host.status == "enrolled")
        .filter_map(|host| host.host_key_fingerprint.as_deref())
        .filter(|fingerprint| !fingerprint.is_empty())
        .collect();
    let authorities: Vec<String> = tenant_authorities(reader, tenant_id, None)
        .await?
        .into_iter()
        .map(|item| item.fingerprint)
        .collect();
    let mut lines: IndexMap<String, String> = IndexMap::new();
    for host in &hosts {
        if let (Some(key), Some(fingerprint)) = (&host.host_key, &host.host_key_fingerprint)
            && host.status == "disabled"
            && !key.is_empty()
            && !fingerprint.is_empty()
        {
            lines.insert(fingerprint.clone(), key.clone());
        }
    }
    for record in live_records(ctx, reader, tenant_id).await? {
        if let Some(public_key) = &record.public_key
            && record.kind == "host"
            && record.revoked_at.is_some()
            && !public_key.is_empty()
            && record.valid_before > now
            && !in_use.contains(record.public_key_fingerprint.as_str())
        {
            lines.insert(record.public_key_fingerprint.clone(), public_key.clone());
        }
    }
    for fingerprint in &authorities {
        lines.shift_remove(fingerprint);
    }
    Ok(lines.values().map(|line| first_two_words(line)).collect())
}

/// Trust material. `public` (anyone with the tenant ID): the authority keys, and a known_hosts line only for
/// configured `hostPatterns`. `member` (members and hosts): the known_hosts line for the enrolled names as well,
/// and `@revoked` lines for host keys clients must refuse.
pub async fn trust_bundle(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    tenant: &better_iam_core::Tenant,
    audience: &str,
) -> IamResult<Value> {
    let settings = load_ssh_settings(ctx, reader, &tenant.id).await?;
    let authorities = tenant_authorities(reader, &tenant.id, None).await?;
    let trusted = |kind: &str| -> Vec<&SshAuthority> {
        authorities
            .iter()
            .filter(|item| item.kind == kind && TRUSTED_STATUSES.contains(&item.status.as_str()))
            .collect()
    };
    let user_authorities = trusted("user");
    let host_authorities = trusted("host");
    let mut patterns = settings.host_patterns.clone();
    if patterns.is_empty() && audience == "member" {
        let enrolled: Vec<SshHost> = decode_all(
            reader
                .find(
                    "sshHosts",
                    &Filter::new()
                        .eq("tenantId", tenant.id.as_str())
                        .eq("status", "enrolled"),
                    &FindOptions::default(),
                )
                .await?,
        )?;
        patterns = unique(
            enrolled
                .into_iter()
                .flat_map(|host| std::iter::once(host.name).chain(host.addresses)),
        );
        sort_strings(&mut patterns);
    }
    let comment = format!("better-iam:{}", tenant.id);
    let mut known_hosts: Vec<String> = Vec::new();
    if !patterns.is_empty() {
        for authority in &host_authorities {
            known_hosts.push(format!(
                "@cert-authority {} {} {comment}",
                patterns.join(","),
                first_two_words(&authority.public_key)
            ));
        }
    }
    if audience == "member" {
        for key in revoked_host_keys(ctx, reader, &tenant.id).await? {
            known_hosts.push(format!("@revoked * {key} better-iam:revoked"));
        }
    }
    let view = |item: &&SshAuthority| {
        json!({
            "id": item.id,
            "status": item.status,
            "publicKey": item.public_key,
            "fingerprint": item.fingerprint,
        })
    };
    Ok(json!({
        "tenantId": tenant.id,
        // For hosts: sshd `TrustedUserCAKeys`.
        "userAuthorities": user_authorities.iter().map(view).collect::<Vec<_>>(),
        // For clients: known_hosts `@cert-authority` lines.
        "hostAuthorities": host_authorities.iter().map(view).collect::<Vec<_>>(),
        "hostPatterns": settings.host_patterns,
        "trustedUserCaKeys": user_authorities
            .iter()
            .map(|item| format!("{}\n", item.public_key))
            .collect::<String>(),
        "knownHosts": known_hosts.iter().map(|line| format!("{line}\n")).collect::<String>(),
    }))
}

/// Unexpired certificate records of a tenant (plus some recently expired ones), read through the expiry index:
/// `expiresAt` is `validBefore` plus a retention of at least a day, so a record still valid has `expiresAt` over a day
/// ahead.
pub async fn live_records(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    tenant_id: &str,
) -> IamResult<Vec<SshCertificateRecord>> {
    let now = ctx.now();
    let records = find_ordered(
        reader.as_ref(),
        "sshCertificates",
        &Filter::new().eq("tenantId", tenant_id),
        &OrderOptions {
            from: Some(now + DAY),
            ..OrderOptions::by("expiresAt")
        },
        None,
    )
    .await?;
    Ok(decode_all::<SshCertificateRecord>(records)?
        .into_iter()
        .filter(|record| record.valid_before > now)
        .collect())
}

/// Certificate records that are still valid and not revoked.
pub async fn live_certificates(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    filter: &Value,
) -> IamResult<Vec<crate::ssh::SshCertificateRecord>> {
    let now = ctx.now();
    let filter = filter_of(filter)?.absent("revokedAt");
    Ok(decode_all::<SshCertificateRecord>(
        tx.find("sshCertificates", &filter, &FindOptions::default())
            .await?,
    )?
    .into_iter()
    .filter(|record| record.valid_before > now)
    .collect())
}

/// Marks one certificate revoked (idempotent); the caller bumps the revocation version.
pub async fn mark_revoked(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    record: &crate::ssh::SshCertificateRecord,
    reason: &str,
    actor_id: &str,
) -> IamResult<crate::ssh::SshCertificateRecord> {
    if record.revoked_at.is_some() {
        return Ok(record.clone());
    }
    let mut updated = to_record(record);
    updated.insert("revokedAt".into(), number(ctx.now()));
    updated.insert("revokedBy".into(), Value::String(actor_id.to_owned()));
    updated.insert("revocationReason".into(), Value::String(reason.to_owned()));
    decode(tx.put("sshCertificates", &updated).await?)
}

/// `activeIdentity(ctx, identity)`.
fn active_identity(ctx: &ServerContext, identity: Option<&Identity>) -> bool {
    identity.is_some_and(|identity| {
        identity.status == IdentityStatus::Active && !ctx.identity_expired(identity)
    })
}

/// A stored identity, as the checks above read it (a record that is not an identity reads as none).
async fn stored_identity(reader: &Store, identity_id: &str) -> IamResult<Option<Identity>> {
    Ok(reader
        .get("identities", identity_id)
        .await?
        .and_then(|record| decode::<Identity>(record).ok()))
}

/// `session.identityId !== identityId` on a stored session.
fn other_identity(session: &Record, identity_id: Option<&str>) -> bool {
    match (session.get("identityId"), identity_id) {
        (Some(Value::String(stored)), Some(identity_id)) => stored != identity_id,
        (None, None) => false,
        _ => true,
    }
}

/// `BigInt(serial)` of a stored decimal serial.
fn serial_of(serial: &str) -> IamResult<u64> {
    let trimmed = core_js::trim(serial);
    if trimmed.is_empty() {
        return Ok(0);
    }
    trimmed.parse::<u64>().map_err(|_| internal_error())
}

/// A tenant's binary key revocation list. - `user` (sshd `RevokedKeys`): the serials of unexpired user certificates
/// that were revoked, whose holder is no longer active or whose session is gone (even before the sweep marks them),
/// or all of them while the tenant or an ancestor is suspended. - `host` (ssh `RevokedHostKeys` on clients):
/// revoked host certificate serials and host keys clients must refuse.
pub async fn revocation_list(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    tenant: &better_iam_core::Tenant,
    kind: Option<&str>,
) -> IamResult<Value> {
    let kind = kind.unwrap_or("user");
    let settings = load_ssh_settings(ctx, reader, &tenant.id).await?;
    let now = ctx.now();
    let active = tenant_active(ctx, reader, tenant).await?;
    let records: Vec<SshCertificateRecord> = live_records(ctx, reader, &tenant.id)
        .await?
        .into_iter()
        .filter(|record| record.kind == kind)
        .collect();
    let mut identities: HashMap<String, bool> = HashMap::new();
    let mut by_serial: IndexMap<String, Vec<u64>> = IndexMap::new();
    let mut revoked = 0u64;
    for record in &records {
        let mut dead = record.revoked_at.is_some() || (kind == "user" && !active);
        if let Some(identity_id) = record.identity_id.as_deref().filter(|_| !dead)
            && !identity_id.is_empty()
        {
            if !identities.contains_key(identity_id) {
                let identity = stored_identity(reader, identity_id).await?;
                identities.insert(
                    identity_id.to_owned(),
                    active_identity(ctx, identity.as_ref()),
                );
            }
            dead = !identities.get(identity_id).copied().unwrap_or(false);
        }
        if let Some(session_id) = record.session_id.as_deref().filter(|_| !dead)
            && !session_id.is_empty()
        {
            dead = match reader.get("sessions", session_id).await? {
                None => true,
                Some(session) => {
                    stored_number(&session, "expiresAt") <= now
                        || other_identity(&session, record.identity_id.as_deref())
                }
            };
        }
        if !dead {
            continue;
        }
        revoked += 1;
        by_serial
            .entry(record.authority_id.clone())
            .or_default()
            .push(serial_of(&record.serial)?);
    }
    let authorities: IndexMap<String, SshAuthority> = tenant_authorities(reader, &tenant.id, None)
        .await?
        .into_iter()
        .map(|item| (item.id.clone(), item))
        .collect();
    let keys: Vec<Vec<u8>> = if kind == "host" {
        revoked_host_keys(ctx, reader, &tenant.id)
            .await?
            .iter()
            .map(|line| public_blob_of(line))
            .collect::<IamResult<_>>()?
    } else {
        Vec::new()
    };
    let mut sections = Vec::new();
    for (authority_id, serials) in by_serial {
        if let Some(authority) = authorities.get(&authority_id) {
            sections.push(KrlAuthoritySection {
                authority: public_blob_of(&authority.public_key)?,
                serials,
                key_ids: Vec::new(),
            });
        }
    }
    let krl = build_ssh_krl(&SshKrlInput {
        version: settings.revocation_version as u64,
        generated_at: now,
        comment: Some(format!("better-iam:{}:{kind}", tenant.id)),
        authorities: sections,
        keys: keys.clone(),
    });
    Ok(json!({
        "tenantId": tenant.id,
        "kind": kind,
        "version": number(settings.revocation_version),
        "generatedAt": number(now),
        "tenantActive": active,
        "revokedCertificates": revoked,
        "revokedHostKeys": keys.len(),
        // The KRL, base64: write it (decoded) to the file sshd's `RevokedKeys` (or ssh's `RevokedHostKeys`) names.
        "krl": STANDARD.encode(krl),
    }))
}

/// The latest a certificate may be valid until given the caller's time-limited grants of `ssh:login`
/// (grant-deadline.ts).
pub async fn grant_deadline(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    tenant_id: &str,
    horizon: f64,
) -> IamResult<f64> {
    crate::grant_deadline::grant_deadline(ctx, tx, principal, tenant_id, horizon, SSH_LOGIN_ACTION)
        .await
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshSweepResult {
    #[serde(rename = "examined")]
    pub examined: f64,
    #[serde(rename = "revoked")]
    pub revoked: f64,
    /// Revocations per reason, in the order the reasons first occurred.
    #[serde(rename = "byReason")]
    pub by_reason: Value,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Per issuing session: its decision, `Ended` when it no longer validates, `Skip` while its tenant is suspended.
enum SessionState {
    Prepared(PreparedDecision),
    Ended,
    Skip,
}

/// What the sweep did in one tenant.
#[derive(Default)]
struct TenantSweep {
    examined: u64,
    revocations: Vec<String>,
}

/// The decision a certificate's issuing session gets now (the `try` block of the sweep).
async fn session_state(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    identity: &Identity,
    session: Record,
    device_key_id: Option<&str>,
    tenant: &Tenant,
) -> IamResult<SessionState> {
    let session: Session = decode(session)?;
    // The same validation every request gets: revocations, expiry and idle limits, authority chains, delegations
    // and their confirmations, network rules.
    let current = ctx
        .principals()?
        .current_principal(
            tx,
            &AuthenticatedPrincipal {
                identity: identity.clone(),
                session,
                device_proof: None,
            },
        )
        .await?;
    // With no request to carry a proof, device conditions judge the device the issuing request proved.
    let principal = match device_key_id {
        Some(key_id) if !key_id.is_empty() => with_device_key(&current, key_id)?,
        _ => current,
    };
    let mut state = ctx
        .decisions()?
        .prepare_decision(tx, &principal, tenant, SSH_LOGIN_ACTION)
        .await?;
    if is_root_override(&state) && principal.identity.tenant_id != tenant.id {
        state = PreparedDecision::Fixed(Decision {
            allowed: false,
            reason: "ROOT_SSH_RESTRICTED".into(),
            matched: Vec::new(),
        });
    }
    Ok(SessionState::Prepared(state))
}

async fn sweep_tenant(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<TenantSweep> {
    let mut outcome = TenantSweep::default();
    let Some(tenant) = tx.get("tenants", tenant_id).await? else {
        return Ok(outcome);
    };
    let tenant: Tenant = decode(tenant)?;
    let records =
        live_certificates(ctx, tx, &json!({ "tenantId": tenant_id, "kind": "user" })).await?;
    let mut hosts: IndexMap<String, SshHost> = IndexMap::new();
    for host in tenant_hosts(tx, tenant_id).await? {
        hosts.insert(host.name.clone(), host);
    }
    // With security clearances, the hosts' resources carry their classification labels, as `resolve` attaches them.
    let resources: Vec<ResolvedResource> = if records.is_empty() {
        Vec::new()
    } else {
        hosts
            .values()
            .flat_map(|host| {
                std::iter::once(host_resource(host))
                    .chain(host.logins.iter().map(|login| login_resource(host, login)))
            })
            .collect()
    };
    let labeled = module_resource_labels(ctx, tx, tenant_id, &resources).await?;
    let mut decisions: HashMap<String, SessionState> = HashMap::new();
    let mut changed = false;
    for record in &records {
        outcome.examined += 1;
        let identity = match record.identity_id.as_deref().filter(|id| !id.is_empty()) {
            Some(identity_id) => stored_identity(tx, identity_id).await?,
            None => None,
        };
        let mut reason: Option<&str> = None;
        match identity
            .as_ref()
            .filter(|identity| active_identity(ctx, Some(identity)))
        {
            None => reason = Some("identity-inactive"),
            Some(identity) => {
                let key = format!(
                    "{} {}",
                    record.session_id.as_deref().unwrap_or(""),
                    record.device_key_id.as_deref().unwrap_or("")
                );
                if !decisions.contains_key(&key) {
                    let session = match record.session_id.as_deref().filter(|id| !id.is_empty()) {
                        Some(session_id) => tx.get("sessions", session_id).await?,
                        None => None,
                    };
                    let mut state = SessionState::Ended;
                    if let Some(session) = session
                        && !other_identity(&session, Some(&identity.id))
                    {
                        state = match session_state(
                            ctx,
                            tx,
                            identity,
                            session,
                            record.device_key_id.as_deref(),
                            &tenant,
                        )
                        .await
                        {
                            Ok(state) => state,
                            // A suspended tenant is refused by the revocation list itself; its certificates return
                            // with it.
                            Err(error) if error.code == "TENANT_INACTIVE" => SessionState::Skip,
                            Err(_) => SessionState::Ended,
                        };
                    }
                    decisions.insert(key.clone(), state);
                }
                match decisions.get(&key) {
                    Some(SessionState::Skip) => continue,
                    Some(SessionState::Ended) | None => reason = Some("session-ended"),
                    Some(SessionState::Prepared(prepared)) => {
                        let decide =
                            |resource: &ResolvedResource, action: &str| -> IamResult<bool> {
                                Ok(decide_on(prepared, &labeled.apply(resource), Some(action))?
                                    .allowed)
                            };
                        let access = record.access.as_deref().unwrap_or(&[]);
                        let named: Vec<&SshHost> = access
                            .iter()
                            .filter_map(|entry| hosts.get(&entry.host))
                            .collect();
                        let mut login_lost = false;
                        'access: for entry in access {
                            // A deleted host takes nothing away; its principals open nothing any more.
                            let Some(host) = hosts.get(&entry.host) else {
                                continue;
                            };
                            for login in &entry.logins {
                                if !host.logins.contains(login)
                                    || !decide(&login_resource(host, login), SSH_LOGIN_ACTION)?
                                {
                                    login_lost = true;
                                    break 'access;
                                }
                            }
                        }
                        let mut forwarding_lost = false;
                        'forwarding: for (action, extension) in SSH_FORWARDING_PAIRS {
                            if !record.extensions.iter().any(|item| item == extension) {
                                continue;
                            }
                            for host in &named {
                                if !decide(&host_resource(host), action)? {
                                    forwarding_lost = true;
                                    break 'forwarding;
                                }
                            }
                        }
                        if login_lost || forwarding_lost {
                            reason = Some("access-changed");
                        }
                    }
                }
            }
        }
        let Some(reason) = reason else {
            continue;
        };
        mark_revoked(ctx, tx, record, reason, "deployment-operator").await?;
        let mut metadata = Map::new();
        metadata.insert("reason".into(), Value::String(reason.to_owned()));
        metadata.insert("serial".into(), Value::String(record.serial.clone()));
        metadata.insert(
            "identityId".into(),
            record
                .identity_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        let mut event = Record::new();
        event.insert("id".into(), Value::String(id()));
        event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
        event.insert(
            "actorId".into(),
            Value::String("deployment-operator".into()),
        );
        event.insert(
            "action".into(),
            Value::String("ssh:certificate:revoke".into()),
        );
        event.insert(
            "resourceId".into(),
            Value::String(format!("ssh/certificates/{}", record.id)),
        );
        event.insert("outcome".into(), Value::String("allow".into()));
        event.insert("timestamp".into(), number(ctx.now()));
        event.insert("metadata".into(), Value::Object(metadata));
        ctx.events()?.record_audit(tx, &event).await?;
        outcome.revocations.push(reason.to_owned());
        changed = true;
    }
    if changed {
        bump_revocation_version(ctx, tx, tenant_id).await?;
    }
    Ok(outcome)
}

/// Continuous authorization for certificates already issued: revokes live user certificates whose holder is no
/// longer active, whose issuing session (user session, API key, role session, session token or delegated session)
/// was revoked, ended or no longer validates, or whose hosts, logins and forwarding policies no longer allow as
/// decided for that very session. A scheduler job (`iam.ssh.sweep`); hosts pick the result up with their next
/// revocation list.
pub async fn sweep_ssh_certificates(
    ctx: &Arc<ServerContext>,
    input: Option<&Value>,
) -> IamResult<crate::ssh::SshSweepResult> {
    assert_ssh(ctx)?;
    let mut examined = 0u64;
    let mut revoked = 0u64;
    let mut by_reason: IndexMap<String, u64> = IndexMap::new();
    let requested = crate::js::member(input, "tenantId");
    let tenant_ids: Vec<String> = if crate::js::truthy(requested) {
        vec![crate::js::js_string(requested)]
    } else {
        let records: Vec<SshCertificateRecord> = decode_all(
            ctx.store
                .find(
                    "sshCertificates",
                    &Filter::new().eq("kind", "user").absent("revokedAt"),
                    &FindOptions::default(),
                )
                .await?,
        )?;
        unique(
            records
                .into_iter()
                .filter(|record| record.valid_before > ctx.now())
                .map(|record| record.tenant_id),
        )
    };
    for tenant_id in tenant_ids {
        let job = ctx.clone();
        let outcome = ctx
            .store
            .transaction(move |tx| async move { sweep_tenant(&job, &tx, &tenant_id).await })
            .await?;
        examined += outcome.examined;
        for reason in outcome.revocations {
            revoked += 1;
            *by_reason.entry(reason).or_insert(0) += 1;
        }
    }
    Ok(SshSweepResult {
        examined: examined as f64,
        revoked: revoked as f64,
        by_reason: Value::Object(
            by_reason
                .into_iter()
                .map(|(reason, count)| (reason, Value::from(count)))
                .collect(),
        ),
        extra: Map::new(),
    })
}

/// A key ID for sshd logs: who (and the agent acting for them), printable ASCII only.
pub fn certificate_key_id(principal: &better_iam_core::AuthenticatedPrincipal) -> String {
    let who = principal
        .identity
        .email
        .as_deref()
        .unwrap_or(&principal.identity.name);
    let via = match (
        &principal.session.agent_id,
        &principal.session.original_identity_id,
    ) {
        (Some(agent), _) => format!(" via agent {agent}"),
        (None, Some(original)) if !original.is_empty() => format!(" via {original}"),
        _ => String::new(),
    };
    let text = format!("{who} ({}){via}", principal.identity.id);
    let mut out = String::new();
    for c in text.chars() {
        if (' '..='~').contains(&c) && c != '"' {
            out.push(c);
        } else {
            // One `_` per UTF-16 code unit (`/[^\x20-\x7e]|"/g` without the `u` flag).
            for _ in 0..c.len_utf16() {
                out.push('_');
            }
        }
    }
    out.truncate(256);
    out
}

/// Parses a stored host key line (enrolled keys were validated when they arrived).
pub fn stored_host_key(host: &crate::ssh::SshHost) -> IamResult<crate::ssh_ca::SshPublicKey> {
    parse_ssh_public_key(host.host_key.clone().map(Value::String).as_ref(), None)
}
