//! Port of `packages/server/src/api/ssh.ts`: the `ssh` API group, the tenant's SSH certificate authority.
//! Administrators (`iam:ssh:manage`, `iam:ssh:read`) set it up, enroll hosts and review and revoke certificates;
//! members get certificates for what policies allow them (`ssh:login` on `ssh-login/{host}/{login}`); hosts enroll
//! with a one-time join token and then check in with their renewal token (`syncHost`), which also renews their
//! certificate and hands them the current trust and revocation list.

use std::cmp::Ordering;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use better_iam_auth::service::base::LimitAttemptOptions;
use better_iam_core::boxed;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Identity, IdentityKind, Record, SessionKind, Tenant, js as core_js,
};
use better_iam_types::api::ssh;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{
    Mutation, MutationContext, OperationDenied, OperationResult, PreparedDecision, decide_on,
    is_root_override,
};
use crate::decisions::{ModuleResourceLabels, module_resource_labels};
use crate::devices::presented_device;
use crate::js::{js_string, number, truthy, unique};
use crate::observe::SpanKind;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::decode;
use crate::ssh::{
    DELEGATED_CERTIFICATE_MS, ResolvedSshOptions, SSH_FORWARDING_ACTIONS, SSH_LOGIN_ACTION,
    SshAuthority, SshCertificateRecord, SshHost, SshSettings, SshSweepResult, active_authority,
    assert_host_key_free, assert_names_free, assert_ssh, assert_vouchable, bump_revocation_version,
    certificate_key_id, create_authority, ensure_authorities, grant_deadline, host_by_name,
    host_pattern_list, host_resource, live_certificates, load_ssh_settings, login_resource,
    mark_revoked, open_authority, principal_files, revocation_list, save_ssh_settings,
    ssh_host_name, ssh_labels, stored_host_key, sweep_ssh_certificates, tenant_active,
    tenant_authorities, trust_bundle, verified_domains,
};
use crate::ssh_ca::{
    SSH_CERT_HOST, SSH_CERT_USER, SshCertificateSpec, SshPublicKey, parse_ssh_public_key,
    sign_ssh_certificate, ssh_host_address, ssh_key_line, ssh_login, ssh_login_principal,
    ssh_serial,
};
use crate::utils::{by_id, hash, id, same_hash, token};
use crate::validation::{integer, text};

/// `hostKeyFile`: the sshd host key file each key type is usually stored in.
fn host_key_file(key_type: &str) -> Option<&'static str> {
    match key_type {
        "ssh-ed25519" => Some("ssh_host_ed25519_key"),
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            Some("ssh_host_ecdsa_key")
        }
        "ssh-rsa" => Some("ssh_host_rsa_key"),
        _ => None,
    }
}

const PRINCIPALS_DIRECTORY: &str = "/etc/ssh/better-iam/principals";
/// A forced renewal (`renew: true`) is honoured at most this often.
const FORCED_RENEWAL_MS: f64 = 3_600_000.0;
/// How long a public revocation list is served from the cache (it is never served stale: a revocation bumps the
/// version the cache is keyed by).
const REVOCATION_CACHE_MS: f64 = 10_000.0;
const DAY: f64 = 86_400_000.0;

const MANAGE: &str = "iam:ssh:manage";
const READ: &str = "iam:ssh:read";

/// Codes a host-management refusal is audited with (a denied `iam:ssh:manage`).
const AUDITED_REFUSALS: [&str; 3] = [
    "HOST_OUTSIDE_PATTERNS",
    "HOST_NAME_TAKEN",
    "HOST_KEY_IN_USE",
];

// --- record helpers ----------------------------------------------------------------------------------------------

fn str_of<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or("")
}

fn num_of(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

fn s(value: impl Into<String>) -> Value {
    Value::String(value.into())
}

fn strings_value(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::String).collect())
}

/// `a < b ? -1 : 1` on JavaScript strings.
fn before(a: &str, b: &str) -> Ordering {
    if core_js::cmp_utf16(a, b) == Ordering::Less {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// `value.slice(0, max)` (UTF-16 code units).
fn truncate_utf16(value: &str, max: usize) -> String {
    let mut out = String::new();
    let mut units = 0;
    for c in value.chars() {
        let width = c.len_utf16();
        if units + width > max {
            break;
        }
        units += width;
        out.push(c);
    }
    out
}

/// `key.comment?.replace(/[^\x20-\x7e]/g, '_')` (one `_` per UTF-16 code unit).
fn printable_comment(comment: &str) -> String {
    let mut out = String::new();
    for c in comment.chars() {
        if (' '..='~').contains(&c) {
            out.push(c);
        } else {
            for _ in 0..c.len_utf16() {
                out.push('_');
            }
        }
    }
    out
}

/// `isIP(value)` of node:net: 4, 6, or 0.
fn ip_family(value: &str) -> u8 {
    if value.parse::<Ipv4Addr>().is_ok() {
        return 4;
    }
    let (address, zone) = match value.split_once('%') {
        Some((address, zone)) => (address, Some(zone)),
        None => (value, None),
    };
    if let Some(zone) = zone
        && (zone.is_empty()
            || !zone
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':')))
    {
        return 0;
    }
    if address.contains(':') && address.parse::<Ipv6Addr>().is_ok() {
        return 6;
    }
    0
}

fn iam_request(tenant_id: &str, action: &str, resource_id: &str) -> AuthorizationRequest {
    AuthorizationRequest {
        credential: CredentialInput::default(),
        tenant_id: tenant_id.to_owned(),
        action: action.to_owned(),
        resource: ResourceTarget {
            kind: "iam".into(),
            id: resource_id.to_owned(),
        },
    }
}

fn invalid_token() -> IamError {
    IamError::with_status("INVALID_TOKEN", "Invalid or expired host token", 401)
}

fn tenant_value(tenant_id: &str) -> Value {
    Value::String(tenant_id.to_owned())
}

// --- views -------------------------------------------------------------------------------------------------------

/// An authority as administrators see it: never the sealed key.
fn public_authority(authority: &SshAuthority) -> Value {
    let mut view = Map::new();
    view.insert("id".into(), s(&authority.id));
    view.insert("tenantId".into(), s(&authority.tenant_id));
    view.insert("kind".into(), s(&authority.kind));
    view.insert("status".into(), s(&authority.status));
    view.insert("algorithm".into(), s(&authority.algorithm));
    view.insert("publicKey".into(), s(&authority.public_key));
    view.insert("fingerprint".into(), s(&authority.fingerprint));
    view.insert("createdAt".into(), number(authority.created_at));
    view.insert("createdBy".into(), s(&authority.created_by));
    if let Some(at) = authority.activated_at {
        view.insert("activatedAt".into(), number(at));
    }
    if let Some(at) = authority.rotated_at {
        view.insert("rotatedAt".into(), number(at));
    }
    if let Some(at) = authority.retired_at {
        view.insert("retiredAt".into(), number(at));
    }
    Value::Object(view)
}

fn public_authority_record(record: Record) -> IamResult<Value> {
    Ok(public_authority(&decode::<SshAuthority>(record)?))
}

/// A host as administrators see it: never its token hashes.
fn public_host(host: &Record) -> Value {
    let mut view = host.clone();
    for key in [
        "joinTokenHash",
        "renewalTokenHash",
        "previousRenewalTokenHash",
        "uniqueKey",
    ] {
        view.shift_remove(key);
    }
    Value::Object(view)
}

fn settings_view(settings: &SshSettings, options: &ResolvedSshOptions) -> Value {
    let mut view = Map::new();
    view.insert("tenantId".into(), s(&settings.tenant_id));
    view.insert("requireMfa".into(), Value::Bool(settings.require_mfa));
    view.insert(
        "requireSecurityKey".into(),
        Value::Bool(settings.require_security_key),
    );
    view.insert(
        "requireUserVerification".into(),
        Value::Bool(settings.require_user_verification),
    );
    view.insert(
        "bindSourceAddress".into(),
        Value::Bool(settings.bind_source_address),
    );
    view.insert(
        "defaultCertificateMs".into(),
        number(settings.default_certificate_ms),
    );
    view.insert(
        "maxCertificateMs".into(),
        number(settings.max_certificate_ms),
    );
    view.insert(
        "hostPatterns".into(),
        strings_value(&settings.host_patterns),
    );
    view.insert(
        "revocationVersion".into(),
        number(settings.revocation_version),
    );
    view.insert(
        "deploymentMaxCertificateMs".into(),
        number(options.max_user_certificate_ms),
    );
    if let Some(at) = settings.updated_at {
        view.insert("updatedAt".into(), number(at));
    }
    if let Some(by) = &settings.updated_by {
        view.insert("updatedBy".into(), s(by));
    }
    Value::Object(view)
}

/// A certificate record as administrators and holders see it: never the line, the key, or the session.
fn certificate_view(record: &Record, now: f64) -> Value {
    let mut view = record.clone();
    for key in [
        "expiresAt",
        "uniqueKey",
        "certificate",
        "publicKey",
        "sessionId",
    ] {
        view.shift_remove(key);
    }
    let status = if record.contains_key("revokedAt") {
        "revoked"
    } else if num_of(record, "validBefore").is_some_and(|before| before <= now) {
        "expired"
    } else {
        "active"
    };
    view.insert("status".into(), s(status));
    Value::Object(view)
}

fn certificate_status(view: &Value) -> &str {
    view.get("status").and_then(Value::as_str).unwrap_or("")
}

// --- input validation --------------------------------------------------------------------------------------------

fn list_of(
    value: Option<&Value>,
    name: &str,
    max: usize,
    each: impl Fn(Option<&Value>) -> IamResult<String>,
) -> IamResult<Vec<String>> {
    match value {
        Some(Value::Array(items)) if items.len() <= max => {
            let mapped = items
                .iter()
                .map(|item| each(Some(item)))
                .collect::<IamResult<Vec<String>>>()?;
            Ok(unique(mapped))
        }
        _ => Err(IamError::new(
            "INVALID_INPUT",
            format!("{name} must be a list of at most {max} items"),
        )),
    }
}

fn host_logins(value: Option<&Value>) -> IamResult<Vec<String>> {
    let logins = list_of(value, "logins", 64, ssh_login)?;
    if logins.is_empty() {
        return Err(IamError::new(
            "INVALID_INPUT",
            "A host needs at least one login",
        ));
    }
    Ok(logins)
}

fn host_addresses(value: Option<&Value>) -> IamResult<Vec<String>> {
    match value {
        None => Ok(Vec::new()),
        Some(_) => list_of(value, "addresses", 32, ssh_host_address),
    }
}

/// Join and renewal tokens name their host: `biam_sshj.{hostId}.{secret}` / `biam_sshr.{hostId}.{secret}`.
fn token_host(value: Option<&Value>, prefix: &str) -> IamResult<String> {
    let parts: Vec<&str> = match value {
        Some(Value::String(text)) if core_js::utf16_len(text) <= 256 => text.split('.').collect(),
        _ => Vec::new(),
    };
    if parts.len() != 3 || parts[0] != prefix || parts[1].is_empty() || parts[2].is_empty() {
        return Err(invalid_token());
    }
    Ok(parts[1].to_owned())
}

fn tenant_of(value: Option<&Value>) -> IamResult<String> {
    text(value, "tenantId", 256)
}

/// What one host of a certificate or of `myAccess` opens.
struct HostAccess {
    host: SshHost,
    logins: Vec<String>,
    forwarding: IndexMap<String, bool>,
}

/// The forwarding actions and the certificate extensions they allow, in declaration order.
fn forwarding_actions() -> Vec<(String, String)> {
    SSH_FORWARDING_ACTIONS
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(action, extension)| (action.clone(), js_string(Some(extension))))
                .collect()
        })
        .unwrap_or_default()
}

/// The hosts and logins a principal may open, and what forwarding each host allows.
fn access_of(
    prepared: &PreparedDecision,
    hosts: &[SshHost],
    logins: Option<&IndexSet<String>>,
    labeled: &ModuleResourceLabels,
) -> IamResult<Vec<HostAccess>> {
    let mut sorted: Vec<&SshHost> = hosts.iter().collect();
    sorted.sort_by(|a, b| before(&a.name, &b.name));
    let mut result = Vec::new();
    for host in sorted {
        let mut allowed = Vec::new();
        for login in &host.logins {
            if logins.is_some_and(|wanted| !wanted.contains(login)) {
                continue;
            }
            let resource = labeled.apply(&login_resource(host, login));
            if decide_on(prepared, &resource, Some(SSH_LOGIN_ACTION))?.allowed {
                allowed.push(login.clone());
            }
        }
        if allowed.is_empty() {
            continue;
        }
        let mut forwarding = IndexMap::new();
        for (action, _) in forwarding_actions() {
            let resource = labeled.apply(&host_resource(host));
            let allowed = decide_on(prepared, &resource, Some(&action))?.allowed;
            forwarding.insert(action, allowed);
        }
        result.push(HostAccess {
            host: host.clone(),
            logins: allowed,
            forwarding,
        });
    }
    Ok(result)
}

/// A root override from outside the tenant (the platform's administrators acting in an organization).
fn cross_tenant_root(
    prepared: &PreparedDecision,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
) -> bool {
    is_root_override(prepared) && principal.identity.tenant_id != tenant_id
}

fn refused_fixed(prepared: &PreparedDecision) -> bool {
    matches!(prepared, PreparedDecision::Fixed(decision) if !decision.allowed)
}

async fn find_records(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

async fn find_hosts(tx: &Store, filter: Filter) -> IamResult<Vec<SshHost>> {
    find_records(tx, "sshHosts", filter)
        .await?
        .into_iter()
        .map(decode::<SshHost>)
        .collect()
}

/// The outcome of a host call (enroll, sync) whose refusal is audited after the transaction.
enum HostOutcome {
    Refused {
        error: IamError,
        host: Option<Record>,
        metadata: Map<String, Value>,
    },
    Done(Value),
}

/// The outcome of `issueCertificate`'s transaction: a refusal commits its audit record and then throws.
enum IssueOutcome {
    Refused(IamError),
    Issued { value: Value, usage: bool },
}

type RevocationCache = IndexMap<String, (f64, f64, Value)>;

/// The `ssh` API group (`createSshApi(ctx)`): one method per route `ssh/{method}`.
pub struct SshApi {
    ctx: Arc<ServerContext>,
    /// The public revocation list is read by every host every few minutes: cached per tenant, kind and version and
    /// read outside any transaction (a revocation bumps the version, so it is never served stale; holders or sessions
    /// that ended meanwhile show within seconds).
    revocation_cache: Mutex<RevocationCache>,
}

/// `createSshApi(ctx)`.
pub fn create_ssh_api(ctx: &Arc<ServerContext>) -> IamResult<SshApi> {
    Ok(SshApi {
        ctx: ctx.clone(),
        revocation_cache: Mutex::new(IndexMap::new()),
    })
}

// --- private helpers ---------------------------------------------------------------------------------------------

impl SshApi {
    async fn active_tenant(&self, tx: &Store, tenant_id: &str) -> IamResult<Tenant> {
        let tenant = self.ctx.tenant(tx, tenant_id).await?;
        if !tenant_active(&self.ctx, tx, &tenant).await? {
            return Err(IamError::with_status(
                "TENANT_INACTIVE",
                "This organization is not active",
                403,
            ));
        }
        Ok(tenant)
    }

    async fn scoped_host(
        &self,
        tx: &Store,
        tenant_id: &str,
        host_id: Option<&Value>,
    ) -> IamResult<Record> {
        let host_id = text(host_id, "hostId", 256)?;
        self.ctx
            .scoped(tx, "sshHosts", Some(&Value::String(host_id)), tenant_id)
            .await
    }

    async fn host_record_name(
        &self,
        tenant_id: &str,
        host_id: Option<&Value>,
    ) -> IamResult<String> {
        let host = self
            .scoped_host(&self.ctx.store, tenant_id, host_id)
            .await?;
        Ok(str_of(&host, "name").to_owned())
    }

    /// Records a refused host call (bad token, key swap) in its own transaction, then throws.
    async fn refuse_host(
        &self,
        host: Option<Record>,
        action: &str,
        error: IamError,
        metadata: Map<String, Value>,
    ) -> IamError {
        if let Some(host) = host {
            let ctx = self.ctx.clone();
            let mut details = Map::new();
            details.insert("reason".into(), s(&error.code));
            for (key, value) in metadata {
                details.insert(key, value);
            }
            let mut event = Record::new();
            event.insert("id".into(), s(id()));
            event.insert("tenantId".into(), s(str_of(&host, "tenantId")));
            event.insert(
                "actorId".into(),
                s(format!("ssh-host:{}", str_of(&host, "id"))),
            );
            event.insert("action".into(), s(action));
            event.insert(
                "resourceId".into(),
                s(format!("ssh/hosts/{}", str_of(&host, "name"))),
            );
            event.insert("outcome".into(), s("deny"));
            event.insert("timestamp".into(), number(ctx.now()));
            event.insert("metadata".into(), Value::Object(details));
            // Bookkeeping never masks the refusal.
            let store = ctx.store.clone();
            let _ = store
                .transaction(move |tx| async move { ctx.events()?.record_audit(&tx, &event).await })
                .await;
        }
        error
    }

    /// An administrative host operation whose policy-shaped refusals (names outside patterns, taken) are audited.
    async fn audited<F>(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        resource_id: &str,
        run: F,
    ) -> IamResult<Value>
    where
        F: std::future::Future<Output = IamResult<Value>>,
    {
        match run.await {
            Ok(value) => Ok(value),
            Err(error) => {
                if AUDITED_REFUSALS.contains(&error.code.as_str()) {
                    let _ = self
                        .audit_refusal(credential, tenant_id, resource_id, &error)
                        .await;
                }
                Err(error)
            }
        }
    }

    async fn audit_refusal(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        resource_id: &str,
        error: &IamError,
    ) -> IamResult<()> {
        let ctx = self.ctx.clone();
        let principal = ctx.principals()?.authenticate(credential).await?;
        let mut metadata = Map::new();
        metadata.insert("reason".into(), s(&error.code));
        metadata.insert("message".into(), s(truncate_utf16(&error.message, 256)));
        let tenant_id = tenant_id.to_owned();
        let resource_id = resource_id.to_owned();
        ctx.store
            .clone()
            .transaction(move |tx| async move {
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        MANAGE,
                        &tenant_id,
                        &resource_id,
                        AuditOutcome::Deny,
                        false,
                        Some(metadata),
                    )
                    .await
            })
            .await
    }

    /// Every name a host certificate would carry must be one the organization can vouch for, used by no other host,
    /// and within the caller's own `iam:ssh:manage` scope (`iam/ssh/hosts/{name}` for each address), so an
    /// administrator of some hosts cannot claim another host's name.
    async fn assert_names_allowed(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        names: &[String],
        host_id: Option<&str>,
    ) -> OperationResult<()> {
        let ctx = &self.ctx;
        let settings = load_ssh_settings(ctx, tx, tenant_id).await?;
        let domains = verified_domains(tx, tenant_id).await?;
        assert_vouchable(&settings, &domains, names)?;
        assert_names_free(tx, tenant_id, names, host_id).await?;
        for name in names.iter().skip(1) {
            let decision = ctx
                .operations()?
                .recorded_decision(
                    tx,
                    principal,
                    &iam_request(tenant_id, MANAGE, &format!("ssh/hosts/{name}")),
                )
                .await?;
            if !decision.allowed {
                return Err(OperationDenied::new(Some(&format!(
                    "You may not manage the host name {name}"
                ))));
            }
        }
        Ok(())
    }

    /// Issues a host certificate for the host's name and addresses and supersedes every earlier one.
    async fn certify_host(
        &self,
        tx: &Store,
        host: &SshHost,
        key: &SshPublicKey,
        options: &ResolvedSshOptions,
    ) -> IamResult<(Record, String)> {
        let ctx = &self.ctx;
        let authority = active_authority(tx, &host.tenant_id, "host").await?;
        let now = ctx.now();
        let serial = ssh_serial();
        let serial_string = serial.to_string();
        let mut names = vec![host.name.clone()];
        names.extend(host.addresses.iter().cloned());
        let principals = unique(names);
        // Never vouch for a name outside the organization's reach, whatever the host record says.
        let settings = load_ssh_settings(ctx, tx, &host.tenant_id).await?;
        let domains = verified_domains(tx, &host.tenant_id).await?;
        assert_vouchable(&settings, &domains, &principals)?;
        let previous = live_certificates(
            ctx,
            tx,
            &json!({ "tenantId": host.tenant_id, "hostId": host.id }),
        )
        .await?;
        let valid_before = now + options.host_certificate_ms;
        let key_id = format!("host:{}", host.name);
        let spec = SshCertificateSpec {
            key: key.clone(),
            serial,
            kind: SSH_CERT_HOST as u32,
            key_id: key_id.clone(),
            principals: principals.clone(),
            valid_after: ((now - options.clock_skew_ms) / 1000.0).floor() as u64,
            valid_before: (valid_before / 1000.0).floor() as u64,
            critical_options: IndexMap::new(),
            extensions: Vec::new(),
        };
        let signed =
            sign_ssh_certificate(&open_authority(ctx, &authority)?, &spec, Some(&host.name))?;
        let line = signed.line;
        let mut record = Record::new();
        record.insert("id".into(), s(id()));
        record.insert("tenantId".into(), s(&host.tenant_id));
        record.insert(
            "uniqueKey".into(),
            s(format!("{}:{}", authority.id, serial_string)),
        );
        record.insert("kind".into(), s("host"));
        record.insert("serial".into(), s(&serial_string));
        record.insert("keyId".into(), s(&key_id));
        record.insert("authorityId".into(), s(&authority.id));
        record.insert("hostId".into(), s(&host.id));
        record.insert("principals".into(), strings_value(&principals));
        record.insert("extensions".into(), json!([]));
        record.insert("keyType".into(), s(&key.r#type));
        record.insert("publicKeyFingerprint".into(), s(&key.fingerprint));
        record.insert("publicKey".into(), s(ssh_key_line(&key.blob, None)?));
        record.insert("validAfter".into(), number(now - options.clock_skew_ms));
        record.insert("validBefore".into(), number(valid_before));
        record.insert("issuedAt".into(), number(now));
        record.insert("certificate".into(), s(&line));
        record.insert(
            "expiresAt".into(),
            number(valid_before + options.record_retention_ms),
        );
        let record = tx.insert("sshCertificates", &record).await?;
        // One live certificate per host: earlier ones (another key, other names, another authority) end here.
        self.revoke_all(
            tx,
            &host.tenant_id,
            previous,
            "superseded",
            &format!("ssh-host:{}", host.id),
        )
        .await?;
        Ok((record, line))
    }

    async fn host_setup(
        &self,
        tx: &Store,
        tenant: &Tenant,
        host: &Record,
        certificate: (&str, f64, bool),
        renewal: Option<&str>,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let (line, expires_at, renewed) = certificate;
        let typed: SshHost = decode(host.clone())?;
        let bundle = trust_bundle(ctx, tx, tenant, "member").await?;
        let krl = revocation_list(ctx, tx, tenant, Some("user")).await?;
        let principals = principal_files(&typed);
        let key_type = typed
            .host_key
            .as_deref()
            .map(|key| key.split(' ').next().unwrap_or(""))
            .unwrap_or("ssh-ed25519");
        let certificate_path = format!(
            "/etc/ssh/{}-cert.pub",
            host_key_file(key_type).unwrap_or("ssh_host_ed25519_key")
        );
        let sshd_config = [
            format!(
                "# Managed by better-iam: host {} of tenant {}",
                typed.name, tenant.id
            ),
            "# The first value sshd reads wins, so this drop-in sorts first (check with sshd -T)."
                .into(),
            "TrustedUserCAKeys /etc/ssh/better-iam/user-ca.pub".into(),
            format!("AuthorizedPrincipalsFile {PRINCIPALS_DIRECTORY}/%u"),
            "RevokedKeys /etc/ssh/better-iam/revoked.krl".into(),
            format!("HostCertificate {certificate_path}"),
            String::new(),
        ]
        .join("\n");
        let trusted_user_ca_keys = bundle
            .get("trustedUserCaKeys")
            .cloned()
            .unwrap_or(Value::Null);
        let krl_text = krl.get("krl").cloned().unwrap_or(Value::Null);
        let mut principals_map = Map::new();
        for (login, content) in &principals {
            principals_map.insert(login.clone(), s(content));
        }
        let mut files = vec![
            json!({ "path": certificate_path, "content": format!("{line}\n"), "mode": "0644" }),
            json!({ "path": "/etc/ssh/better-iam/user-ca.pub", "content": trusted_user_ca_keys, "mode": "0644" }),
        ];
        for (login, content) in &principals {
            files.push(json!({
                "path": format!("{PRINCIPALS_DIRECTORY}/{login}"),
                "content": content,
                "mode": "0644",
            }));
        }
        files.push(json!({
            "path": "/etc/ssh/better-iam/revoked.krl",
            "content": krl_text,
            "mode": "0644",
            "encoding": "base64",
        }));
        files.push(json!({
            "path": "/etc/ssh/sshd_config.d/00-better-iam.conf",
            "content": sshd_config,
            "mode": "0644",
        }));
        let mut setup = Map::new();
        setup.insert("host".into(), public_host(host));
        setup.insert("certificate".into(), s(line));
        setup.insert("certificateExpiresAt".into(), number(expires_at));
        setup.insert("certificateRenewed".into(), Value::Bool(renewed));
        if let Some(renewal) = renewal.filter(|renewal| !renewal.is_empty()) {
            setup.insert("renewalToken".into(), s(renewal));
        }
        setup.insert("trustedUserCaKeys".into(), trusted_user_ca_keys);
        setup.insert("principals".into(), Value::Object(principals_map));
        setup.insert("revocationList".into(), krl_text);
        setup.insert(
            "revocationVersion".into(),
            krl.get("version").cloned().unwrap_or(Value::Null),
        );
        setup.insert("files".into(), Value::Array(files));
        setup.insert("managedDirectories".into(), json!([PRINCIPALS_DIRECTORY]));
        setup.insert("sshdConfig".into(), s(sshd_config));
        Ok(Value::Object(setup))
    }

    async fn host_audit(
        &self,
        tx: &Store,
        host: &Record,
        action: &str,
        metadata: Value,
    ) -> IamResult<()> {
        let ctx = &self.ctx;
        let mut event = Record::new();
        event.insert("id".into(), s(id()));
        event.insert("tenantId".into(), s(str_of(host, "tenantId")));
        event.insert(
            "actorId".into(),
            s(format!("ssh-host:{}", str_of(host, "id"))),
        );
        event.insert("action".into(), s(action));
        event.insert(
            "resourceId".into(),
            s(format!("ssh/hosts/{}", str_of(host, "name"))),
        );
        event.insert("outcome".into(), s("allow"));
        event.insert("timestamp".into(), number(ctx.now()));
        event.insert("metadata".into(), metadata);
        ctx.events()?.record_audit(tx, &event).await
    }

    /// Revokes the certificates in `records` and bumps the revocation version once.
    async fn revoke_all(
        &self,
        tx: &Store,
        tenant_id: &str,
        records: Vec<SshCertificateRecord>,
        reason: &str,
        actor_id: &str,
    ) -> IamResult<f64> {
        let ctx = &self.ctx;
        let mut count = 0.0;
        for record in records {
            if record.revoked_at.is_some() {
                continue;
            }
            mark_revoked(ctx, tx, &record, reason, actor_id).await?;
            count += 1.0;
        }
        if count > 0.0 {
            bump_revocation_version(ctx, tx, tenant_id).await?;
        }
        Ok(count)
    }

    /// With security clearances, the classification labels of the hosts' `ssh-host` and `ssh-login` resources.
    async fn classified_hosts(
        &self,
        tx: &Store,
        tenant_id: &str,
        hosts: &[SshHost],
    ) -> IamResult<ModuleResourceLabels> {
        let mut resources = Vec::new();
        for host in hosts {
            resources.push(host_resource(host));
            for login in &host.logins {
                resources.push(login_resource(host, login));
            }
        }
        module_resource_labels(&self.ctx, tx, tenant_id, &resources).await
    }

    /// Switches the signing key: the current active authority becomes `previous`.
    async fn activate(&self, tx: &Store, pending: Record) -> IamResult<Record> {
        let ctx = &self.ctx;
        let now = ctx.now();
        let kind = str_of(&pending, "kind").to_owned();
        let tenant_id = str_of(&pending, "tenantId").to_owned();
        for current in tenant_authorities(tx, &tenant_id, Some(&kind)).await? {
            if current.status == "active" {
                let mut next = match tx.get("sshAuthorities", &current.id).await? {
                    Some(record) => record,
                    None => crate::port::encode(&current),
                };
                next.insert("status".into(), s("previous"));
                next.insert("rotatedAt".into(), number(now));
                tx.put("sshAuthorities", &next).await?;
            }
        }
        let mut next = pending;
        next.insert("status".into(), s("active"));
        next.insert("activatedAt".into(), number(now));
        tx.put("sshAuthorities", &next).await
    }

    async fn operation(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(
                credential,
                Some(&tenant_value(tenant_id)),
                action,
                resource_id,
                mutation,
                false,
            )
            .await
    }
}

// --- routes ------------------------------------------------------------------------------------------------------

impl SshApi {
    /// `ssh/activateAuthority`: makes a pending authority the signing key; the one it replaces stays trusted as
    /// `previous`. Requires iam:ssh:manage.
    pub async fn activate_authority(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::ActivateAuthorityInput>,
    ) -> IamResult<Reply<ssh::ActivateAuthorityOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let authority_id = text(input.get("authorityId"), "authorityId", 256)?;
        let found = ctx
            .scoped(
                &ctx.store,
                "sshAuthorities",
                Some(&s(&authority_id)),
                &tenant_id,
            )
            .await?;
        let found_id = str_of(&found, "id").to_owned();
        let resource = format!("ssh/authorities/{}", js_string(found.get("kind")));
        let tenant_ref = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                assert_ssh(ctx)?;
                let authority = ctx
                    .scoped(&tx, "sshAuthorities", Some(&s(&found_id)), tenant_ref)
                    .await?;
                if str_of(&authority, "status") != "pending" {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "Only a pending authority can be activated",
                        409,
                    )
                    .into());
                }
                Ok(public_authority_record(
                    self.activate(&tx, authority).await?,
                )?)
            })
        });
        let result = self
            .operation(credential, &tenant_id, MANAGE, &resource, mutation)
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/clientTrust`: what a member's SSH client needs: known_hosts lines for the organization's hosts (and
    /// `@revoked` ones for keys to refuse), and the host revocation list for `RevokedHostKeys`.
    pub async fn client_trust(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::ClientTrustInput>,
    ) -> IamResult<Reply<ssh::ClientTrustOutput>> {
        let ctx = self.ctx.clone();
        assert_ssh(&ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let store = ctx.store.clone();
        let result = store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                if principal.session.tenant_id != tenant_id {
                    return Err(IamError::with_status("ACCESS_DENIED", "Access denied", 403));
                }
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                let bundle = trust_bundle(&ctx, &tx, &tenant, "member").await?;
                let hosts = revocation_list(&ctx, &tx, &tenant, Some("host")).await?;
                let mut out = Map::new();
                out.insert(
                    "knownHosts".into(),
                    bundle.get("knownHosts").cloned().unwrap_or(Value::Null),
                );
                out.insert(
                    "revokedHostKeys".into(),
                    hosts.get("krl").cloned().unwrap_or(Value::Null),
                );
                out.insert(
                    "hostPatterns".into(),
                    bundle.get("hostPatterns").cloned().unwrap_or(Value::Null),
                );
                Ok(Value::Object(out))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/createHost`: registers a host and returns its one-time join token (shown once; valid for
    /// `joinTokenMs`). Its name and every address must be unused, within the caller's `iam:ssh:manage` scope, and
    /// names the organization can vouch for. Needs the authorities (`setup`). Requires iam:ssh:manage.
    pub async fn create_host(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::CreateHostInput>,
    ) -> IamResult<Reply<ssh::CreateHostOutput>> {
        let ctx = &self.ctx;
        let name = ssh_host_name(input.get("name"))?;
        let logins = host_logins(input.get("logins"))?;
        let addresses: Vec<String> = host_addresses(input.get("addresses"))?
            .into_iter()
            .filter(|address| *address != name)
            .collect();
        let labels = ssh_labels(input.get("labels"))?;
        let description = match input.get("description") {
            None => None,
            Some(value) => Some(text(Some(value), "description", 512)?),
        };
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let resource = format!("ssh/hosts/{name}");
        let (name_ref, logins_ref, addresses_ref, labels_ref, description_ref) =
            (&name, &logins, &addresses, &labels, &description);
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let options = assert_ssh(ctx)?;
                    if host_by_name(&tx, &tenant.id, name_ref).await?.is_some() {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A host with this name already exists",
                            409,
                        )
                        .into());
                    }
                    // Creating the authorities is `setup`, a decision of its own.
                    active_authority(&tx, &tenant.id, "host").await?;
                    let mut names = vec![name_ref.clone()];
                    names.extend(addresses_ref.iter().cloned());
                    self.assert_names_allowed(&tx, &principal, &tenant.id, &names, None)
                        .await?;
                    let host_id = id();
                    let secret = format!("biam_sshj.{host_id}.{}", token());
                    let now = ctx.now();
                    let mut record = Record::new();
                    record.insert("id".into(), s(&host_id));
                    record.insert("tenantId".into(), s(&tenant.id));
                    record.insert("uniqueKey".into(), s(name_ref));
                    record.insert("name".into(), s(name_ref));
                    if let Some(description) = description_ref.as_ref().filter(|d| !d.is_empty()) {
                        record.insert("description".into(), s(description));
                    }
                    record.insert("addresses".into(), strings_value(addresses_ref));
                    record.insert("logins".into(), strings_value(logins_ref));
                    let mut label_map = Map::new();
                    for (key, value) in labels_ref {
                        label_map.insert(key.clone(), s(value));
                    }
                    record.insert("labels".into(), Value::Object(label_map));
                    record.insert("status".into(), s("pending"));
                    record.insert("joinTokenHash".into(), s(hash(&secret)));
                    record.insert(
                        "joinTokenExpiresAt".into(),
                        number(now + options.join_token_ms),
                    );
                    record.insert("createdAt".into(), number(now));
                    record.insert("createdBy".into(), s(&principal.identity.id));
                    record.insert("updatedAt".into(), number(now));
                    let host = tx.insert("sshHosts", &record).await?;
                    let mut out = Map::new();
                    out.insert("host".into(), public_host(&host));
                    out.insert("joinToken".into(), s(&secret));
                    out.insert(
                        "joinTokenExpiresAt".into(),
                        host.get("joinTokenExpiresAt")
                            .cloned()
                            .unwrap_or(Value::Null),
                    );
                    Ok(Value::Object(out))
                })
            },
        );
        let result = self
            .audited(
                credential,
                &tenant_id,
                &resource,
                self.operation(credential, &tenant_id, MANAGE, &resource, mutation),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/deleteHost`: deletes a host; its certificate is revoked and its key published as revoked. Requires
    /// iam:ssh:manage.
    pub async fn delete_host(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::DeleteHostInput>,
    ) -> IamResult<Reply<ssh::DeleteHostOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let name = self
            .host_record_name(&tenant_id, input.get("hostId"))
            .await?;
        let (tenant_ref, body) = (&tenant_id, &input);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                assert_ssh(ctx)?;
                let host = self
                    .scoped_host(&tx, tenant_ref, body.get("hostId"))
                    .await?;
                let host_id = str_of(&host, "id").to_owned();
                let live = live_certificates(
                    ctx,
                    &tx,
                    &json!({ "tenantId": tenant_ref, "hostId": host_id }),
                )
                .await?;
                self.revoke_all(
                    &tx,
                    tenant_ref,
                    live,
                    "host-deleted",
                    &principal.identity.id,
                )
                .await?;
                tx.delete("sshHosts", &host_id).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = self
            .operation(
                credential,
                &tenant_id,
                MANAGE,
                &format!("ssh/hosts/{name}"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/disableHost`: takes a host out of service: its certificate is revoked, its key is published as revoked
    /// to clients, it can no longer sync, and no user certificate names it. Requires iam:ssh:manage.
    pub async fn disable_host(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::DisableHostInput>,
    ) -> IamResult<Reply<ssh::DisableHostOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let name = self
            .host_record_name(&tenant_id, input.get("hostId"))
            .await?;
        let (tenant_ref, body) = (&tenant_id, &input);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                assert_ssh(ctx)?;
                let host = self
                    .scoped_host(&tx, tenant_ref, body.get("hostId"))
                    .await?;
                if str_of(&host, "status") == "disabled" {
                    return Ok(public_host(&host));
                }
                let live = live_certificates(
                    ctx,
                    &tx,
                    &json!({ "tenantId": tenant_ref, "hostId": str_of(&host, "id") }),
                )
                .await?;
                self.revoke_all(
                    &tx,
                    tenant_ref,
                    live,
                    "host-disabled",
                    &principal.identity.id,
                )
                .await?;
                let mut rest = host;
                for key in [
                    "joinTokenHash",
                    "joinTokenExpiresAt",
                    "renewalTokenHash",
                    "previousRenewalTokenHash",
                ] {
                    rest.shift_remove(key);
                }
                rest.insert("status".into(), s("disabled"));
                rest.insert("updatedAt".into(), number(ctx.now()));
                let saved = tx.put("sshHosts", &rest).await?;
                bump_revocation_version(ctx, &tx, tenant_ref).await?;
                Ok(public_host(&saved))
            })
        });
        let result = self
            .operation(
                credential,
                &tenant_id,
                MANAGE,
                &format!("ssh/hosts/{name}"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/enrollHost` (public: no credential): enrolls a host with its one-time join token and its public host
    /// key: returns the host certificate, the trust and principals files sshd needs, the revocation list, and the
    /// renewal token for `syncHost`. The join token is the credential. Refusals of a real host's token are audited.
    pub async fn enroll_host(
        &self,
        input: Body<ssh::EnrollHostInput>,
    ) -> IamResult<Reply<ssh::EnrollHostOutput>> {
        let ctx = &self.ctx;
        let options = assert_ssh(ctx)?;
        let host_id = token_host(input.get("joinToken"), "biam_sshj")?;
        if let Some(known) = ctx.store.get("sshHosts", &host_id).await? {
            ctx.auth
                .limit_attempt(
                    str_of(&known, "tenantId"),
                    &format!("ssh:enroll:{host_id}"),
                    LimitAttemptOptions {
                        limit: Some(10.0),
                        ..LimitAttemptOptions::default()
                    },
                )
                .await?;
        }
        let key = parse_ssh_public_key(input.get("publicKey"), None)?;
        let presented = hash(&js_string(input.get("joinToken")));
        let (options_ref, key_ref, host_ref) = (&options, &key, &host_id);
        let outcome = ctx
            .store
            .transaction(move |tx| async move {
                let host = tx.get("sshHosts", host_ref).await?;
                let usable = host.as_ref().is_some_and(|host| {
                    str_of(host, "status") != "disabled"
                        && host
                            .get("joinTokenHash")
                            .and_then(Value::as_str)
                            .is_some_and(|stored| {
                                !stored.is_empty() && same_hash(stored, &presented)
                            })
                        && num_of(host, "joinTokenExpiresAt").unwrap_or(0.0) > ctx.now()
                });
                let host = match host {
                    Some(host) if usable => host,
                    other => {
                        return Ok(HostOutcome::Refused {
                            error: invalid_token(),
                            host: other,
                            metadata: Map::new(),
                        });
                    }
                };
                let typed: SshHost = decode(host.clone())?;
                let tenant = self.active_tenant(&tx, &typed.tenant_id).await?;
                assert_host_key_free(&tx, &typed.tenant_id, &typed.id, key_ref).await?;
                let (record, line) = self.certify_host(&tx, &typed, key_ref, options_ref).await?;
                let renewal = format!("biam_sshr.{}.{}", typed.id, token());
                let now = ctx.now();
                let mut rest = host;
                for key in [
                    "joinTokenHash",
                    "joinTokenExpiresAt",
                    "previousRenewalTokenHash",
                ] {
                    rest.shift_remove(key);
                }
                rest.insert("status".into(), s("enrolled"));
                rest.insert("hostKey".into(), s(ssh_key_line(&key_ref.blob, None)?));
                rest.insert("hostKeyFingerprint".into(), s(&key_ref.fingerprint));
                rest.insert("certificateId".into(), s(str_of(&record, "id")));
                let valid_before = num_of(&record, "validBefore").unwrap_or(0.0);
                rest.insert("certificateExpiresAt".into(), number(valid_before));
                rest.insert("renewalTokenHash".into(), s(hash(&renewal)));
                rest.insert("enrolledAt".into(), number(now));
                rest.insert("renewedAt".into(), number(now));
                rest.insert("lastSeenAt".into(), number(now));
                rest.insert("updatedAt".into(), number(now));
                let saved = tx.put("sshHosts", &rest).await?;
                self.host_audit(
                    &tx,
                    &saved,
                    "ssh:host:enroll",
                    json!({
                        "serial": record.get("serial").cloned().unwrap_or(Value::Null),
                        "fingerprint": key_ref.fingerprint,
                        "keyType": key_ref.r#type,
                    }),
                )
                .await?;
                let value = self
                    .host_setup(
                        &tx,
                        &tenant,
                        &saved,
                        (&line, valid_before, true),
                        Some(&renewal),
                    )
                    .await?;
                Ok(HostOutcome::Done(value))
            })
            .await?;
        match outcome {
            HostOutcome::Refused {
                error,
                host,
                metadata,
            } => Err(self
                .refuse_host(host, "ssh:host:enroll", error, metadata)
                .await),
            HostOutcome::Done(value) => Ok(Reply::json(value)),
        }
    }

    /// `ssh/getCertificate`: one certificate record. Requires iam:ssh:read.
    pub async fn get_certificate(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::GetCertificateInput>,
    ) -> IamResult<Reply<ssh::GetCertificateOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let certificate_id = text(input.get("certificateId"), "certificateId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let record = ctx
                    .scoped(
                        &tx,
                        "sshCertificates",
                        body.get("certificateId"),
                        &tenant.id,
                    )
                    .await?;
                Ok(certificate_view(&record, ctx.now()))
            })
        });
        let result = self
            .operation(
                credential,
                &tenant_id,
                READ,
                &format!("ssh/certificates/{certificate_id}"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/getHost`: one host. Requires iam:ssh:read.
    pub async fn get_host(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::GetHostInput>,
    ) -> IamResult<Reply<ssh::GetHostOutput>> {
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let name = self
            .host_record_name(&tenant_id, input.get("hostId"))
            .await?;
        let (tenant_ref, body) = (&tenant_id, &input);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let host = self
                    .scoped_host(&tx, tenant_ref, body.get("hostId"))
                    .await?;
                Ok(public_host(&host))
            })
        });
        let result = self
            .operation(
                credential,
                &tenant_id,
                READ,
                &format!("ssh/hosts/{name}"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/getSettings`: the tenant's SSH settings. Requires iam:ssh:read.
    pub async fn get_settings(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::GetSettingsInput>,
    ) -> IamResult<Reply<ssh::GetSettingsOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let settings = load_ssh_settings(ctx, &tx, &tenant.id).await?;
                Ok(settings_view(&settings, &assert_ssh(ctx)?))
            })
        });
        let result = self
            .operation(credential, &tenant_id, READ, "ssh/settings", mutation)
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/issueCertificate`: issues a user certificate for the caller's public key, naming every requested host
    /// and login that policies allow (`ssh:login` on `ssh-login/{host}/{login}`), with forwarding extensions only
    /// where every named host allows them. The lifetime never outlives the caller's session or account, nor a
    /// time-limited grant that allows `ssh:login`; certificates for agents acting for people last ten minutes. Rate
    /// limited per identity (`ssh.issuanceLimit`). Audited as `ssh:certificate:issue`; a refusal is audited as a
    /// denied `ssh:login`.
    pub async fn issue_certificate(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::IssueCertificateInput>,
    ) -> IamResult<Reply<ssh::IssueCertificateOutput>> {
        let ctx = &self.ctx;
        let options = assert_ssh(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let key = parse_ssh_public_key(input.get("publicKey"), None)?;
        let requested_hosts = match input.get("hosts") {
            None => None,
            Some(value) => Some(list_of(Some(value), "hosts", 256, ssh_host_name)?),
        };
        let requested_logins: Option<IndexSet<String>> = match input.get("logins") {
            None => None,
            Some(value) => Some(
                list_of(Some(value), "logins", 64, ssh_login)?
                    .into_iter()
                    .collect(),
            ),
        };
        let ttl = match input.get("ttlMs") {
            None => None,
            Some(value) => Some(integer(
                Some(value),
                "ttlMs",
                60_000.0,
                options.max_user_certificate_ms,
            )?),
        };
        let reason = match input.get("reason") {
            None => None,
            Some(value) => Some(text(Some(value), "reason", 512)?),
        };
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        boxed(|| async {
            ctx.auth
                .limit_attempt(
                    &tenant_id,
                    &format!("ssh:issue:{}", authenticated.identity.id),
                    LimitAttemptOptions {
                        limit: Some(options.issuance_limit),
                        ..LimitAttemptOptions::default()
                    },
                )
                .await
        })
        .await?;
        let (
            options_ref,
            key_ref,
            hosts_ref,
            logins_ref,
            reason_ref,
            tenant_ref,
            authenticated_ref,
        ) = (
            &options,
            &key,
            &requested_hosts,
            &requested_logins,
            &reason,
            &tenant_id,
            &authenticated,
        );
        let work = ctx.store.transaction(move |tx| async move {
            let principal = ctx
                .principals()?
                .current_principal(&tx, authenticated_ref)
                .await?;
            let tenant = boxed(|| ctx.tenant(&tx, tenant_ref)).await?;
            let target = match hosts_ref {
                Some(hosts) if !hosts.is_empty() => {
                    truncate_utf16(&format!("ssh-login/{}", hosts.join(",")), 256)
                }
                _ => "ssh-login/*".to_owned(),
            };
            let refuse = |code: &'static str, message: &'static str, status: u16| {
                let (tx, principal, target) = (tx.clone(), principal.clone(), target.clone());
                async move {
                    let mut metadata = Map::new();
                    metadata.insert("reason".into(), s(code));
                    metadata.insert("fingerprint".into(), s(&key_ref.fingerprint));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            SSH_LOGIN_ACTION,
                            tenant_ref,
                            &target,
                            AuditOutcome::Deny,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok::<_, IamError>(IssueOutcome::Refused(IamError::with_status(
                        code, message, status,
                    )))
                }
            };
            if principal.session.impersonator_id.is_some() {
                return boxed(|| refuse(
                    "IMPERSONATION_RESTRICTED",
                    "SSH certificates cannot be issued while viewing as someone",
                    403,
                ))
                .await;
            }
            // Decided first, so a principal of another tenant learns nothing about this one's hosts or settings.
            let prepared = ctx
                .decisions()?
                .prepare_decision(&tx, &principal, &tenant, SSH_LOGIN_ACTION)
                .await?;
            if refused_fixed(&prepared) {
                return boxed(|| refuse("ACCESS_DENIED", "Access denied", 403)).await;
            }
            // The platform's root override never opens an organization's servers: a root administrator needs a role
            // in that organization like anyone else (only the root tenant's own hosts are theirs).
            if cross_tenant_root(&prepared, &principal, tenant_ref) {
                return boxed(|| refuse(
                    "ROOT_SSH_RESTRICTED",
                    "Platform administrators need a role in this organization to open its hosts",
                    403,
                ))
                .await;
            }
            let settings = boxed(|| load_ssh_settings(ctx, &tx, tenant_ref)).await?;
            if settings.require_mfa
                && principal.identity.kind == IdentityKind::User
                && !principal.session.mfa
            {
                return boxed(|| refuse(
                    "MFA_REQUIRED",
                    "Sign in with multi-factor authentication to get an SSH certificate",
                    403,
                ))
                .await;
            }
            if settings.require_security_key && !key_ref.security_key {
                return boxed(|| refuse(
                    "SECURITY_KEY_REQUIRED",
                    "This organization certifies only hardware security keys (ed25519-sk or ecdsa-sk)",
                    403,
                ))
                .await;
            }
            let authority = boxed(|| active_authority(&tx, tenant_ref, "user")).await?;
            let authorities = boxed(|| tenant_authorities(&tx, tenant_ref, None)).await?;
            if authorities
                .iter()
                .any(|item| item.fingerprint == key_ref.fingerprint)
            {
                return Ok(IssueOutcome::Refused(IamError::new(
                    "INVALID_INPUT",
                    "An authority key cannot be certified",
                )));
            }
            let hosts: Vec<SshHost> = match hosts_ref {
                Some(names) => {
                    let mut hosts = Vec::new();
                    for name in names {
                        match boxed(|| host_by_name(&tx, tenant_ref, name)).await? {
                            Some(host) if host.status == "enrolled" => hosts.push(host),
                            _ => {
                                return Ok(IssueOutcome::Refused(IamError::with_status(
                                    "NOT_FOUND",
                                    format!("No enrolled host is named {name}"),
                                    404,
                                )));
                            }
                        }
                    }
                    hosts
                }
                None => {
                    boxed(|| find_hosts(
                        &tx,
                        Filter::new()
                            .eq("tenantId", tenant_ref.as_str())
                            .eq("status", "enrolled"),
                    ))
                    .await?
                }
            };
            let labeled = boxed(|| self.classified_hosts(&tx, tenant_ref, &hosts)).await?;
            let access = access_of(&prepared, &hosts, logins_ref.as_ref(), &labeled)?;
            if access.is_empty() {
                return boxed(|| refuse("ACCESS_DENIED", "Access denied", 403)).await;
            }
            if access.len() as f64 > options_ref.max_hosts_per_certificate {
                return Ok(IssueOutcome::Refused(IamError::with_status(
                    "TOO_MANY_HOSTS",
                    format!(
                        "The certificate would name {} hosts; name at most {} with hosts",
                        access.len(),
                        core_js::number_to_string(options_ref.max_hosts_per_certificate)
                    ),
                    400,
                )));
            }
            let mut principals = Vec::new();
            for entry in &access {
                for login in &entry.logins {
                    principals.push(ssh_login_principal(login, &entry.host.name));
                }
            }
            if principals.len() > 256 {
                return Ok(IssueOutcome::Refused(IamError::with_status(
                    "TOO_MANY_HOSTS",
                    "Name fewer hosts or logins (at most 256 principals)",
                    400,
                )));
            }
            let mut extensions: Vec<String> = vec!["permit-pty".into(), "permit-user-rc".into()];
            for (action, extension) in forwarding_actions() {
                if access
                    .iter()
                    .all(|entry| entry.forwarding.get(&action).copied().unwrap_or(false))
                {
                    extensions.push(extension);
                }
            }
            let now = ctx.now();
            let mut valid_before = now
                + ttl
                    .unwrap_or(settings.default_certificate_ms)
                    .min(settings.max_certificate_ms);
            valid_before = valid_before.min(principal.session.expires_at);
            if let Some(expires_at) = principal.identity.expires_at {
                valid_before = valid_before.min(expires_at);
            }
            if principal.session.kind == SessionKind::Delegated {
                valid_before = valid_before.min(now + DELEGATED_CERTIFICATE_MS);
            }
            if !is_root_override(&prepared) {
                valid_before = boxed(|| grant_deadline(ctx, &tx, &principal, tenant_ref, valid_before)).await?;
            }
            if valid_before < now + 60_000.0 {
                return Ok(IssueOutcome::Refused(IamError::with_status(
                    "SESSION_EXPIRING",
                    "This session or the access that allows it ends within a minute; renew it first",
                    401,
                )));
            }
            let mut critical_options: IndexMap<String, String> = IndexMap::new();
            let mut source_address: Option<String> = None;
            if settings.bind_source_address {
                let ip = ctx.auth.current_client().and_then(|client| client.ip);
                let family = match ip.as_deref() {
                    Some(ip) if !ip.is_empty() => ip_family(ip),
                    _ => 0,
                };
                if family == 0 {
                    return Ok(IssueOutcome::Refused(IamError::with_status(
                        "SOURCE_ADDRESS_UNKNOWN",
                        "This organization binds certificates to your address, which could not be determined",
                        400,
                    )));
                }
                let address = format!(
                    "{}/{}",
                    ip.unwrap_or_default(),
                    if family == 6 { 128 } else { 32 }
                );
                critical_options.insert("source-address".into(), address.clone());
                source_address = Some(address);
            }
            if key_ref.security_key && settings.require_user_verification {
                critical_options.insert("verify-required".into(), String::new());
            }
            let serial = ssh_serial();
            let serial_string = serial.to_string();
            let key_id = certificate_key_id(&principal);
            let spec = SshCertificateSpec {
                key: key_ref.clone(),
                serial,
                kind: SSH_CERT_USER as u32,
                key_id: key_id.clone(),
                principals: principals.clone(),
                valid_after: ((now - options_ref.clock_skew_ms) / 1000.0).floor() as u64,
                valid_before: (valid_before / 1000.0).floor() as u64,
                critical_options,
                extensions: extensions.clone(),
            };
            let comment = key_ref.comment.as_deref().map(printable_comment);
            let signed = sign_ssh_certificate(
                &open_authority(ctx, &authority)?,
                &spec,
                comment.as_deref(),
            )?;
            let line = signed.line;
            let root_override = is_root_override(&prepared);
            // The device this request proved, which the sweep judges device conditions by (devices.ts).
            let device = boxed(|| presented_device(&tx, &principal, now)).await?;
            let mut sorted_extensions = extensions.clone();
            crate::js::sort_strings(&mut sorted_extensions);
            let access_value = Value::Array(
                access
                    .iter()
                    .map(|entry| json!({ "host": entry.host.name, "logins": entry.logins }))
                    .collect(),
            );
            let mut record = Record::new();
            record.insert("id".into(), s(id()));
            record.insert("tenantId".into(), s(tenant_ref));
            record.insert(
                "uniqueKey".into(),
                s(format!("{}:{}", authority.id, serial_string)),
            );
            record.insert("kind".into(), s("user"));
            record.insert("serial".into(), s(&serial_string));
            record.insert("keyId".into(), s(&key_id));
            record.insert("authorityId".into(), s(&authority.id));
            record.insert("identityId".into(), s(&principal.identity.id));
            record.insert("sessionId".into(), s(&principal.session.id));
            record.insert("sessionKind".into(), s(principal.session.kind.as_str()));
            record.insert("mfa".into(), Value::Bool(principal.session.mfa));
            if let Some(device) = &device {
                record.insert(
                    "deviceKeyId".into(),
                    device
                        .get("key")
                        .and_then(|key| key.get("id"))
                        .cloned()
                        .unwrap_or(Value::Null),
                );
            }
            record.insert("principals".into(), strings_value(&principals));
            record.insert("access".into(), access_value);
            record.insert("extensions".into(), strings_value(&sorted_extensions));
            if let Some(address) = &source_address {
                record.insert("sourceAddress".into(), s(address));
            }
            record.insert("keyType".into(), s(&key_ref.r#type));
            record.insert("publicKeyFingerprint".into(), s(&key_ref.fingerprint));
            record.insert(
                "validAfter".into(),
                number(now - options_ref.clock_skew_ms),
            );
            record.insert("validBefore".into(), number(valid_before));
            record.insert("issuedAt".into(), number(now));
            if let Some(reason) = reason_ref.as_ref().filter(|reason| !reason.is_empty()) {
                record.insert("reason".into(), s(reason));
            }
            record.insert(
                "expiresAt".into(),
                number(valid_before + options_ref.record_retention_ms),
            );
            let record = boxed(|| tx.insert("sshCertificates", &record)).await?;
            let record_id = str_of(&record, "id").to_owned();
            let mut metadata = Map::new();
            metadata.insert(
                "serial".into(),
                record.get("serial").cloned().unwrap_or(Value::Null),
            );
            metadata.insert("keyId".into(), s(&key_id));
            metadata.insert(
                "hosts".into(),
                Value::Array(access.iter().map(|entry| s(&entry.host.name)).collect()),
            );
            metadata.insert("principals".into(), number(principals.len() as f64));
            metadata.insert("validBefore".into(), number(valid_before));
            metadata.insert("fingerprint".into(), s(&key_ref.fingerprint));
            metadata.insert("keyType".into(), s(&key_ref.r#type));
            if let Some(reason) = reason_ref.as_ref().filter(|reason| !reason.is_empty()) {
                metadata.insert("reason".into(), s(reason));
            }
            ctx.events()?
                .audit(
                    &tx,
                    &principal,
                    "ssh:certificate:issue",
                    tenant_ref,
                    &format!("ssh/certificates/{record_id}"),
                    AuditOutcome::Allow,
                    root_override,
                    Some(metadata),
                )
                .await?;
            let bundle = boxed(|| trust_bundle(ctx, &tx, &tenant, "member")).await?;
            let host_list = boxed(|| revocation_list(ctx, &tx, &tenant, Some("host"))).await?;
            let mut value = Map::new();
            value.insert("id".into(), s(&record_id));
            value.insert("certificate".into(), s(&line));
            value.insert(
                "serial".into(),
                record.get("serial").cloned().unwrap_or(Value::Null),
            );
            value.insert("keyId".into(), s(&key_id));
            value.insert("principals".into(), strings_value(&principals));
            value.insert(
                "validAfter".into(),
                record.get("validAfter").cloned().unwrap_or(Value::Null),
            );
            value.insert("validBefore".into(), number(valid_before));
            value.insert(
                "extensions".into(),
                record.get("extensions").cloned().unwrap_or(Value::Null),
            );
            if let Some(address) = &source_address {
                value.insert("sourceAddress".into(), s(address));
            }
            value.insert(
                "hosts".into(),
                Value::Array(
                    access
                        .iter()
                        .map(|entry| {
                            json!({
                                "name": entry.host.name,
                                "addresses": entry.host.addresses,
                                "logins": entry.logins,
                            })
                        })
                        .collect(),
                ),
            );
            value.insert(
                "knownHosts".into(),
                bundle.get("knownHosts").cloned().unwrap_or(Value::Null),
            );
            value.insert(
                "revokedHostKeys".into(),
                host_list.get("krl").cloned().unwrap_or(Value::Null),
            );
            Ok(IssueOutcome::Issued {
                value: Value::Object(value),
                usage: !root_override,
            })
        });
        let outcome = boxed(|| {
            ctx.observe.span(
                SpanKind::Operation,
                "ssh:certificate:issue",
                Some(&tenant_id),
                work,
                None,
                None,
            )
        })
        .await?;
        match outcome {
            IssueOutcome::Refused(error) => Err(error),
            IssueOutcome::Issued { value, usage } => {
                // Using SSH access is using `ssh:login` (not a root override), for role mining and right-sizing.
                if usage {
                    ctx.usage()?
                        .record(&tenant_id, &authenticated.identity.id, SSH_LOGIN_ACTION);
                }
                Ok(Reply::json(value))
            }
        }
    }

    /// `ssh/listAuthorities`: every authority key of the tenant, newest last (retired ones included). Requires
    /// iam:ssh:read.
    pub async fn list_authorities(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::ListAuthoritiesInput>,
    ) -> IamResult<Reply<ssh::ListAuthoritiesOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                assert_ssh(ctx)?;
                let authorities = tenant_authorities(&tx, &tenant.id, None).await?;
                Ok(Value::Array(
                    authorities.iter().map(public_authority).collect(),
                ))
            })
        });
        let result = self
            .operation(credential, &tenant_id, READ, "ssh/authorities", mutation)
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/listCertificates`: issued certificates, newest first, with filters. Requires iam:ssh:read.
    pub async fn list_certificates(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::ListCertificatesInput>,
    ) -> IamResult<Reply<ssh::ListCertificatesOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                assert_ssh(ctx)?;
                let default_limit = json!(100);
                let default_offset = json!(0);
                let limit = integer(
                    crate::js::defined(body.get("limit")).or(Some(&default_limit)),
                    "limit",
                    1.0,
                    500.0,
                )?;
                let offset = integer(
                    crate::js::defined(body.get("offset")).or(Some(&default_offset)),
                    "offset",
                    0.0,
                    1_000_000.0,
                )?;
                let mut filter = Filter::new().eq("tenantId", tenant.id.as_str());
                if let Some(kind) = body.get("kind") {
                    filter = filter.eq("kind", kind.clone());
                }
                if let Some(identity_id) = body.get("identityId") {
                    filter = filter.eq("identityId", text(Some(identity_id), "identityId", 256)?);
                }
                if let Some(host_id) = body.get("hostId") {
                    filter = filter.eq("hostId", text(Some(host_id), "hostId", 256)?);
                }
                let now = ctx.now();
                let mut views: Vec<(f64, String, Value)> =
                    find_records(&tx, "sshCertificates", filter)
                        .await?
                        .iter()
                        .map(|record| {
                            (
                                num_of(record, "issuedAt").unwrap_or(f64::NAN),
                                str_of(record, "id").to_owned(),
                                certificate_view(record, now),
                            )
                        })
                        .filter(|(_, _, view)| match body.get("status") {
                            None => true,
                            Some(status) => status.as_str() == Some(certificate_status(view)),
                        })
                        .collect();
                views.sort_by(|a, b| newest_first(a.0, &a.1, b.0, &b.1));
                let total = views.len();
                let start = (offset as usize).min(total);
                let end = (offset as usize).saturating_add(limit as usize).min(total);
                let page: Vec<Value> = views[start..end]
                    .iter()
                    .map(|(_, _, view)| view.clone())
                    .collect();
                let mut out = Map::new();
                out.insert("certificates".into(), Value::Array(page));
                out.insert("total".into(), number(total as f64));
                Ok(Value::Object(out))
            })
        });
        let result = self
            .operation(credential, &tenant_id, READ, "ssh/certificates", mutation)
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/listHosts`: the tenant's hosts by name, optionally by status or matching labels. Requires iam:ssh:read.
    pub async fn list_hosts(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::ListHostsInput>,
    ) -> IamResult<Reply<ssh::ListHostsOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                assert_ssh(ctx)?;
                let labels = match body.get("labels") {
                    None => IndexMap::new(),
                    Some(value) => ssh_labels(Some(value))?,
                };
                let query = match body.get("query") {
                    None => None,
                    Some(value) => Some(core_js::to_lower(&text(Some(value), "query", 128)?)),
                };
                let mut filter = Filter::new().eq("tenantId", tenant.id.as_str());
                if truthy(body.get("status")) {
                    filter =
                        filter.eq("status", body.get("status").cloned().unwrap_or(Value::Null));
                }
                let mut hosts: Vec<Record> = find_records(&tx, "sshHosts", filter)
                    .await?
                    .into_iter()
                    .filter(|host| {
                        labels.iter().all(|(key, value)| {
                            host.get("labels")
                                .and_then(|labels| labels.get(key))
                                .and_then(Value::as_str)
                                == Some(value.as_str())
                        })
                    })
                    .filter(|host| match &query {
                        None => true,
                        Some(query) if query.is_empty() => true,
                        Some(query) => {
                            str_of(host, "name").contains(query.as_str())
                                || host.get("addresses").and_then(Value::as_array).is_some_and(
                                    |addresses| {
                                        addresses.iter().any(|address| {
                                            address.as_str().is_some_and(|address| {
                                                address.contains(query.as_str())
                                            })
                                        })
                                    },
                                )
                                || core_js::to_lower(str_of(host, "description"))
                                    .contains(query.as_str())
                        }
                    })
                    .collect();
                hosts.sort_by(|a, b| before(str_of(a, "name"), str_of(b, "name")));
                Ok(Value::Array(hosts.iter().map(public_host).collect()))
            })
        });
        let result = self
            .operation(credential, &tenant_id, READ, "ssh/hosts", mutation)
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/myAccess`: the enrolled hosts the caller may open, with the logins and forwarding policies allow. No
    /// permission needed.
    pub async fn my_access(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::MyAccessInput>,
    ) -> IamResult<Reply<ssh::MyAccessOutput>> {
        let ctx = &self.ctx;
        assert_ssh(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let (tenant_ref, authenticated_ref) = (&tenant_id, &authenticated);
        let result = ctx
            .store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated_ref)
                    .await?;
                let tenant = ctx.tenant(&tx, tenant_ref).await?;
                let prepared = ctx
                    .decisions()?
                    .prepare_decision(&tx, &principal, &tenant, SSH_LOGIN_ACTION)
                    .await?;
                let refused = refused_fixed(&prepared)
                    || cross_tenant_root(&prepared, &principal, tenant_ref);
                let settings = load_ssh_settings(ctx, &tx, tenant_ref).await?;
                let hosts = if refused {
                    Vec::new()
                } else {
                    find_hosts(
                        &tx,
                        Filter::new()
                            .eq("tenantId", tenant_ref.as_str())
                            .eq("status", "enrolled"),
                    )
                    .await?
                };
                let labeled = self.classified_hosts(&tx, tenant_ref, &hosts).await?;
                let hosts_view: Vec<Value> = access_of(&prepared, &hosts, None, &labeled)?
                    .into_iter()
                    .map(|entry| {
                        let mut view = Map::new();
                        view.insert("name".into(), s(&entry.host.name));
                        if let Some(description) =
                            entry.host.description.as_ref().filter(|d| !d.is_empty())
                        {
                            view.insert("description".into(), s(description));
                        }
                        view.insert("addresses".into(), strings_value(&entry.host.addresses));
                        let mut labels = Map::new();
                        for (key, value) in &entry.host.labels {
                            labels.insert(key.clone(), s(value));
                        }
                        view.insert("labels".into(), Value::Object(labels));
                        view.insert("logins".into(), strings_value(&entry.logins));
                        let flag = |action: &str| {
                            entry
                                .forwarding
                                .get(action)
                                .map(|allowed| Value::Bool(*allowed))
                                .unwrap_or(Value::Null)
                        };
                        view.insert(
                            "forwarding".into(),
                            json!({
                                "port": flag("ssh:port-forward"),
                                "agent": flag("ssh:agent-forward"),
                                "x11": flag("ssh:x11-forward"),
                            }),
                        );
                        Value::Object(view)
                    })
                    .collect();
                let mut out = Map::new();
                out.insert("hosts".into(), Value::Array(hosts_view));
                out.insert("requireMfa".into(), Value::Bool(settings.require_mfa));
                out.insert(
                    "requireSecurityKey".into(),
                    Value::Bool(settings.require_security_key),
                );
                out.insert(
                    "defaultCertificateMs".into(),
                    number(settings.default_certificate_ms),
                );
                out.insert(
                    "maxCertificateMs".into(),
                    number(settings.max_certificate_ms),
                );
                Ok(Value::Object(out))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/myCertificates`: the caller's own certificates in the tenant, newest first (the last 100).
    pub async fn my_certificates(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::MyCertificatesInput>,
    ) -> IamResult<Reply<ssh::MyCertificatesOutput>> {
        let ctx = &self.ctx;
        assert_ssh(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let (tenant_ref, authenticated_ref) = (&tenant_id, &authenticated);
        let result = ctx
            .store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated_ref)
                    .await?;
                let now = ctx.now();
                // An agent acting for the person sees only the certificates its own session obtained.
                let delegated = principal.session.kind == SessionKind::Delegated;
                let mut records: Vec<Record> = find_records(
                    &tx,
                    "sshCertificates",
                    Filter::new()
                        .eq("tenantId", tenant_ref.as_str())
                        .eq("identityId", principal.identity.id.as_str()),
                )
                .await?
                .into_iter()
                .filter(|record| !delegated || str_of(record, "sessionId") == principal.session.id)
                .collect();
                records.sort_by(|a, b| {
                    newest_first(
                        num_of(a, "issuedAt").unwrap_or(f64::NAN),
                        str_of(a, "id"),
                        num_of(b, "issuedAt").unwrap_or(f64::NAN),
                        str_of(b, "id"),
                    )
                });
                Ok(Value::Array(
                    records
                        .iter()
                        .take(100)
                        .map(|record| certificate_view(record, now))
                        .collect(),
                ))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/resetJoinToken`: puts a disabled host back into enrollment (or re-enrolls a rebuilt one): returns a
    /// fresh one-time join token; the host's renewal tokens stop working. Requires iam:ssh:manage.
    pub async fn reset_join_token(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::ResetJoinTokenInput>,
    ) -> IamResult<Reply<ssh::ResetJoinTokenOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let name = self
            .host_record_name(&tenant_id, input.get("hostId"))
            .await?;
        let (tenant_ref, body) = (&tenant_id, &input);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let options = assert_ssh(ctx)?;
                let host = self
                    .scoped_host(&tx, tenant_ref, body.get("hostId"))
                    .await?;
                let secret = format!("biam_sshj.{}.{}", str_of(&host, "id"), token());
                let status = if str_of(&host, "status") == "disabled" {
                    s("pending")
                } else {
                    host.get("status").cloned().unwrap_or(Value::Null)
                };
                let mut rest = host;
                rest.shift_remove("renewalTokenHash");
                rest.shift_remove("previousRenewalTokenHash");
                rest.insert("status".into(), status);
                rest.insert("joinTokenHash".into(), s(hash(&secret)));
                rest.insert(
                    "joinTokenExpiresAt".into(),
                    number(ctx.now() + options.join_token_ms),
                );
                rest.insert("updatedAt".into(), number(ctx.now()));
                let saved = tx.put("sshHosts", &rest).await?;
                let mut out = Map::new();
                out.insert("host".into(), public_host(&saved));
                out.insert("joinToken".into(), s(&secret));
                out.insert(
                    "joinTokenExpiresAt".into(),
                    saved
                        .get("joinTokenExpiresAt")
                        .cloned()
                        .unwrap_or(Value::Null),
                );
                Ok(Value::Object(out))
            })
        });
        let result = self
            .operation(
                credential,
                &tenant_id,
                MANAGE,
                &format!("ssh/hosts/{name}"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/retireAuthority`: stops trusting a previous authority. Refused while certificates it signed are still
    /// valid, unless `force` (they are revoked). Requires iam:ssh:manage.
    pub async fn retire_authority(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::RetireAuthorityInput>,
    ) -> IamResult<Reply<ssh::RetireAuthorityOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let authority_id = text(input.get("authorityId"), "authorityId", 256)?;
        let found = ctx
            .scoped(
                &ctx.store,
                "sshAuthorities",
                Some(&s(&authority_id)),
                &tenant_id,
            )
            .await?;
        let found_id = str_of(&found, "id").to_owned();
        let resource = format!("ssh/authorities/{}", js_string(found.get("kind")));
        let (tenant_ref, body) = (&tenant_id, &input);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                assert_ssh(ctx)?;
                let authority = ctx
                    .scoped(&tx, "sshAuthorities", Some(&s(&found_id)), tenant_ref)
                    .await?;
                let status = str_of(&authority, "status");
                if status != "previous" && status != "pending" {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "Only a previous or pending authority can be retired",
                        409,
                    )
                    .into());
                }
                let live = live_certificates(
                    ctx,
                    &tx,
                    &json!({ "tenantId": tenant_ref, "authorityId": str_of(&authority, "id") }),
                )
                .await?;
                if !live.is_empty() && body.get("force") != Some(&Value::Bool(true)) {
                    return Err(IamError::with_status(
                        "RESOURCE_IN_USE",
                        format!(
                            "{} certificates signed by this authority are still valid",
                            live.len()
                        ),
                        409,
                    )
                    .into());
                }
                self.revoke_all(
                    &tx,
                    tenant_ref,
                    live,
                    "authority-retired",
                    &principal.identity.id,
                )
                .await?;
                let mut next = authority;
                next.insert("status".into(), s("retired"));
                next.insert("retiredAt".into(), number(ctx.now()));
                Ok(public_authority_record(
                    tx.put("sshAuthorities", &next).await?,
                )?)
            })
        });
        let result = self
            .operation(credential, &tenant_id, MANAGE, &resource, mutation)
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/revocationList` (public: no credential): the tenant's key revocation list: `user` (default, for sshd
    /// `RevokedKeys`) or `host` (for ssh `RevokedHostKeys`), base64. Public, like a certificate revocation list:
    /// serials and public keys only. Served for suspended organizations too (every user certificate is then
    /// revoked).
    pub async fn revocation_list(
        &self,
        input: Body<ssh::RevocationListInput>,
    ) -> IamResult<Reply<ssh::RevocationListOutput>> {
        let ctx = &self.ctx;
        assert_ssh(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let kind = match crate::js::defined(input.get("kind")) {
            None => "user".to_owned(),
            Some(Value::String(kind)) if kind == "user" || kind == "host" => kind.clone(),
            Some(_) => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "kind must be 'user' or 'host'",
                ));
            }
        };
        let settings = load_ssh_settings(ctx, &ctx.store, &tenant_id).await?;
        let cache_key = format!("{tenant_id}:{kind}");
        let now = ctx.now();
        let cached = self
            .revocation_cache
            .lock()
            .map_err(|_| crate::js::internal_error())?
            .get(&cache_key)
            .cloned();
        if let Some((at, version, value)) = cached
            && version == settings.revocation_version
            && now - at < REVOCATION_CACHE_MS
            && now >= at
        {
            return Ok(Reply::json(value));
        }
        let tenant = ctx.tenant(&ctx.store, &tenant_id).await?;
        let value = revocation_list(ctx, &ctx.store, &tenant, Some(&kind)).await?;
        {
            let mut cache = self
                .revocation_cache
                .lock()
                .map_err(|_| crate::js::internal_error())?;
            if cache.len() >= 1000 {
                cache.shift_remove_index(0);
            }
            cache.insert(cache_key, (now, settings.revocation_version, value.clone()));
        }
        Ok(Reply::json(value))
    }

    /// `ssh/revokeAllCertificates`: revokes every live user certificate of the tenant (a suspected compromise).
    /// Requires iam:ssh:manage.
    pub async fn revoke_all_certificates(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::RevokeAllCertificatesInput>,
    ) -> IamResult<Reply<ssh::RevokeAllCertificatesOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    assert_ssh(ctx)?;
                    let records = live_certificates(
                        ctx,
                        &tx,
                        &json!({ "tenantId": tenant.id, "kind": "user" }),
                    )
                    .await?;
                    let revoked = self
                        .revoke_all(
                            &tx,
                            &tenant.id,
                            records,
                            "tenant-revoked",
                            &principal.identity.id,
                        )
                        .await?;
                    Ok(json!({ "revoked": number(revoked) }))
                })
            },
        );
        let result = self
            .operation(credential, &tenant_id, MANAGE, "ssh/certificates", mutation)
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/revokeCertificate`: revokes one certificate: the caller's own without any permission (not while viewing
    /// as someone nor with a scoped credential; an agent only those of its own session), anyone's with
    /// iam:ssh:manage. Hosts refuse it from their next revocation list.
    pub async fn revoke_certificate(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::RevokeCertificateInput>,
    ) -> IamResult<Reply<ssh::RevokeCertificateOutput>> {
        let ctx = &self.ctx;
        assert_ssh(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let certificate_id = text(input.get("certificateId"), "certificateId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let found = ctx
            .scoped(
                &ctx.store,
                "sshCertificates",
                Some(&s(&certificate_id)),
                &tenant_id,
            )
            .await?;
        let (tenant_ref, certificate_ref) = (&tenant_id, &certificate_id);
        // The own path skips the permission, so only a session acting in its own unrestricted right takes it (not
        // "view as", not a key or token narrowed by a session policy); an agent acting for the person only for
        // certificates its own session obtained.
        let session = &authenticated.session;
        let own = found.get("identityId").and_then(Value::as_str)
            == Some(authenticated.identity.id.as_str())
            && str_of(&found, "kind") == "user"
            && session.impersonator_id.is_none()
            && session.policy.is_none()
            && session.source_policy.is_none()
            && (session.kind != SessionKind::Delegated
                || found.get("sessionId").and_then(Value::as_str) == Some(session.id.as_str()));
        if own {
            let (authenticated_ref, found_ref) = (&authenticated, &found);
            let result = ctx
                .store
                .transaction(move |tx| async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated_ref)
                        .await?;
                    let result = self
                        .revoke_one(&tx, &principal, tenant_ref, certificate_ref)
                        .await?;
                    let mut metadata = Map::new();
                    metadata.insert("reason".into(), s("revoked"));
                    metadata.insert(
                        "serial".into(),
                        found_ref.get("serial").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("own".into(), Value::Bool(true));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "ssh:certificate:revoke",
                            tenant_ref,
                            &format!("ssh/certificates/{certificate_ref}"),
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(result)
                })
                .await?;
            return Ok(Reply::json(result));
        }
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                Ok(self
                    .revoke_one(&tx, &principal, tenant_ref, certificate_ref)
                    .await?)
            })
        });
        let result = self
            .operation(
                credential,
                &tenant_id,
                MANAGE,
                &format!("ssh/certificates/{certificate_id}"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    async fn revoke_one(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        certificate_id: &str,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let record = ctx
            .scoped(tx, "sshCertificates", Some(&s(certificate_id)), tenant_id)
            .await?;
        let typed: SshCertificateRecord = decode(record)?;
        self.revoke_all(
            tx,
            tenant_id,
            vec![typed],
            "revoked",
            &principal.identity.id,
        )
        .await?;
        let record = ctx
            .scoped(tx, "sshCertificates", Some(&s(certificate_id)), tenant_id)
            .await?;
        Ok(certificate_view(&record, ctx.now()))
    }

    /// `ssh/revokeIdentity`: revokes every live certificate of one identity (incident response). Requires
    /// iam:ssh:manage.
    pub async fn revoke_identity(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::RevokeIdentityInput>,
    ) -> IamResult<Reply<ssh::RevokeIdentityOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let identity_id = text(input.get("identityId"), "identityId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    assert_ssh(ctx)?;
                    let records = live_certificates(
                        ctx,
                        &tx,
                        &json!({
                            "tenantId": tenant.id,
                            "identityId": body.get("identityId").cloned().unwrap_or(Value::Null),
                            "kind": "user",
                        }),
                    )
                    .await?;
                    let revoked = self
                        .revoke_all(
                            &tx,
                            &tenant.id,
                            records,
                            "identity-revoked",
                            &principal.identity.id,
                        )
                        .await?;
                    Ok(json!({ "revoked": number(revoked) }))
                })
            },
        );
        let result = self
            .operation(
                credential,
                &tenant_id,
                MANAGE,
                &format!("ssh/identities/{identity_id}"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/rotateAuthority`: starts rotating an authority: a new key is published as `pending`, trusted by hosts
    /// and clients from their next sync, and signs from `activateAuthority`. `activate: true` switches at once (a
    /// compromised key; certificates then only work on hosts that already synced). Requires iam:ssh:manage.
    pub async fn rotate_authority(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::RotateAuthorityInput>,
    ) -> IamResult<Reply<ssh::RotateAuthorityOutput>> {
        let ctx = &self.ctx;
        let kind = match input.get("kind") {
            Some(Value::String(kind)) if kind == "user" || kind == "host" => kind.clone(),
            _ => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "kind must be 'user' or 'host'",
                ));
            }
        };
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let (kind_ref, body) = (&kind, &input);
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    assert_ssh(ctx)?;
                    let existing = tenant_authorities(&tx, &tenant.id, Some(kind_ref)).await?;
                    if existing.iter().any(|item| item.status == "pending") {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A rotation is already pending; activate or retire it first",
                            409,
                        )
                        .into());
                    }
                    let pending = create_authority(
                        ctx,
                        &tx,
                        &tenant.id,
                        kind_ref,
                        "pending",
                        &principal.identity.id,
                    )
                    .await?;
                    if body.get("activate") != Some(&Value::Bool(true)) {
                        return Ok(public_authority(&pending));
                    }
                    let raw = match tx.get("sshAuthorities", &pending.id).await? {
                        Some(record) => record,
                        None => crate::port::encode(&pending),
                    };
                    Ok(public_authority_record(self.activate(&tx, raw).await?)?)
                })
            },
        );
        let result = self
            .operation(
                credential,
                &tenant_id,
                MANAGE,
                &format!("ssh/authorities/{kind}"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/setup`: creates the tenant's user and host authorities (idempotent) and returns the trust to
    /// distribute. Requires iam:ssh:manage.
    pub async fn setup(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::SetupInput>,
    ) -> IamResult<Reply<ssh::SetupOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    assert_ssh(ctx)?;
                    let ensured =
                        ensure_authorities(ctx, &tx, &tenant.id, &principal.identity.id).await?;
                    let authorities = tenant_authorities(&tx, &tenant.id, None).await?;
                    let trust = trust_bundle(ctx, &tx, &tenant, "member").await?;
                    let mut out = Map::new();
                    out.insert("created".into(), strings_value(&ensured.created));
                    out.insert(
                        "authorities".into(),
                        Value::Array(authorities.iter().map(public_authority).collect()),
                    );
                    out.insert("trust".into(), trust);
                    Ok(Value::Object(out))
                })
            },
        );
        let result = self
            .operation(credential, &tenant_id, MANAGE, "ssh/authorities", mutation)
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/status`: configuration and counts at a glance. Requires iam:ssh:read.
    pub async fn status(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::StatusInput>,
    ) -> IamResult<Reply<ssh::StatusOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let options = assert_ssh(ctx)?;
                let authorities = tenant_authorities(&tx, &tenant.id, None).await?;
                let hosts = find_records(
                    &tx,
                    "sshHosts",
                    Filter::new().eq("tenantId", tenant.id.as_str()),
                )
                .await?;
                let now = ctx.now();
                let certificates: Vec<Record> = find_records(
                    &tx,
                    "sshCertificates",
                    Filter::new().eq("tenantId", tenant.id.as_str()),
                )
                .await?
                .into_iter()
                .filter(|record| num_of(record, "validBefore").is_some_and(|before| before > now))
                .collect();
                let count = |status: &str| {
                    hosts
                        .iter()
                        .filter(|host| str_of(host, "status") == status)
                        .count() as f64
                };
                let live_of = |kind: &str| {
                    certificates
                        .iter()
                        .filter(|record| {
                            str_of(record, "kind") == kind && !record.contains_key("revokedAt")
                        })
                        .count() as f64
                };
                let settings = load_ssh_settings(ctx, &tx, &tenant.id).await?;
                let mut out = Map::new();
                out.insert(
                    "configured".into(),
                    Value::Bool(
                        authorities
                            .iter()
                            .any(|item| item.kind == "user" && item.status == "active"),
                    ),
                );
                out.insert("settings".into(), settings_view(&settings, &options));
                out.insert(
                    "authorities".into(),
                    Value::Array(
                        authorities
                            .iter()
                            .filter(|item| item.status != "retired")
                            .map(public_authority)
                            .collect(),
                    ),
                );
                out.insert(
                    "hosts".into(),
                    json!({
                        "pending": number(count("pending")),
                        "enrolled": number(count("enrolled")),
                        "disabled": number(count("disabled")),
                    }),
                );
                out.insert(
                    "certificates".into(),
                    json!({
                        "activeUser": number(live_of("user")),
                        "activeHost": number(live_of("host")),
                        "revoked": number(
                            certificates
                                .iter()
                                .filter(|record| record.contains_key("revokedAt"))
                                .count() as f64
                        ),
                    }),
                );
                out.insert(
                    "hostsExpiringSoon".into(),
                    number(
                        hosts
                            .iter()
                            .filter(|host| {
                                str_of(host, "status") == "enrolled"
                                    && num_of(host, "certificateExpiresAt").unwrap_or(0.0)
                                        < now + 14.0 * DAY
                            })
                            .count() as f64,
                    ),
                );
                Ok(Value::Object(out))
            })
        });
        let result = self
            .operation(credential, &tenant_id, READ, "ssh/settings", mutation)
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/sweep`: runs the continuous-authorization sweep for this tenant now (the scheduler job covers every
    /// tenant). Requires iam:ssh:manage.
    pub async fn sweep(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::SweepInput>,
    ) -> IamResult<Reply<ssh::SweepOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        // Authorized (and audited) first; the sweep then runs in its own short transactions.
        let mutation: Mutation<'_> = Box::new(move |_| {
            Box::pin(async move {
                let options = assert_ssh(ctx)?;
                Ok(serde_json::to_value(&options).unwrap_or(Value::Null))
            })
        });
        self.operation(credential, &tenant_id, MANAGE, "ssh/certificates", mutation)
            .await?;
        let result: SshSweepResult =
            sweep_ssh_certificates(ctx, Some(&json!({ "tenantId": tenant_id }))).await?;
        Ok(Reply::json(sweep_value(&result)))
    }

    /// `ssh/syncHost` (public: no credential): a host's periodic check-in with its renewal token: returns the
    /// current trust, principals files and revocation list, and a new host certificate (with a new renewal token)
    /// when its addresses or the host authority changed or the current one is past two thirds of its lifetime;
    /// `renew: true` forces one at most hourly. `publicKey`, when sent, must be the enrolled key
    /// (`HOST_KEY_CHANGED` otherwise: re-enroll). The renewal token is the credential. While the organization is
    /// suspended a host still syncs (its revocation list then revokes every user certificate) but gets no new
    /// certificate.
    pub async fn sync_host(
        &self,
        input: Body<ssh::SyncHostInput>,
    ) -> IamResult<Reply<ssh::SyncHostOutput>> {
        let ctx = &self.ctx;
        let options = assert_ssh(ctx)?;
        let host_id = token_host(input.get("renewalToken"), "biam_sshr")?;
        if let Some(known) = ctx.store.get("sshHosts", &host_id).await? {
            ctx.auth
                .limit_attempt(
                    str_of(&known, "tenantId"),
                    &format!("ssh:sync:{host_id}"),
                    LimitAttemptOptions {
                        limit: Some(120.0),
                        ..LimitAttemptOptions::default()
                    },
                )
                .await?;
        }
        let offered = match input.get("publicKey") {
            None => None,
            Some(value) => Some(parse_ssh_public_key(Some(value), None)?),
        };
        let presented = hash(&js_string(input.get("renewalToken")));
        let renew = input.get("renew") == Some(&Value::Bool(true));
        let (options_ref, offered_ref, host_ref, presented_ref) =
            (&options, &offered, &host_id, &presented);
        let outcome = ctx
            .store
            .transaction(move |tx| async move {
                let host = tx.get("sshHosts", host_ref).await?;
                let matches = |key: &str| {
                    host.as_ref()
                        .and_then(|host| host.get(key))
                        .and_then(Value::as_str)
                        .is_some_and(|stored| !stored.is_empty() && same_hash(stored, presented_ref))
                };
                let current = matches("renewalTokenHash");
                let previous = matches("previousRenewalTokenHash");
                let host = match host {
                    Some(host) if str_of(&host, "status") == "enrolled" && (current || previous) => host,
                    other => {
                        return Ok(HostOutcome::Refused {
                            error: invalid_token(),
                            host: other,
                            metadata: Map::new(),
                        });
                    }
                };
                let typed: SshHost = decode(host.clone())?;
                let tenant = ctx.tenant(&tx, &typed.tenant_id).await?;
                let active = tenant_active(ctx, &tx, &tenant).await?;
                let key = stored_host_key(&typed)?;
                // The renewal token never moves the host's identity to another key: a stolen token must not yield a
                // host certificate for an attacker's key. A rebuilt host re-enrolls with a new join token.
                if let Some(offered) = offered_ref
                    && offered.fingerprint != key.fingerprint
                {
                    let mut metadata = Map::new();
                    metadata.insert("offered".into(), s(&offered.fingerprint));
                    return Ok(HostOutcome::Refused {
                        error: IamError::with_status(
                            "HOST_KEY_CHANGED",
                            "This host key differs from the enrolled one; re-enroll the host with a new join token",
                            409,
                        ),
                        host: Some(host),
                        metadata,
                    });
                }
                let certificate = match typed.certificate_id.as_deref().filter(|id| !id.is_empty()) {
                    Some(certificate_id) => tx.get("sshCertificates", certificate_id).await?,
                    None => None,
                };
                let now = ctx.now();
                let mut names = vec![typed.name.clone()];
                names.extend(typed.addresses.iter().cloned());
                let principals = unique(names);
                let host_authority = if active {
                    Some(active_authority(&tx, &typed.tenant_id, "host").await?)
                } else {
                    None
                };
                let stale = match &certificate {
                    None => true,
                    Some(certificate) => {
                        let valid_after = num_of(certificate, "validAfter").unwrap_or(f64::NAN);
                        let valid_before = num_of(certificate, "validBefore").unwrap_or(f64::NAN);
                        certificate.contains_key("revokedAt")
                            || certificate.get("publicKeyFingerprint").and_then(Value::as_str)
                                != Some(key.fingerprint.as_str())
                            || host_authority.as_ref().is_some_and(|authority| {
                                certificate.get("authorityId").and_then(Value::as_str)
                                    != Some(authority.id.as_str())
                            })
                            || core_js::stringify(
                                certificate.get("principals").unwrap_or(&Value::Null),
                            ) != core_js::stringify(&strings_value(&principals))
                            || now >= valid_after + ((valid_before - valid_after) * 2.0) / 3.0
                    }
                };
                let forced = renew
                    && match &certificate {
                        None => true,
                        Some(certificate) => {
                            now - num_of(certificate, "issuedAt").unwrap_or(f64::NAN)
                                >= FORCED_RENEWAL_MS
                        }
                    };
                let mut line = certificate
                    .as_ref()
                    .and_then(|certificate| certificate.get("certificate"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let mut issued = certificate;
                let renewed = active && (forced || stale || line.is_empty());
                let mut renewal: Option<String> = None;
                if renewed {
                    let (record, next_line) = self.certify_host(&tx, &typed, &key, options_ref).await?;
                    line = next_line;
                    issued = Some(record);
                    renewal = Some(format!("biam_sshr.{}.{}", typed.id, token()));
                }
                // `issued!.id` of an enrolled host whose certificate record is gone while the organization is
                // suspended: a TypeError in TypeScript.
                let Some(issued) = issued else {
                    return Err(crate::js::internal_error());
                };
                let issued_valid_before = issued.get("validBefore").cloned().unwrap_or(Value::Null);
                let mut next = host.clone();
                next.insert(
                    "certificateId".into(),
                    issued.get("id").cloned().unwrap_or(Value::Null),
                );
                next.insert("certificateExpiresAt".into(), issued_valid_before.clone());
                // A new token rotates in; the one presented stays valid until the new one is used. Using the new one
                // retires the old for good.
                if let Some(renewal) = &renewal {
                    next.insert("renewalTokenHash".into(), s(hash(renewal)));
                    let kept = if current {
                        host.get("renewalTokenHash").cloned()
                    } else {
                        host.get("previousRenewalTokenHash").cloned()
                    };
                    match kept {
                        Some(kept) => {
                            next.insert("previousRenewalTokenHash".into(), kept);
                        }
                        None => {
                            next.shift_remove("previousRenewalTokenHash");
                        }
                    }
                } else if current && truthy(host.get("previousRenewalTokenHash")) {
                    next.shift_remove("previousRenewalTokenHash");
                }
                if renewed {
                    next.insert("renewedAt".into(), number(now));
                }
                next.insert("lastSeenAt".into(), number(now));
                next.insert(
                    "updatedAt".into(),
                    if renewed {
                        number(now)
                    } else {
                        host.get("updatedAt").cloned().unwrap_or(Value::Null)
                    },
                );
                let saved = tx.put("sshHosts", &next).await?;
                if renewed {
                    self.host_audit(
                        &tx,
                        &saved,
                        "ssh:host:renew",
                        json!({
                            "serial": issued.get("serial").cloned().unwrap_or(Value::Null),
                            "fingerprint": key.fingerprint,
                        }),
                    )
                    .await?;
                }
                let expires_at = issued_valid_before.as_f64().unwrap_or(f64::NAN);
                let value = self
                    .host_setup(
                        &tx,
                        &tenant,
                        &saved,
                        (&line, expires_at, renewed),
                        renewal.as_deref(),
                    )
                    .await?;
                Ok(HostOutcome::Done(value))
            })
            .await?;
        match outcome {
            HostOutcome::Refused {
                error,
                host,
                metadata,
            } => Err(self
                .refuse_host(host, "ssh:host:sync", error, metadata)
                .await),
            HostOutcome::Done(value) => Ok(Reply::json(value)),
        }
    }

    /// `ssh/trust` (public: no credential): the tenant's public trust: user authority keys for hosts
    /// (`trustedUserCaKeys` for `TrustedUserCAKeys`) and, when the organization set `hostPatterns`, the
    /// `@cert-authority` line for clients. Public keys and patterns only; members get the line for the enrolled
    /// names from `clientTrust`.
    pub async fn trust(&self, input: Body<ssh::TrustInput>) -> IamResult<Reply<ssh::TrustOutput>> {
        let ctx = &self.ctx;
        assert_ssh(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let tenant = ctx.tenant(&ctx.store, &tenant_id).await?;
        Ok(Reply::json(
            trust_bundle(ctx, &ctx.store, &tenant, "public").await?,
        ))
    }

    /// `ssh/updateHost`: changes a host's addresses, logins, labels or description. New addresses follow the
    /// `createHost` rules; a removed address revokes the host's certificate at once (the host gets a new one at its
    /// next `syncHost`), and new logins reach the principals files then too. Requires iam:ssh:manage.
    pub async fn update_host(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::UpdateHostInput>,
    ) -> IamResult<Reply<ssh::UpdateHostOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let name = self
            .host_record_name(&tenant_id, input.get("hostId"))
            .await?;
        let mut changes: Vec<(&'static str, Value)> = Vec::new();
        if let Some(value) = input.get("logins") {
            changes.push(("logins", strings_value(&host_logins(Some(value))?)));
        }
        if let Some(value) = input.get("addresses") {
            let addresses: Vec<String> = host_addresses(Some(value))?
                .into_iter()
                .filter(|address| *address != name)
                .collect();
            changes.push(("addresses", strings_value(&addresses)));
        }
        if let Some(value) = input.get("labels") {
            let mut labels = Map::new();
            for (key, label) in ssh_labels(Some(value))? {
                labels.insert(key, s(label));
            }
            changes.push(("labels", Value::Object(labels)));
        }
        let resource = format!("ssh/hosts/{name}");
        let (tenant_ref, body, changes_ref) = (&tenant_id, &input, &changes);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                assert_ssh(ctx)?;
                let host = self
                    .scoped_host(&tx, tenant_ref, body.get("hostId"))
                    .await?;
                let mut next = host.clone();
                for (key, value) in changes_ref {
                    next.insert((*key).into(), value.clone());
                }
                next.insert("updatedAt".into(), number(ctx.now()));
                match body.get("description") {
                    Some(Value::Null) => {
                        next.shift_remove("description");
                    }
                    Some(value) => {
                        next.insert(
                            "description".into(),
                            s(text(Some(value), "description", 512)?),
                        );
                    }
                    None => {}
                }
                let addresses_of = |record: &Record| -> Vec<String> {
                    record
                        .get("addresses")
                        .and_then(Value::as_array)
                        .map(|items| items.iter().map(|item| js_string(Some(item))).collect())
                        .unwrap_or_default()
                };
                let (old_addresses, new_addresses) = (addresses_of(&host), addresses_of(&next));
                let added: Vec<String> = new_addresses
                    .iter()
                    .filter(|address| !old_addresses.contains(address))
                    .cloned()
                    .collect();
                let removed: Vec<String> = old_addresses
                    .iter()
                    .filter(|address| !new_addresses.contains(address))
                    .cloned()
                    .collect();
                let host_id = str_of(&host, "id").to_owned();
                if !added.is_empty() {
                    let mut names = vec![str_of(&host, "name").to_owned()];
                    names.extend(added.iter().cloned());
                    self.assert_names_allowed(&tx, &principal, tenant_ref, &names, Some(&host_id))
                        .await?;
                }
                // A name the host gives up could be claimed by another host: its certificate must stop vouching for
                // it.
                if !removed.is_empty() {
                    let live = live_certificates(
                        ctx,
                        &tx,
                        &json!({ "tenantId": tenant_ref, "hostId": host_id }),
                    )
                    .await?;
                    self.revoke_all(
                        &tx,
                        tenant_ref,
                        live,
                        "addresses-changed",
                        &principal.identity.id,
                    )
                    .await?;
                }
                let saved = tx.put("sshHosts", &next).await?;
                let logins_changed = core_js::stringify(host.get("logins").unwrap_or(&Value::Null))
                    != core_js::stringify(saved.get("logins").unwrap_or(&Value::Null));
                let mut out = Map::new();
                out.insert("host".into(), public_host(&saved));
                out.insert(
                    "syncRequired".into(),
                    Value::Bool(logins_changed || !added.is_empty() || !removed.is_empty()),
                );
                Ok(Value::Object(out))
            })
        });
        let result = self
            .audited(
                credential,
                &tenant_id,
                &resource,
                self.operation(credential, &tenant_id, MANAGE, &resource, mutation),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/updateSettings`: changes the tenant's SSH settings (fields left out keep their values). `hostPatterns`
    /// must pin a verified domain of the organization or an address prefix, and cover every host already enrolled.
    /// Requires iam:ssh:manage.
    pub async fn update_settings(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::UpdateSettingsInput>,
    ) -> IamResult<Reply<ssh::UpdateSettingsOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let options = assert_ssh(ctx)?;
                    let current = load_ssh_settings(ctx, &tx, &tenant.id).await?;
                    let mut next: SshSettings = current.clone();
                    for key in [
                        "requireMfa",
                        "requireSecurityKey",
                        "requireUserVerification",
                        "bindSourceAddress",
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
                            "requireMfa" => next.require_mfa = *flag,
                            "requireSecurityKey" => next.require_security_key = *flag,
                            "requireUserVerification" => next.require_user_verification = *flag,
                            _ => next.bind_source_address = *flag,
                        }
                    }
                    if let Some(value) = body.get("maxCertificateMs") {
                        next.max_certificate_ms = integer(
                            Some(value),
                            "maxCertificateMs",
                            60_000.0,
                            options.max_user_certificate_ms,
                        )?;
                    }
                    if let Some(value) = body.get("defaultCertificateMs") {
                        next.default_certificate_ms = integer(
                            Some(value),
                            "defaultCertificateMs",
                            60_000.0,
                            options.max_user_certificate_ms,
                        )?;
                    }
                    if next.default_certificate_ms > next.max_certificate_ms {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "defaultCertificateMs cannot exceed maxCertificateMs",
                        )
                        .into());
                    }
                    if let Some(value) = body.get("hostPatterns") {
                        let domains = verified_domains(&tx, &tenant.id).await?;
                        next.host_patterns = host_pattern_list(Some(value), &domains)?;
                        // Every host the authority already vouches for must stay inside the new patterns.
                        for host in
                            find_hosts(&tx, Filter::new().eq("tenantId", tenant.id.as_str()))
                                .await?
                        {
                            if host.status != "disabled" {
                                let mut names = vec![host.name.clone()];
                                names.extend(host.addresses.iter().cloned());
                                assert_vouchable(&next, &domains, &names)?;
                            }
                        }
                    }
                    next.updated_at = Some(ctx.now());
                    next.updated_by = Some(principal.identity.id.clone());
                    save_ssh_settings(&tx, &next).await?;
                    Ok(settings_view(&next, &options))
                })
            },
        );
        let result = self
            .audited(
                credential,
                &tenant_id,
                "ssh/settings",
                self.operation(credential, &tenant_id, MANAGE, "ssh/settings", mutation),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `ssh/whoCanLogin`: access review: which active identities may log in to a host, and as which logins (each
    /// identity decided in a synthetic session, with MFA when `assumeMfa`). Requires iam:ssh:read.
    pub async fn who_can_login(
        &self,
        credential: &CredentialInput,
        input: Body<ssh::WhoCanLoginInput>,
    ) -> IamResult<Reply<ssh::WhoCanLoginOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let name = self
            .host_record_name(&tenant_id, input.get("hostId"))
            .await?;
        let only = match input.get("login") {
            None => None,
            Some(value) => Some(ssh_login(Some(value))?),
        };
        let (tenant_ref, body, only_ref) = (&tenant_id, &input, &only);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                assert_ssh(ctx)?;
                let host_record = self
                    .scoped_host(&tx, tenant_ref, body.get("hostId"))
                    .await?;
                let host: SshHost = decode(host_record)?;
                let logins: Vec<String> = match only_ref {
                    Some(only) if !only.is_empty() => host
                        .logins
                        .iter()
                        .filter(|login| *login == only)
                        .cloned()
                        .collect(),
                    _ => host.logins.clone(),
                };
                let mut filter = Filter::new()
                    .eq("tenantId", tenant_ref.as_str())
                    .eq("status", "active");
                if let Some(kind) = body.get("kind") {
                    filter = filter.eq("kind", kind.clone());
                }
                let mut identities: Vec<Identity> = find_records(&tx, "identities", filter)
                    .await?
                    .into_iter()
                    .map(decode::<Identity>)
                    .collect::<IamResult<_>>()?;
                identities.sort_by(|a, b| by_id(&a.id, &b.id));
                let labeled = self
                    .classified_hosts(&tx, tenant_ref, std::slice::from_ref(&host))
                    .await?;
                let assume_mfa = body.get("assumeMfa") == Some(&Value::Bool(true));
                let decisions = ctx.decisions()?;
                let mut result = Vec::new();
                for identity in &identities {
                    if ctx.identity_expired(identity) {
                        continue;
                    }
                    let prepared = decisions
                        .prepare_decision(
                            &tx,
                            &decisions.simulated_principal(identity, assume_mfa),
                            &tenant,
                            SSH_LOGIN_ACTION,
                        )
                        .await?;
                    let mut allowed = Vec::new();
                    for login in &logins {
                        let resource = labeled.apply(&login_resource(&host, login));
                        if decide_on(&prepared, &resource, Some(SSH_LOGIN_ACTION))?.allowed {
                            allowed.push(login.clone());
                        }
                    }
                    if !allowed.is_empty() {
                        let mut entry = Map::new();
                        entry.insert("identityId".into(), s(&identity.id));
                        if !identity.name.is_empty() {
                            entry.insert("name".into(), s(&identity.name));
                        }
                        if let Some(email) =
                            identity.email.as_ref().filter(|email| !email.is_empty())
                        {
                            entry.insert("email".into(), s(email));
                        }
                        entry.insert(
                            "kind".into(),
                            serde_json::to_value(identity.kind).unwrap_or(Value::Null),
                        );
                        entry.insert("logins".into(), strings_value(&allowed));
                        result.push(Value::Object(entry));
                    }
                }
                let mut out = Map::new();
                out.insert("host".into(), s(&host.name));
                out.insert("identities".into(), Value::Array(result));
                Ok(Value::Object(out))
            })
        });
        let result = self
            .operation(
                credential,
                &tenant_id,
                READ,
                &format!("ssh/hosts/{name}"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `b.issuedAt - a.issuedAt || (a.id < b.id ? -1 : 1)`.
fn newest_first(a_issued: f64, a_id: &str, b_issued: f64, b_id: &str) -> Ordering {
    let difference = b_issued - a_issued;
    if difference != 0.0 && !difference.is_nan() {
        if difference > 0.0 {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    } else {
        before(a_id, b_id)
    }
}

/// A sweep result as TypeScript returns it (JavaScript numbers).
fn sweep_value(result: &SshSweepResult) -> Value {
    let mut out = Map::new();
    out.insert("examined".into(), number(result.examined));
    out.insert("revoked".into(), number(result.revoked));
    out.insert("byReason".into(), result.by_reason.clone());
    for (key, value) in &result.extra {
        out.insert(key.clone(), value.clone());
    }
    Value::Object(out)
}

/// `iam.ssh`: the deployment-side jobs and public reads (no credential), for schedulers and custom routes.
pub struct SshRuntime {
    ctx: Arc<ServerContext>,
}

/// `createSshRuntime(ctx)`.
pub fn create_ssh_runtime(ctx: &Arc<ServerContext>) -> IamResult<SshRuntime> {
    Ok(SshRuntime { ctx: ctx.clone() })
}

impl SshRuntime {
    /// Whether the `ssh` option is on. (A module that is not ported yet answers its NOT_IMPLEMENTED instead of a
    /// silent false.)
    pub fn enabled(&self) -> IamResult<bool> {
        match assert_ssh(&self.ctx) {
            Ok(_) => Ok(true),
            Err(error) if error.code == "NOT_IMPLEMENTED" => Err(error),
            Err(_) => Ok(false),
        }
    }

    /// Continuous authorization: revokes live certificates whose holder, session or access went away (run every few
    /// minutes).
    pub async fn sweep(&self, input: Option<&Value>) -> IamResult<SshSweepResult> {
        sweep_ssh_certificates(&self.ctx, input).await
    }

    /// A tenant's KRL as bytes, for serving it from a custom route (`application/octet-stream`): the list with
    /// `bytes`, the decoded KRL in the tagged JSON form (`{"$bytes": base64}`).
    pub async fn revocation_list(&self, tenant_id: &str, kind: Option<&str>) -> IamResult<Value> {
        let ctx = &self.ctx;
        assert_ssh(ctx)?;
        let tenant = ctx.tenant(&ctx.store, tenant_id).await?;
        let list = revocation_list(ctx, &ctx.store, &tenant, Some(kind.unwrap_or("user"))).await?;
        let mut out = list.as_object().cloned().unwrap_or_default();
        let krl = list.get("krl").cloned().unwrap_or(s(""));
        out.insert("bytes".into(), json!({ "$bytes": krl }));
        Ok(Value::Object(out))
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let arg = |index: usize| args.get(index).filter(|value| !value.is_null());
        match method {
            "sweep" => Some(self.sweep(arg(0)).await.map(|result| sweep_value(&result))),
            "revocationList" => {
                let tenant_id = arg(0)
                    .map(|value| js_string(Some(value)))
                    .unwrap_or_default();
                let kind = arg(1).map(|value| js_string(Some(value)));
                Some(self.revocation_list(&tenant_id, kind.as_deref()).await)
            }
            _ => None,
        }
    }
}
