//! Port of `packages/ldap/src/server.ts`: the read-only LDAPv3 gateway over Better IAM, on tokio (plain LDAP, or
//! LDAPS with a rustls server configuration).

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use better_iam_core::{CredentialInput, IamError, IamResult, js};
use regex::Regex;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

use crate::ber::{self, BerError};
use crate::directory::{
    AttributeList, DirectoryData, DirectoryEntry, build_entries, select_attributes,
};
use crate::dn::{DnError, Rdn, depth_below, format_dn, is_under, normalize_dn, parse_dn};
use crate::filter::{Filter, match_filter};
use crate::protocol::{
    LdapMessage, LdapRequest, SearchScope, bind_response, compare_response, decode_message,
    extended_response, generic_response, notice_of_disconnection, oid, paged_results_control,
    read_paged_results, result_code, search_done, search_entry,
};

/// The client a bind records on the session it creates (`{ ip, userAgent }`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientInfo {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

/// What a service bind needs from `iam.authenticate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapPrincipal {
    pub identity_id: String,
    pub identity_tenant_id: String,
    pub identity_kind: String,
    pub session_tenant_id: String,
    pub session_kind: String,
}

/// `iam.ldap.tenantForBase`: the tenant publishing its directory under a base DN, with its gateway settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapTenant {
    pub tenant_id: String,
    pub base_dn: String,
    pub normalized_base_dn: String,
    pub people_bind: bool,
    pub service_bind: bool,
    pub require_tls: bool,
    /// `auto` or `never`.
    pub mfa_suffix: String,
}

/// The kind of account a bind name names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindKind {
    Person,
    Service,
}

impl BindKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BindKind::Person => "person",
            BindKind::Service => "service",
        }
    }
}

/// `iam.ldap.resolveBindName`: the account a bind name names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindName {
    pub identity_id: String,
    pub email: Option<String>,
    /// `none`, `totp` or `unavailable`.
    pub mfa: Option<String>,
}

/// What the gateway needs from a `betterIam()` instance (`LdapIam`). Calls that record the client (`iam.auth.withClient`
/// around them in TypeScript) receive it.
#[async_trait::async_trait]
pub trait LdapIam: Send + Sync {
    /// `iam.auth.withClient(client, () => iam.api.auth.signIn(input))`.
    async fn sign_in(&self, client: &ClientInfo, input: Value) -> IamResult<Value>;
    /// `iam.auth.withClient(client, () => iam.api.auth.verifyMfa(input))`.
    async fn verify_mfa(&self, client: &ClientInfo, input: Value) -> IamResult<Value>;
    /// `iam.api.auth.signOut(credential)`.
    async fn sign_out(&self, credential: &CredentialInput) -> IamResult<Value>;
    /// `iam.api.ldap.directory(credential, { tenantId })`.
    async fn directory(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
    ) -> IamResult<DirectoryData>;
    /// `iam.auth.withClient(client, () => iam.authenticate(credential))`.
    async fn authenticate(
        &self,
        client: &ClientInfo,
        credential: &CredentialInput,
    ) -> IamResult<LdapPrincipal>;
    /// `iam.ldap.tenantForBase(normalizedBaseDn)`.
    async fn tenant_for_base(&self, normalized_base_dn: &str) -> IamResult<Option<LdapTenant>>;
    /// `iam.ldap.resolveBindName(tenantId, kind, value)`.
    async fn resolve_bind_name(
        &self,
        tenant_id: &str,
        kind: BindKind,
        value: &str,
    ) -> IamResult<Option<BindName>>;
}

/// An error the gateway could not answer (reported to `on_error`, then the connection closes).
#[derive(Debug, Clone, PartialEq)]
pub enum LdapError {
    Iam(IamError),
    Ber(BerError),
    Dn(DnError),
}

impl fmt::Display for LdapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LdapError::Iam(error) => write!(f, "{}", error.message),
            LdapError::Ber(error) => write!(f, "{error}"),
            LdapError::Dn(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LdapError {}

impl From<IamError> for LdapError {
    fn from(error: IamError) -> Self {
        LdapError::Iam(error)
    }
}

impl From<BerError> for LdapError {
    fn from(error: BerError) -> Self {
        LdapError::Ber(error)
    }
}

impl From<DnError> for LdapError {
    fn from(error: DnError) -> Self {
        LdapError::Dn(error)
    }
}

/// `onError`: called with errors the gateway could not answer.
pub type ErrorHandler = Arc<dyn Fn(&LdapError) + Send + Sync>;

/// `LdapServerOptions`.
#[derive(Clone)]
pub struct LdapServerOptions {
    pub iam: Arc<dyn LdapIam>,
    /// Serve LDAPS (TLS from the first byte) with this configuration. Without it, plain LDAP.
    pub tls: Option<Arc<ServerConfig>>,
    /// The most entries one search returns, and the largest page (default 1000).
    pub max_results: Option<usize>,
    /// Connections idle this long are closed (default 5 minutes).
    pub idle_timeout_ms: Option<u64>,
    /// The largest request accepted (default 64 KiB).
    pub max_request_bytes: Option<usize>,
    /// How long a connection reuses a directory snapshot between searches (default 5 seconds).
    pub cache_ms: Option<f64>,
    /// The most simultaneous connections (default 1000).
    pub max_connections: Option<usize>,
    /// Called with errors the gateway could not answer (logging).
    pub on_error: Option<ErrorHandler>,
}

impl LdapServerOptions {
    /// Options with every default.
    pub fn new(iam: Arc<dyn LdapIam>) -> Self {
        Self {
            iam,
            tls: None,
            max_results: None,
            idle_timeout_ms: None,
            max_request_bytes: None,
            cache_ms: None,
            max_connections: None,
            on_error: None,
        }
    }
}

/// A bound connection: the tenant, the bound DN, and the credential searches use.
#[derive(Clone)]
struct Binding {
    tenant_id: String,
    base_dn: String,
    normalized_base_dn: String,
    dn: String,
    credential: CredentialInput,
    /// The gateway created the session (a person's bind) and signs it out when the binding ends.
    owned: bool,
}

#[derive(Clone)]
struct Cache {
    at: f64,
    tenant_id: String,
    entries: Arc<Vec<DirectoryEntry>>,
}

type Writer = Box<dyn AsyncWrite + Send + Unpin>;

struct Connection {
    id: u64,
    secure: bool,
    remote: Option<String>,
    writer: tokio::sync::Mutex<Option<Writer>>,
    binding: Mutex<Option<Binding>>,
    cache: Mutex<Option<Cache>>,
    closed: AtomicBool,
    stopped: Notify,
    last_activity: Mutex<tokio::time::Instant>,
}

struct Settings {
    iam: Arc<dyn LdapIam>,
    max_results: usize,
    idle_timeout: Duration,
    max_request_bytes: usize,
    cache_ms: f64,
    max_connections: usize,
    on_error: Option<ErrorHandler>,
}

struct Inner {
    settings: Settings,
    tls: Option<Arc<ServerConfig>>,
    connections: Mutex<HashMap<u64, Arc<Connection>>>,
    next_id: AtomicU64,
}

/// The server `createLdapServer` returns.
pub struct LdapServer {
    inner: Arc<Inner>,
    accept: Mutex<Option<JoinHandle<()>>>,
}

fn loopback(address: Option<&str>) -> bool {
    match address {
        None => true,
        Some(address) => {
            address.is_empty()
                || address == "::1"
                || address.starts_with("127.")
                || address == "::ffff:127.0.0.1"
        }
    }
}

fn credential_of(value: &Value) -> Option<CredentialInput> {
    value
        .get("token")
        .and_then(Value::as_str)
        .map(|token| CredentialInput {
            headers: None,
            token: Some(token.to_owned()),
        })
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(number)) => number
            .as_f64()
            .is_some_and(|value| value != 0.0 && !value.is_nan()),
        Some(Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    }
}

/// `value.slice(0, 64)` in UTF-16 code units (a split surrogate pair encodes as U+FFFD).
fn slice_utf16(value: &str, units: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    for c in value.chars() {
        let width = c.len_utf16();
        if count + width > units {
            if count < units {
                out.push('\u{FFFD}');
            }
            break;
        }
        out.push(c);
        count += width;
    }
    out
}

/// `Number.parseInt(text, 10)`: NaN when no digits lead.
fn parse_int(text: &str) -> f64 {
    let trimmed = js::trim(text);
    let (negative, digits) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let digits: String = digits.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return f64::NAN;
    }
    let value: f64 = digits.parse().unwrap_or(f64::NAN);
    if negative { -value } else { value }
}

static MFA_SUFFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)^.+[0-9]{6}$").unwrap());

/// A read-only LDAPv3 gateway over Better IAM. Applications bind as a person (`uid={uid},ou=people,{base}` with the
/// password, plus the current one-time code appended when the organization requires MFA) or as a service account
/// (`cn={name},ou=services,{base}` with an API key as the password), then search people, groups and service accounts
/// of the organization whose base DN they use. Binds go through Better IAM sign-in, so rate limits, lockouts, allowed
/// methods, IP rules and sign-in alerts apply; searches are authorized as the bound account (`iam:ldap:read` for the
/// whole directory, otherwise only its own entry). Writes are refused.
pub fn create_ldap_server(options: LdapServerOptions) -> LdapServer {
    LdapServer {
        inner: Arc::new(Inner {
            settings: Settings {
                iam: options.iam,
                max_results: options.max_results.unwrap_or(1000),
                idle_timeout: Duration::from_millis(options.idle_timeout_ms.unwrap_or(5 * 60_000)),
                max_request_bytes: options.max_request_bytes.unwrap_or(65536),
                cache_ms: options.cache_ms.unwrap_or(5000.0),
                max_connections: options.max_connections.unwrap_or(1000),
                on_error: options.on_error,
            },
            tls: options.tls,
            connections: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }),
        accept: Mutex::new(None),
    }
}

impl LdapServer {
    /// Starts listening (port 0 picks a free one; default 389, or 636 with TLS, on 127.0.0.1); answers the bound
    /// address.
    pub async fn listen(
        &self,
        port: Option<u16>,
        host: Option<&str>,
    ) -> std::io::Result<SocketAddr> {
        let port = port.unwrap_or(if self.inner.tls.is_some() { 636 } else { 389 });
        let listener = TcpListener::bind((host.unwrap_or("127.0.0.1"), port)).await?;
        let address = listener.local_addr()?;
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((socket, remote)) = listener.accept().await else {
                    continue;
                };
                let inner = inner.clone();
                tokio::spawn(async move {
                    let remote = Some(remote.ip().to_string());
                    match inner.tls.clone() {
                        Some(config) => {
                            if let Ok(stream) = TlsAcceptor::from(config).accept(socket).await {
                                inner.accept(stream, true, remote).await;
                            }
                        }
                        None => inner.accept(socket, false, remote).await,
                    }
                });
            }
        });
        if let Some(previous) = self
            .accept
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(handle)
        {
            previous.abort();
        }
        Ok(address)
    }

    /// Stops accepting connections, tells connected clients, and signs out the sessions it created.
    pub async fn close(&self) {
        if let Some(handle) = self.accept.lock().unwrap_or_else(|e| e.into_inner()).take() {
            handle.abort();
        }
        let connections: Vec<Arc<Connection>> = self
            .inner
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        let notice = notice_of_disconnection(result_code::UNAVAILABLE, "Server shutting down");
        futures_join(
            connections
                .iter()
                .map(|connection| self.inner.close(connection, Some(&notice))),
        )
        .await;
    }

    /// Live connections (for metrics).
    pub fn connections(&self) -> usize {
        self.inner
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

impl Drop for LdapServer {
    fn drop(&mut self) {
        if let Some(handle) = self.accept.lock().unwrap_or_else(|e| e.into_inner()).take() {
            handle.abort();
        }
    }
}

async fn futures_join<F: std::future::Future<Output = ()>>(futures: impl Iterator<Item = F>) {
    for future in futures {
        future.await;
    }
}

impl Inner {
    async fn write(&self, connection: &Connection, chunks: &[Vec<u8>]) {
        if connection.closed.load(Ordering::SeqCst) {
            return;
        }
        let mut writer = connection.writer.lock().await;
        if let Some(stream) = writer.as_mut() {
            let bytes = chunks.concat();
            if stream.write_all(&bytes).await.is_err() || stream.flush().await.is_err() {
                *writer = None;
            }
        }
        *connection
            .last_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();
    }

    async fn release(&self, binding: Option<Binding>) {
        if let Some(binding) = binding.filter(|binding| binding.owned) {
            let _ = self.settings.iam.sign_out(&binding.credential).await;
        }
    }

    async fn close(&self, connection: &Connection, notice: Option<&Vec<u8>>) {
        if connection.closed.load(Ordering::SeqCst) {
            return;
        }
        if let Some(notice) = notice {
            self.write(connection, std::slice::from_ref(notice)).await;
        }
        if connection.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&connection.id);
        let binding = connection
            .binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(mut stream) = connection.writer.lock().await.take() {
            let _ = stream.shutdown().await;
        }
        connection.stopped.notify_waiters();
        connection.stopped.notify_one();
        self.release(binding).await;
    }

    /// The tenant whose base DN `dn` lies under: the longest matching suffix.
    async fn tenant_of(&self, dn: &str) -> Result<Option<(LdapTenant, Vec<Vec<Rdn>>)>, LdapError> {
        let rdns = parse_dn(dn)?;
        for start in 0..rdns.len() {
            let suffix = normalize_dn(&format_dn(&rdns[start..]))?;
            if let Some(found) = self.settings.iam.tenant_for_base(&suffix).await? {
                return Ok(Some((found, rdns[..start].to_vec())));
            }
        }
        Ok(None)
    }

    async fn bind(
        &self,
        connection: &Connection,
        id: i64,
        version: i64,
        name: &str,
        password: Option<&[u8]>,
        sasl: Option<&str>,
    ) {
        let previous = connection
            .binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        *connection.cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.release(previous).await;
        let answer = |code: i64, message: &str| bind_response(id, code, message);
        if version != 3 {
            return self
                .write(
                    connection,
                    &[answer(
                        result_code::PROTOCOL_ERROR,
                        "Only LDAPv3 is supported",
                    )],
                )
                .await;
        }
        if sasl.is_some() {
            return self
                .write(
                    connection,
                    &[answer(
                        result_code::AUTH_METHOD_NOT_SUPPORTED,
                        "Use a simple bind",
                    )],
                )
                .await;
        }
        let password = password
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .unwrap_or_default();
        if name.is_empty() && password.is_empty() {
            return self
                .write(connection, &[answer(result_code::SUCCESS, "")])
                .await;
        }
        // RFC 4513 5.1.2: a name with an empty password is an unauthenticated bind; never treat it as signed in.
        if password.is_empty() {
            return self
                .write(
                    connection,
                    &[answer(
                        result_code::UNWILLING_TO_PERFORM,
                        "Unauthenticated binds are not allowed",
                    )],
                )
                .await;
        }
        let invalid = answer(result_code::INVALID_CREDENTIALS, "Invalid credentials");
        let target = match self.tenant_of(name).await {
            Ok(target) => target,
            Err(_) => {
                return self
                    .write(
                        connection,
                        &[answer(result_code::INVALID_DN_SYNTAX, "Invalid DN")],
                    )
                    .await;
            }
        };
        let Some((target, relative)) = target.filter(|(_, relative)| relative.len() == 2) else {
            return self.write(connection, &[invalid]).await;
        };
        if target.require_tls && !connection.secure && !loopback(connection.remote.as_deref()) {
            return self
                .write(
                    connection,
                    &[answer(
                        result_code::CONFIDENTIALITY_REQUIRED,
                        "Bind over TLS (LDAPS)",
                    )],
                )
                .await;
        }
        let (leaf, container) = (&relative[0], &relative[1]);
        let ou = if container.len() == 1 && js::to_lower(&container[0].kind) == "ou" {
            js::to_lower(&container[0].value)
        } else {
            String::new()
        };
        let rdn = if leaf.len() == 1 {
            Some(&leaf[0])
        } else {
            None
        };
        let client = ClientInfo {
            ip: connection.remote.clone(),
            user_agent: Some("better-iam-ldap".into()),
        };
        let outcome: IamResult<Option<Binding>> = async {
            if ou == "people"
                && rdn.is_some_and(|rdn| js::to_lower(&rdn.kind) == "uid")
                && target.people_bind
            {
                let rdn = rdn.expect("checked");
                let person = self
                    .settings
                    .iam
                    .resolve_bind_name(&target.tenant_id, BindKind::Person, &rdn.value)
                    .await?;
                let Some(person) = person else {
                    return Ok(None);
                };
                let Some(email) = person.email.clone().filter(|email| !email.is_empty()) else {
                    return Ok(None);
                };
                let credential = self
                    .sign_in_person(
                        &target.tenant_id,
                        &email,
                        person.mfa.as_deref(),
                        &password,
                        &target.mfa_suffix,
                        &client,
                    )
                    .await?;
                let Some(credential) = credential else {
                    return Ok(None);
                };
                return Ok(Some(Binding {
                    tenant_id: target.tenant_id.clone(),
                    base_dn: target.base_dn.clone(),
                    normalized_base_dn: target.normalized_base_dn.clone(),
                    dn: name.to_owned(),
                    credential,
                    owned: true,
                }));
            }
            if ou == "services"
                && rdn.is_some_and(|rdn| js::to_lower(&rdn.kind) == "cn")
                && target.service_bind
            {
                let rdn = rdn.expect("checked");
                let service = self
                    .settings
                    .iam
                    .resolve_bind_name(&target.tenant_id, BindKind::Service, &rdn.value)
                    .await?;
                let Some(service) = service else {
                    return Ok(None);
                };
                let credential = CredentialInput {
                    headers: None,
                    token: Some(password.clone()),
                };
                let principal = self.settings.iam.authenticate(&client, &credential).await?;
                if principal.identity_id != service.identity_id
                    || principal.session_tenant_id != target.tenant_id
                    || principal.session_kind != "api-key"
                {
                    return Ok(None);
                }
                return Ok(Some(Binding {
                    tenant_id: target.tenant_id.clone(),
                    base_dn: target.base_dn.clone(),
                    normalized_base_dn: target.normalized_base_dn.clone(),
                    dn: name.to_owned(),
                    credential,
                    owned: false,
                }));
            }
            Ok(None)
        }
        .await;
        match outcome {
            Ok(Some(binding)) => {
                *connection.binding.lock().unwrap_or_else(|e| e.into_inner()) = Some(binding);
                self.write(connection, &[answer(result_code::SUCCESS, "")])
                    .await
            }
            Ok(None) => self.write(connection, &[invalid]).await,
            Err(error) if error.code == "RATE_LIMITED" => {
                self.write(
                    connection,
                    &[answer(
                        result_code::UNWILLING_TO_PERFORM,
                        "Too many attempts; try again later",
                    )],
                )
                .await
            }
            Err(_) => self.write(connection, &[invalid]).await,
        }
    }

    /// Signs a person in: with the password, or, when they must use MFA and `mfa_suffix` allows it, with the password
    /// followed by the current six-digit authenticator code. Exactly one sign-in attempt per bind, so a person's own
    /// binds never count as failed sign-ins.
    async fn sign_in_person(
        &self,
        tenant_id: &str,
        email: &str,
        mfa: Option<&str>,
        password: &str,
        mfa_suffix: &str,
        client: &ClientInfo,
    ) -> IamResult<Option<CredentialInput>> {
        let iam = &self.settings.iam;
        let sign_in = |secret: String| {
            iam.sign_in(
                client,
                json!({ "tenantId": tenant_id, "email": email, "password": secret }),
            )
        };
        let mfa = mfa.unwrap_or("none");
        if mfa == "unavailable" {
            return Ok(None);
        }
        if mfa == "none" {
            return Ok(credential_of(&sign_in(password.to_owned()).await?));
        }
        if mfa_suffix != "auto" || !MFA_SUFFIX.is_match(password) {
            return Ok(None);
        }
        let (secret, code) = password.split_at(password.len() - 6);
        let result = sign_in(secret.to_owned()).await?;
        // MFA stopped being required in the meantime: the digits were not part of the password.
        if let Some(direct) = credential_of(&result) {
            let _ = iam.sign_out(&direct).await;
            return Ok(None);
        }
        let challenge = result
            .get("challenge")
            .filter(|challenge| truthy(Some(challenge)));
        let (true, Some(challenge)) = (truthy(result.get("mfaRequired")), challenge) else {
            return Ok(None);
        };
        let verified = iam
            .verify_mfa(
                client,
                json!({ "tenantId": tenant_id, "challenge": challenge, "code": code }),
            )
            .await?;
        Ok(credential_of(&verified))
    }

    async fn entries_for(
        &self,
        connection: &Connection,
    ) -> Result<Arc<Vec<DirectoryEntry>>, LdapError> {
        let Some(binding) = connection
            .binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            return Err(LdapError::Iam(IamError::new(
                "UNAUTHENTICATED",
                "Bind first",
            )));
        };
        let now = js::now_ms();
        if let Some(cache) = connection
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            && cache.tenant_id == binding.tenant_id
            && now - cache.at < self.settings.cache_ms
        {
            return Ok(cache.entries.clone());
        }
        let data = self
            .settings
            .iam
            .directory(&binding.credential, &binding.tenant_id)
            .await?;
        let entries = Arc::new(build_entries(&data)?);
        *connection.cache.lock().unwrap_or_else(|e| e.into_inner()) = Some(Cache {
            at: now,
            tenant_id: binding.tenant_id.clone(),
            entries: entries.clone(),
        });
        Ok(entries)
    }

    fn root_dse() -> AttributeList {
        vec![
            (
                "objectClass".into(),
                vec!["top".into(), "extensibleObject".into()],
            ),
            ("supportedLDAPVersion".into(), vec!["3".into()]),
            ("supportedExtension".into(), vec![oid::WHO_AM_I.into()]),
            ("supportedControl".into(), vec![oid::PAGED_RESULTS.into()]),
            ("supportedSASLMechanisms".into(), Vec::new()),
            ("vendorName".into(), vec!["Better IAM".into()]),
        ]
    }

    #[allow(clippy::too_many_arguments)]
    async fn search(
        &self,
        connection: &Connection,
        message: &LdapMessage,
        base: &str,
        scope: SearchScope,
        size_limit: i64,
        types_only: bool,
        filter: &Filter,
        attributes: &[String],
    ) -> Result<(), LdapError> {
        let id = message.id;
        let binding = connection
            .binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if base.is_empty() && scope == SearchScope::Base {
            let mut entry = Self::root_dse();
            if let Some(binding) = &binding {
                entry.push(("namingContexts".into(), vec![binding.base_dn.clone()]));
            }
            let entry: AttributeList = entry
                .into_iter()
                .filter(|(_, values)| !values.is_empty())
                .collect();
            self.write(connection, &[search_entry(id, "", &entry, types_only)])
                .await;
            self.write(
                connection,
                &[search_done(id, result_code::SUCCESS, "", "", None)],
            )
            .await;
            return Ok(());
        }
        let Some(binding) = binding else {
            self.write(
                connection,
                &[search_done(
                    id,
                    result_code::INSUFFICIENT_ACCESS_RIGHTS,
                    "Bind first",
                    "",
                    None,
                )],
            )
            .await;
            return Ok(());
        };
        let Ok(base) = normalize_dn(base) else {
            self.write(
                connection,
                &[search_done(
                    id,
                    result_code::INVALID_DN_SYNTAX,
                    "Invalid base DN",
                    "",
                    None,
                )],
            )
            .await;
            return Ok(());
        };
        // Another organization's tree does not exist for this binding.
        if !is_under(&base, &binding.normalized_base_dn)? {
            self.write(
                connection,
                &[search_done(
                    id,
                    result_code::NO_SUCH_OBJECT,
                    "No such object",
                    "",
                    None,
                )],
            )
            .await;
            return Ok(());
        }
        let Ok(entries) = self.entries_for(connection).await else {
            self.write(
                connection,
                &[search_done(
                    id,
                    result_code::INSUFFICIENT_ACCESS_RIGHTS,
                    "Access denied",
                    "",
                    None,
                )],
            )
            .await;
            return Ok(());
        };
        if !entries.iter().any(|item| item.normalized_dn == base) {
            self.write(
                connection,
                &[search_done(
                    id,
                    result_code::NO_SUCH_OBJECT,
                    "No such object",
                    &binding.normalized_base_dn,
                    None,
                )],
            )
            .await;
            return Ok(());
        }
        let mut matches: Vec<&DirectoryEntry> = Vec::new();
        for item in entries.iter() {
            let depth = depth_below(&item.normalized_dn, &base)?;
            let in_scope = match scope {
                SearchScope::Base => depth == 0,
                SearchScope::One => depth == 1,
                SearchScope::Sub => depth >= 0,
            };
            if in_scope && match_filter(filter, &item.index) {
                matches.push(item);
            }
        }
        let max_results = self.settings.max_results as i64;
        if let Some(paging) = message
            .controls
            .iter()
            .find(|control| control.kind == oid::PAGED_RESULTS)
        {
            let page = read_paged_results(paging.value.as_deref())?;
            let size = page
                .as_ref()
                .map(|page| page.size)
                .unwrap_or(max_results)
                .max(1)
                .min(max_results);
            let offset = match &page {
                Some(page) if !page.cookie.is_empty() => {
                    parse_int(&String::from_utf8_lossy(&page.cookie))
                }
                _ => 0.0,
            };
            if !js::is_safe_integer(offset) || offset < 0.0 {
                self.write(
                    connection,
                    &[search_done(
                        id,
                        result_code::PROTOCOL_ERROR,
                        "Invalid paging cookie",
                        "",
                        None,
                    )],
                )
                .await;
                return Ok(());
            }
            let offset = offset as usize;
            let end = offset.saturating_add(size as usize);
            for item in matches.iter().skip(offset).take(size as usize) {
                self.write(
                    connection,
                    &[search_entry(
                        id,
                        &item.dn,
                        &select_attributes(item, attributes),
                        types_only,
                    )],
                )
                .await;
            }
            let next = if end < matches.len() {
                end.to_string().into_bytes()
            } else {
                Vec::new()
            };
            self.write(
                connection,
                &[search_done(
                    id,
                    result_code::SUCCESS,
                    "",
                    "",
                    Some(paged_results_control(matches.len() as i64, &next)),
                )],
            )
            .await;
            return Ok(());
        }
        let limit = (if size_limit > 0 {
            size_limit
        } else {
            max_results
        })
        .min(max_results);
        for item in matches.iter().take(limit.max(0) as usize) {
            self.write(
                connection,
                &[search_entry(
                    id,
                    &item.dn,
                    &select_attributes(item, attributes),
                    types_only,
                )],
            )
            .await;
        }
        let done = if matches.len() as i64 > limit {
            search_done(
                id,
                result_code::SIZE_LIMIT_EXCEEDED,
                &format!("More than {limit} entries match"),
                "",
                None,
            )
        } else {
            search_done(id, result_code::SUCCESS, "", "", None)
        };
        self.write(connection, &[done]).await;
        Ok(())
    }

    async fn compare(
        &self,
        connection: &Connection,
        id: i64,
        entry: &str,
        attribute: &str,
        value: &str,
    ) -> Result<(), LdapError> {
        let binding = connection
            .binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(binding) = binding else {
            self.write(
                connection,
                &[compare_response(
                    id,
                    result_code::INSUFFICIENT_ACCESS_RIGHTS,
                    "Bind first",
                )],
            )
            .await;
            return Ok(());
        };
        let Ok(target) = normalize_dn(entry) else {
            self.write(
                connection,
                &[compare_response(
                    id,
                    result_code::INVALID_DN_SYNTAX,
                    "Invalid DN",
                )],
            )
            .await;
            return Ok(());
        };
        let found = if is_under(&target, &binding.normalized_base_dn)? {
            self.entries_for(connection)
                .await?
                .iter()
                .find(|item| item.normalized_dn == target)
                .cloned()
        } else {
            None
        };
        let Some(found) = found else {
            self.write(
                connection,
                &[compare_response(
                    id,
                    result_code::NO_SUCH_OBJECT,
                    "No such object",
                )],
            )
            .await;
            return Ok(());
        };
        let matched = match_filter(
            &Filter::Equal {
                attribute: attribute.to_owned(),
                value: value.to_owned(),
            },
            &found.index,
        );
        let code = if matched {
            result_code::COMPARE_TRUE
        } else {
            result_code::COMPARE_FALSE
        };
        self.write(connection, &[compare_response(id, code, "")])
            .await;
        Ok(())
    }

    async fn handle(
        &self,
        connection: &Connection,
        message: &LdapMessage,
    ) -> Result<(), LdapError> {
        let id = message.id;
        match &message.request {
            LdapRequest::Bind {
                version,
                name,
                password,
                sasl,
            } => {
                self.bind(
                    connection,
                    id,
                    *version,
                    name,
                    password.as_deref(),
                    sasl.as_deref(),
                )
                .await;
                Ok(())
            }
            LdapRequest::Unbind => {
                self.close(connection, None).await;
                Ok(())
            }
            LdapRequest::Search {
                base,
                scope,
                size_limit,
                types_only,
                filter,
                attributes,
                ..
            } => {
                self.search(
                    connection,
                    message,
                    base,
                    *scope,
                    *size_limit,
                    *types_only,
                    filter,
                    attributes,
                )
                .await
            }
            LdapRequest::Compare {
                entry,
                attribute,
                value,
            } => self.compare(connection, id, entry, attribute, value).await,
            LdapRequest::Extended { name, .. } => {
                if name == oid::WHO_AM_I {
                    let dn = connection
                        .binding
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .as_ref()
                        .map(|binding| format!("dn:{}", binding.dn))
                        .unwrap_or_default();
                    self.write(
                        connection,
                        &[extended_response(
                            id,
                            result_code::SUCCESS,
                            "",
                            None,
                            Some(dn.as_bytes()),
                        )],
                    )
                    .await;
                    return Ok(());
                }
                let message = format!("Unsupported extended operation {}", slice_utf16(name, 64));
                self.write(
                    connection,
                    &[extended_response(
                        id,
                        result_code::PROTOCOL_ERROR,
                        &message,
                        None,
                        None,
                    )],
                )
                .await;
                Ok(())
            }
            LdapRequest::Abandon { .. } => Ok(()),
            LdapRequest::Unsupported { response_tag, .. } => {
                self.write(
                    connection,
                    &[generic_response(
                        id,
                        *response_tag,
                        result_code::UNWILLING_TO_PERFORM,
                        "This directory is read-only",
                    )],
                )
                .await;
                Ok(())
            }
        }
    }

    async fn accept<S>(self: Arc<Self>, socket: S, secure: bool, remote: Option<String>)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut reader, writer) = tokio::io::split(socket);
        if self
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
            >= self.settings.max_connections
        {
            let mut writer = writer;
            let _ = writer
                .write_all(&notice_of_disconnection(
                    result_code::BUSY,
                    "Too many connections",
                ))
                .await;
            let _ = writer.shutdown().await;
            return;
        }
        let connection = Arc::new(Connection {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            secure,
            remote,
            writer: tokio::sync::Mutex::new(Some(Box::new(writer))),
            binding: Mutex::new(None),
            cache: Mutex::new(None),
            closed: AtomicBool::new(false),
            stopped: Notify::new(),
            last_activity: Mutex::new(tokio::time::Instant::now()),
        });
        self.connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(connection.id, connection.clone());
        // One request at a time per connection, in order.
        let (queue, mut requests) = mpsc::unbounded_channel::<LdapMessage>();
        let worker = {
            let inner = self.clone();
            let connection = connection.clone();
            tokio::spawn(async move {
                while let Some(message) = requests.recv().await {
                    if connection.closed.load(Ordering::SeqCst) {
                        continue;
                    }
                    if let Err(error) = inner.handle(&connection, &message).await {
                        if let Some(on_error) = &inner.settings.on_error {
                            on_error(&error);
                        }
                        let notice = notice_of_disconnection(result_code::OTHER, "Internal error");
                        inner.close(&connection, Some(&notice)).await;
                    }
                }
            })
        };
        let mut buffer: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 16 * 1024];
        let max = self.settings.max_request_bytes;
        'reading: loop {
            if connection.closed.load(Ordering::SeqCst) {
                break;
            }
            let idle_deadline = *connection
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                + self.settings.idle_timeout;
            let read = tokio::select! {
                read = reader.read(&mut chunk) => Some(read),
                _ = tokio::time::sleep_until(idle_deadline) => None,
                _ = connection.stopped.notified() => break 'reading,
            };
            let count = match read {
                None => {
                    let last = *connection
                        .last_activity
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if tokio::time::Instant::now() >= last + self.settings.idle_timeout {
                        let notice =
                            notice_of_disconnection(result_code::UNAVAILABLE, "Idle timeout");
                        self.close(&connection, Some(&notice)).await;
                        break;
                    }
                    continue;
                }
                Some(Ok(0)) | Some(Err(_)) => {
                    self.close(&connection, None).await;
                    break;
                }
                Some(Ok(count)) => count,
            };
            *connection
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();
            buffer.extend_from_slice(&chunk[..count]);
            loop {
                let item = match ber::read_element(&buffer, 0, max) {
                    Err(error) => {
                        let notice =
                            notice_of_disconnection(result_code::PROTOCOL_ERROR, error.message());
                        self.close(&connection, Some(&notice)).await;
                        break 'reading;
                    }
                    Ok(item) => item,
                };
                let Some(item) = item else {
                    if buffer.len() > max + 8 {
                        let notice = notice_of_disconnection(
                            result_code::PROTOCOL_ERROR,
                            "Request too large",
                        );
                        self.close(&connection, Some(&notice)).await;
                        break 'reading;
                    }
                    break;
                };
                let size = item.size;
                let decoded = decode_message(&item);
                buffer.drain(..size);
                match decoded {
                    Ok(message) => {
                        let _ = queue.send(message);
                    }
                    Err(error) => {
                        let notice =
                            notice_of_disconnection(result_code::PROTOCOL_ERROR, error.message());
                        self.close(&connection, Some(&notice)).await;
                        break 'reading;
                    }
                }
            }
        }
        drop(queue);
        let _ = worker.await;
    }
}
