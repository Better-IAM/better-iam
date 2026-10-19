//! The standalone server configuration (`better-iam.json`, spec/conformance/CONFIG.md): the native counterpart of
//! `optionsFromConfig` in `scripts/conformance/lib/config.mjs` (Rust-only module).
//!
//! The reader refuses what the TypeScript reader refuses, with the same `INVALID_CONFIG` messages in the same order,
//! and keeps the JSON it read as the options' model value, so the option validators (`resolveConfig`, the catalog,
//! the module settings) see exactly what the TypeScript reader hands `betterIam()`. Callbacks a JSON file cannot hold
//! are the reader's: delivery transports (`delivery`), the echo resolver, the `http.clientInfo` header mapping, and,
//! in conformance mode, scripted callbacks (`{"$scripted": true}`).

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use better_iam_auth::password_policy::{PasswordCheckContext, PasswordPolicyOptions};
use better_iam_auth::{DeliveryError, DeliveryMessage, RateLimitOptions};
use better_iam_core::{IamError, IamResult, IamStore, ResourceRef, SessionClientInfo};
use futures::future::BoxFuture;
use regex::Regex;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::client_info::header;
use crate::js::{self, function_marker, internal_error, is_function, js_string, truthy};
use crate::observe::ObservabilityOptions;
use crate::options::{
    AuditArchiveOptions, BetterIamOptions, ClientInfoFn, DomainOptions, EventOptions, HttpOptions,
    RequestHead, ResolvedResource, ServerAuthOptions, ServerPasskeyOptions, StsOptions, Toggle,
    VaultEngine, VaultOptions, VaultRotator,
};
use crate::safe_fetch::{FetchBody, FetchRequest, GuardedFetchOptions, create_guarded_fetch};

/// Top-level configuration members, in the order CONFIG.md documents them (`configKeys`).
pub const CONFIG_KEYS: [&str; 33] = [
    "$schema",
    "store",
    "secret",
    "previousSecrets",
    "baseURL",
    "basePath",
    "trustedOrigins",
    "authentication",
    "delivery",
    "resolveResource",
    "resolveContext",
    "hierarchy",
    "permissions",
    "onboarding",
    "events",
    "accessRequests",
    "observability",
    "accessUsage",
    "inference",
    "a2a",
    "billing",
    "ssh",
    "verifiableCredentials",
    "clearances",
    "vault",
    "http",
    "tenantDefaults",
    "domains",
    "hosts",
    "regions",
    "sts",
    "signals",
    "auditArchive",
];

/// `BetterIamOptions` members whose value is copied as JSON (`jsonOptionKeys`).
const JSON_OPTION_KEYS: [&str; 19] = [
    "secret",
    "previousSecrets",
    "baseURL",
    "basePath",
    "trustedOrigins",
    "hierarchy",
    "permissions",
    "onboarding",
    "accessRequests",
    "accessUsage",
    "inference",
    "a2a",
    "billing",
    "ssh",
    "verifiableCredentials",
    "clearances",
    "tenantDefaults",
    "hosts",
    "signals",
];

/// The application callbacks a conformance server answers from the recording (`scriptablePaths`).
static SCRIPTABLE_PATHS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"^resolveResource$",
        r"^resolveContext$",
        r"^authentication\.requireMfa$",
        r"^authentication\.passwordPolicy\.(?:isBreached|check)$",
        r"^domains\.resolveTxt$",
        r"^regions\.locate$",
        r"^sts\.webIdentity\.fetchJson$",
        r"^vault\.rotators\.[^.]+\.rotate$",
        r"^vault\.engines\.[^.]+\.(?:issue|revoke|renew)$",
        r"^auditArchive\.write$",
    ]
    .iter()
    .map(|pattern| Regex::new(pattern).expect("regex"))
    .collect()
});

/// `isScriptable(path)`.
pub fn is_scriptable(path: &str) -> bool {
    SCRIPTABLE_PATHS
        .iter()
        .any(|pattern| pattern.is_match(path))
}

/// A scripted callback: called with JSON-representable arguments, it returns the answer the recording gave.
pub type ScriptedFn = Arc<dyn Fn(Vec<Value>) -> BoxFuture<'static, IamResult<Value>> + Send + Sync>;
/// The conformance server's scripted callback for an option path (`runtime.scripted(path)`).
pub type ScriptedFactory = Arc<dyn Fn(&str) -> ScriptedFn + Send + Sync>;
/// A `capture` delivery (`runtime.deliver(kind, message)`), kept for the control endpoints.
pub type CaptureFn =
    Arc<dyn Fn(String, Value) -> BoxFuture<'static, Result<(), DeliveryError>> + Send + Sync>;
/// A `log` delivery line (`runtime.log`, default: standard output).
pub type LogFn = Arc<dyn Fn(String) + Send + Sync>;
/// Opens a store from its JSON description (`runtime.adapters`); the default opens the adapters this crate was built
/// with.
pub type StoreFactory =
    Arc<dyn Fn(&Map<String, Value>) -> IamResult<Arc<dyn IamStore>> + Send + Sync>;

/// What `optionsFromConfig` takes besides the configuration (`runtime`).
#[derive(Clone, Default)]
pub struct ConfigRuntime {
    /// The environment `{"env": "NAME"}` values read (default: this process's).
    pub env: Option<HashMap<String, String>>,
    /// The server clock (conformance mode).
    pub now: Option<better_iam_auth::NowFn>,
    /// `capture` deliveries (conformance mode only).
    pub deliver: Option<CaptureFn>,
    pub log: Option<LogFn>,
    /// Scripted callbacks (conformance mode only).
    pub scripted: Option<ScriptedFactory>,
    /// Replaces the built-in store construction.
    pub open_store: Option<StoreFactory>,
}

fn invalid(message: impl AsRef<str>) -> IamError {
    IamError::new(
        "INVALID_CONFIG",
        format!("Invalid better-iam.json: {}", message.as_ref()),
    )
}

fn is_plain_object(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Object(_))) && !is_function(value)
}

fn as_object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    match value {
        Some(Value::Object(map)) if !is_function(value) => Some(map),
        _ => None,
    }
}

/// `secretValue(value, path, env)`: a string, or `{ "env": "NAME" }`.
fn secret_value(
    value: Option<&Value>,
    path: &str,
    env: &HashMap<String, String>,
) -> IamResult<String> {
    if let Some(Value::String(text)) = value {
        return Ok(text.clone());
    }
    if let Some(map) = as_object(value)
        && let Some(Value::String(name)) = map.get("env")
    {
        return match env.get(name) {
            Some(resolved) if !resolved.is_empty() => Ok(resolved.clone()),
            _ => Err(invalid(format!(
                "{path} names environment variable {name}, which is not set"
            ))),
        };
    }
    Err(invalid(format!(
        "{path} must be a string or {{ \"env\": \"NAME\" }}"
    )))
}

/// An adapter's integer option: values a Rust integer cannot hold become one the adapter refuses with its own
/// message (TypeScript hands the adapter the raw value, which it refuses the same way).
fn adapter_integer(value: Option<&Value>) -> Option<i64> {
    value.map(|value| match js::as_number(value) {
        Some(number) if js::is_safe_integer(number) => number as i64,
        _ => i64::MIN,
    })
}

/// An adapter's string option: anything but a string becomes one the adapter refuses.
fn adapter_string(value: Option<&Value>) -> Option<String> {
    value.map(|value| match value {
        Value::String(text) => text.clone(),
        _ => "\u{0}".to_owned(),
    })
}

/// Opens the store a configuration describes with the adapters this crate was built with.
pub fn open_store(
    store: &Map<String, Value>,
    env: &HashMap<String, String>,
) -> IamResult<Arc<dyn IamStore>> {
    match store.get("kind").and_then(Value::as_str) {
        Some("sqlite") => {
            #[cfg(feature = "sqlite")]
            {
                let filename = match store.get("path") {
                    None => ":memory:".to_owned(),
                    Some(Value::String(path)) => path.clone(),
                    Some(_) => return Err(invalid("store.path must be a string")),
                };
                better_iam_adapter_sqlite::sqlite_adapter(
                    better_iam_adapter_sqlite::SqliteAdapterOptions {
                        filename,
                        busy_timeout_ms: adapter_integer(store.get("busyTimeoutMs")),
                        journal_mode: adapter_string(store.get("journalMode")),
                        durability: adapter_string(store.get("durability")),
                    },
                )
            }
            #[cfg(not(feature = "sqlite"))]
            {
                let _ = env;
                Err(invalid("the sqlite adapter is not available"))
            }
        }
        Some("postgres") => {
            #[cfg(feature = "postgres")]
            {
                better_iam_adapter_postgres::postgres_adapter(
                    better_iam_adapter_postgres::PostgresAdapterOptions {
                        connection_string: secret_value(store.get("url"), "store.url", env)?,
                        pool_size: adapter_integer(store.get("poolSize")),
                        lock_timeout_ms: adapter_integer(store.get("lockTimeoutMs")),
                    },
                )
            }
            #[cfg(not(feature = "postgres"))]
            {
                let _ = env;
                Err(invalid("the postgres adapter is not available"))
            }
        }
        Some("libsql") => {
            #[cfg(feature = "libsql")]
            {
                let url = secret_value(store.get("url"), "store.url", env)?;
                let auth_token = match store.get("authToken") {
                    None => None,
                    Some(value) => Some(secret_value(Some(value), "store.authToken", env)?),
                };
                let encryption_key = match store.get("encryptionKey") {
                    None => None,
                    Some(value) => Some(secret_value(Some(value), "store.encryptionKey", env)?),
                };
                better_iam_adapter_libsql::libsql_adapter(
                    better_iam_adapter_libsql::LibsqlAdapterOptions {
                        url,
                        auth_token,
                        encryption_key,
                        sync_url: adapter_string(store.get("syncUrl")),
                        sync_interval: store
                            .get("syncInterval")
                            .map(|value| js::as_number(value).unwrap_or(f64::NAN)),
                        busy_timeout_ms: None,
                    },
                )
            }
            #[cfg(not(feature = "libsql"))]
            {
                let _ = env;
                Err(invalid("the libsql adapter is not available"))
            }
        }
        _ => Err(invalid("store.kind must be sqlite, postgres or libsql")),
    }
}

/// `isScriptedMarker(value)`: exactly `{"$scripted": true}`.
fn is_scripted_marker(value: Option<&Value>) -> bool {
    matches!(as_object(value), Some(map) if map.len() == 1 && map.get("$scripted") == Some(&Value::Bool(true)))
}

/// `injectScripted(value, path, runtime)`: replaces every `{"$scripted": true}` with a function marker, refusing
/// markers at paths that cannot be scripted or outside conformance mode. Returns the scripted paths in order.
fn inject_scripted(
    value: &mut Value,
    path: &str,
    runtime: &ConfigRuntime,
    scripted: &mut Vec<String>,
) -> IamResult<()> {
    if is_scripted_marker(Some(value)) {
        if !is_scriptable(path) {
            return Err(invalid(format!("{path} cannot be scripted")));
        }
        if runtime.scripted.is_none() {
            return Err(invalid(format!(
                "{path} is scripted, which needs the server's conformance mode"
            )));
        }
        *value = function_marker();
        scripted.push(path.to_owned());
        return Ok(());
    }
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                inject_scripted(item, &format!("{path}[{index}]"), runtime, scripted)?;
            }
        }
        Value::Object(map) if !is_function(Some(&Value::Object(map.clone()))) => {
            let keys: Vec<String> = js::keys(map).into_iter().cloned().collect();
            for key in keys {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if let Some(item) = map.get_mut(&key) {
                    inject_scripted(item, &child, runtime, scripted)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// `clientInfoFunction({ userAgent = true, ipHeader, labelHeader, ipValue = 'first' })`: the JSON form of
/// `http.clientInfo(request)`.
pub fn client_info_function(spec: &Map<String, Value>) -> ClientInfoFn {
    let user_agent = match spec.get("userAgent") {
        None => true,
        Some(value) => truthy(Some(value)),
    };
    let ip_header = spec
        .get("ipHeader")
        .filter(|value| truthy(Some(value)))
        .map(|value| js_string(Some(value)).to_lowercase());
    let label_header = spec
        .get("labelHeader")
        .filter(|value| truthy(Some(value)))
        .map(|value| js_string(Some(value)).to_lowercase());
    let whole = spec.get("ipValue").and_then(Value::as_str) == Some("whole");
    Arc::new(move |request: &RequestHead| {
        let mut info = SessionClientInfo::default();
        if let Some(name) = &ip_header {
            let value = header(&request.headers, name);
            let ip = if whole {
                value
            } else {
                value.map(|value| js::trim(value.split(',').next().unwrap_or("")).to_owned())
            };
            info.ip = ip.filter(|ip| !ip.is_empty());
        }
        if user_agent {
            info.user_agent =
                header(&request.headers, "user-agent").filter(|agent| !agent.is_empty());
        }
        if let Some(name) = &label_header {
            info.label = header(&request.headers, name).filter(|label| !label.is_empty());
        }
        (info.ip.is_some() || info.user_agent.is_some() || info.label.is_some()).then_some(info)
    })
}

/// A delivery transport (`transport(kind)`): what one `delivery` channel does with a message (as JSON).
type Transport = Arc<dyn Fn(Value) -> BoxFuture<'static, Result<(), DeliveryError>> + Send + Sync>;

fn transport(
    delivery: &Map<String, Value>,
    kind: &str,
    runtime: &ConfigRuntime,
) -> IamResult<Option<Transport>> {
    let Some(spec) = delivery.get(kind) else {
        return Ok(None);
    };
    let Some(spec) = as_object(Some(spec)) else {
        return Err(invalid(format!("delivery.{kind} must be an object")));
    };
    let channel = kind.to_owned();
    match spec.get("kind").and_then(Value::as_str) {
        Some("capture") => {
            let Some(deliver) = runtime.deliver.clone() else {
                return Err(invalid(format!(
                    "delivery.{kind} \"capture\" needs the server's conformance mode"
                )));
            };
            Ok(Some(Arc::new(move |message| {
                deliver(channel.clone(), message)
            })))
        }
        Some("log") => {
            let log = runtime.log.clone();
            Ok(Some(Arc::new(move |message| {
                let mut line = Map::new();
                line.insert("delivery".into(), Value::String(channel.clone()));
                line.insert("message".into(), message);
                let text = js::stringify(&Value::Object(line));
                match &log {
                    Some(log) => log(text),
                    None => println!("{text}"),
                }
                Box::pin(async { Ok(()) })
            })))
        }
        Some("http") => {
            let Some(Value::String(url)) = spec.get("url") else {
                return Err(invalid(format!("delivery.{kind}.url is required")));
            };
            let url = url.clone();
            let mut headers: Vec<(String, String)> =
                vec![("content-type".into(), "application/json".into())];
            if let Some(extra) = as_object(spec.get("headers")) {
                for (name, value) in js::entries(extra) {
                    let name = name.to_lowercase();
                    headers.retain(|(existing, _)| *existing != name);
                    headers.push((name, js_string(Some(value))));
                }
            }
            let timeout = spec
                .get("timeoutMs")
                .and_then(js::as_number)
                .unwrap_or(10_000.0);
            // The operator's own endpoint: any address, any port; http only on loopback hosts (TLS elsewhere).
            let fetch = create_guarded_fetch(GuardedFetchOptions {
                allow_private_networks: true,
                allow_insecure_localhost: true,
                any_port: true,
                max_bytes: None,
            });
            Ok(Some(Arc::new(move |message| {
                let mut body = Map::new();
                body.insert("kind".into(), Value::String(channel.clone()));
                body.insert("message".into(), message);
                let mut request = FetchRequest::new(
                    url.clone(),
                    "POST",
                    Some(FetchBody::Text(js::stringify(&Value::Object(body)))),
                );
                for (name, value) in &headers {
                    request = request.header(name.clone(), value.clone());
                }
                let fetch = fetch;
                Box::pin(async move {
                    let wait = Duration::from_millis(timeout.max(0.0) as u64);
                    match tokio::time::timeout(wait, fetch.fetch(request)).await {
                        Err(_) => Err(DeliveryError::new(
                            "TimeoutError",
                            "The operation was aborted due to timeout",
                        )),
                        Ok(Err(_)) => Err(DeliveryError::new("TypeError", "fetch failed")),
                        Ok(Ok(mut response)) => {
                            response.body.cancel();
                            if response.ok() {
                                Ok(())
                            } else {
                                Err(DeliveryError::error(format!(
                                    "delivery endpoint answered {}",
                                    response.status
                                )))
                            }
                        }
                    }
                })
            })))
        }
        _ => Err(invalid(format!(
            "delivery.{kind}.kind must be capture, log or http"
        ))),
    }
}

fn message_value(message: &DeliveryMessage) -> Value {
    serde_json::to_value(message).unwrap_or(Value::Null)
}

/// Decodes a typed member, recording the members a Rust type cannot hold (they are refused after validation).
fn typed<T: DeserializeOwned>(
    model: &Map<String, Value>,
    key: &str,
    undecodable: &mut Vec<(String, String)>,
) -> Option<T> {
    let value = model.get(key)?;
    if value.is_null() {
        return None;
    }
    match serde_json::from_value(strip_functions(value)) {
        Ok(decoded) => Some(decoded),
        Err(error) => {
            undecodable.push((key.to_owned(), error.to_string()));
            None
        }
    }
}

/// The value without function markers (serde reads callbacks from the reader, not from JSON).
fn strip_functions(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(_, item)| !is_function(Some(item)))
                .map(|(key, item)| (key.clone(), strip_functions(item)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(strip_functions).collect()),
        other => other.clone(),
    }
}

fn number_member(map: &Map<String, Value>, key: &str) -> Option<f64> {
    // A non-number becomes NaN, which every numeric validator refuses as TypeScript refuses the raw value.
    map.get(key)
        .filter(|value| !value.is_null())
        .map(|value| js::as_number(value).unwrap_or(f64::NAN))
}

fn bool_member(
    map: &Map<String, Value>,
    key: &str,
    path: &str,
    undecodable: &mut Vec<(String, String)>,
) -> Option<bool> {
    match map.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::Bool(flag)) => Some(*flag),
        Some(_) => {
            undecodable.push((format!("{path}.{key}"), "expected a boolean".into()));
            None
        }
    }
}

fn string_member(
    map: &Map<String, Value>,
    key: &str,
    path: &str,
    undecodable: &mut Vec<(String, String)>,
) -> Option<String> {
    match map.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(_) => {
            undecodable.push((format!("{path}.{key}"), "expected a string".into()));
            None
        }
    }
}

fn scripted_call(runtime: &ConfigRuntime, path: &str) -> ScriptedFn {
    match &runtime.scripted {
        Some(factory) => factory(path),
        None => Arc::new(|_| Box::pin(async { Err(internal_error()) })),
    }
}

/// The typed `authentication` member of a JSON configuration (callbacks come from `delivery` and the script).
fn authentication_options(
    model: &Map<String, Value>,
    runtime: &ConfigRuntime,
    scripted: &[String],
    undecodable: &mut Vec<(String, String)>,
) -> ServerAuthOptions {
    let Some(auth) = as_object(model.get("authentication")) else {
        return ServerAuthOptions::default();
    };
    let path = "authentication";
    let mut options = ServerAuthOptions {
        app_name: string_member(auth, "appName", path, undecodable),
        sign_up_enabled: bool_member(auth, "signUpEnabled", path, undecodable),
        require_email_verification: bool_member(
            auth,
            "requireEmailVerification",
            path,
            undecodable,
        ),
        email_password: bool_member(auth, "emailPassword", path, undecodable),
        passwordless_email: bool_member(auth, "passwordlessEmail", path, undecodable),
        passwordless_sms: bool_member(auth, "passwordlessSms", path, undecodable),
        max_delivery_attempts: number_member(auth, "maxDeliveryAttempts"),
        session_lifetime_ms: number_member(auth, "sessionLifetimeMs"),
        session_idle_timeout_ms: number_member(auth, "sessionIdleTimeoutMs"),
        recent_authentication_ms: number_member(auth, "recentAuthenticationMs"),
        trusted_device_lifetime_ms: number_member(auth, "trustedDeviceLifetimeMs"),
        sign_in_notifications: bool_member(auth, "signInNotifications", path, undecodable),
        mfa_email_codes: bool_member(auth, "mfaEmailCodes", path, undecodable),
        failed_sign_in_alerts: number_member(auth, "failedSignInAlerts"),
        now: runtime.now.clone(),
        ..ServerAuthOptions::default()
    };
    if let Some(limits) = as_object(auth.get("rateLimits")) {
        options.rate_limits = Some(RateLimitOptions {
            attempts: number_member(limits, "attempts"),
            sensitive_attempts: number_member(limits, "sensitiveAttempts"),
            window_ms: number_member(limits, "windowMs"),
            ip_attempts: number_member(limits, "ipAttempts"),
            limiter: None,
        });
    }
    if let Some(passkeys) = as_object(auth.get("passkeys")) {
        let rp_id = string_member(passkeys, "rpID", "authentication.passkeys", undecodable);
        options.passkeys = rp_id.map(|rp_id| ServerPasskeyOptions {
            rp_id,
            rp_name: string_member(passkeys, "rpName", "authentication.passkeys", undecodable),
        });
    }
    if scripted
        .iter()
        .any(|path| path == "authentication.requireMfa")
    {
        let call = scripted_call(runtime, "authentication.requireMfa");
        options.require_mfa = Some(Arc::new(move |tenant, identity| {
            let call = call.clone();
            Box::pin(async move {
                let answer = call(vec![
                    serde_json::to_value(&tenant).unwrap_or(Value::Null),
                    serde_json::to_value(&identity).unwrap_or(Value::Null),
                ])
                .await?;
                Ok(truthy(Some(&answer)))
            })
        }));
    }
    if let Some(policy) = as_object(auth.get("passwordPolicy")) {
        let mut screening = PasswordPolicyOptions {
            block_common_passwords: bool_member(
                policy,
                "blockCommonPasswords",
                "authentication.passwordPolicy",
                undecodable,
            ),
            ..PasswordPolicyOptions::default()
        };
        if scripted
            .iter()
            .any(|path| path == "authentication.passwordPolicy.isBreached")
        {
            let call = scripted_call(runtime, "authentication.passwordPolicy.isBreached");
            screening.is_breached = Some(Arc::new(move |password| {
                let call = call.clone();
                Box::pin(async move {
                    let answer = call(vec![Value::String(password)]).await?;
                    Ok(truthy(Some(&answer)))
                })
            }));
        }
        if scripted
            .iter()
            .any(|path| path == "authentication.passwordPolicy.check")
        {
            let call = scripted_call(runtime, "authentication.passwordPolicy.check");
            screening.check = Some(Arc::new(move |password, context: PasswordCheckContext| {
                let call = call.clone();
                Box::pin(async move {
                    let mut argument = Map::new();
                    argument.insert("tenantId".into(), Value::String(context.tenant_id.clone()));
                    if let Some(identity) = &context.identity {
                        let mut person = Map::new();
                        person.insert("id".into(), Value::String(identity.id.clone()));
                        if let Some(email) = &identity.email {
                            person.insert("email".into(), Value::String(email.clone()));
                        }
                        person.insert("name".into(), Value::String(identity.name.clone()));
                        argument.insert("identity".into(), Value::Object(person));
                    }
                    let answer =
                        call(vec![Value::String(password), Value::Object(argument)]).await?;
                    Ok(answer.as_str().map(str::to_owned))
                })
            }));
        }
        options.password_policy = Some(screening);
    }
    options
}

struct ScriptedRotator(ScriptedFn);

#[async_trait::async_trait]
impl VaultRotator for ScriptedRotator {
    async fn rotate(&self, input: Value) -> IamResult<()> {
        (self.0)(vec![input]).await.map(|_| ())
    }
}

struct ScriptedEngine {
    issue: Option<ScriptedFn>,
    revoke: Option<ScriptedFn>,
    renew: Option<ScriptedFn>,
}

#[async_trait::async_trait]
impl VaultEngine for ScriptedEngine {
    async fn issue(&self, input: Value) -> IamResult<Value> {
        match &self.issue {
            Some(call) => call(vec![input]).await,
            // `engine.issue` is not a function: a TypeError when the vault calls it.
            None => Err(internal_error()),
        }
    }
    fn has_revoke(&self) -> bool {
        self.revoke.is_some()
    }
    async fn revoke(&self, input: Value) -> IamResult<()> {
        match &self.revoke {
            Some(call) => call(vec![input]).await.map(|_| ()),
            None => Ok(()),
        }
    }
    fn has_renew(&self) -> bool {
        self.renew.is_some()
    }
    async fn renew(&self, input: Value) -> IamResult<()> {
        match &self.renew {
            Some(call) => call(vec![input]).await.map(|_| ()),
            None => Ok(()),
        }
    }
}

/// `optionsFromConfig(config, runtime)`: `BetterIamOptions` for a JSON configuration.
pub fn options_from_config(config: &Value, runtime: &ConfigRuntime) -> IamResult<BetterIamOptions> {
    let env: HashMap<String, String> = runtime
        .env
        .clone()
        .unwrap_or_else(|| std::env::vars().collect());
    let Some(config) = as_object(Some(config)) else {
        return Err(invalid("the configuration must be a JSON object"));
    };
    for key in js::keys(config) {
        if !CONFIG_KEYS.contains(&key.as_str()) {
            return Err(invalid(format!("unknown member \"{key}\"")));
        }
    }
    let default_store = {
        let mut store = Map::new();
        store.insert("kind".into(), Value::String("sqlite".into()));
        store.insert("path".into(), Value::String(":memory:".into()));
        Value::Object(store)
    };
    let store = config.get("store").unwrap_or(&default_store);
    let Some(store) = as_object(Some(store)) else {
        return Err(invalid("store must be an object"));
    };
    let database = match (
        &runtime.open_store,
        store.get("kind").and_then(Value::as_str),
    ) {
        (Some(open), Some("sqlite" | "postgres" | "libsql")) => open(store)?,
        (Some(_), _) => return Err(invalid("store.kind must be sqlite, postgres or libsql")),
        (None, _) => open_store(store, &env)?,
    };
    let mut model = Map::new();
    model.insert("database".into(), Value::Object(Map::new()));
    for key in JSON_OPTION_KEYS {
        if let Some(value) = config.get(key) {
            model.insert(key.to_owned(), value.clone());
        }
    }
    if !config.contains_key("secret") {
        return Err(invalid("secret is required"));
    }
    let secret = secret_value(config.get("secret"), "secret", &env)?;
    model.insert("secret".into(), Value::String(secret.clone()));
    let mut previous_secrets = None;
    if let Some(previous) = config.get("previousSecrets") {
        let Value::Array(items) = previous else {
            return Err(invalid("previousSecrets must be an array"));
        };
        let values = items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                secret_value(Some(item), &format!("previousSecrets[{index}]"), &env)
            })
            .collect::<IamResult<Vec<_>>>()?;
        model.insert(
            "previousSecrets".into(),
            Value::Array(values.iter().cloned().map(Value::String).collect()),
        );
        previous_secrets = Some(values);
    }
    let Some(Value::String(base_url)) = config.get("baseURL") else {
        return Err(invalid("baseURL is required"));
    };
    let base_url = base_url.clone();
    for key in ["vault", "domains", "regions", "sts", "auditArchive"] {
        if let Some(value) = config.get(key) {
            model.insert(key.to_owned(), value.clone());
        }
    }
    let mut authentication = if truthy(config.get("authentication")) {
        config.get("authentication").cloned().unwrap_or(Value::Null)
    } else {
        Value::Object(Map::new())
    };
    if runtime.now.is_some() {
        match &mut authentication {
            Value::Object(map) => {
                map.insert("now".into(), function_marker());
            }
            // Assigning a member of a primitive throws in a module (strict mode).
            Value::Array(_) => {}
            _ => return Err(internal_error()),
        }
    }
    let empty = Value::Object(Map::new());
    let delivery = config.get("delivery").unwrap_or(&empty);
    let Some(delivery) = as_object(Some(delivery)) else {
        return Err(invalid("delivery must be an object"));
    };
    for key in js::keys(delivery) {
        if !["email", "sms", "webhook", "events"].contains(&key.as_str()) {
            return Err(invalid(format!("delivery.{key} is not a channel")));
        }
    }
    let send_email = transport(delivery, "email", runtime)?;
    let send_sms = transport(delivery, "sms", runtime)?;
    let deliver_webhook = transport(delivery, "webhook", runtime)?;
    let on_event = transport(delivery, "events", runtime)?;
    if let Value::Object(map) = &mut authentication {
        if send_email.is_some() {
            map.insert("sendEmail".into(), function_marker());
        }
        if send_sms.is_some() {
            map.insert("sendSms".into(), function_marker());
        }
    }
    model.insert("authentication".into(), authentication);
    if config.contains_key("events") || deliver_webhook.is_some() || on_event.is_some() {
        // `structuredClone(config.events ?? {})`.
        let mut events = js::defined(config.get("events"))
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        if deliver_webhook.is_some() || on_event.is_some() {
            // Assigning a member of a primitive throws in a module (strict mode).
            let Value::Object(map) = &mut events else {
                return Err(internal_error());
            };
            if deliver_webhook.is_some() {
                map.insert("deliverWebhook".into(), function_marker());
            }
            if on_event.is_some() {
                map.insert("onEvent".into(), function_marker());
            }
        }
        model.insert("events".into(), events);
    }
    if let Some(observability) = config.get("observability") {
        model.insert("observability".into(), observability.clone());
    }
    let mut client_info = None;
    if let Some(http) = config.get("http") {
        // `const { clientInfo, ...rest } = config.http`: destructuring null throws.
        if http.is_null() {
            return Err(internal_error());
        }
        let mut rest = match http {
            Value::Object(map) => map.clone(),
            _ => Map::new(),
        };
        let spec = rest.shift_remove("clientInfo");
        if let Some(spec) = spec {
            let Some(spec) = as_object(Some(&spec)) else {
                return Err(invalid("http.clientInfo must be an object"));
            };
            if let Some(ip_value) = spec.get("ipValue")
                && ip_value.as_str() != Some("first")
                && ip_value.as_str() != Some("whole")
            {
                return Err(invalid(
                    "http.clientInfo.ipValue must be \"first\" or \"whole\"",
                ));
            }
            client_info = Some(client_info_function(spec));
            rest.insert("clientInfo".into(), function_marker());
        }
        model.insert("http".into(), Value::Object(rest));
    }
    let mut echo = false;
    if let Some(resolver) = config.get("resolveResource") {
        if is_scripted_marker(Some(resolver)) {
            model.insert("resolveResource".into(), resolver.clone());
        } else if !is_plain_object(Some(resolver))
            || resolver.get("kind").and_then(Value::as_str) != Some("echo")
        {
            return Err(invalid("resolveResource.kind must be \"echo\""));
        } else {
            echo = true;
            model.insert("resolveResource".into(), function_marker());
        }
    }
    if let Some(context) = config.get("resolveContext") {
        if !is_scripted_marker(Some(context)) {
            return Err(invalid(
                "resolveContext has no JSON form other than {\"$scripted\": true}",
            ));
        }
        model.insert("resolveContext".into(), context.clone());
    }
    // Every `{"$scripted": true}` becomes the conformance server's callback (database excluded).
    let mut scripted = Vec::new();
    let keys: Vec<String> = model.keys().cloned().collect();
    for key in keys {
        if key == "database" {
            continue;
        }
        if let Some(value) = model.get_mut(&key) {
            inject_scripted(value, &key, runtime, &mut scripted)?;
        }
    }
    let mut undecodable = Vec::new();
    let mut options = BetterIamOptions {
        database: Some(database),
        secret,
        previous_secrets,
        base_url,
        base_path: model
            .get("basePath")
            .and_then(Value::as_str)
            .map(str::to_owned),
        trusted_origins: typed(&model, "trustedOrigins", &mut undecodable),
        hierarchy: typed(&model, "hierarchy", &mut undecodable),
        permissions: typed(&model, "permissions", &mut undecodable),
        onboarding: typed(&model, "onboarding", &mut undecodable),
        access_requests: typed(&model, "accessRequests", &mut undecodable),
        access_usage: typed(&model, "accessUsage", &mut undecodable),
        inference: typed(&model, "inference", &mut undecodable),
        a2a: typed(&model, "a2a", &mut undecodable),
        billing: typed(&model, "billing", &mut undecodable),
        ssh: typed(&model, "ssh", &mut undecodable),
        verifiable_credentials: typed(&model, "verifiableCredentials", &mut undecodable),
        clearances: typed(&model, "clearances", &mut undecodable),
        tenant_defaults: typed(&model, "tenantDefaults", &mut undecodable),
        hosts: typed(&model, "hosts", &mut undecodable),
        signals: typed(&model, "signals", &mut undecodable),
        ..BetterIamOptions::default()
    };
    options.authentication = Some(authentication_options(
        &model,
        runtime,
        &scripted,
        &mut undecodable,
    ));
    let to_message = |transport: &Transport| {
        let transport = transport.clone();
        better_iam_auth::delivery_fn(move |message: DeliveryMessage| {
            transport(message_value(&message))
        })
    };
    if let Some(authentication) = &mut options.authentication {
        authentication.send_email = send_email.as_ref().map(to_message);
        authentication.send_sms = send_sms.as_ref().map(to_message);
    }
    if model.contains_key("events") {
        let mut events: EventOptions =
            typed(&model, "events", &mut undecodable).unwrap_or_default();
        if let Some(transport) = &deliver_webhook {
            let transport = transport.clone();
            events.deliver_webhook = Some(Arc::new(move |delivery| {
                transport(serde_json::to_value(&delivery).unwrap_or(Value::Null))
            }));
        }
        if let Some(transport) = &on_event {
            let transport = transport.clone();
            events.on_event = Some(Arc::new(move |event| {
                let send = transport(Value::Object(event));
                Box::pin(async move { send.await.map_err(|_| internal_error()) })
            }));
        }
        options.events = Some(events);
    }
    if let Some(Value::Object(observability)) = model.get("observability") {
        options.observability = Some(ObservabilityOptions {
            on_span: None,
            metrics: observability.get("metrics").and_then(
                |metrics| match serde_json::from_value::<Toggle<crate::metrics::MetricsOptions>>(
                    metrics.clone(),
                ) {
                    Ok(toggle) => Some(toggle),
                    Err(error) => {
                        undecodable.push(("observability.metrics".into(), error.to_string()));
                        None
                    }
                },
            ),
        });
    }
    if model.contains_key("http") {
        let mut http: HttpOptions = typed(&model, "http", &mut undecodable).unwrap_or_default();
        http.client_info = client_info;
        options.http = Some(http);
    }
    if echo {
        options.resolve_resource = Some(Arc::new(|reference: ResourceRef| {
            Box::pin(async move { Ok(ResolvedResource::of(&reference)) })
        }));
    }
    let has = |path: &str| scripted.iter().any(|item| item == path);
    if has("resolveResource") {
        let call = scripted_call(runtime, "resolveResource");
        options.resolve_resource = Some(Arc::new(move |reference: ResourceRef| {
            let call = call.clone();
            Box::pin(async move {
                let answer = call(vec![
                    serde_json::to_value(&reference).unwrap_or(Value::Null),
                ])
                .await?;
                ResolvedResource::from_value(&answer).ok_or_else(internal_error)
            })
        }));
    }
    if has("resolveContext") {
        let call = scripted_call(runtime, "resolveContext");
        options.resolve_context = Some(Arc::new(move |principal| {
            let call = call.clone();
            Box::pin(async move {
                let mut argument = Map::new();
                argument.insert(
                    "identity".into(),
                    serde_json::to_value(&principal.identity).unwrap_or(Value::Null),
                );
                argument.insert(
                    "session".into(),
                    serde_json::to_value(&principal.session).unwrap_or(Value::Null),
                );
                let answer = call(vec![Value::Object(argument)]).await?;
                match answer {
                    Value::Object(map) => Ok(map),
                    _ => Ok(Map::new()),
                }
            })
        }));
    }
    if model.contains_key("domains") {
        let mut domains: DomainOptions =
            typed(&model, "domains", &mut undecodable).unwrap_or_default();
        if has("domains.resolveTxt") {
            let call = scripted_call(runtime, "domains.resolveTxt");
            domains.resolve_txt = Some(Arc::new(move |hostname| {
                let call = call.clone();
                Box::pin(async move {
                    let answer = call(vec![Value::String(hostname)]).await?;
                    serde_json::from_value(answer).map_err(|_| internal_error())
                })
            }));
        }
        options.domains = Some(domains);
    }
    if model.contains_key("regions") {
        let mut regions: Option<crate::hosts::RegionOptions> =
            typed(&model, "regions", &mut undecodable);
        if let Some(regions) = &mut regions
            && has("regions.locate")
        {
            let call = scripted_call(runtime, "regions.locate");
            regions.locate = Some(Arc::new(move |alias| {
                let call = call.clone();
                Box::pin(async move {
                    let answer = call(vec![Value::String(alias)]).await?;
                    Ok(answer.as_str().map(str::to_owned))
                })
            }));
        }
        options.regions = regions;
    }
    if model.contains_key("sts") {
        let mut sts: Option<StsOptions> = typed(&model, "sts", &mut undecodable);
        if let Some(sts) = &mut sts
            && has("sts.webIdentity.fetchJson")
        {
            let call = scripted_call(runtime, "sts.webIdentity.fetchJson");
            let web = sts.web_identity.get_or_insert_with(Default::default);
            web.fetch_json = Some(Arc::new(move |url| {
                let call = call.clone();
                Box::pin(async move { call(vec![Value::String(url.to_string())]).await })
            }));
        }
        options.sts = sts;
    }
    if model.contains_key("vault") {
        let mut vault: VaultOptions = typed(&model, "vault", &mut undecodable).unwrap_or_default();
        let rotators: Vec<String> = scripted
            .iter()
            .filter_map(|path| path.strip_prefix("vault.rotators."))
            .filter_map(|rest| rest.strip_suffix(".rotate"))
            .map(str::to_owned)
            .collect();
        if !rotators.is_empty() {
            let map = vault.rotators.get_or_insert_with(Default::default);
            for name in rotators {
                let call = scripted_call(runtime, &format!("vault.rotators.{name}.rotate"));
                map.insert(
                    name,
                    Arc::new(ScriptedRotator(call)) as Arc<dyn VaultRotator>,
                );
            }
        }
        let mut engine_names: Vec<String> = Vec::new();
        for path in &scripted {
            if let Some(rest) = path.strip_prefix("vault.engines.")
                && let Some((name, _)) = rest.rsplit_once('.')
                && !engine_names.iter().any(|existing| existing == name)
            {
                engine_names.push(name.to_owned());
            }
        }
        if !engine_names.is_empty() {
            let map = vault.engines.get_or_insert_with(Default::default);
            for name in engine_names {
                let method = |method: &str| {
                    let path = format!("vault.engines.{name}.{method}");
                    has(&path).then(|| scripted_call(runtime, &path))
                };
                map.insert(
                    name.clone(),
                    Arc::new(ScriptedEngine {
                        issue: method("issue"),
                        revoke: method("revoke"),
                        renew: method("renew"),
                    }) as Arc<dyn VaultEngine>,
                );
            }
        }
        options.vault = Some(vault);
    }
    if model.contains_key("auditArchive") {
        let mut archive: AuditArchiveOptions =
            typed(&model, "auditArchive", &mut undecodable).unwrap_or_default();
        if has("auditArchive.write") {
            let call = scripted_call(runtime, "auditArchive.write");
            archive.write = Some(Arc::new(move |batch| {
                let call = call.clone();
                Box::pin(async move {
                    call(vec![serde_json::to_value(&batch).unwrap_or(Value::Null)])
                        .await
                        .map(|_| ())
                })
            }));
        }
        options.audit_archive = Some(archive);
    }
    options.model = Some(Arc::new(Value::Object(model)));
    options.undecodable = undecodable;
    Ok(options)
}

/// Reads `better-iam.json` (`JSON.parse`; a syntax error is an exception the server answers as INTERNAL_ERROR) and
/// builds the options.
pub fn load_config_file(
    path: &std::path::Path,
    runtime: &ConfigRuntime,
) -> IamResult<BetterIamOptions> {
    let text = std::fs::read_to_string(path).map_err(|_| internal_error())?;
    let config = js::parse_json(&text)?;
    options_from_config(&config, runtime)
}
