//! Port of `packages/server/src/hosts.ts`: organization sign-in addresses (`hosts`) and regions (`regions`), their
//! records, `normalizeHost`, and the request-time service `createHosts` ([`create_hosts`]).
//!
//! Like an AWS account's sign-in URL or a Slack workspace address, each organization can be reached at its own host:
//! a subdomain built from its alias (`acme.signin.example.com`), optionally with a region in it, or a custom hostname
//! the organization proved it controls. The request-time service is the [`crate::contracts::HostService`] contract.

use std::sync::{Arc, LazyLock};

use better_iam_core::{IamError, IamResult};
use futures::future::BoxFuture;
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::Url;

use crate::js::{self, internal_error, invalid_config, is_function, member, utf16_len};

/// `HostOptions`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostOptions {
    /// Hostname templates; `{tenant}` stands for an organization's alias and `{region}` for one of the regions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<String>>,
    /// Lets organizations verify hostnames of their own with a DNS TXT record. Default false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_hostnames: Option<bool>,
    /// The hostname organizations point their custom hostname at with a CNAME record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname_target: Option<String>,
    /// The path of your sign-in page on an organization's address (default `/`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_path: Option<String>,
    /// Read the address from `X-Forwarded-Host` before `Host` (only behind a proxy you control).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded_host: Option<bool>,
}

/// One region of [`RegionOptions`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionSettings {
    #[serde(rename = "baseURL", default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// `regions.locate(alias)`: the region an organization alias lives in when this region's database does not know it.
pub type LocateFn =
    Arc<dyn Fn(String) -> BoxFuture<'static, IamResult<Option<String>>> + Send + Sync>;

/// `RegionOptions`.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct RegionOptions {
    /// This deployment's region, for example `us-east-1`.
    pub current: String,
    /// Every region organizations can live in, with the base URL of that region's deployment and a display label.
    pub regions: IndexMap<String, RegionSettings>,
    #[serde(skip)]
    pub locate: Option<LocateFn>,
}

impl std::fmt::Debug for RegionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegionOptions")
            .field("current", &self.current)
            .field("regions", &self.regions)
            .field("locate", &self.locate.is_some())
            .finish()
    }
}

/// `TenantHostname`: a hostname an organization claims as its own sign-in address.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantHostname {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub hostname: String,
    /// `'pending' | 'verified'`.
    pub status: String,
    pub verification_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    pub created_at: f64,
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<f64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `HostnameOwner`: global ownership record (id = the hostname).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostnameOwner {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub hostname_id: String,
    pub verified_at: f64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `HostMatch`: the organization an address belongs to.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostMatch {
    pub tenant_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    pub hostname: String,
    /// `'pattern' | 'custom'`.
    pub via: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_region: Option<String>,
}

/// `WrongRegionError`: the organization is served by another region's deployment (HTTP 421).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrongRegionError {
    pub region: String,
    pub location: Option<String>,
    pub error: IamError,
}

impl WrongRegionError {
    /// `new WrongRegionError(region, location, organization = 'This organization')`.
    pub fn new(region: &str, location: Option<String>, organization: Option<&str>) -> Self {
        let organization = organization.unwrap_or("This organization");
        let message = match &location {
            Some(location) => format!("{organization} signs in at {location}"),
            None => format!("{organization} is served from the {region} region"),
        };
        Self {
            region: region.to_owned(),
            location,
            error: IamError::with_status("WRONG_REGION", message, 421),
        }
    }
}

impl From<WrongRegionError> for IamError {
    /// The error, with its region and sign-in location kept for the HTTP answer ([`crate::port::details_of`]).
    fn from(error: WrongRegionError) -> Self {
        crate::port::with_details(
            error.error,
            crate::port::ErrorDetails {
                region: Some(error.region),
                location: error.location,
                ..crate::port::ErrorDetails::default()
            },
        )
    }
}

/// A compiled hostname template (`CompiledPattern`).
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub source: String,
    pub regex: Regex,
    pub has_region: bool,
    /// Everything after the last placeholder when it starts a new label (`.signin.example.com`), else ''.
    pub suffix: String,
    current_region: Option<String>,
}

impl CompiledPattern {
    /// `fill(alias, region)`: the hostname of an alias (in a region, default the current one).
    pub fn fill(&self, alias: &str, region: Option<&str>) -> String {
        let region = region
            .map(str::to_owned)
            .or_else(|| self.current_region.clone())
            .unwrap_or_default();
        self.source
            .replacen("{tenant}", alias, 1)
            .replacen("{region}", &region, 1)
    }
}

/// `ResolvedHostConfig`.
#[derive(Debug, Clone)]
pub struct ResolvedHostConfig {
    pub patterns: Vec<CompiledPattern>,
    pub custom_hostnames: bool,
    pub cname_target: Option<String>,
    pub sign_in_path: String,
    pub forwarded_host: bool,
    /// True when any organization address can exist, so requests must be resolved.
    pub enabled: bool,
}

/// `ResolvedRegionConfig`.
#[derive(Clone)]
pub struct ResolvedRegionConfig {
    pub current: String,
    pub regions: IndexMap<String, RegionSettings>,
    pub locate: Option<LocateFn>,
}

impl std::fmt::Debug for ResolvedRegionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedRegionConfig")
            .field("current", &self.current)
            .field("regions", &self.regions)
            .field("locate", &self.locate.is_some())
            .finish()
    }
}

const ALIAS_SOURCE: &str = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
static REGION_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").expect("regex"));
static HOST_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:]+\])(?::[0-9]{1,5})?$").expect("regex")
});
static SIGN_IN_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/[A-Za-z0-9_./~%-]*$").expect("regex"));

/// `/^(?!-)[a-z0-9-]{1,63}(?<!-)$/`.
fn hostname_label(part: &str) -> bool {
    (1..=63).contains(&part.len())
        && part
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !part.starts_with('-')
        && !part.ends_with('-')
}

/// `loopbackHost(hostname)`.
pub fn loopback_host(hostname: &str) -> bool {
    hostname == "localhost"
        || hostname.ends_with(".localhost")
        || hostname == "127.0.0.1"
        || hostname == "[::1]"
}

/// `url.hostname` as WHATWG serializes it (IPv6 in brackets).
pub fn url_hostname(url: &Url) -> String {
    match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        Some(url::Host::Ipv4(address)) => address.to_string(),
        Some(url::Host::Domain(domain)) => domain.to_owned(),
        None => String::new(),
    }
}

/// `url.origin` (`null` for opaque origins).
pub fn url_origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

/// `url.protocol` (`https:`).
pub fn url_protocol(url: &Url) -> String {
    format!("{}:", url.scheme())
}

/// `normalizeHost(value)`: a request's address, lowercase and without a trailing dot, or None when it is not a plain
/// `host[:port]`.
pub fn normalize_host(value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.is_empty() {
        return None;
    }
    let mut host = js::trim(value).to_lowercase();
    // `.replace(/\.(?=:\d+$|$)/, '')`: the first dot that ends the host or precedes the port.
    let found = host
        .char_indices()
        .find(|(index, c)| {
            *c == '.' && {
                let rest = &host[index + 1..];
                rest.is_empty()
                    || (rest.len() > 1
                        && rest.starts_with(':')
                        && rest[1..].bytes().all(|b| b.is_ascii_digit()))
            }
        })
        .map(|(index, _)| index);
    if let Some(index) = found {
        host.remove(index);
    }
    (HOST_SHAPE.is_match(&host) && utf16_len(&host) <= 260).then_some(host)
}

/// The members of an object or array as `Object.entries` lists them.
fn object_entries(value: &Value) -> Vec<(String, &Value)> {
    match value {
        Value::Object(map) => js::entries(map)
            .into_iter()
            .map(|(key, value)| (key.clone(), value))
            .collect(),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), value))
            .collect(),
        Value::String(text) => text
            .encode_utf16()
            .enumerate()
            .map(|(index, _)| (index.to_string(), &Value::Null))
            .collect(),
        _ => Vec::new(),
    }
}

/// `typeof value === 'object'` (null and arrays included, functions excluded).
fn typeof_object(value: &Value) -> bool {
    matches!(value, Value::Null | Value::Array(_) | Value::Object(_)) && !is_function(Some(value))
}

/// `resolveRegionConfig(options)`: validates `options.regions` and applies defaults; None for a single-region
/// deployment. `locate` is the typed callback (the model value only says whether one is set).
pub fn resolve_region_config(
    options: Option<&Value>,
    locate: Option<LocateFn>,
) -> IamResult<Option<ResolvedRegionConfig>> {
    let Some(options) = options else {
        return Ok(None);
    };
    let invalid = |detail: String| invalid_config(format!("regions.{detail}"));
    if options.is_null() || !typeof_object(options) {
        return Err(invalid("options must be an object".into()));
    }
    let current = match member(Some(options), "current") {
        Some(Value::String(current)) if REGION_NAME.is_match(current) => current.clone(),
        _ => {
            return Err(invalid(
                "current must be a region name such as us-east-1".into(),
            ));
        }
    };
    let regions_value = member(Some(options), "regions");
    if !js::truthy(regions_value) || !regions_value.is_some_and(typeof_object) {
        return Err(invalid(
            "regions must map each region name to its settings".into(),
        ));
    }
    let entries = object_entries(regions_value.expect("checked"));
    if entries.is_empty() || entries.len() > 64 {
        return Err(invalid("regions must list 1 to 64 regions".into()));
    }
    let mut regions = IndexMap::new();
    for (name, settings) in entries {
        if !REGION_NAME.is_match(&name) {
            return Err(invalid(format!(
                "regions has an invalid region name: {name}"
            )));
        }
        let empty = Value::Object(Map::new());
        let value = if settings.is_null() { &empty } else { settings };
        if !typeof_object(value) {
            return Err(invalid(format!("regions.{name} must be an object")));
        }
        let mut entry = RegionSettings::default();
        if let Some(base_url) = member(Some(value), "baseURL") {
            let Ok(url) = Url::parse(&js::js_string(Some(base_url))) else {
                return Err(invalid(format!(
                    "regions.{name}.baseURL must be an absolute URL"
                )));
            };
            if url.scheme() != "https"
                && !(url.scheme() == "http" && loopback_host(&url_hostname(&url)))
            {
                return Err(invalid(format!(
                    "regions.{name}.baseURL must use HTTPS outside localhost"
                )));
            }
            let path = url.path();
            let path = path.strip_suffix('/').unwrap_or(path);
            entry.base_url = Some(format!("{}{path}", url_origin(&url)));
        }
        if let Some(label) = member(Some(value), "label") {
            match label {
                Value::String(text) if !js::trim(text).is_empty() && utf16_len(text) <= 64 => {
                    entry.label = Some(js::trim(text).to_owned());
                }
                _ => {
                    return Err(invalid(format!(
                        "regions.{name}.label must be 1 to 64 characters"
                    )));
                }
            }
        }
        regions.insert(name, entry);
    }
    if !regions.contains_key(&current) {
        return Err(invalid("current must be one of regions".into()));
    }
    let locate_value = member(Some(options), "locate");
    if locate_value.is_some() && !is_function(locate_value) {
        return Err(invalid("locate must be a function".into()));
    }
    Ok(Some(ResolvedRegionConfig {
        current,
        regions,
        locate: if locate_value.is_some() { locate } else { None },
    }))
}

/// What `resolveHostConfig` validates the patterns against.
pub struct HostConfigContext<'a> {
    pub base_url: &'a Url,
    pub regions: Option<&'a ResolvedRegionConfig>,
    pub passkey_rp_id: Option<&'a str>,
}

/// `resolveHostConfig(options, context)`: validates `options.hosts` against the base URL, the regions, and the
/// passkey RP ID, and compiles the patterns.
pub fn resolve_host_config(
    options: Option<&Value>,
    context: &HostConfigContext<'_>,
) -> IamResult<ResolvedHostConfig> {
    let invalid = |detail: String| invalid_config(format!("hosts.{detail}"));
    if let Some(options) = options
        && (options.is_null() || !typeof_object(options))
    {
        return Err(invalid("options must be an object".into()));
    }
    let patterns_value = member(options, "patterns");
    if let Some(patterns) = patterns_value
        && !matches!(patterns, Value::Array(items) if items.len() <= 16)
    {
        return Err(invalid(
            "patterns must be an array of at most 16 templates".into(),
        ));
    }
    let mut region_names: Vec<&String> = context
        .regions
        .map(|regions| regions.regions.keys().collect())
        .unwrap_or_default();
    region_names.sort_by_key(|name| std::cmp::Reverse(utf16_len(name)));
    let current = context.regions.map(|regions| regions.current.clone());
    let mut patterns = Vec::new();
    for raw in patterns_value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let Value::String(raw) = raw else {
            return Err(invalid("patterns must be strings".into()));
        };
        let source = js::trim(raw).to_lowercase();
        let count = |placeholder: &str| source.matches(placeholder).count();
        if count("{tenant}") != 1 {
            return Err(invalid(format!(
                "patterns entry {raw} must contain {{tenant}} exactly once"
            )));
        }
        if count("{region}") > 1 {
            return Err(invalid(format!(
                "patterns entry {raw} may contain {{region}} at most once"
            )));
        }
        let has_region = count("{region}") == 1;
        if has_region && context.regions.is_none() {
            return Err(invalid(format!(
                "patterns entry {raw} uses {{region}}, which needs the regions option"
            )));
        }
        let sample = source.replacen("{tenant}", "tenant", 1).replacen(
            "{region}",
            current.as_deref().unwrap_or("region"),
            1,
        );
        let mut pieces = sample.split(':');
        let hostname = pieces.next().unwrap_or("");
        let port = pieces.next();
        let rest = pieces.next();
        let valid = rest.is_none()
            && port.is_none_or(|port| {
                (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit())
            })
            && !sample.contains(['{', '}'])
            && !hostname.is_empty()
            && hostname.split('.').count() >= 2
            && hostname.split('.').all(hostname_label);
        if !valid {
            return Err(invalid(format!(
                "patterns entry {raw} is not a valid hostname template"
            )));
        }
        if context.base_url.scheme() != "https" && !loopback_host(hostname) {
            return Err(invalid(
                "patterns need an HTTPS baseURL outside localhost".into(),
            ));
        }
        if let Some(rp_id) = context.passkey_rp_id
            && !rp_id.is_empty()
            && hostname != rp_id
            && !hostname.ends_with(&format!(".{rp_id}"))
        {
            return Err(invalid(format!(
                "patterns entry {raw} must be under the passkey RP ID {rp_id}"
            )));
        }
        let parts = split_placeholders(&source);
        let mut expression = String::from("^");
        for part in &parts {
            match part.as_str() {
                "{tenant}" => expression.push_str(&format!("(?P<tenant>{ALIAS_SOURCE})")),
                "{region}" => {
                    let names: Vec<String> = region_names
                        .iter()
                        .map(|name| regex::escape(name))
                        .collect();
                    expression.push_str(&format!("(?P<region>{})", names.join("|")));
                }
                other => expression.push_str(&regex::escape(other)),
            }
        }
        expression.push('$');
        let regex = Regex::new(&expression).map_err(|_| internal_error())?;
        let last = parts.last().cloned().unwrap_or_default();
        let suffix = if last.starts_with('.') {
            strip_port(&last).to_owned()
        } else {
            String::new()
        };
        patterns.push(CompiledPattern {
            source,
            regex,
            has_region,
            suffix,
            current_region: current.clone(),
        });
    }
    let custom = member(options, "customHostnames");
    if custom.is_some() && !matches!(custom, Some(Value::Bool(_))) {
        return Err(invalid("customHostnames must be a boolean".into()));
    }
    let mut cname_target = None;
    if let Some(target) = member(options, "cnameTarget") {
        let normalized = match target {
            Value::String(text) => normalize_host(Some(text)),
            // `normalizeHost` returns undefined for falsy values and throws a TypeError reading `.trim` of others.
            other if !js::truthy(Some(other)) => None,
            _ => return Err(internal_error()),
        };
        match normalized {
            Some(host) if !host.contains(':') => cname_target = Some(host),
            _ => {
                return Err(invalid(
                    "cnameTarget must be a hostname such as custom.signin.example.com".into(),
                ));
            }
        }
    }
    let sign_in_path = match js::defined(member(options, "signInPath")) {
        None => "/".to_owned(),
        Some(Value::String(path)) if SIGN_IN_PATH.is_match(path) => path.clone(),
        Some(_) => {
            return Err(invalid("signInPath must be a path starting with /".into()));
        }
    };
    let forwarded = member(options, "forwardedHost");
    if forwarded.is_some() && !matches!(forwarded, Some(Value::Bool(_))) {
        return Err(invalid("forwardedHost must be a boolean".into()));
    }
    let custom_hostnames = custom == Some(&Value::Bool(true));
    Ok(ResolvedHostConfig {
        enabled: !patterns.is_empty() || custom_hostnames,
        patterns,
        custom_hostnames,
        cname_target,
        sign_in_path,
        forwarded_host: forwarded == Some(&Value::Bool(true)),
    })
}

/// `source.split(/(\{tenant\}|\{region\})/)`: the text between placeholders, with the placeholders kept.
fn split_placeholders(source: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut rest = source;
    loop {
        let next = ["{tenant}", "{region}"]
            .iter()
            .filter_map(|placeholder| rest.find(placeholder).map(|index| (index, *placeholder)))
            .min_by_key(|(index, _)| *index);
        match next {
            Some((index, placeholder)) => {
                parts.push(rest[..index].to_owned());
                parts.push(placeholder.to_owned());
                rest = &rest[index + placeholder.len()..];
            }
            None => {
                parts.push(rest.to_owned());
                return parts;
            }
        }
    }
}

/// `value.replace(/:\d+$/, '')`.
fn strip_port(value: &str) -> &str {
    if let Some(index) = value.rfind(':') {
        let digits = &value[index + 1..];
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            return &value[..index];
        }
    }
    value
}

// --- createHosts (kernel B): the request-time host and region service ----------------------------------------------

/// `createHosts(ctx)`: the host and region service of one deployment ([`crate::contracts::HostService`]).
pub fn create_hosts(ctx: &Arc<crate::context::ServerContext>) -> Arc<Hosts> {
    let config = &ctx.config;
    let own_hostnames = std::iter::once(config.origin())
        .chain(config.trusted_origins.iter().cloned())
        .map(|origin| {
            Url::parse(&origin)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
                .unwrap_or_default()
        })
        .collect();
    Arc::new(Hosts {
        ctx: Arc::downgrade(ctx),
        hosts: config.hosts.clone(),
        regions: config.regions.clone(),
        base_host: url_host(&config.base_url),
        scheme: format!("{}:", config.base_url.scheme()),
        own_hostnames,
    })
}

/// `url.host`: the hostname with a non-default port.
pub fn url_host(url: &Url) -> String {
    let host = match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        Some(host) => host.to_string(),
        None => String::new(),
    };
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

/// The host and region service (`HostService` of hosts.ts).
pub struct Hosts {
    ctx: std::sync::Weak<crate::context::ServerContext>,
    hosts: ResolvedHostConfig,
    regions: Option<ResolvedRegionConfig>,
    base_host: String,
    scheme: String,
    own_hostnames: indexmap::IndexSet<String>,
}

type HostStore = crate::context::Store;

impl Hosts {
    fn context(&self) -> IamResult<Arc<crate::context::ServerContext>> {
        self.ctx.upgrade().ok_or_else(internal_error)
    }

    async fn active(
        &self,
        tx: &HostStore,
        realm: Option<better_iam_core::Tenant>,
    ) -> IamResult<Option<better_iam_core::Tenant>> {
        let Some(realm) = realm else {
            return Ok(None);
        };
        if realm.status != better_iam_core::TenantStatus::Active {
            return Ok(None);
        }
        let ctx = self.context()?;
        let chain = ctx.ancestry(tx, &realm).await?;
        Ok(chain
            .iter()
            .all(|item| item.status == better_iam_core::TenantStatus::Active)
            .then_some(realm))
    }

    async fn tenant(tx: &HostStore, id: &str) -> IamResult<Option<better_iam_core::Tenant>> {
        match tx.get("tenants", id).await? {
            Some(record) => Ok(Some(crate::port::decode(record)?)),
            None => Ok(None),
        }
    }

    async fn region_of_tenant(
        &self,
        tx: &HostStore,
        tenant: &better_iam_core::Tenant,
    ) -> IamResult<Option<String>> {
        if self.regions.is_none() {
            return Ok(None);
        }
        let ctx = self.context()?;
        for item in ctx.ancestry(tx, tenant).await? {
            if let Some(region) = &item.region {
                return Ok(Some(region.clone()));
            }
        }
        Ok(None)
    }

    async fn sign_in_url_for(
        &self,
        realm: &better_iam_core::Tenant,
        tx: &HostStore,
    ) -> IamResult<Option<String>> {
        let home = self.region_of_tenant(tx, realm).await?;
        if self.hosts.custom_hostnames {
            let records = tx
                .find(
                    "tenantHostnames",
                    &better_iam_core::Filter::new().eq("tenantId", realm.id.clone()),
                    &better_iam_core::FindOptions::default(),
                )
                .await?;
            let primary = records.iter().find(|record| {
                js::truthy(record.get("primary"))
                    && record.get("status").and_then(Value::as_str) == Some("verified")
            });
            if let Some(primary) = primary {
                let hostname = js::js_string(primary.get("hostname"));
                return Ok(Some(format!(
                    "{}//{hostname}{}",
                    self.scheme, self.hosts.sign_in_path
                )));
            }
        }
        if let (Some(slug), Some(pattern)) = (&realm.slug, self.hosts.patterns.first()) {
            return Ok(Some(format!(
                "{}//{}{}",
                self.scheme,
                pattern.fill(slug, home.as_deref()),
                self.hosts.sign_in_path
            )));
        }
        let base = home.as_ref().and_then(|home| {
            self.regions
                .as_ref()
                .and_then(|regions| regions.regions.get(home))
                .and_then(|region| region.base_url.clone())
        });
        Ok(base.map(|base| {
            if self.hosts.sign_in_path == "/" {
                base
            } else {
                format!("{base}{}", self.hosts.sign_in_path)
            }
        }))
    }

    async fn served_here(
        &self,
        tx: &HostStore,
        tenant: &better_iam_core::Tenant,
        host_region: Option<&str>,
    ) -> IamResult<()> {
        let Some(regions) = &self.regions else {
            return Ok(());
        };
        let home = self
            .region_of_tenant(tx, tenant)
            .await?
            .unwrap_or_else(|| regions.current.clone());
        if home != regions.current || host_region.is_some_and(|region| region != home) {
            let location = self.sign_in_url_for(tenant, tx).await?;
            return Err(WrongRegionError::new(&home, location, Some(&tenant.name)).into());
        }
        Ok(())
    }

    async fn alias_elsewhere(&self, alias: &str) -> Option<WrongRegionError> {
        let regions = self.regions.as_ref()?;
        let locate = regions.locate.as_ref()?;
        let region = locate(alias.to_owned()).await.ok().flatten()?;
        if region == regions.current || !regions.regions.contains_key(&region) {
            return None;
        }
        let base = regions
            .regions
            .get(&region)
            .and_then(|settings| settings.base_url.clone());
        let location = match (self.hosts.patterns.first(), base) {
            (Some(pattern), _) => Some(format!(
                "{}//{}{}",
                self.scheme,
                pattern.fill(alias, Some(&region)),
                self.hosts.sign_in_path
            )),
            (None, Some(base)) => Some(if self.hosts.sign_in_path == "/" {
                base
            } else {
                format!("{base}{}", self.hosts.sign_in_path)
            }),
            (None, None) => None,
        };
        Some(WrongRegionError::new(&region, location, None))
    }

    async fn resolve_in(&self, raw_host: &str, tx: &HostStore) -> IamResult<Option<HostMatch>> {
        if !self.hosts.enabled {
            return Ok(None);
        }
        let Some(host) = normalize_host(Some(raw_host)) else {
            return Ok(None);
        };
        if host == self.base_host {
            return Ok(None);
        }
        for pattern in &self.hosts.patterns {
            let Some(captures) = pattern.regex.captures(&host) else {
                continue;
            };
            let Some(alias) = captures.name("tenant").map(|m| m.as_str().to_owned()) else {
                continue;
            };
            let record = tx.get("tenantAliases", &alias).await?;
            let owner = match &record {
                Some(record) => {
                    Self::tenant(
                        tx,
                        record.get("tenantId").and_then(Value::as_str).unwrap_or(""),
                    )
                    .await?
                }
                None => None,
            };
            let Some(realm) = self.active(tx, owner).await? else {
                if record.is_none()
                    && let Some(elsewhere) = self.alias_elsewhere(&alias).await
                {
                    return Err(elsewhere.into());
                }
                return Err(IamError::with_status(
                    "NOT_FOUND",
                    "No organization uses this address",
                    404,
                ));
            };
            return Ok(Some(HostMatch {
                tenant_id: realm.id.clone(),
                name: realm.name.clone(),
                slug: Some(alias),
                hostname: host.clone(),
                via: "pattern".into(),
                host_region: captures
                    .name("region")
                    .map(|m| m.as_str().to_owned())
                    .filter(|region| !region.is_empty()),
            }));
        }
        if self.hosts.custom_hostnames {
            let hostname = strip_port(&host);
            if let Some(owner) = tx.get("hostnameOwners", hostname).await? {
                let tenant_id = owner.get("tenantId").and_then(Value::as_str).unwrap_or("");
                let owner = Self::tenant(tx, tenant_id).await?;
                let Some(realm) = self.active(tx, owner).await? else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "No organization uses this address",
                        404,
                    ));
                };
                return Ok(Some(HostMatch {
                    tenant_id: realm.id.clone(),
                    name: realm.name.clone(),
                    slug: realm.slug.clone(),
                    hostname: host.clone(),
                    via: "custom".into(),
                    host_region: None,
                }));
            }
        }
        Ok(None)
    }

    fn valid_region(&self, value: Option<&Value>) -> IamResult<String> {
        let Some(regions) = &self.regions else {
            return Err(js::invalid_input(
                "This deployment has no regions configured",
            ));
        };
        match value.and_then(Value::as_str) {
            Some(region) if regions.regions.contains_key(region) => Ok(region.to_owned()),
            _ => Err(js::invalid_input(format!(
                "Region must be one of {}",
                regions
                    .regions
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// `originHost(origin)`: the host of an origin of this deployment's scheme, spelled exactly as an origin.
    fn origin_host(&self, origin: &str) -> Option<String> {
        let url = Url::parse(origin).ok()?;
        let scheme = format!("{}:", url.scheme());
        (scheme == self.scheme && url_origin(&url) == origin).then(|| url_host(&url))
    }

    /// `candidate(host)`: whether an address could belong to an organization, decided without storage.
    fn candidate(&self, host: Option<&str>) -> bool {
        let Some(normalized) = normalize_host(host) else {
            return false;
        };
        normalized != self.base_host
            && (self.hosts.custom_hostnames
                || self
                    .hosts
                    .patterns
                    .iter()
                    .any(|pattern| pattern.regex.is_match(&normalized)))
    }
}

#[async_trait::async_trait]
impl crate::contracts::HostService for Hosts {
    fn enabled(&self) -> bool {
        self.hosts.enabled
    }

    async fn resolve(&self, host: &str, tx: Option<&HostStore>) -> IamResult<Option<HostMatch>> {
        match tx {
            Some(tx) => self.resolve_in(host, tx).await,
            None => {
                let store = self.context()?.store.clone();
                self.resolve_in(host, &store).await
            }
        }
    }

    async fn request_tenant(
        &self,
        request: &crate::options::HttpRequest,
    ) -> IamResult<Option<HostMatch>> {
        if !self.hosts.enabled {
            return Ok(None);
        }
        // `request.headers.get(name)`: every value of the name, joined with ", " (lossy for non-UTF-8 bytes).
        let header = |name: &str| {
            let values: Vec<String> = request
                .headers()
                .get_all(name)
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                .collect();
            (!values.is_empty()).then(|| values.join(", "))
        };
        let forwarded = if self.hosts.forwarded_host {
            header("x-forwarded-host").map(|value| value.split(',').next().unwrap_or("").to_owned())
        } else {
            None
        };
        let address = match forwarded
            .map(|value| js::trim(&value).to_owned())
            .filter(|value| !value.is_empty())
        {
            Some(value) => Some(value),
            None => request
                .uri()
                .authority()
                .map(|authority| authority.as_str().to_lowercase())
                .or_else(|| header("host")),
        };
        let from_origin = header("origin").and_then(|origin| self.origin_host(&origin));
        // Most requests arrive on the deployment's own address: no storage read for those.
        if !self.candidate(address.as_deref()) && !self.candidate(from_origin.as_deref()) {
            return Ok(None);
        }
        let ctx = self.context()?;
        use better_iam_core::IamStoreExt;
        ctx.store
            .transaction(|tx| async move {
                let by_host = match &address {
                    Some(address) => self.resolve_in(address, &tx).await?,
                    None => None,
                };
                let by_origin = match &from_origin {
                    Some(origin) if Some(origin) != address.as_ref() => {
                        self.resolve_in(origin, &tx).await?
                    }
                    _ => None,
                };
                if let (Some(host), Some(origin)) = (&by_host, &by_origin)
                    && host.tenant_id != origin.tenant_id
                {
                    return Err(IamError::with_status(
                        "HOST_MISMATCH",
                        "This page and this address belong to different organizations",
                        403,
                    ));
                }
                let found = by_host.or(by_origin);
                if let Some(found) = &found {
                    let tenant = self.context()?.tenant(&tx, &found.tenant_id).await?;
                    self.served_here(&tx, &tenant, found.host_region.as_deref())
                        .await?;
                }
                Ok(found)
            })
            .await
    }

    async fn trusts_origin(&self, origin: &str) -> bool {
        if !self.hosts.enabled {
            return false;
        }
        let Some(host) = self.origin_host(origin) else {
            return false;
        };
        matches!(
            crate::contracts::HostService::resolve(self, &host, None).await,
            Ok(Some(_))
        )
    }

    async fn sign_in_url(&self, tenant_id: &str) -> IamResult<Option<String>> {
        let store = self.context()?.store.clone();
        match Self::tenant(&store, tenant_id).await? {
            Some(realm) => self.sign_in_url_for(&realm, &store).await,
            None => Ok(None),
        }
    }

    async fn sign_in_url_of(
        &self,
        tenant: &better_iam_core::Tenant,
        tx: Option<&HostStore>,
    ) -> IamResult<Option<String>> {
        match tx {
            Some(tx) => self.sign_in_url_for(tenant, tx).await,
            None => {
                let store = self.context()?.store.clone();
                self.sign_in_url_for(tenant, &store).await
            }
        }
    }

    async fn region_of(
        &self,
        tx: &HostStore,
        tenant: &better_iam_core::Tenant,
    ) -> IamResult<Option<String>> {
        self.region_of_tenant(tx, tenant).await
    }

    async fn assert_served_here(
        &self,
        tx: &HostStore,
        tenant: &better_iam_core::Tenant,
        host_region: Option<&str>,
    ) -> IamResult<()> {
        self.served_here(tx, tenant, host_region).await
    }

    async fn assert_tenant_served_here(&self, tenant_id: &str) -> IamResult<()> {
        if self.regions.is_none() {
            return Ok(());
        }
        let ctx = self.context()?;
        use better_iam_core::IamStoreExt;
        ctx.store
            .transaction(|tx| async move {
                if let Some(realm) = Self::tenant(&tx, tenant_id).await? {
                    self.served_here(&tx, &realm, None).await?;
                }
                Ok(())
            })
            .await
    }

    async fn remote_alias(&self, alias: &str) -> Option<WrongRegionError> {
        self.alias_elsewhere(alias).await
    }

    async fn region_for_new(
        &self,
        tx: &HostStore,
        parent: &better_iam_core::Tenant,
        requested: Option<&Value>,
    ) -> IamResult<Option<String>> {
        if requested.is_none_or(Value::is_null) {
            // The first organizations under the (region-less) root are homed where they are created.
            let Some(regions) = &self.regions else {
                return Ok(None);
            };
            if self.region_of_tenant(tx, parent).await?.is_some() {
                return Ok(None);
            }
            return Ok(Some(regions.current.clone()));
        }
        let region = self.valid_region(requested)?;
        if let Some(regions) = &self.regions
            && regions.locate.is_some()
            && region != regions.current
        {
            return Err(js::invalid_input(
                "Regions keep separate databases here: create the organization on the deployment of its region",
            ));
        }
        Ok(Some(region))
    }

    fn region(&self, value: Option<&Value>) -> IamResult<String> {
        self.valid_region(value)
    }

    fn assert_claimable(&self, hostname: &str) -> IamResult<()> {
        let refuse = || {
            Err(IamError::new(
                "HOSTNAME_NOT_ALLOWED",
                "This hostname belongs to the deployment itself and cannot be claimed",
            ))
        };
        if self.own_hostnames.contains(hostname) {
            return refuse();
        }
        for pattern in &self.hosts.patterns {
            if pattern.regex.is_match(hostname) {
                return refuse();
            }
            let suffix = &pattern.suffix;
            if !suffix.is_empty()
                && (hostname.ends_with(suffix.as_str()) || hostname == &suffix[1..])
            {
                return refuse();
            }
        }
        Ok(())
    }

    async fn allowed(&self, hostname: &str) -> bool {
        let Some(host) = normalize_host(Some(hostname)) else {
            return false;
        };
        if self.own_hostnames.contains(strip_port(&host)) {
            return true;
        }
        matches!(
            crate::contracts::HostService::resolve(self, &host, None).await,
            Ok(Some(_))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base(url: &str) -> Url {
        Url::parse(url).unwrap()
    }

    #[test]
    fn hosts_normalize() {
        assert_eq!(
            normalize_host(Some(" Example.COM. ")).unwrap(),
            "example.com"
        );
        assert_eq!(normalize_host(Some("a.b.:8080")).unwrap(), "a.b:8080");
        assert_eq!(normalize_host(Some("[::1]:3000")).unwrap(), "[::1]:3000");
        assert!(normalize_host(Some("a b")).is_none());
        assert!(normalize_host(Some("")).is_none());
        assert!(normalize_host(Some("a:123456")).is_none());
    }

    #[test]
    fn region_config() {
        assert!(resolve_region_config(None, None).unwrap().is_none());
        let resolved = resolve_region_config(
            Some(&json!({
                "current": "us-east-1",
                "regions": {
                    "us-east-1": { "baseURL": "https://us.example.com/iam/", "label": " US " },
                    "eu-west-1": null
                }
            })),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            resolved.regions["us-east-1"].base_url.as_deref(),
            Some("https://us.example.com/iam")
        );
        assert_eq!(resolved.regions["us-east-1"].label.as_deref(), Some("US"));
        let message = |value: Value| {
            resolve_region_config(Some(&value), None)
                .unwrap_err()
                .message
        };
        assert_eq!(message(json!("x")), "regions.options must be an object");
        assert_eq!(
            message(json!({ "current": "US" })),
            "regions.current must be a region name such as us-east-1"
        );
        assert_eq!(
            message(json!({ "current": "us", "regions": {} })),
            "regions.regions must list 1 to 64 regions"
        );
        assert_eq!(
            message(json!({ "current": "us", "regions": { "eu": {} } })),
            "regions.current must be one of regions"
        );
        assert_eq!(
            message(
                json!({ "current": "us", "regions": { "us": { "baseURL": "http://x.example.com" } } })
            ),
            "regions.regions.us.baseURL must use HTTPS outside localhost"
        );
        assert_eq!(
            message(json!({ "current": "us", "regions": { "us": { "baseURL": "nope" } } })),
            "regions.regions.us.baseURL must be an absolute URL"
        );
    }

    #[test]
    fn host_config() {
        let url = base("https://iam.example.com");
        let regions = resolve_region_config(
            Some(
                &json!({ "current": "eu-west-1", "regions": { "eu-west-1": {}, "us-east-1": {} } }),
            ),
            None,
        )
        .unwrap()
        .unwrap();
        let context = HostConfigContext {
            base_url: &url,
            regions: Some(&regions),
            passkey_rp_id: Some("example.com"),
        };
        let config = resolve_host_config(
            Some(&json!({ "patterns": ["{tenant}.signin.{region}.example.com"], "cnameTarget": "Custom.Example.com." })),
            &context,
        )
        .unwrap();
        assert!(config.enabled);
        assert_eq!(config.cname_target.as_deref(), Some("custom.example.com"));
        let pattern = &config.patterns[0];
        assert_eq!(pattern.suffix, ".example.com");
        let captures = pattern
            .regex
            .captures("acme.signin.us-east-1.example.com")
            .unwrap();
        assert_eq!(&captures["tenant"], "acme");
        assert_eq!(&captures["region"], "us-east-1");
        assert_eq!(
            pattern.fill("acme", None),
            "acme.signin.eu-west-1.example.com"
        );
        let message = |value: Value| {
            resolve_host_config(Some(&value), &context)
                .unwrap_err()
                .message
        };
        assert_eq!(
            message(json!({ "patterns": ["signin.example.com"] })),
            "hosts.patterns entry signin.example.com must contain {tenant} exactly once"
        );
        assert_eq!(
            message(json!({ "patterns": ["{tenant}.other.org"] })),
            "hosts.patterns entry {tenant}.other.org must be under the passkey RP ID example.com"
        );
        assert_eq!(
            message(json!({ "patterns": ["{tenant}"] })),
            "hosts.patterns entry {tenant} is not a valid hostname template"
        );
        assert_eq!(
            message(json!({ "signInPath": "x" })),
            "hosts.signInPath must be a path starting with /"
        );
        assert_eq!(
            message(json!({ "customHostnames": "yes" })),
            "hosts.customHostnames must be a boolean"
        );
        let local = base("http://localhost:3000");
        let insecure = HostConfigContext {
            base_url: &local,
            regions: None,
            passkey_rp_id: None,
        };
        assert_eq!(
            resolve_host_config(
                Some(&json!({ "patterns": ["{tenant}.example.com"] })),
                &insecure
            )
            .unwrap_err()
            .message,
            "hosts.patterns need an HTTPS baseURL outside localhost"
        );
        let dev = resolve_host_config(
            Some(&json!({ "patterns": ["{tenant}.localhost:3000"] })),
            &insecure,
        )
        .unwrap();
        assert_eq!(dev.patterns[0].suffix, ".localhost");
        assert!(!resolve_host_config(None, &insecure).unwrap().enabled);
    }
}
