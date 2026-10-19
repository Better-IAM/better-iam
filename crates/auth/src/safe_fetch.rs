//! Guarded outbound HTTP for URLs that tenants control (OIDC discovery documents and JWKS, webhook endpoints, SCIM
//! targets, Shared Signals receivers, AI provider base URLs) (`safe-fetch.ts`).
//!
//! It refuses anything that could turn the server into a proxy into its own network (SSRF): non-public resolved
//! addresses (checked at connect time, so DNS rebinding cannot swap in a private address after validation),
//! redirects, plain http, non-443 https ports unless allowed, and credentials in the URL. Requests are HTTP/1.1 over
//! TCP, with TLS from rustls and the Mozilla root store (webpki-roots); every connection is closed after its
//! response, as Node's `agent: false` requests are.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, LazyLock};

use better_iam_core::{ip_counter_key, ip_matches, js};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use url::{Host, Url};

/// Which rule stopped a guarded fetch (`SafeFetchFailureReason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SafeFetchFailureReason {
    Url,
    Address,
    Timeout,
    Status,
    Size,
    ContentType,
    Redirect,
    Json,
    Network,
}

impl SafeFetchFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::Address => "address",
            Self::Timeout => "timeout",
            Self::Status => "status",
            Self::Size => "size",
            Self::ContentType => "content-type",
            Self::Redirect => "redirect",
            Self::Json => "json",
            Self::Network => "network",
        }
    }
}

/// A refused or failed guarded fetch; `reason` says which rule stopped it (`SafeFetchError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SafeFetchError {
    pub reason: SafeFetchFailureReason,
    pub message: String,
}

impl SafeFetchError {
    /// `new SafeFetchError(reason)`: the message is `Fetch refused: {reason}`.
    pub fn new(reason: SafeFetchFailureReason) -> Self {
        Self {
            reason,
            message: format!("Fetch refused: {}", reason.as_str()),
        }
    }

    pub fn with_message(reason: SafeFetchFailureReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }

    /// The error's name (`SafeFetchError`).
    pub fn name(&self) -> &'static str {
        "SafeFetchError"
    }
}

/// `SafeFetchOptions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SafeFetchOptions {
    /// Deadline for the whole request, in milliseconds.
    pub timeout_ms: u64,
    /// Largest accepted response body, in bytes.
    pub max_bytes: u64,
    /// Lets requests reach private and reserved addresses. Development and tests only.
    pub allow_private_networks: bool,
    /// Allows `http://` and any port on loopback hosts (localhost, 127.0.0.1, [::1]). Development and tests only.
    pub allow_insecure_localhost: bool,
}

/// The address rules of a guarded request (`SafeFetchAddressOptions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SafeFetchAddressOptions {
    pub allow_private_networks: bool,
    pub allow_insecure_localhost: bool,
    /// Also allows https on ports other than 443 (the address rules still apply).
    pub any_port: bool,
}

impl From<&SafeFetchOptions> for SafeFetchAddressOptions {
    fn from(options: &SafeFetchOptions) -> Self {
        Self {
            allow_private_networks: options.allow_private_networks,
            allow_insecure_localhost: options.allow_insecure_localhost,
            any_port: false,
        }
    }
}

/// Networks that are never reachable through a guarded fetch.
const NON_PUBLIC_NETWORKS: [&str; 29] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "::/96",
    "::ffff:0:0:0/96",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
];
const LOOPBACK_HOSTS: [&str; 4] = ["localhost", "127.0.0.1", "[::1]", "::1"];

/// `isPublicAddress(address)`: true for a globally routable unicast address; false for private, reserved and
/// malformed values.
pub fn is_public_address(address: &str) -> bool {
    if ip_counter_key(address).is_none() {
        return false;
    }
    let trimmed = js::trim(address);
    !NON_PUBLIC_NETWORKS
        .iter()
        .any(|network| ip_matches(trimmed, network))
}

fn is_loopback_address(address: &str) -> bool {
    ip_matches(address, "127.0.0.0/8") || ip_matches(address, "::1/128")
}

/// `url.hostname` as WHATWG serializes it (IPv6 in brackets).
fn hostname(url: &Url) -> String {
    match url.host() {
        Some(Host::Ipv6(address)) => format!("[{address}]"),
        Some(Host::Ipv4(address)) => address.to_string(),
        Some(Host::Domain(domain)) => domain.to_owned(),
        None => String::new(),
    }
}

fn is_loopback_host(url: &Url) -> bool {
    LOOPBACK_HOSTS.contains(&hostname(url).as_str())
}

/// `checkFetchUrl(value, options)`: https on port 443 (any port with `any_port`) without credentials or a fragment
/// (loopback hosts may use http and any port with `allow_insecure_localhost`), and, for an IP-literal host, a public
/// address. Returns the parsed URL.
pub fn check_fetch_url(
    value: &str,
    options: &SafeFetchAddressOptions,
) -> Result<Url, SafeFetchError> {
    let url = Url::parse(value).map_err(|_| {
        SafeFetchError::with_message(SafeFetchFailureReason::Url, "Not an absolute URL")
    })?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some_and(|fragment| !fragment.is_empty())
        || value.contains('#')
    {
        return Err(SafeFetchError::with_message(
            SafeFetchFailureReason::Url,
            "Credentials and fragments are not allowed",
        ));
    }
    let loopback = is_loopback_host(&url) && options.allow_insecure_localhost;
    if !loopback && (url.scheme() != "https" || (url.port().is_some() && !options.any_port)) {
        return Err(SafeFetchError::with_message(
            SafeFetchFailureReason::Url,
            if options.any_port {
                "Only https is allowed"
            } else {
                "Only https on port 443 is allowed"
            },
        ));
    }
    if loopback && url.scheme() != "https" && url.scheme() != "http" {
        return Err(SafeFetchError::with_message(
            SafeFetchFailureReason::Url,
            "Only http and https are allowed",
        ));
    }
    let literal = match url.host() {
        Some(Host::Ipv4(address)) => Some(address.to_string()),
        Some(Host::Ipv6(address)) => Some(address.to_string()),
        _ => None,
    };
    if let Some(address) = literal
        && !loopback
        && !options.allow_private_networks
        && !is_public_address(&address)
    {
        return Err(SafeFetchError::with_message(
            SafeFetchFailureReason::Address,
            "The address is not public",
        ));
    }
    Ok(url)
}

/// Why a request could not complete: a guarded-fetch refusal or a network failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchCause {
    #[error(transparent)]
    Refused(SafeFetchError),
    #[error("{0}")]
    Network(String),
}

/// A failed `fetch` (`TypeError('fetch failed', { cause })` in TypeScript), or a failed body read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct FetchError {
    pub message: String,
    pub cause: Option<FetchCause>,
}

impl FetchError {
    fn failed(cause: FetchCause) -> Self {
        Self {
            message: "fetch failed".to_owned(),
            cause: Some(cause),
        }
    }

    fn refused(error: SafeFetchError) -> Self {
        Self::failed(FetchCause::Refused(error))
    }

    fn network(message: impl Into<String>) -> Self {
        Self::failed(FetchCause::Network(message.into()))
    }

    /// The guarded-fetch refusal behind this failure, if one was.
    pub fn refusal(&self) -> Option<&SafeFetchError> {
        match &self.cause {
            Some(FetchCause::Refused(error)) => Some(error),
            _ => None,
        }
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

static TLS: LazyLock<tokio_rustls::TlsConnector> = LazyLock::new(|| {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the ring provider supports the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
});

/// The address rules applied when connecting; None for an unguarded request.
#[derive(Clone, Copy)]
struct Guard {
    options: SafeFetchAddressOptions,
    loopback_host: bool,
}

enum ConnectError {
    Refused(SafeFetchError),
    Network(String),
}

/// How long a connection attempt runs before the next address is tried alongside it (Node's
/// `autoSelectFamilyAttemptTimeout`).
const ATTEMPT_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Connects to the first address that answers, starting the next attempt whenever the current ones have run for
/// [`ATTEMPT_DELAY`] (as Node's `autoSelectFamily` does), so an address that never answers (an IPv6 `localhost`
/// nothing listens on) does not hold up the others.
async fn connect_any(addresses: Vec<SocketAddr>) -> Result<TcpStream, String> {
    use futures::StreamExt;
    use futures::stream::FuturesUnordered;
    let mut remaining = addresses.into_iter();
    let mut attempts = FuturesUnordered::new();
    let mut last = String::from("connect failed");
    let attempt = |address: SocketAddr| async move {
        TcpStream::connect(address)
            .await
            .map_err(|error| format!("connect {} {address}", error.kind()))
    };
    match remaining.next() {
        Some(address) => attempts.push(attempt(address)),
        None => return Err(last),
    }
    loop {
        let more = remaining.len() > 0;
        tokio::select! {
            outcome = attempts.next() => match outcome {
                Some(Ok(stream)) => return Ok(stream),
                Some(Err(error)) => {
                    last = error;
                    if let Some(address) = remaining.next() {
                        attempts.push(attempt(address));
                    } else if attempts.is_empty() {
                        return Err(last);
                    }
                }
                None => match remaining.next() {
                    Some(address) => attempts.push(attempt(address)),
                    None => return Err(last),
                },
            },
            () = tokio::time::sleep(ATTEMPT_DELAY), if more => {
                if let Some(address) = remaining.next() {
                    attempts.push(attempt(address));
                }
            }
        }
    }
}

/// Resolves and connects, refusing a host when any resolved address is not public (unless the options allow it).
async fn connect(url: &Url, guard: Option<Guard>) -> Result<Box<dyn Io>, ConnectError> {
    let port = url
        .port_or_known_default()
        .ok_or_else(|| ConnectError::Network("Unsupported protocol".to_owned()))?;
    let addresses: Vec<SocketAddr> = match url.host() {
        Some(Host::Ipv4(address)) => vec![SocketAddr::new(IpAddr::V4(address), port)],
        Some(Host::Ipv6(address)) => vec![SocketAddr::new(IpAddr::V6(address), port)],
        Some(Host::Domain(domain)) => {
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((domain, port))
                .await
                .map_err(|error| {
                    ConnectError::Network(format!("getaddrinfo ENOTFOUND {domain}: {error}"))
                })?
                .collect();
            if let Some(guard) = guard {
                let allowed = |address: &SocketAddr| {
                    let text = address.ip().to_string();
                    guard.options.allow_private_networks
                        || is_public_address(&text)
                        || (guard.loopback_host
                            && guard.options.allow_insecure_localhost
                            && is_loopback_address(&text))
                };
                if resolved.is_empty() || !resolved.iter().all(allowed) {
                    return Err(ConnectError::Refused(SafeFetchError::with_message(
                        SafeFetchFailureReason::Address,
                        "The host resolves to a non-public address",
                    )));
                }
            }
            resolved
        }
        None => return Err(ConnectError::Network("Invalid URL".to_owned())),
    };
    let stream = connect_any(addresses)
        .await
        .map_err(ConnectError::Network)?;
    let _ = stream.set_nodelay(true);
    if url.scheme() == "https" {
        let name = match url.host() {
            Some(Host::Ipv4(address)) => {
                rustls::pki_types::ServerName::IpAddress(IpAddr::V4(address).into())
            }
            Some(Host::Ipv6(address)) => {
                rustls::pki_types::ServerName::IpAddress(IpAddr::V6(address).into())
            }
            Some(Host::Domain(domain)) => {
                rustls::pki_types::ServerName::try_from(domain.to_owned())
                    .map_err(|error| ConnectError::Network(error.to_string()))?
            }
            None => return Err(ConnectError::Network("Invalid URL".to_owned())),
        };
        let tls = TLS
            .connect(name, stream)
            .await
            .map_err(|error| ConnectError::Network(error.to_string()))?;
        return Ok(Box::new(tls));
    }
    Ok(Box::new(stream))
}

/// The `Host` header Node sends: the host, plus the port when it is not the scheme's default.
fn host_header(url: &Url) -> String {
    let host = hostname(url);
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

/// The request target: path and query.
fn target(url: &Url) -> String {
    let mut path = url.path().to_owned();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

async fn send(
    url: &Url,
    method: &str,
    headers: &[(String, String)],
    body: Option<Vec<u8>>,
    guard: Option<Guard>,
) -> Result<hyper::Response<Incoming>, ConnectError> {
    let io = connect(url, guard).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(io))
            .await
            .map_err(|error| ConnectError::Network(error.to_string()))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(target(url))
        .header("host", host_header(url));
    for (name, value) in headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder = builder.header("connection", "close");
    let request = builder
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .map_err(|error| ConnectError::Network(error.to_string()))?;
    sender
        .send_request(request)
        .await
        .map_err(|error| ConnectError::Network(error.to_string()))
}

fn declared_length(response: &hyper::Response<Incoming>) -> f64 {
    response
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .map_or(f64::NAN, js::string_to_number)
}

/// `fetchJsonSafely(url, options)`: GETs a JSON document under the SSRF rules. Any status other than 200 fails
/// (`redirect` for 3xx, else `status`), as do a content type without "json", a body over `max_bytes`, the deadline,
/// and unparseable JSON.
pub async fn fetch_json_safely(
    value: &str,
    options: &SafeFetchOptions,
) -> Result<Value, SafeFetchError> {
    let address = SafeFetchAddressOptions::from(options);
    let url = check_fetch_url(value, &address)?;
    let guard = Guard {
        options: address,
        loopback_host: is_loopback_host(&url),
    };
    let max_bytes = options.max_bytes;
    let work = async move {
        let headers = vec![
            ("accept".to_owned(), "application/json".to_owned()),
            ("user-agent".to_owned(), "better-iam".to_owned()),
        ];
        let response = send(&url, "GET", &headers, None, Some(guard))
            .await
            .map_err(|error| match error {
                ConnectError::Refused(error) => error,
                ConnectError::Network(_) => SafeFetchError::new(SafeFetchFailureReason::Network),
            })?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err(SafeFetchError::new(SafeFetchFailureReason::Redirect));
        }
        if status != 200 {
            return Err(SafeFetchError::with_message(
                SafeFetchFailureReason::Status,
                format!("Unexpected status {status}"),
            ));
        }
        let content_type = response
            .headers()
            .get_all("content-type")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ")
            .to_lowercase();
        if !content_type.contains("json") {
            return Err(SafeFetchError::new(SafeFetchFailureReason::ContentType));
        }
        let declared = declared_length(&response);
        if declared.is_finite() && declared > max_bytes as f64 {
            return Err(SafeFetchError::new(SafeFetchFailureReason::Size));
        }
        let mut body = response.into_body();
        let mut chunks: Vec<u8> = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| SafeFetchError::new(SafeFetchFailureReason::Network))?;
            if let Ok(data) = frame.into_data() {
                if (chunks.len() + data.len()) as u64 > max_bytes {
                    return Err(SafeFetchError::new(SafeFetchFailureReason::Size));
                }
                chunks.extend_from_slice(&data);
            }
        }
        js::parse(&String::from_utf8_lossy(&chunks))
            .map_err(|_| SafeFetchError::new(SafeFetchFailureReason::Json))
    };
    match tokio::time::timeout(std::time::Duration::from_millis(options.timeout_ms), work).await {
        Ok(result) => result,
        Err(_) => Err(SafeFetchError::new(SafeFetchFailureReason::Timeout)),
    }
}

/// What `createGuardedFetch` enforces besides the address rules (`GuardedFetchOptions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuardedFetchOptions {
    pub allow_private_networks: bool,
    pub allow_insecure_localhost: bool,
    pub any_port: bool,
    /// Largest response body a caller may read, in bytes; reading past it fails (default: unlimited).
    pub max_bytes: Option<u64>,
}

/// `RequestInit.redirect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedirectMode {
    /// Redirects are never followed: a 3xx is returned as is.
    #[default]
    Follow,
    /// A 3xx rejects.
    Error,
    /// A 3xx is returned as is.
    Manual,
}

/// A request body: text gets `content-type: text/plain;charset=UTF-8` unless the request names one, as a `Request`
/// built from a string does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchBody {
    Text(String),
    Bytes(Vec<u8>),
}

/// A `fetch` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<FetchBody>,
    pub redirect: RedirectMode,
}

impl FetchRequest {
    /// A GET of `url`.
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: "GET".to_owned(),
            headers: Vec::new(),
            body: None,
            redirect: RedirectMode::Follow,
        }
    }

    /// A request with a method and body.
    pub fn new(url: impl Into<String>, method: impl Into<String>, body: Option<FetchBody>) -> Self {
        Self {
            url: url.into(),
            method: method.into(),
            headers: Vec::new(),
            body,
            redirect: RedirectMode::Follow,
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn redirect(mut self, mode: RedirectMode) -> Self {
        self.redirect = mode;
        self
    }
}

/// A streamed response body, bounded by `max_bytes` when set. Dropping it (or [`ResponseBody::cancel`]) closes the
/// connection.
pub struct ResponseBody {
    incoming: Option<Incoming>,
    limit: Option<u64>,
    size: u64,
    failed: Option<FetchError>,
}

impl ResponseBody {
    fn empty() -> Self {
        Self {
            incoming: None,
            limit: None,
            size: 0,
            failed: None,
        }
    }

    /// The next chunk; None at the end. Past the bound it fails with a `size` refusal.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, FetchError> {
        if let Some(error) = &self.failed {
            return Err(error.clone());
        }
        loop {
            let Some(incoming) = self.incoming.as_mut() else {
                return Ok(None);
            };
            match incoming.frame().await {
                None => {
                    self.incoming = None;
                    return Ok(None);
                }
                Some(Err(_)) => {
                    self.incoming = None;
                    let error = FetchError {
                        message: "terminated".to_owned(),
                        cause: None,
                    };
                    self.failed = Some(error.clone());
                    return Err(error);
                }
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    self.size += data.len() as u64;
                    if self.limit.is_some_and(|limit| self.size > limit) {
                        self.incoming = None;
                        let error = FetchError {
                            message: "Fetch refused: size".to_owned(),
                            cause: Some(FetchCause::Refused(SafeFetchError::new(
                                SafeFetchFailureReason::Size,
                            ))),
                        };
                        self.failed = Some(error.clone());
                        return Err(error);
                    }
                    return Ok(Some(data));
                }
            }
        }
    }

    /// The whole body (`arrayBuffer()`).
    pub async fn bytes(&mut self) -> Result<Vec<u8>, FetchError> {
        let mut out = Vec::new();
        while let Some(chunk) = self.chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// The whole body as UTF-8 text (`text()`).
    pub async fn text(&mut self) -> Result<String, FetchError> {
        Ok(String::from_utf8_lossy(&self.bytes().await?).into_owned())
    }

    /// The whole body parsed as JSON (`json()`).
    pub async fn json(&mut self) -> Result<Value, FetchError> {
        let text = self.text().await?;
        js::parse(&text).map_err(|error| FetchError {
            message: error.to_string(),
            cause: None,
        })
    }

    /// `body.cancel()`: closes the connection; later reads end at once.
    pub fn cancel(&mut self) {
        self.incoming = None;
    }
}

/// A `fetch` response.
pub struct FetchResponse {
    pub status: u16,
    pub status_text: String,
    /// Header names in lower case, repeated headers as separate entries.
    pub headers: Vec<(String, String)>,
    pub url: String,
    pub body: ResponseBody,
}

impl FetchResponse {
    /// `response.ok`.
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// `response.headers.get(name)`: repeated values joined with ", ".
    pub fn header(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }
}

/// A `fetch` under the SSRF rules (`createGuardedFetch`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuardedFetch {
    options: GuardedFetchOptions,
}

/// `createGuardedFetch(options)`: the URL rules of [`check_fetch_url`] and a connect-time DNS check that refuses
/// hosts resolving to non-public addresses. Redirects are never followed: with [`RedirectMode::Error`] a 3xx
/// fails, otherwise it is returned as is. The response body streams, bounded by `max_bytes` when set.
pub fn create_guarded_fetch(options: GuardedFetchOptions) -> GuardedFetch {
    GuardedFetch { options }
}

const NULL_BODY_STATUSES: [u16; 4] = [101, 204, 205, 304];

impl GuardedFetch {
    pub fn options(&self) -> &GuardedFetchOptions {
        &self.options
    }

    /// Sends one request.
    pub async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let address = SafeFetchAddressOptions {
            allow_private_networks: self.options.allow_private_networks,
            allow_insecure_localhost: self.options.allow_insecure_localhost,
            any_port: self.options.any_port,
        };
        if Url::parse(&request.url).is_err() {
            return Err(FetchError {
                message: format!("Failed to parse URL from {}", request.url),
                cause: None,
            });
        }
        let method = request.method.to_uppercase();
        if request.body.is_some() && (method == "GET" || method == "HEAD") {
            return Err(FetchError {
                message: "Request with GET/HEAD method cannot have body.".to_owned(),
                cause: None,
            });
        }
        let url = check_fetch_url(&request.url, &address).map_err(FetchError::refused)?;
        let mut headers: Vec<(String, String)> = Vec::new();
        for (name, value) in &request.headers {
            let name = name.to_lowercase();
            if let Some(existing) = headers.iter_mut().find(|(key, _)| *key == name) {
                existing.1 = format!("{}, {value}", existing.1);
            } else {
                headers.push((name, value.clone()));
            }
        }
        let body = match request.body {
            Some(FetchBody::Text(text)) => {
                if !headers.iter().any(|(name, _)| name == "content-type") {
                    headers.push((
                        "content-type".to_owned(),
                        "text/plain;charset=UTF-8".to_owned(),
                    ));
                }
                Some(text.into_bytes())
            }
            Some(FetchBody::Bytes(bytes)) => Some(bytes),
            None => None,
        };
        headers.sort_by(|a, b| a.0.cmp(&b.0));
        if let Some(body) = &body {
            headers.retain(|(name, _)| name != "content-length");
            headers.push(("content-length".to_owned(), body.len().to_string()));
        }
        let guard = Guard {
            options: address,
            loopback_host: is_loopback_host(&url),
        };
        let response = send(&url, &method, &headers, body, Some(guard))
            .await
            .map_err(|error| match error {
                ConnectError::Refused(error) => FetchError::refused(error),
                ConnectError::Network(message) => FetchError::network(message),
            })?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) && request.redirect == RedirectMode::Error {
            return Err(FetchError::refused(SafeFetchError::new(
                SafeFetchFailureReason::Redirect,
            )));
        }
        let declared = declared_length(&response);
        if let Some(max) = self.options.max_bytes
            && declared.is_finite()
            && declared > max as f64
        {
            return Err(FetchError::refused(SafeFetchError::new(
                SafeFetchFailureReason::Size,
            )));
        }
        let response_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let status_text = response
            .status()
            .canonical_reason()
            .unwrap_or("")
            .to_owned();
        let empty = method == "HEAD" || NULL_BODY_STATUSES.contains(&status);
        let body = if empty {
            ResponseBody::empty()
        } else {
            ResponseBody {
                incoming: Some(response.into_body()),
                limit: self.options.max_bytes,
                size: 0,
                failed: None,
            }
        };
        Ok(FetchResponse {
            status,
            status_text,
            headers: response_headers,
            url: url.to_string(),
            body,
        })
    }
}

type BoxedFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// An unguarded GET that follows redirects (the global `fetch` the TypeScript code uses for public services such as
/// Have I Been Pwned and certificate revocation lists): status and body bytes.
pub(crate) fn plain_fetch<'a>(
    url: &'a str,
    headers: &'a [(String, String)],
) -> BoxedFuture<'a, Result<(u16, Vec<u8>), FetchError>> {
    Box::pin(async move {
        let mut current = Url::parse(url).map_err(|_| FetchError {
            message: format!("Failed to parse URL from {url}"),
            cause: None,
        })?;
        for _ in 0..=20 {
            if current.scheme() != "http" && current.scheme() != "https" {
                return Err(FetchError::network("unknown scheme"));
            }
            let response = send(&current, "GET", headers, None, None)
                .await
                .map_err(|error| match error {
                    ConnectError::Refused(error) => FetchError::refused(error),
                    ConnectError::Network(message) => FetchError::network(message),
                })?;
            let status = response.status().as_u16();
            if [301, 302, 303, 307, 308].contains(&status)
                && let Some(location) = response
                    .headers()
                    .get("location")
                    .and_then(|value| value.to_str().ok())
            {
                current = current
                    .join(location)
                    .map_err(|_| FetchError::network("invalid redirect"))?;
                continue;
            }
            let mut body = ResponseBody {
                incoming: Some(response.into_body()),
                limit: None,
                size: 0,
                failed: None,
            };
            return Ok((status, body.bytes().await?));
        }
        Err(FetchError::network("redirect count exceeded"))
    })
}

/// [`plain_fetch`] with the body as text.
pub(crate) async fn plain_get(
    url: &str,
    headers: &[(String, String)],
) -> Result<(u16, String), FetchError> {
    let (status, body) = plain_fetch(url, headers).await?;
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

impl std::fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseBody")
            .field("open", &self.incoming.is_some())
            .field("limit", &self.limit)
            .field("size", &self.size)
            .finish()
    }
}

impl std::fmt::Debug for FetchResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchResponse")
            .field("status", &self.status)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}
