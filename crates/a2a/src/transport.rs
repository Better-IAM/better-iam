//! The web platform pieces the TypeScript package uses, in Rust form: request and response bodies (`Request`,
//! `Response`), `fetch` (a [`Fetch`] implementation, by default [`HttpFetch`]), `TextDecoder` and bounded body
//! reads.

use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;
use futures::future::BoxFuture;
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::TokioIo;
use url::{Host, Url};

use crate::error::A2aError;

/// The error type of a [`Body`].
pub type BodyError = Box<dyn std::error::Error + Send + Sync>;

/// A request or response body: a stream of byte chunks (a `ReadableStream` of a `Request` or `Response`).
pub type Body = http_body_util::combinators::UnsyncBoxBody<Bytes, BodyError>;

/// A body holding `bytes`.
pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// An empty body.
pub fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// The URL a fetched response came from (`response.url`), set by [`HttpFetch`]; a response without it reads as
/// `response.url === ''`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseUrl(pub String);

/// `fetch` for the requests the package makes (key sets and agent cards): a GET of an absolute URL. Requests are
/// made with `redirect: 'error'` (the request carries [`RedirectPolicy::Error`]): an implementation must not follow
/// redirects. Timeouts are applied by the caller.
pub trait Fetch: Send + Sync {
    /// Sends `request` and answers its response, or fails as `fetch` rejects.
    fn fetch(
        &self,
        request: http::Request<Body>,
    ) -> BoxFuture<'_, Result<http::Response<Body>, A2aError>>;
}

/// The redirect mode of a [`Fetch`] request (`RequestInit.redirect`); the package always sends `Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectPolicy {
    /// A redirect fails the request.
    Error,
}

/// A [`Fetch`] from a function or closure.
pub struct FetchFn<F>(pub F);

impl<F, Fut> Fetch for FetchFn<F>
where
    F: Fn(http::Request<Body>) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<http::Response<Body>, A2aError>> + Send + 'static,
{
    fn fetch(
        &self,
        request: http::Request<Body>,
    ) -> BoxFuture<'_, Result<http::Response<Body>, A2aError>> {
        Box::pin((self.0)(request))
    }
}

/// A shared [`Fetch`] from a closure.
pub fn fetch_fn<F, Fut>(function: F) -> Arc<dyn Fetch>
where
    F: Fn(http::Request<Body>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<http::Response<Body>, A2aError>> + Send + 'static,
{
    Arc::new(FetchFn(function))
}

/// The global `fetch`: HTTP/1.1 over TCP, TLS (with the Web PKI roots) for `https:`. Redirects fail the request.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpFetch;

/// The shared default fetch (`globalThis.fetch`).
pub(crate) static DEFAULT_FETCH: LazyLock<Arc<dyn Fetch>> = LazyLock::new(|| Arc::new(HttpFetch));

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

fn fetch_failed(detail: impl std::fmt::Display) -> A2aError {
    A2aError::message(format!("fetch failed: {detail}"))
}

impl Fetch for HttpFetch {
    fn fetch(
        &self,
        request: http::Request<Body>,
    ) -> BoxFuture<'_, Result<http::Response<Body>, A2aError>> {
        Box::pin(async move {
            let text = request.uri().to_string();
            let url = Url::parse(&text)
                .map_err(|_| A2aError::message(format!("Failed to parse URL from {text}")))?;
            if url.scheme() != "http" && url.scheme() != "https" {
                return Err(fetch_failed("unknown scheme"));
            }
            let port = url
                .port_or_known_default()
                .ok_or_else(|| fetch_failed("no port"))?;
            let addresses: Vec<std::net::SocketAddr> = match url.host() {
                Some(Host::Ipv4(address)) => vec![(IpAddr::V4(address), port).into()],
                Some(Host::Ipv6(address)) => vec![(IpAddr::V6(address), port).into()],
                Some(Host::Domain(domain)) => tokio::net::lookup_host((domain, port))
                    .await
                    .map_err(|error| fetch_failed(format!("getaddrinfo {domain}: {error}")))?
                    .collect(),
                None => return Err(fetch_failed("no host")),
            };
            let mut stream = None;
            let mut last = String::from("no address");
            for address in addresses {
                match tokio::net::TcpStream::connect(address).await {
                    Ok(connected) => {
                        stream = Some(connected);
                        break;
                    }
                    Err(error) => last = error.to_string(),
                }
            }
            let stream = stream.ok_or_else(|| fetch_failed(last))?;
            let _ = stream.set_nodelay(true);
            let (parts, body) = request.into_parts();
            let response = if url.scheme() == "https" {
                let name = match url.host() {
                    Some(Host::Ipv4(address)) => {
                        rustls::pki_types::ServerName::IpAddress(IpAddr::V4(address).into())
                    }
                    Some(Host::Ipv6(address)) => {
                        rustls::pki_types::ServerName::IpAddress(IpAddr::V6(address).into())
                    }
                    Some(Host::Domain(domain)) => {
                        rustls::pki_types::ServerName::try_from(domain.to_owned())
                            .map_err(fetch_failed)?
                    }
                    None => return Err(fetch_failed("no host")),
                };
                let tls = TLS.connect(name, stream).await.map_err(fetch_failed)?;
                send_over(tls, &url, parts, body).await?
            } else {
                send_over(stream, &url, parts, body).await?
            };
            let status = response.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308)
                && response.headers().contains_key(http::header::LOCATION)
            {
                return Err(fetch_failed("unexpected redirect"));
            }
            let (mut parts, incoming) = response.into_parts();
            parts.extensions.insert(ResponseUrl(url.to_string()));
            let body = incoming
                .map_err(|error| Box::new(error) as BodyError)
                .boxed_unsync();
            Ok(http::Response::from_parts(parts, body))
        })
    }
}

async fn send_over<IO>(
    io: IO,
    url: &Url,
    parts: http::request::Parts,
    body: Body,
) -> Result<http::Response<hyper::body::Incoming>, A2aError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(io))
            .await
            .map_err(fetch_failed)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut target = url.path().to_owned();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    let host = match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_owned(),
        (None, _) => String::new(),
    };
    let mut builder = http::Request::builder()
        .method(parts.method)
        .uri(target)
        .header(http::header::HOST, host);
    for (name, value) in &parts.headers {
        if name != http::header::HOST {
            builder = builder.header(name, value);
        }
    }
    let request = builder
        .header(http::header::CONNECTION, "close")
        .body(body)
        .map_err(fetch_failed)?;
    sender.send_request(request).await.map_err(fetch_failed)
}

/// `new TextDecoder().decode(bytes)`: UTF-8 with replacement characters, a leading byte order mark removed.
pub(crate) fn decode_utf8(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

/// A streaming `TextDecoder` (`decode(chunk, { stream: true })`, then `decode()`).
#[derive(Debug, Default)]
pub(crate) struct Utf8Stream {
    pending: Vec<u8>,
    bom_checked: bool,
}

impl Utf8Stream {
    /// Decodes a chunk, keeping an incomplete trailing sequence for the next one.
    pub(crate) fn decode(&mut self, chunk: &[u8]) -> String {
        self.pending.extend_from_slice(chunk);
        if !self.bom_checked {
            const BOM: &[u8] = b"\xEF\xBB\xBF";
            if self.pending.len() < BOM.len() && BOM.starts_with(&self.pending) {
                return String::new();
            }
            if self.pending.starts_with(BOM) {
                self.pending.drain(..BOM.len());
            }
            self.bom_checked = true;
        }
        let mut out = String::new();
        let mut offset = 0;
        loop {
            match std::str::from_utf8(&self.pending[offset..]) {
                Ok(text) => {
                    out.push_str(text);
                    offset = self.pending.len();
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    out.push_str(
                        std::str::from_utf8(&self.pending[offset..offset + valid])
                            .expect("validated prefix"),
                    );
                    match error.error_len() {
                        Some(length) => {
                            out.push('\u{FFFD}');
                            offset += valid + length;
                        }
                        None => {
                            offset += valid;
                            break;
                        }
                    }
                }
            }
        }
        self.pending.drain(..offset);
        out
    }

    /// Ends the stream: what is left, with replacement characters for an incomplete sequence.
    pub(crate) fn finish(&mut self) -> String {
        let rest = std::mem::take(&mut self.pending);
        if !self.bom_checked {
            self.bom_checked = true;
            return decode_utf8(&rest);
        }
        String::from_utf8_lossy(&rest).into_owned()
    }
}

/// Reads a body to its end, or None (stopping there) once it is larger than `max_bytes`.
pub(crate) async fn read_bounded(
    mut body: Body,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, A2aError> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| A2aError::message(error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if bytes.len() + data.len() > max_bytes {
                return Ok(None);
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(Some(bytes))
}

/// Reads a whole body (`response.text()` as bytes).
pub(crate) async fn read_all(mut body: Body) -> Result<Vec<u8>, A2aError> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| A2aError::message(error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes)
}

/// `headers.get(name)`: the values of a header joined with ", ", or None.
pub(crate) fn header(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let values: Vec<String> = headers
        .get_all(name)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

/// A response with a JSON body: `new Response(JSON.stringify(body), { status, headers: { 'content-type':
/// 'application/json', ...headers } })`.
pub(crate) fn json_response(
    body: &serde_json::Value,
    status: u16,
    headers: &[(&str, &str)],
) -> http::Response<Body> {
    let mut builder = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(full(better_iam_core::js::stringify(body)))
        .expect("valid response")
}

/// Runs `future` with a deadline (`AbortSignal.timeout(ms)`): past it, the TimeoutError fetch rejects with.
pub(crate) async fn with_timeout<T>(
    milliseconds: u64,
    future: impl std::future::Future<Output = Result<T, A2aError>>,
) -> Result<T, A2aError> {
    match tokio::time::timeout(Duration::from_millis(milliseconds), future).await {
        Ok(result) => result,
        Err(_) => Err(A2aError::message(
            "The operation was aborted due to timeout",
        )),
    }
}
