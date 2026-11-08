//! The transport the client sends its requests through: the Rust form of the `fetch` option.
//!
//! A [`FetchRequest`] carries exactly what the TypeScript client hands to `fetch`: the URL, `POST`, the headers, the
//! JSON body, and the request modes (`credentials: 'include'`, `redirect: 'error'`, `cache: 'no-store'`) and signal,
//! which a transport honours as far as it can. [`HyperFetch`] (feature `default-transport`) is the built-in one;
//! tests and server-side code can route requests anywhere, for example straight into a server's handler with
//! [`FetchRequest::into_http`] and [`FetchResponse::from_http`].

use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use futures::future::BoxFuture;
use http::{HeaderMap, Method};

use crate::abort::AbortSignal;

/// An error a transport fails with (`fetch` rejecting, as with a network failure).
pub type BoxError = Arc<dyn std::error::Error + Send + Sync>;

/// One request of the client.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    /// The absolute URL: `{origin}{basePath}/{path}`.
    pub url: String,
    /// Always `POST`.
    pub method: Method,
    pub headers: HeaderMap,
    /// The JSON text of the request input.
    pub body: String,
    /// `include`: send the cookies a browser-like transport holds for the origin.
    pub credentials: &'static str,
    /// `error`: a redirect fails the request instead of being followed.
    pub redirect: &'static str,
    /// `no-store`: never answer from or write to an HTTP cache.
    pub cache: &'static str,
    /// The call's signal, when it has one.
    pub signal: Option<AbortSignal>,
}

impl FetchRequest {
    /// The request as an `http::Request` (URL, method, headers and body), for transports built on the `http` types.
    pub fn into_http(self) -> http::Result<http::Request<Bytes>> {
        let mut builder = http::Request::builder()
            .method(self.method)
            .uri(self.url.as_str());
        if let Some(headers) = builder.headers_mut() {
            *headers = self.headers;
        }
        builder.body(Bytes::from(self.body))
    }
}

/// The answer of a transport.
#[derive(Debug, Clone, Default)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl FetchResponse {
    /// A response from an `http::Response`.
    pub fn from_http(response: http::Response<Bytes>) -> Self {
        let (parts, body) = response.into_parts();
        Self {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body,
        }
    }

    /// `Response.json(value, { status })`: a JSON answer.
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        Self {
            status,
            headers,
            body: Bytes::from(value.to_string()),
        }
    }

    /// Whether the status is 200 to 299 (`Response.ok`).
    pub fn ok(&self) -> bool {
        (200..=299).contains(&self.status)
    }
}

/// Sends one request and returns the answer, or fails as `fetch` rejects (network failure, refused redirect).
pub trait Fetch: Send + Sync {
    fn fetch(&self, request: FetchRequest) -> BoxFuture<'static, Result<FetchResponse, BoxError>>;
}

/// A transport from an async function or closure.
pub struct FnFetch<F>(pub F);

impl<F, Fut> Fetch for FnFetch<F>
where
    F: Fn(FetchRequest) -> Fut + Send + Sync,
    Fut: Future<Output = Result<FetchResponse, BoxError>> + Send + 'static,
{
    fn fetch(&self, request: FetchRequest) -> BoxFuture<'static, Result<FetchResponse, BoxError>> {
        Box::pin((self.0)(request))
    }
}

/// A transport error with a message (`TypeError: fetch failed` and its kin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchError(pub String);

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FetchError {}

#[cfg(feature = "default-transport")]
pub use transport::HyperFetch;

#[cfg(feature = "default-transport")]
mod transport {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
    use hyper_util::client::legacy::Client;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::rt::TokioExecutor;

    /// The built-in transport: HTTP/1.1 over TCP, HTTPS with rustls and the Mozilla root certificates. It follows the
    /// request modes a server-side `fetch` follows: redirects fail the request (`redirect: 'error'`), nothing is
    /// cached, and no cookie jar exists (pass cookies in `headers` when a server-side caller needs them).
    #[derive(Clone)]
    pub struct HyperFetch {
        client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    }

    impl HyperFetch {
        pub fn new() -> Result<Self, BoxError> {
            let connector = HttpsConnectorBuilder::new()
                .with_provider_and_webpki_roots(Arc::new(rustls::crypto::ring::default_provider()))
                .map_err(|error| Arc::new(FetchError(error.to_string())) as BoxError)?
                .https_or_http()
                .enable_http1()
                .build();
            Ok(Self {
                client: Client::builder(TokioExecutor::new()).build(connector),
            })
        }
    }

    /// Fetch's redirect statuses.
    const REDIRECTS: [u16; 5] = [301, 302, 303, 307, 308];

    impl Fetch for HyperFetch {
        fn fetch(
            &self,
            request: FetchRequest,
        ) -> BoxFuture<'static, Result<FetchResponse, BoxError>> {
            let client = self.client.clone();
            Box::pin(async move {
                let failed = |message: String| Arc::new(FetchError(message)) as BoxError;
                let redirect_error = request.redirect == "error";
                let request = request
                    .into_http()
                    .map_err(|error| failed(format!("fetch failed: {error}")))?;
                let (parts, body) = request.into_parts();
                let request = http::Request::from_parts(parts, Full::new(body));
                let response = client
                    .request(request)
                    .await
                    .map_err(|error| failed(format!("fetch failed: {error}")))?;
                let status = response.status().as_u16();
                if redirect_error && REDIRECTS.contains(&status) {
                    return Err(failed(
                        "fetch failed: unexpected redirect (redirect mode is error)".to_owned(),
                    ));
                }
                let (parts, body) = response.into_parts();
                let body = body
                    .collect()
                    .await
                    .map_err(|error| failed(format!("fetch failed: {error}")))?
                    .to_bytes();
                Ok(FetchResponse {
                    status,
                    headers: parts.headers,
                    body,
                })
            })
        }
    }
}
