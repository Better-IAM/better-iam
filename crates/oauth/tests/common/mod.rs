//! Shared test harness: a runtime with large stacks, an in-memory SQLite store, local HTTP servers, a fetch helper
//! and a cookie-keeping browser.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::safe_fetch::{
    FetchBody, FetchRequest, GuardedFetchOptions, RedirectMode, create_guarded_fetch,
};
use better_iam_core::{IamStore, IamStoreExt};
use bytes::Bytes;
use futures::future::BoxFuture;
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};

/// Runs a test body on a runtime with large worker stacks (debug-build futures are big).
pub fn run<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(32 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join()
        .expect("test body");
}

pub fn now_ms() -> f64 {
    better_iam_core::js::now_ms()
}

/// A migrated in-memory SQLite store.
pub async fn memory_store() -> Arc<dyn IamStore> {
    let store = sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    store.migrate().await.expect("migrate");
    store
}

pub async fn insert(store: &Arc<dyn IamStore>, collection: &str, record: Value) {
    let collection = collection.to_owned();
    let record = record.as_object().cloned().expect("object record");
    store
        .transaction(move |tx| async move {
            tx.insert(&collection, &record).await?;
            Ok(())
        })
        .await
        .expect("insert");
}

pub async fn put(store: &Arc<dyn IamStore>, collection: &str, record: Value) {
    let collection = collection.to_owned();
    let record = record.as_object().cloned().expect("object record");
    store
        .transaction(move |tx| async move {
            tx.put(&collection, &record).await?;
            Ok(())
        })
        .await
        .expect("put");
}

pub async fn delete(store: &Arc<dyn IamStore>, collection: &str, id: &str) {
    let collection = collection.to_owned();
    let id = id.to_owned();
    store
        .transaction(move |tx| async move { tx.delete(&collection, &id).await })
        .await
        .expect("delete");
}

pub async fn get(
    store: &Arc<dyn IamStore>,
    collection: &str,
    id: &str,
) -> Option<Map<String, Value>> {
    store.get(collection, id).await.expect("get")
}

pub async fn find(
    store: &Arc<dyn IamStore>,
    collection: &str,
    filter: better_iam_core::Filter,
) -> Vec<Map<String, Value>> {
    store
        .find(
            collection,
            &filter,
            &better_iam_core::FindOptions::default(),
        )
        .await
        .expect("find")
}

/// The fixture RSA keys (private JWKs) with `kid`, `alg` and `use`.
pub fn rsa_key(index: usize, kid: &str) -> (Value, Value) {
    let keys: Value =
        serde_json::from_str(include_str!("../fixtures/rsa-keys.json")).expect("fixture");
    let mut private = keys[index].as_object().cloned().expect("key");
    private.insert("kid".into(), json!(kid));
    private.insert("alg".into(), json!("RS256"));
    private.insert("use".into(), json!("sig"));
    let public: Map<String, Value> = private
        .iter()
        .filter(|(key, _)| !["d", "p", "q", "dp", "dq", "qi"].contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    (Value::Object(private), Value::Object(public))
}

/// A fresh P-256 key pair as JWKs (private, public).
pub fn ec_key() -> (Value, Value) {
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let point =
        p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&secret.public_key(), false);
    let b64 = |bytes: &[u8]| better_iam_oauth::jose::b64url(bytes);
    let public = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64(point.x().expect("x")),
        "y": b64(point.y().expect("y")),
    });
    let mut private = public.as_object().cloned().unwrap();
    private.insert("d".into(), json!(b64(&secret.to_bytes())));
    (Value::Object(private), public)
}

pub fn random_b64(len: usize) -> String {
    let bytes: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
    better_iam_oauth::jose::b64url(&bytes)
}

pub fn random_key_b64() -> String {
    better_iam_oauth::jose::b64(&rand::random::<[u8; 32]>())
}

pub fn sha256_b64url(value: &str) -> String {
    better_iam_oauth::jose::sha256_b64url(value)
}

pub fn hash(value: &str) -> String {
    better_iam_oauth::hash(value)
}

/// Signs a JWT with a private JWK.
pub fn sign(jwk: &Value, alg: &str, header: Value, payload: Value) -> String {
    let key = better_iam_oauth::jose::import_jwk(jwk.as_object().unwrap()).expect("key");
    better_iam_oauth::jose::sign_jwt(
        &key,
        alg,
        header.as_object().cloned().unwrap_or_default(),
        &payload,
    )
    .expect("sign")
}

pub fn claims_of(jwt: &str) -> Map<String, Value> {
    let part = jwt.split('.').nth(1).expect("payload");
    let bytes = better_iam_oauth::jose::b64url_decode(part).expect("base64url");
    serde_json::from_slice::<Value>(&bytes)
        .unwrap()
        .as_object()
        .cloned()
        .unwrap()
}

pub type HttpRequest = http::Request<Bytes>;
pub type HttpResponse = http::Response<Bytes>;
pub type Handler = Arc<dyn Fn(HttpRequest) -> BoxFuture<'static, HttpResponse> + Send + Sync>;

/// Serves `handler` on 127.0.0.1 and returns its origin.
pub async fn serve(handler: Handler) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    move |request: http::Request<hyper::body::Incoming>| {
                        let handler = handler.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let bytes = body
                                .collect()
                                .await
                                .map(|collected| collected.to_bytes())
                                .unwrap_or_default();
                            let response = handler(http::Request::from_parts(parts, bytes)).await;
                            let (parts, body) = response.into_parts();
                            Ok::<_, std::convert::Infallible>(http::Response::from_parts(
                                parts,
                                http_body_util::Full::new(body),
                            ))
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// A late-bound handler slot (the server starts before the provider that answers it exists).
pub type Slot<T> = Arc<std::sync::OnceLock<T>>;

pub fn json_response(status: u16, body: &Value) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Bytes::from(serde_json::to_string(body).unwrap()))
        .unwrap()
}

pub fn text_response(status: u16, body: &str) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .body(Bytes::from(body.to_owned()))
        .unwrap()
}

/// A finished response.
#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
    pub fn header(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }
    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, value)| value.clone())
            .collect()
    }
    pub fn location(&self) -> String {
        self.header("location").unwrap_or_default()
    }
}

/// `fetch(url, { method, headers, body, redirect: 'manual' })`.
pub async fn fetch(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>) -> Resp {
    let fetch = create_guarded_fetch(GuardedFetchOptions {
        allow_private_networks: true,
        allow_insecure_localhost: true,
        any_port: true,
        max_bytes: None,
    });
    let mut request = FetchRequest::new(
        url,
        method,
        body.map(|body| FetchBody::Text(body.to_owned())),
    )
    .redirect(RedirectMode::Manual);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut response = fetch.fetch(request).await.expect("fetch");
    let text = response.body.text().await.unwrap_or_default();
    Resp {
        status: response.status,
        headers: response.headers.clone(),
        body: text,
    }
}

pub async fn get_url(url: &str) -> Resp {
    fetch("GET", url, &[], None).await
}

pub fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter())
        .finish()
}

pub fn basic(id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        better_iam_oauth::jose::b64(format!("{id}:{secret}").as_bytes())
    )
}

/// A cookie jar following the TypeScript tests' `visit` helper.
#[derive(Debug, Default, Clone)]
pub struct Browser {
    pub cookies: BTreeMap<String, String>,
    order: Vec<String>,
}

impl Browser {
    pub async fn visit(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Resp {
        let cookie = self
            .order
            .iter()
            .map(|name| format!("{name}={}", self.cookies[name]))
            .collect::<Vec<_>>()
            .join("; ");
        let mut all: Vec<(&str, &str)> = headers.to_vec();
        if !self.cookies.is_empty() {
            all.push(("cookie", cookie.as_str()));
        }
        let response = fetch(method, url, &all, body).await;
        for set in response.set_cookies() {
            let part = set.split(';').next().unwrap_or_default();
            if let Some(index) = part.find('=') {
                let name = part[..index].to_owned();
                if !self.cookies.contains_key(&name) {
                    self.order.push(name.clone());
                }
                self.cookies.insert(name, part[index + 1..].to_owned());
            }
        }
        response
    }

    pub async fn get(&mut self, url: &str) -> Resp {
        self.visit("GET", url, &[], None).await
    }
}

/// Resolves a possibly relative location against an origin.
pub fn absolute(location: &str, origin: &str) -> String {
    url::Url::parse(origin)
        .unwrap()
        .join(location)
        .unwrap()
        .to_string()
}

pub fn query_param(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}
