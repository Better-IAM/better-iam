//! A minimal HTTP server for downstream SCIM services in tests (`node:http` `createServer`): every request goes to a
//! handler that answers a status and an optional JSON body.

#![allow(dead_code)]

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::Value;

/// One request as the handler sees it.
pub struct Incoming {
    pub method: String,
    pub path: String,
    /// Decoded query parameters (`url.searchParams`).
    pub query: Vec<(String, String)>,
    pub headers: http::HeaderMap,
    pub body: String,
}

impl Incoming {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

pub type Handler = Arc<dyn Fn(Incoming) -> (u16, Option<Value>) + Send + Sync>;

/// A listening server; dropping it stops accepting connections.
pub struct FakeServer {
    pub origin: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn serve(handler: Handler) -> FakeServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("address").port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
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
                                .map(|body| body.to_bytes())
                                .unwrap_or_default();
                            let url = url::Url::parse(&format!(
                                "http://scim.test{}",
                                parts
                                    .uri
                                    .path_and_query()
                                    .map(|p| p.as_str())
                                    .unwrap_or("/")
                            ))
                            .expect("url");
                            let incoming = Incoming {
                                method: parts.method.as_str().to_owned(),
                                path: url.path().to_owned(),
                                query: url
                                    .query_pairs()
                                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                                    .collect(),
                                headers: parts.headers,
                                body: String::from_utf8_lossy(&bytes).into_owned(),
                            };
                            let (status, json) = handler(incoming);
                            let mut response = http::Response::new(Full::new(
                                json.map(|json| Bytes::from(json.to_string()))
                                    .unwrap_or_default(),
                            ));
                            *response.status_mut() =
                                http::StatusCode::from_u16(status).expect("status");
                            response.headers_mut().insert(
                                "content-type",
                                http::HeaderValue::from_static("application/scim+json"),
                            );
                            Ok::<_, Infallible>(response)
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    FakeServer {
        origin: format!("http://127.0.0.1:{port}"),
        task,
    }
}
