//! Shared helpers of the client suites: a recording `fetch` stub (`vi.fn<typeof fetch>()`), JSON answers
//! (`Response.json`), and an in-process transport into a server's handler (`fetch: (input, init) =>
//! iam.handler(new Request(input, init))`).
#![allow(dead_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};

use better_iam_client::{BoxError, Fetch, FetchRequest, FetchResponse, FnFetch};
use serde_json::{Value, json};

/// Runs a test body on a runtime with large worker stacks (debug-build futures are big).
pub fn run<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join()
        .expect("test body");
}

/// Like [`run`], with tokio's clock paused (`vi.useFakeTimers()`): time moves only when the test advances it, or
/// when every task is idle.
pub fn run_paused<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join()
        .expect("test body");
}

/// `Response.json({ data })`.
pub fn data(value: Value) -> FetchResponse {
    FetchResponse::json(200, &json!({ "data": value }))
}

/// `Response.json({ error: { code, message: code, ...extra } }, { status, headers })`.
pub fn failure(code: &str, status: u16, extra: Value, headers: &[(&str, &str)]) -> FetchResponse {
    let mut error = json!({ "code": code, "message": code });
    if let (Some(error), Value::Object(extra)) = (error.as_object_mut(), extra) {
        error.extend(extra);
    }
    let mut response = FetchResponse::json(status, &json!({ "error": error }));
    for (name, value) in headers {
        response.headers.append(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            http::HeaderValue::from_str(value).unwrap(),
        );
    }
    response
}

/// A raw answer with a body that is not JSON.
pub fn text(status: u16, body: &str) -> FetchResponse {
    FetchResponse {
        status,
        headers: http::HeaderMap::new(),
        body: bytes::Bytes::from(body.to_owned()),
    }
}

#[derive(Default)]
struct MockState {
    calls: Vec<FetchRequest>,
    queued: VecDeque<FetchResponse>,
    fallback: Option<FetchResponse>,
}

/// A recording transport: answers queued responses in order, then the fallback.
#[derive(Clone, Default)]
pub struct Mock {
    state: Arc<Mutex<MockState>>,
}

impl Mock {
    pub fn new() -> Self {
        Self::default()
    }

    /// `mockResolvedValue`: the answer once the queue is empty.
    pub fn always(&self, response: FetchResponse) -> &Self {
        self.state.lock().unwrap().fallback = Some(response);
        self
    }

    /// `mockResolvedValueOnce`.
    pub fn once(&self, response: FetchResponse) -> &Self {
        self.state.lock().unwrap().queued.push_back(response);
        self
    }

    pub fn calls(&self) -> Vec<FetchRequest> {
        self.state.lock().unwrap().calls.clone()
    }

    pub fn count(&self) -> usize {
        self.state.lock().unwrap().calls.len()
    }

    pub fn call(&self, index: usize) -> FetchRequest {
        self.calls()[index].clone()
    }

    pub fn last(&self) -> FetchRequest {
        self.calls().last().cloned().expect("a call")
    }

    pub fn fetch(&self) -> impl Fetch + use<> {
        let state = self.state.clone();
        FnFetch(move |request: FetchRequest| {
            let answer = {
                let mut state = state.lock().unwrap();
                state.calls.push(request);
                state
                    .queued
                    .pop_front()
                    .or_else(|| state.fallback.clone())
                    .expect("an answer for the request")
            };
            async move { Ok::<_, BoxError>(answer) }
        })
    }
}

/// The JSON body a request carried.
pub fn body(request: &FetchRequest) -> Value {
    serde_json::from_str(&request.body).expect("JSON body")
}

/// A header of a request.
pub fn header(request: &FetchRequest, name: &str) -> Option<String> {
    request
        .headers
        .get(name)
        .map(|value| value.to_str().unwrap().to_owned())
}

/// A transport into a server's HTTP handler, in process.
pub fn server_fetch(http: Arc<better_iam_server::http::Http>) -> impl Fetch + 'static {
    FnFetch(move |request: FetchRequest| {
        let http = http.clone();
        async move {
            let request = request
                .into_http()
                .map_err(|error| Arc::new(error) as BoxError)?;
            Ok::<_, BoxError>(FetchResponse::from_http(http.handler(request).await))
        }
    })
}
