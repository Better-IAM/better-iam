//! Port of `packages/server/src/observe.ts`: timed spans for every operation, authorization query, authentication
//! call, and HTTP request.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Instant;

use better_iam_core::{IamError, IamResult};
use serde::Serialize;

/// `SpanKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum SpanKind {
    #[serde(rename = "operation")]
    Operation,
    #[serde(rename = "authorize")]
    Authorize,
    #[serde(rename = "authorizeMany")]
    AuthorizeMany,
    #[serde(rename = "listAccessible")]
    ListAccessible,
    #[serde(rename = "auth")]
    Auth,
    #[serde(rename = "http")]
    Http,
}

impl SpanKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::Authorize => "authorize",
            Self::AuthorizeMany => "authorizeMany",
            Self::ListAccessible => "listAccessible",
            Self::Auth => "auth",
            Self::Http => "http",
        }
    }
}

/// `IamSpan.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SpanOutcome {
    Ok,
    Denied,
    Error,
}

impl SpanOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }
}

/// `IamSpan`: one timed unit of work.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IamSpan {
    pub kind: SpanKind,
    /// The action, authentication method, or request path.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// The caller's `X-Request-Id` on `http` spans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub outcome: SpanOutcome,
    /// The IamError code for denied and error outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// HTTP status for `http` spans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub duration_ms: f64,
}

/// What `outcomeOf` may set on a successful span (`Partial<Pick<IamSpan, 'outcome' | 'status' | 'code'>>`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SpanOverride {
    pub outcome: Option<SpanOutcome>,
    pub status: Option<u16>,
    pub code: Option<String>,
}

/// `onSpan(span)`: must not panic; panics are caught so they can never affect requests.
pub type SpanHandler = Arc<dyn Fn(&IamSpan) + Send + Sync>;

/// `ObservabilityOptions`.
#[derive(Clone, Default)]
pub struct ObservabilityOptions {
    /// Receives every span after it completes.
    pub on_span: Option<SpanHandler>,
    /// Prometheus-style counters and latency histograms from the spans (`iam.metrics`).
    pub metrics: Option<crate::options::Toggle<crate::metrics::MetricsOptions>>,
}

/// Authentication and authorization refusals (401, 403, 429) are `denied`; everything else that fails is an `error`.
pub const DENIED_STATUSES: [u16; 3] = [401, 403, 429];

/// `Observer`.
#[derive(Clone, Default)]
pub struct Observer {
    handler: Option<SpanHandler>,
}

/// `createObserver(options)`: the observer for an `onSpan` handler.
pub fn create_observer(on_span: Option<SpanHandler>) -> Observer {
    Observer { handler: on_span }
}

impl Observer {
    /// `observer.enabled`.
    pub fn enabled(&self) -> bool {
        self.handler.is_some()
    }

    fn emit(&self, span: &IamSpan) {
        if let Some(handler) = &self.handler {
            // Observability never interferes with the request.
            let _ = catch_unwind(AssertUnwindSafe(|| handler(span)));
        }
    }

    /// `span(kind, name, tenantId, fn, outcomeOf?, extra?)`: times `work`, then reports the span; `outcome_of`
    /// classifies a successful result (for advisory denials).
    pub async fn span<T, F>(
        &self,
        kind: SpanKind,
        name: &str,
        tenant_id: Option<&str>,
        work: F,
        outcome_of: Option<&(dyn Fn(&T) -> SpanOverride + Send + Sync)>,
        request_id: Option<&str>,
    ) -> IamResult<T>
    where
        F: Future<Output = IamResult<T>>,
    {
        if self.handler.is_none() {
            return work.await;
        }
        let started = Instant::now();
        let result = work.await;
        let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
        let mut span = IamSpan {
            kind,
            name: name.to_owned(),
            tenant_id: tenant_id.map(str::to_owned),
            request_id: request_id.map(str::to_owned),
            outcome: SpanOutcome::Ok,
            code: None,
            status: None,
            duration_ms,
        };
        match &result {
            Ok(value) => {
                if let Some(classify) = outcome_of {
                    let extra = classify(value);
                    if let Some(outcome) = extra.outcome {
                        span.outcome = outcome;
                    }
                    span.status = extra.status;
                    span.code = extra.code;
                }
            }
            Err(error) => {
                span.outcome = outcome_for(error);
                span.code = Some(error.code.clone());
            }
        }
        self.emit(&span);
        result
    }
}

/// The outcome of a span that failed with `error`.
pub fn outcome_for(error: &IamError) -> SpanOutcome {
    if DENIED_STATUSES.contains(&error.status) {
        SpanOutcome::Denied
    } else {
        SpanOutcome::Error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[tokio::test]
    async fn spans_report_outcomes() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let observer = create_observer(Some(Arc::new(move |span: &IamSpan| {
            sink.lock().unwrap().push(span.clone());
        })));
        assert!(observer.enabled());
        let value = observer
            .span(
                SpanKind::Operation,
                "iam:groups:create",
                Some("t1"),
                async { Ok(5) },
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(value, 5);
        let denied: IamResult<()> = observer
            .span(
                SpanKind::Auth,
                "signIn",
                None,
                async { Err(IamError::with_status("UNAUTHENTICATED", "no", 401)) },
                None,
                None,
            )
            .await;
        assert!(denied.is_err());
        let failed: IamResult<()> = observer
            .span(
                SpanKind::Http,
                "/x",
                None,
                async { Err(IamError::new("INVALID_INPUT", "bad")) },
                None,
                Some("req-1"),
            )
            .await;
        assert!(failed.is_err());
        let advisory = |_: &bool| SpanOverride {
            outcome: Some(SpanOutcome::Denied),
            code: Some("ACCESS_DENIED".into()),
            status: None,
        };
        observer
            .span(
                SpanKind::Authorize,
                "docs:read",
                None,
                async { Ok(false) },
                Some(&advisory),
                None,
            )
            .await
            .unwrap();
        // A panicking handler is ignored.
        let panicky = create_observer(Some(Arc::new(|_: &IamSpan| panic!("boom"))));
        assert_eq!(
            panicky
                .span(SpanKind::Auth, "x", None, async { Ok(1) }, None, None)
                .await
                .unwrap(),
            1
        );
        let spans = seen.lock().unwrap();
        assert_eq!(spans[0].outcome, SpanOutcome::Ok);
        assert_eq!(spans[0].tenant_id.as_deref(), Some("t1"));
        assert_eq!(spans[1].outcome, SpanOutcome::Denied);
        assert_eq!(spans[1].code.as_deref(), Some("UNAUTHENTICATED"));
        assert_eq!(spans[2].outcome, SpanOutcome::Error);
        assert_eq!(spans[2].request_id.as_deref(), Some("req-1"));
        assert_eq!(spans[3].outcome, SpanOutcome::Denied);
        assert_eq!(spans[3].code.as_deref(), Some("ACCESS_DENIED"));
    }
}
