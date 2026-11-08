//! axum integration: [`IamRequest`] as an extractor, [`MiddlewareError`] and [`IamRequestError`] as responses, and
//! route parameters for guard callbacks. Install [`crate::layer::IamTower::layer`] with `Router::layer` and the
//! guards with `route_layer` (so route parameters are known when they run).
//!
//! ```ignore
//! async fn me(iam: IamRequest<BetterIam>) -> Result<Json<Value>, MiddlewareError> {
//!     let session = iam.require_session(None).await?;
//!     Ok(Json(session["identity"].clone()))
//! }
//! ```

use ::axum::extract::{FromRequestParts, RawPathParams};
use ::axum::response::{IntoResponse, Response};
use futures::FutureExt;
use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::request::Parts;
use http::{HeaderValue, StatusCode};

use crate::iam::IamLike;
use crate::{IamRequest, IamRequestError, MiddlewareError, RefusalMarker, error_body};

impl<S, T> FromRequestParts<S> for IamRequest<T>
where
    S: Send + Sync,
    T: IamLike,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<IamRequest<T>>()
            .cloned()
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "The Better IAM layer is not installed on this route",
                )
                    .into_response()
            })
    }
}

impl IntoResponse for IamRequestError {
    /// The IAM JSON error envelope, with the refusal left on the response so the layer can redirect page
    /// navigations to the login / step-up page.
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = (status, error_body(&self.code, &self.message)).into_response();
        let headers = response.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response.extensions_mut().insert(RefusalMarker(self));
        response
    }
}

impl IntoResponse for MiddlewareError {
    /// IAM refusals become the JSON envelope (or, through the layer, a redirect for pages); anything else is logged
    /// and answered with a plain 500.
    fn into_response(self) -> Response {
        match self {
            MiddlewareError::Refusal(refusal) => refusal.into_response(),
            MiddlewareError::Other(message) => {
                eprintln!("better-iam middleware: {message}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
        }
    }
}

/// The route parameters of a request matched by an axum router (in a guard installed with `route_layer`).
pub fn path_params(parts: &Parts) -> Vec<(String, String)> {
    let (mut probe, ()) = http::Request::new(()).into_parts();
    probe.extensions = parts.extensions.clone();
    match RawPathParams::from_request_parts(&mut probe, &()).now_or_never() {
        Some(Ok(params)) => params
            .iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
        _ => Vec::new(),
    }
}

/// One route parameter of a request matched by an axum router.
pub fn path_param(parts: &Parts, name: &str) -> Option<String> {
    path_params(parts)
        .into_iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}
