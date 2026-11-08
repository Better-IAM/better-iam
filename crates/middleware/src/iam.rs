//! `IamLike`: the server surface the middleware uses. A [`BetterIam`] (or anything that borrows one, such as an
//! `Arc<BetterIam>` or an application state holding it) satisfies it.

use std::borrow::Borrow;
use std::sync::Arc;

use async_trait::async_trait;
use better_iam_core::CredentialInput;
use better_iam_server::BetterIam;
use better_iam_server::api::Body;
use better_iam_server::api::filters::PlanResourcesRequest;
use better_iam_server::http::AuthArgs;
use better_iam_server::options::{
    AccessibleResourcesRequest, AuthorizationRequest, BatchAuthorizationRequest, HttpRequest,
    HttpResponse,
};
use bytes::Bytes;
use futures::future::BoxFuture;
use http::{HeaderMap, Method};
use serde_json::{Map, Value, json};

use crate::helpers::AuthorizeResult;
use crate::{MiddlewareError, ResourceRef};

/// Where the IAM HTTP API is served (`iam.endpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRef {
    pub origin: String,
    pub base_path: String,
    pub secure: Option<bool>,
}

/// How the node transport wants a request body read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRead {
    /// Read the whole body, refusing it with 413 beyond this many bytes.
    Limit(usize),
    /// Do not read the body: the transport answers the request without it (an unsupported method, an invalid
    /// request target).
    Skip,
}

/// The server surface the middleware uses (`IamLike`); a `betterIam()` instance satisfies it. Optional members of
/// the TypeScript interface are a `supports_*` / `has_*` probe with a default implementation.
#[async_trait]
pub trait IamLike: Send + Sync + 'static {
    /// `api.auth.getSession(credential)`.
    async fn get_session(&self, credential: &CredentialInput) -> Result<Value, MiddlewareError>;

    /// `api.auth.signOut(credential)`.
    async fn sign_out(&self, credential: &CredentialInput) -> Result<Value, MiddlewareError>;

    /// Whether `api.assertions` exists.
    fn issues_assertions(&self) -> bool {
        false
    }

    /// `api.assertions.issue(credential, input)`.
    async fn issue_assertion(
        &self,
        _credential: &CredentialInput,
        _input: &Value,
    ) -> Result<Value, MiddlewareError> {
        Err(MiddlewareError::Other(
            "This IAM server does not issue assertions".into(),
        ))
    }

    /// `handler(request)`: the fetch-style handler.
    async fn handler(&self, request: HttpRequest) -> HttpResponse;

    /// Whether the node transport (`nodeHandler`) exists; it serves node-only protocol mounts too.
    fn has_node_handler(&self) -> bool {
        false
    }

    /// How the node transport reads the body of a request (its size limit).
    fn node_read(&self, _method: &Method, _target: &str, _headers: &HeaderMap) -> NodeRead {
        NodeRead::Limit(2_097_152)
    }

    /// `nodeHandler(req, res)`: the request-target as sent, the headers and the whole body.
    async fn node_handler(
        &self,
        _method: Method,
        _target: &str,
        _headers: HeaderMap,
        _body: Bytes,
    ) -> HttpResponse {
        let mut response = http::Response::new(Bytes::from_static(b"Not Found"));
        *response.status_mut() = http::StatusCode::NOT_FOUND;
        response
    }

    /// `require(request)`: the server's refusal (401/403/429) unless allowed.
    async fn require(&self, request: &AuthorizationRequest) -> Result<(), MiddlewareError>;

    /// `authorizeMany(request)`.
    async fn authorize_many(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> Result<Vec<AuthorizeResult>, MiddlewareError>;

    /// Whether `listAccessible` exists.
    fn lists_accessible(&self) -> bool {
        false
    }

    /// `listAccessible(request)`: `{ resources, total }`.
    async fn list_accessible(
        &self,
        _request: &AccessibleResourcesRequest,
    ) -> Result<Value, MiddlewareError> {
        Err(MiddlewareError::Other(
            "This IAM server does not list accessible resources".into(),
        ))
    }

    /// Whether `planResources` exists.
    fn plans_resources(&self) -> bool {
        false
    }

    /// `planResources(request)`: which resources of a type the caller may act on, as a filter.
    async fn plan_resources(
        &self,
        _request: &PlanResourcesRequest,
    ) -> Result<Value, MiddlewareError> {
        Err(MiddlewareError::Other(
            "This IAM server does not plan resources".into(),
        ))
    }

    /// `endpoint`: where the handler is mounted.
    fn endpoint(&self) -> Option<EndpointRef> {
        None
    }

    /// Whether `hosts` (organization sign-in addresses) exists: in-process calls then keep the visitor's host so the
    /// server pins them to that organization.
    fn has_hosts(&self) -> bool {
        false
    }
}

#[async_trait]
impl<B> IamLike for B
where
    B: Borrow<BetterIam> + Send + Sync + 'static,
{
    async fn get_session(&self, credential: &CredentialInput) -> Result<Value, MiddlewareError> {
        let iam: &BetterIam = self.borrow();
        Ok(iam
            .api
            .auth
            .call(
                "getSession",
                AuthArgs::Authenticated(credential.clone(), Value::Object(Map::new())),
            )
            .await?)
    }

    async fn sign_out(&self, credential: &CredentialInput) -> Result<Value, MiddlewareError> {
        let iam: &BetterIam = self.borrow();
        Ok(iam
            .api
            .auth
            .call(
                "signOut",
                AuthArgs::Authenticated(credential.clone(), Value::Object(Map::new())),
            )
            .await?)
    }

    fn issues_assertions(&self) -> bool {
        true
    }

    async fn issue_assertion(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> Result<Value, MiddlewareError> {
        let iam: &BetterIam = self.borrow();
        Ok(iam
            .api
            .assertions
            .issue(credential, Body::from_value(input.clone()))
            .await?
            .into_value()?)
    }

    async fn handler(&self, request: HttpRequest) -> HttpResponse {
        let iam: &BetterIam = self.borrow();
        iam.handler(request).await
    }

    fn has_node_handler(&self) -> bool {
        true
    }

    fn node_read(&self, method: &Method, target: &str, headers: &HeaderMap) -> NodeRead {
        let iam: &BetterIam = self.borrow();
        if matches!(method.as_str(), "TRACE" | "CONNECT" | "TRACK") {
            return NodeRead::Skip;
        }
        match iam.http.node_url(target, headers) {
            Ok(url) => NodeRead::Limit(iam.http.body_limit(&url)),
            Err(_) => NodeRead::Skip,
        }
    }

    async fn node_handler(
        &self,
        method: Method,
        target: &str,
        headers: HeaderMap,
        body: Bytes,
    ) -> HttpResponse {
        let iam: &BetterIam = self.borrow();
        iam.http.node_handler(method, target, headers, body).await
    }

    async fn require(&self, request: &AuthorizationRequest) -> Result<(), MiddlewareError> {
        let iam: &BetterIam = self.borrow();
        Ok(iam.require(request).await?)
    }

    async fn authorize_many(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> Result<Vec<AuthorizeResult>, MiddlewareError> {
        let iam: &BetterIam = self.borrow();
        Ok(iam
            .authorize_many(request)
            .await?
            .into_iter()
            .map(|result| AuthorizeResult {
                action: result.check.action,
                resource: result.check.resource,
                allowed: result.allowed,
                reason: result.reason,
            })
            .collect())
    }

    fn lists_accessible(&self) -> bool {
        true
    }

    async fn list_accessible(
        &self,
        request: &AccessibleResourcesRequest,
    ) -> Result<Value, MiddlewareError> {
        let iam: &BetterIam = self.borrow();
        let answer = iam.list_accessible(request).await?;
        Ok(json!({
            "resources": answer.resources,
            "total": better_iam_core::js::number(answer.total),
        }))
    }

    fn plans_resources(&self) -> bool {
        true
    }

    async fn plan_resources(
        &self,
        request: &PlanResourcesRequest,
    ) -> Result<Value, MiddlewareError> {
        let iam: &BetterIam = self.borrow();
        Ok(iam.plan_resources.plan_resources(request).await?)
    }

    fn endpoint(&self) -> Option<EndpointRef> {
        let iam: &BetterIam = self.borrow();
        Some(EndpointRef {
            origin: iam.endpoint.origin.clone(),
            base_path: iam.endpoint.base_path.clone(),
            secure: Some(iam.endpoint.secure),
        })
    }

    fn has_hosts(&self) -> bool {
        true
    }
}

/// A lazily resolved instance (`() => T | Promise<T>`).
pub type IamFactory<T> =
    Arc<dyn Fn() -> BoxFuture<'static, Result<Arc<T>, MiddlewareError>> + Send + Sync>;

/// The instance an adapter works with: ready, or resolved on first use of each request (`source: T | (() => T)`).
pub enum IamSource<T> {
    Ready(Arc<T>),
    Lazy(IamFactory<T>),
}

impl<T> Clone for IamSource<T> {
    fn clone(&self) -> Self {
        match self {
            IamSource::Ready(iam) => IamSource::Ready(iam.clone()),
            IamSource::Lazy(factory) => IamSource::Lazy(factory.clone()),
        }
    }
}

impl<T> IamSource<T> {
    /// A source resolved by `factory` each time it is needed.
    pub fn lazy<F, Fut>(factory: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Arc<T>, MiddlewareError>> + Send + 'static,
    {
        IamSource::Lazy(Arc::new(move || Box::pin(factory())))
    }

    /// `resolveIam()`.
    pub async fn resolve(&self) -> Result<Arc<T>, MiddlewareError> {
        match self {
            IamSource::Ready(iam) => Ok(iam.clone()),
            IamSource::Lazy(factory) => factory().await,
        }
    }
}

impl<T> From<Arc<T>> for IamSource<T> {
    fn from(iam: Arc<T>) -> Self {
        IamSource::Ready(iam)
    }
}

/// The default resource of a check: the tenant itself.
pub(crate) fn tenant_resource(tenant_id: &str) -> ResourceRef {
    ResourceRef {
        kind: "iam".into(),
        id: tenant_id.to_owned(),
    }
}
