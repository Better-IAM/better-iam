//! Port of `packages/server/src/http.ts`: the HTTP layer over the provisioning API, with the CSRF boundary, cookies,
//! CORS, host pinning, operational GET routes, protocol mounts, and the authentication API ([`AuthApi`]).
//!
//! [`Http::handler`] is the framework-neutral fetch-style handler (`http::Request<Bytes>` in, `http::Response<Bytes>`
//! out); [`Http::node_handler`] is the transport of `nodeHandler` (request-target checks, the body limits outside the
//! API, the Host header with organization addresses), which the standalone server and framework adapters use.

use std::sync::{Arc, Mutex};

use better_iam_auth::service::mfa::ConfirmMfaInput;
use better_iam_auth::{AuthService, MfaCredential, RequestHost};
use better_iam_core::{
    CredentialInput, IamError, IamResult, OutboxMessage, Session, SessionClientInfo, SessionKind,
    js as core_js,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::api::dispatch::{dispatch as dispatch_route, is_route};
use crate::api::index::Api;
use crate::client_info::client_from_request;
use crate::context::ServerContext;
use crate::contracts::PluginCall;
use crate::hosts::normalize_host;
use crate::metrics::MetricsCollector;
use crate::observe::{DENIED_STATUSES, Observer, SpanKind, SpanOutcome, SpanOverride};
use crate::operations::parse_checks;
use crate::options::{
    AccessibleResourcesRequest, AuthorizationRequest, BatchAuthorizationRequest, HttpRequest,
    HttpResponse, ProtocolMount, RequestHead, ResourceTarget,
};
use crate::port::details_of;
use crate::validation::{object, text};

// HTTP endpoints are mapped explicitly: infrastructure helpers are never remotely callable.

/// `publicAuthMethods`.
pub const PUBLIC_AUTH_METHODS: &[&str] = &[
    "signUp",
    "signIn",
    "requestEmailVerification",
    "verifyEmail",
    "requestPasswordReset",
    "resetPassword",
    "confirmEmailChange",
    "startPasswordless",
    "finishPasswordless",
    "beginMfa",
    "confirmMfa",
    "verifyMfa",
    "requestMfaCode",
    "recoverMfa",
    "beginPasskeyAuthentication",
    "finishPasskeyAuthentication",
    "beginPasskeyMfa",
    "finishPasskeyMfa",
];

/// `authenticatedAuthMethods`.
pub const AUTHENTICATED_AUTH_METHODS: &[&str] = &[
    "signOut",
    "getSession",
    "listSessions",
    "revokeSession",
    "revokeOtherSessions",
    "changePassword",
    "requestEmailChange",
    "beginPasskeyRegistration",
    "finishPasskeyRegistration",
    "startPhoneVerification",
    "confirmPhoneVerification",
    "reauthenticate",
    "listPasskeys",
    "deletePasskey",
    "renamePasskey",
    "regenerateRecoveryCodes",
    "disableMfa",
    "listTrustedDevices",
    "revokeTrustedDevice",
    "revokeTrustedDevices",
    "listSecurityEvents",
    "mfaStatus",
];

/// `routeGroups`.
pub const ROUTE_GROUPS: &[&str] = &[
    "tenants",
    "identities",
    "policies",
    "roles",
    "bindings",
    "authorities",
    "groups",
    "actions",
    "resourceTypes",
    "resources",
    "serviceAccounts",
    "credentials",
    "trust",
    "links",
    "root",
    "audit",
    "accessRequests",
    "webhooks",
    "relationships",
    "assertions",
    "domains",
    "config",
    "analysis",
    "certifications",
    "sod",
    "reports",
    "packages",
    "security",
    "roleMining",
    "impact",
    "invariants",
    "agreements",
    "accessPaths",
    "sts",
    "oidcProviders",
    "features",
    "onboarding",
    "hostnames",
    "agents",
    "delegations",
    "inference",
    "teams",
    "departments",
    "billing",
    "keys",
    "pki",
    "protection",
    "vault",
    "privacy",
    "ssh",
    "threats",
    "workflows",
    "compliance",
    "applications",
    "verifiableCredentials",
    "ldap",
    "devices",
    "filters",
    "signals",
    "quotas",
    "licenses",
    "guests",
    "clearances",
];

/// `publicApiMethods`: routes called with the body only (their own token, or none, is the credential).
pub const PUBLIC_API_METHODS: &[&str] = &[
    "tenants/acceptInvitation",
    "tenants/lookup",
    "domains/discover",
    "identities/acceptInvitation",
    "sts/assumeRoleWithWebIdentity",
    "privacy/submitPublic",
    "privacy/confirmPublic",
    "ssh/enrollHost",
    "ssh/syncHost",
    "ssh/trust",
    "ssh/revocationList",
    "verifiableCredentials/nonce",
    "verifiableCredentials/verify",
    "verifiableCredentials/issuerMetadata",
    "guests/redeem",
];

/// `tenantBoundPublicMethods`: public routes that act in one organization named by `tenantId`.
pub const TENANT_BOUND_PUBLIC_METHODS: &[&str] = &[
    "tenants/acceptInvitation",
    "identities/acceptInvitation",
    "sts/assumeRoleWithWebIdentity",
    "privacy/submitPublic",
    "privacy/confirmPublic",
    "ssh/trust",
    "ssh/revocationList",
    "guests/redeem",
];

/// `sessionCookieRoutes`: routes whose session becomes the browser's session.
pub const SESSION_COOKIE_ROUTES: &[&str] = &[
    "auth/signIn",
    "auth/verifyMfa",
    "auth/confirmMfa",
    "auth/recoverMfa",
    "auth/finishPasswordless",
    "auth/finishPasskeyAuthentication",
    "auth/finishPasskeyMfa",
    "auth/reauthenticate",
    "tenants/acceptInvitation",
    "identities/acceptInvitation",
    "guests/redeem",
    "links/switch",
];

/// Routes whose body gets the remembered device's token (`deviceTokenRoutes`).
const DEVICE_TOKEN_ROUTES: &[&str] = &["auth/signIn", "auth/finishPasswordless"];

/// The request body limit under the base path.
pub const BODY_LIMIT: usize = 65536;
/// The node transport's body limit outside the base path (protocol mounts).
pub const NODE_BODY_LIMIT_ELSEWHERE: usize = 2_097_152;

/// `ProtocolService`: a protocol handler mounted with `useProtocol` (OAuth/OIDC, SAML, SCIM, ...).
#[async_trait::async_trait]
pub trait ProtocolService: Send + Sync {
    /// The path the protocol is served under.
    fn base_path(&self) -> &str;
    /// Answers a request, or None to pass it on.
    async fn handler(&self, request: &HttpRequest) -> IamResult<Option<HttpResponse>>;
}

struct MountedProtocol(Arc<dyn ProtocolService>);

#[async_trait::async_trait]
impl ProtocolMount for MountedProtocol {
    async fn handle(&self, request: &HttpRequest) -> IamResult<Option<HttpResponse>> {
        self.0.handler(request).await
    }
}

/// Response headers every JSON answer carries: never cached, never sniffed, never leaking the URL as a referrer.
pub const HARDENED: [(&str, &str); 3] = [
    ("cache-control", "no-store"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
];

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// `headers.get(name)` of a fetch `Headers`: every value of the name joined with ", " (lossy for non-UTF-8 bytes).
fn header_joined(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<String> = headers
        .get_all(name)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// `requestIdOf(request)`: a caller-supplied correlation ID (`X-Request-Id`), kept only when short and plain.
fn request_id_of(headers: &HeaderMap) -> Option<String> {
    let value = header_joined(headers, "x-request-id")?;
    ((1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')))
    .then_some(value)
}

fn set_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(name, value);
    }
}

fn append_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.append(name, value);
    }
}

/// `Response.json(value, { status, headers })`.
pub fn json_response(status: u16, value: &Value, headers: &[(&str, &str)]) -> HttpResponse {
    let mut response = http::Response::new(Bytes::from(core_js::stringify(value)));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    set_header(response.headers_mut(), "content-type", "application/json");
    for (name, value) in headers {
        set_header(response.headers_mut(), name, value);
    }
    response
}

/// `withHeaders(response, extra)`.
fn with_headers(mut response: HttpResponse, extra: &[(String, String)]) -> HttpResponse {
    for (name, value) in extra {
        set_header(response.headers_mut(), name, value);
    }
    response
}

/// `publicResult(result)`: a top-level `session` object loses `tokenHash` and `uniqueKey`.
pub fn public_result(result: Value) -> Value {
    let Value::Object(mut map) = result else {
        return result;
    };
    if let Some(Value::Object(session)) = map.get_mut("session")
        && (session.contains_key("tokenHash") || session.contains_key("uniqueKey"))
    {
        session.shift_remove("tokenHash");
        session.shift_remove("uniqueKey");
    }
    Value::Object(map)
}

/// The `retryAfterMs` hint of an error (`typeof hint === "number" && hint > 0`): the member the error carries
/// (the auth service's `RATE_LIMITED` refusals, quota refusals).
fn retry_after_ms(error: &IamError) -> Option<f64> {
    details_of(error)
        .and_then(|details| details.retry_after_ms)
        .filter(|hint| *hint > 0.0)
}

/// `errorResponse(error)`.
pub fn error_response(error: &IamError) -> HttpResponse {
    let retry_after = retry_after_ms(error);
    let mut body = Map::new();
    body.insert("code".into(), Value::String(error.code.clone()));
    body.insert("message".into(), Value::String(error.message.clone()));
    if let Some(retry_after) = retry_after {
        body.insert("retryAfterMs".into(), crate::js::number(retry_after));
    }
    // A request for an organization another region serves learns where to go instead (`WRONG_REGION`).
    if error.code == "WRONG_REGION"
        && let Some(details) = details_of(error)
        && let Some(region) = details.region
    {
        body.insert("region".into(), Value::String(region));
        if let Some(location) = details.location {
            body.insert("location".into(), Value::String(location));
        }
    }
    let mut response = json_response(
        error.status,
        &json!({ "error": Value::Object(body) }),
        &HARDENED,
    );
    // Rate-limited callers learn when to come back (RFC 9110 Retry-After, in seconds).
    if let Some(retry_after) = retry_after {
        set_header(
            response.headers_mut(),
            "retry-after",
            &core_js::number_to_string((retry_after / 1000.0).ceil()),
        );
    }
    response
}

/// `encodeURIComponent(value)`.
pub fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let c = *byte as char;
        if c.is_ascii_alphanumeric() || "-_.!~*'()".contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `decodeURIComponent(value)`; None for a malformed sequence (a URIError in JavaScript).
pub fn decode_uri_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = value.get(index + 1..index + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The request's URL: its absolute target, or its path resolved against the deployment's base URL.
pub fn request_url(request: &HttpRequest, base_url: &url::Url) -> Option<url::Url> {
    let uri = request.uri();
    if uri.scheme().is_some() && uri.authority().is_some() {
        url::Url::parse(&uri.to_string()).ok()
    } else {
        base_url
            .join(uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"))
            .ok()
    }
}

/// The request head the client-info mapping reads (`clientFromRequest(options, request)`).
fn head_of(request: &HttpRequest) -> RequestHead {
    let (mut parts, ()) = http::Request::builder()
        .method(request.method().clone())
        .uri(request.uri().clone())
        .body(())
        .map(http::Request::into_parts)
        .unwrap_or_else(|_| http::Request::new(()).into_parts());
    parts.headers = request.headers().clone();
    parts
}

/// The request credential: its headers (a bearer header or the session cookie).
fn credential_of(headers: &HeaderMap) -> CredentialInput {
    CredentialInput {
        headers: Some(
            headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect(),
        ),
        token: None,
    }
}

// --- the authentication API -----------------------------------------------------------------------------------------

/// The arguments of an authentication method as the router calls it.
#[derive(Debug, Clone)]
pub enum AuthArgs {
    /// Public methods: the request body.
    Public(Value),
    /// Authenticated methods: the request credential and the body.
    Authenticated(CredentialInput, Value),
    /// `beginMfa`: a sign-in challenge or the request credential.
    BeginMfa(MfaCredential),
    /// `confirmMfa`.
    ConfirmMfa(ConfirmMfaInput),
}

/// `clientOf(headers)`: the client derived from a credential's headers.
pub type ClientOf = Arc<dyn Fn(&[(String, String)]) -> Option<SessionClientInfo> + Send + Sync>;

/// `createAuthApi(auth, observe, clientOf)`: end-user authentication operations, bound to the auth service; the
/// router decides which are public.
pub struct AuthApi {
    auth: AuthService,
    observe: Option<Observer>,
    client_of: Option<ClientOf>,
}

/// Every method of the authentication API, in the TypeScript order.
pub const AUTH_METHODS: &[&str] = &[
    "signUp",
    "signIn",
    "signOut",
    "getSession",
    "listSessions",
    "revokeSession",
    "revokeOtherSessions",
    "requestEmailVerification",
    "verifyEmail",
    "requestPasswordReset",
    "resetPassword",
    "changePassword",
    "reauthenticate",
    "requestEmailChange",
    "confirmEmailChange",
    "startPhoneVerification",
    "confirmPhoneVerification",
    "startPasswordless",
    "finishPasswordless",
    "beginMfa",
    "confirmMfa",
    "verifyMfa",
    "requestMfaCode",
    "recoverMfa",
    "beginPasskeyRegistration",
    "finishPasskeyRegistration",
    "beginPasskeyAuthentication",
    "finishPasskeyAuthentication",
    "beginPasskeyMfa",
    "finishPasskeyMfa",
    "listPasskeys",
    "deletePasskey",
    "renamePasskey",
    "regenerateRecoveryCodes",
    "disableMfa",
    "listTrustedDevices",
    "revokeTrustedDevice",
    "revokeTrustedDevices",
    "listSecurityEvents",
    "mfaStatus",
];

/// `createAuthApi(auth, observe?, clientOf?)`.
pub fn create_auth_api(
    auth: AuthService,
    observe: Option<Observer>,
    client_of: Option<ClientOf>,
) -> Arc<AuthApi> {
    Arc::new(AuthApi {
        auth,
        observe,
        client_of,
    })
}

fn to_json<T: Serialize>(value: T) -> IamResult<Value> {
    serde_json::to_value(value).map_err(|_| crate::js::internal_error())
}

/// Header pairs of a JSON `headers` member (`{ name: value }` or `[[name, value]]`).
fn json_headers(value: Option<&Value>) -> Option<Vec<(String, String)>> {
    match value? {
        Value::Object(map) => Some(
            map.iter()
                .filter_map(|(name, value)| {
                    value.as_str().map(|value| (name.clone(), value.to_owned()))
                })
                .collect(),
        ),
        Value::Array(items) => Some(
            items
                .iter()
                .filter_map(|pair| match pair.as_array().map(Vec::as_slice) {
                    Some([Value::String(name), Value::String(value)]) => {
                        Some((name.clone(), value.clone()))
                    }
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

/// `beginMfa`'s credential: a sign-in challenge from `body`, otherwise `credential` (the router's `dispatchAuth`).
fn begin_mfa_credential(
    body: &Map<String, Value>,
    credential: &CredentialInput,
) -> IamResult<MfaCredential> {
    Ok(match body.get("challenge") {
        Some(Value::String(challenge)) => MfaCredential::Challenge {
            tenant_id: text(body.get("tenantId"), "tenantId", 256)?,
            challenge: challenge.clone(),
        },
        _ => MfaCredential::Credential(credential.clone()),
    })
}

/// `confirmMfa`'s input: the login challenge named in `body.credential`, otherwise `credential`, with the code and
/// `rememberDevice` from `body` (the router's `dispatchAuth`).
fn confirm_mfa_input(
    body: &Map<String, Value>,
    credential: &CredentialInput,
) -> IamResult<ConfirmMfaInput> {
    let empty = Map::new();
    let challenge = if crate::js::truthy(body.get("credential")) {
        object(body.get("credential"))?
    } else {
        &empty
    };
    let mfa = match challenge.get("challenge") {
        Some(Value::String(token)) => MfaCredential::Challenge {
            tenant_id: text(challenge.get("tenantId"), "tenantId", 256)?,
            challenge: token.clone(),
        },
        _ => MfaCredential::Credential(credential.clone()),
    };
    Ok(ConfirmMfaInput {
        credential: mfa,
        code: text(body.get("code"), "code", 256)?,
        remember_device: body.get("rememberDevice") == Some(&Value::Bool(true)),
    })
}

/// A credential spelled as a JSON object (`{ headers?, token? }`), as in-process callers pass it.
fn json_credential(value: Option<&Value>) -> CredentialInput {
    CredentialInput {
        headers: json_headers(value.and_then(|value| value.get("headers"))),
        token: value
            .and_then(|value| value.get("token"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

fn endpoint_not_found() -> IamError {
    IamError::with_status("NOT_FOUND", "Endpoint not found", 404)
}

impl AuthApi {
    /// `Object.hasOwn(authApi, method)`.
    pub fn has(&self, method: &str) -> bool {
        AUTH_METHODS.contains(&method)
    }

    /// The auth service the API is bound to.
    pub fn service(&self) -> &AuthService {
        &self.auth
    }

    /// Calls a method: timed as an `auth` span named after it (the tenant from the first argument when present), with
    /// the client derived from the credential's headers when no client scope is set.
    pub async fn call(&self, method: &str, args: AuthArgs) -> IamResult<Value> {
        if !self.has(method) {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "Endpoint not found",
                404,
            ));
        }
        let headers = match &args {
            AuthArgs::Public(body) => json_headers(body.get("headers")),
            AuthArgs::Authenticated(credential, _) => credential.headers.clone(),
            AuthArgs::BeginMfa(MfaCredential::Credential(credential)) => credential.headers.clone(),
            AuthArgs::ConfirmMfa(input) => match &input.credential {
                MfaCredential::Credential(credential) => credential.headers.clone(),
                MfaCredential::Challenge { .. } => None,
            },
            AuthArgs::BeginMfa(MfaCredential::Challenge { .. }) => None,
        };
        let tenant_id = match &args {
            AuthArgs::Public(body) => body
                .get("tenantId")
                .and_then(Value::as_str)
                .map(str::to_owned),
            AuthArgs::BeginMfa(MfaCredential::Challenge { tenant_id, .. }) => {
                Some(tenant_id.clone())
            }
            _ => None,
        };
        let client = match (&self.client_of, headers) {
            (Some(client_of), Some(headers)) if self.auth.current_client().is_none() => {
                Some(client_of(&headers))
            }
            _ => None,
        };
        let call = async {
            match client {
                Some(client) => {
                    self.auth
                        .with_client(client, self.invoke(method, args))
                        .await
                }
                None => self.invoke(method, args).await,
            }
        };
        match self.observe.as_ref().filter(|observe| observe.enabled()) {
            Some(observe) => {
                observe
                    .span(
                        SpanKind::Auth,
                        method,
                        tenant_id.as_deref(),
                        call,
                        None,
                        None,
                    )
                    .await
            }
            None => call.await,
        }
    }

    async fn invoke(&self, method: &str, args: AuthArgs) -> IamResult<Value> {
        let auth = &self.auth;
        let empty = Value::Object(Map::new());
        match args {
            AuthArgs::BeginMfa(credential) => to_json(auth.begin_mfa(&credential).await?),
            AuthArgs::ConfirmMfa(input) => to_json(auth.confirm_mfa(&input).await?),
            AuthArgs::Public(body) => match method {
                "signUp" => to_json(auth.sign_up(&body).await?),
                "signIn" => to_json(auth.sign_in(&body).await?),
                "requestEmailVerification" => {
                    to_json(auth.request_email_verification(&body).await?)
                }
                "verifyEmail" => to_json(auth.verify_email(&body).await?),
                "requestPasswordReset" => to_json(auth.request_password_reset(&body).await?),
                "resetPassword" => to_json(auth.reset_password(&body).await?),
                "confirmEmailChange" => to_json(auth.confirm_email_change(&body).await?),
                "startPasswordless" => to_json(auth.start_passwordless(&body).await?),
                "finishPasswordless" => to_json(auth.finish_passwordless(&body).await?),
                "verifyMfa" => to_json(auth.verify_mfa(&body).await?),
                "requestMfaCode" => to_json(auth.request_mfa_code(&body).await?),
                "recoverMfa" => to_json(auth.recover_mfa(&body).await?),
                "beginPasskeyAuthentication" => {
                    to_json(auth.begin_passkey_authentication(&body).await?)
                }
                "finishPasskeyAuthentication" => {
                    to_json(auth.finish_passkey_authentication(&body).await?)
                }
                "beginPasskeyMfa" => to_json(auth.begin_passkey_mfa(&body).await?),
                "finishPasskeyMfa" => to_json(auth.finish_passkey_mfa(&body).await?),
                // In-process callers: `beginMfa(credential)` and `confirmMfa({ credential, code, rememberDevice })`.
                "beginMfa" => {
                    let map = body.as_object().cloned().unwrap_or_default();
                    let credential = begin_mfa_credential(&map, &json_credential(Some(&body)))?;
                    to_json(auth.begin_mfa(&credential).await?)
                }
                "confirmMfa" => {
                    let map = body.as_object().cloned().unwrap_or_default();
                    let input = confirm_mfa_input(&map, &json_credential(map.get("credential")))?;
                    to_json(auth.confirm_mfa(&input).await?)
                }
                // An authenticated method called with a body as its credential (in-process callers). The
                // authenticated arm handles every one of these itself, so this never bounces back here.
                _ if AUTHENTICATED_AUTH_METHODS.contains(&method) => {
                    let credential = json_credential(Some(&body));
                    Box::pin(self.invoke(method, AuthArgs::Authenticated(credential, empty))).await
                }
                _ => Err(endpoint_not_found()),
            },
            AuthArgs::Authenticated(credential, body) => {
                let c = &credential;
                match method {
                    "signOut" => to_json(auth.sign_out(c).await?),
                    "getSession" => to_json(auth.get_session(c).await?),
                    "listSessions" => to_json(auth.list_sessions(c).await?),
                    "revokeSession" => to_json(auth.revoke_session(c, &body).await?),
                    "revokeOtherSessions" => to_json(auth.revoke_other_sessions(c).await?),
                    "changePassword" => to_json(auth.change_password(c, &body).await?),
                    "requestEmailChange" => to_json(auth.request_email_change(c, &body).await?),
                    "beginPasskeyRegistration" => {
                        to_json(auth.begin_passkey_registration(c).await?)
                    }
                    "finishPasskeyRegistration" => {
                        to_json(auth.finish_passkey_registration(c, &body).await?)
                    }
                    "startPhoneVerification" => {
                        to_json(auth.start_phone_verification(c, &body).await?)
                    }
                    "confirmPhoneVerification" => {
                        to_json(auth.confirm_phone_verification(c, &body).await?)
                    }
                    "reauthenticate" => to_json(auth.reauthenticate(c, &body).await?),
                    "listPasskeys" => to_json(auth.list_passkeys(c).await?),
                    "deletePasskey" => to_json(auth.delete_passkey(c, &body).await?),
                    "renamePasskey" => to_json(auth.rename_passkey(c, &body).await?),
                    "regenerateRecoveryCodes" => to_json(auth.regenerate_recovery_codes(c).await?),
                    "disableMfa" => to_json(auth.disable_mfa(c).await?),
                    "listTrustedDevices" => to_json(auth.list_trusted_devices(c).await?),
                    "revokeTrustedDevice" => to_json(auth.revoke_trusted_device(c, &body).await?),
                    "revokeTrustedDevices" => to_json(auth.revoke_trusted_devices(c).await?),
                    "listSecurityEvents" => to_json(auth.list_security_events(c, &body).await?),
                    "mfaStatus" => to_json(auth.mfa_status(c).await?),
                    "beginMfa" => to_json(
                        auth.begin_mfa(&MfaCredential::Credential(credential.clone()))
                            .await?,
                    ),
                    "confirmMfa" => {
                        let map = body.as_object().cloned().unwrap_or_default();
                        to_json(auth.confirm_mfa(&confirm_mfa_input(&map, c)?).await?)
                    }
                    // A public method called with a credential (in-process callers): the body is its input. The
                    // public arm handles every one of these itself, so this never bounces back here.
                    _ if PUBLIC_AUTH_METHODS.contains(&method) => {
                        Box::pin(self.invoke(method, AuthArgs::Public(body))).await
                    }
                    _ => Err(endpoint_not_found()),
                }
            }
        }
    }
}

// --- the HTTP handler ---------------------------------------------------------------------------------------------

/// `createHttp`'s `extras`.
#[derive(Clone, Default)]
pub struct HttpExtras {
    pub metrics: Option<Arc<MetricsCollector>>,
    pub metrics_token: Option<String>,
    pub metrics_gauges: bool,
}

/// `createHttp(ctx, api, authApi, extras)`: the fetch and node transports over the provisioning API.
pub struct Http {
    ctx: Arc<ServerContext>,
    api: Arc<Api>,
    auth_api: Arc<AuthApi>,
    extras: HttpExtras,
    secure: bool,
    same_site_strict: bool,
}

/// `createHttp(ctx, api, authApi, extras)`. Refuses `http.cookieSameSite` other than lax or strict and a non-boolean
/// `http.persistentCookies` (INVALID_CONFIG).
pub fn create_http(
    ctx: &Arc<ServerContext>,
    api: Arc<Api>,
    auth_api: Arc<AuthApi>,
    extras: HttpExtras,
) -> IamResult<Arc<Http>> {
    let model = crate::options_value::options_value(&ctx.options);
    let http = model.get("http");
    let same_site = http
        .and_then(|http| http.get("cookieSameSite"))
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or(Value::String("lax".into()));
    if same_site != json!("lax") && same_site != json!("strict") {
        return Err(crate::js::invalid_config(
            "http.cookieSameSite must be lax or strict",
        ));
    }
    if let Some(persistent) = http.and_then(|http| http.get("persistentCookies"))
        && !persistent.is_boolean()
    {
        return Err(crate::js::invalid_config(
            "http.persistentCookies must be a boolean",
        ));
    }
    Ok(Arc::new(Http {
        secure: ctx.config.https(),
        same_site_strict: same_site == json!("strict"),
        ctx: ctx.clone(),
        api,
        auth_api,
        extras,
    }))
}

impl Http {
    /// `cookieNamed(name, raw, maxAge)`: without a Max-Age the cookie lasts for the browser session only.
    fn cookie_named(&self, name: &str, raw: &str, max_age: Option<f64>) -> String {
        format!(
            "{}{name}={}; HttpOnly; {}SameSite={}; Path=/{}",
            if self.secure { "__Host-" } else { "" },
            encode_uri_component(raw),
            if self.secure { "Secure; " } else { "" },
            if self.same_site_strict {
                "Strict"
            } else {
                "Lax"
            },
            match max_age {
                Some(max_age) => format!("; Max-Age={}", core_js::number_to_string(max_age)),
                None => String::new(),
            }
        )
    }

    fn cookie(&self, raw: &str, max_age: Option<f64>) -> String {
        self.cookie_named("better-iam.session", raw, max_age)
    }

    /// Seconds left until `expiresAt` on the clock that stamped it (`authentication.now`).
    fn seconds_until(&self, expires_at: f64) -> f64 {
        ((expires_at - self.ctx.now()) / 1000.0).floor().max(0.0)
    }

    fn session_cookie(&self, token: &str, expires_at: f64, persistent: bool) -> String {
        self.cookie(token, persistent.then(|| self.seconds_until(expires_at)))
    }

    /// `persistentFor(request)`: `X-Better-IAM-Persistent: 1|0` decides; otherwise the deployment default.
    fn persistent_for(&self, headers: &HeaderMap) -> bool {
        match header_joined(headers, "x-better-iam-persistent").as_deref() {
            Some("1") => true,
            Some("0") => false,
            _ => self
                .ctx
                .options
                .http
                .as_ref()
                .and_then(|http| http.persistent_cookies)
                .unwrap_or(true),
        }
    }

    fn device_cookie_name(&self) -> String {
        format!(
            "{}better-iam.device",
            if self.secure { "__Host-" } else { "" }
        )
    }

    fn device_cookie(&self, raw: &str, expires_at: f64) -> String {
        self.cookie_named(
            "better-iam.device",
            raw,
            Some(self.seconds_until(expires_at)),
        )
    }

    fn device_cookie_value(&self, headers: &HeaderMap) -> Option<String> {
        let name = format!("{}=", self.device_cookie_name());
        header_joined(headers, "cookie")?
            .split(';')
            .map(|part| core_js::trim(part).to_owned())
            .find(|part| part.starts_with(&name))
            .map(|part| part[name.len()..].to_owned())
    }

    /// Mounts a protocol service (`useProtocol`).
    pub fn use_protocol(&self, protocol: Arc<dyn ProtocolService>) {
        self.ctx
            .mounted_protocols
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Arc::new(MountedProtocol(protocol)));
    }

    /// `followableRedirect(value)`: a redirect a protocol asks for (`x-better-iam-redirect`, the SAML ACS's
    /// `afterSignIn`): a path on this site or a URL on this deployment's origin or one of `trustedOrigins`. Anything
    /// else is not followed.
    fn followable_redirect(&self, value: Option<&str>) -> Option<String> {
        let value = value.filter(|value| !value.is_empty())?;
        if value.encode_utf16().count() > 4096
            || value
                .chars()
                .any(|c| c <= '\u{1f}' || c == '\u{7f}' || c == '\\')
        {
            return None;
        }
        if value.starts_with('/') {
            return (!value.starts_with("//")).then(|| value.to_owned());
        }
        let target = url::Url::parse(value).ok()?;
        (target.username().is_empty()
            && target.password().is_none()
            && self
                .ctx
                .config
                .trusted_origins
                .contains(&crate::hosts::url_origin(&target)))
        .then(|| target.as_str().to_owned())
    }

    /// `protocolResponse(request)`: the first mount that answers; a JSON answer with `token` and `session.expiresAt`
    /// sets the session cookie, and a followable `x-better-iam-redirect` turns the answer into a 303 to that page.
    async fn protocol_response(&self, request: &HttpRequest) -> IamResult<Option<HttpResponse>> {
        let mounts: Vec<Arc<dyn ProtocolMount>> = self
            .ctx
            .mounted_protocols
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        for protocol in mounts {
            let Some(mut response) = protocol.handle(request).await? else {
                continue;
            };
            let hint = header_joined(response.headers(), "x-better-iam-redirect");
            let redirect = self.followable_redirect(hint.as_deref());
            if hint.is_some() {
                response.headers_mut().remove("x-better-iam-redirect");
            }
            let mut cookie = None;
            let json = response.status().is_success()
                && header_str(response.headers(), "content-type")
                    .is_some_and(|value| value.contains("application/json"));
            if json
                && let Ok(result) = core_js::parse(&String::from_utf8_lossy(response.body()))
                && let (Some(Value::String(token)), Some(expires_at)) = (
                    result.get("token"),
                    result
                        .get("session")
                        .and_then(|session| session.get("expiresAt"))
                        .and_then(Value::as_f64),
                )
            {
                cookie = Some(self.session_cookie(
                    token,
                    expires_at,
                    self.persistent_for(request.headers()),
                ));
            }
            // A browser sign-in that finishes on a page: 303 there, carrying the protocol's cookies and the session
            // cookie, never the body (the token stays out of the page).
            if let Some(redirect) = redirect {
                let mut headers = HeaderMap::new();
                append_header(&mut headers, "location", &redirect);
                append_header(&mut headers, "cache-control", "no-store");
                for value in response.headers().get_all("set-cookie") {
                    headers.append(http::header::SET_COOKIE, value.clone());
                }
                if let Some(cookie) = &cookie {
                    append_header(&mut headers, "set-cookie", cookie);
                }
                let mut redirected = HttpResponse::new(Bytes::new());
                *redirected.status_mut() = StatusCode::SEE_OTHER;
                *redirected.headers_mut() = headers;
                return Ok(Some(redirected));
            }
            if let Some(cookie) = &cookie {
                append_header(response.headers_mut(), "set-cookie", cookie);
            }
            return Ok(Some(response));
        }
        Ok(None)
    }

    /// `dispatch(path, body, credential)`.
    async fn dispatch(
        &self,
        path: &str,
        body: &Map<String, Value>,
        credential: &CredentialInput,
    ) -> IamResult<Value> {
        let operations = self.ctx.operations()?;
        if path == "authorize" {
            let resource = object(body.get("resource"))?;
            let request = AuthorizationRequest {
                credential: credential.clone(),
                tenant_id: text(body.get("tenantId"), "tenantId", 256)?,
                action: text(body.get("action"), "action", 256)?,
                resource: ResourceTarget {
                    kind: text(resource.get("type"), "resource type", 256)?,
                    id: text(resource.get("id"), "resource id", 256)?,
                },
            };
            return to_json(operations.authorize(&request).await?);
        }
        if path == "authorizeMany" {
            let tenant_id = text(body.get("tenantId"), "tenantId", 256)?;
            let checks = parse_checks(body.get("checks"))?;
            let results = operations
                .authorize_many(&BatchAuthorizationRequest {
                    credential: credential.clone(),
                    tenant_id,
                    checks,
                })
                .await?;
            let results: Vec<Value> = results
                .into_iter()
                .map(|result| {
                    json!({
                        "action": result.check.action,
                        "resource": { "type": result.check.resource.kind, "id": result.check.resource.id },
                        "allowed": result.allowed,
                        "reason": result.reason,
                    })
                })
                .collect();
            return Ok(json!({ "results": results }));
        }
        if path == "listAccessible" {
            let tenant_id = text(body.get("tenantId"), "tenantId", 256)?;
            let action = text(body.get("action"), "action", 256)?;
            let kind = text(body.get("type"), "resource type", 64)?;
            // `body.limit as number | undefined`: anything but a number fails `integer` in queryAccessible.
            let number = |key: &str| -> IamResult<Option<f64>> {
                match body.get(key) {
                    None | Some(Value::Null) => Ok(None),
                    Some(value) => match value.as_f64() {
                        Some(number) => Ok(Some(number)),
                        None => Err(crate::js::invalid_input(format!("Invalid {key}"))),
                    },
                }
            };
            let limit = number("limit")?;
            let offset = match number("offset") {
                Ok(offset) => offset,
                Err(error) => {
                    // `integer(limit)` runs before `integer(offset)`.
                    crate::validation::integer(
                        Some(&crate::js::number(limit.unwrap_or(100.0))),
                        "limit",
                        1.0,
                        1000.0,
                    )?;
                    return Err(error);
                }
            };
            let listed = operations
                .list_accessible(&AccessibleResourcesRequest {
                    credential: credential.clone(),
                    tenant_id,
                    action,
                    kind,
                    limit,
                    offset,
                })
                .await?;
            return Ok(
                json!({ "resources": listed.resources, "total": crate::js::number(listed.total) }),
            );
        }
        if let Some(rest) = path.strip_prefix("plugins/") {
            let mut parts = rest.split('/');
            let plugin_id = parts.next().map(|id| Value::String(id.to_owned()));
            let endpoint_path: Vec<&str> = parts.collect();
            let plugin_id = text(plugin_id.as_ref(), "pluginId", 256)?;
            let tenant_id = text(body.get("tenantId"), "tenantId", 256)?;
            return operations
                .call_plugin(
                    credential,
                    PluginCall {
                        plugin_id: Some(Value::String(plugin_id)),
                        path: Some(Value::String(endpoint_path.join("/"))),
                        tenant_id: Some(Value::String(tenant_id)),
                        input: Some(Value::Object(body.clone())),
                    },
                )
                .await;
        }
        let parts: Vec<&str> = path.split('/').collect();
        let not_found = || IamError::with_status("NOT_FOUND", "Endpoint not found", 404);
        let (Some(group), Some(method)) = (parts.first(), parts.get(1)) else {
            return Err(not_found());
        };
        if group.is_empty() || method.is_empty() || parts.len() > 2 {
            return Err(not_found());
        }
        if *group == "auth" {
            return self.dispatch_auth(method, body, credential).await;
        }
        if !ROUTE_GROUPS.contains(group) {
            return Err(not_found());
        }
        match dispatch_route(&self.api, path, body.clone(), credential).await {
            Some(result) => result,
            None => Err(not_found()),
        }
    }

    /// `dispatchAuth(method, body, credential)`.
    async fn dispatch_auth(
        &self,
        method: &str,
        body: &Map<String, Value>,
        credential: &CredentialInput,
    ) -> IamResult<Value> {
        if !self.auth_api.has(method) {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "Endpoint not found",
                404,
            ));
        }
        // MFA enrollment takes either a sign-in challenge from the body or the request's own credential.
        if method == "beginMfa" {
            let mfa = begin_mfa_credential(body, credential)?;
            return self.auth_api.call(method, AuthArgs::BeginMfa(mfa)).await;
        }
        if method == "confirmMfa" {
            let input = confirm_mfa_input(body, credential)?;
            return self
                .auth_api
                .call(method, AuthArgs::ConfirmMfa(input))
                .await;
        }
        if PUBLIC_AUTH_METHODS.contains(&method) {
            return self
                .auth_api
                .call(method, AuthArgs::Public(Value::Object(body.clone())))
                .await;
        }
        if AUTHENTICATED_AUTH_METHODS.contains(&method) {
            return self
                .auth_api
                .call(
                    method,
                    AuthArgs::Authenticated(credential.clone(), Value::Object(body.clone())),
                )
                .await;
        }
        Err(IamError::with_status(
            "NOT_FOUND",
            "Endpoint not found",
            404,
        ))
    }

    /// `routeName(path)`: the route when the route table (or a registered plugin endpoint) knows it, otherwise
    /// `(unknown)`.
    fn route_name(&self, path: &str) -> String {
        if matches!(path, "authorize" | "authorizeMany" | "listAccessible") {
            return path.to_owned();
        }
        let parts: Vec<&str> = path.split('/').collect();
        let group = parts.first().copied().unwrap_or("");
        let method = parts.get(1).copied().unwrap_or("");
        if group == "plugins" {
            let endpoint_path = parts
                .get(2..)
                .map(|rest| rest.join("/"))
                .unwrap_or_default();
            let endpoint_path = endpoint_path.strip_prefix('/').unwrap_or(&endpoint_path);
            let known = self
                .ctx
                .plugins
                .iter()
                .find(|plugin| plugin.id() == method)
                .is_some_and(|plugin| {
                    plugin.endpoints().iter().any(|candidate| {
                        candidate
                            .path()
                            .strip_prefix('/')
                            .unwrap_or(candidate.path())
                            == endpoint_path
                    })
                });
            return if known {
                format!("plugins/{method}/{endpoint_path}")
            } else {
                "(unknown)".into()
            };
        }
        if group.is_empty() || method.is_empty() || parts.len() > 2 {
            return "(unknown)".into();
        }
        if group == "auth" {
            return if self.auth_api.has(method)
                && (PUBLIC_AUTH_METHODS.contains(&method)
                    || AUTHENTICATED_AUTH_METHODS.contains(&method))
            {
                path.to_owned()
            } else {
                "(unknown)".into()
            };
        }
        if ROUTE_GROUPS.contains(&group) && is_route(path) {
            path.to_owned()
        } else {
            "(unknown)".into()
        }
    }

    /// `operational(pathname, request)`: `/health`, `/.well-known/jwks.json`, `/metrics`.
    async fn operational(&self, pathname: &str, request: &HttpRequest) -> IamResult<HttpResponse> {
        let base_path = &self.ctx.config.base_path;
        if pathname == format!("{base_path}/health") {
            let started = crate::utils::date_now();
            // A lookup by primary key costs the same however many tenants exist.
            return Ok(match self.ctx.store.get("tenants", "health-probe").await {
                Ok(_) => json_response(
                    200,
                    &json!({
                        "status": "ok",
                        "database": "ok",
                        "latencyMs": crate::js::number(crate::utils::date_now() - started),
                        "time": crate::js::number(started),
                    }),
                    &HARDENED,
                ),
                Err(_) => json_response(
                    503,
                    &json!({ "status": "unavailable", "database": "error", "time": crate::js::number(started) }),
                    &HARDENED,
                ),
            });
        }
        if pathname == format!("{base_path}/.well-known/jwks.json") {
            let Some(signer) = self.ctx.session_tokens() else {
                return Err(IamError::with_status(
                    "NOT_FOUND",
                    "Endpoint not found",
                    404,
                ));
            };
            return Ok(json_response(
                200,
                &json!({ "keys": to_json(signer.public_jwks())? }),
                &[
                    ("x-content-type-options", "nosniff"),
                    ("referrer-policy", "no-referrer"),
                    ("cache-control", "public, max-age=300"),
                    ("content-type", "application/jwk-set+json"),
                ],
            ));
        }
        if pathname == format!("{base_path}/metrics")
            && let (Some(metrics), Some(token)) = (&self.extras.metrics, &self.extras.metrics_token)
        {
            let provided = header_joined(request.headers(), "authorization").unwrap_or_default();
            let expected = format!("Bearer {token}");
            // Fixed-length digests: no length leak, no failure on non-ASCII headers.
            let digest = |value: &str| Sha256::digest(value.as_bytes());
            if !bool::from(digest(&provided).ct_eq(&digest(&expected))) {
                return Err(IamError::with_status(
                    "UNAUTHENTICATED",
                    "A metrics bearer token is required",
                    401,
                ));
            }
            let body = if self.extras.metrics_gauges {
                format!("{}{}", metrics.render(), self.storage_gauges().await?)
            } else {
                metrics.render()
            };
            let mut response = http::Response::new(Bytes::from(body));
            for (name, value) in HARDENED {
                set_header(response.headers_mut(), name, value);
            }
            set_header(
                response.headers_mut(),
                "content-type",
                "text/plain; version=0.0.4; charset=utf-8",
            );
            return Ok(response);
        }
        Err(IamError::with_status(
            "NOT_FOUND",
            "Endpoint not found",
            404,
        ))
    }

    /// `storageGauges()`: point-in-time gauges read from storage on each scrape.
    async fn storage_gauges(&self) -> IamResult<String> {
        let now = self.ctx.now();
        let everything = better_iam_core::Filter::new();
        let options = better_iam_core::FindOptions::default();
        let outbox: Vec<OutboxMessage> = self
            .ctx
            .store
            .find("outbox", &everything, &options)
            .await?
            .into_iter()
            .map(crate::port::decode)
            .collect::<IamResult<_>>()?;
        let sessions: Vec<Session> = self
            .ctx
            .store
            .find("sessions", &everything, &options)
            .await?
            .into_iter()
            .map(crate::port::decode)
            .collect::<IamResult<_>>()?;
        let pending = outbox
            .iter()
            .filter(|message| message.delivered_at.is_none() && message.failed_at.is_none())
            .count();
        let failed = outbox
            .iter()
            .filter(|message| message.failed_at.is_some())
            .count();
        let live: Vec<&Session> = sessions
            .iter()
            .filter(|session| session.expires_at > now)
            .collect();
        let count = |kind: SessionKind| live.iter().filter(|session| session.kind == kind).count();
        Ok([
            "# HELP better_iam_outbox_messages Delivery outbox messages by state.".to_owned(),
            "# TYPE better_iam_outbox_messages gauge".to_owned(),
            format!("better_iam_outbox_messages{{state=\"pending\"}} {pending}"),
            format!("better_iam_outbox_messages{{state=\"failed\"}} {failed}"),
            "# HELP better_iam_sessions_live Unexpired sessions by kind.".to_owned(),
            "# TYPE better_iam_sessions_live gauge".to_owned(),
            format!(
                "better_iam_sessions_live{{kind=\"user\"}} {}",
                count(SessionKind::User)
            ),
            format!(
                "better_iam_sessions_live{{kind=\"api-key\"}} {}",
                count(SessionKind::ApiKey)
            ),
            format!(
                "better_iam_sessions_live{{kind=\"role\"}} {}",
                count(SessionKind::Role)
            ),
            format!(
                "better_iam_sessions_live{{kind=\"session-token\"}} {}",
                count(SessionKind::SessionToken)
            ),
            format!(
                "better_iam_sessions_live{{kind=\"delegated\"}} {}",
                count(SessionKind::Delegated)
            ),
            String::new(),
        ]
        .join("\n"))
    }

    /// `handler(request)`: the fetch-style handler.
    pub async fn handler(&self, request: HttpRequest) -> HttpResponse {
        let request_id = request_id_of(request.headers());
        // Headers every IAM answer carries, errors and GET endpoints included.
        let mut answer_headers: Vec<(String, String)> = request_id
            .iter()
            .map(|id| ("x-request-id".to_owned(), id.clone()))
            .collect();
        match Box::pin(self.handle(&request, &request_id, &mut answer_headers)).await {
            Ok(response) => response,
            Err(error) => with_headers(error_response(&error), &answer_headers),
        }
    }

    async fn handle(
        &self,
        request: &HttpRequest,
        request_id: &Option<String>,
        answer_headers: &mut Vec<(String, String)>,
    ) -> IamResult<HttpResponse> {
        let ctx = &self.ctx;
        let auth = &ctx.auth;
        // Protocol mounts (the SAML ACS, OAuth login callbacks) issue sessions too: they run with the request's
        // client so network allowlists, blocks, and IP binding judge those sessions like any other sign-in.
        let client = client_from_request(ctx.options.http.as_ref(), &head_of(request));
        if let Some(mounted) = auth
            .with_client(client.clone(), self.protocol_response(request))
            .await?
        {
            let extra: Vec<(String, String)> = request_id
                .iter()
                .map(|id| ("x-request-id".to_owned(), id.clone()))
                .collect();
            return Ok(with_headers(mounted, &extra));
        }
        let url = request_url(request, &ctx.config.base_url).ok_or_else(|| {
            IamError::with_status("INVALID_REQUEST", "Invalid request target", 400)
        })?;
        let base_path = ctx.config.base_path.clone();
        let pathname = url.path().to_owned();
        if !pathname.starts_with(&format!("{base_path}/")) {
            return Ok(with_headers(
                json_response(
                    404,
                    &json!({ "error": { "code": "NOT_FOUND", "message": "Not found" } }),
                    &[],
                ),
                answer_headers,
            ));
        }
        let headers = request.headers();
        let origin = header_joined(headers, "origin");
        // `if (origin)`: an empty Origin header counts as none here and in the cookie check below.
        if let Some(origin) = origin.as_ref().filter(|origin| !origin.is_empty()) {
            // Organization addresses (`hosts`) are trusted like the deployment's own origins.
            if !ctx.config.trusted_origins.contains(origin)
                && !ctx.hosts()?.trusts_origin(origin).await
            {
                return Err(IamError::with_status(
                    "UNTRUSTED_ORIGIN",
                    "Origin is not trusted",
                    403,
                ));
            }
            answer_headers.push(("access-control-allow-origin".into(), origin.clone()));
            answer_headers.push(("access-control-allow-credentials".into(), "true".into()));
            answer_headers.push((
                "access-control-expose-headers".into(),
                "retry-after, x-request-id".into(),
            ));
            answer_headers.push(("vary".into(), "Origin".into()));
        }
        let method = request.method();
        if method == Method::OPTIONS {
            let mut response = http::Response::new(Bytes::new());
            *response.status_mut() = StatusCode::NO_CONTENT;
            set_header(
                response.headers_mut(),
                "access-control-allow-methods",
                "GET, POST, OPTIONS",
            );
            set_header(
                response.headers_mut(),
                "access-control-allow-headers",
                "content-type, x-better-iam, authorization, x-request-id, x-better-iam-persistent, x-better-iam-device",
            );
            return Ok(with_headers(response, answer_headers));
        }
        // Awaited so a refusal inside becomes an error response like every other failure here.
        if method == Method::GET {
            return Ok(with_headers(
                self.operational(&pathname, request).await?,
                answer_headers,
            ));
        }
        if method != Method::POST {
            return Err(IamError::with_status("METHOD_NOT_ALLOWED", "Use POST", 405));
        }
        let json_content = header_joined(headers, "content-type")
            .is_some_and(|value| value.to_lowercase().starts_with("application/json"));
        if !json_content || header_joined(headers, "x-better-iam").as_deref() != Some("1") {
            return Err(IamError::with_status(
                "CSRF_REJECTED",
                "JSON and X-Better-IAM header required",
                403,
            ));
        }
        if headers.contains_key("cookie") && origin.as_deref().is_none_or(str::is_empty) {
            return Err(IamError::with_status(
                "CSRF_REJECTED",
                "Cookie requests require Origin",
                403,
            ));
        }
        if request.body().len() > BODY_LIMIT {
            return Err(IamError::with_status(
                "PAYLOAD_TOO_LARGE",
                "Request body too large",
                413,
            ));
        }
        let raw = String::from_utf8_lossy(request.body()).into_owned();
        let mut body = match core_js::parse(&raw) {
            Ok(Value::Object(map)) => map,
            _ => return Err(IamError::new("INVALID_INPUT", "Invalid JSON")),
        };
        let path = pathname[base_path.len() + 1..].to_owned();
        let mut segments = path.split('/');
        let group = segments.next().unwrap_or("");
        let method_name = segments.next().unwrap_or("");
        let public_route = if group == "auth" {
            PUBLIC_AUTH_METHODS.contains(&method_name)
        } else {
            PUBLIC_API_METHODS.contains(&path.as_str())
        };
        // On an organization's own address the request is pinned to that organization.
        let pinned = ctx.hosts()?.request_tenant(request).await?;
        if public_route && (group == "auth" || TENANT_BOUND_PUBLIC_METHODS.contains(&path.as_str()))
        {
            // confirmMfa names its tenant inside `credential` (the login challenge), so that tenant is pinned too.
            let nested =
                path == "auth/confirmMfa" && body.get("credential").is_some_and(Value::is_object);
            let holders: Vec<bool> = if nested {
                vec![false, true]
            } else {
                vec![false]
            };
            for is_nested in holders {
                let body_tenant_absent = !body.contains_key("tenantId");
                if !is_nested && nested && body_tenant_absent {
                    continue;
                }
                let holder: &mut Map<String, Value> = if is_nested {
                    match body.get_mut("credential") {
                        Some(Value::Object(map)) => map,
                        _ => continue,
                    }
                } else {
                    &mut body
                };
                match &pinned {
                    Some(pinned) => match holder.get("tenantId") {
                        None => {
                            holder
                                .insert("tenantId".into(), Value::String(pinned.tenant_id.clone()));
                        }
                        Some(value) if value != &Value::String(pinned.tenant_id.clone()) => {
                            return Err(IamError::with_status(
                                "HOST_MISMATCH",
                                "This address belongs to another organization",
                                403,
                            ));
                        }
                        Some(_) => {}
                    },
                    None => {
                        if let Some(Value::String(tenant_id)) = holder.get("tenantId") {
                            let tenant_id = tenant_id.clone();
                            ctx.hosts()?.assert_tenant_served_here(&tenant_id).await?;
                        }
                    }
                }
            }
        }
        let tenant_id = body
            .get("tenantId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        // A bearer credential takes precedence over the cookie, so a bearer-authenticated request neither replaces
        // nor clears the browser's session cookie. Public routes use no request credential.
        let bearer = !public_route
            && header_joined(headers, "authorization").is_some_and(|value| !value.is_empty());
        // The IamError code of a refused request, reported on the span.
        let code: Mutex<Option<String>> = Mutex::new(None);
        let route = self.route_name(&path);
        let work = async {
            let result = async {
                if DEVICE_TOKEN_ROUTES.contains(&path.as_str())
                    && !body.contains_key("deviceToken")
                    && let Some(remembered) = self.device_cookie_value(headers)
                    && !remembered.is_empty()
                {
                    let decoded =
                        decode_uri_component(&remembered).ok_or_else(crate::js::internal_error)?;
                    body.insert("deviceToken".into(), Value::String(decoded));
                }
                let host = RequestHost {
                    origin: origin.clone(),
                    tenant_id: pinned.as_ref().map(|pinned| pinned.tenant_id.clone()),
                };
                auth.with_client(
                    client.clone(),
                    auth.with_request_host(
                        Some(host),
                        Box::pin(self.dispatch(&path, &body, &credential_of(headers))),
                    ),
                )
                .await
            }
            .await;
            let mut response_headers: Vec<(String, String)> = Vec::new();
            match result {
                Ok(result) => {
                    let mut response = json_response(
                        200,
                        &json!({ "data": public_result(result.clone()) }),
                        &HARDENED,
                    );
                    if !bearer
                        && SESSION_COOKIE_ROUTES.contains(&path.as_str())
                        && let (Some(Value::String(token)), Some(expires_at)) = (
                            result.get("token"),
                            result
                                .get("session")
                                .and_then(|session| session.get("expiresAt"))
                                .and_then(Value::as_f64),
                        )
                    {
                        let cookie =
                            self.session_cookie(token, expires_at, self.persistent_for(headers));
                        append_header(response.headers_mut(), "set-cookie", &cookie);
                    }
                    if let (Some(Value::String(device_token)), Some(device_expires_at)) = (
                        result.get("deviceToken"),
                        result.get("deviceExpiresAt").and_then(Value::as_f64),
                    ) {
                        let cookie = self.device_cookie(device_token, device_expires_at);
                        append_header(response.headers_mut(), "set-cookie", &cookie);
                    }
                    if path == "auth/signOut" && !bearer {
                        set_header(
                            response.headers_mut(),
                            "set-cookie",
                            &self.cookie("", Some(0.0)),
                        );
                    }
                    if path == "auth/revokeTrustedDevices" {
                        append_header(
                            response.headers_mut(),
                            "set-cookie",
                            &self.device_cookie("", 0.0),
                        );
                    }
                    response_headers.clear();
                    Ok::<_, IamError>(with_headers(response, answer_headers))
                }
                Err(error) => {
                    *code.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
                        Some(error.code.clone());
                    let mut response = error_response(&error);
                    // Signing out forgets the browser's cookie even when the sign-out is refused.
                    if path == "auth/signOut" && !bearer {
                        append_header(
                            response.headers_mut(),
                            "set-cookie",
                            &self.cookie("", Some(0.0)),
                        );
                    }
                    Ok(with_headers(response, answer_headers))
                }
            }
        };
        let classify = |response: &HttpResponse| {
            let status = response.status().as_u16();
            SpanOverride {
                status: Some(status),
                outcome: Some(if response.status().is_success() {
                    SpanOutcome::Ok
                } else if DENIED_STATUSES.contains(&status) {
                    SpanOutcome::Denied
                } else {
                    SpanOutcome::Error
                }),
                code: code
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone(),
            }
        };
        ctx.observe
            .span(
                SpanKind::Http,
                &route,
                tenant_id.as_deref(),
                work,
                Some(&classify),
                request_id.as_deref(),
            )
            .await
    }

    /// `nodeHandler(req, res)`: the node transport. `method`, `target` (the request-target as sent), headers and the
    /// whole body; the body limit is checked by the caller while reading ([`Http::body_limit`]).
    pub async fn node_handler(
        &self,
        method: Method,
        target: &str,
        headers: HeaderMap,
        body: Bytes,
    ) -> HttpResponse {
        match self.node_request(method, target, headers, body).await {
            Ok(response) => response,
            Err(error) => {
                let mut response = http::Response::new(Bytes::from(core_js::stringify(&json!({
                    "error": { "code": error.code, "message": error.message }
                }))));
                *response.status_mut() =
                    StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                set_header(response.headers_mut(), "content-type", "application/json");
                set_header(response.headers_mut(), "cache-control", "no-store");
                response
            }
        }
    }

    /// The node transport's URL of a request-target: with organization addresses the Host header decides the host,
    /// otherwise the deployment's own address.
    pub fn node_url(&self, target: &str, headers: &HeaderMap) -> IamResult<url::Url> {
        let invalid = || IamError::with_status("INVALID_REQUEST", "Invalid request target", 400);
        let base = &self.ctx.config.base_url;
        let host = if self.ctx.hosts()?.enabled() {
            normalize_host(header_str(headers, "host"))
        } else {
            None
        };
        let base = match host {
            Some(host) => {
                url::Url::parse(&format!("{}//{host}", format_args!("{}:", base.scheme())))
                    .map_err(|_| invalid())?
            }
            None => base.clone(),
        };
        base.join(if target.is_empty() { "/" } else { target })
            .map_err(|_| invalid())
    }

    /// The body limit of the node transport for a request-target: 64 KiB under the base path, 2 MiB elsewhere.
    pub fn body_limit(&self, url: &url::Url) -> usize {
        if url
            .path()
            .starts_with(&format!("{}/", self.ctx.config.base_path))
        {
            BODY_LIMIT
        } else {
            NODE_BODY_LIMIT_ELSEWHERE
        }
    }

    async fn node_request(
        &self,
        method: Method,
        target: &str,
        headers: HeaderMap,
        body: Bytes,
    ) -> IamResult<HttpResponse> {
        if matches!(method.as_str(), "TRACE" | "CONNECT" | "TRACK") {
            return Err(IamError::with_status(
                "METHOD_NOT_ALLOWED",
                "Method is not supported",
                405,
            ));
        }
        let url = self.node_url(target, &headers)?;
        let mut request = http::Request::builder()
            .method(method.clone())
            .uri(url.as_str())
            .body(if method == Method::GET || method == Method::HEAD {
                Bytes::new()
            } else {
                body
            })
            .map_err(|_| IamError::with_status("INVALID_REQUEST", "Invalid request target", 400))?;
        *request.headers_mut() = headers;
        Ok(self.handler(request).await)
    }
}

/// `tower::Service` over the fetch-style handler, for tower-based servers and middleware (axum and actix adapters live in
/// `better-iam-middleware`). It never fails: refusals are HTTP answers.
#[derive(Clone)]
pub struct HttpService(pub Arc<Http>);

impl tower_service::Service<HttpRequest> for HttpService {
    type Response = HttpResponse;
    type Error = std::convert::Infallible;
    type Future =
        futures::future::BoxFuture<'static, Result<HttpResponse, std::convert::Infallible>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: HttpRequest) -> Self::Future {
        let http = self.0.clone();
        Box::pin(async move { Ok(http.handler(request).await) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_components() {
        assert_eq!(encode_uri_component("a b/c=d"), "a%20b%2Fc%3Dd");
        assert_eq!(encode_uri_component("biam_ses_x-y.z~"), "biam_ses_x-y.z~");
        assert_eq!(decode_uri_component("a%20b").unwrap(), "a b");
        assert!(decode_uri_component("%E0%A4%A").is_none());
    }

    #[test]
    fn session_projection() {
        let result = public_result(
            json!({ "token": "t", "session": { "id": "s", "tokenHash": "h", "uniqueKey": "h" } }),
        );
        assert_eq!(result, json!({ "token": "t", "session": { "id": "s" } }));
        assert_eq!(public_result(json!([1])), json!([1]));
    }

    #[test]
    fn request_ids() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("abc-1:2.3_4"));
        assert_eq!(request_id_of(&headers).as_deref(), Some("abc-1:2.3_4"));
        headers.insert("x-request-id", HeaderValue::from_static("bad id"));
        assert_eq!(request_id_of(&headers), None);
    }

    #[test]
    fn route_sets_match_the_route_table() {
        let routes = crate::api::dispatch::ROUTE_PATHS;
        for path in PUBLIC_API_METHODS {
            assert!(routes.contains(path), "{path}");
        }
        for group in ROUTE_GROUPS {
            assert!(
                routes
                    .iter()
                    .any(|path| path.starts_with(&format!("{group}/"))),
                "{group}"
            );
        }
    }
}
