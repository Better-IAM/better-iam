//! The provider's protocol endpoints, ported from the `oidc-provider` actions the TypeScript configuration enables:
//! discovery, JWKS, authorization (with resume, PAR and interactions), token (authorization code, refresh token,
//! client credentials, device code, token exchange), userinfo, introspection, revocation, device flow, RP-initiated
//! logout, and dynamic registration behind the registration gate.

use std::sync::Arc;

use better_iam_auth::safe_fetch::{FetchBody, FetchRequest, RedirectMode};
use better_iam_core::{IamStoreExt, js, tenant_tree_active};
use bytes::Bytes;
use serde_json::{Map, Value, json};

use super::core::{
    CHALLENGE_OK_WINDOW, Client, DPOP_SIGNING_ALGS, ResourceServerInfo, epoch, filter_claims,
    grant as grant_ops, n, nanoid, num, s, scope_set,
};
use super::http::{
    CookieOptions, Out, Param, Params, RawParams, accepts_html, form_post, format_list,
    get_signed_cookie, html_safe, parse_query, pluralize, redirect_with_query, request_cookies,
    serialize_cookie,
};
use super::{
    ACCESS_TOKEN_TYPE, DevicePageInput, Inner, RegistrationContext, TOKEN_EXCHANGE,
    TokenExchangeRequest, text,
};
use crate::adapter::{hash, truthy};
use crate::errors::{OidcError, ProviderError, ProviderResult};
use crate::jose::{self, VerifyKey, VerifyOptions};
use crate::resource_server::{HttpRequest, HttpResponse};

const PARAM_LIST: [&str; 20] = [
    "acr_values",
    "claims_locales",
    "client_id",
    "code_challenge",
    "code_challenge_method",
    "display",
    "id_token_hint",
    "login_hint",
    "max_age",
    "nonce",
    "prompt",
    "redirect_uri",
    "registration",
    "request",
    "request_uri",
    "response_mode",
    "response_type",
    "scope",
    "state",
    "ui_locales",
];
const FRONTCHANNEL: [&str; 8] = [
    "web_message_uri",
    "response_type",
    "response_mode",
    "code_challenge_method",
    "code_challenge",
    "state",
    "redirect_uri",
    "prompt",
];
const PUSHED_REQUEST_URN: &str = "urn:ietf:params:oauth:request_uri:";
const DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const BODY_LIMIT: usize = 56 * 1024;

/// The routes of the provider (`routes`).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    Discovery,
    Jwks,
    Authorization,
    Resume(String),
    Userinfo,
    Token,
    Registration,
    ClientRead,
    Revocation,
    Introspection,
    EndSession,
    EndSessionConfirm,
    EndSessionSuccess,
    DeviceAuthorization,
    CodeVerification,
    DeviceResume(String),
    PushedAuthorizationRequest,
}

impl Route {
    fn name(&self) -> &'static str {
        match self {
            Route::Discovery => "discovery",
            Route::Jwks => "jwks",
            Route::Authorization => "authorization",
            Route::Resume(_) => "resume",
            Route::Userinfo => "userinfo",
            Route::Token => "token",
            Route::Registration => "registration",
            Route::ClientRead => "client",
            Route::Revocation => "revocation",
            Route::Introspection => "introspection",
            Route::EndSession => "end_session",
            Route::EndSessionConfirm => "end_session_confirm",
            Route::EndSessionSuccess => "end_session_success",
            Route::DeviceAuthorization => "device_authorization",
            Route::CodeVerification => "code_verification",
            Route::DeviceResume(_) => "device_resume",
            Route::PushedAuthorizationRequest => "pushed_authorization_request",
        }
    }
}

/// `routes` by name.
fn route_path(name: &str) -> &'static str {
    match name {
        "authorization" => "/auth",
        "resume" => "/auth",
        "userinfo" => "/me",
        "token" => "/token",
        "jwks" => "/jwks",
        "registration" | "client" => "/reg",
        "revocation" => "/token/revocation",
        "introspection" => "/token/introspection",
        "end_session" => "/session/end",
        "end_session_confirm" => "/session/end/confirm",
        "end_session_success" => "/session/end/success",
        "device_authorization" => "/device/auth",
        "code_verification" | "device_resume" => "/device",
        "pushed_authorization_request" => "/request",
        _ => "/",
    }
}

/// The router's case folding (`fold`).
fn fold(value: &str) -> String {
    value.to_uppercase()
}

fn percent_decode(value: &str) -> String {
    crate::client::percent_decode(value).unwrap_or_else(|| value.to_owned())
}

fn match_route(method: &str, path: &str) -> Option<Route> {
    let attempt = |path: &str| -> Option<Route> {
        let folded = fold(path);
        let get = method == "GET" || method == "HEAD";
        let post = method == "POST";
        let options = method == "OPTIONS";
        let found = match folded.as_str() {
            "/.WELL-KNOWN/OPENID-CONFIGURATION" | "/.WELL-KNOWN/OAUTH-AUTHORIZATION-SERVER"
                if get || options =>
            {
                Some(Route::Discovery)
            }
            "/JWKS" if get || options => Some(Route::Jwks),
            "/AUTH" if get => Some(Route::Authorization),
            "/ME" if get || post || options => Some(Route::Userinfo),
            "/TOKEN" if post || options => Some(Route::Token),
            "/REG" if post => Some(Route::Registration),
            "/TOKEN/REVOCATION" if post || options => Some(Route::Revocation),
            "/TOKEN/INTROSPECTION" if post || options => Some(Route::Introspection),
            "/SESSION/END/CONFIRM" if post => Some(Route::EndSessionConfirm),
            "/SESSION/END" if get => Some(Route::EndSession),
            "/SESSION/END/SUCCESS" if get => Some(Route::EndSessionSuccess),
            "/DEVICE/AUTH" if post || options => Some(Route::DeviceAuthorization),
            "/DEVICE" if get || post => Some(Route::CodeVerification),
            "/REQUEST" if post || options => Some(Route::PushedAuthorizationRequest),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
        let parts: Vec<&str> = path.split('/').collect();
        let folded_parts: Vec<String> = parts.iter().map(|part| fold(part)).collect();
        if parts.len() == 3 && !parts[2].is_empty() && get {
            match folded_parts[1].as_str() {
                "AUTH" => return Some(Route::Resume(percent_decode(parts[2]))),
                "REG" => return Some(Route::ClientRead),
                "DEVICE" => return Some(Route::DeviceResume(percent_decode(parts[2]))),
                _ => {}
            }
        }
        None
    };
    attempt(path).or_else(|| {
        if path.len() > 1 && path.ends_with('/') {
            attempt(&path[..path.len() - 1])
        } else {
            None
        }
    })
}

/// A loaded DPoP proof (`validateDpop` result).
#[derive(Debug, Clone)]
struct Dpop {
    thumbprint: String,
    jti: String,
}

/// The provider session (`Session`).
#[derive(Debug, Clone, Default)]
struct OpSession {
    payload: Map<String, Value>,
    new: bool,
    touched: bool,
    destroyed: bool,
    old_id: Option<String>,
}

impl OpSession {
    fn instantiate(payload: Option<Map<String, Value>>) -> Self {
        let new = payload.is_none();
        let mut payload = payload.unwrap_or_default();
        if !truthy(payload.get("uid")) {
            payload.insert("uid".into(), json!(nanoid(21)));
        }
        if !truthy(payload.get("jti")) {
            payload.insert("jti".into(), json!(nanoid(21)));
        }
        Self {
            payload,
            new,
            ..Self::default()
        }
    }
    fn id(&self) -> String {
        text(self.payload.get("jti"))
    }
    fn uid(&self) -> String {
        text(self.payload.get("uid"))
    }
    fn account_id(&self) -> Option<String> {
        s(&self.payload, "accountId")
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
    }
    fn authorization_for(
        &mut self,
        client_id: &str,
        create: bool,
    ) -> Option<&mut Map<String, Value>> {
        if !create
            && !self
                .payload
                .get("authorizations")
                .is_some_and(Value::is_object)
        {
            return None;
        }
        if !self
            .payload
            .get("authorizations")
            .is_some_and(Value::is_object)
        {
            self.payload.insert("authorizations".into(), json!({}));
            self.touched = true;
        }
        let authorizations = self
            .payload
            .get_mut("authorizations")
            .and_then(Value::as_object_mut)?;
        if !authorizations.contains_key(client_id) {
            if !create {
                return None;
            }
            authorizations.insert(client_id.to_owned(), json!({}));
            self.touched = true;
        }
        authorizations
            .get_mut(client_id)
            .and_then(Value::as_object_mut)
    }
    fn grant_id_for(&self, client_id: &str) -> Option<String> {
        self.payload
            .get("authorizations")
            .and_then(|value| value.get(client_id))
            .and_then(|value| value.get("grantId"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    }
    fn sid_for(&self, client_id: &str) -> Option<String> {
        self.payload
            .get("authorizations")
            .and_then(|value| value.get(client_id))
            .and_then(|value| value.get("sid"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    }
    fn set_authorization(&mut self, client_id: &str, key: &str, value: Value) {
        if let Some(authorization) = self.authorization_for(client_id, true) {
            authorization.insert(key.to_owned(), value);
        }
        self.touched = true;
    }
    fn ensure_client_container(&mut self, client_id: &str) {
        if self.sid_for(client_id).is_none() {
            self.set_authorization(client_id, "sid", json!(nanoid(21)));
        }
    }
    fn set(&mut self, key: &str, value: Value) {
        if value.is_null() {
            self.payload.shift_remove(key);
        } else {
            self.payload.insert(key.to_owned(), value);
        }
        self.touched = true;
    }
    fn reset_identifier(&mut self) {
        self.old_id = Some(self.id());
        self.payload.insert("jti".into(), json!(nanoid(21)));
        self.touched = true;
    }
    fn past(&self, max_age: f64) -> bool {
        match n(&self.payload, "loginTs") {
            Some(login) if login != 0.0 => epoch() - login > max_age,
            _ => true,
        }
    }
}

/// The authorization request state (`ctx.oidc` of the authorization endpoints).
#[derive(Debug, Clone, Default)]
struct Auth {
    params: Params,
    client: Option<Client>,
    grant: Option<Map<String, Value>>,
    account: Option<Account>,
    resource_servers: indexmap::IndexMap<String, ResourceServerInfo>,
    claims: Map<String, Value>,
    trusted: Vec<String>,
    result: Option<Map<String, Value>>,
    par: Option<Map<String, Value>>,
    interaction: Option<Map<String, Value>>,
    device_code: Option<Map<String, Value>>,
    id_token_hint: Option<Map<String, Value>>,
    redirect_uri_check_performed: bool,
    no_client: bool,
}

/// An account loaded by `findAccount`.
#[derive(Debug, Clone)]
pub(crate) struct Account {
    pub account_id: String,
    pub identity: Map<String, Value>,
}

/// The per-request context.
pub(crate) struct Ctx<'a> {
    inner: &'a Inner,
    request: &'a HttpRequest,
    method: String,
    path: String,
    route: Route,
    origin: String,
    mount: String,
    query: RawParams,
    body: Option<RawParams>,
    json_body: Option<Value>,
    raw_body: Bytes,
    cookies: Vec<(String, String)>,
    out: Out,
    set_cookies: Vec<String>,
    session: Option<OpSession>,
    dpop: Option<Option<Dpop>>,
    exchange: Option<(Map<String, Value>, f64)>,
    entities_client: Option<Client>,
}

fn header_value(request: &HttpRequest, name: &str) -> Option<String> {
    let values: Vec<&str> = request
        .headers()
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

fn content_type_is(request: &HttpRequest, wanted: &str) -> bool {
    header_value(request, "content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case(wanted)
    })
}

/// The request's origin as Koa sees it (`ctx.protocol://ctx.host`).
fn request_origin(inner: &Inner, request: &HttpRequest) -> String {
    let uri = request.uri();
    if let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) {
        return format!("{scheme}://{authority}");
    }
    let forwarded = |name: &str| {
        header_value(request, name).map(|value| {
            value
                .split(',')
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned()
        })
    };
    let scheme = if inner.config.trust_proxy {
        forwarded("x-forwarded-proto").unwrap_or_else(|| "http".to_owned())
    } else {
        "http".to_owned()
    };
    let host = if inner.config.trust_proxy {
        forwarded("x-forwarded-host").or_else(|| header_value(request, "host"))
    } else {
        header_value(request, "host")
    };
    match host {
        Some(host) => format!("{scheme}://{host}"),
        None => url::Url::parse(&inner.core.issuer)
            .map(|url| url.origin().ascii_serialization())
            .unwrap_or_default(),
    }
}

/// `nodeHandler(req, res)`.
pub(crate) async fn handle(inner: &Inner, request: &HttpRequest) -> HttpResponse {
    let base = inner.core.base_path.clone();
    let raw_path = request.uri().path().to_owned();
    let discovery_alias = format!("/.well-known/oauth-authorization-server{base}");
    let (path, mount) = if raw_path == discovery_alias {
        (
            "/.well-known/oauth-authorization-server".to_owned(),
            String::new(),
        )
    } else if !base.is_empty() && raw_path.starts_with(&format!("{base}/")) {
        (raw_path[base.len()..].to_owned(), base.clone())
    } else {
        (raw_path.clone(), String::new())
    };
    let method = request.method().as_str().to_owned();
    let query = parse_query(request.uri().query().unwrap_or_default());
    let mut ctx = Ctx {
        inner,
        request,
        method: method.clone(),
        path: path.clone(),
        route: Route::Discovery,
        origin: request_origin(inner, request),
        mount,
        query,
        body: None,
        json_body: None,
        raw_body: request.body().clone(),
        cookies: request_cookies(request),
        out: Out::default(),
        set_cookies: Vec::new(),
        session: None,
        dpop: None,
        exchange: None,
        entities_client: None,
    };
    // The registration gate runs before the router (`provider.use`).
    if inner.config.registration.is_some() {
        let decoded = percent_decode(&path);
        if method == "POST" && decoded.to_lowercase().trim_end_matches('/') == "/reg" {
            match registration_gate(&mut ctx).await {
                Ok(Some(context)) => {
                    return match match_route(&method, &path) {
                        Some(route) => {
                            ctx.route = route;
                            let key = inner.registration_scope;
                            better_iam_core::task_scope::run(
                                key,
                                Arc::new(context),
                                dispatch(&mut ctx),
                            )
                            .await;
                            finish(ctx)
                        }
                        None => finish(ctx),
                    };
                }
                Ok(None) => return finish(ctx),
                Err(error) => {
                    render_error_plain(&mut ctx, &error);
                    return finish(ctx);
                }
            }
        }
    }
    let Some(route) = match_route(&method, &path) else {
        return finish(ctx);
    };
    ctx.route = route;
    dispatch(&mut ctx).await;
    finish(ctx)
}

fn finish(ctx: Ctx<'_>) -> HttpResponse {
    let mut out = ctx.out;
    for cookie in ctx.set_cookies {
        out.append("set-cookie", cookie);
    }
    out.finish()
}

async fn dispatch(ctx: &mut Ctx<'_>) {
    let route = ctx.route.clone();
    match route {
        Route::Authorization | Route::Resume(_) => {
            let result = authorization_endpoint(ctx).await;
            if let Err(error) = result {
                authorization_error(ctx, error).await;
            }
            finalize_session(ctx).await;
        }
        _ => {
            let result = plain_endpoint(ctx).await;
            if let Err(error) = result {
                plain_error(ctx, error).await;
            }
            finalize_session(ctx).await;
        }
    }
}

async fn plain_endpoint(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    match ctx.route.clone() {
        Route::Discovery => {
            cors_open(ctx);
            if ctx.method == "OPTIONS" {
                return Ok(());
            }
            discovery(ctx);
            Ok(())
        }
        Route::Jwks => {
            cors_open(ctx);
            if ctx.method == "OPTIONS" {
                return Ok(());
            }
            ctx.out.json(&ctx.inner.core.keystore.public);
            ctx.out.content_type = Some("application/jwk-set+json; charset=utf-8".into());
            Ok(())
        }
        Route::Token => {
            if cors_client(ctx, true, true) {
                return Ok(());
            }
            token_endpoint(ctx).await
        }
        Route::Userinfo => {
            if cors_client(ctx, true, false) {
                return Ok(());
            }
            userinfo_endpoint(ctx).await
        }
        Route::Introspection => {
            if cors_client(ctx, false, false) {
                return Ok(());
            }
            introspection_endpoint(ctx).await
        }
        Route::Revocation => {
            if cors_client(ctx, false, false) {
                return Ok(());
            }
            revocation_endpoint(ctx).await
        }
        Route::PushedAuthorizationRequest => {
            if cors_client(ctx, true, true) {
                return Ok(());
            }
            par_endpoint(ctx).await
        }
        Route::DeviceAuthorization => {
            if cors_client(ctx, false, false) {
                return Ok(());
            }
            device_authorization_endpoint(ctx).await
        }
        Route::CodeVerification | Route::DeviceResume(_) => device_user_flow(ctx).await,
        Route::EndSession => end_session(ctx).await,
        Route::EndSessionConfirm => end_session_confirm(ctx).await,
        Route::EndSessionSuccess => end_session_success(ctx).await,
        Route::Registration => registration_endpoint(ctx).await,
        Route::ClientRead => {
            ctx.out.set("cache-control", "no-store");
            Err(OidcError::invalid_token("registration access token not found").into())
        }
        Route::Authorization | Route::Resume(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Context helpers

impl<'a> Ctx<'a> {
    fn core(&self) -> &super::core::Core {
        &self.inner.core
    }

    /// `ctx.oidc.urlFor(name, { uid })`.
    fn url_for(&self, name: &str, param: Option<&str>) -> String {
        let mut path = route_path(name).to_owned();
        if let Some(param) = param {
            let encoded: String = url::form_urlencoded::byte_serialize(param.as_bytes())
                .collect::<String>()
                .replace('+', "%20");
            path = format!("{path}/{encoded}");
        }
        let full = format!("{}{}{}", self.origin, self.mount, path);
        url::Url::parse(&full)
            .map(|url| url.to_string())
            .unwrap_or(full)
    }

    fn header(&self, name: &str) -> Option<String> {
        header_value(self.request, name)
    }

    /// `selectiveBody('application/x-www-form-urlencoded')` for POST requests.
    fn parse_form(&mut self) -> ProviderResult<()> {
        if self.method != "POST" || self.body.is_some() {
            return Ok(());
        }
        if content_type_is(self.request, "application/x-www-form-urlencoded") {
            if self.raw_body.len() > BODY_LIMIT {
                return Err(OidcError::invalid_request("failed to parse the request body").into());
            }
            let text = String::from_utf8_lossy(&self.raw_body).into_owned();
            self.body = Some(parse_query(&text));
        } else if self.header("content-type").is_some() {
            return Err(OidcError::invalid_request(format!(
                "only application/x-www-form-urlencoded content-type bodies are supported on {} {}",
                self.method, self.path
            ))
            .into());
        } else {
            self.body = Some(RawParams::new());
        }
        Ok(())
    }

    fn source(&self) -> RawParams {
        if self.method == "POST" {
            self.body.clone().unwrap_or_default()
        } else {
            self.query.clone()
        }
    }

    /// `assembleParams(allowList)`.
    fn params(&self, allow: &[&str]) -> Params {
        Params::new(allow, &self.source())
    }

    fn set_cookie(&mut self, name: &str, value: Option<&str>, options: &CookieOptions) {
        self.set_cookies
            .push(serialize_cookie(name, value, options));
        let signature_value =
            value.map(|value| self.core().keygrip.sign(&format!("{name}={value}")));
        self.set_cookies.push(serialize_cookie(
            &format!("{name}.sig"),
            signature_value.as_deref(),
            options,
        ));
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        get_signed_cookie(&self.cookies, &self.core().keygrip, name)
    }

    fn cookie_options(&self) -> CookieOptions {
        CookieOptions {
            http_only: true,
            secure: self.core().secure,
            same_site_lax: true,
            ..CookieOptions::default()
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// CORS

fn cors_open(ctx: &mut Ctx<'_>) {
    if ctx.out.has_prefix("access-control-") {
        return;
    }
    ctx.out.vary("Origin");
    let origin = ctx
        .header("origin")
        .filter(|origin| !origin.is_empty())
        .unwrap_or_else(|| "*".into());
    if ctx.method != "OPTIONS" {
        ctx.out.set("access-control-allow-origin", origin);
        return;
    }
    if ctx.header("access-control-request-method").is_none() {
        return;
    }
    ctx.out.set("access-control-allow-origin", origin);
    ctx.out.set("access-control-max-age", "3600");
    ctx.out.set("access-control-allow-methods", "GET");
    if let Some(headers) = ctx.header("access-control-request-headers") {
        ctx.out.set("access-control-allow-headers", headers);
    }
    ctx.out.status = Some(204);
}

/// Client-based CORS; true when the request was a preflight that is now answered.
fn cors_client(ctx: &mut Ctx<'_>, dpop: bool, userinfo_methods: bool) -> bool {
    ctx.out.vary("Origin");
    let origin = ctx
        .header("origin")
        .filter(|origin| !origin.is_empty())
        .unwrap_or_else(|| "*".into());
    let methods = if matches!(ctx.route, Route::Userinfo) {
        "GET,POST"
    } else {
        "POST"
    };
    let _ = userinfo_methods;
    if ctx.method == "OPTIONS" {
        if ctx.header("access-control-request-method").is_none() {
            return true;
        }
        ctx.out.set("access-control-allow-origin", origin);
        ctx.out.set("access-control-max-age", "3600");
        ctx.out.set("access-control-allow-methods", methods);
        if let Some(headers) = ctx.header("access-control-request-headers") {
            ctx.out.set("access-control-allow-headers", headers);
        }
        ctx.out.status = Some(204);
        return true;
    }
    ctx.out.set("access-control-allow-origin", origin);
    let mut expose = Vec::new();
    if dpop && ctx.core().dpop_nonces.is_some() {
        expose.push("DPoP-Nonce");
    }
    expose.push("WWW-Authenticate");
    ctx.out
        .set("access-control-expose-headers", expose.join(","));
    false
}

/// `checkClientCORS`: run when the client is known on a cross-origin request.
fn check_client_cors(ctx: &mut Ctx<'_>, client: &Client) -> ProviderResult<()> {
    let Some(origin) = ctx.header("origin").filter(|origin| !origin.is_empty()) else {
        return Ok(());
    };
    let allowed = client.strings("redirect_uris").iter().any(|uri| {
        url::Url::parse(uri).is_ok_and(|url| url.origin().ascii_serialization() == origin)
    });
    if !allowed {
        ctx.out.remove("access-control-allow-origin");
        return Err(OidcError::invalid_request(format!(
            "origin {origin} not allowed for client: {}",
            client.client_id()
        ))
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Errors

fn render_error_json(ctx: &mut Ctx<'_>, out: &Map<String, Value>) {
    // The configured `renderError`: JSON, with a generic description.
    let body = json!({
        "error": out.get("error").cloned().unwrap_or(Value::Null),
        "error_description": "The identity request could not be completed.",
    });
    ctx.out.json(&body);
}

fn render_error_plain(ctx: &mut Ctx<'_>, error: &ProviderError) {
    ctx.out.status = Some(error.status());
    let out = error.out(None);
    if accepts_html(ctx.request) {
        render_error_json(ctx, &out);
    } else {
        ctx.out.json(&Value::Object(out));
    }
}

/// `errorHandler(eventName)`.
async fn plain_error(ctx: &mut Ctx<'_>, error: ProviderError) {
    let error = match error {
        ProviderError::Oidc(mut oidc) => {
            // Client authentication failures with an Authorization header carry a Basic challenge.
            if oidc.status == 401
                && ctx.header("authorization").is_some()
                && matches!(
                    ctx.route,
                    Route::Token
                        | Route::Introspection
                        | Route::Revocation
                        | Route::PushedAuthorizationRequest
                        | Route::DeviceAuthorization
                )
                && oidc.class == "InvalidClientAuth"
            {
                append_www_authenticate(
                    &mut ctx.out,
                    "Basic",
                    &[
                        ("realm", Some(ctx.inner.core.issuer.clone())),
                        ("error", Some(oidc.error.clone())),
                        ("error_description", oidc.description.clone()),
                    ],
                );
            }
            if matches!(ctx.route, Route::Userinfo) {
                userinfo_www_authenticate(ctx, &mut oidc);
            }
            if matches!(ctx.route, Route::Registration) && oidc.status == 401 {
                append_www_authenticate(
                    &mut ctx.out,
                    "Bearer",
                    &[
                        ("realm", Some(ctx.inner.core.issuer.clone())),
                        ("error", Some(oidc.error.clone())),
                        ("error_description", oidc.description.clone()),
                        ("scope", oidc.scope.clone()),
                    ],
                );
            }
            ProviderError::Oidc(oidc)
        }
        other => other,
    };
    ctx.out.status = Some(error.status());
    let out = error.out(None);
    let user_input = matches!(ctx.route, Route::CodeVerification | Route::DeviceResume(_));
    if user_input && ctx.session.is_some() {
        let secret = hex(&rand::random::<[u8; 24]>());
        if let Some(session) = ctx.session.as_mut() {
            session.set("state", json!({ "secret": secret }));
        }
        let action = ctx.url_for("code_verification", None);
        let form = user_code_input_form(&action, &secret, None);
        if let Ok(page) = (ctx.inner.config.render_device_page)(DevicePageInput {
            kind: "input".into(),
            form,
            user_code: None,
            client_name: None,
        })
        .await
        {
            ctx.out.html(page);
        }
        return;
    }
    if accepts_html(ctx.request) {
        render_error_json(ctx, &out);
    } else {
        ctx.out.json(&Value::Object(out));
    }
}

fn append_www_authenticate(out: &mut Out, scheme: &str, fields: &[(&str, Option<String>)]) {
    let parameters: Vec<String> = fields
        .iter()
        .filter_map(|(key, value)| {
            value.as_ref().map(|value| {
                format!(
                    "{key}=\"{}\"",
                    value.replace('\\', "\\\\").replace('"', "\\\"")
                )
            })
        })
        .collect();
    out.append(
        "www-authenticate",
        format!("{scheme} {}", parameters.join(", ")),
    );
}

fn userinfo_www_authenticate(ctx: &mut Ctx<'_>, error: &mut OidcError) {
    if error.status >= 500 {
        return;
    }
    let algs = DPOP_SIGNING_ALGS.join(" ");
    let realm = ctx.inner.core.issuer.clone();
    if error.class == "NoAccessTokenProvided" {
        append_www_authenticate(
            &mut ctx.out,
            "Bearer",
            &[
                ("realm", Some(realm.clone())),
                ("scope", error.scope.clone()),
            ],
        );
        append_www_authenticate(
            &mut ctx.out,
            "DPoP",
            &[
                ("realm", Some(realm)),
                ("scope", error.scope.clone()),
                ("algs", Some(algs)),
            ],
        );
        return;
    }
    let mut scheme = "Bearer";
    let description = error.description.clone().unwrap_or_default();
    if description.to_lowercase().contains("dpop") || ctx.header("dpop").is_some() {
        scheme = "DPoP";
    }
    if error.class == "InvalidDpopProof" || error.class == "UseDpopNonce" {
        error.status = 401;
    }
    let mut fields = vec![
        ("realm", Some(realm)),
        ("error", Some(error.error.clone())),
        ("error_description", error.description.clone()),
        ("scope", error.scope.clone()),
    ];
    if scheme == "DPoP" {
        fields.push(("algs", Some(algs)));
    }
    append_www_authenticate(&mut ctx.out, scheme, &fields);
}

// ---------------------------------------------------------------------------------------------------------------
// Session

async fn load_session(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    if ctx.session.is_some() {
        return Ok(());
    }
    let cookie = ctx.get_cookie("_session");
    let mut session = None;
    if let Some(id) = &cookie {
        session = ctx
            .core()
            .find_model("Session", id, false)
            .await?
            .map(|payload| OpSession::instantiate(Some(payload)));
    }
    let session = match session {
        Some(session) => session,
        None if cookie.is_some() => OpSession::instantiate(Some(Map::new())),
        None => OpSession::instantiate(None),
    };
    ctx.session = Some(session);
    Ok(())
}

async fn finalize_session(ctx: &mut Ctx<'_>) {
    let Some(mut session) = ctx.session.take() else {
        return;
    };
    if (!session.new || session.touched) && !session.destroyed {
        let options = ctx.cookie_options();
        let id = session.id();
        let name_index = ctx.set_cookies.len();
        ctx.set_cookie("_session", Some(&id), &options);
        if let Some(old) = session.old_id.take() {
            let _ = ctx.core().adapter.model("Session").destroy(&old).await;
        }
        let mut payload = session.payload.clone();
        payload.shift_remove("exp");
        if ctx
            .core()
            .save_model("Session", &mut payload, 86400.0)
            .await
            .is_ok()
        {
            session.payload = payload;
            session.touched = false;
        }
        if session.payload.get("transient") != Some(&Value::Bool(true))
            && let Some(exp) = n(&session.payload, "exp")
        {
            let expires = super::http::serialize_cookie(
                "x",
                Some("x"),
                &CookieOptions {
                    expires: Some(exp * 1000.0),
                    ..CookieOptions::default()
                },
            );
            let suffix = expires
                .split("; ")
                .find(|part| part.starts_with("expires="))
                .map(str::to_owned);
            if let Some(suffix) = suffix {
                for cookie in ctx.set_cookies.iter_mut().skip(name_index) {
                    if (cookie.starts_with("_session=") || cookie.starts_with("_session.sig="))
                        && !cookie.contains("expires=Thu, 01 Jan 1970")
                    {
                        cookie.push_str(&format!("; {suffix}"));
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Accounts and claims

/// `findAccount(ctx, accountId)`.
pub(crate) async fn find_account(
    inner: &Inner,
    client: Option<&Client>,
    account_id: &str,
) -> ProviderResult<Option<Account>> {
    let store = inner.config.store.as_ref();
    if account_id.is_empty() {
        return Ok(None);
    }
    let Some(account) = store.get("identities", account_id).await? else {
        return Ok(None);
    };
    let tenant_id = s(&account, "tenantId").unwrap_or_default().to_owned();
    if s(&account, "status") != Some("active") || !tenant_tree_active(store, &tenant_id).await? {
        return Ok(None);
    }
    if let Some(client) = client {
        let row = store.get("oauthClients", &hash(client.client_id())).await?;
        if !row.is_some_and(|row| {
            !truthy(row.get("revoked")) && s(&row, "tenantId") == Some(tenant_id.as_str())
        }) {
            return Ok(None);
        }
        if let Some(allowed) = &inner.config.client_allowed
            && !allowed((
                text(account.get("id")),
                tenant_id.clone(),
                client.client_id().to_owned(),
            ))
            .await?
        {
            return Ok(None);
        }
    }
    Ok(Some(Account {
        account_id: account_id.to_owned(),
        identity: account,
    }))
}

/// `account.claims(use, scope)`.
async fn account_claims(
    inner: &Inner,
    account: &Account,
    scope: &str,
) -> ProviderResult<Map<String, Value>> {
    let identity = &account.identity;
    let mut base = Map::new();
    base.insert("sub".into(), json!(account.account_id));
    base.insert(
        "tenant_id".into(),
        identity.get("tenantId").cloned().unwrap_or(Value::Null),
    );
    for (claim, key) in [
        ("email", "email"),
        ("email_verified", "emailVerified"),
        ("name", "name"),
    ] {
        if let Some(value) = identity.get(key) {
            base.insert(claim.into(), value.clone());
        }
    }
    if !scope.split(' ').any(|value| value == "iam") {
        return Ok(base);
    }
    let identity_id = text(identity.get("id"));
    let tenant_id = text(identity.get("tenantId"));
    let (groups, roles) = match &inner.config.live_grants {
        Some(live) => {
            let live = live((identity_id.clone(), tenant_id.clone())).await?;
            (live.group_ids, live.role_ids)
        }
        None => {
            let store = inner.config.store.as_ref();
            let now = js::now_ms();
            let live = |record: &Map<String, Value>| {
                !record.get("expiresAt").is_some_and(Value::is_number)
                    || n(record, "expiresAt").is_some_and(|expires| expires > now)
            };
            let groups: Vec<String> = store
                .find(
                    "groupMembers",
                    &better_iam_core::Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("identityId", identity_id.clone()),
                    &better_iam_core::FindOptions::default(),
                )
                .await?
                .into_iter()
                .filter(|record| live(record))
                .map(|record| js_string(record.get("groupId")))
                .collect();
            let roles: Vec<String> = store
                .find(
                    "bindings",
                    &better_iam_core::Filter::new().eq("tenantId", tenant_id.clone()),
                    &better_iam_core::FindOptions::default(),
                )
                .await?
                .into_iter()
                .filter(|binding| {
                    live(binding)
                        && (!binding.get("startsAt").is_some_and(Value::is_number)
                            || n(binding, "startsAt").is_some_and(|start| start <= now))
                        && binding.get("eligible") != Some(&Value::Bool(true))
                        && binding.get("window").is_none()
                        && ((s(binding, "subjectType") == Some("identity")
                            && s(binding, "subjectId") == Some(identity_id.as_str()))
                            || (s(binding, "subjectType") == Some("group")
                                && groups.contains(&js_string(binding.get("subjectId")))))
                })
                .map(|binding| js_string(binding.get("roleId")))
                .collect();
            (groups, roles)
        }
    };
    let mut unique_roles: Vec<String> = Vec::new();
    for role in roles {
        if !unique_roles.contains(&role) {
            unique_roles.push(role);
        }
    }
    unique_roles.sort_by(|a, b| js::cmp_utf16(a, b));
    let mut sorted_groups = groups;
    sorted_groups.sort_by(|a, b| js::cmp_utf16(a, b));
    base.insert("roles".into(), json!(unique_roles));
    base.insert("groups".into(), json!(sorted_groups));
    base.insert(
        "attributes".into(),
        identity
            .get("attributes")
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    Ok(base)
}

fn js_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) => "null".into(),
        None => "undefined".into(),
        Some(Value::Number(number)) => js::number_to_string(number.as_f64().unwrap_or_default()),
        Some(other) => js::stringify(other),
    }
}

/// `getCtxAccountClaims(ctx, use, scope)`: the account's claims with `sub`.
async fn ctx_account_claims(
    inner: &Inner,
    account: &Account,
    scope: &str,
) -> ProviderResult<Map<String, Value>> {
    let mut claims = account_claims(inner, account, scope).await?;
    claims.insert("sub".into(), json!(account.account_id));
    Ok(claims)
}

/// `extraTokenClaims(ctx, token)`.
async fn extra_token_claims(
    inner: &Inner,
    token: &Map<String, Value>,
    exchange: Option<&Map<String, Value>>,
) -> ProviderResult<Map<String, Value>> {
    let row = match s(token, "clientId").filter(|id| !id.is_empty()) {
        Some(id) => inner.config.store.get("oauthClients", &hash(id)).await?,
        None => None,
    };
    let Some(row) = row else {
        return Ok(Map::new());
    };
    let for_client = !truthy(token.get("accountId"));
    let mut out = Map::new();
    out.insert(
        "tenant_id".into(),
        row.get("tenantId").cloned().unwrap_or(Value::Null),
    );
    if truthy(row.get("serviceAccountId")) && exchange.is_none() && for_client {
        out.insert("identity_id".into(), row["serviceAccountId"].clone());
    }
    if let Some(act) = exchange {
        out.insert("act".into(), Value::Object(act.clone()));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------------------------
// Tokens

/// An access or refresh token, code or grant under construction.
#[derive(Debug, Clone)]
struct Token {
    model: &'static str,
    payload: Map<String, Value>,
    resource_server: Option<ResourceServerInfo>,
    expires_in: Option<f64>,
}

impl Token {
    fn new(model: &'static str, client: Option<&Client>) -> Self {
        let mut payload = Map::new();
        if let Some(client) = client {
            payload.insert("clientId".into(), json!(client.client_id()));
        }
        Self {
            model,
            payload,
            resource_server: None,
            expires_in: None,
        }
    }
    fn set(&mut self, key: &str, value: Option<Value>) {
        match value.filter(|value| !value.is_null()) {
            Some(value) => {
                self.payload.insert(key.to_owned(), value);
            }
            None => {
                self.payload.shift_remove(key);
            }
        }
    }
    fn get(&self, key: &str) -> Option<&Value> {
        self.payload.get(key)
    }
    fn scope(&self) -> Option<String> {
        s(&self.payload, "scope").map(str::to_owned)
    }
    fn set_resource_server(&mut self, server: ResourceServerInfo) {
        self.payload.insert("aud".into(), json!(server.audience));
        self.resource_server = Some(server);
    }
    fn jkt(&self) -> Option<String> {
        s(&self.payload, "jkt").map(str::to_owned)
    }
    fn token_type(&self) -> &'static str {
        if self.jkt().is_some() {
            "DPoP"
        } else {
            "Bearer"
        }
    }
}

fn exchange_remaining(ctx: &Ctx<'_>) -> Option<f64> {
    ctx.exchange
        .as_ref()
        .map(|(_, remaining)| *remaining)
        .filter(|value| *value != 0.0)
}

/// `ttl[model](ctx, token, client)` as the TypeScript configuration sets it.
fn token_ttl(ctx: &Ctx<'_>, token: &Token, client: Option<&Client>) -> f64 {
    let client_ttl = |key: &str| client.and_then(|client| client.lifetime(key));
    let access = |token: &Token, with_exchange: bool| -> f64 {
        let mut ttl = token
            .resource_server
            .as_ref()
            .map(|server| server.access_token_ttl)
            .unwrap_or(900.0);
        if let Some(value) = client_ttl("access_token_ttl") {
            ttl = ttl.min(value);
        }
        if with_exchange && let Some(remaining) = exchange_remaining(ctx) {
            ttl = ttl.min(remaining);
        }
        ttl
    };
    match token.model {
        "AccessToken" => access(token, true),
        "ClientCredentials" => access(token, false),
        "AuthorizationCode" => 60.0,
        "DeviceCode" => 600.0,
        "Grant" => 30.0 * 86400.0,
        "RefreshToken" => client_ttl("refresh_token_ttl").unwrap_or(30.0 * 86400.0),
        _ => 600.0,
    }
}

/// `token.save()` for the token models; returns the token value (opaque `jti` or a signed JWT).
async fn save_token(
    ctx: &mut Ctx<'_>,
    token: &mut Token,
    client: Option<&Client>,
) -> ProviderResult<String> {
    let expiration = match token.expires_in {
        Some(value) => value,
        None => {
            let ttl = token_ttl(ctx, token, client);
            token.expires_in = Some(ttl);
            ttl
        }
    };
    let now = epoch();
    let jwt = matches!(token.model, "AccessToken" | "ClientCredentials")
        && token
            .resource_server
            .as_ref()
            .is_some_and(|server| server.access_token_format == "jwt");
    if !truthy(token.payload.get("jti")) {
        let jti = if jwt { nanoid(21) } else { nanoid(43) };
        token.payload.insert("jti".into(), json!(jti));
    }
    if matches!(token.model, "AccessToken" | "ClientCredentials") {
        token.payload.insert(
            "format".into(),
            json!(
                token
                    .resource_server
                    .as_ref()
                    .map(|server| server.access_token_format.clone())
                    .unwrap_or_else(|| "opaque".into())
            ),
        );
    }
    let ttl = match n(&token.payload, "exp") {
        Some(exp) => exp - now,
        None => expiration,
    };
    token.payload.insert("kind".into(), json!(token.model));
    if !truthy(token.payload.get("iat")) {
        token.payload.insert("iat".into(), num(now));
    }
    if !truthy(token.payload.get("exp")) {
        token.payload.insert("exp".into(), num(now + expiration));
    }
    if matches!(token.model, "AccessToken" | "ClientCredentials") {
        let exchange = ctx.exchange.as_ref().map(|(act, _)| act.clone());
        let extra = extra_token_claims(ctx.inner, &token.payload, exchange.as_ref()).await?;
        token.payload.insert("extra".into(), Value::Object(extra));
    }
    let jti = text(token.payload.get("jti"));
    if jwt {
        return sign_access_token(ctx, token, client);
    }
    let stored = super::core::stored_payload(&token.payload);
    ctx.core()
        .adapter
        .model(token.model)
        .upsert(&jti, &stored, Some(ttl))
        .await?;
    Ok(jti)
}

/// The JWT access token format (`formats/jwt.js`).
fn sign_access_token(
    ctx: &Ctx<'_>,
    token: &Token,
    client: Option<&Client>,
) -> ProviderResult<String> {
    let payload = &token.payload;
    let mut sub = s(payload, "accountId")
        .filter(|id| !id.is_empty())
        .map(str::to_owned);
    if sub.is_some() && client.map(Client::client_id) != s(payload, "clientId") {
        return Err(server_error("clientId and client mismatch"));
    }
    let client_id = payload.get("clientId").cloned().unwrap_or(Value::Null);
    let mut out = payload
        .get("extra")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    out.insert(
        "jti".into(),
        payload.get("jti").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "sub".into(),
        sub.take()
            .map(Value::String)
            .unwrap_or_else(|| client_id.clone()),
    );
    out.insert(
        "iat".into(),
        payload.get("iat").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "exp".into(),
        payload.get("exp").cloned().unwrap_or(Value::Null),
    );
    if let Some(scope) = payload.get("scope").filter(|scope| truthy(Some(scope))) {
        out.insert("scope".into(), scope.clone());
    }
    out.insert("client_id".into(), client_id);
    out.insert("iss".into(), json!(ctx.core().issuer));
    out.insert(
        "aud".into(),
        payload.get("aud").cloned().unwrap_or(Value::Null),
    );
    if let Some(jkt) = payload.get("jkt") {
        out.insert("cnf".into(), json!({ "jkt": jkt }));
    }
    if !truthy(out.get("aud")) {
        return Err(server_error(
            "JWT Access Tokens must contain an audience, for Access Tokens without audience (only usable at the userinfo_endpoint) use an opaque format",
        ));
    }
    out.retain(|_, value| !value.is_null());
    let key = ctx
        .core()
        .keystore
        .select("RS256")
        .ok_or_else(|| server_error("resolved Resource Server jwt configuration has no corresponding key in the provider's keystore"))?;
    let mut header = Map::new();
    header.insert("typ".into(), json!("at+jwt"));
    if let Some(kid) = &key.kid {
        header.insert("kid".into(), json!(kid));
    }
    jose::sign_jwt(&key.key, "RS256", header, &Value::Object(out))
        .map_err(|error| server_error(&error.to_string()))
}

fn server_error(message: &str) -> ProviderError {
    ProviderError::Iam(better_iam_core::IamError::with_status(
        "INTERNAL_ERROR",
        message,
        500,
    ))
}

/// `Model.find(value)` with the session binding of the token models (`checkSessionBinding`).
async fn find_token(
    ctx: &Ctx<'_>,
    model: &str,
    value: &str,
    ignore_expiration: bool,
    ignore_session_binding: bool,
) -> ProviderResult<Option<Map<String, Value>>> {
    let Some(token) = ctx
        .core()
        .find_model(model, value, ignore_expiration)
        .await?
    else {
        return Ok(None);
    };
    if ignore_session_binding || !truthy(token.get("expiresWithSession")) {
        return Ok(Some(token));
    }
    let Some(session) =
        find_session_by_uid(ctx, s(&token, "sessionUid").unwrap_or_default()).await?
    else {
        return Ok(None);
    };
    let session = OpSession::instantiate(Some(session));
    if session.account_id().as_deref() != s(&token, "accountId")
        || session
            .grant_id_for(s(&token, "clientId").unwrap_or_default())
            .as_deref()
            != s(&token, "grantId")
    {
        return Ok(None);
    }
    Ok(Some(token))
}

async fn find_session_by_uid(
    ctx: &Ctx<'_>,
    uid: &str,
) -> ProviderResult<Option<Map<String, Value>>> {
    if uid.is_empty() {
        return Ok(None);
    }
    let Some(stored) = ctx.core().adapter.model("Session").find_by_uid(uid).await? else {
        return Ok(None);
    };
    Ok(super::core::verify_stored("Session", stored, false))
}

/// `Grant.find(id)`.
pub(crate) async fn find_grant(
    inner: &Inner,
    id: &str,
) -> ProviderResult<Option<Map<String, Value>>> {
    inner.core.find_model("Grant", id, false).await
}

/// `grant.save()`.
pub(crate) async fn save_grant(
    inner: &Inner,
    grant: &mut Map<String, Value>,
) -> ProviderResult<String> {
    grant_ops::clean(grant);
    if let Some(Value::Object(rejected)) = grant.get_mut("rejected") {
        grant_ops::clean(rejected);
    }
    let now = epoch();
    let expiration = 30.0 * 86400.0;
    if !truthy(grant.get("jti")) {
        grant.insert("jti".into(), json!(nanoid(43)));
    }
    grant.insert("kind".into(), json!("Grant"));
    let ttl = match n(grant, "exp") {
        Some(exp) => exp - now,
        None => expiration,
    };
    if !truthy(grant.get("iat")) {
        grant.insert("iat".into(), num(now));
    }
    if !truthy(grant.get("exp")) {
        grant.insert("exp".into(), num(now + expiration));
    }
    let jti = text(grant.get("jti"));
    let stored = super::core::stored_payload(grant);
    inner
        .core
        .adapter
        .model("Grant")
        .upsert(&jti, &stored, Some(ttl))
        .await?;
    Ok(jti)
}

/// `revoke(ctx, grantId)`: everything issued under a grant.
async fn revoke_grant(
    ctx: &Ctx<'_>,
    grant_id: Option<&str>,
    revoke_grant: bool,
) -> ProviderResult<()> {
    let Some(grant_id) = grant_id.filter(|id| !id.is_empty()) else {
        return Ok(());
    };
    // Every model's `revokeByGrantId` reaches the same adapter operation, which also deletes the grant.
    let _ = revoke_grant;
    ctx.core()
        .adapter
        .model("AccessToken")
        .revoke_by_grant_id(grant_id)
        .await
}

// ---------------------------------------------------------------------------------------------------------------
// Discovery

fn discovery(ctx: &mut Ctx<'_>) {
    let core = ctx.core();
    let registration = ctx.inner.config.registration.is_some();
    let mut body = Map::new();
    body.insert(
        "authorization_endpoint".into(),
        json!(ctx.url_for("authorization", None)),
    );
    body.insert(
        "device_authorization_endpoint".into(),
        json!(ctx.url_for("device_authorization", None)),
    );
    body.insert("claims_parameter_supported".into(), json!(false));
    body.insert("claims_supported".into(), json!(core.claims.supported));
    body.insert("code_challenge_methods_supported".into(), json!(["S256"]));
    body.insert(
        "end_session_endpoint".into(),
        json!(ctx.url_for("end_session", None)),
    );
    body.insert("grant_types_supported".into(), json!(core.grant_types));
    body.insert("issuer".into(), json!(core.issuer));
    body.insert("jwks_uri".into(), json!(ctx.url_for("jwks", None)));
    if registration {
        body.insert(
            "registration_endpoint".into(),
            json!(ctx.url_for("registration", None)),
        );
    }
    body.insert(
        "authorization_response_iss_parameter_supported".into(),
        json!(true),
    );
    body.insert(
        "response_modes_supported".into(),
        json!(["form_post", "fragment", "query"]),
    );
    body.insert("response_types_supported".into(), json!(["code"]));
    body.insert("scopes_supported".into(), json!(core.scopes));
    body.insert("subject_types_supported".into(), json!(["public"]));
    body.insert(
        "token_endpoint_auth_methods_supported".into(),
        json!(super::core::CLIENT_AUTH_METHODS),
    );
    body.insert(
        "token_endpoint_auth_signing_alg_values_supported".into(),
        json!(super::core::CLIENT_AUTH_SIGNING_ALGS),
    );
    body.insert("token_endpoint".into(), json!(ctx.url_for("token", None)));
    body.insert(
        "id_token_signing_alg_values_supported".into(),
        json!(core.keystore.id_token_algs),
    );
    body.insert(
        "pushed_authorization_request_endpoint".into(),
        json!(ctx.url_for("pushed_authorization_request", None)),
    );
    if ctx.inner.config.require_pushed_authorization_requests {
        body.insert("require_pushed_authorization_requests".into(), json!(true));
    }
    body.insert("request_uri_parameter_supported".into(), json!(false));
    body.insert(
        "userinfo_endpoint".into(),
        json!(ctx.url_for("userinfo", None)),
    );
    body.insert(
        "introspection_endpoint".into(),
        json!(ctx.url_for("introspection", None)),
    );
    body.insert(
        "dpop_signing_alg_values_supported".into(),
        json!(DPOP_SIGNING_ALGS),
    );
    body.insert(
        "revocation_endpoint".into(),
        json!(ctx.url_for("revocation", None)),
    );
    body.insert("backchannel_logout_supported".into(), json!(true));
    body.insert("backchannel_logout_session_supported".into(), json!(true));
    body.insert("claim_types_supported".into(), json!(["normal"]));
    ctx.out.json(&Value::Object(body));
}

// ---------------------------------------------------------------------------------------------------------------
// Client authentication

fn auth_params() -> Vec<&'static str> {
    vec![
        "client_id",
        "client_secret",
        "client_assertion",
        "client_assertion_type",
    ]
}

fn is_valid_base64(input: &str) -> bool {
    let Some(captures) = regex::Regex::new(r"^([A-Za-z0-9+/]*)(={0,2})$")
        .expect("valid regex")
        .captures(input)
    else {
        return false;
    };
    let body = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
    let padding = captures.get(2).map(|m| m.as_str()).unwrap_or_default();
    if body.is_empty() {
        return false;
    }
    let remainder = body.len() % 4;
    if padding.is_empty() {
        return remainder != 1;
    }
    (body.len() + padding.len()).is_multiple_of(4) && padding.len() == 4 - remainder
}

fn decode_auth_token(token: &str) -> Option<String> {
    let decoded = crate::client::percent_decode(&token.replace('+', "%20"))?;
    if decoded.chars().any(|c| !(' '..='~').contains(&c)) {
        return None;
    }
    Some(decoded)
}

/// `clientAuth`: duplicates, then the authentication mechanism, then the registered method's check.
async fn authenticate_client(ctx: &mut Ctx<'_>, params: &mut Params) -> ProviderResult<Client> {
    let auth = auth_params();
    let dupes = params.reject_dupes(&[], Some(&auth));
    if !dupes.is_empty() {
        return Err(dupes_error(&dupes));
    }
    let authorization = ctx.header("authorization");
    let mechanisms = [
        authorization.is_some(),
        params.has("client_assertion"),
        params.has("client_secret"),
    ]
    .iter()
    .filter(|present| **present)
    .count();
    if mechanisms > 1 {
        return Err(OidcError::invalid_request(
            "client authentication must only be provided using one mechanism",
        )
        .into());
    }
    let mut client_id: Option<String> = None;
    let mut set_client_id = |value: String| -> ProviderResult<()> {
        if client_id
            .as_ref()
            .is_some_and(|existing| *existing != value)
        {
            return Err(OidcError::invalid_request("client_id mismatch").into());
        }
        client_id = Some(value);
        Ok(())
    };
    if let Some(id) = params.get("client_id") {
        set_client_id(id.to_owned())?;
    }
    let mut secret: Option<String> = None;
    let methods: Vec<&str>;
    if let Some(value) = params.get("client_secret") {
        secret = Some(value.to_owned());
        methods = vec!["client_secret_basic", "client_secret_post"];
    } else if let Some(header) = &authorization {
        let parts: Vec<&str> = header.split(' ').collect();
        if parts.len() != 2 || parts[0].to_lowercase() != "basic" {
            return Err(
                OidcError::invalid_request("invalid authorization header value format").into(),
            );
        }
        if !is_valid_base64(parts[1]) {
            return Err(
                OidcError::invalid_request("invalid authorization header value format").into(),
            );
        }
        let basic = String::from_utf8_lossy(&jose::b64_decode_lenient(parts[1])).into_owned();
        let Some(index) = basic.find(':') else {
            return Err(
                OidcError::invalid_request("invalid authorization header value format").into(),
            );
        };
        let (Some(id), Some(value)) = (
            decode_auth_token(&basic[..index]),
            decode_auth_token(&basic[index + 1..]),
        ) else {
            return Err(OidcError::invalid_request(
                "client_id and client_secret in the authorization header are not properly encoded",
            )
            .into());
        };
        set_client_id(id)?;
        if value.is_empty() {
            return Err(OidcError::invalid_request(
                "client_secret must be provided in the Authorization header",
            )
            .into());
        }
        secret = Some(value);
        methods = vec!["client_secret_basic", "client_secret_post"];
    } else if let Some(assertion) = params.get("client_assertion") {
        let sub = jose::decode(assertion)
            .map_err(|_| OidcError::invalid_request("invalid client_assertion format"))?
            .payload
            .get("sub")
            .filter(|sub| truthy(Some(sub)))
            .cloned();
        let Some(sub) = sub else {
            return Err(OidcError::invalid_client_auth(
                "sub (JWT subject) must be provided in the client_assertion JWT",
            )
            .into());
        };
        match params.get("client_assertion_type") {
            None => {
                return Err(
                    OidcError::invalid_request("client_assertion_type must be provided").into(),
                );
            }
            Some(kind) if kind != ASSERTION_TYPE => {
                return Err(OidcError::invalid_request(format!(
                    "client_assertion_type must have value {ASSERTION_TYPE}"
                ))
                .into());
            }
            _ => {}
        }
        set_client_id(js_string(Some(&sub)))?;
        methods = vec!["client_secret_jwt", "private_key_jwt"];
    } else {
        methods = vec!["none", "tls_client_auth", "self_signed_tls_client_auth"];
    }
    let Some(client_id) = client_id else {
        return Err(
            OidcError::invalid_request("no client authentication mechanism provided").into(),
        );
    };
    let Some(client) = ctx.core().find_client(&client_id).await? else {
        return Err(OidcError::invalid_client_auth("client not found").into());
    };
    ctx.entities_client = Some(client.clone());
    check_client_cors(ctx, &client)?;
    if !methods.contains(&client.auth_method()) {
        return Err(OidcError::invalid_client_auth(
            "the provided authentication mechanism does not match the registered client authentication method",
        )
        .into());
    }
    match client.auth_method() {
        "none" => {}
        "client_secret_basic" | "client_secret_post" => {
            client.check_secret_expiration(
                "could not authenticate the client - its client secret is expired",
            )?;
            if !client.compare_secret(secret.as_deref().unwrap_or_default()) {
                return Err(OidcError::invalid_client_auth("invalid secret provided").into());
            }
        }
        "client_secret_jwt" => {
            client.check_secret_expiration(
                "could not authenticate the client - its client secret used for the client_assertion is expired",
            )?;
            jwt_client_auth(ctx, &client, params, true).await?;
        }
        "private_key_jwt" => jwt_client_auth(ctx, &client, params, false).await?,
        _ => {
            return Err(
                OidcError::invalid_client_auth("client certificate was not provided").into(),
            );
        }
    }
    Ok(client)
}

/// `jwtClientAuth(ctx, keystore)`.
async fn jwt_client_auth(
    ctx: &mut Ctx<'_>,
    client: &Client,
    params: &Params,
    symmetric: bool,
) -> ProviderResult<()> {
    let assertion = params
        .get("client_assertion")
        .unwrap_or_default()
        .to_owned();
    let accepted = [
        ctx.core().issuer.clone(),
        ctx.url_for("token", None),
        ctx.url_for(ctx.route.name(), None),
    ];
    let decoded = jose::decode(&assertion)
        .map_err(|error| OidcError::invalid_client_auth(error.to_string()))?;
    let alg = text(decoded.header.get("alg"));
    let registered = s(&client.metadata, "token_endpoint_auth_signing_alg");
    let algorithm_ok = match registered {
        Some(registered) => alg == registered,
        None => super::core::CLIENT_AUTH_SIGNING_ALGS
            .iter()
            .filter(|candidate| candidate.starts_with("HS") == symmetric)
            .any(|candidate| *candidate == alg),
    };
    if !algorithm_ok {
        return Err(OidcError::invalid_client_auth("alg mismatch").into());
    }
    let payload = &decoded.payload;
    if !truthy(payload.get("exp")) {
        return Err(OidcError::invalid_client_auth(
            "expiration must be specified in the client_assertion JWT",
        )
        .into());
    }
    if !truthy(payload.get("jti")) {
        return Err(OidcError::invalid_client_auth(
            "unique jti (JWT ID) must be provided in the client_assertion JWT",
        )
        .into());
    }
    if !truthy(payload.get("iss")) {
        return Err(OidcError::invalid_client_auth(
            "iss (JWT issuer) must be provided in the client_assertion JWT",
        )
        .into());
    }
    if s(payload, "iss") != Some(client.client_id()) {
        return Err(
            OidcError::invalid_client_auth("iss (JWT issuer) must be the client_id").into(),
        );
    }
    match payload.get("aud") {
        None | Some(Value::Null) => {
            return Err(OidcError::invalid_client_auth(
                "aud (JWT audience) must be provided in the client_assertion JWT",
            )
            .into());
        }
        Some(Value::Array(values)) => {
            if !values.iter().any(|aud| {
                aud.as_str()
                    .is_some_and(|aud| accepted.iter().any(|a| a == aud))
            }) {
                return Err(OidcError::invalid_client_auth(
                    "list of audience (aud) must include the endpoint url, issuer identifier or token endpoint url",
                )
                .into());
            }
        }
        Some(aud) => {
            if !aud
                .as_str()
                .is_some_and(|aud| accepted.iter().any(|a| a == aud))
            {
                return Err(OidcError::invalid_client_auth(
                    "audience (aud) must equal the endpoint url, issuer identifier or token endpoint url",
                )
                .into());
            }
        }
    }
    let verified = if symmetric {
        let secret = s(&client.metadata, "client_secret").unwrap_or_default();
        verify_hmac(&decoded, &alg, secret.as_bytes())
    } else {
        let mut keys = ctx.core().client_keys(client, false).await?;
        let mut ok = keys.verify(&decoded).is_ok();
        if !ok && s(&client.metadata, "jwks_uri").is_some() {
            keys = ctx.core().client_keys(client, true).await?;
            ok = keys.verify(&decoded).is_ok();
        }
        ok
    };
    if !verified {
        return Err(OidcError::invalid_client_auth("signature verification failed").into());
    }
    let mut assert_options = VerifyOptions {
        clock_tolerance: 15.0,
        ..VerifyOptions::default()
    };
    assert_options.algorithms = Some(vec![alg.clone()]);
    assert_payload(payload, 15.0, false).map_err(OidcError::invalid_client_auth)?;
    let exp = n(payload, "exp").unwrap_or_default();
    let unique = replay_unique(
        ctx,
        &text(payload.get("iss")),
        &js_string(payload.get("jti")),
        exp + 15.0,
    )
    .await?;
    if !unique {
        return Err(OidcError::invalid_client_auth(
            "client assertion tokens must only be used once",
        )
        .into());
    }
    Ok(())
}

fn verify_hmac(decoded: &jose::Decoded, alg: &str, key: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    let expected = match alg {
        "HS256" => Hmac::<sha2::Sha256>::new_from_slice(key).map(|mut mac| {
            mac.update(decoded.signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }),
        "HS384" => Hmac::<sha2::Sha384>::new_from_slice(key).map(|mut mac| {
            mac.update(decoded.signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }),
        "HS512" => Hmac::<sha2::Sha512>::new_from_slice(key).map(|mut mac| {
            mac.update(decoded.signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }),
        _ => return false,
    };
    expected.is_ok_and(|expected| {
        use subtle::ConstantTimeEq;
        expected.len() == decoded.signature.len() && bool::from(expected.ct_eq(&decoded.signature))
    })
}

/// `assertPayload(payload, { clockTolerance, ignoreExpiration })`.
fn assert_payload(
    payload: &Map<String, Value>,
    tolerance: f64,
    ignore_expiration: bool,
) -> Result<(), String> {
    let now = epoch();
    if let Some(nbf) = payload.get("nbf") {
        let nbf = nbf.as_f64().ok_or("invalid nbf value")?;
        if nbf > now + tolerance {
            return Err("jwt not active yet".into());
        }
    }
    if let Some(iat) = payload.get("iat") {
        let iat = iat.as_f64().ok_or("invalid iat value")?;
        if payload.get("exp").is_none() && iat > now + tolerance {
            return Err("jwt issued in the future".into());
        }
    }
    if let Some(exp) = payload.get("exp")
        && !ignore_expiration
    {
        let exp = exp.as_f64().ok_or("invalid exp value")?;
        if now - tolerance >= exp {
            return Err("jwt expired".into());
        }
    }
    if payload.get("jti").is_some_and(|jti| !jti.is_string()) {
        return Err("invalid jti value".into());
    }
    if payload.get("iss").is_some_and(|iss| !iss.is_string()) {
        return Err("invalid iss value".into());
    }
    if let Some(aud) = payload.get("aud")
        && !aud.is_string()
        && !aud
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
    {
        return Err("invalid aud value".into());
    }
    Ok(())
}

/// `ReplayDetection.unique(iss, jti, exp)`.
async fn replay_unique(ctx: &Ctx<'_>, iss: &str, jti: &str, exp: f64) -> ProviderResult<bool> {
    let id = jose::sha256_b64url(&format!("{iss}{jti}"));
    if ctx
        .core()
        .find_model("ReplayDetection", &id, false)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    let mut payload = Map::new();
    payload.insert("jti".into(), json!(id));
    payload.insert("iss".into(), json!(iss));
    ctx.core()
        .save_model("ReplayDetection", &mut payload, exp - epoch())
        .await?;
    Ok(true)
}

fn dupes_error(dupes: &[String]) -> ProviderError {
    OidcError::invalid_request(format!(
        "{} {} must not be provided twice",
        format_list(dupes, false),
        pluralize("parameter", dupes.len())
    ))
    .into()
}

fn presence(params: &Params, required: &[&str]) -> ProviderResult<()> {
    let missing: Vec<String> = required
        .iter()
        .filter(|name| !params.has(name))
        .map(|name| (*name).to_owned())
        .collect();
    if !missing.is_empty() {
        return Err(OidcError::invalid_request(format!(
            "missing required {} {}",
            pluralize("parameter", missing.len()),
            format_list(&missing, false)
        ))
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// DPoP

/// `validateDpop(ctx, accessToken?)`.
async fn validate_dpop(
    ctx: &mut Ctx<'_>,
    access_token: Option<&str>,
) -> ProviderResult<Option<Dpop>> {
    if let Some(memo) = &ctx.dpop {
        return Ok(memo.clone());
    }
    let Some(proof) = ctx.header("dpop").filter(|proof| !proof.is_empty()) else {
        ctx.dpop = Some(None);
        return Ok(None);
    };
    let next_nonce = ctx
        .core()
        .dpop_nonces
        .as_ref()
        .map(|nonces| nonces.next_challenge());
    let options = VerifyOptions {
        typ: Some("dpop+jwt".into()),
        algorithms: Some(
            DPOP_SIGNING_ALGS
                .iter()
                .map(|alg| (*alg).to_owned())
                .collect(),
        ),
        current_date: Some(epoch()),
        clock_tolerance: f64::INFINITY,
        ..VerifyOptions::default()
    };
    let decoded = match jose::verify_jwt(&proof, VerifyKey::Embedded, &options) {
        Ok(decoded) => decoded,
        Err(_) => return Err(OidcError::invalid_dpop_proof("invalid DPoP key binding").into()),
    };
    let payload = &decoded.payload;
    if !payload
        .get("iat")
        .is_some_and(|iat| iat.as_f64().is_some_and(|iat| iat != 0.0))
    {
        return Err(
            OidcError::invalid_dpop_proof("DPoP proof must have a iat number property").into(),
        );
    }
    if !payload
        .get("jti")
        .is_some_and(|jti| jti.as_str().is_some_and(|jti| !jti.is_empty()))
    {
        return Err(
            OidcError::invalid_dpop_proof("DPoP proof must have a jti string property").into(),
        );
    }
    if payload.get("nonce").is_some_and(|nonce| !nonce.is_string()) {
        return Err(OidcError::invalid_dpop_proof("DPoP proof nonce must be a string").into());
    }
    let nonce = s(payload, "nonce")
        .filter(|nonce| !nonce.is_empty())
        .map(str::to_owned);
    if nonce.is_none() {
        let diff = (epoch() - n(payload, "iat").unwrap_or_default()).abs();
        if diff > CHALLENGE_OK_WINDOW {
            if let Some(next) = &next_nonce {
                ctx.out.set("dpop-nonce", next.clone());
                return Err(OidcError::use_dpop_nonce(
                    "DPoP proof iat is not recent enough, use a DPoP nonce instead",
                )
                .into());
            }
            return Err(
                OidcError::invalid_dpop_proof("DPoP proof iat is not recent enough").into(),
            );
        }
    } else if ctx.core().dpop_nonces.is_none() {
        return Err(OidcError::invalid_dpop_proof("DPoP nonces are not supported").into());
    }
    if s(payload, "htm") != Some(ctx.method.as_str()) {
        return Err(OidcError::invalid_dpop_proof("DPoP proof htm mismatch").into());
    }
    let expected = ctx.url_for(ctx.route.name(), None);
    let htu = s(payload, "htu")
        .and_then(|htu| url::Url::parse(htu).ok())
        .map(|mut url| {
            url.set_fragment(None);
            url.set_query(None);
            url.to_string()
        });
    if htu.as_deref() != Some(expected.as_str()) {
        return Err(OidcError::invalid_dpop_proof("DPoP proof htu mismatch").into());
    }
    if let Some(token) = access_token
        && s(payload, "ath") != Some(jose::sha256_b64url(token).as_str())
    {
        return Err(OidcError::invalid_dpop_proof("DPoP proof ath mismatch").into());
    }
    if let (Some(nonce), Some(nonces)) = (&nonce, &ctx.core().dpop_nonces)
        && !nonces.check_challenge(nonce)
    {
        if let Some(next) = &next_nonce {
            ctx.out.set("dpop-nonce", next.clone());
        }
        return Err(OidcError::use_dpop_nonce("invalid nonce in DPoP proof").into());
    }
    if let Some(next) = &next_nonce
        && nonce.as_deref() != Some(next.as_str())
    {
        ctx.out.set("dpop-nonce", next.clone());
    }
    let jwk = decoded
        .header
        .get("jwk")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let thumbprint = jose::jwk_thumbprint(&jwk)
        .map_err(|_| OidcError::invalid_dpop_proof("invalid DPoP key binding"))?;
    let result = Dpop {
        thumbprint,
        jti: text(payload.get("jti")),
    };
    ctx.dpop = Some(Some(result.clone()));
    Ok(Some(result))
}

/// `checkDpopReplay(ctx, dPoP, clientId, ErrorClass)`.
async fn check_dpop_replay(
    ctx: &Ctx<'_>,
    dpop: Option<&Dpop>,
    client_id: &str,
    error: fn(&str) -> OidcError,
) -> ProviderResult<()> {
    let Some(dpop) = dpop else {
        return Ok(());
    };
    if !replay_unique(ctx, client_id, &dpop.jti, epoch() + CHALLENGE_OK_WINDOW).await? {
        return Err(error("DPoP proof JWT Replay detected").into());
    }
    Ok(())
}

fn grant_error(message: &str) -> OidcError {
    OidcError::invalid_grant(message)
}
fn request_error(message: &str) -> OidcError {
    OidcError::invalid_request(message)
}
fn token_error(message: &str) -> OidcError {
    OidcError::invalid_token(message)
}

// ---------------------------------------------------------------------------------------------------------------
// Authorization endpoint

fn authorization_allow_list(route: &Route) -> Vec<&'static str> {
    let mut allow: Vec<&'static str> = PARAM_LIST.to_vec();
    allow.push("resource");
    let non_frontchannel = matches!(
        route,
        Route::DeviceAuthorization | Route::CodeVerification | Route::DeviceResume(_)
    );
    if non_frontchannel {
        allow.retain(|param| !FRONTCHANNEL.contains(param));
    }
    if matches!(
        route,
        Route::Authorization | Route::Resume(_) | Route::PushedAuthorizationRequest
    ) {
        allow.push("dpop_jkt");
    }
    allow
}

fn prompts(params: &Params) -> Vec<String> {
    params
        .get("prompt")
        .map(|prompt| prompt.split(' ').map(str::to_owned).collect::<Vec<_>>())
        .map(|values| {
            let mut unique: Vec<String> = Vec::new();
            for value in values {
                if !unique.contains(&value) {
                    unique.push(value);
                }
            }
            unique
        })
        .unwrap_or_default()
}

fn request_scopes(params: &Params) -> Vec<String> {
    scope_set(params.get("scope"))
}

fn request_oidc_scopes(inner: &Inner, params: &Params) -> Vec<String> {
    params
        .get("scope")
        .map(|scope| {
            let mut out: Vec<String> = Vec::new();
            for value in scope.split(' ') {
                if inner.core.scopes.iter().any(|known| known == value)
                    && !out.iter().any(|existing| existing == value)
                {
                    out.push(value.to_owned());
                }
            }
            out
        })
        .unwrap_or_default()
}

fn is_valid_scope(scope: Option<&str>) -> bool {
    match scope {
        None => true,
        Some(scope) => {
            regex::Regex::new(r"^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$")
                .expect("valid regex")
                .is_match(scope)
        }
    }
}

fn check_format(input: &str, param: &str) -> ProviderResult<()> {
    if input.len() < 43 {
        return Err(OidcError::invalid_request(format!(
            "{param} must be a string with a minimum length of 43 characters"
        ))
        .into());
    }
    if input.len() > 128 {
        return Err(OidcError::invalid_request(format!(
            "{param} must be a string with a maximum length of 128 characters"
        ))
        .into());
    }
    if input
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || "_.-~".contains(c)))
    {
        return Err(
            OidcError::invalid_request(format!("{param} contains invalid characters")).into(),
        );
    }
    Ok(())
}

async fn authorization_endpoint(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    ctx.out.set("cache-control", "no-store");
    load_session(ctx).await?;
    let mut auth = Auth::default();
    if let Route::Resume(uid) = ctx.route.clone() {
        if !resume(ctx, &mut auth, &uid).await? {
            return Ok(());
        }
        check_client(ctx, &mut auth).await?;
    } else {
        let allow = authorization_allow_list(&ctx.route);
        auth.params = ctx.params(&allow);
        let dupes = auth.params.reject_dupes(&["resource"], None);
        if !dupes.is_empty() {
            return Err(dupes_error(&dupes));
        }
        reject_unsupported(ctx, &auth.params)?;
        check_client(ctx, &mut auth).await?;
        load_pushed_authorization_request(ctx, &mut auth).await?;
        process_request_object(ctx, &mut auth)?;
        check_response_mode(&mut auth)?;
        one_redirect_uri_client(&mut auth);
        presence(&auth.params, &["response_type", "client_id"])?;
        if auth.params.has("registration") {
            return Err(OidcError::registration_not_supported().into());
        }
        check_response_type(&mut auth)?;
        presence(&auth.params, &["redirect_uri"])?;
        check_prompt(&auth.params)?;
        check_scope(ctx, &mut auth)?;
        check_openid_scope(ctx, &auth)?;
        check_redirect_uri(&mut auth)?;
        check_pkce(&auth.params)?;
        check_resource(ctx, &mut auth).await?;
        check_max_age(&mut auth.params)?;
        check_id_token_hint(ctx, &mut auth)?;
    }
    if matches!(ctx.route, Route::Resume(_)) {
        check_resource(ctx, &mut auth).await?;
    }
    assign_claims(&mut auth);
    load_account(ctx, &mut auth).await?;
    load_grant(ctx, &mut auth).await?;
    if !interactions(ctx, &mut auth).await? {
        return Ok(());
    }
    respond(ctx, &mut auth).await
}

fn reject_unsupported(ctx: &Ctx<'_>, params: &Params) -> ProviderResult<()> {
    if params.has("request") {
        return Err(OidcError::request_not_supported().into());
    }
    if params.has("request_uri") && !matches!(ctx.route, Route::Authorization) {
        return Err(OidcError::request_uri_not_supported().into());
    }
    Ok(())
}

async fn check_client(ctx: &mut Ctx<'_>, auth: &mut Auth) -> ProviderResult<()> {
    presence(&auth.params, &["client_id"])?;
    let client_id = auth.params.get("client_id").unwrap_or_default().to_owned();
    let Some(client) = ctx.core().find_client(&client_id).await? else {
        auth.no_client = true;
        return Err(OidcError::invalid_client(Some("client is invalid")).into());
    };
    ctx.entities_client = Some(client.clone());
    auth.client = Some(client);
    Ok(())
}

async fn load_pushed_authorization_request(
    ctx: &mut Ctx<'_>,
    auth: &mut Auth,
) -> ProviderResult<()> {
    if auth.params.has("request") && auth.params.has("request_uri") {
        return Err(OidcError::invalid_request(
            "request and request_uri parameters MUST NOT be used together",
        )
        .into());
    }
    let Some(request_uri) = auth.params.get("request_uri").map(str::to_owned) else {
        return Ok(());
    };
    if !request_uri.starts_with(PUSHED_REQUEST_URN) {
        return Err(OidcError::request_uri_not_supported().into());
    }
    if url::Url::parse(&request_uri).is_err() {
        return Err(OidcError::invalid_request_uri("invalid request_uri").into());
    }
    let id = request_uri
        .split(PUSHED_REQUEST_URN)
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let par = ctx
        .core()
        .find_model("PushedAuthorizationRequest", &id, true)
        .await?;
    let Some(par) =
        par.filter(|par| !truthy(par.get("consumed")) && !super::core::Core::is_expired(par))
    else {
        return Err(OidcError::invalid_request_uri(
            "request_uri is invalid, expired, or was already used",
        )
        .into());
    };
    auth.params.set("request", Some(text(par.get("request"))));
    auth.par = Some(par);
    Ok(())
}

/// `processRequestObject`: the pushed request's parameters replace the query (request objects are disabled).
fn process_request_object(ctx: &Ctx<'_>, auth: &mut Auth) -> ProviderResult<()> {
    let client = auth.client.clone().expect("client loaded");
    let pushed = auth.par.is_some();
    if (client.require_par() || ctx.inner.config.require_pushed_authorization_requests)
        && matches!(ctx.route, Route::Authorization)
        && !pushed
    {
        return Err(OidcError::invalid_request("Pushed Authorization Request must be used").into());
    }
    let Some(request) = auth.params.get("request").map(str::to_owned) else {
        return Ok(());
    };
    let decoded = decode_unsecured(&request)
        .ok_or_else(|| OidcError::invalid_request_object("could not parse Request Object"))?;
    let allow = authorization_allow_list(&ctx.route);
    let mut values: RawParams = RawParams::new();
    for (key, value) in &decoded {
        if !allow.contains(&key.as_str()) {
            continue;
        }
        let param = match value {
            Value::Array(_) => Param::from_value(value),
            Value::String(text) => Some(Param::One(text.clone())),
            Value::Object(_) if key == "claims" => Some(Param::One(js::stringify(value))),
            other => Some(Param::One(js_string(Some(other)))),
        };
        if let Some(param) = param {
            values.insert(key.clone(), param);
        }
    }
    let mut check = Params::new(&allow, &values);
    let dupes = check.reject_dupes(&["resource"], None);
    if !dupes.is_empty() {
        return Err(dupes_error(&dupes));
    }
    let original_response_type = auth.params.get("response_type").map(str::to_owned);
    if values.contains_key("request") || values.contains_key("request_uri") {
        return Err(OidcError::invalid_request_object(
            "Request Object must not contain request or request_uri properties",
        )
        .into());
    }
    let request_type = match values.get("response_type") {
        Some(Param::One(value)) => Some(value.clone()),
        _ => None,
    };
    if let (Some(original), Some(request)) = (&original_response_type, &request_type)
        && original != request
    {
        return Err(OidcError::invalid_request_object(
            "request response_type must equal the one in request parameters",
        )
        .into());
    }
    let request_client = match values.get("client_id") {
        Some(Param::One(value)) => Some(value.clone()),
        _ => None,
    };
    if let (Some(param), Some(request)) = (auth.params.get("client_id"), &request_client)
        && param != request
    {
        return Err(OidcError::invalid_request_object(
            "request client_id must equal the one in request parameters",
        )
        .into());
    }
    if request_client
        .as_deref()
        .is_some_and(|id| id != client.client_id())
    {
        return Err(OidcError::invalid_request_object("request client_id mismatch").into());
    }
    assert_payload(&decoded, 15.0, false)
        .and_then(|()| {
            if s(&decoded, "iss").is_some_and(|iss| iss != client.client_id())
                || !decoded.contains_key("iss")
            {
                return Err("jwt issuer invalid".to_owned());
            }
            let aud_ok = match decoded.get("aud") {
                Some(Value::String(aud)) => *aud == ctx.core().issuer,
                Some(Value::Array(values)) => values
                    .iter()
                    .any(|value| value.as_str() == Some(ctx.core().issuer.as_str())),
                _ => false,
            };
            if aud_ok {
                Ok(())
            } else {
                Err("jwt audience missing".into())
            }
        })
        .map_err(|_| OidcError::invalid_request_object("Request Object claims are invalid"))?;
    let par = auth.par.clone().unwrap_or_default();
    if par.get("trusted") == Some(&Value::Bool(true)) {
        auth.trusted = values.keys().cloned().collect();
    }
    let keys: Vec<String> = auth.params.values.keys().cloned().collect();
    for key in keys {
        match values.get(&key) {
            Some(Param::One(value)) if value.is_empty() => auth.params.set_raw(&key, None),
            Some(value) => auth.params.set_raw(&key, Some(value.clone())),
            None => auth.params.set_raw(&key, None),
        }
    }
    if let Some(jkt) = s(&par, "dpopJkt").filter(|jkt| !jkt.is_empty()) {
        auth.params.set("dpop_jkt", Some(jkt.to_owned()));
        auth.trusted.push("dpop_jkt".into());
    }
    Ok(())
}

fn decode_unsecured(token: &str) -> Option<Map<String, Value>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = jose::b64url_decode(parts[1])?;
    serde_json::from_slice::<Value>(&payload)
        .ok()?
        .as_object()
        .cloned()
}

fn response_mode(params: &Params) -> String {
    params
        .get("response_mode")
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if params
                .get("response_type")
                .is_some_and(|value| value.contains("token"))
            {
                "fragment".into()
            } else {
                "query".into()
            }
        })
}

fn check_response_mode(auth: &mut Auth) -> ProviderResult<()> {
    let Some(mode) = auth.params.get("response_mode").map(str::to_owned) else {
        return Ok(());
    };
    if !["query", "fragment", "form_post"].contains(&mode.as_str()) {
        auth.params.remove("response_mode");
        return Err(OidcError::unsupported_response_mode().into());
    }
    let client = auth.client.as_ref().expect("client loaded");
    let modes = client
        .metadata
        .get("response_modes")
        .and_then(Value::as_array);
    if modes.is_some_and(|modes| {
        !modes
            .iter()
            .any(|value| value.as_str() == Some(mode.as_str()))
    }) {
        return Err(OidcError::invalid_request(
            "requested response_mode is not allowed for this client or request",
        )
        .into());
    }
    if mode == "query"
        && auth
            .params
            .get("response_type")
            .is_some_and(|value| value.contains("token"))
    {
        return Err(OidcError::invalid_request(
            "requested response_mode is not allowed for the requested response_type",
        )
        .into());
    }
    Ok(())
}

fn one_redirect_uri_client(auth: &mut Auth) {
    let client = auth.client.as_ref().expect("client loaded");
    let uris = client.strings("redirect_uris");
    if !auth.params.has("redirect_uri") && uris.len() == 1 {
        auth.redirect_uri_check_performed = true;
        auth.params.set("redirect_uri", Some(uris[0].clone()));
    }
}

fn check_response_type(auth: &mut Auth) -> ProviderResult<()> {
    let value = auth
        .params
        .get("response_type")
        .unwrap_or_default()
        .to_owned();
    let mut parts: Vec<&str> = Vec::new();
    for part in value.split(' ') {
        if !parts.contains(&part) {
            parts.push(part);
        }
    }
    parts.sort_unstable();
    let normalized = parts.join(" ");
    auth.params.set("response_type", Some(normalized.clone()));
    if normalized != "code" {
        return Err(OidcError::unsupported_response_type().into());
    }
    if !auth
        .client
        .as_ref()
        .expect("client loaded")
        .response_type_allowed(&normalized)
    {
        return Err(OidcError::invalid_request(
            "requested response_type is not allowed for this client",
        )
        .into());
    }
    Ok(())
}

fn check_prompt(params: &Params) -> ProviderResult<()> {
    if !params.has("prompt") {
        return Ok(());
    }
    let prompts = prompts(params);
    for prompt in &prompts {
        if !["none", "login", "consent"].contains(&prompt.as_str()) {
            return Err(OidcError::invalid_request("unsupported prompt value requested").into());
        }
    }
    if prompts.iter().any(|prompt| prompt == "none") && prompts.len() != 1 {
        return Err(OidcError::invalid_request("prompt none must only be used alone").into());
    }
    Ok(())
}

fn check_scope(ctx: &Ctx<'_>, auth: &mut Auth) -> ProviderResult<()> {
    let allow = authorization_allow_list(&ctx.route);
    if !is_valid_scope(auth.params.get("scope")) {
        return Err(OidcError::invalid_scope("scope contains invalid characters", None).into());
    }
    let mut scopes = request_scopes(&auth.params);
    let client = auth.client.clone().expect("client loaded");
    if scopes.iter().any(|scope| scope == "offline_access") {
        let response_type = auth
            .params
            .get("response_type")
            .unwrap_or_default()
            .to_owned();
        let prompts = prompts(&auth.params);
        if (allow.contains(&"response_type") && !response_type.contains("code"))
            || (allow.contains(&"prompt") && !prompts.iter().any(|prompt| prompt == "consent"))
            || !client.grant_type_allowed("refresh_token")
        {
            scopes.retain(|scope| scope != "offline_access");
        }
    }
    auth.params
        .set("scope", (!scopes.is_empty()).then(|| scopes.join(" ")));
    if let Some(client_scope) = client.scope() {
        let allowed = scope_set(Some(client_scope));
        for scope in scopes
            .iter()
            .filter(|scope| ctx.core().scopes.contains(scope))
        {
            if !allowed.contains(scope) {
                return Err(OidcError::invalid_scope(
                    "requested scope is not allowed",
                    Some(scope.clone()),
                )
                .into());
            }
        }
    }
    Ok(())
}

fn check_openid_scope(ctx: &Ctx<'_>, auth: &Auth) -> ProviderResult<()> {
    if auth
        .params
        .get("scope")
        .is_some_and(|scope| scope.split(' ').any(|value| value == "openid"))
    {
        return Ok(());
    }
    let allow = authorization_allow_list(&ctx.route);
    if allow.contains(&"response_type")
        && auth
            .params
            .get("response_type")
            .is_some_and(|value| value.contains("id_token"))
    {
        return Err(OidcError::invalid_request(
            "openid scope must be requested for this response_type",
        )
        .into());
    }
    let client = auth.client.as_ref().expect("client loaded");
    for (key, label) in [
        ("default_acr_values", "default_acr_values"),
        ("default_max_age", "default_max_age"),
        ("require_auth_time", "require_auth_time"),
    ] {
        if truthy(client.metadata.get(key)) {
            return Err(OidcError::invalid_request(format!(
                "openid scope must be requested for clients with {label}"
            ))
            .into());
        }
    }
    for param in [
        "acr_values",
        "claims",
        "claims_locales",
        "id_token_hint",
        "max_age",
        "nonce",
    ] {
        if auth.params.has(param) {
            return Err(OidcError::invalid_request(format!(
                "openid scope must be requested when using the {param} parameter"
            ))
            .into());
        }
    }
    Ok(())
}

fn check_redirect_uri(auth: &mut Auth) -> ProviderResult<()> {
    let client = auth.client.as_ref().expect("client loaded");
    let redirect = auth.params.get("redirect_uri").unwrap_or_default();
    if !client.redirect_uri_allowed(redirect) {
        return Err(OidcError::invalid_redirect_uri().into());
    }
    auth.redirect_uri_check_performed = true;
    Ok(())
}

fn check_pkce(params: &Params) -> ProviderResult<()> {
    if !params.has("code_challenge_method") && params.has("code_challenge") {
        return Err(OidcError::invalid_request("code_challenge_method must be provided").into());
    }
    if let Some(method) = params.get("code_challenge_method") {
        if method != "S256" {
            return Err(
                OidcError::invalid_request("not supported value of code_challenge_method").into(),
            );
        }
        if !params.has("code_challenge") {
            return Err(OidcError::invalid_request(
                "code_challenge must be provided with code_challenge_method",
            )
            .into());
        }
    }
    if params
        .get("response_type")
        .is_some_and(|value| value.contains("code"))
        && !params.has("code_challenge")
    {
        return Err(OidcError::invalid_request(
            "Authorization Server policy requires PKCE to be used for this request",
        )
        .into());
    }
    if let Some(challenge) = params.get("code_challenge") {
        check_format(challenge, "code_challenge")?;
    }
    Ok(())
}

/// `checkResource`: resolves the requested resource indicators.
async fn check_resource(ctx: &Ctx<'_>, auth: &mut Auth) -> ProviderResult<()> {
    let client = auth.client.clone().expect("client loaded");
    let resource = auth.params.raw("resource").cloned();
    let empty = match &resource {
        None => true,
        Some(Param::Many(values)) => values.is_empty(),
        Some(Param::One(value)) => value.is_empty(),
    };
    if auth.params.has("scope") && empty {
        let scopes = request_oidc_scopes(ctx.inner, &auth.params);
        auth.params.set("scope", Some(scopes.join(" ")));
        return Ok(());
    }
    let Some(resource) = resource else {
        return Ok(());
    };
    let identifiers = match resource {
        Param::One(value) => vec![value],
        Param::Many(values) => values,
    };
    for identifier in identifiers {
        let Ok(parsed) = url::Url::parse(&identifier) else {
            return Err(OidcError::invalid_target(Some(
                "resource indicator must be an absolute URI",
            ))
            .into());
        };
        if parsed.as_str().contains('#') {
            return Err(OidcError::invalid_target(Some(
                "resource indicator must not contain a fragment component",
            ))
            .into());
        }
        let info = ctx
            .core()
            .resource_server_info(&identifier, &client)
            .await?;
        auth.resource_servers.insert(identifier, info);
    }
    Ok(())
}

fn check_max_age(params: &mut Params) -> ProviderResult<()> {
    let Some(value) = params.get("max_age").map(str::to_owned) else {
        return Ok(());
    };
    let max_age = js::string_to_number(&value);
    if !js::is_safe_integer(max_age) || max_age.is_sign_negative() && max_age != 0.0 {
        return Err(OidcError::invalid_request("invalid max_age parameter value").into());
    }
    if max_age == 0.0 {
        let mut prompts = prompts(params);
        params.remove("max_age");
        if !prompts.iter().any(|prompt| prompt == "login") {
            prompts.push("login".into());
            params.set("prompt", Some(prompts.join(" ")));
        }
    }
    Ok(())
}

fn check_id_token_hint(ctx: &Ctx<'_>, auth: &mut Auth) -> ProviderResult<()> {
    let Some(hint) = auth.params.get("id_token_hint").map(str::to_owned) else {
        return Ok(());
    };
    let client = auth.client.clone().expect("client loaded");
    let decoded = validate_id_token(ctx, &hint, &client)
        .map_err(|_| OidcError::invalid_request("could not validate id_token_hint"))?;
    auth.id_token_hint = Some(decoded);
    Ok(())
}

/// `IdToken.validate(jwt, client)`: signed by the provider for the client (expiration ignored).
fn validate_id_token(
    ctx: &Ctx<'_>,
    token: &str,
    client: &Client,
) -> Result<Map<String, Value>, String> {
    let decoded = jose::decode(token).map_err(|error| error.to_string())?;
    let alg = client.id_token_alg();
    if s(&decoded.header, "alg") != Some(alg) {
        return Err("alg mismatch".into());
    }
    let keys = jose::KeySet::new(
        ctx.core()
            .keystore
            .keys
            .iter()
            .map(|key| key.jwk.clone())
            .collect(),
    );
    keys.verify(&decoded).map_err(|error| error.to_string())?;
    assert_payload(&decoded.payload, 15.0, true)?;
    let aud_ok = match decoded.payload.get("aud") {
        Some(Value::String(aud)) => aud == client.client_id(),
        Some(Value::Array(values)) => values
            .iter()
            .any(|value| value.as_str() == Some(client.client_id())),
        _ => false,
    };
    if !aud_ok {
        return Err(format!("jwt audience missing {}", client.client_id()));
    }
    if s(&decoded.payload, "iss") != Some(ctx.core().issuer.as_str()) {
        return Err("jwt issuer invalid".into());
    }
    if !decoded.payload.get("sub").is_some_and(Value::is_string) {
        return Err("invalid sub value".into());
    }
    Ok(decoded.payload)
}

fn assign_claims(auth: &mut Auth) {
    let client = auth.client.as_ref().expect("client loaded");
    let login = prompts(&auth.params).iter().any(|prompt| prompt == "login");
    let mut id_token = auth
        .claims
        .get("id_token")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if auth.params.has("max_age")
        || client.metadata.get("require_auth_time") == Some(&Value::Bool(true))
        || login
    {
        id_token.insert("auth_time".into(), json!({ "essential": true }));
    }
    if let Some(acr) = auth.params.get("acr_values") {
        id_token.insert(
            "acr".into(),
            json!({ "values": acr.split(' ').collect::<Vec<_>>() }),
        );
    }
    if !id_token.is_empty() {
        auth.claims
            .insert("id_token".into(), Value::Object(id_token));
    }
}

async fn load_account(ctx: &mut Ctx<'_>, auth: &mut Auth) -> ProviderResult<()> {
    let account_id = ctx.session.as_ref().and_then(OpSession::account_id);
    if let Some(account_id) = account_id {
        auth.account = find_account(ctx.inner, auth.client.as_ref(), &account_id).await?;
        if auth.account.is_none() {
            return Err(server_error("findAccount must resolve an account"));
        }
    }
    Ok(())
}

async fn load_grant(ctx: &mut Ctx<'_>, auth: &mut Auth) -> ProviderResult<()> {
    let Some(account) = auth.account.clone() else {
        return Ok(());
    };
    let client = auth.client.clone().expect("client loaded");
    let session = ctx.session.as_mut().expect("session loaded");
    let grant_id = auth
        .result
        .as_ref()
        .and_then(|result| result.get("consent"))
        .and_then(|consent| consent.get("grantId"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| session.grant_id_for(client.client_id()));
    let existing = match grant_id {
        Some(id) => find_grant(ctx.inner, &id).await?,
        None => None,
    };
    let session = ctx.session.as_mut().expect("session loaded");
    let grant = match existing {
        Some(grant) => {
            if s(&grant, "accountId") != Some(account.account_id.as_str()) {
                return Err(server_error("accountId mismatch"));
            }
            if s(&grant, "clientId") != Some(client.client_id()) {
                return Err(server_error("clientId mismatch"));
            }
            let client_id = auth
                .params
                .get("client_id")
                .unwrap_or(client.client_id())
                .to_owned();
            session.ensure_client_container(&client_id);
            session.set_authorization(&client_id, "grantId", json!(text(grant.get("jti"))));
            grant
        }
        None => {
            let mut grant = Map::new();
            grant.insert("accountId".into(), json!(account.account_id));
            grant.insert("clientId".into(), json!(client.client_id()));
            grant
        }
    };
    auth.grant = Some(grant);
    Ok(())
}

/// `oidc.promptPending(name)`.
fn prompt_pending(ctx: &Ctx<'_>, auth: &Auth, name: &str) -> bool {
    let prompts = prompts(&auth.params);
    if matches!(ctx.route, Route::Resume(_) | Route::DeviceResume(_)) {
        let result_keys: Vec<String> = auth
            .result
            .as_ref()
            .map(|result| result.keys().cloned().collect())
            .unwrap_or_default();
        return prompts
            .iter()
            .any(|prompt| prompt == name && !result_keys.contains(prompt));
    }
    prompts.iter().any(|prompt| prompt == name)
}

/// A prompt that needs the end-user: name, details, reasons, error code, error description.
type PromptOutcome = (String, Map<String, Value>, Vec<String>, String, String);

/// The interaction policy: returns false when an interaction (or a prompt=none error) answered the request.
async fn interactions(ctx: &mut Ctx<'_>, auth: &mut Auth) -> ProviderResult<bool> {
    let session_account = ctx.session.as_ref().and_then(OpSession::account_id);
    let prompts_list = prompts(&auth.params);
    // login
    let mut failed: Vec<(&str, &str, Map<String, Value>)> = Vec::new();
    let mut login_details = Map::new();
    if let Some(max_age) = auth.params.get("max_age") {
        login_details.insert("max_age".into(), json!(max_age));
    }
    if let Some(hint) = auth.params.get("login_hint") {
        login_details.insert("login_hint".into(), json!(hint));
    }
    if let Some(hint) = auth.params.get("id_token_hint") {
        login_details.insert("id_token_hint".into(), json!(hint));
    }
    if prompts_list.iter().any(|prompt| prompt == "login") && prompt_pending(ctx, auth, "login") {
        failed.push(("login_prompt", "login prompt was not resolved", Map::new()));
    }
    if session_account.is_none() {
        failed.push((
            "no_session",
            "End-User authentication is required",
            Map::new(),
        ));
    }
    if let Some(max_age) = auth.params.get("max_age") {
        let session = ctx.session.as_ref().expect("session loaded");
        let stale = session_account.is_none()
            || (session.past(js::string_to_number(max_age))
                && !auth
                    .result
                    .as_ref()
                    .is_some_and(|result| result.contains_key("login")));
        if stale {
            failed.push((
                "max_age",
                "End-User authentication could not be obtained",
                Map::new(),
            ));
        }
    }
    if let Some(hint) = &auth.id_token_hint {
        let mismatch = match &session_account {
            None => true,
            Some(account) => s(hint, "sub") != Some(account.as_str()),
        };
        if mismatch {
            failed.push((
                "id_token_hint",
                "id_token_hint and authenticated subject do not match",
                Map::new(),
            ));
        }
    }
    let mut prompt: Option<PromptOutcome> = None;
    if !failed.is_empty() {
        let mut details = login_details.clone();
        for (_, _, extra) in &failed {
            for (key, value) in extra {
                details.insert(key.clone(), value.clone());
            }
        }
        let reasons = failed
            .iter()
            .map(|(reason, _, _)| (*reason).to_owned())
            .collect();
        prompt = Some((
            "login".into(),
            details,
            reasons,
            "login_required".into(),
            failed[0].1.to_owned(),
        ));
    } else {
        // consent
        let mut failed: Vec<(&str, &str, &str, Map<String, Value>)> = Vec::new();
        let client = auth.client.clone().expect("client loaded");
        let grant = auth.grant.clone().unwrap_or_default();
        if prompts_list.iter().any(|prompt| prompt == "consent")
            && prompt_pending(ctx, auth, "consent")
        {
            failed.push((
                "consent_prompt",
                "consent prompt was not resolved",
                "consent_required",
                Map::new(),
            ));
        }
        if client.application_type() == "native"
            && auth.params.get("response_type") != Some("none")
            && !auth
                .result
                .as_ref()
                .is_some_and(|result| result.contains_key("consent"))
        {
            failed.push((
                "native_client_prompt",
                "native clients require End-User interaction",
                "interaction_required",
                Map::new(),
            ));
        }
        let encountered = grant_ops::oidc_scope_encountered(&grant);
        let missing_scope: Vec<String> = request_oidc_scopes(ctx.inner, &auth.params)
            .into_iter()
            .filter(|scope| !encountered.contains(scope))
            .collect();
        if !missing_scope.is_empty() {
            let mut details = Map::new();
            details.insert("missingOIDCScope".into(), json!(missing_scope));
            failed.push((
                "op_scopes_missing",
                "requested scopes not granted",
                "consent_required",
                details,
            ));
        }
        let mut missing_resource = Map::new();
        let requested = request_scopes(&auth.params);
        for (indicator, server) in &auth.resource_servers {
            let encountered = grant_ops::resource_scope_encountered(&grant, indicator);
            let available = server.scopes();
            for scope in &requested {
                if available.contains(scope) && !encountered.contains(scope) {
                    let entry = missing_resource
                        .entry(indicator.clone())
                        .or_insert_with(|| json!([]));
                    if let Value::Array(values) = entry {
                        values.push(json!(scope));
                    }
                }
            }
        }
        if !missing_resource.is_empty() {
            let mut details = Map::new();
            details.insert(
                "missingResourceScopes".into(),
                Value::Object(missing_resource),
            );
            failed.push((
                "rs_scopes_missing",
                "requested scopes not granted",
                "consent_required",
                details,
            ));
        }
        if !failed.is_empty() {
            let mut details = Map::new();
            for (_, _, _, extra) in &failed {
                for (key, value) in extra {
                    details.insert(key.clone(), value.clone());
                }
            }
            let reasons = failed
                .iter()
                .map(|(reason, _, _, _)| (*reason).to_owned())
                .collect();
            prompt = Some((
                "consent".into(),
                details,
                reasons,
                failed[0].2.to_owned(),
                failed[0].1.to_owned(),
            ));
        }
    }
    let Some((name, details, reasons, error, description)) = prompt else {
        if session_account.is_none() {
            return Err(OidcError::access_denied(None).into());
        }
        let grant = auth.grant.clone().unwrap_or_default();
        let oidc = request_oidc_scopes(ctx.inner, &auth.params);
        let requested = request_scopes(&auth.params);
        let any_resource = auth.resource_servers.keys().any(|resource| {
            !grant_ops::resource_scope_filtered(&grant, resource, &requested).is_empty()
        });
        if grant_ops::oidc_scope_filtered(&grant, &oidc).is_empty() && !any_resource {
            return Err(OidcError::access_denied(None).into());
        }
        return Ok(true);
    };
    if prompt_pending(ctx, auth, "none") {
        let mut err = OidcError::from_code(&error, Some(&description));
        let code = if matches!(ctx.route, Route::CodeVerification | Route::DeviceResume(_)) {
            400
        } else {
            303
        };
        err.status = code;
        return Err(err.into());
    }
    let uid = nanoid(21);
    let device = matches!(ctx.route, Route::CodeVerification | Route::DeviceResume(_));
    let return_to = ctx.url_for(if device { "device_resume" } else { "resume" }, Some(&uid));
    let session = ctx.session.as_ref().expect("session loaded");
    let mut interaction = Map::new();
    interaction.insert("jti".into(), json!(uid));
    interaction.insert("returnTo".into(), json!(return_to));
    interaction.insert(
        "prompt".into(),
        json!({ "name": name, "reasons": reasons, "details": Value::Object(details) }),
    );
    if let Some(result) = &auth.result {
        interaction.insert("lastSubmission".into(), Value::Object(result.clone()));
    }
    if let Some(account) = session.account_id() {
        interaction.insert("accountId".into(), json!(account));
    }
    interaction.insert("params".into(), Value::Object(auth.params.to_plain()));
    interaction.insert("trusted".into(), json!(auth.trusted));
    if let Some(account) = session.account_id() {
        let mut snapshot = Map::new();
        snapshot.insert("accountId".into(), json!(account));
        snapshot.insert("uid".into(), json!(session.uid()));
        snapshot.insert("cookie".into(), json!(session.id()));
        if let Some(acr) = session.payload.get("acr").filter(|v| truthy(Some(v))) {
            snapshot.insert("acr".into(), acr.clone());
        }
        if let Some(amr) = session.payload.get("amr").filter(|v| truthy(Some(v))) {
            snapshot.insert("amr".into(), amr.clone());
        }
        interaction.insert("session".into(), Value::Object(snapshot));
    }
    if let Some(grant_id) = auth.grant.as_ref().and_then(|grant| s(grant, "jti")) {
        interaction.insert("grantId".into(), json!(grant_id));
    }
    let cid = auth
        .interaction
        .as_ref()
        .and_then(|interaction| s(interaction, "cid"))
        .map(str::to_owned)
        .unwrap_or_else(|| nanoid(21));
    interaction.insert("cid".into(), json!(cid));
    if let Some(device) = auth.device_code.as_ref().and_then(|code| s(code, "jti")) {
        interaction.insert("deviceCode".into(), json!(device));
    }
    let par_jti = auth
        .par
        .as_ref()
        .and_then(|par| s(par, "jti"))
        .or_else(|| {
            auth.interaction
                .as_ref()
                .and_then(|interaction| s(interaction, "parJti"))
        })
        .map(str::to_owned);
    if let Some(par) = par_jti {
        interaction.insert("parJti".into(), json!(par));
    }
    let ttl = 600.0;
    ctx.core()
        .save_model("Interaction", &mut interaction, ttl)
        .await?;
    let destination = (ctx.inner.config.interaction_url)(&uid);
    let destination_path = url::Url::parse(&ctx.core().issuer)
        .ok()
        .and_then(|issuer| issuer.join(&destination).ok())
        .map(|url| url.path().to_owned())
        .unwrap_or_else(|| "/".into());
    let options = ctx.cookie_options();
    ctx.set_cookie(
        "_interaction",
        Some(&uid),
        &CookieOptions {
            path: Some(destination_path),
            max_age_ms: Some(ttl * 1000.0),
            ..options.clone()
        },
    );
    let resume_path = url::Url::parse(&return_to)
        .map(|url| url.path().to_owned())
        .unwrap_or_else(|_| "/".into());
    ctx.set_cookie(
        "_interaction_resume",
        Some(&uid),
        &CookieOptions {
            path: Some(resume_path),
            max_age_ms: Some(ttl * 1000.0),
            ..options
        },
    );
    ctx.out.status = Some(303);
    ctx.out.redirect(&destination);
    Ok(false)
}

/// `getResume`: loads the finished interaction; false when the response is already written (logout confirmation).
async fn resume(ctx: &mut Ctx<'_>, auth: &mut Auth, _uid: &str) -> ProviderResult<bool> {
    let cookie = ctx.get_cookie("_interaction_resume");
    let Some(cookie_id) = cookie else {
        return Err(OidcError::session_not_found("authorization request has expired").into());
    };
    let interaction = ctx
        .core()
        .find_model("Interaction", &cookie_id, false)
        .await?;
    let Some(mut interaction) = interaction else {
        return Err(OidcError::session_not_found("interaction session not found").into());
    };
    auth.interaction = Some(interaction.clone());
    if s(&interaction, "jti") != Some(cookie_id.as_str()) {
        return Err(OidcError::session_not_found(
            "authorization session and cookie identifier mismatch",
        )
        .into());
    }
    let result = interaction
        .get("result")
        .and_then(Value::as_object)
        .cloned();
    let stored = interaction
        .get("params")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let trusted: Vec<String> = interaction
        .get("trusted")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let origin_uid = interaction
        .get("session")
        .and_then(|session| session.get("uid"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let session = ctx.session.as_mut().expect("session loaded");
    if let Some(uid) = &origin_uid
        && *uid != session.uid()
    {
        return Err(OidcError::session_not_found(
            "interaction session and authentication session mismatch",
        )
        .into());
    }
    let login_account = result
        .as_ref()
        .and_then(|result| result.get("login"))
        .and_then(|login| login.get("accountId"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let (Some(login), Some(current)) = (&login_account, session.account_id())
        && *login != current
    {
        if let Some(Value::Object(snapshot)) = interaction.get_mut("session")
            && snapshot.contains_key("uid")
        {
            snapshot.shift_remove("uid");
            let exp = n(&interaction, "exp").unwrap_or_default();
            interaction.shift_remove("exp");
            ctx.core()
                .save_model("Interaction", &mut interaction, exp - epoch())
                .await?;
        }
        let secret = nanoid(21);
        let client_id = stored.get("client_id").cloned().unwrap_or(Value::Null);
        let post_logout = ctx.url_for(
            ctx.route.name(),
            match &ctx.route {
                Route::Resume(uid) | Route::DeviceResume(uid) => Some(uid.as_str()),
                _ => None,
            },
        );
        let session = ctx.session.as_mut().expect("session loaded");
        session.set(
            "state",
            json!({ "secret": secret, "clientId": client_id, "postLogoutRedirectUri": post_logout }),
        );
        let action = ctx.url_for("end_session_confirm", None);
        form_post(
            &mut ctx.out,
            &action,
            &[("xsrf", secret), ("logout", "yes".into())],
        );
        return Ok(false);
    }
    ctx.core()
        .adapter
        .model("Interaction")
        .destroy(&cookie_id)
        .await?;
    let allow = authorization_allow_list(&ctx.route);
    let mut raw = RawParams::new();
    for (key, value) in &stored {
        if let Some(param) = Param::from_value(value) {
            raw.insert(key.clone(), param);
        }
    }
    auth.params = Params::new(&allow, &raw);
    auth.trusted = trusted;
    auth.redirect_uri_check_performed = true;
    let device = matches!(ctx.route, Route::DeviceResume(_));
    let resume_path = url::Url::parse(&ctx.url_for(
        if device { "device_resume" } else { "resume" },
        Some(&cookie_id),
    ))
    .map(|url| url.path().to_owned())
    .unwrap_or_else(|_| "/".into());
    let options = ctx.cookie_options();
    ctx.set_cookie(
        "_interaction_resume",
        None,
        &CookieOptions {
            path: Some(resume_path),
            ..options
        },
    );
    if let Some(result) = &result
        && let Some(error) = s(result, "error")
    {
        return Err(OidcError::from_code(error, s(result, "error_description")).into());
    }
    if let Some(login) = result
        .as_ref()
        .and_then(|result| result.get("login"))
        .and_then(Value::as_object)
    {
        let remember = login.get("remember") != Some(&Value::Bool(false));
        let session = ctx.session.as_mut().expect("session loaded");
        session.set(
            "accountId",
            login.get("accountId").cloned().unwrap_or(Value::Null),
        );
        session.set(
            "loginTs",
            login
                .get("ts")
                .cloned()
                .filter(|v| !v.is_null())
                .unwrap_or_else(|| num(epoch())),
        );
        session.set("amr", login.get("amr").cloned().unwrap_or(Value::Null));
        session.set("acr", login.get("acr").cloned().unwrap_or(Value::Null));
        if !remember {
            session.set("transient", json!(true));
        }
    }
    auth.result = result;
    let session = ctx.session.as_mut().expect("session loaded");
    if !session.new {
        session.reset_identifier();
    }
    Ok(true)
}

/// `respond`: issues the code and redirects back to the client.
async fn respond(ctx: &mut Ctx<'_>, auth: &mut Auth) -> ProviderResult<()> {
    let mut par = auth.par.clone();
    if par.is_none()
        && let Some(jti) = auth
            .interaction
            .as_ref()
            .and_then(|interaction| s(interaction, "parJti"))
            .map(str::to_owned)
    {
        par = ctx
            .core()
            .find_model("PushedAuthorizationRequest", &jti, true)
            .await?;
    }
    if let Some(par) = &par {
        if truthy(par.get("consumed")) {
            return Err(OidcError::invalid_request_uri(
                "request_uri is invalid, expired, or was already used",
            )
            .into());
        }
        ctx.core()
            .adapter
            .model("PushedAuthorizationRequest")
            .consume(&text(par.get("jti")))
            .await?;
    }
    let client = auth.client.clone().expect("client loaded");
    let grant = auth.grant.clone().unwrap_or_default();
    let requested = request_scopes(&auth.params);
    let mut combined: Vec<String> = Vec::new();
    for scope in grant_ops::oidc_scope_filtered(&grant, &requested)
        .split(' ')
        .filter(|s| !s.is_empty())
    {
        if !combined.iter().any(|existing| existing == scope) {
            combined.push(scope.to_owned());
        }
    }
    for indicator in auth.resource_servers.keys() {
        for scope in grant_ops::resource_scope_filtered(&grant, indicator, &requested)
            .split(' ')
            .filter(|s| !s.is_empty())
        {
            if !combined.iter().any(|existing| existing == scope) {
                combined.push(scope.to_owned());
            }
        }
    }
    let session = ctx.session.as_mut().expect("session loaded");
    let mut code = Token::new("AuthorizationCode", Some(&client));
    code.set("accountId", session.account_id().map(Value::String));
    code.set("acr", session.payload.get("acr").cloned());
    code.set("amr", session.payload.get("amr").cloned());
    code.set("authTime", session.payload.get("loginTs").cloned());
    if !auth.claims.is_empty() {
        code.set("claims", Some(Value::Object(auth.claims.clone())));
    }
    code.set(
        "codeChallenge",
        auth.params.get("code_challenge").map(|v| json!(v)),
    );
    code.set(
        "codeChallengeMethod",
        auth.params.get("code_challenge_method").map(|v| json!(v)),
    );
    code.set(
        "grantId",
        session.grant_id_for(client.client_id()).map(Value::String),
    );
    code.set("nonce", auth.params.get("nonce").map(|v| json!(v)));
    code.set(
        "redirectUri",
        auth.params.get("redirect_uri").map(|v| json!(v)),
    );
    let resources: Vec<String> = auth.resource_servers.keys().cloned().collect();
    match resources.len() {
        0 => {}
        1 => code.set("resource", Some(json!(resources[0]))),
        _ => code.set("resource", Some(json!(resources))),
    }
    code.set("scope", Some(json!(combined.join(" "))));
    code.set("sessionUid", Some(json!(session.uid())));
    code.set("dpopJkt", auth.params.get("dpop_jkt").map(|v| json!(v)));
    if !combined.iter().any(|scope| scope == "offline_access") {
        code.set("expiresWithSession", Some(json!(true)));
    } else {
        session.set_authorization(client.client_id(), "persistsLogout", json!(true));
    }
    if client.include_sid() {
        code.set(
            "sid",
            session.sid_for(client.client_id()).map(Value::String),
        );
    }
    let value = save_token(ctx, &mut code, Some(&client)).await?;
    let mut out: Vec<(String, String)> = vec![("code".into(), value)];
    if let Some(state) = auth.params.get("state") {
        out.push(("state".into(), state.to_owned()));
    }
    out.push(("iss".into(), ctx.core().issuer.clone()));
    let mode = response_mode(&auth.params);
    let redirect = auth
        .params
        .get("redirect_uri")
        .unwrap_or_default()
        .to_owned();
    send_response(ctx, &mode, &redirect, &out);
    Ok(())
}

fn send_response(ctx: &mut Ctx<'_>, mode: &str, redirect: &str, payload: &[(String, String)]) {
    match mode {
        "form_post" => {
            let inputs: Vec<(&str, String)> = payload
                .iter()
                .map(|(key, value)| (key.as_str(), value.clone()))
                .collect();
            form_post(&mut ctx.out, redirect, &inputs);
        }
        "fragment" => {
            let mut url = url::Url::parse(redirect).ok();
            if let Some(url) = url.as_mut() {
                let fragment = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(payload.iter())
                    .finish();
                url.set_fragment(Some(&fragment));
            }
            ctx.out.status = Some(303);
            ctx.out.redirect(
                &url.map(|url| url.to_string())
                    .unwrap_or_else(|| redirect.to_owned()),
            );
        }
        _ => {
            ctx.out.status = Some(303);
            ctx.out.redirect(&redirect_with_query(redirect, payload));
        }
    }
}

/// `authorizationErrorHandler`.
async fn authorization_error(ctx: &mut Ctx<'_>, caught: ProviderError) {
    let mut error = caught.clone();
    ctx.out.status = Some(error.status());
    let params = ctx.params(&authorization_allow_list(&ctx.route));
    let safe = |name: &str| params.get(name).map(str::to_owned);
    let mut client = ctx.entities_client.clone();
    if client.is_none()
        && let Some(id) = safe("client_id")
        && let Ok(found) = ctx.core().find_client(&id).await
    {
        client = found;
    }
    let already_invalid_redirect =
        matches!(&error, ProviderError::Oidc(oidc) if oidc.class == "InvalidRedirectUri");
    if let Some(client) = &client
        && !already_invalid_redirect
    {
        let mut redirect = safe("redirect_uri");
        if redirect.is_none() && client.strings("redirect_uris").len() == 1 {
            redirect = client.strings("redirect_uris").first().cloned();
        }
        if let Some(uri) = &redirect
            && !client.redirect_uri_allowed(uri)
        {
            error = OidcError::invalid_redirect_uri().into();
            ctx.out.status = Some(error.status());
        }
    }
    let mut out = error.out(safe("state").as_deref());
    out.insert("iss".into(), json!(ctx.core().issuer));
    let allow_redirect = match &error {
        ProviderError::Oidc(oidc) => oidc.allow_redirect,
        ProviderError::Iam(_) => true,
    };
    let redirect = safe("redirect_uri").or_else(|| {
        client
            .as_ref()
            .filter(|client| client.strings("redirect_uris").len() == 1)
            .and_then(|client| client.strings("redirect_uris").first().cloned())
    });
    if safe("client_id").is_none()
        || client.is_none()
        || redirect.is_none()
        || !allow_redirect
        || safe("redirect_uri").is_none()
    {
        render_error_json(ctx, &out);
        return;
    }
    let mut mode = safe("response_mode").unwrap_or_default();
    if !["query", "fragment", "form_post"].contains(&mode.as_str()) {
        mode = if safe("response_type").is_some_and(|value| value.contains("token")) {
            "fragment".into()
        } else {
            "query".into()
        };
    }
    let payload: Vec<(String, String)> = out
        .iter()
        .map(|(key, value)| (key.clone(), js_string(Some(value))))
        .collect();
    let redirect = redirect.unwrap_or_default();
    send_response(ctx, &mode, &redirect, &payload);
}

// ---------------------------------------------------------------------------------------------------------------
// Interactions (management side)

/// `provider.interactionDetails(req, res)`: the interaction named by the `_interaction` cookie.
pub(crate) async fn get_interaction(
    inner: &Inner,
    request: &HttpRequest,
) -> ProviderResult<Map<String, Value>> {
    let cookies = request_cookies(request);
    let Some(id) = get_signed_cookie(&cookies, &inner.core.keygrip, "_interaction") else {
        return Err(OidcError::session_not_found("interaction session id cookie not found").into());
    };
    let Some(interaction) = inner.core.find_model("Interaction", &id, false).await? else {
        return Err(OidcError::session_not_found("interaction session not found").into());
    };
    if let Some(uid) = interaction
        .get("session")
        .and_then(|session| session.get("uid"))
        .and_then(Value::as_str)
    {
        let stored = inner.core.adapter.model("Session").find_by_uid(uid).await?;
        let session =
            stored.and_then(|stored| super::core::verify_stored("Session", stored, false));
        let Some(session) = session else {
            return Err(OidcError::session_not_found("session not found").into());
        };
        if interaction
            .get("session")
            .and_then(|value| value.get("accountId"))
            != session.get("accountId")
        {
            return Err(OidcError::session_not_found("session principal changed").into());
        }
    }
    Ok(interaction)
}

/// `provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false })`.
pub(crate) async fn interaction_finished(
    inner: &Inner,
    interaction: &mut Map<String, Value>,
    result: Value,
) -> ProviderResult<HttpResponse> {
    interaction.insert("result".into(), result);
    let exp = n(interaction, "exp").unwrap_or_default();
    interaction.shift_remove("exp");
    inner
        .core
        .save_model("Interaction", interaction, exp - epoch())
        .await?;
    let return_to = text(interaction.get("returnTo"));
    Ok(http::Response::builder()
        .status(303)
        .header("location", return_to)
        .header("content-length", "0")
        .body(Bytes::new())
        .unwrap_or_else(|_| http::Response::new(Bytes::new())))
}

// ---------------------------------------------------------------------------------------------------------------
// Token endpoint

fn token_params(ctx: &Ctx<'_>) -> Vec<&'static str> {
    let _ = ctx;
    let mut allow = vec!["grant_type"];
    for param in [
        "code",
        "code_verifier",
        "redirect_uri",
        "refresh_token",
        "scope",
        "device_code",
        "subject_token",
        "subject_token_type",
        "actor_token",
        "actor_token_type",
        "requested_token_type",
        "audience",
        "resource",
    ] {
        allow.push(param);
    }
    allow.extend(auth_params());
    allow
}

fn grant_params(grant_type: &str) -> Option<Vec<&'static str>> {
    match grant_type {
        "authorization_code" => Some(vec![
            "grant_type",
            "code",
            "code_verifier",
            "redirect_uri",
            "resource",
        ]),
        "refresh_token" => Some(vec!["grant_type", "refresh_token", "scope", "resource"]),
        "client_credentials" => Some(vec!["grant_type", "scope", "resource"]),
        DEVICE_CODE => Some(vec!["grant_type", "device_code", "resource"]),
        TOKEN_EXCHANGE => Some(vec![
            "grant_type",
            "subject_token",
            "subject_token_type",
            "actor_token",
            "actor_token_type",
            "requested_token_type",
            "audience",
            "resource",
            "scope",
        ]),
        _ => None,
    }
}

async fn token_endpoint(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    ctx.out.set("cache-control", "no-store");
    ctx.parse_form()?;
    let allow = token_params(ctx);
    let mut params = ctx.params(&allow);
    let client = authenticate_client(ctx, &mut params).await?;
    let dupes = params.reject_dupes(&[], Some(&["grant_type"]));
    if !dupes.is_empty() {
        return Err(dupes_error(&dupes));
    }
    let auth = auth_params();
    if let Some(grant) = params.get("grant_type").and_then(grant_params) {
        let keys: Vec<String> = params.values.keys().cloned().collect();
        for key in keys {
            if !(auth.contains(&key.as_str()) || grant.contains(&key.as_str())) {
                params.values.shift_remove(&key);
            }
        }
    }
    presence(&params, &["grant_type"])?;
    let grant_type = params.get("grant_type").unwrap_or_default().to_owned();
    if !ctx.core().grant_types.contains(&grant_type) {
        return Err(OidcError::unsupported_grant_type().into());
    }
    if !client.grant_type_allowed(&grant_type) {
        return Err(OidcError::invalid_request(
            "requested grant type is not allowed for this client",
        )
        .into());
    }
    let except: Vec<&str> = if grant_type == TOKEN_EXCHANGE {
        vec!["audience", "resource"]
    } else {
        vec!["resource"]
    };
    let dupes = params.reject_dupes(&except, None);
    if !dupes.is_empty() {
        return Err(dupes_error(&dupes));
    }
    if !is_valid_scope(params.get("scope")) {
        return Err(OidcError::invalid_scope("scope contains invalid characters", None).into());
    }
    match grant_type.as_str() {
        "authorization_code" => authorization_code_grant(ctx, &client, &mut params).await,
        "refresh_token" => refresh_token_grant(ctx, &client, &mut params).await,
        "client_credentials" => client_credentials_grant(ctx, &client, &mut params).await,
        DEVICE_CODE => device_code_grant(ctx, &client, &mut params).await,
        TOKEN_EXCHANGE => token_exchange_grant(ctx, &client, &mut params).await,
        _ => Err(OidcError::unsupported_grant_type().into()),
    }
}

fn check_pkce_grant(
    verifier: Option<&str>,
    challenge: Option<&str>,
    method: Option<&str>,
) -> ProviderResult<()> {
    if let Some(verifier) = verifier {
        check_format(verifier, "code_verifier")?;
    }
    if verifier.is_some() || challenge.is_some() {
        let Some(verifier) = verifier else {
            return Err(OidcError::invalid_grant("code_verifier must be provided").into());
        };
        if method != Some("S256") {
            return Err(OidcError::invalid_grant("unsupported code_challenge_method").into());
        }
        let expected = jose::sha256_b64url(verifier);
        if !jose::constant_equals(challenge.unwrap_or_default(), &expected) {
            return Err(
                OidcError::invalid_grant("code_verifier does not match code_challenge").into(),
            );
        }
    }
    Ok(())
}

/// `findGrantSource(ctx, Model, value, label)`.
async fn find_grant_source(
    ctx: &Ctx<'_>,
    model: &str,
    value: &str,
    label: &str,
    client: &Client,
    ignore_session_binding: bool,
) -> ProviderResult<Map<String, Value>> {
    let source = find_token(ctx, model, value, true, ignore_session_binding).await?;
    let Some(source) = source else {
        return Err(OidcError::invalid_grant(format!("{label} not found")).into());
    };
    if s(&source, "clientId") != Some(client.client_id()) {
        return Err(OidcError::invalid_grant("client mismatch").into());
    }
    Ok(source)
}

/// `validateGrant(ctx, grantId)`.
async fn validate_grant(
    ctx: &Ctx<'_>,
    grant_id: Option<&str>,
    client: &Client,
) -> ProviderResult<Map<String, Value>> {
    let grant = match grant_id.filter(|id| !id.is_empty()) {
        Some(id) => ctx.core().find_model("Grant", id, true).await?,
        None => None,
    };
    let Some(grant) = grant else {
        return Err(OidcError::invalid_grant("grant not found").into());
    };
    if super::core::Core::is_expired(&grant) {
        return Err(OidcError::invalid_grant("grant is expired").into());
    }
    if s(&grant, "clientId") != Some(client.client_id()) {
        return Err(OidcError::invalid_grant("client mismatch").into());
    }
    Ok(grant)
}

/// `consumeGrantSource(ctx, source, label)`.
async fn consume_grant_source(
    ctx: &Ctx<'_>,
    model: &str,
    source: &Map<String, Value>,
    label: &str,
) -> ProviderResult<()> {
    if truthy(source.get("consumed")) {
        revoke_grant(ctx, s(source, "grantId"), true).await?;
        return Err(OidcError::invalid_grant(format!("{label} already consumed")).into());
    }
    ctx.core()
        .adapter
        .model(model)
        .consume(&text(source.get("jti")))
        .await
}

/// `resolveResource(ctx, model, config, scopes)`.
fn resolve_resource(
    params: &Params,
    model: &Map<String, Value>,
    scopes: &[String],
) -> ProviderResult<Option<String>> {
    let model_resources: Vec<String> = match model.get("resource") {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(value)) => vec![value.clone()],
        _ => Vec::new(),
    };
    let requested = params.raw("resource").cloned();
    let resource: Option<Vec<String>> = if let Some(param) = requested {
        Some(match param {
            Param::One(value) => vec![value],
            Param::Many(values) => values,
        })
    } else if model_resources.is_empty() {
        None
    } else if !scopes.iter().any(|scope| scope == "openid") {
        Some(model_resources.clone())
    } else {
        None
    };
    let Some(resource) = resource else {
        return Ok(None);
    };
    if resource.len() != 1 {
        return Err(OidcError::invalid_target(Some(
            "only a single resource indicator value must be requested/resolved during Access Token Request",
        ))
        .into());
    }
    let resource = resource[0].clone();
    // `model.resourceIndicators`: the model's resources (a missing resource is the set of `undefined`).
    if !model_resources.contains(&resource) {
        return Err(OidcError::invalid_target(None).into());
    }
    Ok(Some(resource))
}

/// What a grant issues tokens as.
struct Issue<'a> {
    gty: &'a str,
    label: &'a str,
    dpop: Option<Dpop>,
}

/// `issueTokens(...)`: access token, refresh token, and ID token for a grant source.
async fn issue_tokens(
    ctx: &mut Ctx<'_>,
    client: &Client,
    params: &Params,
    source: &Map<String, Value>,
    grant: &Map<String, Value>,
    issue: Issue<'_>,
) -> ProviderResult<()> {
    let Issue { gty, label, dpop } = issue;
    let account = find_account(
        ctx.inner,
        Some(client),
        s(source, "accountId").unwrap_or_default(),
    )
    .await?;
    let Some(account) = account else {
        return Err(OidcError::invalid_grant(format!(
            "{label} invalid (referenced account not found)"
        ))
        .into());
    };
    if s(source, "accountId") != s(grant, "accountId") {
        return Err(OidcError::invalid_grant("accountId mismatch").into());
    }
    let mut at = Token::new("AccessToken", Some(client));
    at.set("accountId", Some(json!(account.account_id)));
    at.set(
        "expiresWithSession",
        source.get("expiresWithSession").cloned(),
    );
    at.set("grantId", source.get("grantId").cloned());
    at.set("gty", Some(json!(gty)));
    at.set("sessionUid", source.get("sessionUid").cloned());
    at.set("sid", source.get("sid").cloned());
    if gty == "authorization_code" && truthy(source.get("dpopJkt")) && dpop.is_none() {
        return Err(OidcError::invalid_grant("missing DPoP proof JWT").into());
    }
    if let Some(proof) = &dpop {
        check_dpop_replay(ctx, Some(proof), client.client_id(), grant_error).await?;
        at.set("jkt", Some(json!(proof.thumbprint)));
    }
    if gty == "authorization_code"
        && let (Some(proof), Some(jkt)) = (&dpop, s(source, "dpopJkt"))
        && proof.thumbprint != jkt
    {
        return Err(
            OidcError::invalid_grant("DPoP proof key thumbprint does not match dpop_jkt").into(),
        );
    }
    let source_scopes = scope_set(s(source, "scope"));
    let resource = resolve_resource(params, source, &source_scopes)?;
    if let Some(resource) = &resource {
        let info = ctx.core().resource_server_info(resource, client).await?;
        at.set_resource_server(info);
        at.set(
            "scope",
            Some(json!(grant_ops::resource_scope_filtered(
                grant,
                resource,
                &source_scopes
            ))),
        );
    } else {
        at.set("claims", source.get("claims").cloned());
        at.set(
            "scope",
            Some(json!(grant_ops::oidc_scope_filtered(grant, &source_scopes))),
        );
    }
    let access_token = save_token(ctx, &mut at, Some(client)).await?;
    let issue_refresh = client.grant_type_allowed("refresh_token")
        && (source_scopes.iter().any(|scope| scope == "offline_access")
            || (s(source, "kind") == Some("AuthorizationCode")
                && !source_scopes.iter().any(|scope| scope == "openid")));
    let mut refresh_token = None;
    if issue_refresh {
        let mut rt = Token::new("RefreshToken", Some(client));
        for key in [
            "accountId",
            "acr",
            "amr",
            "authTime",
            "claims",
            "expiresWithSession",
            "grantId",
            "nonce",
            "resource",
            "scope",
            "sessionUid",
            "sid",
        ] {
            rt.set(key, source.get(key).cloned());
        }
        rt.set("gty", Some(json!(gty)));
        rt.set("rotations", Some(json!(0)));
        rt.set("iiat", Some(num(epoch())));
        if client.auth_method() == "none"
            && let Some(jkt) = at.jkt()
        {
            rt.set("jkt", Some(json!(jkt)));
        }
        refresh_token = Some(save_token(ctx, &mut rt, Some(client)).await?);
    }
    let id_token = issue_id_token(ctx, client, &account, source, &at, grant, None).await?;
    let mut body = Map::new();
    body.insert("access_token".into(), json!(access_token));
    body.insert("expires_in".into(), num(at.expires_in.unwrap_or_default()));
    if let Some(id_token) = id_token {
        body.insert("id_token".into(), json!(id_token));
    }
    if let Some(refresh) = refresh_token {
        body.insert("refresh_token".into(), json!(refresh));
    }
    let at_scope = at.scope().unwrap_or_default();
    if truthy(source.get("scope")) || !at_scope.is_empty() {
        body.insert("scope".into(), json!(at_scope));
    }
    body.insert("token_type".into(), json!(at.token_type()));
    ctx.out.json(&Value::Object(body));
    Ok(())
}

/// `issueIdToken(...)`.
async fn issue_id_token(
    ctx: &Ctx<'_>,
    client: &Client,
    account: &Account,
    source: &Map<String, Value>,
    at: &Token,
    grant: &Map<String, Value>,
    scope_override: Option<&[String]>,
) -> ProviderResult<Option<String>> {
    let source_scopes = scope_set(s(source, "scope"));
    let scopes: Vec<String> = scope_override
        .map(<[String]>::to_vec)
        .unwrap_or(source_scopes);
    if !scopes.iter().any(|scope| scope == "openid") {
        return Ok(None);
    }
    let claims_mask = filter_claims(source.get("claims"), "id_token", grant);
    let rejected = grant_ops::rejected_oidc_claims(grant);
    let account_scope =
        if scope_override.is_none() && source.get("scope").is_some_and(Value::is_string) {
            text(source.get("scope"))
        } else {
            scopes.join(" ")
        };
    let mut available = ctx_account_claims(ctx.inner, account, &account_scope).await?;
    for key in ["acr", "amr"] {
        if let Some(value) = source.get(key) {
            available.insert(key.into(), value.clone());
        }
    }
    if let Some(value) = source.get("authTime") {
        available.insert("auth_time".into(), value.clone());
    }
    let token_scope = if !at.payload.contains_key("aud") {
        "openid".to_owned()
    } else {
        grant_ops::oidc_scope_filtered(grant, &scopes)
    };
    let mut payload = ctx
        .core()
        .claims
        .result(&available, &token_scope, &claims_mask, &rejected);
    if let Some(nonce) = source.get("nonce").filter(|value| !value.is_null()) {
        payload.insert("nonce".into(), nonce.clone());
    }
    if let Some(sid) = source.get("sid").filter(|value| !value.is_null()) {
        payload.insert("sid".into(), sid.clone());
    }
    sign_id_token(ctx.core(), client, payload, "idtoken").map(Some)
}

/// `IdToken.issue({ use })` for ID tokens and logout tokens.
fn sign_id_token(
    core: &super::core::Core,
    client: &Client,
    mut payload: Map<String, Value>,
    usage: &str,
) -> ProviderResult<String> {
    let alg = client.id_token_alg().to_owned();
    let key = core
        .keystore
        .select(&alg)
        .ok_or_else(|| server_error(&format!("{usage} signing algorithm has no key")))?;
    let now = epoch();
    let sub = payload.get("sub").cloned();
    payload.insert("aud".into(), json!(client.client_id()));
    payload.insert(
        "exp".into(),
        num(now + if usage == "logout" { 120.0 } else { 900.0 }),
    );
    if !payload.contains_key("iat") {
        payload.insert("iat".into(), num(now));
    }
    payload.insert("iss".into(), json!(core.issuer));
    if let Some(sub) = sub {
        payload.insert("sub".into(), sub);
    }
    let mut header = Map::new();
    if usage == "logout" {
        header.insert("typ".into(), json!("logout+jwt"));
    }
    if let Some(kid) = &key.kid {
        header.insert("kid".into(), json!(kid));
    }
    payload.retain(|_, value| !value.is_null());
    jose::sign_jwt(&key.key, &alg, header, &Value::Object(payload))
        .map_err(|error| server_error(&error.to_string()))
}

async fn authorization_code_grant(
    ctx: &mut Ctx<'_>,
    client: &Client,
    params: &mut Params,
) -> ProviderResult<()> {
    if !params.has("redirect_uri") {
        let uris = client.strings("redirect_uris");
        if uris.len() == 1 {
            params.set("redirect_uri", Some(uris[0].clone()));
        }
    }
    presence(params, &["code", "redirect_uri"])?;
    let dpop = validate_dpop(ctx, None).await?;
    let code_value = params.get("code").unwrap_or_default().to_owned();
    let code = find_grant_source(
        ctx,
        "AuthorizationCode",
        &code_value,
        "authorization code",
        client,
        false,
    )
    .await?;
    if super::core::Core::is_expired(&code) {
        return Err(OidcError::invalid_grant("authorization code is expired").into());
    }
    let grant = validate_grant(ctx, s(&code, "grantId"), client).await?;
    check_pkce_grant(
        params.get("code_verifier"),
        s(&code, "codeChallenge"),
        s(&code, "codeChallengeMethod"),
    )?;
    if dpop.is_none() && client.dpop_bound() {
        return Err(OidcError::invalid_grant("DPoP proof JWT not provided").into());
    }
    if s(&code, "redirectUri") != params.get("redirect_uri") {
        return Err(OidcError::invalid_grant("authorization code redirect_uri mismatch").into());
    }
    consume_grant_source(ctx, "AuthorizationCode", &code, "authorization code").await?;
    issue_tokens(
        ctx,
        client,
        params,
        &code,
        &grant,
        Issue {
            gty: "authorization_code",
            label: "authorization code",
            dpop,
        },
    )
    .await
}

async fn refresh_token_grant(
    ctx: &mut Ctx<'_>,
    client: &Client,
    params: &mut Params,
) -> ProviderResult<()> {
    presence(params, &["refresh_token"])?;
    let dpop = validate_dpop(ctx, None).await?;
    let value = params.get("refresh_token").unwrap_or_default().to_owned();
    let refresh = find_token(ctx, "RefreshToken", &value, true, false).await?;
    let Some(refresh) = refresh else {
        return Err(OidcError::invalid_grant("refresh token not found").into());
    };
    if s(&refresh, "clientId") != Some(client.client_id()) {
        return Err(OidcError::invalid_grant("client mismatch").into());
    }
    if super::core::Core::is_expired(&refresh) {
        return Err(OidcError::invalid_grant("refresh token is expired").into());
    }
    if dpop.is_none() && client.dpop_bound() {
        return Err(OidcError::invalid_grant("DPoP proof JWT not provided").into());
    }
    let grant = validate_grant(ctx, s(&refresh, "grantId"), client).await?;
    let refresh_scopes = scope_set(s(&refresh, "scope"));
    if params.has("scope") {
        let missing: Vec<String> = request_scopes(params)
            .into_iter()
            .filter(|scope| !refresh_scopes.contains(scope))
            .collect();
        if !missing.is_empty() {
            return Err(OidcError::invalid_scope(
                format!(
                    "refresh token missing requested {}",
                    pluralize("scope", missing.len())
                ),
                Some(missing.join(" ")),
            )
            .into());
        }
    }
    check_dpop_replay(ctx, dpop.as_ref(), client.client_id(), grant_error).await?;
    if let Some(jkt) = s(&refresh, "jkt")
        && dpop.as_ref().is_none_or(|proof| proof.thumbprint != jkt)
    {
        return Err(OidcError::invalid_grant("failed jkt verification").into());
    }
    let account = find_account(
        ctx.inner,
        Some(client),
        s(&refresh, "accountId").unwrap_or_default(),
    )
    .await?;
    let Some(account) = account else {
        return Err(OidcError::invalid_grant(
            "refresh token invalid (referenced account not found)",
        )
        .into());
    };
    if s(&refresh, "accountId") != s(&grant, "accountId") {
        return Err(OidcError::invalid_grant("accountId mismatch").into());
    }
    if truthy(refresh.get("consumed")) {
        ctx.core()
            .adapter
            .model("RefreshToken")
            .destroy(&text(refresh.get("jti")))
            .await?;
        revoke_grant(ctx, s(&refresh, "grantId"), true).await?;
        return Err(OidcError::invalid_grant("refresh token already used").into());
    }
    // rotateRefreshToken: true.
    ctx.core()
        .adapter
        .model("RefreshToken")
        .consume(&text(refresh.get("jti")))
        .await?;
    let mut rotated = Token::new("RefreshToken", Some(client));
    for key in [
        "accountId",
        "acr",
        "amr",
        "authTime",
        "claims",
        "expiresWithSession",
        "iiat",
        "grantId",
        "gty",
        "nonce",
        "resource",
        "scope",
        "sessionUid",
        "sid",
        "jkt",
        "x5t#S256",
        "attestationJkt",
    ] {
        rotated.set(key, refresh.get(key).cloned());
    }
    let rotations = match refresh.get("rotations") {
        Some(Value::Number(value)) => value.as_f64().unwrap_or_default() + 1.0,
        _ => 1.0,
    };
    rotated.set("rotations", Some(num(rotations)));
    if !truthy(rotated.get("iiat")) {
        rotated.set("iiat", Some(num(epoch())));
    }
    if let Some(gty) = s(&rotated.payload, "gty")
        .filter(|gty| !gty.is_empty())
        .map(str::to_owned)
        && !gty.ends_with("refresh_token")
    {
        rotated.set("gty", Some(json!(format!("{gty} refresh_token"))));
    }
    let refresh_value = save_token(ctx, &mut rotated, Some(client)).await?;
    let mut at = Token::new("AccessToken", Some(client));
    at.set("accountId", Some(json!(account.account_id)));
    at.set(
        "expiresWithSession",
        rotated.get("expiresWithSession").cloned(),
    );
    at.set("grantId", rotated.get("grantId").cloned());
    at.set("sessionUid", rotated.get("sessionUid").cloned());
    at.set("sid", rotated.get("sid").cloned());
    at.set("gty", rotated.get("gty").cloned());
    if let Some(proof) = &dpop {
        at.set("jkt", Some(json!(proof.thumbprint)));
    }
    if let Some(gty) = s(&at.payload, "gty")
        .filter(|gty| !gty.is_empty())
        .map(str::to_owned)
        && !gty.ends_with("refresh_token")
    {
        at.set("gty", Some(json!(format!("{gty} refresh_token"))));
    }
    let scope = if params.has("scope") {
        request_scopes(params)
    } else {
        scope_set(s(&rotated.payload, "scope"))
    };
    let resource = resolve_resource(params, &rotated.payload, &scope)?;
    if let Some(resource) = &resource {
        let info = ctx.core().resource_server_info(resource, client).await?;
        let server_scopes = info.scopes();
        at.set_resource_server(info);
        let filtered: Vec<String> = scope
            .iter()
            .filter(|value| server_scopes.contains(value))
            .cloned()
            .collect();
        at.set(
            "scope",
            Some(json!(grant_ops::resource_scope_filtered(
                &grant, resource, &filtered
            ))),
        );
    } else {
        at.set("claims", rotated.get("claims").cloned());
        at.set(
            "scope",
            Some(json!(grant_ops::oidc_scope_filtered(&grant, &scope))),
        );
    }
    let access_token = save_token(ctx, &mut at, Some(client)).await?;
    let id_token = issue_id_token(
        ctx,
        client,
        &account,
        &rotated.payload,
        &at,
        &grant,
        Some(&scope),
    )
    .await?;
    let mut body = Map::new();
    body.insert("access_token".into(), json!(access_token));
    body.insert("expires_in".into(), num(at.expires_in.unwrap_or_default()));
    if let Some(id_token) = id_token {
        body.insert("id_token".into(), json!(id_token));
    }
    body.insert("refresh_token".into(), json!(refresh_value));
    let at_scope = at.scope().unwrap_or_default();
    if truthy(rotated.get("scope")) || !at_scope.is_empty() {
        body.insert("scope".into(), json!(at_scope));
    }
    body.insert("token_type".into(), json!(at.token_type()));
    ctx.out.json(&Value::Object(body));
    Ok(())
}

async fn client_credentials_grant(
    ctx: &mut Ctx<'_>,
    client: &Client,
    params: &mut Params,
) -> ProviderResult<()> {
    let dpop = validate_dpop(ctx, None).await?;
    // resolveRequestedResources.
    let mut servers: Vec<ResourceServerInfo> = Vec::new();
    let resource = params.raw("resource").cloned();
    let empty = match &resource {
        None => true,
        Some(Param::Many(values)) => values.is_empty(),
        Some(Param::One(value)) => value.is_empty(),
    };
    if params.has("scope") && empty {
        let scopes = request_oidc_scopes(ctx.inner, params);
        params.set("scope", Some(scopes.join(" ")));
    } else if let Some(resource) = resource {
        let identifiers = match resource {
            Param::One(value) => vec![value],
            Param::Many(values) => values,
        };
        for identifier in identifiers {
            let Ok(parsed) = url::Url::parse(&identifier) else {
                return Err(OidcError::invalid_target(Some(
                    "resource indicator must be an absolute URI",
                ))
                .into());
            };
            if parsed.as_str().contains('#') {
                return Err(OidcError::invalid_target(Some(
                    "resource indicator must not contain a fragment component",
                ))
                .into());
            }
            servers.push(ctx.core().resource_server_info(&identifier, client).await?);
        }
    }
    // validateClientScope.
    let scopes = request_scopes(params);
    if let Some(client_scope) = client.scope() {
        let allowed = scope_set(Some(client_scope));
        for scope in &scopes {
            if ctx.core().scopes.contains(scope) && !allowed.contains(scope) {
                return Err(OidcError::invalid_scope(
                    "requested scope is not allowed",
                    Some(scope.clone()),
                )
                .into());
            }
        }
    }
    let mut token = Token::new("ClientCredentials", Some(client));
    token.set(
        "scope",
        (!scopes.is_empty()).then(|| json!(scopes.join(" "))),
    );
    if let Some(server) = servers.first().cloned() {
        if servers.len() != 1 {
            return Err(OidcError::invalid_target(Some(
                "only a single resource indicator value is supported for this grant type",
            ))
            .into());
        }
        let server_scopes = server.scopes();
        token.set_resource_server(server);
        let filtered: Vec<String> = scopes
            .iter()
            .filter(|scope| server_scopes.contains(scope))
            .cloned()
            .collect();
        token.set(
            "scope",
            (!filtered.is_empty()).then(|| json!(filtered.join(" "))),
        );
    }
    if let Some(proof) = &dpop {
        check_dpop_replay(ctx, Some(proof), client.client_id(), grant_error).await?;
        token.set("jkt", Some(json!(proof.thumbprint)));
    }
    if dpop.is_none() && client.dpop_bound() {
        return Err(OidcError::invalid_grant("DPoP proof JWT not provided").into());
    }
    let value = save_token(ctx, &mut token, Some(client)).await?;
    let mut body = Map::new();
    body.insert("access_token".into(), json!(value));
    body.insert(
        "expires_in".into(),
        num(token.expires_in.unwrap_or_default()),
    );
    if let Some(scope) = token.scope().filter(|scope| !scope.is_empty()) {
        body.insert("scope".into(), json!(scope));
    }
    body.insert("token_type".into(), json!(token.token_type()));
    ctx.out.json(&Value::Object(body));
    Ok(())
}

async fn device_code_grant(
    ctx: &mut Ctx<'_>,
    client: &Client,
    params: &mut Params,
) -> ProviderResult<()> {
    presence(params, &["device_code"])?;
    let dpop = validate_dpop(ctx, None).await?;
    let value = params.get("device_code").unwrap_or_default().to_owned();
    let code = find_grant_source(ctx, "DeviceCode", &value, "device code", client, false).await?;
    if dpop.is_none() && client.dpop_bound() {
        return Err(OidcError::invalid_grant("DPoP proof JWT not provided").into());
    }
    if super::core::Core::is_expired(&code) {
        return Err(OidcError::expired_token(Some("device code is expired")).into());
    }
    if !truthy(code.get("accountId")) && !truthy(code.get("error")) {
        return Err(OidcError::authorization_pending().into());
    }
    consume_grant_source(ctx, "DeviceCode", &code, "device code").await?;
    if let Some(error) = s(&code, "error").filter(|error| !error.is_empty()) {
        return Err(OidcError::from_code(error, s(&code, "errorDescription")).into());
    }
    let grant = validate_grant(ctx, s(&code, "grantId"), client).await?;
    issue_tokens(
        ctx,
        client,
        params,
        &code,
        &grant,
        Issue {
            gty: "device_code",
            label: "device code",
            dpop,
        },
    )
    .await
}

/// The account behind a subject token (`exchangedSubject`).
struct Subject {
    identity_id: String,
    client_id: String,
    scopes: Vec<String>,
    expires_at: f64,
    grant_id: Option<String>,
    act: Option<Value>,
    format: &'static str,
    personal: bool,
}

async fn exchanged_subject(ctx: &Ctx<'_>, value: &str) -> ProviderResult<Subject> {
    if value.split('.').count() == 3 {
        let public: Vec<Map<String, Value>> = ctx
            .core()
            .keystore
            .keys
            .iter()
            .map(|key| jose::public_jwk(&key.jwk))
            .collect();
        let keys = jose::KeySet::new(public);
        let options = VerifyOptions {
            issuer: Some(vec![ctx.core().issuer.clone()]),
            typ: Some("at+jwt".into()),
            required_claims: vec!["exp".into(), "client_id".into(), "sub".into()],
            ..VerifyOptions::default()
        };
        let claims = jose::verify_jwt(value, VerifyKey::Set(&keys), &options)
            .map_err(|_| OidcError::invalid_grant("The subject token is invalid."))?
            .payload;
        if claims
            .get("cnf")
            .and_then(|cnf| cnf.get("jkt"))
            .is_some_and(|jkt| truthy(Some(jkt)))
        {
            return Err(
                OidcError::invalid_grant("Sender-constrained tokens cannot be exchanged.").into(),
            );
        }
        let identity_id = match claims.get("identity_id") {
            Some(Value::String(id)) if claims.get("sub") == claims.get("client_id") => id.clone(),
            _ => js_string(claims.get("sub")),
        };
        let act = claims.get("act").filter(|act| truthy(Some(act))).cloned();
        return Ok(Subject {
            identity_id,
            client_id: js_string(claims.get("client_id")),
            scopes: match claims.get("scope") {
                Some(Value::String(scope)) => scope
                    .split(' ')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
                _ => Vec::new(),
            },
            expires_at: claims.get("exp").map(js::to_number).unwrap_or(f64::NAN),
            grant_id: None,
            personal: claims.get("sub") != claims.get("client_id") && act.is_none(),
            act,
            format: "jwt",
        });
    }
    let token = find_token(ctx, "AccessToken", value, false, false).await?;
    let Some(token) = token
        .filter(|token| !super::core::Core::is_expired(token) && truthy(token.get("accountId")))
    else {
        return Err(OidcError::invalid_grant("The subject token is invalid.").into());
    };
    if truthy(token.get("jkt")) || truthy(token.get("x5t#S256")) {
        return Err(
            OidcError::invalid_grant("Sender-constrained tokens cannot be exchanged.").into(),
        );
    }
    Ok(Subject {
        identity_id: text(token.get("accountId")),
        client_id: text(token.get("clientId")),
        scopes: text(token.get("scope"))
            .split(' ')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        expires_at: n(&token, "exp").unwrap_or_default(),
        grant_id: s(&token, "grantId")
            .filter(|id| !id.is_empty())
            .map(str::to_owned),
        act: token
            .get("extra")
            .and_then(|extra| extra.get("act"))
            .filter(|act| truthy(Some(act)))
            .cloned(),
        format: "opaque",
        personal: true,
    })
}

/// RFC 8693 token exchange for delegation (`registerTokenExchange`).
async fn token_exchange_grant(
    ctx: &mut Ctx<'_>,
    client: &Client,
    params: &mut Params,
) -> ProviderResult<()> {
    let value = |name: &str| -> ProviderResult<Option<String>> {
        match params.raw(name) {
            Some(Param::Many(_)) => Err(OidcError::invalid_request(format!(
                "{name} must be given at most once."
            ))
            .into()),
            Some(Param::One(value)) if !value.is_empty() => Ok(Some(value.clone())),
            _ => Ok(None),
        }
    };
    let subject_token = value("subject_token")?;
    let Some(subject_token) = subject_token.filter(|_| {
        value("subject_token_type").ok().flatten().as_deref() == Some(ACCESS_TOKEN_TYPE)
    }) else {
        return Err(OidcError::invalid_request(
            "subject_token must be an access token from this issuer.",
        )
        .into());
    };
    if let Some(requested) = value("requested_token_type")?
        && requested != ACCESS_TOKEN_TYPE
    {
        return Err(OidcError::invalid_request("Only access tokens can be requested.").into());
    }
    if value("actor_token")?.is_some() {
        return Err(OidcError::invalid_request(
            "actor_token is not supported; the client is the actor.",
        )
        .into());
    }
    let inner = ctx.inner;
    let store = inner.config.store.clone();
    let row = store.get("oauthClients", &hash(client.client_id())).await?;
    let Some(row) = row.filter(|row| !truthy(row.get("revoked"))) else {
        return Err(OidcError::invalid_client(Some("Client is unavailable.")).into());
    };
    if client.dpop_bound() {
        return Err(OidcError::invalid_request(
            "This client requires DPoP-bound tokens, which token exchange does not issue.",
        )
        .into());
    }
    let subject = exchanged_subject(ctx, &subject_token).await?;
    let tenant_id = text(row.get("tenantId"));
    let subject_row = store.get("oauthClients", &hash(&subject.client_id)).await?;
    if !subject_row.is_some_and(|subject_row| {
        !truthy(subject_row.get("revoked"))
            && s(&subject_row, "tenantId") == Some(tenant_id.as_str())
    }) {
        return Err(
            OidcError::invalid_grant("The subject token is not usable by this client.").into(),
        );
    }
    if subject.format == "jwt"
        && subject.personal
        && !inner
            .account_grants(&tenant_id, &subject.identity_id)
            .await?
            .iter()
            .any(|grant| {
                grant.summary.get("clientId").and_then(Value::as_str)
                    == Some(subject.client_id.as_str())
            })
    {
        return Err(OidcError::invalid_grant("The subject token was revoked.").into());
    }
    let identity = store.get("identities", &subject.identity_id).await?;
    let usable = match identity {
        Some(identity) => {
            s(&identity, "status") == Some("active")
                && s(&identity, "tenantId") == Some(tenant_id.as_str())
                && tenant_tree_active(store.as_ref(), &tenant_id).await?
        }
        None => false,
    };
    if !usable {
        return Err(
            OidcError::invalid_grant("The subject token is not usable by this client.").into(),
        );
    }
    let indicator = match value("resource")? {
        Some(resource) => Some(resource),
        None => value("audience")?,
    };
    let row_resources: Vec<String> = row
        .get("resources")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let server = indicator
        .as_ref()
        .and_then(|indicator| inner.core.resource_servers.get(indicator))
        .cloned();
    let (Some(indicator), Some(server)) = (
        indicator.filter(|indicator| row_resources.contains(indicator)),
        server,
    ) else {
        return Err(
            OidcError::invalid_target(Some("Name one resource this client may call.")).into(),
        );
    };
    let client_scopes: Vec<String> = client
        .scope()
        .unwrap_or_default()
        .split(' ')
        .map(str::to_owned)
        .collect();
    let allowed: Vec<String> = server
        .scopes
        .iter()
        .filter(|scope| client_scopes.contains(scope))
        .cloned()
        .collect();
    let scopes: Vec<String> = match value("scope")? {
        Some(scope) => scope
            .split(' ')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        None => allowed.clone(),
    };
    let refused: Vec<String> = scopes
        .iter()
        .filter(|scope| !allowed.contains(scope))
        .cloned()
        .collect();
    if !refused.is_empty() || scopes.is_empty() {
        return Err(OidcError::invalid_scope(
            "The requested scope is not allowed.",
            Some(refused.join(" ")),
        )
        .into());
    }
    let remaining = subject.expires_at - epoch();
    if remaining.is_nan() || remaining <= 0.0 {
        return Err(OidcError::invalid_grant("The subject token has expired.").into());
    }
    let request = TokenExchangeRequest {
        tenant_id: tenant_id.clone(),
        client_id: client.client_id().to_owned(),
        identity_id: subject.identity_id.clone(),
        subject_client_id: subject.client_id.clone(),
        subject_scopes: subject.scopes.clone(),
        resource: indicator.clone(),
        scopes: scopes.clone(),
    };
    if let Some(authorize) = &inner.config.authorize_token_exchange
        && !authorize(request).await?
    {
        return Err(OidcError::access_denied(Some("The token exchange is not permitted.")).into());
    }
    let mut act = Map::new();
    act.insert("sub".into(), json!(client.client_id()));
    if let Some(previous) = &subject.act {
        act.insert("act".into(), previous.clone());
    }
    ctx.exchange = Some((act, remaining));
    let mut token = Token::new("AccessToken", Some(client));
    token.set("accountId", Some(json!(subject.identity_id)));
    token.set(
        "grantId",
        Some(json!(subject.grant_id.clone().unwrap_or_default())),
    );
    token.set("gty", Some(json!("token_exchange")));
    token.set("scope", Some(json!(scopes.join(" "))));
    token.set_resource_server(ResourceServerInfo {
        identifier: indicator.clone(),
        scope: server.scopes.join(" "),
        audience: server.audience.clone().unwrap_or_else(|| indicator.clone()),
        access_token_ttl: server.access_token_ttl.unwrap_or(900.0),
        access_token_format: server
            .access_token_format
            .clone()
            .unwrap_or_else(|| "jwt".into()),
    });
    // An empty grant ID is kept as given (`grantId: subject.grantId ?? ''`).
    if subject.grant_id.is_none() {
        token.payload.insert("grantId".into(), json!(""));
    }
    let issued = save_token(ctx, &mut token, Some(client)).await?;
    let identity_id = subject.identity_id.clone();
    let client_id = client.client_id().to_owned();
    let tenant = tenant_id.clone();
    store
        .transaction(move |tx| async move {
            Inner::audit(
                tx.as_ref(),
                &tenant,
                &identity_id,
                "iam:oauth:TokenExchange",
                &client_id,
            )
            .await
        })
        .await?;
    ctx.out.json(&json!({
        "access_token": issued,
        "issued_token_type": ACCESS_TOKEN_TYPE,
        "token_type": "Bearer",
        "expires_in": num(token.expires_in.unwrap_or_default()),
        "scope": scopes.join(" "),
    }));
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Userinfo, introspection, revocation

/// `ctx.oidc.getAccessToken({ acceptDPoP: true })`.
fn get_access_token(ctx: &Ctx<'_>, body: Option<&RawParams>) -> ProviderResult<String> {
    let mut mechanisms: Vec<(&str, String)> = Vec::new();
    if let Some(Param::One(token)) = body.and_then(|body| body.get("access_token"))
        && !token.is_empty()
        && content_type_is(ctx.request, "application/x-www-form-urlencoded")
    {
        mechanisms.push(("body", token.clone()));
    }
    if let Some(header) = ctx
        .header("authorization")
        .filter(|header| !header.is_empty())
    {
        mechanisms.push(("header", header));
    }
    if let Some(Param::One(token)) = ctx.query.get("access_token")
        && !token.is_empty()
    {
        mechanisms.push(("query", token.clone()));
    }
    if mechanisms.is_empty() {
        return Err(OidcError::no_access_token().into());
    }
    if mechanisms.len() > 1 {
        return Err(OidcError::invalid_request(
            "access token must only be provided using one mechanism",
        )
        .into());
    }
    let (mechanism, token) = mechanisms.remove(0);
    if mechanism == "query" {
        return Err(OidcError::invalid_request(
            "access tokens must not be provided via query parameter",
        )
        .into());
    }
    let dpop = ctx.header("dpop").is_some_and(|value| !value.is_empty());
    if mechanism == "header" {
        let parts: Vec<&str> = token.split(' ').collect();
        if parts.len() != 2 {
            return Err(
                OidcError::invalid_request("invalid authorization header value format").into(),
            );
        }
        let scheme = parts[0].to_lowercase();
        if dpop && scheme != "dpop" {
            return Err(OidcError::invalid_request(
                "authorization header scheme must be `DPoP` when DPoP is used",
            )
            .into());
        } else if !dpop && scheme == "dpop" {
            return Err(OidcError::invalid_request("`DPoP` header not provided").into());
        } else if !dpop && scheme != "bearer" {
            return Err(
                OidcError::invalid_request("authorization header scheme must be `Bearer`").into(),
            );
        }
        return Ok(parts[1].to_owned());
    }
    if dpop {
        return Err(OidcError::invalid_request(
            "`DPoP` tokens must be provided via an authorization header",
        )
        .into());
    }
    Ok(token)
}

async fn userinfo_endpoint(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    ctx.out.set("cache-control", "no-store");
    ctx.parse_form()?;
    let mut params = ctx.params(&["scope", "access_token"]);
    let dupes = params.reject_dupes(&[], None);
    if !dupes.is_empty() {
        return Err(dupes_error(&dupes));
    }
    let body = ctx.body.clone();
    let value = get_access_token(ctx, body.as_ref())?;
    let dpop = validate_dpop(ctx, Some(&value)).await?;
    let token = find_token(ctx, "AccessToken", &value, false, false).await?;
    let Some(token) = token else {
        return Err(OidcError::invalid_token("access token not found").into());
    };
    let token_scopes = scope_set(s(&token, "scope"));
    if token_scopes.is_empty()
        || !token_scopes.iter().any(|scope| scope == "openid")
        || s(&token, "scope").is_none_or(str::is_empty)
    {
        return Err(OidcError::insufficient_scope(
            "access token missing openid scope",
            Some("openid".into()),
        )
        .into());
    }
    check_dpop_replay(
        ctx,
        dpop.as_ref(),
        s(&token, "clientId").unwrap_or_default(),
        token_error,
    )
    .await?;
    if dpop.is_some() && !truthy(token.get("jkt")) {
        return Err(OidcError::invalid_token(
            "access token is not sender-constrained but proof of possession was provided",
        )
        .into());
    }
    if let Some(jkt) = s(&token, "jkt")
        && dpop.as_ref().is_none_or(|proof| proof.thumbprint != jkt)
    {
        return Err(OidcError::invalid_token("failed jkt verification").into());
    }
    if token.get("aud").is_some() {
        return Err(OidcError::invalid_token(
            "token audience prevents accessing the userinfo endpoint",
        )
        .into());
    }
    if let Some(scope) = params.get("scope") {
        if !is_valid_scope(Some(scope)) {
            return Err(OidcError::invalid_request("scope contains invalid characters").into());
        }
        let missing: Vec<String> = scope
            .split(' ')
            .filter(|value| !token_scopes.iter().any(|s| s == value))
            .map(str::to_owned)
            .collect();
        if !missing.is_empty() {
            return Err(OidcError::insufficient_scope(
                "access token missing requested scope",
                Some(missing.join(" ")),
            )
            .into());
        }
    }
    let client = ctx
        .core()
        .find_client(s(&token, "clientId").unwrap_or_default())
        .await?;
    let Some(client) = client else {
        return Err(OidcError::invalid_token("associated client not found").into());
    };
    ctx.entities_client = Some(client.clone());
    check_client_cors(ctx, &client)?;
    let account = find_account(
        ctx.inner,
        Some(&client),
        s(&token, "accountId").unwrap_or_default(),
    )
    .await?;
    let Some(account) = account else {
        return Err(OidcError::invalid_token("associated account not found").into());
    };
    let grant = ctx
        .core()
        .find_model("Grant", s(&token, "grantId").unwrap_or_default(), true)
        .await?;
    let Some(grant) = grant else {
        return Err(OidcError::invalid_token("grant not found").into());
    };
    if super::core::Core::is_expired(&grant) {
        return Err(OidcError::invalid_token("grant is expired").into());
    }
    if s(&grant, "clientId") != s(&token, "clientId") {
        return Err(OidcError::invalid_token("clientId mismatch").into());
    }
    if s(&grant, "accountId") != s(&token, "accountId") {
        return Err(OidcError::invalid_token("accountId mismatch").into());
    }
    let claims = filter_claims(token.get("claims"), "userinfo", &grant);
    let rejected = grant_ops::rejected_oidc_claims(&grant);
    let filter: Vec<String> = scope_set(Some(
        params
            .get("scope")
            .map(str::to_owned)
            .unwrap_or_else(|| text(token.get("scope")))
            .as_str(),
    ));
    let scope = grant_ops::oidc_scope_filtered(&grant, &filter);
    let available = ctx_account_claims(ctx.inner, &account, &scope).await?;
    let result = ctx
        .core()
        .claims
        .result(&available, &scope, &claims, &rejected);
    ctx.out.json(&Value::Object(result));
    Ok(())
}

/// `findToken(provider, value, hint)`.
async fn find_any_token(
    ctx: &Ctx<'_>,
    value: &str,
    hint: Option<&str>,
) -> ProviderResult<Option<Map<String, Value>>> {
    async fn access(ctx: &Ctx<'_>, value: &str) -> ProviderResult<Option<Map<String, Value>>> {
        if let Some(token) = find_token(ctx, "AccessToken", value, false, false).await? {
            return Ok(Some(token));
        }
        ctx.core()
            .find_model("ClientCredentials", value, false)
            .await
    }
    match hint {
        Some("access_token" | "urn:ietf:params:oauth:token-type:access_token") => {
            if let Some(token) = access(ctx, value).await? {
                return Ok(Some(token));
            }
            find_token(ctx, "RefreshToken", value, false, false).await
        }
        Some("refresh_token" | "urn:ietf:params:oauth:token-type:refresh_token") => {
            if let Some(token) = find_token(ctx, "RefreshToken", value, false, false).await? {
                return Ok(Some(token));
            }
            access(ctx, value).await
        }
        _ => {
            if let Some(token) = access(ctx, value).await? {
                return Ok(Some(token));
            }
            find_token(ctx, "RefreshToken", value, false, false).await
        }
    }
}

fn token_is_valid(token: &Map<String, Value>) -> bool {
    !super::core::Core::is_expired(token)
        && !(matches!(s(token, "kind"), Some("RefreshToken")) && truthy(token.get("consumed")))
}

async fn introspection_endpoint(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    ctx.out.set("cache-control", "no-store");
    ctx.parse_form()?;
    let mut allow = vec!["token", "token_type_hint"];
    allow.extend(auth_params());
    let mut params = ctx.params(&allow);
    let client = authenticate_client(ctx, &mut params).await?;
    let dupes = params.reject_dupes(&[], None);
    if !dupes.is_empty() {
        return Err(dupes_error(&dupes));
    }
    presence(&params, &["token"])?;
    let value = params.get("token").unwrap_or_default().to_owned();
    if jose::decode_protected_header(&value).is_some() {
        return Err(OidcError::unsupported_token_type(
            "Structured JWT Tokens cannot be introspected via the introspection_endpoint",
        )
        .into());
    }
    let mut body = Map::new();
    body.insert("active".into(), json!(false));
    let token = find_any_token(ctx, &value, params.get("token_type_hint")).await?;
    let Some(token) = token.filter(token_is_valid) else {
        ctx.out.json(&Value::Object(body));
        return Ok(());
    };
    if let Some(grant_id) = s(&token, "grantId").filter(|id| !id.is_empty()) {
        let grant = ctx.core().find_model("Grant", grant_id, true).await?;
        let usable = grant.is_some_and(|grant| {
            !super::core::Core::is_expired(&grant)
                && grant.get("clientId") == token.get("clientId")
                && grant.get("accountId") == token.get("accountId")
        });
        if !usable {
            ctx.out.json(&Value::Object(body));
            return Ok(());
        }
    }
    if !matches!(
        s(&token, "kind"),
        Some("AccessToken" | "ClientCredentials" | "RefreshToken")
    ) {
        ctx.out.json(&Value::Object(body));
        return Ok(());
    }
    // allowedPolicy: the client may introspect its own tokens only.
    if Some(client.client_id()) != s(&token, "clientId") {
        ctx.out.json(&Value::Object(body));
        return Ok(());
    }
    if let Some(account) = s(&token, "accountId").filter(|id| !id.is_empty()) {
        body.insert("sub".into(), json!(account));
    }
    if let Some(Value::Object(extra)) = token.get("extra") {
        for (key, value) in extra {
            body.insert(key.clone(), value.clone());
        }
    }
    body.insert("active".into(), json!(true));
    let mut set = |key: &str, value: Option<Value>| {
        if let Some(value) = value.filter(|value| !value.is_null()) {
            body.insert(key.to_owned(), value);
        } else {
            body.shift_remove(key);
        }
    };
    set("client_id", token.get("clientId").cloned());
    set("exp", token.get("exp").cloned());
    set("iat", token.get("iat").cloned());
    set("sid", token.get("sid").cloned());
    set("iss", Some(json!(ctx.core().issuer)));
    set(
        "jti",
        token
            .get("jti")
            .filter(|jti| jti.as_str() != Some(value.as_str()))
            .cloned(),
    );
    set("aud", token.get("aud").cloned());
    set(
        "scope",
        token
            .get("scope")
            .filter(|scope| truthy(Some(scope)))
            .cloned(),
    );
    let sender = truthy(token.get("jkt")) || truthy(token.get("x5t#S256"));
    let mut cnf = Map::new();
    if let Some(jkt) = token.get("jkt").filter(|v| truthy(Some(v))) {
        cnf.insert("jkt".into(), jkt.clone());
    }
    set("cnf", sender.then_some(Value::Object(cnf)));
    let token_type = if s(&token, "kind") != Some("RefreshToken") {
        Some(json!(if truthy(token.get("jkt")) {
            "DPoP"
        } else {
            "Bearer"
        }))
    } else {
        None
    };
    set("token_type", token_type);
    ctx.out.json(&Value::Object(body));
    Ok(())
}

async fn revocation_endpoint(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    ctx.parse_form()?;
    let mut allow = vec!["token", "token_type_hint"];
    allow.extend(auth_params());
    let mut params = ctx.params(&allow);
    let client = authenticate_client(ctx, &mut params).await?;
    let dupes = params.reject_dupes(&[], None);
    if !dupes.is_empty() {
        return Err(dupes_error(&dupes));
    }
    presence(&params, &["token"])?;
    let value = params.get("token").unwrap_or_default().to_owned();
    if jose::decode_protected_header(&value).is_some() {
        return Err(OidcError::unsupported_token_type(
            "Structured JWT Tokens cannot be revoked via the revocation_endpoint",
        )
        .into());
    }
    ctx.out.status = Some(200);
    ctx.out.body = Some(Bytes::new());
    let token = find_any_token(ctx, &value, params.get("token_type_hint")).await?;
    let Some(token) = token else {
        return Ok(());
    };
    let kind = s(&token, "kind").unwrap_or_default().to_owned();
    if !["AccessToken", "ClientCredentials", "RefreshToken"].contains(&kind.as_str()) {
        return Ok(());
    }
    if Some(client.client_id()) != s(&token, "clientId") {
        return Ok(());
    }
    ctx.core()
        .adapter
        .model(&kind)
        .destroy(&text(token.get("jti")))
        .await?;
    if kind == "RefreshToken" || kind == "AccessToken" {
        revoke_grant(ctx, s(&token, "grantId"), kind != "AccessToken").await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Pushed authorization requests

async fn par_endpoint(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    ctx.out.set("cache-control", "no-store");
    ctx.parse_form()?;
    let mut allow: Vec<&str> = authorization_allow_list(&ctx.route);
    for param in auth_params() {
        if !allow.contains(&param) {
            allow.push(param);
        }
    }
    let mut auth_only = ctx.params(&auth_params());
    let client = authenticate_client(ctx, &mut auth_only).await?;
    let mut auth = Auth {
        params: ctx.params(&authorization_allow_list(&ctx.route)),
        client: Some(client.clone()),
        ..Auth::default()
    };
    let dupes = auth.params.reject_dupes(&["resource"], None);
    if !dupes.is_empty() {
        return Err(dupes_error(&dupes));
    }
    reject_unsupported(ctx, &auth.params)?;
    let remap = |error: ProviderError| -> ProviderError {
        match error {
            ProviderError::Oidc(mut oidc) if oidc.class == "InvalidRedirectUri" => {
                oidc.error = "invalid_request".into();
                ProviderError::Oidc(oidc)
            }
            other => other,
        }
    };
    let result: ProviderResult<()> = async {
        check_response_mode(&mut auth)?;
        one_redirect_uri_client(&mut auth);
        presence(&auth.params, &["response_type", "client_id"])?;
        if auth.params.has("registration") {
            return Err(OidcError::registration_not_supported().into());
        }
        check_response_type(&mut auth)?;
        presence(&auth.params, &["redirect_uri"])?;
        check_prompt(&auth.params)?;
        check_scope(ctx, &mut auth)?;
        check_openid_scope(ctx, &auth)?;
        check_redirect_uri(&mut auth)?;
        check_pkce(&auth.params)?;
        check_resource(ctx, &mut auth).await?;
        check_max_age(&mut auth.params)?;
        check_id_token_hint(ctx, &mut auth)?;
        // checkDpopJkt
        let dpop = validate_dpop(ctx, None).await?;
        if let Some(proof) = &dpop {
            check_dpop_replay(ctx, Some(proof), client.client_id(), request_error).await?;
            match auth.params.get("dpop_jkt") {
                Some(jkt) if jkt != proof.thumbprint => {
                    return Err(OidcError::invalid_request(
                        "DPoP proof key thumbprint does not match dpop_jkt",
                    )
                    .into());
                }
                Some(_) => {}
                None => auth.params.set("dpop_jkt", Some(proof.thumbprint.clone())),
            }
        }
        Ok(())
    }
    .await;
    result.map_err(remap)?;
    let now = epoch();
    let ttl = 60.0;
    let mut payload = auth.params.to_plain();
    payload.insert("iat".into(), num(now));
    payload.insert("iss".into(), json!(client.client_id()));
    payload.insert("aud".into(), json!(ctx.core().issuer));
    payload.insert("exp".into(), num(now + ttl));
    payload.insert("nbf".into(), num(now));
    let request = format!(
        "{}.{}.",
        jose::b64url(br#"{"alg":"none"}"#),
        jose::b64url(js::stringify(&Value::Object(payload)).as_bytes())
    );
    let mut record = Map::new();
    record.insert("request".into(), json!(request));
    if let Some(jkt) = auth.params.get("dpop_jkt") {
        record.insert("dpopJkt".into(), json!(jkt));
    }
    record.insert(
        "trusted".into(),
        json!(client.auth_method() != "none" || !auth.trusted.is_empty()),
    );
    let id = ctx
        .core()
        .save_model("PushedAuthorizationRequest", &mut record, ttl)
        .await?;
    ctx.out.status = Some(201);
    ctx.out.json(
        &json!({ "expires_in": num(ttl), "request_uri": format!("{PUSHED_REQUEST_URN}{id}") }),
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Device flow

const BASE20: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

fn generate_user_code() -> String {
    let mask = "****-****";
    let mut out = String::new();
    for c in mask.chars() {
        if c == '*' {
            let index = loop {
                let byte = rand::random::<u8>() & 31;
                if (byte as usize) < BASE20.len() {
                    break byte as usize;
                }
            };
            out.push(BASE20[index] as char);
        } else {
            out.push(c);
        }
    }
    out
}

fn normalize_user_code(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

fn denormalize_user_code(normalized: &str) -> String {
    let mut chars = normalized.chars();
    "****-****"
        .chars()
        .map(|c| {
            if c == '*' {
                chars.next().unwrap_or_default()
            } else {
                c
            }
        })
        .collect()
}

async fn device_authorization_endpoint(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    ctx.out.set("cache-control", "no-store");
    ctx.parse_form()?;
    let mut auth_only = ctx.params(&auth_params());
    let client = authenticate_client(ctx, &mut auth_only).await?;
    if let Some(body) = ctx.body.as_mut()
        && !matches!(body.get("client_id"), Some(Param::One(value)) if !value.is_empty())
    {
        body.insert(
            "client_id".into(),
            Param::One(client.client_id().to_owned()),
        );
    }
    let mut auth = Auth {
        params: ctx.params(&authorization_allow_list(&ctx.route)),
        ..Auth::default()
    };
    let dupes = auth.params.reject_dupes(&["resource"], None);
    if !dupes.is_empty() {
        return Err(dupes_error(&dupes));
    }
    reject_unsupported(ctx, &auth.params)?;
    check_client(ctx, &mut auth).await?;
    let client = auth.client.clone().expect("client loaded");
    if !client.grant_type_allowed(DEVICE_CODE) {
        return Err(OidcError::invalid_request(format!(
            "{DEVICE_CODE} is not allowed for this client"
        ))
        .into());
    }
    if auth.params.has("registration") {
        return Err(OidcError::registration_not_supported().into());
    }
    check_scope(ctx, &mut auth)?;
    check_openid_scope(ctx, &auth)?;
    check_resource(ctx, &mut auth).await?;
    check_max_age(&mut auth.params)?;
    check_id_token_hint(ctx, &mut auth)?;
    let user_code = generate_user_code();
    let mut code = Token::new("DeviceCode", Some(&client));
    code.set(
        "deviceInfo",
        Some(json!({
            "ip": ctx.header("x-forwarded-for").filter(|_| ctx.inner.config.trust_proxy).map(|value| value.split(',').next().unwrap_or_default().trim().to_owned()),
            "ua": ctx.header("user-agent"),
        })),
    );
    code.set("params", Some(Value::Object(auth.params.to_plain())));
    code.set("userCode", Some(json!(normalize_user_code(&user_code))));
    let device_code = save_token(ctx, &mut code, Some(&client)).await?;
    let verification = ctx.url_for("code_verification", None);
    let complete = format!(
        "{verification}?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("user_code", &user_code)
            .finish()
    );
    ctx.out.json(&json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification,
        "verification_uri_complete": complete,
        "expires_in": num(code.expires_in.unwrap_or(600.0)),
    }));
    Ok(())
}

fn user_code_input_form(action: &str, secret: &str, code: Option<&str>) -> String {
    format!(
        "<form id=\"op.deviceInputForm\" novalidate method=\"post\" action=\"{action}\">\n  <input type=\"hidden\" name=\"xsrf\" value=\"{secret}\"/>\n  <input\n    {}type=\"text\" name=\"user_code\" placeholder=\"Enter code\" onfocus=\"this.select(); this.onfocus = undefined;\" autofocus autocomplete=\"off\"></input>\n  </form>",
        code.map(|code| format!("value=\"{}\" ", html_safe(code)))
            .unwrap_or_default()
    )
}

fn user_code_confirm_form(action: &str, secret: &str, code: &str) -> String {
    format!(
        "<form id=\"op.deviceConfirmForm\" method=\"post\" action=\"{action}\">\n<input type=\"hidden\" name=\"xsrf\" value=\"{secret}\"/>\n<input type=\"hidden\" name=\"user_code\" value=\"{}\"/>\n<input type=\"hidden\" name=\"confirm\" value=\"yes\"/>\n</form>",
        html_safe(code)
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A re-rendered user code page (`ReRenderError`).
async fn rerender(ctx: &mut Ctx<'_>, user_code: Option<&str>) -> ProviderResult<()> {
    let secret = hex(&rand::random::<[u8; 24]>());
    ctx.session
        .as_mut()
        .expect("session loaded")
        .set("state", json!({ "secret": secret }));
    let action = ctx.url_for("code_verification", None);
    let page = (ctx.inner.config.render_device_page)(DevicePageInput {
        kind: "input".into(),
        form: user_code_input_form(&action, &secret, user_code),
        user_code: None,
        client_name: None,
    })
    .await?;
    ctx.out.status = Some(200);
    ctx.out.html(page);
    Ok(())
}

async fn device_user_flow(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    load_session(ctx).await?;
    if matches!(ctx.route, Route::CodeVerification) && ctx.method == "GET" {
        let params = ctx.params(&["user_code"]);
        let secret = hex(&rand::random::<[u8; 24]>());
        ctx.session
            .as_mut()
            .expect("session loaded")
            .set("state", json!({ "secret": secret }));
        let action = ctx.url_for("code_verification", None);
        if let Some(code) = params.get("user_code") {
            form_post(
                &mut ctx.out,
                &action,
                &[("xsrf", secret), ("user_code", code.to_owned())],
            );
        } else {
            let page = (ctx.inner.config.render_device_page)(DevicePageInput {
                kind: "input".into(),
                form: user_code_input_form(&action, &secret, None),
                user_code: None,
                client_name: None,
            })
            .await?;
            ctx.out.html(page);
        }
        return Ok(());
    }
    let mut auth = Auth::default();
    let mut device_code: Option<Map<String, Value>> = None;
    let outcome: ProviderResult<()> = async {
        if let Route::DeviceResume(uid) = ctx.route.clone() {
            if !resume(ctx, &mut auth, &uid).await? {
                return Ok(());
            }
            let device = auth
                .interaction
                .as_ref()
                .and_then(|interaction| s(interaction, "deviceCode"))
                .unwrap_or_default()
                .to_owned();
            let code = find_token(ctx, "DeviceCode", &device, true, true).await?;
            let Some(code) = code else {
                return rerender(ctx, None).await;
            };
            if super::core::Core::is_expired(&code)
                || truthy(code.get("error"))
                || truthy(code.get("accountId"))
            {
                return rerender(ctx, None).await;
            }
            device_code = Some(code.clone());
            auth.device_code = Some(code);
        } else {
            ctx.parse_form()?;
            let mut params = ctx.params(&["xsrf", "user_code", "confirm", "abort"]);
            let dupes = params.reject_dupes(&[], None);
            if !dupes.is_empty() {
                return Err(dupes_error(&dupes));
            }
            let session = ctx.session.as_ref().expect("session loaded");
            let Some(state) = session
                .payload
                .get("state")
                .filter(|state| truthy(Some(state)))
            else {
                return Err(
                    OidcError::invalid_request("could not find device form details").into(),
                );
            };
            if !jose::constant_equals(
                &text(state.get("secret")),
                params.get("xsrf").unwrap_or_default(),
            ) {
                return Err(OidcError::invalid_request("xsrf token invalid").into());
            }
            let Some(user_code) = params.get("user_code").map(str::to_owned) else {
                return rerender(ctx, None).await;
            };
            let normalized = normalize_user_code(&user_code);
            let stored = ctx
                .core()
                .adapter
                .model("DeviceCode")
                .find_by_user_code(&normalized)
                .await?;
            let code = stored
                .and_then(|stored| super::core::verify_stored("DeviceCode", stored, true))
                .filter(|code| jose::constant_equals(&normalized, &text(code.get("userCode"))));
            let Some(mut code) = code else {
                return rerender(ctx, Some(&user_code)).await;
            };
            if super::core::Core::is_expired(&code)
                || truthy(code.get("error"))
                || truthy(code.get("accountId"))
                || truthy(code.get("inFlight"))
            {
                return rerender(ctx, Some(&user_code)).await;
            }
            let client = ctx
                .core()
                .find_client(s(&code, "clientId").unwrap_or_default())
                .await?;
            if params.has("abort") {
                code.insert("error".into(), json!("access_denied"));
                code.insert(
                    "errorDescription".into(),
                    json!("End-User aborted interaction"),
                );
                save_stored_token(ctx, "DeviceCode", &mut code).await?;
                return rerender(ctx, None).await;
            }
            if !params.has("confirm") {
                let Some(client) = client else {
                    return Err(OidcError::invalid_client(Some("client is invalid")).into());
                };
                let action = ctx.url_for("code_verification", None);
                let secret = text(state.get("secret"));
                let page = (ctx.inner.config.render_device_page)(DevicePageInput {
                    kind: "confirm".into(),
                    form: user_code_confirm_form(&action, &secret, &user_code),
                    user_code: Some(denormalize_user_code(&normalized)),
                    client_name: client.client_name().map(str::to_owned),
                })
                .await?;
                ctx.out.html(page);
                return Ok(());
            }
            code.insert("inFlight".into(), json!(true));
            save_stored_token(ctx, "DeviceCode", &mut code).await?;
            ctx.session
                .as_mut()
                .expect("session loaded")
                .set("state", Value::Null);
            params.remove("xsrf");
            let stored_params = code
                .get("params")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let mut raw = RawParams::new();
            for (key, value) in &stored_params {
                if let Some(param) = Param::from_value(value) {
                    raw.insert(key.clone(), param);
                }
            }
            auth.params = Params::new(&authorization_allow_list(&ctx.route), &raw);
            device_code = Some(code.clone());
            auth.device_code = Some(code);
        }
        check_client(ctx, &mut auth).await?;
        check_resource(ctx, &mut auth).await?;
        assign_claims(&mut auth);
        load_account(ctx, &mut auth).await?;
        load_grant(ctx, &mut auth).await?;
        if !interactions(ctx, &mut auth).await? {
            return Ok(());
        }
        device_verification_response(ctx, &mut auth).await
    }
    .await;
    if let Err(error) = outcome {
        // deviceUserFlowErrors: the device code learns the error.
        let mut code = device_code;
        if code.is_none()
            && let Some(device) = auth
                .interaction
                .as_ref()
                .and_then(|interaction| s(interaction, "deviceCode"))
                .map(str::to_owned)
        {
            code = find_token(ctx, "DeviceCode", &device, true, true)
                .await
                .ok()
                .flatten();
        }
        if let Some(mut code) = code {
            let out = error.out(None);
            code.insert(
                "error".into(),
                out.get("error").cloned().unwrap_or(Value::Null),
            );
            code.insert(
                "errorDescription".into(),
                out.get("error_description").cloned().unwrap_or(Value::Null),
            );
            let _ = save_stored_token(ctx, "DeviceCode", &mut code).await;
            if matches!(&error, ProviderError::Oidc(oidc) if oidc.class == "AccessDenied") {
                return rerender(ctx, None).await;
            }
        }
        return Err(error);
    }
    Ok(())
}

/// Saves a loaded token payload back (`code.save()`): its remaining lifetime is kept.
async fn save_stored_token(
    ctx: &Ctx<'_>,
    model: &str,
    payload: &mut Map<String, Value>,
) -> ProviderResult<()> {
    let ttl = n(payload, "exp").map(|exp| exp - epoch()).unwrap_or(600.0);
    let jti = text(payload.get("jti"));
    let stored = super::core::stored_payload(payload);
    ctx.core()
        .adapter
        .model(model)
        .upsert(&jti, &stored, Some(ttl))
        .await
}

async fn device_verification_response(ctx: &mut Ctx<'_>, auth: &mut Auth) -> ProviderResult<()> {
    let client = auth.client.clone().expect("client loaded");
    let grant = auth.grant.clone().unwrap_or_default();
    let requested = request_scopes(&auth.params);
    let mut combined: Vec<String> = Vec::new();
    for scope in grant_ops::oidc_scope_filtered(&grant, &requested)
        .split(' ')
        .filter(|s| !s.is_empty())
    {
        if !combined.iter().any(|existing| existing == scope) {
            combined.push(scope.to_owned());
        }
    }
    for indicator in auth.resource_servers.keys() {
        for scope in grant_ops::resource_scope_filtered(&grant, indicator, &requested)
            .split(' ')
            .filter(|s| !s.is_empty())
        {
            if !combined.iter().any(|existing| existing == scope) {
                combined.push(scope.to_owned());
            }
        }
    }
    let mut code = auth.device_code.clone().unwrap_or_default();
    let session = ctx.session.as_mut().expect("session loaded");
    let mut set = |key: &str, value: Option<Value>| match value.filter(|value| !value.is_null()) {
        Some(value) => {
            code.insert(key.to_owned(), value);
        }
        None => {
            code.shift_remove(key);
        }
    };
    set("accountId", session.account_id().map(Value::String));
    set("acr", session.payload.get("acr").cloned());
    set("amr", session.payload.get("amr").cloned());
    set("authTime", session.payload.get("loginTs").cloned());
    set(
        "claims",
        (!auth.claims.is_empty()).then(|| Value::Object(auth.claims.clone())),
    );
    set(
        "grantId",
        session.grant_id_for(client.client_id()).map(Value::String),
    );
    set("scope", Some(json!(combined.join(" "))));
    set("sessionUid", Some(json!(session.uid())));
    let resources: Vec<String> = auth.resource_servers.keys().cloned().collect();
    match resources.len() {
        0 => set("resource", None),
        1 => set("resource", Some(json!(resources[0]))),
        _ => set("resource", Some(json!(resources))),
    }
    if !combined.iter().any(|scope| scope == "offline_access") {
        set("expiresWithSession", Some(json!(true)));
    } else {
        session.set_authorization(client.client_id(), "persistsLogout", json!(true));
    }
    if client.include_sid() {
        let sid = session.sid_for(client.client_id());
        code.insert("sid".into(), sid.map(Value::String).unwrap_or(Value::Null));
    }
    save_stored_token(ctx, "DeviceCode", &mut code).await?;
    let page = (ctx.inner.config.render_device_page)(DevicePageInput {
        kind: "success".into(),
        form: String::new(),
        user_code: None,
        client_name: None,
    })
    .await?;
    ctx.out.html(page);
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// RP-initiated logout

async fn end_session(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    ctx.out.set("cache-control", "no-store");
    load_session(ctx).await?;
    let mut params = ctx.params(&[
        "id_token_hint",
        "post_logout_redirect_uri",
        "state",
        "ui_locales",
        "client_id",
        "logout_hint",
    ]);
    let dupes = params.reject_dupes(&[], None);
    if !dupes.is_empty() {
        return Err(dupes_error(&dupes));
    }
    let mut client: Option<Client> = None;
    if let Some(hint) = params.get("id_token_hint").map(str::to_owned) {
        let decoded = jose::decode(&hint)
            .map_err(|_| OidcError::invalid_request("could not decode id_token_hint"))?;
        let client_id = js_string(decoded.payload.get("aud"));
        if let Some(param) = params.get("client_id")
            && param != client_id
        {
            return Err(OidcError::invalid_request(
                "client_id does not match the provided id_token_hint",
            )
            .into());
        }
        let found = ctx.core().find_client(&client_id).await?;
        let Some(found) = found else {
            return Err(
                OidcError::invalid_client(Some("unrecognized id_token_hint audience")).into(),
            );
        };
        validate_id_token(ctx, &hint, &found)
            .map_err(|_| OidcError::invalid_request("could not validate id_token_hint"))?;
        client = Some(found);
    } else if let Some(client_id) = params.get("client_id").map(str::to_owned) {
        let found = ctx.core().find_client(&client_id).await?;
        let Some(found) = found else {
            return Err(OidcError::invalid_client(Some("client is invalid")).into());
        };
        client = Some(found);
    }
    if let Some(client) = &client
        && let Some(uri) = params.get("post_logout_redirect_uri")
    {
        if !client.post_logout_redirect_uri_allowed(uri) {
            return Err(
                OidcError::invalid_request("post_logout_redirect_uri not registered").into(),
            );
        }
    } else if params.has("post_logout_redirect_uri") {
        params.remove("post_logout_redirect_uri");
    }
    let secret = hex(&rand::random::<[u8; 24]>());
    let mut state = Map::new();
    state.insert("secret".into(), json!(secret));
    if let Some(client) = &client {
        state.insert("clientId".into(), json!(client.client_id()));
    }
    if let Some(value) = params.get("state") {
        state.insert("state".into(), json!(value));
    }
    if let Some(uri) = params.get("post_logout_redirect_uri") {
        state.insert("postLogoutRedirectUri".into(), json!(uri));
    }
    let session = ctx.session.as_mut().expect("session loaded");
    session.set("state", Value::Object(state));
    let logged_in = session.account_id().is_some();
    let action = ctx.url_for("end_session_confirm", None);
    if logged_in {
        ctx.out.status = Some(200);
        let form = format!(
            "<form id=\"op.logoutForm\" method=\"post\" action=\"{action}\"><input type=\"hidden\" name=\"xsrf\" value=\"{secret}\"/></form>"
        );
        let page = (ctx.inner.config.render_logout_page)(form).await?;
        ctx.out.html(page);
    } else {
        form_post(
            &mut ctx.out,
            &action,
            &[("xsrf", secret), ("logout", "yes".into())],
        );
    }
    Ok(())
}

/// `client.backchannelLogout(sub, sid)`: a signed logout token POSTed to the client.
pub(crate) async fn backchannel_logout(
    inner: &Inner,
    client: &Client,
    sub: &str,
    sid: &str,
) -> ProviderResult<()> {
    let mut payload = Map::new();
    payload.insert("sub".into(), json!(sub));
    payload.insert(
        "events".into(),
        json!({ "http://schemas.openid.net/event/backchannel-logout": {} }),
    );
    payload.insert("jti".into(), json!(nanoid(21)));
    if client.backchannel_session_required() {
        payload.insert("sid".into(), json!(sid));
    }
    let token = sign_id_token(&inner.core, client, payload, "logout")?;
    let uri = client
        .backchannel_logout_uri()
        .unwrap_or_default()
        .to_owned();
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("logout_token", &token)
        .finish();
    let fetch = super::outbound_fetch(&inner.core);
    let response = fetch
        .fetch(
            FetchRequest::new(uri.clone(), "POST", Some(FetchBody::Text(body)))
                .header("content-type", "application/x-www-form-urlencoded")
                .redirect(RedirectMode::Manual),
        )
        .await
        .map_err(|error| server_error(&error.to_string()))?;
    if response.status != 200 && response.status != 204 {
        return Err(server_error(&format!(
            "expected 200 OK from {uri}, got: {}",
            response.status
        )));
    }
    Ok(())
}

async fn end_session_confirm(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    ctx.out.set("cache-control", "no-store");
    load_session(ctx).await?;
    ctx.parse_form()?;
    let mut params = ctx.params(&["xsrf", "logout"]);
    let dupes = params.reject_dupes(&[], None);
    if !dupes.is_empty() {
        return Err(dupes_error(&dupes));
    }
    let session = ctx.session.as_ref().expect("session loaded");
    let Some(state) = session
        .payload
        .get("state")
        .and_then(Value::as_object)
        .cloned()
    else {
        return Err(OidcError::invalid_request("could not find logout details").into());
    };
    if !jose::constant_equals(
        &text(state.get("secret")),
        params.get("xsrf").unwrap_or_default(),
    ) {
        return Err(OidcError::invalid_request("xsrf token invalid").into());
    }
    let logout = params.has("logout");
    let state_client = s(&state, "clientId").map(str::to_owned);
    let authorizations: Vec<String> = session
        .payload
        .get("authorizations")
        .and_then(Value::as_object)
        .map(|value| value.keys().cloned().collect())
        .unwrap_or_default();
    let account = session.account_id().unwrap_or_default();
    for client_id in &authorizations {
        if logout || Some(client_id) == state_client.as_ref() {
            let client = ctx.core().find_client(client_id).await.ok().flatten();
            if let Some(client) = client
                && client.backchannel_logout_uri().is_some()
            {
                let sid = ctx
                    .session
                    .as_ref()
                    .and_then(|session| session.sid_for(client_id))
                    .unwrap_or_default();
                let _ = backchannel_logout(ctx.inner, &client, &account, &sid).await;
            }
        }
    }
    let session = ctx.session.clone().expect("session loaded");
    if logout {
        if let Some(Value::Object(authorizations)) = session.payload.get("authorizations") {
            for value in authorizations.values() {
                let persists = value.get("persistsLogout") == Some(&Value::Bool(true));
                if let Some(grant_id) = value.get("grantId").and_then(Value::as_str)
                    && !persists
                {
                    revoke_grant(ctx, Some(grant_id), true).await?;
                }
            }
        }
        ctx.core()
            .adapter
            .model("Session")
            .destroy(&session.id())
            .await?;
        if let Some(session) = ctx.session.as_mut() {
            session.destroyed = true;
        }
        let options = ctx.cookie_options();
        ctx.set_cookie("_session", None, &options);
    } else if let Some(client_id) = &state_client {
        let persists = session
            .payload
            .get("authorizations")
            .and_then(|value| value.get(client_id))
            .and_then(|value| value.get("persistsLogout"))
            == Some(&Value::Bool(true));
        if let Some(grant_id) = session.grant_id_for(client_id)
            && !persists
        {
            revoke_grant(ctx, Some(&grant_id), true).await?;
        }
        let session = ctx.session.as_mut().expect("session loaded");
        session.set("state", Value::Null);
        if let Some(Value::Object(authorizations)) = session.payload.get_mut("authorizations") {
            authorizations.shift_remove(client_id);
        }
        session.reset_identifier();
    }
    let post_logout = s(&state, "postLogoutRedirectUri").map(str::to_owned);
    let forward = post_logout.is_none() && !logout && state_client.is_some();
    let mut payload: Vec<(String, String)> = Vec::new();
    if post_logout.is_some()
        && let Some(value) = state.get("state").filter(|value| !value.is_null())
    {
        payload.push(("state".into(), js_string(Some(value))));
    }
    if forward && let Some(client_id) = &state_client {
        payload.push(("client_id".into(), client_id.clone()));
    }
    let base = post_logout.unwrap_or_else(|| ctx.url_for("end_session_success", None));
    ctx.out.status = Some(303);
    ctx.out.redirect(&redirect_with_query(&base, &payload));
    Ok(())
}

async fn end_session_success(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    ctx.out.set("cache-control", "no-store");
    let params = ctx.params(&["client_id"]);
    let mut display: Option<String> = None;
    if let Some(client_id) = params.get("client_id") {
        let client = ctx.core().find_client(client_id).await?;
        let Some(client) = client else {
            return Err(OidcError::invalid_client(Some("client is invalid")).into());
        };
        display = Some(
            client
                .client_name()
                .unwrap_or(client.client_id())
                .to_owned(),
        );
    }
    let safe = display
        .map(|display| format!("with {}", html_safe(&display)))
        .unwrap_or_default();
    ctx.out.html(format!(
        "<!DOCTYPE html>\n    <html>\n    <head>\n      <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n      <meta charset=\"utf-8\">\n      <title>Sign-out Success</title>\n      <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n    </head>\n    <body>\n      <div class=\"container\">\n        <h1>Sign-out Success</h1>\n        <p>Your sign-out {safe} was successful.</p>\n      </div>\n    </body>\n    </html>"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Dynamic registration

/// The registration gate: a live registration token, or a request the `anonymous` hook maps to a tenant.
/// `Ok(None)` when the gate answered (refused).
async fn registration_gate(ctx: &mut Ctx<'_>) -> ProviderResult<Option<RegistrationContext>> {
    let inner = ctx.inner;
    let refuse = |ctx: &mut Ctx<'_>, description: &str| {
        ctx.out.status = Some(401);
        ctx.out
            .set("www-authenticate", "Bearer error=\"invalid_token\"");
        ctx.out.set("cache-control", "no-store");
        ctx.out
            .json(&json!({ "error": "invalid_token", "error_description": description }));
    };
    let header = ctx
        .header("authorization")
        .filter(|header| !header.is_empty());
    let context = if let Some(header) = header {
        let pattern = regex::Regex::new(r"^Bearer ([A-Za-z0-9_-]{20,200})$").expect("valid regex");
        let record = match pattern.captures(&header) {
            Some(captures) => {
                inner
                    .config
                    .store
                    .get("oauthRegistrationTokens", &hash(&captures[1]))
                    .await?
            }
            None => None,
        };
        let Some(record) = record.filter(Inner::usable_registration_token) else {
            refuse(
                ctx,
                "The registration token is invalid, expired, or used up.",
            );
            return Ok(None);
        };
        RegistrationContext {
            tenant_id: text(record.get("tenantId")),
            scopes: record
                .get("scopes")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            resources: record
                .get("resources")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            allow_confidential: record.get("allowConfidential") == Some(&Value::Bool(true)),
            max_clients: n(&record, "maxClients").unwrap_or_default(),
            token_id: Some(text(record.get("id"))),
            actor_id: text(record.get("createdBy")),
        }
    } else {
        let anonymous = inner
            .config
            .registration
            .as_ref()
            .and_then(|registration| registration.anonymous.clone());
        let policy = match anonymous {
            Some(hook) => {
                let headers = ctx
                    .request
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .to_str()
                            .ok()
                            .map(|value| (name.as_str().to_owned(), value.to_owned()))
                    })
                    .collect();
                hook(super::AnonymousRegistrationRequest {
                    headers,
                    ip: ctx
                        .header("x-forwarded-for")
                        .filter(|_| inner.config.trust_proxy)
                        .map(|value| {
                            value
                                .split(',')
                                .next()
                                .unwrap_or_default()
                                .trim()
                                .to_owned()
                        }),
                })
                .await?
            }
            None => None,
        };
        let Some(policy) = policy else {
            refuse(ctx, "Registration requires a registration token.");
            return Ok(None);
        };
        let mut context = inner.registration_limits(&policy)?;
        context.actor_id = "dynamic-registration".into();
        context
    };
    if !tenant_tree_active(inner.config.store.as_ref(), &context.tenant_id).await? {
        refuse(ctx, "The tenant is unavailable.");
        return Ok(None);
    }
    Ok(Some(context))
}

/// `applyRegistrationPolicy(client, registering)`.
fn apply_registration_policy(
    client: &mut Map<String, Value>,
    registering: &RegistrationContext,
) -> Result<(), OidcError> {
    let refuse = |message: &str| Err(OidcError::invalid_client_metadata(message));
    client.insert("tenant_id".into(), json!(registering.tenant_id));
    let grant_types: Vec<Value> = match client.get("grant_types") {
        Some(Value::Array(values)) => values.clone(),
        _ => vec![json!("authorization_code")],
    };
    if grant_types.iter().any(|grant| {
        grant.as_str() != Some("authorization_code") && grant.as_str() != Some("refresh_token")
    }) {
        return refuse(
            "Registered clients may use only the authorization_code and refresh_token grants.",
        );
    }
    let method = match client.get("token_endpoint_auth_method") {
        Some(Value::Null) | None => "client_secret_basic".to_owned(),
        Some(value) => js_string(Some(value)),
    };
    if method != "none" && !registering.allow_confidential {
        return refuse(
            "Only public clients (token_endpoint_auth_method \"none\") may register here.",
        );
    }
    if !["none", "client_secret_basic", "client_secret_post"].contains(&method.as_str()) {
        return refuse("Unsupported token_endpoint_auth_method for dynamic registration.");
    }
    for key in [
        "jwks",
        "jwks_uri",
        "sector_identifier_uri",
        "backchannel_logout_uri",
        "request_uris",
        "initiate_login_uri",
        "access_token_ttl",
        "refresh_token_ttl",
    ] {
        if client.contains_key(key) {
            return Err(OidcError::invalid_client_metadata(format!(
                "{key} cannot be registered dynamically."
            )));
        }
    }
    let mut uris: Vec<Value> = client
        .get("redirect_uris")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    uris.extend(
        client
            .get("post_logout_redirect_uris")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );
    let custom = regex::Regex::new(r"^[a-z][a-z0-9+-]*(\.[a-z0-9+-]+)+:$").expect("valid regex");
    for uri in uris {
        let Ok(parsed) = url::Url::parse(&js_string(Some(&uri))) else {
            return refuse("Redirect URIs must be absolute.");
        };
        let protocol = format!("{}:", parsed.scheme());
        let acceptable = parsed.fragment().is_none()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && (protocol == "https:"
                || (protocol == "http:"
                    && ["localhost", "127.0.0.1", "[::1]"]
                        .contains(&super::core::hostname(&parsed).as_str()))
                || custom.is_match(&protocol));
        if !acceptable {
            return refuse(
                "Redirect URIs must use HTTPS, loopback HTTP, or a reverse-domain custom scheme.",
            );
        }
    }
    let requested: Vec<String> = match client.get("scope") {
        Some(Value::String(scope)) => scope
            .split(' ')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    if requested.is_empty() {
        client.insert("scope".into(), json!(registering.scopes.join(" ")));
    } else if requested
        .iter()
        .any(|scope| !registering.scopes.contains(scope))
    {
        return refuse("The requested scope is not allowed for this registration.");
    }
    Ok(())
}

async fn registration_endpoint(ctx: &mut Ctx<'_>) -> ProviderResult<()> {
    ctx.out.set("cache-control", "no-store");
    if content_type_is(ctx.request, "application/json") {
        let body = js::parse(&String::from_utf8_lossy(&ctx.raw_body))
            .map_err(|_| OidcError::invalid_request("failed to parse the request body"))?;
        ctx.json_body = Some(body);
    } else if ctx.header("content-type").is_some() {
        return Err(OidcError::invalid_request(format!(
            "only application/json content-type bodies are supported on {} {}",
            ctx.method, ctx.path
        ))
        .into());
    } else {
        ctx.json_body = Some(json!({}));
    }
    let Some(Value::Object(body)) = ctx.json_body.clone() else {
        return Err(OidcError::invalid_request(
            "client registration request must be a JSON object",
        )
        .into());
    };
    let client_id = nanoid(21);
    let mut properties = body.clone();
    properties.insert("client_id".into(), json!(client_id));
    properties.insert("client_id_issued_at".into(), num(epoch()));
    let secret_required = super::core::needs_secret(&properties);
    if secret_required {
        let mut bytes = rand::random::<[u8; 32]>().to_vec();
        bytes.extend_from_slice(&rand::random::<[u8; 32]>());
        properties.insert("client_secret".into(), json!(jose::b64url(&bytes)));
        properties.insert("client_secret_expires_at".into(), json!(0));
    } else {
        properties.shift_remove("client_secret");
        properties.shift_remove("client_secret_expires_at");
    }
    let registering = ctx.inner.registering();
    let mut validator = |key: &str, client: &mut Map<String, Value>| -> Result<(), OidcError> {
        if key == "tenant_id"
            && let Some(context) = &registering
        {
            return apply_registration_policy(client, context);
        }
        super::core::plain_validator(key, client)
    };
    let client = super::core::build_client(ctx.core(), &properties, &mut validator)?;
    ctx.core()
        .adapter
        .model("Client")
        .upsert(&client_id, &client.metadata, None)
        .await?;
    ctx.out.status = Some(201);
    ctx.out.json(&Value::Object(client.metadata.clone()));
    Ok(())
}
