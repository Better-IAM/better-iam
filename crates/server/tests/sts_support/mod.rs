//! Port of `tests/support/organization.ts` for the temporary-credential suites: a bootstrapped platform with one
//! organization ("Acme") whose owner accepted the invitation, a controllable clock, seven-day sessions, an email
//! inbox, and the request helpers the TypeScript tests share (`rowOf`, `patch`, `allowed`, `post`, `totp`).
//!
//! Calls into modules other units are still porting answer `NOT_IMPLEMENTED`; the `ok!`/`fails!` macros (defined in
//! `tests/sts.rs`) skip the rest of a test then, so the suites run in full once those units land. The one exception
//! is the owner's acceptance of the invitation (`tenants.acceptInvitation`, `flows.ts`): while it is a stub the
//! fixture completes it as `acceptOwnerInvitation` does (owner identity, Owner role and binding, tenant activated,
//! invitation consumed, password session), so tests reach the code under test.

#![allow(dead_code)]

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_auth::service::mfa::ConfirmMfaInput;
use better_iam_auth::{DeliveryMessage, MfaCredential, SignInResult, delivery_fn, totp as otp};
use better_iam_core::{
    AuthMethod, CredentialInput, Filter, FindOptions, IamError, IamResult, IamStore, IamStoreExt,
    PermissionsConfig, Record, Tenant,
};
use better_iam_server::api::{Body, Reply};
use better_iam_server::http::AuthArgs;
use better_iam_server::models::GrantAuthority;
use better_iam_server::options::{
    AuthorizationRequest, BetterIamOptions, HttpRequest, HttpResponse, ResolvedResource,
    ResourceTarget, ServerAuthOptions, StsOptions,
};
use better_iam_server::port::decode;
use better_iam_server::utils::{date_now, hash};
use better_iam_server::{BetterIam, better_iam};
use bytes::Bytes;
use serde::Serialize;
use serde_json::{Map, Value, json};

pub const ORIGIN: &str = "http://localhost:3000";
pub const ISSUER: &str = "http://localhost:3000/api/iam";
pub const SECRET: &str = "organization-fixture-secret-with-32-characters";
pub const ROOT_PASSWORD: &str = "a strong root test password";
pub const OWNER_PASSWORD: &str = "a strong tenant owner password";
pub const DAY: f64 = 86_400_000.0;

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

/// The fixture's controllable clock (`authentication.now`), starting at `Date.now()`.
#[derive(Clone)]
pub struct Clock(Arc<AtomicU64>);

impl Clock {
    pub fn new(start: f64) -> Self {
        Clock(Arc::new(AtomicU64::new(start.to_bits())))
    }
    pub fn now(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::SeqCst))
    }
    pub fn advance(&self, ms: f64) {
        let next = self.now() + ms;
        self.0.store(next.to_bits(), Ordering::SeqCst);
    }
    pub fn now_fn(&self) -> Arc<dyn Fn() -> f64 + Send + Sync> {
        let clock = self.clone();
        Arc::new(move || clock.now())
    }
}

pub type Inbox = Arc<Mutex<Vec<DeliveryMessage>>>;

pub struct Fixture {
    pub iam: BetterIam,
    pub database: Arc<dyn IamStore>,
    pub inbox: Inbox,
    /// The bootstrap result (`root.tenant`, `root.identity`).
    pub root: Value,
    pub root_tenant: String,
    pub root_credential: CredentialInput,
    pub tenant_id: String,
    pub owner_credential: CredentialInput,
    pub owner_id: String,
    pub clock: Clock,
}

/// The options every instance on a fixture's database shares (the TypeScript `betterIam({...})` call of the
/// fixture, before its overrides).
pub fn base_options(
    database: Arc<dyn IamStore>,
    clock: &Clock,
    inbox: Option<&Inbox>,
) -> BetterIamOptions {
    let mut options = BetterIamOptions::new(database, SECRET, ORIGIN);
    options.permissions = Some(PermissionsConfig {
        actions: Some(vec!["documents:read".into(), "documents:write".into()]),
        ..PermissionsConfig::default()
    });
    options.resolve_resource = Some(Arc::new(|reference| {
        Box::pin(async move { Ok(ResolvedResource::of(&reference)) })
    }));
    let send_email = inbox.map(|inbox| {
        let sink = inbox.clone();
        delivery_fn(move |message| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(message);
                Ok(())
            }
        })
    });
    options.authentication = Some(ServerAuthOptions {
        send_email,
        session_lifetime_ms: Some(7.0 * DAY),
        session_idle_timeout_ms: Some(7.0 * DAY),
        now: Some(clock.now_fn()),
        ..ServerAuthOptions::default()
    });
    options
}

/// `sts` options from their JSON form (the TypeScript object literal).
pub fn sts(value: Value) -> StsOptions {
    serde_json::from_value(value).expect("sts options")
}

pub fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

pub fn headers(pairs: &[(&str, &str)]) -> CredentialInput {
    CredentialInput {
        headers: Some(
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        ),
        token: None,
    }
}

pub fn token_of(credential: &CredentialInput) -> &str {
    credential.token.as_deref().unwrap_or_default()
}

/// A request body.
pub fn body<I>(value: Value) -> Body<I> {
    match value {
        Value::Object(map) => Body::new(map),
        _ => panic!("a body is an object"),
    }
}

/// A route method's answer as JSON.
pub fn json<O: Serialize>(reply: IamResult<Reply<O>>) -> IamResult<Value> {
    reply?.into_value()
}

fn sign_in_session(result: Value, what: &str) -> IamResult<Value> {
    if result.get("token").is_some() {
        Ok(result)
    } else {
        Err(IamError::new(
            "TEST_FIXTURE",
            format!("Unexpected MFA for {what}"),
        ))
    }
}

/// `organizationFixture(overrides)`: `configure` applies the overrides to the base options (as the TypeScript spread
/// does; `options.authentication` is already set, so overriding one of its members keeps the others).
pub async fn organization_fixture(
    configure: impl FnOnce(&mut BetterIamOptions),
) -> IamResult<Fixture> {
    let database: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let inbox: Inbox = Arc::default();
    let clock = Clock::new(date_now());
    let mut options = base_options(database.clone(), &clock, Some(&inbox));
    configure(&mut options);
    let iam = better_iam(options)?;
    iam.initialize().await?;
    let root = iam
        .bootstrap(
            &json!({ "email": "root@example.test", "name": "Root", "password": ROOT_PASSWORD }),
        )
        .await?;
    let root_tenant = root["tenant"]["id"].as_str().unwrap_or_default().to_owned();
    let challenge = iam
        .api
        .auth
        .call(
            "signIn",
            AuthArgs::Public(json!({
                "tenantId": root_tenant,
                "email": "root@example.test",
                "password": ROOT_PASSWORD,
            })),
        )
        .await?;
    if challenge.get("mfaRequired").is_none() {
        return Err(IamError::new("TEST_FIXTURE", "Root must require MFA"));
    }
    let challenge = challenge["challenge"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let enrollment = iam
        .api
        .auth
        .call(
            "beginMfa",
            AuthArgs::BeginMfa(MfaCredential::Challenge {
                tenant_id: root_tenant.clone(),
                challenge: challenge.clone(),
            }),
        )
        .await?;
    let root_session = iam
        .api
        .auth
        .call(
            "confirmMfa",
            AuthArgs::ConfirmMfa(ConfirmMfaInput {
                credential: MfaCredential::Challenge {
                    tenant_id: root_tenant.clone(),
                    challenge,
                },
                code: totp(
                    enrollment["secret"].as_str().unwrap_or_default(),
                    clock.now(),
                ),
                remember_device: false,
            }),
        )
        .await?;
    let root_credential = bearer(root_session["token"].as_str().unwrap_or_default());
    let created = json(
        iam.api
            .tenants
            .create(
                &root_credential,
                body(json!({
                    "parentId": root_tenant,
                    "name": "Acme",
                    "type": "organization",
                    "ownerEmail": "owner@acme.test",
                })),
            )
            .await,
    )?;
    iam.auth.dispatch_outbox(None).await?;
    let tenant_id = created["tenant"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let invitation = inbox
        .lock()
        .unwrap()
        .iter()
        .find(|message| message.tenant_id == tenant_id && message.template == "owner-invitation")
        .cloned()
        .ok_or_else(|| IamError::new("TEST_FIXTURE", "No owner invitation"))?;
    let invitation_token = invitation
        .payload_str("token")
        .unwrap_or_default()
        .to_owned();
    let accepted = json(
        iam.api
            .tenants
            .accept_invitation(body(json!({
                "tenantId": tenant_id,
                "token": invitation_token,
                "name": "Owner",
                "password": OWNER_PASSWORD,
            })))
            .await,
    );
    let owner_token = match accepted {
        Ok(owner) => sign_in_session(owner, "the owner")?["token"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        Err(error) if error.code == "NOT_IMPLEMENTED" => {
            accept_owner_invitation(&iam, &tenant_id, &invitation_token).await?
        }
        Err(error) => return Err(error),
    };
    let owner_credential = bearer(&owner_token);
    let owner = iam
        .api
        .auth
        .call(
            "getSession",
            AuthArgs::Authenticated(owner_credential.clone(), json!({})),
        )
        .await?;
    let owner_id = owner["identity"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    Ok(Fixture {
        iam,
        database,
        inbox,
        root,
        root_tenant,
        root_credential,
        tenant_id,
        owner_credential,
        owner_id,
        clock,
    })
}

/// What `flows.acceptOwnerInvitation` does for the fixture's invitation (no linked credential), while that stub of
/// another unit answers NOT_IMPLEMENTED: the owner identity, the protected Owner setup, the tenant activated, the
/// invitation consumed, and a password session. Returns the session token.
async fn accept_owner_invitation(
    iam: &BetterIam,
    tenant_id: &str,
    token: &str,
) -> IamResult<String> {
    let ctx = iam.ctx.clone();
    let auth = iam.auth.clone();
    let (tenant_id, token) = (tenant_id.to_owned(), token.to_owned());
    iam.store
        .transaction(move |tx| async move {
            let realm: Tenant = decode(
                tx.get("tenants", &tenant_id)
                    .await?
                    .ok_or_else(|| IamError::new("TEST_FIXTURE", "No tenant"))?,
            )?;
            let mut invitation = tx
                .find(
                    "ownerInvitations",
                    &Filter::new()
                        .eq("tenantId", realm.id.clone())
                        .eq("tokenHash", hash(&token)),
                    &FindOptions::default(),
                )
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| IamError::new("TEST_FIXTURE", "No invitation"))?;
            let authority: GrantAuthority = decode(
                tx.get(
                    "grantAuthorities",
                    invitation["authorityId"].as_str().unwrap_or_default(),
                )
                .await?
                .ok_or_else(|| IamError::new("TEST_FIXTURE", "No authority"))?,
            )?;
            let identity = auth
                .create_identity(
                    &tx,
                    CreateIdentityInput {
                        tenant_id: realm.id.clone(),
                        email: invitation["email"].as_str().unwrap_or_default().to_owned(),
                        name: "Owner".into(),
                        password: Some(OWNER_PASSWORD.into()),
                        owner: Some(true),
                        root_admin: None,
                        email_verified: Some(true),
                    },
                )
                .await?;
            ctx.owner_setup(&tx, &realm, &identity, &authority).await?;
            let mut tenant = tx.get("tenants", &realm.id).await?.unwrap_or_default();
            tenant.insert("status".into(), json!("active"));
            tx.put("tenants", &tenant).await?;
            invitation.insert("consumed".into(), json!(true));
            tx.put("ownerInvitations", &invitation).await?;
            match auth
                .complete_authentication(&tx, &identity, Some(AuthMethod::Password), None)
                .await?
            {
                SignInResult::Session(session) => Ok(session.token),
                SignInResult::MfaRequired(_) => {
                    Err(IamError::new("TEST_FIXTURE", "Unexpected owner MFA"))
                }
            }
        })
        .await
}

impl Fixture {
    pub fn now(&self) -> f64 {
        self.clock.now()
    }

    pub fn advance(&self, ms: f64) {
        self.clock.advance(ms);
    }

    /// Creates a person `{name}@acme.test` with a password, as the owner (`identities.create`).
    pub async fn member(&self, name: &str) -> IamResult<Value> {
        json(
            self.iam
                .api
                .identities
                .create(
                    &self.owner_credential,
                    body(json!({
                        "tenantId": self.tenant_id,
                        "email": format!("{name}@acme.test"),
                        "name": name,
                        "password": format!("a strong {name} password"),
                    })),
                )
                .await,
        )
    }

    /// Signs `{name}@acme.test` in with its password (no MFA expected).
    pub async fn sign_in(&self, name: &str) -> IamResult<Value> {
        let result = self
            .iam
            .api
            .auth
            .call(
                "signIn",
                AuthArgs::Public(json!({
                    "tenantId": self.tenant_id,
                    "email": format!("{name}@acme.test"),
                    "password": format!("a strong {name} password"),
                })),
            )
            .await?;
        sign_in_session(result, name)
    }

    /// The credential of [`Fixture::sign_in`].
    pub async fn sign_in_credential(&self, name: &str) -> IamResult<CredentialInput> {
        Ok(bearer(
            self.sign_in(name).await?["token"]
                .as_str()
                .unwrap_or_default(),
        ))
    }

    /// A fresh owner session, recently authenticated.
    pub async fn owner_sign_in(&self) -> IamResult<CredentialInput> {
        let result = self
            .iam
            .api
            .auth
            .call(
                "signIn",
                AuthArgs::Public(json!({
                    "tenantId": self.tenant_id,
                    "email": "owner@acme.test",
                    "password": OWNER_PASSWORD,
                })),
            )
            .await?;
        let result = sign_in_session(result, "the owner")?;
        Ok(bearer(result["token"].as_str().unwrap_or_default()))
    }

    /// `iam.api.auth.<method>(credential, input)`.
    pub async fn auth(
        &self,
        method: &str,
        credential: &CredentialInput,
        input: Value,
    ) -> IamResult<Value> {
        self.iam
            .api
            .auth
            .call(method, AuthArgs::Authenticated(credential.clone(), input))
            .await
    }

    /// `iam.api.sts.getSessionToken(credential, input)`.
    pub async fn get_session_token(
        &self,
        credential: &CredentialInput,
        input: Value,
    ) -> IamResult<Value> {
        json(
            self.iam
                .api
                .sts
                .get_session_token(credential, body(input))
                .await,
        )
    }

    /// `iam.api.sts.getCallerIdentity(credential)`.
    pub async fn get_caller_identity(&self, credential: &CredentialInput) -> IamResult<Value> {
        json(
            self.iam
                .api
                .sts
                .get_caller_identity(credential, body(json!({})))
                .await,
        )
    }

    /// `iam.authenticate({ token })`: the session record of the principal, as JSON.
    pub async fn authenticate(&self, credential: &CredentialInput) -> IamResult<Value> {
        let principal = self.iam.authenticate(credential).await?;
        Ok(serde_json::to_value(&principal.session).expect("session"))
    }

    /// `(await iam.authorize({ token, tenantId, action, resource: { type: 'document', id } })).allowed`.
    pub async fn allowed(&self, token: &str, action: &str, id: &str) -> IamResult<bool> {
        Ok(self
            .iam
            .authorize(&AuthorizationRequest {
                credential: bearer(token),
                tenant_id: self.tenant_id.clone(),
                action: action.to_owned(),
                resource: ResourceTarget {
                    kind: "document".into(),
                    id: id.to_owned(),
                },
            })
            .await?
            .allowed)
    }

    /// The session row of a token (`rowOf`).
    pub async fn row_of(&self, token: &str) -> Record {
        self.find("sessions", json!({ "tokenHash": hash(token) }))
            .await
            .into_iter()
            .next()
            .expect("No session for this token")
    }

    pub async fn get(&self, collection: &str, id: &str) -> Option<Record> {
        self.iam.store.get(collection, id).await.unwrap()
    }

    /// `store.find(collection, filter)` with equality members.
    pub async fn find(&self, collection: &str, filter: Value) -> Vec<Record> {
        let mut query = Filter::new();
        for (key, value) in filter.as_object().cloned().unwrap_or_default() {
            query = query.eq(key, value);
        }
        self.iam
            .store
            .find(collection, &query, &FindOptions::default())
            .await
            .unwrap()
    }

    /// The tenant's audit events, in recorded order (by `sequence`).
    pub async fn audit(&self, tenant_id: &str) -> Vec<Record> {
        let mut events = self.find("audit", json!({ "tenantId": tenant_id })).await;
        events.sort_by(|a, b| {
            let sequence =
                |event: &Record| event.get("sequence").and_then(Value::as_f64).unwrap_or(0.0);
            sequence(a).total_cmp(&sequence(b))
        });
        events
    }

    /// Rewrites a stored record: `Some(value)` sets a member, `None` removes it (a legacy shape).
    pub async fn patch(&self, collection: &str, id: &str, change: Vec<(&str, Option<Value>)>) {
        let collection = collection.to_owned();
        let id = id.to_owned();
        let change: Vec<(String, Option<Value>)> = change
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect();
        self.iam
            .store
            .transaction(move |tx| async move {
                let mut record = tx.get(&collection, &id).await?.expect("stored record");
                for (key, value) in change {
                    match value {
                        Some(value) => {
                            record.insert(key, value);
                        }
                        None => {
                            record.shift_remove(&key);
                        }
                    }
                }
                tx.put(&collection, &record).await
            })
            .await
            .unwrap();
    }

    /// Inserts a record.
    pub async fn insert(&self, collection: &str, record: Value) {
        let collection = collection.to_owned();
        let record: Record = record.as_object().cloned().expect("a record");
        self.iam
            .store
            .transaction(move |tx| async move { tx.insert(&collection, &record).await })
            .await
            .unwrap();
    }

    /// Replaces a stored record (delete and insert, since stores refuse to move a record between tenants).
    pub async fn replace(&self, collection: &str, record: Record) {
        let collection = collection.to_owned();
        self.iam
            .store
            .transaction(move |tx| async move {
                let id = record["id"].as_str().unwrap_or_default().to_owned();
                tx.delete(&collection, &id).await?;
                tx.insert(&collection, &record).await
            })
            .await
            .unwrap();
    }

    /// Deletes a stored record.
    pub async fn delete(&self, collection: &str, id: &str) {
        let collection = collection.to_owned();
        let id = id.to_owned();
        self.iam
            .store
            .transaction(move |tx| async move { tx.delete(&collection, &id).await })
            .await
            .unwrap();
    }

    /// `POST {ORIGIN}/api/iam/{path}` with the JSON body, `content-type` and `x-better-iam` headers.
    pub async fn post(&self, path: &str, body: Value, extra: &[(&str, &str)]) -> HttpResponse {
        post(&self.iam, path, body, extra).await
    }
}

pub fn request(
    method: http::Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> HttpRequest {
    let mut builder = http::Request::builder().method(method).uri(url);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(
            body.map(|body| Bytes::from(body.to_string()))
                .unwrap_or_default(),
        )
        .unwrap()
}

pub async fn post(
    iam: &BetterIam,
    path: &str,
    body: Value,
    extra: &[(&str, &str)],
) -> HttpResponse {
    let mut all = vec![("content-type", "application/json"), ("x-better-iam", "1")];
    all.extend_from_slice(extra);
    iam.handler(request(
        http::Method::POST,
        &format!("{ORIGIN}/api/iam/{path}"),
        &all,
        Some(body),
    ))
    .await
}

pub async fn get_url(iam: &BetterIam, url: &str, headers: &[(&str, &str)]) -> HttpResponse {
    iam.handler(request(http::Method::GET, url, headers, None))
        .await
}

pub fn response_json(response: &HttpResponse) -> Value {
    serde_json::from_slice(response.body()).unwrap_or(Value::Null)
}

pub fn response_text(response: &HttpResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

pub fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
}

/// An HTTP answer that names a stub of another unit, as the error the `ok!`/`fails!` macros skip on.
pub fn unported(response: &HttpResponse) -> IamResult<()> {
    let value = response_json(response);
    if response.status().as_u16() == 501 && value["error"]["code"] == "NOT_IMPLEMENTED" {
        return Err(IamError::with_status(
            "NOT_IMPLEMENTED",
            value["error"]["message"].as_str().unwrap_or_default(),
            501,
        ));
    }
    Ok(())
}

/// The TOTP code an authenticator shows at `at` (epoch ms).
pub fn totp(secret: &str, at: f64) -> String {
    otp::generate(secret, at).expect("TOTP secret")
}

/// `{ version: 1, statements: [{ effect: 'allow', actions, resources: ['*'] }] }`.
pub fn allow(actions: &[&str]) -> Value {
    json!({ "version": 1, "statements": [{ "effect": "allow", "actions": actions, "resources": ["*"] }] })
}

/// Asserts two JSON values are equal as JavaScript sees them (numbers as doubles).
#[track_caller]
pub fn same(actual: &Value, expected: &Value) {
    assert!(
        better_iam_core::js::deep_equal(actual, expected),
        "\n  actual:   {}\n  expected: {}",
        better_iam_core::js::stringify(actual),
        better_iam_core::js::stringify(expected)
    );
}

/// `toMatchObject`: every member of `expected` matches in `actual`, recursively; arrays match element by element.
pub fn subset(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => expected
            .iter()
            .all(|(key, value)| actual.get(key).is_some_and(|member| subset(member, value))),
        (Value::Array(actual), Value::Array(expected)) => {
            actual.len() == expected.len()
                && actual
                    .iter()
                    .zip(expected)
                    .all(|(left, right)| subset(left, right))
        }
        _ => better_iam_core::js::deep_equal(actual, expected),
    }
}

#[track_caller]
pub fn matches(actual: &Value, expected: &Value) {
    assert!(
        subset(actual, expected),
        "\n  actual:   {}\n  does not match: {}",
        better_iam_core::js::stringify(actual),
        better_iam_core::js::stringify(expected)
    );
}

/// A record as JSON.
pub fn value(record: &Record) -> Value {
    Value::Object(record.clone())
}

/// Asserts an error's code, and its status and message when given.
#[track_caller]
pub fn refused(error: &IamError, code: &str, status: Option<u16>, message: Option<&str>) {
    assert_eq!(
        error.code, code,
        "unexpected error: {} ({})",
        error.message, error.code
    );
    if let Some(status) = status {
        assert_eq!(error.status, status, "status of {}", error.code);
    }
    if let Some(message) = message {
        assert_eq!(error.message, message);
    }
}

pub fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

pub fn map_of(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

/// Whether `text` matches `/^{prefix}[A-Za-z0-9_-]{49}$/`.
pub fn typed_token(text: &str, prefix: &str) -> bool {
    text.strip_prefix(prefix).is_some_and(|rest| {
        rest.len() == 49
            && rest
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    })
}
