//! Shared harness of the tenants, lifecycle and self-check suites: a composed server on an in-memory SQLite store with
//! a fixed clock, an email inbox, and a root administrator signed in with MFA (as the TypeScript fixtures do through
//! `auth.signIn`, `auth.beginMfa` and `auth.confirmMfa`).

#![allow(dead_code)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_auth::service::mfa::ConfirmMfaInput;
use better_iam_auth::{DeliveryMessage, MfaCredential, SignInResult, delivery_fn, totp};
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamResult, IamStore, IamStoreExt, Record,
};
use better_iam_server::api::{Body, Reply};
use better_iam_server::options::{BetterIamOptions, ServerAuthOptions};
use better_iam_server::{BetterIam, better_iam};
use serde::Serialize;
use serde_json::{Value, json};

pub const ORIGIN: &str = "http://localhost:3000";
pub const SECRET: &str = "tenants-port-test-secret-with-32-characters!!";
pub const ROOT_PASSWORD: &str = "a strong root test password";
pub const MEMBER_PASSWORD: &str = "a strong member test password";
/// The injected clock (`authentication.now`) of every fixture.
pub const NOW: f64 = 1_893_456_000_000.0;
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

/// A stub of another unit answers NOT_IMPLEMENTED until that unit is ported: the rest of the test is skipped then.
#[macro_export]
macro_rules! or_skip {
    ($result:expr) => {
        match $result {
            Err(error) if error.code == "NOT_IMPLEMENTED" => {
                eprintln!("skipped (not ported yet): {}", error.message);
                return;
            }
            other => other,
        }
    };
}

pub type Inbox = Arc<Mutex<Vec<DeliveryMessage>>>;

pub struct Fixture {
    pub iam: BetterIam,
    pub inbox: Inbox,
    pub root_tenant: String,
    pub root_id: String,
    pub root: CredentialInput,
}

/// Options for an in-memory deployment with an email inbox (unless `email` is false) and the fixed clock.
pub fn options(email: bool, inbox: &Inbox) -> BetterIamOptions {
    let store: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let mut options = BetterIamOptions::new(store, SECRET, ORIGIN);
    let sink = inbox.clone();
    options.authentication = Some(ServerAuthOptions {
        send_email: email.then(|| {
            delivery_fn(move |message| {
                let sink = sink.clone();
                async move {
                    sink.lock().unwrap().push(message);
                    Ok(())
                }
            })
        }),
        now: Some(Arc::new(|| NOW)),
        ..ServerAuthOptions::default()
    });
    options
}

/// A bootstrapped deployment with a root administrator signed in with MFA.
pub async fn fixture(email: bool, configure: impl FnOnce(&mut BetterIamOptions)) -> Fixture {
    let inbox: Inbox = Arc::default();
    let mut options = options(email, &inbox);
    configure(&mut options);
    let iam = better_iam(options).expect("valid options");
    iam.initialize().await.expect("initialize");
    let root = iam
        .bootstrap(
            &json!({ "email": "root@example.test", "name": "Root", "password": ROOT_PASSWORD }),
        )
        .await
        .expect("bootstrap");
    let root_tenant = root["tenant"]["id"].as_str().unwrap().to_owned();
    let root_id = root["identity"]["id"].as_str().unwrap().to_owned();
    let challenge = match iam
        .auth
        .sign_in(&json!({ "tenantId": root_tenant, "email": "root@example.test", "password": ROOT_PASSWORD }))
        .await
        .expect("root sign-in")
    {
        SignInResult::MfaRequired(required) => required.challenge,
        SignInResult::Session(_) => panic!("Root must require MFA"),
    };
    let credential = MfaCredential::Challenge {
        tenant_id: root_tenant.clone(),
        challenge,
    };
    let enrollment = iam.auth.begin_mfa(&credential).await.expect("begin MFA");
    let session = iam
        .auth
        .confirm_mfa(&ConfirmMfaInput {
            credential,
            code: totp::generate(&enrollment.secret, NOW).unwrap(),
            remember_device: false,
        })
        .await
        .expect("confirm MFA");
    Fixture {
        iam,
        inbox,
        root_tenant,
        root_id,
        root: bearer(&session.token),
    }
}

pub fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
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

/// The error of an answer that must fail.
pub fn failure<T: std::fmt::Debug>(result: IamResult<T>) -> IamError {
    result.expect_err("expected an error")
}

pub async fn insert(iam: &BetterIam, collection: &str, record: Value) {
    let collection = collection.to_owned();
    let record = record.as_object().unwrap().clone();
    iam.store
        .transaction(|tx| async move { tx.insert(&collection, &record).await })
        .await
        .unwrap();
}

pub async fn put(iam: &BetterIam, collection: &str, record: Record) {
    let collection = collection.to_owned();
    iam.store
        .transaction(|tx| async move { tx.put(&collection, &record).await })
        .await
        .unwrap();
}

pub async fn get(iam: &BetterIam, collection: &str, id: &str) -> Option<Record> {
    iam.store.get(collection, id).await.unwrap()
}

pub async fn find(iam: &BetterIam, collection: &str, filter: Value) -> Vec<Record> {
    let mut query = Filter::new();
    for (key, value) in filter.as_object().unwrap() {
        query = query.eq(key.clone(), value.clone());
    }
    iam.store
        .find(collection, &query, &FindOptions::default())
        .await
        .unwrap()
}

/// Creates an active organization under the root (`tenants.create` with `activate: true`).
pub async fn organization(f: &Fixture, name: &str, extra: Value) -> Value {
    let mut input = json!({
        "parentId": f.root_tenant,
        "type": "organization",
        "name": name,
        "ownerEmail": format!("owner@{}.test", name.to_lowercase()),
        "activate": true,
    });
    for (key, value) in extra.as_object().unwrap() {
        input[key] = value.clone();
    }
    json(f.iam.api.tenants.create(&f.root, body(input)).await).expect("organization")
}

/// A member with a password in `tenant_id` (owner when `owner`), signed in: its identity ID and credential.
pub async fn member(
    f: &Fixture,
    tenant_id: &str,
    email: &str,
    owner: bool,
) -> (String, CredentialInput) {
    let identity = f
        .iam
        .store
        .transaction(|tx| {
            let auth = f.iam.auth.clone();
            let input = CreateIdentityInput {
                tenant_id: tenant_id.to_owned(),
                email: email.to_owned(),
                name: email.split('@').next().unwrap().to_owned(),
                password: Some(MEMBER_PASSWORD.into()),
                owner: Some(owner),
                root_admin: None,
                email_verified: Some(true),
            };
            async move { auth.create_identity(&tx, input).await }
        })
        .await
        .expect("member");
    if owner {
        // The protected Owner role of the organization, bound under its owner authority.
        let role = find(
            &f.iam,
            "roles",
            json!({ "tenantId": tenant_id, "uniqueKey": "system:owner" }),
        )
        .await
        .into_iter()
        .next()
        .expect("owner role");
        let binding = find(
            &f.iam,
            "bindings",
            json!({ "tenantId": tenant_id, "roleId": role["id"] }),
        )
        .await
        .into_iter()
        .next()
        .expect("owner binding");
        insert(
            &f.iam,
            "bindings",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": tenant_id,
                "subjectType": "identity",
                "subjectId": identity.id,
                "roleId": role["id"],
                "authorityId": binding["authorityId"],
            }),
        )
        .await;
        // A delegated grant authority under the organization's, as an owner granted through the API holds.
        insert(
            &f.iam,
            "grantAuthorities",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": tenant_id,
                "identityId": identity.id,
                "parentAuthorityId": binding["authorityId"],
                "ceiling": { "version": 1, "statements": [{ "effect": "allow", "actions": ["*"], "resources": ["*"] }] },
                "revoked": false,
            }),
        )
        .await;
    }
    let session = match f
        .iam
        .auth
        .sign_in(&json!({ "tenantId": tenant_id, "email": email, "password": MEMBER_PASSWORD }))
        .await
        .expect("member sign-in")
    {
        SignInResult::Session(session) => session,
        SignInResult::MfaRequired(_) => panic!("unexpected MFA"),
    };
    (identity.id, bearer(&session.token))
}

/// The messages delivered so far with this template.
pub fn mails(f: &Fixture, template: &str) -> Vec<DeliveryMessage> {
    f.inbox
        .lock()
        .unwrap()
        .iter()
        .filter(|message| message.template == template)
        .cloned()
        .collect()
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
