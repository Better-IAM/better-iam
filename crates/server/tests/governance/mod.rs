//! The organization fixture of the access governance suites (certifications, access requests, agreements), after
//! tests/support/organization.ts: a root tenant, an active organization `Acme` with its owner (the protected Owner
//! role under the owner's own grant authority, as accepting the owner invitation sets it up), members, and an
//! injectable clock. Roles, bindings, groups and identity changes are written to the store directly where the
//! TypeScript suites go through the `roles`, `bindings`, `groups` and `identities` API groups.

#![allow(dead_code)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::DeliveryMessage;
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamStore, IamStoreExt, Identity,
    PermissionsConfig, Record, Tenant,
};
use better_iam_server::api::{Body, Reply};
use better_iam_server::models::GrantAuthority;
use better_iam_server::options::{BetterIamOptions, ResolvedResource, ServerAuthOptions};
use better_iam_server::{BetterIam, better_iam};
use bytes::Bytes;
use http::Method;
use serde_json::{Map, Value, json};

pub const ORIGIN: &str = "http://localhost:3000";
pub const SECRET: &str = "organization-fixture-secret-with-32-characters";
pub const DAY: f64 = 86_400_000.0;
const START: f64 = 1_767_225_600_000.0;

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

/// A request body for an API method.
pub fn body<I>(value: Value) -> Body<I> {
    Body::from_value(value)
}

/// An API answer as JSON, or the error.
pub fn value<O: serde::Serialize>(result: Result<Reply<O>, IamError>) -> Result<Value, IamError> {
    result.and_then(Reply::into_value)
}

/// The successful answer of an API call.
#[track_caller]
pub fn ok<O: serde::Serialize>(result: Result<Reply<O>, IamError>) -> Value {
    match value(result) {
        Ok(value) => value,
        Err(error) => panic!(
            "expected success, got {} {} ({})",
            error.code, error.message, error.status
        ),
    }
}

/// The error of an API call that must fail.
#[track_caller]
pub fn err<O: serde::Serialize>(result: Result<Reply<O>, IamError>) -> IamError {
    match value(result) {
        Ok(value) => panic!("expected an error, got {value}"),
        Err(error) => error,
    }
}

pub fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

pub struct Fixture {
    pub iam: BetterIam,
    pub database: Arc<dyn IamStore>,
    pub root_tenant_id: String,
    pub root_id: String,
    pub root_authority: String,
    pub tenant_id: String,
    pub owner_id: String,
    pub owner_authority: String,
    pub owner: CredentialInput,
    clock: Arc<Mutex<f64>>,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
}

pub struct FixtureOptions {
    pub send_email: bool,
    /// `accessRequests.lifetimeMs`.
    pub access_request_lifetime_ms: Option<f64>,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            send_email: true,
            access_request_lifetime_ms: None,
        }
    }
}

/// The options of the fixture's deployment over `database`.
pub fn deployment_options(
    database: Arc<dyn IamStore>,
    clock: Arc<Mutex<f64>>,
    inbox: Option<Arc<Mutex<Vec<DeliveryMessage>>>>,
) -> BetterIamOptions {
    let mut options = BetterIamOptions::new(database, SECRET, ORIGIN);
    options.permissions = Some(PermissionsConfig {
        actions: Some(vec!["documents:read".into(), "documents:write".into()]),
        ..PermissionsConfig::default()
    });
    options.resolve_resource = Some(Arc::new(|reference| {
        Box::pin(async move { Ok(ResolvedResource::of(&reference)) })
    }));
    let now_clock = clock.clone();
    options.authentication = Some(ServerAuthOptions {
        session_lifetime_ms: Some(30.0 * DAY),
        session_idle_timeout_ms: Some(30.0 * DAY),
        now: Some(Arc::new(move || *now_clock.lock().unwrap())),
        send_email: inbox.map(|inbox| {
            better_iam_auth::delivery_fn(move |message| {
                let inbox = inbox.clone();
                async move {
                    inbox.lock().unwrap().push(message);
                    Ok(())
                }
            })
        }),
        ..ServerAuthOptions::default()
    });
    options
}

pub async fn organization(settings: FixtureOptions) -> Fixture {
    let database: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let clock = Arc::new(Mutex::new(START));
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let mut options = deployment_options(
        database.clone(),
        clock.clone(),
        settings.send_email.then(|| inbox.clone()),
    );
    if let Some(lifetime_ms) = settings.access_request_lifetime_ms {
        options.access_requests = Some(better_iam_server::options::AccessRequestOptions {
            lifetime_ms: Some(lifetime_ms),
            ..Default::default()
        });
    }
    let iam = better_iam(options).expect("valid options");
    iam.initialize().await.expect("initialize");
    let root = iam
        .bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
        .await
        .expect("bootstrap");
    let root_tenant_id = root["tenant"]["id"].as_str().unwrap().to_owned();
    let root_id = root["identity"]["id"].as_str().unwrap().to_owned();
    let root_authority = database
        .find(
            "grantAuthorities",
            &Filter::new().eq("identityId", root_id.clone()),
            &FindOptions::default(),
        )
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("root authority")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let tenant_id = better_iam_server::utils::id();
    let now = *clock.lock().unwrap();
    let (owner_id, owner_authority) = {
        let ctx = iam.ctx.clone();
        let auth = iam.auth.clone();
        let tenant_id = tenant_id.clone();
        let root_tenant_id = root_tenant_id.clone();
        let root_authority = root_authority.clone();
        iam.store
            .transaction(move |tx| async move {
                let realm = json!({
                    "id": tenant_id,
                    "tenantId": tenant_id,
                    "name": "Acme",
                    "type": "organization",
                    "parentId": root_tenant_id,
                    "status": "active",
                    "createdAt": now,
                });
                let realm = tx.insert("tenants", realm.as_object().unwrap()).await?;
                let realm: Tenant = better_iam_server::port::decode(realm)?;
                let owner: Identity = auth
                    .create_identity(
                        &tx,
                        CreateIdentityInput {
                            tenant_id: tenant_id.clone(),
                            email: "owner@acme.test".into(),
                            name: "Owner".into(),
                            password: Some("a strong tenant owner password".into()),
                            owner: Some(true),
                            root_admin: None,
                            email_verified: Some(true),
                        },
                    )
                    .await?;
                let authority = json!({
                    "id": better_iam_server::utils::id(),
                    "tenantId": tenant_id,
                    "identityId": owner.id,
                    "ceiling": better_iam_server::utils::all_value(),
                    "parentAuthorityId": root_authority,
                    "revoked": false,
                });
                let authority = tx
                    .insert("grantAuthorities", authority.as_object().unwrap())
                    .await?;
                let authority: GrantAuthority = better_iam_server::port::decode(authority)?;
                ctx.owner_setup(&tx, &realm, &owner, &authority).await?;
                Ok((owner.id, authority.id))
            })
            .await
            .expect("organization")
    };
    let mut fixture = Fixture {
        iam,
        database,
        root_tenant_id,
        root_id,
        root_authority,
        tenant_id,
        owner_id,
        owner_authority,
        owner: CredentialInput::default(),
        clock,
        inbox,
    };
    fixture.owner = fixture
        .sign_in_with("owner@acme.test", "a strong tenant owner password")
        .await;
    fixture
}

impl Fixture {
    pub fn now(&self) -> f64 {
        *self.clock.lock().unwrap()
    }

    pub fn advance(&self, ms: f64) {
        *self.clock.lock().unwrap() += ms;
    }

    /// Signs in with a password in the organization; a bearer credential.
    pub async fn sign_in_with(&self, email: &str, password: &str) -> CredentialInput {
        let request = http::Request::builder()
            .method(Method::POST)
            .uri(format!("{ORIGIN}/api/iam/auth/signIn"))
            .header("content-type", "application/json")
            .header("x-better-iam", "1")
            .body(Bytes::from(
                json!({ "tenantId": self.tenant_id, "email": email, "password": password })
                    .to_string(),
            ))
            .unwrap();
        let response = self.iam.handler(request).await;
        let answer: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        let token = answer["data"]["token"]
            .as_str()
            .unwrap_or_else(|| panic!("sign-in of {email} failed: {answer}"));
        bearer(token)
    }

    /// Signs in a member created with [`Fixture::member`].
    pub async fn sign_in(&self, name: &str) -> CredentialInput {
        self.sign_in_with(
            &format!("{name}@acme.test"),
            &format!("a strong {name} password"),
        )
        .await
    }

    /// A member of the organization (`{name}@acme.test`); its identity ID.
    pub async fn member(&self, name: &str) -> String {
        let auth = self.iam.auth.clone();
        let tenant_id = self.tenant_id.clone();
        let name = name.to_owned();
        self.iam
            .store
            .transaction(move |tx| async move {
                auth.create_identity(
                    &tx,
                    CreateIdentityInput {
                        tenant_id,
                        email: format!("{name}@acme.test"),
                        name: name.clone(),
                        password: Some(format!("a strong {name} password")),
                        owner: None,
                        root_admin: None,
                        email_verified: Some(true),
                    },
                )
                .await
            })
            .await
            .expect("member")
            .id
    }

    /// `store.transaction(tx => tx.insert(collection, record))`.
    pub async fn insert(&self, collection: &str, record: Value) -> Record {
        let collection = collection.to_owned();
        let record = record.as_object().unwrap().clone();
        self.iam
            .store
            .transaction(move |tx| async move { tx.insert(&collection, &record).await })
            .await
            .unwrap()
    }

    /// Merges members into a stored record.
    pub async fn patch(&self, collection: &str, id: &str, patch: Value) {
        let collection = collection.to_owned();
        let id = id.to_owned();
        self.iam
            .store
            .transaction(move |tx| async move {
                let mut record = tx.get(&collection, &id).await?.expect("record");
                for (key, value) in patch.as_object().unwrap() {
                    record.insert(key.clone(), value.clone());
                }
                tx.put(&collection, &record).await
            })
            .await
            .unwrap();
    }

    /// Deletes a stored record.
    pub async fn remove(&self, collection: &str, id: &str) {
        let collection = collection.to_owned();
        let id = id.to_owned();
        self.iam
            .store
            .transaction(move |tx| async move { tx.delete(&collection, &id).await })
            .await
            .unwrap();
    }

    /// A role of the organization allowing `actions` on every resource.
    pub async fn role(&self, name: &str, actions: &[&str]) -> String {
        let id = better_iam_server::utils::id();
        self.insert(
            "roles",
            json!({
                "id": id,
                "tenantId": self.tenant_id,
                "name": name,
                "policyIds": [],
                "document": {
                    "version": 1,
                    "statements": [{ "effect": "allow", "actions": actions, "resources": ["*"] }],
                },
                "protected": false,
                "authorityId": self.owner_authority,
            }),
        )
        .await;
        id
    }

    /// A role with an inline policy document.
    pub async fn role_with(&self, name: &str, statements: Value) -> String {
        let id = better_iam_server::utils::id();
        self.insert(
            "roles",
            json!({
                "id": id,
                "tenantId": self.tenant_id,
                "name": name,
                "policyIds": [],
                "document": { "version": 1, "statements": statements },
                "protected": false,
                "authorityId": self.owner_authority,
            }),
        )
        .await;
        id
    }

    async fn bind_under(
        &self,
        authority: &str,
        role_id: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> String {
        let id = better_iam_server::utils::id();
        self.insert(
            "bindings",
            json!({
                "id": id,
                "tenantId": self.tenant_id,
                "uniqueKey": format!("{subject_type}:{subject_id}:{role_id}:{authority}"),
                "subjectType": subject_type,
                "subjectId": subject_id,
                "roleId": role_id,
                "authorityId": authority,
            }),
        )
        .await;
        id
    }

    /// A binding under the owner's grant authority (`bindings.create` as the owner).
    pub async fn bind(&self, role_id: &str, subject_type: &str, subject_id: &str) -> String {
        let authority = self.owner_authority.clone();
        self.bind_under(&authority, role_id, subject_type, subject_id)
            .await
    }

    /// A binding under root's grant authority (`bindings.create` as root).
    pub async fn bind_as_root(
        &self,
        role_id: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> String {
        let authority = self.root_authority.clone();
        self.bind_under(&authority, role_id, subject_type, subject_id)
            .await
    }

    /// A group of the organization.
    pub async fn group(&self, name: &str) -> String {
        let id = better_iam_server::utils::id();
        self.insert(
            "groups",
            json!({ "id": id, "tenantId": self.tenant_id, "name": name, "uniqueKey": name.to_lowercase() }),
        )
        .await;
        id
    }

    pub async fn add_member(&self, group_id: &str, identity_id: &str) {
        self.insert(
            "groupMembers",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": self.tenant_id,
                "uniqueKey": format!("{group_id}:{identity_id}"),
                "groupId": group_id,
                "identityId": identity_id,
            }),
        )
        .await;
    }

    /// `store.find(collection, filter)` with string members.
    pub async fn find(&self, collection: &str, filter: &[(&str, Value)]) -> Vec<Record> {
        let mut query = Filter::new();
        for (key, value) in filter {
            query = query.eq(*key, value.clone());
        }
        self.iam
            .store
            .find(collection, &query, &FindOptions::default())
            .await
            .unwrap()
    }

    /// Dispatches the outbox and returns the messages delivered since the last call.
    pub async fn deliveries(&self) -> Vec<DeliveryMessage> {
        self.iam.auth.dispatch_outbox(None).await.expect("dispatch");
        std::mem::take(&mut *self.inbox.lock().unwrap())
    }

    /// A deployment over the same database without an email callback.
    pub fn silent(&self) -> BetterIam {
        better_iam(deployment_options(
            self.database.clone(),
            self.clock.clone(),
            None,
        ))
        .expect("valid options")
    }
}

/// `{ ...map }` of a JSON object.
pub fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("an object")
}

/// A JavaScript number as JSON (integral values as integers, as the server writes them).
pub fn num(value: f64) -> Value {
    better_iam_core::js::number(value).expect("a finite number")
}
