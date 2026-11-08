//! The Rust counterpart of tests/support/organization.ts: a bootstrapped platform with one organization ("Acme")
//! whose owner is active, a controllable clock, and helpers for members and sessions. Tenants, owners and grants are
//! written the way `tenants.create` (with `activate`), `identities.create`, `roles.create` and `bindings.create`
//! write them, so the suites that use it do not depend on those API groups; sessions come from `issueSession`, as
//! the sign-in ceremonies end (root sessions carry `mfa`, as after the TOTP step).

#![allow(dead_code)]

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::service::base::{CreateIdentityInput, IssueSessionOptions};
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamResult, IamStore, IamStoreExt, Identity,
    PermissionsConfig, Record, Tenant,
};
use better_iam_server::api::{Body, Reply};
use better_iam_server::models::GrantAuthority;
use better_iam_server::options::{BetterIamOptions, ResolvedResource, ServerAuthOptions};
use better_iam_server::{BetterIam, better_iam};
use bytes::Bytes;
use http::Method;
use serde_json::{Value, json};

pub const ORIGIN: &str = "http://localhost:3000";
const SECRET: &str = "organization-fixture-secret-with-32-characters";
const DAY: f64 = 86_400_000.0;

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

pub struct Org {
    pub iam: BetterIam,
    clock: Arc<AtomicU64>,
    pub root_tenant: String,
    pub root_id: String,
    pub root_credential: CredentialInput,
    pub tenant_id: String,
    pub owner_id: String,
    pub owner_credential: CredentialInput,
}

pub fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

/// The JSON a credential travels as inside a request (`{ ...credential, tenantId, ... }`).
pub fn with_credential(credential: &CredentialInput, input: Value) -> Value {
    let mut out = input.as_object().cloned().unwrap_or_default();
    if let Some(token) = &credential.token {
        out.insert("token".into(), Value::String(token.clone()));
    }
    Value::Object(out)
}

pub fn body<I>(value: Value) -> Body<I> {
    Body::from_value(value)
}

pub fn code(error: &IamError) -> &str {
    error.code.as_str()
}

/// The JSON result of an API call that must succeed.
#[track_caller]
pub fn ok<O: serde::Serialize>(result: IamResult<Reply<O>>) -> Value {
    match result {
        Ok(reply) => reply.into_value().expect("JSON result"),
        Err(error) => panic!("expected success, got {error:?}"),
    }
}

/// The error of an API call that must fail.
#[track_caller]
pub fn fails<O>(result: IamResult<Reply<O>>) -> IamError {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => error,
    }
}

/// Whether `actual` contains every member of `expected` with the same value (`toMatchObject`), recursively.
pub fn matches(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => expected
            .iter()
            .all(|(key, value)| actual.get(key).is_some_and(|member| matches(member, value))),
        // `toMatchObject` matches arrays element by element (same length).
        (Value::Array(actual), Value::Array(expected)) => {
            actual.len() == expected.len()
                && actual
                    .iter()
                    .zip(expected)
                    .all(|(actual, expected)| matches(actual, expected))
        }
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (actual, expected) => actual == expected,
    }
}

#[track_caller]
pub fn assert_matches(actual: &Value, expected: Value) {
    assert!(
        matches(actual, &expected),
        "\n  actual:   {actual}\n  expected: {expected}"
    );
}

/// `organizationFixture(overrides)`.
pub async fn organization(configure: impl FnOnce(&mut BetterIamOptions)) -> Org {
    let store: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let mut options = BetterIamOptions::new(store, SECRET, ORIGIN);
    options.permissions = Some(PermissionsConfig {
        actions: Some(vec!["documents:read".into(), "documents:write".into()]),
        ..PermissionsConfig::default()
    });
    options.resolve_resource = Some(Arc::new(|reference| {
        Box::pin(async move { Ok(ResolvedResource::of(&reference)) })
    }));
    let clock = Arc::new(AtomicU64::new(
        better_iam_server::utils::date_now().to_bits(),
    ));
    let reader = clock.clone();
    options.authentication = Some(ServerAuthOptions {
        session_lifetime_ms: Some(7.0 * DAY),
        session_idle_timeout_ms: Some(7.0 * DAY),
        now: Some(Arc::new(move || {
            f64::from_bits(reader.load(Ordering::SeqCst))
        })),
        ..ServerAuthOptions::default()
    });
    configure(&mut options);
    let iam = better_iam(options).expect("valid options");
    iam.initialize().await.expect("initialize");
    let root = iam
        .bootstrap(&json!({
            "email": "root@example.test",
            "name": "Root",
            "password": "a strong root test password",
        }))
        .await
        .expect("bootstrap");
    let root_tenant = root["tenant"]["id"].as_str().unwrap().to_owned();
    let root_id = root["identity"]["id"].as_str().unwrap().to_owned();
    let mut org = Org {
        iam,
        clock,
        root_tenant: root_tenant.clone(),
        root_id: root_id.clone(),
        root_credential: CredentialInput::default(),
        tenant_id: String::new(),
        owner_id: String::new(),
        owner_credential: CredentialInput::default(),
    };
    org.root_credential = org.session(&root_id, true).await;
    let (tenant_id, owner_id, owner_credential) = org
        .activate(&root_tenant, "Acme", "organization", "owner@acme.test")
        .await;
    org.tenant_id = tenant_id;
    org.owner_id = owner_id;
    org.owner_credential = owner_credential;
    org
}

impl Org {
    pub fn now(&self) -> f64 {
        f64::from_bits(self.clock.load(Ordering::SeqCst))
    }

    pub fn advance(&self, ms: f64) {
        self.clock
            .store((self.now() + ms).to_bits(), Ordering::SeqCst);
    }

    pub fn store(&self) -> Arc<dyn IamStore> {
        self.iam.store.clone()
    }

    /// A session for an identity, as a completed sign-in issues it.
    pub async fn session(&self, identity_id: &str, mfa: bool) -> CredentialInput {
        let auth = self.iam.auth.clone();
        let identity_id = identity_id.to_owned();
        let result = self
            .iam
            .store
            .transaction(|tx| async move {
                let record = tx.get("identities", &identity_id).await?.expect("identity");
                let identity: Identity = better_iam_server::port::decode(record)?;
                auth.issue_session(
                    &tx,
                    &identity,
                    IssueSessionOptions {
                        mfa: Some(mfa),
                        ..IssueSessionOptions::default()
                    },
                )
                .await
            })
            .await
            .expect("session");
        bearer(&result.token)
    }

    /// The grant authority of a tenant (the one its owner holds), or the root administrator's for the root tenant.
    async fn authority_of(&self, tenant_id: &str) -> String {
        let filter = if tenant_id == self.root_tenant {
            Filter::new().eq("identityId", self.root_id.clone())
        } else {
            Filter::new().eq("tenantId", tenant_id.to_owned())
        };
        self.iam
            .store
            .find("grantAuthorities", &filter, &FindOptions::default())
            .await
            .unwrap()
            .into_iter()
            .next()
            .expect("authority")["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// `tenants.create({ activate: true, ... })`: an active tenant with its owner, the protected Owner role, and a
    /// grant authority below the parent's. Returns the tenant, the owner, and an owner session.
    pub async fn activate(
        &self,
        parent_id: &str,
        name: &str,
        kind: &str,
        owner_email: &str,
    ) -> (String, String, CredentialInput) {
        let parent_authority = self.authority_of(parent_id).await;
        let ctx = self.iam.ctx.clone();
        let auth = self.iam.auth.clone();
        let tenant_id = better_iam_server::utils::id();
        let realm = json!({
            "id": tenant_id,
            "tenantId": tenant_id,
            "name": name,
            "type": kind,
            "parentId": parent_id,
            "status": "active",
            "createdAt": better_iam_server::utils::date_now(),
        });
        let (owner_name, owner_email) = (format!("{name} owner"), owner_email.to_owned());
        let owner = self
            .iam
            .store
            .transaction(|tx| async move {
                let realm = tx.insert("tenants", realm.as_object().unwrap()).await?;
                let realm: Tenant = better_iam_server::port::decode(realm)?;
                let authority = tx
                    .insert(
                        "grantAuthorities",
                        json!({
                            "id": better_iam_server::utils::id(),
                            "tenantId": realm.id,
                            "identityId": "pending",
                            "parentAuthorityId": parent_authority,
                            "ceiling": better_iam_server::utils::all_value(),
                            "revoked": false,
                        })
                        .as_object()
                        .unwrap(),
                    )
                    .await?;
                let authority: GrantAuthority = better_iam_server::port::decode(authority)?;
                let owner = auth
                    .create_identity(
                        &tx,
                        CreateIdentityInput {
                            tenant_id: realm.id.clone(),
                            email: owner_email,
                            name: owner_name,
                            password: Some("a strong tenant owner password".into()),
                            owner: Some(true),
                            root_admin: None,
                            email_verified: Some(true),
                        },
                    )
                    .await?;
                ctx.owner_setup(&tx, &realm, &owner, &authority).await?;
                Ok(owner)
            })
            .await
            .expect("activate tenant");
        let credential = self.session(&owner.id, false).await;
        (tenant_id, owner.id, credential)
    }

    /// `identities.create`: a person `{name}@acme.test` in the organization.
    pub async fn member(&self, name: &str) -> String {
        self.member_in(&self.tenant_id.clone(), name).await
    }

    pub async fn member_in(&self, tenant_id: &str, name: &str) -> String {
        let auth = self.iam.auth.clone();
        let (tenant_id, name) = (tenant_id.to_owned(), name.to_owned());
        self.iam
            .store
            .transaction(|tx| async move {
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

    /// A fresh session of an identity (a password sign-in without MFA).
    pub async fn sign_in(&self, identity_id: &str) -> CredentialInput {
        self.session(identity_id, false).await
    }

    /// `store.transaction(tx => tx.insert(collection, record))`.
    pub async fn insert(&self, collection: &str, record: Value) -> Record {
        let collection = collection.to_owned();
        let record = record.as_object().unwrap().clone();
        self.iam
            .store
            .transaction(|tx| async move { tx.insert(&collection, &record).await })
            .await
            .unwrap()
    }

    /// `store.transaction(tx => tx.put(collection, record))`.
    pub async fn put(&self, collection: &str, record: Record) -> Record {
        let collection = collection.to_owned();
        self.iam
            .store
            .transaction(|tx| async move { tx.put(&collection, &record).await })
            .await
            .unwrap()
    }

    /// Every record of a collection matching an equality filter.
    pub async fn find(&self, collection: &str, filter: Filter) -> Vec<Record> {
        self.iam
            .store
            .find(collection, &filter, &FindOptions::default())
            .await
            .unwrap()
    }

    /// `roles.create` with an inline document and `bindings.create` for an identity, in the organization.
    pub async fn grant(&self, identity_id: &str, statements: Value) -> String {
        let authority = self.authority_of(&self.tenant_id.clone()).await;
        let role_id = better_iam_server::utils::id();
        self.insert(
            "roles",
            json!({
                "id": role_id,
                "tenantId": self.tenant_id,
                "name": format!("Role {role_id}"),
                "policyIds": [],
                "document": { "version": 1, "statements": statements },
                "protected": false,
                "authorityId": authority,
            }),
        )
        .await;
        self.insert(
            "bindings",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": self.tenant_id,
                "subjectType": "identity",
                "subjectId": identity_id,
                "roleId": role_id,
                "authorityId": authority,
            }),
        )
        .await;
        role_id
    }

    /// `POST {basePath}/{path}` with a bearer token.
    pub async fn post(&self, path: &str, token: &str, body: Value) -> (u16, Value) {
        let request = http::Request::builder()
            .method(Method::POST)
            .uri(format!("{ORIGIN}/api/iam/{path}"))
            .header("content-type", "application/json")
            .header("x-better-iam", "1")
            .header("authorization", format!("Bearer {token}"))
            .body(Bytes::from(body.to_string()))
            .unwrap();
        let response = self.iam.handler(request).await;
        let status = response.status().as_u16();
        let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        (status, json)
    }
}
