//! The fixture of the delegation suites (tests/delegations.test.ts, tests/delegation-handoffs.test.ts,
//! tests/delegation-spend.test.ts and tests/delegation-tokens.test.ts), after tests/support/organization.ts: a root
//! tenant, an active organization `Acme` with its owner, members, agents with API keys, an injectable clock and an
//! email inbox, over options the suite may adjust (`inference`, `a2a`).

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::DeliveryMessage;
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamResult, IamStore, IamStoreExt, Identity,
    Record, Tenant,
};
use better_iam_server::models::GrantAuthority;
use better_iam_server::options::{AuthorizationRequest, BetterIamOptions, ResourceTarget};
use better_iam_server::{BetterIam, better_iam};
use bytes::Bytes;
use http::Method;
use serde_json::{Value, json};

use crate::governance::{ORIGIN, bearer, body, deployment_options, ok};

const START: f64 = 1_767_225_600_000.0;

pub struct Fixture {
    pub iam: BetterIam,
    pub database: Arc<dyn IamStore>,
    pub tenant_id: String,
    pub owner_id: String,
    pub owner_authority: String,
    pub owner: CredentialInput,
    clock: Arc<Mutex<f64>>,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
}

/// An agent with its own API key.
#[derive(Clone)]
pub struct TestAgent {
    pub id: String,
    pub key: CredentialInput,
}

/// `organizationFixture(overrides)`: the organization over the default options, adjusted by `configure`.
pub async fn organization(configure: impl FnOnce(&mut BetterIamOptions)) -> Fixture {
    let database: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let clock = Arc::new(Mutex::new(START));
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let mut options = deployment_options(database.clone(), clock.clone(), Some(inbox.clone()));
    configure(&mut options);
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
        tenant_id,
        owner_id,
        owner_authority,
        owner: CredentialInput::default(),
        clock,
        inbox,
    };
    fixture.owner = fixture.owner_sign_in().await;
    fixture
}

/// The error of a call that must fail (`refusal(promise)`).
#[track_caller]
pub fn refusal<T: std::fmt::Debug>(result: IamResult<T>) -> IamError {
    match result {
        Ok(value) => panic!("expected an error, got {value:?}"),
        Err(error) => error,
    }
}

/// Whether `actual` contains every member of `expected` with the same value (`toMatchObject`), recursively.
pub fn matches(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => expected
            .iter()
            .all(|(key, value)| actual.get(key).is_some_and(|member| matches(member, value))),
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

/// `{ version: 1, statements: [{ effect: 'allow', actions, resources }] }`.
pub fn doc(actions: &[&str], resources: &[&str]) -> Value {
    json!({ "version": 1, "statements": [{ "effect": "allow", "actions": actions, "resources": resources }] })
}

pub fn id_of(value: &Value) -> String {
    value["id"].as_str().expect("an id").to_owned()
}

pub fn token_of(value: &Value) -> CredentialInput {
    bearer(value["token"].as_str().expect("a token"))
}

/// The members of a list answer, by `id`.
pub fn ids(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("a list")
        .iter()
        .map(id_of)
        .collect()
}

/// The `action` of each audit event of a list answer.
pub fn actions(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("a list")
        .iter()
        .map(|event| event["action"].as_str().unwrap_or_default().to_owned())
        .collect()
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

    /// `f.signIn(name)`: a fresh session of a member created with [`Fixture::member`].
    pub async fn sign_in(&self, name: &str) -> CredentialInput {
        self.sign_in_with(
            &format!("{name}@acme.test"),
            &format!("a strong {name} password"),
        )
        .await
    }

    /// `f.ownerSignIn()`: a fresh owner session (for recent-authentication checks).
    pub async fn owner_sign_in(&self) -> CredentialInput {
        self.sign_in_with("owner@acme.test", "a strong tenant owner password")
            .await
    }

    /// `f.member(name)`: a person of the organization (`{name}@acme.test`); its identity ID.
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

    /// `roles.create` with a document and `bindings.create` for an identity, as the owner.
    pub async fn grant(&self, name: &str, document: Value, identity_id: &str) -> String {
        let role = ok(self
            .iam
            .api
            .roles
            .create(
                &self.owner,
                body(json!({ "tenantId": self.tenant_id, "name": name, "document": document })),
            )
            .await);
        ok(self
            .iam
            .api
            .bindings
            .create(
                &self.owner,
                body(json!({
                    "tenantId": self.tenant_id,
                    "roleId": role["id"],
                    "subjectType": "identity",
                    "subjectId": identity_id,
                })),
            )
            .await);
        id_of(&role)
    }

    /// `agents.create` (with `extra` profile members) and `credentials.create` (with `key` members), as the owner.
    pub async fn agent(&self, name: &str, extra: Value, key: Value) -> TestAgent {
        let mut input = json!({ "tenantId": self.tenant_id, "name": name });
        for (member, value) in extra.as_object().cloned().unwrap_or_default() {
            input[member] = value;
        }
        let created = ok(self.iam.api.agents.create(&self.owner, body(input)).await);
        let mut key_input = json!({ "tenantId": self.tenant_id, "identityId": created["id"] });
        for (member, value) in key.as_object().cloned().unwrap_or_default() {
            key_input[member] = value;
        }
        let issued = ok(self
            .iam
            .api
            .credentials
            .create(&self.owner, body(key_input))
            .await);
        TestAgent {
            id: id_of(&created),
            key: token_of(&issued),
        }
    }

    /// `f.iam.authorize({ token, tenantId, action, resource: { type: 'document', id } })`.
    pub async fn allowed(
        &self,
        credential: &CredentialInput,
        action: &str,
        id: &str,
    ) -> IamResult<bool> {
        self.iam
            .authorize(&AuthorizationRequest {
                credential: credential.clone(),
                tenant_id: self.tenant_id.clone(),
                action: action.to_owned(),
                resource: ResourceTarget {
                    kind: "document".into(),
                    id: id.to_owned(),
                },
            })
            .await
            .map(|decision| decision.allowed)
    }

    /// Dispatches the outbox and returns every message delivered so far.
    pub async fn inbox(&self) -> Vec<DeliveryMessage> {
        self.iam.auth.dispatch_outbox(None).await.expect("dispatch");
        self.inbox.lock().unwrap().clone()
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

    pub async fn get(&self, collection: &str, id: &str) -> Option<Record> {
        self.iam.store.get(collection, id).await.unwrap()
    }

    /// `store.find(collection, filter)` with equality members.
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
}
