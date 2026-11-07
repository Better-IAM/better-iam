//! Shared fixture of the directory API tests (webhooks, domains, hostnames, reports, resources, relationships).
//!
//! The TypeScript suites create organizations, members, groups, roles and bindings through the `tenants`,
//! `identities`, `groups`, `roles` and `bindings` API groups. Those groups are ported separately, so this fixture
//! writes the same records directly: an organization is created as `tenants.create({ activate: true })` creates one
//! (tenant, delegated grant authority, owner identity and the protected Owner role), members are created through
//! the authentication service, and sessions are issued as a completed sign-in issues them.

#![allow(dead_code)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::service::base::{CreateIdentityInput, IssueSessionOptions};
use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::{
    AuthMethod, CredentialInput, Filter, FindOptions, IamError, IamStore, IamStoreExt, Identity,
    Record, Tenant,
};
use better_iam_server::api::{Body, Reply};
use better_iam_server::models::GrantAuthority;
use better_iam_server::options::{BetterIamOptions, ServerAuthOptions};
use better_iam_server::port::decode;
use better_iam_server::utils::{all_value, id};
use better_iam_server::{BetterIam, better_iam};
use bytes::Bytes;
use http::Method;
use serde::Serialize;
use serde_json::{Map, Value, json};

pub const ORIGIN: &str = "http://localhost:3000";

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

/// The composed server, its root administrator, and the injected clock and inbox.
pub struct Fixture {
    pub iam: BetterIam,
    pub root_tenant_id: String,
    pub root_id: String,
    pub root_authority: String,
    pub root: CredentialInput,
    pub clock: Arc<Mutex<f64>>,
    pub inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
}

/// An organization created by root, with its owner signed in.
#[derive(Clone)]
pub struct Org {
    pub tenant_id: String,
    pub owner_id: String,
    pub authority_id: String,
    pub owner: CredentialInput,
}

/// A member of an organization, signed in.
#[derive(Clone)]
pub struct Member {
    pub id: String,
    pub credential: CredentialInput,
}

/// Options over an in-memory SQLite store with an injected clock and email inbox.
pub fn options(
    secret: &str,
    clock: &Arc<Mutex<f64>>,
    inbox: &Arc<Mutex<Vec<DeliveryMessage>>>,
) -> BetterIamOptions {
    let store: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let mut options = BetterIamOptions::new(store, secret, ORIGIN);
    let now = clock.clone();
    let sink = inbox.clone();
    options.authentication = Some(ServerAuthOptions {
        send_email: Some(delivery_fn(move |message| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(message);
                Ok(())
            }
        })),
        now: Some(Arc::new(move || *now.lock().unwrap())),
        ..ServerAuthOptions::default()
    });
    options
}

/// `Date.now()` as the fixture's starting clock.
fn wall_clock() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as f64
}

/// A bootstrapped deployment; `configure` adjusts the options first.
pub async fn fixture(secret: &str, configure: impl FnOnce(&mut BetterIamOptions)) -> Fixture {
    let clock = Arc::new(Mutex::new(wall_clock()));
    let inbox = Arc::new(Mutex::new(Vec::new()));
    let mut options = options(secret, &clock, &inbox);
    configure(&mut options);
    let iam = better_iam(options).expect("valid options");
    iam.initialize().await.expect("initialize");
    let root = iam
        .bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
        .await
        .expect("bootstrap");
    let root_tenant_id = root["tenant"]["id"].as_str().unwrap().to_owned();
    let root_id = root["identity"]["id"].as_str().unwrap().to_owned();
    let authority = iam
        .store
        .find(
            "grantAuthorities",
            &Filter::new().eq("identityId", root_id.clone()),
            &FindOptions::default(),
        )
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("root authority");
    let mut f = Fixture {
        iam,
        root_tenant_id,
        root_id: root_id.clone(),
        root_authority: authority["id"].as_str().unwrap().to_owned(),
        root: CredentialInput::default(),
        clock,
        inbox,
    };
    f.root = f.session(&root_id).await;
    f
}

impl Fixture {
    /// The injected clock.
    pub fn now(&self) -> f64 {
        *self.clock.lock().unwrap()
    }

    /// Moves the injected clock forward.
    pub fn advance(&self, ms: f64) {
        *self.clock.lock().unwrap() += ms;
    }

    /// A fresh multi-factor session of an identity, as a completed sign-in issues it.
    pub async fn session(&self, identity_id: &str) -> CredentialInput {
        let auth = self.iam.auth.clone();
        let identity_id = identity_id.to_owned();
        let result = self
            .iam
            .store
            .transaction(|tx| async move {
                let identity: Identity = decode(
                    tx.get("identities", &identity_id)
                        .await?
                        .expect("identity exists"),
                )?;
                auth.issue_session(
                    &tx,
                    &identity,
                    IssueSessionOptions {
                        mfa: Some(true),
                        method: Some(AuthMethod::Password),
                        ..IssueSessionOptions::default()
                    },
                )
                .await
            })
            .await
            .expect("session");
        CredentialInput {
            headers: None,
            token: Some(result.token),
        }
    }

    /// `tenants.create({ parentId: root, name, type: 'organization', ownerEmail, activate: true })` and the owner's
    /// sign-in.
    pub async fn organization(&self, name: &str, owner_email: &str) -> Org {
        self.organization_under(&self.root_tenant_id.clone(), name, owner_email)
            .await
    }

    /// An organization (or project) under `parent_id`.
    pub async fn organization_under(&self, parent_id: &str, name: &str, owner_email: &str) -> Org {
        let ctx = self.iam.ctx.clone();
        let auth = self.iam.auth.clone();
        let (parent_id, name, owner_email) = (
            parent_id.to_owned(),
            name.to_owned(),
            owner_email.to_owned(),
        );
        let parent_authority = if parent_id == self.root_tenant_id {
            self.root_authority.clone()
        } else {
            self.iam
                .store
                .find(
                    "grantAuthorities",
                    &Filter::new().eq("tenantId", parent_id.clone()),
                    &FindOptions::default(),
                )
                .await
                .unwrap()
                .into_iter()
                .next()
                .expect("parent authority")["id"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let kind = if parent_id == self.root_tenant_id {
            "organization"
        } else {
            "project"
        };
        let (tenant_id, owner_id, authority_id) = self
            .iam
            .store
            .transaction(|tx| async move {
                let tenant_id = id();
                let mut realm = Record::new();
                realm.insert("id".into(), Value::String(tenant_id.clone()));
                realm.insert("tenantId".into(), Value::String(tenant_id.clone()));
                realm.insert("name".into(), Value::String(name));
                realm.insert("type".into(), Value::String(kind.into()));
                realm.insert("parentId".into(), Value::String(parent_id));
                realm.insert("status".into(), Value::String("active".into()));
                realm.insert("createdAt".into(), json!(wall_clock()));
                let realm = tx.insert("tenants", &realm).await?;
                let mut authority = Record::new();
                authority.insert("id".into(), Value::String(id()));
                authority.insert("tenantId".into(), Value::String(tenant_id.clone()));
                authority.insert("identityId".into(), Value::String("pending".into()));
                authority.insert("parentAuthorityId".into(), Value::String(parent_authority));
                authority.insert("ceiling".into(), all_value());
                authority.insert("revoked".into(), Value::Bool(false));
                let authority = tx.insert("grantAuthorities", &authority).await?;
                let owner = auth
                    .create_identity(
                        &tx,
                        CreateIdentityInput {
                            tenant_id: tenant_id.clone(),
                            email: owner_email,
                            name: "Owner".into(),
                            password: Some("a strong tenant owner password".into()),
                            owner: Some(true),
                            root_admin: None,
                            email_verified: Some(true),
                        },
                    )
                    .await?;
                let realm: Tenant = decode(realm)?;
                let authority: GrantAuthority = decode(authority)?;
                ctx.owner_setup(&tx, &realm, &owner, &authority).await?;
                Ok::<_, IamError>((tenant_id, owner.id, authority.id))
            })
            .await
            .expect("organization");
        let owner = self.session(&owner_id).await;
        Org {
            tenant_id,
            owner_id,
            authority_id,
            owner,
        }
    }

    /// A member of the organization (`identities.create` with a password) and their sign-in.
    pub async fn member(&self, org: &Org, name: &str) -> Member {
        let auth = self.iam.auth.clone();
        let (tenant_id, name) = (org.tenant_id.clone(), name.to_owned());
        let identity = self
            .iam
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
            .expect("member");
        Member {
            credential: self.session(&identity.id).await,
            id: identity.id,
        }
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

    /// Merges `changes` into a stored record.
    pub async fn update(&self, collection: &str, record_id: &str, changes: Value) -> Record {
        let mut record = self
            .iam
            .store
            .get(collection, record_id)
            .await
            .unwrap()
            .expect("record exists");
        for (key, value) in changes.as_object().unwrap() {
            if value.is_null() {
                record.shift_remove(key);
            } else {
                record.insert(key.clone(), value.clone());
            }
        }
        self.put(collection, record).await
    }

    /// `roles.create` with an inline document, under the organization's authority.
    pub async fn role(&self, org: &Org, statements: Value) -> String {
        let role_id = id();
        self.insert(
            "roles",
            json!({
                "id": role_id,
                "tenantId": org.tenant_id,
                "name": format!("Role {role_id}"),
                "policyIds": [],
                "document": { "version": 1, "statements": statements },
                "protected": false,
                "authorityId": org.authority_id,
            }),
        )
        .await;
        role_id
    }

    /// `bindings.create` under the organization's authority; `extra` adds members (`expiresAt`, `eligible`, ...).
    pub async fn bind(
        &self,
        org: &Org,
        role_id: &str,
        subject_type: &str,
        subject_id: &str,
        extra: Value,
    ) -> String {
        let binding_id = id();
        let mut binding = json!({
            "id": binding_id,
            "tenantId": org.tenant_id,
            "subjectType": subject_type,
            "subjectId": subject_id,
            "roleId": role_id,
            "authorityId": org.authority_id,
        });
        for (key, value) in extra.as_object().unwrap() {
            binding[key] = value.clone();
        }
        self.insert("bindings", binding).await;
        binding_id
    }

    /// A role with `statements`, bound to the member.
    pub async fn grant(&self, org: &Org, member_id: &str, statements: Value) -> String {
        let role_id = self.role(org, statements).await;
        self.bind(org, &role_id, "identity", member_id, json!({}))
            .await;
        role_id
    }

    /// `groups.create`.
    pub async fn group(&self, org: &Org, name: &str) -> String {
        let group_id = id();
        self.insert(
            "groups",
            json!({ "id": group_id, "tenantId": org.tenant_id, "name": name }),
        )
        .await;
        group_id
    }

    /// `groups.addMember`; `expires_at` makes the membership temporary.
    pub async fn add_member(
        &self,
        org: &Org,
        group_id: &str,
        identity_id: &str,
        expires_at: Option<f64>,
    ) {
        let mut member = json!({
            "id": id(),
            "tenantId": org.tenant_id,
            "uniqueKey": format!("{group_id}:{identity_id}"),
            "groupId": group_id,
            "identityId": identity_id,
        });
        if let Some(expires_at) = expires_at {
            member["expiresAt"] = json!(expires_at);
        }
        self.insert("groupMembers", member).await;
    }

    /// A POST to `/api/iam/{path}` through the HTTP handler; the status and the JSON body.
    pub async fn post(&self, path: &str, body: Value, token: Option<&str>) -> (u16, Value) {
        let mut builder = http::Request::builder()
            .method(Method::POST)
            .uri(format!("{ORIGIN}/api/iam/{path}"))
            .header("content-type", "application/json")
            .header("x-better-iam", "1")
            .header("origin", ORIGIN);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let response = self
            .iam
            .handler(builder.body(Bytes::from(body.to_string())).unwrap())
            .await;
        (
            response.status().as_u16(),
            serde_json::from_slice(response.body()).unwrap_or(Value::Null),
        )
    }

    /// The audit events of a tenant with `action`.
    pub async fn audit(&self, tenant_id: &str, action: &str) -> Vec<Record> {
        self.iam
            .store
            .find(
                "audit",
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("action", action),
                &FindOptions::default(),
            )
            .await
            .unwrap()
    }
}

/// A route method's result as JSON.
pub fn ok<O: Serialize>(result: Result<Reply<O>, IamError>) -> Value {
    match result {
        Ok(reply) => reply.into_value().expect("serializable result"),
        Err(error) => panic!(
            "unexpected error {} ({}): {}",
            error.code, error.status, error.message
        ),
    }
}

/// A route method's error.
pub fn err<O: Serialize>(result: Result<Reply<O>, IamError>) -> IamError {
    match result {
        Ok(reply) => panic!(
            "expected an error, got {}",
            reply.into_value().unwrap_or(Value::Null)
        ),
        Err(error) => error,
    }
}

/// A request body.
pub fn body<I>(value: Value) -> Body<I> {
    Body::from_value(value)
}

/// The members of a JSON object.
pub fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("an object")
}

/// The token of a credential.
pub fn token(credential: &CredentialInput) -> &str {
    credential.token.as_deref().unwrap()
}
