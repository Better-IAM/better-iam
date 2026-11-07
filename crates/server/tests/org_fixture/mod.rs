//! A bootstrapped platform with one organization ("Acme") and its owner, the Rust counterpart of
//! tests/support/organization.ts for the suites of the application catalog, OIDC providers and federation. The
//! groups, tenants and identities API groups belong to other port units, so the fixture writes the organization,
//! its owner (with the protected Owner role of `ownerSetup`) and members to the store directly, and signs people in
//! through the authentication service.

#![allow(dead_code)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamStore, IamStoreExt, Identity,
    PermissionsConfig, Record, Tenant,
};
use better_iam_server::options::{BetterIamOptions, ResolvedResource, ServerAuthOptions};
use better_iam_server::{BetterIam, better_iam};
use serde_json::{Value, json};

pub const DAY: f64 = 86_400_000.0;
pub const START: f64 = 1_792_410_217_881.0;

/// Runs a test body on a runtime with large stacks (debug-build futures are big).
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
    pub clock: Arc<Mutex<f64>>,
    pub root_tenant_id: String,
    pub root_id: String,
    pub tenant_id: String,
    pub owner_id: String,
    pub owner: CredentialInput,
    pub authority_id: String,
}

pub fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

/// The error code of a failed call.
pub fn code<T: std::fmt::Debug>(result: Result<T, IamError>) -> String {
    result.expect_err("expected an error").code
}

impl Org {
    pub async fn new(configure: impl FnOnce(&mut BetterIamOptions)) -> Org {
        let clock = Arc::new(Mutex::new(START));
        let store: Arc<dyn IamStore> =
            sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
        let mut options = BetterIamOptions::new(
            store,
            "organization-fixture-secret-with-32-characters",
            "http://localhost:3000",
        );
        options.permissions = Some(PermissionsConfig {
            actions: Some(vec!["documents:read".into(), "documents:write".into()]),
            ..PermissionsConfig::default()
        });
        options.resolve_resource = Some(Arc::new(|reference| {
            Box::pin(async move { Ok(ResolvedResource::of(&reference)) })
        }));
        let now = clock.clone();
        options.authentication = Some(ServerAuthOptions {
            session_lifetime_ms: Some(7.0 * DAY),
            session_idle_timeout_ms: Some(7.0 * DAY),
            now: Some(Arc::new(move || *now.lock().unwrap())),
            ..ServerAuthOptions::default()
        });
        configure(&mut options);
        let iam = better_iam(options).expect("valid options");
        iam.initialize().await.expect("initialize");
        let root = iam
            .bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
            .await
            .expect("bootstrap");
        let root_tenant_id = root["tenant"]["id"].as_str().unwrap().to_owned();
        let root_id = root["identity"]["id"].as_str().unwrap().to_owned();
        let tenant_id = better_iam_server::utils::id();
        let authority_id = better_iam_server::utils::id();
        let start = *clock.lock().unwrap();
        let owner_id = {
            let ctx = iam.ctx.clone();
            let auth = iam.auth.clone();
            let tenant_id = tenant_id.clone();
            let root_tenant_id = root_tenant_id.clone();
            let authority_id = authority_id.clone();
            iam.store
                .transaction(|tx| async move {
                    let tenant = json!({
                        "id": tenant_id,
                        "tenantId": tenant_id,
                        "name": "Acme",
                        "type": "organization",
                        "parentId": root_tenant_id,
                        "status": "active",
                        "createdAt": start,
                    });
                    let tenant = tx.insert("tenants", tenant.as_object().unwrap()).await?;
                    let authority = json!({
                        "id": authority_id,
                        "tenantId": tenant_id,
                        "identityId": "pending",
                        "ceiling": better_iam_server::utils::all_value(),
                        "revoked": false,
                    });
                    let authority = tx
                        .insert("grantAuthorities", authority.as_object().unwrap())
                        .await?;
                    let owner = auth
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
                    let realm: Tenant = better_iam_server::port::decode(tenant)?;
                    let authority: better_iam_server::models::GrantAuthority =
                        better_iam_server::port::decode(authority)?;
                    ctx.owner_setup(&tx, &realm, &owner, &authority).await?;
                    Ok(owner.id)
                })
                .await
                .expect("organization")
        };
        let mut org = Org {
            iam,
            clock,
            root_tenant_id,
            root_id,
            tenant_id,
            owner_id,
            owner: CredentialInput::default(),
            authority_id,
        };
        org.owner = org.owner_sign_in().await;
        org
    }

    pub fn now(&self) -> f64 {
        *self.clock.lock().unwrap()
    }

    pub fn advance(&self, ms: f64) {
        *self.clock.lock().unwrap() += ms;
    }

    /// Creates a person `{name}@acme.test` with a password.
    pub async fn member(&self, name: &str) -> Identity {
        let auth = self.iam.auth.clone();
        let tenant_id = self.tenant_id.clone();
        let name = name.to_owned();
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
    }

    async fn password_sign_in(&self, email: &str, password: &str) -> CredentialInput {
        let result = self
            .iam
            .auth
            .sign_in(&json!({ "tenantId": self.tenant_id, "email": email, "password": password }))
            .await
            .expect("sign in");
        bearer(&result.session().expect("no MFA").token)
    }

    /// A session of member `{name}@acme.test`.
    pub async fn sign_in(&self, name: &str) -> CredentialInput {
        self.password_sign_in(
            &format!("{name}@acme.test"),
            &format!("a strong {name} password"),
        )
        .await
    }

    /// A fresh owner session, recently authenticated.
    pub async fn owner_sign_in(&self) -> CredentialInput {
        self.password_sign_in("owner@acme.test", "a strong tenant owner password")
            .await
    }

    pub async fn insert(&self, collection: &str, record: Value) -> Record {
        let collection = collection.to_owned();
        let record = record.as_object().unwrap().clone();
        self.iam
            .store
            .transaction(|tx| async move { tx.insert(&collection, &record).await })
            .await
            .unwrap()
    }

    pub async fn put(&self, collection: &str, record: Record) -> Record {
        let collection = collection.to_owned();
        self.iam
            .store
            .transaction(|tx| async move { tx.put(&collection, &record).await })
            .await
            .unwrap()
    }

    pub async fn get(&self, collection: &str, id: &str) -> Option<Record> {
        self.iam.store.get(collection, id).await.unwrap()
    }

    pub async fn find(&self, collection: &str, filter: Filter) -> Vec<Record> {
        self.iam
            .store
            .find(collection, &filter, &FindOptions::default())
            .await
            .unwrap()
    }

    /// A group of the organization (as `groups.create` stores it).
    pub async fn group(&self, name: &str) -> String {
        let id = better_iam_server::utils::id();
        self.insert(
            "groups",
            json!({ "id": id, "tenantId": self.tenant_id, "name": name, "createdAt": self.now() }),
        )
        .await;
        id
    }

    /// A membership (as `groups.addMember` stores it).
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

    /// A role with an inline document bound to an identity under the owner's authority (`roles.create` and
    /// `bindings.create`).
    pub async fn grant(&self, identity_id: &str, statements: Value) -> String {
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
                "authorityId": self.authority_id,
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
                "authorityId": self.authority_id,
            }),
        )
        .await;
        role_id
    }

    /// Changes members of a stored record.
    pub async fn patch(&self, collection: &str, id: &str, changes: Value) -> Record {
        let mut record = self.get(collection, id).await.expect("record");
        for (key, value) in changes.as_object().unwrap() {
            if value.is_null() {
                record.shift_remove(key);
            } else {
                record.insert(key.clone(), value.clone());
            }
        }
        self.put(collection, record).await
    }
}
