//! The fixture of the roles, policies and groups suites, after tests/server-security.test.ts: a root tenant and two
//! organizations (`a`, `b`) written to the store, a root administrator with an MFA session, and two administrators
//! of `a` (`user` and `other`) holding full grant authorities (`user-authority`, `higher-authority`); `user` holds
//! a role granting everything under its own authority.

#![allow(dead_code)]

use std::future::Future;
use std::sync::Arc;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_auth::service::base::IssueSessionOptions;
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamStore, IamStoreExt, Identity,
    PermissionsConfig,
};
use better_iam_server::api::Body;
use better_iam_server::options::{
    AuthorizationRequest, BetterIamOptions, ResolvedResource, ResourceTarget,
};
use better_iam_server::{BetterIam, better_iam};
use serde_json::{Map, Value, json};

pub const SECRET: &str = "security-test-secret-32-characters-minimum";

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

pub fn full() -> Value {
    json!({ "version": 1, "statements": [{ "effect": "allow", "actions": ["*"], "resources": ["*"] }] })
}

pub struct Fixture {
    pub iam: BetterIam,
    pub user: Identity,
    pub other: Identity,
    pub root: CredentialInput,
    pub credential: CredentialInput,
}

pub fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

pub fn body<I>(value: Value) -> Body<I> {
    Body::from_value(value)
}

/// Writes records in one transaction.
pub async fn insert_all(iam: &BetterIam, records: Vec<(&str, Value)>) {
    let records: Vec<(String, Map<String, Value>)> = records
        .into_iter()
        .map(|(collection, record)| (collection.to_owned(), record.as_object().unwrap().clone()))
        .collect();
    iam.store
        .transaction(|tx| async move {
            for (collection, record) in records {
                tx.insert(&collection, &record).await?;
            }
            Ok(())
        })
        .await
        .unwrap();
}

pub async fn get(iam: &BetterIam, collection: &str, id: &str) -> Option<Map<String, Value>> {
    iam.store.get(collection, id).await.unwrap()
}

pub async fn find(iam: &BetterIam, collection: &str, filter: Filter) -> Vec<Map<String, Value>> {
    iam.store
        .find(collection, &filter, &FindOptions::default())
        .await
        .unwrap()
}

/// A verified identity of a tenant.
pub async fn identity(iam: &BetterIam, tenant_id: &str, email: &str, name: &str) -> Identity {
    let auth = iam.auth.clone();
    let input = CreateIdentityInput {
        tenant_id: tenant_id.to_owned(),
        email: email.to_owned(),
        name: name.to_owned(),
        password: None,
        owner: None,
        root_admin: None,
        email_verified: Some(true),
    };
    iam.store
        .transaction(|tx| async move { auth.create_identity(&tx, input).await })
        .await
        .unwrap()
}

/// A fresh session of an identity (`iam.auth.issueSession(tx, identity, { mfa })`).
pub async fn session(iam: &BetterIam, identity: &Identity, mfa: bool) -> CredentialInput {
    let auth = iam.auth.clone();
    let identity = identity.clone();
    let result = iam
        .store
        .transaction(|tx| async move {
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
        .unwrap();
    bearer(&result.token)
}

pub async fn fixture() -> Fixture {
    let store: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let mut options = BetterIamOptions::new(store, SECRET, "https://iam.example.com");
    options.permissions = Some(PermissionsConfig {
        actions: Some(vec!["documents:read".into(), "documents:write".into()]),
        ..PermissionsConfig::default()
    });
    options.resolve_resource = Some(Arc::new(|reference| {
        Box::pin(async move {
            let mut resolved = ResolvedResource::of(&reference);
            resolved.tenant_id = if reference.id.starts_with("b-") {
                "b".into()
            } else {
                "a".into()
            };
            Ok(resolved)
        })
    }));
    let iam = better_iam(options).expect("valid options");
    iam.initialize().await.expect("initialize");
    let now = better_iam_server::utils::date_now();
    let mut tenants = Vec::new();
    for (tenant_id, parent_id, kind) in [
        ("root", Value::Null, "root"),
        ("a", json!("root"), "organization"),
        ("b", json!("root"), "organization"),
    ] {
        tenants.push((
            "tenants",
            json!({
                "id": tenant_id,
                "tenantId": tenant_id,
                "parentId": parent_id,
                "type": kind,
                "name": tenant_id,
                "status": "active",
                "createdAt": now,
            }),
        ));
    }
    insert_all(&iam, tenants).await;
    let auth = iam.auth.clone();
    let administrator = iam
        .store
        .transaction(|tx| async move {
            auth.create_identity(
                &tx,
                CreateIdentityInput {
                    tenant_id: "root".into(),
                    email: "root@example.com".into(),
                    name: "Root".into(),
                    password: None,
                    owner: Some(true),
                    root_admin: Some(true),
                    email_verified: Some(true),
                },
            )
            .await
        })
        .await
        .unwrap();
    let user = identity(&iam, "a", "user@example.com", "User").await;
    let other = identity(&iam, "a", "superior@example.com", "Superior").await;
    let root = session(&iam, &administrator, true).await;
    let credential = session(&iam, &user, false).await;
    insert_all(
        &iam,
        vec![
            (
                "grantAuthorities",
                json!({ "id": "user-authority", "tenantId": "a", "identityId": user.id, "ceiling": full(), "revoked": false }),
            ),
            (
                "grantAuthorities",
                json!({ "id": "higher-authority", "tenantId": "a", "identityId": other.id, "ceiling": full(), "revoked": false }),
            ),
            (
                "policies",
                json!({ "id": "user-policy", "tenantId": "a", "name": "User permissions", "document": full(), "version": 1, "authorityId": "user-authority" }),
            ),
            (
                "roles",
                json!({ "id": "user-role", "tenantId": "a", "name": "User role", "policyIds": ["user-policy"], "protected": false, "authorityId": "user-authority" }),
            ),
            (
                "bindings",
                json!({ "id": "user-binding", "tenantId": "a", "subjectType": "identity", "subjectId": user.id, "roleId": "user-role", "authorityId": "user-authority" }),
            ),
        ],
    )
    .await;
    Fixture {
        iam,
        user,
        other,
        root,
        credential,
    }
}

/// A binding written to the store (`bindings.create` belongs to another API group).
pub async fn bind(iam: &BetterIam, role_id: &str, subject_id: &str, authority_id: &str) {
    insert_all(
        iam,
        vec![(
            "bindings",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": "a",
                "subjectType": "identity",
                "subjectId": subject_id,
                "roleId": role_id,
                "authorityId": authority_id,
            }),
        )],
    )
    .await;
}

/// Whether the credential may perform `action` on `document/{id}` in tenant `a`.
pub async fn can(iam: &BetterIam, credential: &CredentialInput, action: &str, id: &str) -> bool {
    iam.authorize(&AuthorizationRequest {
        credential: credential.clone(),
        tenant_id: "a".into(),
        action: action.into(),
        resource: ResourceTarget {
            kind: "document".into(),
            id: id.into(),
        },
    })
    .await
    .unwrap()
    .allowed
}

/// The code and status of a refusal.
pub fn refused<T: std::fmt::Debug>(result: Result<T, IamError>) -> (String, u16) {
    let error = result.expect_err("refused");
    (error.code, error.status)
}

pub fn code<T: std::fmt::Debug>(result: Result<T, IamError>) -> String {
    refused(result).0
}

/// A route method's answer as JSON.
pub fn value<O: serde::Serialize>(
    result: Result<better_iam_server::api::Reply<O>, IamError>,
) -> Result<Value, IamError> {
    result.and_then(|reply| reply.into_value())
}
