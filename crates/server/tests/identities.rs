//! The `identities` and `serviceAccounts` API groups. Ported from the TypeScript suites that exercise them
//! (tests/directory.test.ts, tests/impersonation.test.ts, tests/owner-gates.test.ts, tests/manager.test.ts,
//! tests/data-export.test.ts, tests/federation-import-gaps.test.ts, tests/credential-hygiene.test.ts). The tenant, its
//! owner and the grants are written to the store directly where the TypeScript tests create them through
//! `tenants.create`, `tenants.acceptInvitation`, `roles.create` and `bindings.create`, and members are created with
//! `auth.createIdentity`. Calls that end in `afterIdentityChange` (package automation) commit before it runs; while
//! that module is still a skeleton their effect is read back from the store.

use std::future::Future;
use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::DeliveryMessage;
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamStore, IamStoreExt, Record, Tenant,
};
use better_iam_server::api::Body;
use better_iam_server::models::GrantAuthority;
use better_iam_server::options::{BetterIamOptions, ServerAuthOptions};
use better_iam_server::{BetterIam, better_iam};
use bytes::Bytes;
use http::Method;
use serde_json::{Value, json};

const ORIGIN: &str = "https://iam.example.com";
const SECRET: &str = "identities-test-secret-with-at-least-32-chars!!";
const OWNER_PASSWORD: &str = "a strong tenant owner password";

fn run<F, Fut>(body: F)
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

struct Fixture {
    iam: BetterIam,
    tenant_id: String,
    owner_id: String,
    owner_authority: String,
    owner: CredentialInput,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
}

fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

async fn post(iam: &BetterIam, path: &str, body: Value, token: Option<&str>) -> Value {
    let mut builder = http::Request::builder()
        .method(Method::POST)
        .uri(format!("{ORIGIN}/api/iam/{path}"))
        .header("content-type", "application/json")
        .header("x-better-iam", "1");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = iam
        .handler(builder.body(Bytes::from(body.to_string())).unwrap())
        .await;
    serde_json::from_slice(response.body()).unwrap_or(Value::Null)
}

async fn sign_in(f: &Fixture, email: &str, password: &str) -> String {
    let answer = post(
        &f.iam,
        "auth/signIn",
        json!({ "tenantId": f.tenant_id, "email": email, "password": password }),
        None,
    )
    .await;
    answer["data"]["token"]
        .as_str()
        .unwrap_or_else(|| panic!("sign-in failed: {answer}"))
        .to_owned()
}

async fn transact<T, F, Fut>(iam: &BetterIam, body: F) -> T
where
    T: Send + 'static,
    F: FnOnce(Arc<dyn IamStore>) -> Fut + Send,
    Fut: Future<Output = Result<T, IamError>> + Send,
{
    iam.store.transaction(body).await.unwrap()
}

async fn insert(iam: &BetterIam, collection: &str, record: Value) -> Record {
    let collection = collection.to_owned();
    let record = record.as_object().unwrap().clone();
    transact(
        iam,
        |tx| async move { tx.insert(&collection, &record).await },
    )
    .await
}

async fn put(iam: &BetterIam, collection: &str, record: Record) -> Record {
    let collection = collection.to_owned();
    transact(iam, |tx| async move { tx.put(&collection, &record).await }).await
}

async fn get(iam: &BetterIam, collection: &str, id: &str) -> Option<Record> {
    iam.store.get(collection, id).await.unwrap()
}

async fn find(iam: &BetterIam, collection: &str, filter: Filter) -> Vec<Record> {
    iam.store
        .find(collection, &filter, &FindOptions::default())
        .await
        .unwrap()
}

async fn fixture() -> Fixture {
    let store: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let mut options = BetterIamOptions::new(store, SECRET, ORIGIN);
    let sink = inbox.clone();
    options.authentication = Some(ServerAuthOptions {
        send_email: Some(better_iam_auth::delivery_fn(move |message| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(message);
                Ok(())
            }
        })),
        ..ServerAuthOptions::default()
    });
    let iam = better_iam(options).expect("valid options");
    iam.initialize().await.expect("initialize");
    let root = iam
        .bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
        .await
        .expect("bootstrap");
    let root_tenant = root["tenant"]["id"].as_str().unwrap().to_owned();
    let root_id = root["identity"]["id"].as_str().unwrap().to_owned();
    let root_authority = find(
        &iam,
        "grantAuthorities",
        Filter::new().eq("identityId", root_id),
    )
    .await
    .into_iter()
    .next()
    .expect("root authority")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // `tenants.create` + `tenants.acceptInvitation`: an active organization under the root, its owner, the owner's
    // unlimited grant authority and the protected Owner role.
    let tenant_id = better_iam_server::utils::id();
    let tenant = insert(
        &iam,
        "tenants",
        json!({
            "id": tenant_id,
            "tenantId": tenant_id,
            "name": "Acme",
            "type": "organization",
            "parentId": root_tenant,
            "status": "active",
            "createdAt": better_iam_server::utils::date_now(),
        }),
    )
    .await;
    let tenant: Tenant = serde_json::from_value(Value::Object(tenant)).unwrap();
    let (owner_id, owner_authority) = {
        let ctx = iam.ctx.clone();
        let auth = iam.auth.clone();
        let tenant = tenant.clone();
        let root_authority = root_authority.clone();
        transact(&iam, |tx| async move {
            let owner = auth
                .create_identity(
                    &tx,
                    CreateIdentityInput {
                        tenant_id: tenant.id.clone(),
                        email: "owner@acme.test".into(),
                        name: "Owner".into(),
                        password: Some(OWNER_PASSWORD.into()),
                        owner: Some(true),
                        root_admin: None,
                        email_verified: Some(true),
                    },
                )
                .await?;
            let authority = tx
                .insert(
                    "grantAuthorities",
                    json!({
                        "id": better_iam_server::utils::id(),
                        "tenantId": tenant.id,
                        "identityId": owner.id,
                        "ceiling": better_iam_server::utils::all_value(),
                        "parentAuthorityId": root_authority,
                        "revoked": false,
                    })
                    .as_object()
                    .unwrap(),
                )
                .await?;
            let authority: GrantAuthority =
                serde_json::from_value(Value::Object(authority)).unwrap();
            ctx.owner_setup(&tx, &tenant, &owner, &authority).await?;
            Ok((owner.id, authority.id))
        })
        .await
    };
    let mut f = Fixture {
        iam,
        tenant_id,
        owner_id,
        owner_authority,
        owner: CredentialInput::default(),
        inbox,
    };
    let token = sign_in(&f, "owner@acme.test", OWNER_PASSWORD).await;
    f.owner = bearer(&token);
    f
}

/// `auth.createIdentity` for a member of the fixture's tenant.
async fn member(f: &Fixture, name: &str, email: &str, password: Option<&str>) -> String {
    let auth = f.iam.auth.clone();
    let input = CreateIdentityInput {
        tenant_id: f.tenant_id.clone(),
        email: email.into(),
        name: name.into(),
        password: password.map(str::to_owned),
        owner: None,
        root_admin: None,
        email_verified: Some(true),
    };
    transact(&f.iam, |tx| async move {
        auth.create_identity(&tx, input).await
    })
    .await
    .id
}

/// A role with an inline document, bound to `subject` under the owner's authority (`roles.create` +
/// `bindings.create`).
async fn grant(f: &Fixture, subject: &str, actions: &[&str]) {
    let role_id = better_iam_server::utils::id();
    insert(
        &f.iam,
        "roles",
        json!({
            "id": role_id,
            "tenantId": f.tenant_id,
            "name": format!("Role {role_id}"),
            "policyIds": [],
            "document": { "version": 1, "statements": [{ "effect": "allow", "actions": actions, "resources": ["*"] }] },
            "protected": false,
            "authorityId": f.owner_authority,
        }),
    )
    .await;
    insert(
        &f.iam,
        "bindings",
        json!({
            "id": better_iam_server::utils::id(),
            "tenantId": f.tenant_id,
            "subjectType": "identity",
            "subjectId": subject,
            "roleId": role_id,
            "authorityId": f.owner_authority,
        }),
    )
    .await;
}

fn reply<O: serde::Serialize>(reply: better_iam_server::api::Reply<O>) -> Value {
    match reply {
        better_iam_server::api::Reply::Json(value) => value,
        better_iam_server::api::Reply::Typed(typed) => serde_json::to_value(typed).unwrap(),
    }
}

/// `iam.api.<group>.<method>(credential, input)` as JSON.
macro_rules! call {
    ($f:expr, $group:ident . $method:ident, $credential:expr, $input:expr) => {
        $f.iam
            .api
            .$group
            .$method(&$credential, Body::from_value($input))
            .await
            .map(reply)
    };
}

fn code(result: Result<Value, IamError>) -> (String, u16, String) {
    let error = result.expect_err("expected a refusal");
    (error.code, error.status, error.message)
}

/// A call whose operation committed before `afterIdentityChange` (package automation, another module of the port)
/// answered: while that is a skeleton it answers NOT_IMPLEMENTED, and the committed record is read back instead.
async fn after_change(f: &Fixture, result: Result<Value, IamError>, identity: &Filter) -> Value {
    match result {
        Ok(value) => value,
        Err(error)
            if error.code == "NOT_IMPLEMENTED" && error.message.contains("afterIdentityChange") =>
        {
            let mut record = find(&f.iam, "identities", identity.clone())
                .await
                .into_iter()
                .next()
                .expect("committed identity");
            record.shift_remove("passwordHash");
            Value::Object(record)
        }
        Err(error) => panic!("unexpected error {error:?}"),
    }
}

fn names(list: &Value) -> Vec<String> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap().to_owned())
        .collect()
}

async fn audit_events(f: &Fixture, action: &str) -> Vec<Record> {
    find(
        &f.iam,
        "audit",
        Filter::new()
            .eq("tenantId", f.tenant_id.clone())
            .eq("action", action),
    )
    .await
}

#[test]
fn searches_identities_by_name_or_email_with_stable_pagination() {
    run(|| async {
        let f = fixture().await;
        member(&f, "Zoe Zhang", "zoe@acme.test", None).await;
        member(&f, "Alice Adams", "alice@acme.test", None).await;
        member(&f, "Bob Brown", "bob@other.test", None).await;
        insert(
            &f.iam,
            "identities",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": f.tenant_id,
                "kind": "service",
                "name": "ci-bot",
                "status": "active",
                "emailVerified": false,
                "owner": false,
                "rootAdmin": false,
                "createdAt": 1,
            }),
        )
        .await;
        let all = call!(
            f,
            identities.list,
            f.owner,
            json!({ "tenantId": f.tenant_id })
        )
        .unwrap();
        // Ordered by name, case-insensitively.
        assert_eq!(
            names(&all),
            ["Alice Adams", "Bob Brown", "ci-bot", "Owner", "Zoe Zhang"]
        );
        assert!(
            all.as_array()
                .unwrap()
                .iter()
                .all(|identity| identity.get("passwordHash").is_none())
        );
        let acme = call!(
            f,
            identities.list,
            f.owner,
            json!({ "tenantId": f.tenant_id, "query": "ACME" })
        )
        .unwrap();
        let emails: Vec<&str> = acme
            .as_array()
            .unwrap()
            .iter()
            .map(|identity| identity["email"].as_str().unwrap())
            .collect();
        assert_eq!(
            emails,
            ["alice@acme.test", "owner@acme.test", "zoe@acme.test"]
        );
        let bo = call!(
            f,
            identities.list,
            f.owner,
            json!({ "tenantId": f.tenant_id, "query": "bo" })
        )
        .unwrap();
        assert_eq!(names(&bo), ["Bob Brown", "ci-bot"]);
        let page = call!(
            f,
            identities.list,
            f.owner,
            json!({ "tenantId": f.tenant_id, "kind": "user", "limit": 2, "offset": 1 })
        )
        .unwrap();
        assert_eq!(names(&page), ["Bob Brown", "Owner"]);
        let (code_, _, message) = code(call!(
            f,
            identities.list,
            f.owner,
            json!({ "tenantId": f.tenant_id, "limit": 0 })
        ));
        assert_eq!(
            (code_.as_str(), message.as_str()),
            ("INVALID_INPUT", "Invalid limit")
        );
        let (code_, _, message) = code(call!(
            f,
            identities.list,
            f.owner,
            json!({ "tenantId": f.tenant_id, "kind": "robot" })
        ));
        assert_eq!(
            (code_.as_str(), message.as_str()),
            ("INVALID_INPUT", "Invalid identity kind")
        );
        let (_, _, message) = code(call!(
            f,
            identities.list,
            f.owner,
            json!({ "tenantId": f.tenant_id, "status": "gone" })
        ));
        assert_eq!(message, "Invalid identity status");
        // Deleted identities show with includeDeleted or status: 'deleted' only; expiresBefore keeps the scheduled.
        let mut zoe = find(
            &f.iam,
            "identities",
            Filter::new().eq("email", "zoe@acme.test"),
        )
        .await
        .remove(0);
        zoe.insert("status".into(), json!("deleted"));
        put(&f.iam, "identities", zoe).await;
        let mut bob = find(
            &f.iam,
            "identities",
            Filter::new().eq("email", "bob@other.test"),
        )
        .await
        .remove(0);
        bob.insert("expiresAt".into(), json!(5_000));
        put(&f.iam, "identities", bob).await;
        let listed = call!(
            f,
            identities.list,
            f.owner,
            json!({ "tenantId": f.tenant_id })
        )
        .unwrap();
        assert_eq!(
            names(&listed),
            ["Alice Adams", "Bob Brown", "ci-bot", "Owner"]
        );
        let everyone = call!(
            f,
            identities.list,
            f.owner,
            json!({ "tenantId": f.tenant_id, "includeDeleted": true })
        )
        .unwrap();
        assert_eq!(everyone.as_array().unwrap().len(), 5);
        let deleted = call!(
            f,
            identities.list,
            f.owner,
            json!({ "tenantId": f.tenant_id, "status": "deleted" })
        )
        .unwrap();
        assert_eq!(names(&deleted), ["Zoe Zhang"]);
        let expiring = call!(
            f,
            identities.list,
            f.owner,
            json!({ "tenantId": f.tenant_id, "expiresBefore": 5_000 })
        )
        .unwrap();
        assert_eq!(names(&expiring), ["Bob Brown"]);
    });
}

#[test]
fn lets_administrators_change_a_member_email_revoking_sessions_and_verification() {
    run(|| async {
        let f = fixture().await;
        let alice = member(
            &f,
            "Alice",
            "alice@acme.test",
            Some("a strong alice password"),
        )
        .await;
        member(&f, "Taken", "taken@acme.test", None).await;
        let login = sign_in(&f, "alice@acme.test", "a strong alice password").await;
        let (code_, status, _) = code(call!(
            f,
            identities.update,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice, "email": "taken@acme.test" })
        ));
        assert_eq!((code_.as_str(), status), ("IDENTITY_EXISTS", 409));
        let (code_, _, message) = code(call!(
            f,
            identities.update,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice })
        ));
        assert_eq!(
            (code_.as_str(), message.as_str()),
            ("INVALID_INPUT", "Nothing to update")
        );
        let result = call!(
            f,
            identities.update,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice, "email": "Alice.New@Acme.test" })
        );
        let updated = after_change(&f, result, &Filter::new().eq("id", alice.clone())).await;
        assert_eq!(updated["email"], json!("alice.new@acme.test"));
        assert_eq!(updated["emailVerified"], json!(false));
        assert_eq!(updated["uniqueKey"], json!("email:alice.new@acme.test"));
        let session = post(&f.iam, "auth/getSession", json!({}), Some(&login)).await;
        assert_eq!(session["error"]["code"], json!("UNAUTHENTICATED"));
        sign_in(&f, "alice.new@acme.test", "a strong alice password").await;
        let trail = audit_events(&f, "identity:email-change").await;
        assert_eq!(trail.len(), 1);
        assert_eq!(
            trail[0]["metadata"],
            json!({ "from": "alice@acme.test", "to": "alice.new@acme.test" })
        );
        // Setting the same email again changes nothing and is not audited twice.
        let again = call!(
            f,
            identities.update,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice, "email": "alice.new@acme.test" })
        );
        after_change(&f, again, &Filter::new().eq("id", alice.clone())).await;
        assert_eq!(audit_events(&f, "identity:email-change").await.len(), 1);
    });
}

#[test]
fn lists_a_members_active_sessions_without_token_material() {
    run(|| async {
        let f = fixture().await;
        let alice = member(
            &f,
            "Alice",
            "alice@acme.test",
            Some("a strong alice password"),
        )
        .await;
        let first = sign_in(&f, "alice@acme.test", "a strong alice password").await;
        sign_in(&f, "alice@acme.test", "a strong alice password").await;
        let input = json!({ "tenantId": f.tenant_id, "identityId": alice });
        let sessions = call!(f, identities.list_sessions, f.owner, input.clone()).unwrap();
        let list = sessions.as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert!(
            list.iter()
                .all(|session| session["method"] == json!("password"))
        );
        assert!(!sessions.to_string().contains(&first));
        assert!(list[0].get("tokenHash").is_none() && list[0].get("uniqueKey").is_none());
        let (code_, _, _) = code(call!(
            f,
            identities.list_sessions,
            bearer(&first),
            input.clone()
        ));
        assert_eq!(code_, "ACCESS_DENIED");
        let revoked = post(
            &f.iam,
            "auth/revokeSession",
            json!({ "sessionId": list[1]["id"] }),
            Some(&first),
        )
        .await;
        assert!(revoked.get("error").is_none(), "{revoked}");
        let left = call!(f, identities.list_sessions, f.owner, input).unwrap();
        assert_eq!(left.as_array().unwrap().len(), 1);
    });
}

#[test]
fn impersonation_is_opt_in_limited_to_eligible_members_and_attributed() {
    run(|| async {
        let f = fixture().await;
        let alice = member(
            &f,
            "alice",
            "alice@acme.test",
            Some("a strong alice password"),
        )
        .await;
        let bob = member(&f, "bob", "bob@acme.test", Some("a strong bob password")).await;
        let impersonate = |credential: CredentialInput, identity_id: String, reason: &str| {
            let input =
                json!({ "tenantId": f.tenant_id, "identityId": identity_id, "reason": reason });
            let iam = &f.iam;
            async move {
                iam.api
                    .identities
                    .impersonate(&credential, Body::from_value(input))
                    .await
                    .map(reply)
            }
        };
        let (code_, _, _) = code(impersonate(f.owner.clone(), alice.clone(), "ticket 42").await);
        assert_eq!(code_, "FEATURE_DISABLED");
        // `tenants.setAuthPolicy({ allowImpersonation: true })`.
        let mut tenant = get(&f.iam, "tenants", &f.tenant_id).await.unwrap();
        tenant.insert("authPolicy".into(), json!({ "allowImpersonation": true }));
        put(&f.iam, "tenants", tenant).await;
        // Eligibility: a reason, permission, and a target who is neither the caller nor an owner.
        let (code_, _, _) = code(impersonate(f.owner.clone(), alice.clone(), "").await);
        assert_eq!(code_, "INVALID_INPUT");
        let (code_, _, message) =
            code(impersonate(f.owner.clone(), f.owner_id.clone(), "ticket 42").await);
        assert_eq!(
            (code_.as_str(), message.as_str()),
            ("INVALID_INPUT", "You cannot impersonate yourself")
        );
        let alice_login = sign_in(&f, "alice@acme.test", "a strong alice password").await;
        let (code_, _, _) = code(impersonate(bearer(&alice_login), bob.clone(), "ticket 42").await);
        assert_eq!(code_, "ACCESS_DENIED");
        // Support staff get a scoped role: read members and impersonate them.
        grant(
            &f,
            &bob,
            &["iam:identities:read", "iam:identities:impersonate"],
        )
        .await;
        grant(
            &f,
            &alice,
            &["iam:identities:read", "iam:identities:impersonate"],
        )
        .await;
        let bob_login = sign_in(&f, "bob@acme.test", "a strong bob password").await;
        let (code_, status, message) =
            code(impersonate(bearer(&bob_login), f.owner_id.clone(), "ticket 42").await);
        assert_eq!(
            (code_.as_str(), status, message.as_str()),
            (
                "ACCESS_DENIED",
                403,
                "Owners and root administrators cannot be impersonated"
            )
        );
        let view_as = call!(
            f,
            identities.impersonate,
            bearer(&bob_login),
            json!({ "tenantId": f.tenant_id, "identityId": alice, "reason": "ticket 42", "durationMs": 600_000 })
        )
        .unwrap();
        assert_eq!(view_as["identity"]["id"], json!(alice));
        assert!(view_as["identity"].get("passwordHash").is_none());
        assert_eq!(view_as["session"]["identityId"], json!(alice));
        assert_eq!(view_as["session"]["method"], json!("impersonation"));
        assert_eq!(view_as["session"]["impersonatorId"], json!(bob));
        assert_eq!(
            view_as["session"]["expiresAt"].as_f64().unwrap()
                - view_as["session"]["createdAt"].as_f64().unwrap(),
            600_000.0
        );
        assert!(!view_as.to_string().contains("tokenHash"));
        let token = view_as["token"].as_str().unwrap();
        let seen = post(&f.iam, "auth/getSession", json!({}), Some(token)).await;
        assert_eq!(seen["data"]["identity"]["id"], json!(alice));
        assert_eq!(seen["data"]["session"]["impersonatorId"], json!(bob));
        // Operations run as Alice but every record names Bob as the impersonator.
        let read = call!(
            f,
            identities.get,
            bearer(token),
            json!({ "tenantId": f.tenant_id, "identityId": bob })
        )
        .unwrap();
        assert_eq!(read["name"], json!("bob"));
        let started = audit_events(&f, "identity:impersonate").await;
        assert_eq!(started.len(), 1);
        assert_eq!(started[0]["actorId"], json!(bob));
        assert_eq!(started[0]["resourceId"], json!(alice));
        assert_eq!(started[0]["metadata"]["reason"], json!("ticket 42"));
        assert_eq!(
            started[0]["metadata"]["sessionId"],
            view_as["session"]["id"]
        );
        let reads = audit_events(&f, "iam:identities:read").await;
        assert!(
            reads
                .iter()
                .any(|event| event["actorId"] == json!(alice)
                    && event["impersonatorId"] == json!(bob))
        );
        // The impersonation session cannot open another one (recent authentication).
        let (code_, _, _) = code(impersonate(bearer(token), bob.clone(), "again").await);
        assert_eq!(code_, "IMPERSONATION_RESTRICTED");
    });
}

#[test]
fn links_and_unlinks_external_sign_ins_ahead_of_the_first_one() {
    run(|| async {
        let f = fixture().await;
        let alice = member(&f, "Alice", "alice@acme.test", None).await;
        let bob = member(&f, "Bob", "bob@acme.test", None).await;
        let link = |identity: &str, provider: &str, subject: &str| {
            json!({
                "tenantId": f.tenant_id,
                "identityId": identity,
                "providerId": provider,
                "issuer": "https://idp.example.test",
                "subject": subject,
            })
        };
        let linked = call!(
            f,
            identities.link_provider,
            f.owner,
            link(&alice, "okta", "00u1")
        )
        .unwrap();
        assert_eq!(linked["identityId"], json!(alice));
        assert_eq!(linked["providerId"], json!("okta"));
        assert_eq!(linked["subject"], json!("00u1"));
        assert!(linked["createdAt"].is_number());
        let stored = get(&f.iam, "externalIdentities", linked["id"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(
            stored["uniqueKey"],
            json!(r#"["okta","https://idp.example.test","00u1"]"#)
        );
        // The same external account links to one person only, and a person once per provider.
        let (code_, status, message) = code(call!(
            f,
            identities.link_provider,
            f.owner,
            link(&bob, "okta", "00u1")
        ));
        assert_eq!(
            (code_.as_str(), status, message.as_str()),
            (
                "ACCOUNT_LINK_CONFLICT",
                409,
                "External identity is already linked to another account"
            )
        );
        let (_, _, message) = code(call!(
            f,
            identities.link_provider,
            f.owner,
            link(&alice, "okta", "00u2")
        ));
        assert_eq!(
            message,
            "This account is already linked through that provider; unlink it first"
        );
        let (_, _, message) = code(call!(
            f,
            identities.link_provider,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice, "providerId": "x", "issuer": "y" })
        ));
        assert_eq!(message, "Invalid subject");
        call!(
            f,
            identities.link_provider,
            f.owner,
            link(&alice, "azure", "aad-1")
        )
        .unwrap();
        let providers = call!(
            f,
            identities.list_providers,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice })
        )
        .unwrap();
        let order: Vec<&str> = providers
            .as_array()
            .unwrap()
            .iter()
            .map(|link| link["providerId"].as_str().unwrap())
            .collect();
        assert_eq!(order, ["azure", "okta"]);
        let audited = audit_events(&f, "identity:link-provider").await;
        assert_eq!(audited.len(), 2);
        assert_eq!(audited[0]["metadata"]["providerId"], json!("okta"));
        assert_eq!(audited[0]["metadata"]["linkId"], linked["id"]);
        // Another person's link is not found through this account.
        let (code_, status, message) = code(call!(
            f,
            identities.unlink_provider,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": bob, "linkId": linked["id"] })
        ));
        assert_eq!(
            (code_.as_str(), status, message.as_str()),
            ("NOT_FOUND", 404, "Linked sign-in not found")
        );
        let removed = call!(
            f,
            identities.unlink_provider,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice, "linkId": linked["id"] })
        )
        .unwrap();
        assert_eq!(removed["id"], linked["id"]);
        assert!(
            get(&f.iam, "externalIdentities", linked["id"].as_str().unwrap())
                .await
                .is_none()
        );
        assert_eq!(audit_events(&f, "identity:unlink-provider").await.len(), 1);
        // Only people sign in through external providers.
        let service = insert(
            &f.iam,
            "identities",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": f.tenant_id,
                "kind": "service",
                "name": "ci-bot",
                "status": "active",
                "emailVerified": false,
                "owner": false,
                "rootAdmin": false,
                "createdAt": 1,
            }),
        )
        .await;
        let (_, _, message) = code(call!(
            f,
            identities.link_provider,
            f.owner,
            link(service["id"].as_str().unwrap(), "okta", "svc")
        ));
        assert_eq!(message, "Only people sign in through external providers");
    });
}

#[test]
fn an_owners_sign_in_address_and_password_need_another_owner() {
    run(|| async {
        let f = fixture().await;
        let admin = member(
            &f,
            "Admin",
            "admin@acme.test",
            Some("a strong admin password"),
        )
        .await;
        grant(
            &f,
            &admin,
            &["iam:identities:update", "iam:identities:read"],
        )
        .await;
        let token = sign_in(&f, "admin@acme.test", "a strong admin password").await;
        let (code_, status, message) = code(call!(
            f,
            identities.request_password_reset,
            bearer(&token),
            json!({ "tenantId": f.tenant_id, "identityId": f.owner_id })
        ));
        assert_eq!(
            (code_.as_str(), status, message.as_str()),
            (
                "ACCESS_DENIED",
                403,
                "Only an owner can change an owner\u{2019}s sign-in address or password"
            )
        );
        let (_, _, message) = code(call!(
            f,
            identities.link_provider,
            bearer(&token),
            json!({ "tenantId": f.tenant_id, "identityId": f.owner_id, "providerId": "okta", "issuer": "i", "subject": "s" })
        ));
        assert_eq!(
            message,
            "Only an owner can change an owner\u{2019}s sign-in address or password"
        );
        // The refusals are audited as denials of the operation.
        let denials: Vec<Record> = audit_events(&f, "iam:identities:update")
            .await
            .into_iter()
            .filter(|event| event["outcome"] == json!("deny"))
            .collect();
        assert_eq!(denials.len(), 2);
        // An administrator may reset a member's password; the owner may reset anyone's.
        let alice = member(&f, "Alice", "alice@acme.test", None).await;
        let queued = call!(
            f,
            identities.request_password_reset,
            bearer(&token),
            json!({ "tenantId": f.tenant_id, "identityId": alice })
        )
        .unwrap();
        assert_eq!(
            queued,
            json!({ "queued": true, "email": "alice@acme.test" })
        );
        assert_eq!(audit_events(&f, "identity:password-reset").await.len(), 1);
        // Changing your own manager needs another administrator.
        let (code_, _, message) = code(call!(
            f,
            identities.update,
            bearer(&token),
            json!({ "tenantId": f.tenant_id, "identityId": admin, "managerId": alice })
        ));
        assert_eq!(
            (code_.as_str(), message.as_str()),
            (
                "ACCESS_DENIED",
                "Your own attributes, manager and expiry are changed by another administrator"
            )
        );
        // Renaming yourself is not such a change.
        let renamed = call!(
            f,
            identities.update,
            bearer(&token),
            json!({ "tenantId": f.tenant_id, "identityId": admin, "name": "Admin Two" })
        );
        let renamed = after_change(&f, renamed, &Filter::new().eq("id", admin.clone())).await;
        assert_eq!(renamed["name"], json!("Admin Two"));
    });
}

#[test]
fn transfers_ownership_and_passes_the_owner_authority_on() {
    run(|| async {
        let f = fixture().await;
        let alice = member(
            &f,
            "Alice",
            "alice@acme.test",
            Some("a strong alice password"),
        )
        .await;
        let promoted = call!(
            f,
            identities.set_owner,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice, "owner": true })
        )
        .unwrap();
        assert_eq!(promoted["owner"], json!(true));
        let authority = find(
            &f.iam,
            "grantAuthorities",
            Filter::new()
                .eq("tenantId", f.tenant_id.clone())
                .eq("identityId", alice.clone()),
        )
        .await
        .remove(0);
        assert_eq!(authority["parentAuthorityId"], json!(f.owner_authority));
        assert_eq!(authority["revoked"], json!(false));
        let owner_role = find(
            &f.iam,
            "roles",
            Filter::new()
                .eq("tenantId", f.tenant_id.clone())
                .eq("uniqueKey", "system:owner"),
        )
        .await
        .remove(0);
        let binding = find(
            &f.iam,
            "bindings",
            Filter::new()
                .eq("subjectId", alice.clone())
                .eq("roleId", owner_role["id"].clone()),
        )
        .await;
        assert_eq!(binding.len(), 1);
        assert_eq!(binding[0]["authorityId"], authority["id"]);
        // Only an owner (in person) or root transfers ownership.
        let bob = member(&f, "Bob", "bob@acme.test", Some("a strong bob password")).await;
        grant(&f, &bob, &["iam:identities:update"]).await;
        let bob_token = sign_in(&f, "bob@acme.test", "a strong bob password").await;
        let (code_, status, message) = code(call!(
            f,
            identities.set_owner,
            bearer(&bob_token),
            json!({ "tenantId": f.tenant_id, "identityId": bob, "owner": true })
        ));
        assert_eq!(
            (code_.as_str(), status, message.as_str()),
            ("ACCESS_DENIED", 403, "Only an owner can transfer ownership")
        );
        let (_, _, message) = code(call!(
            f,
            identities.set_owner,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": bob, "owner": "yes" })
        ));
        assert_eq!(message, "Invalid owner");
        // Alice steps down: her owner authority passes to the remaining owner who removed her.
        let demoted = call!(
            f,
            identities.set_owner,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice, "owner": false })
        )
        .unwrap();
        assert_eq!(demoted["owner"], json!(false));
        let passed = get(
            &f.iam,
            "grantAuthorities",
            authority["id"].as_str().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(passed["identityId"], json!(f.owner_id));
        assert_eq!(passed["revoked"], json!(false));
        assert!(
            find(
                &f.iam,
                "bindings",
                Filter::new()
                    .eq("subjectId", alice.clone())
                    .eq("roleId", owner_role["id"].clone()),
            )
            .await
            .is_empty()
        );
        // The last owner stays.
        let (code_, status, _) = code(call!(
            f,
            identities.set_owner,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": f.owner_id, "owner": false })
        ));
        assert_eq!((code_.as_str(), status), ("LAST_OWNER", 409));
    });
}

#[test]
fn revokes_sessions_with_or_without_the_api_keys() {
    run(|| async {
        let f = fixture().await;
        let service_id = better_iam_server::utils::id();
        insert(
            &f.iam,
            "identities",
            json!({
                "id": service_id,
                "tenantId": f.tenant_id,
                "kind": "service",
                "name": "ci-bot",
                "status": "active",
                "emailVerified": false,
                "owner": false,
                "rootAdmin": false,
                "createdAt": 1,
            }),
        )
        .await;
        let key = call!(
            f,
            credentials.create,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": service_id, "name": "deploy" })
        )
        .unwrap();
        assert!(key["token"].as_str().unwrap().starts_with("biam_key_"));
        let input =
            json!({ "tenantId": f.tenant_id, "identityId": service_id, "keepApiKeys": true });
        let kept = call!(f, identities.revoke_sessions, f.owner, input).unwrap();
        assert_eq!(kept, json!({ "revoked": 0 }));
        let key_id = key["credentialId"].as_str().unwrap().to_owned();
        assert!(get(&f.iam, "sessions", &key_id).await.is_some());
        let (_, _, message) = code(call!(
            f,
            identities.revoke_sessions,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": service_id, "keepApiKeys": "yes" })
        ));
        assert_eq!(message, "keepApiKeys must be a boolean");
        let all = call!(
            f,
            identities.revoke_sessions,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": service_id })
        )
        .unwrap();
        assert_eq!(all, json!({ "revoked": 1 }));
        assert!(get(&f.iam, "sessions", &key_id).await.is_none());
        let audited = audit_events(&f, "identity:revoke-sessions").await;
        let metadata: Vec<&Value> = audited.iter().map(|event| &event["metadata"]).collect();
        assert!(metadata.contains(&&json!({ "revoked": 0, "keptApiKeys": true })));
        assert!(metadata.contains(&&json!({ "revoked": 1, "keptApiKeys": false })));
        // A member's user sessions end while their keys would stay.
        let alice = member(
            &f,
            "Alice",
            "alice@acme.test",
            Some("a strong alice password"),
        )
        .await;
        let login = sign_in(&f, "alice@acme.test", "a strong alice password").await;
        let ended = call!(
            f,
            identities.revoke_sessions,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice, "keepApiKeys": true })
        )
        .unwrap();
        assert_eq!(ended, json!({ "revoked": 1 }));
        let session = post(&f.iam, "auth/getSession", json!({}), Some(&login)).await;
        assert_eq!(session["error"]["code"], json!("UNAUTHENTICATED"));
    });
}

#[test]
fn exports_what_the_tenant_stores_about_a_person() {
    run(|| async {
        let f = fixture().await;
        let alice = member(
            &f,
            "Alice",
            "alice@acme.test",
            Some("a strong alice password"),
        )
        .await;
        sign_in(&f, "alice@acme.test", "a strong alice password").await;
        let group_id = better_iam_server::utils::id();
        insert(
            &f.iam,
            "groups",
            json!({ "id": group_id, "tenantId": f.tenant_id, "name": "Engineering" }),
        )
        .await;
        insert(
            &f.iam,
            "groupMembers",
            json!({ "id": better_iam_server::utils::id(), "tenantId": f.tenant_id, "uniqueKey": format!("{group_id}:{alice}"), "groupId": group_id, "identityId": alice }),
        )
        .await;
        call!(
            f,
            identities.link_provider,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice, "providerId": "okta", "issuer": "https://idp", "subject": "00u1" })
        )
        .unwrap();
        let export = call!(
            f,
            identities.export,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": alice })
        )
        .unwrap();
        assert_eq!(export["tenantId"], json!(f.tenant_id));
        assert_eq!(export["identity"]["id"], json!(alice));
        assert!(export["identity"].get("passwordHash").is_none());
        let sessions = export["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].get("tokenHash").is_none());
        assert_eq!(export["mfa"], json!({ "enabled": false }));
        assert_eq!(export["passkeys"], json!([]));
        assert_eq!(
            export["externalIdentities"],
            json!([{ "providerId": "okta", "issuer": "https://idp", "subject": "00u1" }])
        );
        assert_eq!(export["groups"][0]["name"], json!("Engineering"));
        assert_eq!(export["bindings"], json!([]));
        assert_eq!(export["boundaries"], json!([]));
        assert_eq!(export["links"], json!([]));
        assert_eq!(export["auditIncluded"], json!(true));
        let actions: Vec<&str> = export["audit"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["action"].as_str().unwrap())
            .collect();
        assert!(actions.contains(&"auth:session:create"));
        assert!(!export.to_string().contains("tokenHash"));
        let audited = audit_events(&f, "identity:export").await;
        assert_eq!(
            audited[0]["metadata"],
            json!({ "kind": "user", "auditIncluded": true })
        );
        // Without iam:audit:read the export leaves the audit trail out.
        let reader = member(
            &f,
            "Reader",
            "reader@acme.test",
            Some("a strong reader password"),
        )
        .await;
        grant(&f, &reader, &["iam:identities:read"]).await;
        let token = sign_in(&f, "reader@acme.test", "a strong reader password").await;
        let partial = call!(
            f,
            identities.export,
            bearer(&token),
            json!({ "tenantId": f.tenant_id, "identityId": alice })
        )
        .unwrap();
        assert_eq!(partial["auditIncluded"], json!(false));
        assert!(partial.get("audit").is_none());
    });
}

#[test]
fn lists_reports_groups_bindings_and_unlocks() {
    run(|| async {
        let f = fixture().await;
        let alice = member(&f, "Alice", "alice@acme.test", None).await;
        let zed = member(&f, "Zed", "zed@acme.test", None).await;
        let bea = member(&f, "Bea", "bea@acme.test", None).await;
        for (report, status) in [(&zed, "active"), (&bea, "active"), (&alice, "disabled")] {
            let mut record = get(&f.iam, "identities", report).await.unwrap();
            record.insert("managerId".into(), json!(f.owner_id));
            record.insert("status".into(), json!(status));
            put(&f.iam, "identities", record).await;
        }
        let reports = call!(
            f,
            identities.list_reports,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": f.owner_id })
        )
        .unwrap();
        assert_eq!(names(&reports), ["Bea", "Zed"]);
        let (live, expired) = (
            better_iam_server::utils::id(),
            better_iam_server::utils::id(),
        );
        for (group, expires) in [(&live, json!(9_999_999_999_999u64)), (&expired, json!(1))] {
            insert(
                &f.iam,
                "groups",
                json!({ "id": group, "tenantId": f.tenant_id, "name": format!("Group {group}") }),
            )
            .await;
            insert(
                &f.iam,
                "groupMembers",
                json!({ "id": better_iam_server::utils::id(), "tenantId": f.tenant_id, "uniqueKey": format!("{group}:{zed}"), "groupId": group, "identityId": zed, "expiresAt": expires }),
            )
            .await;
        }
        let groups = call!(
            f,
            identities.list_groups,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": zed })
        )
        .unwrap();
        let groups = groups.as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["id"], json!(live));
        assert_eq!(
            groups[0]["membershipExpiresAt"],
            json!(9_999_999_999_999u64)
        );
        let bindings = call!(
            f,
            identities.list_bindings,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": f.owner_id })
        )
        .unwrap();
        assert_eq!(bindings[0]["role"]["uniqueKey"], json!("system:owner"));
        assert_eq!(bindings[0]["via"], json!("identity"));
        let unlocked = call!(
            f,
            identities.unlock,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": zed })
        )
        .unwrap();
        assert_eq!(unlocked["supported"], json!(true));
        assert!(unlocked["cleared"].is_number());
        let audited = audit_events(&f, "identity:unlock").await;
        assert_eq!(audited[0]["metadata"]["supported"], json!(true));
        let (code_, status, _) = code(call!(
            f,
            identities.get,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": "missing" })
        ));
        assert_eq!((code_.as_str(), status), ("NOT_FOUND", 404));
    });
}

#[test]
fn lists_and_revokes_member_invitations_without_token_material() {
    run(|| async {
        let f = fixture().await;
        let invitation_id = better_iam_server::utils::id();
        insert(
            &f.iam,
            "memberInvitations",
            json!({
                "id": invitation_id,
                "tenantId": f.tenant_id,
                "email": "new@acme.test",
                "tokenHash": "hash",
                "uniqueKey": "hash",
                "roleIds": [],
                "groupIds": [],
                "inviterId": f.owner_id,
                "createdAt": 1,
                "expiresAt": 9_999_999_999_999u64,
                "consumed": false,
            }),
        )
        .await;
        let listed = call!(
            f,
            identities.list_invitations,
            f.owner,
            json!({ "tenantId": f.tenant_id })
        )
        .unwrap();
        assert_eq!(listed[0]["id"], json!(invitation_id));
        assert!(listed[0].get("tokenHash").is_none() && listed[0].get("uniqueKey").is_none());
        let input = json!({ "tenantId": f.tenant_id, "invitationId": invitation_id });
        let revoked = call!(f, identities.revoke_invitation, f.owner, input.clone()).unwrap();
        assert_eq!(revoked["revoked"], json!(true));
        assert!(revoked.get("tokenHash").is_none());
        let (code_, status, message) = code(call!(
            f,
            identities.revoke_invitation,
            f.owner,
            input.clone()
        ));
        assert_eq!(
            (code_.as_str(), status, message.as_str()),
            ("CONFLICT", 409, "Invitation is already consumed or revoked")
        );
        let (code_, _, _) = code(call!(f, identities.resend_invitation, f.owner, input));
        assert_eq!(code_, "CONFLICT");
        // Invitations need an email delivery callback; bulk creation takes 1-100 people.
        let (code_, _, message) = code(call!(
            f,
            identities.create_many,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identities": [] })
        ));
        assert_eq!(
            (code_.as_str(), message.as_str()),
            ("INVALID_INPUT", "Provide 1-100 identities")
        );
        assert!(f.inbox.lock().unwrap().is_empty());
    });
}

#[test]
fn creates_people_with_a_manager_providers_and_verified_addresses() {
    run(|| async {
        let f = fixture().await;
        let (_, _, message) = code(call!(
            f,
            identities.create,
            f.owner,
            json!({ "tenantId": f.tenant_id, "email": "a@acme.test", "name": "A", "emailVerified": "yes" })
        ));
        assert_eq!(message, "emailVerified must be a boolean");
        let (_, _, message) = code(call!(
            f,
            identities.create,
            f.owner,
            json!({
                "tenantId": f.tenant_id, "email": "a@acme.test", "name": "A",
                "providers": [
                    { "providerId": "okta", "issuer": "i", "subject": "1" },
                    { "providerId": "okta", "issuer": "i", "subject": "2" },
                ],
            })
        ));
        assert_eq!(message, "providers must name each provider once");
        let result = call!(
            f,
            identities.create,
            f.owner,
            json!({
                "tenantId": f.tenant_id,
                "email": "Dana@Acme.test",
                "name": "Dana",
                "emailVerified": true,
                "managerId": f.owner_id,
                "providers": [{ "providerId": "okta", "issuer": "https://idp", "subject": "00u9" }],
            })
        );
        let dana = after_change(&f, result, &Filter::new().eq("email", "dana@acme.test")).await;
        assert_eq!(dana["email"], json!("dana@acme.test"));
        assert_eq!(dana["emailVerified"], json!(true));
        assert_eq!(dana["managerId"], json!(f.owner_id));
        assert!(dana.get("passwordHash").is_none());
        let links = find(
            &f.iam,
            "externalIdentities",
            Filter::new().eq("identityId", dana["id"].clone()),
        )
        .await;
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["subject"], json!("00u9"));
        // A reporting line never loops back.
        let dana_id = dana["id"].as_str().unwrap().to_owned();
        let mut owner = get(&f.iam, "identities", &f.owner_id).await.unwrap();
        owner.insert("managerId".into(), json!(dana_id));
        put(&f.iam, "identities", owner).await;
        let erin = member(&f, "Erin", "erin@acme.test", None).await;
        let mut record = get(&f.iam, "identities", &erin).await.unwrap();
        record.insert("managerId".into(), json!(f.owner_id));
        put(&f.iam, "identities", record).await;
        let (_, _, message) = code(call!(
            f,
            identities.update,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": dana_id, "managerId": erin })
        ));
        assert_eq!(message, "That would make the reporting line circular");
        let (_, _, message) = code(call!(
            f,
            identities.update,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": dana_id, "managerId": dana_id })
        ));
        assert_eq!(message, "An identity cannot be its own manager");
        // Guard rails before any change: deleting or offboarding yourself, setting an unknown status.
        let (_, _, message) = code(call!(
            f,
            identities.delete,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": f.owner_id })
        ));
        assert_eq!(message, "An identity cannot delete itself");
        let (_, _, message) = code(call!(
            f,
            identities.offboard,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": f.owner_id, "reason": "leaving" })
        ));
        assert_eq!(message, "You cannot offboard yourself");
        let (_, _, message) = code(call!(
            f,
            identities.set_status,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": erin, "status": "gone" })
        ));
        assert_eq!(message, "Invalid identity status");
        let (code_, status, message) = code(call!(
            f,
            identities.set_boundary,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": erin, "document": { "version": 1, "statements": [] } })
        ));
        assert_eq!(
            (code_.as_str(), status, message.as_str()),
            (
                "ACCESS_DENIED",
                403,
                "Principal ceilings are platform controlled"
            )
        );
    });
}

#[test]
fn service_accounts_are_created_listed_and_updated() {
    run(|| async {
        let f = fixture().await;
        let result = call!(
            f,
            service_accounts.create,
            f.owner,
            json!({ "tenantId": f.tenant_id, "name": "ci-bot", "description": "Deploys" })
        );
        let account = after_change(&f, result, &Filter::new().eq("name", "ci-bot")).await;
        assert_eq!(account["kind"], json!("service"));
        assert_eq!(account["description"], json!("Deploys"));
        assert_eq!(account["status"], json!("active"));
        assert_eq!(account["owner"], json!(false));
        let account_id = account["id"].as_str().unwrap().to_owned();
        let listed = call!(
            f,
            service_accounts.list,
            f.owner,
            json!({ "tenantId": f.tenant_id })
        )
        .unwrap();
        assert_eq!(names(&listed), ["ci-bot"]);
        let got = call!(
            f,
            service_accounts.get,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": account_id })
        )
        .unwrap();
        assert_eq!(got["id"], json!(account_id));
        let (code_, status, message) = code(call!(
            f,
            service_accounts.get,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": f.owner_id })
        ));
        assert_eq!(
            (code_.as_str(), status, message.as_str()),
            ("NOT_FOUND", 404, "Service account not found")
        );
        let (_, _, message) = code(call!(
            f,
            service_accounts.update,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": account_id })
        ));
        assert_eq!(message, "Nothing to update");
        let (_, _, message) = code(call!(
            f,
            service_accounts.set_status,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": account_id, "status": "paused" })
        ));
        assert_eq!(message, "Invalid status");
        let expires = better_iam_server::utils::date_now() as u64 + 86_400_000;
        let result = call!(
            f,
            service_accounts.update,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": account_id, "name": "deployer", "expiresAt": expires })
        );
        let updated = after_change(&f, result, &Filter::new().eq("id", account_id.clone())).await;
        assert_eq!(updated["name"], json!("deployer"));
        assert_eq!(updated["expiresAt"], json!(expires));
        let result = call!(
            f,
            service_accounts.update,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": account_id, "expiresAt": null })
        );
        let cleared = after_change(&f, result, &Filter::new().eq("id", account_id.clone())).await;
        assert!(cleared.get("expiresAt").is_none());
        // Deleted accounts are listed only on request.
        let mut record = get(&f.iam, "identities", &account_id).await.unwrap();
        record.insert("status".into(), json!("deleted"));
        put(&f.iam, "identities", record).await;
        let listed = call!(
            f,
            service_accounts.list,
            f.owner,
            json!({ "tenantId": f.tenant_id })
        )
        .unwrap();
        assert_eq!(listed, json!([]));
        let all = call!(
            f,
            service_accounts.list,
            f.owner,
            json!({ "tenantId": f.tenant_id, "includeDeleted": true })
        )
        .unwrap();
        assert_eq!(all.as_array().unwrap().len(), 1);
        let (_, status, message) = code(call!(
            f,
            service_accounts.update,
            f.owner,
            json!({ "tenantId": f.tenant_id, "identityId": account_id, "name": "again" })
        ));
        assert_eq!(
            (status, message.as_str()),
            (404, "Service account has been deleted")
        );
    });
}
