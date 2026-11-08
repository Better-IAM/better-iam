//! The `bindings` API group: eligible (just-in-time) bindings, activations, approval-gated activation, and the binding
//! life cycle. Ported from tests/eligible-bindings.test.ts and tests/activation-approvals.test.ts, plus the binding
//! rules of tests/access.test.ts and tests/access-windows.test.ts. The TypeScript tests set up an organization through
//! `tenants.create`, `identities.create`, `roles.create` and `groups.*`; here the people, roles, groups and grant
//! authorities are written to the store directly (in the root tenant), and every bindings call goes through the API.

use std::future::Future;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamStore, IamStoreExt, PermissionsConfig,
};
use better_iam_server::api::Body;
use better_iam_server::options::{BetterIamOptions, ResolvedResource, ServerAuthOptions};
use better_iam_server::{BetterIam, better_iam};
use bytes::Bytes;
use http::Method;
use serde_json::{Value, json};

const ORIGIN: &str = "http://localhost:3000";
const SECRET: &str = "organization-fixture-secret-with-32-characters";
const START: i64 = 1_800_000_000_000;

/// Runs a test body on a runtime with large worker stacks (debug-build futures are big).
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
    owner: CredentialInput,
    owner_authority: String,
    clock: Arc<AtomicI64>,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
}

impl Fixture {
    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn advance(&self, ms: i64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    async fn insert(&self, collection: &str, record: Value) {
        let collection = collection.to_owned();
        let record = record.as_object().unwrap().clone();
        self.iam
            .store
            .transaction(|tx| async move { tx.insert(&collection, &record).await })
            .await
            .unwrap();
    }

    async fn update(&self, collection: &str, id: &str, members: Value) {
        let mut record = self.iam.store.get(collection, id).await.unwrap().unwrap();
        for (key, value) in members.as_object().unwrap() {
            record.insert(key.clone(), value.clone());
        }
        let collection = collection.to_owned();
        self.iam
            .store
            .transaction(|tx| async move { tx.put(&collection, &record).await })
            .await
            .unwrap();
    }

    async fn find(&self, collection: &str, filter: Filter) -> Vec<Value> {
        self.iam
            .store
            .find(collection, &filter, &FindOptions::default())
            .await
            .unwrap()
            .into_iter()
            .map(Value::Object)
            .collect()
    }

    /// A person `{name}@acme.test` with the password `a strong {name} password`.
    async fn member(&self, name: &str) -> String {
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
            .expect("identity")
            .id
    }

    /// `roles.create({ permissions })`: an inline allow statement over every resource, under the owner's authority.
    async fn role(&self, name: &str, permissions: &[&str]) -> String {
        let id = better_iam_server::utils::id();
        self.insert(
            "roles",
            json!({
                "id": id,
                "tenantId": self.tenant_id,
                "name": name,
                "policyIds": [],
                "document": { "version": 1, "statements": [{ "effect": "allow", "actions": permissions, "resources": ["*"] }] },
                "protected": false,
                "authorityId": self.owner_authority,
            }),
        )
        .await;
        id
    }

    async fn group(&self, name: &str) -> String {
        let id = better_iam_server::utils::id();
        self.insert(
            "groups",
            json!({ "id": id, "tenantId": self.tenant_id, "name": name }),
        )
        .await;
        id
    }

    async fn add_member(&self, group_id: &str, identity_id: &str) -> String {
        let id = better_iam_server::utils::id();
        self.insert(
            "groupMembers",
            json!({
                "id": id,
                "tenantId": self.tenant_id,
                "uniqueKey": format!("{group_id}:{identity_id}"),
                "groupId": group_id,
                "identityId": identity_id,
            }),
        )
        .await;
        id
    }

    async fn sign_in(&self, name: &str) -> CredentialInput {
        let response = self
            .post(
                "auth/signIn",
                json!({
                    "tenantId": self.tenant_id,
                    "email": format!("{name}@acme.test"),
                    "password": format!("a strong {name} password"),
                }),
            )
            .await;
        let token = response["data"]["token"]
            .as_str()
            .unwrap_or_else(|| panic!("sign-in of {name}: {response}"));
        bearer(token)
    }

    async fn post(&self, path: &str, body: Value) -> Value {
        let request = http::Request::builder()
            .method(Method::POST)
            .uri(format!("{ORIGIN}/api/iam/{path}"))
            .header("content-type", "application/json")
            .header("x-better-iam", "1")
            .body(Bytes::from(body.to_string()))
            .unwrap();
        let response = self.iam.handler(request).await;
        serde_json::from_slice(response.body()).unwrap_or(Value::Null)
    }

    async fn dispatch(&self) {
        self.iam.auth.dispatch_outbox(None).await.unwrap();
    }

    fn sent(&self, template: &str) -> Vec<DeliveryMessage> {
        self.inbox
            .lock()
            .unwrap()
            .iter()
            .filter(|message| message.template == template)
            .cloned()
            .collect()
    }

    async fn audit(&self, credential: &CredentialInput, action: &str) -> Vec<Value> {
        self.iam
            .api
            .audit
            .list(
                credential,
                Body::from_value(json!({ "tenantId": self.tenant_id, "action": action })),
            )
            .await
            .unwrap()
            .into_value()
            .unwrap()
            .as_array()
            .unwrap()
            .clone()
    }

    /// `audit.list({ limit: 1 })`: succeeds only while the caller holds iam:audit:read.
    async fn read_audit(&self, credential: &CredentialInput) -> Result<Value, IamError> {
        self.iam
            .api
            .audit
            .list(
                credential,
                Body::from_value(json!({ "tenantId": self.tenant_id, "limit": 1 })),
            )
            .await?
            .into_value()
    }
}

fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

/// One `bindings` call with a JSON input, answered as JSON.
macro_rules! call {
    ($f:expr, $method:ident, $credential:expr, $input:expr) => {
        $f.iam
            .api
            .bindings
            .$method($credential, Body::from_value($input))
            .await
            .and_then(|reply| reply.into_value())
    };
}

fn code(result: Result<Value, IamError>) -> String {
    match result {
        Ok(value) => panic!("expected an error, got {value}"),
        Err(error) => error.code,
    }
}

fn error(result: Result<Value, IamError>) -> (String, u16, String) {
    match result {
        Ok(value) => panic!("expected an error, got {value}"),
        Err(error) => (error.code, error.status, error.message),
    }
}

fn ids(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .collect()
}

/// A bootstrapped deployment whose root tenant has an owner holding every permission and a delegated grant
/// authority, with a controllable clock and a captured email outbox.
async fn fixture() -> Fixture {
    let store: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let clock = Arc::new(AtomicI64::new(START));
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let mut options = BetterIamOptions::new(store, SECRET, ORIGIN);
    options.permissions = Some(PermissionsConfig {
        actions: Some(vec!["documents:read".into(), "documents:write".into()]),
        ..PermissionsConfig::default()
    });
    options.resolve_resource = Some(Arc::new(|reference| {
        Box::pin(async move { Ok(ResolvedResource::of(&reference)) })
    }));
    let sink = inbox.clone();
    let now = clock.clone();
    options.authentication = Some(ServerAuthOptions {
        send_email: Some(delivery_fn(move |message| {
            sink.lock().unwrap().push(message);
            async { Ok(()) }
        })),
        session_lifetime_ms: Some(7.0 * 86_400_000.0),
        session_idle_timeout_ms: Some(7.0 * 86_400_000.0),
        now: Some(Arc::new(move || now.load(Ordering::SeqCst) as f64)),
        ..ServerAuthOptions::default()
    });
    let iam = better_iam(options).expect("valid options");
    iam.initialize().await.expect("initialize");
    let root = iam
        .bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
        .await
        .expect("bootstrap");
    let tenant_id = root["tenant"]["id"].as_str().unwrap().to_owned();
    let root_id = root["identity"]["id"].as_str().unwrap().to_owned();
    let root_authority = iam
        .store
        .find(
            "grantAuthorities",
            &Filter::new().eq("identityId", root_id),
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
    let mut f = Fixture {
        iam,
        tenant_id,
        owner_id: String::new(),
        owner: CredentialInput::default(),
        owner_authority: String::new(),
        clock,
        inbox,
    };
    f.owner_id = f.member("owner").await;
    // The owner's grant authority, delegated by root, and the Owner role bound under root's authority.
    f.owner_authority = better_iam_server::utils::id();
    f.insert(
        "grantAuthorities",
        json!({
            "id": f.owner_authority,
            "tenantId": f.tenant_id,
            "identityId": f.owner_id,
            "ceiling": better_iam_server::utils::all_value(),
            "parentAuthorityId": root_authority,
            "revoked": false,
        }),
    )
    .await;
    let owner_role = better_iam_server::utils::id();
    f.insert(
        "roles",
        json!({
            "id": owner_role,
            "tenantId": f.tenant_id,
            "name": "Owner",
            "policyIds": [],
            "document": better_iam_server::utils::all_value(),
            "protected": false,
            "authorityId": root_authority,
        }),
    )
    .await;
    f.insert(
        "bindings",
        json!({
            "id": better_iam_server::utils::id(),
            "tenantId": f.tenant_id,
            "subjectType": "identity",
            "subjectId": f.owner_id,
            "roleId": owner_role,
            "authorityId": root_authority,
        }),
    )
    .await;
    f.owner = f.sign_in("owner").await;
    f
}

#[test]
fn eligible_bindings_grant_nothing_until_activated_enforce_rules_and_expire() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner.clone();
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let auditor = f.role("Auditor", &["iam:audit:read"]).await;
        let member = f.role("Member", &["iam:bindings:activate"]).await;
        for identity in [&alice, &bob] {
            call!(f, create, &owner, json!({ "tenantId": tenant_id, "roleId": member, "subjectType": "identity", "subjectId": identity }))
                .unwrap();
        }
        // Activation settings belong to eligible bindings only.
        assert_eq!(
            error(call!(
                f,
                create,
                &owner,
                json!({ "tenantId": tenant_id, "roleId": auditor, "subjectType": "identity", "subjectId": alice, "maxActivationMs": 60_000 })
            )),
            (
                "INVALID_INPUT".into(),
                400,
                "Activation settings apply to eligible bindings only".into()
            )
        );
        assert_eq!(
            error(call!(
                f,
                create,
                &owner,
                json!({ "tenantId": tenant_id, "roleId": auditor, "subjectType": "identity", "subjectId": alice, "eligible": "yes" })
            )),
            (
                "INVALID_INPUT".into(),
                400,
                "eligible must be boolean".into()
            )
        );
        assert_eq!(
            error(call!(
                f,
                create,
                &owner,
                json!({ "tenantId": tenant_id, "roleId": auditor, "subjectType": "identity", "subjectId": alice, "eligible": true, "maxActivationMs": 8 * 86_400_000_i64 })
            )),
            (
                "INVALID_INPUT".into(),
                400,
                "Invalid maxActivationMs".into()
            )
        );
        let eligible = call!(f, create, &owner, json!({
            "tenantId": tenant_id, "roleId": auditor, "subjectType": "identity", "subjectId": alice,
            "eligible": true, "maxActivationMs": 600_000, "requireJustification": true,
        }))
        .unwrap();
        assert_eq!(eligible["eligible"], json!(true));
        assert_eq!(eligible["maxActivationMs"], json!(600_000));
        assert_eq!(eligible["requireJustification"], json!(true));
        assert_eq!(
            eligible["uniqueKey"],
            json!(format!("identity:{alice}:{auditor}:{}", f.owner_authority))
        );
        let eligible_id = eligible["id"].as_str().unwrap().to_owned();
        assert_eq!(
            ids(&call!(
                f,
                list,
                &owner,
                json!({ "tenantId": tenant_id, "eligible": true })
            )
            .unwrap()),
            vec![eligible_id.clone()]
        );
        let standing = call!(
            f,
            list,
            &owner,
            json!({ "tenantId": tenant_id, "roleId": member, "eligible": false })
        )
        .unwrap();
        assert_eq!(
            standing
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b["roleId"].clone())
                .collect::<Vec<_>>(),
            vec![json!(member), json!(member)]
        );
        assert_eq!(
            call!(
                f,
                list,
                &owner,
                json!({ "tenantId": tenant_id, "roleId": auditor, "eligible": false })
            )
            .unwrap(),
            json!([])
        );
        let as_alice = f.sign_in("alice").await;
        let as_bob = f.sign_in("bob").await;
        assert_eq!(code(f.read_audit(&as_alice).await), "ACCESS_DENIED");
        // She can see what she may elevate to without holding iam:bindings:read.
        let mine = call!(f, list_mine, &as_alice, json!({ "tenantId": tenant_id })).unwrap();
        let mine = mine.as_array().unwrap();
        let pairs: Vec<(Value, bool)> = mine
            .iter()
            .map(|b| (b["roleId"].clone(), b["eligible"] == json!(true)))
            .collect();
        assert!(pairs.contains(&(json!(member), false)), "{pairs:?}");
        assert!(pairs.contains(&(json!(auditor), true)), "{pairs:?}");
        let own = mine.iter().find(|b| b["id"] == json!(eligible_id)).unwrap();
        assert!(own.get("activation").is_none());
        let activate = |credential: CredentialInput, extra: Value| {
            let mut input = json!({ "tenantId": tenant_id, "bindingId": eligible_id });
            for (key, value) in extra.as_object().unwrap() {
                input[key] = value.clone();
            }
            let f = &f;
            async move { call!(f, activate, &credential, input) }
        };
        assert_eq!(
            error(activate(as_alice.clone(), json!({})).await),
            (
                "INVALID_INPUT".into(),
                400,
                "This activation requires a justification".into()
            )
        );
        assert_eq!(
            error(
                activate(
                    as_alice.clone(),
                    json!({ "justification": "quarterly review", "durationMs": 600_001 })
                )
                .await
            ),
            ("INVALID_INPUT".into(), 400, "Invalid durationMs".into())
        );
        assert_eq!(
            error(activate(as_bob.clone(), json!({ "justification": "not mine" })).await),
            (
                "ACCESS_DENIED".into(),
                403,
                "This binding does not apply to you".into()
            )
        );
        let alice_standing = call!(
            f,
            list,
            &owner,
            json!({ "tenantId": tenant_id, "subjectId": alice, "eligible": false })
        )
        .unwrap();
        assert_eq!(
            error(call!(
                f,
                activate,
                &as_alice,
                json!({ "tenantId": tenant_id, "bindingId": alice_standing[0]["id"], "justification": "standing role" })
            )),
            (
                "INVALID_TRANSITION".into(),
                400,
                "This binding is not eligible for activation".into()
            )
        );
        let activation = activate(
            as_alice.clone(),
            json!({ "justification": "quarterly review" }),
        )
        .await
        .unwrap();
        assert_eq!(activation["bindingId"], json!(eligible_id));
        assert_eq!(activation["identityId"], json!(alice));
        assert_eq!(activation["roleId"], json!(auditor));
        assert_eq!(activation["active"], json!(true));
        assert_eq!(activation["status"], json!("active"));
        assert_eq!(activation["justification"], json!("quarterly review"));
        assert_eq!(activation["expiresAt"], json!(f.now() + 600_000));
        assert!(activation.get("uniqueKey").is_none());
        assert!(f.read_audit(&as_alice).await.is_ok());
        assert_eq!(
            error(activate(as_alice.clone(), json!({ "justification": "again" })).await),
            (
                "CONFLICT".into(),
                409,
                "This role is already active for you".into()
            )
        );
        // Her effective bindings show the activation.
        let mine = call!(f, list_mine, &as_alice, json!({ "tenantId": tenant_id })).unwrap();
        let own = mine
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["id"] == json!(eligible_id))
            .unwrap()
            .clone();
        assert_eq!(own["activation"]["id"], activation["id"]);
        assert_eq!(own["activation"]["expiresAt"], activation["expiresAt"]);
        let started = f.audit(&owner, "binding:activate").await;
        assert_eq!(started[0]["actorId"], json!(alice));
        assert_eq!(started[0]["resourceId"], json!(eligible_id));
        assert_eq!(started[0]["metadata"]["activationId"], activation["id"]);
        assert_eq!(started[0]["metadata"]["roleId"], json!(auditor));
        assert_eq!(
            started[0]["metadata"]["justification"],
            json!("quarterly review")
        );
        assert_eq!(
            call!(
                f,
                list_activations,
                &owner,
                json!({ "tenantId": tenant_id, "roleId": auditor })
            )
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
            1
        );
        f.advance(600_001);
        assert_eq!(code(f.read_audit(&as_alice).await), "ACCESS_DENIED");
        assert_eq!(
            call!(
                f,
                list_activations,
                &owner,
                json!({ "tenantId": tenant_id })
            )
            .unwrap(),
            json!([])
        );
        let ended = call!(
            f,
            list_activations,
            &owner,
            json!({ "tenantId": tenant_id, "includeExpired": true })
        )
        .unwrap();
        assert_eq!(
            ended
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a["active"].clone())
                .collect::<Vec<_>>(),
            vec![json!(false)]
        );
        // Re-activation replaces the ended record; the holder may end it early, nobody else.
        let second = activate(
            as_alice.clone(),
            json!({ "justification": "follow-up", "durationMs": 60_000 }),
        )
        .await
        .unwrap();
        assert_eq!(second["expiresAt"], json!(f.now() + 60_000));
        assert_eq!(
            f.find(
                "bindingActivations",
                Filter::new().eq("tenantId", tenant_id.clone())
            )
            .await
            .len(),
            1
        );
        assert_eq!(
            error(call!(
                f,
                deactivate,
                &as_bob,
                json!({ "tenantId": tenant_id, "activationId": second["id"] })
            )),
            (
                "ACCESS_DENIED".into(),
                403,
                "Only the holder can end this activation".into()
            )
        );
        assert_eq!(
            call!(
                f,
                deactivate,
                &as_alice,
                json!({ "tenantId": tenant_id, "activationId": second["id"] })
            )
            .unwrap(),
            json!({ "deactivated": true })
        );
        assert_eq!(code(f.read_audit(&as_alice).await), "ACCESS_DENIED");
        // Requiring MFA refuses password-only sessions.
        let updated = call!(
            f,
            update,
            &owner,
            json!({ "tenantId": tenant_id, "bindingId": eligible_id, "requireMfa": true })
        )
        .unwrap();
        assert_eq!(updated["requireMfa"], json!(true));
        assert_eq!(
            error(activate(as_alice.clone(), json!({ "justification": "mfa" })).await),
            (
                "MFA_REQUIRED".into(),
                403,
                "Activation requires an MFA-verified session".into()
            )
        );
        let relaxed = call!(f, update, &owner, json!({ "tenantId": tenant_id, "bindingId": eligible_id, "requireMfa": false, "requireJustification": false })).unwrap();
        assert!(relaxed.get("requireMfa").is_none());
        assert!(relaxed.get("requireJustification").is_none());
        let third = activate(as_alice.clone(), json!({})).await.unwrap();
        assert!(third.get("justification").is_none());
        // Administrators can end someone's activation, and turning eligibility off ends them all.
        assert_eq!(
            call!(
                f,
                revoke_activation,
                &owner,
                json!({ "tenantId": tenant_id, "activationId": third["id"] })
            )
            .unwrap(),
            json!({ "deactivated": true })
        );
        let revoked = f.audit(&owner, "binding:deactivate").await;
        assert_eq!(revoked[0]["actorId"], json!(f.owner_id));
        assert_eq!(revoked[0]["metadata"]["identityId"], json!(alice));
        assert_eq!(revoked[0]["metadata"]["revoked"], json!(true));
        activate(as_alice.clone(), json!({})).await.unwrap();
        let standing = call!(
            f,
            update,
            &owner,
            json!({ "tenantId": tenant_id, "bindingId": eligible_id, "eligible": false })
        )
        .unwrap();
        assert!(standing.get("eligible").is_none());
        assert!(standing.get("maxActivationMs").is_none());
        assert_eq!(
            call!(
                f,
                list_activations,
                &owner,
                json!({ "tenantId": tenant_id })
            )
            .unwrap(),
            json!([])
        );
        // Now a standing binding: the role applies without activation.
        assert!(f.read_audit(&as_alice).await.is_ok());
        assert_eq!(
            code(activate(as_alice.clone(), json!({})).await),
            "INVALID_TRANSITION"
        );
        // Turning eligibility back on brings the role back under activation.
        call!(
            f,
            update,
            &owner,
            json!({ "tenantId": tenant_id, "bindingId": eligible_id, "eligible": true })
        )
        .unwrap();
        assert_eq!(code(f.read_audit(&as_alice).await), "ACCESS_DENIED");
        activate(as_alice.clone(), json!({ "durationMs": 60_000 }))
            .await
            .unwrap();
        f.advance(60_001);
        assert_eq!(code(f.read_audit(&as_alice).await), "ACCESS_DENIED");
        // The ended activation stays until it is replaced or swept; deleting the binding removes it.
        assert_eq!(
            f.find(
                "bindingActivations",
                Filter::new().eq("tenantId", tenant_id.clone())
            )
            .await
            .len(),
            1
        );
        assert_eq!(
            call!(
                f,
                delete,
                &owner,
                json!({ "tenantId": tenant_id, "bindingId": eligible_id })
            )
            .unwrap(),
            json!({ "deleted": true })
        );
        assert!(
            f.find(
                "bindingActivations",
                Filter::new().eq("tenantId", tenant_id.clone())
            )
            .await
            .is_empty()
        );
        assert!(
            f.iam
                .store
                .get("bindings", &eligible_id)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn eligible_bindings_apply_to_group_members() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner.clone();
        let bob = f.member("bob").await;
        let responders = f.group("Responders").await;
        let membership = f.add_member(&responders, &bob).await;
        let member = f.role("Member", &["iam:bindings:activate"]).await;
        let responder = f.role("Incident responder", &["iam:audit:read"]).await;
        call!(f, create, &owner, json!({ "tenantId": tenant_id, "roleId": member, "subjectType": "group", "subjectId": responders }))
            .unwrap();
        let eligible = call!(f, create, &owner, json!({ "tenantId": tenant_id, "roleId": responder, "subjectType": "group", "subjectId": responders, "eligible": true }))
            .unwrap();
        let as_bob = f.sign_in("bob").await;
        assert_eq!(code(f.read_audit(&as_bob).await), "ACCESS_DENIED");
        let mine = call!(f, list_mine, &as_bob, json!({ "tenantId": tenant_id })).unwrap();
        let own = mine
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["id"] == eligible["id"])
            .unwrap()
            .clone();
        assert_eq!(own["via"], json!({ "groupId": responders }));
        assert_eq!(own["eligible"], json!(true));
        let activation = call!(
            f,
            activate,
            &as_bob,
            json!({ "tenantId": tenant_id, "bindingId": eligible["id"] })
        )
        .unwrap();
        // The default activation is one hour.
        assert_eq!(activation["expiresAt"], json!(f.now() + 3_600_000));
        assert!(f.read_audit(&as_bob).await.is_ok());
        // Leaving the group ends what the group's binding granted.
        f.iam
            .store
            .transaction(|tx| {
                let membership = membership.clone();
                async move { tx.delete("groupMembers", &membership).await }
            })
            .await
            .unwrap();
        assert_eq!(code(f.read_audit(&as_bob).await), "ACCESS_DENIED");
        // Someone outside the group cannot activate the group's binding.
        call!(f, create, &owner, json!({ "tenantId": tenant_id, "roleId": member, "subjectType": "identity", "subjectId": bob }))
            .unwrap();
        call!(
            f,
            revoke_activation,
            &owner,
            json!({ "tenantId": tenant_id, "activationId": activation["id"] })
        )
        .unwrap();
        assert_eq!(
            error(call!(
                f,
                activate,
                &as_bob,
                json!({ "tenantId": tenant_id, "bindingId": eligible["id"] })
            )),
            (
                "ACCESS_DENIED".into(),
                403,
                "This binding does not apply to you".into()
            )
        );
        // A membership that has expired does not count either.
        let lapsed = f.add_member(&responders, &bob).await;
        f.update("groupMembers", &lapsed, json!({ "expiresAt": f.now() - 1 }))
            .await;
        assert_eq!(
            code(call!(
                f,
                activate,
                &as_bob,
                json!({ "tenantId": tenant_id, "bindingId": eligible["id"] })
            )),
            "ACCESS_DENIED"
        );
        f.update(
            "groupMembers",
            &lapsed,
            json!({ "expiresAt": f.now() + 86_400_000 }),
        )
        .await;
        let again = call!(
            f,
            activate,
            &as_bob,
            json!({ "tenantId": tenant_id, "bindingId": eligible["id"] })
        )
        .unwrap();
        assert_eq!(again["active"], json!(true));
        assert_eq!(
            call!(
                f,
                list_activations,
                &owner,
                json!({ "tenantId": tenant_id, "identityId": bob })
            )
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
            1
        );
    });
}

#[test]
fn approval_gated_activation_with_emails_and_audit() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner.clone();
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let carol = f.member("carol").await;
        let auditor = f.role("Auditor", &["iam:audit:read"]).await;
        let member = f.role("Member", &["iam:bindings:activate"]).await;
        let approver = f.role("Approver", &["iam:bindings:approve"]).await;
        let approvers = f.group("Approvers").await;
        for identity in [&alice, &bob, &carol] {
            call!(f, create, &owner, json!({ "tenantId": tenant_id, "roleId": member, "subjectType": "identity", "subjectId": identity }))
                .unwrap();
        }
        call!(f, create, &owner, json!({ "tenantId": tenant_id, "roleId": approver, "subjectType": "group", "subjectId": approvers }))
            .unwrap();
        f.add_member(&approvers, &bob).await;
        // The approver group must exist and only applies to eligible bindings.
        assert_eq!(
            code(call!(
                f,
                create,
                &owner,
                json!({ "tenantId": tenant_id, "roleId": auditor, "subjectType": "identity", "subjectId": alice, "eligible": true, "approverGroupId": "missing" })
            )),
            "NOT_FOUND"
        );
        assert_eq!(
            code(call!(
                f,
                create,
                &owner,
                json!({ "tenantId": tenant_id, "roleId": auditor, "subjectType": "identity", "subjectId": alice, "requireApproval": true })
            )),
            "INVALID_INPUT"
        );
        let eligible = call!(f, create, &owner, json!({
            "tenantId": tenant_id, "roleId": auditor, "subjectType": "identity", "subjectId": alice,
            "eligible": true, "requireApproval": true, "approverGroupId": approvers, "maxActivationMs": 2 * 3_600_000,
        }))
        .unwrap();
        assert_eq!(eligible["requireApproval"], json!(true));
        assert_eq!(eligible["approverGroupId"], json!(approvers));
        let binding_id = eligible["id"].clone();
        let as_alice = f.sign_in("alice").await;
        let as_bob = f.sign_in("bob").await;
        let as_carol = f.sign_in("carol").await;
        // The request grants nothing yet, shows as pending, and emails the approver group.
        let request = call!(f, activate, &as_alice, json!({ "tenantId": tenant_id, "bindingId": binding_id, "justification": "INC-7", "durationMs": 30 * 60_000 })).unwrap();
        assert_eq!(request["status"], json!("pending"));
        assert_eq!(request["active"], json!(false));
        assert_eq!(request["requestedDurationMs"], json!(30 * 60_000));
        assert_eq!(request["expiresAt"], json!(f.now() + 24 * 3_600_000));
        assert_eq!(code(f.read_audit(&as_alice).await), "ACCESS_DENIED");
        assert_eq!(
            error(call!(
                f,
                activate,
                &as_alice,
                json!({ "tenantId": tenant_id, "bindingId": binding_id })
            )),
            (
                "CONFLICT".into(),
                409,
                "Your request is still awaiting a decision".into()
            )
        );
        let mine = call!(f, list_mine, &as_alice, json!({ "tenantId": tenant_id })).unwrap();
        let own = mine
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["id"] == binding_id)
            .unwrap()
            .clone();
        assert_eq!(own["pendingActivation"]["id"], request["id"]);
        assert_eq!(own["pendingActivation"]["expiresAt"], request["expiresAt"]);
        f.dispatch().await;
        let notices = f.sent("activation-request");
        assert_eq!(
            notices.iter().map(|m| m.to.as_str()).collect::<Vec<_>>(),
            vec!["bob@acme.test"]
        );
        assert_eq!(notices[0].payload["activationId"], request["id"]);
        assert_eq!(notices[0].payload["roleName"], json!("Auditor"));
        assert_eq!(notices[0].payload["requesterName"], json!("alice"));
        assert_eq!(
            notices[0].payload["requesterEmail"],
            json!("alice@acme.test")
        );
        assert_eq!(notices[0].payload["requestedDurationMs"], json!("1800000"));
        assert_eq!(notices[0].payload["justification"], json!("INC-7"));
        let requested = f.audit(&owner, "binding:activation-requested").await;
        assert_eq!(requested[0]["actorId"], json!(alice));
        assert_eq!(requested[0]["metadata"]["activationId"], request["id"]);
        assert_eq!(
            requested[0]["metadata"]["requestedDurationMs"],
            json!(30 * 60_000)
        );
        // Who may decide: not the requester, not a holder outside the approver group, not without the permission.
        assert_eq!(
            code(call!(
                f,
                approve_activation,
                &as_alice,
                json!({ "tenantId": tenant_id, "activationId": request["id"] })
            )),
            "ACCESS_DENIED"
        );
        assert_eq!(
            code(call!(
                f,
                approve_activation,
                &as_carol,
                json!({ "tenantId": tenant_id, "activationId": request["id"] })
            )),
            "ACCESS_DENIED"
        );
        f.add_member(&approvers, &alice).await;
        assert_eq!(
            error(call!(
                f,
                approve_activation,
                &as_alice,
                json!({ "tenantId": tenant_id, "activationId": request["id"] })
            )),
            (
                "INVALID_INPUT".into(),
                400,
                "You cannot decide on your own request".into()
            )
        );
        assert_eq!(
            call!(
                f,
                list_approvals,
                &as_alice,
                json!({ "tenantId": tenant_id })
            )
            .unwrap(),
            json!([])
        );
        let inbox = call!(f, list_approvals, &as_bob, json!({ "tenantId": tenant_id })).unwrap();
        assert_eq!(inbox.as_array().unwrap().len(), 1);
        assert_eq!(inbox[0]["id"], request["id"]);
        assert_eq!(inbox[0]["status"], json!("pending"));
        assert_eq!(
            inbox[0]["role"],
            json!({ "id": auditor, "name": "Auditor" })
        );
        assert_eq!(
            inbox[0]["requester"],
            json!({ "id": alice, "name": "alice", "email": "alice@acme.test" })
        );
        assert_eq!(
            call!(
                f,
                list_activations,
                &owner,
                json!({ "tenantId": tenant_id, "status": "pending" })
            )
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            call!(
                f,
                list_activations,
                &owner,
                json!({ "tenantId": tenant_id })
            )
            .unwrap(),
            json!([])
        );
        assert_eq!(
            error(call!(
                f,
                list_activations,
                &owner,
                json!({ "tenantId": tenant_id, "status": "expired" })
            )),
            (
                "INVALID_INPUT".into(),
                400,
                "status must be pending, active, or denied".into()
            )
        );
        // Approval with a shorter duration makes the role live from now.
        let approved = call!(f, approve_activation, &as_bob, json!({ "tenantId": tenant_id, "activationId": request["id"], "durationMs": 10 * 60_000, "note": "ok for the incident" })).unwrap();
        assert_eq!(approved["status"], json!("active"));
        assert_eq!(approved["active"], json!(true));
        assert_eq!(approved["decidedBy"], json!(bob));
        assert_eq!(approved["note"], json!("ok for the incident"));
        assert_eq!(approved["expiresAt"], json!(f.now() + 10 * 60_000));
        assert!(f.read_audit(&as_alice).await.is_ok());
        f.dispatch().await;
        let decided = f.sent("activation-decided");
        assert_eq!(decided.len(), 1);
        assert_eq!(decided[0].to, "alice@acme.test");
        assert_eq!(decided[0].payload["decision"], json!("approved"));
        assert_eq!(decided[0].payload["deciderName"], json!("bob"));
        assert_eq!(decided[0].payload["note"], json!("ok for the incident"));
        assert_eq!(
            decided[0].payload["expiresAt"],
            json!(format!("{}", (f.now() + 10 * 60_000)))
        );
        assert_eq!(
            call!(f, list_approvals, &as_bob, json!({ "tenantId": tenant_id })).unwrap(),
            json!([])
        );
        assert_eq!(
            error(call!(
                f,
                approve_activation,
                &as_bob,
                json!({ "tenantId": tenant_id, "activationId": request["id"] })
            )),
            (
                "INVALID_TRANSITION".into(),
                409,
                "This request is not awaiting a decision".into()
            )
        );
        f.advance(10 * 60_000 + 1);
        assert_eq!(code(f.read_audit(&as_alice).await), "ACCESS_DENIED");
        // Denial keeps a record until the worker sweeps it; cancelling one's own request is allowed.
        let second = call!(
            f,
            activate,
            &as_alice,
            json!({ "tenantId": tenant_id, "bindingId": binding_id })
        )
        .unwrap();
        let denied = call!(f, deny_activation, &as_bob, json!({ "tenantId": tenant_id, "activationId": second["id"], "note": "not now", "durationMs": 1 })).unwrap();
        assert_eq!(denied["status"], json!("denied"));
        assert_eq!(denied["active"], json!(false));
        assert_eq!(denied["note"], json!("not now"));
        assert_eq!(denied["expiresAt"], json!(f.now()));
        assert_eq!(
            ids(&call!(
                f,
                list_activations,
                &owner,
                json!({ "tenantId": tenant_id, "status": "denied" })
            )
            .unwrap()),
            vec![second["id"].as_str().unwrap().to_owned()]
        );
        let refusal = f.audit(&owner, "binding:activation-denied").await;
        assert_eq!(refusal[0]["actorId"], json!(bob));
        assert_eq!(refusal[0]["metadata"]["note"], json!("not now"));
        assert_eq!(refusal[0]["metadata"]["identityId"], json!(alice));
        assert!(refusal[0]["metadata"].get("expiresAt").is_none());
        let third = call!(
            f,
            activate,
            &as_alice,
            json!({ "tenantId": tenant_id, "bindingId": binding_id })
        )
        .unwrap();
        assert_eq!(third["status"], json!("pending"));
        assert_eq!(
            call!(
                f,
                deactivate,
                &as_alice,
                json!({ "tenantId": tenant_id, "activationId": third["id"] })
            )
            .unwrap(),
            json!({ "deactivated": true })
        );
        let cancelled = f.audit(&owner, "binding:deactivate").await;
        assert_eq!(cancelled[0]["metadata"]["cancelled"], json!(true));
        // Requests lapse after a day.
        let fourth = call!(
            f,
            activate,
            &as_alice,
            json!({ "tenantId": tenant_id, "bindingId": binding_id })
        )
        .unwrap();
        f.advance(24 * 3_600_000 + 1);
        assert_eq!(
            call!(
                f,
                list_activations,
                &owner,
                json!({ "tenantId": tenant_id, "status": "pending" })
            )
            .unwrap(),
            json!([])
        );
        assert_eq!(
            code(call!(
                f,
                approve_activation,
                &owner,
                json!({ "tenantId": tenant_id, "activationId": fourth["id"] })
            )),
            "INVALID_TRANSITION"
        );
        // One record per binding and identity: each new request replaced the previous ended one.
        assert_eq!(
            f.find(
                "bindingActivations",
                Filter::new().eq("tenantId", tenant_id.clone())
            )
            .await
            .len(),
            1
        );
        // Without an approver group, anyone holding the permission on the role may decide (owner included).
        let cleared = call!(
            f,
            update,
            &owner,
            json!({ "tenantId": tenant_id, "bindingId": binding_id, "approverGroupId": null })
        )
        .unwrap();
        assert!(cleared.get("approverGroupId").is_none());
        let fifth = call!(
            f,
            activate,
            &as_alice,
            json!({ "tenantId": tenant_id, "bindingId": binding_id })
        )
        .unwrap();
        assert_eq!(
            code(call!(
                f,
                list_approvals,
                &as_carol,
                json!({ "tenantId": tenant_id })
            )),
            "ACCESS_DENIED"
        );
        assert_eq!(
            ids(&call!(f, list_approvals, &owner, json!({ "tenantId": tenant_id })).unwrap()),
            vec![fifth["id"].as_str().unwrap().to_owned()]
        );
        let granted = call!(
            f,
            approve_activation,
            &owner,
            json!({ "tenantId": tenant_id, "activationId": fifth["id"] })
        )
        .unwrap();
        // No duration was requested, so the binding's maximum (two hours) applies.
        assert_eq!(granted["expiresAt"], json!(f.now() + 2 * 3_600_000));
    });
}

#[test]
fn manager_approval_reaches_an_active_manager() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner.clone();
        let alice = f.member("alice").await;
        let dave = f.member("dave").await;
        let auditor = f.role("Auditor", &["iam:audit:read"]).await;
        let member = f
            .role("Member", &["iam:bindings:activate", "iam:bindings:approve"])
            .await;
        for identity in [&alice, &dave] {
            call!(f, create, &owner, json!({ "tenantId": tenant_id, "roleId": member, "subjectType": "identity", "subjectId": identity }))
                .unwrap();
        }
        let eligible = call!(f, create, &owner, json!({
            "tenantId": tenant_id, "roleId": auditor, "subjectType": "identity", "subjectId": alice,
            "eligible": true, "requireApproval": true, "managerApproval": true,
        }))
        .unwrap();
        assert_eq!(eligible["managerApproval"], json!(true));
        let as_alice = f.sign_in("alice").await;
        let as_dave = f.sign_in("dave").await;
        // Nobody can act on the request while she has no manager.
        assert_eq!(
            error(call!(f, activate, &as_alice, json!({ "tenantId": tenant_id, "bindingId": eligible["id"] }))),
            (
                "INVALID_TRANSITION".into(),
                409,
                "Nobody can approve this request: the approver group is empty and you have no active manager".into()
            )
        );
        f.update("identities", &alice, json!({ "managerId": dave }))
            .await;
        let request = call!(
            f,
            activate,
            &as_alice,
            json!({ "tenantId": tenant_id, "bindingId": eligible["id"] })
        )
        .unwrap();
        f.dispatch().await;
        assert_eq!(
            f.sent("activation-request")
                .iter()
                .map(|m| m.to.as_str())
                .collect::<Vec<_>>(),
            vec!["dave@acme.test"]
        );
        assert_eq!(
            ids(&call!(
                f,
                list_approvals,
                &as_dave,
                json!({ "tenantId": tenant_id })
            )
            .unwrap()),
            vec![request["id"].as_str().unwrap().to_owned()]
        );
        let approved = call!(
            f,
            approve_activation,
            &as_dave,
            json!({ "tenantId": tenant_id, "activationId": request["id"] })
        )
        .unwrap();
        // The binding allows the default hour.
        assert_eq!(approved["expiresAt"], json!(f.now() + 3_600_000));
        assert!(f.read_audit(&as_alice).await.is_ok());
    });
}

#[test]
fn binding_creation_rules_and_updates() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner.clone();
        let alice = f.member("alice").await;
        let reader = f.role("Reader", &["documents:read"]).await;
        let create = |input: Value| {
            let f = &f;
            let owner = owner.clone();
            async move { call!(f, create, &owner, input) }
        };
        let base = json!({ "tenantId": tenant_id, "roleId": reader, "subjectType": "identity", "subjectId": alice });
        let with = |extra: Value| {
            let mut input = base.clone();
            for (key, value) in extra.as_object().unwrap() {
                input[key] = value.clone();
            }
            input
        };
        assert_eq!(
            error(create(with(json!({ "subjectType": "robot" }))).await),
            ("INVALID_INPUT".into(), 400, "Invalid subject type".into())
        );
        assert_eq!(
            code(create(with(json!({ "subjectId": "nobody" }))).await),
            "NOT_FOUND"
        );
        assert_eq!(
            code(
                create(with(
                    json!({ "subjectType": "group", "subjectId": "nobody" })
                ))
                .await
            ),
            "NOT_FOUND"
        );
        assert_eq!(
            code(create(with(json!({ "roleId": "nothing" }))).await),
            "NOT_FOUND"
        );
        assert_eq!(
            error(create(with(json!({ "expiresAt": f.now() - 1 }))).await),
            (
                "INVALID_INPUT".into(),
                400,
                "expiresAt must be in the future".into()
            )
        );
        assert_eq!(
            error(
                create(with(
                    json!({ "expiresAt": f.now() + 11 * 365 * 86_400_000 })
                ))
                .await
            ),
            (
                "INVALID_INPUT".into(),
                400,
                "expiresAt must be within ten years".into()
            )
        );
        assert_eq!(
            error(
                create(with(
                    json!({ "startsAt": f.now() + 7_200_000, "expiresAt": f.now() + 3_600_000 })
                ))
                .await
            ),
            (
                "INVALID_INPUT".into(),
                400,
                "startsAt must be before expiresAt".into()
            )
        );
        assert_eq!(
            error(
                create(with(
                    json!({ "window": { "from": "09:00", "to": "09:00", "timeZone": "UTC" } })
                ))
                .await
            ),
            (
                "INVALID_INPUT".into(),
                400,
                "Window must not be empty".into()
            )
        );
        assert_eq!(
            error(create(with(json!({ "authorityId": 5 }))).await),
            ("INVALID_INPUT".into(), 400, "Invalid id".into())
        );
        // A protected role is transferred, never bound by hand.
        let protected = f.role("Protected", &["documents:read"]).await;
        f.update("roles", &protected, json!({ "protected": true }))
            .await;
        assert_eq!(
            error(create(with(json!({ "roleId": protected }))).await),
            (
                "PROTECTED_RESOURCE".into(),
                403,
                "Use owner transfer for protected roles".into()
            )
        );
        // A temporary, windowed, future-dated grant keeps the TypeScript member order.
        let starts_at = f.now() + 3_600_000;
        let expires_at = f.now() + 86_400_000;
        let binding = create(with(json!({
            "startsAt": starts_at, "expiresAt": expires_at,
            "window": { "from": "09:00", "to": "17:00", "timeZone": "Europe/Berlin", "days": [1, 2, 3, 4, 5] },
        })))
        .await
        .unwrap();
        let keys: Vec<&str> = binding
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![
                "id",
                "tenantId",
                "uniqueKey",
                "subjectType",
                "subjectId",
                "roleId",
                "authorityId",
                "expiresAt",
                "startsAt",
                "window"
            ]
        );
        assert_eq!(
            binding["window"],
            json!({ "from": "09:00", "to": "17:00", "timeZone": "Europe/Berlin", "days": [1, 2, 3, 4, 5] })
        );
        let binding_id = binding["id"].clone();
        // Listing: future-dated bindings are not expired; expiry reports filter on expiresBefore.
        assert_eq!(
            ids(&call!(
                f,
                list,
                &owner,
                json!({ "tenantId": tenant_id, "roleId": reader, "expiresBefore": expires_at })
            )
            .unwrap()),
            vec![binding_id.as_str().unwrap().to_owned()]
        );
        assert_eq!(
            call!(
                f,
                list,
                &owner,
                json!({ "tenantId": tenant_id, "roleId": reader, "expiresBefore": expires_at - 1 })
            )
            .unwrap(),
            json!([])
        );
        assert_eq!(
            error(call!(
                f,
                list,
                &owner,
                json!({ "tenantId": tenant_id, "subjectType": "robot" })
            )),
            ("INVALID_INPUT".into(), 400, "Invalid subject type".into())
        );
        assert_eq!(
            error(call!(
                f,
                list,
                &owner,
                json!({ "tenantId": tenant_id, "eligible": 1 })
            )),
            (
                "INVALID_INPUT".into(),
                400,
                "eligible must be boolean".into()
            )
        );
        assert_eq!(
            error(call!(
                f,
                list,
                &owner,
                json!({ "tenantId": tenant_id, "expiresBefore": -1 })
            )),
            ("INVALID_INPUT".into(), 400, "Invalid expiresBefore".into())
        );
        // Updates: nothing to update, clearing members, and the expiry order rule.
        assert_eq!(
            error(call!(
                f,
                update,
                &owner,
                json!({ "tenantId": tenant_id, "bindingId": binding_id })
            )),
            ("INVALID_INPUT".into(), 400, "Nothing to update".into())
        );
        assert_eq!(
            error(call!(
                f,
                update,
                &owner,
                json!({ "tenantId": tenant_id, "bindingId": binding_id, "expiresAt": starts_at - 1_000 })
            )),
            (
                "INVALID_INPUT".into(),
                400,
                "startsAt must be before expiresAt".into()
            )
        );
        let cleared = call!(f, update, &owner, json!({ "tenantId": tenant_id, "bindingId": binding_id, "startsAt": null, "expiresAt": null, "window": null })).unwrap();
        for key in ["startsAt", "expiresAt", "window"] {
            assert!(
                cleared.get(key).is_none(),
                "{key} was not cleared: {cleared}"
            );
        }
        let stored = f
            .iam
            .store
            .get("bindings", binding_id.as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(stored.get("expiresAt").is_none());
        // A package's binding edited by hand is taken over: its package link is dropped.
        f.update(
            "bindings",
            binding_id.as_str().unwrap(),
            json!({ "packageAssignmentId": "pkg-1" }),
        )
        .await;
        let taken = call!(
            f,
            update,
            &owner,
            json!({ "tenantId": tenant_id, "bindingId": binding_id, "expiresAt": expires_at })
        )
        .unwrap();
        assert!(taken.get("packageAssignmentId").is_none());
        assert_eq!(taken["expiresAt"], json!(expires_at));
        // An expired binding drops out of the default listing.
        f.advance(86_400_001);
        assert_eq!(
            call!(
                f,
                list,
                &owner,
                json!({ "tenantId": tenant_id, "roleId": reader })
            )
            .unwrap(),
            json!([])
        );
        assert_eq!(
            ids(&call!(
                f,
                list,
                &owner,
                json!({ "tenantId": tenant_id, "roleId": reader, "includeExpired": true })
            )
            .unwrap()),
            vec![binding_id.as_str().unwrap().to_owned()]
        );
    });
}

#[test]
fn only_the_issuing_authority_mutates_a_binding() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner.clone();
        let alice = f.member("alice").await;
        let admin = f.member("admin").await;
        let reader = f.role("Reader", &["documents:read"]).await;
        let manager = f.role("Binding manager", &["iam:bindings:*"]).await;
        call!(f, create, &owner, json!({ "tenantId": tenant_id, "roleId": manager, "subjectType": "identity", "subjectId": admin }))
            .unwrap();
        let theirs = call!(f, create, &owner, json!({ "tenantId": tenant_id, "roleId": reader, "subjectType": "identity", "subjectId": alice, "eligible": true }))
            .unwrap();
        let as_admin = f.sign_in("admin").await;
        // Without a grant authority of their own, the administrator cannot grant.
        assert_eq!(
            error(call!(
                f,
                create,
                &as_admin,
                json!({ "tenantId": tenant_id, "roleId": reader, "subjectType": "identity", "subjectId": alice })
            )),
            (
                "GRANT_AUTHORITY_REQUIRED".into(),
                403,
                "An active delegated grant authority is required".into()
            )
        );
        f.insert(
            "grantAuthorities",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": tenant_id,
                "identityId": admin,
                "ceiling": better_iam_server::utils::all_value(),
                "parentAuthorityId": f.owner_authority,
                "revoked": false,
            }),
        )
        .await;
        let mine = call!(f, create, &as_admin, json!({ "tenantId": tenant_id, "roleId": reader, "subjectType": "identity", "subjectId": alice }))
            .unwrap();
        assert_ne!(mine["authorityId"], theirs["authorityId"]);
        // The owner's binding is a higher authority's: no update, delete or activation revocation.
        let as_alice = f.sign_in("alice").await;
        let member = f.role("Member", &["iam:bindings:activate"]).await;
        call!(f, create, &owner, json!({ "tenantId": tenant_id, "roleId": member, "subjectType": "identity", "subjectId": alice }))
            .unwrap();
        let activation = call!(
            f,
            activate,
            &as_alice,
            json!({ "tenantId": tenant_id, "bindingId": theirs["id"] })
        )
        .unwrap();
        for result in [
            call!(
                f,
                update,
                &as_admin,
                json!({ "tenantId": tenant_id, "bindingId": theirs["id"], "expiresAt": f.now() + 60_000 })
            ),
            call!(
                f,
                delete,
                &as_admin,
                json!({ "tenantId": tenant_id, "bindingId": theirs["id"] })
            ),
            call!(
                f,
                revoke_activation,
                &as_admin,
                json!({ "tenantId": tenant_id, "activationId": activation["id"] })
            ),
        ] {
            assert_eq!(
                error(result),
                (
                    "ACCESS_DENIED".into(),
                    403,
                    "Cannot mutate a higher authority binding".into()
                )
            );
        }
        // Their own binding is theirs to remove.
        assert_eq!(
            call!(
                f,
                delete,
                &as_admin,
                json!({ "tenantId": tenant_id, "bindingId": mine["id"] })
            )
            .unwrap(),
            json!({ "deleted": true })
        );
        // Activations are made from an ordinary session of the binding's tenant.
        assert_eq!(
            error(call!(
                f,
                activate,
                &as_alice,
                json!({ "tenantId": "elsewhere", "bindingId": theirs["id"] })
            )),
            ("NOT_FOUND".into(), 404, "Resource not found".into())
        );
        assert_eq!(
            error(call!(f, list_mine, &as_alice, json!({ "tenantId": 5 }))),
            ("INVALID_INPUT".into(), 400, "Invalid tenantId".into())
        );
    });
}
