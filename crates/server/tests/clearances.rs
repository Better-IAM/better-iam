//! Security clearances and mandatory access control (clearances.ts): the port of the decision-path parts of
//! tests/clearances-enforcement.test.ts, tests/clearances-fail-closed.test.ts, tests/clearances-hardening.test.ts,
//! tests/clearances-integrations.test.ts and tests/clearances.test.ts.
//!
//! Schemes, clearances, read-ins and labels are written to the store directly, in the record shapes the `clearances`
//! API group writes, where the TypeScript tests go through that group (ported in its own unit); roles and bindings
//! too, as in the governance suites. The lifecycle helpers (`terminateClearancesOf`, `releaseClearancesOf`,
//! `suspendClearance`, `notifyClearanceStatus`, `assertSchemeKept`) and the decision-time helpers (`clearanceScope`,
//! `sessionParties`, `partyState`, `clearedFor`, `attachLabel`) are called directly where the TypeScript tests reach
//! them through other groups.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::DeliveryMessage;
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_core::{
    AuthenticatedPrincipal, ClassificationLabel, ClearanceParty, CredentialInput, Filter,
    FindOptions, IamError, IamStore, IamStoreExt, Identity, PermissionsConfig, Record,
    ResourceTypeDefinition, SessionKind, Tenant, classification_template,
};
use better_iam_server::api::filters::PlanResourcesRequest;
use better_iam_server::api::{Body, Reply};
use better_iam_server::clearances::{
    self, ClassificationScheme, KnownLabeling, applicable_label, attach_label, clearance_keys,
    clearance_scope, cleared_for, label_key, labels_for_type, parties_fail, party_state,
    read_clearance, release_clearances_of, scheme_for_tenant, session_parties, suspend_clearance,
    terminate_clearances_of,
};
use better_iam_server::models::GrantAuthority;
use better_iam_server::options::{
    AccessibleResourcesRequest, AuthorizationRequest, BetterIamOptions, ClearanceOptions,
    ResolvedResource, ResourceTarget, ServerAuthOptions,
};
use better_iam_server::{BetterIam, better_iam};
use bytes::Bytes;
use http::Method;
use serde_json::{Map, Value, json};

const ORIGIN: &str = "http://localhost:3000";
const SECRET: &str = "clearances-fixture-secret-with-32-characters";
const DAY: f64 = 86_400_000.0;
const START: f64 = 1_767_225_600_000.0;

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

fn body<I>(value: Value) -> Body<I> {
    Body::from_value(value)
}

#[track_caller]
fn ok<O: serde::Serialize>(result: Result<Reply<O>, IamError>) -> Value {
    match result.and_then(Reply::into_value) {
        Ok(value) => value,
        Err(error) => panic!(
            "expected success, got {} {} ({})",
            error.code, error.message, error.status
        ),
    }
}

#[track_caller]
fn err<O: serde::Serialize>(result: Result<Reply<O>, IamError>) -> IamError {
    match result.and_then(Reply::into_value) {
        Ok(value) => panic!("expected an error, got {value}"),
        Err(error) => error,
    }
}

fn num(value: f64) -> Value {
    better_iam_core::js::number(value).expect("a finite number")
}

/// What the application's resolver returns for one `{type}/{id}` besides the reference itself.
type AppRecords = Arc<Mutex<HashMap<String, Value>>>;

const READER_PERMISSIONS: [&str; 11] = [
    "documents:read",
    "documents:write",
    "reports:read",
    "notes:read",
    "folders:read",
    "files:read",
    "pages:read",
    "iam:resources:read",
    "iam:resources:create",
    "iam:resources:delete",
    "iam:roles:assume",
];

fn app_type(actions: &[&str]) -> ResourceTypeDefinition {
    ResourceTypeDefinition {
        actions: Some(actions.iter().map(|action| (*action).to_owned()).collect()),
        ..ResourceTypeDefinition::default()
    }
}

fn managed_type(actions: &[&str], parent: Option<&str>) -> ResourceTypeDefinition {
    ResourceTypeDefinition {
        managed: Some(true),
        parent: parent.map(str::to_owned),
        ..app_type(actions)
    }
}

/// Settings of the fixture's deployment.
#[derive(Clone)]
struct Settings {
    /// `clearances` (None: the option is off).
    clearances: Option<ClearanceOptions>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            clearances: Some(ClearanceOptions::default()),
        }
    }
}

/// The platform's root tenant, an active organization `Acme` with its owner under the owner's own grant authority,
/// the clearances option, application types `document`, `report` and `note` answered by a scriptable resolver, and
/// managed `folder` > `file` > `page` (after tests/support/organization.ts and the enforcement suite's setup).
struct Fixture {
    iam: BetterIam,
    root_tenant_id: String,
    root_id: String,
    tenant_id: String,
    owner_id: String,
    owner_authority: String,
    owner: CredentialInput,
    app: AppRecords,
    clock: Arc<Mutex<f64>>,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
    readers: String,
}

fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

async fn fixture(settings: Settings) -> Fixture {
    let database: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let clock = Arc::new(Mutex::new(START));
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let app: AppRecords = Arc::default();
    let mut options = BetterIamOptions::new(database.clone(), SECRET, ORIGIN);
    let mut types = indexmap::IndexMap::new();
    types.insert(
        "document".to_owned(),
        app_type(&["documents:read", "documents:write"]),
    );
    types.insert("report".to_owned(), app_type(&["reports:read"]));
    types.insert("note".to_owned(), app_type(&["notes:read"]));
    types.insert("folder".to_owned(), managed_type(&["folders:read"], None));
    types.insert(
        "file".to_owned(),
        managed_type(&["files:read"], Some("folder")),
    );
    types.insert(
        "page".to_owned(),
        managed_type(&["pages:read"], Some("file")),
    );
    options.permissions = Some(PermissionsConfig {
        resource_types: Some(types),
        ..PermissionsConfig::default()
    });
    let records = app.clone();
    options.resolve_resource = Some(Arc::new(move |reference| {
        let record = records
            .lock()
            .unwrap()
            .get(&format!("{}/{}", reference.kind, reference.id))
            .cloned();
        Box::pin(async move {
            let mut resolved = ResolvedResource::of(&reference);
            if let Some(record) = record {
                resolved.attributes = record.get("attributes").and_then(Value::as_object).cloned();
                resolved.classification = record.get("classification").cloned();
            }
            Ok(resolved)
        })
    }));
    options.clearances = settings.clearances.clone();
    let now_clock = clock.clone();
    let mailbox = inbox.clone();
    options.authentication = Some(ServerAuthOptions {
        session_lifetime_ms: Some(30.0 * DAY),
        session_idle_timeout_ms: Some(30.0 * DAY),
        now: Some(Arc::new(move || *now_clock.lock().unwrap())),
        send_email: Some(better_iam_auth::delivery_fn(move |message| {
            let inbox = mailbox.clone();
            async move {
                inbox.lock().unwrap().push(message);
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
    let mut f = Fixture {
        iam,
        root_tenant_id,
        root_id,
        tenant_id,
        owner_id,
        owner_authority,
        owner: CredentialInput::default(),
        app,
        clock,
        inbox,
        readers: String::new(),
    };
    f.owner = f
        .sign_in_with("owner@acme.test", "a strong tenant owner password")
        .await;
    f.readers = f.role("Readers", &READER_PERMISSIONS).await;
    f
}

/// A member holding the readers role, signed in.
struct Person {
    id: String,
    credential: CredentialInput,
}

impl Fixture {
    fn now(&self) -> f64 {
        *self.clock.lock().unwrap()
    }

    fn advance(&self, ms: f64) {
        *self.clock.lock().unwrap() += ms;
    }

    async fn sign_in_with(&self, email: &str, password: &str) -> CredentialInput {
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

    /// A member of the organization (`{name}@acme.test`); its identity ID.
    async fn member(&self, name: &str) -> String {
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

    /// A member bound to the readers role, signed in.
    async fn person(&self, name: &str) -> Person {
        let id = self.member(name).await;
        self.bind(&self.readers.clone(), &id).await;
        let credential = self
            .sign_in_with(
                &format!("{name}@acme.test"),
                &format!("a strong {name} password"),
            )
            .await;
        Person { id, credential }
    }

    async fn insert(&self, collection: &str, record: Value) -> Record {
        let collection = collection.to_owned();
        let record = record.as_object().unwrap().clone();
        self.iam
            .store
            .transaction(move |tx| async move { tx.insert(&collection, &record).await })
            .await
            .unwrap()
    }

    /// Writes a record, replacing one with the same id.
    async fn save(&self, collection: &str, record: Value) {
        let collection = collection.to_owned();
        let record = record.as_object().unwrap().clone();
        self.iam
            .store
            .transaction(move |tx| async move {
                let id = record["id"].as_str().unwrap().to_owned();
                if tx.get(&collection, &id).await?.is_some() {
                    tx.put(&collection, &record).await
                } else {
                    tx.insert(&collection, &record).await
                }
            })
            .await
            .unwrap();
    }

    async fn patch(&self, collection: &str, id: &str, patch: Value) {
        let collection = collection.to_owned();
        let id = id.to_owned();
        self.iam
            .store
            .transaction(move |tx| async move {
                let mut record = tx.get(&collection, &id).await?.expect("record");
                for (key, value) in patch.as_object().unwrap() {
                    if value.is_null() {
                        record.shift_remove(key);
                    } else {
                        record.insert(key.clone(), value.clone());
                    }
                }
                tx.put(&collection, &record).await
            })
            .await
            .unwrap();
    }

    async fn get(&self, collection: &str, id: &str) -> Option<Record> {
        self.iam.store.get(collection, id).await.unwrap()
    }

    async fn find(&self, collection: &str, filter: &[(&str, Value)]) -> Vec<Record> {
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

    /// A role of the organization allowing `actions` on every resource.
    async fn role(&self, name: &str, actions: &[&str]) -> String {
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

    /// A binding of the role to an identity under the owner's grant authority.
    async fn bind(&self, role_id: &str, identity_id: &str) {
        let authority = self.owner_authority.clone();
        self.insert(
            "bindings",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": self.tenant_id,
                "uniqueKey": format!("identity:{identity_id}:{role_id}:{authority}"),
                "subjectType": "identity",
                "subjectId": identity_id,
                "roleId": role_id,
                "authorityId": authority,
            }),
        )
        .await;
    }

    /// A scheme record as `clearances.defineScheme` writes it: the US template with compartments GAMMA and HCS and
    /// unrestricted adjudication, `settings` merged in.
    async fn define_scheme(&self, tenant_id: &str, settings: Value) -> Value {
        let mut definition = serde_json::to_value(classification_template("us").unwrap()).unwrap();
        definition["compartments"] = json!([
            { "id": "GAMMA", "name": "Gamma codeword" },
            { "id": "HCS", "name": "Humint control" },
        ]);
        let now = self.now();
        let mut record = json!({
            "id": better_iam_server::utils::id(),
            "tenantId": tenant_id,
            "uniqueKey": "scheme",
            "definition": definition,
            "name": "Acme",
            "requireLabels": [],
            "guestCeiling": null,
            "interimAllowed": false,
            "adjudication": "unrestricted",
            "createdAt": num(now),
            "createdBy": self.owner_id,
            "updatedAt": num(now),
            "updatedBy": self.owner_id,
            "version": 1,
        });
        for (key, value) in settings.as_object().unwrap() {
            record[key] = value.clone();
        }
        self.insert("classificationSchemes", record.clone()).await;
        record
    }

    /// Changes settings of the scheme a tenant defines.
    async fn update_scheme(&self, tenant_id: &str, settings: Value) {
        let scheme = self
            .find(
                "classificationSchemes",
                &[
                    ("tenantId", json!(tenant_id)),
                    ("uniqueKey", json!("scheme")),
                ],
            )
            .await;
        let id = scheme[0]["id"].as_str().unwrap().to_owned();
        self.patch("classificationSchemes", &id, settings).await;
    }

    /// A clearance record as `clearances.grant` writes it (citizenship USA unless `extra` says otherwise).
    async fn clear_in(
        &self,
        tenant_id: &str,
        identity_id: &str,
        scheme_tenant_id: &str,
        level: &str,
        extra: Value,
    ) {
        let now = self.now();
        let mut record = json!({
            "id": identity_id,
            "tenantId": tenant_id,
            "uniqueKey": format!("identity:{identity_id}"),
            "identityId": identity_id,
            "schemeTenantId": scheme_tenant_id,
            "level": level,
            "citizenship": ["USA"],
            "status": "active",
            "readIns": [],
            "grantedAt": num(now),
            "grantedBy": self.owner_id,
            "updatedAt": num(now),
            "updatedBy": self.owner_id,
        });
        for (key, value) in extra.as_object().unwrap() {
            record[key] = value.clone();
        }
        self.save("clearances", record).await;
    }

    /// A clearance in the organization under its own scheme.
    async fn clear(&self, identity_id: &str, level: &str, extra: Value) {
        let tenant_id = self.tenant_id.clone();
        self.clear_in(&tenant_id, identity_id, &tenant_id, level, extra)
            .await;
    }

    /// A label record as `clearances.label` writes it.
    async fn store_label(
        &self,
        tenant_id: &str,
        kind: &str,
        resource_id: &str,
        label: Value,
        scheme_tenant_id: &str,
        inherit_to_children: bool,
    ) {
        let now = self.now();
        self.save(
            "resourceLabels",
            json!({
                "id": format!("label-{tenant_id}-{kind}-{resource_id}"),
                "tenantId": tenant_id,
                "uniqueKey": label_key(kind, resource_id).unwrap(),
                "type": kind,
                "resourceId": resource_id,
                "label": label,
                "inheritToChildren": inherit_to_children,
                "schemeTenantId": scheme_tenant_id,
                "labeledBy": self.owner_id,
                "labeledAt": num(now),
                "version": 1,
            }),
        )
        .await;
    }

    /// A label in the organization under its own scheme.
    async fn label(&self, kind: &str, resource_id: &str, label: Value, inherit_to_children: bool) {
        let tenant_id = self.tenant_id.clone();
        self.store_label(
            &tenant_id,
            kind,
            resource_id,
            label,
            &tenant_id,
            inherit_to_children,
        )
        .await;
    }

    async fn register(&self, kind: &str, id: &str, parent_id: Option<&str>) -> Value {
        let mut input = json!({ "tenantId": self.tenant_id, "type": kind, "id": id });
        if let Some(parent_id) = parent_id {
            input["parentId"] = json!(parent_id);
        }
        ok(self
            .iam
            .api
            .resources
            .register(&self.owner, body(input))
            .await)
    }

    async fn can(&self, credential: &CredentialInput, action: &str, kind: &str, id: &str) -> bool {
        self.iam
            .authorize(&AuthorizationRequest {
                credential: credential.clone(),
                tenant_id: self.tenant_id.clone(),
                action: action.into(),
                resource: ResourceTarget {
                    kind: kind.into(),
                    id: id.into(),
                },
            })
            .await
            .expect("decision")
            .allowed
    }

    async fn reads(&self, credential: &CredentialInput, id: &str) -> bool {
        self.can(credential, "documents:read", "document", id).await
    }

    async fn listed(&self, credential: &CredentialInput, action: &str, kind: &str) -> Vec<String> {
        self.iam
            .list_accessible(&AccessibleResourcesRequest {
                credential: credential.clone(),
                tenant_id: self.tenant_id.clone(),
                action: action.into(),
                kind: kind.into(),
                limit: None,
                offset: None,
            })
            .await
            .expect("listing")
            .resources
            .iter()
            .map(|item| item["resourceId"].as_str().unwrap().to_owned())
            .collect()
    }

    async fn plan(
        &self,
        credential: &CredentialInput,
        action: &str,
        kind: &str,
    ) -> Result<Value, IamError> {
        self.iam
            .plan_resources
            .plan_resources(&PlanResourcesRequest {
                credential: credential.clone(),
                tenant_id: self.tenant_id.clone(),
                action: action.into(),
                kind: kind.into(),
            })
            .await
    }

    async fn principal(&self, credential: &CredentialInput) -> AuthenticatedPrincipal {
        self.iam
            .ctx
            .principals()
            .unwrap()
            .authenticate(credential)
            .await
            .expect("principal")
    }

    async fn identity(&self, identity_id: &str) -> Identity {
        better_iam_server::port::decode(
            self.get("identities", identity_id).await.expect("identity"),
        )
        .unwrap()
    }

    /// Another tenant written to the store (`type`, below `parent_id`).
    async fn tenant_below(&self, name: &str, kind: &str, parent_id: &str) -> String {
        let id = better_iam_server::utils::id();
        self.insert(
            "tenants",
            json!({
                "id": id,
                "tenantId": id,
                "name": name,
                "type": kind,
                "parentId": parent_id,
                "status": "active",
                "createdAt": num(self.now()),
            }),
        )
        .await;
        id
    }

    async fn audit(&self, action: &str) -> Vec<Record> {
        self.find(
            "audit",
            &[
                ("tenantId", json!(self.tenant_id)),
                ("action", json!(action)),
            ],
        )
        .await
    }

    async fn deliveries(&self) -> Vec<DeliveryMessage> {
        self.iam.auth.dispatch_outbox(None).await.expect("dispatch");
        std::mem::take(&mut *self.inbox.lock().unwrap())
    }

    /// What the application resolver answers for `{type}/{id}` (attributes, classification).
    fn resolves(&self, kind: &str, id: &str, record: Value) {
        self.app
            .lock()
            .unwrap()
            .insert(format!("{kind}/{id}"), record);
    }
}

/// `not(id in ids)`: the plan of a principal who may read everything of the type but `ids`.
fn all_but(ids: &[&str]) -> Value {
    json!({ "kind": "not", "filter": { "kind": "equals", "field": "id", "values": ids } })
}

// --- mandatory access control on the decision paths ------------------------------------------------

#[test]
fn refuses_reading_up_whatever_roles_say_and_limits_listings_and_plans() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        let bob = f.person("bob").await;
        f.clear(&alice.id, "S", json!({})).await;
        f.label("document", "d1", json!({ "level": "S" }), false)
            .await;
        f.label("document", "d2", json!({ "level": "TS" }), false)
            .await;
        f.label("document", "d3", json!({ "level": "U" }), false)
            .await;
        assert!(f.reads(&alice.credential, "d1").await);
        assert!(!f.reads(&alice.credential, "d2").await);
        assert!(f.reads(&alice.credential, "d3").await);
        // Unlabeled resources of types the scheme does not require a label on stay open.
        assert!(f.reads(&alice.credential, "d4").await);
        // Bob holds no clearance: not even UNCLASSIFIED.
        assert!(!f.reads(&bob.credential, "d1").await);
        assert!(!f.reads(&bob.credential, "d3").await);
        assert!(f.reads(&bob.credential, "d4").await);
        // The owner holds every permission and no clearance.
        assert!(!f.reads(&f.owner, "d1").await);
        // `iam:*` administration is never subject.
        assert!(
            f.can(&f.owner, "iam:resources:read", "iam", "document/d2")
                .await
        );
        // A refusal masks the reason (CLEARANCE_REQUIRED is audited, not answered).
        let decision = f
            .iam
            .authorize(&AuthorizationRequest {
                credential: alice.credential.clone(),
                tenant_id: f.tenant_id.clone(),
                action: "documents:read".into(),
                resource: ResourceTarget {
                    kind: "document".into(),
                    id: "d2".into(),
                },
            })
            .await
            .unwrap();
        assert!(!decision.allowed);

        // Plans for an application type exclude what the clearance does not read.
        let plan = f
            .plan(&alice.credential, "documents:read", "document")
            .await
            .unwrap();
        assert_eq!(plan["filter"], all_but(&["d2"]));
        // The conformance `planResources` call reads the request's credential in every wire form, the tagged
        // `{"$headers": {...}}` one included (tests/middleware-plan.test.ts).
        let token = alice.credential.token.clone().expect("token");
        let called = f
            .iam
            .plan_resources
            .call(
                "",
                vec![json!({
                    "headers": { "$headers": { "authorization": format!("Bearer {token}") } },
                    "tenantId": f.tenant_id,
                    "action": "documents:read",
                    "type": "document",
                })],
            )
            .await
            .expect("planResources")
            .expect("plan");
        assert_eq!(called["filter"], all_but(&["d2"]));
        let plan = f
            .plan(&bob.credential, "documents:read", "document")
            .await
            .unwrap();
        assert_eq!(plan["filter"], all_but(&["d1", "d2", "d3"]));

        // Listings of managed types too.
        for id in ["f1", "f2", "f3"] {
            f.register("folder", id, None).await;
        }
        f.label("folder", "f2", json!({ "level": "TS" }), false)
            .await;
        assert_eq!(
            f.listed(&alice.credential, "folders:read", "folder").await,
            vec!["f1", "f3"]
        );
        let plan = f
            .plan(&alice.credential, "folders:read", "folder")
            .await
            .unwrap();
        assert_eq!(plan["filter"], all_but(&["f2"]));
    });
}

#[test]
fn passes_labels_down_managed_parents_as_far_as_they_go_decided_at_the_time() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        f.clear(&alice.id, "S", json!({})).await;
        f.register("folder", "vault", None).await;
        f.register("file", "plan", Some("vault")).await;
        f.register("page", "p1", Some("plan")).await;
        f.register("folder", "open", None).await;
        f.register("file", "memo", Some("open")).await;
        assert!(f.can(&alice.credential, "pages:read", "page", "p1").await);
        // A label without inheritToChildren stays on its resource.
        f.label("folder", "vault", json!({ "level": "TS" }), false)
            .await;
        assert!(
            !f.can(&alice.credential, "folders:read", "folder", "vault")
                .await
        );
        assert!(f.can(&alice.credential, "files:read", "file", "plan").await);
        assert!(f.can(&alice.credential, "pages:read", "page", "p1").await);
        // Passed down, it reaches every descendant.
        f.label("folder", "vault", json!({ "level": "TS" }), true)
            .await;
        assert!(!f.can(&alice.credential, "files:read", "file", "plan").await);
        assert!(!f.can(&alice.credential, "pages:read", "page", "p1").await);
        assert!(f.can(&alice.credential, "files:read", "file", "memo").await);
        assert_eq!(
            f.listed(&alice.credential, "files:read", "file").await,
            vec!["memo"]
        );
        // Labels join along the way: a compartment below the folder's level.
        f.label(
            "file",
            "plan",
            json!({ "level": "C", "compartments": ["GAMMA"] }),
            true,
        )
        .await;
        let labels = within(&f, |tx, tenant_id| async move {
            labels_for_type(&tx, &tenant_id, "page").await
        })
        .await;
        assert_eq!(
            serde_json::to_value(&labels["p1"]).unwrap(),
            json!({ "level": "TS", "compartments": ["GAMMA"] })
        );
        // Decided at the time: once the folder is relabeled, its descendants follow.
        f.label("folder", "vault", json!({ "level": "C" }), true)
            .await;
        f.clear(
            &alice.id,
            "S",
            json!({ "readIns": [{ "compartmentId": "GAMMA", "readInAt": num(f.now()), "readInBy": f.owner_id }] }),
        )
        .await;
        assert!(f.can(&alice.credential, "pages:read", "page", "p1").await);
    });
}

#[test]
fn refuses_unlabeled_resources_of_required_types_unless_a_default_label_applies() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(
            &f.tenant_id,
            json!({ "requireLabels": ["document", "folder"] }),
        )
        .await;
        let alice = f.person("alice").await;
        f.clear(&alice.id, "S", json!({})).await;
        assert!(!f.reads(&alice.credential, "d1").await);
        f.label("document", "d1", json!({ "level": "C" }), false)
            .await;
        assert!(f.reads(&alice.credential, "d1").await);
        // Types not required stay open.
        assert!(
            f.can(&alice.credential, "reports:read", "report", "r1")
                .await
        );
        // The `iam/{type}/{id}` alias of a required type is refused like the resource, except for administration.
        assert!(
            !f.can(&alice.credential, "documents:read", "iam", "document/d2")
                .await
        );
        assert!(
            f.can(
                &alice.credential,
                "iam:resources:read",
                "iam",
                "document/d2"
            )
            .await
        );
        // A filter cannot check labels of application resources.
        let error = f
            .plan(&alice.credential, "documents:read", "document")
            .await
            .unwrap_err();
        assert_eq!(error.code, "UNSUPPORTED_FILTER");
        // Managed resources are planned by id: unlabeled registrations are refused.
        f.register("folder", "f1", None).await;
        f.register("folder", "f2", None).await;
        f.label("folder", "f2", json!({ "level": "C" }), false)
            .await;
        let plan = f
            .plan(&alice.credential, "folders:read", "folder")
            .await
            .unwrap();
        assert_eq!(
            plan["filter"],
            json!({ "kind": "equals", "field": "id", "values": ["f2"] })
        );
        // With a default label the unlabeled ones read as it.
        f.update_scheme(&f.tenant_id, json!({ "defaultLabel": { "level": "C" } }))
            .await;
        assert!(f.reads(&alice.credential, "d2").await);
        let plan = f
            .plan(&alice.credential, "folders:read", "folder")
            .await
            .unwrap();
        assert_eq!(
            plan["filter"],
            json!({ "kind": "equals", "field": "id", "values": ["f1", "f2"] })
        );
        f.update_scheme(&f.tenant_id, json!({ "defaultLabel": { "level": "TS" } }))
            .await;
        assert!(!f.reads(&alice.credential, "d2").await);
        let plan = f
            .plan(&alice.credential, "folders:read", "folder")
            .await
            .unwrap();
        assert_eq!(
            plan["filter"],
            json!({ "kind": "equals", "field": "id", "values": ["f2"] })
        );
    });
}

#[test]
fn decides_noforn_and_rel_to_by_adjudicated_citizenship_never_by_attributes() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        let bob = f.person("bob").await;
        f.clear(&alice.id, "TS", json!({})).await;
        f.clear(&bob.id, "TS", json!({ "citizenship": ["GBR"] }))
            .await;
        f.patch(
            "identities",
            &bob.id,
            json!({ "attributes": { "citizenship": "USA" } }),
        )
        .await;
        f.label(
            "document",
            "noforn",
            json!({ "level": "S", "noforn": true }),
            false,
        )
        .await;
        f.label(
            "document",
            "gbr",
            json!({ "level": "S", "releasableTo": ["GBR"] }),
            false,
        )
        .await;
        f.label(
            "document",
            "can",
            json!({ "level": "S", "releasableTo": ["CAN"] }),
            false,
        )
        .await;
        assert!(f.reads(&alice.credential, "noforn").await);
        assert!(!f.reads(&bob.credential, "noforn").await);
        assert!(f.reads(&alice.credential, "gbr").await);
        assert!(f.reads(&bob.credential, "gbr").await);
        assert!(f.reads(&alice.credential, "can").await);
        assert!(!f.reads(&bob.credential, "can").await);
    });
}

#[test]
fn counts_read_ins_only_while_their_nda_acceptance_is_current() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        let agreement_id = better_iam_server::utils::id();
        f.insert(
            "agreements",
            json!({
                "id": agreement_id,
                "tenantId": f.tenant_id,
                "uniqueKey": "name:gamma nda",
                "name": "Gamma NDA",
                "content": "Keep it secret.",
                "version": 1,
                "required": false,
                "reacceptAfterDays": 1,
                "createdAt": num(f.now()),
                "createdBy": f.owner_id,
                "updatedAt": num(f.now()),
            }),
        )
        .await;
        let read_in = json!({
            "compartmentId": "GAMMA",
            "readInAt": num(f.now()),
            "readInBy": f.owner_id,
            "agreementId": agreement_id,
        });
        f.clear(&alice.id, "S", json!({ "readIns": [read_in] }))
            .await;
        f.label(
            "document",
            "g",
            json!({ "level": "S", "compartments": ["GAMMA"] }),
            false,
        )
        .await;
        assert!(!f.reads(&alice.credential, "g").await);
        f.insert(
            "agreementAcceptances",
            json!({
                "id": format!("{agreement_id}:{}", alice.id),
                "tenantId": f.tenant_id,
                "agreementId": agreement_id,
                "identityId": alice.id,
                "version": 1,
                "acceptedAt": num(f.now()),
            }),
        )
        .await;
        assert!(f.reads(&alice.credential, "g").await);
        // A new version of the NDA needs a new acceptance.
        f.patch("agreements", &agreement_id, json!({ "version": 2 }))
            .await;
        assert!(!f.reads(&alice.credential, "g").await);
        f.patch("agreements", &agreement_id, json!({ "version": 1 }))
            .await;
        assert!(f.reads(&alice.credential, "g").await);
        // So does an acceptance that lapsed.
        f.advance(2.0 * DAY);
        assert!(!f.reads(&alice.credential, "g").await);
        // A read-in without an agreement counts as long as it stands; an unknown compartment never does.
        f.clear(
            &alice.id,
            "S",
            json!({ "readIns": [
                { "compartmentId": "GAMMA", "readInAt": num(f.now()), "readInBy": f.owner_id },
                { "compartmentId": "OMEGA", "readInAt": num(f.now()), "readInBy": f.owner_id },
            ] }),
        )
        .await;
        assert!(f.reads(&alice.credential, "g").await);
        let principal = f.principal(&alice.credential).await;
        let keys = scope_keys(&f, principal).await;
        assert_eq!(keys["principal.clearanceCompartments"], json!(["GAMMA"]));
        assert_eq!(keys["principal.clearanceLevel"], json!("S"));
        assert_eq!(keys["principal.clearanceRank"], json!(2));
        assert_eq!(keys["principal.clearanceStatus"], json!("active"));
        assert_eq!(keys["principal.clearanceCitizenship"], json!(["USA"]));
    });
}

/// Runs `body` in a transaction with the organization's id.
async fn within<T, F, Fut>(f: &Fixture, body: F) -> T
where
    T: Send + 'static,
    F: FnOnce(better_iam_server::context::Store, String) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, IamError>> + Send + 'static,
{
    let tenant_id = f.tenant_id.clone();
    f.iam
        .store
        .transaction(move |tx| async move { body(tx, tenant_id).await })
        .await
        .expect("transaction")
}

/// The `principal.clearance*` keys of a principal in the organization.
async fn scope_keys(f: &Fixture, principal: AuthenticatedPrincipal) -> Map<String, Value> {
    let ctx = f.iam.ctx.clone();
    let now = f.now();
    within(f, move |tx, tenant_id| async move {
        let tenant: Tenant =
            better_iam_server::port::decode(tx.get("tenants", &tenant_id).await?.unwrap())?;
        let chain = ctx.ancestry(&tx, &tenant).await?;
        let scope = clearance_scope(&ctx, &tx, &principal, &tenant, &chain, None, now, None)
            .await?
            .expect("a scheme to enforce");
        Ok(scope.keys().clone())
    })
    .await
}

#[test]
fn counts_interim_clearances_expiry_and_suspension_at_decision_time() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        f.label("document", "d1", json!({ "level": "C" }), false)
            .await;
        f.clear(&alice.id, "S", json!({ "status": "interim" }))
            .await;
        assert!(!f.reads(&alice.credential, "d1").await);
        let principal = f.principal(&alice.credential).await;
        assert_eq!(
            scope_keys(&f, principal.clone()).await["principal.clearanceStatus"],
            json!("none")
        );
        f.update_scheme(&f.tenant_id, json!({ "interimAllowed": true }))
            .await;
        assert!(f.reads(&alice.credential, "d1").await);
        assert_eq!(
            scope_keys(&f, principal.clone()).await["principal.clearanceStatus"],
            json!("interim")
        );
        f.clear(&alice.id, "S", json!({ "expiresAt": num(f.now() + DAY) }))
            .await;
        assert!(f.reads(&alice.credential, "d1").await);
        f.advance(DAY);
        assert!(!f.reads(&alice.credential, "d1").await);
        assert_eq!(
            scope_keys(&f, principal.clone()).await["principal.clearanceStatus"],
            json!("expired")
        );
        f.clear(&alice.id, "S", json!({})).await;
        assert!(f.reads(&alice.credential, "d1").await);
        let identity = f.identity(&alice.id).await;
        let outcome = within(&f, {
            let identity = json!({ "id": identity.id, "tenantId": identity.tenant_id });
            let at = f.now();
            move |tx, _| async move {
                suspend_clearance(
                    &tx,
                    &identity,
                    &json!({ "by": "officer", "at": num(at), "reason": "under investigation", "incidentId": "INC-1" }),
                )
                .await
            }
        })
        .await;
        assert_eq!(outcome["outcome"], json!("suspended"));
        assert_eq!(outcome["record"]["status"], json!("suspended"));
        assert_eq!(
            outcome["record"]["suspended"],
            json!({ "by": "officer", "at": num(f.now()), "reason": "under investigation", "incidentId": "INC-1", "previousStatus": "active" })
        );
        assert!(!f.reads(&alice.credential, "d1").await);
        assert_eq!(
            scope_keys(&f, principal.clone()).await["principal.clearanceStatus"],
            json!("suspended")
        );
        // Suspending again does nothing; neither does suspending what ended or never was.
        let again = within(&f, {
            let identity = json!({ "id": identity.id, "tenantId": identity.tenant_id });
            move |tx, _| async move {
                suspend_clearance(
                    &tx,
                    &identity,
                    &json!({ "by": "x", "at": 1, "reason": "again" }),
                )
                .await
            }
        })
        .await;
        assert_eq!(again["outcome"], json!("already-applied"));
        f.clear(&alice.id, "S", json!({ "status": "revoked" }))
            .await;
        let revoked = within(&f, {
            let identity = json!({ "id": identity.id, "tenantId": identity.tenant_id });
            move |tx, _| async move {
                suspend_clearance(
                    &tx,
                    &identity,
                    &json!({ "by": "x", "at": 1, "reason": "no" }),
                )
                .await
            }
        })
        .await;
        assert_eq!(revoked, json!({ "outcome": "no-clearance" }));
        // A disabled account never counts.
        f.clear(&alice.id, "S", json!({})).await;
        assert!(f.reads(&alice.credential, "d1").await);
        let scheme = within(&f, |tx, tenant_id| async move {
            scheme_for_tenant(&tx, &tenant_id).await
        })
        .await
        .unwrap();
        let mut disabled = identity.clone();
        disabled.status = better_iam_core::IdentityStatus::Disabled;
        let now = f.now();
        let state = within(&f, {
            let scheme = scheme.clone();
            move |tx, tenant_id| async move {
                party_state(
                    &tx,
                    &scheme,
                    Some(&disabled),
                    &disabled.id.clone(),
                    Some(tenant_id.as_str()),
                    now,
                )
                .await
            }
        })
        .await;
        assert_eq!(state.status, json!("none"));
        assert_eq!(state.party.rank, -1.0);
        assert!(state.record.is_some());
    });
}

#[test]
fn caps_guests_at_the_ceiling_and_never_gives_them_compartments() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        f.clear(
            &alice.id,
            "TS",
            json!({ "readIns": [{ "compartmentId": "GAMMA", "readInAt": num(f.now()), "readInBy": f.owner_id }] }),
        )
        .await;
        let mut guest = f.identity(&alice.id).await;
        guest.guest = Some(better_iam_core::GuestProfile {
            sponsor_id: f.owner_id.clone(),
            since: f.now(),
            home_tenant_id: None,
            home_domain: None,
            extra: Map::new(),
        });
        let now = f.now();
        let state_of = |scheme: ClassificationScheme| {
            let guest = guest.clone();
            move |tx: better_iam_server::context::Store, tenant_id: String| async move {
                party_state(
                    &tx,
                    &scheme,
                    Some(&guest),
                    &guest.id.clone(),
                    Some(tenant_id.as_str()),
                    now,
                )
                .await
            }
        };
        let scheme = |f: &Fixture| {
            let tenant_id = f.tenant_id.clone();
            let store = f.iam.store.clone();
            async move {
                scheme_for_tenant(&store, &tenant_id)
                    .await
                    .unwrap()
                    .unwrap()
            }
        };
        // Without a ceiling guests hold no clearance.
        let state = within(&f, state_of(scheme(&f).await)).await;
        assert_eq!(state.status, json!("none"));
        f.update_scheme(&f.tenant_id, json!({ "guestCeiling": "C" }))
            .await;
        let state = within(&f, state_of(scheme(&f).await)).await;
        assert_eq!(state.status, json!("active"));
        assert_eq!(state.level.as_ref().unwrap().id, "C");
        assert_eq!(state.party.rank, 1.0);
        assert!(state.party.compartments.is_empty());
        // A member counts at their own level, compartments included.
        let member = f.identity(&alice.id).await;
        let tenant_id = f.tenant_id.clone();
        let scheme_now = scheme(&f).await;
        let state = within(&f, move |tx, _| async move {
            party_state(
                &tx,
                &scheme_now,
                Some(&member),
                &member.id.clone(),
                Some(tenant_id.as_str()),
                now,
            )
            .await
        })
        .await;
        assert_eq!(state.level.as_ref().unwrap().id, "TS");
        assert_eq!(
            state.party.compartments.into_iter().collect::<Vec<_>>(),
            vec!["GAMMA"]
        );
    });
}

// --- fails closed ----------------------------------------------------------------------------------

#[test]
fn refuses_a_label_written_under_another_scheme_and_labels_left_without_one() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        f.clear(&alice.id, "S", json!({})).await;
        for id in ["d1", "d2"] {
            f.register("folder", id, None).await;
        }
        let tenant_id = f.tenant_id.clone();
        f.store_label(
            &tenant_id,
            "folder",
            "d1",
            json!({ "level": "U" }),
            "a-scheme-no-longer-in-force",
            false,
        )
        .await;
        assert!(
            !f.can(&alice.credential, "folders:read", "folder", "d1")
                .await
        );
        assert_eq!(
            f.listed(&alice.credential, "folders:read", "folder").await,
            vec!["d2"]
        );
        // An asserted label the scheme cannot read refuses everyone; a valid one can only raise.
        f.resolves(
            "document",
            "a1",
            json!({ "classification": { "level": "SECRET" } }),
        );
        assert!(!f.reads(&alice.credential, "a1").await);
        f.resolves(
            "document",
            "a2",
            json!({ "classification": { "level": "TS" } }),
        );
        f.label("document", "a2", json!({ "level": "U" }), false)
            .await;
        assert!(!f.reads(&alice.credential, "a2").await);
        f.resolves(
            "document",
            "a3",
            json!({ "classification": { "level": "U" } }),
        );
        f.label("document", "a3", json!({ "level": "TS" }), false)
            .await;
        assert!(!f.reads(&alice.credential, "a3").await);
        f.resolves(
            "document",
            "a4",
            json!({ "classification": { "level": "C" } }),
        );
        assert!(f.reads(&alice.credential, "a4").await);
        f.resolves("document", "a5", json!({ "classification": "secret" }));
        assert!(!f.reads(&alice.credential, "a5").await);

        // Labels left in a tenant no scheme applies to refuse everyone; the rest stays open.
        let globex = f
            .tenant_below("Globex", "organization", &f.root_tenant_id)
            .await;
        f.store_label(
            &globex,
            "document",
            "q3",
            json!({ "level": "TS" }),
            &tenant_id,
            false,
        )
        .await;
        let scheme = within(&f, {
            let globex = globex.clone();
            move |tx, _| async move { scheme_for_tenant(&tx, &globex).await }
        })
        .await
        .expect("the stand-in scheme");
        assert_eq!(scheme.tenant_id, "!no-scheme-in-force");
        assert!(scheme.definition.levels.is_empty());
        let labels = within(&f, {
            let globex = globex.clone();
            move |tx, _| async move { labels_for_type(&tx, &globex, "document").await }
        })
        .await;
        assert_eq!(labels["q3"].level, "!invalid");
        // Without labels there is nothing to enforce.
        let none = within(&f, {
            let root = f.root_tenant_id.clone();
            move |tx, _| async move { scheme_for_tenant(&tx, &root).await }
        })
        .await;
        assert!(none.is_none());
    });
}

#[test]
fn stops_planning_application_types_while_a_label_passes_down_to_children() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        f.clear(&alice.id, "S", json!({})).await;
        f.label("note", "n1", json!({ "level": "TS" }), false).await;
        let plan = f
            .plan(&alice.credential, "notes:read", "note")
            .await
            .unwrap();
        assert_eq!(plan["filter"], all_but(&["n1"]));
        f.label("folder", "f1", json!({ "level": "TS" }), true)
            .await;
        let error = f
            .plan(&alice.credential, "notes:read", "note")
            .await
            .unwrap_err();
        assert_eq!(error.code, "UNSUPPORTED_FILTER");
        // Registered resources inherit only through registered parents, which the plan follows.
        let plan = f
            .plan(&alice.credential, "folders:read", "folder")
            .await
            .unwrap();
        assert_eq!(plan["filter"], all_but(&["f1"]));
        // An application resource inherits what the parent its resolver reports passes down.
        f.resolves(
            "note",
            "n2",
            json!({ "attributes": { "parentType": "folder", "parentId": "f1" } }),
        );
        assert!(!f.can(&alice.credential, "notes:read", "note", "n2").await);
        assert!(f.can(&alice.credential, "notes:read", "note", "n3").await);
    });
}

#[test]
fn decides_an_application_action_on_the_iam_alias_like_the_resource_it_names() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        f.clear(&alice.id, "S", json!({})).await;
        f.label("document", "d1", json!({ "level": "TS" }), false)
            .await;
        assert!(
            !f.can(&alice.credential, "documents:read", "iam", "document/d1")
                .await
        );
        assert!(
            f.can(
                &alice.credential,
                "iam:resources:read",
                "iam",
                "document/d1"
            )
            .await
        );
        // What the application resolves for the named resource counts as well.
        f.resolves(
            "document",
            "d2",
            json!({ "classification": { "level": "TS" } }),
        );
        assert!(!f.reads(&alice.credential, "d2").await);
        assert!(
            !f.can(&alice.credential, "documents:read", "iam", "document/d2")
                .await
        );
        assert!(
            f.can(&alice.credential, "documents:read", "iam", "document/d3")
                .await
        );
        // attachLabel: an alias whose named resource failed to resolve refuses every party.
        let ctx = f.iam.ctx.clone();
        let labeled = within(&f, move |tx, tenant_id| async move {
            let scheme = scheme_for_tenant(&tx, &tenant_id).await?;
            let alias = ResolvedResource {
                tenant_id: tenant_id.clone(),
                kind: "iam".into(),
                id: "document/d3".into(),
                attributes: None,
                classification: None,
            };
            let failed = attach_label(
                &ctx,
                &tx,
                &tenant_id,
                &alias,
                Some(&KnownLabeling {
                    scheme: scheme.clone(),
                    named: Some(None),
                }),
            )
            .await?;
            let open = attach_label(
                &ctx,
                &tx,
                &tenant_id,
                &alias,
                Some(&KnownLabeling {
                    scheme,
                    named: None,
                }),
            )
            .await?;
            let platform = attach_label(
                &ctx,
                &tx,
                &tenant_id,
                &ResolvedResource {
                    id: "role/r1".into(),
                    ..alias.clone()
                },
                None,
            )
            .await?;
            Ok((failed, open, platform))
        })
        .await;
        assert_eq!(
            labeled.0.classification,
            Some(json!({ "level": "!invalid" }))
        );
        assert_eq!(labeled.1.classification, Some(Value::Null));
        assert_eq!(labeled.2.classification, None);
    });
}

// --- every party of a session ----------------------------------------------------------------------

#[test]
fn needs_every_party_of_a_session() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        f.clear(&alice.id, "TS", json!({})).await;
        let principal = f.principal(&alice.credential).await;
        let agent_id = better_iam_server::utils::id();
        f.insert(
            "identities",
            json!({
                "id": agent_id,
                "tenantId": f.tenant_id,
                "kind": "agent",
                "agent": { "sponsorId": f.owner_id },
                "name": "Helper",
                "status": "active",
                "emailVerified": false,
                "rootAdmin": false,
                "owner": false,
                "createdAt": num(f.now()),
            }),
        )
        .await;
        let agent = f.identity(&agent_id).await;
        let scheme = within(&f, |tx, tenant_id| async move {
            scheme_for_tenant(&tx, &tenant_id).await
        })
        .await
        .unwrap();
        let target = json!({ "id": f.tenant_id });
        let parties = |principal: AuthenticatedPrincipal, root: bool| {
            let scheme = scheme.clone();
            let target = target.clone();
            let now = f.now();
            move |tx: better_iam_server::context::Store, _: String| async move {
                let states =
                    session_parties(&tx, &principal, &target, None, &scheme, now, root).await?;
                Ok(states
                    .iter()
                    .map(|state| (state.party.identity_id.clone(), state.party.rank))
                    .collect::<Vec<_>>())
            }
        };
        // A person in their own tenant.
        assert_eq!(
            within(&f, parties(principal.clone(), false)).await,
            vec![(alice.id.clone(), 3.0)]
        );
        // An agent's key: the agent and its sponsor.
        let mut key = principal.clone();
        key.identity = agent.clone();
        key.session.kind = SessionKind::ApiKey;
        key.session.identity_id = agent_id.clone();
        assert_eq!(
            within(&f, parties(key.clone(), false)).await,
            vec![(agent_id.clone(), -1.0), (f.owner_id.clone(), -1.0)]
        );
        f.clear(&agent_id, "S", json!({})).await;
        f.clear(&f.owner_id, "C", json!({})).await;
        assert_eq!(
            within(&f, parties(key.clone(), false)).await,
            vec![(agent_id.clone(), 2.0), (f.owner_id.clone(), 1.0)]
        );
        let mut unsponsored = key.clone();
        unsponsored.identity.agent = None;
        assert_eq!(
            within(&f, parties(unsponsored, false)).await,
            vec![
                (agent_id.clone(), 2.0),
                (format!("{agent_id}#sponsor"), -1.0)
            ]
        );
        // A delegated session: the person and the acting agent.
        let mut delegated = principal.clone();
        delegated.session.kind = SessionKind::Delegated;
        delegated.session.agent_id = Some(agent_id.clone());
        assert_eq!(
            within(&f, parties(delegated.clone(), false)).await,
            vec![(alice.id.clone(), 3.0), (agent_id.clone(), 2.0)]
        );
        delegated.session.agent_id = None;
        assert_eq!(
            within(&f, parties(delegated, false)).await,
            vec![
                (alice.id.clone(), 3.0),
                (format!("{}#agent", alice.id), -1.0)
            ]
        );
        // A role session: nobody cleared.
        let mut role = principal.clone();
        role.session.kind = SessionKind::Role;
        assert_eq!(
            within(&f, parties(role, false)).await,
            vec![(alice.id.clone(), -1.0)]
        );
        // Another tenant's session is uncleared.
        let mut elsewhere = principal.clone();
        elsewhere.session.tenant_id = f.root_tenant_id.clone();
        assert_eq!(
            within(&f, parties(elsewhere, false)).await,
            vec![(alice.id.clone(), -1.0)]
        );
        // Root: its own record, when issued under the target's scheme, whatever tenant it lives in.
        let mut root = principal.clone();
        root.identity = f.identity(&f.root_id).await;
        root.session.tenant_id = f.root_tenant_id.clone();
        assert_eq!(
            within(&f, parties(root.clone(), true)).await,
            vec![(f.root_id.clone(), -1.0)]
        );
        let root_tenant = f.root_tenant_id.clone();
        let tenant_id = f.tenant_id.clone();
        let root_id = f.root_id.clone();
        f.clear_in(&root_tenant, &root_id, &tenant_id, "TS", json!({}))
            .await;
        assert_eq!(
            within(&f, parties(root.clone(), true)).await,
            vec![(f.root_id.clone(), 3.0)]
        );
        f.clear_in(&root_tenant, &root_id, "elsewhere", "TS", json!({}))
            .await;
        assert_eq!(
            within(&f, parties(root, true)).await,
            vec![(f.root_id.clone(), -1.0)]
        );
    });
}

#[test]
fn binds_root_unless_applies_to_root_is_false() {
    run(|| async {
        for applies in [None, Some(false)] {
            let f = fixture(Settings {
                clearances: Some(ClearanceOptions {
                    applies_to_root: applies,
                }),
            })
            .await;
            f.define_scheme(&f.tenant_id, json!({})).await;
            f.label("document", "d1", json!({ "level": "U" }), false)
                .await;
            let alice = f.person("alice").await;
            let mut root = f.principal(&alice.credential).await;
            root.identity = f.identity(&f.root_id).await;
            root.session.tenant_id = f.root_tenant_id.clone();
            let ctx = f.iam.ctx.clone();
            let now = f.now();
            let checks = within(&f, move |tx, tenant_id| async move {
                let tenant: Tenant =
                    better_iam_server::port::decode(tx.get("tenants", &tenant_id).await?.unwrap())?;
                let chain = ctx.ancestry(&tx, &tenant).await?;
                let scope =
                    clearance_scope(&ctx, &tx, &root, &tenant, &chain, None, now, Some(true))
                        .await?;
                let Some(scope) = scope else {
                    return Ok(None);
                };
                let resource = attach_label(
                    &ctx,
                    &tx,
                    &tenant_id,
                    &ResolvedResource {
                        tenant_id: tenant_id.clone(),
                        kind: "document".into(),
                        id: "d1".into(),
                        attributes: None,
                        classification: None,
                    },
                    None,
                )
                .await?;
                Ok(Some((
                    scope
                        .check(&resource, "documents:read")
                        .map(|decision| decision.reason),
                    scope.check(&resource, "iam:resources:read").is_none(),
                )))
            })
            .await;
            match applies {
                None => assert_eq!(checks, Some((Some("CLEARANCE_REQUIRED".to_owned()), true))),
                Some(_) => assert_eq!(checks, None),
            }
        }
    });
}

#[test]
fn clears_on_someones_behalf_with_cleared_for() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        let alice = f.person("alice").await;
        let principal = f.principal(&alice.credential).await;
        let ctx = f.iam.ctx.clone();
        let check = |principal: AuthenticatedPrincipal, action: &'static str| {
            let ctx = ctx.clone();
            move |tx: better_iam_server::context::Store, tenant_id: String| async move {
                let tenant: Tenant =
                    better_iam_server::port::decode(tx.get("tenants", &tenant_id).await?.unwrap())?;
                let resource = ResolvedResource {
                    tenant_id: tenant_id.clone(),
                    kind: "document".into(),
                    id: "d1".into(),
                    attributes: None,
                    classification: None,
                };
                cleared_for(&ctx, &tx, &principal, &tenant, &resource, action).await
            }
        };
        // No scheme: nothing to enforce.
        assert!(within(&f, check(principal.clone(), "documents:read")).await);
        f.define_scheme(&f.tenant_id, json!({})).await;
        f.label("document", "d1", json!({ "level": "S" }), false)
            .await;
        assert!(!within(&f, check(principal.clone(), "documents:read")).await);
        assert!(within(&f, check(principal.clone(), "iam:resources:read")).await);
        f.clear(&alice.id, "S", json!({})).await;
        assert!(within(&f, check(principal, "documents:read")).await);
    });
}

// --- labels outlive what they were inherited through -----------------------------------------------

#[test]
fn keeps_what_a_registration_inherited_when_it_is_deleted_and_registered_again() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let adam = f.person("adam").await;
        f.register("folder", "vault", None).await;
        f.register("file", "a", Some("vault")).await;
        f.label("folder", "vault", json!({ "level": "TS" }), true)
            .await;
        assert!(!f.can(&adam.credential, "files:read", "file", "a").await);
        f.register("folder", "open", None).await;
        ok(f.iam
            .api
            .resources
            .delete(
                &adam.credential,
                body(json!({ "tenantId": f.tenant_id, "type": "file", "id": "a" })),
            )
            .await);
        f.register("file", "a", Some("open")).await;
        assert!(!f.can(&adam.credential, "files:read", "file", "a").await);
        assert!(
            f.listed(&adam.credential, "files:read", "file")
                .await
                .is_empty()
        );
        let kept = f
            .find(
                "resourceLabels",
                &[
                    ("tenantId", json!(f.tenant_id)),
                    ("uniqueKey", json!("file/a")),
                ],
            )
            .await;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0]["label"], json!({ "level": "TS" }));
        assert_eq!(kept[0]["inheritToChildren"], json!(false));
        assert_eq!(kept[0]["schemeTenantId"], json!(f.tenant_id));
        assert_eq!(kept[0]["labeledBy"], json!(adam.id));
        assert_eq!(kept[0]["version"], json!(1));
        let events = f.audit("classification:label").await;
        let event = events
            .iter()
            .find(|event| event["metadata"]["reason"] == json!("resource-deleted"))
            .expect("the kept label is audited");
        assert_eq!(event["actorId"], json!(adam.id));
        assert_eq!(event["resourceId"], json!("file/a"));
        assert_eq!(
            event["metadata"],
            json!({ "type": "file", "level": "TS", "inheritToChildren": false, "reason": "resource-deleted" })
        );
        // Deleting again joins into the own label it now has; nothing changes while it covers what it inherits.
        f.label(
            "folder",
            "open",
            json!({ "level": "S", "compartments": ["HCS"] }),
            true,
        )
        .await;
        ok(f.iam
            .api
            .resources
            .delete(
                &adam.credential,
                body(json!({ "tenantId": f.tenant_id, "type": "file", "id": "a" })),
            )
            .await);
        let kept = f
            .find(
                "resourceLabels",
                &[
                    ("tenantId", json!(f.tenant_id)),
                    ("uniqueKey", json!("file/a")),
                ],
            )
            .await;
        assert_eq!(
            kept[0]["label"],
            json!({ "level": "TS", "compartments": ["HCS"] })
        );
        assert_eq!(kept[0]["version"], json!(2));
        let events = f.audit("classification:label").await;
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .any(|event| event["metadata"]["previousLevel"] == json!("TS")
                    && event["metadata"]["compartments"] == json!(["HCS"]))
        );
        // What it inherits must be readable under the scheme in force before it can go.
        f.register("folder", "stale", None).await;
        let tenant_id = f.tenant_id.clone();
        f.store_label(
            &tenant_id,
            "folder",
            "stale",
            json!({ "level": "U" }),
            "another-scheme",
            true,
        )
        .await;
        f.register("file", "b", Some("stale")).await;
        let error = err(f
            .iam
            .api
            .resources
            .delete(
                &adam.credential,
                body(json!({ "tenantId": f.tenant_id, "type": "file", "id": "b" })),
            )
            .await);
        assert_eq!(error.code, "RESOURCE_IN_USE");
        assert_eq!(error.status, 409);
    });
}

// --- a tenant and the scheme its labels were written under -----------------------------------------

#[test]
fn refuses_moving_a_tenant_out_from_under_its_scheme_while_it_holds_labels_or_clearances() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let globex = f
            .tenant_below("Globex", "organization", &f.root_tenant_id)
            .await;
        let apollo = f.tenant_below("Apollo", "project", &f.tenant_id).await;
        let gemini = f.tenant_below("Gemini", "project", &f.tenant_id).await;
        let tenant_id = f.tenant_id.clone();
        let ctx = f.iam.ctx.clone();
        let mover = |moved: String, parent: String| {
            let ctx = ctx.clone();
            move |tx: better_iam_server::context::Store, _: String| async move {
                let tenant: Tenant =
                    better_iam_server::port::decode(tx.get("tenants", &moved).await?.unwrap())?;
                let parent: Tenant =
                    better_iam_server::port::decode(tx.get("tenants", &parent).await?.unwrap())?;
                Ok(
                    clearances::assert_scheme_kept(&ctx, &tx, &tenant, &parent, &json!([moved]))
                        .await,
                )
            }
        };
        // Nothing labeled or cleared moves freely.
        assert!(
            within(&f, mover(apollo.clone(), globex.clone()))
                .await
                .is_ok()
        );
        f.store_label(
            &apollo,
            "document",
            "q3",
            json!({ "level": "TS" }),
            &tenant_id,
            false,
        )
        .await;
        let error = within(&f, mover(apollo.clone(), globex.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code, "RESOURCE_IN_USE");
        assert_eq!(error.status, 409);
        // Moving within the scheme's subtree keeps the scheme in force.
        assert!(
            within(&f, mover(apollo.clone(), gemini.clone()))
                .await
                .is_ok()
        );
        // A live clearance holds a project in place too, until it ends.
        let pat = better_iam_server::utils::id();
        f.clear_in(&gemini, &pat, &tenant_id, "C", json!({})).await;
        let error = within(&f, mover(gemini.clone(), globex.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code, "RESOURCE_IN_USE");
        f.clear_in(
            &gemini,
            &pat,
            &tenant_id,
            "C",
            json!({ "status": "suspended" }),
        )
        .await;
        assert!(
            within(&f, mover(gemini.clone(), globex.clone()))
                .await
                .is_err()
        );
        f.clear_in(
            &gemini,
            &pat,
            &tenant_id,
            "C",
            json!({ "status": "revoked" }),
        )
        .await;
        assert!(
            within(&f, mover(gemini.clone(), globex.clone()))
                .await
                .is_ok()
        );
    });
}

#[test]
fn moves_labeled_tenants_freely_while_the_scheme_in_force_stays_the_same() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        let root_tenant = f.root_tenant_id.clone();
        f.define_scheme(&root_tenant, json!({ "name": "Platform" }))
            .await;
        let globex = f.tenant_below("Globex", "organization", &root_tenant).await;
        let apollo = f.tenant_below("Apollo", "project", &f.tenant_id).await;
        f.store_label(
            &apollo,
            "document",
            "q3",
            json!({ "level": "TS" }),
            &root_tenant,
            false,
        )
        .await;
        let ctx = f.iam.ctx.clone();
        let result = within(&f, move |tx, _| async move {
            let tenant: Tenant =
                better_iam_server::port::decode(tx.get("tenants", &apollo).await?.unwrap())?;
            let parent: Tenant =
                better_iam_server::port::decode(tx.get("tenants", &globex).await?.unwrap())?;
            Ok(clearances::assert_scheme_kept(&ctx, &tx, &tenant, &parent, &json!([apollo])).await)
        })
        .await;
        assert!(result.is_ok());
        // The organization inherits the platform's scheme.
        let scheme = within(&f, |tx, tenant_id| async move {
            scheme_for_tenant(&tx, &tenant_id).await
        })
        .await
        .unwrap();
        assert_eq!(scheme.tenant_id, f.root_tenant_id);
        assert_eq!(scheme.name, "Platform");
    });
}

// --- clearances across the identity lifecycle ------------------------------------------------------

#[test]
fn terminates_the_clearance_on_offboarding_and_debriefs_every_compartment() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        let at = num(f.now());
        f.clear(
            &alice.id,
            "S",
            json!({
                "status": "suspended",
                "suspended": { "by": "officer", "at": at, "reason": "x", "previousStatus": "active" },
                "readIns": [
                    { "compartmentId": "GAMMA", "readInAt": at, "readInBy": f.owner_id },
                    { "compartmentId": "HCS", "readInAt": at, "readInBy": f.owner_id },
                ],
            }),
        )
        .await;
        let owner = f.principal(&f.owner).await;
        let identity = f.identity(&alice.id).await;
        let ctx = f.iam.ctx.clone();
        let reason = "x".repeat(600);
        let terminated = within(&f, {
            let owner = owner.clone();
            let identity = identity.clone();
            let ctx = ctx.clone();
            move |tx, _| async move {
                terminate_clearances_of(&ctx, &tx, &owner, &identity, &reason).await
            }
        })
        .await;
        assert_eq!(terminated, 1.0);
        let record = f.get("clearances", &alice.id).await.unwrap();
        assert_eq!(record["status"], json!("terminated"));
        assert_eq!(record["readIns"], json!([]));
        assert!(record.get("suspended").is_none());
        assert_eq!(record["terminated"]["by"], json!(f.owner_id));
        assert_eq!(record["terminated"]["at"], num(f.now()));
        assert_eq!(record["terminated"]["reason"].as_str().unwrap().len(), 512);
        assert_eq!(record["updatedBy"], json!(f.owner_id));
        let debriefs = f.audit("clearance:debrief").await;
        assert_eq!(debriefs.len(), 2);
        let mut debriefed: Vec<String> = debriefs
            .iter()
            .map(|event| {
                event["metadata"]["compartmentId"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        debriefed.sort();
        assert_eq!(debriefed, vec!["GAMMA", "HCS"]);
        assert!(
            debriefs
                .iter()
                .all(|event| event["resourceId"] == json!(alice.id)
                    && event["metadata"]["reason"] == json!("terminated"))
        );
        let ends = f.audit("clearance:terminate").await;
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0]["metadata"]["level"], json!("S"));
        assert_eq!(ends[0]["metadata"]["previousStatus"], json!("suspended"));
        // One that already ended is left as it is.
        f.clear(
            &alice.id,
            "S",
            json!({ "status": "revoked", "revoked": { "by": "o", "at": at, "reason": "cause" } }),
        )
        .await;
        let again = within(&f, {
            let owner = owner.clone();
            let identity = identity.clone();
            let ctx = ctx.clone();
            move |tx, _| async move {
                terminate_clearances_of(&ctx, &tx, &owner, &identity, "leaving").await
            }
        })
        .await;
        assert_eq!(again, 0.0);
        assert_eq!(
            f.get("clearances", &alice.id).await.unwrap()["status"],
            json!("revoked")
        );
        // Nobody without a record.
        let bob = f.person("bob").await;
        let bob_identity = f.identity(&bob.id).await;
        let none = within(&f, move |tx, _| async move {
            terminate_clearances_of(&ctx, &tx, &owner, &bob_identity, "leaving").await
        })
        .await;
        assert_eq!(none, 0.0);
    });
}

#[test]
fn keeps_the_clearance_as_terminated_history_when_the_identity_is_deleted() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        let at = num(f.now());
        f.clear(
            &alice.id,
            "S",
            json!({ "readIns": [{ "compartmentId": "GAMMA", "readInAt": at, "readInBy": f.owner_id }] }),
        )
        .await;
        let identity = f.identity(&alice.id).await;
        let now = f.now() + 5.0;
        within(&f, {
            let identity = identity.clone();
            move |tx, _| async move { release_clearances_of(&tx, &identity, Some(now), None).await }
        })
        .await;
        let record = f.get("clearances", &alice.id).await.unwrap();
        assert_eq!(record["status"], json!("terminated"));
        assert_eq!(record["readIns"], json!([]));
        assert_eq!(
            record["terminated"],
            json!({ "by": "identity-deleted", "at": num(now), "reason": "identity deleted" })
        );
        assert_eq!(record["updatedBy"], json!("identity-deleted"));
        // A revocation stays one and only loses read-ins left.
        f.clear(
            &alice.id,
            "S",
            json!({
                "status": "revoked",
                "revoked": { "by": "o", "at": at, "reason": "cause" },
                "readIns": [{ "compartmentId": "GAMMA", "readInAt": at, "readInBy": f.owner_id }],
            }),
        )
        .await;
        within(&f, {
            let identity = identity.clone();
            move |tx, _| async move {
                release_clearances_of(&tx, &identity, Some(now), Some("admin")).await
            }
        })
        .await;
        let record = f.get("clearances", &alice.id).await.unwrap();
        assert_eq!(record["status"], json!("revoked"));
        assert_eq!(record["readIns"], json!([]));
        assert!(record.get("terminated").is_none());
        assert_eq!(record["updatedBy"], json!("admin"));
        // Nothing left to release: untouched.
        let before = f.get("clearances", &alice.id).await.unwrap();
        within(&f, move |tx, _| async move {
            release_clearances_of(&tx, &identity, Some(now + 1.0), None).await
        })
        .await;
        assert_eq!(f.get("clearances", &alice.id).await.unwrap(), before);
    });
}

#[test]
fn reads_a_clearance_only_in_the_identitys_own_tenant() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        f.clear(&alice.id, "S", json!({})).await;
        let read = |identity: Value| {
            move |tx: better_iam_server::context::Store, _: String| async move {
                read_clearance(&tx, &identity).await
            }
        };
        let found = within(&f, read(json!({ "id": alice.id, "tenantId": f.tenant_id }))).await;
        assert_eq!(found.unwrap().level, "S");
        let elsewhere = within(
            &f,
            read(json!({ "id": alice.id, "tenantId": f.root_tenant_id })),
        )
        .await;
        assert!(elsewhere.is_none());
    });
}

#[test]
fn leaves_clearance_records_alone_without_the_option() {
    run(|| async {
        let f = fixture(Settings { clearances: None }).await;
        f.define_scheme(&f.tenant_id, json!({})).await;
        let alice = f.person("alice").await;
        f.clear(&alice.id, "U", json!({})).await;
        f.label("document", "d1", json!({ "level": "TS" }), false)
            .await;
        // Decisions are exactly as before.
        assert!(f.reads(&alice.credential, "d1").await);
        let plan = f
            .plan(&alice.credential, "documents:read", "document")
            .await
            .unwrap();
        assert_eq!(plan["kind"], json!("always"));
        let owner = f.principal(&f.owner).await;
        let identity = f.identity(&alice.id).await;
        let ctx = f.iam.ctx.clone();
        let terminated = within(&f, move |tx, _| async move {
            terminate_clearances_of(&ctx, &tx, &owner, &identity, "leaving").await
        })
        .await;
        assert_eq!(terminated, 0.0);
        assert_eq!(
            f.get("clearances", &alice.id).await.unwrap()["status"],
            json!("active")
        );
        let error = clearances::assert_clearances(&f.iam.ctx).unwrap_err();
        assert_eq!(error.code, "FEATURE_DISABLED");
        assert_eq!(error.status, 403);
    });
}

#[test]
fn tells_the_person_about_suspension_naming_the_level_only() {
    run(|| async {
        let f = fixture(Settings::default()).await;
        let scheme_record = f.define_scheme(&f.tenant_id, json!({})).await;
        let scheme: ClassificationScheme = serde_json::from_value(scheme_record).unwrap();
        let alice = f.person("alice").await;
        f.deliveries().await;
        let identity = f.identity(&alice.id).await;
        let ctx = f.iam.ctx.clone();
        within(&f, {
            let identity = identity.clone();
            let ctx = ctx.clone();
            let scheme = scheme.clone();
            move |tx, _| async move {
                clearances::notify_clearance_status(
                    &ctx,
                    &tx,
                    &identity,
                    Some(&scheme),
                    &json!({ "level": "TS" }),
                    "suspended",
                )
                .await
            }
        })
        .await;
        let messages = f.deliveries().await;
        assert_eq!(messages.len(), 1);
        let message = serde_json::to_value(&messages[0]).unwrap();
        assert_eq!(message["to"], json!("alice@acme.test"));
        assert_eq!(message["template"], json!("clearance-status"));
        assert_eq!(
            message["payload"],
            json!({ "tenantId": f.tenant_id, "tenantName": "Acme", "status": "suspended", "levelName": "TOP SECRET" })
        );
        // Agents and service accounts get nothing.
        let mut agent = identity.clone();
        agent.kind = better_iam_core::IdentityKind::Agent;
        within(&f, move |tx, _| async move {
            clearances::notify_clearance_status(
                &ctx,
                &tx,
                &agent,
                None,
                &json!({ "level": "TS" }),
                "revoked",
            )
            .await
        })
        .await;
        assert!(f.deliveries().await.is_empty());
    });
}

// --- pure helpers ----------------------------------------------------------------------------------

#[test]
fn keys_labels_by_type_and_id_hashing_long_ones() {
    assert_eq!(label_key("document", "d1").unwrap(), "document/d1");
    let long = "x".repeat(600);
    let key = label_key("document", &long).unwrap();
    assert_eq!(
        key,
        format!(
            "sha256:{}",
            better_iam_server::utils::hash(&format!("document/{long}"))
        )
    );
    // 512 UTF-8 bytes still fit.
    let fits = format!("{}x", "é".repeat(251));
    assert_eq!(
        label_key("document", &fits).unwrap(),
        format!("document/{fits}")
    );
    assert!(
        label_key("document", &"é".repeat(252))
            .unwrap()
            .starts_with("sha256:")
    );
}

fn resource(kind: &str, id: &str, classification: Option<Value>) -> ResolvedResource {
    ResolvedResource {
        tenant_id: "t".into(),
        kind: kind.into(),
        id: id.into(),
        attributes: None,
        classification,
    }
}

#[test]
fn applies_labels_failing_closed_on_what_was_never_looked_up() {
    let scheme = json!({ "requireLabels": ["document"] });
    // Never looked up: refused.
    assert_eq!(
        applicable_label(&scheme, &resource("report", "r", None)).unwrap(),
        Some(json!(false))
    );
    // Looked up and unlabeled: refused only where a label is required, unless a default applies.
    assert_eq!(
        applicable_label(&scheme, &resource("report", "r", Some(Value::Null))).unwrap(),
        None
    );
    assert_eq!(
        applicable_label(&scheme, &resource("document", "d", Some(Value::Null))).unwrap(),
        Some(json!(false))
    );
    let defaulted = json!({ "requireLabels": ["*"], "defaultLabel": { "level": "C" } });
    assert_eq!(
        applicable_label(&defaulted, &resource("document", "d", Some(Value::Null))).unwrap(),
        Some(json!({ "level": "C" }))
    );
    // `*` covers application types, not the built-in modules' own.
    assert_eq!(
        applicable_label(&defaulted, &resource("model", "m", Some(Value::Null))).unwrap(),
        None
    );
    // A label is returned as it is; what is not an object refuses.
    assert_eq!(
        applicable_label(
            &scheme,
            &resource("report", "r", Some(json!({ "level": "S" })))
        )
        .unwrap(),
        Some(json!({ "level": "S" }))
    );
    assert_eq!(
        applicable_label(&scheme, &resource("report", "r", Some(json!("S")))).unwrap(),
        Some(json!(false))
    );
    assert_eq!(
        applicable_label(&scheme, &resource("report", "r", Some(json!(["S"])))).unwrap(),
        Some(json!(false))
    );
    // Platform resources carry a label only as `iam/{type}/{id}`.
    assert_eq!(
        applicable_label(&scheme, &resource("iam", "document/d", None)).unwrap(),
        None
    );
    assert_eq!(
        applicable_label(&scheme, &resource("iam", "document/d", Some(Value::Null))).unwrap(),
        Some(json!(false))
    );
    assert_eq!(
        applicable_label(&scheme, &resource("iam", "report/r", Some(Value::Null))).unwrap(),
        None
    );
    assert_eq!(
        applicable_label(
            &scheme,
            &resource("iam", "report/r", Some(json!({ "level": "U" })))
        )
        .unwrap(),
        Some(json!({ "level": "U" }))
    );
    assert_eq!(
        applicable_label(&scheme, &resource("role", "r1", Some(Value::Null))).unwrap(),
        None
    );
}

fn party(rank: f64, compartments: &[&str], citizenship: &[&str]) -> ClearanceParty {
    ClearanceParty {
        identity_id: "p".into(),
        rank,
        compartments: compartments.iter().map(|item| (*item).to_owned()).collect(),
        citizenship: citizenship.iter().map(|item| (*item).to_owned()).collect(),
    }
}

#[test]
fn needs_every_party_to_dominate_the_label() {
    let mut definition = classification_template("us").unwrap();
    definition.compartments = vec![better_iam_core::Compartment {
        id: "GAMMA".into(),
        name: "Gamma".into(),
    }];
    let label = |value: Value| -> ClassificationLabel { serde_json::from_value(value).unwrap() };
    let secret = label(json!({ "level": "S" }));
    assert_eq!(
        parties_fail(&[], &secret, &definition).unwrap(),
        Some("level".to_owned())
    );
    assert_eq!(
        parties_fail(&[party(2.0, &[], &["USA"])], &secret, &definition).unwrap(),
        None
    );
    assert_eq!(
        parties_fail(
            &[party(3.0, &[], &["USA"]), party(1.0, &[], &["USA"])],
            &secret,
            &definition
        )
        .unwrap(),
        Some("level".to_owned())
    );
    assert_eq!(
        parties_fail(
            &[party(3.0, &[], &["USA"])],
            &label(json!({ "level": "S", "compartments": ["GAMMA"] })),
            &definition
        )
        .unwrap(),
        Some("compartment".to_owned())
    );
    assert_eq!(
        parties_fail(
            &[party(3.0, &[], &["GBR"])],
            &label(json!({ "level": "S", "noforn": true })),
            &definition
        )
        .unwrap(),
        Some("noforn".to_owned())
    );
    assert_eq!(
        parties_fail(
            &[party(3.0, &[], &["USA"])],
            &label(json!({ "level": "UNKNOWN" })),
            &definition
        )
        .unwrap(),
        Some("invalid-label".to_owned())
    );
}

#[test]
fn derives_the_clearance_keys_of_the_weakest_party() {
    let keys = clearance_keys(&[]);
    assert_eq!(
        Value::Object(keys),
        json!({
            "principal.clearanceRank": -1,
            "principal.clearanceStatus": "none",
            "principal.clearanceCompartments": [],
            "principal.clearanceCitizenship": [],
        })
    );
    let level = |id: &str, rank: f64| better_iam_core::ClassificationLevel {
        id: id.into(),
        name: id.into(),
        rank,
        abbreviation: None,
    };
    let state = |rank: f64, status: &str, compartments: &[&str], citizenship: &[&str]| {
        clearances::PartyState {
            party: party(rank, compartments, citizenship),
            status: json!(status),
            level: (rank >= 0.0).then(|| level(if rank >= 3.0 { "TS" } else { "S" }, rank)),
            record: None,
        }
    };
    let keys = clearance_keys(&[
        state(3.0, "active", &["GAMMA", "HCS"], &["USA", "GBR"]),
        state(2.0, "interim", &["HCS", "GAMMA"], &["GBR"]),
    ]);
    assert_eq!(
        Value::Object(keys),
        json!({
            "principal.clearanceRank": 2,
            "principal.clearanceLevel": "S",
            "principal.clearanceStatus": "interim",
            "principal.clearanceCompartments": ["GAMMA", "HCS"],
            "principal.clearanceCitizenship": ["GBR"],
        })
    );
    let keys = clearance_keys(&[
        state(3.0, "active", &[], &["USA"]),
        state(-1.0, "suspended", &[], &[]),
    ]);
    assert_eq!(keys["principal.clearanceRank"], json!(-1));
    assert!(keys.get("principal.clearanceLevel").is_none());
    assert_eq!(keys["principal.clearanceStatus"], json!("suspended"));
    assert_eq!(keys["principal.clearanceCitizenship"], json!([]));
}
