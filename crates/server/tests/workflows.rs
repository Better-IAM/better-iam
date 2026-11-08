//! Port of tests/workflows.test.ts: lifecycle workflows (joiner, mover, leaver and date triggers, manual runs, the
//! daily brake, `subscribe()`, validation) and the review fixes (self-changing steps, email recipients, cancelling
//! runs in progress).
//!
//! Members come from the organization fixture (written as `identities.create` writes them). Several cases need
//! modules of other units that are still stubs: every step that changes something re-checks the owner's rights with
//! api/packages.ts `allow`; scopes compile through package-rules.ts (`ruleDocument`, `parseAutoAssign`) and the org
//! rule environment through licenses.ts `licenseRuleKeys`; `identities.update` and `identities.setStatus` end in
//! api/package-automation.ts `afterIdentityChange`. Those cases are ported and ignored with the reason until the
//! modules land; every other case runs now.

mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::{AttributeType, CredentialInput, IamError, IamResult, IamStoreExt, Record};
use better_iam_server::api::Reply;
use indexmap::IndexMap;
use organization_fixture::{Org, assert_matches, body, code, ok, organization, run};
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;

struct Scenario {
    f: Org,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
    tenant_id: String,
    owner: CredentialInput,
    engineering: String,
    everyone: String,
}

fn value<O: serde::Serialize>(result: IamResult<Reply<O>>) -> IamResult<Value> {
    result.map(|reply| reply.into_value().expect("JSON result"))
}

#[track_caller]
fn rejects(result: IamResult<Value>, expected: &str) -> IamError {
    match result {
        Ok(value) => panic!("expected {expected}, got {value}"),
        Err(error) => {
            assert_eq!(code(&error), expected, "{error:?}");
            error
        }
    }
}

fn id_of(value: &Value) -> String {
    value["id"].as_str().expect("id").to_owned()
}

async fn scenario() -> Scenario {
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let sink = inbox.clone();
    let f = organization(move |options| {
        let permissions = options.permissions.as_mut().unwrap();
        let mut attributes = IndexMap::new();
        attributes.insert("department".to_owned(), AttributeType::String);
        attributes.insert("startDate".to_owned(), AttributeType::String);
        attributes.insert("title".to_owned(), AttributeType::String);
        permissions.identity_attributes = Some(attributes);
        let authentication = options.authentication.as_mut().unwrap();
        authentication.send_email = Some(delivery_fn(move |message| {
            sink.lock().unwrap().push(message);
            async { Ok(()) }
        }));
    })
    .await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let engineering = ok(f
        .iam
        .api
        .groups
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Engineering" })),
        )
        .await);
    let everyone = ok(f
        .iam
        .api
        .groups
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Everyone" })),
        )
        .await);
    Scenario {
        f,
        inbox,
        tenant_id,
        owner,
        engineering: id_of(&engineering),
        everyone: id_of(&everyone),
    }
}

impl Scenario {
    /// `{ tenantId, ...members }`.
    fn input(&self, members: Value) -> Value {
        let mut input = serde_json::Map::new();
        input.insert("tenantId".into(), json!(self.tenant_id));
        for (key, value) in members.as_object().unwrap() {
            input.insert(key.clone(), value.clone());
        }
        Value::Object(input)
    }

    async fn person(&self, name: &str, attributes: Option<Value>) -> String {
        let created = self.f.member(name).await;
        if let Some(attributes) = attributes {
            ok(self
                .f
                .iam
                .api
                .identities
                .update(
                    &self.owner,
                    body(self.input(json!({ "identityId": created, "attributes": attributes }))),
                )
                .await);
        }
        created
    }

    async fn groups_of(&self, identity_id: &str) -> Vec<String> {
        let groups = ok(self
            .f
            .iam
            .api
            .identities
            .list_groups(
                &self.owner,
                body(self.input(json!({ "identityId": identity_id }))),
            )
            .await);
        let mut names: Vec<String> = groups
            .as_array()
            .unwrap()
            .iter()
            .map(|group| group["name"].as_str().unwrap().to_owned())
            .collect();
        names.sort();
        names
    }

    async fn identity(&self, identity_id: &str) -> Record {
        let identity_id = identity_id.to_owned();
        self.f
            .iam
            .store
            .transaction(|tx| async move { tx.get("identities", &identity_id).await })
            .await
            .unwrap()
            .expect("identity")
    }

    async fn create(&self, credential: &CredentialInput, members: Value) -> IamResult<Value> {
        value(
            self.f
                .iam
                .api
                .workflows
                .create(credential, body(self.input(members)))
                .await,
        )
    }

    async fn update(&self, credential: &CredentialInput, members: Value) -> IamResult<Value> {
        value(
            self.f
                .iam
                .api
                .workflows
                .update(credential, body(self.input(members)))
                .await,
        )
    }

    async fn start(&self, credential: &CredentialInput, members: Value) -> IamResult<Value> {
        value(
            self.f
                .iam
                .api
                .workflows
                .run(credential, body(self.input(members)))
                .await,
        )
    }

    async fn list_runs(&self, credential: &CredentialInput, workflow_id: &str) -> Value {
        ok(self
            .f
            .iam
            .api
            .workflows
            .list_runs(
                credential,
                body(self.input(json!({ "workflowId": workflow_id }))),
            )
            .await)
    }

    async fn run_due(&self) -> Value {
        self.f
            .iam
            .workflows
            .run_due(Some(&json!({ "tenantId": self.tenant_id })))
            .await
            .expect("runDue")
    }

    async fn started(&self) -> f64 {
        self.run_due().await["started"].as_f64().unwrap()
    }

    async fn audit_text(&self, credential: &CredentialInput) -> String {
        let audit = ok(self
            .f
            .iam
            .api
            .audit
            .list(credential, body(self.input(json!({}))))
            .await);
        let events = if audit.is_array() {
            audit
        } else {
            audit["events"].clone()
        };
        events.to_string()
    }

    /// A fresh (recently authenticated) owner session.
    async fn owner_sign_in(&self) -> CredentialInput {
        self.f.sign_in(&self.f.owner_id).await
    }
}

#[test]
#[ignore = "steps re-check the owner's rights with api/packages.ts allow, scopes compile with package-rules.ts ruleDocument, and identities.update ends in api/package-automation.ts afterIdentityChange: other units' stubs"]
fn runs_joiner_steps_for_people_who_join_after_the_workflow_exists_within_its_scope() {
    run(|| async {
        let s = scenario().await;
        let existing = s
            .person("early", Some(json!({ "department": "Engineering" })))
            .await;
        s.f.advance(1000.0);
        let workflow = s
            .create(
                &s.owner,
                json!({
                    "name": "Engineering joiners",
                    "trigger": { "kind": "joiner" },
                    "scope": { "include": [{ "StringEquals": { "principal.department": "Engineering" } }] },
                    "steps": [
                        { "kind": "add-to-group", "groupId": s.engineering },
                        {
                            "kind": "send-email",
                            "to": "subject",
                            "subject": "Welcome to {organization}, {name}",
                            "body": "You joined {attribute.department}.",
                        },
                        { "kind": "emit-event", "name": "engineer.joined" },
                    ],
                }),
            )
            .await
            .unwrap();
        assert_matches(
            &workflow,
            json!({ "enabled": true, "version": 1, "maxRunsPerDay": 200 }),
        );
        let alice = s
            .person("alice", Some(json!({ "department": "Engineering" })))
            .await;
        let bob = s
            .person("bob", Some(json!({ "department": "Sales" })))
            .await;
        let result = s.run_due().await;
        assert_matches(
            &result,
            json!({ "started": 1, "executed": 1, "completed": 1 }),
        );
        assert_eq!(s.groups_of(&alice).await, vec!["Engineering"]);
        assert!(s.groups_of(&bob).await.is_empty());
        assert!(s.groups_of(&existing).await.is_empty());
        s.f.iam.auth.dispatch_outbox(None).await.unwrap();
        let welcome = s
            .inbox
            .lock()
            .unwrap()
            .iter()
            .find(|message| message.template == "workflow-message")
            .cloned()
            .expect("welcome");
        assert_eq!(welcome.to, "alice@acme.test");
        assert_matches(
            &Value::Object(welcome.payload),
            json!({ "subject": "Welcome to Acme, alice", "body": "You joined Engineering." }),
        );
        // Each joiner runs once.
        assert_eq!(s.started().await, 0.0);
        let runs = s.list_runs(&s.owner, &id_of(&workflow)).await;
        assert_matches(
            &runs["runs"][0],
            json!({
                "identityId": alice,
                "status": "completed",
                "results": [
                    { "kind": "add-to-group", "outcome": "done", "detail": "Engineering" },
                    { "kind": "send-email", "outcome": "done" },
                    { "kind": "emit-event", "outcome": "done" },
                ],
            }),
        );
        assert!(s.audit_text(&s.owner).await.contains("\"workflow:event\""));
    });
}

#[test]
#[ignore = "steps re-check the owner's rights with api/packages.ts allow, and identities.update / setStatus end in api/package-automation.ts afterIdentityChange: other units' stubs"]
fn fires_mover_workflows_on_watched_attribute_changes_and_leaver_workflows_on_disabling() {
    run(|| async {
        let s = scenario().await;
        let carol = s
            .person("carol", Some(json!({ "department": "Engineering" })))
            .await;
        let add = |group: String| s.input(json!({ "groupId": group, "identityId": carol }));
        ok(s.f
            .iam
            .api
            .groups
            .add_member(&s.owner, body(add(s.engineering.clone())))
            .await);
        s.create(
            &s.owner,
            json!({
                "name": "Department movers",
                "trigger": { "kind": "mover", "attributes": ["department"] },
                "steps": [{ "kind": "remove-from-group", "groupId": s.engineering }],
            }),
        )
        .await
        .unwrap();
        let leaver = s
            .create(
                &s.owner,
                json!({
                    "name": "Leavers",
                    "trigger": { "kind": "leaver" },
                    "steps": [
                        { "kind": "remove-from-all-groups" },
                        { "kind": "wait", "hours": 24 * 30 },
                        { "kind": "delete" },
                    ],
                }),
            )
            .await
            .unwrap();
        assert_eq!(leaver["maxRunsPerDay"], json!(25));
        // No change yet: the baselines were taken when the workflows were created.
        assert_eq!(s.started().await, 0.0);
        let update = |department: &str| {
            s.input(json!({ "identityId": carol, "attributes": { "department": department } }))
        };
        ok(s.f
            .iam
            .api
            .identities
            .update(&s.owner, body(update("Sales")))
            .await);
        assert_eq!(s.started().await, 1.0);
        assert!(s.groups_of(&carol).await.is_empty());
        // Moving back fires again.
        ok(s.f
            .iam
            .api
            .groups
            .add_member(&s.owner, body(add(s.engineering.clone())))
            .await);
        ok(s.f
            .iam
            .api
            .groups
            .add_member(&s.owner, body(add(s.everyone.clone())))
            .await);
        ok(s.f
            .iam
            .api
            .identities
            .update(&s.owner, body(update("Engineering")))
            .await);
        assert_eq!(s.started().await, 1.0);
        assert_eq!(s.groups_of(&carol).await, vec!["Everyone"]);

        // Leaving: groups go now, the account is deleted after the wait.
        let owner = s.owner_sign_in().await;
        ok(s.f
            .iam
            .api
            .identities
            .set_status(
                &owner,
                body(s.input(json!({ "identityId": carol, "status": "disabled" }))),
            )
            .await);
        let first = s.run_due().await;
        assert_matches(&first, json!({ "started": 1, "waiting": 1 }));
        assert!(s.groups_of(&carol).await.is_empty());
        assert_eq!(s.identity(&carol).await["status"], json!("disabled"));
        s.f.advance(31.0 * DAY);
        let later = s.run_due().await;
        assert_matches(&later, json!({ "started": 0, "completed": 1 }));
        assert_eq!(s.identity(&carol).await["status"], json!("deleted"));
    });
}

#[test]
#[ignore = "identities.update ends in api/package-automation.ts afterIdentityChange, and the add-to-group step re-checks the owner's rights with api/packages.ts allow: other units' stubs"]
fn runs_date_workflows_relative_to_a_date_attribute() {
    run(|| async {
        let s = scenario().await;
        let start: String = better_iam_core::js::iso_string(s.f.now() + 10.0 * DAY)
            .unwrap()
            .chars()
            .take(10)
            .collect();
        let dave = s.person("dave", Some(json!({ "startDate": start }))).await;
        s.create(
            &s.owner,
            json!({
                "name": "Before the first day",
                "trigger": { "kind": "date", "attribute": "startDate", "offsetDays": -7 },
                "steps": [{ "kind": "add-to-group", "groupId": s.everyone, "days": 30 }],
            }),
        )
        .await
        .unwrap();
        let listed = ok(s
            .f
            .iam
            .api
            .workflows
            .list(&s.owner, body(s.input(json!({}))))
            .await);
        let preview = ok(s
            .f
            .iam
            .api
            .workflows
            .preview(
                &s.owner,
                body(s.input(json!({ "workflowId": id_of(&listed[0]) }))),
            )
            .await);
        let upcoming: Vec<&Value> = preview["upcoming"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| &item["id"])
            .collect();
        assert_eq!(upcoming, vec![&json!(dave)]);
        assert_eq!(preview["wouldStart"], json!([]));
        assert_eq!(s.started().await, 0.0);
        s.f.advance(4.0 * DAY);
        assert_eq!(s.started().await, 1.0);
        assert_eq!(s.groups_of(&dave).await, vec!["Everyone"]);
        assert_eq!(s.started().await, 0.0);
    });
}

#[test]
#[ignore = "the add-to-group step re-checks the owner's rights with api/packages.ts allow: another unit's stub"]
fn refuses_to_save_steps_the_caller_could_not_do_by_hand_and_fails_runs_when_the_owner_loses_rights()
 {
    run(|| async {
        let s = scenario().await;
        let manager = s.person("manager", None).await;
        let role = ok(s
            .f
            .iam
            .api
            .roles
            .create(
                &s.owner,
                body(s.input(json!({
                    "name": "Workflow author",
                    "document": {
                        "version": 1,
                        "statements": [
                            { "effect": "allow", "actions": ["iam:workflows:*"], "resources": ["*"] },
                            {
                                "effect": "allow",
                                "actions": ["iam:groups:update"],
                                "resources": [format!("iam/{}", s.everyone)],
                            },
                        ],
                    },
                }))),
            )
            .await);
        let binding = ok(s
            .f
            .iam
            .api
            .bindings
            .create(
                &s.owner,
                body(s.input(json!({
                    "roleId": id_of(&role),
                    "subjectType": "identity",
                    "subjectId": manager,
                }))),
            )
            .await);
        let token = s.f.sign_in(&manager).await;
        rejects(
            s.create(
                &token,
                json!({
                    "name": "Too much",
                    "trigger": { "kind": "joiner" },
                    "steps": [{ "kind": "add-to-group", "groupId": s.engineering }],
                }),
            )
            .await,
            "ACCESS_DENIED",
        );
        let workflow = s
            .create(
                &token,
                json!({
                    "name": "Everyone",
                    "trigger": { "kind": "manual" },
                    "steps": [{ "kind": "add-to-group", "groupId": s.everyone }],
                }),
            )
            .await
            .unwrap();
        let erin = s.person("erin", None).await;
        let done = s
            .start(
                &token,
                json!({ "workflowId": id_of(&workflow), "identityIds": [erin] }),
            )
            .await
            .unwrap();
        assert_matches(&done[0], json!({ "status": "completed" }));
        // The author loses the right: the owner's next run fails at the step, and retrying needs the right back.
        ok(s.f
            .iam
            .api
            .bindings
            .delete(
                &s.owner,
                body(s.input(json!({ "bindingId": id_of(&binding) }))),
            )
            .await);
        let frank = s.person("frank", None).await;
        let owner = s.owner_sign_in().await;
        let failed = s
            .start(
                &owner,
                json!({ "workflowId": id_of(&workflow), "identityIds": [frank] }),
            )
            .await
            .unwrap();
        assert_matches(
            &failed[0],
            json!({ "status": "failed", "error": { "code": "ACCESS_DENIED" } }),
        );
        // Saving it again makes the owner the one with the rights.
        s.update(
            &owner,
            json!({ "workflowId": id_of(&workflow), "name": "Everyone" }),
        )
        .await
        .unwrap();
        let retried = ok(s
            .f
            .iam
            .api
            .workflows
            .retry_run(&owner, body(s.input(json!({ "runId": id_of(&failed[0]) }))))
            .await);
        assert_eq!(retried["status"], json!("completed"));
        assert_eq!(s.groups_of(&frank).await, vec!["Everyone"]);
    });
}

#[test]
fn never_strips_owners_and_stops_at_the_daily_brake() {
    run(|| async {
        let s = scenario().await;
        let workflow = s
            .create(
                &s.owner,
                json!({
                    "name": "Disable",
                    "trigger": { "kind": "manual" },
                    "steps": [{ "kind": "disable" }],
                }),
            )
            .await
            .unwrap();
        let owner = s.owner_sign_in().await;
        let other = s.person("gina", None).await;
        ok(s.f
            .iam
            .api
            .identities
            .set_owner(
                &owner,
                body(s.input(json!({ "identityId": other, "owner": true }))),
            )
            .await);
        let runs = s
            .start(
                &owner,
                json!({ "workflowId": id_of(&workflow), "identityIds": [other] }),
            )
            .await
            .unwrap();
        assert_matches(
            &runs[0],
            json!({ "status": "failed", "error": { "code": "PROTECTED_RESOURCE" } }),
        );

        let brake = s
            .create(
                &s.owner,
                json!({
                    "name": "Tag everyone",
                    "trigger": { "kind": "joiner" },
                    "includeExisting": true,
                    "maxRunsPerDay": 2,
                    "steps": [{ "kind": "add-to-group", "groupId": s.everyone }],
                }),
            )
            .await
            .unwrap();
        for name in ["h1", "h2", "h3"] {
            s.person(name, None).await;
        }
        // Five people qualify: two start today, the rest wait for tomorrow (or a higher limit).
        assert_eq!(s.started().await, 2.0);
        assert_eq!(s.started().await, 0.0);
        assert!(s.audit_text(&owner).await.contains("workflow:brake"));
        let raised = s
            .update(
                &owner,
                json!({ "workflowId": id_of(&brake), "maxRunsPerDay": 50 }),
            )
            .await
            .unwrap();
        assert!(raised.get("brakedOn").is_none());
        assert_eq!(s.started().await, 3.0);
    });
}

#[test]
#[ignore = "the add-to-group step re-checks the owner's rights with api/packages.ts allow: another unit's stub"]
fn reacts_to_changes_through_subscribe_when_audit_hooks_are_dispatched() {
    run(|| async {
        let s = scenario().await;
        s.create(
            &s.owner,
            json!({
                "name": "Welcome",
                "trigger": { "kind": "joiner" },
                "steps": [{ "kind": "add-to-group", "groupId": s.everyone }],
            }),
        )
        .await
        .unwrap();
        let stop = s.f.iam.workflows.subscribe().unwrap();
        let ivan = s.person("ivan", None).await;
        s.f.iam.dispatch_audit_hooks().await.unwrap();
        s.f.iam.workflows.idle().await.unwrap();
        let groups = s.groups_of(&ivan).await;
        stop(Vec::new()).await.unwrap();
        assert_eq!(groups, vec!["Everyone"]);
    });
}

/// `workflows.create` with a valid definition overridden by `members`.
async fn attempt(s: &Scenario, members: Value) -> IamResult<Value> {
    let mut input = json!({
        "name": "Bad",
        "trigger": { "kind": "joiner" },
        "steps": [{ "kind": "emit-event", "name": "x" }],
    });
    for (key, value) in members.as_object().unwrap() {
        input[key] = value.clone();
    }
    s.create(&s.owner, input).await
}

#[test]
fn validates_definitions() {
    run(|| async {
        let s = scenario().await;
        rejects(
            attempt(
                &s,
                json!({ "trigger": { "kind": "mover", "attributes": ["shoeSize"] } }),
            )
            .await,
            "INVALID_INPUT",
        );
        rejects(
            attempt(
                &s,
                json!({ "trigger": { "kind": "date", "attribute": "title", "offsetDays": 400000 } }),
            )
            .await,
            "INVALID_INPUT",
        );
        rejects(
            attempt(&s, json!({ "steps": [{ "kind": "wait", "hours": 2 }] })).await,
            "INVALID_INPUT",
        );
        rejects(
            attempt(
                &s,
                json!({ "steps": [{ "kind": "delete" }, { "kind": "emit-event", "name": "after" }] }),
            )
            .await,
            "INVALID_INPUT",
        );
        rejects(
            attempt(
                &s,
                json!({ "steps": [{ "kind": "send-email", "to": "nobody", "subject": "s", "body": "b" }] }),
            )
            .await,
            "INVALID_INPUT",
        );
        rejects(
            attempt(
                &s,
                json!({ "steps": [{ "kind": "add-to-group", "groupId": "missing" }] }),
            )
            .await,
            "INVALID_INPUT",
        );
    });
}

#[test]
#[ignore = "scopes are validated with package-rules.ts parseAutoAssign against the org rule environment, which needs licenses.ts licenseRuleKeys: other units' stubs"]
fn validates_definition_scopes() {
    run(|| async {
        let s = scenario().await;
        rejects(
            attempt(
                &s,
                json!({ "scope": { "include": [{ "StringEquals": { "principal.unknown": "x" } }] } }),
            )
            .await,
            "INVALID_INPUT",
        );
    });
}

#[test]
fn refuses_workflows_that_change_the_account_of_whoever_runs_them() {
    run(|| async {
        let s = scenario().await;
        let admin = s.person("admin", None).await;
        let role = ok(s
            .f
            .iam
            .api
            .roles
            .create(
                &s.owner,
                body(s.input(json!({
                    "name": "Directory admin",
                    "document": {
                        "version": 1,
                        "statements": [{
                            "effect": "allow",
                            "actions": ["iam:workflows:*", "iam:identities:update", "iam:identities:read"],
                            "resources": ["*"],
                        }],
                    },
                }))),
            )
            .await);
        ok(s.f
            .iam
            .api
            .bindings
            .create(
                &s.owner,
                body(s.input(json!({
                    "roleId": id_of(&role),
                    "subjectType": "identity",
                    "subjectId": admin,
                }))),
            )
            .await);
        let token = s.f.sign_in(&admin).await;
        let workflow = s
            .create(
                &token,
                json!({
                    "name": "Move to finance",
                    "trigger": { "kind": "manual" },
                    "steps": [{ "kind": "set-attributes", "attributes": { "department": "Finance" } }],
                }),
            )
            .await
            .unwrap();
        rejects(
            s.start(
                &token,
                json!({ "workflowId": id_of(&workflow), "identityIds": [admin] }),
            )
            .await,
            "ACCESS_DENIED",
        );
        // Someone else may run it on the admin, but it still refuses to act on the workflow's own owner.
        let owner = s.owner_sign_in().await;
        let runs = s
            .start(
                &owner,
                json!({ "workflowId": id_of(&workflow), "identityIds": [admin] }),
            )
            .await
            .unwrap();
        assert_matches(
            &runs[0],
            json!({ "status": "failed", "error": { "code": "INVALID_INPUT" } }),
        );
        let identity = s.identity(&admin).await;
        assert!(
            identity
                .get("attributes")
                .and_then(|attributes| attributes.get("department"))
                .is_none()
        );
    });
}

#[test]
fn sends_workflow_email_only_inside_the_organization() {
    run(|| async {
        let s = scenario().await;
        s.person("hr", None).await;
        let email = |to: &str| {
            json!({
                "name": format!("Notify {to}"),
                "trigger": { "kind": "joiner" },
                "steps": [{ "kind": "send-email", "to": to, "subject": "New person", "body": "{name} {email}" }],
            })
        };
        rejects(
            s.create(&s.owner, email("collector@evil.example")).await,
            "INVALID_INPUT",
        );
        assert_eq!(
            s.create(&s.owner, email("hr@acme.test")).await.unwrap()["enabled"],
            json!(true)
        );
    });
}

#[test]
fn can_cancel_runs_in_progress_when_the_workflow_changes() {
    run(|| async {
        let s = scenario().await;
        let workflow = s
            .create(
                &s.owner,
                json!({
                    "name": "Grace period",
                    "trigger": { "kind": "manual" },
                    "steps": [{ "kind": "wait", "hours": 48 }, { "kind": "disable" }],
                }),
            )
            .await
            .unwrap();
        let jane = s.person("jane", None).await;
        let waiting = s
            .start(
                &s.owner,
                json!({ "workflowId": id_of(&workflow), "identityIds": [jane] }),
            )
            .await
            .unwrap();
        assert_eq!(waiting[0]["status"], json!("waiting"));
        s.update(
            &s.owner,
            json!({
                "workflowId": id_of(&workflow),
                "steps": [{ "kind": "emit-event", "name": "kept" }],
                "activeRuns": "cancel",
            }),
        )
        .await
        .unwrap();
        s.f.advance(3.0 * DAY);
        s.run_due().await;
        assert_eq!(s.identity(&jane).await["status"], json!("active"));
        let owner = s.owner_sign_in().await;
        let runs = s.list_runs(&owner, &id_of(&workflow)).await;
        assert_eq!(runs["runs"][0]["status"], json!("cancelled"));
    });
}

// --- the pure helpers of workflows.ts ------------------------------------------------------------------------------

mod pure {
    use better_iam_core::{AttributeType, Identity};
    use better_iam_server::workflows::{
        SubjectSnapshot, TemplateValues, TriggerWorkflow, date_target, default_brake,
        fill_template, parse_steps, parse_trigger, trigger_occurrence, utc_day,
    };
    use indexmap::IndexMap;
    use serde_json::{Map, Value, json};

    fn attributes() -> IndexMap<String, AttributeType> {
        let mut attributes = IndexMap::new();
        attributes.insert("department".to_owned(), AttributeType::String);
        attributes.insert("startDate".to_owned(), AttributeType::String);
        attributes.insert("level".to_owned(), AttributeType::Number);
        attributes
    }

    fn identity(members: Value) -> Identity {
        let mut record = json!({
            "id": "usr_1",
            "tenantId": "t1",
            "kind": "user",
            "email": "ada@acme.test",
            "name": "Ada",
            "status": "active",
            "emailVerified": true,
            "rootAdmin": false,
            "owner": false,
            "createdAt": 1_000_000,
        });
        for (key, value) in members.as_object().unwrap() {
            record[key] = value.clone();
        }
        serde_json::from_value(record).unwrap()
    }

    fn message(result: better_iam_core::IamResult<impl std::fmt::Debug>) -> String {
        result.unwrap_err().message
    }

    #[test]
    fn triggers_validate_and_normalize() {
        let attrs = attributes();
        assert_eq!(
            parse_trigger(
                Some(&json!({ "kind": "mover", "attributes": ["managerId", "department", "department"] })),
                &attrs
            )
            .unwrap(),
            json!({ "kind": "mover", "attributes": ["department", "managerId"] })
        );
        assert_eq!(
            parse_trigger(
                Some(&json!({ "kind": "date", "attribute": "startDate" })),
                &attrs
            )
            .unwrap(),
            json!({ "kind": "date", "attribute": "startDate", "offsetDays": 0 })
        );
        assert_eq!(
            message(parse_trigger(
                Some(&json!({ "kind": "date", "attribute": "level" })),
                &attrs
            )),
            "trigger.attribute must be createdAt, expiresAt, or a declared string attribute holding an ISO date"
        );
        assert_eq!(
            message(parse_trigger(
                Some(&json!({ "kind": "mover", "attributes": [] })),
                &attrs
            )),
            "trigger.attributes must name 1-20 attributes to watch"
        );
        assert_eq!(
            message(parse_trigger(Some(&json!({ "kind": "sometimes" })), &attrs)),
            "trigger.kind must be joiner, mover, leaver, date or manual"
        );
        assert_eq!(message(parse_trigger(None, &attrs)), "Expected an object");
    }

    #[test]
    fn steps_validate_in_order() {
        let attrs = attributes();
        assert_eq!(
            parse_steps(
                Some(&json!([
                    { "kind": "send-email", "to": " Manager ", "subject": "Hi", "body": "Hello" },
                    { "kind": "set-attributes", "attributes": { "level": 3, "department": null } },
                    { "kind": "set-expiry", "days": null },
                    { "kind": "revoke-packages" },
                ])),
                &attrs
            )
            .unwrap(),
            vec![
                json!({ "kind": "send-email", "to": "manager", "subject": "Hi", "body": "Hello" }),
                json!({ "kind": "set-attributes", "attributes": { "level": 3, "department": null } }),
                json!({ "kind": "set-expiry", "days": null }),
                json!({ "kind": "revoke-packages" }),
            ]
        );
        assert_eq!(
            message(parse_steps(
                Some(&json!([{ "kind": "disable", "extra": 1 }])),
                &attrs
            )),
            "steps[0]: unknown field extra"
        );
        assert_eq!(
            message(parse_steps(
                Some(&json!([{ "kind": "set-attributes", "attributes": { "level": "high" } }])),
                &attrs
            )),
            "steps[0].attributes: level must be a number (or null to clear it)"
        );
        assert_eq!(
            message(parse_steps(
                Some(&json!([{ "kind": "emit-event", "name": "Bad Name" }])),
                &attrs
            )),
            "steps[0].name uses lowercase letters, digits, dots, underscores or hyphens"
        );
        assert_eq!(
            message(parse_steps(Some(&json!([{ "kind": "teleport" }])), &attrs)),
            "steps[0].kind must be one of add-to-group, remove-from-group, remove-from-all-groups, assign-package, revoke-packages, send-email, revoke-sessions, disable, enable, set-attributes, set-expiry, delete, emit-event, wait"
        );
        let waits: Vec<Value> = (0..6)
            .map(|_| json!({ "kind": "wait", "hours": 1 }))
            .chain([json!({ "kind": "disable" })])
            .collect();
        assert_eq!(
            message(parse_steps(Some(&Value::Array(waits)), &attrs)),
            "A workflow may wait at most 5 times"
        );
        assert_eq!(
            message(parse_steps(
                Some(&json!([{ "kind": "disable" }, { "kind": "wait", "hours": 1 }])),
                &attrs
            )),
            "A workflow cannot end with a wait"
        );
        assert_eq!(
            message(parse_steps(Some(&json!([])), &attrs)),
            "steps must list 1-20 steps"
        );
    }

    #[test]
    fn brakes_dates_and_templates() {
        assert_eq!(
            default_brake(&[json!({ "kind": "emit-event", "name": "x" })]),
            200.0
        );
        assert_eq!(default_brake(&[json!({ "kind": "revoke-sessions" })]), 25.0);
        assert_eq!(utc_day(86_400_000.0 * 3.5).unwrap(), "1970-01-04");
        let person = identity(json!({ "attributes": {
            "startDate": "1970-01-11",
            "stamp": "1970-01-02T12:00:00+02:00",
            "local": "1970-01-02T12:00:00",
        } }));
        let trigger = |attribute: &str, offset: i64| json!({ "kind": "date", "attribute": attribute, "offsetDays": offset });
        assert_eq!(
            date_target(&trigger("startDate", -7), &person),
            Some(3.0 * 86_400_000.0)
        );
        assert_eq!(
            date_target(&trigger("stamp", 0), &person),
            Some(86_400_000.0 + 10.0 * 3_600_000.0)
        );
        assert_eq!(date_target(&trigger("local", 0), &person), None);
        assert_eq!(
            date_target(&trigger("createdAt", 1), &person),
            Some(1_000_000.0 + 86_400_000.0)
        );
        assert_eq!(date_target(&trigger("expiresAt", 1), &person), None);
        let filled = fill_template(
            "{name} <{email}> of {organization} ({workflow}): {attribute.startDate}{attribute.none} {unknown}",
            &TemplateValues {
                identity: &person,
                organization: "Acme",
                workflow: "Joiners",
            },
        );
        assert_eq!(
            filled,
            "Ada <ada@acme.test> of Acme (Joiners): 1970-01-11 {unknown}"
        );
    }

    #[test]
    fn mover_and_leaver_occurrences() {
        let mover = json!({ "kind": "mover", "attributes": ["department"] });
        let shape = TriggerWorkflow {
            trigger: &mover,
            active_since: 0.0,
            include_existing: false,
        };
        let person = identity(json!({ "attributes": { "department": "Sales" } }));
        let first = trigger_occurrence(&shape, &person, None, 10.0).unwrap();
        assert_eq!(first.occurrence, None);
        let baseline = first.snapshot.unwrap();
        assert_eq!(baseline.fired, 0.0);
        let same = trigger_occurrence(&shape, &person, Some(&baseline), 10.0).unwrap();
        assert_eq!(same.occurrence, None);
        assert_eq!(same.snapshot, None);
        let moved = identity(json!({ "attributes": { "department": "Engineering" } }));
        let fired = trigger_occurrence(&shape, &moved, Some(&baseline), 10.0).unwrap();
        assert!(fired.occurrence.unwrap().starts_with("mover:1:"));
        assert_eq!(fired.snapshot.unwrap().fired, 1.0);

        let leaver = json!({ "kind": "leaver" });
        let shape = TriggerWorkflow {
            trigger: &leaver,
            active_since: 0.0,
            include_existing: false,
        };
        let active = SubjectSnapshot {
            values: Map::new(),
            status: "active".into(),
            fired: 0.0,
        };
        let disabled = identity(json!({ "status": "disabled" }));
        let left = trigger_occurrence(&shape, &disabled, Some(&active), 10.0).unwrap();
        assert_eq!(left.occurrence.as_deref(), Some("leaver:1"));
        assert_eq!(left.snapshot.unwrap().status, "disabled");
    }
}
