//! Access invariants (guardrails): the `invariants` API group, enforcement around access-changing operations, and the
//! scheduled check (`iam.checkInvariants`). Ported from tests/invariants.test.ts.
//!
//! The organization, its members and the grants come from the organization fixture. Steps that go through another
//! unit's API still being ported (`identities.update` ends in package automation, `groups.addMember` reconciles
//! license seats, `groups.delete` releases them, `impact.preview`) are tolerated when they answer NOT_IMPLEMENTED: their
//! effect is written to the store directly where the scenario needs it, and the assertion about the refusal runs once
//! that unit is ported.

mod organization_fixture;

use better_iam_core::{AttributeType, Filter, IamError, IamResult, PermissionsConfig};
use better_iam_server::api::Reply;
use organization_fixture::{Org, assert_matches, body, fails, ok, organization, run};
use serde_json::{Value, json};

fn d1() -> Value {
    json!({ "type": "document", "id": "d1" })
}

/// Whether an answer is another unit's NOT_IMPLEMENTED stub.
fn unported<T>(result: &IamResult<T>) -> bool {
    matches!(result, Err(error) if error.code == "NOT_IMPLEMENTED")
}

/// A call that must be refused with `code`, unless the API it goes through is another unit's stub.
#[track_caller]
fn refused<O>(result: IamResult<Reply<O>>, code: &str) -> Option<IamError> {
    if unported(&result) {
        return None;
    }
    let error = fails(result);
    assert_eq!(error.code, code, "{error:?}");
    Some(error)
}

struct Scenario {
    f: Org,
    tenant_id: String,
    alice: String,
    bob: String,
    carol: String,
    reader: String,
    writer: String,
    oncall: String,
    oncall_writer: String,
}

/// `identities.update({ attributes })`, or the same change written directly while package automation is unported
/// (the update commits before that hook runs).
async fn set_attributes(s: &Scenario, identity_id: &str, attributes: Value) -> IamResult<()> {
    let result = s
        .f
        .iam
        .api
        .identities
        .update(
            &s.f.owner_credential,
            body(json!({ "tenantId": s.tenant_id, "identityId": identity_id, "attributes": attributes })),
        )
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) if error.code == "NOT_IMPLEMENTED" => {
            let stored =
                s.f.iam
                    .store
                    .get("identities", identity_id)
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(stored["attributes"], attributes, "the update committed");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// `groups.addMember`, or the membership written directly while license reconciliation is unported.
async fn add_member(s: &Scenario, group_id: &str, identity_id: &str) -> IamResult<()> {
    let result = s
        .f
        .iam
        .api
        .groups
        .add_member(
            &s.f.owner_credential,
            body(
                json!({ "tenantId": s.tenant_id, "groupId": group_id, "identityId": identity_id }),
            ),
        )
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) if error.code == "NOT_IMPLEMENTED" => {
            s.f.insert(
                "groupMembers",
                json!({
                    "id": better_iam_server::utils::id(),
                    "tenantId": s.tenant_id,
                    "uniqueKey": format!("{group_id}:{identity_id}"),
                    "groupId": group_id,
                    "identityId": identity_id,
                }),
            )
            .await;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn scenario() -> Scenario {
    let f = organization(|options| {
        let mut attributes = indexmap::IndexMap::new();
        attributes.insert("contractor".to_owned(), AttributeType::Boolean);
        options.permissions = Some(PermissionsConfig {
            actions: Some(vec!["documents:read".into(), "documents:write".into()]),
            identity_attributes: Some(attributes),
            ..PermissionsConfig::default()
        });
    })
    .await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let alice = f.member("alice").await;
    let bob = f.member("bob").await;
    let carol = f.member("carol").await;
    let reader = ok(f
        .iam
        .api
        .roles
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Reader", "permissions": ["documents:read"] })),
        )
        .await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let writer = ok(f
        .iam
        .api
        .roles
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Writer", "permissions": ["documents:write"] })),
        )
        .await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let oncall = ok(f
        .iam
        .api
        .groups
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "On-call" })),
        )
        .await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut s = Scenario {
        f,
        tenant_id,
        alice,
        bob,
        carol,
        reader,
        writer,
        oncall,
        oncall_writer: String::new(),
    };
    set_attributes(&s, &s.alice.clone(), json!({ "contractor": true }))
        .await
        .expect("contractor");
    add_member(&s, &s.oncall.clone(), &s.bob.clone())
        .await
        .expect("on-call member");
    s.oncall_writer = ok(s
        .f
        .iam
        .api
        .bindings
        .create(
            &owner,
            body(json!({
                "tenantId": s.tenant_id,
                "roleId": s.writer,
                "subjectType": "group",
                "subjectId": s.oncall,
            })),
        )
        .await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    s
}

impl Scenario {
    async fn bind(&self, role_id: &str, identity_id: &str) -> IamResult<Value> {
        self.f
            .iam
            .api
            .bindings
            .create(
                &self.f.owner_credential,
                body(json!({
                    "tenantId": self.tenant_id,
                    "roleId": role_id,
                    "subjectType": "identity",
                    "subjectId": identity_id,
                })),
            )
            .await?
            .into_value()
    }

    async fn invariant(&self, input: Value) -> IamResult<Value> {
        let mut input = input;
        input["tenantId"] = Value::String(self.tenant_id.clone());
        self.f
            .iam
            .api
            .invariants
            .create(&self.f.owner_credential, body(input))
            .await?
            .into_value()
    }
}

#[test]
fn refuses_changes_that_newly_break_an_enforced_invariant() {
    run(|| async {
        let s = scenario().await;
        let created = s
            .invariant(json!({
                "name": "Contractors never write d1",
                "subject": { "attribute": { "name": "contractor", "value": true } },
                "action": "documents:write",
                "resource": d1(),
                "expect": "deny",
                "mode": "enforce",
            }))
            .await
            .unwrap();
        assert_eq!(created["invariant"]["assumeMfa"], json!(true));
        assert_matches(
            &created["result"],
            json!({ "passed": true, "evaluated": 1, "violations": [] }),
        );
        // The stored record keeps the TypeScript member order.
        let keys: Vec<&String> = created["invariant"].as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "tenantId",
                "uniqueKey",
                "name",
                "subject",
                "action",
                "resource",
                "expect",
                "mode",
                "assumeMfa",
                "updatedAt",
                "id",
                "createdBy",
                "createdAt"
            ]
        );
        assert_eq!(
            created["invariant"]["uniqueKey"],
            json!("name:contractors never write d1")
        );

        // A direct binding, a group membership, and a role edit would each let Alice write.
        let error = s.bind(&s.writer, &s.alice).await.unwrap_err();
        assert_eq!(error.code, "INVARIANT_VIOLATION");
        assert_eq!(error.status, 409);
        assert_eq!(
            error.message,
            "Access invariant \"Contractors never write d1\": alice@acme.test would be allowed documents:write on document/d1"
        );
        refused(
            s.f.iam
                .api
                .groups
                .add_member(
                    &s.f.owner_credential,
                    body(json!({ "tenantId": s.tenant_id, "groupId": s.oncall, "identityId": s.alice })),
                )
                .await,
            "INVARIANT_VIOLATION",
        );
        s.bind(&s.reader, &s.alice).await.unwrap();
        let error = fails(
            s.f.iam
                .api
                .roles
                .update(
                    &s.f.owner_credential,
                    body(json!({
                        "tenantId": s.tenant_id,
                        "roleId": s.reader,
                        "permissions": ["documents:read", "documents:write"],
                    })),
                )
                .await,
        );
        assert_eq!(error.code, "INVARIANT_VIOLATION");
        assert!(error.message.contains("Contractors never write d1"));
        // Nothing was written: the transaction rolled back.
        let bindings = ok(s
            .f
            .iam
            .api
            .bindings
            .list(
                &s.f.owner_credential,
                body(json!({ "tenantId": s.tenant_id })),
            )
            .await);
        let alices = bindings
            .as_array()
            .unwrap()
            .iter()
            .filter(|binding| binding["subjectId"] == json!(s.alice))
            .count();
        assert_eq!(alices, 1);
        let members =
            s.f.find(
                "groupMembers",
                Filter::new().eq("groupId", s.oncall.clone()),
            )
            .await;
        assert!(
            !Value::Array(members.into_iter().map(Value::Object).collect())
                .to_string()
                .contains(&s.alice)
        );
        // Unrelated changes still go through, and the same change is fine for a non-contractor.
        s.bind(&s.writer, &s.carol).await.unwrap();
        // Changing Alice's attribute so she is no longer a contractor lifts the guard for her.
        set_attributes(&s, &s.alice, json!({ "contractor": false }))
            .await
            .unwrap();
        add_member(&s, &s.oncall, &s.alice).await.unwrap();
        // ...but making her a contractor again now breaks the invariant, so that update is refused.
        let error =
            s.f.iam
                .api
                .identities
                .update(
                    &s.f.owner_credential,
                    body(json!({
                        "tenantId": s.tenant_id,
                        "identityId": s.alice,
                        "attributes": { "contractor": true },
                    })),
                )
                .await
                .unwrap_err();
        assert_eq!(error.code, "INVARIANT_VIOLATION");
        let stored =
            s.f.iam
                .store
                .get("identities", &s.alice)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(stored["attributes"], json!({ "contractor": false }));
    });
}

#[test]
fn protects_must_allow_invariants_and_tolerates_violations_that_predate_enforcement() {
    run(|| async {
        let s = scenario().await;
        s.invariant(json!({
            "name": "On-call can always write d1",
            "subject": { "groupId": s.oncall },
            "action": "documents:write",
            "resource": d1(),
            "expect": "allow",
            "mode": "enforce",
        }))
        .await
        .unwrap();
        let error = fails(
            s.f.iam
                .api
                .bindings
                .delete(
                    &s.f.owner_credential,
                    body(json!({ "tenantId": s.tenant_id, "bindingId": s.oncall_writer })),
                )
                .await,
        );
        assert_eq!(error.code, "INVARIANT_VIOLATION");
        assert_eq!(
            error.message,
            "Access invariant \"On-call can always write d1\": bob@acme.test would no longer be allowed documents:write on document/d1"
        );

        // Carol is not allowed to read yet; an enforced must-allow invariant about her starts out broken.
        let broken = s
            .invariant(json!({
                "name": "Carol reads d1",
                "subject": { "identityId": s.carol },
                "action": "documents:read",
                "resource": d1(),
                "expect": "allow",
            }))
            .await
            .unwrap();
        assert_eq!(broken["result"]["passed"], json!(false));
        assert_eq!(broken["invariant"]["mode"], json!("monitor"));
        assert_matches(
            &broken["result"]["violations"][0],
            json!({ "identity": { "id": s.carol, "name": "carol@acme.test" } }),
        );
        let invariant_id = broken["invariant"]["id"].as_str().unwrap().to_owned();
        let enforced = ok(s
            .f
            .iam
            .api
            .invariants
            .update(
                &s.f.owner_credential,
                body(json!({ "tenantId": s.tenant_id, "invariantId": invariant_id, "mode": "enforce" })),
            )
            .await);
        assert_eq!(enforced["invariant"]["mode"], json!("enforce"));
        assert_eq!(enforced["invariant"]["name"], json!("Carol reads d1"));
        assert_eq!(
            enforced["invariant"]["createdAt"],
            broken["invariant"]["createdAt"]
        );
        // The pre-existing violation does not block unrelated work.
        s.bind(&s.reader, &s.bob).await.unwrap();

        let report = ok(s
            .f
            .iam
            .api
            .invariants
            .run(
                &s.f.owner_credential,
                body(json!({ "tenantId": s.tenant_id })),
            )
            .await);
        assert_eq!(
            report["summary"],
            json!({ "passed": 1, "failed": 1, "errors": 0 })
        );
        let outcomes: Vec<(Value, Value)> = report["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|result| {
                (
                    result["invariant"]["name"].clone(),
                    result["passed"].clone(),
                )
            })
            .collect();
        assert_eq!(
            outcomes,
            [
                (json!("Carol reads d1"), json!(false)),
                (json!("On-call can always write d1"), json!(true)),
            ]
        );
        // Granting Carol read fixes it.
        s.bind(&s.reader, &s.carol).await.unwrap();
        let single = ok(s
            .f
            .iam
            .api
            .invariants
            .run(
                &s.f.owner_credential,
                body(json!({ "tenantId": s.tenant_id, "invariantId": invariant_id })),
            )
            .await);
        assert_eq!(
            single["summary"],
            json!({ "passed": 1, "failed": 0, "errors": 0 })
        );

        // Deleting the group an enforced invariant is about would switch it off silently, so it is refused.
        if let Some(error) = refused(
            s.f.iam
                .api
                .groups
                .delete(
                    &s.f.owner_credential,
                    body(json!({ "tenantId": s.tenant_id, "groupId": s.oncall })),
                )
                .await,
            "INVARIANT_VIOLATION",
        ) {
            assert!(error.message.contains("could no longer be evaluated"));
        }

        // Deleting the invariant lifts enforcement.
        let list = ok(s
            .f
            .iam
            .api
            .invariants
            .list(
                &s.f.owner_credential,
                body(json!({ "tenantId": s.tenant_id })),
            )
            .await);
        let names: Vec<&Value> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|invariant| &invariant["name"])
            .collect();
        assert_eq!(
            names,
            [
                &json!("Carol reads d1"),
                &json!("On-call can always write d1")
            ]
        );
        let guard = list
            .as_array()
            .unwrap()
            .iter()
            .find(|invariant| invariant["name"] == json!("On-call can always write d1"))
            .unwrap();
        assert_eq!(
            ok(s.f
                .iam
                .api
                .invariants
                .delete(
                    &s.f.owner_credential,
                    body(json!({ "tenantId": s.tenant_id, "invariantId": guard["id"] })),
                )
                .await),
            json!({ "deleted": true })
        );
        ok(s.f
            .iam
            .api
            .bindings
            .delete(
                &s.f.owner_credential,
                body(json!({ "tenantId": s.tenant_id, "bindingId": s.oncall_writer })),
            )
            .await);
    });
}

#[test]
fn shows_broken_invariants_in_impact_previews() {
    run(|| async {
        let s = scenario().await;
        s.bind(&s.reader, &s.alice).await.unwrap();
        let created = s
            .invariant(json!({
                "name": "Alice never writes",
                "subject": { "identityId": s.alice },
                "action": "documents:write",
                "resource": d1(),
                "expect": "deny",
            }))
            .await
            .unwrap();
        let preview = s
            .f
            .iam
            .api
            .impact
            .preview(
                &s.f.owner_credential,
                body(json!({
                    "tenantId": s.tenant_id,
                    "change": { "role": { "roleId": s.reader, "permissions": ["documents:read", "documents:write"] } },
                    "resources": [d1()],
                })),
            )
            .await;
        if unported(&preview) {
            return;
        }
        let preview = ok(preview);
        let broken = &preview["invariants"]["broken"];
        assert_eq!(broken.as_array().unwrap().len(), 1);
        assert_matches(
            &broken[0],
            json!({
                "id": created["invariant"]["id"],
                "name": "Alice never writes",
                "mode": "monitor",
                "violations": [{ "identity": { "id": s.alice, "name": "alice@acme.test" } }],
            }),
        );
        assert!(broken[0]["violations"][0]["reason"].is_string());
        assert_eq!(preview["invariants"]["fixed"], json!([]));
    });
}

#[test]
fn monitors_invariants_on_a_schedule_and_audits_breaks_and_restorations_once() {
    run(|| async {
        let s = scenario().await;
        let created = s
            .invariant(json!({
                "name": "Carol never writes",
                "subject": { "identityId": s.carol },
                "action": "documents:write",
                "resource": d1(),
                "expect": "deny",
            }))
            .await
            .unwrap();
        let invariant_id = created["invariant"]["id"].clone();
        assert_eq!(
            s.f.iam.check_invariants(None).await.unwrap(),
            json!({ "checked": 1, "broken": [], "restored": [] })
        );
        // Monitor mode lets the change through; the next check reports it once.
        let binding = s.bind(&s.writer, &s.carol).await.unwrap();
        assert_eq!(
            s.f.iam
                .check_invariants(Some(&json!({ "tenantId": s.tenant_id })))
                .await
                .unwrap(),
            json!({
                "checked": 1,
                "broken": [{
                    "tenantId": s.tenant_id,
                    "invariantId": invariant_id,
                    "name": "Carol never writes",
                    "violations": [s.carol],
                }],
                "restored": [],
            })
        );
        assert_eq!(
            s.f.iam.check_invariants(None).await.unwrap()["broken"],
            json!([])
        );
        let list = ok(s
            .f
            .iam
            .api
            .invariants
            .list(
                &s.f.owner_credential,
                body(json!({ "tenantId": s.tenant_id })),
            )
            .await);
        assert_matches(
            &list[0]["lastCheck"],
            json!({ "passed": false, "violations": [s.carol] }),
        );
        ok(s.f
            .iam
            .api
            .bindings
            .delete(
                &s.f.owner_credential,
                body(json!({ "tenantId": s.tenant_id, "bindingId": binding["id"] })),
            )
            .await);
        assert_eq!(
            s.f.iam.check_invariants(None).await.unwrap()["restored"],
            json!([{ "tenantId": s.tenant_id, "invariantId": invariant_id, "name": "Carol never writes" }])
        );
        let events =
            s.f.find("audit", Filter::new().eq("tenantId", s.tenant_id.clone()))
                .await;
        let broken: Vec<_> = events
            .iter()
            .filter(|event| event["action"] == json!("invariant:broken"))
            .collect();
        assert_eq!(broken.len(), 1);
        assert_eq!(broken[0]["actorId"], json!("deployment-operator"));
        assert_eq!(broken[0]["outcome"], json!("deny"));
        assert_eq!(
            broken[0]["metadata"],
            json!({ "name": "Carol never writes", "mode": "monitor", "violations": [s.carol] })
        );
        let restored: Vec<_> = events
            .iter()
            .filter(|event| event["action"] == json!("invariant:restored"))
            .collect();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0]["outcome"], json!("allow"));
        assert_eq!(
            restored[0]["metadata"],
            json!({ "name": "Carol never writes", "mode": "monitor" })
        );
        // The audit API shows both to the owner.
        let audit = ok(s
            .f
            .iam
            .api
            .audit
            .list(
                &s.f.owner_credential,
                body(json!({ "tenantId": s.tenant_id })),
            )
            .await)
        .to_string();
        assert!(audit.contains("invariant:broken"));
        assert!(audit.contains("invariant:restored"));
    });
}

#[test]
fn validates_invariants_and_requires_permissions() {
    run(|| async {
        let s = scenario().await;
        let base = json!({
            "name": "x",
            "subject": { "everyone": true },
            "action": "documents:read",
            "resource": d1(),
            "expect": "deny",
        });
        let with = |changes: Value| {
            let mut input = base.clone();
            for (key, value) in changes.as_object().unwrap() {
                input[key] = value.clone();
            }
            input
        };
        s.invariant(base.clone()).await.unwrap();
        let code = |result: IamResult<Value>| result.unwrap_err().code;
        assert_eq!(
            code(s.invariant(with(json!({ "name": "X" }))).await),
            "CONFLICT"
        );
        assert_eq!(
            code(
                s.invariant(with(json!({ "name": "y", "action": "documents:fly" })))
                    .await
            ),
            "INVALID_ACTION"
        );
        assert_eq!(
            code(
                s.invariant(with(json!({
                    "name": "z",
                    "subject": { "everyone": true, "identityId": s.alice },
                })))
                .await
            ),
            "INVALID_INPUT"
        );
        let error = s
            .invariant(with(json!({
                "name": "w",
                "subject": { "attribute": { "name": "contractor", "value": "yes" } },
            })))
            .await
            .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        assert_eq!(error.message, "subject.attribute.value must be a boolean");
        let error = s
            .invariant(with(json!({
                "name": "v",
                "subject": { "attribute": { "name": "department", "value": "x" } },
            })))
            .await
            .unwrap_err();
        assert_eq!(error.message, "Unknown identity attribute department");
        let error = s
            .invariant(with(json!({ "name": "u", "expect": "maybe" })))
            .await
            .unwrap_err();
        assert_eq!(error.message, "expect must be allow or deny");
        let error = s
            .invariant(with(json!({ "name": "t", "mode": "audit" })))
            .await
            .unwrap_err();
        assert_eq!(error.message, "mode must be enforce or monitor");
        let error = s
            .invariant(with(json!({ "name": "s", "assumeMfa": "yes" })))
            .await
            .unwrap_err();
        assert_eq!(error.message, "assumeMfa must be a boolean");
        let error = s
            .invariant(with(json!({ "name": "   " })))
            .await
            .unwrap_err();
        // `text` refuses a blank name before the trimmed check could.
        assert_eq!(error.message, "Invalid name");
        let error = s
            .invariant(with(json!({ "name": "r", "subject": { "everyone": 1 } })))
            .await
            .unwrap_err();
        assert_eq!(error.message, "subject.everyone must be true");
        let alice = s.f.sign_in(&s.alice).await;
        let error = fails(
            s.f.iam
                .api
                .invariants
                .list(&alice, body(json!({ "tenantId": s.tenant_id })))
                .await,
        );
        assert_eq!(error.code, "ACCESS_DENIED");
        let mut mine = with(json!({ "name": "mine" }));
        mine["tenantId"] = json!(s.tenant_id);
        let error = fails(s.f.iam.api.invariants.create(&alice, body(mine)).await);
        assert_eq!(error.code, "ACCESS_DENIED");
    });
}

#[test]
fn reports_unevaluable_invariants_and_caps_the_tenant() {
    run(|| async {
        let s = scenario().await;
        let created = s
            .invariant(json!({
                "name": "Bob writes",
                "subject": { "identityId": s.bob },
                "action": "documents:write",
                "resource": d1(),
                "expect": "allow",
            }))
            .await
            .unwrap();
        assert_matches(
            &created["result"],
            json!({ "passed": true, "evaluated": 1, "truncated": false }),
        );
        // The identity it names disappears: the run reports an error instead of a verdict.
        let id = created["invariant"]["id"].as_str().unwrap().to_owned();
        let mut stored =
            s.f.iam
                .store
                .get("accessInvariants", &id)
                .await
                .unwrap()
                .unwrap();
        stored.insert("subject".into(), json!({ "identityId": "nobody" }));
        s.f.put("accessInvariants", stored).await;
        let report = ok(s
            .f
            .iam
            .api
            .invariants
            .run(
                &s.f.owner_credential,
                body(json!({ "tenantId": s.tenant_id })),
            )
            .await);
        assert_eq!(
            report["summary"],
            json!({ "passed": 0, "failed": 0, "errors": 1 })
        );
        assert_eq!(
            report["results"][0],
            json!({
                "invariant": {
                    "id": id,
                    "name": "Bob writes",
                    "mode": "monitor",
                    "expect": "allow",
                    "action": "documents:write",
                    "resource": d1(),
                },
                "passed": false,
                "evaluated": 0,
                "truncated": false,
                "violations": [],
                "error": { "code": "NOT_FOUND", "message": "The invariant names an identity that no longer exists" },
            })
        );
        let check = s.f.iam.check_invariants(None).await.unwrap();
        assert_eq!(check["broken"][0]["violations"], json!([]));
        let events =
            s.f.find("audit", Filter::new().eq("action", "invariant:broken"))
                .await;
        assert_eq!(events[0]["metadata"]["error"], json!("NOT_FOUND"));
        let stored =
            s.f.iam
                .store
                .get("accessInvariants", &id)
                .await
                .unwrap()
                .unwrap();
        assert_matches(
            &stored["lastCheck"],
            json!({ "passed": false, "violations": [], "error": "The invariant names an identity that no longer exists" }),
        );
        // A tenant holds at most 100 invariants.
        for index in 0..99 {
            s.f.insert(
                "accessInvariants",
                json!({
                    "id": format!("filler-{index}"),
                    "tenantId": s.tenant_id,
                    "uniqueKey": format!("name:filler {index}"),
                    "name": format!("filler {index}"),
                    "subject": { "everyone": true },
                    "action": "documents:read",
                    "resource": d1(),
                    "expect": "deny",
                    "mode": "monitor",
                    "assumeMfa": true,
                    "createdBy": s.f.owner_id,
                    "createdAt": 1,
                    "updatedAt": 1,
                }),
            )
            .await;
        }
        let error = s
            .invariant(json!({
                "name": "one too many",
                "subject": { "everyone": true },
                "action": "documents:read",
                "resource": d1(),
                "expect": "deny",
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code, "LIMIT_EXCEEDED");
        assert_eq!(error.message, "At most 100 invariants");
    });
}
