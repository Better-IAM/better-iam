//! Port of the tests of the `packages` API group (api/packages.ts): tests/access-packages.test.ts,
//! tests/package-requests.test.ts, tests/package-review-requests.test.ts, tests/package-review-integrity.test.ts
//! and the `packages` cases of tests/package-review-authz.test.ts.
//!
//! Left out, with the unit that blocks them: steps that offboard or suspend an identity (`identities.offboard` and
//! `setStatus` reach threats.ts `endContainment`), the configuration document (`config.export`/`plan`/`apply`, the
//! sync unit), deleting an approver group (`groups.delete` reaches package-rules.ts `ruleGroupIds`), and every
//! birthright rule (`autoAssign`, package-rules.ts and api/package-automation.ts).

mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::{CredentialInput, Filter, IamError, IamResult, Record};
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use organization_fixture::{Org, body, organization, run};
use serde_json::{Value, json};

const HOUR: f64 = 3_600_000.0;
const DAY: f64 = 24.0 * HOUR;

type Inbox = Arc<Mutex<Vec<DeliveryMessage>>>;

macro_rules! api {
    ($f:expr, $group:ident . $method:ident, $credential:expr, $input:expr) => {
        $f.iam
            .api
            .$group
            .$method($credential, body($input))
            .await
            .and_then(|reply| reply.into_value())
    };
}

/// `toMatchObject`: objects match on the members `expected` names, arrays element by element (same length).
fn matches(actual: &Value, expected: &Value) -> bool {
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
fn assert_matches(actual: &Value, expected: Value) {
    assert!(
        matches(actual, &expected),
        "\n  actual:   {actual}\n  expected: {expected}"
    );
}

#[track_caller]
fn ok(result: IamResult<Value>) -> Value {
    match result {
        Ok(value) => value,
        Err(error) => panic!("expected success, got {error:?}"),
    }
}

#[track_caller]
fn fails(result: IamResult<Value>, code: &str) -> IamError {
    match result {
        Ok(value) => panic!("expected {code}, got {value}"),
        Err(error) => {
            assert_eq!(error.code, code, "{error:?}");
            error
        }
    }
}

fn id_of(value: &Value) -> String {
    value["id"].as_str().expect("id").to_owned()
}

fn ids(list: &Value) -> Vec<String> {
    list.as_array()
        .expect("list")
        .iter()
        .map(id_of)
        .collect::<Vec<_>>()
}

fn sorted(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items
}

fn num(value: f64) -> Value {
    json!(value as i64)
}

/// The organization fixture with a captured email outbox.
async fn fixture() -> (Org, Inbox) {
    let inbox: Inbox = Arc::default();
    let sink = inbox.clone();
    let f = organization(move |options| {
        if let Some(authentication) = options.authentication.as_mut() {
            authentication.send_email = Some(delivery_fn(move |message| {
                sink.lock().unwrap().push(message);
                async { Ok(()) }
            }));
        }
    })
    .await;
    (f, inbox)
}

async fn role(f: &Org, name: &str, permissions: Value) -> String {
    id_of(&ok(api!(
        f,
        roles.create,
        &f.owner_credential,
        json!({ "tenantId": f.tenant_id, "name": name, "permissions": permissions })
    )))
}

async fn group(f: &Org, name: &str) -> String {
    id_of(&ok(api!(
        f,
        groups.create,
        &f.owner_credential,
        json!({ "tenantId": f.tenant_id, "name": name })
    )))
}

async fn bind(f: &Org, role_id: &str, subject_type: &str, subject_id: &str) -> Value {
    ok(api!(
        f,
        bindings.create,
        &f.owner_credential,
        json!({
            "tenantId": f.tenant_id,
            "roleId": role_id,
            "subjectType": subject_type,
            "subjectId": subject_id,
        })
    ))
}

/// Binds a fresh role with these permissions to an identity, as the owner (`grant`).
async fn grant(f: &Org, identity_id: &str, name: &str, permissions: Value) -> String {
    let role_id = role(f, name, permissions).await;
    bind(f, &role_id, "identity", identity_id).await;
    role_id
}

async fn add_member(f: &Org, group_id: &str, identity_id: &str) {
    ok(api!(
        f,
        groups.add_member,
        &f.owner_credential,
        json!({ "tenantId": f.tenant_id, "groupId": group_id, "identityId": identity_id })
    ));
}

async fn authority(f: &Org, identity_id: &str) -> Value {
    ok(api!(
        f,
        authorities.create,
        &f.owner_credential,
        json!({
            "tenantId": f.tenant_id,
            "identityId": identity_id,
            "ceiling": {
                "version": 1,
                "statements": [{ "effect": "allow", "actions": ["documents:*"], "resources": ["*"] }],
            },
        })
    ))
}

/// Whether a credential may act on document `a`.
async fn can(f: &Org, credential: &CredentialInput, action: &str) -> bool {
    f.iam
        .authorize(&AuthorizationRequest {
            credential: credential.clone(),
            tenant_id: f.tenant_id.clone(),
            action: action.to_owned(),
            resource: ResourceTarget {
                kind: "documents".into(),
                id: "a".into(),
            },
        })
        .await
        .unwrap()
        .allowed
}

async fn get(f: &Org, collection: &str, id: &str) -> Option<Record> {
    f.store().get(collection, id).await.unwrap()
}

async fn stored_status(f: &Org, request_id: &str) -> Option<String> {
    get(f, "packageRequests", request_id)
        .await
        .and_then(|request| {
            request
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
}

async fn membership(f: &Org, group_id: &str, identity_id: &str) -> Option<Record> {
    f.find(
        "groupMembers",
        Filter::new()
            .eq("tenantId", f.tenant_id.clone())
            .eq("groupId", group_id.to_owned())
            .eq("identityId", identity_id.to_owned()),
    )
    .await
    .into_iter()
    .next()
}

async fn tagged(f: &Org, collection: &str, assignment_id: &str) -> Vec<Record> {
    f.find(
        collection,
        Filter::new()
            .eq("tenantId", f.tenant_id.clone())
            .eq("packageAssignmentId", assignment_id.to_owned()),
    )
    .await
}

async fn in_group(f: &Org, group_id: &str, name: &str) -> bool {
    ok(api!(
        f,
        groups.list_members,
        &f.owner_credential,
        json!({ "tenantId": f.tenant_id, "groupId": group_id })
    ))
    .as_array()
    .unwrap()
    .iter()
    .any(|member| member["name"] == json!(name))
}

async fn audit_count(f: &Org, action: &str) -> usize {
    ok(api!(
        f,
        audit.list,
        &f.owner_credential,
        json!({ "tenantId": f.tenant_id, "action": action })
    ))
    .as_array()
    .unwrap()
    .len()
}

fn sent(inbox: &Inbox, template: &str) -> Vec<DeliveryMessage> {
    inbox
        .lock()
        .unwrap()
        .iter()
        .filter(|message| message.template == template)
        .cloned()
        .collect()
}

/// Acme with a Reader role, a Writer role, and an Engineering group that carries Writer.
struct Setup {
    f: Org,
    tenant: String,
    owner: CredentialInput,
    reader: String,
    writer: String,
    engineering: String,
}

async fn setup() -> Setup {
    let (f, _) = fixture().await;
    let reader = role(&f, "Reader", json!(["documents:read"])).await;
    let writer = role(&f, "Writer", json!(["documents:write"])).await;
    let engineering = group(&f, "Engineering").await;
    bind(&f, &writer, "group", &engineering).await;
    Setup {
        tenant: f.tenant_id.clone(),
        owner: f.owner_credential.clone(),
        f,
        reader,
        writer,
        engineering,
    }
}

impl Setup {
    async fn package(&self, input: Value) -> Value {
        let mut input = input;
        input["tenantId"] = json!(self.tenant);
        ok(api!(self.f, packages.create, &self.owner, input))
    }

    async fn assign(&self, input: Value) -> IamResult<Value> {
        let mut input = input;
        input["tenantId"] = json!(self.tenant);
        api!(self.f, packages.assign, &self.owner, input)
    }

    async fn revoke(&self, package_id: &str, identity_id: &str) -> IamResult<Value> {
        api!(
            self.f,
            packages.revoke,
            &self.owner,
            json!({ "tenantId": self.tenant, "packageId": package_id, "identityId": identity_id })
        )
    }
}

// --- tests/access-packages.test.ts -----------------------------------------------------------------------------

#[test]
fn bundles_roles_and_groups_grants_them_together_and_revokes_only_what_it_added() {
    run(|| async {
        let s = setup().await;
        let (f, tenant, owner) = (&s.f, &s.tenant, &s.owner);
        fails(
            api!(
                f,
                packages.create,
                owner,
                json!({ "tenantId": tenant, "name": "Empty" })
            ),
            "INVALID_INPUT",
        );
        fails(
            api!(
                f,
                packages.create,
                owner,
                json!({ "tenantId": tenant, "name": "Ghost", "roleIds": ["missing"] })
            ),
            "NOT_FOUND",
        );
        let roles = ok(api!(f, roles.list, owner, json!({ "tenantId": tenant })));
        let owner_role = roles
            .as_array()
            .unwrap()
            .iter()
            .find(|role| role["protected"] == json!(true))
            .map(id_of)
            .unwrap();
        fails(
            api!(
                f,
                packages.create,
                owner,
                json!({ "tenantId": tenant, "name": "Owners", "roleIds": [owner_role] })
            ),
            "PROTECTED_RESOURCE",
        );
        let kit = s
            .package(json!({
                "name": "Engineer kit",
                "description": "Document access and the Engineering group",
                "roleIds": [s.reader],
                "groupIds": [s.engineering],
            }))
            .await;
        assert_matches(
            &kit,
            json!({
                "name": "Engineer kit",
                "roleIds": [s.reader],
                "groupIds": [s.engineering],
                "assignments": 0,
            }),
        );
        assert!(kit.get("uniqueKey").is_none());
        let kit_id = id_of(&kit);
        fails(
            api!(
                f,
                packages.create,
                owner,
                json!({ "tenantId": tenant, "name": "engineer KIT", "roleIds": [s.reader] })
            ),
            "CONFLICT",
        );
        let alice = f.member("alice").await;
        let as_alice = f.sign_in(&alice).await;
        assert!(!can(f, &as_alice, "documents:read").await);
        let assigned = ok(s
            .assign(json!({
                "packageId": kit_id,
                "identityId": alice,
                "expiresAt": num(f.now() + 5.0 * DAY),
                "justification": "Joined the platform team",
            }))
            .await);
        assert_matches(
            &assigned,
            json!({
                "packageName": "Engineer kit",
                "identityName": "alice",
                "identityEmail": "alice@acme.test",
                "expired": false,
                "created": { "bindings": 1, "memberships": 1 },
                "skipped": [],
            }),
        );
        assert!(can(f, &as_alice, "documents:read").await);
        assert!(can(f, &as_alice, "documents:write").await);
        // The grants are ordinary records tagged with the assignment and ending with it.
        let assignment_id = id_of(&assigned);
        let bindings: Vec<(Value, Value)> = tagged(f, "bindings", &assignment_id)
            .await
            .iter()
            .map(|binding| (binding["roleId"].clone(), binding["expiresAt"].clone()))
            .collect();
        assert_eq!(bindings, vec![(json!(s.reader), num(f.now() + 5.0 * DAY))]);
        let members: Vec<(Value, Value)> = tagged(f, "groupMembers", &assignment_id)
            .await
            .iter()
            .map(|member| (member["groupId"].clone(), member["expiresAt"].clone()))
            .collect();
        assert_eq!(
            members,
            vec![(json!(s.engineering), num(f.now() + 5.0 * DAY))]
        );
        fails(
            s.assign(json!({ "packageId": kit_id, "identityId": alice }))
                .await,
            "CONFLICT",
        );
        let listed = ok(api!(f, packages.list, owner, json!({ "tenantId": tenant })));
        assert_eq!(listed[0]["assignments"], json!(1));
        let by_identity = ok(api!(
            f,
            packages.list_assignments,
            owner,
            json!({ "tenantId": tenant, "identityId": alice })
        ));
        assert_eq!(
            by_identity
                .as_array()
                .unwrap()
                .iter()
                .map(|assignment| assignment["packageId"].clone())
                .collect::<Vec<_>>(),
            vec![json!(kit_id)]
        );
        // Bob already holds Reader directly: the package adds a binding of its own beside it and never touches the
        // direct one.
        let bob = f.member("bob").await;
        let as_bob = f.sign_in(&bob).await;
        let direct = bind(f, &s.reader, "identity", &bob).await;
        let partial = ok(s
            .assign(json!({ "packageId": kit_id, "identityId": bob }))
            .await);
        assert_eq!(
            partial["created"],
            json!({ "bindings": 1, "memberships": 1 })
        );
        assert_eq!(partial["skipped"], json!([]));
        assert!(
            !partial["bindingIds"]
                .as_array()
                .unwrap()
                .contains(&direct["id"])
        );
        assert!(can(f, &as_bob, "documents:write").await);
        ok(s.revoke(&kit_id, &bob).await);
        assert!(can(f, &as_bob, "documents:read").await);
        assert!(!can(f, &as_bob, "documents:write").await);
        // Nothing is deleted from under a package; revoking clears the way.
        fails(
            api!(
                f,
                packages.delete,
                owner,
                json!({ "tenantId": tenant, "packageId": kit_id })
            ),
            "RESOURCE_IN_USE",
        );
        fails(
            api!(
                f,
                roles.delete,
                owner,
                json!({ "tenantId": tenant, "roleId": s.reader })
            ),
            "RESOURCE_IN_USE",
        );
        let revoked = ok(s.revoke(&kit_id, &alice).await);
        assert_eq!(
            revoked,
            json!({ "revoked": true, "bindings": 1, "memberships": 1 })
        );
        assert!(!can(f, &as_alice, "documents:read").await);
        assert!(!can(f, &as_alice, "documents:write").await);
        fails(s.revoke(&kit_id, &alice).await, "NOT_FOUND");
        let trail = ok(api!(
            f,
            audit.list,
            owner,
            json!({ "tenantId": tenant, "action": "package:assign" })
        ));
        let trail = trail.as_array().unwrap();
        assert_eq!(trail.len(), 2);
        let bobs = trail
            .iter()
            .find(|event| event["metadata"]["identityId"] == json!(bob))
            .unwrap();
        assert_matches(
            &bobs["metadata"],
            json!({ "packageName": "Engineer kit", "bindings": 1, "memberships": 1, "skipped": [] }),
        );
        assert_eq!(audit_count(f, "package:revoke").await, 2);
        ok(api!(
            f,
            packages.delete,
            owner,
            json!({ "tenantId": tenant, "packageId": kit_id })
        ));
        assert_eq!(
            ok(api!(f, packages.list, owner, json!({ "tenantId": tenant }))),
            json!([])
        );
    });
}

#[test]
fn enforces_the_package_rules_ends_with_its_expiry_and_follows_permissions() {
    run(|| async {
        let s = setup().await;
        let (f, tenant, owner) = (&s.f, &s.tenant, &s.owner);
        let vendor = s
            .package(json!({
                "name": "Vendor",
                "roleIds": [s.reader],
                "groupIds": [s.engineering],
                "maxDurationMs": num(2.0 * DAY),
                "requireJustification": true,
            }))
            .await;
        let vendor_id = id_of(&vendor);
        let alice = f.member("alice").await;
        let as_alice = f.sign_in(&alice).await;
        let assign = |extra: Value| {
            let mut input = json!({ "packageId": vendor_id, "identityId": alice });
            for (key, value) in extra.as_object().unwrap() {
                input[key] = value.clone();
            }
            s.assign(input)
        };
        // An end date within the cap and a justification are mandatory here.
        let error = fails(
            assign(json!({ "justification": "Audit" })).await,
            "INVALID_INPUT",
        );
        assert_eq!(
            error.message,
            "This package requires an end date (expiresAt)"
        );
        let error = fails(
            assign(json!({ "justification": "Audit", "expiresAt": num(f.now() + 3.0 * DAY) }))
                .await,
            "INVALID_INPUT",
        );
        assert_eq!(
            error.message,
            "expiresAt exceeds the maximum duration of this package"
        );
        let error = fails(
            assign(json!({ "expiresAt": num(f.now() + DAY) })).await,
            "INVALID_INPUT",
        );
        assert_eq!(error.message, "This package requires a justification");
        ok(
            assign(json!({ "expiresAt": num(f.now() + DAY), "justification": "Quarterly audit" }))
                .await,
        );
        assert!(can(f, &as_alice, "documents:read").await);
        f.advance(DAY + 1.0);
        assert!(!can(f, &as_alice, "documents:read").await);
        assert!(!can(f, &as_alice, "documents:write").await);
        assert_eq!(
            ok(api!(
                f,
                packages.list_assignments,
                owner,
                json!({ "tenantId": tenant, "packageId": vendor_id })
            )),
            json!([])
        );
        let ended = ok(api!(
            f,
            packages.list_assignments,
            owner,
            json!({ "tenantId": tenant, "packageId": vendor_id, "includeExpired": true })
        ));
        assert_eq!(
            ended
                .as_array()
                .unwrap()
                .iter()
                .map(|assignment| assignment["expired"].clone())
                .collect::<Vec<_>>(),
            vec![json!(true)]
        );
        assert_matches(
            &f.iam.purge_deleted(None).await.unwrap(),
            json!({ "expiredBindings": 1, "expiredMemberships": 1, "expiredAssignments": 1 }),
        );
        // Reassigning after the end starts afresh.
        let again = ok(assign(
            json!({ "expiresAt": num(f.now() + DAY), "justification": "Follow-up audit" }),
        )
        .await);
        assert_eq!(again["created"], json!({ "bindings": 1, "memberships": 1 }));
        assert!(can(f, &as_alice, "documents:read").await);
        // Assigning needs the package permission and the right to grant every part of it.
        let admin = f.sign_in(&f.owner_id).await;
        let carol = f.member("carol").await;
        grant(
            f,
            &carol,
            "Assigner",
            json!(["iam:packages:read", "iam:packages:assign"]),
        )
        .await;
        let as_carol = f.sign_in(&carol).await;
        let dave = f.member("dave").await;
        fails(
            api!(
                f,
                packages.assign,
                &as_carol,
                json!({
                    "tenantId": tenant,
                    "packageId": vendor_id,
                    "identityId": dave,
                    "expiresAt": num(f.now() + DAY),
                    "justification": "Onboarding",
                })
            ),
            "ACCESS_DENIED",
        );
        fails(
            api!(
                f,
                packages.create,
                &as_carol,
                json!({ "tenantId": tenant, "name": "Nope", "roleIds": [s.reader] })
            ),
            "ACCESS_DENIED",
        );
        let names = ok(api!(
            f,
            packages.list,
            &as_carol,
            json!({ "tenantId": tenant })
        ));
        assert_eq!(
            names
                .as_array()
                .unwrap()
                .iter()
                .map(|pkg| pkg["name"].clone())
                .collect::<Vec<_>>(),
            vec![json!("Vendor")]
        );
        let as_dave = f.sign_in(&dave).await;
        fails(
            api!(f, packages.list, &as_dave, json!({ "tenantId": tenant })),
            "ACCESS_DENIED",
        );
        // Editing a package changes future assignments only.
        let updated = ok(api!(
            f,
            packages.update,
            &admin,
            json!({
                "tenantId": tenant,
                "packageId": vendor_id,
                "groupIds": [],
                "maxDurationMs": null,
                "requireJustification": false,
            })
        ));
        assert_matches(
            &updated,
            json!({ "roleIds": [s.reader], "groupIds": [], "assignments": 1 }),
        );
        assert!(updated.get("maxDurationMs").is_none());
        assert!(updated.get("requireJustification").is_none());
        let plain = ok(api!(
            f,
            packages.assign,
            &admin,
            json!({ "tenantId": tenant, "packageId": vendor_id, "identityId": dave })
        ));
        assert_eq!(plain["created"], json!({ "bindings": 1, "memberships": 0 }));
        assert!(plain.get("expiresAt").is_none());
    });
}

// --- tests/package-requests.test.ts ----------------------------------------------------------------------------

#[test]
fn lets_members_request_a_package_routes_it_to_approvers_and_assigns_it_on_approval() {
    run(|| async {
        let (f, inbox) = fixture().await;
        let tenant = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let reader = role(&f, "Reader", json!(["documents:read"])).await;
        let engineering = group(&f, "Engineering").await;
        let approvers = group(&f, "Approvers").await;
        let everyone = group(&f, "Everyone").await;
        let member = role(&f, "Member", json!(["iam:packages:request"])).await;
        bind(&f, &member, "group", &everyone).await;
        // Approvers decide and, because approval assigns under their authority, may grant every part.
        let approver = role(
            &f,
            "Package approver",
            json!([
                "iam:packages:approve",
                "iam:bindings:create",
                "iam:groups:update"
            ]),
        )
        .await;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let carol = f.member("carol").await;
        ok(api!(
            f,
            groups.add_members,
            &owner,
            json!({ "tenantId": tenant, "groupId": everyone, "identityIds": [alice, bob] })
        ));
        add_member(&f, &approvers, &bob).await;
        bind(&f, &approver, "identity", &bob).await;
        authority(&f, &bob).await;
        let kit = ok(api!(
            f,
            packages.create,
            &owner,
            json!({
                "tenantId": tenant,
                "name": "Engineer kit",
                "roleIds": [reader],
                "groupIds": [engineering],
                "approverGroupId": approvers,
                "requireJustification": true,
                "maxDurationMs": num(30.0 * DAY),
            })
        ));
        let kit_id = id_of(&kit);
        let as_alice = f.sign_in(&alice).await;
        let as_bob = f.sign_in(&bob).await;
        let as_carol = f.sign_in(&carol).await;
        let request = |credential: &CredentialInput, extra: Value| {
            let mut input = json!({ "tenantId": tenant, "packageId": kit_id });
            for (key, value) in extra.as_object().unwrap() {
                input[key] = value.clone();
            }
            let credential = credential.clone();
            let f = &f;
            async move { api!(f, packages.request, &credential, input) }
        };
        // Only requestable packages, only by members holding iam:packages:request, within the package's rules.
        fails(
            request(
                &as_alice,
                json!({ "justification": "x", "expiresAt": num(f.now() + DAY) }),
            )
            .await,
            "INVALID_TRANSITION",
        );
        ok(api!(
            f,
            packages.update,
            &owner,
            json!({ "tenantId": tenant, "packageId": kit_id, "requestable": true })
        ));
        fails(
            request(
                &as_carol,
                json!({ "justification": "x", "expiresAt": num(f.now() + DAY) }),
            )
            .await,
            "ACCESS_DENIED",
        );
        fails(
            request(&as_alice, json!({ "expiresAt": num(f.now() + DAY) })).await,
            "INVALID_INPUT",
        );
        fails(
            request(
                &as_alice,
                json!({ "justification": "x", "expiresAt": num(f.now() + 60.0 * DAY) }),
            )
            .await,
            "INVALID_INPUT",
        );
        let first = ok(request(
            &as_alice,
            json!({ "justification": "Joining the platform team", "expiresAt": num(f.now() + 10.0 * DAY) }),
        )
        .await);
        assert_matches(
            &first,
            json!({
                "status": "pending",
                "packageName": "Engineer kit",
                "identityName": "alice",
                "desiredExpiresAt": num(f.now() + 10.0 * DAY),
                "expiresAt": num(f.now() + DAY),
            }),
        );
        let first_id = id_of(&first);
        fails(
            request(
                &as_alice,
                json!({ "justification": "again", "expiresAt": num(f.now() + DAY) }),
            )
            .await,
            "CONFLICT",
        );
        f.iam.auth.dispatch_outbox(None).await.unwrap();
        let requests: Vec<(String, Option<String>, Option<String>)> =
            sent(&inbox, "package-request")
                .iter()
                .map(|message| {
                    (
                        message.to.clone(),
                        message
                            .payload
                            .get("requesterName")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        message
                            .payload
                            .get("packageName")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    )
                })
                .collect();
        assert_eq!(
            requests,
            vec![(
                "bob@acme.test".to_owned(),
                Some("alice".to_owned()),
                Some("Engineer kit".to_owned())
            )]
        );
        let mine = ok(api!(
            f,
            packages.list_mine,
            &as_alice,
            json!({ "tenantId": tenant })
        ));
        let pkg = &mine["packages"][0];
        assert_eq!(mine["packages"].as_array().unwrap().len(), 1);
        assert_eq!(pkg["name"], json!("Engineer kit"));
        assert_eq!(pkg["roles"], json!([{ "id": reader, "name": "Reader" }]));
        assert_eq!(
            pkg["groups"],
            json!([{ "id": engineering, "name": "Engineering" }])
        );
        assert_eq!(pkg["approverGroupName"], json!("Approvers"));
        assert_eq!(pkg["pending"]["id"], json!(first_id));
        assert!(pkg.get("assignment").is_none());
        assert!(pkg.get("autoAssign").is_none() && pkg.get("roleIds").is_none());
        // Deciding takes iam:packages:approve and membership of the approver group; nobody decides on their own.
        fails(
            api!(
                f,
                packages.approve_request,
                &as_alice,
                json!({ "tenantId": tenant, "requestId": first_id })
            ),
            "ACCESS_DENIED",
        );
        let error = fails(
            api!(
                f,
                packages.approve_request,
                &owner,
                json!({ "tenantId": tenant, "requestId": first_id })
            ),
            "ACCESS_DENIED",
        );
        assert_eq!(error.message, "Only the designated approvers may decide");
        assert_eq!(
            ids(&ok(api!(
                f,
                packages.list_approvals,
                &as_bob,
                json!({ "tenantId": tenant })
            ))),
            vec![first_id.clone()]
        );
        let approved = ok(api!(
            f,
            packages.approve_request,
            &as_bob,
            json!({ "tenantId": tenant, "requestId": first_id, "note": "Welcome" })
        ));
        assert_matches(
            &approved,
            json!({ "status": "approved", "decidedBy": bob, "note": "Welcome" }),
        );
        assert!(can(&f, &as_alice, "documents:read").await);
        let assignment = ok(api!(
            f,
            packages.list_assignments,
            &owner,
            json!({ "tenantId": tenant, "packageId": kit_id })
        ))[0]
            .clone();
        assert_matches(
            &assignment,
            json!({
                "id": approved["assignmentId"],
                "identityId": alice,
                "assignedBy": bob,
                "expiresAt": num(f.now() + 10.0 * DAY),
                "justification": "Joining the platform team",
            }),
        );
        f.iam.auth.dispatch_outbox(None).await.unwrap();
        let decided: Vec<(String, Value, Value)> = sent(&inbox, "package-decided")
            .iter()
            .map(|message| {
                (
                    message.to.clone(),
                    message
                        .payload
                        .get("decision")
                        .cloned()
                        .unwrap_or(Value::Null),
                    message.payload.get("note").cloned().unwrap_or(Value::Null),
                )
            })
            .collect();
        assert_eq!(
            decided,
            vec![(
                "alice@acme.test".to_owned(),
                json!("approved"),
                json!("Welcome")
            )]
        );
        assert_eq!(
            ok(api!(
                f,
                packages.list_approvals,
                &as_bob,
                json!({ "tenantId": tenant })
            )),
            json!([])
        );
        let mine = ok(api!(
            f,
            packages.list_mine,
            &as_alice,
            json!({ "tenantId": tenant })
        ));
        assert_eq!(
            mine["packages"][0]["assignment"]["id"],
            approved["assignmentId"]
        );
        fails(
            request(
                &as_alice,
                json!({ "justification": "more", "expiresAt": num(f.now() + DAY) }),
            )
            .await,
            "CONFLICT",
        );
        fails(
            api!(
                f,
                packages.approve_request,
                &as_bob,
                json!({ "tenantId": tenant, "requestId": first_id })
            ),
            "INVALID_TRANSITION",
        );
        // Bob is the only approver, and nobody decides on their own request: his request could reach no one.
        fails(
            request(
                &as_bob,
                json!({ "justification": "Me too", "expiresAt": num(f.now() + DAY) }),
            )
            .await,
            "INVALID_TRANSITION",
        );
        // Cancelling, denying, and lapsing.
        let dave = f.member("dave").await;
        add_member(&f, &everyone, &dave).await;
        let as_dave = f.sign_in(&dave).await;
        let second = ok(request(
            &as_dave,
            json!({ "justification": "Me too", "expiresAt": num(f.now() + DAY) }),
        )
        .await);
        fails(
            api!(
                f,
                packages.cancel_request,
                &as_alice,
                json!({ "tenantId": tenant, "requestId": second["id"] })
            ),
            "ACCESS_DENIED",
        );
        assert_eq!(
            ok(api!(
                f,
                packages.cancel_request,
                &as_dave,
                json!({ "tenantId": tenant, "requestId": second["id"] })
            ))["status"],
            json!("cancelled")
        );
        let third = ok(request(
            &as_dave,
            json!({ "justification": "Curious", "expiresAt": num(f.now() + DAY) }),
        )
        .await);
        let denied = ok(api!(
            f,
            packages.deny_request,
            &as_bob,
            json!({ "tenantId": tenant, "requestId": third["id"], "note": "Not yet" })
        ));
        assert_matches(
            &denied,
            json!({ "status": "denied", "decidedBy": bob, "note": "Not yet" }),
        );
        f.iam.auth.dispatch_outbox(None).await.unwrap();
        let last = sent(&inbox, "package-decided").last().cloned().unwrap();
        assert_eq!(last.to, "dave@acme.test");
        assert_eq!(last.payload.get("decision"), Some(&json!("denied")));
        assert_eq!(last.payload.get("note"), Some(&json!("Not yet")));
        let erin = f.member("erin").await;
        add_member(&f, &everyone, &erin).await;
        let as_erin = f.sign_in(&erin).await;
        let fourth = ok(request(
            &as_erin,
            json!({ "justification": "Later", "expiresAt": num(f.now() + 5.0 * DAY) }),
        )
        .await);
        f.advance(DAY + 1.0);
        assert_eq!(
            f.iam.purge_deleted(None).await.unwrap()["expiredRequests"],
            json!(1)
        );
        fails(
            api!(
                f,
                packages.approve_request,
                &as_bob,
                json!({ "tenantId": tenant, "requestId": fourth["id"] })
            ),
            "INVALID_TRANSITION",
        );
        let admin = f.sign_in(&f.owner_id).await;
        assert_eq!(
            ids(&ok(api!(
                f,
                packages.list_requests,
                &admin,
                json!({ "tenantId": tenant, "status": "expired" })
            ))),
            vec![id_of(&fourth)]
        );
        let statuses = ok(api!(
            f,
            packages.list_requests,
            &admin,
            json!({ "tenantId": tenant, "packageId": kit_id })
        ));
        assert_eq!(
            sorted(
                statuses
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|item| item["status"].as_str().unwrap().to_owned())
                    .collect()
            ),
            vec!["approved", "cancelled", "denied", "expired"]
        );
        fails(
            api!(
                f,
                packages.list_requests,
                &admin,
                json!({ "tenantId": tenant, "status": "waiting" })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(audit_count(&f, "package:request-approved").await, 1);
        // The owner revokes what the approver granted (the assignment owns its records), then deletes the package.
        assert_eq!(
            ok(api!(
                f,
                packages.revoke,
                &admin,
                json!({ "tenantId": tenant, "packageId": kit_id, "identityId": alice })
            )),
            json!({ "revoked": true, "bindings": 1, "memberships": 1 })
        );
        assert!(!can(&f, &as_alice, "documents:read").await);
        ok(api!(
            f,
            packages.delete,
            &admin,
            json!({ "tenantId": tenant, "packageId": kit_id })
        ));
        assert_eq!(
            ok(api!(
                f,
                packages.list_requests,
                &admin,
                json!({ "tenantId": tenant })
            )),
            json!([])
        );
    });
}

// --- tests/package-review-requests.test.ts ---------------------------------------------------------------------

/// A tenant with a Reader role and members who may request packages (through an Everyone group).
struct Requesters {
    f: Org,
    tenant: String,
    owner: CredentialInput,
    reader: String,
    people: Vec<(String, String, CredentialInput)>,
}

impl Requesters {
    fn person(&self, name: &str) -> (&String, &CredentialInput) {
        let (_, id, credential) = self
            .people
            .iter()
            .find(|(person, _, _)| person == name)
            .unwrap();
        (id, credential)
    }

    async fn kit(&self, extra: Value) -> String {
        let mut input = json!({
            "tenantId": self.tenant,
            "name": "Kit",
            "roleIds": [self.reader],
            "requestable": true,
        });
        for (key, value) in extra.as_object().unwrap() {
            input[key] = value.clone();
        }
        id_of(&ok(api!(self.f, packages.create, &self.owner, input)))
    }

    async fn request(&self, name: &str, package_id: &str, extra: Value) -> Value {
        let mut input = json!({ "tenantId": self.tenant, "packageId": package_id });
        for (key, value) in extra.as_object().unwrap() {
            input[key] = value.clone();
        }
        let (_, credential) = self.person(name);
        ok(api!(self.f, packages.request, credential, input))
    }

    async fn approvals(&self) -> Vec<String> {
        sorted(ids(&ok(api!(
            self.f,
            packages.list_approvals,
            &self.owner,
            json!({ "tenantId": self.tenant })
        ))))
    }

    async fn requests(&self, filter: Value) -> Value {
        let mut input = json!({ "tenantId": self.tenant });
        for (key, value) in filter.as_object().unwrap() {
            input[key] = value.clone();
        }
        ok(api!(self.f, packages.list_requests, &self.owner, input))
    }

    async fn update(&self, package_id: &str, changes: Value) -> Value {
        let mut input = json!({ "tenantId": self.tenant, "packageId": package_id });
        for (key, value) in changes.as_object().unwrap() {
            input[key] = value.clone();
        }
        ok(api!(self.f, packages.update, &self.owner, input))
    }

    async fn decide(&self, approve: bool, request_id: &Value) -> IamResult<Value> {
        let input = json!({ "tenantId": self.tenant, "requestId": request_id });
        if approve {
            api!(self.f, packages.approve_request, &self.owner, input)
        } else {
            api!(self.f, packages.deny_request, &self.owner, input)
        }
    }
}

async fn requesters(names: &[&str]) -> Requesters {
    let (f, _) = fixture().await;
    let reader = role(&f, "Reader", json!(["documents:read"])).await;
    let requester = role(&f, "Requester", json!(["iam:packages:request"])).await;
    let everyone = group(&f, "Everyone").await;
    bind(&f, &requester, "group", &everyone).await;
    let mut people = Vec::new();
    for name in names {
        let identity = f.member(name).await;
        add_member(&f, &everyone, &identity).await;
        let credential = f.sign_in(&identity).await;
        people.push(((*name).to_owned(), identity, credential));
    }
    Requesters {
        tenant: f.tenant_id.clone(),
        owner: f.owner_credential.clone(),
        f,
        reader,
        people,
    }
}

fn by_id(list: &Value) -> std::collections::HashMap<String, Value> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|item| (id_of(item), item.clone()))
        .collect()
}

#[test]
fn a_request_never_lapses_later_than_the_end_the_requester_asks_for() {
    run(|| async {
        let r = requesters(&["alice", "bob"]).await;
        let f = &r.f;
        let kit = r.kit(json!({})).await;
        let start = f.now();
        // Control: an end beyond the (default 24h) approval lifetime lapses at the lifetime.
        let long = r
            .request("bob", &kit, json!({ "expiresAt": num(start + 3.0 * DAY) }))
            .await;
        assert_matches(
            &long,
            json!({ "status": "pending", "desiredExpiresAt": num(start + 3.0 * DAY), "expiresAt": num(start + DAY) }),
        );
        // An end shorter than the lifetime is the lapse time.
        let short = r
            .request(
                "alice",
                &kit,
                json!({ "expiresAt": num(start + 4.0 * HOUR) }),
            )
            .await;
        assert_matches(
            &short,
            json!({ "status": "pending", "desiredExpiresAt": num(start + 4.0 * HOUR), "expiresAt": num(start + 4.0 * HOUR) }),
        );
        let short_id = id_of(&short);
        assert_eq!(
            get(f, "packageRequests", &short_id).await.unwrap()["expiresAt"],
            num(start + 4.0 * HOUR)
        );
        // Still awaiting a decision before its end.
        f.advance(3.0 * HOUR);
        assert_eq!(
            r.approvals().await,
            sorted(vec![id_of(&long), short_id.clone()])
        );
        // Past the end it asked for, it no longer waits for anyone.
        f.advance(2.0 * HOUR);
        assert_eq!(r.approvals().await, vec![id_of(&long)]);
        fails(r.decide(true, &short["id"]).await, "INVALID_TRANSITION");
        fails(r.decide(false, &short["id"]).await, "INVALID_TRANSITION");
        // Nor can the requester withdraw it: it is no longer awaiting a decision.
        let (alice, as_alice) = r.person("alice");
        fails(
            api!(
                f,
                packages.cancel_request,
                as_alice,
                json!({ "tenantId": r.tenant, "requestId": short_id })
            ),
            "INVALID_TRANSITION",
        );
        // It is reported as expired (the worker has not run yet), and the requester sees nothing pending.
        assert_eq!(
            stored_status(f, &short_id).await.as_deref(),
            Some("pending")
        );
        let listed = r.requests(json!({ "identityId": alice })).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_matches(&listed[0], json!({ "id": short_id, "status": "expired" }));
        let mine = ok(api!(
            f,
            packages.list_mine,
            as_alice,
            json!({ "tenantId": r.tenant })
        ));
        let pkg = mine["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|pkg| pkg["id"] == json!(kit))
            .unwrap();
        assert!(pkg.get("pending").is_none());
        assert_eq!(mine["requests"].as_array().unwrap().len(), 1);
        assert_matches(
            &mine["requests"][0],
            json!({ "id": short_id, "status": "expired" }),
        );
        // The failed approval granted nothing.
        assert!(!can(f, as_alice, "documents:read").await);
        // The requester may ask again.
        let again = r
            .request(
                "alice",
                &kit,
                json!({ "expiresAt": num(f.now() + 4.0 * HOUR) }),
            )
            .await;
        assert_matches(
            &again,
            json!({ "status": "pending", "expiresAt": num(f.now() + 4.0 * HOUR) }),
        );
        assert_ne!(id_of(&again), short_id);
        assert_eq!(
            r.approvals().await,
            sorted(vec![id_of(&long), id_of(&again)])
        );
        // The worker then marks the lapsed one.
        assert_eq!(
            f.iam.purge_deleted(None).await.unwrap()["expiredRequests"],
            json!(1)
        );
        assert_eq!(
            stored_status(f, &short_id).await.as_deref(),
            Some("expired")
        );
    });
}

#[test]
fn reports_a_lapsed_pending_request_as_expired_before_the_worker_runs() {
    run(|| async {
        let r = requesters(&["alice", "bob"]).await;
        let f = &r.f;
        let kit = r.kit(json!({})).await;
        let lapsing = r.request("alice", &kit, json!({})).await;
        let lapsing_id = id_of(&lapsing);
        assert_eq!(lapsing["expiresAt"], num(f.now() + DAY));
        // At exactly its lapse time it is expired, as the purge worker and listApprovals count it.
        f.advance(DAY);
        let listed = r.requests(json!({})).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_matches(&listed[0], json!({ "id": lapsing_id, "status": "expired" }));
        assert_eq!(r.requests(json!({ "status": "pending" })).await, json!([]));
        assert!(r.approvals().await.is_empty());
        f.advance(1.0);
        // A fresh request that is genuinely still pending.
        let fresh = r.request("bob", &kit, json!({})).await;
        let fresh_id = id_of(&fresh);
        // The store still says pending: the purge worker has not run.
        assert_eq!(
            stored_status(f, &lapsing_id).await.as_deref(),
            Some("pending")
        );
        let all = by_id(&r.requests(json!({})).await);
        assert_eq!(all.len(), 2);
        assert_eq!(all[&lapsing_id]["status"], json!("expired"));
        assert_eq!(all[&fresh_id]["status"], json!("pending"));
        assert_eq!(
            ids(&r.requests(json!({ "status": "pending" })).await),
            vec![fresh_id.clone()]
        );
        assert_eq!(
            ids(&r.requests(json!({ "status": "expired" })).await),
            vec![lapsing_id.clone()]
        );
        // The same holds when filtered by package or by identity.
        assert_eq!(
            ids(&r
                .requests(json!({ "packageId": kit, "status": "pending" }))
                .await),
            vec![fresh_id.clone()]
        );
        let (alice, as_alice) = r.person("alice");
        assert!(
            ids(&r
                .requests(json!({ "identityId": alice, "status": "pending" }))
                .await)
            .is_empty()
        );
        assert_eq!(
            ids(&r
                .requests(json!({ "identityId": alice, "status": "expired" }))
                .await),
            vec![lapsing_id.clone()]
        );
        // The requester's own view agrees.
        let mine = ok(api!(
            f,
            packages.list_mine,
            as_alice,
            json!({ "tenantId": r.tenant })
        ));
        assert_eq!(ids(&mine["requests"]), vec![lapsing_id.clone()]);
        assert_eq!(mine["requests"][0]["status"], json!("expired"));
        assert!(mine["packages"][0].get("pending").is_none());
        // After the worker marks it, the listing is unchanged.
        assert_eq!(
            f.iam.purge_deleted(None).await.unwrap()["expiredRequests"],
            json!(1)
        );
        assert_eq!(
            stored_status(f, &lapsing_id).await.as_deref(),
            Some("expired")
        );
        assert_eq!(
            ids(&r.requests(json!({ "status": "expired" })).await),
            vec![lapsing_id]
        );
        assert_eq!(
            ids(&r.requests(json!({ "status": "pending" })).await),
            vec![fresh_id]
        );
    });
}

#[test]
fn update_leaves_pending_requests_alone_when_the_rules_are_not_tightened() {
    run(|| async {
        let r = requesters(&["alice"]).await;
        let kit = r.kit(json!({})).await;
        let request = r.request("alice", &kit, json!({})).await;
        r.update(
            &kit,
            json!({
                "name": "Renamed kit",
                "description": "Same rules",
                "requestable": true,
                "requireJustification": false,
            }),
        )
        .await;
        assert_eq!(
            stored_status(&r.f, &id_of(&request)).await.as_deref(),
            Some("pending")
        );
        assert_eq!(r.approvals().await, vec![id_of(&request)]);
    });
}

#[test]
fn requestable_false_cancels_every_pending_request_with_a_note() {
    run(|| async {
        let r = requesters(&["alice", "bob"]).await;
        let f = &r.f;
        let kit = r.kit(json!({})).await;
        let first = r
            .request(
                "alice",
                &kit,
                json!({ "justification": "Needed for the audit", "expiresAt": num(f.now() + 2.0 * DAY) }),
            )
            .await;
        let second = r.request("bob", &kit, json!({})).await;
        // A request for another package is not touched by this package's change.
        let other = r.kit(json!({ "name": "Other" })).await;
        let elsewhere = r.request("alice", &other, json!({})).await;
        f.advance(1000.0);
        r.update(&kit, json!({ "requestable": false })).await;
        let listed = r.requests(json!({ "packageId": kit })).await;
        assert_eq!(listed.as_array().unwrap().len(), 2);
        for item in listed.as_array().unwrap() {
            assert_eq!(item["status"], json!("cancelled"));
            assert_eq!(item["decidedAt"], num(f.now()));
            assert_eq!(
                item["note"],
                json!("The package can no longer be requested")
            );
        }
        assert_eq!(
            sorted(ids(&listed)),
            sorted(vec![id_of(&first), id_of(&second)])
        );
        assert_eq!(
            stored_status(f, &id_of(&first)).await.as_deref(),
            Some("cancelled")
        );
        assert_eq!(
            stored_status(f, &id_of(&second)).await.as_deref(),
            Some("cancelled")
        );
        assert_eq!(
            stored_status(f, &id_of(&elsewhere)).await.as_deref(),
            Some("pending")
        );
        assert_eq!(r.approvals().await, vec![id_of(&elsewhere)]);
        for cancelled in [&first, &second] {
            fails(r.decide(true, &cancelled["id"]).await, "INVALID_TRANSITION");
            fails(
                r.decide(false, &cancelled["id"]).await,
                "INVALID_TRANSITION",
            );
        }
        // Making it requestable again does not revive them; the requester asks anew.
        r.update(&kit, json!({ "requestable": true })).await;
        assert_eq!(
            stored_status(f, &id_of(&first)).await.as_deref(),
            Some("cancelled")
        );
        let again = r.request("alice", &kit, json!({})).await;
        assert_eq!(again["status"], json!("pending"));
    });
}

#[test]
fn require_justification_cancels_only_the_requests_without_a_justification() {
    run(|| async {
        let r = requesters(&["alice", "bob"]).await;
        let f = &r.f;
        let kit = r.kit(json!({})).await;
        let justified = r
            .request(
                "alice",
                &kit,
                json!({ "justification": "On-call rotation" }),
            )
            .await;
        let unjustified = r.request("bob", &kit, json!({})).await;
        r.update(&kit, json!({ "requireJustification": true }))
            .await;
        let listed = by_id(&r.requests(json!({ "packageId": kit })).await);
        assert_eq!(listed[&id_of(&justified)]["status"], json!("pending"));
        assert!(listed[&id_of(&justified)].get("note").is_none());
        assert_matches(
            &listed[&id_of(&unjustified)],
            json!({
                "status": "cancelled",
                "decidedAt": num(f.now()),
                "note": "The package now requires a justification",
            }),
        );
        assert_eq!(r.approvals().await, vec![id_of(&justified)]);
        // The one that fits can still be approved.
        assert_eq!(
            ok(r.decide(true, &justified["id"]).await)["status"],
            json!("approved")
        );
        // The cancelled requester may ask again, now with a justification.
        let again = r
            .request("bob", &kit, json!({ "justification": "Now justified" }))
            .await;
        assert_eq!(again["status"], json!("pending"));
    });
}

#[test]
fn a_new_max_duration_cancels_open_ended_requests_and_those_ending_beyond_it() {
    run(|| async {
        let r = requesters(&["alice", "bob", "carol", "dave"]).await;
        let f = &r.f;
        let kit = r.kit(json!({})).await;
        let open_ended = r.request("alice", &kit, json!({})).await;
        let too_long = r
            .request(
                "bob",
                &kit,
                json!({ "expiresAt": num(f.now() + 10.0 * DAY) }),
            )
            .await;
        let fits = r
            .request(
                "carol",
                &kit,
                json!({ "expiresAt": num(f.now() + 2.0 * DAY) }),
            )
            .await;
        // Asks to end 5d + 1h out; the cap arrives an hour later, so the end is exactly now + max: it still fits.
        let edge = r
            .request(
                "dave",
                &kit,
                json!({ "expiresAt": num(f.now() + 5.0 * DAY + HOUR) }),
            )
            .await;
        f.advance(HOUR);
        r.update(&kit, json!({ "maxDurationMs": num(5.0 * DAY) }))
            .await;
        let listed = by_id(&r.requests(json!({ "packageId": kit })).await);
        for cancelled in [&open_ended, &too_long] {
            assert_matches(
                &listed[&id_of(cancelled)],
                json!({
                    "status": "cancelled",
                    "decidedAt": num(f.now()),
                    "note": "The requested end no longer fits the package",
                }),
            );
            assert_eq!(
                stored_status(f, &id_of(cancelled)).await.as_deref(),
                Some("cancelled")
            );
        }
        for kept in [&fits, &edge] {
            assert_eq!(listed[&id_of(kept)]["status"], json!("pending"));
            assert!(listed[&id_of(kept)].get("note").is_none());
        }
        assert_eq!(
            r.approvals().await,
            sorted(vec![id_of(&fits), id_of(&edge)])
        );
        // The fitting ones can be approved as the console sends it (no override end).
        assert_eq!(
            ok(r.decide(true, &fits["id"]).await)["status"],
            json!("approved")
        );
        assert_eq!(
            ok(r.decide(true, &edge["id"]).await)["status"],
            json!("approved")
        );
        // A cancelled one cannot be.
        fails(r.decide(true, &too_long["id"]).await, "INVALID_TRANSITION");
    });
}

#[test]
fn lowering_max_duration_cancels_requests_whose_end_now_exceeds_it() {
    run(|| async {
        let r = requesters(&["alice", "bob"]).await;
        let f = &r.f;
        let kit = r.kit(json!({ "maxDurationMs": num(30.0 * DAY) })).await;
        let long = r
            .request(
                "alice",
                &kit,
                json!({ "expiresAt": num(f.now() + 20.0 * DAY) }),
            )
            .await;
        let short = r
            .request(
                "bob",
                &kit,
                json!({ "expiresAt": num(f.now() + 3.0 * DAY) }),
            )
            .await;
        r.update(&kit, json!({ "maxDurationMs": num(7.0 * DAY) }))
            .await;
        assert_eq!(
            stored_status(f, &id_of(&long)).await.as_deref(),
            Some("cancelled")
        );
        assert_eq!(
            stored_status(f, &id_of(&short)).await.as_deref(),
            Some("pending")
        );
    });
}

#[test]
fn update_does_not_rewrite_a_lapsed_request_into_a_cancellation() {
    run(|| async {
        let r = requesters(&["alice", "bob"]).await;
        let f = &r.f;
        let kit = r.kit(json!({})).await;
        let lapsed = r.request("alice", &kit, json!({})).await;
        f.advance(DAY + HOUR);
        let live = r.request("bob", &kit, json!({})).await;
        let (alice, _) = r.person("alice");
        assert_eq!(
            r.requests(json!({ "identityId": alice })).await[0]["status"],
            json!("expired")
        );
        r.update(&kit, json!({ "requestable": false })).await;
        // The live one is cancelled by the change...
        assert_eq!(
            stored_status(f, &id_of(&live)).await.as_deref(),
            Some("cancelled")
        );
        // ...but the one that had already lapsed stays expired: the change did not end it.
        let reported = r.requests(json!({ "identityId": alice })).await[0].clone();
        assert_matches(
            &reported,
            json!({ "id": id_of(&lapsed), "status": "expired" }),
        );
        assert!(reported.get("decidedAt").is_none());
        assert!(reported.get("note").is_none());
        assert_eq!(
            f.iam.purge_deleted(None).await.unwrap()["expiredRequests"],
            json!(1)
        );
        assert_eq!(
            stored_status(f, &id_of(&lapsed)).await.as_deref(),
            Some("expired")
        );
    });
}

#[test]
fn refuses_approval_for_a_package_no_longer_requestable_but_still_allows_denial() {
    run(|| async {
        let r = requesters(&["alice", "bob"]).await;
        let f = &r.f;
        let kit = r.kit(json!({})).await;
        let first = r.request("alice", &kit, json!({})).await;
        let second = r.request("bob", &kit, json!({})).await;
        // Flip requestable off behind the API, so the pending requests are not cancelled by packages.update.
        let mut stored = get(f, "accessPackages", &kit).await.unwrap();
        assert_eq!(stored["requestable"], json!(true));
        stored.shift_remove("requestable");
        f.put("accessPackages", stored).await;
        assert_eq!(
            stored_status(f, &id_of(&first)).await.as_deref(),
            Some("pending")
        );
        let error = fails(r.decide(true, &first["id"]).await, "INVALID_TRANSITION");
        assert_eq!(error.message, "The package is no longer requestable");
        fails(
            api!(
                f,
                packages.approve_request,
                &r.owner,
                json!({ "tenantId": r.tenant, "requestId": first["id"], "expiresAt": num(f.now() + DAY) })
            ),
            "INVALID_TRANSITION",
        );
        // Nothing was granted and the request is still pending.
        assert_eq!(
            stored_status(f, &id_of(&first)).await.as_deref(),
            Some("pending")
        );
        assert_eq!(
            ok(api!(
                f,
                packages.list_assignments,
                &r.owner,
                json!({ "tenantId": r.tenant, "packageId": kit })
            )),
            json!([])
        );
        let (_, as_alice) = r.person("alice");
        assert!(!can(f, as_alice, "documents:read").await);
        // Denying still works.
        let denied = ok(api!(
            f,
            packages.deny_request,
            &r.owner,
            json!({ "tenantId": r.tenant, "requestId": first["id"], "note": "No longer offered" })
        ));
        assert_matches(
            &denied,
            json!({ "status": "denied", "decidedBy": f.owner_id, "note": "No longer offered" }),
        );
        assert_eq!(
            stored_status(f, &id_of(&first)).await.as_deref(),
            Some("denied")
        );
        assert_eq!(
            ok(r.decide(false, &second["id"]).await)["status"],
            json!("denied")
        );
    });
}

// --- tests/package-review-integrity.test.ts --------------------------------------------------------------------

#[test]
fn a_package_adds_its_own_binding_beside_a_direct_one_and_leaves_it_on_revoke() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let kit = id_of(
            &s.package(json!({ "name": "Kit", "roleIds": [s.reader] }))
                .await,
        );
        let bob = f.member("bob").await;
        let direct = bind(f, &s.reader, "identity", &bob).await;
        let assigned = ok(s
            .assign(json!({ "packageId": kit, "identityId": bob }))
            .await);
        assert_eq!(
            assigned["created"],
            json!({ "bindings": 1, "memberships": 0 })
        );
        assert_eq!(assigned["skipped"], json!([]));
        let binding_ids = assigned["bindingIds"].as_array().unwrap();
        assert_eq!(binding_ids.len(), 1);
        assert!(!binding_ids.contains(&direct["id"]));
        assert_eq!(
            get(f, "bindings", binding_ids[0].as_str().unwrap())
                .await
                .unwrap()["packageAssignmentId"],
            assigned["id"]
        );
        assert_eq!(
            ok(s.revoke(&kit, &bob).await),
            json!({ "revoked": true, "bindings": 1, "memberships": 0 })
        );
        assert!(get(f, "bindings", &id_of(&direct)).await.is_some());
        assert!(can(f, &f.sign_in(&bob).await, "documents:read").await);
    });
}

#[test]
fn a_direct_binding_of_a_packaged_role_is_allowed_and_kept_on_revoke() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let kit = id_of(
            &s.package(json!({ "name": "Kit", "roleIds": [s.reader] }))
                .await,
        );
        let alice = f.member("alice").await;
        ok(s.assign(json!({ "packageId": kit, "identityId": alice }))
            .await);
        let direct = bind(f, &s.reader, "identity", &alice).await;
        assert!(direct.get("packageAssignmentId").is_none());
        assert_eq!(
            ok(s.revoke(&kit, &alice).await),
            json!({ "revoked": true, "bindings": 1, "memberships": 0 })
        );
        assert!(get(f, "bindings", &id_of(&direct)).await.is_some());
        assert!(can(f, &f.sign_in(&alice).await, "documents:read").await);
    });
}

#[test]
fn two_packages_with_the_same_role_each_get_their_own_binding() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let project = id_of(
            &s.package(json!({ "name": "Project", "roleIds": [s.reader] }))
                .await,
        );
        let base = id_of(
            &s.package(json!({ "name": "Base", "roleIds": [s.reader] }))
                .await,
        );
        let alice = f.member("alice").await;
        let temporary = ok(s
            .assign(json!({ "packageId": project, "identityId": alice, "expiresAt": num(f.now() + DAY) }))
            .await);
        let permanent = ok(s
            .assign(json!({ "packageId": base, "identityId": alice }))
            .await);
        assert_eq!(
            permanent["created"],
            json!({ "bindings": 1, "memberships": 0 })
        );
        assert_eq!(permanent["skipped"], json!([]));
        assert!(
            !permanent["bindingIds"]
                .as_array()
                .unwrap()
                .contains(&temporary["bindingIds"][0])
        );
        let permanent_binding = permanent["bindingIds"][0].as_str().unwrap().to_owned();
        assert!(
            get(f, "bindings", &permanent_binding)
                .await
                .unwrap()
                .get("expiresAt")
                .is_none()
        );
        // Project ends; Base still grants Reader through its own binding.
        f.advance(2.0 * DAY);
        let as_alice = f.sign_in(&alice).await;
        assert!(can(f, &as_alice, "documents:read").await);
        assert_eq!(
            ok(s.revoke(&project, &alice).await),
            json!({ "revoked": true, "bindings": 1, "memberships": 0 })
        );
        assert!(get(f, "bindings", &permanent_binding).await.is_some());
        assert!(can(f, &as_alice, "documents:read").await);
    });
}

#[test]
fn records_edited_by_hand_after_the_assignment_ended_leave_the_package() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let kit = id_of(
            &s.package(
                json!({ "name": "Kit", "roleIds": [s.reader], "groupIds": [s.engineering] }),
            )
            .await,
        );
        let alice = f.member("alice").await;
        let assigned = ok(s
            .assign(
                json!({ "packageId": kit, "identityId": alice, "expiresAt": num(f.now() + HOUR) }),
            )
            .await);
        assert_eq!(
            assigned["created"],
            json!({ "bindings": 1, "memberships": 1 })
        );
        f.advance(2.0 * HOUR);
        let as_alice = f.sign_in(&alice).await;
        assert!(!can(f, &as_alice, "documents:read").await);
        assert!(!can(f, &as_alice, "documents:write").await);
        // The owner puts alice back in Engineering by hand and makes the old package binding permanent.
        add_member(f, &s.engineering, &alice).await;
        let renewed = membership(f, &s.engineering, &alice).await.unwrap();
        assert!(renewed.get("packageAssignmentId").is_none());
        assert!(renewed.get("expiresAt").is_none());
        let binding_id = assigned["bindingIds"][0].as_str().unwrap().to_owned();
        ok(api!(
            f,
            bindings.update,
            &s.owner,
            json!({ "tenantId": s.tenant, "bindingId": binding_id, "expiresAt": null })
        ));
        let edited = get(f, "bindings", &binding_id).await.unwrap();
        assert!(edited.get("packageAssignmentId").is_none());
        assert!(edited.get("expiresAt").is_none());
        // Cleaning up the ended assignment no longer takes them away.
        assert_eq!(
            ok(s.revoke(&kit, &alice).await),
            json!({ "revoked": true, "bindings": 0, "memberships": 0 })
        );
        assert!(get(f, "bindings", &binding_id).await.is_some());
        assert!(membership(f, &s.engineering, &alice).await.is_some());
        assert!(can(f, &as_alice, "documents:read").await);
        assert!(can(f, &as_alice, "documents:write").await);
    });
}

#[test]
fn groups_update_member_takes_a_package_membership_over() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let kit = id_of(
            &s.package(json!({ "name": "Kit", "groupIds": [s.engineering] }))
                .await,
        );
        let alice = f.member("alice").await;
        let assigned = ok(s
            .assign(
                json!({ "packageId": kit, "identityId": alice, "expiresAt": num(f.now() + HOUR) }),
            )
            .await);
        assert_eq!(
            membership(f, &s.engineering, &alice).await.unwrap()["packageAssignmentId"],
            assigned["id"]
        );
        ok(api!(
            f,
            groups.update_member,
            &s.owner,
            json!({ "tenantId": s.tenant, "groupId": s.engineering, "identityId": alice, "expiresAt": null })
        ));
        let taken = membership(f, &s.engineering, &alice).await.unwrap();
        assert!(taken.get("packageAssignmentId").is_none());
        assert!(taken.get("expiresAt").is_none());
        f.advance(2.0 * HOUR);
        assert_eq!(
            ok(s.revoke(&kit, &alice).await),
            json!({ "revoked": true, "bindings": 0, "memberships": 0 })
        );
        assert!(in_group(f, &s.engineering, "alice").await);
        assert!(can(f, &f.sign_in(&alice).await, "documents:write").await);
    });
}

/// Two packages ("Short", "Long") of the Engineering group, and alice.
async fn shared() -> (Setup, String, String, String) {
    let s = setup().await;
    let short = id_of(
        &s.package(json!({ "name": "Short", "groupIds": [s.engineering] }))
            .await,
    );
    let long = id_of(
        &s.package(json!({ "name": "Long", "groupIds": [s.engineering] }))
            .await,
    );
    let alice = s.f.member("alice").await;
    (s, short, long, alice)
}

#[test]
fn the_longer_assignment_owns_a_shared_membership_and_hands_it_over_on_revoke() {
    run(|| async {
        let (s, short, long, alice) = shared().await;
        let f = &s.f;
        let a = ok(s
            .assign(
                json!({ "packageId": short, "identityId": alice, "expiresAt": num(f.now() + DAY) }),
            )
            .await);
        let b = ok(s
            .assign(json!({ "packageId": long, "identityId": alice }))
            .await);
        assert_eq!(b["skipped"], json!([]));
        let record = membership(f, &s.engineering, &alice).await.unwrap();
        assert_eq!(record["packageAssignmentId"], b["id"]);
        assert!(record.get("expiresAt").is_none());
        assert_eq!(
            f.find(
                "groupMembers",
                Filter::new()
                    .eq("tenantId", s.tenant.clone())
                    .eq("groupId", s.engineering.clone())
                    .eq("identityId", alice.clone())
            )
            .await
            .len(),
            1
        );
        // Revoking the owner of the record hands it to the live survivor, with the survivor's end.
        ok(s.revoke(&long, &alice).await);
        let handed = membership(f, &s.engineering, &alice).await.unwrap();
        assert_eq!(handed["id"], record["id"]);
        assert_eq!(handed["packageAssignmentId"], a["id"]);
        assert_eq!(handed["expiresAt"], a["expiresAt"]);
        assert!(in_group(f, &s.engineering, "alice").await);
        let as_alice = f.sign_in(&alice).await;
        assert!(can(f, &as_alice, "documents:write").await);
        // Revoking the last one removes it.
        assert_eq!(
            ok(s.revoke(&short, &alice).await),
            json!({ "revoked": true, "bindings": 0, "memberships": 1 })
        );
        assert!(membership(f, &s.engineering, &alice).await.is_none());
        assert!(!can(f, &as_alice, "documents:write").await);
    });
}

#[test]
fn revoking_the_shorter_assignment_first_leaves_the_longer_one_its_membership() {
    run(|| async {
        let (s, short, long, alice) = shared().await;
        let f = &s.f;
        ok(s.assign(
            json!({ "packageId": short, "identityId": alice, "expiresAt": num(f.now() + DAY) }),
        )
        .await);
        let b = ok(s
            .assign(json!({ "packageId": long, "identityId": alice }))
            .await);
        assert_eq!(
            ok(s.revoke(&short, &alice).await),
            json!({ "revoked": true, "bindings": 0, "memberships": 0 })
        );
        let kept = membership(f, &s.engineering, &alice).await.unwrap();
        assert_eq!(kept["packageAssignmentId"], b["id"]);
        assert!(kept.get("expiresAt").is_none());
        assert!(in_group(f, &s.engineering, "alice").await);
        f.advance(2.0 * DAY);
        assert!(in_group(f, &s.engineering, "alice").await);
        assert_eq!(
            ok(s.revoke(&long, &alice).await),
            json!({ "revoked": true, "bindings": 0, "memberships": 1 })
        );
        assert!(membership(f, &s.engineering, &alice).await.is_none());
    });
}

#[test]
fn a_permanent_assignment_made_first_is_skipped_by_the_shorter_one() {
    run(|| async {
        let (s, short, long, alice) = shared().await;
        let f = &s.f;
        let b = ok(s
            .assign(json!({ "packageId": long, "identityId": alice }))
            .await);
        let a = ok(s
            .assign(
                json!({ "packageId": short, "identityId": alice, "expiresAt": num(f.now() + DAY) }),
            )
            .await);
        assert_eq!(
            a["skipped"],
            json!(["already a member of group Engineering (through package Long)"])
        );
        assert_eq!(
            membership(f, &s.engineering, &alice).await.unwrap()["packageAssignmentId"],
            b["id"]
        );
        ok(s.revoke(&long, &alice).await);
        let handed = membership(f, &s.engineering, &alice).await.unwrap();
        assert_eq!(handed["packageAssignmentId"], a["id"]);
        assert_eq!(handed["expiresAt"], a["expiresAt"]);
        assert!(in_group(f, &s.engineering, "alice").await);
        assert_eq!(
            ok(s.revoke(&short, &alice).await),
            json!({ "revoked": true, "bindings": 0, "memberships": 1 })
        );
        assert!(!in_group(f, &s.engineering, "alice").await);
    });
}

#[test]
fn shortening_an_assignment_hands_the_membership_to_one_that_needs_it_longer() {
    run(|| async {
        let (s, short, long, alice) = shared().await;
        let f = &s.f;
        // "Long" is permanent and owns the membership; "Short" lasts three days and is skipped.
        let permanent = ok(s
            .assign(json!({ "packageId": long, "identityId": alice }))
            .await);
        let three_days = ok(s
            .assign(json!({ "packageId": short, "identityId": alice, "expiresAt": num(f.now() + 3.0 * DAY) }))
            .await);
        assert_eq!(
            membership(f, &s.engineering, &alice).await.unwrap()["packageAssignmentId"],
            permanent["id"]
        );
        // Cut "Long" down to one day: the membership goes to "Short" (three days) instead of ending after one.
        let shortened = ok(api!(
            f,
            packages.extend,
            &s.owner,
            json!({ "tenantId": s.tenant, "packageId": long, "identityId": alice, "expiresAt": num(f.now() + DAY) })
        ));
        assert_eq!(shortened["expiresAt"], num(f.now() + DAY));
        let handed = membership(f, &s.engineering, &alice).await.unwrap();
        assert_eq!(handed["packageAssignmentId"], three_days["id"]);
        assert_eq!(handed["expiresAt"], three_days["expiresAt"]);
        f.advance(2.0 * DAY);
        assert!(in_group(f, &s.engineering, "alice").await);
        // Cleaning up the ended "Long" assignment leaves the membership "Short" now owns.
        assert_eq!(
            ok(s.revoke(&long, &alice).await),
            json!({ "revoked": true, "bindings": 0, "memberships": 0 })
        );
        assert!(in_group(f, &s.engineering, "alice").await);
        assert_eq!(
            ok(s.revoke(&short, &alice).await),
            json!({ "revoked": true, "bindings": 0, "memberships": 1 })
        );
        assert!(!in_group(f, &s.engineering, "alice").await);
    });
}

#[test]
fn a_permanent_hand_membership_is_skipped_and_survives_revoking_the_package() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let kit = id_of(
            &s.package(json!({ "name": "Kit", "groupIds": [s.engineering] }))
                .await,
        );
        let alice = f.member("alice").await;
        add_member(f, &s.engineering, &alice).await;
        let assigned = ok(s
            .assign(
                json!({ "packageId": kit, "identityId": alice, "expiresAt": num(f.now() + DAY) }),
            )
            .await);
        assert_eq!(
            assigned["skipped"],
            json!(["already a member of group Engineering"])
        );
        assert_eq!(
            assigned["created"],
            json!({ "bindings": 0, "memberships": 0 })
        );
        assert!(
            membership(f, &s.engineering, &alice)
                .await
                .unwrap()
                .get("packageAssignmentId")
                .is_none()
        );
        assert_eq!(
            ok(s.revoke(&kit, &alice).await),
            json!({ "revoked": true, "bindings": 0, "memberships": 0 })
        );
        assert!(in_group(f, &s.engineering, "alice").await);
        assert!(
            membership(f, &s.engineering, &alice)
                .await
                .unwrap()
                .get("expiresAt")
                .is_none()
        );
    });
}

#[test]
fn a_shorter_hand_membership_is_extended_to_the_assignment_end_and_belongs_to_it() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let kit = id_of(
            &s.package(json!({ "name": "Kit", "groupIds": [s.engineering] }))
                .await,
        );
        let bob = f.member("bob").await;
        ok(api!(
            f,
            groups.add_member,
            &s.owner,
            json!({ "tenantId": s.tenant, "groupId": s.engineering, "identityId": bob, "expiresAt": num(f.now() + DAY) })
        ));
        let before = membership(f, &s.engineering, &bob).await.unwrap();
        let assigned = ok(s
            .assign(json!({ "packageId": kit, "identityId": bob, "expiresAt": num(f.now() + 3.0 * DAY) }))
            .await);
        assert_eq!(assigned["skipped"], json!([]));
        assert_eq!(
            assigned["created"],
            json!({ "bindings": 0, "memberships": 1 })
        );
        let extended = membership(f, &s.engineering, &bob).await.unwrap();
        assert_eq!(extended["id"], before["id"]);
        assert_eq!(extended["expiresAt"], num(f.now() + 3.0 * DAY));
        assert_eq!(extended["packageAssignmentId"], assigned["id"]);
        f.advance(2.0 * DAY);
        assert!(in_group(f, &s.engineering, "bob").await);
        assert_eq!(
            ok(s.revoke(&kit, &bob).await),
            json!({ "revoked": true, "bindings": 0, "memberships": 1 })
        );
        assert!(!in_group(f, &s.engineering, "bob").await);
    });
}

#[test]
fn a_direct_assignment_fulfils_a_pending_request() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let requester = role(f, "Requester", json!(["iam:packages:request"])).await;
        let kit = id_of(
            &s.package(json!({ "name": "Kit", "roleIds": [s.reader], "requestable": true }))
                .await,
        );
        let alice = f.member("alice").await;
        bind(f, &requester, "identity", &alice).await;
        let as_alice = f.sign_in(&alice).await;
        let request = ok(api!(
            f,
            packages.request,
            &as_alice,
            json!({ "tenantId": s.tenant, "packageId": kit })
        ));
        assert_eq!(
            ids(&ok(api!(
                f,
                packages.list_approvals,
                &s.owner,
                json!({ "tenantId": s.tenant })
            ))),
            vec![id_of(&request)]
        );
        let assigned = ok(s
            .assign(json!({ "packageId": kit, "identityId": alice }))
            .await);
        let listed = ok(api!(
            f,
            packages.list_requests,
            &s.owner,
            json!({ "tenantId": s.tenant, "identityId": alice })
        ));
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_matches(
            &listed[0],
            json!({
                "id": request["id"],
                "status": "approved",
                "assignmentId": assigned["id"],
                "decidedBy": f.owner_id,
            }),
        );
        assert_eq!(
            ok(api!(
                f,
                packages.list_approvals,
                &s.owner,
                json!({ "tenantId": s.tenant })
            )),
            json!([])
        );
        assert_eq!(
            ok(api!(
                f,
                packages.list_requests,
                &s.owner,
                json!({ "tenantId": s.tenant, "status": "pending" })
            )),
            json!([])
        );
    });
}

// --- tests/package-review-authz.test.ts (packages) -------------------------------------------------------------

#[test]
fn a_holder_of_only_packages_assign_may_shorten_but_not_lengthen() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let engineering = group(f, "Platform").await;
        let kit = id_of(
            &s.package(json!({ "name": "Kit", "roleIds": [s.reader], "groupIds": [engineering] }))
                .await,
        );
        let alice = f.member("alice").await;
        let carol = f.member("carol").await;
        grant(
            f,
            &carol,
            "Package operator",
            json!(["iam:packages:assign", "iam:packages:read"]),
        )
        .await;
        let assigned = ok(s
            .assign(json!({ "packageId": kit, "identityId": alice, "expiresAt": num(f.now() + 2.0 * DAY) }))
            .await);
        let assignment_id = id_of(&assigned);
        let original = tagged(f, "bindings", &assignment_id).await;
        let owner_authority = original[0]["authorityId"].clone();
        let as_carol = f.sign_in(&carol).await;
        let extend = |expires_at: Value| {
            let input = json!({ "tenantId": s.tenant, "packageId": kit, "identityId": alice, "expiresAt": expires_at });
            let credential = as_carol.clone();
            async move { api!(f, packages.extend, &credential, input) }
        };
        let state = || async {
            let bindings: Vec<(Value, Value)> = tagged(f, "bindings", &assignment_id)
                .await
                .iter()
                .map(|binding| (binding["expiresAt"].clone(), binding["authorityId"].clone()))
                .collect();
            let members: Vec<Value> = tagged(f, "groupMembers", &assignment_id)
                .await
                .iter()
                .map(|member| member["expiresAt"].clone())
                .collect();
            (bindings, members)
        };
        // Shortening is like revoking: iam:packages:assign on the package suffices.
        let shortened = ok(extend(num(f.now() + DAY)).await);
        assert_eq!(shortened["expiresAt"], num(f.now() + DAY));
        assert_eq!(
            state().await,
            (
                vec![(num(f.now() + DAY), owner_authority.clone())],
                vec![num(f.now() + DAY)]
            )
        );
        // Lengthening is granting: a later end or no end is refused without the rights assign needs.
        let error = fails(extend(num(f.now() + 2.0 * DAY)).await, "ACCESS_DENIED");
        assert_eq!(error.status, 403);
        fails(extend(Value::Null).await, "ACCESS_DENIED");
        // Nothing moved.
        assert_eq!(
            state().await,
            (
                vec![(num(f.now() + DAY), owner_authority.clone())],
                vec![num(f.now() + DAY)]
            )
        );
        assert_eq!(
            ok(api!(
                f,
                packages.list_assignments,
                &s.owner,
                json!({ "tenantId": s.tenant, "packageId": kit })
            ))[0]["expiresAt"],
            num(f.now() + DAY)
        );
        assert_eq!(audit_count(f, "package:extend").await, 1);
        // expiresAt is required (null for no end), and automatic validation keeps its order.
        let error = fails(
            api!(
                f,
                packages.extend,
                &s.owner,
                json!({ "tenantId": s.tenant, "packageId": kit, "identityId": alice })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(error.message, "expiresAt is required (null for no end)");
    });
}

#[test]
fn lengthening_needs_every_part_and_a_grant_authority_and_moves_the_bindings() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let platform = group(f, "Platform").await;
        let kit = id_of(
            &s.package(json!({
                "name": "Kit",
                "roleIds": [s.reader, s.writer],
                "groupIds": [platform],
            }))
            .await,
        );
        let alice = f.member("alice").await;
        let erin = f.member("erin").await;
        let frank = f.member("frank").await;
        let gina = f.member("gina").await;
        // Erin may create bindings but not update groups.
        grant(
            f,
            &erin,
            "No groups",
            json!([
                "iam:packages:assign",
                "iam:packages:read",
                "iam:bindings:create"
            ]),
        )
        .await;
        // Frank may update groups but create bindings for the Reader role only.
        grant(
            f,
            &frank,
            "Groups",
            json!([
                "iam:packages:assign",
                "iam:packages:read",
                "iam:groups:update"
            ]),
        )
        .await;
        let reader_only = id_of(&ok(api!(
            f,
            roles.create,
            &s.owner,
            json!({
                "tenantId": s.tenant,
                "name": "Reader grants only",
                "document": {
                    "version": 1,
                    "statements": [{ "effect": "allow", "actions": ["iam:bindings:create"], "resources": [format!("iam/{}", s.reader)] }],
                },
            })
        )));
        bind(f, &reader_only, "identity", &frank).await;
        // Gina has every permission but, at first, no grant authority.
        grant(
            f,
            &gina,
            "Full grants",
            json!([
                "iam:packages:assign",
                "iam:packages:read",
                "iam:bindings:create",
                "iam:groups:update"
            ]),
        )
        .await;
        for who in [&erin, &frank] {
            authority(f, who).await;
        }
        let assigned = ok(s
            .assign(
                json!({ "packageId": kit, "identityId": alice, "expiresAt": num(f.now() + DAY) }),
            )
            .await);
        let assignment_id = id_of(&assigned);
        let before = tagged(f, "bindings", &assignment_id).await;
        assert_eq!(before.len(), 2);
        let owner_authority = before[0]["authorityId"].clone();
        assert!(
            before
                .iter()
                .all(|binding| binding["authorityId"] == owner_authority)
        );
        let extend_as = |identity: &String, expires_at: Value| {
            let input = json!({ "tenantId": s.tenant, "packageId": kit, "identityId": alice, "expiresAt": expires_at });
            let identity = identity.clone();
            async move {
                let credential = f.sign_in(&identity).await;
                api!(f, packages.extend, &credential, input)
            }
        };
        fails(
            extend_as(&erin, num(f.now() + 2.0 * DAY)).await,
            "ACCESS_DENIED",
        );
        fails(extend_as(&erin, Value::Null).await, "ACCESS_DENIED");
        fails(
            extend_as(&frank, num(f.now() + 2.0 * DAY)).await,
            "ACCESS_DENIED",
        );
        fails(extend_as(&frank, Value::Null).await, "ACCESS_DENIED");
        let error = fails(
            extend_as(&gina, num(f.now() + 2.0 * DAY)).await,
            "GRANT_AUTHORITY_REQUIRED",
        );
        assert_eq!(error.status, 403);
        fails(
            extend_as(&gina, Value::Null).await,
            "GRANT_AUTHORITY_REQUIRED",
        );
        let ends: Vec<Value> = tagged(f, "bindings", &assignment_id)
            .await
            .iter()
            .map(|binding| binding["expiresAt"].clone())
            .collect();
        assert_eq!(ends, vec![num(f.now() + DAY), num(f.now() + DAY)]);
        // Each of them may still shorten.
        assert_eq!(
            ok(extend_as(&erin, num(f.now() + DAY - 60_000.0)).await)["expiresAt"],
            num(f.now() + DAY - 60_000.0)
        );
        // The owner lengthening keeps the owner's own authority.
        ok(api!(
            f,
            packages.extend,
            &s.owner,
            json!({ "tenantId": s.tenant, "packageId": kit, "identityId": alice, "expiresAt": num(f.now() + 2.0 * DAY) })
        ));
        let after: Vec<(Value, Value)> = tagged(f, "bindings", &assignment_id)
            .await
            .iter()
            .map(|binding| (binding["expiresAt"].clone(), binding["authorityId"].clone()))
            .collect();
        assert_eq!(
            after,
            vec![
                (num(f.now() + 2.0 * DAY), owner_authority.clone()),
                (num(f.now() + 2.0 * DAY), owner_authority.clone()),
            ]
        );
        // With a grant authority Gina may lengthen, and the package's bindings move to her authority.
        let gina_authority = authority(f, &gina).await;
        let extended = ok(extend_as(&gina, Value::Null).await);
        assert!(extended.get("expiresAt").is_none());
        for binding_id in assigned["bindingIds"].as_array().unwrap() {
            let stored = get(f, "bindings", binding_id.as_str().unwrap())
                .await
                .unwrap();
            assert_eq!(stored["authorityId"], gina_authority["id"]);
            assert!(stored.get("expiresAt").is_none());
            assert!(stored["uniqueKey"].as_str().unwrap().ends_with(&format!(
                "{}:package:{assignment_id}",
                gina_authority["id"].as_str().unwrap()
            )));
        }
        let members: Vec<Option<Value>> = tagged(f, "groupMembers", &assignment_id)
            .await
            .iter()
            .map(|member| member.get("expiresAt").cloned())
            .collect();
        assert_eq!(members, vec![None]);
        assert_matches(
            &ok(api!(
                f,
                packages.list_assignments,
                &s.owner,
                json!({ "tenantId": s.tenant, "packageId": kit })
            ))[0],
            json!({ "broken": false }),
        );
        let as_alice = f.sign_in(&alice).await;
        assert!(can(f, &as_alice, "documents:read").await);
        assert!(can(f, &as_alice, "documents:write").await);
    });
}

#[test]
fn impersonation_sessions_cannot_decide_requests() {
    run(|| async {
        let (f, _) = fixture().await;
        let tenant = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        ok(api!(
            f,
            tenants.set_auth_policy,
            &owner,
            json!({ "tenantId": tenant, "authPolicy": { "allowImpersonation": true } })
        ));
        let reader = role(&f, "Reader", json!(["documents:read"])).await;
        let approvers = group(&f, "Approvers").await;
        let kit = id_of(&ok(api!(
            f,
            packages.create,
            &owner,
            json!({
                "tenantId": tenant,
                "name": "Kit",
                "roleIds": [reader],
                "requestable": true,
                "approverGroupId": approvers,
            })
        )));
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let erin = f.member("erin").await;
        grant(&f, &alice, "Member", json!(["iam:packages:request"])).await;
        grant(
            &f,
            &bob,
            "Package approver",
            json!([
                "iam:packages:approve",
                "iam:packages:read",
                "iam:bindings:create",
                "iam:groups:update"
            ]),
        )
        .await;
        grant(
            &f,
            &erin,
            "Approver with support",
            json!([
                "iam:packages:approve",
                "iam:packages:request",
                "iam:bindings:create",
                "iam:groups:update",
                "iam:identities:impersonate"
            ]),
        )
        .await;
        for who in [&bob, &erin] {
            add_member(&f, &approvers, who).await;
            authority(&f, who).await;
        }
        let as_alice = f.sign_in(&alice).await;
        let as_bob = f.sign_in(&bob).await;
        let as_erin = f.sign_in(&erin).await;
        let alice_request = ok(api!(
            f,
            packages.request,
            &as_alice,
            json!({ "tenantId": tenant, "packageId": kit })
        ));
        let erin_request = ok(api!(
            f,
            packages.request,
            &as_erin,
            json!({ "tenantId": tenant, "packageId": kit })
        ));
        // The owner viewing as Bob (a legitimate approver) cannot decide in his name.
        let owner_as_bob = ok(api!(
            f,
            identities.impersonate,
            &owner,
            json!({ "tenantId": tenant, "identityId": bob, "reason": "ticket 1" })
        ));
        let view_as_bob = organization_fixture::bearer(owner_as_bob["token"].as_str().unwrap());
        for approve in [true, false] {
            let input = json!({ "tenantId": tenant, "requestId": alice_request["id"] });
            let result = if approve {
                api!(f, packages.approve_request, &view_as_bob, input)
            } else {
                api!(f, packages.deny_request, &view_as_bob, input)
            };
            assert_eq!(fails(result, "IMPERSONATION_RESTRICTED").status, 403);
        }
        // Erin, refused on her own request, cannot approve it by viewing as a fellow approver either.
        fails(
            api!(
                f,
                packages.approve_request,
                &as_erin,
                json!({ "tenantId": tenant, "requestId": erin_request["id"] })
            ),
            "INVALID_INPUT",
        );
        let erin_as_bob = ok(api!(
            f,
            identities.impersonate,
            &as_erin,
            json!({ "tenantId": tenant, "identityId": bob, "reason": "ticket 2" })
        ));
        let erin_view = organization_fixture::bearer(erin_as_bob["token"].as_str().unwrap());
        fails(
            api!(
                f,
                packages.approve_request,
                &erin_view,
                json!({ "tenantId": tenant, "requestId": erin_request["id"] })
            ),
            "IMPERSONATION_RESTRICTED",
        );
        fails(
            api!(
                f,
                packages.deny_request,
                &erin_view,
                json!({ "tenantId": tenant, "requestId": alice_request["id"] })
            ),
            "IMPERSONATION_RESTRICTED",
        );
        // Both requests still wait, nothing was granted, and no decision was recorded.
        let statuses = ok(api!(
            f,
            packages.list_requests,
            &owner,
            json!({ "tenantId": tenant, "packageId": kit })
        ));
        assert!(
            statuses
                .as_array()
                .unwrap()
                .iter()
                .all(|request| request["status"] == json!("pending"))
        );
        assert!(!can(&f, &as_alice, "documents:read").await);
        assert!(!can(&f, &as_erin, "documents:read").await);
        let decisions = f
            .find("audit", Filter::new().eq("tenantId", tenant.clone()))
            .await
            .into_iter()
            .filter(|event| {
                event["action"]
                    .as_str()
                    .is_some_and(|action| action.starts_with("package:request-"))
            })
            .count();
        assert_eq!(decisions, 0);
        // Bob from his own session decides normally.
        assert_eq!(
            ok(api!(
                f,
                packages.approve_request,
                &as_bob,
                json!({ "tenantId": tenant, "requestId": alice_request["id"] })
            ))["status"],
            json!("approved")
        );
        assert_eq!(
            ok(api!(
                f,
                packages.deny_request,
                &as_bob,
                json!({ "tenantId": tenant, "requestId": erin_request["id"] })
            ))["status"],
            json!("denied")
        );
        assert!(can(&f, &as_alice, "documents:read").await);
    });
}

#[test]
fn records_keep_the_typescript_member_order() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let kit = s
            .package(json!({
                "name": "Kit",
                "description": "Ordered",
                "roleIds": [s.reader],
                "maxDurationMs": num(30.0 * DAY),
                "requestable": true,
            }))
            .await;
        let stored = get(f, "accessPackages", &id_of(&kit)).await.unwrap();
        let keys: Vec<&String> = stored.keys().collect();
        assert_eq!(
            keys,
            vec![
                "id",
                "tenantId",
                "uniqueKey",
                "name",
                "roleIds",
                "groupIds",
                "createdAt",
                "updatedAt",
                "description",
                "maxDurationMs",
                "requestable"
            ]
        );
        assert_eq!(stored["uniqueKey"], json!("name:kit"));
        let alice = f.member("alice").await;
        let assigned = ok(s
            .assign(json!({ "packageId": id_of(&kit), "identityId": alice, "expiresAt": num(f.now() + DAY) }))
            .await);
        let record = get(f, "packageAssignments", &id_of(&assigned))
            .await
            .unwrap();
        let keys: Vec<&String> = record.keys().collect();
        assert_eq!(
            keys,
            vec![
                "id",
                "tenantId",
                "uniqueKey",
                "packageId",
                "identityId",
                "assignedBy",
                "assignedAt",
                "expiresAt",
                "bindingIds",
                "membershipIds"
            ]
        );
        assert_eq!(
            record["uniqueKey"],
            json!(format!("{}:{alice}", id_of(&kit)))
        );
        let keys: Vec<String> = assigned.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            vec![
                "id",
                "tenantId",
                "packageId",
                "identityId",
                "assignedBy",
                "assignedAt",
                "expiresAt",
                "bindingIds",
                "membershipIds",
                "packageName",
                "identityName",
                "identityEmail",
                "expired",
                "broken",
                "automatic",
                "created",
                "skipped",
                "replacedAutomatic"
            ]
        );
        // Validation keeps the TypeScript messages.
        let error = fails(
            api!(
                f,
                packages.update,
                &s.owner,
                json!({ "tenantId": s.tenant, "packageId": id_of(&kit), "requestable": "yes" })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(error.message, "requestable must be boolean");
        let error = fails(
            api!(
                f,
                packages.list_assignments,
                &s.owner,
                json!({ "tenantId": s.tenant, "source": "other" })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(error.message, "source must be automatic or manual");
        let error = fails(
            api!(
                f,
                packages.update,
                &s.owner,
                json!({ "tenantId": s.tenant, "packageId": id_of(&kit), "keepAutomaticAssignments": true })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(
            error.message,
            "keepAutomaticAssignments applies only with autoAssign: null"
        );
        let error = fails(
            api!(
                f,
                packages.update,
                &s.owner,
                json!({ "tenantId": s.tenant, "packageId": id_of(&kit), "autoAssign": null, "keepAutomaticAssignments": true })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(
            error.message,
            "keepAutomaticAssignments needs a rule to clear"
        );
        let error = fails(
            api!(
                f,
                packages.reconcile,
                &s.owner,
                json!({ "tenantId": s.tenant, "confirm": true })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(error.message, "confirm needs packageId");
        let error = fails(
            api!(
                f,
                packages.reconcile,
                &s.owner,
                json!({ "tenantId": s.tenant, "packageId": id_of(&kit), "confirm": true })
            ),
            "INVALID_TRANSITION",
        );
        assert_eq!(error.message, "This package has no rule");
    });
}
