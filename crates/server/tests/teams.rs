//! Port of tests/teams.test.ts and tests/security-team-authority.test.ts: the `teams` API group (api/teams.ts).
//!
//! The suites that create a team need the team helpers of teams.ts (`slugFromName`, `loadTeam`, `teamChain`,
//! `liveTeamMember`, `syncTeamGroups`, ..., ported by the teams unit), `afterIdentityChange` (package-automation unit),
//! and for some of them `completeTeamReview` (team-reviews unit), departments, access analysis and configuration
//! sync; until those land they are `#[ignore]`d with that reason. What works without them runs now: reads of an
//! organization without teams, the self-service guard, the team-scoped envelope refusing callers without standing,
//! and input validation in the TypeScript order.

mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::{CredentialInput, IamStoreExt};
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;

struct Scenario {
    f: Org,
    tenant_id: String,
    owner: CredentialInput,
    alice: String,
    bob: String,
    carol: String,
    reader: Value,
    writer: Value,
    platform: Value,
    sre: Value,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
}

/// The organization fixture with a captured email outbox.
async fn fixture() -> (Org, Arc<Mutex<Vec<DeliveryMessage>>>) {
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
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

async fn role(f: &Org, owner: &CredentialInput, input: Value) -> Value {
    ok(f.iam.api.roles.create(owner, body(input)).await)
}

async fn bind_group(f: &Org, owner: &CredentialInput, role_id: &Value, group_id: &Value) {
    ok(f.iam
        .api
        .bindings
        .create(
            owner,
            body(json!({
                "tenantId": f.tenant_id,
                "roleId": role_id,
                "subjectType": "group",
                "subjectId": group_id,
            })),
        )
        .await);
}

async fn scenario() -> Scenario {
    let (f, inbox) = fixture().await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let alice = f.member("alice").await;
    let bob = f.member("bob").await;
    let carol = f.member("carol").await;
    let reader = role(
        &f,
        &owner,
        json!({ "tenantId": tenant_id, "name": "Reader", "permissions": ["documents:read"] }),
    )
    .await;
    let writer = role(
        &f,
        &owner,
        json!({ "tenantId": tenant_id, "name": "Writer", "permissions": ["documents:write"] }),
    )
    .await;
    let platform = ok(f
        .iam
        .api
        .teams
        .create(
            &owner,
            body(json!({
                "tenantId": tenant_id,
                "name": "Platform",
                "description": "Runs the platform",
                "maintainerIds": [bob],
            })),
        )
        .await);
    let sre = ok(f
        .iam
        .api
        .teams
        .create(
            &owner,
            body(json!({
                "tenantId": tenant_id,
                "name": "Site Reliability",
                "slug": "sre",
                "parentId": platform["id"],
            })),
        )
        .await);
    Scenario {
        f,
        tenant_id,
        owner,
        alice,
        bob,
        carol,
        reader,
        writer,
        platform,
        sre,
        inbox,
    }
}

impl Scenario {
    async fn can(&self, credential: &CredentialInput, action: &str) -> bool {
        self.f
            .iam
            .authorize(&AuthorizationRequest {
                credential: credential.clone(),
                tenant_id: self.tenant_id.clone(),
                action: action.into(),
                resource: ResourceTarget {
                    kind: "documents".into(),
                    id: "a".into(),
                },
            })
            .await
            .expect("authorize")
            .allowed
    }

    async fn add_member(
        &self,
        credential: &CredentialInput,
        team: &Value,
        identity_id: &str,
    ) -> Value {
        ok(self
            .f
            .iam
            .api
            .teams
            .add_member(
                credential,
                body(json!({ "tenantId": self.tenant_id, "teamId": team["id"], "identityId": identity_id })),
            )
            .await)
    }

    async fn create(&self, input: Value) -> Value {
        let mut input = input;
        input["tenantId"] = json!(self.tenant_id);
        ok(self.f.iam.api.teams.create(&self.owner, body(input)).await)
    }

    async fn audit(&self, action: &str) -> Vec<Value> {
        let listed = ok(self
            .f
            .iam
            .api
            .audit
            .list(
                &self.owner,
                body(json!({ "tenantId": self.tenant_id, "action": action })),
            )
            .await);
        match listed {
            Value::Array(items) => items,
            other => other["events"].as_array().cloned().unwrap_or_default(),
        }
    }

    fn mail(&self, template: &str) -> Option<DeliveryMessage> {
        self.inbox
            .lock()
            .unwrap()
            .iter()
            .find(|message| message.template == template)
            .cloned()
    }
}

fn names(list: &Value, key: &str) -> Vec<String> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|item| item[key].as_str().unwrap_or_default().to_owned())
        .collect()
}

// --- Without the teams.ts helpers -----------------------------------------------------------------------------------

#[test]
fn reads_an_organization_without_teams() {
    run(|| async {
        let (f, _) = fixture().await;
        let owner = f.owner_credential.clone();
        let alice = f.member("alice").await;
        let tenant_id = f.tenant_id.clone();
        assert_eq!(
            ok(f.iam
                .api
                .teams
                .list(&owner, body(json!({ "tenantId": tenant_id })))
                .await),
            json!([])
        );
        assert_eq!(
            ok(f.iam
                .api
                .teams
                .list(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "parentId": null, "query": "plat" }))
                )
                .await),
            json!([])
        );
        assert_eq!(
            ok(f.iam
                .api
                .teams
                .list_for_identity(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "identityId": alice }))
                )
                .await),
            json!([])
        );
        assert_eq!(
            ok(f.iam
                .api
                .teams
                .list_reviews(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "status": "open" }))
                )
                .await),
            json!([])
        );
        let session = f.sign_in(&alice).await;
        assert_eq!(
            ok(f.iam
                .api
                .teams
                .list_mine(&session, body(json!({ "tenantId": tenant_id })))
                .await),
            json!({ "reviews": [], "teams": [], "requests": [], "joinable": [] })
        );
        // An identity of another tenant is not found.
        let error = fails(
            f.iam
                .api
                .teams
                .list_for_identity(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "identityId": f.root_id })),
                )
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
    });
}

#[test]
fn self_service_needs_a_persons_own_session_in_the_organization() {
    run(|| async {
        let (f, _) = fixture().await;
        let tenant_id = f.tenant_id.clone();
        // The root administrator acts from the root tenant.
        let error = fails(
            f.iam
                .api
                .teams
                .list_mine(&f.root_credential, body(json!({ "tenantId": tenant_id })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_eq!(error.status, 403);
        assert_eq!(
            error.message,
            "Teams are joined and left from a person’s own session in their organization"
        );
        // The tenant is validated before the credential is read.
        let error = fails(
            f.iam
                .api
                .teams
                .request_to_join(&CredentialInput::default(), body(json!({ "teamId": "x" })))
                .await,
        );
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("INVALID_INPUT", "Invalid tenantId")
        );
        // Withdrawing a request that does not exist.
        let alice = f.member("alice").await;
        let session = f.sign_in(&alice).await;
        let error = fails(
            f.iam
                .api
                .teams
                .cancel_request(
                    &session,
                    body(json!({ "tenantId": tenant_id, "requestId": "nope" })),
                )
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
    });
}

#[test]
fn refuses_callers_without_a_permission_or_standing() {
    run(|| async {
        let (f, _) = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let alice = f.member("alice").await;
        let session = f.sign_in(&alice).await;
        let error = fails(
            f.iam
                .api
                .teams
                .list(&session, body(json!({ "tenantId": tenant_id })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // A team that does not exist gives no standing: the ordinary operation refuses.
        for result in [
            fails(f.iam.api.teams.get(&session, body(json!({ "tenantId": tenant_id, "teamId": "missing" }))).await),
            fails(
                f.iam
                    .api
                    .teams
                    .list_members(&session, body(json!({ "tenantId": tenant_id, "teamId": "missing" })))
                    .await,
            ),
            fails(
                f.iam
                    .api
                    .teams
                    .add_member(
                        &session,
                        body(json!({ "tenantId": tenant_id, "teamId": "missing", "identityId": alice })),
                    )
                    .await,
            ),
            fails(
                f.iam
                    .api
                    .teams
                    .get_review(&session, body(json!({ "tenantId": tenant_id, "reviewId": "missing" })))
                    .await,
            ),
            fails(
                f.iam
                    .api
                    .teams
                    .approve_request(&session, body(json!({ "tenantId": tenant_id, "requestId": "missing" })))
                    .await,
            ),
        ] {
            assert_eq!(code(&result), "ACCESS_DENIED", "{result:?}");
        }
        let denied = f
            .find(
                "audit",
                better_iam_core::Filter::new().eq("action", "iam:teams:read"),
            )
            .await;
        assert!(
            denied
                .iter()
                .any(|event| event["outcome"] == "deny" && event["resourceId"] == "missing")
        );
    });
}

#[test]
fn validates_input_in_the_typescript_order() {
    run(|| async {
        let (f, _) = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        // The team ID is checked before the credential.
        let error = fails(
            f.iam
                .api
                .teams
                .get(
                    &CredentialInput::default(),
                    body(json!({ "tenantId": tenant_id, "teamId": 5 })),
                )
                .await,
        );
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("INVALID_INPUT", "Invalid teamId")
        );
        let error = fails(
            f.iam
                .api
                .teams
                .list_reviews(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "status": "bogus" })),
                )
                .await,
        );
        assert_eq!(
            (code(&error), error.message.as_str()),
            (
                "INVALID_INPUT",
                "status must be one of open, completed, cancelled"
            )
        );
        let error = fails(
            f.iam
                .api
                .teams
                .get_review(&owner, body(json!({ "tenantId": tenant_id })))
                .await,
        );
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("INVALID_INPUT", "Invalid reviewId")
        );
        let error = fails(
            f.iam
                .api
                .teams
                .deny_request(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "requestId": "r", "note": 7 })),
                )
                .await,
        );
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("INVALID_INPUT", "Invalid note")
        );
        let error = fails(
            f.iam
                .api
                .teams
                .list(&owner, body(json!({ "tenantId": tenant_id, "query": "" })))
                .await,
        );
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("INVALID_INPUT", "Invalid query")
        );
    });
}

// --- tests/teams.test.ts --------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn creates_nested_teams_with_backing_groups_and_derived_slugs() {
    run(|| async {
        let s = scenario().await;
        assert_matches(
            &s.platform,
            json!({
                "name": "Platform",
                "slug": "platform",
                "joinPolicy": "closed",
                "memberManagement": "maintainers",
                "memberCount": 1,
                "maintainerCount": 1,
                "path": [],
            }),
        );
        assert_eq!(names(&s.platform["maintainers"], "id"), vec![s.bob.clone()]);
        assert_matches(
            &s.sre,
            json!({ "slug": "sre", "parentId": s.platform["id"] }),
        );
        assert_eq!(names(&s.sre["path"], "slug"), vec!["platform"]);
        let group = ok(s
            .f
            .iam
            .api
            .groups
            .get(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "groupId": s.platform["groupId"] })),
            )
            .await);
        assert_matches(
            &group,
            json!({ "name": "team:platform", "teamId": s.platform["id"] }),
        );
        let error = fails(
            s.f.iam
                .api
                .teams
                .create(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "name": "platform" })),
                )
                .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let list = ok(s
            .f
            .iam
            .api
            .teams
            .list(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        let pairs: Vec<(String, f64)> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|team| {
                (
                    team["slug"].as_str().unwrap().to_owned(),
                    team["childCount"].as_f64().unwrap(),
                )
            })
            .collect();
        assert_eq!(pairs, vec![("platform".into(), 1.0), ("sre".into(), 0.0)]);
        let top = ok(s
            .f
            .iam
            .api
            .teams
            .list(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "parentId": null })),
            )
            .await);
        assert_eq!(names(&top, "slug"), vec!["platform"]);
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn gives_child_team_members_the_parent_teams_roles_through_the_backing_groups() {
    run(|| async {
        let s = scenario().await;
        bind_group(&s.f, &s.owner, &s.reader["id"], &s.platform["groupId"]).await;
        let alice = s.f.sign_in(&s.alice).await;
        assert!(!s.can(&alice, "documents:read").await);
        s.add_member(&s.owner, &s.sre, &s.alice).await;
        assert!(s.can(&alice, "documents:read").await);
        let detail = ok(s
            .f
            .iam
            .api
            .teams
            .get(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"] })),
            )
            .await);
        let roles = detail["roles"].as_array().unwrap();
        assert_eq!(roles.len(), 1);
        assert_matches(
            &roles[0],
            json!({ "roleName": "Reader", "inherited": true, "team": { "slug": "platform" } }),
        );
        let platform = ok(s
            .f
            .iam
            .api
            .teams
            .get(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"] })),
            )
            .await);
        // Bob directly, Alice through SRE.
        assert_eq!(platform["totalMemberCount"], json!(2));
        assert_eq!(platform["memberCount"], json!(1));
        let members = ok(s
            .f
            .iam
            .api
            .teams
            .list_members(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"], "includeChildTeams": true })),
            )
            .await);
        let rows: Vec<(String, String, String)> = members
            .as_array()
            .unwrap()
            .iter()
            .map(|member| {
                (
                    member["name"].as_str().unwrap().to_owned(),
                    member["role"].as_str().unwrap().to_owned(),
                    member["team"]["slug"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                ("bob".into(), "maintainer".into(), "platform".into()),
                ("alice".into(), "member".into(), "sre".into()),
            ]
        );
        ok(s
            .f
            .iam
            .api
            .teams
            .remove_member(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"], "identityId": s.alice })),
            )
            .await);
        assert!(!s.can(&alice, "documents:read").await);
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn lets_maintainers_manage_membership_without_an_administrator_permission() {
    run(|| async {
        let s = scenario().await;
        let bob = s.f.sign_in(&s.bob).await;
        // Bob maintains Platform, so he manages SRE below it too.
        ok(s.f
            .iam
            .api
            .teams
            .add_member(
                &bob,
                body(json!({
                    "tenantId": s.tenant_id,
                    "teamId": s.sre["id"],
                    "identityId": s.carol,
                    "role": "maintainer",
                })),
            )
            .await);
        let carol = s.f.sign_in(&s.carol).await;
        s.add_member(&carol, &s.sre, &s.alice).await;
        // Carol maintains SRE, not Platform.
        let error = fails(
            s.f.iam
                .api
                .teams
                .add_member(
                    &carol,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"], "identityId": s.alice })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Settings stay with administrators.
        let error = fails(
            s.f.iam
                .api
                .teams
                .update(
                    &bob,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"], "name": "Ops" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let added = s.audit("team:member:add").await;
        assert_eq!(
            added
                .iter()
                .filter(|event| event["metadata"]["via"] == "maintainer")
                .count(),
            2
        );
        let updates = s.audit("iam:teams:update").await;
        assert!(updates.iter().any(|event| {
            event["outcome"] == "allow" && event["metadata"]["via"] == "team-maintainer"
        }));

        // With memberManagement 'admins' maintainers are refused.
        ok(s
            .f
            .iam
            .api
            .teams
            .update(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"], "memberManagement": "admins" })),
            )
            .await);
        let error = fails(
            s.f.iam
                .api
                .teams
                .remove_member(
                    &carol,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"], "identityId": s.alice })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn lets_members_read_their_own_team_but_not_others() {
    run(|| async {
        let s = scenario().await;
        s.add_member(&s.owner, &s.sre, &s.alice).await;
        let other = s.create(json!({ "name": "Sales" })).await;
        let alice = s.f.sign_in(&s.alice).await;
        let own = ok(s
            .f
            .iam
            .api
            .teams
            .get(
                &alice,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"] })),
            )
            .await);
        assert_eq!(own["slug"], "sre");
        // Being in SRE makes Alice part of Platform as well.
        ok(s.f
            .iam
            .api
            .teams
            .list_members(
                &alice,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"] })),
            )
            .await);
        let error = fails(
            s.f.iam
                .api
                .teams
                .get(
                    &alice,
                    body(json!({ "tenantId": s.tenant_id, "teamId": other["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            s.f.iam
                .api
                .teams
                .list(&alice, body(json!({ "tenantId": s.tenant_id })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Members are not maintainers.
        let error = fails(
            s.f.iam
                .api
                .teams
                .add_member(
                    &alice,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"], "identityId": s.carol })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit), afterIdentityChange (package-automation unit) and the config export/plan (org-sync unit)"]
fn keeps_team_managed_groups_out_of_the_groups_packages_and_invitation_apis() {
    run(|| async {
        let s = scenario().await;
        let group_id = s.platform["groupId"].clone();
        let error = fails(
            s.f.iam
                .api
                .groups
                .add_member(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "groupId": group_id, "identityId": s.alice })),
                )
                .await,
        );
        assert_eq!(code(&error), "TEAM_MANAGED");
        let error = fails(
            s.f.iam
                .api
                .groups
                .remove_member(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "groupId": group_id, "identityId": s.bob })),
                )
                .await,
        );
        assert_eq!(code(&error), "TEAM_MANAGED");
        let error = fails(
            s.f.iam
                .api
                .groups
                .delete(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "groupId": group_id })),
                )
                .await,
        );
        assert_eq!(code(&error), "TEAM_MANAGED");
        let error = fails(
            s.f.iam
                .api
                .packages
                .create(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "name": "Platform kit", "groupIds": [group_id] })),
                )
                .await,
        );
        assert_eq!(code(&error), "TEAM_MANAGED");
        // Configuration sync leaves team groups (and what is bound to them) alone.
        bind_group(&s.f, &s.owner, &s.reader["id"], &group_id).await;
        let exported = ok(s
            .f
            .iam
            .api
            .config
            .export(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        assert!(
            !exported["groups"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .any(|group| group["name"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("team:"))
        );
        assert_eq!(
            exported.get("bindings").cloned().unwrap_or(json!([])),
            json!([])
        );
        let plan = ok(s
            .f
            .iam
            .api
            .config
            .plan(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "config": exported, "prune": true })),
            )
            .await);
        assert!(
            plan["changes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|change| change["action"] == "unchanged")
        );
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn refuses_cycles_overly_deep_nesting_and_deleting_a_team_with_teams_below_it() {
    run(|| async {
        let s = scenario().await;
        let error = fails(
            s.f.iam
                .api
                .teams
                .update(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"], "parentId": s.sre["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = fails(
            s.f.iam
                .api
                .teams
                .delete(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "RESOURCE_IN_USE");
        let mut parent = s.sre["id"].clone();
        for depth in 3..=10 {
            parent = s
                .create(json!({ "name": format!("Level {depth}"), "parentId": parent }))
                .await["id"]
                .clone();
        }
        let error = fails(
            s.f.iam
                .api
                .teams
                .create(
                    &s.owner,
                    body(
                        json!({ "tenantId": s.tenant_id, "name": "Too deep", "parentId": parent }),
                    ),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn moves_a_team_and_recomputes_both_parents() {
    run(|| async {
        let s = scenario().await;
        let other = s.create(json!({ "name": "Data" })).await;
        bind_group(&s.f, &s.owner, &s.reader["id"], &s.platform["groupId"]).await;
        bind_group(&s.f, &s.owner, &s.writer["id"], &other["groupId"]).await;
        s.add_member(&s.owner, &s.sre, &s.alice).await;
        let alice = s.f.sign_in(&s.alice).await;
        assert_eq!(
            (
                s.can(&alice, "documents:read").await,
                s.can(&alice, "documents:write").await
            ),
            (true, false)
        );
        let moved = ok(s
            .f
            .iam
            .api
            .teams
            .update(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"], "parentId": other["id"] })),
            )
            .await);
        assert_eq!(names(&moved["path"], "slug"), vec!["data"]);
        assert_eq!(
            (
                s.can(&alice, "documents:read").await,
                s.can(&alice, "documents:write").await
            ),
            (false, true)
        );
        let top = ok(s
            .f
            .iam
            .api
            .teams
            .update(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"], "parentId": null })),
            )
            .await);
        assert!(top.get("parentId").is_none());
        assert!(!s.can(&alice, "documents:write").await);
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn handles_join_requests_end_to_end() {
    run(|| async {
        let s = scenario().await;
        let teams = &s.f.iam.api.teams;
        ok(teams
            .update(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"], "joinPolicy": "request" })),
            )
            .await);
        let alice = s.f.sign_in(&s.alice).await;
        let mine = ok(teams
            .list_mine(&alice, body(json!({ "tenantId": s.tenant_id })))
            .await);
        assert_eq!(names(&mine["joinable"], "slug"), vec!["platform"]);
        let error = fails(
            teams
                .request_to_join(
                    &alice,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_TRANSITION");
        let request = ok(teams
            .request_to_join(
                &alice,
                body(json!({
                    "tenantId": s.tenant_id,
                    "teamId": s.platform["id"],
                    "justification": "On call next week",
                })),
            )
            .await);
        assert_matches(
            &request,
            json!({ "status": "pending", "justification": "On call next week" }),
        );
        let error = fails(
            teams
                .request_to_join(
                    &alice,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        s.f.iam.auth.dispatch_outbox(None).await.unwrap();
        let mail = s.mail("team-join-request").expect("join request mail");
        assert_eq!(mail.to, "bob@acme.test");
        assert_matches(
            &Value::Object(mail.payload.clone()),
            json!({ "teamName": "Platform", "requesterName": "alice" }),
        );

        let bob = s.f.sign_in(&s.bob).await;
        let pending = ok(teams
            .list_requests(
                &bob,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"] })),
            )
            .await);
        let requesters: Vec<Value> = pending
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["requester"]["id"].clone())
            .collect();
        assert_eq!(requesters, vec![json!(s.alice)]);
        let approved = ok(teams
            .approve_request(
                &bob,
                body(json!({ "tenantId": s.tenant_id, "requestId": request["id"], "note": "Welcome" })),
            )
            .await);
        assert_matches(
            &approved,
            json!({ "status": "approved", "decidedBy": s.bob, "note": "Welcome" }),
        );
        s.f.iam.auth.dispatch_outbox(None).await.unwrap();
        assert_matches(
            &Value::Object(s.mail("team-join-decided").expect("decision mail").payload),
            json!({ "decision": "approved", "teamName": "Platform" }),
        );
        let after = ok(teams
            .list_mine(&alice, body(json!({ "tenantId": s.tenant_id })))
            .await);
        let rows: Vec<(String, String)> = after["teams"]
            .as_array()
            .unwrap()
            .iter()
            .map(|team| {
                (
                    team["slug"].as_str().unwrap().to_owned(),
                    team["role"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(rows, vec![("platform".into(), "member".into())]);
        assert_eq!(after["joinable"], json!([]));

        // Nobody decides their own request; carol asks, then withdraws.
        let carol = s.f.sign_in(&s.carol).await;
        let second = ok(teams
            .request_to_join(
                &carol,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"] })),
            )
            .await);
        let error = fails(
            teams
                .approve_request(
                    &carol,
                    body(json!({ "tenantId": s.tenant_id, "requestId": second["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let cancelled = ok(teams
            .cancel_request(
                &carol,
                body(json!({ "tenantId": s.tenant_id, "requestId": second["id"] })),
            )
            .await);
        assert_eq!(cancelled["status"], "cancelled");
        let error = fails(
            teams
                .deny_request(
                    &bob,
                    body(json!({ "tenantId": s.tenant_id, "requestId": second["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_TRANSITION");

        // Requests lapse after fourteen days.
        let third = ok(teams
            .request_to_join(
                &carol,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"] })),
            )
            .await);
        s.f.advance(15.0 * DAY);
        let late = s.f.sign_in(&s.bob).await;
        let error = fails(
            teams
                .approve_request(
                    &late,
                    body(json!({ "tenantId": s.tenant_id, "requestId": third["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_TRANSITION");

        // Alice leaves.
        let alice_again = s.f.sign_in(&s.alice).await;
        ok(teams
            .leave(
                &alice_again,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"] })),
            )
            .await);
        let mine = ok(teams
            .list_mine(&alice_again, body(json!({ "tenantId": s.tenant_id })))
            .await);
        assert_eq!(mine["teams"], json!([]));
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn exposes_principal_teams_to_policies_including_the_teams_above() {
    run(|| async {
        let s = scenario().await;
        let policy_role = role(
            &s.f,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "name": "Platform readers",
                "document": {
                    "version": 1,
                    "statements": [{
                        "effect": "allow",
                        "actions": ["documents:read"],
                        "resources": ["*"],
                        "conditions": { "ArrayContains": { "principal.teams": [s.platform["id"]] } },
                    }],
                },
            }),
        )
        .await;
        ok(s.f
            .iam
            .api
            .bindings
            .create(
                &s.owner,
                body(json!({
                    "tenantId": s.tenant_id,
                    "roleId": policy_role["id"],
                    "subjectType": "identity",
                    "subjectId": s.alice,
                })),
            )
            .await);
        let alice = s.f.sign_in(&s.alice).await;
        assert!(!s.can(&alice, "documents:read").await);
        s.add_member(&s.owner, &s.sre, &s.alice).await;
        assert!(s.can(&alice, "documents:read").await);
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit), afterIdentityChange (package-automation unit) and sodVerify (sod unit)"]
fn enforces_separation_of_duties_across_teams() {
    run(|| async {
        let s = scenario().await;
        let payments = s.create(json!({ "name": "Payments" })).await;
        bind_group(&s.f, &s.owner, &s.reader["id"], &s.platform["groupId"]).await;
        bind_group(&s.f, &s.owner, &s.writer["id"], &payments["groupId"]).await;
        ok(s.f
            .iam
            .api
            .sod
            .create(
                &s.owner,
                body(json!({
                    "tenantId": s.tenant_id,
                    "name": "Readers never write",
                    "roleIds": [s.reader["id"], s.writer["id"]],
                })),
            )
            .await);
        s.add_member(&s.owner, &payments, &s.alice).await;
        let error = fails(
            s.f.iam
                .api
                .teams
                .add_member(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"], "identityId": s.alice })),
                )
                .await,
        );
        assert_eq!(code(&error), "SOD_CONFLICT");
        // The maintainer path is checked too.
        let bob = s.f.sign_in(&s.bob).await;
        let error = fails(
            s.f.iam
                .api
                .teams
                .add_member(
                    &bob,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"], "identityId": s.alice })),
                )
                .await,
        );
        assert_eq!(code(&error), "SOD_CONFLICT");
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit), afterIdentityChange (package-automation unit) and offboarding (identities lifecycle)"]
fn ends_temporary_memberships_and_cleans_up_on_offboarding_and_deletion() {
    run(|| async {
        let s = scenario().await;
        bind_group(&s.f, &s.owner, &s.reader["id"], &s.platform["groupId"]).await;
        ok(s.f
            .iam
            .api
            .teams
            .add_member(
                &s.owner,
                body(json!({
                    "tenantId": s.tenant_id,
                    "teamId": s.sre["id"],
                    "identityId": s.alice,
                    "expiresAt": s.f.now() + 3_600_000.0,
                })),
            )
            .await);
        let alice = s.f.sign_in(&s.alice).await;
        assert!(s.can(&alice, "documents:read").await);
        s.f.advance(2.0 * 3_600_000.0);
        assert!(!s.can(&alice, "documents:read").await);
        // The retention sweep removes the ended membership record.
        let swept = s.f.iam.sweep_expired(None).await.unwrap();
        assert_eq!(swept["deleted"]["teamMembers"], json!(1));
        assert!(
            s.f.find(
                "teamMembers",
                better_iam_core::Filter::new()
                    .eq("tenantId", s.tenant_id.clone())
                    .eq("identityId", s.alice.clone()),
            )
            .await
            .is_empty()
        );

        s.add_member(&s.owner, &s.sre, &s.alice).await;
        let owner = s.f.session(&s.f.owner_id, false).await;
        let result = ok(s
            .f
            .iam
            .api
            .identities
            .offboard(
                &owner,
                body(json!({ "tenantId": s.tenant_id, "identityId": s.alice, "reason": "Left the company" })),
            )
            .await);
        assert_matches(&result, json!({ "teamsLeft": 1 }));
        assert!(
            s.f.find(
                "groupMembers",
                better_iam_core::Filter::new()
                    .eq("tenantId", s.tenant_id.clone())
                    .eq("identityId", s.alice.clone()),
            )
            .await
            .is_empty()
        );

        ok(s.f
            .iam
            .api
            .identities
            .delete(
                &owner,
                body(json!({ "tenantId": s.tenant_id, "identityId": s.bob })),
            )
            .await);
        let platform = ok(s
            .f
            .iam
            .api
            .teams
            .get(
                &owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"] })),
            )
            .await);
        assert_eq!(platform["maintainers"], json!([]));
        assert_eq!(platform["totalMemberCount"], json!(0));
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn keeps_a_team_in_step_with_its_source_groups() {
    run(|| async {
        let s = scenario().await;
        let groups = &s.f.iam.api.groups;
        let directory = ok(groups
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "name": "Okta: Engineers" })),
            )
            .await);
        ok(groups
            .add_members(
                &s.owner,
                body(json!({
                    "tenantId": s.tenant_id,
                    "groupId": directory["id"],
                    "identityIds": [s.alice, s.bob],
                })),
            )
            .await);
        let engineers = s
            .create(json!({ "name": "Engineers", "syncGroupIds": [directory["id"]] }))
            .await;
        assert_eq!(
            engineers["syncGroups"],
            json!([{ "id": directory["id"], "name": "Okta: Engineers" }])
        );
        let members = || async {
            let listed = ok(s
                .f
                .iam
                .api
                .teams
                .list_members(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "teamId": engineers["id"] })),
                )
                .await);
            let mut rows: Vec<String> = listed
                .as_array()
                .unwrap()
                .iter()
                .map(|member| {
                    format!(
                        "{}:{}",
                        member["name"].as_str().unwrap(),
                        member["source"].as_str().unwrap_or("manual")
                    )
                })
                .collect();
            rows.sort();
            rows
        };
        assert_eq!(members().await, vec!["alice:sync", "bob:sync"]);

        // Group changes flow into the team; manual members stay.
        s.add_member(&s.owner, &engineers, &s.carol).await;
        ok(groups
            .remove_member(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "groupId": directory["id"], "identityId": s.alice })),
            )
            .await);
        ok(groups
            .add_member(
                &s.owner,
                body(json!({
                    "tenantId": s.tenant_id,
                    "groupId": directory["id"],
                    "identityId": s.carol,
                    "expiresAt": s.f.now() + DAY,
                })),
            )
            .await);
        assert_eq!(members().await, vec!["bob:sync", "carol:manual"]);

        // A temporary source membership makes a temporary synced membership.
        let dave = s.f.member("dave").await;
        ok(groups
            .add_member(
                &s.owner,
                body(json!({
                    "tenantId": s.tenant_id,
                    "groupId": directory["id"],
                    "identityId": dave,
                    "expiresAt": s.f.now() + 3_600_000.0,
                })),
            )
            .await);
        let listed = ok(s
            .f
            .iam
            .api
            .teams
            .list_members(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": engineers["id"] })),
            )
            .await);
        let dave_row = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|member| member["name"] == "dave")
            .cloned()
            .expect("dave");
        assert_matches(
            &dave_row,
            json!({ "source": "sync", "expiresAt": s.f.now() + 3_600_000.0 }),
        );

        // Synced members are managed through the source group.
        let error = fails(
            s.f.iam
                .api
                .teams
                .remove_member(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "teamId": engineers["id"], "identityId": s.bob })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_TRANSITION");
        let error = fails(
            groups
                .delete(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "groupId": directory["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "RESOURCE_IN_USE");

        // A directory push (SCIM) that drops Bob reaches the team through the protocol host.
        let host = s.f.iam.protocol_host();
        let (tenant_id, group_id, bob_id) = (
            s.tenant_id.clone(),
            directory["id"].as_str().unwrap().to_owned(),
            s.bob.clone(),
        );
        s.f.iam
            .store
            .transaction(|tx| async move {
                use better_iam_core::Filter;
                for row in tx
                    .find(
                        "groupMembers",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("groupId", group_id.clone())
                            .eq("identityId", bob_id.clone()),
                        &better_iam_core::FindOptions::default(),
                    )
                    .await?
                {
                    tx.delete("groupMembers", row["id"].as_str().unwrap())
                        .await?;
                }
                host.sync_role_mappings(
                    &tx,
                    &json!({
                        "tenantId": tenant_id,
                        "connectionId": "scim",
                        "groupId": group_id,
                        "identityIds": [],
                        "roleIds": [],
                    }),
                )
                .await
            })
            .await
            .unwrap();
        assert_eq!(members().await, vec!["carol:manual", "dave:sync"]);
        let events = s.audit("team:member:remove").await;
        assert!(
            events
                .iter()
                .any(|event| event["actorId"] == "directory-sync")
        );

        // Turning sync off removes the synced members and keeps the manual ones.
        ok(s
            .f
            .iam
            .api
            .teams
            .update(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": engineers["id"], "syncGroupIds": null })),
            )
            .await);
        assert_eq!(members().await, vec!["carol:manual"]);
        ok(groups
            .delete(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "groupId": directory["id"] })),
            )
            .await);
        let error = fails(
            s.f.iam
                .api
                .teams
                .create(
                    &s.owner,
                    body(json!({
                        "tenantId": s.tenant_id,
                        "name": "Loop",
                        "syncGroupIds": [s.platform["groupId"]],
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit), afterIdentityChange (package-automation unit) and access packages"]
fn follows_access_packages_that_grant_a_source_group() {
    run(|| async {
        let s = scenario().await;
        let directory = ok(s
            .f
            .iam
            .api
            .groups
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "name": "On-call" })),
            )
            .await);
        let team = s
            .create(json!({ "name": "Responders", "syncGroupIds": [directory["id"]] }))
            .await;
        let pkg = ok(s
            .f
            .iam
            .api
            .packages
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "name": "On-call kit", "groupIds": [directory["id"]] })),
            )
            .await);
        let week = s.f.now() + 7.0 * DAY;
        ok(s.f
            .iam
            .api
            .packages
            .assign(
                &s.owner,
                body(json!({
                    "tenantId": s.tenant_id,
                    "packageId": pkg["id"],
                    "identityId": s.alice,
                    "expiresAt": week,
                })),
            )
            .await);
        let members = || async {
            let listed = ok(s
                .f
                .iam
                .api
                .teams
                .list_members(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "teamId": team["id"] })),
                )
                .await);
            listed
                .as_array()
                .unwrap()
                .iter()
                .map(|member| {
                    format!(
                        "{}:{}",
                        member["name"].as_str().unwrap(),
                        member["expiresAt"]
                            .as_f64()
                            .map(|at| format!("{at}"))
                            .unwrap_or_else(|| "permanent".into())
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(members().await, vec![format!("alice:{week}")]);
        // Extending the package extends the synced membership.
        let fortnight = s.f.now() + 14.0 * DAY;
        let owner = s.f.session(&s.f.owner_id, false).await;
        ok(s.f
            .iam
            .api
            .packages
            .extend(
                &owner,
                body(json!({
                    "tenantId": s.tenant_id,
                    "packageId": pkg["id"],
                    "identityId": s.alice,
                    "expiresAt": fortnight,
                })),
            )
            .await);
        assert_eq!(members().await, vec![format!("alice:{fortnight}")]);
        ok(s
            .f
            .iam
            .api
            .packages
            .revoke(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "packageId": pkg["id"], "identityId": s.alice })),
            )
            .await);
        assert!(members().await.is_empty());
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit), afterIdentityChange (package-automation unit), departments and access analysis"]
fn reports_risky_teams_and_departments_in_access_analysis() {
    run(|| async {
        let s = scenario().await;
        let admin = role(
            &s.f,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "name": "Administrator",
                "document": { "version": 1, "statements": [{ "effect": "allow", "actions": ["*"], "resources": ["*"] }] },
            }),
        )
        .await;
        bind_group(&s.f, &s.owner, &admin["id"], &s.platform["groupId"]).await;
        s.add_member(&s.owner, &s.sre, &s.alice).await;
        let orphan = s.create(json!({ "name": "Data" })).await;
        s.add_member(&s.owner, &orphan, &s.carol).await;
        let sales = ok(s
            .f
            .iam
            .api
            .departments
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "name": "Sales" })),
            )
            .await);
        ok(s
            .f
            .iam
            .api
            .departments
            .assign(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "departmentId": sales["id"], "identityIds": [s.carol] })),
            )
            .await);
        let kinds = || async {
            let findings = ok(s
                .f
                .iam
                .api
                .analysis
                .findings(&s.owner, body(json!({ "tenantId": s.tenant_id })))
                .await);
            let mut rows: Vec<String> = findings["findings"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|finding| {
                    ["team", "department"]
                        .contains(&finding["subject"]["type"].as_str().unwrap_or_default())
                })
                .map(|finding| {
                    format!(
                        "{}:{}",
                        finding["kind"].as_str().unwrap(),
                        finding["subject"]["name"].as_str().unwrap()
                    )
                })
                .collect();
            rows.sort();
            rows
        };
        // Bob maintains Platform, so he can make anyone an administrator through Platform or SRE.
        assert_eq!(
            kinds().await,
            vec![
                "department-without-head:Sales",
                "team-maintainers-grant-admin:Platform",
                "team-maintainers-grant-admin:Site Reliability",
                "team-without-maintainer:Data",
            ]
        );
        ok(s
            .f
            .iam
            .api
            .teams
            .update(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"], "memberManagement": "admins" })),
            )
            .await);
        ok(s
            .f
            .iam
            .api
            .departments
            .update(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "departmentId": sales["id"], "headId": s.bob })),
            )
            .await);
        assert_eq!(
            kinds().await,
            vec![
                "team-maintainers-grant-admin:Site Reliability",
                "team-without-maintainer:Data",
            ]
        );
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit), afterIdentityChange (package-automation unit) and packagesNaming (org-rules unit)"]
fn deletes_a_team_with_its_backing_group_and_rejects_people_who_cannot_belong() {
    run(|| async {
        let s = scenario().await;
        let service = ok(s
            .f
            .iam
            .api
            .service_accounts
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "name": "deployer" })),
            )
            .await);
        let error = fails(
            s.f.iam
                .api
                .teams
                .add_member(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"], "identityId": service["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        s.add_member(&s.owner, &s.sre, &s.alice).await;
        let error = fails(
            s.f.iam
                .api
                .teams
                .add_member(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"], "identityId": s.alice })),
                )
                .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let removed = ok(s
            .f
            .iam
            .api
            .teams
            .delete(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.sre["id"] })),
            )
            .await);
        assert_eq!(removed, json!({ "deleted": true, "members": 1 }));
        assert!(
            s.f.iam
                .store
                .get("groups", s.sre["groupId"].as_str().unwrap())
                .await
                .unwrap()
                .is_none()
        );
        let platform = ok(s
            .f
            .iam
            .api
            .teams
            .get(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "teamId": s.platform["id"] })),
            )
            .await);
        // Only Bob remains in Platform's group once SRE is gone.
        assert_eq!(platform["totalMemberCount"], json!(1));
        let repaired = ok(s
            .f
            .iam
            .api
            .teams
            .reconcile(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        assert_matches(
            &repaired,
            json!({
                "added": 0,
                "removed": 0,
                "updated": 0,
                "synced": { "added": 0, "removed": 0, "updated": 0, "teams": [] },
            }),
        );
    });
}

// --- tests/security-team-authority.test.ts --------------------------------------------------------------------------

struct Privileged {
    f: Org,
    tenant_id: String,
    owner: CredentialInput,
    mallory: String,
    eve: String,
    ops: Value,
    m: CredentialInput,
    e: CredentialInput,
}

/// Mallory administers teams (no grant authority); Ops's backing group holds the owner-bound Writer role.
async fn privileged_team(ops: impl FnOnce(&str) -> Value) -> Privileged {
    let (f, _) = fixture().await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let mallory = f.member("mallory").await;
    let eve = f.member("eve").await;
    let team_admin = role(
        &f,
        &owner,
        json!({
            "tenantId": tenant_id,
            "name": "Team admin",
            "permissions": ["iam:teams:create", "iam:teams:update", "iam:teams:read"],
        }),
    )
    .await;
    ok(f.iam
        .api
        .bindings
        .create(
            &owner,
            body(json!({
                "tenantId": tenant_id,
                "roleId": team_admin["id"],
                "subjectType": "identity",
                "subjectId": mallory,
            })),
        )
        .await);
    let writer = role(
        &f,
        &owner,
        json!({ "tenantId": tenant_id, "name": "Writer", "permissions": ["documents:write"] }),
    )
    .await;
    let mut input = ops(&eve);
    input["tenantId"] = json!(tenant_id);
    input["name"] = json!("Ops");
    let team = ok(f.iam.api.teams.create(&owner, body(input)).await);
    bind_group(&f, &owner, &writer["id"], &team["groupId"]).await;
    let m = f.sign_in(&mallory).await;
    let e = f.sign_in(&eve).await;
    Privileged {
        f,
        tenant_id,
        owner,
        mallory,
        eve,
        ops: team,
        m,
        e,
    }
}

impl Privileged {
    async fn may_write(&self) -> bool {
        self.f
            .iam
            .authorize(&AuthorizationRequest {
                credential: self.m.clone(),
                tenant_id: self.tenant_id.clone(),
                action: "documents:write".into(),
                resource: ResourceTarget {
                    kind: "documents".into(),
                    id: "a".into(),
                },
            })
            .await
            .expect("authorize")
            .allowed
    }
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn refuses_moving_a_privileged_team_under_a_team_whose_maintainers_the_mover_chose() {
    run(|| async {
        let p = privileged_team(|_| json!({})).await;
        let shadow = ok(p
            .f
            .iam
            .api
            .teams
            .create(
                &p.m,
                body(
                    json!({ "tenantId": p.tenant_id, "name": "Shadow", "maintainerIds": [p.eve] }),
                ),
            )
            .await);
        let error = fails(
            p.f.iam
                .api
                .teams
                .update(
                    &p.m,
                    body(json!({ "tenantId": p.tenant_id, "teamId": p.ops["id"], "parentId": shadow["id"] })),
                )
                .await,
        );
        assert_eq!(error.status, 403);
        fails(
            p.f.iam
                .api
                .teams
                .add_member(
                    &p.e,
                    body(json!({ "tenantId": p.tenant_id, "teamId": p.ops["id"], "identityId": p.mallory })),
                )
                .await,
        );
        assert!(!p.may_write().await);
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn refuses_opening_an_admins_only_team_to_its_maintainers_without_grant_authority() {
    run(|| async {
        let p =
            privileged_team(|eve| json!({ "memberManagement": "admins", "maintainerIds": [eve] }))
                .await;
        let error = fails(
            p.f.iam
                .api
                .teams
                .update(
                    &p.m,
                    body(json!({ "tenantId": p.tenant_id, "teamId": p.ops["id"], "memberManagement": "maintainers" })),
                )
                .await,
        );
        assert_eq!(error.status, 403);
        fails(
            p.f.iam
                .api
                .teams
                .add_member(
                    &p.e,
                    body(json!({ "tenantId": p.tenant_id, "teamId": p.ops["id"], "identityId": p.mallory })),
                )
                .await,
        );
        assert!(!p.may_write().await);
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn still_lets_an_administrator_with_grant_authority_move_and_open_teams() {
    run(|| async {
        let p = privileged_team(|_| json!({ "memberManagement": "admins" })).await;
        let parent = ok(p
            .f
            .iam
            .api
            .teams
            .create(
                &p.owner,
                body(json!({ "tenantId": p.tenant_id, "name": "Engineering" })),
            )
            .await);
        ok(p.f
            .iam
            .api
            .teams
            .update(
                &p.owner,
                body(json!({
                    "tenantId": p.tenant_id,
                    "teamId": p.ops["id"],
                    "parentId": parent["id"],
                    "memberManagement": "maintainers",
                })),
            )
            .await);
        let ops = ok(p
            .f
            .iam
            .api
            .teams
            .get(
                &p.owner,
                body(json!({ "tenantId": p.tenant_id, "teamId": p.ops["id"] })),
            )
            .await);
        assert_matches(
            &ops,
            json!({ "parentId": parent["id"], "memberManagement": "maintainers" }),
        );
    });
}

#[test]
#[ignore = "needs the teams.ts helpers (teams unit) and afterIdentityChange (package-automation unit)"]
fn keeps_an_explicit_deny_in_force_for_a_maintainer() {
    run(|| async {
        let (f, _) = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let bob = f.member("bob").await;
        let alice = f.member("alice").await;
        let platform = ok(f
            .iam
            .api
            .teams
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Platform", "maintainerIds": [bob] })),
            )
            .await);
        let b = f.sign_in(&bob).await;
        // Without the deny, the maintainer path works as designed.
        ok(f.iam
            .api
            .teams
            .add_member(
                &b,
                body(
                    json!({ "tenantId": tenant_id, "teamId": platform["id"], "identityId": alice }),
                ),
            )
            .await);
        let lockout = role(
            &f,
            &owner,
            json!({
                "tenantId": tenant_id,
                "name": "No team management",
                "document": {
                    "version": 1,
                    "statements": [{ "effect": "deny", "actions": ["iam:teams:*"], "resources": ["*"] }],
                },
            }),
        )
        .await;
        ok(f.iam
            .api
            .bindings
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "roleId": lockout["id"],
                    "subjectType": "identity",
                    "subjectId": bob,
                })),
            )
            .await);
        let error = fails(
            f.iam
                .api
                .teams
                .remove_member(
                    &b,
                    body(json!({ "tenantId": tenant_id, "teamId": platform["id"], "identityId": alice })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let members = ok(f
            .iam
            .api
            .teams
            .list_members(
                &owner,
                body(json!({ "tenantId": tenant_id, "teamId": platform["id"] })),
            )
            .await);
        assert!(names(&members, "id").contains(&alice));
    });
}
