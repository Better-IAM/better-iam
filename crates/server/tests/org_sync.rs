//! Configuration as code for teams and departments (the `teams` and `departments` kinds of `config.plan` and
//! `config.apply`, org-sync.ts). Ported from tests/config-org.test.ts.
//!
//! Every configuration call reads the tenant's AI kinds (ai-sync.ts `readAiState`, `exportAi`, `applyAi`), which are
//! another unit's stubs, and team membership changes run package automation (api/package-automation.ts
//! `afterIdentityChange`, another unit): the scenarios are ignored until those units are ported.

mod organization_fixture;

use better_iam_core::{CredentialInput, IamResult};
use better_iam_server::api::Reply;
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use organization_fixture::{Org, assert_matches, body, ok, organization, run};
use serde_json::{Value, json};

struct Scenario {
    f: Org,
    tenant_id: String,
    owner: CredentialInput,
    bob: String,
    dave: String,
}

async fn scenario() -> Scenario {
    let f = organization(|_| {}).await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    f.member("alice").await;
    let bob = f.member("bob").await;
    f.member("carol").await;
    let dave = f.member("dave").await;
    for (name, permission) in [("Reader", "documents:read"), ("Writer", "documents:write")] {
        ok(f.iam
            .api
            .roles
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": name, "permissions": [permission] })),
            )
            .await);
    }
    Scenario {
        f,
        tenant_id,
        owner,
        bob,
        dave,
    }
}

impl Scenario {
    async fn plan(&self, config: Value, prune: bool) -> IamResult<Value> {
        self.f
            .iam
            .api
            .config
            .plan(
                &self.owner,
                body(json!({ "tenantId": self.tenant_id, "config": config, "prune": prune })),
            )
            .await
            .and_then(Reply::into_value)
    }

    async fn apply(&self, config: Value, prune: bool) -> Value {
        ok(self
            .f
            .iam
            .api
            .config
            .apply(
                &self.owner,
                body(json!({ "tenantId": self.tenant_id, "config": config, "prune": prune })),
            )
            .await)
    }

    async fn export(&self) -> Value {
        ok(self
            .f
            .iam
            .api
            .config
            .export(&self.owner, body(json!({ "tenantId": self.tenant_id })))
            .await)
    }

    async fn teams(&self) -> Value {
        ok(self
            .f
            .iam
            .api
            .teams
            .list(&self.owner, body(json!({ "tenantId": self.tenant_id })))
            .await)
    }

    async fn team_members(&self, team_id: &Value) -> Value {
        ok(self
            .f
            .iam
            .api
            .teams
            .list_members(
                &self.owner,
                body(json!({ "tenantId": self.tenant_id, "teamId": team_id })),
            )
            .await)
    }

    async fn team(&self, team_id: &Value) -> Value {
        ok(self
            .f
            .iam
            .api
            .teams
            .get(
                &self.owner,
                body(json!({ "tenantId": self.tenant_id, "teamId": team_id })),
            )
            .await)
    }
}

fn base() -> Value {
    json!({
        "version": 1,
        "departments": [
            { "name": "Engineering", "code": "ENG", "head": "alice@acme.test", "members": ["alice@acme.test"] },
            {
                "name": "Platform",
                "parent": "Engineering",
                "head": "bob@acme.test",
                "costCenter": "CC-7",
                "members": ["bob@acme.test", "carol@acme.test"],
            },
        ],
        "teams": [
            { "name": "Site Reliability", "slug": "sre", "parent": "platform", "members": ["carol@acme.test"] },
            {
                "name": "Platform",
                "slug": "platform",
                "department": "Platform",
                "joinPolicy": "request",
                "maintainers": ["bob@acme.test"],
                "members": ["alice@acme.test"],
                "roles": ["Reader"],
            },
        ],
    })
}

fn find_by<'a>(list: &'a Value, key: &str, value: &str) -> &'a Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|item| item[key] == value)
        .unwrap_or_else(|| panic!("{key} {value} in {list}"))
}

fn pending(plan: &Value) -> Vec<Value> {
    plan["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|change| change["action"] != "unchanged")
        .cloned()
        .collect()
}

fn role_names(detail: &Value) -> Vec<String> {
    detail["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|grant| grant["roleName"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
#[ignore = "needs ai-sync.ts readAiState, exportAi and applyAi (ai-sync unit) and api/package-automation.ts afterIdentityChange"]
fn applies_teams_and_departments_from_a_document_and_exports_them_back_unchanged() {
    run(|| async {
        let s = scenario().await;
        let plan = s.plan(base(), false).await.unwrap();
        let org: Vec<String> = plan["changes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|change| change["kind"] == "team" || change["kind"] == "department")
            .map(|change| {
                format!(
                    "{}:{}:{}",
                    change["kind"].as_str().unwrap(),
                    change["name"].as_str().unwrap(),
                    change["action"].as_str().unwrap()
                )
            })
            .collect();
        assert_eq!(
            org,
            [
                "department:Engineering:create",
                "department:Platform:create",
                "team:platform:create",
                "team:sre:create",
            ]
        );
        s.apply(base(), false).await;

        let teams = s.teams().await;
        let platform = find_by(&teams, "slug", "platform").clone();
        let sre = find_by(&teams, "slug", "sre").clone();
        assert_eq!(sre["parentId"], platform["id"]);
        assert_matches(
            &platform,
            json!({ "joinPolicy": "request", "memberCount": 2, "maintainerCount": 1 }),
        );
        let detail = s.team(&platform["id"]).await;
        assert_eq!(detail["department"]["name"], "Platform");
        assert_eq!(role_names(&detail), ["Reader"]);
        // Carol is in SRE, so she holds Reader through Platform.
        let carol_id =
            s.f.find(
                "identities",
                better_iam_core::Filter::new().eq("email", "carol@acme.test"),
            )
            .await[0]["id"]
                .as_str()
                .unwrap()
                .to_owned();
        let carol = s.f.sign_in(&carol_id).await;
        let decision =
            s.f.iam
                .authorize(&AuthorizationRequest {
                    credential: carol,
                    tenant_id: s.tenant_id.clone(),
                    action: "documents:read".into(),
                    resource: ResourceTarget {
                        kind: "documents".into(),
                        id: "a".into(),
                    },
                })
                .await
                .unwrap();
        assert!(decision.allowed);
        let tree = ok(s
            .f
            .iam
            .api
            .departments
            .tree(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        assert_matches(
            &tree[0],
            json!({ "name": "Engineering", "head": { "name": "alice" } }),
        );
        assert_matches(
            &tree[0]["children"][0],
            json!({ "name": "Platform", "costCenter": "CC-7", "memberCount": 2 }),
        );

        let exported = s.export().await;
        assert_eq!(
            find_by(&exported["teams"], "slug", "platform"),
            &json!({
                "name": "Platform",
                "slug": "platform",
                "department": "Platform",
                "joinPolicy": "request",
                "memberManagement": "maintainers",
                "maintainers": ["bob@acme.test"],
                "members": ["alice@acme.test"],
                "roles": ["Reader"],
            })
        );
        let departments: Vec<&str> = exported["departments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|department| department["name"].as_str().unwrap())
            .collect();
        assert_eq!(departments, ["Engineering", "Platform"]);
        let again = s.plan(exported, true).await.unwrap();
        assert_eq!(pending(&again), Vec::<Value>::new());
    });
}

#[test]
#[ignore = "needs ai-sync.ts readAiState, exportAi and applyAi (ai-sync unit) and api/package-automation.ts afterIdentityChange"]
fn updates_membership_roles_settings_and_structure_and_prunes_what_the_document_omits() {
    run(|| async {
        let s = scenario().await;
        s.apply(base(), false).await;
        let next = json!({
            "version": 1,
            "departments": [
                { "name": "Engineering", "code": "ENG", "head": "alice@acme.test", "members": ["alice@acme.test"] },
            ],
            "teams": [
                {
                    "name": "Platform Engineering",
                    "slug": "platform",
                    "joinPolicy": "closed",
                    "maintainers": ["alice@acme.test"],
                    "members": ["bob@acme.test", "dave@acme.test"],
                    "roles": ["Writer"],
                },
            ],
        });
        let plan = s.plan(next.clone(), true).await.unwrap();
        let platform = plan["changes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|change| change["kind"] == "team" && change["name"] == "platform")
            .unwrap();
        assert_eq!(platform["action"], "update");
        let fields: Vec<&str> = platform["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field.as_str().unwrap())
            .collect();
        for field in [
            "department",
            "joinPolicy",
            "maintainers",
            "members",
            "name",
            "roles",
        ] {
            assert!(fields.contains(&field), "{field} in {fields:?}");
        }
        let mut deletions: Vec<String> = plan["changes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|change| change["action"] == "delete")
            .map(|change| {
                format!(
                    "{}:{}",
                    change["kind"].as_str().unwrap(),
                    change["name"].as_str().unwrap()
                )
            })
            .collect();
        deletions.sort();
        assert_eq!(deletions, ["department:Platform", "team:sre"]);
        s.apply(next.clone(), true).await;

        let teams = s.teams().await;
        let slugs: Vec<&str> = teams
            .as_array()
            .unwrap()
            .iter()
            .map(|team| team["slug"].as_str().unwrap())
            .collect();
        assert_eq!(slugs, ["platform"]);
        let members = s.team_members(&teams[0]["id"]).await;
        let mut roster: Vec<String> = members
            .as_array()
            .unwrap()
            .iter()
            .map(|member| {
                format!(
                    "{}:{}",
                    member["name"].as_str().unwrap(),
                    member["role"].as_str().unwrap()
                )
            })
            .collect();
        roster.sort();
        assert_eq!(roster, ["alice:maintainer", "bob:member", "dave:member"]);
        let detail = s.team(&teams[0]["id"]).await;
        assert_matches(
            &detail,
            json!({ "name": "Platform Engineering", "joinPolicy": "closed" }),
        );
        assert!(detail.get("department").is_none());
        assert_eq!(role_names(&detail), ["Writer"]);
        let departments = ok(s
            .f
            .iam
            .api
            .departments
            .list(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        let names: Vec<&str> = departments
            .as_array()
            .unwrap()
            .iter()
            .map(|department| department["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["Engineering"]);
        // Bob and Carol lost their department with Platform.
        let bob = ok(s
            .f
            .iam
            .api
            .departments
            .of_identity(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "identityId": s.bob })),
            )
            .await);
        assert_eq!(bob, Value::Null);
        let converged = s.plan(next, true).await.unwrap();
        assert_eq!(pending(&converged), Vec::<Value>::new());
    });
}

#[test]
#[ignore = "needs ai-sync.ts readAiState, exportAi and applyAi (ai-sync unit) and api/package-automation.ts afterIdentityChange"]
fn configures_team_sync_by_group_name_and_keeps_synced_members_out_of_the_document() {
    run(|| async {
        let s = scenario().await;
        let document = json!({
            "version": 1,
            "groups": [{ "name": "Okta: Engineers", "members": ["carol@acme.test", "dave@acme.test"] }],
            "teams": [
                {
                    "name": "Engineers",
                    "slug": "engineers",
                    "syncGroups": ["Okta: Engineers"],
                    "maintainers": ["alice@acme.test"],
                },
            ],
        });
        s.apply(document, false).await;
        let team = s.teams().await[0].clone();
        let members = s.team_members(&team["id"]).await;
        let mut roster: Vec<String> = members
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
        roster.sort();
        assert_eq!(roster, ["alice:manual", "carol:sync", "dave:sync"]);
        let exported = s.export().await;
        assert_eq!(exported["teams"].as_array().unwrap().len(), 1);
        assert_matches(
            &exported["teams"][0],
            json!({
                "slug": "engineers",
                "syncGroups": ["Okta: Engineers"],
                "maintainers": ["alice@acme.test"],
                "members": [],
            }),
        );
        let converged = s.plan(exported, true).await.unwrap();
        assert_eq!(pending(&converged), Vec::<Value>::new());
        // Dropping the source stops syncing: the synced members go, the manual maintainer stays.
        s.apply(
            json!({
                "version": 1,
                "teams": [
                    { "name": "Engineers", "slug": "engineers", "syncGroups": [], "maintainers": ["alice@acme.test"] },
                ],
            }),
            false,
        )
        .await;
        let members = s.team_members(&team["id"]).await;
        let names: Vec<&str> = members
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["alice"]);
        let error = s
            .plan(
                json!({ "version": 1, "teams": [{ "name": "X", "slug": "x", "syncGroups": ["Nope"] }] }),
                false,
            )
            .await
            .unwrap_err();
        assert!(
            error.message.contains("unknown sync group"),
            "{}",
            error.message
        );
    });
}

#[test]
#[ignore = "needs ai-sync.ts readAiState, exportAi and applyAi (ai-sync unit) and api/package-automation.ts afterIdentityChange"]
fn leaves_temporary_memberships_alone_and_rejects_dangling_references() {
    run(|| async {
        let s = scenario().await;
        s.apply(base(), false).await;
        let teams = s.teams().await;
        let team = find_by(&teams, "slug", "platform").clone();
        let expires_at = s.f.now() + 86_400_000.0;
        let added =
            s.f.iam
                .api
                .teams
                .add_member(
                    &s.owner,
                    body(json!({
                        "tenantId": s.tenant_id,
                        "teamId": team["id"],
                        "identityId": s.dave,
                        "expiresAt": expires_at,
                    })),
                )
                .await;
        if matches!(&added, Err(error) if error.code == "NOT_IMPLEMENTED") {
            // teams.addMember commits, then runs package automation (another unit): the membership is written.
            let written =
                s.f.find(
                    "teamMembers",
                    better_iam_core::Filter::new().eq("identityId", s.dave.clone()),
                )
                .await;
            assert_eq!(written.len(), 1);
        } else {
            ok(added);
        }
        let plan = s.plan(base(), false).await.unwrap();
        assert_eq!(pending(&plan), Vec::<Value>::new());
        s.apply(base(), false).await;
        let members = s.team_members(&team["id"]).await;
        assert!(
            members
                .as_array()
                .unwrap()
                .iter()
                .any(|member| member["name"] == "dave")
        );

        let broken = |patch: Value| {
            let mut team = json!({ "name": "Data", "slug": "data" });
            for (key, value) in patch.as_object().unwrap() {
                team[key] = value.clone();
            }
            json!({ "version": 1, "teams": [team] })
        };
        for (patch, message) in [
            (json!({ "members": ["nobody@acme.test"] }), "unknown person"),
            (json!({ "roles": ["Missing"] }), "unknown role"),
            (json!({ "parent": "ghost" }), "unknown parent"),
            (json!({ "department": "Nowhere" }), "unknown department"),
            (
                json!({ "maintainers": ["bob@acme.test"], "members": ["bob@acme.test"] }),
                "both maintainer and member",
            ),
        ] {
            let error = s.plan(broken(patch), false).await.unwrap_err();
            assert!(error.message.contains(message), "{}", error.message);
        }
        let error = s
            .plan(
                json!({
                    "version": 1,
                    "teams": [
                        { "name": "A", "slug": "a", "parent": "b" },
                        { "name": "B", "slug": "b", "parent": "a" },
                    ],
                }),
                false,
            )
            .await
            .unwrap_err();
        assert!(error.message.contains("cycle"), "{}", error.message);
    });
}
