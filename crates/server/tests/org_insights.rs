//! Port of the tests of `org-insights.ts` and `org-rules.ts`: tests/org-birthright.test.ts (birthright suggestions
//! from the access most of a department or team already holds; what identity.teams and identity.departments hold for
//! a person; which packages name a team or department). Departments, teams, roles, bindings and memberships are
//! written as their API groups (other port units) store them. Reading the org facts also reads license seats
//! (licenses.ts `loadLicenseFacts`) and package rules (package-rules.ts `ruleValues`), which other units port, so
//! the scenarios that reach them stay ignored until those are ported.

#![allow(clippy::cloned_ref_to_slice_refs)]

mod org_fixture;
mod teams_fixture;

use better_iam_core::IamStoreExt;
use better_iam_server::org_insights::{birthright_options, suggest_birthright};
use better_iam_server::org_rules::{load_org_facts, org_rule_environment, packages_naming};
use org_fixture::{Org, run};
use serde_json::{Value, json};
use teams_fixture::{
    add_team_member, bind, create_department, create_team, permission_role, place,
};

#[test]
fn validates_the_birthright_options() {
    assert_eq!(
        birthright_options(&json!({})).unwrap(),
        json!({ "minShare": 0.8, "minPeople": 3 })
    );
    assert_eq!(
        birthright_options(&json!({ "minShare": 0.6, "minPeople": 2, "minShareX": 1 })).unwrap(),
        json!({ "minShare": 0.6, "minPeople": 2 })
    );
    assert_eq!(
        birthright_options(&json!({ "minShare": 1, "minPeople": null })).unwrap(),
        json!({ "minShare": 1, "minPeople": 3 })
    );
    for share in [json!(0.2), json!(1.5), json!("0.8"), json!(true)] {
        let error = birthright_options(&json!({ "minShare": share })).unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_INPUT", "minShare must be between 0.5 and 1")
        );
    }
    for people in [json!(1), json!(100_001), json!(2.5), json!("3")] {
        let error = birthright_options(&json!({ "minPeople": people })).unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_INPUT", "Invalid minPeople")
        );
    }
}

struct Scenario {
    org: Org,
    alice: String,
    bob: String,
    carol: String,
    dave: String,
    wiki: String,
    engineering: String,
    platform_department: String,
    platform: teams_fixture::TeamRef,
    sre: teams_fixture::TeamRef,
}

async fn scenario() -> Scenario {
    let org = Org::new(|_| {}).await;
    let alice = org.member("alice").await.id;
    let bob = org.member("bob").await.id;
    let carol = org.member("carol").await.id;
    let dave = org.member("dave").await.id;
    let wiki = org.group("Wiki editors").await;
    let engineering = create_department(&org, "Engineering", None).await;
    let platform_department = create_department(&org, "Platform", Some(&engineering)).await;
    let platform = create_team(&org, "Platform", "platform", None, &[]).await;
    let sre = create_team(&org, "Site Reliability", "sre", Some(&platform.id), &[]).await;
    Scenario {
        org,
        alice,
        bob,
        carol,
        dave,
        wiki,
        engineering,
        platform_department,
        platform,
        sre,
    }
}

fn summary(suggestions: &[better_iam_server::org_insights::BirthrightSuggestion]) -> Value {
    json!(
        suggestions
            .iter()
            .map(|item| json!({
                "unit": item.unit["name"],
                "people": better_iam_server::js::number(item.people),
                "roles": item.roles.iter().map(|role| role["name"].clone()).collect::<Vec<_>>(),
                "groups": item.groups.iter().map(|group| format!(
                    "{} {}",
                    group["name"].as_str().unwrap(),
                    group["share"]
                )).collect::<Vec<_>>(),
                "wouldGrant": better_iam_server::js::number(item.would_grant),
            }))
            .collect::<Vec<_>>()
    )
}

/// tests/org-birthright.test.ts "suggests birthright packages from the access most of a department or team already
/// holds", through the module.
#[test]
#[ignore = "needs licenses.ts loadLicenseFacts and package-rules.ts ruleValues (other port units)"]
fn suggests_birthright_packages_from_the_access_most_of_a_unit_already_holds() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let reader = permission_role(org, "Reader", "iam:resources:read").await;
        let writer = permission_role(org, "Writer", "iam:resources:read").await;
        // Engineering: Dave directly; Platform (below it): Alice, Bob, Carol.
        for person in [&s.alice, &s.bob, &s.carol] {
            place(org, &s.platform_department, person).await;
        }
        place(org, &s.engineering, &s.dave).await;
        for person in [&s.alice, &s.bob, &s.carol, &s.dave] {
            bind(org, "identity", person, &reader).await;
        }
        for person in [&s.alice, &s.bob] {
            bind(org, "identity", person, &writer).await;
        }
        for person in [&s.alice, &s.bob, &s.carol] {
            org.add_member(&s.wiki, person).await;
        }
        let suggest = |kind: &'static str, options: Value| {
            let ctx = org.iam.ctx.clone();
            let tenant_id = org.tenant_id.clone();
            async move {
                org.iam
                    .store
                    .transaction(|tx| async move {
                        let mut full = birthright_options(&options)?;
                        if let Some(unit) = options.get("unitId") {
                            full["unitId"] = unit.clone();
                        }
                        suggest_birthright(&ctx, &tx, &tenant_id, kind, &full).await
                    })
                    .await
                    .unwrap()
            }
        };
        let suggestions = suggest("department", json!({})).await;
        assert_eq!(
            summary(&suggestions),
            json!([
                // Everyone in Engineering (with Platform) reads; Platform adds only what Engineering does not.
                { "unit": "Engineering", "people": 4, "roles": ["Reader"], "groups": [], "wouldGrant": 0 },
                { "unit": "Platform", "people": 3, "roles": [], "groups": ["Wiki editors 1"], "wouldGrant": 0 },
            ])
        );
        let lower = suggest(
            "department",
            json!({ "unitId": s.platform_department, "minShare": 0.6 }),
        )
        .await;
        assert_eq!(lower.len(), 1);
        assert_eq!(
            lower[0]
                .roles
                .iter()
                .map(|role| format!("{} {}", role["name"].as_str().unwrap(), role["share"]))
                .collect::<Vec<_>>(),
            ["Writer 0.67"]
        );
        assert_eq!(lower[0].would_grant, 1.0);
        let engineering = &suggestions[0];
        assert_eq!(
            engineering.package["name"],
            json!("Engineering department basics")
        );
        assert_eq!(
            engineering.package["description"],
            json!(
                "Birthright access for everyone in the Engineering department and the departments below it."
            )
        );
        assert_eq!(engineering.package["roleIds"], json!([reader]));
        assert_eq!(
            engineering.package["autoAssign"],
            json!({ "include": [{
                "StringEquals": { "principal.kind": "user" },
                "ArrayContains": { "identity.departments": [s.engineering] },
            }] })
        );

        // Teams: Platform with SRE below it; SRE's members also count for Platform above it.
        for person in [&s.alice, &s.bob, &s.carol] {
            add_team_member(org, &s.sre.id, person, "member", None).await;
        }
        let teams = suggest("team", json!({})).await;
        assert_eq!(
            teams
                .iter()
                .map(|item| json!([
                    item.unit["name"],
                    item.groups
                        .iter()
                        .map(|group| group["name"].clone())
                        .collect::<Vec<_>>()
                ]))
                .collect::<Vec<_>>(),
            [json!(["Platform", ["Wiki editors"]])]
        );
        assert!(
            suggest("team", json!({ "unitId": s.sre.id }))
                .await
                .is_empty()
        );
        assert_eq!(
            teams[0].package["autoAssign"]["include"],
            json!([{
                "StringEquals": { "principal.kind": "user" },
                "ArrayContains": { "identity.teams": [s.platform.id] },
            }])
        );
    });
}

/// What identity.teams / identity.departments hold and which packages name a unit (org-rules.ts).
#[test]
#[ignore = "needs licenses.ts loadLicenseFacts / licenseRuleKeys and package-rules.ts ruleValues (other port units)"]
fn reads_the_org_facts_rules_see() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        place(org, &s.platform_department, &s.alice).await;
        add_team_member(org, &s.sre.id, &s.alice, "member", None).await;
        // A synced membership counts only while a direct source membership backs it.
        let directory = org.group("Directory").await;
        org.patch(
            "teams",
            &s.platform.id,
            json!({ "syncGroupIds": [directory] }),
        )
        .await;
        org.insert(
            "teamMembers",
            json!({
                "id": better_iam_server::utils::id(), "tenantId": org.tenant_id,
                "uniqueKey": format!("{}:{}", s.platform.id, s.bob), "teamId": s.platform.id,
                "identityId": s.bob, "role": "member", "addedAt": org.now(), "addedBy": "sync",
                "source": "sync",
            }),
        )
        .await;
        let tx = org.iam.store.clone();
        let facts = load_org_facts(&tx, &org.tenant_id, org.now())
            .await
            .unwrap();
        assert_eq!(facts.team_ids.len(), 2);
        assert_eq!(facts.department_ids.len(), 2);
        let alice = facts.of(&s.alice, &[]);
        let mut teams = vec![s.platform.id.clone(), s.sre.id.clone()];
        teams.sort();
        assert_eq!(alice.teams, teams);
        let mut departments = vec![s.engineering.clone(), s.platform_department.clone()];
        departments.sort();
        assert_eq!(alice.departments, departments);
        assert!(facts.of(&s.bob, &[]).teams.is_empty());
        assert_eq!(
            facts.of(&s.bob, &[directory.clone()]).teams,
            [s.platform.id.clone()]
        );
        assert!(facts.of(&s.carol, &[]).departments.is_empty());

        let environment = org_rule_environment(&tx, &org.tenant_id).await.unwrap();
        assert_eq!(environment["teams"].as_array().unwrap().len(), 2);
        assert_eq!(environment["departments"].as_array().unwrap().len(), 2);

        for (name, key, value) in [
            ("Zeta kit", "identity.teams", s.platform.id.clone()),
            ("alpha kit", "identity.departments", s.engineering.clone()),
            ("Group kit", "identity.groups", s.platform.group_id.clone()),
        ] {
            org.insert(
                "accessPackages",
                json!({
                    "id": better_iam_server::utils::id(), "tenantId": org.tenant_id, "name": name,
                    "roleIds": [], "groupIds": [], "createdAt": org.now(), "updatedAt": org.now(),
                    "autoAssign": {
                        "include": [{ "ArrayContains": { key: [value] } }],
                        "ownerId": org.owner_id, "authorityId": org.authority_id,
                        "revision": 1, "updatedAt": org.now(),
                    },
                }),
            )
            .await;
        }
        assert_eq!(
            packages_naming(
                &tx,
                &org.tenant_id,
                "identity.teams",
                std::slice::from_ref(&s.platform.id),
                Some(std::slice::from_ref(&s.platform.group_id)),
            )
            .await
            .unwrap(),
            ["Group kit", "Zeta kit"]
        );
        assert_eq!(
            packages_naming(
                &tx,
                &org.tenant_id,
                "identity.departments",
                std::slice::from_ref(&s.engineering),
                None,
            )
            .await
            .unwrap(),
            ["alpha kit"]
        );
    });
}
