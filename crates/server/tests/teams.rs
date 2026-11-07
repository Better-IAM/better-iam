//! Port of the tests of `teams.ts`: tests/teams.test.ts (nested teams and their backing groups, roles through the
//! backing groups, principal.teams, temporary memberships and offboarding, team sync) and the helpers other modules
//! use (`teamsOf`, `primaryTeamOf`, `teamMaintainers`, `isTeamMaintainer`). The teams, groups, roles and bindings
//! API groups belong to other port units, so the records are written as those groups store them and the module
//! functions are called directly. Team sync reconciles license seats afterwards (licenses.ts, another unit), so the
//! sync scenario stays ignored until that is ported.

#![allow(clippy::cloned_ref_to_slice_refs)]

mod org_fixture;
mod teams_fixture;

use better_iam_core::{Filter, IamStoreExt};
use better_iam_server::teams::{
    MAX_TEAM_DEPTH, Team, assert_no_team_groups, assert_not_team_group, is_team_group,
    is_team_maintainer, load_team, primary_team_of, role_holds_deny, slug_from_name,
    sync_team_groups, sync_teams_from_groups, team_chain, team_chain_bindings, team_context,
    team_descendants, team_maintainers, team_slug, team_sync_groups, teams_of, teams_syncing_from,
    tenant_teams,
};
use org_fixture::{DAY, Org, code, run};
use serde_json::{Value, json};
use teams_fixture::{
    TeamRef, add_team_member, bind, can, create_team, group_members, leave_all_teams,
    permission_role, remove_team_member, role,
};

struct Scenario {
    org: Org,
    alice: String,
    bob: String,
    carol: String,
    reader: String,
    platform: TeamRef,
    sre: TeamRef,
}

async fn scenario() -> Scenario {
    let org = Org::new(|_| {}).await;
    let alice = org.member("alice").await.id;
    let bob = org.member("bob").await.id;
    let carol = org.member("carol").await.id;
    let reader = permission_role(&org, "Reader", "documents:read").await;
    let platform = create_team(&org, "Platform", "platform", None, &[]).await;
    add_team_member(&org, &platform.id, &bob, "maintainer", None).await;
    let sre = create_team(&org, "Site Reliability", "sre", Some(&platform.id), &[]).await;
    Scenario {
        org,
        alice,
        bob,
        carol,
        reader,
        platform,
        sre,
    }
}

#[test]
fn validates_and_derives_slugs() {
    assert_eq!(
        team_slug(Some(&json!("platform-team"))).unwrap(),
        "platform-team"
    );
    assert_eq!(team_slug(Some(&json!("a"))).unwrap(), "a");
    for bad in [
        json!("-lead"),
        json!("trail-"),
        json!("Upper"),
        json!(""),
        json!(7),
    ] {
        let error = team_slug(Some(&bad)).unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        assert_eq!(
            error.message,
            "slug must use 1-64 lowercase letters, digits, or inner hyphens"
        );
    }
    assert_eq!(team_slug(None).unwrap_err().code, "INVALID_INPUT");
    assert_eq!(
        team_slug(Some(&json!("a".repeat(65)))).unwrap_err().code,
        "INVALID_INPUT"
    );

    assert_eq!(
        slug_from_name("Platform Team").unwrap().as_deref(),
        Some("platform-team")
    );
    assert_eq!(
        slug_from_name("Site Reliability").unwrap().as_deref(),
        Some("site-reliability")
    );
    assert_eq!(
        slug_from_name("  Équipe Données!  ").unwrap().as_deref(),
        Some("equipe-donnees")
    );
    assert_eq!(
        slug_from_name("R&D / Ops").unwrap().as_deref(),
        Some("r-d-ops")
    );
    assert_eq!(slug_from_name("!!!").unwrap(), None);
    assert_eq!(slug_from_name("数据").unwrap(), None);
    // 64 characters at most, without a trailing hyphen left by the cut.
    let long = format!("{} tail", "a".repeat(63));
    assert_eq!(
        slug_from_name(&long).unwrap().as_deref(),
        Some("a".repeat(63).as_str())
    );
}

fn team(id: &str, parent: Option<&str>) -> Team {
    let mut record = json!({
        "id": id, "tenantId": "t", "name": id, "slug": id, "groupId": format!("g-{id}"),
        "joinPolicy": "closed", "memberManagement": "maintainers",
        "createdAt": 1, "createdBy": "x", "updatedAt": 1,
    });
    if let Some(parent) = parent {
        record["parentId"] = json!(parent);
    }
    serde_json::from_value(record).unwrap()
}

#[test]
fn walks_chains_and_descendants() {
    let teams: indexmap::IndexMap<String, Team> = [
        team("root", None),
        team("child", Some("root")),
        team("grandchild", Some("child")),
        team("orphan", Some("missing")),
        team("loop-a", Some("loop-b")),
        team("loop-b", Some("loop-a")),
    ]
    .into_iter()
    .map(|team| (team.id.clone(), team))
    .collect();
    let ids = |chain: Vec<Team>| chain.into_iter().map(|team| team.id).collect::<Vec<_>>();
    assert_eq!(
        ids(team_chain(&teams, "grandchild").unwrap()),
        ["grandchild", "child", "root"]
    );
    assert_eq!(ids(team_chain(&teams, "orphan").unwrap()), ["orphan"]);
    assert_eq!(
        ids(team_chain(&teams, "loop-a").unwrap()),
        ["loop-a", "loop-b"]
    );
    assert!(team_chain(&teams, "unknown").unwrap().is_empty());
    let list = json!(teams.values().collect::<Vec<_>>());
    assert_eq!(
        ids(team_descendants(&list, "root").unwrap()),
        ["child", "grandchild"]
    );
    assert!(team_descendants(&list, "grandchild").unwrap().is_empty());
    assert_eq!(ids(team_descendants(&list, "loop-a").unwrap()), ["loop-b"]);

    // A chain stops after the team and MAX_TEAM_DEPTH levels above it.
    let mut deep: indexmap::IndexMap<String, Team> = indexmap::IndexMap::new();
    for level in 0..20 {
        let parent = (level > 0).then(|| format!("t{}", level - 1));
        let team = team(&format!("t{level}"), parent.as_deref());
        deep.insert(team.id.clone(), team);
    }
    assert_eq!(
        team_chain(&deep, "t19").unwrap().len(),
        MAX_TEAM_DEPTH as usize + 1
    );
}

#[test]
fn gives_child_team_members_the_parent_team_roles_through_the_backing_groups() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        bind(org, "group", &s.platform.group_id, &s.reader).await;
        let alice = org.sign_in("alice").await;
        assert!(!can(org, &alice, "documents:read").await);
        add_team_member(org, &s.sre.id, &s.alice, "member", None).await;
        assert!(can(org, &alice, "documents:read").await);
        // Bob directly, Alice through SRE; SRE's own group holds Alice only.
        let mut expected = vec![s.alice.clone(), s.bob.clone()];
        expected.sort();
        assert_eq!(group_members(org, &s.platform.group_id).await, expected);
        assert_eq!(group_members(org, &s.sre.group_id).await, [s.alice.clone()]);
        let inherited = org
            .find(
                "groupMembers",
                Filter::new()
                    .eq("groupId", s.platform.group_id.as_str())
                    .eq("identityId", s.alice.as_str()),
            )
            .await;
        assert_eq!(inherited[0]["teamId"], json!(s.platform.id));
        assert_eq!(
            inherited[0]["uniqueKey"],
            json!(format!("{}:{}", s.platform.group_id, s.alice))
        );

        // Helpers other modules use (billing attributes spend with them).
        let tx = org.iam.store.clone();
        assert_eq!(
            teams_of(&tx, &org.tenant_id, &s.alice, None).await.unwrap(),
            [s.sre.id.clone()]
        );
        let mut both = teams_of(
            &tx,
            &org.tenant_id,
            &s.alice,
            Some(&json!({ "includeAncestors": true })),
        )
        .await
        .unwrap();
        both.sort();
        let mut expected = vec![s.platform.id.clone(), s.sre.id.clone()];
        expected.sort();
        assert_eq!(both, expected);
        assert_eq!(
            primary_team_of(&tx, &org.tenant_id, &s.alice, None)
                .await
                .unwrap(),
            Some(s.sre.id.clone())
        );
        assert_eq!(
            team_maintainers(&tx, &org.tenant_id, &s.platform.id, None)
                .await
                .unwrap(),
            [s.bob.clone()]
        );
        assert!(
            !is_team_maintainer(&tx, &org.tenant_id, &s.sre.id, &s.bob, None)
                .await
                .unwrap()
        );
        assert!(
            is_team_maintainer(
                &tx,
                &org.tenant_id,
                &s.sre.id,
                &s.bob,
                Some(&json!({ "includeAncestors": true }))
            )
            .await
            .unwrap()
        );
        assert!(
            teams_of(&tx, &org.tenant_id, &s.carol, None)
                .await
                .unwrap()
                .is_empty()
        );

        remove_team_member(org, &s.sre.id, &s.alice).await;
        assert!(!can(org, &alice, "documents:read").await);
        assert_eq!(
            group_members(org, &s.platform.group_id).await,
            [s.bob.clone()]
        );
        assert!(group_members(org, &s.sre.group_id).await.is_empty());
    });
}

#[test]
fn exposes_principal_teams_to_policies_including_the_teams_above() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let readers = role(
            org,
            "Platform readers",
            json!([{
                "effect": "allow",
                "actions": ["documents:read"],
                "resources": ["*"],
                "conditions": { "ArrayContains": { "principal.teams": [s.platform.id] } },
            }]),
        )
        .await;
        bind(org, "identity", &s.alice, &readers).await;
        let alice = org.sign_in("alice").await;
        assert!(!can(org, &alice, "documents:read").await);
        add_team_member(org, &s.sre.id, &s.alice, "member", None).await;
        assert!(can(org, &alice, "documents:read").await);

        let context = team_context(&org.iam.store, &org.tenant_id, &s.alice, org.now())
            .await
            .unwrap();
        let mut expected = vec![s.platform.id.clone(), s.sre.id.clone()];
        expected.sort();
        assert_eq!(context["principal.teams"], json!(expected));
        let empty = team_context(&org.iam.store, &org.tenant_id, &s.carol, org.now())
            .await
            .unwrap();
        assert_eq!(Value::Object(empty), json!({ "principal.teams": [] }));
    });
}

#[test]
fn ends_temporary_memberships_and_cleans_up_on_offboarding_and_deletion() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        bind(org, "group", &s.platform.group_id, &s.reader).await;
        add_team_member(
            org,
            &s.sre.id,
            &s.alice,
            "member",
            Some(org.now() + 3_600_000.0),
        )
        .await;
        let alice = org.sign_in("alice").await;
        assert!(can(org, &alice, "documents:read").await);
        let inherited = org
            .find(
                "groupMembers",
                Filter::new()
                    .eq("groupId", s.platform.group_id.as_str())
                    .eq("identityId", s.alice.as_str()),
            )
            .await;
        assert_eq!(inherited[0]["expiresAt"], num(org.now() + 3_600_000.0));
        org.advance(2.0 * 3_600_000.0);
        assert!(!can(org, &alice, "documents:read").await);
        let tx = org.iam.store.clone();
        assert!(
            teams_of(
                &tx,
                &org.tenant_id,
                &s.alice,
                Some(&json!({ "at": org.now() }))
            )
            .await
            .unwrap()
            .is_empty()
        );
        // At an earlier moment the membership still counted.
        assert_eq!(
            teams_of(
                &tx,
                &org.tenant_id,
                &s.alice,
                Some(&json!({ "at": org.now() - 3.0 * 3_600_000.0 }))
            )
            .await
            .unwrap(),
            [s.sre.id.clone()]
        );
        // The retention sweep removes ended records; a sync leaves the lapsed person out of the backing groups.
        for member in org
            .find(
                "teamMembers",
                Filter::new().eq("identityId", s.alice.as_str()),
            )
            .await
        {
            let id = member["id"].as_str().unwrap().to_owned();
            org.iam
                .store
                .transaction(|tx| async move { tx.delete("teamMembers", &id).await })
                .await
                .unwrap();
        }

        add_team_member(org, &s.sre.id, &s.alice, "member", None).await;
        // A pending join request is cancelled with the memberships.
        let request_id = better_iam_server::utils::id();
        org.insert(
            "teamJoinRequests",
            json!({
                "id": request_id, "tenantId": org.tenant_id, "teamId": s.platform.id,
                "identityId": s.alice, "status": "pending", "requestedAt": org.now(),
                "expiresAt": org.now() + 7.0 * DAY,
            }),
        )
        .await;
        // A stale backing-group membership written before a repair goes too.
        let stray = create_team(org, "Stray", "stray", None, &[]).await;
        org.insert(
            "groupMembers",
            json!({
                "id": better_iam_server::utils::id(), "tenantId": org.tenant_id,
                "uniqueKey": format!("{}:{}", stray.group_id, s.alice), "groupId": stray.group_id,
                "identityId": s.alice, "teamId": stray.id,
            }),
        )
        .await;
        // An ordinary group membership stays.
        let ordinary = org.group("Ordinary").await;
        org.add_member(&ordinary, &s.alice).await;
        assert_eq!(leave_all_teams(org, &s.alice).await, 1.0);
        let left: Vec<String> = org
            .find(
                "groupMembers",
                Filter::new()
                    .eq("tenantId", org.tenant_id.as_str())
                    .eq("identityId", s.alice.as_str()),
            )
            .await
            .iter()
            .map(|member| member["groupId"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(left, [ordinary.clone()]);
        let request = org.get("teamJoinRequests", &request_id).await.unwrap();
        assert_eq!(request["status"], json!("cancelled"));
        assert_eq!(request["decidedAt"], num(org.now()));
        assert!(!can(org, &alice, "documents:read").await);
        assert_eq!(leave_all_teams(org, &s.alice).await, 0.0);

        // A deleted person leaves the backing groups on the next sync.
        org.patch("identities", &s.bob, json!({ "status": "deleted" }))
            .await;
        let tenant_id = org.tenant_id.clone();
        let platform_id = s.platform.id.clone();
        let now = org.now();
        let result = org
            .iam
            .store
            .transaction(|tx| async move {
                sync_team_groups(&tx, &tenant_id, &json!([platform_id]), now).await
            })
            .await
            .unwrap();
        assert_eq!(
            (result.added, result.removed, result.updated),
            (0.0, 1.0, 0.0)
        );
        assert!(group_members(org, &s.platform.group_id).await.is_empty());
    });
}

#[test]
fn merges_memberships_and_ends_activations_of_the_backing_group() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        // Temporary in SRE and permanent in Platform: permanent in Platform's group.
        add_team_member(org, &s.sre.id, &s.alice, "member", Some(org.now() + DAY)).await;
        add_team_member(org, &s.platform.id, &s.alice, "member", None).await;
        assert!(
            membership(org, &s.platform.group_id, &s.alice)
                .await
                .get("expiresAt")
                .is_none()
        );
        // Two temporary sources: the latest end counts.
        let deep = create_team(org, "Deep", "deep", Some(&s.sre.id), &[]).await;
        add_team_member(
            org,
            &deep.id,
            &s.carol,
            "member",
            Some(org.now() + 2.0 * DAY),
        )
        .await;
        add_team_member(
            org,
            &s.sre.id,
            &s.carol,
            "member",
            Some(org.now() + 5.0 * DAY),
        )
        .await;
        let carol = org
            .find(
                "groupMembers",
                Filter::new()
                    .eq("groupId", s.platform.group_id.as_str())
                    .eq("identityId", s.carol.as_str()),
            )
            .await;
        assert_eq!(carol[0]["expiresAt"], num(org.now() + 5.0 * DAY));
        let deep_group = org
            .find(
                "groupMembers",
                Filter::new()
                    .eq("groupId", deep.group_id.as_str())
                    .eq("identityId", s.carol.as_str()),
            )
            .await;
        assert_eq!(deep_group[0]["expiresAt"], num(org.now() + 2.0 * DAY));

        // An eligible binding on Platform's group, activated by Alice, ends when she leaves the group.
        let binding = bind(org, "group", &s.platform.group_id, &s.reader).await;
        org.patch("bindings", &binding, json!({ "eligible": true }))
            .await;
        let activation = better_iam_server::utils::id();
        org.insert(
            "bindingActivations",
            json!({
                "id": activation, "tenantId": org.tenant_id,
                "uniqueKey": format!("{binding}:{}", s.alice), "bindingId": binding,
                "identityId": s.alice, "roleId": s.reader, "activatedAt": org.now(),
                "expiresAt": org.now() + 3_600_000.0, "createdBy": s.alice,
            }),
        )
        .await;
        remove_team_member(org, &s.platform.id, &s.alice).await;
        // Still in Platform's group through SRE (temporary now): the activation stays.
        assert_eq!(
            membership(org, &s.platform.group_id, &s.alice).await["expiresAt"],
            num(org.now() + DAY)
        );
        assert!(org.get("bindingActivations", &activation).await.is_some());
        remove_team_member(org, &s.sre.id, &s.alice).await;
        assert!(org.get("bindingActivations", &activation).await.is_none());

        // A backing-group membership changed by hand loses its package link and regains the team on the next sync.
        let manual = membership(org, &s.sre.group_id, &s.carol).await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        org.patch(
            "groupMembers",
            &manual,
            json!({ "packageAssignmentId": "assignment", "teamId": null }),
        )
        .await;
        let tenant_id = org.tenant_id.clone();
        let sre_id = s.sre.id.clone();
        let now = org.now();
        let result = org
            .iam
            .store
            .transaction(|tx| async move {
                sync_team_groups(&tx, &tenant_id, &json!([sre_id]), now).await
            })
            .await
            .unwrap();
        assert_eq!(
            (result.added, result.removed, result.updated),
            (0.0, 0.0, 1.0)
        );
        let repaired = org.get("groupMembers", &manual).await.unwrap();
        assert!(repaired.get("packageAssignmentId").is_none());
        assert_eq!(repaired["teamId"], json!(s.sre.id));
        assert_eq!(repaired["expiresAt"], num(org.now() + 5.0 * DAY));
        // Idempotent.
        let tenant_id = org.tenant_id.clone();
        let sre_id = s.sre.id.clone();
        let again = org
            .iam
            .store
            .transaction(|tx| async move {
                sync_team_groups(&tx, &tenant_id, &json!([sre_id, "unknown"]), now).await
            })
            .await
            .unwrap();
        assert_eq!((again.added, again.removed, again.updated), (0.0, 0.0, 0.0));
    });
}

#[test]
fn loads_teams_and_guards_their_backing_groups() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let tx = org.iam.store.clone();
        let loaded = load_team(&tx, &org.tenant_id, Some(&json!(s.sre.id)))
            .await
            .unwrap();
        assert_eq!(loaded.slug, "sre");
        assert_eq!(loaded.parent_id.as_deref(), Some(s.platform.id.as_str()));
        let missing = load_team(&tx, &org.tenant_id, Some(&json!("nope")))
            .await
            .unwrap_err();
        assert_eq!(
            (
                missing.code.as_str(),
                missing.message.as_str(),
                missing.status
            ),
            ("NOT_FOUND", "Team not found", 404)
        );
        let foreign = load_team(&tx, &org.root_tenant_id, Some(&json!(s.sre.id)))
            .await
            .unwrap_err();
        assert_eq!(foreign.code, "NOT_FOUND");
        for bad in [None, Some(json!("")), Some(json!(5))] {
            let error = load_team(&tx, &org.tenant_id, bad.as_ref())
                .await
                .unwrap_err();
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                ("INVALID_INPUT", "Invalid teamId")
            );
        }
        assert_eq!(tenant_teams(&tx, &org.tenant_id).await.unwrap().len(), 2);

        let backing = org
            .get("groups", &s.platform.group_id)
            .await
            .map(Value::Object);
        assert!(is_team_group(backing.as_ref()).unwrap());
        let error = assert_not_team_group(backing.as_ref()).unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str(), error.status),
            (
                "TEAM_MANAGED",
                "This group belongs to a team; manage its members with the teams API",
                409
            )
        );
        let ordinary_id = org.group("Ordinary").await;
        let ordinary = org.get("groups", &ordinary_id).await.map(Value::Object);
        assert!(!is_team_group(ordinary.as_ref()).unwrap());
        assert!(assert_not_team_group(ordinary.as_ref()).is_ok());
        assert!(assert_not_team_group(None).is_ok());
        assert!(!is_team_group(Some(&json!({ "teamId": 5 }))).unwrap());
        assert!(
            assert_no_team_groups(&tx, &[ordinary_id.clone(), "missing".into()])
                .await
                .is_ok()
        );
        assert_eq!(
            code(assert_no_team_groups(&tx, &[ordinary_id.clone(), s.sre.group_id.clone()]).await),
            "TEAM_MANAGED"
        );
    });
}

#[test]
fn validates_source_groups_and_finds_the_teams_syncing_from_them() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let tx = org.iam.store.clone();
        let directory = org.group("Okta: Engineers").await;
        assert_eq!(
            team_sync_groups(&tx, &org.tenant_id, Some(&json!([directory, directory])))
                .await
                .unwrap(),
            [directory.clone()]
        );
        assert!(
            team_sync_groups(&tx, &org.tenant_id, Some(&json!([])))
                .await
                .unwrap()
                .is_empty()
        );
        let too_many = json!((0..11).map(|n| format!("g{n}")).collect::<Vec<_>>());
        for bad in [Some(too_many), Some(json!("x")), None] {
            let error = team_sync_groups(&tx, &org.tenant_id, bad.as_ref())
                .await
                .unwrap_err();
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                ("INVALID_INPUT", "syncGroupIds must list at most 10 groups")
            );
        }
        let missing = team_sync_groups(&tx, &org.tenant_id, Some(&json!(["nope"])))
            .await
            .unwrap_err();
        assert_eq!(
            (
                missing.code.as_str(),
                missing.message.as_str(),
                missing.status
            ),
            ("NOT_FOUND", "Group nope not found", 404)
        );
        let backing = team_sync_groups(&tx, &org.tenant_id, Some(&json!([s.platform.group_id])))
            .await
            .unwrap_err();
        assert_eq!(
            (backing.code.as_str(), backing.message.as_str()),
            (
                "INVALID_INPUT",
                "A team cannot sync from another team\u{2019}s backing group"
            )
        );

        let engineers =
            create_team(org, "Engineers", "engineers", None, &[directory.clone()]).await;
        let syncing: Vec<String> = teams_syncing_from(&tx, &org.tenant_id, &directory)
            .await
            .unwrap()
            .into_iter()
            .map(|team| team.id)
            .collect();
        assert_eq!(syncing, [engineers.id.clone()]);
        assert!(
            teams_syncing_from(&tx, &org.tenant_id, "other")
                .await
                .unwrap()
                .is_empty()
        );

        // Nothing to sync: no reconciliation, nothing changes.
        let ctx = org.iam.ctx.clone();
        let tenant_id = org.tenant_id.clone();
        let result = org
            .iam
            .store
            .transaction(|tx| async move {
                sync_teams_from_groups(
                    &ctx,
                    &tx,
                    &tenant_id,
                    &json!({ "teamIds": [], "actorId": "directory-sync" }),
                )
                .await
            })
            .await
            .unwrap();
        assert_eq!(
            (result.added, result.removed, result.updated),
            (0.0, 0.0, 0.0)
        );
        assert!(result.teams.is_empty());
    });
}

#[test]
fn finds_what_a_team_chain_hands_out_and_which_roles_carry_denies() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let tx = org.iam.store.clone();
        let parent_binding = bind(org, "group", &s.platform.group_id, &s.reader).await;
        let writer = permission_role(org, "Writer", "documents:write").await;
        let child_binding = bind(org, "group", &s.sre.group_id, &writer).await;
        bind(org, "identity", &s.alice, &writer).await;
        let ids = |bindings: Vec<better_iam_server::models::Binding>| {
            bindings
                .into_iter()
                .map(|binding| binding.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids(team_chain_bindings(&tx, &org.tenant_id, &json!([s.sre.id]))
                .await
                .unwrap()),
            [child_binding.clone(), parent_binding.clone()]
        );
        assert_eq!(
            ids(
                team_chain_bindings(&tx, &org.tenant_id, &json!([s.platform.id, s.sre.id]))
                    .await
                    .unwrap()
            ),
            [parent_binding.clone(), child_binding.clone()]
        );
        assert!(
            team_chain_bindings(&tx, &org.tenant_id, &json!([]))
                .await
                .unwrap()
                .is_empty()
        );

        // Deny in an attached policy of an inherited role.
        let policy = better_iam_server::utils::id();
        org.insert(
            "policies",
            json!({
                "id": policy, "tenantId": org.tenant_id, "name": "No deletes",
                "document": { "version": 1, "statements": [
                    { "effect": "deny", "actions": ["documents:delete"], "resources": ["*"] }
                ] },
            }),
        )
        .await;
        let base = better_iam_server::utils::id();
        org.insert(
            "roles",
            json!({ "id": base, "tenantId": org.tenant_id, "name": "Base", "policyIds": [policy], "protected": false }),
        )
        .await;
        let derived = better_iam_server::utils::id();
        org.insert(
            "roles",
            json!({
                "id": derived, "tenantId": org.tenant_id, "name": "Derived", "policyIds": [],
                "inherits": [base, derived], "protected": false,
                "document": { "version": 1, "statements": [
                    { "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }
                ] },
            }),
        )
        .await;
        assert!(role_holds_deny(&tx, &derived).await.unwrap());
        assert!(role_holds_deny(&tx, &base).await.unwrap());
        assert!(!role_holds_deny(&tx, &s.reader).await.unwrap());
        assert!(!role_holds_deny(&tx, "missing").await.unwrap());
        let inline = role(
            org,
            "Inline deny",
            json!([{ "effect": "deny", "actions": ["documents:read"], "resources": ["*"] }]),
        )
        .await;
        assert!(role_holds_deny(&tx, &inline).await.unwrap());
    });
}

/// tests/teams.test.ts "keeps a team in step with its source groups (team sync)", through the module: needs
/// licenses.ts `reconcileGroupLicenses` (another unit) after every change.
#[test]
#[ignore = "needs licenses.ts reconcileGroupLicenses (port unit licenses)"]
fn keeps_a_team_in_step_with_its_source_groups() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let directory = org.group("Okta: Engineers").await;
        org.add_member(&directory, &s.alice).await;
        org.add_member(&directory, &s.bob).await;
        let engineers =
            create_team(org, "Engineers", "engineers", None, &[directory.clone()]).await;
        let sync = |group_id: Option<&str>| {
            let ctx = org.iam.ctx.clone();
            let tenant_id = org.tenant_id.clone();
            let mut options = json!({ "actorId": "directory-sync" });
            match group_id {
                Some(group_id) => options["groupId"] = json!(group_id),
                None => options["teamIds"] = json!([engineers.id]),
            }
            async move {
                org.iam
                    .store
                    .transaction(|tx| async move {
                        sync_teams_from_groups(&ctx, &tx, &tenant_id, &options).await
                    })
                    .await
                    .unwrap()
            }
        };
        let members = || async {
            let mut names: Vec<String> = org
                .find(
                    "teamMembers",
                    Filter::new().eq("teamId", engineers.id.as_str()),
                )
                .await
                .iter()
                .map(|member| {
                    format!(
                        "{}:{}",
                        member["identityId"].as_str().unwrap(),
                        member
                            .get("source")
                            .and_then(Value::as_str)
                            .unwrap_or("manual")
                    )
                })
                .collect();
            names.sort();
            names
        };
        let first = sync(None).await;
        assert_eq!(
            (first.added, first.teams.clone()),
            (2.0, vec![engineers.id.clone()])
        );
        let mut expected = vec![format!("{}:sync", s.alice), format!("{}:sync", s.bob)];
        expected.sort();
        assert_eq!(members().await, expected);
        let mut backing = vec![s.alice.clone(), s.bob.clone()];
        backing.sort();
        assert_eq!(group_members(org, &engineers.group_id).await, backing);

        // Group changes flow into the team; manual members stay.
        add_team_member(org, &engineers.id, &s.carol, "member", None).await;
        for member in org
            .find(
                "groupMembers",
                Filter::new()
                    .eq("groupId", directory.as_str())
                    .eq("identityId", s.alice.as_str()),
            )
            .await
        {
            let id = member["id"].as_str().unwrap().to_owned();
            org.iam
                .store
                .transaction(|tx| async move { tx.delete("groupMembers", &id).await })
                .await
                .unwrap();
        }
        org.insert(
            "groupMembers",
            json!({
                "id": better_iam_server::utils::id(), "tenantId": org.tenant_id,
                "uniqueKey": format!("{directory}:{}", s.carol), "groupId": directory,
                "identityId": s.carol, "expiresAt": org.now() + DAY,
            }),
        )
        .await;
        let second = sync(Some(&directory)).await;
        assert_eq!((second.added, second.removed), (0.0, 1.0));
        let mut expected = vec![format!("{}:sync", s.bob), format!("{}:manual", s.carol)];
        expected.sort();
        assert_eq!(members().await, expected);

        // A temporary source membership makes a temporary synced membership.
        let dave = org.member("dave").await.id;
        org.insert(
            "groupMembers",
            json!({
                "id": better_iam_server::utils::id(), "tenantId": org.tenant_id,
                "uniqueKey": format!("{directory}:{dave}"), "groupId": directory,
                "identityId": dave, "expiresAt": org.now() + 3_600_000.0,
            }),
        )
        .await;
        sync(Some(&directory)).await;
        let synced = org
            .find(
                "teamMembers",
                Filter::new()
                    .eq("teamId", engineers.id.as_str())
                    .eq("identityId", dave.as_str()),
            )
            .await;
        assert_eq!(synced[0]["source"], json!("sync"));
        assert_eq!(synced[0]["expiresAt"], num(org.now() + 3_600_000.0));
        let events = org
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", org.tenant_id.as_str())
                    .eq("action", "team:member:remove"),
            )
            .await;
        assert!(
            events
                .iter()
                .any(|event| event["actorId"] == json!("directory-sync")
                    && event["metadata"]["source"] == json!("sync")
                    && event["metadata"]["team"] == json!("engineers"))
        );

        // Turning sync off removes the synced members and keeps the manual ones.
        org.patch("teams", &engineers.id, json!({ "syncGroupIds": null }))
            .await;
        sync(None).await;
        assert_eq!(members().await, [format!("{}:manual", s.carol)]);
    });
}

/// One person's membership of one group.
async fn membership(org: &Org, group_id: &str, identity_id: &str) -> better_iam_core::Record {
    org.find(
        "groupMembers",
        Filter::new()
            .eq("groupId", group_id)
            .eq("identityId", identity_id),
    )
    .await
    .remove(0)
}

/// A JavaScript number as the server writes it (`1`, not `1.0`).
fn num(value: f64) -> Value {
    better_iam_server::js::number(value)
}
