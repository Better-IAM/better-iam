//! Port of the tests of `team-reviews.ts`: tests/team-reviews.test.ts (completing a review removes the people decided
//! or defaulted to `remove`, leaves synced and departed members alone, audits each removal and the completion; the
//! scheduler job closes overdue reviews in active organizations). Teams, reviews and their items are written as the
//! teams API group (another port unit) stores them, and the module functions are called directly. The scheduler job
//! re-evaluates birthright packages afterwards (api/package-automation.ts, another unit), so these tests do not
//! assert on its `failed` list.

#![allow(clippy::cloned_ref_to_slice_refs)]

mod org_fixture;
mod teams_fixture;

use better_iam_core::{Filter, IamStoreExt};
use better_iam_server::team_reviews::{
    DEFAULT_REVIEW_MS, MAX_REVIEW_MS, MIN_REVIEW_MS, TeamReview, close_overdue_team_reviews,
    complete_team_review, complete_team_review_of,
};
use org_fixture::{DAY, Org, run};
use serde_json::{Value, json};
use teams_fixture::{TeamRef, add_team_member, create_team, group_members};

struct Scenario {
    org: Org,
    alice: String,
    bob: String,
    carol: String,
    dave: String,
    erin: String,
    team: TeamRef,
}

/// Platform: Bob maintains it; Alice, Carol and Dave are manual members; Erin comes from team sync.
async fn scenario() -> Scenario {
    let org = Org::new(|_| {}).await;
    let alice = org.member("alice").await.id;
    let bob = org.member("bob").await.id;
    let carol = org.member("carol").await.id;
    let dave = org.member("dave").await.id;
    let erin = org.member("erin").await.id;
    let contractors = org.group("Contractors").await;
    org.add_member(&contractors, &erin).await;
    let team = create_team(&org, "Platform", "platform", None, &[contractors]).await;
    add_team_member(&org, &team.id, &bob, "maintainer", None).await;
    for person in [&alice, &carol, &dave] {
        add_team_member(&org, &team.id, person, "member", None).await;
    }
    // Team sync's member (as syncTeamsFromGroups writes it).
    org.insert(
        "teamMembers",
        json!({
            "id": better_iam_server::utils::id(), "tenantId": org.tenant_id,
            "uniqueKey": format!("{}:{erin}", team.id), "teamId": team.id, "identityId": erin,
            "role": "member", "addedAt": org.now(), "addedBy": "directory-sync", "source": "sync",
        }),
    )
    .await;
    Scenario {
        org,
        alice,
        bob,
        carol,
        dave,
        erin,
        team,
    }
}

/// Opens a review of the team's manual members, as `teams.startReview` stores it.
async fn start_review(s: &Scenario, due_at: f64, on_undecided: &str) -> String {
    let org = &s.org;
    let review_id = better_iam_server::utils::id();
    org.insert(
        "teamReviews",
        json!({
            "id": review_id, "tenantId": org.tenant_id, "uniqueKey": format!("open:{}", s.team.id),
            "teamId": s.team.id, "status": "open", "onUndecided": on_undecided,
            "startedAt": org.now(), "startedBy": org.owner_id, "dueAt": due_at,
        }),
    )
    .await;
    for member in org
        .find(
            "teamMembers",
            Filter::new().eq("teamId", s.team.id.as_str()),
        )
        .await
    {
        if member.get("source").is_some() {
            continue;
        }
        let identity_id = member["identityId"].as_str().unwrap();
        org.insert(
            "teamReviewItems",
            json!({
                "id": better_iam_server::utils::id(), "tenantId": org.tenant_id,
                "uniqueKey": format!("{review_id}:{identity_id}"), "reviewId": review_id,
                "teamId": s.team.id, "identityId": identity_id, "role": member["role"],
            }),
        )
        .await;
    }
    review_id
}

/// Records a decision on one person, as `teams.decideReview` stores it.
async fn decide(s: &Scenario, review_id: &str, identity_id: &str, decision: &str) {
    let org = &s.org;
    let item = org
        .find(
            "teamReviewItems",
            Filter::new()
                .eq("reviewId", review_id)
                .eq("identityId", identity_id),
        )
        .await
        .remove(0);
    org.patch(
        "teamReviewItems",
        item["id"].as_str().unwrap(),
        json!({ "decision": decision, "decidedBy": s.bob, "decidedAt": org.now() }),
    )
    .await;
}

async fn members(s: &Scenario) -> Vec<String> {
    let mut ids: Vec<String> = s
        .org
        .find(
            "teamMembers",
            Filter::new().eq("teamId", s.team.id.as_str()),
        )
        .await
        .iter()
        .map(|member| member["identityId"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}

fn num(value: f64) -> Value {
    better_iam_server::js::number(value)
}

#[test]
fn review_windows_match_the_typescript_limits() {
    assert_eq!(MIN_REVIEW_MS, DAY);
    assert_eq!(MAX_REVIEW_MS, 90.0 * DAY);
    assert_eq!(DEFAULT_REVIEW_MS, 14.0 * DAY);
}

#[test]
fn applies_the_decisions_when_a_maintainer_completes_the_review() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let review_id = start_review(&s, org.now() + 14.0 * DAY, "keep").await;
        decide(&s, &review_id, &s.alice, "keep").await;
        decide(&s, &review_id, &s.carol, "remove").await;
        decide(&s, &review_id, &s.dave, "remove").await;
        // Dave left before the review completed: he is gone, not removed.
        let dave_member = org
            .find(
                "teamMembers",
                Filter::new()
                    .eq("teamId", s.team.id.as_str())
                    .eq("identityId", s.dave.as_str()),
            )
            .await
            .remove(0);
        let dave_id = dave_member["id"].as_str().unwrap().to_owned();
        org.iam
            .store
            .transaction(|tx| async move { tx.delete("teamMembers", &dave_id).await })
            .await
            .unwrap();
        org.advance(DAY);
        let principal = org
            .iam
            .ctx
            .principals()
            .unwrap()
            .authenticate(&org.sign_in("bob").await)
            .await
            .unwrap();
        let review: TeamReview =
            better_iam_server::port::decode(org.get("teamReviews", &review_id).await.unwrap())
                .unwrap();
        let ctx = org.iam.ctx.clone();
        let done = org
            .iam
            .store
            .transaction(|tx| async move {
                complete_team_review(&ctx, &tx, &review, Some(&principal)).await
            })
            .await
            .unwrap();
        assert_eq!(done["removed"], json!([s.carol]));
        assert_eq!(done["review"]["status"], json!("completed"));
        assert_eq!(done["review"]["completedBy"], json!(s.bob));
        assert_eq!(done["review"]["completedAt"], num(org.now()));
        assert!(done["review"].get("uniqueKey").is_none());
        // Bob was undecided and the review keeps the undecided.
        assert_eq!(
            done["review"]["outcome"],
            json!({ "kept": 2, "removed": 1, "undecided": 1, "gone": 1 })
        );
        let stored = org.get("teamReviews", &review_id).await.unwrap();
        assert_eq!(Value::Object(stored), done["review"]);
        assert_eq!(
            members(&s).await,
            sorted(vec![s.alice.clone(), s.bob.clone(), s.erin.clone()])
        );
        assert_eq!(
            group_members(org, &s.team.group_id).await,
            sorted(vec![s.alice.clone(), s.bob.clone(), s.erin.clone()])
        );
        let events = org
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", org.tenant_id.as_str())
                    .eq("resourceId", s.team.id.as_str()),
            )
            .await;
        let removal = events
            .iter()
            .find(|event| event["action"] == json!("team:member:remove"))
            .expect("removal audited");
        assert_eq!(removal["actorId"], json!(s.bob));
        assert_eq!(
            removal["metadata"],
            json!({ "identityId": s.carol, "role": "member", "source": "review", "reviewId": review_id })
        );
        let completion = events
            .iter()
            .find(|event| event["action"] == json!("team:review:complete"))
            .expect("completion audited");
        assert_eq!(
            completion["metadata"],
            json!({ "reviewId": review_id, "kept": 2, "removed": 1, "undecided": 1, "gone": 1 })
        );
    });
}

#[test]
fn removes_the_undecided_when_the_review_says_so() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let review_id = start_review(&s, org.now() + 2.0 * DAY, "remove").await;
        decide(&s, &review_id, &s.alice, "keep").await;
        let review: TeamReview =
            better_iam_server::port::decode(org.get("teamReviews", &review_id).await.unwrap())
                .unwrap();
        let ctx = org.iam.ctx.clone();
        let done = org
            .iam
            .store
            .transaction(
                |tx| async move { complete_team_review_of(&ctx, &tx, &review, None).await },
            )
            .await
            .unwrap();
        assert_eq!(
            sorted(done.removed.clone()),
            sorted(vec![s.bob.clone(), s.carol.clone(), s.dave.clone()])
        );
        assert_eq!(done.review["completedBy"], json!("deployment-operator"));
        assert_eq!(
            done.review["outcome"],
            json!({ "kept": 1, "removed": 3, "undecided": 3, "gone": 0 })
        );
        // The synced member stays.
        assert_eq!(
            members(&s).await,
            sorted(vec![s.alice.clone(), s.erin.clone()])
        );
        let removals = org
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", org.tenant_id.as_str())
                    .eq("action", "team:member:remove"),
            )
            .await;
        assert_eq!(removals.len(), 3);
        assert!(
            removals
                .iter()
                .all(|event| event["actorId"] == json!("deployment-operator")
                    && event["metadata"]["undecided"] == json!(true)
                    && event["outcome"] == json!("allow"))
        );
    });
}

#[test]
fn closes_overdue_reviews_on_schedule() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let review_id = start_review(&s, org.now() + 2.0 * DAY, "remove").await;
        decide(&s, &review_id, &s.alice, "keep").await;
        // Not due yet: nothing happens.
        let result = close_overdue_team_reviews(&org.iam.ctx, None)
            .await
            .unwrap();
        assert_eq!(result["completed"], json!(0));
        assert_eq!(result["removed"], json!(0));
        assert_eq!(result["failed"], json!([]));
        // Another organization's filter leaves it alone.
        org.advance(3.0 * DAY);
        let other = close_overdue_team_reviews(
            &org.iam.ctx,
            Some(&json!({ "tenantId": org.root_tenant_id })),
        )
        .await
        .unwrap();
        assert_eq!(other["completed"], json!(0));
        let result =
            close_overdue_team_reviews(&org.iam.ctx, Some(&json!({ "tenantId": org.tenant_id })))
                .await
                .unwrap();
        assert_eq!(result["completed"], json!(1));
        assert_eq!(result["removed"], json!(3));
        // Undecided people (bob, carol, dave) left; the synced member stays.
        assert_eq!(
            members(&s).await,
            sorted(vec![s.alice.clone(), s.erin.clone()])
        );
        let closed = org.get("teamReviews", &review_id).await.unwrap();
        assert_eq!(closed["status"], json!("completed"));
        assert_eq!(closed["completedBy"], json!("deployment-operator"));
        assert_eq!(
            closed["outcome"],
            json!({ "kept": 1, "removed": 3, "undecided": 3, "gone": 0 })
        );
        // Completed reviews are not closed twice.
        let again = close_overdue_team_reviews(&org.iam.ctx, None)
            .await
            .unwrap();
        assert_eq!(again["completed"], json!(0));
        assert_eq!(again["failed"], json!([]));
    });
}

#[test]
fn skips_reviews_of_suspended_organizations_and_deleted_teams() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let review_id = start_review(&s, org.now() + DAY, "remove").await;
        org.advance(2.0 * DAY);
        org.patch("tenants", &org.tenant_id, json!({ "status": "suspended" }))
            .await;
        let result = close_overdue_team_reviews(&org.iam.ctx, None)
            .await
            .unwrap();
        assert_eq!(result["completed"], json!(0));
        assert_eq!(
            org.get("teamReviews", &review_id).await.unwrap()["status"],
            json!("open")
        );
        org.patch("tenants", &org.tenant_id, json!({ "status": "active" }))
            .await;
        let team_id = s.team.id.clone();
        org.iam
            .store
            .transaction(|tx| async move { tx.delete("teams", &team_id).await })
            .await
            .unwrap();
        let result = close_overdue_team_reviews(&org.iam.ctx, None)
            .await
            .unwrap();
        assert_eq!(result["completed"], json!(0));
        assert_eq!(result["failed"], json!([]));
        assert_eq!(
            org.get("teamReviews", &review_id).await.unwrap()["status"],
            json!("open")
        );
        assert_eq!(members(&s).await.len(), 5);
    });
}
