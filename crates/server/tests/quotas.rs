//! API usage plans and quotas: ported from tests/quotas.test.ts. Tenants, members, groups and service accounts come
//! from the organization fixture and the store (written as `identities.create`, `groups.create`,
//! `groups.addMember` and `serviceAccounts.create` write them).

mod organization_fixture;

use better_iam_core::{CredentialInput, Filter};
use better_iam_server::quotas::quota_window;
use organization_fixture::{
    Org, assert_matches, body, code, fails, ok, organization, run, with_credential,
};
use serde_json::{Value, json};

const SECOND: f64 = 1000.0;
const HOUR: f64 = 3_600_000.0;
const DAY: f64 = 24.0 * HOUR;

async fn audit_actions(f: &Org) -> Vec<String> {
    f.find("audit", Filter::new())
        .await
        .into_iter()
        .filter_map(|event| {
            let action = event.get("action")?.as_str()?.to_owned();
            let outcome = event.get("outcome")?.as_str()?.to_owned();
            action
                .starts_with("quota:")
                .then(|| format!("{action}:{outcome}"))
        })
        .collect()
}

fn token(credential: &CredentialInput) -> &str {
    credential.token.as_deref().unwrap()
}

/// `groups.create`.
async fn group(f: &Org, name: &str) -> String {
    let id = better_iam_server::utils::id();
    f.insert(
        "groups",
        json!({ "id": id, "tenantId": f.tenant_id, "name": name }),
    )
    .await;
    id
}

/// `groups.addMember`.
async fn add_member(f: &Org, group_id: &str, identity_id: &str) {
    f.insert(
        "groupMembers",
        json!({
            "id": better_iam_server::utils::id(),
            "tenantId": f.tenant_id,
            "groupId": group_id,
            "identityId": identity_id,
        }),
    )
    .await;
}

#[test]
fn counts_use_against_period_limits_and_refuses_past_them() {
    run(|| async {
        let f = organization(|_| {}).await;
        let quotas = &f.iam.api.quotas;
        ok(quotas
            .create_plan(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "free",
                    "meter": "requests",
                    "limits": [{ "period": "day", "limit": 3 }, { "period": "month", "limit": 100 }],
                    "alertThresholds": [50, 100],
                })),
            )
            .await);
        let alice = f.member("alice").await;
        ok(quotas
            .assign(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id, "plan": "free", "subjectType": "identity", "subjectId": alice,
                })),
            )
            .await);
        let credential = f.sign_in(&alice).await;
        let request = with_credential(
            &credential,
            json!({ "tenantId": f.tenant_id, "meter": "requests" }),
        );
        for call in 1..=3 {
            let decision = f.iam.quotas.consume(&request).await.unwrap().to_json();
            assert_matches(
                &decision,
                json!({ "allowed": true, "plan": "free", "via": "identity" }),
            );
            assert_matches(
                &decision["limits"][0],
                json!({ "period": "day", "used": call, "remaining": 3 - call }),
            );
        }
        let refused = f.iam.quotas.consume(&request).await.unwrap();
        assert_matches(
            &refused.to_json(),
            json!({ "allowed": false, "reason": "day" }),
        );
        let midnight = quota_window("day", f.now(), "UTC").unwrap().end;
        assert_eq!(refused.retry_after_ms, Some(midnight - f.now()));
        // A refusal counts nothing.
        assert_matches(
            &refused.to_json()["limits"][1],
            json!({ "period": "month", "used": 3 }),
        );
        let error = f.iam.quotas.enforce(&request).await.unwrap_err();
        assert_eq!((code(&error), error.status), ("QUOTA_EXCEEDED", 429));
        assert_eq!(
            better_iam_server::port::details_of(&error).and_then(|details| details.retry_after_ms),
            Some(midnight - f.now())
        );
        assert_eq!(
            error.message,
            "The day requests quota of plan free is used up"
        );
        let status = ok(quotas
            .status(
                &credential,
                body(json!({ "tenantId": f.tenant_id, "meter": "requests" })),
            )
            .await);
        assert_matches(&status["limits"][0], json!({ "used": 3, "remaining": 0 }));
        // Crossing 50% and 100% of the day's limit, and the first refusal, are each recorded once.
        let actions = audit_actions(&f).await;
        assert!(actions.contains(&"quota:threshold:allow".to_owned()));
        assert!(actions.contains(&"quota:exceeded:deny".to_owned()));
        assert_eq!(
            actions
                .iter()
                .filter(|entry| *entry == "quota:exceeded:deny")
                .count(),
            1
        );

        f.advance(midnight - f.now() + SECOND);
        let fresh = f.sign_in(&alice).await;
        let request = with_credential(
            &fresh,
            json!({ "tenantId": f.tenant_id, "meter": "requests" }),
        );
        assert!(f.iam.quotas.consume(&request).await.unwrap().allowed);
        // Meters without a plan are unlimited.
        let unlimited = f
            .iam
            .quotas
            .consume(&with_credential(
                &fresh,
                json!({ "tenantId": f.tenant_id, "meter": "exports" }),
            ))
            .await
            .unwrap();
        assert_matches(
            &unlimited.to_json(),
            json!({ "allowed": true, "plan": null }),
        );
    });
}

#[test]
fn throttles_bursts_with_a_shared_token_bucket() {
    run(|| async {
        let f = organization(|_| {}).await;
        ok(f.iam
            .api
            .quotas
            .create_plan(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "steady",
                    "meter": "requests",
                    "throttle": { "ratePerSecond": 1, "burst": 2 },
                    "default": true,
                })),
            )
            .await);
        let request = with_credential(
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "meter": "requests" }),
        );
        assert!(f.iam.quotas.consume(&request).await.unwrap().allowed);
        assert!(f.iam.quotas.consume(&request).await.unwrap().allowed);
        let refused = f.iam.quotas.consume(&request).await.unwrap();
        assert_matches(
            &refused.to_json(),
            json!({ "allowed": false, "reason": "throttle", "via": "default" }),
        );
        assert_eq!(refused.retry_after_ms, Some(SECOND));
        f.advance(SECOND);
        assert!(f.iam.quotas.consume(&request).await.unwrap().allowed);
        // Another server instance on the same database sees the same bucket.
        assert!(!f.iam.quotas.consume(&request).await.unwrap().allowed);
        // A cost above the burst can never succeed: no retry time is given.
        let mut too_big = request.clone();
        too_big["cost"] = json!(5);
        let too_big = f.iam.quotas.consume(&too_big).await.unwrap();
        assert_matches(
            &too_big.to_json(),
            json!({ "allowed": false, "reason": "throttle" }),
        );
        assert_eq!(too_big.retry_after_ms, None);
        let error = f.iam.quotas.enforce(&request).await.unwrap_err();
        assert_eq!(error.message, "Too many requests requests; slow down");
    });
}

#[test]
fn applies_the_most_specific_plan() {
    run(|| async {
        let f = organization(|_| {}).await;
        let quotas = &f.iam.api.quotas;
        let plan = |name: &'static str, limit: u32, extra: Value| {
            let mut input = json!({
                "tenantId": f.tenant_id,
                "name": name,
                "meter": "requests",
                "limits": [{ "period": "day", "limit": limit }],
            });
            for (key, value) in extra.as_object().unwrap() {
                input[key] = value.clone();
            }
            quotas.create_plan(&f.owner_credential, body(input))
        };
        ok(plan("basic", 10, json!({ "default": true })).await);
        ok(plan("team", 100, json!({})).await);
        ok(plan("vip", 1000, json!({ "priority": 5 })).await);
        ok(plan("ci", 5000, json!({})).await);
        let error = fails(plan("other-default", 1, json!({ "default": true })).await);
        assert_eq!(
            (code(&error), error.message.as_str()),
            (
                "CONFLICT",
                "The tenant already has a default plan for requests"
            )
        );
        let engineers = group(&f, "Engineers").await;
        let vips = group(&f, "VIPs").await;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        for group_id in [&engineers, &vips] {
            add_member(&f, group_id, &alice).await;
        }
        for (plan, subject) in [("team", &engineers), ("vip", &vips)] {
            ok(quotas
                .assign(
                    &f.owner_credential,
                    body(json!({
                        "tenantId": f.tenant_id, "plan": plan, "subjectType": "group", "subjectId": subject,
                    })),
                )
                .await);
        }
        let alice_token = f.sign_in(&alice).await;
        let bob_token = f.sign_in(&bob).await;
        let f = &f;
        let plan_of = |credential: CredentialInput| async move {
            ok(f.iam
                .api
                .quotas
                .status(
                    &credential,
                    body(json!({ "tenantId": f.tenant_id, "meter": "requests" })),
                )
                .await)["plan"]
                .clone()
        };
        assert_eq!(plan_of(bob_token.clone()).await, json!("basic"));
        // Of two group plans, the higher priority applies.
        assert_eq!(plan_of(alice_token.clone()).await, json!("vip"));
        ok(quotas
            .assign(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id, "plan": "team", "subjectType": "identity", "subjectId": alice,
                })),
            )
            .await);
        assert_eq!(plan_of(alice_token.clone()).await, json!("team"));

        // `serviceAccounts.create`: a service identity of the tenant.
        let bot = f.member("ci-bot").await;
        let mut record = f
            .find("identities", Filter::new().eq("id", bot.clone()))
            .await
            .remove(0);
        record.insert("kind".into(), json!("service"));
        record.insert("name".into(), json!("ci-bot"));
        f.put("identities", record).await;
        let key = ok(f
            .iam
            .api
            .credentials
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "identityId": bot, "name": "deploy" })),
            )
            .await);
        let key_id = key["credentialId"].as_str().unwrap().to_owned();
        let key_token = key["token"].as_str().unwrap().to_owned();
        ok(quotas
            .assign(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id, "plan": "ci", "subjectType": "apiKey", "subjectId": key_id,
                })),
            )
            .await);
        assert_eq!(
            plan_of(organization_fixture::bearer(&key_token)).await,
            json!("ci")
        );
        let for_bot = f
            .iam
            .quotas
            .consume_for(&json!({
                "tenantId": f.tenant_id, "identityId": bot, "apiKeyId": key_id, "meter": "requests",
            }))
            .await
            .unwrap();
        assert_eq!(for_bot.plan.as_deref(), Some("ci"));
        // A key of another identity is refused.
        let error = f
            .iam
            .quotas
            .consume_for(&json!({
                "tenantId": f.tenant_id, "identityId": alice, "apiKeyId": key_id, "meter": "requests",
            }))
            .await
            .unwrap_err();
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("NOT_FOUND", "API key not found")
        );
        let assignments = ok(quotas
            .list_assignments(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        let mut labels: Vec<String> = assignments
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                format!(
                    "{}:{}:{}",
                    entry["plan"].as_str().unwrap(),
                    entry["subjectType"].as_str().unwrap(),
                    entry["subjectName"].as_str().unwrap_or("undefined")
                )
            })
            .collect();
        labels.sort();
        assert_eq!(
            labels,
            vec![
                "ci:apiKey:deploy",
                "team:group:Engineers",
                "team:identity:alice",
                "vip:group:VIPs",
            ]
        );
        ok(quotas
            .unassign(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id, "meter": "requests", "subjectType": "identity", "subjectId": alice,
                })),
            )
            .await);
        assert_eq!(plan_of(alice_token.clone()).await, json!("vip"));
        assert_eq!(
            ok(quotas
                .unassign(
                    &f.owner_credential,
                    body(json!({
                        "tenantId": f.tenant_id, "meter": "requests", "subjectType": "identity", "subjectId": alice,
                    })),
                )
                .await),
            json!({ "removed": false })
        );
    });
}

#[test]
fn shares_tenant_scoped_counters_reports_usage_resets_and_cleans_up() {
    run(|| async {
        let f = organization(|_| {}).await;
        let quotas = &f.iam.api.quotas;
        ok(quotas
            .create_plan(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "shared",
                    "meter": "exports",
                    "scope": "tenant",
                    "default": true,
                    "limits": [{ "period": "hour", "limit": 3 }],
                })),
            )
            .await);
        let alice_id = f.member("alice").await;
        let bob_id = f.member("bob").await;
        let alice = f.sign_in(&alice_id).await;
        let bob = f.sign_in(&bob_id).await;
        ok(quotas
            .consume(
                &alice,
                body(json!({ "tenantId": f.tenant_id, "meter": "exports", "cost": 2 })),
            )
            .await);
        assert_matches(
            &ok(quotas
                .consume(
                    &bob,
                    body(json!({ "tenantId": f.tenant_id, "meter": "exports", "cost": 2 })),
                )
                .await),
            json!({ "allowed": false, "reason": "hour" }),
        );
        assert_eq!(
            ok(quotas
                .consume(
                    &bob,
                    body(json!({ "tenantId": f.tenant_id, "meter": "exports" })),
                )
                .await)["allowed"],
            json!(true)
        );
        let usage = ok(quotas
            .usage(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "plan": "shared" })),
            )
            .await);
        let usage = usage.as_array().unwrap();
        assert_eq!(usage.len(), 1);
        assert_matches(&usage[0], json!({ "subject": "tenant" }));
        let limits = usage[0]["limits"].as_array().unwrap();
        assert_eq!(limits.len(), 1);
        assert_matches(
            &limits[0],
            json!({ "period": "hour", "used": 3, "remaining": 0 }),
        );
        assert!(usage[0].get("exceededAt").is_some());
        assert_eq!(
            ok(quotas
                .reset(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "plan": "shared" })),
                )
                .await),
            json!({ "reset": 1 })
        );
        assert_eq!(
            ok(quotas
                .consume(
                    &bob,
                    body(json!({ "tenantId": f.tenant_id, "meter": "exports", "cost": 3 })),
                )
                .await)["allowed"],
            json!(true)
        );
        let plans = ok(quotas
            .list_plans(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        assert_matches(
            &plans[0],
            json!({ "name": "shared", "scope": "tenant", "default": true, "assignments": 0, "timeZone": "UTC" }),
        );
        assert_matches(
            &ok(quotas
                .delete_plan(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "name": "shared" })),
                )
                .await),
            json!({ "deleted": true }),
        );
        assert!(
            f.find(
                "quotaCounters",
                Filter::new().eq("tenantId", f.tenant_id.clone())
            )
            .await
            .is_empty()
        );
        let actions = audit_actions(&f).await;
        for expected in [
            "quota:plan-create:allow",
            "quota:reset:allow",
            "quota:plan-delete:allow",
        ] {
            assert!(actions.contains(&expected.to_owned()), "{expected}");
        }
    });
}

#[test]
fn updates_plans_and_keeps_what_is_left_out() {
    run(|| async {
        let f = organization(|_| {}).await;
        let quotas = &f.iam.api.quotas;
        ok(quotas
            .create_plan(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "pro",
                    "meter": "requests",
                    "description": "  Paying customers  ",
                    "throttle": { "ratePerSecond": 0.5 },
                    "limits": [{ "period": "month", "limit": 10 }, { "period": "minute", "limit": 2 }],
                    "alertThresholds": [90, 50, 90],
                    "timeZone": "Europe/Berlin",
                })),
            )
            .await);
        let plan = ok(quotas
            .get_plan(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "name": "pro" })),
            )
            .await);
        assert_matches(
            &plan,
            json!({
                "description": "Paying customers",
                "throttle": { "ratePerSecond": 0.5, "burst": 1 },
                "limits": [{ "period": "minute", "limit": 2 }, { "period": "month", "limit": 10 }],
                "alertThresholds": [50, 90],
                "timeZone": "Europe/Berlin",
                "scope": "subject",
                "priority": 0,
            }),
        );
        let updated = ok(quotas
            .update_plan(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "name": "pro", "throttle": null, "priority": 3 })),
            )
            .await);
        assert!(updated.get("throttle").is_none());
        assert_matches(
            &updated,
            json!({ "description": "Paying customers", "priority": 3 }),
        );
        let error = fails(
            quotas
                .update_plan(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "name": "pro", "limits": [] })),
                )
                .await,
        );
        assert_eq!(error.message, "A plan needs a throttle, limits, or both");
        let error = fails(
            quotas
                .update_plan(
                    &f.owner_credential,
                    body(
                        json!({ "tenantId": f.tenant_id, "name": "pro", "timeZone": "Mars/Base" }),
                    ),
                )
                .await,
        );
        assert_eq!(error.message, "Unknown timeZone");
        let updated = ok(quotas
            .update_plan(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "name": "pro", "description": null })),
            )
            .await);
        assert!(updated.get("description").is_none());
        let trail = f
            .find("audit", Filter::new().eq("action", "quota:plan-update"))
            .await;
        assert_eq!(trail.len(), 2);
        assert_matches(
            &Value::Object(trail[0].clone()),
            json!({ "metadata": { "name": "pro", "throttle": null, "scope": "subject" } }),
        );
        let created = f
            .find("audit", Filter::new().eq("action", "quota:plan-create"))
            .await;
        assert_matches(
            &Value::Object(created[0].clone()),
            json!({ "metadata": { "limits": ["2/minute", "10/month"], "throttle": "0.5/s burst 1" } }),
        );
    });
}

#[test]
fn validates_plans_refuses_other_tenants_and_serves_http() {
    run(|| async {
        let f = organization(|_| {}).await;
        let quotas = &f.iam.api.quotas;
        let error = fails(
            quotas
                .create_plan(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "name": "empty", "meter": "requests" })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        for limits in [
            json!([{ "period": "year", "limit": 1 }]),
            json!([{ "period": "day", "limit": 0 }]),
            json!([{ "period": "day", "limit": 1 }, { "period": "day", "limit": 2 }]),
        ] {
            let error = fails(
                quotas
                    .create_plan(
                        &f.owner_credential,
                        body(json!({
                            "tenantId": f.tenant_id, "name": "bad", "meter": "requests", "limits": limits,
                        })),
                    )
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT");
        }
        let error = fails(
            quotas
                .create_plan(
                    &f.owner_credential,
                    body(json!({
                        "tenantId": f.tenant_id, "name": "bad", "meter": "Requests!",
                        "limits": [{ "period": "day", "limit": 1 }],
                    })),
                )
                .await,
        );
        assert_eq!(
            (code(&error), error.message.as_str()),
            (
                "INVALID_INPUT",
                "meter must be 1-64 lowercase letters, digits and ._- starting with a letter or digit"
            )
        );
        ok(quotas
            .create_plan(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id, "name": "free", "meter": "requests", "default": true,
                    "limits": [{ "period": "minute", "limit": 1 }],
                })),
            )
            .await);
        // A session of another tenant cannot count here.
        let error = f
            .iam
            .quotas
            .consume(&with_credential(
                &f.root_credential,
                json!({ "tenantId": f.tenant_id, "meter": "requests" }),
            ))
            .await
            .unwrap_err();
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_eq!(
            error.message,
            "Quotas count in the session\u{2019}s own tenant"
        );
        let owner = token(&f.owner_credential).to_owned();
        let (status, first) = f
            .post(
                "quotas/consume",
                &owner,
                json!({ "tenantId": f.tenant_id, "meter": "requests" }),
            )
            .await;
        assert_eq!(status, 200, "{first}");
        assert_eq!(first["data"]["allowed"], json!(true));
        let (_, second) = f
            .post(
                "quotas/consume",
                &owner,
                json!({ "tenantId": f.tenant_id, "meter": "requests" }),
            )
            .await;
        assert_matches(
            &second["data"],
            json!({ "allowed": false, "reason": "minute" }),
        );
        // The conformance server's `call` throws QUOTA_EXCEEDED with the retry time.
        let error = f
            .iam
            .quotas
            .call(
                "enforce",
                vec![with_credential(
                    &f.owner_credential,
                    json!({ "tenantId": f.tenant_id, "meter": "requests" }),
                )],
            )
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(code(&error), "QUOTA_EXCEEDED");
        assert!(
            better_iam_server::port::details_of(&error)
                .and_then(|details| details.retry_after_ms)
                .is_some()
        );
    });
}

#[test]
fn starts_day_week_and_month_windows_at_local_midnight() {
    let iso = |at: f64| better_iam_core::js::iso_string(at).unwrap();
    // 2026-03-08 is the day New York moves to daylight saving time.
    let at = 1_772_982_000_000.0; // 2026-03-08T15:00:00Z
    assert_eq!(iso(at), "2026-03-08T15:00:00.000Z");
    let day = quota_window("day", at, "America/New_York").unwrap();
    assert_eq!(iso(day.start), "2026-03-08T05:00:00.000Z");
    assert_eq!(iso(day.end), "2026-03-09T04:00:00.000Z");
    let week = quota_window("week", at, "America/New_York").unwrap();
    assert_eq!(iso(week.start), "2026-03-02T05:00:00.000Z");
    let month = quota_window("month", at, "Europe/Berlin").unwrap();
    assert_eq!(iso(month.start), "2026-02-28T23:00:00.000Z");
    assert_eq!(iso(month.end), "2026-03-31T22:00:00.000Z");
    let hour = quota_window("hour", at, "UTC").unwrap();
    assert_eq!(hour.end - hour.start, HOUR);
    let utc = quota_window("day", at, "UTC").unwrap();
    assert_eq!(utc.end - utc.start, DAY);
    let minute = quota_window("minute", at + 1234.0, "UTC").unwrap();
    assert_eq!((minute.start, minute.end), (at, at + 60_000.0));
}
