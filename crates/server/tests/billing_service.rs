//! The billing service (billing-service.ts): recording, spend reports, budgets and alerts, statements, credits,
//! payments, seats, priced usage from other modules, anomalies and CSV. Ported from tests/billing.test.ts,
//! tests/billing-invoicing.test.ts and tests/security-billing.test.ts, driving the service itself: meters, prices,
//! profiles, credits and terms are written the way `billing.createMeter`, `setPrice`, `setProfile`, `grantCredit` and
//! `setTerms` write them, so these cases do not depend on the `billing` API group.
//!
//! Every pricing and period helper the service calls lives in billing.ts (and billing-plans.ts, billing-invoices.ts),
//! which belong to other units and are still stubs; the cases that need them are ported and ignored until those land.
//! The cases that do not need them run now.

mod organization_fixture;

use std::future::Future;
use std::sync::{Arc, Mutex};

use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::{Filter, IamResult, IamStoreExt, PolicyDocument, Record};
use better_iam_server::billing::{UsageReceipt, period_bounds, period_of, shift_period};
use better_iam_server::billing_service::{
    BillingService, RecordExtras, billing_service_of, built_in_meter_key, mentions_spend,
};
use better_iam_server::context::Store;
use better_iam_server::options::BillingOptions;
use better_iam_server::utils::id;
use organization_fixture::{Org, assert_matches, matches, organization, run};
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;

struct Billing {
    f: Org,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
    service: Arc<BillingService>,
    alice: String,
    bob: String,
    carol: String,
}

impl std::ops::Deref for Billing {
    type Target = Org;
    fn deref(&self) -> &Org {
        &self.f
    }
}

/// The period an instant falls in (UTC).
fn period(at: f64) -> String {
    period_of(at, "UTC").expect("period")
}

fn start_of(period: &str) -> f64 {
    period_bounds(period, "UTC").expect("bounds")["start"]
        .as_f64()
        .unwrap()
}

fn previous_period(f: &Org) -> String {
    shift_period(&period(f.now()), -1.0).expect("period")
}

/// Acme with a platform `api-calls` meter: 1000 free calls a month, then $0.01 each up to 10 000, then $0.005.
async fn setup(
    configure: impl FnOnce(&mut better_iam_server::options::BetterIamOptions),
) -> Billing {
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let sink = inbox.clone();
    let f = organization(move |options| {
        let authentication = options.authentication.as_mut().unwrap();
        authentication.send_email = Some(delivery_fn(move |message| {
            sink.lock().unwrap().push(message);
            async { Ok(()) }
        }));
        configure(options);
    })
    .await;
    let service = billing_service_of(&f.iam.ctx).expect("billing service");
    let root = f.root_tenant.clone();
    let meter_id = meter(&f, &root, "api-calls", "API calls", "request", "sum").await;
    // From last month on, so usage backdated into it is priced too (nothing is invoiced yet).
    price(
        &f,
        &root,
        &meter_id,
        "api-calls",
        &previous_period(&f),
        json!({
            "model": "graduated",
            "includedQuantity": 1000,
            "tiers": [
                { "upTo": 10_000, "unitAmountMicros": 10_000 },
                { "upTo": null, "unitAmountMicros": 5_000 },
            ],
        }),
    )
    .await;
    let alice = f.member("alice").await;
    let bob = f.member("bob").await;
    let carol = f.member("carol").await;
    Billing {
        f,
        inbox,
        service,
        alice,
        bob,
        carol,
    }
}

/// A meter as `billing.createMeter` writes it.
async fn meter(
    f: &Org,
    tenant_id: &str,
    key: &str,
    name: &str,
    unit: &str,
    aggregation: &str,
) -> String {
    let meter_id = id();
    let now = f.now();
    f.insert(
        "billingMeters",
        json!({
            "id": meter_id,
            "tenantId": tenant_id,
            "uniqueKey": key,
            "key": key,
            "name": name,
            "unit": unit,
            "aggregation": aggregation,
            "pricing": "rate-card",
            "archived": false,
            "createdAt": now,
            "createdBy": f.root_id,
            "updatedAt": now,
            "updatedBy": f.root_id,
        }),
    )
    .await;
    meter_id
}

/// A rate card entry as `billing.setPrice` writes it (amounts in micros).
async fn price(f: &Org, tenant_id: &str, meter_id: &str, key: &str, from: &str, spec: Value) {
    f.insert(
        "billingPrices",
        json!({
            "id": id(),
            "tenantId": tenant_id,
            "uniqueKey": format!("{meter_id}:{from}"),
            "meterId": meter_id,
            "meter": key,
            "definerId": f.root_tenant,
            "effectiveFrom": from,
            "spec": spec,
            "setAt": f.now(),
            "setBy": f.root_id,
        }),
    )
    .await;
}

/// A credit as `billing.grantCredit` writes it.
async fn credit(f: &Org, tenant_id: &str, amount_micros: f64, reason: &str) -> String {
    let credit_id = id();
    f.insert(
        "billingCredits",
        json!({
            "id": credit_id,
            "tenantId": tenant_id,
            "amountMicros": amount_micros,
            "remainingMicros": amount_micros,
            "reason": reason,
            "grantedAt": f.now(),
            "grantedBy": f.root_id,
        }),
    )
    .await;
    credit_id
}

fn merge(mut base: Value, extra: Value) -> Value {
    if let (Value::Object(base), Value::Object(extra)) = (&mut base, extra) {
        base.extend(extra);
    }
    base
}

impl Billing {
    /// Runs service calls in one transaction.
    async fn tx<T, F, Fut>(&self, run: F) -> IamResult<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<BillingService>, Store) -> Fut + Send,
        Fut: Future<Output = IamResult<T>> + Send,
    {
        let service = self.service.clone();
        self.iam.store.transaction(move |tx| run(service, tx)).await
    }

    /// `billing.record` by the owner: `api-calls` in Acme for a person.
    async fn record(
        &self,
        identity_id: &str,
        quantity: f64,
        extra: Value,
    ) -> IamResult<UsageReceipt> {
        let input = merge(
            json!({
                "tenantId": self.tenant_id,
                "meter": "api-calls",
                "quantity": quantity,
                "identityId": identity_id,
            }),
            extra.clone(),
        );
        self.record_as(
            &self.owner_id.clone(),
            input,
            extra["enforceBudgets"] == json!(true),
        )
        .await
    }

    async fn record_as(&self, actor: &str, input: Value, enforce: bool) -> IamResult<UsageReceipt> {
        let actor = actor.to_owned();
        self.tx(move |service, tx| async move {
            service
                .record(
                    &tx,
                    &input,
                    &actor,
                    RecordExtras {
                        enforce_budgets: enforce,
                        ..RecordExtras::default()
                    },
                )
                .await
        })
        .await
    }

    /// `iam.billing.record`: trusted server code, no credential.
    async fn record_trusted(&self, input: Value) -> IamResult<UsageReceipt> {
        self.record_as("deployment", input, false).await
    }

    /// A spend report as JSON (`billing.spend`).
    async fn spend(&self, tenant_id: &str, query: Value) -> IamResult<Value> {
        let ctx = self.iam.ctx.clone();
        let tenant_id = tenant_id.to_owned();
        self.tx(move |service, tx| async move {
            let scope = ctx.tenant(&tx, &tenant_id).await?;
            let report = service.report(&tx, &scope, &query, None, None).await?;
            Ok(serde_json::to_value(report).unwrap())
        })
        .await
    }

    async fn statement(&self, statement_id: &str) -> Record {
        self.iam
            .store
            .get("billingStatements", statement_id)
            .await
            .unwrap()
            .expect("statement")
    }

    async fn sent(&self, template: &str) -> Vec<DeliveryMessage> {
        self.iam.auth.dispatch_outbox(None).await.unwrap();
        self.inbox
            .lock()
            .unwrap()
            .iter()
            .filter(|message| message.template == template)
            .cloned()
            .collect()
    }
}

fn rows(report: &Value) -> Vec<Value> {
    report["rows"].as_array().cloned().unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------------------------
// Cases that run now

#[test]
fn keeps_one_billing_service_per_server() {
    run(|| async {
        let f = organization(|_| {}).await;
        let first = billing_service_of(&f.iam.ctx).unwrap();
        let again = billing_service_of(&f.iam.ctx).unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        let other = organization(|_| {}).await;
        assert!(!Arc::ptr_eq(
            &first,
            &billing_service_of(&other.iam.ctx).unwrap()
        ));
    });
}

#[test]
fn never_fails_the_work_it_bills() {
    run(|| async {
        let f = organization(|_| {}).await;
        let hooks = f.iam.ctx.billing().expect("billing hooks").clone();
        let store = f.store();
        // Unknown tenants, missing members and garbage are skipped without an error.
        for input in [
            json!({ "tenantId": "missing", "meter": "inference", "costMicros": 10 }),
            json!({ "meter": "inference", "costMicros": 10 }),
            json!(null),
            json!({ "tenantId": 7 }),
        ] {
            let hooks = hooks.clone();
            store
                .transaction(move |tx| async move {
                    hooks.record_priced(&tx, &input).await;
                    Ok(())
                })
                .await
                .unwrap();
        }
        assert!(f.find("billingUsage", Filter::new()).await.is_empty());
        assert!(f.find("billingMeters", Filter::new()).await.is_empty());
    });
}

#[test]
fn reads_budgets_only_for_policies_that_name_spend_keys() {
    let document = |condition: Value| -> PolicyDocument {
        serde_json::from_value(json!({
            "version": 1,
            "statements": [{
                "effect": "deny",
                "actions": ["documents:write"],
                "resources": ["*"],
                "conditions": condition,
            }],
        }))
        .unwrap()
    };
    let spend = document(json!({ "Bool": { "principal.spendExceeded": true } }));
    let names = document(json!({ "StringEquals": { "principal.budgetsExceeded": "Bob" } }));
    let other = document(json!({ "Bool": { "principal.mfa": true } }));
    assert!(mentions_spend(&[&spend]));
    assert!(mentions_spend(&[&other, &names]));
    assert!(!mentions_spend(&[&other]));
    assert!(!mentions_spend(&[]));
}

#[test]
fn reserves_built_in_meter_keys_for_the_platform() {
    assert!(built_in_meter_key("inference").unwrap());
    assert!(!built_in_meter_key("api-calls").unwrap());
    assert!(!built_in_meter_key("constructor").unwrap());
}

// ---------------------------------------------------------------------------------------------------------------
// Cases that need billing.ts

#[test]
#[ignore = "needs billing.ts (billing unit)"]
fn prices_the_account_total_once_and_shares_it_out() {
    run(|| async {
        let b = setup(|_| {}).await;
        let (apollo, apollo_owner, _) = b
            .activate(
                &b.tenant_id.clone(),
                "Apollo",
                "project",
                "apollo@acme.test",
            )
            .await;
        b.record(&b.alice, 3000.0, json!({})).await.unwrap();
        b.record(&b.bob, 500.0, json!({})).await.unwrap();
        b.record_as(
            &apollo_owner,
            json!({ "tenantId": apollo, "meter": "api-calls", "quantity": 500 }),
            false,
        )
        .await
        .unwrap();
        // 4000 calls, 1000 free: 3000 x $0.01 = $30, shared by quantity (75% / 12.5% / 12.5%).
        let by_person = b
            .spend(&b.tenant_id, json!({ "groupBy": "identity" }))
            .await
            .unwrap();
        assert_matches(
            &by_person["total"],
            json!({ "costMicros": 30_000_000, "amount": 30, "events": 3 }),
        );
        assert_eq!(by_person["currency"], "USD");
        let people = rows(&by_person);
        assert_eq!(people.len(), 3);
        assert_matches(
            &people[0],
            json!({
                "key": b.alice,
                "costMicros": 22_500_000,
                "share": 75,
                "label": "alice <alice@acme.test>",
            }),
        );
        assert_matches(
            &people[1],
            json!({ "key": "(unattributed)", "costMicros": 3_750_000 }),
        );
        assert_matches(
            &people[2],
            json!({ "key": b.bob, "costMicros": 3_750_000, "quantities": { "api-calls": 500 } }),
        );
        let by_project = b
            .spend(&b.tenant_id, json!({ "groupBy": "tenant" }))
            .await
            .unwrap();
        let projects: Vec<Value> = rows(&by_project)
            .iter()
            .map(|row| json!([row["label"], row["amount"]]))
            .collect();
        assert!(matches(
            &Value::Array(projects),
            &json!([["Acme", 26.25], ["Apollo", 3.75]])
        ));
        // The project's own view covers only its subtree, priced within Acme's account.
        let project_view = b.spend(&apollo, json!({})).await.unwrap();
        assert_matches(
            &project_view["rows"],
            json!([{ "key": "api-calls", "label": "API calls", "costMicros": 3_750_000 }]),
        );
    });
}

#[test]
#[ignore = "needs billing.ts (billing unit)"]
fn validates_usage_and_stays_idempotent() {
    run(|| async {
        let b = setup(|_| {}).await;
        let first = b
            .record(
                &b.alice,
                10.0,
                json!({ "idempotencyKey": "request-1", "tags": { "env": "prod" } }),
            )
            .await
            .unwrap();
        let again = b
            .record(&b.alice, 10.0, json!({ "idempotencyKey": "request-1" }))
            .await
            .unwrap();
        assert_eq!(again.id, first.id);
        assert!(again.duplicate);
        let code = |result: IamResult<UsageReceipt>| result.unwrap_err().code;
        assert_eq!(
            code(b.record(&b.alice, 1.0, json!({ "cost": 1 })).await),
            "INVALID_INPUT"
        );
        assert_eq!(
            code(
                b.record_trusted(json!({ "tenantId": b.tenant_id, "meter": "nope" }))
                    .await
            ),
            "NOT_FOUND"
        );
        assert_eq!(
            code(b.record(&b.alice, -1.0, json!({})).await),
            "INVALID_INPUT"
        );
        assert_eq!(
            code(
                b.record(
                    &b.alice,
                    1.0,
                    json!({ "occurredAt": b.now() + 3_600_000.0 })
                )
                .await
            ),
            "INVALID_INPUT"
        );
        // The server records without a credential.
        b.record_trusted(json!({
            "tenantId": b.tenant_id,
            "meter": "api-calls",
            "quantity": 5,
            "identityId": b.alice,
            "tags": { "env": "staging" },
        }))
        .await
        .unwrap();
        let by_env = b
            .spend(&b.tenant_id, json!({ "groupBy": "tag:env" }))
            .await
            .unwrap();
        let envs: Vec<Value> = rows(&by_env)
            .iter()
            .map(|row| json!([row["key"], row["quantities"]["api-calls"]]))
            .collect();
        assert!(matches(
            &Value::Array(envs),
            &json!([["prod", 10], ["staging", 5]])
        ));
        let events = b.find("billingUsage", Filter::new()).await;
        assert_eq!(events.len(), 2);
        let tagged = events
            .iter()
            .find(|event| event["quantity"].as_f64() == Some(10.0))
            .unwrap();
        assert_matches(
            &Value::Object(tagged.clone()),
            json!({ "uniqueKey": "idem:request-1", "recordedBy": b.owner_id, "tags": { "env": "prod" } }),
        );
        let invalid = b
            .spend(&b.tenant_id, json!({ "groupBy": 7 }))
            .await
            .unwrap_err();
        assert_eq!(invalid.code, "INVALID_INPUT");
        let invalid = b
            .spend(
                &b.tenant_id,
                json!({ "groupBy": "identity", "shareUnattributed": "yes" }),
            )
            .await
            .unwrap_err();
        assert_eq!(invalid.code, "INVALID_INPUT");
        // Archived meters keep their history but refuse new usage.
        let mut archived = b
            .find("billingMeters", Filter::new().eq("key", "api-calls"))
            .await
            .remove(0);
        archived.insert("archived".into(), json!(true));
        b.put("billingMeters", archived).await;
        assert_eq!(
            code(b.record(&b.alice, 1.0, json!({})).await),
            "METER_ARCHIVED"
        );
        // Nothing covers usage without budgets.
        let ctx = b.iam.ctx.clone();
        let tenant_id = b.tenant_id.clone();
        let verdict = b
            .tx(move |service, tx| async move {
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                service.check(&tx, &tenant, &json!({})).await
            })
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(verdict).unwrap(),
            json!({ "allowed": true, "budgets": [] })
        );
    });
}

#[test]
#[ignore = "needs billing.ts (billing unit)"]
fn alerts_on_budget_thresholds_once_and_enforces_spent_budgets() {
    run(|| async {
        let b = setup(|_| {}).await;
        let now = b.now();
        let budget_id = id();
        b.insert(
            "billingBudgets",
            json!({
                "id": budget_id,
                "tenantId": b.tenant_id,
                "uniqueKey": "bob monthly",
                "name": "Bob monthly",
                "subjectType": "identity",
                "subjectId": b.bob,
                "amountMicros": 20_000_000,
                "period": "month",
                "thresholds": [50, 100],
                "forecastAlerts": false,
                "notify": { "owners": true, "subject": true, "emails": ["finance@acme.test"] },
                "enforce": true,
                "createdAt": now,
                "createdBy": b.owner_id,
                "updatedAt": now,
                "updatedBy": b.owner_id,
            }),
        )
        .await;
        b.record(&b.bob, 2500.0, json!({})).await.unwrap(); // 1500 billable: $15 (75%).
        let first = b.service.check_budgets(None).await.unwrap();
        assert_matches(
            &first["alerts"],
            json!([{ "budgetId": budget_id, "kind": "actual", "threshold": 50, "recipients": 3 }]),
        );
        assert_eq!(
            b.service.check_budgets(None).await.unwrap()["alerts"],
            json!([])
        );
        b.record(&b.bob, 1000.0, json!({})).await.unwrap(); // $25 in total.
        let second = b.service.check_budgets(None).await.unwrap();
        assert_matches(&second["alerts"], json!([{ "threshold": 100 }]));
        let alerts = b.sent("spend-alert").await;
        let mut recipients: Vec<String> = alerts.iter().map(|message| message.to.clone()).collect();
        recipients.sort();
        assert_eq!(
            recipients,
            [
                "bob@acme.test",
                "bob@acme.test",
                "finance@acme.test",
                "finance@acme.test",
                "owner@acme.test",
                "owner@acme.test",
            ]
        );
        let full = alerts
            .iter()
            .find(|message| message.payload["threshold"] == "100")
            .unwrap();
        assert_matches(
            &Value::Object(full.payload.clone()),
            json!({
                "spent": "$25.00",
                "amount": "$20.00",
                "budgetName": "Bob monthly",
                "subjectName": "bob",
            }),
        );
        assert_eq!(
            b.find("audit", Filter::new().eq("action", "billing:budget-alert"))
                .await
                .len(),
            2
        );
        // The spent budget now refuses the person's usage when asked to enforce.
        let error = b
            .record(&b.bob, 1.0, json!({ "enforceBudgets": true }))
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.status),
            ("SPEND_LIMIT_REACHED", 402)
        );
        // People the budget does not cover are not refused.
        b.record(&b.carol, 1.0, json!({ "enforceBudgets": true }))
            .await
            .unwrap();
        // Policies see the spent budget (statuses are cached for up to 30 seconds).
        b.advance(31_000.0);
        let ctx = b.iam.ctx.clone();
        let (tenant_id, bob, carol) = (b.tenant_id.clone(), b.bob.clone(), b.carol.clone());
        let (for_bob, for_carol) = b
            .tx(move |service, tx| async move {
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                Ok((
                    service.spend_context(&tx, &tenant, Some(&bob)).await?,
                    service.spend_context(&tx, &tenant, Some(&carol)).await?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            Value::Object(for_bob),
            json!({ "principal.spendExceeded": true, "principal.budgetsExceeded": ["Bob monthly"] })
        );
        assert_eq!(
            Value::Object(for_carol),
            json!({ "principal.spendExceeded": false, "principal.budgetsExceeded": [] })
        );
    });
}

#[test]
#[ignore = "needs billing.ts (billing unit)"]
fn closes_a_period_into_statements_and_refuses_late_usage_until_voided() {
    run(|| async {
        let b = setup(|_| {}).await;
        let last_month = previous_period(&b);
        let backdated = start_of(&last_month) + 3_600_000.0;
        b.record(&b.alice, 6000.0, json!({ "occurredAt": backdated }))
            .await
            .unwrap();
        let now = b.now();
        b.insert(
            "billingProfiles",
            json!({
                "id": id(),
                "tenantId": b.tenant_id,
                "uniqueKey": "profile",
                "companyName": "Acme Corporation",
                "billingEmails": ["ap@acme.test"],
                "purchaseOrder": "PO-7",
                "paymentTermsDays": 15,
                "createdAt": now,
                "createdBy": b.owner_id,
                "updatedAt": now,
                "updatedBy": b.owner_id,
            }),
        )
        .await;
        let credit_id = credit(&b, &b.tenant_id.clone(), 20_000_000.0, "Launch promotion").await;
        let ctx = b.iam.ctx.clone();
        let (tenant_id, draft_period) = (b.tenant_id.clone(), last_month.clone());
        let draft = b
            .tx(move |service, tx| async move {
                let account = ctx.tenant(&tx, &tenant_id).await?;
                service
                    .draft_statement(&tx, &account, &draft_period, None, None)
                    .await
            })
            .await
            .unwrap();
        assert_matches(
            &Value::Object(draft),
            json!({ "subtotalMicros": 50_000_000, "creditsMicros": 20_000_000, "totalMicros": 30_000_000 }),
        );
        let closed = serde_json::to_value(b.service.close_period(None).await.unwrap()).unwrap();
        assert_matches(
            &closed,
            json!({ "period": last_month, "skipped": { "existing": 0, "empty": 0 } }),
        );
        let number = format!("INV-{}-0001", last_month.replacen('-', "", 1));
        assert_matches(
            &closed["issued"],
            json!([{
                "accountId": b.tenant_id,
                "totalMicros": 30_000_000,
                "recipients": 1,
                "number": number,
            }]),
        );
        // Idempotent: a second run skips the invoiced account.
        let again = serde_json::to_value(b.service.close_period(None).await.unwrap()).unwrap();
        assert_eq!(again["skipped"]["existing"].as_f64(), Some(1.0));
        let mailed = b.sent("billing-statement").await;
        assert_eq!(mailed.len(), 1);
        assert_eq!(mailed[0].to, "ap@acme.test");
        assert_matches(
            &Value::Object(mailed[0].payload.clone()),
            json!({ "total": "$30.00", "period": last_month }),
        );
        let statement_id = closed["issued"][0]["statementId"]
            .as_str()
            .unwrap()
            .to_owned();
        let statement = b.statement(&statement_id).await;
        assert_matches(
            &Value::Object(statement.clone()),
            json!({
                "status": "finalized",
                "lines": [{ "meter": "api-calls", "quantity": 6000, "amountMicros": 50_000_000 }],
                "billTo": {
                    "companyName": "Acme Corporation",
                    "purchaseOrder": "PO-7",
                    "emails": ["ap@acme.test"],
                },
                "breakdown": { "identities": [{ "id": b.alice, "costMicros": 50_000_000 }] },
            }),
        );
        assert_eq!(
            statement["dueAt"].as_f64().unwrap() - statement["issuedAt"].as_f64().unwrap(),
            15.0 * DAY
        );
        let sheet = b.service.statement_csv(&statement);
        assert!(sheet.contains("line,api-calls,API calls,6000,request,50.000000,\r\n"));
        assert!(sheet.contains("credit,,,,,-20.000000,\r\n"));
        assert!(sheet.contains(&format!("identity,{},alice,,,50.000000,\r\n", b.alice)));
        let spent = b
            .iam
            .store
            .get("billingCredits", &credit_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(spent["remainingMicros"].as_f64(), Some(0.0));
        assert_eq!(
            b.find("audit", Filter::new().eq("action", "billing:statement"))
                .await
                .len(),
            1
        );

        // The invoiced period is closed to late usage.
        let late = b
            .record(
                &b.alice,
                1.0,
                json!({ "occurredAt": start_of(&last_month) + 7_200_000.0 }),
            )
            .await
            .unwrap_err();
        assert_eq!(late.code, "BILLING_PERIOD_CLOSED");
        // Voiding restores the credit and reopens the period; closing again issues a new number.
        let principal = b
            .iam
            .ctx
            .principals()
            .unwrap()
            .authenticate(&b.root_credential)
            .await
            .unwrap();
        let voided = b
            .tx(move |service, tx| async move {
                service
                    .void_statement(&tx, &statement, &principal, "Usage correction")
                    .await
            })
            .await
            .unwrap();
        assert_matches(
            &Value::Object(voided),
            json!({ "status": "void", "voidReason": "Usage correction", "uniqueKey": format!("void:{statement_id}") }),
        );
        let restored = b
            .iam
            .store
            .get("billingCredits", &credit_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored["remainingMicros"].as_f64(), Some(20_000_000.0));
        b.record(
            &b.alice,
            1000.0,
            json!({ "occurredAt": start_of(&last_month) + 7_200_000.0 }),
        )
        .await
        .unwrap();
        let reissued = serde_json::to_value(
            b.service
                .close_period(Some(&json!({ "period": last_month })))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_matches(
            &reissued["issued"],
            json!([{
                "number": format!("INV-{}-0002", last_month.replacen('-', "", 1)),
                "totalMicros": 40_000_000,
            }]),
        );
        let current = period(b.now());
        let error = b
            .service
            .close_period(Some(&json!({ "period": current })))
            .await
            .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        let error = b
            .service
            .close_period(Some(&json!({ "draft": "yes" })))
            .await
            .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
    });
}

#[test]
#[ignore = "needs billing.ts (billing unit)"]
fn takes_payments_and_credit_notes_and_reminds_before_and_after_the_due_date() {
    run(|| async {
        let b = setup(|options| {
            options.billing = Some(BillingOptions {
                payment_reminder_days: Some(vec![-3.0, 0.0, 7.0]),
                ..BillingOptions::default()
            });
        })
        .await;
        let last_month = previous_period(&b);
        b.record(
            &b.alice,
            6000.0,
            json!({ "occurredAt": start_of(&last_month) + 3_600_000.0 }),
        )
        .await
        .unwrap();
        let closed = serde_json::to_value(b.service.close_period(None).await.unwrap()).unwrap();
        let statement_id = closed["issued"][0]["statementId"]
            .as_str()
            .unwrap()
            .to_owned();
        // Due in 30 days: nothing yet.
        assert_eq!(
            b.service.send_payment_reminders().await.unwrap()["reminders"],
            json!([])
        );
        b.advance(27.0 * DAY);
        assert_matches(
            &b.service.send_payment_reminders().await.unwrap()["reminders"],
            json!([{
                "statementId": statement_id,
                "step": -3,
                "amountDueMicros": 50_000_000,
                "recipients": 1,
            }]),
        );
        assert_eq!(
            b.service.send_payment_reminders().await.unwrap()["reminders"],
            json!([])
        );
        // Eight days late: the missed due-date step is skipped for the latest one.
        b.advance(11.0 * DAY);
        assert_matches(
            &b.service.send_payment_reminders().await.unwrap()["reminders"],
            json!([{ "statementId": statement_id, "step": 7 }]),
        );
        let reminders = b.sent("payment-reminder").await;
        assert_eq!(reminders.len(), 2);
        assert_matches(
            &Value::Object(reminders[1].payload.clone()),
            json!({ "days": "8", "overdue": "true", "amountDue": "$50.00" }),
        );
        // A partial payment, then a credit note for part of the rest, then the balance.
        let statement = b.statement(&statement_id).await;
        let actor = b.root_id.clone();
        let paid = b
            .tx(move |service, tx| async move {
                service
                    .record_payment(
                        &tx,
                        &statement,
                        &json!({ "amount": 20, "reference": " wire-1 " }),
                        &actor,
                    )
                    .await
            })
            .await
            .unwrap();
        assert_matches(
            &Value::Object(paid.statement.clone()),
            json!({ "status": "finalized", "amountPaidMicros": 20_000_000 }),
        );
        assert_matches(
            &Value::Object(paid.payment),
            json!({ "amountMicros": 20_000_000, "method": "manual", "reference": "wire-1" }),
        );
        let actor = b.root_id.clone();
        let statement = paid.statement;
        let too_much = statement.clone();
        let error = b
            .tx({
                let actor = actor.clone();
                move |service, tx| async move {
                    service
                        .create_credit_note(&tx, &too_much, &json!({ "amount": 60 }), &actor)
                        .await
                }
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        assert_eq!(
            error.message,
            "At most $50.00 of the invoice can still be credited"
        );
        let noted = b
            .tx(move |service, tx| async move {
                service
                    .create_credit_note(
                        &tx,
                        &statement,
                        &json!({ "amount": 10, "reason": "service_issue" }),
                        &actor,
                    )
                    .await
            })
            .await
            .unwrap();
        assert_matches(
            &Value::Object(noted.credit_note),
            json!({
                "amountMicros": 10_000_000,
                "applied": { "dueMicros": 10_000_000, "creditMicros": 0, "refundMicros": 0 },
            }),
        );
        let statement = noted.statement;
        let actor = b.root_id.clone();
        let settled = b
            .tx(move |service, tx| async move {
                service
                    .record_payment(&tx, &statement, &json!({ "amount": 25 }), &actor)
                    .await
            })
            .await
            .unwrap();
        // $5 above the amount due stays as account credit.
        assert_matches(
            &Value::Object(settled.statement),
            json!({ "status": "paid", "amountPaidMicros": 40_000_000 }),
        );
        assert_matches(
            &Value::Object(settled.payment),
            json!({ "overpaymentMicros": 5_000_000 }),
        );
        let credits = b.find("billingCredits", Filter::new()).await;
        assert!(
            credits
                .iter()
                .any(|credit| credit["remainingMicros"].as_f64() == Some(5_000_000.0))
        );
    });
}

#[test]
#[ignore = "needs billing.ts (billing unit)"]
fn records_seats_daily_for_every_active_person() {
    run(|| async {
        let b = setup(|_| {}).await;
        let root = b.root_tenant.clone();
        let seats = meter(&b, &root, "seats", "Active seats", "seat", "unique").await;
        price(
            &b,
            &root,
            &seats,
            "seats",
            &period(b.now()),
            json!({ "model": "per-unit", "unitAmountMicros": 12_000_000 }),
        )
        .await;
        let first = b.service.record_seats(None).await.unwrap();
        // The owner, alice, bob and carol.
        assert_matches(
            &first,
            json!({ "meter": "seats", "recorded": 4, "duplicates": 0, "failedTenants": [] }),
        );
        assert_matches(
            &b.service.record_seats(None).await.unwrap(),
            json!({ "recorded": 0, "duplicates": 4 }),
        );
        let spend = b
            .spend(&b.tenant_id, json!({ "groupBy": "meter" }))
            .await
            .unwrap();
        assert_matches(
            &spend["rows"],
            json!([{ "key": "seats", "costMicros": 48_000_000 }]),
        );
        let per_person = b
            .spend(
                &b.tenant_id,
                json!({ "groupBy": "identity", "meter": "seats" }),
            )
            .await
            .unwrap();
        assert!(
            rows(&per_person)
                .iter()
                .all(|row| row["costMicros"].as_f64() == Some(12_000_000.0))
        );
        let error = b
            .service
            .record_seats(Some(&json!({ "kinds": ["robot"] })))
            .await
            .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
    });
}

#[test]
#[ignore = "needs billing.ts (billing unit)"]
fn records_priced_usage_on_the_platform_inference_meter() {
    run(|| async {
        let b = setup(|_| {}).await;
        let hooks = b.iam.ctx.billing().unwrap().clone();
        let input = json!({
            "tenantId": b.tenant_id,
            "meter": "inference",
            "costMicros": 2000,
            "quantity": 1200,
            "identityId": b.owner_id,
            "tags": { "model": "haiku" },
            "sourceId": "call-1",
        });
        for _ in 0..2 {
            let (hooks, input) = (hooks.clone(), input.clone());
            b.store()
                .transaction(move |tx| async move {
                    hooks.record_priced(&tx, &input).await;
                    Ok(())
                })
                .await
                .unwrap();
        }
        // The source id makes the push idempotent.
        let spend = b
            .spend(&b.tenant_id, json!({ "groupBy": "tag:model" }))
            .await
            .unwrap();
        assert_matches(
            &spend["rows"],
            json!([{ "key": "haiku", "costMicros": 2000, "quantities": { "inference": 1200 } }]),
        );
        let meters = b
            .find("billingMeters", Filter::new().eq("key", "inference"))
            .await;
        assert_eq!(meters.len(), 1);
        assert_matches(
            &Value::Object(meters[0].clone()),
            json!({
                "tenantId": b.root_tenant,
                "pricing": "reported",
                "name": "AI inference",
                "createdBy": "deployment",
            }),
        );
    });
}

#[test]
#[ignore = "needs billing.ts (billing unit)"]
fn finds_spend_spikes_alerts_on_them_once_and_exports_csv() {
    run(|| async {
        let b = setup(|_| {}).await;
        let root = b.root_tenant.clone();
        let builds = meter(&b, &root, "builds", "CI builds", "build", "sum").await;
        price(
            &b,
            &root,
            &builds,
            "builds",
            &previous_period(&b),
            json!({ "model": "per-unit", "unitAmountMicros": 1_000_000 }),
        )
        .await;
        let today = (b.now() / DAY).floor() * DAY;
        let noon_days_ago = |days: f64| today - days * DAY + 43_200_000.0;
        let build = |identity_id: String, quantity: f64, days_ago: f64| {
            json!({
                "tenantId": b.tenant_id,
                "meter": "builds",
                "quantity": quantity,
                "identityId": identity_id,
                "occurredAt": noon_days_ago(days_ago),
            })
        };
        for days_ago in 2..=15 {
            b.record_trusted(build(b.bob.clone(), 2.0, days_ago as f64))
                .await
                .unwrap();
            b.record_trusted(build(b.alice.clone(), 1.0, days_ago as f64))
                .await
                .unwrap();
        }
        b.record_trusted(build(b.bob.clone(), 40.0, 1.0))
            .await
            .unwrap();
        b.record_trusted(build(b.alice.clone(), 1.0, 1.0))
            .await
            .unwrap();
        let ctx = b.iam.ctx.clone();
        let tenant_id = b.tenant_id.clone();
        let anomalies = |options: Value| {
            let (ctx, tenant_id) = (ctx.clone(), tenant_id.clone());
            b.tx(move |service, tx| async move {
                let scope = ctx.tenant(&tx, &tenant_id).await?;
                let found = service.anomalies(&tx, &scope, Some(&options)).await?;
                Ok(serde_json::to_value(found).unwrap())
            })
        };
        let found = anomalies(json!({})).await.unwrap();
        assert_matches(
            &found,
            json!([
                {
                    "dimension": "meter",
                    "key": "builds",
                    "label": "CI builds",
                    "costMicros": 41_000_000,
                    "baselineMicros": 3_000_000,
                },
                {
                    "dimension": "identity",
                    "key": b.bob,
                    "label": "bob",
                    "costMicros": 40_000_000,
                    "baselineMicros": 2_000_000,
                    "factor": 20,
                },
            ]),
        );
        // A higher bar reports nothing.
        assert_eq!(anomalies(json!({ "factor": 50 })).await.unwrap(), json!([]));
        assert_eq!(
            anomalies(json!({ "factor": 1 })).await.unwrap_err().code,
            "INVALID_INPUT"
        );
        // The daily job alerts once per spike.
        let first = b.service.detect_anomalies(None).await.unwrap();
        let alerted: Vec<Value> = first["anomalies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|anomaly| json!([anomaly["dimension"], anomaly["accountId"]]))
            .collect();
        assert_eq!(
            Value::Array(alerted),
            json!([["meter", b.tenant_id], ["identity", b.tenant_id]])
        );
        assert_eq!(
            b.service.detect_anomalies(None).await.unwrap()["anomalies"],
            json!([])
        );
        let mail = b.sent("spend-anomaly").await;
        assert_eq!(mail.len(), 1);
        assert_eq!(mail[0].to, "owner@acme.test");
        assert_eq!(mail[0].payload["count"], "2");
        assert_eq!(
            b.find("audit", Filter::new().eq("action", "billing:anomaly"))
                .await
                .len(),
            2
        );
        // CSV of a spend report, guarded against spreadsheet formulas.
        let mut alice = b
            .iam
            .store
            .get("identities", &b.alice)
            .await
            .unwrap()
            .unwrap();
        alice.insert("name".into(), json!("=HYPERLINK(\"x\")"));
        b.put("identities", alice).await;
        let report = {
            let (ctx, tenant_id) = (b.iam.ctx.clone(), b.tenant_id.clone());
            b.tx(move |service, tx| async move {
                let scope = ctx.tenant(&tx, &tenant_id).await?;
                service
                    .report(&tx, &scope, &json!({ "groupBy": "identity" }), None, None)
                    .await
            })
            .await
            .unwrap()
        };
        let body = b.service.spend_csv(&report);
        let lines: Vec<&str> = body.trim().split("\r\n").collect();
        assert_eq!(
            lines[0],
            "identity,label,amount_usd,share_percent,events,quantity_builds"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("\"'=HYPERLINK(\"\"x\"\")"))
        );
        assert!(lines.last().unwrap().starts_with("total,,"));
    });
}

#[test]
#[ignore = "needs billing.ts (billing unit)"]
fn spreads_unattributed_spend_over_people_when_asked() {
    run(|| async {
        let b = setup(|_| {}).await;
        b.record(&b.alice, 3000.0, json!({})).await.unwrap();
        b.record(&b.bob, 1000.0, json!({})).await.unwrap();
        // Shared usage nobody caused: 1000 calls.
        b.record_trusted(
            json!({ "tenantId": b.tenant_id, "meter": "api-calls", "quantity": 1000 }),
        )
        .await
        .unwrap();
        // 5000 calls, 4000 billable at $0.01 = $40: alice 24, bob 8, shared 8.
        let plain = b
            .spend(&b.tenant_id, json!({ "groupBy": "identity" }))
            .await
            .unwrap();
        let amounts: Vec<Value> = rows(&plain)
            .iter()
            .map(|row| json!([row["key"], row["amount"]]))
            .collect();
        assert!(matches(
            &Value::Array(amounts),
            &json!([[b.alice, 24], ["(unattributed)", 8], [b.bob, 8]])
        ));
        let shared = b
            .spend(
                &b.tenant_id,
                json!({ "groupBy": "identity", "shareUnattributed": true }),
            )
            .await
            .unwrap();
        assert_eq!(shared["sharedMicros"].as_f64(), Some(8_000_000.0));
        let spread: Vec<Value> = rows(&shared)
            .iter()
            .map(|row| json!([row["key"], row["amount"], row["sharedMicros"]]))
            .collect();
        assert!(matches(
            &Value::Array(spread),
            &json!([[b.alice, 30, 6_000_000], [b.bob, 10, 2_000_000]])
        ));
        let sum: f64 = rows(&shared)
            .iter()
            .map(|row| row["costMicros"].as_f64().unwrap())
            .sum();
        assert_eq!(Some(sum), shared["total"]["costMicros"].as_f64());
    });
}

#[test]
#[ignore = "needs billing.ts (billing unit)"]
fn applies_a_discount_a_minimum_commitment_credit_and_tax_to_statements() {
    run(|| async {
        let b = setup(|_| {}).await;
        let last_month = previous_period(&b);
        // 6000 calls, 1000 free: $50 of usage.
        b.record(
            &b.alice,
            6000.0,
            json!({ "occurredAt": start_of(&last_month) + 3_600_000.0 }),
        )
        .await
        .unwrap();
        b.insert(
            "billingTerms",
            json!({
                "id": id(),
                "tenantId": b.tenant_id,
                "uniqueKey": "terms",
                "discountPercent": 10,
                "minimumCommitmentMicros": 100_000_000,
                "taxRatePercent": 20,
                "taxLabel": "VAT",
                "setAt": b.now(),
                "setBy": b.root_id,
            }),
        )
        .await;
        credit(&b, &b.tenant_id.clone(), 20_000_000.0, "Goodwill").await;
        // $50 - 10% = $45; the $100 commitment adds $55; $20 credit leaves $80; 20% VAT: $96.
        let closed = serde_json::to_value(b.service.close_period(None).await.unwrap()).unwrap();
        assert_matches(&closed["issued"], json!([{ "totalMicros": 96_000_000 }]));
        let statement = b
            .statement(closed["issued"][0]["statementId"].as_str().unwrap())
            .await;
        assert_matches(
            &Value::Object(statement.clone()),
            json!({
                "subtotalMicros": 50_000_000,
                "discount": { "percent": 10, "amountMicros": 5_000_000 },
                "commitment": { "minimumMicros": 100_000_000, "trueUpMicros": 55_000_000 },
                "creditsMicros": 20_000_000,
                "tax": { "label": "VAT", "ratePercent": 20, "amountMicros": 16_000_000 },
                "totalMicros": 96_000_000,
            }),
        );
        let sheet = b.service.statement_csv(&statement);
        assert!(sheet.contains("discount,,10%,,,-5.000000,"));
        assert!(sheet.contains("commitment,,minimum commitment true-up,,,55.000000,"));
        assert!(sheet.contains("tax,,VAT 20%,,,16.000000,"));
    });
}

#[test]
#[ignore = "needs billing.ts (billing unit)"]
fn refuses_bad_billing_options_when_the_server_is_built() {
    run(|| async {
        let mut options = better_iam_server::options::BetterIamOptions::new(
            better_iam_adapter_sqlite::sqlite_adapter(
                better_iam_adapter_sqlite::SqliteAdapterOptions::new(":memory:"),
            )
            .unwrap(),
            "billing-options-secret-with-32-characters!!",
            organization_fixture::ORIGIN,
        );
        options.billing = Some(BillingOptions {
            payment_reminder_days: Some(vec![500.0]),
            ..BillingOptions::default()
        });
        let error = better_iam_server::better_iam(options)
            .err()
            .expect("refused");
        assert_eq!(error.code, "INVALID_CONFIG");
    });
}
