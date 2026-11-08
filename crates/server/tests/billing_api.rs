//! Port of the tests of the `billing` API group and `iam.billing` (api/billing.ts): tests/billing.test.ts,
//! tests/security-billing.test.ts (the API guards: team spend reads, payment terms, built-in meter keys) and
//! tests/billing-invoicing.test.ts, plus the guards of the group that run before the billing engine is reached.
//!
//! The scenarios meter usage, price it and draw up statements through `billing.ts`, `billing-service.ts`,
//! `billing-plans.ts` and `billing-invoices.ts`, which other units port: they are `#[ignore]`d with that reason until
//! those land. The guard tests run now.

mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::{CredentialInput, Filter, IamError, IamResult, js};
use organization_fixture::{Org, assert_matches, body, organization, run};
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;

macro_rules! billing {
    ($f:expr, $method:ident, $credential:expr, $input:expr) => {
        $f.iam
            .api
            .billing
            .$method($credential, body($input))
            .await
            .and_then(|reply| reply.into_value())
    };
}

macro_rules! api {
    ($f:expr, $group:ident, $method:ident, $credential:expr, $input:expr) => {
        $f.iam
            .api
            .$group
            .$method($credential, body($input))
            .await
            .and_then(|reply| reply.into_value())
            .expect(concat!(stringify!($group), ".", stringify!($method)))
    };
}

#[track_caller]
fn fails_with(result: IamResult<Value>, code: &str) -> IamError {
    match result {
        Ok(value) => panic!("expected {code}, got {value}"),
        Err(error) => {
            assert_eq!(error.code, code, "{error:?}");
            error
        }
    }
}

#[track_caller]
fn ok(result: IamResult<Value>) -> Value {
    match result {
        Ok(value) => value,
        Err(error) => panic!("expected success, got {error:?}"),
    }
}

fn s(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_owned()
}

/// `periodOf(at, 'UTC')`.
fn utc_period(at: f64) -> String {
    let (year, month, _) = js::civil_from_days((at / DAY).floor() as i64);
    format!("{year:04}-{month:02}")
}

/// `shiftPeriod(period, months)`.
fn shift(period: &str, months: i64) -> String {
    let year: i64 = period[..4].parse().unwrap();
    let month: i64 = period[5..7].parse().unwrap();
    let total = year * 12 + (month - 1) + months;
    format!(
        "{:04}-{:02}",
        total.div_euclid(12),
        total.rem_euclid(12) + 1
    )
}

/// `periodBounds(period, 'UTC').start`.
fn period_start(period: &str) -> f64 {
    let year: i64 = period[..4].parse().unwrap();
    let month: i64 = period[5..7].parse().unwrap();
    js::days_from_civil(year, month, 1) as f64 * DAY
}

/// The organization fixture with a captured email outbox.
async fn fixture_with(
    configure: impl FnOnce(&mut better_iam_server::options::BetterIamOptions),
) -> (Org, Arc<Mutex<Vec<DeliveryMessage>>>) {
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let sink = inbox.clone();
    let f = organization(move |options| {
        if let Some(authentication) = options.authentication.as_mut() {
            authentication.send_email = Some(delivery_fn(move |message| {
                sink.lock().unwrap().push(message);
                async { Ok(()) }
            }));
        }
        configure(options);
    })
    .await;
    (f, inbox)
}

/// Acme with a platform `api-calls` meter: 1000 free calls a month, then $0.01 each up to 10 000, then $0.005.
struct Setup {
    f: Org,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
    root: String,
    alice: String,
    bob: String,
    carol: String,
}

async fn setup() -> Setup {
    let (f, inbox) = fixture_with(|_| {}).await;
    let root = f.root_tenant.clone();
    ok(billing!(
        f,
        create_meter,
        &f.root_credential,
        json!({ "tenantId": root, "key": "api-calls", "name": "API calls", "unit": "request" })
    ));
    ok(billing!(
        f,
        set_price,
        &f.root_credential,
        json!({
            "tenantId": root,
            "meter": "api-calls",
            // From last month on, so usage backdated into it is priced too (nothing is invoiced yet).
            "effectiveFrom": shift(&utc_period(f.now()), -1),
            "price": {
                "model": "graduated",
                "includedQuantity": 1000,
                "tiers": [{ "upTo": 10_000, "unitAmount": 0.01 }, { "upTo": null, "unitAmount": 0.005 }],
            },
        })
    ));
    let alice = f.member("alice").await;
    let bob = f.member("bob").await;
    let carol = f.member("carol").await;
    Setup {
        f,
        inbox,
        root,
        alice,
        bob,
        carol,
    }
}

impl Setup {
    /// `record(identityId, quantity, extra)` with the owner's credential.
    async fn record(&self, identity_id: &str, quantity: f64, extra: Value) -> IamResult<Value> {
        let mut input = json!({
            "tenantId": self.f.tenant_id,
            "meter": "api-calls",
            "quantity": quantity,
            "identityId": identity_id,
        });
        if let (Value::Object(input), Value::Object(extra)) = (&mut input, extra) {
            input.extend(extra);
        }
        billing!(self.f, record, &self.f.owner_credential, input)
    }

    fn previous_period_start(&self) -> f64 {
        period_start(&shift(&utc_period(self.f.now()), -1))
    }

    async fn dispatch(&self) {
        self.f.iam.auth.dispatch_outbox(None).await.unwrap();
    }

    fn mail(&self, template: &str) -> Vec<DeliveryMessage> {
        self.inbox
            .lock()
            .unwrap()
            .iter()
            .filter(|message| message.template == template)
            .cloned()
            .collect()
    }
}

/// A project under Acme whose owner is active.
async fn project(f: &Org, name: &str) -> (String, CredentialInput) {
    let (tenant_id, _, credential) = f
        .activate(
            &f.tenant_id.clone(),
            name,
            "project",
            &format!("{}@acme.test", name.to_lowercase()),
        )
        .await;
    (tenant_id, credential)
}

fn rows(report: &Value) -> Vec<Value> {
    report["rows"].as_array().cloned().unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------------------------------
// Guards that run before the billing engine

#[test]
fn checks_and_own_spend_are_read_in_the_credentials_own_tenant() {
    run(|| async {
        let f = organization(|_| {}).await;
        // The platform tenant is not in Acme's chain.
        let denied = fails_with(
            billing!(
                f,
                check,
                &f.owner_credential,
                json!({ "tenantId": f.root_tenant })
            ),
            "ACCESS_DENIED",
        );
        assert_eq!(
            denied.message,
            "Budgets are checked in the credential\u{2019}s own tenant"
        );
        assert_eq!(denied.status, 403);
        fails_with(
            billing!(f, check, &f.owner_credential, json!({ "tenantId": 7 })),
            "INVALID_INPUT",
        );
        let denied = fails_with(
            billing!(
                f,
                my_spend,
                &f.owner_credential,
                json!({ "tenantId": f.root_tenant })
            ),
            "ACCESS_DENIED",
        );
        assert_eq!(
            denied.message,
            "Spend is read in the credential\u{2019}s own tenant"
        );
        let invalid = fails_with(
            billing!(
                f,
                my_spend,
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id, "groupBy": 7 })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(
            invalid.message,
            "groupBy must be 'meter', 'day', 'agent', 'tenant' or 'tag:{name}'"
        );
        fails_with(
            billing!(
                f,
                my_spend,
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id, "groupBy": "identity" })
            ),
            "INVALID_INPUT",
        );
    });
}

#[test]
fn platform_work_happens_on_the_root_tenant_and_only_root_administrators_do_it() {
    run(|| async {
        let f = organization(|_| {}).await;
        // Root-only operations refuse other principals.
        fails_with(
            billing!(
                f,
                close_period,
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id })
            ),
            "ACCESS_DENIED",
        );
        fails_with(
            billing!(
                f,
                grant_credit,
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id, "amount": 5, "reason": "x" })
            ),
            "ACCESS_DENIED",
        );
        fails_with(
            billing!(
                f,
                set_terms,
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id, "discountPercent": 90 })
            ),
            "ACCESS_DENIED",
        );
        // Periods are closed, plans and coupons managed, on the platform tenant.
        let wrong = fails_with(
            billing!(
                f,
                close_period,
                &f.root_credential,
                json!({ "tenantId": f.tenant_id })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(
            wrong.message,
            "Periods are closed on the platform (root) tenant"
        );
        let wrong = fails_with(
            billing!(
                f,
                create_plan,
                &f.root_credential,
                json!({ "tenantId": f.tenant_id, "key": "pro", "name": "Pro", "items": [] })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(
            wrong.message,
            "Plans are managed on the platform (root) tenant"
        );
        let wrong = fails_with(
            billing!(
                f,
                list_coupons,
                &f.root_credential,
                json!({ "tenantId": f.tenant_id })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(
            wrong.message,
            "Coupons are managed on the platform (root) tenant"
        );
        // The platform tenant is no billing account.
        let wrong = fails_with(
            billing!(
                f,
                grant_credit,
                &f.root_credential,
                json!({ "tenantId": f.root_tenant, "amount": 5, "reason": "x" })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(
            wrong.message,
            "Credit is granted to a billing account (an organization or a tenant with a billing profile)"
        );
        fails_with(
            billing!(
                f,
                set_terms,
                &f.root_credential,
                json!({ "tenantId": f.root_tenant, "discountPercent": 5 })
            ),
            "INVALID_INPUT",
        );
        let wrong = fails_with(
            billing!(
                f,
                set_profile,
                &f.root_credential,
                json!({ "tenantId": f.root_tenant, "companyName": "Platform" })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(wrong.message, "The platform tenant is not billed");
    });
}

#[test]
fn unknown_records_are_not_found_and_empty_lists_are_empty() {
    run(|| async {
        let f = organization(|_| {}).await;
        let root = f.root_tenant.clone();
        let acme = f.tenant_id.clone();
        let missing = fails_with(
            billing!(
                f,
                get_statement,
                &f.root_credential,
                json!({ "tenantId": root, "statementId": "missing" })
            ),
            "NOT_FOUND",
        );
        assert_eq!(missing.message, "Statement not found");
        assert_eq!(missing.status, 404);
        for result in [
            billing!(
                f,
                mark_paid,
                &f.root_credential,
                json!({ "tenantId": acme, "statementId": "missing" })
            ),
            billing!(
                f,
                void_statement,
                &f.root_credential,
                json!({ "tenantId": acme, "statementId": "missing", "reason": "x" })
            ),
            billing!(
                f,
                delete_invoice_item,
                &f.root_credential,
                json!({ "tenantId": acme, "itemId": "missing" })
            ),
            billing!(
                f,
                revoke_credit,
                &f.root_credential,
                json!({ "tenantId": acme, "creditId": "missing" })
            ),
            billing!(
                f,
                remove_discount,
                &f.root_credential,
                json!({ "tenantId": acme, "discountId": "missing" })
            ),
            billing!(
                f,
                cancel_subscription,
                &f.owner_credential,
                json!({ "tenantId": acme, "subscriptionId": "missing" })
            ),
            billing!(
                f,
                delete_budget,
                &f.owner_credential,
                json!({ "tenantId": acme, "budgetId": "missing" })
            ),
        ] {
            fails_with(result, "NOT_FOUND");
        }
        fails_with(
            billing!(
                f,
                revoke_credit,
                &f.root_credential,
                json!({ "tenantId": acme, "creditId": 7 })
            ),
            "INVALID_INPUT",
        );
        for result in [
            billing!(
                f,
                list_statements,
                &f.root_credential,
                json!({ "tenantId": root })
            ),
            billing!(
                f,
                list_invoice_items,
                &f.root_credential,
                json!({ "tenantId": root })
            ),
            billing!(
                f,
                list_credit_notes,
                &f.root_credential,
                json!({ "tenantId": root })
            ),
            billing!(
                f,
                list_subscriptions,
                &f.root_credential,
                json!({ "tenantId": root })
            ),
            billing!(
                f,
                list_plans,
                &f.root_credential,
                json!({ "tenantId": root })
            ),
            billing!(
                f,
                list_coupons,
                &f.root_credential,
                json!({ "tenantId": root })
            ),
            billing!(
                f,
                list_budgets,
                &f.owner_credential,
                json!({ "tenantId": acme })
            ),
        ] {
            assert_eq!(ok(result), json!([]));
        }
        let invalid = fails_with(
            billing!(
                f,
                list_invoice_items,
                &f.root_credential,
                json!({ "tenantId": root, "status": "paid" })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(invalid.message, "status must be 'pending' or 'invoiced'");
        let invalid = fails_with(
            billing!(
                f,
                create_budget,
                &f.owner_credential,
                json!({ "tenantId": acme })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(invalid.message, "name is required");
        let invalid = fails_with(
            billing!(
                f,
                record_many,
                &f.owner_credential,
                json!({ "tenantId": acme, "events": [] })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(invalid.message, "events must list 1-100 usage events");
    });
}

#[test]
fn team_and_department_spend_need_the_role_or_the_permission() {
    run(|| async {
        let f = organization(|_| {}).await;
        let bob = f.member("bob").await;
        let session = f.sign_in(&bob).await;
        let denied = fails_with(
            billing!(
                f,
                team_spend,
                &session,
                json!({ "tenantId": f.tenant_id, "teamId": "no-such-team" })
            ),
            "ACCESS_DENIED",
        );
        assert_eq!(denied.message, "Access denied");
        fails_with(
            billing!(
                f,
                department_spend,
                &session,
                json!({ "tenantId": f.tenant_id, "departmentId": "no-such-department" })
            ),
            "ACCESS_DENIED",
        );
        fails_with(
            billing!(f, team_spend, &session, json!({ "tenantId": f.tenant_id })),
            "INVALID_INPUT",
        );
        // The refusals are recorded as denials of iam:billing:read.
        let mut denials: Vec<_> = f
            .find("audit", Filter::new().eq("action", "iam:billing:read"))
            .await
            .into_iter()
            .filter(|event| event.get("outcome") == Some(&json!("deny")))
            .map(|event| event["resourceId"].as_str().unwrap_or_default().to_owned())
            .collect();
        denials.sort();
        assert_eq!(
            denials,
            vec![
                "billing/departments/no-such-department".to_owned(),
                "billing/teams/no-such-team".to_owned()
            ]
        );
    });
}

#[test]
fn the_trusted_runtime_validates_its_input() {
    run(|| async {
        let f = organization(|_| {}).await;
        let invalid = f.iam.billing.record_many(&json!([])).await.unwrap_err();
        assert_eq!(invalid.message, "events must list 1-1000 usage events");
        let invalid = f.iam.billing.record_many(&json!({})).await.unwrap_err();
        assert_eq!(invalid.code, "INVALID_INPUT");
        let invalid = f.iam.billing.record_payment(&json!({})).await.unwrap_err();
        assert_eq!(invalid.message, "Give statementId or number");
        let missing = f
            .iam
            .billing
            .record_payment(&json!({ "statementId": "missing" }))
            .await
            .unwrap_err();
        assert_eq!((missing.code.as_str(), missing.status), ("NOT_FOUND", 404));
        let missing = f
            .iam
            .billing
            .record_payment(&json!({ "number": "INV-209901-0001" }))
            .await
            .unwrap_err();
        assert_eq!(missing.message, "Statement not found");
        // The conformance server reaches the same members by name.
        let called = f
            .iam
            .billing
            .call("recordMany", vec![json!([])])
            .await
            .expect("member")
            .unwrap_err();
        assert_eq!(called.code, "INVALID_INPUT");
        assert!(f.iam.billing.call("noSuchMember", vec![]).await.is_none());
        let check = f
            .iam
            .billing
            .check(&json!({ "tenantId": 7 }))
            .await
            .unwrap_err();
        assert_eq!(check.message, "Invalid tenantId");
    });
}

/// The meter, rate card, credit, terms and profile routes of the group, which reach `billing.ts` (meters, prices,
/// periods, accounts) but not the ledger.
#[test]
#[ignore = "needs billing.ts (meterKey, priceSpec, accountOf, periodOf, ...) from the billing unit"]
fn manages_meters_rate_cards_credits_terms_and_profiles() {
    run(|| async {
        let f = organization(|_| {}).await;
        let root = f.root_tenant.clone();
        let rc = &f.root_credential;
        let oc = &f.owner_credential;
        let meter = ok(billing!(
            f,
            create_meter,
            rc,
            json!({ "tenantId": root, "key": "api-calls", "name": "API calls", "unit": "request" })
        ));
        assert_matches(
            &meter,
            json!({
                "key": "api-calls",
                "aggregation": "sum",
                "pricing": "rate-card",
                "archived": false,
                "definedBy": root,
                "scope": "platform",
                "inherited": false,
            }),
        );
        let list = ok(billing!(
            f,
            set_price,
            rc,
            json!({
                "tenantId": root,
                "meter": "api-calls",
                "price": { "model": "per-unit", "unitAmount": 0.01 },
                "note": "list",
            })
        ));
        assert_matches(
            &list,
            json!({ "targetTenantId": root, "targetTenantName": "Platform", "note": "list", "setBy": f.root_id }),
        );
        ok(billing!(
            f,
            set_price,
            rc,
            json!({
                "tenantId": root,
                "meter": "api-calls",
                "targetTenantId": f.tenant_id,
                "price": { "model": "per-unit", "unitAmount": 0.002 },
            })
        ));
        // Below the platform, prices never name the root administrator who set them.
        let meters = ok(billing!(
            f,
            list_meters,
            oc,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_matches(
            &meters,
            json!([{ "key": "api-calls", "inherited": true, "price": { "targetTenantId": f.tenant_id } }]),
        );
        assert!(meters[0]["price"].get("setBy").is_none());
        let card = ok(billing!(
            f,
            list_prices,
            oc,
            json!({ "tenantId": f.tenant_id, "meter": "api-calls" })
        ));
        assert_eq!(card["entries"].as_array().unwrap().len(), 2);
        assert_matches(&card["effective"], json!({ "targetTenantId": f.tenant_id }));
        assert_matches(
            &ok(billing!(
                f,
                quote,
                oc,
                json!({ "tenantId": f.tenant_id, "meter": "api-calls", "quantity": 1000 })
            )),
            json!({ "quantity": 1000, "currency": "USD", "amountMicros": 2_000_000, "amount": 2 }),
        );
        let refused = fails_with(
            billing!(
                f,
                quote,
                oc,
                json!({ "tenantId": f.tenant_id, "meter": "api-calls", "quantity": -1 })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(refused.message, "quantity must be a number of at least 0");
        // A description is set and cleared; the stored meter keeps its other members in place.
        let described = ok(billing!(
            f,
            update_meter,
            rc,
            json!({ "tenantId": root, "key": "api-calls", "name": "Calls", "description": "d" })
        ));
        assert_matches(&described, json!({ "name": "Calls", "description": "d" }));
        let cleared = ok(billing!(
            f,
            update_meter,
            rc,
            json!({ "tenantId": root, "key": "api-calls", "description": null })
        ));
        assert!(cleared.get("description").is_none());
        let stored = f.find("billingMeters", Filter::new()).await.remove(0);
        assert_eq!(
            stored.keys().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "id",
                "tenantId",
                "uniqueKey",
                "key",
                "name",
                "unit",
                "aggregation",
                "pricing",
                "archived",
                "createdAt",
                "createdBy",
                "updatedAt",
                "updatedBy"
            ]
        );
        assert!(
            ok(billing!(
                f,
                set_price,
                rc,
                json!({ "tenantId": root, "meter": "api-calls", "targetTenantId": f.tenant_id, "price": null })
            ))
            .is_null()
        );
        // Credits: granted to an account, listed with the balance, revoked once.
        let credit = ok(billing!(
            f,
            grant_credit,
            rc,
            json!({ "tenantId": f.tenant_id, "amount": 20, "reason": " Launch ", "expiresAt": f.now() + 30.0 * DAY })
        ));
        assert_matches(
            &credit,
            json!({ "amountMicros": 20_000_000, "amount": 20, "remaining": 20, "reason": "Launch", "active": true }),
        );
        assert_matches(
            &ok(billing!(
                f,
                list_credits,
                oc,
                json!({ "tenantId": f.tenant_id })
            )),
            json!({ "accountId": f.tenant_id, "inherited": false, "balanceMicros": 20_000_000, "balance": 20 }),
        );
        let revoked = ok(billing!(
            f,
            revoke_credit,
            rc,
            json!({ "tenantId": f.tenant_id, "creditId": credit["id"] })
        ));
        assert_matches(&revoked, json!({ "remainingMicros": 0, "active": false }));
        fails_with(
            billing!(
                f,
                revoke_credit,
                rc,
                json!({ "tenantId": f.tenant_id, "creditId": credit["id"] })
            ),
            "INVALID_TRANSITION",
        );
        // Terms: percentages keep three decimals; the setter shows to the platform only.
        let terms = ok(billing!(
            f,
            set_terms,
            rc,
            json!({
                "tenantId": f.tenant_id,
                "discountPercent": 10.12345,
                "minimumCommitment": 100,
                "taxRatePercent": 20,
                "taxLabel": " VAT ",
            })
        ));
        assert_matches(
            &terms,
            json!({
                "discountPercent": 10.123,
                "minimumCommitmentMicros": 100_000_000,
                "minimumCommitment": 100,
                "taxLabel": "VAT",
                "setBy": f.root_id,
            }),
        );
        let seen = ok(billing!(
            f,
            get_terms,
            oc,
            json!({ "tenantId": f.tenant_id })
        ));
        assert!(seen.get("setBy").is_none());
        // Profiles: below an organization, a tenant becomes its own account only from its parent.
        let profile = ok(billing!(
            f,
            set_profile,
            oc,
            json!({
                "tenantId": f.tenant_id,
                "companyName": "Acme",
                "billingEmails": ["AP@acme.test", "ap@acme.test"],
                "paymentTermsDays": 15,
            })
        ));
        assert_matches(
            &profile,
            json!({
                "account": { "id": f.tenant_id, "name": "Acme", "inherited": false },
                "profile": { "billingEmails": ["ap@acme.test"], "companyName": "Acme", "paymentTermsDays": 15 },
            }),
        );
        assert_eq!(
            ok(billing!(
                f,
                get_profile,
                oc,
                json!({ "tenantId": f.tenant_id })
            )),
            profile
        );
        let (apollo, _, apollo_credential) = f
            .activate(
                &f.tenant_id.clone(),
                "Apollo",
                "project",
                "apollo@acme.test",
            )
            .await;
        fails_with(
            billing!(
                f,
                set_profile,
                &apollo_credential,
                json!({ "tenantId": apollo, "companyName": "Apollo" })
            ),
            "ACCESS_DENIED",
        );
        ok(billing!(
            f,
            set_profile,
            oc,
            json!({ "tenantId": f.tenant_id, "targetTenantId": apollo, "companyName": "Apollo Ltd" })
        ));
        assert_eq!(
            ok(billing!(
                f,
                get_terms,
                &apollo_credential,
                json!({ "tenantId": apollo })
            )),
            json!({ "accountId": apollo, "inherited": false })
        );
        fails_with(
            billing!(
                f,
                delete_profile,
                &apollo_credential,
                json!({ "tenantId": apollo })
            ),
            "ACCESS_DENIED",
        );
        assert_eq!(
            ok(billing!(
                f,
                delete_profile,
                oc,
                json!({ "tenantId": f.tenant_id, "targetTenantId": apollo })
            )),
            json!({ "success": true })
        );
        assert_matches(
            &ok(billing!(
                f,
                list_usage,
                oc,
                json!({ "tenantId": f.tenant_id })
            )),
            json!({ "tenantId": f.tenant_id, "period": utc_period(f.now()), "events": [] }),
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// tests/billing.test.ts: billing and spend

#[test]
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn prices_the_account_total_once_and_shares_it_out_by_person_meter_and_project() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let (apollo, apollo_credential) = project(f, "Apollo").await;
        ok(t.record(&t.alice, 3000.0, json!({})).await);
        ok(t.record(&t.bob, 500.0, json!({})).await);
        ok(billing!(
            f,
            record,
            &apollo_credential,
            json!({ "tenantId": apollo, "meter": "api-calls", "quantity": 500 })
        ));
        // 4000 calls, 1000 free: 3000 × $0.01 = $30, shared by quantity (75% / 12.5% / 12.5%).
        let by_person = ok(billing!(
            f,
            spend,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "groupBy": "identity" })
        ));
        assert_matches(
            &by_person["total"],
            json!({ "costMicros": 30_000_000, "amount": 30, "events": 3 }),
        );
        assert_eq!(by_person["currency"], "USD");
        assert_matches(
            &by_person["rows"],
            json!([
                { "key": t.alice, "costMicros": 22_500_000, "share": 75, "label": "alice <alice@acme.test>" },
                { "key": "(unattributed)", "costMicros": 3_750_000 },
                { "key": t.bob, "costMicros": 3_750_000, "quantities": { "api-calls": 500 } },
            ]),
        );
        let by_project = ok(billing!(
            f,
            spend,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "groupBy": "tenant" })
        ));
        assert_matches(
            &by_project["rows"],
            json!([{ "label": "Acme", "amount": 26.25 }, { "label": "Apollo", "amount": 3.75 }]),
        );
        // The project's own view covers only its subtree, priced within Acme's account.
        let project_view = ok(billing!(
            f,
            spend,
            &apollo_credential,
            json!({ "tenantId": apollo })
        ));
        assert_matches(
            &project_view["rows"],
            json!([{ "key": "api-calls", "label": "API calls", "costMicros": 3_750_000 }]),
        );
        // The platform sees every organization.
        let platform = ok(billing!(
            f,
            accounts,
            &f.root_credential,
            json!({ "tenantId": t.root })
        ));
        assert_matches(
            &platform,
            json!([{ "accountId": f.tenant_id, "name": "Acme", "monthToDateMicros": 30_000_000 }]),
        );
        // A negotiated price for Acme wins over the list price from this period on.
        ok(billing!(
            f,
            set_price,
            &f.root_credential,
            json!({
                "tenantId": t.root,
                "meter": "api-calls",
                "targetTenantId": f.tenant_id,
                "price": { "model": "per-unit", "unitAmount": 0.002 },
                "note": "Enterprise agreement",
            })
        ));
        let negotiated = ok(billing!(
            f,
            spend,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_eq!(negotiated["total"]["costMicros"], json!(8_000_000));
        let card = ok(billing!(
            f,
            list_prices,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "meter": "api-calls" })
        ));
        assert_matches(
            &card["effective"],
            json!({ "targetTenantId": f.tenant_id, "note": "Enterprise agreement" }),
        );
        assert_eq!(card["entries"].as_array().unwrap().len(), 2);
        assert_matches(
            &ok(billing!(
                f,
                quote,
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id, "meter": "api-calls", "quantity": 1000 })
            )),
            json!({ "amountMicros": 2_000_000, "amount": 2 }),
        );
        // Organizations cannot price platform meters or define keys the platform owns.
        fails_with(
            billing!(
                f,
                set_price,
                &f.owner_credential,
                json!({
                    "tenantId": f.tenant_id,
                    "meter": "api-calls",
                    "price": { "model": "per-unit", "unitAmount": 0 },
                })
            ),
            "NOT_FOUND",
        );
        fails_with(
            billing!(
                f,
                create_meter,
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id, "key": "api-calls", "name": "Mine" })
            ),
            "CONFLICT",
        );
    });
}

#[test]
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn validates_usage_stays_idempotent_and_records_through_the_trusted_runtime() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let first = ok(t
            .record(
                &t.alice,
                10.0,
                json!({ "idempotencyKey": "request-1", "tags": { "env": "prod" } }),
            )
            .await);
        let again = ok(t
            .record(&t.alice, 10.0, json!({ "idempotencyKey": "request-1" }))
            .await);
        assert_matches(&again, json!({ "id": first["id"], "duplicate": true }));
        fails_with(
            t.record(&t.alice, 1.0, json!({ "cost": 1 })).await,
            "INVALID_INPUT",
        );
        fails_with(
            billing!(
                f,
                record,
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id, "meter": "nope" })
            ),
            "NOT_FOUND",
        );
        fails_with(t.record(&t.alice, -1.0, json!({})).await, "INVALID_INPUT");
        fails_with(
            t.record(
                &t.alice,
                1.0,
                json!({ "occurredAt": f.now() + 3_600_000.0 }),
            )
            .await,
            "INVALID_INPUT",
        );
        // The server records without a credential (and without an audit event per call).
        f.iam
            .billing
            .record(&json!({
                "tenantId": f.tenant_id,
                "meter": "api-calls",
                "quantity": 5,
                "identityId": t.alice,
                "tags": { "env": "staging" },
            }))
            .await
            .unwrap();
        let by_env = serde_json::to_value(
            f.iam
                .billing
                .spend(&json!({ "tenantId": f.tenant_id, "groupBy": "tag:env" }))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_matches(
            &by_env["rows"],
            json!([
                { "key": "prod", "quantities": { "api-calls": 10 } },
                { "key": "staging", "quantities": { "api-calls": 5 } },
            ]),
        );
        let events = ok(billing!(
            f,
            list_usage,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id })
        ));
        let events = events["events"].as_array().unwrap().clone();
        assert_eq!(events.len(), 2);
        let ten = events
            .iter()
            .find(|event| event["quantity"] == json!(10))
            .unwrap();
        assert_matches(
            ten,
            json!({ "idempotencyKey": "request-1", "recordedBy": f.owner_id, "tags": { "env": "prod" } }),
        );
        // Archived meters keep their history but refuse new usage.
        ok(billing!(
            f,
            update_meter,
            &f.root_credential,
            json!({ "tenantId": t.root, "key": "api-calls", "archived": true })
        ));
        fails_with(t.record(&t.alice, 1.0, json!({})).await, "METER_ARCHIVED");
        fails_with(
            billing!(
                f,
                delete_meter,
                &f.root_credential,
                json!({ "tenantId": t.root, "key": "api-calls" })
            ),
            "RESOURCE_IN_USE",
        );
        // Members without billing permissions can read only their own spend.
        let bob_session = f.sign_in(&t.bob).await;
        fails_with(
            billing!(f, spend, &bob_session, json!({ "tenantId": f.tenant_id })),
            "ACCESS_DENIED",
        );
        let alice_session = f.sign_in(&t.alice).await;
        let mine = ok(billing!(
            f,
            my_spend,
            &alice_session,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_matches(
            &mine["rows"],
            json!([{ "key": "api-calls", "quantities": { "api-calls": 15 } }]),
        );
        let bobs = ok(billing!(
            f,
            my_spend,
            &bob_session,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_eq!(bobs["rows"], json!([]));
        fails_with(
            billing!(
                f,
                my_spend,
                &bob_session,
                json!({ "tenantId": f.tenant_id, "groupBy": 7 })
            ),
            "INVALID_INPUT",
        );
        // The same routes over HTTP.
        let token = alice_session.token.clone().unwrap();
        let (status, over_http) = f
            .post(
                "billing/mySpend",
                &token,
                json!({ "tenantId": f.tenant_id }),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(over_http["total"], mine["total"]);
        let (_, verdict) = f
            .post("billing/check", &token, json!({ "tenantId": f.tenant_id }))
            .await;
        assert_eq!(verdict, json!({ "allowed": true, "budgets": [] }));
    });
}

#[test]
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn attributes_spend_to_teams_and_departments_readable_by_maintainers_and_heads() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let owner = &f.owner_credential;
        let engineering = api!(
            f,
            departments,
            create,
            owner,
            json!({
                "tenantId": f.tenant_id,
                "name": "Engineering",
                "code": "ENG",
                "headId": t.carol,
                "costCenter": "CC-100",
            })
        );
        api!(
            f,
            departments,
            assign,
            owner,
            json!({
                "tenantId": f.tenant_id,
                "departmentId": engineering["id"],
                "identityIds": [t.alice, t.bob],
            })
        );
        let platform = api!(
            f,
            teams,
            create,
            owner,
            json!({
                "tenantId": f.tenant_id,
                "name": "Platform",
                "departmentId": engineering["id"],
                "maintainerIds": [t.alice],
            })
        );
        let web = api!(
            f,
            teams,
            create,
            owner,
            json!({ "tenantId": f.tenant_id, "name": "Web", "parentId": platform["id"] })
        );
        api!(
            f,
            teams,
            add_member,
            owner,
            json!({ "tenantId": f.tenant_id, "teamId": web["id"], "identityId": t.bob })
        );
        ok(t.record(&t.alice, 3000.0, json!({})).await);
        ok(t.record(&t.bob, 1000.0, json!({})).await);
        ok(t.record(&t.carol, 1000.0, json!({})).await);
        // 5000 calls, 4000 billable at $0.01 = $40: alice 24, bob 8, carol 8.
        let by_team = ok(billing!(
            f,
            spend,
            owner,
            json!({ "tenantId": f.tenant_id, "groupBy": "team" })
        ));
        let labelled: Vec<(Value, Value)> = rows(&by_team)
            .iter()
            .map(|row| {
                (
                    if row["label"].is_null() {
                        row["key"].clone()
                    } else {
                        row["label"].clone()
                    },
                    row["amount"].clone(),
                )
            })
            .collect();
        assert_eq!(
            labelled,
            vec![
                (json!("Platform"), json!(24)),
                (json!("(no team)"), json!(8)),
                (json!("Web"), json!(8))
            ]
        );
        // A team's spend includes the teams below it; its maintainers may read it.
        let alice_session = f.sign_in(&t.alice).await;
        let team_view = ok(billing!(
            f,
            team_spend,
            &alice_session,
            json!({ "tenantId": f.tenant_id, "teamId": platform["id"] })
        ));
        assert_eq!(team_view["total"]["amount"], json!(32));
        assert_eq!(
            rows(&team_view)
                .iter()
                .map(|row| s(&row["key"]))
                .collect::<Vec<_>>(),
            vec![t.alice.clone(), t.bob.clone()]
        );
        let bob_session = f.sign_in(&t.bob).await;
        fails_with(
            billing!(
                f,
                team_spend,
                &bob_session,
                json!({ "tenantId": f.tenant_id, "teamId": platform["id"] })
            ),
            "ACCESS_DENIED",
        );
        // Maintaining a team reads it only in the team's own tenant (or below), not from the platform's.
        fails_with(
            billing!(
                f,
                team_spend,
                &alice_session,
                json!({ "tenantId": t.root, "teamId": platform["id"] })
            ),
            "ACCESS_DENIED",
        );
        // Department spend rolls up people in the department; the head reads it.
        let carol_session = f.sign_in(&t.carol).await;
        let department = ok(billing!(
            f,
            department_spend,
            &carol_session,
            json!({ "tenantId": f.tenant_id, "departmentId": engineering["id"], "groupBy": "department" })
        ));
        assert_matches(
            &department["rows"],
            json!([{ "key": engineering["id"], "label": "Engineering (ENG)", "amount": 32 }]),
        );
        let reads = api!(
            f,
            audit,
            list,
            owner,
            json!({ "tenantId": f.tenant_id, "action": "iam:billing:read" })
        );
        let reads = reads.as_array().cloned().unwrap_or_default();
        // Reads through a role are audited with it; bob's refused attempt is audited as a denial.
        let mut via: Vec<String> = reads
            .iter()
            .filter_map(|event| event["metadata"]["via"].as_str().map(str::to_owned))
            .collect();
        via.sort();
        assert_eq!(via, vec!["department-head", "team-maintainer"]);
        // Alice's attempt against the platform tenant is recorded here too, in her own tenant, naming its target.
        let denials: Vec<&Value> = reads
            .iter()
            .filter(|event| event["outcome"] == json!("deny"))
            .collect();
        assert_eq!(
            denials
                .iter()
                .filter(|event| event["metadata"]["targetTenantId"].is_null())
                .count(),
            1
        );
        let targeted: Vec<Value> = denials
            .iter()
            .filter(|event| !event["metadata"]["targetTenantId"].is_null())
            .map(|event| (*event).clone())
            .collect();
        assert_matches(
            &Value::Array(targeted),
            json!([{ "metadata": { "targetTenantId": t.root } }]),
        );
    });
}

#[test]
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn alerts_on_budget_thresholds_once_and_enforces_spent_budgets() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let owner = &f.owner_credential;
        let platform = api!(
            f,
            teams,
            create,
            owner,
            json!({ "tenantId": f.tenant_id, "name": "Platform", "maintainerIds": [t.alice] })
        );
        api!(
            f,
            teams,
            add_member,
            owner,
            json!({ "tenantId": f.tenant_id, "teamId": platform["id"], "identityId": t.bob })
        );
        let budget = ok(billing!(
            f,
            create_budget,
            owner,
            json!({
                "tenantId": f.tenant_id,
                "name": "Platform monthly",
                "subjectType": "team",
                "subjectId": platform["id"],
                "amount": 20,
                "thresholds": [50, 100],
                "forecastAlerts": false,
                "notify": { "emails": ["finance@acme.test"] },
                "enforce": true,
            })
        ));
        assert_matches(
            &budget,
            json!({ "spentMicros": 0, "percent": 0, "exceeded": false, "subjectName": "Platform" }),
        );
        ok(t.record(&t.bob, 2500.0, json!({})).await); // 1500 billable: $15 (75%).
        let first_run = f.iam.billing.check_budgets(None).await.unwrap();
        assert_matches(
            &first_run["alerts"],
            json!([{ "budgetId": budget["budgetId"], "kind": "actual", "threshold": 50, "recipients": 3 }]),
        );
        assert_eq!(
            f.iam.billing.check_budgets(None).await.unwrap()["alerts"],
            json!([])
        );
        ok(t.record(&t.bob, 1000.0, json!({})).await); // $25 in total.
        let second_run = f.iam.billing.check_budgets(None).await.unwrap();
        assert_matches(&second_run["alerts"], json!([{ "threshold": 100 }]));
        t.dispatch().await;
        let alerts = t.mail("spend-alert");
        let mut to: Vec<String> = alerts.iter().map(|message| message.to.clone()).collect();
        to.sort();
        assert_eq!(
            to,
            vec![
                "alice@acme.test",
                "alice@acme.test",
                "finance@acme.test",
                "finance@acme.test",
                "owner@acme.test",
                "owner@acme.test"
            ]
        );
        let full = alerts
            .iter()
            .find(|message| message.payload.get("threshold") == Some(&json!("100")))
            .unwrap();
        assert_matches(
            &Value::Object(full.payload.clone()),
            json!({
                "spent": "$25.00",
                "amount": "$20.00",
                "budgetName": "Platform monthly",
                "subjectName": "Platform",
            }),
        );
        // The spent budget now refuses the team's usage when asked to enforce.
        let bob_session = f.sign_in(&t.bob).await;
        let verdict = ok(billing!(
            f,
            check,
            &bob_session,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_matches(
            &verdict,
            json!({ "allowed": false, "blockedBy": { "name": "Platform monthly" } }),
        );
        let refused = fails_with(
            t.record(&t.bob, 1.0, json!({ "enforceBudgets": true }))
                .await,
            "SPEND_LIMIT_REACHED",
        );
        assert_eq!(refused.status, 402);
        // People outside the team are not covered by its budget.
        ok(t.record(&t.carol, 1.0, json!({ "enforceBudgets": true }))
            .await);
        let listed = ok(billing!(
            f,
            list_budgets,
            owner,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_matches(
            &listed[0],
            json!({ "reached": [50, 100], "exceeded": true }),
        );
        fails_with(
            billing!(
                f,
                create_budget,
                owner,
                json!({ "tenantId": f.tenant_id, "name": "platform MONTHLY", "amount": 1 })
            ),
            "CONFLICT",
        );
    });
}

#[test]
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn closes_a_period_into_statements_with_credits_and_refuses_late_usage_until_voided() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let owner = &f.owner_credential;
        let last_month = shift(&utc_period(f.now()), -1);
        let at = t.previous_period_start() + 3_600_000.0;
        ok(t.record(&t.alice, 6000.0, json!({ "occurredAt": at }))
            .await);
        ok(billing!(
            f,
            set_profile,
            owner,
            json!({
                "tenantId": f.tenant_id,
                "companyName": "Acme Corporation",
                "billingEmails": ["ap@acme.test"],
                "purchaseOrder": "PO-7",
                "paymentTermsDays": 15,
            })
        ));
        let credit = ok(billing!(
            f,
            grant_credit,
            &f.root_credential,
            json!({ "tenantId": f.tenant_id, "amount": 20, "reason": "Launch promotion" })
        ));
        // Only root administrators grant credit or close periods.
        fails_with(
            billing!(
                f,
                grant_credit,
                owner,
                json!({ "tenantId": f.tenant_id, "amount": 5, "reason": "x" })
            ),
            "ACCESS_DENIED",
        );
        fails_with(
            billing!(f, close_period, owner, json!({ "tenantId": f.tenant_id })),
            "ACCESS_DENIED",
        );
        let draft = ok(billing!(
            f,
            preview_statement,
            owner,
            json!({ "tenantId": f.tenant_id, "period": last_month })
        ));
        assert_matches(
            &draft,
            json!({ "subtotalMicros": 50_000_000, "creditsMicros": 20_000_000, "totalMicros": 30_000_000 }),
        );
        let closed = ok(billing!(
            f,
            close_period,
            &f.root_credential,
            json!({ "tenantId": t.root })
        ));
        assert_matches(
            &closed,
            json!({ "period": last_month, "skipped": { "existing": 0, "empty": 0 } }),
        );
        assert_matches(
            &closed["issued"],
            json!([{ "accountId": f.tenant_id, "totalMicros": 30_000_000, "recipients": 1 }]),
        );
        let number = format!("INV-{}-0001", last_month.replace('-', ""));
        assert_eq!(closed["issued"][0]["number"], json!(number));
        // Idempotent: a second run skips the invoiced account.
        let again = f.iam.billing.close_period(None).await.unwrap();
        assert_eq!(again.skipped["existing"], json!(1));
        t.dispatch().await;
        let mailed = t.mail("billing-statement").remove(0);
        assert_eq!(mailed.to, "ap@acme.test");
        assert_matches(
            &Value::Object(mailed.payload.clone()),
            json!({ "total": "$30.00", "period": last_month }),
        );
        let statements = ok(billing!(
            f,
            list_statements,
            owner,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_matches(
            &statements,
            json!([{ "status": "finalized", "total": 30, "overdue": false, "tenantName": "Acme" }]),
        );
        let statement = ok(billing!(
            f,
            get_statement,
            owner,
            json!({ "tenantId": f.tenant_id, "statementId": statements[0]["id"] })
        ));
        assert_matches(
            &statement,
            json!({
                "verified": true,
                "lines": [{ "meter": "api-calls", "quantity": 6000, "amountMicros": 50_000_000 }],
                "billTo": { "companyName": "Acme Corporation", "purchaseOrder": "PO-7", "emails": ["ap@acme.test"] },
                "breakdown": { "identities": [{ "id": t.alice, "costMicros": 50_000_000 }] },
            }),
        );
        assert_eq!(
            statement["dueAt"].as_f64().unwrap() - statement["issuedAt"].as_f64().unwrap(),
            15.0 * DAY
        );
        let sheet = ok(billing!(
            f,
            export_statement,
            owner,
            json!({ "tenantId": f.tenant_id, "statementId": statement["id"] })
        ));
        assert_eq!(
            sheet["filename"],
            json!(format!("{}.csv", s(&statement["number"])))
        );
        let text = s(&sheet["body"]);
        assert!(text.contains("line,api-calls,API calls,6000,request,50.000000,\r\n"));
        assert!(text.contains("credit,,,,,-20.000000,\r\n"));
        assert!(text.contains(&format!("identity,{},alice,,,50.000000,\r\n", t.alice)));
        let credits = ok(billing!(
            f,
            list_credits,
            owner,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_matches(
            &credits,
            json!({ "balanceMicros": 0, "credits": [{ "id": credit["id"], "remainingMicros": 0 }] }),
        );
        // The invoiced period is closed to late usage.
        let late = t.previous_period_start() + 7_200_000.0;
        fails_with(
            t.record(&t.alice, 1.0, json!({ "occurredAt": late })).await,
            "BILLING_PERIOD_CLOSED",
        );
        // Voiding restores the credit and reopens the period; closing again issues a new number.
        ok(billing!(
            f,
            void_statement,
            &f.root_credential,
            json!({ "tenantId": f.tenant_id, "statementId": statement["id"], "reason": "Usage correction" })
        ));
        assert_eq!(
            ok(billing!(
                f,
                list_credits,
                owner,
                json!({ "tenantId": f.tenant_id })
            ))["balanceMicros"],
            json!(20_000_000)
        );
        ok(t.record(&t.alice, 1000.0, json!({ "occurredAt": late }))
            .await);
        let reissued = f
            .iam
            .billing
            .close_period(Some(&json!({ "period": last_month })))
            .await
            .unwrap();
        let reissued = serde_json::to_value(reissued).unwrap();
        assert_matches(
            &reissued["issued"],
            json!([{ "number": format!("INV-{}-0002", last_month.replace('-', "")), "totalMicros": 40_000_000 }]),
        );
        let paid = ok(billing!(
            f,
            mark_paid,
            &f.root_credential,
            json!({
                "tenantId": f.tenant_id,
                "statementId": reissued["issued"][0]["statementId"],
                "reference": "wire-2231",
            })
        ));
        assert_matches(&paid, json!({ "status": "paid" }));
        fails_with(
            billing!(
                f,
                close_period,
                &f.root_credential,
                json!({ "tenantId": t.root, "period": utc_period(f.now()) })
            ),
            "INVALID_INPUT",
        );
    });
}

#[test]
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn keeps_organization_chargeback_meters_off_statements_and_bills_projects_with_their_own_profile() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let owner = &f.owner_credential;
        let (apollo, apollo_credential) = project(f, "Apollo").await;
        // An internal meter Acme defines for its own chargeback, with costs reported per event.
        ok(billing!(
            f,
            create_meter,
            owner,
            json!({
                "tenantId": f.tenant_id,
                "key": "cloud-compute",
                "name": "Cloud compute",
                "unit": "vCPU-hour",
                "pricing": "reported",
            })
        ));
        let last_month = shift(&utc_period(f.now()), -1);
        let at = t.previous_period_start() + 3_600_000.0;
        ok(billing!(
            f,
            record,
            owner,
            json!({
                "tenantId": f.tenant_id,
                "meter": "cloud-compute",
                "quantity": 12,
                "cost": 7.5,
                "identityId": t.alice,
                "occurredAt": at,
            })
        ));
        fails_with(
            billing!(
                f,
                record,
                owner,
                json!({ "tenantId": f.tenant_id, "meter": "cloud-compute", "quantity": 1 })
            ),
            "INVALID_INPUT",
        );
        ok(t.record(&t.alice, 2000.0, json!({ "occurredAt": at }))
            .await);
        // The project becomes its own billing account: its owner alone may not decide that, the organization does.
        fails_with(
            billing!(
                f,
                set_profile,
                &apollo_credential,
                json!({ "tenantId": apollo, "companyName": "Apollo" })
            ),
            "ACCESS_DENIED",
        );
        assert_matches(
            &ok(billing!(
                f,
                get_profile,
                &apollo_credential,
                json!({ "tenantId": apollo })
            )),
            json!({ "account": { "id": f.tenant_id, "inherited": true }, "profile": null }),
        );
        ok(billing!(
            f,
            set_profile,
            owner,
            json!({ "tenantId": f.tenant_id, "targetTenantId": apollo, "companyName": "Apollo Ltd" })
        ));
        // From then on the project's own billing managers keep it up to date.
        let updated = ok(billing!(
            f,
            set_profile,
            &apollo_credential,
            json!({ "tenantId": apollo, "billingEmails": ["billing@apollo.test"] })
        ));
        assert_matches(
            &updated,
            json!({
                "account": { "id": apollo, "inherited": false },
                "profile": { "companyName": "Apollo Ltd", "billingEmails": ["billing@apollo.test"] },
            }),
        );
        ok(billing!(
            f,
            record,
            &apollo_credential,
            json!({ "tenantId": apollo, "meter": "api-calls", "quantity": 1500, "occurredAt": at })
        ));
        let spend = ok(billing!(
            f,
            spend,
            owner,
            json!({ "tenantId": f.tenant_id, "period": last_month, "groupBy": "meter" })
        ));
        assert_matches(
            &spend["rows"],
            json!([{ "key": "api-calls", "amount": 15 }, { "key": "cloud-compute", "amount": 7.5 }]),
        );
        // The platform's view of what it bills leaves Acme's chargeback meter out.
        let platform = ok(billing!(
            f,
            spend,
            &f.root_credential,
            json!({ "tenantId": t.root, "period": last_month, "billableOnly": true })
        ));
        assert_eq!(
            rows(&platform)
                .iter()
                .map(|row| s(&row["key"]))
                .collect::<Vec<_>>(),
            vec!["api-calls".to_owned()]
        );
        let closed = serde_json::to_value(f.iam.billing.close_period(None).await.unwrap()).unwrap();
        let by_account: serde_json::Map<String, Value> = closed["issued"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| (s(&entry["accountId"]), entry["totalMicros"].clone()))
            .collect();
        // Each account gets its own 1000 free calls; the chargeback meter never reaches a statement.
        assert_eq!(
            Value::Object(by_account),
            json!({ f.tenant_id.clone(): 10_000_000, apollo.clone(): 5_000_000 })
        );
        let all = ok(billing!(
            f,
            list_statements,
            &f.root_credential,
            json!({ "tenantId": t.root })
        ));
        assert_eq!(all.as_array().unwrap().len(), 2);
        let acme_statement = all
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["tenantId"] == json!(f.tenant_id))
            .unwrap()
            .clone();
        let acme = ok(billing!(
            f,
            get_statement,
            owner,
            json!({ "tenantId": f.tenant_id, "statementId": acme_statement["id"] })
        ));
        assert_eq!(
            acme["lines"]
                .as_array()
                .unwrap()
                .iter()
                .map(|line| s(&line["meter"]))
                .collect::<Vec<_>>(),
            vec!["api-calls".to_owned()]
        );
    });
}

#[test]
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn records_seats_daily_for_every_active_person_and_bills_active_users() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        ok(billing!(
            f,
            create_meter,
            &f.root_credential,
            json!({
                "tenantId": t.root,
                "key": "seats",
                "name": "Active seats",
                "unit": "seat",
                "aggregation": "unique",
            })
        ));
        ok(billing!(
            f,
            set_price,
            &f.root_credential,
            json!({ "tenantId": t.root, "meter": "seats", "price": { "model": "per-unit", "unitAmount": 12 } })
        ));
        let first = f.iam.billing.record_seats(None).await.unwrap();
        // The owner, alice, bob and carol.
        assert_matches(
            &first,
            json!({ "meter": "seats", "recorded": 4, "duplicates": 0 }),
        );
        assert_matches(
            &f.iam.billing.record_seats(None).await.unwrap(),
            json!({ "recorded": 0, "duplicates": 4 }),
        );
        let spend = serde_json::to_value(
            f.iam
                .billing
                .spend(&json!({ "tenantId": f.tenant_id, "groupBy": "meter" }))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_matches(
            &spend["rows"],
            json!([{ "key": "seats", "costMicros": 48_000_000 }]),
        );
        let per_person = serde_json::to_value(
            f.iam
                .billing
                .spend(&json!({ "tenantId": f.tenant_id, "groupBy": "identity" }))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            rows(&per_person)
                .iter()
                .all(|row| row["costMicros"] == json!(12_000_000))
        );
    });
}

#[test]
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn finds_spend_spikes_alerts_on_them_once_and_exports_csv() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let owner = &f.owner_credential;
        ok(billing!(
            f,
            create_meter,
            &f.root_credential,
            json!({ "tenantId": t.root, "key": "builds", "name": "CI builds", "unit": "build" })
        ));
        ok(billing!(
            f,
            set_price,
            &f.root_credential,
            json!({
                "tenantId": t.root,
                "meter": "builds",
                "effectiveFrom": shift(&utc_period(f.now()), -1),
                "price": { "model": "per-unit", "unitAmount": 1 },
            })
        ));
        let noon_days_ago = |days: f64| (f.now() / DAY).floor() * DAY - days * DAY + 43_200_000.0;
        for days_ago in 2..=15 {
            for (identity, quantity) in [(&t.bob, 2), (&t.alice, 1)] {
                f.iam
                    .billing
                    .record(&json!({
                        "tenantId": f.tenant_id,
                        "meter": "builds",
                        "quantity": quantity,
                        "identityId": identity,
                        "occurredAt": noon_days_ago(days_ago as f64),
                    }))
                    .await
                    .unwrap();
            }
        }
        for (identity, quantity) in [(&t.bob, 40), (&t.alice, 1)] {
            f.iam
                .billing
                .record(&json!({
                    "tenantId": f.tenant_id,
                    "meter": "builds",
                    "quantity": quantity,
                    "identityId": identity,
                    "occurredAt": noon_days_ago(1.0),
                }))
                .await
                .unwrap();
        }
        let found = ok(billing!(
            f,
            anomalies,
            owner,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_matches(
            &found["anomalies"],
            json!([
                { "dimension": "meter", "key": "builds", "label": "CI builds", "costMicros": 41_000_000, "baselineMicros": 3_000_000 },
                { "dimension": "identity", "key": t.bob, "label": "bob", "costMicros": 40_000_000, "baselineMicros": 2_000_000, "factor": 20 },
            ]),
        );
        // A higher bar reports nothing.
        assert_eq!(
            ok(billing!(
                f,
                anomalies,
                owner,
                json!({ "tenantId": f.tenant_id, "factor": 50 })
            ))["anomalies"],
            json!([])
        );
        fails_with(
            billing!(
                f,
                anomalies,
                owner,
                json!({ "tenantId": f.tenant_id, "factor": 1 })
            ),
            "INVALID_INPUT",
        );
        // The daily job alerts once per spike.
        let first = f.iam.billing.detect_anomalies(None).await.unwrap();
        assert_matches(
            &first["anomalies"],
            json!([
                { "dimension": "meter", "accountId": f.tenant_id },
                { "dimension": "identity", "accountId": f.tenant_id },
            ]),
        );
        assert_eq!(
            f.iam.billing.detect_anomalies(None).await.unwrap()["anomalies"],
            json!([])
        );
        t.dispatch().await;
        let mail = t.mail("spend-anomaly").remove(0);
        assert_eq!(mail.to, "owner@acme.test");
        assert_eq!(mail.payload.get("count"), Some(&json!("2")));
        let audited = api!(
            f,
            audit,
            list,
            owner,
            json!({ "tenantId": f.tenant_id, "action": "billing:anomaly" })
        );
        assert_eq!(audited.as_array().unwrap().len(), 2);
        // CSV of a spend report, guarded against spreadsheet formulas.
        api!(
            f,
            identities,
            update,
            owner,
            json!({ "tenantId": f.tenant_id, "identityId": t.alice, "name": "=HYPERLINK(\"x\")" })
        );
        let exported = ok(billing!(
            f,
            export_spend,
            owner,
            json!({ "tenantId": f.tenant_id, "groupBy": "identity" })
        ));
        assert_eq!(exported["contentType"], json!("text/csv; charset=utf-8"));
        let filename = s(&exported["filename"]);
        assert!(filename.starts_with("spend-") && filename.ends_with("-identity.csv"));
        let body = s(&exported["body"]);
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
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn spreads_unattributed_spend_over_teams_when_asked() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let owner = &f.owner_credential;
        let platform = api!(
            f,
            teams,
            create,
            owner,
            json!({ "tenantId": f.tenant_id, "name": "Platform", "maintainerIds": [t.alice] })
        );
        let web = api!(
            f,
            teams,
            create,
            owner,
            json!({ "tenantId": f.tenant_id, "name": "Web" })
        );
        api!(
            f,
            teams,
            add_member,
            owner,
            json!({ "tenantId": f.tenant_id, "teamId": web["id"], "identityId": t.bob })
        );
        ok(t.record(&t.alice, 3000.0, json!({})).await);
        ok(t.record(&t.bob, 1000.0, json!({})).await);
        // Shared usage nobody on a team caused: 1000 calls.
        f.iam
            .billing
            .record(&json!({ "tenantId": f.tenant_id, "meter": "api-calls", "quantity": 1000 }))
            .await
            .unwrap();
        let shared = ok(billing!(
            f,
            spend,
            owner,
            json!({ "tenantId": f.tenant_id, "groupBy": "team", "shareUnattributed": true })
        ));
        assert_eq!(shared["sharedMicros"], json!(8_000_000));
        assert_matches(
            &shared["rows"],
            json!([
                { "key": platform["id"], "amount": 30, "sharedMicros": 6_000_000 },
                { "key": web["id"], "amount": 10, "sharedMicros": 2_000_000 },
            ]),
        );
        let total: f64 = rows(&shared)
            .iter()
            .map(|row| row["costMicros"].as_f64().unwrap())
            .sum();
        assert_eq!(
            json!(total),
            json!(shared["total"]["costMicros"].as_f64().unwrap())
        );
    });
}

#[test]
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn lets_policies_refuse_actions_once_an_enforced_budget_covering_the_person_is_spent() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let owner = &f.owner_credential;
        let role = api!(
            f,
            roles,
            create,
            owner,
            json!({
                "tenantId": f.tenant_id,
                "name": "Writers within budget",
                "document": {
                    "version": 1,
                    "statements": [
                        { "effect": "allow", "actions": ["documents:write"], "resources": ["*"] },
                        {
                            "effect": "deny",
                            "actions": ["documents:write"],
                            "resources": ["*"],
                            "conditions": { "Bool": { "principal.spendExceeded": true } },
                        },
                    ],
                },
            })
        );
        for person in [&t.bob, &t.alice] {
            api!(
                f,
                bindings,
                create,
                owner,
                json!({ "tenantId": f.tenant_id, "roleId": role["id"], "subjectType": "identity", "subjectId": person })
            );
        }
        ok(billing!(
            f,
            create_budget,
            owner,
            json!({
                "tenantId": f.tenant_id,
                "name": "Bob monthly",
                "subjectType": "identity",
                "subjectId": t.bob,
                "amount": 5,
                "enforce": true,
            })
        ));
        let bob_session = f.sign_in(&t.bob).await;
        let alice_session = f.sign_in(&t.alice).await;
        let write = |credential: CredentialInput| {
            let tenant_id = f.tenant_id.clone();
            async move {
                f.iam
                    .authorize(&better_iam_server::options::AuthorizationRequest {
                        credential,
                        tenant_id,
                        action: "documents:write".into(),
                        resource: better_iam_server::options::ResourceTarget {
                            kind: "document".into(),
                            id: "plan".into(),
                        },
                    })
                    .await
                    .unwrap()
                    .allowed
            }
        };
        assert!(write(bob_session.clone()).await);
        // 1500 calls, 1000 free: $5 spent, the whole budget.
        ok(t.record(&t.bob, 1500.0, json!({})).await);
        // Budget standings are cached for up to 30 seconds.
        f.advance(31_000.0);
        assert!(!write(bob_session).await);
        assert!(write(alice_session).await);
    });
}

#[test]
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn applies_a_discount_a_minimum_commitment_credit_and_tax_to_statements() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let owner = &f.owner_credential;
        let at = t.previous_period_start() + 3_600_000.0;
        // 6000 calls, 1000 free: $50 of usage.
        ok(t.record(&t.alice, 6000.0, json!({ "occurredAt": at }))
            .await);
        fails_with(
            billing!(
                f,
                set_terms,
                owner,
                json!({ "tenantId": f.tenant_id, "discountPercent": 90 })
            ),
            "ACCESS_DENIED",
        );
        let terms = ok(billing!(
            f,
            set_terms,
            &f.root_credential,
            json!({
                "tenantId": f.tenant_id,
                "discountPercent": 10,
                "minimumCommitment": 100,
                "taxRatePercent": 20,
                "taxLabel": "VAT",
            })
        ));
        assert_matches(
            &terms,
            json!({ "discountPercent": 10, "minimumCommitment": 100, "taxLabel": "VAT" }),
        );
        assert_matches(
            &ok(billing!(
                f,
                get_terms,
                owner,
                json!({ "tenantId": f.tenant_id })
            )),
            json!({ "inherited": false, "taxRatePercent": 20 }),
        );
        ok(billing!(
            f,
            grant_credit,
            &f.root_credential,
            json!({ "tenantId": f.tenant_id, "amount": 20, "reason": "Goodwill" })
        ));
        // $50 − 10% = $45; the $100 commitment adds $55; $20 credit leaves $80; 20% VAT: $96.
        let closed = ok(billing!(
            f,
            close_period,
            &f.root_credential,
            json!({ "tenantId": t.root })
        ));
        assert_matches(&closed["issued"], json!([{ "totalMicros": 96_000_000 }]));
        let statement = ok(billing!(
            f,
            get_statement,
            owner,
            json!({ "tenantId": f.tenant_id, "statementId": closed["issued"][0]["statementId"] })
        ));
        assert_matches(
            &statement,
            json!({
                "verified": true,
                "subtotalMicros": 50_000_000,
                "discount": { "percent": 10, "amountMicros": 5_000_000 },
                "commitment": { "minimumMicros": 100_000_000, "trueUpMicros": 55_000_000 },
                "creditsMicros": 20_000_000,
                "tax": { "label": "VAT", "ratePercent": 20, "amountMicros": 16_000_000 },
                "totalMicros": 96_000_000,
            }),
        );
        let sheet = ok(billing!(
            f,
            export_statement,
            owner,
            json!({ "tenantId": f.tenant_id, "statementId": statement["id"] })
        ));
        let text = s(&sheet["body"]);
        assert!(text.contains("discount,,10%,,,-5.000000,"));
        assert!(text.contains("commitment,,minimum commitment true-up,,,55.000000,"));
        assert!(text.contains("tax,,VAT 20%,,,16.000000,"));
        // Clearing terms returns to plain statements for later months.
        let cleared = ok(billing!(
            f,
            set_terms,
            &f.root_credential,
            json!({
                "tenantId": f.tenant_id,
                "discountPercent": null,
                "minimumCommitment": null,
                "taxRatePercent": null,
                "taxLabel": null,
            })
        ));
        let keys: Vec<&String> = cleared.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["accountId", "inherited", "setAt", "setBy"]);
        assert_eq!(cleared["accountId"], json!(f.tenant_id));
        assert_eq!(cleared["inherited"], json!(false));
        fails_with(
            billing!(
                f,
                set_terms,
                &f.root_credential,
                json!({ "tenantId": f.tenant_id, "taxRatePercent": 120 })
            ),
            "INVALID_INPUT",
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// tests/security-billing.test.ts: the API guards

/// security-billing's `setup`: Acme with a platform `api-calls` meter at $1 a call from last month on.
async fn per_call_setup() -> (Org, String) {
    let f = organization(|_| {}).await;
    let root = f.root_tenant.clone();
    ok(billing!(
        f,
        create_meter,
        &f.root_credential,
        json!({ "tenantId": root, "key": "api-calls", "name": "API calls" })
    ));
    ok(billing!(
        f,
        set_price,
        &f.root_credential,
        json!({
            "tenantId": root,
            "meter": "api-calls",
            "effectiveFrom": shift(&utc_period(f.now()), -1),
            "price": { "model": "per-unit", "unitAmount": 1 },
        })
    ));
    (f, root)
}

#[test]
#[ignore = "needs billing.ts (meterKey, from the billing unit) and billing-service.ts builtInMeterKey"]
fn reserves_built_in_meter_keys_for_the_platform() {
    run(|| async {
        let (f, _) = per_call_setup().await;
        let refused = fails_with(
            billing!(
                f,
                create_meter,
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id, "key": "inference", "name": "Mine", "pricing": "reported" })
            ),
            "CONFLICT",
        );
        assert_eq!(refused.message, "inference is a built-in platform meter");
    });
}

#[test]
#[ignore = "needs billing.ts and billing-service.ts (other units)"]
fn lets_team_maintainers_read_team_spend_only_from_their_own_sign_in_session() {
    run(|| async {
        let (f, _) = per_call_setup().await;
        let owner = &f.owner_credential;
        let alice = f.member("alice").await;
        let team = api!(
            f,
            teams,
            create,
            owner,
            json!({ "tenantId": f.tenant_id, "name": "Platform", "maintainerIds": [alice] })
        );
        ok(billing!(
            f,
            record,
            owner,
            json!({ "tenantId": f.tenant_id, "meter": "api-calls", "quantity": 10, "identityId": alice })
        ));
        let alice_session = f.sign_in(&alice).await;
        let own = ok(billing!(
            f,
            team_spend,
            &alice_session,
            json!({ "tenantId": f.tenant_id, "teamId": team["id"] })
        ));
        assert_eq!(own["total"]["costMicros"], json!(10_000_000));
        // A session token derived from her session is not her acting in her own right.
        let minter = api!(
            f,
            roles,
            create,
            owner,
            json!({ "tenantId": f.tenant_id, "name": "Token minter", "permissions": ["iam:session-tokens:create"] })
        );
        api!(
            f,
            bindings,
            create,
            owner,
            json!({ "tenantId": f.tenant_id, "roleId": minter["id"], "subjectType": "identity", "subjectId": alice })
        );
        let derived = api!(f, sts, get_session_token, &alice_session, json!({}));
        let derived = CredentialInput {
            headers: None,
            token: derived["token"].as_str().map(str::to_owned),
        };
        fails_with(
            billing!(
                f,
                team_spend,
                &derived,
                json!({ "tenantId": f.tenant_id, "teamId": team["id"] })
            ),
            "ACCESS_DENIED",
        );
    });
}

#[test]
#[ignore = "needs billing.ts (meterKey and accountOf, from the billing unit)"]
fn keeps_payment_terms_beyond_the_default_for_root_administrators() {
    run(|| async {
        let (f, _) = per_call_setup().await;
        let owner = &f.owner_credential;
        let refused = fails_with(
            billing!(
                f,
                set_profile,
                owner,
                json!({ "tenantId": f.tenant_id, "paymentTermsDays": 365 })
            ),
            "ACCESS_DENIED",
        );
        assert_eq!(
            refused.message,
            "Payment terms above 30 days are set by root administrators"
        );
        let shorter = ok(billing!(
            f,
            set_profile,
            owner,
            json!({ "tenantId": f.tenant_id, "paymentTermsDays": 15 })
        ));
        assert_eq!(shorter["profile"]["paymentTermsDays"], json!(15));
        ok(billing!(
            f,
            set_profile,
            &f.root_credential,
            json!({ "tenantId": f.tenant_id, "paymentTermsDays": 60 })
        ));
        // Saving the profile again keeps what the platform granted; asking for more is refused.
        let resaved = ok(billing!(
            f,
            set_profile,
            owner,
            json!({ "tenantId": f.tenant_id, "companyName": "Acme Corporation", "paymentTermsDays": 60 })
        ));
        assert_eq!(resaved["profile"]["paymentTermsDays"], json!(60));
        fails_with(
            billing!(
                f,
                set_profile,
                owner,
                json!({ "tenantId": f.tenant_id, "paymentTermsDays": 90 })
            ),
            "ACCESS_DENIED",
        );
    });
}

#[test]
#[ignore = "needs billing.ts, billing-invoices.ts and billing-service.ts (other units)"]
fn neutralizes_formulas_in_csv_exports_but_keeps_plain_negative_numbers() {
    run(|| async {
        let (f, _) = per_call_setup().await;
        ok(billing!(
            f,
            create_invoice_item,
            &f.root_credential,
            json!({ "tenantId": f.tenant_id, "description": "-1+cmd|' /C calc'!A0", "amount": 5 })
        ));
        ok(billing!(
            f,
            create_invoice_item,
            &f.root_credential,
            json!({ "tenantId": f.tenant_id, "description": "Service credit", "amount": -2 })
        ));
        let closed = serde_json::to_value(f.iam.billing.close_period(None).await.unwrap()).unwrap();
        let sheet = ok(billing!(
            f,
            export_statement,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "statementId": closed["issued"][0]["statementId"] })
        ));
        let text = s(&sheet["body"]);
        assert!(text.contains(",'-1+cmd|' /C calc'!A0,"));
        assert!(!text.contains(",-1+cmd"));
        assert!(text.contains(",-2.000000,"));
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// tests/billing-invoicing.test.ts and the coupon, plan and credit-note guards of the group

#[test]
#[ignore = "needs billing.ts, billing-invoices.ts and billing-service.ts (other units)"]
fn drafts_invoices_with_items_finalizes_them_and_takes_payments_and_credit_notes() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let root = &f.root_credential;
        let at = t.previous_period_start() + 3_600_000.0;
        ok(t.record(&t.alice, 3000.0, json!({ "occurredAt": at }))
            .await);
        let last_month = shift(&utc_period(f.now()), -1);
        // A one-off charge on the next invoice.
        let item = ok(billing!(
            f,
            create_invoice_item,
            root,
            json!({ "tenantId": f.tenant_id, "description": "Onboarding", "amount": 250 })
        ));
        assert_matches(
            &item,
            json!({ "accountId": f.tenant_id, "description": "Onboarding", "amountMicros": 250_000_000, "status": "pending", "source": "manual" }),
        );
        let closed = ok(billing!(
            f,
            close_period,
            root,
            json!({ "tenantId": t.root, "draft": true })
        ));
        assert_eq!(closed["period"], json!(last_month));
        let draft_id = closed["drafted"][0]["statementId"].clone();
        let finalized = ok(billing!(
            f,
            finalize_invoice,
            root,
            json!({ "tenantId": f.tenant_id, "statementId": draft_id })
        ));
        assert_matches(&finalized, json!({ "status": "finalized" }));
        // A partial payment leaves the rest due.
        let paid = ok(billing!(
            f,
            record_payment,
            root,
            json!({ "tenantId": f.tenant_id, "statementId": draft_id, "amount": 100, "method": "bank_transfer" })
        ));
        assert_matches(
            &paid,
            json!({ "statement": { "status": "finalized" }, "payment": { "amountMicros": 100_000_000, "method": "bank_transfer" } }),
        );
        // A credit note reduces what is still due.
        let note = ok(billing!(
            f,
            create_credit_note,
            root,
            json!({ "tenantId": f.tenant_id, "statementId": draft_id, "amount": 20, "reason": "order_change" })
        ));
        assert_matches(
            &note,
            json!({ "creditNote": { "amountMicros": 20_000_000, "reason": "order_change" } }),
        );
        let notes = ok(billing!(
            f,
            list_credit_notes,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_eq!(notes.as_array().unwrap().len(), 1);
        let page = ok(billing!(
            f,
            render_invoice,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "statementId": draft_id })
        ));
        assert_eq!(page["contentType"], json!("text/html; charset=utf-8"));
        // Payment processors record payments through the runtime, idempotently.
        let processor = f
            .iam
            .billing
            .record_payment(&json!({ "statementId": draft_id, "idempotencyKey": "pi_1" }))
            .await
            .unwrap();
        assert_eq!(processor["duplicate"], json!(false));
        let redelivered = f
            .iam
            .billing
            .record_payment(&json!({ "statementId": draft_id, "idempotencyKey": "pi_1" }))
            .await
            .unwrap();
        assert_eq!(redelivered["duplicate"], json!(true));
        // Invoiced items cannot be deleted.
        fails_with(
            billing!(
                f,
                delete_invoice_item,
                root,
                json!({ "tenantId": f.tenant_id, "itemId": item["id"] })
            ),
            "INVALID_TRANSITION",
        );
    });
}

#[test]
#[ignore = "needs billing.ts, billing-invoices.ts and billing-service.ts (other units)"]
fn coupons_are_redeemed_once_per_account_and_unknown_codes_look_alike() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let root = &f.root_credential;
        let coupon = ok(billing!(
            f,
            create_coupon,
            root,
            json!({ "tenantId": t.root, "code": "launch", "percentOff": 20, "duration": "once" })
        ));
        assert_matches(
            &coupon,
            json!({ "code": "LAUNCH", "percentOff": 20, "redemptions": 0, "active": true }),
        );
        fails_with(
            billing!(
                f,
                create_coupon,
                root,
                json!({ "tenantId": t.root, "code": "LAUNCH", "percentOff": 10 })
            ),
            "CONFLICT",
        );
        let discount = ok(billing!(
            f,
            redeem_coupon,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "code": "launch" })
        ));
        assert_matches(
            &discount,
            json!({ "accountId": f.tenant_id, "code": "LAUNCH", "appliedInvoices": 0, "active": true }),
        );
        fails_with(
            billing!(
                f,
                redeem_coupon,
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id, "code": "launch" })
            ),
            "CONFLICT",
        );
        let unknown = fails_with(
            billing!(
                f,
                redeem_coupon,
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id, "code": "nothing" })
            ),
            "NOT_FOUND",
        );
        assert_eq!(unknown.message, "This code is not valid");
        let deactivated = ok(billing!(
            f,
            deactivate_coupon,
            root,
            json!({ "tenantId": t.root, "code": "launch" })
        ));
        assert_matches(&deactivated, json!({ "active": false, "redemptions": 1 }));
        let removed = ok(billing!(
            f,
            remove_discount,
            root,
            json!({ "tenantId": f.tenant_id, "discountId": discount["id"] })
        ));
        assert!(removed["endedAt"].is_number());
        fails_with(
            billing!(
                f,
                remove_discount,
                root,
                json!({ "tenantId": f.tenant_id, "discountId": discount["id"] })
            ),
            "INVALID_TRANSITION",
        );
    });
}

#[test]
#[ignore = "needs billing.ts, billing-plans.ts and billing-service.ts (other units)"]
fn plans_are_subscribed_by_account_billing_managers_only_when_self_serve() {
    run(|| async {
        let t = setup().await;
        let f = &t.f;
        let root = &f.root_credential;
        let owner = &f.owner_credential;
        let team = ok(billing!(
            f,
            create_plan,
            root,
            json!({
                "tenantId": t.root,
                "key": "team",
                "name": "Team",
                "items": [{ "id": "base", "kind": "fee", "name": "Base fee", "amount": 49 }],
                "selfServe": true,
            })
        ));
        assert_matches(
            &team,
            json!({ "key": "team", "selfServe": true, "subscribers": 0 }),
        );
        ok(billing!(
            f,
            create_plan,
            root,
            json!({
                "tenantId": t.root,
                "key": "enterprise",
                "name": "Enterprise",
                "items": [{ "id": "base", "kind": "fee", "name": "Base fee", "amount": 999 }],
            })
        ));
        fails_with(
            billing!(
                f,
                create_plan,
                root,
                json!({ "tenantId": t.root, "key": "team", "name": "Again", "items": [] })
            ),
            "CONFLICT",
        );
        let refused = fails_with(
            billing!(
                f,
                subscribe,
                owner,
                json!({ "tenantId": f.tenant_id, "plan": "enterprise" })
            ),
            "ACCESS_DENIED",
        );
        assert_eq!(
            refused.message,
            "Only root administrators manage subscriptions to plans that are not self-serve"
        );
        fails_with(
            billing!(
                f,
                subscribe,
                owner,
                json!({ "tenantId": f.tenant_id, "plan": "team", "trialDays": 30 })
            ),
            "ACCESS_DENIED",
        );
        let subscribed = ok(billing!(
            f,
            subscribe,
            owner,
            json!({ "tenantId": f.tenant_id, "plan": "team", "seats": 3 })
        ));
        assert_matches(
            &subscribed,
            json!({ "subscription": { "accountId": f.tenant_id, "planKey": "team", "seats": 3, "accountName": "Acme" } }),
        );
        let subscription_id = subscribed["subscription"]["id"].clone();
        fails_with(
            billing!(
                f,
                cancel_subscription,
                owner,
                json!({ "tenantId": f.tenant_id, "subscriptionId": subscription_id, "atPeriodEnd": false })
            ),
            "ACCESS_DENIED",
        );
        fails_with(
            billing!(
                f,
                cancel_subscription,
                owner,
                json!({ "tenantId": f.tenant_id, "subscriptionId": subscription_id, "atPeriodEnd": "no" })
            ),
            "INVALID_INPUT",
        );
        let listed = ok(billing!(f, list_plans, root, json!({ "tenantId": t.root })));
        assert_eq!(
            listed
                .as_array()
                .unwrap()
                .iter()
                .map(|plan| s(&plan["key"]))
                .collect::<Vec<_>>(),
            vec!["enterprise".to_owned(), "team".to_owned()]
        );
        let updated = ok(billing!(
            f,
            update_plan,
            root,
            json!({ "tenantId": t.root, "plan": "enterprise", "archived": true })
        ));
        assert_matches(&updated, json!({ "archived": true }));
        let visible = ok(billing!(
            f,
            list_plans,
            owner,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_eq!(visible.as_array().unwrap().len(), 1);
    });
}
