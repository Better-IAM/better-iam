//! Port of the tests of `licenses.ts` and the `licenses` API group: tests/licenses.test.ts (products, pools and seats,
//! limits, settings and self-service), tests/licenses-access.test.ts (permissions and platform pools) and the job and
//! notification suites of tests/licenses-lifecycle.test.ts.
//!
//! The organization fixture writes tenants and people the way `tenants.create` and `identities.create` store them
//! (identities.create runs `afterIdentityChange`, another unit), and service accounts are written as
//! `serviceAccounts.create` stores them for the same reason. The lifecycle suites' birthright package (packages, another
//! unit) is left out of their scenario; what they check about seats, jobs and mail does not depend on it.

mod organization_fixture;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::{CredentialInput, Filter, IamResult, IamStoreExt, Record, js};
use organization_fixture::{Org, bearer, body, organization, run};
use serde_json::{Value, json};

const HOUR: f64 = 3_600_000.0;
const DAY: f64 = 24.0 * HOUR;

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

macro_rules! call {
    ($f:expr, $method:ident, $credential:expr, $input:expr) => {
        $f.iam
            .api
            .licenses
            .$method($credential, body($input))
            .await
            .and_then(|reply| reply.into_value())
    };
}

#[track_caller]
fn assert_same(actual: &Value, expected: Value) {
    assert!(
        js::deep_equal(actual, &expected),
        "\n  actual:   {}\n  expected: {}",
        js::stringify(actual),
        js::stringify(&expected)
    );
}

#[track_caller]
fn fails_with(result: IamResult<Value>, code: &str) -> better_iam_core::IamError {
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

/// The audit events of a tenant whose action starts with `prefix`, oldest first.
async fn trail(f: &Org, tenant_id: &str, prefix: &str) -> Vec<Record> {
    let mut events: Vec<Record> = f
        .find("audit", Filter::new().eq("tenantId", tenant_id))
        .await
        .into_iter()
        .filter(|event| {
            event["action"]
                .as_str()
                .is_some_and(|action| action.starts_with(prefix))
        })
        .collect();
    events.sort_by(|a, b| {
        let sequence =
            |event: &Record| event.get("sequence").and_then(Value::as_f64).unwrap_or(0.0);
        sequence(a).total_cmp(&sequence(b))
    });
    events
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

/// Acme with a product "pro" and three people. `assign` moves the fixture clock a second first, so seniority never
/// falls back to identity order.
struct Scenario {
    f: Org,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
    tenant_id: String,
    owner: CredentialInput,
    pro: Value,
    pro_id: String,
    alice: String,
    bob: String,
    carol: String,
    names: Mutex<HashMap<String, String>>,
}

async fn scenario() -> Scenario {
    let (f, inbox) = fixture().await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let pro = call!(
        f,
        create_product,
        &owner,
        json!({
            "tenantId": tenant_id,
            "key": "pro",
            "name": "Pro",
            "description": "Everything in Pro",
            "featureKeys": ["sso", "exports"],
        })
    )
    .expect("pro");
    let alice = f.member("alice").await;
    let bob = f.member("bob").await;
    let carol = f.member("carol").await;
    let names = Mutex::new(HashMap::from([
        (alice.clone(), "alice".to_owned()),
        (bob.clone(), "bob".to_owned()),
        (carol.clone(), "carol".to_owned()),
    ]));
    Scenario {
        pro_id: id_of(&pro),
        f,
        inbox,
        tenant_id,
        owner,
        pro,
        alice,
        bob,
        carol,
        names,
    }
}

impl Scenario {
    async fn person(&self, name: &str) -> String {
        let id = self.f.member(name).await;
        self.names
            .lock()
            .unwrap()
            .insert(id.clone(), name.to_owned());
        id
    }

    async fn assign(&self, identity_id: &str) -> IamResult<Value> {
        self.assign_to(identity_id, &self.pro_id.clone()).await
    }

    async fn assign_to(&self, identity_id: &str, product_id: &str) -> IamResult<Value> {
        self.f.advance(1000.0);
        call!(
            self.f,
            assign,
            &self.owner,
            json!({
                "tenantId": self.tenant_id,
                "productId": product_id,
                "subjectType": "identity",
                "subjectId": identity_id,
            })
        )
    }

    async fn seats(&self) -> Vec<String> {
        let listed = call!(
            self.f,
            list_seats,
            &self.owner,
            json!({ "tenantId": self.tenant_id, "productId": self.pro_id })
        )
        .expect("seats");
        listed["seats"]
            .as_array()
            .unwrap()
            .iter()
            .map(|seat| {
                let position = seat
                    .get("position")
                    .map(|position| format!(" #{position}"))
                    .unwrap_or_default();
                format!(
                    "{} {}{position}",
                    seat["identityName"].as_str().unwrap(),
                    seat["status"].as_str().unwrap()
                )
            })
            .collect()
    }

    fn changes(&self, list: &Value) -> Vec<String> {
        let names = self.names.lock().unwrap();
        list.as_array()
            .unwrap()
            .iter()
            .map(|change| {
                format!(
                    "{} {}->{}",
                    names
                        .get(change["identityId"].as_str().unwrap())
                        .cloned()
                        .unwrap_or_default(),
                    change["from"].as_str().unwrap(),
                    change["to"].as_str().unwrap()
                )
            })
            .collect()
    }

    fn sorted_changes(&self, list: &Value) -> Vec<String> {
        let mut changes = self.changes(list);
        changes.sort();
        changes
    }
}

fn sorted(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item[key].as_str().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn defines_validates_updates_and_lists_a_tenant_product() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        assert_same(
            &s.pro,
            json!({
                "id": s.pro_id,
                "key": "pro",
                "name": "Pro",
                "description": "Everything in Pro",
                "featureKeys": ["exports", "sso"],
                "status": "active",
                "scope": "tenant",
                "definedBy": tenant_id,
                "definedHere": true,
                "shadowed": false,
                "createdAt": f.now(),
                "createdBy": f.owner_id,
                "updatedAt": f.now(),
                "updatedBy": f.owner_id,
            }),
        );

        let create = |input: Value| {
            let mut full = json!({ "tenantId": tenant_id, "key": "team", "name": "Team" });
            for (key, value) in input.as_object().unwrap() {
                full[key] = value.clone();
            }
            full
        };
        for key in [
            json!("Pro"),
            json!("-pro"),
            json!("pro plan"),
            json!(""),
            json!("x".repeat(65)),
            json!("pro/plan"),
            json!(7),
        ] {
            fails_with(
                call!(f, create_product, owner, create(json!({ "key": key }))),
                "INVALID_INPUT",
            );
        }
        let many: Vec<String> = (0..51).map(|index| format!("feature-{index}")).collect();
        for input in [
            json!({ "name": " " }),
            json!({ "name": "x".repeat(101) }),
            json!({ "description": "x".repeat(513) }),
            json!({ "featureKeys": ["Bad Key"] }),
            json!({ "featureKeys": "sso" }),
            json!({ "featureKeys": many }),
        ] {
            fails_with(
                call!(f, create_product, owner, create(input)),
                "INVALID_INPUT",
            );
        }
        let conflict = fails_with(
            call!(f, create_product, owner, create(json!({ "key": "pro" }))),
            "CONFLICT",
        );
        assert_eq!(conflict.status, 409);
        let team = call!(
            f,
            create_product,
            owner,
            create(json!({ "key": "team.v2_b-1" }))
        )
        .unwrap();
        assert_matches(&team, json!({ "key": "team.v2_b-1", "featureKeys": [] }));
        assert!(team.get("description").is_none());

        // The key never changes; the name, description (null clears) and feature keys do.
        f.advance(1000.0);
        let renamed = call!(
            f,
            update_product,
            owner,
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "name": "Pro plan",
                "description": null,
                "featureKeys": ["sso", "sso", "audit-log"],
            })
        )
        .unwrap();
        assert_matches(
            &renamed,
            json!({
                "key": "pro",
                "name": "Pro plan",
                "featureKeys": ["audit-log", "sso"],
                "updatedAt": f.now(),
                "createdAt": s.pro["createdAt"],
            }),
        );
        assert!(renamed.get("description").is_none());
        let nothing = fails_with(
            call!(
                f,
                update_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": s.pro_id })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(nothing.message, "Nothing to update");
        fails_with(
            call!(
                f,
                update_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": "missing", "name": "x" })
            ),
            "NOT_FOUND",
        );
        fails_with(
            call!(
                f,
                update_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": s.pro_id, "featureKeys": ["Nope"] })
            ),
            "INVALID_INPUT",
        );
        assert_same(
            &call!(
                f,
                get_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": s.pro_id })
            )
            .unwrap(),
            renamed.clone(),
        );
        let missing = fails_with(
            call!(
                f,
                get_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": "missing" })
            ),
            "NOT_FOUND",
        );
        assert_eq!(missing.status, 404);

        let listed = call!(f, list_products, owner, json!({ "tenantId": tenant_id })).unwrap();
        assert_eq!(listed["tenantId"], json!(tenant_id));
        assert_eq!(
            strings(&listed["products"], "key"),
            vec!["pro", "team.v2_b-1"]
        );
        assert_same(
            &call!(
                f,
                list_products,
                owner,
                json!({ "tenantId": tenant_id, "status": "retired" })
            )
            .unwrap()["products"],
            json!([]),
        );
        fails_with(
            call!(
                f,
                list_products,
                owner,
                json!({ "tenantId": tenant_id, "status": "gone" })
            ),
            "INVALID_INPUT",
        );

        let events = trail(f, &tenant_id, "license:").await;
        assert_eq!(
            events
                .iter()
                .map(|event| event["action"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "license:product-create",
                "license:product-create",
                "license:product-update"
            ]
        );
        assert_matches(
            &Value::Object(events[0].clone()),
            json!({
                "actorId": f.owner_id,
                "resourceId": format!("licenses/products/{}", s.pro_id),
                "metadata": {
                    "productId": s.pro_id,
                    "key": "pro",
                    "name": "Pro",
                    "description": "Everything in Pro",
                    "featureKeys": ["exports", "sso"],
                    "status": "active",
                },
            }),
        );
        assert_matches(
            &events[2]["metadata"],
            json!({
                "before": { "name": "Pro", "description": "Everything in Pro" },
                "after": { "name": "Pro plan", "description": null, "featureKeys": ["audit-log", "sso"] },
            }),
        );
    });
}

#[test]
fn requires_recent_authentication_to_define_or_retire_a_product() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        f.advance(6.0 * 60_000.0);
        fails_with(
            call!(
                f,
                create_product,
                owner,
                json!({ "tenantId": tenant_id, "key": "team", "name": "Team" })
            ),
            "RECENT_AUTH_REQUIRED",
        );
        fails_with(
            call!(
                f,
                retire_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": s.pro_id })
            ),
            "RECENT_AUTH_REQUIRED",
        );
        // Renaming does not.
        assert_matches(
            &call!(
                f,
                update_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": s.pro_id, "name": "Pro 2" })
            )
            .unwrap(),
            json!({ "name": "Pro 2" }),
        );
        let fresh = f.session(&f.owner_id, false).await;
        assert_matches(
            &call!(
                f,
                create_product,
                &fresh,
                json!({ "tenantId": tenant_id, "key": "team", "name": "Team" })
            )
            .unwrap(),
            json!({ "key": "team" }),
        );
        assert_matches(
            &call!(
                f,
                retire_product,
                &fresh,
                json!({ "tenantId": tenant_id, "productId": s.pro_id })
            )
            .unwrap(),
            json!({ "product": { "status": "retired" } }),
        );
    });
}

#[test]
fn shows_platform_products_to_every_tenant_and_ancestors_products_to_their_subtree() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        let root_id = f.root_tenant.clone();
        let root = &f.root_credential;
        let suite = call!(
            f,
            create_product,
            root,
            json!({ "tenantId": root_id, "key": "suite", "name": "Suite", "featureKeys": ["suite"] })
        )
        .unwrap();
        assert_matches(
            &suite,
            json!({ "scope": "platform", "definedBy": root_id, "definedHere": true }),
        );
        let listed = call!(f, list_products, owner, json!({ "tenantId": tenant_id })).unwrap();
        let products = listed["products"].as_array().unwrap();
        assert_eq!(products.len(), 2);
        assert_matches(
            &products[0],
            json!({ "key": "pro", "scope": "tenant", "definedHere": true }),
        );
        assert_matches(
            &products[1],
            json!({
                "key": "suite",
                "scope": "platform",
                "definedBy": root_id,
                "definedHere": false,
                "shadowed": false,
            }),
        );
        assert_matches(
            &call!(
                f,
                get_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": id_of(&suite) })
            )
            .unwrap(),
            json!({ "key": "suite", "definedHere": false }),
        );
        // Only root administrators define and change platform products; tenants never repeat their keys.
        fails_with(
            call!(
                f,
                create_product,
                owner,
                json!({ "tenantId": root_id, "key": "mine", "name": "Mine" })
            ),
            "ACCESS_DENIED",
        );
        let taken = fails_with(
            call!(
                f,
                create_product,
                owner,
                json!({ "tenantId": tenant_id, "key": "suite", "name": "Suite copy" })
            ),
            "CONFLICT",
        );
        assert_eq!(
            taken.message,
            "A platform license product already uses this key"
        );
        fails_with(
            call!(
                f,
                update_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": id_of(&suite), "name": "Mine now" })
            ),
            "INVALID_INPUT",
        );
        fails_with(
            call!(
                f,
                retire_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": id_of(&suite) })
            ),
            "INVALID_INPUT",
        );
        fails_with(
            call!(
                f,
                update_product,
                owner,
                json!({ "tenantId": root_id, "productId": id_of(&suite), "name": "Mine now" })
            ),
            "ACCESS_DENIED",
        );

        // A project sees Acme's products and the platform's, and may not repeat an enclosing key.
        let (apollo_id, _, apollo) = f
            .activate(&tenant_id, "Apollo", "project", "apollo@acme.test")
            .await;
        let seen = call!(f, list_products, &apollo, json!({ "tenantId": apollo_id })).unwrap();
        assert_same(
            &Value::Array(
                seen["products"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|product| {
                        json!([
                            product["key"],
                            product["scope"],
                            product["definedBy"] == json!(tenant_id)
                        ])
                    })
                    .collect(),
            ),
            json!([["pro", "tenant", true], ["suite", "platform", false]]),
        );
        let enclosing = fails_with(
            call!(
                f,
                create_product,
                &apollo,
                json!({ "tenantId": apollo_id, "key": "pro", "name": "Pro copy" })
            ),
            "CONFLICT",
        );
        assert_eq!(
            enclosing.message,
            "An enclosing tenant already defines a license product with this key"
        );
        let addon = call!(
            f,
            create_product,
            &apollo,
            json!({ "tenantId": apollo_id, "key": "apollo-addon", "name": "Apollo add-on" })
        )
        .unwrap();
        assert_eq!(
            strings(
                &call!(f, list_products, owner, json!({ "tenantId": tenant_id })).unwrap()["products"],
                "key"
            ),
            vec!["pro", "suite"]
        );
        fails_with(
            call!(
                f,
                get_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": id_of(&addon) })
            ),
            "NOT_FOUND",
        );

        // The platform may later define a key a tenant already uses: the tenant's product is then shadowed.
        let platform_pro = call!(
            f,
            create_product,
            root,
            json!({ "tenantId": root_id, "key": "pro", "name": "Platform Pro" })
        )
        .unwrap();
        let listed = call!(f, list_products, owner, json!({ "tenantId": tenant_id })).unwrap();
        assert_same(
            &Value::Array(
                listed["products"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|product| json!([product["id"], product["shadowed"]]))
                    .collect(),
            ),
            json!([
                [id_of(&platform_pro), false],
                [s.pro_id, true],
                [id_of(&suite), false]
            ]),
        );
        assert_matches(
            &call!(
                f,
                get_product,
                owner,
                json!({ "tenantId": tenant_id, "productId": s.pro_id })
            )
            .unwrap(),
            json!({ "shadowed": true }),
        );
    });
}

#[test]
fn retires_a_product_for_good_releasing_its_seats_in_every_tenant() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        let root_id = f.root_tenant.clone();
        let root = &f.root_credential;
        let (apollo_id, apollo_owner, apollo) = f
            .activate(&tenant_id, "Apollo", "project", "apollo@acme.test")
            .await;
        let suite = call!(
            f,
            create_product,
            root,
            json!({ "tenantId": root_id, "key": "suite", "name": "Suite", "featureKeys": ["suite"] })
        )
        .unwrap();
        let suite_id = id_of(&suite);
        let acme_pool = call!(
            f,
            add_pool,
            root,
            json!({ "tenantId": tenant_id, "productId": suite_id, "quantity": 2 })
        )
        .unwrap();
        let acme_pool_id = id_of(&acme_pool["pool"]);
        call!(
            f,
            add_pool,
            root,
            json!({ "tenantId": apollo_id, "productId": suite_id, "quantity": 1 })
        )
        .unwrap();
        call!(
            f,
            assign_many,
            owner,
            json!({ "tenantId": tenant_id, "productId": suite_id, "identityIds": [s.alice, s.bob] })
        )
        .unwrap();
        let held = call!(
            f,
            assign,
            &apollo,
            json!({
                "tenantId": apollo_id,
                "productId": suite_id,
                "subjectType": "identity",
                "subjectId": apollo_owner,
            })
        )
        .unwrap();
        assert_eq!(held["seats"].as_array().unwrap().len(), 1);
        assert_matches(&held["seats"][0], json!({ "from": "none", "to": "active" }));

        let retired = call!(
            f,
            retire_product,
            root,
            json!({ "tenantId": root_id, "productId": suite_id })
        )
        .unwrap();
        assert_matches(
            &retired["product"],
            json!({ "key": "suite", "status": "retired" }),
        );
        let mut where_to: Vec<String> = retired["seats"]
            .as_array()
            .unwrap()
            .iter()
            .map(|change| {
                format!(
                    "{} {}",
                    if change["tenantId"] == json!(tenant_id) {
                        "acme"
                    } else {
                        "apollo"
                    },
                    change["to"].as_str().unwrap()
                )
            })
            .collect();
        where_to.sort();
        assert_eq!(where_to, vec!["acme none", "acme none", "apollo none"]);
        let acme_changes = Value::Array(
            retired["seats"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|change| change["tenantId"] == json!(tenant_id))
                .cloned()
                .collect(),
        );
        assert_eq!(
            s.sorted_changes(&acme_changes),
            vec!["alice active->none", "bob active->none"]
        );
        assert_same(
            &call!(f, list_seats, owner, json!({ "tenantId": tenant_id })).unwrap()["seats"],
            json!([]),
        );

        // Retired is final: no seats, no new assignments or pool changes, and the key stays taken.
        let again = fails_with(
            call!(
                f,
                retire_product,
                root,
                json!({ "tenantId": root_id, "productId": suite_id })
            ),
            "INVALID_TRANSITION",
        );
        assert_eq!(again.status, 409);
        fails_with(
            call!(
                f,
                assign,
                owner,
                json!({
                    "tenantId": tenant_id,
                    "productId": suite_id,
                    "subjectType": "identity",
                    "subjectId": s.carol,
                })
            ),
            "INVALID_TRANSITION",
        );
        fails_with(
            call!(
                f,
                assign_many,
                owner,
                json!({ "tenantId": tenant_id, "productId": suite_id, "identityIds": [s.carol] })
            ),
            "INVALID_TRANSITION",
        );
        fails_with(
            call!(
                f,
                add_pool,
                root,
                json!({ "tenantId": tenant_id, "productId": suite_id, "quantity": 1 })
            ),
            "INVALID_TRANSITION",
        );
        fails_with(
            call!(
                f,
                update_pool,
                root,
                json!({ "tenantId": tenant_id, "poolId": acme_pool_id, "quantity": 5 })
            ),
            "INVALID_TRANSITION",
        );
        fails_with(
            call!(
                f,
                remove_pool,
                root,
                json!({ "tenantId": tenant_id, "poolId": acme_pool_id })
            ),
            "INVALID_TRANSITION",
        );
        fails_with(
            call!(
                f,
                create_product,
                root,
                json!({ "tenantId": root_id, "key": "suite", "name": "Again" })
            ),
            "CONFLICT",
        );
        assert_eq!(
            strings(
                &call!(
                    f,
                    list_products,
                    owner,
                    json!({ "tenantId": tenant_id, "status": "retired" })
                )
                .unwrap()["products"],
                "key"
            ),
            vec!["suite"]
        );
        let usage = call!(f, usage, owner, json!({ "tenantId": tenant_id })).unwrap();
        let suite_usage = usage["products"]
            .as_array()
            .unwrap()
            .iter()
            .find(|product| product["key"] == json!("suite"))
            .unwrap();
        assert_matches(
            suite_usage,
            json!({ "status": "retired", "capacity": 2, "active": 0, "waiting": 0, "assignments": 2 }),
        );
        // The safety net never brings seats back; unassigning still tidies up.
        f.iam.licenses.reconcile(None).await.unwrap();
        assert_same(
            &call!(f, list_seats, owner, json!({ "tenantId": tenant_id })).unwrap()["seats"],
            json!([]),
        );
        assert_same(
            &call!(
                f,
                unassign,
                owner,
                json!({
                    "tenantId": tenant_id,
                    "productId": suite_id,
                    "subjectType": "identity",
                    "subjectId": s.alice,
                })
            )
            .unwrap(),
            json!({ "removed": true, "seats": [] }),
        );
        let as_alice = f.sign_in(&s.alice).await;
        assert_matches(
            &call!(f, mine, &as_alice, json!({ "tenantId": tenant_id })).unwrap(),
            json!({ "licenses": [], "featureKeys": [], "allFeatureKeys": [] }),
        );

        // Retirement is audited in the defining tenant, each release where the seat was.
        assert_same(
            &trail(f, &root_id, "license:product-retire").await[0]["metadata"],
            json!({ "productId": suite_id, "key": "suite", "releasedSeats": 3, "tenants": 2 }),
        );
        assert_same(
            &Value::Array(
                trail(f, &apollo_id, "license:seat-release")
                    .await
                    .iter()
                    .map(|event| json!([event["resourceId"], event["metadata"]["reason"]]))
                    .collect(),
            ),
            json!([[apollo_owner, "product-retired"]]),
        );
    });
}

#[test]
fn ranks_claimants_by_seniority_against_the_capacity_of_the_live_pools() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        let first = s.assign(&s.alice).await.unwrap();
        assert_same(
            &first["assignment"],
            json!({
                "id": first["assignment"]["id"],
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "productKey": "pro",
                "productName": "Pro",
                "subjectType": "identity",
                "subjectId": s.alice,
                "subjectName": "alice",
                "subjectEmail": "alice@acme.test",
                "assignedBy": f.owner_id,
                "assignedAt": f.now(),
            }),
        );
        assert!(first["assignment"]["id"].is_string());
        // No capacity yet: the claim waits.
        assert_eq!(s.changes(&first["seats"]), vec!["alice none->waiting"]);
        let initial = call!(
            f,
            add_pool,
            owner,
            json!({ "tenantId": tenant_id, "productId": s.pro_id, "quantity": 2, "note": "Initial purchase" })
        )
        .unwrap();
        let initial_id = id_of(&initial["pool"]);
        assert_same(
            &initial["pool"],
            json!({
                "id": initial_id,
                "tenantId": tenant_id,
                "tenantName": "Acme",
                "productId": s.pro_id,
                "productKey": "pro",
                "productName": "Pro",
                "quantity": 2,
                "note": "Initial purchase",
                "source": "manual",
                "live": true,
                "createdAt": f.now(),
                "createdBy": f.owner_id,
            }),
        );
        assert_eq!(s.changes(&initial["seats"]), vec!["alice waiting->active"]);
        assert_eq!(
            s.changes(&s.assign(&s.bob).await.unwrap()["seats"]),
            vec!["bob none->active"]
        );
        assert_eq!(
            s.changes(&s.assign(&s.carol).await.unwrap()["seats"]),
            vec!["carol none->waiting"]
        );
        assert_eq!(
            s.seats().await,
            vec!["alice active", "bob active", "carol waiting #1"]
        );
        assert_same(
            &call!(f, usage, owner, json!({ "tenantId": tenant_id })).unwrap(),
            json!({
                "tenantId": tenant_id,
                "products": [{
                    "productId": s.pro_id,
                    "key": "pro",
                    "name": "Pro",
                    "scope": "tenant",
                    "status": "active",
                    "capacity": 2,
                    "active": 2,
                    "waiting": 1,
                    "available": 0,
                    "pools": 1,
                    "assignments": 3,
                    "reclaimable": 0,
                    "reclaimableThroughGroups": 0,
                }],
            }),
        );

        // A capacity cut moves the newest active seat to the head of the waiting list; it is never an error.
        f.advance(1000.0);
        let cut = call!(
            f,
            update_pool,
            owner,
            json!({ "tenantId": tenant_id, "poolId": initial_id, "quantity": 1 })
        )
        .unwrap();
        assert_matches(
            &cut["pool"],
            json!({ "quantity": 1, "updatedAt": f.now(), "updatedBy": f.owner_id }),
        );
        assert_eq!(s.changes(&cut["seats"]), vec!["bob active->waiting"]);
        assert_eq!(
            s.seats().await,
            vec!["alice active", "bob waiting #1", "carol waiting #2"]
        );
        // Seats filter by status and person, and page.
        let waiting_list = call!(
            f,
            list_seats,
            owner,
            json!({ "tenantId": tenant_id, "status": "waiting" })
        )
        .unwrap();
        assert_same(&waiting_list["total"], json!(2));
        assert_same(
            &Value::Array(
                waiting_list["seats"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|seat| json!([seat["identityName"], seat["position"]]))
                    .collect(),
            ),
            json!([["bob", 1], ["carol", 2]]),
        );
        assert_matches(
            &call!(
                f,
                list_seats,
                owner,
                json!({ "tenantId": tenant_id, "status": "waiting", "limit": 1, "offset": 1 })
            )
            .unwrap(),
            json!({ "total": 2, "seats": [{ "identityName": "carol", "position": 2 }] }),
        );
        assert_same(
            &call!(
                f,
                list_seats,
                owner,
                json!({ "tenantId": tenant_id, "identityId": s.alice, "status": "waiting" })
            )
            .unwrap(),
            json!({ "seats": [], "total": 0 }),
        );
        for input in [
            json!({ "status": "gone" }),
            json!({ "limit": 0 }),
            json!({ "limit": 1001 }),
            json!({ "offset": -1 }),
        ] {
            let mut full = input;
            full["tenantId"] = json!(tenant_id);
            fails_with(call!(f, list_seats, owner, full), "INVALID_INPUT");
        }

        // A pool with an end: waiting people take its seats at once and keep them until the term ends.
        f.advance(1000.0);
        let trial = call!(
            f,
            add_pool,
            owner,
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "quantity": 5,
                "endsAt": f.now() + HOUR,
                "note": "Trial",
            })
        )
        .unwrap();
        let trial_id = id_of(&trial["pool"]);
        assert_matches(
            &trial["pool"],
            json!({ "endsAt": f.now() + HOUR, "live": true }),
        );
        assert_eq!(
            s.changes(&trial["seats"]),
            vec!["bob waiting->active", "carol waiting->active"]
        );
        assert_eq!(
            strings(
                &call!(f, list_pools, owner, json!({ "tenantId": tenant_id })).unwrap()["pools"],
                "note"
            ),
            vec!["Trial", "Initial purchase"]
        );
        f.advance(2.0 * HOUR);
        let job = f.iam.licenses.reconcile(None).await.unwrap();
        assert_same(
            &job,
            json!({ "tenants": 1, "activated": 0, "waiting": 2, "released": 0, "failedTenants": [] }),
        );
        assert_eq!(
            s.seats().await,
            vec!["alice active", "bob waiting #1", "carol waiting #2"]
        );
        assert_same(
            &f.iam
                .licenses
                .reconcile(Some(&json!({ "tenantId": tenant_id })))
                .await
                .unwrap(),
            json!({ "tenants": 1, "activated": 0, "waiting": 0, "released": 0, "failedTenants": [] }),
        );
        assert_matches(
            &call!(f, list_pools, owner, json!({ "tenantId": tenant_id })).unwrap(),
            json!({ "total": 1, "pools": [{ "note": "Initial purchase" }] }),
        );
        let everything = call!(
            f,
            list_pools,
            owner,
            json!({ "tenantId": tenant_id, "includeEnded": true })
        )
        .unwrap();
        assert_same(
            &Value::Array(
                everything["pools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|pool| json!([pool["note"], pool["live"]]))
                    .collect(),
            ),
            json!([["Trial", false], ["Initial purchase", true]]),
        );
        assert_matches(
            &call!(
                f,
                list_pools,
                owner,
                json!({ "tenantId": tenant_id, "includeEnded": true, "limit": 1, "offset": 1 })
            )
            .unwrap(),
            json!({ "total": 2, "pools": [{ "note": "Initial purchase" }] }),
        );

        // An ended pool can be reopened (null clears the end) and removed.
        let reopened = call!(
            f,
            update_pool,
            owner,
            json!({ "tenantId": tenant_id, "poolId": trial_id, "endsAt": null, "note": null })
        )
        .unwrap();
        assert!(reopened["pool"].get("endsAt").is_none());
        assert!(reopened["pool"].get("note").is_none());
        assert_eq!(reopened["pool"]["live"], json!(true));
        assert_eq!(
            s.changes(&reopened["seats"]),
            vec!["bob waiting->active", "carol waiting->active"]
        );
        let removed = call!(
            f,
            remove_pool,
            owner,
            json!({ "tenantId": tenant_id, "poolId": trial_id })
        )
        .unwrap();
        assert_eq!(removed["removed"], json!(true));
        assert_eq!(
            s.changes(&removed["seats"]),
            vec!["bob active->waiting", "carol active->waiting"]
        );
        fails_with(
            call!(
                f,
                remove_pool,
                owner,
                json!({ "tenantId": tenant_id, "poolId": trial_id })
            ),
            "NOT_FOUND",
        );

        // A pool that starts later adds nothing until it starts.
        let later = call!(
            f,
            add_pool,
            owner,
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "quantity": 1,
                "startsAt": f.now() + HOUR,
            })
        )
        .unwrap();
        assert_eq!(later["pool"]["live"], json!(false));
        assert_same(&later["seats"], json!([]));
        assert_matches(
            &call!(f, usage, owner, json!({ "tenantId": tenant_id })).unwrap()["products"][0],
            json!({ "capacity": 1, "pools": 1 }),
        );
        f.advance(2.0 * HOUR);
        assert_matches(
            &f.iam.licenses.reconcile(None).await.unwrap(),
            json!({ "activated": 1 }),
        );
        assert_eq!(
            s.seats().await,
            vec!["alice active", "bob active", "carol waiting #1"]
        );

        let actions: Vec<String> = trail(f, &tenant_id, "license:pool-")
            .await
            .iter()
            .map(|event| event["action"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            actions,
            vec![
                "license:pool-add",
                "license:pool-update",
                "license:pool-add",
                "license:pool-update",
                "license:pool-remove",
                "license:pool-add"
            ]
        );
        let update = &trail(f, &tenant_id, "license:pool-update").await[0];
        assert_matches(
            &Value::Object(update.clone()),
            json!({
                "resourceId": format!("licenses/pools/{initial_id}"),
                "metadata": {
                    "before": { "poolId": initial_id, "quantity": 2, "productKey": "pro" },
                    "after": { "quantity": 1 },
                },
            }),
        );
        let scheduled: Vec<Value> = trail(f, &tenant_id, "license:seat-waiting")
            .await
            .iter()
            .filter(|event| event["actorId"] == json!("deployment-operator"))
            .map(|event| json!([event["resourceId"], event["metadata"]["reason"]]))
            .collect();
        assert_same(
            &Value::Array(scheduled),
            json!([[s.bob, "schedule"], [s.carol, "schedule"]]),
        );
    });
}

#[test]
fn never_gives_an_existing_seat_to_a_claimant_who_arrives_in_the_same_millisecond() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        call!(
            f,
            add_pool,
            owner,
            json!({ "tenantId": tenant_id, "productId": s.pro_id, "quantity": 1 })
        )
        .unwrap();
        // Assign in descending ID order without moving the clock, so identity order alone would reverse seniority.
        let mut people = [s.alice.clone(), s.bob.clone(), s.carol.clone()];
        people.sort_by(|a, b| b.cmp(a));
        let (first, second, third) = (people[0].clone(), people[1].clone(), people[2].clone());
        let assign = |identity_id: String| {
            let tenant_id = tenant_id.clone();
            let pro_id = s.pro_id.clone();
            async move {
                call!(
                    f,
                    assign,
                    owner,
                    json!({
                        "tenantId": tenant_id,
                        "productId": pro_id,
                        "subjectType": "identity",
                        "subjectId": identity_id,
                    })
                )
                .unwrap()
            }
        };
        for (identity, to) in [
            (&first, "active"),
            (&second, "waiting"),
            (&third, "waiting"),
        ] {
            let seats = assign(identity.clone()).await["seats"].clone();
            assert_eq!(seats.as_array().unwrap().len(), 1);
            assert_matches(
                &seats[0],
                json!({ "identityId": identity, "from": "none", "to": to }),
            );
        }
        let holders = || async {
            Value::Array(
                call!(f, list_seats, owner, json!({ "tenantId": tenant_id })).unwrap()["seats"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|seat| {
                        json!([
                            seat["identityId"],
                            seat["status"],
                            seat.get("position").cloned().unwrap_or(Value::Null)
                        ])
                    })
                    .collect(),
            )
        };
        let expected = json!([
            [first, "active", null],
            [third, "waiting", 1],
            [second, "waiting", 2]
        ]);
        assert_same(&holders().await, expected.clone());
        // Later runs keep it that way, and the next free seat goes to the head of the waiting list.
        assert_matches(
            &f.iam.licenses.reconcile(None).await.unwrap(),
            json!({ "activated": 0, "waiting": 0 }),
        );
        assert_same(&holders().await, expected);
        let more = call!(
            f,
            add_pool,
            owner,
            json!({ "tenantId": tenant_id, "productId": s.pro_id, "quantity": 1 })
        )
        .unwrap();
        assert_eq!(more["seats"].as_array().unwrap().len(), 1);
        assert_matches(
            &more["seats"][0],
            json!({ "identityId": third, "from": "waiting", "to": "active" }),
        );
    });
}

#[test]
fn validates_pools() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        let add = |input: Value| {
            let mut full = json!({ "tenantId": tenant_id, "productId": s.pro_id, "quantity": 1 });
            for (key, value) in input.as_object().unwrap() {
                full[key] = value.clone();
            }
            async move { call!(f, add_pool, owner, full) }
        };
        for quantity in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!(1_000_001),
            json!("3"),
        ] {
            fails_with(add(json!({ "quantity": quantity })).await, "INVALID_INPUT");
        }
        fails_with(
            add(json!({ "endsAt": f.now() - 1.0 })).await,
            "INVALID_INPUT",
        );
        fails_with(add(json!({ "endsAt": f.now() })).await, "INVALID_INPUT");
        fails_with(
            add(json!({ "startsAt": f.now() + 2.0 * HOUR, "endsAt": f.now() + HOUR })).await,
            "INVALID_INPUT",
        );
        fails_with(add(json!({ "startsAt": -5 })).await, "INVALID_INPUT");
        fails_with(
            add(json!({ "note": "x".repeat(513) })).await,
            "INVALID_INPUT",
        );
        fails_with(
            add(json!({ "subscriptionId": "missing" })).await,
            "NOT_FOUND",
        );
        fails_with(add(json!({ "productId": "missing" })).await, "NOT_FOUND");
        assert_matches(
            &add(json!({ "quantity": 1_000_000 })).await.unwrap(),
            json!({ "pool": { "quantity": 1_000_000 } }),
        );
        let later = add(json!({ "startsAt": f.now() + HOUR, "endsAt": f.now() + 3.0 * HOUR }))
            .await
            .unwrap();
        let later_id = id_of(&later["pool"]);
        let nothing = fails_with(
            call!(
                f,
                update_pool,
                owner,
                json!({ "tenantId": tenant_id, "poolId": later_id })
            ),
            "INVALID_INPUT",
        );
        assert_eq!(nothing.message, "Nothing to update");
        fails_with(
            call!(
                f,
                update_pool,
                owner,
                json!({ "tenantId": tenant_id, "poolId": later_id, "endsAt": f.now() + HOUR })
            ),
            "INVALID_INPUT",
        );
        fails_with(
            call!(
                f,
                update_pool,
                owner,
                json!({ "tenantId": tenant_id, "poolId": later_id, "quantity": 0 })
            ),
            "INVALID_INPUT",
        );
        fails_with(
            call!(
                f,
                update_pool,
                owner,
                json!({ "tenantId": tenant_id, "poolId": "missing", "quantity": 2 })
            ),
            "NOT_FOUND",
        );
        fails_with(
            call!(
                f,
                list_pools,
                owner,
                json!({ "tenantId": tenant_id, "limit": 0 })
            ),
            "INVALID_INPUT",
        );
        fails_with(
            call!(
                f,
                list_pools,
                owner,
                json!({ "tenantId": tenant_id, "includeEnded": "yes" })
            ),
            "INVALID_INPUT",
        );
        // Ended pools are kept 400 days after their end as purchase history, then swept.
        let ending = add(json!({ "endsAt": f.now() + HOUR })).await.unwrap();
        f.advance(HOUR + 399.0 * DAY);
        let swept = f.iam.sweep_expired(None).await.unwrap();
        assert!(swept["deleted"].get("licensePools").is_none(), "{swept}");
        f.advance(2.0 * DAY);
        let swept = f.iam.sweep_expired(None).await.unwrap();
        assert_matches(&swept["deleted"], json!({ "licensePools": 2 }));
        let left = f
            .find(
                "licensePools",
                Filter::new().eq("tenantId", tenant_id.clone()),
            )
            .await;
        assert!(!left.iter().any(|pool| pool["id"] == ending["pool"]["id"]));
        assert_eq!(left.len(), 1);
    });
}

async fn create_group(f: &Org, owner: &CredentialInput, name: &str) -> String {
    let group = f
        .iam
        .api
        .groups
        .create(
            owner,
            body(json!({ "tenantId": f.tenant_id, "name": name })),
        )
        .await
        .and_then(|reply| reply.into_value())
        .expect("group");
    id_of(&group)
}

async fn add_member(
    f: &Org,
    owner: &CredentialInput,
    group_id: &str,
    identity_id: &str,
    expires_at: Option<f64>,
) {
    let mut input =
        json!({ "tenantId": f.tenant_id, "groupId": group_id, "identityId": identity_id });
    if let Some(expires_at) = expires_at {
        input["expiresAt"] = json!(expires_at);
    }
    f.iam
        .api
        .groups
        .add_member(owner, body(input))
        .await
        .and_then(|reply| reply.into_value())
        .expect("add member");
}

async fn remove_member(f: &Org, owner: &CredentialInput, group_id: &str, identity_id: &str) {
    f.iam
        .api
        .groups
        .remove_member(
            owner,
            body(
                json!({ "tenantId": f.tenant_id, "groupId": group_id, "identityId": identity_id }),
            ),
        )
        .await
        .and_then(|reply| reply.into_value())
        .expect("remove member");
}

#[test]
fn assigns_people_and_groups_and_follows_group_membership() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        call!(
            f,
            add_pool,
            owner,
            json!({ "tenantId": tenant_id, "productId": s.pro_id, "quantity": 10 })
        )
        .unwrap();
        let design = create_group(f, owner, "Design").await;
        f.iam
            .api
            .groups
            .add_members(
                owner,
                body(json!({ "tenantId": tenant_id, "groupId": design, "identityIds": [s.alice, s.bob] })),
            )
            .await
            .and_then(|reply| reply.into_value())
            .expect("add members");
        f.advance(1000.0);
        let grouped = call!(
            f,
            assign,
            owner,
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "subjectType": "group",
                "subjectId": design,
            })
        )
        .unwrap();
        assert_matches(
            &grouped["assignment"],
            json!({ "subjectType": "group", "subjectId": design, "subjectName": "Design" }),
        );
        assert!(grouped["assignment"].get("subjectEmail").is_none());
        assert_eq!(
            s.sorted_changes(&grouped["seats"]),
            vec!["alice none->active", "bob none->active"]
        );
        // A direct assignment on top only adds a source.
        let direct = s.assign(&s.alice).await.unwrap();
        assert_same(&direct["seats"], json!([]));
        let alice_seats = call!(
            f,
            list_seats,
            owner,
            json!({ "tenantId": tenant_id, "identityId": s.alice })
        )
        .unwrap();
        assert_eq!(alice_seats["seats"].as_array().unwrap().len(), 1);
        assert_matches(
            &alice_seats["seats"][0],
            json!({
                "identityName": "alice",
                "identityEmail": "alice@acme.test",
                "identityKind": "user",
                "status": "active",
                "direct": true,
                "groupIds": [design],
            }),
        );

        // Membership changes move seats in the same transaction, whoever writes them.
        add_member(f, owner, &design, &s.carol, None).await;
        assert_eq!(
            sorted(s.seats().await),
            vec!["alice active", "bob active", "carol active"]
        );
        remove_member(f, owner, &design, &s.bob).await;
        remove_member(f, owner, &design, &s.alice).await;
        assert_eq!(s.seats().await, vec!["alice active", "carol active"]);
        assert_matches(
            &call!(
                f,
                list_seats,
                owner,
                json!({ "tenantId": tenant_id, "identityId": s.alice })
            )
            .unwrap()["seats"][0],
            json!({ "direct": true, "groupIds": [] }),
        );
        let release = trail(f, &tenant_id, "license:seat-release")
            .await
            .pop()
            .unwrap();
        assert_matches(
            &Value::Object(release),
            json!({
                "actorId": f.owner_id,
                "resourceId": s.bob,
                "metadata": {
                    "productId": s.pro_id,
                    "productKey": "pro",
                    "from": "active",
                    "to": "none",
                    "reason": "group-membership",
                },
            }),
        );

        // A temporary membership ends by itself; the next reconcile releases the seat.
        let erin = s.person("erin").await;
        add_member(f, owner, &design, &erin, Some(f.now() + HOUR)).await;
        assert!(s.seats().await.contains(&"erin active".to_owned()));
        f.advance(2.0 * HOUR);
        assert_matches(
            &f.iam.licenses.reconcile(None).await.unwrap(),
            json!({ "released": 1 }),
        );
        assert_eq!(s.seats().await, vec!["alice active", "carol active"]);

        // Duplicates and unknown subjects are refused.
        let duplicate = fails_with(s.assign(&s.alice).await, "CONFLICT");
        assert_eq!(duplicate.status, 409);
        fails_with(s.assign("missing").await, "NOT_FOUND");
        fails_with(s.assign_to(&s.alice, "missing").await, "NOT_FOUND");
        fails_with(
            call!(
                f,
                assign,
                owner,
                json!({
                    "tenantId": tenant_id,
                    "productId": s.pro_id,
                    "subjectType": "group",
                    "subjectId": "missing",
                })
            ),
            "NOT_FOUND",
        );
        fails_with(
            call!(
                f,
                assign,
                owner,
                json!({
                    "tenantId": tenant_id,
                    "productId": s.pro_id,
                    "subjectType": "team",
                    "subjectId": s.alice,
                })
            ),
            "INVALID_INPUT",
        );

        // Listing assignments: newest first, filtered and paged.
        let all = call!(f, list_assignments, owner, json!({ "tenantId": tenant_id })).unwrap();
        assert_same(&all["total"], json!(2));
        assert_eq!(
            strings(&all["assignments"], "subjectName"),
            vec!["alice", "Design"]
        );
        let groups = call!(
            f,
            list_assignments,
            owner,
            json!({ "tenantId": tenant_id, "subjectType": "group" })
        )
        .unwrap();
        assert_eq!(
            strings(&groups["assignments"], "subjectId"),
            vec![design.clone()]
        );
        assert_matches(
            &call!(
                f,
                list_assignments,
                owner,
                json!({ "tenantId": tenant_id, "subjectId": s.alice, "productId": s.pro_id })
            )
            .unwrap(),
            json!({ "total": 1, "assignments": [{ "id": direct["assignment"]["id"] }] }),
        );
        assert_matches(
            &call!(
                f,
                list_assignments,
                owner,
                json!({ "tenantId": tenant_id, "limit": 1, "offset": 1 })
            )
            .unwrap(),
            json!({ "total": 2, "assignments": [{ "subjectName": "Design" }] }),
        );
        fails_with(
            call!(
                f,
                list_assignments,
                owner,
                json!({ "tenantId": tenant_id, "subjectType": "robot" })
            ),
            "INVALID_INPUT",
        );

        // Unassigning by product and subject, or by ID; seats a remaining assignment covers stay.
        let ungrouped = call!(
            f,
            unassign,
            owner,
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "subjectType": "group",
                "subjectId": design,
            })
        )
        .unwrap();
        assert_eq!(s.changes(&ungrouped["seats"]), vec!["carol active->none"]);
        fails_with(
            call!(
                f,
                unassign,
                owner,
                json!({
                    "tenantId": tenant_id,
                    "productId": s.pro_id,
                    "subjectType": "group",
                    "subjectId": design,
                })
            ),
            "NOT_FOUND",
        );
        let by_id = call!(
            f,
            unassign,
            owner,
            json!({ "tenantId": tenant_id, "assignmentId": direct["assignment"]["id"] })
        )
        .unwrap();
        assert_eq!(s.changes(&by_id["seats"]), vec!["alice active->none"]);
        fails_with(
            call!(
                f,
                unassign,
                owner,
                json!({ "tenantId": tenant_id, "assignmentId": direct["assignment"]["id"] })
            ),
            "NOT_FOUND",
        );
        fails_with(
            call!(f, unassign, owner, json!({ "tenantId": tenant_id })),
            "INVALID_INPUT",
        );
        assert!(s.seats().await.is_empty());
        assert_same(
            &Value::Array(
                trail(f, &tenant_id, "license:unassign")
                    .await
                    .iter()
                    .map(|event| json!([event["resourceId"], event["metadata"]["subjectType"]]))
                    .collect(),
            ),
            json!([[design, "group"], [s.alice, "identity"]]),
        );
    });
}

#[test]
fn assigns_many_people_at_once_and_releases_a_deleted_groups_seats() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        call!(
            f,
            add_pool,
            owner,
            json!({ "tenantId": tenant_id, "productId": s.pro_id, "quantity": 3 })
        )
        .unwrap();
        s.assign(&s.bob).await.unwrap();
        let dave = s.person("dave").await;
        f.advance(1000.0);
        let many = call!(
            f,
            assign_many,
            owner,
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "identityIds": [s.bob, dave, dave, s.carol],
            })
        )
        .unwrap();
        assert_same(&many["skipped"], json!([s.bob]));
        assert_eq!(
            strings(&many["assigned"], "subjectName"),
            vec!["dave", "carol"]
        );
        assert_eq!(
            s.sorted_changes(&many["seats"]),
            vec!["carol none->active", "dave none->active"]
        );
        assert_eq!(
            trail(f, &tenant_id, "license:assign")
                .await
                .iter()
                .map(|event| event["resourceId"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>(),
            vec![s.bob.clone(), dave.clone(), s.carol.clone()]
        );
        // Nothing new: no seat run, no error.
        assert_same(
            &call!(
                f,
                assign_many,
                owner,
                json!({ "tenantId": tenant_id, "productId": s.pro_id, "identityIds": [s.bob] })
            )
            .unwrap(),
            json!({ "assigned": [], "skipped": [s.bob], "seats": [] }),
        );
        let too_many: Vec<String> = (0..101).map(|index| format!("id-{index}")).collect();
        for identity_ids in [json!([]), json!("x"), json!(too_many)] {
            fails_with(
                call!(
                    f,
                    assign_many,
                    owner,
                    json!({ "tenantId": tenant_id, "productId": s.pro_id, "identityIds": identity_ids })
                ),
                "INVALID_INPUT",
            );
        }
        // One unknown person rejects the whole batch.
        fails_with(
            call!(
                f,
                assign_many,
                owner,
                json!({ "tenantId": tenant_id, "productId": s.pro_id, "identityIds": [s.alice, "missing"] })
            ),
            "NOT_FOUND",
        );
        assert_same(
            &call!(
                f,
                list_assignments,
                owner,
                json!({ "tenantId": tenant_id, "subjectId": s.alice })
            )
            .unwrap()["total"],
            json!(0),
        );

        // Deleting a group deletes its license assignments; the seats they carried go.
        let ops = create_group(f, owner, "Ops").await;
        add_member(f, owner, &ops, &s.alice, None).await;
        add_member(f, owner, &ops, &s.bob, None).await;
        f.advance(1000.0);
        let grouped = call!(
            f,
            assign,
            owner,
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "subjectType": "group",
                "subjectId": ops,
            })
        )
        .unwrap();
        assert_eq!(s.changes(&grouped["seats"]), vec!["alice none->waiting"]);
        f.iam
            .api
            .groups
            .delete(
                owner,
                body(json!({ "tenantId": tenant_id, "groupId": ops })),
            )
            .await
            .and_then(|reply| reply.into_value())
            .expect("delete group");
        assert_same(
            &call!(
                f,
                list_assignments,
                owner,
                json!({ "tenantId": tenant_id, "subjectType": "group" })
            )
            .unwrap()["total"],
            json!(0),
        );
        assert_eq!(
            sorted(s.seats().await),
            vec!["bob active", "carol active", "dave active"]
        );
        let release = trail(f, &tenant_id, "license:seat-release")
            .await
            .pop()
            .unwrap();
        assert_matches(
            &Value::Object(release),
            json!({ "resourceId": s.alice, "metadata": { "from": "waiting", "reason": "group-deleted" } }),
        );
    });
}

#[test]
fn caps_products_per_tenant_pools_per_product_and_assignments_per_product() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        let now = f.now();
        let (tenant, owner_id, pro_id) = (tenant_id.clone(), f.owner_id.clone(), s.pro_id.clone());
        f.iam
            .store
            .transaction(|tx| async move {
                for index in 1..200 {
                    let record = json!({
                        "id": format!("product-{index}"),
                        "tenantId": tenant,
                        "uniqueKey": format!("key:bulk-{index}"),
                        "key": format!("bulk-{index}"),
                        "name": format!("Bulk {index}"),
                        "featureKeys": [],
                        "status": "active",
                        "createdAt": now,
                        "createdBy": owner_id,
                        "updatedAt": now,
                        "updatedBy": owner_id,
                    });
                    tx.insert("licenseProducts", record.as_object().unwrap())
                        .await?;
                }
                for index in 0..100 {
                    let record = json!({
                        "id": format!("pool-{index}"),
                        "tenantId": tenant,
                        "productId": pro_id,
                        "quantity": 1,
                        "source": "manual",
                        "createdAt": now,
                        "createdBy": owner_id,
                    });
                    tx.insert("licensePools", record.as_object().unwrap())
                        .await?;
                }
                for index in 0..10_000 {
                    let record = json!({
                        "id": format!("assignment-{index}"),
                        "tenantId": tenant,
                        "uniqueKey": format!("{pro_id}:identity:ghost-{index}"),
                        "productId": pro_id,
                        "subjectType": "identity",
                        "subjectId": format!("ghost-{index}"),
                        "assignedBy": owner_id,
                        "assignedAt": now,
                    });
                    tx.insert("licenseAssignments", record.as_object().unwrap())
                        .await?;
                }
                Ok(())
            })
            .await
            .unwrap();
        let limit = fails_with(
            call!(
                f,
                create_product,
                owner,
                json!({ "tenantId": tenant_id, "key": "one-more", "name": "One more" })
            ),
            "LIMIT_EXCEEDED",
        );
        assert_eq!(limit.status, 409);
        fails_with(
            call!(
                f,
                add_pool,
                owner,
                json!({ "tenantId": tenant_id, "productId": s.pro_id, "quantity": 1 })
            ),
            "LIMIT_EXCEEDED",
        );
        fails_with(
            call!(
                f,
                assign,
                owner,
                json!({
                    "tenantId": tenant_id,
                    "productId": s.pro_id,
                    "subjectType": "identity",
                    "subjectId": s.alice,
                })
            ),
            "LIMIT_EXCEEDED",
        );
        fails_with(
            call!(
                f,
                assign_many,
                owner,
                json!({ "tenantId": tenant_id, "productId": s.pro_id, "identityIds": [s.alice] })
            ),
            "LIMIT_EXCEEDED",
        );
        // Another product has room.
        assert_matches(
            &call!(
                f,
                add_pool,
                owner,
                json!({ "tenantId": tenant_id, "productId": "product-1", "quantity": 1 })
            )
            .unwrap(),
            json!({ "pool": { "productKey": "bulk-1" } }),
        );
    });
}

#[test]
fn configures_reclaim_and_waiting_list_email() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        assert_same(
            &call!(f, get_settings, owner, json!({ "tenantId": tenant_id })).unwrap(),
            json!({ "tenantId": tenant_id, "notifyWaiting": false }),
        );
        assert_same(
            &call!(
                f,
                configure,
                owner,
                json!({ "tenantId": tenant_id, "reclaimAfterDays": 30 })
            )
            .unwrap(),
            json!({
                "tenantId": tenant_id,
                "reclaimAfterDays": 30,
                "notifyWaiting": false,
                "updatedAt": f.now(),
                "updatedBy": f.owner_id,
            }),
        );
        assert_matches(
            &call!(
                f,
                configure,
                owner,
                json!({ "tenantId": tenant_id, "notifyWaiting": true })
            )
            .unwrap(),
            json!({ "reclaimAfterDays": 30, "notifyWaiting": true }),
        );
        let cleared = call!(
            f,
            configure,
            owner,
            json!({ "tenantId": tenant_id, "reclaimAfterDays": null })
        )
        .unwrap();
        assert_matches(&cleared, json!({ "notifyWaiting": true }));
        assert!(cleared.get("reclaimAfterDays").is_none());
        assert_same(
            &call!(f, get_settings, owner, json!({ "tenantId": tenant_id })).unwrap(),
            cleared,
        );
        for input in [
            json!({}),
            json!({ "reclaimAfterDays": 6 }),
            json!({ "reclaimAfterDays": 366 }),
            json!({ "reclaimAfterDays": 7.5 }),
            json!({ "reclaimAfterDays": "30" }),
            json!({ "notifyWaiting": "yes" }),
        ] {
            let mut full = input;
            full["tenantId"] = json!(tenant_id);
            fails_with(call!(f, configure, owner, full), "INVALID_INPUT");
        }
        assert_same(
            &Value::Array(
                trail(f, &tenant_id, "license:settings")
                    .await
                    .iter()
                    .map(|event| event["metadata"].clone())
                    .collect(),
            ),
            json!([
                {
                    "reclaimAfterDays": 30,
                    "notifyWaiting": false,
                    "previousReclaimAfterDays": null,
                    "previousNotifyWaiting": false,
                },
                {
                    "reclaimAfterDays": 30,
                    "notifyWaiting": true,
                    "previousReclaimAfterDays": 30,
                    "previousNotifyWaiting": false,
                },
                {
                    "reclaimAfterDays": null,
                    "notifyWaiting": true,
                    "previousReclaimAfterDays": 30,
                    "previousNotifyWaiting": true,
                },
            ]),
        );
    });
}

#[test]
fn shows_people_their_own_licenses_without_auditing_the_read() {
    run(|| async {
        let s = scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        let team = call!(
            f,
            create_product,
            owner,
            json!({ "tenantId": tenant_id, "key": "team", "name": "Team", "featureKeys": ["boards", "sso"] })
        )
        .unwrap();
        let team_id = id_of(&team);
        call!(
            f,
            add_pool,
            owner,
            json!({ "tenantId": tenant_id, "productId": s.pro_id, "quantity": 1 })
        )
        .unwrap();
        call!(
            f,
            add_pool,
            owner,
            json!({ "tenantId": tenant_id, "productId": team_id, "quantity": 5 })
        )
        .unwrap();
        s.assign(&s.alice).await.unwrap();
        s.assign_to(&s.alice, &team_id).await.unwrap();
        s.assign(&s.bob).await.unwrap();
        let as_alice = f.sign_in(&s.alice).await;
        let as_bob = f.sign_in(&s.bob).await;
        let as_carol = f.sign_in(&s.carol).await;
        assert_same(
            &call!(f, mine, &as_alice, json!({ "tenantId": tenant_id })).unwrap(),
            json!({
                "tenantId": tenant_id,
                "identityId": s.alice,
                "licenses": [
                    {
                        "productId": s.pro_id,
                        "key": "pro",
                        "name": "Pro",
                        "description": "Everything in Pro",
                        "status": "active",
                        "featureKeys": ["exports", "sso"],
                        "platform": false,
                        "definedBy": tenant_id,
                    },
                    {
                        "productId": team_id,
                        "key": "team",
                        "name": "Team",
                        "status": "active",
                        "featureKeys": ["boards", "sso"],
                        "platform": false,
                        "definedBy": tenant_id,
                    },
                ],
                // Acme's own products: their feature keys are not the platform's entitlements.
                "featureKeys": [],
                "allFeatureKeys": ["boards", "exports", "sso"],
            }),
        );
        assert_same(
            &call!(f, mine, &as_bob, json!({ "tenantId": tenant_id })).unwrap(),
            json!({
                "tenantId": tenant_id,
                "identityId": s.bob,
                "licenses": [{
                    "productId": s.pro_id,
                    "key": "pro",
                    "name": "Pro",
                    "description": "Everything in Pro",
                    "status": "waiting",
                    "position": 1,
                    "featureKeys": [],
                    "platform": false,
                    "definedBy": tenant_id,
                }],
                "featureKeys": [],
                "allFeatureKeys": [],
            }),
        );
        assert_same(
            &call!(f, mine, &as_carol, json!({ "tenantId": tenant_id })).unwrap(),
            json!({
                "tenantId": tenant_id,
                "identityId": s.carol,
                "licenses": [],
                "featureKeys": [],
                "allFeatureKeys": [],
            }),
        );
        let acme = json!({ "trustedTenantId": tenant_id });
        let licenses = &f.iam.licenses;
        assert_eq!(
            licenses
                .features(&s.alice, &tenant_id, Some(&acme))
                .await
                .unwrap(),
            vec!["boards", "exports", "sso"]
        );
        assert!(
            licenses
                .features(&s.alice, &tenant_id, None)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            licenses.products(&s.alice, &tenant_id).await.unwrap(),
            vec!["pro", "team"]
        );
        assert!(
            licenses
                .features(&s.bob, &tenant_id, Some(&acme))
                .await
                .unwrap()
                .is_empty()
        );

        let count = || async {
            f.find("audit", Filter::new().eq("tenantId", tenant_id.clone()))
                .await
                .len()
        };
        let before = count().await;
        call!(f, mine, &as_alice, json!({ "tenantId": tenant_id })).unwrap();
        assert_eq!(count().await, before);

        // Only the caller's own tenant; administrators of other tenants see nothing of theirs here.
        fails_with(
            call!(f, mine, &as_alice, json!({ "tenantId": f.root_tenant })),
            "ACCESS_DENIED",
        );
        fails_with(
            call!(
                f,
                mine,
                &bearer("not-a-token"),
                json!({ "tenantId": tenant_id })
            ),
            "UNAUTHENTICATED",
        );
        fails_with(
            call!(f, mine, &as_alice, json!({ "tenantId": "" })),
            "INVALID_INPUT",
        );
        assert_matches(
            &call!(
                f,
                mine,
                &f.root_credential,
                json!({ "tenantId": tenant_id })
            )
            .unwrap(),
            json!({ "licenses": [], "featureKeys": [], "allFeatureKeys": [] }),
        );
        assert_matches(
            &call!(f, mine, owner, json!({ "tenantId": tenant_id })).unwrap(),
            json!({ "identityId": f.owner_id, "licenses": [] }),
        );
    });
}

// --- tests/licenses-access.test.ts --------------------------------------------------------------------------------

struct Access {
    s: Scenario,
    pool_id: String,
    assignment_id: String,
}

async fn access_scenario() -> Access {
    let s = scenario().await;
    let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
    let pool = call!(
        f,
        add_pool,
        owner,
        json!({ "tenantId": tenant_id, "productId": s.pro_id, "quantity": 2 })
    )
    .unwrap();
    create_group(f, owner, "Design").await;
    let assigned = call!(
        f,
        assign,
        owner,
        json!({
            "tenantId": tenant_id,
            "productId": s.pro_id,
            "subjectType": "identity",
            "subjectId": s.alice,
        })
    )
    .unwrap();
    Access {
        pool_id: id_of(&pool["pool"]),
        assignment_id: id_of(&assigned["assignment"]),
        s,
    }
}

impl Access {
    /// A member holding a role with `permissions` (none when empty), signed in.
    async fn member(&self, name: &str, permissions: &[&str]) -> (String, CredentialInput) {
        let f = &self.s.f;
        let identity = f.member(name).await;
        if !permissions.is_empty() {
            let role = f
                .iam
                .api
                .roles
                .create(
                    &self.s.owner,
                    body(json!({
                        "tenantId": self.s.tenant_id,
                        "name": format!("{name} role"),
                        "permissions": permissions,
                    })),
                )
                .await
                .and_then(|reply| reply.into_value())
                .expect("role");
            f.iam
                .api
                .bindings
                .create(
                    &self.s.owner,
                    body(json!({
                        "tenantId": self.s.tenant_id,
                        "roleId": role["id"],
                        "subjectType": "identity",
                        "subjectId": identity,
                    })),
                )
                .await
                .and_then(|reply| reply.into_value())
                .expect("binding");
        }
        let credential = f.sign_in(&identity).await;
        (identity, credential)
    }

    /// Every licenses call against Acme of one kind: `read`, `manage`, `assign` or `destructive`.
    async fn calls(
        &self,
        kind: &str,
        credential: &CredentialInput,
        subject_id: &str,
    ) -> Vec<(&'static str, IamResult<Value>)> {
        let (f, tenant_id) = (&self.s.f, self.s.tenant_id.clone());
        let pro_id = self.s.pro_id.clone();
        let mut out = Vec::new();
        match kind {
            "read" => {
                out.push((
                    "listProducts",
                    call!(
                        f,
                        list_products,
                        credential,
                        json!({ "tenantId": tenant_id })
                    ),
                ));
                out.push((
                    "getProduct",
                    call!(
                        f,
                        get_product,
                        credential,
                        json!({ "tenantId": tenant_id, "productId": pro_id })
                    ),
                ));
                out.push((
                    "listPools",
                    call!(f, list_pools, credential, json!({ "tenantId": tenant_id })),
                ));
                out.push((
                    "listAssignments",
                    call!(
                        f,
                        list_assignments,
                        credential,
                        json!({ "tenantId": tenant_id })
                    ),
                ));
                out.push((
                    "listSeats",
                    call!(f, list_seats, credential, json!({ "tenantId": tenant_id })),
                ));
                out.push((
                    "usage",
                    call!(f, usage, credential, json!({ "tenantId": tenant_id })),
                ));
                out.push((
                    "getSettings",
                    call!(
                        f,
                        get_settings,
                        credential,
                        json!({ "tenantId": tenant_id })
                    ),
                ));
            }
            "manage" => {
                out.push((
                    "createProduct",
                    call!(
                        f,
                        create_product,
                        credential,
                        json!({
                            "tenantId": tenant_id,
                            "key": format!("made-{}", subject_id.len()),
                            "name": "Made",
                        })
                    ),
                ));
                out.push((
                    "updateProduct",
                    call!(
                        f,
                        update_product,
                        credential,
                        json!({ "tenantId": tenant_id, "productId": pro_id, "name": "Renamed" })
                    ),
                ));
                out.push((
                    "addPool",
                    call!(
                        f,
                        add_pool,
                        credential,
                        json!({ "tenantId": tenant_id, "productId": pro_id, "quantity": 1 })
                    ),
                ));
                out.push((
                    "updatePool",
                    call!(
                        f,
                        update_pool,
                        credential,
                        json!({ "tenantId": tenant_id, "poolId": self.pool_id, "quantity": 3 })
                    ),
                ));
                out.push((
                    "configure",
                    call!(
                        f,
                        configure,
                        credential,
                        json!({ "tenantId": tenant_id, "notifyWaiting": true })
                    ),
                ));
            }
            "assign" => {
                out.push((
                    "assign",
                    call!(
                        f,
                        assign,
                        credential,
                        json!({
                            "tenantId": tenant_id,
                            "productId": pro_id,
                            "subjectType": "identity",
                            "subjectId": subject_id,
                        })
                    ),
                ));
                out.push((
                    "assignMany",
                    call!(
                        f,
                        assign_many,
                        credential,
                        json!({ "tenantId": tenant_id, "productId": pro_id, "identityIds": [subject_id] })
                    ),
                ));
                out.push((
                    "unassign",
                    call!(
                        f,
                        unassign,
                        credential,
                        json!({ "tenantId": tenant_id, "assignmentId": self.assignment_id })
                    ),
                ));
            }
            _ => {
                out.push((
                    "removePool",
                    call!(
                        f,
                        remove_pool,
                        credential,
                        json!({ "tenantId": tenant_id, "poolId": self.pool_id })
                    ),
                ));
                out.push((
                    "retireProduct",
                    call!(
                        f,
                        retire_product,
                        credential,
                        json!({ "tenantId": tenant_id, "productId": pro_id })
                    ),
                ));
            }
        }
        out
    }
}

#[test]
fn denies_every_administrative_call_to_members_without_license_actions_and_audits_it() {
    run(|| async {
        let a = access_scenario().await;
        let (dave, credential) = a.member("dave", &[]).await;
        for kind in ["read", "manage", "assign", "destructive"] {
            for (name, result) in a.calls(kind, &credential, &dave).await {
                let error = result.expect_err(name);
                assert_eq!(
                    (error.code.as_str(), error.status),
                    ("ACCESS_DENIED", 403),
                    "{name}"
                );
            }
        }
        let f = &a.s.f;
        // Their own licenses need no permission.
        assert_matches(
            &call!(f, mine, &credential, json!({ "tenantId": a.s.tenant_id })).unwrap(),
            json!({ "identityId": dave, "licenses": [] }),
        );
        let denials: Vec<String> = f
            .find("audit", Filter::new().eq("tenantId", a.s.tenant_id.clone()))
            .await
            .iter()
            .filter(|event| event["actorId"] == json!(dave) && event["outcome"] == json!("deny"))
            .map(|event| event["action"].as_str().unwrap().to_owned())
            .collect();
        let mut kinds = denials.clone();
        kinds.sort();
        kinds.dedup();
        assert_eq!(
            kinds,
            vec![
                "iam:licenses:assign",
                "iam:licenses:manage",
                "iam:licenses:read"
            ]
        );
        assert_eq!(denials.len(), 17);
        // Nothing changed.
        let seats = call!(
            f,
            list_seats,
            &a.s.owner,
            json!({ "tenantId": a.s.tenant_id })
        )
        .unwrap();
        assert_eq!(seats["seats"].as_array().unwrap().len(), 1);
        assert_matches(
            &seats["seats"][0],
            json!({ "identityId": a.s.alice, "status": "active" }),
        );
    });
}

#[test]
fn separates_reading_assigning_and_managing() {
    run(|| async {
        let a = access_scenario().await;
        let f = &a.s.f;
        let (_, reader) = a.member("reader", &["iam:licenses:read"]).await;
        let (assigner_id, assigner) = a
            .member("assigner", &["iam:licenses:read", "iam:licenses:assign"])
            .await;
        let (manager_id, manager) = a
            .member("manager", &["iam:licenses:read", "iam:licenses:manage"])
            .await;
        let bob = a.s.bob.clone();

        for (name, result) in a.calls("read", &reader, &bob).await {
            result.unwrap_or_else(|error| panic!("{name}: {error:?}"));
        }
        for kind in ["manage", "assign"] {
            for (name, result) in a.calls(kind, &reader, &bob).await {
                assert_eq!(result.expect_err(name).code, "ACCESS_DENIED", "{name}");
            }
        }

        let assign = a.calls("assign", &assigner, &bob).await;
        let mut assign = assign.into_iter();
        assert_matches(
            &assign.next().unwrap().1.unwrap(),
            json!({ "assignment": { "subjectId": bob, "assignedBy": assigner_id } }),
        );
        // assignMany for bob ran as well (skipped: he holds a direct assignment now).
        assign.next().unwrap().1.unwrap();
        assert_matches(
            &assign.next().unwrap().1.unwrap(),
            json!({ "removed": true }),
        );
        assert_matches(
            &call!(
                f,
                assign_many,
                &assigner,
                json!({ "tenantId": a.s.tenant_id, "productId": a.s.pro_id, "identityIds": [a.s.alice] })
            )
            .unwrap(),
            json!({ "assigned": [{ "subjectId": a.s.alice }] }),
        );
        for kind in ["manage", "destructive"] {
            for (name, result) in a.calls(kind, &assigner, &bob).await {
                assert_eq!(result.expect_err(name).code, "ACCESS_DENIED", "{name}");
            }
        }

        for (name, result) in a.calls("manage", &manager, &bob).await {
            result.unwrap_or_else(|error| panic!("{name}: {error:?}"));
        }
        for (name, result) in a.calls("assign", &manager, &bob).await {
            assert_eq!(result.expect_err(name).code, "ACCESS_DENIED", "{name}");
        }
        let removed = call!(
            f,
            remove_pool,
            &manager,
            json!({ "tenantId": a.s.tenant_id, "poolId": a.pool_id })
        )
        .unwrap();
        assert_matches(&removed, json!({ "removed": true }));
        // Retiring needs a recent sign-in as well as the permission.
        f.advance(6.0 * 60_000.0);
        fails_with(
            call!(
                f,
                retire_product,
                &manager,
                json!({ "tenantId": a.s.tenant_id, "productId": a.s.pro_id })
            ),
            "RECENT_AUTH_REQUIRED",
        );
        fails_with(
            call!(
                f,
                create_product,
                &manager,
                json!({ "tenantId": a.s.tenant_id, "key": "made-late", "name": "Made" })
            ),
            "RECENT_AUTH_REQUIRED",
        );
        let fresh = f.sign_in(&manager_id).await;
        assert_matches(
            &call!(
                f,
                retire_product,
                &fresh,
                json!({ "tenantId": a.s.tenant_id, "productId": a.s.pro_id })
            )
            .unwrap(),
            json!({ "product": { "status": "retired", "updatedBy": manager_id } }),
        );
    });
}

#[test]
fn keeps_platform_pools_to_root_administrators_and_lets_a_tenant_grant_its_own_products_below_it() {
    run(|| async {
        let a = access_scenario().await;
        let s = &a.s;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        let root_id = f.root_tenant.clone();
        let root = &f.root_credential;
        let suite = call!(
            f,
            create_product,
            root,
            json!({ "tenantId": root_id, "key": "suite", "name": "Suite" })
        )
        .unwrap();
        let suite_id = id_of(&suite);
        // Capacity of a platform product is bought from the platform: an owner cannot add it to their own tenant.
        fails_with(
            call!(
                f,
                add_pool,
                owner,
                json!({ "tenantId": tenant_id, "productId": suite_id, "quantity": 5 })
            ),
            "ACCESS_DENIED",
        );
        // Authorized in the root tenant, the refusal is recorded in the caller's own tenant, naming the target.
        let refused: Vec<Record> = f
            .find("audit", Filter::new())
            .await
            .into_iter()
            .filter(|event| {
                event["actorId"] == json!(f.owner_id) && event["outcome"] == json!("deny")
            })
            .collect();
        assert_eq!(refused.len(), 1);
        assert_matches(
            &Value::Object(refused[0].clone()),
            json!({
                "action": "iam:licenses:manage",
                "tenantId": tenant_id,
                "resourceId": "licenses/pools",
                "metadata": { "targetTenantId": root_id },
            }),
        );

        let granted = call!(
            f,
            add_pool,
            root,
            json!({ "tenantId": tenant_id, "productId": suite_id, "quantity": 3, "note": "Contract 42" })
        )
        .unwrap();
        let granted_id = id_of(&granted["pool"]);
        assert_matches(
            &granted["pool"],
            json!({ "tenantId": tenant_id, "tenantName": "Acme", "productKey": "suite" }),
        );
        // The grant is recorded where the capacity lands; the permission check where the product is defined.
        let added: Vec<Record> = f
            .find("audit", Filter::new().eq("tenantId", tenant_id.clone()))
            .await
            .into_iter()
            .filter(|event| {
                event["action"] == json!("license:pool-add")
                    && event["resourceId"] == json!(format!("licenses/pools/{granted_id}"))
            })
            .collect();
        assert_eq!(added.len(), 1);
        assert_matches(
            &Value::Object(added[0].clone()),
            json!({
                "actorId": f.root_id,
                "metadata": { "productKey": "suite", "quantity": 3, "source": "manual" },
            }),
        );
        assert!(
            f.find("audit", Filter::new().eq("tenantId", root_id.clone()))
                .await
                .iter()
                .any(|event| event["action"] == json!("iam:licenses:manage")
                    && event["outcome"] == json!("allow")
                    && event["resourceId"] == json!("licenses/pools"))
        );
        let mut keys = strings(
            &call!(f, list_pools, owner, json!({ "tenantId": tenant_id })).unwrap()["pools"],
            "productKey",
        );
        keys.sort();
        assert_eq!(keys, vec!["pro", "suite"]);
        // The root tenant sees the pools it granted.
        let granted_by_root = call!(f, list_pools, root, json!({ "tenantId": root_id })).unwrap();
        assert_same(
            &Value::Array(
                granted_by_root["pools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|pool| json!([pool["tenantName"], pool["productKey"]]))
                    .collect(),
            ),
            json!([["Acme", "suite"]]),
        );
        fails_with(
            call!(
                f,
                update_pool,
                owner,
                json!({ "tenantId": tenant_id, "poolId": granted_id, "quantity": 30 })
            ),
            "ACCESS_DENIED",
        );
        fails_with(
            call!(
                f,
                remove_pool,
                owner,
                json!({ "tenantId": tenant_id, "poolId": granted_id })
            ),
            "ACCESS_DENIED",
        );
        assert_matches(
            &call!(
                f,
                update_pool,
                root,
                json!({ "tenantId": tenant_id, "poolId": granted_id, "quantity": 4 })
            )
            .unwrap(),
            json!({ "pool": { "quantity": 4 } }),
        );
        // People of the tenant take the platform product's seats like any other.
        assert_matches(
            &call!(
                f,
                assign,
                owner,
                json!({
                    "tenantId": tenant_id,
                    "productId": suite_id,
                    "subjectType": "identity",
                    "subjectId": s.alice,
                })
            )
            .unwrap(),
            json!({ "seats": [{ "to": "active" }] }),
        );

        // Acme's own product can be granted to its project, by Acme's managers only.
        let (apollo_id, apollo_owner, apollo) = f
            .activate(&tenant_id, "Apollo", "project", "owner@apollo.test")
            .await;
        let for_apollo = call!(
            f,
            add_pool,
            owner,
            json!({ "tenantId": apollo_id, "productId": s.pro_id, "quantity": 1 })
        )
        .unwrap();
        let for_apollo_id = id_of(&for_apollo["pool"]);
        assert_matches(
            &for_apollo["pool"],
            json!({ "tenantId": apollo_id, "tenantName": "Apollo" }),
        );
        let mut names = strings(
            &call!(f, list_pools, owner, json!({ "tenantId": tenant_id })).unwrap()["pools"],
            "tenantName",
        );
        names.sort();
        assert_eq!(names, vec!["Acme", "Acme", "Apollo"]);
        assert_eq!(
            strings(
                &call!(f, list_pools, &apollo, json!({ "tenantId": apollo_id })).unwrap()["pools"],
                "id"
            ),
            vec![for_apollo_id.clone()]
        );
        fails_with(
            call!(
                f,
                add_pool,
                &apollo,
                json!({ "tenantId": apollo_id, "productId": s.pro_id, "quantity": 10 })
            ),
            "ACCESS_DENIED",
        );
        fails_with(
            call!(
                f,
                update_pool,
                &apollo,
                json!({ "tenantId": apollo_id, "poolId": for_apollo_id, "quantity": 10 })
            ),
            "ACCESS_DENIED",
        );
        fails_with(
            call!(
                f,
                remove_pool,
                &apollo,
                json!({ "tenantId": apollo_id, "poolId": for_apollo_id })
            ),
            "ACCESS_DENIED",
        );
        let seated = call!(
            f,
            assign,
            &apollo,
            json!({
                "tenantId": apollo_id,
                "productId": s.pro_id,
                "subjectType": "identity",
                "subjectId": apollo_owner,
            })
        )
        .unwrap();
        assert_eq!(seated["seats"].as_array().unwrap().len(), 1);
        assert_matches(
            &seated["seats"][0],
            json!({ "tenantId": apollo_id, "productKey": "pro", "to": "active" }),
        );
        // Acme's seats and Apollo's are counted apart.
        let acme_usage = call!(f, usage, owner, json!({ "tenantId": tenant_id })).unwrap();
        assert!(
            acme_usage["products"]
                .as_array()
                .unwrap()
                .iter()
                .any(|product| matches(
                    product,
                    &json!({ "key": "pro", "capacity": 2, "active": 1 })
                ))
        );
        let apollo_usage = call!(f, usage, &apollo, json!({ "tenantId": apollo_id })).unwrap();
        assert_eq!(apollo_usage["products"].as_array().unwrap().len(), 1);
        assert_matches(
            &apollo_usage["products"][0],
            json!({ "key": "pro", "capacity": 1, "active": 1, "assignments": 1 }),
        );
        assert_matches(
            &call!(
                f,
                update_pool,
                owner,
                json!({ "tenantId": apollo_id, "poolId": for_apollo_id, "quantity": 2 })
            )
            .unwrap(),
            json!({ "pool": { "quantity": 2 } }),
        );
    });
}

#[test]
fn is_routed_over_http() {
    run(|| async {
        let s = scenario().await;
        let f = &s.f;
        let token = s.owner.token.clone().unwrap();
        let (status, answer) = f
            .post(
                "licenses/listProducts",
                &token,
                json!({ "tenantId": s.tenant_id }),
            )
            .await;
        assert_eq!(status, 200, "{answer}");
        let products = &answer["data"]["products"];
        assert_eq!(strings(products, "key"), vec!["pro"]);
        let (status, answer) = f
            .post("licenses/mine", &token, json!({ "tenantId": s.tenant_id }))
            .await;
        assert_eq!(status, 200, "{answer}");
        assert_matches(
            &answer["data"],
            json!({ "identityId": f.owner_id, "licenses": [] }),
        );
    });
}

// --- tests/licenses-lifecycle.test.ts: jobs and notifications ---------------------------------------------------

/// A service account as `serviceAccounts.create` stores it.
async fn service_account(f: &Org, name: &str) -> String {
    let id = better_iam_server::utils::id();
    f.insert(
        "identities",
        json!({
            "id": id,
            "tenantId": f.tenant_id,
            "kind": "service",
            "name": name,
            "status": "active",
            "emailVerified": false,
            "rootAdmin": false,
            "owner": false,
            "createdAt": f.now(),
        }),
    )
    .await;
    id
}

/// The lifecycle suites' Acme: product "pro" with one seat, alice and bob (the birthright package is left out).
async fn lifecycle_scenario() -> (Scenario, String) {
    let s = scenario().await;
    let pool = call!(
        s.f,
        add_pool,
        &s.owner,
        json!({ "tenantId": s.tenant_id, "productId": s.pro_id, "quantity": 1 })
    )
    .unwrap();
    let pool_id = id_of(&pool["pool"]);
    (s, pool_id)
}

#[test]
fn reconciles_only_tenants_with_licenses() {
    run(|| async {
        let (s, _) = lifecycle_scenario().await;
        let (f, tenant_id) = (&s.f, s.tenant_id.clone());
        let licenses = &f.iam.licenses;
        assert_same(
            &licenses.reconcile(None).await.unwrap(),
            json!({ "tenants": 0, "activated": 0, "waiting": 0, "released": 0, "failedTenants": [] }),
        );
        s.assign(&s.alice).await.unwrap();
        assert_matches(
            &licenses.reconcile(None).await.unwrap(),
            json!({ "tenants": 1, "activated": 0 }),
        );
        let missing = licenses
            .reconcile(Some(&json!({ "tenantId": "missing" })))
            .await
            .unwrap_err();
        assert_eq!(missing.code, "NOT_FOUND");
        // Inconsistent state (a seat nobody claims any more) is repaired.
        let tenant = tenant_id.clone();
        f.iam
            .store
            .transaction(|tx| async move {
                for row in tx
                    .find(
                        "licenseAssignments",
                        &Filter::new().eq("tenantId", tenant),
                        &Default::default(),
                    )
                    .await?
                {
                    tx.delete("licenseAssignments", row["id"].as_str().unwrap())
                        .await?;
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_matches(
            &licenses
                .reconcile(Some(&json!({ "tenantId": tenant_id })))
                .await
                .unwrap(),
            json!({ "released": 1 }),
        );
        assert!(s.seats().await.is_empty());
        // Suspended tenants are left alone.
        s.assign(&s.alice).await.unwrap();
        let tenant = tenant_id.clone();
        f.iam
            .store
            .transaction(|tx| async move {
                for row in tx
                    .find(
                        "licenseSeats",
                        &Filter::new().eq("tenantId", tenant),
                        &Default::default(),
                    )
                    .await?
                {
                    tx.delete("licenseSeats", row["id"].as_str().unwrap())
                        .await?;
                }
                Ok(())
            })
            .await
            .unwrap();
        let mut realm = f
            .iam
            .store
            .get("tenants", &tenant_id)
            .await
            .unwrap()
            .unwrap();
        realm.insert("status".into(), json!("suspended"));
        f.put("tenants", realm).await;
        assert_matches(
            &licenses.reconcile(None).await.unwrap(),
            json!({ "tenants": 0 }),
        );
        assert_matches(
            &licenses
                .reconcile(Some(&json!({ "tenantId": tenant_id })))
                .await
                .unwrap(),
            json!({ "tenants": 0 }),
        );
    });
}

#[test]
fn reclaims_direct_assignments_of_people_inactive_for_the_configured_time() {
    run(|| async {
        let (s, pool_id) = lifecycle_scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        let licenses = &f.iam.licenses;
        call!(
            f,
            update_pool,
            owner,
            json!({ "tenantId": tenant_id, "poolId": pool_id, "quantity": 10 })
        )
        .unwrap();
        // Reclaim is off by default.
        assert_same(
            &licenses.reclaim(None).await.unwrap(),
            json!({ "tenants": 0, "reclaimed": [], "failedTenants": [] }),
        );
        call!(
            f,
            configure,
            owner,
            json!({ "tenantId": tenant_id, "reclaimAfterDays": 30 })
        )
        .unwrap();
        let carol = s.carol.clone();
        let dave = s.person("dave").await;
        let erin = s.person("erin").await;
        let robot = service_account(f, "robot").await;
        let key = f
            .iam
            .api
            .credentials
            .create(
                owner,
                body(json!({ "tenantId": tenant_id, "identityId": robot })),
            )
            .await
            .and_then(|reply| reply.into_value())
            .expect("api key");
        let field = create_group(f, owner, "Field").await;
        add_member(f, owner, &field, &erin, None).await;
        call!(
            f,
            assign,
            owner,
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "subjectType": "group",
                "subjectId": field,
            })
        )
        .unwrap();
        call!(
            f,
            assign_many,
            owner,
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "identityIds": [s.alice, s.bob, dave, robot],
            })
        )
        .unwrap();
        let created_at = |identity: String| async move {
            f.iam
                .store
                .get("identities", &identity)
                .await
                .unwrap()
                .unwrap()["createdAt"]
                .clone()
        };
        // Day 2: dave is disabled (as identities.setStatus stores it, reconciling his seats). Day 15: the robot's key
        // is used. Day 20: alice signs in. Day 25: carol gets Pro.
        f.advance(2.0 * DAY);
        let mut disabled = f.iam.store.get("identities", &dave).await.unwrap().unwrap();
        disabled.insert("status".into(), json!("disabled"));
        f.put("identities", disabled).await;
        better_iam_server::licenses::reconcile_licenses_of(
            &f.iam.ctx,
            &tenant_id,
            std::slice::from_ref(&dave),
            None,
        )
        .await
        .unwrap();
        f.advance(13.0 * DAY);
        call!(
            f,
            mine,
            &bearer(key["token"].as_str().unwrap()),
            json!({ "tenantId": tenant_id })
        )
        .unwrap();
        f.advance(5.0 * DAY);
        f.sign_in(&s.alice).await;
        f.advance(5.0 * DAY);
        let admin = f.session(&f.owner_id, false).await;
        call!(
            f,
            assign,
            &admin,
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "subjectType": "identity",
                "subjectId": carol,
            })
        )
        .unwrap();
        f.advance(6.0 * DAY);
        let current = f.session(&f.owner_id, false).await;
        // Usage reports inactive active seats, including those held through groups.
        assert_matches(
            &call!(f, usage, &current, json!({ "tenantId": tenant_id })).unwrap()["products"][0],
            json!({ "active": 5, "reclaimable": 2, "reclaimableThroughGroups": 1 }),
        );

        let result = licenses.reclaim(None).await.unwrap();
        assert_same(&result["tenants"], json!(1));
        assert_same(&result["failedTenants"], json!([]));
        let reclaimed = result["reclaimed"].as_array().unwrap();
        assert_eq!(
            sorted(strings(&result["reclaimed"], "identityId")),
            sorted(vec![s.bob.clone(), dave.clone()])
        );
        assert_same(
            reclaimed
                .iter()
                .find(|item| item["identityId"] == json!(s.bob))
                .unwrap(),
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "productKey": "pro",
                "identityId": s.bob,
                "lastActivityAt": created_at(s.bob.clone()).await,
            }),
        );
        let seats = call!(f, list_seats, &current, json!({ "tenantId": tenant_id })).unwrap();
        let held: HashMap<String, Value> = seats["seats"]
            .as_array()
            .unwrap()
            .iter()
            .map(|seat| {
                (
                    seat["identityId"].as_str().unwrap().to_owned(),
                    seat.clone(),
                )
            })
            .collect();
        assert_eq!(
            sorted(held.keys().cloned().collect()),
            sorted(vec![
                s.alice.clone(),
                carol.clone(),
                erin.clone(),
                robot.clone()
            ])
        );
        // The pass records what it saw on each seat.
        assert_same(
            &held[&s.alice]["lastActivityAt"],
            json!(f.now() - 11.0 * DAY),
        );
        assert_same(&held[&robot]["lastActivityAt"], json!(f.now() - 16.0 * DAY));
        assert_same(
            &held[&erin]["lastActivityAt"],
            created_at(erin.clone()).await,
        );
        assert_eq!(
            sorted(strings(
                &call!(
                    f,
                    list_assignments,
                    &current,
                    json!({ "tenantId": tenant_id, "subjectType": "identity" })
                )
                .unwrap()["assignments"],
                "subjectId"
            )),
            sorted(vec![s.alice.clone(), carol.clone(), robot.clone()])
        );
        assert_matches(
            &call!(f, usage, &current, json!({ "tenantId": tenant_id })).unwrap()["products"][0],
            json!({ "active": 4, "reclaimable": 1, "reclaimableThroughGroups": 1 }),
        );
        let reclaims = trail(f, &tenant_id, "license:reclaim").await;
        assert_eq!(
            sorted(
                reclaims
                    .iter()
                    .map(|event| event["resourceId"].as_str().unwrap().to_owned())
                    .collect()
            ),
            sorted(vec![s.bob.clone(), dave.clone()])
        );
        assert_matches(
            &Value::Object(
                reclaims
                    .iter()
                    .find(|event| event["resourceId"] == json!(s.bob))
                    .unwrap()
                    .clone(),
            ),
            json!({
                "actorId": "deployment-operator",
                "metadata": {
                    "productId": s.pro_id,
                    "productKey": "pro",
                    "lastActivityAt": created_at(s.bob.clone()).await,
                    "reclaimAfterDays": 30,
                },
            }),
        );
        assert_matches(
            &Value::Object(
                trail(f, &tenant_id, "license:seat-release")
                    .await
                    .pop()
                    .unwrap(),
            ),
            json!({ "resourceId": s.bob, "metadata": { "reason": "reclaim" } }),
        );
        // A second pass finds nothing more; turning reclaim off stops it.
        assert_same(
            &licenses
                .reclaim(Some(&json!({ "tenantId": tenant_id })))
                .await
                .unwrap()["reclaimed"],
            json!([]),
        );
        call!(
            f,
            configure,
            &current,
            json!({ "tenantId": tenant_id, "reclaimAfterDays": null })
        )
        .unwrap();
        let off = json!({ "tenants": 0, "reclaimed": [], "failedTenants": [] });
        assert_same(
            &licenses
                .reclaim(Some(&json!({ "tenantId": tenant_id })))
                .await
                .unwrap(),
            off.clone(),
        );
        assert_same(&licenses.reclaim(None).await.unwrap(), off);
        let missing = licenses
            .reclaim(Some(&json!({ "tenantId": "missing" })))
            .await
            .unwrap();
        assert_matches(
            &missing,
            json!({ "tenants": 0, "failedTenants": [{ "tenantId": "missing", "code": "NOT_FOUND" }] }),
        );
    });
}

#[test]
fn emails_people_when_they_join_the_waiting_list_and_when_their_seat_is_ready_when_asked_to() {
    run(|| async {
        let (s, _) = lifecycle_scenario().await;
        let (f, tenant_id, owner) = (&s.f, s.tenant_id.clone(), &s.owner);
        let mail = || async {
            f.iam.auth.dispatch_outbox(None).await.unwrap();
            s.inbox
                .lock()
                .unwrap()
                .iter()
                .filter(|message| message.template.starts_with("license-"))
                .cloned()
                .collect::<Vec<DeliveryMessage>>()
        };
        s.assign(&s.alice).await.unwrap();
        s.assign(&s.bob).await.unwrap();
        assert!(mail().await.is_empty());
        call!(
            f,
            configure,
            owner,
            json!({ "tenantId": tenant_id, "notifyWaiting": true })
        )
        .unwrap();
        s.assign(&s.carol).await.unwrap();
        let robot = service_account(f, "robot").await;
        s.names
            .lock()
            .unwrap()
            .insert(robot.clone(), "robot".into());
        s.assign(&robot).await.unwrap();
        let waiting = mail().await;
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].tenant_id, tenant_id);
        assert_eq!(waiting[0].to, "carol@acme.test");
        assert_eq!(waiting[0].template, "license-waiting");
        assert_same(
            &Value::Object(waiting[0].payload.clone()),
            json!({ "tenantId": tenant_id, "tenantName": "Acme", "productKey": "pro", "productName": "Pro" }),
        );
        assert_eq!(
            better_iam_auth::templates::render_delivery_message(
                &(&waiting[0]).into(),
                &Default::default()
            )
            .expect("rendered")
            .subject,
            "You are on the waiting list for Pro"
        );
        call!(
            f,
            unassign,
            owner,
            json!({
                "tenantId": tenant_id,
                "productId": s.pro_id,
                "subjectType": "identity",
                "subjectId": s.alice,
            })
        )
        .unwrap();
        let all = mail().await;
        assert_eq!(
            all.iter()
                .map(|message| (message.to.as_str(), message.template.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("carol@acme.test", "license-waiting"),
                ("bob@acme.test", "license-activated")
            ]
        );
        assert_eq!(
            better_iam_auth::templates::render_delivery_message(
                &(&all[1]).into(),
                &Default::default()
            )
            .expect("rendered")
            .subject,
            "Your Pro seat is ready"
        );
        assert_eq!(
            s.seats().await,
            vec!["bob active", "carol waiting #1", "robot waiting #2"]
        );
    });
}
