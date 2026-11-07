//! The `protection` API group and `iam.protection.sweep()`: ported from tests/protection.test.ts and the API-level
//! cases of tests/protection-security.test.ts. Members and their grants come from the organization fixture (written
//! as `identities.create`, `roles.create` and `bindings.create` write them).
//!
//! Every profile, token and mask goes through tokenization.ts and the KMS service helpers of kms.ts, which belong to
//! other units and are still stubs: the end-to-end cases are ported and ignored until those land. Input validation
//! (which runs before anything is looked up) and the retention sweep (which reads and writes stored records only) run
//! now.

mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_core::{
    CredentialInput, Filter, IamPlugin, IamResult, OperationHookInput, PluginHooks, Record,
};
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use regex::Regex;
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;

/// A JavaScript number as the API answers it (`1`, not `1.0`).
fn n(value: f64) -> Value {
    better_iam_server::js::number(value)
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn luhn(digits: &str) -> bool {
    let mut sum = 0;
    for (index, char) in digits.chars().rev().enumerate() {
        let mut digit = char.to_digit(10).unwrap();
        if index % 2 == 1 {
            digit = if digit * 2 > 9 {
                digit * 2 - 9
            } else {
                digit * 2
            };
        }
        sum += digit;
    }
    sum % 10 == 0
}

/// A member of the organization with an inline grant, and a fresh session.
async fn member_with(f: &Org, name: &str, statements: Value) -> CredentialInput {
    let person = f.member(name).await;
    f.grant(&person, statements).await;
    f.sign_in(&person).await
}

async fn audit_of(f: &Org, action: &str) -> Vec<Record> {
    f.find("audit", Filter::new().eq("tenantId", f.tenant_id.clone()))
        .await
        .into_iter()
        .filter(|event| event["action"] == action)
        .collect()
}

async fn create_profile(f: &Org, input: Value) -> Value {
    let mut input = input;
    input["tenantId"] = json!(f.tenant_id);
    ok(f.iam
        .api
        .protection
        .create_profile(&f.owner_credential, body(input))
        .await)
}

async fn tokenize(f: &Org, credential: &CredentialInput, profile: &str, values: Value) -> Value {
    ok(f.iam
        .api
        .protection
        .tokenize(
            credential,
            body(json!({ "tenantId": f.tenant_id, "profile": profile, "values": values })),
        )
        .await)["tokens"]
        .clone()
}

/// A profile and its tokens as `protection.createProfile` and `protection.tokenize` store them.
async fn seed_profile(f: &Org, name: &str, retention_days: Option<f64>, tokens: f64) -> Record {
    let id = uuid();
    let mut profile = json!({
        "id": id,
        "tenantId": f.tenant_id,
        "uniqueKey": format!("name:{name}"),
        "name": name,
        "dataType": "email",
        "format": "format-preserving",
        "deterministic": false,
        "keyId": uuid(),
        "mask": "email",
        "lookupKeyWrapped": "kms1.key.1.wrapped",
        "tokens": tokens,
        "createdAt": n(f.now()),
        "createdBy": f.owner_id,
        "updatedAt": n(f.now()),
    });
    if let Some(days) = retention_days {
        profile["retentionDays"] = n(days);
    }
    f.insert("protectionProfiles", profile).await
}

async fn seed_token(f: &Org, profile: &Record, created_at: f64) -> String {
    let id = uuid();
    let token = format!("tok_{}", id.replace('-', ""));
    f.insert(
        "protectionTokens",
        json!({
            "id": id,
            "tenantId": profile["tenantId"],
            "uniqueKey": format!("token:{}:{}", profile["id"].as_str().unwrap(), token),
            "profileId": profile["id"],
            "token": token,
            "fingerprint": uuid(),
            "wrapped": "kms1.key.1.batch",
            "sealed": "sealed",
            "createdAt": n(created_at),
            "createdBy": f.owner_id,
        }),
    )
    .await;
    id
}

async fn get(f: &Org, collection: &str, record_id: &str) -> Option<Record> {
    f.find(collection, Filter::new().eq("id", record_id.to_owned()))
        .await
        .into_iter()
        .next()
}

#[test]
fn validates_batches_tokens_and_purposes_before_anything_is_looked_up() {
    run(|| async {
        let f = organization(|_| {}).await;
        let protection = f.iam.api.protection.clone();
        let base = json!({ "tenantId": f.tenant_id, "profile": "cards" });
        let with = |extra: Value| {
            let mut input = base.clone();
            for (key, value) in extra.as_object().unwrap() {
                input[key] = value.clone();
            }
            input
        };
        let hundred_and_one: Vec<String> = (0..101).map(|index| format!("v{index}")).collect();
        for values in [
            json!("4242"),
            json!([]),
            json!(hundred_and_one),
            Value::Null,
        ] {
            let error = fails(
                protection
                    .tokenize(&f.owner_credential, body(with(json!({ "values": values }))))
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT");
            assert_eq!(error.message, "values must list 1 to 100 entries");
        }
        let long = "x".repeat(4097);
        for tokens in [
            json!([42]),
            json!([""]),
            json!(["tok\u{0007}"]),
            json!([long]),
            json!([Value::Null]),
        ] {
            let error = fails(
                protection
                    .detokenize(
                        &f.owner_credential,
                        body(with(json!({ "tokens": tokens, "purpose": "support" }))),
                    )
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT");
            assert_eq!(error.message, "Every token must be a string");
            let error = fails(
                protection
                    .mask(&f.owner_credential, body(with(json!({ "tokens": tokens }))))
                    .await,
            );
            assert_eq!(error.message, "Every token must be a string");
        }
        let error = fails(
            protection
                .detokenize(&f.owner_credential, body(with(json!({ "tokens": "tok" }))))
                .await,
        );
        assert_eq!(error.message, "tokens must list 1 to 100 entries");
        for purpose in [
            json!("Not A Purpose"),
            json!("9lives"),
            json!("x".repeat(65)),
        ] {
            let error = fails(
                protection
                    .detokenize(
                        &f.owner_credential,
                        body(with(json!({ "tokens": ["tok"], "purpose": purpose }))),
                    )
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT");
        }
        let error = fails(
            protection
                .detokenize(
                    &f.owner_credential,
                    body(with(
                        json!({ "tokens": ["tok"], "purpose": "Not-A-Purpose" }),
                    )),
                )
                .await,
        );
        assert_eq!(
            error.message,
            "purpose is a short lowercase name, such as payment-processing or fraud-review"
        );
        for extra in [
            json!({}),
            json!({ "tokens": ["tok"], "values": ["ann@acme.test"] }),
        ] {
            let error = fails(
                protection
                    .delete_tokens(&f.owner_credential, body(with(extra)))
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT");
            assert_eq!(error.message, "Name either tokens or values");
        }
        let error = fails(
            protection
                .delete_tokens(&f.owner_credential, body(with(json!({ "values": [] }))))
                .await,
        );
        assert_eq!(error.message, "values must list 1 to 100 entries");
        // Validation happens before authentication: an anonymous caller learns nothing more.
        let error = fails(
            protection
                .tokenize(
                    &CredentialInput::default(),
                    body(with(json!({ "values": [] }))),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
fn sweep_deletes_tokens_past_their_profiles_retention_in_batches_and_audits_each_profile() {
    run(|| async {
        let f = organization(|_| {}).await;
        let now = f.now();
        // 501 old tokens span two sweep batches (500 per transaction); one fresh token stays.
        let emails = seed_profile(&f, "emails", Some(1.0), 502.0).await;
        for offset in 0..501 {
            seed_token(&f, &emails, now - 2.0 * DAY - f64::from(offset)).await;
        }
        let fresh = seed_token(&f, &emails, now).await;
        // A profile without retention keeps its tokens whatever their age.
        let notes = seed_profile(&f, "notes", None, 1.0).await;
        let kept = seed_token(&f, &notes, now - 400.0 * DAY).await;
        let result = f.iam.protection.sweep(None).await.unwrap();
        assert_eq!(result, json!({ "deleted": 501, "profiles": 1 }));
        assert!(get(&f, "protectionTokens", &fresh).await.is_some());
        assert!(get(&f, "protectionTokens", &kept).await.is_some());
        let stored = get(&f, "protectionProfiles", emails["id"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(stored["tokens"], json!(1));
        let events = audit_of(&f, "protection:retention-sweep").await;
        assert_eq!(events.len(), 1);
        assert_matches(
            &Value::Object(events[0].clone()),
            json!({
                "tenantId": f.tenant_id,
                "actorId": "deployment-operator",
                "resourceId": "protection/emails",
                "outcome": "allow",
                "metadata": { "deleted": 501, "retentionDays": 1 },
            }),
        );
        // Nothing left to delete: no new audit event.
        assert_eq!(
            f.iam.protection.sweep(None).await.unwrap(),
            json!({ "deleted": 0, "profiles": 1 })
        );
        assert_eq!(audit_of(&f, "protection:retention-sweep").await.len(), 1);
        // The conformance entry: `sweep()` and `sweep({ tenantId })`.
        f.advance(2.0 * DAY);
        assert_eq!(
            f.iam
                .protection
                .call("sweep", vec![json!({ "tenantId": f.root_tenant })])
                .await
                .unwrap()
                .unwrap(),
            json!({ "deleted": 0, "profiles": 0 })
        );
        assert_eq!(
            f.iam
                .protection
                .call("sweep", vec![])
                .await
                .unwrap()
                .unwrap(),
            json!({ "deleted": 1, "profiles": 1 })
        );
        let error = f
            .iam
            .protection
            .sweep(Some(&json!({ "tenantId": 42 })))
            .await
            .unwrap_err();
        assert_eq!(code(&error), "INVALID_INPUT");
        assert!(f.iam.protection.call("other", vec![]).await.is_none());
    });
}

#[test]
fn sweep_never_takes_the_token_counter_below_zero() {
    run(|| async {
        let f = organization(|_| {}).await;
        let profile = seed_profile(&f, "emails", Some(30.0), 0.0).await;
        seed_token(&f, &profile, f.now()).await;
        f.advance(31.0 * DAY);
        assert_eq!(
            f.iam
                .protection
                .sweep(Some(&json!({ "tenantId": f.tenant_id })))
                .await
                .unwrap(),
            json!({ "deleted": 1, "profiles": 1 })
        );
        let stored = get(&f, "protectionProfiles", profile["id"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(stored["tokens"], json!(0));
    });
}

#[test]
#[ignore = "blocked on tokenization.ts and kms.ts (profileName, kmsDataKeyFor, ... are stubs)"]
fn tokenizes_card_numbers_into_format_preserving_tokens_and_back() {
    run(|| async {
        let f = organization(|_| {}).await;
        let protection = f.iam.api.protection.clone();
        let profile = create_profile(
            &f,
            json!({ "name": "cards", "dataType": "card", "deterministic": true }),
        )
        .await;
        assert_matches(
            &profile,
            json!({ "format": "format-preserving", "mask": "last4", "deterministic": true }),
        );
        let cards = [
            "4242 4242 4242 4242",
            "5555-5555-5555-4444",
            "4242424242424242",
        ];
        let tokens = tokenize(&f, &f.owner_credential, "cards", json!(cards)).await;
        let tokens: Vec<String> = tokens
            .as_array()
            .unwrap()
            .iter()
            .map(|token| token.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(tokens.len(), 3);
        // Deterministic: the same card (however it is spelled) gets the same token.
        assert_eq!(tokens[0], tokens[2]);
        let sixteen = Regex::new(r"^\d{16}$").unwrap();
        for (index, token) in tokens.iter().enumerate() {
            assert!(sixteen.is_match(token));
            let digits: String = cards[index].chars().filter(char::is_ascii_digit).collect();
            assert_eq!(&token[12..], &digits[12..]);
            // A token is never mistaken for a card number.
            assert!(!luhn(token));
        }
        let again = tokenize(
            &f,
            &f.owner_credential,
            "cards",
            json!(["4242424242424242"]),
        )
        .await;
        assert_eq!(again, json!([tokens[0]]));

        let mut asked = tokens.clone();
        asked.push("0000000000004242".into());
        let values = ok(protection
            .detokenize(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "profile": "cards",
                    "tokens": asked,
                    "purpose": "payment-processing",
                })),
            )
            .await);
        assert_eq!(
            values["values"],
            json!([
                "4242424242424242",
                "5555555555554444",
                "4242424242424242",
                null
            ])
        );
        let masked = ok(protection
            .mask(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "profile": "cards", "tokens": [tokens[1]] })),
            )
            .await);
        assert_eq!(masked["values"], json!(["************4444"]));
        let first_six = ok(protection
            .mask(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "profile": "cards",
                    "tokens": [tokens[1]],
                    "style": "first6last4",
                })),
            )
            .await);
        assert_eq!(first_six["values"], json!(["555555******4444"]));

        // Invalid cards are refused, not tokenized.
        let error = fails(
            protection
                .tokenize(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "profile": "cards", "values": ["4242424242424241"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");

        // Neither values nor tokens reach the audit trail or the store in the clear.
        let events = f
            .find("audit", Filter::new().eq("tenantId", f.tenant_id.clone()))
            .await;
        let text = serde_json::to_string(&events).unwrap();
        assert!(!text.contains("4242424242424242"));
        assert!(!text.contains(&tokens[1]));
        let detokenized = events
            .iter()
            .find(|event| event["action"] == "iam:protection:detokenize")
            .unwrap();
        // Four tokens asked for; two distinct stored tokens (the deterministic profile reused one).
        assert_matches(
            &detokenized["metadata"],
            json!({ "purpose": "payment-processing", "count": 4, "found": 2 }),
        );
        let stored = serde_json::to_string(
            &f.find(
                "protectionTokens",
                Filter::new().eq("tenantId", f.tenant_id.clone()),
            )
            .await,
        )
        .unwrap();
        assert!(!stored.contains("4242424242424242"));
        assert!(!stored.contains("5555555555554444"));
    });
}

#[test]
#[ignore = "blocked on tokenization.ts and kms.ts (profileName, kmsDataKeyFor, ... are stubs)"]
fn keeps_each_data_type_recognizable_and_masks_it_for_display() {
    run(|| async {
        let f = organization(|_| {}).await;
        let protection = f.iam.api.protection.clone();
        let cases = [
            (
                "ssns",
                "ssn",
                "123-45-6789",
                r"^9\d\d-\d\d-6789$",
                "***-**-6789",
            ),
            (
                "emails",
                "email",
                "Jane.Doe@Example.com",
                r"^[a-z0-9]{16}@example\.com$",
                "j***@example.com",
            ),
            (
                "phones",
                "phone",
                "+1 (415) 555-0199",
                r"^\+\d{7}0199$",
                "+*******0199",
            ),
            (
                "notes",
                "generic",
                "patient allergic to penicillin",
                r"^tok_[0-9A-Za-z]{22}$",
                "******* ******** ** **********",
            ),
        ];
        for (name, data_type, value, shape, masked) in cases {
            create_profile(&f, json!({ "name": name, "dataType": data_type })).await;
            let token = tokenize(&f, &f.owner_credential, name, json!([value])).await[0].clone();
            assert!(Regex::new(shape).unwrap().is_match(token.as_str().unwrap()));
            let shown = ok(protection
                .mask(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "profile": name, "tokens": [token] })),
                )
                .await);
            assert_eq!(shown["values"], json!([masked]));
        }
        // Non-deterministic profiles issue a new token each time; format-preserving SSNs are always deterministic.
        let first = tokenize(
            &f,
            &f.owner_credential,
            "emails",
            json!(["jane.doe@example.com", "JANE.DOE@example.com"]),
        )
        .await;
        assert_ne!(first[0], first[1]);
        let ssns = tokenize(
            &f,
            &f.owner_credential,
            "ssns",
            json!(["123-45-6789", "123456789"]),
        )
        .await;
        assert_eq!(ssns[0], ssns[1]);
        // Format-preserving generic tokens keep each character's class.
        create_profile(
            &f,
            json!({ "name": "accounts", "dataType": "generic", "format": "format-preserving" }),
        )
        .await;
        let account = tokenize(
            &f,
            &f.owner_credential,
            "accounts",
            json!(["DE89-3704-0044-0532-0130-00"]),
        )
        .await[0]
            .clone();
        assert!(
            Regex::new(r"^[A-Z]{2}\d{2}-\d{4}-\d{4}-\d{4}-\d{4}-\d{2}$")
                .unwrap()
                .is_match(account.as_str().unwrap())
        );
        let error = fails(
            protection
                .tokenize(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "profile": "accounts", "values": ["AB-12"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
#[ignore = "blocked on tokenization.ts and kms.ts (profileName, kmsDataKeyFor, ... are stubs)"]
fn decides_detokenizing_by_profile_and_purpose_apart_from_tokenizing_and_masking() {
    run(|| async {
        let f = organization(|_| {}).await;
        let protection = f.iam.api.protection.clone();
        create_profile(&f, json!({ "name": "cards", "dataType": "card" })).await;
        create_profile(&f, json!({ "name": "ssns", "dataType": "ssn" })).await;
        let card = tokenize(
            &f,
            &f.owner_credential,
            "cards",
            json!(["4242424242424242"]),
        )
        .await[0]
            .clone();
        // Checkout may tokenize cards and detokenize them for payments only; support may only see masks.
        let checkout = member_with(
            &f,
            "checkout",
            json!([
                { "effect": "allow", "actions": ["iam:protection:tokenize"], "resources": ["iam/protection/cards"] },
                {
                    "effect": "allow",
                    "actions": ["iam:protection:detokenize"],
                    "resources": ["iam/protection/cards"],
                    "conditions": { "StringEquals": { "resource.purpose": "payment-processing" } },
                },
            ]),
        )
        .await;
        let support = member_with(
            &f,
            "support",
            json!([{ "effect": "allow", "actions": ["iam:protection:mask"], "resources": ["iam/protection/*"] }]),
        )
        .await;
        let detokenize = |credential: CredentialInput, purpose: &str| {
            let api = protection.clone();
            let input = json!({ "tenantId": f.tenant_id, "profile": "cards", "tokens": [card], "purpose": purpose });
            async move { api.detokenize(&credential, body(input)).await }
        };
        assert_eq!(
            ok(detokenize(checkout.clone(), "payment-processing").await),
            json!({ "values": ["4242424242424242"] })
        );
        let error = fails(detokenize(checkout.clone(), "marketing").await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            protection
                .tokenize(
                    &checkout,
                    body(json!({ "tenantId": f.tenant_id, "profile": "ssns", "values": ["123-45-6789"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(detokenize(support.clone(), "payment-processing").await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_eq!(
            ok(protection
                .mask(
                    &support,
                    body(json!({ "tenantId": f.tenant_id, "profile": "cards", "tokens": [card] })),
                )
                .await),
            json!({ "values": ["************4242"] })
        );
        let error = fails(detokenize(checkout.clone(), "Not A Purpose").await);
        assert_eq!(code(&error), "INVALID_INPUT");
        // Denials are audited with the purpose asked for.
        let denied = audit_of(&f, "iam:protection:detokenize")
            .await
            .into_iter()
            .filter(|event| event["outcome"] == "deny")
            .count();
        assert!(denied >= 2);
    });
}

#[test]
#[ignore = "blocked on tokenization.ts and kms.ts (profileName, kmsDataKeyFor, ... are stubs)"]
fn erases_by_token_or_by_value_sweeps_by_retention_and_follows_its_kms_key() {
    run(|| async {
        let f = organization(|_| {}).await;
        let protection = f.iam.api.protection.clone();
        let profile = create_profile(
            &f,
            json!({ "name": "emails", "dataType": "email", "retentionDays": 30 }),
        )
        .await;
        let tokens = tokenize(
            &f,
            &f.owner_credential,
            "emails",
            json!(["ann@acme.test", "ann@acme.test", "bob@acme.test"]),
        )
        .await;
        // Erasure by value finds every token issued for it, deterministic profile or not.
        assert_eq!(
            ok(protection
                .delete_tokens(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "profile": "emails", "values": ["ANN@acme.test"] })),
                )
                .await),
            json!({ "deleted": 2 })
        );
        let after = ok(protection
            .detokenize(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "profile": "emails", "tokens": tokens, "purpose": "support" })),
            )
            .await);
        assert_eq!(after["values"], json!([null, null, "bob@acme.test"]));

        // Disabling the profile's KMS key makes every value unreadable (crypto-shredding while disabled).
        let key = json!({ "tenantId": f.tenant_id, "keyId": profile["keyId"] });
        ok(f.iam
            .api
            .keys
            .disable(&f.owner_credential, body(key.clone()))
            .await);
        let error = fails(
            protection
                .detokenize(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "profile": "emails", "tokens": [tokens[2]], "purpose": "support" })),
                )
                .await,
        );
        assert_eq!(code(&error), "KEY_STATE_INVALID");
        ok(f.iam
            .api
            .keys
            .enable(&f.owner_credential, body(key.clone()))
            .await);

        // Retention: the daily sweep deletes tokens past 30 days.
        f.advance(31.0 * DAY);
        assert_eq!(
            f.iam.protection.sweep(None).await.unwrap(),
            json!({ "deleted": 1, "profiles": 1 })
        );
        let owner = f.sign_in(&f.owner_id).await;
        assert_matches(
            &ok(protection
                .get_profile(
                    &owner,
                    body(json!({ "tenantId": f.tenant_id, "profile": "emails" })),
                )
                .await),
            json!({ "tokens": 0 }),
        );
        assert_eq!(
            ok(protection
                .delete_profile(
                    &owner,
                    body(json!({ "tenantId": f.tenant_id, "profile": "emails" })),
                )
                .await),
            json!({ "success": true })
        );
    });
}

struct Spy(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl PluginHooks for Spy {
    async fn after_operation(&self, input: &OperationHookInput, result: &Value) -> IamResult<()> {
        if input.action.starts_with("iam:protection:") {
            self.0.lock().unwrap().push(result.clone());
        }
        Ok(())
    }
}

struct SpyPlugin(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl IamPlugin for SpyPlugin {
    fn id(&self) -> &str {
        "spy"
    }
    fn hooks(&self) -> Option<Arc<dyn PluginHooks>> {
        Some(Arc::new(Spy(self.0.clone())))
    }
}

#[test]
#[ignore = "blocked on tokenization.ts and kms.ts (profileName, kmsDataKeyFor, ... are stubs)"]
fn audits_refusals_with_the_purpose_guards_retention_and_tidies_up_after_itself() {
    run(|| async {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let plugin = SpyPlugin(seen.clone());
        let f = organization(move |options| options.plugins = Some(vec![Arc::new(plugin)])).await;
        let protection = f.iam.api.protection.clone();
        let profile = create_profile(&f, json!({ "name": "emails", "dataType": "email" })).await;
        let tokens = tokenize(
            &f,
            &f.owner_credential,
            "emails",
            json!(["ann@acme.test", "bob@acme.test"]),
        )
        .await;
        // Plugins never see tokens (format-preserving ones keep the domain).
        assert!(
            !serde_json::to_string(&*seen.lock().unwrap())
                .unwrap()
                .contains("@acme.test")
        );

        let clerk = member_with(
            &f,
            "clerk",
            json!([{ "effect": "allow", "actions": ["iam:protection:manage"], "resources": ["iam/protection/*"] }]),
        )
        .await;
        let error = fails(
            protection
                .detokenize(
                    &clerk,
                    body(json!({ "tenantId": f.tenant_id, "profile": "emails", "tokens": tokens, "purpose": "marketing" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let refusal = audit_of(&f, "iam:protection:detokenize")
            .await
            .into_iter()
            .find(|event| event["outcome"] == "deny")
            .unwrap();
        assert_matches(
            &refusal["metadata"],
            json!({ "profile": "emails", "purpose": "marketing" }),
        );
        // Managing a profile is not deleting its tokens: a retention of one day would.
        let error = fails(
            protection
                .update_profile(
                    &clerk,
                    body(
                        json!({ "tenantId": f.tenant_id, "profile": "emails", "retentionDays": 1 }),
                    ),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_matches(
            &ok(protection
                .update_profile(
                    &clerk,
                    body(json!({ "tenantId": f.tenant_id, "profile": "emails", "description": "Customer email addresses" })),
                )
                .await),
            json!({ "description": "Customer email addresses" }),
        );
        let owner = f.sign_in(&f.owner_id).await;
        ok(protection
            .update_profile(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "profile": "emails", "retentionDays": 1 })),
            )
            .await);
        f.advance(2.0 * DAY);
        assert_eq!(
            f.iam.protection.sweep(None).await.unwrap(),
            json!({ "deleted": 2, "profiles": 1 })
        );
        assert_matches(
            &Value::Object(audit_of(&f, "protection:retention-sweep").await[0].clone()),
            json!({
                "actorId": "deployment-operator",
                "resourceId": "protection/emails",
                "metadata": { "deleted": 2, "retentionDays": 1 },
            }),
        );

        // A value altered in storage fails as such, not as a crash.
        let fresh = tokenize(&f, &owner, "emails", json!(["cy@acme.test"])).await;
        let mut stored = f
            .find(
                "protectionTokens",
                Filter::new().eq("tenantId", f.tenant_id.clone()),
            )
            .await[0]
            .clone();
        let sealed = stored["sealed"].as_str().unwrap().to_owned();
        let flipped = if &sealed[20..21] == "A" { "B" } else { "A" };
        stored.insert(
            "sealed".into(),
            json!(format!("{}{}{}", &sealed[..20], flipped, &sealed[21..])),
        );
        f.put("protectionTokens", stored).await;
        let error = fails(
            protection
                .detokenize(
                    &owner,
                    body(json!({ "tenantId": f.tenant_id, "profile": "emails", "tokens": fresh, "purpose": "support" })),
                )
                .await,
        );
        assert_eq!(code(&error), "KEY_MATERIAL_UNAVAILABLE");
        ok(protection
            .delete_tokens(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "profile": "emails", "tokens": fresh })),
            )
            .await);

        // Deleting the profile retires the key it created (after a fresh sign-in: two days went by).
        let fresh_owner = f.sign_in(&f.owner_id).await;
        ok(protection
            .delete_profile(
                &fresh_owner,
                body(json!({ "tenantId": f.tenant_id, "profile": "emails" })),
            )
            .await);
        assert_matches(
            &ok(f
                .iam
                .api
                .keys
                .get(
                    &owner,
                    body(json!({ "tenantId": f.tenant_id, "keyId": profile["keyId"] })),
                )
                .await),
            json!({ "state": "pending-deletion" }),
        );
    });
}
