//! Shared helpers of the threat detection suites (tests/threat-rules.test.ts, tests/threats-engine.test.ts): the
//! organization fixture, password sign-ins from simulated client addresses, and readers of what a run recorded.

#![allow(dead_code)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::{
    CredentialInput, Filter, IamResult, IamStore, IamStoreExt, Record, SessionClientInfo,
};
use better_iam_server::http::AuthArgs;
use serde_json::{Value, json};

#[allow(unused_imports)]
pub use crate::organization_fixture::{
    Org, assert_matches, bearer, body, fails, matches, ok, organization, run,
};

pub const MINUTE: f64 = 60_000.0;
pub const DAY: f64 = 24.0 * 60.0 * MINUTE;

/// The organization fixture with its delivered emails (`f.inbox`).
pub struct Threats {
    pub f: Org,
    pub inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
}

impl std::ops::Deref for Threats {
    type Target = Org;
    fn deref(&self) -> &Org {
        &self.f
    }
}

/// `organizationFixture()` with an inbox.
pub async fn fixture() -> Threats {
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let sink = inbox.clone();
    let f = organization(move |options| {
        let authentication = options.authentication.as_mut().unwrap();
        authentication.send_email = Some(delivery_fn(move |message| {
            sink.lock().unwrap().push(message);
            async { Ok(()) }
        }));
    })
    .await;
    Threats { f, inbox }
}

impl Threats {
    /// `iam.detectThreats(input)` as JSON.
    pub async fn detect_threats(&self, input: Option<Value>) -> Value {
        self.iam
            .detect_threats(input.as_ref())
            .await
            .expect("detect threats")
    }

    /// Writes the deferred sign-in failure bookkeeping, then runs detection for the fixture tenant.
    pub async fn detect(&self) -> Value {
        self.iam.auth.settle_bookkeeping().await;
        self.detect_threats(Some(json!({ "tenantId": self.tenant_id })))
            .await
    }

    /// The fixture tenant's detections, optionally of one rule, oldest first.
    pub async fn detections(&self, rule_id: Option<&str>) -> Vec<Value> {
        let mut filter = Filter::new().eq("tenantId", self.tenant_id.clone());
        if let Some(rule_id) = rule_id {
            filter = filter.eq("ruleId", rule_id);
        }
        let mut found: Vec<Value> = self
            .find("threatDetections", filter)
            .await
            .into_iter()
            .map(Value::Object)
            .collect();
        found.sort_by(|a, b| {
            let key = |value: &Value, name: &str| value[name].as_f64().unwrap_or(0.0);
            key(a, "occurredAt")
                .total_cmp(&key(b, "occurredAt"))
                .then(key(a, "detectedAt").total_cmp(&key(b, "detectedAt")))
        });
        found
    }

    /// `store.get(collection, id)` as JSON (None when absent).
    pub async fn get(&self, collection: &str, id: &str) -> Option<Value> {
        self.store()
            .get(collection, id)
            .await
            .unwrap()
            .map(Value::Object)
    }

    /// `store.find(collection, { tenantId })` as JSON.
    pub async fn tenant_records(&self, collection: &str) -> Vec<Value> {
        self.find(
            collection,
            Filter::new().eq("tenantId", self.tenant_id.clone()),
        )
        .await
        .into_iter()
        .map(Value::Object)
        .collect()
    }

    /// The tenant's audit events, newest (highest sequence) first.
    pub async fn audit_newest_first(&self) -> Vec<Record> {
        let mut events = self
            .find(
                "audit",
                Filter::new().eq("tenantId", self.tenant_id.clone()),
            )
            .await;
        events.sort_by(|a, b| {
            b["sequence"]
                .as_f64()
                .unwrap()
                .total_cmp(&a["sequence"].as_f64().unwrap())
        });
        events
    }

    /// Replaces a stored record in a transaction (`database.transaction(tx => tx.put(collection, record))`).
    pub async fn overwrite(&self, collection: &str, record: Record) {
        let collection = collection.to_owned();
        self.store()
            .transaction(|tx| async move {
                let id = record["id"].as_str().unwrap_or_default().to_owned();
                if tx.get(&collection, &id).await?.is_some() {
                    tx.put(&collection, &record).await
                } else {
                    tx.insert(&collection, &record).await
                }
            })
            .await
            .unwrap();
    }

    /// `auth.signIn` with a password; the raw result.
    pub async fn password_sign_in(&self, email: &str, password: &str) -> IamResult<Value> {
        self.iam
            .api
            .auth
            .call(
                "signIn",
                AuthArgs::Public(
                    json!({ "tenantId": self.tenant_id, "email": email, "password": password }),
                ),
            )
            .await
    }

    /// `f.signIn(name)`: `{name}@acme.test` signs in with their password; the session result (`token`, `session`).
    pub async fn sign_in_as(&self, name: &str) -> Value {
        let result = self
            .password_sign_in(
                &format!("{name}@acme.test"),
                &format!("a strong {name} password"),
            )
            .await
            .expect("sign in");
        assert!(result.get("token").is_some(), "unexpected MFA: {result}");
        result
    }

    /// `f.ownerSignIn()`: a fresh owner session, recently authenticated.
    pub async fn owner_sign_in(&self) -> CredentialInput {
        let result = self
            .password_sign_in("owner@acme.test", "a strong tenant owner password")
            .await
            .expect("owner sign in");
        bearer(result["token"].as_str().expect("unexpected owner MFA"))
    }

    /// Runs `future` as a request from `ip`.
    pub async fn from<F: Future>(&self, ip: &str, future: F) -> F::Output {
        self.iam
            .auth
            .with_client(
                Some(SessionClientInfo {
                    ip: Some(ip.to_owned()),
                    user_agent: Some("threat-rules-test".to_owned()),
                    ..SessionClientInfo::default()
                }),
                future,
            )
            .await
    }

    /// Runs `future` as a request from `ip` with the user agent `test`.
    pub async fn as_test_client<F: Future>(&self, ip: &str, future: F) -> F::Output {
        self.iam
            .auth
            .with_client(
                Some(SessionClientInfo {
                    ip: Some(ip.to_owned()),
                    user_agent: Some("test".to_owned()),
                    ..SessionClientInfo::default()
                }),
                future,
            )
            .await
    }

    /// Wrong-password sign-ins for `{name}@acme.test` from `ip`; each must be refused as a bad credential (not rate
    /// limited).
    pub async fn fail_password(&self, name: &str, ip: &str, times: usize) {
        for _ in 0..times {
            let error = self
                .from(
                    ip,
                    self.password_sign_in(&format!("{name}@acme.test"), "not the right password"),
                )
                .await
                .expect_err("wrong password must be refused");
            assert_eq!(error.code, "INVALID_CREDENTIALS", "{error:?}");
        }
    }

    /// Creates `{prefix}{n}@acme.test` people with passwords and returns their names and ids.
    pub async fn members(&self, prefix: &str, count: usize) -> Vec<(String, String)> {
        let mut created = Vec::new();
        for index in 0..count {
            let name = format!("{prefix}{index}");
            let id = self.member(&name).await;
            created.push((name, id));
        }
        created
    }

    /// The fixture's store as the trait object tests patch around.
    pub fn database(&self) -> Arc<dyn IamStore> {
        self.store()
    }
}

/// A member of a JSON result as a number.
pub fn number(value: &Value, name: &str) -> f64 {
    value[name]
        .as_f64()
        .unwrap_or_else(|| panic!("{name} is not a number in {value}"))
}

/// Sorted strings of a JSON array.
pub fn sorted(value: &Value) -> Vec<String> {
    let mut items: Vec<String> = value
        .as_array()
        .unwrap_or_else(|| panic!("not an array: {value}"))
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect();
    items.sort();
    items
}
