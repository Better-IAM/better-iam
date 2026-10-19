//! The server-owned vectors of `spec/vectors` (assertions, webhooks, assertion key derivations) and the catalog
//! contract of `spec/catalog/actions.json`.

mod common;

use std::sync::{Arc, Mutex};

use better_iam_auth::{DeliveryMessage, encrypt_secret};
use better_iam_core::{IamError, IamStoreExt, js};
use better_iam_server::assertions::{
    AssertionSubject, VerifyAssertionOptions, assertion_audience, assertion_key, assertion_ttl,
    refuse_scoped, sign_assertion, verify_assertion,
};
use better_iam_server::catalog::{
    BUILT_IN_ACTIONS, CLASSIFICATION_ATTRIBUTE_NAMES, CLEARANCE_PRINCIPAL_NAMES, Catalog,
    INTERNAL_RESOURCE_TYPES, RESERVED_PRINCIPAL_KEYS, RESERVED_RESOURCE_TYPES,
};
use better_iam_server::events::{VerifyWebhookInput, verify_webhook_signature, webhook_body};
use better_iam_server::options::{BetterIamOptions, EventOptions, WebhookDelivery, resolve_config};
use common::{assert_same, memory_store, read_json};
use serde_json::{Map, Value, json};

const SECRET_A: &str = "deployment-secret-A-with-at-least-32-characters";

fn cases(file: &str) -> Vec<Value> {
    read_json(&format!("spec/vectors/{file}.json"))["cases"]
        .as_array()
        .expect("cases")
        .clone()
}

fn expect_error(name: &str, error: &IamError, expected: &Value) {
    let expected = &expected["$error"];
    assert_eq!(error.code, expected["code"], "{name}: code");
    assert_eq!(
        f64::from(error.status),
        expected["status"].as_f64().unwrap(),
        "{name}: status"
    );
    assert_eq!(error.message, expected["message"], "{name}: message");
}

fn subject(principal: &Value) -> AssertionSubject {
    let identity = &principal["identity"];
    let session = &principal["session"];
    let text = |value: &Value| value.as_str().map(str::to_owned);
    AssertionSubject {
        identity_id: identity["id"].as_str().unwrap().to_owned(),
        name: identity["name"].as_str().unwrap().to_owned(),
        email: text(&identity["email"]),
        kind: session["kind"].as_str().unwrap().to_owned(),
        mfa: session["mfa"].as_bool().unwrap(),
        method: text(&session["method"]),
        impersonator_id: text(&session["impersonatorId"]),
        role_id: text(&session["roleId"]),
        scoped: session.get("policy").is_some() || session.get("sourcePolicy").is_some(),
    }
}

#[test]
fn assertion_vectors() {
    let key = assertion_key(SECRET_A);
    let mut issued = 0;
    let mut verified = 0;
    for case in cases("assertions") {
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];
        let output = &case["output"];
        if name.starts_with("issue") {
            let subject = subject(&input["principal"]);
            let request = &input["request"];
            let strings = |value: &Value| -> Vec<String> {
                value
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|item| item.as_str().unwrap().to_owned())
                    .collect()
            };
            let jti = output["claims"]["jti"].as_str().unwrap_or("").to_owned();
            let outcome = assertion_audience(request.get("audience"))
                .and_then(|_| refuse_scoped(&subject).map_err(|failure| failure.error))
                .and_then(|()| assertion_ttl(request))
                .and_then(|ttl| {
                    let origin = url::Url::parse(input["baseURL"].as_str().unwrap())
                        .unwrap()
                        .origin()
                        .ascii_serialization();
                    sign_assertion(
                        &key,
                        &origin,
                        request["audience"].as_str().unwrap(),
                        request["tenantId"].as_str().unwrap(),
                        &subject,
                        input["now"].as_f64().unwrap(),
                        ttl,
                        &strings(&input["groupIds"]),
                        &strings(&input["roleIds"]),
                        request.get("claims"),
                        jti,
                    )
                });
            match outcome {
                Ok(assertion) => {
                    assert_eq!(assertion.token, output["token"], "{name}: token");
                    assert_same(name, &assertion.to_value(), output);
                }
                Err(error) => expect_error(name, &error, output),
            }
            issued += 1;
        } else {
            let options = &input["options"];
            let keys = match &options["key"] {
                Value::String(key) => vec![key.clone()],
                Value::Array(keys) => keys
                    .iter()
                    .map(|key| key.as_str().unwrap().to_owned())
                    .collect(),
                _ => Vec::new(),
            };
            let outcome = verify_assertion(
                input["token"].as_str().unwrap(),
                &VerifyAssertionOptions {
                    key: keys,
                    audience: options["audience"].as_str().unwrap().to_owned(),
                    issuer: options["issuer"].as_str().map(str::to_owned),
                    now: options["now"].as_f64(),
                    tolerance_seconds: options["toleranceSeconds"].as_f64(),
                },
            );
            match outcome {
                Ok(claims) => assert_same(name, &Value::Object(claims), output),
                Err(error) => expect_error(name, &error, output),
            }
            verified += 1;
        }
    }
    assert_eq!((issued, verified), (11, 17));
}

#[test]
fn assertion_key_derivations() {
    let mut checked = 0;
    for case in cases("derivations") {
        if case["name"].as_str().unwrap().starts_with("assertionKey") {
            assert_eq!(
                assertion_key(case["input"]["secret"].as_str().unwrap()),
                case["output"].as_str().unwrap()
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 3);
}

#[tokio::test]
async fn webhook_vectors() {
    let mut checked = 0;
    for case in cases("webhooks") {
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];
        let output = &case["output"];
        if name.starts_with("webhookBody") {
            // Vector inputs spell undefined members as {"$undefined": true} (FORMAT.md value encoding).
            let mut event = input["event"].as_object().unwrap().clone();
            event.retain(|_, value| *value != json!({ "$undefined": true }));
            let body = webhook_body(&event);
            assert_same(name, &Value::Object(body.clone()), &output["body"]);
            assert_eq!(
                js::stringify(&Value::Object(body)),
                output["json"],
                "{name}"
            );
        } else if name.starts_with("deliver") {
            let captured: Arc<Mutex<Vec<WebhookDelivery>>> = Arc::default();
            let sink = captured.clone();
            let mut options =
                BetterIamOptions::new(memory_store(), SECRET_A, "https://iam.example.com");
            options.events = Some(EventOptions {
                deliver_webhook: Some(Arc::new(move |delivery| {
                    sink.lock().unwrap().push(delivery);
                    Box::pin(async { Ok(()) })
                })),
                ..EventOptions::default()
            });
            let ctx = common::context(options, input["now"].as_f64().unwrap());
            ctx.store.migrate().await.unwrap();
            let hook_id = input["hookId"].as_str().unwrap().to_owned();
            let mut hook = Map::new();
            hook.insert("id".into(), json!(hook_id));
            hook.insert("tenantId".into(), output["tenantId"].clone());
            hook.insert("url".into(), output["url"].clone());
            hook.insert("events".into(), json!(["*"]));
            hook.insert("active".into(), json!(true));
            hook.insert("scope".into(), json!("tenant"));
            hook.insert(
                "secretSealed".into(),
                json!(encrypt_secret(
                    input["webhookSecret"].as_str().unwrap(),
                    SECRET_A,
                    &format!("webhook:{hook_id}")
                )),
            );
            ctx.store
                .transaction(
                    move |tx| async move { tx.insert("webhooks", &hook).await.map(|_| ()) },
                )
                .await
                .unwrap();
            let mut payload = Map::new();
            payload.insert("url".into(), output["url"].clone());
            payload.insert("body".into(), input["body"].clone());
            ctx.events()
                .unwrap()
                .deliver_webhook_message(DeliveryMessage {
                    id: input["messageId"].as_str().unwrap().to_owned(),
                    tenant_id: output["tenantId"].as_str().unwrap().to_owned(),
                    to: hook_id,
                    template: input["event"].as_str().unwrap().to_owned(),
                    payload,
                    sign_in_url: None,
                })
                .await
                .unwrap();
            let delivery = captured.lock().unwrap().pop().expect("delivered");
            let value = serde_json::to_value(&delivery).unwrap();
            assert_same(name, &value, output);
            // Header order is part of the contract.
            let order: Vec<&String> = delivery.headers.keys().collect();
            let expected: Vec<&String> = output["headers"].as_object().unwrap().keys().collect();
            assert_eq!(order, expected, "{name}: header order");
        } else {
            let verified = verify_webhook_signature(&VerifyWebhookInput {
                secret: input["secret"].as_str().unwrap(),
                timestamp: &input["timestamp"],
                body: input["body"].as_str().unwrap(),
                signature: input["signature"].as_str().unwrap(),
                tolerance_seconds: input["toleranceSeconds"].as_f64(),
                now: input["now"].as_f64(),
            });
            assert_eq!(Value::Bool(verified), *output, "{name}");
        }
        checked += 1;
    }
    assert_eq!(checked, 16);
}

#[test]
fn catalog_contract() {
    let spec = read_json("spec/catalog/actions.json");
    let strings = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(*BUILT_IN_ACTIONS, strings(&spec["builtInActions"]));
    assert_eq!(
        INTERNAL_RESOURCE_TYPES.to_vec(),
        strings(&spec["internalResourceTypes"])
    );
    assert_eq!(
        RESERVED_RESOURCE_TYPES.to_vec(),
        strings(&spec["reservedResourceTypes"])
    );
    assert_eq!(
        RESERVED_PRINCIPAL_KEYS.iter().cloned().collect::<Vec<_>>(),
        strings(&spec["reservedPrincipalKeys"])
    );
    assert_eq!(
        CLEARANCE_PRINCIPAL_NAMES
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        strings(&spec["clearancePrincipalNames"])
    );
    assert_eq!(
        CLASSIFICATION_ATTRIBUTE_NAMES
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        strings(&spec["classificationAttributeNames"])
    );
    let options = BetterIamOptions::new(memory_store(), SECRET_A, "https://iam.example.com");
    let config = resolve_config(&options).unwrap();
    let catalog = Catalog::new(&options, &[], &config).unwrap();
    let default = &spec["default"];
    let actions: Vec<Value> = catalog
        .actions
        .iter()
        .map(|action| {
            let mut entry = json!({ "name": action, "source": "platform" });
            if let Some(kind) = catalog.action_types.get(action) {
                entry["resourceType"] = json!(kind);
            }
            entry
        })
        .collect();
    assert_same(
        "default actions",
        &Value::Array(actions),
        &default["actions"],
    );
    assert_same(
        "default namespaces",
        &json!(catalog.namespaces.iter().collect::<Vec<_>>()),
        &default["namespaces"],
    );
    assert!(catalog.resource_types.is_empty());
    assert_eq!(default["resourceTypes"], json!([]));
    assert_eq!(default["reservedAttributes"], Value::Null);
    assert!(catalog.reserved_attributes.is_none());
    let patterns = &spec["patterns"];
    assert_eq!(patterns["resourceTypeName"], "^[a-z][a-z0-9-]{0,63}$");
    assert_eq!(patterns["attributeName"], "^[a-zA-Z][a-zA-Z0-9_]{0,63}$");
}
