//! How the generated types map TypeScript JSON: absent, null and a value stay distinct; unions pick the variant the
//! JSON describes; enums keep their strings; numbers serialize in JavaScript form.

use better_iam_types::api::agents;
use better_iam_types::routes::{self, Call, Operation};
use better_iam_types::schemas::*;
use better_iam_types::to_json_string;
use serde_json::{Value, json};

fn round_trip<T: serde::Serialize + serde::de::DeserializeOwned>(value: Value) -> (T, String) {
    let typed: T = serde_json::from_value(value.clone()).unwrap();
    let text = to_json_string(&typed).unwrap();
    assert_eq!(text, better_iam_core::js::stringify(&value));
    (typed, text)
}

#[test]
fn optional_and_nullable_members_keep_absent_null_and_value_apart() {
    // `model?: string | null`: absent, null and a value.
    let (absent, _) = round_trip::<CreateAgentInput>(json!({ "tenantId": "t", "name": "a" }));
    assert_eq!(absent.model, None);
    let (null, _) =
        round_trip::<CreateAgentInput>(json!({ "tenantId": "t", "name": "a", "model": null }));
    assert_eq!(null.model, Some(None));
    let (value, _) =
        round_trip::<CreateAgentInput>(json!({ "tenantId": "t", "name": "a", "model": "m" }));
    assert_eq!(value.model, Some(Some("m".into())));
    // Built in Rust: unset optional members are left out.
    let built = CreateAgentInput {
        tenant_id: "t".into(),
        name: "a".into(),
        ..Default::default()
    };
    assert_eq!(
        to_json_string(&built).unwrap(),
        r#"{"tenantId":"t","name":"a"}"#
    );
}

#[test]
fn required_nullable_members_are_written_as_null() {
    let anomaly = json!({
        "dimension": "team", "key": "k", "day": "2026-10-01", "costMicros": 5, "baselineMicros": 0, "factor": null
    });
    let (typed, text) = round_trip::<SpendAnomaly>(anomaly);
    assert_eq!(typed.factor, None);
    assert!(text.ends_with(r#""factor":null}"#));
    assert_eq!(typed.dimension, SpendAnomalyDimension::Team);
}

#[test]
fn members_of_any_type_keep_null() {
    let (change, _) = round_trip::<ConfigChange>(
        json!({ "kind": "role", "name": "r", "action": "update", "before": null }),
    );
    assert_eq!(change.before, Some(Value::Null));
    assert_eq!(change.after, None);
}

#[test]
fn tagged_unions_use_the_discriminator() {
    let (mfa, _) = round_trip::<AccessPath>(json!({ "kind": "mfa" }));
    assert_eq!(mfa, AccessPath::Mfa);
    let (activate, _) = round_trip::<AccessPath>(json!({
        "kind": "activate", "bindingId": "b", "role": { "id": "r", "name": "R" },
        "requireApproval": false, "requireJustification": true, "requireMfa": false
    }));
    let AccessPath::Activate(activate) = activate else {
        panic!("not activate")
    };
    assert_eq!(activate.binding_id, "b");
    assert!(serde_json::from_value::<AccessPath>(json!({ "kind": "nope" })).is_err());
}

#[test]
fn untagged_unions_pick_the_variant_whose_shape_matches() {
    let (required, _) = round_trip::<SignInResult>(json!({
        "mfaRequired": true, "challenge": "c", "enrollmentRequired": false
    }));
    assert!(matches!(required, SignInResult::MfaRequired(_)));
    let (values, _) = round_trip::<Vec<FilterValue>>(json!(["a", 1, 2.5, true]));
    assert_eq!(values[1], FilterValue::Number(1.0));
    assert!(serde_json::from_value::<SignInResult>(json!({ "challenge": "c" })).is_err());
}

#[test]
fn enums_keep_their_strings() {
    assert_eq!(
        AuthenticatorTransportFuture::SmartCard.as_str(),
        "smart-card"
    );
    assert_eq!(
        AuthenticatorTransportFuture::from_str("usb"),
        Some(AuthenticatorTransportFuture::Usb)
    );
    assert!(serde_json::from_value::<AuthenticatorTransportFuture>(json!("floppy")).is_err());
    // Open enums accept other strings and name the known ones.
    let (custom, _) = round_trip::<SpendGroupBy>(json!("project"));
    assert!(!custom.is_known());
    assert_eq!(SpendGroupBy::TEAM, "team");
    assert!(SpendGroupBy::from(SpendGroupBy::TEAM).is_known());
}

#[test]
fn core_types_are_reused() {
    let decision: better_iam_core::Decision = Decision {
        allowed: true,
        reason: "ALLOWED".into(),
        matched: vec![],
    };
    assert_eq!(
        to_json_string(&decision).unwrap(),
        r#"{"allowed":true,"reason":"ALLOWED","matched":[]}"#
    );
    assert!(CORE_SCHEMAS.contains(&"Tenant"));
}

#[test]
fn operations_carry_their_route() {
    let route = <agents::Create as Operation>::ROUTE;
    assert_eq!(route.path, "agents/create");
    assert_eq!(route.call, Call::CredentialInput);
    assert!(!route.public);
    assert_eq!(
        routes::lookup("auth/signIn").map(|route| (route.public, route.call)),
        Some((true, Call::Input))
    );
    assert_eq!(
        routes::lookup("auth/beginMfa").map(|route| route.call),
        Some(Call::BeginMfa)
    );
    assert_eq!(
        routes::lookup("authorize").map(|route| route.call),
        Some(Call::Special)
    );
    assert_eq!(routes::BASE_PATH, "/api/iam");
}
