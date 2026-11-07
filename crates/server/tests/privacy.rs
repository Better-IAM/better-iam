//! Privacy and consent (privacy.ts): the module's decisions, validators, receipts, subjects, legal holds and the
//! `principal.consents` policy context, after tests/privacy.test.ts and the privacy cases of
//! spec/vectors/derivations.json.
//!
//! The TypeScript suite drives these through the `privacy` API group, which is ported separately; here purposes,
//! decisions, restrictions and holds are written to the store directly and the module's functions are called the way
//! the API group calls them. The steps that go through `tenants.setStatus` and `identities.delete` use those groups.

mod common;
mod governance;

use better_iam_auth::service::mfa::ConfirmMfaInput;
use better_iam_auth::{MfaCredential, SignInResult, totp};
use better_iam_core::{CredentialInput, IamError, IamStoreExt, Identity};
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use better_iam_server::privacy::{
    self, ConsentReceipt, PrivacyConsent, PrivacyConsentEvent, PrivacyPurpose, PrivacyRestriction,
    SubjectRequest,
};
use common::read_json;
use governance::{DAY, Fixture, FixtureOptions, bearer, body, err, ok, organization, run};
use serde_json::{Map, Value, json};

const SECRET_A: &str = "deployment-secret-A-with-at-least-32-characters";
const SECRET_B: &str = "deployment-secret-B-with-at-least-32-characters";

fn derivations() -> Vec<Value> {
    read_json("spec/vectors/derivations.json")["cases"]
        .as_array()
        .expect("cases")
        .clone()
}

fn purpose(value: Value) -> PrivacyPurpose {
    let mut record = json!({
        "id": "p1",
        "tenantId": "t1",
        "key": "marketing-email",
        "name": "Marketing email",
        "description": "Product news and offers by email.",
        "legalBasis": "consent",
        "mode": "opt-in",
        "version": 1,
        "dataCategories": [],
        "reconsentOnVersion": true,
        "archived": false,
        "createdAt": 0,
        "updatedAt": 0,
    });
    for (key, member) in value.as_object().unwrap() {
        record[key] = member.clone();
    }
    serde_json::from_value(record).unwrap()
}

fn consent(value: Value) -> PrivacyConsent {
    let mut record = json!({
        "id": "c1",
        "tenantId": "t1",
        "purposeId": "p1",
        "purposeKey": "marketing-email",
        "subject": "identity:alice",
        "granted": true,
        "purposeVersion": 1,
        "source": "self",
        "recordedAt": 0,
        "recordedBy": "alice",
        "receiptId": "r1",
    });
    for (key, member) in value.as_object().unwrap() {
        record[key] = member.clone();
    }
    serde_json::from_value(record).unwrap()
}

fn reason(
    purpose: &PrivacyPurpose,
    consent: Option<&PrivacyConsent>,
    restricted: Value,
    now: f64,
) -> (bool, String) {
    let state = privacy::consent_state(purpose, consent, &restricted, now).unwrap();
    (state.allowed, state.reason)
}

fn invalid(result: Result<impl std::fmt::Debug, IamError>, message: &str) {
    let error = result.expect_err("expected INVALID_INPUT");
    assert_eq!(
        (error.code.as_str(), error.message.as_str(), error.status),
        ("INVALID_INPUT", message, 400)
    );
}

#[test]
fn derivation_vectors() {
    let mut checked = 0;
    for case in derivations() {
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];
        if name.starts_with("emailSubject") {
            assert_eq!(
                privacy::email_subject(
                    input["secret"].as_str().unwrap(),
                    input["address"].as_str().unwrap()
                )
                .unwrap(),
                case["output"].as_str().unwrap(),
                "{name}"
            );
            checked += 1;
        } else if name == "signReceipt" {
            let receipt = privacy::sign_receipt_value(
                input["secret"].as_str().unwrap(),
                input["body"].as_object().unwrap().clone(),
            );
            assert_eq!(Value::Object(receipt.clone()), case["output"], "{name}");
            // Member order is the body's with the signature appended.
            assert_eq!(
                better_iam_core::js::stringify(&Value::Object(receipt)),
                better_iam_core::js::stringify(&case["output"])
            );
            let typed = privacy::sign_receipt(
                input["secret"].as_str().unwrap(),
                input["body"].as_object().unwrap().clone(),
            )
            .unwrap();
            assert_eq!(typed.signature, case["output"]["signature"]);
            checked += 1;
        } else if name.starts_with("receiptSignatureValid") {
            let secrets: Vec<String> = serde_json::from_value(input["secrets"].clone()).unwrap();
            let expected = case["output"].as_bool().unwrap();
            assert_eq!(
                privacy::receipt_value_signature_valid(&secrets, &input["receipt"]),
                expected,
                "{name}"
            );
            let typed: ConsentReceipt = serde_json::from_value(input["receipt"].clone()).unwrap();
            assert_eq!(
                privacy::receipt_signature_valid(&secrets, &typed).unwrap(),
                expected,
                "{name} (typed)"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 8);
}

#[test]
fn rebuilds_receipts_from_the_consent_history() {
    let event: PrivacyConsentEvent = serde_json::from_value(json!({
        "id": "e1",
        "tenantId": "tnt_01",
        "receiptId": "rcpt_01",
        "purposeId": "p1",
        "purposeKey": "marketing",
        "purposeName": "Marketing email",
        "legalBasis": "consent",
        "purposeVersion": 2,
        "subject": "identity:idn_01",
        "identityId": "idn_01",
        "granted": true,
        "source": "api",
        "method": "checkbox",
        "evidence": "Signup form v3",
        "recordedAt": 1_767_225_600_000_u64,
        "recordedBy": "owner",
    }))
    .unwrap();
    let receipt = privacy::receipt_from_event(SECRET_A, &event).unwrap();
    // The same receipt as the signReceipt vector: evidence and the recorder are not part of it.
    let vector = derivations()
        .into_iter()
        .find(|case| case["name"] == "signReceipt")
        .unwrap();
    assert_eq!(
        better_iam_core::js::stringify(&serde_json::to_value(&receipt).unwrap()),
        better_iam_core::js::stringify(&vector["output"])
    );
    assert!(privacy::receipt_signature_valid(&[SECRET_A.into()], &receipt).unwrap());
    // Rotated secrets: an older receipt still verifies against the previous secret.
    assert!(
        privacy::receipt_signature_valid(&[SECRET_B.into(), SECRET_A.into()], &receipt).unwrap()
    );
    assert!(!privacy::receipt_signature_valid(&[SECRET_B.into()], &receipt).unwrap());
    // A tampered copy does not verify.
    let mut tampered = receipt.clone();
    tampered.granted = false;
    assert!(!privacy::receipt_signature_valid(&[SECRET_A.into()], &tampered).unwrap());
    // A receipt without a method leaves the member out rather than signing an empty one.
    let mut silent = event.clone();
    silent.method = Some(String::new());
    let receipt = privacy::receipt_from_event(SECRET_A, &silent).unwrap();
    assert_eq!(receipt.method, None);
    let value = serde_json::to_value(&receipt).unwrap();
    assert!(value.get("method").is_none());
    assert!(privacy::receipt_value_signature_valid(
        &[SECRET_A.into()],
        &value
    ));
    // Untrusted shapes: no signature, a signature that is not a string, a non-object.
    let mut unsigned = value.as_object().unwrap().clone();
    unsigned.remove("signature");
    assert!(!privacy::receipt_value_signature_valid(
        &[SECRET_A.into()],
        &Value::Object(unsigned.clone())
    ));
    unsigned.insert("signature".into(), json!(42));
    assert!(!privacy::receipt_value_signature_valid(
        &[SECRET_A.into()],
        &Value::Object(unsigned)
    ));
    assert!(!privacy::receipt_value_signature_valid(
        &[SECRET_A.into()],
        &json!("receipt")
    ));
}

#[test]
fn decides_each_basis_and_mode() {
    // tests/privacy.test.ts "lets people decide, with receipts, versions and the effect of each basis".
    let marketing = purpose(json!({}));
    let analytics =
        purpose(json!({ "key": "product-analytics", "legalBasis": "legitimate-interests" }));
    let sale = purpose(json!({ "key": "data-sharing", "mode": "opt-out" }));
    let billing = purpose(json!({ "key": "billing", "legalBasis": "contract" }));
    let no = json!(false);
    assert_eq!(
        reason(&marketing, None, no.clone(), 0.0),
        (false, "NO_CONSENT".into())
    );
    assert_eq!(
        reason(&analytics, None, no.clone(), 0.0),
        (true, "LEGITIMATE_INTERESTS".into())
    );
    assert_eq!(
        reason(&sale, None, no.clone(), 0.0),
        (true, "NOT_OPTED_OUT".into())
    );
    assert_eq!(
        reason(&billing, None, no.clone(), 0.0),
        (true, "LEGAL_BASIS".into())
    );
    for (purpose, decidable) in [
        (&marketing, true),
        (&analytics, true),
        (&sale, true),
        (&billing, false),
    ] {
        assert_eq!(
            privacy::decidable(&serde_json::to_value(purpose).unwrap()).unwrap(),
            decidable
        );
    }
    for basis in ["legal-obligation", "vital-interests", "public-task"] {
        assert!(!privacy::decidable(&json!({ "legalBasis": basis })).unwrap());
    }
    assert!(!privacy::decidable(&json!({})).unwrap());

    let granted = consent(json!({}));
    assert_eq!(
        reason(&marketing, Some(&granted), no.clone(), 0.0),
        (true, "CONSENT_GIVEN".into())
    );
    let withdrawn = consent(json!({ "granted": false }));
    assert_eq!(
        reason(&sale, Some(&withdrawn), no.clone(), 0.0),
        (false, "CONSENT_WITHDRAWN".into())
    );
    assert_eq!(
        reason(&marketing, Some(&withdrawn), no.clone(), 0.0),
        (false, "CONSENT_WITHDRAWN".into())
    );
    assert_eq!(
        reason(&analytics, Some(&withdrawn), no.clone(), 0.0),
        (false, "OBJECTED".into())
    );
    // A contract purpose ignores decisions.
    assert_eq!(
        reason(&billing, Some(&withdrawn), no.clone(), 0.0),
        (true, "LEGAL_BASIS".into())
    );

    // A new version asks again unless the purpose keeps older grants valid.
    let second = purpose(json!({ "version": 2 }));
    assert_eq!(
        reason(&second, Some(&granted), no.clone(), 0.0),
        (false, "CONSENT_OUTDATED".into())
    );
    let lenient = purpose(json!({ "version": 2, "reconsentOnVersion": false }));
    assert_eq!(
        reason(&lenient, Some(&granted), no.clone(), 0.0),
        (true, "CONSENT_GIVEN".into())
    );

    // Archived purposes are refused before anything else.
    let archived = purpose(json!({ "legalBasis": "contract", "archived": true }));
    assert_eq!(
        reason(&archived, None, json!("erased"), 0.0),
        (false, "PURPOSE_ARCHIVED".into())
    );
}

#[test]
fn lets_grants_lapse_after_the_consent_lifetime() {
    // tests/privacy.test.ts "lets grants lapse after the consent lifetime".
    let cookies = purpose(json!({ "key": "cookies.ads", "consentLifetimeDays": 30 }));
    let grant = consent(json!({ "expiresAt": 30.0 * DAY }));
    assert_eq!(
        reason(&cookies, Some(&grant), json!(false), 29.0 * DAY),
        (true, "CONSENT_GIVEN".into())
    );
    assert_eq!(
        reason(&cookies, Some(&grant), json!(false), 30.0 * DAY),
        (false, "CONSENT_EXPIRED".into())
    );
    assert_eq!(
        reason(&cookies, Some(&grant), json!(false), 31.0 * DAY),
        (false, "CONSENT_EXPIRED".into())
    );
}

#[test]
fn restriction_and_erasure_hold_back_all_but_legal_obligations() {
    // tests/privacy.test.ts "restricts processing, ..." and "keeps an erased application subject suppressed instead
    // of opted back in".
    let restriction: PrivacyRestriction = serde_json::from_value(json!({
        "id": "r1", "tenantId": "t1", "subject": "external:c-1", "externalId": "c-1",
        "restrictedAt": 0, "restrictedBy": "owner",
    }))
    .unwrap();
    assert_eq!(privacy::restriction_state(None).unwrap(), json!(false));
    assert_eq!(
        privacy::restriction_state(Some(&restriction)).unwrap(),
        json!(true)
    );
    let mut erased = restriction.clone();
    erased.erased = Some(true);
    assert_eq!(
        privacy::restriction_state(Some(&erased)).unwrap(),
        json!("erased")
    );
    erased.erased = Some(false);
    assert_eq!(
        privacy::restriction_state(Some(&erased)).unwrap(),
        json!(true)
    );

    let granted = consent(json!({}));
    let sale = purpose(json!({ "mode": "opt-out" }));
    let analytics = purpose(json!({ "legalBasis": "legitimate-interests" }));
    for restricted in [json!(true), json!("erased")] {
        let expected = if restricted == json!(true) {
            "RESTRICTED"
        } else {
            "ERASED"
        };
        for purpose in [&purpose(json!({})), &sale, &analytics] {
            assert_eq!(
                reason(purpose, Some(&granted), restricted.clone(), 0.0),
                (false, expected.into())
            );
            assert_eq!(
                reason(purpose, None, restricted.clone(), 0.0),
                (false, expected.into())
            );
        }
        for basis in ["legal-obligation", "vital-interests"] {
            assert_eq!(
                reason(
                    &purpose(json!({ "legalBasis": basis })),
                    None,
                    restricted.clone(),
                    0.0
                ),
                (true, "LEGAL_BASIS".into())
            );
        }
        assert_eq!(
            reason(
                &purpose(json!({ "legalBasis": "contract" })),
                None,
                restricted.clone(),
                0.0
            ),
            (false, expected.into())
        );
    }
}

#[test]
fn validates_inputs_as_typescript_does() {
    // Purpose keys.
    assert_eq!(
        privacy::purpose_key(Some(&json!("marketing-email"))).unwrap(),
        "marketing-email"
    );
    assert_eq!(
        privacy::purpose_key(Some(&json!("cookies.ads_v2"))).unwrap(),
        "cookies.ads_v2"
    );
    for bad in ["Marketing", "1st-party", "-x", "a b", "émail", "x/y"] {
        invalid(
            privacy::purpose_key(Some(&json!(bad))),
            "Purpose keys use lowercase letters, digits, dots, underscores or hyphens",
        );
    }
    invalid(
        privacy::purpose_key(Some(&json!("a".repeat(65)))),
        "Invalid purposeKey",
    );
    assert!(privacy::purpose_key(Some(&json!("a".repeat(64)))).is_ok());
    invalid(privacy::purpose_key(None), "Invalid purposeKey");
    invalid(privacy::purpose_key(Some(&json!(7))), "Invalid purposeKey");

    // Prose: tabs and line breaks allowed, other controls not.
    let text = "Line one.\n\tLine two.\r\n";
    assert_eq!(
        privacy::prose(Some(&json!(text)), "description", 5000.0).unwrap(),
        text
    );
    for bad in [
        json!("   \n "),
        json!("bell\u{7}"),
        json!("del\u{7f}"),
        json!("vt\u{b}"),
        json!(""),
        json!(5),
        Value::Null,
    ] {
        invalid(
            privacy::prose(Some(&bad), "description", 5000.0),
            "Invalid description",
        );
    }
    invalid(
        privacy::prose(Some(&json!("abcdef")), "details", 5.0),
        "Invalid details",
    );
    // Lengths are UTF-16 code units.
    invalid(
        privacy::prose(Some(&json!("🔑🔑🔑")), "details", 5.0),
        "Invalid details",
    );
    assert!(privacy::prose(Some(&json!("🔑🔑")), "details", 4.0).is_ok());

    // Application subject identifiers.
    assert_eq!(
        privacy::external_subject_id(Some(&json!("customer-42"))).unwrap(),
        "customer-42"
    );
    invalid(
        privacy::external_subject_id(Some(&json!(" customer-42"))),
        "Invalid externalId",
    );
    invalid(
        privacy::external_subject_id(Some(&json!("a".repeat(257)))),
        "Invalid externalId",
    );
    invalid(
        privacy::external_subject_id(Some(&json!("tab\there"))),
        "Invalid externalId",
    );

    // Enumerations.
    let bases: Vec<Value> = privacy::LEGAL_BASES
        .iter()
        .map(|basis| json!(basis))
        .collect();
    assert_eq!(
        privacy::one_of(Some(&json!("contract")), &bases, "legalBasis").unwrap(),
        json!("contract")
    );
    invalid(
        privacy::one_of(Some(&json!("whim")), &bases, "legalBasis"),
        "legalBasis must be one of consent, contract, legal-obligation, vital-interests, public-task, legitimate-interests",
    );
    invalid(
        privacy::one_of_str(None, privacy::REJECTION_REASONS, "reason"),
        "reason must be one of unverified, unfounded, excessive, exempt, duplicate, no-data, other",
    );
    assert_eq!(
        privacy::one_of_str(
            Some(&json!("opt-out")),
            privacy::SUBJECT_REQUEST_TYPES,
            "type"
        )
        .unwrap(),
        "opt-out"
    );

    // Days.
    assert_eq!(
        privacy::days(Some(&json!(365)), "consentLifetimeDays", None).unwrap(),
        365.0
    );
    invalid(
        privacy::days(Some(&json!(3651)), "retentionDays", None),
        "Invalid retentionDays",
    );
    invalid(
        privacy::days(Some(&json!(0)), "retentionDays", None),
        "Invalid retentionDays",
    );
    invalid(
        privacy::days(Some(&json!(1.5)), "retentionDays", None),
        "Invalid retentionDays",
    );
    invalid(
        privacy::days(Some(&json!(31)), "days", Some(30.0)),
        "Invalid days",
    );
}

#[test]
fn computes_response_windows_and_deadlines() {
    assert_eq!(
        privacy::regulations().unwrap(),
        vec![
            json!("gdpr"),
            json!("uk-gdpr"),
            json!("ccpa"),
            json!("lgpd"),
            json!("pipeda"),
            json!("other")
        ]
    );
    let window = |regulation: &str, settings: Value| {
        privacy::response_window(&json!(regulation), &settings).unwrap()
    };
    assert_eq!(
        window("gdpr", json!({})),
        json!({ "responseDays": 30, "extensionDays": 60 })
    );
    assert_eq!(
        window("ccpa", json!({})),
        json!({ "responseDays": 45, "extensionDays": 45 })
    );
    assert_eq!(
        window("lgpd", json!({})),
        json!({ "responseDays": 15, "extensionDays": 0 })
    );
    // A tenant may shorten the window, never lengthen it.
    assert_eq!(
        window(
            "gdpr",
            json!({ "responseDays": { "gdpr": 20, "ccpa": 10 } })
        ),
        json!({ "responseDays": 20, "extensionDays": 60 })
    );
    assert_eq!(
        window("pipeda", json!({ "responseDays": { "pipeda": 90 } })),
        json!({ "responseDays": 30, "extensionDays": 30 })
    );
    assert_eq!(
        window("ccpa", json!({ "responseDays": { "gdpr": 20 } })),
        json!({ "responseDays": 45, "extensionDays": 45 })
    );
    let settings = serde_json::to_value(privacy::default_privacy_settings("t1")).unwrap();
    assert_eq!(
        window("uk-gdpr", settings),
        json!({ "responseDays": 30, "extensionDays": 60 })
    );
    let error = privacy::response_window(&json!("nowhere"), &json!({})).unwrap_err();
    assert_eq!(error.code, "INTERNAL_ERROR");

    // Request numbers: DSR- and eight Crockford base32 characters.
    let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    for _ in 0..50 {
        let number = privacy::request_number().unwrap();
        assert_eq!(number.len(), 12);
        assert!(number.starts_with("DSR-"));
        assert!(number[4..].chars().all(|c| alphabet.contains(c)));
    }

    // Overdue once the deadline passed while the request is open.
    let request = |status: &str, due_at: Option<f64>| -> SubjectRequest {
        let mut record = json!({
            "id": "q1", "tenantId": "t1", "number": "DSR-00000000", "type": "access", "regulation": "gdpr",
            "status": status, "subject": "identity:alice", "channel": "staff",
            "verification": { "status": "verified" }, "submittedAt": 0, "events": [],
        });
        if let Some(due_at) = due_at {
            record["dueAt"] = json!(due_at);
        }
        serde_json::from_value(record).unwrap()
    };
    assert!(privacy::request_overdue(&request("open", Some(10.0)), 10.0).unwrap());
    assert!(!privacy::request_overdue(&request("open", Some(10.0)), 9.0).unwrap());
    assert!(!privacy::request_overdue(&request("completed", Some(10.0)), 20.0).unwrap());
    assert!(!privacy::request_overdue(&request("pending-verification", None), 20.0).unwrap());

    assert_eq!(
        privacy::identity_subject("abc").unwrap(),
        "identity:abc".to_owned()
    );
    assert_eq!(privacy::DAY_MS, DAY);
}

struct Scenario {
    f: Fixture,
    tenant_id: String,
    alice: String,
}

async fn scenario() -> Scenario {
    let f = organization(FixtureOptions::default()).await;
    let tenant_id = f.tenant_id.clone();
    let alice = f.member("alice").await;
    Scenario {
        f,
        tenant_id,
        alice,
    }
}

impl Scenario {
    async fn identity(&self, id: &str) -> Identity {
        let records = self.f.find("identities", &[("id", json!(id))]).await;
        better_iam_server::port::decode(records.into_iter().next().expect("identity")).unwrap()
    }

    async fn add_purpose(&self, id: &str, key: &str, basis: &str, extra: Value) {
        let mut record = json!({
            "id": id,
            "tenantId": self.tenant_id,
            "uniqueKey": format!("key:{key}"),
            "key": key,
            "name": key,
            "description": "A purpose.",
            "legalBasis": basis,
            "mode": "opt-in",
            "version": 1,
            "dataCategories": [],
            "reconsentOnVersion": true,
            "archived": false,
            "createdAt": self.f.now(),
            "updatedAt": self.f.now(),
        });
        for (name, member) in extra.as_object().unwrap() {
            record[name] = member.clone();
        }
        self.f.insert("privacyPurposes", record).await;
    }

    async fn decide(&self, purpose_id: &str, key: &str, subject: &str, granted: bool) {
        let id = format!("{purpose_id}:{subject}");
        let existing = self.f.find("privacyConsents", &[("id", json!(id))]).await;
        let record = json!({
            "id": id,
            "tenantId": self.tenant_id,
            "uniqueKey": id,
            "purposeId": purpose_id,
            "purposeKey": key,
            "subject": subject,
            "granted": granted,
            "purposeVersion": 1,
            "source": "self",
            "recordedAt": self.f.now(),
            "recordedBy": "test",
            "receiptId": better_iam_server::utils::id(),
        });
        if existing.is_empty() {
            self.f.insert("privacyConsents", record).await;
        } else {
            self.f.patch("privacyConsents", &id, record).await;
        }
    }

    async fn allowed(&self, credential: &CredentialInput) -> bool {
        self.f
            .iam
            .authorize(&AuthorizationRequest {
                credential: credential.clone(),
                tenant_id: self.tenant_id.clone(),
                action: "documents:read".into(),
                resource: ResourceTarget {
                    kind: "document".into(),
                    id: "d1".into(),
                },
            })
            .await
            .unwrap()
            .allowed
    }

    /// The root administrator signed in with MFA (root requires it), as the TypeScript fixture's `rootCredential`.
    async fn root(&self) -> CredentialInput {
        let auth = &self.f.iam.auth;
        let challenge = match auth
            .sign_in(&json!({
                "tenantId": self.f.root_tenant_id,
                "email": "root@example.test",
                "password": "a strong root test password",
            }))
            .await
            .expect("root sign-in")
        {
            SignInResult::MfaRequired(required) => required.challenge,
            SignInResult::Session(_) => panic!("Root must require MFA"),
        };
        let credential = MfaCredential::Challenge {
            tenant_id: self.f.root_tenant_id.clone(),
            challenge,
        };
        let enrollment = auth.begin_mfa(&credential).await.expect("begin MFA");
        let session = auth
            .confirm_mfa(&ConfirmMfaInput {
                credential,
                code: totp::generate(&enrollment.secret, self.f.now()).unwrap(),
                remember_device: false,
            })
            .await
            .expect("confirm MFA");
        bearer(&session.token)
    }
}

#[test]
fn resolves_subjects_inside_the_tenant() {
    run(|| async {
        let s = scenario().await;
        let store = &s.f.database;
        let tenant = s.tenant_id.as_str();
        let resolved =
            privacy::resolve_subject(store, tenant, Some(&json!({ "identityId": s.alice })), None)
                .await
                .unwrap();
        assert_eq!(resolved.key, format!("identity:{}", s.alice));
        assert_eq!(resolved.identity_id.as_deref(), Some(s.alice.as_str()));
        assert_eq!(resolved.identity.as_ref().unwrap().id, s.alice);
        let external = privacy::resolve_subject(
            store,
            tenant,
            Some(&json!({ "externalId": "customer-42" })),
            None,
        )
        .await
        .unwrap();
        assert_eq!(external.key, "external:customer-42");
        assert_eq!(external.external_id.as_deref(), Some("customer-42"));
        assert!(external.identity.is_none());

        for shape in [None, Some(json!(null)), Some(json!([])), Some(json!("x"))] {
            invalid(
                privacy::resolve_subject(store, tenant, shape.as_ref(), None).await,
                "subject must name an identityId or an externalId",
            );
        }
        for shape in [
            json!({}),
            json!({ "identityId": s.alice, "externalId": "customer-42" }),
            // A null member is named (only an absent one is undefined).
            json!({ "identityId": null, "externalId": "customer-42" }),
        ] {
            invalid(
                privacy::resolve_subject(store, tenant, Some(&shape), None).await,
                "subject must name exactly one of identityId or externalId",
            );
        }
        invalid(
            privacy::resolve_subject(store, tenant, Some(&json!({ "identityId": 5 })), None).await,
            "Invalid identityId",
        );
        let missing = privacy::resolve_subject(
            store,
            tenant,
            Some(&json!({ "identityId": "nobody" })),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(
            (
                missing.code.as_str(),
                missing.message.as_str(),
                missing.status
            ),
            ("NOT_FOUND", "Identity not found", 404)
        );
        // Another tenant's people are not found here.
        let elsewhere = privacy::resolve_subject(
            store,
            &s.f.root_tenant_id,
            Some(&json!({ "identityId": s.alice })),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(elsewhere.code, "NOT_FOUND");
        // Service accounts are not data subjects.
        s.f.patch("identities", &s.alice, json!({ "kind": "service" }))
            .await;
        invalid(
            privacy::resolve_subject(store, tenant, Some(&json!({ "identityId": s.alice })), None)
                .await,
            "Only people are data subjects",
        );
        // Tombstones resolve only when allowed.
        s.f.patch(
            "identities",
            &s.alice,
            json!({ "kind": "user", "status": "deleted" }),
        )
        .await;
        let deleted =
            privacy::resolve_subject(store, tenant, Some(&json!({ "identityId": s.alice })), None)
                .await
                .unwrap_err();
        assert_eq!(deleted.code, "NOT_FOUND");
        let allowed = privacy::resolve_subject(
            store,
            tenant,
            Some(&json!({ "identityId": s.alice })),
            Some(true),
        )
        .await
        .unwrap();
        assert_eq!(allowed.key, format!("identity:{}", s.alice));
    });
}

#[test]
fn reads_settings_consents_restrictions_and_holds() {
    run(|| async {
        let s = scenario().await;
        let store = &s.f.database;
        let tenant = s.tenant_id.as_str();
        let settings = privacy::privacy_settings(store, tenant).await.unwrap();
        assert_eq!(settings, privacy::default_privacy_settings(tenant));
        assert_eq!(
            Value::Object(privacy::default_privacy_settings_record(tenant)),
            json!({
                "id": format!("privacy:{tenant}"),
                "tenantId": tenant,
                "defaultRegulation": "gdpr",
                "publicIntake": false,
                "exportLifetimeDays": 14,
                "updatedAt": 0,
            })
        );
        s.f.insert(
            "privacySettings",
            json!({
                "id": format!("privacy:{tenant}"),
                "tenantId": tenant,
                "contactEmail": "dpo@acme.test",
                "defaultRegulation": "ccpa",
                "responseDays": { "ccpa": 30 },
                "publicIntake": true,
                "exportLifetimeDays": 7,
                "updatedAt": 5,
            }),
        )
        .await;
        let settings = privacy::privacy_settings(store, tenant).await.unwrap();
        assert_eq!(settings.contact_email.as_deref(), Some("dpo@acme.test"));
        assert_eq!(settings.default_regulation, json!("ccpa"));
        assert!(settings.public_intake);
        assert_eq!(
            privacy::response_window(
                &settings.default_regulation,
                &serde_json::to_value(&settings).unwrap()
            )
            .unwrap(),
            json!({ "responseDays": 30, "extensionDays": 45 })
        );

        let subject = format!("identity:{}", s.alice);
        s.add_purpose("p1", "marketing-email", "consent", json!({}))
            .await;
        s.add_purpose("p2", "product-analytics", "legitimate-interests", json!({}))
            .await;
        s.decide("p1", "marketing-email", &subject, true).await;
        s.decide("p2", "product-analytics", &subject, false).await;
        s.decide("p1", "marketing-email", "external:other", false)
            .await;
        let consents = privacy::consents_of(store, tenant, &subject).await.unwrap();
        assert_eq!(consents.len(), 2);
        assert!(consents["p1"].granted);
        assert!(!consents["p2"].granted);
        assert!(
            privacy::consents_of(store, &s.f.root_tenant_id, &subject)
                .await
                .unwrap()
                .is_empty()
        );

        assert!(
            privacy::restriction_of(store, tenant, &subject)
                .await
                .unwrap()
                .is_none()
        );
        s.f.insert(
            "privacyRestrictions",
            json!({
                "id": "r1", "tenantId": tenant, "subject": subject, "identityId": s.alice,
                "restrictedAt": s.f.now(), "restrictedBy": s.f.owner_id,
            }),
        )
        .await;
        let restriction = privacy::restriction_of(store, tenant, &subject)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restriction.id, "r1");

        // Holds: an expired one is not live, an open-ended or future one is.
        assert!(
            privacy::active_hold(store, tenant, &subject, s.f.now())
                .await
                .unwrap()
                .is_none()
        );
        s.f.insert(
            "privacyHolds",
            json!({
                "id": "h1", "tenantId": tenant, "subject": subject, "identityId": s.alice,
                "reason": "Old matter", "placedBy": s.f.owner_id, "placedAt": 0, "expiresAt": s.f.now() - 1.0,
            }),
        )
        .await;
        assert!(
            privacy::active_hold(store, tenant, &subject, s.f.now())
                .await
                .unwrap()
                .is_none()
        );
        s.f.insert(
            "privacyHolds",
            json!({
                "id": "h2", "tenantId": tenant, "subject": subject, "identityId": s.alice,
                "reason": "Litigation", "placedBy": s.f.owner_id, "placedAt": 0, "expiresAt": s.f.now() + DAY,
            }),
        )
        .await;
        let hold = privacy::active_hold(store, tenant, &subject, s.f.now())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hold.id, "h2");
        assert!(
            privacy::active_hold(store, tenant, &subject, s.f.now() + DAY)
                .await
                .unwrap()
                .is_none()
        );
        let alice = s.identity(&s.alice).await;
        let error = privacy::assert_no_legal_hold(store, &alice, s.f.now())
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str(), error.status),
            (
                "LEGAL_HOLD",
                "This person is under a legal hold; release the hold before deleting them",
                409
            )
        );
        privacy::assert_no_legal_hold(store, &alice, s.f.now() + DAY)
            .await
            .unwrap();
        // Holds only apply to people.
        let mut service = alice.clone();
        service.kind = better_iam_core::IdentityKind::Service;
        privacy::assert_no_legal_hold(store, &service, s.f.now())
            .await
            .unwrap();

        // Deleting the person's privacy records keeps the history and other subjects' decisions.
        s.f.insert(
            "privacyConsentEvents",
            json!({
                "id": "e1", "tenantId": tenant, "receiptId": "rc1", "purposeId": "p1", "purposeKey": "marketing-email",
                "purposeName": "marketing-email", "legalBasis": "consent", "purposeVersion": 1, "subject": subject,
                "identityId": s.alice, "granted": true, "source": "self", "recordedAt": 0, "recordedBy": s.alice,
            }),
        )
        .await;
        s.f.iam
            .store
            .transaction(
                move |tx| async move { privacy::release_privacy_records(&tx, &alice).await },
            )
            .await
            .unwrap();
        assert!(
            privacy::consents_of(store, tenant, &subject)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            privacy::restriction_of(store, tenant, &subject)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            s.f.find("privacyConsents", &[("subject", json!("external:other"))])
                .await
                .len(),
            1
        );
        assert_eq!(
            s.f.find("privacyConsentEvents", &[("subject", json!(subject))])
                .await
                .len(),
            1
        );
        assert_eq!(
            s.f.find("privacyHolds", &[("subject", json!(subject))])
                .await
                .len(),
            2
        );
    });
}

#[test]
fn exposes_principal_consents_to_policies() {
    // tests/privacy.test.ts "exposes principal.consents to policies".
    run(|| async {
        let s = scenario().await;
        s.add_purpose("p1", "marketing-email", "consent", json!({}))
            .await;
        s.add_purpose("p2", "product-analytics", "legitimate-interests", json!({}))
            .await;
        s.add_purpose(
            "p3",
            "data-sharing",
            "consent",
            json!({ "mode": "opt-out" }),
        )
        .await;
        s.add_purpose("p4", "billing", "contract", json!({})).await;
        s.add_purpose(
            "p5",
            "old-survey",
            "consent",
            json!({ "archived": true, "mode": "opt-out" }),
        )
        .await;
        let role = s
            .f
            .role_with(
                "Newsletter reader",
                json!([{
                    "effect": "allow",
                    "actions": ["documents:read"],
                    "resources": ["*"],
                    "conditions": { "ArrayContains": { "principal.consents": ["marketing-email"] } },
                }]),
            )
            .await;
        s.f.bind(&role, "identity", &s.alice).await;
        let alice_token = s.f.sign_in("alice").await;
        let subject = format!("identity:{}", s.alice);
        assert!(!s.allowed(&alice_token).await);
        s.decide("p1", "marketing-email", &subject, true).await;
        assert!(s.allowed(&alice_token).await);
        s.decide("p1", "marketing-email", &subject, false).await;
        assert!(!s.allowed(&alice_token).await);

        // The context itself: decidable, unarchived purposes that may be processed, sorted by key.
        let store = &s.f.database;
        let alice = s.identity(&s.alice).await;
        let context = |value: Map<String, Value>| value["principal.consents"].clone();
        assert_eq!(
            context(
                privacy::consent_context(store, &s.tenant_id, &alice, s.f.now())
                    .await
                    .unwrap()
            ),
            json!(["data-sharing", "product-analytics"])
        );
        s.decide("p1", "marketing-email", &subject, true).await;
        s.decide("p2", "product-analytics", &subject, false).await;
        assert_eq!(
            context(
                privacy::consent_context(store, &s.tenant_id, &alice, s.f.now())
                    .await
                    .unwrap()
            ),
            json!(["data-sharing", "marketing-email"])
        );
        // Restricted people have nothing processed.
        s.f.insert(
            "privacyRestrictions",
            json!({
                "id": "r1", "tenantId": s.tenant_id, "subject": subject, "identityId": s.alice,
                "restrictedAt": s.f.now(), "restrictedBy": s.f.owner_id,
            }),
        )
        .await;
        assert_eq!(
            context(
                privacy::consent_context(store, &s.tenant_id, &alice, s.f.now())
                    .await
                    .unwrap()
            ),
            json!([])
        );
        assert!(!s.allowed(&alice_token).await);
        // Outside their own tenant, or for a service account, the list is empty.
        assert_eq!(
            context(
                privacy::consent_context(store, &s.f.root_tenant_id, &alice, s.f.now())
                    .await
                    .unwrap()
            ),
            json!([])
        );
        let mut service = alice.clone();
        service.kind = better_iam_core::IdentityKind::Service;
        assert_eq!(
            context(
                privacy::consent_context(store, &s.tenant_id, &service, s.f.now())
                    .await
                    .unwrap()
            ),
            json!([])
        );
    });
}

#[test]
fn refuses_to_delete_people_or_organizations_under_a_legal_hold() {
    // tests/privacy.test.ts "refuses to delete an organization while someone in it is under a legal hold" and the
    // hold step of "erases a person after the legal hold is released".
    run(|| async {
        let s = scenario().await;
        let subject = format!("identity:{}", s.alice);
        s.f.insert(
            "privacyHolds",
            json!({
                "id": "h1", "tenantId": s.tenant_id, "subject": subject, "identityId": s.alice,
                "reason": "Litigation", "placedBy": s.f.owner_id, "placedAt": s.f.now(),
            }),
        )
        .await;
        let error = err(s
            .f
            .iam
            .api
            .identities
            .delete(
                &s.f.owner,
                body(json!({ "tenantId": s.tenant_id, "identityId": s.alice })),
            )
            .await);
        assert_eq!((error.code.as_str(), error.status), ("LEGAL_HOLD", 409));
        let root = s.root().await;
        let error = err(s
            .f
            .iam
            .api
            .tenants
            .set_status(
                &root,
                body(json!({ "tenantId": s.tenant_id, "status": "deleted" })),
            )
            .await);
        assert_eq!(
            (error.code.as_str(), error.message.as_str(), error.status),
            (
                "LEGAL_HOLD",
                "People in this organization are under a legal hold; release the holds before deleting it",
                409
            )
        );
        // A hold below the organization counts too.
        let store = &s.f.database;
        let child = better_iam_server::utils::id();
        s.f.insert(
            "tenants",
            json!({
                "id": child, "tenantId": child, "name": "Acme EU", "type": "organization",
                "parentId": s.tenant_id, "status": "active", "createdAt": s.f.now(),
            }),
        )
        .await;
        s.f.remove("privacyHolds", "h1").await;
        s.f.insert(
            "privacyHolds",
            json!({
                "id": "h2", "tenantId": child, "subject": "external:eu-customer", "externalId": "eu-customer",
                "reason": "Regulator inquiry", "placedBy": s.f.owner_id, "placedAt": s.f.now(),
            }),
        )
        .await;
        let error = privacy::assert_no_tenant_legal_hold(store, &s.tenant_id, s.f.now(), 5.0)
            .await
            .unwrap_err();
        assert_eq!(error.code, "LEGAL_HOLD");
        // ... but only within the configured depth.
        privacy::assert_no_tenant_legal_hold(store, &s.tenant_id, s.f.now(), 0.0)
            .await
            .unwrap();
        // A lapsed hold no longer blocks.
        s.f.patch(
            "privacyHolds",
            "h2",
            json!({ "expiresAt": s.f.now() + DAY }),
        )
        .await;
        privacy::assert_no_tenant_legal_hold(store, &s.tenant_id, s.f.now() + DAY, 5.0)
            .await
            .unwrap();
        // Released: the organization can be deleted. (Deleting the person also passes `identities.delete` through
        // guests.ts, another unit; `release_privacy_records` is covered above.)
        s.f.remove("privacyHolds", "h2").await;
        let result = ok(s
            .f
            .iam
            .api
            .tenants
            .set_status(
                &root,
                body(json!({ "tenantId": s.tenant_id, "status": "deleted" })),
            )
            .await);
        assert_eq!(result["status"], "deleted");
    });
}
