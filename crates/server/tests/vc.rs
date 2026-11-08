//! Verifiable credentials: ported from tests/vc.test.ts, and the credential-offer case of
//! tests/clearances-hardening.test.ts ("needs the holder of an administrator's credential offer cleared at the
//! offer, the redemption and the sweep"). The TypeScript wallet signs with `node:crypto` keys and jose; here a P-256
//! key signs the same OpenID4VCI proofs and presentations through `sd_jwt::sign_jwt` / `present_sd_jwt`.

mod organization_fixture;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_core::{CredentialInput, Filter, FindOptions, IamError, IamResult, IamStore};
use better_iam_server::api::Reply;
use better_iam_server::options::{ClearanceOptions, Toggle};
use better_iam_server::sd_jwt::{
    Disclose, PresentOptions, SigningKey, VerificationKey, VerifyFailure, present_sd_jwt,
    read_disclosure, read_status_list, sign_jwt, split_sd_jwt, status_at,
};
use bytes::Bytes;
use http::Method;
use organization_fixture::{ORIGIN, Org, assert_matches, body, ok, organization, run};
use serde_json::{Map, Value, json};

const DAY: f64 = 86_400_000.0;
const GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

fn issuer_of(org: &Org) -> String {
    format!("{ORIGIN}/api/iam/vc/{}", org.tenant_id)
}

fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `decodeJwt` / `decodeProtectedHeader`: a segment of a compact JWS as JSON.
fn segment(jwt: &str, index: usize) -> Value {
    let part = jwt.split('.').nth(index).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

#[track_caller]
fn code<O>(result: IamResult<Reply<O>>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => error.code,
    }
}

/// A wallet: a P-256 holder key that signs OpenID4VCI proofs and presentations.
struct Wallet {
    key: SigningKey,
    jwk: Map<String, Value>,
}

impl Wallet {
    fn new() -> Self {
        let key = loop {
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&rand::random::<[u8; 32]>()) {
                break key;
            }
        };
        let point = key.verifying_key().to_encoded_point(false);
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64(point.x().unwrap()),
            "y": b64(point.y().unwrap()),
        });
        Wallet {
            key: SigningKey::P256(key),
            jwk: jwk.as_object().unwrap().clone(),
        }
    }

    fn proof(&self, audience: &str, nonce: &str, at: f64) -> String {
        let header = json!({ "alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": self.jwk });
        let payload = json!({ "aud": audience, "nonce": nonce, "iat": (at / 1000.0).floor() });
        sign_jwt(
            header.as_object().unwrap(),
            payload.as_object().unwrap(),
            &self.key,
        )
        .unwrap()
    }

    fn present(
        &self,
        credential: &str,
        disclose: Disclose,
        audience: &str,
        nonce: &str,
        at: f64,
    ) -> String {
        present_sd_jwt(
            credential,
            &PresentOptions {
                disclose,
                holder_key: &self.key,
                alg: "ES256",
                audience,
                nonce,
                issued_at: Some(at),
            },
        )
        .unwrap()
    }
}

async fn fixture(clearances: bool) -> Org {
    organization(|options| {
        options.verifiable_credentials = Some(Toggle::Flag(true));
        if clearances {
            options.clearances = Some(ClearanceOptions::default());
        }
    })
    .await
}

struct Setup {
    org: Org,
    credential_type: Value,
    alice: String,
    alice_session: CredentialInput,
}

/// A role allowing `vc:request` on `credential-type/employee`, bound to an identity (optionally expiring).
async fn allow_requests(
    org: &Org,
    name: &str,
    identity_id: &str,
    expires_at: Option<f64>,
) -> Value {
    let api = &org.iam.api;
    let role = ok(api
        .roles
        .create(
            &org.owner_credential,
            body(json!({
                "tenantId": org.tenant_id,
                "name": name,
                "document": {
                    "version": 1,
                    "statements": [{ "effect": "allow", "actions": ["vc:request"], "resources": ["credential-type/employee"] }],
                },
            })),
        )
        .await);
    let mut input = json!({
        "tenantId": org.tenant_id,
        "roleId": role["id"],
        "subjectType": "identity",
        "subjectId": identity_id,
    });
    if let Some(expires_at) = expires_at {
        input["expiresAt"] = json!(expires_at);
    }
    ok(api
        .bindings
        .create(&org.owner_credential, body(input))
        .await)
}

/// Acme issuing an `employee` credential that alice may request for herself.
async fn setup() -> Setup {
    let org = fixture(false).await;
    let credential_type = ok(org
        .iam
        .api
        .verifiable_credentials
        .create_type(
            &org.owner_credential,
            body(json!({
                "tenantId": org.tenant_id,
                "name": "employee",
                "displayName": "Acme employee",
                "description": "Works at Acme",
                "claims": [
                    { "name": "email", "source": "email", "label": "Email" },
                    { "name": "name", "source": "name", "selective": false },
                    { "name": "organization", "source": "tenantName", "selective": false },
                    { "name": "employee_id", "source": "identityId" },
                    { "name": "clearance", "source": "static", "value": "standard" },
                    { "name": "team_names", "source": "teams" },
                ],
                "lifetimeMs": 7.0 * DAY,
                "backgroundColor": "#112233",
            })),
        )
        .await);
    let alice = org.member("alice").await;
    allow_requests(&org, "Badge holders", &alice, None).await;
    let alice_session = org.sign_in(&alice).await;
    Setup {
        org,
        credential_type,
        alice,
        alice_session,
    }
}

async fn nonce(org: &Org) -> String {
    let answer = ok(org
        .iam
        .api
        .verifiable_credentials
        .nonce(body(json!({ "tenantId": org.tenant_id })))
        .await);
    answer["nonce"].as_str().unwrap().to_owned()
}

async fn request_credential(
    org: &Org,
    session: &CredentialInput,
    holder: &Wallet,
) -> IamResult<Reply<better_iam_types::api::verifiable_credentials::RequestOutput>> {
    let nonce = nonce(org).await;
    org.iam
        .api
        .verifiable_credentials
        .request(
            session,
            body(json!({
                "tenantId": org.tenant_id,
                "type": "employee",
                "proof": holder.proof(&issuer_of(org), &nonce, org.now()),
            })),
        )
        .await
}

/// A request through the HTTP handler: status, headers and body.
async fn send(org: &Org, request: http::Request<Bytes>) -> (u16, http::HeaderMap, Bytes) {
    let response = org.iam.handler(request).await;
    (
        response.status().as_u16(),
        response.headers().clone(),
        response.body().clone(),
    )
}

async fn get(org: &Org, url: &str) -> (u16, http::HeaderMap, Bytes) {
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(url)
        .body(Bytes::new())
        .unwrap();
    send(org, request).await
}

fn json_of(bytes: &Bytes) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

async fn token(org: &Org, pairs: &[(&str, &str)]) -> (u16, Value) {
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let request = http::Request::builder()
        .method(Method::POST)
        .uri(format!("{}/token", issuer_of(org)))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Bytes::from(form))
        .unwrap();
    let (status, _, body) = send(org, request).await;
    (status, json_of(&body))
}

async fn credential_request(org: &Org, authorization: &str, payload: Value) -> (u16, Value) {
    let request = http::Request::builder()
        .method(Method::POST)
        .uri(format!("{}/credential", issuer_of(org)))
        .header("content-type", "application/json")
        .header("authorization", authorization)
        .body(Bytes::from(payload.to_string()))
        .unwrap();
    let (status, _, body) = send(org, request).await;
    (status, json_of(&body))
}

fn pre_authorized_code(offer: &Value) -> String {
    offer["credentialOffer"]["grants"][GRANT]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Audit events of the organization for an action, through `audit.list`.
async fn audit_events(org: &Org, action: &str) -> Vec<Value> {
    let listed = ok(org
        .iam
        .api
        .audit
        .list(
            &org.owner_credential,
            body(json!({ "tenantId": org.tenant_id, "action": action })),
        )
        .await);
    match listed {
        Value::Array(events) => events,
        Value::Object(map) => map
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn sweep_result(result: IamResult<better_iam_server::vc::VcSweepResult>) -> Value {
    result.expect("sweep").to_json()
}

#[test]
fn is_off_unless_the_option_is_set() {
    run(|| async {
        let org = organization(|_| {}).await;
        let refused = code(
            org.iam
                .api
                .verifiable_credentials
                .list_types(
                    &org.owner_credential,
                    body(json!({ "tenantId": org.tenant_id })),
                )
                .await,
        );
        assert_eq!(refused, "FEATURE_DISABLED");
    });
}

#[test]
fn issues_holder_bound_sd_jwt_vcs_that_verify_with_selective_disclosure() {
    run(|| async {
        let Setup {
            org,
            credential_type,
            alice,
            alice_session,
        } = setup().await;
        let issuer = issuer_of(&org);
        assert_eq!(credential_type["vct"], format!("{issuer}/types/employee"));
        let holder = Wallet::new();
        let issued = ok(request_credential(&org, &alice_session, &holder).await);
        let (credential, record) = (issued["credential"].as_str().unwrap(), &issued["record"]);
        assert_matches(
            record,
            json!({ "typeName": "employee", "identityId": alice, "status": "valid", "via": "request" }),
        );

        let split = split_sd_jwt(credential).unwrap();
        assert_matches(
            &segment(&split.jwt, 0),
            json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        );
        let payload = segment(&split.jwt, 1);
        assert_matches(
            &payload,
            json!({
                "iss": issuer,
                "vct": credential_type["vct"],
                "cnf": { "jwk": holder.jwk },
                "name": "alice",
                "organization": "Acme",
                "status": { "status_list": {
                    "idx": record["statusIndex"],
                    "uri": format!("{issuer}/status/{}", record["statusListId"].as_str().unwrap()),
                } },
            }),
        );
        assert_eq!(
            payload["exp"].as_f64().unwrap() - payload["iat"].as_f64().unwrap(),
            7.0 * 86_400.0
        );
        assert!(!payload.to_string().contains("alice@acme.test"));
        let mut names: Vec<String> = split
            .disclosures
            .iter()
            .map(|item| read_disclosure(item).unwrap().0)
            .collect();
        names.sort();
        assert_eq!(names, ["clearance", "email", "employee_id"]);

        // The holder shows only the email to a verifier, bound to its nonce.
        let presentation = holder.present(
            credential,
            Disclose::Names(vec!["email".into()]),
            "https://verifier.example",
            "n-1",
            org.now(),
        );
        let verified = org
            .iam
            .verifiable_credentials
            .verify(
                &presentation,
                Some(&json!({ "audience": "https://verifier.example", "nonce": "n-1" })),
            )
            .await
            .unwrap();
        let verified = Value::Object(verified.to_json());
        assert_matches(
            &verified,
            json!({
                "tenantId": org.tenant_id,
                "type": "employee",
                "disclosed": ["email"],
                "keyBound": true,
                "claims": { "email": "alice@acme.test", "name": "alice", "organization": "Acme" },
            }),
        );
        assert!(verified["claims"].get("employee_id").is_none());
        // The public API reports instead of throwing.
        let reported = ok(org
            .iam
            .api
            .verifiable_credentials
            .verify(body(json!({
                "presentation": presentation,
                "audience": "https://other.example",
                "nonce": "n-1",
            })))
            .await);
        assert_matches(
            &reported,
            json!({ "valid": false, "reason": "wrong-audience" }),
        );

        // A proof nonce works once, and a proof for another issuer is refused.
        let fresh = nonce(&org).await;
        let proof = holder.proof(&issuer, &fresh, org.now());
        let input = json!({ "tenantId": org.tenant_id, "type": "employee", "proof": proof });
        let api = &org.iam.api.verifiable_credentials;
        ok(api.request(&alice_session, body(input.clone())).await);
        assert_eq!(
            code(api.request(&alice_session, body(input)).await),
            "INVALID_NONCE"
        );
        let other = nonce(&org).await;
        let refused = api
            .request(
                &alice_session,
                body(json!({
                    "tenantId": org.tenant_id,
                    "type": "employee",
                    "proof": holder.proof("https://evil.example", &other, org.now()),
                })),
            )
            .await;
        assert_eq!(code(refused), "INVALID_PROOF");
        let mine = ok(api
            .mine(&alice_session, body(json!({ "tenantId": org.tenant_id })))
            .await);
        assert_eq!(mine.as_array().unwrap().len(), 2);
    });
}

#[test]
fn decides_self_service_with_policy_and_refuses_people_without_vc_request() {
    run(|| async {
        let Setup { org, .. } = setup().await;
        let bob = org.member("bob").await;
        let bob_session = org.sign_in(&bob).await;
        assert_eq!(
            code(request_credential(&org, &bob_session, &Wallet::new()).await),
            "ACCESS_DENIED"
        );
        let api = &org.iam.api.verifiable_credentials;
        let available = ok(api
            .available(&bob_session, body(json!({ "tenantId": org.tenant_id })))
            .await);
        assert_eq!(available, json!([]));
        let events = audit_events(&org, "vc:request").await;
        assert!(events.iter().any(|event| event["outcome"] == "deny"));
        // Types that require MFA refuse sessions without it (the owner signed in with a password only).
        ok(api
            .update_type(
                &org.owner_credential,
                body(json!({ "tenantId": org.tenant_id, "name": "employee", "requireMfa": true })),
            )
            .await);
        assert_eq!(
            code(request_credential(&org, &org.owner_credential, &Wallet::new()).await),
            "MFA_REQUIRED"
        );
    });
}

#[test]
fn revokes_and_suspends_through_the_token_status_list() {
    run(|| async {
        let Setup {
            org, alice_session, ..
        } = setup().await;
        let holder = Wallet::new();
        let issued = ok(request_credential(&org, &alice_session, &holder).await);
        let credential = issued["credential"].as_str().unwrap().to_owned();
        let record = issued["record"].clone();
        let record_id = record["id"].as_str().unwrap();
        let api = &org.iam.api.verifiable_credentials;
        let check = || async {
            let presentation = holder.present(
                &credential,
                Disclose::All,
                "https://verifier.example",
                "n",
                org.now(),
            );
            ok(api
                .verify(body(json!({
                    "presentation": presentation,
                    "audience": "https://verifier.example",
                    "nonce": "n",
                })))
                .await)
        };
        assert_matches(&check().await, json!({ "valid": true }));
        ok(api
            .suspend(
                &org.owner_credential,
                body(json!({ "tenantId": org.tenant_id, "credentialId": record_id, "reason": "Lost laptop" })),
            )
            .await);
        assert_matches(
            &check().await,
            json!({ "valid": false, "reason": "suspended" }),
        );

        // Verifiers read the same status from the public status list token, signed by the issuer.
        let status_url = format!(
            "{}/status/{}",
            issuer_of(&org),
            record["statusListId"].as_str().unwrap()
        );
        let (status, headers, token) = get(&org, &status_url).await;
        assert_eq!(status, 200);
        assert_eq!(
            headers.get("content-type").unwrap(),
            "application/statuslist+jwt"
        );
        let (_, _, metadata) = get(
            &org,
            &format!(
                "{ORIGIN}/.well-known/jwt-vc-issuer/api/iam/vc/{}",
                org.tenant_id
            ),
        )
        .await;
        let metadata = json_of(&metadata);
        assert_eq!(metadata["issuer"], issuer_of(&org));
        let key = metadata["jwks"]["keys"][0].as_object().unwrap().clone();
        let list = read_status_list(
            std::str::from_utf8(&token).unwrap(),
            &VerificationKey::Jwk(key),
            &status_url,
            Some(org.now()),
        )
        .await
        .unwrap();
        assert_eq!(
            status_at(&list.bytes, record["statusIndex"].as_f64().unwrap(), 2.0).unwrap(),
            2.0
        );

        ok(api
            .reinstate(
                &org.owner_credential,
                body(json!({ "tenantId": org.tenant_id, "credentialId": record_id })),
            )
            .await);
        assert_matches(&check().await, json!({ "valid": true }));
        // The holder may revoke their own credential; revocation is final.
        ok(api
            .revoke(
                &alice_session,
                body(json!({ "tenantId": org.tenant_id, "credentialId": record_id })),
            )
            .await);
        assert_matches(
            &check().await,
            json!({ "valid": false, "reason": "revoked" }),
        );
        assert_eq!(
            code(
                api.reinstate(
                    &org.owner_credential,
                    body(json!({ "tenantId": org.tenant_id, "credentialId": record_id })),
                )
                .await
            ),
            "INVALID_TRANSITION"
        );
    });
}

#[test]
fn serves_openid4vci_wallets_metadata_offers_with_a_pin_nonce_and_credential_endpoints() {
    run(|| async {
        let Setup {
            org, alice_session, ..
        } = setup().await;
        let issuer = issuer_of(&org);
        let api = &org.iam.api.verifiable_credentials;
        let offer = ok(api
            .create_offer(
                &alice_session,
                body(json!({ "tenantId": org.tenant_id, "type": "employee", "txCode": true })),
            )
            .await);
        assert!(
            offer["offerUri"]
                .as_str()
                .unwrap()
                .starts_with("openid-credential-offer://?credential_offer=")
        );
        assert_matches(
            &offer["credentialOffer"],
            json!({ "credential_issuer": issuer, "credential_configuration_ids": ["employee"] }),
        );
        let code = pre_authorized_code(&offer);
        let pin = offer["txCode"].as_str().unwrap().to_owned();

        let (_, _, metadata) = get(
            &org,
            &format!(
                "{ORIGIN}/.well-known/openid-credential-issuer/api/iam/vc/{}",
                org.tenant_id
            ),
        )
        .await;
        let metadata = json_of(&metadata);
        assert_matches(
            &metadata,
            json!({
                "credential_issuer": issuer,
                "credential_endpoint": format!("{issuer}/credential"),
                "nonce_endpoint": format!("{issuer}/nonce"),
                "credential_configurations_supported": {
                    "employee": {
                        "format": "dc+sd-jwt",
                        "vct": format!("{issuer}/types/employee"),
                        "cryptographic_binding_methods_supported": ["jwk"],
                    },
                },
            }),
        );
        assert_matches(
            &metadata["credential_configurations_supported"]["employee"]["credential_metadata"]["display"]
                [0],
            json!({ "name": "Acme employee", "background_color": "#112233" }),
        );
        let (_, _, type_metadata) = get(&org, &format!("{issuer}/types/employee")).await;
        assert_matches(
            &json_of(&type_metadata),
            json!({ "vct": format!("{issuer}/types/employee"), "name": "Acme employee" }),
        );

        let wrong_pin = if pin == "000000" { "111111" } else { "000000" };
        let (status, wrong) = token(
            &org,
            &[
                ("grant_type", GRANT),
                ("pre-authorized_code", &code),
                ("tx_code", wrong_pin),
            ],
        )
        .await;
        assert_eq!(status, 400);
        assert_matches(&wrong, json!({ "error": "invalid_grant" }));
        let (status, granted) = token(
            &org,
            &[
                ("grant_type", GRANT),
                ("pre-authorized_code", &code),
                ("tx_code", &pin),
            ],
        )
        .await;
        assert_eq!(status, 200);
        let access_token = granted["access_token"].as_str().unwrap().to_owned();
        // The code works once.
        let (status, _) = token(
            &org,
            &[
                ("grant_type", GRANT),
                ("pre-authorized_code", &code),
                ("tx_code", &pin),
            ],
        )
        .await;
        assert_eq!(status, 400);

        let request = http::Request::builder()
            .method(Method::POST)
            .uri(format!("{issuer}/nonce"))
            .body(Bytes::new())
            .unwrap();
        let (_, _, answered) = send(&org, request).await;
        let c_nonce = json_of(&answered)["c_nonce"].as_str().unwrap().to_owned();
        let holder = Wallet::new();
        let payload = json!({
            "credential_configuration_id": "employee",
            "proofs": { "jwt": [holder.proof(&issuer, &c_nonce, org.now())] },
        });
        let (status, _) = credential_request(&org, "Bearer biam_vcat.x.y", payload.clone()).await;
        assert_eq!(status, 401);
        let (status, issued) =
            credential_request(&org, &format!("Bearer {access_token}"), payload.clone()).await;
        assert_eq!(status, 200);
        let credential = issued["credentials"][0]["credential"].as_str().unwrap();
        let claims = segment(&split_sd_jwt(credential).unwrap().jwt, 1);
        assert_matches(
            &claims,
            json!({ "iss": issuer, "cnf": { "jwk": holder.jwk } }),
        );
        // One credential per offer.
        let (status, _) =
            credential_request(&org, &format!("Bearer {access_token}"), payload).await;
        assert_eq!(status, 401);
        let mine = ok(api
            .mine(&alice_session, body(json!({ "tenantId": org.tenant_id })))
            .await);
        let via: Vec<&Value> = mine
            .as_array()
            .unwrap()
            .iter()
            .map(|item| &item["via"])
            .collect();
        assert_eq!(via, [&json!("offer")]);
    });
}

#[test]
fn lets_administrators_offer_credentials_to_others_and_sweeps_credentials_of_people_who_left() {
    run(|| async {
        let Setup {
            org, alice_session, ..
        } = setup().await;
        let bob = org.member("bob").await;
        let api = &org.iam.api.verifiable_credentials;
        let offer = ok(api
            .create_offer(
                &org.owner_credential,
                body(json!({ "tenantId": org.tenant_id, "type": "employee", "identityId": bob })),
            )
            .await);
        assert!(offer.get("txCode").is_none());
        let issued = ok(request_credential(&org, &alice_session, &Wallet::new()).await);
        assert!(
            issued["credential"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
        assert_eq!(
            sweep_result(org.iam.verifiable_credentials.sweep(None).await),
            json!({ "examined": 1, "revoked": 0 })
        );
        // `identities.setStatus` (disabled): written to the identity as that call writes it. The API call itself
        // reaches the package-automation hook, which another port unit owns.
        let identity_id = issued["record"]["identityId"].as_str().unwrap().to_owned();
        let mut identity = org
            .store()
            .get("identities", &identity_id)
            .await
            .unwrap()
            .expect("identity");
        identity.insert("status".into(), json!("disabled"));
        org.put("identities", identity).await;
        assert_eq!(
            sweep_result(
                org.iam
                    .verifiable_credentials
                    .sweep(Some(&json!({ "tenantId": org.tenant_id })))
                    .await
            ),
            json!({ "examined": 1, "revoked": 1 })
        );
        let listed = ok(api
            .list_issued(
                &org.owner_credential,
                body(json!({ "tenantId": org.tenant_id })),
            )
            .await);
        assert_matches(
            &listed["credentials"][0],
            json!({ "status": "revoked", "reason": "identity-inactive" }),
        );
    });
}

#[test]
fn caps_credentials_at_the_grants_that_allow_them_and_revokes_them_when_access_goes_away() {
    run(|| async {
        let Setup {
            org,
            credential_type,
            ..
        } = setup().await;
        let carol = org.member("carol").await;
        let binding = allow_requests(&org, "Visitors", &carol, Some(org.now() + 2.0 * DAY)).await;
        let carol_session = org.sign_in(&carol).await;
        let issued = ok(request_credential(&org, &carol_session, &Wallet::new()).await);
        let record = &issued["record"];
        // A week-long type, but the grant ends in two days.
        assert_eq!(
            record["validUntil"].as_f64().unwrap(),
            org.now() + 2.0 * DAY
        );
        assert_eq!(credential_type["lifetimeMs"].as_f64().unwrap(), 7.0 * DAY);

        // A self-service offer is re-decided at redemption, and the refusal is audited.
        let api = &org.iam.api.verifiable_credentials;
        let offer = ok(api
            .create_offer(
                &carol_session,
                body(json!({ "tenantId": org.tenant_id, "type": "employee" })),
            )
            .await);
        ok(org
            .iam
            .api
            .bindings
            .delete(
                &org.owner_credential,
                body(json!({ "tenantId": org.tenant_id, "bindingId": binding["id"] })),
            )
            .await);
        let code = pre_authorized_code(&offer);
        let (_, granted) = token(
            &org,
            &[("grant_type", GRANT), ("pre-authorized_code", &code)],
        )
        .await;
        let access_token = granted["access_token"].as_str().unwrap().to_owned();
        let fresh = nonce(&org).await;
        let holder = Wallet::new();
        let (status, _) = credential_request(
            &org,
            &format!("Bearer {access_token}"),
            json!({
                "credential_configuration_id": "employee",
                "proofs": { "jwt": [holder.proof(&issuer_of(&org), &fresh, org.now())] },
            }),
        )
        .await;
        assert_eq!(status, 403);
        let events = audit_events(&org, "vc:offer:redeem").await;
        let denied = events
            .iter()
            .find(|event| event["outcome"] == "deny")
            .expect("a refused redemption");
        assert_matches(&denied["metadata"], json!({ "reason": "access-changed" }));

        // The sweep revokes what was issued once `vc:request` no longer allows it.
        assert_eq!(
            sweep_result(
                org.iam
                    .verifiable_credentials
                    .sweep(Some(&json!({ "tenantId": org.tenant_id })))
                    .await
            ),
            json!({ "examined": 1, "revoked": 1 })
        );
        let listed = ok(api
            .list_issued(
                &org.owner_credential,
                body(json!({ "tenantId": org.tenant_id })),
            )
            .await);
        let swept = listed["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == record["id"])
            .unwrap();
        assert_matches(
            swept,
            json!({ "status": "revoked", "reason": "access-changed" }),
        );
    });
}

#[test]
fn refuses_replays_squatted_types_and_pin_guessing() {
    run(|| async {
        let Setup {
            org, alice_session, ..
        } = setup().await;
        let holder = Wallet::new();
        let issued = ok(request_credential(&org, &alice_session, &holder).await);
        let presentation = holder.present(
            issued["credential"].as_str().unwrap(),
            Disclose::Names(Vec::new()),
            "a",
            "n",
            org.now(),
        );
        let api = &org.iam.api.verifiable_credentials;
        // Without the verifier's audience and nonce, a captured presentation would verify for anyone.
        assert_eq!(
            code(
                api.verify(body(json!({ "presentation": presentation })))
                    .await
            ),
            "INVALID_INPUT"
        );
        let verified = org
            .iam
            .verifiable_credentials
            .verify(
                &presentation,
                Some(&json!({ "audience": "a", "nonce": "n" })),
            )
            .await
            .unwrap();
        assert_matches(
            verified.key_binding.as_ref().unwrap(),
            json!({ "audience": "a", "nonce": "n" }),
        );

        // Type identifiers under another organization's issuer are not this one's to claim.
        let base = format!("{ORIGIN}/api/iam/vc/");
        let squat = api
            .create_type(
                &org.owner_credential,
                body(json!({
                    "tenantId": org.tenant_id,
                    "name": "squat",
                    "displayName": "Squat",
                    "vct": format!("{base}other-org/types/employee"),
                    "claims": [{ "name": "email", "source": "email" }],
                })),
            )
            .await;
        assert_eq!(code(squat), "INVALID_INPUT");
        let external = ok(api
            .create_type(
                &org.owner_credential,
                body(json!({
                    "tenantId": org.tenant_id,
                    "name": "external",
                    "displayName": "External schema",
                    "vct": "https://schemas.example/employee",
                    "claims": [{ "name": "email", "source": "email" }],
                })),
            )
            .await);
        assert_eq!(external["vct"], "https://schemas.example/employee");

        // A wallet that has not asked for the PIN yet has not guessed wrong; wrong guesses are audited and five end
        // the offer.
        let offer = ok(api
            .create_offer(
                &alice_session,
                body(json!({ "tenantId": org.tenant_id, "type": "employee", "txCode": true })),
            )
            .await);
        let code_value = pre_authorized_code(&offer);
        let pin = offer["txCode"].as_str().unwrap().to_owned();
        for _ in 0..6 {
            let (_, answer) = token(
                &org,
                &[("grant_type", GRANT), ("pre-authorized_code", &code_value)],
            )
            .await;
            assert_eq!(answer["error"], "invalid_request");
        }
        let wrong_pin = if pin == "000000" { "111111" } else { "000000" };
        for _ in 0..5 {
            let (_, answer) = token(
                &org,
                &[
                    ("grant_type", GRANT),
                    ("pre-authorized_code", &code_value),
                    ("tx_code", wrong_pin),
                ],
            )
            .await;
            assert_eq!(answer["error"], "invalid_grant");
        }
        let (status, _) = token(
            &org,
            &[
                ("grant_type", GRANT),
                ("pre-authorized_code", &code_value),
                ("tx_code", &pin),
            ],
        )
        .await;
        assert_eq!(status, 400);
        let mut reasons: Vec<String> = audit_events(&org, "vc:offer:redeem")
            .await
            .iter()
            .filter(|event| event["outcome"] == "deny")
            .map(|event| event["metadata"]["reason"].as_str().unwrap().to_owned())
            .collect();
        reasons.sort();
        assert_eq!(
            reasons,
            [
                "pin-locked",
                "wrong-pin",
                "wrong-pin",
                "wrong-pin",
                "wrong-pin"
            ]
        );
    });
}

#[test]
fn rotates_issuer_keys_old_credentials_keep_verifying_until_the_key_is_retired() {
    run(|| async {
        let Setup {
            org, alice_session, ..
        } = setup().await;
        let holder = Wallet::new();
        let issued = ok(request_credential(&org, &alice_session, &holder).await);
        let api = &org.iam.api.verifiable_credentials;
        let tenant = json!({ "tenantId": org.tenant_id });
        let keys = ok(api
            .list_keys(&org.owner_credential, body(tenant.clone()))
            .await);
        let first = keys[0]["kid"].as_str().unwrap().to_owned();
        let next = ok(api
            .rotate_key(&org.owner_credential, body(tenant.clone()))
            .await);
        assert_ne!(next["kid"], first);
        let presentation = holder.present(
            issued["credential"].as_str().unwrap(),
            Disclose::Names(Vec::new()),
            "a",
            "n",
            org.now(),
        );
        let verify = || async {
            ok(api
                .verify(body(
                    json!({ "presentation": presentation, "audience": "a", "nonce": "n" }),
                ))
                .await)
        };
        assert_matches(&verify().await, json!({ "valid": true }));
        let fresh = ok(request_credential(&org, &alice_session, &holder).await);
        let header = segment(
            &split_sd_jwt(fresh["credential"].as_str().unwrap())
                .unwrap()
                .jwt,
            0,
        );
        assert_eq!(header["kid"], next["kid"]);
        let retire = |force: bool| {
            let mut input = json!({ "tenantId": org.tenant_id, "kid": first });
            if force {
                input["force"] = json!(true);
            }
            api.retire_key(&org.owner_credential, body(input))
        };
        assert_eq!(code(retire(false).await), "RESOURCE_IN_USE");
        ok(retire(true).await);
        assert_matches(
            &verify().await,
            json!({ "valid": false, "reason": "unknown-issuer" }),
        );
    });
}

/// Audit records of the organization for an action, straight from the store.
async fn audit_records(org: &Org, action: &str) -> Vec<Value> {
    let store: std::sync::Arc<dyn IamStore> = org.store();
    store
        .find(
            "audit",
            &Filter::new()
                .eq("tenantId", org.tenant_id.clone())
                .eq("action", action.to_owned()),
            &FindOptions::default(),
        )
        .await
        .unwrap()
        .into_iter()
        .map(Value::Object)
        .collect()
}

/// Redeems a credential offer the way a wallet does: the pre-authorized code, then the credential request.
async fn redeem(org: &Org, offer: &Value, credential_type: &str) -> u16 {
    let code = pre_authorized_code(offer);
    let (_, granted) = token(
        org,
        &[("grant_type", GRANT), ("pre-authorized_code", &code)],
    )
    .await;
    let access_token = granted["access_token"].as_str().unwrap().to_owned();
    let fresh = nonce(org).await;
    let proof = Wallet::new().proof(&issuer_of(org), &fresh, org.now());
    let (status, _) = credential_request(
        org,
        &format!("Bearer {access_token}"),
        json!({ "credential_configuration_id": credential_type, "proofs": { "jwt": [proof] } }),
    )
    .await;
    status
}

#[test]
fn needs_the_holder_of_an_administrators_credential_offer_cleared_at_the_offer_the_redemption_and_the_sweep()
 {
    run(|| async {
        let org = fixture(true).await;
        let tenant_id = org.tenant_id.clone();
        let owner = &org.owner_credential;
        let clearances = &org.iam.api.clearances;
        ok(clearances
            .define_scheme(
                owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Acme",
                    "template": "us",
                    "adjudication": "unrestricted",
                })),
            )
            .await);
        ok(org
            .iam
            .api
            .verifiable_credentials
            .create_type(
                owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "facility-badge",
                    "displayName": "Facility badge",
                    "claims": [{ "name": "name", "source": "name", "selective": false }],
                })),
            )
            .await);
        ok(clearances
            .label(
                owner,
                body(json!({
                    "tenantId": tenant_id,
                    "type": "credential-type",
                    "id": "facility-badge",
                    "label": { "level": "TS" },
                })),
            )
            .await);
        let bob = org.member("bob").await;
        let offer = || async {
            org.iam
                .api
                .verifiable_credentials
                .create_offer(
                    owner,
                    body(json!({ "tenantId": tenant_id, "type": "facility-badge", "identityId": bob })),
                )
                .await
        };
        assert_eq!(code(offer().await), "ACCESS_DENIED");
        ok(clearances
            .grant(
                owner,
                body(json!({ "tenantId": tenant_id, "identityId": bob, "level": "TS", "citizenship": ["USA"] })),
            )
            .await);
        let early = ok(offer().await);
        let suspend = || async {
            ok(clearances
                .suspend(
                    owner,
                    body(json!({
                        "tenantId": tenant_id,
                        "identityId": bob,
                        "reason": "review",
                        "notifyPerson": false,
                    })),
                )
                .await)
        };
        // Suspended before the wallet redeems it: the offer is decided again and refused.
        suspend().await;
        assert_eq!(redeem(&org, &early, "facility-badge").await, 403);
        let refusals: Vec<Value> = audit_records(&org, "vc:offer:redeem")
            .await
            .into_iter()
            .filter(|event| event["outcome"] == "deny")
            .map(|event| event["metadata"]["reason"].clone())
            .collect();
        assert_eq!(refusals, [json!("access-changed")]);
        ok(clearances
            .reinstate(
                owner,
                body(json!({ "tenantId": tenant_id, "identityId": bob })),
            )
            .await);
        let later = ok(offer().await);
        assert_eq!(redeem(&org, &later, "facility-badge").await, 200);
        let tenant = json!({ "tenantId": tenant_id });
        assert_eq!(
            sweep_result(org.iam.verifiable_credentials.sweep(Some(&tenant)).await),
            json!({ "examined": 1, "revoked": 0 })
        );
        // The sweep revokes it once the holder no longer dominates the type's label.
        suspend().await;
        assert_eq!(
            sweep_result(org.iam.verifiable_credentials.sweep(Some(&tenant)).await),
            json!({ "examined": 1, "revoked": 1 })
        );
        let listed = ok(org
            .iam
            .api
            .verifiable_credentials
            .list_issued(owner, body(tenant.clone()))
            .await);
        assert_matches(
            &listed["credentials"][0],
            json!({ "identityId": bob, "status": "revoked", "reason": "access-changed" }),
        );
    });
}

#[test]
fn runtime_verification_reports_its_reason_and_is_answered_as_an_exception_elsewhere() {
    run(|| async {
        let Setup {
            org, alice_session, ..
        } = setup().await;
        let holder = Wallet::new();
        let issued = ok(request_credential(&org, &alice_session, &holder).await);
        let presentation = holder.present(
            issued["credential"].as_str().unwrap(),
            Disclose::All,
            "a",
            "n",
            org.now(),
        );
        let runtime = &org.iam.verifiable_credentials;
        assert!(runtime.enabled().unwrap());
        assert_eq!(runtime.issuer(&org.tenant_id).unwrap(), issuer_of(&org));
        let failure = runtime
            .verify(
                &presentation,
                Some(&json!({ "audience": "b", "nonce": "n" })),
            )
            .await
            .unwrap_err();
        match failure {
            VerifyFailure::SdJwt(error) => assert_eq!(error.reason, "wrong-audience"),
            VerifyFailure::Other(error) => panic!("unexpected {error:?}"),
        }
        // Through the conformance `call`, an SdJwtError is an exception that is not an IamError.
        let called = runtime
            .call(
                "verify",
                vec![
                    json!(presentation),
                    json!({ "audience": "b", "nonce": "n" }),
                ],
            )
            .await
            .unwrap();
        let error: IamError = called.unwrap_err();
        assert_eq!(error.code, "INTERNAL_ERROR");
        let nonce = runtime
            .call("nonce", vec![json!(org.tenant_id)])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(nonce.as_str().unwrap().split('.').count(), 3);
    });
}
