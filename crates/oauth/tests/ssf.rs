//! Port of tests/ssf.test.ts (and the Shared Signals case of tests/security-outbound.test.ts): the transmitter.

mod common;
#[allow(unused_imports)]
#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_core::{CredentialInput, Filter, IamStoreExt};
use better_iam_oauth::jose::{self, KeySet, VerifyKey, VerifyOptions};
use better_iam_oauth::{
    SharedSignalsConfig, SharedSignalsTransmitter, create_shared_signals_transmitter,
    shared_signal_events,
};
use bytes::Bytes;
use common::host::protocol_host;
use common::{Handler, HttpRequest, random_key_b64, rsa_key, serve, text_response};
use organization_fixture::{Org, body, organization};
use serde_json::{Map, Value, json};

const ISSUER: &str = "https://id.example.test/oidc";

/// A received delivery: the authorization header, the content type, and the SET.
type Delivery = (Option<String>, Option<String>, String);

/// A push receiver (RFC 8935) that records every SET and can be told to refuse.
#[derive(Clone)]
struct Receiver {
    received: Arc<Mutex<Vec<Delivery>>>,
    status: Arc<Mutex<u16>>,
    url: String,
}

async fn receiver() -> Receiver {
    let received: Arc<Mutex<Vec<Delivery>>> = Arc::new(Mutex::new(Vec::new()));
    let status = Arc::new(Mutex::new(202u16));
    let (sink, code) = (received.clone(), status.clone());
    let handler: Handler = Arc::new(move |request: HttpRequest| {
        let (sink, code) = (sink.clone(), code.clone());
        Box::pin(async move {
            let header = |name: &str| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            };
            sink.lock().unwrap().push((
                header("authorization"),
                header("content-type"),
                String::from_utf8_lossy(request.body()).into_owned(),
            ));
            let status = *code.lock().unwrap();
            let body = if status == 202 {
                String::new()
            } else {
                json!({ "err": "invalid_request", "description": "nope" }).to_string()
            };
            http::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Bytes::from(body))
                .unwrap()
        })
    });
    let origin = serve(handler).await;
    Receiver {
        received,
        status,
        url: format!("{origin}/events"),
    }
}

impl Receiver {
    fn refuse(&self, code: u16) {
        *self.status.lock().unwrap() = code;
    }
    fn last(&self) -> Delivery {
        self.received
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a delivery")
    }
    fn len(&self) -> usize {
        self.received.lock().unwrap().len()
    }
}

struct Setup {
    org: Org,
    endpoint: Receiver,
    transmitter: Arc<SharedSignalsTransmitter>,
    public: Value,
}

fn transmitter_config(org: &Org, keys: Value) -> SharedSignalsConfig {
    let host = protocol_host(&org.iam).expect("protocol host");
    SharedSignalsConfig {
        store: host.store.clone(),
        authorize: host.ssf_authorize(),
        authenticate: host.ssf_authenticate(),
        issuer: ISSUER.into(),
        jwks: keys,
        jwks_uri: None,
        encryption_key: random_key_b64(),
        allow_insecure_localhost: true,
        allow_private_networks: false,
        timeout_ms: None,
        fetch: None,
    }
}

async fn setup() -> Setup {
    let org = organization(|_| {}).await;
    let endpoint = receiver().await;
    let (private, public) = rsa_key(1, "ssf-key");
    let mut private = private;
    private.as_object_mut().unwrap().remove("use");
    let transmitter =
        create_shared_signals_transmitter(transmitter_config(&org, json!({ "keys": [private] })))
            .expect("transmitter");
    Setup {
        org,
        endpoint,
        transmitter,
        public,
    }
}

fn decode(public: &Value, set: &str) -> (Map<String, Value>, Map<String, Value>) {
    let keys = KeySet::new(vec![public.as_object().cloned().unwrap()]);
    let decoded = jose::verify_jwt(
        set,
        VerifyKey::Set(&keys),
        &VerifyOptions {
            issuer: Some(vec![ISSUER.into()]),
            typ: Some("secevent+jwt".into()),
            ..VerifyOptions::default()
        },
    )
    .expect("verified SET");
    (decoded.payload, decoded.header)
}

fn subscribe(setup: &Setup) -> better_iam_server::events::Subscription {
    let events = setup.org.iam.ctx.events().expect("events").clone();
    setup
        .transmitter
        .subscribe(
            move |patterns, handler| events.subscribe(patterns, handler),
            None,
        )
        .expect("subscribed")
}

async fn change_password(org: &Org, credential: &CredentialInput, current: &str, password: &str) {
    org.iam
        .auth
        .change_password(
            credential,
            &json!({ "currentPassword": current, "password": password }),
        )
        .await
        .expect("password changed");
}

#[test]
fn pushes_signed_caep_and_risc_events_for_iam_activity_to_each_tenant_stream() {
    organization_fixture::run(|| async {
        let s = setup().await;
        let tenant_id = s.org.tenant_id.clone();
        let owner = s.org.owner_credential.clone();
        let stream = s
            .transmitter
            .create_stream(
                &owner,
                &json!({ "tenantId": tenant_id, "name": "SIEM", "endpointUrl": s.endpoint.url, "authorization": "Bearer receiver-secret" }),
            )
            .await
            .expect("stream");
        assert_eq!(stream["hasAuthorization"], json!(true));
        assert_eq!(stream["subjectFormat"], json!("iss_sub"));
        assert_eq!(stream["pending"], json!(0));
        assert!(!stream.to_string().contains("receiver-secret"));
        let stream_id = stream["id"].as_str().unwrap().to_owned();
        let verification = s
            .transmitter
            .verify_stream(
                &owner,
                &json!({ "tenantId": tenant_id, "streamId": stream_id, "state": "check-123" }),
            )
            .await
            .expect("verification");
        assert_eq!(verification["delivered"], json!(true), "{verification}");
        let first = s.endpoint.received.lock().unwrap()[0].clone();
        assert_eq!(first.0.as_deref(), Some("Bearer receiver-secret"));
        assert_eq!(first.1.as_deref(), Some("application/secevent+jwt"));
        let (payload, header) = decode(&s.public, &first.2);
        assert_eq!(header["typ"], json!("secevent+jwt"));
        assert_eq!(header["kid"], json!("ssf-key"));
        assert_eq!(payload["aud"], json!(s.endpoint.url));
        assert_eq!(
            payload["events"]["https://schemas.openid.net/secevent/ssf/event-type/verification"],
            json!({ "state": "check-123" })
        );
        let subscription = subscribe(&s);
        let alice = s.org.member("alice").await;
        let _alice_session = s.org.sign_in(&alice).await;
        let fresh_owner = s.org.session(&s.org.owner_id, false).await;
        s.org
            .iam
            .api
            .identities
            .revoke_sessions(
                &fresh_owner,
                body(json!({ "tenantId": tenant_id, "identityId": alice })),
            )
            .await
            .expect("revoked");
        s.org.iam.dispatch_audit_hooks().await.expect("dispatched");
        let (revoked, _) = decode(&s.public, &s.endpoint.last().2);
        assert_eq!(
            revoked["sub_id"],
            json!({ "format": "iss_sub", "iss": ISSUER, "sub": alice })
        );
        assert_eq!(
            revoked["events"][shared_signal_events::SESSION_REVOKED]["initiating_entity"],
            json!("admin")
        );
        assert!(revoked["txn"].is_string());
        let again = s.org.sign_in(&alice).await;
        change_password(
            &s.org,
            &again,
            "a strong alice password",
            "an even stronger alice password",
        )
        .await;
        s.org.iam.dispatch_audit_hooks().await.expect("dispatched");
        let (changed, _) = decode(&s.public, &s.endpoint.last().2);
        let event = &changed["events"][shared_signal_events::CREDENTIAL_CHANGE];
        assert_eq!(event["credential_type"], json!("password"));
        assert_eq!(event["change_type"], json!("update"));
        assert_eq!(event["initiating_entity"], json!("user"));
        let deliveries = s
            .transmitter
            .list_deliveries(
                &owner,
                &json!({ "tenantId": tenant_id, "streamId": stream_id }),
            )
            .await
            .unwrap();
        assert!(
            deliveries
                .iter()
                .all(|delivery| delivery["status"] == json!("delivered"))
        );
        assert_eq!(
            deliveries[0]["eventType"],
            json!(shared_signal_events::CREDENTIAL_CHANGE)
        );
        subscription.unsubscribe();
        let actions: Vec<String> = s
            .org
            .find("audit", Filter::new().eq("tenantId", tenant_id))
            .await
            .iter()
            .map(|event| event["action"].as_str().unwrap_or_default().to_owned())
            .collect();
        assert!(actions.contains(&"iam:ssf:CreateStream".to_owned()));
    });
}

#[test]
fn filters_event_types_identifies_by_email_retries_failures_holds_events_while_paused() {
    organization_fixture::run(|| async {
        let s = setup().await;
        let tenant_id = s.org.tenant_id.clone();
        let owner = s.org.owner_credential.clone();
        let stream = s
            .transmitter
            .create_stream(
                &owner,
                &json!({
                    "tenantId": tenant_id, "name": "Credentials only", "endpointUrl": s.endpoint.url,
                    "audience": "https://receiver.example.test", "events": [shared_signal_events::CREDENTIAL_CHANGE],
                    "subjectFormat": "email",
                }),
            )
            .await
            .unwrap();
        let stream_id = stream["id"].as_str().unwrap().to_owned();
        let _subscription = subscribe(&s);
        let created = s.org.member("bob").await;
        let mut record = s
            .org
            .store()
            .get("identities", &created)
            .await
            .unwrap()
            .unwrap();
        record.insert("emailVerified".into(), json!(true));
        s.org.put("identities", record).await;
        let bob = s.org.sign_in(&created).await;
        s.endpoint.refuse(500);
        change_password(
            &s.org,
            &bob,
            "a strong bob password",
            "an even stronger bob password",
        )
        .await;
        s.org.iam.dispatch_audit_hooks().await.unwrap();
        let deliveries = s
            .transmitter
            .list_deliveries(
                &owner,
                &json!({ "tenantId": tenant_id, "streamId": stream_id }),
            )
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0]["status"], json!("pending"));
        assert_eq!(deliveries[0]["attempts"], json!(1));
        assert_eq!(
            deliveries[0]["lastError"],
            json!("HTTP 500: invalid_request nope")
        );
        let read = s
            .transmitter
            .get_stream(
                &owner,
                &json!({ "tenantId": tenant_id, "streamId": stream_id }),
            )
            .await
            .unwrap();
        assert!(read["lastError"].as_str().unwrap().contains("HTTP 500"));
        assert_eq!(
            s.transmitter.dispatch(None).await.unwrap(),
            json!({ "delivered": 0, "failed": 0 })
        );
        s.endpoint.refuse(202);
        let store = s.org.store();
        let id = stream_id.clone();
        store
            .transaction(move |tx| async move {
                let mut record = tx
                    .find(
                        "ssfDeliveries",
                        &Filter::new().eq("streamId", id),
                        &Default::default(),
                    )
                    .await?
                    .remove(0);
                record.insert("nextAttemptAt".into(), json!(0));
                tx.put("ssfDeliveries", &record).await?;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            s.transmitter.dispatch(None).await.unwrap(),
            json!({ "delivered": 1, "failed": 0 })
        );
        let (set, _) = decode(&s.public, &s.endpoint.last().2);
        assert_eq!(set["aud"], json!("https://receiver.example.test"));
        assert_eq!(
            set["sub_id"],
            json!({ "format": "email", "email": "bob@acme.test" })
        );
        assert_eq!(set["tenant_id"], json!(tenant_id));
        s.transmitter
            .update_stream(
                &owner,
                &json!({ "tenantId": tenant_id, "streamId": stream_id, "enabled": false }),
            )
            .await
            .unwrap();
        let before = s.endpoint.len();
        let signed_in = s
            .org
            .iam
            .auth
            .sign_in(&json!({ "tenantId": tenant_id, "email": "bob@acme.test", "password": "an even stronger bob password" }))
            .await
            .expect("signed in");
        let token = serde_json::to_value(&signed_in).unwrap()["token"]
            .as_str()
            .expect("no MFA")
            .to_owned();
        let bob_again = CredentialInput {
            headers: None,
            token: Some(token),
        };
        change_password(
            &s.org,
            &bob_again,
            "an even stronger bob password",
            "the strongest bob password",
        )
        .await;
        s.org.iam.dispatch_audit_hooks().await.unwrap();
        assert_eq!(s.endpoint.len(), before);
        let read = s
            .transmitter
            .get_stream(
                &owner,
                &json!({ "tenantId": tenant_id, "streamId": stream_id }),
            )
            .await
            .unwrap();
        assert_eq!(read["pending"], json!(1));
        s.transmitter
            .update_stream(
                &owner,
                &json!({ "tenantId": tenant_id, "streamId": stream_id, "enabled": true }),
            )
            .await
            .unwrap();
        assert_eq!(
            s.transmitter.dispatch(None).await.unwrap(),
            json!({ "delivered": 1, "failed": 0 })
        );
        assert_eq!(s.endpoint.len(), before + 1);
        s.transmitter
            .delete_stream(
                &owner,
                &json!({ "tenantId": tenant_id, "streamId": stream_id }),
            )
            .await
            .unwrap();
        assert!(
            s.org
                .find("ssfDeliveries", Filter::new().eq("streamId", stream_id))
                .await
                .is_empty()
        );
    });
}

#[test]
fn guards_management_and_validates_streams_serves_transmitter_metadata() {
    organization_fixture::run(|| async {
        let s = setup().await;
        let tenant_id = s.org.tenant_id.clone();
        let owner = s.org.owner_credential.clone();
        let carol_id = s.org.member("carol").await;
        let carol = s.org.sign_in(&carol_id).await;
        let denied = s
            .transmitter
            .create_stream(
                &carol,
                &json!({ "tenantId": tenant_id, "name": "X", "endpointUrl": s.endpoint.url }),
            )
            .await
            .unwrap_err();
        assert_eq!(denied.status, 403);
        for change in [
            json!({ "endpointUrl": "http://receiver.example.test/events" }),
            json!({ "endpointUrl": "not a url" }),
            json!({ "events": ["https://example.test/unknown"] }),
            json!({ "subjectFormat": "phone" }),
            json!({ "authorization": "Bearer a\r\nx-injected: 1" }),
            json!({ "name": "" }),
        ] {
            let mut input =
                json!({ "tenantId": tenant_id, "name": "X", "endpointUrl": s.endpoint.url });
            for (key, value) in change.as_object().unwrap() {
                input[key] = value.clone();
            }
            let error = s
                .transmitter
                .create_stream(&owner, &input)
                .await
                .unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "{change}");
        }
        let request = |url: &str| {
            http::Request::builder()
                .uri(url)
                .body(Bytes::new())
                .unwrap()
        };
        let served = s
            .transmitter
            .handler(&request(
                "https://id.example.test/.well-known/ssf-configuration/oidc",
            ))
            .expect("served");
        let metadata: Value = serde_json::from_slice(served.body()).unwrap();
        assert_eq!(metadata["spec_version"], json!("1_0"));
        assert_eq!(metadata["issuer"], json!(ISSUER));
        assert_eq!(metadata["jwks_uri"], json!(format!("{ISSUER}/jwks")));
        assert_eq!(
            metadata["delivery_methods_supported"],
            json!(["urn:ietf:rfc:8935"])
        );
        assert!(
            s.transmitter
                .handler(&request("https://id.example.test/other"))
                .is_none()
        );
        let refused = create_shared_signals_transmitter(transmitter_config(
            &s.org,
            json!({ "keys": [s.public] }),
        ))
        .expect_err("refused");
        assert!(refused.message.contains("private signing key"));
    });
}

/// tests/security-outbound.test.ts, "Shared Signals receivers".
#[test]
fn refuses_private_endpoints_and_keeps_the_stored_authorization_from_following_an_endpoint_change()
{
    organization_fixture::run(|| async {
        let org = organization(|_| {}).await;
        let tenant_id = org.tenant_id.clone();
        let owner = org.owner_credential.clone();
        let (private, _) = rsa_key(1, "k");
        let transmitter = create_shared_signals_transmitter(transmitter_config(
            &org,
            json!({ "keys": [private] }),
        ))
        .unwrap();
        for endpoint in ["https://10.0.0.1/events", "https://169.254.169.254/events"] {
            let error = transmitter
                .create_stream(
                    &owner,
                    &json!({ "tenantId": tenant_id, "name": "SIEM", "endpointUrl": endpoint }),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "{endpoint}");
        }
        let received: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();
        let origin = serve(Arc::new(move |request: HttpRequest| {
            let sink = sink.clone();
            Box::pin(async move {
                sink.lock().unwrap().push(
                    request
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned),
                );
                text_response(202, "")
            })
        }))
        .await;
        let stream = transmitter
            .create_stream(
                &owner,
                &json!({ "tenantId": tenant_id, "name": "SIEM", "endpointUrl": "https://siem.example.test/events", "authorization": "Bearer receiver-secret" }),
            )
            .await
            .unwrap();
        let stream_id = stream["id"].as_str().unwrap().to_owned();
        let moved = transmitter
            .update_stream(&owner, &json!({ "tenantId": tenant_id, "streamId": stream_id, "endpointUrl": format!("{origin}/events") }))
            .await
            .unwrap_err();
        assert_eq!(moved.code, "INVALID_INPUT");
        transmitter
            .update_stream(
                &owner,
                &json!({ "tenantId": tenant_id, "streamId": stream_id, "endpointUrl": format!("{origin}/events"), "authorization": null }),
            )
            .await
            .unwrap();
        let verified = transmitter
            .verify_stream(
                &owner,
                &json!({ "tenantId": tenant_id, "streamId": stream_id }),
            )
            .await
            .unwrap();
        assert_eq!(verified["delivered"], json!(true), "{verified}");
        assert_eq!(*received.lock().unwrap(), vec![None]);
    });
}
