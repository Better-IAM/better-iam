//! Port of tests/security-scim.test.ts: SCIM in both directions: an identity provider cannot undo an administrator's
//! decisions or go past plan limits, its changes reach subscribers, and outbound provisioning never hands someone
//! else's downstream account to a person who merely typed that address.

#[path = "support/fake_server.rs"]
mod fake_server;
#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use better_iam_core::{Filter, Record};
use better_iam_scim::host::{provisioning_config, scim_config};
use better_iam_scim::{HttpResponse, ScimProvisioner, ScimService};
use bytes::Bytes;
use fake_server::{Incoming, serve};
use organization_fixture::{Org, body, ok, organization, run};
use serde_json::{Value, json};

const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

struct Directory {
    f: Org,
    service: ScimService,
    connection: Value,
}

async fn directory() -> Directory {
    let f = organization(|_| {}).await;
    let service = ScimService::new(scim_config(&f.iam).expect("protocol host")).expect("service");
    let connection = service
        .create_connection(
            &f.owner_credential,
            &json!({ "tenantId": f.tenant_id, "name": "Directory" }),
        )
        .await
        .expect("connection");
    Directory {
        f,
        service,
        connection,
    }
}

fn parse(response: HttpResponse) -> (u16, Value) {
    let status = response.status().as_u16();
    (
        status,
        serde_json::from_slice(response.body()).unwrap_or(Value::Null),
    )
}

impl Directory {
    async fn request(&self, resource: &str, method: &str, payload: Option<Value>) -> (u16, Value) {
        let request = http::Request::builder()
            .method(method)
            .uri(format!(
                "https://iam.test{}/{resource}",
                self.connection["path"].as_str().unwrap()
            ))
            .header(
                "authorization",
                format!("Bearer {}", self.connection["token"].as_str().unwrap()),
            )
            .header("content-type", "application/scim+json")
            .body(
                payload
                    .map(|payload| Bytes::from(payload.to_string()))
                    .unwrap_or_default(),
            )
            .unwrap();
        parse(self.service.handler(&request).await.expect("a SCIM answer"))
    }

    async fn identity_of(&self, user: &Value) -> Record {
        let store = self.f.store();
        let link = store
            .get("scimUsers", user["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        store
            .get("identities", link["identityId"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
    }
}

#[test]
fn never_re_enables_someone_an_administrator_disabled_unless_the_idp_itself_deactivated_them() {
    run(|| async {
        let d = directory().await;
        let (_, created) = d
            .request(
                "Users",
                "POST",
                Some(json!({ "userName": "mallory@acme.test", "active": true })),
            )
            .await;
        let identity = d.identity_of(&created).await;
        ok(d.f
            .iam
            .api
            .identities
            .set_status(
                &d.f.owner_credential,
                body(json!({ "tenantId": d.f.tenant_id, "identityId": identity["id"], "status": "disabled" })),
            )
            .await);
        let (status, _) = d
            .request(
                &format!("Users/{}", created["id"].as_str().unwrap()),
                "PATCH",
                Some(json!({ "schemas": [PATCH], "Operations": [{ "op": "replace", "path": "title", "value": "Engineer" }] })),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(d.identity_of(&created).await["status"], json!("disabled"));

        // The IdP's own deactivation and reactivation still round-trip.
        let (_, other) = d
            .request(
                "Users",
                "POST",
                Some(json!({ "userName": "olivia@acme.test", "active": true })),
            )
            .await;
        let path = format!("Users/{}", other["id"].as_str().unwrap());
        let off = json!({ "schemas": [PATCH], "Operations": [{ "op": "replace", "path": "active", "value": false }] });
        let on = json!({ "schemas": [PATCH], "Operations": [{ "op": "replace", "path": "active", "value": true }] });
        assert_eq!(d.request(&path, "PATCH", Some(off)).await.0, 200);
        assert_eq!(d.identity_of(&other).await["status"], json!("disabled"));
        assert_eq!(d.request(&path, "PATCH", Some(on)).await.0, 200);
        assert_eq!(d.identity_of(&other).await["status"], json!("active"));
    });
}

#[test]
fn keeps_to_the_tenant_plan_limits_for_people_and_groups() {
    run(|| async {
        let d = directory().await;
        let members =
            d.f.find(
                "identities",
                Filter::new()
                    .eq("tenantId", d.f.tenant_id.clone())
                    .eq("kind", "user"),
            )
            .await
            .len();
        ok(d.f
            .iam
            .api
            .tenants
            .set_limits(
                &d.f.root_credential,
                body(json!({ "tenantId": d.f.tenant_id, "limits": { "identities": members + 1, "groups": 0 } })),
            )
            .await);
        assert_eq!(
            d.request(
                "Users",
                "POST",
                Some(json!({ "userName": "one@acme.test" }))
            )
            .await
            .0,
            201
        );
        assert_eq!(
            d.request(
                "Users",
                "POST",
                Some(json!({ "userName": "two@acme.test" }))
            )
            .await
            .0,
            409
        );
        assert_eq!(
            d.request("Groups", "POST", Some(json!({ "displayName": "Admins" })))
                .await
                .0,
            409
        );
    });
}

#[test]
fn fans_its_audit_events_out_to_subscribers() {
    run(|| async {
        let d = directory().await;
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let events = d.f.iam.ctx.events().unwrap();
        let subscription = events
            .subscribe(
                &["iam:scim:*"],
                Arc::new(move |event| {
                    sink.lock().unwrap().push(
                        event
                            .get("action")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    );
                    Box::pin(async { Ok(()) })
                }),
            )
            .unwrap();
        assert_eq!(
            d.request(
                "Users",
                "POST",
                Some(json!({ "userName": "sam@acme.test" }))
            )
            .await
            .0,
            201
        );
        events.dispatch().await.unwrap();
        assert!(
            seen.lock()
                .unwrap()
                .contains(&"iam:scim:CreateUser".to_owned())
        );
        subscription.unsubscribe();
    });
}

#[test]
fn refuses_oversized_bodies() {
    run(|| async {
        let d = directory().await;
        let huge = vec![b' '; 1024 * 1024 + 256 * 1024];
        let request = http::Request::builder()
            .method("POST")
            .uri(format!(
                "https://iam.test{}/Users",
                d.connection["path"].as_str().unwrap()
            ))
            .header("content-type", "application/scim+json")
            .body(Bytes::from(huge))
            .unwrap();
        let response = d.service.handler(&request).await.unwrap();
        assert_eq!(response.status().as_u16(), 413);
    });
}

#[test]
fn adopts_a_downstream_account_by_email_only_for_a_verified_address_escaping_filter_values() {
    run(|| async {
        let f = organization(|_| {}).await;
        let users: Arc<Mutex<HashMap<String, Value>>> = Arc::new(Mutex::new(HashMap::from([(
            "victim-remote".to_owned(),
            json!({ "id": "victim-remote", "userName": "victim@acme.test", "active": true }),
        )])));
        let filters: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (state, seen) = (users.clone(), filters.clone());
        let server = serve(Arc::new(move |request: Incoming| {
            let mut users = state.lock().unwrap();
            if request.method == "GET" && request.path == "/scim/Users" {
                let filter = request.param("filter").unwrap_or_default().to_owned();
                seen.lock().unwrap().push(filter.clone());
                let (attribute, value) = filter.split_once(" eq ").expect("an eq filter");
                let wanted: String = serde_json::from_str(value).expect("a JSON string");
                let matches: Vec<Value> = users
                    .values()
                    .filter(|user| user[attribute] == json!(wanted))
                    .cloned()
                    .collect();
                return (
                    200,
                    Some(json!({ "totalResults": matches.len(), "Resources": matches })),
                );
            }
            if request.method == "POST" && request.path == "/scim/Users" {
                let mut user: Value = serde_json::from_str(&request.body).unwrap();
                let id = hex_id();
                user["id"] = json!(id);
                users.insert(id, user.clone());
                return (201, Some(user));
            }
            if request.method == "PUT"
                && let Some(id) = request.path.strip_prefix("/scim/Users/")
            {
                let user: Value = serde_json::from_str(&request.body).unwrap();
                users.insert(id.to_owned(), user.clone());
                return (200, Some(user));
            }
            (404, Some(json!({ "detail": "not found" })))
        }))
        .await;
        // Someone signs up with the victim's address plus a quote: unverified, and not the same address.
        f.insert(
            "identities",
            json!({
                "id": "impostor",
                "tenantId": f.tenant_id,
                "name": "Impostor",
                "kind": "user",
                "email": "victim\"@acme.test",
                "emailVerified": false,
                "status": "active",
                "rootAdmin": false,
                "owner": false,
                "createdAt": better_iam_core::js::now_ms(),
            }),
        )
        .await;
        let key = base64::engine::general_purpose::STANDARD.encode(rand_bytes());
        let mut config = provisioning_config(&f.iam, key).unwrap();
        config.allow_insecure_localhost = true;
        let provisioner = ScimProvisioner::new(config).unwrap();
        let target = provisioner
            .create_target(
                &f.owner_credential,
                &json!({
                    "tenantId": f.tenant_id,
                    "name": "App",
                    "baseUrl": format!("{}/scim", server.origin),
                    "token": "downstream-provisioning-token",
                }),
            )
            .await
            .unwrap();
        provisioner
            .sync_target(
                &f.owner_credential,
                &json!({ "tenantId": f.tenant_id, "targetId": target["id"] }),
            )
            .await
            .unwrap();
        // The victim's downstream account is untouched and the impostor got an account of their own.
        let victim = users.lock().unwrap()["victim-remote"].clone();
        assert_eq!(victim["userName"], json!("victim@acme.test"));
        assert!(victim.get("externalId").is_none());
        let filters = filters.lock().unwrap().clone();
        assert!(filters.contains(&"externalId eq \"impostor\"".to_owned()));
        assert!(
            !filters
                .iter()
                .any(|filter| filter.starts_with("userName eq") && filter.contains("victim"))
        );
    });
}

fn rand_bytes() -> Vec<u8> {
    better_iam_scim::js::random_bytes(32)
}

fn hex_id() -> String {
    hex_encode(&better_iam_scim::js::random_bytes(4))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
