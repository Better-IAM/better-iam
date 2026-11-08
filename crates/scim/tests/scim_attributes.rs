//! Port of the SCIM part of tests/federation-import-gaps.test.ts: attributes the service does not store (lenient
//! `unsupportedAttributes: 'ignore'` and strict `'reject'`).

#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use better_iam_scim::host::scim_config;
use better_iam_scim::{HttpResponse, ScimService};
use bytes::Bytes;
use organization_fixture::{Org, organization, run};
use serde_json::{Value, json};

const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const CUSTOM: &str = "urn:ietf:params:scim:schemas:extension:acme:2.0:User";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

struct Directory {
    f: Org,
    service: ScimService,
    connection: Value,
}

async fn directory(unsupported: Option<&str>) -> Directory {
    let f = organization(|_| {}).await;
    let mut config = scim_config(&f.iam).expect("protocol host");
    config.unsupported_attributes = unsupported.map(str::to_owned);
    let service = ScimService::new(config).expect("service");
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
}

#[test]
fn ignores_read_only_and_unsupported_core_attributes_and_foreign_extensions_in_post_put_and_patch()
{
    run(|| async {
        let d = directory(None).await;
        // An Entra ID style create: defaults Better IAM has no place for, plus read-only attributes echoed back.
        let (status, user) = d
            .request(
                "Users",
                "POST",
                Some(json!({
                    "schemas": [USER, ENTERPRISE, CUSTOM],
                    "id": "client-chosen",
                    "meta": { "resourceType": "User" },
                    "groups": [{ "value": "g1" }],
                    "userName": "ada@acme.test",
                    "active": true,
                    "displayName": "Ada",
                    "preferredLanguage": "en-US",
                    "locale": "en-US",
                    "password": "never stored",
                    "addresses": [{ "type": "work", "formatted": "1 Main St", "primary": true }],
                    "phoneNumbers": [{ "type": "work", "value": "+1 555 0100" }],
                    "emails": [{ "value": "ada@acme.test", "type": "work", "primary": true }],
                    ENTERPRISE: { "department": "Finance" },
                    CUSTOM: { "badge": "gold" },
                })),
            )
            .await;
        assert_eq!(status, 201, "{user}");
        let id = user["id"].as_str().unwrap().to_owned();
        assert_ne!(id, "client-chosen");
        assert!(user.get("addresses").is_none());
        assert!(user.get("preferredLanguage").is_none());
        assert!(!user["schemas"].as_array().unwrap().contains(&json!(CUSTOM)));
        assert_eq!(user[ENTERPRISE], json!({ "department": "Finance" }));
        let link = d.f.store().get("scimUsers", &id).await.unwrap().unwrap();
        assert!(!Value::Object(link).to_string().contains("never stored"));

        // PUT with the full resource as the IdP last saw it (id and meta included).
        let mut full = user.clone();
        full["displayName"] = json!("Ada Lovelace");
        full["phoneNumbers"] = json!([{ "type": "mobile", "value": "+1 555 0101" }]);
        let (status, replaced) = d.request(&format!("Users/{id}"), "PUT", Some(full)).await;
        assert_eq!(status, 200, "{replaced}");
        assert_eq!(replaced["displayName"], json!("Ada Lovelace"));

        // Entra PATCH: unsupported paths (value filters, core-qualified names, pathless values) are skipped, supported
        // ones in the same request still apply.
        let (status, after) = d
            .request(
                &format!("Users/{id}"),
                "PATCH",
                Some(json!({
                    "schemas": [PATCH],
                    "Operations": [
                        { "op": "replace", "path": "phoneNumbers[type eq \"work\"].value", "value": "+1 555 0199" },
                        { "op": "replace", "path": "addresses[type eq \"work\"].formatted", "value": "2 Main St" },
                        { "op": "add", "path": format!("{USER}:preferredLanguage"), "value": "fr-FR" },
                        { "op": "replace", "path": format!("{CUSTOM}:badge"), "value": "silver" },
                        { "op": "replace", "value": { "title": "Controller", "locale": "fr-FR", "meta": {} } },
                        { "op": "replace", "path": format!("{ENTERPRISE}:department"), "value": "Treasury" },
                        { "op": "remove", "path": "addresses" },
                    ],
                })),
            )
            .await;
        assert_eq!(status, 200, "{after}");
        assert_eq!(after["title"], json!("Controller"));
        assert_eq!(after[ENTERPRISE], json!({ "department": "Treasury" }));
        assert!(after.get("locale").is_none());

        // Attributes no supported schema defines are still errors, so typos are not silently dropped.
        for payload in [
            json!({ "userName": "ada@acme.test", "badge": "gold" }),
            json!({ "userName": "ada@acme.test", ENTERPRISE: { "badge": "gold" } }),
            json!({ "userName": "ada@acme.test", "name": { "nickname": "A" } }),
        ] {
            let (status, refused) = d
                .request(&format!("Users/{id}"), "PUT", Some(payload.clone()))
                .await;
            assert_eq!(status, 400, "{payload}");
            assert_eq!(refused["scimType"], json!("mutability"));
        }
        let (status, _) = d
            .request(
                &format!("Users/{id}"),
                "PATCH",
                Some(json!({ "schemas": [PATCH], "Operations": [{ "op": "replace", "path": "badge", "value": "x" }] })),
            )
            .await;
        assert_eq!(status, 400);
    });
}

#[test]
fn rejects_unsupported_attributes_with_reject_still_ignoring_read_only_ones() {
    run(|| async {
        let d = directory(Some("reject")).await;
        let (status, refused) = d
            .request(
                "Users",
                "POST",
                Some(json!({ "userName": "ada@acme.test", "addresses": [{ "formatted": "1 Main St" }] })),
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(refused["scimType"], json!("mutability"));
        let (status, _) = d
            .request(
                "Users",
                "POST",
                Some(json!({ "schemas": [USER, CUSTOM], "userName": "ada@acme.test" })),
            )
            .await;
        assert_eq!(status, 400);
        let (status, user) = d
            .request(
                "Users",
                "POST",
                Some(json!({ "id": "ignored", "meta": { "resourceType": "User" }, "userName": "ada@acme.test" })),
            )
            .await;
        assert_eq!(status, 201);
        let (status, _) = d
            .request(
                &format!("Users/{}", user["id"].as_str().unwrap()),
                "PATCH",
                Some(json!({
                    "schemas": [PATCH],
                    "Operations": [{ "op": "replace", "path": "preferredLanguage", "value": "en" }],
                })),
            )
            .await;
        assert_eq!(status, 400);
        let mut config = scim_config(&d.f.iam).unwrap();
        config.unsupported_attributes = Some("drop".into());
        let error = ScimService::new(config)
            .err()
            .expect("a configuration error");
        assert!(error.message.contains("unsupportedAttributes"));
    });
}
