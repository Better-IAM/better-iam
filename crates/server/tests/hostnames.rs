//! Custom sign-in hostnames (tests/custom-hostnames.test.ts). Organizations, slugs and members are written to the
//! store directly where the TypeScript test uses the `tenants` and `identities` groups.

mod directory_support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use better_iam_core::IamError;
use better_iam_server::hosts::HostOptions;
use better_iam_server::options::{DomainOptions, ServerPasskeyOptions};
use bytes::Bytes;
use directory_support::{Fixture, Org, body, err, fixture, ok, run, token};
use http::Method;
use serde_json::{Value, json};

type Dns = Arc<Mutex<HashMap<String, Vec<Vec<String>>>>>;

struct Hostnames {
    f: Fixture,
    dns: Dns,
    acme: Org,
}

async fn setup(custom_hostnames: bool, passkeys: bool) -> Hostnames {
    let dns: Dns = Arc::default();
    let zone = dns.clone();
    let f = fixture(
        "custom-hostnames-test-secret-with-32-characters",
        move |options| {
            options.hosts = Some(HostOptions {
                patterns: Some(vec!["{tenant}.localhost:3000".into()]),
                custom_hostnames: Some(custom_hostnames),
                cname_target: Some("custom.signin.example.com".into()),
                ..HostOptions::default()
            });
            options.domains = Some(DomainOptions {
                resolve_txt: Some(Arc::new(move |hostname| {
                    let records = zone.lock().unwrap().get(&hostname).cloned();
                    Box::pin(async move {
                        records.ok_or_else(|| IamError::new("ENOTFOUND", "ENOTFOUND"))
                    })
                })),
                ..DomainOptions::default()
            });
            if passkeys {
                options.authentication.as_mut().unwrap().passkeys = Some(ServerPasskeyOptions {
                    rp_id: "localhost".into(),
                    rp_name: None,
                });
            }
        },
    )
    .await;
    let acme = f.organization("Acme", "owner@acme.test").await;
    set_slug(&f, &acme.tenant_id, "acme").await;
    f.member(&acme, "alice").await;
    Hostnames { f, dns, acme }
}

/// `tenants.setSlug`: the alias record and the tenant's slug.
async fn set_slug(f: &Fixture, tenant_id: &str, slug: &str) {
    f.insert(
        "tenantAliases",
        json!({ "id": slug, "tenantId": tenant_id, "createdAt": f.now() }),
    )
    .await;
    f.update("tenants", tenant_id, json!({ "slug": slug })).await;
}

/// Claims and verifies a hostname for Acme.
async fn verified(h: &Hostnames, hostname: &str) -> Value {
    let api = &h.f.iam.api.hostnames;
    let claimed = ok(api
        .add(
            &h.acme.owner,
            body(json!({ "tenantId": h.acme.tenant_id, "hostname": hostname })),
        )
        .await);
    publish(&h.dns, &claimed["dnsRecords"]["verification"]);
    let result = ok(api
        .verify(
            &h.acme.owner,
            body(json!({ "tenantId": h.acme.tenant_id, "hostnameId": claimed["id"] })),
        )
        .await);
    result["hostname"].clone()
}

fn publish(dns: &Dns, record: &Value) {
    dns.lock().unwrap().insert(
        record["name"].as_str().unwrap().to_owned(),
        vec![vec![record["value"].as_str().unwrap().to_owned()]],
    );
}

/// A POST to an absolute URL through the HTTP handler: status, headers, JSON body.
async fn post(
    f: &Fixture,
    url: &str,
    payload: Value,
    headers: &[(&str, &str)],
) -> (u16, http::HeaderMap, Value) {
    let mut builder = http::Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .header("x-better-iam", "1");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = f
        .iam
        .handler(builder.body(Bytes::from(payload.to_string())).unwrap())
        .await;
    (
        response.status().as_u16(),
        response.headers().clone(),
        serde_json::from_slice(response.body()).unwrap_or(Value::Null),
    )
}

#[test]
fn is_off_unless_the_deployment_enables_it() {
    run(|| async {
        let h = setup(false, false).await;
        let error = err(h
            .f
            .iam
            .api
            .hostnames
            .add(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id, "hostname": "login.acme.test" })),
            )
            .await);
        assert_eq!(error.code, "FEATURE_DISABLED");
    });
}

#[test]
fn claims_a_hostname_and_returns_the_dns_records_that_verify_and_route_it() {
    run(|| async {
        let h = setup(true, false).await;
        let api = &h.f.iam.api.hostnames;
        let claimed = ok(api
            .add(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id, "hostname": "Login.Acme.Test." })),
            )
            .await);
        assert_eq!(claimed["hostname"], json!("login.acme.test"));
        assert_eq!(claimed["status"], json!("pending"));
        assert_eq!(claimed["primary"], json!(false));
        assert_eq!(claimed["url"], json!("http://login.acme.test/"));
        assert_eq!(
            claimed["dnsRecords"]["verification"]["name"],
            json!("_better-iam-challenge.login.acme.test")
        );
        assert_eq!(claimed["dnsRecords"]["verification"]["type"], json!("TXT"));
        assert_eq!(
            claimed["dnsRecords"]["routing"],
            json!({ "type": "CNAME", "name": "login.acme.test", "value": "custom.signin.example.com" })
        );
        let value = claimed["dnsRecords"]["verification"]["value"]
            .as_str()
            .unwrap();
        let secret = value.strip_prefix("better-iam-hostname=").unwrap();
        assert_eq!(secret.len(), 24);
        for (hostname, code) in [
            ("login.acme.test", "CONFLICT"),
            ("localhost", "INVALID_INPUT"),
            // The deployment's own subdomain space cannot be claimed.
            ("globex.localhost", "HOSTNAME_NOT_ALLOWED"),
            ("deep.acme.localhost", "HOSTNAME_NOT_ALLOWED"),
        ] {
            let error = err(api
                .add(
                    &h.acme.owner,
                    body(json!({ "tenantId": h.acme.tenant_id, "hostname": hostname })),
                )
                .await);
            assert_eq!(error.code, code, "{hostname}");
        }
        // Pending hostnames resolve to nothing.
        assert!(
            h.f.iam
                .hosts
                .resolve("login.acme.test")
                .await
                .unwrap()
                .is_none()
        );
        let listed = ok(api
            .list(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id })),
            )
            .await);
        let names: Vec<&Value> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|item| &item["hostname"])
            .collect();
        assert_eq!(names, vec![&json!("login.acme.test")]);
    });
}

#[test]
fn verifies_through_dns_then_pins_requests_on_the_hostname_to_the_organization() {
    run(|| async {
        let h = setup(true, false).await;
        let api = &h.f.iam.api.hostnames;
        let claimed = ok(api
            .add(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id, "hostname": "login.acme.test" })),
            )
            .await);
        let verify = || {
            api.verify(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id, "hostnameId": claimed["id"] })),
            )
        };
        let pending = ok(verify().await);
        assert_eq!(pending["verified"], json!(false));
        assert_eq!(pending["hostname"]["status"], json!("pending"));
        publish(&h.dns, &claimed["dnsRecords"]["verification"]);
        let done = ok(verify().await);
        assert_eq!(done["verified"], json!(true));
        assert_eq!(done["hostname"]["status"], json!("verified"));
        let resolved = h
            .f
            .iam
            .hosts
            .resolve("login.acme.test")
            .await
            .unwrap()
            .expect("resolves");
        assert_eq!(resolved.tenant_id, h.acme.tenant_id);
        assert_eq!(resolved.via, "custom");
        assert!(h.f.iam.hosts.allowed("login.acme.test").await.unwrap());

        let origin = "http://login.acme.test";
        let (status, headers, _) = post(
            &h.f,
            &format!("{origin}/api/iam/auth/signIn"),
            json!({ "email": "alice@acme.test", "password": "a strong alice password" }),
            &[("origin", origin)],
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(
            headers
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some(origin)
        );

        // Another organization cannot take a verified hostname, even with its own TXT record.
        let globex = h.f.organization("Globex", "owner@globex.test").await;
        set_slug(&h.f, &globex.tenant_id, "globex").await;
        let rival = err(api
            .add(
                &globex.owner,
                body(json!({ "tenantId": globex.tenant_id, "hostname": "login.acme.test" })),
            )
            .await);
        assert_eq!(rival.code, "HOSTNAME_TAKEN");
        let bearer = format!("Bearer {}", token(&globex.owner));
        let (status, _, foreign) = post(
            &h.f,
            &format!("{origin}/api/iam/auth/getSession"),
            json!({}),
            &[("authorization", &bearer)],
        )
        .await;
        assert_eq!(status, 403);
        assert_eq!(foreign["error"]["code"], json!("HOST_MISMATCH"));
    });
}

#[test]
fn makes_a_verified_hostname_the_primary_sign_in_address_and_releases_it() {
    run(|| async {
        let h = setup(true, false).await;
        let api = &h.f.iam.api.hostnames;
        let pending = ok(api
            .add(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id, "hostname": "sso.acme.test" })),
            )
            .await);
        let error = err(api
            .set_primary(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id, "hostnameId": pending["id"] })),
            )
            .await);
        assert_eq!(error.code, "INVALID_INPUT");
        let hostname = verified(&h, "login.acme.test").await;
        let primary = ok(api
            .set_primary(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id, "hostnameId": hostname["id"] })),
            )
            .await);
        assert_eq!(primary["primary"]["hostname"], json!("login.acme.test"));
        assert_eq!(primary["primary"]["primary"], json!(true));
        assert_eq!(primary["signInUrl"], json!("http://login.acme.test/"));
        assert_eq!(
            h.f.iam
                .hosts
                .sign_in_url(&h.acme.tenant_id)
                .await
                .unwrap()
                .as_deref(),
            Some("http://login.acme.test/")
        );
        // Only one hostname is primary at a time.
        let stored = h
            .f
            .iam
            .store
            .get("tenantHostnames", hostname["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored["primary"], json!(true));
        let back = ok(api
            .set_primary(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id, "hostnameId": null })),
            )
            .await);
        assert_eq!(back["primary"], Value::Null);
        assert_eq!(back["signInUrl"], json!("http://acme.localhost:3000/"));
        let stored = h
            .f
            .iam
            .store
            .get("tenantHostnames", hostname["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(stored.get("primary").is_none());

        ok(api
            .delete(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id, "hostnameId": hostname["id"] })),
            )
            .await);
        assert!(
            h.f.iam
                .hosts
                .resolve("login.acme.test")
                .await
                .unwrap()
                .is_none()
        );
        assert!(!h.f.iam.hosts.allowed("login.acme.test").await.unwrap());
    });
}

#[test]
fn refuses_passkey_ceremonies_on_a_hostname_outside_the_passkey_domain() {
    run(|| async {
        let h = setup(true, true).await;
        verified(&h, "login.acme.test").await;
        let origin = "http://login.acme.test";
        let (status, _, custom) = post(
            &h.f,
            &format!("{origin}/api/iam/auth/beginPasskeyAuthentication"),
            json!({}),
            &[("origin", origin)],
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(custom["error"]["code"], json!("FEATURE_DISABLED"));
        // The organization's subdomain is under the RP ID, so passkeys work there.
        let subdomain = "http://acme.localhost:3000";
        let (status, _, begun) = post(
            &h.f,
            &format!("{subdomain}/api/iam/auth/beginPasskeyAuthentication"),
            json!({}),
            &[("origin", subdomain)],
        )
        .await;
        assert_eq!(status, 200, "{begun}");
        assert_eq!(begun["data"]["options"]["rpId"], json!("localhost"));
    });
}

#[test]
fn authorizes_claims_on_the_hostname_and_hides_other_organizations_claims() {
    run(|| async {
        let h = setup(true, false).await;
        let api = &h.f.iam.api.hostnames;
        let claimed = ok(api
            .add(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id, "hostname": "login.acme.test" })),
            )
            .await);
        // A member may verify only the hostname its grant names.
        let alice = h.f.member(&h.acme, "bob").await;
        h.f.grant(
            &h.acme,
            &alice.id,
            json!([{ "effect": "allow", "actions": ["iam:hostnames:update"], "resources": ["iam/hostnames/other.acme.test"] }]),
        )
        .await;
        let denied = err(api
            .verify(
                &alice.credential,
                body(json!({ "tenantId": h.acme.tenant_id, "hostnameId": claimed["id"] })),
            )
            .await);
        assert_eq!(denied.status, 403);
        // The refusal is audited on the hostname resource.
        let events = h.f.audit(&h.acme.tenant_id, "iam:hostnames:update").await;
        assert!(events.iter().any(|event| event["outcome"] == json!("deny")
            && event["resourceId"] == json!("hostnames/login.acme.test")));
        // Another organization's owner cannot see the claim.
        let globex = h.f.organization("Globex", "owner@globex.test").await;
        let foreign = err(api
            .delete(
                &globex.owner,
                body(json!({ "tenantId": globex.tenant_id, "hostnameId": claimed["id"] })),
            )
            .await);
        assert_eq!(foreign.status, 404);
        // Making no hostname primary needs no claim.
        let none = ok(api
            .set_primary(
                &h.acme.owner,
                body(json!({ "tenantId": h.acme.tenant_id, "hostnameId": null })),
            )
            .await);
        assert_eq!(none["primary"], Value::Null);
        assert_eq!(
            err(api
                .set_primary(&h.acme.owner, body(json!({ "tenantId": h.acme.tenant_id })))
                .await)
            .message,
            "Invalid hostnameId"
        );
    });
}
