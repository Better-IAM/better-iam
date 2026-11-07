//! Verified email domains and home-realm discovery (tests/domains.test.ts). Organizations, members and tenant
//! settings are written to the store directly where the TypeScript test uses the `tenants` and `identities` groups.

mod directory_support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use better_iam_core::{IamError, PermissionsConfig};
use better_iam_server::api::domains::domain_name;
use better_iam_server::options::{DomainOptions, ResolvedResource};
use directory_support::{Fixture, body, err, fixture, ok, run, token};
use serde_json::{Value, json};

type Dns = Arc<Mutex<HashMap<String, Vec<Vec<String>>>>>;

struct Domains {
    f: Fixture,
    dns: Dns,
    lookups: Arc<Mutex<Vec<String>>>,
}

async fn setup() -> Domains {
    let dns: Dns = Arc::default();
    let lookups: Arc<Mutex<Vec<String>>> = Arc::default();
    let (zone, seen) = (dns.clone(), lookups.clone());
    let f = fixture(
        "domains-test-secret-with-at-least-32-characters",
        move |options| {
            options.domains = Some(DomainOptions {
                resolve_txt: Some(Arc::new(move |hostname| {
                    seen.lock().unwrap().push(hostname.clone());
                    let records = zone.lock().unwrap().get(&hostname).cloned();
                    Box::pin(async move {
                        records.ok_or_else(|| IamError::new("ENOTFOUND", "ENOTFOUND"))
                    })
                })),
                ..DomainOptions::default()
            });
            options.permissions = Some(PermissionsConfig {
                actions: Some(vec!["documents:read".into()]),
                ..PermissionsConfig::default()
            });
            options.resolve_resource = Some(Arc::new(|reference| {
                Box::pin(async move { Ok(ResolvedResource::of(&reference)) })
            }));
        },
    )
    .await;
    Domains { f, dns, lookups }
}

fn publish(dns: &Dns, name: &Value, records: Vec<Vec<String>>) {
    dns.lock()
        .unwrap()
        .insert(name.as_str().unwrap().to_owned(), records);
}

#[test]
fn claims_verifies_through_dns_and_discovers_the_owning_organization() {
    run(|| async {
        let Domains { f, dns, lookups } = setup().await;
        let acme = f.organization("Acme", "owner@acme.test").await;
        let api = &f.iam.api.domains;
        let claimed = ok(api
            .add(
                &acme.owner,
                body(json!({ "tenantId": acme.tenant_id, "domain": "Acme.Example." })),
            )
            .await);
        assert_eq!(claimed["domain"], json!("acme.example"));
        assert_eq!(claimed["status"], json!("pending"));
        assert_eq!(claimed["dnsRecord"]["type"], json!("TXT"));
        assert_eq!(
            claimed["dnsRecord"]["name"],
            json!("_better-iam-challenge.acme.example")
        );
        let value = claimed["dnsRecord"]["value"].as_str().unwrap().to_owned();
        let token_part = value.strip_prefix("better-iam-verification=").unwrap();
        assert_eq!(token_part.len(), 24);
        assert!(
            token_part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        );
        for (domain, code) in [
            ("gmail.com", "DOMAIN_NOT_ALLOWED"),
            ("not a domain", "INVALID_INPUT"),
            ("localhost", "INVALID_INPUT"),
            ("10.0.0.1", "INVALID_INPUT"),
            ("-bad.example", "INVALID_INPUT"),
            ("acme.example", "CONFLICT"),
        ] {
            let error = err(api
                .add(
                    &acme.owner,
                    body(json!({ "tenantId": acme.tenant_id, "domain": domain })),
                )
                .await);
            assert_eq!(error.code, code, "{domain}");
        }

        // Pending domains are not discoverable, and a missing record leaves the claim pending.
        let error = err(api
            .discover(body(json!({ "email": "jane@acme.example" })))
            .await);
        assert_eq!(error.status, 404);
        let pending = ok(api
            .verify(
                &acme.owner,
                body(json!({ "tenantId": acme.tenant_id, "domainId": claimed["id"] })),
            )
            .await);
        assert_eq!(pending["verified"], json!(false));
        assert!(pending["domain"]["lastCheckedAt"].is_number());

        // TXT records may arrive split into chunks; the joined value must match exactly.
        publish(
            &dns,
            &claimed["dnsRecord"]["name"],
            vec![
                vec!["unrelated".into()],
                vec![value[..10].to_owned(), value[10..].to_owned()],
            ],
        );
        let verified = ok(api
            .verify(
                &acme.owner,
                body(json!({ "tenantId": acme.tenant_id, "domainId": claimed["id"] })),
            )
            .await);
        assert_eq!(verified["verified"], json!(true));
        assert_eq!(verified["domain"]["status"], json!("verified"));
        assert_eq!(
            ok(api
                .discover(body(json!({ "email": "Jane@ACME.example" })))
                .await),
            json!({
                "domain": "acme.example",
                "tenantId": acme.tenant_id,
                "name": "Acme",
                "type": "organization",
                "allowedMethods": null,
                "requireMfa": false,
            })
        );
        // Re-verifying a verified domain does not query DNS again.
        let count = lookups.lock().unwrap().len();
        ok(api
            .verify(
                &acme.owner,
                body(json!({ "tenantId": acme.tenant_id, "domainId": claimed["id"] })),
            )
            .await);
        assert_eq!(lookups.lock().unwrap().len(), count);
        let list = ok(api
            .list(&acme.owner, body(json!({ "tenantId": acme.tenant_id })))
            .await);
        let names: Vec<&Value> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|row| &row["domain"])
            .collect();
        assert_eq!(names, vec![&json!("acme.example")]);

        // Discovery reflects the tenant's sign-in requirements.
        f.update(
            "tenants",
            &acme.tenant_id,
            json!({ "authPolicy": { "requireMfa": true, "allowedMethods": ["passkey"] } }),
        )
        .await;
        let discovered = ok(api
            .discover(body(json!({ "domain": "acme.example" })))
            .await);
        assert_eq!(discovered["allowedMethods"], json!(["passkey"]));
        assert_eq!(discovered["requireMfa"], json!(true));
    });
}

#[test]
fn keeps_one_owner_per_domain_isolates_tenants_and_stops_discovery_on_release_or_suspension() {
    run(|| async {
        let Domains { f, dns, .. } = setup().await;
        let acme = f.organization("Acme", "owner@acme.test").await;
        let rival = f.organization("Rival", "owner@rival.test").await;
        let api = &f.iam.api.domains;
        let acme_claim = ok(api
            .add(
                &acme.owner,
                body(json!({ "tenantId": acme.tenant_id, "domain": "shared.example" })),
            )
            .await);
        // Two organizations may hold pending claims; only the one that proves DNS control wins.
        let rival_claim = ok(api
            .add(
                &rival.owner,
                body(json!({ "tenantId": rival.tenant_id, "domain": "shared.example" })),
            )
            .await);
        assert_ne!(
            rival_claim["dnsRecord"]["value"],
            acme_claim["dnsRecord"]["value"]
        );
        let txt = |claim: &Value| vec![vec![claim["dnsRecord"]["value"].as_str().unwrap().into()]];
        publish(&dns, &acme_claim["dnsRecord"]["name"], txt(&acme_claim));
        ok(api
            .verify(
                &acme.owner,
                body(json!({ "tenantId": acme.tenant_id, "domainId": acme_claim["id"] })),
            )
            .await);
        // The rival's own token is not published, so it stays pending; publishing it cannot steal ownership.
        let rival_verify = || {
            api.verify(
                &rival.owner,
                body(json!({ "tenantId": rival.tenant_id, "domainId": rival_claim["id"] })),
            )
        };
        assert_eq!(ok(rival_verify().await)["verified"], json!(false));
        publish(&dns, &acme_claim["dnsRecord"]["name"], txt(&rival_claim));
        assert_eq!(err(rival_verify().await).code, "DOMAIN_TAKEN");
        ok(api
            .add(
                &rival.owner,
                body(json!({ "tenantId": rival.tenant_id, "domain": "other.example" })),
            )
            .await);
        // Already verified elsewhere: a new claim is refused outright.
        assert_eq!(
            err(api
                .add(
                    &rival.owner,
                    body(json!({ "tenantId": rival.tenant_id, "domain": "shared.example" })),
                )
                .await)
            .code,
            "CONFLICT"
        );
        // Cross-tenant access to another organization's claim is not found.
        assert_eq!(
            err(api
                .delete(
                    &rival.owner,
                    body(json!({ "tenantId": rival.tenant_id, "domainId": acme_claim["id"] })),
                )
                .await)
            .status,
            404
        );

        let discover = || api.discover(body(json!({ "email": "a@shared.example" })));
        assert_eq!(ok(discover().await)["tenantId"], json!(acme.tenant_id));
        f.update("tenants", &acme.tenant_id, json!({ "status": "suspended" }))
            .await;
        assert_eq!(err(discover().await).status, 404);
        f.update("tenants", &acme.tenant_id, json!({ "status": "active" }))
            .await;
        let again = f.session(&acme.owner_id).await;
        ok(api
            .delete(
                &again,
                body(json!({ "tenantId": acme.tenant_id, "domainId": acme_claim["id"] })),
            )
            .await);
        assert_eq!(err(discover().await).status, 404);
        // Released: the rival can now verify its pending claim.
        assert_eq!(ok(rival_verify().await)["verified"], json!(true));
    });
}

#[test]
fn serves_discovery_publicly_over_http_while_management_requires_permission() {
    run(|| async {
        let Domains { f, dns, .. } = setup().await;
        let acme = f.organization("Acme", "owner@acme.test").await;
        let api = &f.iam.api.domains;
        let claim = ok(api
            .add(
                &acme.owner,
                body(json!({ "tenantId": acme.tenant_id, "domain": "web.example" })),
            )
            .await);
        publish(
            &dns,
            &claim["dnsRecord"]["name"],
            vec![vec![claim["dnsRecord"]["value"].as_str().unwrap().into()]],
        );
        ok(api
            .verify(
                &acme.owner,
                body(json!({ "tenantId": acme.tenant_id, "domainId": claim["id"] })),
            )
            .await);
        let (status, discovered) = f
            .post(
                "domains/discover",
                json!({ "email": "x@web.example" }),
                None,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(discovered["data"]["tenantId"], json!(acme.tenant_id));
        assert_eq!(
            f.post("domains/discover", json!({ "email": "nobody" }), None)
                .await
                .0,
            400
        );
        assert_eq!(
            f.post(
                "domains/discover",
                json!({ "email": "x@unknown.example" }),
                None
            )
            .await
            .0,
            404
        );
        assert_eq!(
            f.post("domains/list", json!({ "tenantId": acme.tenant_id }), None)
                .await
                .0,
            401
        );

        // A member without iam:domains:* cannot manage domains.
        let member = f.member(&acme, "member").await;
        assert_eq!(
            err(api
                .add(
                    &member.credential,
                    body(json!({ "tenantId": acme.tenant_id, "domain": "x.example" })),
                )
                .await)
            .status,
            403
        );
        assert_eq!(
            err(api
                .list(
                    &member.credential,
                    body(json!({ "tenantId": acme.tenant_id }))
                )
                .await)
            .status,
            403
        );
        let (status, _) = f
            .post(
                "domains/list",
                json!({ "tenantId": acme.tenant_id }),
                Some(token(&member.credential)),
            )
            .await;
        assert_eq!(status, 403);
    });
}

#[test]
fn normalizes_domain_names_and_validates_the_record_label() {
    run(|| async {
        for (input, expected) in [
            ("Example.COM", Some("example.com")),
            ("  sub.example.org. ", Some("sub.example.org")),
            ("xn--bcher-kva.example", Some("xn--bcher-kva.example")),
            ("example.xn--p1ai", Some("example.xn--p1ai")),
            ("example", None),
            ("exa_mple.com", None),
            ("example.c0m", None),
            ("bad-.example", None),
            ("a..example", None),
        ] {
            let result = domain_name(Some(&json!(input)));
            match expected {
                Some(domain) => assert_eq!(result.unwrap(), domain, "{input}"),
                None => {
                    let error = result.unwrap_err();
                    assert_eq!(
                        (error.code.as_str(), error.message.as_str()),
                        ("INVALID_INPUT", "Enter a domain such as example.com"),
                        "{input}"
                    );
                }
            }
        }
        assert_eq!(
            domain_name(Some(&json!(42))).unwrap_err().message,
            "Invalid domain"
        );
        // `domains.recordName` must be a single DNS label: the API refuses to start otherwise.
        let clock = Arc::new(Mutex::new(0.0));
        let inbox = Arc::new(Mutex::new(Vec::new()));
        let mut options = directory_support::options(
            "domains-test-secret-with-at-least-32-characters",
            &clock,
            &inbox,
        );
        options.domains = Some(DomainOptions {
            record_name: Some("two.labels".into()),
            ..DomainOptions::default()
        });
        let error = better_iam_server::better_iam(options)
            .err()
            .expect("a record name with a dot is refused");
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "INVALID_CONFIG",
                "domains.recordName must be a single DNS label"
            )
        );
    });
}
