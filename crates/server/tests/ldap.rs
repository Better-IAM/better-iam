//! The server side of the LDAP directory gateway: the `ldap` API group (settings and the directory a bound account
//! may read), the deployment-side lookups (`iam.ldap.tenantForBase`, `iam.ldap.resolveBindName`), and the base DN
//! rules. Ported from tests/ldap.test.ts: the gateway itself (`@better-iam/ldap`, which decodes LDAP over TCP) is a
//! separate package, so these tests drive what it calls on the server: the bind-name resolution before each bind, the
//! sign-in it then makes, and `ldap.directory` as the bound account.
//!
//! Group memberships and the service account are written to the store directly when the APIs of the units still
//! being ported (`groups.addMembers` reconciles license seats, `serviceAccounts.create`) answer NOT_IMPLEMENTED.

mod organization_fixture;

use better_iam_auth::MfaCredential;
use better_iam_auth::service::mfa::ConfirmMfaInput;
use better_iam_auth::totp;
use better_iam_core::{AttributeType, CredentialInput, Filter, PermissionsConfig};
use better_iam_server::ldap::{default_ldap_settings, normalize_base_dn};
use organization_fixture::{Org, assert_matches, bearer, body, fails, ok, organization, run};
use serde_json::{Value, json};

const BASE: &str = "dc=acme,dc=test";

struct Setup {
    f: Org,
    alice: String,
    bob: String,
    engineering: String,
    reader: String,
    key: CredentialInput,
    settings: Value,
}

/// Acme publishing its directory under dc=acme,dc=test, with a directory reader service account.
async fn setup() -> Setup {
    let f = organization(|options| {
        let mut attributes = indexmap::IndexMap::new();
        attributes.insert("department".to_owned(), AttributeType::String);
        attributes.insert("salaryBand".to_owned(), AttributeType::Number);
        attributes.insert("cost_center".to_owned(), AttributeType::String);
        options.permissions = Some(PermissionsConfig {
            actions: Some(vec!["documents:read".into(), "documents:write".into()]),
            identity_attributes: Some(attributes),
            ..PermissionsConfig::default()
        });
    })
    .await;
    let owner = f.owner_credential.clone();
    let alice = f.member("alice").await;
    let bob = f.member("bob").await;
    let engineering = ok(f
        .iam
        .api
        .groups
        .create(
            &owner,
            body(json!({ "tenantId": f.tenant_id, "name": "Engineering" })),
        )
        .await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let added = f
        .iam
        .api
        .groups
        .add_members(
            &owner,
            body(
                json!({ "tenantId": f.tenant_id, "groupId": engineering, "identityIds": [alice] }),
            ),
        )
        .await;
    match added {
        Ok(_) => {}
        Err(error)
            if error.code == "NOT_IMPLEMENTED"
                && f.find(
                    "groupMembers",
                    Filter::new().eq("groupId", engineering.clone()),
                )
                .await
                .is_empty() =>
        {
            f.insert(
                "groupMembers",
                json!({
                    "id": better_iam_server::utils::id(),
                    "tenantId": f.tenant_id,
                    "uniqueKey": format!("{engineering}:{alice}"),
                    "groupId": engineering,
                    "identityId": alice,
                }),
            )
            .await;
        }
        Err(error) if error.code == "NOT_IMPLEMENTED" => {}
        Err(error) => panic!("addMembers: {error:?}"),
    }
    let reader = match f
        .iam
        .api
        .service_accounts
        .create(
            &owner,
            body(json!({ "tenantId": f.tenant_id, "name": "vpn" })),
        )
        .await
    {
        Ok(reply) => reply.into_value().unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned(),
        // The account commits before package automation (still a skeleton) runs.
        Err(error) if error.code == "NOT_IMPLEMENTED" => {
            let committed = f
                .find(
                    "identities",
                    Filter::new()
                        .eq("tenantId", f.tenant_id.clone())
                        .eq("name", "vpn"),
                )
                .await;
            if let Some(account) = committed.first() {
                return_id(account)
            } else {
                insert_service(&f).await
            }
        }
        Err(error) => panic!("serviceAccounts.create: {error:?}"),
    };
    finish(f, alice, bob, engineering, reader).await
}

fn return_id(record: &better_iam_core::Record) -> String {
    record["id"].as_str().unwrap().to_owned()
}

async fn insert_service(f: &Org) -> String {
    let id = better_iam_server::utils::id();
    f.insert(
        "identities",
        json!({
            "id": id,
            "tenantId": f.tenant_id,
            "kind": "service",
            "name": "vpn",
            "status": "active",
            "emailVerified": false,
            "rootAdmin": false,
            "owner": false,
            "createdAt": f.now(),
        }),
    )
    .await;
    id
}

/// The reader's grant and key, and the gateway turned on.
async fn finish(f: Org, alice: String, bob: String, engineering: String, reader: String) -> Setup {
    let owner = f.owner_credential.clone();
    f.grant(
        &reader,
        json!([{ "effect": "allow", "actions": ["iam:ldap:read"], "resources": ["*"] }]),
    )
    .await;
    let key = match f
        .iam
        .api
        .credentials
        .create(
            &owner,
            body(json!({ "tenantId": f.tenant_id, "identityId": reader })),
        )
        .await
    {
        Ok(reply) => bearer(reply.into_value().unwrap()["token"].as_str().unwrap()),
        Err(error) if error.code == "NOT_IMPLEMENTED" => f.session(&reader, false).await,
        Err(error) => panic!("credentials.create: {error:?}"),
    };
    let settings = ok(f
        .iam
        .api
        .ldap
        .update_settings(
            &owner,
            body(json!({
                "tenantId": f.tenant_id,
                "enabled": true,
                "baseDn": "dc=acme, dc=test",
                "includeServiceAccounts": true,
            })),
        )
        .await);
    Setup {
        f,
        alice,
        bob,
        engineering,
        reader,
        key,
        settings,
    }
}

impl Setup {
    async fn directory(
        &self,
        credential: &CredentialInput,
    ) -> Result<Value, better_iam_core::IamError> {
        self.f
            .iam
            .api
            .ldap
            .directory(credential, body(json!({ "tenantId": self.f.tenant_id })))
            .await?
            .into_value()
    }

    async fn resolve(&self, kind: &str, value: &str) -> Option<Value> {
        self.f
            .iam
            .ldap
            .resolve_bind_name(&self.f.tenant_id, kind, value)
            .await
            .unwrap()
    }

    async fn update(&self, input: Value) -> Result<Value, better_iam_core::IamError> {
        let mut input = input;
        input["tenantId"] = json!(self.f.tenant_id);
        self.f
            .iam
            .api
            .ldap
            .update_settings(&self.f.owner_credential, body(input))
            .await?
            .into_value()
    }
}

#[test]
fn normalizes_base_dns() {
    let normalized = normalize_base_dn(Some(&json!("DC=Acme,  dc = Test "))).unwrap();
    assert_eq!(normalized.base_dn, "DC=Acme,dc = Test");
    assert_eq!(normalized.normalized, "dc=acme,dc=test");
    let spaced = normalize_base_dn(Some(&json!("o=Acme   Corp"))).unwrap();
    assert_eq!(spaced.normalized, "o=acme corp");
    let message = |value: Value| normalize_base_dn(Some(&value)).unwrap_err().message;
    assert_eq!(message(json!("")), "Enter a base DN such as dc=acme,dc=com");
    assert_eq!(
        message(json!("   ")),
        "Enter a base DN such as dc=acme,dc=com"
    );
    assert_eq!(message(json!(7)), "Enter a base DN such as dc=acme,dc=com");
    assert_eq!(
        message(json!(format!("o={}", "a".repeat(511)))),
        "Enter a base DN such as dc=acme,dc=com"
    );
    assert_eq!(
        message(json!(
            "dc=a,dc=b,dc=c,dc=d,dc=e,dc=f,dc=g,dc=h,dc=i,dc=j,dc=k"
        )),
        "A base DN has at most 10 components"
    );
    for bad in [
        "dc=acme,",
        "dc=ac\\,me",
        "=acme",
        "dc=-acme",
        "1dc=acme",
        "dc=acme+o=x",
    ] {
        assert_eq!(
            message(json!(bad)),
            "Base DN components are attr=value with letters, digits, spaces, \".\", \"_\" or \"-\"",
            "{bad}"
        );
    }
    assert_eq!(
        message(json!("OU=People,dc=acme")),
        "The base DN cannot itself be ou=people, ou=groups or ou=services"
    );
    assert!(normalize_base_dn(None).is_err());
    assert_eq!(
        normalize_base_dn(Some(&json!("dc=acme,ou=people")))
            .unwrap()
            .normalized,
        "dc=acme,ou=people"
    );
}

#[test]
fn defaults_follow_the_tenant_slug() {
    let mut tenant: better_iam_core::Tenant = serde_json::from_value(json!({
        "id": "T1",
        "tenantId": "T1",
        "name": "Acme",
        "type": "organization",
        "parentId": null,
        "status": "active",
        "createdAt": 1,
    }))
    .unwrap();
    let settings = default_ldap_settings(&tenant);
    assert_eq!(settings.base_dn, "o=t1");
    assert_eq!(settings.normalized_base_dn, "o=t1");
    assert_eq!(
        serde_json::Value::Object(settings.to_record()),
        json!({
            "id": "T1",
            "tenantId": "T1",
            "enabled": false,
            "baseDn": "o=t1",
            "normalizedBaseDn": "o=t1",
            "uid": "email",
            "peopleBind": true,
            "serviceBind": true,
            "requireTls": true,
            "mfaSuffix": "auto",
            "includeServiceAccounts": false,
            "attributes": [],
            "groups": "all",
            "groupIds": [],
            "updatedAt": 0,
            "updatedBy": "",
        })
    );
    tenant.slug = Some("--Acme Corp!--".into());
    assert_eq!(default_ldap_settings(&tenant).base_dn, "o=acme-corp");
    tenant.slug = Some("***".into());
    assert_eq!(default_ldap_settings(&tenant).base_dn, "o=tenant");
}

#[test]
fn lets_people_and_service_accounts_bind_and_serves_the_directory_each_may_read() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        assert_matches(
            &s.settings,
            json!({ "tenantId": f.tenant_id, "enabled": true, "baseDn": BASE, "uid": "email", "attributes": [], "includeServiceAccounts": true, "updatedBy": f.owner_id }),
        );
        let stored = f
            .iam
            .store
            .get("ldapSettings", &f.tenant_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored["normalizedBaseDn"], json!(BASE));
        let base = f.iam.store.get("ldapBases", BASE).await.unwrap().unwrap();
        assert_eq!(
            Value::Object(base),
            json!({ "id": BASE, "tenantId": f.tenant_id, "settingsId": f.tenant_id })
        );

        // The gateway finds the organization by the normalized base DN; other trees do not exist.
        assert_eq!(
            f.iam.ldap.tenant_for_base(BASE).await.unwrap(),
            Some(json!({
                "tenantId": f.tenant_id,
                "tenantName": "Acme",
                "baseDn": BASE,
                "normalizedBaseDn": BASE,
                "uid": "email",
                "peopleBind": true,
                "serviceBind": true,
                "requireTls": true,
                "mfaSuffix": "auto",
            }))
        );
        assert_eq!(
            f.iam
                .ldap
                .tenant_for_base("dc=other,dc=test")
                .await
                .unwrap(),
            None
        );

        // People bind under the uid the organization chose; names compare without regard to case.
        assert_eq!(
            s.resolve("person", "ALICE@acme.test").await,
            Some(json!({ "identityId": s.alice, "email": "alice@acme.test", "mfa": "none" }))
        );
        assert_eq!(s.resolve("person", "nobody@acme.test").await, None);
        assert_eq!(
            s.resolve("service", "VPN").await,
            Some(json!({ "identityId": s.reader }))
        );
        assert_eq!(
            s.resolve("service", &s.reader.to_uppercase()).await,
            Some(json!({ "identityId": s.reader }))
        );
        assert_eq!(s.resolve("service", "alice@acme.test").await, None);

        // Without iam:ldap:read a person sees only their own entry, and their groups with only them in it.
        let alice = f.sign_in(&s.alice).await;
        let own = s.directory(&alice).await.unwrap();
        assert_eq!(own["scope"], json!("self"));
        assert_eq!(
            own["people"],
            json!([{
                "id": s.alice,
                "uid": "alice@acme.test",
                "email": "alice@acme.test",
                "name": "alice",
                "emailVerified": true,
                "attributes": {},
                "groupIds": [s.engineering],
            }])
        );
        assert_eq!(
            own["groups"],
            json!([{ "id": s.engineering, "name": "Engineering", "memberIds": [s.alice] }])
        );
        assert_eq!(own["services"], json!([]));
        assert_eq!(own["baseDn"], json!(BASE));
        assert_eq!(own["tenantName"], json!("Acme"));
        // Bob is in no group: his own entry only.
        let bob = f.sign_in(&s.bob).await;
        let bobs = s.directory(&bob).await.unwrap();
        assert_eq!(bobs["groups"], json!([]));
        assert_eq!(bobs["people"].as_array().unwrap().len(), 1);
        assert!(
            f.find("audit", Filter::new().eq("action", "ldap:directory:read"))
                .await
                .is_empty()
        );

        // A service account with iam:ldap:read reads the whole published directory.
        let full = s.directory(&s.key).await.unwrap();
        assert_eq!(full["scope"], json!("full"));
        let uids: Vec<&Value> = full["people"]
            .as_array()
            .unwrap()
            .iter()
            .map(|person| &person["uid"])
            .collect();
        assert_eq!(
            uids,
            [
                &json!("alice@acme.test"),
                &json!("bob@acme.test"),
                &json!("owner@acme.test")
            ]
        );
        assert_eq!(full["groups"][0]["memberIds"], json!([s.alice]));
        assert_eq!(
            full["services"],
            json!([{ "id": s.reader, "name": "vpn", "kind": "service", "groupIds": [] }])
        );
        let reads = f
            .find("audit", Filter::new().eq("action", "ldap:directory:read"))
            .await;
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0]["resourceId"], json!("ldap/directory"));
        assert_eq!(reads[0]["metadata"], json!({ "people": 3, "groups": 1 }));

        // The platform root does not read an organization's directory over LDAP.
        let error = s.directory(&f.root_credential).await.unwrap_err();
        assert_eq!(error.code, "ACCESS_DENIED");

        // Selected groups only, and services hidden again.
        let narrowed = s
            .update(
                json!({ "groups": "selected", "groupIds": [], "includeServiceAccounts": false }),
            )
            .await
            .unwrap();
        assert_eq!(narrowed["groups"], json!("selected"));
        let full = s.directory(&s.key).await.unwrap();
        assert_eq!(full["groups"], json!([]));
        assert_eq!(full["services"], json!([]));
        assert_eq!(full["people"][0]["groupIds"], json!([]));
        s.update(json!({ "groupIds": [s.engineering, s.engineering] }))
            .await
            .unwrap();
        let full = s.directory(&s.key).await.unwrap();
        assert_eq!(full["groups"][0]["id"], json!(s.engineering));
        let error = s
            .update(json!({ "groupIds": ["missing"] }))
            .await
            .unwrap_err();
        assert_eq!(error.code, "NOT_FOUND");
    });
}

#[test]
fn resolves_bind_names_by_uid_mode_and_reports_how_mfa_binds() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        // A second alice under another domain makes local parts collide: those fall back to the email.
        let other = f.member_in(&f.tenant_id, "carol").await;
        let mut record = f
            .iam
            .store
            .get("identities", &other)
            .await
            .unwrap()
            .unwrap();
        record.insert("email".into(), json!("alice@other.test"));
        f.put("identities", record).await;
        s.update(json!({ "uid": "localPart" })).await.unwrap();
        assert_eq!(
            s.resolve("person", "bob").await.unwrap()["identityId"],
            json!(s.bob)
        );
        assert_eq!(s.resolve("person", "alice").await, None);
        assert_eq!(
            s.resolve("person", "Alice@Other.test").await.unwrap()["identityId"],
            json!(other)
        );
        let full = s.directory(&s.key).await.unwrap();
        let uids: Vec<&Value> = full["people"]
            .as_array()
            .unwrap()
            .iter()
            .map(|person| &person["uid"])
            .collect();
        assert_eq!(
            uids,
            [
                &json!("alice@acme.test"),
                &json!("alice@other.test"),
                &json!("bob"),
                &json!("owner")
            ]
        );
        s.update(json!({ "uid": "id" })).await.unwrap();
        assert_eq!(
            s.resolve("person", &s.bob.to_lowercase())
                .await
                .map(|found| found["identityId"].clone()),
            if s.bob == s.bob.to_lowercase() {
                Some(json!(s.bob))
            } else {
                None
            }
        );
        s.update(json!({ "uid": "email" })).await.unwrap();

        // People who use MFA bind with the password followed by the one-time code.
        let bob = f.sign_in(&s.bob).await;
        let credential = MfaCredential::Credential(bob.clone());
        let enrollment = f.iam.auth.begin_mfa(&credential).await.unwrap();
        f.iam
            .auth
            .confirm_mfa(&ConfirmMfaInput {
                credential,
                code: totp::generate(&enrollment.secret, f.now()).unwrap(),
                remember_device: false,
            })
            .await
            .unwrap();
        assert_eq!(
            s.resolve("person", "bob@acme.test").await,
            Some(json!({ "identityId": s.bob, "email": "bob@acme.test", "mfa": "totp" }))
        );
        // MFA required by the organization without an authenticator enrolled cannot be satisfied over LDAP.
        let mut tenant = f
            .iam
            .store
            .get("tenants", &f.tenant_id)
            .await
            .unwrap()
            .unwrap();
        tenant.insert("authPolicy".into(), json!({ "requireMfa": true }));
        f.put("tenants", tenant).await;
        assert_eq!(
            s.resolve("person", "alice@acme.test").await.unwrap()["mfa"],
            json!("unavailable")
        );
        // Disabled people do not resolve.
        let mut alice = f
            .iam
            .store
            .get("identities", &s.alice)
            .await
            .unwrap()
            .unwrap();
        alice.insert("status".into(), json!("disabled"));
        f.put("identities", alice).await;
        assert_eq!(s.resolve("person", "alice@acme.test").await, None);
        assert_eq!(
            f.iam
                .ldap
                .resolve_bind_name("missing", "person", "bob@acme.test")
                .await
                .unwrap(),
            None
        );
        // The conformance entry answers `undefined` for nobody.
        assert_eq!(
            f.iam
                .ldap
                .call(
                    "resolveBindName",
                    vec![json!(f.tenant_id), json!("person"), json!("nobody")]
                )
                .await
                .unwrap()
                .unwrap(),
            better_iam_server::port::undefined()
        );
    });
}

#[test]
fn validates_settings_publishes_declared_attributes_and_stops_when_turned_off() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        // Only declared identity attributes can be published, and only names LDAP can carry.
        let error = s
            .update(json!({ "attributes": ["salary"] }))
            .await
            .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        assert_eq!(
            error.message,
            "salary is not a declared identity attribute LDAP can publish"
        );
        let error = s
            .update(json!({ "attributes": ["cost_center"] }))
            .await
            .unwrap_err();
        assert_eq!(
            error.message,
            "cost_center is not a declared identity attribute LDAP can publish"
        );
        let checks = [
            (json!({ "enabled": "yes" }), "enabled must be a boolean"),
            (
                json!({ "requireTls": null }),
                "requireTls must be a boolean",
            ),
            (
                json!({ "uid": "name" }),
                "uid must be 'email', 'localPart' or 'id'",
            ),
            (
                json!({ "mfaSuffix": "always" }),
                "mfaSuffix must be 'auto' or 'never'",
            ),
            (
                json!({ "attributes": "department" }),
                "attributes must list at most 64 identity attributes",
            ),
            (
                json!({ "groups": "some" }),
                "groups must be 'all' or 'selected'",
            ),
            (
                json!({ "groupIds": {} }),
                "groupIds must list at most 500 groups",
            ),
            (
                json!({ "baseDn": "ou=groups" }),
                "The base DN cannot itself be ou=people, ou=groups or ou=services",
            ),
            (json!({ "attributes": [""] }), "Invalid attribute"),
        ];
        for (input, message) in checks {
            let error = s.update(input.clone()).await.unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "{input}");
            assert_eq!(error.message, message, "{input}");
        }
        let updated = s
            .update(json!({ "attributes": ["department", "salaryBand", "department"], "mfaSuffix": "never" }))
            .await
            .unwrap();
        assert_eq!(updated["attributes"], json!(["department", "salaryBand"]));
        assert_eq!(updated["mfaSuffix"], json!("never"));
        let mut alice = f
            .iam
            .store
            .get("identities", &s.alice)
            .await
            .unwrap()
            .unwrap();
        alice.insert(
            "attributes".into(),
            json!({ "department": "R&D", "salaryBand": null, "secret": "x" }),
        );
        f.put("identities", alice).await;
        let full = s.directory(&s.key).await.unwrap();
        assert_eq!(
            full["people"][0]["attributes"],
            json!({ "department": "R&D" })
        );

        // Reading settings needs iam:ldap:read; changing them needs iam:ldap:manage.
        let view = ok(f
            .iam
            .api
            .ldap
            .get_settings(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        assert_eq!(view["baseDn"], json!(BASE));
        assert_eq!(view["updatedBy"], json!(f.owner_id));
        let alice = f.sign_in(&s.alice).await;
        assert_eq!(
            fails(
                f.iam
                    .api
                    .ldap
                    .get_settings(&alice, body(json!({ "tenantId": f.tenant_id })))
                    .await
            )
            .code,
            "ACCESS_DENIED"
        );
        assert_eq!(
            fails(
                f.iam
                    .api
                    .ldap
                    .update_settings(
                        &s.key,
                        body(json!({ "tenantId": f.tenant_id, "enabled": false }))
                    )
                    .await
            )
            .code,
            "ACCESS_DENIED"
        );
        assert_eq!(
            fails(
                f.iam
                    .api
                    .ldap
                    .get_settings(&f.owner_credential, body(json!({ "tenantId": 7 })))
                    .await
            )
            .message,
            "Invalid tenantId"
        );

        // A base DN belongs to one organization.
        let (other_tenant, _, other_owner) = f
            .activate(
                &f.root_tenant,
                "Globex",
                "organization",
                "owner@globex.test",
            )
            .await;
        let error = fails(
            f.iam
                .api
                .ldap
                .update_settings(
                    &other_owner,
                    body(json!({ "tenantId": other_tenant, "enabled": true, "baseDn": "DC=Acme,DC=Test" })),
                )
                .await,
        );
        assert_eq!(error.code, "LDAP_BASE_TAKEN");
        assert_eq!(error.status, 409);
        // A fresh tenant's defaults have no update stamp.
        let fresh = ok(f
            .iam
            .api
            .ldap
            .get_settings(&other_owner, body(json!({ "tenantId": other_tenant })))
            .await);
        assert_eq!(fresh["enabled"], json!(false));
        assert!(fresh.get("updatedAt").is_none());
        assert!(fresh.get("updatedBy").is_none());

        // Moving the base DN releases the old one.
        s.update(json!({ "baseDn": "dc=acme,dc=example" }))
            .await
            .unwrap();
        assert!(f.iam.store.get("ldapBases", BASE).await.unwrap().is_none());
        assert!(
            f.iam
                .store
                .get("ldapBases", "dc=acme,dc=example")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(f.iam.ldap.tenant_for_base(BASE).await.unwrap(), None);

        // Turned off: no tenant for the base DN, and the directory refuses.
        s.update(json!({ "enabled": false })).await.unwrap();
        assert!(
            f.iam
                .store
                .get("ldapBases", "dc=acme,dc=example")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            f.iam
                .ldap
                .tenant_for_base("dc=acme,dc=example")
                .await
                .unwrap(),
            None
        );
        let error = s.directory(&s.key).await.unwrap_err();
        assert_eq!(error.code, "FEATURE_DISABLED");
        assert_eq!(
            error.message,
            "The LDAP gateway is off for this organization"
        );
        assert_eq!(error.status, 403);

        // A suspended organization publishes nothing.
        s.update(json!({ "enabled": true })).await.unwrap();
        assert!(
            f.iam
                .ldap
                .tenant_for_base("dc=acme,dc=example")
                .await
                .unwrap()
                .is_some()
        );
        let mut tenant = f
            .iam
            .store
            .get("tenants", &f.tenant_id)
            .await
            .unwrap()
            .unwrap();
        tenant.insert("status".into(), json!("suspended"));
        f.put("tenants", tenant).await;
        assert_eq!(
            f.iam
                .ldap
                .tenant_for_base("dc=acme,dc=example")
                .await
                .unwrap(),
            None
        );
    });
}
