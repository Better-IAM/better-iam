//! Port of tests/oidc-providers.test.ts: OIDC provider management (`oidcProviders.*`).
//!
//! The suites that run with `sts.webIdentity.enabled` need the web-identity validators and verifier
//! (`webIdentityAudiences`, `webIdentityKeys`, `webIdentityJwksUri`, `webIdentityAlgorithms`,
//! `createWebIdentityVerifier`, ported by the web-identity unit) and `deleteTemporarySessions` (temporary-credentials
//! unit); until those land they are `#[ignore]`d with that reason. Everything that works with the feature off runs
//! now: the feature gate, reads, the disable-only kill switch, deletion, session revocation, permissions, recent
//! authentication and the creator's grant authority. Roles, bindings, authorities and trusts the TypeScript suite
//! creates through other API groups are written to the store directly.

mod org_fixture;

use better_iam_core::{CredentialInput, Filter, Identity};
use better_iam_server::api::Body;
use better_iam_server::js::number;
use better_iam_server::options::{StsOptions, StsWebIdentityOptions};
use org_fixture::{Org, code, run};
use serde_json::{Value, json};

const ISSUER: &str = "https://token.actions.example.test";
const AUDIENCE: &str = "https://acme.example";

fn public_key() -> Value {
    json!({
        "kty": "RSA",
        "kid": "rsa-1",
        "n": "qPngCyM7DyqWx_cz6zyXntR1Cyd2FgEDM1RnZenXJXJxJlbBJqk-I4cZF16wrQzKodRlsXoUJrW2UiYhjU-JJn3zFmYqtl3hiPlJMwuJFfHPdox7jxiZwms2k5y8dyOFfmTgz6_cWTf3YiURATPgHvgROSWTHrHHPEAXI20zS73NEmZoGaij5G9vY2aNrcV2-m7JzgFMQm55DB_bOQl4ECk8liNF4pOlaN8M6z-qgiw7SNhCo2tfaHa6elUIPfmZ4BiJPH_89lUa41r217Sc69RAsh3D89sVF0CCx_Vxjti7ePk0lMFQ6uDVcv3eYFV5WGphBVB4cO4OuzTl_cJTmw",
        "e": "AQAB",
    })
}

fn second_key() -> Value {
    json!({
        "kty": "RSA",
        "kid": "rsa-2",
        "n": "tNn7oB_Jlb6qhN--JYfhAGrgbaOmLegcO9KPZsx5P60djvrsLmcnhecsUbSPMJkzIEPARguWRgBKS-Nzf3ZPjFwRTFTjIIzoreiwlB6cfwMw_W_6CRw4Uq0G9KSl87XPmhB17N7NNaJtLmDxFXEoi6BDD4SAPWCbIHKtYKMAhEFWen9NmK_qdKEjJKMLGT7fSfufFnfN2VzSaX_J6JakODq9bN7Ic-rW8ntsUZoH0l6VkxOslzX9KGISBoaSWSRX1-H76wLpM43dAYs8_vgsz-OU3Aay1QpV-n6ER9Kr_kMfSD5B62ut5CTltAOs47ISYzfC4EKX3YWCLHT60zQzSw",
        "e": "AQAB",
    })
}

async fn enabled_fixture(configure: impl FnOnce(&mut StsWebIdentityOptions)) -> Org {
    Org::new(|options| {
        let mut web_identity = StsWebIdentityOptions {
            enabled: Some(true),
            ..StsWebIdentityOptions::default()
        };
        configure(&mut web_identity);
        options.sts = Some(StsOptions {
            web_identity: Some(web_identity),
            ..StsOptions::default()
        });
    })
    .await
}

fn provider_input(org: &Org, extra: Value) -> Value {
    let mut input = json!({
        "tenantId": org.tenant_id,
        "name": "GitHub Actions",
        "issuer": ISSUER,
        "audiences": [AUDIENCE],
        "jwks": { "keys": [public_key()] },
    });
    for (key, value) in extra.as_object().unwrap() {
        if value.is_null() && key == "jwks" {
            input.as_object_mut().unwrap().remove(key);
        } else {
            input[key] = value.clone();
        }
    }
    input
}

macro_rules! providers {
    ($org:expr, $method:ident, $credential:expr, $input:expr) => {
        async {
            $org.iam
                .api
                .oidc_providers
                .$method($credential, Body::from_value($input))
                .await
                .and_then(|reply| reply.into_value())
        }
    };
}

/// A provider registered while the feature was on, under the given grant authority.
async fn seed_provider(org: &Org, issuer: &str, authority_id: &str) -> Value {
    let now = org.now();
    let id = better_iam_server::utils::id();
    Value::Object(
        org.insert(
            "oidcProviders",
            json!({
                "id": id,
                "tenantId": org.tenant_id,
                "uniqueKey": format!("issuer:{issuer}"),
                "name": "GitHub Actions",
                "issuer": issuer,
                "audiences": [AUDIENCE],
                "jwks": { "keys": [public_key()] },
                "algorithms": ["RS256"],
                "maxTokenLifetimeSeconds": 3600,
                "clockToleranceSeconds": 30,
                "replayProtection": "single-use",
                "enabled": true,
                "authorityId": authority_id,
                "createdAt": now,
                "createdBy": org.owner_id,
                "updatedAt": now,
            }),
        )
        .await,
    )
}

/// The public projection of a seeded provider (`publicOidcProvider`).
fn public_view(stored: &Value) -> Value {
    better_iam_server::api::oidc_providers::public_oidc_provider(stored.as_object().unwrap())
}

/// A member holding the given IAM permissions through a role, optionally with a delegated grant authority.
async fn administrator(
    org: &Org,
    name: &str,
    permissions: &[&str],
    authority: bool,
) -> (Identity, CredentialInput, Option<String>) {
    let identity = org.member(name).await;
    org.grant(
        &identity.id,
        json!([{ "effect": "allow", "actions": permissions, "resources": ["*"] }]),
    )
    .await;
    let authority_id = if authority {
        let id = better_iam_server::utils::id();
        org.insert(
            "grantAuthorities",
            json!({
                "id": id,
                "tenantId": org.tenant_id,
                "identityId": identity.id,
                "parentAuthorityId": org.authority_id,
                "ceiling": { "version": 1, "statements": [{ "effect": "allow", "actions": ["*"], "resources": ["*"] }] },
                "revoked": false,
            }),
        )
        .await;
        Some(id)
    } else {
        None
    };
    let credential = org.sign_in(name).await;
    (identity, credential, authority_id)
}

fn target(org: &Org, provider: &Value) -> Value {
    json!({ "tenantId": org.tenant_id, "providerId": provider["id"] })
}

fn with(base: &Value, extra: Value) -> Value {
    let mut merged = base.clone();
    for (key, value) in extra.as_object().unwrap() {
        merged[key] = value.clone();
    }
    merged
}

#[test]
fn is_gated_by_the_feature_except_reads_disabling_and_deletion() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let owner = &org.owner;
        let error = providers!(org, create, owner, provider_input(&org, json!({})))
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.status, error.message.as_str()),
            (
                "FEATURE_DISABLED",
                403,
                "Web identity federation is not enabled"
            )
        );
        let seeded = seed_provider(&org, ISSUER, &org.authority_id).await;
        let target = target(&org, &seeded);
        assert_eq!(
            code(
                providers!(
                    org,
                    update,
                    owner,
                    with(&target, json!({ "name": "Renamed" }))
                )
                .await
            ),
            "FEATURE_DISABLED"
        );
        assert_eq!(
            code(
                providers!(
                    org,
                    update,
                    owner,
                    with(&target, json!({ "enabled": true, "name": "x" }))
                )
                .await
            ),
            "FEATURE_DISABLED"
        );
        assert_eq!(
            code(
                providers!(
                    org,
                    update,
                    owner,
                    with(&target, json!({ "enabled": true }))
                )
                .await
            ),
            "FEATURE_DISABLED"
        );
        // Reads keep working, as the explicit public projection.
        let view = providers!(org, get, owner, target.clone()).await.unwrap();
        assert_eq!(view, public_view(&seeded));
        let keys: Vec<&String> = view.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            vec![
                "id",
                "tenantId",
                "name",
                "issuer",
                "audiences",
                "algorithms",
                "maxTokenLifetimeSeconds",
                "clockToleranceSeconds",
                "replayProtection",
                "enabled",
                "authorityId",
                "createdAt",
                "createdBy",
                "updatedAt",
                "jwks"
            ]
        );
        // The kill switch keeps working and moves the watermark.
        org.advance(1000.0);
        let disabled = providers!(
            org,
            update,
            owner,
            with(&target, json!({ "enabled": false }))
        )
        .await
        .unwrap();
        assert_eq!(disabled["enabled"], json!(false));
        assert_eq!(disabled["sessionsRevokedBefore"], number(org.now() + 1.0));
        assert_eq!(disabled["updatedAt"], number(org.now()));
        let listed = providers!(org, list, owner, json!({ "tenantId": org.tenant_id }))
            .await
            .unwrap();
        assert_eq!(listed, json!([disabled]));
        // Disabling again changes nothing; the issuer never changes.
        assert_eq!(
            providers!(
                org,
                update,
                owner,
                with(&target, json!({ "enabled": false }))
            )
            .await
            .unwrap_err()
            .message,
            "The update changes nothing"
        );
        assert_eq!(
            providers!(
                org,
                update,
                owner,
                with(
                    &target,
                    json!({ "enabled": false, "issuer": "https://x.test" })
                )
            )
            .await
            .unwrap_err()
            .message,
            "The issuer of a provider cannot change"
        );
        assert_eq!(
            providers!(
                org,
                update,
                owner,
                with(&target, json!({ "enabled": "no" }))
            )
            .await
            .unwrap_err()
            .code,
            "FEATURE_DISABLED"
        );
        // Deletion waits for the trusts that use it to be revoked, which also works with the feature off.
        let trust_id = better_iam_server::utils::id();
        org.insert(
            "trusts",
            json!({
                "id": trust_id, "tenantId": org.tenant_id, "kind": "web-identity",
                "sourceTenantId": org.tenant_id, "providerId": seeded["id"], "revoked": false,
                "authorityId": org.authority_id, "createdAt": org.now(), "updatedAt": org.now(),
            }),
        )
        .await;
        let error = providers!(org, delete, owner, target.clone())
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.status, error.message.as_str()),
            (
                "CONFLICT",
                409,
                "Revoke the trusts that use this provider first"
            )
        );
        org.patch("trusts", &trust_id, json!({ "revoked": true }))
            .await;
        assert_eq!(
            providers!(org, delete, owner, target.clone())
                .await
                .unwrap(),
            json!({ "deleted": true })
        );
        assert!(
            org.get("oidcProviders", seeded["id"].as_str().unwrap())
                .await
                .is_none()
        );
        assert_eq!(
            code(providers!(org, get, owner, target.clone()).await),
            "NOT_FOUND"
        );
        assert_eq!(
            providers!(org, delete, owner, json!({ "tenantId": org.tenant_id }))
                .await
                .unwrap_err()
                .message,
            "Invalid providerId"
        );
    });
}

#[test]
fn revokes_sessions_with_a_watermark_that_only_moves_forward() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let owner = &org.owner;
        let seeded = seed_provider(&org, ISSUER, &org.authority_id).await;
        let target = target(&org, &seeded);
        let first = providers!(org, revoke_sessions, owner, target.clone())
            .await
            .unwrap();
        assert_eq!(
            first,
            json!({ "providerId": seeded["id"], "sessionsRevokedBefore": number(org.now() + 1.0), "revoked": 0 })
        );
        // updatedAt stays: it versions the key settings.
        let stored = org
            .get("oidcProviders", seeded["id"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(stored["updatedAt"], seeded["updatedAt"]);
        assert_eq!(stored["sessionsRevokedBefore"], number(org.now() + 1.0));
        let audit = org
            .find("audit", Filter::new().eq("action", "role:sessions-revoked"))
            .await;
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0]["resourceId"], seeded["id"]);
        assert_eq!(
            audit[0]["metadata"],
            json!({ "sessionsRevokedBefore": number(org.now() + 1.0), "revoked": 0 })
        );
        // An earlier `before` keeps the later watermark; a future one is refused.
        org.advance(5000.0);
        let earlier = providers!(
            org,
            revoke_sessions,
            owner,
            with(&target, json!({ "before": org.now() - 10_000.0 }))
        )
        .await
        .unwrap();
        assert_eq!(
            earlier["sessionsRevokedBefore"],
            first["sessionsRevokedBefore"]
        );
        let error = providers!(
            org,
            revoke_sessions,
            owner,
            with(&target, json!({ "before": org.now() + 2.0 }))
        )
        .await
        .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_INPUT", "before must be a time no later than now")
        );
        let later = providers!(org, revoke_sessions, owner, target.clone())
            .await
            .unwrap();
        assert_eq!(later["sessionsRevokedBefore"], number(org.now() + 1.0));
    });
}

#[test]
fn requires_the_provider_permissions_and_recent_authentication() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let (_, reader, _) =
            administrator(&org, "reader", &["iam:oidc-providers:read"], false).await;
        let (_, nobody, _) = administrator(&org, "nobody", &["iam:trust:read"], false).await;
        let seeded = seed_provider(&org, ISSUER, &org.authority_id).await;
        let target = target(&org, &seeded);
        assert_eq!(
            providers!(org, get, &reader, target.clone()).await.unwrap(),
            public_view(&seeded)
        );
        assert_eq!(
            code(providers!(org, list, &nobody, json!({ "tenantId": org.tenant_id })).await),
            "ACCESS_DENIED"
        );
        assert_eq!(
            code(
                providers!(
                    org,
                    update,
                    &reader,
                    with(&target, json!({ "enabled": false }))
                )
                .await
            ),
            "ACCESS_DENIED"
        );
        assert_eq!(
            code(providers!(org, delete, &reader, target.clone()).await),
            "ACCESS_DENIED"
        );
        assert_eq!(
            code(providers!(org, revoke_sessions, &reader, target.clone()).await),
            "ACCESS_DENIED"
        );
        // Past the five-minute window the owner's session may still read, but not change anything.
        org.advance(6.0 * 60_000.0);
        let owner = &org.owner;
        assert_eq!(
            providers!(org, get, owner, target.clone()).await.unwrap()["id"],
            seeded["id"]
        );
        assert_eq!(
            code(
                providers!(
                    org,
                    update,
                    owner,
                    with(&target, json!({ "enabled": false }))
                )
                .await
            ),
            "RECENT_AUTH_REQUIRED"
        );
        assert_eq!(
            code(providers!(org, delete, owner, target.clone()).await),
            "RECENT_AUTH_REQUIRED"
        );
        assert_eq!(
            code(providers!(org, revoke_sessions, owner, target.clone()).await),
            "RECENT_AUTH_REQUIRED"
        );
        let fresh = org.owner_sign_in().await;
        assert_eq!(
            providers!(
                org,
                update,
                &fresh,
                with(&target, json!({ "enabled": false }))
            )
            .await
            .unwrap()["enabled"],
            json!(false)
        );
    });
}

#[test]
fn lets_only_the_creators_grant_authority_or_root_edit_a_provider() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let permissions = [
            "iam:oidc-providers:create",
            "iam:oidc-providers:read",
            "iam:oidc-providers:update",
            "iam:oidc-providers:delete",
        ];
        let (_, admin, admin_authority) = administrator(&org, "admin", &permissions, true).await;
        let mine = seed_provider(&org, ISSUER, admin_authority.as_deref().unwrap()).await;
        let owners = seed_provider(&org, "https://gitlab.example.test", &org.authority_id).await;
        assert_ne!(mine["authorityId"], owners["authorityId"]);
        // Neither can edit or delete the other's provider.
        let error = providers!(
            org,
            update,
            &org.owner,
            with(&target(&org, &mine), json!({ "enabled": false }))
        )
        .await
        .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "ACCESS_DENIED",
                "Cannot use another administrator\u{2019}s grant authority"
            )
        );
        assert_eq!(
            code(providers!(org, delete, &admin, target(&org, &owners)).await),
            "ACCESS_DENIED"
        );
        // A provider without an authority is controlled by a superior authority.
        org.patch(
            "oidcProviders",
            owners["id"].as_str().unwrap(),
            json!({ "authorityId": null }),
        )
        .await;
        assert_eq!(
            code(
                providers!(
                    org,
                    update,
                    &org.owner,
                    with(&target(&org, &owners), json!({ "enabled": false }))
                )
                .await
            ),
            "PROTECTED_RESOURCE"
        );
        // The creator and root may.
        assert_eq!(
            providers!(org, delete, &admin, target(&org, &mine))
                .await
                .unwrap(),
            json!({ "deleted": true })
        );
        let root = org.root_sign_in().await;
        assert_eq!(
            providers!(
                org,
                update,
                &root,
                with(&target(&org, &owners), json!({ "enabled": false }))
            )
            .await
            .unwrap()["enabled"],
            json!(false)
        );
    });
}

#[test]
#[ignore = "needs createWebIdentityVerifier and the web-identity validators (web-identity unit)"]
fn creates_reads_updates_and_deletes_providers() {
    run(|| async {
        let org = enabled_fixture(|_| {}).await;
        let owner = &org.owner;
        let created = providers!(org, create, owner, provider_input(&org, json!({})))
            .await
            .unwrap();
        let mut keys: Vec<&String> = created.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "algorithms",
                "audiences",
                "authorityId",
                "clockToleranceSeconds",
                "createdAt",
                "createdBy",
                "enabled",
                "id",
                "issuer",
                "jwks",
                "maxTokenLifetimeSeconds",
                "name",
                "replayProtection",
                "tenantId",
                "updatedAt"
            ]
        );
        assert_eq!(created["algorithms"], json!(["RS256", "ES256"]));
        assert_eq!(created["maxTokenLifetimeSeconds"], json!(3600));
        assert_eq!(created["clockToleranceSeconds"], json!(30));
        assert_eq!(created["replayProtection"], json!("single-use"));
        assert_eq!(created["createdBy"], json!(org.owner_id));
        assert_eq!(created["createdAt"], number(org.now()));
        assert_eq!(created["jwks"]["keys"][0]["kid"], json!("rsa-1"));
        let stored = org
            .get("oidcProviders", created["id"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(stored["uniqueKey"], json!(format!("issuer:{ISSUER}")));
        let authority = org
            .get("grantAuthorities", created["authorityId"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(authority["identityId"], json!(org.owner_id));
        let target = target(&org, &created);
        assert_eq!(
            providers!(org, get, owner, target.clone()).await.unwrap(),
            created
        );
        assert_eq!(
            providers!(org, list, owner, json!({ "tenantId": org.tenant_id }))
                .await
                .unwrap(),
            json!([created])
        );
        org.advance(1000.0);
        let updated = providers!(
            org,
            update,
            owner,
            with(
                &target,
                json!({
                    "name": "GitHub",
                    "audiences": [AUDIENCE, "sts.amazonaws.com"],
                    "jwks": null,
                    "jwksUri": "https://token.actions.example.test/.well-known/jwks",
                    "algorithms": ["RS256"],
                    "maxTokenLifetimeSeconds": 600,
                    "clockToleranceSeconds": 5,
                    "replayProtection": "off",
                })
            )
        )
        .await
        .unwrap();
        assert_eq!(updated["name"], json!("GitHub"));
        assert_eq!(
            updated["jwksUri"],
            json!("https://token.actions.example.test/.well-known/jwks")
        );
        assert!(updated.get("jwks").is_none());
        assert_eq!(updated["updatedAt"], number(org.now()));
        assert_eq!(updated["createdAt"], created["createdAt"]);
        assert_eq!(
            providers!(
                org,
                update,
                owner,
                with(&target, json!({ "name": "GitHub" }))
            )
            .await
            .unwrap_err()
            .message,
            "The update changes nothing"
        );
        assert_eq!(
            code(
                providers!(
                    org,
                    update,
                    owner,
                    with(&target, json!({ "issuer": "https://other.example.test" }))
                )
                .await
            ),
            "INVALID_INPUT"
        );
        assert_eq!(
            providers!(
                org,
                update,
                owner,
                with(&target, json!({ "jwks": { "keys": [public_key()] } }))
            )
            .await
            .unwrap_err()
            .message,
            "Give jwks or jwksUri, not both"
        );
        assert_eq!(
            providers!(org, delete, owner, target.clone())
                .await
                .unwrap(),
            json!({ "deleted": true })
        );
        assert_eq!(
            code(providers!(org, get, owner, target.clone()).await),
            "NOT_FOUND"
        );
        // One provider per issuer in a tenant; another issuer is fine with keys found by discovery.
        providers!(org, create, owner, provider_input(&org, json!({})))
            .await
            .unwrap();
        let error = providers!(
            org,
            create,
            owner,
            provider_input(&org, json!({ "name": "Again" }))
        )
        .await
        .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("CONFLICT", "A provider for this issuer already exists")
        );
        let discovered = providers!(
            org,
            create,
            owner,
            provider_input(
                &org,
                json!({
                    "issuer": "https://gitlab.example.test", "jwks": null,
                })
            )
        )
        .await
        .unwrap();
        assert!(discovered.get("jwks").is_none());
        assert!(discovered.get("jwksUri").is_none());
    });
}

#[test]
#[ignore = "needs createWebIdentityVerifier and the web-identity validators (web-identity unit)"]
fn refuses_bad_keys_urls_issuers_and_iams_own_issuer() {
    run(|| async {
        let org = enabled_fixture(|_| {}).await;
        let self_issuer = format!("{}{}", org.iam.endpoint.origin, org.iam.endpoint.base_path);
        let mut private_key = public_key();
        private_key["d"] = json!("secret");
        let invalid = [
            json!({ "jwks": { "keys": [private_key] } }),
            json!({ "jwks": { "keys": [] } }),
            json!({ "jwks": null, "jwksUri": "http://keys.example.test/jwks" }),
            json!({ "jwks": null, "jwksUri": "https://keys.example.test:8443/jwks" }),
            json!({ "jwks": null, "jwksUri": "https://user:pass@keys.example.test/jwks" }),
            json!({ "jwks": null, "jwksUri": "https://10.0.0.1/jwks" }),
            json!({ "jwksUri": "https://keys.example.test/jwks" }),
            json!({ "issuer": "http://token.actions.example.test" }),
            json!({ "issuer": "not a url" }),
            json!({ "issuer": "https://token.actions.example.test?tenant=1" }),
            json!({ "issuer": "https://token.actions.example.test#fragment" }),
            json!({ "issuer": format!("https://{}.test", "a".repeat(510)) }),
            json!({ "issuer": self_issuer }),
            json!({ "issuer": format!("{self_issuer}/") }),
            json!({ "audiences": [] }),
            json!({ "audiences": ["x".repeat(257)] }),
            json!({ "audiences": (0..11).map(|index| format!("aud-{index}")).collect::<Vec<_>>() }),
            json!({ "algorithms": ["HS256"] }),
            json!({ "algorithms": ["none"] }),
            json!({ "algorithms": [] }),
            json!({ "maxTokenLifetimeSeconds": 59 }),
            json!({ "maxTokenLifetimeSeconds": 86401 }),
            json!({ "clockToleranceSeconds": 121 }),
            json!({ "clockToleranceSeconds": -1 }),
            json!({ "replayProtection": "sometimes" }),
            json!({ "enabled": "yes" }),
            json!({ "name": "" }),
        ];
        for extra in invalid {
            assert_eq!(
                code(
                    providers!(org, create, &org.owner, provider_input(&org, extra.clone())).await
                ),
                "INVALID_INPUT",
                "{extra}"
            );
        }
        assert!(
            org.find(
                "oidcProviders",
                Filter::new().eq("tenantId", org.tenant_id.clone())
            )
            .await
            .is_empty()
        );
        // Loopback http issuers only with the development switch.
        let dev = enabled_fixture(|options| options.allow_insecure_localhost = Some(true)).await;
        let created = providers!(
            dev,
            create,
            &dev.owner,
            provider_input(&dev, json!({ "issuer": "http://127.0.0.1:8080/idp" }))
        )
        .await
        .unwrap();
        assert_eq!(created["issuer"], json!("http://127.0.0.1:8080/idp"));
        // sts.webIdentity.allowedIssuers pins the issuers.
        let pinned =
            enabled_fixture(|options| options.allowed_issuers = Some(vec![ISSUER.to_owned()]))
                .await;
        let error = providers!(
            pinned,
            create,
            &pinned.owner,
            provider_input(&pinned, json!({ "issuer": "https://gitlab.example.test" }))
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.message,
            "The issuer is not in sts.webIdentity.allowedIssuers"
        );
        assert_eq!(
            providers!(
                pinned,
                create,
                &pinned.owner,
                provider_input(&pinned, json!({}))
            )
            .await
            .unwrap()["issuer"],
            json!(ISSUER)
        );
    });
}

#[test]
#[ignore = "needs createWebIdentityVerifier, the web-identity validators (web-identity unit) and deleteTemporarySessions (temporary-credentials unit)"]
fn ends_the_providers_sessions_when_its_keys_or_claim_rules_change() {
    run(|| async {
        let org = enabled_fixture(|_| {}).await;
        let owner = &org.owner;
        let provider = providers!(org, create, owner, provider_input(&org, json!({})))
            .await
            .unwrap();
        let account = better_iam_server::utils::id();
        let role = better_iam_server::utils::id();
        let trust = better_iam_server::utils::id();
        org.insert(
            "trusts",
            json!({
                "id": trust, "tenantId": org.tenant_id, "kind": "web-identity", "sourceTenantId": org.tenant_id,
                "sourceIdentityId": account, "roleId": role, "requireMfa": false, "revoked": false,
                "providerId": provider["id"],
                "conditions": { "StringEquals": { "token.sub": "repo:acme/app:ref:refs/heads/main" } },
                "authorityId": org.authority_id, "createdAt": org.now(), "updatedAt": org.now(),
            }),
        )
        .await;
        let session = |provider_id: Value| {
            let org = &org;
            let account = account.clone();
            let role = role.clone();
            let trust = trust.clone();
            async move {
                let id = better_iam_server::utils::id();
                let token_hash = format!("hash-{id}");
                org.insert(
                    "sessions",
                    json!({
                        "id": id, "tenantId": org.tenant_id, "identityId": account, "originalIdentityId": account,
                        "roleId": role, "trustId": trust, "kind": "role", "tokenHash": token_hash,
                        "uniqueKey": token_hash, "createdAt": org.now(), "lastSeenAt": org.now(),
                        "authenticatedAt": org.now(), "expiresAt": org.now() + 900_000.0, "mfa": false,
                        "credentialAuthorityId": org.authority_id,
                        "webIdentity": { "providerId": provider_id, "issuer": ISSUER, "subject": "repo:acme/app" },
                    }),
                )
                .await;
                id
            }
        };
        let org_ref = &org;
        let alive = |id: String| async move { org_ref.get("sessions", &id).await.is_some() };
        let target = target(&org, &provider);
        let update = |fields: Value| {
            let input = with(&target, fields);
            async move { providers!(org_ref, update, owner, input).await.unwrap() }
        };
        // A rename and the replay switch keep live sessions.
        let kept = session(provider["id"].clone()).await;
        for fields in [
            json!({ "name": "GitHub" }),
            json!({ "replayProtection": "off" }),
        ] {
            assert!(update(fields).await.get("sessionsRevokedBefore").is_none());
        }
        assert!(alive(kept.clone()).await);
        // The kill switch ends them for good.
        org.advance(1000.0);
        let killed = session(provider["id"].clone()).await;
        let disabled = update(json!({ "enabled": false })).await;
        assert_eq!(disabled["sessionsRevokedBefore"], number(org.now() + 1.0));
        assert!(!alive(killed).await);
        assert!(!alive(kept).await);
        org.advance(1000.0);
        let enabled = update(json!({ "enabled": true })).await;
        assert_eq!(
            enabled["sessionsRevokedBefore"],
            disabled["sessionsRevokedBefore"]
        );
        let later = session(provider["id"].clone()).await;
        // Each change to what a token is verified against moves the watermark and deletes the older sessions.
        let mut watermark = disabled["sessionsRevokedBefore"].as_f64().unwrap();
        for fields in [
            json!({ "audiences": [AUDIENCE, "sts.amazonaws.com"] }),
            json!({ "algorithms": ["RS256"] }),
            json!({ "maxTokenLifetimeSeconds": 600 }),
            json!({ "clockToleranceSeconds": 5 }),
            json!({ "jwks": { "keys": [second_key()] } }),
            json!({ "jwks": null, "jwksUri": "https://token.actions.example.test/.well-known/jwks" }),
            json!({ "jwksUri": "https://keys.example.test/jwks" }),
        ] {
            org.advance(1000.0);
            let older = session(provider["id"].clone()).await;
            let updated = update(fields).await;
            assert_eq!(updated["sessionsRevokedBefore"], number(org.now() + 1.0));
            assert!(updated["sessionsRevokedBefore"].as_f64().unwrap() > watermark);
            watermark = updated["sessionsRevokedBefore"].as_f64().unwrap();
            assert!(!alive(older).await);
        }
        assert!(!alive(later).await);
    });
}
