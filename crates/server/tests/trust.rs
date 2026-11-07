//! The `trust` API group: ported from tests/trust-management.test.ts, the `trust.revokeSessions` and `trust.revoke`
//! suites of tests/revoke-older-sessions.test.ts, the trust listing of tests/administration.test.ts, and the parts of
//! tests/web-identity.test.ts that manage web-identity trusts. Roles, service accounts, OIDC providers and role
//! sessions are written to the store directly where the TypeScript tests use the `roles`, `serviceAccounts` and
//! `oidcProviders` groups or `roles.assume` (other units); assertions that need a live role session (`works`) or the
//! web-identity claim validators are left to those units' suites.

mod organization_fixture;

use better_iam_core::{CredentialInput, Filter, Record};
use better_iam_server::options::{StsOptions, StsWebIdentityOptions};
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

fn sha256(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// A JavaScript number as the API answers it (`1`, not `1.0`).
fn n(value: f64) -> Value {
    better_iam_server::js::number(value)
}

fn all() -> Value {
    json!({ "version": 1, "statements": [{ "effect": "allow", "actions": ["*"], "resources": ["*"] }] })
}

fn read_documents() -> Value {
    json!({ "version": 1, "statements": [{ "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }] })
}

const PUBLIC_TRUST_KEYS: [&str; 16] = [
    "allowedTagKeys",
    "ceiling",
    "createdAt",
    "createdBy",
    "id",
    "kind",
    "passSourceAttributes",
    "requireMfa",
    "requiresExternalId",
    "revoked",
    "roleId",
    "sourceIdentityId",
    "sourceIdentityMode",
    "sourceTenantId",
    "tenantId",
    "updatedAt",
];

/// `{ ...base, ...extra }`.
fn merged(base: &Value, extra: Value) -> Value {
    let mut out = base.as_object().cloned().unwrap_or_default();
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        out.insert(key, value);
    }
    Value::Object(out)
}

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

fn web_identity_on(options: &mut better_iam_server::options::BetterIamOptions) {
    options.sts = Some(StsOptions {
        web_identity: Some(StsWebIdentityOptions {
            enabled: Some(true),
            ..StsWebIdentityOptions::default()
        }),
        ..StsOptions::default()
    });
}

fn role_session_cap(
    seconds: f64,
) -> impl FnOnce(&mut better_iam_server::options::BetterIamOptions) {
    move |options| {
        options.sts = Some(StsOptions {
            max_role_session_seconds: Some(seconds),
            ..StsOptions::default()
        });
    }
}

/// The grant authority an organization's owner holds.
async fn tenant_authority(f: &Org, tenant_id: &str) -> String {
    f.find(
        "grantAuthorities",
        Filter::new().eq("tenantId", tenant_id.to_owned()),
    )
    .await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The root administrator's grant authority.
async fn root_authority(f: &Org) -> String {
    f.find(
        "grantAuthorities",
        Filter::new().eq("identityId", f.root_id.clone()),
    )
    .await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A reader role in a tenant under a grant authority (as `roles.create` writes it).
async fn role_in(f: &Org, tenant_id: &str, authority: &str, document: Value) -> String {
    let id = uuid();
    f.insert(
        "roles",
        json!({
            "id": id,
            "tenantId": tenant_id,
            "name": format!("Reader {}", &id[..8]),
            "policyIds": [],
            "document": document,
            "protected": false,
            "authorityId": authority,
        }),
    )
    .await;
    id
}

/// A reader role the owner creates, under the owner's own grant authority.
async fn reader_role(f: &Org) -> (String, String) {
    let authority = tenant_authority(f, &f.tenant_id).await;
    let role = role_in(f, &f.tenant_id, &authority, read_documents()).await;
    (role, authority)
}

/// A reader role and a same-tenant trust (no MFA) from the owner to it.
async fn owner_trust(f: &Org, extra: Value) -> (String, Value) {
    let (role, _) = reader_role(f).await;
    let trust = ok(f
        .iam
        .api
        .trust
        .create(
            &f.root_credential,
            body(merged(
                &json!({
                    "tenantId": f.tenant_id,
                    "sourceTenantId": f.tenant_id,
                    "sourceIdentityId": f.owner_id,
                    "roleId": role,
                    "requireMfa": false,
                }),
                extra,
            )),
        )
        .await);
    (role, trust)
}

/// Replaces fields of a stored record; a `null` value removes the field.
async fn patch(f: &Org, collection: &str, record_id: &str, fields: Value) {
    let current = f
        .find(collection, Filter::new().eq("id", record_id.to_owned()))
        .await;
    let mut next = current[0].clone();
    for (key, value) in fields.as_object().unwrap() {
        if value.is_null() {
            next.shift_remove(key);
        } else {
            next.insert(key.clone(), value.clone());
        }
    }
    f.put(collection, next).await;
}

async fn get(f: &Org, collection: &str, record_id: &str) -> Option<Record> {
    f.find(collection, Filter::new().eq("id", record_id.to_owned()))
        .await
        .into_iter()
        .next()
}

async fn audit_of(f: &Org, action: &str) -> Vec<Record> {
    f.find("audit", Filter::new().eq("tenantId", f.tenant_id.clone()))
        .await
        .into_iter()
        .filter(|event| event["action"] == action)
        .collect()
}

/// A service account of the organization (as `serviceAccounts.create` writes it).
async fn service_account(f: &Org) -> String {
    let id = uuid();
    f.insert(
        "identities",
        json!({
            "id": id,
            "tenantId": f.tenant_id,
            "kind": "service",
            "name": format!("workload-{}", &id[..8]),
            "status": "active",
            "emailVerified": false,
            "rootAdmin": false,
            "owner": false,
            "createdAt": n(f.now()),
        }),
    )
    .await;
    id
}

/// Seeds a web-identity trust record, as the web-identity API stores it.
async fn seed_web_trust(f: &Org, role_id: &str, fields: Value) -> Record {
    let account = service_account(f).await;
    let now = f.now();
    let trust = merged(
        &json!({
            "id": uuid(),
            "tenantId": f.tenant_id,
            "kind": "web-identity",
            "sourceTenantId": f.tenant_id,
            "sourceIdentityId": account,
            "roleId": role_id,
            "requireMfa": false,
            "revoked": false,
            "ceiling": all(),
            "passSourceAttributes": true,
            "providerId": uuid(),
            "conditions": { "StringEquals": { "token.sub": "repo:acme/app:ref:refs/heads/main" } },
            "createdAt": now,
            "createdBy": f.owner_id,
            "updatedAt": now,
        }),
        fields,
    );
    f.insert("trusts", trust).await
}

/// A live role session under a trust, as `roles.assume` stores it.
async fn role_session(f: &Org, trust: &Value, created_at: f64) -> String {
    let id = uuid();
    let token_hash = sha256(&uuid());
    f.insert(
        "sessions",
        json!({
            "id": id,
            "tenantId": trust["tenantId"],
            "identityId": trust["sourceIdentityId"],
            "originalIdentityId": trust["sourceIdentityId"],
            "roleId": trust["roleId"],
            "trustId": trust["id"],
            "kind": "role",
            "tokenHash": token_hash,
            "uniqueKey": token_hash,
            "createdAt": created_at,
            "lastSeenAt": created_at,
            "authenticatedAt": created_at,
            "expiresAt": created_at + 900_000.0,
            "mfa": false,
        }),
    )
    .await;
    id
}

fn text(value: &Value) -> String {
    value.as_str().unwrap().to_owned()
}

#[test]
fn create_returns_a_public_trust_with_the_identity_defaults_and_never_the_external_id_hash() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (role, _) = reader_role(&f).await;
        let created = ok(f
            .iam
            .api
            .trust
            .create(
                &f.root_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "sourceTenantId": f.tenant_id,
                    "sourceIdentityId": f.owner_id,
                    "roleId": role,
                    "externalId": "contract-7",
                })),
            )
            .await);
        assert_eq!(sorted_keys(&created), PUBLIC_TRUST_KEYS);
        assert_eq!(
            created,
            json!({
                "id": created["id"],
                "tenantId": f.tenant_id,
                "kind": "identity",
                "sourceTenantId": f.tenant_id,
                "sourceIdentityId": f.owner_id,
                "roleId": role,
                "requireMfa": true,
                "requiresExternalId": true,
                "revoked": false,
                "ceiling": all(),
                "passSourceAttributes": true,
                "allowedTagKeys": [],
                "sourceIdentityMode": "forbidden",
                "createdAt": n(f.now()),
                "createdBy": f.root_id,
                "updatedAt": n(f.now()),
            })
        );
        let stored = get(&f, "trusts", &text(&created["id"])).await.unwrap();
        assert_eq!(stored["externalIdHash"], sha256("contract-7"));
        let listed = ok(f
            .iam
            .api
            .trust
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        assert_eq!(listed, json!([created]));
        let serialized = listed.to_string();
        assert!(!serialized.contains("externalIdHash"));
        assert!(!serialized.contains(stored["externalIdHash"].as_str().unwrap()));
    });
}

#[test]
fn create_keeps_source_attributes_out_of_new_cross_tenant_trusts_unless_asked() {
    run(|| async {
        let f = organization(|_| {}).await;
        let platform = f.root_tenant.clone();
        let ops = f.member_in(&platform, "ops").await;
        let (role, _) = reader_role(&f).await;
        let base = json!({
            "tenantId": f.tenant_id,
            "sourceTenantId": platform,
            "sourceIdentityId": ops,
            "roleId": role,
        });
        let closed = ok(f
            .iam
            .api
            .trust
            .create(&f.root_credential, body(base.clone()))
            .await);
        assert_matches(
            &closed,
            json!({ "passSourceAttributes": false, "requiresExternalId": false }),
        );
        let open = ok(f
            .iam
            .api
            .trust
            .create(
                &f.root_credential,
                body(merged(&base, json!({ "passSourceAttributes": true }))),
            )
            .await);
        assert_eq!(open["passSourceAttributes"], true);
    });
}

#[test]
fn create_validates_the_new_knobs() {
    run(|| async {
        let f = organization(role_session_cap(7200.0)).await;
        let (role, _) = reader_role(&f).await;
        let base = json!({
            "tenantId": f.tenant_id,
            "sourceTenantId": f.tenant_id,
            "sourceIdentityId": f.owner_id,
            "roleId": role,
        });
        let many: Vec<String> = (0..51).map(|index| format!("key{index}")).collect();
        let invalid = [
            json!({ "maxSessionSeconds": 59 }),
            json!({ "maxSessionSeconds": 7201 }),
            json!({ "maxSessionSeconds": 900.5 }),
            json!({ "maxSessionSeconds": "900" }),
            json!({ "allowedTagKeys": "team" }),
            json!({ "allowedTagKeys": ["team", "Team"] }),
            json!({ "allowedTagKeys": ["*", "team"] }),
            json!({ "allowedTagKeys": ["bad-key"] }),
            json!({ "allowedTagKeys": many }),
            json!({ "sourceIdentityMode": "sometimes" }),
            json!({ "passSourceAttributes": "yes" }),
            json!({ "requireMfa": "no" }),
            json!({ "description": "x".repeat(513) }),
            json!({ "description": "" }),
            json!({ "externalId": 42 }),
            json!({ "kind": "saml" }),
        ];
        for extra in invalid {
            let error = fails(
                f.iam
                    .api
                    .trust
                    .create(&f.root_credential, body(merged(&base, extra.clone())))
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT", "{extra}");
        }
        // Web-identity trusts are gated by sts.webIdentity (off in this fixture); the gate is checked first.
        let error = fails(
            f.iam
                .api
                .trust
                .create(
                    &f.root_credential,
                    body(merged(&base, json!({ "kind": "web-identity" }))),
                )
                .await,
        );
        assert_eq!(code(&error), "FEATURE_DISABLED");
        assert_eq!(error.message, "Web identity federation is not enabled");
        let configured = ok(f
            .iam
            .api
            .trust
            .create(
                &f.root_credential,
                body(merged(
                    &base,
                    json!({
                        "kind": "identity",
                        "maxSessionSeconds": 7200,
                        "allowedTagKeys": ["team", "env"],
                        "sourceIdentityMode": "required",
                        "passSourceAttributes": false,
                        "description": "Break-glass access for the on-call engineer",
                    }),
                )),
            )
            .await);
        assert_matches(
            &configured,
            json!({
                "maxSessionSeconds": 7200,
                "allowedTagKeys": ["team", "env"],
                "sourceIdentityMode": "required",
                "passSourceAttributes": false,
                "description": "Break-glass access for the on-call engineer",
            }),
        );
        let wildcard = ok(f
            .iam
            .api
            .trust
            .create(
                &f.root_credential,
                body(merged(&base, json!({ "allowedTagKeys": ["*"] }))),
            )
            .await);
        assert_eq!(wildcard["allowedTagKeys"], json!(["*"]));
        // Identity trusts stay platform-controlled.
        let owner = f.sign_in(&f.owner_id).await;
        let error = fails(f.iam.api.trust.create(&owner, body(base.clone())).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
    });
}

#[test]
fn update_bumps_the_watermark_only_when_the_trust_tightens() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (_, trust) = owner_trust(&f, json!({ "allowedTagKeys": ["team"] })).await;
        let trust_id = text(&trust["id"]);
        let update = |fields: Value| {
            let input = merged(
                &json!({ "tenantId": f.tenant_id, "trustId": trust_id }),
                fields,
            );
            let api = f.iam.api.trust.clone();
            let credential = f.root_credential.clone();
            async move { api.update(&credential, body(input)).await }
        };
        f.advance(1000.0);
        // Loosening or relabelling keeps live sessions.
        for fields in [
            json!({ "description": "Support access" }),
            json!({ "passSourceAttributes": false }),
            json!({ "requireMfa": false, "description": "Support access for tickets" }),
            json!({ "ceiling": read_documents() }),
        ] {
            let updated = ok(update(fields).await);
            assert!(updated.get("sessionsRevokedBefore").is_none());
            assert_eq!(updated["updatedAt"], n(f.now()));
        }
        // A lower session cap ends the sessions issued under the higher one.
        let capped = ok(update(json!({ "maxSessionSeconds": 1800 })).await);
        assert_matches(
            &capped,
            json!({ "maxSessionSeconds": 1800, "sessionsRevokedBefore": f.now() + 1.0 }),
        );
        f.advance(1000.0);
        // Raising it again (or clearing it back to the 3600 s default) does not.
        let raised = ok(update(json!({ "maxSessionSeconds": null })).await);
        assert!(raised.get("maxSessionSeconds").is_none());
        assert_eq!(
            raised["sessionsRevokedBefore"],
            capped["sessionsRevokedBefore"]
        );
        // Tag keys (compared as a set) and the source identity mode bump it.
        let error = fails(update(json!({ "allowedTagKeys": ["team"] })).await);
        assert_eq!(code(&error), "INVALID_INPUT");
        let tagged = ok(update(json!({ "allowedTagKeys": ["team", "env"] })).await);
        assert_eq!(tagged["sessionsRevokedBefore"], n(f.now() + 1.0));
        // The same keys in another order are stored as given, but compare as the same set: no new watermark.
        f.advance(1000.0);
        let reordered = ok(update(json!({ "allowedTagKeys": ["env", "team"] })).await);
        assert_eq!(reordered["allowedTagKeys"], json!(["env", "team"]));
        assert_eq!(
            reordered["sessionsRevokedBefore"],
            tagged["sessionsRevokedBefore"]
        );
        let moded = ok(update(json!({ "sourceIdentityMode": "optional" })).await);
        assert_eq!(moded["sessionsRevokedBefore"], n(f.now() + 1.0));
        f.advance(1000.0);
        let cleared = ok(update(json!({ "allowedTagKeys": null, "description": null })).await);
        assert_eq!(cleared["allowedTagKeys"], json!([]));
        assert!(cleared.get("description").is_none());
        assert_eq!(cleared["sessionsRevokedBefore"], n(f.now() + 1.0));
        assert!(cleared.get("externalIdHash").is_none());
    });
}

#[test]
fn update_refuses_non_root_callers_no_ops_foreign_fields_revoked_trusts_and_stale_sessions() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (_, trust) = owner_trust(&f, json!({ "description": "Support" })).await;
        let base = json!({ "tenantId": f.tenant_id, "trustId": trust["id"] });
        // The owner holds iam:trust:update but identity trusts are platform-controlled; the refusal is audited.
        let owner = f.sign_in(&f.owner_id).await;
        let error = fails(
            f.iam
                .api
                .trust
                .update(
                    &owner,
                    body(merged(&base, json!({ "description": "Mine" }))),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let denials: Vec<Record> = audit_of(&f, "iam:trust:update")
            .await
            .into_iter()
            .filter(|event| event["outcome"] == "deny")
            .collect();
        assert_eq!(denials.len(), 1);
        for fields in [
            json!({}),
            json!({ "description": "Support" }),
            json!({ "requireMfa": false }),
            json!({ "maxSessionSeconds": 3601 }),
            json!({ "maxSessionSeconds": 30 }),
            json!({ "sourceIdentityMode": "maybe" }),
            json!({ "conditions": { "StringEquals": { "token.sub": "repo:acme/app" } } }),
            json!({ "tagClaims": { "team": "token.team" } }),
            json!({ "sourceIdentityClaim": "token.actor" }),
        ] {
            let error = fails(
                f.iam
                    .api
                    .trust
                    .update(&f.root_credential, body(merged(&base, fields.clone())))
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT", "{fields}");
        }
        let error = fails(
            f.iam
                .api
                .trust
                .update(
                    &f.root_credential,
                    body(json!({ "tenantId": f.tenant_id, "trustId": uuid(), "description": "x" })),
                )
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
        let revoked = ok(f
            .iam
            .api
            .trust
            .revoke(&f.root_credential, body(base.clone()))
            .await);
        assert_eq!(revoked["revoked"], true);
        let error = fails(
            f.iam
                .api
                .trust
                .update(
                    &f.root_credential,
                    body(merged(&base, json!({ "description": "Again" }))),
                )
                .await,
        );
        assert_eq!((code(&error), error.status), ("CONFLICT", 409));
        f.advance(6.0 * 60_000.0);
        let error = fails(
            f.iam
                .api
                .trust
                .update(
                    &f.root_credential,
                    body(merged(&base, json!({ "description": "Late" }))),
                )
                .await,
        );
        assert_eq!(code(&error), "RECENT_AUTH_REQUIRED");
    });
}

#[test]
#[ignore = "blocked on web-identity.ts: createWebIdentityVerifier (sts.webIdentity.enabled) is not ported"]
fn update_manages_web_identity_trusts_through_the_creator_authority_and_their_own_fields() {
    run(|| async {
        let f = organization(web_identity_on).await;
        let (role, authority) = reader_role(&f).await;
        let mine = seed_web_trust(&f, &role, json!({ "authorityId": authority })).await;
        let owner = f.sign_in(&f.owner_id).await;
        let base = json!({ "tenantId": f.tenant_id, "trustId": mine["id"] });
        for fields in [
            json!({ "requireMfa": true }),
            json!({ "allowedTagKeys": ["team"] }),
            json!({ "sourceIdentityMode": "optional" }),
            json!({ "tagClaims": { "bad-key": "token.team" } }),
            json!({ "tagClaims": "token.team" }),
        ] {
            let error = fails(
                f.iam
                    .api
                    .trust
                    .update(&owner, body(merged(&base, fields.clone())))
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT", "{fields}");
        }
        // The creator's authority edits the trust (no root needed).
        let described = ok(f
            .iam
            .api
            .trust
            .update(
                &owner,
                body(merged(&base, json!({ "description": "CI deploys" }))),
            )
            .await);
        assert_matches(
            &described,
            json!({ "kind": "web-identity", "description": "CI deploys" }),
        );
        assert!(described.get("sessionsRevokedBefore").is_none());
        // A trust issued under another administrator's authority is out of the owner's reach.
        let platform_authority = root_authority(&f).await;
        assert_ne!(platform_authority, authority);
        let root_role = role_in(&f, &f.tenant_id, &platform_authority, read_documents()).await;
        let foreign =
            seed_web_trust(&f, &root_role, json!({ "authorityId": platform_authority })).await;
        let foreign_target = json!({ "tenantId": f.tenant_id, "trustId": foreign["id"] });
        let error = fails(
            f.iam
                .api
                .trust
                .update(
                    &owner,
                    body(merged(
                        &foreign_target,
                        json!({ "description": "Mine now" }),
                    )),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            f.iam
                .api
                .trust
                .revoke(&owner, body(foreign_target.clone()))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let revoked = ok(f.iam.api.trust.revoke(&owner, body(base.clone())).await);
        assert_matches(&revoked, json!({ "kind": "web-identity", "revoked": true }));
    });
}

#[test]
fn update_is_unavailable_for_web_identity_trusts_while_the_feature_is_off() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (role, authority) = reader_role(&f).await;
        let web = seed_web_trust(&f, &role, json!({ "authorityId": authority })).await;
        let error = fails(
            f.iam
                .api
                .trust
                .update(
                    &f.root_credential,
                    body(json!({ "tenantId": f.tenant_id, "trustId": web["id"], "description": "x" })),
                )
                .await,
        );
        assert_eq!((code(&error), error.status), ("FEATURE_DISABLED", 403));
    });
}

#[test]
fn update_bounds_max_session_seconds_by_the_deployment_ceiling() {
    run(|| async {
        let f = organization(role_session_cap(7200.0)).await;
        let (_, trust) = owner_trust(&f, json!({})).await;
        let updated = ok(f
            .iam
            .api
            .trust
            .update(
                &f.root_credential,
                body(json!({ "tenantId": f.tenant_id, "trustId": trust["id"], "maxSessionSeconds": 7200 })),
            )
            .await);
        // Raising the cap above the legacy 3600 s default is a loosening: no watermark.
        assert_matches(&updated, json!({ "maxSessionSeconds": 7200 }));
        assert!(updated.get("sessionsRevokedBefore").is_none());
        let error = fails(
            f.iam
                .api
                .trust
                .update(
                    &f.root_credential,
                    body(json!({ "tenantId": f.tenant_id, "trustId": trust["id"], "maxSessionSeconds": 7201 })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
fn revoke_sessions_revokes_one_trusts_sessions_and_leaves_the_roles_other_trusts_alone() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (role, trust) = owner_trust(&f, json!({})).await;
        let sibling = ok(f
            .iam
            .api
            .trust
            .create(
                &f.root_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "sourceTenantId": f.tenant_id,
                    "sourceIdentityId": f.owner_id,
                    "roleId": role,
                    "requireMfa": false,
                })),
            )
            .await);
        let revoked_session = role_session(&f, &trust, f.now()).await;
        let kept = role_session(&f, &sibling, f.now()).await;
        let owner = f.sign_in(&f.owner_id).await;
        let result = ok(f
            .iam
            .api
            .trust
            .revoke_sessions(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "trustId": trust["id"] })),
            )
            .await);
        assert_eq!(
            result,
            json!({ "trustId": trust["id"], "sessionsRevokedBefore": n(f.now() + 1.0), "revoked": 1 })
        );
        assert!(get(&f, "sessions", &revoked_session).await.is_none());
        assert!(get(&f, "sessions", &kept).await.is_some());
        let stored = get(&f, "trusts", &text(&trust["id"])).await.unwrap();
        assert_eq!(stored["sessionsRevokedBefore"], n(f.now() + 1.0));
        let events = audit_of(&f, "role:sessions-revoked").await;
        assert_matches(
            &Value::Object(events[0].clone()),
            json!({
                "resourceId": trust["id"],
                "metadata": { "sessionsRevokedBefore": result["sessionsRevokedBefore"], "revoked": 1 },
            }),
        );
    });
}

#[test]
fn revoke_sessions_validates_input_and_requires_recent_authentication_and_the_permission_on_the_role()
 {
    run(|| async {
        let f = organization(|_| {}).await;
        let (_, trust) = owner_trust(&f, json!({})).await;
        let owner = f.sign_in(&f.owner_id).await;
        let revoke = |credential: CredentialInput, input: Value| {
            let api = f.iam.api.trust.clone();
            async move { api.revoke_sessions(&credential, body(input)).await }
        };
        let error = fails(
            revoke(
                owner.clone(),
                json!({ "tenantId": f.tenant_id, "trustId": trust["id"], "before": f.now() + 60_000.0 }),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = fails(
            revoke(
                owner.clone(),
                json!({ "tenantId": f.tenant_id, "trustId": uuid() }),
            )
            .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
        let error = fails(
            revoke(
                owner.clone(),
                json!({ "tenantId": f.root_tenant, "trustId": trust["id"] }),
            )
            .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
        let alice = f.member("alice").await;
        let alice = f.sign_in(&alice).await;
        let error = fails(
            revoke(
                alice,
                json!({ "tenantId": f.tenant_id, "trustId": trust["id"] }),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        f.advance(6.0 * 60_000.0);
        let error = fails(
            revoke(
                owner,
                json!({ "tenantId": f.tenant_id, "trustId": trust["id"] }),
            )
            .await,
        );
        assert_eq!(code(&error), "RECENT_AUTH_REQUIRED");
    });
}

#[test]
fn revoke_sessions_lets_a_target_tenant_administrator_end_sessions_under_a_platform_controlled_cross_tenant_trust()
 {
    run(|| async {
        let f = organization(|_| {}).await;
        let platform = f.root_tenant.clone();
        let ops = f.member_in(&platform, "ops").await;
        let (role, _) = reader_role(&f).await;
        let trust = ok(f
            .iam
            .api
            .trust
            .create(
                &f.root_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "sourceTenantId": platform,
                    "sourceIdentityId": ops,
                    "roleId": role,
                    "requireMfa": false,
                })),
            )
            .await);
        let assumed = role_session(&f, &trust, f.now()).await;
        // The owner is not root: the trust itself stays out of reach, but its sessions can be ended.
        let owner = f.sign_in(&f.owner_id).await;
        let target = json!({ "tenantId": f.tenant_id, "trustId": trust["id"] });
        let error = fails(f.iam.api.trust.revoke(&owner, body(target.clone())).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        let result = ok(f
            .iam
            .api
            .trust
            .revoke_sessions(&owner, body(target.clone()))
            .await);
        assert_eq!(result["revoked"], 1);
        assert!(get(&f, "sessions", &assumed).await.is_none());
        let stored = get(&f, "trusts", &text(&trust["id"])).await.unwrap();
        assert_eq!(stored["revoked"], false);
    });
}

#[test]
fn revoke_deletes_the_trusts_live_sessions() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (role, trust) = owner_trust(&f, json!({})).await;
        let other = ok(f
            .iam
            .api
            .trust
            .create(
                &f.root_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "sourceTenantId": f.tenant_id,
                    "sourceIdentityId": f.owner_id,
                    "roleId": role,
                    "requireMfa": false,
                })),
            )
            .await);
        let first = role_session(&f, &trust, f.now()).await;
        let second = role_session(&f, &trust, f.now()).await;
        let kept = role_session(&f, &other, f.now()).await;
        let revoked = ok(f
            .iam
            .api
            .trust
            .revoke(
                &f.root_credential,
                body(json!({ "tenantId": f.tenant_id, "trustId": trust["id"] })),
            )
            .await);
        assert_eq!(revoked["revoked"], true);
        assert_eq!(revoked["updatedAt"], n(f.now()));
        assert!(get(&f, "sessions", &first).await.is_none());
        assert!(get(&f, "sessions", &second).await.is_none());
        assert!(get(&f, "sessions", &kept).await.is_some());
    });
}

#[test]
fn list_hides_external_identifiers_and_revoked_trusts_and_refuses_other_tenants() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (a_tenant, a_owner, a_credential) = f
            .activate(
                &f.root_tenant.clone(),
                "Beta",
                "organization",
                "owner@beta.test",
            )
            .await;
        // The trust targets Acme (b in the TypeScript test) from Beta's owner (a).
        let (role, _) = reader_role(&f).await;
        let trust = ok(f
            .iam
            .api
            .trust
            .create(
                &f.root_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "sourceTenantId": a_tenant,
                    "sourceIdentityId": a_owner,
                    "roleId": role,
                    "externalId": "contract-7",
                })),
            )
            .await);
        let list = |credential: CredentialInput, input: Value| {
            let api = f.iam.api.trust.clone();
            async move { api.list(&credential, body(input)).await }
        };
        let listed = ok(list(
            f.owner_credential.clone(),
            json!({ "tenantId": f.tenant_id }),
        )
        .await);
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_matches(
            &listed[0],
            json!({ "id": trust["id"], "roleId": role, "sourceTenantId": a_tenant, "requiresExternalId": true }),
        );
        assert!(listed[0].get("externalIdHash").is_none());
        ok(f.iam
            .api
            .trust
            .revoke(
                &f.root_credential,
                body(json!({ "tenantId": f.tenant_id, "trustId": trust["id"] })),
            )
            .await);
        assert_eq!(
            ok(list(
                f.owner_credential.clone(),
                json!({ "tenantId": f.tenant_id })
            )
            .await),
            json!([])
        );
        let with_revoked = ok(list(
            f.owner_credential.clone(),
            json!({ "tenantId": f.tenant_id, "includeRevoked": true }),
        )
        .await);
        let flags: Vec<Value> = with_revoked
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["revoked"].clone())
            .collect();
        assert_eq!(flags, vec![json!(true)]);
        let error = fails(list(a_credential, json!({ "tenantId": f.tenant_id })).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
    });
}

#[test]
fn web_identity_trusts_need_the_feature_to_be_created_evaluated_or_updated_but_not_revoked() {
    run(|| async {
        let f = organization(|_| {}).await;
        let conditions =
            json!({ "StringEquals": { "token.sub": "repo:acme/app:ref:refs/heads/main" } });
        let error = fails(
            f.iam
                .api
                .trust
                .create(
                    &f.owner_credential,
                    body(json!({
                        "tenantId": f.tenant_id,
                        "kind": "web-identity",
                        "providerId": uuid(),
                        "serviceAccountId": uuid(),
                        "roleId": uuid(),
                        "conditions": conditions,
                    })),
                )
                .await,
        );
        assert_eq!((code(&error), error.status), ("FEATURE_DISABLED", 403));
        // A web trust stored while the feature was on.
        let now = f.now();
        let seeded = f
            .insert(
                "trusts",
                json!({
                    "id": uuid(),
                    "tenantId": f.tenant_id,
                    "kind": "web-identity",
                    "sourceTenantId": f.tenant_id,
                    "sourceIdentityId": uuid(),
                    "roleId": uuid(),
                    "requireMfa": false,
                    "revoked": false,
                    "providerId": uuid(),
                    "conditions": conditions,
                    "createdAt": now,
                    "updatedAt": now,
                }),
            )
            .await;
        let target = json!({ "tenantId": f.tenant_id, "trustId": seeded["id"] });
        let error = fails(
            f.iam
                .api
                .trust
                .evaluate_web_identity(
                    &f.owner_credential,
                    body(merged(&target, json!({ "webIdentityToken": "a.b.c" }))),
                )
                .await,
        );
        assert_eq!(code(&error), "FEATURE_DISABLED");
        let error = fails(
            f.iam
                .api
                .trust
                .update(
                    &f.root_credential,
                    body(merged(&target, json!({ "description": "x" }))),
                )
                .await,
        );
        assert_eq!(code(&error), "FEATURE_DISABLED");
        // Revoking only removes access, so it works with the feature off and deletes the trust's sessions.
        let session = role_session(&f, &Value::Object(seeded.clone()), now).await;
        let revoked = ok(f
            .iam
            .api
            .trust
            .revoke(&f.root_credential, body(target.clone()))
            .await);
        assert_matches(&revoked, json!({ "id": seeded["id"], "revoked": true }));
        let stored = get(&f, "trusts", &text(&seeded["id"])).await.unwrap();
        assert_eq!(stored["revoked"], true);
        assert!(get(&f, "sessions", &session).await.is_none());
    });
}

#[test]
#[ignore = "blocked on web-identity.ts: createWebIdentityVerifier (sts.webIdentity.enabled) is not ported"]
fn web_identity_create_refuses_identity_fields_and_identity_create_refuses_web_fields() {
    run(|| async {
        let f = organization(web_identity_on).await;
        let (role, _) = reader_role(&f).await;
        let account = service_account(&f).await;
        let base = json!({
            "tenantId": f.tenant_id,
            "kind": "web-identity",
            "providerId": uuid(),
            "serviceAccountId": account,
            "roleId": role,
            "conditions": { "StringEquals": { "token.sub": "repo:acme/app:ref:refs/heads/main" } },
        });
        for extra in [
            json!({ "sourceTenantId": f.tenant_id }),
            json!({ "sourceIdentityId": account }),
            json!({ "requireMfa": false }),
            json!({ "externalId": "shared" }),
            json!({ "allowedTagKeys": ["team"] }),
            json!({ "sourceIdentityMode": "optional" }),
            json!({ "providerId": null }),
            json!({ "serviceAccountId": "" }),
        ] {
            let mut input = merged(&base, extra.clone());
            if extra.get("providerId").is_some_and(Value::is_null) {
                input.as_object_mut().unwrap().shift_remove("providerId");
            }
            let error = fails(
                f.iam
                    .api
                    .trust
                    .create(&f.owner_credential, body(input))
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT", "{extra}");
        }
        // Web-only fields on an identity trust are refused as well.
        for extra in [
            json!({ "providerId": uuid() }),
            json!({ "serviceAccountId": account }),
            json!({ "conditions": {} }),
            json!({ "tagClaims": {} }),
            json!({ "sourceIdentityClaim": "token.actor" }),
        ] {
            let error = fails(
                f.iam
                    .api
                    .trust
                    .create(
                        &f.root_credential,
                        body(merged(
                            &json!({
                                "tenantId": f.tenant_id,
                                "sourceTenantId": f.tenant_id,
                                "sourceIdentityId": f.owner_id,
                                "roleId": role,
                            }),
                            extra.clone(),
                        )),
                    )
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT", "{extra}");
        }
    });
}

#[test]
#[ignore = "blocked on web-identity.ts: createWebIdentityVerifier (sts.webIdentity.enabled) is not ported"]
fn evaluate_web_identity_authorizes_first_reads_web_trusts_only_and_never_verifies_malformed_tokens()
 {
    run(|| async {
        let f = organization(web_identity_on).await;
        let (role, authority) = reader_role(&f).await;
        let trust = seed_web_trust(&f, &role, json!({ "authorityId": authority })).await;
        let provider_id = text(&trust["providerId"]);
        let issuer = format!("https://token.example.test/{provider_id}");
        f.insert(
            "oidcProviders",
            json!({
                "id": provider_id,
                "tenantId": f.tenant_id,
                "uniqueKey": format!("issuer:{issuer}"),
                "name": "CI",
                "issuer": issuer,
                "audiences": ["sts.example.test"],
                "algorithms": ["RS256"],
                "maxTokenLifetimeSeconds": 3600,
                "clockToleranceSeconds": 30,
                "replayProtection": "single-use",
                "enabled": true,
                "authorityId": authority,
                "createdAt": n(f.now()),
                "createdBy": f.owner_id,
                "updatedAt": n(f.now()),
            }),
        )
        .await;
        let evaluate = |credential: CredentialInput, input: Value| {
            let api = f.iam.api.trust.clone();
            async move { api.evaluate_web_identity(&credential, body(input)).await }
        };
        let target = json!({ "tenantId": f.tenant_id, "trustId": trust["id"] });
        assert_eq!(
            ok(evaluate(
                f.owner_credential.clone(),
                merged(&target, json!({ "webIdentityToken": "garbage" }))
            )
            .await),
            json!({ "verified": false, "reason": "malformed" })
        );
        for token in [json!("x".repeat(8193)), json!(42), Value::Null] {
            let error = fails(
                evaluate(
                    f.owner_credential.clone(),
                    merged(&target, json!({ "webIdentityToken": token })),
                )
                .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT");
        }
        // Web trusts only; authorized before the trust is read.
        let identity_trust = ok(f
            .iam
            .api
            .trust
            .create(
                &f.root_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "sourceTenantId": f.tenant_id,
                    "sourceIdentityId": f.owner_id,
                    "roleId": role,
                    "requireMfa": false,
                })),
            )
            .await);
        let error = fails(
            evaluate(
                f.owner_credential.clone(),
                json!({ "tenantId": f.tenant_id, "trustId": identity_trust["id"], "webIdentityToken": "a.b.c" }),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let alice = f.member("alice").await;
        let alice = f.sign_in(&alice).await;
        for trust_id in [text(&trust["id"]), uuid()] {
            let error = fails(
                evaluate(
                    alice.clone(),
                    json!({ "tenantId": f.tenant_id, "trustId": trust_id, "webIdentityToken": "a.b.c" }),
                )
                .await,
            );
            assert_eq!(code(&error), "ACCESS_DENIED");
        }
        let error = fails(
            evaluate(
                f.owner_credential.clone(),
                json!({ "tenantId": f.tenant_id, "trustId": uuid(), "webIdentityToken": "a.b.c" }),
            )
            .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
    });
}

#[test]
fn public_trust_reads_legacy_records_and_drops_malformed_tag_key_lists() {
    let mut record = Map::new();
    for (key, value) in [
        ("id", json!("t1")),
        ("tenantId", json!("acme")),
        ("sourceTenantId", json!("acme")),
        ("sourceIdentityId", json!("usr")),
        ("roleId", json!("rol")),
        ("requireMfa", json!(true)),
        ("externalIdHash", json!("abc")),
        ("revoked", json!(false)),
        ("allowedTagKeys", json!("*")),
        ("tagClaims", Value::Null),
    ] {
        record.insert(key.into(), value);
    }
    let public = better_iam_server::api::trust::public_trust(&record);
    assert_eq!(
        Value::Object(public),
        json!({
            "id": "t1",
            "tenantId": "acme",
            "kind": "identity",
            "sourceTenantId": "acme",
            "sourceIdentityId": "usr",
            "roleId": "rol",
            "requireMfa": true,
            "requiresExternalId": true,
            "revoked": false,
            "tagClaims": {},
        })
    );
}

#[test]
fn legacy_trust_records_without_a_kind_are_platform_controlled_identity_trusts() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (_, trust) = owner_trust(&f, json!({})).await;
        let trust_id = text(&trust["id"]);
        patch(&f, "trusts", &trust_id, json!({ "kind": null })).await;
        let listed = ok(f
            .iam
            .api
            .trust
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        assert_eq!(listed[0]["kind"], "identity");
        let owner = f.sign_in(&f.owner_id).await;
        let error = fails(
            f.iam
                .api
                .trust
                .update(
                    &owner,
                    body(json!({ "tenantId": f.tenant_id, "trustId": trust_id, "description": "Mine" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let updated = ok(f
            .iam
            .api
            .trust
            .update(
                &f.root_credential,
                body(json!({ "tenantId": f.tenant_id, "trustId": trust_id, "description": "Legacy" })),
            )
            .await);
        assert_matches(
            &updated,
            json!({ "kind": "identity", "description": "Legacy" }),
        );
        // The stored record keeps its shape: no kind is written back.
        let stored = get(&f, "trusts", &trust_id).await.unwrap();
        assert!(stored.get("kind").is_none());
    });
}
