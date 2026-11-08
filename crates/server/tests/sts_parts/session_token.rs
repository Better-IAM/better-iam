//! Port of `tests/sts-session-token.test.ts`, the `sts.getSessionToken` suite: the permission, the sources it accepts,
//! duration bounds, scope-down and source policies, the MFA step-up, the per-identity cap, revocation with the source,
//! and the HTTP transport. (Its `duration bounds fail closed` block tests `temporary-credentials.ts`, which another
//! unit ports with that module.)

use std::sync::atomic::{AtomicUsize, Ordering};

use better_iam_core::{CredentialInput, IamResult};
use serde_json::{Value, json};

use crate::support::*;

static NAMES: AtomicUsize = AtomicUsize::new(0);

fn next_name() -> usize {
    NAMES.fetch_add(1, Ordering::SeqCst) + 1
}

/// Binds a fresh role with `permissions` (an allow over every resource) to an identity of Acme.
async fn grant(f: &Fixture, subject_id: &str, permissions: &[&str]) -> IamResult<Value> {
    let role = api!(
        f.iam.api.roles,
        create,
        &f.owner_credential,
        json!({ "tenantId": f.tenant_id, "name": format!("Grant {}", next_name()), "permissions": permissions })
    )?;
    api!(
        f.iam.api.bindings,
        create,
        &f.owner_credential,
        json!({
            "tenantId": f.tenant_id,
            "roleId": role["id"],
            "subjectType": "identity",
            "subjectId": subject_id,
        })
    )?;
    Ok(role)
}

/// A service account holding `permissions`, with one API key (optionally scoped or short-lived).
async fn service_key(
    f: &Fixture,
    permissions: Option<&[&str]>,
    scopes: Option<&[&str]>,
    expires_in_seconds: Option<f64>,
) -> IamResult<(Value, CredentialInput)> {
    let account = api!(
        f.iam.api.service_accounts,
        create,
        &f.owner_credential,
        json!({ "tenantId": f.tenant_id, "name": format!("svc-{}", next_name()) })
    )?;
    let account_id = str_of(&account, "id").to_owned();
    if let Some(permissions) = permissions {
        grant(f, &account_id, permissions).await?;
    }
    let mut input = json!({ "tenantId": f.tenant_id, "identityId": account_id });
    if let Some(scopes) = scopes {
        input["scopes"] = json!(scopes);
    }
    if let Some(seconds) = expires_in_seconds {
        input["expiresInSeconds"] = json!(seconds);
    }
    let key = api!(
        f.iam.api.credentials,
        create,
        &f.owner_sign_in().await?,
        input
    )?;
    Ok((account, bearer(str_of(&key, "token"))))
}

/// A read-only role in Acme, a same-tenant trust (no MFA) from the owner to it, and an assumed session.
async fn owner_role(f: &Fixture) -> IamResult<(Value, Value, String)> {
    let role = api!(
        f.iam.api.roles,
        create,
        &f.owner_credential,
        json!({ "tenantId": f.tenant_id, "name": format!("Reader {}", next_name()), "permissions": ["documents:read"] })
    )?;
    let trust = api!(
        f.iam.api.trust,
        create,
        &f.root_credential,
        json!({
            "tenantId": f.tenant_id,
            "sourceTenantId": f.tenant_id,
            "sourceIdentityId": f.owner_id,
            "roleId": role["id"],
            "requireMfa": false,
        })
    )?;
    let assumed = api!(
        f.iam.api.roles,
        assume,
        &f.owner_sign_in().await?,
        json!({ "tenantId": f.tenant_id, "trustId": trust["id"] })
    )?;
    let token = str_of(&assumed, "token").to_owned();
    Ok((role, trust, token))
}

/// Enrolls TOTP for the person signed in with `token`; returns the secret and the new MFA session's token.
async fn enroll_totp(f: &Fixture, token: &str) -> IamResult<(String, String)> {
    let enrollment = f.auth("beginMfa", &bearer(token), json!({})).await?;
    let secret = str_of(&enrollment, "secret").to_owned();
    let confirmed = f
        .auth(
            "confirmMfa",
            &bearer(token),
            json!({ "code": totp(&secret, f.now()) }),
        )
        .await?;
    Ok((secret, str_of(&confirmed, "token").to_owned()))
}

fn events(events: &[better_iam_core::Record], action: &str) -> Vec<Value> {
    events
        .iter()
        .filter(|event| event.get("action").and_then(Value::as_str) == Some(action))
        .map(value)
        .collect()
}

#[test]
fn requires_the_permission_and_returns_a_typed_opaque_token_once_audited() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let alice = ok!(f.member("alice").await);
        let alice_id = str_of(&alice, "id").to_owned();
        let login = ok!(f.sign_in_credential("alice").await);
        let error = fails!(f.get_session_token(&login, json!({})).await);
        refused(&error, "ACCESS_DENIED", Some(403), None);
        matches(
            &Value::Array(events(
                &f.audit(&f.tenant_id).await,
                "iam:session-tokens:create",
            )),
            &json!([{ "outcome": "deny", "actorId": alice_id, "resourceId": alice_id }]),
        );

        ok!(grant(
            &f,
            &alice_id,
            &["iam:session-tokens:create", "documents:read"]
        )
        .await);
        let issued = ok!(f
            .get_session_token(&login, json!({ "sessionName": "cli-laptop" }))
            .await);
        let token = str_of(&issued, "token").to_owned();
        assert!(typed_token(&token, "biam_sts_"), "{token}");
        let source = f.row_of(token_of(&login)).await;
        let row = f.row_of(&token).await;
        let now = f.now();
        same(
            &issued,
            &json!({
                "token": token,
                "tokenType": "Bearer",
                "format": "opaque",
                "expiresAt": now + 3_600_000.0,
                "expiresIn": 3600,
                "session": {
                    "id": row["id"],
                    "tenantId": f.tenant_id,
                    "kind": "session-token",
                    "identityId": alice_id,
                    "expiresAt": now + 3_600_000.0,
                    "mfa": false,
                    "sessionName": "cli-laptop",
                },
            }),
        );
        matches(
            &value(&row),
            &json!({
                "kind": "session-token",
                "tenantId": f.tenant_id,
                "identityId": alice_id,
                "sourceSessionId": source["id"],
                "tokenHash": better_iam_server::utils::hash(&token),
                "uniqueKey": better_iam_server::utils::hash(&token),
                "createdAt": now,
                "lastSeenAt": now,
                "authenticatedAt": source["authenticatedAt"],
                "expiresAt": now + 3_600_000.0,
                "mfa": false,
                "sessionName": "cli-laptop",
            }),
        );
        for absent in [
            "policy",
            "sourcePolicy",
            "format",
            "audience",
            "mfaAuthenticatedAt",
        ] {
            assert!(!row.contains_key(absent), "{absent}");
        }
        assert!(
            !issued
                .to_string()
                .contains(row["tokenHash"].as_str().unwrap())
        );

        // The token acts with the identity's grants.
        assert!(ok!(f
            .allowed(&token, "documents:read", "sts-document")
            .await));
        assert!(!ok!(f
            .allowed(&token, "documents:write", "sts-document")
            .await));

        let audit = f.audit(&f.tenant_id).await;
        let allowed: Vec<Value> = events(&audit, "iam:session-tokens:create")
            .into_iter()
            .filter(|event| event["outcome"] == "allow")
            .collect();
        matches(
            &Value::Array(allowed),
            &json!([{
                "actorId": alice_id,
                "resourceId": alice_id,
                "sessionContext": { "sessionId": source["id"], "kind": "user" },
            }]),
        );
        matches(
            &Value::Array(events(&audit, "session-token:issued")),
            &json!([{
                "actorId": alice_id,
                "resourceId": alice_id,
                "outcome": "allow",
                "metadata": {
                    "sessionId": row["id"],
                    "sourceSessionKind": "user",
                    "durationSeconds": 3600,
                    "format": "opaque",
                    "mfaStepUp": false,
                },
            }]),
        );
    });
}

#[test]
fn mints_from_user_sessions_and_api_keys_and_refuses_temporary_and_impersonation_sources() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let from_owner = ok!(f.get_session_token(&f.owner_credential, json!({})).await);
        let from_owner = bearer(str_of(&from_owner, "token"));
        assert_eq!(
            ok!(f.authenticate(&from_owner).await)["kind"],
            "session-token"
        );
        assert!(ok!(f
            .allowed(token_of(&from_owner), "documents:write", "sts-document")
            .await));

        let (account, key) = ok!(service_key(
            &f,
            Some(&["iam:session-tokens:create", "documents:read"]),
            None,
            None
        )
        .await);
        let from_key = ok!(f.get_session_token(&key, json!({})).await);
        let from_key = bearer(str_of(&from_key, "token"));
        let key_row = f.row_of(token_of(&key)).await;
        matches(
            &value(&f.row_of(token_of(&from_key)).await),
            &json!({
                "identityId": account["id"],
                "sourceSessionId": key_row["id"],
                "credentialAuthorityId": key_row["credentialAuthorityId"],
                "authenticatedAt": key_row["authenticatedAt"],
                "mfa": false,
            }),
        );
        assert!(ok!(f
            .allowed(token_of(&from_key), "documents:read", "sts-document")
            .await));
        assert!(!ok!(f
            .allowed(token_of(&from_key), "documents:write", "sts-document")
            .await));

        let chaining = |error: &better_iam_core::IamError| {
            refused(
                error,
                "CREDENTIAL_CHAINING_DISABLED",
                Some(400),
                Some("Temporary credentials cannot mint session tokens"),
            )
        };
        chaining(&fails!(f.get_session_token(&from_owner, json!({})).await));
        chaining(&fails!(f.get_session_token(&from_key, json!({})).await));
        let (_, _, role_token) = ok!(owner_role(&f).await);
        chaining(&fails!(
            f.get_session_token(&bearer(&role_token), json!({})).await
        ));

        ok!(api!(
            f.iam.api.tenants,
            set_auth_policy,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "authPolicy": { "allowImpersonation": true } })
        ));
        let alice = ok!(f.member("alice").await);
        let view_as = ok!(api!(
            f.iam.api.identities,
            impersonate,
            &ok!(f.owner_sign_in().await),
            json!({ "tenantId": f.tenant_id, "identityId": alice["id"], "reason": "ticket 7" })
        ));
        let error = fails!(
            f.get_session_token(&bearer(str_of(&view_as, "token")), json!({}))
                .await
        );
        refused(&error, "IMPERSONATION_RESTRICTED", Some(403), None);
    });
}

#[test]
fn bounds_the_duration_refuses_malformed_input_and_never_outlives_the_source() {
    run(|| async {
        let f = ok!(organization_fixture(|options| {
            options.sts = Some(sts(json!({ "maxSessionTokenSeconds": 1800 })))
        })
        .await);
        let get = |input: Value| f.get_session_token(&f.owner_credential, input);
        assert_eq!(ok!(get(json!({})).await)["expiresIn"], 1800);
        assert_eq!(
            ok!(get(json!({ "durationSeconds": 60 })).await)["expiresIn"],
            60
        );
        assert_eq!(
            ok!(get(json!({ "durationSeconds": 1800 })).await)["expiresIn"],
            1800
        );
        for duration in [json!(59), json!(1801), json!(90.5), json!(-1), json!("900")] {
            let error = fails!(get(json!({ "durationSeconds": duration })).await);
            refused(&error, "INVALID_INPUT", None, None);
        }
        for input in [
            json!({ "sessionName": "x" }),
            json!({ "sessionName": "has spaces" }),
            json!({ "format": "xml" }),
            json!({ "audience": ["https://api.example"] }),
            json!({ "policy": "everything" }),
        ] {
            let error = fails!(get(input.clone()).await);
            refused(&error, "INVALID_INPUT", None, None);
        }
        let error = fails!(get(json!({ "format": "jwt" })).await);
        refused(&error, "FEATURE_DISABLED", Some(403), None);

        // An API key that expires sooner caps the token's expiry.
        let (_, key) =
            ok!(service_key(&f, Some(&["iam:session-tokens:create"]), None, Some(600.0)).await);
        let key_row = f.row_of(token_of(&key)).await;
        let capped = ok!(f
            .get_session_token(&key, json!({ "durationSeconds": 1800 }))
            .await);
        same(&capped["expiresAt"], &key_row["expiresAt"]);
        assert_eq!(capped["expiresIn"], 600);
        same(
            &f.row_of(str_of(&capped, "token")).await["expiresAt"],
            &key_row["expiresAt"],
        );
    });
}

#[test]
fn narrows_access_by_the_scope_down_policy_and_the_source_key_scopes() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let read_only = allow(&["documents:read"]);
        let scoped = ok!(f
            .get_session_token(&f.owner_credential, json!({ "policy": read_only }))
            .await);
        let scoped = str_of(&scoped, "token").to_owned();
        assert!(ok!(f
            .allowed(&scoped, "documents:read", "sts-document")
            .await));
        assert!(!ok!(f
            .allowed(&scoped, "documents:write", "sts-document")
            .await));
        matches(
            &value(&f.row_of(&scoped).await),
            &json!({ "policy": read_only }),
        );

        let (_, key) = ok!(service_key(
            &f,
            Some(&[
                "iam:session-tokens:create",
                "documents:read",
                "documents:write"
            ]),
            Some(&["iam:session-tokens:create", "documents:read"]),
            None,
        )
        .await);
        let from_key = ok!(f.get_session_token(&key, json!({})).await);
        let from_key = str_of(&from_key, "token").to_owned();
        let key_row = f.row_of(token_of(&key)).await;
        let from_key_row = f.row_of(&from_key).await;
        same(&from_key_row["sourcePolicy"], &key_row["policy"]);
        assert!(!from_key_row.contains_key("policy"));
        assert!(ok!(f
            .allowed(&from_key, "documents:read", "sts-document")
            .await));
        assert!(!ok!(f
            .allowed(&from_key, "documents:write", "sts-document")
            .await));
        // Both boundaries apply: the policy allows only writing, the key's scopes only reading.
        let both = ok!(f
            .get_session_token(&key, json!({ "policy": allow(&["documents:write"]) }))
            .await);
        let both = str_of(&both, "token").to_owned();
        assert!(!ok!(f
            .allowed(&both, "documents:read", "sts-document")
            .await));
        assert!(!ok!(f
            .allowed(&both, "documents:write", "sts-document")
            .await));
        // A key whose scopes leave out the permission cannot mint at all.
        let (_, narrow) = ok!(service_key(
            &f,
            Some(&["iam:session-tokens:create", "documents:read"]),
            Some(&["documents:read"]),
            None,
        )
        .await);
        refused(
            &fails!(f.get_session_token(&narrow, json!({})).await),
            "ACCESS_DENIED",
            None,
            None,
        );

        // Assertions list the identity's roles, which would escape a scope-down: scoped tokens are refused even when
        // their boundaries allow the action itself.
        let fr = &f;
        let issue = |token: String| async move {
            api!(
                fr.iam.api.assertions,
                issue,
                &bearer(&token),
                json!({ "tenantId": fr.tenant_id, "audience": "billing" })
            )
        };
        refused(
            &fails!(issue(scoped.clone()).await),
            "ACCESS_DENIED",
            None,
            Some("Access denied"),
        );
        let assertive = ok!(f
            .get_session_token(
                &f.owner_credential,
                json!({ "policy": allow(&["documents:read", "iam:assertions:create"]) }),
            )
            .await);
        let (_, assertive_key) = ok!(service_key(
            &f,
            Some(&["iam:session-tokens:create", "iam:assertions:create"]),
            Some(&["iam:session-tokens:create", "iam:assertions:create"]),
            None,
        )
        .await);
        let from_assertive_key = ok!(f.get_session_token(&assertive_key, json!({})).await);
        for token in [
            str_of(&assertive, "token"),
            str_of(&from_assertive_key, "token"),
        ] {
            refused(
                &fails!(issue(token.to_owned()).await),
                "ACCESS_DENIED",
                None,
                Some("Scoped session tokens cannot obtain assertions"),
            );
        }
        let unscoped = ok!(f.get_session_token(&f.owner_credential, json!({})).await);
        let assertion = ok!(issue(str_of(&unscoped, "token").to_owned()).await);
        assert_eq!(str_of(&assertion, "token").split('.').count(), 3);
    });
}

#[test]
fn never_passes_recent_authentication_or_root_checks() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let account = ok!(api!(
            f.iam.api.service_accounts,
            create,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "name": "recent-check" })
        ));
        let token = ok!(f
            .get_session_token(&ok!(f.owner_sign_in().await), json!({}))
            .await);
        let error = fails!(api!(
            f.iam.api.credentials,
            create,
            &bearer(str_of(&token, "token")),
            json!({ "tenantId": f.tenant_id, "identityId": account["id"] })
        ));
        refused(&error, "RECENT_AUTH_REQUIRED", Some(403), None);
        let key = ok!(api!(
            f.iam.api.credentials,
            create,
            &ok!(f.owner_sign_in().await),
            json!({ "tenantId": f.tenant_id, "identityId": account["id"] })
        ));
        assert!(str_of(&key, "token").starts_with("biam_key_"));

        // A root administrator's token is neither root nor a root override.
        let platform = f.root_tenant.clone();
        let administrators = ok!(api!(
            f.iam.api.root,
            list_administrators,
            &f.root_credential,
            json!({ "tenantId": platform })
        ));
        assert_eq!(administrators.as_array().map(Vec::len), Some(1));
        let roles = ok!(api!(
            f.iam.api.roles,
            list,
            &f.root_credential,
            json!({ "tenantId": f.tenant_id })
        ));
        assert_ne!(roles.as_array().map(Vec::len), Some(0));
        let root_token = ok!(f.get_session_token(&f.root_credential, json!({})).await);
        assert_eq!(root_token["session"]["mfa"], true);
        let root_token = bearer(str_of(&root_token, "token"));
        let error = fails!(api!(
            f.iam.api.root,
            list_administrators,
            &root_token,
            json!({ "tenantId": platform })
        ));
        refused(&error, "ACCESS_DENIED", None, None);
        let error = fails!(api!(
            f.iam.api.roles,
            list,
            &root_token,
            json!({ "tenantId": f.tenant_id })
        ));
        refused(&error, "ACCESS_DENIED", None, None);
    });
}

#[test]
fn caps_live_session_tokens_per_identity() {
    run(|| async {
        let f = ok!(organization_fixture(|options| {
            options.sts = Some(sts(json!({ "maxSessionTokensPerIdentity": 2 })))
        })
        .await);
        ok!(f.get_session_token(&f.owner_credential, json!({})).await);
        ok!(f
            .get_session_token(&f.owner_credential, json!({ "durationSeconds": 600 }))
            .await);
        let error = fails!(f.get_session_token(&f.owner_credential, json!({})).await);
        refused(
            &error,
            "LIMIT_EXCEEDED",
            Some(409),
            Some("This identity holds the maximum number of live session tokens"),
        );
        // The cap is per identity.
        let (_, key) = ok!(service_key(&f, Some(&["iam:session-tokens:create"]), None, None).await);
        ok!(f.get_session_token(&key, json!({})).await);
        // Expired tokens no longer count.
        f.advance(600_000.0);
        let fresh = ok!(f.get_session_token(&f.owner_credential, json!({})).await);
        assert!(str_of(&fresh, "token").starts_with("biam_sts_"));
        refused(
            &fails!(f.get_session_token(&f.owner_credential, json!({})).await),
            "LIMIT_EXCEEDED",
            None,
            None,
        );
    });
}

#[test]
fn verifies_a_first_hand_totp_code_for_an_mfa_step_up() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let alice = ok!(f.member("alice").await);
        ok!(grant(
            &f,
            str_of(&alice, "id"),
            &["iam:session-tokens:create", "documents:read"]
        )
        .await);
        // Nobody without an authenticator can step up: a person without TOTP, or an API key (refused before counting).
        let error = fails!(
            f.get_session_token(&f.owner_credential, json!({ "mfaCode": "123456" }))
                .await
        );
        refused(&error, "MFA_NOT_ENROLLED", Some(403), None);
        let (_, key) = ok!(service_key(&f, Some(&["iam:session-tokens:create"]), None, None).await);
        let error = fails!(
            f.get_session_token(&key, json!({ "mfaCode": "123456" }))
                .await
        );
        refused(&error, "MFA_NOT_ENROLLED", Some(403), None);

        let login = ok!(f.sign_in("alice").await);
        let (secret, token) = ok!(enroll_totp(&f, str_of(&login, "token")).await);
        let credential = bearer(&token);
        let source = f.row_of(&token).await;
        assert_eq!(source["mfa"], true);
        // Without a code the source's MFA state is copied.
        let copied = ok!(f.get_session_token(&credential, json!({})).await);
        assert_eq!(copied["session"]["mfa"], true);
        same(
            &f.row_of(str_of(&copied, "token")).await["mfaAuthenticatedAt"],
            &source["mfaAuthenticatedAt"],
        );
        // The enrollment code's time step is spent.
        let error = fails!(
            f.get_session_token(&credential, json!({ "mfaCode": totp(&secret, f.now()) }))
                .await
        );
        refused(&error, "INVALID_MFA", Some(401), None);

        f.advance(30_000.0);
        let code = totp(&secret, f.now());
        let stepped = ok!(f
            .get_session_token(&credential, json!({ "mfaCode": code }))
            .await);
        assert_eq!(stepped["session"]["mfa"], true);
        matches(
            &value(&f.row_of(str_of(&stepped, "token")).await),
            &json!({ "mfa": true, "mfaAuthenticatedAt": f.now() }),
        );
        let audit = f.audit(&f.tenant_id).await;
        assert!(!events(&audit, "auth:mfa:step-up").is_empty());
        let issued = events(&audit, "session-token:issued")
            .into_iter()
            .find(|event| event["metadata"]["sessionId"] == stepped["session"]["id"])
            .expect("issued event");
        matches(&issued["metadata"], &json!({ "mfaStepUp": true }));
        // Replayed and wrong codes are refused.
        refused(
            &fails!(
                f.get_session_token(&credential, json!({ "mfaCode": code }))
                    .await
            ),
            "INVALID_MFA",
            None,
            None,
        );
        refused(
            &fails!(
                f.get_session_token(
                    &credential,
                    json!({ "mfaCode": totp(&secret, f.now() + 600_000.0) })
                )
                .await
            ),
            "INVALID_MFA",
            None,
            None,
        );
    });
}

#[test]
fn counts_step_up_attempts_against_the_sensitive_rate_limit_before_verifying_them() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let alice = ok!(f.member("alice").await);
        ok!(grant(&f, str_of(&alice, "id"), &["iam:session-tokens:create"]).await);
        let login = ok!(f.sign_in("alice").await);
        let (secret, token) = ok!(enroll_totp(&f, str_of(&login, "token")).await);
        let credential = bearer(&token);
        f.advance(30_000.0);
        for _ in 0..5 {
            refused(
                &fails!(
                    f.get_session_token(
                        &credential,
                        json!({ "mfaCode": totp(&secret, f.now() + 600_000.0) })
                    )
                    .await
                ),
                "INVALID_MFA",
                None,
                None,
            );
        }
        let error = fails!(
            f.get_session_token(&credential, json!({ "mfaCode": totp(&secret, f.now()) }))
                .await
        );
        refused(&error, "RATE_LIMITED", Some(429), None);
        // Tokens without a code are not rate limited.
        assert_eq!(
            ok!(f.get_session_token(&credential, json!({})).await)["session"]["mfa"],
            true
        );
    });
}

#[test]
fn lets_a_stepped_up_token_assume_an_mfa_gated_trust_and_the_role_session_ends_with_the_token() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let alice = ok!(f.member("alice").await);
        let alice_id = str_of(&alice, "id").to_owned();
        ok!(grant(
            &f,
            &alice_id,
            &["iam:session-tokens:create", "iam:roles:assume"]
        )
        .await);
        let role = ok!(api!(
            f.iam.api.roles,
            create,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "name": "Guarded reader", "permissions": ["documents:read"] })
        ));
        let trust = ok!(api!(
            f.iam.api.trust,
            create,
            &f.root_credential,
            json!({
                "tenantId": f.tenant_id,
                "sourceTenantId": f.tenant_id,
                "sourceIdentityId": alice_id,
                "roleId": role["id"],
                "requireMfa": true,
            })
        ));
        let plain = ok!(f.sign_in("alice").await);
        let plain_token = str_of(&plain, "token").to_owned();
        let unverified = ok!(f.get_session_token(&bearer(&plain_token), json!({})).await);
        let unverified = bearer(str_of(&unverified, "token"));
        let error = fails!(api!(
            f.iam.api.roles,
            assume,
            &unverified,
            json!({ "tenantId": f.tenant_id, "trustId": trust["id"] })
        ));
        refused(&error, "ACCESS_DENIED", None, None);

        let (secret, token) = ok!(enroll_totp(&f, &plain_token).await);
        let credential = bearer(&token);
        // Enrolling ended the earlier sessions, and the token minted from one of them.
        refused(
            &fails!(f.authenticate(&unverified).await),
            "UNAUTHENTICATED",
            None,
            None,
        );
        f.advance(30_000.0);
        let stepped = ok!(f
            .get_session_token(&credential, json!({ "mfaCode": totp(&secret, f.now()) }))
            .await);
        let stepped_token = bearer(str_of(&stepped, "token"));
        let assumed = ok!(api!(
            f.iam.api.roles,
            assume,
            &stepped_token,
            json!({ "tenantId": f.tenant_id, "trustId": trust["id"] })
        ));
        matches(
            &assumed["session"],
            &json!({ "mfa": true, "roleId": role["id"], "trustId": trust["id"] }),
        );
        same(
            &f.row_of(str_of(&assumed, "token")).await["sourceSessionId"],
            &stepped["session"]["id"],
        );
        assert!(ok!(f
            .allowed(str_of(&assumed, "token"), "documents:read", "sts-document")
            .await));

        // The person sees the token among their sessions (without hashes) and can revoke it.
        let listed = ok!(f.auth("listSessions", &credential, json!({})).await);
        let entry = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|session| session["id"] == stepped["session"]["id"])
            .cloned()
            .expect("listed token");
        matches(
            &entry,
            &json!({ "kind": "session-token", "current": false }),
        );
        assert!(entry.get("tokenHash").is_none());
        assert!(entry.get("uniqueKey").is_none());
        ok!(f
            .auth(
                "revokeSession",
                &credential,
                json!({ "sessionId": stepped["session"]["id"] })
            )
            .await);
        refused(
            &fails!(f.authenticate(&stepped_token).await),
            "UNAUTHENTICATED",
            None,
            None,
        );
        refused(
            &fails!(f.authenticate(&bearer(str_of(&assumed, "token"))).await),
            "UNAUTHENTICATED",
            None,
            Some("Role credential revoked"),
        );
    });
}

#[test]
fn answers_over_http_with_the_token_in_the_body_and_never_sets_a_cookie() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let authorization = format!("Bearer {}", token_of(&f.owner_credential));
        let bearer_answer = f
            .post(
                "sts/getSessionToken",
                json!({ "sessionName": "http-cli" }),
                &[("authorization", &authorization)],
            )
            .await;
        reached!(bearer_answer);
        assert_eq!(bearer_answer.status(), 200);
        assert!(header(&bearer_answer, "set-cookie").is_none());
        let body = response_json(&bearer_answer);
        let token = str_of(&body["data"], "token").to_owned();
        assert!(token.starts_with("biam_sts_"));
        matches(
            &body["data"]["session"],
            &json!({ "kind": "session-token", "sessionName": "http-cli" }),
        );
        assert_eq!(
            ok!(f.authenticate(&bearer(&token)).await)["kind"],
            "session-token"
        );

        let cookie = format!(
            "better-iam.session={}",
            better_iam_server::http::encode_uri_component(token_of(&f.owner_credential))
        );
        let cookie_answer = f
            .post(
                "sts/getSessionToken",
                json!({}),
                &[("cookie", &cookie), ("origin", ORIGIN)],
            )
            .await;
        reached!(cookie_answer);
        assert_eq!(cookie_answer.status(), 200);
        assert!(header(&cookie_answer, "set-cookie").is_none());
        assert!(str_of(&response_json(&cookie_answer)["data"], "token").starts_with("biam_sts_"));

        let chained_authorization = format!("Bearer {token}");
        let chained = f
            .post(
                "sts/getSessionToken",
                json!({}),
                &[("authorization", &chained_authorization)],
            )
            .await;
        assert_eq!(chained.status(), 400);
        assert_eq!(
            response_json(&chained)["error"]["code"],
            "CREDENTIAL_CHAINING_DISABLED"
        );
    });
}

/// Port-only regression: `confirmMfa` called in-process reaches the service in both of its spellings, the request
/// credential with `{ code }` and `{ credential, code }` as one input, instead of bouncing between the public and the
/// authenticated dispatch until the stack overflows.
#[test]
fn confirm_mfa_reaches_the_service_in_process_with_a_credential_or_as_one_input() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        ok!(f.member("alice").await);
        let login = ok!(f.sign_in("alice").await);
        let credential = bearer(str_of(&login, "token"));
        // Nothing enrolled yet: both spellings are refused by the service itself.
        let error = fails!(
            f.auth("confirmMfa", &credential, json!({ "code": "123456" }))
                .await
        );
        refused(&error, "INVALID_CHALLENGE", Some(401), None);
        let error = fails!(
            f.iam
                .api
                .auth
                .call(
                    "confirmMfa",
                    better_iam_server::http::AuthArgs::Public(json!({
                        "credential": { "token": str_of(&login, "token") },
                        "code": "123456",
                    })),
                )
                .await
        );
        refused(&error, "INVALID_CHALLENGE", Some(401), None);
        // The credential spelling enrolls once a code is valid.
        let (_, token) = ok!(enroll_totp(&f, str_of(&login, "token")).await);
        assert_eq!(f.row_of(&token).await["mfa"], true);
    });
}
