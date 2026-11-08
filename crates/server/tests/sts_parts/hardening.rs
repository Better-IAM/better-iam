//! Port of the temporary-credential parts of `tests/sts-hardening.test.ts`: the constant-time hash comparison helper,
//! session tokens recording the client of in-process `{ headers }` callers, dead tokens neither holding places under
//! the per-identity cap nor staying stored, and `bindSessionsToIp` applying to session tokens. (Its trust-flag,
//! certification and package-request blocks test the trust, roles, certifications and packages modules, which other
//! units port.)

use std::sync::Arc;

use better_iam_core::{AttributeType, IamResult, PermissionsConfig, SessionClientInfo};
use better_iam_server::options::{
    AuthorizationRequest, BetterIamOptions, HttpOptions, ResourceTarget,
};
use better_iam_server::utils::{hash, same_hash, same_hash_value};
use serde_json::{Value, json};

use crate::support::*;

const HOME: &str = "203.0.113.7";
const AWAY: &str = "198.51.100.9";

/// Acme with a `department` attribute, a controllable per-request IP (`x-test-ip`), and an optional token cap.
fn hardening(max_session_tokens_per_identity: Option<f64>) -> impl FnOnce(&mut BetterIamOptions) {
    move |options: &mut BetterIamOptions| {
        let mut attributes = indexmap::IndexMap::new();
        attributes.insert("department".to_owned(), AttributeType::String);
        options.permissions = Some(PermissionsConfig {
            actions: Some(vec!["documents:read".into(), "documents:write".into()]),
            identity_attributes: Some(attributes),
            ..PermissionsConfig::default()
        });
        options.http = Some(HttpOptions {
            client_info: Some(Arc::new(|request| {
                Some(SessionClientInfo {
                    ip: request
                        .headers
                        .get("x-test-ip")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned),
                    user_agent: Some("hardening-test".into()),
                    ..SessionClientInfo::default()
                })
            })),
            ..HttpOptions::default()
        });
        if let Some(cap) = max_session_tokens_per_identity {
            options.sts = Some(sts(json!({ "maxSessionTokensPerIdentity": cap })));
        }
    }
}

fn client(ip: &str) -> Option<SessionClientInfo> {
    Some(SessionClientInfo {
        ip: Some(ip.to_owned()),
        user_agent: Some("hardening-test".into()),
        ..SessionClientInfo::default()
    })
}

#[test]
fn same_hash_compares_in_constant_time_and_never_matches_malformed_or_differently_sized_values() {
    let a = hash("one");
    assert!(same_hash(&a, &hash("one")));
    assert!(!same_hash(&a, &hash("two")));
    assert!(!same_hash(&a, &a[1..]));
    assert!(same_hash("", ""));
    // Equal string lengths but different byte lengths are refused rather than thrown.
    assert!(!same_hash("é", "e"));
    assert!(!same_hash_value(None, Some(&json!(a))));
    assert!(!same_hash_value(Some(&json!(a)), Some(&json!(42))));
}

#[test]
fn records_the_issuing_client_of_an_in_process_headers_caller() {
    run(|| async {
        let f = ok!(organization_fixture(hardening(None)).await);
        let authorization = format!("Bearer {}", token_of(&f.owner_credential));
        let via_headers = ok!(f
            .get_session_token(
                &headers(&[("authorization", &authorization), ("x-test-ip", AWAY)]),
                json!({})
            )
            .await);
        let via_headers = str_of(&via_headers, "token").to_owned();
        same(
            &f.row_of(&via_headers).await["client"],
            &json!({ "ip": AWAY, "userAgent": "hardening-test" }),
        );
        // A token credential with no client scope records none; a scope set by the caller is never replaced.
        let bare = ok!(f.get_session_token(&f.owner_credential, json!({})).await);
        let bare = str_of(&bare, "token").to_owned();
        assert!(f.row_of(&bare).await.get("client").is_none());
        let scoped = ok!(f
            .iam
            .auth
            .with_client(
                client(HOME),
                f.get_session_token(
                    &headers(&[("authorization", &authorization), ("x-test-ip", AWAY)]),
                    json!({}),
                ),
            )
            .await);
        let scoped = str_of(&scoped, "token").to_owned();
        assert_eq!(f.row_of(&scoped).await["client"]["ip"], HOME);
        // The recorded address is judged against the tenant's allowlist on every use.
        ok!(api!(
            f.iam.api.tenants,
            set_auth_policy,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "authPolicy": { "allowedIpRanges": ["203.0.113.0/24"] } })
        ));
        refused(
            &fails!(f.authenticate(&bearer(&via_headers)).await),
            "IP_NOT_ALLOWED",
            None,
            None,
        );
        assert_eq!(
            ok!(f.authenticate(&bearer(&scoped)).await)["kind"],
            "session-token"
        );
        assert_eq!(
            ok!(f.authenticate(&bearer(&bare)).await)["kind"],
            "session-token"
        );
    });
}

#[test]
fn does_not_count_tokens_whose_source_session_is_gone_against_the_cap() {
    run(|| async {
        let f = ok!(organization_fixture(hardening(Some(2.0))).await);
        let first = ok!(f.owner_sign_in().await);
        ok!(f.get_session_token(&first, json!({})).await);
        ok!(f
            .get_session_token(&first, json!({ "durationSeconds": 900 }))
            .await);
        let second = ok!(f.owner_sign_in().await);
        refused(
            &fails!(f.get_session_token(&second, json!({})).await),
            "LIMIT_EXCEEDED",
            Some(409),
            Some("This identity holds the maximum number of live session tokens"),
        );
        // Signing out removes the source row; its tokens are dead and no longer hold places.
        ok!(f.auth("signOut", &first, json!({})).await);
        let fresh = ok!(f.get_session_token(&second, json!({})).await);
        assert!(str_of(&fresh, "token").starts_with("biam_sts_"));
        ok!(f.get_session_token(&second, json!({})).await);
        // Live tokens still count.
        refused(
            &fails!(f.get_session_token(&second, json!({})).await),
            "LIMIT_EXCEEDED",
            None,
            None,
        );
    });
}

async fn stored_tokens(f: &Fixture) -> usize {
    f.find(
        "sessions",
        json!({ "identityId": f.owner_id, "kind": "session-token" }),
    )
    .await
    .len()
}

#[test]
fn deletes_dead_tokens_at_issuance_so_storage_never_grows_past_the_cap() {
    run(|| async {
        let cap = 3;
        let f = ok!(organization_fixture(|options| {
            options.sts = Some(sts(json!({ "maxSessionTokensPerIdentity": cap })))
        })
        .await);
        for round in 0..3 {
            let source = ok!(f.owner_sign_in().await);
            for _ in 0..cap {
                ok!(f
                    .get_session_token(&source, json!({ "durationSeconds": 43200 }))
                    .await);
            }
            refused(
                &fails!(f.get_session_token(&source, json!({})).await),
                "LIMIT_EXCEEDED",
                None,
                None,
            );
            assert_eq!(stored_tokens(&f).await, cap, "round {round}");
            ok!(f.auth("signOut", &source, json!({})).await);
        }
        // The next issuance removes the last round's dead rows as well.
        ok!(f
            .get_session_token(&ok!(f.owner_sign_in().await), json!({}))
            .await);
        assert_eq!(stored_tokens(&f).await, 1);
    });
}

#[test]
fn frees_and_deletes_the_places_of_tokens_whose_source_session_idled_out() {
    run(|| async {
        let f = ok!(organization_fixture(|options| {
            options.sts = Some(sts(json!({ "maxSessionTokensPerIdentity": 2 })));
            if let Some(authentication) = options.authentication.as_mut() {
                authentication.session_idle_timeout_ms = Some(60.0 * 60_000.0);
            }
        })
        .await);
        let idle = ok!(f.owner_sign_in().await);
        ok!(f
            .get_session_token(&idle, json!({ "durationSeconds": 43200 }))
            .await);
        ok!(f
            .get_session_token(&idle, json!({ "durationSeconds": 43200 }))
            .await);
        f.advance(50.0 * 60_000.0);
        let active = ok!(f.owner_sign_in().await);
        // Fifty idle minutes: the source still works, so its tokens hold their places.
        refused(
            &fails!(f.get_session_token(&active, json!({})).await),
            "LIMIT_EXCEEDED",
            None,
            None,
        );
        f.advance(20.0 * 60_000.0);
        // Seventy: the source idled out and can never be used again, nor can its unexpired tokens, although its row
        // is still stored.
        let idle_row = f.row_of(token_of(&idle)).await;
        let fresh = ok!(f.get_session_token(&active, json!({})).await);
        assert!(
            f.get("sessions", str_of(&value(&idle_row), "id"))
                .await
                .is_some()
        );
        let error = fails!(f.auth("getSession", &idle, json!({})).await);
        assert_eq!(error.status, 401);
        assert!(str_of(&fresh, "token").starts_with("biam_sts_"));
        assert_eq!(stored_tokens(&f).await, 1);
    });
}

#[test]
fn refuses_a_bound_token_from_another_address_like_a_user_session() {
    run(|| async {
        let f = ok!(organization_fixture(hardening(None)).await);
        let token = ok!(f
            .iam
            .auth
            .with_client(
                client(HOME),
                f.get_session_token(&f.owner_credential, json!({}))
            )
            .await);
        let token = str_of(&token, "token").to_owned();
        let bare = ok!(f.get_session_token(&f.owner_credential, json!({})).await);
        let bare = str_of(&bare, "token").to_owned();
        let use_from = |ip: Option<&'static str>, value: String| {
            let f = &f;
            async move {
                let credential = bearer(&value);
                match ip {
                    Some(ip) => {
                        f.iam
                            .auth
                            .with_client(client(ip), f.authenticate(&credential))
                            .await
                    }
                    None => f.authenticate(&credential).await,
                }
            }
        };
        // Off by default: the token roams.
        assert_eq!(
            ok!(use_from(Some(AWAY), token.clone()).await)["kind"],
            "session-token"
        );
        ok!(api!(
            f.iam.api.tenants,
            set_auth_policy,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "authPolicy": { "bindSessionsToIp": true } })
        ));
        assert_eq!(
            ok!(use_from(Some(HOME), token.clone()).await)["kind"],
            "session-token"
        );
        refused(
            &fails!(use_from(Some(AWAY), token.clone()).await),
            "SESSION_NETWORK_MISMATCH",
            Some(401),
            Some("This session can only be used from the network it was signed in from"),
        );
        // In-process callers passing request headers are judged by the address those headers carry.
        let authorization = format!("Bearer {token}");
        refused(
            &fails!(
                f.authenticate(&headers(&[
                    ("authorization", &authorization),
                    ("x-test-ip", AWAY)
                ]))
                .await
            ),
            "SESSION_NETWORK_MISMATCH",
            None,
            None,
        );
        // Unknown addresses on either side are not judged.
        assert_eq!(
            ok!(use_from(None, token.clone()).await)["kind"],
            "session-token"
        );
        assert_eq!(
            ok!(use_from(Some(AWAY), bare.clone()).await)["kind"],
            "session-token"
        );
        // Every decision path authenticates the same way.
        let decision: IamResult<Value> = f
            .iam
            .auth
            .with_client(client(AWAY), async {
                f.iam
                    .authorize(&AuthorizationRequest {
                        credential: bearer(&token),
                        tenant_id: f.tenant_id.clone(),
                        action: "documents:read".into(),
                        resource: ResourceTarget {
                            kind: "document".into(),
                            id: "hardening-document".into(),
                        },
                    })
                    .await
                    .map(|decision| json!(decision.allowed))
            })
            .await;
        refused(&fails!(decision), "SESSION_NETWORK_MISMATCH", None, None);
    });
}
