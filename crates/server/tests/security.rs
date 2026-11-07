//! Incident response: the `security` API group (network blocks). Ported from tests/network-blocks.test.ts, plus the
//! root-tenant rules of tests/security-identities.test.ts ("keeps the root tenant's sign-in policy, sessions and
//! network blocks for root").

mod organization_fixture;

use better_iam_auth::SignInResult;
use better_iam_core::{CredentialInput, Filter, IamResult, SessionClientInfo};
use organization_fixture::{Org, assert_matches, bearer, body, fails, ok, organization, run};
use serde_json::{Value, json};

const HOUR: f64 = 3_600_000.0;

fn client(ip: &str) -> Option<SessionClientInfo> {
    Some(serde_json::from_value(json!({ "ip": ip, "userAgent": "test" })).unwrap())
}

/// `auth.signIn` of a member with the fixture's password, from `ip`.
async fn sign_in_from(f: &Org, ip: &str, name: &str) -> IamResult<SignInResult> {
    let input = json!({
        "tenantId": f.tenant_id,
        "email": format!("{name}@acme.test"),
        "password": format!("a strong {name} password"),
    });
    f.iam
        .auth
        .with_client(client(ip), f.iam.auth.sign_in(&input))
        .await
}

fn token(result: SignInResult) -> String {
    match result {
        SignInResult::Session(session) => session.token,
        SignInResult::MfaRequired(_) => panic!("unexpected MFA"),
    }
}

async fn block(f: &Org, credential: &CredentialInput, input: Value) -> IamResult<Value> {
    f.iam
        .api
        .security
        .block_network(credential, body(input))
        .await?
        .into_value()
}

async fn list(f: &Org, credential: &CredentialInput, tenant_id: &str) -> IamResult<Value> {
    f.iam
        .api
        .security
        .list_blocks(credential, body(json!({ "tenantId": tenant_id })))
        .await?
        .into_value()
}

#[test]
fn lets_root_block_a_network_platform_wide_until_lifted_or_lapsed() {
    run(|| async {
        let f = organization(with_email).await;
        let alice = f.member("alice").await;
        let early = token(sign_in_from(&f, "198.51.100.9", "alice").await.unwrap());
        let root_tenant = f.root_tenant.clone();
        let created = block(
            &f,
            &f.root_credential,
            json!({
                "tenantId": root_tenant,
                "network": "198.51.100.0/24",
                "reason": "credential stuffing",
                "durationMs": 3_600_000,
                "platform": true,
            }),
        )
        .await
        .unwrap();
        assert_matches(
            &created,
            json!({
                "tenantId": root_tenant,
                "network": "198.51.100.0/24",
                "reason": "credential stuffing",
                "createdBy": f.root_id,
                "platform": true,
                "expiresAt": f.now() + HOUR,
                "active": true,
            }),
        );
        let keys: Vec<&String> = created.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "id",
                "tenantId",
                "network",
                "reason",
                "createdAt",
                "createdBy",
                "expiresAt",
                "platform",
                "active"
            ]
        );
        let block_id = created["id"].as_str().unwrap().to_owned();
        // Refused before any credential or counter is examined, in every tenant and flow.
        let error = sign_in_from(&f, "198.51.100.9", "alice").await.unwrap_err();
        assert_eq!(error.code, "IP_BLOCKED");
        assert_eq!(error.status, 403);
        let reset = f
            .iam
            .auth
            .with_client(
                client("198.51.100.200"),
                f.iam.auth.request_password_reset(
                    &json!({ "tenantId": f.tenant_id, "email": "alice@acme.test" }),
                ),
            )
            .await;
        assert_eq!(reset.unwrap_err().code, "IP_BLOCKED");
        let root_sign_in = f
            .iam
            .auth
            .with_client(
                client("198.51.100.200"),
                f.iam.auth.sign_in(&json!({
                    "tenantId": root_tenant,
                    "email": "root@example.test",
                    "password": "a strong root test password",
                })),
            )
            .await;
        assert_eq!(root_sign_in.unwrap_err().code, "IP_BLOCKED");
        let failures = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", f.tenant_id.clone())
                    .eq("action", "auth:signin:fail")
                    .eq("actorId", alice.clone()),
            )
            .await;
        assert!(failures.is_empty());
        // The session established from that network before the block stops working; others are untouched.
        assert_eq!(
            f.iam
                .auth
                .get_session(&bearer(&early))
                .await
                .unwrap_err()
                .code,
            "IP_BLOCKED"
        );
        sign_in_from(&f, "203.0.113.7", "alice").await.unwrap();
        // Root sees the block on the root tenant; an organization sees only its own.
        let blocks = list(&f, &f.root_credential, &root_tenant).await.unwrap();
        assert_eq!(blocks.as_array().unwrap().len(), 1);
        assert_matches(
            &blocks[0],
            json!({ "id": block_id, "active": true, "reason": "credential stuffing" }),
        );
        assert_eq!(
            list(&f, &f.owner_credential, &f.tenant_id).await.unwrap(),
            json!([])
        );
        // Lifting it restores the network at once.
        assert_eq!(
            ok(f.iam
                .api
                .security
                .unblock_network(
                    &f.root_credential,
                    body(json!({ "tenantId": root_tenant, "blockId": block_id })),
                )
                .await),
            json!({ "success": true })
        );
        sign_in_from(&f, "198.51.100.9", "alice").await.unwrap();
        // A timed block lapses by itself.
        let short = block(
            &f,
            &f.root_credential,
            json!({
                "tenantId": root_tenant,
                "network": "198.51.100.9",
                "reason": "one minute",
                "durationMs": 60_000,
                "platform": true,
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            sign_in_from(&f, "198.51.100.9", "alice")
                .await
                .unwrap_err()
                .code,
            "IP_BLOCKED"
        );
        f.advance(61_000.0);
        sign_in_from(&f, "198.51.100.9", "alice").await.unwrap();
        let blocks = list(&f, &f.root_credential, &root_tenant).await.unwrap();
        assert_eq!(blocks.as_array().unwrap().len(), 1);
        assert_matches(&blocks[0], json!({ "id": short["id"], "active": false }));
        // Everything was audited with the network named.
        let events: Vec<(Value, Value)> = f
            .find("audit", Filter::new().eq("tenantId", root_tenant.clone()))
            .await
            .into_iter()
            .filter(|event| {
                event["action"]
                    .as_str()
                    .is_some_and(|action| action.starts_with("security:network-"))
            })
            .map(|event| {
                (
                    event["action"].clone(),
                    event["metadata"]["network"].clone(),
                )
            })
            .collect();
        for expected in [
            (json!("security:network-block"), json!("198.51.100.0/24")),
            (json!("security:network-unblock"), json!("198.51.100.0/24")),
            (json!("security:network-block"), json!("198.51.100.9")),
        ] {
            assert!(events.contains(&expected), "{expected:?} in {events:?}");
        }
        let first = f
            .find("audit", Filter::new().eq("resourceId", block_id.clone()))
            .await;
        let blocked = first
            .iter()
            .find(|event| event["action"] == json!("security:network-block"))
            .unwrap();
        assert_eq!(
            blocked["metadata"],
            json!({
                "network": "198.51.100.0/24",
                "reason": "credential stuffing",
                "platform": true,
                "expiresAt": created["expiresAt"],
                "renewed": false,
            })
        );
        let lifted = first
            .iter()
            .find(|event| event["action"] == json!("security:network-unblock"))
            .unwrap();
        assert_eq!(
            lifted["metadata"],
            json!({ "network": "198.51.100.0/24", "platform": true })
        );
    });
}

#[test]
fn lets_an_organization_block_networks_for_itself_only_and_validates_the_request() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let owner = f
            .iam
            .auth
            .with_client(client("10.0.0.5"), f.session(&f.owner_id, false))
            .await;
        let created = block(
            &f,
            &owner,
            json!({ "tenantId": f.tenant_id, "network": "192.0.2.0/24", "reason": "scanner" }),
        )
        .await
        .unwrap();
        assert_matches(
            &created,
            json!({ "network": "192.0.2.0/24", "active": true }),
        );
        assert!(created.get("platform").is_none());
        assert!(created.get("expiresAt").is_none());
        assert_eq!(
            sign_in_from(&f, "192.0.2.5", "alice")
                .await
                .unwrap_err()
                .code,
            "IP_BLOCKED"
        );
        // The block is the organization's: the root tenant still accepts that network.
        let root_attempt = f
            .iam
            .auth
            .with_client(
                client("192.0.2.5"),
                f.iam.auth.sign_in(&json!({
                    "tenantId": f.root_tenant,
                    "email": "root@example.test",
                    "password": "a strong root test password",
                })),
            )
            .await
            .unwrap();
        assert!(matches!(root_attempt, SignInResult::MfaRequired(_)));
        // Renewing the same network updates the record instead of adding one.
        let renewed = block(
            &f,
            &owner,
            json!({
                "tenantId": f.tenant_id,
                "network": " 192.0.2.0/24 ",
                "reason": "scanner, again",
                "durationMs": 120_000,
            }),
        )
        .await
        .unwrap();
        assert_eq!(renewed["id"], created["id"]);
        assert_eq!(renewed["expiresAt"].as_f64(), Some(f.now() + 120_000.0));
        assert_eq!(
            list(&f, &owner, &f.tenant_id)
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let renewal = f
            .find(
                "audit",
                Filter::new()
                    .eq("action", "security:network-block")
                    .eq("tenantId", f.tenant_id.clone()),
            )
            .await;
        assert_eq!(renewal.len(), 2);
        assert!(
            renewal
                .iter()
                .any(|event| event["metadata"]["renewed"] == json!(true))
        );
        // Validation: platform blocks are root's, networks must parse, and the caller cannot block themselves.
        let error = block(
            &f,
            &owner,
            json!({ "tenantId": f.tenant_id, "network": "203.0.113.0/24", "reason": "x", "platform": true }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "ACCESS_DENIED");
        assert_eq!(
            error.message,
            "Platform-wide blocks are set by root administrators on the root tenant"
        );
        let checks = [
            (
                json!({ "network": "not-a-network", "reason": "x" }),
                "network must be an IPv4/IPv6 address or CIDR block",
            ),
            (
                json!({ "network": "10.0.0.0/8", "reason": "would lock me out" }),
                "That network includes your own address",
            ),
            (
                json!({ "network": "203.0.113.1", "reason": "x", "durationMs": 1_000 }),
                "Invalid durationMs",
            ),
            (
                json!({ "network": "203.0.113.1", "reason": "   " }),
                "Invalid reason",
            ),
            (json!({ "reason": "x" }), "Invalid network"),
        ];
        for (input, message) in checks {
            let mut input = input;
            input["tenantId"] = json!(f.tenant_id);
            let error = block(&f, &owner, input.clone()).await.unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "{input}");
            assert!(
                error.message.starts_with(message),
                "{input}: {}",
                error.message
            );
        }
        // The address the request comes from counts too.
        let error = f
            .iam
            .auth
            .with_client(
                client("203.0.113.50"),
                block(
                    &f,
                    &owner,
                    json!({ "tenantId": f.tenant_id, "network": "203.0.113.0/24", "reason": "x" }),
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(error.message, "That network includes your own address");
        // A member without the permission can neither read nor manage blocks.
        let alice_token = token(sign_in_from(&f, "203.0.113.9", "alice").await.unwrap());
        assert_eq!(
            list(&f, &bearer(&alice_token), &f.tenant_id)
                .await
                .unwrap_err()
                .code,
            "ACCESS_DENIED"
        );
        let _ = alice;
        // Unblocking an unknown block is NOT_FOUND; the owner lifts their own.
        let error = fails(
            f.iam
                .api
                .security
                .unblock_network(
                    &owner,
                    body(json!({ "tenantId": f.tenant_id, "blockId": "missing" })),
                )
                .await,
        );
        assert_eq!(error.code, "NOT_FOUND");
        ok(f.iam
            .api
            .security
            .unblock_network(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "blockId": created["id"] })),
            )
            .await);
        sign_in_from(&f, "192.0.2.5", "alice").await.unwrap();
    });
}

#[test]
fn keeps_the_root_tenants_network_blocks_for_root() {
    run(|| async {
        let f = organization(|_| {}).await;
        // A platform operator with security permissions on the root tenant, who is not a root administrator.
        let ops = f.member_in(&f.root_tenant.clone(), "ops").await;
        let authority = f
            .find(
                "grantAuthorities",
                Filter::new().eq("identityId", f.root_id.clone()),
            )
            .await[0]["id"]
            .clone();
        let role_id = better_iam_server::utils::id();
        f.insert(
            "roles",
            json!({
                "id": role_id,
                "tenantId": f.root_tenant,
                "name": "Platform operator",
                "policyIds": [],
                "document": { "version": 1, "statements": [{ "effect": "allow", "actions": ["iam:security:manage", "iam:security:read"], "resources": ["*"] }] },
                "protected": false,
                "authorityId": authority,
            }),
        )
        .await;
        f.insert(
            "bindings",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": f.root_tenant,
                "subjectType": "identity",
                "subjectId": ops,
                "roleId": role_id,
                "authorityId": authority,
            }),
        )
        .await;
        let operator = f.session(&ops, true).await;
        let error = block(
            &f,
            &operator,
            json!({ "tenantId": f.root_tenant, "network": "192.0.2.0/24", "reason": "root admins sit here" }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "ACCESS_DENIED");
        assert_eq!(
            error.message,
            "Blocks on the root tenant are set by root administrators"
        );
        // The operator still reads them.
        assert_eq!(
            list(&f, &operator, &f.root_tenant).await.unwrap(),
            json!([])
        );
        let created = block(
            &f,
            &f.root_credential,
            json!({ "tenantId": f.root_tenant, "network": "192.0.2.0/24", "reason": "scanner" }),
        )
        .await
        .unwrap();
        let error = fails(
            f.iam
                .api
                .security
                .unblock_network(
                    &operator,
                    body(json!({ "tenantId": f.root_tenant, "blockId": created["id"] })),
                )
                .await,
        );
        assert_eq!(
            error.message,
            "Blocks on the root tenant are set by root administrators"
        );
        // A refused change was audited as a deny and wrote nothing.
        assert_eq!(
            list(&f, &f.root_credential, &f.root_tenant)
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // Root administrators need recent authentication.
        f.advance(2.0 * HOUR);
        let error = block(
            &f,
            &f.root_credential,
            json!({ "tenantId": f.root_tenant, "network": "198.51.100.0/24", "reason": "late" }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "RECENT_AUTH_REQUIRED");
    });
}

/// An email channel (discarding messages), so the password reset flow is enabled as in the TypeScript fixture.
fn with_email(options: &mut better_iam_server::options::BetterIamOptions) {
    if let Some(authentication) = options.authentication.as_mut() {
        authentication.send_email = Some(better_iam_auth::delivery_fn(|_message| async { Ok(()) }));
    }
}
