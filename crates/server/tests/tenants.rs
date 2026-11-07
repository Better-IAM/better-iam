//! The `tenants` API group (api/tenants.ts). Ported from tests/tenant-defaults.test.ts and the tenant cases of
//! tests/server.test.ts, tests/limits.test.ts, tests/tenant-auth-policy.test.ts, tests/access-policy.test.ts and
//! tests/security-identities.test.ts. Records the TypeScript tests create through API groups other units port
//! (members, roles) are written to the store directly; steps that reach another unit's stub (owner invitations are
//! accepted in flows.ts, deletions check privacy.ts legal holds, moves check clearances.ts) end the test early with
//! a note until that unit lands.

mod tenants_support;

use better_iam_core::TenantLimits;
use better_iam_server::better_iam;
use better_iam_server::options::TenantDefaults;
use serde_json::{Value, json};
use tenants_support::*;

#[test]
fn rejects_invalid_defaults_at_construction() {
    let inbox = Inbox::default();
    let mut bad_limits = options(true, &inbox);
    let mut limits = TenantLimits::default();
    limits.extra.insert("seats".into(), json!(1));
    bad_limits.tenant_defaults = Some(TenantDefaults {
        limits: Some(limits),
        auth_policy: None,
    });
    let error = better_iam(bad_limits).err().expect("invalid limits");
    assert!(
        error.message.contains("tenantDefaults"),
        "{}",
        error.message
    );
    let mut bad_policy = options(true, &inbox);
    bad_policy.tenant_defaults = Some(TenantDefaults {
        limits: None,
        auth_policy: Some(better_iam_core::TenantAuthPolicy {
            min_password_length: Some(4.0),
            ..Default::default()
        }),
    });
    let error = better_iam(bad_policy).err().expect("invalid policy");
    assert!(
        error.message.contains("tenantDefaults"),
        "{}",
        error.message
    );
}

#[test]
fn applies_defaults_to_new_organizations_and_resends_invitations() {
    run(|| async {
        let f = fixture(true, |options| {
            options.tenant_defaults = Some(TenantDefaults {
                limits: Some(TenantLimits {
                    identities: Some(2.0),
                    ..Default::default()
                }),
                auth_policy: Some(better_iam_core::TenantAuthPolicy {
                    min_password_length: Some(16.0),
                    ..Default::default()
                }),
            });
        })
        .await;
        let created = json(
            f.iam
                .api
                .tenants
                .create(
                    &f.root,
                    body(json!({
                        "parentId": f.root_tenant,
                        "name": "Acme",
                        "type": "organization",
                        "ownerEmail": "Owner@Acme.test",
                    })),
                )
                .await,
        )
        .unwrap();
        let tenant_id = created["tenant"]["id"].as_str().unwrap().to_owned();
        let invitation_id = created["invitationId"].as_str().unwrap().to_owned();
        assert_eq!(created["tenant"]["limits"], json!({ "identities": 2 }));
        assert_eq!(
            created["tenant"]["authPolicy"],
            json!({ "minPasswordLength": 16 })
        );
        assert_eq!(created["tenant"]["status"], "pending");
        assert_eq!(created["tenant"]["tenantId"], tenant_id.as_str());
        assert_eq!(created["ownerEmail"], "owner@acme.test");
        f.iam.auth.dispatch_outbox(None).await.unwrap();
        let first = mails(&f, "owner-invitation");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].to, "owner@acme.test");
        assert_eq!(first[0].payload["tenantId"], tenant_id.as_str());
        assert_eq!(first[0].payload["tenantName"], "Acme");
        // The invitation's grant authority hangs under the root's, and waits for its owner.
        let authority = find(&f.iam, "grantAuthorities", json!({ "tenantId": tenant_id }))
            .await
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(authority["identityId"], "pending");
        assert!(authority["parentAuthorityId"].is_string());
        // Re-sending rotates the token: the old link stops working, the new one is delivered.
        let resent = json(
            f.iam
                .api
                .tenants
                .resend_invitation(
                    &f.root,
                    body(json!({ "tenantId": tenant_id, "invitationId": invitation_id })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(resent["email"], "owner@acme.test");
        assert_eq!(resent["invitationId"], invitation_id.as_str());
        assert!(resent["expiresAt"].is_number());
        f.iam.auth.dispatch_outbox(None).await.unwrap();
        let owners = mails(&f, "owner-invitation");
        assert_eq!(owners.len(), 2);
        assert_ne!(owners[1].payload["token"], owners[0].payload["token"]);
        // Listing never shows token hashes.
        let listed = json(
            f.iam
                .api
                .tenants
                .list_invitations(&f.root, body(json!({ "tenantId": tenant_id })))
                .await,
        )
        .unwrap();
        let listed = listed.as_array().unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].get("tokenHash").is_none());
        assert!(listed[0].get("uniqueKey").is_none());
        assert_eq!(listed[0]["email"], "owner@acme.test");
        let accepted = f
            .iam
            .api
            .tenants
            .accept_invitation(body(json!({
                "tenantId": tenant_id,
                "token": owners[0].payload["token"],
                "name": "Owner",
                "password": "a strong tenant owner password",
            })))
            .await;
        let error = or_skip!(json(accepted)).unwrap_err();
        assert_eq!(error.code, "INVITATION_INVALID");
        // The default policy applies to the owner's first password.
        let weak = f
            .iam
            .api
            .tenants
            .accept_invitation(body(json!({
                "tenantId": tenant_id,
                "token": owners[1].payload["token"],
                "name": "Owner",
                "password": "twelve chars!",
            })))
            .await;
        assert_eq!(failure(json(weak)).code, "WEAK_PASSWORD");
        let owner = json(
            f.iam
                .api
                .tenants
                .accept_invitation(body(json!({
                    "tenantId": tenant_id,
                    "token": owners[1].payload["token"],
                    "name": "Owner",
                    "password": "a strong tenant owner password",
                })))
                .await,
        )
        .unwrap();
        assert!(owner["token"].is_string());
        let again = f
            .iam
            .api
            .tenants
            .resend_invitation(
                &f.root,
                body(json!({ "tenantId": tenant_id, "invitationId": invitation_id })),
            )
            .await;
        assert_eq!(failure(json(again)).code, "CONFLICT");
    });
}

#[test]
fn revoked_invitations_cannot_be_resent_or_revoked_again() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let created = json(
            f.iam
                .api
                .tenants
                .create(
                    &f.root,
                    body(json!({
                        "parentId": f.root_tenant,
                        "name": "Initech",
                        "type": "organization",
                        "ownerEmail": "owner@initech.test",
                    })),
                )
                .await,
        )
        .unwrap();
        let tenant_id = created["tenant"]["id"].as_str().unwrap();
        let input = json!({ "tenantId": tenant_id, "invitationId": created["invitationId"] });
        let revoked = json(
            f.iam
                .api
                .tenants
                .revoke_invitation(&f.root, body(input.clone()))
                .await,
        )
        .unwrap();
        assert_eq!(revoked["revoked"], true);
        assert!(revoked.get("tokenHash").is_none());
        assert!(revoked.get("uniqueKey").is_none());
        for result in [
            json(
                f.iam
                    .api
                    .tenants
                    .revoke_invitation(&f.root, body(input.clone()))
                    .await,
            ),
            json(
                f.iam
                    .api
                    .tenants
                    .resend_invitation(&f.root, body(input.clone()))
                    .await,
            ),
        ] {
            let error = failure(result);
            assert_eq!(error.code, "CONFLICT");
            assert_eq!(error.status, 409);
            assert_eq!(error.message, "Invitation is already consumed or revoked");
        }
        // An invitation of another tenant is not found through this one.
        let missing = f
            .iam
            .api
            .tenants
            .revoke_invitation(
                &f.root,
                body(json!({ "tenantId": f.root_tenant, "invitationId": created["invitationId"] })),
            )
            .await;
        assert_eq!(failure(json(missing)).code, "NOT_FOUND");
    });
}

#[test]
fn create_validates_its_input_and_who_may_skip_the_invitation() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let base = json!({
            "parentId": f.root_tenant,
            "name": "Acme",
            "type": "organization",
            "ownerEmail": "owner@acme.test",
        });
        let with = |extra: Value| {
            let mut input = base.clone();
            for (key, value) in extra.as_object().unwrap() {
                input[key] = value.clone();
            }
            input
        };
        let cases = [
            (
                with(json!({ "activate": "yes" })),
                "INVALID_INPUT",
                "activate must be a boolean",
            ),
            (
                with(json!({ "ownerEmailVerified": 1 })),
                "INVALID_INPUT",
                "ownerEmailVerified must be a boolean",
            ),
            (
                with(json!({ "ownerName": "Olive" })),
                "INVALID_INPUT",
                "ownerName and ownerEmailVerified need activate: true",
            ),
            (
                with(json!({ "ownerEmail": "not an email" })),
                "INVALID_INPUT",
                "Invalid email",
            ),
            (with(json!({ "name": "" })), "INVALID_INPUT", "Invalid name"),
            (
                with(json!({ "type": "project" })),
                "INVALID_HIERARCHY",
                "Child type is not permitted",
            ),
            (
                with(json!({ "slug": "-bad-" })),
                "INVALID_INPUT",
                "Slug must use 1-63 lowercase letters, digits, or hyphens",
            ),
        ];
        for (input, code, message) in cases {
            let error = failure(json(f.iam.api.tenants.create(&f.root, body(input)).await));
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                (code, message)
            );
        }
        // Without an email transport, only an activated tenant can be created.
        let quiet = fixture(false, |_| {}).await;
        let error = failure(json(
            quiet
                .iam
                .api
                .tenants
                .create(
                    &quiet.root,
                    body(json!({
                        "parentId": quiet.root_tenant,
                        "name": "Acme",
                        "type": "organization",
                        "ownerEmail": "owner@acme.test",
                    })),
                )
                .await,
        ));
        assert_eq!(error.code, "DELIVERY_REQUIRED");
        // The owner of an organization may create projects, but never skip the invitation.
        let org = organization(&f, "Globex", json!({})).await;
        let org_id = org["tenant"]["id"].as_str().unwrap().to_owned();
        let (_, owner) = member(&f, &org_id, "second-owner@globex.test", true).await;
        let error = failure(json(
            f.iam
                .api
                .tenants
                .create(
                    &owner,
                    body(json!({
                        "parentId": org_id,
                        "name": "Apollo",
                        "type": "project",
                        "ownerEmail": "lead@globex.test",
                        "activate": true,
                    })),
                )
                .await,
        ));
        assert_eq!(error.code, "ACCESS_DENIED");
        assert_eq!(error.status, 403);
        let project = json(
            f.iam
                .api
                .tenants
                .create(
                    &owner,
                    body(json!({
                        "parentId": org_id,
                        "name": "Apollo",
                        "type": "project",
                        "ownerEmail": "lead@globex.test",
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(project["tenant"]["parentId"], org_id.as_str());
        assert_eq!(project["tenant"]["type"], "project");
        // Projects have no children in the default hierarchy.
        let error = failure(json(
            f.iam
                .api
                .tenants
                .create(
                    &f.root,
                    body(json!({
                        "parentId": project["tenant"]["id"],
                        "name": "Deeper",
                        "type": "project",
                        "ownerEmail": "lead@globex.test",
                    })),
                )
                .await,
        ));
        assert_eq!(error.code, "INVALID_HIERARCHY");
    });
}

#[test]
fn root_creates_active_organizations_with_their_owner() {
    run(|| async {
        let f = fixture(false, |_| {}).await;
        let created = organization(
            &f,
            "Acme",
            json!({ "ownerName": "Olive Owner", "ownerEmailVerified": true, "slug": "Acme" }),
        )
        .await;
        let tenant = &created["tenant"];
        let tenant_id = tenant["id"].as_str().unwrap();
        assert_eq!(tenant["status"], "active");
        assert_eq!(tenant["slug"], "acme");
        assert_eq!(created["ownerEmail"], "owner@acme.test");
        let owner = &created["owner"];
        assert_eq!(owner["name"], "Olive Owner");
        assert_eq!(owner["owner"], true);
        assert_eq!(owner["emailVerified"], true);
        assert!(owner.get("passwordHash").is_none());
        // No invitation was sent; the protected Owner role is bound to the owner under the tenant's authority.
        assert!(
            find(&f.iam, "ownerInvitations", json!({ "tenantId": tenant_id }))
                .await
                .is_empty()
        );
        let role = find(
            &f.iam,
            "roles",
            json!({ "tenantId": tenant_id, "uniqueKey": "system:owner" }),
        )
        .await;
        assert_eq!(role.len(), 1);
        let bindings = find(&f.iam, "bindings", json!({ "tenantId": tenant_id })).await;
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0]["subjectId"], owner["id"]);
        let authority = find(&f.iam, "grantAuthorities", json!({ "tenantId": tenant_id })).await;
        assert_eq!(authority[0]["identityId"], owner["id"]);
        let events = find(
            &f.iam,
            "audit",
            json!({ "tenantId": tenant_id, "action": "tenant:activate" }),
        )
        .await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]["metadata"],
            json!({ "ownerId": owner["id"], "invitation": false })
        );
        assert_eq!(events[0]["actorId"], f.root_id.as_str());
        // The alias is taken.
        let error = failure(json(
            f.iam
                .api
                .tenants
                .create(
                    &f.root,
                    body(json!({
                        "parentId": f.root_tenant,
                        "name": "Acme 2",
                        "type": "organization",
                        "ownerEmail": "owner@acme2.test",
                        "activate": true,
                        "slug": "acme",
                    })),
                )
                .await,
        ));
        assert_eq!(error.code, "SLUG_TAKEN");
        assert_eq!(error.status, 409);
    });
}

#[test]
fn aliases_and_sign_in_discovery() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let org = organization(&f, "Acme", json!({ "slug": "acme" })).await;
        let tenant_id = org["tenant"]["id"].as_str().unwrap().to_owned();
        let found = json(
            f.iam
                .api
                .tenants
                .lookup(body(json!({ "slug": "ACME" })))
                .await,
        )
        .unwrap();
        assert_eq!(
            found,
            json!({ "tenantId": tenant_id, "name": "Acme", "type": "organization", "slug": "acme" })
        );
        for input in [
            json!({ "slug": "nobody" }),
            json!({ "host": "acme.example.test" }),
        ] {
            let error = failure(json(f.iam.api.tenants.lookup(body(input)).await));
            assert_eq!(
                (error.code.as_str(), error.status, error.message.as_str()),
                ("NOT_FOUND", 404, "Organization not found")
            );
        }
        let error = failure(json(
            f.iam.api.tenants.lookup(body(json!({ "slug": 5 }))).await,
        ));
        assert_eq!(error.code, "INVALID_INPUT");
        // A pending organization is not discoverable.
        json(
            f.iam
                .api
                .tenants
                .create(
                    &f.root,
                    body(json!({
                        "parentId": f.root_tenant,
                        "name": "Waiting",
                        "type": "organization",
                        "ownerEmail": "owner@waiting.test",
                        "slug": "waiting",
                    })),
                )
                .await,
        )
        .unwrap();
        let error = failure(json(
            f.iam
                .api
                .tenants
                .lookup(body(json!({ "slug": "waiting" })))
                .await,
        ));
        assert_eq!(error.code, "NOT_FOUND");
        // Changing the alias frees the old one; null clears it.
        let renamed = json(
            f.iam
                .api
                .tenants
                .set_slug(
                    &f.root,
                    body(json!({ "tenantId": tenant_id, "slug": "acme-corp" })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(renamed["slug"], "acme-corp");
        assert!(get(&f.iam, "tenantAliases", "acme").await.is_none());
        assert_eq!(
            json(
                f.iam
                    .api
                    .tenants
                    .lookup(body(json!({ "slug": "acme-corp" })))
                    .await
            )
            .unwrap()["tenantId"],
            tenant_id.as_str()
        );
        let taken = f
            .iam
            .api
            .tenants
            .set_slug(
                &f.root,
                body(json!({ "tenantId": tenant_id, "slug": "waiting" })),
            )
            .await;
        assert_eq!(failure(json(taken)).code, "SLUG_TAKEN");
        let cleared = json(
            f.iam
                .api
                .tenants
                .set_slug(
                    &f.root,
                    body(json!({ "tenantId": tenant_id, "slug": null })),
                )
                .await,
        )
        .unwrap();
        assert!(cleared.get("slug").is_none());
        assert!(get(&f.iam, "tenantAliases", "acme-corp").await.is_none());
        // A suspended organization is not discoverable either.
        json(
            f.iam
                .api
                .tenants
                .set_slug(
                    &f.root,
                    body(json!({ "tenantId": tenant_id, "slug": "acme" })),
                )
                .await,
        )
        .unwrap();
        json(
            f.iam
                .api
                .tenants
                .set_status(
                    &f.root,
                    body(json!({ "tenantId": tenant_id, "status": "suspended" })),
                )
                .await,
        )
        .unwrap();
        let error = failure(json(
            f.iam
                .api
                .tenants
                .lookup(body(json!({ "slug": "acme" })))
                .await,
        ));
        assert_eq!(error.code, "NOT_FOUND");
    });
}

#[test]
fn reads_renames_children_and_usage() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let org = organization(&f, "Acme", json!({})).await;
        let tenant_id = org["tenant"]["id"].as_str().unwrap().to_owned();
        let read = json(
            f.iam
                .api
                .tenants
                .get(&f.root, body(json!({ "tenantId": tenant_id })))
                .await,
        )
        .unwrap();
        assert_eq!(read, org["tenant"]);
        let renamed = json(
            f.iam
                .api
                .tenants
                .update(
                    &f.root,
                    body(json!({ "tenantId": tenant_id, "name": "Acme Corp" })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(renamed["name"], "Acme Corp");
        let error = failure(json(
            f.iam
                .api
                .tenants
                .update(&f.root, body(json!({ "tenantId": tenant_id, "name": "" })))
                .await,
        ));
        assert_eq!(error.message, "Invalid name");
        let children = json(
            f.iam
                .api
                .tenants
                .list_children(&f.root, body(json!({ "tenantId": f.root_tenant })))
                .await,
        )
        .unwrap();
        assert_eq!(children.as_array().unwrap().len(), 1);
        assert_eq!(children[0]["id"], tenant_id.as_str());
        // Usage: people (the owner and two members, one of them deleted), a service account, MFA adoption, sessions.
        let (alice, _) = member(&f, &tenant_id, "alice@acme.test", false).await;
        let (bob, _) = member(&f, &tenant_id, "bob@acme.test", false).await;
        let mut gone = get(&f.iam, "identities", &bob).await.unwrap();
        gone.insert("status".into(), json!("deleted"));
        put(&f.iam, "identities", gone).await;
        let service = better_iam_server::utils::id();
        insert(
            &f.iam,
            "identities",
            json!({
                "id": service, "tenantId": tenant_id, "kind": "service", "name": "Robot", "status": "active",
                "owner": false, "rootAdmin": false, "emailVerified": false, "createdAt": NOW,
            }),
        )
        .await;
        insert(
            &f.iam,
            "authMfa",
            json!({ "id": alice, "tenantId": tenant_id, "identityId": alice, "enabled": true }),
        )
        .await;
        insert(
            &f.iam,
            "groups",
            json!({ "id": "g1", "tenantId": tenant_id, "name": "Team" }),
        )
        .await;
        let usage = json(
            f.iam
                .api
                .tenants
                .usage(&f.root, body(json!({ "tenantId": tenant_id })))
                .await,
        )
        .unwrap();
        assert_eq!(
            usage,
            json!({
                "tenantId": tenant_id,
                "identities": 2,
                "mfaEnrolled": 1,
                "serviceAccounts": 1,
                "groups": 1,
                "roles": 1,
                "policies": 1,
                "resources": 0,
                "relationships": 0,
                "webhooks": 0,
                "activeSessions": 2,
                "limits": {},
            })
        );
    });
}

#[test]
fn plan_limits_are_root_controlled_and_tighten_descendants() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let org = organization(&f, "Acme", json!({})).await;
        let org_id = org["tenant"]["id"].as_str().unwrap().to_owned();
        let limited = json(
            f.iam
                .api
                .tenants
                .set_limits(
                    &f.root,
                    body(json!({ "tenantId": org_id, "limits": { "identities": 5, "groups": 3 } })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(limited["limits"], json!({ "identities": 5, "groups": 3 }));
        let error = failure(json(
            f.iam
                .api
                .tenants
                .set_limits(
                    &f.root,
                    body(json!({ "tenantId": org_id, "limits": { "seats": 1 } })),
                )
                .await,
        ));
        assert_eq!(error.message, "Unknown limit seats");
        // A child project starts no looser than its organization.
        let project = json(
            f.iam
                .api
                .tenants
                .create(
                    &f.root,
                    body(json!({
                        "parentId": org_id, "type": "project", "name": "Apollo",
                        "ownerEmail": "lead@acme.test", "activate": true,
                    })),
                )
                .await,
        )
        .unwrap();
        let project_id = project["tenant"]["id"].as_str().unwrap().to_owned();
        assert_eq!(
            project["tenant"]["limits"],
            json!({ "identities": 5, "groups": 3 })
        );
        // Tightening the organization tightens the project per key; loosening leaves it.
        json(
            f.iam
                .api
                .tenants
                .set_limits(
                    &f.root,
                    body(json!({ "tenantId": org_id, "limits": { "identities": 2, "roles": 4 } })),
                )
                .await,
        )
        .unwrap();
        let tightened = get(&f.iam, "tenants", &project_id).await.unwrap();
        assert_eq!(
            tightened["limits"],
            json!({ "identities": 2, "groups": 3, "roles": 4 })
        );
        json(
            f.iam
                .api
                .tenants
                .set_limits(&f.root, body(json!({ "tenantId": org_id, "limits": null })))
                .await,
        )
        .unwrap();
        assert!(
            get(&f.iam, "tenants", &org_id)
                .await
                .unwrap()
                .get("limits")
                .is_none()
        );
        assert_eq!(
            get(&f.iam, "tenants", &project_id).await.unwrap()["limits"],
            json!({ "identities": 2, "groups": 3, "roles": 4 })
        );
        let events = find(
            &f.iam,
            "audit",
            json!({ "tenantId": org_id, "action": "tenant:limits" }),
        )
        .await;
        assert_eq!(events.len(), 3);
        // Only root sets plan limits; the owner's attempt is denied and audited.
        let (_, owner) = member(&f, &org_id, "boss@acme.test", true).await;
        let error = failure(json(
            f.iam
                .api
                .tenants
                .set_limits(
                    &owner,
                    body(json!({ "tenantId": org_id, "limits": { "identities": 100 } })),
                )
                .await,
        ));
        assert_eq!(error.code, "ACCESS_DENIED");
        // The root tenant's limits are the platform's own: an organization does not inherit them.
        json(
            f.iam
                .api
                .tenants
                .set_limits(
                    &f.root,
                    body(json!({ "tenantId": f.root_tenant, "limits": { "identities": 1 } })),
                )
                .await,
        )
        .unwrap();
        let fresh = organization(&f, "Globex", json!({})).await;
        assert!(fresh["tenant"].get("limits").is_none());
    });
}

#[test]
fn status_transitions_cascade_session_revocation() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let org = organization(&f, "Acme", json!({})).await;
        let org_id = org["tenant"]["id"].as_str().unwrap().to_owned();
        let (_, alice) = member(&f, &org_id, "alice@acme.test", false).await;
        assert_eq!(
            find(&f.iam, "sessions", json!({ "tenantId": org_id }))
                .await
                .len(),
            1
        );
        let invalid = [
            (f.root_tenant.clone(), "suspended"),
            (org_id.clone(), "archived"),
        ];
        for (tenant_id, status) in invalid {
            let error = failure(json(
                f.iam
                    .api
                    .tenants
                    .set_status(
                        &f.root,
                        body(json!({ "tenantId": tenant_id, "status": status })),
                    )
                    .await,
            ));
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                ("INVALID_TRANSITION", "Tenant cannot make this transition")
            );
        }
        let suspended = json(
            f.iam
                .api
                .tenants
                .set_status(
                    &f.root,
                    body(json!({ "tenantId": org_id, "status": "suspended" })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(suspended["status"], "suspended");
        assert!(suspended.get("deletedAt").is_none());
        assert!(
            find(&f.iam, "sessions", json!({ "tenantId": org_id }))
                .await
                .is_empty()
        );
        let error = failure(f.iam.authenticate(&alice).await);
        assert_eq!(error.code, "UNAUTHENTICATED");
        let active = json(
            f.iam
                .api
                .tenants
                .set_status(
                    &f.root,
                    body(json!({ "tenantId": org_id, "status": "active" })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(active["status"], "active");
        // A pending tenant can only be deleted.
        let pending = json(
            f.iam
                .api
                .tenants
                .create(
                    &f.root,
                    body(json!({
                        "parentId": f.root_tenant, "type": "organization", "name": "Waiting",
                        "ownerEmail": "owner@waiting.test",
                    })),
                )
                .await,
        )
        .unwrap();
        let pending_id = pending["tenant"]["id"].as_str().unwrap().to_owned();
        let error = failure(json(
            f.iam
                .api
                .tenants
                .set_status(
                    &f.root,
                    body(json!({ "tenantId": pending_id, "status": "active" })),
                )
                .await,
        ));
        assert_eq!(error.code, "INVALID_TRANSITION");
        let deleted = f
            .iam
            .api
            .tenants
            .set_status(
                &f.root,
                body(json!({ "tenantId": pending_id, "status": "deleted" })),
            )
            .await;
        let deleted = or_skip!(json(deleted)).unwrap();
        assert_eq!(deleted["status"], "deleted");
        assert!(deleted["deletedAt"].is_number());
        let error = failure(json(
            f.iam
                .api
                .tenants
                .update(
                    &f.root,
                    body(json!({ "tenantId": pending_id, "name": "Again" })),
                )
                .await,
        ));
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_TRANSITION", "Deleted tenants cannot be updated")
        );
    });
}

#[test]
fn authentication_and_access_policies_boundaries_and_revocation() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let org = organization(&f, "Acme", json!({})).await;
        let org_id = org["tenant"]["id"].as_str().unwrap().to_owned();
        let updated = json(
            f.iam
                .api
                .tenants
                .set_auth_policy(
                    &f.root,
                    body(json!({ "tenantId": org_id, "authPolicy": { "requireMfa": true, "maxSessions": 3 } })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(
            updated["authPolicy"],
            json!({ "requireMfa": true, "maxSessions": 3 })
        );
        let events = find(
            &f.iam,
            "audit",
            json!({ "tenantId": org_id, "action": "tenant:auth-policy" }),
        )
        .await;
        assert_eq!(
            events[0]["metadata"],
            json!({ "authPolicy": { "requireMfa": true, "maxSessions": 3 } })
        );
        let error = failure(json(
            f.iam
                .api
                .tenants
                .set_auth_policy(
                    &f.root,
                    body(json!({ "tenantId": org_id, "authPolicy": { "unknown": true } })),
                )
                .await,
        ));
        assert_eq!(error.code, "INVALID_INPUT");
        let cleared = json(
            f.iam
                .api
                .tenants
                .set_auth_policy(
                    &f.root,
                    body(json!({ "tenantId": org_id, "authPolicy": null })),
                )
                .await,
        )
        .unwrap();
        assert!(cleared.get("authPolicy").is_none());
        // The root tenant's policy is root's alone; an organization owner cannot touch it.
        let (_, owner) = member(&f, &org_id, "boss@acme.test", true).await;
        let error = failure(json(
            f.iam
                .api
                .tenants
                .set_auth_policy(
                    &owner,
                    body(json!({ "tenantId": f.root_tenant, "authPolicy": null })),
                )
                .await,
        ));
        assert_eq!(error.code, "ACCESS_DENIED");
        // An empty access policy stores nothing.
        let access = json(
            f.iam
                .api
                .tenants
                .set_access_policy(
                    &owner,
                    body(json!({ "tenantId": org_id, "accessPolicy": {} })),
                )
                .await,
        )
        .unwrap();
        assert!(access.get("accessPolicy").is_none());
        let access = json(
            f.iam
                .api
                .tenants
                .set_access_policy(
                    &owner,
                    body(json!({ "tenantId": org_id, "accessPolicy": { "requireJustification": true } })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(
            access["accessPolicy"],
            json!({ "requireJustification": true })
        );
        // Ceilings are platform controlled.
        let boundary = json!({ "version": 1, "statements": [{ "effect": "allow", "actions": ["*"], "resources": ["*"] }] });
        let error = failure(json(
            f.iam
                .api
                .tenants
                .set_boundary(
                    &owner,
                    body(json!({ "tenantId": org_id, "boundary": boundary })),
                )
                .await,
        ));
        assert_eq!(error.code, "ACCESS_DENIED");
        let bounded = json(
            f.iam
                .api
                .tenants
                .set_boundary(
                    &f.root,
                    body(json!({ "tenantId": org_id, "boundary": boundary })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(bounded["boundary"], boundary);
        // Signing everyone out keeps the caller's own session unless includeSelf.
        let (_, alice) = member(&f, &org_id, "alice@acme.test", false).await;
        let revoked = json(
            f.iam
                .api
                .tenants
                .revoke_sessions(&owner, body(json!({ "tenantId": org_id })))
                .await,
        )
        .unwrap();
        assert_eq!(revoked, json!({ "revoked": 1 }));
        assert_eq!(
            failure(f.iam.authenticate(&alice).await).code,
            "UNAUTHENTICATED"
        );
        assert!(f.iam.authenticate(&owner).await.is_ok());
        let error = failure(json(
            f.iam
                .api
                .tenants
                .revoke_sessions(&owner, body(json!({ "tenantId": f.root_tenant })))
                .await,
        ));
        assert_eq!(error.code, "ACCESS_DENIED");
        let revoked = json(
            f.iam
                .api
                .tenants
                .revoke_sessions(
                    &owner,
                    body(json!({ "tenantId": org_id, "includeSelf": true })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(revoked, json!({ "revoked": 1 }));
        let events = find(
            &f.iam,
            "audit",
            json!({ "tenantId": org_id, "action": "tenant:revoke-sessions" }),
        )
        .await;
        assert_eq!(events.len(), 2);
    });
}

#[test]
fn moving_tenants_checks_the_hierarchy() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let acme = organization(&f, "Acme", json!({})).await;
        let acme_id = acme["tenant"]["id"].as_str().unwrap().to_owned();
        let globex = organization(&f, "Globex", json!({})).await;
        let globex_id = globex["tenant"]["id"].as_str().unwrap().to_owned();
        let project = json(
            f.iam
                .api
                .tenants
                .create(
                    &f.root,
                    body(json!({
                        "parentId": acme_id, "type": "project", "name": "Apollo",
                        "ownerEmail": "lead@acme.test", "activate": true,
                    })),
                )
                .await,
        )
        .unwrap();
        let project_id = project["tenant"]["id"].as_str().unwrap().to_owned();
        let cases = [
            (
                f.root_tenant.clone(),
                acme_id.clone(),
                "INVALID_TRANSITION",
                "Tenant cannot be moved",
            ),
            (
                project_id.clone(),
                acme_id.clone(),
                "INVALID_INPUT",
                "Tenant is already under this parent",
            ),
            (
                acme_id.clone(),
                globex_id.clone(),
                "INVALID_HIERARCHY",
                "Child type is not permitted under the new parent",
            ),
            (
                project_id.clone(),
                "missing".to_owned(),
                "NOT_FOUND",
                "Tenant not found",
            ),
        ];
        for (tenant_id, parent_id, code, message) in cases {
            let error = failure(json(
                f.iam
                    .api
                    .tenants
                    .reparent(
                        &f.root,
                        body(json!({ "tenantId": tenant_id, "parentId": parent_id })),
                    )
                    .await,
            ));
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                (code, message)
            );
        }
        let moved = f
            .iam
            .api
            .tenants
            .reparent(
                &f.root,
                body(json!({ "tenantId": project_id, "parentId": globex_id })),
            )
            .await;
        let moved = or_skip!(json(moved)).unwrap();
        assert_eq!(moved["parentId"], globex_id.as_str());
        let events = find(
            &f.iam,
            "audit",
            json!({ "tenantId": project_id, "action": "tenant:reparent" }),
        )
        .await;
        assert_eq!(
            events[0]["metadata"],
            json!({ "from": acme_id, "to": globex_id })
        );
    });
}

#[test]
fn regions_need_a_parent_to_inherit_from() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let error = failure(json(
            f.iam
                .api
                .tenants
                .set_region(
                    &f.root,
                    body(json!({ "tenantId": f.root_tenant, "region": null })),
                )
                .await,
        ));
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "INVALID_INPUT",
                "The root tenant has no parent to inherit a region from"
            )
        );
        // Only root moves regions.
        let org = organization(&f, "Acme", json!({})).await;
        let org_id = org["tenant"]["id"].as_str().unwrap().to_owned();
        let (_, owner) = member(&f, &org_id, "boss@acme.test", true).await;
        let error = failure(json(
            f.iam
                .api
                .tenants
                .set_region(&owner, body(json!({ "tenantId": org_id, "region": null })))
                .await,
        ));
        assert_eq!(error.code, "ACCESS_DENIED");
        let inherited = json(
            f.iam
                .api
                .tenants
                .set_region(&f.root, body(json!({ "tenantId": org_id, "region": null })))
                .await,
        )
        .unwrap();
        assert!(inherited.get("region").is_none());
        let events = find(
            &f.iam,
            "audit",
            json!({ "tenantId": org_id, "action": "tenant:region" }),
        )
        .await;
        assert_eq!(events[0]["metadata"], json!({ "from": null, "to": null }));
    });
}
