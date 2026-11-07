//! The `guests` API group and `iam.guests` jobs: ported from tests/guests.test.ts, tests/guests-access.test.ts,
//! tests/guests-hardening.test.ts, tests/guests-edges.test.ts and tests/guests-lifecycle.test.ts. Members and their
//! grants come from the organization fixture (written as `identities.create`, `roles.create` and `bindings.create`
//! write them).
//!
//! A successful redemption ends in sod.ts `sodAssertIdentity` and api/package-automation.ts `afterIdentityChange`,
//! which belong to other units and are still stubs; so do the grant checks of api/packages.ts (`allow`), the team
//! helpers of teams.ts, and the removal helpers (departments.ts, delegations.ts, threats.ts). The cases that need
//! them are ported and ignored until those land. Every other case runs now: guests that a redemption would create
//! are written as `guests.redeem` writes them (`seed_guest`), after a real invitation.

// Expected ids read best as one-element arrays.
#![allow(clippy::cloned_ref_to_slice_refs)]

mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::{
    CredentialInput, Filter, IamError, IamResult, IamStoreExt, Identity, Record, SessionClientInfo,
};
use better_iam_server::api::Reply;
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use regex::Regex;
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;

/// A JavaScript number as the API answers it (`1`, not `1.0`).
fn n(value: f64) -> Value {
    better_iam_server::js::number(value)
}

fn iso(at: f64) -> String {
    better_iam_core::js::iso_string(at).unwrap()
}

fn password(name: &str) -> String {
    format!("a strong {name} password")
}

/// The organization fixture with a captured email outbox.
struct Guests {
    f: Org,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
}

impl std::ops::Deref for Guests {
    type Target = Org;
    fn deref(&self) -> &Org {
        &self.f
    }
}

async fn fixture() -> Guests {
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let sink = inbox.clone();
    let f = organization(move |options| {
        let authentication = options.authentication.as_mut().unwrap();
        authentication.send_email = Some(delivery_fn(move |message| {
            sink.lock().unwrap().push(message);
            async { Ok(()) }
        }));
    })
    .await;
    Guests { f, inbox }
}

impl Guests {
    fn with_tenant(&self, input: Value) -> Value {
        let mut input = input;
        if input.get("tenantId").is_none() {
            input["tenantId"] = json!(self.tenant_id);
        }
        input
    }

    async fn invite(&self, credential: &CredentialInput, input: Value) -> IamResult<Value> {
        let input = self.with_tenant(input);
        self.iam
            .api
            .guests
            .invite(credential, body(input))
            .await
            .map(|reply| reply.into_value().unwrap())
    }

    async fn configure(&self, credential: &CredentialInput, input: Value) -> IamResult<Value> {
        let input = self.with_tenant(input);
        self.iam
            .api
            .guests
            .configure(credential, body(input))
            .await
            .map(|reply| reply.into_value().unwrap())
    }

    async fn redeem(&self, input: Value) -> IamResult<Value> {
        let input = self.with_tenant(input);
        self.iam
            .api
            .guests
            .redeem(body(input))
            .await
            .map(|reply| reply.into_value().unwrap())
    }

    async fn list_invitations(&self, credential: &CredentialInput, input: Value) -> Value {
        ok(self
            .iam
            .api
            .guests
            .list_invitations(credential, body(self.with_tenant(input)))
            .await)
    }

    async fn get(&self, credential: &CredentialInput, identity_id: &str) -> IamResult<Value> {
        self.iam
            .api
            .guests
            .get(
                credential,
                body(json!({ "tenantId": self.tenant_id, "identityId": identity_id })),
            )
            .await
            .map(|reply| reply.into_value().unwrap())
    }

    async fn attest(&self, credential: &CredentialInput, input: Value) -> IamResult<Value> {
        self.iam
            .api
            .guests
            .attest(credential, body(self.with_tenant(input)))
            .await
            .map(|reply| reply.into_value().unwrap())
    }

    async fn sweep(&self, input: Option<Value>) -> Value {
        self.iam.guests.sweep(input.as_ref()).await.unwrap()
    }

    async fn reminders(&self, input: Option<Value>) -> IamResult<Value> {
        self.iam.guests.send_review_reminders(input.as_ref()).await
    }

    /// Delivers the outbox into the inbox.
    async fn dispatch(&self) {
        self.iam.auth.dispatch_outbox(None).await.unwrap();
    }

    fn sent(&self, template: &str) -> Vec<DeliveryMessage> {
        self.inbox
            .lock()
            .unwrap()
            .iter()
            .filter(|message| message.template == template)
            .cloned()
            .collect()
    }

    /// The newest guest invitation token emailed to `address` (delivers the outbox first).
    async fn token_for(&self, address: &str) -> String {
        self.dispatch().await;
        let address = address.to_lowercase();
        self.sent("guest-invitation")
            .into_iter()
            .rev()
            .find(|message| message.to == address)
            .and_then(|message| message.payload["token"].as_str().map(str::to_owned))
            .unwrap_or_else(|| panic!("No guest invitation was emailed to {address}"))
    }

    async fn record(&self, collection: &str, id: &str) -> Option<Record> {
        self.iam.store.get(collection, id).await.unwrap()
    }

    async fn audit(&self, tenant_id: &str) -> Vec<Record> {
        let mut events = self
            .find("audit", Filter::new().eq("tenantId", tenant_id.to_owned()))
            .await;
        events.sort_by(|a, b| {
            a["sequence"]
                .as_f64()
                .unwrap_or(0.0)
                .total_cmp(&b["sequence"].as_f64().unwrap_or(0.0))
        });
        events
    }

    async fn audit_of(&self, action: &str) -> Vec<Record> {
        self.audit(&self.tenant_id)
            .await
            .into_iter()
            .filter(|event| event["action"] == action)
            .collect()
    }

    /// Records the tenant as the verifier of `domain`, as a verified domain claim does (domains.ts).
    async fn verify_domain(&self, tenant_id: &str, domain: &str) {
        self.insert(
            "domainOwners",
            json!({
                "id": domain,
                "tenantId": tenant_id,
                "domainId": format!("domain-{domain}"),
                "verifiedAt": n(self.now()),
            }),
        )
        .await;
    }

    /// Another organization under the platform with its owner signed in (`owner@{slug}.test`).
    async fn other_organization(
        &self,
        name: &str,
        slug: &str,
    ) -> (String, String, CredentialInput) {
        self.activate(
            &self.root_tenant.clone(),
            name,
            "organization",
            &format!("owner@{slug}.test"),
        )
        .await
    }

    /// Sets an identity's status (and optionally its end), as `identities.setStatus` / `update` store it.
    async fn set_identity(&self, identity_id: &str, changes: Value) {
        let mut identity = self.record("identities", identity_id).await.unwrap();
        for (key, value) in changes.as_object().unwrap() {
            if value.is_null() {
                identity.shift_remove(key);
            } else {
                identity.insert(key.clone(), value.clone());
            }
        }
        self.put("identities", identity).await;
    }

    /// Invites `{name}@partner.test` (with `input`) as `credential`, then writes the guest exactly as
    /// `guests.redeem` writes it for an invitation that grants nothing: the identity with its end and `guest`
    /// marker, the guest account, and the spent invitation. Returns the guest identity's id.
    async fn seed_guest_by(
        &self,
        credential: &CredentialInput,
        name: &str,
        input: Value,
    ) -> String {
        let mut request = json!({ "email": format!("{name}@partner.test") });
        for (key, value) in input.as_object().unwrap() {
            request[key] = value.clone();
        }
        let invitation = self.invite(credential, request).await.unwrap();
        let invitation_id = invitation["id"].as_str().unwrap().to_owned();
        let auth = self.iam.auth.clone();
        let tenant_id = self.tenant_id.clone();
        let now = self.now();
        let name = name.to_owned();
        self.iam
            .store
            .transaction(|tx| async move {
                let invitation = tx.get("guestInvitations", &invitation_id).await?.unwrap();
                let settings = better_iam_server::guests::guest_settings(&tx, &tenant_id).await?;
                let created = auth
                    .create_identity(
                        &tx,
                        CreateIdentityInput {
                            tenant_id: tenant_id.clone(),
                            email: invitation["email"].as_str().unwrap().to_owned(),
                            name: name.clone(),
                            password: Some(password(&name)),
                            owner: None,
                            root_admin: None,
                            email_verified: Some(true),
                        },
                    )
                    .await?;
                let expires_at = now + invitation["accessDays"].as_f64().unwrap() * DAY;
                let mut identity = tx.get("identities", &created.id).await?.unwrap();
                identity.insert("expiresAt".into(), n(expires_at));
                identity.insert(
                    "guest".into(),
                    json!({
                        "sponsorId": invitation["sponsorId"],
                        "since": n(now),
                        "homeDomain": invitation["email"].as_str().unwrap().split('@').nth(1).unwrap(),
                    }),
                );
                tx.put("identities", &identity).await?;
                tx.insert(
                    "guestAccounts",
                    json!({
                        "id": created.id,
                        "tenantId": tenant_id,
                        "identityId": created.id,
                        "sponsorId": invitation["sponsorId"],
                        "email": invitation["email"],
                        "source": "invitation",
                        "invitationId": invitation["id"],
                        "invitedBy": invitation["invitedBy"],
                        "redeemedAt": n(now),
                        "reviewDueAt": n((now + settings.review_every_days * DAY).min(expires_at)),
                        "status": "active",
                        "grants": {
                            "bindingIds": [],
                            "membershipIds": [],
                            "packageAssignmentIds": [],
                            "packageMembershipIds": [],
                        },
                        "grantsEndAt": n(expires_at),
                    })
                    .as_object()
                    .unwrap(),
                )
                .await?;
                let mut spent = invitation.clone();
                spent.shift_remove("uniqueKey");
                spent.insert("status".into(), json!("redeemed"));
                spent.insert("redeemedAt".into(), n(now));
                spent.insert("identityId".into(), json!(created.id));
                tx.put("guestInvitations", &spent).await?;
                Ok(created.id)
            })
            .await
            .unwrap()
    }

    async fn seed_guest(&self, name: &str, input: Value) -> String {
        let owner = self.owner_credential.clone();
        self.seed_guest_by(&owner, name, input).await
    }

    /// A fresh owner session (`f.ownerSignIn()`).
    async fn owner_sign_in(&self) -> CredentialInput {
        self.sign_in(&self.owner_id.clone()).await
    }

    /// A member holding an inline grant of `actions` on everything, signed in.
    async fn administrator(&self, name: &str, actions: &[&str]) -> (String, CredentialInput) {
        let person = self.member(name).await;
        self.grant(
            &person,
            json!([{ "effect": "allow", "actions": actions, "resources": ["*"] }]),
        )
        .await;
        let credential = self.sign_in(&person).await;
        (person, credential)
    }
}

fn error_of(result: IamResult<Value>) -> IamError {
    match result {
        Ok(value) => panic!("expected an error, got {value}"),
        Err(error) => error,
    }
}

#[track_caller]
fn assert_code(result: IamResult<Value>, expected: &str) -> IamError {
    let error = error_of(result);
    assert_eq!(code(&error), expected, "{error:?}");
    error
}

fn ids(values: &Value, key: &str) -> Vec<String> {
    values
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item[key].as_str().unwrap().to_owned())
        .collect()
}

fn reply<O: serde::Serialize>(result: IamResult<Reply<O>>) -> IamResult<Value> {
    result.map(|reply| reply.into_value().unwrap())
}

// --- guest invitations and redemption -----------------------------------------------------------------------------

#[test]
fn invites_a_person_by_email_with_an_emailed_token() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let alice = f.member("alice").await;
        let invited_at = f.now();
        let invitation = f
            .invite(
                &owner,
                json!({
                    "email": "Gina@Partner.test",
                    "sponsorId": alice,
                    "message": "  Welcome to the launch project  ",
                    "accessDays": 30,
                    "expiresInDays": 7,
                }),
            )
            .await
            .unwrap();
        let invitation_id = invitation["id"].as_str().unwrap().to_owned();
        assert_eq!(
            invitation,
            json!({
                "id": invitation_id,
                "tenantId": tenant_id,
                "email": "gina@partner.test",
                "status": "pending",
                "sponsorId": alice,
                "sponsorName": "alice",
                "invitedBy": f.owner_id,
                "inviterName": "Acme owner",
                "message": "Welcome to the launch project",
                "roleIds": [],
                "groupIds": [],
                "packageIds": [],
                "accessDays": 30,
                "expiresAt": n(invited_at + 7.0 * DAY),
                "createdAt": n(invited_at),
                "sentAt": n(invited_at),
            })
        );
        // Only the token's hash is stored; the address holds the pending slot.
        let stored = f
            .find(
                "guestInvitations",
                Filter::new().eq("tenantId", tenant_id.clone()),
            )
            .await;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0]["uniqueKey"], "pending:gina@partner.test");

        // The invitee gets a personal email with the token.
        f.dispatch().await;
        let email = f.sent("guest-invitation").remove(0);
        assert_eq!(email.tenant_id, tenant_id);
        assert_eq!(email.to, "gina@partner.test");
        let token = email.payload["token"].as_str().unwrap().to_owned();
        assert!(
            Regex::new(r"^biam_gst_[A-Za-z0-9_-]{43}$")
                .unwrap()
                .is_match(&token)
        );
        assert_eq!(
            Value::Object(email.payload.clone()),
            json!({
                "tenantId": tenant_id,
                "tenantName": "Acme",
                "inviterName": "Acme owner",
                "sponsorName": "alice",
                "message": "Welcome to the launch project",
                "token": token,
                "expiresAt": iso(invited_at + 7.0 * DAY),
            })
        );
        assert!(!stored[0]["tokenHash"].as_str().unwrap().contains(&token));
        assert_eq!(
            stored[0]["tokenHash"],
            json!(better_iam_server::utils::hash(&token))
        );

        assert_eq!(
            f.list_invitations(&owner, json!({})).await,
            json!([invitation])
        );

        // Everything is audited.
        let events = f.audit(&tenant_id).await;
        let invite = events
            .iter()
            .find(|event| event["action"] == "guest:invite")
            .unwrap();
        assert_matches(
            &Value::Object(invite.clone()),
            json!({
                "actorId": f.owner_id,
                "resourceId": invitation_id,
                "outcome": "allow",
                "metadata": {
                    "email": "gina@partner.test",
                    "sponsorId": alice,
                    "roleIds": [],
                    "groupIds": [],
                    "packageIds": [],
                    "accessDays": 30,
                    "expiresAt": n(invited_at + 7.0 * DAY),
                },
            }),
        );
        for action in ["iam:guests:invite", "iam:guests:read"] {
            assert!(
                events
                    .iter()
                    .any(|event| event["action"] == action && event["outcome"] == "allow"),
                "{action}"
            );
        }
    });
}

#[test]
#[ignore = "a successful redemption needs sod.ts sodAssertIdentity and api/package-automation.ts afterIdentityChange (other units)"]
fn turns_the_redeemed_invitation_into_a_signed_in_guest() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let alice = f.member("alice").await;
        let invitation = f
            .invite(
                &owner,
                json!({ "email": "gina@partner.test", "sponsorId": alice, "accessDays": 30 }),
            )
            .await
            .unwrap();
        let token = f.token_for("gina@partner.test").await;
        f.advance(60_000.0);
        let redeemed_at = f.now();
        let result = f
            .redeem(json!({ "token": token, "name": "Gina", "password": password("Gina") }))
            .await
            .unwrap();
        assert_matches(
            &result["identity"],
            json!({
                "tenantId": tenant_id,
                "kind": "user",
                "email": "gina@partner.test",
                "emailVerified": true,
                "name": "Gina",
                "status": "active",
                "owner": false,
                "expiresAt": n(redeemed_at + 30.0 * DAY),
                "guest": { "sponsorId": alice, "since": n(redeemed_at), "homeDomain": "partner.test" },
            }),
        );
        assert!(result["identity"]["guest"].get("homeTenantId").is_none());
        assert!(result["identity"].get("passwordHash").is_none());
        let guest_id = result["identity"]["id"].as_str().unwrap().to_owned();
        assert_matches(
            &result["session"],
            json!({ "identityId": guest_id, "method": "password" }),
        );
        let redeemed = f.list_invitations(&owner, json!({})).await;
        assert_matches(
            &redeemed[0],
            json!({ "status": "redeemed", "redeemedAt": n(redeemed_at), "identityId": guest_id }),
        );
        assert_code(
            f.redeem(json!({ "token": token, "name": "Gina again", "password": password("Gina") }))
                .await,
            "INVITATION_INVALID",
        );
        let view = f.get(&owner, &guest_id).await.unwrap();
        assert_matches(
            &view,
            json!({
                "identityId": guest_id,
                "accountStatus": "active",
                "sponsorId": alice,
                "invitationId": invitation["id"],
                "reviewDueAt": n(redeemed_at + 30.0 * DAY),
            }),
        );
        let event = f.audit_of("guest:redeem").await.remove(0);
        assert_matches(
            &Value::Object(event),
            json!({ "actorId": guest_id, "resourceId": guest_id, "outcome": "allow" }),
        );
    });
}

#[test]
fn validates_what_an_invitation_asks_for() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let alice = f.member("alice").await;
        let invite = |input: Value| {
            let mut request = json!({ "email": "val@partner.test" });
            for (key, value) in input.as_object().unwrap() {
                request[key] = value.clone();
            }
            f.invite(&owner, request)
        };
        for input in [
            json!({ "email": "not an address" }),
            json!({ "email": 42 }),
            json!({ "accessDays": 0 }),
            json!({ "accessDays": 366 }),
            json!({ "accessDays": 1.5 }),
            json!({ "expiresInDays": 0 }),
            json!({ "expiresInDays": 31 }),
            json!({ "message": "x".repeat(1001) }),
            json!({ "roleIds": "role" }),
            json!({ "groupIds": [42] }),
            json!({ "packageIds": {} }),
        ] {
            let error = error_of(invite(input.clone()).await);
            assert_eq!(code(&error), "INVALID_INPUT", "{input}");
        }
        assert_code(invite(json!({ "roleIds": ["missing"] })).await, "NOT_FOUND");
        assert_code(
            invite(json!({ "groupIds": ["missing"] })).await,
            "NOT_FOUND",
        );
        assert_code(
            invite(json!({ "packageIds": ["missing"] })).await,
            "NOT_FOUND",
        );
        // Protected roles pass by ownership transfer only.
        let owner_role = f
            .find(
                "roles",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("uniqueKey", "system:owner"),
            )
            .await;
        let error = assert_code(
            invite(json!({ "roleIds": [owner_role[0]["id"]] })).await,
            "PROTECTED_RESOURCE",
        );
        assert_eq!(error.status, 403);
        // Sponsors are active members who are not guests.
        let guest = f.seed_guest("gus", json!({})).await;
        let bob = f.member("bob").await;
        f.set_identity(&bob, json!({ "status": "disabled" })).await;
        for sponsor_id in [guest.as_str(), bob.as_str(), "missing", ""] {
            let error = error_of(invite(json!({ "sponsorId": sponsor_id })).await);
            let expected = if sponsor_id.is_empty() {
                "INVALID_INPUT"
            } else {
                "INVALID_SPONSOR"
            };
            assert_eq!(code(&error), expected, "{sponsor_id}");
        }
        // An address that already belongs to someone here, or already has a pending invitation.
        for email in ["alice@acme.test", "gus@partner.test", "GUS@partner.test"] {
            let error = error_of(invite(json!({ "email": email })).await);
            assert_eq!((code(&error), error.status), ("CONFLICT", 409), "{email}");
        }
        invite(json!({ "sponsorId": alice })).await.unwrap();
        let error = assert_code(invite(json!({})).await, "CONFLICT");
        assert_eq!(error.status, 409);
        // The platform tenant takes no guests.
        assert_code(
            f.invite(
                &f.root_credential,
                json!({ "tenantId": f.root_tenant, "email": "someone@partner.test" }),
            )
            .await,
            "INVALID_INPUT",
        );
        // Nothing was sent for the refused invitations.
        f.dispatch().await;
        // (Both were queued at the same instant, so the delivery order between them is not fixed.)
        let mut sent: Vec<String> = f
            .sent("guest-invitation")
            .into_iter()
            .map(|message| message.to)
            .collect();
        sent.sort();
        assert_eq!(sent, ["gus@partner.test", "val@partner.test"]);
        let pending = f
            .list_invitations(&owner, json!({ "status": "pending" }))
            .await;
        assert_eq!(pending.as_array().unwrap().len(), 1);
        assert_matches(
            &pending[0],
            json!({ "email": "val@partner.test", "sponsorId": alice }),
        );
    });
}

#[test]
fn checks_the_redemption_itself() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        f.invite(&owner, json!({ "email": "ivy@partner.test" }))
            .await
            .unwrap();
        let token = f.token_for("ivy@partner.test").await;
        let redeem = |input: Value| {
            let mut request = json!({ "token": token, "name": "Ivy", "password": password("Ivy") });
            for (key, value) in input.as_object().unwrap() {
                if value.is_null() {
                    request.as_object_mut().unwrap().remove(key);
                } else {
                    request[key] = value.clone();
                }
            }
            f.redeem(request)
        };
        for input in [
            json!({ "name": "" }),
            json!({ "password": null }),
            json!({ "password": 42 }),
            json!({ "token": "" }),
        ] {
            let error = error_of(redeem(input.clone()).await);
            assert_eq!(code(&error), "INVALID_INPUT", "{input}");
        }
        assert_eq!(
            error_of(redeem(json!({ "password": "short" })).await).status,
            400
        );
        assert_code(
            redeem(json!({ "token": "biam_gst_unknown" })).await,
            "INVITATION_INVALID",
        );
        assert_eq!(
            error_of(redeem(json!({ "tenantId": "missing" })).await).status,
            404
        );
        // A refused redemption leaves no trace behind: the invitation is still pending.
        assert!(
            f.find(
                "identities",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("email", "ivy@partner.test"),
            )
            .await
            .is_empty()
        );
        assert_matches(
            &f.list_invitations(&owner, json!({})).await[0],
            json!({ "status": "pending" }),
        );
    });
}

// --- guest lifecycle: invitations -------------------------------------------------------------------------------

#[test]
fn revokes_resends_and_lapses_invitations() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let guests = &f.iam.api.guests;
        let first = f
            .invite(&owner, json!({ "email": "jo@partner.test" }))
            .await
            .unwrap();
        let first_id = first["id"].as_str().unwrap().to_owned();
        let first_token = f.token_for("jo@partner.test").await;
        let revoked = ok(guests
            .revoke_invitation(
                &owner,
                body(json!({ "tenantId": tenant_id, "invitationId": first_id })),
            )
            .await);
        assert_matches(
            &revoked,
            json!({ "status": "revoked", "revokedAt": n(f.now()), "revokedBy": f.owner_id }),
        );
        assert_code(
            f.redeem(json!({ "token": first_token, "name": "Jo", "password": password("Jo") }))
                .await,
            "INVITATION_INVALID",
        );
        for error in [
            fails(
                guests
                    .revoke_invitation(
                        &owner,
                        body(json!({ "tenantId": tenant_id, "invitationId": first_id })),
                    )
                    .await,
            ),
            fails(
                guests
                    .resend_invitation(
                        &owner,
                        body(json!({ "tenantId": tenant_id, "invitationId": first_id })),
                    )
                    .await,
            ),
        ] {
            assert_eq!((code(&error), error.status), ("INVALID_TRANSITION", 409));
        }
        for error in [
            fails(
                guests
                    .revoke_invitation(
                        &owner,
                        body(json!({ "tenantId": tenant_id, "invitationId": "missing" })),
                    )
                    .await,
            ),
            fails(
                guests
                    .resend_invitation(
                        &owner,
                        body(json!({ "tenantId": tenant_id, "invitationId": "missing" })),
                    )
                    .await,
            ),
        ] {
            assert_eq!(code(&error), "NOT_FOUND");
        }

        // Revoking frees the address for a new invitation; sending again rotates its token.
        let second = f
            .invite(&owner, json!({ "email": "jo@partner.test" }))
            .await
            .unwrap();
        let second_id = second["id"].as_str().unwrap().to_owned();
        let old_token = f.token_for("jo@partner.test").await;
        f.advance(DAY);
        let owner = f.owner_sign_in().await;
        let resent = ok(guests
            .resend_invitation(
                &owner,
                body(
                    json!({ "tenantId": tenant_id, "invitationId": second_id, "expiresInDays": 3 }),
                ),
            )
            .await);
        assert_matches(
            &resent,
            json!({
                "id": second_id,
                "status": "pending",
                "createdAt": second["createdAt"],
                "sentAt": n(f.now()),
                "expiresAt": n(f.now() + 3.0 * DAY),
            }),
        );
        let new_token = f.token_for("jo@partner.test").await;
        assert_ne!(new_token, old_token);
        assert_code(
            f.redeem(json!({ "token": old_token, "name": "Jo", "password": password("Jo") }))
                .await,
            "INVITATION_INVALID",
        );
        for days in [0, 31] {
            let error = fails(
                guests
                    .resend_invitation(
                        &owner,
                        body(json!({ "tenantId": tenant_id, "invitationId": second_id, "expiresInDays": days })),
                    )
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT");
        }

        // A lapsed invitation reads as expired at once, cannot be redeemed, and can be sent again.
        f.advance(3.0 * DAY);
        let owner = f.owner_sign_in().await;
        assert_eq!(
            ids(
                &f.list_invitations(&owner, json!({ "status": "expired" }))
                    .await,
                "id"
            ),
            [second_id.clone()]
        );
        assert_code(
            f.redeem(json!({ "token": new_token, "name": "Jo", "password": password("Jo") }))
                .await,
            "INVITATION_INVALID",
        );
        let again = ok(guests
            .resend_invitation(
                &owner,
                body(json!({ "tenantId": tenant_id, "invitationId": second_id })),
            )
            .await);
        assert_matches(
            &again,
            json!({ "status": "pending", "expiresAt": n(f.now() + 14.0 * DAY) }),
        );

        // A new invitation to a lapsed address takes over its pending slot.
        f.invite(
            &owner,
            json!({ "email": "kim@partner.test", "expiresInDays": 1 }),
        )
        .await
        .unwrap();
        f.advance(2.0 * DAY);
        let owner = f.owner_sign_in().await;
        let kim = f
            .invite(&owner, json!({ "email": "kim@partner.test" }))
            .await
            .unwrap();
        let listed = f.list_invitations(&owner, json!({})).await;
        let statuses: Vec<(bool, Value)> = listed
            .as_array()
            .unwrap()
            .iter()
            .filter(|invitation| invitation["email"] == "kim@partner.test")
            .map(|invitation| (invitation["id"] == kim["id"], invitation["status"].clone()))
            .collect();
        assert_eq!(
            statuses,
            [(true, json!("pending")), (false, json!("expired"))]
        );
        let error = fails(
            guests
                .list_invitations(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "status": "lost" })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");

        let mut trail: Vec<String> = f
            .audit(&tenant_id)
            .await
            .into_iter()
            .filter_map(|event| event["action"].as_str().map(str::to_owned))
            .filter(|action| action.starts_with("guest:invitation-"))
            .collect();
        trail.sort();
        assert_eq!(
            trail,
            [
                "guest:invitation-resend",
                "guest:invitation-resend",
                "guest:invitation-revoke"
            ]
        );
    });
}

#[test]
fn neither_revokes_nor_resends_a_redeemed_invitation() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let guest = f.seed_guest("jo", json!({})).await;
        let invitation_id = f.record("guestAccounts", &guest).await.unwrap()["invitationId"]
            .as_str()
            .unwrap()
            .to_owned();
        for error in [
            fails(
                f.iam
                    .api
                    .guests
                    .revoke_invitation(
                        &owner,
                        body(json!({ "tenantId": tenant_id, "invitationId": invitation_id })),
                    )
                    .await,
            ),
            fails(
                f.iam
                    .api
                    .guests
                    .resend_invitation(
                        &owner,
                        body(json!({ "tenantId": tenant_id, "invitationId": invitation_id })),
                    )
                    .await,
            ),
        ] {
            assert_eq!(code(&error), "INVALID_TRANSITION");
        }
    });
}

// --- cross-tenant access settings ---------------------------------------------------------------------------------

#[test]
fn settings_default_to_open_validate_changes_and_are_audited() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let (globex, _, _) = f.other_organization("Globex", "globex").await;
        assert_eq!(
            ok(f.iam
                .api
                .guests
                .get_settings(&owner, body(json!({ "tenantId": tenant_id })))
                .await),
            json!({
                "tenantId": tenant_id,
                "configured": false,
                "inbound": { "allowGuests": true, "allowedDomains": [], "blockedDomains": [], "partners": [] },
                "outbound": { "allowGuestInvitations": true, "partners": [] },
                "accessDays": 90,
                "reviewEveryDays": 90,
            })
        );
        for input in [
            json!({}),
            json!({ "inbound": {} }),
            json!({ "inbound": "open" }),
            json!({ "inbound": { "allowGuests": "yes" } }),
            json!({ "inbound": { "colour": "blue" } }),
            json!({ "inbound": { "allowedDomains": "partner.test" } }),
            json!({ "inbound": { "allowedDomains": ["not a domain"] } }),
            json!({ "inbound": { "blockedDomains": ["http://partner.test"] } }),
            json!({ "inbound": { "partners": [{ "tenantId": tenant_id }] } }),
            json!({ "inbound": { "partners": [{ "tenantId": tenant_id, "allow": true }] } }),
            json!({ "inbound": { "partners": [{ "tenantId": "missing", "allow": true }] } }),
            json!({ "inbound": { "partners": [{ "tenantId": globex, "allow": "yes" }] } }),
            json!({ "inbound": { "partners": [{ "tenantId": globex, "allow": true, "note": "x" }] } }),
            json!({ "inbound": { "partners": [
                { "tenantId": globex, "allow": true },
                { "tenantId": globex, "allow": false },
            ] } }),
            json!({ "outbound": { "allowGuestInvitations": 1 } }),
            json!({ "outbound": { "allowGuests": true } }),
            json!({ "outbound": { "partners": [{ "tenantId": format!("{}x", f.root_tenant), "allow": true }] } }),
            json!({ "accessDays": 0 }),
            json!({ "accessDays": 366 }),
            json!({ "reviewEveryDays": 6 }),
            json!({ "reviewEveryDays": 366 }),
            json!({ "colour": "blue", "accessDays": 5 }),
        ] {
            let error = error_of(f.configure(&owner, input.clone()).await);
            assert_eq!(code(&error), "INVALID_INPUT", "{input}");
        }
        // The boundary is checked like any policy, actions included.
        assert_code(
            f.configure(
                &owner,
                json!({ "guestBoundary": { "version": 1, "statements": "none" } }),
            )
            .await,
            "INVALID_POLICY",
        );
        assert_code(
            f.configure(
                &owner,
                json!({ "guestBoundary": { "version": 1, "statements": [
                    { "effect": "allow", "actions": ["documents:shred"], "resources": ["*"] }
                ] } }),
            )
            .await,
            "INVALID_ACTION",
        );
        let boundary = json!({
            "version": 1,
            "statements": [{ "effect": "allow", "actions": ["documents:read"], "resources": ["document/shared-*"] }],
        });
        let configured = f
            .configure(
                &owner,
                json!({
                    "inbound": {
                        "allowedDomains": ["Partner.test", "partner.test", "agency.test"],
                        "partners": [{ "tenantId": globex, "allow": true }],
                    },
                    "outbound": { "partners": [{ "tenantId": globex, "allow": false }] },
                    "accessDays": 30,
                    "reviewEveryDays": 14,
                    "guestBoundary": boundary,
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            configured,
            json!({
                "tenantId": tenant_id,
                "configured": true,
                "inbound": {
                    "allowGuests": true,
                    "allowedDomains": ["agency.test", "partner.test"],
                    "blockedDomains": [],
                    "partners": [{ "tenantId": globex, "allow": true }],
                },
                "outbound": {
                    "allowGuestInvitations": true,
                    "partners": [{ "tenantId": globex, "allow": false }],
                },
                "accessDays": 30,
                "reviewEveryDays": 14,
                "guestBoundary": boundary,
                "updatedAt": n(f.now()),
                "updatedBy": f.owner_id,
            })
        );
        assert_eq!(
            ok(f.iam
                .api
                .guests
                .get_settings(&owner, body(json!({ "tenantId": tenant_id })))
                .await),
            configured
        );
        // Only the fields given change, inside inbound and outbound too; null removes the boundary.
        let next = f
            .configure(
                &owner,
                json!({ "inbound": { "allowGuests": false }, "guestBoundary": null }),
            )
            .await
            .unwrap();
        let mut inbound = configured["inbound"].clone();
        inbound["allowGuests"] = json!(false);
        assert_eq!(next["inbound"], inbound);
        assert_eq!(next["outbound"], configured["outbound"]);
        assert!(next.get("guestBoundary").is_none());
        assert_eq!(next["accessDays"], 30);
        let latest = f.audit_of("guest:settings").await.pop().unwrap();
        assert_matches(
            &Value::Object(latest),
            json!({
                "actorId": f.owner_id,
                "resourceId": tenant_id,
                "metadata": {
                    "changed": ["inbound.allowGuests", "guestBoundary"],
                    "allowGuests": false,
                    "allowedDomains": ["agency.test", "partner.test"],
                    "inboundPartners": [{ "tenantId": globex, "allow": true }],
                    "outboundPartners": [{ "tenantId": globex, "allow": false }],
                    "guestBoundary": false,
                },
            }),
        );
        // A root administrator may configure any organization, with a recent sign-in.
        let root = f.session(&f.root_id.clone(), true).await;
        assert_matches(
            &f.configure(&root, json!({ "tenantId": globex, "accessDays": 10 }))
                .await
                .unwrap(),
            json!({ "tenantId": globex, "accessDays": 10, "configured": true }),
        );
        // The tenant's durations shape new guests.
        f.configure(&owner, json!({ "inbound": { "allowGuests": true } }))
            .await
            .unwrap();
        let guest = f.seed_guest("gina", json!({})).await;
        let invitation = &f.list_invitations(&owner, json!({})).await[0];
        assert_eq!(invitation["accessDays"], 30);
        assert_eq!(
            f.get(&owner, &guest).await.unwrap()["reviewDueAt"],
            n(f.now() + 14.0 * DAY)
        );
    });
}

#[test]
fn admits_guests_only_as_the_hosts_inbound_settings_allow() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let (globex, _, _) = f.other_organization("Globex", "globex").await;
        f.verify_domain(&globex, "globex.test").await;
        f.verify_domain(&tenant_id, "acme.example").await;
        let invite = |email: &str| f.invite(&owner, json!({ "email": email }));
        let refused = |result: IamResult<Value>, message: Option<&str>| {
            let error = error_of(result);
            assert_eq!((code(&error), error.status), ("GUEST_NOT_ALLOWED", 403));
            if let Some(message) = message {
                assert_eq!(error.message, message);
            }
        };
        // An address at the host's own verified domain belongs to a member.
        refused(
            invite("someone@acme.example").await,
            Some(
                "acme.example is a verified domain of this organization: invite the person as a member",
            ),
        );
        f.configure(&owner, json!({ "inbound": { "allowGuests": false } }))
            .await
            .unwrap();
        refused(
            invite("a@partner.test").await,
            Some("This organization does not accept guests"),
        );
        f.configure(
            &owner,
            json!({ "inbound": {
                "allowGuests": true,
                "allowedDomains": ["partner.test"],
                "blockedDomains": ["bad.partner.test"],
            } }),
        )
        .await
        .unwrap();
        refused(
            invite("a@agency.test").await,
            Some("This organization accepts guests only from its allowed domains"),
        );
        refused(
            invite("a@bad.partner.test").await,
            Some("This organization does not accept guests from bad.partner.test"),
        );
        refused(invite("a@deeper.bad.partner.test").await, None);
        assert_eq!(
            invite("a@sub.partner.test").await.unwrap()["status"],
            "pending"
        );
        assert_eq!(invite("b@partner.test").await.unwrap()["status"], "pending");
        // A partner entry admits its people over the defaults, and a refusing one wins over everything else.
        refused(invite("c@globex.test").await, None);
        f.configure(
            &owner,
            json!({ "inbound": { "allowGuests": false, "partners": [{ "tenantId": globex, "allow": true }] } }),
        )
        .await
        .unwrap();
        assert_eq!(
            invite("c@globex.test").await.unwrap()["homeTenantId"],
            json!(globex)
        );
        refused(invite("d@partner.test").await, None);
        f.configure(
            &owner,
            json!({ "inbound": {
                "allowGuests": true,
                "allowedDomains": [],
                "partners": [{ "tenantId": globex, "allow": false }],
            } }),
        )
        .await
        .unwrap();
        refused(
            invite("e@globex.test").await,
            Some("This organization does not accept guests from the person\u{2019}s organization"),
        );
        f.configure(
            &owner,
            json!({ "inbound": {
                "partners": [{ "tenantId": globex, "allow": true }],
                "blockedDomains": ["globex.test"],
            } }),
        )
        .await
        .unwrap();
        refused(
            invite("e@globex.test").await,
            Some("This organization does not accept guests from globex.test"),
        );

        // Redemption checks the settings again.
        f.configure(
            &owner,
            json!({ "inbound": { "blockedDomains": [], "allowGuests": true, "partners": [] } }),
        )
        .await
        .unwrap();
        invite("late@partner.test").await.unwrap();
        f.configure(
            &owner,
            json!({ "inbound": { "blockedDomains": ["partner.test"] } }),
        )
        .await
        .unwrap();
        let token = f.token_for("late@partner.test").await;
        assert_code(
            f.redeem(json!({ "token": token, "name": "Late", "password": password("Late") }))
                .await,
            "GUEST_NOT_ALLOWED",
        );
    });
}

#[test]
fn respects_the_home_organizations_outbound_settings_without_revealing_them() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let (globex, _, globex_owner) = f.other_organization("Globex", "globex").await;
        let (initech, _, initech_owner) = f.other_organization("Initech", "initech").await;
        f.verify_domain(&globex, "globex.test").await;
        let outbound = |input: Value| {
            f.configure(
                &globex_owner,
                json!({ "tenantId": globex, "outbound": input }),
            )
        };
        let message = "The person\u{2019}s organization does not allow its members to join this organization as guests";
        outbound(json!({ "allowGuestInvitations": false }))
            .await
            .unwrap();
        let error = assert_code(
            f.invite(&owner, json!({ "email": "gil@globex.test" }))
                .await,
            "GUEST_NOT_ALLOWED",
        );
        assert_eq!((error.status, error.message.as_str()), (403, message));
        // A partner entry for the host lets its people join there (and only there).
        outbound(json!({ "partners": [{ "tenantId": tenant_id, "allow": true }] }))
            .await
            .unwrap();
        let invitation = f
            .invite(&owner, json!({ "email": "gil@globex.test" }))
            .await
            .unwrap();
        assert_eq!(invitation["homeTenantId"], json!(globex));
        let error = assert_code(
            f.invite(
                &initech_owner,
                json!({ "tenantId": initech, "email": "gil@globex.test" }),
            )
            .await,
            "GUEST_NOT_ALLOWED",
        );
        assert_eq!(error.message, message);
        // The home organization can change its mind before redemption.
        outbound(json!({ "partners": [{ "tenantId": tenant_id, "allow": false }], "allowGuestInvitations": true }))
            .await
            .unwrap();
        let token = f.token_for("gil@globex.test").await;
        let error = assert_code(
            f.redeem(json!({ "token": token, "name": "Gil", "password": password("Gil") }))
                .await,
            "GUEST_NOT_ALLOWED",
        );
        assert_eq!(error.message, message);
        // Globex's own audit trail stays its own.
        assert!(!f.audit(&globex).await.iter().any(|event| {
            event["action"]
                .as_str()
                .unwrap()
                .starts_with("guest:invite")
        }));
    });
}

// --- guest hardening ------------------------------------------------------------------------------------------

#[test]
fn reads_an_addresss_domain_as_verified_domains_and_domain_lists_spell_it() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let (globex, _, globex_owner) = f.other_organization("Globex", "globex").await;
        f.verify_domain(&globex, "globex.test").await;
        f.verify_domain(&tenant_id, "acme.example").await;
        let invite = |email: &str| f.invite(&owner, json!({ "email": email }));
        // An invitation stored with a trailing dot, as it was before addresses were normalized: redemption still
        // finds Globex behind the address.
        let legacy = invite("lee@globex.test").await.unwrap();
        let mut stored = f
            .record("guestInvitations", legacy["id"].as_str().unwrap())
            .await
            .unwrap();
        stored.insert("email".into(), json!("lee@globex.test."));
        f.put("guestInvitations", stored).await;
        f.configure(
            &globex_owner,
            json!({ "tenantId": globex, "outbound": { "allowGuestInvitations": false } }),
        )
        .await
        .unwrap();
        let outbound = "The person\u{2019}s organization does not allow its members to join this organization as guests";
        // A trailing dot (which mail relays drop) reaches the same mailbox: Globex's outbound refusal still applies.
        for email in ["gil@globex.test.", "gil@GLOBEX.test."] {
            let error = error_of(invite(email).await);
            assert_eq!(
                (code(&error), error.message.as_str()),
                ("GUEST_NOT_ALLOWED", outbound),
                "{email}"
            );
        }
        let token = f.token_for("lee@globex.test").await;
        let error = assert_code(
            f.redeem(json!({ "token": token, "name": "Lee", "password": password("Lee") }))
                .await,
            "GUEST_NOT_ALLOWED",
        );
        assert_eq!(error.message, outbound);
        // The host's own verified domain, however it is spelled, belongs to members.
        let error = assert_code(invite("someone@acme.example.").await, "GUEST_NOT_ALLOWED");
        assert_eq!(
            error.message,
            "acme.example is a verified domain of this organization: invite the person as a member"
        );
        // Internationalized domains are compared in their punycode form, as mail transports send them.
        f.configure(
            &owner,
            json!({ "inbound": { "blockedDomains": ["xn--bcher-kva.example"] } }),
        )
        .await
        .unwrap();
        for email in [
            "bob@bücher.example",
            "bob@BÜCHER.example.",
            "bob@ｂüｃｈｅｒ.example",
        ] {
            let error = error_of(invite(email).await);
            assert_eq!(
                (code(&error), error.message.as_str()),
                (
                    "GUEST_NOT_ALLOWED",
                    "This organization does not accept guests from xn--bcher-kva.example"
                ),
                "{email}"
            );
        }
        // A domain that is no DNS name is refused outright.
        for email in ["x@partner..test", "x@[192.0.2.1]", "x@partner.test.."] {
            let error = error_of(invite(email).await);
            assert_eq!(code(&error), "INVALID_INPUT", "{email}");
        }
        // An admitted address is stored and emailed in its canonical spelling.
        let ann = invite("Ann@Partner.Test.").await.unwrap();
        assert_eq!(ann["email"], "ann@partner.test");
        f.token_for("ann@partner.test").await;
        assert_code(invite("ann@partner.test.").await, "CONFLICT");
    });
}

#[test]
fn needs_iam_guests_manage_to_name_someone_else_as_the_sponsor() {
    run(|| async {
        let f = fixture().await;
        let cfo = f.member("cfo").await;
        let (lead, lead_credential) = f.administrator("lead", &["iam:guests:invite"]).await;
        let f = &f;
        let invite = |credential: CredentialInput, email: &str, sponsor: Option<&str>| {
            let mut input = json!({ "email": email });
            if let Some(sponsor) = sponsor {
                input["sponsorId"] = json!(sponsor);
            }
            async move { f.invite(&credential, input).await }
        };
        // Whether the person exists or not, the refusal is the same.
        for sponsor in [cfo.as_str(), "missing"] {
            let error =
                error_of(invite(lead_credential.clone(), "a@partner.test", Some(sponsor)).await);
            assert_eq!(
                (code(&error), error.status),
                ("ACCESS_DENIED", 403),
                "{sponsor}"
            );
        }
        f.dispatch().await;
        assert!(f.sent("guest-invitation").is_empty());
        // The refusal is audited as a denial.
        assert!(
            f.audit_of("iam:guests:invite")
                .await
                .iter()
                .any(|event| event["outcome"] == "deny" && event["actorId"] == json!(lead))
        );
        // The inviter sponsors their own guests, named or not.
        assert_eq!(
            invite(lead_credential.clone(), "a@partner.test", None)
                .await
                .unwrap()["sponsorId"],
            json!(lead)
        );
        assert_eq!(
            invite(lead_credential.clone(), "b@partner.test", Some(&lead))
                .await
                .unwrap()["sponsorId"],
            json!(lead)
        );
        // Someone who could give a guest another sponsor may name one.
        let (_, manager) = f
            .administrator("manager", &["iam:guests:invite", "iam:guests:manage"])
            .await;
        assert_eq!(
            invite(manager, "c@partner.test", Some(&cfo)).await.unwrap()["sponsorId"],
            json!(cfo)
        );
    });
}

#[test]
fn asks_a_caller_who_cannot_sponsor_to_name_a_sponsor() {
    run(|| async {
        let f = fixture().await;
        // A guest who may invite guests cannot vouch for them: they must name a sponsor.
        let gina = f.seed_guest("gina", json!({})).await;
        f.grant(
            &gina,
            json!([{ "effect": "allow", "actions": ["iam:guests:invite"], "resources": ["*"] }]),
        )
        .await;
        let as_gina = f.sign_in(&gina).await;
        let error = assert_code(
            f.invite(&as_gina, json!({ "email": "a@partner.test" }))
                .await,
            "INVALID_SPONSOR",
        );
        assert!(error.message.starts_with("Name a sponsor (sponsorId)"));
        // Naming the owner needs iam:guests:manage, which the guest lacks: an audited denial.
        let error = assert_code(
            f.invite(
                &as_gina,
                json!({ "email": "a@partner.test", "sponsorId": f.owner_id }),
            )
            .await,
            "ACCESS_DENIED",
        );
        assert_eq!(error.status, 403);
    });
}

#[test]
fn says_how_to_invite_a_former_guest_again() {
    run(|| async {
        let f = fixture().await;
        let owner = f.owner_credential.clone();
        let gina = f.seed_guest("gina", json!({})).await;
        // A removed guest stays disabled with its account closed (as guests.remove leaves it).
        f.set_identity(&gina, json!({ "status": "disabled" })).await;
        let mut account = f.record("guestAccounts", &gina).await.unwrap();
        account.insert("status".into(), json!("removed"));
        f.put("guestAccounts", account).await;
        let error = assert_code(
            f.attest(&owner, json!({ "identityId": gina })).await,
            "INVALID_TRANSITION",
        );
        assert!(
            error
                .message
                .contains("delete the account and invite the person again")
        );
        let error = assert_code(
            f.invite(&owner, json!({ "email": "gina@partner.test" }))
                .await,
            "CONFLICT",
        );
        assert!(error.message.contains("former guest"));
    });
}

// --- renewing guest access ------------------------------------------------------------------------------------

#[test]
fn lets_the_sponsor_or_an_administrator_renew_access_never_a_guest() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let gina = f.seed_guest("gina", json!({ "sponsorId": alice })).await;
        let hal = f.seed_guest("hal", json!({ "sponsorId": alice })).await;
        // Hal holds iam:guests:manage, yet guests renew nobody.
        f.grant(
            &hal,
            json!([{ "effect": "allow", "actions": ["iam:guests:manage"], "resources": ["*"] }]),
        )
        .await;
        let first_end = f.now() + 90.0 * DAY;
        assert_eq!(
            f.record("identities", &gina).await.unwrap()["expiresAt"],
            n(first_end)
        );

        // A month in, the sponsor renews for 60 days without any permission.
        f.advance(30.0 * DAY);
        let as_alice = f.sign_in(&alice).await;
        let second_end = f.now() + 60.0 * DAY;
        let renewed = f
            .attest(&as_alice, json!({ "identityId": gina, "days": 60 }))
            .await
            .unwrap();
        assert_matches(
            &renewed,
            json!({
                "expiresAt": n(second_end),
                "attestedAt": n(f.now()),
                "attestedBy": alice,
                "reviewDueAt": n(second_end),
                "accountStatus": "active",
            }),
        );
        let account = f.record("guestAccounts", &gina).await.unwrap();
        assert_eq!(account["grantsEndAt"], n(second_end));
        for days in [json!(0), json!(366), json!(1.5), json!("30")] {
            let error = error_of(
                f.attest(&as_alice, json!({ "identityId": gina, "days": days }))
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT", "{days}");
        }

        // Nobody else renews without iam:guests:manage; guests never renew, themselves or others.
        let as_bob = f.sign_in(&bob).await;
        assert_code(
            f.attest(&as_bob, json!({ "identityId": gina })).await,
            "ACCESS_DENIED",
        );
        let as_gina = f.sign_in(&gina).await;
        assert_code(
            f.attest(&as_gina, json!({ "identityId": gina })).await,
            "ACCESS_DENIED",
        );
        let as_hal = f.sign_in(&hal).await;
        for identity_id in [&hal, &gina] {
            let error = error_of(
                f.attest(&as_hal, json!({ "identityId": identity_id }))
                    .await,
            );
            assert_eq!((code(&error), error.status), ("ACCESS_DENIED", 403));
        }
        let owned = f.owner_sign_in().await;
        assert_code(
            f.attest(&owned, json!({ "identityId": "missing" })).await,
            "NOT_FOUND",
        );
        assert_code(
            f.attest(&owned, json!({ "identityId": alice })).await,
            "NOT_FOUND",
        );
        let third_end = f.now() + 200.0 * DAY;
        f.attest(&owned, json!({ "identityId": gina, "days": 200 }))
            .await
            .unwrap();
        assert_eq!(
            f.record("identities", &gina).await.unwrap()["expiresAt"],
            n(third_end)
        );

        let attests: Vec<Record> = f
            .audit(&tenant_id)
            .await
            .into_iter()
            .filter(|event| event["action"] == "guest:attest" && event["resourceId"] == json!(gina))
            .collect();
        let actors: Vec<(Value, Value)> = attests
            .iter()
            .map(|event| {
                (
                    event["actorId"].clone(),
                    event["metadata"]["asSponsor"].clone(),
                )
            })
            .collect();
        assert_eq!(
            actors,
            [
                (json!(alice), json!(true)),
                (json!(f.owner_id), json!(false))
            ]
        );
        assert_matches(
            &attests[0]["metadata"],
            json!({ "days": 60, "expiresAt": n(second_end), "previousExpiresAt": n(first_end) }),
        );
        // The sponsor's renewal needs no permission check; the administrator's goes through one.
        let manage: Vec<Value> = f
            .audit(&tenant_id)
            .await
            .into_iter()
            .filter(|event| event["action"] == "iam:guests:manage" && event["outcome"] == "allow")
            .map(|event| event["actorId"].clone())
            .collect();
        assert_eq!(manage, [json!(f.owner_id)]);
    });
}

#[test]
fn refuses_to_renew_a_guest_whose_access_ended_or_who_is_disabled() {
    run(|| async {
        let f = fixture().await;
        let alice = f.member("alice").await;
        let ivy = f
            .seed_guest("ivy", json!({ "sponsorId": alice, "accessDays": 1 }))
            .await;
        let jo = f.seed_guest("jo", json!({ "sponsorId": alice })).await;
        f.set_identity(&jo, json!({ "status": "disabled" })).await;
        f.advance(2.0 * DAY);
        let as_alice = f.sign_in(&alice).await;
        for identity_id in [&ivy, &jo] {
            let error = error_of(
                f.attest(&as_alice, json!({ "identityId": identity_id }))
                    .await,
            );
            assert_eq!((code(&error), error.status), ("INVALID_TRANSITION", 409));
        }
        // The ended guest reads as expired straight away.
        let owner = f.owner_sign_in().await;
        assert_matches(
            &f.get(&owner, &ivy).await.unwrap(),
            json!({ "accountStatus": "expired", "status": "active" }),
        );
    });
}

// --- sponsors -------------------------------------------------------------------------------------------------

#[test]
fn moves_a_guest_to_another_sponsor() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let carol = f.member("carol").await;
        f.set_identity(&carol, json!({ "status": "disabled" }))
            .await;
        let gina = f.seed_guest("gina", json!({ "sponsorId": alice })).await;
        let hal = f.seed_guest("hal", json!({})).await;
        let set_sponsor = |sponsor_id: &str, identity_id: &str| {
            reply_future(f.iam.api.guests.set_sponsor(
                &owner,
                body(json!({ "tenantId": tenant_id, "identityId": identity_id, "sponsorId": sponsor_id })),
            ))
        };
        for sponsor_id in [gina.as_str(), hal.as_str(), carol.as_str(), "missing"] {
            let error = error_of(set_sponsor(sponsor_id, &gina).await);
            assert_eq!(code(&error), "INVALID_SPONSOR", "{sponsor_id}");
        }
        assert_code(set_sponsor("", &gina).await, "INVALID_INPUT");
        for identity_id in ["missing", bob.as_str()] {
            let error = error_of(set_sponsor(&bob, identity_id).await);
            assert_eq!(code(&error), "NOT_FOUND", "{identity_id}");
        }
        let moved = set_sponsor(&bob, &gina).await.unwrap();
        assert_matches(
            &moved,
            json!({ "sponsorId": bob, "sponsorName": "bob", "sponsorMissing": false }),
        );
        assert_eq!(
            f.record("identities", &gina).await.unwrap()["guest"]["sponsorId"],
            json!(bob)
        );
        let as_bob = f.sign_in(&bob).await;
        let as_alice = f.sign_in(&alice).await;
        let f = &f;
        let mine = |credential: CredentialInput| async move {
            ok(f.iam
                .api
                .guests
                .mine(&credential, body(json!({ "tenantId": f.tenant_id })))
                .await)
        };
        assert_eq!(
            ids(&mine(as_bob.clone()).await, "identityId"),
            [gina.clone()]
        );
        assert_eq!(mine(as_alice.clone()).await, json!([]));
        // The former sponsor lost the right to renew; the new one has it.
        assert_code(
            f.attest(&as_alice, json!({ "identityId": gina })).await,
            "ACCESS_DENIED",
        );
        assert_eq!(
            f.attest(&as_bob, json!({ "identityId": gina }))
                .await
                .unwrap()["attestedBy"],
            json!(bob)
        );
        let listed = ok(f
            .iam
            .api
            .guests
            .list(
                &owner,
                body(json!({ "tenantId": tenant_id, "sponsorId": bob })),
            )
            .await);
        assert_eq!(ids(&listed["guests"], "identityId"), [gina.clone()]);
        let event = f.audit_of("guest:sponsor-change").await.remove(0);
        assert_matches(
            &Value::Object(event),
            json!({
                "actorId": f.owner_id,
                "resourceId": gina,
                "metadata": { "from": alice, "to": bob, "reason": "administrator" },
            }),
        );
    });
}

async fn reply_future<O: serde::Serialize>(
    future: impl std::future::Future<Output = IamResult<Reply<O>>>,
) -> IamResult<Value> {
    reply(future.await)
}

#[test]
fn never_lets_a_guest_choose_a_sponsor() {
    run(|| async {
        let f = fixture().await;
        let gina = f.seed_guest("gina", json!({})).await;
        let hal = f.seed_guest("hal", json!({})).await;
        f.grant(
            &gina,
            json!([{ "effect": "allow", "actions": ["iam:guests:manage"], "resources": ["*"] }]),
        )
        .await;
        let as_gina = f.sign_in(&gina).await;
        for identity_id in [&gina, &hal] {
            let error = fails(
                f.iam
                    .api
                    .guests
                    .set_sponsor(
                        &as_gina,
                        body(json!({ "tenantId": f.tenant_id, "identityId": identity_id, "sponsorId": f.owner_id })),
                    )
                    .await,
            );
            assert_eq!(code(&error), "ACCESS_DENIED");
        }
        let denials = f
            .audit_of("iam:guests:manage")
            .await
            .into_iter()
            .filter(|event| event["outcome"] == "deny" && event["actorId"] == json!(gina))
            .count();
        assert_eq!(denials, 2);
    });
}

// --- the guest directory --------------------------------------------------------------------------------------

#[test]
fn pages_and_filters_the_guest_directory() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let alice = f.member("alice").await;
        let zed = f.seed_guest("zed", json!({ "accessDays": 5 })).await;
        let amy = f.seed_guest("amy", json!({ "sponsorId": alice })).await;
        let max = f.seed_guest("max", json!({ "accessDays": 20 })).await;
        let list = |input: Value| {
            let mut input = input;
            input["tenantId"] = json!(tenant_id);
            reply_future(f.iam.api.guests.list(&owner, body(input)))
        };
        let all = list(json!({})).await.unwrap();
        assert_eq!(all["total"], 3);
        assert_eq!(
            ids(&all["guests"], "identityId"),
            [amy.clone(), max.clone(), zed.clone()]
        );
        let page = list(json!({ "limit": 1, "offset": 1 })).await.unwrap();
        assert_eq!(page["total"], 3);
        assert_eq!(ids(&page["guests"], "identityId"), [max.clone()]);
        let expiring = list(json!({ "expiringWithinDays": 10 })).await.unwrap();
        assert_eq!(ids(&expiring["guests"], "identityId"), [zed.clone()]);
        let by_alice = list(json!({ "sponsorId": alice })).await.unwrap();
        assert_eq!(ids(&by_alice["guests"], "identityId"), [amy.clone()]);
        f.advance(6.0 * DAY);
        let owner_now = f.owner_sign_in().await;
        let expired = ok(f
            .iam
            .api
            .guests
            .list(
                &owner_now,
                body(json!({ "tenantId": tenant_id, "status": "expired" })),
            )
            .await);
        assert_eq!(ids(&expired["guests"], "identityId"), [zed.clone()]);
        for input in [
            json!({ "limit": 0 }),
            json!({ "limit": 1001 }),
            json!({ "offset": -1 }),
            json!({ "status": "gone" }),
            json!({ "sponsorId": "" }),
            json!({ "expiringWithinDays": 3651 }),
        ] {
            let error = error_of(list(input.clone()).await);
            assert_eq!(code(&error), "INVALID_INPUT", "{input}");
        }
        // The guest view carries the sponsor's name, the access end, the next review and the last sign-in.
        let view = f.get(&owner_now, &amy).await.unwrap();
        let invitation_id = f.record("guestAccounts", &amy).await.unwrap()["invitationId"].clone();
        let created = f.record("guestAccounts", &amy).await.unwrap()["redeemedAt"]
            .as_f64()
            .unwrap();
        assert_eq!(
            view,
            json!({
                "identityId": amy,
                "tenantId": tenant_id,
                "name": "amy",
                "email": "amy@partner.test",
                "status": "active",
                "accountStatus": "active",
                "sponsorId": alice,
                "sponsorName": "alice",
                "sponsorMissing": false,
                "homeDomain": "partner.test",
                "invitationId": invitation_id,
                "invitedBy": f.owner_id,
                "redeemedAt": n(created),
                "reviewDueAt": n(created + 90.0 * DAY),
                "expiresAt": n(created + 90.0 * DAY),
            })
        );
    });
}

// --- guest jobs -------------------------------------------------------------------------------------------------

fn zero() -> Value {
    json!({
        "invitationsExpired": 0,
        "accountsExpired": 0,
        "accountsRestored": 0,
        "sponsorsMissing": 0,
        "ownersNotified": 0,
        "partnersRemoved": 0,
    })
}

fn with(changes: Value) -> Value {
    let mut result = zero();
    for (key, value) in changes.as_object().unwrap() {
        result[key] = value.clone();
    }
    result
}

#[test]
fn sweeps_lapsed_invitations_ended_guests_and_missing_sponsors() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        f.invite(
            &f.owner_credential,
            json!({ "email": "late@partner.test", "expiresInDays": 1 }),
        )
        .await
        .unwrap();
        let gina = f
            .seed_guest("gina", json!({ "sponsorId": alice, "accessDays": 3 }))
            .await;
        let hal = f
            .seed_guest("hal", json!({ "sponsorId": bob, "accessDays": 30 }))
            .await;
        let gina_end = f.record("identities", &gina).await.unwrap()["expiresAt"].clone();
        assert_eq!(f.sweep(None).await, zero());
        f.advance(2.0 * DAY);
        assert_eq!(
            f.sweep(None).await,
            with(json!({ "invitationsExpired": 1 }))
        );
        let late = f
            .find(
                "guestInvitations",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("email", "late@partner.test"),
            )
            .await
            .remove(0);
        assert_eq!(late["status"], "expired");
        assert!(late.get("uniqueKey").is_none());

        // An ended guest reads as expired at once; the identity worker disables it and the sweep records it.
        f.advance(2.0 * DAY);
        let owner = f.owner_sign_in().await;
        let expired = ok(f
            .iam
            .api
            .guests
            .list(
                &owner,
                body(json!({ "tenantId": tenant_id, "status": "expired" })),
            )
            .await);
        assert_eq!(ids(&expired["guests"], "identityId"), [gina.clone()]);
        f.set_identity(&gina, json!({ "status": "disabled" })).await;
        assert_eq!(f.sweep(None).await, with(json!({ "accountsExpired": 1 })));
        assert_eq!(f.sweep(None).await, zero());
        assert_matches(
            &Value::Object(f.record("guestAccounts", &gina).await.unwrap()),
            json!({ "status": "expired", "endedAt": gina_end }),
        );
        // An administrator gives the guest a later end and enables them again: the account comes back.
        f.set_identity(
            &gina,
            json!({ "expiresAt": n(f.now() + 10.0 * DAY), "status": "active" }),
        )
        .await;
        assert_eq!(f.sweep(None).await, with(json!({ "accountsRestored": 1 })));
        assert_matches(
            &f.get(&owner, &gina).await.unwrap(),
            json!({ "accountStatus": "active", "status": "active" }),
        );
        assert!(
            f.record("guestAccounts", &gina)
                .await
                .unwrap()
                .get("endedAt")
                .is_none()
        );

        // A sponsor who can no longer sponsor leaves the guest flagged, and the owners hear about it once per loss.
        f.dispatch().await;
        f.inbox.lock().unwrap().clear();
        f.set_identity(&bob, json!({ "status": "disabled" })).await;
        assert_eq!(
            f.sweep(None).await,
            with(json!({ "sponsorsMissing": 1, "ownersNotified": 1 }))
        );
        assert_eq!(f.sweep(None).await, zero());
        f.dispatch().await;
        let notices = f.sent("guest-sponsor-missing");
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].to, "owner@acme.test");
        assert_eq!(
            Value::Object(notices[0].payload.clone()),
            json!({
                "tenantId": tenant_id,
                "tenantName": "Acme",
                "guestId": hal,
                "guestName": "hal",
                "guestEmail": "hal@partner.test",
                "sponsorName": "bob",
            })
        );
        assert_matches(
            &f.get(&owner, &hal).await.unwrap(),
            json!({ "sponsorMissing": true, "sponsorId": bob }),
        );
        // The sponsor returns: the flag clears. They leave again: a new loss, a new notice.
        f.set_identity(&bob, json!({ "status": "active" })).await;
        assert_eq!(f.sweep(None).await, zero());
        assert_eq!(
            f.get(&owner, &hal).await.unwrap()["sponsorMissing"],
            json!(false)
        );
        f.set_identity(&bob, json!({ "status": "disabled" })).await;
        assert_eq!(
            f.sweep(None).await,
            with(json!({ "sponsorsMissing": 1, "ownersNotified": 1 }))
        );
        // A new sponsor settles it.
        let owner = f.owner_sign_in().await;
        ok(f.iam
            .api
            .guests
            .set_sponsor(
                &owner,
                body(json!({ "tenantId": tenant_id, "identityId": hal, "sponsorId": alice })),
            )
            .await);
        assert_eq!(
            f.get(&owner, &hal).await.unwrap()["sponsorMissing"],
            json!(false)
        );
        assert_eq!(f.sweep(None).await, zero());
        let events: Vec<(Value, Value, Value)> = f
            .audit(&tenant_id)
            .await
            .into_iter()
            .filter(|event| {
                event["action"] == "guest:expire" || event["action"] == "guest:sponsor-missing"
            })
            .map(|event| {
                (
                    event["action"].clone(),
                    event["actorId"].clone(),
                    event["resourceId"].clone(),
                )
            })
            .collect();
        assert_eq!(
            events,
            [
                (
                    json!("guest:expire"),
                    json!("deployment-operator"),
                    json!(gina)
                ),
                (
                    json!("guest:sponsor-missing"),
                    json!("deployment-operator"),
                    json!(hal)
                ),
                (
                    json!("guest:sponsor-missing"),
                    json!("deployment-operator"),
                    json!(hal)
                ),
            ]
        );

        // Partner entries naming an organization that was purged since are dropped.
        let (initech, _, _) = f.other_organization("Initech", "initech").await;
        f.configure(
            &owner,
            json!({
                "inbound": { "partners": [{ "tenantId": initech, "allow": true }] },
                "outbound": { "partners": [{ "tenantId": initech, "allow": false }] },
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            f.sweep(Some(json!({ "tenantId": tenant_id }))).await,
            zero()
        );
        let store = f.store();
        let purged = initech.clone();
        store
            .transaction(|tx| async move { tx.delete("tenants", &purged).await })
            .await
            .unwrap();
        assert_eq!(f.sweep(Some(json!({ "tenantId": initech }))).await, zero());
        assert_eq!(
            f.sweep(Some(json!({ "tenantId": tenant_id }))).await,
            with(json!({ "partnersRemoved": 2 }))
        );
        let settings = ok(f
            .iam
            .api
            .guests
            .get_settings(&owner, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(
            (
                settings["inbound"]["partners"].clone(),
                settings["outbound"]["partners"].clone()
            ),
            (json!([]), json!([]))
        );
        assert_matches(
            &Value::Object(f.audit_of("guest:settings").await.pop().unwrap()),
            json!({ "actorId": "deployment-operator", "metadata": { "partnersRemoved": 2 } }),
        );
    });
}

#[test]
fn reminds_sponsors_of_reviews_and_access_ends_once_per_due_date() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let alice = f.member("alice").await;
        f.configure(&f.owner_credential, json!({ "reviewEveryDays": 30 }))
            .await
            .unwrap();
        let gina = f.seed_guest("gina", json!({ "sponsorId": alice })).await;
        let hal = f
            .seed_guest("hal", json!({ "sponsorId": alice, "accessDays": 10 }))
            .await;
        let start = f.now();
        for days in [json!(0), json!(91), json!(1.5)] {
            let error = error_of(f.reminders(Some(json!({ "withinDays": days }))).await);
            assert_eq!(code(&error), "INVALID_INPUT", "{days}");
        }
        f.dispatch().await;
        f.inbox.lock().unwrap().clear();
        // Hal's access ends in ten days; Gina's review is a month out.
        assert_eq!(
            f.reminders(None).await.unwrap(),
            json!({
                "sent": [{ "tenantId": tenant_id, "guestId": hal, "sponsorId": alice, "dueAt": n(start + 10.0 * DAY) }],
                "skipped": { "inactive": 0, "quiet": 0 },
            })
        );
        f.dispatch().await;
        let reminder = f.sent("guest-review").remove(0);
        assert_eq!(reminder.to, "alice@acme.test");
        assert_eq!(
            Value::Object(reminder.payload.clone()),
            json!({
                "tenantId": tenant_id,
                "tenantName": "Acme",
                "guestId": hal,
                "guestName": "hal",
                "guestEmail": "hal@partner.test",
                "dueAt": iso(start + 10.0 * DAY),
                "reviewDueAt": iso(start + 10.0 * DAY),
                "expiresAt": iso(start + 10.0 * DAY),
            })
        );
        // Nothing new: nothing sent.
        assert_eq!(
            f.reminders(None).await.unwrap(),
            json!({ "sent": [], "skipped": { "inactive": 0, "quiet": 1 } })
        );
        // Seventeen days on, Gina's review is near; Hal's access has ended, so nobody is reminded about him.
        f.advance(17.0 * DAY);
        assert_eq!(
            f.reminders(None).await.unwrap()["sent"],
            json!([{ "tenantId": tenant_id, "guestId": gina, "sponsorId": alice, "dueAt": n(start + 30.0 * DAY) }])
        );
        // Renewing moves the due date; the new one is reminded when it nears.
        let as_alice = f.sign_in(&alice).await;
        f.attest(&as_alice, json!({ "identityId": gina, "days": 20 }))
            .await
            .unwrap();
        assert_eq!(f.reminders(None).await.unwrap()["sent"], json!([]));
        f.advance(10.0 * DAY);
        assert_eq!(
            f.reminders(None).await.unwrap()["sent"],
            json!([{ "tenantId": tenant_id, "guestId": gina, "sponsorId": alice, "dueAt": n(start + 37.0 * DAY) }])
        );
        let mut events: Vec<(Value, Value)> = f
            .audit_of("guest:review-reminder")
            .await
            .into_iter()
            .map(|event| (event["actorId"].clone(), event["resourceId"].clone()))
            .collect();
        events.sort_by_key(|(_, resource)| resource.to_string());
        let mut expected = vec![
            (json!("deployment-operator"), json!(gina)),
            (json!("deployment-operator"), json!(gina)),
            (json!("deployment-operator"), json!(hal)),
        ];
        expected.sort_by_key(|(_, resource)| resource.to_string());
        assert_eq!(events, expected);
        // A suspended organization is left alone.
        let mut tenant = f.record("tenants", &tenant_id).await.unwrap();
        tenant.insert("status".into(), json!("suspended"));
        f.put("tenants", tenant).await;
        f.advance(40.0 * DAY);
        assert_eq!(
            f.reminders(Some(json!({ "tenantId": tenant_id })))
                .await
                .unwrap(),
            json!({ "sent": [], "skipped": { "inactive": 1, "quiet": 0 } })
        );
    });
}

#[test]
fn reminds_a_sponsor_of_an_overdue_review_once_also_for_a_guest_without_an_end() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let alice = f.member("alice").await;
        f.configure(&f.owner_credential, json!({ "reviewEveryDays": 30 }))
            .await
            .unwrap();
        let gina = f.seed_guest("gina", json!({ "sponsorId": alice })).await;
        f.set_identity(&gina, json!({ "expiresAt": null })).await;
        let start = f.now();
        f.advance(16.0 * DAY);
        assert_eq!(
            f.reminders(None).await.unwrap()["sent"],
            json!([{ "tenantId": tenant_id, "guestId": gina, "sponsorId": alice, "dueAt": n(start + 30.0 * DAY) }])
        );
        // The review goes unanswered for months while the job keeps running.
        for cycle in 0..30 {
            f.advance(5.0 * DAY);
            assert_eq!(
                f.reminders(None).await.unwrap()["sent"],
                json!([]),
                "cycle {cycle}"
            );
        }
        f.dispatch().await;
        assert_eq!(f.sent("guest-review").len(), 1);
        // Renewed, the next review is reminded as usual.
        let as_alice = f.sign_in(&alice).await;
        f.attest(&as_alice, json!({ "identityId": gina, "days": 90 }))
            .await
            .unwrap();
        f.advance(20.0 * DAY);
        assert_eq!(
            f.reminders(None).await.unwrap()["sent"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    });
}

#[test]
fn needs_an_email_delivery_callback_for_reminders() {
    run(|| async {
        let f = organization(|_| {}).await;
        let error = f.iam.guests.send_review_reminders(None).await.unwrap_err();
        assert_eq!(code(&error), "DELIVERY_REQUIRED");
        assert_eq!(f.iam.guests.sweep(None).await.unwrap(), zero());
        // Invitations need it too.
        let error = fails(
            f.iam
                .api
                .guests
                .invite(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "email": "a@partner.test" })),
                )
                .await,
        );
        assert_eq!(code(&error), "DELIVERY_REQUIRED");
    });
}

// --- guests when people leave -----------------------------------------------------------------------------------

/// The owner as an authenticated principal, as the operation envelope hands it to a mutation.
async fn owner_principal(f: &Guests) -> better_iam_core::AuthenticatedPrincipal {
    f.iam
        .ctx
        .principals()
        .unwrap()
        .authenticate(&f.owner_credential)
        .await
        .unwrap()
}

async fn identity(f: &Guests, id: &str) -> Identity {
    better_iam_server::port::decode(f.record("identities", id).await.unwrap()).unwrap()
}

#[test]
fn hands_guests_to_a_successor_at_offboarding_or_flags_them() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let carol = f.member("carol").await;
        let dave = f.member("dave").await;
        let gina = f.seed_guest("gina", json!({ "sponsorId": alice })).await;
        let hal = f.seed_guest("hal", json!({ "sponsorId": alice })).await;
        let ivy = f.seed_guest("ivy", json!({ "sponsorId": carol })).await;
        let jo = f.seed_guest("jo", json!({ "sponsorId": dave })).await;
        let principal = owner_principal(&f).await;
        let ctx = f.iam.ctx.clone();
        let hand_over = |leaver: Identity, successor: Option<Identity>| {
            let ctx = ctx.clone();
            let principal = principal.clone();
            async move {
                ctx.store
                    .clone()
                    .transaction(|tx| async move {
                        better_iam_server::guests::hand_over_guests(
                            &ctx,
                            &tx,
                            &principal,
                            &leaver,
                            successor.as_ref(),
                        )
                        .await
                    })
                    .await
                    .unwrap()
            }
        };
        // With a successor who can sponsor, the guests move to them.
        let first = hand_over(identity(&f, &alice).await, Some(identity(&f, &bob).await)).await;
        assert_eq!(first, json!({ "reassigned": 2, "unsponsored": 0 }));
        for guest in [&gina, &hal] {
            assert_eq!(
                f.record("identities", guest).await.unwrap()["guest"]["sponsorId"],
                json!(bob)
            );
            assert_eq!(
                f.record("guestAccounts", guest).await.unwrap()["sponsorId"],
                json!(bob)
            );
        }
        // Without one, or with a guest as successor, they are flagged.
        let second = hand_over(identity(&f, &carol).await, None).await;
        assert_eq!(second, json!({ "reassigned": 0, "unsponsored": 1 }));
        let third = hand_over(identity(&f, &dave).await, Some(identity(&f, &gina).await)).await;
        assert_eq!(third, json!({ "reassigned": 0, "unsponsored": 1 }));
        for guest in [&ivy, &jo] {
            assert_matches(
                &f.get(&owner, guest).await.unwrap(),
                json!({ "sponsorMissing": true }),
            );
        }
        // Offboarding a guest closes its guest account.
        let fourth = hand_over(identity(&f, &hal).await, None).await;
        assert_eq!(fourth, json!({ "reassigned": 0, "unsponsored": 0 }));
        assert_matches(
            &Value::Object(f.record("guestAccounts", &hal).await.unwrap()),
            json!({ "status": "removed", "removalReason": "Offboarded", "endedBy": f.owner_id }),
        );
        let events: Vec<(Value, Value, Value)> = f
            .audit(&tenant_id)
            .await
            .into_iter()
            .filter(|event| {
                event["action"] == "guest:sponsor-change"
                    || event["action"] == "guest:sponsor-missing"
            })
            .map(|event| {
                (
                    event["action"].clone(),
                    event["resourceId"].clone(),
                    event["metadata"].clone(),
                )
            })
            .collect();
        assert_eq!(events.len(), 4);
        assert_eq!(
            (events[0].0.clone(), events[0].2.clone()),
            (
                json!("guest:sponsor-change"),
                json!({ "from": alice, "to": bob, "reason": "offboarding" })
            )
        );
        assert_eq!(
            events[1].2,
            json!({ "from": alice, "to": bob, "reason": "offboarding" })
        );
        assert_eq!(
            events[2],
            (
                json!("guest:sponsor-missing"),
                json!(ivy),
                json!({ "sponsorId": carol, "reason": "offboarding" })
            )
        );
        assert_eq!(
            events[3],
            (
                json!("guest:sponsor-missing"),
                json!(jo),
                json!({ "sponsorId": dave, "reason": "offboarding" })
            )
        );
        // The sweep tells the owners about the flagged guests (already audited, so not counted again), once the
        // sponsors are really gone.
        for person in [&carol, &dave] {
            f.set_identity(person, json!({ "status": "disabled" }))
                .await;
        }
        assert_matches(
            &f.sweep(None).await,
            json!({ "sponsorsMissing": 0, "ownersNotified": 2 }),
        );
    });
}

#[test]
fn removes_a_deleted_guests_account_and_flags_the_guests_of_a_deleted_sponsor() {
    run(|| async {
        let f = fixture().await;
        let owner = f.owner_credential.clone();
        let alice = f.member("alice").await;
        let gina = f.seed_guest("gina", json!({ "sponsorId": alice })).await;
        let hal = f.seed_guest("hal", json!({})).await;
        let principal = owner_principal(&f).await;
        let ctx = f.iam.ctx.clone();
        let release = |identity: Value| {
            let ctx = ctx.clone();
            let principal = principal.clone();
            async move {
                ctx.store
                    .clone()
                    .transaction(|tx| async move {
                        better_iam_server::guests::release_guest_records(
                            &ctx, &tx, &principal, &identity,
                        )
                        .await?;
                        // identities.delete marks the identity deleted in the same transaction.
                        let id = identity["id"].as_str().unwrap();
                        let mut record = tx.get("identities", id).await?.unwrap();
                        record.insert("status".into(), json!("deleted"));
                        tx.put("identities", &record).await?;
                        Ok(())
                    })
                    .await
                    .unwrap()
            }
        };
        release(json!({ "id": hal, "tenantId": f.tenant_id })).await;
        assert!(f.record("guestAccounts", &hal).await.is_none());
        assert_code(f.get(&owner, &hal).await, "NOT_FOUND");
        let listed = ok(f
            .iam
            .api
            .guests
            .list(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_eq!(ids(&listed["guests"], "identityId"), [gina.clone()]);
        let invitations = f.list_invitations(&owner, json!({})).await;
        assert_eq!(
            invitations
                .as_array()
                .unwrap()
                .iter()
                .find(|invitation| invitation["identityId"] == json!(hal))
                .unwrap()["status"],
            "redeemed"
        );
        release(json!({ "id": alice, "tenantId": f.tenant_id })).await;
        assert_matches(
            &f.get(&owner, &gina).await.unwrap(),
            json!({ "sponsorMissing": true, "sponsorId": alice }),
        );
        let event = f.audit_of("guest:sponsor-missing").await.remove(0);
        assert_matches(
            &Value::Object(event),
            json!({
                "actorId": f.owner_id,
                "resourceId": gina,
                "metadata": { "sponsorId": alice, "reason": "deletion" },
            }),
        );
    });
}

#[test]
fn revokes_the_pending_invitations_of_a_disabled_inviter_or_sponsor() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let (lead, lead_credential) = f.administrator("lead", &["iam:guests:invite"]).await;
        let alice = f.member("alice").await;
        let by_lead = f
            .invite(&lead_credential, json!({ "email": "a@partner.test" }))
            .await
            .unwrap();
        let for_alice = f
            .invite(
                &owner,
                json!({ "email": "b@partner.test", "sponsorId": alice }),
            )
            .await
            .unwrap();
        let untouched = f
            .invite(&owner, json!({ "email": "c@partner.test" }))
            .await
            .unwrap();
        let lead_token = f.token_for("a@partner.test").await;
        // identities.setStatus revokes their invitations (api/identities.ts revokeInvitationsBy).
        for person in [&lead, &alice] {
            f.set_identity(person, json!({ "status": "disabled" }))
                .await;
            let person = person.clone();
            f.store()
                .transaction(|tx| async move {
                    better_iam_server::api::identities::revoke_invitations_by(&tx, &person).await
                })
                .await
                .unwrap();
        }
        let listed = f.list_invitations(&owner, json!({})).await;
        let by_id = |id: &Value| {
            listed
                .as_array()
                .unwrap()
                .iter()
                .find(|invitation| &invitation["id"] == id)
                .unwrap()
                .clone()
        };
        assert_matches(
            &by_id(&by_lead["id"]),
            json!({ "status": "revoked", "revokedReason": "inviter-inactive" }),
        );
        assert_matches(
            &by_id(&for_alice["id"]),
            json!({ "status": "revoked", "revokedReason": "sponsor-inactive" }),
        );
        assert_matches(&by_id(&untouched["id"]), json!({ "status": "pending" }));
        assert_code(
            f.redeem(json!({ "tenantId": tenant_id, "token": lead_token, "name": "A", "password": password("A") }))
                .await,
            "INVITATION_INVALID",
        );
        // The address can be invited again.
        assert_eq!(
            f.invite(&owner, json!({ "email": "b@partner.test" }))
                .await
                .unwrap()["status"],
            "pending"
        );
    });
}

// --- redemption safeguards ----------------------------------------------------------------------------------------

#[test]
fn refuses_a_sponsor_who_can_no_longer_sponsor_and_inactive_tenants() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let temp = f.member("temp").await;
        f.set_identity(&temp, json!({ "expiresAt": n(f.now() + DAY) }))
            .await;
        f.invite(
            &owner,
            json!({ "email": "a@partner.test", "sponsorId": temp }),
        )
        .await
        .unwrap();
        f.advance(2.0 * DAY);
        let token = f.token_for("a@partner.test").await;
        let error = assert_code(
            f.redeem(json!({ "token": token, "name": "Ann", "password": password("Ann") }))
                .await,
            "INVITATION_INVALID",
        );
        assert_eq!(error.message, "The sponsor can no longer sponsor guests");
        let owner = f.owner_sign_in().await;
        f.invite(&owner, json!({ "email": "c@partner.test" }))
            .await
            .unwrap();
        let mut tenant = f.record("tenants", &tenant_id).await.unwrap();
        tenant.insert("status".into(), json!("suspended"));
        f.put("tenants", tenant).await;
        let token = f.token_for("c@partner.test").await;
        assert_eq!(
            error_of(
                f.redeem(json!({ "token": token, "name": "Cy", "password": password("Cy") }))
                    .await
            )
            .status,
            403
        );
    });
}

#[test]
fn rate_limits_redemption_per_token_and_per_client_address() {
    run(|| async {
        let f = fixture().await;
        f.invite(&f.owner_credential, json!({ "email": "a@partner.test" }))
            .await
            .unwrap();
        let redeem = |token: String| {
            f.redeem(json!({ "token": token, "name": "A", "password": password("A") }))
        };
        for _ in 0..10 {
            assert_code(redeem("biam_gst_guess".into()).await, "INVITATION_INVALID");
        }
        assert_code(redeem("biam_gst_guess".into()).await, "RATE_LIMITED");
        assert_code(redeem("biam_gst_other".into()).await, "INVITATION_INVALID");
        // From one address, twenty tries per window whatever the token.
        let client = |ip: &str| SessionClientInfo {
            ip: Some(ip.to_owned()),
            user_agent: Some("test".into()),
            ..SessionClientInfo::default()
        };
        for attempt in 0..20 {
            let result = f
                .iam
                .auth
                .with_client(
                    Some(client("203.0.113.7")),
                    redeem(format!("biam_gst_try{attempt}")),
                )
                .await;
            assert_code(result, "INVITATION_INVALID");
        }
        let result = f
            .iam
            .auth
            .with_client(Some(client("203.0.113.7")), redeem("biam_gst_last".into()))
            .await;
        assert_code(result, "RATE_LIMITED");
        let token = f.token_for("a@partner.test").await;
        let result = f
            .iam
            .auth
            .with_client(Some(client("203.0.113.7")), redeem(token))
            .await;
        assert_code(result, "RATE_LIMITED");
    });
}

// --- HTTP ---------------------------------------------------------------------------------------------------------

#[test]
fn every_method_but_redeem_needs_a_credential_over_http() {
    run(|| async {
        let f = fixture().await;
        let (status, _) = f
            .post("guests/list", "", json!({ "tenantId": f.tenant_id }))
            .await;
        assert_eq!(status, 401);
        let owner_token = f.owner_credential.token.clone().unwrap();
        let (status, answer) = f
            .post(
                "guests/list",
                &owner_token,
                json!({ "tenantId": f.tenant_id }),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(answer["data"], json!({ "guests": [], "total": 0 }));
        let (status, answer) = f
            .post(
                "guests/mine",
                &owner_token,
                json!({ "tenantId": f.tenant_id }),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(answer["data"], json!([]));
        // The public redemption answers its refusals like any route.
        let (status, answer) = f
            .post(
                "guests/redeem",
                "",
                json!({ "tenantId": f.tenant_id, "token": "biam_gst_unknown", "name": "X", "password": password("X") }),
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(answer["error"]["code"], "INVITATION_INVALID");
    });
}

// --- the domain helpers -----------------------------------------------------------------------------------------

#[test]
fn spells_addresses_in_their_canonical_form() {
    use better_iam_server::guests::{email_domain, guest_address};
    assert_eq!(
        guest_address(Some(&json!("Ann@Partner.Test."))).unwrap(),
        "ann@partner.test"
    );
    assert_eq!(
        guest_address(Some(&json!("bob@bücher.example"))).unwrap(),
        "bob@xn--bcher-kva.example"
    );
    assert_eq!(
        email_domain("x@ｂüｃｈｅｒ.example").unwrap(),
        "xn--bcher-kva.example"
    );
    for address in [
        "x@partner..test",
        "x@[192.0.2.1]",
        "x@partner.test..",
        "x@1.2.3.4",
    ] {
        let error = email_domain(address).unwrap_err();
        assert_eq!(
            (code(&error), error.message.as_str()),
            (
                "INVALID_INPUT",
                "Invalid email: its domain is not a DNS name"
            ),
            "{address}"
        );
    }
    assert_eq!(
        code(&guest_address(Some(&json!(42))).unwrap_err()),
        "INVALID_INPUT"
    );
}

// --- conversion and removal ---------------------------------------------------------------------------------------

/// Gives a seeded guest a role binding as a redemption grants it (until the guest's end, tracked in the account's
/// grants), with an inline role allowing `documents:read`.
async fn seed_granted_role(f: &Guests, guest: &str) -> String {
    let end = f.record("identities", guest).await.unwrap()["expiresAt"].clone();
    let role_id = f
        .grant(
            guest,
            json!([{ "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }]),
        )
        .await;
    let mut binding = f
        .find(
            "bindings",
            Filter::new()
                .eq("subjectId", guest.to_owned())
                .eq("roleId", role_id),
        )
        .await
        .remove(0);
    binding.insert("expiresAt".into(), end);
    let binding = f.put("bindings", binding).await;
    let mut account = f.record("guestAccounts", guest).await.unwrap();
    account["grants"]["bindingIds"] = json!([binding["id"]]);
    f.put("guestAccounts", account).await;
    binding["id"].as_str().unwrap().to_owned()
}

/// The answer of a call whose transaction committed before api/package-automation.ts `afterIdentityChange` runs:
/// its result, or None while that stub (another unit) still answers NOT_IMPLEMENTED.
fn settled(result: IamResult<Value>) -> Option<Value> {
    match result {
        Ok(value) => Some(value),
        Err(error)
            if error.code == "NOT_IMPLEMENTED" && error.message.contains("afterIdentityChange") =>
        {
            None
        }
        Err(error) => panic!("unexpected error {error:?}"),
    }
}

#[test]
fn converts_a_guest_into_an_ordinary_member() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let gina = f.seed_guest("gina", json!({})).await;
        let hal = f.seed_guest("hal", json!({})).await;
        let gina_binding = seed_granted_role(&f, &gina).await;
        let hal_binding = seed_granted_role(&f, &hal).await;
        let end = f.now() + 90.0 * DAY;
        let convert = |input: Value| {
            let mut input = input;
            input["tenantId"] = json!(tenant_id);
            reply_future(f.iam.api.guests.convert_to_member(&owner, body(input)))
        };
        assert_code(
            convert(json!({ "identityId": gina, "clearExpiry": "yes" })).await,
            "INVALID_INPUT",
        );
        if let Some(member) = settled(convert(json!({ "identityId": gina })).await) {
            assert!(member.get("guest").is_none());
            assert_matches(
                &member,
                json!({ "id": gina, "status": "active", "expiresAt": n(end) }),
            );
        }
        let stored = f.record("identities", &gina).await.unwrap();
        assert!(stored.get("guest").is_none());
        assert_eq!(stored["expiresAt"], n(end));
        assert!(stored.get("passwordHash").is_some());
        assert_matches(
            &f.get(&owner, &gina).await.unwrap(),
            json!({ "accountStatus": "converted", "status": "active" }),
        );
        assert_matches(
            &Value::Object(f.record("guestAccounts", &gina).await.unwrap()),
            json!({ "status": "converted", "endedAt": n(f.now()), "endedBy": f.owner_id, "grantsEndAt": n(end) }),
        );
        let list = |status: &str| {
            reply_future(f.iam.api.guests.list(
                &owner,
                body(json!({ "tenantId": tenant_id, "status": status })),
            ))
        };
        assert_eq!(
            ids(&list("converted").await.unwrap()["guests"], "identityId"),
            [gina.clone()]
        );
        assert_eq!(
            ids(&list("active").await.unwrap()["guests"], "identityId"),
            [hal.clone()]
        );
        // Its grants keep their end unless the expiry is cleared.
        assert_eq!(
            f.record("bindings", &gina_binding).await.unwrap()["expiresAt"],
            n(end)
        );
        // A member is no guest any more: the guest actions no longer apply.
        let guests = &f.iam.api.guests;
        for error in [
            f.attest(&owner, json!({ "identityId": gina }))
                .await
                .unwrap_err(),
            fails(
                guests
                    .set_sponsor(
                        &owner,
                        body(json!({ "tenantId": tenant_id, "identityId": gina, "sponsorId": f.owner_id })),
                    )
                    .await,
            ),
            convert(json!({ "identityId": gina })).await.unwrap_err(),
        ] {
            assert_eq!((code(&error), error.status), ("INVALID_TRANSITION", 409));
        }

        // Clearing the expiry frees the grants of their end too.
        if let Some(cleared) =
            settled(convert(json!({ "identityId": hal, "clearExpiry": true })).await)
        {
            assert!(cleared.get("expiresAt").is_none());
        }
        assert!(
            f.record("identities", &hal)
                .await
                .unwrap()
                .get("expiresAt")
                .is_none()
        );
        assert!(
            f.record("bindings", &hal_binding)
                .await
                .unwrap()
                .get("expiresAt")
                .is_none()
        );
        assert!(
            f.record("guestAccounts", &hal)
                .await
                .unwrap()
                .get("grantsEndAt")
                .is_none()
        );
        let converts: Vec<Value> = f
            .audit_of("guest:convert")
            .await
            .into_iter()
            .map(|event| event["metadata"].clone())
            .collect();
        assert_eq!(
            converts,
            [
                json!({ "sponsorId": f.owner_id, "clearExpiry": false, "expiresAt": n(end) }),
                json!({ "sponsorId": f.owner_id, "clearExpiry": true, "expiresAt": n(end) }),
            ]
        );
    });
}

#[test]
fn renews_what_the_invitation_granted_even_after_an_administrator_moved_the_guests_end() {
    run(|| async {
        let f = fixture().await;
        let alice = f.member("alice").await;
        let gina = f.seed_guest("gina", json!({ "sponsorId": alice })).await;
        let binding = seed_granted_role(&f, &gina).await;
        let moved_end = f.now() + 40.0 * DAY;
        // An administrator moves the guest's own end (identities.update); the grant keeps the end it was given.
        f.set_identity(&gina, json!({ "expiresAt": n(moved_end) }))
            .await;
        f.advance(10.0 * DAY);
        let as_alice = f.sign_in(&alice).await;
        let renewed_end = f.now() + 60.0 * DAY;
        f.attest(&as_alice, json!({ "identityId": gina, "days": 60 }))
            .await
            .unwrap();
        // The renewal moves the grants still ending where the invitation put them.
        assert_eq!(
            f.record("bindings", &binding).await.unwrap()["expiresAt"],
            n(renewed_end)
        );
        let account = f.record("guestAccounts", &gina).await.unwrap();
        assert_eq!(account["grantsEndAt"], n(renewed_end));
        assert_eq!(
            f.audit_of("guest:attest").await[0]["metadata"]["previousExpiresAt"],
            n(moved_end)
        );
        // A grant whose end was changed since keeps its own.
        let mut changed = f.record("bindings", &binding).await.unwrap();
        changed.insert("expiresAt".into(), n(f.now() + 5.0 * DAY));
        f.put("bindings", changed).await;
        f.attest(&as_alice, json!({ "identityId": gina, "days": 30 }))
            .await
            .unwrap();
        assert_eq!(
            f.record("bindings", &binding).await.unwrap()["expiresAt"],
            n(f.now() + 5.0 * DAY)
        );
    });
}

#[test]
#[ignore = "guests.remove needs teams.ts removeFromAllTeams, departments.ts releaseDepartments, delegations.ts revokeDelegationsOf and threats.ts endContainment (other units)"]
fn removes_a_guest_with_everything_it_holds() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let ivy = f.seed_guest("ivy", json!({})).await;
        seed_granted_role(&f, &ivy).await;
        f.sign_in(&ivy).await;
        let (admin, admin_credential) = f
            .administrator("admin", &["iam:guests:manage", "iam:guests:read"])
            .await;
        let remove = |input: Value| {
            let mut request =
                json!({ "tenantId": tenant_id, "identityId": ivy, "reason": "Project ended" });
            for (key, value) in input.as_object().unwrap() {
                request[key] = value.clone();
            }
            reply_future(f.iam.api.guests.remove(&admin_credential, body(request)))
        };
        for reason in [String::new(), "   ".into(), "x".repeat(513)] {
            assert_code(remove(json!({ "reason": reason })).await, "INVALID_INPUT");
        }
        assert_code(remove(json!({ "identityId": admin })).await, "NOT_FOUND");
        let removal = remove(json!({})).await.unwrap();
        assert_matches(
            &removal,
            json!({
                "guest": { "identityId": ivy, "status": "disabled", "accountStatus": "removed" },
                "sessions": 1,
                "bindings": 1,
                "memberships": 0,
                "packages": 0,
            }),
        );
        assert!(
            f.find("bindings", Filter::new().eq("subjectId", ivy.clone()))
                .await
                .is_empty()
        );
        assert_matches(
            &Value::Object(f.record("guestAccounts", &ivy).await.unwrap()),
            json!({ "status": "removed", "endedBy": admin, "removalReason": "Project ended" }),
        );
        assert_code(remove(json!({})).await, "INVALID_TRANSITION");
        let event = f.audit_of("guest:remove").await.remove(0);
        assert_matches(
            &Value::Object(event),
            json!({
                "actorId": admin,
                "resourceId": ivy,
                "metadata": { "reason": "Project ended", "sponsorId": f.owner_id, "sessions": 1, "bindings": 1 },
            }),
        );
    });
}
