//! Access certification campaigns and the auto-closing worker: the port of tests/certifications.test.ts.
//!
//! Roles, bindings, groups and identity changes are written to the store directly (see `governance`).

mod governance;

use governance::{DAY, FixtureOptions, body, err, num, ok, organization, run, value};
use serde_json::{Value, json};

fn items(view: &Value) -> Vec<Value> {
    view["items"].as_array().cloned().unwrap_or_default()
}

/// The item of a subject and role in a campaign view.
fn item(view: &Value, subject: &str, role: &str) -> Value {
    items(view)
        .into_iter()
        .find(|row| row["subjectName"] == json!(subject) && row["roleName"] == json!(role))
        .unwrap_or_else(|| panic!("no item {subject} {role}"))
}

fn id_of(value: &Value) -> String {
    value["id"].as_str().expect("an id").to_owned()
}

#[test]
fn snapshots_bindings_collects_reviewer_decisions_and_applies_them_on_close() {
    run(|| async {
        let f = organization(FixtureOptions::default()).await;
        let api = &f.iam.api.certifications;
        let (tenant_id, owner) = (f.tenant_id.clone(), f.owner.clone());
        let readers = f.role("Readers", &["documents:read"]).await;
        let writers = f.role("Writers", &["documents:write"]).await;
        let reviewers = f
            .role(
                "Reviewers",
                &["iam:certifications:read", "iam:certifications:review"],
            )
            .await;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let carol = f.member("carol").await;
        let dave = f.member("dave").await;
        let team = f.group("Team").await;
        f.add_member(&team, &bob).await;
        f.bind(&readers, "identity", &alice).await;
        f.bind(&writers, "identity", &bob).await;
        f.bind(&readers, "group", &team).await;
        f.bind(&reviewers, "identity", &carol).await;
        f.bind(&reviewers, "identity", &dave).await;
        // A binding issued under root's authority: the owner may not remove it.
        let root_binding = f.bind_as_root(&writers, "identity", &alice).await;

        let missing = err(api
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Bad", "reviewerIds": ["missing"] })),
            )
            .await);
        assert_eq!(missing.status, 404);
        let campaign = ok(api
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Q3 access review",
                    "reviewerIds": [carol],
                    "undecided": "revoke",
                })),
            )
            .await);
        // Owner bindings (protected roles) are never part of a campaign.
        assert_eq!(campaign["items"], json!(6));
        assert_eq!(campaign["status"], json!("open"));
        assert_eq!(
            campaign["progress"],
            json!({ "total": 0, "decided": 0, "keep": 0, "revoke": 0 })
        );
        let campaign_id = id_of(&campaign);
        // Named reviewers are emailed.
        let reviews: Vec<_> = f
            .deliveries()
            .await
            .into_iter()
            .filter(|message| message.template == "certification-review")
            .collect();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].to, "carol@acme.test");
        assert_eq!(
            reviews[0].payload["campaignName"],
            json!("Q3 access review")
        );
        assert_eq!(reviews[0].payload["items"], json!("6"));
        assert!(reviews[0].payload.get("dueAt").is_none());

        let carol_credential = f.sign_in("carol").await;
        let view = ok(api
            .get(
                &carol_credential,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign_id, "mine": true })),
            )
            .await);
        assert_eq!(items(&view).len(), 5);
        let all = ok(api
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign_id })),
            )
            .await);
        let carol_own = item(&all, "carol@acme.test", "Reviewers");
        let refused = err(api
            .decide(
                &carol_credential,
                body(json!({
                    "tenantId": tenant_id,
                    "campaignId": campaign_id,
                    "decisions": [{ "itemId": carol_own["id"], "decision": "keep" }],
                })),
            )
            .await);
        assert_eq!(refused.code, "SELF_REVIEW");
        // Dave holds the review permission but is not a reviewer of this campaign.
        let alice_readers = item(&view, "alice@acme.test", "Readers");
        let refused = err(api
            .decide(
                &f.sign_in("dave").await,
                body(json!({
                    "tenantId": tenant_id,
                    "campaignId": campaign_id,
                    "decisions": [{ "itemId": alice_readers["id"], "decision": "keep" }],
                })),
            )
            .await);
        assert_eq!(refused.status, 403);
        // Alice lacks iam:certifications:review altogether.
        let refused = err(api
            .decide(
                &f.sign_in("alice").await,
                body(json!({
                    "tenantId": tenant_id,
                    "campaignId": campaign_id,
                    "decisions": [{ "itemId": alice_readers["id"], "decision": "keep" }],
                })),
            )
            .await);
        assert_eq!(refused.status, 403);
        // Malformed decision lists are refused before anything is recorded.
        for decisions in [
            json!([]),
            json!("keep"),
            json!([{ "itemId": alice_readers["id"], "decision": "maybe" }]),
        ] {
            let refused = err(api
                .decide(
                    &carol_credential,
                    body(json!({ "tenantId": tenant_id, "campaignId": campaign_id, "decisions": decisions })),
                )
                .await);
            assert_eq!(refused.code, "INVALID_INPUT");
        }

        let recorded = ok(api
            .decide(
                &carol_credential,
                body(json!({
                    "tenantId": tenant_id,
                    "campaignId": campaign_id,
                    "decisions": [
                        { "itemId": item(&view, "alice@acme.test", "Readers")["id"], "decision": "keep" },
                        { "itemId": item(&view, "alice@acme.test", "Writers")["id"], "decision": "revoke", "note": " Left team " },
                        { "itemId": item(&view, "bob@acme.test", "Writers")["id"], "decision": "revoke" },
                        { "itemId": item(&view, "dave@acme.test", "Reviewers")["id"], "decision": "keep" },
                    ],
                })),
            )
            .await);
        assert_eq!(recorded, json!({ "recorded": 4 }));
        let listed = ok(api
            .list(&owner, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(
            listed[0]["progress"],
            json!({ "total": 6, "decided": 4, "keep": 2, "revoke": 2 })
        );
        let decided_writers = item(
            &ok(api
                .get(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "campaignId": campaign_id })),
                )
                .await),
            "alice@acme.test",
            "Writers",
        );
        assert_eq!(decided_writers["note"], json!("Left team"));
        assert_eq!(decided_writers["decidedBy"], json!(carol));
        // A status filter narrows the listing.
        let closed_only = ok(api
            .list(
                &owner,
                body(json!({ "tenantId": tenant_id, "status": "closed" })),
            )
            .await);
        assert_eq!(closed_only, json!([]));

        let closed = ok(api
            .close(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign_id })),
            )
            .await);
        assert_eq!(closed["status"], json!("closed"));
        // Kept: alice Readers, dave Reviewers. Revoked: bob Writers, plus undecided Team and carol (undecided =
        // revoke). Alice's Writers binding belongs to root's authority, so the owner cannot remove it.
        assert_eq!(
            closed["outcomes"],
            json!({ "kept": 2, "revoked": 3, "already-removed": 0, "revocation-failed": 1 })
        );
        let after = ok(api
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign_id })),
            )
            .await);
        let failed = items(&after)
            .into_iter()
            .find(|row| row["outcome"] == json!("revocation-failed"))
            .unwrap();
        assert_eq!(failed["bindingId"], json!(root_binding));
        assert!(
            failed["outcomeDetail"]
                .as_str()
                .is_some_and(|detail| !detail.is_empty())
        );
        let remaining: Vec<String> = f
            .find("bindings", &[("tenantId", json!(tenant_id))])
            .await
            .iter()
            .map(|row| {
                format!(
                    "{}:{}",
                    row["subjectId"].as_str().unwrap(),
                    row["roleId"].as_str().unwrap()
                )
            })
            .collect();
        assert!(remaining.contains(&format!("{alice}:{readers}")));
        assert!(remaining.contains(&format!("{alice}:{writers}")));
        assert!(!remaining.contains(&format!("{bob}:{writers}")));
        assert!(!remaining.contains(&format!("{team}:{readers}")));
        assert!(!remaining.contains(&format!("{carol}:{reviewers}")));
        assert_eq!(
            f.find(
                "audit",
                &[
                    ("tenantId", json!(tenant_id)),
                    ("action", json!("iam:bindings:delete"))
                ]
            )
            .await
            .len(),
            3
        );
        let refused = err(api
            .decide(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "campaignId": campaign_id,
                    "decisions": [{ "itemId": failed["id"], "decision": "keep" }],
                })),
            )
            .await);
        assert_eq!(refused.code, "CONFLICT");
        let refused = err(api
            .close(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign_id })),
            )
            .await);
        assert_eq!(refused.code, "CONFLICT");
        ok(api
            .delete(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign_id })),
            )
            .await);
        assert!(
            f.find("certificationItems", &[("tenantId", json!(tenant_id))])
                .await
                .is_empty()
        );
        let _ = dave;
    });
}

#[test]
fn scopes_campaigns_by_role_and_subject_type_and_keeps_undecided_access_by_default() {
    run(|| async {
        let f = organization(FixtureOptions::default()).await;
        let api = &f.iam.api.certifications;
        let (tenant_id, owner) = (f.tenant_id.clone(), f.owner.clone());
        let readers = f.role("Readers", &["documents:read"]).await;
        let writers = f.role("Writers", &["documents:write"]).await;
        let erin = f.member("erin").await;
        let group = f.group("Crew").await;
        f.bind(&readers, "identity", &erin).await;
        f.bind(&writers, "identity", &erin).await;
        f.bind(&readers, "group", &group).await;
        let scoped = ok(api
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "  Readers only  ",
                    "roleIds": [readers, readers],
                    "subjectType": "identity",
                })),
            )
            .await);
        assert_eq!(scoped["items"], json!(1));
        assert_eq!(scoped["name"], json!("Readers only"));
        assert_eq!(scoped["roleIds"], json!([readers]));
        assert_eq!(scoped["subjectType"], json!("identity"));
        assert_eq!(scoped["undecided"], json!("keep"));
        assert_eq!(scoped["reviewerMode"], json!("named"));
        let owner_role = f
            .find("roles", &[("tenantId", json!(tenant_id))])
            .await
            .into_iter()
            .find(|role| role["protected"] == json!(true))
            .unwrap();
        let refused = err(api
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Owners", "roleIds": [owner_role["id"]] })),
            )
            .await);
        assert_eq!(refused.code, "INVALID_INPUT");
        assert_eq!(
            refused.message,
            format!(
                "Role {} cannot be certified",
                owner_role["id"].as_str().unwrap()
            )
        );
        // Input validation follows the TypeScript order and messages.
        for (input, message) in [
            (
                json!({ "subjectType": "robot" }),
                "subjectType must be identity or group",
            ),
            (
                json!({ "reviewerMode": "team" }),
                "reviewerMode must be named or manager",
            ),
            (
                json!({ "undecided": "maybe" }),
                "undecided must be keep or revoke",
            ),
            (
                json!({ "dueAt": f.now() }),
                "dueAt must be a future timestamp in milliseconds",
            ),
            (
                json!({ "dueAt": 1.5 }),
                "dueAt must be a future timestamp in milliseconds",
            ),
            (json!({ "autoClose": "yes" }), "autoClose must be boolean"),
            (json!({ "autoClose": true }), "autoClose requires dueAt"),
        ] {
            let mut request = input.as_object().unwrap().clone();
            request.insert("tenantId".into(), json!(tenant_id));
            request.insert("name".into(), json!("Invalid"));
            let refused = err(api.create(&owner, body(Value::Object(request))).await);
            assert_eq!(
                (refused.code.as_str(), refused.message.as_str()),
                ("INVALID_INPUT", message)
            );
        }
        let result = ok(api
            .close(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": scoped["id"] })),
            )
            .await);
        assert_eq!(result["outcomes"]["kept"], json!(1));
        assert_eq!(result["status"], json!("closed"));
        assert_eq!(result["closedBy"], json!(f.owner_id));
        assert_eq!(result["closedAt"], num(f.now()));
        let closed_item = &items(&ok(api
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": scoped["id"] })),
            )
            .await))[0];
        assert_eq!(closed_item["outcome"], json!("kept"));
        assert!(closed_item.get("outcomeDetail").is_none());
        assert_eq!(
            f.find(
                "bindings",
                &[("tenantId", json!(tenant_id)), ("subjectId", json!(erin))]
            )
            .await
            .len(),
            2
        );
        let open = ok(api
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Open" })),
            )
            .await);
        let refused = err(api
            .delete(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": open["id"] })),
            )
            .await);
        assert_eq!(refused.code, "CONFLICT");
        // A binding removed before closing is reported as already removed when revoked, kept otherwise.
        let revoking = ok(api
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Revoking", "roleIds": [writers], "undecided": "revoke" })),
            )
            .await);
        let removed = f
            .find(
                "bindings",
                &[("tenantId", json!(tenant_id)), ("roleId", json!(writers))],
            )
            .await;
        f.remove("bindings", removed[0]["id"].as_str().unwrap())
            .await;
        let result = ok(api
            .close(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": revoking["id"] })),
            )
            .await);
        assert_eq!(
            result["outcomes"],
            json!({ "kept": 0, "revoked": 0, "already-removed": 1, "revocation-failed": 0 })
        );
        // Deleting a closed campaign removes its items.
        ok(api
            .delete(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": scoped["id"] })),
            )
            .await);
        assert!(
            f.find(
                "certificationItems",
                &[
                    ("tenantId", json!(tenant_id)),
                    ("campaignId", scoped["id"].clone())
                ]
            )
            .await
            .is_empty()
        );
        let refused = err(api
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": scoped["id"] })),
            )
            .await);
        assert_eq!(refused.status, 404);
        let refused = err(api
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": 7 })),
            )
            .await);
        assert_eq!(
            (refused.code.as_str(), refused.message.as_str()),
            ("INVALID_INPUT", "Invalid campaignId")
        );
    });
}

#[test]
fn assigns_items_to_managers_who_review_them_without_the_review_permission() {
    run(|| async {
        let f = organization(FixtureOptions::default()).await;
        let api = &f.iam.api.certifications;
        let (tenant_id, owner) = (f.tenant_id.clone(), f.owner.clone());
        let readers = f.role("Readers", &["documents:read"]).await;
        let writers = f.role("Writers", &["documents:write"]).await;
        let reviewers = f
            .role(
                "Reviewers",
                &["iam:certifications:read", "iam:certifications:review"],
            )
            .await;
        // Mia manages Alice and Bob and holds no role at all; Paul manages Dana but is disabled.
        let mia = f.member("mia").await;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let carl = f.member("carl").await;
        let dana = f.member("dana").await;
        let paul = f.member("paul").await;
        let nina = f.member("nina").await;
        let rex = f.member("rex").await;
        for (person, manager) in [(&alice, &mia), (&bob, &mia), (&dana, &paul)] {
            f.patch("identities", person, json!({ "managerId": manager }))
                .await;
        }
        f.patch("identities", &paul, json!({ "status": "disabled" }))
            .await;
        let team = f.group("Team").await;
        f.bind(&readers, "identity", &alice).await;
        f.bind(&writers, "identity", &alice).await;
        f.bind(&readers, "identity", &bob).await;
        f.bind(&readers, "identity", &carl).await;
        f.bind(&readers, "identity", &dana).await;
        f.bind(&readers, "group", &team).await;
        f.bind(&reviewers, "identity", &nina).await;
        f.bind(&reviewers, "identity", &rex).await;

        let refused = err(api
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Bad", "reviewerMode": "team" })),
            )
            .await);
        assert_eq!(refused.code, "INVALID_INPUT");
        let due_at = f.now() + 7.0 * DAY;
        let campaign = ok(api
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Manager review",
                    "reviewerMode": "manager",
                    "reviewerIds": [nina],
                    "dueAt": due_at,
                })),
            )
            .await);
        assert_eq!(campaign["reviewerMode"], json!("manager"));
        assert_eq!(campaign["items"], json!(8));
        assert_eq!(campaign["dueAt"], num(due_at));
        assert!(campaign.get("autoClose").is_none());
        let campaign_id = id_of(&campaign);
        let all = ok(api
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign_id })),
            )
            .await);
        let mut assigned: Vec<String> = items(&all)
            .iter()
            .filter(|row| row["reviewerId"] == json!(mia))
            .map(|row| {
                format!(
                    "{} {}",
                    row["subjectName"].as_str().unwrap(),
                    row["roleName"].as_str().unwrap()
                )
            })
            .collect();
        assigned.sort();
        assert_eq!(
            assigned,
            vec![
                "alice@acme.test Readers",
                "alice@acme.test Writers",
                "bob@acme.test Readers"
            ]
        );
        // Everything else falls back to the named reviewer: no manager, a disabled manager, or a group.
        assert_eq!(
            items(&all)
                .iter()
                .filter(|row| row.get("reviewerId").is_none())
                .count(),
            5
        );
        assert!(
            item(&all, "dana@acme.test", "Readers")
                .get("reviewerId")
                .is_none()
        );
        assert!(item(&all, "Team", "Readers").get("reviewerId").is_none());

        // One email per reviewer with their own item count.
        let invitations: Vec<_> = f
            .deliveries()
            .await
            .into_iter()
            .filter(|message| message.template == "certification-review")
            .collect();
        assert_eq!(invitations.len(), 2);
        let to_mia = invitations
            .iter()
            .find(|message| message.to == "mia@acme.test")
            .unwrap();
        assert_eq!(to_mia.payload["campaignId"], json!(campaign_id));
        assert_eq!(to_mia.payload["campaignName"], json!("Manager review"));
        assert_eq!(to_mia.payload["items"], json!("3"));
        assert_eq!(
            to_mia.payload["dueAt"],
            json!(better_iam_core::js::iso_string(due_at).unwrap())
        );
        let to_nina = invitations
            .iter()
            .find(|message| message.to == "nina@acme.test")
            .unwrap();
        assert_eq!(to_nina.payload["items"], json!("5"));

        // The manager's own worklist.
        let mia_credential = f.sign_in("mia").await;
        let mine = ok(api
            .list_mine(&mia_credential, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(mine.as_array().unwrap().len(), 1);
        assert_eq!(mine[0]["id"], json!(campaign_id));
        assert_eq!(mine[0]["name"], json!("Manager review"));
        assert_eq!(mine[0]["dueAt"], num(due_at));
        assert_eq!(mine[0]["reviewerMode"], json!("manager"));
        assert_eq!(
            mine[0]["progress"],
            json!({ "total": 3, "decided": 0, "keep": 0, "revoke": 0 })
        );
        let order: Vec<String> = items(&mine[0])
            .iter()
            .map(|row| {
                format!(
                    "{} {}",
                    row["subjectName"].as_str().unwrap(),
                    row["roleName"].as_str().unwrap()
                )
            })
            .collect();
        assert_eq!(
            order,
            vec![
                "alice@acme.test Readers",
                "bob@acme.test Readers",
                "alice@acme.test Writers"
            ]
        );
        let carl_credential = f.sign_in("carl").await;
        assert_eq!(
            ok(api
                .list_mine(&carl_credential, body(json!({ "tenantId": tenant_id })))
                .await),
            json!([])
        );
        let refused = err(api
            .list_mine(
                &mia_credential,
                body(json!({ "tenantId": f.root_tenant_id })),
            )
            .await);
        assert_eq!(refused.status, 403);

        // Reminders before anyone decided: Mia for her three, Nina for the five fallback items.
        let nina_credential = f.sign_in("nina").await;
        let refused = err(api
            .remind(
                &nina_credential,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign_id })),
            )
            .await);
        assert_eq!(refused.status, 403);
        assert_eq!(
            ok(api
                .remind(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "campaignId": campaign_id }))
                )
                .await),
            json!({ "reminded": 2, "pending": 8 })
        );
        let mut reminders: Vec<String> = f
            .deliveries()
            .await
            .into_iter()
            .filter(|message| message.template == "certification-reminder")
            .map(|message| {
                format!(
                    "{} {}",
                    message.to,
                    message.payload["pending"].as_str().unwrap()
                )
            })
            .collect();
        reminders.sort();
        assert_eq!(reminders, vec!["mia@acme.test 3", "nina@acme.test 5"]);

        // decide(): manager-assigned items belong to the manager; fallback items to the named reviewers.
        let decide_as = |credential: better_iam_core::CredentialInput, item_id: Value| {
            let tenant_id = tenant_id.clone();
            let campaign_id = campaign_id.clone();
            async move {
                value(
                    api.decide(
                        &credential,
                        body(json!({
                            "tenantId": tenant_id,
                            "campaignId": campaign_id,
                            "decisions": [{ "itemId": item_id, "decision": "keep" }],
                        })),
                    )
                    .await,
                )
            }
        };
        let refused = decide_as(
            mia_credential.clone(),
            item(&all, "alice@acme.test", "Readers")["id"].clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.status, 403);
        let refused = decide_as(
            nina_credential.clone(),
            item(&all, "alice@acme.test", "Readers")["id"].clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            (refused.code.as_str(), refused.message.as_str()),
            (
                "ACCESS_DENIED",
                "This item is assigned to the person's manager"
            )
        );
        let refused = decide_as(
            nina_credential.clone(),
            item(&all, "nina@acme.test", "Reviewers")["id"].clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.code, "SELF_REVIEW");
        let rex_credential = f.sign_in("rex").await;
        let refused = decide_as(
            rex_credential.clone(),
            item(&all, "carl@acme.test", "Readers")["id"].clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            (refused.code.as_str(), refused.message.as_str()),
            ("ACCESS_DENIED", "You are not a reviewer of this campaign")
        );
        let refused = decide_as(
            rex_credential.clone(),
            item(&all, "bob@acme.test", "Readers")["id"].clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.code, "ACCESS_DENIED");
        assert_eq!(
            ok(api
                .decide(
                    &nina_credential,
                    body(json!({
                        "tenantId": tenant_id,
                        "campaignId": campaign_id,
                        "decisions": [
                            { "itemId": item(&all, "carl@acme.test", "Readers")["id"], "decision": "keep" },
                            { "itemId": item(&all, "dana@acme.test", "Readers")["id"], "decision": "revoke" },
                        ],
                    })),
                )
                .await),
            json!({ "recorded": 2 })
        );
        // Holders of iam:certifications:manage may still decide a manager's item.
        assert_eq!(
            decide_as(
                owner.clone(),
                item(&all, "bob@acme.test", "Readers")["id"].clone()
            )
            .await
            .unwrap(),
            json!({ "recorded": 1 })
        );

        // review(): the manager decides their own items, and only those.
        let review = |credential: better_iam_core::CredentialInput,
                      decisions: Value,
                      tenant: String| {
            let campaign_id = campaign_id.clone();
            async move {
                value(
                    api.review(
                        &credential,
                        body(json!({ "tenantId": tenant, "campaignId": campaign_id, "decisions": decisions })),
                    )
                    .await,
                )
            }
        };
        let refused = review(
            mia_credential.clone(),
            json!([{ "itemId": item(&all, "carl@acme.test", "Readers")["id"], "decision": "keep" }]),
            tenant_id.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            (refused.code.as_str(), refused.status),
            ("ACCESS_DENIED", 403)
        );
        let refused = review(
            mia_credential.clone(),
            json!([{ "itemId": "missing", "decision": "keep" }]),
            tenant_id.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.code, "ACCESS_DENIED");
        let refused = review(
            mia_credential.clone(),
            json!([{ "itemId": item(&all, "alice@acme.test", "Readers")["id"], "decision": "keep" }]),
            f.root_tenant_id.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.status, 403);
        let refused = review(mia_credential.clone(), json!([]), tenant_id.clone())
            .await
            .unwrap_err();
        assert_eq!(refused.code, "INVALID_INPUT");
        let refused = review(mia_credential.clone(), json!([null]), tenant_id.clone())
            .await
            .unwrap_err();
        assert_eq!(
            (refused.code.as_str(), refused.message.as_str()),
            ("INVALID_INPUT", "decision must be keep or revoke")
        );
        let refused = review(
            rex_credential.clone(),
            json!([{ "itemId": item(&all, "alice@acme.test", "Readers")["id"], "decision": "keep" }]),
            tenant_id.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.code, "ACCESS_DENIED");
        assert_eq!(
            review(
                mia_credential.clone(),
                json!([
                    { "itemId": item(&all, "alice@acme.test", "Readers")["id"], "decision": "keep" },
                    { "itemId": item(&all, "alice@acme.test", "Writers")["id"], "decision": "revoke", "note": "Moved team" },
                ]),
                tenant_id.clone(),
            )
            .await
            .unwrap(),
            json!({ "recorded": 2 })
        );
        let reviewed = f
            .find(
                "audit",
                &[
                    ("tenantId", json!(tenant_id)),
                    ("action", json!("certification:review")),
                ],
            )
            .await;
        assert_eq!(reviewed.len(), 1);
        assert_eq!(reviewed[0]["actorId"], json!(mia));
        assert_eq!(reviewed[0]["resourceId"], json!(campaign_id));
        assert_eq!(reviewed[0]["outcome"], json!("allow"));
        assert_eq!(
            reviewed[0]["metadata"],
            json!({ "recorded": 2, "keep": 1, "revoke": 1 })
        );
        let writers_id = item(&all, "alice@acme.test", "Writers")["id"].clone();
        let decided_writers = items(&ok(api
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign_id })),
            )
            .await))
        .into_iter()
        .find(|row| row["id"] == writers_id)
        .unwrap();
        assert_eq!(decided_writers["decision"], json!("revoke"));
        assert_eq!(decided_writers["decidedBy"], json!(mia));
        assert_eq!(decided_writers["note"], json!("Moved team"));
        assert_eq!(
            ok(api
                .list_mine(&mia_credential, body(json!({ "tenantId": tenant_id })))
                .await)[0]["progress"],
            json!({ "total": 3, "decided": 3, "keep": 2, "revoke": 1 })
        );

        // Only the three unassigned, undecided items remain, all Nina's.
        assert_eq!(
            ok(api
                .remind(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "campaignId": campaign_id }))
                )
                .await),
            json!({ "reminded": 1, "pending": 3 })
        );
        let reminded = f
            .find(
                "audit",
                &[
                    ("tenantId", json!(tenant_id)),
                    ("action", json!("certification:remind")),
                ],
            )
            .await;
        assert_eq!(reminded.len(), 2);

        let closed = ok(api
            .close(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign_id })),
            )
            .await);
        assert_eq!(closed["closedBy"], json!(f.owner_id));
        assert_eq!(
            closed["outcomes"],
            json!({ "kept": 6, "revoked": 2, "already-removed": 0, "revocation-failed": 0 })
        );
        let remaining: Vec<String> = f
            .find("bindings", &[("tenantId", json!(tenant_id))])
            .await
            .iter()
            .map(|row| {
                format!(
                    "{} {}",
                    row["subjectId"].as_str().unwrap(),
                    row["roleId"].as_str().unwrap()
                )
            })
            .collect();
        assert!(!remaining.contains(&format!("{alice} {writers}")));
        assert!(!remaining.contains(&format!("{dana} {readers}")));
        assert!(remaining.contains(&format!("{alice} {readers}")));
        let refused = review(
            mia_credential.clone(),
            json!([{ "itemId": item(&all, "bob@acme.test", "Readers")["id"], "decision": "keep" }]),
            tenant_id.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!((refused.code.as_str(), refused.status), ("CONFLICT", 409));
        let refused = err(api
            .remind(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign_id })),
            )
            .await);
        assert_eq!(refused.code, "CONFLICT");
        assert_eq!(
            ok(api
                .list_mine(&mia_credential, body(json!({ "tenantId": tenant_id })))
                .await),
            json!([])
        );
    });
}

#[test]
fn reminds_nobody_for_unnamed_fallback_items_and_requires_email_delivery() {
    run(|| async {
        let f = organization(FixtureOptions::default()).await;
        let api = &f.iam.api.certifications;
        let (tenant_id, owner) = (f.tenant_id.clone(), f.owner.clone());
        let readers = f.role("Readers", &["documents:read"]).await;
        let erin = f.member("erin").await;
        f.bind(&readers, "identity", &erin).await;
        let campaign = ok(api
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Open to all" })),
            )
            .await);
        assert_eq!(campaign["reviewerMode"], json!("named"));
        assert_eq!(
            ok(api
                .remind(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "campaignId": campaign["id"] }))
                )
                .await),
            json!({ "reminded": 0, "pending": 1 })
        );
        assert!(
            f.deliveries()
                .await
                .iter()
                .all(|message| message.template != "certification-reminder")
        );
        // The same deployment without an email callback cannot send reminders.
        let silent = f.silent();
        let refused = err(silent
            .api
            .certifications
            .remind(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign["id"] })),
            )
            .await);
        assert_eq!(refused.code, "DELIVERY_REQUIRED");
    });
}

#[test]
fn closes_overdue_auto_closing_campaigns_with_keep_decisions_and_orphaned_creators() {
    run(|| async {
        let f = organization(FixtureOptions::default()).await;
        let api = &f.iam.api.certifications;
        let (tenant_id, owner) = (f.tenant_id.clone(), f.owner.clone());
        let readers = f.role("Readers", &["documents:read"]).await;
        let writers = f.role("Writers", &["documents:write"]).await;
        let certifiers = f.role("Certifiers", &["iam:certifications:manage"]).await;
        let erin = f.member("erin").await;
        let finn = f.member("finn").await;
        let gail = f.member("gail").await;
        let adam = f.member("adam").await;
        f.bind(&readers, "identity", &erin).await;
        f.bind(&readers, "identity", &finn).await;
        f.bind(&readers, "identity", &gail).await;
        f.bind(&writers, "identity", &erin).await;
        f.bind(&certifiers, "identity", &adam).await;

        let refused = err(api
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "No date", "autoClose": true })),
            )
            .await);
        assert_eq!(refused.code, "INVALID_INPUT");
        let due = ok(api
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Due",
                    "roleIds": [readers],
                    "dueAt": f.now() + DAY,
                    "autoClose": true,
                })),
            )
            .await);
        assert_eq!(due["autoClose"], json!(true));
        let later = ok(api
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Later",
                    "roleIds": [readers],
                    "dueAt": f.now() + 10.0 * DAY,
                    "autoClose": true,
                })),
            )
            .await);
        let manual = ok(api
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Manual",
                    "roleIds": [readers],
                    "dueAt": f.now() + DAY,
                })),
            )
            .await);
        let erin_item = items(&ok(api
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": due["id"] })),
            )
            .await))
        .into_iter()
        .find(|row| row["subjectId"] == json!(erin))
        .unwrap();
        ok(api
            .decide(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "campaignId": due["id"],
                    "decisions": [{ "itemId": erin_item["id"], "decision": "keep" }],
                })),
            )
            .await);
        // Adam opens a campaign and is deleted before it closes: nothing is revoked on his behalf.
        let orphan = ok(api
            .create(
                &f.sign_in("adam").await,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Orphan",
                    "roleIds": [writers],
                    "dueAt": f.now() + DAY,
                    "autoClose": true,
                    "undecided": "revoke",
                })),
            )
            .await);
        f.patch(
            "identities",
            &adam,
            json!({ "status": "deleted", "deletedAt": f.now() }),
        )
        .await;

        assert_eq!(
            f.iam.close_overdue_certifications(None).await.unwrap(),
            json!({ "closed": [], "skipped": 3 })
        );
        f.advance(2.0 * DAY);
        let result = f.iam.close_overdue_certifications(None).await.unwrap();
        assert_eq!(result["skipped"], json!(1));
        let closed = result["closed"].as_array().unwrap();
        assert_eq!(closed.len(), 2);
        assert!(closed.contains(&json!({
            "tenantId": tenant_id,
            "campaignId": due["id"],
            "outcomes": { "kept": 3, "revoked": 0, "already-removed": 0, "revocation-failed": 0 },
        })));
        assert!(closed.contains(&json!({
            "tenantId": tenant_id,
            "campaignId": orphan["id"],
            "outcomes": { "kept": 0, "revoked": 0, "already-removed": 0, "revocation-failed": 1 },
        })));

        let closed_due = ok(api
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": due["id"] })),
            )
            .await);
        assert_eq!(closed_due["status"], json!("closed"));
        assert_eq!(closed_due["closedBy"], json!("deployment-operator"));
        assert_eq!(closed_due["closedAt"], num(f.now()));
        let orphan_items = items(&ok(api
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": orphan["id"] })),
            )
            .await));
        assert_eq!(orphan_items.len(), 1);
        assert_eq!(orphan_items[0]["outcome"], json!("revocation-failed"));
        assert!(
            orphan_items[0]["outcomeDetail"]
                .as_str()
                .unwrap()
                .contains("creator")
        );
        assert_eq!(
            ok(api
                .get(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "campaignId": manual["id"] }))
                )
                .await)["status"],
            json!("open")
        );
        assert_eq!(
            f.find(
                "bindings",
                &[("tenantId", json!(tenant_id)), ("subjectId", json!(erin))]
            )
            .await
            .len(),
            2
        );
        let auto_closed = f
            .find(
                "audit",
                &[
                    ("tenantId", json!(tenant_id)),
                    ("action", json!("certification:auto-close")),
                ],
            )
            .await;
        let mut resources: Vec<String> = auto_closed
            .iter()
            .map(|event| event["resourceId"].as_str().unwrap().to_owned())
            .collect();
        resources.sort();
        let mut expected = vec![id_of(&due), id_of(&orphan)];
        expected.sort();
        assert_eq!(resources, expected);
        let due_event = auto_closed
            .iter()
            .find(|event| event["resourceId"] == due["id"])
            .unwrap();
        assert_eq!(due_event["actorId"], json!("deployment-operator"));
        assert_eq!(due_event["outcome"], json!("allow"));
        assert_eq!(
            due_event["metadata"],
            json!({ "kept": 3, "revoked": 0, "already-removed": 0, "revocation-failed": 0 })
        );

        // A second run finds nothing new; a tenant filter limits the sweep.
        assert_eq!(
            f.iam.close_overdue_certifications(None).await.unwrap(),
            json!({ "closed": [], "skipped": 1 })
        );
        assert_eq!(
            f.iam
                .close_overdue_certifications(Some(&json!({ "tenantId": f.root_tenant_id })))
                .await
                .unwrap(),
            json!({ "closed": [], "skipped": 0 })
        );
        let unknown = f
            .iam
            .close_overdue_certifications(Some(&json!({ "tenantId": "missing" })))
            .await
            .unwrap_err();
        assert_eq!(unknown.status, 404);
        f.advance(10.0 * DAY);
        assert_eq!(
            f.iam
                .close_overdue_certifications(Some(&json!({ "tenantId": tenant_id })))
                .await
                .unwrap(),
            json!({
                "closed": [{
                    "tenantId": tenant_id,
                    "campaignId": later["id"],
                    "outcomes": { "kept": 3, "revoked": 0, "already-removed": 0, "revocation-failed": 0 },
                }],
                "skipped": 0,
            })
        );
    });
}

#[test]
fn closes_overdue_auto_closing_campaigns_under_the_creator_authority() {
    run(|| async {
        let f = organization(FixtureOptions::default()).await;
        let api = &f.iam.api.certifications;
        let (tenant_id, owner) = (f.tenant_id.clone(), f.owner.clone());
        let readers = f.role("Readers", &["documents:read"]).await;
        let erin = f.member("erin").await;
        let finn = f.member("finn").await;
        let gail = f.member("gail").await;
        f.bind(&readers, "identity", &erin).await;
        let finn_binding = f.bind(&readers, "identity", &finn).await;
        let gail_binding = f.bind(&readers, "identity", &gail).await;
        let due = ok(api
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Due",
                    "roleIds": [readers],
                    "dueAt": f.now() + DAY,
                    "autoClose": true,
                    "undecided": "revoke",
                })),
            )
            .await);
        let erin_item = items(&ok(api
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": due["id"] })),
            )
            .await))
        .into_iter()
        .find(|row| row["subjectId"] == json!(erin))
        .unwrap();
        ok(api
            .decide(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "campaignId": due["id"],
                    "decisions": [{ "itemId": erin_item["id"], "decision": "keep" }],
                })),
            )
            .await);
        f.advance(2.0 * DAY);
        let result = f.iam.close_overdue_certifications(None).await;
        assert_eq!(
            result.expect("the overdue run"),
            json!({
                "closed": [{
                    "tenantId": tenant_id,
                    "campaignId": due["id"],
                    "outcomes": { "kept": 1, "revoked": 2, "already-removed": 0, "revocation-failed": 0 },
                }],
                "skipped": 0,
            })
        );
        let remaining: Vec<String> = f
            .find("bindings", &[("tenantId", json!(tenant_id))])
            .await
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_owned())
            .collect();
        assert!(!remaining.contains(&finn_binding));
        assert!(!remaining.contains(&gail_binding));
        let mut revocations: Vec<String> = f
            .find(
                "audit",
                &[
                    ("tenantId", json!(tenant_id)),
                    ("action", json!("iam:bindings:delete")),
                ],
            )
            .await
            .into_iter()
            .filter(|event| event["actorId"] == json!("deployment-operator"))
            .map(|event| {
                assert_eq!(event["metadata"]["campaignId"], due["id"]);
                event["resourceId"].as_str().unwrap().to_owned()
            })
            .collect();
        revocations.sort();
        let mut expected = vec![finn_binding, gail_binding];
        expected.sort();
        assert_eq!(revocations, expected);
    });
}
