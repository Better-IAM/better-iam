//! Port of tests/applications.test.ts: the application catalog and the "My apps" launcher. Groups, packages, roles,
//! bindings and identity changes the TypeScript suite makes through other API groups are written to the store
//! directly (with the cleanup hooks `identities.delete` and `groups.delete` run, `releaseAppRecordsOf` and
//! `releaseGroupApps`).

mod org_fixture;

use better_iam_core::{CredentialInput, Filter, IamResult, IamStoreExt, Identity};
use better_iam_server::api::Body;
use better_iam_server::applications::{release_app_records_of, release_group_apps};
use org_fixture::{DAY, Org, bearer, code, run};
use serde_json::{Value, json};

struct Scenario {
    f: Org,
    engineering: String,
    alice: Identity,
    bob: Identity,
}

async fn scenario() -> Scenario {
    let f = Org::new(|_| {}).await;
    let engineering = f.group("Engineering").await;
    let alice = f.member("alice").await;
    let bob = f.member("bob").await;
    f.add_member(&engineering, &alice.id).await;
    Scenario {
        f,
        engineering,
        alice,
        bob,
    }
}

impl Scenario {
    fn tenant(&self) -> &str {
        &self.f.tenant_id
    }
}

macro_rules! apps_call {
    ($f:expr, $method:ident, $credential:expr, $input:expr) => {
        async {
            $f.iam
                .api
                .applications
                .$method($credential, Body::from_value($input))
                .await
                .and_then(|reply| reply.into_value())
        }
    };
}

async fn names(s: &Scenario, credential: &CredentialInput) -> Vec<String> {
    let mine = apps_call!(s.f, mine, credential, json!({ "tenantId": s.tenant() }))
        .await
        .unwrap();
    let mut names: Vec<String> = mine
        .as_array()
        .unwrap()
        .iter()
        .map(|app| {
            format!(
                "{}:{}",
                app["key"].as_str().unwrap(),
                app.get("via")
                    .and_then(Value::as_str)
                    .unwrap_or("undefined")
            )
        })
        .collect();
    names.sort();
    names
}

async fn allowed(s: &Scenario, input: Value) -> IamResult<Value> {
    s.f.iam.applications.allowed(&input).await
}

#[test]
fn shows_people_their_apps_and_records_launches() {
    run(|| async {
        let s = scenario().await;
        let owner = &s.f.owner;
        let wiki = apps_call!(s.f, create, owner, json!({
            "tenantId": s.tenant(), "key": "wiki", "name": "Wiki",
            "launchUrl": "https://wiki.acme.test/login", "visibility": "everyone", "category": "Knowledge",
        }))
        .await
        .unwrap();
        assert_eq!(wiki["kind"], json!("link"));
        assert_eq!(wiki["uniqueKey"], json!("key:wiki"));
        assert_eq!(wiki["ownerIds"], json!([]));
        let ci = apps_call!(s.f, create, owner, json!({
            "tenantId": s.tenant(), "key": "ci", "name": "CI", "launchUrl": "https://ci.acme.test",
        }))
        .await
        .unwrap();
        assert_eq!(ci["visibility"], json!("assigned"));
        assert_eq!(ci["enabled"], json!(true));
        let payroll = apps_call!(s.f, create, owner, json!({
            "tenantId": s.tenant(), "key": "payroll", "name": "Payroll", "launchUrl": "https://payroll.acme.test",
        }))
        .await
        .unwrap();
        apps_call!(s.f, assign, owner, json!({
            "tenantId": s.tenant(), "appId": ci["id"], "subjectType": "group", "subjectId": s.engineering,
        }))
        .await
        .unwrap();
        let assignment = apps_call!(
            s.f,
            assign,
            owner,
            json!({
                "tenantId": s.tenant(), "appId": payroll["id"], "subjectType": "identity",
                "subjectId": s.bob.id, "expiresAt": s.f.now() + 5.0 * DAY,
            })
        )
        .await
        .unwrap();
        assert_eq!(
            assignment["expiresAt"],
            better_iam_server::js::number(s.f.now() + 5.0 * DAY)
        );
        let alice = s.f.sign_in("alice").await;
        let bob = s.f.sign_in("bob").await;
        assert_eq!(names(&s, &alice).await, vec!["ci:group", "wiki:everyone"]);
        assert_eq!(
            names(&s, &bob).await,
            vec!["payroll:direct", "wiki:everyone"]
        );
        // Launching needs the app; launches are counted.
        assert_eq!(
            apps_call!(
                s.f,
                launch,
                &alice,
                json!({ "tenantId": s.tenant(), "appId": ci["id"] })
            )
            .await
            .unwrap(),
            json!({ "url": "https://ci.acme.test/" })
        );
        assert_eq!(
            code(
                apps_call!(
                    s.f,
                    launch,
                    &alice,
                    json!({ "tenantId": s.tenant(), "appId": payroll["id"] })
                )
                .await
            ),
            "ACCESS_DENIED"
        );
        let mine = apps_call!(s.f, mine, &alice, json!({ "tenantId": s.tenant() }))
            .await
            .unwrap();
        assert_eq!(mine[0]["key"], json!("ci"));
        assert_eq!(
            mine[0]["lastLaunchedAt"],
            better_iam_server::js::number(s.f.now())
        );
        let launches =
            s.f.find(
                "appLaunches",
                Filter::new().eq("identityId", s.alice.id.clone()),
            )
            .await;
        assert_eq!(launches.len(), 1);
        assert_eq!(launches[0]["count"], json!(1));
        // Assignments end.
        s.f.advance(6.0 * DAY);
        let later = s.f.sign_in("bob").await;
        assert_eq!(names(&s, &later).await, vec!["wiki:everyone"]);
        // Disabled apps disappear.
        let owner = s.f.owner_sign_in().await;
        apps_call!(
            s.f,
            update,
            &owner,
            json!({ "tenantId": s.tenant(), "appId": wiki["id"], "enabled": false })
        )
        .await
        .unwrap();
        assert!(names(&s, &later).await.is_empty());
        // Every change is audited.
        let mut audit =
            s.f.find("audit", Filter::new().eq("tenantId", s.tenant().to_owned()))
                .await;
        audit.sort_by(|a, b| {
            a["sequence"]
                .as_f64()
                .partial_cmp(&b["sequence"].as_f64())
                .unwrap()
        });
        let actions: Vec<&str> = audit
            .iter()
            .filter_map(|event| event["action"].as_str())
            .filter(|action| action.starts_with("app:"))
            .collect();
        assert_eq!(
            actions,
            vec![
                "app:create",
                "app:create",
                "app:create",
                "app:assign",
                "app:assign",
                "app:launch",
                "app:update"
            ]
        );
        let update = audit
            .iter()
            .find(|event| event["action"] == json!("app:update"))
            .unwrap();
        assert_eq!(
            update["metadata"],
            json!({
                "key": "wiki",
                "before": { "name": "Wiki", "launchUrl": "https://wiki.acme.test/login", "visibility": "everyone", "enabled": true },
                "after": { "name": "Wiki", "launchUrl": "https://wiki.acme.test/login", "visibility": "everyone", "enabled": false },
            })
        );
    });
}

#[test]
fn offers_access_requests_through_a_requestable_package() {
    run(|| async {
        let s = scenario().await;
        let owner = &s.f.owner;
        let package_id = better_iam_server::utils::id();
        s.f.insert(
            "accessPackages",
            json!({
                "id": package_id, "tenantId": s.tenant(), "name": "Engineering tools",
                "roleIds": [], "groupIds": [s.engineering], "requestable": true,
            }),
        )
        .await;
        let ci = apps_call!(s.f, create, owner, json!({
            "tenantId": s.tenant(), "key": "ci", "name": "CI", "launchUrl": "https://ci.acme.test",
            "requestPackageId": package_id,
        }))
        .await
        .unwrap();
        apps_call!(s.f, assign, owner, json!({
            "tenantId": s.tenant(), "appId": ci["id"], "subjectType": "group", "subjectId": s.engineering,
        }))
        .await
        .unwrap();
        let bob = s.f.sign_in("bob").await;
        let mine = apps_call!(s.f, mine, &bob, json!({ "tenantId": s.tenant() }))
            .await
            .unwrap();
        assert_eq!(mine.as_array().unwrap().len(), 1);
        assert_eq!(mine[0]["key"], json!("ci"));
        assert_eq!(mine[0]["requestPackageId"], json!(package_id));
        assert!(mine[0].get("via").is_none());
        assert_eq!(
            code(
                apps_call!(
                    s.f,
                    create,
                    owner,
                    json!({
                        "tenantId": s.tenant(), "key": "other", "name": "Other",
                        "launchUrl": "http://insecure.example.test",
                    })
                )
                .await
            ),
            "INVALID_INPUT"
        );
        // A package that is no longer requestable is not offered.
        s.f.patch(
            "accessPackages",
            &package_id,
            json!({ "requestable": false }),
        )
        .await;
        let mine = apps_call!(s.f, mine, &bob, json!({ "tenantId": s.tenant() }))
            .await
            .unwrap();
        assert_eq!(mine, json!([]));
        // Naming a package members may not request is refused.
        let error = apps_call!(
            s.f,
            create,
            owner,
            json!({
                "tenantId": s.tenant(), "key": "other", "name": "Other",
                "launchUrl": "https://other.acme.test", "requestPackageId": package_id,
            })
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.message,
            "requestPackageId must name a package members may request"
        );
    });
}

#[test]
fn checks_assignments_and_reports_unused_ones() {
    run(|| async {
        let s = scenario().await;
        let owner = &s.f.owner;
        let crm = apps_call!(s.f, create, owner, json!({
            "tenantId": s.tenant(), "key": "crm", "name": "CRM", "launchUrl": "https://crm.acme.test",
        }))
        .await
        .unwrap();
        apps_call!(s.f, assign, owner, json!({
            "tenantId": s.tenant(), "appId": crm["id"], "subjectType": "identity", "subjectId": s.alice.id,
        }))
        .await
        .unwrap();
        let answer = allowed(
            &s,
            json!({ "tenantId": s.tenant(), "identityId": s.alice.id, "appId": crm["id"] }),
        )
        .await
        .unwrap();
        assert_eq!(answer["allowed"], json!(true));
        assert_eq!(answer["governed"], json!(true));
        let answer = allowed(
            &s,
            json!({ "tenantId": s.tenant(), "identityId": s.bob.id, "appId": crm["id"] }),
        )
        .await
        .unwrap();
        assert_eq!(answer["allowed"], json!(false));
        assert_eq!(
            allowed(
                &s,
                json!({ "tenantId": s.tenant(), "identityId": s.bob.id, "oauthClientId": "not-in-catalog" }),
            )
            .await
            .unwrap(),
            json!({ "allowed": true, "governed": false })
        );
        // Exactly one target.
        let error = allowed(
            &s,
            json!({ "tenantId": s.tenant(), "identityId": s.bob.id, "appId": crm["id"], "oauthClientId": "x" }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.message, "Name exactly one of appId or oauthClientId");
        assert_eq!(
            code(
                allowed(
                    &s,
                    json!({ "tenantId": s.tenant(), "identityId": s.bob.id, "appId": "missing" })
                )
                .await
            ),
            "NOT_FOUND"
        );
        // The audited `check` answers the same.
        let checked = apps_call!(
            s.f,
            check,
            owner,
            json!({
                "tenantId": s.tenant(), "identityId": s.alice.id, "appId": crm["id"],
            })
        )
        .await
        .unwrap();
        assert_eq!(
            checked,
            json!({ "allowed": true, "governed": true, "appId": crm["id"] })
        );
        s.f.advance(100.0 * DAY);
        let owner = s.f.owner_sign_in().await;
        let usage = apps_call!(
            s.f,
            usage,
            &owner,
            json!({ "tenantId": s.tenant(), "unusedDays": 90 })
        )
        .await
        .unwrap();
        assert_eq!(usage[0]["key"], json!("crm"));
        assert_eq!(usage[0]["people"], json!(1));
        assert_eq!(usage[0]["launchedLast30Days"], json!(0));
        let unused: Vec<&Value> = usage[0]["unused"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| &item["identityId"])
            .collect();
        assert_eq!(unused, vec![&json!(s.alice.id)]);
        assert_eq!(usage[0]["unused"][0]["name"], json!("alice@acme.test"));
        assert_eq!(
            apps_call!(
                s.f,
                remove_unused,
                &owner,
                json!({
                    "tenantId": s.tenant(), "appId": crm["id"], "unusedDays": 90,
                })
            )
            .await
            .unwrap(),
            json!({ "removed": 1 })
        );
        let assignments = apps_call!(
            s.f,
            list_assignments,
            &owner,
            json!({
                "tenantId": s.tenant(), "appId": crm["id"],
            })
        )
        .await
        .unwrap();
        assert_eq!(assignments, json!([]));
        let removal =
            s.f.find("audit", Filter::new().eq("action", "app:unassign"))
                .await;
        assert_eq!(
            removal[0]["metadata"],
            json!({ "subjectType": "identity", "subjectId": s.alice.id, "reason": "unused 90 days" })
        );
        // Members cannot manage the catalog.
        let alice = s.f.sign_in("alice").await;
        // Expired people have no apps even before the worker disables them.
        apps_call!(s.f, assign, &owner, json!({
            "tenantId": s.tenant(), "appId": crm["id"], "subjectType": "identity", "subjectId": s.bob.id,
        }))
        .await
        .unwrap();
        s.f.patch(
            "identities",
            &s.bob.id,
            json!({ "expiresAt": s.f.now() + 60_000.0 }),
        )
        .await;
        s.f.advance(120_000.0);
        let answer = allowed(
            &s,
            json!({ "tenantId": s.tenant(), "identityId": s.bob.id, "appId": crm["id"] }),
        )
        .await
        .unwrap();
        assert_eq!(answer["allowed"], json!(false));
        assert_eq!(
            code(
                apps_call!(s.f, assign, &alice, json!({
                    "tenantId": s.tenant(), "appId": crm["id"], "subjectType": "identity", "subjectId": s.alice.id,
                }))
                .await
            ),
            "ACCESS_DENIED"
        );
    });
}

#[test]
fn keeps_the_catalog_honest() {
    run(|| async {
        let s = scenario().await;
        let owner = &s.f.owner;
        assert_eq!(
            code(
                apps_call!(
                    s.f,
                    create,
                    owner,
                    json!({ "tenantId": s.tenant(), "key": "x", "name": "X" })
                )
                .await
            ),
            "INVALID_INPUT"
        );
        let carol = s.f.member("carol").await;
        let wiki = apps_call!(s.f, create, owner, json!({
            "tenantId": s.tenant(), "key": "wiki", "name": "Wiki", "launchUrl": "https://wiki.acme.test",
            "ownerIds": [carol.id],
        }))
        .await
        .unwrap();
        assert_eq!(wiki["ownerIds"], json!([carol.id]));
        // A deleted owner never blocks disabling the app, and leaves the owner list (`identities.delete`).
        let deleted =
            s.f.patch("identities", &carol.id, json!({ "status": "deleted" }))
                .await;
        let deleted: Identity = better_iam_server::port::decode(deleted).unwrap();
        s.f.iam
            .store
            .transaction(|tx| async move { release_app_records_of(&tx, &deleted).await })
            .await
            .unwrap();
        let disabled = apps_call!(
            s.f,
            update,
            owner,
            json!({
                "tenantId": s.tenant(), "appId": wiki["id"], "enabled": false,
            })
        )
        .await
        .unwrap();
        assert_eq!(disabled["enabled"], json!(false));
        assert_eq!(disabled["ownerIds"], json!([]));
        apps_call!(
            s.f,
            update,
            owner,
            json!({ "tenantId": s.tenant(), "appId": wiki["id"], "enabled": true })
        )
        .await
        .unwrap();
        // The key cannot change; owners must be active people of the organization.
        assert_eq!(
            apps_call!(
                s.f,
                update,
                owner,
                json!({ "tenantId": s.tenant(), "appId": wiki["id"], "key": "other" })
            )
            .await
            .unwrap_err()
            .message,
            "An app key cannot change"
        );
        assert_eq!(
            code(
                apps_call!(
                    s.f,
                    update,
                    owner,
                    json!({
                        "tenantId": s.tenant(), "appId": wiki["id"], "ownerIds": [carol.id],
                    })
                )
                .await
            ),
            "NOT_FOUND"
        );
        // Group assignments go with the group (`groups.delete`).
        let temp = s.f.group("Temp").await;
        apps_call!(s.f, assign, owner, json!({
            "tenantId": s.tenant(), "appId": wiki["id"], "subjectType": "group", "subjectId": temp,
        }))
        .await
        .unwrap();
        apps_call!(s.f, assign, owner, json!({
            "tenantId": s.tenant(), "appId": wiki["id"], "subjectType": "identity", "subjectId": s.alice.id,
        }))
        .await
        .unwrap();
        {
            let tenant_id = s.tenant().to_owned();
            let temp = temp.clone();
            s.f.iam
                .store
                .transaction(|tx| async move {
                    release_group_apps(&tx, &tenant_id, &temp).await?;
                    tx.delete("groups", &temp).await
                })
                .await
                .unwrap();
        }
        let assignments = apps_call!(
            s.f,
            list_assignments,
            owner,
            json!({ "tenantId": s.tenant() })
        )
        .await
        .unwrap();
        let kinds: Vec<&Value> = assignments
            .as_array()
            .unwrap()
            .iter()
            .map(|item| &item["subjectType"])
            .collect();
        assert_eq!(kinds, vec![&json!("identity")]);
        assert_eq!(assignments[0]["subjectName"], json!("alice@acme.test"));
        // A per-app administrator (assign on this app only) sees no addresses and can remove single assignments.
        s.f.grant(
            &s.bob.id,
            json!([
                {
                    "effect": "allow",
                    "actions": ["iam:applications:assign", "iam:applications:read"],
                    "resources": [format!("iam/{}", wiki["id"].as_str().unwrap())],
                },
                { "effect": "allow", "actions": ["iam:applications:read"], "resources": [format!("iam/{}", s.tenant())] },
            ]),
        )
        .await;
        let bob = s.f.sign_in("bob").await;
        let seen = apps_call!(
            s.f,
            list_assignments,
            &bob,
            json!({ "tenantId": s.tenant(), "appId": wiki["id"] })
        )
        .await
        .unwrap();
        assert!(seen[0].get("subjectName").is_none());
        let usage = apps_call!(s.f, usage, &bob, json!({ "tenantId": s.tenant() }))
            .await
            .unwrap();
        assert!(
            usage[0]["unused"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item.get("name").is_none())
        );
        assert_eq!(
            apps_call!(
                s.f,
                unassign,
                &bob,
                json!({ "tenantId": s.tenant(), "assignmentId": seen[0]["id"] })
            )
            .await
            .unwrap(),
            json!({ "removed": true })
        );
        // Launches are refused while an administrator views as the person.
        apps_call!(
            s.f,
            update,
            owner,
            json!({ "tenantId": s.tenant(), "appId": wiki["id"], "visibility": "everyone" })
        )
        .await
        .unwrap();
        s.f.patch(
            "tenants",
            s.tenant(),
            json!({ "authPolicy": { "allowImpersonation": true } }),
        )
        .await;
        let actor =
            s.f.iam
                .ctx
                .principals()
                .unwrap()
                .authenticate(&s.f.owner_sign_in().await)
                .await
                .unwrap();
        let viewing = {
            let auth = s.f.iam.auth.clone();
            let alice = s.alice.clone();
            s.f.iam
                .store
                .transaction(|tx| async move {
                    auth.issue_impersonation_session(&tx, &actor, &alice, 3_600_000.0)
                        .await
                })
                .await
                .unwrap()
        };
        assert_eq!(
            code(
                apps_call!(
                    s.f,
                    launch,
                    &bearer(&viewing.token),
                    json!({
                        "tenantId": s.tenant(), "appId": wiki["id"],
                    })
                )
                .await
            ),
            "IMPERSONATION_RESTRICTED"
        );
    });
}

#[test]
fn governs_oauth_clients() {
    run(|| async {
        let s = scenario().await;
        let owner = &s.f.owner;
        // A client of the organization, as the OAuth provider registers it.
        let client_id = "crm-client";
        s.f.insert(
            "oauthClients",
            json!({ "id": "crm-client-row", "tenantId": s.tenant(), "clientId": client_id, "revoked": false }),
        )
        .await;
        let crm = apps_call!(s.f, create, owner, json!({
            "tenantId": s.tenant(), "key": "crm", "name": "CRM", "launchUrl": "https://crm.acme.test",
            "oauthClientId": client_id,
        }))
        .await
        .unwrap();
        assert_eq!(crm["kind"], json!("oidc"));
        assert_eq!(
            code(
                apps_call!(s.f, create, owner, json!({
                    "tenantId": s.tenant(), "key": "crm2", "name": "CRM again", "launchUrl": "https://crm.acme.test",
                    "oauthClientId": client_id, "visibility": "everyone",
                }))
                .await
            ),
            "CONFLICT"
        );
        assert_eq!(
            apps_call!(s.f, create, owner, json!({
                "tenantId": s.tenant(), "key": "crm3", "name": "CRM", "launchUrl": "https://crm.acme.test",
                "oauthClientId": "unknown-client",
            }))
            .await
            .unwrap_err()
            .message,
            "oauthClientId must name an OAuth client of this organization"
        );
        apps_call!(s.f, assign, owner, json!({
            "tenantId": s.tenant(), "appId": crm["id"], "subjectType": "identity", "subjectId": s.alice.id,
        }))
        .await
        .unwrap();
        let gate = |identity: String, client: &'static str| {
            let host = s.f.iam.protocol_host();
            let tenant = s.tenant().to_owned();
            async move {
                host.client_allowed(&identity, &tenant, client)
                    .await
                    .unwrap()
            }
        };
        assert!(gate(s.alice.id.clone(), client_id).await);
        assert!(!gate(s.bob.id.clone(), client_id).await);
        assert!(gate(s.bob.id.clone(), "some-other-client").await);
        // The conformance entry answers the same.
        let called =
            s.f.iam
                .federation
                .call(
                    "protocolHost.clientAllowed",
                    vec![json!(s.bob.id), json!(s.tenant()), json!(client_id)],
                )
                .await
                .unwrap()
                .unwrap();
        assert_eq!(called, json!(false));
        // Disabling keeps refusing; releasing the client is explicit.
        apps_call!(
            s.f,
            update,
            owner,
            json!({ "tenantId": s.tenant(), "appId": crm["id"], "enabled": false })
        )
        .await
        .unwrap();
        assert!(!gate(s.alice.id.clone(), client_id).await);
        assert_eq!(
            code(
                apps_call!(
                    s.f,
                    delete,
                    owner,
                    json!({ "tenantId": s.tenant(), "appId": crm["id"] })
                )
                .await
            ),
            "CONFLICT"
        );
        assert_eq!(
            code(
                apps_call!(
                    s.f,
                    update,
                    owner,
                    json!({ "tenantId": s.tenant(), "appId": crm["id"], "oauthClientId": "" })
                )
                .await
            ),
            "CONFLICT"
        );
        assert_eq!(
            apps_call!(
                s.f,
                delete,
                owner,
                json!({ "tenantId": s.tenant(), "appId": crm["id"], "releaseClient": true })
            )
            .await
            .unwrap(),
            json!({ "deleted": true })
        );
        assert!(gate(s.bob.id.clone(), client_id).await);
        assert!(
            s.f.find(
                "appAssignments",
                Filter::new().eq("tenantId", s.tenant().to_owned())
            )
            .await
            .is_empty()
        );
    });
}

#[test]
fn lists_the_catalog_with_counts() {
    run(|| async {
        let s = scenario().await;
        let owner = &s.f.owner;
        for (key, name) in [("zeta", "Zeta"), ("alpha", "alpha"), ("beta", "Beta")] {
            apps_call!(s.f, create, owner, json!({
                "tenantId": s.tenant(), "key": key, "name": name, "launchUrl": format!("https://{key}.acme.test"),
                "description": "  Padded  ",
            }))
            .await
            .unwrap();
        }
        let list = apps_call!(s.f, list, owner, json!({ "tenantId": s.tenant() }))
            .await
            .unwrap();
        let order: Vec<&Value> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|app| &app["name"])
            .collect();
        assert_eq!(order, vec![&json!("alpha"), &json!("Beta"), &json!("Zeta")]);
        assert_eq!(list[0]["assignments"], json!(0));
        assert_eq!(list[0]["launchedLast30Days"], json!(0));
        assert_eq!(list[0]["description"], json!("Padded"));
        // Keys are unique per organization and validated.
        assert_eq!(
            code(
                apps_call!(s.f, create, owner, json!({
                    "tenantId": s.tenant(), "key": "beta", "name": "Again", "launchUrl": "https://b.acme.test",
                }))
                .await
            ),
            "CONFLICT"
        );
        assert_eq!(
            apps_call!(s.f, create, owner, json!({
                "tenantId": s.tenant(), "key": "Bad Key", "name": "Bad", "launchUrl": "https://b.acme.test",
            }))
            .await
            .unwrap_err()
            .message,
            "App keys use lowercase letters, digits, dots, underscores or hyphens"
        );
        assert_eq!(
            apps_call!(s.f, create, owner, json!({
                "tenantId": s.tenant(), "key": "vis", "name": "Vis", "launchUrl": "https://b.acme.test",
                "visibility": "public",
            }))
            .await
            .unwrap_err()
            .message,
            "visibility must be 'everyone' or 'assigned'"
        );
        // A member's launcher needs their own organization's session.
        let alice = s.f.sign_in("alice").await;
        assert_eq!(
            code(apps_call!(s.f, mine, &alice, json!({ "tenantId": s.f.root_tenant_id })).await),
            "ACCESS_DENIED"
        );
        assert_eq!(
            apps_call!(s.f, mine, &alice, json!({}))
                .await
                .unwrap_err()
                .message,
            "Invalid tenantId"
        );
    });
}
