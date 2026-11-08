//! Port of tests/scim-outbound.test.ts: outbound SCIM provisioning against a minimal downstream SCIM service.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use better_iam_core::{CredentialInput, Filter, IamError};
use better_iam_scim::{
    EventHandler, EventSource, ProvisioningConfig, ProvisioningEvent, ScimProvisioner,
    SubscribeOptions, Unsubscribe, authenticate_fn, authorize_fn,
};
use serde_json::{Value, json};
use support::fake_server::{FakeServer, Incoming, serve};
use support::*;

const TOKEN: &str = "downstream-provisioning-token";

/// An insertion-ordered map (`Map` in JavaScript: `set` on an existing key keeps its position).
#[derive(Default, Clone)]
struct Ordered(Vec<(String, Value)>);

impl Ordered {
    fn set(&mut self, key: &str, value: Value) {
        match self.0.iter_mut().find(|(id, _)| id == key) {
            Some(entry) => entry.1 = value,
            None => self.0.push((key.to_owned(), value)),
        }
    }
    fn get(&self, key: &str) -> Option<&Value> {
        self.0
            .iter()
            .find(|(id, _)| id == key)
            .map(|(_, value)| value)
    }
    fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }
    fn delete(&mut self, key: &str) {
        self.0.retain(|(id, _)| id != key);
    }
    fn values(&self) -> Vec<Value> {
        self.0.iter().map(|(_, value)| value.clone()).collect()
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Default)]
struct Downstream {
    users: Ordered,
    groups: Ordered,
    calls: Vec<String>,
    fail_next: Option<u16>,
}

type Shared = Arc<Mutex<Downstream>>;

/// `/^(\w+) eq "(.*)"$/` (the fake decodes the filter value naively, as the TypeScript fake does).
fn eq_filter(filter: &str) -> (String, String) {
    let (attribute, value) = filter.split_once(" eq \"").expect("an eq filter");
    (
        attribute.to_owned(),
        value.strip_suffix('"').unwrap_or(value).to_owned(),
    )
}

/// A minimal SCIM 2.0 service provider: users in memory, bearer auth, filter by externalId/userName.
async fn fake_scim() -> (FakeServer, Shared) {
    let state: Shared = Arc::new(Mutex::new(Downstream::default()));
    let shared = state.clone();
    let server = serve(Arc::new(move |request: Incoming| {
        let mut downstream = shared.lock().unwrap();
        downstream
            .calls
            .push(format!("{} {}", request.method, request.path));
        if request.header("authorization") != Some(&format!("Bearer {TOKEN}")) {
            return (401, Some(json!({ "detail": "bad token" })));
        }
        if let Some(status) = downstream.fail_next.take() {
            return (status, Some(json!({ "detail": "downstream refused" })));
        }
        let method = request.method.as_str();
        if let Some(rest) = request.path.strip_prefix("/scim/v2/Groups") {
            let group_id = rest
                .strip_prefix('/')
                .filter(|id| !id.is_empty() && !id.contains('/'));
            if rest.is_empty() || group_id.is_some() {
                if group_id.is_none() && method == "GET" {
                    let (attribute, value) = eq_filter(request.param("filter").unwrap_or_default());
                    let matches: Vec<Value> = downstream
                        .groups
                        .values()
                        .into_iter()
                        .filter(|item| item[&attribute] == json!(value))
                        .collect();
                    return (
                        200,
                        Some(json!({ "totalResults": matches.len(), "Resources": matches })),
                    );
                }
                if group_id.is_none() && method == "POST" {
                    let mut item: Value = serde_json::from_str(&request.body).unwrap();
                    let id = better_iam_scim::js::random_uuid();
                    item["id"] = json!(id);
                    downstream.groups.set(&id, item.clone());
                    return (201, Some(item));
                }
                let Some(group_id) = group_id.filter(|id| downstream.groups.has(id)) else {
                    return (404, Some(json!({ "detail": "no such group" })));
                };
                if method == "PUT" {
                    let mut item: Value = serde_json::from_str(&request.body).unwrap();
                    item["id"] = json!(group_id);
                    downstream.groups.set(group_id, item.clone());
                    return (200, Some(item));
                }
                if method == "DELETE" {
                    downstream.groups.delete(group_id);
                    return (204, None);
                }
            }
        }
        let id = request
            .path
            .strip_prefix("/scim/v2/Users/")
            .filter(|id| !id.is_empty() && !id.contains('/'))
            .map(str::to_owned);
        if request.path == "/scim/v2/Users" && method == "GET" {
            let (attribute, value) = eq_filter(request.param("filter").unwrap_or_default());
            let matches: Vec<Value> = downstream
                .users
                .values()
                .into_iter()
                .filter(|user| user[&attribute] == json!(value))
                .collect();
            return (
                200,
                Some(json!({ "totalResults": matches.len(), "Resources": matches })),
            );
        }
        if request.path == "/scim/v2/Users" && method == "POST" {
            let mut user: Value = serde_json::from_str(&request.body).unwrap();
            let id = better_iam_scim::js::random_uuid();
            user["id"] = json!(id);
            downstream.users.set(&id, user.clone());
            return (201, Some(user));
        }
        if let Some(id) = &id
            && !downstream.users.has(id)
        {
            return (404, Some(json!({ "detail": "no such user" })));
        }
        if let Some(id) = &id {
            match method {
                "PUT" => {
                    let mut user: Value = serde_json::from_str(&request.body).unwrap();
                    user["id"] = json!(id);
                    downstream.users.set(id, user.clone());
                    return (200, Some(user));
                }
                "PATCH" => {
                    let patch: Value = serde_json::from_str(&request.body).unwrap();
                    let mut user = downstream.users.get(id).cloned().unwrap();
                    for (key, value) in patch["Operations"][0]["value"].as_object().unwrap() {
                        user[key] = value.clone();
                    }
                    downstream.users.set(id, user.clone());
                    return (200, Some(user));
                }
                "DELETE" => {
                    downstream.users.delete(id);
                    return (204, None);
                }
                _ => {}
            }
        }
        (404, None)
    }))
    .await;
    (server, state)
}

struct Fixture {
    store: Store,
    downstream: Shared,
    server: FakeServer,
    denied: Arc<Mutex<Vec<String>>>,
}

async fn fixture() -> Fixture {
    let store = memory_store().await;
    tenants(&store, &["a"]).await;
    for (id, status, kind) in [
        ("ada", "active", "user"),
        ("bob", "active", "user"),
        ("cy", "disabled", "user"),
        ("robot", "active", "service"),
    ] {
        let mut identity = json!({
            "id": id,
            "tenantId": "a",
            "name": id.to_uppercase(),
            "kind": kind,
        });
        if kind == "user" {
            identity["email"] = json!(format!("{id}@acme.test"));
        }
        for (key, value) in [
            ("emailVerified", json!(true)),
            ("status", json!(status)),
            ("rootAdmin", json!(false)),
            ("owner", json!(false)),
            ("createdAt", json!(now())),
            ("attributes", json!({ "department": format!("{id}-dept") })),
        ] {
            identity[key] = value;
        }
        insert(&store, "identities", record(identity)).await;
    }
    insert(
        &store,
        "groupMembers",
        record(
            json!({ "id": "m1", "tenantId": "a", "groupId": "engineering", "identityId": "ada" }),
        ),
    )
    .await;
    let (server, downstream) = fake_scim().await;
    Fixture {
        store,
        downstream,
        server,
        denied: Arc::new(Mutex::new(Vec::new())),
    }
}

fn key() -> String {
    base64::engine::general_purpose::STANDARD.encode(better_iam_scim::js::random_bytes(32))
}

fn admin() -> CredentialInput {
    token("admin")
}

impl Fixture {
    fn config(&self, encryption_key: String) -> ProvisioningConfig {
        let denied = self.denied.clone();
        let authorize = authorize_fn(
            move |credential: CredentialInput, action: String, _resource| {
                let denied = denied.clone();
                async move {
                    let bearer = credential.headers.as_ref().and_then(|headers| {
                        headers
                            .iter()
                            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                            .map(|(_, value)| value.clone())
                    });
                    if credential.token.as_deref() != Some("admin")
                        && bearer.as_deref() != Some("Bearer admin")
                    {
                        denied.lock().unwrap().push(action);
                        return Err(IamError::with_status("ACCESS_DENIED", "Forbidden", 403));
                    }
                    Ok(())
                }
            },
        );
        let authenticate = authenticate_fn(|_| async { Ok("admin".to_owned()) });
        let mut config =
            ProvisioningConfig::new(self.store.clone(), authorize, authenticate, encryption_key);
        config.allow_insecure_localhost = true;
        config
    }

    fn provisioner(&self) -> ScimProvisioner {
        ScimProvisioner::new(self.config(key())).expect("provisioner")
    }

    fn base(&self) -> String {
        format!("{}/scim/v2", self.server.origin)
    }

    fn users(&self) -> Vec<Value> {
        self.downstream.lock().unwrap().users.values()
    }

    fn by_external(&self, external_id: &str) -> Option<Value> {
        self.users()
            .into_iter()
            .find(|user| user["externalId"] == json!(external_id))
    }

    fn calls(&self) -> Vec<String> {
        self.downstream.lock().unwrap().calls.clone()
    }

    async fn update_identity(&self, id: &str, key: &str, value: Value) {
        let mut identity = get(&self.store, "identities", id).await.unwrap();
        identity.insert(key.into(), value);
        put(&self.store, "identities", identity).await;
    }
}

fn input(f: &Fixture, extra: Value) -> Value {
    let mut base = json!({ "tenantId": "a", "name": "X", "baseUrl": f.base(), "token": TOKEN });
    for (key, value) in extra.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

fn target_ref(target: &Value) -> Value {
    json!({ "tenantId": "a", "targetId": target["id"] })
}

#[test]
fn keeps_downstream_tokens_usable_through_an_encryption_key_rotation() {
    run(|| async {
        let f = fixture().await;
        let old_key = key();
        let new_key = key();
        let make = |encryption_key: &str, previous: Option<Vec<String>>| {
            let mut config = f.config(encryption_key.to_owned());
            config.previous_encryption_keys = previous;
            config.authorize = authorize_fn(|_, _, _| async { Ok(()) });
            ScimProvisioner::new(config)
        };
        let target = make(&old_key, None)
            .unwrap()
            .create_target(
                &admin(),
                &json!({ "tenantId": "a", "name": "Acme Slack", "baseUrl": format!("{}/", f.base()), "token": TOKEN }),
            )
            .await
            .unwrap();
        // Rotating: the new key seals, the old one still opens.
        let during = make(&new_key, Some(vec![old_key.clone()])).unwrap();
        let run = during
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(&run, json!({ "created": 2, "failed": 0 }));
        assert_eq!(
            during.rotate_keys().await.unwrap(),
            json!({ "resealed": 1, "current": 0, "unreadable": 0 })
        );
        assert_eq!(
            during.rotate_keys().await.unwrap(),
            json!({ "resealed": 0, "current": 1, "unreadable": 0 })
        );
        // Afterwards the old key can go.
        let run = make(&new_key, None)
            .unwrap()
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(&run, json!({ "failed": 0 }));
        assert_eq!(
            make(&key(), None).unwrap().rotate_keys().await.unwrap(),
            json!({ "resealed": 0, "current": 0, "unreadable": 1 })
        );
        let error = make(&new_key, Some(vec!["c2hvcnQ=".to_owned()]))
            .err()
            .unwrap();
        assert!(error.message.contains("32 bytes"));
    });
}

#[test]
fn provisions_active_members_updates_changes_and_deactivates_people_who_leave() {
    run(|| async {
        let f = fixture().await;
        let service = f.provisioner();
        let target = service
            .create_target(
                &admin(),
                &json!({
                    "tenantId": "a",
                    "name": "Acme Slack",
                    "baseUrl": format!("{}/", f.base()),
                    "token": TOKEN,
                    "attributeMapping": { "department": "department" },
                }),
            )
            .await
            .unwrap();
        assert_matches(
            &target,
            json!({
                "tenantId": "a",
                "name": "Acme Slack",
                "baseUrl": f.base(),
                "deprovision": "deactivate",
                "enabled": true,
                "provisioned": 0,
            }),
        );
        assert!(!target.to_string().contains(TOKEN));
        let stored: Vec<Value> = find(&f.store, "provisioningTargets", Filter::new())
            .await
            .into_iter()
            .map(Value::Object)
            .collect();
        assert!(!json!(stored).to_string().contains(TOKEN));

        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(
            &run,
            json!({ "created": 2, "updated": 0, "deactivated": 0, "failed": 0 }),
        );
        let mut externals: Vec<String> = f
            .users()
            .iter()
            .map(|user| user["externalId"].as_str().unwrap().to_owned())
            .collect();
        externals.sort();
        assert_eq!(externals, ["ada", "bob"]);
        assert_matches(
            &f.by_external("ada").unwrap(),
            json!({
                "userName": "ada@acme.test",
                "displayName": "ADA",
                "active": true,
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { "department": "ada-dept" },
            }),
        );

        // A second run with no changes touches nothing downstream.
        let before = f.calls().len();
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(&run, json!({ "created": 0, "updated": 0, "unchanged": 2 }));
        assert_eq!(f.calls().len(), before);

        // A rename is pushed; a disabled member is deactivated, not deleted.
        f.update_identity("ada", "name", json!("Ada L.")).await;
        f.update_identity("bob", "status", json!("disabled")).await;
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(&run, json!({ "updated": 1, "deactivated": 1, "failed": 0 }));
        assert_matches(
            &f.by_external("ada").unwrap(),
            json!({ "displayName": "Ada L." }),
        );
        assert_matches(&f.by_external("bob").unwrap(), json!({ "active": false }));
        assert_eq!(
            service
                .get_target(&admin(), &target_ref(&target))
                .await
                .unwrap()["provisioned"],
            json!(1)
        );

        // Re-enabling reactivates the same downstream account.
        f.update_identity("bob", "status", json!("active")).await;
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(&run, json!({ "created": 0, "updated": 1 }));
        assert_eq!(f.users().len(), 2);
        assert_matches(&f.by_external("bob").unwrap(), json!({ "active": true }));
        let actions: Vec<Value> = find(&f.store, "audit", Filter::new().eq("tenantId", "a"))
            .await
            .iter()
            .map(|event| event["action"].clone())
            .collect();
        assert!(actions.contains(&json!("iam:scim:CreateTarget")));
        assert!(actions.contains(&json!("iam:scim:SyncTarget")));
    });
}

#[test]
fn scopes_to_groups_adopts_existing_downstream_users_deletes_when_configured_and_records_failures()
{
    run(|| async {
        let f = fixture().await;
        // A downstream account created by hand earlier is adopted by userName instead of duplicated.
        f.downstream.lock().unwrap().users.set(
            "existing",
            json!({ "id": "existing", "userName": "ada@acme.test", "active": true }),
        );
        let service = f.provisioner();
        let target = service
            .create_target(
                &admin(),
                &input(
                    &f,
                    json!({ "name": "Engineering tools", "groupIds": ["engineering"], "deprovision": "delete" }),
                ),
            )
            .await
            .unwrap();
        let target_id = target["id"].as_str().unwrap().to_owned();
        let run = service.sync_all(Some("a")).await.unwrap()[&target_id].clone();
        assert_matches(&run, json!({ "created": 0, "updated": 1, "failed": 0 }));
        assert_eq!(f.users().len(), 1);
        assert_matches(
            f.downstream.lock().unwrap().users.get("existing").unwrap(),
            json!({ "externalId": "ada", "active": true }),
        );

        // Leaving the group deletes the downstream account in delete mode.
        delete(&f.store, "groupMembers", "m1").await;
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(&run, json!({ "deleted": 1 }));
        assert!(f.users().is_empty());
        assert!(
            find(
                &f.store,
                "provisioningLinks",
                Filter::new().eq("targetId", target_id.clone())
            )
            .await
            .is_empty()
        );

        // Downstream refusals are counted and reported without stopping the run.
        insert(
            &f.store,
            "groupMembers",
            record(json!({ "id": "m2", "tenantId": "a", "groupId": "engineering", "identityId": "bob" })),
        )
        .await;
        f.downstream.lock().unwrap().fail_next = Some(500);
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_eq!(run["failed"], json!(1));
        assert_matches(
            &run["errors"][0],
            json!({ "identityId": "bob", "status": 500 }),
        );
        assert!(
            run["errors"][0]["message"]
                .as_str()
                .unwrap()
                .contains("downstream refused")
        );
        let summary = service
            .get_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(&summary["lastRun"], json!({ "failed": 1 }));
        // The next run retries.
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(&run, json!({ "created": 1, "failed": 0 }));

        // A wrong token fails every call with 401 and is fixed by replacing the token.
        service
            .update_target(
                &admin(),
                &json!({ "tenantId": "a", "targetId": target_id, "token": "wrong-token-value" }),
            )
            .await
            .unwrap();
        f.update_identity("bob", "name", json!("Robert")).await;
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(&run["errors"][0], json!({ "status": 401 }));
        service
            .update_target(
                &admin(),
                &json!({ "tenantId": "a", "targetId": target_id, "token": TOKEN }),
            )
            .await
            .unwrap();
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(&run, json!({ "updated": 1, "failed": 0 }));
    });
}

#[test]
fn pushes_scoped_groups_with_their_provisioned_members() {
    run(|| async {
        let f = fixture().await;
        insert(
            &f.store,
            "groups",
            record(json!({ "id": "engineering", "tenantId": "a", "name": "Engineering" })),
        )
        .await;
        insert(
            &f.store,
            "groups",
            record(json!({ "id": "design", "tenantId": "a", "name": "Design" })),
        )
        .await;
        // An existing downstream group with the same name is adopted.
        f.downstream.lock().unwrap().groups.set(
            "g-existing",
            json!({ "id": "g-existing", "displayName": "Engineering", "members": [] }),
        );
        let service = f.provisioner();
        let target = service
            .create_target(
                &admin(),
                &input(
                    &f,
                    json!({ "name": "With groups", "groupIds": ["engineering", "design"], "pushGroups": true }),
                ),
            )
            .await
            .unwrap();
        assert_eq!(target["pushGroups"], json!(true));
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_eq!(
            run["groups"],
            json!({ "created": 1, "updated": 1, "deleted": 0, "unchanged": 0 })
        );
        let remote_id = |external: &str| f.by_external(external).unwrap()["id"].clone();
        let by_name = |name: &str| {
            f.downstream
                .lock()
                .unwrap()
                .groups
                .values()
                .into_iter()
                .find(|item| item["displayName"] == json!(name))
                .unwrap()
        };
        assert_matches(
            &by_name("Engineering"),
            json!({ "id": "g-existing", "externalId": "engineering", "members": [{ "value": remote_id("ada") }] }),
        );
        assert_matches(&by_name("Design"), json!({ "members": [] }));

        // Membership changes update the group; unchanged groups are left alone.
        insert(
            &f.store,
            "groupMembers",
            record(
                json!({ "id": "m3", "tenantId": "a", "groupId": "design", "identityId": "bob" }),
            ),
        )
        .await;
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(
            &run,
            json!({ "created": 1, "groups": { "updated": 1, "unchanged": 1 } }),
        );
        assert_matches(
            &by_name("Design"),
            json!({ "members": [{ "value": remote_id("bob") }] }),
        );

        // Groups that leave scope are deleted downstream; turning pushGroups off removes the rest.
        service
            .update_target(
                &admin(),
                &json!({ "tenantId": "a", "targetId": target["id"], "groupIds": ["engineering"] }),
            )
            .await
            .unwrap();
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_eq!(run["groups"]["deleted"], json!(1));
        let names: Vec<Value> = f
            .downstream
            .lock()
            .unwrap()
            .groups
            .values()
            .iter()
            .map(|item| item["displayName"].clone())
            .collect();
        assert_eq!(names, vec![json!("Engineering")]);
        service
            .update_target(
                &admin(),
                &json!({ "tenantId": "a", "targetId": target["id"], "pushGroups": false }),
            )
            .await
            .unwrap();
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_eq!(run["groups"]["deleted"], json!(1));
        assert_eq!(f.downstream.lock().unwrap().groups.len(), 0);
        let error = service
            .update_target(
                &admin(),
                &json!({ "tenantId": "a", "targetId": target["id"], "groupIds": [], "pushGroups": true }),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
    });
}

struct Patterns(Arc<Mutex<Vec<Vec<String>>>>);

impl EventSource for Patterns {
    fn subscribe(&self, patterns: Vec<String>, _handler: EventHandler) -> Unsubscribe {
        self.0.lock().unwrap().push(patterns);
        Box::new(|| {})
    }
}

#[test]
fn ignores_lapsed_memberships_and_syncs_after_access_package_changes() {
    run(|| async {
        let f = fixture().await;
        insert(
            &f.store,
            "groups",
            record(json!({ "id": "engineering", "tenantId": "a", "name": "Engineering" })),
        )
        .await;
        // Bob's temporary (or package) membership has already ended but not been purged yet.
        insert(
            &f.store,
            "groupMembers",
            record(json!({
                "id": "m-lapsed",
                "tenantId": "a",
                "groupId": "engineering",
                "identityId": "bob",
                "expiresAt": now() - 1000.0,
            })),
        )
        .await;
        let service = f.provisioner();
        let target = service
            .create_target(
                &admin(),
                &input(
                    &f,
                    json!({ "name": "Scoped", "groupIds": ["engineering"], "pushGroups": true }),
                ),
            )
            .await
            .unwrap();
        service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        let externals: Vec<Value> = f
            .users()
            .iter()
            .map(|user| user["externalId"].clone())
            .collect();
        assert_eq!(externals, vec![json!("ada")]);
        let groups = f.downstream.lock().unwrap().groups.values();
        assert_eq!(groups[0]["members"].as_array().unwrap().len(), 1);

        let patterns = Arc::new(Mutex::new(Vec::new()));
        let unsubscribe =
            service.subscribe(&Patterns(patterns.clone()), SubscribeOptions::default());
        unsubscribe();
        let first = patterns.lock().unwrap()[0].clone();
        assert!(first.contains(&"iam:packages:*".to_owned()));
        assert!(first.contains(&"package:*".to_owned()));
    });
}

#[test]
fn previews_the_next_sync_without_writing_downstream() {
    run(|| async {
        let f = fixture().await;
        f.downstream.lock().unwrap().users.set(
            "existing",
            json!({ "id": "existing", "userName": "bob@acme.test", "active": true }),
        );
        let service = f.provisioner();
        let target = service
            .create_target(&admin(), &input(&f, json!({ "name": "Preview" })))
            .await
            .unwrap();
        let writes = || {
            f.calls()
                .iter()
                .filter(|call| !call.starts_with("GET"))
                .count()
        };
        let plan = service
            .preview_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(
            &plan["counts"],
            json!({ "create": 1, "adopt": 1, "unchanged": 0 }),
        );
        let changes = plan["changes"].as_array().unwrap();
        assert!(changes.contains(
            &json!({ "identityId": "ada", "email": "ada@acme.test", "action": "create" })
        ));
        assert!(changes.contains(
            &json!({ "identityId": "bob", "email": "bob@acme.test", "action": "adopt" })
        ));
        assert_eq!(writes(), 0);
        assert!(
            find(&f.store, "provisioningLinks", Filter::new())
                .await
                .is_empty()
        );
        assert!(
            service
                .get_target(&admin(), &target_ref(&target))
                .await
                .unwrap()
                .get("lastRun")
                .is_none()
        );

        service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        let after_sync = writes();
        f.update_identity("ada", "name", json!("Ada L.")).await;
        f.update_identity("bob", "status", json!("disabled")).await;
        let plan = service
            .preview_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_matches(
            &plan["counts"],
            json!({ "update": 1, "deactivate": 1, "create": 0 }),
        );
        assert_eq!(writes(), after_sync);
        let error = service
            .preview_target(&token("member"), &target_ref(&target))
            .await
            .unwrap_err();
        assert_eq!(error.status, 403);
    });
}

#[test]
fn serves_a_json_management_api_with_the_iam_envelope_and_csrf_rule() {
    run(|| async {
        let f = fixture().await;
        let service = f.provisioner();
        let call = |route: &str, payload: Value, headers: Vec<(&'static str, &'static str)>| {
            let mut all: Vec<(&str, &str)> = vec![
                ("content-type", "application/json"),
                ("x-better-iam", "1"),
                ("authorization", "Bearer admin"),
            ];
            for (name, value) in headers {
                match all.iter_mut().find(|(key, _)| *key == name) {
                    Some(entry) => entry.1 = value,
                    None => all.push((name, value)),
                }
            }
            request(
                "POST",
                &format!("https://iam.test/scim/provisioning/{route}"),
                &all,
                Some(payload.to_string()),
            )
        };
        let created = service
            .handler(&call(
                "targets/create",
                input(&f, json!({ "name": "Over HTTP" })),
                vec![],
            ))
            .await
            .unwrap();
        let created = answer(created);
        assert_eq!(created.status, 200);
        let id = created.body["data"]["id"].clone();
        let synced = answer(
            service
                .handler(&call(
                    "targets/sync",
                    json!({ "tenantId": "a", "targetId": id }),
                    vec![],
                ))
                .await
                .unwrap(),
        );
        assert_eq!(synced.body["data"]["created"], json!(2));
        let listed = answer(
            service
                .handler(&call("targets/list", json!({ "tenantId": "a" }), vec![]))
                .await
                .unwrap(),
        );
        let data = listed.body["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        assert_matches(&data[0], json!({ "id": id, "provisioned": 2 }));
        // Missing CSRF header, wrong caller, unknown route, other paths.
        let csrf = service
            .handler(&call(
                "targets/list",
                json!({ "tenantId": "a" }),
                vec![("x-better-iam", "0")],
            ))
            .await
            .unwrap();
        assert_eq!(csrf.status().as_u16(), 403);
        let forbidden = answer(
            service
                .handler(&call(
                    "targets/list",
                    json!({ "tenantId": "a" }),
                    vec![("authorization", "Bearer member")],
                ))
                .await
                .unwrap(),
        );
        assert_eq!(forbidden.status, 403);
        assert_eq!(
            forbidden.body,
            json!({ "error": { "code": "ACCESS_DENIED", "message": "Forbidden" } })
        );
        assert_eq!(
            service
                .handler(&call("targets/nope", json!({}), vec![]))
                .await
                .unwrap()
                .status()
                .as_u16(),
            404
        );
        assert!(
            service
                .handler(&request("GET", "https://iam.test/elsewhere", &[], None))
                .await
                .is_none()
        );
    });
}

struct Handlers(Arc<Mutex<Vec<EventHandler>>>);

impl EventSource for Handlers {
    fn subscribe(&self, _patterns: Vec<String>, handler: EventHandler) -> Unsubscribe {
        self.0.lock().unwrap().push(handler);
        let handlers = self.0.clone();
        Box::new(move || {
            handlers.lock().unwrap().pop();
        })
    }
}

#[test]
fn syncs_from_iam_events_guards_management_and_validates_input() {
    run(|| async {
        let f = fixture().await;
        let service = f.provisioner();
        let target = service
            .create_target(&admin(), &input(&f, json!({ "name": "Events" })))
            .await
            .unwrap();
        let handlers: Arc<Mutex<Vec<EventHandler>>> = Arc::new(Mutex::new(Vec::new()));
        let unsubscribe = service.subscribe(
            &Handlers(handlers.clone()),
            SubscribeOptions {
                debounce_ms: Some(10),
                on_error: None,
            },
        );
        let fire = |action: &str| {
            let handler = handlers.lock().unwrap()[0].clone();
            handler(ProvisioningEvent {
                tenant_id: "a".into(),
                action: action.into(),
            });
        };
        // Its own audit events never trigger a run; member changes do (debounced).
        fire("iam:scim:SyncTarget");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(f.users().is_empty());
        fire("iam:identities:update");
        fire("iam:groups:update");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(f.users().len(), 2);
        unsubscribe();
        assert!(handlers.lock().unwrap().is_empty());

        let error = service
            .sync_target(&token("member"), &target_ref(&target))
            .await
            .unwrap_err();
        assert_eq!(error.status, 403);
        assert!(
            f.denied
                .lock()
                .unwrap()
                .contains(&"iam:scim:targets:sync".to_owned())
        );
        let error = service
            .get_target(
                &admin(),
                &json!({ "tenantId": "b", "targetId": target["id"] }),
            )
            .await
            .unwrap_err();
        assert_eq!(error.status, 404);
        for extra in [
            json!({ "baseUrl": "http://scim.example.test/v2" }),
            json!({ "baseUrl": "not a url" }),
            json!({ "token": "short" }),
            json!({ "deprovision": "archive" }),
            json!({ "attributeMapping": { "manager": "boss" } }),
            json!({ "name": "" }),
        ] {
            let error = service
                .create_target(&admin(), &input(&f, extra.clone()))
                .await
                .unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "{extra}");
        }

        // Disabling a target deprovisions everyone on the next run; deleting it leaves downstream accounts alone.
        service
            .update_target(
                &admin(),
                &json!({ "tenantId": "a", "targetId": target["id"], "enabled": false }),
            )
            .await
            .unwrap();
        let run = service
            .sync_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_eq!(run["deactivated"], json!(2));
        service
            .delete_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        assert_eq!(
            service
                .list_targets(&admin(), &json!({ "tenantId": "a" }))
                .await
                .unwrap(),
            json!([])
        );
        assert!(
            find(&f.store, "provisioningLinks", Filter::new())
                .await
                .is_empty()
        );
        assert_eq!(f.users().len(), 2);
        let mut config = f.config("short".into());
        config.authorize = authorize_fn(|_, _, _| async { Ok(()) });
        let error = ScimProvisioner::new(config).err().unwrap();
        assert!(error.message.contains("32 bytes"));
    });
}

/// Port of tests/security-outbound.test.ts "outbound SCIM targets".
#[test]
fn refuses_private_base_urls_and_keeps_the_token_from_following_a_base_url_change() {
    run(|| async {
        let f = fixture().await;
        let mut config = f.config(key());
        config.authorize = authorize_fn(|credential: CredentialInput, _, _| async move {
            if credential.token.as_deref() != Some("admin") {
                return Err(IamError::with_status("ACCESS_DENIED", "Forbidden", 403));
            }
            Ok(())
        });
        let scim = ScimProvisioner::new(config).unwrap();
        for base_url in ["https://10.0.0.1:8443/scim", "https://[fd00::1]/scim"] {
            let error = scim
                .create_target(
                    &admin(),
                    &json!({ "tenantId": "a", "name": "Internal", "baseUrl": base_url, "token": TOKEN }),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "{base_url}");
        }
        let received: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();
        let server = serve(Arc::new(move |request: Incoming| {
            sink.lock()
                .unwrap()
                .push(request.header("authorization").map(str::to_owned));
            (200, Some(json!({ "totalResults": 0, "Resources": [] })))
        }))
        .await;
        let target = scim
            .create_target(
                &admin(),
                &json!({ "tenantId": "a", "name": "App", "baseUrl": "https://app.example.test/scim/v2", "token": TOKEN }),
            )
            .await
            .unwrap();
        let moved_url = format!("{}/scim", server.origin);
        let error = scim
            .update_target(
                &admin(),
                &json!({ "tenantId": "a", "targetId": target["id"], "baseUrl": moved_url }),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        // Renaming keeps the token; a new URL with a new token is fine.
        scim.update_target(
            &admin(),
            &json!({ "tenantId": "a", "targetId": target["id"], "name": "Renamed" }),
        )
        .await
        .unwrap();
        let moved = scim
            .update_target(
                &admin(),
                &json!({
                    "tenantId": "a",
                    "targetId": target["id"],
                    "baseUrl": moved_url,
                    "token": "a-new-downstream-token",
                }),
            )
            .await
            .unwrap();
        assert_eq!(moved["baseUrl"], json!(moved_url));
        scim.preview_target(&admin(), &target_ref(&target))
            .await
            .unwrap();
        let received = received.lock().unwrap().clone();
        assert!(!received.is_empty());
        assert!(
            received
                .iter()
                .all(|value| value.as_deref() == Some("Bearer a-new-downstream-token"))
        );
    });
}
