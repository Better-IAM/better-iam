//! Port of tests/scim-manager.test.ts: the enterprise extension's `manager.value` mapped to `Identity.managerId` on a
//! Better IAM server's protocol host.

#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use better_iam_core::{Filter, Record};
use better_iam_scim::host::scim_config;
use better_iam_scim::{HttpResponse, ScimService};
use bytes::Bytes;
use organization_fixture::{Org, body, ok, organization, run};
use serde_json::{Value, json};

const ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const BULK: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";

struct Directory {
    f: Org,
    service: ScimService,
    connection: Value,
}

async fn directory(map_manager: Option<bool>) -> Directory {
    let f = organization(|_| {}).await;
    let mut config = scim_config(&f.iam).expect("protocol host");
    config.map_manager = map_manager;
    let service = ScimService::new(config).expect("service");
    let connection = service
        .create_connection(
            &f.owner_credential,
            &json!({ "tenantId": f.tenant_id, "name": "Directory" }),
        )
        .await
        .expect("connection");
    Directory {
        f,
        service,
        connection,
    }
}

fn parse(response: HttpResponse) -> (u16, Value) {
    let status = response.status().as_u16();
    let body = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (status, body)
}

fn managed_by(id: &str) -> Value {
    json!({ ENTERPRISE: { "manager": { "value": id } } })
}

/// `{ ...a, ...b }`.
fn merge(a: Value, b: Value) -> Value {
    let mut out = a.as_object().cloned().unwrap_or_default();
    for (key, value) in b.as_object().cloned().unwrap_or_default() {
        out.insert(key, value);
    }
    Value::Object(out)
}

fn id(value: &Value) -> String {
    value["id"].as_str().unwrap().to_owned()
}

impl Directory {
    async fn request(&self, resource: &str, method: &str, payload: Option<Value>) -> (u16, Value) {
        let request = http::Request::builder()
            .method(method)
            .uri(format!(
                "https://iam.test{}/{resource}",
                self.connection["path"].as_str().unwrap()
            ))
            .header(
                "authorization",
                format!("Bearer {}", self.connection["token"].as_str().unwrap()),
            )
            .header("content-type", "application/scim+json")
            .body(
                payload
                    .map(|payload| Bytes::from(payload.to_string()))
                    .unwrap_or_default(),
            )
            .unwrap();
        parse(self.service.handler(&request).await.expect("a SCIM answer"))
    }

    async fn create(&self, user: Value) -> Value {
        let (status, body) = self.request("Users", "POST", Some(user)).await;
        assert_eq!(status, 201, "{body}");
        body
    }

    async fn put(&self, id: &str, user: Value) -> Value {
        let (status, body) = self
            .request(&format!("Users/{id}"), "PUT", Some(user))
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    async fn patch(&self, id: &str, operations: Value) -> Value {
        let (status, body) = self
            .request(
                &format!("Users/{id}"),
                "PATCH",
                Some(json!({ "schemas": [PATCH], "Operations": operations })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    /// The local identity behind a SCIM user.
    async fn identity_of(&self, user: &Value) -> Record {
        let store = self.f.store();
        let link = store.get("scimUsers", &id(user)).await.unwrap().unwrap();
        store
            .get("identities", link["identityId"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
    }

    async fn identity_id(&self, user: &Value) -> String {
        self.identity_of(user).await["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn manager_of(&self, user: &Value) -> Option<String> {
        self.identity_of(user)
            .await
            .get("managerId")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    async fn set_manager(&self, identity_id: &str, manager_id: &str) {
        ok(self
            .f
            .iam
            .api
            .identities
            .update(
                &self.f.owner_credential,
                body(json!({ "tenantId": self.f.tenant_id, "identityId": identity_id, "managerId": manager_id })),
            )
            .await);
    }
}

fn manager_value(id: &str) -> Value {
    json!([{ "op": "replace", "path": format!("{ENTERPRISE}:manager.value"), "value": id }])
}

#[test]
fn sets_the_manager_on_create_by_scim_id_case_exact_external_id_or_user_name() {
    run(|| async {
        let d = directory(None).await;
        let boss = d
            .create(json!({ "userName": "boss@acme.test", "externalId": "EMP-1" }))
            .await;
        let boss_id = d.identity_id(&boss).await;
        let by_id = d
            .create(merge(
                json!({ "userName": "a@acme.test" }),
                managed_by(&id(&boss)),
            ))
            .await;
        let by_external = d
            .create(merge(
                json!({ "userName": "b@acme.test" }),
                managed_by("EMP-1"),
            ))
            .await;
        let by_user_name = d
            .create(merge(
                json!({ "userName": "c@acme.test" }),
                managed_by("BOSS@acme.test"),
            ))
            .await;
        let wrong_case = d
            .create(merge(
                json!({ "userName": "d@acme.test" }),
                managed_by("emp-1"),
            ))
            .await;
        assert_eq!(
            d.manager_of(&by_id).await.as_deref(),
            Some(boss_id.as_str())
        );
        assert_eq!(
            d.manager_of(&by_external).await.as_deref(),
            Some(boss_id.as_str())
        );
        assert_eq!(
            d.manager_of(&by_user_name).await.as_deref(),
            Some(boss_id.as_str())
        );
        assert_eq!(d.manager_of(&wrong_case).await, None);
        let reports = ok(d
            .f
            .iam
            .api
            .identities
            .list_reports(
                &d.f.owner_credential,
                body(json!({ "tenantId": d.f.tenant_id, "identityId": boss_id })),
            )
            .await);
        let mut ids: Vec<String> = reports
            .as_array()
            .unwrap()
            .iter()
            .map(|report| report["id"].as_str().unwrap().to_owned())
            .collect();
        ids.sort();
        let mut expected = vec![
            d.identity_id(&by_id).await,
            d.identity_id(&by_external).await,
            d.identity_id(&by_user_name).await,
        ];
        expected.sort();
        assert_eq!(ids, expected);

        // Entra ID adds the manager as a bare ID on the manager attribute itself.
        let patched = d
            .patch(
                &id(&wrong_case),
                json!([{ "op": "Add", "path": format!("{ENTERPRISE}:manager"), "value": id(&boss) }]),
            )
            .await;
        assert_eq!(
            patched[ENTERPRISE],
            json!({ "manager": { "value": id(&boss) } })
        );
        assert_eq!(
            d.manager_of(&wrong_case).await.as_deref(),
            Some(boss_id.as_str())
        );
    });
}

#[test]
fn back_fills_reports_provisioned_before_their_manager() {
    run(|| async {
        let d = directory(None).await;
        let first = d
            .create(merge(
                json!({ "userName": "first@acme.test" }),
                managed_by("EMP-9"),
            ))
            .await;
        let second = d
            .create(merge(
                json!({ "userName": "second@acme.test" }),
                managed_by("LEAD@acme.test"),
            ))
            .await;
        let assigned = d
            .create(merge(
                json!({ "userName": "third@acme.test" }),
                managed_by("EMP-9"),
            ))
            .await;
        assert_eq!(d.manager_of(&first).await, None);
        // A manager an administrator set in the meantime is kept.
        let alice = d.f.member("alice").await;
        d.set_manager(&d.identity_id(&assigned).await, &alice).await;

        let lead = d
            .create(json!({ "userName": "lead@acme.test", "externalId": "EMP-9" }))
            .await;
        let lead_id = d.identity_id(&lead).await;
        assert_eq!(
            d.manager_of(&first).await.as_deref(),
            Some(lead_id.as_str())
        );
        assert_eq!(
            d.manager_of(&second).await.as_deref(),
            Some(lead_id.as_str())
        );
        assert_eq!(
            d.manager_of(&assigned).await.as_deref(),
            Some(alice.as_str())
        );
    });
}

#[test]
fn follows_patch_and_put_of_manager_value_and_clears_the_manager_scim_removed() {
    run(|| async {
        let d = directory(None).await;
        let first = d
            .create(json!({ "userName": "first-boss@acme.test" }))
            .await;
        let second = d
            .create(json!({ "userName": "second-boss@acme.test", "externalId": "EMP-2" }))
            .await;
        let user = d.create(json!({ "userName": "user@acme.test" })).await;
        let user_id = id(&user);
        d.patch(&user_id, manager_value(&id(&first))).await;
        assert_eq!(d.manager_of(&user).await, Some(d.identity_id(&first).await));
        d.patch(&user_id, manager_value("EMP-2")).await;
        assert_eq!(
            d.manager_of(&user).await,
            Some(d.identity_id(&second).await)
        );
        d.patch(
            &user_id,
            json!([{ "op": "remove", "path": format!("{ENTERPRISE}:manager") }]),
        )
        .await;
        assert_eq!(d.manager_of(&user).await, None);

        d.put(
            &user_id,
            merge(
                json!({ "userName": "user@acme.test" }),
                managed_by(&id(&first)),
            ),
        )
        .await;
        assert_eq!(d.manager_of(&user).await, Some(d.identity_id(&first).await));
        d.put(
            &user_id,
            json!({ "userName": "user@acme.test", "title": "Engineer" }),
        )
        .await;
        assert_eq!(d.manager_of(&user).await, None);

        // A SCIM-set manager the IdP replaces with someone not provisioned yet is cleared, then back-filled.
        d.patch(&user_id, manager_value(&id(&first))).await;
        d.patch(&user_id, manager_value("EMP-3")).await;
        assert_eq!(d.manager_of(&user).await, None);
        let third = d
            .create(json!({ "userName": "third-boss@acme.test", "externalId": "EMP-3" }))
            .await;
        assert_eq!(d.manager_of(&user).await, Some(d.identity_id(&third).await));
    });
}

#[test]
fn never_clears_a_manager_an_administrator_set() {
    run(|| async {
        let d = directory(None).await;
        let alice = d.f.member("alice").await;
        let boss = d.create(json!({ "userName": "boss@acme.test" })).await;
        let user = d.create(json!({ "userName": "user@acme.test" })).await;
        let user_id = id(&user);
        let identity = d.identity_id(&user).await;
        d.set_manager(&identity, &alice).await;
        d.patch(
            &user_id,
            json!([{ "op": "replace", "path": "displayName", "value": "User" }]),
        )
        .await;
        d.put(&user_id, json!({ "userName": "user@acme.test" }))
            .await;
        assert_eq!(d.manager_of(&user).await.as_deref(), Some(alice.as_str()));

        // The IdP naming a manager wins; once an administrator overrides it, removing it in SCIM keeps theirs.
        d.patch(
            &user_id,
            json!([{ "op": "add", "path": format!("{ENTERPRISE}:manager.value"), "value": id(&boss) }]),
        )
        .await;
        assert_eq!(d.manager_of(&user).await, Some(d.identity_id(&boss).await));
        d.set_manager(&identity, &alice).await;
        d.patch(
            &user_id,
            json!([{ "op": "remove", "path": format!("{ENTERPRISE}:manager") }]),
        )
        .await;
        assert_eq!(d.manager_of(&user).await.as_deref(), Some(alice.as_str()));
    });
}

#[test]
fn ignores_circular_managers_and_settles_reorganizations_sent_reports_first() {
    run(|| async {
        let d = directory(None).await;
        let top = d.create(json!({ "userName": "top@acme.test" })).await;
        let a = d.create(json!({ "userName": "a@acme.test" })).await;
        let b = d
            .create(merge(
                json!({ "userName": "b@acme.test" }),
                managed_by(&id(&a)),
            ))
            .await;
        let c = d
            .create(merge(
                json!({ "userName": "c@acme.test" }),
                managed_by(&id(&b)),
            ))
            .await;
        let (top_id, a_id, b_id) = (
            d.identity_id(&top).await,
            d.identity_id(&a).await,
            d.identity_id(&b).await,
        );
        assert_eq!(d.manager_of(&b).await.as_deref(), Some(a_id.as_str()));

        // B (or B's report C) as A's manager would be circular: ignored, not an error.
        let patched = d.patch(&id(&a), manager_value(&id(&b))).await;
        assert_eq!(patched[ENTERPRISE]["manager"], json!({ "value": id(&b) }));
        assert_eq!(d.manager_of(&a).await, None);
        d.patch(&id(&a), manager_value(&id(&c))).await;
        assert_eq!(d.manager_of(&a).await, None);
        let solo = d
            .create(merge(
                json!({ "userName": "solo@acme.test" }),
                managed_by("solo@acme.test"),
            ))
            .await;
        assert_eq!(d.manager_of(&solo).await, None);

        // Reorganization: A moves under B and B under Top, and the IdP sends A first.
        d.patch(&id(&a), manager_value(&id(&top))).await;
        assert_eq!(d.manager_of(&a).await.as_deref(), Some(top_id.as_str()));
        d.patch(&id(&a), manager_value(&id(&b))).await;
        assert_eq!(d.manager_of(&a).await, None);
        d.patch(&id(&b), manager_value(&id(&top))).await;
        assert_eq!(d.manager_of(&b).await.as_deref(), Some(top_id.as_str()));
        assert_eq!(d.manager_of(&a).await.as_deref(), Some(b_id.as_str()));
        assert_eq!(d.manager_of(&c).await.as_deref(), Some(b_id.as_str()));
    });
}

#[test]
fn releases_reports_when_scim_deletes_their_manager_and_relinks_them_when_it_returns() {
    run(|| async {
        let d = directory(None).await;
        let boss = d
            .create(json!({ "userName": "boss@acme.test", "externalId": "EMP-5" }))
            .await;
        let report = d
            .create(merge(
                json!({ "userName": "report@acme.test" }),
                managed_by("EMP-5"),
            ))
            .await;
        assert_eq!(
            d.manager_of(&report).await,
            Some(d.identity_id(&boss).await)
        );
        assert_eq!(
            d.request(&format!("Users/{}", id(&boss)), "DELETE", None)
                .await
                .0,
            204
        );
        assert_eq!(d.manager_of(&report).await, None);
        let returned = d
            .create(json!({ "userName": "boss-again@acme.test", "externalId": "EMP-5" }))
            .await;
        assert_eq!(
            d.manager_of(&report).await,
            Some(d.identity_id(&returned).await)
        );
    });
}

#[test]
fn back_fills_and_releases_many_reports_in_one_save() {
    run(|| async {
        let d = directory(None).await;
        let operations: Vec<Value> = (0..60)
            .map(|index| {
                json!({
                    "method": "POST",
                    "bulkId": format!("r{index}"),
                    "path": "/Users",
                    "data": merge(
                        json!({ "userName": format!("report-{index}@acme.test") }),
                        managed_by(if index % 2 == 1 { "EMP-7" } else { "LEAD@acme.test" }),
                    ),
                })
            })
            .collect();
        let (_, bulk) = d
            .request(
                "Bulk",
                "POST",
                Some(json!({ "schemas": [BULK], "Operations": operations })),
            )
            .await;
        let statuses: Vec<&str> = bulk["Operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|op| op["status"].as_str().unwrap())
            .collect();
        assert_eq!(statuses, vec!["201"; 60]);
        let lead = d
            .create(json!({ "userName": "lead@acme.test", "externalId": "EMP-7" }))
            .await;
        let lead_id = d.identity_id(&lead).await;
        let reports = || {
            d.f.find(
                "identities",
                Filter::new()
                    .eq("tenantId", d.f.tenant_id.clone())
                    .eq("managerId", lead_id.clone()),
            )
        };
        assert_eq!(reports().await.len(), 60);
        assert_eq!(
            d.request(&format!("Users/{}", id(&lead)), "DELETE", None)
                .await
                .0,
            204
        );
        assert!(reports().await.is_empty());
    });
}

#[test]
fn treats_a_reference_naming_the_user_themself_as_no_manager_never_as_someone_else() {
    run(|| async {
        let d = directory(None).await;
        // A self-managed CEO named by its own externalId, which is also another user's userName.
        let namesake = d.create(json!({ "userName": "jdoe" })).await;
        let ceo = d
            .create(merge(
                json!({ "userName": "ceo@acme.test", "externalId": "jdoe" }),
                managed_by("jdoe"),
            ))
            .await;
        assert_eq!(d.manager_of(&ceo).await, None);
        // Back-fill resolves the same way: saving the namesake adopts no one.
        d.patch(
            &id(&namesake),
            json!([{ "op": "replace", "path": "displayName", "value": "J. Doe" }]),
        )
        .await;
        assert_eq!(d.manager_of(&ceo).await, None);
        // Another user's identical reference still follows precedence: externalId (the CEO) before userName.
        let report = d
            .create(merge(
                json!({ "userName": "report@acme.test" }),
                managed_by("jdoe"),
            ))
            .await;
        assert_eq!(d.manager_of(&report).await, Some(d.identity_id(&ceo).await));
        // SCIM deleting the namesake leaves nobody pointing at its disabled identity.
        let namesake_id = d.identity_id(&namesake).await;
        assert_eq!(
            d.request(&format!("Users/{}", id(&namesake)), "DELETE", None)
                .await
                .0,
            204
        );
        assert!(
            d.f.find(
                "identities",
                Filter::new()
                    .eq("tenantId", d.f.tenant_id.clone())
                    .eq("managerId", namesake_id),
            )
            .await
            .is_empty()
        );

        // Updates too: an own externalId that is another userName ignoring case, and an own SCIM ID that is another
        // user's externalId.
        d.create(json!({ "userName": "e1" })).await;
        let lead = d.create(json!({ "userName": "lead@acme.test" })).await;
        d.put(
            &id(&lead),
            merge(
                json!({ "userName": "lead@acme.test", "externalId": "E1" }),
                managed_by("E1"),
            ),
        )
        .await;
        assert_eq!(d.manager_of(&lead).await, None);
        d.create(json!({ "userName": "shadow@acme.test", "externalId": id(&lead) }))
            .await;
        d.patch(&id(&lead), manager_value(&id(&lead))).await;
        assert_eq!(d.manager_of(&lead).await, None);
    });
}

#[test]
fn never_revives_reassigns_or_regroups_an_identity_an_administrator_deleted() {
    run(|| async {
        let d = directory(None).await;
        let boss = d.create(json!({ "userName": "boss@acme.test" })).await;
        let user = d
            .create(merge(
                json!({ "userName": "gone@acme.test" }),
                managed_by("EMP-8"),
            ))
            .await;
        let (status, group) = d
            .request(
                "Groups",
                "POST",
                Some(json!({ "displayName": "Staff", "members": [{ "value": id(&user) }] })),
            )
            .await;
        assert_eq!(status, 201);
        let identity_id = d.identity_id(&user).await;
        ok(d.f
            .iam
            .api
            .identities
            .delete(
                &d.f.owner_credential,
                body(json!({ "tenantId": d.f.tenant_id, "identityId": identity_id })),
            )
            .await);

        for (method, payload) in [
            (
                "PATCH",
                json!({
                    "schemas": [PATCH],
                    "Operations": [{ "op": "replace", "path": format!("{ENTERPRISE}:manager.value"), "value": id(&boss) }],
                }),
            ),
            (
                "PUT",
                merge(
                    json!({ "userName": "gone@acme.test", "active": true }),
                    managed_by(&id(&boss)),
                ),
            ),
        ] {
            let (status, answer) = d
                .request(&format!("Users/{}", id(&user)), method, Some(payload))
                .await;
            assert_eq!(status, 403, "{method}");
            assert_eq!(answer["scimType"], json!("mutability"));
        }
        // Back-fill skips it, and the IdP's group updates keep it out of the local group (and its mapped roles).
        d.create(json!({ "userName": "lead@acme.test", "externalId": "EMP-8" }))
            .await;
        let (status, _) = d
            .request(
                &format!("Groups/{}", id(&group)),
                "PATCH",
                Some(json!({
                    "schemas": [PATCH],
                    "Operations": [{ "op": "replace", "path": "displayName", "value": "Everyone" }],
                })),
            )
            .await;
        assert_eq!(status, 200);
        let link =
            d.f.store()
                .get("scimGroups", &id(&group))
                .await
                .unwrap()
                .unwrap();
        assert!(
            d.f.find(
                "groupMembers",
                Filter::new()
                    .eq("tenantId", d.f.tenant_id.clone())
                    .eq("groupId", link["groupId"].clone()),
            )
            .await
            .is_empty()
        );
        let tombstone = d.identity_of(&user).await;
        assert_eq!(tombstone["status"], json!("deleted"));
        assert_eq!(tombstone["emailVerified"], json!(false));
        assert!(tombstone.get("email").is_none());
        assert!(tombstone.get("managerId").is_none());

        // The IdP can still deprovision it; the tombstone stays deleted.
        assert_eq!(
            d.request(&format!("Users/{}", id(&user)), "DELETE", None)
                .await
                .0,
            204
        );
        let stored =
            d.f.store()
                .get("identities", &identity_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(stored["status"], json!("deleted"));
    });
}

#[test]
fn leaves_managers_alone_with_map_manager_false() {
    run(|| async {
        let d = directory(Some(false)).await;
        let early = d
            .create(merge(
                json!({ "userName": "early@acme.test" }),
                managed_by("late@acme.test"),
            ))
            .await;
        let boss = d.create(json!({ "userName": "boss@acme.test" })).await;
        let report = d
            .create(merge(
                json!({ "userName": "report@acme.test" }),
                managed_by(&id(&boss)),
            ))
            .await;
        d.create(json!({ "userName": "late@acme.test" })).await;
        let patched = d.patch(&id(&early), manager_value(&id(&boss))).await;
        assert_eq!(
            patched[ENTERPRISE]["manager"],
            json!({ "value": id(&boss) })
        );
        assert_eq!(d.manager_of(&early).await, None);
        assert_eq!(d.manager_of(&report).await, None);
    });
}
