//! The clearances API: ported from tests/clearances.test.ts (schemes and their guarded changes, permissions and recent
//! sign-in, adjudication (never one's own, within-own with the bootstrap exception), NDA-backed read-ins, interim and
//! expiry, suspension and revocation, list/get/mine/explain, labels (raise only, declassify by the cleared), and
//! FEATURE_DISABLED without the option). Tenants, members and grants come from the organization fixture (written as
//! `tenants.create`, `identities.create`, `roles.create` and `bindings.create` write them); the cases that need the
//! guests or agents groups stay in the TypeScript suite and the replayed traces.
//!
//! Every case reaches the clearances module (clearances.ts: `assertClearances`, `effectiveScheme`, `sessionParties`,
//! ...), which another port unit owns; they are ignored until it lands.

mod organization_fixture;

use better_iam_core::{CredentialInput, Filter, Record, classification_template};
use better_iam_server::options::{AuthorizationRequest, ClearanceOptions, ResourceTarget};
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

const OFFICER_PERMISSIONS: [&str; 5] = [
    "iam:clearances:read",
    "iam:clearances:adjudicate",
    "iam:clearances:suspend",
    "iam:classifications:label",
    "iam:classifications:declassify",
];

const DAY: f64 = 86_400_000.0;

async fn enabled() -> Org {
    organization(|options| options.clearances = Some(ClearanceOptions::default())).await
}

fn us_with_compartments() -> Value {
    let mut definition = json!(classification_template("us").unwrap());
    definition["compartments"] = json!([
        { "id": "GAMMA", "name": "Gamma codeword" },
        { "id": "HCS", "name": "Humint control" },
    ]);
    definition
}

fn with(base: &Value, extra: Value) -> Value {
    let mut out = base.as_object().cloned().unwrap_or_default();
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        out.insert(key, value);
    }
    Value::Object(out)
}

/// `administrator(f, name, permissions)`: a member holding a role with `permissions`, signed in.
struct Admin {
    id: String,
    credential: CredentialInput,
}

async fn administrator(f: &Org, name: &str, permissions: &[&str]) -> Admin {
    let id = f.member(name).await;
    f.grant(
        &id,
        json!([{ "sid": "RolePermissions", "effect": "allow", "actions": permissions, "resources": ["*"] }]),
    )
    .await;
    let credential = f.sign_in(&id).await;
    Admin { id, credential }
}

async fn audit_of(f: &Org, action: &str) -> Vec<Record> {
    f.find(
        "audit",
        Filter::new()
            .eq("tenantId", f.tenant_id.clone())
            .eq("action", action),
    )
    .await
}

async fn can_read(f: &Org, credential: &CredentialInput, id: &str) -> bool {
    f.iam
        .authorize(&AuthorizationRequest {
            credential: credential.clone(),
            tenant_id: f.tenant_id.clone(),
            action: "documents:read".into(),
            resource: ResourceTarget {
                kind: "document".into(),
                id: id.into(),
            },
        })
        .await
        .unwrap()
        .allowed
}

#[test]
#[ignore = "needs clearances.ts (the clearances module, another port unit)"]
fn answers_feature_disabled_for_every_method_without_the_option() {
    run(|| async {
        let f = organization(|_| {}).await;
        let api = &f.iam.api.clearances;
        let raw = json!({
            "tenantId": f.tenant_id, "identityId": f.owner_id, "type": "document", "id": "x",
        });
        let c = &f.owner_credential;
        let errors = vec![
            fails(api.debrief(c, body(raw.clone())).await),
            fails(api.declassify(c, body(raw.clone())).await),
            fails(api.define_scheme(c, body(raw.clone())).await),
            fails(api.explain(c, body(raw.clone())).await),
            fails(api.get(c, body(raw.clone())).await),
            fails(api.get_label(c, body(raw.clone())).await),
            fails(api.get_scheme(c, body(raw.clone())).await),
            fails(api.grant(c, body(raw.clone())).await),
            fails(api.label(c, body(raw.clone())).await),
            fails(api.list(c, body(raw.clone())).await),
            fails(api.list_labels(c, body(raw.clone())).await),
            fails(api.mine(c, body(raw.clone())).await),
            fails(api.read_in(c, body(raw.clone())).await),
            fails(api.reinstate(c, body(raw.clone())).await),
            fails(api.revoke(c, body(raw.clone())).await),
            fails(api.suspend(c, body(raw.clone())).await),
            fails(api.templates(c, body(raw.clone())).await),
            fails(api.update(c, body(raw.clone())).await),
            fails(api.update_scheme(c, body(raw.clone())).await),
        ];
        assert!(errors.len() > 15);
        for error in errors {
            assert_eq!(code(&error), "FEATURE_DISABLED");
            assert_eq!(error.status, 403);
        }
        let error = f.iam.clearances.send_reminders(None).await.unwrap_err();
        assert_eq!(code(&error), "FEATURE_DISABLED");
    });
}

#[test]
#[ignore = "needs clearances.ts (the clearances module, another port unit)"]
fn is_routed_over_http() {
    run(|| async {
        let off = organization(|_| {}).await;
        let token = off.owner_credential.token.clone().unwrap();
        let (status, refused) = off
            .post(
                "clearances/getScheme",
                &token,
                json!({ "tenantId": off.tenant_id }),
            )
            .await;
        assert_eq!(status, 403);
        assert_eq!(refused["error"]["code"], "FEATURE_DISABLED");
        let on = enabled().await;
        let token = on.owner_credential.token.clone().unwrap();
        let (status, _) = on
            .post(
                "clearances/defineScheme",
                &token,
                json!({ "tenantId": on.tenant_id, "name": "Acme", "template": "corporate" }),
            )
            .await;
        assert_eq!(status, 200);
        let (_, mine) = on
            .post(
                "clearances/mine",
                &token,
                json!({ "tenantId": on.tenant_id }),
            )
            .await;
        assert_matches(
            &mine["data"],
            json!({ "scheme": { "tenantId": on.tenant_id, "name": "Acme" }, "clearance": null }),
        );
    });
}

#[test]
#[ignore = "needs clearances.ts (the clearances module, another port unit)"]
fn defines_schemes_closest_to_the_root_and_guards_changes_in_use() {
    run(|| async {
        let f = enabled().await;
        let api = &f.iam.api.clearances;
        let tenant_id = f.tenant_id.clone();
        let owner = &f.owner_credential;
        let templates = ok(api.templates(owner, body(json!({}))).await);
        let ids: Vec<&str> = templates
            .as_array()
            .unwrap()
            .iter()
            .map(|template| template["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["us", "uk", "nato", "corporate"]);
        assert_eq!(
            ok(api
                .get_scheme(owner, body(json!({ "tenantId": tenant_id })))
                .await),
            Value::Null
        );
        let error = fails(
            api.define_scheme(
                owner,
                body(json!({ "tenantId": tenant_id, "name": "Acme" })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let scheme = ok(api
            .define_scheme(
                owner,
                body(json!({
                    "tenantId": tenant_id, "name": "Acme", "definition": us_with_compartments(),
                    "requireLabels": ["document"],
                })),
            )
            .await);
        assert_matches(
            &scheme,
            json!({
                "tenantId": tenant_id, "inherited": false, "guestCeiling": null, "interimAllowed": false,
                "adjudication": "within-own", "requireLabels": ["document"], "version": 1,
            }),
        );
        let error = fails(
            api.define_scheme(
                owner,
                body(json!({ "tenantId": tenant_id, "name": "Again", "template": "uk" })),
            )
            .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        // A scheme above one already defined below would re-interpret its clearances and labels.
        let error = fails(
            api.define_scheme(
                &f.root_credential,
                body(json!({ "tenantId": f.root_tenant, "name": "Platform", "template": "nato" })),
            )
            .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let defines = audit_of(&f, "classification:scheme-define").await;
        let metadata = Value::Object(defines[0]["metadata"].as_object().unwrap().clone());
        assert_matches(
            &metadata,
            json!({ "levels": ["U", "C", "S", "TS"], "compartments": ["GAMMA", "HCS"] }),
        );
        assert!(!metadata.to_string().contains("Gamma codeword"));

        // Put levels and a compartment in use.
        let alice = administrator(&f, "alice", &OFFICER_PERMISSIONS).await;
        ok(api
            .grant(
                owner,
                body(json!({
                    "tenantId": tenant_id, "identityId": alice.id, "level": "S", "citizenship": ["USA"],
                })),
            )
            .await);
        ok(api
            .read_in(
                owner,
                body(json!({ "tenantId": tenant_id, "identityId": alice.id, "compartmentId": "GAMMA" })),
            )
            .await);
        ok(api
            .label(
                &alice.credential,
                body(json!({
                    "tenantId": tenant_id, "type": "document", "id": "plan", "label": { "level": "C" },
                })),
            )
            .await);
        let base = us_with_compartments();
        let levels = base["levels"].as_array().unwrap().clone();
        let without_s: Vec<Value> = levels
            .iter()
            .filter(|level| level["id"] != "S")
            .cloned()
            .collect();
        let reranked: Vec<Value> = levels
            .iter()
            .map(|level| match level["id"].as_str().unwrap() {
                "C" => with(level, json!({ "rank": 1 })),
                "U" => level.clone(),
                _ => with(
                    level,
                    json!({ "rank": level["rank"].as_f64().unwrap() + 1.0 }),
                ),
            })
            .collect();
        for definition in [
            with(&base, json!({ "levels": without_s })),
            with(&base, json!({ "levels": reranked })),
            with(
                &base,
                json!({ "compartments": [{ "id": "HCS", "name": "Humint control" }] }),
            ),
        ] {
            let error = fails(
                api.update_scheme(
                    owner,
                    body(json!({ "tenantId": tenant_id, "definition": definition })),
                )
                .await,
            );
            assert_eq!(code(&error), "RESOURCE_IN_USE");
        }
        // New levels go above every level kept.
        let error = fails(
            api.update_scheme(
                owner,
                body(json!({
                    "tenantId": tenant_id,
                    "definition": with(&base, json!({ "levels": [
                        { "id": "U", "name": "UNCLASSIFIED", "rank": 0 },
                        { "id": "X", "name": "EXTRA", "rank": 1 },
                        { "id": "C", "name": "CONFIDENTIAL", "rank": 2 },
                        { "id": "S", "name": "SECRET", "rank": 3 },
                        { "id": "TS", "name": "TOP SECRET", "rank": 4 },
                    ] })),
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let mut more_levels = levels.clone();
        more_levels.push(json!({ "id": "SCI", "name": "SCI", "rank": 4 }));
        let mut more_compartments = base["compartments"].as_array().unwrap().clone();
        more_compartments.push(json!({ "id": "TK", "name": "Talent" }));
        let updated = ok(api
            .update_scheme(
                owner,
                body(json!({
                    "tenantId": tenant_id, "version": 1,
                    "definition": with(&base, json!({ "levels": more_levels, "compartments": more_compartments })),
                    "interimAllowed": true, "guestCeiling": "C",
                })),
            )
            .await);
        assert_matches(
            &updated,
            json!({ "version": 2, "interimAllowed": true, "guestCeiling": "C" }),
        );
        let error = fails(
            api.update_scheme(
                owner,
                body(json!({ "tenantId": tenant_id, "version": 1, "interimAllowed": false })),
            )
            .await,
        );
        assert_eq!(code(&error), "VERSION_CONFLICT");
    });
}

#[test]
#[ignore = "needs clearances.ts (the clearances module, another port unit)"]
fn lets_a_child_inherit_the_roots_scheme_and_refuses_root_its_own_clearance() {
    run(|| async {
        let f = enabled().await;
        let api = &f.iam.api.clearances;
        let root_tenant = f.root_tenant.clone();
        ok(api
            .define_scheme(
                &f.root_credential,
                body(json!({
                    "tenantId": root_tenant, "name": "Platform", "template": "corporate",
                    "adjudication": "unrestricted",
                })),
            )
            .await);
        // Nobody adjudicates their own clearance, root included.
        let error = fails(
            api.grant(
                &f.root_credential,
                body(json!({
                    "tenantId": root_tenant, "identityId": f.root_id, "level": "restricted", "citizenship": [],
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let denied = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", root_tenant.clone())
                    .eq("action", "iam:clearances:adjudicate")
                    .eq("outcome", "deny"),
            )
            .await;
        assert_eq!(denied.len(), 1);
        assert_matches(
            &ok(api
                .get_scheme(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id })),
                )
                .await),
            json!({ "tenantId": root_tenant, "inherited": true }),
        );
        let error = fails(
            api.define_scheme(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "name": "Acme", "template": "us" })),
            )
            .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let error = fails(
            api.update_scheme(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "interimAllowed": true })),
            )
            .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        // Members of the organization are cleared under the inherited scheme.
        let dave = f.member("dave").await;
        let granted = ok(api
            .grant(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id, "identityId": dave, "level": "internal", "citizenship": [],
                })),
            )
            .await);
        assert_matches(
            &granted,
            json!({
                "schemeTenantId": root_tenant, "effectiveStatus": "active", "effectiveLevel": "internal",
            }),
        );
    });
}

#[test]
#[ignore = "needs clearances.ts (the clearances module, another port unit)"]
fn adjudicates_within_ones_own_clearance_bootstraps_once_and_backs_read_ins_with_ndas() {
    run(|| async {
        let f = enabled().await;
        let api = &f.iam.api.clearances;
        let tenant_id = f.tenant_id.clone();
        let owner = &f.owner_credential;
        ok(api
            .define_scheme(
                owner,
                body(json!({ "tenantId": tenant_id, "name": "Acme", "definition": us_with_compartments() })),
            )
            .await);
        let alice = administrator(&f, "alice", &OFFICER_PERMISSIONS).await;
        let bob = administrator(&f, "bob", &OFFICER_PERMISSIONS).await;
        let carol = administrator(&f, "carol", &["documents:read"]).await;
        let grant = |identity: &str, level: &str, citizenship: Value| {
            body(json!({
                "tenantId": tenant_id, "identityId": identity, "level": level, "citizenship": citizenship,
            }))
        };
        // Not even an owner grants themselves a clearance.
        let error = fails(api.grant(owner, grant(&f.owner_id, "TS", json!([]))).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        // The owner holds no clearance but may bootstrap TS: nobody holds it yet.
        let first = ok(api
            .grant(owner, grant(&alice.id, "TS", json!(["USA"])))
            .await);
        assert_matches(
            &first,
            json!({ "status": "active", "effectiveStatus": "active", "effectiveLevel": "TS" }),
        );
        let grants = audit_of(&f, "clearance:grant").await;
        assert_eq!(
            grants[0]["metadata"],
            json!({ "level": "TS", "status": "active", "bootstrap": true })
        );
        assert_eq!(grants[0]["resourceId"], json!(alice.id));
        // Once someone holds it, only cleared officers grant it.
        let error = fails(api.grant(owner, grant(&bob.id, "S", json!(["USA"]))).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        ok(api
            .grant(&alice.credential, grant(&bob.id, "S", json!(["GBR"])))
            .await);
        let error = fails(
            api.grant(&bob.credential, grant(&carol.id, "TS", json!(["USA"])))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        ok(api
            .grant(&bob.credential, grant(&carol.id, "S", json!(["USA"])))
            .await);
        let error = fails(
            api.grant(&alice.credential, grant(&carol.id, "C", json!(["USA"])))
                .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        // Nobody changes their own.
        let error = fails(
            api.update(
                &alice.credential,
                body(json!({ "tenantId": tenant_id, "identityId": alice.id, "citizenship": ["GBR"] })),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            api.grant(
                &alice.credential,
                body(json!({
                    "tenantId": tenant_id, "identityId": carol.id, "level": "S", "citizenship": [],
                    "interim": true,
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");

        // Compartments: alice is not read into GAMMA, so she cannot read others in; the owner bootstraps it once.
        let read_in = |identity: &str| {
            body(json!({ "tenantId": tenant_id, "identityId": identity, "compartmentId": "GAMMA" }))
        };
        let error = fails(api.read_in(&alice.credential, read_in(&carol.id)).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        let bootstrapped = ok(api.read_in(owner, read_in(&alice.id)).await);
        assert_matches(
            &bootstrapped["readIns"][0],
            json!({ "compartmentId": "GAMMA", "compartmentName": "Gamma codeword", "current": true }),
        );
        assert_eq!(bootstrapped["readIns"].as_array().unwrap().len(), 1);
        let error = fails(api.read_in(owner, read_in(&bob.id)).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        let nda = ok(f
            .iam
            .api
            .agreements
            .create(
                owner,
                body(json!({
                    "tenantId": tenant_id, "name": "Compartment NDA", "content": "I will not disclose.",
                    "required": false,
                })),
            )
            .await);
        let nda_id = nda["id"].as_str().unwrap().to_owned();
        let carol_read_in = ok(api
            .read_in(
                &alice.credential,
                body(json!({
                    "tenantId": tenant_id, "identityId": carol.id, "compartmentId": "GAMMA",
                    "agreementId": nda_id,
                })),
            )
            .await);
        assert_matches(
            &carol_read_in["readIns"][0],
            json!({ "compartmentId": "GAMMA", "agreementId": nda_id, "current": false }),
        );
        let read_in_events = audit_of(&f, "clearance:read-in").await;
        assert!(read_in_events.iter().any(|event| event["metadata"]
            == json!({ "compartmentId": "GAMMA", "level": "S", "agreementId": nda_id })));
        assert!(!json!(read_in_events).to_string().contains("Gamma codeword"));

        // A compartmented document: carol reads it only once her NDA acceptance is current.
        let labeled = ok(api
            .label(
                &alice.credential,
                body(json!({
                    "tenantId": tenant_id, "type": "document", "id": "gamma-1",
                    "label": { "level": "C", "compartments": ["GAMMA"] },
                })),
            )
            .await);
        assert_matches(
            &labeled,
            json!({ "levelName": "CONFIDENTIAL", "version": 1 }),
        );
        assert!(!can_read(&f, &carol.credential, "gamma-1").await);
        ok(f.iam
            .api
            .agreements
            .accept(
                &carol.credential,
                body(json!({ "tenantId": tenant_id, "agreementId": nda_id, "version": 1 })),
            )
            .await);
        assert!(can_read(&f, &carol.credential, "gamma-1").await);
        let mine = ok(api
            .mine(&carol.credential, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_matches(
            &mine,
            json!({
                "scheme": { "tenantId": tenant_id, "name": "Acme" },
                "clearance": {
                    "level": { "id": "S", "name": "SECRET" },
                    "effectiveStatus": "active",
                    "citizenship": ["USA"],
                },
            }),
        );
        assert_eq!(
            mine["clearance"]["readIns"],
            json!([{ "compartmentId": "GAMMA", "compartmentName": "Gamma codeword", "agreementId": nda_id, "current": true }])
        );
        // Explain, for officers: bob holds S but no GAMMA.
        let explain = || {
            body(json!({
                "tenantId": tenant_id, "identityId": bob.id, "type": "document", "id": "gamma-1",
            }))
        };
        assert_matches(
            &ok(api.explain(&alice.credential, explain()).await),
            json!({
                "allowed": false,
                "failure": "compartment",
                "label": { "level": "C", "compartments": ["GAMMA"] },
                "party": { "identityId": bob.id, "level": "S", "rank": 2, "compartments": [] },
            }),
        );
        // Without a permission nobody explains or reads clearances.
        let error = fails(api.explain(&carol.credential, explain()).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            api.get(
                &carol.credential,
                body(json!({ "tenantId": tenant_id, "identityId": bob.id })),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");

        // Debrief takes the compartment away at once.
        ok(api.debrief(&bob.credential, body(json!({ "tenantId": tenant_id, "identityId": carol.id, "compartmentId": "GAMMA" }))).await);
        assert!(!can_read(&f, &carol.credential, "gamma-1").await);

        let page = ok(api
            .list(
                owner,
                body(json!({ "tenantId": tenant_id, "status": "active" })),
            )
            .await);
        assert_eq!(page["total"], json!(3));
        let names: Vec<&str> = page["clearances"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["identity"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["alice", "bob", "carol"]);
    });
}

#[test]
#[ignore = "needs clearances.ts (the clearances module, another port unit)"]
fn raises_labels_freely_and_lets_only_the_cleared_declassify() {
    run(|| async {
        let f = enabled().await;
        let api = &f.iam.api.clearances;
        let tenant_id = f.tenant_id.clone();
        let owner = &f.owner_credential;
        ok(api
            .define_scheme(
                owner,
                body(json!({ "tenantId": tenant_id, "name": "Acme", "template": "us" })),
            )
            .await);
        let alice = administrator(&f, "alice", &OFFICER_PERMISSIONS).await;
        ok(api
            .grant(
                owner,
                body(json!({
                    "tenantId": tenant_id, "identityId": alice.id, "level": "S", "citizenship": ["USA"],
                })),
            )
            .await);
        let memo = |label: Value| {
            body(json!({ "tenantId": tenant_id, "type": "document", "id": "memo", "label": label }))
        };
        ok(api
            .label(&alice.credential, memo(json!({ "level": "C" })))
            .await);
        let raised = ok(api
            .label(owner, memo(json!({ "level": "C", "noforn": true })))
            .await);
        assert_matches(
            &raised,
            json!({ "label": { "level": "C", "noforn": true }, "version": 2 }),
        );
        // Lowering any dimension through label is refused (and audited as a denial).
        for label in [
            json!({ "level": "U", "noforn": true }),
            json!({ "level": "C" }),
        ] {
            let error = fails(api.label(&alice.credential, memo(label)).await);
            assert_eq!(code(&error), "ACCESS_DENIED");
        }
        let error = fails(
            api.label(
                &alice.credential,
                memo(json!({ "level": "C", "compartments": ["NOPE"] })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = fails(
            api.label(
                &alice.credential,
                body(json!({ "tenantId": tenant_id, "type": "iam", "id": "x", "label": { "level": "C" } })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let declassify = |label: Value, reason: &str| {
            body(json!({
                "tenantId": tenant_id, "type": "document", "id": "memo", "label": label, "reason": reason,
            }))
        };
        // The owner holds no clearance: declassifying what they could not read is refused.
        let error = fails(
            api.declassify(owner, declassify(Value::Null, "release"))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let lowered = ok(api
            .declassify(
                &alice.credential,
                declassify(json!({ "level": "U" }), "reviewed for release"),
            )
            .await);
        assert_matches(&lowered, json!({ "label": { "level": "U" }, "version": 3 }));
        let get_label = || body(json!({ "tenantId": tenant_id, "type": "document", "id": "memo" }));
        assert_matches(
            &ok(api.get_label(&alice.credential, get_label()).await),
            json!({ "label": { "label": { "level": "U" } }, "inherited": null }),
        );
        assert_eq!(
            ok(api
                .declassify(&alice.credential, declassify(Value::Null, "public"))
                .await),
            Value::Null
        );
        assert_eq!(
            ok(api.get_label(&alice.credential, get_label()).await)["label"],
            Value::Null
        );
        let declassified = audit_of(&f, "classification:declassify")
            .await
            .into_iter()
            .find(|event| event["metadata"]["reason"] == "reviewed for release")
            .unwrap();
        assert_matches(
            &declassified["metadata"],
            json!({
                "type": "document",
                "previous": { "level": "C", "noforn": true },
                "label": { "level": "U" },
                "reason": "reviewed for release",
            }),
        );
        // An id too long for a natural key (over 512 bytes with its type) is keyed by its hash and still labels and
        // lists.
        let long_id = "\u{e9}".repeat(256);
        ok(api
            .label(
                &alice.credential,
                body(json!({
                    "tenantId": tenant_id, "type": "document", "id": long_id, "label": { "level": "S" },
                })),
            )
            .await);
        let listed = ok(api
            .list_labels(
                &alice.credential,
                body(json!({ "tenantId": tenant_id, "type": "document" })),
            )
            .await);
        let ids: Vec<&str> = listed["labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, [long_id.as_str()]);
        assert!(!can_read(&f, owner, &long_id).await);
    });
}

#[test]
#[ignore = "needs clearances.ts (the clearances module, another port unit)"]
fn validates_schemes_and_their_settings_and_changes_only_what_nothing_uses() {
    run(|| async {
        let f = enabled().await;
        let api = &f.iam.api.clearances;
        let tenant_id = f.tenant_id.clone();
        let owner = &f.owner_credential;
        let define = |input: Value| {
            body(with(
                &json!({ "tenantId": tenant_id, "name": "Acme" }),
                input,
            ))
        };
        let mut with_colour = us_with_compartments();
        with_colour["colour"] = json!("red");
        for input in [
            json!({}),
            json!({ "template": "us", "definition": us_with_compartments() }),
            json!({ "template": "secret-service" }),
            json!({ "definition": { "levels": [{ "id": "U", "name": "UNCLASSIFIED", "rank": 0 }] } }),
            json!({ "definition": with_colour }),
            json!({ "template": "us", "name": "" }),
            json!({ "template": "us", "requireLabels": ["iam"] }),
            json!({ "template": "us", "requireLabels": "document" }),
            json!({ "template": "us", "guestCeiling": "COSMIC" }),
            json!({ "template": "us", "guestCeiling": 2 }),
            json!({ "template": "us", "adjudication": "anyone" }),
            json!({ "template": "us", "interimAllowed": "yes" }),
            json!({ "template": "us", "defaultLabel": { "level": "Q" } }),
            json!({ "template": "us", "defaultLabel": { "level": "C", "compartments": ["GAMMA"] } }),
            json!({ "template": "corporate", "defaultLabel": { "level": "internal", "noforn": true } }),
            json!({ "template": "us", "notify": { "emails": ["not an address"] } }),
        ] {
            let error = fails(api.define_scheme(owner, define(input.clone())).await);
            assert_eq!(code(&error), "INVALID_INPUT", "{input}");
        }
        assert_eq!(
            ok(api
                .get_scheme(owner, body(json!({ "tenantId": tenant_id })))
                .await),
            Value::Null
        );
        let error = fails(
            api.update_scheme(
                owner,
                body(json!({ "tenantId": tenant_id, "interimAllowed": true })),
            )
            .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");

        let scheme = ok(api
            .define_scheme(
                owner,
                define(json!({
                    "definition": us_with_compartments(),
                    "requireLabels": ["document", "*", "document"],
                    "defaultLabel": { "level": "C" },
                    "guestCeiling": "C",
                    "notify": { "emails": ["Security@Acme.test", "security@acme.test"] },
                })),
            )
            .await);
        assert_matches(
            &scheme,
            json!({
                "name": "Acme",
                "requireLabels": ["*", "document"],
                "defaultLabel": { "level": "C" },
                "guestCeiling": "C",
                "notify": { "emails": ["security@acme.test"] },
            }),
        );
        let error = fails(
            api.update_scheme(
                owner,
                body(json!({ "tenantId": tenant_id, "template": "uk" })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let base = us_with_compartments();
        let without_c_levels: Vec<Value> = base["levels"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|level| level["id"] != "C")
            .cloned()
            .collect();
        let without_c = with(&base, json!({ "levels": without_c_levels }));
        // Settings that name a level must follow the definition: drop them first.
        for input in [
            json!({ "tenantId": tenant_id, "definition": without_c }),
            json!({ "tenantId": tenant_id, "definition": without_c, "defaultLabel": null }),
        ] {
            let error = fails(api.update_scheme(owner, body(input)).await);
            assert_eq!(code(&error), "INVALID_INPUT");
        }

        // Levels and compartments that only ended clearances used are free to go; a suspended one still holds them.
        let bob = f.member("bob").await;
        let carol = f.member("carol").await;
        ok(api
            .grant(
                owner,
                body(json!({ "tenantId": tenant_id, "identityId": bob, "level": "C", "citizenship": ["USA"] })),
            )
            .await);
        ok(api
            .read_in(
                owner,
                body(json!({ "tenantId": tenant_id, "identityId": bob, "compartmentId": "HCS" })),
            )
            .await);
        ok(api
            .revoke(
                owner,
                body(json!({ "tenantId": tenant_id, "identityId": bob, "reason": "left the program" })),
            )
            .await);
        ok(api
            .grant(
                owner,
                body(json!({ "tenantId": tenant_id, "identityId": carol, "level": "TS", "citizenship": ["USA"] })),
            )
            .await);
        ok(api
            .suspend(
                owner,
                body(json!({
                    "tenantId": tenant_id, "identityId": carol, "reason": "review", "notifyPerson": false,
                })),
            )
            .await);
        let without_ts: Vec<Value> = without_c["levels"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|level| level["id"] != "TS")
            .cloned()
            .collect();
        let error = fails(
            api.update_scheme(
                owner,
                body(json!({
                    "tenantId": tenant_id,
                    "definition": with(&without_c, json!({ "levels": without_ts })),
                    "defaultLabel": null,
                    "guestCeiling": null,
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "RESOURCE_IN_USE");
        let updated = ok(api
            .update_scheme(
                owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Acme programs",
                    "definition": with(&without_c, json!({ "compartments": [{ "id": "GAMMA", "name": "Gamma renamed" }] })),
                    "defaultLabel": null,
                    "guestCeiling": null,
                    "notify": null,
                    "requireLabels": [],
                })),
            )
            .await);
        let levels: Vec<(String, f64)> = updated["definition"]["levels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|level| {
                (
                    level["id"].as_str().unwrap().to_owned(),
                    level["rank"].as_f64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            levels,
            [
                ("U".to_owned(), 0.0),
                ("S".to_owned(), 2.0),
                ("TS".to_owned(), 3.0)
            ]
        );
        assert_eq!(
            updated["definition"]["compartments"],
            json!([{ "id": "GAMMA", "name": "Gamma renamed" }])
        );
        assert_matches(
            &updated,
            json!({ "name": "Acme programs", "requireLabels": [], "guestCeiling": null }),
        );
        assert!(updated.get("defaultLabel").is_none());
        assert!(updated.get("notify").is_none());
        // A level removed cannot come back below the levels kept.
        let error = fails(
            api.update_scheme(
                owner,
                body(json!({ "tenantId": tenant_id, "definition": base })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let update = audit_of(&f, "classification:scheme-update")
            .await
            .into_iter()
            .find(|event| event["metadata"]["version"] == json!(2))
            .unwrap();
        assert_matches(
            &update["metadata"],
            json!({
                "changed": ["definition", "name", "requireLabels", "defaultLabel", "guestCeiling", "notify"],
                "levels": ["U", "S", "TS"],
                "compartments": ["GAMMA"],
            }),
        );
        assert!(!update["metadata"].to_string().contains("Gamma renamed"));
    });
}

#[test]
#[ignore = "needs clearances.ts (the clearances module, another port unit)"]
fn requires_its_permissions_and_a_recent_sign_in_for_everything_that_widens_access() {
    run(|| async {
        let f = enabled().await;
        let api = &f.iam.api.clearances;
        let tenant_id = f.tenant_id.clone();
        let owner = &f.owner_credential;
        ok(api
            .define_scheme(
                owner,
                body(json!({
                    "tenantId": tenant_id, "name": "Acme", "definition": us_with_compartments(),
                    "adjudication": "unrestricted",
                })),
            )
            .await);
        let officer = administrator(&f, "olga", &OFFICER_PERMISSIONS).await;
        let mallory = administrator(&f, "mallory", &["documents:read"]).await;
        let sam = administrator(&f, "sam", &["iam:clearances:suspend"]).await;
        let carol = f.member("carol").await;
        let dave = f.member("dave").await;
        ok(api
            .grant(
                owner,
                body(json!({ "tenantId": tenant_id, "identityId": carol, "level": "S", "citizenship": ["USA"] })),
            )
            .await);
        ok(api
            .read_in(
                owner,
                body(
                    json!({ "tenantId": tenant_id, "identityId": carol, "compartmentId": "GAMMA" }),
                ),
            )
            .await);
        ok(api
            .label(
                &officer.credential,
                body(json!({
                    "tenantId": tenant_id, "type": "document", "id": "brief", "label": { "level": "S" },
                })),
            )
            .await);

        let m = &mallory.credential;
        let person = json!({ "tenantId": tenant_id, "identityId": carol });
        let document = json!({ "tenantId": tenant_id, "type": "document", "id": "brief" });
        macro_rules! p {
            ($e:expr) => {
                body(with(&person, $e))
            };
        }
        macro_rules! d {
            ($e:expr) => {
                body(with(&document, $e))
            };
        }
        macro_rules! t { ($e:expr) => { body(with(&json!({ "tenantId": tenant_id }), $e)) }; }
        let refusals = vec![
            fails(api.get_scheme(m, t!(json!({}))).await),
            fails(
                api.define_scheme(m, t!(json!({ "name": "Mine", "template": "uk" })))
                    .await,
            ),
            fails(
                api.update_scheme(m, t!(json!({ "interimAllowed": true })))
                    .await,
            ),
            fails(
                api.grant(
                    m,
                    t!(json!({ "identityId": dave, "level": "C", "citizenship": [] })),
                )
                .await,
            ),
            fails(api.update(m, p!(json!({ "citizenship": [] }))).await),
            fails(api.read_in(m, p!(json!({ "compartmentId": "HCS" }))).await),
            fails(
                api.debrief(m, p!(json!({ "compartmentId": "GAMMA" })))
                    .await,
            ),
            fails(api.suspend(m, p!(json!({ "reason": "curious" }))).await),
            fails(api.reinstate(m, p!(json!({}))).await),
            fails(api.revoke(m, p!(json!({ "reason": "curious" }))).await),
            fails(api.get(m, p!(json!({}))).await),
            fails(api.list(m, t!(json!({}))).await),
            fails(
                api.explain(m, p!(json!({ "type": "document", "id": "brief" })))
                    .await,
            ),
            fails(
                api.label(m, d!(json!({ "label": { "level": "TS" } })))
                    .await,
            ),
            fails(
                api.declassify(m, d!(json!({ "label": null, "reason": "curious" })))
                    .await,
            ),
            fails(api.get_label(m, d!(json!({}))).await),
            fails(api.list_labels(m, t!(json!({}))).await),
        ];
        for error in refusals {
            assert_eq!(code(&error), "ACCESS_DENIED");
            assert_eq!(error.status, 403);
        }
        let denied = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("actorId", mallory.id.clone())
                    .eq("outcome", "deny"),
            )
            .await;
        assert!(denied.len() >= 17);
        // The templates and one's own clearance need no permission.
        assert_eq!(
            ok(api.templates(m, body(json!({}))).await)
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_matches(
            &ok(api.mine(m, t!(json!({}))).await),
            json!({ "clearance": null }),
        );
        // Officers change no scheme: that is iam:classifications:manage.
        let error = fails(
            api.update_scheme(&officer.credential, t!(json!({ "interimAllowed": true })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // iam:clearances:suspend alone suspends, and nothing else.
        let error = fails(
            api.grant(
                &sam.credential,
                t!(json!({ "identityId": dave, "level": "C", "citizenship": [] })),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");

        // Past the recent sign-in window: what widens access is refused, what narrows it or reads still works.
        f.advance(6.0 * 60_000.0);
        let o = &officer.credential;
        let stale = vec![
            fails(
                api.update_scheme(owner, t!(json!({ "interimAllowed": true })))
                    .await,
            ),
            fails(
                api.grant(
                    o,
                    t!(json!({ "identityId": dave, "level": "C", "citizenship": [] })),
                )
                .await,
            ),
            fails(
                api.update(o, p!(json!({ "citizenship": ["GBR", "USA"] })))
                    .await,
            ),
            fails(api.read_in(o, p!(json!({ "compartmentId": "HCS" }))).await),
            fails(api.revoke(o, p!(json!({ "reason": "done" }))).await),
            fails(
                api.declassify(
                    o,
                    d!(json!({ "label": { "level": "C" }, "reason": "reviewed" })),
                )
                .await,
            ),
        ];
        for error in stale {
            assert_eq!(code(&error), "RECENT_AUTH_REQUIRED");
        }
        assert_matches(
            &ok(api
                .label(o, d!(json!({ "label": { "level": "TS" } })))
                .await),
            json!({ "version": 2 }),
        );
        assert_matches(
            &ok(api
                .debrief(o, p!(json!({ "compartmentId": "GAMMA" })))
                .await),
            json!({ "readIns": [] }),
        );
        assert_matches(
            &ok(api
                .suspend(&sam.credential, p!(json!({ "reason": "incident" })))
                .await),
            json!({ "status": "suspended" }),
        );
        assert_matches(
            &ok(api.get(o, p!(json!({}))).await),
            json!({ "effectiveStatus": "suspended" }),
        );
        assert_eq!(ok(api.list(o, t!(json!({}))).await)["total"], json!(1));
    });
}

#[test]
#[ignore = "needs clearances.ts (the clearances module) and threats.ts endContainment (identities.setStatus), other port units"]
fn bootstraps_only_for_owners_and_root_while_nobody_able_to_use_the_level_holds_it() {
    run(|| async {
        let f = enabled().await;
        let api = &f.iam.api.clearances;
        let tenant_id = f.tenant_id.clone();
        ok(api
            .define_scheme(
                &f.owner_credential,
                body(json!({ "tenantId": tenant_id, "name": "Acme", "template": "us" })),
            )
            .await);
        let bob = administrator(&f, "bob", &OFFICER_PERMISSIONS).await;
        let alice = f.member("alice").await;
        let carol = f.member("carol").await;
        let dave = f.member("dave").await;
        let grant = |identity: &str, level: &str| {
            body(json!({
                "tenantId": tenant_id, "identityId": identity, "level": level, "citizenship": ["USA"],
            }))
        };
        // An officer holding nothing cannot bootstrap: only an owner of the tenant or root may.
        let error = fails(api.grant(&bob.credential, grant(&alice, "TS")).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_matches(
            &ok(api.grant(&f.root_credential, grant(&alice, "TS")).await),
            json!({ "grantedBy": f.root_id, "effectiveLevel": "TS" }),
        );
        // Once someone holds it (or more), root and the owner hold no more authority than any uncleared officer.
        for credential in [&f.root_credential, &f.owner_credential] {
            let error = fails(api.grant(credential, grant(&carol, "U")).await);
            assert_eq!(code(&error), "ACCESS_DENIED");
        }
        // A disabled holder holds nothing, and neither does an ended clearance.
        ok(f.iam
            .api
            .identities
            .set_status(
                &f.owner_credential,
                body(json!({ "tenantId": tenant_id, "identityId": alice, "status": "disabled" })),
            )
            .await);
        ok(api
            .grant(
                &f.owner_credential,
                body(json!({
                    "tenantId": tenant_id, "identityId": carol, "level": "TS", "citizenship": ["USA"],
                    "expiresAt": f.now() + 3_600_000.0,
                })),
            )
            .await);
        let error = fails(api.grant(&f.owner_credential, grant(&dave, "TS")).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        f.advance(2.0 * 3_600_000.0);
        let fresh = f.sign_in(&f.owner_id).await;
        ok(api.grant(&fresh, grant(&dave, "TS")).await);
        let mut grants: Vec<(String, String, Value)> = audit_of(&f, "clearance:grant")
            .await
            .iter()
            .map(|event| {
                (
                    event["resourceId"].as_str().unwrap().to_owned(),
                    event["actorId"].as_str().unwrap().to_owned(),
                    event["metadata"]["bootstrap"].clone(),
                )
            })
            .collect();
        grants.sort_by(|a, b| a.0.cmp(&b.0));
        let mut expected = vec![
            (alice.clone(), f.root_id.clone(), json!(true)),
            (carol.clone(), f.owner_id.clone(), json!(true)),
            (dave.clone(), f.owner_id.clone(), json!(true)),
        ];
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(grants, expected);
    });
}

#[test]
#[ignore = "needs clearances.ts (the clearances module) and threats.ts endContainment (identities.setStatus), other port units"]
fn counts_interim_clearances_and_expiry_at_decision_time() {
    run(|| async {
        let f = enabled().await;
        let api = &f.iam.api.clearances;
        let tenant_id = f.tenant_id.clone();
        ok(api
            .define_scheme(
                &f.owner_credential,
                body(json!({
                    "tenantId": tenant_id, "name": "Acme", "template": "us", "adjudication": "unrestricted",
                    "interimAllowed": true,
                })),
            )
            .await);
        let officer = administrator(&f, "olga", &OFFICER_PERMISSIONS).await;
        let carol = administrator(&f, "carol", &["documents:read"]).await;
        let dave = f.member("dave").await;
        ok(api
            .label(
                &officer.credential,
                body(json!({
                    "tenantId": tenant_id, "type": "document", "id": "brief", "label": { "level": "S" },
                })),
            )
            .await);
        let person = json!({ "tenantId": tenant_id, "identityId": carol.id });
        macro_rules! p {
            ($e:expr) => {
                body(with(&person, $e))
            };
        }
        let expires_at = f.now() + 2.0 * DAY;
        assert_matches(
            &ok(api
                .grant(
                    &f.owner_credential,
                    p!(json!({
                        "level": "S", "citizenship": ["USA"], "interim": true, "expiresAt": expires_at,
                        "reinvestigationDue": f.now() + 365.0 * DAY,
                        "investigation": { "kind": "Tier 3", "completedAt": f.now() - DAY },
                    })),
                )
                .await),
            json!({
                "status": "interim", "effectiveStatus": "interim", "effectiveLevel": "S",
                "expiresAt": expires_at, "investigation": { "kind": "Tier 3" },
            }),
        );
        assert!(can_read(&f, &carol.credential, "brief").await);
        // A scheme that stops allowing interim clearances stops counting them at once.
        ok(api
            .update_scheme(
                &f.owner_credential,
                body(json!({ "tenantId": tenant_id, "interimAllowed": false })),
            )
            .await);
        assert_matches(
            &ok(api.get(&f.owner_credential, p!(json!({}))).await),
            json!({ "status": "interim", "effectiveStatus": "none" }),
        );
        assert!(!can_read(&f, &carol.credential, "brief").await);
        assert_matches(
            &ok(api
                .mine(&carol.credential, body(json!({ "tenantId": tenant_id })))
                .await),
            json!({ "clearance": { "status": "interim", "effectiveStatus": "none", "expiresAt": expires_at } }),
        );
        let error = fails(
            api.update(&f.owner_credential, p!(json!({ "interim": true })))
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        assert_matches(
            &ok(api
                .update(&officer.credential, p!(json!({ "interim": false })))
                .await),
            json!({ "status": "active", "effectiveStatus": "active" }),
        );
        assert!(can_read(&f, &carol.credential, "brief").await);
        let updates = audit_of(&f, "clearance:update").await;
        assert_eq!(
            updates[0]["metadata"],
            json!({ "level": "S", "status": "active", "changed": ["interim"] })
        );

        // Expiry is computed against the clock, not by a job.
        f.advance(3.0 * DAY);
        assert_matches(
            &ok(api.get(&officer.credential, p!(json!({}))).await),
            json!({ "status": "active", "effectiveStatus": "expired" }),
        );
        assert!(!can_read(&f, &carol.credential, "brief").await);
        let expiring = ok(api
            .list(
                &officer.credential,
                body(json!({ "tenantId": tenant_id, "expiringWithinDays": 1 })),
            )
            .await);
        let ids: Vec<&str> = expiring["clearances"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["identityId"].as_str().unwrap())
            .collect();
        assert_eq!(ids, [carol.id.as_str()]);
        let fresh = f.sign_in(&f.owner_id).await;
        let renewed = ok(api.update(&fresh, p!(json!({ "expiresAt": null }))).await);
        assert_matches(&renewed, json!({ "effectiveStatus": "active" }));
        assert!(renewed.get("expiresAt").is_none());
        assert!(can_read(&f, &carol.credential, "brief").await);
        assert_eq!(
            ok(api
                .list(
                    &fresh,
                    body(json!({ "tenantId": tenant_id, "expiringWithinDays": 1 })),
                )
                .await)["total"],
            json!(0)
        );

        let grant_dave = |extra: Value| {
            body(with(
                &json!({ "tenantId": tenant_id, "identityId": dave, "level": "C", "citizenship": ["USA"] }),
                extra,
            ))
        };
        for input in [
            json!({ "expiresAt": f.now() - 1.0 }),
            json!({ "expiresAt": f.now() + 21.0 * 365.0 * DAY }),
            json!({ "reinvestigationDue": f.now() + 21.0 * 365.0 * DAY }),
            json!({ "investigation": { "kind": "Tier 5", "completedAt": f.now() + 2.0 * DAY } }),
            json!({ "investigation": { "kind": "", "completedAt": f.now() } }),
            json!({ "citizenship": ["usa"] }),
            json!({ "citizenship": "USA" }),
            json!({ "citizenship": ["AAA", "BBB", "CCC", "DDD", "EEE", "FFF", "GGG", "HHH", "III", "JJJ", "KKK"] }),
            json!({ "level": "COSMIC" }),
            json!({ "interim": "yes" }),
            json!({ "interim": true }),
        ] {
            let error = fails(api.grant(&fresh, grant_dave(input.clone())).await);
            assert_eq!(code(&error), "INVALID_INPUT", "{input}");
        }
        ok(f.iam
            .api
            .identities
            .set_status(
                &fresh,
                body(json!({ "tenantId": tenant_id, "identityId": dave, "status": "disabled" })),
            )
            .await);
        let error = fails(api.grant(&fresh, grant_dave(json!({}))).await);
        assert_eq!(code(&error), "INVALID_INPUT");
        assert_eq!(
            ok(api
                .get(
                    &fresh,
                    body(json!({ "tenantId": tenant_id, "identityId": dave })),
                )
                .await),
            Value::Null
        );
    });
}
