//! Tests of `package-rules.ts`, the rule language of automatic (birthright) access packages. The TypeScript suites
//! exercise it through `packages.create`, `packages.previewAutoAssign` and onboarding flows
//! (tests/security-packages.test.ts, tests/org-birthright.test.ts); these cases check the same outcomes on the pure
//! functions: the validation errors, the keys a rule may test, the warnings, and evaluation.

use better_iam_core::{AttributeType, Identity};
use better_iam_server::package_rules::{
    AutoAssignInput, RuleEnvironment, RuleOrgFacts, map_rule_groups, map_rule_values,
    parse_auto_assign, rule_context, rule_document, rule_group_ids, rule_input, rule_keys,
    rule_match, rule_problem, rule_values, rule_warnings, same_rule_input,
};
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

fn people() -> Value {
    json!({ "StringEquals": { "principal.kind": "user" } })
}

fn attributes(list: &[(&str, AttributeType)]) -> IndexMap<String, AttributeType> {
    list.iter()
        .map(|(name, kind)| ((*name).to_owned(), *kind))
        .collect()
}

fn env(identity_attributes: IndexMap<String, AttributeType>) -> RuleEnvironment {
    RuleEnvironment {
        identity_attributes,
        groups: None,
        packaged_groups: None,
        org: None,
        extra: Map::new(),
    }
}

fn set(items: &[&str]) -> IndexSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

#[track_caller]
fn refused(value: Value, env: &RuleEnvironment) -> (String, String) {
    match parse_auto_assign(Some(&value), env, None) {
        Ok(parsed) => panic!("expected a refusal, got {parsed:?}"),
        Err(error) => (error.code, error.message),
    }
}

fn identity(overrides: Value) -> Identity {
    let mut base = json!({
        "id": "i-alice",
        "tenantId": "t-acme",
        "kind": "user",
        "email": "Alice@Acme.TEST",
        "name": "Alice",
        "status": "active",
        "emailVerified": true,
        "rootAdmin": false,
        "owner": false,
        "createdAt": 0,
    });
    for (key, value) in overrides.as_object().unwrap() {
        base[key] = value.clone();
    }
    serde_json::from_value(base).unwrap()
}

#[test]
fn lists_fixed_keys_first_then_org_keys_then_declared_attributes_sorted() {
    let declared = attributes(&[
        ("level", AttributeType::Number),
        ("department", AttributeType::String),
        ("contractor", AttributeType::Boolean),
    ]);
    let keys = rule_keys(&declared, None).unwrap();
    let names: Vec<&str> = keys.iter().map(|key| key.key.as_str()).collect();
    assert_eq!(
        names,
        [
            "principal.id",
            "principal.kind",
            "principal.owner",
            "identity.email",
            "identity.emailDomain",
            "identity.emailVerified",
            "identity.managerId",
            "identity.groups",
            "identity.guest",
            "principal.contractor",
            "principal.department",
            "principal.level",
        ]
    );
    let with_org = rule_keys(&declared, Some(&json!({ "org": true }))).unwrap();
    let names: Vec<&str> = with_org.iter().map(|key| key.key.as_str()).collect();
    assert_eq!(
        &names[9..12],
        [
            "identity.teams",
            "identity.departments",
            "identity.licenses"
        ]
    );
    let department = keys
        .iter()
        .find(|key| key.key == "principal.department")
        .unwrap();
    assert_eq!(department.r#type, "string");
    assert!(department.operators.contains(&"DateBefore".to_owned()));
    assert_eq!(department.operators.last().unwrap(), "Exists");
    let level = keys
        .iter()
        .find(|key| key.key == "principal.level")
        .unwrap();
    assert_eq!(level.operators[0], "NumericEquals");
    let groups = keys
        .iter()
        .find(|key| key.key == "identity.groups")
        .unwrap();
    assert_eq!(
        serde_json::to_value(groups).unwrap(),
        json!({ "key": "identity.groups", "type": "array", "operators": ["ArrayContains", "ArrayContainsAll", "Exists"] })
    );
}

#[test]
fn parses_a_rule_keeping_values_as_given_and_dropping_a_zero_grace() {
    let rule = json!({
        "include": [{ "StringEquals": { "principal.kind": "user", "identity.emailDomain": ["acme.test"] } }],
        "exclude": [],
        "graceMs": 0,
        "maxGrants": 5,
    });
    let parsed = parse_auto_assign(Some(&rule), &env(IndexMap::new()), None).unwrap();
    assert_eq!(
        parsed.to_value(),
        json!({
            "include": [{ "StringEquals": { "principal.kind": "user", "identity.emailDomain": ["acme.test"] } }],
            "maxGrants": 5,
        })
    );
    let with_grace = parse_auto_assign(
        Some(&json!({ "include": [people()], "exclude": [{ "Bool": { "identity.guest": true } }], "graceMs": 86_400_000 })),
        &env(IndexMap::new()),
        None,
    )
    .unwrap();
    assert_eq!(with_grace.grace_ms, Some(86_400_000.0));
    assert_eq!(with_grace.exclude.as_ref().map(Vec::len), Some(1));
}

#[test]
fn refuses_malformed_rules_with_the_typescript_messages() {
    let plain = env(attributes(&[("department", AttributeType::String)]));
    assert_eq!(
        refused(json!([]), &plain),
        (
            "INVALID_INPUT".into(),
            "autoAssign must be an object".into()
        )
    );
    assert_eq!(
        refused(json!({ "include": [people()], "owner": "x" }), &plain).1,
        "autoAssign: unknown field owner"
    );
    assert_eq!(
        refused(json!({ "include": [] }), &plain).1,
        "autoAssign.include must list 1-10 condition sets"
    );
    assert_eq!(
        refused(json!({ "include": [people()], "exclude": null }), &plain).1,
        "autoAssign.exclude must list at most 10 condition sets"
    );
    assert_eq!(
        refused(json!({ "include": [{}] }), &plain).1,
        "autoAssign.include[0] must be a nonempty condition set"
    );
    let (code, message) = refused(
        json!({ "include": [{ "StringMatches": { "principal.kind": "user" } }] }),
        &plain,
    );
    assert_eq!(code, "INVALID_POLICY");
    assert!(message.starts_with("autoAssign.include[0]: "), "{message}");
    assert_eq!(
        refused(
            json!({ "include": [{ "ArrayContains": { "principal.groups": ["g"] } }] }),
            &plain
        )
        .1,
        "autoAssign.include[0]: use identity.groups (memberships not created by access packages) instead of principal.groups"
    );
    assert_eq!(
        refused(
            json!({ "include": [{ "Bool": { "principal.mfa": true } }] }),
            &plain
        )
        .1,
        "autoAssign.include[0]: principal.mfa describes a session or grant and is not available to package rules"
    );
    assert_eq!(
        refused(
            json!({ "include": [{ "StringEquals": { "principal.sessionTags.team": "a" } }] }),
            &plain
        )
        .1,
        "autoAssign.include[0]: principal.sessionTags.team describes a session or grant and is not available to package rules"
    );
    assert_eq!(
        refused(
            json!({ "include": [people(), { "ArrayContains": { "identity.teams": ["t"] } }] }),
            &plain
        )
        .1,
        "autoAssign.include[1]: identity.teams is available to access package rules only"
    );
    assert_eq!(
        refused(
            json!({ "include": [{ "StringEquals": { "principal.title": "x" } }] }),
            &plain
        )
        .1,
        "autoAssign.include[0]: unknown key principal.title; use principal.id, principal.kind, principal.owner, identity.email, identity.emailDomain, identity.emailVerified, identity.managerId, identity.groups, identity.guest, or principal.<declared attribute> (department)"
    );
    assert_eq!(
        refused(
            json!({ "include": [{ "StringEquals": { "principal.title": "x" } }] }),
            &env(IndexMap::new())
        )
        .1,
        "autoAssign.include[0]: unknown key principal.title; use principal.id, principal.kind, principal.owner, identity.email, identity.emailDomain, identity.emailVerified, identity.managerId, identity.groups, identity.guest, or principal.<declared attribute> (none declared)"
    );
    assert_eq!(
        refused(
            json!({ "include": [{ "NumericEquals": { "principal.kind": 1 } }] }),
            &plain
        )
        .1,
        "autoAssign.include[0]: NumericEquals cannot test principal.kind (string); use StringEquals, StringNotEquals, StringEqualsIgnoreCase, StringNotEqualsIgnoreCase, StringLike, StringNotLike, StringLikeIgnoreCase, Exists"
    );
    assert_eq!(
        refused(
            json!({ "include": [{ "StringEquals": { "principal.department": "${principal.id}" } }] }),
            &plain
        )
        .1,
        "autoAssign.include[0]: policy variables are not available in package rules"
    );
    assert_eq!(
        refused(
            json!({ "include": [{ "StringEquals": { "principal.kind": ["user", "agent"] } }] }),
            &plain
        )
        .1,
        "autoAssign.include[0]: principal.kind is 'user' or 'service'"
    );
    // StringLike may name any pattern.
    assert!(
        parse_auto_assign(
            Some(&json!({ "include": [{ "StringLike": { "principal.kind": "us*" } }] })),
            &plain,
            None
        )
        .is_ok()
    );
    assert_eq!(
        refused(
            json!({ "include": [people()], "graceMs": 91 * 86_400_000_i64 }),
            &plain
        )
        .1,
        "Invalid autoAssign.graceMs"
    );
    assert_eq!(
        refused(json!({ "include": [people()], "maxRemovals": 0 }), &plain).1,
        "Invalid autoAssign.maxRemovals"
    );
    let large: Vec<Value> = (0..10)
        .map(|index| {
            json!({ "StringEquals": { "principal.kind": "user", "identity.email": format!("{index}{}", "x".repeat(2000)) } })
        })
        .collect();
    assert_eq!(
        refused(json!({ "include": large }), &plain).1,
        "autoAssign is larger than 16384 bytes"
    );
    // The path names the offending document entry.
    let error =
        parse_auto_assign(Some(&json!(1)), &plain, Some("packages[2].autoAssign")).unwrap_err();
    assert_eq!(error.message, "packages[2].autoAssign must be an object");
}

#[test]
fn checks_the_groups_teams_and_departments_a_rule_names() {
    let mut scoped = env(IndexMap::new());
    scoped.groups = Some(set(&["g-wiki", "g-finance"]));
    scoped.packaged_groups = Some(set(&["g-finance"]));
    scoped.org =
        Some(json!({ "teams": ["t-platform"], "departments": ["d-eng"], "licenses": ["figma"] }));
    let clause = |conditions: Value| {
        let mut clause = people();
        for (key, value) in conditions.as_object().unwrap() {
            clause[key] = value.clone();
        }
        json!({ "include": [clause] })
    };
    assert_eq!(
        refused(
            clause(json!({ "ArrayContains": { "identity.groups": ["g-nope"] } })),
            &scoped
        )
        .1,
        "autoAssign.include[0]: unknown group g-nope"
    );
    assert_eq!(
        refused(
            clause(json!({ "ArrayContains": { "identity.groups": ["g-finance"] } })),
            &scoped
        )
        .1,
        "autoAssign.include[0]: identity.groups cannot name g-finance, a group this package grants"
    );
    assert_eq!(
        refused(
            clause(json!({ "ArrayContains": { "identity.groups": [3] } })),
            &scoped
        )
        .1,
        "autoAssign.include[0]: identity.groups lists groups"
    );
    assert_eq!(
        refused(
            clause(json!({ "ArrayContains": { "identity.teams": ["no-such-team"] } })),
            &scoped
        )
        .1,
        "autoAssign.include[0]: unknown team no-such-team"
    );
    assert_eq!(
        refused(
            clause(json!({ "ArrayContains": { "identity.departments": ["t-platform"] } })),
            &scoped
        )
        .1,
        "autoAssign.include[0]: unknown department t-platform"
    );
    assert_eq!(
        refused(
            clause(json!({ "ArrayContainsAll": { "identity.licenses": ["slack"] } })),
            &scoped
        )
        .1,
        "autoAssign.include[0]: unknown license slack"
    );
    assert_eq!(
        refused(
            clause(json!({ "ArrayContains": { "identity.teams": [true] } })),
            &scoped
        )
        .1,
        "autoAssign.include[0]: identity.teams lists teams"
    );
    let (code, _) = refused(
        clause(
            json!({ "StringEquals": { "principal.kind": "user", "identity.teams": "t-platform" } }),
        ),
        &scoped,
    );
    assert_eq!(code, "INVALID_INPUT");
    assert!(
        parse_auto_assign(
            Some(&clause(
                json!({ "Exists": { "identity.departments": true } })
            )),
            &scoped,
            None
        )
        .is_ok()
    );
    assert!(
        parse_auto_assign(
            Some(&clause(json!({ "ArrayContains": { "identity.teams": "t-platform", "identity.groups": "g-wiki" } }))),
            &scoped,
            None
        )
        .is_ok()
    );
    // Without the valid sets nothing is checked, but the keys are still offered.
    let mut unchecked = env(IndexMap::new());
    unchecked.org = Some(json!({}));
    assert!(
        parse_auto_assign(
            Some(&clause(
                json!({ "ArrayContains": { "identity.teams": ["anything"] } })
            )),
            &unchecked,
            None
        )
        .is_ok()
    );
    let message = refused(
        json!({ "include": [{ "StringEquals": { "principal.title": "x" } }] }),
        &unchecked,
    )
    .1;
    assert!(
        message.contains("identity.guest, identity.teams, identity.departments, identity.licenses, or principal.<declared attribute>"),
        "{message}"
    );
}

#[test]
fn warns_about_facts_lower_privileged_callers_control() {
    let rule = json!({
        "include": [
            { "StringEquals": { "principal.kind": "user", "principal.department": "finance" } },
            { "StringEquals": { "principal.kind": "user", "identity.managerId": "i-mallory" } },
            { "StringEquals": { "principal.kind": "user" }, "ArrayContains": { "identity.groups": ["g-lounge", "g-finance"] } },
        ],
        "exclude": [{ "Bool": { "principal.contractor": true } }],
    });
    let bound = set(&["g-finance"]);
    let warnings = rule_warnings(&rule, Some(&bound)).unwrap();
    assert_eq!(
        warnings,
        [
            "include[0] tests principal.department, which anyone holding iam:identities:update can set, so they choose who receives this package under its owner\u{2019}s authority",
            "include[1] tests identity.managerId, which anyone holding iam:identities:update can set, so they choose who receives this package under its owner\u{2019}s authority",
            "include[2] tests identity.groups for g-lounge, a group without role bindings whose members anyone holding iam:groups:update can change, so they choose who receives this package under its owner\u{2019}s authority",
            "exclude[0] tests principal.contractor, which anyone holding iam:identities:update can set, so they can lift the exclusion",
        ]
    );
    // Groups are not checked without the bound set.
    assert_eq!(rule_warnings(&rule, None).unwrap().len(), 3);
    // Fixed facts draw no warning.
    let fixed = json!({ "include": [{ "StringEquals": { "principal.kind": "user" }, "ArrayContains": { "identity.groups": ["g-finance"] } }] });
    assert!(rule_warnings(&fixed, Some(&bound)).unwrap().is_empty());
}

#[test]
fn warns_about_service_accounts_unverified_email_guests_and_licenses() {
    let rule = json!({
        "include": [
            { "StringEquals": { "identity.emailDomain": "acme.test" } },
            { "StringEquals": { "principal.kind": "user", "identity.email": "a@acme.test" }, "Bool": { "identity.emailVerified": true, "identity.guest": true } },
            { "StringEquals": { "principal.kind": "user" }, "ArrayContains": { "identity.licenses": ["figma"] } },
        ],
    });
    let warnings = rule_warnings(&rule, Some(&IndexSet::new())).unwrap();
    assert_eq!(
        warnings,
        [
            "include[0] does not test identity.guest while the rule does elsewhere, so it also matches guests",
            "include[0] does not test principal.kind, so it also matches service accounts",
            "include[0] tests an email address without requiring Bool identity.emailVerified: true, so unverified addresses match (SCIM-provisioned and administrator-set addresses are unverified)",
            "include[2] does not test identity.guest while the rule does elsewhere, so it also matches guests",
            "include[2] tests identity.licenses, which anyone holding iam:licenses:assign can change, as can whoever manages the members of a group a product is assigned to without it (a team's maintainers, directory sync), so they choose who receives this package under its owner\u{2019}s authority",
        ]
    );
}

#[test]
fn builds_the_context_a_rule_sees_from_the_identity_alone() {
    let alice = identity(json!({
        "attributes": { "department": "finance", "level": 3 },
        "managerId": "i-bob",
    }));
    let context = rule_context(
        &alice,
        &json!(["g-b", "g-a", "g-b"]),
        Some(&RuleOrgFacts {
            teams: vec!["t-2".into(), "t-1".into()],
            departments: vec!["d-1".into()],
            licenses: None,
            extra: Map::new(),
        }),
    )
    .unwrap();
    assert_eq!(
        Value::Object(context),
        json!({
            "principal.department": "finance",
            "principal.level": 3,
            "principal.id": "i-alice",
            "principal.kind": "user",
            "principal.owner": false,
            "identity.email": "alice@acme.test",
            "identity.emailDomain": "acme.test",
            "identity.emailVerified": true,
            "identity.managerId": "i-bob",
            "identity.groups": ["g-a", "g-b"],
            "identity.guest": false,
            "identity.teams": ["t-1", "t-2"],
            "identity.departments": ["d-1"],
            "identity.licenses": [],
        })
    );
    let bare = rule_context(&identity(json!({ "email": null })), &json!([]), None).unwrap();
    assert!(!bare.contains_key("identity.email"));
    assert!(!bare.contains_key("identity.teams"));
}

#[test]
fn names_the_clauses_that_matched_and_keeps_guests_out_unless_the_rule_tests_them() {
    let rule = json!({
        "include": [
            { "StringEquals": { "principal.kind": "user" } },
            { "StringEquals": { "identity.emailDomain": "acme.test" } },
        ],
        "exclude": [{ "ArrayContains": { "identity.groups": "g-contractors" } }],
    });
    let document = rule_document(&rule).unwrap();
    let alice = identity(json!({}));
    let matched = rule_match(
        &document,
        &alice,
        &rule_context(&alice, &json!([]), None).unwrap(),
    )
    .unwrap();
    assert!(matched.matched);
    assert_eq!(matched.matched_by, ["include-0", "include-1"]);
    assert!(matched.excluded_by.is_empty());
    let excluded = rule_match(
        &document,
        &alice,
        &rule_context(&alice, &json!(["g-contractors"]), None).unwrap(),
    )
    .unwrap();
    assert!(!excluded.matched);
    assert_eq!(excluded.excluded_by, ["exclude-0"]);
    assert!(!excluded.matched_by.is_empty());

    let guest = identity(json!({ "guest": { "sponsorId": "i-owner", "since": 0 } }));
    let context = rule_context(&guest, &json!([]), None).unwrap();
    assert_eq!(context["identity.guest"], json!(true));
    let refused = rule_match(&document, &guest, &context).unwrap();
    assert!(!refused.matched && refused.matched_by.is_empty());
    let for_guests =
        rule_document(&json!({ "include": [{ "Bool": { "identity.guest": true } }] })).unwrap();
    assert!(rule_match(&for_guests, &guest, &context).unwrap().matched);
    assert!(
        !rule_match(
            &for_guests,
            &alice,
            &rule_context(&alice, &json!([]), None).unwrap()
        )
        .unwrap()
        .matched
    );
}

#[test]
fn reads_and_maps_the_values_a_rule_tests() {
    let rule = json!({
        "include": [
            { "StringEquals": { "principal.kind": "user" }, "ArrayContains": { "identity.groups": ["g-1", "g-2"], "identity.teams": "t-1" } },
            { "ArrayContainsAll": { "identity.groups": "g-3" } },
        ],
        "exclude": [{ "ArrayContains": { "identity.groups": ["g-1", 4] } }],
        "ownerId": "i-owner",
    });
    assert_eq!(rule_group_ids(Some(&rule)).unwrap(), ["g-1", "g-2", "g-3"]);
    assert_eq!(rule_values(Some(&rule), "identity.teams").unwrap(), ["t-1"]);
    assert!(rule_values(None, "identity.groups").unwrap().is_empty());
    let mapped = map_rule_groups(&rule, &|value| value.to_uppercase()).unwrap();
    assert_eq!(
        rule_group_ids(Some(&mapped)).unwrap(),
        ["G-1", "G-2", "G-3"]
    );
    assert_eq!(
        mapped["exclude"][0]["ArrayContains"]["identity.groups"],
        json!(["G-1", 4])
    );
    assert_eq!(mapped["ownerId"], json!("i-owner"));
    let teams = map_rule_values(&rule, "identity.teams", &|value| format!("slug-{value}")).unwrap();
    assert_eq!(
        teams["include"][0]["ArrayContains"]["identity.teams"],
        json!("slug-t-1")
    );
    // The input is untouched.
    assert_eq!(
        rule["include"][0]["ArrayContains"]["identity.teams"],
        json!("t-1")
    );
}

#[test]
fn separates_the_written_rule_from_its_runtime_state() {
    let stored = json!({
        "include": [people()],
        "exclude": [],
        "graceMs": 0,
        "maxGrants": 10,
        "ownerId": "i-owner",
        "authorityId": "a-1",
        "revision": 3,
        "updatedAt": 5,
    });
    let input: AutoAssignInput = rule_input(&stored).unwrap();
    assert_eq!(
        input.to_value(),
        json!({ "include": [people()], "maxGrants": 10 })
    );
    let reordered = json!({
        "maxGrants": 10,
        "include": [{ "StringEquals": { "principal.kind": "user" } }],
        "revision": 4,
    });
    assert!(same_rule_input(&stored, &reordered).unwrap());
    assert!(!same_rule_input(&stored, &json!({ "include": [people()] })).unwrap());

    let declared = env(attributes(&[("department", AttributeType::String)]));
    let on_attribute = json!({
        "include": [{ "StringEquals": { "principal.kind": "user", "principal.department": "x" } }],
        "ownerId": "i-owner",
    });
    assert_eq!(rule_problem(&on_attribute, &declared).unwrap(), None);
    assert_eq!(
        rule_problem(&on_attribute, &env(IndexMap::new()))
            .unwrap()
            .as_deref(),
        Some(
            "autoAssign.include[0]: unknown key principal.department; use principal.id, principal.kind, principal.owner, identity.email, identity.emailDomain, identity.emailVerified, identity.managerId, identity.groups, identity.guest, or principal.<declared attribute> (none declared)"
        )
    );
}
