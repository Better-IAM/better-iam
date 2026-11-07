//! The policy linter (port of the `policy linter` suite of tests/policy-lint.test.ts; the `analysis.lintPolicy`
//! suite belongs to the analysis API group).

use std::time::Instant;

use better_iam_core::AttributeType;
use better_iam_server::policy_lint::{PolicyLintContext, PolicyLintResult, lint_policy};
use indexmap::IndexMap;
use serde_json::{Value, json};

fn doc(statements: Vec<Value>) -> Value {
    json!({ "version": 1, "statements": statements })
}

fn merge(base: Value, extra: &Value) -> Value {
    let mut base = base;
    for (key, value) in extra.as_object().expect("statement members") {
        base[key] = value.clone();
    }
    base
}

fn allow(extra: Value) -> Value {
    merge(
        json!({ "effect": "allow", "actions": ["documents:read"], "resources": ["documents/*"] }),
        &extra,
    )
}

fn deny(extra: Value) -> Value {
    merge(
        merge(allow(extra.clone()), &json!({ "effect": "deny" })),
        &extra,
    )
}

fn lint(document: &Value, context: Option<&PolicyLintContext>) -> PolicyLintResult {
    lint_policy(Some(document), context).expect("lint")
}

/// `{statement}:{code}` for every warning, in the linter's order.
fn codes(document: &Value, context: Option<&PolicyLintContext>) -> Vec<String> {
    lint(document, context)
        .warnings
        .iter()
        .map(|warning| {
            format!(
                "{}:{}",
                warning["statement"],
                warning["code"].as_str().unwrap()
            )
        })
        .collect()
}

fn only(code: &str, document: &Value, context: Option<&PolicyLintContext>) -> Vec<Value> {
    lint(document, context)
        .warnings
        .into_iter()
        .filter(|warning| warning["code"] == json!(code))
        .collect()
}

fn attributes(pairs: &[(&str, AttributeType)]) -> PolicyLintContext {
    PolicyLintContext {
        identity_attributes: Some(
            pairs
                .iter()
                .map(|(name, kind)| ((*name).to_owned(), *kind))
                .collect::<IndexMap<_, _>>(),
        ),
        ..PolicyLintContext::default()
    }
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn none() -> Vec<String> {
    Vec::new()
}

#[test]
fn accepts_a_sound_document_without_warnings() {
    let result = lint(
        &doc(vec![
            allow(json!({
                "conditions": {
                    "Bool": { "principal.mfa": true },
                    "StringEquals": { "resource.ownerId": "${principal.id}", "principal.kind": "user" },
                    "ArrayContains": { "principal.groups": "writers", "resource.relations": "editor" },
                    "DateBefore": { "request.time": "2030-01-01T00:00:00Z" },
                    "Exists": { "principal.authMethod": true },
                },
            })),
            allow(
                json!({ "actions": ["documents:write"], "resources": ["documents/${principal.id}/*"] }),
            ),
        ]),
        None,
    );
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        json!({ "valid": true, "warnings": [] })
    );
}

#[test]
fn reports_invalid_documents_with_the_validation_error_and_no_warnings() {
    let invalid = lint(&json!({ "version": 2, "statements": [] }), None);
    assert!(!invalid.valid);
    assert!(invalid.warnings.is_empty());
    assert_eq!(
        invalid.error.as_ref().unwrap()["code"],
        json!("INVALID_POLICY")
    );
    assert!(invalid.error.as_ref().unwrap()["message"].is_string());
    let text = lint(&json!("not a policy"), None);
    assert!(!text.valid && text.warnings.is_empty());
    let missing = lint_policy(None, None).unwrap();
    assert!(!missing.valid);
    let broken = lint(
        &doc(vec![allow(json!({ "resources": ["documents/${broken"] }))]),
        None,
    );
    assert!(!broken.valid);
    assert_eq!(broken.error.unwrap()["code"], json!("INVALID_POLICY"));
    let typed = lint(
        &doc(vec![allow(
            json!({ "conditions": { "Bool": { "principal.mfa": "yes" } } }),
        )]),
        None,
    );
    assert!(!typed.valid);
    assert_eq!(typed.error.unwrap()["code"], json!("INVALID_POLICY"));
}

#[test]
fn flags_unrestricted_administration_and_service_wide_wildcards() {
    assert_eq!(
        codes(
            &doc(vec![
                json!({ "effect": "allow", "actions": ["*"], "resources": ["*"] })
            ]),
            None
        ),
        strings(&["0:unrestricted-admin"])
    );
    assert_eq!(
        codes(
            &doc(vec![
                json!({ "effect": "allow", "actions": ["iam:*"], "resources": ["iam/*"] })
            ]),
            None
        ),
        strings(&["0:unrestricted-admin"])
    );
    let both = lint(
        &doc(vec![
            json!({ "effect": "allow", "actions": ["*", "documents:*"], "resources": ["*"] }),
        ]),
        None,
    )
    .warnings;
    assert_eq!(both.len(), 1);
    assert_eq!(both[0]["code"], json!("unrestricted-admin"));
    assert_eq!(both[0]["severity"], json!("warning"));
    // Conditions or scoped resources are not unrestricted.
    assert_eq!(
        codes(
            &doc(vec![json!({
                "effect": "allow",
                "actions": ["*"],
                "resources": ["*"],
                "conditions": { "Bool": { "principal.mfa": true } },
            })]),
            None
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![
                json!({ "effect": "allow", "actions": ["*"], "resources": ["documents/*"] })
            ]),
            None
        ),
        none()
    );

    let wildcard = lint(
        &doc(vec![allow(
            json!({ "actions": ["documents:*", "documents:read"] }),
        )]),
        None,
    );
    assert_eq!(wildcard.warnings.len(), 1);
    assert_eq!(wildcard.warnings[0]["code"], json!("service-wildcard"));
    assert_eq!(wildcard.warnings[0]["severity"], json!("info"));
    assert_eq!(wildcard.warnings[0]["statement"], json!(0));
    assert!(
        wildcard.warnings[0]["message"]
            .as_str()
            .unwrap()
            .contains("documents:*")
    );
    assert_eq!(
        codes(
            &doc(vec![allow(
                json!({ "actions": ["documents:*"], "conditions": { "Bool": { "principal.mfa": true } } })
            )]),
            None
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![allow(json!({ "actions": ["documents:re*"] }))]),
            None
        ),
        none()
    );
}

#[test]
fn flags_condition_keys_and_variables_the_server_never_sets() {
    let ip = only(
        "unknown-context-key",
        &doc(vec![allow(
            json!({ "conditions": { "IpAddress": { "request.ip": "10.0.0.0/8" } } }),
        )]),
        None,
    );
    assert_eq!(ip.len(), 1);
    assert_eq!(ip[0]["severity"], json!("warning"));
    assert_eq!(ip[0]["statement"], json!(0));
    assert!(
        ip[0]["message"]
            .as_str()
            .unwrap()
            .contains("request.ip is never set by the server; supply it with resolveContext")
    );
    // resource.type and resource.id do not exist even when any resource attribute is accepted.
    let kind = only(
        "unknown-context-key",
        &doc(vec![allow(
            json!({ "conditions": { "StringEquals": { "resource.type": "document" } } }),
        )]),
        None,
    );
    assert!(
        kind[0]["message"]
            .as_str()
            .unwrap()
            .contains("resource pattern")
    );
    // A variable naming an unknown key is reported once per statement, like a condition key.
    assert_eq!(
        codes(
            &doc(vec![allow(json!({
                "resources": ["documents/${principal.email}"],
                "conditions": { "StringEquals": { "principal.email": "a@b.test" } },
            }))]),
            None
        ),
        strings(&["0:unknown-context-key"])
    );

    let department = doc(vec![allow(
        json!({ "conditions": { "StringEquals": { "principal.department": "x" } } }),
    )]);
    assert_eq!(
        codes(&department, None),
        strings(&["0:unknown-context-key"])
    );
    assert_eq!(
        codes(
            &department,
            Some(&attributes(&[("department", AttributeType::String)]))
        ),
        none()
    );
    assert_eq!(
        codes(
            &department,
            Some(&PolicyLintContext {
                context_keys: Some(strings(&["principal.department"])),
                ..PolicyLintContext::default()
            })
        ),
        none()
    );

    let resource = doc(vec![allow(json!({
        "conditions": {
            "StringEquals": { "resource.classification": "secret", "resource.ownerId": "x" },
        },
    }))]);
    // Without a resource attribute list any resource attribute is accepted.
    assert_eq!(codes(&resource, None), none());
    assert_eq!(
        codes(
            &resource,
            Some(&PolicyLintContext {
                resource_attributes: Some(strings(&["classification"])),
                ..PolicyLintContext::default()
            })
        ),
        none()
    );
    let unknown = only(
        "unknown-context-key",
        &resource,
        Some(&PolicyLintContext {
            resource_attributes: Some(strings(&["size"])),
            ..PolicyLintContext::default()
        }),
    );
    assert_eq!(unknown.len(), 1);
    assert!(
        unknown[0]["message"]
            .as_str()
            .unwrap()
            .contains("resource.classification")
    );
}

#[test]
fn flags_denies_that_silently_never_apply_when_an_optional_key_is_missing() {
    let context = attributes(&[("department", AttributeType::String)]);
    let risky =
        deny(json!({ "conditions": { "StringNotEquals": { "principal.department": "finance" } } }));
    let document = doc(vec![allow(json!({})), risky.clone()]);
    assert_eq!(
        codes(&document, Some(&context)),
        strings(&["1:optional-key-deny"])
    );
    assert!(
        only("optional-key-deny", &document, Some(&context))[0]["message"]
            .as_str()
            .unwrap()
            .contains("Exists { \"principal.department\": false }")
    );
    // Sign-in method and resource attributes are optional too.
    assert_eq!(
        codes(
            &doc(vec![
                allow(json!({})),
                deny(json!({
                    "conditions": {
                        "StringEquals": { "principal.authMethod": "password", "resource.ownerId": "x" },
                    },
                })),
            ]),
            None
        ),
        strings(&["1:optional-key-deny", "1:optional-key-deny"])
    );
    // An Exists test in the statement, a deny for the missing case, always-present keys, and allows are fine.
    assert_eq!(
        codes(
            &doc(vec![
                allow(json!({})),
                deny(json!({
                    "conditions": {
                        "StringNotEquals": { "principal.department": "finance" },
                        "Exists": { "principal.department": true },
                    },
                })),
            ]),
            Some(&context)
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![
                allow(json!({})),
                risky,
                deny(json!({ "conditions": { "Exists": { "principal.department": false } } })),
            ]),
            Some(&context)
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![
                allow(json!({})),
                deny(json!({ "conditions": { "Bool": { "principal.mfa": false } } })),
            ]),
            None
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![allow(
                json!({ "conditions": { "StringEquals": { "principal.department": "finance" } } })
            )]),
            Some(&context)
        ),
        none()
    );
}

#[test]
fn accepts_a_deny_for_the_missing_key_case_only_when_it_covers_the_risky_deny() {
    let context = attributes(&[("department", AttributeType::String)]);
    let risky = deny(json!({
        "actions": ["documents:delete", "documents:write"],
        "resources": ["documents/a", "documents/b/1"],
        "conditions": { "StringNotEquals": { "principal.department": "finance" } },
    }));
    let absent = |extra: Value| {
        deny(merge(
            json!({ "conditions": { "Exists": { "principal.department": false } } }),
            &extra,
        ))
    };
    // Wildcards covering every action and resource make the risky deny safe.
    assert_eq!(
        codes(
            &doc(vec![
                allow(json!({})),
                risky.clone(),
                absent(json!({ "actions": ["documents:*"], "resources": ["*"] })),
            ]),
            Some(&context)
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![
                absent(json!({
                    "actions": ["documents:delete", "documents:wr*"],
                    "resources": ["documents/a", "documents/b/*"],
                })),
                allow(json!({})),
                risky.clone(),
            ]),
            Some(&context)
        ),
        none()
    );
    // A deny with further conditions only applies to some of the requests missing the key.
    assert_eq!(
        codes(
            &doc(vec![
                allow(json!({})),
                risky.clone(),
                deny(json!({
                    "actions": ["*"],
                    "resources": ["*"],
                    "conditions": {
                        "Exists": { "principal.department": false },
                        "Bool": { "principal.mfa": false },
                    },
                })),
            ]),
            Some(&context)
        ),
        strings(&["1:optional-key-deny"])
    );
    // An unrelated action, a narrower resource, or another key leaves the risky deny open.
    for other in [
        absent(json!({ "actions": ["iam:policies:create"], "resources": ["*"] })),
        absent(json!({ "actions": ["documents:*"], "resources": ["documents/archive"] })),
        absent(json!({ "actions": ["documents:*"], "resources": ["documents/b/*"] })),
        deny(json!({
            "actions": ["*"],
            "resources": ["*"],
            "conditions": { "Exists": { "principal.authMethod": false } },
        })),
    ] {
        assert_eq!(
            codes(
                &doc(vec![allow(json!({})), risky.clone(), other]),
                Some(&context)
            ),
            strings(&["1:optional-key-deny"])
        );
    }
    // Covering the actions and the resources through two different denies is not enough either.
    assert_eq!(
        codes(
            &doc(vec![
                allow(json!({})),
                risky,
                absent(json!({ "actions": ["documents:*"], "resources": ["documents/a"] })),
                absent(json!({ "actions": ["documents:delete"], "resources": ["*"] })),
            ]),
            Some(&context)
        ),
        strings(&["1:optional-key-deny"])
    );
}

#[test]
fn flags_negated_operators_comparing_with_a_variable_that_can_be_missing() {
    let context = attributes(&[("department", AttributeType::String)]);
    let risky = allow(json!({
        "conditions": { "StringNotEquals": { "resource.department": "${principal.department}" } },
    }));
    assert_eq!(
        codes(&doc(vec![risky]), Some(&context)),
        strings(&["0:negated-variable"])
    );
    assert_eq!(
        codes(
            &doc(vec![allow(
                json!({ "conditions": { "StringNotLike": { "resource.ownerId": "x-${resource.team}" } } })
            )]),
            None
        ),
        strings(&["0:negated-variable"])
    );
    // Always-present keys, an Exists guard, and positive operators are fine.
    assert_eq!(
        codes(
            &doc(vec![allow(
                json!({ "conditions": { "StringNotEquals": { "resource.ownerId": "${principal.id}" } } })
            )]),
            None
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![allow(json!({
                "conditions": {
                    "StringNotEquals": { "resource.department": "${principal.department}" },
                    "Exists": { "principal.department": true },
                },
            }))]),
            Some(&context)
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![allow(json!({
                "conditions": { "StringEquals": { "resource.department": "${principal.department}" } },
            }))]),
            Some(&context)
        ),
        none()
    );
}

#[test]
fn flags_case_insensitive_patterns_whose_variable_names_contain_capitals() {
    let context = attributes(&[
        ("costCenter", AttributeType::String),
        ("team", AttributeType::String),
    ]);
    let risky = only(
        "ignorecase-variable",
        &doc(vec![allow(json!({
            "conditions": { "StringLikeIgnoreCase": { "resource.name": "${principal.costCenter}-*" } },
        }))]),
        Some(&context),
    );
    assert_eq!(risky.len(), 1);
    assert_eq!(risky[0]["severity"], json!("warning"));
    assert!(
        risky[0]["message"]
            .as_str()
            .unwrap()
            .contains("${principal.costcenter}")
    );
    assert_eq!(
        codes(
            &doc(vec![allow(json!({
                "conditions": { "StringLike": { "resource.name": "${principal.costCenter}-*" } },
            }))]),
            Some(&context)
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![allow(json!({
                "conditions": { "StringLikeIgnoreCase": { "resource.name": "${principal.team}-*" } },
            }))]),
            Some(&context)
        ),
        none()
    );
}

#[test]
fn flags_list_keys_compared_with_scalar_operators_or_used_as_variables() {
    assert_eq!(
        codes(
            &doc(vec![allow(
                json!({ "conditions": { "StringEquals": { "principal.groups": "admins" } } })
            )]),
            None
        ),
        strings(&["0:array-key-string-operator"])
    );
    // A list key with Bool is a list problem, not a type mismatch.
    assert_eq!(
        codes(
            &doc(vec![allow(
                json!({ "conditions": { "Bool": { "resource.relations": true } } })
            )]),
            None
        ),
        strings(&["0:array-key-string-operator"])
    );
    assert_eq!(
        codes(
            &doc(vec![allow(json!({
                "conditions": {
                    "ArrayContains": { "principal.groups": "admins" },
                    "ArrayContainsAll": { "principal.roles": ["a", "b"] },
                    "Exists": { "resource.parentRelations": true },
                },
            }))]),
            None
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![allow(
                json!({ "resources": ["documents/${principal.groups}"] })
            )]),
            None
        ),
        strings(&["0:array-variable"])
    );
    assert_eq!(
        codes(
            &doc(vec![allow(
                json!({ "conditions": { "StringEquals": { "resource.ownerId": "${principal.roles}" } } })
            )]),
            None
        ),
        strings(&["0:array-variable"])
    );
}

#[test]
fn flags_operators_that_can_never_match_the_type_of_a_known_key() {
    let mismatches = |conditions: Value, context: Option<&PolicyLintContext>| -> Vec<String> {
        only(
            "type-mismatch",
            &doc(vec![allow(json!({ "conditions": conditions }))]),
            context,
        )
        .iter()
        .map(|warning| warning["message"].as_str().unwrap().to_owned())
        .collect()
    };
    assert_eq!(
        mismatches(json!({ "Bool": { "principal.id": true } }), None),
        strings(&["Bool never matches principal.id, which holds a string."])
    );
    assert_eq!(
        mismatches(json!({ "StringEquals": { "principal.mfa": "true" } }), None),
        strings(&["StringEquals never matches principal.mfa, which is a boolean; use Bool."])
    );
    assert_eq!(
        mismatches(json!({ "NumericEquals": { "principal.kind": 1 } }), None).len(),
        1
    );
    assert_eq!(
        mismatches(
            json!({ "DateAfter": { "principal.id": "2024-01-01T00:00:00Z" } }),
            None
        )
        .len(),
        1
    );
    assert_eq!(
        mismatches(
            json!({ "ArrayContains": { "principal.kind": "user" } }),
            None
        )
        .len(),
        1
    );
    assert_eq!(
        mismatches(
            json!({ "DateAfter": { "request.time": "2024-01-01T00:00:00Z" } }),
            None
        ),
        none()
    );
    // Unknown keys have no known type.
    assert_eq!(
        mismatches(
            json!({ "DateAfter": { "session.expires": "2024-01-01T00:00:00Z" } }),
            Some(&PolicyLintContext {
                context_keys: Some(strings(&["session.expires"])),
                ..PolicyLintContext::default()
            })
        ),
        none()
    );
    // Identity attributes follow their declared types.
    let declared = attributes(&[
        ("level", AttributeType::Number),
        ("contractor", AttributeType::Boolean),
        ("hiredAt", AttributeType::String),
    ]);
    assert_eq!(
        mismatches(
            json!({
                "NumericGreaterThan": { "principal.level": 2 },
                "Bool": { "principal.contractor": false },
                "DateBefore": { "principal.hiredAt": "2024-01-01T00:00:00Z" },
            }),
            Some(&declared)
        ),
        none()
    );
    assert_eq!(
        mismatches(
            json!({ "StringEquals": { "principal.level": "2" }, "NumericEquals": { "principal.contractor": 1 } }),
            Some(&declared)
        ),
        strings(&[
            "NumericEquals never matches principal.contractor, which is a boolean; use Bool.",
            "StringEquals never matches principal.level, which is a number; use a Numeric operator.",
        ])
    );
}

#[test]
fn notes_conditions_that_always_hold_and_duplicated_statements() {
    let always = lint(
        &doc(vec![allow(json!({
            "conditions": {
                "Bool": { "principal.mfa": [true, false] },
                "Exists": { "resource.ownerId": [false, true] },
            },
        }))]),
        None,
    )
    .warnings;
    assert_eq!(always.len(), 2);
    for warning in &always {
        assert_eq!(warning["code"], json!("always-true-condition"));
        assert_eq!(warning["severity"], json!("info"));
    }
    assert_eq!(
        codes(
            &doc(vec![allow(
                json!({ "conditions": { "Bool": { "principal.mfa": true } } })
            )]),
            None
        ),
        none()
    );

    let first = allow(json!({
        "sid": "Read",
        "actions": ["documents:read", "documents:write"],
        "conditions": { "StringEquals": { "principal.kind": ["user", "service"] } },
    }));
    let same = allow(json!({
        "sid": "ReadAgain",
        "actions": ["documents:write", "documents:read"],
        "conditions": { "StringEquals": { "principal.kind": ["service", "user"] } },
    }));
    let duplicate = lint(&doc(vec![first.clone(), same]), None).warnings;
    assert_eq!(duplicate.len(), 1);
    assert_eq!(duplicate[0]["code"], json!("duplicate-statement"));
    assert_eq!(duplicate[0]["statement"], json!(1));
    assert_eq!(duplicate[0]["sid"], json!("ReadAgain"));
    assert!(
        duplicate[0]["message"]
            .as_str()
            .unwrap()
            .contains("statement 0 (Read)")
    );
    assert_eq!(
        codes(
            &doc(vec![
                first,
                allow(json!({
                    "actions": ["documents:read", "documents:write"],
                    "conditions": { "StringEquals": { "principal.kind": "user" } },
                })),
            ]),
            None
        ),
        none()
    );
}

#[test]
fn flags_allows_that_an_unconditional_deny_always_overrides() {
    assert_eq!(
        codes(
            &doc(vec![
                allow(json!({ "resources": ["documents/1", "documents/team-*"] })),
                deny(json!({ "actions": ["documents:*"], "resources": ["documents/*"] })),
            ]),
            None
        ),
        strings(&["0:shadowed-allow"])
    );
    // Earlier denies count too, and several denies may cover one allow together.
    let split = lint(
        &doc(vec![
            deny(json!({ "actions": ["documents:read"], "resources": ["*"] })),
            deny(json!({ "actions": ["documents:write"], "resources": ["*"] })),
            allow(json!({ "actions": ["documents:read", "documents:write"] })),
        ]),
        None,
    )
    .warnings;
    assert_eq!(split.len(), 1);
    assert_eq!(split[0]["code"], json!("shadowed-allow"));
    assert_eq!(split[0]["statement"], json!(2));
    assert!(
        split[0]["message"]
            .as_str()
            .unwrap()
            .contains("statement 0, 1")
    );
    // Conditional denies, partial coverage, and wider allow patterns are not shadowed.
    assert_eq!(
        codes(
            &doc(vec![
                allow(json!({})),
                deny(
                    json!({ "resources": ["*"], "conditions": { "Bool": { "principal.mfa": false } } })
                ),
            ]),
            None
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![
                allow(json!({ "resources": ["documents/1", "reports/1"] })),
                deny(json!({ "resources": ["documents/*"] })),
            ]),
            None
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![
                allow(json!({ "resources": ["doc*"] })),
                deny(json!({ "resources": ["documents/*"] })),
            ]),
            None
        ),
        none()
    );
}

fn repeat(value: &str, count: usize) -> Value {
    Value::Array(vec![Value::String(value.into()); count])
}

#[test]
fn bounds_the_shadow_check_on_documents_built_to_make_it_slow() {
    // Repeated patterns: each distinct value is resolved once.
    let mut statements = Vec::new();
    for _ in 0..29 {
        statements.push(allow(
            json!({ "actions": repeat("x", 128), "resources": repeat("x", 128) }),
        ));
    }
    for _ in 0..58 {
        statements.push(deny(
            json!({ "actions": repeat("y", 128), "resources": ["*"] }),
        ));
    }
    statements.push(deny(json!({ "actions": ["*"], "resources": ["*"] })));
    let started = Instant::now();
    let repeated = lint(&doc(statements), None);
    assert!(started.elapsed().as_millis() < 5000);
    let shadowed: Vec<&Value> = repeated
        .warnings
        .iter()
        .filter(|warning| warning["code"] == json!("shadowed-allow"))
        .collect();
    assert_eq!(shadowed.len(), 29);
    assert!(
        shadowed[0]["message"]
            .as_str()
            .unwrap()
            .contains("(statement 87)")
    );

    // Distinct literal values against distinct wildcards exhaust the budget: the rest of the check is skipped.
    let mut statements = Vec::new();
    for i in 0..64 {
        statements.push(allow(json!({
            "actions": (0..128).map(|j| format!("a{i}-{j}")).collect::<Vec<_>>(),
        })));
    }
    for i in 0..64 {
        statements.push(deny(json!({
            "actions": (0..128).map(|j| format!("?{i}.{j}*z")).collect::<Vec<_>>(),
            "resources": ["*"],
        })));
    }
    let started = Instant::now();
    let distinct = lint(&doc(statements), None);
    assert!(started.elapsed().as_millis() < 5000);
    assert_eq!(distinct.warnings.len(), 1);
    assert_eq!(
        distinct.warnings[0]["code"],
        json!("shadowed-allow-skipped")
    );
    assert_eq!(distinct.warnings[0]["severity"], json!("info"));
    assert_eq!(distinct.warnings[0]["statement"], json!(-1));

    // Many patterns that do not interact are still checked in full.
    let mut statements = Vec::new();
    for i in 0..100 {
        statements.push(allow(json!({
            "actions": (0..10).map(|j| format!("service{i}:action{j}")).collect::<Vec<_>>(),
            "resources": [format!("service{i}/*")],
        })));
    }
    for i in 0..20 {
        statements.push(deny(json!({
            "actions": [format!("*:dangerous{i}"), format!("service{i}:*")],
            "resources": [format!("service{i}/*")],
        })));
    }
    assert_eq!(
        codes(&doc(statements), None),
        (0..20)
            .map(|i| format!("{i}:shadowed-allow"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn notes_documents_that_grant_nothing_and_orders_warnings_by_statement_and_code() {
    assert_eq!(
        codes(&doc(vec![deny(json!({}))]), None),
        strings(&["-1:deny-only"])
    );
    let empty = lint(&doc(vec![]), None).warnings;
    assert_eq!(empty.len(), 1);
    assert_eq!(empty[0]["code"], json!("deny-only"));
    assert_eq!(empty[0]["severity"], json!("info"));
    assert_eq!(empty[0]["statement"], json!(-1));
    assert_eq!(
        codes(&doc(vec![allow(json!({})), deny(json!({}))]), None),
        strings(&["0:shadowed-allow"])
    );

    let ordered = lint(
        &doc(vec![
            allow(
                json!({ "sid": "First", "conditions": { "StringEquals": { "principal.groups": "x" } } }),
            ),
            json!({ "effect": "allow", "actions": ["*"], "resources": ["*"] }),
            allow(json!({
                "conditions": {
                    "IpAddress": { "request.ip": "10.0.0.0/8" },
                    "Bool": { "principal.id": true },
                },
            })),
        ]),
        None,
    )
    .warnings;
    assert_eq!(
        ordered
            .iter()
            .map(|warning| format!(
                "{}:{}",
                warning["statement"],
                warning["code"].as_str().unwrap()
            ))
            .collect::<Vec<_>>(),
        strings(&[
            "0:array-key-string-operator",
            "1:unrestricted-admin",
            "2:type-mismatch",
            "2:unknown-context-key",
        ])
    );
    assert_eq!(ordered[0]["sid"], json!("First"));
    assert!(ordered[1].get("sid").is_none());
}

#[test]
fn clearance_keys_belong_to_the_server_only_with_clearances() {
    let document = doc(vec![allow(
        json!({ "conditions": { "NumericGreaterThan": { "principal.clearanceRank": 1 } } }),
    )]);
    // Without clearances the key is an ordinary application key.
    assert_eq!(codes(&document, None), strings(&["0:unknown-context-key"]));
    let cleared = PolicyLintContext {
        clearances: Some(true),
        ..PolicyLintContext::default()
    };
    assert_eq!(codes(&document, Some(&cleared)), none());
    // Session tags: a valid tag name is an optional server string; the bare family name never resolves.
    assert_eq!(
        codes(
            &doc(vec![allow(
                json!({ "conditions": { "StringEquals": { "principal.sessionTags.team": "x" } } })
            )]),
            None
        ),
        none()
    );
    assert_eq!(
        codes(
            &doc(vec![allow(
                json!({ "conditions": { "StringEquals": { "principal.sessionTags": "x" } } })
            )]),
            None
        ),
        strings(&["0:unknown-context-key"])
    );
}
