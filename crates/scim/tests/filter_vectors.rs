//! `spec/vectors/scim-filter.json` (produced by the TypeScript implementation): filter parsing and evaluation,
//! attribute paths, sorting, projection and attribute lists.

use std::path::PathBuf;

use better_iam_core::IamError;
use better_iam_scim::filter::{
    attribute_list, attribute_path, evaluate_filter, parse_filter_expression, project_resource,
    sort_resources,
};
use serde_json::{Value, json};

fn vectors() -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/scim-filter.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("vector JSON")
}

/// `{"$undefined": true}` is absent.
fn defined(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| value.get("$undefined") != Some(&Value::Bool(true)))
}

fn error_json(error: &IamError) -> Value {
    json!({ "$error": { "name": "IamError", "code": error.code, "status": error.status, "message": error.message } })
}

fn outcome(result: Result<Value, IamError>) -> Value {
    match result {
        Ok(value) => value,
        Err(error) => error_json(&error),
    }
}

fn strings(value: Option<&Value>) -> Option<Vec<String>> {
    defined(value).and_then(Value::as_array).map(|items| {
        items
            .iter()
            .map(|item| item.as_str().unwrap_or_default().to_owned())
            .collect()
    })
}

#[test]
fn reproduces_every_scim_filter_vector() {
    let file = vectors();
    let users: Vec<Value> = file["notes"]["resources"]
        .as_array()
        .expect("resources")
        .clone();
    let cases = file["cases"].as_array().expect("cases");
    let mut checked = 0;
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let input = &case["input"];
        let expected = &case["output"];
        let kind = name.split(' ').next().unwrap_or_default();
        let actual = match kind {
            "parse" => outcome(
                parse_filter_expression(input["filter"].as_str().unwrap())
                    .map(|node| node.to_json()),
            ),
            "matches" => outcome(
                parse_filter_expression(input["filter"].as_str().unwrap()).map(|node| {
                    Value::Array(
                        users
                            .iter()
                            .filter(|user| evaluate_filter(&node, user, &[]))
                            .map(|user| user["id"].clone())
                            .collect(),
                    )
                }),
            ),
            "attributePath" => {
                outcome(attribute_path(input["raw"].as_str().unwrap()).map(|path| json!(path)))
            }
            "sort" => outcome(
                sort_resources(
                    users.clone(),
                    defined(input.get("sortBy")).and_then(Value::as_str),
                    defined(input.get("sortOrder")).and_then(Value::as_str),
                )
                .map(|sorted| Value::Array(sorted.iter().map(|user| user["id"].clone()).collect())),
            ),
            "project" => {
                let attributes = strings(input.get("attributes"));
                let excluded = strings(input.get("excluded"));
                outcome(
                    project_resource(
                        input["resource"].as_object().unwrap(),
                        attributes.as_deref(),
                        excluded.as_deref(),
                    )
                    .map(Value::Object),
                )
            }
            "attributeList" => match attribute_list(defined(input.get("value"))) {
                Ok(Some(list)) => json!(list),
                Ok(None) => json!({ "$undefined": true }),
                Err(error) => error_json(&error),
            },
            other => panic!("unknown vector kind {other}"),
        };
        assert_eq!(&actual, expected, "{name}");
        // Member order matters for projections (they are serialized as they are).
        if kind == "project" {
            assert_eq!(
                serde_json::to_string(&actual).unwrap(),
                serde_json::to_string(expected).unwrap(),
                "{name} (member order)"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, cases.len());
    assert!(checked > 140);
}
