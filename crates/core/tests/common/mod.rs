//! Shared helpers for the core integration tests: loading `spec/vectors/*.json` and decoding their tagged values.
#![allow(dead_code)]

pub mod memory;

use std::path::PathBuf;

use better_iam_core::{Filter, IamError, js};
use serde_json::{Map, Value};

/// The repository's `spec/` directory.
pub fn spec_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec")
}

/// One vector case.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub input: Value,
    pub output: Value,
}

/// The cases of `spec/vectors/<name>.json`.
pub fn load(name: &str) -> (Value, Vec<Case>) {
    let path = spec_dir().join("vectors").join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let file: Value = serde_json::from_str(&text).expect("vector file is JSON");
    let cases = file["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| Case {
            name: case["name"].as_str().unwrap_or_default().to_owned(),
            input: case["input"].clone(),
            output: case["output"].clone(),
        })
        .collect();
    (file, cases)
}

/// True when a value carries a tag that has no `serde_json::Value` form (`$utf16`, non-finite `$number`,
/// `$bigint`, `$bytes`) anywhere inside it.
pub fn unrepresentable(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            if map.len() == 1 {
                if map.contains_key("$utf16")
                    || map.contains_key("$bigint")
                    || map.contains_key("$bytes")
                {
                    return true;
                }
                if let Some(Value::String(number)) = map.get("$number") {
                    return number != "-0";
                }
            }
            map.values().any(unrepresentable)
        }
        Value::Array(items) => items.iter().any(unrepresentable),
        _ => false,
    }
}

fn tag<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) if map.len() == 1 => map.get(name),
        _ => None,
    }
}

/// True for `{"$undefined": true}`.
pub fn is_undefined(value: &Value) -> bool {
    tag(value, "$undefined").is_some()
}

/// Decodes a tagged value into plain JSON: `$undefined` members are dropped (array entries become `null`, as
/// `JSON.stringify` writes them), `$number: "-0"` becomes negative zero, `$set` becomes an array.
pub fn plain(value: &Value) -> Value {
    if let Some(Value::String(number)) = tag(value, "$number")
        && number == "-0"
    {
        return js::number(-0.0).unwrap_or(Value::Null);
    }
    if let Some(items) = tag(value, "$set") {
        return plain(items);
    }
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(_, item)| !is_undefined(item))
                .map(|(key, item)| (key.clone(), plain(item)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| {
                    if is_undefined(item) {
                        Value::Null
                    } else {
                        plain(item)
                    }
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// A filter from a tagged object: `$undefined` members become absent conditions.
pub fn filter(value: &Value) -> Filter {
    let mut filter = Filter::new();
    if let Value::Object(map) = value {
        for (key, item) in map {
            if is_undefined(item) {
                filter.set(key.clone(), None);
            } else {
                filter.set(key.clone(), Some(plain(item)));
            }
        }
    }
    filter
}

/// The `undefined` marker, for functions whose TypeScript result is `undefined`.
pub fn undefined() -> Value {
    serde_json::json!({ "$undefined": true })
}

/// The `$error` member of an expected output.
pub fn expected_error(output: &Value) -> Option<&Map<String, Value>> {
    tag(output, "$error").and_then(Value::as_object)
}

/// An error as the vectors encode it.
pub fn iam_error(error: &IamError) -> Value {
    serde_json::json!({ "name": "IamError", "code": error.code, "status": error.status, "message": error.message })
}

/// Compares an actual error (name, code/status/reason, message) with the expected `$error`.
pub fn error_matches(expected: &Map<String, Value>, actual: &Value) -> bool {
    expected
        .iter()
        .all(|(key, value)| actual.get(key) == Some(value))
}

/// Collects mismatches and skipped cases of one vector file.
#[derive(Default)]
pub struct Report {
    pub file: String,
    pub passed: usize,
    pub skipped: Vec<String>,
    pub failures: Vec<String>,
}

impl Report {
    pub fn new(file: &str) -> Self {
        Self {
            file: file.to_owned(),
            ..Self::default()
        }
    }

    pub fn skip(&mut self, case: &Case, why: &str) {
        self.skipped.push(format!("{} ({why})", case.name));
    }

    /// Records a value result: equal by deep JSON equality (numbers as doubles, member order ignored).
    pub fn value(&mut self, case: &Case, actual: Result<Value, Value>) {
        let ok = match (&actual, expected_error(&case.output)) {
            (Err(error), Some(expected)) => error_matches(expected, error),
            (Ok(value), None) if is_undefined(&case.output) => is_undefined(value),
            (Ok(value), None) => js::deep_equal(value, &plain(&case.output)),
            _ => false,
        };
        if ok {
            self.passed += 1;
        } else {
            let shown = match &actual {
                Ok(value) => js::stringify(value),
                Err(error) => format!("error {}", js::stringify(error)),
            };
            self.failures.push(format!(
                "{}\n    expected {}\n    received {shown}",
                case.name,
                js::stringify(&case.output)
            ));
        }
    }

    /// Finishes: panics with every failure, prints the counts.
    pub fn finish(self) {
        println!(
            "{}: {} passed, {} skipped, {} failed",
            self.file,
            self.passed,
            self.skipped.len(),
            self.failures.len()
        );
        for skipped in &self.skipped {
            println!("  skipped: {skipped}");
        }
        assert!(
            self.failures.is_empty(),
            "{} vector failures in {}:\n{}",
            self.failures.len(),
            self.file,
            self.failures.join("\n")
        );
    }
}
