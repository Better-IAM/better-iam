//! Round trip of recorded API traffic through the generated types: every `api` step of the conformance traces
//! (spec/conformance/traces, recorded from the TypeScript test suite) is decoded into the route's `Input` and
//! `Output` types and encoded again, and the JSON must be the same as recorded, byte for byte once object members
//! are sorted (numbers are compared in their JavaScript form).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use better_iam_core::js;
use better_iam_types::routes::{self, Operation, RouteVisitor};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

fn spec_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec")
}

fn traces(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            traces(&path, out);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "jsonl")
        {
            out.push(path);
        }
    }
}

/// The value with every object's members sorted by name.
fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, item)| (key.clone(), sorted(item)))
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    /// The same JSON text, member order included.
    Exact,
    /// The same JSON once members are sorted.
    Reordered,
    Failed(String),
}

fn round_trip<T: Serialize + DeserializeOwned>(recorded: &Value) -> Outcome {
    let typed: T = match serde_json::from_value(recorded.clone()) {
        Ok(typed) => typed,
        Err(error) => return Outcome::Failed(format!("does not decode: {error}")),
    };
    let encoded = match serde_json::to_value(&typed) {
        Ok(encoded) => encoded,
        Err(error) => return Outcome::Failed(format!("does not encode: {error}")),
    };
    if js::stringify(&encoded) == js::stringify(recorded) {
        return Outcome::Exact;
    }
    let (left, right) = (
        js::stringify(&sorted(recorded)),
        js::stringify(&sorted(&encoded)),
    );
    if left == right {
        Outcome::Reordered
    } else {
        Outcome::Failed(format!(
            "differs\n      recorded {left}\n      rust     {right}"
        ))
    }
}

struct Check<'a> {
    input: &'a Value,
    output: Option<&'a Value>,
}

impl RouteVisitor for Check<'_> {
    type Output = (Outcome, Option<Outcome>);
    fn visit<O: Operation>(self) -> Self::Output {
        (
            round_trip::<O::Input>(self.input),
            self.output.map(round_trip::<O::Output>),
        )
    }
}

/// Output schemas of spec/api/openapi.json that disagree with what the TypeScript server answers. They are defects of
/// the OpenAPI generator (scripts/spec), not of this crate's runtime: members typed `T | undefined` are marked
/// required although `JSON.stringify` drops them, and some result types omit members the server returns while
/// declaring `additionalProperties: false`. Each entry is (route, failure text it explains); anything else fails the
/// test. Remove entries as the generator is fixed (the test reports entries that no longer match anything).
const KNOWN_SCHEMA_GAPS: &[(&str, &str)] = &[
    ("roleMining/usage", "missing field `trackingSince`"),
    ("audit/export", "missing field `nextSequence`"),
    ("audit/export", "missing field `firstSequence`"),
    ("credentials/rotate", "missing field `name`"),
    ("identities/export", "missing field `audit`"),
    ("packages/listMine", "missing field `assignment`"),
    ("packages/listMine", "missing field `pending`"),
    // The result type lacks `authorityId`.
    ("policies/restoreVersion", "differs"),
    // IssuedCredential lacks `mfa`, `selfService` and `typeId`.
    ("verifiableCredentials/request", "differs"),
    ("verifiableCredentials/mine", "differs"),
    ("verifiableCredentials/listIssued", "differs"),
    ("verifiableCredentials/suspend", "differs"),
    ("verifiableCredentials/reinstate", "differs"),
    ("verifiableCredentials/revoke", "differs"),
];

fn known_gap(route: &str, why: &str) -> Option<usize> {
    KNOWN_SCHEMA_GAPS
        .iter()
        .position(|(known, text)| *known == route && why.contains(text))
}

#[derive(Default)]
struct Tally {
    exact: usize,
    reordered: usize,
    failed: usize,
}

impl Tally {
    fn add(&mut self, outcome: &Outcome) {
        match outcome {
            Outcome::Exact => self.exact += 1,
            Outcome::Reordered => self.reordered += 1,
            Outcome::Failed(_) => self.failed += 1,
        }
    }
}

#[test]
fn recorded_api_traffic_round_trips() {
    let mut files = Vec::new();
    traces(&spec_dir().join("conformance").join("traces"), &mut files);
    if files.is_empty() {
        eprintln!("skipped: no traces under spec/conformance/traces");
        return;
    }
    let (mut inputs, mut outputs) = (Tally::default(), Tally::default());
    let mut routes_seen = BTreeMap::<String, usize>::new();
    let mut failures = Vec::new();
    let mut gaps_seen = BTreeMap::<usize, usize>::new();
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            // `js::parse`: traces may hold unpaired UTF-16 surrogates (`JSON.stringify` escapes), which serde refuses.
            let step: Value = js::parse(line).unwrap();
            if step["type"] != "step" || step["kind"] != "api" {
                continue;
            }
            let route = step["route"].as_str().unwrap();
            let output = step.get("output");
            let input = step
                .get("input")
                .cloned()
                .unwrap_or(Value::Object(Map::new()));
            // Steps that failed may carry invalid input on purpose; only accepted calls are checked.
            if output.is_none() {
                continue;
            }
            let Some((input_outcome, output_outcome)) = routes::visit(
                route,
                Check {
                    input: &input,
                    output,
                },
            ) else {
                failures.push(format!("{}: unknown route {route}", file.display()));
                continue;
            };
            *routes_seen.entry(route.to_owned()).or_default() += 1;
            inputs.add(&input_outcome);
            let where_ = format!(
                "{} seq {}",
                file.strip_prefix(spec_dir()).unwrap_or(file).display(),
                step["seq"]
            );
            if let Outcome::Failed(why) = input_outcome {
                failures.push(format!("{route} input ({where_}): {why}"));
            }
            if let Some(outcome) = output_outcome {
                outputs.add(&outcome);
                if let Outcome::Failed(why) = outcome {
                    match known_gap(route, &why) {
                        Some(index) => *gaps_seen.entry(index).or_default() += 1,
                        None => failures.push(format!("{route} output ({where_}): {why}")),
                    }
                }
            }
        }
    }
    eprintln!(
        "{} trace files, {} routes; inputs: {} exact, {} reordered, {} failed; outputs: {} exact, {} reordered, {} failed",
        files.len(),
        routes_seen.len(),
        inputs.exact,
        inputs.reordered,
        inputs.failed,
        outputs.exact,
        outputs.reordered,
        outputs.failed,
    );
    assert!(inputs.exact + outputs.exact > 0, "no api step was checked");
    for (index, (route, text)) in KNOWN_SCHEMA_GAPS.iter().enumerate() {
        match gaps_seen.get(&index) {
            Some(count) => eprintln!("  known schema gap: {route} ({text}): {count} values"),
            None => eprintln!("  known schema gap no longer seen (remove it): {route} ({text})"),
        }
    }
    if !failures.is_empty() {
        for failure in failures.iter().take(60) {
            eprintln!("  {failure}");
        }
        panic!("{} recorded values do not round-trip", failures.len());
    }
}

#[test]
fn route_table_matches_routes_json() {
    let text = fs::read_to_string(spec_dir().join("api").join("routes.json")).unwrap();
    let spec: Value = serde_json::from_str(&text).unwrap();
    let mut expected: Vec<String> = ["authorize", "authorizeMany", "listAccessible"]
        .map(String::from)
        .to_vec();
    for route in spec["rpc"].as_array().unwrap() {
        expected.push(route["path"].as_str().unwrap().to_owned());
        let path = route["path"].as_str().unwrap();
        let row = routes::lookup(path).unwrap_or_else(|| panic!("{path} is missing from ROUTES"));
        assert_eq!(row.group, route["group"]);
        assert_eq!(row.method, route["method"]);
        assert_eq!(row.public, route["credential"] == "none", "{path}");
        assert_eq!(row.tenant_bound, route["tenantBound"] == true, "{path}");
        assert_eq!(
            row.sets_session_cookie,
            route["setsSessionCookie"] == true,
            "{path}"
        );
        assert_eq!(
            row.reads_device_cookie,
            route["readsDeviceCookie"] == true,
            "{path}"
        );
    }
    let actual: Vec<String> = routes::ROUTES
        .iter()
        .map(|route| route.path.to_owned())
        .collect();
    assert_eq!(actual, expected);
    struct Path;
    impl RouteVisitor for Path {
        type Output = &'static str;
        fn visit<O: Operation>(self) -> &'static str {
            O::ROUTE.path
        }
    }
    for route in routes::ROUTES {
        assert_eq!(routes::visit(route.path, Path), Some(route.path));
        assert!(std::ptr::eq(routes::lookup(route.path).unwrap(), route));
    }
    assert_eq!(routes::visit("roles/nope", Path), None);
    assert!(routes::lookup("plugins/x/y").is_none());
}
