//! Every core-owned vector of `spec/vectors/*.json`, reproduced from its input and compared with the TypeScript
//! output. Cases whose inputs have no Rust form (unpaired surrogates, non-finite numbers, bigints, `undefined` at the
//! top level) are reported as skipped.

mod common;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use better_iam_core::*;
use common::{
    Case, Report, filter, iam_error, is_undefined, load, memory::MemoryStore, plain, undefined,
    unrepresentable,
};
use serde_json::{Map, Value, json};

fn to_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("serializable")
}

fn type_error(error: &js::TypeError) -> Value {
    json!({ "name": "TypeError", "message": error.0 })
}

fn object(value: &Value) -> Map<String, Value> {
    match plain(value) {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn skip_unrepresentable(report: &mut Report, case: &Case) -> bool {
    if unrepresentable(&case.input) {
        report.skip(case, "input has no serde_json form");
        return true;
    }
    false
}

#[test]
fn jcs_vectors() {
    for (file, canonical) in [("jcs", true), ("canonical-json", false)] {
        let (_, cases) = load(file);
        let mut report = Report::new(file);
        for case in &cases {
            let value = &case.input["value"];
            if unrepresentable(value) || is_undefined(value) {
                report.skip(case, "value has no serde_json form");
                continue;
            }
            let value = plain(value);
            let text = if canonical {
                canonicalize_json(&value)
            } else {
                canonical_json(&value)
            };
            report.value(case, Ok(Value::String(text)));
        }
        report.finish();
    }
}

#[tokio::test]
async fn audit_chain_vectors() {
    let (_, cases) = load("audit-chain");
    let mut report = Report::new("audit-chain");
    let store = MemoryStore::open();
    for case in &cases {
        if case.name.starts_with("hash") {
            let event = object(&case.input["event"]);
            report.value(case, Ok(Value::String(audit_event_hash(&event))));
        } else if case.name.starts_with("append") {
            let event = object(&case.input["event"]);
            let tenant = event["tenantId"].as_str().unwrap_or_default().to_owned();
            let appended = store
                .transaction(move |tx| async move { append_audit_event(tx.as_ref(), &event).await })
                .await
                .expect("append");
            let head = store.get("auditChains", &tenant).await.expect("head");
            report.value(case, Ok(json!({ "event": appended, "head": head })));
        } else {
            let events: Vec<Record> = case.input["events"]
                .as_array()
                .map(|items| items.iter().map(object).collect())
                .unwrap_or_default();
            let options: VerifyAuditChainOptions =
                serde_json::from_value(plain(case.input.get("options").unwrap_or(&json!({}))))
                    .expect("options");
            report.value(case, Ok(to_json(&verify_audit_chain(&events, &options))));
        }
    }
    report.finish();
}

#[test]
fn policy_evaluation_vectors() {
    for file in ["policy-evaluation", "policy-conditions"] {
        let (_, cases) = load(file);
        let mut report = Report::new(file);
        for case in &cases {
            if skip_unrepresentable(&mut report, case) {
                continue;
            }
            let result = evaluate_policy_json(&plain(&case.input))
                .map(|decision| to_json(&decision))
                .map_err(|error| iam_error(&error));
            report.value(case, result);
        }
        report.finish();
    }
}

#[test]
fn policy_validation_vectors() {
    let (_, cases) = load("policy-validation");
    let mut report = Report::new("policy-validation");
    for case in &cases {
        if skip_unrepresentable(&mut report, case) {
            continue;
        }
        let result = validate_policy(&plain(&case.input["document"]))
            .map(|()| Value::Null)
            .map_err(|error| iam_error(&error));
        report.value(case, result);
    }
    report.finish();
}

#[test]
fn policy_pattern_vectors() {
    let (_, cases) = load("policy-patterns");
    let mut report = Report::new("policy-patterns");
    for case in &cases {
        if skip_unrepresentable(&mut report, case) {
            continue;
        }
        let input = &case.input;
        let text = |key: &str| input[key].as_str().unwrap_or_default().to_owned();
        let context = input.get("context").map(object);
        let result = if case.name.starts_with("matchPattern") {
            json!(match_pattern(
                &text("pattern"),
                &text("value"),
                context.as_ref()
            ))
        } else if case.name.starts_with("resolvePolicyValue") {
            resolve_policy_value(&text("value"), context.as_ref())
                .map(Value::String)
                .unwrap_or_else(undefined)
        } else if case.name.starts_with("validPolicyVariables") {
            json!(valid_policy_variables(&text("value")))
        } else if case.name.starts_with("isIpRange") {
            json!(is_ip_range(&text("value")))
        } else if case.name.starts_with("ipMatches") {
            json!(ip_matches(&text("address"), &text("network")))
        } else if case.name.starts_with("ipCounterKey") {
            ip_counter_key(&text("value"))
                .map(Value::String)
                .unwrap_or_else(undefined)
        } else {
            report.skip(case, "unknown case");
            continue;
        };
        report.value(case, Ok(result));
    }
    report.finish();
}

fn filters(value: &Value) -> Vec<ResourceFilter> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| ResourceFilter::from_value(&plain(item)).expect("filter"))
                .collect()
        })
        .unwrap_or_default()
}

fn plan_input(value: &Value) -> IamResult<PlanInput> {
    // planResources validates denies, boundaries, then each path's grants and boundaries, before anything else.
    let empty = Vec::new();
    let list = |key: &str| value.get(key).and_then(Value::as_array).unwrap_or(&empty);
    for document in list("denies").iter().chain(list("boundaries")) {
        validate_policy(document)?;
    }
    for path in list("paths") {
        for key in ["grants", "boundaries"] {
            for document in path.get(key).and_then(Value::as_array).unwrap_or(&empty) {
                validate_policy(document)?;
            }
        }
    }
    Ok(serde_json::from_value(value.clone()).expect("plan input"))
}

#[test]
fn plan_vectors() {
    let (_, cases) = load("plan");
    let mut report = Report::new("plan");
    for case in &cases {
        if skip_unrepresentable(&mut report, case) {
            continue;
        }
        let input = plain(&case.input);
        let name = case.name.as_str();
        let result = if name.starts_with("andFilter") {
            Ok(and_filter(filters(&input["filters"])).to_value())
        } else if name.starts_with("orFilter") {
            Ok(or_filter(filters(&input["filters"])).to_value())
        } else if name.starts_with("notFilter") {
            Ok(
                not_filter(ResourceFilter::from_value(&input["filter"]).expect("filter"))
                    .to_value(),
            )
        } else if name.starts_with("parseGlob") {
            Ok(Value::Array(
                parse_glob(input["pattern"].as_str().unwrap_or_default())
                    .iter()
                    .map(GlobToken::to_value)
                    .collect(),
            ))
        } else if name.starts_with("globMatches") {
            let tokens = parse_glob(input["pattern"].as_str().unwrap_or_default());
            Ok(json!(glob_matches(
                &tokens,
                input["value"].as_str().unwrap_or_default()
            )))
        } else if name.starts_with("fixedPlan") {
            Ok(to_json(&fixed_plan(
                input["allowed"].as_bool().unwrap_or(false),
            )))
        } else if name.starts_with("intersectPlans") {
            let left: ResourcePlan = serde_json::from_value(input["left"].clone()).expect("plan");
            let right: ResourcePlan = serde_json::from_value(input["right"].clone()).expect("plan");
            Ok(to_json(&intersect_plans(&left, &right)))
        } else {
            plan_input(&input)
                .and_then(|input| plan_resources(&input))
                .map(|plan| to_json(&plan))
                .map_err(|error| iam_error(&error))
        };
        report.value(case, result);
    }
    report.finish();
}

/// The TypeScript compiler puts `RegExp` objects in MongoDB queries, which JSON writes as `{}`.
fn regexes_as_empty(value: Value) -> Value {
    match value {
        Value::Object(map) if map.len() == 1 && map.contains_key("$regularExpression") => json!({}),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, item)| (key, regexes_as_empty(item)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(regexes_as_empty).collect()),
        other => other,
    }
}

#[test]
fn filter_compiler_vectors() {
    let (_, cases) = load("filter-compilers");
    let mut report = Report::new("filter-compilers");
    let column = |field: &str| {
        if field.starts_with("missing") {
            None
        } else {
            Some(format!("\"{field}\""))
        }
    };
    let prisma_names = |field: &str| {
        if field == "id" {
            "uid".to_owned()
        } else {
            format!("attr_{field}")
        }
    };
    let mongo_names = |field: &str| {
        if field == "id" {
            "_id".to_owned()
        } else {
            field.to_owned()
        }
    };
    for case in &cases {
        if skip_unrepresentable(&mut report, case) {
            continue;
        }
        let input = plain(&case.input);
        let filter = ResourceFilter::from_value(&input["filter"]).expect("filter");
        let name = case.name.as_str();
        let result = if name.starts_with("sqlite ") || name.starts_with("postgres ") {
            let dialect = if input["dialect"] == "postgres" {
                FilterDialect::Postgres
            } else {
                FilterDialect::Sqlite
            };
            let offset = input.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
            filter_to_sql(
                &filter,
                &SqlFilterOptions {
                    dialect,
                    column: &column,
                    offset,
                },
            )
            .map(|sql| json!({ "sql": sql.sql, "params": sql.params }))
            .map_err(|error| iam_error(&error))
        } else if name.starts_with("prisma") {
            let mapping: FieldMapping<'_> = if name == "prisma with field mapping" {
                Some(&prisma_names)
            } else {
                None
            };
            filter_to_prisma(&filter, mapping).map_err(|error| iam_error(&error))
        } else if name.starts_with("mongo") {
            let mapping: FieldMapping<'_> = if name == "mongo with field mapping" {
                Some(&mongo_names)
            } else {
                None
            };
            filter_to_mongo(&filter, mapping)
                .map(regexes_as_empty)
                .map_err(|error| iam_error(&error))
        } else if name.starts_with("describe") {
            Ok(Value::String(describe_filter(&filter)))
        } else if name.starts_with("matches") {
            Ok(json!(filter_matches(
                &filter,
                &object(&case.input["record"])
            )))
        } else {
            report.skip(case, "unknown case");
            continue;
        };
        report.value(case, result);
    }
    report.finish();
}

fn capabilities(value: Option<&Value>) -> QueryCapabilities {
    value
        .map(|value| serde_json::from_value(value.clone()).expect("capabilities"))
        .unwrap_or_default()
}

fn plan_value(plan: &FindPlan) -> Value {
    json!({ "query": plan.query.to_value(), "exact": plan.exact, "empty": plan.empty })
}

#[test]
fn storage_vectors() {
    let (_, cases) = load("storage");
    let mut report = Report::new("storage");
    for case in &cases {
        let input = &case.input;
        let name = case.name.as_str();
        let text = |key: &str| input[key].as_str().unwrap_or_default().to_owned();
        if !name.contains("JsonbDocument") && skip_unrepresentable(&mut report, case) {
            continue;
        }
        let result = if name.starts_with("planQuery") {
            let plan = plan_query(
                &text("collection"),
                &filter(&input["filter"]),
                capabilities(input.get("capabilities")),
            );
            plan_value(&plan)
        } else if name.starts_with("matchesFilter") {
            json!(matches_filter(
                &object(&input["record"]),
                &filter(&input["filter"])
            ))
        } else if name.starts_with("compareIds") {
            json!(compare_ids(&text("a"), &text("b")) as i8)
        } else if name.starts_with("storableString") {
            json!(storable_string(&text("value")))
        } else if name.starts_with("encodeJsonbDocument") {
            Value::String(encode_jsonb_document(&text("data")).expect("encode"))
        } else if name.starts_with("decodeJsonbDocument") {
            Value::String(decode_jsonb_document(&text("data")).expect("decode"))
        } else {
            report.skip(case, "unknown case");
            continue;
        };
        report.value(case, Ok(result));
    }
    report.finish();
}

fn statement_value(statement: &SqlStatement) -> Value {
    json!({ "text": statement.text, "values": statement.values.iter().map(SqlValue::to_json).collect::<Vec<_>>() })
}

#[test]
fn sql_vectors() {
    let (_, cases) = load("sql");
    let mut report = Report::new("sql");
    for case in &cases {
        if skip_unrepresentable(&mut report, case) {
            continue;
        }
        let input = &case.input;
        if let Some(query) = input.get("query") {
            let query = RecordQuery::from_value(query).expect("query");
            report.value(
                case,
                sqlite_select(&query)
                    .map(|statement| statement_value(&statement))
                    .map_err(|error| iam_error(&error)),
            );
            continue;
        }
        let postgres = case.name.starts_with("postgres");
        let defaults = if postgres {
            QueryCapabilities {
                json: true,
                order: true,
            }
        } else {
            QueryCapabilities {
                json: false,
                order: true,
            }
        };
        let caps = input
            .get("capabilities")
            .map(|value| capabilities(Some(value)))
            .unwrap_or(defaults);
        let plan = plan_query(
            input["collection"].as_str().unwrap_or_default(),
            &filter(&input["filter"]),
            caps,
        );
        let mut query = plan.query.to_value();
        for key in ["after", "order", "page"] {
            if let Some(value) = input.get(key) {
                query[key] = value.clone();
            }
        }
        let query_struct = RecordQuery::from_value(&query).expect("query");
        let statement = if postgres {
            postgres_select(&query_struct)
        } else {
            sqlite_select(&query_struct)
        };
        let result = statement
            .map(|statement| json!({ "query": query, "exact": plan.exact, "statement": statement_value(&statement) }))
            .map_err(|error| iam_error(&error));
        report.value(case, result);
    }
    report.finish();
}

const NOW: f64 = 1_767_225_600_000.0;

async fn seeded(records: &Value) -> Arc<dyn IamStore> {
    let store = MemoryStore::open();
    let records = records.clone();
    store
        .transaction(move |tx| async move {
            for (collection, list) in records.as_object().into_iter().flatten() {
                for record in list.as_array().into_iter().flatten() {
                    tx.insert(collection, &object(record)).await?;
                }
            }
            Ok(())
        })
        .await
        .expect("seed");
    store
}

#[tokio::test]
async fn snapshot_vectors() {
    let (_, cases) = load("snapshot");
    let mut report = Report::new("snapshot");
    for case in &cases {
        let input = &case.input;
        if case.name.starts_with("export") {
            let store = seeded(&input["records"]).await;
            let options = input.get("options").cloned().unwrap_or(json!({}));
            let options = SnapshotOptions {
                collections: options
                    .get("collections")
                    .and_then(Value::as_array)
                    .map(|names| {
                        names
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    }),
                page_size: options.get("pageSize").and_then(Value::as_i64),
                now: Some(NOW),
            };
            let lines = Arc::new(Mutex::new(Vec::<String>::new()));
            let sink = lines.clone();
            let result = export_store(
                store.as_ref(),
                move |line| {
                    sink.lock().expect("lines").push(line);
                    Ok(())
                },
                &options,
            )
            .await;
            let lines = lines.lock().expect("lines").clone();
            report.value(
                case,
                result
                    .map(|summary| json!({ "lines": lines, "summary": summary.to_value() }))
                    .map_err(|error| iam_error(&error)),
            );
        } else {
            let store = MemoryStore::open();
            if let Some(existing) = input.get("existing") {
                let existing = object(existing);
                store
                    .transaction(move |tx| async move { tx.insert("tenants", &existing).await })
                    .await
                    .expect("existing");
            }
            let lines: Vec<String> = input["lines"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            let result = match import_store(store.as_ref(), lines).await {
                Ok(summary) => {
                    let mut stored = Map::new();
                    for collection in store.collections().await.expect("collections") {
                        let ids: Vec<Value> = store
                            .find(&collection, &Filter::new(), &FindOptions::default())
                            .await
                            .expect("find")
                            .iter()
                            .map(|record| Value::String(record_id(record).to_owned()))
                            .collect();
                        stored.insert(collection, Value::Array(ids));
                    }
                    Ok(json!({ "summary": summary.to_value(), "stored": stored }))
                }
                Err(error) => Err(iam_error(&error)),
            };
            report.value(case, result);
        }
    }
    report.finish();
}

#[test]
fn shared_signal_vectors() {
    let (_, cases) = load("shared-signals");
    let mut report = Report::new("shared-signals");
    for case in &cases {
        if skip_unrepresentable(&mut report, case) {
            continue;
        }
        let input = &case.input;
        let name = case.name.as_str();
        let optional = |subject: Option<SubjectIdentifier>| {
            subject
                .map(|subject| subject.to_value())
                .unwrap_or_else(undefined)
        };
        let result = if name.starts_with("signalEventType") {
            Ok(Value::String(
                signal_event_type(input["uri"].as_str().unwrap_or_default()).to_owned(),
            ))
        } else if name.starts_with("parseSubjectIdentifier") {
            Ok(optional(parse_subject_identifier(&plain(&input["value"]))))
        } else if name.starts_with("legacyRiscSubject") {
            let value = plain(&input["value"]);
            Ok(optional(legacy_risc_subject(
                if is_undefined(&input["value"]) {
                    None
                } else {
                    Some(&value)
                },
            )))
        } else if name.starts_with("readSecurityEvent") {
            read_security_event(&plain(&input["payload"]))
                .map(|claims| claims.to_value())
                .map_err(|error| json!({ "name": "SignalFormatError", "reason": error.reason.as_str(), "message": error.message }))
        } else if name.starts_with("userSubjects") {
            let subject = if is_undefined(&input["subject"]) {
                None
            } else {
                parse_subject_identifier(&plain(&input["subject"]))
            };
            Ok(Value::Array(
                user_subjects(subject.as_ref())
                    .iter()
                    .map(SubjectIdentifier::to_value)
                    .collect(),
            ))
        } else {
            report.skip(case, "unknown case");
            continue;
        };
        report.value(case, result);
    }
    report.finish();
}

fn party(value: &Value) -> ClearanceParty {
    let set = |key: &str| -> BTreeSet<String> {
        plain(&value[key])
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    ClearanceParty {
        identity_id: value["identityId"].as_str().unwrap_or_default().to_owned(),
        rank: value["rank"].as_f64().unwrap_or(f64::NAN),
        compartments: set("compartments"),
        citizenship: set("citizenship"),
    }
}

#[test]
fn classification_vectors() {
    let (_, cases) = load("classification");
    let mut report = Report::new("classification");
    for case in &cases {
        if skip_unrepresentable(&mut report, case) {
            continue;
        }
        let input = &case.input;
        let name = case.name.as_str();
        let scheme = || validate_scheme(&plain(&input["scheme"])).expect("scheme");
        let optional = |value: &Value| {
            if is_undefined(value) {
                None
            } else {
                Some(plain(value))
            }
        };
        let result = if name.starts_with("template") {
            Ok(to_json(
                &classification_template(input["name"].as_str().unwrap_or_default())
                    .expect("template"),
            ))
        } else if name.starts_with("validateScheme") {
            validate_scheme(&plain(&input["scheme"]))
                .map(|scheme| to_json(&scheme))
                .map_err(|error| iam_error(&error))
        } else if name.starts_with("validateLabel") {
            validate_label(&plain(&input["label"]), &scheme())
                .map(|label| label.to_value())
                .map_err(|error| iam_error(&error))
        } else if name.starts_with("isValidClassificationLabel") {
            Ok(json!(is_valid_classification_label(
                &plain(&input["label"]),
                &scheme()
            )))
        } else if name.starts_with("labelRank") {
            Ok(label_rank(&plain(&input["label"]), &scheme())
                .and_then(js::number)
                .unwrap_or_else(undefined))
        } else if name.starts_with("joinLabels") {
            let (a, b) = (optional(&input["a"]), optional(&input["b"]));
            Ok(join_labels(a.as_ref(), b.as_ref(), &scheme()).unwrap_or_else(undefined))
        } else if name.starts_with("dominates") {
            let failure = dominates(&party(&input["party"]), &plain(&input["label"]), &scheme());
            Ok(failure
                .map(|failure| Value::String(failure.as_str().into()))
                .unwrap_or(Value::Null))
        } else if name.starts_with("labelCovers") {
            Ok(json!(label_covers(
                &plain(&input["upper"]),
                &plain(&input["lower"]),
                &scheme()
            )))
        } else {
            report.skip(case, "unknown case");
            continue;
        };
        report.value(case, result);
    }
    report.finish();
}

#[test]
fn delegation_token_vectors() {
    let (_, cases) = load("delegation-tokens");
    let mut report = Report::new("delegation-tokens");
    for case in &cases {
        let input = &case.input;
        let name = case.name.as_str();
        let result = if name.starts_with("read ") {
            let expected = &input["expected"];
            let issuer = match &expected["issuer"] {
                Value::String(issuer) => vec![issuer.clone()],
                Value::Array(items) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
                _ => Vec::new(),
            };
            let expectations = DelegationTokenExpectations {
                issuer,
                audience: expected["audience"].as_str().unwrap_or_default().to_owned(),
                tenant_id: expected
                    .get("tenantId")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                now: expected["now"].as_f64().unwrap_or(f64::NAN),
                clock_tolerance_seconds: expected
                    .get("clockToleranceSeconds")
                    .and_then(Value::as_f64),
            };
            read_delegation_token_claims(&plain(&input["claims"]), &expectations)
                .map(|read| read.to_value())
                .map_err(|error| type_error(&error))
        } else if name.starts_with("delegationActor") {
            let chain: Vec<String> = input["chain"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            delegation_actor(&chain)
                .map(|actor| to_json(&actor))
                .map_err(|error| type_error(&error))
        } else {
            report.skip(
                case,
                "signing and verification belong to the a2a and server crates",
            );
            continue;
        };
        report.value(case, result);
    }
    report.finish();
}

#[test]
fn migrations_match_the_spec() {
    let dir = common::spec_dir().join("storage/migrations");
    for (dialect, folder) in [
        (SqlDialect::Sqlite, "sqlite"),
        (SqlDialect::Sqlite, "libsql"),
        (SqlDialect::Postgres, "postgres"),
    ] {
        for migration in schema_migrations(dialect) {
            let path = dir.join(folder).join(format!("{}.sql", migration.name));
            let text = std::fs::read_to_string(&path).expect("spec migration");
            assert_eq!(
                Some(text.as_str()),
                migration_file(dialect, &migration.name),
                "{} differs from the spec",
                path.display()
            );
        }
    }
}

/// Records statements; answers `SELECT name FROM iam_migrations` with the names it is given.
struct Recorder {
    applied: Vec<String>,
    log: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl SqlExecutor for Recorder {
    async fn execute(&self, text: &str, values: &[SqlValue]) -> Result<Vec<SqlRow>, DriverError> {
        self.log.lock().expect("log").push(json!({ "sql": text, "params": values.iter().map(SqlValue::to_json).collect::<Vec<_>>() }));
        if text == "SELECT name FROM iam_migrations" {
            return Ok(self
                .applied
                .iter()
                .map(|name| better_iam_core::record(json!({ "name": name })))
                .collect());
        }
        if text.starts_with("SELECT version") && !self.applied.is_empty() {
            return Ok(vec![better_iam_core::record(json!({ "version": 1 }))]);
        }
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn migration_runner_matches_the_spec() {
    let dir = common::spec_dir().join("storage/migrations");
    for (dialect, folder) in [
        (SqlDialect::Sqlite, "sqlite"),
        (SqlDialect::Sqlite, "libsql"),
        (SqlDialect::Postgres, "postgres"),
    ] {
        let runner: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join(folder).join("runner.json")).expect("runner"),
        )
        .expect("json");
        let names: Vec<String> = schema_migrations(dialect)
            .into_iter()
            .map(|migration| migration.name)
            .collect();
        for (state, applied) in [("fresh", Vec::new()), ("current", names.clone())] {
            let recorder = Recorder {
                applied,
                log: Mutex::new(Vec::new()),
            };
            let hook = EncodeLegacyPostgresRows;
            let options = MigrationOptions {
                now: Some(runner["appliedAtClock"].as_f64().expect("clock")),
                before: if dialect == SqlDialect::Postgres {
                    Some(&hook)
                } else {
                    None
                },
            };
            apply_migrations(&recorder, dialect, options)
                .await
                .expect("migrate");
            let expected: Vec<Value> = runner[state]
                .as_array()
                .expect("events")
                .iter()
                .filter(|event| event.get("sql").is_some())
                .filter(|event| {
                    event["kind"] != "adapter" || event["sql"] == LEGACY_POSTGRES_ROWS_SQL
                })
                .map(|event| json!({ "sql": event["sql"], "params": event["params"] }))
                .collect();
            let recorded = recorder.log.lock().expect("log").clone();
            assert_eq!(recorded, expected, "{folder} {state} migration statements");
        }
    }
}
