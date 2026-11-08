//! The vault module (vault.ts): validation, settings, generated values, sealing, versions and stages, the access log,
//! the resource resolver and error redaction. Ported from the cases of tests/vault.test.ts, tests/vault-security.test.ts
//! and tests/vault-review.test.ts that these helpers decide (names, values and settings; json fields; stage moves;
//! disabled and destroyed versions; re-sealing under a new deployment secret; redacted rotator errors; the
//! `constructor` stage). The API-level cases run through api/vault.rs, which another unit ports; customer-managed key
//! paths go through kms.rs, also another unit's.

mod common;

use std::future::Future;
use std::sync::Arc;

use better_iam_core::{Filter, FindOptions, IamError, IamResult, IamStoreExt, Record, ResourceRef};
use better_iam_server::context::ServerContext;
use better_iam_server::options::{BetterIamOptions, VaultEngine, VaultOptions, VaultRotator};
use better_iam_server::vault::{
    self, AccessEntry, VaultSecret, VaultSettings, VaultVersion, vault_settings,
};
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

const SECRET: &str = "organization-fixture-secret-with-32-characters";
const NOW: f64 = 1_800_000_000_000.0;
const DAY: f64 = 86_400_000.0;

fn run<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join()
        .expect("test body");
}

struct NoopRotator;

#[async_trait::async_trait]
impl VaultRotator for NoopRotator {
    async fn rotate(&self, _input: Value) -> IamResult<()> {
        Ok(())
    }
}

struct NoopEngine;

#[async_trait::async_trait]
impl VaultEngine for NoopEngine {
    async fn issue(&self, _input: Value) -> IamResult<Value> {
        Ok(json!({ "value": "minted" }))
    }
}

fn options(configure: impl FnOnce(&mut BetterIamOptions)) -> BetterIamOptions {
    let mut options =
        BetterIamOptions::new(common::memory_store(), SECRET, "http://localhost:3000");
    configure(&mut options);
    options
}

async fn context(configure: impl FnOnce(&mut BetterIamOptions)) -> Arc<ServerContext> {
    let ctx = common::context(options(configure), NOW);
    ctx.store.migrate().await.expect("migrate");
    ctx
}

fn with_rotator(options: &mut BetterIamOptions) {
    let mut rotators: IndexMap<String, Arc<dyn VaultRotator>> = IndexMap::new();
    rotators.insert("db".into(), Arc::new(NoopRotator));
    let mut engines: IndexMap<String, Arc<dyn VaultEngine>> = IndexMap::new();
    engines.insert("pg".into(), Arc::new(NoopEngine));
    options.vault = Some(VaultOptions {
        rotators: Some(rotators),
        engines: Some(engines),
        ..VaultOptions::default()
    });
}

fn code<T: std::fmt::Debug>(result: IamResult<T>) -> String {
    result.expect_err("an error").code
}

fn message<T: std::fmt::Debug>(result: IamResult<T>) -> String {
    result.expect_err("an error").message
}

fn s(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn settings(ctx: &ServerContext) -> VaultSettings {
    vault_settings(ctx).expect("valid vault option")
}

/// A stored static secret with no versions yet, as `vault.create` writes it.
async fn secret(ctx: &Arc<ServerContext>, name: &str, format: &str) -> VaultSecret {
    let record = json!({
        "id": better_iam_server::utils::id(),
        "tenantId": "tenant-1",
        "uniqueKey": name,
        "name": name,
        "kind": "static",
        "format": format,
        "tags": { "environment": "prod" },
        "status": "active",
        "stages": {},
        "latestVersion": 0,
        "maxVersions": 3,
        "createdAt": NOW,
        "createdBy": "owner",
        "updatedAt": NOW,
        "updatedBy": "owner",
    });
    let Value::Object(record) = record else {
        unreachable!()
    };
    ctx.store
        .transaction(move |tx| async move { tx.insert("vaultSecrets", &record).await })
        .await
        .expect("insert secret");
    vault::find_secret(&ctx.store, "tenant-1", name)
        .await
        .expect("find")
        .expect("stored secret")
}

/// `put` as the API does it: a new version made current (or only staged).
async fn put(
    ctx: &Arc<ServerContext>,
    secret: &VaultSecret,
    value: &str,
    stage: Option<&str>,
) -> (VaultSecret, VaultVersion) {
    let ctx = ctx.clone();
    let secret = secret.clone();
    let value = value.to_owned();
    let stage = stage.map(str::to_owned);
    ctx.store
        .clone()
        .transaction(move |tx| async move {
            let added =
                vault::add_version(&ctx, &tx, &secret, &value, "put", "owner", None).await?;
            let stored = match stage {
                None => {
                    vault::promote_version(
                        &ctx,
                        &tx,
                        &added.secret,
                        added.version.version,
                        "owner",
                        None,
                    )
                    .await?
                }
                Some(stage) => {
                    let mut next = added.secret.clone();
                    next.stages.insert(stage, added.version.version);
                    better_iam_server::port::decode(
                        tx.put("vaultSecrets", &better_iam_server::port::encode(&next))
                            .await?,
                    )?
                }
            };
            Ok((stored, added.version))
        })
        .await
        .expect("put")
}

async fn reveal(ctx: &Arc<ServerContext>, secret: &VaultSecret, input: Value) -> IamResult<String> {
    let version = vault::select_version(&ctx.store, secret, &input).await?;
    vault::open_version(ctx, &ctx.store, &version, None).await
}

async fn records(ctx: &Arc<ServerContext>, collection: &str) -> Vec<Record> {
    ctx.store
        .find(collection, &Filter::new(), &FindOptions::default())
        .await
        .expect("find")
}

#[test]
fn validates_names_prefixes_tags_stages_and_formats() {
    // tests/vault.test.ts "validates names, values and settings".
    for name in ["../etc", "a//b", ".hidden", "a/-b", &"x".repeat(65)] {
        assert_eq!(code(vault::secret_name(Some(&s(name)))), "INVALID_INPUT");
    }
    assert_eq!(
        message(vault::secret_name(Some(&s("a/../b")))),
        "Secret names are 1-16 segments of letters, digits and _.- (not starting with . or -) separated by /"
    );
    let deep = vec!["a"; 17].join("/");
    assert_eq!(code(vault::secret_name(Some(&s(&deep)))), "INVALID_INPUT");
    assert_eq!(
        vault::secret_name(Some(&s("prod/db/password"))).unwrap(),
        "prod/db/password"
    );
    assert_eq!(message(vault::secret_name(None)), "Invalid name");

    assert_eq!(vault::secret_prefix(None).unwrap(), "");
    assert_eq!(vault::secret_prefix(Some(&s(""))).unwrap(), "");
    assert_eq!(vault::secret_prefix(Some(&s("prod/"))).unwrap(), "prod/");
    assert_eq!(
        code(vault::secret_prefix(Some(&s("prod//")))),
        "INVALID_INPUT"
    );
    assert_eq!(
        message(vault::secret_prefix(Some(&json!(5)))),
        "Invalid prefix"
    );

    let tags =
        vault::secret_tags(Some(&json!({ "team": "payments", "environment": "prod" }))).unwrap();
    assert_eq!(
        tags.keys().collect::<Vec<_>>(),
        ["environment", "team"],
        "tags are kept sorted by key"
    );
    assert!(vault::secret_tags(None).unwrap().is_empty());
    assert_eq!(
        message(vault::secret_tags(Some(&json!({ "1bad": "x" })))),
        "Invalid tag name 1bad"
    );
    assert_eq!(
        message(vault::secret_tags(Some(&json!({ "team": "" })))),
        "Invalid tag team"
    );
    let many: Map<String, Value> = (0..21).map(|index| (format!("t{index}"), s("v"))).collect();
    assert_eq!(
        message(vault::secret_tags(Some(&Value::Object(many)))),
        "A secret has at most 20 tags"
    );
    assert_eq!(
        message(vault::secret_tags(Some(&json!([])))),
        "Expected an object"
    );

    assert_eq!(vault::stage_name(Some(&s("canary"))).unwrap(), "canary");
    assert_eq!(
        message(vault::stage_name(Some(&s("Canary")))),
        "Stage labels are 1-32 lowercase letters, digits or hyphens, starting with a letter"
    );
    assert_eq!(vault::secret_format(None).unwrap(), "text");
    assert_eq!(vault::secret_format(Some(&s("json"))).unwrap(), "json");
    assert_eq!(
        message(vault::secret_format(Some(&s("yaml")))),
        "format must be text or json"
    );
    assert_eq!(vault::secret_resource("a/b").unwrap(), "vault/secrets/a/b");
    assert_eq!(vault::lease_handle_context("l1").unwrap(), "vault-lease:l1");
}

#[test]
fn validates_values_and_json_fields() {
    run(|| async {
        let ctx = context(|_| {}).await;
        let settings = settings(&ctx);
        assert_eq!(
            vault::secret_value(&settings, "text", &json!({ "value": "abc" })).unwrap(),
            "abc"
        );
        assert_eq!(
            message(vault::secret_value(
                &settings,
                "text",
                &json!({ "value": "" })
            )),
            "value must be a nonempty string"
        );
        assert_eq!(
            message(vault::secret_value(
                &settings,
                "text",
                &json!({ "fields": {} })
            )),
            "fields are for json secrets; pass value instead"
        );
        // A json value is an object: `[1,2]` is refused.
        assert_eq!(
            message(vault::secret_value(
                &settings,
                "json",
                &json!({ "value": "[1,2]" })
            )),
            "json secrets hold a JSON object"
        );
        assert_eq!(
            vault::secret_value(
                &settings,
                "json",
                &json!({ "fields": { "username": "app", "port": 5432 } })
            )
            .unwrap(),
            r#"{"username":"app","port":5432}"#
        );
        assert_eq!(
            message(vault::secret_value(
                &settings,
                "json",
                &json!({ "fields": null })
            )),
            "Expected an object"
        );
        let big = "x".repeat(65537);
        assert_eq!(
            message(vault::secret_value(
                &settings,
                "text",
                &json!({ "value": big })
            )),
            "Secret values are at most 65536 bytes"
        );

        let fields = vault::parse_fields(r#"{"password":"p","n":1}"#).unwrap();
        assert_eq!(
            vault::own_field(Some(&fields), "password").unwrap(),
            Some(s("p"))
        );
        // Own properties only: `constructor` names no field (tests/vault-security.test.ts).
        assert_eq!(
            vault::own_field(Some(&fields), "constructor").unwrap(),
            None
        );
        assert_eq!(vault::own_field(None, "password").unwrap(), None);
        assert_eq!(code(vault::parse_fields("nope")), "INVALID_INPUT");

        for field in ["__proto__", "constructor", "prototype", "a b"] {
            assert_eq!(
                message(vault::field_name(Some(&s(field)), "rotation.field")),
                "rotation.field must be a field name of letters, digits and _.-"
            );
        }
        assert_eq!(
            vault::field_name(Some(&s("password")), "rotation.field").unwrap(),
            "password"
        );
    });
}

#[test]
fn validates_the_vault_option() {
    run(|| async {
        let ctx = context(with_rotator).await;
        let settings = settings(&ctx);
        assert_eq!(settings.rotators.keys().collect::<Vec<_>>(), ["db"]);
        assert_eq!(settings.engines.keys().collect::<Vec<_>>(), ["pg"]);
        assert_eq!(settings.max_value_bytes, 65536.0);
        assert_eq!(settings.max_secrets_per_tenant, 1000.0);
        assert_eq!(settings.access_retention_ms, 90.0 * DAY);
        assert_eq!(settings.call_timeout_ms, 30_000.0);

        // tests/vault.test.ts: a rotator named outside the identifier rules is refused.
        let bad = context(|options| {
            let mut rotators: IndexMap<String, Arc<dyn VaultRotator>> = IndexMap::new();
            rotators.insert("Bad".into(), Arc::new(NoopRotator));
            options.vault = Some(VaultOptions {
                rotators: Some(rotators),
                ..VaultOptions::default()
            });
        })
        .await;
        let error = vault_settings(&bad).err().expect("refused");
        assert_eq!(error.code, "INVALID_CONFIG");
        assert_eq!(
            error.message,
            "vault.rotators keys must be lowercase identifiers"
        );

        let limits = context(|options| {
            options.vault = Some(VaultOptions {
                call_timeout_ms: Some(10.0),
                ..VaultOptions::default()
            });
        })
        .await;
        assert_eq!(
            vault_settings(&limits).err().expect("refused").message,
            "vault.callTimeoutMs must be an integer from 1000 to 300000"
        );
        let retention = context(|options| {
            options.vault = Some(VaultOptions {
                access_retention_days: Some(7.0),
                max_value_bytes: Some(16.0),
                ..VaultOptions::default()
            });
        })
        .await;
        let retention = settings_of(&retention);
        assert_eq!(retention.access_retention_ms, 7.0 * DAY);
        assert_eq!(retention.max_value_bytes, 16.0);
    });
}

fn settings_of(ctx: &ServerContext) -> VaultSettings {
    vault_settings(ctx).expect("valid")
}

#[test]
fn generates_values_from_the_generator() {
    let default = vault::password_generator(None).unwrap();
    assert_eq!(default, *vault::DEFAULT_GENERATOR);
    assert_eq!(
        vault::password_generator(Some(&json!(true))).unwrap(),
        default
    );
    let value = vault::generate_value(&default).unwrap();
    assert_eq!(value.len(), 32);
    assert!(value.chars().any(|c| c.is_ascii_lowercase()));
    assert!(value.chars().any(|c| c.is_ascii_uppercase()));
    assert!(value.chars().any(|c| c.is_ascii_digit()));
    assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));

    // tests/vault.test.ts: `generate({ generator: { length: 12, charset: 'numeric', eachClass: false } })`.
    let numeric = vault::password_generator(Some(
        &json!({ "length": 12, "charset": "numeric", "eachClass": false }),
    ))
    .unwrap();
    let digits = vault::generate_value(&numeric).unwrap();
    assert_eq!(digits.len(), 12);
    assert!(digits.chars().all(|c| c.is_ascii_digit()));

    let ascii = vault::password_generator(Some(
        &json!({ "length": 64, "charset": "ascii", "exclude": "!#$%&" }),
    ))
    .unwrap();
    assert_eq!(ascii.exclude.as_deref(), Some("!#$%&"));
    let symbols = vault::generate_value(&ascii).unwrap();
    assert!(!symbols.contains(['!', '#', '$', '%', '&']));
    assert!(symbols.chars().any(|c| !c.is_ascii_alphanumeric()));

    assert_eq!(
        message(vault::password_generator(Some(
            &json!({ "charset": "emoji" })
        ))),
        "generator.charset must be alphanumeric, ascii, hex, base64url or numeric"
    );
    assert_eq!(
        message(vault::password_generator(Some(
            &json!({ "eachClass": "yes" })
        ))),
        "generator.eachClass must be a boolean"
    );
    assert_eq!(
        message(vault::password_generator(Some(&json!({ "length": 7 })))),
        "Invalid generator.length"
    );
    assert_eq!(
        message(vault::password_generator(Some(
            &json!({ "charset": "numeric", "exclude": "0" })
        ))),
        "The generator must keep at least 10 characters"
    );
    assert_eq!(
        message(vault::password_generator(Some(&json!(false)))),
        "Expected an object"
    );
}

#[test]
fn validates_rotation_checkout_lease_and_engine_settings() {
    run(|| async {
        let ctx = context(with_rotator).await;
        let settings = settings(&ctx);
        // tests/vault.test.ts: an unknown rotator.
        assert_eq!(
            message(vault::rotation_settings(
                &settings,
                "text",
                Some(&json!({ "rotator": "nope" })),
                None
            )),
            "Unknown rotator nope"
        );
        // tests/vault-security.test.ts: json secrets name the field rotation replaces, never a prototype name.
        assert_eq!(
            message(vault::rotation_settings(
                &settings,
                "json",
                Some(&json!({ "generator": true })),
                None
            )),
            "json secrets name the field rotation replaces (rotation.field)"
        );
        for field in ["__proto__", "constructor", "prototype"] {
            assert_eq!(
                code(vault::rotation_settings(
                    &settings,
                    "json",
                    Some(&json!({ "field": field, "generator": true })),
                    None
                )),
                "INVALID_INPUT"
            );
        }
        assert_eq!(
            message(vault::rotation_settings(
                &settings,
                "text",
                Some(&json!({ "field": "password" })),
                None
            )),
            "rotation.field is for json secrets"
        );
        let previous = vault::SecretRotation {
            last_rotated_at: Some(NOW - DAY),
            ..vault::SecretRotation::default()
        };
        let rotation = vault::rotation_settings(
            &settings,
            "json",
            Some(&json!({ "rotator": "db", "field": "password", "intervalDays": 30 })),
            Some(&previous),
        )
        .unwrap()
        .expect("a rotation");
        assert_eq!(
            serde_json::to_value(&rotation).unwrap(),
            json!({ "intervalDays": 30.0, "rotator": "db", "field": "password", "lastRotatedAt": NOW - DAY })
        );
        assert_eq!(
            vault::rotation_settings(&settings, "text", None, Some(&previous)).unwrap(),
            Some(previous.clone())
        );
        assert_eq!(
            vault::rotation_settings(&settings, "text", Some(&Value::Null), Some(&previous))
                .unwrap(),
            None
        );

        // The interval counts from the last rotation (or creation), never before now.
        let scheduled = vault::schedule_rotation(Some(&rotation), NOW - 100.0 * DAY, NOW)
            .unwrap()
            .unwrap();
        assert_eq!(scheduled.next_rotation_at, Some(NOW + 29.0 * DAY));
        let overdue = vault::SecretRotation {
            interval_days: Some(1.0),
            ..vault::SecretRotation::default()
        };
        assert_eq!(
            vault::schedule_rotation(Some(&overdue), NOW - 10.0 * DAY, NOW)
                .unwrap()
                .unwrap()
                .next_rotation_at,
            Some(NOW)
        );
        assert_eq!(vault::schedule_rotation(None, NOW, NOW).unwrap(), None);

        let policy = vault::checkout_policy(Some(&json!({ "exclusive": true })), None)
            .unwrap()
            .unwrap();
        assert!(policy.required && policy.exclusive && !policy.rotate_on_checkin);
        assert_eq!(policy.max_duration_ms, 3_600_000.0);
        assert_eq!(
            message(vault::checkout_policy(
                Some(&json!({ "required": "yes" })),
                None
            )),
            "checkout.required must be a boolean"
        );
        assert_eq!(
            message(vault::checkout_policy(
                Some(&json!({ "maxDurationMs": 1000 })),
                None
            )),
            "Invalid checkout.maxDurationMs"
        );
        assert_eq!(
            vault::checkout_policy(Some(&Value::Null), Some(&policy)).unwrap(),
            None
        );
        assert_eq!(
            vault::checkout_policy(None, Some(&policy)).unwrap(),
            Some(policy.clone())
        );

        let lease = vault::lease_settings(None, None).unwrap();
        assert_eq!((lease.default_ttl_ms, lease.max_ttl_ms), (3_600_000.0, DAY));
        let long =
            vault::lease_settings(Some(&json!({ "defaultTtlMs": 2.0 * DAY })), None).unwrap();
        assert_eq!(long.max_ttl_ms, 2.0 * DAY);
        assert_eq!(
            message(vault::lease_settings(
                Some(&json!({ "defaultTtlMs": 2.0 * DAY, "maxTtlMs": DAY })),
                None
            )),
            "lease.defaultTtlMs must not exceed lease.maxTtlMs"
        );
        assert_eq!(vault::lease_settings(None, Some(&long)).unwrap(), long);

        assert_eq!(vault::engine_config(None).unwrap(), json!({}));
        assert_eq!(
            vault::engine_config(Some(&json!({ "role": "reader", "ttl": 1.0 }))).unwrap(),
            json!({ "role": "reader", "ttl": 1 })
        );
        assert_eq!(
            message(vault::engine_config(Some(&s(&"x".repeat(9000))))),
            "engineConfig must be JSON of at most 8 KiB"
        );
    });
}

#[test]
fn stores_versions_moves_stages_and_reveals() {
    // tests/vault.test.ts "stores versions, moves stages, reveals, and logs access".
    run(|| async {
        let ctx = context(|_| {}).await;
        let created = secret(&ctx, "prod/db/password", "text").await;
        let (first, version) = put(&ctx, &created, "first-password-value", None).await;
        assert_eq!(version.version, 1.0);
        assert_eq!(first.stages, IndexMap::from([("current".to_owned(), 1.0)]));
        assert_eq!(first.latest_version, 1.0);
        // Values are sealed at rest.
        let stored = better_iam_core::js::stringify(&Value::Array(
            records(&ctx, "vaultVersions")
                .await
                .into_iter()
                .map(Value::Object)
                .collect(),
        ));
        assert!(!stored.contains("first-password-value"));
        assert_eq!(version.unique_key, format!("{}:1", created.id));

        let (second, _) = put(&ctx, &first, "second-password-value", None).await;
        assert_eq!(
            reveal(&ctx, &second, json!({})).await.unwrap(),
            "second-password-value"
        );
        assert_eq!(
            reveal(&ctx, &second, json!({ "stage": "previous" }))
                .await
                .unwrap(),
            "first-password-value"
        );

        // Staged values wait for promotion; promote also rolls back.
        let (staged, third) = put(&ctx, &second, "third-password-value", Some("pending")).await;
        assert_eq!(third.version, 3.0);
        let promoted = {
            let ctx = ctx.clone();
            ctx.store
                .clone()
                .transaction(move |tx| async move {
                    vault::promote_version(&ctx, &tx, &staged, 3.0, "owner", None).await
                })
                .await
                .unwrap()
        };
        assert_eq!(
            serde_json::to_value(&promoted.stages).unwrap(),
            json!({ "current": 3.0, "previous": 2.0 })
        );
        let rolled_back = {
            let ctx = ctx.clone();
            ctx.store
                .clone()
                .transaction(move |tx| async move {
                    vault::promote_version(&ctx, &tx, &promoted, 1.0, "owner", None).await
                })
                .await
                .unwrap()
        };
        assert_eq!(
            reveal(&ctx, &rolled_back, json!({})).await.unwrap(),
            "first-password-value"
        );

        // Version and stage selection.
        assert_eq!(
            message(
                reveal(
                    &ctx,
                    &rolled_back,
                    json!({ "version": 1, "stage": "current" })
                )
                .await
            ),
            "Pass version or stage, not both"
        );
        assert_eq!(
            message(reveal(&ctx, &rolled_back, json!({ "stage": "canary" })).await),
            "No version has this stage"
        );
        // `stages.constructor` is Object.prototype's: a lookup that names no version.
        assert_eq!(
            message(reveal(&ctx, &rolled_back, json!({ "stage": "constructor" })).await),
            "Version not found"
        );
        assert_eq!(
            message(reveal(&ctx, &rolled_back, json!({ "version": 9 })).await),
            "Version not found"
        );
        assert_eq!(
            message(reveal(&ctx, &rolled_back, json!({ "version": 0 })).await),
            "Invalid version"
        );
        let empty = secret(&ctx, "empty", "text").await;
        let error = reveal(&ctx, &empty, json!({})).await.unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.status, error.message.as_str()),
            ("NOT_FOUND", 404, "This secret has no current version")
        );

        // Disabled and destroyed versions are not revealed.
        let mut disabled = vault::version_of(&ctx.store, &rolled_back, 2.0)
            .await
            .unwrap()
            .unwrap();
        disabled.state = "disabled".into();
        assert_eq!(
            vault::open_version(&ctx, &ctx.store, &disabled, None)
                .await
                .unwrap_err()
                .code,
            "VERSION_DISABLED"
        );
        // A disabled version still opens for re-encryption.
        assert_eq!(
            vault::open_stored(&ctx, &ctx.store, &disabled, None)
                .await
                .unwrap(),
            "second-password-value"
        );
        let mut destroyed = disabled.clone();
        destroyed.state = "destroyed".into();
        destroyed.sealed = None;
        let error = vault::open_version(&ctx, &ctx.store, &destroyed, None)
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.status),
            ("VERSION_DESTROYED", 410)
        );

        let versions = vault::secret_versions(&ctx.store, &rolled_back)
            .await
            .unwrap();
        assert_eq!(
            versions
                .iter()
                .map(|version| version.version)
                .collect::<Vec<_>>(),
            [3.0, 2.0, 1.0]
        );
    });
}

#[test]
fn prunes_versions_no_stage_names() {
    run(|| async {
        let ctx = context(|_| {}).await;
        let mut current = secret(&ctx, "pruned", "text").await;
        for index in 1..=5 {
            current = put(&ctx, &current, &format!("value-number-{index}"), None)
                .await
                .0;
        }
        // maxVersions 3: versions 1 and 2 are gone, 4 stays as `previous`.
        let versions = vault::secret_versions(&ctx.store, &current).await.unwrap();
        assert_eq!(
            versions
                .iter()
                .map(|version| version.version)
                .collect::<Vec<_>>(),
            [5.0, 4.0, 3.0]
        );
        // A staged old version survives pruning.
        let mut staged = current.clone();
        staged.stages.insert("canary".into(), 3.0);
        staged.max_versions = 1.0;
        let removed = {
            let staged = staged.clone();
            ctx.store
                .transaction(move |tx| async move { vault::prune_versions(&tx, &staged).await })
                .await
                .unwrap()
        };
        assert_eq!(removed, 0.0, "versions 5, 4 and 3 are all staged");
        staged.stages.shift_remove("canary");
        let removed = ctx
            .store
            .transaction(move |tx| async move { vault::prune_versions(&tx, &staged).await })
            .await
            .unwrap();
        assert_eq!(removed, 1.0, "version 3 is past maxVersions and unstaged");
    });
}

#[test]
fn rotation_bookkeeping_follows_promotions() {
    run(|| async {
        let ctx = context(|_| {}).await;
        let mut created = secret(&ctx, "rotating", "text").await;
        created.rotation = Some(vault::SecretRotation {
            interval_days: Some(30.0),
            failures: Some(2.0),
            last_failure: Some(vault::RotationFailure {
                at: NOW - DAY,
                message: "boom".into(),
                extra: Map::new(),
            }),
            due_notified_at: Some(NOW - DAY),
            ..vault::SecretRotation::default()
        });
        let (first, _) = put(&ctx, &created, "first-rotating-value", None).await;
        let rotation = first.rotation.clone().unwrap();
        assert_eq!(rotation.last_rotated_at, Some(NOW));
        assert_eq!(rotation.next_rotation_at, Some(NOW + 30.0 * DAY));
        assert_eq!(rotation.failures, None);
        assert_eq!(rotation.last_failure, None);
        assert_eq!(rotation.due_notified_at, None);

        // A rotation's staged version stays marked until it becomes current.
        let (staged, pending) = put(&ctx, &first, "second-rotating-value", Some("pending")).await;
        let mut marked = staged.clone();
        marked.rotation_pending = Some(pending.version);
        let (kept, _) = {
            let ctx = ctx.clone();
            let marked = marked.clone();
            ctx.store
                .clone()
                .transaction(move |tx| async move {
                    let stored =
                        vault::promote_version(&ctx, &tx, &marked, 1.0, "owner", None).await?;
                    Ok((stored, ()))
                })
                .await
                .unwrap()
        };
        assert_eq!(kept.rotation_pending, Some(2.0));
        let done = {
            let ctx = ctx.clone();
            ctx.store
                .clone()
                .transaction(move |tx| async move {
                    vault::promote_version(&ctx, &tx, &marked, 2.0, "owner", Some(true)).await
                })
                .await
                .unwrap()
        };
        assert_eq!(done.rotation_pending, None);
        assert_eq!(done.stages.get("pending"), None);

        // A rotation on a secret without settings only records when it happened.
        let plain = secret(&ctx, "plain", "text").await;
        let rotated = {
            let ctx = ctx.clone();
            ctx.store
                .clone()
                .transaction(move |tx| async move {
                    let added = vault::add_version(
                        &ctx,
                        &tx,
                        &plain,
                        "rotated-value",
                        "rotation",
                        "op",
                        None,
                    )
                    .await?;
                    vault::promote_version(&ctx, &tx, &added.secret, 1.0, "op", Some(true)).await
                })
                .await
                .unwrap()
        };
        assert_eq!(
            serde_json::to_value(rotated.rotation.unwrap()).unwrap(),
            json!({ "lastRotatedAt": NOW })
        );
    });
}

#[test]
fn records_access_and_lists_live_leases() {
    run(|| async {
        let ctx = context(|_| {}).await;
        let created = secret(&ctx, "logged", "text").await;
        {
            let ctx = ctx.clone();
            let created = created.clone();
            ctx.store
                .clone()
                .transaction(move |tx| async move {
                    vault::record_access(
                        &ctx,
                        &tx,
                        &created,
                        &AccessEntry {
                            identity_id: "reader".into(),
                            action: "reveal".into(),
                            version: Some(1.0),
                            session_kind: Some("user".into()),
                            ..AccessEntry::default()
                        },
                    )
                    .await?;
                    vault::record_access(
                        &ctx,
                        &tx,
                        &created,
                        &AccessEntry {
                            identity_id: "writer".into(),
                            action: "put".into(),
                            ..AccessEntry::default()
                        },
                    )
                    .await
                })
                .await
                .unwrap();
        }
        let access = records(&ctx, "vaultAccess").await;
        assert_eq!(access.len(), 2);
        let reveal = access
            .iter()
            .find(|record| record["action"] == "reveal")
            .unwrap();
        assert_eq!(
            reveal.keys().collect::<Vec<_>>(),
            [
                "id",
                "tenantId",
                "secretId",
                "name",
                "identityId",
                "action",
                "version",
                "sessionKind",
                "at",
                "expiresAt"
            ]
        );
        assert_eq!(reveal["expiresAt"].as_f64(), Some(NOW + 90.0 * DAY));
        let stored = vault::find_secret(&ctx.store, "tenant-1", "logged")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.last_accessed_at, Some(NOW));

        let lease = |id: &str, state: &str, issued: f64, expires: f64| {
            json!({
                "id": id, "tenantId": "tenant-1", "secretId": created.id, "name": "logged", "kind": "checkout",
                "holderId": "reader", "state": state, "issuedAt": issued, "expiresAt": expires,
                "maxExpiresAt": expires,
            })
        };
        let leases = vec![
            lease("late", "active", NOW - 10.0, NOW + 1000.0),
            lease("early", "active", NOW - 20.0, NOW + 1000.0),
            lease("expired", "active", NOW - 30.0, NOW),
            lease("ended", "ended", NOW - 40.0, NOW + 1000.0),
        ];
        ctx.store
            .transaction(move |tx| async move {
                for lease in leases {
                    let Value::Object(lease) = lease else {
                        unreachable!()
                    };
                    tx.insert("vaultLeases", &lease).await?;
                }
                Ok(())
            })
            .await
            .unwrap();
        let live = vault::live_leases(&ctx, &ctx.store, &created)
            .await
            .unwrap();
        assert_eq!(
            live.iter()
                .map(|lease| lease.id.as_str())
                .collect::<Vec<_>>(),
            ["early", "late"]
        );
    });
}

#[test]
fn resolves_secrets_with_their_attributes() {
    run(|| async {
        let ctx = context(|_| {}).await;
        let mut created = secret(&ctx, "prod/api-key", "text").await;
        created.checkout = vault::checkout_policy(Some(&json!({})), None).unwrap();
        ctx.store
            .transaction({
                let created = created.clone();
                move |tx| async move {
                    tx.put("vaultSecrets", &better_iam_server::port::encode(&created))
                        .await
                }
            })
            .await
            .unwrap();
        let reference = |id: &str| ResourceRef {
            tenant_id: "tenant-1".into(),
            kind: "iam".into(),
            id: id.into(),
        };
        let resolved =
            vault::resolve_secret_resource(&ctx.store, &reference("vault/secrets/prod/api-key"))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            Value::Object(resolved.attributes.unwrap()),
            json!({
                "name": "prod/api-key",
                "kind": "static",
                "format": "text",
                "status": "active",
                "createdBy": "owner",
                "checkoutRequired": true,
                "rotationEnabled": false,
                "customerManagedKey": false,
                "tag.environment": "prod",
            })
        );
        // A name nobody uses resolves without attributes; other resources are not the vault's.
        let unknown =
            vault::resolve_secret_resource(&ctx.store, &reference("vault/secrets/nobody"))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(unknown.attributes, None);
        assert_eq!(unknown.id, "vault/secrets/nobody");
        assert!(
            vault::resolve_secret_resource(&ctx.store, &reference("roles/r1"))
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn reseals_under_a_new_deployment_secret() {
    // tests/vault.test.ts "serves trusted code, resolves references, and re-seals under a new deployment secret".
    run(|| async {
        let old = context(|_| {}).await;
        let sealed = vault::seal_value(&old, "sealed-value", "vault:t:s:1").unwrap();
        assert_eq!(
            vault::open_value(&old, &sealed, "vault:t:s:1").unwrap(),
            "sealed-value"
        );
        // Bound to the version it was sealed for.
        let error = vault::open_value(&old, &sealed, "vault:t:s:2").unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.status, error.message.as_str()),
            (
                "INVALID_SEALED_VALUE",
                500,
                "The secret value cannot be opened"
            )
        );
        let rotated = context(|options| {
            options.secret = "a-brand-new-deployment-secret-of-32-chars".into();
            options.previous_secrets = Some(vec![SECRET.into()]);
        })
        .await;
        assert_eq!(
            vault::open_value(&rotated, &sealed, "vault:t:s:1").unwrap(),
            "sealed-value"
        );
        let forgotten = context(|options| {
            options.secret = "a-brand-new-deployment-secret-of-32-chars".into();
        })
        .await;
        assert_eq!(
            vault::open_value(&forgotten, &sealed, "vault:t:s:1")
                .unwrap_err()
                .code,
            "INVALID_SEALED_VALUE"
        );
    });
}

#[test]
fn redacts_values_and_their_spellings_from_errors() {
    // tests/vault-security.test.ts "redacts every field of a json value from rotator errors".
    let error = IamError::new(
        "INTERNAL_ERROR",
        "ALTER ROLE app PASSWORD 'initial-password' failed",
    );
    let value = Some(r#"{"username":"app","password":"initial-password"}"#.to_owned());
    assert_eq!(
        vault::redacted_message(&error, &[value.clone(), None]).unwrap(),
        "ALTER ROLE app PASSWORD '[redacted]' failed"
    );
    // JSON-escaped, URL-encoded and base64 spellings are redacted too; short fields (`app`) are not.
    let spelled = IamError::new(
        "INTERNAL_ERROR",
        "url=pa%24%24word%2F1 b64=cGEkJHdvcmQvMQ json=quote\\\"d",
    );
    assert_eq!(
        vault::redacted_message(
            &spelled,
            &[Some("pa$$word/1".into()), Some("quote\"d".into())]
        )
        .unwrap(),
        "url=[redacted] b64=[redacted] json=[redacted]"
    );
    // Control characters become spaces; long messages are cut at 512 characters.
    let long = IamError::new("INTERNAL_ERROR", format!("line\none{}", "x".repeat(600)));
    let redacted = vault::redacted_message(&long, &[]).unwrap();
    assert!(redacted.starts_with("line one"));
    assert_eq!(redacted.len(), 512);
    assert_eq!(
        vault::redacted_message(&IamError::new("X", ""), &[]).unwrap(),
        "Unknown error"
    );
    // A number field of a json value is redacted by its digits.
    let numeric = IamError::new("INTERNAL_ERROR", "pin 123456 refused");
    assert_eq!(
        vault::redacted_message(&numeric, &[Some(r#"{"pin":123456}"#.into())]).unwrap(),
        "pin [redacted] refused"
    );
}

#[test]
fn times_out_slow_calls() {
    run(|| async {
        let ctx = context(|options| {
            options.vault = Some(VaultOptions {
                call_timeout_ms: Some(1000.0),
                ..VaultOptions::default()
            });
        })
        .await;
        let quick = vault::with_timeout(&ctx, "The rotator db", async { Ok(7) })
            .await
            .unwrap();
        assert_eq!(quick, 7);
        let failed: IamResult<()> = vault::with_timeout(&ctx, "The rotator db", async {
            Err(IamError::new("ROTATOR", "refused"))
        })
        .await;
        assert_eq!(failed.unwrap_err().message, "refused");
        let slow: IamResult<()> = vault::with_timeout(&ctx, "The engine pg", async {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            Ok(())
        })
        .await;
        assert_eq!(
            slow.unwrap_err().message,
            "The engine pg did not finish within 1000 ms"
        );
    });
}

#[test]
fn vault_constants() {
    assert_eq!(
        vault::vault_time().unwrap(),
        json!({ "MINUTE": 60000, "HOUR": 3600000, "DAY": 86400000 })
    );
    assert_eq!(vault::VAULT_OPERATOR, "deployment-operator");
    assert_eq!(vault::VAULT_COLLECTIONS["versions"], "vaultVersions");
    assert_eq!(vault::SYSTEM_STAGES, ["current", "previous", "pending"]);
}

#[test]
fn keeps_records_round_tripping() {
    // A dynamic secret's engine configuration may be JSON null; a read-modify-write keeps it.
    let record = json!({
        "id": "s1", "tenantId": "t1", "uniqueKey": "db", "name": "db", "kind": "dynamic", "format": "json",
        "tags": {}, "status": "active", "stages": {}, "latestVersion": 0, "maxVersions": 10, "createdAt": 1,
        "createdBy": "o", "updatedAt": 1, "updatedBy": "o", "engine": "pg", "engineConfig": null,
        "lease": { "defaultTtlMs": 3600000, "maxTtlMs": 86400000 }, "futureMember": true,
    });
    let secret: VaultSecret = serde_json::from_value(record).unwrap();
    assert_eq!(secret.engine_config, Some(Value::Null));
    let encoded = serde_json::to_value(&secret).unwrap();
    assert_eq!(encoded["engineConfig"], Value::Null);
    assert!(encoded.as_object().unwrap().contains_key("engineConfig"));
    assert_eq!(encoded["futureMember"], json!(true));
    let absent: VaultSecret = serde_json::from_value(json!({
        "id": "s1", "tenantId": "t1", "uniqueKey": "x", "name": "x", "kind": "static", "format": "text",
        "tags": {}, "status": "active", "stages": {}, "latestVersion": 0, "maxVersions": 10, "createdAt": 1,
        "createdBy": "o", "updatedAt": 1, "updatedBy": "o",
    }))
    .unwrap();
    assert_eq!(absent.engine_config, None);
}
