//! Snapshot commands (`commands/storage.ts`): deployment operations straight on storage, like migrate (no
//! credential).

use std::io::{BufRead as _, BufReader, Write as _};
use std::sync::{Arc, Mutex};

use better_iam_core::{IamError, SnapshotOptions, copy_store, export_store, import_store};
use serde_json::{Map, Value};

use crate::errors::{CliResult, io_error, usage_error};
use crate::framework::{CommandSpec, CommandTarget, FlagSpec, define_command};
use crate::paths::display;

fn with_summary(first: (&str, Value), summary: Value, last: Option<(&str, Value)>) -> Value {
    let mut map = Map::new();
    map.insert(first.0.into(), first.1);
    if let Value::Object(members) = summary {
        map.extend(members);
    }
    if let Some((key, value)) = last {
        map.insert(key.into(), value);
    }
    Value::Object(map)
}

fn create_private(path: &std::path::Path) -> CliResult<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| io_error(&error, "open", path))
}

pub fn storage_commands() -> Vec<CommandSpec> {
    vec![
        define_command(
            "store-export",
            "Write every record of the database as a JSON Lines snapshot",
            |context| async move {
                let output = context.path(context.flags.string("output").unwrap_or_default());
                let instance = context.iam()?;
                let file = create_private(&output)?;
                let sink = Arc::new(Mutex::new((file, String::new(), None::<std::io::Error>)));
                let writer = sink.clone();
                let exported = export_store(
                    instance.store.as_ref(),
                    move |line: String| {
                        let mut guard = writer.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        let (file, buffered, failed) = &mut *guard;
                        buffered.push_str(&line);
                        buffered.push('\n');
                        if buffered.len() >= 1 << 20 {
                            if let Err(error) = file.write_all(buffered.as_bytes()) {
                                let message = error.to_string();
                                *failed = Some(error);
                                return Err(IamError::with_status("EIO", message, 500));
                            }
                            buffered.clear();
                        }
                        Ok(())
                    },
                    &SnapshotOptions::default(),
                )
                .await;
                let finished = (|| -> CliResult<Value> {
                    let summary = exported?;
                    let mut guard = sink.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    let (file, buffered, failed) = &mut *guard;
                    if let Some(error) = failed.take() {
                        return Err(io_error(&error, "write", &output));
                    }
                    if !buffered.is_empty() {
                        file.write_all(buffered.as_bytes())
                            .map_err(|error| io_error(&error, "write", &output))?;
                    }
                    file.sync_all().map_err(|error| io_error(&error, "fsync", &output))?;
                    Ok(summary.to_value())
                })();
                drop(sink);
                match finished {
                    Ok(summary) => Ok(Some(with_summary(("output", Value::String(display(&output))), summary, None))),
                    Err(error) => {
                        let _ = std::fs::remove_file(&output);
                        Err(error)
                    }
                }
            },
        )
        .group("Storage")
        .description(
            "store-export writes every record of the database as a JSON Lines snapshot (one consistent transaction; the file holds credential hashes and encrypted secrets, so protect it like the database). It never overwrites a file.",
        )
        .target(CommandTarget::Config)
        .config_defaults(false)
        .flag(
            "output",
            FlagSpec::string("The snapshot file to create (mode 0600; it must not exist)")
                .value("PATH")
                .required(),
        ),
        define_command("store-import", "Load a snapshot into an empty database", |context| async move {
            // Open the file before touching a database, so a wrong path changes nothing.
            let input_path = context.path(context.flags.string("input").unwrap_or_default());
            let input = std::fs::File::open(&input_path).map_err(|error| io_error(&error, "open", &input_path))?;
            let instance = context.iam()?;
            // Schema only: initialize() would write records, and the target must stay empty until the import.
            instance.store.migrate().await?;
            let lines = BufReader::new(input).lines().map_while(Result::ok);
            let summary = import_store(instance.store.as_ref(), lines).await?;
            Ok(Some(with_summary(
                ("input", Value::String(display(&input_path))),
                summary.to_value(),
                Some(("next", Value::String("Run migrate to apply plugin migrations.".into()))),
            )))
        })
        .group("Storage")
        .description(
            "store-import loads a snapshot into an empty database in one transaction; it migrates the target first and changes nothing on failure. Run migrate afterwards to apply plugin migrations.",
        )
        .target(CommandTarget::Config)
        .config_defaults(false)
        .flag("input", FlagSpec::string("The snapshot to load").value("PATH").required()),
        define_command(
            "store-copy",
            "Copy the database into the empty database of another configuration",
            |context| async move {
                let target_path = context.path(context.flags.string("target-config").unwrap_or_default());
                if context.config_path()?.is_some_and(|located| located.path == target_path) {
                    return Err(usage_error("--target-config must name a different configuration", None));
                }
                let source = context.iam()?;
                let target = context.open(Some(&display(&target_path)))?;
                target.store.migrate().await?;
                let summary =
                    copy_store(source.store.as_ref(), target.store.as_ref(), &SnapshotOptions::default()).await?;
                Ok(Some(with_summary(
                    ("target", Value::String(display(&target_path))),
                    summary.to_value(),
                    Some(("next", Value::String("Run migrate with the target configuration.".into()))),
                )))
            },
        )
        .group("Storage")
        .description(
            "store-copy copies the configured database into the empty database of --target-config (for example SQLite to PostgreSQL); it migrates the target first and changes nothing on failure.",
        )
        .target(CommandTarget::Config)
        .config_defaults(false)
        .flag(
            "target-config",
            FlagSpec::string("Configuration of the empty target database").value("PATH").required(),
        )
        .examples(&["better-iam store-copy --config sqlite.json --target-config postgres.json"]),
    ]
}
