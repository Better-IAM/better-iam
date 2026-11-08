//! `load_config_file` reports files it cannot read the way the CLI's `loadConfig` does (packages/cli config.ts).

use better_iam_server::standalone_config::{ConfigRuntime, load_config_file};

#[test]
fn a_missing_configuration_file_is_config_not_found() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("better-iam.json");
    let Err(error) = load_config_file(&path, &ConfigRuntime::default()) else {
        panic!("a missing file must be refused");
    };
    assert_eq!(error.code, "CONFIG_NOT_FOUND");
    assert_eq!(
        error.message,
        format!("Configuration {} does not exist", path.display())
    );
    assert_eq!(error.status, 400);
}

#[test]
fn an_unreadable_configuration_file_is_config_load_failed() {
    // A directory exists but cannot be read as a file.
    let directory = tempfile::tempdir().unwrap();
    let Err(error) = load_config_file(directory.path(), &ConfigRuntime::default()) else {
        panic!("a directory must be refused");
    };
    assert_eq!(error.code, "CONFIG_LOAD_FAILED");
    assert!(
        error.message.starts_with(&format!(
            "Configuration {} could not be read: ",
            directory.path().display()
        )),
        "{}",
        error.message
    );
}
