//! The default device key store over the host's key database ("keeps one browser key per scope in the default
//! store" of tests/device-posture.test.ts). A binary of its own: it installs a process-wide key database.

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use better_iam_client::BoxError;
use better_iam_client::device::{
    DeviceKeyPair, DeviceKeyStore, DeviceProverOptions, KeyDatabase, create_device_prover,
    indexed_db_key_store, set_key_database,
};
use support::run;

/// Just enough of a key database: databases by name, one object store each, values kept as given.
#[derive(Default)]
struct FakeDatabase {
    databases: Mutex<BTreeMap<String, BTreeMap<String, DeviceKeyPair>>>,
}

impl FakeDatabase {
    fn names(&self) -> Vec<String> {
        self.databases.lock().unwrap().keys().cloned().collect()
    }
}

#[async_trait::async_trait]
impl KeyDatabase for FakeDatabase {
    async fn get(
        &self,
        database: &str,
        store: &str,
        key: &str,
    ) -> Result<Option<DeviceKeyPair>, BoxError> {
        assert_eq!(store, "keys");
        let mut databases = self.databases.lock().unwrap();
        Ok(databases
            .entry(database.to_owned())
            .or_default()
            .get(key)
            .cloned())
    }

    async fn put(
        &self,
        database: &str,
        store: &str,
        key: &str,
        pair: DeviceKeyPair,
    ) -> Result<(), BoxError> {
        assert_eq!((store, key), ("keys", "current"));
        let mut databases = self.databases.lock().unwrap();
        databases
            .entry(database.to_owned())
            .or_default()
            .insert(key.to_owned(), pair);
        Ok(())
    }

    async fn delete(&self, database: &str, store: &str, key: &str) -> Result<(), BoxError> {
        assert_eq!(store, "keys");
        let mut databases = self.databases.lock().unwrap();
        databases
            .entry(database.to_owned())
            .or_default()
            .remove(key);
        Ok(())
    }
}

#[test]
fn keeps_one_key_per_scope_in_the_default_store() {
    run(|| async {
        let fake = Arc::new(FakeDatabase::default());
        let previous = set_key_database(Some(fake.clone()));
        let scoped = |scope: &str| {
            create_device_prover(DeviceProverOptions {
                scope: Some(scope.to_owned()),
                ..DeviceProverOptions::default()
            })
            .unwrap()
        };
        let first = scoped("identity-1");
        let second = scoped("identity-2");
        let again = scoped("identity-1");
        assert_ne!(
            first.key_id().await.unwrap(),
            second.key_id().await.unwrap()
        );
        assert_eq!(again.key_id().await.unwrap(), first.key_id().await.unwrap());
        assert_eq!(
            fake.names(),
            vec![
                "better-iam-registered-device:identity-1".to_owned(),
                "better-iam-registered-device:identity-2".to_owned(),
            ]
        );
        let error = create_device_prover(DeviceProverOptions {
            scope: Some("has a space".into()),
            ..DeviceProverOptions::default()
        })
        .err()
        .unwrap();
        assert!(error.client().unwrap().message.contains("scope"));
        // The unscoped default database, and the explicit store over it.
        let unscoped = create_device_prover(DeviceProverOptions::default()).unwrap();
        let kid = unscoped.key_id().await.unwrap();
        let store = indexed_db_key_store(None).unwrap();
        assert!(store.load().await.unwrap().is_some());
        unscoped.reset().await.unwrap();
        assert!(store.load().await.unwrap().is_none());
        assert_ne!(unscoped.key_id().await.unwrap(), kid);
        set_key_database(previous);
    });
}
