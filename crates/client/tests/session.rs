//! The session store (the "session store" suite of tests/react.test.tsx), and the store over a real server.

mod support;

#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_client::session::{
    SessionClient, SessionStatus, SessionStoreOptions, create_session_store, is_unauthenticated,
};
use better_iam_client::{
    BoxError, ClientOptions, Error, FetchError, FetchRequest, FetchResponse, IamClient,
    IamClientError, create_iam_client,
};
use futures::future::BoxFuture;
use serde_json::{Value, json};
use support::{run, server_fetch};

/// A session client over the generic transport, so the stub backend can answer any session shape.
#[derive(Clone)]
struct LooseClient(IamClient);

impl SessionClient for LooseClient {
    type Session = Value;
    type Error = Error;

    fn get_session(&self) -> BoxFuture<'static, Result<Value, Error>> {
        Box::pin(
            self.0
                .request::<Value>("auth/getSession", &json!({}))
                .send(),
        )
    }

    fn sign_out(&self) -> BoxFuture<'static, Result<(), Error>> {
        let call = self.0.request::<Value>("auth/signOut", &json!({}));
        Box::pin(async move { call.send().await.map(|_| ()) })
    }
}

/// A backend with a current user (`server()` of the React suite).
#[derive(Clone, Default)]
struct Backend {
    user: Arc<Mutex<Option<Value>>>,
    calls: Arc<Mutex<Vec<String>>>,
}

impl Backend {
    fn new() -> Self {
        let backend = Self::default();
        *backend.user.lock().unwrap() = Some(json!({ "id": "alice", "name": "Alice" }));
        backend
    }

    fn client(&self) -> IamClient {
        let backend = self.clone();
        create_iam_client(ClientOptions::new("https://app.example.test").fetch_fn(
            move |request: FetchRequest| {
                let path = request
                    .url
                    .trim_start_matches("https://app.example.test/api/iam/")
                    .to_owned();
                backend.calls.lock().unwrap().push(path.clone());
                let user = backend.user.lock().unwrap().clone();
                async move {
                    Ok::<_, BoxError>(match (path.as_str(), user) {
                        ("auth/getSession", Some(user)) => FetchResponse::json(
                            200,
                            &json!({ "data": { "identity": user, "session": { "tenantId": "acme" } } }),
                        ),
                        ("auth/signOut", _) => {
                            FetchResponse::json(200, &json!({ "data": { "success": true } }))
                        }
                        _ => FetchResponse::json(
                            401,
                            &json!({ "error": { "code": "UNAUTHENTICATED", "message": "Sign in" } }),
                        ),
                    })
                }
            },
        ))
        .unwrap()
    }
}

#[test]
fn tracks_loading_authenticated_unauthenticated_and_error_states_and_shares_in_flight_refreshes() {
    run(|| async {
        let backend = Backend::new();
        let store = create_session_store(
            LooseClient(backend.client()),
            SessionStoreOptions::default(),
        );
        let seen: Arc<Mutex<Vec<SessionStatus>>> = Arc::default();
        let (record, observed) = (seen.clone(), store.clone());
        let _subscription = store.subscribe(Arc::new(move || {
            record.lock().unwrap().push(observed.get_snapshot().status)
        }));
        assert_eq!(store.get_snapshot().status, SessionStatus::Loading);
        assert_eq!(store.get_snapshot().updated_at, 0.0);
        let (first, second) = futures::join!(store.refresh(), store.refresh());
        assert_eq!(first.updated_at, second.updated_at);
        assert_eq!(first.status, SessionStatus::Authenticated);
        assert_eq!(second.status, SessionStatus::Authenticated);
        assert_eq!(
            first.session.as_ref().unwrap()["identity"]["name"],
            json!("Alice")
        );
        let session_calls = |backend: &Backend| {
            backend
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|path| *path == "auth/getSession")
                .count()
        };
        assert_eq!(session_calls(&backend), 1);
        *backend.user.lock().unwrap() = None;
        assert_eq!(store.refresh().await.status, SessionStatus::Unauthenticated);
        let error = store.get_snapshot().error.unwrap();
        assert!(error.client().is_some());
        assert_eq!(error.code(), Some("UNAUTHENTICATED"));
        store.set(Some(json!({ "identity": { "id": "bob", "name": "Bob" }, "session": { "tenantId": "acme" } })));
        assert_eq!(
            store.get_snapshot().session.unwrap()["identity"]["id"],
            json!("bob")
        );

        let offline = create_iam_client(ClientOptions::new("https://app.example.test").fetch_fn(
            |_request: FetchRequest| async {
                Err::<FetchResponse, BoxError>(Arc::new(FetchError("offline".into())))
            },
        ))
        .unwrap();
        let broken = create_session_store(
            LooseClient(offline),
            SessionStoreOptions {
                initial: Some(Some(
                    json!({ "identity": { "id": "x", "name": "X" }, "session": { "tenantId": "acme" } }),
                )),
            },
        );
        assert_eq!(broken.get_snapshot().status, SessionStatus::Authenticated);
        assert_eq!(broken.refresh().await.status, SessionStatus::Error);
        assert_eq!(
            broken.get_snapshot().session.unwrap()["identity"]["id"],
            json!("x")
        );
        assert!(broken.sign_out().await.is_err());
        let snapshot = broken.get_snapshot();
        assert_eq!(snapshot.status, SessionStatus::Unauthenticated);
        assert!(snapshot.session.is_none());
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                SessionStatus::Authenticated,
                SessionStatus::Unauthenticated,
                SessionStatus::Authenticated
            ]
        );
    });
}

#[test]
fn starts_signed_out_from_an_explicit_empty_session_and_stops_listeners_on_unsubscribe() {
    run(|| async {
        let backend = Backend::new();
        let store = create_session_store(
            LooseClient(backend.client()),
            SessionStoreOptions {
                initial: Some(None),
            },
        );
        assert_eq!(store.get_snapshot().status, SessionStatus::Unauthenticated);
        assert!(store.get_snapshot().updated_at > 0.0);
        let count = Arc::new(Mutex::new(0));
        let counter = count.clone();
        let listener: better_iam_client::session::Listener =
            Arc::new(move || *counter.lock().unwrap() += 1);
        // The same listener subscribed twice is called once per change.
        let subscription = store.subscribe(listener.clone());
        let _again = store.subscribe(listener);
        store.set(None);
        assert_eq!(*count.lock().unwrap(), 1);
        subscription.unsubscribe();
        store.refresh().await;
        assert_eq!(*count.lock().unwrap(), 1);
        assert_eq!(store.get_snapshot().status, SessionStatus::Authenticated);
        store.sign_out().await.unwrap();
        assert_eq!(store.get_snapshot().status, SessionStatus::Unauthenticated);
        assert!(
            backend
                .calls
                .lock()
                .unwrap()
                .contains(&"auth/signOut".to_owned())
        );
    });
}

#[test]
fn recognizes_unauthenticated_errors_from_the_client_and_the_server() {
    let refused = |status: u16| Error::from(IamClientError::new("X", "x", status));
    assert!(is_unauthenticated(&refused(401)));
    assert!(is_unauthenticated(&refused(403)));
    assert!(!is_unauthenticated(&refused(500)));
    assert!(!is_unauthenticated(&refused(0)));
    assert!(is_unauthenticated(&IamClientError::new("X", "x", 401)));
    assert!(is_unauthenticated(&better_iam_core::IamError::with_status(
        "UNAUTHENTICATED",
        "Sign in",
        401
    )));
    assert!(!is_unauthenticated(&better_iam_core::IamError::new(
        "INVALID_INPUT",
        "bad"
    )));
    assert!(!is_unauthenticated(&FetchError("offline".into())));
    assert!(!is_unauthenticated(&Error::Fetch(Arc::new(FetchError(
        "offline".into()
    )))));
}

#[test]
fn keeps_the_session_of_a_real_server_and_clears_it_on_sign_out() {
    organization_fixture::run(|| async {
        let f = organization_fixture::organization(|_| {}).await;
        let alice = f.member("alice").await;
        let credential = f.sign_in(&alice).await;
        let client = create_iam_client(
            ClientOptions::new("http://localhost:3000")
                .token(credential.token.clone().unwrap())
                .fetch(server_fetch(f.iam.http.clone())),
        )
        .unwrap();
        let store = create_session_store(client.clone(), SessionStoreOptions::default());
        let snapshot = store.refresh().await;
        assert_eq!(snapshot.status, SessionStatus::Authenticated);
        assert_eq!(snapshot.session.unwrap().identity.id, alice);
        store.sign_out().await.unwrap();
        assert_eq!(store.get_snapshot().status, SessionStatus::Unauthenticated);
        // The token was revoked on the server, so the next refresh is signed out with the server's error.
        let snapshot = store.refresh().await;
        assert_eq!(snapshot.status, SessionStatus::Unauthenticated);
        assert_eq!(snapshot.error.unwrap().status(), Some(401));
    });
}
