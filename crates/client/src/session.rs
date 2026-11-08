//! Framework-agnostic session state (`@better-iam/client/session`): the current identity and session, a status,
//! the last error, and change notifications. UI bindings subscribe to it; it can also drive plain programs.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use futures::FutureExt;
use futures::future::{BoxFuture, Shared};

use crate::{IamClient, IamClientError};

/// The minimum client surface the session store needs; [`IamClient`] provides it.
pub trait SessionClient: Send + Sync + 'static {
    /// What `auth.getSession` answers.
    type Session: Clone + Send + Sync + 'static;
    type Error: std::error::Error + Send + Sync + 'static;
    fn get_session(&self) -> BoxFuture<'static, Result<Self::Session, Self::Error>>;
    fn sign_out(&self) -> BoxFuture<'static, Result<(), Self::Error>>;
}

impl SessionClient for IamClient {
    type Session = better_iam_types::api::auth::GetSessionOutput;
    type Error = crate::Error;

    fn get_session(&self) -> BoxFuture<'static, Result<Self::Session, Self::Error>> {
        Box::pin(self.auth().get_session().send())
    }

    fn sign_out(&self) -> BoxFuture<'static, Result<(), Self::Error>> {
        let call = self.auth().sign_out();
        Box::pin(async move { call.send().await.map(|_| ()) })
    }
}

/// `SessionStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionStatus {
    Loading,
    Authenticated,
    Unauthenticated,
    Error,
}

impl SessionStatus {
    /// The TypeScript value (`'loading'`, `'authenticated'`, `'unauthenticated'`, `'error'`).
    pub fn as_str(self) -> &'static str {
        match self {
            SessionStatus::Loading => "loading",
            SessionStatus::Authenticated => "authenticated",
            SessionStatus::Unauthenticated => "unauthenticated",
            SessionStatus::Error => "error",
        }
    }
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `SessionSnapshot`.
pub struct SessionSnapshot<Session, E> {
    pub status: SessionStatus,
    /// The current identity and session, or `None` when signed out.
    pub session: Option<Session>,
    /// The last transport or authentication error. Unauthenticated states keep the server's error so its code can
    /// be shown.
    pub error: Option<Arc<E>>,
    /// When the snapshot was taken (`Date.now()`), 0 while loading the first time.
    pub updated_at: f64,
}

impl<Session: Clone, E> Clone for SessionSnapshot<Session, E> {
    fn clone(&self) -> Self {
        Self {
            status: self.status,
            session: self.session.clone(),
            error: self.error.clone(),
            updated_at: self.updated_at,
        }
    }
}

impl<Session: fmt::Debug, E: fmt::Debug> fmt::Debug for SessionSnapshot<Session, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSnapshot")
            .field("status", &self.status)
            .field("session", &self.session)
            .field("error", &self.error)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// The snapshot type of a store over client `C`.
pub type SnapshotOf<C> =
    SessionSnapshot<<C as SessionClient>::Session, <C as SessionClient>::Error>;

/// `isUnauthenticated`: the server answers 401 or 403 for missing, expired, or step-up-required credentials;
/// anything else is a transport failure. Accepts the client's errors and, for server-side callers that call the
/// server in process, its `IamError`.
pub fn is_unauthenticated(error: &(dyn std::error::Error + 'static)) -> bool {
    let unauthenticated = |status: u16| status == 401 || status == 403;
    if let Some(error) = error.downcast_ref::<crate::Error>() {
        return error.status().is_some_and(unauthenticated);
    }
    if let Some(error) = error.downcast_ref::<IamClientError>() {
        return unauthenticated(error.status);
    }
    if let Some(error) = error.downcast_ref::<better_iam_core::IamError>() {
        return unauthenticated(error.status);
    }
    false
}

/// `Date.now()`.
fn date_now() -> f64 {
    better_iam_core::js::now_ms()
}

/// A change listener.
pub type Listener = Arc<dyn Fn() + Send + Sync>;

type Inflight<C> = Shared<BoxFuture<'static, SnapshotOf<C>>>;

struct State<C: SessionClient> {
    snapshot: SnapshotOf<C>,
    listeners: Vec<Listener>,
    inflight: Option<Inflight<C>>,
}

struct Inner<C: SessionClient> {
    client: C,
    state: Mutex<State<C>>,
}

impl<C: SessionClient> Inner<C> {
    fn state(&self) -> MutexGuard<'_, State<C>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn publish(&self, next: SnapshotOf<C>) {
        let listeners = {
            let mut state = self.state();
            state.snapshot = next;
            state.listeners.clone()
        };
        for listener in listeners {
            listener();
        }
    }
}

/// `SessionStore`: the session of one client. Clones share the same state.
pub struct SessionStore<C: SessionClient> {
    inner: Arc<Inner<C>>,
}

impl<C: SessionClient> Clone for SessionStore<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Stops a listener (the function `subscribe` returns).
#[must_use = "dropping the subscription keeps the listener subscribed; call unsubscribe() to stop it"]
pub struct Subscription<C: SessionClient> {
    store: SessionStore<C>,
    listener: Listener,
}

impl<C: SessionClient> Subscription<C> {
    pub fn unsubscribe(self) {
        self.store
            .inner
            .state()
            .listeners
            .retain(|listener| !Arc::ptr_eq(listener, &self.listener));
    }
}

/// The options of [`create_session_store`].
pub struct SessionStoreOptions<Session> {
    /// The session the page already knows: `None` starts `loading`, `Some(None)` signed out, `Some(Some(session))`
    /// signed in.
    pub initial: Option<Option<Session>>,
}

impl<Session> Default for SessionStoreOptions<Session> {
    fn default() -> Self {
        Self { initial: None }
    }
}

/// `createSessionStore(client, options)`.
pub fn create_session_store<C: SessionClient>(
    client: C,
    options: SessionStoreOptions<C::Session>,
) -> SessionStore<C> {
    let snapshot = match options.initial {
        None => SessionSnapshot {
            status: SessionStatus::Loading,
            session: None,
            error: None,
            updated_at: 0.0,
        },
        Some(initial) => SessionSnapshot {
            status: if initial.is_none() {
                SessionStatus::Unauthenticated
            } else {
                SessionStatus::Authenticated
            },
            session: initial,
            error: None,
            updated_at: date_now(),
        },
    };
    SessionStore {
        inner: Arc::new(Inner {
            client,
            state: Mutex::new(State {
                snapshot,
                listeners: Vec::new(),
                inflight: None,
            }),
        }),
    }
}

impl<C: SessionClient> SessionStore<C> {
    pub fn get_snapshot(&self) -> SnapshotOf<C> {
        self.inner.state().snapshot.clone()
    }

    /// Calls `listener` after every change. Subscribing the same listener twice keeps one subscription.
    pub fn subscribe(&self, listener: Listener) -> Subscription<C> {
        {
            let mut state = self.inner.state();
            if !state
                .listeners
                .iter()
                .any(|existing| Arc::ptr_eq(existing, &listener))
            {
                state.listeners.push(listener.clone());
            }
        }
        Subscription {
            store: self.clone(),
            listener,
        }
    }

    /// Reloads the session from the server. Concurrent calls share one request.
    pub async fn refresh(&self) -> SnapshotOf<C> {
        let pending = {
            let mut state = self.inner.state();
            match &state.inflight {
                Some(pending) => pending.clone(),
                None => {
                    let inner = self.inner.clone();
                    let pending = async move {
                        let next = match inner.client.get_session().await {
                            Ok(session) => SessionSnapshot {
                                status: SessionStatus::Authenticated,
                                session: Some(session),
                                error: None,
                                updated_at: date_now(),
                            },
                            Err(error) => {
                                let unauthenticated = is_unauthenticated(&error);
                                let current = inner.state().snapshot.session.clone();
                                SessionSnapshot {
                                    status: if unauthenticated {
                                        SessionStatus::Unauthenticated
                                    } else {
                                        SessionStatus::Error
                                    },
                                    session: if unauthenticated { None } else { current },
                                    error: Some(Arc::new(error)),
                                    updated_at: date_now(),
                                }
                            }
                        };
                        inner.publish(next);
                        let mut state = inner.state();
                        state.inflight = None;
                        state.snapshot.clone()
                    }
                    .boxed()
                    .shared();
                    state.inflight = Some(pending.clone());
                    pending
                }
            }
        };
        pending.await
    }

    /// Signs out on the server, then clears the local session even if the server call failed.
    pub async fn sign_out(&self) -> Result<(), C::Error> {
        let result = self.inner.client.sign_out().await;
        self.inner.publish(SessionSnapshot {
            status: SessionStatus::Unauthenticated,
            session: None,
            error: None,
            updated_at: date_now(),
        });
        result
    }

    /// Replaces the local session, for example right after a sign-in response.
    pub fn set(&self, session: Option<C::Session>) {
        self.inner.publish(SessionSnapshot {
            status: if session.is_none() {
                SessionStatus::Unauthenticated
            } else {
                SessionStatus::Authenticated
            },
            session,
            error: None,
            updated_at: date_now(),
        });
    }
}
