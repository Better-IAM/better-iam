//! Values scoped to the current asynchronous call chain (Rust-only module), the counterpart of Node's
//! `AsyncLocalStorage` that the TypeScript adapters use to route calls on the root store into the transaction that
//! the same call chain opened.
//!
//! A scope is entered with [`run`]; inside the future (and every future it awaits on the same task) [`current`]
//! finds the value. Futures spawned onto other tasks with `tokio::spawn` do not inherit the scope, which matches how
//! a detached callback in Node would lose it when run outside the async context.

use std::any::Any;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

type Entry = (usize, Arc<dyn Any + Send + Sync>);

#[derive(Clone, Default)]
struct Scopes(Arc<Vec<Entry>>);

tokio::task_local! {
    static SCOPES: Scopes;
}

static NEXT_KEY: AtomicUsize = AtomicUsize::new(1);

/// A fresh scope key, the identity of one `AsyncLocalStorage` instance.
pub fn new_key() -> usize {
    NEXT_KEY.fetch_add(1, Ordering::Relaxed)
}

/// The innermost value stored under `key` in the current call chain.
pub fn current<T: Send + Sync + 'static>(key: usize) -> Option<Arc<T>> {
    SCOPES
        .try_with(|scopes| {
            scopes
                .0
                .iter()
                .rev()
                .find(|(entry, _)| *entry == key)
                .and_then(|(_, value)| value.clone().downcast::<T>().ok())
        })
        .ok()
        .flatten()
}

/// Runs `future` with `value` stored under `key` (`storage.run(value, fn)`).
pub async fn run<T, F>(key: usize, value: Arc<T>, future: F) -> F::Output
where
    T: Send + Sync + 'static,
    F: Future,
{
    let mut entries: Vec<Entry> = SCOPES
        .try_with(|scopes| scopes.0.as_ref().clone())
        .unwrap_or_default();
    entries.push((key, value));
    SCOPES.scope(Scopes(Arc::new(entries)), future).await
}
