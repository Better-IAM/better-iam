//! Keeping futures off the stack.
//!
//! An unoptimized (debug) build gives every `async fn`'s poll function a stack frame with room for each future it
//! creates and awaits, with no reuse between them, and polling nests one such frame per `.await` level. Large request
//! futures therefore need far more stack in debug builds than the 1 MiB of a Windows main thread or the 2 MiB of a
//! tokio or actix-web worker. [`boxed`] builds a future in its own short-lived frame and moves it to the heap, so the
//! caller's frame and future hold only a pointer: use it where a large future is awaited, and at public entry points.

use futures::future::BoxFuture;
use std::future::Future;

/// Creates the future `make` returns inside this function's frame and returns it boxed: unlike `Box::pin(f())`
/// written inside an `async fn`, the future's bytes never occupy the awaiting function's frame.
#[inline(never)]
pub fn boxed<'a, F, Fut>(make: F) -> BoxFuture<'a, Fut::Output>
where
    F: FnOnce() -> Fut,
    Fut: Future + Send + 'a,
{
    Box::pin(make())
}
