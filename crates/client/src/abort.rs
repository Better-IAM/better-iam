//! Per-call cancellation, the Rust form of `AbortController` / `AbortSignal`.
//!
//! Dropping a call's future also cancels it; a signal additionally lets one place cancel calls it does not own, and
//! settles the call at once with the signal's reason (`ClientCallOptions.signal` in the TypeScript client).

use std::fmt;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

/// The reason a signal carries: any error, [`AbortError`] when [`AbortController::abort`] was called without one.
pub type AbortReason = Arc<dyn std::error::Error + Send + Sync>;

/// The standard rejection of an aborted call without a reason (`DOMException` named `AbortError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AbortError;

impl AbortError {
    /// The error's name, `AbortError`.
    pub const NAME: &'static str = "AbortError";

    /// `AbortError`.
    pub fn name(&self) -> &'static str {
        Self::NAME
    }
}

impl fmt::Display for AbortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("This operation was aborted")
    }
}

impl std::error::Error for AbortError {}

struct SignalState {
    reason: Mutex<Option<AbortReason>>,
    aborted: watch::Sender<bool>,
}

/// Observes whether its controller aborted, and why. Clones observe the same controller.
#[derive(Clone)]
pub struct AbortSignal {
    state: Arc<SignalState>,
}

impl AbortSignal {
    fn new() -> Self {
        let (aborted, _) = watch::channel(false);
        Self {
            state: Arc::new(SignalState {
                reason: Mutex::new(None),
                aborted,
            }),
        }
    }

    /// A signal that is already aborted with `reason` (`AbortSignal.abort(reason)`).
    pub fn aborted_with(reason: AbortReason) -> Self {
        let signal = Self::new();
        signal.abort(Some(reason));
        signal
    }

    /// Whether the controller aborted.
    pub fn aborted(&self) -> bool {
        *self.state.aborted.borrow()
    }

    /// The abort reason, once aborted.
    pub fn reason(&self) -> Option<AbortReason> {
        self.state
            .reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Resolves with the reason once the signal is aborted (at once when it already is).
    pub async fn cancelled(&self) -> AbortReason {
        let mut receiver = self.state.aborted.subscribe();
        // The sender lives in `self`, so the channel stays open while this future runs.
        let _ = receiver.wait_for(|aborted| *aborted).await;
        self.reason().unwrap_or_else(|| Arc::new(AbortError))
    }

    /// Whether two signals observe the same controller.
    pub fn same(&self, other: &AbortSignal) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    fn abort(&self, reason: Option<AbortReason>) {
        {
            let mut current = self
                .state
                .reason
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Only the first abort counts, as in the DOM.
            if current.is_some() {
                return;
            }
            *current = Some(reason.unwrap_or_else(|| Arc::new(AbortError)));
        }
        self.state.aborted.send_replace(true);
    }
}

impl fmt::Debug for AbortSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbortSignal")
            .field("aborted", &self.aborted())
            .finish()
    }
}

/// Aborts the calls that carry its [`signal`](AbortController::signal).
#[derive(Clone, Debug)]
pub struct AbortController {
    signal: AbortSignal,
}

impl Default for AbortController {
    fn default() -> Self {
        Self::new()
    }
}

impl AbortController {
    pub fn new() -> Self {
        Self {
            signal: AbortSignal::new(),
        }
    }

    /// The signal to pass to calls.
    pub fn signal(&self) -> AbortSignal {
        self.signal.clone()
    }

    /// Aborts with the standard [`AbortError`].
    pub fn abort(&self) {
        self.signal.abort(None);
    }

    /// Aborts with `reason`; calls waiting on the signal reject with exactly this value.
    pub fn abort_with(&self, reason: AbortReason) {
        self.signal.abort(Some(reason));
    }
}
