//! The authentication service (`service/*.ts` and `index.ts`).
//!
//! The TypeScript service is a class chain (`AuthBase` → `SessionAuth` → `AccountAuth` → `PasswordlessAuth` →
//! `MfaAuth` → `PasskeyAuth`, exported as `AuthService`). Here it is one [`AuthService`] whose methods are defined in
//! the module of their TypeScript class: [`base`], [`sessions`], [`account`], [`passwordless`], [`mfa`] and
//! [`passkeys`].
//!
//! Methods the HTTP layer exposes take the request body as JSON (`&Value`) and validate it exactly as the TypeScript
//! methods validate their untrusted input; internal helpers for trusted server integrations take typed arguments.

pub mod account;
pub mod base;
pub mod mfa;
pub mod passkeys;
pub mod passwordless;
pub mod sessions;

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use better_iam_core::IamResult;
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;

use crate::outbox::OutboxContext;
use crate::rate_limit::ResolvedRateLimits;
use crate::types::{AuthOptions, NetworkBlock, NowFn};

pub use base::{
    CreateIdentityInput, CreateIdentityRaw, IssueSessionOptions, LimitAttemptOptions, RateTier,
    RequestHost, ResetRateLimitsResult, SessionLimits,
};

/// The configuration and process-local state behind an [`AuthService`].
pub struct AuthState {
    pub options: AuthOptions,
    pub(crate) now: NowFn,
    pub(crate) origins: Vec<String>,
    pub(crate) session_lifetime: f64,
    pub(crate) idle_lifetime: f64,
    pub(crate) cookie_name: String,
    pub(crate) recent_lifetime: f64,
    /// Deployment ceiling for "remember this device"; 0 disables it everywhere.
    pub(crate) device_lifetime: f64,
    /// Failed attempts since the last sign-in at which one `sign-in-failures` email goes out; 0 disables it.
    pub(crate) failed_alert_threshold: f64,
    pub(crate) app_name: String,
    pub(crate) require_email_verification: bool,
    pub(crate) dummy_password_hash: OnceCell<String>,
    pub(crate) limits: ResolvedRateLimits,
    pub(crate) outbox: OutboxContext,
    /// The `AsyncLocalStorage` holding the client of sessions issued inside `with_client`.
    pub(crate) client_scope: usize,
    /// The `AsyncLocalStorage` holding the address of the current request (`with_request_host`).
    pub(crate) host_scope: usize,
    /// Network block lists per tenant (own plus platform-wide), reused for a few seconds.
    pub(crate) block_cache: Mutex<HashMap<String, (f64, Vec<NetworkBlock>)>>,
    /// Failed-attempt bookkeeping still being written after its refusal was answered.
    pub(crate) bookkeeping: Mutex<Vec<JoinHandle<()>>>,
    /// The current secret first, then the ones being rotated out (`previousSecrets`).
    pub secrets: Vec<String>,
}

/// Authentication services (`AuthService`). Cheap to clone: clones share one state. Low-level transaction helpers
/// are for trusted server integrations only.
#[derive(Clone)]
pub struct AuthService {
    pub(crate) state: Arc<AuthState>,
}

impl Deref for AuthService {
    type Target = AuthState;
    fn deref(&self) -> &AuthState {
        &self.state
    }
}

/// `createAuth(options)`.
pub fn create_auth(options: AuthOptions) -> IamResult<AuthService> {
    AuthService::new(options)
}
