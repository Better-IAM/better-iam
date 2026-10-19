//! Tenant-scoped authentication for Better IAM (Rust), the counterpart of `@better-iam/auth`: passwords, passkeys,
//! magic links, email and SMS codes, TOTP with recovery codes, remembered devices, and sessions.
//!
//! Every stored record, token, hash, and sealed value is byte-compatible with the TypeScript implementation, so
//! TypeScript and Rust servers can serve one deployment from one database: sessions issued by either validate on
//! the other, password hashes (argon2id) verify on both, and sealed outbox payloads and authenticator secrets open on
//! both.
//!
//! Module and function names mirror the TypeScript sources (`service/sessions.ts` → [`service::sessions`],
//! `signIn` → [`AuthService::sign_in`]). The TypeScript class chain (`AuthBase` → `SessionAuth` → `AccountAuth`
//! → `PasswordlessAuth` → `MfaAuth` → `PasskeyAuth`) is one [`AuthService`] whose methods live in the module of
//! their TypeScript class.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod js_date;
pub mod outbox;
pub mod password_policy;
pub mod passwords;
pub mod rate_limit;
pub mod safe_fetch;
pub mod service;
pub mod templates;
pub mod totp;
pub mod types;
pub mod util;
pub mod validation;
pub mod webauthn;

pub use crypto::{
    CREDENTIAL_TOKEN_KINDS, CREDENTIAL_TOKEN_SCAN_PATTERN, CredentialTokenType, decrypt_secret,
    encrypt_secret, hash_token, new_credential_token, new_credential_token_named, new_id,
    new_token, open_secret, parse_credential_token,
};
pub use outbox::DispatchResult;
pub use password_policy::{
    PasswordCheckContext, PasswordIdentity, PasswordPolicyOptions, PwnedPasswordsOptions,
    character_classes, is_common_password, pwned_passwords,
};
pub use rate_limit::{
    MemoryRateLimiterOptions, create_memory_rate_limiter, create_store_rate_limiter,
};
pub use safe_fetch::{
    GuardedFetch, GuardedFetchOptions, SafeFetchAddressOptions, SafeFetchError,
    SafeFetchFailureReason, SafeFetchOptions, check_fetch_url, create_guarded_fetch,
    fetch_json_safely, is_public_address,
};
pub use service::{AuthService, RequestHost, create_auth};
pub use templates::{
    RenderedMessage, TemplateLinks, TemplateOptions, describe_user_agent, render_delivery_message,
};
pub use types::*;
