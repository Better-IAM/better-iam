//! The temporary-credential suites (one test binary): `tests/sts-config.test.ts`, `tests/http-session-tokens.test.ts`,
//! `tests/jwt-session-tokens.test.ts`, `tests/sts-session-token.test.ts`, `tests/sts-end-to-end.test.ts`, the
//! session-token parts of `tests/sts-hardening.test.ts`, and the exchange parts of `tests/web-identity.test.ts`.
//!
//! A call that reaches a stub of another unit (`NOT_IMPLEMENTED`) skips the rest of its test: `ok!` unwraps a result
//! that must succeed, `fails!` the error of one that must fail.

/// Unwraps a result that must succeed; a `NOT_IMPLEMENTED` stub of another unit skips the rest of the test.
macro_rules! ok {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) if error.code == "NOT_IMPLEMENTED" => {
                eprintln!("skipped (not ported yet): {}", error.message);
                return;
            }
            Err(error) => panic!(
                "{} failed: {} {} ({})",
                stringify!($result),
                error.code,
                error.message,
                error.status
            ),
        }
    };
}

/// The error of a result that must fail; a `NOT_IMPLEMENTED` stub of another unit skips the rest of the test.
macro_rules! fails {
    ($result:expr) => {
        match $result {
            Ok(_) => panic!("{} should fail", stringify!($result)),
            Err(error) if error.code == "NOT_IMPLEMENTED" => {
                eprintln!("skipped (not ported yet): {}", error.message);
                return;
            }
            Err(error) => error,
        }
    };
}

/// `iam.api.<group>.<method>(credential, input)` as JSON.
macro_rules! api {
    ($group:expr, $method:ident, $credential:expr, $input:expr) => {
        $crate::support::json(
            $group
                .$method($credential, $crate::support::body($input))
                .await,
        )
    };
}

/// Skips the rest of a test when an HTTP answer names a stub of another unit.
macro_rules! reached {
    ($response:expr) => {
        ok!($crate::support::unported(&$response))
    };
}

mod jwt_keys;
#[path = "sts_support/mod.rs"]
mod support;

#[path = "sts_parts/config.rs"]
mod config;
#[path = "sts_parts/end_to_end.rs"]
mod end_to_end;
#[path = "sts_parts/hardening.rs"]
mod hardening;
#[path = "sts_parts/http_session_tokens.rs"]
mod http_session_tokens;
#[path = "sts_parts/jwt_session_tokens.rs"]
mod jwt_session_tokens;
#[path = "sts_parts/session_token.rs"]
mod session_token;
#[path = "sts_parts/web_identity.rs"]
mod web_identity;
