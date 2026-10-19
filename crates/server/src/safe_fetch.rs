//! Port of `packages/server/src/safe-fetch.ts`: the SSRF guard for URLs that tenants control lives in
//! `better-iam-auth` (shared with the SCIM and OAuth packages); this module keeps the server's import path.

pub use better_iam_auth::safe_fetch::{
    FetchBody, FetchError, FetchRequest, FetchResponse, GuardedFetch, GuardedFetchOptions,
    RedirectMode, SafeFetchAddressOptions, SafeFetchError, SafeFetchFailureReason,
    SafeFetchOptions, check_fetch_url, create_guarded_fetch, fetch_json_safely, is_public_address,
};
