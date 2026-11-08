//! OAuth 2.0 and OpenID Connect for Better IAM: federated sign-in (`create_oauth_login`), a tenant-aware
//! authorization server (`create_oauth_provider`), resource-server token verification, and an OpenID Shared Signals
//! transmitter. The port of `@better-iam/oauth`.

pub mod adapter;
pub mod errors;
pub mod jose;

pub use adapter::*;
pub use errors::*;
pub mod resource_server;
pub mod ssf;

pub use resource_server::*;
pub use ssf::*;
pub mod client;
pub use client::*;
pub mod provider;
pub use provider::*;
