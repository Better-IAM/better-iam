//! The Better IAM server for Rust, the counterpart of the `@better-iam/server` npm package.
//!
//! Every module mirrors the TypeScript module of the same name in `packages/server/src` (`catalog.ts` →
//! [`catalog`], `events.ts` → [`events`], `api/roles.ts` → [`api::roles`], ...), so a change in one implementation is
//! easy to find in the other. The TypeScript source is the specification: validation order, error codes and messages,
//! defaults, record shapes and audit event names are the same, so TypeScript and Rust servers can share one database.
//!
//! [`index::better_iam`] composes the server (the TypeScript `betterIam(options)`): configuration and catalog
//! validation, the authentication service, the shared [`context::ServerContext`], the decision engine
//! ([`decisions`]), the transactional authorization envelope ([`operations`]), credential resolution
//! ([`principals`]), the provisioning API ([`api`]), deployment operations ([`lifecycle`]) and the HTTP handler
//! ([`http`]). Modules not ported yet are skeletons whose items return `NOT_IMPLEMENTED` (501); see crates/PORTING.md.
//! Rust-only modules: [`contracts`] (service traits), [`conformance`] (the standalone server's test-control
//! endpoints), [`js`], [`options_value`], [`port`], [`standalone_config`], [`timezones`].

pub mod a2a;
pub mod access_policy;
pub mod agents;
pub mod agreements;
pub mod ai_sync;
pub mod api;
pub mod applications;
pub mod assertions;
pub mod audit_archive;
pub mod billing;
pub mod billing_invoices;
pub mod billing_plans;
pub mod billing_service;
pub mod catalog;
pub mod certification_worker;
pub mod clearances;
pub mod client_info;
pub mod compliance;
pub mod conformance;
pub mod context;
pub mod context_keys;
pub mod contracts;
pub mod decisions;
pub mod define;
pub mod delegation_tokens;
pub mod delegations;
pub mod departments;
pub mod devices;
pub mod events;
pub mod features;
pub mod federation;
pub mod flows;
pub mod grant_deadline;
pub mod guarded;
pub mod guests;
pub mod hosts;
pub mod http;
pub mod index;
pub mod inference;
pub mod inference_gateway;
pub mod invariants;
pub mod js;
pub mod kms;
pub mod ldap;
pub mod licenses;
pub mod lifecycle;
pub mod metrics;
pub mod models;
pub mod observe;
pub mod onboarding;
pub mod operations;
pub mod options;
pub mod options_value;
pub mod org_insights;
pub mod org_rules;
pub mod org_sync;
pub mod package_rules;
pub mod pki;
pub mod plugins;
pub mod policy_lint;
pub mod port;
pub mod principals;
pub mod privacy;
pub mod quotas;
pub mod retention;
pub mod safe_fetch;
pub mod sd_jwt;
pub mod secrets;
pub mod self_check;
pub mod session_kinds;
pub mod session_tokens;
pub mod signal_receiver;
pub mod sod;
pub mod ssh;
pub mod ssh_ca;
pub mod standalone_config;
pub mod sync;
pub mod team_reviews;
pub mod teams;
pub mod temporary_credentials;
pub mod tenant_policy;
pub mod threat_engine;
pub mod threat_response;
pub mod threat_rules;
pub mod threats;
pub mod timezones;
pub mod token_signing;
pub mod tokenization;
pub mod usage;
pub mod utils;
pub mod validation;
pub mod vault;
pub mod vc;
pub mod web_identity;
pub mod web_identity_exchange;
pub mod workflows;
pub mod x509;

pub use better_iam_core::{IamError, IamResult};
pub use index::{BetterIam, better_iam};
