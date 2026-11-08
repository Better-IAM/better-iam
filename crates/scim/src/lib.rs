//! SCIM 2.0 provisioning for Better IAM (Rust), the counterpart of the `@better-iam/scim` npm package: connection-
//! scoped Users and Groups endpoints with RFC 7643/7644 filters, PATCH, Bulk, and ETags ([`ScimService`]), the JSON
//! administration API for connections, and outbound provisioning to downstream SCIM services ([`ScimProvisioner`]).
//!
//! The crate mirrors `packages/scim/src` module for module and shares its records (`scimConnections`, `scimUsers`,
//! `scimGroups`, `provisioningTargets`, `provisioningLinks`, `provisioningGroupLinks`) and audit events with the
//! TypeScript implementation. With the `server` feature (default), [`host`] builds both configurations from a Better
//! IAM server's protocol host and mounts both services on its handler.

pub mod attributes;
pub mod filter;
#[cfg(feature = "server")]
pub mod host;
pub mod js;
pub mod outbound;
pub mod patch;
pub mod provisioning;
pub mod resources;
pub mod service;
pub mod types;
pub mod validation;

pub use filter::{FilterNode, parse_filter_expression, parse_scim_filter};
pub use outbound::{
    EventHandler, EventSource, GuardedTransport, ProvisioningConfig, ProvisioningEvent,
    ScimProvisioner, ScimTransport, SubscribeOptions, TransportError, TransportRequest,
    TransportResponse, Unsubscribe, create_scim_provisioner,
};
pub use resources::HttpResponse;
pub use service::{HttpRequest, ScimService, create_scim_service};
pub use types::*;
