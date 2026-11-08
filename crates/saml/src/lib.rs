//! `better-iam-saml`: SAML 2.0 single sign-on for Better IAM, the counterpart of the `@better-iam/saml` npm package.
//! Tenant-managed service-provider connections for Okta, Entra ID, ADFS, Google Workspace and more, beside
//! connections fixed in configuration.
//!
//! XML parsing, exclusive and inclusive canonicalization, XML signature verification and creation, and XML decryption
//! are implemented here in Rust (no libxml2, no xmlsec), following the libraries the TypeScript implementation uses
//! (`@xmldom/xmldom`, `xml-crypto`, `xml-encryption`, `@node-saml/node-saml`) so both implementations accept and
//! refuse the same responses. Identities are only ever read from the canonical bytes a verified signature covers,
//! which defeats signature wrapping and comment injection.

pub mod c14n;
pub mod dsig;
pub mod keys;
pub mod metadata;
pub mod node_saml;
#[cfg(feature = "server")]
mod server;
pub mod service;
pub mod xml;
pub mod xml2js;
pub mod xmlenc;

pub use keys::{SamlError, SamlResult};
pub use metadata::{
    CertificateInfo, IdpMetadata, certificate_info, normalize_certificate, parse_idp_metadata,
};
pub use node_saml::{AssertionXml, CacheProvider, Profile};
pub use service::{
    AssertTrustChangeFn, AuthenticateFn, AuthorizeFn, BeginResult, BoxFuture, CallbackInput,
    CompleteAuthenticationFn, MapAttributes, RevokeSessionFn, SamlCache, SamlConfigOptions,
    SamlConnection, SamlService, SamlServiceProvider, create_saml_cache, create_saml_service,
    validate_saml_envelope,
};
