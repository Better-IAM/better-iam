//! `better-iam-ldap`: a read-only LDAPv3 directory gateway over Better IAM, the counterpart of the `@better-iam/ldap`
//! npm package, so applications that only speak LDAP (VPNs, NAS devices, CI servers, wikis, printers) can look up
//! people and groups and check passwords. Start it with [`create_ldap_server`]; each organization publishes its
//! directory under its own base DN (`ldap.updateSettings`). The BER codec, DN and filter helpers and message encoders
//! are exported for tools and tests.
//!
//! The gateway reaches Better IAM through the [`LdapIam`] trait; with the `server` feature, [`ServerLdapIam`]
//! implements it for a `better_iam_server::BetterIam` instance.

pub mod ber;
pub mod directory;
pub mod dn;
pub mod filter;
pub mod protocol;
pub mod server;
#[cfg(feature = "server")]
mod server_iam;

pub use ber::{BerError, read_element};
pub use directory::{DirectoryData, DirectoryEntry, build_entries, select_attributes};
pub use dn::{
    DnError, Rdn, depth_below, escape_dn_value, format_dn, is_under, normalize_dn, parent_dn,
    parse_dn,
};
pub use filter::{
    EntryAttributes, Filter, decode_filter, encode_filter, match_filter, parse_filter,
};
pub use protocol::{
    LdapControl, LdapMessage, LdapRequest, LdapResponse, SearchOptions, SearchScope,
    decode_message, decode_response, encode_bind, encode_compare, encode_extended, encode_search,
    encode_unbind, oid, paged_results_request, result_code,
};
pub use server::{
    BindKind, BindName, ClientInfo, LdapError, LdapIam, LdapPrincipal, LdapServer,
    LdapServerOptions, LdapTenant, create_ldap_server,
};
#[cfg(feature = "server")]
pub use server_iam::ServerLdapIam;
