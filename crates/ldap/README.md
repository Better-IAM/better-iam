# better-iam-ldap

A read-only LDAPv3 directory gateway over [Better IAM](https://github.com/Better-IAM/better-iam) for Rust, the
counterpart of the `@better-iam/ldap` npm package. Applications that only speak LDAP (VPNs, NAS devices, CI servers,
wikis, printers) bind as a person (password, plus the current one-time code when the organization requires MFA) or as
a service account (an API key as the password), then search the people, groups and service accounts of the
organization whose base DN they use. Writes are refused.

```rust,ignore
use std::sync::Arc;
use better_iam_ldap::{LdapServerOptions, ServerLdapIam, create_ldap_server};

let gateway = create_ldap_server(LdapServerOptions::new(Arc::new(ServerLdapIam::new(&iam)?)));
let address = gateway.listen(Some(389), Some("0.0.0.0")).await?;
```

The `server` feature provides `ServerLdapIam`, the `LdapIam` view of a `better_iam_server::BetterIam` instance. The BER
codec, DN and filter helpers and the client-side message encoders are exported for tools and tests.
