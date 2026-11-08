# better-iam-saml

SAML 2.0 single sign-on for [Better IAM](https://github.com/Better-IAM/better-iam) in Rust, the counterpart of the
`@better-iam/saml` npm package: tenant-managed service-provider connections (Okta, Entra ID, ADFS, Google Workspace,
...) beside connections fixed in configuration, IdP metadata import, certificate rollover, IdP-initiated sign-in with
single-use assertions, encrypted assertions, and signed SP metadata.

XML parsing, canonicalization (exclusive and inclusive), XML signatures and XML decryption are implemented in Rust
without libxml2 or xmlsec, following the libraries of the TypeScript implementation so both accept and refuse the same
responses. Identities are read only from the canonical bytes a verified signature covers, which defeats signature
wrapping and comment injection.

```rust,ignore
use std::sync::Arc;
use better_iam_saml::{SamlConfigOptions, SamlServiceProvider, create_saml_service};

let mut options = SamlConfigOptions::from_protocol_host(&iam)?; // the `server` feature
options.service_provider = Some(SamlServiceProvider {
    base_url: "https://id.example.com".into(),
    private_key,
    public_certificate,
    ..Default::default()
});
let saml = create_saml_service(options)?;
iam.use_protocol(Arc::new(saml.clone()));
```
