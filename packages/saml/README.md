# @better-iam/saml

Tenant-specific SAML service-provider connections for Better IAM, backed by Node-SAML.

`createSamlService` supplies signed metadata, SP-initiated login, signed/encrypted assertion validation, certificate rollover, persistent replay checks, and explicit account linking. Each connection has a fixed tenant, IdP issuer, SP audience and callback URL. Connections come from deployment configuration or are managed per tenant at runtime (`createConnection`, `updateConnection`, …) with IdP metadata import (`parseIdpMetadata`) and certificate expiry reporting. IdP-initiated login is opt-in per connection (`allowIdpInitiated`, single-use assertions); SAML IdP operation and federated logout are not provided.

Use `better-iam/saml` from the umbrella installation or install this package directly. Configure trusted server callbacks and keys, then mount with `iam.useProtocol`.

See the repository's `docs/protocols.md` for configuration, email trust and protocol limits.

License: Apache-2.0.
