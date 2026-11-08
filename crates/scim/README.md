# better-iam-scim

SCIM 2.0 provisioning for [Better IAM](https://github.com/Better-IAM/better-iam) in Rust, the counterpart of the
`@better-iam/scim` npm package. It shares its records and audit events with the TypeScript implementation, so
TypeScript and Rust servers can serve one deployment from one database.

- **Inbound** (`ScimService`, `createScimService`): connection-scoped bearer tokens; `Users` and `Groups` with RFC
  7644 filters, sorting, attribute projection, `/.search`, PATCH value paths (Entra ID and Okta conventions), `/Bulk`
  with `bulkId` references, ETags and pagination; the enterprise User extension with manager mapping; lenient or
  strict handling of attributes the service does not store; administrator-controlled group-to-role mappings and the
  JSON administration API for connections (`{adminBasePath}/connections/{list,create,rotate,revoke,groups,mappings}`).
- **Outbound** (`ScimProvisioner`, `createScimProvisioner`): keeps downstream SCIM services in step with a tenant's
  members (create, adopt, update, deactivate or delete, pushed groups), with encrypted downstream tokens, key rotation,
  previews, event-driven syncs and a JSON management API.

With the default `server` feature, `host::scim_config(&iam)` and `host::provisioning_config(&iam, key)` build both
configurations from a server's protocol host (`{ ...iam.protocolHost }`), both services implement the server's
`ProtocolService` (`iam.use_protocol(Arc::new(service))`), and `host::ServerEvents(&iam)` feeds `iam.events` to the
provisioner's `subscribe`.

Licensed under Apache-2.0.
