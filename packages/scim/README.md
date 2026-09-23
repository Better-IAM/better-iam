# @better-iam/scim

Connection-scoped SCIM 2.0 Users and Groups provisioning for Better IAM.

`createScimService` supplies authenticated connection administration (create, list, rotate, revoke), hashed bearer credentials, Users/Groups CRUD, PATCH with value paths, RFC 7644 filters (`and`/`or`/`not`, value paths, sub-attributes), sorting, attribute projection, `/.search`, `/Bulk` with `bulkId` references, pagination, optimistic ETags and discovery. Deactivation revokes the local identity's sessions. Role mappings require explicit administrator authorization and retain the host's delegated grant authority.

`createScimProvisioner` is the outbound direction: it keeps downstream SCIM 2.0 applications (Slack, GitHub, …) in step with a tenant's members or selected groups: create, update, deactivate or delete, adopt existing accounts, encrypted downstream tokens, per-run reports, and event-driven or scheduled syncs.

Use `better-iam/scim` from the umbrella installation or install this package directly, pass `iam.protocolHost`, and mount with `iam.useProtocol`. Nested groups, extension schemas other than the enterprise user extension, and SCIM password management are not enabled.

See the repository's `docs/protocols.md` for supported filters and attribute paths.

License: Apache-2.0.
