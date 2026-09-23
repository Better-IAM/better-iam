# @better-iam/oauth

OAuth2/OIDC sign-in and an independent OAuth/OIDC authorization server for Better IAM.

- `createOAuthLogin`: Google, GitHub, Microsoft Entra ID (single- or allowlisted multi-tenant), generic OIDC and configured OAuth2 providers; PKCE, verified identity mapping and explicit account linking.
- `createOAuthProvider`: tenant-bound clients, authorization code, refresh-token rotation, service credentials, device authorization, introspection and revocation; client management (list, update, secret rotation); connected apps (list and revoke consents); pushed authorization requests; DPoP-bound tokens; resource indicators with JWT access tokens.
- `createAccessTokenVerifier`: offline verification of JWT access tokens and DPoP proofs for resource servers (APIs).
- `createSharedSignalsTransmitter`: OpenID Shared Signals (CAEP/RISC) transmitter pushing signed security events for sessions, credentials, identifiers, and account status to tenant receivers.
- Dynamic client registration (RFC 7591) with tenant-scoped registration tokens or a host-controlled anonymous policy, and RFC 9728 protected resource metadata (`createProtectedResourceHandler`, `protectedResourceMetadataUrl`) — what MCP servers and hosts need.
- `createProviderAdapter`: encrypted persistent protocol artifacts over `IamStore`.

Use `better-iam/oauth` from the umbrella installation or install this package directly. All factories are server-only. Configure verified host callbacks, persistent keys and application-owned interaction pages, then mount with `iam.useProtocol` and `iam.nodeHandler`.

See the repository's `docs/protocols.md` and runnable examples for integration and protocol limits.

License: MIT.
