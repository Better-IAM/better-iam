# better-iam-oauth

OAuth 2.0 / OpenID Connect for Better IAM in Rust, the port of `@better-iam/oauth`:

- `create_oauth_login`: Google, GitHub, Microsoft Entra ID, generic OIDC and configured OAuth2 sign-in with PKCE,
  verified identity mapping and explicit account linking.
- `create_oauth_provider`: a tenant-aware OAuth 2.1 / OpenID Connect authorization server (authorization code with
  PKCE, refresh-token rotation, client credentials, device authorization, token exchange, PAR, DPoP, resource
  indicators with JWT access tokens, introspection, revocation, back-channel logout, dynamic registration), sharing
  its encrypted artifacts with the TypeScript provider.
- `create_access_token_verifier`, `create_resource_guard`: offline verification of JWT access tokens and DPoP proofs,
  RFC 9728 protected resource metadata.
- `create_shared_signals_transmitter`: OpenID Shared Signals (CAEP/RISC) transmitter.

License: Apache-2.0.
