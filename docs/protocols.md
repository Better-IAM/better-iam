# Federation and provisioning

Protocol packages use the same store, verified credential resolution, and authorization services as Better IAM. Initialize the database before using them. Importing the umbrella's main entrypoint does not activate a provider; configure and mount the required protocol explicitly.

```ts
import { createOAuthLogin, createOAuthProvider } from 'better-iam/oauth';
import { createSamlService } from 'better-iam/saml';
import { createScimService } from 'better-iam/scim';

const host = iam.protocolHost;
const scim = createScimService({ ...host });
iam.useProtocol(scim);
```

`iam.handler(request)` dispatches Fetch-compatible protocol handlers. `iam.nodeHandler(req, res)` also mounts the complete OAuth authorization server. When mounted through IAM, successful federation sets the standard IAM session cookie. Standalone package users are responsible for applying the returned session to their application response and must implement all host callbacks as trusted server functions.

## OAuth and OpenID Connect sign-in

```ts
const login = createOAuthLogin({
  ...host,
  trustedOrigins: ['https://product.example'],
  connections: [
    {
      id: 'org-google',
      tenantId: organization.id,
      kind: 'google',
      clientId: secrets.googleId,
      clientSecret: secrets.googleSecret,
      redirectUri: 'https://product.example/oauth/google/callback',
    },
  ],
});
iam.useProtocol(login);
```

Navigate to `/oauth/login/org-google` to start login. The package supplies PKCE, state, nonce, a browser-binding cookie, single-use database state, and validation of token signatures, issuer, audience and nonce. Google uses its fixed OIDC issuer. GitHub uses an authenticated profile API and its stable numeric account ID. `kind: 'oidc'` accepts a configured issuer and uses discovery.

`kind: 'microsoft'` signs in with Microsoft Entra ID. `microsoftTenant` selects the directory: `organizations` (default), `common`, `consumers`, or one tenant ID or domain. `issuer` may point at a sovereign-cloud authority instead of `https://login.microsoftonline.com`. Multi-tenant settings require `allowedMicrosoftTenants`, the Entra tenant IDs (`tid`) that may sign in, so a directory you have not approved cannot create or reach accounts in this tenant. The ID token must come from the concrete issuer of its own `tid`, and the external identity is keyed by that issuer. Entra lets directory administrators set any email address, so `email` counts as verified only when the token carries `xms_edov: true`. Enable that optional claim in the app registration if first sign-in should enroll accounts by email.

Sign-in hints skip steps on the provider's page, for example after home-realm discovery has matched an email to a connection: `login.begin(connectionId, undefined, { loginHint, domainHint, prompt })`, or `?login_hint=&domain_hint=&prompt=` on the `GET` start route. `loginHint` pre-fills the account (GitHub's `login`). `domainHint` becomes Microsoft's `domain_hint` or Google's `hd`. `prompt` is `login`, `select_account`, `consent`, or `none`. Hints are validated and forwarded only. They never influence which identity the callback accepts.

For an OAuth2 provider without OIDC, use `kind: 'oauth2'` with `issuer`, `authorizationEndpoint`, `tokenEndpoint`, `userInfoEndpoint`, and `mapProfile(profile)`. The mapper runs only on a successful authenticated profile response and must return a stable `subject`; it can additionally supply `email`, `emailVerified`, and `name`. These are server configuration fields, never request parameters. Do not use an email address or mutable username as the subject. Configured endpoints and registered callback URLs must use HTTPS; `allowInsecureLocalhost: true` enables HTTP only for loopback development. Each connection needs its own callback URL.

External identities are keyed by tenant, provider, issuer and subject. Same-email identities never merge automatically. Initial enrollment requires a verified email; an existing account must be linked explicitly. Root administrators cannot use the ordinary linking flow. Federation invokes local MFA requirements before issuing a session.

To link an already authenticated account, reauthenticate and POST to the same login URL:

```ts
const response = await fetch('/oauth/login/org-google', {
  method: 'POST',
  credentials: 'include',
  headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
  body: '{}',
});
const { url } = await response.json();
location.assign(url);
```

The browser supplies `Origin`. Linking requires a trusted origin, a current user session authenticated within five minutes, and the same target tenant. Only session and identity IDs are saved with the browser-bound ceremony; raw IAM credentials are never stored. The host rechecks the original session and identity at completion and rejects competing mappings. The direct equivalent is `login.begin(connectionId, credential)` followed by `callback(connectionId, callbackUrl, binding)`; protect the returned binding like the HTTP-only cookie used by the built-in handler.

Sign-in connections (OIDC, Google, GitHub, generic OAuth2) accept `mapAttributes(claims)` and SAML connections accept `mapAttributes(profile)`: the mapped values are validated against `permissions.identityAttributes` inside the sign-in transaction and replace the identity's stored attributes on every sign-in, so directory data such as a department drives `principal.{name}` conditions. An invalid mapping fails the sign-in closed.

## OAuth/OIDC authorization server

```ts
const issuer = createOAuthProvider({
  ...host,
  issuer: 'https://identity.example/oidc',
  jwks: secrets.privateSigningJwks,
  cookieKeys: secrets.cookieSigningKeys,
  encryptionKey: secrets.base64Encoded32ByteEncryptionKey,
  trustedOrigins: ['https://identity.example'],
  scopes: ['documents:read'],
  interactionUrl: (uid) => `https://identity.example/interactions/${uid}`,
  renderDevicePage: ({ kind, form }) => renderDeviceScreen(kind, form),
  renderLogoutPage: ({ form }) => renderLogoutScreen(form),
});
iam.useProtocol(issuer);
```

Supply persistent signing keys, cookie-signing keys, and a separate 32-byte encryption key. Keep the same keys across replicas and process restarts. Do not regenerate them during normal startup. Signing-key rollover uses a JWKS containing the active private key and still-valid verification keys. Changing the encryption key requires re-encrypting stored protocol artifacts; automatic key migration is not provided.

The configured issuer remains fixed. Metadata and generated endpoint URLs retain its mount path. Discovery, JWKS, authorization code with required PKCE, rotating refresh tokens, client credentials, device authorization, userinfo, introspection, revocation and RP-initiated logout are supplied by `oidc-provider`. Only the code response type is enabled. The development interaction UI is disabled, and dynamic registration stays off unless `registration` is configured (see [Dynamic client registration and MCP](#dynamic-client-registration-and-mcp)).

Clients are created using `issuer.registerClient(credential, input)`. Their tenant and ID are immutable. Public clients use PKCE without a secret; confidential clients receive a random secret once. A client using `client_credentials` must specify an active same-tenant `serviceAccountId`. Service deactivation makes its client and tokens unavailable. Client secrets and protocol payloads are encrypted at rest; token identifiers are hashed for storage. Registered redirect URIs are exact, and browser CORS access is limited to registered redirect origins. Introspection and revocation are restricted to a client's own tokens.

Interaction routes belong to your application. Render `issuer.interactionDetails(req, res)` for the login/consent screen, then call `issuer.completeInteraction(req, res, { credential, consent })` on a POST with a trusted Origin. The credential must resolve to a user in the client's tenant. Never pass account IDs or tenant IDs from a form as verified identity. The provider-generated forms supplied to device/logout render callbacks carry required CSRF fields; retain those forms unchanged when embedding them in your page. The runnable example demonstrates the full browser flow.

Every user grant is bound to the IAM session used to approve it. Expiry, logout, deactivation, tenant suspension, current MFA policy, and configured idle limits are rechecked on later token use. `iam.protocolHost.validateSession` supplies the exact product policy; standalone integrations without that callback use a one-day idle maximum. Refresh-token reuse permanently revokes the grant family, including tokens issued by a racing request. Database transactions protect individual artifact operations and do not hold a writer lock while waiting for request bodies.

Tokens carry `tenant_id`; service tokens also carry `identity_id`. The built-in `iam` scope adds `roles` and `groups` (the account's live role and group IDs when the claims are read, expired bindings excluded) and `attributes` (declared identity attributes) to the userinfo response, following the standard rule that ID tokens issued alongside an access token carry only `openid` claims; relying parties can render navigation or map roles without a callback. The values are snapshots, and enforcement stays with Better IAM. OAuth scopes are client-facing claims, not IAM permission grants. Resource servers should introspect tokens, verify their tenant and scope, and apply their product's authorization policy. OAuth tokens are not accepted as IAM administrative session credentials by default.

### Client management

`listClients(credential, { tenantId, includeRevoked? })` returns the clients the caller may read (`iam:oauth:clients:read` per `oauth-client`), and `getClient` reads one. Neither ever returns a secret. `updateClient(credential, { tenantId, clientId, ...settings })` (action `iam:oauth:clients:update`) changes the name, redirect URIs, grant types, scopes, resources, `requireDpop`, and `requirePushedAuthorization` with the same validation as registration; tenant, ID, client type, and service account stay immutable. Removing a grant type, scope, or resource, or turning on `requireDpop`, revokes every token, code, and consent issued to the client (`tokensRevoked: true`), so no credential keeps authority the client no longer has. `rotateClientSecret(credential, { tenantId, clientId, revokeTokens? })` returns a new secret once and disables the previous one immediately; pass `revokeTokens` when the old secret leaked. Updates and rotations are audited as `iam:oauth:UpdateClient` and `iam:oauth:RotateClientSecret`.

Access tokens live 15 minutes by default, or as long as the target resource server's `accessTokenTtl` says. A client's `accessTokenTtl` (60–86,400 seconds) can only shorten that. `refreshTokenTtl` (5 minutes to 30 days, default 30 days) sets each refresh token's lifetime and restarts on every rotation, but never outlives the consent (30 days from the last consent). Pass `null` to `updateClient` to restore a default.

Consent screens get the client's branding from `interactionDetails(...).client`: `name`, and the HTTPS `logoUri`, `clientUri`, `policyUri`, and `tosUri` set at registration (`null` in `updateClient` removes one). They also get `firstParty`, which marks the deployment's own applications. Hosts may approve consent for them without asking by calling `completeInteraction` with `consent: true` once the person is signed in. The provider never skips the interaction by itself.

### Connected apps

Each consent is a grant. Repeating consent in the same provider session extends the existing grant, so an account has one grant per client instead of a new one per sign-in. `listGrants(credential, { tenantId, identityId?, clientId? })` returns the live grants (client name, OIDC scopes and claims, resource scopes, creation and expiry), leaving out revoked, expired, and session-orphaned grants. `revokeGrant(credential, { tenantId, grantId })` revokes one grant by its opaque `id`, and `revokeGrants(credential, { tenantId, identityId?, clientId? })` disconnects all of an account's apps, or one client's. Revocation invalidates the grant's refresh tokens, access tokens, and codes at once and is audited as `iam:oauth:RevokeGrant`. Callers manage their own grants without extra permissions; reading or revoking another account's grants requires `iam:oauth:grants:read` or `iam:oauth:grants:revoke` on `iam/{identityId}` in that account's tenant.

### Resource servers, DPoP, and pushed authorization

```ts
const issuer = createOAuthProvider({
  ...options,
  resourceServers: {
    'https://api.example': { scopes: ['invoices:read', 'invoices:write'], accessTokenTtl: 600 },
  },
});
await issuer.registerClient(credential, {
  tenantId,
  clientId: 'billing-sync',
  name: 'Billing sync',
  redirectUris: [],
  grantTypes: ['client_credentials'],
  serviceAccountId,
  scopes: ['invoices:read'],
  resources: ['https://api.example'],
  requireDpop: true,
});
```

A `resource` parameter (RFC 8707) that names a configured resource server gets an access token restricted to that audience, carrying only that API's scopes, in JWT format (RFC 9068) unless `accessTokenFormat: 'opaque'`. A client may only target the resources it was registered with; anything else fails with `invalid_target`. Without `resource`, OpenID requests keep receiving UserInfo access tokens.

Resource servers verify JWT access tokens offline with the same package:

```ts
import { createAccessTokenVerifier } from 'better-iam/oauth';

const verifier = createAccessTokenVerifier({
  issuer: 'https://identity.example/oidc',
  audience: 'https://api.example',
});
const token = await verifier.verifyRequest(
  {
    authorization: req.headers.authorization,
    dpop: req.headers.dpop,
    method: req.method,
    url: fullUrl,
  },
  { scopes: ['invoices:read'] },
);
// token.tenantId, token.clientId, token.identityId (service account), token.subject, token.scopes
```

By default the verifier fetches and caches `{issuer}/jwks`; pass `jwks` for pinned keys. It checks signature, `typ: at+jwt`, issuer, audience, expiry, and scopes (`INSUFFICIENT_SCOPE`, 403, otherwise `INVALID_TOKEN`, 401), and `challenge(error)` builds a `WWW-Authenticate` value.

DPoP (RFC 9449) is on: a client that sends a `DPoP` proof receives a key-bound token (`token_type: DPoP`), and a client registered with `requireDpop` cannot get anything else. `verifyRequest` requires the `DPoP` scheme and a proof for bound tokens and checks the key thumbprint, method, URL, access-token hash, and age, and rejects replayed proofs. `verify(token)` rejects bound tokens because it has no proof to check. Replay detection keeps state in memory per verifier instance. A deployment with several API replicas should also enforce short proof lifetimes (`dpopMaxAge`). `dpopNonceSecret` (32 bytes, base64) enables server-provided nonces at the authorization server.

Pushed authorization requests (RFC 9126) are available at the discovered `pushed_authorization_request_endpoint`. Require them for every client with `requirePushedAuthorizationRequests: true`, or per client with `requirePushedAuthorization`.

Browser clients request resource tokens by adding `resource` to the authorization request and the code exchange. Consent grants each requested resource the requested scopes its resource server defines, and `listGrants` shows them per resource.

### Token exchange

An API that receives a user's access token can call another API on that user's behalf with OAuth 2.0 Token Exchange (RFC 8693). Register the API as a confidential client with the `urn:ietf:params:oauth:grant-type:token-exchange` grant type, the downstream `resources`, and the `scopes` it may use there. Then:

```http
POST /oidc/token
Authorization: Basic <client credentials>

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<the caller's access token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&resource=https://reports.example
&scope=reports:read
```

The subject token can be a JWT access token from this issuer or an opaque one it stores. It must belong to an active account in the exchanging client's tenant and must not be DPoP-bound. The issued token keeps the account as `sub`, names the exchanging client as `client_id` and as the actor in `act` (nested for chains), carries only the requested scopes allowed by both the client and the target resource server, and expires no later than the subject token. `actor_token` is refused, because the authenticated client is always the actor. `authorizeTokenExchange(request)` adds product policy, for example which subject clients or scopes an API may delegate; returning `false` answers `access_denied`. Each exchange is audited as `iam:oauth:TokenExchange`. `createAccessTokenVerifier` reports the chain as `actor`.

### OAuth access tokens and IAM session JWTs

Better IAM issues two kinds of JWT that a resource server might receive, and they are never interchangeable:

|                        | OAuth access tokens (this provider)                          | IAM session JWTs ([temporary credentials](temporary-credentials.md#session-jwts))                  |
| ---------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| `typ`                  | `at+jwt`                                                     | `biam-session+jwt`                                                                                 |
| Keys                   | The provider's own signing JWKs, published at its `jwks_uri` | `sts.jwt.signingKeys`, published at `{basePath}/.well-known/jwks.json`                             |
| Issued by              | The authorization server, after consent, for OAuth clients   | `roles.assume`, `sts.getSessionToken` and `sts.assumeRoleWithWebIdentity` with `format: 'jwt'`     |
| Audience               | A registered resource server (`resource`)                    | An entry of `sts.jwt.audiences` the credential may obtain (`iam:assertions:create` on `iam/{aud}`) |
| Verify with            | `createAccessTokenVerifier`                                  | `createSessionTokenVerifier` (`better-iam/session-tokens`)                                         |
| Accepted by IAM itself | No; they authorize the client at resource servers            | Yes, as bearers, when the audience includes the IAM issuer and the stored session is live          |

Each verifier pins its own `typ`, so an access token presented to a session-token verifier (or the reverse) is refused even when keys overlap, and the keys are configured separately in any case. Web-identity federation also refuses both types as external tokens, and the IAM session issuer can never be registered as an OIDC provider, so neither kind can be exchanged back into IAM through web identity.

### Dynamic client registration and MCP

Clients that configure themselves, such as Model Context Protocol (MCP) hosts connecting to an MCP server, discover an API's authorization server and register on the fly. Turn this on with `registration`:

```ts
const issuer = createOAuthProvider({
  ...options,
  resourceServers: { 'https://mcp.example.com/mcp': { scopes: ['mcp:tools'] } },
  registration: {
    // Optional: accept registrations without a token (what most MCP hosts do), for the tenant the host serves.
    anonymous: ({ headers }) =>
      tenantForHost(headers.host)
        ? {
            tenantId: tenantForHost(headers.host)!,
            scopes: ['openid', 'offline_access', 'mcp:tools'],
            resources: ['https://mcp.example.com/mcp'],
            maxClients: 500,
          }
        : undefined,
  },
});

// Or hand out tenant-scoped initial access tokens (RFC 7591 §3):
const { token } = await issuer.createRegistrationToken(credential, {
  tenantId,
  name: 'Claude Desktop',
  scopes: ['openid', 'offline_access', 'mcp:tools'],
  resources: ['https://mcp.example.com/mcp'],
  maxClients: 1,
  expiresIn: 86400,
});
```

The discovered `registration_endpoint` (`{issuer}/reg`) accepts RFC 7591 registrations carrying `Authorization: Bearer <registration token>`, or no token when the `anonymous` hook maps the request to a tenant. Registrations are held to these limits:

- The tenant comes from the token or the hook. A `tenant_id` in the request is ignored.
- Only the `authorization_code` and `refresh_token` grants are allowed, always with PKCE.
- Clients are public (`token_endpoint_auth_method: "none"`) unless the token or policy sets `allowConfidential`, which permits a client secret.
- Redirect URIs must use HTTPS, loopback HTTP on any port (RFC 8252), or a reverse-domain custom scheme for native apps.
- Nothing the provider would have to fetch can be registered: `jwks_uri`, `sector_identifier_uri`, `backchannel_logout_uri`, request URIs, or custom lifetimes.
- A client that omits `scope` gets the allowance (default `openid profile email offline_access`). One that asks for more is refused. It may request tokens only for the allowance's `resources`.

Each registration uses one of the token's `maxClients`. Anonymous registrations are capped per tenant (`maxClients`, default 100). New clients are audited as `iam:oauth:RegisterClient`, appear in `listClients` with `registeredVia` (the token ID or `anonymous`), and are managed like any other client. `listRegistrationTokens` and `revokeRegistrationToken` manage tokens, which are stored hashed and shown once. Registration management (`registration_client_uri`) is not offered, so administrators change and revoke registered clients through `updateClient` and `revokeClient`.

The MCP server (the API) then tells clients where to go with RFC 9728 protected resource metadata. `createResourceGuard` does all of it in front of your routes:

```ts
import { createResourceGuard } from 'better-iam/oauth';

const guard = createResourceGuard({
  resource: 'https://mcp.example.com/mcp',
  authorizationServers: ['https://id.example.com/oidc'],
  scopes: ['mcp:tools'],
  requiredScopes: ['mcp:tools'],
  resourceName: 'Acme MCP',
});

async function handle(request: Request): Promise<Response> {
  const { response, token } = await guard.check(request); // also serves /.well-known/oauth-protected-resource/mcp
  if (response) return response;
  return runMcp(request, token); // token.subject, token.tenantId, token.clientId, token.scopes
}
```

Requests without credentials get `401` with `WWW-Authenticate: Bearer resource_metadata="…", scope="…"` (no error code, per RFC 6750). Invalid, expired, or wrong-audience tokens get `401 invalid_token`. Missing scopes get `403 insufficient_scope` naming the scopes needed. `check(request, { scopes })` adds per-route scopes. The lower-level pieces are exported too: `protectedResourceMetadata`, `protectedResourceMetadataUrl`, `createProtectedResourceHandler`, and the verifier's `challenge(error, realm, { resourceMetadata, scopes })`.
An MCP host that calls the server without a token receives the challenge, reads `resource_metadata`, fetches the authorization server metadata (`/.well-known/oauth-authorization-server{issuer path}`), registers, and runs the authorization code flow with PKCE and `resource`. The consent screen shows the registered `client_name`. Consenting binds the client to the person's IAM session, so signing out or deactivation revokes it like any other grant. Refresh tokens follow OAuth 2.1 for such requests. An authorization code without the `openid` scope yields a refresh token whenever the client is registered for the `refresh_token` grant, with no `offline_access` or `prompt=consent` needed. OpenID requests keep the OIDC rule. Refresh tokens rotate on every use and end with the consenting session.

### Key-based client authentication

Confidential clients default to `client_secret_basic`. Register with `tokenEndpointAuthMethod: 'client_secret_post'` to send the secret in the form body, or `'private_key_jwt'` with public keys in `jwks` (at most ten, and private key members are refused) or an HTTPS `jwksUri`. A `private_key_jwt` client receives no secret. It signs a short-lived assertion (`iss` and `sub` = client ID, `aud` = issuer, unique `jti`) per token, introspection, or revocation request, and each assertion works once. Rotate keys with `updateClient({ jwks })` (or a new `jwksUri`) without revoking tokens. Client summaries list `tokenEndpointAuthMethod`, `keyIds`, and `jwksUri`.

### Back-channel logout

Register `backchannelLogoutUri` (HTTPS) on a client to receive OpenID back-channel logout tokens. `logoutEndedSessions({ identityId? })` finds consents whose IAM session expired, was revoked, or belongs to an account or tenant that is no longer active. It posts a logout token signed with the provider keys (`sub` = account, `aud` = client, back-channel logout event) to each client once per account, revokes the grants and their tokens, and audits `iam:oauth:SessionLogout`. It returns `{ sessions, grants, notified, failures }`. Deliveries time out after 2.5 seconds and are not retried. Sessions expire without an event, so run the sweep on an interval and after sign-out events:

```ts
iam.events.subscribe(['auth:session:*', 'identity:*', 'tenant:*'], () =>
  issuer.logoutEndedSessions(),
);
setInterval(() => void issuer.logoutEndedSessions(), 60_000).unref();
```

Outbound requests (client JWKS URIs and logout deliveries) refuse private and special-use addresses; `allowInsecureLocalhost` exempts loopback targets for local development only.

## Shared Signals (CAEP and RISC)

`createSharedSignalsTransmitter` makes Better IAM an OpenID Shared Signals Framework transmitter. It pushes security events about a tenant's people to the tenant's receivers (a SIEM, an application that should drop sessions at once, a partner IdP) as signed Security Event Tokens (RFC 8417) over RFC 8935 push delivery:

```ts
import { createSharedSignalsTransmitter } from 'better-iam/oauth';

const signals = createSharedSignalsTransmitter({
  ...iam.protocolHost,
  issuer: 'https://id.example.com/oidc', // usually the OAuth issuer; its /jwks publishes the public keys
  jwks: secrets.privateSigningJwks,
  encryptionKey: secrets.base64Encoded32ByteKey,
});
signals.subscribe(iam.events); // publish as IAM events are dispatched
setInterval(() => void signals.dispatch(), 60_000).unref(); // retries

await signals.createStream(credential, {
  tenantId,
  name: 'Acme SIEM',
  endpointUrl: 'https://siem.acme.com/ssf/events',
  authorization: 'Bearer receiver-issued-token',
  events: [sharedSignalEvents.sessionRevoked, sharedSignalEvents.credentialChange],
  subjectFormat: 'email',
});
```

| IAM activity                                                                                              | Event                                                       |
| --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| sign-out of a session, "sign out other devices", administrator session revocation, tenant-wide revocation | CAEP `session-revoked`                                      |
| password changed or reset, authenticator added or removed, passkey added or removed                       | CAEP `credential-change` (`credential_type`, `change_type`) |
| email address changed (by the person or an administrator)                                                 | RISC `identifier-changed`                                   |
| offboarding, scheduled expiry                                                                             | RISC `account-disabled`                                     |
| deletion                                                                                                  | RISC `account-purged`                                       |

Each SET is signed with the first private key that has an `alg` (`typ: secevent+jwt`, `kid`). It carries `iss`, `aud` (the stream's `audience`, default its endpoint), `jti`, `iat`, `txn` (the IAM audit event ID), and `sub_id`. `sub_id` is `{ format: "iss_sub", iss, sub: identityId }` by default, or `{ format: "email" }` when the stream asks for it and the address still exists. Tenant-wide revocation uses a `complex` subject naming the tenant. Events also carry `event_timestamp` and `initiating_entity` (`user` for the person themselves, otherwise `admin`).

Streams are managed with `createStream`, `listStreams`, `getStream`, `updateStream`, and `deleteStream`, authorized as `iam:ssf:streams:create|read|update|delete` on `ssf/{streamId}` and audited. The receiver's `authorization` header is encrypted and write-only. Endpoints must use HTTPS (`allowInsecureLocalhost` allows loopback HTTP for development). `verifyStream` sends an SSF verification event with a `state` at once and reports whether the receiver accepted it. Deliveries expect `202` (also accepting `200`/`204`), retry with backoff (30 seconds growing to two hours, eight attempts), and are listed per stream with `listDeliveries`. A paused stream (`enabled: false`) keeps collecting events and delivers them after it is re-enabled. Deleting a stream drops its queue. `handler(request)` serves the transmitter metadata at `/.well-known/ssf-configuration{issuer path}`. Receiver-driven stream management (the SSF stream configuration API) and poll delivery are not offered: streams are configured by administrators.

Better IAM also receives Shared Signals from upstream identity providers (push and poll, mapped to the organization's people, feeding threat detection): see the [Shared Signals receiver](shared-signals-receiver.md).

## SAML service provider

Configure `createSamlService({ ...host, connections })` with each tenant's `entryPoint`, `idpIssuer`, `idpCertificates`, `entityId`, `callbackUrl`, SP `privateKey`, and `publicCertificate`. Supply `decryptionPrivateKey` and `decryptionCertificate` to accept encrypted assertions; `requireEncryptedAssertions: true` rejects plaintext assertions.

`GET /saml/:connectionId/login` starts an SP-initiated flow, and `GET /saml/:connectionId/metadata` returns signed SP metadata. POST to the login path with the same trusted-origin and recent-authentication requirements as OAuth to link an account. The configured callback URL accepts the SAML HTTP POST binding.

Both the response and assertion must be signed. Validation also requires the exact IdP issuer, SP audience, response destination, subject recipient, bounded assertion age, and an outstanding `InResponseTo` request. A persistent connection-scoped cache and transaction around verification prevent cross-process replay. The RelayState and request ID are bound to a Secure, HTTP-only, SameSite=None cookie. DTDs and entity declarations are rejected. To roll IdP certificates, temporarily include the previous and new certificates in `idpCertificates`.

For first-login enrollment, explicitly configure `trustedEmailDomains` only for domains whose account email attributes this IdP is authorized to verify. Otherwise use an already linked external identity or link an existing authenticated local account. SAML email attributes are unverified by default; matching an existing email alone never links it. `logout(credential)` invokes the configured local session revoker. SAML IdP functionality and federated single logout are outside this release.

IdP-initiated sign-in (app tiles in an Okta or Entra portal) is off by default. Set `allowIdpInitiated: true` on a connection to accept responses at its callback URL that answer no request. Such responses must carry no `InResponseTo` and pass the same signature, issuer, audience, destination, recipient, and five-minute age checks. Each assertion ID is accepted once per connection, recorded in `samlAssertions` for ten minutes. The response signs the person in without account linking, and a `RelayState` is ignored. Responses that do carry `InResponseTo` still need the browser-bound request. IdP-initiated SSO cannot be tied to a browser the way SP-initiated login is, so a stolen, still-unused response can be replayed once in another browser within those minutes. Enable it only for IdPs your organizations rely on for portal launches. `idpInitiated(connectionId, samlResponse)` is the direct call.

### Tenant-managed connections

Organizations can connect their own identity provider without a deployment change. Give the service one service-provider identity for every managed connection, plus the host's authorization:

```ts
const saml = createSamlService({
  ...iam.protocolHost,
  serviceProvider: {
    baseUrl: 'https://identity.example',
    privateKey: secrets.samlSpKey,
    publicCertificate: secrets.samlSpCertificate,
  },
});
iam.useProtocol(saml);

const connection = await saml.createConnection(credential, {
  tenantId: organization.id,
  id: 'acme-okta',
  name: 'Acme Okta',
  metadataXml: uploadedIdpMetadata,
  trustedEmailDomains: ['acme.com'],
  attributeMapping: { department: 'department' },
});
// connection.entityId, connection.acsUrl → register them at the IdP
```

`createConnection`, `listConnections`, `getConnection`, `updateConnection`, and `deleteConnection` are authorized as `iam:saml:connections:create|read|update|delete` on `saml/{connectionId}` (`saml/*` for listing) in the connection's tenant, and changes are audited as `iam:saml:{Create,Update,Delete}Connection`. IdP details come from `metadataXml` (entity ID, the HTTP-Redirect sign-on URL, and every signing certificate) or from explicit `entryPoint`, `idpIssuer`, and `idpCertificates` (one to five, PEM or base64). Explicit values override imported ones. Metadata import refuses DTDs, entities, and documents that do not describe exactly one IdP. It does not check metadata signatures, so accept metadata only from administrators or the IdP's own HTTPS URL.

Each managed connection gets fixed URLs under the base URL: `{basePath}/{id}/metadata` (also the SP entity ID), `{basePath}/{id}/acs` (HTTP-POST assertion consumer), and `{basePath}/{id}/login`. Responses are validated exactly like configured connections. `attributeMapping` maps identity attribute names to SAML attribute names (the first value of multi-valued attributes). The mapped values reach `completeAuthentication` like `mapAttributes`. Summaries report each certificate's SHA-256 fingerprint, subject, validity, and `expired`, so certificate rollover can be monitored. List old and new certificates together through `updateConnection` until the IdP switches. `enabled: false` stops new sign-ins immediately. Deleting a connection removes its pending sign-ins, while external identities linked through it stay with their accounts. `getMetadata(id)` serves both kinds of connection; the synchronous `metadata(id)` covers configured ones only. Configured `connections` keep working alongside managed ones, and their IDs are reserved.

## SCIM 2.0

Create a connection using `scim.createConnection(credential, { tenantId, name, expiresIn? })`; the caller needs `iam:scim:connections:create`. The result contains a bearer token once, its expiry, and a connection-specific base path. Configure that path and token in the provisioning client. The token is hashed, defaults to 90 days, and is restricted to exactly one connection and tenant. `revokeConnection` immediately invalidates it and removes the connection's configured role bindings.

Users and Groups support create, retrieve, list, replace, PATCH and delete. User fields include `userName`, `displayName`, `externalId`, `active`, `name`, `emails`, `title`, and the enterprise user extension (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`: `employeeNumber`, `costCenter`, `organization`, `division`, `department`, `manager`), which are stored and returned as provisioned. Supply `mapAttributes` in the SCIM configuration to turn them into the identity attributes the product declares (`permissions.identityAttributes`); `validateIdentityAttributes` from `iam.protocolHost` validates the mapping, so a directory can drive `principal.department`-style policy conditions. Group membership accepts same-connection users only. Deactivation disables the local identity and revokes its user, API and assumed-role sessions. Deletion preserves the disabled identity as a historical principal. Protected owners and root administrators cannot be modified by SCIM.

User/group links remain isolated from other SCIM connections. A provisioning request cannot take over an existing local account based on email. Group-to-role mappings are explicitly authorized through `setRoleMappings` and the host's transactional `syncRoleMappings` callback; subsequent membership updates inherit that configured group binding and its original delegated authority. A SCIM token cannot create policies, roles, boundaries or trust relationships.

Filtering implements the RFC 7644 grammar: `and`, `or`, `not (...)`, parentheses, value paths (`emails[type eq "work" and primary eq true]`), sub-attributes (`name.familyName`, `meta.lastModified`), schema-qualified names (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department`) and `eq ne co sw ew pr gt ge lt le`. Filters evaluate against the rendered resource, so any returned attribute is filterable; a multi-valued attribute matches when any value does. IDs, external IDs and member values are case-exact; other strings compare case-insensitively. `active`/`primary` require booleans, and booleans allow only `eq`/`ne`. Filters are bounded (2048 characters, 64 comparisons, 16 levels of nesting). `sortBy`/`sortOrder` sort by any attribute (multi-valued attributes by their primary value; unassigned values last), and `attributes` / `excludedAttributes` project responses (`id` and `schemas` are always returned). `POST {Users|Groups}/.search` accepts the same query as a `SearchRequest` body. Pagination uses one-based `startIndex`, with at most 200 results per response.

PATCH supports pathless add/replace (including schema-qualified keys and whole extension objects), sub-attribute paths (`name.givenName`, `urn:…:enterprise:2.0:User:manager.value`), value paths with optional sub-attributes (`emails[type eq "work"].value`, `members[value eq "…"]`), and removal of listed members (`{ op: "remove", path: "members", value: [{ value }] }`). An `add` to a value path that matches nothing creates the entry seeded from the filter's `eq` comparisons; a `replace` that matches nothing returns `noTarget`. Operation names are case-insensitive and `"True"`/`"False"` strings are accepted for boolean attributes, matching Microsoft Entra ID. Every PATCH is applied to a copy and saved through the same validation as PUT, so a failing operation leaves the resource unchanged. `GET` honours `If-None-Match` (304) and writes honour `If-Match` (412 on a stale version).

`POST {connection}/Bulk` accepts up to 100 operations in one `BulkRequest` (1 MiB). Each operation commits in its own transaction, so a failed operation never leaves partial writes; `bulkId:` references in paths or data resolve to resources created in the same request regardless of order (forward references are deferred; cycles and references to failed operations return 409, unknown references 400). `failOnErrors` stops processing after that many failures, and `version` maps to `If-Match`.

`scim.listConnections(credential, { tenantId })` (`iam:scim:connections:read`) returns each connection's name, path, expiry, revocation, creation/last-use/rotation times, provisioned user/group counts and role mappings, never the token. `scim.rotateToken(credential, { tenantId, connectionId, expiresIn? })` (`iam:scim:credentials:create`) issues a replacement token once; the previous token stops working immediately and provisioned users, groups and mappings are kept (audited `iam:scim:RotateToken`). `scim.listGroups(credential, { tenantId, connectionId })` (`iam:scim:connections:read`) lists the groups an identity provider pushed through a connection with their member counts and mapped roles.

The same administration is available as JSON routes for browser consoles: `handler` serves `POST {adminBasePath}/connections/{list,create,rotate,revoke,groups,mappings}` (default `adminBasePath` `/scim/admin`; it must be absolute and must not overlap `basePath`). The routes authenticate the caller's session cookie or bearer token like any IAM call, require `X-Better-IAM: 1` and a JSON body of at most 64 KiB, refuse a mismatched `Origin`, and answer `{ data }` or `{ error: { code, message } }`. Mount both under the IAM handler's path, for example `createScimService({ ...iam.protocolHost, basePath: '/api/iam/scim/v2', adminBasePath: '/api/iam/scim-admin' })`, and forward `PUT`, `PATCH`, and `DELETE` as well as `GET` and `POST` to `iam.handler` so identity providers reach the protocol endpoints.

The enterprise extension's `manager.value` becomes the person's `Identity.managerId` (`mapManager`, on by default), so approvals and manager-review certification campaigns route to the directory's reporting line. The value may be the manager's SCIM ID, `externalId`, or `userName` within the same connection, and a reference naming the person themself is ignored. A report provisioned before their manager is linked once the manager arrives; a manager that would close a reporting loop, or a deleted one, is skipped rather than refused. SCIM clears only a manager it set itself, never one an administrator chose, and deleting the manager through SCIM releases the reports it linked. An identity an administrator deleted can no longer be updated through SCIM (`mutability`, 403): SCIM never reactivates it or adds it back to groups, while a SCIM delete of it still succeeds.

`ServiceProviderConfig`, `ResourceTypes` and `Schemas` describe available capabilities, including the enterprise user extension. Password changes, nested groups, and extension schemas other than the enterprise user extension are not enabled. Mutation records and audit events commit together; administrative events retain the authenticated administrator, and provisioning events identify the SCIM connection.

### Outbound provisioning

`createScimProvisioner` pushes a tenant's members to downstream applications that accept SCIM 2.0 (the direction opposite to the SCIM service above):

```ts
import { createScimProvisioner } from 'better-iam/scim';

const provisioner = createScimProvisioner({
  ...iam.protocolHost,
  encryptionKey: secrets.base64Encoded32ByteKey,
});
const target = await provisioner.createTarget(credential, {
  tenantId,
  name: 'Slack',
  baseUrl: 'https://api.slack.com/scim/v2',
  token: slackScimToken,
  groupIds: [engineeringGroupId], // omit for every member
  attributeMapping: { department: 'department', title: 'jobTitle' },
});
provisioner.subscribe(iam.events); // sync after member changes
setInterval(() => void provisioner.syncAll(), 15 * 60_000).unref(); // and on a schedule
```

Each target receives every active user member in scope as a SCIM user: `externalId` = identity ID, `userName` and the primary work email = the member's email, `displayName`, `active: true`, `title`, and enterprise-extension `department`, `division`, or `employeeNumber` from the mapped identity attributes. A first sync adopts an existing downstream user with the same `externalId` or `userName` instead of creating a duplicate. Later runs replace users whose data changed, skip unchanged ones without calling the service, and recreate a user the service lost. Members who are disabled, deleted, past their expiry, or no longer in the scoped groups (a temporary or access-package membership stops counting at its end, before the purge worker removes it) are deactivated downstream (`PATCH active: false`), or deleted when `deprovision: 'delete'`. The same downstream account is reactivated when they return. A disabled target, or a suspended tenant, deprovisions everyone at the next run.

Management is authorized as `iam:scim:targets:create|read|update|delete|sync` on `scim/outbound/{targetId}` and audited (`iam:scim:{Create,Update,Delete,Sync}Target`). The downstream bearer token is encrypted with `encryptionKey` (AES-256-GCM), is write-only, and is replaced through `updateTarget({ token })`. Target summaries report the number of provisioned accounts and `lastRun`: counts of created, updated, deactivated, deleted, unchanged, and failed users, plus the first 20 failures with HTTP status and the service's `detail`. A failure is retried by the next run and never stops the rest of the run. `syncTarget` runs one target on demand. `syncAll({ tenantId? })` is a deployment operation for schedulers (no credential, never expose it over HTTP). `subscribe(iam.events, { debounceMs })` schedules a tenant's targets after identity, group, access-package, tenant, SCIM, and invitation events, ignoring the provisioner's own events. One run per target executes at a time. Downstream calls send no credentials in redirects, time out after `timeoutMs` (10 seconds), and require HTTPS (`allowInsecureLocalhost` permits loopback HTTP for development). Deleting a target leaves downstream accounts as they are.

`previewTarget(credential, { tenantId, targetId })` (`iam:scim:targets:read`) shows what the next sync would do without doing it: counts and the first 200 planned changes (`create`, `adopt`, `update`, `reactivate`, `deactivate`, `delete`). It sends only the read-only lookups that detect adoptable accounts, writes nothing to the store, and leaves `lastRun` untouched.

`provisioner.handler` serves the same operations as a JSON API for browsers: `POST {basePath}/targets/{list,get,create,update,delete,sync}` with the caller's IAM cookie or bearer token. It applies the IAM API's CSRF rule (`X-Better-IAM: 1` and a JSON body) and answers with the `{ data }` / `{ error }` envelope. Mount it under the IAM path with `iam.useProtocol(createScimProvisioner({ ..., basePath: '/api/iam/provisioning' }))`, and the typed client reaches it through `$request('provisioning/targets/list', { tenantId })`. The console's App provisioning page works this way.

With `pushGroups: true`, the target's `groupIds` groups are maintained downstream as SCIM groups: `externalId` = group ID, `displayName` = group name, and `members` = the provisioned users of that group. Groups are adopted by `externalId` or `displayName`, replaced only when name or membership changes, and deleted downstream when they leave `groupIds`, are deleted, or `pushGroups` is turned off. `lastRun.groups` counts created, updated, deleted, and unchanged groups, and group failures are reported with `groupId`.

Protocol references: [OAuth/OIDC provider documentation](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md), [oauth4webapi](https://github.com/panva/oauth4webapi), [Node-SAML](https://github.com/node-saml/node-saml), and [SCIM protocol RFC 7644](https://www.rfc-editor.org/rfc/rfc7644.html).
