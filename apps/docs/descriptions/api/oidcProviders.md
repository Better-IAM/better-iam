# oidcProviders

OIDC providers are the external token issuers a tenant trusts for web-identity federation: GitHub Actions, GitLab,
a Kubernetes cluster, or a cloud workload identity service. Registering a provider lets
[web-identity trusts](/docs/reference/api/trust#create) admit its tokens, so a CI job or workload can obtain a role
session through [`sts.assumeRoleWithWebIdentity`](/docs/reference/api/sts#assumerolewithwebidentity) without storing
any IAM secret.

## How providers are managed

Providers are tenant-managed. Creating or changing one needs recent authentication and the deployment switch
`sts.webIdentity.enabled` (see [web-identity federation](/docs/operations/deployment/configuration#web-identity-federation));
reading, deleting, disabling, and revoking sessions keep working when the switch is off, so you can always shut
federation down. Each provider records the grant authority of the administrator who created it. That authority
bounds every session admitted through the provider, and only its holder (or root) may edit or delete the provider,
so an administrator who can change a provider's keys can never mint sessions beyond their own reach.

A provider names its exact `issuer` (https, no query or fragment; never IAM's own issuer, and on
`sts.webIdentity.allowedIssuers` when the deployment pins issuers), the `audiences` its tokens must carry, and where
its keys come from: static public `jwks`, a `jwksUri`, or neither, in which case IAM uses OpenID Connect discovery on
the issuer. Nothing is fetched when a provider is created. Fetches refuse private addresses, redirects, oversized and
non-JSON responses, and keys are cached per provider for `sts.webIdentity.jwksCacheSeconds`.

`replayProtection` is `'single-use'` by default: each token is redeemed at most once at this provider. Set it to
`'off'` for tokens that SDKs reuse until they rotate, such as Kubernetes projected service account tokens.

## create

Registers an OIDC provider whose tokens the tenant's web-identity trusts can admit.

- **Permission:** `iam:oidc-providers:create` on the tenant, with recent authentication and an active grant
  authority.
- **Audited as:** `iam:oidc-providers:create`.
- **Errors:** `FEATURE_DISABLED` when web identity is not enabled; `CONFLICT` when the tenant already has a provider
  for this issuer; `INVALID_INPUT` for an issuer that is not https, is IAM's own, or is not on
  `sts.webIdentity.allowedIssuers`, a `jwksUri` that is not https on port 443 or points at a private address, private
  or weak static keys, both `jwks` and `jwksUri`, or an algorithm outside RS256, RS384, RS512, PS256, PS384, PS512,
  ES256, ES384, and EdDSA; `RECENT_AUTH_REQUIRED`; `GRANT_AUTHORITY_REQUIRED`.

Defaults: algorithms `RS256` and `ES256`, tokens at most 3600 seconds old and long (`maxTokenLifetimeSeconds`), 30
seconds of clock tolerance, single-use replay protection, and enabled.

```ts
const github = await iam.api.oidcProviders.create(credential, {
  tenantId,
  name: 'GitHub Actions',
  issuer: 'https://token.actions.githubusercontent.com',
  audiences: ['https://iam.example.com'],
});
```

## delete

Deletes a provider that no live trust uses any more.

- **Permission:** `iam:oidc-providers:delete` on the provider, with recent authentication, and the grant authority it
  was created under (or root).
- **Audited as:** `iam:oidc-providers:delete`.
- **Errors:** `CONFLICT` (409) while an unrevoked trust still names the provider; `ACCESS_DENIED` when another
  administrator's authority created it; `NOT_FOUND`; `RECENT_AUTH_REQUIRED`.

Revoke the trusts that use it first; revoking a trust already ends its sessions.

## get

Returns one provider.

- **Permission:** `iam:oidc-providers:read` on the provider.
- **Audited as:** `iam:oidc-providers:read`.
- **Errors:** `NOT_FOUND` when the provider is not in this tenant.

## list

Lists the tenant's OIDC providers, oldest first.

- **Permission:** `iam:oidc-providers:read` on the tenant.
- **Audited as:** `iam:oidc-providers:read`.

## revokeSessions

Ends the web-identity sessions issued through a provider before a point in time, across every trust that uses it.

- **Permission:** `iam:roles:revoke-sessions` on the provider, with recent authentication.
- **Audited as:** `iam:roles:revoke-sessions` and `role:sessions-revoked` (with the watermark and the number of
  sessions deleted).
- **Errors:** `INVALID_INPUT` when `before` is not a whole number of milliseconds, is negative, or lies in the future;
  `NOT_FOUND`; `RECENT_AUTH_REQUIRED`.

`before` defaults to now, which ends every session issued so far. The provider's `sessionsRevokedBefore` watermark
only moves forward, so a session issued earlier is refused at its next use even if it is created concurrently, and
the matching rows are deleted at once. Use it to end sessions without changing the provider, for example after a
workload's token leaked. After a provider's signing key leaks, removing the key with [`update`](#update) is enough:
the update itself ends every session issued so far, so a separate revoke is not needed. Session JWTs checked offline
by other services stay valid until they expire.

```ts
const { revoked } = await iam.api.oidcProviders.revokeSessions(credential, { tenantId, providerId });
```

## update

Changes a provider's name, audiences, keys, algorithms, token limits, replay protection, or enabled state.

- **Permission:** `iam:oidc-providers:update` on the provider, with recent authentication, and the grant authority it
  was created under (or root).
- **Audited as:** `iam:oidc-providers:update`.
- **Errors:** `FEATURE_DISABLED` when web identity is off, unless the update only sets `enabled: false`;
  `INVALID_INPUT` when the update changes nothing, tries to change the issuer, or gives invalid values (as for
  `create`); `ACCESS_DENIED` when another administrator's authority created it; `NOT_FOUND`; `RECENT_AUTH_REQUIRED`.

Only the fields you pass change; `jwksUri: null` or `jwks: null` removes that key source. Cached keys are dropped, so
the next token is checked against the new settings.

Some changes end every session issued through the provider so far, across all of its trusts, because those sessions
were admitted under the old rules: changing `jwks` or `jwksUri` (adding a key for a rotation counts), `algorithms`,
`audiences`, `maxTokenLifetimeSeconds` or `clockToleranceSeconds`, and disabling the provider. Such an update moves
the provider's `sessionsRevokedBefore` watermark to now (the response carries it) and deletes the matching session
rows, as [`revokeSessions`](#revokesessions) would; workloads simply exchange a fresh token. Changing `name` or
`replayProtection`, or enabling the provider, keeps live sessions. Plan key rotations for a quiet moment, or publish
keys through `jwksUri` or discovery so rotations need no update at all.

`enabled: false` is the kill switch: a disabled provider admits no exchanges, and the sessions issued through it end
for good, so enabling it again does not bring them back.
