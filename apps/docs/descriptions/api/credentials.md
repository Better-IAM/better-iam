# credentials

Credentials manages API keys: opaque bearer tokens that let a [service account](/docs/reference/api/service-accounts)
call Better IAM and your product without a person signing in. Keys carry a label, record when they were last used,
can be limited to a list of actions, and always expire, so you can find and remove the ones nobody needs. People
never get API keys; they use sessions. The
[API key hygiene guide](/docs/guides/privileged-access/lifecycle#api-key-hygiene) covers the routine.

## What a key can do

A key acts as its service account: it carries the account's roles, group memberships, and relations, and policies see
`principal.kind` as `service` and `principal.sessionKind` as `api-key`. Present it as `Authorization: Bearer <key>`
over HTTP, or as `{ token }` in server calls. Two limits apply on top of the account's grants, and both only ever
narrow access:

- **Scopes or a session policy.** `scopes: ['documents:read']` compiles into a policy that allows exactly those actions
  on every resource; `policy` accepts a full [policy document](/docs/guides/authorization/policies) instead. Either one
  acts as a boundary: the key can do only what both the account's roles and the policy allow.
- **The issuer's grant authority.** A key is tied to the
  [grant authority](/docs/guides/authorization/roles) of the administrator who issued it and stays within that
  authority's ceiling. If the authority is revoked (for example when that administrator is offboarded), the key stops
  working.

A session token the key mints with [`sts.getSessionToken`](/docs/reference/api/sts#getsessiontoken) keeps both
limits. A role session it assumes with [`roles.assume`](/docs/reference/api/roles#assume) does not: the key's scopes
only decide whether it may assume the role (`iam:roles:assume`), and the role session then acts with the role's
permissions, bounded by the trust's ceiling and its own session `policy`. Scope the role or the trust, not only the
key.

A key is refused as soon as its account is disabled, expires, or is deleted. Operations that require recent
authentication, such as creating webhooks or keys, accept a key only during the first minutes after it was issued or
rotated (five minutes by default), because a key's authentication time is its creation time.

## Keeping keys clean

Every key has a `name` (at most 128 characters) and `description` for reviews, an `expiresAt` (90 days by default, at
most a year), and a `lastUsedAt` that is recorded at most once a minute and absent until first use. `list` with
`unusedForMs` finds keys nobody uses, [`analysis.findings`](/docs/reference/api/analysis#findings) reports them as
`stale-api-key`, and [`reports.access`](/docs/reference/api/reports#access) lists keys unused or ending soon. Expired
keys stay listed with `expired: true` until you renew or revoke them. Token material is never returned after
`create` and `rotate`; only a hash is stored.

## create

Issues an API key for an active service account and returns its token, which is shown only once.

- **Permission:** `iam:credentials:create` on the service account (`iam/{identityId}`), with recent authentication and
  an active grant authority.
- **Audited as:** `iam:credentials:create`, on the service account.
- **Errors:** `INVALID_IDENTITY` when the identity is not an active, unexpired service account; `NOT_FOUND` when it is
  not in this tenant; `INVALID_INPUT` for both `scopes` and `policy`, an empty `scopes` list, or `expiresInSeconds`
  outside 60 seconds to 365 days; `INVALID_ACTION` or `INVALID_POLICY` when the scopes or policy do not validate
  against the catalog; `GRANT_AUTHORITY_REQUIRED` when the caller holds no grant authority; `RECENT_AUTH_REQUIRED`;
  `IMPERSONATION_RESTRICTED`.

Because the permission is checked on the service account, you can let a team issue keys for its own integration
accounts only. Give every key the narrowest scopes that work and a name that says where it is deployed.

New keys are 58 characters that start with `biam_key_` and end in a checksum, so secret scanners (and the
`credentialTokenScanPattern` export of `@better-iam/auth`) can recognize a leaked one; keys issued before the format
existed keep working until they expire. For short-lived, narrower credentials derived from a key, such as one per CI
job, use [`sts.getSessionToken`](/docs/reference/api/sts#getsessiontoken) with the key as the caller.

```ts
const { token, credentialId, expiresAt } = await iam.api.credentials.create(credential, {
  tenantId,
  identityId: deployBotId,
  name: 'github-actions',
  description: 'Release workflow in acme/api',
  scopes: ['deployments:create', 'deployments:read'],
  expiresInSeconds: 30 * 86400,
});
// Store `token` in the CI secret store now; it cannot be read again.
```

## get

Returns one API key's label, lifetime, scopes, and last use, without token material.

- **Permission:** `iam:credentials:read` on the key.
- **Audited as:** `iam:credentials:read`.
- **Errors:** `NOT_FOUND` when the key is not in this tenant; `INVALID_CREDENTIAL` when the id belongs to a session
  that is not an API key.

`scopes` is present when the key was issued with `scopes` (its policy is exactly that list); otherwise `policy` shows
the session policy, if any. `credentialAuthorityId` names the grant authority the key was issued under.

## list

Lists the API keys of the tenant or of one service account, newest first, optionally only the unused ones.

- **Permission:** `iam:credentials:read` on the service account when `identityId` is given, otherwise on the tenant.
- **Audited as:** `iam:credentials:read`.
- **Errors:** `INVALID_INPUT` when `unusedForMs` is negative or more than ten years.

`unusedForMs` keeps only keys that have not authenticated a request in that long, counting keys never used since
they were issued. Expired keys are included, marked `expired: true`.

```ts
const stale = await iam.api.credentials.list(credential, { tenantId, unusedForMs: 60 * 86_400_000 });
for (const key of stale)
  await iam.api.credentials.revoke(credential, { tenantId, credentialId: key.id });
```

## revoke

Deletes an API key so it stops working immediately.

- **Permission:** `iam:credentials:revoke` on the key, with recent authentication.
- **Audited as:** `iam:credentials:revoke`.
- **Errors:** `NOT_FOUND` when the key is not in this tenant; `INVALID_CREDENTIAL` for any other kind of session
  (user sessions and role sessions end through their own calls); `RECENT_AUTH_REQUIRED`; `IMPERSONATION_RESTRICTED`.

Revocation cannot be undone; issue a new key if the integration still needs access. To stop every key of an account
at once, disable the account with [`serviceAccounts.setStatus`](/docs/reference/api/service-accounts#setstatus).

## rotate

Replaces an API key with a new token in one transaction, so the old token stops working the moment the new one exists.

- **Permission:** `iam:credentials:create` on the key, with recent authentication.
- **Audited as:** `iam:credentials:create`.
- **Errors:** `NOT_FOUND` when the key is not in this tenant; `INVALID_CREDENTIAL` when the id is not an API key;
  `ACCESS_DENIED` unless the caller issued the key (holds its grant authority) or is the platform root, or when that
  authority has been revoked; `RECENT_AUTH_REQUIRED`; `IMPERSONATION_RESTRICTED`.

The replacement gets a new `credentialId` and keeps the name, description, scopes or policy, and expiry of the old
key. Its usage history starts over, so it shows as unused until the integration uses it. Rotate on a schedule, or at
once when a token may have leaked; deploy the returned token before anything else, because the old one is already
dead.

## update

Relabels an API key or moves its expiry; the token itself does not change.

- **Permission:** `iam:credentials:create` on the key; changing `expiresAt` also requires recent authentication and
  the key's grant authority (the issuer, or the platform root).
- **Audited as:** `iam:credentials:create`.
- **Errors:** `INVALID_INPUT` when nothing is given to change, or `expiresAt` is not in the future or is more than a
  year away; `NOT_FOUND`; `INVALID_CREDENTIAL`; `ACCESS_DENIED` when changing the expiry of a key issued under
  another administrator's authority; `RECENT_AUTH_REQUIRED` when changing the expiry without recent authentication.

Pass `null` for `name` or `description` to clear it. `expiresAt` can shorten a key's life or extend it, including
renewing a key that has already expired, which then works again without a new token.
