# vault

The secrets vault keeps each tenant's secrets under path-like names: database passwords, upstream API keys, signing
keys. Secrets are versioned with stage labels, rotated with generated values and deployment-configured rotators,
handed out through time-limited check-outs, or minted per caller by a dynamic secret engine. Values are sealed with the
deployment secret, bound to tenant, secret and version, or encrypted under a customer-managed KMS key. Server code
reads secrets through `iam.vault` (no credential). The repository guide is `docs/secrets-vault.md`.

## Permissions and resources

Every method acts on `iam/vault/secrets/{name}`, so wildcards scope access by path (`iam/vault/secrets/prod/*`,
`iam/vault/secrets/users/${principal.id}/*`). Conditions see `resource.name`, `resource.kind`, `resource.format`,
`resource.status`, `resource.createdBy`, `resource.checkoutRequired`, `resource.rotationEnabled`,
`resource.customerManagedKey`, `resource.engine` and each tag as `resource.tag.{key}`. A name nobody uses has no
attributes, so tag conditions fail closed.

| Action             | Methods                                                                     |
| ------------------ | --------------------------------------------------------------------------- |
| `iam:vault:read`   | `get`, `listVersions`, `listLeases`, `accessLog`, and each row of `list`    |
| `iam:vault:reveal` | `reveal`                                                                    |
| `iam:vault:write`  | `put`, `promote`, `setStage`                                                |
| `iam:vault:rotate` | `rotate`                                                                    |
| `iam:vault:lease`  | `checkout`, `lease`                                                         |
| `iam:vault:manage` | `create`, `update`, `delete`, `restore`, `setVersionState`, `destroyVersion`, others' leases |

`reveal`, `checkout` and `lease` are refused in "view as" sessions. Changing a secret's tags is decided again with the
new tags. For a secret under a customer-managed key, `reveal` and `checkout` also need `iam:kms:decrypt` on that key,
`put` needs `iam:kms:encrypt`, `rotate` both, and moving the secret off the key needs `iam:kms:decrypt` on it; refusals
are `ACCESS_DENIED`.

## create

Creates a secret. A static secret may start with `value` (or `fields` for a `json` secret), with `generate` (`true` or
a generator), or without a value. A dynamic secret names an `engine` from the deployment's `vault.engines`, with
`engineConfig` and `lease` lengths, and stores no value.

- **Permission:** `iam:vault:manage` on `iam/vault/secrets/{name}`; `kmsKey` also needs `iam:kms:encrypt` on that key.
- **Audited as:** `vault:create`, with the name, kind, format, tags, first version, engine and key.
- **Errors:** `CONFLICT` (409) when the name is taken, including by a secret pending deletion; `LIMIT_EXCEEDED` (409)
  past `vault.maxSecretsPerTenant` (1000 by default); `INVALID_INPUT` for a malformed name, tags, value over
  `vault.maxValueBytes`, a `json` value that is not an object, an unknown rotator or engine, or settings that do not
  fit the kind; `ACCESS_DENIED` when the caller may not use `kmsKey`, or may not manage a secret with the new
  secret's attributes (a deny on `resource.engine`, say); `KEY_STATE_INVALID` (409) for a disabled key.

Names are 1 to 16 segments of letters, digits and `_.-` (not starting with `.` or `-`) separated by `/`, at most 256
characters. Up to 20 tags. `rotation` takes `intervalDays` (1-365), `generator`, `rotator` and, for json secrets,
`field`. `checkout` takes `required` (default true), `exclusive`, `maxDurationMs` (1 minute to 24 hours, default 1
hour), `rotateOnCheckin` and `requireReason`. `maxVersions` is 1-100 (default 10).

## update

Changes settings: `description` (`null` clears), `tags` (replaced), `maxVersions`, `rotation` and `checkout` (`null`
removes), a dynamic secret's `engineConfig` and `lease`, and `kmsKey` (a new key re-encrypts every kept version; `null`
moves them back under the deployment secret).

- **Permission:** `iam:vault:manage`, before and after the change; a new `kmsKey` also needs `iam:kms:encrypt` on it.
- **Audited as:** `vault:update`, with the resulting settings and how many versions were re-encrypted.
- **Errors:** `NOT_FOUND` (404); `SECRET_PENDING_DELETION` (409); `INVALID_INPUT` as for `create`; `ACCESS_DENIED`
  when the change would open a vault action on the secret to the caller that they did not have on it before (re-tagging
  a secret into what they may reveal).

## delete

Schedules the secret for deletion after `recoveryDays` (7-30, default 30), during which it can be restored but not read,
changed or leased; its check-outs end. `recoveryDays: 0` deletes it at once with its versions, leases and access
records, revoking live dynamic leases at their engine first. `iam.vault.purgeDeleted` removes secrets whose window has
ended.

- **Permission:** `iam:vault:manage`; `recoveryDays: 0` also needs recent authentication.
- **Audited as:** `vault:delete` (and `vault:purge` when the secret is removed).
- **Errors:** `NOT_FOUND` (404); `SECRET_PENDING_DELETION` (409) when already scheduled (unless `recoveryDays: 0`);
  `RECENT_AUTH_REQUIRED` (403) for `recoveryDays: 0` from a session that did not sign in recently.

## restore

Cancels a scheduled deletion.

- **Permission:** `iam:vault:manage`.
- **Audited as:** `vault:restore`.
- **Errors:** `NOT_FOUND` (404); `INVALID_TRANSITION` when the secret is not scheduled for deletion.

## get

A secret's metadata: kind, format, tags, status, stage labels, rotation schedule (with `due` and the last failure),
check-out policy, engine settings, key, live check-outs (who holds the value until when) and the number of live dynamic
leases. Never a value.

- **Permission:** `iam:vault:read`.
- **Errors:** `NOT_FOUND` (404).

## list

The secrets the caller may read, sorted by name, optionally under `prefix`, with all of `tags`, and by `status`
(`active` by default, `pending-deletion` or `all`), at most `limit` (1-500, default 100) from `offset`, with the `total`
the caller may see. Needs only a session of the tenant: each secret is decided like `iam:vault:read` on it. Not
audited.

## reveal

The value of the `current` version, or of `version` or `stage`: `value`, and `fields` for json secrets.

- **Permission:** `iam:vault:reveal`.
- **Audited as:** `vault:reveal` with the version; also recorded in the access log.
- **Errors:** `NOT_FOUND` (404) for a missing secret, version or stage; `SECRET_PENDING_DELETION` (409);
  `CHECKOUT_REQUIRED` (409) when the secret is handed out only through check-outs (a holder may reveal the version
  they checked out); `VERSION_DISABLED` (409); `VERSION_DESTROYED` (410); `INVALID_INPUT` for dynamic secrets;
  `ACCESS_DENIED` in "view as" sessions; `KEY_STATE_INVALID` (409) when the customer-managed key is disabled.

## put

Stores a new version from `value`, `fields` or `generate`. It becomes `current` (the old one `previous`) unless `stage`
names `pending` or a custom label. Versions past `maxVersions` that no label names are deleted.

- **Permission:** `iam:vault:write`.
- **Audited as:** `vault:put` with the version and stage.
- **Errors:** `NOT_FOUND` (404); `SECRET_PENDING_DELETION` (409); `LIMIT_EXCEEDED` (409) past 8 custom labels;
  `INVALID_INPUT` for a bad value, `stage: 'previous'`, or a dynamic secret.

## listVersions

Every kept version, newest first, with its state (`enabled`, `disabled`, `destroyed`), stage labels, source (`put`,
`generated`, `rotation`) and author. Never a value.

- **Permission:** `iam:vault:read`.

## promote

Makes an enabled version current; the old current version becomes `previous`. Rolls back as well as forward; rolling
back does not restart the rotation clock.

- **Permission:** `iam:vault:write`.
- **Audited as:** `vault:promote`, with the version and the previous current one.
- **Errors:** `NOT_FOUND` (404); `VERSION_DISABLED` (409) for a disabled or destroyed version.

## setStage

Points a custom stage label, or `pending`, at a version, or removes it with `version: null`. `current` and `previous`
move only through `put`, `promote` and `rotate`.

- **Permission:** `iam:vault:write`.
- **Audited as:** `vault:stage`.
- **Errors:** `NOT_FOUND` (404); `LIMIT_EXCEEDED` (409) past 8 custom labels.

## setVersionState

Disables a version (kept, but not revealed) or enables it again. The current version cannot be disabled.

- **Permission:** `iam:vault:manage`.
- **Audited as:** `vault:version-state`.
- **Errors:** `NOT_FOUND` (404); `INVALID_TRANSITION` for the current version; `VERSION_DESTROYED` (410).

## destroyVersion

Erases a version's value for good; its record stays as history and labels on it are removed. The current version
cannot be destroyed.

- **Permission:** `iam:vault:manage` and recent authentication.
- **Audited as:** `vault:destroy-version`.
- **Errors:** `NOT_FOUND` (404); `INVALID_TRANSITION` for the current version; `RECENT_AUTH_REQUIRED` (403).

## rotate

Rotates a static secret now: stages a new version as `pending` (generated, or `value` / `fields` when given), calls the
secret's rotator with it outside any transaction, then makes it current. A failing rotator leaves the pending version
for the next attempt (which passes the same value), records the error with secret values redacted, and schedules a
retry for scheduled rotations and secrets that rotate on check-in. Only a version the rotation staged itself is ever
retried: a `pending` label set with `put` or `setStage` is never passed to the rotator. A version disabled while the
rotator runs is not made current.

- **Permission:** `iam:vault:rotate`; a chosen `value` or `fields` also needs `iam:vault:write` and
  `iam:vault:reveal`, since the caller knows the new value.
- **Audited as:** `vault:rotate` (outcome `deny` when the rotator failed).
- **Errors:** `ROTATION_FAILED` (502); `NOT_FOUND` (404); `SECRET_PENDING_DELETION` (409); `INVALID_INPUT` for dynamic
  secrets, json secrets without `rotation.field` and without new fields, or a chosen value for a secret that only
  check-outs hand out; `ACCESS_DENIED` for a chosen value without `iam:vault:write` and `iam:vault:reveal`.

## checkout

Hands out a static secret's current value with a lease of `durationMs` (default and at most the policy's
`maxDurationMs`), with a `reason` when the policy asks for one. Only secrets with a check-out policy can be checked
out. Exclusive secrets have one holder at a time.

- **Permission:** `iam:vault:lease` (and `iam:kms:decrypt` on a customer-managed key).
- **Audited as:** `vault:checkout`, with the version, lease, expiry and reason.
- **Errors:** `SECRET_CHECKED_OUT` (409) when someone else holds an exclusive secret, or the caller already holds it;
  `INVALID_INPUT` without a check-out policy, without a required reason, or for dynamic secrets; `ACCESS_DENIED` in
  "view as" sessions.

## checkin

Returns a check-out. The session that took it needs no further permission, and the holder's other sessions (an agent
acting for them, another sign-in) need `iam:vault:lease` on the secret; anyone else needs `iam:vault:manage`. A secret
with `rotateOnCheckin` rotates once its last holder returns it; `rotated` names the new version.

- **Audited as:** `vault:checkin`.
- **Errors:** `NOT_FOUND` (404); `INVALID_TRANSITION` when the check-out already ended; `INVALID_INPUT` for a dynamic
  lease.

## lease

Asks a dynamic secret's engine for a credential minted for the caller, valid for `ttlMs` (default and at most from the
secret's `lease` settings). The credential is returned once and never stored.

- **Permission:** `iam:vault:lease`.
- **Audited as:** `vault:lease` (outcome `deny` when the engine failed).
- **Errors:** `ENGINE_FAILED` (502); `INVALID_INPUT` for static secrets; `ACCESS_DENIED` in "view as" sessions.

## renewLease

Extends the caller's live check-out or dynamic lease by `ttlMs` from now (default: the length it was issued for),
never past `maxExpiresAt`; tells the engine when it has `renew`. Holder only, and only while the holder still has
`iam:vault:lease` on the secret.

- **Audited as:** `vault:renew`.
- **Errors:** `INVALID_TRANSITION` when the lease ended; `LIMIT_EXCEEDED` (409) at the longest allowed length;
  `ENGINE_FAILED` (502).

## revokeLease

Ends a lease now: a check-out ends like a check-in (a secret with `rotateOnCheckin` rotates once its last holder is
gone, reported as `rotated`), a dynamic lease is revoked at its engine. The holder (from the session that took it, or
another that may lease the secret), or `iam:vault:manage` for anyone's. A revocation the engine refuses stays
`revoking` and is retried by `iam.vault.expireLeases` with backoff for seven days.

- **Audited as:** `vault:revoke`.
- **Errors:** `NOT_FOUND` (404); `INVALID_TRANSITION` when the lease already ended.

## listLeases

A secret's live check-outs and leases, or all kept history with `includeEnded`, newest first, with the holder's name
and reason.

- **Permission:** `iam:vault:read`.

## listMine

The caller's own live check-outs and leases in the tenant. Needs only a session of the tenant.

## accessLog

Who used a secret, newest first: reveals, check-outs and returns, leases, renewals, revocations, new versions and
rotations, with the person's name, session kind and agent. At most `limit` (1-500, default 100), optionally for one
`identityId`. Records stay `vault.accessRetentionDays` (90 by default).

- **Permission:** `iam:vault:read`.

## generate

A value from a generator without storing it: `length` 8-256 (default 32), `charset` (`alphanumeric`, `ascii`, `hex`,
`base64url`, `numeric`), `exclude`, and `eachClass`. Needs only a credential.
