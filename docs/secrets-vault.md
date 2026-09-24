# Secrets vault

The vault keeps an organization's secrets next to the identities and policies that decide who may use them: database
passwords, API keys for upstream services, signing keys, connection strings. It covers four jobs that usually need
separate products:

- **A secrets manager.** Named secrets with versions and stage labels (`current`, `previous`, `pending`), scheduled
  rotation with generated values, and rotators that apply a new value to the system it unlocks.
- **A password vault for shared privileged accounts.** Check-outs hand out a credential for a limited time, one person
  at a time if you like, with a reason, and can rotate it when it comes back.
- **Dynamic secrets.** An engine mints a fresh credential per caller (a short-lived database role, a cloud token) with a
  lease, and takes it back when the lease ends.
- **Encryption you control.** Values are sealed with the deployment secret, or under the organization's own
  [KMS key](key-management.md), so disabling that key makes them unreadable.

Access is decided like everything else in Better IAM: the `iam:vault:*` actions on `iam/vault/secrets/{name}`, with
the secret's tags available to policy conditions.

## Secrets and names

A secret lives in one tenant under a path-like name: 1 to 16 segments of letters, digits and `_.-` (not starting with
`.` or `-`), separated by `/`, at most 256 characters. Names are unique per tenant.

```ts
await iam.api.vault.create(admin, {
  tenantId,
  name: 'prod/payments/db-password',
  description: 'Primary payments database, app user',
  tags: { environment: 'prod', team: 'payments' },
  value: 'correct horse battery staple',
});

const { value, version } = await iam.api.vault.reveal(session, {
  tenantId,
  name: 'prod/payments/db-password',
});
```

A secret's `format` is `text` (the default) or `json`, which holds an object. Pass a json secret's value as `fields`
(or as a JSON string in `value`); `reveal` returns both `value` and the parsed `fields`.

```ts
await iam.api.vault.create(admin, {
  tenantId,
  name: 'prod/smtp',
  format: 'json',
  fields: { host: 'smtp.acme.test', username: 'mailer', password: 'mail-password' },
});
```

Values are at most 64 KiB by default (`vault.maxValueBytes`), and a tenant holds at most 1000 secrets
(`vault.maxSecretsPerTenant`).

## Who may do what

| Action             | Allows                                                                          |
| ------------------ | ------------------------------------------------------------------------------- |
| `iam:vault:read`   | Metadata: `get`, `list`, `listVersions`, `listLeases`, `accessLog`. No values.   |
| `iam:vault:reveal` | `reveal`: a stored value.                                                        |
| `iam:vault:write`  | New versions and stage labels: `put`, `promote`, `setStage`.                     |
| `iam:vault:rotate` | `rotate`.                                                                        |
| `iam:vault:lease`  | `checkout` of a static secret and `lease` of a dynamic one.                      |
| `iam:vault:manage` | `create`, `update`, `delete`, `restore`, version state, and ending others' leases. |

Every action applies to `iam/vault/secrets/{name}`, so wildcards scope access by path:

```json
{
  "version": 1,
  "statements": [
    {
      "sid": "PaymentsTeamReadsItsSecrets",
      "effect": "allow",
      "actions": ["iam:vault:read", "iam:vault:reveal"],
      "resources": ["iam/vault/secrets/prod/payments/*"]
    },
    {
      "sid": "PersonalSecrets",
      "effect": "allow",
      "actions": ["iam:vault:*"],
      "resources": ["iam/vault/secrets/users/${principal.id}/*"]
    }
  ]
}
```

Conditions see the secret's attributes: `resource.name`, `resource.kind` (`static` or `dynamic`), `resource.format`,
`resource.status`, `resource.createdBy`, `resource.checkoutRequired`, `resource.rotationEnabled`,
`resource.customerManagedKey`, `resource.engine`, and each tag as `resource.tag.{key}`:

```json
{
  "effect": "allow",
  "actions": ["iam:vault:reveal"],
  "resources": ["iam/vault/secrets/*"],
  "conditions": {
    "StringEquals": { "resource.tag.environment": "staging" },
    "Bool": { "principal.mfa": true }
  }
}
```

A name nobody uses yet has no attributes, so a tag condition never lets anyone create a secret; grant `manage` by path
for that. A new secret is decided again with its attributes (tags, kind, engine, settings), so a deny on
`resource.engine` refuses creating a secret bound to that engine. Every `update` is decided again too: the caller must
still be allowed to manage the secret afterwards, and the change may not open any vault action on it to them that they
did not have before. Re-tagging a `prod` secret as `staging` is refused for someone who may reveal only staging
secrets, however broad their `manage`. `list` returns only the secrets the caller may read, and needs no permission of
its own.

Values never leave through "view as": `reveal`, `checkout` and `lease` are refused in impersonation sessions, whatever
the member may do. Agents acting for a person are decided like any delegated session, so a delegation's `confirm` list
can hold `iam:vault:reveal` back for the person to approve call by call. Each approval opens one call, including the
`iam:kms:decrypt` a secret under a [customer-managed key](#customer-managed-keys) needs. Plugins'
`afterOperation` hooks see the answers of `reveal`, `checkout` and `rotate` without their values.

## Versions and stages

Every change of value is a new version. Stage labels point at versions:

- `current` is what callers get by default. `put` makes the new version current, and the old one becomes `previous`.
- `pending` holds a value that is not live yet: `put({ stage: 'pending' })`, then `promote({ version })`. Rotation
  uses it too.
- Up to 8 custom labels (`setStage`), such as `canary`.

```ts
await iam.api.vault.put(admin, { tenantId, name, value: 'new value' }); // version 2 is current
await iam.api.vault.reveal(session, { tenantId, name, stage: 'previous' }); // version 1
await iam.api.vault.promote(admin, { tenantId, name, version: 1 }); // roll back
```

`maxVersions` (default 10, at most 100) keeps the newest versions; older ones no label points at are deleted. A version
can be disabled (`setVersionState`), kept but not revealed, or destroyed (`destroyVersion`, only from a session signed
in within the last five minutes by default), which erases its value for good and keeps its record as history. The
current version can be neither.

## Rotation

`rotate` replaces a static secret's value in three steps: it stages a new version as `pending`, lets the secret's
rotator apply it to the system the secret unlocks, and then makes it current.

```ts
await iam.api.vault.create(admin, {
  tenantId,
  name: 'prod/payments/db-password',
  generate: true,
  rotation: {
    intervalDays: 30,
    rotator: 'postgres',
    generator: { length: 32, charset: 'ascii', exclude: '%' },
  },
});
```

- **Generators** draw from the operating system's CSPRNG: `length` 8 to 256 (default 32), `charset` `alphanumeric`
  (default), `ascii` (printable, without space, quotes, backslash or backtick), `hex`, `base64url` or `numeric`,
  `exclude` for characters a target rejects, and `eachClass` (default on) for at least one lowercase, uppercase, digit
  and symbol. `vault.generate` returns a value without storing it. A json secret names the field rotation replaces
  (`rotation.field`); its other fields are carried over.
- **Rotators** are functions you configure on the deployment. The rotator gets the pending value and the one being
  replaced; throwing fails the rotation.

```ts
const iam = betterIam({
  // ...
  vault: {
    rotators: {
      postgres: {
        async rotate({ tenantId, name, value, tags }) {
          await admin.query(`ALTER ROLE ${ident(tags.role!)} PASSWORD ${literal(value)}`);
        },
      },
    },
  },
});
```

A failed rotation keeps the pending version, records the error (with the new and old values, each field of a json
secret, and their JSON-, URL- and base64-encoded spellings replaced by `[redacted]`), and fails with
`ROTATION_FAILED`. The next attempt, by hand or on schedule, gives the rotator the same value, so rotators must be
idempotent. Scheduled retries back off from one hour to a day. Only a version the rotation itself staged is retried: a
value someone put under the `pending` label by hand is never handed to the rotator, so `iam:vault:write` cannot choose
the credential a rotator sets on the target system. `rotate({ value })` (or `fields`) chooses the new value and needs
`iam:vault:write` and `iam:vault:reveal` besides `iam:vault:rotate`, since the caller knows it; it is refused for
secrets that check-outs alone hand out, which always rotate to generated values. A version disabled while the rotator
runs is not made current.

With `intervalDays`, the secret is due that many days after its last new value (a `put` counts; rolling back with
`promote` does not). Run `iam.vault.rotateDue()` hourly: it rotates due secrets that have a generator or a rotator,
acting as `deployment-operator`. A due secret with neither, such as a key a vendor issues, is recorded once per due date
as `vault:rotation-due`; subscribe a [webhook](events.md) to remind its owners. `get` and `list` show
`rotation.due`, `nextRotationAt`, and the last failure.

Rotators and engines are called outside any database transaction, with a 30 second timeout (`vault.callTimeoutMs`).

## Check-outs for shared credentials

Some credentials are shared by a team: a break-glass root password, a vendor portal account. A check-out policy makes
the vault hand them out one use at a time:

```ts
await iam.api.vault.create(admin, {
  tenantId,
  name: 'break-glass/db-root',
  generate: true,
  checkout: {
    required: true, // reveal is refused (CHECKOUT_REQUIRED); only check-outs hand the value out
    exclusive: true, // one holder at a time (SECRET_CHECKED_OUT)
    maxDurationMs: 2 * 3_600_000, // 1 minute to 24 hours; 1 hour by default
    rotateOnCheckin: true, // a returned password stops working
    requireReason: true,
  },
});

const out = await iam.api.vault.checkout(operator, {
  tenantId,
  name: 'break-glass/db-root',
  reason: 'INC-1234: primary database unresponsive',
});
// out.value, out.leaseId, out.expiresAt
await iam.api.vault.checkin(operator, { tenantId, leaseId: out.leaseId });
```

Only secrets with a check-out policy can be checked out, so an `iam:vault:lease` grant meant for dynamic secrets never
hands out stored values. The holder may reveal the version they checked out while the check-out lasts, renew it
(`renewLease`, by the length it was issued for, never past the policy's longest duration, and only while they still
hold `iam:vault:lease`) and return it. The session that took a check-out may always return it, even after the holder's
access was taken away; the holder's other sessions (another sign-in, an agent acting for them, a narrower API key) act
on it only while they may lease the secret themselves. Anyone with `iam:vault:manage` can end someone else's check-out
(`revokeLease`). With `rotateOnCheckin`,
the secret rotates once its last holder returns it, however the check-out ended: checked in, ended with `revokeLease`,
or expired (`iam.vault.expireLeases`). A json secret that rotates on check-in must name `rotation.field`. A rotation
that fails after a return is recorded and retried by `iam.vault.rotateDue`. A scheduled rotation waits while the
secret is checked out. `get` shows who holds it and until when.

## Dynamic secrets

A dynamic secret stores no value. Each `lease` asks an engine for a credential minted for the caller:

```ts
const iam = betterIam({
  // ...
  vault: {
    engines: {
      postgres: {
        async issue({ leaseId, config, ttlMs, holder }) {
          const username = `v_${holder.id.slice(0, 8)}_${leaseId.slice(0, 8)}`;
          const password = randomPassword();
          const until = new Date(Date.now() + ttlMs).toISOString();
          await admin.query(
            `CREATE ROLE ${ident(username)} LOGIN PASSWORD ${literal(password)} VALID UNTIL ${literal(until)} IN ROLE ${ident(config.role)}`,
          );
          return { fields: { username, password }, handle: username };
        },
        async revoke({ handle }) {
          await admin.query(`DROP ROLE IF EXISTS ${ident(handle!)}`);
        },
      },
    },
  },
});

await iam.api.vault.create(admin, {
  tenantId,
  name: 'prod/analytics/readonly',
  kind: 'dynamic',
  format: 'json',
  engine: 'postgres',
  engineConfig: { role: 'analytics_readonly' },
  lease: { defaultTtlMs: 3_600_000, maxTtlMs: 8 * 3_600_000 },
});

const lease = await iam.api.vault.lease(analyst, { tenantId, name: 'prod/analytics/readonly' });
// lease.fields.username, lease.fields.password, lease.expiresAt
```

- The credential is returned once and never stored. The engine's `handle` (at most 4096 characters) is sealed and
  handed back to `revoke` and `renew`.
- `renewLease` extends a lease up to `lease.maxTtlMs` from its start, telling the engine when it has `renew`.
- `revokeLease` (the holder, or `iam:vault:manage`) revokes it at the engine. A revocation the engine refuses stays
  `revoking` and is retried by `iam.vault.expireLeases`, one minute later and then doubling up to six hours, for seven
  days; after that the lease is given up and recorded as `vault:revoke-failed`.
- `iam.vault.expireLeases()` (every few minutes) revokes expired leases and the leases of holders who may no longer
  have them: people and agents who were deactivated or deleted, agents whose sponsor left, and leases an agent took for
  a person under a delegation that was revoked or ran out. It looks at every live lease on each run, however many there
  are, and ends at most `limit` (default 1000) of each kind per run.
- An engine failure fails the call with `ENGINE_FAILED`. Once `issue` was called, whatever went wrong afterwards (an
  error, a timeout, a credential or handle the vault refuses, or the lease being revoked while it was issued), the
  lease is revoked at the engine by its `leaseId`, so engines must be able to find a credential by lease id when no
  handle came back.
- Deleting a dynamic secret for good waits until its live leases are revoked.

Engines should give credentials an expiry of their own (like `VALID UNTIL` above), so a revocation that keeps failing
cannot leave them working forever.

## Customer-managed keys

By default, values are sealed with the deployment secret (AES-256-GCM, bound to the tenant, secret and version, so a
sealed value cannot be moved to another record). `kmsKey` puts a secret's values under one of the organization's own
[KMS](key-management.md) encryption keys instead:

```ts
await iam.api.vault.create(admin, {
  tenantId,
  name: 'prod/signing-key',
  value: pem,
  kmsKey: 'alias/vault',
});
// Move an existing secret under the key (every kept version is re-encrypted), or back with kmsKey: null.
await iam.api.vault.update(admin, { tenantId, name: 'prod/smtp', kmsKey: 'alias/vault' });
```

As with AWS KMS, the key's owner keeps a say over the values:

- Binding a secret to a key needs `iam:kms:encrypt` on it as well as `iam:vault:manage`; moving a secret off its key
  (to another key or back to the deployment secret) needs `iam:kms:decrypt` on the current one.
- `reveal` and `checkout` need `iam:kms:decrypt` on the key besides the vault permission; `put` needs
  `iam:kms:encrypt`, and `rotate` both. The scheduler jobs and `iam.vault` are not asked.
- Every use appears in the key's audit trail as `iam:kms:encrypt` or `iam:kms:decrypt` with `metadata.via: 'vault'`.
- Disabling the key makes the values unreadable (`KEY_STATE_INVALID`) until it is enabled again. Deleting it destroys
  them for good.

Customer-managed keys are `aes-256-gcm` encryption keys; values of any size are envelope-encrypted with them.

## Deleting secrets

`delete` schedules the deletion after a recovery window of 7 to 30 days (`recoveryDays`, default 30). Meanwhile the
secret cannot be read, changed or leased, its check-outs end, its name stays taken, and `restore` brings it back.
`iam.vault.purgeDeleted()` (daily) deletes secrets whose window has ended, with their versions, leases and access
records, once their live dynamic leases are revoked at their engine (a refused revocation keeps the secret for the next
run). `recoveryDays: 0` deletes at once, and only from a session signed in within the last five minutes by
default (`RECENT_AUTH_REQUIRED` otherwise).

## Server code

The deployment's own code reads secrets without a credential through `iam.vault`:

```ts
const db = await iam.vault.get(tenantId, 'prod/payments/db-password');

// Replace vault:// references in a configuration object; each secret is read once.
const config = await iam.vault.resolve(tenantId, {
  smtp: { host: 'vault://prod/smtp#host', password: 'vault://prod/smtp#password' },
  stripeKey: 'vault://prod/stripe/secret-key',
});
```

`iam.vault` is not reachable over HTTP. It skips check-out rules and records nothing, so keep it to trusted code.

## From the command line

With `BETTER_IAM_TOKEN` (and `BETTER_IAM_TENANT` or `--tenant`), the [CLI](cli.md) reads and writes secrets and starts
programs with them:

```bash
better-iam vault-get prod/payments/db-password
printf %s "$NEW_PASSWORD" | better-iam vault-put prod/payments/db-password
better-iam vault-run --prefix prod/payments/ --env STRIPE_KEY=prod/stripe#secret -- node server.js
```

`vault-run` reveals the secrets and runs the command after `--` with them as environment variables, so they never
touch disk or shell history: `--env VAR=name[#field]` maps variables one by one, and `--prefix` adds every secret
under a path, named after the rest of its path (`prod/payments/db-password` becomes `DB_PASSWORD`; a json secret adds
one variable per field). The command inherits the terminal, its exit status becomes `vault-run`'s, and
`BETTER_IAM_TOKEN` is removed from its environment unless `--keep-token`. `vault-put` takes the value from standard
input or `--value-env`, never from the command line. The jobs run as `vault-rotate-due`, `vault-expire-leases` and
`vault-purge-deleted`.

Schedule the jobs:

| Job                          | How often         | Does                                                              |
| ---------------------------- | ----------------- | ----------------------------------------------------------------- |
| `iam.vault.rotateDue()`      | hourly            | Rotates due secrets; records `vault:rotation-due` for manual ones. |
| `iam.vault.expireLeases()`   | every few minutes | Ends expired check-outs and leases, retries failed revocations.    |
| `iam.vault.purgeDeleted()`   | daily             | Deletes secrets past their recovery window.                       |

`iam.sweepExpired()` deletes access records older than `vault.accessRetentionDays` (default 90), and
`iam.rotateSecrets()` re-seals vault values when the deployment secret changes (values under a customer-managed key are
unaffected).

## Audit and the access log

Every call is audited as its `iam:vault:*` action, and value-changing and value-returning calls also as `vault:create`,
`vault:update`, `vault:delete`, `vault:restore`, `vault:purge`, `vault:reveal`, `vault:put`, `vault:promote`,
`vault:stage`, `vault:version-state`, `vault:destroy-version`, `vault:rotate` (outcome `deny` when the rotator
failed), `vault:rotation-due`, `vault:checkout`, `vault:checkin`, `vault:checkout-expired`, `vault:lease` (`deny` when
the engine failed), `vault:renew`, `vault:revoke`, `vault:lease-expired` and `vault:revoke-failed`. Refused calls are
audited with outcome `deny` like any other.

`accessLog` answers "who used this secret" without searching the audit log: reveals, check-outs and returns, leases,
renewals, revocations, new versions and rotations, newest first, with the person's name, the session kind and the
agent, if one acted.

## Errors

| Code                      | Status | Meaning                                                                        |
| ------------------------- | ------ | ------------------------------------------------------------------------------ |
| `SECRET_PENDING_DELETION` | 409    | The secret is scheduled for deletion; restore it first.                        |
| `CHECKOUT_REQUIRED`       | 409    | The secret is handed out only through check-outs.                              |
| `SECRET_CHECKED_OUT`      | 409    | An exclusive secret is checked out by someone else (or already by the caller). |
| `VERSION_DISABLED`        | 409    | The version is disabled.                                                       |
| `VERSION_DESTROYED`       | 410    | The version's value was destroyed.                                             |
| `ROTATION_FAILED`         | 502    | The rotator failed; the pending version waits for the next attempt.            |
| `ENGINE_FAILED`           | 502    | The dynamic secret engine failed to issue or renew a credential.               |
| `KEY_STATE_INVALID`       | 409    | The secret's customer-managed key is disabled or pending deletion.             |
