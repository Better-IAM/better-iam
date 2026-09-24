# Data protection (tokenization)

Tokenization keeps sensitive values out of your application's databases, logs and analytics. Card numbers, national
identifiers, email addresses, phone numbers and free-text fields are replaced by **tokens**, which are safe to store,
index and pass between services. The values themselves are encrypted under a tenant [KMS key](key-management.md).
Turning a token back into its value (**detokenizing**) is a separate permission, decided per profile and per stated
purpose, and every call is audited. The model follows Skyflow, VGS and the de-identification side of Google DLP.

```ts
await iam.api.protection.createProfile(admin, {
  tenantId,
  name: 'cards',
  dataType: 'card',
  deterministic: true,
});

const { tokens } = await iam.api.protection.tokenize(checkout, {
  tenantId,
  profile: 'cards',
  values: ['4242 4242 4242 4242'],
});
// tokens[0] looks like '7304918265534242': same length, same last four digits, never a valid card number.

const { values } = await iam.api.protection.detokenize(paymentService, {
  tenantId,
  profile: 'cards',
  tokens,
  purpose: 'payment-processing',
});
```

Over HTTP the same calls are `POST {basePath}/protection/{method}`.

## Profiles

A **profile** says how one kind of value is handled. Its name is how policies refer to it: `iam/protection/{name}`.

| Option          | Meaning                                                                                                                                                    |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `dataType`      | `card`, `ssn`, `email`, `phone` or `generic`: how values are validated, normalized and tokenized                                                           |
| `format`        | `format-preserving` (default, except `generic`) or `random` (`tok_` and 22 base62 characters)                                                              |
| `deterministic` | The same value always gets the same token, so tokens can be joined, grouped and counted (see below for `ssn` and `phone`)                                  |
| `mask`          | How `mask` displays values; each data type allows its own styles (below)                                                                                   |
| `retentionDays` | Tokens are deleted this many days after they were issued                                                                                                   |
| `keyId`         | An existing AES key the caller may use (`iam:kms:generate-data-key` and `iam:kms:decrypt`); otherwise a new key the profile manages (`protection-profile`) |

The data type, format and key never change after the profile is created, because issued tokens depend on them.
`updateProfile` changes only the description, the mask and the retention. `getProfile` and `listProfiles` report how
many tokens each profile holds (`tokens`).

**Format-preserving `ssn` and `phone` profiles are always deterministic.** Their tokens keep the last four digits, which
leaves few random ones: 10,000 tokens per last four digits of a social security number, 1,000 for a seven-digit phone
number. Issuing a new token on every call would use them up, so these profiles default to `deterministic: true` and
refuse `false`. Use `format: 'random'` for non-deterministic tokens of these types.

### Values and tokens by data type

| `dataType` | Accepted values                                                                    | Format-preserving token                                                                                                                                |
| ---------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `card`     | 12 to 19 digits (spaces and dashes ignored), Luhn-valid                            | Same length and last four digits, and never Luhn-valid                                                                                                 |
| `ssn`      | 9 digits, stored as `NNN-NN-NNNN`                                                  | `9XX-`, group digits outside the ITIN ranges, and the last four: never a valid SSN or ITIN                                                             |
| `email`    | An email address, stored in Unicode NFC and lowercase                              | A random local part at the same domain (a deliverable-looking address: never send mail to tokens)                                                      |
| `phone`    | 7 to 15 digits with an optional `+`, compared as written (give them in E.164)      | Same length, leading `+` and last four digits                                                                                                          |
| `generic`  | 1 to 4096 characters of well-formed text, stored in NFC; tab and line feed allowed | Each letter of any script replaced by an ASCII letter (capitals by capitals), each digit by a digit, everything else kept (needs 12 letters or digits) |

A token is never the value itself. Values are normalized before they are tokenized. `4242 4242 4242 4242` and
`4242424242424242` are the same card, and composed and decomposed spellings of `José` are the same text, so a
deterministic profile gives them the same token, erasure by value finds both, and detokenizing returns the normalized
form. Phone numbers are not reformatted: `+14155550199` and `14155550199` are different values.

Control characters (DEL and the C1 range included), unpaired surrogates and bidirectional formatting characters are
refused: they would store or display as something other than what was sent.

### Masks

| `dataType` | Masks                                | Default |
| ---------- | ------------------------------------ | ------- |
| `card`     | `last4`, `first6last4`, `full`       | `last4` |
| `ssn`      | `last4`, `full`                      | `last4` |
| `email`    | `email` (`j***@example.com`), `full` | `email` |
| `phone`    | `last4`, `full`                      | `last4` |
| `generic`  | `full`, `last4`                      | `full`  |

A mask never shows more than half of a value's letters and digits: a seven-digit phone number shows its last three.
The one exception is `first6last4` on a card number of 15 digits or more, which PCI DSS allows; on a shorter card
number it shows the last four only. The `email` mask shows the first character of the local part only when it has
four or more. Letters and digits of every script are hidden.

## Calls

- `tokenize` takes up to 100 values of one profile and returns their tokens in order. All the new values of one call
  share one data key, which is wrapped under the profile's KMS key. The response does not say which values were
  already stored (that would tell the caller who else is); the audit event records it.
- `detokenize` takes up to 100 tokens of one profile and a `purpose`, and returns the values in order, with `null` for
  tokens the profile does not hold. The purpose is a short lowercase name such as `payment-processing`, `fraud-review`
  or `tax-filing`.
- `mask` returns the masked values (`************4242`, `j***@example.com`), with the profile's mask or a `style` its
  data type allows. It is a separate permission, so support staff can recognize a card without ever seeing it.
- `deleteTokens` erases tokens and their values for good, named by `tokens` or by `values`. Erasing by value finds
  every token issued for it through a keyed fingerprint, even in profiles that are not deterministic, which is what a
  data-subject erasure request needs. It needs the profile's KMS key enabled; erasing by token does not.

## Permissions

| Action                      | Resource                | Calls                                                                   |
| --------------------------- | ----------------------- | ----------------------------------------------------------------------- |
| `iam:protection:manage`     | `iam/protection/{name}` | `createProfile`, `updateProfile`, `deleteProfile`                       |
| `iam:protection:read`       | `iam/protection/{name}` | `listProfiles` (per profile), `getProfile`                              |
| `iam:protection:tokenize`   | `iam/protection/{name}` | `tokenize`                                                              |
| `iam:protection:detokenize` | `iam/protection/{name}` | `detokenize`                                                            |
| `iam:protection:mask`       | `iam/protection/{name}` | `mask`                                                                  |
| `iam:protection:delete`     | `iam/protection/{name}` | `deleteTokens`, and setting or shortening `retentionDays` (with manage) |

Conditions can use `resource.profile`, `resource.dataType`, `resource.format` and `resource.deterministic`.
`detokenize` adds `resource.purpose`, and `mask` adds `resource.style`: the style actually used, the profile's default
included.

```json
{
  "effect": "allow",
  "actions": ["iam:protection:detokenize"],
  "resources": ["iam/protection/cards"],
  "conditions": { "StringEquals": { "resource.purpose": "payment-processing" } }
}
```

Tokenizing and detokenizing are separate so that the services that collect data (checkout forms, import jobs) can be
allowed to tokenize without ever being able to read anything back. Callers from another tenant, and sessions that view
as someone else, are refused.

**Tokenizing into a deterministic profile is a lookup.** Whoever may tokenize can submit guesses and compare the tokens
with ones they hold: a format-preserving SSN token shows the last four digits, which leaves 100,000 candidates, one
thousand calls. Grant `iam:protection:tokenize` on deterministic profiles as narrowly as detokenize (conditions can
name `resource.deterministic`), and watch the `iam:protection:tokenize` audit events for volume.

Setting or shortening a profile's retention deletes tokens at the next sweep, so it needs `iam:protection:delete` as
well as `iam:protection:manage`, and a recent sign-in, like deleting the profile.

### Customer keys

A profile bound to an existing key (`keyId`) leaves the key's owner in charge, as the [vault](secrets-vault.md) does.
Every call needs the caller's own KMS permission on the key besides the protection one: `iam:kms:generate-data-key`
to tokenize, `iam:kms:decrypt` to detokenize or mask. Revoking those permissions, or disabling the key, stops the
profile. A key the profile created is managed by it (`managedBy: 'protection'`): the KMS API refuses to use it
directly (`KEY_MANAGED`), and deleting the profile schedules its deletion after 7 days. A key another profile or
module manages cannot be bound.

## How values are protected

- Each call that stores new values generates one data key, wraps it under the profile's AES KMS key (bound to the
  profile), and encrypts each value with AES-256-GCM. The associated data names the tenant, the profile and the token,
  so a stored ciphertext cannot be moved to another token. A stored value that fails authentication (altered in
  storage) is reported as `KEY_MATERIAL_UNAVAILABLE`.
- Disabling the KMS key makes every value of the profile unreadable (`KEY_STATE_INVALID`) and stops deterministic
  lookups until it is enabled again. Deleting the key destroys them for good.
- Every token stores an HMAC fingerprint of its value, in every profile: deterministic profiles find existing tokens
  by it, and erasure by value finds every token of a value. The fingerprint key is a data key wrapped under the
  profile's KMS key, so it stops with the key, and without it fingerprints cannot be tested against guesses. Its
  material lives in KMS, which `iam.rotateSecrets()` re-seals, so tokens stay the same across secret rotations.
- Tokens are unique per profile. SQL adapters index fingerprints (migration `0006_protection_indexes`), so
  deterministic lookups and erasure by value do not scan the tenant's tokens.
- The audit trail records the profile, the number of values or tokens, how many were found, and the purpose, for
  refusals too. It never records values or tokens. Uses of the KMS key are audited on the key with
  `via: 'protection'`. Plugin `afterOperation` hooks never see values or tokens.

## Retention

Run `iam.protection.sweep()` daily. It deletes tokens older than their profile's `retentionDays`, 500 per transaction
so the write lock is never held for a whole profile, audits each profile it emptied as `protection:retention-sweep`
(actor `deployment-operator`, with the number deleted), and returns `{ deleted, profiles }`. `deleteProfile` refuses a
profile that still holds tokens. Delete its tokens first, or let retention empty it.

## Errors

| Code                       | Status | When                                                                                       |
| -------------------------- | ------ | ------------------------------------------------------------------------------------------ |
| `INVALID_INPUT`            | 400    | A value that is not valid for the data type, a mask its type does not allow, a bad purpose |
| `KEY_STATE_INVALID`        | 409    | The profile's KMS key is disabled or pending deletion                                      |
| `KEY_MANAGED`              | 409    | Binding a key another profile or module manages                                            |
| `KEY_MATERIAL_UNAVAILABLE` | 500    | A stored value failed authentication (altered in storage)                                  |
| `RESOURCE_IN_USE`          | 409    | Deleting a profile that still holds tokens                                                 |
| `CONFLICT`                 | 409    | A profile name in use, or no free format-preserving token for a value                      |
| `ACCESS_DENIED`            | 403    | The profile, the purpose, the mask style or the customer key is not allowed                |
