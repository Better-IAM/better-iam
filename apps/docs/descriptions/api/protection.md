# protection

Data protection by tokenization. Sensitive values such as card numbers, national identifiers, email addresses, phone
numbers and free text are replaced by tokens that are safe to store and pass around. The values are encrypted under a
tenant KMS key, and turning a token back into its value is decided by policy per profile and stated purpose. Every
call is audited with counts, never with values or tokens. The repository guide is `docs/data-protection.md`.

## Profiles and policies

A profile handles one kind of value: its `dataType` (`card`, `ssn`, `email`, `phone`, `generic`), its token `format`
(`format-preserving` or `random`), whether tokens are `deterministic`, its display `mask` and its retention. Policies
name a profile as `iam/protection/{name}` and can use `resource.profile`, `resource.dataType`, `resource.format` and
`resource.deterministic`. `detokenize` adds `resource.purpose`, and `mask` adds `resource.style` (the style used, the
profile's default included). Tokenizing, detokenizing, masking and erasing are separate permissions, so the services
that collect data can be allowed to tokenize without ever reading anything back. Tokenizing into a deterministic
profile can test guesses against known tokens: grant it as narrowly as detokenizing.

A profile bound to a customer key (`keyId`) leaves the key's owner in charge: every call also needs the caller's
`iam:kms:generate-data-key` (tokenize) or `iam:kms:decrypt` (detokenize, mask) on the key. A key the profile created
is managed by it (`KEY_MANAGED` for direct KMS use) and is scheduled for deletion with the profile.

## createProfile

Creates a tokenization profile, with an existing tenant AES key the caller may use (`keyId`) or a new one.

- **Permission:** `iam:protection:manage` on `iam/protection/{name}`; with `keyId`, also `iam:kms:generate-data-key`
  and `iam:kms:decrypt` on the key.
- **Audited as:** `iam:protection:manage` (metadata: `profile`, `dataType`, `format`, `deterministic`, `keyId`).
- **Errors:** `INVALID_INPUT` for an unknown data type or format, a mask the data type does not allow, a
  non-deterministic format-preserving `ssn` or `phone` profile, or a key that is not `aes-256-gcm`; `KEY_MANAGED` for
  a key another profile or module manages; `CONFLICT` for a name in use; `LIMIT_EXCEEDED` past 100 profiles.

```ts
await iam.api.protection.createProfile(admin, {
  tenantId,
  name: 'cards',
  dataType: 'card',
  deterministic: true,
  retentionDays: 365,
});
```

## listProfiles

The tenant's profiles the caller may read, by name.

- **Permission:** `iam:protection:read`, evaluated for each profile.

## getProfile

One profile, with the number of tokens it holds.

- **Permission:** `iam:protection:read`.

## updateProfile

Changes the description, the mask, or the retention (`retentionDays: null` keeps tokens until they are deleted). The
data type, format and key never change.

- **Permission:** `iam:protection:manage`; setting or shortening `retentionDays` deletes tokens, so it also needs
  `iam:protection:delete` and recent authentication.

## deleteProfile

Deletes a profile that holds no tokens. A key the profile created is scheduled for deletion after 7 days.

- **Permission:** `iam:protection:manage`, with recent authentication.
- **Audited as:** `iam:protection:manage` (metadata: `profile`, `keyDeletionDate`).
- **Errors:** `RESOURCE_IN_USE` while tokens remain.

## tokenize

Replaces up to 100 values by tokens, in order. Values are validated and normalized for the data type (text to Unicode
NFC; a card number must pass the Luhn check). A deterministic profile returns the token it already issued for a value.
The response does not say which values were stored already; the audit event does.

- **Permission:** `iam:protection:tokenize` (and `iam:kms:generate-data-key` on a customer key).
- **Audited as:** `iam:protection:tokenize` (metadata: `profile`, `count`, `created`).
- **Errors:** `INVALID_INPUT` for a value the data type does not accept; `KEY_STATE_INVALID` when the profile's key is
  disabled.

## detokenize

Turns up to 100 tokens of the profile back into their values, in order, with `null` for tokens the profile does not
hold. `purpose` is required: a short lowercase name such as `payment-processing`.

- **Permission:** `iam:protection:detokenize`, with `resource.purpose` (and `iam:kms:decrypt` on a customer key).
- **Audited as:** `iam:protection:detokenize` (metadata: `profile`, `purpose`, `count`, `found`).
- **Errors:** `INVALID_INPUT` for a malformed purpose; `KEY_STATE_INVALID`.

## mask

The masked form of up to 100 tokens' values (`************4242`, `j***@example.com`), with the profile's mask or a
`style` its data type allows (`last4`, `first6last4` for cards, `email` for email addresses, `full`). A mask never
shows more than half of a value, except the first six and last four digits of a card number of 15 digits or more.

- **Permission:** `iam:protection:mask`, with `resource.style` (and `iam:kms:decrypt` on a customer key).
- **Audited as:** `iam:protection:mask` (metadata: `profile`, `style`, `count`, `found`).

## deleteTokens

Deletes tokens and their values for good, named by `tokens` or by `values`. Erasing by value finds every token issued
for it, even in profiles that are not deterministic.

- **Permission:** `iam:protection:delete`.
- **Audited as:** `iam:protection:delete` (metadata: `profile`, `deleted`, `by`).
