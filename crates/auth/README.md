# better-iam-auth

Tenant-scoped authentication for [Better IAM](https://github.com/Better-IAM/better-iam) in Rust, the counterpart of
the `@better-iam/auth` npm package: password sign-up and sign-in (argon2id), sessions with idle and absolute
lifetimes, email verification and password recovery, magic links and one-time codes over email or SMS, TOTP with
recovery codes, emailed MFA codes, remembered devices, WebAuthn passkeys (sign-in and second factor), rate limits,
network blocks and allowlists, and a transactional outbox with ready-made message templates.

Everything it stores is byte-compatible with the TypeScript implementation, so TypeScript and Rust servers can serve
one deployment from one database:

- session tokens (`biam_ses_…` with a CRC-32 check) and their SHA-256 hashes;
- argon2id password hashes in node-argon2's PHC format (each implementation verifies the other's);
- values sealed with AES-256-GCM under the deployment secret (authenticator secrets, outbox payloads), including
  secret rotation;
- challenge digests (HMAC-SHA256), TOTP as otplib computes it, and the WebAuthn credential keys
  `@simplewebauthn/server` stores;
- every record shape (`sessions`, `authChallenges`, `authMfa`, `authPasskeys`, `authDevices`, `authSignIns`,
  `authRateLimits`, `passwordHistory`, `outbox`) and audit event (`auth:*`).

WebAuthn verification is a port of `@simplewebauthn/server` 13 on RustCrypto and `x509-cert` (no OpenSSL): `none`,
`packed` (self and full), `fido-u2f`, `tpm`, `android-key`, `android-safetynet` and `apple` attestation; ES256/384/512,
EdDSA, RS256/384/512, PS256/384/512 and RS1 signatures.

```rust,ignore
use better_iam_auth::{AuthOptions, create_auth};
use serde_json::json;

let auth = create_auth(AuthOptions::new(store, secret, "https://iam.example.com"))?;
let signed_in = auth
    .sign_in(&json!({ "tenantId": "org", "email": "ada@example.com", "password": "a long passphrase" }))
    .await?;
```

Methods mirror the TypeScript service (`signIn` → `sign_in`, `finishPasskeyAuthentication` →
`finish_passkey_authentication`); the ones the HTTP API exposes take the request body as JSON and validate it exactly
as the TypeScript methods do.

Licensed under Apache-2.0.
