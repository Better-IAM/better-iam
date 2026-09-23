# @better-iam/auth

Independent tenant-scoped authentication for Better IAM. Authentication methods consume credentials, verify current identity and tenant state, and persist their state changes transactionally. Use the server package to expose these services over HTTP with origin and CSRF enforcement.

```ts
import { createAuth } from '@better-iam/auth';

const auth = createAuth({
  store,
  secret: process.env.BETTER_IAM_SECRET!, // At least 32 characters; use a random secret.
  baseURL: 'https://app.example.com',
  signUpEnabled: true,
  passwordlessEmail: true,
  passkeys: { rpID: 'app.example.com', rpName: 'My Product' },
  sendEmail: async ({ id, tenantId, to, template, payload }) => {
    // Deliver using your application provider. Deduplicate deliveries using id.
  },
});
```

Self-registration is disabled by default. Enabling it requires verified email and a `sendEmail` callback by default. Root accounts cannot self-register. `requireEmailVerification: false` is an explicit override. SMS requires an application callback and verified E.164 phone ownership. Passwordless authentication signs into an existing identity; it never links accounts by matching email.

Passwords use Argon2id. Session tokens are random opaque values; only their SHA-256 digests are stored. Sessions have a seven-day absolute lifetime and a one-day idle timeout by default; configure `sessionLifetimeMs` and `sessionIdleTimeoutMs`. Authentication checks current identity, MFA requirements, and every tenant ancestor on each request. HTTPS sessions use the `__Host-better-iam.session` cookie, with the unprefixed name restricted to loopback HTTP development.

MFA login returns `{ mfaRequired: true, challenge, enrollmentRequired }` until a second factor succeeds. A restricted challenge permits initial TOTP enrollment but cannot authenticate API calls. TOTP secrets are encrypted with AES-256-GCM; accepted time steps cannot be replayed. Recovery codes are stored only as hashes and are consumed once. Password recovery revokes sessions without removing MFA or issuing a new session. Root administrators and tenants requiring MFA cannot disable it.

Passkeys use SimpleWebAuthn with required user verification, RP/origin checks, globally unique credential IDs, identity-bound user handles, counters, and transactional one-use challenges. A verified passkey with user verification satisfies MFA. Enrollment and removal require recent authentication.

Email verification, recovery, passwordless codes, and phone verification use short-lived challenges. Low-entropy codes use a keyed digest and durable rate limits. Rate-limit attempts commit independently before credential validation. No plaintext delivery tokens are persisted: transactionally queued outbox payloads are encrypted and deleted after successful delivery.

Call `auth.dispatchOutbox()` from a worker or after committed operations. Delivery is at-least-once, uses leases to coordinate workers, and requires callback deduplication by message ID. Encryption keys must remain stable across all application workers and deployments; rotating the application secret invalidates encrypted MFA state and pending challenges unless the application migrates them deliberately.

`createIdentity`, `issueSession`, `completeAuthentication`, `revokeIdentity`, and `enqueueDelivery` are **trusted server integration primitives** accepting a transactional store. Do not expose these helpers as public endpoints. Protocol adapters must verify external identity proof before calling `completeAuthentication`; it enforces MFA before creating a session. The ordinary authentication API accepts opaque credentials rather than caller-supplied actors.

Supported end-user operations include signup/signin/signout, session listing/revocation, password and email changes, email/phone verification, passwordless email/SMS, TOTP enrollment/challenges/recovery, recovery-code rotation, MFA disable where allowed, passkey registration/authentication/listing/removal, and reauthentication. The server package maps these to its authenticated HTTP service boundary.
