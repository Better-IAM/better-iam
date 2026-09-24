# Temporary credentials

Better IAM has a security token service (STS) in the style of AWS STS: short-lived credentials derived from a signed-in session, an API key, or an external OpenID Connect token, each bounded by its source and re-validated on every use. This guide is the entry point: which calls exist, which session kinds they create, how tokens look, how signed session JWTs are verified by other services, how CI and Kubernetes workloads federate without stored secrets, and how to revoke all of it. Policies over the new session keys are in [policies](policies.md#session-context-keys); the guarantees are summarised in the [security model](security.md#temporary-credentials).

## AWS STS mapping

| AWS                                                                                                                                 | Better IAM                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AssumeRole`                                                                                                                        | `roles.assume({ tenantId, trustId, … })` through an identity trust (`trust.create`, root only)                                                                  |
| `GetSessionToken`                                                                                                                   | `sts.getSessionToken({ durationSeconds?, policy?, sessionName?, mfaCode?, format?, audience? })`                                                                |
| `AssumeRoleWithWebIdentity`                                                                                                         | `sts.assumeRoleWithWebIdentity({ tenantId, trustId, webIdentityToken, sessionName, … })` (public) through a web-identity trust and an OIDC provider             |
| `GetCallerIdentity`                                                                                                                 | `sts.getCallerIdentity()`; CLI `better-iam whoami`                                                                                                              |
| Revoke older sessions                                                                                                               | `roles.revokeSessions`, `trust.revokeSessions`, `oidcProviders.revokeSessions` (`before` watermark plus eager deletion)                                         |
| Role trust policy                                                                                                                   | `Trust`: `requireMfa`, `externalId`, `ceiling`, `allowedTagKeys`, `sourceIdentityMode`, `passSourceAttributes`; web trusts: `conditions` on `token.*`           |
| `MaxSessionDuration`                                                                                                                | `trust.maxSessionSeconds`, capped by `sts.maxRoleSessionSeconds` (and `sts.maxSessionTokenSeconds` for session tokens)                                          |
| Session policies                                                                                                                    | `policy` on every issuer: the credential can do only what both its grants and the policy allow                                                                  |
| Session tags, `RoleSessionName`, `SourceIdentity`                                                                                   | `tags`, `sessionName`, `sourceIdentity` on `roles.assume`; `tagClaims` and `sourceIdentityClaim` on web trusts                                                  |
| `aws:TokenIssueTime`, `aws:MultiFactorAuthAge`, `aws:SourceIp`, `aws:PrincipalTag/…`, `aws:SourceIdentity`, `aws:FederatedProvider` | `principal.tokenIssueTime`, `principal.mfaTime`, `request.sourceIp`, `principal.sessionTags.<key>`, `principal.sourceIdentity`, `principal.webIdentityProvider` |

Not supported: `AssumeRoleWithSAML`, `GetFederationToken`, role chaining and transitive tags, MFA codes on `roles.assume` (use `getSessionToken` with `mfaCode`, then assume), identity- and tenant-level watermarks (use `identities.revokeSessions` / `tenants.revokeSessions`, or a `DateBefore` deny on `principal.tokenIssueTime`), and general conditions on identity trusts.

## Session kinds

Every credential is a stored session row with a `kind`. The stored kind is authoritative; token prefixes only route and triage.

| Kind                   | Token prefix | Lifetime                                                                                                                        | Source                                                        | MFA                             | Revocation                                                                              | Cookie |
| ---------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------- | --------------------------------------------------------------------------------------- | ------ |
| `user`                 | `biam_ses_`  | `sessionLifetimeMs` (7 days) with an idle timeout (1 day)                                                                       | A sign-in                                                     | From the ceremony               | Sign-out, `revokeSession`, `identities.revokeSessions`, policy and status changes       | Yes    |
| `user` (impersonation) | `biam_ses_`  | At most 8 hours, never beyond the administrator's session                                                                       | `identities.impersonate`                                      | The administrator's             | The administrator signing out or being disabled                                         | No     |
| `api-key`              | `biam_key_`  | 90 days by default, at most a year                                                                                              | `credentials.create` / `rotate`                               | Never                           | `credentials.revoke`, rotation, the issuer's authority                                  | No     |
| `session-token`        | `biam_sts_`  | 60 s up to `sts.maxSessionTokenSeconds` (ceiling 43200 s by default; 3600 s when no duration is asked), never beyond the source | `sts.getSessionToken` from a user session or API key          | Copied, or fresh with `mfaCode` | Its source ending, `auth.revokeSession`, `identities.revokeSessions`                    | No     |
| `role`                 | `biam_rol_`  | 60 s up to the trust's maximum (default 900 s, cap 3600 s unless configured), never beyond the source                           | `roles.assume` from a user session, API key, or session token | Copied from the source          | Its source ending, trust revoke, watermarks, a revoked grant authority                  | No     |
| `role` (web identity)  | `biam_rol_`  | 60 s up to the trust's maximum (default 900 s); not bounded by the external token's `exp`                                       | `sts.assumeRoleWithWebIdentity`                               | Never                           | Trust revoke, provider disabled, watermarks, service account disabled, either authority | No     |

`role` and `session-token` are the temporary kinds (`temporarySessionKinds`). A temporary credential never outlives its source, is re-validated recursively against its source on every use, never passes `auth.requireRecent` (`RECENT_AUTH_REQUIRED`, "Temporary credentials cannot perform this operation; use a signed-in session"), is never treated as a tenant owner or root administrator (so never gets a root override), and is refused by self-service actions (accepting agreements, certification reviews, activating eligible bindings, access requests, package rules, access paths) with the same errors role sessions already got. `actsInOwnRight(session)` is the shared check: true only for `user` and `api-key`. Using a derived credential never refreshes the source's idle timer, so a leaked role session or session token cannot keep a person's browser session alive; long-running automation should mint session tokens from an API key.

Which credential may be the source of which flow:

| Flow                    | `user`                  | `user` (impersonation)     | `api-key`          | `session-token`                                     | `role`                         |
| ----------------------- | ----------------------- | -------------------------- | ------------------ | --------------------------------------------------- | ------------------------------ |
| `sts.getSessionToken`   | Yes (`mfaCode` allowed) | `IMPERSONATION_RESTRICTED` | Yes (no `mfaCode`) | `CREDENTIAL_CHAINING_DISABLED`                      | `CREDENTIAL_CHAINING_DISABLED` |
| `roles.assume`          | Yes                     | `IMPERSONATION_RESTRICTED` | Yes                | Yes (validation depth at most 2)                    | `ROLE_CHAINING_DISABLED`       |
| `sts.getCallerIdentity` | Yes                     | Yes                        | Yes                | Yes                                                 | Yes                            |
| `assertions.issue`      | Yes                     | Yes                        | Yes                | Yes, unless it carries a `policy` or `sourcePolicy` | Yes                            |

## Assuming a role

`roles.assume(credential, { tenantId, trustId, externalId?, durationSeconds?, policy?, sessionName?, sourceIdentity?, tags?, format?, audience? })` issues a role session in the trust's tenant. The caller needs `iam:roles:assume` on `iam/{roleId}` in its own tenant, and the trust must name the caller's identity and tenant. Refusals are `ACCESS_DENIED` "Role trust does not permit assumption" for a revoked trust, another source identity, an unmet `requireMfa`, a wrong or missing `externalId` (compared in constant time), a web-identity trust, a tag key the trust does not admit, or a source identity the trust forbids or requires; `ROLE_CHAINING_DISABLED` from a role session; `IMPERSONATION_RESTRICTED` from a "view as" session; `INVALID_INPUT` for malformed names, tags, durations, formats or audiences; `FEATURE_DISABLED` for `format: 'jwt'` without `sts.jwt`.

- `sessionName` and `sourceIdentity` match `/^[\w+=,.@-]{2,64}$/`. The name labels the session in audits and policies; the source identity names the person or workload behind an automated caller and is admitted only when the trust's `sourceIdentityMode` is `optional` or `required` (default `forbidden`).
- `tags`: at most 50, keys matching `/^[A-Za-z][A-Za-z0-9_]{0,63}$/` and unique case-insensitively, values of at most 256 letters, digits, spaces or `_.:/=+-@`, at most 2048 bytes packed. Every key must be in the trust's `allowedTagKeys` (default none; `['*']` admits any). Tags and source identities can satisfy ABAC conditions, which is why both are closed by default and only root opens them per trust.
- Duration: `max = min(sts.maxRoleSessionSeconds, trust.maxSessionSeconds ?? 3600, sts.jwt.maxLifetimeSeconds for JWTs)`, default `min(900, max)`, minimum 60. A request outside the range is `INVALID_INPUT`, never silently clamped; `expiresAt` is additionally clamped to the source's expiry and reported in the response.
- The session acts with the role's permissions, bounded by the trust's `ceiling`, the optional `policy`, the target tenant's boundaries and the role's grant authority. Unlike a session token it does not inherit the source's policy or credential authority: an API key's scopes or a session token's `policy` bound only the `iam:roles:assume` decision, which runs as the verified source at issuance and again on every use. A key scoped to `['iam:roles:assume']` can therefore obtain everything the role allows; to narrow a role session, narrow the role, the trust `ceiling` or the session `policy`.
- The session copies the source's `mfa`, `authenticatedAt`, and MFA time; it records the caller's client address (so the target tenant's allowlist and network blocks judge it) but never the sign-in method or remembered device.
- `role:assumed` is recorded in the target tenant with the trust, source tenant, source session kind, duration, format and tag keys, next to the `iam:roles:assume` operation event in the source tenant.

The response is a `RoleCredential`: `{ token, tokenType: 'Bearer', format, expiresAt, expiresIn, audience?, session: { id, tenantId, kind, identityId, expiresAt, mfa, roleId, trustId, sessionName?, sourceIdentity? } }`, a superset of the earlier `{ token, session: { id, tenantId, expiresAt, roleId } }`. The token appears only in the body.

Identity trusts gain typed knobs, changed later with the root-only `trust.update`: `maxSessionSeconds` (60 up to `sts.maxRoleSessionSeconds`), `passSourceAttributes`, `allowedTagKeys`, `sourceIdentityMode`, and `description`. `passSourceAttributes` decides whether the source identity's attributes reach policies as `principal.{attr}`: new cross-tenant trusts default to `false` so another tenant cannot steer this tenant's conditions, same-tenant and web trusts default to `true`, and trusts created before the option existed keep passing them until changed. `analysis.findings` reports live cross-tenant trusts that still pass attributes as `trust-passes-foreign-attributes`. Session tags are the explicit channel for passing data.

## Session tokens

`sts.getSessionToken(credential, { durationSeconds?, policy?, sessionName?, mfaCode?, format?, audience? })` (HTTP `POST {basePath}/sts/getSessionToken`) returns a `TemporaryCredential` for the caller's own identity. It is an operation on `iam:session-tokens:create` over `iam/{identityId}` in the identity's tenant: owners hold it through the Owner role, anyone else needs an explicit grant, and a deny gives administrators a lever (for example, to stop CI keys minting tokens). It is audited as the operation plus `session-token:issued`.

- The token acts with the identity's grants, bounded by `policy`, by the source's own policy (an API key's scopes, kept as `sourcePolicy`), and by the source's credential authority. It lasts `durationSeconds` (default 3600, at most `sts.maxSessionTokenSeconds`, default 43200) and never beyond its source, and ends when the source ends.
- `mfaCode` is accepted only from a user session whose identity has an authenticator: the attempt is counted against the sensitive rate limit first (`RATE_LIMITED`), then a first-hand TOTP code is verified with the same single-use rules as sign-in (`INVALID_MFA` for a wrong or replayed code; `MFA_NOT_ENROLLED` without an authenticator or from an API key; emailed and recovery codes never count), audited as `auth:mfa:step-up`. The token then carries `mfa: true` and a fresh `principal.mfaTime`. Without a code the source's MFA state is copied; API keys never carry MFA.
- Live tokens per identity are capped by `sts.maxSessionTokensPerIdentity` (default 50, `LIMIT_EXCEEDED`); tokens that can never be used again are deleted at issuance and do not count.
- The issuing client address is recorded: the tenant's `allowedIpRanges` judge it on every use, and network blocks judge both it and the presenting address.

The MFA-then-assume pattern for command-line tools: `getSessionToken({ mfaCode })` once, then `roles.assume` with the resulting token against a trust with `requireMfa: true`. Roles never take a code themselves.

```ts
const step = await iam.api.sts.getSessionToken(
  { token: userToken },
  { mfaCode: '123456', sessionName: 'ops-cli' },
);
const role = await iam.api.roles.assume(
  { token: step.token },
  { tenantId: customerTenantId, trustId, sessionName: 'ticket-4711' },
);
```

## Who am I, and who is in my tenant

`sts.getCallerIdentity(credential)` (HTTP `POST {basePath}/sts/getCallerIdentity`) re-validates any credential and returns an allowlist projection: `identityId`, `identityTenantId`, `identityKind`, `tenantId`, `sessionId`, `sessionKind`, `format`, `mfa`, `authenticatedAt`, `issuedAt`, `expiresAt`, and when set `method`, `roleId`, `trustId`, `sourceTenantId`, `sessionName`, `sourceIdentity`, `sessionTags`, `audience`, `webIdentity`, `impersonatorId`. It needs no permission and writes no audit event, so it is also the online revocation check for services holding a session JWT. `auth.getSession` stays user-only. The CLI's `whoami` prints it for `BETTER_IAM_TOKEN`.

`roles.listSessions({ tenantId, roleId?, trustId?, limit? })` (`iam:trust:read` on the role or tenant, `limit` 1..500, default 100) lists live role sessions newest first as `RoleSessionSummary` (`id`, `roleId`, `trustId`, `identityId`, `sourceTenantId?`, `sessionName?`, `sourceIdentity?`, `webIdentity?: { providerId, subject }`, `mfa`, `format`, `createdAt`, `expiresAt`, `clientIp?`), leaving out expired, revoked-trust and watermarked sessions. `clientIp` is omitted for cross-tenant role sessions, because it is the source person's address. None of these projections carries a token, hash, policy, source session id, or authority id. The source identity sees its own current credential through `getCallerIdentity`; source-side listing of assumed sessions is deferred.

## Revoking temporary credentials

| Call                                                                                                                            | Permission                                      | Ends                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `roles.revokeSessions({ tenantId, roleId, before? })`                                                                           | `iam:roles:revoke-sessions` on the role         | Every role session of the role (classic and web)                                                         |
| `trust.revokeSessions({ tenantId, trustId, before? })`                                                                          | `iam:roles:revoke-sessions` on the trust's role | The trust's sessions; delegable to the target tenant's admins                                            |
| `oidcProviders.revokeSessions({ tenantId, providerId, before? })`                                                               | `iam:roles:revoke-sessions` on the provider     | Web sessions of every trust that uses the provider                                                       |
| `trust.revoke` / `trust.update` (tightening)                                                                                    | as for the trust                                | All of the trust's sessions / sessions issued under the old rules                                        |
| `oidcProviders.update` changing keys, algorithms, audiences, `maxTokenLifetimeSeconds` or `clockToleranceSeconds`, or disabling | `iam:oidc-providers:update` on the provider     | Web sessions of every trust that uses the provider (a rename, `replayProtection` or enabling keeps them) |
| `identities.revokeSessions({ …, keepApiKeys? })`                                                                                | `iam:identities:update`                         | Every session of the identity; with `keepApiKeys: true`, all but its API keys                            |

Each `revokeSessions` call needs recent authentication, moves the record's `sessionsRevokedBefore` watermark to `max(current, before ?? now + 1)` (a `before` that is not a safe integer, is negative, or is later than now + 1 is `INVALID_INPUT`), deletes the matching rows through the indexed `roleId`, returns `{ sessionsRevokedBefore, revoked }`, and records `role:sessions-revoked`. Watermarks only move forward and never lie in the future, so they can neither resurrect a session nor block new issuance; a role session created before any of its role, trust or provider watermarks is refused with 401 "Role credential revoked", which also covers rows issued concurrently. Session tokens die through their source. `roles.update` and configuration sync keep the role's watermark. An `oidcProviders.update` that ends sessions moves the provider's watermark to now + 1 and deletes the rows in the same way, audited only as `iam:oidc-providers:update`; the updated provider carries the new `sessionsRevokedBefore`.

## Token format

Opaque credentials are `biam_<type>_<random><check>`: `type` is `ses` (user and impersonation sessions), `key` (API keys), `rol` (role sessions, including web identity) or `sts` (session tokens); `random` is 43 base64url characters (32 random bytes); `check` is 6 base64url characters of the big-endian CRC-32 of everything before it. The whole token is 58 characters of `[A-Za-z0-9_-]`. Only its SHA-256 is stored.

- A prefixed value whose shape or checksum is wrong is refused with 401 before any storage read, by the resolver and by `auth.authenticate` (cookies included). The checksum is public: it filters typos and garbage, it authenticates nothing.
- The stored kind must equal the prefix's kind (`credentialTokenKinds`: `ses` → `user`, `key` → `api-key`, `rol` → `role`, `sts` → `session-token`), else 401. The prefix is never trusted for authorization.
- Legacy unprefixed 43-character tokens keep working until they expire.
- Scanner pattern (`credentialTokenScanPattern` from `@better-iam/auth`): `(?<![A-Za-z0-9_-])biam_(?:ses|key|rol|sts)_[A-Za-z0-9_-]{49}(?![A-Za-z0-9_-])`. Scanners without lookbehind use `biam_(ses|key|rol|sts)_[A-Za-z0-9_-]{49}` with explicit boundary rules. `newCredentialToken(type)` and `parseCredentialToken(value)` produce and check the format.

Challenges, invitations, remembered devices, webhook secrets, OAuth tokens and assertions keep their own formats.

## Session JWTs

Role sessions and session tokens (never user sessions or API keys) can be issued as signed JWTs with `format: 'jwt'` on `roles.assume`, `sts.getSessionToken` and `sts.assumeRoleWithWebIdentity`, once the deployment configures `sts.jwt` (otherwise `FEATURE_DISABLED`). They are hybrid: other services verify them offline, while IAM still requires the stored row.

- Header: `{ alg: 'EdDSA' | 'ES256', kid, typ: 'biam-session+jwt' }`; at most 4096 characters; never prefixed.
- Claims: `iss`, `aud` (a string for one audience, else an array), `sub` (identity), `tid` (tenant), `sid` = `jti` (session id), `iat` = `nbf`, `exp`, `auth_time`, `kind` (`role` or `session-token`), `mfa`, and when set `role`, `trust`, `src_tid`, `session_name`, `source_identity`, `idp` (provider id), `idp_sub`. Tags, policies, authority ids, the source session id and hashes are never included; read tags online through `getCallerIdentity`.
- `audience`: 1 to 5 entries from `sts.jwt.audiences` (the issuer is always allowed and is the default). Every audience other than the issuer must also be allowed as `iam:assertions:create` on `iam/{aud}` for the credential being issued (`ACCESS_DENIED` otherwise), so a scoped-down credential cannot name a service its scope forbids.
- Lifetime: the duration bounds already include `sts.jwt.maxLifetimeSeconds` (default 3600); a longer request is `INVALID_INPUT`.
- Inside IAM, a JWT bearer is accepted only when its signature, `typ`, algorithm (pinned per `kid`), issuer, audience (which must contain the IAM issuer), times and lifetime verify, and the row `sessions/{sid}` has `format: 'jwt'`, the same kind, identity and tenant, and `tokenHash` equal to the token's SHA-256. Then the usual per-use validation runs. A token for a downstream audience only is refused by IAM.

`GET {basePath}/.well-known/jwks.json` publishes the public signing and verification keys (`kty`, `crv`, `x`, `y`, `kid`, `alg`, `use: 'sig'` only) as `application/jwk-set+json` with `Cache-Control: public, max-age=300`, and returns 404 without `sts.jwt`. The same set is `iam.sessionTokens.jwks()`; `iam.sessionTokens.verify(token, { audience? })` verifies in process and also requires the stored session to be live (reason `revoked` otherwise).

Revocation semantics:

| Event                                                                         | Inside IAM (`authorize`, `getCallerIdentity`, `iam.sessionTokens.verify`) | Offline verifier (`createSessionTokenVerifier`) |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ----------------------------------------------- |
| Source sign-out, rotation, `revokeSessions`, `trust.revoke`, identity revoked | Refused on the next request                                               | Accepted until `exp`                            |
| Watermark moved, provider or service account disabled, authority revoked      | Refused on the next request                                               | Accepted until `exp`                            |
| `kid` removed from both `signingKeys` and `verificationKeys`                  | Refused on the next request                                               | Refused once its JWKS cache refreshes           |
| `exp` passed                                                                  | Refused                                                                   | Refused (5 s clock tolerance)                   |

Use 5 to 15 minute tokens for high-risk services, or check online with `sts.getCallerIdentity` (HTTP) or `iam.sessionTokens.verify` (in process). Removing a key early is the emergency revoke for every token it signed, legitimate ones included.

Key rotation runbook (signing keys are independent of `options.secret`, so secret rotation never touches them):

1. Add the new private key to `sts.jwt.signingKeys` and deploy. It is published but not yet used.
2. Wait at least the JWKS `max-age` plus your verifiers' cache time (15 minutes with the defaults: the 300 s `max-age` plus a verifier's 600 s cache).
3. Set `activeKeyId` to the new `kid` and deploy.
4. Move the old key's public part to `verificationKeys` (private members there are an `INVALID_CONFIG`).
5. Remove it once `maxLifetimeSeconds` has passed.

Generate an Ed25519 key with `jose`: `const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true }); const jwk = { ...(await exportJWK(privateKey)), kid: '2026-09', alg: 'EdDSA', use: 'sig' };`. Keep private JWKs in your secret store like `secret`.

## Verifying session JWTs in other services

`better-iam/session-tokens` (also `@better-iam/server/session-tokens`) is runtime-neutral: it imports only `jose`, never `node:*`, so it runs in Node, Bun, Deno, workers and edge middleware. `createSessionTokenVerifier({ issuer, audience, jwks, algorithms?, kinds?, clockToleranceSeconds?, maxLifetimeSeconds?, now?, cacheMaxAgeSeconds?, cooldownSeconds?, timeoutMs? })` enforces the same type, algorithm allowlist, issuer, audience (any of the configured ones), lifetime, kind and claim checks as IAM. `jwks` is a key set (`iam.sessionTokens.jwks()`, algorithms pinned per `kid`) or the JWKS URL, which must be https except on localhost and is cached (`cacheMaxAgeSeconds`, default 600) and refetched on an unknown `kid` at most once per `cooldownSeconds` (default 30). `verify(token)` and `verifyRequest({ headers })` (case-insensitive `Bearer`) return the claims or throw `SessionTokenError` (`code: 'INVALID_SESSION_TOKEN'`, `status: 401`, and a `reason` such as `expired`, `audience`, `signature`, `unknown-key` or `jwks` for logs only).

```ts
// session-tokens.ts, shared by the examples below
import { createSessionTokenVerifier, SessionTokenError } from 'better-iam/session-tokens';

export const verifier = createSessionTokenVerifier({
  issuer: 'https://iam.example.com/api/iam', // `${baseURL.origin}${basePath}` unless sts.jwt.issuer overrides it
  audience: 'https://billing.example.com', // must be in sts.jwt.audiences and requested at issuance
  jwks: 'https://iam.example.com/api/iam/.well-known/jwks.json',
});
export { SessionTokenError };
```

Plain Node:

```ts
import { createServer } from 'node:http';

createServer(async (request, response) => {
  try {
    const claims = await verifier.verifyRequest({
      headers: { authorization: request.headers.authorization ?? '' },
    });
    response.end(`hello ${claims.sub} in ${claims.tid}`);
  } catch (error) {
    response.writeHead(error instanceof SessionTokenError ? 401 : 500).end();
  }
}).listen(8080);
```

Next.js middleware (edge):

```ts
import { NextResponse, type NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  try {
    const claims = await verifier.verifyRequest(request);
    const headers = new Headers(request.headers);
    headers.set('x-caller', claims.sub);
    return NextResponse.next({ request: { headers } });
  } catch {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }
}
export const config = { matcher: '/api/billing/:path*' };
```

Hono:

```ts
app.use('/billing/*', async (c, next) => {
  try {
    c.set('claims', await verifier.verifyRequest(c.req.raw));
  } catch {
    return c.json({ error: 'unauthorized' }, 401);
  }
  await next();
});
```

Express:

```ts
app.use('/billing', async (req, res, next) => {
  try {
    res.locals.claims = await verifier.verifyRequest({
      headers: { authorization: req.get('authorization') ?? '' },
    });
    next();
  } catch {
    res.status(401).json({ error: 'unauthorized' });
  }
});
```

Fastify:

```ts
app.addHook('onRequest', async (request, reply) => {
  try {
    request.claims = await verifier.verifyRequest({
      headers: { authorization: request.headers.authorization ?? '' },
    });
  } catch {
    return reply.code(401).send({ error: 'unauthorized' });
  }
});
```

SvelteKit (`hooks.server.ts`):

```ts
export const handle: Handle = async ({ event, resolve }) => {
  if (event.url.pathname.startsWith('/api/billing')) {
    try {
      event.locals.claims = await verifier.verifyRequest(event.request);
    } catch {
      return new Response('unauthorized', { status: 401 });
    }
  }
  return resolve(event);
};
```

NestJS guard:

```ts
@Injectable()
export class SessionTokenGuard implements CanActivate {
  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    try {
      request.claims = await verifier.verifyRequest({
        headers: { authorization: request.headers.authorization ?? '' },
      });
      return true;
    } catch {
      throw new UnauthorizedException();
    }
  }
}
```

A service that must honour revocation immediately calls `POST {basePath}/sts/getCallerIdentity` with the bearer (or `iam.sessionTokens.verify` when it runs in the IAM process) instead of, or after, the offline check. Services that run inside the IAM application need none of this: `iam.authenticate`, Next `apiRoute`, the NestJS `IamGuard` and every `iam.api` call accept session JWTs and opaque temporary tokens as bearers.

## Web-identity federation

`sts.assumeRoleWithWebIdentity` lets a workload exchange the OIDC token its platform already issues (GitHub Actions, GitLab CI, Kubernetes, cloud workload identity) for a role session, so no IAM secret is stored in CI. It is off until `sts.webIdentity.enabled: true`.

Setup, as a tenant administrator (each step needs recent authentication):

1. Create a service account for the workload (`serviceAccounts.create`). Sessions act as it, so audits attribute each workload separately; use one per workload.
2. Register the provider: `oidcProviders.create({ tenantId, name, issuer, audiences, jwksUri?, jwks?, algorithms?, maxTokenLifetimeSeconds?, clockToleranceSeconds?, replayProtection?, enabled? })` (`iam:oidc-providers:create`). The issuer must be https, not IAM's own, and on `sts.webIdentity.allowedIssuers` when that is set. Without `jwks` or `jwksUri`, keys come from OIDC discovery.
3. Create a web trust: `trust.create({ tenantId, kind: 'web-identity', providerId, serviceAccountId, roleId, conditions, tagClaims?, sourceIdentityClaim?, maxSessionSeconds?, ceiling?, passSourceAttributes?, description? })` (`iam:trust:create` on the role; not root-only). The role must not be protected and the service account must be active.
4. The workload posts to `POST {basePath}/sts/assumeRoleWithWebIdentity` with JSON and `X-Better-IAM: 1` (no cookie, no credential) and uses the returned token as `Authorization: Bearer`.

Conditions use the policy condition grammar over the verified token's claims, flattened to `token.<claim>` keys: nested objects to depth 3 joined with `.` (Kubernetes' `kubernetes.io.namespace` becomes `token.kubernetes.io.namespace`), strings up to 1024 characters, numbers, booleans and arrays of up to 64 scalars, at most 128 keys. Keys match `/^token\.[A-Za-z0-9_:.-]{1,122}$/`, at most 20 entries, no `${…}` variables. They must pin `token.sub` with `StringEquals` or `StringLike` whose values are non-empty and, for `StringLike`, put any `*` or `?` only after two complete segments ended by `:` or `/` (`repo:acme/*` and `repo:acme/api:*` are accepted; `*`, `repo:*` and `repo:acme*`, which would also admit `acme-evil`, are not), else `WEAK_TRUST_CONDITIONS`, which prevents the "any repository" misconfiguration. Conditions are evaluated only at exchange time, never re-evaluated per request. `tagClaims` (at most 10) maps session tag keys to claim names (only string claims of at most 256 characters in the tag charset become tags); `sourceIdentityClaim` names the claim that becomes `principal.sourceIdentity`, and a token without a valid one is refused.

The session is kind `role` acting as the service account, with `session.webIdentity = { providerId, issuer, subject }`, `mfa: false`, `authenticatedAt` = exchange time, and `sessionName` required. Its duration follows `roleDurationBounds` (default 900 s) and is not bounded by the external token's `exp`. It is bounded by the role, the trust's ceiling, the optional `policy`, the grant authority of the trust's creator (`credentialAuthorityId`) and of the provider's creator (a narrow provider authority also narrows other administrators' trusts on it). Disabling the provider (`oidcProviders.update({ enabled: false })`, allowed even with the feature off) or the service account, revoking the trust or either authority, or a watermark ends live sessions at their next use. Disabling the provider, or changing its keys, algorithms, audiences, `maxTokenLifetimeSeconds` or `clockToleranceSeconds`, also moves its watermark and deletes every session issued through it so far, for good: re-enabling does not restore them, and workloads must exchange a fresh token. Renaming it or changing `replayProtection` keeps them.

Order of checks and errors: the feature flag (`FEATURE_DISABLED`), then input shape only (`INVALID_INPUT`; token at most 8192 characters), then the per-trust rate limit `web-identity:{trustId}` (`sts.webIdentity.maxExchangesPerWindow`, default 600 per window, plus network blocks and `rateLimits.ipAttempts` when configured) before any lookup. Every failure that depends on stored state or the token is `WEB_IDENTITY_REJECTED` (403) "The web identity token was not accepted", with an identical body for an unknown trust, a revoked trust, a disabled provider, any verification failure, unmet conditions, replay, an inactive service account or tenant, or a revoked authority. Only after a verified token matched the trust do specific errors surface: `RATE_LIMITED`, `IP_BLOCKED`/`IP_NOT_ALLOWED`, `LIMIT_EXCEEDED` (`sts.webIdentity.maxSessionsPerTrust`, default 1000 live sessions), `INVALID_INPUT`/`INVALID_POLICY` for duration, policy, format or audience, `FEATURE_DISABLED` for a JWT without keys, and `ACCESS_DENIED` for audiences. Audits are `role:assumed-with-web-identity` (allow, or deny with `metadata.reason`), written only once the trust resolved in its tenant; issuer and subject appear only when the signature verified; the raw token is never stored or recorded.

Replay: with `replayProtection: 'single-use'` (default) each token is redeemed once per provider, keyed by `jti` (or, without one, by the hash of the token's signed content, `header.payload`, so a re-encoded or ECDSA-malleated signature of the same token is still the same token) in the `webIdentityReplays` collection inside the issuance transaction, so a failed issuance does not burn it; retention sweeps the rows after the token's expiry plus clock tolerance. Because the key is per provider, a token can be redeemed once at each tenant whose provider trusts its issuer and audience; the audience and subject pins bind each workload. `'off'` suits tokens that SDKs reuse until the file rotates (Kubernetes projected tokens).

### GitHub Actions

```ts
const provider = await iam.api.oidcProviders.create(admin, {
  tenantId,
  name: 'GitHub Actions',
  issuer: 'https://token.actions.githubusercontent.com',
  audiences: ['https://iam.example.com'],
});
const trust = await iam.api.trust.create(admin, {
  tenantId,
  kind: 'web-identity',
  providerId: provider.id,
  serviceAccountId: deployBotId,
  roleId: deployerRoleId,
  conditions: {
    StringEquals: {
      'token.sub': 'repo:acme/app:ref:refs/heads/main',
      'token.repository_owner': 'acme',
    },
  },
  tagClaims: { repository: 'token.repository', workflow: 'token.workflow' },
  maxSessionSeconds: 1800,
});
```

```yaml
permissions:
  id-token: write # lets the job request an OIDC token
  contents: read
steps:
  - name: Get an IAM role session
    run: |
      ID_TOKEN=$(curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://iam.example.com" | jq -r .value)
      IAM_TOKEN=$(curl -sf https://iam.example.com/api/iam/sts/assumeRoleWithWebIdentity \
        -H 'Content-Type: application/json' -H 'X-Better-IAM: 1' \
        -d "{\"tenantId\":\"$TENANT_ID\",\"trustId\":\"$TRUST_ID\",\"webIdentityToken\":\"$ID_TOKEN\",\"sessionName\":\"gha-$GITHUB_RUN_ID\"}" \
        | jq -r .data.token)
      echo "::add-mask::$IAM_TOKEN"
      echo "BETTER_IAM_TOKEN=$IAM_TOKEN" >> "$GITHUB_ENV"
```

Pull-request workflows present `repo:acme/app:pull_request` as the subject; environment-protected jobs present `repo:acme/app:environment:production`. Pin the one you mean.

### Kubernetes

Register the cluster's service account issuer (for example `https://oidc.eks.eu-west-1.amazonaws.com/id/ABC123`, or your cluster's `--service-account-issuer`). Discovery must be reachable over public https on port 443; for a private API server, pass the keys as static `jwks` (`kubectl get --raw /openid/v1/jwks`) and update them when the cluster rotates, or route fetches through `sts.webIdentity.fetchJson`. Every change to static `jwks` (adding the new key included) ends all live sessions issued through the provider, so the cluster's workloads must exchange again at their next call; a fetched `jwksUri` or discovery rotates without ending sessions. Set `replayProtection: 'off'`, because the projected token is reused until the kubelet rotates it, and keep `maxTokenLifetimeSeconds` at or above the projection's `expirationSeconds`.

```ts
await iam.api.trust.create(admin, {
  tenantId,
  kind: 'web-identity',
  providerId: clusterProviderId,
  serviceAccountId: exporterAccountId,
  roleId: readerRoleId,
  conditions: {
    StringEquals: {
      'token.sub': 'system:serviceaccount:billing:exporter',
      'token.kubernetes.io.namespace': 'billing',
    },
  },
});
```

The pod mounts a projected service account token with `audience` set to one of the provider's `audiences` and posts it as `webIdentityToken`.

### Debugging a refusal

`trust.evaluateWebIdentity({ tenantId, trustId, webIdentityToken })` (`iam:trust:read`) runs verification, conditions and claim mapping without issuing anything or writing a replay record, and returns `{ verified, reason?, claims?, conditions?: { matched, failed }, sessionTags?, sourceIdentity? }`: `reason` is a verification failure (`malformed`, `type`, `algorithm`, `unknown-key`, `signature`, `issuer`, `audience`, `expired`, `not-yet-valid`, `too-old`, `lifetime`, `claims`, `jwks-unavailable`), `conditions` or `source-identity`, or a stored-state reason the exchange would also refuse for (`trust`, `provider`, `role`, `service-account`, `authority`), and `failed` lists each unmet entry as `Operator:key`. The deny audits carry the same reason.

## Options and limits

| Option                                                           | Default                        | Range         | Effect                                                               |
| ---------------------------------------------------------------- | ------------------------------ | ------------- | -------------------------------------------------------------------- |
| `sts.maxRoleSessionSeconds`                                      | 3600                           | 900..43200    | Ceiling for role sessions; trusts can only lower it                  |
| `sts.maxSessionTokenSeconds`                                     | 43200                          | 900..129600   | Ceiling for session tokens                                           |
| `sts.maxSessionTokensPerIdentity`                                | 50                             | 1..1000       | Live session tokens per identity                                     |
| `sts.jwt.signingKeys`                                            | none (JWTs disabled)           | 1..10 keys    | Ed25519/EdDSA or P-256/ES256 private JWKs with unique `kid`s         |
| `sts.jwt.activeKeyId`                                            | the first signing key          |               | Which key signs                                                      |
| `sts.jwt.verificationKeys`                                       | none                           | 0..10 keys    | Public-only retired keys that still verify                           |
| `sts.jwt.issuer`                                                 | `${baseURL.origin}${basePath}` |               | The `iss` claim                                                      |
| `sts.jwt.audiences`                                              | the issuer                     |               | Audiences tokens may name; the issuer is always included             |
| `sts.jwt.maxLifetimeSeconds`                                     | 3600                           | 300..43200    | Longest JWT                                                          |
| `sts.webIdentity.enabled`                                        | `false`                        |               | Turns federation on                                                  |
| `sts.webIdentity.allowedIssuers`                                 | any https issuer               | at most 100   | Deployment-wide issuer pin list                                      |
| `sts.webIdentity.jwksCacheSeconds`                               | 600                            | 60..3600      | Provider key cache                                                   |
| `sts.webIdentity.fetchTimeoutMs`                                 | 5000                           | 500..10000    | Discovery and JWKS fetch timeout                                     |
| `sts.webIdentity.maxJwksBytes`                                   | 65536                          | 1024..1048576 | Largest discovery or JWKS response                                   |
| `sts.webIdentity.maxExchangesPerWindow`                          | 600                            | 1..100000     | Exchanges per trust per rate-limit window                            |
| `sts.webIdentity.maxSessionsPerTrust`                            | 1000                           | 1..100000     | Live sessions per web trust                                          |
| `sts.webIdentity.allowPrivateNetworks`, `allowInsecureLocalhost` | `false`                        |               | Development and tests only                                           |
| `sts.webIdentity.fetchJson`                                      | built-in guarded fetch         |               | Host transport; bypasses the SSRF guard, so the host owns its safety |

Per-record limits: `trust.maxSessionSeconds` 60 up to `sts.maxRoleSessionSeconds`; `allowedTagKeys` at most 50 or `['*']`; trust `description` at most 512 characters; tags at most 50 and 2048 bytes; `audience` 1 to 5 entries; provider `audiences` 1 to 10, static `jwks` 1 to 20 public keys (RSA at least 2048 bits, EC P-256/P-384/P-521, Ed25519), `algorithms` from RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, EdDSA (default RS256 and ES256), `maxTokenLifetimeSeconds` 60..86400 (default 3600), `clockToleranceSeconds` 0..120 (default 30).

New catalog actions: `iam:session-tokens:create`, `iam:roles:revoke-sessions`, `iam:trust:update`, `iam:oidc-providers:create|read|update|delete`. `iam:roles:assume`, `iam:trust:create`, `iam:trust:update`, `iam:session-tokens:create`, `iam:oidc-providers:create` and `iam:oidc-providers:update` count as access-changing for enforced invariants.
