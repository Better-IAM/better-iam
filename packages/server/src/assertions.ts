import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { IamError, type CredentialInput, type Json } from '@better-iam/core';
import type { ServerContext } from './context.js';
import { OperationDenied } from './operations.js';
import { id } from './utils.js';
import { integer, object, text } from './validation.js';

/**
 * Stateless assertions: short-lived HS256 JSON Web Tokens that describe the caller for another service, signed with a
 * key derived from the deployment secret. A downstream service holding only the derived key (`iam.assertionKey()`)
 * verifies them with `verifyAssertion` without a database round trip. They grant nothing inside IAM itself.
 */
export interface AssertionClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  /** The tenant the assertion was issued for. */
  tid: string;
  /** The caller's session kind; `session-token` for temporary credentials minted by `sts.getSessionToken`. */
  kind: 'user' | 'api-key' | 'role' | 'session-token';
  mfa: boolean;
  method?: string;
  /** Present when an administrator is acting through an impersonation session; `sub` is the member. */
  impersonatorId?: string;
  name: string;
  email?: string;
  roles: string[];
  groups: string[];
  /** Caller-supplied public claims, at most 4 KiB of JSON. */
  ext?: Record<string, Json>;
}

const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const header = encode({ alg: 'HS256', typ: 'JWT' });
const audiencePattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;

/** The verification key for a deployment secret: SHA-256 of a purpose-bound derivation, as hex. */
export function assertionKey(secret: string): string {
  return createHash('sha256').update(`better-iam:assertion:${secret}`).digest('hex');
}

function sign(key: string, signingInput: string): Buffer {
  return createHmac('sha256', Buffer.from(key, 'hex')).update(signingInput).digest();
}

/**
 * Verifies an assertion against the derived key, audience, optional issuer, and time; returns its
 * claims. `key` may list several keys (`iam.assertionKeys()`) while a deployment secret rotates.
 */
export function verifyAssertion(
  token: string,
  options: {
    key: string | readonly string[];
    audience: string;
    issuer?: string;
    now?: number;
    toleranceSeconds?: number;
  },
): AssertionClaims {
  const invalid = (message: string) => new IamError('INVALID_ASSERTION', message, 401);
  if (typeof token !== 'string' || token.length > 16384) throw invalid('Malformed assertion');
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== header) throw invalid('Malformed assertion');
  const keys = typeof options.key === 'string' ? [options.key] : options.key;
  if (
    !Array.isArray(keys) ||
    !keys.length ||
    keys.some((key) => typeof key !== 'string' || !/^[0-9a-f]{64}$/.test(key))
  )
    throw invalid('Invalid verification key');
  let provided: Buffer;
  try {
    provided = Buffer.from(parts[2]!, 'base64url');
  } catch {
    throw invalid('Malformed assertion');
  }
  // Base64url decoding is lenient (unused trailing bits, padding, stray characters), so only the canonical spelling
  // of a signature is accepted: one assertion has exactly one valid string form.
  if (provided.toString('base64url') !== parts[2]) throw invalid('Malformed assertion');
  const signingInput = `${parts[0]}.${parts[1]}`;
  if (
    !keys.some((key) => {
      const expected = sign(key, signingInput);
      return provided.length === expected.length && timingSafeEqual(provided, expected);
    })
  )
    throw invalid('Invalid signature');
  let claims: AssertionClaims;
  try {
    claims = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as AssertionClaims;
  } catch {
    throw invalid('Malformed assertion');
  }
  const now = Math.floor((options.now ?? Date.now()) / 1000);
  const tolerance = options.toleranceSeconds ?? 30;
  if (
    !claims ||
    typeof claims !== 'object' ||
    typeof claims.sub !== 'string' ||
    typeof claims.tid !== 'string' ||
    typeof claims.exp !== 'number' ||
    typeof claims.iat !== 'number'
  )
    throw invalid('Malformed assertion');
  if (claims.aud !== options.audience) throw invalid('Audience mismatch');
  if (options.issuer !== undefined && claims.iss !== options.issuer)
    throw invalid('Issuer mismatch');
  if (claims.exp + tolerance <= now) throw invalid('Assertion expired');
  if (claims.iat - tolerance > now) throw invalid('Assertion not yet valid');
  return claims;
}

export function createAssertionsApi(ctx: ServerContext) {
  const { config, options } = ctx;
  const { operation } = ctx.operations;
  const key = assertionKey(options.secret);
  return {
    /**
     * Issues an assertion about the caller for `audience`, authorized as `iam:assertions:create` on `iam/{audience}` so
     * administrators decide which audiences each role may obtain tokens for. Lifetime is 10 seconds to one hour
     * (default five minutes). Role sessions assert the assumed role's identity and no groups. Scoped credentials (API
     * keys with scopes, session tokens with a policy or source policy, role sessions with a session policy) are refused
     * (ACCESS_DENIED, audited), since the roles claim would escape the scope.
     */
    issue: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        audience: string;
        ttlSeconds?: number;
        claims?: Record<string, Json>;
      },
    ) => {
      const audience = text(input.audience, 'audience', 256);
      if (!audiencePattern.test(audience))
        throw new IamError('INVALID_INPUT', 'audience must be a URL-safe identifier');
      return operation(
        credential,
        input.tenantId,
        'iam:assertions:create',
        audience,
        async ({ tx, principal, tenant }) => {
          // The roles claim lists the identity's roles (or the assumed role), which would escape any scope-down: a
          // session token's policy or source policy, an API key's scopes, or a role session's session policy.
          if (principal.session.policy || principal.session.sourcePolicy)
            throw new OperationDenied(
              principal.session.kind === 'session-token'
                ? 'Scoped session tokens cannot obtain assertions'
                : 'Scoped credentials cannot obtain assertions',
            );
          // Likewise a delegated agent session, which is always bounded by its delegation's scope.
          if (principal.session.kind === 'delegated')
            throw new OperationDenied('Delegated agent sessions cannot obtain assertions');
          const kind = principal.session.kind;
          const ttl = integer(input.ttlSeconds ?? 300, 'ttlSeconds', 10, 3600);
          const issuedAt = Math.floor(ctx.now() / 1000);
          const sources =
            principal.session.kind === 'role'
              ? { groupIds: new Set<string>(), bindings: [] }
              : await ctx.decisions.grantSources(tx, principal.identity.id, tenant.id);
          const roles =
            principal.session.kind === 'role'
              ? [principal.session.roleId!]
              : [...new Set(sources.bindings.map((binding) => binding.roleId))].sort();
          const claims: AssertionClaims = {
            iss: config.baseURL.origin,
            sub: principal.identity.id,
            aud: audience,
            iat: issuedAt,
            exp: issuedAt + ttl,
            jti: id(),
            tid: tenant.id,
            kind,
            mfa: principal.session.mfa,
            name: principal.identity.name,
            roles,
            groups: [...sources.groupIds].sort(),
          };
          if (principal.session.method) claims.method = principal.session.method;
          if (principal.session.impersonatorId)
            claims.impersonatorId = principal.session.impersonatorId;
          if (principal.identity.email) claims.email = principal.identity.email;
          if (input.claims !== undefined) {
            const ext = object(input.claims) as Record<string, Json>;
            const serialized = JSON.stringify(ext);
            if (serialized.length > 4096)
              throw new IamError('INVALID_INPUT', 'claims must serialize to at most 4 KiB');
            for (const name of Object.keys(ext))
              if (name in claims)
                throw new IamError('INVALID_INPUT', `claims cannot redefine ${name}`);
            claims.ext = ext;
          }
          const signingInput = `${header}.${encode(claims)}`;
          return {
            token: `${signingInput}.${sign(key, signingInput).toString('base64url')}`,
            expiresAt: claims.exp * 1000,
            claims,
          };
        },
      );
    },
  };
}
