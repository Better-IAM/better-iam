import {
  IamError,
  ipCounterKey,
  type Identity,
  type IamStore,
  type Json,
  type PolicyDocument,
  type Session,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import type { OidcProvider, Role, Trust, WebIdentityReplay } from './models.js';
import {
  audienceValue,
  credentialFormat,
  durationWithin,
  mintCredential,
  roleDurationBounds,
  sessionNamePattern,
  sessionTagsValue,
  temporaryCredential,
  type CredentialFormat,
  type RoleCredential,
} from './temporary-credentials.js';
import { id } from './utils.js';
import { text } from './validation.js';
import {
  matchWebIdentityConditions,
  webIdentityConditions,
  webIdentityReplayId,
  WebIdentityFailure,
  type VerifiedWebIdentity,
  type WebIdentityFailureReason,
} from './web-identity.js';

/**
 * AssumeRoleWithWebIdentity: the public exchange of a verified external OIDC token (GitHub Actions, GitLab,
 * Kubernetes, cloud workload identity) for a role session under a web-identity trust (`sts/assumeRoleWithWebIdentity`,
 * listed in `publicApiMethods`), plus the administrators' dry run (`trust.evaluateWebIdentity`).
 *
 * The external token is the only credential, so the exchange is built against enumeration: the feature flag and the
 * input shape are checked first, the per-trust rate limit is consumed before anything is looked up, and every failure
 * that depends on stored state or on the token is the same WEB_IDENTITY_REJECTED (403). Only once a verified token has
 * matched the trust do specific errors surface (rate and network refusals, the per-trust session cap, duration,
 * policy, format and audience problems). Denials are audited best-effort, and only once the trust has resolved in its
 * tenant; claims are recorded only when the signature verified, and the raw token is never stored or recorded.
 */

/** `sts.assumeRoleWithWebIdentity` input. */
export interface WebIdentityExchangeInput {
  /** The tenant of the trust (and of the role). */
  tenantId: string;
  trustId: string;
  /** The external OIDC ID token (a compact JWS of at most 8192 characters). */
  webIdentityToken: string;
  /** Required: a label for the session (/^[\w+=,.@-]{2,64}$/), exposed as principal.sessionName. */
  sessionName: string;
  /** 60 up to the trust's maximum (default 900, or less when the maximum is lower). */
  durationSeconds?: number;
  /** A scope-down policy: the session may do only what both the role and this policy allow. */
  policy?: PolicyDocument;
  format?: CredentialFormat;
  /** Session JWTs only: 1 to 5 audiences from `sts.jwt.audiences` (default: the IAM issuer). */
  audience?: string[];
}

/** What the exchange returns: a role credential plus the verified external identity behind it. */
export interface WebIdentityCredential extends RoleCredential {
  webIdentity: { providerId: string; issuer: string; subject: string };
}

/**
 * Why a token was not accepted: a verification failure, unmet trust conditions, or a missing or invalid source
 * identity claim; or stored state that refuses every token: a revoked (or malformed) trust, a disabled provider, a
 * missing or protected role, an inactive or expired service account, or a revoked authority behind the role, the
 * trust or the provider. The public exchange never reveals it; audits and the dry run do.
 */
export type WebIdentityRejectionReason =
  | WebIdentityFailureReason
  | 'conditions'
  | 'source-identity'
  | 'trust'
  | 'provider'
  | 'role'
  | 'service-account'
  | 'authority';

/** `trust.evaluateWebIdentity`: what the exchange would conclude about a token, without issuing anything. */
export interface WebIdentityEvaluation {
  /** Whether the signature, issuer, audience and time claims verified against the provider. */
  verified: boolean;
  /** Set when the exchange would refuse the token. */
  reason?: WebIdentityRejectionReason;
  /** The verified registered claims; `aud` is the provider audience the token was accepted for. */
  claims?: { iss: string; sub: string; aud: string; iat: number; exp: number; jti?: string };
  /** The trust conditions; `failed` lists each unmet entry as `Operator:key`. */
  conditions?: { matched: boolean; failed: string[] };
  /** The session tags the trust's `tagClaims` would map. */
  sessionTags?: Record<string, string>;
  /** The source identity the trust's `sourceIdentityClaim` would map. */
  sourceIdentity?: string;
}

const maxTokenLength = 8192;
const tokenShape = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
/** The replay record outlives the provider's acceptance window; an unusable stored tolerance counts as the maximum. */
const maxClockToleranceSeconds = 120;
const auditAction = 'role:assumed-with-web-identity';

function invalid(message: string): never {
  throw new IamError('INVALID_INPUT', message);
}
const featureDisabled = () =>
  new IamError('FEATURE_DISABLED', 'Web identity federation is not enabled', 403);
const rejected = () =>
  new IamError('WEB_IDENTITY_REJECTED', 'The web identity token was not accepted', 403);

/** A refusal that depends on stored state or on the token; it always surfaces as `rejected()`. */
class Rejection extends Error {
  constructor(readonly reason: string) {
    super(`Web identity exchange rejected (${reason})`);
    this.name = 'Rejection';
  }
}

/** A live web-identity trust of the tenant (read fail-closed). */
function liveTrust(
  trust: Trust | undefined,
  tenantId: string,
): trust is Trust & { providerId: string } {
  return (
    !!trust &&
    trust.tenantId === tenantId &&
    trust.kind === 'web-identity' &&
    trust.revoked === false &&
    typeof trust.providerId === 'string' &&
    typeof trust.roleId === 'string' &&
    typeof trust.sourceIdentityId === 'string'
  );
}

/** An enabled provider of the tenant (read fail-closed). */
function liveProvider(
  provider: OidcProvider | undefined,
  tenantId: string,
): provider is OidcProvider {
  return !!provider && provider.tenantId === tenantId && provider.enabled === true;
}

interface Inspection {
  evaluation: WebIdentityEvaluation;
  /** Present once the token verified. */
  verified?: VerifiedWebIdentity;
  sessionTags?: Record<string, string>;
  sourceIdentity?: string;
}

/**
 * Verifies a token against a provider and matches it against a trust: the signature and claims, the trust's claim
 * conditions (re-validated, so a malformed or unpinned stored block matches nothing), then the claim mappings. Only
 * string claims of at most 256 characters in the tag value charset become tags (others are left out, as is a tag
 * that would overflow the packed size); a `sourceIdentityClaim` that is missing or not a valid source identity
 * refuses the token.
 */
async function inspect(
  ctx: ServerContext,
  trust: Trust,
  provider: OidcProvider,
  token: unknown,
): Promise<Inspection> {
  const verifier = ctx.webIdentity;
  if (!verifier) throw featureDisabled();
  // The deployment's issuer pin holds for providers registered before it was narrowed, too.
  if (!issuerAllowed(ctx, provider)) return { evaluation: { verified: false, reason: 'issuer' } };
  let verified: VerifiedWebIdentity;
  try {
    verified = await verifier.verify(provider, token as string);
  } catch (error) {
    // Anything but a typed refusal (a malformed stored provider, say) refuses the token all the same.
    const reason = error instanceof WebIdentityFailure ? error.reason : 'malformed';
    return { evaluation: { verified: false, reason } };
  }
  return matchTrust(trust, verified);
}

/** Whether `sts.webIdentity.allowedIssuers` (when set) still admits the provider's issuer. */
function issuerAllowed(ctx: ServerContext, provider: OidcProvider): boolean {
  const allowed = ctx.config.sts.webIdentity.allowedIssuers;
  return allowed === undefined || allowed.includes(provider.issuer);
}

/**
 * The provider settings a verification depends on. Issuance compares them between the record the token was verified
 * against and the one re-read in the transaction, so a key, audience or algorithm change in between refuses it.
 */
function verificationSettings(provider: OidcProvider): string {
  return JSON.stringify([
    provider.issuer,
    provider.audiences ?? null,
    provider.algorithms ?? null,
    provider.jwks ?? null,
    provider.jwksUri ?? null,
    provider.maxTokenLifetimeSeconds ?? null,
    provider.clockToleranceSeconds ?? null,
  ]);
}

/**
 * Matches a verified token against a trust: its claim conditions, then its claim mappings. Pure, so issuance can
 * repeat it against the trust as re-read in the transaction.
 */
function matchTrust(trust: Trust, verified: VerifiedWebIdentity): Inspection {
  const evaluation: WebIdentityEvaluation = {
    verified: true,
    claims: {
      iss: verified.issuer,
      sub: verified.subject,
      aud: verified.audience,
      iat: verified.issuedAt,
      exp: verified.expiresAt,
      ...(verified.jti !== undefined ? { jti: verified.jti } : {}),
    },
  };
  let conditions: { matched: boolean; failed: string[] };
  try {
    conditions = matchWebIdentityConditions(
      webIdentityConditions(trust.conditions),
      verified.context,
      trust.id,
    );
  } catch {
    conditions = { matched: false, failed: ['conditions'] };
  }
  evaluation.conditions = conditions;
  const claim = (name: unknown) =>
    typeof name === 'string' && Object.hasOwn(verified.context, name)
      ? verified.context[name]
      : undefined;
  const sessionTags: Record<string, string> = {};
  const mapping = trust.tagClaims;
  if (mapping && typeof mapping === 'object' && !Array.isArray(mapping))
    for (const [key, name] of Object.entries(mapping)) {
      const value = claim(name);
      if (typeof value !== 'string') continue;
      try {
        sessionTagsValue({ ...sessionTags, [key]: value });
        sessionTags[key] = value;
      } catch {
        /* Not a usable tag: left out. */
      }
    }
  const tags = Object.keys(sessionTags).length ? sessionTags : undefined;
  if (tags) evaluation.sessionTags = { ...tags };
  let sourceIdentity: string | undefined;
  let sourceIdentityRefused = false;
  if (trust.sourceIdentityClaim !== undefined) {
    const value = claim(trust.sourceIdentityClaim);
    if (typeof value === 'string' && sessionNamePattern.test(value)) sourceIdentity = value;
    else sourceIdentityRefused = true;
  }
  if (sourceIdentity !== undefined) evaluation.sourceIdentity = sourceIdentity;
  if (!conditions.matched) evaluation.reason = 'conditions';
  else if (sourceIdentityRefused) evaluation.reason = 'source-identity';
  return { evaluation, verified, sessionTags: tags, sourceIdentity };
}

/**
 * What backs a live trust's sessions, read fail-closed: the role (present, unprotected, under a live authority), the
 * service account (active, unexpired, in the tenant) and the authorities of the trust's and the provider's creators.
 * Returns the role and the account, or the first refusal in the order issuance checks them.
 */
async function sessionBacking(
  ctx: ServerContext,
  tx: IamStore,
  trust: Trust & { providerId: string },
  provider: OidcProvider,
): Promise<
  { role: Role; account: Identity } | { reason: 'role' | 'service-account' | 'authority' }
> {
  const { tenantId } = trust;
  const role = await tx.get<Role>('roles', trust.roleId);
  if (
    !role ||
    role.tenantId !== tenantId ||
    Boolean(role.protected) ||
    typeof role.authorityId !== 'string' ||
    !(await ctx.authorityChain(tx, role.authorityId))
  )
    return { reason: 'role' };
  const account = await tx.get<Identity>('identities', trust.sourceIdentityId);
  if (
    !account ||
    account.kind !== 'service' ||
    account.status !== 'active' ||
    account.tenantId !== tenantId ||
    trust.sourceTenantId !== tenantId ||
    ctx.identityExpired(account)
  )
    return { reason: 'service-account' };
  // Sessions are bounded by the authorities of the trust's and the provider's creators.
  if (
    typeof trust.authorityId !== 'string' ||
    !(await ctx.authorityChain(tx, trust.authorityId)) ||
    typeof provider.authorityId !== 'string' ||
    !(await ctx.authorityChain(tx, provider.authorityId))
  )
    return { reason: 'authority' };
  return { role, account };
}

/**
 * The dry run behind `trust.evaluateWebIdentity`: verification, trust conditions and claim mappings for a token,
 * with no replay record and no issuance. The caller has authorized the read and loaded the trust and its provider.
 * Stored state that would refuse the exchange is reported too, in the exchange's order: a revoked trust or a disabled
 * provider comes before the token's own problems, and the role, service account and authorities after them.
 */
export async function evaluateWebIdentity(
  ctx: ServerContext,
  input: { trust: Trust; provider: OidcProvider; token: string },
): Promise<WebIdentityEvaluation> {
  const { trust, provider } = input;
  const { evaluation } = await inspect(ctx, trust, provider, input.token);
  if (!liveTrust(trust, trust.tenantId)) evaluation.reason = 'trust';
  else if (!liveProvider(provider, trust.tenantId) || trust.providerId !== provider.id)
    evaluation.reason = 'provider';
  else if (evaluation.reason === undefined) {
    const backing = await ctx.store.transaction((tx) => sessionBacking(ctx, tx, trust, provider));
    if ('reason' in backing) evaluation.reason = backing.reason;
  }
  return evaluation;
}

/**
 * The public side of the `sts` group: `assumeRoleWithWebIdentity`. Pre-wired into `createStsApi` by spreading.
 */
export function createWebIdentityStsApi(ctx: ServerContext) {
  const { auth, catalog } = ctx;
  const settings = ctx.config.sts.webIdentity;

  /** Records a refusal in its own transaction; bookkeeping never masks the refusal itself. */
  async function recordDenial(
    trust: Trust,
    reason: string,
    verified: VerifiedWebIdentity | undefined,
  ): Promise<void> {
    const metadata: Record<string, Json> = {
      trustId: trust.id,
      providerId: typeof trust.providerId === 'string' ? trust.providerId : null,
      reason,
    };
    // Claims are recorded only once the signature verified; unverified input never reaches the audit log.
    if (verified) {
      metadata.issuer = verified.issuer.slice(0, 256);
      metadata.subject = verified.subject.slice(0, 256);
    }
    try {
      await ctx.store.transaction((tx) =>
        ctx.events.recordAudit(tx, {
          id: id(),
          tenantId: trust.tenantId,
          // The trust's anchoring service account, the identity a session would have acted as.
          actorId: trust.sourceIdentityId,
          action: auditAction,
          resourceId: trust.roleId,
          outcome: 'deny',
          rootOverride: false,
          timestamp: ctx.now(),
          metadata,
        }),
      );
    } catch {
      /* Best-effort. */
    }
  }

  /** The issuance transaction: every stored-state check is repeated here, next to the replay record and the row. */
  async function issue(
    tx: IamStore,
    request: {
      tenantId: string;
      trustId: string;
      token: string;
      sessionName: string;
      durationSeconds: unknown;
      policy: PolicyDocument | undefined;
      format: CredentialFormat;
      audience: string[] | undefined;
    },
    verifiedWith: OidcProvider,
    verified: VerifiedWebIdentity,
  ): Promise<WebIdentityCredential> {
    const { tenantId } = request;
    const trust = await tx.get<Trust>('trusts', request.trustId);
    if (!liveTrust(trust, tenantId) || trust.providerId !== verifiedWith.id)
      throw new Rejection('trust');
    // The token was verified and matched outside this transaction: the provider settings it was verified against
    // must still be the live ones, and the live trust must still admit it (with its current mappings).
    const provider = await tx.get<OidcProvider>('oidcProviders', verifiedWith.id);
    if (
      !liveProvider(provider, tenantId) ||
      provider.issuer !== verified.issuer ||
      !issuerAllowed(ctx, provider) ||
      verificationSettings(provider) !== verificationSettings(verifiedWith)
    )
      throw new Rejection('provider');
    const inspection = matchTrust(trust, verified);
    if (inspection.evaluation.reason !== undefined)
      throw new Rejection(inspection.evaluation.reason);
    const backing = await sessionBacking(ctx, tx, trust, provider);
    if ('reason' in backing) throw new Rejection(backing.reason);
    const { role, account } = backing;
    let target: Tenant | undefined;
    try {
      target = await tx.get<Tenant>('tenants', tenantId);
      if (!target || (await ctx.ancestry(tx, target)).some((item) => item.status !== 'active'))
        target = undefined;
    } catch {
      target = undefined;
    }
    if (!target) throw new Rejection('tenant');

    // From here on the token matched a live trust, so specific refusals may surface.
    const ip = auth.currentClient()?.ip;
    auth.assertIpAllowed(target, ip);
    await auth.assertNetworkNotBlocked(tx, tenantId, ip);
    // The injected clock, like user sessions, so validation and issuance agree under a test clock.
    const now = ctx.now();
    const live = (await tx.find<Session>('sessions', { roleId: trust.roleId })).filter(
      (session) =>
        session.kind === 'role' &&
        session.trustId === trust.id &&
        session.tenantId === tenantId &&
        session.expiresAt > now,
    );
    if (live.length >= settings.maxSessionsPerTrust)
      throw new IamError(
        'LIMIT_EXCEEDED',
        'This trust holds the maximum number of live role sessions',
        409,
      );
    if (request.policy !== undefined) await catalog.validate(tx, tenantId, request.policy);
    const durationSeconds = durationWithin(
      request.durationSeconds,
      roleDurationBounds(ctx, trust, request.format),
    );
    // Single use unless the provider opts out; recorded in this transaction, so a failed issuance does not burn it.
    if (provider.replayProtection !== 'off') {
      const replayId = webIdentityReplayId(provider.id, verified.jti, request.token);
      if (await tx.get<WebIdentityReplay>('webIdentityReplays', replayId))
        throw new Rejection('replay');
      // Kept for the largest tolerance any provider may be given, not this provider's current one: raising its
      // clockToleranceSeconds later must not reopen a window in which an already redeemed token is accepted again.
      await tx.insert<WebIdentityReplay>('webIdentityReplays', {
        id: replayId,
        tenantId: provider.tenantId,
        providerId: provider.id,
        expiresAt: verified.expiresAt * 1000 + maxClockToleranceSeconds * 1000,
      });
    }
    const webIdentity = {
      providerId: provider.id,
      issuer: verified.issuer,
      subject: verified.subject,
    };
    const draft: Session = {
      id: id(),
      tenantId,
      identityId: account.id,
      originalIdentityId: account.id,
      roleId: role.id,
      trustId: trust.id,
      kind: 'role',
      tokenHash: '',
      createdAt: now,
      lastSeenAt: now,
      // The exchange is the authentication; external tokens never attest MFA.
      authenticatedAt: now,
      expiresAt: now + durationSeconds * 1000,
      mfa: false,
      credentialAuthorityId: trust.authorityId,
      webIdentity,
      sessionName: request.sessionName,
    };
    if (request.policy !== undefined) draft.policy = request.policy;
    if (inspection.sessionTags) draft.sessionTags = { ...inspection.sessionTags };
    if (inspection.sourceIdentity !== undefined) draft.sourceIdentity = inspection.sourceIdentity;
    // The presenting address: the tenant's allowlist and network blocks judge it on every use.
    const client = auth.currentClient();
    if (client && Object.keys(client).length) draft.client = { ...client };
    const { token, session } = await mintCredential(ctx, tx, {
      identity: account,
      draft,
      format: request.format,
      audience: request.audience,
    });
    await ctx.events.audit(
      tx,
      { identity: account, session },
      auditAction,
      tenantId,
      role.id,
      'allow',
      false,
      {
        trustId: trust.id,
        providerId: provider.id,
        issuer: verified.issuer.slice(0, 256),
        subject: verified.subject.slice(0, 256),
        durationSeconds,
        format: request.format,
        tagKeys: Object.keys(inspection.sessionTags ?? {}).sort(),
      },
    );
    return {
      ...(temporaryCredential(token, session, now) as RoleCredential),
      webIdentity: { ...webIdentity },
    };
  }

  return {
    /**
     * AssumeRoleWithWebIdentity (public; no IAM credential): exchanges a verified external OIDC token for a role
     * session of kind 'role' under a web-identity trust, acting as the trust's service account and bounded by the
     * role, the trust's ceiling, and the authorities of the trust's and the provider's creators. The token must be
     * signed by the provider's keys with an allowed algorithm, name the provider's issuer and one of its audiences,
     * be fresh, satisfy the trust's claim conditions and (by default) not have been redeemed before at this provider.
     *
     * Every refusal that depends on stored state or on the token is WEB_IDENTITY_REJECTED (403) with the same body.
     * The attempt counts against `sts.webIdentity.maxExchangesPerWindow` for the trust before anything is looked up.
     * The credential is returned once, in the body; this route never sets a cookie. Audited as
     * `role:assumed-with-web-identity` (allow, or deny with a reason once the trust resolved).
     */
    async assumeRoleWithWebIdentity(
      input: WebIdentityExchangeInput,
    ): Promise<WebIdentityCredential> {
      if (!settings.enabled || !ctx.webIdentity) throw featureDisabled();
      // (1) Shape only: nothing here depends on stored state.
      if (!input || typeof input !== 'object' || Array.isArray(input))
        invalid('Expected an object');
      const tenantId = text(input.tenantId, 'tenantId');
      const trustId = text(input.trustId, 'trustId');
      const token: unknown = input.webIdentityToken;
      if (typeof token !== 'string' || token.length > maxTokenLength || !tokenShape.test(token))
        invalid('webIdentityToken must be a compact JWT of at most 8192 characters');
      const sessionName: unknown = input.sessionName;
      if (typeof sessionName !== 'string' || !sessionNamePattern.test(sessionName))
        invalid('sessionName must be 2-64 letters, digits or +=,.@_- characters');
      if (input.durationSeconds !== undefined && typeof input.durationSeconds !== 'number')
        invalid('durationSeconds must be a number');
      const policy: unknown = input.policy;
      if (policy !== undefined && (!policy || typeof policy !== 'object' || Array.isArray(policy)))
        invalid('policy must be a policy document');
      if (input.format !== undefined && typeof input.format !== 'string')
        invalid("format must be 'opaque' or 'jwt'");
      if (input.audience !== undefined && !Array.isArray(input.audience))
        invalid('audience must be a list');

      // (2) Counted before any lookup and outside any transaction, so a refusal cannot roll it back. Trust ids are
      // public (they sit in CI workflow files), so when the client's address is known the budget is per address,
      // and one source posting junk tokens cannot use up the trust's exchanges for everyone; the trust as a whole
      // still has a ceiling (ten budgets) that bounds the work any number of sources can cause.
      const ip = auth.currentClient()?.ip;
      if (ip) {
        // An IPv6 /64 counts as one source, so rotating through it earns no fresh budget.
        await auth.limitAttempt(tenantId, `web-identity:${trustId}:${ipCounterKey(ip) ?? ip}`, {
          limit: settings.maxExchangesPerWindow,
        });
        await auth.limitAttempt(tenantId, `web-identity:${trustId}`, {
          limit: settings.maxExchangesPerWindow * 10,
          countClient: false,
        });
      } else
        await auth.limitAttempt(tenantId, `web-identity:${trustId}`, {
          limit: settings.maxExchangesPerWindow,
        });

      // (3) The trust and its provider; an unknown trust is refused like every other failure, without an audit.
      const trust = await ctx.store.get<Trust>('trusts', trustId);
      if (!liveTrust(trust, tenantId)) throw rejected();
      const provider = await ctx.store.get<OidcProvider>('oidcProviders', trust.providerId);
      if (!liveProvider(provider, tenantId)) throw rejected();

      // (4)-(6) Verification, claim conditions and mappings, outside any transaction (keys may be fetched).
      const inspection = await inspect(ctx, trust, provider, token);
      const { verified } = inspection;
      if (!verified || inspection.evaluation.reason !== undefined) {
        await recordDenial(trust, inspection.evaluation.reason ?? 'malformed', verified);
        throw rejected();
      }

      // (7) Issuance. Stored-state failures and replays are rejections; the rest surface as themselves.
      try {
        const format = credentialFormat(input.format);
        const audience = audienceValue(input.audience, format);
        if (format === 'jwt' && !ctx.sessionTokens)
          throw new IamError(
            'FEATURE_DISABLED',
            'Session JWTs are not enabled on this deployment (sts.jwt)',
            403,
          );
        return await ctx.store.transaction((tx) =>
          issue(
            tx,
            {
              tenantId,
              trustId,
              token,
              sessionName,
              durationSeconds: input.durationSeconds,
              policy: policy as PolicyDocument | undefined,
              format,
              audience,
            },
            provider,
            verified,
          ),
        );
      } catch (error) {
        // A concurrent redemption of the same token loses the insert race: the same refusal as a replay.
        const reason =
          error instanceof Rejection
            ? error.reason
            : error instanceof IamError && error.code === 'CONFLICT'
              ? 'replay'
              : undefined;
        if (reason !== undefined) {
          await recordDenial(trust, reason, verified);
          throw rejected();
        }
        if (error instanceof IamError) await recordDenial(trust, error.code, verified);
        throw error;
      }
    },
  };
}
