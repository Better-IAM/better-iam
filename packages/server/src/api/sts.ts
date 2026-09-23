import {
  IamError,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Session,
} from '@better-iam/core';
import { clientFromHeaders } from '../client-info.js';
import type { ServerContext } from '../context.js';
import { actsInOwnRight } from '../session-kinds.js';
import {
  audienceValue,
  callerIdentity,
  credentialFormat,
  durationWithin,
  mintCredential,
  sessionNameValue,
  sessionTokenDurationBounds,
  temporaryCredential,
  type CallerIdentity,
  type GetSessionTokenInput,
  type TemporaryCredential,
} from '../temporary-credentials.js';
import { id } from '../utils.js';
import { createWebIdentityStsApi } from '../web-identity-exchange.js';

const chainingDisabled = () =>
  new IamError(
    'CREDENTIAL_CHAINING_DISABLED',
    'Temporary credentials cannot mint session tokens',
    400,
  );

/**
 * How a stored session token stands for the per-identity cap: `live` (usable, counts), `dead` (can never be used
 * again, so it is deleted) or `suspended` (refused for now for a reason that can be lifted, such as a network block
 * or a tenant's MFA requirement; neither counted nor deleted).
 */
type TokenStanding = 'live' | 'dead' | 'suspended';

/**
 * Judges a session token of `identity` as `principals` would, without its per-use network checks: the token must be
 * unexpired and consistent with a stored source (a user session or API key of the same identity and tenant, never an
 * impersonation, which it does not outlive and whose authority it carries), and the source must still pass
 * re-validation. A source refused as `UNAUTHENTICATED` (signed out, expired, idled out, key authority revoked) never
 * comes back, so its tokens are dead. Source verdicts are cached per source in `sources`.
 */
async function tokenStanding(
  ctx: ServerContext,
  tx: IamStore,
  identity: Identity,
  token: Session,
  now: number,
  sources: Map<string, TokenStanding>,
): Promise<TokenStanding> {
  if (token.expiresAt <= now || typeof token.sourceSessionId !== 'string') return 'dead';
  const source = await tx.get<Session>('sessions', token.sourceSessionId);
  if (
    !source ||
    (source.kind !== 'user' && source.kind !== 'api-key') ||
    source.impersonatorId ||
    source.identityId !== identity.id ||
    source.tenantId !== token.tenantId ||
    token.tenantId !== identity.tenantId ||
    source.expiresAt <= now ||
    token.expiresAt > source.expiresAt ||
    token.credentialAuthorityId !== source.credentialAuthorityId
  )
    return 'dead';
  const cached = sources.get(source.id);
  if (cached) return cached;
  let standing: TokenStanding = 'live';
  try {
    await ctx.principals.currentPrincipal(tx, { identity, session: source });
  } catch (error) {
    if (!(error instanceof IamError)) throw error;
    standing = error.code === 'UNAUTHENTICATED' ? 'dead' : 'suspended';
  }
  sources.set(source.id, standing);
  return standing;
}

/**
 * The `sts` group: temporary credentials (GetSessionToken, GetCallerIdentity) plus the public web-identity exchange.
 * Every method takes the caller's credential first; tokens are returned once, in the response body, and never set a
 * cookie.
 */
export function createStsApi(ctx: ServerContext) {
  const { auth, catalog, config } = ctx;

  /** GetSessionToken inside the caller's client scope (see `getSessionToken`). */
  async function issueSessionToken(
    credential: CredentialInput,
    input: GetSessionTokenInput,
  ): Promise<TemporaryCredential> {
    const source = await ctx.principals.authenticate(credential);
    if (source.session.impersonatorId)
      throw new IamError(
        'IMPERSONATION_RESTRICTED',
        'Session tokens cannot be minted while impersonating a member',
        403,
      );
    if (!actsInOwnRight(source.session)) throw chainingDisabled();
    const request: GetSessionTokenInput = input ?? {};
    const mfaCode = request.mfaCode;
    if (mfaCode !== undefined) {
      if (source.session.kind !== 'user')
        throw new IamError('MFA_NOT_ENROLLED', 'Only a signed-in person can verify MFA', 403);
      // Counted before anything else is examined and outside any transaction, so a refusal cannot roll it back.
      await auth.limitAttempt(source.identity.tenantId, `step-up:${source.identity.id}`, {
        tier: 'sensitive',
      });
      if (typeof mfaCode !== 'string')
        throw new IamError('INVALID_INPUT', 'mfaCode must be a string');
    }
    // Input shapes are refused before the operation; the policy is validated against the catalog inside it.
    const sessionName = sessionNameValue(request.sessionName);
    const format = credentialFormat(request.format);
    const audience = audienceValue(request.audience, format);
    if (format === 'jwt' && !ctx.sessionTokens)
      throw new IamError(
        'FEATURE_DISABLED',
        'Session JWTs are not enabled on this deployment (sts.jwt)',
        403,
      );
    const durationSeconds = durationWithin(
      request.durationSeconds,
      sessionTokenDurationBounds(ctx, format),
    );
    if (
      request.policy !== undefined &&
      (!request.policy || typeof request.policy !== 'object' || Array.isArray(request.policy))
    )
      throw new IamError('INVALID_INPUT', 'policy must be a policy document');
    const identityId = source.identity.id;
    const tenantId = source.identity.tenantId;
    return ctx.operations.operation(
      credential,
      tenantId,
      'iam:session-tokens:create',
      identityId,
      async ({ tx, principal }) => {
        // The re-validated principal must still be the credential examined above, acting in its own right.
        if (
          principal.identity.id !== identityId ||
          principal.session.id !== source.session.id ||
          principal.session.impersonatorId
        )
          throw new IamError('UNAUTHENTICATED', 'Credential revoked', 401);
        if (!actsInOwnRight(principal.session)) throw chainingDisabled();
        if (request.policy !== undefined) await catalog.validate(tx, tenantId, request.policy);
        const stepUp =
          mfaCode !== undefined
            ? await auth.verifyStepUpCode(tx, principal.identity, mfaCode)
            : undefined;
        // The injected clock, like user sessions, so validation and issuance agree under a test clock.
        const now = ctx.now();
        // Only tokens that can still be used hold a place under the cap, and dead ones are deleted here, so the cap
        // bounds the stored rows too: every issuance leaves at most `maxSessionTokensPerIdentity` rows behind, and
        // no row is added between issuances. (A refused issuance rolls its deletions back, but then nothing is added.)
        let live = 0;
        const sources = new Map<string, TokenStanding>();
        for (const session of await tx.find<Session>('sessions', {
          identityId,
          kind: 'session-token',
        })) {
          if (session.kind !== 'session-token' || session.identityId !== identityId) continue;
          const standing = await tokenStanding(ctx, tx, principal.identity, session, now, sources);
          if (standing === 'dead') await tx.delete('sessions', session.id);
          else if (standing === 'live') live++;
        }
        if (live >= config.sts.maxSessionTokensPerIdentity)
          throw new IamError(
            'LIMIT_EXCEEDED',
            'This identity holds the maximum number of live session tokens',
            409,
          );
        const sourceSession = principal.session;
        // API keys never carry MFA; a person's session passes its own MFA state on unless a code was verified now.
        const sourceMfa = sourceSession.kind === 'user' && sourceSession.mfa === true;
        const draft: Session = {
          id: id(),
          tenantId,
          identityId,
          kind: 'session-token',
          sourceSessionId: sourceSession.id,
          tokenHash: '',
          createdAt: now,
          lastSeenAt: now,
          authenticatedAt: sourceSession.authenticatedAt,
          expiresAt: Math.min(sourceSession.expiresAt, now + durationSeconds * 1000),
          mfa: stepUp ? true : sourceMfa,
        };
        if (stepUp) draft.mfaAuthenticatedAt = now;
        else if (sourceMfa && typeof sourceSession.mfaAuthenticatedAt === 'number')
          draft.mfaAuthenticatedAt = sourceSession.mfaAuthenticatedAt;
        if (request.policy !== undefined) draft.policy = request.policy;
        if (sourceSession.policy) draft.sourcePolicy = sourceSession.policy;
        if (typeof sourceSession.credentialAuthorityId === 'string')
          draft.credentialAuthorityId = sourceSession.credentialAuthorityId;
        if (sessionName !== undefined) draft.sessionName = sessionName;
        // The issuing address: the tenant's allowlist judges it on every use, network blocks judge it and the
        // presenting address.
        const client = auth.currentClient();
        if (client && Object.keys(client).length) draft.client = { ...client };
        const { token, session } = await mintCredential(ctx, tx, {
          identity: principal.identity,
          draft,
          format,
          audience,
        });
        await ctx.events.audit(
          tx,
          principal,
          'session-token:issued',
          tenantId,
          identityId,
          'allow',
          false,
          {
            sessionId: session.id,
            sourceSessionKind: sourceSession.kind,
            durationSeconds,
            format,
            mfaStepUp: stepUp !== undefined,
          },
        );
        return temporaryCredential(token, session, now);
      },
    );
  }

  return {
    /**
     * GetCallerIdentity: who the presented credential acts as, for every session kind (user, impersonation, API key,
     * role session, session token, session JWT). The credential is re-validated like any other use, so this doubles as
     * the online revocation check for holders of a session JWT. Needs no permission and writes no audit event; the
     * result is an allowlist projection that never carries hashes, policies or authority ids.
     */
    async getCallerIdentity(credential: CredentialInput): Promise<CallerIdentity> {
      const authenticated = await ctx.principals.authenticate(credential);
      const principal = await ctx.store.transaction((tx) =>
        ctx.principals.currentPrincipal(tx, authenticated),
      );
      return callerIdentity(principal);
    },

    /**
     * GetSessionToken: a temporary credential of kind 'session-token' (`biam_sts_…`, or a session JWT with
     * `format: 'jwt'`) for the caller's own identity, minted from a user session (not impersonated) or an API key.
     * Needs `iam:session-tokens:create` on `iam/{identityId}` in the identity's tenant. The token acts with the
     * identity's grants, bounded by `input.policy` and by the source's own policy (API-key scopes, kept as
     * `sourcePolicy`) and authority; it expires with its source at the latest, ends when the source ends, and cannot
     * pass recent-authentication, ownership, root or self-service checks.
     *
     * With `mfaCode` (user sources whose identity has TOTP enabled only), a first-hand code is verified and the token
     * carries a fresh MFA time; the attempt counts against the sensitive rate limit first. Without it, the source's
     * MFA state is copied (API keys: never MFA). Live tokens per identity are capped (`sts.maxSessionTokensPerIdentity`):
     * tokens that can never be used again (expired, or whose source is gone, expired, idled out or lost its key
     * authority) do not count and are deleted at issuance, and tokens whose source is refused for a liftable reason
     * (a network block, an MFA requirement) do not count while it lasts.
     * Audited as the operation plus a `session-token:issued` event naming the new session.
     *
     * The issuing client is recorded on the token. In-process integrations that pass the incoming request's headers
     * as the credential (with no client scope set) get the client derived from those headers (`http.clientInfo`),
     * exactly as behind the HTTP handler, so allowlists, network blocks and `bindSessionsToIp` judge the token.
     */
    async getSessionToken(
      credential: CredentialInput,
      input: GetSessionTokenInput = {},
    ): Promise<TemporaryCredential> {
      if (!auth.currentClient() && credential?.headers)
        return auth.withClient(
          clientFromHeaders(ctx.options, credential.headers, config.baseURL),
          () => issueSessionToken(credential, input),
        );
      return issueSessionToken(credential, input);
    },

    ...createWebIdentityStsApi(ctx),
  };
}
