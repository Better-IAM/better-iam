import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Session,
  type Tenant,
} from '@better-iam/core';
import { credentialTokenKinds, parseCredentialToken } from '@better-iam/auth';
import { assertAgentUsable, machineIdentity } from './agents.js';
import { clientFromHeaders } from './client-info.js';
import type { ServerContext } from './context.js';
import { checkDelegatedSession } from './delegations.js';
import { deviceProofOf, withRequestDevice } from './devices.js';
import { trustRequiresMfa } from './flows.js';
import type { OidcProvider, Role, Trust } from './models.js';
import { revokedByWatermark } from './session-kinds.js';
import { looksLikeJwt, type SessionTokenClaims } from './session-tokens.js';
import { hash, sameHash } from './utils.js';
import { text } from './validation.js';

export interface PrincipalService {
  /**
   * Resolves a credential to its identity and session: user sessions through the auth service; API keys, role
   * sessions, session tokens and IAM-signed session JWTs here. Every credential is backed by a stored session row.
   */
  authenticate(input: CredentialInput): Promise<AuthenticatedPrincipal>;
  /** Re-reads the principal inside a transaction and re-validates every revocation condition before it is used. */
  currentPrincipal(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
  ): Promise<AuthenticatedPrincipal>;
}

/** The kinds a session token may be minted from; temporary kinds never are (no chaining). */
const sessionTokenSourceKinds: ReadonlySet<Session['kind']> = new Set(['user', 'api-key']);
/** The kinds a classic role session may be assumed from; a session-token source is re-validated down to its root. */
const roleSourceKinds: ReadonlySet<Session['kind']> = new Set(['user', 'api-key', 'session-token']);
/** The shape of every opaque token (legacy unprefixed ones included); anything else is never looked up. */
const opaqueToken = /^[A-Za-z0-9_-]{32,512}$/;
/** `Authorization: Bearer <value>`; the scheme is case-insensitive (RFC 9110). */
const bearerHeader = /^Bearer (\S{1,4096})$/i;

/** The presented credential: `input.token`, else the bearer header, else '' (the auth service reads cookies). */
function credentialValue(input: CredentialInput): string {
  if (input.token) return text(input.token, 'token', 4096);
  const headers = new Headers(input.headers);
  return bearerHeader.exec(headers.get('authorization') ?? '')?.[1] ?? '';
}

const invalidCredentials = () => new IamError('UNAUTHENTICATED', 'Invalid credentials', 401);
const expiredOrRevoked = () =>
  new IamError('UNAUTHENTICATED', 'Credential expired or revoked', 401);
const roleRevoked = () => new IamError('UNAUTHENTICATED', 'Role credential revoked', 401);

/**
 * A session token bound by `bindSessionsToIp` presented from another network. `authenticate` records it as
 * `auth:session:mismatch` after the refusal rolled back, as the auth service does for user sessions.
 */
class SessionTokenNetworkMismatch extends IamError {
  /** Ids only, never the rows: an in-process caller may log the error. */
  readonly sessionId: string;
  readonly identityId: string;
  readonly sessionIp: string;
  constructor(session: Session) {
    super(
      'SESSION_NETWORK_MISMATCH',
      'This session can only be used from the network it was signed in from',
      401,
    );
    this.sessionId = session.id;
    this.identityId = session.identityId;
    this.sessionIp = session.client?.ip ?? '';
  }
}

/** Whether a stored row is the one a verified session JWT names (its claims bind kind, identity and tenant). */
function boundToJwt(session: Session, claims: SessionTokenClaims): boolean {
  return (
    session.format === 'jwt' &&
    session.kind === claims.kind &&
    session.identityId === claims.sub &&
    session.tenantId === claims.tid
  );
}

export function createPrincipals(ctx: ServerContext): PrincipalService {
  const { store, auth, options } = ctx;

  /**
   * The path every non-user credential shares once its row is known: the row is re-read in a transaction, must be
   * unexpired and carry the presented token's hash (plus `bound` for JWT rows), its identity must be active and not
   * expired, API keys record their use, and `currentPrincipal` applies the kind-specific checks.
   */
  function resolveStored(
    sessionId: string,
    tokenHash: string,
    bound: (session: Session) => boolean = () => true,
    deviceProof?: string,
  ): Promise<AuthenticatedPrincipal> {
    return store.transaction(async (tx) => {
      const session = await tx.get<Session>('sessions', sessionId);
      if (
        !session ||
        session.expiresAt <= ctx.now() ||
        !sameHash(session.tokenHash, tokenHash) ||
        !bound(session)
      )
        throw expiredOrRevoked();
      const identity = await tx.get<Identity>('identities', session.identityId);
      if (!identity || identity.status !== 'active')
        throw new IamError('UNAUTHENTICATED', 'Identity disabled', 401);
      if (ctx.identityExpired(identity))
        throw new IamError('UNAUTHENTICATED', 'Identity expired', 401);
      // API keys record when they were last used (at most once a minute) so unused keys can be found and revoked.
      const now = ctx.now();
      const current =
        session.kind === 'api-key' && now - session.lastSeenAt >= 60_000
          ? await tx.put<Session>('sessions', { ...session, lastSeenAt: now })
          : session;
      // The request's device proof goes along: a role session's source decides its assumption again here.
      return service.currentPrincipal(tx, {
        identity,
        session: current,
        ...(deviceProof !== undefined ? { deviceProof } : {}),
      });
    });
  }

  /**
   * Hybrid session JWTs: the signature, header and claims are verified first (no storage read for a bad token),
   * then the stored row the `sid` names must be a JWT row bound to the same kind, identity and tenant, holding the
   * hash of exactly this token. Revocation inside IAM is therefore immediate, whatever the token's `exp`.
   */
  async function resolveJwt(value: string, deviceProof?: string): Promise<AuthenticatedPrincipal> {
    const signer = ctx.sessionTokens;
    if (!signer) throw invalidCredentials();
    let claims: SessionTokenClaims;
    try {
      claims = await signer.verify(value, { audience: signer.issuer });
    } catch {
      throw invalidCredentials();
    }
    const tokenHash = hash(value);
    const candidate = await store.get<Session>('sessions', claims.sid);
    if (!candidate || !boundToJwt(candidate, claims) || !sameHash(candidate.tokenHash, tokenHash))
      throw expiredOrRevoked();
    return resolveStored(
      candidate.id,
      tokenHash,
      (session) => boundToJwt(session, claims),
      deviceProof,
    );
  }

  async function resolveCredential(input: CredentialInput): Promise<AuthenticatedPrincipal> {
    const provided = credentialValue(input);
    if (!provided) return auth.authenticate(input);
    const deviceProof = deviceProofOf(input?.headers);
    // (`looksLikeJwt` is a type guard over unknown; the cast keeps `provided` a string on the other branch.)
    if (looksLikeJwt(provided as unknown)) return resolveJwt(provided, deviceProof);
    // Prefixed tokens route by type; the stored kind stays authoritative and a mismatch never falls back to auth.
    let expected: Session['kind'] | undefined;
    if (provided.startsWith('biam_')) {
      const parsed = parseCredentialToken(provided);
      if (!parsed) throw invalidCredentials();
      if (parsed.type === 'ses') return auth.authenticate(input);
      expected = credentialTokenKinds[parsed.type];
    } else if (!opaqueToken.test(provided)) return auth.authenticate(input); // refused there, unread

    const tokenHash = hash(provided);
    const candidate = (await store.find<Session>('sessions', { tokenHash }))[0];
    if (expected !== undefined) {
      if (!candidate || candidate.kind !== expected) throw invalidCredentials();
    } else if (!candidate || candidate.kind === 'user') return auth.authenticate(input);
    return resolveStored(candidate.id, tokenHash, undefined, deviceProof);
  }

  /**
   * A session token (GetSessionToken) lives only as long as its source: the source must still exist as a user
   * session or API key of the same identity and tenant (never an impersonation), the token may not outlive it or
   * carry another authority, and the source is re-validated under its own rules.
   */
  async function checkSessionToken(tx: IamStore, identity: Identity, session: Session) {
    const source =
      typeof session.sourceSessionId === 'string'
        ? await tx.get<Session>('sessions', session.sourceSessionId)
        : undefined;
    if (
      !source ||
      !sessionTokenSourceKinds.has(source.kind) ||
      source.impersonatorId ||
      source.identityId !== identity.id ||
      source.tenantId !== session.tenantId ||
      session.tenantId !== identity.tenantId ||
      session.expiresAt > source.expiresAt ||
      session.credentialAuthorityId !== source.credentialAuthorityId
    )
      throw new IamError('UNAUTHENTICATED', 'Session token revoked', 401);
    await service.currentPrincipal(tx, { identity, session: source });
  }

  /**
   * Role sessions. Common to both forms: a live trust and role of the session's tenant that belong together, the
   * session's anchoring identity, and the trust and role revocation watermarks. Then either the classic checks (a
   * source credential re-validated recursively and a live re-decision of `iam:roles:assume`) or the web-identity
   * checks (an enabled provider, the anchoring service account, and the trust and provider authority chains).
   */
  async function checkRoleSession(
    tx: IamStore,
    identity: Identity,
    session: Session,
    request: AuthenticatedPrincipal,
  ) {
    const trust =
      typeof session.trustId === 'string'
        ? await tx.get<Trust>('trusts', session.trustId)
        : undefined;
    const role =
      typeof session.roleId === 'string' ? await tx.get<Role>('roles', session.roleId) : undefined;
    if (
      !trust ||
      trust.revoked ||
      trust.tenantId !== session.tenantId ||
      !role ||
      role.tenantId !== session.tenantId ||
      trust.roleId !== role.id ||
      session.originalIdentityId !== identity.id ||
      revokedByWatermark(session.createdAt, trust.sessionsRevokedBefore, role.sessionsRevokedBefore)
    )
      throw roleRevoked();
    if (session.webIdentity) await checkWebIdentitySession(tx, identity, session, trust, role);
    else await checkClassicRoleSession(tx, identity, session, trust, role, request);
  }

  async function checkClassicRoleSession(
    tx: IamStore,
    identity: Identity,
    session: Session,
    trust: Trust,
    role: Role,
    request: AuthenticatedPrincipal,
  ) {
    const source =
      typeof session.sourceSessionId === 'string'
        ? await tx.get<Session>('sessions', session.sourceSessionId)
        : undefined;
    const consistent =
      (trust.kind ?? 'identity') === 'identity' &&
      trust.sourceIdentityId === identity.id &&
      trust.sourceTenantId === identity.tenantId &&
      session.sourceTenantId === identity.tenantId &&
      source &&
      roleSourceKinds.has(source.kind) &&
      source.identityId === identity.id &&
      source.tenantId === identity.tenantId &&
      // Read fail-closed: any stored value but `false` requires a source session that carries MFA.
      !(trustRequiresMfa(trust) && source.mfa !== true);
    if (!consistent) throw roleRevoked();
    // The re-decision sees the device this request proves (bound to the role session), as the assumption saw the
    // device of the request that made it; device conditions on iam:roles:assume would otherwise always fail here.
    const verifiedSource = withRequestDevice(
      await service.currentPrincipal(tx, { identity, session: source }),
      request,
    );
    for (const authorityId of session.sourceAuthorityIds ?? [])
      if (!(await ctx.authorityChain(tx, authorityId)))
        throw new IamError('UNAUTHENTICATED', 'Source authority revoked', 401);
    if (typeof role.authorityId !== 'string' || !(await ctx.authorityChain(tx, role.authorityId)))
      throw new IamError('UNAUTHENTICATED', 'Role authority revoked', 401);
    const sourceDecision = await ctx.decisions.decide(tx, verifiedSource, {
      tenantId: identity.tenantId,
      action: 'iam:roles:assume',
      resource: { type: 'iam', id: role.id },
    });
    if (!sourceDecision.allowed)
      throw new IamError('UNAUTHENTICATED', 'Assumption permission revoked', 401);
  }

  /**
   * Web-identity role sessions (AssumeRoleWithWebIdentity) have no source credential: they are anchored to the
   * trust's service account and bounded by the authorities of the trust's and the provider's creators. Disabling the
   * feature or the provider, revoking the trust or either authority, or a watermark ends them. Claim conditions are
   * evaluated at exchange time only.
   */
  async function checkWebIdentitySession(
    tx: IamStore,
    identity: Identity,
    session: Session,
    trust: Trust,
    role: Role,
  ) {
    const web = session.webIdentity!;
    const provider =
      typeof web.providerId === 'string'
        ? await tx.get<OidcProvider>('oidcProviders', web.providerId)
        : undefined;
    if (
      !ctx.config.sts.webIdentity.enabled ||
      trust.kind !== 'web-identity' ||
      trust.providerId !== web.providerId ||
      trust.sourceIdentityId !== identity.id ||
      trust.sourceTenantId !== session.tenantId ||
      identity.kind !== 'service' ||
      identity.tenantId !== session.tenantId ||
      session.sourceSessionId !== undefined ||
      !provider ||
      provider.tenantId !== session.tenantId ||
      provider.enabled !== true ||
      provider.issuer !== web.issuer ||
      revokedByWatermark(session.createdAt, provider.sessionsRevokedBefore) ||
      typeof trust.authorityId !== 'string' ||
      session.credentialAuthorityId !== trust.authorityId
    )
      throw roleRevoked();
    if (
      typeof provider.authorityId !== 'string' ||
      !(await ctx.authorityChain(tx, provider.authorityId)) ||
      !(await ctx.authorityChain(tx, trust.authorityId))
    )
      throw roleRevoked();
    if (typeof role.authorityId !== 'string' || !(await ctx.authorityChain(tx, role.authorityId)))
      throw new IamError('UNAUTHENTICATED', 'Role authority revoked', 401);
  }

  /**
   * `resolveCredential`, noting in the identity's trail when a bound session token (itself, or the source of a role
   * session) was presented from another network: `auth:session:mismatch` with both addresses, written in its own
   * transaction once the refusal rolled back, as the auth service records it for user sessions. Never masks the
   * refusal.
   */
  async function resolveRecorded(input: CredentialInput): Promise<AuthenticatedPrincipal> {
    try {
      return await resolveCredential(input);
    } catch (error) {
      if (error instanceof SessionTokenNetworkMismatch) {
        const client = auth.currentClient();
        try {
          await store.transaction(async (tx) => {
            const identity = await tx.get<Identity>('identities', error.identityId);
            const session = await tx.get<Session>('sessions', error.sessionId);
            if (!identity || !session) return;
            await ctx.events.audit(
              tx,
              { identity, session },
              'auth:session:mismatch',
              identity.tenantId,
              identity.id,
              'allow',
              false,
              {
                sessionId: error.sessionId,
                sessionIp: error.sessionIp,
                ...(client?.ip ? { ip: client.ip } : {}),
                ...(client?.userAgent ? { userAgent: client.userAgent } : {}),
              },
            );
          });
        } catch {
          /* Bookkeeping never masks the refusal. */
        }
      }
      throw error;
    }
  }

  const service: PrincipalService = {
    async authenticate(input) {
      // Framework integrations (Next, Nuxt, NestJS, iam.authenticate) pass the incoming request's headers as the
      // credential and set no client scope. The client is derived from those headers (`http.clientInfo`) so session
      // binding and network checks judge the presenting address as they do behind the HTTP handler.
      const principal =
        !auth.currentClient() && input?.headers
          ? await auth.withClient(
              clientFromHeaders(options, input.headers, ctx.config.baseURL),
              () => resolveRecorded(input),
            )
          : await resolveRecorded(input);
      // On an organization's own address (`hosts`), only that organization's credentials are accepted.
      auth.assertRequestHost(principal.session.tenantId);
      // A device proof travels with the principal unverified; decisions verify it (devices.ts).
      const deviceProof = deviceProofOf(input?.headers);
      return deviceProof === undefined ? principal : { ...principal, deviceProof };
    },
    async currentPrincipal(tx, principal) {
      const identity = await tx.get<Identity>('identities', principal.identity.id);
      const session = await tx.get<Session>('sessions', principal.session.id);
      const now = options.authentication?.now?.() ?? Date.now();
      if (
        !identity ||
        identity.status !== 'active' ||
        !session ||
        session.expiresAt <= now ||
        session.identityId !== identity.id ||
        session.tokenHash !== principal.session.tokenHash
      )
        throw new IamError('UNAUTHENTICATED', 'Credential revoked', 401);
      if (ctx.identityExpired(identity))
        throw new IamError('UNAUTHENTICATED', 'Identity expired', 401);
      const realm = await ctx.tenant(tx, identity.tenantId);
      if (
        (await ctx.ancestry(tx, realm)).some((item) => item.status !== 'active') ||
        (await ctx.ancestry(tx, await ctx.tenant(tx, session.tenantId))).some(
          (item) => item.status !== 'active',
        )
      )
        throw new IamError('TENANT_INACTIVE', 'Tenant inactive', 403);
      if (session.kind === 'user') {
        const limits = auth.sessionLimits(realm);
        if (
          identity.kind !== 'user' ||
          identity.tenantId !== session.tenantId ||
          now - session.lastSeenAt >= limits.idleTimeoutMs ||
          now - session.createdAt >= limits.lifetimeMs
        )
          throw new IamError('UNAUTHENTICATED', 'User session expired', 401);
        if (!session.mfa && (await auth.mfaRequired(tx, identity)))
          throw new IamError('MFA_REQUIRED', 'Multi-factor authentication is required', 403);
        await auth.assertImpersonationSource(tx, session);
        // The recorded address is judged as the auth service judges it, so a role session sourced from this one ends
        // as soon as this session's network is blocked or no longer allowed.
        auth.assertIpAllowed(realm, session.client?.ip);
        await auth.assertNetworkNotBlocked(tx, session.tenantId, session.client?.ip);
        // The address presenting the credential now (this session, or a role session sourced from it) is judged too:
        // a stolen cookie or role token is useless from a blocked network, and with `bindSessionsToIp` from any
        // network but the one this session was signed in from.
        const presented = auth.currentClient()?.ip;
        await auth.assertNetworkNotBlocked(tx, session.tenantId, presented);
        if (
          realm?.authPolicy?.bindSessionsToIp &&
          session.client?.ip &&
          presented &&
          presented !== session.client.ip
        )
          throw new SessionTokenNetworkMismatch(session);
      } else if (session.kind === 'api-key') {
        if (
          !machineIdentity(identity) ||
          identity.tenantId !== session.tenantId ||
          typeof session.credentialAuthorityId !== 'string' ||
          !(await ctx.authorityChain(tx, session.credentialAuthorityId))
        )
          throw new IamError('UNAUTHENTICATED', 'Service credential revoked', 401);
        // An agent's key works only while the agent and its sponsor are in good standing (agents.ts).
        if (identity.kind === 'agent') await assertAgentUsable(ctx, tx, identity);
      } else if (session.kind === 'session-token') await checkSessionToken(tx, identity, session);
      else if (session.kind === 'role') await checkRoleSession(tx, identity, session, principal);
      else if (session.kind === 'delegated')
        await checkDelegatedSession(ctx, tx, identity, session, (source) =>
          service.currentPrincipal(tx, source),
        );
      else throw new IamError('UNAUTHENTICATED', 'Invalid credential kind', 401);
      if (session.kind !== 'user') {
        // API keys, assumed roles and session tokens have no sign-in of their own to refuse, so they are judged against
        // the address presenting them now (and any address recorded on them): a leaked key or token is useless from a
        // blocked network. A role also honours the allowlist of the organization it acts in; a session token, like the
        // user session it may come from, has its recorded (issuing) address judged against its tenant's allowlist.
        const target: Tenant | undefined =
          session.kind === 'role' ? await ctx.tenant(tx, session.tenantId) : undefined;
        if (session.kind === 'session-token') {
          const home = await ctx.tenant(tx, session.tenantId);
          auth.assertIpAllowed(home, session.client?.ip);
          // With `bindSessionsToIp`, a session token, like a user session, works only from the network it was issued
          // from; unknown addresses on either side are not judged.
          if (home?.authPolicy?.bindSessionsToIp) {
            const presented = auth.currentClient()?.ip;
            if (session.client?.ip && presented && presented !== session.client.ip)
              throw new SessionTokenNetworkMismatch(session);
          }
        }
        for (const ip of new Set([auth.currentClient()?.ip, session.client?.ip])) {
          if (target) auth.assertIpAllowed(target, ip);
          await auth.assertNetworkNotBlocked(tx, session.tenantId, ip);
        }
      }
      // The request's device proof (still unverified) stays with the principal for decisions (devices.ts).
      return principal.deviceProof === undefined
        ? { identity, session }
        : { identity, session, deviceProof: principal.deviceProof };
    },
  };
  return service;
}
