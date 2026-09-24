import { randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { authenticator } from 'otplib';
import {
  IamError,
  type AuthMethod,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Tenant,
} from '@better-iam/core';
import { decryptSecret, encryptSecret, hashToken } from '../crypto.js';
import type {
  Challenge,
  MfaCredential,
  MfaRecord,
  MfaSessionResult,
  SessionResult,
} from '../types.js';
import { text } from '../validation.js';
import { PasswordlessAuth } from './passwordless.js';

/** TOTP enrollment, verification, recovery codes, and disabling where the tenant allows it. */
export class MfaAuth extends PasswordlessAuth {
  /**
   * The stored form of an emailed MFA code: keyed with the deployment secret and bound to its login challenge, since a
   * plain hash of six digits is reversed by trying all million values.
   */
  protected mfaCodeDigest(
    challenge: Challenge,
    code: string,
    secret = this.options.secret,
  ): string {
    return this.digestChallenge(challenge.tenantId, `mfa-code:${challenge.id}:${code}`, secret);
  }

  /** Enrollment may start from a restricted login challenge (first factor passed) or from a recently authenticated session. */
  protected async mfaActor(
    tx: IamStore,
    credential: MfaCredential,
  ): Promise<{
    identity: Identity;
    principal?: AuthenticatedPrincipal;
    loginChallenge?: Challenge;
  }> {
    if ('challenge' in credential) {
      const loginChallenge = await this.readChallenge(
        tx,
        credential.tenantId,
        credential.challenge,
        'mfa-login',
      );
      const identity = await this.user(tx, loginChallenge.identityId, credential.tenantId);
      // A password alone must not add a factor over an existing one: an enabled authenticator or a usable passkey
      // has to be presented first (then enroll from the recently authenticated session).
      if (
        (await tx.get<MfaRecord>('authMfa', identity.id))?.enabled ||
        (await this.passkeyFactor(tx, identity))
      )
        throw new IamError(
          'MFA_REQUIRED',
          'Use an existing MFA factor before changing enrollment',
          403,
        );
      return { identity, loginChallenge };
    }
    const principal = await this.authenticate(credential);
    this.requireRecent(principal);
    return { identity: principal.identity, principal };
  }

  async beginMfa(credential: MfaCredential): Promise<{ secret: string; uri: string }> {
    return this.options.store.transaction(async (tx) => {
      const actor = await this.mfaActor(tx, credential);
      const existing = await tx.get<MfaRecord>('authMfa', actor.identity.id);
      if (existing?.enabled)
        throw new IamError('MFA_ALREADY_ENABLED', 'MFA is already enabled', 409);
      // 160 bits, as RFC 4226 recommends (otplib's default is 80, below the RFC's 128-bit minimum).
      const secret = authenticator.generateSecret(20);
      const record: MfaRecord = {
        id: actor.identity.id,
        tenantId: actor.identity.tenantId,
        identityId: actor.identity.id,
        encryptedSecret: encryptSecret(secret, this.options.secret, `mfa:${actor.identity.id}`),
        recoveryHashes: [],
        enabled: false,
        lastUsedStep: -1,
        enrollmentExpiresAt: this.now() + 10 * 60_000,
        enrollmentCredential: actor.principal?.session.id ?? actor.loginChallenge!.id,
      };
      if (existing) await tx.put('authMfa', record);
      else await tx.insert('authMfa', record);
      return {
        secret,
        uri: authenticator.keyuri(actor.identity.email ?? actor.identity.id, this.appName, secret),
      };
    });
  }

  /** Accepts a code once per time step; the step is recorded so a captured code cannot be replayed. */
  protected checkTotp(record: MfaRecord, code: string): number {
    if (!/^\d{6}$/.test(code)) throw new IamError('INVALID_MFA', 'Invalid MFA code', 401);
    const totp = authenticator.clone();
    totp.options = { epoch: this.now(), window: 1 };
    const delta = totp.checkDelta(
      code,
      decryptSecret(record.encryptedSecret, this.secrets, `mfa:${record.identityId}`),
    );
    const step = Math.floor(this.now() / 30_000) + (delta ?? 0);
    if (delta === null || step <= record.lastUsedStep)
      throw new IamError('INVALID_MFA', 'Invalid or previously used MFA code', 401);
    return step;
  }

  /**
   * Internal: verifies a first-hand TOTP code for an MFA step-up on an existing credential (such as
   * `sts.getSessionToken({ mfaCode })`), inside the caller's transaction. Only an enrolled authenticator counts:
   * emailed codes, recovery codes and remembered devices never do. The code's time step is recorded, so it cannot be
   * replayed here or at sign-in. The caller rate-limits the attempt (`limitAttempt`, sensitive tier) outside the
   * transaction. Throws MFA_NOT_ENROLLED (403) for service identities and people without an enabled authenticator,
   * and INVALID_MFA (401) for a wrong or previously used code.
   */
  async verifyStepUpCode(
    tx: IamStore,
    identity: Identity,
    code: string,
  ): Promise<{ verifiedAt: number }> {
    const record =
      identity.kind === 'user' ? await tx.get<MfaRecord>('authMfa', identity.id) : undefined;
    if (!record?.enabled || record.tenantId !== identity.tenantId)
      throw new IamError('MFA_NOT_ENROLLED', 'MFA is not enrolled', 403);
    record.lastUsedStep = this.checkTotp(record, typeof code === 'string' ? code : '');
    await tx.put('authMfa', record);
    await this.audit(tx, identity, 'auth:mfa:step-up');
    return { verifiedAt: this.now() };
  }

  /** `rememberDevice` returns a device token (when the tenant allows it) that lets this browser skip MFA later. */
  async confirmMfa(input: {
    credential: MfaCredential;
    code: string;
    rememberDevice?: boolean;
  }): Promise<MfaSessionResult & { recoveryCodes: string[] }> {
    const actor = await this.options.store.transaction((tx) => this.mfaActor(tx, input.credential));
    await this.rate(actor.identity.tenantId, `mfa-enroll:${actor.identity.id}`, 'sensitive');
    return this.options.store.transaction(async (tx) => {
      const verified = await this.mfaActor(tx, input.credential);
      const record = await tx.get<MfaRecord>('authMfa', verified.identity.id);
      const valid =
        record &&
        !record.enabled &&
        typeof record.enrollmentExpiresAt === 'number' &&
        record.enrollmentExpiresAt > this.now() &&
        record.enrollmentCredential ===
          (verified.principal?.session.id ?? verified.loginChallenge?.id);
      if (!valid)
        throw new IamError('INVALID_CHALLENGE', 'MFA enrollment is invalid or expired', 401);
      record.lastUsedStep = this.checkTotp(record, input.code);
      record.enabled = true;
      const recoveryCodes = Array.from({ length: 10 }, () => randomBytes(12).toString('hex'));
      record.recoveryHashes = recoveryCodes.map(hashToken);
      await tx.put('authMfa', record);
      await this.revokeIdentity(tx, verified.identity.id);
      await this.audit(tx, verified.identity, 'auth:mfa:enable');
      const method =
        (verified.loginChallenge?.payload.method as AuthMethod | undefined) ??
        verified.principal?.session.method;
      return {
        ...(await this.issueSession(tx, verified.identity, { mfa: true, method })),
        ...(input.rememberDevice === true ? await this.rememberDevice(tx, verified.identity) : {}),
        recoveryCodes,
      };
    });
  }

  async verifyMfa(input: {
    tenantId: string;
    challenge: string;
    code: string;
    rememberDevice?: boolean;
  }): Promise<MfaSessionResult> {
    text(input.code, 'code', 6);
    const tenantId = text(input.tenantId, 'tenantId');
    const token = text(input.challenge, 'challenge');
    await this.rate(tenantId, `mfa:${hashToken(token)}`, 'sensitive');
    // Also per person: each correct password mints a new challenge with a fresh per-challenge budget.
    await this.rateChallengeIdentity(tenantId, token, 'mfa-login', 'mfa-verify');
    // A wrong code for a real login challenge counts as a failed attempt once the refusal rolled back.
    let attempted: Identity | undefined;
    try {
      return await this.options.store.transaction(async (tx) => {
        const challenge = await this.readChallenge(
          tx,
          input.tenantId,
          input.challenge,
          'mfa-login',
        );
        const identity = await this.user(tx, challenge.identityId, input.tenantId);
        attempted = identity;
        const record = await tx.get<MfaRecord>('authMfa', identity.id);
        if (record?.enabled) {
          record.lastUsedStep = this.checkTotp(record, input.code);
          await tx.put('authMfa', record);
        } else {
          // No authenticator: only a code emailed for this very challenge (see requestMfaCode) can satisfy it.
          const expected = challenge.payload.codeHash;
          const validUntil = Number(challenge.payload.codeExpiresAt);
          const matches = this.secrets.some((secret) => {
            const provided = this.mfaCodeDigest(challenge, input.code, secret);
            return (
              !!expected &&
              expected.length === provided.length &&
              timingSafeEqual(Buffer.from(expected), Buffer.from(provided))
            );
          });
          if (!expected || !(validUntil > this.now()) || !matches)
            throw new IamError(
              expected ? 'INVALID_MFA' : 'MFA_NOT_ENROLLED',
              expected ? 'Invalid or expired code' : 'MFA is not enrolled',
              expected ? 401 : 403,
            );
        }
        await tx.delete('authChallenges', challenge.id);
        const session = await this.issueSession(tx, identity, {
          mfa: true,
          method: challenge.payload.method as AuthMethod | undefined,
        });
        return {
          ...session,
          ...(input.rememberDevice === true ? await this.rememberDevice(tx, identity) : {}),
        };
      });
    } catch (error) {
      if (attempted && error instanceof IamError && error.code === 'INVALID_MFA')
        this.deferSignInFailure(attempted, 'mfa');
      throw error;
    }
  }

  /**
   * Emails a six-digit one-time code for a login challenge whose sign-in offered `emailCodeAvailable`; `verifyMfa`
   * then accepts it once, within ten minutes and before the challenge itself expires. Requesting again replaces the
   * code. Rate limited as a sensitive flow per challenge and per person.
   */
  async requestMfaCode(input: {
    tenantId: string;
    challenge: string;
  }): Promise<{ success: true; expiresAt: number }> {
    const tenantId = text(input.tenantId, 'tenantId');
    const token = text(input.challenge, 'challenge', 512);
    await this.rate(tenantId, `mfa-code:${hashToken(token)}`, 'sensitive');
    // Per person too, so repeated sign-ins cannot queue unbounded code emails to the account's inbox.
    await this.rateChallengeIdentity(tenantId, token, 'mfa-login', 'mfa-code-send');
    return this.options.store.transaction(async (tx) => {
      const challenge = await this.readChallenge(tx, tenantId, token, 'mfa-login');
      if (challenge.payload.emailCodes !== '1')
        throw new IamError(
          'FEATURE_DISABLED',
          'Emailed codes are not available for this sign-in',
          403,
        );
      const identity = await this.user(tx, challenge.identityId, tenantId);
      if (!identity.email || !identity.emailVerified)
        throw new IamError('FEATURE_DISABLED', 'A verified email address is required', 403);
      const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
      const expiresAt = Math.min(challenge.expiresAt, this.now() + 10 * 60_000);
      await tx.put('authChallenges', {
        ...challenge,
        payload: {
          ...challenge.payload,
          codeHash: this.mfaCodeDigest(challenge, code),
          codeExpiresAt: String(expiresAt),
        },
      });
      await this.enqueue(tx, identity, 'email', identity.email, 'mfa-code', { code });
      return { success: true, expiresAt };
    });
  }

  async recoverMfa(input: {
    tenantId: string;
    challenge: string;
    code: string;
  }): Promise<SessionResult> {
    text(input.code, 'code', 128);
    const tenantId = text(input.tenantId, 'tenantId');
    const token = text(input.challenge, 'challenge');
    await this.rate(tenantId, `mfa-recover:${hashToken(token)}`, 'sensitive');
    await this.rateChallengeIdentity(tenantId, token, 'mfa-login', 'mfa-recovery');
    let attempted: Identity | undefined;
    try {
      return await this.options.store.transaction(async (tx) => {
        const challenge = await this.readChallenge(
          tx,
          input.tenantId,
          input.challenge,
          'mfa-login',
        );
        const identity = await this.user(tx, challenge.identityId, input.tenantId);
        attempted = identity;
        const record = await tx.get<MfaRecord>('authMfa', identity.id);
        const codeHash = hashToken(input.code);
        const index =
          record?.recoveryHashes.findIndex((value) =>
            timingSafeEqual(Buffer.from(value), Buffer.from(codeHash)),
          ) ?? -1;
        if (!record?.enabled || index < 0)
          throw new IamError('INVALID_MFA', 'Invalid recovery code', 401);
        record.recoveryHashes.splice(index, 1);
        await tx.put('authMfa', record);
        await tx.delete('authChallenges', challenge.id);
        await this.audit(tx, identity, 'auth:mfa:recover');
        return await this.issueSession(tx, identity, {
          mfa: true,
          method: challenge.payload.method as AuthMethod | undefined,
        });
      });
    } catch (error) {
      if (attempted && error instanceof IamError && error.code === 'INVALID_MFA')
        this.deferSignInFailure(attempted, 'recovery-code');
      throw error;
    }
  }

  /** What the caller has set up: authenticator state, unused recovery codes, passkeys, and remembered devices. */
  async mfaStatus(credentials: CredentialInput): Promise<{
    enabled: boolean;
    recoveryCodesRemaining: number;
    passkeys: number;
    trustedDevices: number;
    sessionMfa: boolean;
  }> {
    const principal = await this.authenticate(credentials);
    const scope = { tenantId: principal.identity.tenantId, identityId: principal.identity.id };
    const record = await this.options.store.get<MfaRecord>('authMfa', principal.identity.id);
    const enabled = Boolean(record?.enabled);
    const passkeys = (await this.options.store.find('authPasskeys', scope)).length;
    const trustedDevices = (
      await this.options.store.find<{ expiresAt: number } & MfaRecord>('authDevices', scope)
    ).filter((device) => device.expiresAt > this.now()).length;
    return {
      enabled,
      recoveryCodesRemaining: enabled ? (record?.recoveryHashes.length ?? 0) : 0,
      passkeys,
      trustedDevices,
      sessionMfa: principal.session.mfa,
    };
  }

  async regenerateRecoveryCodes(
    credentials: CredentialInput,
  ): Promise<{ recoveryCodes: string[] }> {
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      if (!principal.session.mfa)
        throw new IamError('MFA_REQUIRED', 'Multi-factor authentication is required', 403);
      const record = await tx.get<MfaRecord>('authMfa', principal.identity.id);
      if (!record?.enabled) throw new IamError('MFA_NOT_ENROLLED', 'MFA is not enrolled', 403);
      const recoveryCodes = Array.from({ length: 10 }, () => randomBytes(12).toString('hex'));
      record.recoveryHashes = recoveryCodes.map(hashToken);
      await tx.put('authMfa', record);
      await this.audit(tx, principal.identity, 'auth:mfa:recovery-codes');
      return { recoveryCodes };
    });
  }

  async disableMfa(credentials: CredentialInput): Promise<{ success: true }> {
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      if (!principal.session.mfa)
        throw new IamError('MFA_REQUIRED', 'Multi-factor authentication is required', 403);
      const tenant = (await tx.get<Tenant>('tenants', principal.identity.tenantId))!;
      if (
        principal.identity.rootAdmin ||
        (await this.tenantRequiresMfa(tenant, principal.identity))
      )
        throw new IamError('MFA_REQUIRED', 'MFA is required by this tenant', 403);
      await tx.delete('authMfa', principal.identity.id);
      await this.revokeIdentity(tx, principal.identity.id);
      await this.audit(tx, principal.identity, 'auth:mfa:disable');
      return { success: true };
    });
  }
}
