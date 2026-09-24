import argon2 from 'argon2';
import {
  IamError,
  type AuditEvent,
  type CredentialInput,
  type Identity,
  type Json,
  type Session,
  type Tenant,
} from '@better-iam/core';
import type {
  SafeIdentity,
  SafeSession,
  SafeTrustedDevice,
  SignInResult,
  TrustedDevice,
} from '../types.js';
import { email, publicIdentity, publicSession, text } from '../validation.js';
import { AuthBase } from './base.js';

/** Password sign-up and sign-in, plus session listing and revocation. */
export class SessionAuth extends AuthBase {
  async signUp(input: {
    tenantId: string;
    email: string;
    name: string;
    password: string;
  }): Promise<{ identity: SafeIdentity; verificationRequired: boolean }> {
    if (!this.options.signUpEnabled || this.options.emailPassword === false)
      throw new IamError('FEATURE_DISABLED', 'Self registration is disabled', 403);
    const tenantId = text(input.tenantId, 'tenantId');
    const normalized = email(input.email);
    await this.rate(tenantId, `signup:${normalized}`, 'sensitive');
    return this.options.store.transaction(async (tx) => {
      await this.assertTenantActive(tx, tenantId);
      const tenant = await tx.get<Tenant>('tenants', tenantId);
      if (!tenant?.parentId)
        throw new IamError(
          'FORBIDDEN',
          'Root identity provisioning requires an administrator',
          403,
        );
      const created = await this.createIdentity(tx, {
        ...input,
        tenantId,
        email: normalized,
        owner: false,
        rootAdmin: false,
        emailVerified: false,
      });
      // Nobody has proven this address yet: see Identity.unprovenPassword (finishPasswordless acts on it).
      const identity = await tx.put<Identity>('identities', { ...created, unprovenPassword: true });
      if (this.requireEmailVerification) {
        const token = await this.challenge(
          tx,
          identity,
          'verify-email',
          { email: normalized },
          24 * 60 * 60_000,
        );
        await this.enqueue(tx, identity, 'email', normalized, 'verify-email', { token });
      }
      return {
        identity: publicIdentity(identity),
        verificationRequired: this.requireEmailVerification,
      };
    });
  }

  /** `deviceToken` (from "remember this device") lets a browser that completed MFA before skip the second factor. */
  async signIn(input: {
    tenantId: string;
    email: string;
    password: string;
    deviceToken?: string;
  }): Promise<SignInResult> {
    if (this.options.emailPassword === false)
      throw new IamError('FEATURE_DISABLED', 'Password authentication is disabled', 403);
    const tenantId = text(input.tenantId, 'tenantId');
    const normalized = email(input.email);
    text(input.password, 'password', 1024);
    const deviceToken =
      input.deviceToken === undefined ? undefined : text(input.deviceToken, 'deviceToken', 512);
    await this.rate(tenantId, `signin:${normalized}`);
    // A wrong password for a real, active account is counted after the refused transaction rolled back, without
    // holding the refusal (an unknown address writes nothing, so waiting would reveal which accounts exist).
    let failed: Identity | undefined;
    try {
      return await this.options.store.transaction(async (tx) => {
        await this.assertTenantActive(tx, tenantId);
        await this.methodAllowed(tx, tenantId, 'password');
        const identity = (
          await tx.find<Identity>('identities', { tenantId, email: normalized })
        )[0];
        // Unknown and passwordless-only accounts perform the same password-hash operation.
        const valid = await argon2.verify(
          identity?.passwordHash ?? (await this.dummyPasswordHash),
          input.password,
        );
        // An expired identity is refused like a disabled one (and, like it, leaves no failure record).
        const usable = identity?.status === 'active' && !this.identityExpired(identity);
        if (!identity || !valid || !usable) {
          if (identity && !valid && identity.kind === 'user' && usable) failed = identity;
          throw new IamError('INVALID_CREDENTIALS', 'Invalid email or password', 401);
        }
        if (this.requireEmailVerification && !identity.emailVerified)
          throw new IamError('EMAIL_UNVERIFIED', 'Verify your email before signing in', 403);
        await this.assertPasswordCurrent(tx, identity);
        return await this.completeAuthentication(tx, identity, 'password', deviceToken);
      });
    } catch (error) {
      if (failed) this.deferSignInFailure(failed, 'password');
      throw error;
    }
  }

  /**
   * The caller's own authentication trail (sessions, failed attempts, factors, passwords, devices, passkeys),
   * newest first: the `auth:*` audit events recorded for their identity in this tenant, with the administrator
   * named when one acted through impersonation and the event's `metadata` (such as the client behind a sign-in or
   * a failed attempt). For account pages; the tenant's full audit log needs `iam:audit:read`.
   */
  async listSecurityEvents(
    credentials: CredentialInput,
    input: { limit?: number } = {},
  ): Promise<
    {
      id: string;
      action: string;
      timestamp: number;
      impersonatorId?: string;
      sequence?: number;
      metadata?: Record<string, Json>;
    }[]
  > {
    const limit = input.limit ?? 50;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200)
      throw new IamError('INVALID_INPUT', 'limit must be an integer between 1 and 200');
    const principal = await this.authenticate(credentials);
    return (
      await this.options.store.find<AuditEvent>('audit', {
        tenantId: principal.identity.tenantId,
        actorId: principal.identity.id,
      })
    )
      .filter((event) => event.action.startsWith('auth:'))
      .sort((a, b) => b.timestamp - a.timestamp || (a.id < b.id ? 1 : -1))
      .slice(0, limit)
      .map((event) => ({
        id: event.id,
        action: event.action,
        timestamp: event.timestamp,
        ...(event.impersonatorId ? { impersonatorId: event.impersonatorId } : {}),
        ...(typeof event.sequence === 'number' ? { sequence: event.sequence } : {}),
        ...(event.metadata ? { metadata: event.metadata } : {}),
      }));
  }

  /** Remembered devices of the caller in this tenant, newest first, without their tokens. */
  async listTrustedDevices(credentials: CredentialInput): Promise<SafeTrustedDevice[]> {
    const principal = await this.authenticate(credentials);
    return (
      await this.options.store.find<TrustedDevice>('authDevices', {
        identityId: principal.identity.id,
        tenantId: principal.identity.tenantId,
      })
    )
      .filter((device) => device.expiresAt > this.now())
      .sort((a, b) => b.lastUsedAt - a.lastUsedAt || (a.id < b.id ? -1 : 1))
      .map(({ tokenHash: _hash, uniqueKey: _key, ...safe }) => safe);
  }

  /** Forgets one remembered device; the next sign-in from it asks for MFA again. Requires recent authentication. */
  async revokeTrustedDevice(
    credentials: CredentialInput,
    input: { deviceId: string },
  ): Promise<{ success: true }> {
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      const device = await tx.get<TrustedDevice>('authDevices', text(input.deviceId, 'deviceId'));
      if (
        !device ||
        device.identityId !== principal.identity.id ||
        device.tenantId !== principal.identity.tenantId
      )
        throw new IamError('NOT_FOUND', 'Device not found', 404);
      await tx.delete('authDevices', device.id);
      await this.audit(tx, principal.identity, 'auth:device:revoke');
      return { success: true };
    });
  }

  /** Forgets every remembered device of the caller. Requires recent authentication. */
  async revokeTrustedDevices(credentials: CredentialInput): Promise<{ revoked: number }> {
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      const devices = await tx.find<TrustedDevice>('authDevices', {
        identityId: principal.identity.id,
        tenantId: principal.identity.tenantId,
      });
      for (const device of devices) await tx.delete('authDevices', device.id);
      if (devices.length) await this.audit(tx, principal.identity, 'auth:device:revoke');
      return { revoked: devices.length };
    });
  }

  /**
   * The caller's identity and session, plus the limits in force for their tenant: the absolute lifetime, the idle
   * timeout, and `idleExpiresAt`, when the session lapses if nothing touches it again (this call just did), so a
   * client can warn before an idle sign-out and keep the session alive on request.
   */
  async getSession(credentials: CredentialInput): Promise<{
    identity: SafeIdentity;
    session: SafeSession;
    /** `now` is the server's clock when it answered, so clients can correct for their own clock skew. */
    limits: { lifetimeMs: number; idleTimeoutMs: number; idleExpiresAt: number; now: number };
  }> {
    const principal = await this.authenticate(credentials);
    const tenant = await this.options.store.get<Tenant>('tenants', principal.identity.tenantId);
    const { lifetimeMs, idleTimeoutMs } = this.sessionLimits(tenant);
    return {
      identity: publicIdentity(principal.identity),
      session: publicSession(principal.session),
      limits: {
        lifetimeMs,
        idleTimeoutMs,
        idleExpiresAt: Math.min(
          principal.session.lastSeenAt + idleTimeoutMs,
          principal.session.expiresAt,
        ),
        now: this.now(),
      },
    };
  }

  /** The caller's live sessions; `current` marks the one making this call. */
  async listSessions(
    credentials: CredentialInput,
  ): Promise<Array<SafeSession & { current: boolean }>> {
    const principal = await this.authenticate(credentials);
    return (
      await this.options.store.find<Session>('sessions', {
        identityId: principal.identity.id,
        tenantId: principal.identity.tenantId,
      })
    )
      .filter((session) => session.expiresAt > this.now())
      .map((session) => ({
        ...publicSession(session),
        current: session.id === principal.session.id,
      }));
  }

  async revokeSession(
    credentials: CredentialInput,
    input: { sessionId: string },
  ): Promise<{ success: true }> {
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      const session = await tx.get<Session>('sessions', text(input.sessionId, 'sessionId'));
      if (
        !session ||
        session.identityId !== principal.identity.id ||
        session.tenantId !== principal.identity.tenantId
      )
        throw new IamError('NOT_FOUND', 'Session not found', 404);
      await this.endSession(tx, session.id);
      await this.audit(tx, principal.identity, 'auth:session:revoke');
      return { success: true };
    });
  }

  /** Ends every other user session of the caller's identity in this tenant ("sign out everywhere else"). */
  async revokeOtherSessions(credentials: CredentialInput): Promise<{ revoked: number }> {
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      let revoked = 0;
      for (const session of await tx.find<Session>('sessions', {
        identityId: principal.identity.id,
        tenantId: principal.identity.tenantId,
        kind: 'user',
      }))
        if (session.id !== principal.session.id) {
          await this.endSession(tx, session.id);
          revoked++;
        }
      await this.audit(tx, principal.identity, 'auth:session:revoke-others');
      return { revoked };
    });
  }

  async signOut(credentials: CredentialInput): Promise<{ success: true }> {
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      await this.endSession(tx, principal.session.id);
      await this.audit(tx, principal.identity, 'auth:session:revoke', principal.session);
      return { success: true };
    });
  }
}
