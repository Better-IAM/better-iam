import { randomInt } from 'node:crypto';
import argon2 from 'argon2';
import {
  IamError,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Session,
  type Tenant,
} from '@better-iam/core';
import { hashToken } from '../crypto.js';
import type { Challenge, SignInResult } from '../types.js';
import { email, password, phone, text } from '../validation.js';
import { SessionAuth } from './sessions.js';

/** Email verification, password recovery and change, reauthentication, and email/phone changes. */
export class AccountAuth extends SessionAuth {
  async requestEmailVerification(input: {
    tenantId: string;
    email: string;
  }): Promise<{ success: true }> {
    const tenantId = text(input.tenantId, 'tenantId');
    const normalized = email(input.email);
    if (!this.options.sendEmail)
      throw new IamError('FEATURE_DISABLED', 'Email delivery is not configured');
    await this.rate(tenantId, `verify-email:${normalized}`, 'sensitive');
    return this.options.store.transaction(async (tx) => {
      await this.assertTenantActive(tx, tenantId);
      const identity = (
        await tx.find<Identity>('identities', {
          tenantId,
          email: normalized,
          status: 'active',
          kind: 'user',
        })
      )[0];
      if (identity && !identity.emailVerified) {
        const token = await this.challenge(
          tx,
          identity,
          'verify-email',
          { email: normalized },
          24 * 60 * 60_000,
        );
        await this.enqueue(tx, identity, 'email', normalized, 'verify-email', { token });
      }
      return { success: true };
    });
  }

  async verifyEmail(input: { tenantId: string; token: string }): Promise<{ success: true }> {
    await this.rate(
      text(input.tenantId, 'tenantId'),
      `verify-token:${hashToken(text(input.token, 'token'))}`,
    );
    return this.options.store.transaction(async (tx) => {
      const challenge = await this.readChallenge(tx, input.tenantId, input.token, 'verify-email');
      const identity = await this.user(tx, challenge.identityId, input.tenantId);
      // The link proves control of the address it was mailed to, and only that one: after any change of address
      // (including by an identity provider or SCIM), it verifies nothing.
      this.assertSameAddress(challenge, identity);
      identity.emailVerified = true;
      // The address owner completed the sign-up themselves, so the password they chose stands.
      delete identity.unprovenPassword;
      await tx.put('identities', identity);
      await tx.delete('authChallenges', challenge.id);
      await this.audit(tx, identity, 'auth:email:verify');
      return { success: true };
    });
  }

  async requestPasswordReset(input: {
    tenantId: string;
    email: string;
  }): Promise<{ success: true }> {
    const tenantId = text(input.tenantId, 'tenantId');
    const normalized = email(input.email);
    if (!this.options.sendEmail || this.options.emailPassword === false)
      throw new IamError('FEATURE_DISABLED', 'Password recovery is unavailable');
    await this.rate(tenantId, `password-reset:${normalized}`, 'sensitive');
    return this.options.store.transaction(async (tx) => {
      await this.assertTenantActive(tx, tenantId);
      const identity = (
        await tx.find<Identity>('identities', {
          tenantId,
          email: normalized,
          status: 'active',
          kind: 'user',
        })
      )[0];
      if (identity?.emailVerified) {
        const token = await this.challenge(tx, identity, 'password-reset', { email: normalized });
        await this.enqueue(tx, identity, 'email', normalized, 'password-reset', { token });
      }
      return { success: true };
    });
  }

  /** Internal: queues a password-reset email for an identity on an administrator's behalf, verified or not. */
  async issuePasswordReset(tx: IamStore, identity: Identity): Promise<void> {
    if (!this.options.sendEmail || this.options.emailPassword === false)
      throw new IamError('FEATURE_DISABLED', 'Password recovery is unavailable');
    if (identity.kind !== 'user' || identity.status !== 'active' || !identity.email)
      throw new IamError('INVALID_INPUT', 'Only active people with an email can reset a password');
    const token = await this.challenge(tx, identity, 'password-reset', { email: identity.email });
    await this.enqueue(tx, identity, 'email', identity.email, 'password-reset', { token });
  }

  /** Refuses a mailed link once the identity's address is no longer the one it was sent to. */
  protected assertSameAddress(challenge: Challenge, identity: Identity): void {
    if (!identity.email || challenge.payload.email !== identity.email)
      throw new IamError('INVALID_CHALLENGE', 'Email has changed', 401);
  }

  async resetPassword(input: {
    tenantId: string;
    token: string;
    password: string;
  }): Promise<{ success: true }> {
    if (this.options.emailPassword === false)
      throw new IamError('FEATURE_DISABLED', 'Password authentication is disabled', 403);
    const newPassword = password(input.password);
    await this.rate(
      text(input.tenantId, 'tenantId'),
      `reset-token:${hashToken(text(input.token, 'token'))}`,
    );
    return this.options.store.transaction(async (tx) => {
      const challenge = await this.readChallenge(tx, input.tenantId, input.token, 'password-reset');
      const identity = await this.user(tx, challenge.identityId, input.tenantId);
      this.assertSameAddress(challenge, identity);
      // A password chosen through the mailed link is the address owner's.
      delete identity.unprovenPassword;
      await this.setPassword(
        tx,
        await tx.get<Tenant>('tenants', identity.tenantId),
        identity,
        newPassword,
      );
      await tx.put('identities', identity);
      await this.revokeIdentity(tx, identity.id);
      // Recovery never creates a session or removes MFA.
      await this.audit(tx, identity, 'auth:password:reset');
      return { success: true };
    });
  }

  async changePassword(
    credentials: CredentialInput,
    input: { currentPassword: string; password: string },
  ): Promise<{ success: true }> {
    const newPassword = password(input.password);
    text(input.currentPassword, 'currentPassword', 1024);
    const initial = await this.authenticate(credentials);
    await this.rate(initial.identity.tenantId, `password-change:${initial.identity.id}`);
    // A wrong current password is a failed attempt on the account like one at sign-in: someone holding a session
    // may be guessing it. It is recorded once the refusal rolled back.
    let failed: Identity | undefined;
    try {
      return await this.options.store.transaction(async (tx) => {
        const principal = await this.authenticate(credentials);
        this.requireRecent(principal);
        if (
          !principal.identity.passwordHash ||
          !(await argon2.verify(principal.identity.passwordHash, input.currentPassword))
        ) {
          failed = principal.identity;
          throw new IamError('INVALID_CREDENTIALS', 'Invalid current password', 401);
        }
        await this.setPassword(
          tx,
          await tx.get<Tenant>('tenants', principal.identity.tenantId),
          principal.identity,
          newPassword,
        );
        await tx.put('identities', principal.identity);
        await this.revokeIdentity(tx, principal.identity.id);
        await this.audit(tx, principal.identity, 'auth:password:change');
        return { success: true as const };
      });
    } catch (error) {
      if (failed) this.deferSignInFailure(failed, 'password');
      throw error;
    }
  }

  /** Re-runs the password (and MFA) ceremony for an existing session so sensitive operations can require recent authentication. */
  async reauthenticate(
    credentials: CredentialInput,
    input: { password: string },
  ): Promise<SignInResult> {
    if (this.options.emailPassword === false)
      throw new IamError('FEATURE_DISABLED', 'Password authentication is disabled', 403);
    text(input.password, 'password', 1024);
    const initial = await this.authenticate(credentials);
    if (initial.session.impersonatorId)
      throw new IamError(
        'IMPERSONATION_RESTRICTED',
        'An impersonated session cannot be re-authenticated',
        403,
      );
    await this.rate(initial.identity.tenantId, `reauth:${initial.identity.id}`);
    // Reauthentication is a sign-in (it issues a session and restarts the sign-in record), so a wrong password here
    // is recorded like one at sign-in once the refusal rolled back.
    let failed: Identity | undefined;
    try {
      return await this.options.store.transaction(async (tx) => {
        const principal = await this.authenticate(credentials);
        await this.methodAllowed(tx, principal.identity.tenantId, 'password');
        if (
          !principal.identity.passwordHash ||
          !(await argon2.verify(principal.identity.passwordHash, input.password))
        ) {
          failed = principal.identity;
          throw new IamError('INVALID_CREDENTIALS', 'Invalid password', 401);
        }
        // As at sign-in: an expired password is refused once verified, so each new session cannot dodge the expiry.
        await this.assertPasswordCurrent(tx, principal.identity);
        return await this.completeAuthentication(tx, principal.identity, 'password');
      });
    } catch (error) {
      if (failed) this.deferSignInFailure(failed, 'password');
      throw error;
    }
  }

  async requestEmailChange(
    credentials: CredentialInput,
    input: { email: string },
  ): Promise<{ success: true }> {
    const normalized = email(input.email);
    const initial = await this.authenticate(credentials);
    await this.rate(initial.identity.tenantId, `email-change:${initial.identity.id}`, 'sensitive');
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      const token = await this.challenge(
        tx,
        principal.identity,
        'email-change',
        { email: normalized },
        10 * 60_000,
        undefined,
        principal.session.id,
      );
      await this.enqueue(tx, principal.identity, 'email', normalized, 'email-change', { token });
      return { success: true };
    });
  }

  async confirmEmailChange(input: { tenantId: string; token: string }): Promise<{ success: true }> {
    await this.rate(
      text(input.tenantId, 'tenantId'),
      `email-change-token:${hashToken(text(input.token, 'token'))}`,
    );
    return this.options.store.transaction(async (tx) => {
      const challenge = await this.readChallenge(tx, input.tenantId, input.token, 'email-change');
      const identity = await this.user(tx, challenge.identityId, input.tenantId);
      const session =
        challenge.sessionId && (await tx.get<Session>('sessions', challenge.sessionId));
      if (!session || session.expiresAt <= this.now())
        throw new IamError('UNAUTHENTICATED', 'Original session is no longer valid', 401);
      const normalized = email(challenge.payload.email);
      if (
        (
          await tx.find<Identity>('identities', { tenantId: input.tenantId, email: normalized })
        ).some((item) => item.id !== identity.id)
      )
        throw new IamError('IDENTITY_EXISTS', 'Email is already in use in this tenant', 409);
      identity.email = normalized;
      identity.emailVerified = true;
      identity.uniqueKey = `email:${normalized}`;
      await tx.put('identities', identity);
      await this.revokeIdentity(tx, identity.id);
      await this.audit(tx, identity, 'auth:email:change');
      return { success: true };
    });
  }

  async startPhoneVerification(
    credentials: CredentialInput,
    input: { phone: string },
  ): Promise<{ success: true }> {
    const normalized = phone(input.phone);
    const initial = await this.authenticate(credentials);
    await this.rate(initial.identity.tenantId, `phone-verify:${initial.identity.id}`, 'sensitive');
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      const token = randomInt(0, 1_000_000).toString().padStart(6, '0');
      await this.challenge(
        tx,
        principal.identity,
        'phone-verify',
        { phone: normalized },
        5 * 60_000,
        token,
        principal.session.id,
      );
      await this.enqueue(tx, principal.identity, 'sms', normalized, 'phone-verify', { token });
      return { success: true };
    });
  }

  async confirmPhoneVerification(
    credentials: CredentialInput,
    input: { phone: string; code: string },
  ): Promise<{ success: true }> {
    const normalized = phone(input.phone);
    text(input.code, 'code', 6);
    const initial = await this.authenticate(credentials);
    await this.rate(initial.identity.tenantId, `phone-code:${initial.identity.id}`, 'sensitive');
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      const challenge = await this.readChallenge(
        tx,
        principal.identity.tenantId,
        input.code,
        'phone-verify',
        { identityId: principal.identity.id },
      );
      if (
        challenge.identityId !== principal.identity.id ||
        challenge.sessionId !== principal.session.id ||
        challenge.payload.phone !== normalized
      )
        throw new IamError('INVALID_CHALLENGE', 'Invalid verification code', 401);
      const existing = await tx.find<Identity>('identities', {
        tenantId: principal.identity.tenantId,
        phone: normalized,
        phoneVerified: true,
      });
      if (existing.some((identity) => identity.id !== principal.identity.id))
        throw new IamError('PHONE_EXISTS', 'Phone is already verified by another identity', 409);
      principal.identity.phone = normalized;
      principal.identity.phoneVerified = true;
      await tx.put('identities', principal.identity);
      await tx.delete('authChallenges', challenge.id);
      await this.audit(tx, principal.identity, 'auth:phone:verify');
      return { success: true };
    });
  }
}
