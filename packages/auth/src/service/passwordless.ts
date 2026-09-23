import { randomInt } from 'node:crypto';
import { IamError, type Identity } from '@better-iam/core';
import { newToken } from '../crypto.js';
import type { SignInResult } from '../types.js';
import { email, phone, text } from '../validation.js';
import { AccountAuth } from './account.js';

/** Magic links and one-time codes over email or SMS. Passwordless sign-in never links accounts by matching email. */
export class PasswordlessAuth extends AccountAuth {
  async startPasswordless(input: {
    tenantId: string;
    destination: string;
    channel: 'email' | 'sms';
    kind: 'magic-link' | 'code';
  }): Promise<{ success: true }> {
    if (!['email', 'sms'].includes(input.channel) || !['magic-link', 'code'].includes(input.kind))
      throw new IamError('INVALID_INPUT', 'Invalid passwordless method');
    if (input.channel === 'sms' && input.kind !== 'code')
      throw new IamError('INVALID_INPUT', 'SMS authentication requires a code');
    if (
      !(input.channel === 'email' ? this.options.passwordlessEmail : this.options.passwordlessSms)
    )
      throw new IamError('FEATURE_DISABLED', 'Passwordless method is disabled');
    const tenantId = text(input.tenantId, 'tenantId');
    const destination =
      input.channel === 'email' ? email(input.destination) : phone(input.destination);
    await this.rate(tenantId, `passwordless-start:${destination}`, 'sensitive');
    return this.options.store.transaction(async (tx) => {
      await this.assertTenantActive(tx, tenantId);
      await this.methodAllowed(tx, tenantId, `passwordless-${input.channel}`);
      const identity = (
        await tx.find<Identity>('identities', {
          tenantId,
          kind: 'user',
          status: 'active',
          ...(input.channel === 'email'
            ? { email: destination }
            : { phone: destination, phoneVerified: true }),
        })
      )[0];
      if (identity) {
        const token =
          input.kind === 'code' ? randomInt(0, 1_000_000).toString().padStart(6, '0') : newToken();
        await this.challenge(
          tx,
          identity,
          'passwordless',
          { destination, channel: input.channel },
          5 * 60_000,
          token,
        );
        await this.enqueue(tx, identity, input.channel, destination, input.kind, { token });
      }
      return { success: true };
    });
  }

  async finishPasswordless(input: {
    tenantId: string;
    destination: string;
    token: string;
    deviceToken?: string;
  }): Promise<SignInResult> {
    const tenantId = text(input.tenantId, 'tenantId');
    const deviceToken =
      input.deviceToken === undefined ? undefined : text(input.deviceToken, 'deviceToken', 512);
    const destination = input.destination?.startsWith('+')
      ? phone(input.destination)
      : email(input.destination);
    await this.rate(tenantId, `passwordless-finish:${destination}`, 'sensitive');
    return this.options.store.transaction(async (tx) => {
      const channel = destination.startsWith('+') ? 'sms' : 'email';
      await this.methodAllowed(tx, tenantId, `passwordless-${channel}`);
      const challenge = await this.readChallenge(tx, tenantId, input.token, 'passwordless', {
        destination,
      });
      if (
        !(challenge.payload.channel === 'email'
          ? this.options.passwordlessEmail
          : this.options.passwordlessSms)
      )
        throw new IamError('FEATURE_DISABLED', 'Passwordless method is disabled');
      if (challenge.payload.destination !== destination)
        throw new IamError('INVALID_CHALLENGE', 'Invalid verification code', 401);
      const identity = await this.user(tx, challenge.identityId, tenantId);
      if (challenge.payload.channel === 'email') {
        if (identity.email !== destination)
          throw new IamError('INVALID_CHALLENGE', 'Email has changed', 401);
        identity.emailVerified = true;
        await tx.put('identities', identity);
      } else if (identity.phone !== destination || !identity.phoneVerified)
        throw new IamError('INVALID_CHALLENGE', 'Phone has changed', 401);
      await tx.delete('authChallenges', challenge.id);
      return this.completeAuthentication(
        tx,
        identity,
        challenge.payload.channel === 'email' ? 'passwordless-email' : 'passwordless-sms',
        deviceToken,
      );
    });
  }
}
