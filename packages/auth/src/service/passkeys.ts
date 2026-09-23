import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { IamError, type AuthMethod, type CredentialInput, type Identity } from '@better-iam/core';
import { hashToken, newId, newToken } from '../crypto.js';
import type {
  Challenge,
  MfaSessionResult,
  PasskeyRecord,
  SafePasskey,
  SessionResult,
} from '../types.js';
import { email, text } from '../validation.js';
import { MfaAuth } from './mfa.js';

const PASSKEY_NAME_LIMIT = 64;

/** A readable default label from what the authenticator reported about itself. */
function defaultPasskeyName(transports: string[] | undefined): string {
  const set = new Set(transports ?? []);
  if (set.has('internal')) return 'This device';
  if (set.has('hybrid')) return 'Phone';
  if (set.has('usb') || set.has('nfc') || set.has('ble')) return 'Security key';
  return 'Passkey';
}

function passkeyName(value: unknown, fallback: string): string {
  if (value === undefined) return fallback;
  const name = text(value, 'name', PASSKEY_NAME_LIMIT).trim();
  if (!name) throw new IamError('INVALID_INPUT', 'name must not be empty');
  return name;
}

function publicPasskey(record: PasskeyRecord): SafePasskey {
  const { publicKey: _key, counter: _counter, uniqueKey: _unique, ...safe } = record;
  return { ...safe, name: record.name ?? defaultPasskeyName(record.transports) };
}

/** WebAuthn passkeys: registration from a recently authenticated session and passwordless sign-in that satisfies MFA. */
export class PasskeyAuth extends MfaAuth {
  protected passkeys(): { rpID: string; rpName: string } {
    if (!this.options.passkeys)
      throw new IamError('FEATURE_DISABLED', 'Passkeys are not configured');
    // A passkey belongs to one domain (the RP ID). On an organization's custom hostname outside it, such as
    // login.acme.com for passkeys of example.com, the browser would refuse the ceremony, so say why up front.
    const origin = this.requestHost()?.origin;
    if (origin) {
      const hostname = new URL(origin).hostname;
      const rpID = this.options.passkeys.rpID;
      if (hostname !== rpID && !hostname.endsWith(`.${rpID}`))
        throw new IamError('FEATURE_DISABLED', 'Passkeys are not available at this address');
    }
    return {
      rpID: this.options.passkeys.rpID,
      rpName: this.options.passkeys.rpName ?? this.appName,
    };
  }

  async beginPasskeyRegistration(credentials: CredentialInput): Promise<{
    challengeId: string;
    options: Awaited<ReturnType<typeof generateRegistrationOptions>>;
  }> {
    const config = this.passkeys();
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      const existing = await tx.find<PasskeyRecord>('authPasskeys', {
        tenantId: principal.identity.tenantId,
        identityId: principal.identity.id,
      });
      const options = await generateRegistrationOptions({
        ...config,
        userName: principal.identity.email ?? principal.identity.id,
        userID: new TextEncoder().encode(principal.identity.id),
        userDisplayName: principal.identity.name,
        attestationType: 'none',
        excludeCredentials: existing.map((item) => ({
          id: item.credentialId,
          transports: item.transports,
        })),
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      });
      const challengeId = await this.challenge(
        tx,
        principal.identity,
        'passkey-register',
        { challenge: options.challenge },
        5 * 60_000,
        undefined,
        principal.session.id,
      );
      return { challengeId, options };
    });
  }

  /** `name` labels the passkey for the person's own list (at most 64 characters); the default names the device kind. */
  async finishPasskeyRegistration(
    credentials: CredentialInput,
    input: { challengeId: string; response: RegistrationResponseJSON; name?: string },
  ): Promise<{ id: string; name: string }> {
    const config = this.passkeys();
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      const challenge = await this.readChallenge(
        tx,
        principal.identity.tenantId,
        input.challengeId,
        'passkey-register',
      );
      if (
        challenge.identityId !== principal.identity.id ||
        challenge.sessionId !== principal.session.id
      )
        throw new IamError('INVALID_CHALLENGE', 'Invalid passkey challenge', 401);
      const result = await verifyRegistrationResponse({
        response: input.response,
        expectedChallenge: challenge.payload.challenge!,
        expectedOrigin: this.expectedOrigins(),
        expectedRPID: config.rpID,
        requireUserVerification: true,
      }).catch(() => {
        throw new IamError('INVALID_PASSKEY', 'Passkey registration verification failed', 401);
      });
      if (!result.verified || !result.registrationInfo)
        throw new IamError('INVALID_PASSKEY', 'Passkey verification failed', 401);
      const { credential, credentialDeviceType, credentialBackedUp, aaguid } =
        result.registrationInfo;
      const id = newId('pk');
      // A credential is globally unique for this RP, including across tenant accounts.
      if ((await tx.find<PasskeyRecord>('authPasskeys', { credentialId: credential.id })).length)
        throw new IamError('PASSKEY_EXISTS', 'Passkey is already registered', 409);
      const name = passkeyName(input.name, defaultPasskeyName(credential.transports));
      const record: PasskeyRecord = {
        id,
        tenantId: principal.identity.tenantId,
        uniqueKey: credential.id,
        identityId: principal.identity.id,
        credentialId: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter,
        transports: credential.transports,
        name,
        createdAt: this.now(),
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
      };
      if (aaguid && aaguid !== '00000000-0000-0000-0000-000000000000') record.aaguid = aaguid;
      await tx.insert<PasskeyRecord>('authPasskeys', record);
      await tx.delete('authChallenges', challenge.id);
      await this.audit(tx, principal.identity, 'auth:passkey:create', undefined, { name });
      return { id, name };
    });
  }

  /**
   * Starts a passkey sign-in. With `email`, the options name that person's credentials. Without it, the
   * authenticator offers whatever discoverable credential it holds for this relying party (the browser's passkey
   * picker or autofill) and `finishPasskeyAuthentication` finds the account from the credential itself.
   */
  async beginPasskeyAuthentication(input: { tenantId: string; email?: string }): Promise<{
    challengeId: string;
    options: Awaited<ReturnType<typeof generateAuthenticationOptions>>;
  }> {
    const config = this.passkeys();
    const tenantId = text(input.tenantId, 'tenantId');
    if (input.email === undefined) {
      // Discovery names nobody, so the counter is per address; login pages start one per visit for autofill.
      await this.rate(
        tenantId,
        `passkey-discover:${this.clientScope.getStore()?.ip ?? 'unknown'}`,
        'generous',
      );
      return this.options.store.transaction(async (tx) => {
        await this.assertTenantActive(tx, tenantId);
        await this.methodAllowed(tx, tenantId, 'passkey');
        const options = await generateAuthenticationOptions({
          rpID: config.rpID,
          userVerification: 'required',
        });
        const token = newToken();
        await tx.insert<Challenge>('authChallenges', {
          id: newId('ch'),
          tenantId,
          identityId: '',
          purpose: 'passkey-authenticate',
          tokenHash: this.digestChallenge(tenantId, token),
          payload: { challenge: options.challenge, discovery: '1' },
          expiresAt: this.now() + 5 * 60_000,
        });
        return { challengeId: token, options };
      });
    }
    const normalized = email(input.email);
    await this.rate(tenantId, `passkey:${normalized}`);
    return this.options.store.transaction(async (tx) => {
      await this.assertTenantActive(tx, tenantId);
      await this.methodAllowed(tx, tenantId, 'passkey');
      const identity = (
        await tx.find<Identity>('identities', {
          tenantId,
          email: normalized,
          status: 'active',
          kind: 'user',
        })
      )[0];
      if (!identity)
        throw new IamError(
          'INVALID_CREDENTIALS',
          'Authentication is unavailable for this account',
          401,
        );
      const keys = await tx.find<PasskeyRecord>('authPasskeys', {
        tenantId,
        identityId: identity.id,
      });
      const options = await generateAuthenticationOptions({
        rpID: config.rpID,
        userVerification: 'required',
        allowCredentials: keys.map((key) => ({ id: key.credentialId, transports: key.transports })),
      });
      const challengeId = await this.challenge(
        tx,
        identity,
        'passkey-authenticate',
        { challenge: options.challenge },
        5 * 60_000,
      );
      return { challengeId, options };
    });
  }

  async finishPasskeyAuthentication(input: {
    tenantId: string;
    challengeId: string;
    response: AuthenticationResponseJSON;
  }): Promise<SessionResult> {
    const config = this.passkeys();
    if (
      !input.response ||
      typeof input.response !== 'object' ||
      typeof input.response.id !== 'string' ||
      !input.response.response
    )
      throw new IamError('INVALID_INPUT', 'A passkey authentication response is required');
    await this.rate(
      text(input.tenantId, 'tenantId'),
      `passkey-finish:${hashToken(text(input.challengeId, 'challengeId'))}`,
      'sensitive',
    );
    return this.options.store.transaction(async (tx) => {
      await this.methodAllowed(tx, input.tenantId, 'passkey');
      const challenge = await this.readChallenge(
        tx,
        input.tenantId,
        input.challengeId,
        'passkey-authenticate',
      );
      // A discovery challenge names nobody: the presented credential identifies the account.
      const discovered =
        challenge.payload.discovery === '1'
          ? (
              await tx.find<PasskeyRecord>('authPasskeys', {
                tenantId: input.tenantId,
                credentialId: input.response.id,
              })
            )[0]
          : undefined;
      if (challenge.payload.discovery === '1' && !discovered)
        throw new IamError(
          'INVALID_PASSKEY',
          'Passkey is not registered for this organization',
          401,
        );
      const identity = await this.user(
        tx,
        discovered ? discovered.identityId : challenge.identityId,
        input.tenantId,
      );
      if (
        input.response.response.userHandle &&
        input.response.response.userHandle !== Buffer.from(identity.id).toString('base64url')
      )
        throw new IamError(
          'INVALID_PASSKEY',
          'Passkey user handle does not match this identity',
          401,
        );
      const key =
        discovered ??
        (
          await tx.find<PasskeyRecord>('authPasskeys', {
            tenantId: input.tenantId,
            identityId: identity.id,
            credentialId: input.response.id,
          })
        )[0];
      if (!key)
        throw new IamError(
          'INVALID_PASSKEY',
          'Passkey does not belong to this tenant identity',
          401,
        );
      const result = await verifyAuthenticationResponse({
        response: input.response,
        expectedChallenge: challenge.payload.challenge!,
        expectedOrigin: this.expectedOrigins(),
        expectedRPID: config.rpID,
        requireUserVerification: true,
        credential: {
          id: key.credentialId,
          publicKey: new Uint8Array(Buffer.from(key.publicKey, 'base64url')),
          counter: key.counter,
          transports: key.transports,
        },
      }).catch(() => {
        throw new IamError('INVALID_PASSKEY', 'Passkey authentication verification failed', 401);
      });
      if (!result.verified || !result.authenticationInfo.userVerified)
        throw new IamError('INVALID_PASSKEY', 'Passkey verification failed', 401);
      key.counter = result.authenticationInfo.newCounter;
      key.lastUsedAt = this.now();
      await tx.put('authPasskeys', key);
      await tx.delete('authChallenges', challenge.id);
      return this.issueSession(tx, identity, { mfa: true, method: 'passkey' });
    });
  }

  /**
   * Passkey as the second factor: after a password or passwordless sign-in returned `mfaRequired` with
   * `passkeyAvailable`, the person proves possession of a registered passkey instead of entering a code.
   */
  async beginPasskeyMfa(input: { tenantId: string; challenge: string }): Promise<{
    challengeId: string;
    options: Awaited<ReturnType<typeof generateAuthenticationOptions>>;
  }> {
    const config = this.passkeys();
    const tenantId = text(input.tenantId, 'tenantId');
    const token = text(input.challenge, 'challenge', 512);
    await this.rate(tenantId, `passkey-mfa:${hashToken(token)}`, 'sensitive');
    await this.rateChallengeIdentity(tenantId, token, 'mfa-login', 'passkey-mfa-begin');
    return this.options.store.transaction(async (tx) => {
      const login = await this.readChallenge(tx, tenantId, token, 'mfa-login');
      const identity = await this.user(tx, login.identityId, tenantId);
      const keys = await tx.find<PasskeyRecord>('authPasskeys', {
        tenantId,
        identityId: identity.id,
      });
      if (!keys.length)
        throw new IamError('FEATURE_DISABLED', 'No passkey is registered for this account', 403);
      const options = await generateAuthenticationOptions({
        rpID: config.rpID,
        userVerification: 'required',
        allowCredentials: keys.map((key) => ({ id: key.credentialId, transports: key.transports })),
      });
      const challengeId = await this.challenge(
        tx,
        identity,
        'passkey-mfa',
        { challenge: options.challenge, loginChallengeId: login.id },
        5 * 60_000,
      );
      return { challengeId, options };
    });
  }

  async finishPasskeyMfa(input: {
    tenantId: string;
    challengeId: string;
    response: AuthenticationResponseJSON;
    rememberDevice?: boolean;
  }): Promise<MfaSessionResult> {
    const config = this.passkeys();
    if (
      !input.response ||
      typeof input.response !== 'object' ||
      typeof input.response.id !== 'string' ||
      !input.response.response
    )
      throw new IamError('INVALID_INPUT', 'A passkey authentication response is required');
    const tenantId = text(input.tenantId, 'tenantId');
    const token = text(input.challengeId, 'challengeId');
    await this.rate(tenantId, `passkey-mfa-finish:${hashToken(token)}`, 'sensitive');
    await this.rateChallengeIdentity(tenantId, token, 'passkey-mfa', 'passkey-mfa-verify');
    return this.options.store.transaction(async (tx) => {
      const challenge = await this.readChallenge(
        tx,
        input.tenantId,
        input.challengeId,
        'passkey-mfa',
      );
      const identity = await this.user(tx, challenge.identityId, input.tenantId);
      // The login challenge this assertion completes must still be open and belong to the same person.
      const login = await tx.get<Challenge>('authChallenges', challenge.payload.loginChallengeId!);
      if (
        !login ||
        login.purpose !== 'mfa-login' ||
        login.identityId !== identity.id ||
        login.expiresAt <= this.now()
      )
        throw new IamError('INVALID_CHALLENGE', 'Sign-in challenge is invalid or expired', 401);
      const key = (
        await tx.find<PasskeyRecord>('authPasskeys', {
          tenantId: input.tenantId,
          identityId: identity.id,
          credentialId: input.response.id,
        })
      )[0];
      if (!key)
        throw new IamError('INVALID_PASSKEY', 'Passkey does not belong to this account', 401);
      const result = await verifyAuthenticationResponse({
        response: input.response,
        expectedChallenge: challenge.payload.challenge!,
        expectedOrigin: this.expectedOrigins(),
        expectedRPID: config.rpID,
        requireUserVerification: true,
        credential: {
          id: key.credentialId,
          publicKey: new Uint8Array(Buffer.from(key.publicKey, 'base64url')),
          counter: key.counter,
          transports: key.transports,
        },
      }).catch(() => {
        throw new IamError('INVALID_PASSKEY', 'Passkey authentication verification failed', 401);
      });
      if (!result.verified || !result.authenticationInfo.userVerified)
        throw new IamError('INVALID_PASSKEY', 'Passkey verification failed', 401);
      key.counter = result.authenticationInfo.newCounter;
      key.lastUsedAt = this.now();
      await tx.put('authPasskeys', key);
      await tx.delete('authChallenges', challenge.id);
      await tx.delete('authChallenges', login.id);
      const session = await this.issueSession(tx, identity, {
        mfa: true,
        method: login.payload.method as AuthMethod | undefined,
      });
      return {
        ...session,
        ...(input.rememberDevice === true ? await this.rememberDevice(tx, identity) : {}),
      };
    });
  }

  /** The caller's passkeys, newest first: name, when registered and last used, device kind, and transports. */
  async listPasskeys(credentials: CredentialInput): Promise<SafePasskey[]> {
    const principal = await this.authenticate(credentials);
    return (
      await this.options.store.find<PasskeyRecord>('authPasskeys', {
        tenantId: principal.identity.tenantId,
        identityId: principal.identity.id,
      })
    )
      .sort((a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0) || (a.id < b.id ? -1 : 1))
      .map(publicPasskey);
  }

  /** Relabels one of the caller's passkeys (at most 64 characters). */
  async renamePasskey(
    credentials: CredentialInput,
    input: { id: string; name: string },
  ): Promise<SafePasskey> {
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      const passkey = await tx.get<PasskeyRecord>('authPasskeys', text(input.id, 'id'));
      if (
        !passkey ||
        passkey.identityId !== principal.identity.id ||
        passkey.tenantId !== principal.identity.tenantId
      )
        throw new IamError('NOT_FOUND', 'Passkey not found', 404);
      const name = passkeyName(input.name, defaultPasskeyName(passkey.transports));
      const saved = await tx.put<PasskeyRecord>('authPasskeys', { ...passkey, name });
      await this.audit(tx, principal.identity, 'auth:passkey:rename', principal.session, { name });
      return publicPasskey(saved);
    });
  }

  async deletePasskey(
    credentials: CredentialInput,
    input: { id: string },
  ): Promise<{ success: true }> {
    return this.options.store.transaction(async (tx) => {
      const principal = await this.authenticate(credentials);
      this.requireRecent(principal);
      const passkey = await tx.get<PasskeyRecord>('authPasskeys', text(input.id, 'id'));
      if (
        !passkey ||
        passkey.identityId !== principal.identity.id ||
        passkey.tenantId !== principal.identity.tenantId
      )
        throw new IamError('NOT_FOUND', 'Passkey not found', 404);
      // Require another login method before removing the last registered passkey.
      const keys = await tx.find<PasskeyRecord>('authPasskeys', {
        tenantId: principal.identity.tenantId,
        identityId: principal.identity.id,
      });
      const alternative =
        principal.identity.passwordHash ||
        (this.options.passwordlessEmail && principal.identity.emailVerified) ||
        (this.options.passwordlessSms && principal.identity.phoneVerified);
      if (keys.length === 1 && !alternative)
        throw new IamError(
          'LAST_AUTHENTICATOR',
          'Configure another login method before removing the last passkey',
          409,
        );
      await tx.delete('authPasskeys', passkey.id);
      await this.revokeIdentity(tx, principal.identity.id);
      await this.audit(tx, principal.identity, 'auth:passkey:delete');
      return { success: true };
    });
  }
}
