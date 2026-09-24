import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, IamPlugin } from '@better-iam/core';
import { betterIam } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const DAY = 86_400_000;
const luhn = (digits: string) => {
  let sum = 0;
  for (let index = 0; index < digits.length; index++) {
    let digit = Number(digits[digits.length - 1 - index]);
    if (index % 2 === 1) digit = digit * 2 > 9 ? digit * 2 - 9 : digit * 2;
    sum += digit;
  }
  return sum % 10 === 0;
};

async function memberWith(
  f: OrganizationFixture,
  name: string,
  statements: Array<Record<string, unknown>>,
) {
  const person = await f.member(name);
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `${name} data`,
    document: { version: 1, statements } as never,
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: person.id,
  });
  return { id: person.id, credential: { token: (await f.signIn(name)).token } };
}

describe('data protection (tokenization)', () => {
  it('tokenizes card numbers into format-preserving tokens and back', async () => {
    const f = await organizationFixture();
    const protection = f.iam.api.protection;
    const profile = await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'cards',
      dataType: 'card',
      deterministic: true,
    });
    expect(profile).toMatchObject({
      format: 'format-preserving',
      mask: 'last4',
      deterministic: true,
    });
    const cards = ['4242 4242 4242 4242', '5555-5555-5555-4444', '4242424242424242'];
    const { tokens } = await protection.tokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'cards',
      values: cards,
    });
    expect(tokens).toHaveLength(3);
    // Deterministic: the same card (however it is spelled) gets the same token.
    expect(tokens[0]).toBe(tokens[2]);
    for (const [index, token] of tokens.entries()) {
      expect(token).toMatch(/^\d{16}$/);
      expect(token.slice(-4)).toBe(cards[index]!.replace(/\D/g, '').slice(-4));
      // A token is never mistaken for a card number.
      expect(luhn(token)).toBe(false);
    }
    const again = await protection.tokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'cards',
      values: ['4242424242424242'],
    });
    expect(again).toEqual({ tokens: [tokens[0]] });

    const { values } = await protection.detokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'cards',
      tokens: [...tokens, '0000000000004242'],
      purpose: 'payment-processing',
    });
    expect(values).toEqual(['4242424242424242', '5555555555554444', '4242424242424242', null]);
    const masked = await protection.mask(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'cards',
      tokens: [tokens[1]!],
    });
    expect(masked.values).toEqual(['************4444']);
    expect(
      (
        await protection.mask(f.ownerCredential, {
          tenantId: f.tenantId,
          profile: 'cards',
          tokens: [tokens[1]!],
          style: 'first6last4',
        })
      ).values,
    ).toEqual(['555555******4444']);

    // Invalid cards are refused, not tokenized.
    await expect(
      protection.tokenize(f.ownerCredential, {
        tenantId: f.tenantId,
        profile: 'cards',
        values: ['4242424242424241'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // Neither values nor tokens reach the audit trail or the store in the clear.
    const events = await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId });
    const text = JSON.stringify(events);
    expect(text).not.toContain('4242424242424242');
    expect(text).not.toContain(tokens[1]!);
    expect(
      events.find((event) => event.action === 'iam:protection:detokenize')?.metadata,
      // Four tokens asked for; two distinct stored tokens (the deterministic profile reused one).
    ).toMatchObject({ purpose: 'payment-processing', count: 4, found: 2 });
    const stored = JSON.stringify(
      await f.database.find('protectionTokens', { tenantId: f.tenantId }),
    );
    expect(stored).not.toContain('4242424242424242');
    expect(stored).not.toContain('5555555555554444');
  });

  it('keeps each data type recognizable and masks it for display', async () => {
    const f = await organizationFixture();
    const protection = f.iam.api.protection;
    const cases = [
      {
        name: 'ssns',
        dataType: 'ssn',
        value: '123-45-6789',
        shape: /^9\d\d-\d\d-6789$/,
        masked: '***-**-6789',
      },
      {
        name: 'emails',
        dataType: 'email',
        value: 'Jane.Doe@Example.com',
        shape: /^[a-z0-9]{16}@example\.com$/,
        masked: 'j***@example.com',
      },
      {
        name: 'phones',
        dataType: 'phone',
        value: '+1 (415) 555-0199',
        shape: /^\+\d{7}0199$/,
        masked: '+*******0199',
      },
      {
        name: 'notes',
        dataType: 'generic',
        value: 'patient allergic to penicillin',
        shape: /^tok_[0-9A-Za-z]{22}$/,
        masked: '******* ******** ** **********',
      },
    ] as const;
    for (const item of cases) {
      await protection.createProfile(f.ownerCredential, {
        tenantId: f.tenantId,
        name: item.name,
        dataType: item.dataType,
      });
      const [token] = (
        await protection.tokenize(f.ownerCredential, {
          tenantId: f.tenantId,
          profile: item.name,
          values: [item.value],
        })
      ).tokens;
      expect(token).toMatch(item.shape);
      expect(
        (
          await protection.mask(f.ownerCredential, {
            tenantId: f.tenantId,
            profile: item.name,
            tokens: [token!],
          })
        ).values,
      ).toEqual([item.masked]);
    }
    // Non-deterministic profiles issue a new token each time; format-preserving SSNs are always deterministic.
    const first = await protection.tokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'emails',
      values: ['jane.doe@example.com', 'JANE.DOE@example.com'],
    });
    expect(first.tokens[0]).not.toBe(first.tokens[1]);
    const ssns = await protection.tokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'ssns',
      values: ['123-45-6789', '123456789'],
    });
    expect(ssns.tokens[0]).toBe(ssns.tokens[1]);
    // Format-preserving generic tokens keep each character's class.
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'accounts',
      dataType: 'generic',
      format: 'format-preserving',
    });
    const [account] = (
      await protection.tokenize(f.ownerCredential, {
        tenantId: f.tenantId,
        profile: 'accounts',
        values: ['DE89-3704-0044-0532-0130-00'],
      })
    ).tokens;
    expect(account).toMatch(/^[A-Z]{2}\d{2}-\d{4}-\d{4}-\d{4}-\d{4}-\d{2}$/);
    await expect(
      protection.tokenize(f.ownerCredential, {
        tenantId: f.tenantId,
        profile: 'accounts',
        values: ['AB-12'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('decides detokenizing by profile and purpose, apart from tokenizing and masking', async () => {
    const f = await organizationFixture();
    const protection = f.iam.api.protection;
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'cards',
      dataType: 'card',
    });
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ssns',
      dataType: 'ssn',
    });
    const [card] = (
      await protection.tokenize(f.ownerCredential, {
        tenantId: f.tenantId,
        profile: 'cards',
        values: ['4242424242424242'],
      })
    ).tokens;
    // Checkout may tokenize cards and detokenize them for payments only; support may only see masks.
    const checkout = await memberWith(f, 'checkout', [
      {
        effect: 'allow',
        actions: ['iam:protection:tokenize'],
        resources: ['iam/protection/cards'],
      },
      {
        effect: 'allow',
        actions: ['iam:protection:detokenize'],
        resources: ['iam/protection/cards'],
        conditions: { StringEquals: { 'resource.purpose': 'payment-processing' } },
      },
    ]);
    const support = await memberWith(f, 'support', [
      { effect: 'allow', actions: ['iam:protection:mask'], resources: ['iam/protection/*'] },
    ]);
    const detokenize = (credential: { token: string }, purpose: string) =>
      protection.detokenize(credential, {
        tenantId: f.tenantId,
        profile: 'cards',
        tokens: [card!],
        purpose,
      });
    await expect(detokenize(checkout.credential, 'payment-processing')).resolves.toEqual({
      values: ['4242424242424242'],
    });
    await expect(detokenize(checkout.credential, 'marketing')).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(
      protection.tokenize(checkout.credential, {
        tenantId: f.tenantId,
        profile: 'ssns',
        values: ['123-45-6789'],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(detokenize(support.credential, 'payment-processing')).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(
      protection.mask(support.credential, {
        tenantId: f.tenantId,
        profile: 'cards',
        tokens: [card!],
      }),
    ).resolves.toEqual({ values: ['************4242'] });
    await expect(detokenize(checkout.credential, 'Not A Purpose')).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    // Denials are audited with the purpose asked for.
    const denied = (await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId })).filter(
      (event) => event.action === 'iam:protection:detokenize' && event.outcome === 'deny',
    );
    expect(denied.length).toBeGreaterThanOrEqual(2);
  });

  it('erases by token or by value, sweeps by retention, and follows its KMS key', async () => {
    const f = await organizationFixture();
    const protection = f.iam.api.protection;
    const profile = await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'emails',
      dataType: 'email',
      retentionDays: 30,
    });
    const { tokens } = await protection.tokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'emails',
      values: ['ann@acme.test', 'ann@acme.test', 'bob@acme.test'],
    });
    // Erasure by value finds every token issued for it, deterministic profile or not.
    expect(
      await protection.deleteTokens(f.ownerCredential, {
        tenantId: f.tenantId,
        profile: 'emails',
        values: ['ANN@acme.test'],
      }),
    ).toEqual({ deleted: 2 });
    const after = await protection.detokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'emails',
      tokens,
      purpose: 'support',
    });
    expect(after.values).toEqual([null, null, 'bob@acme.test']);

    // Disabling the profile's KMS key makes every value unreadable (crypto-shredding while disabled).
    await f.iam.api.keys.disable(f.ownerCredential, { tenantId: f.tenantId, keyId: profile.keyId });
    await expect(
      protection.detokenize(f.ownerCredential, {
        tenantId: f.tenantId,
        profile: 'emails',
        tokens: [tokens[2]!],
        purpose: 'support',
      }),
    ).rejects.toMatchObject({ code: 'KEY_STATE_INVALID' });
    await f.iam.api.keys.enable(f.ownerCredential, { tenantId: f.tenantId, keyId: profile.keyId });

    // Retention: the daily sweep deletes tokens past 30 days.
    f.advance(31 * DAY);
    expect(await f.iam.protection.sweep()).toEqual({ deleted: 1, profiles: 1 });
    const owner = await f.ownerSignIn();
    expect(
      await protection.getProfile(owner, { tenantId: f.tenantId, profile: 'emails' }),
    ).toMatchObject({
      tokens: 0,
    });
    await expect(
      protection.deleteProfile(owner, { tenantId: f.tenantId, profile: 'emails' }),
    ).resolves.toEqual({ success: true });
  });

  it('keeps values away from plugins and survives a deployment secret rotation', async () => {
    const seen: unknown[] = [];
    const spy: IamPlugin = {
      id: 'spy',
      hooks: { afterOperation: async ({ result }) => void seen.push(result) },
    };
    const f = await organizationFixture({ plugins: [spy] });
    const protection = f.iam.api.protection;
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ssns',
      dataType: 'ssn',
      deterministic: true,
    });
    const { tokens } = await protection.tokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'ssns',
      values: ['123-45-6789'],
    });
    await protection.detokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'ssns',
      tokens,
      purpose: 'tax-filing',
    });
    expect(JSON.stringify(seen)).not.toContain('123-45-6789');

    // A new deployment secret re-seals the KMS key material that wraps the profile's lookup key: deterministic
    // tokens stay the same.
    const rotated = betterIam({
      database: f.database,
      secret: 'a brand new deployment secret with 32+ chars',
      previousSecrets: ['organization-fixture-secret-with-32-characters'],
      baseURL: 'http://localhost:3000',
      resolveResource: async (reference) => reference,
      authentication: {
        sendEmail: async () => {},
        sessionLifetimeMs: 7 * 86400000,
        sessionIdleTimeoutMs: 7 * 86400000,
        now: f.now,
      },
    });
    const result = await rotated.rotateSecrets();
    expect(result.resealed.kmsKeyVersions).toBeGreaterThanOrEqual(1);
    expect(
      (
        await rotated.api.protection.tokenize(f.ownerCredential, {
          tenantId: f.tenantId,
          profile: 'ssns',
          values: ['123456789'],
        })
      ).tokens,
    ).toEqual(tokens);
  });
});
