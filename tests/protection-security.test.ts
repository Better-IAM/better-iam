import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, IamPlugin } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const DAY = 86_400_000;

/** A card number with a valid Luhn check digit. */
function card(prefix: string): string {
  for (let check = 0; check < 10; check++) {
    const digits = prefix + check;
    let sum = 0;
    for (let index = 0; index < digits.length; index++) {
      let digit = Number(digits[digits.length - 1 - index]);
      if (index % 2 === 1) digit = digit * 2 > 9 ? digit * 2 - 9 : digit * 2;
      sum += digit;
    }
    if (sum % 10 === 0) return digits;
  }
  throw new Error('unreachable');
}

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

const audit = async (f: OrganizationFixture, action: string) =>
  (await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId })).filter(
    (event) => event.action === action,
  );

describe('data protection security regressions', () => {
  it('never lets a mask reveal most of a value, and decides the style actually used', async () => {
    const f = await organizationFixture();
    const protection = f.iam.api.protection;
    const tokenize = async (profile: string, values: string[]) =>
      (await protection.tokenize(f.ownerCredential, { tenantId: f.tenantId, profile, values }))
        .tokens;
    const mask = async (profile: string, tokens: string[], style?: 'last4' | 'first6last4') =>
      (
        await protection.mask(f.ownerCredential, {
          tenantId: f.tenantId,
          profile,
          tokens,
          ...(style ? { style } : {}),
        })
      ).values;
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ssns',
      dataType: 'ssn',
    });
    // A card style on a social security number would show all nine digits.
    await expect(
      mask('ssns', await tokenize('ssns', ['123-45-6789']), 'first6last4'),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      protection.createProfile(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'ssn-wide',
        dataType: 'ssn',
        mask: 'first6last4',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Short values keep at least half hidden.
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'phones',
      dataType: 'phone',
    });
    expect(await mask('phones', await tokenize('phones', ['555-0199']))).toEqual(['****199']);
    // Six and four digits of a card only when at least five stay hidden (15 digits or more).
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'cards',
      dataType: 'card',
      mask: 'first6last4',
    });
    const short = card('42424242424');
    const long = card('424242424242424');
    const [shortToken, longToken] = await tokenize('cards', [short, long]);
    expect(await mask('cards', [shortToken!, longToken!])).toEqual([
      `********${short.slice(-4)}`,
      `424242******${long.slice(-4)}`,
    ]);

    // Policies see the style used, the profile's default included.
    const support = await memberWith(f, 'support', [
      {
        effect: 'allow',
        actions: ['iam:protection:mask'],
        resources: ['iam/protection/*'],
        conditions: { StringEquals: { 'resource.style': 'last4' } },
      },
    ]);
    await expect(
      protection.mask(support.credential, {
        tenantId: f.tenantId,
        profile: 'cards',
        tokens: [longToken!],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      protection.mask(support.credential, {
        tenantId: f.tenantId,
        profile: 'cards',
        tokens: [longToken!],
        style: 'last4',
      }),
    ).resolves.toEqual({ values: [`************${long.slice(-4)}`] });
  });

  it('hides and replaces letters and digits of every script', async () => {
    const f = await organizationFixture();
    const protection = f.iam.api.protection;
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'names',
      dataType: 'generic',
    });
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'accounts',
      dataType: 'generic',
      format: 'format-preserving',
    });
    const names = 'Иван Петров, José García, 山田太郎';
    const { tokens } = await protection.tokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'names',
      values: [names],
    });
    const [masked] = (
      await protection.mask(f.ownerCredential, { tenantId: f.tenantId, profile: 'names', tokens })
    ).values;
    expect(masked).not.toMatch(/[\p{L}\p{N}]/u);
    expect([...masked!]).toHaveLength([...names].length);

    const values = ['Иван Петров ACCT-1234-5678', '١٢٣٤٥٦٧٨٩٠١٢'];
    const preserved = (
      await protection.tokenize(f.ownerCredential, {
        tenantId: f.tenantId,
        profile: 'accounts',
        values,
      })
    ).tokens;
    expect(preserved[0]).toMatch(/^[A-Z][a-z]{3} [A-Z][a-z]{5} [A-Z]{4}-\d{4}-\d{4}$/);
    expect(preserved[1]).toMatch(/^\d{12}$/);
    // Long format-preserving values fit: tokens are unique by hash.
    const long = 'Ab1-'.repeat(200);
    const [longToken] = (
      await protection.tokenize(f.ownerCredential, {
        tenantId: f.tenantId,
        profile: 'accounts',
        values: [long],
      })
    ).tokens;
    expect(
      (
        await protection.detokenize(f.ownerCredential, {
          tenantId: f.tenantId,
          profile: 'accounts',
          tokens: [longToken!],
          purpose: 'reconciliation',
        })
      ).values,
    ).toEqual([long]);
  });

  it('normalizes text so equal values share a token, and refuses what cannot be shown faithfully', async () => {
    const f = await organizationFixture();
    const protection = f.iam.api.protection;
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'notes',
      dataType: 'generic',
      deterministic: true,
    });
    const tokenize = (values: string[]) =>
      protection.tokenize(f.ownerCredential, { tenantId: f.tenantId, profile: 'notes', values });
    // Composed and decomposed spellings of the same text are one value, and erasure finds both.
    const { tokens } = await tokenize(['jos\u00e9 garcia', 'jose\u0301 garcia']);
    expect(tokens[0]).toBe(tokens[1]);
    expect(
      await protection.deleteTokens(f.ownerCredential, {
        tenantId: f.tenantId,
        profile: 'notes',
        values: ['jose\u0301 garcia'],
      }),
    ).toEqual({ deleted: 1 });
    for (const value of ['key-\ud800', 'key-\udc00x', 'abc\u007fdef', 'pay\u0085', '\u202eevil'])
      await expect(tokenize([value])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'emails',
      dataType: 'email',
    });
    await expect(
      protection.tokenize(f.ownerCredential, {
        tenantId: f.tenantId,
        profile: 'emails',
        values: ['a\u0001b@acme.test'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('keeps short format-preserving tokens from running out or matching real numbers', async () => {
    const f = await organizationFixture();
    const protection = f.iam.api.protection;
    await expect(
      protection.createProfile(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'ssns',
        dataType: 'ssn',
        deterministic: false,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(
      await protection.createProfile(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'ssns',
        dataType: 'ssn',
      }),
    ).toMatchObject({ deterministic: true, tokens: 0 });
    const values = Array.from(
      { length: 100 },
      (_, index) => `123-45-${String(index).padStart(4, '0')}`,
    );
    const { tokens } = await protection.tokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'ssns',
      values,
    });
    // Area 9XX with a group no ITIN uses: never a valid SSN or ITIN.
    for (const token of tokens) {
      const group = Number(token.slice(4, 6));
      expect(token).toMatch(/^9\d\d-\d\d-\d{4}$/);
      expect(
        (group >= 50 && group <= 65) ||
          (group >= 70 && group <= 88) ||
          group === 90 ||
          group === 91 ||
          group === 92 ||
          group >= 94 ||
          group === 0,
      ).toBe(false);
    }
    expect(
      await protection.getProfile(f.ownerCredential, { tenantId: f.tenantId, profile: 'ssns' }),
    ).toMatchObject({ tokens: 100 });
    // Whether a value was stored before is not the caller's business.
    const again = await protection.tokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'ssns',
      values: [values[0]!],
    });
    expect(again).toEqual({ tokens: [tokens[0]] });
    expect(
      (await audit(f, 'iam:protection:tokenize')).find((event) => event.metadata?.count === 1)
        ?.metadata,
    ).toMatchObject({ created: 0 });
  });

  it('leaves the owner of a customer key in charge, and stops lookups with the key', async () => {
    const f = await organizationFixture();
    const protection = f.iam.api.protection;
    const key = await f.iam.api.keys.create(f.ownerCredential, { tenantId: f.tenantId });
    await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'cards',
      dataType: 'card',
      deterministic: true,
      keyId: key.id,
    });
    const value = card('424242424242424');
    const { tokens } = await protection.tokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'cards',
      values: [value],
    });
    const detokenizer = [
      { effect: 'allow', actions: ['iam:protection:detokenize'], resources: ['iam/protection/*'] },
    ];
    const withoutKey = await memberWith(f, 'nokey', detokenizer);
    const withKey = await memberWith(f, 'withkey', [
      ...detokenizer,
      { effect: 'allow', actions: ['iam:kms:decrypt'], resources: [`iam/kms/${key.id}`] },
    ]);
    const detokenize = (credential: { token: string }) =>
      protection.detokenize(credential, {
        tenantId: f.tenantId,
        profile: 'cards',
        tokens,
        purpose: 'payment-processing',
      });
    await expect(detokenize(withoutKey.credential)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(detokenize(withKey.credential)).resolves.toEqual({ values: [value] });
    // The refusal is audited as one.
    expect(
      (await audit(f, 'iam:protection:detokenize')).some(
        (event) => event.outcome === 'deny' && event.metadata?.reason === 'refused',
      ),
    ).toBe(true);

    // Disabling the key stops deterministic lookups too, not just new tokens.
    await f.iam.api.keys.disable(f.ownerCredential, { tenantId: f.tenantId, keyId: key.id });
    await expect(
      protection.tokenize(f.ownerCredential, {
        tenantId: f.tenantId,
        profile: 'cards',
        values: [value],
      }),
    ).rejects.toMatchObject({ code: 'KEY_STATE_INVALID' });
    // No lookup secret lives outside KMS.
    const [profile] = await f.database.find('protectionProfiles', { tenantId: f.tenantId });
    expect(profile).not.toHaveProperty('fingerprintKeySealed');
    expect(String(profile!.lookupKeyWrapped)).toMatch(new RegExp(`^kms1\\.${key.id}\\.1\\.`));
  });

  it('audits refusals with the purpose, guards retention, and tidies up after itself', async () => {
    const seen: unknown[] = [];
    const spy: IamPlugin = {
      id: 'spy',
      hooks: {
        afterOperation: async ({ action, result }) => {
          if (action.startsWith('iam:protection:')) seen.push(result);
        },
      },
    };
    const f = await organizationFixture({ plugins: [spy] });
    const protection = f.iam.api.protection;
    const profile = await protection.createProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'emails',
      dataType: 'email',
    });
    const { tokens } = await protection.tokenize(f.ownerCredential, {
      tenantId: f.tenantId,
      profile: 'emails',
      values: ['ann@acme.test', 'bob@acme.test'],
    });
    // Plugins never see tokens (format-preserving ones keep the domain).
    expect(JSON.stringify(seen)).not.toContain('@acme.test');

    const clerk = await memberWith(f, 'clerk', [
      { effect: 'allow', actions: ['iam:protection:manage'], resources: ['iam/protection/*'] },
    ]);
    await expect(
      protection.detokenize(clerk.credential, {
        tenantId: f.tenantId,
        profile: 'emails',
        tokens,
        purpose: 'marketing',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (await audit(f, 'iam:protection:detokenize')).find((event) => event.outcome === 'deny')
        ?.metadata,
    ).toMatchObject({ profile: 'emails', purpose: 'marketing' });
    // Managing a profile is not deleting its tokens: a retention of one day would.
    await expect(
      protection.updateProfile(clerk.credential, {
        tenantId: f.tenantId,
        profile: 'emails',
        retentionDays: 1,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      protection.updateProfile(clerk.credential, {
        tenantId: f.tenantId,
        profile: 'emails',
        description: 'Customer email addresses',
      }),
    ).resolves.toMatchObject({ description: 'Customer email addresses' });
    const owner = await f.ownerSignIn();
    await protection.updateProfile(owner, {
      tenantId: f.tenantId,
      profile: 'emails',
      retentionDays: 1,
    });
    f.advance(2 * DAY);
    expect(await f.iam.protection.sweep()).toEqual({ deleted: 2, profiles: 1 });
    expect((await audit(f, 'protection:retention-sweep'))[0]).toMatchObject({
      actorId: 'deployment-operator',
      resourceId: 'protection/emails',
      metadata: { deleted: 2, retentionDays: 1 },
    });

    // A value altered in storage fails as such, not as a crash.
    const fresh = await protection.tokenize(owner, {
      tenantId: f.tenantId,
      profile: 'emails',
      values: ['cy@acme.test'],
    });
    const [stored] = await f.database.find('protectionTokens', { tenantId: f.tenantId });
    const sealed = String(stored!.sealed);
    await f.database.transaction((tx) =>
      tx.put('protectionTokens', {
        ...stored!,
        sealed: sealed.slice(0, 20) + (sealed[20] === 'A' ? 'B' : 'A') + sealed.slice(21),
      }),
    );
    await expect(
      protection.detokenize(owner, {
        tenantId: f.tenantId,
        profile: 'emails',
        tokens: fresh.tokens,
        purpose: 'support',
      }),
    ).rejects.toMatchObject({ code: 'KEY_MATERIAL_UNAVAILABLE' });
    await protection.deleteTokens(owner, {
      tenantId: f.tenantId,
      profile: 'emails',
      tokens: fresh.tokens,
    });

    // Deleting the profile retires the key it created (after a fresh sign-in: two days went by).
    await protection.deleteProfile(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      profile: 'emails',
    });
    expect(
      await f.iam.api.keys.get(owner, { tenantId: f.tenantId, keyId: profile.keyId }),
    ).toMatchObject({ state: 'pending-deletion' });
  });
});
