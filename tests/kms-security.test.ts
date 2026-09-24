import { afterEach, describe, expect, it } from 'vitest';
import type { IamPlugin } from '@better-iam/core';
import { kmsDecryptFor, kmsEncryptFor } from '../packages/server/src/kms.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/** A member with one inline role, bound for `expiresAt` when given. */
async function memberWith(
  f: OrganizationFixture,
  name: string,
  statements: Array<Record<string, unknown>>,
  binding: { expiresAt?: number } = {},
) {
  const person = await f.member(name);
  let bindingId: string | undefined;
  if (statements.length) {
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: `${name} keys`,
      document: { version: 1, statements } as never,
    });
    bindingId = (
      await f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: role.id,
        subjectType: 'identity',
        subjectId: person.id,
        ...binding,
      })
    ).id;
  }
  return { id: person.id, bindingId, credential: { token: (await f.signIn(name)).token } };
}

const keyAdmin = [{ effect: 'allow', actions: ['iam:kms:*'], resources: ['iam/kms', 'iam/kms/*'] }];

describe('KMS security regressions', () => {
  it('stops a grant once its creator loses the access it passed on', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const key = await keys.create(f.ownerCredential, { tenantId: f.tenantId });
    const sealed = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintext: 'payroll',
    });
    // Gina's key access lasts an hour; she grants herself and Bob decrypt.
    const gina = await memberWith(f, 'gina', keyAdmin, { expiresAt: f.now() + 3_600_000 });
    const bob = await memberWith(f, 'bob', []);
    await keys.createGrant(gina.credential, {
      tenantId: f.tenantId,
      keyId: key.id,
      granteeId: gina.id,
      operations: ['decrypt'],
    });
    await keys.createGrant(gina.credential, {
      tenantId: f.tenantId,
      keyId: key.id,
      granteeId: bob.id,
      operations: ['decrypt'],
    });
    const open = (credential: { token: string }) =>
      keys.decrypt(credential, { tenantId: f.tenantId, ciphertext: sealed.ciphertext });
    await expect(open(bob.credential)).resolves.toMatchObject({ plaintext: 'payroll' });
    f.advance(2 * 3_600_000);
    // Her binding expired: neither her self-grant nor Bob's grant works any more.
    const ginaAgain = { token: (await f.signIn('gina')).token };
    await expect(open(ginaAgain)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(open(bob.credential)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // Deleting the creator's binding does the same.
    const hana = await memberWith(f, 'hana', keyAdmin);
    const ivan = await memberWith(f, 'ivan', []);
    await keys.createGrant(hana.credential, {
      tenantId: f.tenantId,
      keyId: key.id,
      granteeId: ivan.id,
      operations: ['decrypt'],
    });
    await expect(open(ivan.credential)).resolves.toMatchObject({ plaintext: 'payroll' });
    await f.iam.api.bindings.delete(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      bindingId: hana.bindingId!,
    });
    await expect(open(ivan.credential)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it("carries the creator's conditional denies into every use of a grant", async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const key = await keys.create(f.ownerCredential, { tenantId: f.tenantId });
    const secret = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintext: 'TOP SECRET',
      encryptionContext: { class: 'secret' },
    });
    const internal = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintext: 'internal',
      encryptionContext: { class: 'internal' },
    });
    const gina = await memberWith(f, 'gina', [
      ...keyAdmin,
      {
        effect: 'deny',
        actions: ['iam:kms:decrypt'],
        resources: ['iam/kms/*'],
        conditions: { StringEquals: { 'resource.encryptionContext.class': 'secret' } },
      },
    ]);
    const bob = await memberWith(f, 'bob', []);
    await keys.createGrant(gina.credential, {
      tenantId: f.tenantId,
      keyId: key.id,
      granteeId: bob.id,
      operations: ['decrypt'],
    });
    await expect(
      keys.decrypt(bob.credential, {
        tenantId: f.tenantId,
        ciphertext: internal.ciphertext,
        encryptionContext: { class: 'internal' },
      }),
    ).resolves.toMatchObject({ plaintext: 'internal' });
    await expect(
      keys.decrypt(bob.credential, {
        tenantId: f.tenantId,
        ciphertext: secret.ciphertext,
        encryptionContext: { class: 'secret' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('authorizes alias names so nobody can squat on a name others use', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    // Mallory manages sandbox keys, and aliases under alias/sandbox/ only.
    const mallory = await memberWith(f, 'mallory', [
      {
        effect: 'allow',
        actions: ['iam:kms:*'],
        resources: ['iam/kms', 'iam/kms/*'],
        conditions: { StringEquals: { 'resource.tags.team': 'sandbox' } },
      },
      { effect: 'allow', actions: ['iam:kms:create'], resources: ['iam/kms'] },
      { effect: 'allow', actions: ['iam:kms:update'], resources: ['iam/kms/alias/sandbox/*'] },
    ]);
    const own = await keys.create(mallory.credential, {
      tenantId: f.tenantId,
      tags: { team: 'sandbox' },
    });
    await expect(
      keys.createAlias(mallory.credential, {
        tenantId: f.tenantId,
        alias: 'alias/prod/payments',
        keyId: own.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      keys.create(mallory.credential, {
        tenantId: f.tenantId,
        tags: { team: 'sandbox' },
        alias: 'alias/prod/billing',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      keys.createAlias(mallory.credential, {
        tenantId: f.tenantId,
        alias: 'alias/sandbox/test',
        keyId: own.id,
      }),
    ).resolves.toMatchObject({ name: 'alias/sandbox/test' });
  });

  it('never shows plaintexts, data keys or tokens to plugins', async () => {
    const seen: unknown[] = [];
    const spy: IamPlugin = {
      id: 'spy',
      hooks: { afterOperation: async ({ result }) => void seen.push(result) },
    };
    const f = await organizationFixture({ plugins: [spy] });
    const keys = f.iam.api.keys;
    const key = await keys.create(f.ownerCredential, { tenantId: f.tenantId });
    const sealed = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintext: 'hunter2',
    });
    await keys.decrypt(f.ownerCredential, { tenantId: f.tenantId, ciphertext: sealed.ciphertext });
    const dataKey = await keys.generateDataKey(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
    });
    const signer = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      keySpec: 'ed25519',
    });
    const jwt = await keys.signJwt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: signer.id,
      claims: { sub: 'x' },
    });
    const text = JSON.stringify(seen);
    expect(text).not.toContain('hunter2');
    expect(text).not.toContain(dataKey.plaintextBase64!);
    expect(text).not.toContain(jwt.token);
    expect(seen.length).toBeGreaterThan(3);
  });

  it('answers callers from other tenants the same whether a key exists or not', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const key = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      keySpec: 'ecc-p256',
      alias: 'alias/signing',
    });
    const other = await f.iam.api.tenants.create(f.rootCredential, {
      parentId: f.root.tenant.id,
      name: 'Globex',
      type: 'organization',
      ownerEmail: 'owner@globex.test',
    });
    await f.iam.auth.dispatchOutbox();
    const invitation = f.inbox.find(
      (message) => message.tenantId === other.tenant.id && message.template === 'owner-invitation',
    )!;
    const globex = await f.iam.api.tenants.acceptInvitation({
      tenantId: other.tenant.id,
      token: invitation.payload.token!,
      name: 'Globex owner',
      password: 'a strong globex owner password',
    });
    if (!('token' in globex)) throw new Error('Unexpected MFA');
    const probe = (keyId: string, algorithm?: string) =>
      keys.sign(
        { token: globex.token },
        { tenantId: f.tenantId, keyId, message: 'x', ...(algorithm ? { algorithm } : {}) },
      );
    for (const attempt of [
      probe(key.id),
      probe('alias/signing'),
      probe('alias/missing'),
      probe(key.id, 'RS256'),
    ])
      await expect(attempt).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('lets policies limit the tokens a caller may mint, apart from raw signatures', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const signer = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      keySpec: 'ecc-p256',
    });
    const minter = await memberWith(f, 'minter', [
      {
        effect: 'allow',
        actions: ['iam:kms:sign'],
        resources: ['iam/kms/*'],
        conditions: {
          Bool: { 'resource.jwt': true },
          StringEquals: { 'resource.jwt.iss': 'https://acme.test' },
        },
      },
    ]);
    await expect(
      keys.signJwt(minter.credential, {
        tenantId: f.tenantId,
        keyId: signer.id,
        claims: { iss: 'https://acme.test', sub: 'svc' },
      }),
    ).resolves.toMatchObject({ algorithm: 'ES256' });
    await expect(
      keys.signJwt(minter.credential, {
        tenantId: f.tenantId,
        keyId: signer.id,
        claims: { iss: 'https://evil.test', sub: 'svc' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      keys.sign(minter.credential, { tenantId: f.tenantId, keyId: signer.id, message: 'x' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('refuses tokens with critical headers or malformed times, and non-canonical encodings', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const hmac = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      keySpec: 'hmac-sha256',
    });
    const sign = async (header: Record<string, unknown>, claims: Record<string, unknown>) => {
      const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
      const input = `${encode({ alg: 'HS256', kid: `${hmac.id}.1`, ...header })}.${encode(claims)}`;
      const { mac } = await keys.generateMac(f.ownerCredential, {
        tenantId: f.tenantId,
        keyId: hmac.id,
        message: input,
      });
      return `${input}.${mac}`;
    };
    const verify = async (token: string) =>
      keys.verifyJwt(f.ownerCredential, { tenantId: f.tenantId, token });
    expect(await verify(await sign({}, { sub: 'ok' }))).toMatchObject({ valid: true });
    expect(await verify(await sign({ crit: ['exp'] }, { sub: 'x' }))).toMatchObject({
      valid: false,
      reason: 'header',
    });
    expect(await verify(await sign({}, { exp: '9999999999' }))).toMatchObject({
      valid: false,
      reason: 'claims',
    });
    // A MAC spelled with non-canonical trailing bits is not accepted as the same MAC.
    const { mac } = await keys.generateMac(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: hmac.id,
      message: 'm',
    });
    const last = mac.at(-1)!;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const twin = mac.slice(0, -1) + alphabet[alphabet.indexOf(last) ^ 1];
    if (Buffer.from(twin, 'base64url').equals(Buffer.from(mac, 'base64url')))
      await expect(
        keys.verifyMac(f.ownerCredential, {
          tenantId: f.tenantId,
          keyId: hmac.id,
          message: 'm',
          mac: twin,
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('protects stored values of any size under an AES key only (service helpers)', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const aes = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      alias: 'alias/vault',
    });
    const rsa = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      keySpec: 'rsa-2048',
      keyUsage: 'encrypt',
    });
    // The helpers need only the secret, the clock and the audit writer from the server context.
    const audited: string[] = [];
    const ctx = {
      options: { secret: 'organization-fixture-secret-with-32-characters' },
      now: f.now,
      events: {
        recordAudit: async (_tx: unknown, event: { action: string }) =>
          void audited.push(event.action),
        audit: async () => undefined,
      },
    } as never;
    const large = `${'x'.repeat(200_000)} and a tail`;
    const sealed = await kmsEncryptFor(
      ctx,
      f.database,
      f.tenantId,
      'alias/vault',
      large,
      'secret-1',
      {
        via: 'vault',
      },
    );
    expect(sealed.keyId).toBe(aes.id);
    expect(sealed.ciphertext).not.toContain('tail');
    expect(
      await kmsDecryptFor(ctx, f.database, f.tenantId, sealed, 'secret-1', { via: 'vault' }),
    ).toBe(large);
    await expect(
      kmsDecryptFor(ctx, f.database, f.tenantId, sealed, 'secret-2', { via: 'vault' }),
    ).rejects.toMatchObject({ code: 'INVALID_CIPHERTEXT' });
    // The payload cannot be moved under another wrapped data key.
    const other = await kmsEncryptFor(ctx, f.database, f.tenantId, aes.id, 'other', 'secret-1');
    const [wrapped] = other.ciphertext.split('~');
    const [, payload] = sealed.ciphertext.split('~');
    await expect(
      kmsDecryptFor(
        ctx,
        f.database,
        f.tenantId,
        { ciphertext: `${wrapped}~${payload}` },
        'secret-1',
      ),
    ).rejects.toMatchObject({ code: 'INVALID_CIPHERTEXT' });
    await expect(
      kmsEncryptFor(ctx, f.database, f.tenantId, rsa.id, 'x', 'secret-1'),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(audited).toEqual(['iam:kms:encrypt', 'iam:kms:decrypt', 'iam:kms:encrypt']);
  });

  it('opens one call per confirmation for an agent acting for a person', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const alice = await memberWith(f, 'alice', [
      {
        effect: 'allow',
        actions: ['iam:kms:encrypt', 'iam:kms:decrypt'],
        resources: ['iam/kms/*'],
      },
    ]);
    const key = await f.iam.api.keys.create(f.ownerCredential, { tenantId });
    const { ciphertext } = await f.iam.api.keys.encrypt(alice.credential, {
      tenantId,
      keyId: key.id,
      plaintext: 'record-1',
    });
    const agent = await f.iam.api.agents.create(f.ownerCredential, { tenantId, name: 'Helper' });
    const agentKey = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId,
      identityId: agent.id,
    });
    const delegation = await f.iam.api.delegations.grant(alice.credential, {
      tenantId,
      agentId: agent.id,
      scopes: ['iam:kms:decrypt'],
      confirm: ['iam:kms:decrypt'],
    });
    const acting = {
      token: (
        await f.iam.api.delegations.assume(
          { token: agentKey.token },
          { tenantId, delegationId: delegation.id },
        )
      ).token,
    };
    const decrypt = () => f.iam.api.keys.decrypt(acting, { tenantId, ciphertext });
    await expect(decrypt()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const request = await f.iam.api.delegations.requestConfirmation(acting, {
      tenantId,
      action: 'iam:kms:decrypt',
      resource: { type: 'iam', id: `kms/${key.id}` },
      reason: 'Decrypt one record for you',
      validSeconds: 3600,
    });
    await f.iam.api.delegations.decideConfirmation(alice.credential, {
      tenantId,
      confirmationId: request.id,
      approve: true,
    });
    await expect(decrypt()).resolves.toMatchObject({ plaintext: 'record-1' });
    // The approval is used up: the next decrypt needs another one.
    await expect(decrypt()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (await f.iam.api.delegations.listConfirmations(alice.credential, { tenantId })).find(
        (item) => item.id === request.id,
      )?.status,
    ).toBe('used');
  });

  it('never lets a change of tags or aliases open a key to the one making it', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const keys = f.iam.api.keys;
    const key = await keys.create(f.ownerCredential, { tenantId, tags: { team: 'payments' } });
    const { ciphertext } = await keys.encrypt(f.ownerCredential, {
      tenantId,
      keyId: key.id,
      plaintext: 'card on file: 4242',
    });
    // Manages every key, decrypts only the search team's, and never under a production alias.
    const operator = await memberWith(f, 'keyops', [
      { effect: 'allow', actions: ['iam:kms:update', 'iam:kms:read'], resources: ['iam/kms/*'] },
      {
        effect: 'allow',
        actions: ['iam:kms:decrypt'],
        resources: ['iam/kms/*'],
        conditions: { StringEquals: { 'resource.tags.team': 'search' } },
      },
      {
        effect: 'deny',
        actions: ['iam:kms:decrypt'],
        resources: ['iam/kms/*'],
        conditions: { ArrayContains: { 'resource.aliases': 'alias/prod-search' } },
      },
    ]);
    await expect(
      keys.update(operator.credential, { tenantId, keyId: key.id, tags: { team: 'search' } }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(keys.decrypt(operator.credential, { tenantId, ciphertext })).rejects.toMatchObject(
      {
        code: 'ACCESS_DENIED',
      },
    );
    // Tags that open nothing new are fine.
    await expect(
      keys.update(operator.credential, {
        tenantId,
        keyId: key.id,
        tags: { team: 'payments', owner: 'ops' },
      }),
    ).resolves.toMatchObject({ tags: { team: 'payments', owner: 'ops' } });
    // A search key under a production alias: dropping the alias would lift the deny.
    const search = await keys.create(f.ownerCredential, {
      tenantId,
      tags: { team: 'search' },
      alias: 'alias/prod-search',
    });
    await expect(
      keys.deleteAlias(operator.credential, { tenantId, alias: 'alias/prod-search' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Moving it away would too; the owner may.
    const spare = await keys.create(f.ownerCredential, { tenantId, tags: { team: 'payments' } });
    await expect(
      keys.updateAlias(operator.credential, {
        tenantId,
        alias: 'alias/prod-search',
        keyId: spare.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await keys.deleteAlias(f.ownerCredential, { tenantId, alias: 'alias/prod-search' });
    expect((await keys.get(operator.credential, { tenantId, keyId: search.id })).aliases).toEqual(
      [],
    );
  });
});
