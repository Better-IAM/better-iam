import { createCipheriv, createPublicKey, randomBytes, verify } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import type { AuditEvent } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const DAY = 86_400_000;

async function auditOf(f: OrganizationFixture, action: string) {
  return (await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId })).filter(
    (event) => event.action === action,
  );
}

/** A member holding one inline role document. */
async function memberWith(
  f: OrganizationFixture,
  name: string,
  statements: Array<Record<string, unknown>>,
) {
  const person = await f.member(name);
  if (statements.length) {
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: `${name} keys`,
      document: { version: 1, statements } as never,
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: person.id,
    });
  }
  return { id: person.id, credential: { token: (await f.signIn(name)).token } };
}

describe('key management (KMS)', () => {
  it('encrypts and decrypts under an alias, bound to the encryption context', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const key = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      description: 'Customer records',
      alias: 'alias/customers',
      tags: { team: 'payments' },
    });
    expect(key).toMatchObject({
      keySpec: 'aes-256-gcm',
      keyUsage: 'encrypt',
      state: 'enabled',
      currentVersion: 1,
      aliases: ['alias/customers'],
      tags: { team: 'payments' },
      algorithms: [],
    });
    expect(JSON.stringify(key)).not.toMatch(/material/i);

    const sealed = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: 'alias/customers',
      plaintext: 'card on file: 4242',
      encryptionContext: { record: 'cus_1' },
    });
    expect(sealed).toMatchObject({ keyId: key.id, keyVersion: 1 });
    expect(sealed.ciphertext.startsWith(`kms1.${key.id}.1.t.`)).toBe(true);
    expect(sealed.ciphertext).not.toContain('4242');

    await expect(
      keys.decrypt(f.ownerCredential, {
        tenantId: f.tenantId,
        ciphertext: sealed.ciphertext,
        encryptionContext: { record: 'cus_1' },
      }),
    ).resolves.toEqual({ plaintext: 'card on file: 4242', keyId: key.id, keyVersion: 1 });

    // A different context, or a flipped byte, fails the same way and is audited as a denied decrypt.
    await expect(
      keys.decrypt(f.ownerCredential, {
        tenantId: f.tenantId,
        ciphertext: sealed.ciphertext,
        encryptionContext: { record: 'cus_2' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CIPHERTEXT', status: 400 });
    // Flipped mid-payload: the last character of base64 may carry padding bits, which parsing refuses first.
    const at = sealed.ciphertext.length - 12;
    const tampered =
      sealed.ciphertext.slice(0, at) +
      (sealed.ciphertext[at] === 'A' ? 'B' : 'A') +
      sealed.ciphertext.slice(at + 1);
    await expect(
      keys.decrypt(f.ownerCredential, {
        tenantId: f.tenantId,
        ciphertext: tampered,
        encryptionContext: { record: 'cus_1' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CIPHERTEXT' });
    // Insisting on another key refuses before decrypting.
    const other = await keys.create(f.ownerCredential, { tenantId: f.tenantId });
    await expect(
      keys.decrypt(f.ownerCredential, {
        tenantId: f.tenantId,
        ciphertext: sealed.ciphertext,
        encryptionContext: { record: 'cus_1' },
        keyId: other.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CIPHERTEXT' });

    const decrypts = await auditOf(f, 'iam:kms:decrypt');
    expect(decrypts.filter((event) => event.outcome === 'allow')).toHaveLength(1);
    expect(
      decrypts.filter(
        (event) => event.outcome === 'deny' && event.metadata?.reason === 'invalid-ciphertext',
      ),
    ).toHaveLength(2);
    const allowed = decrypts.find((event) => event.outcome === 'allow')!;
    expect(allowed.resourceId).toBe(`kms/${key.id}`);
    expect(allowed.metadata).toMatchObject({
      keyId: key.id,
      keyVersion: 1,
      encryptionContext: { record: 'cus_1' },
    });
    expect(JSON.stringify(allowed)).not.toContain('4242');

    // Binary plaintexts come back as base64.
    const bytes = randomBytes(40);
    const binary = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintextBase64: bytes.toString('base64'),
    });
    expect(
      await keys.decrypt(f.ownerCredential, {
        tenantId: f.tenantId,
        ciphertext: binary.ciphertext,
      }),
    ).toEqual({ plaintextBase64: bytes.toString('base64'), keyId: key.id, keyVersion: 1 });

    // The material is sealed at rest: nothing in the store opens without the deployment secret.
    const versions = await f.database.find('kmsKeyVersions', { tenantId: f.tenantId });
    expect(versions.every((version) => typeof version.materialSealed === 'string')).toBe(true);
    expect(JSON.stringify(versions)).not.toMatch(/PRIVATE KEY/);
  });

  it('rotates on demand and on schedule while old ciphertexts keep decrypting', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const key = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      rotationPeriodDays: 30,
    });
    expect(key.nextRotationAt).toBe(f.now() + 30 * DAY);
    const first = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintext: 'v1',
    });
    const rotated = await keys.rotate(f.ownerCredential, { tenantId: f.tenantId, keyId: key.id });
    expect(rotated.currentVersion).toBe(2);
    const second = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintext: 'v2',
    });
    expect(second.keyVersion).toBe(2);

    f.advance(31 * DAY);
    const owner = await f.ownerSignIn();
    expect(await f.iam.kms.maintain()).toEqual({
      rotated: [{ tenantId: f.tenantId, keyId: key.id, keyVersion: 3 }],
      destroyed: [],
      grantsRemoved: 0,
    });
    // Once rotated, nothing is due until the next period.
    expect((await f.iam.kms.maintain()).rotated).toEqual([]);
    for (const [sealed, plaintext] of [
      [first, 'v1'],
      [second, 'v2'],
    ] as const)
      expect(
        (await keys.decrypt(owner, { tenantId: f.tenantId, ciphertext: sealed.ciphertext }))
          .plaintext,
      ).toBe(plaintext);
    const versions = await keys.listVersions(owner, { tenantId: f.tenantId, keyId: key.id });
    expect(versions.map((version) => [version.version, version.origin, version.current])).toEqual([
      [3, 'automatic', true],
      [2, 'rotate', false],
      [1, 'create', false],
    ]);
    expect(
      (await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId })).some(
        (event) => event.action === 'kms:key-rotate' && event.actorId === 'deployment-operator',
      ),
    ).toBe(true);

    // Clearing the period stops automatic rotation.
    const manual = await keys.update(owner, {
      tenantId: f.tenantId,
      keyId: key.id,
      rotationPeriodDays: null,
    });
    expect(manual.rotationPeriodDays).toBeUndefined();
    expect(manual.nextRotationAt).toBeUndefined();
  });

  it('issues data keys for envelope encryption', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const key = await keys.create(f.ownerCredential, { tenantId: f.tenantId });
    const dataKey = await keys.generateDataKey(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      encryptionContext: { bucket: 'invoices' },
    });
    expect(dataKey.bytes).toBe(32);
    const plaintextKey = Buffer.from(dataKey.plaintextBase64!, 'base64');
    expect(plaintextKey).toHaveLength(32);
    // The application encrypts locally with the plaintext key, then keeps only the wrapped copy.
    const iv = randomBytes(12);
    const local = createCipheriv('aes-256-gcm', plaintextKey, iv);
    local.update('a large invoice archive');
    local.final();
    const unwrapped = await keys.decrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      ciphertext: dataKey.ciphertext,
      encryptionContext: { bucket: 'invoices' },
    });
    expect(unwrapped.plaintextBase64).toBe(dataKey.plaintextBase64);

    const withoutPlaintext = await keys.generateDataKey(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      bytes: 16,
      includePlaintext: false,
    });
    expect(withoutPlaintext.plaintextBase64).toBeUndefined();
    expect(withoutPlaintext.bytes).toBe(16);

    // Re-encrypting moves a ciphertext to another key and context without exposing the plaintext.
    const next = await keys.create(f.ownerCredential, { tenantId: f.tenantId });
    const moved = await keys.reEncrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      ciphertext: dataKey.ciphertext,
      sourceEncryptionContext: { bucket: 'invoices' },
      destinationKeyId: next.id,
      destinationEncryptionContext: { bucket: 'archive' },
    });
    expect(moved).toMatchObject({ keyId: next.id, sourceKeyId: key.id, keyVersion: 1 });
    expect(
      (
        await keys.decrypt(f.ownerCredential, {
          tenantId: f.tenantId,
          ciphertext: moved.ciphertext,
          encryptionContext: { bucket: 'archive' },
        })
      ).plaintextBase64,
    ).toBe(dataKey.plaintextBase64);
  });

  it('signs and verifies with ECDSA, Ed25519 and RSA keys, offline too', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const message = 'release 1.2.3 sha256:abcdef';
    for (const [spec, usage, algorithm] of [
      ['ecc-p256', undefined, 'ES256'],
      ['ecc-p384', undefined, 'ES384'],
      ['ed25519', undefined, 'EdDSA'],
      ['rsa-2048', 'sign', 'PS256'],
    ] as const) {
      const key = await keys.create(f.ownerCredential, {
        tenantId: f.tenantId,
        keySpec: spec,
        ...(usage ? { keyUsage: usage } : {}),
      });
      expect(key.algorithms[0]).toBe(algorithm);
      const signed = await keys.sign(f.ownerCredential, {
        tenantId: f.tenantId,
        keyId: key.id,
        message,
      });
      expect(signed.algorithm).toBe(algorithm);
      expect(
        await keys.verify(f.ownerCredential, {
          tenantId: f.tenantId,
          keyId: key.id,
          message,
          signature: signed.signature,
        }),
      ).toMatchObject({ valid: true, keyVersion: 1 });
      expect(
        (
          await keys.verify(f.ownerCredential, {
            tenantId: f.tenantId,
            keyId: key.id,
            message: `${message}!`,
            signature: signed.signature,
          })
        ).valid,
      ).toBe(false);
      // Anyone holding the public key verifies without calling IAM.
      const published = await keys.publicKey(f.ownerCredential, {
        tenantId: f.tenantId,
        keyId: key.id,
      });
      const publicKey = createPublicKey(published.publicKeyPem);
      const hash = algorithm === 'EdDSA' ? null : algorithm.endsWith('384') ? 'sha384' : 'sha256';
      const options =
        algorithm === 'PS256' ? { key: publicKey, padding: 6, saltLength: -1 } : { key: publicKey };
      expect(
        verify(hash, Buffer.from(message), options, Buffer.from(signed.signature, 'base64url')),
      ).toBe(true);
      expect(published.jwk).toMatchObject({ kid: `${key.id}.1`, use: 'sig' });
    }
    // Encryption keys cannot sign, signing keys cannot encrypt.
    const aes = await keys.create(f.ownerCredential, { tenantId: f.tenantId });
    await expect(
      keys.sign(f.ownerCredential, { tenantId: f.tenantId, keyId: aes.id, message }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      keys.create(f.ownerCredential, { tenantId: f.tenantId, keySpec: 'rsa-2048' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('encrypts small secrets with RSA-OAEP keys', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const key = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      keySpec: 'rsa-2048',
      keyUsage: 'encrypt',
    });
    const sealed = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintext: 'short secret',
      encryptionContext: { purpose: 'test' },
    });
    expect(
      (
        await keys.decrypt(f.ownerCredential, {
          tenantId: f.tenantId,
          ciphertext: sealed.ciphertext,
          encryptionContext: { purpose: 'test' },
        })
      ).plaintext,
    ).toBe('short secret');
    await expect(
      keys.decrypt(f.ownerCredential, { tenantId: f.tenantId, ciphertext: sealed.ciphertext }),
    ).rejects.toMatchObject({ code: 'INVALID_CIPHERTEXT' });
    await expect(
      keys.encrypt(f.ownerCredential, {
        tenantId: f.tenantId,
        keyId: key.id,
        plaintext: 'x'.repeat(300),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(
      (await keys.publicKey(f.ownerCredential, { tenantId: f.tenantId, keyId: key.id })).jwk,
    ).toMatchObject({ use: 'enc', kty: 'RSA' });
    // No `alg`: KMS ciphertexts bind a label, so a plain offline RSA-OAEP-256 encrypter would not produce one.
    expect(
      (await keys.publicKey(f.ownerCredential, { tenantId: f.tenantId, keyId: key.id })).jwk.alg,
    ).toBeUndefined();
  });

  it('computes MACs and signs and verifies JWTs', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const hmac = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      keySpec: 'hmac-sha256',
    });
    const mac = await keys.generateMac(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: hmac.id,
      message: 'webhook body',
    });
    expect(mac.algorithm).toBe('HS256');
    expect(
      (
        await keys.verifyMac(f.ownerCredential, {
          tenantId: f.tenantId,
          keyId: hmac.id,
          message: 'webhook body',
          mac: mac.mac,
        })
      ).valid,
    ).toBe(true);
    expect(
      (
        await keys.verifyMac(f.ownerCredential, {
          tenantId: f.tenantId,
          keyId: hmac.id,
          message: 'webhook body.',
          mac: mac.mac,
        })
      ).valid,
    ).toBe(false);

    const signer = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      keySpec: 'ecc-p256',
      alias: 'alias/tokens',
    });
    const issued = await keys.signJwt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: 'alias/tokens',
      claims: { sub: 'svc_1', aud: 'billing', iss: 'acme' },
      expiresInSeconds: 300,
    });
    expect(issued.algorithm).toBe('ES256');
    const [header, claims] = issued.token
      .split('.')
      .slice(0, 2)
      .map((part) => JSON.parse(Buffer.from(part, 'base64url').toString()));
    expect(header).toEqual({ alg: 'ES256', kid: `${signer.id}.1`, typ: 'JWT' });
    expect(claims.exp - claims.iat).toBe(300);
    // The JWKS verifies it offline (JOSE signature encoding).
    const jwks = await keys.jwks(f.ownerCredential, { tenantId: f.tenantId, keyId: signer.id });
    const jwk = jwks.keys.find((item) => item.kid === header.kid)!;
    const [h, c, s] = issued.token.split('.');
    expect(
      verify(
        'sha256',
        Buffer.from(`${h}.${c}`),
        { key: createPublicKey({ key: jwk as never, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
        Buffer.from(s!, 'base64url'),
      ),
    ).toBe(true);
    const verified = await keys.verifyJwt(f.ownerCredential, {
      tenantId: f.tenantId,
      token: issued.token,
      audience: 'billing',
      issuer: 'acme',
    });
    expect(verified).toMatchObject({ valid: true, claims: { sub: 'svc_1' } });
    expect(
      await keys.verifyJwt(f.ownerCredential, {
        tenantId: f.tenantId,
        token: issued.token,
        audience: 'other',
      }),
    ).toMatchObject({ valid: false, reason: 'audience' });
    // After rotation the old token still verifies by its kid; a forged one does not.
    await keys.rotate(f.ownerCredential, { tenantId: f.tenantId, keyId: signer.id });
    expect(
      (await keys.verifyJwt(f.ownerCredential, { tenantId: f.tenantId, token: issued.token }))
        .valid,
    ).toBe(true);
    const forged = `${h}.${Buffer.from(JSON.stringify({ ...claims, sub: 'admin' })).toString('base64url')}.${s}`;
    expect(
      await keys.verifyJwt(f.ownerCredential, { tenantId: f.tenantId, token: forged }),
    ).toMatchObject({ valid: false, reason: 'signature' });
    f.advance(10 * 60_000);
    expect(
      await keys.verifyJwt(await f.ownerSignIn(), { tenantId: f.tenantId, token: issued.token }),
    ).toMatchObject({ valid: false, reason: 'expired' });

    // HMAC keys sign HS256 tokens.
    const hs = await keys.signJwt(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      keyId: hmac.id,
      claims: { sub: 'x' },
    });
    expect(hs.algorithm).toBe('HS256');
    expect(
      (await keys.verifyJwt(await f.ownerSignIn(), { tenantId: f.tenantId, token: hs.token }))
        .valid,
    ).toBe(true);
  });

  it('authorizes by key tags and encryption context, and refuses other tenants', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const payments = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      tags: { team: 'payments' },
    });
    const research = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      tags: { team: 'research' },
    });
    const alice = await memberWith(f, 'alice', [
      {
        effect: 'allow',
        actions: ['iam:kms:encrypt', 'iam:kms:decrypt'],
        resources: ['iam/kms/*'],
        conditions: {
          StringEquals: {
            'resource.tags.team': 'payments',
            'resource.encryptionContext.app': 'billing',
          },
        },
      },
      {
        effect: 'allow',
        actions: ['iam:kms:read'],
        resources: ['iam/kms/*'],
        conditions: { StringEquals: { 'resource.tags.team': 'payments' } },
      },
    ]);
    const sealed = await keys.encrypt(alice.credential, {
      tenantId: f.tenantId,
      keyId: payments.id,
      plaintext: 'ok',
      encryptionContext: { app: 'billing' },
    });
    await expect(
      keys.encrypt(alice.credential, {
        tenantId: f.tenantId,
        keyId: payments.id,
        plaintext: 'no',
        encryptionContext: { app: 'crm' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      keys.encrypt(alice.credential, {
        tenantId: f.tenantId,
        keyId: research.id,
        plaintext: 'no',
        encryptionContext: { app: 'billing' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (
        await keys.decrypt(alice.credential, {
          tenantId: f.tenantId,
          ciphertext: sealed.ciphertext,
          encryptionContext: { app: 'billing' },
        })
      ).plaintext,
    ).toBe('ok');
    // Listing shows only the keys a tag-scoped reader may read.
    const listed = await keys.list(alice.credential, { tenantId: f.tenantId });
    expect(listed.keys.map((key) => key.id)).toEqual([payments.id]);
    expect((await keys.list(f.ownerCredential, { tenantId: f.tenantId })).total).toBe(2);
    // Management is a separate permission.
    await expect(
      keys.disable(alice.credential, { tenantId: f.tenantId, keyId: payments.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (await auditOf(f, 'iam:kms:update')).some(
        (event) => event.outcome === 'deny' && event.actorId === alice.id,
      ),
    ).toBe(true);

    // A tag-scoped administrator cannot re-tag a key out of their reach.
    const admin = await memberWith(f, 'adam', [
      {
        effect: 'allow',
        actions: ['iam:kms:*'],
        // Creating names the key collection (`iam/kms`); everything else names the key.
        resources: ['iam/kms', 'iam/kms/*'],
        conditions: { StringEquals: { 'resource.tags.team': 'payments' } },
      },
    ]);
    await expect(
      keys.update(admin.credential, {
        tenantId: f.tenantId,
        keyId: payments.id,
        tags: { team: 'research' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      keys.update(admin.credential, {
        tenantId: f.tenantId,
        keyId: payments.id,
        tags: { team: 'payments', env: 'prod' },
      }),
    ).resolves.toMatchObject({ tags: { team: 'payments', env: 'prod' } });
    // And may only create keys carrying their tag.
    await expect(
      keys.create(admin.credential, { tenantId: f.tenantId, tags: { team: 'research' } }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      keys.create(admin.credential, { tenantId: f.tenantId, tags: { team: 'payments' } }),
    ).resolves.toMatchObject({ tags: { team: 'payments' } });

    // Another organization's owner cannot use Acme's keys, even knowing their ids.
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
    await expect(
      keys.decrypt(
        { token: globex.token },
        {
          tenantId: f.tenantId,
          ciphertext: sealed.ciphertext,
          encryptionContext: { app: 'billing' },
        },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      keys.decrypt(
        { token: globex.token },
        {
          tenantId: other.tenant.id,
          ciphertext: sealed.ciphertext,
          encryptionContext: { app: 'billing' },
        },
      ),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('delegates key use through grants that never exceed the grantor', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const key = await keys.create(f.ownerCredential, { tenantId: f.tenantId });
    const sealed = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintext: 'billing data',
      encryptionContext: { app: 'billing', record: '7' },
    });
    const crm = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintext: 'crm data',
      encryptionContext: { app: 'crm' },
    });
    const bob = await memberWith(f, 'bob', []);
    const decrypt = (ciphertext: string, encryptionContext: Record<string, string>) =>
      keys.decrypt(bob.credential, { tenantId: f.tenantId, ciphertext, encryptionContext });
    await expect(decrypt(sealed.ciphertext, { app: 'billing', record: '7' })).rejects.toMatchObject(
      { code: 'ACCESS_DENIED' },
    );

    const grant = await keys.createGrant(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      granteeType: 'identity',
      granteeId: bob.id,
      operations: ['decrypt'],
      constraints: { encryptionContextSubset: { app: 'billing' } },
      name: 'billing worker',
    });
    expect(grant).toMatchObject({ operations: ['decrypt'], active: true });
    expect((await decrypt(sealed.ciphertext, { app: 'billing', record: '7' })).plaintext).toBe(
      'billing data',
    );
    const used = (await auditOf(f, 'iam:kms:decrypt')).find(
      (event) => event.actorId === bob.id && event.outcome === 'allow',
    )!;
    expect(used.metadata?.grantId).toBe(grant.id);
    // Outside the constraint, or another operation, the grant does not apply.
    await expect(decrypt(crm.ciphertext, { app: 'crm' })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(
      keys.encrypt(bob.credential, {
        tenantId: f.tenantId,
        keyId: key.id,
        plaintext: 'x',
        encryptionContext: { app: 'billing' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Constraints only fit context operations; unknown operations are refused.
    const signer = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      keySpec: 'ed25519',
    });
    await expect(
      keys.createGrant(f.ownerCredential, {
        tenantId: f.tenantId,
        keyId: signer.id,
        granteeType: 'identity',
        granteeId: bob.id,
        operations: ['sign'],
        constraints: { encryptionContextEquals: { a: 'b' } },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      keys.createGrant(f.ownerCredential, {
        tenantId: f.tenantId,
        keyId: signer.id,
        granteeType: 'identity',
        granteeId: bob.id,
        operations: ['decrypt'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // A grantor with the grant permission but without decrypt cannot hand out decrypt.
    const carol = await memberWith(f, 'carol', [
      {
        effect: 'allow',
        actions: ['iam:kms:grant', 'iam:kms:encrypt', 'iam:kms:read'],
        resources: ['iam/kms/*'],
      },
    ]);
    await expect(
      keys.createGrant(carol.credential, {
        tenantId: f.tenantId,
        keyId: key.id,
        granteeType: 'identity',
        granteeId: bob.id,
        operations: ['decrypt'],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      keys.createGrant(carol.credential, {
        tenantId: f.tenantId,
        keyId: key.id,
        granteeType: 'identity',
        granteeId: bob.id,
        operations: ['encrypt'],
      }),
    ).resolves.toMatchObject({ operations: ['encrypt'] });

    // Groups are not grantees (membership changes would move key access around unseen).
    const group = await f.iam.api.groups.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Readers',
    });
    await expect(
      keys.createGrant(f.ownerCredential, {
        tenantId: f.tenantId,
        keyId: key.id,
        granteeType: 'group' as never,
        granteeId: group.id,
        operations: ['decrypt'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The grantee's own explicit denies still win over a grant.
    const dana = await memberWith(f, 'dana', [
      {
        effect: 'deny',
        actions: ['iam:kms:decrypt'],
        resources: ['iam/kms/*'],
        conditions: { StringEquals: { 'resource.encryptionContext.record': '7' } },
      },
    ]);
    await keys.createGrant(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      granteeId: dana.id,
      operations: ['decrypt'],
    });
    await expect(
      keys.decrypt(dana.credential, {
        tenantId: f.tenantId,
        ciphertext: crm.ciphertext,
        encryptionContext: { app: 'crm' },
      }),
    ).resolves.toMatchObject({ plaintext: 'crm data' });
    await expect(
      keys.decrypt(dana.credential, {
        tenantId: f.tenantId,
        ciphertext: sealed.ciphertext,
        encryptionContext: { app: 'billing', record: '7' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // The grantee can retire its own grant; others cannot.
    await expect(
      keys.retireGrant(carol.credential, { tenantId: f.tenantId, grantId: grant.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await keys.retireGrant(bob.credential, { tenantId: f.tenantId, grantId: grant.id });
    await expect(decrypt(sealed.ciphertext, { app: 'billing', record: '7' })).rejects.toMatchObject(
      { code: 'ACCESS_DENIED' },
    );
    expect(
      (await keys.listGrants(f.ownerCredential, { tenantId: f.tenantId, keyId: key.id }))
        .map((item) => item.granteeId)
        .sort(),
    ).toEqual([bob.id, dana.id].sort());

    // Lapsed grants stop working and the maintenance job removes them.
    const brief = await keys.createGrant(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      granteeType: 'identity',
      granteeId: bob.id,
      operations: ['decrypt'],
      expiresAt: f.now() + 60_000,
    });
    f.advance(120_000);
    await expect(decrypt(sealed.ciphertext, { app: 'billing', record: '7' })).rejects.toMatchObject(
      { code: 'ACCESS_DENIED' },
    );
    expect((await f.iam.kms.maintain()).grantsRemoved).toBe(1);
    expect(
      (await keys.listGrants(f.ownerCredential, { tenantId: f.tenantId, keyId: key.id })).some(
        (item) => item.id === brief.id,
      ),
    ).toBe(false);
  });

  it('disables, schedules deletion, cancels, and destroys keys', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const key = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      alias: 'alias/old',
    });
    const sealed = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintext: 'soon unreadable',
    });
    await keys.disable(f.ownerCredential, { tenantId: f.tenantId, keyId: key.id });
    await expect(
      keys.decrypt(f.ownerCredential, { tenantId: f.tenantId, ciphertext: sealed.ciphertext }),
    ).rejects.toMatchObject({ code: 'KEY_STATE_INVALID', status: 409 });
    await keys.enable(f.ownerCredential, { tenantId: f.tenantId, keyId: key.id });
    await expect(
      keys.decrypt(f.ownerCredential, { tenantId: f.tenantId, ciphertext: sealed.ciphertext }),
    ).resolves.toMatchObject({ plaintext: 'soon unreadable' });

    await expect(
      keys.scheduleDeletion(f.ownerCredential, {
        tenantId: f.tenantId,
        keyId: key.id,
        waitingDays: 3,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const pending = await keys.scheduleDeletion(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      waitingDays: 7,
    });
    expect(pending).toMatchObject({ state: 'pending-deletion', deletionDate: f.now() + 7 * DAY });
    await expect(
      keys.enable(f.ownerCredential, { tenantId: f.tenantId, keyId: key.id }),
    ).rejects.toMatchObject({ code: 'KEY_STATE_INVALID' });
    const restored = await keys.cancelDeletion(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
    });
    expect(restored.state).toBe('disabled');
    expect(restored.deletionDate).toBeUndefined();

    await keys.scheduleDeletion(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      waitingDays: 7,
    });
    f.advance(6 * DAY);
    expect((await f.iam.kms.maintain()).destroyed).toEqual([]);
    f.advance(2 * DAY);
    expect((await f.iam.kms.maintain()).destroyed).toEqual([
      { tenantId: f.tenantId, keyId: key.id },
    ]);
    const owner = await f.ownerSignIn();
    await expect(keys.get(owner, { tenantId: f.tenantId, keyId: key.id })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    await expect(
      keys.get(owner, { tenantId: f.tenantId, keyId: 'alias/old' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      keys.decrypt(owner, { tenantId: f.tenantId, ciphertext: sealed.ciphertext }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(await f.database.find('kmsKeyVersions', { tenantId: f.tenantId })).toEqual([]);
  });

  it('moves aliases between keys of the same kind', async () => {
    const f = await organizationFixture();
    const keys = f.iam.api.keys;
    const first = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      alias: 'alias/app',
    });
    const second = await keys.create(f.ownerCredential, { tenantId: f.tenantId });
    const signer = await keys.create(f.ownerCredential, {
      tenantId: f.tenantId,
      keySpec: 'ecc-p256',
    });
    await expect(
      keys.createAlias(f.ownerCredential, {
        tenantId: f.tenantId,
        alias: 'alias/app',
        keyId: second.id,
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      keys.updateAlias(f.ownerCredential, {
        tenantId: f.tenantId,
        alias: 'alias/app',
        keyId: signer.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await keys.updateAlias(f.ownerCredential, {
      tenantId: f.tenantId,
      alias: 'alias/app',
      keyId: second.id,
    });
    const sealed = await keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: 'alias/app',
      plaintext: 'x',
    });
    expect(sealed.keyId).toBe(second.id);
    expect(await keys.listAliases(f.ownerCredential, { tenantId: f.tenantId })).toMatchObject([
      { name: 'alias/app', keyId: second.id },
    ]);
    expect(
      (await keys.get(f.ownerCredential, { tenantId: f.tenantId, keyId: first.id })).aliases,
    ).toEqual([]);
    await keys.deleteAlias(f.ownerCredential, { tenantId: f.tenantId, alias: 'alias/app' });
    await expect(
      keys.encrypt(f.ownerCredential, { tenantId: f.tenantId, keyId: 'alias/app', plaintext: 'x' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      keys.createAlias(f.ownerCredential, {
        tenantId: f.tenantId,
        alias: 'not-an-alias',
        keyId: first.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('re-seals key material when the deployment secret rotates, and serves HTTP', async () => {
    const f = await organizationFixture();
    const key = await f.iam.api.keys.create(f.ownerCredential, { tenantId: f.tenantId });
    const sealed = await f.iam.api.keys.encrypt(f.ownerCredential, {
      tenantId: f.tenantId,
      keyId: key.id,
      plaintext: 'survives rotation',
    });
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
    expect(result.resealed.kmsKeyVersions).toBe(1);
    expect((await rotated.rotateSecrets({ dryRun: true })).done).toBe(true);
    const response = await rotated.handler(
      new Request('http://localhost:3000/api/iam/keys/decrypt', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${f.ownerCredential.token}`,
        },
        body: JSON.stringify({ tenantId: f.tenantId, ciphertext: sealed.ciphertext }),
      }),
    );
    expect(response.status).toBe(200);
    expect(((await response.json()) as { data: { plaintext: string } }).data.plaintext).toBe(
      'survives rotation',
    );
  });
});
