import { X509Certificate, generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { createCertificateRequest } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const privateKey = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
const csr = (
  names: Parameters<typeof createCertificateRequest>[0] extends infer T
    ? Omit<T & object, 'privateKey'>
    : never,
) => createCertificateRequest({ privateKey: privateKey(), ...names });

async function setup(f: OrganizationFixture) {
  const owner = await f.ownerSignIn();
  const pki = f.iam.api.pki;
  const root = await pki.createAuthority(owner, {
    tenantId: f.tenantId,
    name: 'Root',
    subject: { commonName: 'Acme Root' },
    pathLength: 1,
  });
  const issuing = await pki.createAuthority(owner, {
    tenantId: f.tenantId,
    name: 'Issuing',
    parentId: root.id,
    subject: { commonName: 'Acme Issuing' },
    trustDomain: 'acme.test',
    permitted: { dnsNames: ['internal'], uriHosts: ['acme.test'] },
  });
  return { owner, pki, root, issuing };
}

/** A member holding one inline role. */
async function memberWith(f: OrganizationFixture, name: string, statements: unknown[]) {
  const person = await f.member(name);
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `${name} pki`,
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

describe('private CA security regressions', () => {
  it('never lets a CA key sign through the KMS API', async () => {
    const f = await organizationFixture();
    const { owner, pki, issuing } = await setup(f);
    // Even the owner, who may do anything with KMS, cannot sign raw bytes (or a forged certificate body) with it.
    await expect(
      f.iam.api.keys.sign(owner, { tenantId: f.tenantId, keyId: issuing.keyId, message: 'tbs' }),
    ).rejects.toMatchObject({ code: 'KEY_MANAGED' });
    await expect(
      f.iam.api.keys.signJwt(owner, { tenantId: f.tenantId, keyId: issuing.keyId, claims: {} }),
    ).rejects.toMatchObject({ code: 'KEY_MANAGED' });
    const member = await f.member('gus');
    await expect(
      f.iam.api.keys.createGrant(owner, {
        tenantId: f.tenantId,
        keyId: issuing.keyId,
        granteeId: member.id,
        operations: ['sign'],
      }),
    ).rejects.toMatchObject({ code: 'KEY_MANAGED' });
    expect(
      await f.iam.api.keys.get(owner, { tenantId: f.tenantId, keyId: issuing.keyId }),
    ).toMatchObject({ managedBy: 'pki', managedId: issuing.id });
    // Adopting an existing key takes it over; a key another authority owns cannot be adopted.
    const own = await f.iam.api.keys.create(owner, { tenantId: f.tenantId, keySpec: 'ed25519' });
    await f.iam.api.keys.sign(owner, { tenantId: f.tenantId, keyId: own.id, message: 'before' });
    await pki.createAuthority(owner, {
      tenantId: f.tenantId,
      name: 'Adopted',
      subject: { commonName: 'Adopted Root' },
      keyId: own.id,
    });
    await expect(
      f.iam.api.keys.sign(owner, { tenantId: f.tenantId, keyId: own.id, message: 'after' }),
    ).rejects.toMatchObject({ code: 'KEY_MANAGED' });
    await expect(
      pki.createAuthority(owner, {
        tenantId: f.tenantId,
        name: 'Twin',
        subject: { commonName: 'Twin Root' },
        keyId: own.id,
      }),
    ).rejects.toMatchObject({ code: 'KEY_MANAGED' });
  });

  it('keeps workload certificates within the credential, and stops them with the identity', async () => {
    const f = await organizationFixture();
    const { owner, pki, issuing } = await setup(f);
    const account = await f.iam.api.serviceAccounts.create(owner, {
      tenantId: f.tenantId,
      name: 'job',
    });
    const role = await f.iam.api.roles.create(owner, {
      tenantId: f.tenantId,
      name: 'Service workloads',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['iam:pki:request'],
            resources: ['iam/pki/*'],
            // Decided on the SPIFFE ID and the caller's kind.
            conditions: {
              StringEquals: { 'resource.identityKind': 'service' },
              StringLike: { 'resource.name': 'spiffe://acme.test/service/*' },
            },
          },
        ],
      },
    });
    await f.iam.api.bindings.create(owner, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: account.id,
    });
    const key = await f.iam.api.credentials.create(owner, {
      tenantId: f.tenantId,
      identityId: account.id,
      name: 'short',
      expiresInSeconds: 30 * 60,
    });
    const svid = await pki.requestCertificate(
      { token: key.token },
      {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: csr({}),
        validitySeconds: 86_400,
      },
    );
    // Asked for a day; the API key ends in 30 minutes, so the certificate does too.
    expect(svid.notAfter).toBeLessThanOrEqual(f.now() + 30 * 60_000);
    await expect(
      pki.requestCertificate(
        { token: key.token },
        {
          tenantId: f.tenantId,
          authorityId: issuing.id,
          csr: csr({}),
          validitySeconds: 2 * 86_400,
        },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(await f.iam.pki.verify(svid.certificatePem, { tenantId: f.tenantId })).toMatchObject({
      identityId: account.id,
    });
    await f.iam.api.identities.setStatus(owner, {
      tenantId: f.tenantId,
      identityId: account.id,
      status: 'disabled',
    });
    await expect(
      f.iam.pki.verify(svid.certificatePem, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'CERTIFICATE_INVALID' });
  });

  it('decides and encodes the same canonical names', async () => {
    const f = await organizationFixture();
    const { owner, pki, issuing } = await setup(f);
    const issue = (names: Parameters<typeof csr>[0]) =>
      pki.issueCertificate(owner, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: csr(names),
      });
    // Non-ASCII email local parts would be truncated to other bytes when encoded.
    expect(() => csr({ emails: ['ţeo@corp.internal'] })).toThrow();
    // Dot segments and non-canonical forms in URIs are refused rather than normalized behind the policy's back.
    expect(() => csr({ uris: ['spiffe://acme.test/team-a/../service/x'] })).toThrow();
    expect(() => csr({ uris: ['https://Acme.test/x'] })).toThrow();
    expect(() => csr({ uris: ['https://user@acme.test/x'] })).toThrow();
    // IP addresses are canonical: an IPv4-mapped IPv6 address is the IPv4 address.
    const mapped = await issue({
      commonName: 'db.internal',
      dnsNames: ['db.internal'],
      ipAddresses: ['::ffff:10.0.0.1'],
    });
    expect(new X509Certificate(mapped.certificatePem).subjectAltName).toContain(
      'IP Address:10.0.0.1',
    );
    // Identity paths are reserved for the identities themselves.
    await expect(
      issue({ uris: ['spiffe://acme.test/service/someone-else'] }),
    ).rejects.toMatchObject({
      code: 'NAME_NOT_PERMITTED',
    });
    // The common name must be one of the alternative names, and name constraints cover it.
    await expect(
      issue({ subject: { commonName: 'www.example.com' }, dnsNames: ['api.internal'] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(issue({ subject: { commonName: 'www.example.com' } })).rejects.toMatchObject({
      code: 'NAME_NOT_PERMITTED',
    });
    // Refusals after authorization are audited.
    const denied = (await f.database.find('audit', { tenantId: f.tenantId })).filter(
      (event) =>
        event.action === 'iam:pki:issue' &&
        event.outcome === 'deny' &&
        (event.metadata as { reason?: string } | undefined)?.reason === 'name-not-permitted',
    );
    expect(denied.length).toBeGreaterThanOrEqual(2);
  });

  it('keeps path lengths, trust anchors and trust domains straight', async () => {
    const f = await organizationFixture();
    const { owner, pki, root, issuing } = await setup(f);
    // The root allows one level: the intermediate got path length 0, so nothing goes below it.
    expect(issuing.pathLength).toBe(0);
    await expect(
      pki.createAuthority(owner, {
        tenantId: f.tenantId,
        name: 'Deeper',
        parentId: issuing.id,
        subject: { commonName: 'Deeper' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The bundle holds roots only.
    const bundle = await pki.bundle(owner, { tenantId: f.tenantId });
    expect(bundle).toMatchObject({ authorities: 1, pem: root.certificatePem });
    // Revoking an intermediate's certificate revokes everything below it.
    const open = await pki.createAuthority(owner, {
      tenantId: f.tenantId,
      name: 'Open root',
      subject: { commonName: 'Open Root' },
    });
    const first = await pki.createAuthority(owner, {
      tenantId: f.tenantId,
      name: 'First',
      parentId: open.id,
      subject: { commonName: 'First' },
    });
    const second = await pki.createAuthority(owner, {
      tenantId: f.tenantId,
      name: 'Second',
      parentId: first.id,
      subject: { commonName: 'Second' },
    });
    const firstCertificate = (
      await pki.listCertificates(owner, { tenantId: f.tenantId, authorityId: open.id })
    ).certificates[0]!;
    await pki.revokeCertificate(owner, {
      tenantId: f.tenantId,
      serialNumber: firstCertificate.serialNumber,
      reason: 'caCompromise',
    });
    expect(
      (await pki.getAuthority(owner, { tenantId: f.tenantId, authorityId: second.id })).state,
    ).toBe('revoked');

    // Another organization cannot claim the trust domain, and verification is per tenant.
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
      pki.createAuthority(
        { token: globex.token },
        {
          tenantId: other.tenant.id,
          name: 'Impostor',
          subject: { commonName: 'Acme Issuing' },
          trustDomain: 'acme.test',
        },
      ),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const leaf = await pki.issueCertificate(owner, {
      tenantId: f.tenantId,
      authorityId: issuing.id,
      csr: csr({ subject: { commonName: 'a.internal' }, dnsNames: ['a.internal'] }),
    });
    await expect(
      f.iam.pki.verify(leaf.certificatePem, { tenantId: other.tenant.id }),
    ).rejects.toMatchObject({ code: 'CERTIFICATE_INVALID' });
    await expect(f.iam.pki.verify(leaf.certificatePem, undefined as never)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
  });

  it('decides wildcard names as wildcards, apart from the hosts they cover', async () => {
    const f = await organizationFixture();
    const { issuing } = await setup(f);
    // May certify any single host under .internal except the vault; wildcards are not hosts.
    const hosts = await memberWith(f, 'hosts', [
      {
        effect: 'allow',
        actions: ['iam:pki:issue'],
        resources: ['iam/pki/*'],
        conditions: {
          StringEquals: { 'resource.nameType': ['dns', 'commonName'] },
          StringLike: { 'resource.name': '*.internal' },
        },
      },
      {
        effect: 'deny',
        actions: ['iam:pki:issue'],
        resources: ['iam/pki/*'],
        conditions: { StringEquals: { 'resource.name': 'vault.internal' } },
      },
    ]);
    const issue = (dnsNames: string[]) =>
      f.iam.api.pki.issueCertificate(hosts.credential, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: csr({ dnsNames }),
      });
    await expect(issue(['api.internal'])).resolves.toMatchObject({
      serialNumber: expect.any(String),
    });
    await expect(issue(['vault.internal'])).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // `*.internal` would cover vault.internal: it is decided as nameType `wildcard`, which nothing allowed.
    await expect(issue(['*.internal'])).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('parses requests only for callers of the tenant', async () => {
    const f = await organizationFixture();
    const { issuing } = await setup(f);
    // A malformed request from someone without a valid credential never reaches the parser.
    await expect(
      f.iam.api.pki.issueCertificate(
        { token: 'biam_ses_not-a-real-token' },
        { tenantId: f.tenantId, authorityId: issuing.id, csr: 'garbage' },
      ),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    const nobody = await memberWith(f, 'nobody', []);
    await expect(
      f.iam.api.pki.issueCertificate(nobody.credential, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: csr({ dnsNames: ['x.internal'] }),
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});
