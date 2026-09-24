import { X509Certificate, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { connect, createServer, type TLSSocket } from 'node:tls';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { createCertificateRequest } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const keyPair = (kind: 'ec' | 'ed25519' | 'rsa' = 'ec') =>
  kind === 'ec'
    ? generateKeyPairSync('ec', { namedCurve: 'P-256' })
    : kind === 'rsa'
      ? generateKeyPairSync('rsa', { modulusLength: 2048 })
      : generateKeyPairSync('ed25519');
const pemOf = (key: KeyObject) => key.export({ format: 'pem', type: 'pkcs8' }).toString();

async function authorities(f: OrganizationFixture) {
  const owner = await f.ownerSignIn();
  const pki = f.iam.api.pki;
  const root = await pki.createAuthority(owner, {
    tenantId: f.tenantId,
    name: 'Acme Root',
    subject: { commonName: 'Acme Root CA', organization: 'Acme', country: 'US' },
    pathLength: 1,
  });
  const issuing = await pki.createAuthority(owner, {
    tenantId: f.tenantId,
    name: 'Acme Workloads',
    parentId: root.id,
    subject: { commonName: 'Acme Workload CA', organization: 'Acme' },
    trustDomain: 'acme.test',
    permitted: { dnsNames: ['internal', 'localhost'], uriHosts: ['acme.test'] },
    crlUrl: 'https://pki.acme.test/crl/workloads.crl',
  });
  return { owner, pki, root, issuing };
}

/** A TLS server and client that both present certificates; resolves with the peer the server saw. */
async function mutualTls(
  server: { key: string; cert: string },
  client: { key: string; cert: string },
  ca: string,
) {
  const tls = createServer({
    key: server.key,
    cert: server.cert,
    ca,
    requestCert: true,
    rejectUnauthorized: true,
  });
  const seen = new Promise<string>((resolve, reject) => {
    tls.on('secureConnection', (socket: TLSSocket) => {
      resolve(socket.getPeerCertificate().subjectaltname ?? '');
      socket.end();
    });
    tls.on('tlsClientError', reject);
  });
  await new Promise<void>((resolve) => tls.listen(0, 'localhost', resolve));
  const { port } = tls.address() as AddressInfo;
  try {
    await new Promise<void>((resolve, reject) => {
      const socket = connect(
        {
          port,
          host: 'localhost',
          servername: 'localhost',
          key: client.key,
          cert: client.cert,
          ca,
        },
        () => {
          if (!socket.authorized) reject(socket.authorizationError);
          else resolve();
        },
      );
      socket.on('error', reject);
      socket.on('end', () => socket.destroy());
    });
    return await seen;
  } finally {
    await new Promise((resolve) => tls.close(resolve));
  }
}

describe('private certificate authority', () => {
  it('creates a root and an intermediate that Node reads and verifies', async () => {
    const f = await organizationFixture();
    const { owner, pki, root, issuing } = await authorities(f);
    const rootCert = new X509Certificate(root.certificatePem);
    const issuingCert = new X509Certificate(issuing.certificatePem);
    expect(rootCert.ca).toBe(true);
    expect(issuingCert.ca).toBe(true);
    expect(rootCert.subject).toContain('CN=Acme Root CA');
    expect(rootCert.verify(rootCert.publicKey)).toBe(true);
    expect(issuingCert.checkIssued(rootCert)).toBe(true);
    expect(issuingCert.verify(rootCert.publicKey)).toBe(true);
    expect(issuing).toMatchObject({
      type: 'intermediate',
      parentId: root.id,
      trustDomain: 'acme.test',
      state: 'active',
    });
    // The signing keys are KMS keys, visible and tagged.
    const key = await f.iam.api.keys.get(owner, { tenantId: f.tenantId, keyId: root.keyId });
    expect(key).toMatchObject({
      keySpec: 'ecc-p256',
      keyUsage: 'sign',
      tags: { 'pki-authority': 'Acme Root' },
    });
    // The intermediate's own certificate is recorded under the root, so the root can revoke it.
    const underRoot = await pki.listCertificates(owner, {
      tenantId: f.tenantId,
      authorityId: root.id,
    });
    expect(underRoot.certificates).toMatchObject([{ usage: 'ca', subordinateId: issuing.id }]);
    // Path length 1 under the root leaves none below the intermediate... unless it is given a smaller one.
    await expect(
      pki.createAuthority(owner, {
        tenantId: f.tenantId,
        name: 'Too deep',
        parentId: root.id,
        subject: { commonName: 'Too deep' },
        pathLength: 1,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const bundle = await pki.bundle(owner, { tenantId: f.tenantId });
    // Only roots are trust anchors; intermediates travel in each server's chain.
    expect(bundle.authorities).toBe(1);
    expect(bundle.pem.indexOf(root.certificatePem)).toBe(0);
    expect(await f.iam.pki.bundle(f.tenantId)).toBe(bundle.pem);
  });

  it('issues certificates from requests that complete a mutual TLS handshake', async () => {
    const f = await organizationFixture();
    const { owner, pki, root, issuing } = await authorities(f);
    const serverKey = keyPair('ec');
    const serverCsr = createCertificateRequest({
      privateKey: serverKey.privateKey,
      subject: { commonName: 'localhost' },
      dnsNames: ['localhost', 'api.internal'],
      ipAddresses: ['127.0.0.1'],
    });
    const server = await pki.issueCertificate(owner, {
      tenantId: f.tenantId,
      authorityId: issuing.id,
      csr: serverCsr,
      usage: 'server',
      validitySeconds: 3600,
    });
    const leaf = new X509Certificate(server.certificatePem);
    expect(leaf.ca).toBe(false);
    expect(leaf.checkHost('api.internal')).toBe('api.internal');
    expect(leaf.checkIP('127.0.0.1')).toBe('127.0.0.1');
    expect(leaf.verify(new X509Certificate(issuing.certificatePem).publicKey)).toBe(true);
    expect(leaf.publicKey.export({ format: 'der', type: 'spki' })).toEqual(
      serverKey.publicKey.export({ format: 'der', type: 'spki' }),
    );
    expect(server.chainPem).toBe(issuing.certificatePem);
    expect(server.rootPem).toBe(root.certificatePem);
    expect(Date.parse(leaf.validTo) - f.now()).toBeLessThanOrEqual(3600_000);

    const clientKey = keyPair('ed25519');
    const client = await pki.issueCertificate(owner, {
      tenantId: f.tenantId,
      authorityId: issuing.id,
      csr: createCertificateRequest({
        privateKey: clientKey.privateKey,
        uris: ['spiffe://acme.test/billing'],
      }),
      usage: 'client',
    });
    const peer = await mutualTls(
      { key: pemOf(serverKey.privateKey), cert: server.certificatePem + server.chainPem },
      { key: pemOf(clientKey.privateKey), cert: client.certificatePem + client.chainPem },
      root.certificatePem,
    );
    expect(peer).toContain('URI:spiffe://acme.test/billing');

    // Verification for the server side of mTLS: the stored chain, not what the client sent.
    const verified = await f.iam.pki.verify(client.certificatePem, {
      tenantId: f.tenantId,
      usage: 'client',
    });
    expect(verified).toMatchObject({
      serialNumber: client.serialNumber,
      uris: ['spiffe://acme.test/billing'],
    });
    await expect(
      f.iam.pki.verify(client.certificatePem, { tenantId: f.tenantId, usage: 'server' }),
    ).rejects.toMatchObject({
      code: 'CERTIFICATE_INVALID',
    });
  });

  it('decides every name on a certificate, and enforces name constraints and SPIFFE rules', async () => {
    const f = await organizationFixture();
    const { owner, pki, issuing } = await authorities(f);
    const person = await f.member('pat');
    const role = await f.iam.api.roles.create(owner, {
      tenantId: f.tenantId,
      name: 'Payments certificates',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['iam:pki:issue'],
            resources: ['iam/pki/*'],
            conditions: {
              StringLike: { 'resource.name': ['*.payments.internal', 'payments.internal'] },
              NumericLessThanEquals: { 'resource.validitySeconds': 86400 },
            },
          },
        ],
      },
    });
    await f.iam.api.bindings.create(owner, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: person.id,
    });
    const pat = { token: (await f.signIn('pat')).token };
    const csr = (names: { dnsNames?: string[]; commonName?: string }) =>
      createCertificateRequest({
        privateKey: keyPair().privateKey,
        ...(names.commonName ? { subject: { commonName: names.commonName } } : {}),
        ...(names.dnsNames ? { dnsNames: names.dnsNames } : {}),
      });
    await expect(
      pki.issueCertificate(pat, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: csr({ commonName: 'api.payments.internal', dnsNames: ['api.payments.internal'] }),
      }),
    ).resolves.toMatchObject({ serialNumber: expect.any(String) });
    // One name outside the policy refuses the whole certificate.
    await expect(
      pki.issueCertificate(pat, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: csr({ dnsNames: ['api.payments.internal', 'admin.internal'] }),
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Validity is part of the decision too.
    await expect(
      pki.issueCertificate(pat, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: csr({ dnsNames: ['api.payments.internal'] }),
        validitySeconds: 7 * 86400,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Name constraints bind even the owner: `.internal` and `localhost` only.
    await expect(
      pki.issueCertificate(owner, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: csr({ dnsNames: ['www.example.com'] }),
      }),
    ).rejects.toMatchObject({ code: 'NAME_NOT_PERMITTED' });
    await expect(
      pki.issueCertificate(owner, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: createCertificateRequest({
          privateKey: keyPair().privateKey,
          uris: ['spiffe://other.test/x'],
        }),
      }),
    ).rejects.toMatchObject({ code: 'NAME_NOT_PERMITTED' });
    await expect(
      pki.issueCertificate(owner, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: createCertificateRequest({
          privateKey: keyPair().privateKey,
          uris: ['spiffe://acme.test/a', 'https://acme.test/b'],
        }),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Validity beyond the authority's maximum is refused outright.
    await expect(
      pki.issueCertificate(owner, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: csr({ dnsNames: ['a.internal'] }),
        validitySeconds: 400 * 86400,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('refuses requests whose signature does not prove the key', async () => {
    const f = await organizationFixture();
    const { owner, pki, issuing } = await authorities(f);
    const good = createCertificateRequest({
      privateKey: keyPair().privateKey,
      dnsNames: ['a.internal'],
    });
    const der = Buffer.from(good.replace(/-----[^-]+-----|\s/g, ''), 'base64');
    der[der.length - 5] ^= 0xff;
    const tampered = `-----BEGIN CERTIFICATE REQUEST-----\n${der.toString('base64')}\n-----END CERTIFICATE REQUEST-----\n`;
    await expect(
      pki.issueCertificate(owner, { tenantId: f.tenantId, authorityId: issuing.id, csr: tampered }),
    ).rejects.toMatchObject({ code: 'INVALID_CSR' });
    await expect(
      pki.issueCertificate(owner, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: 'not a csr',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CSR' });
    // RSA requests work too.
    await expect(
      pki.issueCertificate(owner, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: createCertificateRequest({
          privateKey: keyPair('rsa').privateKey,
          dnsNames: ['rsa.internal'],
        }),
      }),
    ).resolves.toMatchObject({ serialNumber: expect.any(String) });
  });

  it('gives workloads SPIFFE certificates for their own identity, revocable with a CRL', async () => {
    const f = await organizationFixture();
    const { owner, pki, issuing } = await authorities(f);
    const account = await f.iam.api.serviceAccounts.create(owner, {
      tenantId: f.tenantId,
      name: 'billing-job',
    });
    const role = await f.iam.api.roles.create(owner, {
      tenantId: f.tenantId,
      name: 'Workload identity',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['iam:pki:request'], resources: ['iam/pki/*'] }],
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
      name: 'job',
    });
    const workload = keyPair();
    const svid = await pki.requestCertificate(
      { token: key.token },
      {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: createCertificateRequest({
          privateKey: workload.privateKey,
          dnsNames: ['ignored.internal'],
        }),
      },
    );
    expect(svid.spiffeId).toBe(`spiffe://acme.test/service/${account.id}`);
    const certificate = new X509Certificate(svid.certificatePem);
    expect(certificate.subjectAltName).toBe(`URI:${svid.spiffeId}`);
    // An SVID has an empty subject (Node reports it as undefined) and names the workload only in its URI.
    expect(certificate.subject ?? '').toBe('');
    expect(Date.parse(certificate.validTo) - f.now()).toBeLessThanOrEqual(3600_000);
    expect(await f.iam.pki.verify(svid.certificatePem + svid.chainPem, { tenantId: f.tenantId })).toMatchObject({
      identityId: account.id,
      spiffeId: svid.spiffeId,
      tenantId: f.tenantId,
    });
    // Without iam:pki:request, a person gets nothing.
    await f.member('una');
    await expect(
      pki.requestCertificate(
        { token: (await f.signIn('una')).token },
        {
          tenantId: f.tenantId,
          authorityId: issuing.id,
          csr: createCertificateRequest({ privateKey: keyPair().privateKey }),
        },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // Revocation takes effect for verification at once, and lands on the CRL.
    const before = await pki.crl(owner, { tenantId: f.tenantId, authorityId: issuing.id });
    await pki.revokeCertificate(owner, {
      tenantId: f.tenantId,
      serialNumber: svid.serialNumber,
      reason: 'keyCompromise',
    });
    await expect(f.iam.pki.verify(svid.certificatePem, { tenantId: f.tenantId })).rejects.toMatchObject({
      code: 'CERTIFICATE_INVALID',
    });
    const after = await f.iam.pki.crl(issuing.id);
    expect(after.crlNumber).toBe(before.crlNumber + 1);
    expect(after.der.includes(Buffer.from(svid.serialNumber, 'hex'))).toBe(true);
    const response = await f.iam.pki.crlResponse(issuing.id);
    expect(response.headers.get('content-type')).toBe('application/pkix-crl');
    expect(Buffer.from(await response.arrayBuffer())).toEqual(after.der);
    // A cached CRL is served until something changes.
    expect((await f.iam.pki.crl(issuing.id)).crlNumber).toBe(after.crlNumber);
    expect((await f.iam.pki.crlResponse('missing')).status).toBe(404);
    const listed = await pki.listCertificates(owner, {
      tenantId: f.tenantId,
      identityId: account.id,
    });
    expect(listed.certificates).toMatchObject([
      { status: 'revoked', revocationReason: 'keyCompromise' },
    ]);
  });

  it('revokes subordinate authorities, pins CA keys, and stops with a disabled key', async () => {
    const f = await organizationFixture();
    const { owner, pki, root, issuing } = await authorities(f);
    const leaf = await pki.issueCertificate(owner, {
      tenantId: f.tenantId,
      authorityId: issuing.id,
      csr: createCertificateRequest({ privateKey: keyPair().privateKey, dnsNames: ['a.internal'] }),
    });
    // Rotating the CA's KMS key does not change the authority: its pinned version keeps signing.
    await f.iam.api.keys.rotate(owner, { tenantId: f.tenantId, keyId: issuing.keyId });
    const again = await pki.issueCertificate(owner, {
      tenantId: f.tenantId,
      authorityId: issuing.id,
      csr: createCertificateRequest({ privateKey: keyPair().privateKey, dnsNames: ['b.internal'] }),
    });
    expect(
      new X509Certificate(again.certificatePem).verify(
        new X509Certificate(issuing.certificatePem).publicKey,
      ),
    ).toBe(true);
    // Disabling the KMS key stops the authority.
    await f.iam.api.keys.disable(owner, { tenantId: f.tenantId, keyId: issuing.keyId });
    await expect(
      pki.issueCertificate(owner, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: createCertificateRequest({
          privateKey: keyPair().privateKey,
          dnsNames: ['c.internal'],
        }),
      }),
    ).rejects.toMatchObject({ code: 'KEY_STATE_INVALID' });
    await f.iam.api.keys.enable(owner, { tenantId: f.tenantId, keyId: issuing.keyId });
    // Revoking the intermediate's certificate at the root revokes the authority and everything it issued.
    const intermediate = (
      await pki.listCertificates(owner, { tenantId: f.tenantId, authorityId: root.id })
    ).certificates[0]!;
    await pki.revokeCertificate(owner, {
      tenantId: f.tenantId,
      serialNumber: intermediate.serialNumber,
    });
    expect(
      (await pki.getAuthority(owner, { tenantId: f.tenantId, authorityId: issuing.id })).state,
    ).toBe('revoked');
    await expect(f.iam.pki.verify(leaf.certificatePem, { tenantId: f.tenantId })).rejects.toMatchObject({
      code: 'CERTIFICATE_INVALID',
    });
    await expect(
      pki.issueCertificate(owner, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        csr: createCertificateRequest({
          privateKey: keyPair().privateKey,
          dnsNames: ['d.internal'],
        }),
      }),
    ).rejects.toMatchObject({ code: 'AUTHORITY_UNAVAILABLE' });
    await expect(
      pki.updateAuthority(owner, {
        tenantId: f.tenantId,
        authorityId: issuing.id,
        state: 'active',
      }),
    ).rejects.toMatchObject({ code: 'AUTHORITY_UNAVAILABLE' });
    // Audit: issuing and revoking are recorded with serial numbers, never keys.
    const events = await f.database.find('audit', { tenantId: f.tenantId });
    expect(
      events.some(
        (event) =>
          event.action === 'iam:pki:issue' &&
          (event.metadata as { serialNumber?: string })?.serialNumber === leaf.serialNumber,
      ),
    ).toBe(true);
    expect(JSON.stringify(events)).not.toMatch(/PRIVATE KEY/);
  });
});
