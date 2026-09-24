import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createSamlService } from '@better-iam/saml';
import { closeFixtures, organizationFixture } from './support/organization.js';

/**
 * Accounts linked through one sign-in provider must stay out of reach of every other trust anchor: a SAML connection
 * given another provider's ID, a connection deleted and recreated under the same ID, or an administrator who swaps a
 * connection's IdP certificates to sign assertions for the owner.
 */

const require = createRequire(new URL('../packages/saml/package.json', import.meta.url));
const { generate } = require('selfsigned');
const { SignedXml } = require('xml-crypto');

const assertionNamespace = 'urn:oasis:names:tc:SAML:2.0:assertion';
const protocolNamespace = 'urn:oasis:names:tc:SAML:2.0:protocol';
type KeyPair = { private: string; cert: string };
let idp: KeyPair;
let attacker: KeyPair;
let sp: KeyPair;
beforeAll(async () => {
  const options = { keySize: 2048, algorithm: 'sha256' };
  idp = await generate([{ name: 'commonName', value: 'idp.test' }], options);
  attacker = await generate([{ name: 'commonName', value: 'attacker.test' }], options);
  sp = await generate([{ name: 'commonName', value: 'iam.test' }], options);
});
afterEach(closeFixtures);

function sign(xml: string, type: 'Assertion' | 'Response', key: KeyPair) {
  const signer = new SignedXml({
    privateKey: key.private,
    publicCert: key.cert,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  signer.addReference({
    xpath: `//*[local-name()='${type}']`,
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  signer.computeSignature(xml, {
    location: {
      reference: `//*[local-name()='${type}']/*[local-name()='Issuer']`,
      action: 'after',
    },
  });
  return signer.getSignedXml() as string;
}

/** A signed, unsolicited (IdP-initiated) response. */
function unsolicited(
  connection: { acsUrl: string; entityId: string },
  key: KeyPair,
  claims: { issuer: string; nameId: string; email?: string },
) {
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + 120000).toISOString();
  const email = claims.email
    ? `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${claims.email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`
    : '';
  const assertion = `<saml:Assertion xmlns:saml="${assertionNamespace}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${now}"><saml:Issuer>${claims.issuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${claims.nameId}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="${connection.acsUrl}" NotOnOrAfter="${expires}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${new Date(Date.now() - 1000).toISOString()}" NotOnOrAfter="${expires}"><saml:AudienceRestriction><saml:Audience>${connection.entityId}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now}" SessionIndex="session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>${email}</saml:Assertion>`;
  const document = `<samlp:Response xmlns:samlp="${protocolNamespace}" xmlns:saml="${assertionNamespace}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${now}" Destination="${connection.acsUrl}"><saml:Issuer>${claims.issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${sign(assertion, 'Assertion', key)}</samlp:Response>`;
  return Buffer.from(sign(document, 'Response', key)).toString('base64');
}

async function setup() {
  const f = await organizationFixture();
  const service = createSamlService({
    ...f.iam.protocolHost,
    serviceProvider: {
      baseUrl: 'https://iam.test',
      privateKey: sp.private,
      publicCertificate: sp.cert,
    },
  });
  const signedInAs = async (result: unknown) =>
    (await f.iam.api.auth.getSession({ token: (result as { token: string }).token })).identity.id;
  return { ...f, service, signedInAs };
}

const connectionInput = (certificate: string, issuer = 'https://idp.test') => ({
  name: 'Acme IdP',
  entryPoint: 'https://idp.test/login',
  idpIssuer: issuer,
  idpCertificates: [certificate],
  trustedEmailDomains: ['acme.test'],
  allowIdpInitiated: true,
});

describe('claims about grants', () => {
  it('lists only roles in force: not an eligible binding before it is activated, nor one not started', async () => {
    const f = await setup();
    const alice = await f.member('alice');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Deployer',
      permissions: ['documents:write'],
    });
    const later = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Starts later',
      permissions: ['documents:read'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: later.id,
      subjectType: 'identity',
      subjectId: alice.id,
      startsAt: f.now() + 86400000,
    });
    expect((await f.iam.protocolHost.liveGrants(alice.id, f.tenantId)).roleIds).toEqual([]);
  });
});

describe('federated enrollment', () => {
  it('never creates a platform (root tenant) account from a sign-in elsewhere', async () => {
    const f = await setup();
    await expect(
      f.iam.protocolHost.completeAuthentication({
        tenantId: f.root.tenant.id,
        providerId: 'google',
        issuer: 'https://accounts.google.com',
        subject: 'stranger-1',
        email: 'stranger@gmail.example',
        emailVerified: true,
      }),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
    // Organizations still enroll verified addresses as documented.
    await expect(
      f.iam.protocolHost.completeAuthentication({
        tenantId: f.tenantId,
        providerId: 'google',
        issuer: 'https://accounts.google.com',
        subject: 'new-member-1',
        email: 'new.member@acme.test',
        emailVerified: true,
      }),
    ).resolves.toBeDefined();
  });
});

describe('federated account links', () => {
  it('never lets a SAML connection reach accounts linked through another provider with the same ID', async () => {
    const f = await setup();
    // The owner signs in with GitHub through a deployment OAuth connection named "github".
    await f.database.transaction(async (tx) => {
      await tx.insert('externalIdentities', {
        id: randomUUID(),
        tenantId: f.tenantId,
        uniqueKey: JSON.stringify(['github', 'https://github.com', '1234']),
        identityId: f.ownerId,
        providerId: 'github',
        issuer: 'https://github.com',
        subject: '1234',
      });
    });
    const owner = await f.ownerSignIn();
    const connection = await f.service.createConnection(owner, {
      tenantId: f.tenantId,
      id: 'github',
      ...connectionInput(attacker.cert, 'https://github.com'),
    });
    await expect(
      f.service.idpInitiated(
        'github',
        unsolicited(connection, attacker, {
          issuer: 'https://github.com',
          nameId: '1234',
          email: 'owner@acme.test',
        }),
      ),
    ).rejects.toMatchObject({ code: 'ACCOUNT_LINK_REQUIRED' });
  });

  it('unlinks accounts when a connection is deleted, so a recreated one with the same ID starts over', async () => {
    const f = await setup();
    const owner = await f.ownerSignIn();
    const first = await f.service.createConnection(owner, {
      tenantId: f.tenantId,
      id: 'acme',
      ...connectionInput(idp.cert),
    });
    const claims = { issuer: 'https://idp.test', nameId: 'employee-7', email: 'emp7@acme.test' };
    const employee = await f.signedInAs(
      await f.service.idpInitiated('acme', unsolicited(first, idp, claims)),
    );
    expect(await f.signedInAs(await f.service.idpInitiated('acme', unsolicited(first, idp, claims)))).toBe(
      employee,
    );
    await f.service.deleteConnection(owner, { tenantId: f.tenantId, connectionId: 'acme' });
    expect(await f.database.find('externalIdentities', { tenantId: f.tenantId })).toEqual([]);
    const second = await f.service.createConnection(owner, {
      tenantId: f.tenantId,
      id: 'acme',
      ...connectionInput(attacker.cert),
    });
    await expect(
      f.service.idpInitiated('acme', unsolicited(second, attacker, claims)),
    ).rejects.toMatchObject({ code: 'ACCOUNT_LINK_REQUIRED' });
  });

  it('lets only an owner, recently signed in, change what a connection an owner signs in through trusts', async () => {
    const f = await setup();
    const owner = await f.ownerSignIn();
    const connection = await f.service.createConnection(owner, {
      tenantId: f.tenantId,
      id: 'acme',
      ...connectionInput(idp.cert),
    });
    const record = (await f.database.get('samlConnections', 'acme')) as { providerKey: string };
    await f.database.transaction(async (tx) => {
      await tx.insert('externalIdentities', {
        id: randomUUID(),
        tenantId: f.tenantId,
        uniqueKey: JSON.stringify([record.providerKey, 'https://idp.test', 'owner-at-idp']),
        identityId: f.ownerId,
        providerId: record.providerKey,
        issuer: 'https://idp.test',
        subject: 'owner-at-idp',
      });
    });
    // A delegated administrator of SAML connections.
    const dana = await f.member('dana');
    const role = await f.iam.api.roles.create(owner, {
      tenantId: f.tenantId,
      name: 'SSO admin',
      permissions: [
        'iam:saml:connections:read',
        'iam:saml:connections:update',
        'iam:saml:connections:create',
      ],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: dana.id,
    });
    const danaSession = { token: (await f.signIn('dana')).token };
    const swap = { idpCertificates: [idp.cert, attacker.cert] };
    await expect(
      f.service.updateConnection(danaSession, {
        tenantId: f.tenantId,
        connectionId: 'acme',
        ...swap,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    for (const change of [
      { idpIssuer: 'https://evil.test' },
      { trustedEmailDomains: ['acme.test', 'evil.test'] },
    ])
      await expect(
        f.service.updateConnection(danaSession, {
          tenantId: f.tenantId,
          connectionId: 'acme',
          ...change,
        }),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Nothing that widens trust went through; the owner cannot be signed in with the attacker's key.
    await expect(
      f.service.idpInitiated(
        'acme',
        unsolicited(connection, attacker, { issuer: 'https://idp.test', nameId: 'owner-at-idp' }),
      ),
    ).rejects.toBeDefined();
    // Renaming changes no trust, so the delegated administrator may.
    await expect(
      f.service.updateConnection(danaSession, {
        tenantId: f.tenantId,
        connectionId: 'acme',
        name: 'Acme SSO',
      }),
    ).resolves.toMatchObject({ name: 'Acme SSO' });
    // The owner may, but only with a recent sign-in.
    f.advance(10 * 60_000);
    await expect(
      f.service.updateConnection(owner, { tenantId: f.tenantId, connectionId: 'acme', ...swap }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    const fresh = await f.ownerSignIn();
    await expect(
      f.service.updateConnection(fresh, { tenantId: f.tenantId, connectionId: 'acme', ...swap }),
    ).resolves.toMatchObject({ certificates: expect.any(Array) });
  });
});
