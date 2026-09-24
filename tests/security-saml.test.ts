import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { inflateRawSync } from 'node:zlib';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createSamlService } from '@better-iam/saml';
import { IamError, type AuthenticatedPrincipal, type IamStore } from '@better-iam/core';

/**
 * SAML responses: an IdP-initiated assertion is accepted only while it is fresh (not forever once its single-use
 * record lapses), and `requireEncryptedAssertions` is judged where assertions are actually read.
 */

const require = createRequire(new URL('../packages/saml/package.json', import.meta.url));
const { generate } = require('selfsigned');
const { SignedXml } = require('xml-crypto');

const assertionNamespace = 'urn:oasis:names:tc:SAML:2.0:assertion';
const protocolNamespace = 'urn:oasis:names:tc:SAML:2.0:protocol';
let idp: { private: string; cert: string };
let sp: { private: string; cert: string };
beforeAll(async () => {
  const options = { keySize: 2048, algorithm: 'sha256' };
  idp = await generate([{ name: 'commonName', value: 'idp.test' }], options);
  sp = await generate([{ name: 'commonName', value: 'iam.test' }], options);
});
const bare = (pem: string) => pem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, '');
const metadata = (cert: string) =>
  `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.test"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${bare(cert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/login"/></md:IDPSSODescriptor></md:EntityDescriptor>`;

function sign(xml: string, type: 'Assertion' | 'Response') {
  const signer = new SignedXml({
    privateKey: idp.private,
    publicCert: idp.cert,
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

function response(options: {
  requestId: string | null;
  acs: string;
  audience: string;
  issuedAgoMs?: number;
  conditionTimes?: boolean;
  injectEncrypted?: boolean;
}) {
  const answers = options.requestId === null ? '' : ` InResponseTo="${options.requestId}"`;
  const issued = new Date(Date.now() - (options.issuedAgoMs ?? 0));
  const instant = issued.toISOString();
  const expires = new Date(issued.getTime() + 120000).toISOString();
  const conditions =
    options.conditionTimes === false
      ? '<saml:Conditions>'
      : `<saml:Conditions NotBefore="${new Date(issued.getTime() - 1000).toISOString()}" NotOnOrAfter="${expires}">`;
  const assertion = `<saml:Assertion xmlns:saml="${assertionNamespace}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${instant}"><saml:Issuer>https://idp.test</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">employee-42</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${answers} Recipient="${options.acs}" NotOnOrAfter="${expires}"/></saml:SubjectConfirmation></saml:Subject>${conditions}<saml:AudienceRestriction><saml:Audience>${options.audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${instant}" SessionIndex="s"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>`;
  const document = `<samlp:Response xmlns:samlp="${protocolNamespace}" xmlns:saml="${assertionNamespace}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${instant}" Destination="${options.acs}"${answers}><saml:Issuer>https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${sign(assertion, 'Assertion')}</samlp:Response>`;
  let signed = sign(document, 'Response');
  if (options.injectEncrypted)
    // The Response signature is the first </Signature>; the enveloped transform excludes its contents.
    signed = signed.replace(
      '</Signature>',
      `<Object><saml:EncryptedAssertion xmlns:saml="${assertionNamespace}"/></Object></Signature>`,
    );
  return Buffer.from(signed).toString('base64');
}

describe('SAML response checks', () => {
  let store: IamStore;
  let completed: unknown[];
  let service: ReturnType<typeof createSamlService>;
  beforeEach(async () => {
    store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
    completed = [];
    await store.transaction(async (tx) => {
      await tx.insert('tenants', {
        id: 'a',
        tenantId: 'a',
        name: 'a',
        type: 'organization',
        parentId: null,
        status: 'active',
        createdAt: Date.now(),
      });
    });
    const principal = {
      identity: { id: 'admin-a', tenantId: 'a' },
      session: { id: 's', kind: 'user', authenticatedAt: Date.now() },
    } as unknown as AuthenticatedPrincipal;
    service = createSamlService({
      store,
      serviceProvider: {
        baseUrl: 'https://iam.test',
        privateKey: sp.private,
        publicCertificate: sp.cert,
        decryptionPrivateKey: sp.private,
        decryptionCertificate: sp.cert,
      },
      authenticate: async () => principal,
      authorize: async (credential) => {
        if (credential.token !== 'admin') throw new IamError('ACCESS_DENIED', 'no', 403);
      },
      completeAuthentication: async (input) => {
        completed.push(input);
        return { signedIn: input.subject };
      },
    });
  });
  afterEach(async () => {
    vi.useRealTimers();
    await store.close();
  });
  const admin = { token: 'admin' };

  it('accepts an IdP-initiated assertion without Conditions times only while it is fresh, and once', async () => {
    const connection = await service.createConnection(admin, {
      tenantId: 'a',
      id: 'portal',
      name: 'Portal',
      metadataXml: metadata(idp.cert),
      allowIdpInitiated: true,
    });
    const post = (samlResponse: string) =>
      service.handler(
        new Request('https://iam.test/saml/portal/acs', {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ SAMLResponse: samlResponse }),
        }),
      );
    const timeless = { acs: connection.acsUrl, audience: connection.entityId, conditionTimes: false };
    // A day-old one is refused outright.
    expect(
      (await post(response({ requestId: null, ...timeless, issuedAgoMs: 86400000 })))?.status,
    ).toBe(401);
    // A fresh one works once; replaying it fails now, after the single-use record lapses, and a month later.
    const fresh = response({ requestId: null, ...timeless });
    expect((await post(fresh))?.status).toBe(200);
    expect((await post(fresh))?.status).toBe(401);
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 11 * 60_000);
    expect((await post(fresh))?.status).toBe(401);
    vi.setSystemTime(Date.now() + 30 * 86400_000);
    expect((await post(fresh))?.status).toBe(401);
    expect(completed).toHaveLength(1);
  });

  it('is not fooled by an empty EncryptedAssertion hidden in the signature when encryption is required', async () => {
    const connection = await service.createConnection(admin, {
      tenantId: 'a',
      id: 'enc',
      name: 'Enc',
      metadataXml: metadata(idp.cert),
      requireEncryptedAssertions: true,
    });
    const begin = async () => {
      const state = await service.begin('enc');
      const xml = inflateRawSync(
        Buffer.from(new URL(state.url).searchParams.get('SAMLRequest')!, 'base64'),
      ).toString();
      return { ...state, requestId: /\bID="([^"]+)"/.exec(xml)![1]! };
    };
    for (const injectEncrypted of [false, true]) {
      const state = await begin();
      await expect(
        service.callback('enc', {
          relayState: state.relayState,
          binding: state.binding,
          samlResponse: response({
            requestId: state.requestId,
            acs: connection.acsUrl,
            audience: connection.entityId,
            injectEncrypted,
          }),
        }),
      ).rejects.toThrow(/encrypted assertion is required/);
    }
    expect(completed).toEqual([]);
  });
});
