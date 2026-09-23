import { beforeAll, beforeEach, afterEach, describe, expect, it } from 'vitest';
import { createRequire } from 'node:module';
import { inflateRawSync } from 'node:zlib';
import { randomUUID } from 'node:crypto';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  createSamlService,
  createSamlCache,
  validateSamlEnvelope,
  type SamlConnection,
} from '@better-iam/saml';
import type { IamStore } from '@better-iam/core';
const require = createRequire(new URL('../packages/saml/package.json', import.meta.url));
const { generate } = require('selfsigned');
const { SignedXml } = require('xml-crypto');
const { encrypt } = require('xml-encryption');
const { DOMParser } = require('@xmldom/xmldom');
let keys: { private: string; cert: string; public: string };
const assertionNamespace = 'urn:oasis:names:tc:SAML:2.0:assertion';
const protocolNamespace = 'urn:oasis:names:tc:SAML:2.0:protocol';
beforeAll(async () => {
  keys = await generate([{ name: 'commonName', value: 'test.idp' }], {
    keySize: 2048,
    algorithm: 'sha256',
  });
});
function sign(xml: string, type: 'Assertion' | 'Response') {
  const signer = new SignedXml({
    privateKey: keys.private,
    publicCert: keys.cert,
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
function makeResponse(
  requestId: string,
  changes: { issuer?: string; audience?: string; destination?: string; expires?: string } = {},
) {
  const now = new Date().toISOString();
  const expires = changes.expires ?? new Date(Date.now() + 120000).toISOString();
  const assertion = `<saml:Assertion xmlns:saml="${assertionNamespace}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${now}"><saml:Issuer>${changes.issuer ?? 'https://idp.test'}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">stable-user-subject</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${requestId}" Recipient="https://iam.test/saml/callback" NotOnOrAfter="${expires}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${new Date(Date.now() - 1000).toISOString()}" NotOnOrAfter="${expires}"><saml:AudienceRestriction><saml:Audience>${changes.audience ?? 'https://iam.test/sp'}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now}" SessionIndex="session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>same@example.test</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;
  const signedAssertion = sign(assertion, 'Assertion');
  const response = `<samlp:Response xmlns:samlp="${protocolNamespace}" xmlns:saml="${assertionNamespace}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${now}" Destination="${changes.destination ?? 'https://iam.test/saml/callback'}" InResponseTo="${requestId}"><saml:Issuer>https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${signedAssertion}</samlp:Response>`;
  return sign(response, 'Response');
}
describe('SAML SP security and shared replay state', () => {
  let store: IamStore;
  let service: ReturnType<typeof createSamlService>;
  let completed: unknown[];
  beforeEach(async () => {
    store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
    completed = [];
    await store.transaction(async (tx) => {
      await tx.insert('tenants', {
        id: 'a',
        tenantId: 'a',
        name: 'A',
        type: 'organization',
        parentId: null,
        status: 'active',
        createdAt: Date.now(),
      });
    });
    const connection: SamlConnection = {
      id: 'enterprise',
      tenantId: 'a',
      entryPoint: 'https://idp.test/login',
      idpIssuer: 'https://idp.test',
      idpCertificates: [keys.cert],
      entityId: 'https://iam.test/sp',
      callbackUrl: 'https://iam.test/saml/callback',
      privateKey: keys.private,
      publicCertificate: keys.cert,
      mapAttributes: (profile) =>
        typeof profile.email === 'string' ? { mail: profile.email } : undefined,
    };
    service = createSamlService({
      store,
      connections: [connection],
      completeAuthentication: async (input) => {
        completed.push(input);
        return { authenticated: true };
      },
    });
  });
  afterEach(async () => {
    await store.close();
  });
  async function begin() {
    const result = await service.begin('enterprise');
    const xml = inflateRawSync(
      Buffer.from(new URL(result.url).searchParams.get('SAMLRequest')!, 'base64'),
    ).toString();
    const requestId = /\bID="([^"]+)"/.exec(xml)![1]!;
    return { ...result, requestId };
  }
  it('validates real signed responses and rejects concurrent replay', async () => {
    const state = await begin();
    const input = {
      relayState: state.relayState,
      binding: state.binding,
      samlResponse: Buffer.from(makeResponse(state.requestId)).toString('base64'),
    };
    const results = await Promise.allSettled([
      service.callback('enterprise', input),
      service.callback('enterprise', input),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(completed).toEqual([
      {
        tenantId: 'a',
        providerId: 'enterprise',
        issuer: 'https://idp.test',
        subject: 'stable-user-subject',
        email: 'same@example.test',
        emailVerified: false,
        name: undefined,
        attributes: { mail: 'same@example.test' },
      },
    ]);
    expect(await store.find('samlRequests')).toHaveLength(0);
    expect(await store.find('samlRelays')).toHaveLength(0);
  });
  it('requires browser binding and rejects forged or modified assertions', async () => {
    const state = await begin();
    const xml = makeResponse(state.requestId);
    const input = {
      relayState: state.relayState,
      binding: state.binding,
      samlResponse: Buffer.from(xml).toString('base64'),
    };
    await expect(service.callback('enterprise', { ...input, binding: 'forged' })).rejects.toThrow();
    await expect(
      service.callback('enterprise', {
        ...input,
        samlResponse: Buffer.from(
          xml.replace('same@example.test', 'attacker@example.test'),
        ).toString('base64'),
      }),
    ).rejects.toThrow();
    expect(completed).toHaveLength(0);
    await expect(service.callback('enterprise', input)).resolves.toEqual({ authenticated: true });
  });
  it('rejects wrong destination, issuer, audience and expired assertion', async () => {
    for (const change of [
      { destination: 'https://evil.test/callback' },
      { issuer: 'https://evil.test' },
      { audience: 'https://another-sp.test' },
      { expires: new Date(Date.now() - 300000).toISOString() },
    ]) {
      const state = await begin();
      await expect(
        service.callback('enterprise', {
          relayState: state.relayState,
          binding: state.binding,
          samlResponse: Buffer.from(makeResponse(state.requestId, change)).toString('base64'),
        }),
      ).rejects.toThrow();
    }
    expect(completed).toHaveLength(0);
  });
  it('does not accept unsolicited SAML and scopes cache to the connection', async () => {
    await expect(
      service.callback('enterprise', {
        relayState: 'unsolicited',
        binding: 'unsolicited',
        samlResponse: Buffer.from(makeResponse('_unsolicited')).toString('base64'),
      }),
    ).rejects.toThrow();
    const a = createSamlCache(store, 'a', 'connection-one');
    const b = createSamlCache(store, 'a', 'connection-two');
    await a.saveAsync('_request', 'now');
    expect(await b.getAsync('_request')).toBeNull();
    expect(await a.getAsync('_request')).toBe('now');
    await a.removeAsync('_request');
    expect(await a.getAsync('_request')).toBeNull();
  });
  it('decrypts and verifies encrypted signed assertions and supports certificate rollover', async () => {
    const old = await generate([{ name: 'commonName', value: 'old.idp' }], {
      keySize: 2048,
      algorithm: 'sha256',
    });
    service = createSamlService({
      store,
      connections: [
        {
          id: 'enterprise',
          tenantId: 'a',
          entryPoint: 'https://idp.test/login',
          idpIssuer: 'https://idp.test',
          idpCertificates: [old.cert, keys.cert],
          entityId: 'https://iam.test/sp',
          callbackUrl: 'https://iam.test/saml/callback',
          privateKey: keys.private,
          publicCertificate: keys.cert,
          decryptionPrivateKey: keys.private,
          decryptionCertificate: keys.cert,
          requireEncryptedAssertions: true,
        },
      ],
      completeAuthentication: async (input) => {
        completed.push(input);
        return { authenticated: true };
      },
    });
    const state = await begin();
    const document = new DOMParser().parseFromString(makeResponse(state.requestId), 'text/xml');
    const root = document.documentElement;
    const assertion = document.getElementsByTagNameNS(assertionNamespace, 'Assertion').item(0);
    const encrypted = await new Promise<string>((resolve, reject) =>
      encrypt(
        assertion.toString(),
        {
          rsa_pub: keys.public,
          pem: keys.cert,
          encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
          keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
          disallowEncryptionWithInsecureAlgorithm: true,
        },
        (error: Error | null, value: string) => (error ? reject(error) : resolve(value)),
      ),
    );
    root.replaceChild(
      document.importNode(
        new DOMParser().parseFromString(
          `<saml:EncryptedAssertion xmlns:saml="${assertionNamespace}">${encrypted}</saml:EncryptedAssertion>`,
          'text/xml',
        ).documentElement,
        true,
      ),
      assertion,
    );
    for (const child of Array.from(root.childNodes) as { localName: string }[])
      if (child.localName === 'Signature') root.removeChild(child);
    const xml = sign(root.toString(), 'Response');
    await expect(
      service.callback('enterprise', {
        relayState: state.relayState,
        binding: state.binding,
        samlResponse: Buffer.from(xml).toString('base64'),
      }),
    ).resolves.toEqual({ authenticated: true });
    expect(completed).toHaveLength(1);
  });
  it('generates signed metadata with rollover support and rejects XML entities', () => {
    const metadata = service.metadata('enterprise');
    expect(metadata).toContain('Signature');
    expect(metadata).toContain('https://iam.test/saml/callback');
    expect(metadata).toContain('WantAssertionsSigned="true"');
    expect(() =>
      validateSamlEnvelope(
        '<!DOCTYPE a [<!ENTITY x SYSTEM "file:///secrets">]><a/>',
        'https://iam.test/saml/callback',
        '_request',
      ),
    ).toThrow();
    expect(() =>
      validateSamlEnvelope(
        makeResponse('_request'),
        'https://iam.test/saml/callback',
        '_request',
        true,
      ),
    ).toThrow('encrypted');
  });
});
