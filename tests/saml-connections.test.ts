import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createRequire } from 'node:module';
import { inflateRawSync } from 'node:zlib';
import { randomUUID } from 'node:crypto';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createSamlService, parseIdpMetadata, type SamlConnection } from '@better-iam/saml';
import { IamError, type AuthenticatedPrincipal, type IamStore } from '@better-iam/core';
const require = createRequire(new URL('../packages/saml/package.json', import.meta.url));
const { generate } = require('selfsigned');
const { SignedXml } = require('xml-crypto');

const assertionNamespace = 'urn:oasis:names:tc:SAML:2.0:assertion';
const protocolNamespace = 'urn:oasis:names:tc:SAML:2.0:protocol';
let idp: { private: string; cert: string };
let next: { private: string; cert: string };
let sp: { private: string; cert: string };
beforeAll(async () => {
  const options = { keySize: 2048, algorithm: 'sha256' };
  idp = await generate([{ name: 'commonName', value: 'idp.test' }], options);
  next = await generate([{ name: 'commonName', value: 'next.idp.test' }], options);
  sp = await generate([{ name: 'commonName', value: 'iam.test' }], options);
});
const bare = (pem: string) => pem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, '');

function metadata(certificates: string[], extra = '') {
  const keys = certificates
    .map(
      (cert) =>
        `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${bare(cert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`,
    )
    .join('');
  return `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.test"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${keys}${extra}<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/logout"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.test/post"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/login"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
}

function sign(xml: string, type: 'Assertion' | 'Response', key = idp) {
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

/** A signed IdP response for a managed connection's ACS URL and SP entity ID. */
function response(requestId: string | null, acs: string, audience: string, key = idp) {
  const answers = requestId === null ? '' : ` InResponseTo="${requestId}"`;
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + 120000).toISOString();
  const assertion = `<saml:Assertion xmlns:saml="${assertionNamespace}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${now}"><saml:Issuer>https://idp.test</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">employee-42</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${answers} Recipient="${acs}" NotOnOrAfter="${expires}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${new Date(Date.now() - 1000).toISOString()}" NotOnOrAfter="${expires}"><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now}" SessionIndex="session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>ada@acme.test</saml:AttributeValue></saml:Attribute><saml:Attribute Name="dept"><saml:AttributeValue>finance</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;
  const document = `<samlp:Response xmlns:samlp="${protocolNamespace}" xmlns:saml="${assertionNamespace}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${now}" Destination="${acs}"${answers}><saml:Issuer>https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${sign(assertion, 'Assertion', key)}</samlp:Response>`;
  return Buffer.from(sign(document, 'Response', key)).toString('base64');
}

describe('tenant-managed SAML connections', () => {
  let store: IamStore;
  let completed: Record<string, unknown>[];
  let service: ReturnType<typeof createSamlService>;
  const denied: string[] = [];
  beforeEach(async () => {
    store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
    completed = [];
    denied.length = 0;
    await store.transaction(async (tx) => {
      for (const id of ['a', 'b'])
        await tx.insert('tenants', {
          id,
          tenantId: id,
          name: id,
          type: 'organization',
          parentId: null,
          status: 'active',
          createdAt: Date.now(),
        });
    });
    const principal = {
      identity: { id: 'admin-a', tenantId: 'a' },
      session: { id: 'session', kind: 'user', authenticatedAt: Date.now() },
    } as unknown as AuthenticatedPrincipal;
    const configured: SamlConnection = {
      id: 'static',
      tenantId: 'a',
      entryPoint: 'https://idp.test/login',
      idpIssuer: 'https://idp.test',
      idpCertificates: [idp.cert],
      entityId: 'https://iam.test/static',
      callbackUrl: 'https://iam.test/static/callback',
      privateKey: sp.private,
      publicCertificate: sp.cert,
    };
    service = createSamlService({
      store,
      connections: [configured],
      serviceProvider: {
        baseUrl: 'https://iam.test',
        privateKey: sp.private,
        publicCertificate: sp.cert,
      },
      authenticate: async () => principal,
      authorize: async (credential, action) => {
        if (credential.token !== 'admin') {
          denied.push(action);
          throw new IamError('ACCESS_DENIED', 'Forbidden', 403);
        }
      },
      completeAuthentication: async (input) => {
        completed.push(input);
        return { signedIn: input.subject };
      },
    });
  });
  afterEach(async () => {
    await store.close();
  });
  const admin = { token: 'admin' };

  it('parses IdP metadata: redirect endpoints and signing certificates only', () => {
    const parsed = parseIdpMetadata(
      metadata(
        [idp.cert, next.cert],
        `<md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${bare(sp.cert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`,
      ),
    );
    expect(parsed).toMatchObject({
      entityId: 'https://idp.test',
      entryPoint: 'https://idp.test/login',
      singleLogoutUrl: 'https://idp.test/logout',
    });
    expect(parsed.certificates).toHaveLength(2);
    expect(parsed.certificates[0]).toContain('-----BEGIN CERTIFICATE-----');
    expect(() => parseIdpMetadata('<!DOCTYPE x [<!ENTITY a "b">]><x/>')).toThrow(/Unsafe/);
    expect(() =>
      parseIdpMetadata(
        metadata([idp.cert]).replace(
          /HTTP-Redirect" Location="https:\/\/idp.test\/login/,
          'SOAP" Location="https://idp.test/login',
        ),
      ),
    ).toThrow(/HTTP-Redirect/);
    expect(() =>
      parseIdpMetadata(metadata([idp.cert]).replace(bare(idp.cert), 'bm90IGEgY2VydA==')),
    ).toThrow(/X.509/);
  });

  it('creates a connection from metadata and signs members in through its ACS URL', async () => {
    const created = await service.createConnection(admin, {
      tenantId: 'a',
      id: 'acme',
      name: 'Acme Okta',
      metadataXml: metadata([idp.cert]),
      trustedEmailDomains: ['ACME.test'],
      attributeMapping: { department: 'dept' },
    });
    expect(created).toMatchObject({
      id: 'acme',
      tenantId: 'a',
      name: 'Acme Okta',
      enabled: true,
      entryPoint: 'https://idp.test/login',
      idpIssuer: 'https://idp.test',
      trustedEmailDomains: ['acme.test'],
      entityId: 'https://iam.test/saml/acme/metadata',
      acsUrl: 'https://iam.test/saml/acme/acs',
      loginUrl: 'https://iam.test/saml/acme/login',
    });
    expect(created.certificates[0]).toMatchObject({ expired: false });
    expect(created.certificates[0]!.fingerprint256).toMatch(/^[0-9A-F:]+$/);

    // SP metadata is served for the managed connection.
    const served = await service.handler(new Request('https://iam.test/saml/acme/metadata'));
    expect(served?.status).toBe(200);
    expect(await served!.text()).toContain('https://iam.test/saml/acme/acs');
    expect(await service.getMetadata('acme')).toContain('WantAssertionsSigned="true"');

    // Browser flow: login redirect sets the binding cookie, the IdP posts back to the ACS URL.
    const login = await service.handler(new Request('https://iam.test/saml/acme/login'));
    expect(login?.status).toBe(302);
    const location = new URL(login!.headers.get('location')!);
    expect(location.origin + location.pathname).toBe('https://idp.test/login');
    const request = inflateRawSync(
      Buffer.from(location.searchParams.get('SAMLRequest')!, 'base64'),
    ).toString();
    const requestId = /\bID="([^"]+)"/.exec(request)![1]!;
    expect(request).toContain('AssertionConsumerServiceURL="https://iam.test/saml/acme/acs"');
    const cookie = login!.headers.get('set-cookie')!.split(';')[0]!;
    const posted = await service.handler(
      new Request('https://iam.test/saml/acme/acs', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
        body: new URLSearchParams({
          SAMLResponse: response(requestId, created.acsUrl, created.entityId),
          RelayState: location.searchParams.get('RelayState')!,
        }),
      }),
    );
    expect(posted?.status).toBe(200);
    expect(await posted!.json()).toEqual({ signedIn: 'employee-42' });
    expect(completed).toEqual([
      expect.objectContaining({
        tenantId: 'a',
        // Links are keyed by a random provider key of this very connection, never by its reusable ID.
        providerId: expect.stringMatching(/^saml:acme:[A-Za-z0-9_-]{16}$/),
        issuer: 'https://idp.test',
        subject: 'employee-42',
        email: 'ada@acme.test',
        emailVerified: true,
        attributes: { department: 'finance' },
      }),
    ]);
    const actions = (await store.find('audit', { tenantId: 'a' })).map((event) => event.action);
    expect(actions).toContain('iam:saml:CreateConnection');
  });

  it('rolls over certificates, disables, and deletes connections within the tenant', async () => {
    await service.createConnection(admin, {
      tenantId: 'a',
      id: 'acme',
      name: 'Acme',
      entryPoint: 'https://idp.test/login',
      idpIssuer: 'https://idp.test',
      idpCertificates: [idp.cert],
    });
    const begin = async () => {
      const state = await service.begin('acme');
      const xml = inflateRawSync(
        Buffer.from(new URL(state.url).searchParams.get('SAMLRequest')!, 'base64'),
      ).toString();
      return { ...state, requestId: /\bID="([^"]+)"/.exec(xml)![1]! };
    };
    const acs = 'https://iam.test/saml/acme/acs';
    const audience = 'https://iam.test/saml/acme/metadata';
    // An assertion signed by the next IdP key fails until the rollover lists it.
    let state = await begin();
    await expect(
      service.callback('acme', {
        relayState: state.relayState,
        binding: state.binding,
        samlResponse: response(state.requestId, acs, audience, next),
      }),
    ).rejects.toThrow();
    const rolled = await service.updateConnection(admin, {
      tenantId: 'a',
      connectionId: 'acme',
      idpCertificates: [idp.cert, next.cert],
    });
    expect(rolled.certificates).toHaveLength(2);
    state = await begin();
    await expect(
      service.callback('acme', {
        relayState: state.relayState,
        binding: state.binding,
        samlResponse: response(state.requestId, acs, audience, next),
      }),
    ).resolves.toEqual({ signedIn: 'employee-42' });

    // Disabled connections stop new sign-ins; listing still shows them.
    await service.updateConnection(admin, { tenantId: 'a', connectionId: 'acme', enabled: false });
    await expect(service.begin('acme')).rejects.toMatchObject({ status: 404 });
    expect((await service.handler(new Request('https://iam.test/saml/acme/login')))?.status).toBe(
      404,
    );
    expect(await service.listConnections(admin, { tenantId: 'a' })).toEqual([
      expect.objectContaining({ id: 'acme', enabled: false }),
    ]);

    // Other tenants and callers without permission see nothing.
    await expect(
      service.getConnection(admin, { tenantId: 'b', connectionId: 'acme' }),
    ).rejects.toMatchObject({ status: 404 });
    await expect(
      service.updateConnection(
        { token: 'member' },
        { tenantId: 'a', connectionId: 'acme', name: 'Mine' },
      ),
    ).rejects.toMatchObject({ status: 403 });
    expect(denied).toContain('iam:saml:connections:update');

    await service.deleteConnection(admin, { tenantId: 'a', connectionId: 'acme' });
    expect(await service.listConnections(admin, { tenantId: 'a' })).toEqual([]);
    await expect(service.getMetadata('acme')).rejects.toMatchObject({ status: 404 });
    const actions = (await store.find('audit', { tenantId: 'a' })).map((event) => event.action);
    expect(actions).toEqual(
      expect.arrayContaining([
        'iam:saml:CreateConnection',
        'iam:saml:UpdateConnection',
        'iam:saml:DeleteConnection',
      ]),
    );
  });

  it('accepts IdP-initiated sign-in only when enabled, once per assertion', async () => {
    const created = await service.createConnection(admin, {
      tenantId: 'a',
      id: 'portal',
      name: 'Portal',
      metadataXml: metadata([idp.cert]),
      allowIdpInitiated: true,
    });
    expect(created.allowIdpInitiated).toBe(true);
    const post = (samlResponse: string, relayState?: string) =>
      service.handler(
        new Request('https://iam.test/saml/portal/acs', {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            SAMLResponse: samlResponse,
            ...(relayState ? { RelayState: relayState } : {}),
          }),
        }),
      );
    const unsolicited = response(null, created.acsUrl, created.entityId);
    const accepted = await post(unsolicited, 'https://app.example/dashboard');
    expect(accepted?.status).toBe(200);
    expect(await accepted!.json()).toEqual({ signedIn: 'employee-42' });
    // The same assertion cannot be replayed, and responses to requests still need their browser binding.
    expect((await post(unsolicited))?.status).toBe(401);
    expect((await post(response('_forged', created.acsUrl, created.entityId), 'x'))?.status).toBe(
      401,
    );
    // Other audiences and signers are refused like SP-initiated responses.
    expect(
      (await post(response(null, created.acsUrl, 'https://elsewhere.test', idp)))?.status,
    ).toBe(401);
    expect((await post(response(null, created.acsUrl, created.entityId, next)))?.status).toBe(401);
    expect(completed).toHaveLength(1);

    // Turning it off refuses unsolicited responses again.
    await service.updateConnection(admin, {
      tenantId: 'a',
      connectionId: 'portal',
      allowIdpInitiated: false,
    });
    expect((await post(response(null, created.acsUrl, created.entityId)))?.status).toBe(401);
    await expect(
      service.idpInitiated('portal', response(null, created.acsUrl, created.entityId)),
    ).rejects.toMatchObject({ code: 'SAML_INVALID' });
    expect(completed).toHaveLength(1);
  });

  it('validates connection input', async () => {
    const base = {
      tenantId: 'a',
      name: 'Acme',
      entryPoint: 'https://idp.test/login',
      idpIssuer: 'https://idp.test',
      idpCertificates: [idp.cert],
    };
    await service.createConnection(admin, { ...base, id: 'taken' });
    for (const [input, code] of [
      [{ ...base, id: 'taken' }, 'CONFLICT'],
      [{ ...base, id: 'static' }, 'CONFLICT'],
      [{ ...base, id: 'Not Valid' }, 'INVALID_INPUT'],
      [{ ...base, entryPoint: 'http://idp.test/login' }, 'INVALID_INPUT'],
      [{ ...base, idpCertificates: [] }, 'INVALID_INPUT'],
      [{ ...base, idpCertificates: ['not a certificate'] }, 'INVALID_INPUT'],
      [{ ...base, trustedEmailDomains: ['*.acme.test'] }, 'INVALID_INPUT'],
      [{ ...base, attributeMapping: { 'bad name': 'x' } }, 'INVALID_INPUT'],
      [{ ...base, requireEncryptedAssertions: true }, 'INVALID_INPUT'],
      [{ ...base, name: '', metadataXml: undefined }, 'INVALID_INPUT'],
      [{ ...base, metadataXml: '<!DOCTYPE x><x/>' }, 'INVALID_INPUT'],
    ] as const)
      await expect(service.createConnection(admin, input)).rejects.toMatchObject({ code });
    // Configured connections keep their fixed URLs and are not managed through the API.
    await expect(
      service.getConnection(admin, { tenantId: 'a', connectionId: 'static' }),
    ).rejects.toMatchObject({ status: 404 });
    expect(service.metadata('static')).toContain('https://iam.test/static/callback');
    expect(() =>
      createSamlService({
        store,
        serviceProvider: { baseUrl: 'http://iam.test', privateKey: 'x', publicCertificate: 'y' },
        completeAuthentication: async () => undefined,
      }),
    ).toThrow(/HTTPS/);
  });

  it('passes trustScimProvisioned to the host, gated as a trust change, and shows the provider key', async () => {
    const trustChanges: string[] = [];
    const principal = {
      identity: { id: 'admin-a', tenantId: 'a' },
      session: { id: 'session', kind: 'user', authenticatedAt: Date.now() },
    } as unknown as AuthenticatedPrincipal;
    const trusting = createSamlService({
      store,
      serviceProvider: {
        baseUrl: 'https://iam.test',
        privateKey: sp.private,
        publicCertificate: sp.cert,
      },
      authenticate: async () => principal,
      authorize: async () => undefined,
      assertTrustChange: async (_credential, input) => {
        trustChanges.push(input.providerId);
      },
      completeAuthentication: async (input) => {
        completed.push(input);
        return { signedIn: input.subject };
      },
    });
    const created = await trusting.createConnection(admin, {
      tenantId: 'a',
      id: 'okta',
      name: 'Okta',
      metadataXml: metadata([idp.cert]),
      trustedEmailDomains: ['acme.test'],
    });
    expect(created.trustScimProvisioned).toBe(false);
    expect(created.providerId).toMatch(/^saml:okta:/);
    expect(trustChanges).toEqual([created.providerId]);
    // Trusting SCIM-provisioned accounts widens what the connection can sign in to; narrowing does not.
    const scim = await trusting.updateConnection(admin, {
      tenantId: 'a',
      connectionId: 'okta',
      trustScimProvisioned: ['scim-1', 'scim-1'],
    });
    expect(scim.trustScimProvisioned).toEqual(['scim-1']);
    expect(trustChanges).toHaveLength(2);
    await trusting.updateConnection(admin, {
      tenantId: 'a',
      connectionId: 'okta',
      trustScimProvisioned: true,
    });
    expect(trustChanges).toHaveLength(3);
    await trusting.updateConnection(admin, {
      tenantId: 'a',
      connectionId: 'okta',
      trustScimProvisioned: ['scim-1'],
    });
    expect(trustChanges).toHaveLength(3);
    await expect(
      trusting.updateConnection(admin, {
        tenantId: 'a',
        connectionId: 'okta',
        trustScimProvisioned: 'yes' as unknown as boolean,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    const login = await trusting.handler(new Request('https://iam.test/saml/okta/login'));
    const location = new URL(login!.headers.get('location')!);
    const requestId = /\bID="([^"]+)"/.exec(
      inflateRawSync(Buffer.from(location.searchParams.get('SAMLRequest')!, 'base64')).toString(),
    )![1]!;
    await trusting.handler(
      new Request('https://iam.test/saml/okta/acs', {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          cookie: login!.headers.get('set-cookie')!.split(';')[0]!,
        },
        body: new URLSearchParams({
          SAMLResponse: response(requestId, created.acsUrl, created.entityId),
          RelayState: location.searchParams.get('RelayState')!,
        }),
      }),
    );
    expect(completed.at(-1)).toMatchObject({
      providerId: created.providerId,
      emailVerified: true,
      trustScimProvisioned: ['scim-1'],
    });
    expect(() =>
      createSamlService({
        store,
        connections: [
          {
            id: 'bad',
            tenantId: 'a',
            entryPoint: 'https://idp.test/login',
            idpIssuer: 'https://idp.test',
            idpCertificates: [idp.cert],
            entityId: 'https://iam.test/bad',
            callbackUrl: 'https://iam.test/bad/callback',
            privateKey: sp.private,
            publicCertificate: sp.cert,
            trustScimProvisioned: [42 as unknown as string],
          },
        ],
        completeAuthentication: async () => undefined,
      }),
    ).toThrow(/trustScimProvisioned/);
  });

  it('asks the host to redirect after sign-in: afterSignIn, returnTo, MFA fragment, error page', async () => {
    let outcome: unknown = { token: 'session-token', session: { expiresAt: Date.now() + 60_000 } };
    const redirecting = createSamlService({
      store,
      serviceProvider: {
        baseUrl: 'https://iam.test',
        privateKey: sp.private,
        publicCertificate: sp.cert,
      },
      authenticate: async () => {
        throw new IamError('UNAUTHENTICATED', 'No', 401);
      },
      authorize: async () => undefined,
      trustedOrigins: ['https://app.example.test'],
      afterSignIn: 'https://app.example.test/home',
      mfaUrl: '/mfa',
      errorUrl: '/login?sso=1',
      completeAuthentication: async (input) => {
        completed.push(input);
        if (outcome instanceof Error) throw outcome;
        return outcome;
      },
    });
    const created = await service.createConnection(admin, {
      tenantId: 'a',
      id: 'acme',
      name: 'Acme',
      metadataXml: metadata([idp.cert]),
    });
    const signIn = async (query = '') => {
      const login = await redirecting.handler(
        new Request(`https://iam.test/saml/acme/login${query}`),
      );
      expect(login?.status).toBe(302);
      const location = new URL(login!.headers.get('location')!);
      const requestId = /\bID="([^"]+)"/.exec(
        inflateRawSync(Buffer.from(location.searchParams.get('SAMLRequest')!, 'base64')).toString(),
      )![1]!;
      return (await redirecting.handler(
        new Request('https://iam.test/saml/acme/acs', {
          method: 'POST',
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            cookie: login!.headers.get('set-cookie')!.split(';')[0]!,
          },
          body: new URLSearchParams({
            SAMLResponse: response(requestId, created.acsUrl, created.entityId),
            RelayState: location.searchParams.get('RelayState')!,
          }),
        }),
      ))!;
    };
    // A session: the JSON stays (the host turns it into a 303 with the cookie), the hint names the page.
    const plain = await signIn();
    expect(plain.status).toBe(200);
    expect(plain.headers.get('x-better-iam-redirect')).toBe('https://app.example.test/home');
    expect(await plain.json()).toMatchObject({ token: 'session-token' });
    const back = await signIn('?returnTo=%2Finvoices%3Fpage%3D2');
    expect(back.headers.get('x-better-iam-redirect')).toBe('/invoices?page=2');

    // MFA: the challenge goes in the fragment, to the MFA page, with returnTo.
    outcome = { mfaRequired: true, challenge: 'challenge-1', enrollmentRequired: false };
    const mfa = await signIn('?returnTo=/reports');
    const target = mfa.headers.get('x-better-iam-redirect')!;
    expect(target.startsWith('/mfa#')).toBe(true);
    expect(Object.fromEntries(new URLSearchParams(target.split('#')[1]))).toEqual({
      tenantId: 'a',
      mfaRequired: 'true',
      challenge: 'challenge-1',
      enrollmentRequired: 'false',
      returnTo: '/reports',
    });

    // Failures go to the error page with the host's code; the JSON body stays generic.
    outcome = new IamError('ACCOUNT_LINK_REQUIRED', 'Link first', 409);
    const failed = await signIn();
    expect(failed.status).toBe(401);
    expect(failed.headers.get('x-better-iam-redirect')).toBe(
      '/login?sso=1&error=ACCOUNT_LINK_REQUIRED',
    );
    expect(await failed.json()).toEqual({ error: 'SAML_INVALID' });

    // returnTo must be a path on this site.
    for (const bad of ['https://evil.test/', '//evil.test', '/\\evil.test', 'relative'])
      expect(
        (await redirecting.handler(
          new Request(`https://iam.test/saml/acme/login?returnTo=${encodeURIComponent(bad)}`),
        ))!.status,
        bad,
      ).toBe(400);
    // Without afterSignIn nothing changes: no hint.
    outcome = { token: 'session-token', session: { expiresAt: Date.now() + 60_000 } };
    const login = await service.handler(
      new Request('https://iam.test/saml/acme/login?returnTo=/x'),
    );
    expect(login?.status).toBe(302);

    const options = {
      store,
      serviceProvider: {
        baseUrl: 'https://iam.test',
        privateKey: sp.private,
        publicCertificate: sp.cert,
      },
      completeAuthentication: async () => undefined,
    };
    expect(() => createSamlService({ ...options, afterSignIn: 'https://evil.test/' })).toThrow(
      /afterSignIn/,
    );
    expect(() => createSamlService({ ...options, afterSignIn: '//evil.test/' })).toThrow(
      /afterSignIn/,
    );
    expect(() => createSamlService({ ...options, mfaUrl: '/mfa' })).toThrow(/need afterSignIn/);
    expect(() =>
      createSamlService({ ...options, afterSignIn: 'https://iam.test/welcome' }),
    ).not.toThrow();
  });
});
