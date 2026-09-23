import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import {
  SAML,
  ValidateInResponseTo,
  type CacheProvider,
  type Profile,
  type SamlConfig,
} from '@node-saml/node-saml';
import { DOMParser } from '@xmldom/xmldom';
import {
  IamError,
  appendAuditEvent,
  tenantTreeActive,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type ResourceRef,
  type StoredRecord,
} from '@better-iam/core';
import {
  certificateInfo,
  normalizeCertificate,
  parseIdpMetadata,
  type CertificateInfo,
} from './metadata.js';

export {
  certificateInfo,
  normalizeCertificate,
  parseIdpMetadata,
  type CertificateInfo,
  type IdpMetadata,
} from './metadata.js';

export interface SamlConnection {
  id: string;
  tenantId: string;
  entryPoint: string;
  idpIssuer: string;
  idpCertificates: string[];
  entityId: string;
  callbackUrl: string;
  privateKey: string;
  publicCertificate: string;
  decryptionPrivateKey?: string;
  decryptionCertificate?: string;
  requireEncryptedAssertions?: boolean;
  /** Domains whose email attributes this administrator-configured IdP is trusted to verify. */
  trustedEmailDomains?: string[];
  /**
   * Accept IdP-initiated (unsolicited) sign-in at the callback URL, such as app tiles in an IdP portal. Each assertion
   * is accepted once; SP-initiated responses keep their request binding. Off by default.
   */
  allowIdpInitiated?: boolean;
  /**
   * Maps the validated assertion attributes (Node-SAML profile) to identity attributes declared by the product;
   * they are validated by the host and stored on every sign-in. Return undefined to leave them untouched.
   */
  mapAttributes?(profile: Record<string, unknown>): Record<string, unknown> | undefined;
}
/** The deployment's own SAML service-provider identity, shared by every tenant-managed connection. */
export interface SamlServiceProvider {
  /** Public HTTPS origin (and optional path prefix) the SAML routes are served from, e.g. `https://id.example.com`. */
  baseUrl: string;
  privateKey: string;
  publicCertificate: string;
  /** Needed for connections that require encrypted assertions. */
  decryptionPrivateKey?: string;
  decryptionCertificate?: string;
}

/** Settings an administrator manages for a tenant's identity provider. */
export interface ManagedSamlConnectionInput {
  name: string;
  /** IdP metadata XML; supplies `entryPoint`, `idpIssuer`, and `idpCertificates` unless those are given explicitly. */
  metadataXml?: string;
  entryPoint?: string;
  idpIssuer?: string;
  idpCertificates?: string[];
  trustedEmailDomains?: string[];
  requireEncryptedAssertions?: boolean;
  /** Identity attribute name → SAML attribute name (for example `{ department: 'department' }`). */
  attributeMapping?: Record<string, string>;
  /** Accept IdP-initiated sign-in (app tiles in the IdP portal); each assertion is accepted once. */
  allowIdpInitiated?: boolean;
  enabled?: boolean;
}

/** A tenant-managed connection as administrators see it, with the values to enter at the IdP. */
export interface ManagedSamlConnection {
  id: string;
  tenantId: string;
  name: string;
  enabled: boolean;
  entryPoint: string;
  idpIssuer: string;
  certificates: CertificateInfo[];
  trustedEmailDomains: string[];
  requireEncryptedAssertions: boolean;
  attributeMapping: Record<string, string>;
  allowIdpInitiated: boolean;
  /** Service-provider entity ID (audience) to register at the IdP. */
  entityId: string;
  /** Assertion consumer service URL (HTTP-POST) to register at the IdP. */
  acsUrl: string;
  metadataUrl: string;
  loginUrl: string;
  createdAt: number;
  updatedAt: number;
}

interface ConnectionRecord extends StoredRecord {
  name: string;
  enabled: boolean;
  entryPoint: string;
  idpIssuer: string;
  idpCertificates: string[];
  trustedEmailDomains: string[];
  requireEncryptedAssertions: boolean;
  attributeMapping: Record<string, string>;
  allowIdpInitiated?: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface SamlConfigOptions {
  store: IamStore;
  /** Connections fixed in deployment configuration. Tenant-managed connections live in the database. */
  connections?: SamlConnection[];
  /** Enables tenant-managed connections (`createConnection` and friends). */
  serviceProvider?: SamlServiceProvider;
  /** Authorizes connection management (`iam:saml:connections:*` on `saml/{id}`); `iam.protocolHost` supplies it. */
  authorize?(credential: CredentialInput, action: string, resource: ResourceRef): Promise<unknown>;
  basePath?: string;
  completeAuthentication(input: {
    tenantId: string;
    providerId: string;
    issuer: string;
    subject: string;
    email?: string;
    emailVerified?: boolean;
    name?: string;
    linkingSessionId?: string;
    linkingIdentityId?: string;
    attributes?: Record<string, unknown>;
  }): Promise<unknown>;
  authenticate?(credential: CredentialInput): Promise<AuthenticatedPrincipal>;
  trustedOrigins?: string[];
  /** Revokes the local IAM session; upstream SAML sessions are not modified. */
  revokeSession?(credential: CredentialInput): Promise<unknown>;
}
interface Relay extends StoredRecord {
  requestId: string;
  connectionId: string;
  bindingHash: string;
  expiresAt: number;
  linkingSessionId?: string;
  linkingIdentityId?: string;
}
interface CachedRequest extends StoredRecord {
  value: string;
  createdAt: number;
  expiresAt: number;
}
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
/** Tenant-managed connection IDs appear in SAML URLs. */
const connectionName = /^[a-z0-9][a-z0-9-]{1,62}$/;
const PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
const ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';

/** Shared replay cache. Run response verification inside one store transaction. */
export function createSamlCache(
  store: IamStore,
  tenantId: string,
  connectionId: string,
  expectedRequestId?: string,
): CacheProvider {
  const id = (key: string) => hash(`${tenantId}:${connectionId}:${key}`);
  return {
    async saveAsync(key, value) {
      const createdAt = Date.now();
      await store.transaction(async (tx) => {
        await tx.insert<CachedRequest>('samlRequests', {
          id: id(key),
          tenantId,
          value,
          createdAt,
          expiresAt: createdAt + 600_000,
        });
      });
      return { value, createdAt };
    },
    async getAsync(key) {
      if (expectedRequestId && key !== expectedRequestId) return null;
      const item = await store.get<CachedRequest>('samlRequests', id(key));
      return item && item.tenantId === tenantId && item.expiresAt > Date.now() ? item.value : null;
    },
    async removeAsync(key) {
      if (!key || (expectedRequestId && key !== expectedRequestId)) return null;
      return store.transaction(async (tx) => {
        const item = await tx.get<CachedRequest>('samlRequests', id(key));
        if (!item || item.tenantId !== tenantId) return null;
        await tx.delete('samlRequests', item.id);
        return item.value;
      });
    },
  };
}
async function activeTenant(store: IamStore, tenantId: string): Promise<void> {
  if (!(await tenantTreeActive(store, tenantId)))
    throw new IamError('TENANT_INACTIVE', 'Tenant unavailable.', 403);
}
/**
 * Supplements Node-SAML's cryptographic checks with exact response destination checks. `expectedRequestId: null`
 * validates an IdP-initiated response, which must not answer any request.
 */
export function validateSamlEnvelope(
  xml: string,
  callbackUrl: string,
  expectedRequestId: string | null,
  encryptedRequired = false,
): void {
  if (xml.length > 1024 * 1024 || /<!DOCTYPE|<!ENTITY/i.test(xml))
    throw new IamError('SAML_INVALID', 'Unsafe SAML document.', 401);
  const errors: string[] = [];
  const document = new DOMParser({
    errorHandler: {
      warning: (message) => errors.push(message),
      error: (message) => errors.push(message),
      fatalError: (message) => errors.push(message),
    },
  }).parseFromString(xml, 'text/xml');
  const root = document.documentElement;
  if (
    errors.length ||
    root.namespaceURI !== PROTOCOL_NS ||
    root.localName !== 'Response' ||
    root.getAttribute('Destination') !== callbackUrl ||
    (expectedRequestId === null
      ? root.hasAttribute('InResponseTo')
      : root.getAttribute('InResponseTo') !== expectedRequestId)
  )
    throw new IamError('SAML_INVALID', 'SAML response binding is invalid.', 401);
  if (
    encryptedRequired &&
    root.getElementsByTagNameNS(ASSERTION_NS, 'EncryptedAssertion').length !== 1
  )
    throw new IamError('SAML_INVALID', 'An encrypted assertion is required.', 401);
  for (
    let i = 0;
    i < root.getElementsByTagNameNS(ASSERTION_NS, 'SubjectConfirmationData').length;
    i++
  ) {
    const subject = root.getElementsByTagNameNS(ASSERTION_NS, 'SubjectConfirmationData').item(i)!;
    if (subject.getAttribute('Recipient') !== callbackUrl)
      throw new IamError('SAML_INVALID', 'SAML subject recipient is invalid.', 401);
    if (expectedRequestId === null && subject.hasAttribute('InResponseTo'))
      throw new IamError('SAML_INVALID', 'An unsolicited response cannot answer a request.', 401);
  }
}

export function createSamlService(config: SamlConfigOptions) {
  const basePath = (config.basePath ?? '/saml').replace(/\/$/, '');
  const connections = new Map<string, SamlConnection>();
  for (const item of config.connections ?? []) {
    if (
      !item.id ||
      connections.has(item.id) ||
      !item.tenantId ||
      !item.idpIssuer ||
      !item.entityId ||
      !item.privateKey ||
      !item.publicCertificate ||
      !item.idpCertificates.length
    )
      throw new IamError('configuration', 'SAML connection configuration is incomplete.');
    for (const value of [item.entryPoint, item.callbackUrl]) {
      const parsed = new URL(value);
      if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash)
        throw new IamError('configuration', 'SAML endpoints require HTTPS.');
    }
    if (
      item.requireEncryptedAssertions &&
      (!item.decryptionPrivateKey || !item.decryptionCertificate)
    )
      throw new IamError(
        'configuration',
        'Encrypted SAML assertions require decryption key and certificate.',
      );
    if ([...connections.values()].some((value) => value.callbackUrl === item.callbackUrl))
      throw new IamError('configuration', 'SAML callback URLs must be unique per connection.');
    if (
      item.trustedEmailDomains?.some(
        (value) => !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(value),
      )
    )
      throw new IamError('configuration', 'Trusted SAML email domains must be exact domain names.');
    connections.set(item.id, { ...item, idpCertificates: [...item.idpCertificates] });
  }
  const sp = config.serviceProvider;
  let spBase = '';
  if (sp) {
    const parsed = new URL(sp.baseUrl);
    if (
      parsed.protocol !== 'https:' ||
      parsed.username ||
      parsed.password ||
      parsed.hash ||
      parsed.search ||
      !sp.privateKey ||
      !sp.publicCertificate
    )
      throw new IamError(
        'configuration',
        'The SAML service provider needs an HTTPS base URL, a private key, and a certificate.',
      );
    spBase = `${parsed.origin}${parsed.pathname.replace(/\/$/, '')}`;
  }
  const managedUrls = (id: string) => {
    const root = `${spBase}${basePath}/${encodeURIComponent(id)}`;
    return {
      entityId: `${root}/metadata`,
      acsUrl: `${root}/acs`,
      metadataUrl: `${root}/metadata`,
      loginUrl: `${root}/login`,
    };
  };
  function fromRecord(record: ConnectionRecord): SamlConnection {
    const urls = managedUrls(record.id);
    const mapping = Object.entries(record.attributeMapping);
    return {
      id: record.id,
      tenantId: record.tenantId,
      entryPoint: record.entryPoint,
      idpIssuer: record.idpIssuer,
      idpCertificates: [...record.idpCertificates],
      entityId: urls.entityId,
      callbackUrl: urls.acsUrl,
      privateKey: sp!.privateKey,
      publicCertificate: sp!.publicCertificate,
      decryptionPrivateKey: sp!.decryptionPrivateKey,
      decryptionCertificate: sp!.decryptionCertificate,
      requireEncryptedAssertions: record.requireEncryptedAssertions,
      allowIdpInitiated: record.allowIdpInitiated === true,
      trustedEmailDomains: [...record.trustedEmailDomains],
      ...(mapping.length
        ? {
            mapAttributes: (profile: Record<string, unknown>) => {
              const attributes: Record<string, unknown> = {};
              for (const [attribute, name] of mapping) {
                const raw = profile[name];
                const value = Array.isArray(raw) ? raw[0] : raw;
                if (typeof value === 'string') attributes[attribute] = value;
              }
              return attributes;
            },
          }
        : {}),
    };
  }
  function staticConnection(id: string) {
    const item = connections.get(id);
    if (!item) throw new IamError('NOT_FOUND', 'SAML connection unavailable.', 404);
    return item;
  }
  /** A configured connection, or an enabled tenant-managed one. */
  async function connection(id: string, store: IamStore = config.store): Promise<SamlConnection> {
    const item = connections.get(id);
    if (item) return item;
    if (sp && typeof id === 'string' && connectionName.test(id)) {
      const record = await store.get<ConnectionRecord>('samlConnections', id);
      if (record?.enabled) return fromRecord(record);
    }
    throw new IamError('NOT_FOUND', 'SAML connection unavailable.', 404);
  }

  function summary(record: ConnectionRecord): ManagedSamlConnection {
    return {
      id: record.id,
      tenantId: record.tenantId,
      name: record.name,
      enabled: record.enabled,
      entryPoint: record.entryPoint,
      idpIssuer: record.idpIssuer,
      certificates: record.idpCertificates.map(certificateInfo),
      trustedEmailDomains: [...record.trustedEmailDomains],
      requireEncryptedAssertions: record.requireEncryptedAssertions,
      attributeMapping: { ...record.attributeMapping },
      allowIdpInitiated: record.allowIdpInitiated === true,
      ...managedUrls(record.id),
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }
  /** Validates administrator input, filling IdP details from metadata and unchanged values from `current`. */
  function settings(input: Partial<ManagedSamlConnectionInput>, current?: ConnectionRecord) {
    const imported =
      input.metadataXml !== undefined ? parseIdpMetadata(input.metadataXml) : undefined;
    const name = input.name ?? current?.name;
    const entryPoint = input.entryPoint ?? imported?.entryPoint ?? current?.entryPoint;
    const idpIssuer = input.idpIssuer ?? imported?.entityId ?? current?.idpIssuer;
    const certificates =
      input.idpCertificates ?? imported?.certificates ?? current?.idpCertificates;
    const domains = input.trustedEmailDomains ?? current?.trustedEmailDomains ?? [];
    const mapping = input.attributeMapping ?? current?.attributeMapping ?? {};
    const requireEncryptedAssertions =
      input.requireEncryptedAssertions ?? current?.requireEncryptedAssertions ?? false;
    const enabled = input.enabled ?? current?.enabled ?? true;
    const allowIdpInitiated = input.allowIdpInitiated ?? current?.allowIdpInitiated ?? false;
    if (typeof name !== 'string' || !name.trim() || name.length > 200)
      throw new IamError(
        'INVALID_INPUT',
        'A connection name of at most 200 characters is required.',
      );
    let entry: URL;
    try {
      entry = new URL(String(entryPoint));
    } catch {
      throw new IamError('INVALID_INPUT', 'The IdP sign-on URL must be an absolute HTTPS URL.');
    }
    if (entry.protocol !== 'https:' || entry.username || entry.password || entry.hash)
      throw new IamError('INVALID_INPUT', 'The IdP sign-on URL must be an absolute HTTPS URL.');
    if (typeof idpIssuer !== 'string' || !idpIssuer || idpIssuer.length > 1024)
      throw new IamError('INVALID_INPUT', 'The IdP issuer (entity ID) is required.');
    if (!Array.isArray(certificates) || !certificates.length || certificates.length > 5)
      throw new IamError(
        'INVALID_INPUT',
        'Between one and five IdP signing certificates are required.',
      );
    if (
      !Array.isArray(domains) ||
      domains.length > 20 ||
      domains.some(
        (value) =>
          typeof value !== 'string' ||
          !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(value),
      )
    )
      throw new IamError('INVALID_INPUT', 'Trusted email domains must be exact domain names.');
    if (
      !mapping ||
      typeof mapping !== 'object' ||
      Array.isArray(mapping) ||
      Object.keys(mapping).length > 32 ||
      Object.entries(mapping).some(
        ([attribute, source]) =>
          !/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(attribute) ||
          typeof source !== 'string' ||
          !source ||
          source.length > 256,
      )
    )
      throw new IamError(
        'INVALID_INPUT',
        'attributeMapping maps up to 32 identity attribute names to SAML attribute names.',
      );
    if (
      typeof requireEncryptedAssertions !== 'boolean' ||
      typeof enabled !== 'boolean' ||
      typeof allowIdpInitiated !== 'boolean'
    )
      throw new IamError('INVALID_INPUT', 'Invalid SAML connection settings.');
    if (requireEncryptedAssertions && (!sp?.decryptionPrivateKey || !sp.decryptionCertificate))
      throw new IamError(
        'INVALID_INPUT',
        'Encrypted assertions need a service-provider decryption key.',
      );
    return {
      name: name.trim(),
      entryPoint: entry.href,
      idpIssuer,
      idpCertificates: [...new Set(certificates.map(normalizeCertificate))],
      trustedEmailDomains: [...new Set(domains.map((domain) => domain.toLowerCase()))],
      attributeMapping: { ...mapping },
      requireEncryptedAssertions,
      allowIdpInitiated,
      enabled,
    };
  }
  /** Authorizes a management call on `saml/{id}` and returns the acting principal. */
  async function manager(
    credential: CredentialInput,
    action: string,
    tenantId: string,
    id: string,
  ): Promise<AuthenticatedPrincipal> {
    if (!sp || !config.authorize || !config.authenticate)
      throw new IamError(
        'configuration',
        'Managed SAML connections need serviceProvider, authorize, and authenticate.',
      );
    await config.authorize(credential, action, { tenantId, type: 'saml', id });
    return config.authenticate(credential);
  }
  async function managed(tx: IamStore, tenantId: string, id: string): Promise<ConnectionRecord> {
    const record =
      typeof id === 'string' && connectionName.test(id)
        ? await tx.get<ConnectionRecord>('samlConnections', id)
        : undefined;
    if (!record || record.tenantId !== tenantId)
      throw new IamError('NOT_FOUND', 'SAML connection not found.', 404);
    return record;
  }
  async function audit(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    action: string,
    resourceId: string,
  ): Promise<void> {
    await appendAuditEvent(tx, {
      id: randomUUID(),
      tenantId,
      actorId: principal.identity.id,
      action,
      resourceId,
      timestamp: Date.now(),
      outcome: 'allow',
    });
  }
  function saml(
    item: SamlConnection,
    store: IamStore,
    requestId?: string,
    expectedRequestId?: string,
    unsolicited = false,
  ) {
    const options: SamlConfig = {
      entryPoint: item.entryPoint,
      issuer: item.entityId,
      idpIssuer: item.idpIssuer,
      callbackUrl: item.callbackUrl,
      audience: item.entityId,
      idpCert: item.idpCertificates,
      privateKey: item.privateKey,
      publicCert: item.publicCertificate,
      decryptionPvk: item.decryptionPrivateKey,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: true,
      signMetadata: true,
      signatureAlgorithm: 'sha256',
      digestAlgorithm: 'sha256',
      validateInResponseTo: unsolicited ? ValidateInResponseTo.never : ValidateInResponseTo.always,
      requestIdExpirationPeriodMs: 600_000,
      maxAssertionAgeMs: 300_000,
      acceptedClockSkewMs: 30_000,
      cacheProvider: createSamlCache(store, item.tenantId, item.id, expectedRequestId),
      generateUniqueId: requestId ? () => requestId : () => `_${randomUUID()}`,
    };
    return new SAML(options);
  }
  async function begin(connectionId: string, linkingCredential?: CredentialInput) {
    const item = await connection(connectionId);
    const requestId = `_${randomUUID()}`;
    const relayState = randomBytes(32).toString('base64url');
    const binding = randomBytes(32).toString('base64url');
    let linkingSessionId: string | undefined;
    let linkingIdentityId: string | undefined;
    if (linkingCredential) {
      if (!config.authenticate)
        throw new IamError('configuration', 'Linking requires an authenticate callback.');
      const principal = await config.authenticate(linkingCredential);
      const age = Date.now() - principal.session.authenticatedAt;
      if (
        principal.identity.tenantId !== item.tenantId ||
        principal.identity.rootAdmin ||
        principal.session.kind !== 'user' ||
        age < 0 ||
        age > 300_000
      )
        throw new IamError(
          'RECENT_AUTH_REQUIRED',
          'Linking requires recent authentication to a non-root identity in this tenant.',
          403,
        );
      linkingSessionId = principal.session.id;
      linkingIdentityId = principal.identity.id;
    }
    const destination = await config.store.transaction(async (tx) => {
      await activeTenant(tx, item.tenantId);
      const destination = await saml(item, tx, requestId).getAuthorizeUrlAsync(
        relayState,
        undefined,
        {},
      );
      await tx.insert<Relay>('samlRelays', {
        id: hash(relayState),
        tenantId: item.tenantId,
        connectionId: item.id,
        requestId,
        bindingHash: hash(binding),
        expiresAt: Date.now() + 600_000,
        linkingSessionId,
        linkingIdentityId,
      });
      return destination;
    });
    return { url: destination, relayState, binding };
  }
  async function callback(
    connectionId: string,
    input: { samlResponse: string; relayState: string; binding: string },
  ) {
    const item = await connection(connectionId);
    if (
      !input.binding ||
      !input.relayState ||
      input.relayState.length > 512 ||
      input.samlResponse.length > 1_400_000
    )
      throw new IamError('SAML_INVALID', 'Invalid SAML response.', 401);
    return config.store.transaction(async (tx) => {
      await activeTenant(tx, item.tenantId);
      const relay = await tx.get<Relay>('samlRelays', hash(input.relayState));
      if (
        !relay ||
        relay.tenantId !== item.tenantId ||
        relay.connectionId !== item.id ||
        relay.expiresAt <= Date.now() ||
        !timingSafeEqual(Buffer.from(relay.bindingHash), Buffer.from(hash(input.binding)))
      )
        throw new IamError('SAML_INVALID', 'Invalid, expired, or replayed SAML login.', 401);
      const xml = Buffer.from(input.samlResponse, 'base64').toString('utf8');
      validateSamlEnvelope(xml, item.callbackUrl, relay.requestId, item.requireEncryptedAssertions);
      const { profile, loggedOut } = await saml(
        item,
        tx,
        undefined,
        relay.requestId,
      ).validatePostResponseAsync({ SAMLResponse: input.samlResponse });
      if (!profile || loggedOut || profile.issuer !== item.idpIssuer || !profile.nameID)
        throw new IamError('SAML_INVALID', 'Invalid SAML identity.', 401);
      // Node-SAML decrypts and validates the assertion before exposing this XML.
      const assertion = profile.getAssertionXml?.();
      if (assertion) {
        const document = new DOMParser().parseFromString(assertion, 'text/xml');
        const subjects = document.getElementsByTagNameNS(ASSERTION_NS, 'SubjectConfirmationData');
        for (let i = 0; i < subjects.length; i++)
          if (subjects.item(i)!.getAttribute('Recipient') !== item.callbackUrl)
            throw new IamError('SAML_INVALID', 'SAML assertion recipient is invalid.', 401);
      }
      await tx.delete('samlRelays', relay.id);
      return finish(item, profile, relay);
    });
  }
  /** Hands a validated SAML identity to the host, with a trusted-domain email and mapped attributes. */
  function finish(item: SamlConnection, profile: Profile, relay?: Relay) {
    const email = profile.email ?? profile.mail ?? profile['urn:oid:0.9.2342.19200300.100.1.3'];
    const verified =
      typeof email === 'string' &&
      /^[^\s@]+@[^\s@]+$/.test(email) &&
      !!item.trustedEmailDomains?.some(
        (domain) => domain.toLowerCase() === email.split('@')[1]!.toLowerCase(),
      );
    const attributes = item.mapAttributes?.(profile as unknown as Record<string, unknown>);
    return config.completeAuthentication({
      tenantId: item.tenantId,
      providerId: item.id,
      issuer: item.idpIssuer,
      subject: profile.nameID,
      email: typeof email === 'string' ? email : undefined,
      emailVerified: verified,
      name: typeof profile.displayName === 'string' ? profile.displayName : undefined,
      ...(relay?.linkingSessionId
        ? { linkingSessionId: relay.linkingSessionId, linkingIdentityId: relay.linkingIdentityId }
        : {}),
      ...(attributes !== undefined ? { attributes } : {}),
    });
  }
  /** Whether a base64 SAML response carries `InResponseTo` (SP-initiated). Unparseable input counts as solicited. */
  function answersRequest(samlResponse: string): boolean {
    const xml = Buffer.from(samlResponse, 'base64').toString('utf8');
    if (xml.length > 1024 * 1024 || /<!DOCTYPE|<!ENTITY/i.test(xml)) return true;
    const root = new DOMParser({ errorHandler: { warning: () => undefined } }).parseFromString(
      xml,
      'text/xml',
    ).documentElement;
    return !root || root.hasAttribute('InResponseTo');
  }
  /**
   * IdP-initiated sign-in for connections with `allowIdpInitiated`: the same signature, issuer, audience, destination,
   * recipient, and age checks as SP-initiated responses, no `InResponseTo`, and each assertion ID accepted only once.
   */
  async function unsolicited(connectionId: string, samlResponse: string) {
    const item = await connection(connectionId);
    if (!item.allowIdpInitiated || samlResponse.length > 1_400_000)
      throw new IamError('SAML_INVALID', 'Unsolicited SAML responses are not accepted.', 401);
    return config.store.transaction(async (tx) => {
      await activeTenant(tx, item.tenantId);
      const xml = Buffer.from(samlResponse, 'base64').toString('utf8');
      validateSamlEnvelope(xml, item.callbackUrl, null, item.requireEncryptedAssertions);
      const { profile, loggedOut } = await saml(
        item,
        tx,
        undefined,
        undefined,
        true,
      ).validatePostResponseAsync({ SAMLResponse: samlResponse });
      if (!profile || loggedOut || profile.issuer !== item.idpIssuer || !profile.nameID)
        throw new IamError('SAML_INVALID', 'Invalid SAML identity.', 401);
      const assertion = profile.getAssertionXml?.();
      const document = assertion
        ? new DOMParser().parseFromString(assertion, 'text/xml')
        : undefined;
      const assertionId = document?.documentElement?.getAttribute('ID');
      if (!document || !assertionId)
        throw new IamError('SAML_INVALID', 'The assertion has no identifier.', 401);
      const subjects = document.getElementsByTagNameNS(ASSERTION_NS, 'SubjectConfirmationData');
      for (let i = 0; i < subjects.length; i++)
        if (
          subjects.item(i)!.getAttribute('Recipient') !== item.callbackUrl ||
          subjects.item(i)!.hasAttribute('InResponseTo')
        )
          throw new IamError('SAML_INVALID', 'SAML assertion recipient is invalid.', 401);
      // One use per assertion for longer than an assertion can be accepted (maximum age plus clock skew).
      const now = Date.now();
      for (const seen of await tx.find<CachedRequest & { connectionId: string }>('samlAssertions', {
        connectionId: item.id,
      }))
        if (seen.expiresAt <= now) await tx.delete('samlAssertions', seen.id);
      const key = hash(`${item.tenantId}:${item.id}:${assertionId}`);
      if (await tx.get('samlAssertions', key))
        throw new IamError('SAML_INVALID', 'The assertion was already used.', 401);
      await tx.insert('samlAssertions', {
        id: key,
        tenantId: item.tenantId,
        connectionId: item.id,
        value: '',
        createdAt: now,
        expiresAt: now + 600_000,
      });
      return finish(item, profile);
    });
  }
  /** The assertion consumer service: HTTP-POST binding, browser-binding cookie, then `callback`. */
  async function acs(item: SamlConnection, request: Request): Promise<Response> {
    try {
      if (!request.headers.get('content-type')?.startsWith('application/x-www-form-urlencoded'))
        throw new IamError('SAML_INVALID', 'SAML POST binding is required.', 415);
      const body = await request.text();
      if (body.length > 2_000_000)
        throw new IamError('SAML_INVALID', 'SAML response is too large.', 413);
      const form = new URLSearchParams(body);
      if (form.getAll('SAMLResponse').length !== 1 || form.getAll('RelayState').length > 1)
        throw new IamError('SAML_INVALID', 'Invalid SAML POST parameters.', 400);
      // Responses that answer no request are IdP-initiated; only connections that opt in accept them.
      if (item.allowIdpInitiated && !answersRequest(form.get('SAMLResponse')!))
        return Response.json(await unsolicited(item.id, form.get('SAMLResponse')!), {
          headers: { 'cache-control': 'no-store' },
        });
      if (form.getAll('RelayState').length !== 1)
        throw new IamError('SAML_INVALID', 'Invalid SAML POST parameters.', 400);
      const cookieName = `__Host-better-iam-saml-${hash(item.id).slice(0, 12)}`;
      const binding =
        request.headers
          .get('cookie')
          ?.split(';')
          .map((value) => value.trim())
          .find((value) => value.startsWith(`${cookieName}=`))
          ?.slice(cookieName.length + 1) ?? '';
      const result = await callback(item.id, {
        samlResponse: form.get('SAMLResponse')!,
        relayState: form.get('RelayState')!,
        binding,
      });
      return Response.json(result, {
        headers: {
          'cache-control': 'no-store',
          'set-cookie': `${cookieName}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`,
        },
      });
    } catch {
      return Response.json(
        { error: 'SAML_INVALID' },
        { status: 401, headers: { 'cache-control': 'no-store' } },
      );
    }
  }
  return {
    begin,
    callback,
    /** Accepts an IdP-initiated response for a connection with `allowIdpInitiated` (the ACS route calls it). */
    idpInitiated: unsolicited,
    basePath,
    /** Signed SP metadata of any available connection, configured or tenant-managed. */
    async getMetadata(connectionId: string): Promise<string> {
      const item = await connection(connectionId);
      return saml(item, config.store).generateServiceProviderMetadata(
        item.decryptionCertificate ?? null,
        item.publicCertificate,
      );
    },
    /**
     * Adds a tenant's identity provider (`iam:saml:connections:create` on `saml/{id}`). Give IdP metadata XML or the
     * sign-on URL, issuer, and signing certificates; the result lists the SP values to enter at the IdP.
     */
    async createConnection(
      credential: CredentialInput,
      input: ManagedSamlConnectionInput & { tenantId: string; id?: string },
    ): Promise<ManagedSamlConnection> {
      const id = input.id ?? `saml-${randomBytes(6).toString('hex')}`;
      if (typeof id !== 'string' || !connectionName.test(id))
        throw new IamError(
          'INVALID_INPUT',
          'Connection IDs are 2-63 lowercase letters, digits, and hyphens.',
        );
      const principal = await manager(
        credential,
        'iam:saml:connections:create',
        input.tenantId,
        id,
      );
      const values = settings(input);
      return config.store.transaction(async (tx) => {
        await activeTenant(tx, input.tenantId);
        if (connections.has(id) || (await tx.get('samlConnections', id)))
          throw new IamError('CONFLICT', 'A SAML connection with this ID already exists.', 409);
        const now = Date.now();
        const record: ConnectionRecord = {
          id,
          tenantId: input.tenantId,
          ...values,
          createdAt: now,
          updatedAt: now,
        };
        await tx.insert('samlConnections', record);
        await audit(tx, principal, input.tenantId, 'iam:saml:CreateConnection', id);
        return summary(record);
      });
    },
    /** The tenant's managed connections (`iam:saml:connections:read` on `saml/*`). */
    async listConnections(
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<ManagedSamlConnection[]> {
      await manager(credential, 'iam:saml:connections:read', input.tenantId, '*');
      return (
        await config.store.find<ConnectionRecord>('samlConnections', { tenantId: input.tenantId })
      )
        .map(summary)
        .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.id < b.id ? -1 : 1));
    },
    async getConnection(
      credential: CredentialInput,
      input: { tenantId: string; connectionId: string },
    ): Promise<ManagedSamlConnection> {
      await manager(credential, 'iam:saml:connections:read', input.tenantId, input.connectionId);
      return summary(await managed(config.store, input.tenantId, input.connectionId));
    },
    /**
     * Changes a managed connection, for example new IdP certificates during rollover (list old and new together
     * until the IdP switches) or refreshed metadata. Disabling it stops new sign-ins at once.
     */
    async updateConnection(
      credential: CredentialInput,
      input: Partial<ManagedSamlConnectionInput> & { tenantId: string; connectionId: string },
    ): Promise<ManagedSamlConnection> {
      const principal = await manager(
        credential,
        'iam:saml:connections:update',
        input.tenantId,
        input.connectionId,
      );
      return config.store.transaction(async (tx) => {
        const current = await managed(tx, input.tenantId, input.connectionId);
        const record: ConnectionRecord = {
          ...current,
          ...settings(input, current),
          updatedAt: Date.now(),
        };
        await tx.put('samlConnections', record);
        await audit(tx, principal, input.tenantId, 'iam:saml:UpdateConnection', current.id);
        return summary(record);
      });
    },
    /** Removes a managed connection and its pending sign-ins. Linked external identities stay with their accounts. */
    async deleteConnection(
      credential: CredentialInput,
      input: { tenantId: string; connectionId: string },
    ): Promise<void> {
      const principal = await manager(
        credential,
        'iam:saml:connections:delete',
        input.tenantId,
        input.connectionId,
      );
      await config.store.transaction(async (tx) => {
        const current = await managed(tx, input.tenantId, input.connectionId);
        await tx.delete('samlConnections', current.id);
        for (const relay of await tx.find<Relay>('samlRelays', { connectionId: current.id }))
          await tx.delete('samlRelays', relay.id);
        await audit(tx, principal, input.tenantId, 'iam:saml:DeleteConnection', current.id);
      });
    },
    /** Signed SP metadata of a configured connection; `getMetadata` also serves tenant-managed ones. */
    metadata(connectionId: string) {
      const item = staticConnection(connectionId);
      return saml(item, config.store).generateServiceProviderMetadata(
        item.decryptionCertificate ?? null,
        item.publicCertificate,
      );
    },
    async logout(credential: CredentialInput) {
      if (!config.revokeSession)
        throw new IamError('configuration', 'Local logout callback is required.');
      return config.revokeSession(credential);
    },
    async handler(request: Request): Promise<Response | undefined> {
      const requestUrl = new URL(request.url);
      const callbackConnection = [...connections.values()].find(
        (item) => item.callbackUrl === `${requestUrl.origin}${requestUrl.pathname}`,
      );
      if (callbackConnection && request.method === 'POST') return acs(callbackConnection, request);
      if (!requestUrl.pathname.startsWith(`${basePath}/`)) return undefined;
      try {
        const parts = requestUrl.pathname.slice(basePath.length + 1).split('/');
        const id = decodeURIComponent(parts[0]!);
        if (request.method === 'POST' && parts[1] === 'acs' && parts.length === 2) {
          const item = connections.has(id)
            ? undefined
            : await connection(id).catch(() => undefined);
          if (!item) return Response.json({ error: 'NOT_FOUND' }, { status: 404 });
          return await acs(item, request);
        }
        if (request.method === 'GET' && parts[1] === 'metadata' && parts.length === 2) {
          const item = await connection(id);
          return new Response(
            saml(item, config.store).generateServiceProviderMetadata(
              item.decryptionCertificate ?? null,
              item.publicCertificate,
            ),
            { headers: { 'content-type': 'application/samlmetadata+xml' } },
          );
        }
        if (!['GET', 'POST'].includes(request.method) || parts.length !== 2 || parts[1] !== 'login')
          return Response.json({ error: 'NOT_FOUND' }, { status: 404 });
        if (request.method === 'POST') {
          const item = await connection(id);
          const origin = request.headers.get('origin');
          if (
            !origin ||
            !(config.trustedOrigins ?? [new URL(item.callbackUrl).origin]).includes(origin) ||
            request.headers.get('x-better-iam') !== '1' ||
            !request.headers.get('content-type')?.startsWith('application/json')
          )
            throw new IamError(
              'CSRF',
              'Linking requires a trusted Origin and X-Better-IAM header.',
              403,
            );
        }
        const result = await begin(
          id,
          request.method === 'POST' ? { headers: request.headers } : undefined,
        );
        const headers = {
          'cache-control': 'no-store',
          'set-cookie': `__Host-better-iam-saml-${hash(id).slice(0, 12)}=${result.binding}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=600`,
        };
        return request.method === 'POST'
          ? Response.json({ url: result.url }, { headers })
          : new Response(null, { status: 302, headers: { ...headers, location: result.url } });
      } catch (error) {
        return Response.json(
          { error: error instanceof IamError ? error.code : 'SAML_FAILED' },
          { status: error instanceof IamError ? error.status : 401 },
        );
      }
    },
  };
}

export type SamlService = ReturnType<typeof createSamlService>;
