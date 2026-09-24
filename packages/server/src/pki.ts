import { X509Certificate, createPublicKey } from 'node:crypto';
import { IamError, type IamStore, type Identity, type StoredRecord } from '@better-iam/core';
import type { ServerContext } from './context.js';
import { kmsSignFor } from './kms.js';
import {
  certificateDer,
  dnsName,
  pem,
  signedStructure,
  tbsCertList,
  type DistinguishedName,
  type RevocationReason,
  type SignatureAlgorithm,
  type SubjectAltNames,
} from './x509.js';
import { text } from './validation.js';

/**
 * A private certificate authority for workload identity (like AWS Private CA, step-ca or a SPIFFE server): tenant
 * certificate authorities whose signing keys are KMS keys, certificates issued from PKCS#10 requests with every name
 * decided by policy, SPIFFE workload certificates (SVIDs) for the caller's own identity, revocation, CRLs and chain
 * verification for mTLS. The API lives in api/pki.ts; the X.509 encoding in x509.ts.
 */

export type AuthorityState = 'active' | 'disabled' | 'revoked';
export type CertificateUsage = 'server' | 'client' | 'both';

export interface PkiAuthority extends StoredRecord {
  /** `name:{lowercase name}`, unique in the tenant. */
  uniqueKey: string;
  name: string;
  type: 'root' | 'intermediate';
  parentId?: string;
  subject: DistinguishedName;
  /** The subject name's DER (base64), reused byte for byte as the issuer of what this authority signs. */
  subjectDer: string;
  /** Hex SHA-1 key identifier of the authority's public key. */
  subjectKeyId: string;
  /** The KMS signing key and the version pinned for this authority (rotation never changes a CA's key). */
  keyId: string;
  keyVersion: number;
  algorithm: SignatureAlgorithm;
  certificatePem: string;
  serialNumber: string;
  notBefore: number;
  notAfter: number;
  pathLength?: number;
  state: AuthorityState;
  /** SPIFFE trust domain for workload certificates (`spiffe://{trustDomain}/…`). */
  trustDomain?: string;
  /** Written into issued certificates as their CRL distribution point. */
  crlUrl?: string;
  /** Names this authority (and everything below it) may certify: DNS suffixes and URI hosts. */
  permitted?: { dnsNames?: string[]; uriHosts?: string[] };
  maxValiditySeconds: number;
  defaultValiditySeconds: number;
  /** Bumped on every revocation, so the cached CRL is rebuilt. */
  revision: number;
  crlNumber: number;
  crl?: {
    der: string;
    thisUpdate: number;
    nextUpdate: number;
    revision: number;
    crlNumber: number;
  };
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}

export interface PkiCertificate extends StoredRecord {
  /** `serial:{hex}`. */
  uniqueKey: string;
  authorityId: string;
  serialNumber: string;
  commonName?: string;
  names: SubjectAltNames;
  keyType: string;
  usage: CertificateUsage | 'ca';
  notBefore: number;
  notAfter: number;
  certificatePem: string;
  fingerprint: string;
  /** Workload certificates: the identity the SPIFFE ID names. */
  identityId?: string;
  spiffeId?: string;
  /** A subordinate authority's own certificate. */
  subordinateId?: string;
  status: 'valid' | 'revoked';
  revokedAt?: number;
  revocationReason?: RevocationReason;
  revokedBy?: string;
  issuedAt: number;
  issuedBy: string;
}

export interface AuthoritySummary {
  id: string;
  tenantId: string;
  name: string;
  type: 'root' | 'intermediate';
  parentId?: string;
  subject: DistinguishedName;
  keyId: string;
  keyVersion: number;
  algorithm: SignatureAlgorithm;
  certificatePem: string;
  serialNumber: string;
  notBefore: number;
  notAfter: number;
  pathLength?: number;
  state: AuthorityState;
  trustDomain?: string;
  crlUrl?: string;
  permitted?: { dnsNames?: string[]; uriHosts?: string[] };
  maxValiditySeconds: number;
  defaultValiditySeconds: number;
  createdAt: number;
  createdBy: string;
}

export interface CertificateSummary {
  id: string;
  tenantId: string;
  authorityId: string;
  serialNumber: string;
  commonName?: string;
  names: SubjectAltNames;
  keyType: string;
  usage: CertificateUsage | 'ca';
  notBefore: number;
  notAfter: number;
  fingerprint: string;
  identityId?: string;
  spiffeId?: string;
  subordinateId?: string;
  status: 'valid' | 'revoked' | 'expired';
  revokedAt?: number;
  revocationReason?: RevocationReason;
  issuedAt: number;
  issuedBy: string;
  certificatePem: string;
}

export const pkiActions = Object.freeze({
  create: 'iam:pki:create',
  read: 'iam:pki:read',
  update: 'iam:pki:update',
  issue: 'iam:pki:issue',
  request: 'iam:pki:request',
  revoke: 'iam:pki:revoke',
});

export const MAX_AUTHORITIES_PER_TENANT = 50;
const DAY_SECONDS = 86_400;
/** Leaf certificates never outlive 825 days, the CA/Browser Forum's old ceiling. */
export const MAX_LEAF_VALIDITY_SECONDS = 825 * DAY_SECONDS;

export function summarizeAuthority(authority: PkiAuthority): AuthoritySummary {
  const summary: AuthoritySummary = {
    id: authority.id,
    tenantId: authority.tenantId,
    name: authority.name,
    type: authority.type,
    subject: { ...authority.subject },
    keyId: authority.keyId,
    keyVersion: authority.keyVersion,
    algorithm: authority.algorithm,
    certificatePem: authority.certificatePem,
    serialNumber: authority.serialNumber,
    notBefore: authority.notBefore,
    notAfter: authority.notAfter,
    state: authority.state,
    maxValiditySeconds: authority.maxValiditySeconds,
    defaultValiditySeconds: authority.defaultValiditySeconds,
    createdAt: authority.createdAt,
    createdBy: authority.createdBy,
  };
  if (authority.parentId !== undefined) summary.parentId = authority.parentId;
  if (authority.pathLength !== undefined) summary.pathLength = authority.pathLength;
  if (authority.trustDomain !== undefined) summary.trustDomain = authority.trustDomain;
  if (authority.crlUrl !== undefined) summary.crlUrl = authority.crlUrl;
  if (authority.permitted !== undefined) summary.permitted = structuredClone(authority.permitted);
  return summary;
}

export function summarizeCertificate(certificate: PkiCertificate, now: number): CertificateSummary {
  const summary: CertificateSummary = {
    id: certificate.id,
    tenantId: certificate.tenantId,
    authorityId: certificate.authorityId,
    serialNumber: certificate.serialNumber,
    names: structuredClone(certificate.names),
    keyType: certificate.keyType,
    usage: certificate.usage,
    notBefore: certificate.notBefore,
    notAfter: certificate.notAfter,
    fingerprint: certificate.fingerprint,
    status:
      certificate.status === 'revoked'
        ? 'revoked'
        : certificate.notAfter <= now
          ? 'expired'
          : 'valid',
    issuedAt: certificate.issuedAt,
    issuedBy: certificate.issuedBy,
    certificatePem: certificate.certificatePem,
  };
  if (certificate.commonName !== undefined) summary.commonName = certificate.commonName;
  if (certificate.identityId !== undefined) summary.identityId = certificate.identityId;
  if (certificate.spiffeId !== undefined) summary.spiffeId = certificate.spiffeId;
  if (certificate.subordinateId !== undefined) summary.subordinateId = certificate.subordinateId;
  if (certificate.revokedAt !== undefined) summary.revokedAt = certificate.revokedAt;
  if (certificate.revocationReason !== undefined)
    summary.revocationReason = certificate.revocationReason;
  return summary;
}

/** The attributes an authority presents to policies (`resource.{name}`). */
export function authorityAttributes(authority: PkiAuthority): Record<string, unknown> {
  const attributes: Record<string, unknown> = {
    authorityId: authority.id,
    authorityName: authority.name,
    authorityType: authority.type,
    authorityState: authority.state,
  };
  if (authority.trustDomain) attributes.trustDomain = authority.trustDomain;
  return attributes;
}

/** A distinguished name: `commonName` required for authorities, every part within X.520 bounds. */
export function distinguishedName(value: unknown, requireCommonName: boolean): DistinguishedName {
  if (value === undefined && !requireCommonName) return {};
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new IamError('INVALID_INPUT', 'subject must be an object');
  const input = value as Record<string, unknown>;
  const allowed = [
    'commonName',
    'organization',
    'organizationalUnit',
    'locality',
    'state',
    'country',
  ];
  for (const key of Object.keys(input))
    if (!allowed.includes(key)) throw new IamError('INVALID_INPUT', `Unknown subject field ${key}`);
  const part = (key: string, max: number) =>
    input[key] === undefined ? undefined : text(input[key], `subject.${key}`, max).trim();
  const name: DistinguishedName = {};
  const commonName = part('commonName', 64);
  if (commonName) name.commonName = commonName;
  else if (requireCommonName) throw new IamError('INVALID_INPUT', 'subject.commonName is required');
  const organization = part('organization', 64);
  if (organization) name.organization = organization;
  const unit = part('organizationalUnit', 64);
  if (unit) name.organizationalUnit = unit;
  const locality = part('locality', 128);
  if (locality) name.locality = locality;
  const state = part('state', 128);
  if (state) name.state = state;
  const country = part('country', 2);
  if (country) {
    if (!/^[A-Z]{2}$/.test(country))
      throw new IamError('INVALID_INPUT', 'subject.country must be a two-letter ISO code');
    name.country = country;
  }
  return name;
}

const trustDomainPattern = /^[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?$/;
export function trustDomain(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  const domain = text(value, 'trustDomain', 255).toLowerCase();
  if (!trustDomainPattern.test(domain))
    throw new IamError(
      'INVALID_INPUT',
      'trustDomain must be lowercase letters, digits, dots, hyphens or underscores',
    );
  return domain;
}

export function httpUrl(value: unknown, name: string): string | undefined {
  if (value === undefined) return undefined;
  const raw = text(value, name, 2048);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new IamError('INVALID_INPUT', `${name} must be an http(s) URL`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:')
    throw new IamError('INVALID_INPUT', `${name} must be an http(s) URL`);
  return url.href;
}

/** Name constraints: DNS suffixes (`example.internal`, matching it and its subdomains) and URI hosts. */
export function permittedNames(
  value: unknown,
): { dnsNames?: string[]; uriHosts?: string[] } | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new IamError('INVALID_INPUT', 'permitted must be an object');
  const input = value as Record<string, unknown>;
  const list = (key: string) => {
    const items = input[key];
    if (items === undefined) return undefined;
    if (!Array.isArray(items) || items.length > 50)
      throw new IamError('INVALID_INPUT', `permitted.${key} must list at most 50 names`);
    return items.map((item) => {
      const name = text(item, `permitted.${key}`, 253).toLowerCase().replace(/^\./, '');
      if (!/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(name))
        throw new IamError('INVALID_INPUT', `Invalid permitted name ${name}`);
      return name;
    });
  };
  const dnsNames = list('dnsNames');
  const uriHosts = list('uriHosts');
  if (!dnsNames?.length && !uriHosts?.length) return undefined;
  return { ...(dnsNames?.length ? { dnsNames } : {}), ...(uriHosts?.length ? { uriHosts } : {}) };
}

const withinSuffix = (host: string, suffix: string) =>
  host === suffix || host.endsWith(`.${suffix}`);

/**
 * Checks names against the name constraints of an authority and every authority above it. A constraint list
 * applies to its kind of name only: DNS names against `dnsNames`, URI hosts against `uriHosts`. A common name that
 * looks like a host name counts as a DNS name, because TLS clients still fall back to it.
 */
export function namesPermitted(
  chain: PkiAuthority[],
  names: SubjectAltNames,
  commonName?: string,
): boolean {
  const hostLike = commonName && dnsName.test(commonName.toLowerCase()) ? [commonName.toLowerCase()] : [];
  for (const authority of chain) {
    const permitted = authority.permitted;
    if (!permitted) continue;
    if (permitted.dnsNames)
      for (const name of [...names.dnsNames, ...hostLike]) {
        const host = name.replace(/^\*\./, '');
        if (!permitted.dnsNames.some((suffix) => withinSuffix(host, suffix))) return false;
      }
    if (permitted.uriHosts)
      for (const uri of names.uris) {
        const host = new URL(uri).hostname.toLowerCase();
        if (!permitted.uriHosts.some((suffix) => withinSuffix(host, suffix))) return false;
      }
  }
  return true;
}

/** The authority and its parents up to the root. */
export async function authorityChain(
  tx: IamStore,
  authority: PkiAuthority,
): Promise<PkiAuthority[]> {
  const chain = [authority];
  let current = authority;
  while (current.parentId) {
    const parent = await tx.get<PkiAuthority>('pkiAuthorities', current.parentId);
    if (!parent || parent.tenantId !== authority.tenantId || chain.length > 10)
      throw new IamError('INVALID_HIERARCHY', 'The authority chain is broken', 500);
    chain.push(parent);
    current = parent;
  }
  return chain;
}

/** Usable for signing: active, within its validity, and every authority above it active too. */
export function assertAuthorityUsable(chain: PkiAuthority[], now: number): void {
  for (const authority of chain) {
    if (authority.state !== 'active')
      throw new IamError(
        'AUTHORITY_UNAVAILABLE',
        `The certificate authority ${authority.name} is ${authority.state}`,
        409,
      );
    if (authority.notAfter <= now)
      throw new IamError(
        'AUTHORITY_UNAVAILABLE',
        `The certificate authority ${authority.name} has expired`,
        409,
      );
  }
}

export async function findAuthority(
  tx: IamStore,
  tenantId: string,
  authorityId: unknown,
): Promise<PkiAuthority> {
  const authority = await tx.get<PkiAuthority>('pkiAuthorities', text(authorityId, 'authorityId'));
  if (!authority || authority.tenantId !== tenantId)
    throw new IamError('NOT_FOUND', 'Certificate authority not found', 404);
  return authority;
}

/** The signature an authority's KMS key makes over `data`, audited on the key as used by `pki`. */
export function authoritySigner(ctx: ServerContext, tx: IamStore, authority: PkiAuthority) {
  return (data: Buffer, principal?: Parameters<typeof kmsSignFor>[7]['principal']) =>
    kmsSignFor(
      ctx,
      tx,
      authority.tenantId,
      authority.keyId,
      authority.keyVersion,
      authority.algorithm,
      data,
      { via: 'pki', ...(principal ? { principal } : {}) },
    );
}

const CRL_LIFETIME_MS = 24 * 3_600_000;
const CRL_REFRESH_MS = 12 * 3_600_000;

/**
 * The authority's current CRL (DER), rebuilt when a certificate was revoked since the last one or half its
 * lifetime has passed. Lists every revoked certificate that has not expired yet.
 */
export async function currentCrl(
  ctx: ServerContext,
  tx: IamStore,
  authority: PkiAuthority,
): Promise<{ der: Buffer; thisUpdate: number; nextUpdate: number; crlNumber: number }> {
  const now = ctx.now();
  const cached = authority.crl;
  if (cached && cached.revision === authority.revision && now < cached.thisUpdate + CRL_REFRESH_MS)
    return { ...cached, der: Buffer.from(cached.der, 'base64') };
  const revoked = (
    await tx.find<PkiCertificate>('pkiCertificates', {
      tenantId: authority.tenantId,
      authorityId: authority.id,
      status: 'revoked',
    })
  )
    .filter((certificate) => certificate.notAfter > now)
    .sort((a, b) => (a.serialNumber < b.serialNumber ? -1 : 1))
    .map((certificate) => ({
      serialNumber: certificate.serialNumber,
      revokedAt: certificate.revokedAt ?? now,
      ...(certificate.revocationReason ? { reason: certificate.revocationReason } : {}),
    }));
  const crlNumber = authority.crlNumber + 1;
  const tbs = tbsCertList(
    {
      issuer: Buffer.from(authority.subjectDer, 'base64'),
      thisUpdate: now,
      nextUpdate: now + CRL_LIFETIME_MS,
      crlNumber,
      authorityKeyId: Buffer.from(authority.subjectKeyId, 'hex'),
      revoked,
    },
    authority.algorithm,
  );
  const signature = await authoritySigner(ctx, tx, authority)(tbs);
  const der = signedStructure(tbs, authority.algorithm, signature);
  const crl = {
    der: der.toString('base64'),
    thisUpdate: now,
    nextUpdate: now + CRL_LIFETIME_MS,
    revision: authority.revision,
    crlNumber,
  };
  await tx.put<PkiAuthority>('pkiAuthorities', { ...authority, crlNumber, crl });
  return { der, thisUpdate: crl.thisUpdate, nextUpdate: crl.nextUpdate, crlNumber };
}

export interface CertificateVerification {
  tenantId: string;
  authorityId: string;
  serialNumber: string;
  fingerprint: string;
  subject: string;
  spiffeId?: string;
  identityId?: string;
  dnsNames: string[];
  uris: string[];
  notAfter: number;
}

function sanList(certificate: X509Certificate, prefix: 'DNS' | 'URI'): string[] {
  const text = certificate.subjectAltName ?? '';
  return text
    .split(', ')
    .filter((entry) => entry.startsWith(`${prefix}:`))
    .map((entry) => entry.slice(prefix.length + 1));
}

/**
 * Verifies a client or server certificate chain (leaf first, PEM concatenated or as a list) against one tenant's
 * certificate authorities: every signature, path length, validity period, authority state and revocation, and for a
 * workload certificate the standing of the identity it names. For mTLS: a server that terminates TLS passes the
 * peer's certificate and gets the identity behind a workload certificate.
 */
export async function verifyCertificateChain(
  ctx: ServerContext,
  chain: string | string[],
  options: { tenantId: string; usage?: 'server' | 'client'; at?: number },
): Promise<CertificateVerification> {
  // Trust is per tenant: without a tenant, one organization's authority could vouch for another's names.
  const tenantId = text(options?.tenantId, 'tenantId');
  const pems = (Array.isArray(chain) ? chain : [chain])
    .flatMap(
      (entry) => entry.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [],
    )
    .slice(0, 10);
  if (!pems.length) throw new IamError('CERTIFICATE_INVALID', 'No certificate was presented', 401);
  let leaf: X509Certificate;
  try {
    leaf = new X509Certificate(pems[0]!);
  } catch {
    throw new IamError('CERTIFICATE_INVALID', 'The certificate cannot be read', 401);
  }
  const now = options.at ?? ctx.now();
  const serialNumber = leaf.serialNumber.toLowerCase().replace(/^0+(?=.)/, '');
  return ctx.store.transaction(async (tx) => {
    const records = (
      await tx.find<PkiCertificate>('pkiCertificates', {
        tenantId,
        uniqueKey: `serial:${serialNumber}`,
      })
    ).filter((record) => certificateDer(record.certificatePem).equals(leaf.raw));
    const record = records[0];
    if (!record)
      throw new IamError('CERTIFICATE_INVALID', 'The certificate was not issued here', 401);
    if (record.status === 'revoked')
      throw new IamError('CERTIFICATE_INVALID', 'The certificate has been revoked', 401);
    if (record.usage === 'ca')
      throw new IamError('CERTIFICATE_INVALID', 'A CA certificate cannot authenticate', 401);
    if (options.usage && record.usage !== 'both' && record.usage !== options.usage)
      throw new IamError(
        'CERTIFICATE_INVALID',
        `The certificate is not for ${options.usage} use`,
        401,
      );
    if (Date.parse(leaf.validFrom) > now || Date.parse(leaf.validTo) <= now)
      throw new IamError('CERTIFICATE_INVALID', 'The certificate is not valid at this time', 401);
    const authority = await tx.get<PkiAuthority>('pkiAuthorities', record.authorityId);
    if (!authority || authority.tenantId !== record.tenantId)
      throw new IamError('CERTIFICATE_INVALID', 'The issuing authority is gone', 401);
    // Walk the stored chain (not whatever the client sent): each link must verify, be live, and allow the number of
    // authorities below it (its path length).
    let child = leaf;
    for (const [index, link] of (await authorityChain(tx, authority)).entries()) {
      const issuer = new X509Certificate(link.certificatePem);
      if (!child.checkIssued(issuer) || !child.verify(issuer.publicKey))
        throw new IamError('CERTIFICATE_INVALID', 'The certificate chain does not verify', 401);
      if (link.state !== 'active' || link.notAfter <= now || link.notBefore > now + 60_000)
        throw new IamError('CERTIFICATE_INVALID', 'An issuing authority is not active', 401);
      if (link.pathLength !== undefined && index > link.pathLength)
        throw new IamError('CERTIFICATE_INVALID', 'The chain exceeds a path length', 401);
      child = issuer;
    }
    if (!child.verify(child.publicKey))
      throw new IamError('CERTIFICATE_INVALID', 'The root does not verify', 401);
    // A workload certificate is only as good as the identity it names.
    if (record.identityId) {
      const identity = await tx.get<Identity>('identities', record.identityId);
      if (
        !identity ||
        identity.tenantId !== record.tenantId ||
        identity.status !== 'active' ||
        ctx.identityExpired(identity) ||
        Boolean(identity.agent?.suspended)
      )
        throw new IamError('CERTIFICATE_INVALID', 'The identity it names is no longer active', 401);
    }
    const result: CertificateVerification = {
      tenantId: record.tenantId,
      authorityId: record.authorityId,
      serialNumber: record.serialNumber,
      fingerprint: record.fingerprint,
      subject: leaf.subject ?? '',
      dnsNames: sanList(leaf, 'DNS'),
      uris: sanList(leaf, 'URI'),
      notAfter: record.notAfter,
    };
    if (record.spiffeId) result.spiffeId = record.spiffeId;
    if (record.identityId) result.identityId = record.identityId;
    return result;
  });
}

/** The DER SubjectPublicKeyInfo of a KMS key version's public key. */
export const spkiOf = (publicKeyPem: string): Buffer =>
  createPublicKey(publicKeyPem).export({ format: 'der', type: 'spki' });

export const certificatePem = (der: Buffer) => pem('CERTIFICATE', der);
export const crlPem = (der: Buffer) => pem('X509 CRL', der);

/** The X.509 signature algorithm a KMS signing key uses for certificates. */
export function algorithmForSpec(spec: string): SignatureAlgorithm {
  if (spec === 'ecc-p256') return 'ES256';
  if (spec === 'ecc-p384') return 'ES384';
  if (spec === 'ed25519') return 'EdDSA';
  if (spec.startsWith('rsa-')) return 'RS256';
  throw new IamError(
    'INVALID_INPUT',
    'A certificate authority needs an ECDSA, Ed25519 or RSA signing key',
  );
}
