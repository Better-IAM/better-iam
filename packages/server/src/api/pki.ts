import { X509Certificate } from 'node:crypto';
import { IamError, type CredentialInput, type IamStore, type Json } from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { createGuard, type GuardTarget } from '../guarded.js';
import {
  actsInOwnRight,
  aliasNames,
  assertUnmanaged,
  assertUsable,
  createServiceKey,
  findKey,
  keyAttributes,
  keySpec as parseKeySpec,
  keyVersion,
  kmsActions,
  kmsSignFor,
  type KeySpec,
} from '../kms.js';
import {
  MAX_AUTHORITIES_PER_TENANT,
  MAX_LEAF_VALIDITY_SECONDS,
  algorithmForSpec,
  assertAuthorityUsable,
  authorityAttributes,
  authorityChain,
  authoritySigner,
  certificatePem,
  crlPem,
  currentCrl,
  distinguishedName,
  findAuthority,
  httpUrl,
  namesPermitted,
  permittedNames,
  pkiActions,
  spkiOf,
  summarizeAuthority,
  summarizeCertificate,
  trustDomain as parseTrustDomain,
  verifyCertificateChain,
  type AuthorityState,
  type AuthoritySummary,
  type CertificateSummary,
  type CertificateUsage,
  type CertificateVerification,
  type PkiAuthority,
  type PkiCertificate,
} from '../pki.js';
import { OperationDenied } from '../operations.js';
import { id } from '../utils.js';
import { integer, text } from '../validation.js';
import {
  encodeName,
  keyIdentifier,
  parseCertificateRequest,
  randomSerial,
  revocationReasons,
  sha256Fingerprint,
  signedStructure,
  subjectAltNames,
  tbsCertificate,
  type DistinguishedName,
  type RevocationReason,
  type SubjectAltNames,
} from '../x509.js';

const DAY_MS = 86_400_000;
const CLOCK_SKEW_MS = 60_000;

interface PkiTarget extends GuardTarget {
  authority?: PkiAuthority;
}

export interface AuthorityCreateInput {
  tenantId: string;
  name: string;
  /** Defaults to `intermediate` with a `parentId`, `root` otherwise. */
  type?: 'root' | 'intermediate';
  parentId?: string;
  subject: DistinguishedName;
  /** A new KMS signing key of this kind (default `ecc-p256`), unless `keyId` names an existing one. */
  keySpec?: KeySpec;
  /** An existing KMS signing key (id or alias) the caller may sign with; its current version is pinned. */
  keyId?: string;
  /** Roots default to ten years (up to thirty), intermediates to five (never past their parent). */
  validityDays?: number;
  pathLength?: number;
  trustDomain?: string;
  crlUrl?: string;
  permitted?: { dnsNames?: string[]; uriHosts?: string[] };
  /** Longest leaf certificate this authority issues (default 90 days, at most 825). */
  maxValiditySeconds?: number;
  /** Leaf validity when a request names none (default one day). */
  defaultValiditySeconds?: number;
}

export interface CertificateIssueInput extends Partial<SubjectAltNames> {
  tenantId: string;
  authorityId: string;
  /** A PEM PKCS#10 request: proof that the requester holds the private key. */
  csr: string;
  /** Overrides the request's subject common name. */
  commonName?: string;
  validitySeconds?: number;
  /** `both` (default), `server` or `client` (extended key usage). */
  usage?: CertificateUsage;
}

export interface IssuedCertificate {
  id: string;
  serialNumber: string;
  certificatePem: string;
  /** The issuing authority and those above it, below the root, leaf's issuer first. */
  chainPem: string;
  /** The root certificate to trust. */
  rootPem: string;
  notBefore: number;
  notAfter: number;
  fingerprint: string;
  spiffeId?: string;
}

const validityDays = (value: unknown, fallback: number, max: number) =>
  value === undefined ? fallback : integer(value, 'validityDays', 1, max);

/**
 * The names a certificate carries, each decided on its own. A wildcard DNS name (`*.internal`) is its own name type,
 * never `dns`: it covers hosts a policy may deny one by one, so policies allow wildcard certificates explicitly.
 */
function nameEntries(commonName: string | undefined, names: SubjectAltNames) {
  return [
    ...(commonName ? [{ nameType: 'commonName', name: commonName }] : []),
    ...names.dnsNames.map((name) => ({
      nameType: name.startsWith('*.') ? 'wildcard' : 'dns',
      name,
    })),
    ...names.uris.map((name) => ({ nameType: 'uri', name })),
    ...names.ipAddresses.map((name) => ({ nameType: 'ip', name })),
    ...names.emails.map((name) => ({ nameType: 'email', name })),
  ];
}

function usageOf(value: unknown): CertificateUsage {
  if (value === undefined) return 'both';
  if (value !== 'server' && value !== 'client' && value !== 'both')
    throw new IamError('INVALID_INPUT', 'usage must be server, client or both');
  return value;
}

/**
 * The private certificate authority (pki.ts). Authorities are `iam/pki/{authorityId}`; issuing decides
 * `iam:pki:issue` once for every name on the certificate (the common name and each subject alternative name), with
 * `resource.name` and `resource.nameType` (`commonName`, `dns`, `uri`, `ip`, `email`) plus the authority's attributes
 * and `resource.usage`, `resource.validitySeconds` and `resource.keyType`, so policies can say which names a caller
 * may certify. Workload certificates (`requestCertificate`) name the caller's own identity as a SPIFFE ID and need
 * `iam:pki:request`. Signing keys are KMS keys, pinned to one version per authority.
 */
export function createPkiApi(ctx: ServerContext) {
  const guard = createGuard<PkiTarget>(ctx, 'pki', {
    describe: (target): Record<string, Json> =>
      target.authority ? { authorityId: target.authority.id } : {},
    // Refusals after authorization are evidence too.
    recordedFailures: {
      NAME_NOT_PERMITTED: 'name-not-permitted',
      INVALID_CSR: 'invalid-csr',
      INVALID_INPUT: 'invalid-input',
      AUTHORITY_UNAVAILABLE: 'authority-unavailable',
      KEY_STATE_INVALID: 'key-state',
    },
  });

  const authorityTarget =
    (tenantId: string, authorityId: unknown, extra: Record<string, unknown> = {}) =>
    async (tx: IamStore): Promise<PkiTarget> => {
      const authority = await findAuthority(tx, text(tenantId, 'tenantId'), authorityId);
      return {
        resourceId: `pki/${authority.id}`,
        attributes: { ...authorityAttributes(authority), ...extra },
        authority,
      };
    };

  /** Signs a leaf certificate for `spki` with `names` under an authority whose chain is usable. */
  async function issue(
    tx: IamStore,
    authority: PkiAuthority,
    request: {
      spki: Buffer;
      keyType: string;
      commonName?: string;
      names: SubjectAltNames;
      usage: CertificateUsage;
      validitySeconds: number;
      identityId?: string;
      spiffeId?: string;
      /** The latest the certificate may be valid until (the credential or identity it stands for ends then). */
      notAfterCap?: number;
      issuedBy: string;
      principal: Parameters<ReturnType<typeof authoritySigner>>[1];
    },
  ): Promise<IssuedCertificate> {
    const now = ctx.now();
    const chain = await authorityChain(tx, authority);
    assertAuthorityUsable(chain, now);
    if (!namesPermitted(chain, request.names, request.commonName))
      throw new IamError(
        'NAME_NOT_PERMITTED',
        "A requested name is outside the authority's name constraints",
        403,
      );
    const notAfter = Math.min(
      now + request.validitySeconds * 1000,
      authority.notAfter,
      request.notAfterCap ?? Infinity,
    );
    if (notAfter <= now + 60_000)
      throw new IamError('INVALID_INPUT', 'The certificate would expire within a minute');
    const serialNumber = randomSerial();
    const tbs = tbsCertificate(
      {
        serialNumber,
        issuer: Buffer.from(authority.subjectDer, 'base64'),
        subject: request.commonName ? { commonName: request.commonName } : {},
        spki: request.spki,
        notBefore: now - CLOCK_SKEW_MS,
        notAfter,
        names: request.names,
        usage: request.usage,
        authorityKeyId: Buffer.from(authority.subjectKeyId, 'hex'),
        ...(authority.crlUrl ? { crlUrl: authority.crlUrl } : {}),
      },
      authority.algorithm,
    );
    const der = signedStructure(
      tbs,
      authority.algorithm,
      await authoritySigner(ctx, tx, authority)(tbs, request.principal),
    );
    const pemText = certificatePem(der);
    const record: PkiCertificate = {
      id: id(),
      tenantId: authority.tenantId,
      uniqueKey: `serial:${serialNumber}`,
      authorityId: authority.id,
      serialNumber,
      names: request.names,
      keyType: request.keyType,
      usage: request.usage,
      notBefore: now - CLOCK_SKEW_MS,
      notAfter,
      certificatePem: pemText,
      fingerprint: sha256Fingerprint(der),
      status: 'valid',
      issuedAt: now,
      issuedBy: request.issuedBy,
    };
    if (request.commonName) record.commonName = request.commonName;
    if (request.identityId) record.identityId = request.identityId;
    if (request.spiffeId) record.spiffeId = request.spiffeId;
    await tx.insert('pkiCertificates', record);
    const intermediates = chain.filter((link) => link.type === 'intermediate');
    const result: IssuedCertificate = {
      id: record.id,
      serialNumber,
      certificatePem: pemText,
      chainPem: intermediates.map((link) => link.certificatePem).join(''),
      rootPem: chain.at(-1)!.certificatePem,
      notBefore: record.notBefore,
      notAfter,
      fingerprint: record.fingerprint,
    };
    if (request.spiffeId) result.spiffeId = request.spiffeId;
    return result;
  }

  function leafValidity(authority: PkiAuthority, value: unknown): number {
    if (value === undefined) return authority.defaultValiditySeconds;
    return integer(value, 'validitySeconds', 60, authority.maxValiditySeconds);
  }

  /**
   * SPIFFE SVID rules: one URI per certificate, only in the authority's trust domain, and never in the paths
   * `/user/`, `/service/` and `/agent/`, which name identities and are issued only to those identities themselves
   * (`requestCertificate`).
   */
  function spiffeRules(authority: PkiAuthority, names: SubjectAltNames) {
    const spiffe = names.uris.filter((uri) => uri.toLowerCase().startsWith('spiffe://'));
    if (!spiffe.length) return;
    if (names.uris.length !== 1)
      throw new IamError('INVALID_INPUT', 'A SPIFFE certificate carries exactly one URI');
    const [, , host = '', segment = ''] = spiffe[0]!.split('/');
    if (!authority.trustDomain || host !== authority.trustDomain)
      throw new IamError(
        'NAME_NOT_PERMITTED',
        `This authority issues SPIFFE IDs only in ${authority.trustDomain ?? 'no trust domain'}`,
        403,
      );
    if (['user', 'service', 'agent'].includes(segment))
      throw new IamError(
        'NAME_NOT_PERMITTED',
        `spiffe://${host}/${segment}/… names an identity; it is issued only to that identity (requestCertificate)`,
        403,
      );
  }

  /** The SPIFFE ID of an identity's own workload certificate. */
  const workloadId = (authority: PkiAuthority, identity: { id: string; kind: string }) =>
    `spiffe://${authority.trustDomain}/${identity.kind}/${identity.id}`;

  return {
    /**
     * Creates a certificate authority: a self-signed root, or an intermediate signed by a `parentId` authority in
     * the tenant (which needs iam:pki:update on the parent and respects its path length). The signing key is a new
     * KMS key (`keySpec`, default `ecc-p256`) or an existing one the caller may sign with (`keyId`); its current
     * version is pinned, so rotating the KMS key never changes the authority. Requires iam:pki:create on `iam/pki`
     * and recent authentication.
     */
    async createAuthority(
      credential: CredentialInput,
      input: AuthorityCreateInput,
    ): Promise<AuthoritySummary> {
      const name = text(input.name, 'name', 128).trim();
      const type = input.type ?? (input.parentId === undefined ? 'root' : 'intermediate');
      if (type !== 'root' && type !== 'intermediate')
        throw new IamError('INVALID_INPUT', 'type must be root or intermediate');
      if ((type === 'intermediate') !== (input.parentId !== undefined))
        throw new IamError(
          'INVALID_INPUT',
          'An intermediate authority needs a parentId; a root has none',
        );
      const subject = distinguishedName(input.subject, true);
      const spec =
        input.keyId === undefined ? parseKeySpec(input.keySpec ?? 'ecc-p256') : undefined;
      if (spec) algorithmForSpec(spec);
      const pathLength =
        input.pathLength === undefined ? undefined : integer(input.pathLength, 'pathLength', 0, 10);
      const domain = parseTrustDomain(input.trustDomain);
      const crlUrl = httpUrl(input.crlUrl, 'crlUrl');
      const permitted = permittedNames(input.permitted);
      const maxValiditySeconds =
        input.maxValiditySeconds === undefined
          ? 90 * 86_400
          : integer(input.maxValiditySeconds, 'maxValiditySeconds', 60, MAX_LEAF_VALIDITY_SECONDS);
      const defaultValiditySeconds =
        input.defaultValiditySeconds === undefined
          ? Math.min(86_400, maxValiditySeconds)
          : integer(input.defaultValiditySeconds, 'defaultValiditySeconds', 60, maxValiditySeconds);
      return guard.run(
        credential,
        input.tenantId,
        pkiActions.create,
        async () => ({
          resourceId: 'pki',
          attributes: {
            authorityType: type,
            ...(spec ? { keySpec: spec } : {}),
            ...(domain ? { trustDomain: domain } : {}),
          },
        }),
        async (call) => {
          const { tx, principal, tenant, metadata } = call;
          ctx.auth.requireRecent(principal);
          if (
            (await tx.find<PkiAuthority>('pkiAuthorities', { tenantId: tenant.id })).length >=
            MAX_AUTHORITIES_PER_TENANT
          )
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant keeps at most ${MAX_AUTHORITIES_PER_TENANT} certificate authorities`,
              409,
            );
          const uniqueKey = `name:${name.toLowerCase()}`;
          if ((await tx.find('pkiAuthorities', { tenantId: tenant.id, uniqueKey })).length)
            throw new IamError('CONFLICT', 'A certificate authority with that name exists', 409);
          // A SPIFFE trust domain names one organization's workloads: no other tenant may claim it.
          if (
            domain &&
            (await tx.find<PkiAuthority>('pkiAuthorities', { trustDomain: domain })).some(
              (other) => other.tenantId !== tenant.id,
            )
          )
            throw new IamError('CONFLICT', 'Another organization uses that trust domain', 409);
          const now = ctx.now();
          const authorityId = id();
          let parent: PkiAuthority | undefined;
          let parentChain: PkiAuthority[] = [];
          let childPathLength = pathLength;
          if (type === 'intermediate') {
            parent = await findAuthority(tx, tenant.id, input.parentId);
            parentChain = await authorityChain(tx, parent);
            assertAuthorityUsable(parentChain, now);
            // Every authority above bounds how many authorities may sit below it: the new one is the (i+1)-th below
            // the ancestor at index i, which leaves `pathLength - (i + 1)` levels for everything under it.
            let remaining = Infinity;
            for (const [index, ancestor] of parentChain.entries())
              if (ancestor.pathLength !== undefined)
                remaining = Math.min(remaining, ancestor.pathLength - (index + 1));
            if (remaining < 0)
              throw new IamError(
                'INVALID_INPUT',
                'An authority above allows no more levels of subordinate authorities (path length)',
              );
            if (pathLength !== undefined && pathLength > remaining)
              throw new IamError(
                'INVALID_INPUT',
                'pathLength exceeds what the authorities above allow',
              );
            if (childPathLength === undefined && remaining !== Infinity)
              childPathLength = remaining;
            if (
              !(await call.allowed(pkiActions.update, {
                resourceId: `pki/${parent.id}`,
                attributes: authorityAttributes(parent),
              }))
            )
              throw new OperationDenied('You may not add authorities under that parent');
          }
          // The signing key: a new KMS key, or an existing one the caller may sign with.
          let key;
          if (input.keyId !== undefined) {
            key = await findKey(tx, tenant.id, input.keyId);
            assertUsable(key, 'sign');
            // One key, one authority; and a key others use cannot become a CA key without their knowing.
            assertUnmanaged(key);
            const algorithm = algorithmForSpec(key.keySpec);
            if (
              !(await call.allowed(kmsActions.sign, {
                resourceId: `kms/${key.id}`,
                attributes: keyAttributes(key, await aliasNames(tx, key), { algorithm }),
              }))
            )
              throw new OperationDenied('You may not sign with that key');
            // From now on the key signs only through this authority: raw KMS signatures could forge certificates.
            key = { ...key, managedBy: 'pki' as const, managedId: authorityId, updatedAt: now };
            await tx.put('kmsKeys', key);
          } else
            key = await createServiceKey(ctx, tx, {
              tenantId: tenant.id,
              keySpec: spec!,
              keyUsage: 'sign',
              description: `Certificate authority: ${name}`.slice(0, 512),
              tags: { 'pki-authority': name.slice(0, 256) },
              createdBy: principal.identity.id,
              managedBy: 'pki',
              managedId: authorityId,
            });
          const version = await keyVersion(tx, key, key.currentVersion);
          const algorithm = algorithmForSpec(key.keySpec);
          const spki = spkiOf(version.publicKeyPem!);
          const subjectDer = encodeName(subject);
          const subjectKeyId = keyIdentifier(spki);
          const days =
            type === 'root'
              ? validityDays(input.validityDays, 3650, 10_950)
              : validityDays(input.validityDays, 1825, 10_950);
          const notAfter = Math.min(now + days * DAY_MS, parent?.notAfter ?? Infinity);
          const serialNumber = randomSerial();
          const tbs = tbsCertificate(
            {
              serialNumber,
              issuer: parent ? Buffer.from(parent.subjectDer, 'base64') : subjectDer,
              subject,
              spki,
              notBefore: now - CLOCK_SKEW_MS,
              notAfter,
              ca: childPathLength === undefined ? {} : { pathLength: childPathLength },
              ...(parent ? { authorityKeyId: Buffer.from(parent.subjectKeyId, 'hex') } : {}),
              ...(parent?.crlUrl ? { crlUrl: parent.crlUrl } : {}),
              ...(permitted && parent ? { permitted } : {}),
            },
            algorithm,
          );
          const signature = parent
            ? await authoritySigner(ctx, tx, parent)(tbs, principal)
            : await kmsSignFor(ctx, tx, tenant.id, key.id, version.version, algorithm, tbs, {
                via: 'pki',
                principal,
              });
          const der = signedStructure(tbs, algorithm, signature);
          const pemText = certificatePem(der);
          // Node reads it back, or the encoding is wrong: fail before storing anything.
          const parsed = new X509Certificate(pemText);
          if (!parsed.ca)
            throw new IamError('INTERNAL_ERROR', 'The CA certificate is malformed', 500);
          const authority: PkiAuthority = {
            id: authorityId,
            tenantId: tenant.id,
            uniqueKey,
            name,
            type,
            subject,
            subjectDer: subjectDer.toString('base64'),
            subjectKeyId: subjectKeyId.toString('hex'),
            keyId: key.id,
            keyVersion: version.version,
            algorithm,
            certificatePem: pemText,
            serialNumber,
            notBefore: now - CLOCK_SKEW_MS,
            notAfter,
            state: 'active',
            maxValiditySeconds,
            defaultValiditySeconds,
            revision: 0,
            crlNumber: 0,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
          };
          if (parent) authority.parentId = parent.id;
          if (childPathLength !== undefined) authority.pathLength = childPathLength;
          if (domain) authority.trustDomain = domain;
          if (crlUrl) authority.crlUrl = crlUrl;
          if (permitted) authority.permitted = permitted;
          await tx.insert('pkiAuthorities', authority);
          if (parent)
            await tx.insert<PkiCertificate>('pkiCertificates', {
              id: id(),
              tenantId: tenant.id,
              uniqueKey: `serial:${serialNumber}`,
              authorityId: parent.id,
              serialNumber,
              commonName: subject.commonName,
              names: { dnsNames: [], uris: [], ipAddresses: [], emails: [] },
              keyType: key.keySpec,
              usage: 'ca',
              notBefore: now - CLOCK_SKEW_MS,
              notAfter,
              certificatePem: pemText,
              fingerprint: sha256Fingerprint(der),
              subordinateId: authority.id,
              status: 'valid',
              issuedAt: now,
              issuedBy: principal.identity.id,
            });
          Object.assign(metadata, {
            authorityId: authority.id,
            name,
            type,
            keyId: key.id,
            serialNumber,
            ...(parent ? { parentId: parent.id } : {}),
            ...(childPathLength !== undefined ? { pathLength: childPathLength } : {}),
            ...(domain ? { trustDomain: domain } : {}),
            ...(crlUrl ? { crlUrl } : {}),
            ...(permitted ? { permitted: structuredClone(permitted) as Json } : {}),
          });
          return summarizeAuthority(authority);
        },
      );
    },

    /** The tenant's certificate authorities the caller may read (`iam:pki:read`, per authority). */
    async listAuthorities(
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<AuthoritySummary[]> {
      return guard.visible(credential, input.tenantId, pkiActions.read, 'pki', async (tx, tenant) =>
        (await tx.find<PkiAuthority>('pkiAuthorities', { tenantId: tenant.id }))
          .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1))
          .map((authority) => ({
            item: summarizeAuthority(authority),
            target: {
              resourceId: `pki/${authority.id}`,
              attributes: authorityAttributes(authority),
            },
          })),
      );
    },

    /** One certificate authority. Requires iam:pki:read. */
    async getAuthority(
      credential: CredentialInput,
      input: { tenantId: string; authorityId: string },
    ): Promise<AuthoritySummary> {
      return guard.run(
        credential,
        input.tenantId,
        pkiActions.read,
        authorityTarget(input.tenantId, input.authorityId),
        async (_call, { authority }) => summarizeAuthority(authority!),
      );
    },

    /**
     * Disables or re-enables an authority (`state`; a disabled authority issues nothing and its certificates stop
     * verifying), and changes the leaf validity limits or the CRL URL for future certificates (`crlUrl: null`
     * clears it). Requires iam:pki:update.
     */
    async updateAuthority(
      credential: CredentialInput,
      input: {
        tenantId: string;
        authorityId: string;
        state?: 'active' | 'disabled';
        maxValiditySeconds?: number;
        defaultValiditySeconds?: number;
        crlUrl?: string | null;
      },
    ): Promise<AuthoritySummary> {
      if (input.state !== undefined && input.state !== 'active' && input.state !== 'disabled')
        throw new IamError('INVALID_INPUT', 'state must be active or disabled');
      return guard.run(
        credential,
        input.tenantId,
        pkiActions.update,
        authorityTarget(input.tenantId, input.authorityId),
        async ({ tx, metadata }, { authority }) => {
          const current = authority!;
          if (current.state === 'revoked')
            throw new IamError('AUTHORITY_UNAVAILABLE', 'A revoked authority cannot change', 409);
          const next: PkiAuthority = { ...current, updatedAt: ctx.now() };
          if (input.state !== undefined) next.state = input.state as AuthorityState;
          if (input.maxValiditySeconds !== undefined)
            next.maxValiditySeconds = integer(
              input.maxValiditySeconds,
              'maxValiditySeconds',
              60,
              MAX_LEAF_VALIDITY_SECONDS,
            );
          if (input.defaultValiditySeconds !== undefined)
            next.defaultValiditySeconds = integer(
              input.defaultValiditySeconds,
              'defaultValiditySeconds',
              60,
              next.maxValiditySeconds,
            );
          next.defaultValiditySeconds = Math.min(
            next.defaultValiditySeconds,
            next.maxValiditySeconds,
          );
          if (input.crlUrl === null) delete next.crlUrl;
          else if (input.crlUrl !== undefined) next.crlUrl = httpUrl(input.crlUrl, 'crlUrl')!;
          await tx.put('pkiAuthorities', next);
          Object.assign(metadata, {
            ...(input.state ? { state: input.state } : {}),
            maxValiditySeconds: next.maxValiditySeconds,
            defaultValiditySeconds: next.defaultValiditySeconds,
            ...(input.crlUrl !== undefined ? { crlUrl: next.crlUrl ?? null } : {}),
          });
          return summarizeAuthority(next);
        },
      );
    },

    /**
     * Issues a certificate for the key in a PEM PKCS#10 request (`csr`, which proves possession of the key). Names
     * come from the request unless `commonName`, `dnsNames`, `uris`, `ipAddresses` or `emails` are given. Every name
     * is decided separately (`iam:pki:issue` with `resource.name` / `resource.nameType`), and must fit the name
     * constraints of the authority chain; a `spiffe://` URI must be the only URI and in the authority's trust domain.
     * Validity defaults to the authority's `defaultValiditySeconds`, is capped at its `maxValiditySeconds`, and never
     * outlasts the authority. Audited as `iam:pki:issue` with the serial number and names.
     */
    async issueCertificate(
      credential: CredentialInput,
      input: CertificateIssueInput,
    ): Promise<IssuedCertificate> {
      const usage = usageOf(input.usage);
      // Parsed once the caller is known to belong to the tenant (inside the envelope), never for anonymous callers.
      let request: ReturnType<typeof parseCertificateRequest> | undefined;
      let names: SubjectAltNames | undefined;
      let commonName: string | undefined;
      let entries: ReturnType<typeof nameEntries> = [];
      const base = (authority: PkiAuthority, validitySeconds: number) => ({
        ...authorityAttributes(authority),
        usage,
        validitySeconds,
        keyType: request!.keyType,
      });
      return guard.run(
        credential,
        input.tenantId,
        pkiActions.issue,
        async (tx) => {
          const target = await authorityTarget(input.tenantId, input.authorityId)(tx);
          request = parseCertificateRequest(input.csr);
          const explicit =
            input.dnsNames !== undefined ||
            input.uris !== undefined ||
            input.ipAddresses !== undefined ||
            input.emails !== undefined;
          names = explicit ? subjectAltNames(input) : request.names;
          commonName =
            input.commonName !== undefined
              ? text(input.commonName, 'commonName', 64).trim()
              : request.commonName;
          entries = nameEntries(commonName, names);
          if (!entries.length)
            throw new IamError(
              'INVALID_INPUT',
              'A certificate needs a common name or at least one name',
            );
          // With alternative names, the common name must be one of them (clients may fall back to it).
          const alternatives = [
            ...names.dnsNames,
            ...names.uris,
            ...names.ipAddresses,
            ...names.emails,
          ];
          if (
            commonName !== undefined &&
            alternatives.length &&
            !alternatives.includes(commonName.toLowerCase()) &&
            !alternatives.includes(commonName)
          )
            throw new IamError(
              'INVALID_INPUT',
              'The common name must be one of the subject alternative names',
            );
          const validitySeconds = leafValidity(target.authority!, input.validitySeconds);
          target.attributes = { ...base(target.authority!, validitySeconds), ...entries[0]! };
          return target;
        },
        async (call, { authority }) => {
          const validitySeconds = leafValidity(authority!, input.validitySeconds);
          for (const entry of entries.slice(1))
            if (
              !(await call.allowed(pkiActions.issue, {
                resourceId: `pki/${authority!.id}`,
                attributes: { ...base(authority!, validitySeconds), ...entry },
              }))
            )
              throw new OperationDenied(`You may not certify ${entry.name}`);
          spiffeRules(authority!, names!);
          const issued = await issue(call.tx, authority!, {
            spki: request!.spki,
            keyType: request!.keyType,
            ...(commonName ? { commonName } : {}),
            names: names!,
            usage,
            validitySeconds,
            issuedBy: call.principal.identity.id,
            principal: call.principal,
          });
          Object.assign(call.metadata, {
            serialNumber: issued.serialNumber,
            names: entries.map((entry) => `${entry.nameType}:${entry.name}`),
            notAfter: issued.notAfter,
            usage,
          });
          return issued;
        },
      );
    },

    /**
     * A workload certificate (SPIFFE X.509 SVID) for the caller's own identity: the only name is
     * `spiffe://{trustDomain}/{user|service|agent}/{identityId}` (a critical subject alternative name, empty
     * subject), valid for `validitySeconds` (default one hour, at most a day and the authority's maximum), and never
     * past the end of the calling session or API key or of the identity itself. The authority needs a `trustDomain`.
     * For user sessions and API keys acting in their own right; requires iam:pki:request on the authority, decided
     * with `resource.name` (the SPIFFE ID), `resource.nameType` (`uri`) and `resource.identityKind`.
     */
    async requestCertificate(
      credential: CredentialInput,
      input: { tenantId: string; authorityId: string; csr: string; validitySeconds?: number },
    ): Promise<IssuedCertificate> {
      let request: ReturnType<typeof parseCertificateRequest> | undefined;
      let spiffeId = '';
      let validitySeconds = 0;
      return guard.run(
        credential,
        input.tenantId,
        pkiActions.request,
        async (tx, principal) => {
          const target = await authorityTarget(input.tenantId, input.authorityId)(tx);
          const authority = target.authority!;
          if (!actsInOwnRight(principal) || principal.identity.tenantId !== authority.tenantId)
            throw new IamError(
              'ACCESS_DENIED',
              'Workload certificates are issued to your own identity, from your own session or API key',
              403,
            );
          if (!authority.trustDomain)
            throw new IamError('INVALID_INPUT', 'This authority has no SPIFFE trust domain');
          request = parseCertificateRequest(input.csr);
          spiffeId = workloadId(authority, principal.identity);
          const ceiling = Math.min(86_400, authority.maxValiditySeconds);
          validitySeconds =
            input.validitySeconds === undefined
              ? Math.min(3600, ceiling)
              : integer(input.validitySeconds, 'validitySeconds', 60, ceiling);
          // The workload name is decided like any other: policies may narrow it by kind or trust domain.
          target.attributes = {
            ...target.attributes,
            nameType: 'uri',
            name: spiffeId,
            identityKind: principal.identity.kind,
            validitySeconds,
            keyType: request.keyType,
          };
          return target;
        },
        async (call, { authority }) => {
          const { principal } = call;
          const names: SubjectAltNames = {
            dnsNames: [],
            uris: [spiffeId],
            ipAddresses: [],
            emails: [],
          };
          const issued = await issue(call.tx, authority!, {
            spki: request!.spki,
            keyType: request!.keyType,
            names,
            usage: 'both',
            validitySeconds,
            identityId: principal.identity.id,
            spiffeId,
            // Never outlives the credential that asked for it, or the identity it names.
            notAfterCap: Math.min(
              principal.session.expiresAt,
              typeof principal.identity.expiresAt === 'number'
                ? principal.identity.expiresAt
                : Infinity,
            ),
            issuedBy: principal.identity.id,
            principal,
          });
          Object.assign(call.metadata, {
            serialNumber: issued.serialNumber,
            spiffeId,
            notAfter: issued.notAfter,
          });
          return issued;
        },
      );
    },

    /**
     * Certificates the caller may read (`iam:pki:read` on each one's authority), newest first; filter by
     * `authorityId`, `status` (`valid`, `revoked`, `expired`) or `identityId` (workload certificates).
     */
    async listCertificates(
      credential: CredentialInput,
      input: {
        tenantId: string;
        authorityId?: string;
        status?: 'valid' | 'revoked' | 'expired';
        identityId?: string;
        limit?: number;
        offset?: number;
      },
    ): Promise<{ certificates: CertificateSummary[]; total: number }> {
      const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
      const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
      const certificates = await guard.visible(
        credential,
        input.tenantId,
        pkiActions.read,
        'pki',
        async (tx, tenant) => {
          const authorities = new Map(
            (await tx.find<PkiAuthority>('pkiAuthorities', { tenantId: tenant.id })).map(
              (authority) => [authority.id, authority],
            ),
          );
          const now = ctx.now();
          return (
            await tx.find<PkiCertificate>('pkiCertificates', {
              tenantId: tenant.id,
              ...(input.authorityId !== undefined
                ? { authorityId: text(input.authorityId, 'authorityId') }
                : {}),
              ...(input.identityId !== undefined
                ? { identityId: text(input.identityId, 'identityId') }
                : {}),
            })
          )
            .map((certificate) => summarizeCertificate(certificate, now))
            .filter((summary) => input.status === undefined || summary.status === input.status)
            .sort((a, b) => b.issuedAt - a.issuedAt || (a.id < b.id ? -1 : 1))
            .flatMap((summary) => {
              const authority = authorities.get(summary.authorityId);
              return authority
                ? [
                    {
                      item: summary,
                      target: {
                        resourceId: `pki/${authority.id}`,
                        attributes: authorityAttributes(authority),
                      },
                    },
                  ]
                : [];
            });
        },
      );
      return {
        certificates: certificates.slice(offset, offset + limit),
        total: certificates.length,
      };
    },

    /** One certificate by serial number (hex). Requires iam:pki:read on its authority. */
    async getCertificate(
      credential: CredentialInput,
      input: { tenantId: string; serialNumber: string },
    ): Promise<CertificateSummary> {
      let certificate: PkiCertificate | undefined;
      return guard.run(
        credential,
        input.tenantId,
        pkiActions.read,
        async (tx) => {
          certificate = await findCertificate(tx, input.tenantId, input.serialNumber);
          return authorityTarget(input.tenantId, certificate.authorityId)(tx);
        },
        async () => summarizeCertificate(certificate!, ctx.now()),
      );
    },

    /**
     * Revokes a certificate (`reason`: `unspecified`, `keyCompromise`, `caCompromise`, `affiliationChanged`,
     * `superseded`, `cessationOfOperation`, `privilegeWithdrawn`). It appears on the authority's next CRL and fails
     * `iam.pki.verify` at once. Revoking a subordinate authority's certificate revokes the authority too. Requires
     * iam:pki:revoke on the issuing authority.
     */
    async revokeCertificate(
      credential: CredentialInput,
      input: { tenantId: string; serialNumber: string; reason?: RevocationReason },
    ): Promise<CertificateSummary> {
      const reason = input.reason ?? 'unspecified';
      if (!Object.hasOwn(revocationReasons, reason) || reason === 'certificateHold')
        throw new IamError('INVALID_INPUT', 'Unknown revocation reason');
      let certificate: PkiCertificate | undefined;
      return guard.run(
        credential,
        input.tenantId,
        pkiActions.revoke,
        async (tx) => {
          certificate = await findCertificate(tx, input.tenantId, input.serialNumber);
          return authorityTarget(input.tenantId, certificate.authorityId)(tx);
        },
        async ({ tx, principal, metadata }, { authority }) => {
          if (certificate!.status === 'revoked')
            throw new IamError('CONFLICT', 'The certificate is already revoked', 409);
          const now = ctx.now();
          const revoked: PkiCertificate = {
            ...certificate!,
            status: 'revoked',
            revokedAt: now,
            revocationReason: reason,
            revokedBy: principal.identity.id,
          };
          await tx.put('pkiCertificates', revoked);
          await tx.put('pkiAuthorities', {
            ...authority!,
            revision: authority!.revision + 1,
            updatedAt: now,
          });
          // A revoked authority certificate revokes the authority and every authority below it.
          let cascaded = 0;
          if (revoked.subordinateId) {
            const all = await tx.find<PkiAuthority>('pkiAuthorities', {
              tenantId: authority!.tenantId,
            });
            const doomed = new Set([revoked.subordinateId]);
            for (let grew = true; grew; ) {
              grew = false;
              for (const candidate of all)
                if (
                  candidate.parentId &&
                  doomed.has(candidate.parentId) &&
                  !doomed.has(candidate.id)
                ) {
                  doomed.add(candidate.id);
                  grew = true;
                }
            }
            for (const candidate of all)
              if (doomed.has(candidate.id) && candidate.state !== 'revoked') {
                await tx.put('pkiAuthorities', { ...candidate, state: 'revoked', updatedAt: now });
                cascaded++;
              }
          }
          Object.assign(metadata, {
            serialNumber: revoked.serialNumber,
            reason,
            ...(revoked.subordinateId
              ? { subordinateId: revoked.subordinateId, authoritiesRevoked: cascaded }
              : {}),
          });
          return summarizeCertificate(revoked, now);
        },
      );
    },

    /**
     * The authority's current certificate revocation list (PEM), rebuilt after revocations and at least twice a day.
     * CRLs are public by design: serve them to relying parties with `iam.pki.crlResponse`. Requires iam:pki:read.
     */
    async crl(
      credential: CredentialInput,
      input: { tenantId: string; authorityId: string },
    ): Promise<{ pem: string; crlNumber: number; thisUpdate: number; nextUpdate: number }> {
      return guard.run(
        credential,
        input.tenantId,
        pkiActions.read,
        authorityTarget(input.tenantId, input.authorityId),
        async ({ tx }, { authority }) => {
          const crl = await currentCrl(ctx, tx, authority!);
          return {
            pem: crlPem(crl.der),
            crlNumber: crl.crlNumber,
            thisUpdate: crl.thisUpdate,
            nextUpdate: crl.nextUpdate,
          };
        },
      );
    },

    /**
     * The tenant's trust anchors: every active, unexpired root certificate as one PEM bundle, which is what relying
     * parties trust. Intermediates are never in it (many TLS stacks treat any certificate in a trust store as an
     * anchor); servers send them in their chain (`chainPem`).
     */
    async bundle(
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<{ pem: string; authorities: number }> {
      const authorities = await guard.visible(
        credential,
        input.tenantId,
        pkiActions.read,
        'pki',
        async (tx, tenant) =>
          (await trustAnchors(ctx, tx, tenant.id)).map((authority) => ({
            item: authority,
            target: {
              resourceId: `pki/${authority.id}`,
              attributes: authorityAttributes(authority),
            },
          })),
      );
      return {
        pem: authorities.map((authority) => authority.certificatePem).join(''),
        authorities: authorities.length,
      };
    },
  };
}

/** A tenant's active, unexpired roots, oldest first. */
async function trustAnchors(ctx: ServerContext, tx: IamStore, tenantId: string) {
  return (
    await tx.find<PkiAuthority>('pkiAuthorities', { tenantId, state: 'active', type: 'root' })
  )
    .filter((authority) => authority.notAfter > ctx.now())
    .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1));
}

async function findCertificate(
  tx: IamStore,
  tenantId: string,
  serialNumber: unknown,
): Promise<PkiCertificate> {
  const serial = text(serialNumber, 'serialNumber', 64).toLowerCase().replace(/:/g, '');
  if (!/^[0-9a-f]{1,40}$/.test(serial))
    throw new IamError('INVALID_INPUT', 'serialNumber must be hexadecimal');
  const certificate = (
    await tx.find<PkiCertificate>('pkiCertificates', {
      tenantId: text(tenantId, 'tenantId'),
      uniqueKey: `serial:${serial.replace(/^0+(?=.)/, '')}`,
    })
  )[0];
  if (!certificate) throw new IamError('NOT_FOUND', 'Certificate not found', 404);
  return certificate;
}

/**
 * `iam.pki`, server side: public CRLs for relying parties, trust bundles, and certificate chain verification for
 * servers that terminate mutual TLS.
 */
export function createPkiRuntime(ctx: ServerContext) {
  async function crl(authorityId: string) {
    return ctx.store.transaction(async (tx) => {
      const authority = await tx.get<PkiAuthority>(
        'pkiAuthorities',
        text(authorityId, 'authorityId'),
      );
      if (!authority) throw new IamError('NOT_FOUND', 'Certificate authority not found', 404);
      const current = await currentCrl(ctx, tx, authority);
      return { ...current, pem: crlPem(current.der) };
    });
  }
  return {
    /** An authority's current CRL (DER and PEM), with no credential: CRLs are public. */
    crl,
    /**
     * An HTTP response for an authority's CRL distribution point (`application/pkix-crl`). When a fresh CRL cannot be
     * signed (the authority's KMS key is disabled), the last one is served while it is still valid; otherwise 503.
     */
    async crlResponse(authorityId: string): Promise<Response> {
      const respond = (der: Buffer, nextUpdate: number) =>
        new Response(new Uint8Array(der), {
          headers: {
            'content-type': 'application/pkix-crl',
            'cache-control': `public, max-age=${Math.max(0, Math.floor((nextUpdate - ctx.now()) / 2000))}`,
          },
        });
      try {
        const current = await crl(authorityId);
        return respond(current.der, current.nextUpdate);
      } catch (error) {
        if (error instanceof IamError && error.code === 'NOT_FOUND')
          return new Response('Not found', { status: 404 });
        if (error instanceof IamError) {
          const cached = await ctx.store
            .transaction((tx) => tx.get<PkiAuthority>('pkiAuthorities', authorityId))
            .catch(() => undefined);
          if (cached?.crl && cached.crl.nextUpdate > ctx.now())
            return respond(Buffer.from(cached.crl.der, 'base64'), cached.crl.nextUpdate);
          return new Response('Revocation list unavailable', { status: 503 });
        }
        throw error;
      }
    },
    /** A tenant's trust anchors (active, unexpired roots) as one PEM bundle. */
    async bundle(tenantId: string): Promise<string> {
      return ctx.store.transaction(async (tx) =>
        (await trustAnchors(ctx, tx, text(tenantId, 'tenantId')))
          .map((authority) => authority.certificatePem)
          .join(''),
      );
    },
    /**
     * Verifies a presented certificate (leaf first; intermediates optional) against one tenant's stored chains:
     * signatures, path lengths, validity, authority state and revocation, and for workload certificates the standing
     * of the identity they name. Returns the SPIFFE ID and identity of workload certificates; throws
     * `CERTIFICATE_INVALID` (401) otherwise. `tenantId` is required: trust is per organization.
     */
    verify(
      chain: string | string[],
      options: { tenantId: string; usage?: 'server' | 'client'; at?: number },
    ): Promise<CertificateVerification> {
      return verifyCertificateChain(ctx, chain, options);
    },
  };
}
