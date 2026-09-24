import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as signData,
  verify as verifyData,
  type KeyObject,
} from 'node:crypto';
import { isIP } from 'node:net';
import { IamError } from '@better-iam/core';

/**
 * The X.509 layer of the private certificate authority (pki.ts): a DER encoder and a bounds-checked DER reader,
 * PKCS#10 certification requests (built for clients and tests, parsed and verified for issuance), certificates, and
 * certificate revocation lists (RFC 5280). Node's `crypto.X509Certificate` reads what this writes, so tests check the
 * encoding with it and with real TLS handshakes.
 */

// ---------------------------------------------------------------------------------------------------------------
// DER encoding

const length = (size: number): Buffer => {
  if (size < 0x80) return Buffer.from([size]);
  const bytes: number[] = [];
  for (let rest = size; rest > 0; rest = Math.floor(rest / 256)) bytes.unshift(rest & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
};

export const tlv = (tag: number, contents: Buffer): Buffer =>
  Buffer.concat([Buffer.from([tag]), length(contents.length), contents]);

export const sequence = (...items: Buffer[]) => tlv(0x30, Buffer.concat(items));
export const set = (...items: Buffer[]) => tlv(0x31, Buffer.concat(items));
export const nullValue = () => Buffer.from([0x05, 0x00]);
export const booleanValue = (value: boolean) => tlv(0x01, Buffer.from([value ? 0xff : 0x00]));
export const octetString = (value: Buffer) => tlv(0x04, value);
export const utf8String = (value: string) => tlv(0x0c, Buffer.from(value, 'utf8'));
export const printableString = (value: string) => tlv(0x13, Buffer.from(value, 'ascii'));
export const ia5String = (value: string) => tlv(0x16, Buffer.from(value, 'ascii'));
/** `[n] EXPLICIT`: a constructed context-specific wrapper. */
export const explicit = (tag: number, value: Buffer) => tlv(0xa0 | tag, value);

/** A non-negative INTEGER in minimal two's complement form. */
export function integer(value: bigint | number | Buffer): Buffer {
  let bytes: Buffer;
  if (Buffer.isBuffer(value)) bytes = value;
  else {
    let hex = BigInt(value).toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    bytes = Buffer.from(hex, 'hex');
  }
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0 && (bytes[start + 1]! & 0x80) === 0)
    start++;
  bytes = bytes.subarray(start);
  if (bytes.length === 0) bytes = Buffer.from([0]);
  if (bytes[0]! & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return tlv(0x02, bytes);
}

export function oid(dotted: string): Buffer {
  const parts = dotted.split('.').map((part) => BigInt(part));
  if (parts.length < 2) throw new Error(`Invalid OID ${dotted}`);
  const bytes: number[] = [Number(parts[0]! * 40n + parts[1]!)];
  for (const part of parts.slice(2)) {
    const chunk: number[] = [];
    let rest = part;
    do {
      chunk.unshift(Number(rest & 0x7fn));
      rest >>= 7n;
    } while (rest > 0n);
    for (let index = 0; index < chunk.length - 1; index++) chunk[index]! |= 0x80;
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}

/** A BIT STRING of whole bytes (no unused bits). */
export const bitString = (value: Buffer) => tlv(0x03, Buffer.concat([Buffer.from([0]), value]));

/** A named-bit BIT STRING (key usage): bits numbered from the most significant bit, trailing zeros removed. */
export function namedBits(bits: number[]): Buffer {
  const highest = Math.max(...bits);
  const bytes = Buffer.alloc(Math.floor(highest / 8) + 1);
  for (const bit of bits) bytes[Math.floor(bit / 8)]! |= 0x80 >> bit % 8;
  const last = bytes[bytes.length - 1]!;
  let unused = 0;
  while (unused < 7 && (last & (1 << unused)) === 0) unused++;
  return tlv(0x03, Buffer.concat([Buffer.from([unused]), bytes]));
}

/** UTCTime through 2049, GeneralizedTime from 2050 (RFC 5280 4.1.2.5). */
export function time(at: number): Buffer {
  const date = new Date(Math.floor(at / 1000) * 1000);
  const year = date.getUTCFullYear();
  const pad = (value: number, size = 2) => String(value).padStart(size, '0');
  const rest = `${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  if (year >= 1950 && year < 2050) return tlv(0x17, Buffer.from(`${pad(year % 100)}${rest}`));
  return tlv(0x18, Buffer.from(`${pad(year, 4)}${rest}`));
}

// ---------------------------------------------------------------------------------------------------------------
// DER reading

export interface DerNode {
  tag: number;
  /** Offset of the tag byte. */
  start: number;
  /** Offset of the first content byte. */
  contentStart: number;
  /** Offset just past the node. */
  end: number;
}

const malformed = () =>
  new IamError('INVALID_CSR', 'The certificate request is not valid DER', 400);

export function readNode(buffer: Buffer, offset: number, limit = buffer.length): DerNode {
  if (offset + 2 > limit) throw malformed();
  const tag = buffer[offset]!;
  if ((tag & 0x1f) === 0x1f) throw malformed();
  let size = buffer[offset + 1]!;
  let contentStart = offset + 2;
  if (size & 0x80) {
    const count = size & 0x7f;
    if (count === 0 || count > 4 || contentStart + count > limit) throw malformed();
    size = 0;
    for (let index = 0; index < count; index++) size = size * 256 + buffer[contentStart + index]!;
    contentStart += count;
    if (size < 0x80) throw malformed();
  }
  const end = contentStart + size;
  if (end > limit) throw malformed();
  return { tag, start: offset, contentStart, end };
}

export function childrenOf(buffer: Buffer, node: DerNode): DerNode[] {
  const children: DerNode[] = [];
  for (let offset = node.contentStart; offset < node.end; ) {
    const child = readNode(buffer, offset, node.end);
    children.push(child);
    offset = child.end;
    if (children.length > 1000) throw malformed();
  }
  return children;
}

const contents = (buffer: Buffer, node: DerNode) => buffer.subarray(node.contentStart, node.end);
const whole = (buffer: Buffer, node: DerNode) => buffer.subarray(node.start, node.end);

export function decodeOid(bytes: Buffer): string {
  if (!bytes.length) throw malformed();
  const first = bytes[0]!;
  const parts = [first < 80 ? Math.floor(first / 40) : 2, first < 80 ? first % 40 : first - 80];
  let value = 0;
  for (const byte of bytes.subarray(1)) {
    value = value * 128 + (byte & 0x7f);
    if (value > Number.MAX_SAFE_INTEGER) throw malformed();
    if (!(byte & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

// ---------------------------------------------------------------------------------------------------------------
// Names and algorithms

export const OIDS = {
  commonName: '2.5.4.3',
  country: '2.5.4.6',
  locality: '2.5.4.7',
  state: '2.5.4.8',
  organization: '2.5.4.10',
  organizationalUnit: '2.5.4.11',
  subjectKeyIdentifier: '2.5.29.14',
  keyUsage: '2.5.29.15',
  subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  crlNumber: '2.5.29.20',
  crlReason: '2.5.29.21',
  nameConstraints: '2.5.29.30',
  crlDistributionPoints: '2.5.29.31',
  authorityKeyIdentifier: '2.5.29.35',
  extKeyUsage: '2.5.29.37',
  serverAuth: '1.3.6.1.5.5.7.3.1',
  clientAuth: '1.3.6.1.5.5.7.3.2',
  extensionRequest: '1.2.840.113549.1.9.14',
  ecdsaSha256: '1.2.840.10045.4.3.2',
  ecdsaSha384: '1.2.840.10045.4.3.3',
  ecdsaSha512: '1.2.840.10045.4.3.4',
  rsaSha256: '1.2.840.113549.1.1.11',
  rsaSha384: '1.2.840.113549.1.1.12',
  rsaSha512: '1.2.840.113549.1.1.13',
  ed25519: '1.3.101.112',
} as const;

/** A distinguished name; every part optional. */
export interface DistinguishedName {
  commonName?: string;
  organization?: string;
  organizationalUnit?: string;
  locality?: string;
  state?: string;
  country?: string;
}

/** Encodes a name in the conventional order (C, ST, L, O, OU, CN), one attribute per RDN. */
export function encodeName(name: DistinguishedName): Buffer {
  const rdn = (type: string, value: Buffer) => set(sequence(oid(type), value));
  const parts: Buffer[] = [];
  if (name.country) parts.push(rdn(OIDS.country, printableString(name.country)));
  if (name.state) parts.push(rdn(OIDS.state, utf8String(name.state)));
  if (name.locality) parts.push(rdn(OIDS.locality, utf8String(name.locality)));
  if (name.organization) parts.push(rdn(OIDS.organization, utf8String(name.organization)));
  if (name.organizationalUnit)
    parts.push(rdn(OIDS.organizationalUnit, utf8String(name.organizationalUnit)));
  if (name.commonName) parts.push(rdn(OIDS.commonName, utf8String(name.commonName)));
  return sequence(...parts);
}

export type SignatureAlgorithm = 'ES256' | 'ES384' | 'EdDSA' | 'RS256' | 'RS384' | 'RS512';

const algorithmOids: Record<SignatureAlgorithm, string> = {
  ES256: OIDS.ecdsaSha256,
  ES384: OIDS.ecdsaSha384,
  EdDSA: OIDS.ed25519,
  RS256: OIDS.rsaSha256,
  RS384: OIDS.rsaSha384,
  RS512: OIDS.rsaSha512,
};

export function algorithmIdentifier(algorithm: SignatureAlgorithm): Buffer {
  return algorithm.startsWith('RS')
    ? sequence(oid(algorithmOids[algorithm]), nullValue())
    : sequence(oid(algorithmOids[algorithm]));
}

/** The Node hash for a signature OID, `null` for Ed25519; undefined for anything else (RSA-PSS included). */
function hashForOid(value: string): string | null | undefined {
  switch (value) {
    case OIDS.ecdsaSha256:
    case OIDS.rsaSha256:
      return 'sha256';
    case OIDS.ecdsaSha384:
    case OIDS.rsaSha384:
      return 'sha384';
    case OIDS.ecdsaSha512:
    case OIDS.rsaSha512:
      return 'sha512';
    case OIDS.ed25519:
      return null;
    default:
      return undefined;
  }
}

/** The signature algorithm a private or public key signs certificates and requests with. */
export function algorithmForKey(key: KeyObject): SignatureAlgorithm {
  if (key.asymmetricKeyType === 'ed25519') return 'EdDSA';
  if (key.asymmetricKeyType === 'ec')
    return key.asymmetricKeyDetails?.namedCurve === 'secp384r1' ? 'ES384' : 'ES256';
  if (key.asymmetricKeyType === 'rsa') return 'RS256';
  throw new IamError('INVALID_INPUT', 'Keys must be ECDSA P-256/P-384, Ed25519 or RSA');
}

/** Checks a subject public key: ECDSA P-256/P-384, Ed25519, or RSA of 2048 bits or more. */
export function acceptablePublicKey(key: KeyObject): string {
  const type = key.asymmetricKeyType;
  if (type === 'ed25519') return 'ed25519';
  if (type === 'ec') {
    const curve = key.asymmetricKeyDetails?.namedCurve;
    if (curve === 'prime256v1') return 'ecc-p256';
    if (curve === 'secp384r1') return 'ecc-p384';
  }
  if (type === 'rsa') {
    const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
    // A huge public exponent makes every verification slow; real keys use 65537 (or 3).
    const exponent = key.asymmetricKeyDetails?.publicExponent ?? 0n;
    if (bits >= 2048 && bits <= 8192 && exponent >= 3n && exponent <= 65537n)
      return `rsa-${bits}`;
  }
  throw new IamError(
    'INVALID_CSR',
    'The requested key must be ECDSA P-256 or P-384, Ed25519, or RSA of 2048 to 8192 bits',
    400,
  );
}

function signWith(key: KeyObject, algorithm: SignatureAlgorithm, data: Buffer): Buffer {
  if (algorithm === 'EdDSA') return signData(null, data, key);
  const hash = algorithm.endsWith('384')
    ? 'sha384'
    : algorithm.endsWith('512')
      ? 'sha512'
      : 'sha256';
  return signData(hash, data, { key, dsaEncoding: 'der' });
}

// ---------------------------------------------------------------------------------------------------------------
// Subject alternative names

export interface SubjectAltNames {
  dnsNames: string[];
  uris: string[];
  ipAddresses: string[];
  emails: string[];
}

export const dnsName =
  /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
/** Printable ASCII only: IA5String names are encoded byte for byte, so what is decided is what is signed. */
const emailAddress = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;
/** The SPIFFE ID grammar: a lowercase trust domain and path segments of letters, digits, dots, dashes, underscores. */
const spiffeId = /^spiffe:\/\/[a-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;

function canonicalUri(value: string): string {
  const invalid = () => new IamError('INVALID_INPUT', `Invalid URI ${value}`);
  if (value.length > 2048 || !/^[\x21-\x7e]+$/.test(value) || value.includes('\\')) throw invalid();
  if (value.toLowerCase().startsWith('spiffe:')) {
    if (!spiffeId.test(value) || value.split('/').some((segment) => segment === '.' || segment === '..'))
      throw new IamError(
        'INVALID_INPUT',
        `Invalid SPIFFE ID ${value}: spiffe://{trust domain}/{path}, with no dot segments, query or fragment`,
      );
    return value;
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw invalid();
  }
  // Only a URI already in canonical form is accepted, so policies decide on the exact string that is encoded
  // (dot segments, percent-encoded dots, host case and default ports are all resolved by the parser).
  if (parsed.href !== value || parsed.username || parsed.password) throw invalid();
  return value;
}

/** An IP address in canonical text: dotted IPv4 (IPv4-mapped IPv6 included), RFC 5952 compressed IPv6. */
function canonicalIp(value: string): string {
  if (!isIP(value) || value.includes('%'))
    throw new IamError('INVALID_INPUT', `Invalid IP address ${value}`);
  const bytes = ipBytes(value);
  const mapped =
    bytes.length === 16 &&
    bytes.subarray(0, 10).every((byte) => byte === 0) &&
    bytes[10] === 0xff &&
    bytes[11] === 0xff;
  return ipText(mapped ? bytes.subarray(12) : bytes);
}

/**
 * Validates and canonicalizes requested names, at most 100 in total: lowercase DNS names and email addresses (ASCII
 * only), URIs in canonical form (SPIFFE IDs by the SPIFFE grammar), and IP addresses in canonical text.
 */
export function subjectAltNames(input: Partial<SubjectAltNames>): SubjectAltNames {
  const list = (value: unknown, name: string) => {
    if (value === undefined) return [];
    if (!Array.isArray(value) || value.some((item) => typeof item !== 'string'))
      throw new IamError('INVALID_INPUT', `${name} must be a list of strings`);
    return value as string[];
  };
  const unique = (values: string[]) => [...new Set(values)];
  const dnsNames = unique(list(input.dnsNames, 'dnsNames').map((value) => value.toLowerCase()));
  for (const value of dnsNames)
    if (value.length > 253 || !dnsName.test(value))
      throw new IamError('INVALID_INPUT', `Invalid DNS name ${value}`);
  const emails = unique(list(input.emails, 'emails').map((value) => value.toLowerCase()));
  for (const value of emails)
    if (value.length > 254 || !emailAddress.test(value))
      throw new IamError('INVALID_INPUT', `Invalid email address ${value}`);
  const names: SubjectAltNames = {
    dnsNames,
    uris: unique(list(input.uris, 'uris').map(canonicalUri)),
    ipAddresses: unique(list(input.ipAddresses, 'ipAddresses').map(canonicalIp)),
    emails,
  };
  const total =
    names.dnsNames.length + names.uris.length + names.ipAddresses.length + names.emails.length;
  if (total > 100) throw new IamError('INVALID_INPUT', 'At most 100 subject alternative names');
  return names;
}

function ipBytes(value: string): Buffer {
  if (isIP(value) === 4) return Buffer.from(value.split('.').map(Number));
  const [head = '', tail = ''] = value.split('::');
  const expand = (part: string) => (part ? part.split(':') : []);
  let left = expand(head);
  let right = expand(tail);
  // An IPv4 tail (::ffff:1.2.3.4) becomes two groups.
  const lastRight = right.at(-1) ?? (value.includes('::') ? undefined : left.at(-1));
  if (lastRight?.includes('.')) {
    const octets = lastRight.split('.').map(Number);
    const groups = [
      ((octets[0]! << 8) | octets[1]!).toString(16),
      ((octets[2]! << 8) | octets[3]!).toString(16),
    ];
    if (right.length) right = [...right.slice(0, -1), ...groups];
    else left = [...left.slice(0, -1), ...groups];
  }
  const groups = value.includes('::')
    ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
    : left;
  return Buffer.from(
    groups.flatMap((group) => {
      const number = parseInt(group, 16);
      return [number >> 8, number & 0xff];
    }),
  );
}

/** Dotted IPv4, or IPv6 in RFC 5952 form (lowercase, the longest run of two or more zero groups as `::`). */
function ipText(bytes: Buffer): string {
  if (bytes.length === 4) return [...bytes].join('.');
  const groups: number[] = [];
  for (let index = 0; index < 16; index += 2) groups.push((bytes[index]! << 8) | bytes[index + 1]!);
  let best = { start: -1, length: 0 };
  for (let start = 0; start < 8; ) {
    if (groups[start] !== 0) {
      start++;
      continue;
    }
    let end = start;
    while (end < 8 && groups[end] === 0) end++;
    if (end - start > best.length) best = { start, length: end - start };
    start = end;
  }
  const text = groups.map((group) => group.toString(16));
  if (best.length < 2) return text.join(':');
  return `${text.slice(0, best.start).join(':')}::${text.slice(best.start + best.length).join(':')}`;
}

export function encodeGeneralNames(names: SubjectAltNames): Buffer {
  return sequence(
    ...names.emails.map((value) => tlv(0x81, Buffer.from(value, 'ascii'))),
    ...names.dnsNames.map((value) => tlv(0x82, Buffer.from(value, 'ascii'))),
    ...names.uris.map((value) => tlv(0x86, Buffer.from(value, 'ascii'))),
    ...names.ipAddresses.map((value) => tlv(0x87, ipBytes(value))),
  );
}

function decodeGeneralNames(buffer: Buffer, node: DerNode): SubjectAltNames {
  const names: SubjectAltNames = { dnsNames: [], uris: [], ipAddresses: [], emails: [] };
  for (const child of childrenOf(buffer, node)) {
    const value = contents(buffer, child);
    if (child.tag === 0x82) names.dnsNames.push(value.toString('ascii'));
    else if (child.tag === 0x86) names.uris.push(value.toString('ascii'));
    else if (child.tag === 0x81) names.emails.push(value.toString('ascii'));
    else if (child.tag === 0x87 && (value.length === 4 || value.length === 16))
      names.ipAddresses.push(ipText(value));
    else throw new IamError('INVALID_CSR', 'The request names an unsupported kind of name', 400);
  }
  return names;
}

// ---------------------------------------------------------------------------------------------------------------
// Extensions

export const extension = (type: string, critical: boolean, value: Buffer) =>
  critical
    ? sequence(oid(type), booleanValue(true), octetString(value))
    : sequence(oid(type), octetString(value));

/** RFC 5280 key identifier (method 1): SHA-1 of the subject public key bits. */
export function keyIdentifier(spki: Buffer): Buffer {
  const root = readNode(spki, 0);
  const [, bits] = childrenOf(spki, root);
  if (!bits || bits.tag !== 0x03) throw malformed();
  return createHash('sha1').update(contents(spki, bits).subarray(1)).digest();
}

// ---------------------------------------------------------------------------------------------------------------
// PKCS#10 certification requests

export interface CertificateRequestInput extends Partial<SubjectAltNames> {
  /** A private key (KeyObject or PKCS#8 PEM): ECDSA P-256/P-384, Ed25519 or RSA. */
  privateKey: KeyObject | string;
  subject?: DistinguishedName;
}

/**
 * Builds a PEM PKCS#10 certification request for `privateKey` with a subject and subject alternative names, signed
 * with the key (proof of possession). Clients call it to request certificates without OpenSSL.
 */
export function createCertificateRequest(input: CertificateRequestInput): string {
  const key =
    typeof input.privateKey === 'string' ? createPrivateKey(input.privateKey) : input.privateKey;
  const algorithm = algorithmForKey(key);
  const spki = createPublicKey(key).export({ format: 'der', type: 'spki' });
  const names = subjectAltNames(input);
  const hasNames =
    names.dnsNames.length + names.uris.length + names.ipAddresses.length + names.emails.length > 0;
  const attributes = hasNames
    ? set(
        sequence(
          oid(OIDS.extensionRequest),
          set(sequence(extension(OIDS.subjectAltName, false, encodeGeneralNames(names)))),
        ),
      )
    : Buffer.alloc(0);
  const info = sequence(
    integer(0),
    encodeName(input.subject ?? {}),
    spki,
    // attributes [0] IMPLICIT SET OF Attribute
    tlv(0xa0, hasNames ? contents(attributes, readNode(attributes, 0)) : Buffer.alloc(0)),
  );
  const request = sequence(
    info,
    algorithmIdentifier(algorithm),
    bitString(signWith(key, algorithm, info)),
  );
  return pem('CERTIFICATE REQUEST', request);
}

export interface ParsedCertificateRequest {
  /** The subject public key (SPKI DER). */
  spki: Buffer;
  publicKey: KeyObject;
  /** `ecc-p256`, `ecc-p384`, `ed25519` or `rsa-{bits}`. */
  keyType: string;
  commonName?: string;
  names: SubjectAltNames;
}

function nameValue(buffer: Buffer, node: DerNode): string | undefined {
  if (![0x0c, 0x13, 0x16, 0x14, 0x1e].includes(node.tag)) return undefined;
  const value = contents(buffer, node);
  if (node.tag !== 0x1e) return value.toString('utf8');
  // BMPString: UTF-16BE, so an even length; swapped on a copy, never on the request itself.
  if (value.length % 2) throw malformed();
  return Buffer.from(value).swap16().toString('utf16le');
}

/** Which key types each signature algorithm belongs to: a request's algorithm must match its key. */
function algorithmFits(oidValue: string, keyType: string): boolean {
  if (oidValue === OIDS.ed25519) return keyType === 'ed25519';
  if ([OIDS.ecdsaSha256, OIDS.ecdsaSha384, OIDS.ecdsaSha512].includes(oidValue as never))
    return keyType.startsWith('ecc-');
  return keyType.startsWith('rsa-');
}

/**
 * Parses and verifies a PEM (or base64 DER) PKCS#10 request: the signature must verify with the request's own key
 * (proof of possession), and the key must be of an accepted kind. Returns the key, the subject common name and the
 * requested subject alternative names.
 */
export function parseCertificateRequest(value: unknown): ParsedCertificateRequest {
  if (typeof value !== 'string' || value.length > 65536)
    throw new IamError('INVALID_CSR', 'csr must be a PEM certificate request', 400);
  const body = value
    .replace(/-----BEGIN (NEW )?CERTIFICATE REQUEST-----/, '')
    .replace(/-----END (NEW )?CERTIFICATE REQUEST-----/, '')
    .replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body))
    throw new IamError('INVALID_CSR', 'csr must be a PEM certificate request', 400);
  const der = Buffer.from(body, 'base64');
  const root = readNode(der, 0);
  if (root.tag !== 0x30 || root.end !== der.length) throw malformed();
  const [info, algorithm, signature] = childrenOf(der, root);
  if (!info || !algorithm || !signature || info.tag !== 0x30 || signature.tag !== 0x03)
    throw malformed();
  const [version, subject, spkiNode, attributes] = childrenOf(der, info);
  if (!version || !subject || !spkiNode || version.tag !== 0x02 || subject.tag !== 0x30)
    throw malformed();
  // PKCS#10 version 1 is encoded as 0.
  if (!contents(der, version).equals(Buffer.from([0]))) throw malformed();
  const spki = Buffer.from(whole(der, spkiNode));
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  } catch {
    throw new IamError('INVALID_CSR', 'The request carries an unreadable public key', 400);
  }
  const keyType = acceptablePublicKey(publicKey);
  const [algorithmOid] = childrenOf(der, algorithm);
  if (!algorithmOid || algorithmOid.tag !== 0x06) throw malformed();
  const algorithmValue = decodeOid(contents(der, algorithmOid));
  const hash = hashForOid(algorithmValue);
  if (hash === undefined || !algorithmFits(algorithmValue, keyType))
    throw new IamError('INVALID_CSR', 'The request is signed with an unsupported algorithm', 400);
  const bits = contents(der, signature);
  if (bits[0] !== 0) throw malformed();
  let verified = false;
  try {
    verified = verifyData(hash, whole(der, info), publicKey, bits.subarray(1));
  } catch {
    verified = false;
  }
  if (!verified)
    throw new IamError('INVALID_CSR', 'The request signature does not verify with its key', 400);
  let commonName: string | undefined;
  for (const rdn of childrenOf(der, subject))
    for (const attribute of childrenOf(der, rdn)) {
      const [type, item] = childrenOf(der, attribute);
      if (type?.tag === 0x06 && item && decodeOid(contents(der, type)) === OIDS.commonName)
        commonName = nameValue(der, item);
    }
  // The request's common name follows the same rules as one given explicitly: never truncated or cleaned up.
  if (
    commonName !== undefined &&
    (!commonName.trim() || commonName.length > 64 || /[\u0000-\u001f\u007f]/.test(commonName))
  )
    throw new IamError('INVALID_CSR', 'The request has an invalid common name', 400);
  let names: SubjectAltNames = { dnsNames: [], uris: [], ipAddresses: [], emails: [] };
  if (attributes && attributes.tag === 0xa0)
    for (const attribute of childrenOf(der, attributes)) {
      const [type, values] = childrenOf(der, attribute);
      if (type?.tag !== 0x06 || decodeOid(contents(der, type)) !== OIDS.extensionRequest || !values)
        continue;
      for (const extensions of childrenOf(der, values))
        for (const item of childrenOf(der, extensions)) {
          const parts = childrenOf(der, item);
          const id = parts[0];
          const valueNode = parts.at(-1);
          if (id?.tag !== 0x06 || valueNode?.tag !== 0x04) continue;
          if (decodeOid(contents(der, id)) !== OIDS.subjectAltName) continue;
          const inner = contents(der, valueNode);
          names = decodeGeneralNames(inner, readNode(inner, 0));
        }
    }
  return {
    spki,
    publicKey,
    keyType,
    ...(commonName ? { commonName } : {}),
    names: subjectAltNames(names),
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Certificates and CRLs

export function pem(label: string, der: Buffer): string {
  const body = der
    .toString('base64')
    .replace(/(.{64})/g, '$1\n')
    .replace(/\n$/, '');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

/**
 * A positive random serial number (about 123 random bits), as lowercase hex whose first digit is never `0`, so it
 * reads the same with or without leading-zero stripping (Node's `X509Certificate.serialNumber` strips them).
 */
export function randomSerial(): string {
  const bytes = randomBytes(16);
  bytes[0] = (bytes[0]! & 0x7f) | 0x10;
  return bytes.toString('hex');
}

export interface CertificateSpec {
  serialNumber: string;
  /** DER of the issuer's subject name, byte for byte. */
  issuer: Buffer;
  subject: DistinguishedName;
  /** DER SubjectPublicKeyInfo of the certified key. */
  spki: Buffer;
  notBefore: number;
  notAfter: number;
  names?: SubjectAltNames;
  /** A CA certificate (with an optional path length) or an end-entity certificate. */
  ca?: { pathLength?: number };
  /** End-entity usages. */
  usage?: 'server' | 'client' | 'both';
  /** The issuing key's identifier (authority key identifier); omitted on self-signed roots. */
  authorityKeyId?: Buffer;
  crlUrl?: string;
  /** Name constraints for CA certificates: permitted DNS suffixes and URI hosts. */
  permitted?: { dnsNames?: string[]; uriHosts?: string[] };
}

/** The TBSCertificate DER for a spec, signed by the caller with the issuer's key. */
export function tbsCertificate(spec: CertificateSpec, algorithm: SignatureAlgorithm): Buffer {
  const subjectKeyId = keyIdentifier(spec.spki);
  const extensions: Buffer[] = [];
  if (spec.ca) {
    extensions.push(
      extension(
        OIDS.basicConstraints,
        true,
        sequence(
          booleanValue(true),
          ...(spec.ca.pathLength !== undefined ? [integer(spec.ca.pathLength)] : []),
        ),
      ),
      extension(OIDS.keyUsage, true, namedBits([0, 5, 6])),
    );
    if (spec.permitted && (spec.permitted.dnsNames?.length || spec.permitted.uriHosts?.length)) {
      const subtree = (tag: number, value: string) =>
        sequence(tlv(tag, Buffer.from(value, 'ascii')));
      extensions.push(
        extension(
          OIDS.nameConstraints,
          true,
          sequence(
            tlv(
              0xa0,
              Buffer.concat([
                ...(spec.permitted.dnsNames ?? []).map((value) => subtree(0x82, value)),
                // RFC 5280: a URI host constraint matches that host exactly, `.host` its subdomains; both, to
                // mean what the authority enforces at issuance (the host and everything below it).
                ...(spec.permitted.uriHosts ?? []).flatMap((value) => [
                  subtree(0x86, value),
                  subtree(0x86, `.${value}`),
                ]),
              ]),
            ),
          ),
        ),
      );
    }
  } else {
    const rsa =
      createPublicKey({ key: spec.spki, format: 'der', type: 'spki' }).asymmetricKeyType === 'rsa';
    extensions.push(
      extension(OIDS.basicConstraints, true, sequence()),
      extension(OIDS.keyUsage, true, namedBits(rsa ? [0, 2] : [0])),
      extension(
        OIDS.extKeyUsage,
        false,
        sequence(
          ...(spec.usage !== 'client' ? [oid(OIDS.serverAuth)] : []),
          ...(spec.usage !== 'server' ? [oid(OIDS.clientAuth)] : []),
        ),
      ),
    );
  }
  extensions.push(extension(OIDS.subjectKeyIdentifier, false, octetString(subjectKeyId)));
  if (spec.authorityKeyId)
    extensions.push(
      extension(OIDS.authorityKeyIdentifier, false, sequence(tlv(0x80, spec.authorityKeyId))),
    );
  const names = spec.names;
  const hasNames =
    names &&
    names.dnsNames.length + names.uris.length + names.ipAddresses.length + names.emails.length > 0;
  const emptySubject = !Object.values(spec.subject).some(Boolean);
  if (hasNames)
    // An empty subject makes the alternative names critical (RFC 5280 4.2.1.6), as in SPIFFE SVIDs.
    extensions.push(extension(OIDS.subjectAltName, emptySubject, encodeGeneralNames(names)));
  if (spec.crlUrl)
    extensions.push(
      extension(
        OIDS.crlDistributionPoints,
        false,
        sequence(sequence(explicit(0, tlv(0xa0, tlv(0x86, Buffer.from(spec.crlUrl, 'ascii')))))),
      ),
    );
  return sequence(
    explicit(0, integer(2)),
    integer(Buffer.from(spec.serialNumber, 'hex')),
    algorithmIdentifier(algorithm),
    spec.issuer,
    sequence(time(spec.notBefore), time(spec.notAfter)),
    encodeName(spec.subject),
    spec.spki,
    explicit(3, sequence(...extensions)),
  );
}

/** Wraps a signed TBS structure (certificate or CRL). */
export function signedStructure(
  tbs: Buffer,
  algorithm: SignatureAlgorithm,
  signature: Buffer,
): Buffer {
  return sequence(tbs, algorithmIdentifier(algorithm), bitString(signature));
}

export type RevocationReason =
  | 'unspecified'
  | 'keyCompromise'
  | 'caCompromise'
  | 'affiliationChanged'
  | 'superseded'
  | 'cessationOfOperation'
  | 'certificateHold'
  | 'privilegeWithdrawn';

export const revocationReasons: Record<RevocationReason, number> = {
  unspecified: 0,
  keyCompromise: 1,
  caCompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  certificateHold: 6,
  privilegeWithdrawn: 9,
};

/** A TBSCertList (RFC 5280 5.1) with a CRL number and the issuer's key identifier. */
export function tbsCertList(
  spec: {
    issuer: Buffer;
    thisUpdate: number;
    nextUpdate: number;
    crlNumber: number;
    authorityKeyId: Buffer;
    revoked: Array<{ serialNumber: string; revokedAt: number; reason?: RevocationReason }>;
  },
  algorithm: SignatureAlgorithm,
): Buffer {
  const entries = spec.revoked.map((entry) =>
    sequence(
      integer(Buffer.from(entry.serialNumber, 'hex')),
      time(entry.revokedAt),
      ...(entry.reason && entry.reason !== 'unspecified'
        ? [
            sequence(
              extension(
                OIDS.crlReason,
                false,
                tlv(0x0a, Buffer.from([revocationReasons[entry.reason]])),
              ),
            ),
          ]
        : []),
    ),
  );
  return sequence(
    integer(1),
    algorithmIdentifier(algorithm),
    spec.issuer,
    time(spec.thisUpdate),
    time(spec.nextUpdate),
    ...(entries.length ? [sequence(...entries)] : []),
    explicit(
      0,
      sequence(
        extension(OIDS.authorityKeyIdentifier, false, sequence(tlv(0x80, spec.authorityKeyId))),
        extension(OIDS.crlNumber, false, integer(spec.crlNumber)),
      ),
    ),
  );
}

export const sha256Fingerprint = (der: Buffer) => createHash('sha256').update(der).digest('hex');

/** The DER bytes of a PEM certificate. */
export function certificateDer(pemText: string): Buffer {
  const body = pemText
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s+/g, '');
  return Buffer.from(body, 'base64');
}
