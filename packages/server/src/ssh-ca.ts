import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import { isIP } from 'node:net';
import { IamError } from '@better-iam/core';

/**
 * OpenSSH certificate authority primitives: the SSH wire encoding (RFC 4251), public key parsing, certificates as
 * specified in OpenSSH's PROTOCOL.certkeys, and key revocation lists (PROTOCOL.krl). Authorities are Ed25519 keys; the
 * keys they certify may be Ed25519, ECDSA (P-256/384/521), RSA (2048 bits or more), or FIDO security keys (`sk-*`).
 * Nothing here touches storage; `api/ssh.ts` seals authority keys and records what was issued.
 */

/** Public key algorithms accepted in certificates, with their certificate type names. */
export const sshKeyTypes = {
  'ssh-ed25519': 'ssh-ed25519-cert-v01@openssh.com',
  'ecdsa-sha2-nistp256': 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
  'ecdsa-sha2-nistp384': 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
  'ecdsa-sha2-nistp521': 'ecdsa-sha2-nistp521-cert-v01@openssh.com',
  'ssh-rsa': 'ssh-rsa-cert-v01@openssh.com',
  'sk-ssh-ed25519@openssh.com': 'sk-ssh-ed25519-cert-v01@openssh.com',
  'sk-ecdsa-sha2-nistp256@openssh.com': 'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com',
} as const;
export type SshKeyType = keyof typeof sshKeyTypes;

/** Certificate kinds (PROTOCOL.certkeys `type`). */
export const SSH_CERT_USER = 1;
export const SSH_CERT_HOST = 2;

/** Extensions a user certificate may carry; `permit-pty` and `permit-user-rc` are granted to every login. */
export const sshExtensions = [
  'permit-X11-forwarding',
  'permit-agent-forwarding',
  'permit-port-forwarding',
  'permit-pty',
  'permit-user-rc',
  'no-touch-required',
] as const;
export type SshExtension = (typeof sshExtensions)[number];

const curves: Record<string, { name: string; crv: string; size: number }> = {
  'ecdsa-sha2-nistp256': { name: 'nistp256', crv: 'P-256', size: 32 },
  'ecdsa-sha2-nistp384': { name: 'nistp384', crv: 'P-384', size: 48 },
  'ecdsa-sha2-nistp521': { name: 'nistp521', crv: 'P-521', size: 66 },
  'sk-ecdsa-sha2-nistp256@openssh.com': { name: 'nistp256', crv: 'P-256', size: 32 },
};

const invalidKey = (message = 'Enter an OpenSSH public key such as "ssh-ed25519 AAAA..."') =>
  new IamError('INVALID_INPUT', message);

/** Builds SSH wire-format data: bytes, uint32/uint64 big-endian, length-prefixed strings. */
export class SshWriter {
  private readonly parts: Buffer[] = [];
  byte(value: number): this {
    this.parts.push(Buffer.from([value]));
    return this;
  }
  u32(value: number): this {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(value);
    this.parts.push(buffer);
    return this;
  }
  u64(value: bigint): this {
    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64BE(value);
    this.parts.push(buffer);
    return this;
  }
  string(value: Buffer | string): this {
    const data = typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
    this.u32(data.length);
    this.parts.push(data);
    return this;
  }
  raw(value: Buffer): this {
    this.parts.push(value);
    return this;
  }
  toBuffer(): Buffer {
    return Buffer.concat(this.parts);
  }
}

/** Reads SSH wire-format data; every read is bounds-checked and a short buffer is an invalid key. */
export class SshReader {
  private offset = 0;
  constructor(private readonly buffer: Buffer) {}
  private take(length: number): Buffer {
    if (length < 0 || this.offset + length > this.buffer.length) throw invalidKey('Truncated data');
    const slice = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }
  byte(): number {
    return this.take(1)[0]!;
  }
  u32(): number {
    return this.take(4).readUInt32BE();
  }
  u64(): bigint {
    return this.take(8).readBigUInt64BE();
  }
  string(): Buffer {
    return this.take(this.u32());
  }
  text(): string {
    return this.string().toString('utf8');
  }
  get position(): number {
    return this.offset;
  }
  get done(): boolean {
    return this.offset === this.buffer.length;
  }
}

/** A parsed OpenSSH public key. */
export interface SshPublicKey {
  type: SshKeyType;
  /** The full key blob (type string included), as base64 in an `authorized_keys` line. */
  blob: Buffer;
  /** The blob after its type string: what a certificate embeds after the nonce. */
  fields: Buffer;
  /** `SHA256:...`, as `ssh-keygen -l` prints it. */
  fingerprint: string;
  /** Hardware security key (FIDO) types. */
  securityKey: boolean;
  /** RSA modulus size. */
  bits?: number;
  comment?: string;
}

/** `SHA256:` plus the unpadded base64 SHA-256 of a key blob. */
export function sshFingerprint(blob: Buffer): string {
  return `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
}

/** An `authorized_keys`-style line for a key blob. */
export function sshKeyLine(blob: Buffer, comment?: string): string {
  const type = new SshReader(blob).text();
  return `${type} ${blob.toString('base64')}${comment ? ` ${comment}` : ''}`;
}

function mpintBits(value: Buffer): number {
  let start = 0;
  while (start < value.length && value[start] === 0) start++;
  if (start === value.length) return 0;
  return (value.length - start - 1) * 8 + (32 - Math.clz32(value[start]!));
}

function unsigned(value: Buffer): Buffer {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start++;
  return value.subarray(start);
}

function checkEcPoint(type: string, curveName: string, point: Buffer): void {
  const curve = curves[type]!;
  if (curveName !== curve.name) throw invalidKey('The ECDSA curve does not match the key type');
  if (point.length !== 1 + 2 * curve.size || point[0] !== 4)
    throw invalidKey('ECDSA keys must be uncompressed points');
  try {
    createPublicKey({
      key: {
        kty: 'EC',
        crv: curve.crv,
        x: point.subarray(1, 1 + curve.size).toString('base64url'),
        y: point.subarray(1 + curve.size).toString('base64url'),
      },
      format: 'jwk',
    });
  } catch {
    throw invalidKey('The ECDSA point is not on its curve');
  }
}

/**
 * Parses and validates one public key line (`type base64 [comment]`). Certificates, DSA keys, RSA keys under 2048
 * bits, malformed points and trailing data are refused.
 */
export function parseSshPublicKey(line: unknown, options: { minRsaBits?: number } = {}): SshPublicKey {
  if (typeof line !== 'string' || line.length > 16384) throw invalidKey();
  const [typeName, data, ...rest] = line.trim().split(/\s+/);
  if (!typeName || !data) throw invalidKey();
  if (!Object.hasOwn(sshKeyTypes, typeName)) {
    if (typeName.includes('-cert-v01@'))
      throw invalidKey('Send the public key, not a certificate');
    throw invalidKey(`Unsupported key type ${typeName.slice(0, 64)}`);
  }
  const type = typeName as SshKeyType;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(data)) throw invalidKey();
  const blob = Buffer.from(data, 'base64');
  const reader = new SshReader(blob);
  if (reader.text() !== type) throw invalidKey('The key data does not match its type');
  const fieldsStart = 4 + Buffer.byteLength(type);
  let bits: number | undefined;
  if (type === 'ssh-ed25519' || type === 'sk-ssh-ed25519@openssh.com') {
    if (reader.string().length !== 32) throw invalidKey('Ed25519 keys are 32 bytes');
  } else if (type === 'ssh-rsa') {
    const e = reader.string();
    const n = reader.string();
    // Canonical mpints only: a padded encoding would fingerprint differently from the key sshd logs.
    for (const part of [e, n])
      if (!part.length || part[0]! & 0x80 || (part[0] === 0 && (part.length === 1 || !(part[1]! & 0x80))))
        throw invalidKey('The RSA key is not canonically encoded');
    bits = mpintBits(n);
    const minimum = options.minRsaBits ?? 2048;
    if (bits < minimum) throw invalidKey(`RSA keys must have at least ${minimum} bits`);
    if (bits > 16384) throw invalidKey('RSA keys may have at most 16384 bits');
    try {
      createPublicKey({
        key: {
          kty: 'RSA',
          n: unsigned(n).toString('base64url'),
          e: unsigned(e).toString('base64url'),
        },
        format: 'jwk',
      });
    } catch {
      throw invalidKey('Invalid RSA key');
    }
  } else {
    const curveName = reader.text();
    checkEcPoint(type, curveName, reader.string());
  }
  const securityKey = type.startsWith('sk-');
  if (securityKey) {
    const application = reader.text();
    if (!application.startsWith('ssh:')) throw invalidKey('Security keys need an ssh: application');
  }
  if (!reader.done) throw invalidKey('Unexpected data after the key');
  const comment = rest.join(' ').slice(0, 256);
  return {
    type,
    blob,
    fields: blob.subarray(fieldsStart),
    fingerprint: sshFingerprint(blob),
    securityKey,
    ...(bits !== undefined ? { bits } : {}),
    ...(comment ? { comment } : {}),
  };
}

/** An Ed25519 certificate authority key: its public blob and the private key that signs. */
export interface SshSigningKey {
  publicBlob: Buffer;
  privateKey: KeyObject;
}

/** A new Ed25519 authority key, with the private key as base64 PKCS#8 DER (the caller seals it). */
export function generateSshAuthorityKey(): { publicBlob: Buffer; privatePkcs8: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x!, 'base64url');
  return {
    publicBlob: new SshWriter().string('ssh-ed25519').string(raw).toBuffer(),
    privatePkcs8: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
  };
}

/** Opens a stored authority key. */
export function sshSigningKey(publicBlob: Buffer, privatePkcs8: string): SshSigningKey {
  return {
    publicBlob,
    privateKey: createPrivateKey({
      key: Buffer.from(privatePkcs8, 'base64'),
      format: 'der',
      type: 'pkcs8',
    }),
  };
}

/** A random non-zero 63-bit serial (KRLs cannot revoke serial 0). */
export function sshSerial(): bigint {
  for (;;) {
    const value = randomBytes(8).readBigUInt64BE() & 0x7fffffffffffffffn;
    if (value !== 0n) return value;
  }
}

export interface SshCertificateSpec {
  key: SshPublicKey;
  serial: bigint;
  kind: typeof SSH_CERT_USER | typeof SSH_CERT_HOST;
  keyId: string;
  principals: string[];
  /** Seconds since the epoch. */
  validAfter: number;
  validBefore: number;
  /** Critical options by name (`force-command`, `source-address`, `verify-required`); the value may be empty. */
  criticalOptions?: Record<string, string>;
  extensions?: string[];
}

const byBytes = (a: string, b: string) => Buffer.compare(Buffer.from(a), Buffer.from(b));

/** Options and extensions are name/data pairs in lexical order; an option's data is itself a string. */
function packOptions(entries: [string, string | undefined][]): Buffer {
  const writer = new SshWriter();
  for (const [name, value] of [...entries].sort(([a], [b]) => byBytes(a, b))) {
    writer.string(name);
    writer.string(value === undefined || value === '' ? Buffer.alloc(0) : new SshWriter().string(value).toBuffer());
  }
  return writer.toBuffer();
}

/** Signs `data` with an Ed25519 authority: an `ssh-ed25519` signature blob. */
export function sshSign(key: SshSigningKey, data: Buffer): Buffer {
  return new SshWriter().string('ssh-ed25519').string(sign(null, data, key.privateKey)).toBuffer();
}

/** Issues an OpenSSH certificate; returns the certificate blob and its `*-cert.pub` line. */
export function signSshCertificate(
  authority: SshSigningKey,
  spec: SshCertificateSpec,
  comment?: string,
): { blob: Buffer; line: string } {
  const principals = new SshWriter();
  for (const principal of spec.principals) principals.string(principal);
  const body = new SshWriter()
    .string(sshKeyTypes[spec.key.type])
    .string(randomBytes(32))
    .raw(spec.key.fields)
    .u64(spec.serial)
    .u32(spec.kind)
    .string(spec.keyId)
    .string(principals.toBuffer())
    .u64(BigInt(spec.validAfter))
    .u64(BigInt(spec.validBefore))
    .string(packOptions(Object.entries(spec.criticalOptions ?? {})))
    .string(packOptions((spec.extensions ?? []).map((name) => [name, undefined])))
    .string(Buffer.alloc(0))
    .string(authority.publicBlob)
    .toBuffer();
  const blob = Buffer.concat([body, new SshWriter().string(sshSign(authority, body)).toBuffer()]);
  return { blob, line: `${sshKeyTypes[spec.key.type]} ${blob.toString('base64')}${comment ? ` ${comment}` : ''}` };
}

/** A decoded certificate (the fields PROTOCOL.certkeys defines), with its signature checked. */
export interface ParsedSshCertificate {
  type: string;
  keyType: SshKeyType;
  publicKeyFingerprint: string;
  serial: bigint;
  kind: number;
  keyId: string;
  principals: string[];
  validAfter: number;
  validBefore: number;
  criticalOptions: Record<string, string>;
  extensions: string[];
  signatureKey: Buffer;
  signatureKeyFingerprint: string;
  /** The authority's Ed25519 signature verifies over the certificate body. */
  signatureValid: boolean;
}

function unpackOptions(data: Buffer, withValues: boolean): [string, string][] {
  const reader = new SshReader(data);
  const result: [string, string][] = [];
  while (!reader.done) {
    const name = reader.text();
    const value = reader.string();
    result.push([name, withValues && value.length ? new SshReader(value).text() : '']);
  }
  return result;
}

/** Decodes a certificate line (`*-cert-v01@openssh.com base64 [comment]`). Only Ed25519 authorities verify. */
export function parseSshCertificate(line: string): ParsedSshCertificate {
  const [typeName, data] = line.trim().split(/\s+/);
  const keyType = (Object.keys(sshKeyTypes) as SshKeyType[]).find(
    (candidate) => sshKeyTypes[candidate] === typeName,
  );
  if (!keyType || !data) throw invalidKey('Not an OpenSSH certificate');
  const blob = Buffer.from(data, 'base64');
  const cert = new SshReader(blob);
  if (cert.text() !== typeName) throw invalidKey('The certificate data does not match its type');
  cert.string(); // nonce
  // The embedded public key fields, by type (ed25519: pk; sk-ed25519: pk, application; rsa: e, n;
  // ecdsa: curve, point; sk-ecdsa: curve, point, application), rebuild the plain key blob.
  const keyStart = cert.position;
  const fieldCount =
    keyType === 'ssh-ed25519' ? 1 : keyType === 'sk-ecdsa-sha2-nistp256@openssh.com' ? 3 : 2;
  for (let index = 0; index < fieldCount; index++) cert.string();
  const keyBlob = Buffer.concat([
    new SshWriter().string(keyType).toBuffer(),
    blob.subarray(keyStart, cert.position),
  ]);
  const serial = cert.u64();
  const kind = cert.u32();
  const keyId = cert.text();
  const principalReader = new SshReader(cert.string());
  const principals: string[] = [];
  while (!principalReader.done) principals.push(principalReader.text());
  const validAfter = Number(cert.u64());
  const validBefore = cert.u64();
  const criticalOptions = Object.fromEntries(unpackOptions(cert.string(), true));
  const extensions = unpackOptions(cert.string(), false).map(([name]) => name);
  cert.string(); // reserved
  const signatureKey = cert.string();
  const bodyLength = cert.position;
  const signature = new SshReader(cert.string());
  if (!cert.done) throw invalidKey('Unexpected data after the certificate');
  const algorithm = signature.text();
  const value = signature.string();
  let signatureValid = false;
  const caReader = new SshReader(signatureKey);
  if (algorithm === 'ssh-ed25519' && caReader.text() === 'ssh-ed25519') {
    const raw = caReader.string();
    try {
      signatureValid = verify(
        null,
        blob.subarray(0, bodyLength),
        createPublicKey({
          key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') },
          format: 'jwk',
        }),
        value,
      );
    } catch {
      signatureValid = false;
    }
  }
  return {
    type: typeName!,
    keyType,
    publicKeyFingerprint: sshFingerprint(keyBlob),
    serial,
    kind,
    keyId,
    principals,
    validAfter,
    // "Forever" (2^64-1) does not fit a safe integer; it is never issued here.
    validBefore: validBefore > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(validBefore),
    criticalOptions,
    extensions,
    signatureKey,
    signatureKeyFingerprint: sshFingerprint(signatureKey),
    signatureValid,
  };
}

const KRL_MAGIC = 0x5353484b524c0a00n;
const KRL_SECTION_CERTIFICATES = 1;
const KRL_SECTION_EXPLICIT_KEY = 2;
const KRL_SECTION_CERT_SERIAL_LIST = 0x20;
const KRL_SECTION_CERT_KEY_ID = 0x23;

/** What one authority revokes. */
export interface KrlAuthoritySection {
  authority: Buffer;
  serials?: bigint[];
  keyIds?: string[];
}

/**
 * A binary OpenSSH key revocation list (PROTOCOL.krl) for sshd `RevokedKeys` and ssh `RevokedHostKeys`: certificate
 * serials and key IDs per authority, plus plain keys revoked outright (such as a disabled host's key).
 */
export function buildSshKrl(input: {
  version: bigint;
  generatedAt: number;
  comment?: string;
  authorities: KrlAuthoritySection[];
  keys?: Buffer[];
}): Buffer {
  const writer = new SshWriter()
    .u64(KRL_MAGIC)
    .u32(1)
    .u64(input.version)
    .u64(BigInt(Math.floor(input.generatedAt / 1000)))
    .u64(0n)
    .string(Buffer.alloc(0))
    .string(input.comment ?? '');
  for (const section of input.authorities) {
    const serials = [...new Set(section.serials ?? [])].filter((serial) => serial > 0n).sort((a, b) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    const keyIds = [...new Set(section.keyIds ?? [])].sort(byBytes);
    if (!serials.length && !keyIds.length) continue;
    const body = new SshWriter().string(section.authority).string(Buffer.alloc(0));
    if (serials.length) {
      const list = new SshWriter();
      for (const serial of serials) list.u64(serial);
      body.byte(KRL_SECTION_CERT_SERIAL_LIST).string(list.toBuffer());
    }
    if (keyIds.length) {
      const list = new SshWriter();
      for (const keyId of keyIds) list.string(keyId);
      body.byte(KRL_SECTION_CERT_KEY_ID).string(list.toBuffer());
    }
    writer.byte(KRL_SECTION_CERTIFICATES).string(body.toBuffer());
  }
  const keys = [...new Map((input.keys ?? []).map((key) => [key.toString('base64'), key])).values()];
  if (keys.length) {
    const list = new SshWriter();
    for (const key of keys.sort(Buffer.compare)) list.string(key);
    writer.byte(KRL_SECTION_EXPLICIT_KEY).string(list.toBuffer());
  }
  return writer.toBuffer();
}

const hostLabel = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i;

/** A host certificate principal: a DNS name (a leading `*.` is refused), or an IPv4/IPv6 address. */
export function sshHostAddress(value: unknown): string {
  if (typeof value !== 'string') throw new IamError('INVALID_INPUT', 'Invalid host address');
  const address = value.trim().toLowerCase().replace(/\.$/, '');
  // No IPv6 zone IDs (`fe80::1%eth0`): they name an interface, not a host.
  if (isIP(address) && !address.includes('%')) return address;
  const labels = address.split('.');
  if (
    address.length > 253 ||
    address.includes('%') ||
    !labels.every((label) => hostLabel.test(label)) ||
    // A dotted name ending in digits (`127.1`, `10.0x1`) reads as an address to some resolvers.
    (labels.length > 1 && /^(?:\d+|0x[0-9a-f]+)$/.test(labels.at(-1)!))
  )
    throw new IamError('INVALID_INPUT', `Invalid host address ${address.slice(0, 64)}`);
  return address;
}

/** A Unix login name, as certificate principals carry them: portable user names only. */
export function sshLogin(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-z_][a-z0-9_.-]{0,31}$/i.test(value) || value.endsWith('.'))
    throw new IamError('INVALID_INPUT', 'Logins are 1-32 letters, digits, "_", "." or "-" and start with a letter or "_"');
  return value;
}

/** The principal a host accepts for a login: `{login}@{host}`, so a certificate names the hosts it opens. */
export const sshLoginPrincipal = (login: string, host: string) => `${login}@${host}`;
