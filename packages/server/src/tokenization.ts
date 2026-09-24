import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomInt,
} from 'node:crypto';
import { IamError, type StoredRecord } from '@better-iam/core';
import { text } from './validation.js';

/**
 * Data protection by tokenization (like Skyflow, VGS or Google DLP de-identification): sensitive values (card
 * numbers, national identifiers, email addresses, phone numbers, free text) are replaced by tokens that are safe to
 * store and pass around. The values themselves are encrypted under a tenant KMS key, and turning a token back into
 * its value is decided by policy per profile and purpose. The API lives in api/protection.ts.
 */

export type DataType = 'card' | 'ssn' | 'email' | 'phone' | 'generic';
export type TokenFormat = 'random' | 'format-preserving';
export type MaskStyle = 'last4' | 'first6last4' | 'email' | 'full';

export interface ProtectionProfile extends StoredRecord {
  /** `name:{name}`: profiles are named in policies (`iam/protection/{name}`). */
  uniqueKey: string;
  name: string;
  description?: string;
  dataType: DataType;
  format: TokenFormat;
  /** The same value always gets the same token, so tokens can be joined and counted. */
  deterministic: boolean;
  /** The tenant AES key that wraps each batch's data key and the lookup key. */
  keyId: string;
  mask: MaskStyle;
  /** Tokens older than this are deleted by `iam.protection.sweep()`. */
  retentionDays?: number;
  /**
   * The HMAC key behind value fingerprints, wrapped under the profile's KMS key like a batch data key: disabling or
   * deleting that key stops lookups too, and stored fingerprints cannot be tested against guesses without it.
   */
  lookupKeyWrapped: string;
  /** Tokens the profile holds, kept by every write so nothing counts them by scanning. */
  tokens: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}

export interface ProtectedToken extends StoredRecord {
  /** `token:{profileId}:{SHA-256 of the token}`: a token names one value in its profile. */
  uniqueKey: string;
  profileId: string;
  token: string;
  /**
   * Keyed HMAC of the normalized value under the profile's lookup key, stored for every profile: deterministic
   * profiles find the token they already issued by it, and erasure by value finds every token of a value.
   */
  fingerprint: string;
  /** The batch's data key, wrapped under the profile's KMS key. */
  wrapped: string;
  /** iv | tag | ciphertext of the normalized value (AES-256-GCM, bound to tenant, profile and token). */
  sealed: string;
  createdAt: number;
  createdBy: string;
}

export interface ProfileSummary {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  dataType: DataType;
  format: TokenFormat;
  deterministic: boolean;
  keyId: string;
  mask: MaskStyle;
  retentionDays?: number;
  /** Tokens the profile holds. */
  tokens: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}

export const protectionActions = Object.freeze({
  read: 'iam:protection:read',
  manage: 'iam:protection:manage',
  tokenize: 'iam:protection:tokenize',
  detokenize: 'iam:protection:detokenize',
  mask: 'iam:protection:mask',
  delete: 'iam:protection:delete',
});

export const dataTypes: readonly DataType[] = ['card', 'ssn', 'email', 'phone', 'generic'];
export const MAX_BATCH = 100;
export const MAX_PROFILES_PER_TENANT = 100;
const MAX_GENERIC_LENGTH = 4096;

export const profileName = (value: unknown): string => {
  const name = text(value, 'profile', 64);
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(name))
    throw new IamError(
      'INVALID_INPUT',
      'Profile names are lowercase letters, digits and hyphens, starting with a letter',
    );
  return name;
};

export function summarizeProfile(profile: ProtectionProfile): ProfileSummary {
  const summary: ProfileSummary = {
    id: profile.id,
    tenantId: profile.tenantId,
    name: profile.name,
    dataType: profile.dataType,
    format: profile.format,
    deterministic: profile.deterministic,
    keyId: profile.keyId,
    mask: profile.mask,
    tokens: profile.tokens ?? 0,
    createdAt: profile.createdAt,
    createdBy: profile.createdBy,
    updatedAt: profile.updatedAt,
  };
  if (profile.description !== undefined) summary.description = profile.description;
  if (profile.retentionDays !== undefined) summary.retentionDays = profile.retentionDays;
  return summary;
}

/** The mask a data type gets when none is named. */
export const defaultMask: Record<DataType, MaskStyle> = {
  card: 'last4',
  ssn: 'last4',
  email: 'email',
  phone: 'last4',
  generic: 'full',
};

/** The masks each data type may use: a style meant for one kind of value can reveal most of another. */
export const maskStyles: Record<DataType, readonly MaskStyle[]> = {
  card: ['last4', 'first6last4', 'full'],
  ssn: ['last4', 'full'],
  email: ['email', 'full'],
  phone: ['last4', 'full'],
  generic: ['full', 'last4'],
};

export function maskStyle(type: DataType, value: unknown, name = 'mask'): MaskStyle {
  if (!maskStyles[type].includes(value as MaskStyle))
    throw new IamError(
      'INVALID_INPUT',
      `${name} must be one of ${maskStyles[type].join(', ')} for ${type} values`,
    );
  return value as MaskStyle;
}

/**
 * Format-preserving `ssn` and `phone` tokens keep the last four digits, leaving few random ones (10,000 tokens per
 * last four of a social security number): issuing a new token on every call would use them up, so these profiles
 * are deterministic.
 */
export const needsDeterministic = (type: DataType, format: TokenFormat): boolean =>
  format === 'format-preserving' && (type === 'ssn' || type === 'phone');

// ---------------------------------------------------------------------------------------------------------------
// Values

const luhnValid = (digits: string): boolean => {
  let sum = 0;
  for (let index = 0; index < digits.length; index++) {
    let digit = Number(digits[digits.length - 1 - index]);
    if (index % 2 === 1) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  return sum % 10 === 0;
};

/** Control characters other than tab and line feed, DEL and the C1 range included. */
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/;
/** Bidirectional formatting controls, which make text display as something other than what it is. */
const BIDI = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/;
/** An unpaired surrogate: storage turns each into U+FFFD, so different values would share a token. */
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/**
 * Validates and normalizes a value for its data type: card numbers to their digits (12 to 19, Luhn-valid), US
 * social security numbers to `NNN-NN-NNNN`, email addresses to NFC lowercase, phone numbers to `+digits` or digits
 * (7 to 15, compared as written, so give them in E.164), and anything else to NFC (up to 4096 characters of
 * well-formed text without control or bidirectional formatting characters; tab and line feed are allowed).
 */
export function normalizeValue(type: DataType, value: unknown): string {
  if (typeof value !== 'string')
    throw new IamError('INVALID_INPUT', 'Every value must be a string');
  const invalid = (what: string) => new IamError('INVALID_INPUT', `Not a valid ${what}`);
  switch (type) {
    case 'card': {
      const digits = value.replace(/[\s-]/g, '');
      if (!/^\d{12,19}$/.test(digits) || !luhnValid(digits)) throw invalid('card number');
      return digits;
    }
    case 'ssn': {
      const digits = value.replace(/[\s-]/g, '');
      if (!/^\d{9}$/.test(digits)) throw invalid('social security number');
      return `${digits.slice(0, 3)}-${digits.slice(3, 5)}-${digits.slice(5)}`;
    }
    case 'email': {
      if (LONE_SURROGATE.test(value)) throw invalid('email address');
      const email = value.trim().normalize('NFC').toLowerCase();
      if (
        email.length > 254 ||
        CONTROL.test(email) ||
        BIDI.test(email) ||
        !/^[^\s@<>()[\],;:"\\]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(email)
      )
        throw invalid('email address');
      return email;
    }
    case 'phone': {
      const compact = value.replace(/[\s().-]/g, '');
      if (!/^\+?\d{7,15}$/.test(compact)) throw invalid('phone number');
      return compact;
    }
    case 'generic': {
      const refuse = () =>
        new IamError(
          'INVALID_INPUT',
          `Values are 1 to ${MAX_GENERIC_LENGTH} characters of well-formed text without control or bidirectional formatting characters`,
        );
      if (LONE_SURROGATE.test(value) || CONTROL.test(value) || BIDI.test(value)) throw refuse();
      const normalized = value.normalize('NFC');
      if (!normalized || normalized.length > MAX_GENERIC_LENGTH) throw refuse();
      return normalized;
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Tokens

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const pick = (alphabet: string, length: number) =>
  Array.from({ length }, () => alphabet[randomInt(alphabet.length)]).join('');
const digits = (length: number) => pick('0123456789', length);

/** Letters and digits of any script: what masks hide and format-preserving tokens replace. */
const MASKABLE = /[\p{L}\p{M}\p{N}]/u;
const LETTER = /[\p{L}\p{M}]/u;
const CAPITAL = /[\p{Lu}\p{Lt}]/u;

/** Group digits that no SSN or ITIN has with a 9XX area (ITIN groups are 50-65, 70-88, 90-92 and 94-99). */
const SSN_TOKEN_GROUPS = Array.from({ length: 100 }, (_, group) => group)
  .filter(
    (group) =>
      (group >= 1 && group <= 49) || (group >= 66 && group <= 69) || group === 89 || group === 93,
  )
  .map((group) => String(group).padStart(2, '0'));

function formatPreserving(type: DataType, value: string): string {
  switch (type) {
    case 'card':
      return digits(value.length - 4) + value.slice(-4);
    case 'ssn':
      return `9${digits(2)}-${SSN_TOKEN_GROUPS[randomInt(SSN_TOKEN_GROUPS.length)]}-${value.slice(-4)}`;
    case 'email':
      return `${pick(LOWER + '0123456789', 16)}@${value.slice(value.lastIndexOf('@') + 1)}`;
    case 'phone': {
      const plus = value.startsWith('+') ? '+' : '';
      const body = value.slice(plus.length);
      return plus + digits(body.length - 4) + body.slice(-4);
    }
    case 'generic':
      return [...value]
        .map((character) =>
          CAPITAL.test(character)
            ? pick(UPPER, 1)
            : LETTER.test(character)
              ? pick(LOWER, 1)
              : /\p{N}/u.test(character)
                ? digits(1)
                : character,
        )
        .join('');
  }
}

/**
 * A new token for a normalized value; never the value itself. Random tokens are `tok_` and 22 base62 characters
 * (131 bits). Format-preserving tokens keep what systems validate or display:
 * - card: the same length and last four digits, but failing the Luhn check, so a token is never a card number;
 * - ssn: `9XX-`, group digits outside the ITIN ranges and the last four digits, so a token is never an SSN or ITIN;
 * - email: a random local part at the same domain;
 * - phone: the same length, leading `+` and last four digits;
 * - generic: the same length in characters, each letter (of any script) replaced by an ASCII letter (capitals by
 *   capitals), each digit by a digit, the rest kept.
 */
export function newToken(type: DataType, format: TokenFormat, value: string): string {
  if (format === 'random') return `tok_${pick(BASE62, 22)}`;
  for (;;) {
    const candidate = formatPreserving(type, value);
    if (candidate !== value && (type !== 'card' || !luhnValid(candidate))) return candidate;
  }
}

/** Format-preserving generic tokens need enough random positions to be unguessable and unique. */
export function formatPreservingSpace(type: DataType, value: string): boolean {
  if (type !== 'generic') return true;
  return [...value].filter((character) => MASKABLE.test(character)).length >= 12;
}

/** Where a token is unique: its profile, by hash (a format-preserving token can be long). */
export const tokenKey = (profileId: string, token: string): string =>
  `token:${profileId}:${createHash('sha256').update(token, 'utf8').digest('base64url')}`;

/**
 * A masked form of a normalized value, for display. A mask never shows more than half of a value's letters and
 * digits, except the first six and last four digits of a card number of 15 or more digits (what PCI DSS allows
 * showing); on a shorter card number `first6last4` shows the last four only. Letters and digits of every script
 * are hidden.
 */
export function maskValue(type: DataType, style: MaskStyle, value: string): string {
  const characters = [...value];
  const total = characters.filter((character) => MASKABLE.test(character)).length;
  const half = Math.floor(total / 2);
  const hide = (keepStart: number, keepEnd: number, capped = true) => {
    if (capped && keepStart + keepEnd > half) {
      keepStart = 0;
      keepEnd = Math.min(keepEnd, half);
    }
    let seen = 0;
    return characters
      .map((character) => {
        if (!MASKABLE.test(character)) return character;
        const position = seen++;
        return position < keepStart || position >= total - keepEnd ? character : '*';
      })
      .join('');
  };
  switch (style) {
    case 'last4':
      return hide(0, 4);
    case 'first6last4':
      return type === 'card' && total >= 15 ? hide(6, 4, false) : hide(0, 4);
    case 'email': {
      const at = value.lastIndexOf('@');
      if (at < 1) return hide(0, 0);
      const local = [...value.slice(0, at)];
      // The first character only when most of the local part stays hidden.
      return `${local.length >= 4 ? local[0] : '*'}***@${value.slice(at + 1)}`;
    }
    case 'full':
      return hide(0, 0);
  }
}

export function fingerprint(key: Buffer, value: string): string {
  return createHmac('sha256', key).update(value, 'utf8').digest('base64url');
}

/** The encryption context of a profile's lookup key (batch data keys are bound to `{ protection }` alone). */
export const lookupContext = (profileId: string) => ({ protection: profileId, use: 'lookup' });

const aad = (tenantId: string, profileId: string, token: string) =>
  Buffer.from(`protection:${tenantId}:${profileId}:${token}`, 'utf8');

export function sealValue(
  dataKey: Buffer,
  tenantId: string,
  profileId: string,
  token: string,
  value: string,
): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
  cipher.setAAD(aad(tenantId, profileId, token));
  const sealed = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), sealed]).toString('base64url');
}

/** Opens a stored value; a record that fails authentication was altered in storage. */
export function openValue(
  dataKey: Buffer,
  record: Pick<ProtectedToken, 'tenantId' | 'profileId' | 'token' | 'sealed'>,
): string {
  try {
    const bytes = Buffer.from(record.sealed, 'base64url');
    const decipher = createDecipheriv('aes-256-gcm', dataKey, bytes.subarray(0, 12));
    decipher.setAAD(aad(record.tenantId, record.profileId, record.token));
    decipher.setAuthTag(bytes.subarray(12, 28));
    return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8');
  } catch {
    throw new IamError('KEY_MATERIAL_UNAVAILABLE', 'A stored value cannot be opened', 500);
  }
}
