import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
} from '@better-iam/core';
import { calculateJwkThumbprint, importJWK } from 'jose';
import type { ServerContext } from '../context.js';
import {
  assuranceOf,
  deviceCollections,
  deviceIntegrationVendors,
  deviceKeyAlgorithm,
  deviceKeyIdPattern,
  devicePlatforms,
  deviceSettingsOf,
  evaluateCompliance,
  isOsVersion,
  maxDeviceIntegrations,
  maxDevicesPerPerson,
  maxKeysPerDevice,
  presentedDevice,
  provesPossession,
  resolveDeviceSettings,
  retireDevice,
  type ComplianceReason,
  type ComplianceResult,
  type DeviceAssurance,
  type DeviceEnrollment,
  type DeviceIntegration,
  type DeviceIntegrationVendor,
  type DeviceKey,
  type DevicePlatform,
  type DevicePosture,
  type DevicePublicJwk,
  type DeviceSettings,
  type DeviceStatus,
  type RegisteredDevice,
  type ResolvedDeviceSettings,
} from '../devices.js';
import { OperationDenied } from '../operations.js';
import { actsInOwnRight } from '../session-kinds.js';
import { byNewest, hash, id, sameHash, token } from '../utils.js';
import { integer, object, text } from '../validation.js';

/** A registered device as administrators see it (`devices.list`, `devices.get`). */
export interface DeviceView {
  id: string;
  tenantId: string;
  name: string;
  platform: DevicePlatform;
  status: DeviceStatus;
  ownerIdentityId?: string;
  /** The owner's name and email, while the owner's identity can be read. */
  owner?: { id: string; name: string; email?: string };
  /** The integration that manages the device and the device's id there. */
  source?: { integrationId: string; externalId: string };
  serialNumber?: string;
  model?: string;
  posture?: DevicePosture;
  lastCheckInAt?: number;
  lastSeenAt?: number;
  enrolledBy?: string;
  createdAt: number;
  updatedAt: number;
  compliance: ComplianceResult;
  /** The assurance a proof from this device gets right now (`none` without an enrolled key or when not active). */
  assurance: DeviceAssurance;
  /** How many keys are enrolled for the device. */
  keys: number;
}

/** One enrolled key of a device (`devices.get`). */
export interface DeviceKeyView {
  /** The key's RFC 7638 thumbprint, the `kid` of its proofs. */
  id: string;
  algorithm: 'ES256' | 'EdDSA';
  createdAt: number;
  createdBy: string;
  lastUsedAt?: number;
}

/** A device with its keys (`devices.get`). */
export interface DeviceDetail extends DeviceView {
  publicKeys: DeviceKeyView[];
}

/** One of the caller's own devices (`devices.mine`, `devices.enroll`). */
export interface MyDevice extends DeviceView {
  /** This request carries a valid proof from the device. */
  current: boolean;
}

/** What the presenting device proves (`devices.check`). */
export interface DeviceCheck {
  assurance: DeviceAssurance;
  deviceId?: string;
  platform?: DevicePlatform;
  managed: boolean;
  compliant: boolean;
  /** Why the verified device is not compliant; empty without a verified device. */
  reasons: ComplianceReason[];
  /** Whether the request carried no proof, a proof that did not verify, or a verified one. */
  proof: 'absent' | 'invalid' | 'verified';
}

/** A device's public key for `devices.enroll`: a public EC P-256 or Ed25519 JWK (as WebCrypto exports it). */
export interface DevicePublicKeyInput {
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
  alg?: string;
  use?: string;
  key_ops?: string[];
  ext?: boolean;
}

export interface DeviceEnrollInput {
  tenantId: string;
  /** Shown in device lists; ignored when an enrollment code binds the key to an existing device. */
  name: string;
  /** Ignored when an enrollment code binds the key to an existing device. */
  platform: DevicePlatform;
  publicKey: DevicePublicKeyInput;
  /** A code from `devices.createEnrollment` (`biam_denr_…`). */
  enrollmentCode?: string;
}

/** An enrollment code as administrators see it; the code itself is shown once, at creation. */
export interface DeviceEnrollmentView {
  id: string;
  tenantId: string;
  deviceId?: string;
  ownerIdentityId?: string;
  status: 'pending' | 'used' | 'expired';
  expiresAt: number;
  createdAt: number;
  createdBy: string;
  usedAt?: number;
  usedBy?: string;
}

/** A new enrollment code (`devices.createEnrollment`); `code` is shown only here. */
export interface DeviceEnrollmentCode {
  code: string;
  expiresAt: number;
  enrollmentId: string;
}

/** The tenant's compliance requirements (`devices.getSettings`, `devices.configure`). */
export interface DeviceSettingsView extends ResolvedDeviceSettings {
  tenantId: string;
  /** False while the tenant uses the defaults. */
  configured: boolean;
  updatedAt?: number;
  updatedBy?: string;
}

/** A device integration with the number of devices it manages. */
export interface DeviceIntegrationView {
  id: string;
  tenantId: string;
  name: string;
  vendor: DeviceIntegrationVendor;
  status: 'active' | 'disabled';
  trustVendorCompliance: boolean;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  lastReportAt?: number;
  devices: number;
}

/** One device in an integration's report (`devices.report`). */
export interface DeviceReport {
  /** The device's id in the integration (printable ASCII, at most 200 characters). */
  externalId: string;
  name?: string;
  platform: DevicePlatform;
  serialNumber?: string;
  model?: string;
  /** The leading dotted number is kept (`14.5 (23F79)` reads as `14.5`); anything else reads as unknown. */
  osVersion?: string;
  /** The owner by email or identity id in the tenant; an unknown owner leaves the device without one. */
  ownerEmail?: string;
  ownerIdentityId?: string;
  /** The thumbprint of a key the integration's agent enrolled on the device: the key moves onto this record. */
  keyThumbprint?: string;
  posture: {
    compliant?: boolean;
    encrypted?: boolean;
    firewall?: boolean;
    screenLock?: boolean;
    edrHealthy?: boolean;
    jailbroken?: boolean;
  };
  /** When the device checked in (epoch milliseconds, default now). */
  checkedInAt?: number;
}

export interface DeviceReportResult {
  created: number;
  updated: number;
  unchanged: number;
  /** Existing devices whose compliance flipped (each audited as `device:compliance-change`). */
  complianceChanged: number;
}

const DAY = 86_400_000;
const MIN_ENROLLMENT_MS = 10 * 60_000;
const MAX_ENROLLMENT_MS = 30 * DAY;
const DEFAULT_ENROLLMENT_MS = 7 * DAY;
/** Pending (unused, unexpired) enrollment codes per tenant. */
const maxPendingEnrollments = 1000;
/** Devices per `devices.report` call. */
const maxReportedDevices = 500;
/** Self-enrolments one person may attempt per rate-limit window. */
const enrollAttempts = 30;
/** `lastCheckInAt`, `lastSeenAt` and `lastUsedAt` are written at most this often unless something else changed. */
const TOUCH_MS = 60_000;

const platforms: ReadonlySet<string> = new Set(devicePlatforms);
const vendors: ReadonlySet<string> = new Set(deviceIntegrationVendors);
const enrollmentCodePattern = /^biam_denr_[A-Za-z0-9_-]{43}$/;
const coordinate = /^[A-Za-z0-9_-]{43}$/;
const privateMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];
/** A vendor device id: printable ASCII without leading or trailing spaces. */
const externalIdPattern = /^[!-~](?:[ -~]{0,198}[!-~])?$/;
const leadingVersion = /^v?(\d{1,9}(?:\.\d{1,9}){0,7})/i;
const postureFields = [
  'compliant',
  'encrypted',
  'firewall',
  'screenLock',
  'edrHealthy',
  'jailbroken',
] as const;
const reportFields = [
  'externalId',
  'name',
  'platform',
  'serialNumber',
  'model',
  'osVersion',
  'ownerEmail',
  'ownerIdentityId',
  'keyThumbprint',
  'posture',
  'checkedInAt',
];

const deviceResource = (deviceId: string) => `devices/${deviceId}`;
const integrationResource = (integrationId: string) => `devices/integrations/${integrationId}`;

function platformOf(value: unknown, name = 'platform'): DevicePlatform {
  if (typeof value !== 'string' || !platforms.has(value))
    throw new IamError('INVALID_INPUT', `${name} must be one of ${devicePlatforms.join(', ')}`);
  return value as DevicePlatform;
}

function flag(value: unknown, name: string): boolean {
  if (typeof value !== 'boolean') throw new IamError('INVALID_INPUT', `${name} must be a boolean`);
  return value;
}

/** The input object, refusing fields the call does not know (a misspelt setting must not pass silently). */
function fieldsOf(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  const input = object(value);
  for (const key of Object.keys(input))
    if (!allowed.includes(key)) throw new IamError('INVALID_INPUT', `Unknown field ${key}`);
  return input;
}

const deviceName = (value: unknown): string => text(value, 'name', 128).trim();

const invalidKey = () =>
  new IamError('INVALID_INPUT', 'publicKey must be a public EC P-256 or Ed25519 JWK');

/** A public EC P-256 or Ed25519 JWK reduced to its public members; private material is refused outright. */
function publicKeyOf(value: unknown): DevicePublicJwk {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalidKey();
  const jwk = value as Record<string, unknown>;
  if (privateMembers.some((member) => jwk[member] !== undefined))
    throw new IamError('INVALID_INPUT', 'publicKey must not contain private key material');
  if (jwk.use !== undefined && jwk.use !== 'sig') throw invalidKey();
  const x = typeof jwk.x === 'string' && coordinate.test(jwk.x) ? jwk.x : undefined;
  if (
    jwk.kty === 'EC' &&
    jwk.crv === 'P-256' &&
    x &&
    typeof jwk.y === 'string' &&
    coordinate.test(jwk.y) &&
    (jwk.alg === undefined || jwk.alg === 'ES256')
  )
    return { kty: 'EC', crv: 'P-256', x, y: jwk.y };
  if (
    jwk.kty === 'OKP' &&
    jwk.crv === 'Ed25519' &&
    x &&
    jwk.y === undefined &&
    (jwk.alg === undefined || jwk.alg === 'EdDSA' || jwk.alg === 'Ed25519')
  )
    return { kty: 'OKP', crv: 'Ed25519', x };
  throw invalidKey();
}

/** The key's thumbprint (its id), after checking the key imports (an EC point must lie on the curve). */
async function keyIdOf(jwk: DevicePublicJwk): Promise<string> {
  try {
    await importJWK({ ...jwk }, deviceKeyAlgorithm(jwk));
  } catch {
    throw invalidKey();
  }
  return calculateJwkThumbprint({ ...jwk }, 'sha256');
}

/** Self-service calls act for the caller in their own tenant, from a session in their own right. */
function ownSession(principal: AuthenticatedPrincipal, tenantId: string, message: string): void {
  if (
    !actsInOwnRight(principal.session) ||
    principal.session.tenantId !== tenantId ||
    principal.identity.tenantId !== tenantId
  )
    throw new IamError('ACCESS_DENIED', message, 403);
}

function notImpersonating(principal: AuthenticatedPrincipal): void {
  if (principal.session.impersonatorId)
    throw new IamError(
      'IMPERSONATION_RESTRICTED',
      'Devices cannot be enrolled or retired while impersonating',
      403,
    );
}

const invalidCode = () => new IamError('INVALID_INPUT', 'Invalid or expired enrollment code');

function deviceView(
  device: RegisteredDevice,
  compliance: ComplianceResult,
  keys: number,
  owner: Identity | undefined,
): DeviceView {
  return {
    id: device.id,
    tenantId: device.tenantId,
    name: device.name,
    platform: device.platform,
    status: device.status,
    ...(device.ownerIdentityId !== undefined ? { ownerIdentityId: device.ownerIdentityId } : {}),
    ...(owner
      ? {
          owner: {
            id: owner.id,
            name: owner.name,
            ...(owner.email !== undefined ? { email: owner.email } : {}),
          },
        }
      : {}),
    ...(device.source
      ? {
          source: {
            integrationId: device.source.integrationId,
            externalId: device.source.externalId,
          },
        }
      : {}),
    ...(device.serialNumber !== undefined ? { serialNumber: device.serialNumber } : {}),
    ...(device.model !== undefined ? { model: device.model } : {}),
    ...(device.posture ? { posture: { ...device.posture } } : {}),
    ...(device.lastCheckInAt !== undefined ? { lastCheckInAt: device.lastCheckInAt } : {}),
    ...(device.lastSeenAt !== undefined ? { lastSeenAt: device.lastSeenAt } : {}),
    ...(device.enrolledBy !== undefined ? { enrolledBy: device.enrolledBy } : {}),
    createdAt: device.createdAt,
    updatedAt: device.updatedAt,
    compliance,
    assurance: assuranceOf(compliance, device.status === 'active' && keys > 0),
    keys,
  };
}

/** Views of devices of one tenant, reading the settings, integrations, key counts and owners once. */
async function describe(
  tx: IamStore,
  tenantId: string,
  devices: RegisteredDevice[],
  now: number,
): Promise<DeviceView[]> {
  if (!devices.length) return [];
  const settings = await deviceSettingsOf(tx, tenantId);
  const integrations = new Map(
    (await tx.find<DeviceIntegration>(deviceCollections.integrations, { tenantId })).map(
      (integration) => [integration.id, integration],
    ),
  );
  const keyCounts = new Map<string, number>();
  if (devices.length > 20)
    for (const key of await tx.find<DeviceKey>(deviceCollections.keys, { tenantId }))
      keyCounts.set(key.deviceId, (keyCounts.get(key.deviceId) ?? 0) + 1);
  else
    for (const device of devices)
      keyCounts.set(
        device.id,
        (await tx.find<DeviceKey>(deviceCollections.keys, { tenantId, deviceId: device.id }))
          .length,
      );
  const owners = new Map<string, Identity | undefined>();
  const views: DeviceView[] = [];
  for (const device of devices) {
    const ownerId = device.ownerIdentityId;
    if (ownerId !== undefined && !owners.has(ownerId)) {
      const identity = await tx.get<Identity>('identities', ownerId);
      owners.set(ownerId, identity?.tenantId === tenantId ? identity : undefined);
    }
    const integration = device.source ? integrations.get(device.source.integrationId) : undefined;
    views.push(
      deviceView(
        device,
        evaluateCompliance(device, integration, settings, now),
        keyCounts.get(device.id) ?? 0,
        ownerId !== undefined ? owners.get(ownerId) : undefined,
      ),
    );
  }
  return views;
}

function enrollmentView(enrollment: DeviceEnrollment, now: number): DeviceEnrollmentView {
  return {
    id: enrollment.id,
    tenantId: enrollment.tenantId,
    ...(enrollment.deviceId !== undefined ? { deviceId: enrollment.deviceId } : {}),
    ...(enrollment.ownerIdentityId !== undefined
      ? { ownerIdentityId: enrollment.ownerIdentityId }
      : {}),
    status:
      enrollment.usedAt !== undefined ? 'used' : enrollment.expiresAt <= now ? 'expired' : 'pending',
    expiresAt: enrollment.expiresAt,
    createdAt: enrollment.createdAt,
    createdBy: enrollment.createdBy,
    ...(enrollment.usedAt !== undefined ? { usedAt: enrollment.usedAt } : {}),
    ...(enrollment.usedBy !== undefined ? { usedBy: enrollment.usedBy } : {}),
  };
}

function integrationView(integration: DeviceIntegration, devices: number): DeviceIntegrationView {
  return {
    id: integration.id,
    tenantId: integration.tenantId,
    name: integration.name,
    vendor: integration.vendor,
    status: integration.status,
    trustVendorCompliance: integration.trustVendorCompliance,
    createdAt: integration.createdAt,
    createdBy: integration.createdBy,
    updatedAt: integration.updatedAt,
    ...(integration.lastReportAt !== undefined ? { lastReportAt: integration.lastReportAt } : {}),
    devices,
  };
}

function integrationMetadata(integration: DeviceIntegration): Record<string, Json> {
  return {
    name: integration.name,
    vendor: integration.vendor,
    status: integration.status,
    trustVendorCompliance: integration.trustVendorCompliance,
  };
}

function settingsView(tenantId: string, stored: DeviceSettings | undefined): DeviceSettingsView {
  return {
    ...resolveDeviceSettings(stored),
    tenantId,
    configured: stored !== undefined,
    ...(stored ? { updatedAt: stored.updatedAt, updatedBy: stored.updatedBy } : {}),
  };
}

function settingsMetadata(settings: ResolvedDeviceSettings): Record<string, Json> {
  return {
    requireEncrypted: settings.requireEncrypted,
    requireScreenLock: settings.requireScreenLock,
    requireFirewall: settings.requireFirewall,
    requireEdr: settings.requireEdr,
    blockJailbroken: settings.blockJailbroken,
    minOsVersions: { ...settings.minOsVersions } as Record<string, string>,
    maxCheckInAgeHours: settings.maxCheckInAgeHours,
  };
}

/** A person of the tenant who can own a device (a user identity that is not deleted). */
function person(identity: Identity | undefined, tenantId: string): identity is Identity {
  return (
    identity !== undefined &&
    identity.tenantId === tenantId &&
    identity.kind === 'user' &&
    identity.status !== 'deleted'
  );
}

/** A report item after validation. */
interface ReportItem {
  externalId: string;
  name?: string;
  platform: DevicePlatform;
  serialNumber?: string;
  model?: string;
  osVersion?: string;
  /** Whether the report names an owner at all (then an unknown one clears it). */
  ownerNamed: boolean;
  ownerIdentityId?: string;
  ownerEmail?: string;
  keyThumbprint?: string;
  posture: Partial<Record<(typeof postureFields)[number], boolean>>;
  checkedInAt: number;
}

function reportItems(value: unknown, now: number): ReportItem[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > maxReportedDevices)
    throw new IamError(
      'INVALID_INPUT',
      `devices must list 1-${maxReportedDevices} device reports`,
    );
  const seen = new Set<string>();
  return value.map((raw, index) => {
    const at = `devices[${index}]`;
    const input = fieldsOf(raw, reportFields);
    const externalId = input.externalId;
    if (typeof externalId !== 'string' || !externalIdPattern.test(externalId))
      throw new IamError('INVALID_INPUT', `${at}.externalId is invalid`);
    if (seen.has(externalId))
      throw new IamError('INVALID_INPUT', `${at}.externalId repeats an earlier device`);
    seen.add(externalId);
    // Connectors often send null or an empty string for a field the vendor does not know: both read as absent.
    const given = (name: string) => {
      const value = input[name];
      return value === undefined || value === null || (typeof value === 'string' && !value.trim())
        ? undefined
        : value;
    };
    const optional = (name: string, max: number) => {
      const value = given(name);
      return value === undefined ? undefined : text(value, `${at}.${name}`, max).trim();
    };
    const posture = fieldsOf(given('posture') ?? {}, postureFields);
    const reported: ReportItem['posture'] = {};
    for (const field of postureFields)
      if (posture[field] !== undefined && posture[field] !== null)
        reported[field] = flag(posture[field], `${at}.posture.${field}`);
    let osVersion: string | undefined;
    const os = given('osVersion');
    if (os !== undefined) {
      if (typeof os !== 'string' || os.length > 64)
        throw new IamError(
          'INVALID_INPUT',
          `${at}.osVersion must be a string of at most 64 characters`,
        );
      const match = leadingVersion.exec(os.trim());
      osVersion = match && isOsVersion(match[1]) ? match[1] : undefined;
    }
    const ownerIdentityId = optional('ownerIdentityId', 256);
    const ownerEmail = optional('ownerEmail', 254)?.toLowerCase();
    const keyThumbprint = given('keyThumbprint');
    if (
      keyThumbprint !== undefined &&
      (typeof keyThumbprint !== 'string' || !deviceKeyIdPattern.test(keyThumbprint))
    )
      throw new IamError('INVALID_INPUT', `${at}.keyThumbprint must be a JWK thumbprint`);
    const reportedAt = given('checkedInAt');
    const checkedInAt =
      reportedAt === undefined
        ? now
        : Math.min(integer(reportedAt, `${at}.checkedInAt`, 0, now + 5 * 60_000), now);
    const name = optional('name', 128);
    const serialNumber = optional('serialNumber', 128);
    const model = optional('model', 128);
    return {
      externalId,
      ...(name ? { name } : {}),
      platform: platformOf(input.platform, `${at}.platform`),
      ...(serialNumber ? { serialNumber } : {}),
      ...(model ? { model } : {}),
      ...(osVersion ? { osVersion } : {}),
      ownerNamed: ownerIdentityId !== undefined || ownerEmail !== undefined,
      ...(ownerIdentityId ? { ownerIdentityId } : {}),
      ...(ownerEmail ? { ownerEmail } : {}),
      ...(keyThumbprint !== undefined ? { keyThumbprint } : {}),
      posture: reported,
      checkedInAt,
    };
  });
}

/** What a report can change on a device, for telling a real change from a repeated check-in. */
function reportedState(device: RegisteredDevice): string {
  const posture = device.posture;
  return JSON.stringify([
    device.name,
    device.platform,
    device.ownerIdentityId ?? null,
    device.serialNumber ?? null,
    device.model ?? null,
    posture?.integrationId ?? null,
    ...postureFields.map((field) => posture?.[field] ?? null),
    posture?.osVersion ?? null,
  ]);
}

/**
 * Device posture: registered devices, the keys that prove a request comes from one, the integrations (MDM, EDR) that
 * manage devices and report their posture, and the tenant's compliance requirements. People enrol their own devices and
 * list or retire them without a permission; administrators hold `iam:devices:read` / `iam:devices:manage` on
 * `iam/devices…`; integrations report with `iam:devices:report` on `iam/devices/integrations/{id}` (an API key of a
 * service account). Policies see the presenting device as `request.deviceAssurance`, `request.deviceManaged`,
 * `request.deviceCompliant`, `request.deviceId` and `request.devicePlatform`.
 */
export function createDevicesApi(ctx: ServerContext) {
  const { operation } = ctx.operations;

  async function audit(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    action: string,
    tenantId: string,
    resourceId: string,
    metadata: Record<string, Json>,
  ) {
    await ctx.events.audit(tx, principal, action, tenantId, resourceId, 'allow', false, metadata);
  }

  /** The id of the device this request's proof verifies for, if any. */
  async function currentDeviceId(tx: IamStore, principal: AuthenticatedPrincipal) {
    return (await presentedDevice(tx, principal, ctx.now()))?.device.id;
  }

  /** A pending, unexpired enrollment code of the tenant, or INVALID_INPUT. */
  async function usableEnrollment(tx: IamStore, tenantId: string, code: string, now: number) {
    const codeHash = hash(code);
    const enrollment = (
      await tx.find<DeviceEnrollment>(deviceCollections.enrollments, {
        tenantId,
        uniqueKey: codeHash,
      })
    )[0];
    if (
      !enrollment ||
      !sameHash(enrollment.codeHash, codeHash) ||
      enrollment.usedAt !== undefined ||
      enrollment.expiresAt <= now
    )
      throw invalidCode();
    return enrollment;
  }

  /** A person of the tenant, for owner fields; INVALID_INPUT for anyone else. */
  async function ownerOf(tx: IamStore, tenantId: string, value: unknown): Promise<Identity> {
    const identity = await tx.get<Identity>('identities', text(value, 'ownerIdentityId'));
    if (!person(identity, tenantId))
      throw new IamError('INVALID_INPUT', 'ownerIdentityId must name a person of the tenant');
    return identity;
  }

  /**
   * Moves a key an integration's agent enrolled onto the device the integration reports it on. Only the key's own
   * record of this machine gives it up: the same person's self-enrolled device, or another record of this integration
   * with the same owner, and only while that device is active. So a report never revives a key on a device an
   * administrator marked lost, never takes one off a shared device, another person's device, or a device another
   * integration manages, and never hands a key to a device without the key's owner.
   */
  async function claimKey(
    tx: IamStore,
    thumbprint: string,
    device: RegisteredDevice,
    now: number,
  ): Promise<boolean> {
    const key = await tx.get<DeviceKey>(deviceCollections.keys, thumbprint);
    if (!key || key.tenantId !== device.tenantId || key.deviceId === device.id) return false;
    const previous = await tx.get<RegisteredDevice>(deviceCollections.devices, key.deviceId);
    if (
      !previous ||
      previous.tenantId !== device.tenantId ||
      previous.status !== 'active' ||
      previous.ownerIdentityId === undefined ||
      previous.ownerIdentityId !== device.ownerIdentityId ||
      (previous.source !== undefined &&
        previous.source.integrationId !== device.source?.integrationId)
    )
      return false;
    await tx.put<DeviceKey>(deviceCollections.keys, { ...key, deviceId: device.id });
    // The same person's self-enrolled record of this machine is superseded by the managed one.
    if (
      !previous.source &&
      (
        await tx.find<DeviceKey>(deviceCollections.keys, {
          tenantId: previous.tenantId,
          deviceId: previous.id,
        })
      ).length === 0
    )
      await retireDevice(tx, previous, now);
    return true;
  }

  return {
    // ---------------------------------------------------------------------------------------------------------
    // Self-service

    /**
     * Enrols a key for the caller's device (people only, from an ordinary session of their tenant; never while
     * impersonating). Without `enrollmentCode` it registers a new unmanaged device the caller owns (at most 20 per
     * person). With a code from `devices.createEnrollment` it binds the key to the code's device (which must be active
     * and shared or the caller's) or, when the code names none, creates one owned by the code's person (unset: a shared
     * device); the code is then used up. The key is a public EC P-256 or Ed25519 JWK; its RFC 7638 thumbprint becomes
     * the `keyId` that proofs name, and a key enrolled anywhere already is refused (CONFLICT). The request must carry a
     * device proof signed with that key for this session (`x-better-iam-device`, as the client helper's `headers()`
     * adds), proving the caller holds it, and the session needs a recent sign-in. Rate limited per person; audited as
     * `device:enroll`.
     */
    enroll: async (
      credential: CredentialInput,
      input: DeviceEnrollInput,
    ): Promise<{ device: MyDevice; keyId: string }> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const name = deviceName(input.name);
      const platform = platformOf(input.platform);
      const jwk = publicKeyOf(input.publicKey);
      const code = input.enrollmentCode;
      if (code !== undefined && (typeof code !== 'string' || !enrollmentCodePattern.test(code)))
        throw invalidCode();
      const keyId = await keyIdOf(jwk);
      const authenticated = await ctx.principals.authenticate(credential);
      if (authenticated.session.tenantId !== tenantId)
        throw new IamError(
          'ACCESS_DENIED',
          'Devices are enrolled from an ordinary session of their tenant',
          403,
        );
      // Outside the transaction, so a refusal inside it cannot roll the counter back.
      await ctx.auth.limitAttempt(tenantId, `device-enroll:${authenticated.identity.id}`, {
        limit: enrollAttempts,
      });
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        ownSession(principal, tenantId, 'Devices are enrolled from an ordinary session of their tenant');
        notImpersonating(principal);
        if (principal.identity.kind !== 'user')
          throw new IamError('INVALID_INPUT', 'Only people enrol devices');
        // A stolen session must not bring a key of its own (passkey registration asks for a recent sign-in too), and
        // the caller must hold the key: the request carries a proof signed with it for this session.
        ctx.auth.requireRecent(principal);
        if (!(await provesPossession(principal, jwk, keyId, ctx.now())))
          throw new IamError(
            'INVALID_INPUT',
            'Send a device proof (x-better-iam-device) signed with the key being enrolled',
          );
        const callerId = principal.identity.id;
        if (await tx.get(deviceCollections.keys, keyId))
          throw new IamError('CONFLICT', 'This key is already enrolled', 409);
        const now = ctx.now();
        const enrollment = code !== undefined ? await usableEnrollment(tx, tenantId, code, now) : undefined;
        if (enrollment?.ownerIdentityId !== undefined && enrollment.ownerIdentityId !== callerId)
          throw new IamError('ACCESS_DENIED', 'This enrollment code is for someone else', 403);
        let device: RegisteredDevice;
        let created = false;
        if (enrollment?.deviceId !== undefined) {
          const target = await tx.get<RegisteredDevice>(deviceCollections.devices, enrollment.deviceId);
          if (!target || target.tenantId !== tenantId) throw invalidCode();
          if (target.status !== 'active')
            throw new IamError('INVALID_TRANSITION', 'The device is not active', 409);
          if (target.ownerIdentityId !== undefined && target.ownerIdentityId !== callerId)
            throw new IamError('ACCESS_DENIED', 'The device belongs to someone else', 403);
          const keys = await tx.find<DeviceKey>(deviceCollections.keys, {
            tenantId,
            deviceId: target.id,
          });
          if (keys.length >= maxKeysPerDevice)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A device can hold at most ${maxKeysPerDevice} keys`,
              409,
            );
          device = await tx.put<RegisteredDevice>(deviceCollections.devices, {
            ...target,
            ...(enrollment.ownerIdentityId !== undefined
              ? { ownerIdentityId: enrollment.ownerIdentityId }
              : {}),
            enrolledBy: callerId,
            updatedAt: now,
          });
        } else {
          // Without a code the caller owns the device; a code without a device names its owner (or none: shared).
          const owner = enrollment ? enrollment.ownerIdentityId : callerId;
          if (owner !== undefined) {
            const owned = (
              await tx.find<RegisteredDevice>(deviceCollections.devices, {
                tenantId,
                ownerIdentityId: owner,
              })
            ).filter((record) => record.status !== 'retired');
            if (owned.length >= maxDevicesPerPerson)
              throw new IamError(
                'LIMIT_EXCEEDED',
                `A person can register at most ${maxDevicesPerPerson} devices`,
                409,
              );
          }
          device = await tx.insert<RegisteredDevice>(deviceCollections.devices, {
            id: id(),
            tenantId,
            name,
            platform,
            status: 'active',
            ...(owner !== undefined ? { ownerIdentityId: owner } : {}),
            enrolledBy: callerId,
            createdAt: now,
            updatedAt: now,
          });
          created = true;
        }
        await tx.insert<DeviceKey>(deviceCollections.keys, {
          id: keyId,
          tenantId,
          deviceId: device.id,
          jwk,
          createdAt: now,
          createdBy: callerId,
        });
        if (enrollment)
          await tx.put<DeviceEnrollment>(deviceCollections.enrollments, {
            ...enrollment,
            usedAt: now,
            usedBy: callerId,
          });
        await audit(tx, principal, 'device:enroll', tenantId, deviceResource(device.id), {
          deviceId: device.id,
          keyId,
          platform: device.platform,
          created,
          managed: device.source !== undefined,
          ...(enrollment ? { enrollmentId: enrollment.id } : {}),
        });
        const [view] = await describe(tx, tenantId, [device], now);
        return {
          device: { ...view!, current: (await currentDeviceId(tx, principal)) === device.id },
          keyId,
        };
      });
    },

    /**
     * The caller's devices that are not retired, the one this request presents first (`current`), each with its
     * compliance and assurance. Needs only an ordinary session of the tenant; readable while impersonating.
     */
    mine: async (credential: CredentialInput, input: { tenantId: string }): Promise<MyDevice[]> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        ownSession(principal, tenantId, 'Devices are listed from an ordinary session of their tenant');
        const devices = (
          await tx.find<RegisteredDevice>(deviceCollections.devices, {
            tenantId,
            ownerIdentityId: principal.identity.id,
          })
        ).filter((device) => device.status !== 'retired');
        const current = await currentDeviceId(tx, principal);
        return (await describe(tx, tenantId, devices, ctx.now()))
          .map((view) => ({ ...view, current: view.id === current }))
          .sort((a, b) => Number(b.current) - Number(a.current) || byNewest(a, b));
      });
    },

    /**
     * Retires one of the caller's own unmanaged devices: it stops proving anything and its keys are deleted. Managed
     * devices are retired by administrators. Needs a recent sign-in, never while impersonating; audited as
     * `device:retire`.
     */
    retireMine: async (
      credential: CredentialInput,
      input: { tenantId: string; deviceId: string },
    ): Promise<{ success: true; keysRemoved: number }> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const deviceId = text(input.deviceId, 'deviceId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        ownSession(principal, tenantId, 'Devices are retired from an ordinary session of their tenant');
        notImpersonating(principal);
        // A stolen session must not take the person's own devices away either.
        ctx.auth.requireRecent(principal);
        const device = await ctx.scoped<RegisteredDevice>(
          tx,
          deviceCollections.devices,
          deviceId,
          tenantId,
        );
        if (device.ownerIdentityId !== principal.identity.id)
          throw new IamError('NOT_FOUND', 'Resource not found', 404);
        if (device.source)
          throw new IamError(
            'INVALID_TRANSITION',
            'Managed devices are retired by administrators',
            409,
          );
        if (device.status === 'retired')
          throw new IamError('INVALID_TRANSITION', 'The device is already retired', 409);
        const { keysRemoved } = await retireDevice(tx, device, ctx.now());
        await audit(tx, principal, 'device:retire', tenantId, deviceResource(device.id), {
          deviceId: device.id,
          keysRemoved,
          self: true,
        });
        return { success: true as const, keysRemoved };
      });
    },

    /**
     * What the device presenting this request proves: its assurance, id, platform and compliance, or `none` when the
     * request carries no valid proof (`proof` says which). Records when the device and key were last seen (at most once
     * a minute). Needs only a session of the tenant.
     */
    check: async (credential: CredentialInput, input: { tenantId: string }): Promise<DeviceCheck> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        if (principal.session.tenantId !== tenantId)
          throw new IamError('ACCESS_DENIED', 'Devices are checked from a session of their tenant', 403);
        const now = ctx.now();
        const presented = await presentedDevice(tx, principal, now);
        if (!presented)
          return {
            assurance: 'none',
            managed: false,
            compliant: false,
            reasons: [],
            proof: principal.deviceProof === undefined ? 'absent' : 'invalid',
          };
        const { device, key, compliance } = presented;
        if (now - (device.lastSeenAt ?? 0) >= TOUCH_MS)
          await tx.put<RegisteredDevice>(deviceCollections.devices, { ...device, lastSeenAt: now });
        if (now - (key.lastUsedAt ?? 0) >= TOUCH_MS)
          await tx.put<DeviceKey>(deviceCollections.keys, { ...key, lastUsedAt: now });
        return {
          assurance: presented.assurance,
          deviceId: device.id,
          platform: device.platform,
          managed: compliance.managed,
          compliant: compliance.compliant,
          reasons: compliance.reasons,
          proof: 'verified',
        };
      });
    },

    // ---------------------------------------------------------------------------------------------------------
    // Administration

    /**
     * The tenant's devices, newest first, each with compliance, assurance, key count and owner. Filters: owner,
     * status, platform, `managed`, `compliant`, and `query` (name, serial number, model, external id or owner, case
     * insensitive). Requires iam:devices:read on `iam/devices`.
     */
    list: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        ownerIdentityId?: string;
        status?: DeviceStatus;
        managed?: boolean;
        compliant?: boolean;
        platform?: DevicePlatform;
        query?: string;
        limit?: number;
        offset?: number;
      },
    ): Promise<{ devices: DeviceView[]; total: number }> => {
      const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
      const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
      const ownerIdentityId =
        input.ownerIdentityId === undefined
          ? undefined
          : text(input.ownerIdentityId, 'ownerIdentityId');
      if (
        input.status !== undefined &&
        input.status !== 'active' &&
        input.status !== 'lost' &&
        input.status !== 'retired'
      )
        throw new IamError('INVALID_INPUT', 'status must be active, lost or retired');
      const platform = input.platform === undefined ? undefined : platformOf(input.platform);
      const managed = input.managed === undefined ? undefined : flag(input.managed, 'managed');
      const compliant =
        input.compliant === undefined ? undefined : flag(input.compliant, 'compliant');
      const query =
        input.query === undefined ? undefined : text(input.query, 'query', 200).trim().toLowerCase();
      return operation(credential, input.tenantId, 'iam:devices:read', 'devices', async ({ tx, tenant }) => {
        const devices = await tx.find<RegisteredDevice>(deviceCollections.devices, {
          tenantId: tenant.id,
          ...(ownerIdentityId !== undefined ? { ownerIdentityId } : {}),
          ...(input.status !== undefined ? { status: input.status } : {}),
          ...(platform !== undefined ? { platform } : {}),
        });
        const views = (await describe(tx, tenant.id, devices, ctx.now()))
          .filter(
            (view) =>
              (managed === undefined || view.compliance.managed === managed) &&
              (compliant === undefined || view.compliance.compliant === compliant) &&
              (!query ||
                [
                  view.id,
                  view.name,
                  view.serialNumber,
                  view.model,
                  view.source?.externalId,
                  view.owner?.name,
                  view.owner?.email,
                ].some((value) => value?.toLowerCase().includes(query))),
          )
          .sort(byNewest);
        return { devices: views.slice(offset, offset + limit), total: views.length };
      });
    },

    /** One device with its keys. Requires iam:devices:read on `iam/devices/{id}`. */
    get: async (
      credential: CredentialInput,
      input: { tenantId: string; deviceId: string },
    ): Promise<DeviceDetail> => {
      const deviceId = text(input.deviceId, 'deviceId');
      return operation(
        credential,
        input.tenantId,
        'iam:devices:read',
        deviceResource(deviceId),
        async ({ tx, tenant }) => {
          const device = await ctx.scoped<RegisteredDevice>(
            tx,
            deviceCollections.devices,
            deviceId,
            tenant.id,
          );
          const [view] = await describe(tx, tenant.id, [device], ctx.now());
          const keys = await tx.find<DeviceKey>(deviceCollections.keys, {
            tenantId: tenant.id,
            deviceId: device.id,
          });
          return {
            ...view!,
            publicKeys: keys.sort(byNewest).map((key) => ({
              id: key.id,
              algorithm: deviceKeyAlgorithm(key.jwk) ?? 'ES256',
              createdAt: key.createdAt,
              createdBy: key.createdBy,
              ...(key.lastUsedAt !== undefined ? { lastUsedAt: key.lastUsedAt } : {}),
            })),
          };
        },
      );
    },

    /**
     * Renames a device, reassigns it (`ownerIdentityId`, a person of the tenant, or `null` for a shared device) or
     * marks it `lost` (it stops proving anything) or `active` again. A new owner drops the keys the previous owner
     * enrolled. Retired devices cannot change. Requires iam:devices:manage on `iam/devices/{id}` and recent
     * authentication; audited as `device:update`.
     */
    update: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        deviceId: string;
        name?: string;
        ownerIdentityId?: string | null;
        status?: 'active' | 'lost';
      },
    ): Promise<DeviceView> => {
      const fields = fieldsOf(input, ['tenantId', 'deviceId', 'name', 'ownerIdentityId', 'status']);
      const deviceId = text(input.deviceId, 'deviceId');
      const name = fields.name === undefined ? undefined : deviceName(fields.name);
      if (fields.status !== undefined && fields.status !== 'active' && fields.status !== 'lost')
        throw new IamError('INVALID_INPUT', 'status must be active or lost');
      if (name === undefined && fields.status === undefined && fields.ownerIdentityId === undefined)
        throw new IamError('INVALID_INPUT', 'Nothing to update');
      return operation(
        credential,
        input.tenantId,
        'iam:devices:manage',
        deviceResource(deviceId),
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const device = await ctx.scoped<RegisteredDevice>(
            tx,
            deviceCollections.devices,
            deviceId,
            tenant.id,
          );
          if (device.status === 'retired')
            throw new IamError('INVALID_TRANSITION', 'Retired devices cannot change', 409);
          const owner =
            fields.ownerIdentityId === undefined
              ? device.ownerIdentityId
              : fields.ownerIdentityId === null
                ? undefined
                : (await ownerOf(tx, tenant.id, fields.ownerIdentityId)).id;
          const status = (fields.status as 'active' | 'lost' | undefined) ?? device.status;
          const now = ctx.now();
          let keysRemoved = 0;
          if (owner !== device.ownerIdentityId && device.ownerIdentityId !== undefined)
            for (const key of await tx.find<DeviceKey>(deviceCollections.keys, {
              tenantId: tenant.id,
              deviceId: device.id,
              createdBy: device.ownerIdentityId,
            })) {
              await tx.delete(deviceCollections.keys, key.id);
              keysRemoved++;
            }
          const { ownerIdentityId: _owner, ...rest } = device;
          const next = await tx.put<RegisteredDevice>(deviceCollections.devices, {
            ...rest,
            name: name ?? device.name,
            status,
            ...(owner !== undefined ? { ownerIdentityId: owner } : {}),
            updatedAt: now,
          });
          await audit(tx, principal, 'device:update', tenant.id, deviceResource(device.id), {
            deviceId: device.id,
            before: {
              name: device.name,
              status: device.status,
              ownerIdentityId: device.ownerIdentityId ?? null,
            },
            after: { name: next.name, status: next.status, ownerIdentityId: owner ?? null },
            keysRemoved,
          });
          return (await describe(tx, tenant.id, [next], now))[0]!;
        },
      );
    },

    /**
     * Retires a device for good: it stops proving anything, its keys and pending enrollment codes are deleted, and an
     * integration's later reports keep it retired. Requires iam:devices:manage on `iam/devices/{id}` and recent
     * authentication; audited as `device:retire`.
     */
    retire: async (
      credential: CredentialInput,
      input: { tenantId: string; deviceId: string },
    ): Promise<DeviceView> => {
      const deviceId = text(input.deviceId, 'deviceId');
      return operation(
        credential,
        input.tenantId,
        'iam:devices:manage',
        deviceResource(deviceId),
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const device = await ctx.scoped<RegisteredDevice>(
            tx,
            deviceCollections.devices,
            deviceId,
            tenant.id,
          );
          if (device.status === 'retired')
            throw new IamError('INVALID_TRANSITION', 'The device is already retired', 409);
          const now = ctx.now();
          const { device: retired, keysRemoved } = await retireDevice(tx, device, now);
          await audit(tx, principal, 'device:retire', tenant.id, deviceResource(device.id), {
            deviceId: device.id,
            keysRemoved,
            self: false,
          });
          return (await describe(tx, tenant.id, [retired], now))[0]!;
        },
      );
    },

    /**
     * Deletes a device with its keys and enrollment codes (a managed device reappears with the integration's next
     * report). Requires iam:devices:manage on `iam/devices/{id}` and recent authentication; audited as `device:delete`.
     */
    delete: async (
      credential: CredentialInput,
      input: { tenantId: string; deviceId: string },
    ): Promise<{ success: true; keysRemoved: number; enrollmentsRemoved: number }> => {
      const deviceId = text(input.deviceId, 'deviceId');
      return operation(
        credential,
        input.tenantId,
        'iam:devices:manage',
        deviceResource(deviceId),
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const device = await ctx.scoped<RegisteredDevice>(
            tx,
            deviceCollections.devices,
            deviceId,
            tenant.id,
          );
          const keys = await tx.find<DeviceKey>(deviceCollections.keys, {
            tenantId: tenant.id,
            deviceId: device.id,
          });
          for (const key of keys) await tx.delete(deviceCollections.keys, key.id);
          const enrollments = await tx.find<DeviceEnrollment>(deviceCollections.enrollments, {
            tenantId: tenant.id,
            deviceId: device.id,
          });
          for (const enrollment of enrollments)
            await tx.delete(deviceCollections.enrollments, enrollment.id);
          await tx.delete(deviceCollections.devices, device.id);
          await audit(tx, principal, 'device:delete', tenant.id, deviceResource(device.id), {
            deviceId: device.id,
            name: device.name,
            managed: device.source !== undefined,
            keysRemoved: keys.length,
            enrollmentsRemoved: enrollments.length,
          });
          return {
            success: true as const,
            keysRemoved: keys.length,
            enrollmentsRemoved: enrollments.length,
          };
        },
      );
    },

    /**
     * Removes one key from a device (a lost browser profile, a replaced agent). Requires iam:devices:manage on
     * `iam/devices/{id}` and recent authentication; audited as `device:key-remove`.
     */
    removeKey: async (
      credential: CredentialInput,
      input: { tenantId: string; deviceId: string; keyId: string },
    ): Promise<{ success: true }> => {
      const deviceId = text(input.deviceId, 'deviceId');
      const keyId = text(input.keyId, 'keyId');
      return operation(
        credential,
        input.tenantId,
        'iam:devices:manage',
        deviceResource(deviceId),
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const device = await ctx.scoped<RegisteredDevice>(
            tx,
            deviceCollections.devices,
            deviceId,
            tenant.id,
          );
          const key = await tx.get<DeviceKey>(deviceCollections.keys, keyId);
          if (!key || key.tenantId !== tenant.id || key.deviceId !== device.id)
            throw new IamError('NOT_FOUND', 'Resource not found', 404);
          await tx.delete(deviceCollections.keys, key.id);
          await audit(tx, principal, 'device:key-remove', tenant.id, deviceResource(device.id), {
            deviceId: device.id,
            keyId: key.id,
          });
          return { success: true as const };
        },
      );
    },

    /**
     * Creates a one-time enrollment code (`biam_denr_…`, shown only in this answer) valid for `expiresInMs` (10 minutes
     * to 30 days, default 7 days). With `deviceId` the code binds a key to that device (typically a managed one, so
     * the browsers on it can prove it); without it, enrolment creates a new device. `ownerIdentityId` limits the code
     * to that person (a device with an owner implies it). Requires iam:devices:manage on `iam/devices/enrollments`
     * (and, with `deviceId`, on `iam/devices/{id}`) and recent authentication; audited as `device:enrollment-create`.
     */
    createEnrollment: async (
      credential: CredentialInput,
      input: { tenantId: string; deviceId?: string; ownerIdentityId?: string; expiresInMs?: number },
    ): Promise<DeviceEnrollmentCode> => {
      const deviceId = input.deviceId === undefined ? undefined : text(input.deviceId, 'deviceId');
      const lifetime = integer(
        input.expiresInMs ?? DEFAULT_ENROLLMENT_MS,
        'expiresInMs',
        MIN_ENROLLMENT_MS,
        MAX_ENROLLMENT_MS,
      );
      return operation(
        credential,
        input.tenantId,
        'iam:devices:manage',
        'devices/enrollments',
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const now = ctx.now();
          let owner =
            input.ownerIdentityId === undefined
              ? undefined
              : (await ownerOf(tx, tenant.id, input.ownerIdentityId)).id;
          if (deviceId !== undefined) {
            const device = await ctx.scoped<RegisteredDevice>(
              tx,
              deviceCollections.devices,
              deviceId,
              tenant.id,
            );
            // Using the code adds a key to the device (and may give a shared one an owner), which devices.update and
            // removeKey allow only with iam:devices:manage on the device itself.
            const onDevice = await ctx.decisions.decide(
              tx,
              principal,
              {
                tenantId: tenant.id,
                action: 'iam:devices:manage',
                resource: { type: 'iam', id: deviceResource(device.id) },
              },
              true,
            );
            if (!onDevice.allowed)
              throw new OperationDenied(
                'A code for an existing device requires iam:devices:manage on that device',
              );
            if (device.status !== 'active')
              throw new IamError('INVALID_TRANSITION', 'The device is not active', 409);
            if (device.ownerIdentityId !== undefined) {
              if (owner !== undefined && owner !== device.ownerIdentityId)
                throw new IamError('INVALID_INPUT', 'The device belongs to someone else');
              owner = device.ownerIdentityId;
            }
          }
          const pending = (
            await tx.find<DeviceEnrollment>(deviceCollections.enrollments, { tenantId: tenant.id })
          ).filter((enrollment) => enrollment.usedAt === undefined && enrollment.expiresAt > now);
          if (pending.length >= maxPendingEnrollments)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant can hold at most ${maxPendingEnrollments} pending enrollment codes`,
              409,
            );
          const code = `biam_denr_${token()}`;
          const codeHash = hash(code);
          const enrollment = await tx.insert<DeviceEnrollment>(deviceCollections.enrollments, {
            id: id(),
            tenantId: tenant.id,
            uniqueKey: codeHash,
            codeHash,
            ...(deviceId !== undefined ? { deviceId } : {}),
            ...(owner !== undefined ? { ownerIdentityId: owner } : {}),
            expiresAt: now + lifetime,
            createdAt: now,
            createdBy: principal.identity.id,
          });
          await audit(tx, principal, 'device:enrollment-create', tenant.id, 'devices/enrollments', {
            enrollmentId: enrollment.id,
            deviceId: deviceId ?? null,
            ownerIdentityId: owner ?? null,
            expiresAt: enrollment.expiresAt,
          });
          return { code, expiresAt: enrollment.expiresAt, enrollmentId: enrollment.id };
        },
      );
    },

    /** The tenant's enrollment codes (without the codes), newest first. Requires iam:devices:manage. */
    listEnrollments: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<DeviceEnrollmentView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:devices:manage',
        'devices/enrollments',
        async ({ tx, tenant }) => {
          const now = ctx.now();
          return (
            await tx.find<DeviceEnrollment>(deviceCollections.enrollments, { tenantId: tenant.id })
          )
            .sort(byNewest)
            .map((enrollment) => enrollmentView(enrollment, now));
        },
      ),

    /** Withdraws an enrollment code. Requires iam:devices:manage; audited as `device:enrollment-revoke`. */
    revokeEnrollment: async (
      credential: CredentialInput,
      input: { tenantId: string; enrollmentId: string },
    ): Promise<{ success: true }> => {
      const enrollmentId = text(input.enrollmentId, 'enrollmentId');
      return operation(
        credential,
        input.tenantId,
        'iam:devices:manage',
        'devices/enrollments',
        async ({ tx, tenant, principal }) => {
          const enrollment = await ctx.scoped<DeviceEnrollment>(
            tx,
            deviceCollections.enrollments,
            enrollmentId,
            tenant.id,
          );
          await tx.delete(deviceCollections.enrollments, enrollment.id);
          await audit(tx, principal, 'device:enrollment-revoke', tenant.id, 'devices/enrollments', {
            enrollmentId: enrollment.id,
            deviceId: enrollment.deviceId ?? null,
            used: enrollment.usedAt !== undefined,
          });
          return { success: true as const };
        },
      );
    },

    /** The tenant's compliance requirements (defaults until configured). Requires iam:devices:read on `iam/devices/settings`. */
    getSettings: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<DeviceSettingsView> =>
      operation(
        credential,
        input.tenantId,
        'iam:devices:read',
        'devices/settings',
        async ({ tx, tenant }) => {
          const stored = await tx.get<DeviceSettings>(deviceCollections.settings, tenant.id);
          return settingsView(tenant.id, stored?.tenantId === tenant.id ? stored : undefined);
        },
      ),

    /**
     * Sets the compliance requirements managed devices must meet; fields left out keep their value, and
     * `minOsVersions` (platform to dotted version) replaces the whole map. `maxCheckInAgeHours` is 1 to 720. Requires
     * iam:devices:manage on `iam/devices/settings` and recent authentication; audited as `device:settings`.
     */
    configure: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        requireEncrypted?: boolean;
        requireScreenLock?: boolean;
        requireFirewall?: boolean;
        requireEdr?: boolean;
        blockJailbroken?: boolean;
        minOsVersions?: Partial<Record<DevicePlatform, string>>;
        maxCheckInAgeHours?: number;
      },
    ): Promise<DeviceSettingsView> => {
      const fields = fieldsOf(input, [
        'tenantId',
        'requireEncrypted',
        'requireScreenLock',
        'requireFirewall',
        'requireEdr',
        'blockJailbroken',
        'minOsVersions',
        'maxCheckInAgeHours',
      ]);
      const changes: Partial<ResolvedDeviceSettings> = {};
      for (const name of [
        'requireEncrypted',
        'requireScreenLock',
        'requireFirewall',
        'requireEdr',
        'blockJailbroken',
      ] as const)
        if (fields[name] !== undefined) changes[name] = flag(fields[name], name);
      if (fields.minOsVersions !== undefined) {
        const minimums: Partial<Record<DevicePlatform, string>> = {};
        for (const [platform, version] of Object.entries(object(fields.minOsVersions))) {
          const key = platformOf(platform, 'minOsVersions platform');
          if (!isOsVersion(version))
            throw new IamError(
              'INVALID_INPUT',
              `minOsVersions.${key} must be a dotted version such as 14.5`,
            );
          minimums[key] = version;
        }
        changes.minOsVersions = minimums;
      }
      if (fields.maxCheckInAgeHours !== undefined)
        changes.maxCheckInAgeHours = integer(fields.maxCheckInAgeHours, 'maxCheckInAgeHours', 1, 720);
      return operation(
        credential,
        input.tenantId,
        'iam:devices:manage',
        'devices/settings',
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const stored = await tx.get<DeviceSettings>(deviceCollections.settings, tenant.id);
          const previous = stored?.tenantId === tenant.id ? stored : undefined;
          const before = resolveDeviceSettings(previous);
          const record: DeviceSettings = {
            id: tenant.id,
            tenantId: tenant.id,
            ...before,
            ...changes,
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          };
          const saved = previous
            ? await tx.put<DeviceSettings>(deviceCollections.settings, record)
            : await tx.insert<DeviceSettings>(deviceCollections.settings, record);
          await audit(tx, principal, 'device:settings', tenant.id, 'devices/settings', {
            before: settingsMetadata(before),
            after: settingsMetadata(resolveDeviceSettings(saved)),
          });
          return settingsView(tenant.id, saved);
        },
      );
    },

    /** The tenant's device integrations with the number of devices each manages. Requires iam:devices:read. */
    listIntegrations: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<DeviceIntegrationView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:devices:read',
        'devices/integrations',
        async ({ tx, tenant }) => {
          const counts = new Map<string, number>();
          for (const device of await tx.find<RegisteredDevice>(deviceCollections.devices, {
            tenantId: tenant.id,
          }))
            if (device.source)
              counts.set(device.source.integrationId, (counts.get(device.source.integrationId) ?? 0) + 1);
          return (
            await tx.find<DeviceIntegration>(deviceCollections.integrations, { tenantId: tenant.id })
          )
            .sort((a, b) => a.name.localeCompare(b.name))
            .map((integration) => integrationView(integration, counts.get(integration.id) ?? 0));
        },
      ),

    /**
     * Adds an MDM or EDR integration (at most 20 per tenant, names unique). Its reporter needs `iam:devices:report` on
     * `iam/devices/integrations/{id}`. `trustVendorCompliance` (default true) accepts the vendor's own verdict next to the
     * tenant's requirements. Requires iam:devices:manage and recent authentication; audited as
     * `device:integration-create`.
     */
    createIntegration: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        name: string;
        vendor: DeviceIntegrationVendor;
        trustVendorCompliance?: boolean;
      },
    ): Promise<DeviceIntegrationView> => {
      fieldsOf(input, ['tenantId', 'name', 'vendor', 'trustVendorCompliance']);
      const name = text(input.name, 'name', 100).trim();
      if (typeof input.vendor !== 'string' || !vendors.has(input.vendor))
        throw new IamError(
          'INVALID_INPUT',
          `vendor must be one of ${deviceIntegrationVendors.join(', ')}`,
        );
      const trust =
        input.trustVendorCompliance === undefined
          ? true
          : flag(input.trustVendorCompliance, 'trustVendorCompliance');
      return operation(
        credential,
        input.tenantId,
        'iam:devices:manage',
        'devices/integrations',
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const existing = await tx.find<DeviceIntegration>(deviceCollections.integrations, {
            tenantId: tenant.id,
          });
          const uniqueKey = `name:${name.toLowerCase()}`;
          if (existing.some((integration) => integration.uniqueKey === uniqueKey))
            throw new IamError('CONFLICT', 'An integration with this name exists', 409);
          if (existing.length >= maxDeviceIntegrations)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant can have at most ${maxDeviceIntegrations} device integrations`,
              409,
            );
          const now = ctx.now();
          const integration = await tx.insert<DeviceIntegration>(deviceCollections.integrations, {
            id: id(),
            tenantId: tenant.id,
            uniqueKey,
            name,
            vendor: input.vendor,
            status: 'active',
            trustVendorCompliance: trust,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
          });
          await audit(
            tx,
            principal,
            'device:integration-create',
            tenant.id,
            integrationResource(integration.id),
            { integrationId: integration.id, ...integrationMetadata(integration) },
          );
          return integrationView(integration, 0);
        },
      );
    },

    /**
     * Renames an integration, disables it (its devices stop counting as managed) or enables it, or changes whether its
     * vendor verdict counts. Requires iam:devices:manage on `iam/devices/integrations/{id}` and recent authentication;
     * audited as `device:integration-update`.
     */
    updateIntegration: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        integrationId: string;
        name?: string;
        status?: 'active' | 'disabled';
        trustVendorCompliance?: boolean;
      },
    ): Promise<DeviceIntegrationView> => {
      fieldsOf(input, ['tenantId', 'integrationId', 'name', 'status', 'trustVendorCompliance']);
      const integrationId = text(input.integrationId, 'integrationId');
      const name = input.name === undefined ? undefined : text(input.name, 'name', 100).trim();
      if (input.status !== undefined && input.status !== 'active' && input.status !== 'disabled')
        throw new IamError('INVALID_INPUT', 'status must be active or disabled');
      const trust =
        input.trustVendorCompliance === undefined
          ? undefined
          : flag(input.trustVendorCompliance, 'trustVendorCompliance');
      return operation(
        credential,
        input.tenantId,
        'iam:devices:manage',
        integrationResource(integrationId),
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const integration = await ctx.scoped<DeviceIntegration>(
            tx,
            deviceCollections.integrations,
            integrationId,
            tenant.id,
          );
          const uniqueKey = name === undefined ? integration.uniqueKey : `name:${name.toLowerCase()}`;
          if (
            name !== undefined &&
            (
              await tx.find<DeviceIntegration>(deviceCollections.integrations, {
                tenantId: tenant.id,
                uniqueKey,
              })
            ).some((other) => other.id !== integration.id)
          )
            throw new IamError('CONFLICT', 'An integration with this name exists', 409);
          const next = await tx.put<DeviceIntegration>(deviceCollections.integrations, {
            ...integration,
            ...(uniqueKey !== undefined ? { uniqueKey } : {}),
            name: name ?? integration.name,
            status: input.status ?? integration.status,
            trustVendorCompliance: trust ?? integration.trustVendorCompliance,
            updatedAt: ctx.now(),
          });
          await audit(
            tx,
            principal,
            'device:integration-update',
            tenant.id,
            integrationResource(integration.id),
            {
              integrationId: integration.id,
              before: integrationMetadata(integration),
              after: integrationMetadata(next),
            },
          );
          const managed = (
            await tx.find<RegisteredDevice>(deviceCollections.devices, { tenantId: tenant.id })
          ).filter((device) => device.source?.integrationId === integration.id).length;
          return integrationView(next, managed);
        },
      );
    },

    /**
     * Deletes an integration. While it manages devices the call is refused (RESOURCE_IN_USE) unless `detach` is true:
     * its devices then become unmanaged (they keep their keys and last posture, but no longer count as managed).
     * Requires iam:devices:manage on `iam/devices/integrations/{id}` and recent authentication; audited as
     * `device:integration-delete`.
     */
    deleteIntegration: async (
      credential: CredentialInput,
      input: { tenantId: string; integrationId: string; detach?: boolean },
    ): Promise<{ success: true; detached: number }> => {
      const integrationId = text(input.integrationId, 'integrationId');
      const detach = input.detach === undefined ? false : flag(input.detach, 'detach');
      return operation(
        credential,
        input.tenantId,
        'iam:devices:manage',
        integrationResource(integrationId),
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const integration = await ctx.scoped<DeviceIntegration>(
            tx,
            deviceCollections.integrations,
            integrationId,
            tenant.id,
          );
          const managed = (
            await tx.find<RegisteredDevice>(deviceCollections.devices, { tenantId: tenant.id })
          ).filter((device) => device.source?.integrationId === integration.id);
          if (managed.length && !detach)
            throw new IamError(
              'RESOURCE_IN_USE',
              `The integration manages ${managed.length} devices; pass detach to make them unmanaged`,
              409,
            );
          const now = ctx.now();
          for (const device of managed) {
            const { source: _source, uniqueKey: _key, ...rest } = device;
            await tx.put<RegisteredDevice>(deviceCollections.devices, { ...rest, updatedAt: now });
          }
          await tx.delete(deviceCollections.integrations, integration.id);
          await audit(
            tx,
            principal,
            'device:integration-delete',
            tenant.id,
            integrationResource(integration.id),
            { integrationId: integration.id, name: integration.name, detached: managed.length },
          );
          return { success: true as const, detached: managed.length };
        },
      );
    },

    // ---------------------------------------------------------------------------------------------------------
    // Integration reports

    /**
     * An integration reports up to 500 devices with their posture, all or nothing. Devices are matched by the
     * integration's `externalId` and created on first sight; a report that names an owner (identity id or email of a
     * person of the tenant) sets it, and an unknown one clears it. `keyThumbprint` moves a key the integration's agent
     * enrolled onto the reported device (retiring the same person's self-enrolled record of it when that record is left
     * without keys), but only from an active device of the reported owner that is unmanaged or this integration's;
     * other keys stay where they are. Repeated check-ins within a minute that change nothing (not even compliance, as a
     * stale check-in turning fresh would) are not written, and reports older than the
     * device's last check-in are ignored. Retired devices stay retired. The integration must be active. Requires
     * iam:devices:report on `iam/devices/integrations/{id}` (no recent authentication: meant for a service account's
     * API key); audited once per call as `device:report`, plus `device:compliance-change` for each existing device
     * whose compliance flipped.
     */
    report: async (
      credential: CredentialInput,
      input: { tenantId: string; integrationId: string; devices: DeviceReport[] },
    ): Promise<DeviceReportResult> => {
      const integrationId = text(input.integrationId, 'integrationId');
      const items = reportItems(input.devices, ctx.now());
      return operation(
        credential,
        input.tenantId,
        'iam:devices:report',
        integrationResource(integrationId),
        async ({ tx, tenant, principal }) => {
          const integration = await ctx.scoped<DeviceIntegration>(
            tx,
            deviceCollections.integrations,
            integrationId,
            tenant.id,
          );
          if (integration.status !== 'active')
            throw new IamError('INVALID_TRANSITION', 'The integration is disabled', 409);
          const settings = await deviceSettingsOf(tx, tenant.id);
          const now = ctx.now();
          const owners = new Map<string, string | undefined>();
          const resolveOwner = async (item: ReportItem): Promise<string | undefined> => {
            if (item.ownerIdentityId !== undefined) {
              const key = `id:${item.ownerIdentityId}`;
              if (!owners.has(key)) {
                const identity = await tx.get<Identity>('identities', item.ownerIdentityId);
                owners.set(key, person(identity, tenant.id) ? identity.id : undefined);
              }
              const found = owners.get(key);
              if (found !== undefined) return found;
            }
            if (item.ownerEmail === undefined) return undefined;
            const key = `email:${item.ownerEmail}`;
            if (!owners.has(key))
              owners.set(
                key,
                (
                  await tx.find<Identity>('identities', {
                    tenantId: tenant.id,
                    email: item.ownerEmail,
                  })
                ).find((identity) => person(identity, tenant.id))?.id,
              );
            return owners.get(key);
          };
          const result: DeviceReportResult = {
            created: 0,
            updated: 0,
            unchanged: 0,
            complianceChanged: 0,
          };
          for (const item of items) {
            const uniqueKey = `src:${integration.id}:${item.externalId}`;
            const existing = (
              await tx.find<RegisteredDevice>(deviceCollections.devices, {
                tenantId: tenant.id,
                uniqueKey,
              })
            )[0];
            if (existing?.lastCheckInAt !== undefined && item.checkedInAt < existing.lastCheckInAt) {
              result.unchanged++;
              continue;
            }
            const owner = item.ownerNamed ? await resolveOwner(item) : existing?.ownerIdentityId;
            const posture: DevicePosture = {
              ...item.posture,
              ...(item.osVersion !== undefined ? { osVersion: item.osVersion } : {}),
              reportedAt: item.checkedInAt,
              integrationId: integration.id,
            };
            const serialNumber = item.serialNumber ?? existing?.serialNumber;
            const model = item.model ?? existing?.model;
            const name = (
              item.name ??
              existing?.name ??
              item.model ??
              item.serialNumber ??
              item.externalId
            ).slice(0, 128);
            const described = {
              name,
              platform: item.platform,
              ...(owner !== undefined ? { ownerIdentityId: owner } : {}),
              ...(serialNumber !== undefined ? { serialNumber } : {}),
              ...(model !== undefined ? { model } : {}),
              posture,
              lastCheckInAt: item.checkedInAt,
            };
            if (!existing) {
              const device = await tx.insert<RegisteredDevice>(deviceCollections.devices, {
                id: id(),
                tenantId: tenant.id,
                uniqueKey,
                ...described,
                status: 'active',
                source: { integrationId: integration.id, externalId: item.externalId },
                createdAt: now,
                updatedAt: now,
              });
              if (item.keyThumbprint !== undefined)
                await claimKey(tx, item.keyThumbprint, device, now);
              result.created++;
              continue;
            }
            const {
              ownerIdentityId: _owner,
              serialNumber: _serial,
              model: _model,
              ...kept
            } = existing;
            const next: RegisteredDevice = { ...kept, ...described, updatedAt: now };
            const changed = reportedState(existing) !== reportedState(next);
            const moved =
              item.keyThumbprint !== undefined
                ? await claimKey(tx, item.keyThumbprint, next, now)
                : false;
            const before = evaluateCompliance(existing, integration, settings, now);
            const after = evaluateCompliance(next, integration, settings, now);
            const flipped = before.compliant !== after.compliant;
            // A check-in that flips compliance (the stored one had just gone stale) is written however soon it comes,
            // so the verdict audited below is the one decisions see.
            const due =
              flipped ||
              existing.lastCheckInAt === undefined ||
              item.checkedInAt - existing.lastCheckInAt >= TOUCH_MS;
            if (changed || moved) {
              await tx.put<RegisteredDevice>(deviceCollections.devices, next);
              result.updated++;
            } else {
              if (due)
                await tx.put<RegisteredDevice>(deviceCollections.devices, {
                  ...existing,
                  lastCheckInAt: item.checkedInAt,
                  posture: { ...posture },
                });
              result.unchanged++;
            }
            if (flipped) {
              result.complianceChanged++;
              await audit(
                tx,
                principal,
                'device:compliance-change',
                tenant.id,
                deviceResource(existing.id),
                {
                  deviceId: existing.id,
                  integrationId: integration.id,
                  from: before.compliant,
                  to: after.compliant,
                  reasons: after.reasons,
                },
              );
            }
          }
          await tx.put<DeviceIntegration>(deviceCollections.integrations, {
            ...integration,
            lastReportAt: now,
          });
          await audit(
            tx,
            principal,
            'device:report',
            tenant.id,
            integrationResource(integration.id),
            {
              integrationId: integration.id,
              received: items.length,
              created: result.created,
              updated: result.updated,
              unchanged: result.unchanged,
              complianceChanged: result.complianceChanged,
            },
          );
          return result;
        },
      );
    },
  };
}
