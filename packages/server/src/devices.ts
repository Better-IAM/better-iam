import { compactVerify, decodeProtectedHeader, importJWK } from 'jose';
import type {
  AuthenticatedPrincipal,
  IamStore,
  Identity,
  PolicyDocument,
  StoredRecord,
} from '@better-iam/core';

/**
 * Device posture: registered devices, the keys that prove a request comes from one, and the compliance of the devices
 * an MDM or EDR integration manages. A browser or agent enrols a public key (`devices.enroll`); every request can then
 * carry a short-lived signed proof (`x-better-iam-device`) bound to the presenting session. Decisions verify that proof
 * against the stored key only (never a key the proof carries) and expose the device's assurance to policies as
 * `request.deviceAssurance`, `request.deviceManaged`, `request.deviceCompliant`, `request.deviceId` and
 * `request.devicePlatform`, read only when a document names them.
 *
 * Not to be confused with remembered browsers (`authDevices`, `TrustedDevice`), which skip a second factor: a
 * registered device never satisfies MFA and remembered browsers never count as registered devices.
 */

export const deviceCollections = {
  /** `RegisteredDevice`: one row per device, in the owner's (home) tenant. */
  devices: 'registeredDevices',
  /** `DeviceKey`: the id is the key's RFC 7638 thumbprint, unique across tenants; rows carry their tenant. */
  keys: 'deviceKeys',
  /** `DeviceEnrollment`: one-time codes that bind a key to a (usually managed) device; stored hashed. */
  enrollments: 'deviceEnrollments',
  /** `DeviceIntegration`: the MDM/EDR systems that report posture. */
  integrations: 'deviceIntegrations',
  /** `DeviceSettings`: the tenant's compliance requirements; the id is the tenant id. */
  settings: 'deviceSettings',
} as const;

/** The request header that carries a device proof (a compact JWS). */
export const deviceProofHeader = 'x-better-iam-device';
/** The `typ` every device proof's protected header must carry, exactly. */
export const deviceProofType = 'device-proof+jwt';
/** Proofs longer than this are ignored (never an error). */
export const maxDeviceProofLength = 2048;
/** How far a proof's `iat` may lie from the server clock, either way. */
export const deviceProofSkewSeconds = 300;
/** Devices one person may own (not counting retired ones), for self-enrolment. */
export const maxDevicesPerPerson = 20;
/** Keys one device may hold (one per browser profile or agent). */
export const maxKeysPerDevice = 20;
/** Device integrations per tenant. */
export const maxDeviceIntegrations = 20;

export type DevicePlatform = 'windows' | 'macos' | 'linux' | 'ios' | 'android' | 'chromeos' | 'other';
export type DeviceStatus = 'active' | 'lost' | 'retired';
/**
 * What a request's device proves, weakest first: `none` (no valid proof), `registered` (a proof from an active
 * registered device), `managed` (an active integration manages that device) and `compliant` (it also meets the tenant's
 * requirements).
 */
export type DeviceAssurance = 'none' | 'registered' | 'managed' | 'compliant';
export type DeviceIntegrationVendor =
  | 'intune'
  | 'jamf'
  | 'kandji'
  | 'workspace-one'
  | 'google-endpoint'
  | 'crowdstrike'
  | 'sentinelone'
  | 'custom';

export const devicePlatforms: readonly DevicePlatform[] = [
  'windows',
  'macos',
  'linux',
  'ios',
  'android',
  'chromeos',
  'other',
];
export const deviceIntegrationVendors: readonly DeviceIntegrationVendor[] = [
  'intune',
  'jamf',
  'kandji',
  'workspace-one',
  'google-endpoint',
  'crowdstrike',
  'sentinelone',
  'custom',
];

/** The last posture report from the integration that manages a device. Absent booleans are unknown. */
export interface DevicePosture {
  /** The vendor's own verdict; counts only while the integration has `trustVendorCompliance`. */
  compliant?: boolean;
  encrypted?: boolean;
  firewall?: boolean;
  screenLock?: boolean;
  edrHealthy?: boolean;
  jailbroken?: boolean;
  /** Dotted numeric version (`14.5.1`), at most 32 characters. */
  osVersion?: string;
  /** When the device checked in with the integration (epoch milliseconds). */
  reportedAt: number;
  integrationId: string;
}

/** A registered device: self-enrolled (unmanaged) or reported by an integration (managed). */
export interface RegisteredDevice extends StoredRecord {
  name: string;
  platform: DevicePlatform;
  status: DeviceStatus;
  /** The person the device belongs to; unset means a shared device any member of the tenant may present. */
  ownerIdentityId?: string;
  /** Set when an integration manages the device; the uniqueKey is then `src:{integrationId}:{externalId}`. */
  source?: { integrationId: string; externalId: string };
  serialNumber?: string;
  model?: string;
  posture?: DevicePosture;
  /** The last integration check-in (written at most once a minute unless the posture changed). */
  lastCheckInAt?: number;
  /** The last verified proof seen by `devices.check` (written at most once a minute). */
  lastSeenAt?: number;
  /** The identity that last bound a key to the device (self-enrolment). */
  enrolledBy?: string;
  createdAt: number;
  updatedAt: number;
}

/** A device's public key as stored: EC P-256 (ES256) or Ed25519 (EdDSA), public members only. */
export type DevicePublicJwk =
  | { kty: 'EC'; crv: 'P-256'; x: string; y: string }
  | { kty: 'OKP'; crv: 'Ed25519'; x: string };

/** A key that proves requests come from a device. The id is the key's RFC 7638 thumbprint (base64url SHA-256). */
export interface DeviceKey extends StoredRecord {
  deviceId: string;
  jwk: DevicePublicJwk;
  createdAt: number;
  createdBy: string;
  /** The last verified proof seen by `devices.check` (written at most once a minute). */
  lastUsedAt?: number;
}

/** A one-time code for binding a key to a device; only its hash is stored (uniqueKey = codeHash). */
export interface DeviceEnrollment extends StoredRecord {
  codeHash: string;
  /** Bind the key to this existing (usually managed) device; unset creates a new device on enrolment. */
  deviceId?: string;
  /** Only this person may use the code; unset lets any person of the tenant use it (a shared device). */
  ownerIdentityId?: string;
  expiresAt: number;
  createdAt: number;
  createdBy: string;
  usedAt?: number;
  usedBy?: string;
}

/** An MDM or EDR system that reports devices and their posture (`devices.report`, with `iam:devices:report`). */
export interface DeviceIntegration extends StoredRecord {
  name: string;
  vendor: DeviceIntegrationVendor;
  status: 'active' | 'disabled';
  /** Accept the vendor's `compliant` verdict (still combined with the tenant's own requirements). Default true. */
  trustVendorCompliance: boolean;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  lastReportAt?: number;
}

/** The tenant's compliance requirements for managed devices; the id is the tenant id. */
export interface DeviceSettings extends StoredRecord {
  requireEncrypted: boolean;
  requireScreenLock: boolean;
  requireFirewall: boolean;
  requireEdr: boolean;
  /** Default true. */
  blockJailbroken: boolean;
  minOsVersions: Partial<Record<DevicePlatform, string>>;
  /** 1 to 720 (default 24): a device that has not checked in for longer is not compliant. */
  maxCheckInAgeHours: number;
  updatedAt: number;
  updatedBy: string;
}

/** The requirements that apply to a tenant: its settings, or the defaults where it has none. */
export interface ResolvedDeviceSettings {
  requireEncrypted: boolean;
  requireScreenLock: boolean;
  requireFirewall: boolean;
  requireEdr: boolean;
  blockJailbroken: boolean;
  minOsVersions: Partial<Record<DevicePlatform, string>>;
  maxCheckInAgeHours: number;
}

/** Why a device is not compliant. */
export type ComplianceReason =
  | 'not-managed'
  | 'integration-disabled'
  | 'stale'
  | 'vendor-noncompliant'
  | 'not-encrypted'
  | 'no-screen-lock'
  | 'no-firewall'
  | 'edr-unhealthy'
  | 'jailbroken'
  | 'os-too-old'
  | 'os-unknown'
  | 'lost'
  | 'retired';

export interface ComplianceResult {
  compliant: boolean;
  managed: boolean;
  /** Empty exactly when the device is compliant. */
  reasons: ComplianceReason[];
}

export const defaultDeviceSettings: Readonly<ResolvedDeviceSettings> = Object.freeze({
  requireEncrypted: false,
  requireScreenLock: false,
  requireFirewall: false,
  requireEdr: false,
  blockJailbroken: true,
  minOsVersions: Object.freeze({}),
  maxCheckInAgeHours: 24,
});

/** A dotted numeric version: 1 to 8 parts of at most 9 digits. */
const dottedVersion = /^\d{1,9}(?:\.\d{1,9}){0,7}$/;
/** A compact JWS: three base64url segments. */
const compactJws = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
/** An RFC 7638 SHA-256 thumbprint in base64url. */
export const deviceKeyIdPattern = /^[A-Za-z0-9_-]{43}$/;
/** The only protected header members a device proof may carry; `jwk`, `jku`, `x5u`, `x5c`, `crit` and all others are refused. */
const proofHeaderMembers: ReadonlySet<string> = new Set(['alg', 'typ', 'kid']);
const decoder = new TextDecoder();

/** Whether a value is a dotted numeric version of at most 32 characters. */
export function isOsVersion(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 32 && dottedVersion.test(value);
}

/** Compares two dotted numeric versions part by part (missing parts count as 0): negative, 0 or positive. */
export function compareOsVersions(left: string, right: string): number {
  const a = left.split('.').map(Number);
  const b = right.split('.').map(Number);
  for (let index = 0; index < Math.max(a.length, b.length); index++) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference < 0 ? -1 : 1;
  }
  return 0;
}

/** The requirements for a tenant: the stored settings over the defaults (stored values were validated on write). */
export function resolveDeviceSettings(stored: DeviceSettings | undefined): ResolvedDeviceSettings {
  const flag = (value: unknown, fallback: boolean) =>
    typeof value === 'boolean' ? value : fallback;
  const minimums: Partial<Record<DevicePlatform, string>> = {};
  if (stored?.minOsVersions && typeof stored.minOsVersions === 'object')
    for (const platform of devicePlatforms) {
      const minimum = stored.minOsVersions[platform];
      if (isOsVersion(minimum)) minimums[platform] = minimum;
    }
  const hours = stored?.maxCheckInAgeHours;
  return {
    requireEncrypted: flag(stored?.requireEncrypted, defaultDeviceSettings.requireEncrypted),
    requireScreenLock: flag(stored?.requireScreenLock, defaultDeviceSettings.requireScreenLock),
    requireFirewall: flag(stored?.requireFirewall, defaultDeviceSettings.requireFirewall),
    requireEdr: flag(stored?.requireEdr, defaultDeviceSettings.requireEdr),
    blockJailbroken: flag(stored?.blockJailbroken, defaultDeviceSettings.blockJailbroken),
    minOsVersions: minimums,
    maxCheckInAgeHours:
      typeof hours === 'number' && Number.isSafeInteger(hours) && hours >= 1 && hours <= 720
        ? hours
        : defaultDeviceSettings.maxCheckInAgeHours,
  };
}

/** The tenant's resolved requirements, read from storage. */
export async function deviceSettingsOf(
  tx: IamStore,
  tenantId: string,
): Promise<ResolvedDeviceSettings> {
  const stored = await tx.get<DeviceSettings>(deviceCollections.settings, tenantId);
  return resolveDeviceSettings(stored?.tenantId === tenantId ? stored : undefined);
}

/**
 * Judges a device against the tenant's requirements. Only an active device an active integration manages can be
 * compliant: its last check-in must be recent, the vendor's verdict (when trusted) must not be `false`, every required
 * posture field must be reported `true` (unknown fails), a jailbroken device fails while `blockJailbroken` is on, and a
 * minimum OS version for the platform needs a reported version at least that high.
 */
export function evaluateCompliance(
  device: RegisteredDevice,
  integration: DeviceIntegration | undefined,
  settings: ResolvedDeviceSettings,
  now: number,
): ComplianceResult {
  const reasons: ComplianceReason[] = [];
  if (device.status === 'lost') reasons.push('lost');
  else if (device.status !== 'active') reasons.push('retired');
  const linked =
    device.source !== undefined &&
    integration !== undefined &&
    integration.id === device.source.integrationId &&
    integration.tenantId === device.tenantId;
  const managed = linked && integration.status === 'active';
  if (!linked) reasons.push('not-managed');
  else if (!managed) reasons.push('integration-disabled');
  if (!managed) return { compliant: false, managed, reasons };
  // Posture reported under another integration (before the device moved) says nothing about this one.
  const posture = device.posture?.integrationId === integration.id ? device.posture : undefined;
  if (!posture) return { compliant: false, managed, reasons: [...reasons, 'stale'] };
  const checkedAt = device.lastCheckInAt ?? posture.reportedAt;
  if (!(now - checkedAt <= settings.maxCheckInAgeHours * 3_600_000)) reasons.push('stale');
  if (integration.trustVendorCompliance && posture.compliant === false)
    reasons.push('vendor-noncompliant');
  if (settings.requireEncrypted && posture.encrypted !== true) reasons.push('not-encrypted');
  if (settings.requireScreenLock && posture.screenLock !== true) reasons.push('no-screen-lock');
  if (settings.requireFirewall && posture.firewall !== true) reasons.push('no-firewall');
  if (settings.requireEdr && posture.edrHealthy !== true) reasons.push('edr-unhealthy');
  if (settings.blockJailbroken && posture.jailbroken === true) reasons.push('jailbroken');
  const minimum = settings.minOsVersions[device.platform];
  if (minimum !== undefined) {
    if (!isOsVersion(posture.osVersion)) reasons.push('os-unknown');
    else if (compareOsVersions(posture.osVersion, minimum) < 0) reasons.push('os-too-old');
  }
  return { compliant: reasons.length === 0, managed, reasons };
}

/** The assurance a request gets from a device: `none` unless `registered` (a verified, active device). */
export function assuranceOf(result: ComplianceResult, registered: boolean): DeviceAssurance {
  if (!registered) return 'none';
  return result.compliant ? 'compliant' : result.managed ? 'managed' : 'registered';
}

/** A device's compliance, reading its integration and the tenant's settings. */
export async function complianceOf(
  tx: IamStore,
  device: RegisteredDevice,
  now: number,
): Promise<ComplianceResult> {
  const integration = device.source
    ? await tx.get<DeviceIntegration>(deviceCollections.integrations, device.source.integrationId)
    : undefined;
  return evaluateCompliance(device, integration, await deviceSettingsOf(tx, device.tenantId), now);
}

/** The JWS algorithm a stored key admits: ES256 for EC P-256, EdDSA for Ed25519, nothing else. */
export function deviceKeyAlgorithm(jwk: DevicePublicJwk): 'ES256' | 'EdDSA' | undefined {
  if (jwk?.kty === 'EC' && jwk.crv === 'P-256') return 'ES256';
  if (jwk?.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
  return undefined;
}

/**
 * The device proof a credential's headers carry (`x-better-iam-device`), or undefined when there is none or it is not
 * shaped like a compact JWS of at most 2048 characters. Headers normalize as for the bearer credential (a `Headers`
 * object, an array of pairs or a record); headers that cannot be read carry no proof.
 */
export function deviceProofOf(headers: HeadersInit | undefined): string | undefined {
  if (!headers) return undefined;
  let value: string | null;
  try {
    value = new Headers(headers).get(deviceProofHeader);
  } catch {
    return undefined;
  }
  return value && value.length <= maxDeviceProofLength && compactJws.test(value)
    ? value
    : undefined;
}

const plain = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** A device a proof verified for, with the key that signed it. */
export interface VerifiedDevice {
  device: RegisteredDevice;
  key: DeviceKey;
}

/** The session (and its tenant) a device proof must be bound to. */
interface ProofBinding {
  sessionId: string;
  tenantId: string;
}

/** Principals whose proof is bound to another session (the request's): those `withRequestDevice` makes. */
const proofBindings = new WeakMap<AuthenticatedPrincipal, ProofBinding>();
/** Device keys pinned on principals a background job decides for (`withDeviceKey`). */
const pinnedKeys = new WeakMap<AuthenticatedPrincipal, string>();

const bindingOf = (principal: AuthenticatedPrincipal): ProofBinding =>
  proofBindings.get(principal) ?? {
    sessionId: principal.session.id,
    tenantId: principal.session.tenantId,
  };

/**
 * Another principal a request is decided for besides its own (the source identity of a role session, whose right to
 * the role is decided again on every use; the administrator behind a "view as" session), carrying the request's device
 * proof. The proof stays bound to the request's session and tenant, and the device must still live in this principal's
 * home tenant and be shared or theirs. Without a proof on the request, `derived` is returned as it is.
 */
export function withRequestDevice(
  derived: AuthenticatedPrincipal,
  request: AuthenticatedPrincipal,
): AuthenticatedPrincipal {
  if (request.deviceProof === undefined) return derived;
  const carried: AuthenticatedPrincipal = { ...derived, deviceProof: request.deviceProof };
  proofBindings.set(carried, bindingOf(request));
  return carried;
}

/**
 * A principal a job without a request decides for again (the SSH certificate sweep), with the device key its original
 * request proved: device conditions then judge that device as it stands now (still active, still the identity's or
 * shared, and its current compliance), where they would otherwise always see no device.
 */
export function withDeviceKey(
  principal: AuthenticatedPrincipal,
  keyId: string,
): AuthenticatedPrincipal {
  const pinned: AuthenticatedPrincipal = { ...principal };
  pinnedKeys.set(pinned, keyId);
  return pinned;
}

/** A well-formed proof's protected header: only `alg`, `typ` (exactly `device-proof+jwt`) and a thumbprint `kid`. */
function proofHeaderOf(proof: unknown): { alg: unknown; kid: string } | undefined {
  if (typeof proof !== 'string' || proof.length > maxDeviceProofLength || !compactJws.test(proof))
    return undefined;
  const header = decodeProtectedHeader(proof);
  if (
    Object.keys(header).some((member) => !proofHeaderMembers.has(member)) ||
    header.typ !== deviceProofType ||
    typeof header.kid !== 'string' ||
    !deviceKeyIdPattern.test(header.kid)
  )
    return undefined;
  return { alg: header.alg, kid: header.kid };
}

/**
 * Whether a proof is signed with `jwk` under the algorithm the key's type pins, and its claims hold: `iat` within 300
 * seconds of `now` either way, `sid` the bound session and `tid`, when present, that session's tenant. Throws on
 * malformed input; callers treat that as no proof.
 */
async function proofSigned(
  proof: string,
  alg: unknown,
  jwk: DevicePublicJwk,
  binding: ProofBinding,
  now: number,
): Promise<boolean> {
  const algorithm = deviceKeyAlgorithm(jwk);
  if (!algorithm || alg !== algorithm) return false;
  // Key material comes only from the given key, rebuilt from its public members.
  const key =
    jwk.kty === 'EC'
      ? { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }
      : { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
  const { payload } = await compactVerify(proof, await importJWK(key, algorithm), {
    algorithms: [algorithm],
  });
  const claims: unknown = JSON.parse(decoder.decode(payload));
  if (!plain(claims)) return false;
  const { iat, sid, tid } = claims;
  return (
    typeof iat === 'number' &&
    Number.isFinite(iat) &&
    Math.abs(now / 1000 - iat) <= deviceProofSkewSeconds &&
    typeof sid === 'string' &&
    sid === binding.sessionId &&
    (tid === undefined || tid === binding.tenantId)
  );
}

/** The device a stored key stands for, when it may vouch for the principal: active, and shared or the identity's. */
async function deviceOfKey(
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  key: DeviceKey | undefined,
): Promise<VerifiedDevice | undefined> {
  if (!key || key.tenantId !== principal.identity.tenantId) return undefined;
  const device = await tx.get<RegisteredDevice>(deviceCollections.devices, key.deviceId);
  if (
    !device ||
    device.tenantId !== key.tenantId ||
    device.status !== 'active' ||
    (device.ownerIdentityId !== undefined && device.ownerIdentityId !== principal.identity.id)
  )
    return undefined;
  return { device, key };
}

/**
 * Verifies a device proof for a principal; undefined for anything short of a valid proof (never throws). The protected
 * header may hold only `alg`, `typ` (exactly `device-proof+jwt`) and `kid` (a stored key's thumbprint); the algorithm is
 * pinned by the stored key's type and the signature checked with the stored key only. The payload's `iat` must lie
 * within 300 seconds of `now` either way, its `sid` must be the session that authenticated the request and its `tid`,
 * when present, that session's tenant. The device must be active, live in the identity's home tenant, and be shared
 * or owned by the identity. Simulated principals never verify. Reads only: nothing is written.
 */
export async function verifyDeviceProof(
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  proof: string | undefined,
  now: number,
): Promise<VerifiedDevice | undefined> {
  if (principal.session.id === 'simulation') return undefined;
  try {
    const header = proofHeaderOf(proof);
    if (!header) return undefined;
    const key = await tx.get<DeviceKey>(deviceCollections.keys, header.kid);
    if (!key || key.id !== header.kid || key.tenantId !== principal.identity.tenantId)
      return undefined;
    if (!(await proofSigned(proof!, header.alg, key.jwk, bindingOf(principal), now)))
      return undefined;
    return await deviceOfKey(tx, principal, key);
  } catch {
    return undefined;
  }
}

/**
 * Proof of possession for enrolment: the request's device proof must be signed with the key being enrolled (its `kid`
 * that key's thumbprint) and bound to the enrolling session, with the checks every proof gets. Without it, anyone who
 * saw a public key (one proof is enough to recover it) could enrol it first and lock its holder out. Never throws.
 */
export async function provesPossession(
  principal: AuthenticatedPrincipal,
  jwk: DevicePublicJwk,
  keyId: string,
  now: number,
): Promise<boolean> {
  try {
    const header = proofHeaderOf(principal.deviceProof);
    if (!header || header.kid !== keyId) return false;
    return await proofSigned(principal.deviceProof!, header.alg, jwk, bindingOf(principal), now);
  } catch {
    return false;
  }
}

/** A verified device with its compliance and the assurance it gives the request. */
export interface PresentedDevice extends VerifiedDevice {
  compliance: ComplianceResult;
  assurance: DeviceAssurance;
}

/** One verification per principal object, so a batch of decisions (authorizeMany) verifies the proof once. */
const presented = new WeakMap<AuthenticatedPrincipal, Promise<PresentedDevice | undefined>>();

/**
 * The device the principal's request presents (its `deviceProof`, or the key `withDeviceKey` pinned), verified and
 * judged, or undefined. A session acting in another tenant than the device's (a cross-tenant role session) is decided
 * there, and that tenant neither manages the device nor set the requirements it was judged by, so the device counts as
 * registered only: never managed or compliant. Cached on the principal object: `currentPrincipal` builds a fresh one
 * per transaction, so the cache never outlives the reads.
 */
export function presentedDevice(
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  now: number,
): Promise<PresentedDevice | undefined> {
  let found = presented.get(principal);
  if (!found) {
    found = (async () => {
      try {
        const pinned = pinnedKeys.get(principal);
        const verified =
          pinned === undefined
            ? await verifyDeviceProof(tx, principal, principal.deviceProof, now)
            : principal.session.id === 'simulation'
              ? undefined
              : await deviceOfKey(
                  tx,
                  principal,
                  await tx.get<DeviceKey>(deviceCollections.keys, pinned),
                );
        if (!verified) return undefined;
        const compliance: ComplianceResult =
          principal.session.tenantId === verified.device.tenantId
            ? await complianceOf(tx, verified.device, now)
            : { compliant: false, managed: false, reasons: ['not-managed'] };
        return { ...verified, compliance, assurance: assuranceOf(compliance, true) };
      } catch {
        return undefined;
      }
    })();
    presented.set(principal, found);
  }
  return found;
}

/** The device keys of a decision (see context-keys.ts); `request.deviceId` and `request.devicePlatform` are optional. */
export interface DeviceContextKeys {
  'request.deviceAssurance': DeviceAssurance;
  'request.deviceManaged': boolean;
  'request.deviceCompliant': boolean;
  'request.deviceId'?: string;
  'request.devicePlatform'?: DevicePlatform;
}

/**
 * The device keys for a decision: the assurance, managed and compliant flags always, the device id and platform when a
 * proof verified. Simulated principals and requests without a valid proof get `none`/false. Never throws.
 */
export async function deviceContext(
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  now: number,
): Promise<DeviceContextKeys> {
  const device = await presentedDevice(tx, principal, now);
  if (!device)
    return {
      'request.deviceAssurance': 'none',
      'request.deviceManaged': false,
      'request.deviceCompliant': false,
    };
  return {
    'request.deviceAssurance': device.assurance,
    'request.deviceManaged': device.compliance.managed,
    'request.deviceCompliant': device.compliance.compliant,
    'request.deviceId': device.device.id,
    'request.devicePlatform': device.device.platform,
  };
}

/** Whether any document names a device key (`request.device…`), in conditions or `${…}` variables. */
export function mentionsDevice(documents: readonly (PolicyDocument | undefined)[]): boolean {
  return documents.some(
    (document) =>
      document !== undefined && JSON.stringify(document.statements).includes('request.device'),
  );
}

/** Retires a device: status `retired`, every key and pending enrollment code for it deleted. Returns the keys removed. */
export async function retireDevice(
  tx: IamStore,
  device: RegisteredDevice,
  now: number,
): Promise<{ device: RegisteredDevice; keysRemoved: number }> {
  const keys = await tx.find<DeviceKey>(deviceCollections.keys, {
    tenantId: device.tenantId,
    deviceId: device.id,
  });
  for (const key of keys) await tx.delete(deviceCollections.keys, key.id);
  for (const enrollment of await tx.find<DeviceEnrollment>(deviceCollections.enrollments, {
    tenantId: device.tenantId,
    deviceId: device.id,
  }))
    await tx.delete(deviceCollections.enrollments, enrollment.id);
  const retired = await tx.put<RegisteredDevice>(deviceCollections.devices, {
    ...device,
    status: 'retired',
    updatedAt: now,
  });
  return { device: retired, keysRemoved: keys.length };
}

/**
 * Devices of a deleted identity: its self-enrolled (unmanaged) devices are retired with their keys, managed ones lose
 * their owner (the integration may assign someone else) and the keys the person bound to them, and enrollment codes
 * issued for the person are withdrawn. Shared devices keep the keys the person enrolled on them.
 */
export async function releaseDevicesOf(
  tx: IamStore,
  identity: Identity,
  now: number,
): Promise<void> {
  for (const device of await tx.find<RegisteredDevice>(deviceCollections.devices, {
    tenantId: identity.tenantId,
    ownerIdentityId: identity.id,
  })) {
    if (!device.source) {
      if (device.status !== 'retired') await retireDevice(tx, device, now);
      continue;
    }
    for (const key of await tx.find<DeviceKey>(deviceCollections.keys, {
      tenantId: identity.tenantId,
      deviceId: device.id,
      createdBy: identity.id,
    }))
      await tx.delete(deviceCollections.keys, key.id);
    const { ownerIdentityId: _owner, ...rest } = device;
    await tx.put<RegisteredDevice>(deviceCollections.devices, { ...rest, updatedAt: now });
  }
  for (const enrollment of await tx.find<DeviceEnrollment>(deviceCollections.enrollments, {
    tenantId: identity.tenantId,
    ownerIdentityId: identity.id,
  }))
    await tx.delete(deviceCollections.enrollments, enrollment.id);
}
