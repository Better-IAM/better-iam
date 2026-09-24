// Labels, tones, list filters, and the compliance breakdown shared by the console's device posture pages. Pure: no
// server-only imports, so tests can load it directly.
import type {
  ComplianceResult,
  DeviceAssurance,
  DeviceIntegrationView,
  DevicePlatform,
  DeviceSettingsView,
  DeviceView,
} from 'better-iam';
import type { Tone } from '@/components/ui';
import type { FieldSpec } from './form-body';

export type DeviceStatus = DeviceView['status'];
export type ComplianceReason = ComplianceResult['reasons'][number];
export type IntegrationVendor = DeviceIntegrationView['vendor'];

export const platformLabels: Record<DevicePlatform, string> = {
  windows: 'Windows',
  macos: 'macOS',
  linux: 'Linux',
  ios: 'iOS',
  android: 'Android',
  chromeos: 'ChromeOS',
  other: 'Other',
};
export const platformOptions = Object.entries(platformLabels).map(([value, label]) => ({
  value,
  label,
}));
/** Example versions for the minimum OS fields. */
export const osVersionExamples: Record<DevicePlatform, string> = {
  windows: '10.0.19045',
  macos: '14.5',
  linux: '6.1',
  ios: '17.5',
  android: '14',
  chromeos: '126',
  other: '1.0',
};

export const vendorLabels: Record<IntegrationVendor, string> = {
  intune: 'Microsoft Intune',
  jamf: 'Jamf',
  kandji: 'Kandji',
  'workspace-one': 'Workspace ONE',
  'google-endpoint': 'Google endpoint management',
  crowdstrike: 'CrowdStrike Falcon',
  sentinelone: 'SentinelOne',
  custom: 'Custom',
};
export const vendorOptions = Object.entries(vendorLabels).map(([value, label]) => ({
  value,
  label,
}));

export const assuranceLabels: Record<DeviceAssurance, string> = {
  none: 'none',
  registered: 'registered',
  managed: 'managed',
  compliant: 'compliant',
};
/** What each assurance level means, for tooltips and legends. */
export const assuranceHelp: Record<DeviceAssurance, string> = {
  none: 'Proves nothing: no enrolled key, or the device is lost or retired.',
  registered: 'An active device with an enrolled key, not managed by an integration.',
  managed: 'An active integration manages the device, but it does not meet the requirements.',
  compliant: 'Managed and meeting every compliance requirement.',
};

export function assuranceTone(assurance: DeviceAssurance): Tone {
  return assurance === 'compliant' ? 'success' : assurance === 'managed' ? 'accent' : 'neutral';
}

export function deviceStatusTone(status: DeviceStatus): Tone {
  return status === 'active' ? 'success' : status === 'lost' ? 'danger' : 'neutral';
}

/** Why a device is not compliant, in a few words. */
export const reasonLabels: Record<ComplianceReason, string> = {
  'not-managed': 'not managed',
  'integration-disabled': 'integration disabled',
  stale: 'no recent check-in',
  'vendor-noncompliant': 'vendor reports non-compliant',
  'not-encrypted': 'not encrypted',
  'no-screen-lock': 'no screen lock',
  'no-firewall': 'firewall off',
  'edr-unhealthy': 'EDR unhealthy',
  jailbroken: 'jailbroken or rooted',
  'os-too-old': 'OS too old',
  'os-unknown': 'OS version unknown',
  lost: 'marked lost',
  retired: 'retired',
};

/** The compliance verdict of a device as a short label and tone. */
export function complianceState(compliance: ComplianceResult): { label: string; tone: Tone } {
  if (compliance.compliant) return { label: 'compliant', tone: 'success' };
  if (compliance.managed) return { label: 'non-compliant', tone: 'danger' };
  return { label: 'unmanaged', tone: 'neutral' };
}

/** The reasons worth showing next to a verdict: an unmanaged device's only reason is that it is unmanaged. */
export function shownReasons(compliance: ComplianceResult): string[] {
  return compliance.reasons
    .filter((reason) => reason !== 'not-managed')
    .map((reason) => reasonLabels[reason] ?? reason);
}

/** How long a new enrollment code stays valid, entered in hours (the API takes 10 minutes to 30 days, in ms). */
export const enrollmentLifetimeField: FieldSpec = {
  name: 'expiresInMs',
  label: 'Valid for (hours)',
  type: 'number',
  required: true,
  defaultValue: 168,
  multiplier: 3_600_000,
  help: '1 to 720 (30 days); the default is a week.',
};

/** "just now", "12 min ago", "5 h ago", "3 days ago". */
export function ageLabel(since: number | undefined, now: number): string | undefined {
  if (since === undefined) return undefined;
  const elapsed = Math.max(0, now - since);
  if (elapsed < 60_000) return 'just now';
  if (elapsed < 3_600_000) return `${Math.floor(elapsed / 60_000)} min ago`;
  if (elapsed < 48 * 3_600_000) return `${Math.floor(elapsed / 3_600_000)} h ago`;
  return `${Math.floor(elapsed / 86_400_000)} days ago`;
}

// ---------------------------------------------------------------------------------------------------------------
// Inventory filters (query string ⇄ devices.list input)

export interface DeviceFilters {
  ownerIdentityId?: string;
  platform?: DevicePlatform;
  status?: DeviceStatus;
  managed?: boolean;
  compliant?: boolean;
  query?: string;
}

export interface DeviceFilterParams {
  owner?: string;
  platform?: string;
  status?: string;
  managed?: string;
  compliant?: string;
  q?: string;
  page?: string;
}

const statuses: readonly string[] = ['active', 'lost', 'retired'];

function yesNo(value: string | undefined): boolean | undefined {
  return value === 'yes' ? true : value === 'no' ? false : undefined;
}

/** The inventory filters in a query string; unknown values are ignored rather than refused. */
export function deviceFilters(params: DeviceFilterParams): {
  filters: DeviceFilters;
  page: number;
} {
  const owner = params.owner?.trim();
  const query = params.q?.trim().slice(0, 200);
  const managed = yesNo(params.managed);
  const compliant = yesNo(params.compliant);
  const filters: DeviceFilters = {
    ...(owner ? { ownerIdentityId: owner } : {}),
    ...(params.platform && params.platform in platformLabels
      ? { platform: params.platform as DevicePlatform }
      : {}),
    ...(params.status && statuses.includes(params.status)
      ? { status: params.status as DeviceStatus }
      : {}),
    ...(managed !== undefined ? { managed } : {}),
    ...(compliant !== undefined ? { compliant } : {}),
    ...(query ? { query } : {}),
  };
  const page = Math.max(1, Number.parseInt(params.page ?? '1', 10) || 1);
  return { filters, page };
}

/** Whether any filter narrows the inventory. */
export function filtering(filters: DeviceFilters): boolean {
  return Object.keys(filters).length > 0;
}

/** The query string (with its `?`, or empty) for filters and a page. */
export function deviceFilterQuery(filters: DeviceFilters, page = 1): string {
  const search = new URLSearchParams();
  if (filters.query) search.set('q', filters.query);
  if (filters.ownerIdentityId) search.set('owner', filters.ownerIdentityId);
  if (filters.platform) search.set('platform', filters.platform);
  if (filters.status) search.set('status', filters.status);
  if (filters.managed !== undefined) search.set('managed', filters.managed ? 'yes' : 'no');
  if (filters.compliant !== undefined) search.set('compliant', filters.compliant ? 'yes' : 'no');
  if (page > 1) search.set('page', String(page));
  const text = search.toString();
  return text ? `?${text}` : '';
}

// ---------------------------------------------------------------------------------------------------------------
// Compliance breakdown

export type CheckOutcome = 'pass' | 'fail' | 'not-required' | 'not-evaluated';

export interface ComplianceCheck {
  key: string;
  label: string;
  /** What the tenant requires ("required", "≥ 14.5", "within 24 h"). */
  requirement: string;
  /** What the device's last report says. */
  reported: string;
  outcome: CheckOutcome;
}

export const outcomeLabels: Record<CheckOutcome, string> = {
  pass: 'pass',
  fail: 'fail',
  'not-required': 'not required',
  'not-evaluated': 'not evaluated',
};

export function outcomeTone(outcome: CheckOutcome): Tone {
  return outcome === 'pass' ? 'success' : outcome === 'fail' ? 'danger' : 'neutral';
}

const reportedFlag = (value: boolean | undefined, yes = 'yes', no = 'no') =>
  value === true ? yes : value === false ? no : 'unknown';

/**
 * One row per compliance requirement: what the tenant asks, what the device reported, and whether it passed. Pass
 * and fail come from the server's verdict (`compliance.reasons`), never from re-evaluating here; `settings` and
 * `integration` only describe the requirement. Posture checks read "not evaluated" while no active integration
 * manages the device or it has no report from that integration, as the server stops there too.
 */
export function complianceChecks(
  device: DeviceView,
  settings: DeviceSettingsView | undefined,
  integration: DeviceIntegrationView | undefined,
  now: number,
): ComplianceCheck[] {
  const reasons = new Set<string>(device.compliance.reasons);
  const posture =
    device.posture && device.source && device.posture.integrationId === device.source.integrationId
      ? device.posture
      : undefined;
  const evaluated = device.compliance.managed && posture !== undefined;
  const judged = (failed: boolean, required: boolean | undefined): CheckOutcome =>
    !evaluated ? 'not-evaluated' : failed ? 'fail' : required === false ? 'not-required' : 'pass';
  const required = (value: boolean | undefined) =>
    value === undefined ? '—' : value ? 'required' : 'not required';
  const checks: ComplianceCheck[] = [
    {
      key: 'status',
      label: 'Device status',
      requirement: 'active',
      reported: device.status,
      outcome: reasons.has('lost') || reasons.has('retired') ? 'fail' : 'pass',
    },
    {
      key: 'managed',
      label: 'Managed',
      requirement: 'an active integration reports it',
      reported: !device.source
        ? 'self-enrolled'
        : integration
          ? `${integration.name}${integration.status === 'active' ? '' : ' (disabled)'}`
          : 'by a removed integration',
      outcome: reasons.has('not-managed') || reasons.has('integration-disabled') ? 'fail' : 'pass',
    },
    {
      key: 'check-in',
      label: 'Recent check-in',
      requirement: settings ? `within ${settings.maxCheckInAgeHours} h` : '—',
      reported:
        ageLabel(device.lastCheckInAt ?? posture?.reportedAt, now) ??
        (device.source ? 'never' : '—'),
      outcome: !device.compliance.managed
        ? 'not-evaluated'
        : reasons.has('stale')
          ? 'fail'
          : 'pass',
    },
    {
      key: 'vendor',
      label: 'Vendor verdict',
      requirement: !integration
        ? '—'
        : integration.trustVendorCompliance
          ? 'must not be non-compliant'
          : 'ignored',
      reported: reportedFlag(posture?.compliant, 'compliant', 'non-compliant'),
      outcome: judged(
        reasons.has('vendor-noncompliant'),
        integration ? integration.trustVendorCompliance : undefined,
      ),
    },
    {
      key: 'encrypted',
      label: 'Disk encryption',
      requirement: required(settings?.requireEncrypted),
      reported: reportedFlag(posture?.encrypted),
      outcome: judged(reasons.has('not-encrypted'), settings?.requireEncrypted),
    },
    {
      key: 'screen-lock',
      label: 'Screen lock',
      requirement: required(settings?.requireScreenLock),
      reported: reportedFlag(posture?.screenLock),
      outcome: judged(reasons.has('no-screen-lock'), settings?.requireScreenLock),
    },
    {
      key: 'firewall',
      label: 'Firewall',
      requirement: required(settings?.requireFirewall),
      reported: reportedFlag(posture?.firewall, 'on', 'off'),
      outcome: judged(reasons.has('no-firewall'), settings?.requireFirewall),
    },
    {
      key: 'edr',
      label: 'EDR agent healthy',
      requirement: required(settings?.requireEdr),
      reported: reportedFlag(posture?.edrHealthy, 'healthy', 'unhealthy'),
      outcome: judged(reasons.has('edr-unhealthy'), settings?.requireEdr),
    },
    {
      key: 'jailbroken',
      label: 'Not jailbroken or rooted',
      requirement: settings ? (settings.blockJailbroken ? 'required' : 'not required') : '—',
      reported: reportedFlag(posture?.jailbroken, 'jailbroken', 'no'),
      outcome: judged(reasons.has('jailbroken'), settings?.blockJailbroken),
    },
  ];
  const minimum = settings?.minOsVersions[device.platform];
  checks.push({
    key: 'os',
    label: 'OS version',
    requirement: !settings ? '—' : minimum ? `${minimum} or later` : 'no minimum',
    reported: posture?.osVersion ?? 'unknown',
    outcome: judged(
      reasons.has('os-too-old') || reasons.has('os-unknown'),
      settings ? minimum !== undefined : undefined,
    ),
  });
  return checks;
}
