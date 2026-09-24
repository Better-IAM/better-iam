import { describe, expect, it } from 'vitest';
import {
  assuranceOf,
  evaluateCompliance,
  resolveDeviceSettings,
  type DeviceIntegration,
  type DeviceIntegrationView,
  type DeviceSettingsView,
  type DeviceView,
  type RegisteredDevice,
  type ResolvedDeviceSettings,
} from '@better-iam/server';
import {
  ageLabel,
  complianceChecks,
  complianceState,
  deviceFilterQuery,
  deviceFilters,
  filtering,
  shownReasons,
} from '../apps/console/src/lib/device-posture.js';

const now = Date.UTC(2026, 8, 24, 12);
const HOUR = 3_600_000;

const integration: DeviceIntegration = {
  id: 'int-1',
  tenantId: 't1',
  name: 'Intune',
  vendor: 'intune',
  status: 'active',
  trustVendorCompliance: true,
  createdAt: now - 1000 * HOUR,
  createdBy: 'admin',
  updatedAt: now - 1000 * HOUR,
};
const integrationView: DeviceIntegrationView = {
  id: integration.id,
  tenantId: integration.tenantId,
  name: integration.name,
  vendor: integration.vendor,
  status: integration.status,
  trustVendorCompliance: integration.trustVendorCompliance,
  createdAt: integration.createdAt,
  createdBy: integration.createdBy,
  updatedAt: integration.updatedAt,
  devices: 1,
};

function settingsView(settings: ResolvedDeviceSettings): DeviceSettingsView {
  return { ...settings, tenantId: 't1', configured: true };
}

/** A device view with the server's own verdict, so the breakdown is checked against the real evaluation. */
function view(
  device: Partial<RegisteredDevice>,
  settings: ResolvedDeviceSettings,
  source: DeviceIntegration | undefined = integration,
): DeviceView {
  const record: RegisteredDevice = {
    id: 'dev-1',
    tenantId: 't1',
    name: 'MacBook',
    platform: 'macos',
    status: 'active',
    createdAt: now - 100 * HOUR,
    updatedAt: now - HOUR,
    ...device,
  };
  const compliance = evaluateCompliance(record, source, settings, now);
  return {
    id: record.id,
    tenantId: record.tenantId,
    name: record.name,
    platform: record.platform,
    status: record.status,
    ...(record.source ? { source: record.source } : {}),
    ...(record.posture ? { posture: record.posture } : {}),
    ...(record.lastCheckInAt !== undefined ? { lastCheckInAt: record.lastCheckInAt } : {}),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    compliance,
    assurance: assuranceOf(compliance, record.status === 'active'),
    keys: 1,
  };
}

const managed = {
  source: { integrationId: 'int-1', externalId: 'ext-1' },
  lastCheckInAt: now - 2 * HOUR,
};

describe('console device posture helpers', () => {
  it('reads inventory filters from the query string and writes them back', () => {
    const { filters, page } = deviceFilters({
      q: '  mac ',
      owner: 'id-1',
      platform: 'macos',
      status: 'lost',
      managed: 'yes',
      compliant: 'no',
      page: '3',
    });
    expect(filters).toEqual({
      query: 'mac',
      ownerIdentityId: 'id-1',
      platform: 'macos',
      status: 'lost',
      managed: true,
      compliant: false,
    });
    expect(page).toBe(3);
    expect(
      deviceFilters(Object.fromEntries(new URLSearchParams(deviceFilterQuery(filters, 3)))),
    ).toEqual({
      filters,
      page: 3,
    });
  });

  it('ignores unknown filter values instead of failing the page', () => {
    const { filters, page } = deviceFilters({
      platform: 'toaster',
      status: 'deleted',
      managed: 'maybe',
      page: '-2',
    });
    expect(filters).toEqual({});
    expect(filtering(filters)).toBe(false);
    expect(page).toBe(1);
    expect(deviceFilterQuery(filters)).toBe('');
  });

  it('labels the verdict and hides the reason every unmanaged device shares', () => {
    const settings = resolveDeviceSettings(undefined);
    const unmanaged = view({}, settings, undefined);
    expect(complianceState(unmanaged.compliance)).toEqual({ label: 'unmanaged', tone: 'neutral' });
    expect(shownReasons(unmanaged.compliance)).toEqual([]);
    const lost = view({ status: 'lost' }, settings, undefined);
    expect(shownReasons(lost.compliance)).toEqual(['marked lost']);
  });

  it('does not evaluate posture checks for an unmanaged device', () => {
    const settings = resolveDeviceSettings(undefined);
    const checks = complianceChecks(
      view({}, settings, undefined),
      settingsView(settings),
      undefined,
      now,
    );
    expect(checks.find((check) => check.key === 'managed')?.outcome).toBe('fail');
    expect(checks.find((check) => check.key === 'managed')?.reported).toBe('self-enrolled');
    for (const key of ['check-in', 'vendor', 'encrypted', 'firewall', 'os'])
      expect(checks.find((check) => check.key === key)?.outcome).toBe('not-evaluated');
  });

  it('matches the server verdict for a managed device, check by check', () => {
    const settings: ResolvedDeviceSettings = {
      ...resolveDeviceSettings(undefined),
      requireEncrypted: true,
      requireFirewall: true,
      minOsVersions: { macos: '14.5' },
    };
    const device = view(
      {
        ...managed,
        posture: {
          encrypted: true,
          firewall: false,
          compliant: true,
          osVersion: '14.2',
          reportedAt: now - 2 * HOUR,
          integrationId: 'int-1',
        },
      },
      settings,
    );
    expect(device.compliance.reasons.sort()).toEqual(['no-firewall', 'os-too-old']);
    expect(device.assurance).toBe('managed');
    const checks = Object.fromEntries(
      complianceChecks(device, settingsView(settings), integrationView, now).map((check) => [
        check.key,
        check,
      ]),
    );
    expect(checks.status?.outcome).toBe('pass');
    expect(checks.managed?.outcome).toBe('pass');
    expect(checks['check-in']).toMatchObject({ outcome: 'pass', reported: '2 h ago' });
    expect(checks.vendor).toMatchObject({ outcome: 'pass', reported: 'compliant' });
    expect(checks.encrypted).toMatchObject({ outcome: 'pass', requirement: 'required' });
    expect(checks.firewall).toMatchObject({ outcome: 'fail', reported: 'off' });
    expect(checks['screen-lock']?.outcome).toBe('not-required');
    expect(checks.edr?.outcome).toBe('not-required');
    expect(checks.jailbroken).toMatchObject({ outcome: 'pass', reported: 'unknown' });
    expect(checks.os).toMatchObject({
      outcome: 'fail',
      requirement: '14.5 or later',
      reported: '14.2',
    });
    // Every failing row corresponds to a server reason, and vice versa.
    expect(Object.values(checks).filter((check) => check.outcome === 'fail')).toHaveLength(2);
  });

  it('reports a stale device without posture as failing only the check-in', () => {
    const settings = resolveDeviceSettings(undefined);
    const device = view({ ...managed, lastCheckInAt: undefined }, settings);
    expect(device.compliance.reasons).toEqual(['stale']);
    const checks = complianceChecks(device, settingsView(settings), integrationView, now);
    expect(checks.find((check) => check.key === 'check-in')).toMatchObject({
      outcome: 'fail',
      reported: 'never',
    });
    expect(checks.find((check) => check.key === 'encrypted')?.outcome).toBe('not-evaluated');
  });

  it('describes ages in a few words', () => {
    expect(ageLabel(undefined, now)).toBeUndefined();
    expect(ageLabel(now - 10_000, now)).toBe('just now');
    expect(ageLabel(now - 12 * 60_000, now)).toBe('12 min ago');
    expect(ageLabel(now - 30 * HOUR, now)).toBe('30 h ago');
    expect(ageLabel(now - 72 * HOUR, now)).toBe('3 days ago');
  });
});
