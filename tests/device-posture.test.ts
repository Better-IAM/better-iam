import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '@better-iam/core';
import { createDeviceProver, memoryKeyStore } from '@better-iam/client/device';
import { routeGroups } from '@better-iam/server';
import { presentedDevice } from '../packages/server/src/devices.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const doc = { type: 'document', id: 'd1' };
const compliantOnly = {
  version: 1,
  statements: [
    {
      effect: 'allow' as const,
      actions: ['documents:read'],
      resources: ['*'],
      conditions: { Bool: { 'request.deviceCompliant': true } },
    },
  ],
};

async function setup() {
  const f = await organizationFixture();
  const alice = await f.member('alice');
  const signedIn = await f.signIn('alice');
  const credential = { token: signedIn.token };
  const prover = createDeviceProver({ store: memoryKeyStore() });
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Readers on compliant devices',
    document: compliantOnly,
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: alice.id,
  });
  const withDevice = async (sessionId = signedIn.session.id) => ({
    authorization: `Bearer ${signedIn.token}`,
    ...(await prover.headers(sessionId)),
  });
  const canRead = async (headers: Record<string, string>) =>
    (
      await f.iam.authorize({
        headers,
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: doc,
      })
    ).allowed;
  return { f, alice, signedIn, credential, prover, withDevice, canRead };
}

describe('device posture', () => {
  it('enrolls a device key, verifies proofs bound to the session, and reports assurance', async () => {
    const { f, credential, prover, withDevice, signedIn } = await setup();
    expect(routeGroups.has('devices')).toBe(true);
    const enrolled = await f.iam.api.devices.enroll(
      { headers: await withDevice() },
      {
        tenantId: f.tenantId,
        name: 'Alice laptop',
        platform: 'macos',
        publicKey: await prover.publicJwk(),
      },
    );
    expect(enrolled.keyId).toBe(await prover.keyId());
    await expect(
      f.iam.api.devices.enroll(
        { headers: await withDevice() },
        {
          tenantId: f.tenantId,
          name: 'Again',
          platform: 'macos',
          publicKey: await prover.publicJwk(),
        },
      ),
    ).rejects.toMatchObject({ code: 'CONFLICT' });

    const absent = await f.iam.api.devices.check(credential, { tenantId: f.tenantId });
    expect(absent).toMatchObject({ assurance: 'none', proof: 'absent', managed: false });
    const verified = await f.iam.api.devices.check(
      { headers: await withDevice() },
      { tenantId: f.tenantId },
    );
    expect(verified).toMatchObject({
      assurance: 'registered',
      proof: 'verified',
      deviceId: enrolled.device.id,
      platform: 'macos',
      compliant: false,
    });
    expect(verified.reasons).toContain('not-managed');

    // A proof made for another session does not transfer.
    const other = await f.iam.api.devices.check(
      { headers: await withDevice('ses_someone_else') },
      { tenantId: f.tenantId },
    );
    expect(other).toMatchObject({ assurance: 'none', proof: 'invalid' });
    // Garbage in the header is "no device", never an error.
    const garbage = await f.iam.api.devices.check(
      {
        headers: { authorization: `Bearer ${signedIn.token}`, 'x-better-iam-device': 'not.a.jws' },
      },
      { tenantId: f.tenantId },
    );
    expect(garbage).toMatchObject({ assurance: 'none', proof: 'invalid' });

    const mine = await f.iam.api.devices.mine(
      { headers: await withDevice() },
      { tenantId: f.tenantId },
    );
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({ id: enrolled.device.id, current: true });
  });

  it('turns MDM posture into compliance that policies can require', async () => {
    const { f, prover, withDevice, canRead, signedIn } = await setup();
    const { device } = await f.iam.api.devices.enroll(
      { headers: await withDevice() },
      {
        tenantId: f.tenantId,
        name: 'Alice laptop',
        platform: 'macos',
        publicKey: await prover.publicJwk(),
      },
    );
    // Without a compliant device the policy grants nothing.
    expect(await canRead({ authorization: `Bearer ${signedIn.token}` })).toBe(false);
    expect(await canRead(await withDevice())).toBe(false);

    const owner = await f.ownerSignIn();
    const integration = await f.iam.api.devices.createIntegration(owner, {
      tenantId: f.tenantId,
      name: 'Jamf',
      vendor: 'jamf',
    });
    await f.iam.api.devices.configure(owner, {
      tenantId: f.tenantId,
      requireEncrypted: true,
      minOsVersions: { macos: '14.0' },
    });
    const report = (posture: Record<string, boolean>, osVersion = '14.5 (23F79)') =>
      f.iam.api.devices.report(f.ownerCredential, {
        tenantId: f.tenantId,
        integrationId: integration.id,
        devices: [
          {
            externalId: 'jamf-42',
            platform: 'macos',
            serialNumber: 'C02XYZ',
            osVersion,
            ownerEmail: 'alice@acme.test',
            posture,
          },
        ],
      });
    // The MDM record does not know the key yet: the self-enrolled device stays unmanaged.
    const first = await report({ compliant: true, encrypted: true });
    expect(first.created).toBe(1);
    expect(await canRead(await withDevice())).toBe(false);

    // The agent the MDM deployed reports the key it enrolled: the key moves onto the managed record.
    const keyed = await f.iam.api.devices.report(f.ownerCredential, {
      tenantId: f.tenantId,
      integrationId: integration.id,
      devices: [
        {
          externalId: 'jamf-42',
          platform: 'macos',
          osVersion: '14.5',
          ownerEmail: 'alice@acme.test',
          keyThumbprint: await prover.keyId(),
          posture: { compliant: true, encrypted: true },
        },
      ],
    });
    expect(keyed.updated).toBe(1);
    const check = await f.iam.api.devices.check(
      { headers: await withDevice() },
      { tenantId: f.tenantId },
    );
    expect(check).toMatchObject({ assurance: 'compliant', managed: true, compliant: true });
    expect(check.deviceId).not.toBe(device.id);
    expect(
      (
        await f.iam.api.devices.get(f.ownerCredential, {
          tenantId: f.tenantId,
          deviceId: device.id,
        })
      ).status,
    ).toBe('retired');
    expect(await canRead(await withDevice())).toBe(true);
    // The same session without the proof, or another session with a replayed header, is refused.
    expect(await canRead({ authorization: `Bearer ${signedIn.token}` })).toBe(false);
    const second = await f.signIn('alice');
    expect(
      await canRead({
        authorization: `Bearer ${second.token}`,
        'x-better-iam-device': (await withDevice())['x-better-iam-device']!,
      }),
    ).toBe(false);

    // Posture drift flips compliance and is audited once.
    const drift = await f.iam.api.devices.report(f.ownerCredential, {
      tenantId: f.tenantId,
      integrationId: integration.id,
      devices: [
        {
          externalId: 'jamf-42',
          platform: 'macos',
          osVersion: '13.6',
          posture: { compliant: true, encrypted: true },
        },
      ],
    });
    expect(drift.complianceChanged).toBe(1);
    const reasons = await f.iam.api.devices.check(
      { headers: await withDevice() },
      { tenantId: f.tenantId },
    );
    expect(reasons).toMatchObject({ assurance: 'managed', compliant: false });
    expect(reasons.reasons).toContain('os-too-old');
    expect(await canRead(await withDevice())).toBe(false);
    const audit = await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId });
    // Only the drift changed the verdict (the record was created compliant and stayed so when the key moved).
    const changes = audit.filter((event) => event.action === 'device:compliance-change');
    expect(changes).toHaveLength(1);
    expect(changes[0]!.metadata).toMatchObject({ from: true, to: false });
    expect(audit.some((event) => event.action === 'device:report')).toBe(true);
  });

  it('binds keys to managed records with single-use enrollment codes', async () => {
    const { f, credential, prover, withDevice, alice, signedIn } = await setup();
    const owner = await f.ownerSignIn();
    const integration = await f.iam.api.devices.createIntegration(owner, {
      tenantId: f.tenantId,
      name: 'Intune',
      vendor: 'intune',
    });
    await f.iam.api.devices.report(f.ownerCredential, {
      tenantId: f.tenantId,
      integrationId: integration.id,
      devices: [
        {
          externalId: 'intune-7',
          platform: 'windows',
          osVersion: '10.0.22631',
          ownerIdentityId: alice.id,
          posture: { compliant: true },
        },
      ],
    });
    const managed = (
      await f.iam.api.devices.list(f.ownerCredential, { tenantId: f.tenantId, managed: true })
    ).devices[0]!;
    expect(managed).toMatchObject({ platform: 'windows', ownerIdentityId: alice.id, keys: 0 });

    const code = await f.iam.api.devices.createEnrollment(owner, {
      tenantId: f.tenantId,
      deviceId: managed.id,
      ownerIdentityId: alice.id,
    });
    expect(code.code.startsWith('biam_')).toBe(true);
    // Someone else cannot use a code issued for alice.
    await f.member('mallory');
    const mallory = await f.signIn('mallory');
    const malloryProver = createDeviceProver({ store: memoryKeyStore() });
    await expect(
      f.iam.api.devices.enroll(
        {
          headers: {
            authorization: `Bearer ${mallory.token}`,
            ...(await malloryProver.headers(mallory.session.id)),
          },
        },
        {
          tenantId: f.tenantId,
          name: 'x',
          platform: 'windows',
          publicKey: await malloryProver.publicJwk(),
          enrollmentCode: code.code,
        },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const bound = await f.iam.api.devices.enroll(
      { headers: await withDevice() },
      {
        tenantId: f.tenantId,
        name: 'ignored',
        platform: 'windows',
        publicKey: await prover.publicJwk(),
        enrollmentCode: code.code,
      },
    );
    expect(bound.device.id).toBe(managed.id);
    const check = await f.iam.api.devices.check(
      { headers: await withDevice() },
      { tenantId: f.tenantId },
    );
    expect(check).toMatchObject({ assurance: 'compliant', deviceId: managed.id });
    // The code is spent.
    const another = createDeviceProver({ store: memoryKeyStore() });
    await expect(
      f.iam.api.devices.enroll(
        {
          headers: {
            authorization: `Bearer ${credential.token}`,
            ...(await another.headers(signedIn.session.id)),
          },
        },
        {
          tenantId: f.tenantId,
          name: 'again',
          platform: 'windows',
          publicKey: await another.publicJwk(),
          enrollmentCode: code.code,
        },
      ),
    ).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: 'Invalid or expired enrollment code',
    });

    // Retiring the device ends what its proofs prove.
    await f.iam.api.devices.retire(owner, { tenantId: f.tenantId, deviceId: managed.id });
    expect(
      (await f.iam.api.devices.check({ headers: await withDevice() }, { tenantId: f.tenantId }))
        .assurance,
    ).toBe('none');
  });

  it('keeps administration, reports, and policy defaults behind the right permissions', async () => {
    const { f, credential } = await setup();
    await expect(
      f.iam.api.devices.list(credential, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    const owner = await f.ownerSignIn();
    const integration = await f.iam.api.devices.createIntegration(owner, {
      tenantId: f.tenantId,
      name: 'CrowdStrike',
      vendor: 'crowdstrike',
    });
    await expect(
      f.iam.api.devices.report(credential, {
        tenantId: f.tenantId,
        integrationId: integration.id,
        devices: [{ externalId: 'x', platform: 'linux', posture: {} }],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // policies.test fills the always-present device keys.
    const tested = await f.iam.api.policies.test(f.ownerCredential, {
      tenantId: f.tenantId,
      document: compliantOnly,
      action: 'documents:read',
      resource: 'document/d1',
    });
    expect(tested.allowed).toBe(false);
    const compliant = await f.iam.api.policies.test(f.ownerCredential, {
      tenantId: f.tenantId,
      document: compliantOnly,
      action: 'documents:read',
      resource: 'document/d1',
      context: { 'request.deviceCompliant': true },
    });
    expect(compliant.allowed).toBe(true);
  });

  it('carries the device proof through the HTTP transport and allows it cross-origin', async () => {
    const { f, prover, withDevice, signedIn } = await setup();
    await f.iam.api.devices.enroll(
      { headers: await withDevice() },
      {
        tenantId: f.tenantId,
        name: 'Phone',
        platform: 'ios',
        publicKey: await prover.publicJwk(),
      },
    );
    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/devices/check', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${signedIn.token}`,
          ...(await prover.headers(signedIn.session.id)),
        },
        body: JSON.stringify({ tenantId: f.tenantId }),
      }),
    );
    expect(response.status).toBe(200);
    expect(((await response.json()) as { data: { assurance: string } }).data.assurance).toBe(
      'registered',
    );
  });
});

const hour = 3_600_000;

/** Just enough IndexedDB for `indexedDbKeyStore`: databases by name, one object store each, values kept as given. */
function fakeIndexedDb() {
  const databases = new Map<string, Map<unknown, unknown>>();
  const later = (run: () => void) => void Promise.resolve().then(run);
  const factory = {
    open(name: string) {
      const request: {
        result?: unknown;
        onupgradeneeded?: () => void;
        onsuccess?: () => void;
      } = {};
      later(() => {
        const created = !databases.has(name);
        if (created) databases.set(name, new Map());
        const data = databases.get(name)!;
        request.result = {
          createObjectStore() {},
          close() {},
          transaction() {
            const transaction: { oncomplete?: () => void; objectStore(): unknown } = {
              objectStore: () => {
                const settle = (apply: () => unknown) => {
                  const pending: { result?: unknown } = {};
                  later(() => {
                    pending.result = apply();
                    transaction.oncomplete?.();
                  });
                  return pending;
                };
                return {
                  get: (key: unknown) => settle(() => data.get(key)),
                  put: (value: unknown, key: unknown) => settle(() => data.set(key, value) && key),
                  delete: (key: unknown) => settle(() => void data.delete(key)),
                };
              },
            };
            return transaction;
          },
        };
        if (created) request.onupgradeneeded?.();
        request.onsuccess?.();
      });
      return request;
    },
  };
  return { factory, names: () => [...databases.keys()].sort() };
}

describe('device posture protections', () => {
  it('moves a reported key only off its owner’s own active record', async () => {
    const { f, prover, withDevice } = await setup();
    const tenantId = f.tenantId;
    const { device: laptop } = await f.iam.api.devices.enroll(
      { headers: await withDevice() },
      { tenantId, name: 'Laptop', platform: 'macos', publicKey: await prover.publicJwk() },
    );
    const owner = await f.ownerSignIn();
    const jamf = await f.iam.api.devices.createIntegration(owner, {
      tenantId,
      name: 'Jamf',
      vendor: 'jamf',
    });
    const contractor = await f.iam.api.devices.createIntegration(owner, {
      tenantId,
      name: 'Contractor MDM',
      vendor: 'custom',
    });
    const keyThumbprint = await prover.keyId();
    const report = (integrationId: string, externalId: string, ownerEmail?: string) =>
      f.iam.api.devices.report(f.ownerCredential, {
        tenantId,
        integrationId,
        devices: [
          {
            externalId,
            platform: 'macos',
            keyThumbprint,
            ...(ownerEmail ? { ownerEmail } : {}),
            posture: { compliant: true },
          },
        ],
      });
    const presenting = async () =>
      (await f.iam.api.devices.check({ headers: await withDevice() }, { tenantId })).deviceId;

    // A report naming nobody, or someone else, takes nothing.
    await report(contractor.id, 'c-1');
    await f.member('mallory');
    await report(contractor.id, 'c-2', 'mallory@acme.test');
    expect(await presenting()).toBe(laptop.id);
    // A device marked lost keeps its key dead.
    await f.iam.api.devices.update(owner, { tenantId, deviceId: laptop.id, status: 'lost' });
    await report(jamf.id, 'jamf-1', 'alice@acme.test');
    expect(await presenting()).toBeUndefined();
    expect((await f.iam.api.devices.get(owner, { tenantId, deviceId: laptop.id })).status).toBe(
      'lost',
    );
    // Found again: the managed record takes the key over.
    await f.iam.api.devices.update(owner, { tenantId, deviceId: laptop.id, status: 'active' });
    await report(jamf.id, 'jamf-1', 'alice@acme.test');
    const managed = await presenting();
    expect(managed).toBeDefined();
    expect(managed).not.toBe(laptop.id);
    // Another integration cannot take it off Jamf's record, even naming the owner.
    await report(contractor.id, 'c-3', 'alice@acme.test');
    expect(await presenting()).toBe(managed);
  });

  it('writes a throttled check-in that flips compliance, and audits the flip once', async () => {
    const { f } = await setup();
    const tenantId = f.tenantId;
    const owner = await f.ownerSignIn();
    const integration = await f.iam.api.devices.createIntegration(owner, {
      tenantId,
      name: 'Jamf',
      vendor: 'jamf',
    });
    await f.iam.api.devices.configure(owner, { tenantId, maxCheckInAgeHours: 1 });
    const start = f.now();
    const report = (checkedInAt: number) =>
      f.iam.api.devices.report(f.ownerCredential, {
        tenantId,
        integrationId: integration.id,
        devices: [
          { externalId: 'jamf-7', platform: 'macos', posture: { compliant: true }, checkedInAt },
        ],
      });
    await report(start);
    // The stored check-in has just gone stale; the vendor's timestamp of the new one is fresh but within a minute.
    f.advance(hour + 500);
    expect((await report(start + 30_000)).complianceChanged).toBe(1);
    const [device] = (await f.iam.api.devices.list(f.ownerCredential, { tenantId, managed: true }))
      .devices;
    expect(device).toMatchObject({
      lastCheckInAt: start + 30_000,
      compliance: { compliant: true },
    });
    expect((await report(start + 59_000)).complianceChanged).toBe(0);
    const changes = (await f.iam.store.find<AuditEvent>('audit', { tenantId })).filter(
      (event) => event.action === 'device:compliance-change',
    );
    expect(changes).toHaveLength(1);
  });

  it('binds codes to an existing device only for those who manage that device', async () => {
    const { f, alice } = await setup();
    const tenantId = f.tenantId;
    const owner = await f.ownerSignIn();
    const helpdesk = await f.iam.api.serviceAccounts.create(owner, { tenantId, name: 'helpdesk' });
    const role = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Enrollment codes',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['iam:devices:manage'],
            resources: ['iam/devices/enrollments'],
          },
        ],
      },
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: helpdesk.id,
    });
    const key = {
      token: (await f.iam.api.credentials.create(owner, { tenantId, identityId: helpdesk.id }))
        .token,
    };
    const integration = await f.iam.api.devices.createIntegration(owner, {
      tenantId,
      name: 'Intune',
      vendor: 'intune',
    });
    await f.iam.api.devices.report(f.ownerCredential, {
      tenantId,
      integrationId: integration.id,
      devices: [{ externalId: 'kiosk-1', platform: 'windows', posture: { compliant: true } }],
    });
    const [kiosk] = (await f.iam.api.devices.list(f.ownerCredential, { tenantId, managed: true }))
      .devices;
    await expect(
      f.iam.api.devices.createEnrollment(key, {
        tenantId,
        deviceId: kiosk!.id,
        ownerIdentityId: alice.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await f.iam.api.devices.listEnrollments(owner, { tenantId })).length).toBe(0);
    // Codes for new devices are what the grant is for; the owner may still bind the kiosk.
    await expect(f.iam.api.devices.createEnrollment(key, { tenantId })).resolves.toMatchObject({
      code: expect.stringMatching(/^biam_denr_/),
    });
    await expect(
      f.iam.api.devices.createEnrollment(owner, { tenantId, deviceId: kiosk!.id }),
    ).resolves.toBeDefined();
  });

  it('enrols only a key the caller holds, from a recent sign-in', async () => {
    const { f, prover, withDevice, credential, signedIn } = await setup();
    const tenantId = f.tenantId;
    const enroll = (headers: Record<string, string>, publicKey: object) =>
      f.iam.api.devices.enroll(
        { headers },
        { tenantId, name: 'Laptop', platform: 'linux', publicKey: publicKey as never },
      );
    // No proof at all.
    await expect(
      f.iam.api.devices.enroll(credential, {
        tenantId,
        name: 'Laptop',
        platform: 'linux',
        publicKey: await prover.publicJwk(),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Mallory saw Alice's public key and enrols it first, signing with her own key: refused.
    await f.member('mallory');
    const mallory = await f.signIn('mallory');
    const malloryProver = createDeviceProver({ store: memoryKeyStore() });
    await expect(
      enroll(
        {
          authorization: `Bearer ${mallory.token}`,
          ...(await malloryProver.headers(mallory.session.id)),
        },
        await prover.publicJwk(),
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // A proof Alice made for her own session proves nothing for Mallory's.
    await expect(
      enroll(
        {
          authorization: `Bearer ${mallory.token}`,
          ...(await prover.headers(signedIn.session.id)),
        },
        await prover.publicJwk(),
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Alice enrols her key.
    const { device } = await enroll(await withDevice(), await prover.publicJwk());

    // Hours later, her (possibly stolen) session can neither add a key nor retire her device.
    f.advance(6 * hour);
    const thief = createDeviceProver({ store: memoryKeyStore() });
    await expect(
      enroll(
        {
          authorization: `Bearer ${signedIn.token}`,
          ...(await thief.headers(signedIn.session.id)),
        },
        await thief.publicJwk(),
      ),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    await expect(
      f.iam.api.devices.retireMine(credential, { tenantId, deviceId: device.id }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
  });

  it('counts a device as registered only for a session acting in another tenant', async () => {
    const { f, prover, withDevice } = await setup();
    const tenantId = f.tenantId;
    await f.iam.api.devices.enroll(
      { headers: await withDevice() },
      { tenantId, name: 'Laptop', platform: 'macos', publicKey: await prover.publicJwk() },
    );
    const owner = await f.ownerSignIn();
    const integration = await f.iam.api.devices.createIntegration(owner, {
      tenantId,
      name: 'Jamf',
      vendor: 'jamf',
    });
    await f.iam.api.devices.report(f.ownerCredential, {
      tenantId,
      integrationId: integration.id,
      devices: [
        {
          externalId: 'jamf-9',
          platform: 'macos',
          ownerEmail: 'alice@acme.test',
          keyThumbprint: await prover.keyId(),
          posture: { compliant: true },
        },
      ],
    });
    const home = await f.iam.authenticate({ headers: await withDevice() });
    expect((await presentedDevice(f.database, home, f.now()))?.assurance).toBe('compliant');
    // The same identity and proof acting in another tenant, as a cross-tenant role session does: that tenant neither
    // manages the device nor set the requirements it was judged by.
    const elsewhere = { ...home, session: { ...home.session, tenantId: f.root.tenant.id } };
    expect(await presentedDevice(f.database, elsewhere, f.now())).toMatchObject({
      assurance: 'registered',
      compliance: { managed: false, compliant: false },
    });
  });

  it('keeps the presenting device in view when a role session re-decides its assumption', async () => {
    const { f, alice, prover, withDevice } = await setup();
    const tenantId = f.tenantId;
    await f.iam.api.devices.enroll(
      { headers: await withDevice() },
      { tenantId, name: 'Laptop', platform: 'linux', publicKey: await prover.publicJwk() },
    );
    const fromDevices = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId,
      name: 'Assume from registered devices',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['iam:roles:assume'],
            resources: ['*'],
            conditions: { StringEquals: { 'request.deviceAssurance': 'registered' } },
          },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId,
      roleId: fromDevices.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const writer = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId,
      name: 'Writer',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:write'], resources: ['*'] }],
      },
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId,
      sourceTenantId: tenantId,
      sourceIdentityId: alice.id,
      roleId: writer.id,
      requireMfa: false,
    });
    const assumed = await f.iam.api.roles.assume(
      { headers: await withDevice() },
      { tenantId, trustId: trust.id },
    );
    const write = async (headers: Record<string, string>) =>
      (
        await f.iam.authorize({
          headers,
          tenantId,
          action: 'documents:write',
          resource: doc,
        })
      ).allowed;
    expect(
      await write({
        authorization: `Bearer ${assumed.token}`,
        ...(await prover.headers(assumed.session.id)),
      }),
    ).toBe(true);
    // Without the device, the right to the role no longer holds.
    await expect(write({ authorization: `Bearer ${assumed.token}` })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
  });

  it('keeps one browser key per scope in the default store', async () => {
    const fake = fakeIndexedDb();
    const global = globalThis as { indexedDB?: unknown };
    const previous = global.indexedDB;
    global.indexedDB = fake.factory;
    try {
      const first = createDeviceProver({ scope: 'identity-1' });
      const second = createDeviceProver({ scope: 'identity-2' });
      const again = createDeviceProver({ scope: 'identity-1' });
      expect(await first.keyId()).not.toBe(await second.keyId());
      expect(await again.keyId()).toBe(await first.keyId());
      expect(fake.names()).toEqual([
        'better-iam-registered-device:identity-1',
        'better-iam-registered-device:identity-2',
      ]);
      expect(() => createDeviceProver({ scope: 'has a space' })).toThrow(/scope/);
    } finally {
      if (previous === undefined) delete global.indexedDB;
      else global.indexedDB = previous;
    }
  });
});
