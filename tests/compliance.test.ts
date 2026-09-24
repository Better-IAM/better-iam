import { afterEach, describe, expect, it } from 'vitest';
import { verifyEvidencePack } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const day = 86_400_000;
const minute = 60_000;

async function scenario() {
  const f = await organizationFixture();
  const compliance = f.iam.api.compliance;
  return { f, tenantId: f.tenantId, owner: f.ownerCredential, compliance };
}

describe('compliance center', () => {
  it('adopts a framework, evaluates its controls and reports requirement status', async () => {
    const s = await scenario();
    const adopted = await s.compliance.adoptFramework(s.owner, {
      tenantId: s.tenantId,
      framework: 'soc2',
    });
    expect(adopted.controls.map((control) => control.key)).toContain('mfa-coverage');
    // Adopting a second framework reuses the controls and adds its mappings.
    await s.compliance.adoptFramework(s.owner, { tenantId: s.tenantId, framework: 'iso27001' });
    const controls = await s.compliance.listControls(s.owner, { tenantId: s.tenantId });
    const coverage = controls.find((control) => control.key === 'mfa-coverage')!;
    expect(coverage.mappings).toEqual(expect.arrayContaining(['soc2:CC6.1', 'iso27001:8.5']));

    await s.f.member('alice');
    const { run, results } = await s.compliance.evaluate(s.owner, { tenantId: s.tenantId });
    const byKey = new Map(results.map((result) => [result.controlKey, result]));
    // Nobody enrolled a second factor and the policy does not require one.
    expect(byKey.get('mfa-coverage')).toMatchObject({ status: 'fail' });
    expect(byKey.get('mfa-enforced')).toMatchObject({ status: 'fail' });
    expect(byKey.get('audit-integrity')).toMatchObject({ status: 'pass' });
    expect(byKey.get('owner-redundancy')).toMatchObject({ status: 'warn' });
    // Frameworks expect duties to be separated: no rule at all is not a pass.
    expect(byKey.get('separation-of-duties')).toMatchObject({ status: 'warn' });
    expect(byKey.get('access-reviews')).toMatchObject({ status: 'fail' });
    expect(run.counts.fail).toBeGreaterThan(0);
    expect(run.digest).toMatch(/^[0-9a-f]{64}$/);
    // The evaluation returns counts; findings are read separately.
    expect(byKey.get('mfa-coverage')).not.toHaveProperty('findings');

    const [soc2] = await s.compliance.status(s.owner, { tenantId: s.tenantId, framework: 'soc2' });
    expect(soc2!.framework.id).toBe('soc2');
    expect(soc2!.requirements.find((item) => item.id === 'CC7.2')!.status).toBe('pass');
    expect(soc2!.requirements.find((item) => item.id === 'CC6.1')!.status).toBe('fail');
    expect(soc2!.covered).toBe(soc2!.requirements.length);
    await expect(
      s.compliance.status(s.owner, { tenantId: s.tenantId, framework: 'nope' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // Manual evaluations are limited to one a minute per tenant.
    await expect(s.compliance.evaluate(s.owner, { tenantId: s.tenantId })).rejects.toMatchObject({
      code: 'RATE_LIMITED',
    });
    s.f.advance(minute + 1);

    // Requiring MFA fixes the policy control; the next evaluation records the recovery.
    const owner = await s.f.ownerSignIn();
    await s.f.iam.api.tenants.setAuthPolicy(owner, {
      tenantId: s.tenantId,
      authPolicy: { requireMfa: true },
    });
    // Owners without a second factor are now refused; the (MFA) root administrator carries on.
    const second = await s.compliance.evaluate(s.f.rootCredential, {
      tenantId: s.tenantId,
      controlKeys: ['mfa-enforced'],
    });
    expect(second.results).toEqual([
      expect.objectContaining({ controlKey: 'mfa-enforced', status: 'pass' }),
    ]);
    const audit = await s.f.iam.api.audit.list(s.f.rootCredential, { tenantId: s.tenantId });
    const events = JSON.stringify(
      Array.isArray(audit) ? audit : (audit as { events: unknown[] }).events,
    );
    expect(events).toContain('compliance:control:recover');
    // A control failing on its first run is recorded too.
    expect(events).toContain('compliance:control:fail');

    // Disabling a mapped control keeps its requirements from passing; old results turn stale after three days.
    const policy = (
      await s.compliance.listControls(s.f.rootCredential, { tenantId: s.tenantId })
    ).find((control) => control.key === 'audit-integrity')!;
    await s.compliance.updateControl(s.f.rootCredential, {
      tenantId: s.tenantId,
      controlId: policy.id,
      enabled: false,
    });
    const [after] = await s.compliance.status(s.f.rootCredential, {
      tenantId: s.tenantId,
      framework: 'soc2',
    });
    expect(after!.requirements.find((item) => item.id === 'CC7.2')!.status).toBe('disabled');
    s.f.advance(4 * day);
    const [stale] = await s.compliance.status(s.f.rootCredential, {
      tenantId: s.tenantId,
      framework: 'soc2',
    });
    expect(stale!.requirements.find((item) => item.id === 'CC6.1')!.status).toBe('not-evaluated');
  });

  it('needs a second person to approve an exception, which then covers the finding until it expires', async () => {
    const s = await scenario();
    await s.compliance.createControl(s.owner, {
      tenantId: s.tenantId,
      key: 'inactive-90',
      name: 'Inactive accounts',
      checkId: 'inactive-accounts',
      params: { days: 30 },
      mappings: ['internal:POL-7'],
    });
    const alice = await s.f.member('alice');
    s.f.advance(40 * day);
    const owner = await s.f.ownerSignIn();
    const first = await s.compliance.evaluate(owner, { tenantId: s.tenantId });
    expect(first.results[0]!.status).toBe('fail');
    // The owner signed in just now; Alice never did. Stored findings carry IDs; directory readers see names.
    const [result] = await s.compliance.listResults(owner, {
      tenantId: s.tenantId,
      controlKey: 'inactive-90',
    });
    expect(result!.findings).toEqual([
      { subject: `identity:${alice.id}`, detail: 'Has never signed in', name: 'alice@acme.test' },
    ]);
    const exception = await s.compliance.createException(owner, {
      tenantId: s.tenantId,
      controlKey: 'inactive-90',
      subject: `identity:${alice.id}`,
      reason: 'On parental leave until December',
      expiresAt: s.f.now() + 10 * day,
    });
    expect(exception.status).toBe('pending');
    // Pending exceptions cover nothing, and their author cannot approve them.
    s.f.advance(minute + 1);
    const pending = await s.f.ownerSignIn();
    expect(
      (await s.compliance.evaluate(pending, { tenantId: s.tenantId })).results[0]!.status,
    ).toBe('fail');
    await expect(
      s.compliance.approveException(pending, { tenantId: s.tenantId, exceptionId: exception.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // The root session from the fixture's start has expired by now.
    const root = await s.f.rootSignIn();
    await s.compliance.approveException(root, { tenantId: s.tenantId, exceptionId: exception.id });
    s.f.advance(minute + 1);
    const excepted = await s.compliance.evaluate(root, { tenantId: s.tenantId });
    expect(excepted.results[0]).toMatchObject({ status: 'pass', rawStatus: 'fail', excepted: 1 });
    s.f.advance(11 * day);
    const later = await s.f.ownerSignIn();
    expect((await s.compliance.evaluate(later, { tenantId: s.tenantId })).results[0]!.status).toBe(
      'fail',
    );
    // Revoking keeps the record as history.
    await s.compliance.revokeException(later, { tenantId: s.tenantId, exceptionId: exception.id });
    expect(await s.compliance.listExceptions(later, { tenantId: s.tenantId })).toEqual([
      expect.objectContaining({ id: exception.id, status: 'revoked', active: false }),
    ]);
    // Nobody excepts their own finding, and audit-chain breaks are never excepted.
    const ownerId = (await s.f.iam.api.auth.getSession(later)).identity.id;
    await expect(
      s.compliance.createException(later, {
        tenantId: s.tenantId,
        controlKey: 'inactive-90',
        subject: `identity:${ownerId}`,
        reason: 'Me',
        expiresAt: s.f.now() + day,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await s.compliance.createControl(later, {
      tenantId: s.tenantId,
      key: 'audit',
      name: 'Audit',
      checkId: 'audit-integrity',
    });
    await expect(
      s.compliance.createException(later, {
        tenantId: s.tenantId,
        controlKey: 'audit',
        subject: `tenant:${s.tenantId}:audit-chain`,
        reason: 'Known',
        expiresAt: s.f.now() + day,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      s.compliance.createControl(later, {
        tenantId: s.tenantId,
        key: 'bad',
        name: 'Bad',
        checkId: 'inactive-accounts',
        params: { days: 1 },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('counts every path to full administration', async () => {
    const s = await scenario();
    await s.compliance.createControl(s.owner, {
      tenantId: s.tenantId,
      key: 'admins',
      name: 'Admins',
      checkId: 'privileged-access',
      params: { maxHolders: 1 },
    });
    const roles = s.f.iam.api.roles;
    // Full access to the iam service on iam/* (not the literal `*`), behind an MFA condition, inherited by "Ops".
    const admin = await roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Admin',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['iam:*'],
            resources: ['iam/*'],
            conditions: { Bool: { 'principal.mfa': true } },
          },
        ],
      },
    });
    const ops = await roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Ops',
      permissions: ['iam:audit:read'],
      inherits: [admin.id],
    });
    const reader = await roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Reader',
      permissions: ['iam:identities:read'],
    });
    const alice = await s.f.member('alice');
    const bob = await s.f.member('bob');
    const carol = await s.f.member('carol');
    const dave = await s.f.member('dave');
    const bindings = s.f.iam.api.bindings;
    await bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: ops.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    await bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: admin.id,
      subjectType: 'identity',
      subjectId: bob.id,
      eligible: true,
    });
    await bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: admin.id,
      subjectType: 'identity',
      subjectId: carol.id,
      eligible: true,
      requireApproval: true,
    });
    await bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: dave.id,
    });
    await s.compliance.evaluate(s.owner, { tenantId: s.tenantId });
    const [result] = await s.compliance.listResults(s.owner, {
      tenantId: s.tenantId,
      controlKey: 'admins',
    });
    const subjects = result!.findings.map((finding) => finding.subject);
    // The owner, Alice (through the inherited role) and Bob (eligible without approval); not Carol or Dave.
    expect(subjects).toEqual(
      expect.arrayContaining([`identity:${alice.id}`, `identity:${bob.id}`]),
    );
    expect(subjects).not.toContain(`identity:${carol.id}`);
    expect(subjects).not.toContain(`identity:${dave.id}`);
    expect(result!.metrics).toMatchObject({ holders: 3, eligibleWithApproval: 1 });
    expect(result!.status).toBe('fail');
  });

  it('does not count reviews nobody decided', async () => {
    const s = await scenario();
    await s.compliance.createControl(s.owner, {
      tenantId: s.tenantId,
      key: 'reviews',
      name: 'Reviews',
      checkId: 'access-reviews',
    });
    const reader = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Reader',
      permissions: ['iam:identities:read'],
    });
    const alice = await s.f.member('alice');
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const campaign = await s.f.iam.api.certifications.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Q3',
    });
    await s.f.iam.api.certifications.close(s.owner, {
      tenantId: s.tenantId,
      campaignId: campaign.id,
    });
    await s.compliance.evaluate(s.owner, { tenantId: s.tenantId });
    const [result] = await s.compliance.listResults(s.owner, {
      tenantId: s.tenantId,
      controlKey: 'reviews',
    });
    expect(result).toMatchObject({
      status: 'fail',
      metrics: expect.objectContaining({ qualifying: 0, lastDecidedPercent: 0 }),
    });
    expect(result!.findings[0]!.subject).toBe(`tenant:${s.tenantId}:no-review`);
  });

  it('exports signed evidence that auditors verify offline and that detects edits', async () => {
    const s = await scenario();
    await s.compliance.adoptFramework(s.owner, { tenantId: s.tenantId, framework: 'nist-800-53' });
    await s.compliance.evaluate(s.owner, { tenantId: s.tenantId });
    const pack = await s.compliance.exportEvidence(s.owner, {
      tenantId: s.tenantId,
      framework: 'nist-800-53',
    });
    expect(pack.framework).toEqual({ id: 'nist-800-53', name: 'NIST SP 800-53 Rev. 5' });
    expect(pack.controls.every((control) => control.result)).toBe(true);
    expect(pack.auditHead?.sequence).toBeGreaterThan(0);
    expect(await s.compliance.verifyEvidence(s.owner, { tenantId: s.tenantId, pack })).toEqual({
      valid: true,
    });
    // Large packs: the digest and signature alone.
    expect(
      await s.compliance.verifyEvidence(s.owner, {
        tenantId: s.tenantId,
        digest: pack.digest,
        signature: pack.signature,
      }),
    ).toEqual({ valid: true });
    const keys = await s.compliance.evidenceKeys(s.owner, { tenantId: s.tenantId });
    expect(verifyEvidencePack(pack, keys)).toMatchObject({ valid: true, kid: pack.signature.kid });
    const edited = structuredClone(pack);
    edited.controls[0]!.result!.summary = 'Edited after export';
    expect(
      await s.compliance.verifyEvidence(s.owner, { tenantId: s.tenantId, pack: edited }),
    ).toEqual({ valid: false });
    expect(verifyEvidencePack(edited, keys)).toMatchObject({
      valid: false,
      reason: 'digest mismatch',
    });
    // The export is anchored in the audit chain with its digest.
    const audit = await s.f.iam.api.audit.list(s.owner, { tenantId: s.tenantId });
    expect(JSON.stringify(audit)).toContain(pack.digest);
  });

  it('verifies the audit chain incrementally from a checkpoint', async () => {
    const s = await scenario();
    await s.compliance.createControl(s.owner, {
      tenantId: s.tenantId,
      key: 'audit',
      name: 'Audit',
      checkId: 'audit-integrity',
    });
    await s.compliance.evaluate(s.owner, { tenantId: s.tenantId });
    const [first] = await s.compliance.listResults(s.owner, {
      tenantId: s.tenantId,
      controlKey: 'audit',
    });
    expect(first!.status).toBe('pass');
    const verified = first!.metrics.verifiedThrough!;
    await s.f.member('erin');
    s.f.advance(minute + 1);
    await s.compliance.evaluate(s.owner, { tenantId: s.tenantId });
    const [second] = await s.compliance.listResults(s.owner, {
      tenantId: s.tenantId,
      controlKey: 'audit',
    });
    expect(second!.status).toBe('pass');
    // Only the events since the checkpoint were read.
    expect(second!.metrics.checked).toBe(second!.metrics.verifiedThrough! - verified);
    // Tampering after the checkpoint is found.
    await s.f.database.transaction(async (tx) => {
      const events = await tx.find<
        { id: string; sequence?: number; action: string } & { tenantId: string }
      >('audit', { tenantId: s.tenantId });
      const target = events.find(
        (event) => (event.sequence ?? 0) > second!.metrics.verifiedThrough!,
      )!;
      await tx.put('audit', { ...target, action: 'edited' });
    });
    s.f.advance(minute + 1);
    await s.compliance.evaluate(s.owner, { tenantId: s.tenantId });
    const [third] = await s.compliance.listResults(s.owner, {
      tenantId: s.tenantId,
      controlKey: 'audit',
    });
    expect(third!.status).toBe('fail');
  });

  it('evaluates every tenant with controls from the scheduler job, and needs permissions', async () => {
    const s = await scenario();
    await s.compliance.adoptFramework(s.owner, { tenantId: s.tenantId, framework: 'gdpr' });
    const job = await s.f.iam.compliance.evaluateAll();
    expect(job.evaluated.map((item) => item.tenantId)).toEqual([s.tenantId]);
    expect(job.failed).toEqual([]);
    await s.f.member('bob');
    const bob = { token: (await s.f.signIn('bob')).token };
    await expect(s.compliance.evaluate(bob, { tenantId: s.tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(s.compliance.listControls(bob, { tenantId: s.tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
  });
});
