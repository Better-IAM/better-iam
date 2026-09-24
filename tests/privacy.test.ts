import { afterEach, describe, expect, it } from 'vitest';
import type { Identity } from '@better-iam/core';
import { renderDeliveryMessage } from '@better-iam/auth';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const day = 86_400_000;
const doc = { type: 'document', id: 'd1' };

async function scenario() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const privacy = f.iam.api.privacy;
  const marketing = await privacy.createPurpose(owner, {
    tenantId,
    key: 'marketing-email',
    name: 'Marketing email',
    description: 'Product news and offers by email.',
    legalBasis: 'consent',
    dataCategories: ['contact'],
  });
  const analytics = await privacy.createPurpose(owner, {
    tenantId,
    key: 'product-analytics',
    name: 'Product analytics',
    description: 'How features are used, to improve them.',
    legalBasis: 'legitimate-interests',
    dataCategories: ['usage'],
  });
  const sale = await privacy.createPurpose(owner, {
    tenantId,
    key: 'data-sharing',
    name: 'Sharing with partners',
    description: 'Sharing contact data with advertising partners.',
    legalBasis: 'consent',
    mode: 'opt-out',
  });
  const billing = await privacy.createPurpose(owner, {
    tenantId,
    key: 'billing',
    name: 'Billing',
    description: 'Invoices and payments for your plan.',
    legalBasis: 'contract',
  });
  const alice = await f.member('alice');
  const aliceToken = { token: (await f.signIn('alice')).token };
  return { f, tenantId, owner, privacy, marketing, analytics, sale, billing, alice, aliceToken };
}

describe('privacy purposes and consent', () => {
  it('validates purposes and refuses duplicate keys', async () => {
    const s = await scenario();
    await expect(
      s.privacy.createPurpose(s.owner, {
        tenantId: s.tenantId,
        key: 'marketing-email',
        name: 'Again',
        description: 'x',
        legalBasis: 'consent',
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      s.privacy.createPurpose(s.owner, {
        tenantId: s.tenantId,
        key: 'Bad Key',
        name: 'Bad',
        description: 'x',
        legalBasis: 'consent',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      s.privacy.createPurpose(s.owner, {
        tenantId: s.tenantId,
        key: 'fraud',
        name: 'Fraud',
        description: 'x',
        legalBasis: 'legal-obligation',
        mode: 'opt-out',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Changing the legal basis is material and needs a new version.
    await expect(
      s.privacy.updatePurpose(s.owner, {
        tenantId: s.tenantId,
        purposeId: s.analytics.id,
        legalBasis: 'consent',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // A member without permissions cannot manage purposes.
    await expect(
      s.privacy.listPurposes(s.aliceToken, { tenantId: s.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('lets people decide, with receipts, versions and the effect of each basis', async () => {
    const s = await scenario();
    const mine = await s.privacy.mine(s.aliceToken, { tenantId: s.tenantId });
    const state = (key: string) => mine.purposes.find((purpose) => purpose.key === key)!.state;
    expect(state('marketing-email')).toEqual({ allowed: false, reason: 'NO_CONSENT' });
    expect(state('product-analytics')).toEqual({ allowed: true, reason: 'LEGITIMATE_INTERESTS' });
    expect(state('data-sharing')).toEqual({ allowed: true, reason: 'NOT_OPTED_OUT' });
    expect(state('billing')).toEqual({ allowed: true, reason: 'LEGAL_BASIS' });
    expect(mine.purposes.find((purpose) => purpose.key === 'billing')!.decidable).toBe(false);

    const receipt = await s.privacy.decide(s.aliceToken, {
      tenantId: s.tenantId,
      purposeKey: 'marketing-email',
      version: 1,
      granted: true,
      evidence: 'Signup form v3',
    });
    expect(receipt).toMatchObject({
      tenantId: s.tenantId,
      subject: `identity:${s.alice.id}`,
      granted: true,
      purpose: { key: 'marketing-email', version: 1, legalBasis: 'consent' },
      source: 'self',
    });
    const check = () =>
      s.privacy.check(s.owner, {
        tenantId: s.tenantId,
        subject: { identityId: s.alice.id },
        purposeKey: 'marketing-email',
      });
    expect(await check()).toMatchObject({ allowed: true, reason: 'CONSENT_GIVEN' });
    // Opting out and objecting.
    await s.privacy.decide(s.aliceToken, {
      tenantId: s.tenantId,
      purposeKey: 'data-sharing',
      version: 1,
      granted: false,
    });
    await s.privacy.decide(s.aliceToken, {
      tenantId: s.tenantId,
      purposeKey: 'product-analytics',
      version: 1,
      granted: false,
    });
    const after = await s.privacy.mine(s.aliceToken, { tenantId: s.tenantId });
    const next = (key: string) => after.purposes.find((purpose) => purpose.key === key)!.state;
    expect(next('data-sharing').reason).toBe('CONSENT_WITHDRAWN');
    expect(next('product-analytics').reason).toBe('OBJECTED');
    // Contract purposes are not a matter of consent.
    await expect(
      s.privacy.decide(s.aliceToken, {
        tenantId: s.tenantId,
        purposeKey: 'billing',
        version: 1,
        granted: false,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // A new version asks again: the old grant no longer counts, and deciding on the old text is refused.
    await s.privacy.updatePurpose(s.owner, {
      tenantId: s.tenantId,
      purposeId: s.marketing.id,
      description: 'Product news, offers and partner offers by email.',
      newVersion: true,
    });
    expect(await check()).toMatchObject({ allowed: false, reason: 'CONSENT_OUTDATED' });
    await expect(
      s.privacy.decide(s.aliceToken, {
        tenantId: s.tenantId,
        purposeKey: 'marketing-email',
        version: 1,
        granted: true,
      }),
    ).rejects.toMatchObject({ code: 'VERSION_CONFLICT' });

    // The receipt verifies; a tampered copy does not; a later decision makes it historical.
    expect(
      await s.privacy.verifyReceipt(s.owner, { tenantId: s.tenantId, receipt }),
    ).toEqual({ valid: true, current: true });
    expect(
      await s.privacy.verifyReceipt(s.owner, {
        tenantId: s.tenantId,
        receipt: { ...receipt, granted: false },
      }),
    ).toMatchObject({ valid: false, reason: 'SIGNATURE_INVALID' });
    await s.privacy.decide(s.aliceToken, {
      tenantId: s.tenantId,
      purposeKey: 'marketing-email',
      version: 2,
      granted: true,
    });
    expect(
      await s.privacy.verifyReceipt(s.owner, { tenantId: s.tenantId, receipt }),
    ).toEqual({ valid: true, current: false });
    expect(
      await s.privacy.myReceipt(s.aliceToken, { tenantId: s.tenantId, receiptId: receipt.receiptId }),
    ).toEqual(receipt);
    const history = await s.privacy.myHistory(s.aliceToken, {
      tenantId: s.tenantId,
      purposeKey: 'marketing-email',
    });
    expect(history.map((entry) => entry.purposeVersion)).toEqual([2, 1]);
    expect(history[1]!.evidence).toBe('Signup form v3');
  });

  it('lets grants lapse after the consent lifetime', async () => {
    const s = await scenario();
    const cookies = await s.privacy.createPurpose(s.owner, {
      tenantId: s.tenantId,
      key: 'cookies.ads',
      name: 'Advertising cookies',
      description: 'Cookies that measure ads.',
      legalBasis: 'consent',
      consentLifetimeDays: 30,
    });
    await s.privacy.decide(s.aliceToken, {
      tenantId: s.tenantId,
      purposeKey: cookies.key,
      version: 1,
      granted: true,
    });
    const check = () =>
      s.privacy.check(s.owner, {
        tenantId: s.tenantId,
        subject: { identityId: s.alice.id },
        purposeKey: cookies.key,
      });
    expect((await check()).allowed).toBe(true);
    s.f.advance(31 * day);
    const owner = await s.f.ownerSignIn();
    expect(
      await s.privacy.check(owner, {
        tenantId: s.tenantId,
        subject: { identityId: s.alice.id },
        purposeKey: cookies.key,
      }),
    ).toMatchObject({ allowed: false, reason: 'CONSENT_EXPIRED' });
  });

  it('exposes principal.consents to policies', async () => {
    const s = await scenario();
    const role = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Newsletter reader',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['*'],
            conditions: { ArrayContains: { 'principal.consents': ['marketing-email'] } },
          },
        ],
      },
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: s.alice.id,
    });
    const canRead = async () =>
      (
        await s.f.iam.authorize({
          ...s.aliceToken,
          tenantId: s.tenantId,
          action: 'documents:read',
          resource: doc,
        })
      ).allowed;
    expect(await canRead()).toBe(false);
    await s.privacy.decide(s.aliceToken, {
      tenantId: s.tenantId,
      purposeKey: 'marketing-email',
      version: 1,
      granted: true,
    });
    expect(await canRead()).toBe(true);
    await s.privacy.decide(s.aliceToken, {
      tenantId: s.tenantId,
      purposeKey: 'marketing-email',
      version: 1,
      granted: false,
    });
    expect(await canRead()).toBe(false);
  });

  it('records, imports, checks and lists decisions for application subjects', async () => {
    const s = await scenario();
    const recorded = await s.privacy.record(s.owner, {
      tenantId: s.tenantId,
      subject: { externalId: 'cus_100' },
      purposeKey: 'marketing-email',
      granted: true,
      method: 'banner',
      ip: '203.0.113.9',
    });
    expect(recorded).toMatchObject({ subject: 'external:cus_100', granted: true, current: true });
    // An older imported decision is kept in the history but does not replace the newer one.
    const imported = await s.privacy.importDecisions(s.owner, {
      tenantId: s.tenantId,
      decisions: [
        {
          subject: { externalId: 'cus_100' },
          purposeKey: 'marketing-email',
          granted: false,
          version: 1,
          recordedAt: s.f.now() - 10 * day,
        },
        {
          subject: { externalId: 'cus_200' },
          purposeKey: 'marketing-email',
          granted: false,
          version: 1,
          recordedAt: s.f.now() - day,
        },
      ],
    });
    expect(imported).toEqual({ imported: 2, current: 1 });
    const filtered = await s.privacy.filterSubjects(s.owner, {
      tenantId: s.tenantId,
      purposeKey: 'marketing-email',
      subjects: [
        { externalId: 'cus_100' },
        { externalId: 'cus_200' },
        { externalId: 'cus_300' },
        { identityId: 'missing' },
      ],
    });
    expect(filtered.allowed).toEqual([{ externalId: 'cus_100' }]);
    expect(filtered.refused.map((item) => item.reason)).toEqual([
      'CONSENT_WITHDRAWN',
      'NO_CONSENT',
      'UNKNOWN_SUBJECT',
    ]);
    // The opt-out purpose's audience is every active person (owner and alice) until they opt out.
    const audience = await s.privacy.audience(s.owner, {
      tenantId: s.tenantId,
      purposeKey: 'data-sharing',
    });
    expect(audience.total).toBe(2);
    const consents = await s.privacy.listConsents(s.owner, {
      tenantId: s.tenantId,
      purposeKey: 'marketing-email',
    });
    expect(consents.total).toBe(2);
    const history = await s.privacy.history(s.owner, {
      tenantId: s.tenantId,
      subject: { externalId: 'cus_100' },
    });
    expect(history).toHaveLength(2);
    expect(history[0]).toMatchObject({ granted: true, ip: '203.0.113.9', method: 'banner' });
    // The deployment's own code can check without a credential.
    expect(
      await s.f.iam.privacy.check({
        tenantId: s.tenantId,
        subject: { externalId: 'cus_100' },
        purposeKey: 'marketing-email',
      }),
    ).toMatchObject({ allowed: true });
    const summary = await s.privacy.summary(s.owner, { tenantId: s.tenantId });
    expect(summary.purposes.find((purpose) => purpose.key === 'marketing-email')).toMatchObject({
      granted: 1,
      withdrawn: 1,
    });
  });
});

describe('data-subject requests', () => {
  it('answers an access request with an export only the subject (or a handler) downloads', async () => {
    const s = await scenario();
    await s.privacy.decide(s.aliceToken, {
      tenantId: s.tenantId,
      purposeKey: 'marketing-email',
      version: 1,
      granted: true,
    });
    await s.privacy.updateSettings(s.owner, {
      tenantId: s.tenantId,
      contactEmail: 'dpo@acme.test',
      responseDays: { gdpr: 20 },
    });
    const request = await s.privacy.submitRequest(s.aliceToken, {
      tenantId: s.tenantId,
      type: 'access',
    });
    expect(request).toMatchObject({
      status: 'open',
      regulation: 'gdpr',
      verification: { status: 'verified', method: 'authenticated-session' },
    });
    expect(request.dueAt! - request.receivedAt!).toBe(20 * day);
    await expect(
      s.privacy.submitRequest(s.aliceToken, { tenantId: s.tenantId, type: 'access' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await s.f.iam.auth.dispatchOutbox();
    expect(
      s.f.inbox.some(
        (message) => message.to === 'dpo@acme.test' && message.template === 'privacy-request-received',
      ),
    ).toBe(true);

    const done = await s.privacy.fulfilRequest(s.owner, {
      tenantId: s.tenantId,
      requestId: request.id,
    });
    expect(done).toMatchObject({ status: 'completed', actions: ['export:full'] });
    const download = await s.privacy.downloadExport(s.aliceToken, {
      tenantId: s.tenantId,
      requestId: request.id,
    });
    const data = download.data as Record<string, any>;
    expect(data.profile.email).toBe('alice@acme.test');
    expect(data.consents).toEqual([
      expect.objectContaining({ purpose: 'marketing-email', granted: true }),
    ]);
    expect(data.profile.passwordHash).toBeUndefined();
    // Another member cannot download it.
    await s.f.member('bob');
    const bob = { token: (await s.f.signIn('bob')).token };
    await expect(
      s.privacy.downloadExport(bob, { tenantId: s.tenantId, requestId: request.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // The subject hears back; staff notes stay internal.
    await s.f.iam.auth.dispatchOutbox();
    const update = s.f.inbox.find(
      (message) => message.to === 'alice@acme.test' && message.template === 'privacy-request-update',
    );
    expect(update?.payload).toMatchObject({ event: 'completed', exportReady: 'true' });
  });

  it('erases a person after the legal hold is released, and says so to downstream systems', async () => {
    const s = await scenario();
    await s.privacy.decide(s.aliceToken, {
      tenantId: s.tenantId,
      purposeKey: 'marketing-email',
      version: 1,
      granted: true,
      evidence: 'Signed up at the conference booth',
    });
    const hold = await s.privacy.placeHold(s.owner, {
      tenantId: s.tenantId,
      subject: { identityId: s.alice.id },
      reason: 'Litigation 2026-17',
    });
    // No path deletes a held person.
    const owner = await s.f.ownerSignIn();
    await expect(
      s.f.iam.api.identities.delete(owner, { tenantId: s.tenantId, identityId: s.alice.id }),
    ).rejects.toMatchObject({ code: 'LEGAL_HOLD' });
    const request = await s.privacy.submitRequest(s.aliceToken, {
      tenantId: s.tenantId,
      type: 'erasure',
      details: 'Please delete my account.',
    });
    await expect(
      s.privacy.fulfilRequest(owner, { tenantId: s.tenantId, requestId: request.id }),
    ).rejects.toMatchObject({ code: 'LEGAL_HOLD' });
    await s.privacy.releaseHold(owner, { tenantId: s.tenantId, holdId: hold.id });
    const done = await s.privacy.fulfilRequest(owner, {
      tenantId: s.tenantId,
      requestId: request.id,
    });
    expect(done.status).toBe('completed');
    expect(done.actions).toEqual(
      // Deleting the account already removed the current decision; erasure redacts its history.
      expect.arrayContaining(['account-deleted', 'account-details-erased', 'history-redacted:1']),
    );
    expect(done.details).toBeUndefined();
    expect(done.redacted).toBe(true);
    const tombstone = await s.f.database.transaction((tx) =>
      tx.get<Identity>('identities', s.alice.id),
    );
    expect(tombstone).toMatchObject({ status: 'deleted', name: 'Erased person' });
    expect(tombstone!.deletedEmail).toBeUndefined();
    const history = await s.privacy.history(owner, {
      tenantId: s.tenantId,
      subject: { identityId: s.alice.id },
    });
    expect(history).toHaveLength(1);
    expect(history[0]).toMatchObject({ redacted: true });
    expect(history[0]!.evidence).toBeUndefined();
    const audit = await s.f.iam.api.audit.list(owner, { tenantId: s.tenantId });
    const events = Array.isArray(audit) ? audit : (audit as { events: unknown[] }).events;
    expect(JSON.stringify(events)).toContain('privacy:erasure');
    // The person heard back at their old address before it was erased.
    await s.f.iam.auth.dispatchOutbox();
    expect(
      s.f.inbox.some(
        (message) =>
          message.to === 'alice@acme.test' &&
          message.template === 'privacy-request-update' &&
          message.payload.type === 'erasure',
      ),
    ).toBe(true);
  });

  it('restricts processing, withdraws on objection, and extends by the regulation', async () => {
    const s = await scenario();
    await s.privacy.decide(s.aliceToken, {
      tenantId: s.tenantId,
      purposeKey: 'marketing-email',
      version: 1,
      granted: true,
    });
    const restriction = await s.privacy.submitRequest(s.aliceToken, {
      tenantId: s.tenantId,
      type: 'restriction',
    });
    await s.privacy.fulfilRequest(s.owner, { tenantId: s.tenantId, requestId: restriction.id });
    const check = (purposeKey: string) =>
      s.privacy.check(s.owner, {
        tenantId: s.tenantId,
        subject: { identityId: s.alice.id },
        purposeKey,
      });
    expect(await check('marketing-email')).toMatchObject({ allowed: false, reason: 'RESTRICTED' });
    expect(await check('billing')).toMatchObject({ allowed: false, reason: 'RESTRICTED' });
    await s.privacy.liftRestriction(s.owner, {
      tenantId: s.tenantId,
      subject: { identityId: s.alice.id },
    });
    expect((await check('marketing-email')).allowed).toBe(true);

    const objection = await s.privacy.submitRequest(s.aliceToken, {
      tenantId: s.tenantId,
      type: 'objection',
      regulation: 'lgpd',
    });
    // LGPD allows no extension; GDPR adds two months once.
    await expect(
      s.privacy.extendRequest(s.owner, {
        tenantId: s.tenantId,
        requestId: objection.id,
        reason: 'Complex',
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const done = await s.privacy.fulfilRequest(s.owner, {
      tenantId: s.tenantId,
      requestId: objection.id,
    });
    expect(done.actions).toEqual(['consents-withdrawn:3']);
    expect(await check('marketing-email')).toMatchObject({ reason: 'CONSENT_WITHDRAWN' });
    expect(await check('product-analytics')).toMatchObject({ reason: 'OBJECTED' });
    expect(await check('billing')).toMatchObject({ allowed: true });

    const access = await s.privacy.submitRequest(s.aliceToken, {
      tenantId: s.tenantId,
      type: 'portability',
    });
    const extended = await s.privacy.extendRequest(s.owner, {
      tenantId: s.tenantId,
      requestId: access.id,
      reason: 'Data spread over several systems',
    });
    expect(extended.dueAt! - access.dueAt!).toBe(60 * day);
    await expect(
      s.privacy.extendRequest(s.owner, {
        tenantId: s.tenantId,
        requestId: access.id,
        reason: 'Again',
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    // Rectification needs a note saying what changed.
    const fix = await s.privacy.submitRequest(s.aliceToken, {
      tenantId: s.tenantId,
      type: 'rectification',
      details: 'My name is spelled wrong.',
    });
    await s.privacy.addNote(s.owner, { tenantId: s.tenantId, requestId: fix.id, note: 'internal' });
    await expect(
      s.privacy.fulfilRequest(s.owner, { tenantId: s.tenantId, requestId: fix.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const mine = await s.privacy.mine(s.aliceToken, { tenantId: s.tenantId });
    const view = mine.requests.find((request) => request.id === fix.id)!;
    expect(view.events.some((event) => event.what === 'note')).toBe(false);
  });

  it('takes public requests only when enabled, confirmed by email, and lapses unconfirmed ones', async () => {
    const s = await scenario();
    await expect(
      s.privacy.submitPublic({ tenantId: s.tenantId, type: 'access', email: 'alice@acme.test' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await s.privacy.updateSettings(s.owner, {
      tenantId: s.tenantId,
      publicIntake: true,
      contactEmail: 'dpo@acme.test',
    });
    // Alice's address is verified, so a confirmed public request links to her account.
    await s.f.database.transaction(async (tx) => {
      const alice = await tx.get<Identity>('identities', s.alice.id);
      await tx.put('identities', { ...alice!, emailVerified: true });
    });
    const submitted = await s.privacy.submitPublic({
      tenantId: s.tenantId,
      type: 'access',
      email: 'Alice@Acme.test',
      name: 'Alice',
    });
    expect(submitted.status).toBe('pending-verification');
    await s.f.iam.auth.dispatchOutbox();
    const verify = s.f.inbox.find((message) => message.template === 'privacy-request-verify')!;
    expect(verify.to).toBe('alice@acme.test');
    await expect(
      s.privacy.confirmPublic({
        tenantId: s.tenantId,
        requestId: verify.payload.requestId!,
        token: 'wrong',
      }),
    ).rejects.toMatchObject({ code: 'CONFIRMATION_INVALID' });
    const confirmed = await s.privacy.confirmPublic({
      tenantId: s.tenantId,
      requestId: verify.payload.requestId!,
      token: verify.payload.token!,
    });
    expect(confirmed.status).toBe('open');
    const listed = await s.privacy.getRequest(s.owner, {
      tenantId: s.tenantId,
      requestId: verify.payload.requestId!,
    });
    expect(listed).toMatchObject({
      identityId: s.alice.id,
      subject: `identity:${s.alice.id}`,
      channel: 'public',
      verification: { status: 'verified', method: 'email-link' },
    });
    // The token is single-use.
    await expect(
      s.privacy.confirmPublic({
        tenantId: s.tenantId,
        requestId: verify.payload.requestId!,
        token: verify.payload.token!,
      }),
    ).rejects.toMatchObject({ code: 'CONFIRMATION_INVALID' });

    // An unconfirmed request lapses after seven days.
    await s.privacy.submitPublic({
      tenantId: s.tenantId,
      type: 'opt-out',
      email: 'stranger@example.test',
    });
    s.f.advance(8 * day);
    const run = await s.f.iam.privacy.sendDeadlineReminders({ tenantId: s.tenantId });
    expect(run.lapsed).toBe(1);
    const owner = await s.f.ownerSignIn();
    const cancelled = await s.privacy.listRequests(owner, {
      tenantId: s.tenantId,
      status: 'cancelled',
    });
    expect(cancelled.total).toBe(1);
  });

  it('reminds handlers once before the deadline and once when overdue', async () => {
    const s = await scenario();
    await s.privacy.updateSettings(s.owner, { tenantId: s.tenantId, contactEmail: 'dpo@acme.test' });
    const request = await s.privacy.submitRequest(s.aliceToken, {
      tenantId: s.tenantId,
      type: 'access',
    });
    const job = () => s.f.iam.privacy.sendDeadlineReminders({ tenantId: s.tenantId });
    expect((await job()).reminded).toEqual([]);
    s.f.advance(24 * day);
    expect((await job()).reminded).toEqual([
      { tenantId: s.tenantId, requestId: request.id, kind: 'due-soon' },
    ]);
    expect((await job()).reminded).toEqual([]);
    s.f.advance(7 * day);
    expect((await job()).reminded).toEqual([
      { tenantId: s.tenantId, requestId: request.id, kind: 'overdue' },
    ]);
    const owner = await s.f.ownerSignIn();
    const overdue = await s.privacy.listRequests(owner, { tenantId: s.tenantId, overdue: true });
    expect(overdue.requests.map((item) => item.id)).toEqual([request.id]);
    const summary = await s.privacy.summary(owner, { tenantId: s.tenantId });
    expect(summary.requests).toMatchObject({ open: 1, overdue: 1 });
    await s.f.iam.auth.dispatchOutbox();
    expect(
      s.f.inbox.filter((message) => message.template === 'privacy-request-due').map(
        (message) => message.payload.overdue,
      ),
    ).toEqual(['false', 'true']);
  });
});

describe('privacy emails', () => {
  const links = {
    privacy: (input: { tenantId: string; requestId?: string; token?: string; handler?: boolean }) =>
      `https://app.test/privacy/${input.handler ? 'handle' : input.token ? 'confirm' : 'mine'}?r=${input.requestId ?? ''}${input.token ? `&t=${input.token}` : ''}`,
  };
  const base = { tenantId: 't1', to: 'someone@example.test' };
  it('renders the confirmation, intake, update and deadline messages', () => {
    const verify = renderDeliveryMessage(
      {
        ...base,
        template: 'privacy-request-verify',
        payload: { tenantName: 'Acme', requestId: 'r1', number: 'DSR-1', type: 'erasure', token: 'tok' },
      },
      { links },
    )!;
    expect(verify.subject).toBe('Confirm your privacy request to Acme');
    expect(verify.text).toContain('https://app.test/privacy/confirm?r=r1&t=tok');
    // Without a link builder the code and request ID are shown instead.
    const bare = renderDeliveryMessage({
      ...base,
      template: 'privacy-request-verify',
      payload: { requestId: 'r1', number: 'DSR-1', type: 'access', token: 'tok' },
    })!;
    expect(bare.text).toContain('Request ID: r1');
    expect(bare.text).toContain('Code: tok');
    const received = renderDeliveryMessage(
      {
        ...base,
        template: 'privacy-request-received',
        payload: { tenantName: 'Acme', requestId: 'r1', number: 'DSR-1', type: 'access', regulation: 'gdpr', dueAt: '0' },
      },
      { links },
    )!;
    expect(received.subject).toBe('New privacy request DSR-1: a copy of personal data');
    expect(received.text).toContain('GDPR');
    expect(received.text).toContain('/privacy/handle?r=r1');
    const rejected = renderDeliveryMessage({
      ...base,
      template: 'privacy-request-update',
      payload: { number: 'DSR-1', type: 'access', event: 'rejected', reason: 'excessive' },
    })!;
    expect(rejected.subject).toBe('Your privacy request DSR-1 was declined');
    expect(rejected.text).toContain('excessive or repetitive');
    const erased = renderDeliveryMessage({
      ...base,
      template: 'privacy-request-update',
      payload: { number: 'DSR-2', type: 'erasure', event: 'completed' },
    })!;
    expect(erased.text).toContain('this is the last message about it');
    expect(erased.html).not.toContain('<a href');
    const overdue = renderDeliveryMessage({
      ...base,
      template: 'privacy-request-due',
      payload: { number: 'DSR-3', type: 'opt-out', overdue: 'true', dueAt: '0' },
    })!;
    expect(overdue.subject).toBe('Privacy request DSR-3 is overdue');
  });
});

describe('privacy review fixes', () => {
  /** Bob handles privacy requests but may not read the directory or the audit log. */
  async function handler(s: Awaited<ReturnType<typeof scenario>>) {
    const bob = await s.f.member('bob');
    const role = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Privacy handler',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['iam:privacy:read', 'iam:privacy:handle'],
            resources: ['*'],
          },
        ],
      },
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    return { bob, token: { token: (await s.f.signIn('bob')).token } };
  }

  it('keeps public requests naming an application identifier unverified after the email is confirmed', async () => {
    const s = await scenario();
    await s.privacy.updateSettings(s.owner, { tenantId: s.tenantId, publicIntake: true });
    await s.privacy.submitPublic({
      tenantId: s.tenantId,
      type: 'erasure',
      email: 'attacker@example.test',
      externalId: 'cus_42',
    });
    await s.f.iam.auth.dispatchOutbox();
    const verify = s.f.inbox.find((message) => message.template === 'privacy-request-verify')!;
    const confirmed = await s.privacy.confirmPublic({
      tenantId: s.tenantId,
      requestId: verify.payload.requestId!,
      token: verify.payload.token!,
    });
    expect(confirmed.status).toBe('pending-verification');
    await expect(
      s.privacy.fulfilRequest(s.owner, { tenantId: s.tenantId, requestId: verify.payload.requestId! }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    // A confirmed address does not lapse as unconfirmed.
    s.f.advance(8 * day);
    expect((await s.f.iam.privacy.sendDeadlineReminders({ tenantId: s.tenantId })).lapsed).toBe(0);
  });

  it('keeps an erased application subject suppressed instead of opted back in', async () => {
    const s = await scenario();
    await s.privacy.record(s.owner, {
      tenantId: s.tenantId,
      subject: { externalId: 'cus_7' },
      purposeKey: 'data-sharing',
      granted: false,
    });
    const request = await s.privacy.createRequest(s.owner, {
      tenantId: s.tenantId,
      type: 'erasure',
      subject: { externalId: 'cus_7' },
      verified: { method: 'Signed-in customer portal' },
    });
    await s.privacy.fulfilRequest(s.owner, { tenantId: s.tenantId, requestId: request.id });
    expect(
      await s.privacy.check(s.owner, {
        tenantId: s.tenantId,
        subject: { externalId: 'cus_7' },
        purposeKey: 'data-sharing',
      }),
    ).toMatchObject({ allowed: false, reason: 'ERASED' });
  });

  it('asks handlers for directory rights to export, download or list people, and audits refusals', async () => {
    const s = await scenario();
    const { token } = await handler(s);
    const request = await s.privacy.submitRequest(s.aliceToken, {
      tenantId: s.tenantId,
      type: 'access',
    });
    // Bob may handle requests but not read Alice's account.
    await expect(
      s.privacy.fulfilRequest(token, { tenantId: s.tenantId, requestId: request.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await s.privacy.fulfilRequest(s.owner, { tenantId: s.tenantId, requestId: request.id });
    await expect(
      s.privacy.downloadExport(token, { tenantId: s.tenantId, requestId: request.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const audit = await s.f.iam.api.audit.list(s.owner, { tenantId: s.tenantId });
    const events = (Array.isArray(audit) ? audit : (audit as { events: unknown[] }).events) as Array<{
      action: string;
      outcome: string;
    }>;
    expect(
      events.some((event) => event.action === 'iam:identities:read' && event.outcome === 'deny'),
    ).toBe(true);
    // Audiences list people by ID only without directory rights.
    const audience = await s.privacy.audience(token, {
      tenantId: s.tenantId,
      purposeKey: 'data-sharing',
    });
    expect(audience.subjects.length).toBeGreaterThan(0);
    expect(audience.subjects.every((subject) => subject.email === undefined)).toBe(true);
  });

  it('leaves audit activity out of exports made without audit rights', async () => {
    const s = await scenario();
    const { bob, token } = await handler(s);
    // Bob may also read people, but still not the audit log.
    const reader = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Directory reader',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['iam:identities:read'], resources: ['*'] }],
      },
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const request = await s.privacy.submitRequest(s.aliceToken, {
      tenantId: s.tenantId,
      type: 'access',
    });
    await s.privacy.fulfilRequest(token, { tenantId: s.tenantId, requestId: request.id });
    const data = (
      await s.privacy.downloadExport(s.aliceToken, { tenantId: s.tenantId, requestId: request.id })
    ).data as Record<string, unknown>;
    expect(data.activity).toBeUndefined();
    expect(data.activityOmitted).toBe(true);
  });

  it('needs a linked subject for requests that arrived by email, and records identity:delete on erasure', async () => {
    const s = await scenario();
    const request = await s.privacy.createRequest(s.owner, {
      tenantId: s.tenantId,
      type: 'erasure',
      requesterEmail: 'alice.personal@example.test',
    });
    await s.privacy.verifyRequest(s.owner, {
      tenantId: s.tenantId,
      requestId: request.id,
      method: 'Video call',
    });
    await expect(
      s.privacy.fulfilRequest(s.owner, { tenantId: s.tenantId, requestId: request.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const linked = await s.privacy.linkRequest(s.owner, {
      tenantId: s.tenantId,
      requestId: request.id,
      subject: { identityId: s.alice.id },
      note: 'Same person, second address',
    });
    expect(linked).toMatchObject({ identityId: s.alice.id, subject: `identity:${s.alice.id}` });
    await s.privacy.fulfilRequest(s.owner, { tenantId: s.tenantId, requestId: request.id });
    const audit = await s.f.iam.api.audit.list(s.owner, { tenantId: s.tenantId });
    const events = (Array.isArray(audit) ? audit : (audit as { events: unknown[] }).events) as Array<{
      action: string;
      resourceId: string;
      metadata?: Record<string, unknown>;
    }>;
    const deletion = events.find(
      (event) => event.action === 'identity:delete' && event.resourceId === s.alice.id,
    );
    expect(deletion?.metadata).toEqual({ kind: 'user', erasure: true });
    // Another email-only request can be declined as holding no data.
    const other = await s.privacy.createRequest(s.owner, {
      tenantId: s.tenantId,
      type: 'access',
      requesterEmail: 'stranger@example.test',
    });
    expect(
      (
        await s.privacy.rejectRequest(s.owner, {
          tenantId: s.tenantId,
          requestId: other.id,
          reason: 'no-data',
        })
      ).status,
    ).toBe('rejected');
  });

  it('requires versions on imports and a new version for a mode change', async () => {
    const s = await scenario();
    await expect(
      s.privacy.record(s.owner, {
        tenantId: s.tenantId,
        subject: { externalId: 'cus_1' },
        purposeKey: 'marketing-email',
        granted: true,
        source: 'import',
        recordedAt: s.f.now() - day,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      s.privacy.updatePurpose(s.owner, {
        tenantId: s.tenantId,
        purposeId: s.marketing.id,
        mode: 'opt-out',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const changed = await s.privacy.updatePurpose(s.owner, {
      tenantId: s.tenantId,
      purposeId: s.marketing.id,
      mode: 'opt-out',
      newVersion: true,
    });
    expect(changed).toMatchObject({ mode: 'opt-out', version: 2 });
  });
});

describe('legal holds and organizations', () => {
  it('refuses to delete an organization while someone in it is under a legal hold', async () => {
    const s = await scenario();
    const hold = await s.privacy.placeHold(s.owner, {
      tenantId: s.tenantId,
      subject: { identityId: s.alice.id },
      reason: 'Litigation',
    });
    const root = s.f.rootCredential;
    await expect(
      s.f.iam.api.tenants.setStatus(root, { tenantId: s.tenantId, status: 'deleted' }),
    ).rejects.toMatchObject({ code: 'LEGAL_HOLD' });
    await s.privacy.releaseHold(s.owner, { tenantId: s.tenantId, holdId: hold.id });
    expect(
      (await s.f.iam.api.tenants.setStatus(root, { tenantId: s.tenantId, status: 'deleted' })).status,
    ).toBe('deleted');
  });
});
