import { afterEach, describe, expect, it } from 'vitest';
import type {
  ClassificationSchemeDefinition,
  ClassificationSchemeView,
  ClearanceView,
} from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';
import {
  attempt,
  clearanceAttention,
  clearanceFilterQuery,
  clearanceFilters,
  clearanceResource,
  clearanceSummary,
  compartmentName,
  countryCodes,
  dateValue,
  dueState,
  emptyClearanceDraft,
  featureDisabled,
  grantBody,
  historyEntry,
  labelDraft,
  labelFilterQuery,
  labelFilters,
  labelFromDraft,
  labelMarking,
  labelResource,
  levelName,
  levelOptions,
  parseDate,
  parseDefinition,
  schemeSettingsChange,
  schemeSettingsDraft,
  statusTone,
  updateChange,
  updateDraft,
  valueOf,
  withCompartment,
  withTopLevel,
} from '../apps/console/src/lib/clearances.js';
import { dateTimeLocalValue } from '../apps/console/src/lib/form-body.js';
import { orgAreas } from '../apps/console/src/lib/navigation.js';

afterEach(closeFixtures);

const day = 86_400_000;
const now = Date.UTC(2026, 9, 7, 12);

const definition: ClassificationSchemeDefinition = {
  levels: [
    { id: 'U', name: 'UNCLASSIFIED', rank: 0 },
    { id: 'S', name: 'SECRET', rank: 2, abbreviation: 'S' },
    { id: 'C', name: 'CONFIDENTIAL', rank: 1 },
    { id: 'TS', name: 'TOP SECRET', rank: 3, abbreviation: 'TS' },
  ],
  compartments: [
    { id: 'c-1', name: 'GAMMA' },
    { id: 'c-2', name: 'TALENT' },
  ],
  ownerCountries: ['USA'],
  caveats: ['NOFORN', 'RELTO'],
};

const scheme: ClassificationSchemeView = {
  tenantId: 'tenant-a',
  inherited: false,
  name: 'Program',
  definition,
  requireLabels: ['dataset', 'document'],
  guestCeiling: null,
  interimAllowed: true,
  adjudication: 'within-own',
  notify: { emails: ['officer@example.com'] },
  createdAt: now - 10 * day,
  createdBy: 'owner',
  updatedAt: now - day,
  updatedBy: 'owner',
  version: 3,
};

function clearance(overrides: Partial<ClearanceView> = {}): ClearanceView {
  return {
    identityId: 'alice',
    identity: {
      id: 'alice',
      name: 'Alice',
      email: 'alice@example.com',
      kind: 'user',
      status: 'active',
      guest: false,
    },
    schemeTenantId: 'tenant-a',
    level: { id: 'S', name: 'SECRET', rank: 2 },
    status: 'active',
    effectiveStatus: 'active',
    effectiveLevel: 'S',
    citizenship: ['USA'],
    readIns: [],
    grantedAt: now - 30 * day,
    grantedBy: 'officer',
    updatedAt: now - 30 * day,
    updatedBy: 'officer',
    ...overrides,
  };
}

class FakeIamError extends Error {
  override name = 'IamError';
  constructor(
    readonly code: string,
    readonly status = 403,
  ) {
    super(code);
  }
}

describe('console clearance helpers', () => {
  it('names levels and compartments only from a scheme definition the page passes in', () => {
    expect(levelName(definition, 'TS')).toBe('TOP SECRET');
    expect(levelName(undefined, 'TS')).toBe('TS');
    expect(levelName(definition, 'gone')).toBe('gone');
    expect(compartmentName(definition, 'c-1')).toBe('GAMMA');
    // Without iam:clearances:read the page has no definition: the opaque id, never the codeword.
    expect(compartmentName(undefined, 'c-1')).toBe('c-1');
    expect(levelOptions(definition)).toEqual([
      { value: 'U', label: 'UNCLASSIFIED' },
      { value: 'C', label: 'CONFIDENTIAL' },
      { value: 'S', label: 'SECRET (S)' },
      { value: 'TS', label: 'TOP SECRET (TS)' },
    ]);
  });

  it('prints labels as banner markings', () => {
    expect(
      labelMarking({ level: 'TS', compartments: ['c-1', 'c-2'], noforn: true }, definition),
    ).toBe('TOP SECRET // GAMMA/TALENT // NOFORN');
    expect(labelMarking({ level: 'S', releasableTo: ['GBR', 'CAN'] }, definition)).toBe(
      'SECRET // REL TO USA, GBR, CAN',
    );
    expect(labelMarking({ level: 'S', releasableTo: [] }, definition)).toBe('SECRET // REL TO USA');
    expect(labelMarking({ level: 'S', compartments: ['c-2'], releasableTo: [] })).toBe(
      'S // c-2 // REL TO owner countries',
    );
    expect(labelMarking({ level: 'U' }, definition)).toBe('UNCLASSIFIED');
  });

  it('tones statuses', () => {
    expect(statusTone('active')).toBe('success');
    expect(statusTone('interim')).toBe('accent');
    expect(statusTone('suspended')).toBe('warning');
    expect(statusTone('none')).toBe('warning');
    expect(statusTone('expired')).toBe('danger');
    expect(statusTone('revoked')).toBe('danger');
    expect(statusTone('terminated')).toBe('neutral');
  });

  it('flags what needs an officer and counts the register', () => {
    expect(dueState(undefined, now)).toBeUndefined();
    expect(dueState(now - 1, now)).toBe('overdue');
    expect(dueState(now + 10 * day, now)).toBe('soon');
    expect(dueState(now + 90 * day, now)).toBeUndefined();
    expect(dueState(now + 90 * day, now, 120)).toBe('soon');

    const ending = clearance({ expiresAt: now + 5 * day, reinvestigationDue: now - day });
    expect(clearanceAttention(ending, now)).toEqual([
      { label: 'ends soon', tone: 'warning' },
      { label: 'reinvestigation overdue', tone: 'danger' },
    ]);
    const lapsedNda = clearance({
      reinvestigationDue: now + 20 * day,
      readIns: [
        { compartmentId: 'c-1', readInAt: now, readInBy: 'o', current: false },
        { compartmentId: 'c-2', readInAt: now, readInBy: 'o', current: true },
      ],
    });
    expect(clearanceAttention(lapsedNda, now).map((item) => item.label)).toEqual([
      'reinvestigation due',
      '1 read-in not current',
    ]);
    expect(
      clearanceAttention(clearance({ effectiveStatus: 'expired', expiresAt: now - day }), now),
    ).toEqual([{ label: 'expired', tone: 'danger' }]);
    // Ended clearances need nobody's attention.
    expect(
      clearanceAttention(
        clearance({ status: 'revoked', effectiveStatus: 'revoked', reinvestigationDue: now - day }),
        now,
      ),
    ).toEqual([]);

    expect(
      clearanceSummary(
        [
          ending,
          lapsedNda,
          clearance({ status: 'interim', effectiveStatus: 'interim' }),
          clearance({ status: 'suspended', effectiveStatus: 'suspended' }),
          clearance({ effectiveStatus: 'none' }),
          clearance({ status: 'terminated', effectiveStatus: 'terminated' }),
        ],
        now,
      ),
    ).toEqual({
      inForce: 3,
      interim: 1,
      suspended: 1,
      notCounted: 1,
      endingSoon: 1,
      reinvestigationDue: 2,
      closed: 1,
    });
  });

  it('reads list filters from the query string and writes them back', () => {
    const levels = definition.levels.map((level) => level.id);
    expect(
      clearanceFilters({ status: 'suspended', level: 'TS', ending: '60', page: '2' }, levels),
    ).toEqual({ filters: { status: 'suspended', level: 'TS', expiringWithinDays: 60 }, page: 2 });
    expect(
      clearanceFilters({ status: 'expired', level: 'nope', ending: '7', page: '-3' }, levels),
    ).toEqual({ filters: {}, page: 1 });
    // Without the scheme any well-formed level id is passed on; the server filters by it.
    expect(clearanceFilters({ level: 'S' }).filters).toEqual({ level: 'S' });
    expect(clearanceFilters({ level: '<script>' }).filters).toEqual({});
    expect(clearanceFilterQuery({ status: 'active', expiringWithinDays: 30 }, 3)).toBe(
      '?status=active&ending=30&page=3',
    );
    expect(clearanceFilterQuery({})).toBe('');
    expect(labelFilters({ type: ' document ', level: 'S', page: '4' }, levels)).toEqual({
      filters: { type: 'document', level: 'S' },
      page: 4,
    });
    expect(labelFilterQuery({ type: 'document' }, 2)).toBe('?type=document&page=2');
  });

  it('checks typed citizenship and dates', () => {
    expect(countryCodes('gbr, usa  USA\ncan')).toEqual(['CAN', 'GBR', 'USA']);
    expect(countryCodes('')).toEqual([]);
    expect(() => countryCodes('US, GBR')).toThrow('alpha-3');
    expect(parseDate('', 'Due')).toBeUndefined();
    expect(parseDate('2027-01-15', 'Due')).toBe(new Date(2027, 0, 15).getTime());
    expect(() => parseDate('15/01/2027', 'Due')).toThrow('Due must be a date');
    expect(dateValue(new Date(2027, 0, 15, 18, 30).getTime())).toBe('2027-01-15');
  });

  it('builds the grant body', () => {
    expect(grantBody('t', 'alice', { ...emptyClearanceDraft('S'), citizenship: 'usa' })).toEqual({
      tenantId: 't',
      identityId: 'alice',
      level: 'S',
      citizenship: ['USA'],
    });
    const full = grantBody('t', 'alice', {
      level: 'TS',
      citizenship: 'USA, GBR',
      interim: true,
      investigationKind: ' Tier 5 ',
      investigationCompletedOn: '2026-09-01',
      reinvestigationDueOn: '2031-09-01',
      expiresAt: '2027-06-30T17:00',
    });
    expect(full).toEqual({
      tenantId: 't',
      identityId: 'alice',
      level: 'TS',
      citizenship: ['GBR', 'USA'],
      interim: true,
      investigation: { kind: 'Tier 5', completedAt: new Date(2026, 8, 1).getTime() },
      reinvestigationDue: new Date(2031, 8, 1).getTime(),
      expiresAt: new Date(2027, 5, 30, 17).getTime(),
    });
    expect(() => grantBody('t', 'alice', emptyClearanceDraft())).toThrow('Choose a level');
    expect(() =>
      grantBody('t', 'alice', { ...emptyClearanceDraft('S'), investigationKind: 'Tier 3' }),
    ).toThrow('together');
  });

  it('sends only what an update changes', () => {
    const view = clearance({
      investigation: { kind: 'Tier 5', completedAt: Date.UTC(2026, 0, 10, 15) },
      reinvestigationDue: Date.UTC(2031, 0, 10, 15),
      // Already past: re-sending it would be refused, so an untouched form must not.
      expiresAt: now - day,
    });
    const draft = updateDraft(view);
    expect(draft.term).toBe('final');
    expect(draft.expiresAt).toBe(dateTimeLocalValue(now - day));
    expect(updateChange(view, draft)).toEqual({});
    expect(updateChange(view, { ...draft, citizenship: 'usa' })).toEqual({});
    expect(
      updateChange(view, {
        ...draft,
        level: 'TS',
        citizenship: 'USA, GBR',
        reinvestigationDueOn: '',
        expiresAt: '',
        term: 'interim',
      }),
    ).toEqual({
      level: 'TS',
      citizenship: ['GBR', 'USA'],
      interim: true,
      reinvestigationDue: null,
      expiresAt: null,
    });
    expect(
      updateChange(view, { ...draft, investigationKind: '', investigationCompletedOn: '' }),
    ).toEqual({ investigation: null });
    expect(updateChange(view, { ...draft, investigationKind: 'Tier 3' })).toEqual({
      investigation: {
        kind: 'Tier 3',
        completedAt: parseDate(draft.investigationCompletedOn, 'x'),
      },
    });
    // A suspended clearance does not say which it returns to: "keep" sends nothing, a choice is sent as made.
    const suspended = clearance({ status: 'suspended', effectiveStatus: 'suspended' });
    const held = updateDraft(suspended);
    expect(held.term).toBe('keep');
    expect(updateChange(suspended, held)).toEqual({});
    expect(updateChange(suspended, { ...held, term: 'final' })).toEqual({ interim: false });
  });

  it('turns label drafts into labels', () => {
    const label = { level: 'TS', compartments: ['c-2', 'c-1'], releasableTo: ['GBR'] };
    const draft = labelDraft(label);
    expect(draft).toEqual({
      level: 'TS',
      compartments: ['c-2', 'c-1'],
      noforn: false,
      release: 'listed',
      releasableTo: 'GBR',
    });
    expect(labelFromDraft(draft)).toEqual({
      level: 'TS',
      compartments: ['c-1', 'c-2'],
      releasableTo: ['GBR'],
    });
    expect(labelDraft({ level: 'S', releasableTo: [] }).release).toBe('owners');
    expect(labelFromDraft({ ...labelDraft(), level: 'S', release: 'owners' })).toEqual({
      level: 'S',
      releasableTo: [],
    });
    // NOFORN already confines readers to the owner countries.
    expect(labelFromDraft({ ...draft, noforn: true })).toEqual({
      level: 'TS',
      compartments: ['c-1', 'c-2'],
      noforn: true,
    });
    expect(labelFromDraft(labelDraft(null, 'U'))).toEqual({ level: 'U' });
    expect(() => labelFromDraft(labelDraft())).toThrow('Choose a level');
    expect(() => labelFromDraft({ ...draft, releasableTo: '' })).toThrow('releasable');
  });

  it('sends only the scheme settings that change', () => {
    const draft = schemeSettingsDraft(scheme);
    expect(schemeSettingsChange(scheme, draft)).toEqual({});
    expect(schemeSettingsChange(scheme, { ...draft, requireLabels: 'document dataset' })).toEqual(
      {},
    );
    expect(
      schemeSettingsChange(scheme, {
        ...draft,
        name: ' Program 2 ',
        requireLabels: '*',
        guestCeiling: 'C',
        interimAllowed: false,
        adjudication: 'unrestricted',
        notifyEmails: '',
      }),
    ).toEqual({
      name: 'Program 2',
      requireLabels: ['*'],
      guestCeiling: 'C',
      interimAllowed: false,
      adjudication: 'unrestricted',
      notify: null,
    });
    expect(
      schemeSettingsChange({ ...scheme, guestCeiling: 'C' }, { ...draft, guestCeiling: '' }),
    ).toEqual({ guestCeiling: null });
    expect(() => schemeSettingsChange(scheme, { ...draft, name: ' ' })).toThrow('name');
  });

  it('adds compartments and levels on top, and refuses clashes', () => {
    const added = withCompartment(definition, { id: ' c-3 ', name: ' RUFF ' });
    expect(added.compartments.at(-1)).toEqual({ id: 'c-3', name: 'RUFF' });
    expect(definition.compartments).toHaveLength(2);
    expect(() => withCompartment(definition, { id: 'C-1', name: 'X' })).toThrow('id exists');
    expect(() => withCompartment(definition, { id: 'c-9', name: 'gamma' })).toThrow('name exists');
    expect(() => withCompartment(definition, { id: '-bad', name: 'X' })).toThrow('compartment id');
    const raised = withTopLevel(definition, {
      id: 'SAP',
      name: 'SPECIAL ACCESS',
      abbreviation: '',
    });
    expect(raised.levels.map((level) => [level.id, level.rank])).toEqual([
      ['U', 0],
      ['C', 1],
      ['S', 2],
      ['TS', 3],
      ['SAP', 4],
    ]);
    expect(raised.levels.at(-1)).toEqual({ id: 'SAP', name: 'SPECIAL ACCESS', rank: 4 });
    expect(() => withTopLevel(definition, { id: 'ts', name: 'Other' })).toThrow('id exists');
    expect(parseDefinition('{"levels":[]}')).toEqual({ levels: [] });
    expect(() => parseDefinition('[1]')).toThrow('JSON object');
    expect(() => parseDefinition('{')).toThrow('valid JSON');
  });

  it('describes history events with names only when the scheme is readable', () => {
    const readIn = {
      action: 'clearance:read-in',
      actorId: 'officer',
      timestamp: now,
      metadata: { compartmentId: 'c-1', level: 'S', agreementId: 'nda', bootstrap: true },
    };
    expect(historyEntry(readIn, definition)).toEqual({
      title: 'Read in',
      tone: 'accent',
      details: ['GAMMA', 'backed by an NDA', 'bootstrap: nobody held it yet'],
    });
    expect(historyEntry(readIn).details[0]).toBe('c-1');
    expect(
      historyEntry(
        {
          action: 'clearance:update',
          actorId: 'officer',
          timestamp: now,
          metadata: { level: 'TS', previousLevel: 'S', changed: ['level', 'reinvestigationDue'] },
        },
        definition,
      ).details,
    ).toEqual(['SECRET → TOP SECRET', 'changed level, reinvestigation date']);
    expect(
      historyEntry(
        {
          action: 'clearance:revoke',
          actorId: 'officer',
          timestamp: now,
          metadata: { level: 'S', reason: 'Unfavorable', debriefed: ['c-1', 'c-2'] },
        },
        definition,
      ),
    ).toEqual({
      title: 'Revoked',
      tone: 'danger',
      details: ['SECRET', 'debriefed GAMMA, TALENT', '“Unfavorable”'],
    });
    expect(historyEntry({ action: 'clearance:other', actorId: 'x', timestamp: now }).title).toBe(
      'clearance:other',
    );
  });

  it('tells a disabled feature from a missing permission, and rethrows anything else', async () => {
    const ok = await attempt(async () => 5);
    expect(ok).toEqual({ ok: true, value: 5 });
    expect(valueOf(ok)).toBe(5);
    const denied = await attempt(async () => {
      throw new FakeIamError('ACCESS_DENIED');
    });
    expect(denied).toEqual({ ok: false, code: 'ACCESS_DENIED' });
    expect(valueOf(denied)).toBeUndefined();
    expect(featureDisabled(ok, denied)).toBe(false);
    const off = await attempt(async () => {
      throw new FakeIamError('FEATURE_DISABLED');
    });
    expect(featureDisabled(ok, denied, off)).toBe(true);
    await expect(
      attempt(async () => {
        throw new TypeError('bug');
      }),
    ).rejects.toThrow('bug');
  });

  it('authorizes against the API’s resources', () => {
    expect(clearanceResource('alice')).toEqual({ type: 'iam', id: 'clearances/alice' });
    expect(labelResource('document', 'q3')).toEqual({
      type: 'iam',
      id: 'classifications/labels/document/q3',
    });
    // Too long: the server authorizes a hashed form, so the page falls back to its generic check.
    expect(labelResource('document', 'x'.repeat(300))).toBeUndefined();
  });

  it('registers the pages in the Security section', () => {
    const security = orgAreas('/cloud/acme').find((area) => area.key === 'security');
    expect(security?.pages.map((page) => page.href)).toEqual(
      expect.arrayContaining(['/cloud/acme/clearances', '/cloud/acme/classification']),
    );
  });

  it('sends bodies the clearances API accepts', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId, ownerCredential: owner } = f;
    // What the "Start from a template" form sends (checkbox as a boolean, an empty list left out).
    let scheme = await api.defineScheme(owner, {
      tenantId,
      name: 'Acme',
      template: 'us',
      adjudication: 'unrestricted',
      interimAllowed: false,
    });
    scheme = await api.updateScheme(owner, {
      tenantId,
      version: scheme.version,
      ...schemeSettingsChange(scheme, {
        ...schemeSettingsDraft(scheme),
        requireLabels: 'document',
        guestCeiling: 'C',
        interimAllowed: true,
        notifyEmails: 'Officer@Acme.test',
      }),
    });
    expect(scheme).toMatchObject({
      requireLabels: ['document'],
      guestCeiling: 'C',
      interimAllowed: true,
      notify: { emails: ['officer@acme.test'] },
    });
    // Saved as typed, the settings form has nothing left to send.
    expect(schemeSettingsChange(scheme, schemeSettingsDraft(scheme))).toEqual({});
    scheme = await api.updateScheme(owner, {
      tenantId,
      version: scheme.version,
      definition: withCompartment(scheme.definition, { id: 'GAMMA', name: 'Gamma codeword' }),
    });
    scheme = await api.updateScheme(owner, {
      tenantId,
      version: scheme.version,
      definition: withTopLevel(scheme.definition, { id: 'SAP', name: 'SPECIAL ACCESS' }),
    });
    expect(scheme.definition.levels.at(-1)).toMatchObject({ id: 'SAP', rank: 4 });
    scheme = await api.updateScheme(owner, {
      tenantId,
      version: scheme.version,
      defaultLabel: labelFromDraft({ ...labelDraft(), level: 'C', release: 'owners' }),
    });
    expect(scheme.defaultLabel).toEqual({ level: 'C', releasableTo: [] });

    const alice = await f.member('alice');
    const granted = await api.grant(
      owner,
      grantBody(tenantId, alice.id, {
        ...emptyClearanceDraft('S'),
        citizenship: 'usa, gbr',
        interim: true,
        investigationKind: 'Tier 5',
        investigationCompletedOn: dateValue(Date.now() - 30 * day),
        reinvestigationDueOn: dateValue(Date.now() + 5 * 365 * day),
        expiresAt: dateTimeLocalValue(Date.now() + 365 * day),
      }),
    );
    expect(granted).toMatchObject({
      status: 'interim',
      citizenship: ['GBR', 'USA'],
      investigation: { kind: 'Tier 5' },
    });
    expect(updateChange(granted, updateDraft(granted))).toEqual({});
    const updated = await api.update(owner, {
      tenantId,
      identityId: alice.id,
      ...updateChange(granted, {
        ...updateDraft(granted),
        level: 'TS',
        term: 'final',
        reinvestigationDueOn: '',
        investigationKind: '',
        investigationCompletedOn: '',
      }),
    });
    expect(updated).toMatchObject({ level: { id: 'TS' }, status: 'active' });
    expect(updated.reinvestigationDue).toBeUndefined();
    expect(updated.investigation).toBeUndefined();
    expect(updateChange(updated, updateDraft(updated))).toEqual({});

    const labeled = await api.label(owner, {
      tenantId,
      type: 'document',
      id: 'plan',
      label: labelFromDraft({
        ...labelDraft(),
        level: 'S',
        compartments: ['GAMMA'],
        release: 'listed',
        releasableTo: 'gbr',
      }),
      inheritToChildren: false,
    });
    expect(labelMarking(labeled.label, scheme.definition)).toBe(
      'SECRET // Gamma codeword // REL TO USA, GBR',
    );
    // Without iam:clearances:read the page has no definition: ids, never the codeword.
    expect(labelMarking(labeled.label)).toBe('S // GAMMA // REL TO GBR');

    // The history card reads the clearance's own audit events.
    const events = await f.iam.api.audit.list(owner, {
      tenantId,
      resourceId: alice.id,
      action: 'clearance:*',
    });
    expect(events.map((event) => historyEntry(event, scheme.definition).title).sort()).toEqual([
      'Changed',
      'Granted',
    ]);
    const grantEvent = events.find((event) => event.action === 'clearance:grant')!;
    expect(historyEntry(grantEvent, scheme.definition).details).toEqual(['SECRET', 'as interim']);
    const updateEvent = events.find((event) => event.action === 'clearance:update')!;
    expect(historyEntry(updateEvent, scheme.definition).details).toEqual([
      'SECRET → TOP SECRET',
      'changed level, interim or final, investigation, reinvestigation date',
    ]);
  });
});
