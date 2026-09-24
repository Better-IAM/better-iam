import { afterEach, describe, expect, it } from 'vitest';
import type { ThreatRuleView } from '@better-iam/server';
import {
  actionsSummary,
  durationLabel,
  playbookBody,
  playbookDraft,
  responseActions,
  ruleDraft,
  ruleDraftChanged,
  ruleSettingChange,
  splitList,
  triggerSummary,
} from '../apps/console/src/lib/threats.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const bruteForce: ThreatRuleView = {
  id: 'brute-force',
  title: 'Password guessing',
  description: '',
  category: 'sign-in',
  subject: 'identity',
  technique: 'T1110.001',
  defaults: { enabled: true, severity: 'medium', threshold: 10, windowMs: 15 * 60_000 },
  tunable: { threshold: [3, 1000], windowMs: [60_000, 86_400_000] },
  enabled: true,
  severity: 'medium',
  threshold: 10,
  windowMs: 15 * 60_000,
  customized: false,
};

describe('console threats helpers', () => {
  it('sends a rule change with defaults as null and untunable fields left out', () => {
    const draft = ruleDraft(bruteForce);
    expect(draft).toEqual({
      enabled: true,
      severity: 'medium',
      threshold: '10',
      windowMinutes: '15',
      everyone: false,
    });
    expect(ruleDraftChanged(bruteForce, draft)).toBe(false);
    expect(ruleSettingChange(bruteForce, draft)).toEqual({
      enabled: null,
      severity: null,
      threshold: null,
      windowMs: null,
    });
    const edited = { ...draft, enabled: false, threshold: '25', windowMinutes: '60' };
    expect(ruleDraftChanged(bruteForce, edited)).toBe(true);
    expect(ruleSettingChange(bruteForce, edited)).toEqual({
      enabled: false,
      severity: null,
      threshold: 25,
      windowMs: 3_600_000,
    });
    // An emptied number stands for the default.
    const emptied = { ...draft, threshold: '', windowMinutes: ' ' };
    expect(ruleDraftChanged(bruteForce, emptied)).toBe(false);
    expect(ruleSettingChange(bruteForce, emptied)).toMatchObject({
      threshold: null,
      windowMs: null,
    });
    const hijack: ThreatRuleView = {
      ...bruteForce,
      id: 'session-hijack',
      defaults: { enabled: true, severity: 'high' },
      tunable: undefined,
      severity: 'high',
      threshold: undefined,
      windowMs: undefined,
    };
    expect(ruleSettingChange(hijack, { ...ruleDraft(hijack), severity: 'critical' })).toEqual({
      enabled: null,
      severity: 'critical',
    });
    const newNetwork: ThreatRuleView = { ...hijack, id: 'new-network', everyone: false };
    expect(
      ruleSettingChange(newNetwork, { ...ruleDraft(newNetwork), everyone: true }),
    ).toMatchObject({ everyone: true });
    expect(ruleSettingChange(newNetwork, ruleDraft(newNetwork))).toMatchObject({ everyone: null });
  });

  it('builds response actions in order with their options', () => {
    expect(
      responseActions(['notify', 'block-network', 'revoke-sessions'], {
        blockHours: 2,
        keepApiKeys: false,
      }),
    ).toEqual([
      { kind: 'revoke-sessions', keepApiKeys: false },
      { kind: 'block-network', durationMs: 7_200_000 },
      { kind: 'notify' },
    ]);
    expect(responseActions(['revoke-sessions'], { keepApiKeys: true })).toEqual([
      { kind: 'revoke-sessions' },
    ]);
    expect(
      actionsSummary([{ kind: 'revoke-sessions', keepApiKeys: false }, { kind: 'block-network' }]),
    ).toBe('End sessions and API keys, Block network for 1 day');
    expect(durationLabel(90 * 60_000)).toBe('90 min');
    expect(durationLabel(3 * 3_600_000)).toBe('3 h');
    expect(splitList(' 10.0.0.0/8,\n192.0.2.1 \n\n')).toEqual(['10.0.0.0/8', '192.0.2.1']);
    expect(
      triggerSummary({ ruleIds: ['brute-force'], minSeverity: 'high' }, () => 'Password guessing'),
    ).toBe('Password guessing · high severity or higher');
  });

  it('sends bodies the threats API accepts', async () => {
    const f = await organizationFixture();
    const threats = f.iam.api.threats;
    const owner = await f.ownerSignIn();
    const rule = (await threats.rules(owner, { tenantId: f.tenantId })).find(
      (candidate) => candidate.id === 'brute-force',
    )!;
    await threats.configure(owner, {
      tenantId: f.tenantId,
      rules: {
        'brute-force': ruleSettingChange(rule, {
          ...ruleDraft(rule),
          threshold: '30',
          severity: 'high',
        }),
      },
    });
    const changed = (await threats.rules(owner, { tenantId: f.tenantId })).find(
      (candidate) => candidate.id === 'brute-force',
    )!;
    expect(changed).toMatchObject({ threshold: 30, severity: 'high', customized: true });
    // Putting every field back to its default leaves the rule uncustomized.
    await threats.configure(owner, {
      tenantId: f.tenantId,
      rules: { 'brute-force': ruleSettingChange(changed, ruleDraft(rule)) },
    });
    expect(
      (await threats.rules(owner, { tenantId: f.tenantId })).find(
        (candidate) => candidate.id === 'brute-force',
      ),
    ).toMatchObject({ threshold: 10, severity: 'medium', customized: false });

    const created = await threats.createPlaybook(owner, {
      tenantId: f.tenantId,
      ...playbookBody(
        {
          ...playbookDraft(),
          name: 'Spray response',
          ruleIds: ['password-spray'],
          minSeverity: 'high',
          actions: ['notify', 'block-network'],
          blockHours: '12',
        },
        false,
      ),
      description: undefined,
    });
    expect(created).toMatchObject({
      enabled: true,
      trigger: { ruleIds: ['password-spray'], minSeverity: 'high' },
      actions: [{ kind: 'block-network', durationMs: 43_200_000 }, { kind: 'notify' }],
    });
    await threats.updatePlaybook(owner, {
      tenantId: f.tenantId,
      playbookId: created.id,
      enabled: false,
    });
    // An edit form opened before the playbook was disabled does not switch it back on.
    const updated = await threats.updatePlaybook(owner, {
      tenantId: f.tenantId,
      playbookId: created.id,
      ...playbookBody({ ...playbookDraft(created), ruleIds: [], minSeverity: '' }, true),
    });
    expect(updated.enabled).toBe(false);
    expect(updated.trigger).toEqual({});
    expect(updated.description).toBeUndefined();
  });
});
