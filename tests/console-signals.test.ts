import { afterEach, describe, expect, it } from 'vitest';
import {
  actionsChange,
  claimsSummary,
  createSourceBody,
  mappingChange,
  mappingDraft,
  pollSummary,
  signalReason,
  signalStatusTone,
  sourceDraft,
  sourceSettingsChange,
  splitEntries,
  subjectSummary,
} from '../apps/console/src/lib/signals.js';
import { generateTestKey } from './support/jwt-keys.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('console shared signals helpers', () => {
  it('summarizes subjects, claims and outcomes in words', () => {
    expect(subjectSummary({ format: 'iss_sub', iss: 'https://idp.test', sub: '00u1' })).toBe(
      '00u1 at https://idp.test',
    );
    expect(subjectSummary({ format: 'email', email: 'ada@acme.test' })).toBe('ada@acme.test');
    expect(
      subjectSummary({
        format: 'complex',
        user: { format: 'opaque', id: 'u-1' },
        device: { format: 'opaque', id: 'laptop' },
      }),
    ).toBe('id u-1 · device id laptop');
    expect(
      subjectSummary({
        format: 'aliases',
        identifiers: [
          { format: 'email', email: 'ada@acme.test' },
          { format: 'account', uri: 'acct:ada@acme.test' },
        ],
      }),
    ).toBe('ada@acme.test / acct:ada@acme.test');
    expect(subjectSummary({ format: 'complex', _truncated: true })).toBe(
      'complex (too large to keep)',
    );
    expect(subjectSummary(undefined)).toBe('—');
    expect(
      claimsSummary('risk-level-change', {
        current_level: 'HIGH',
        previous_level: 'LOW',
        reason_admin: { en: 'Leaked credentials found' },
      }),
    ).toBe('LOW → HIGH · Leaked credentials found');
    expect(
      claimsSummary('credential-change', { credential_type: 'password', change_type: 'update' }),
    ).toBe('password update');
    expect(claimsSummary('session-revoked', { initiating_entity: 'admin' })).toBeUndefined();
    expect(signalReason('no-match')).toBe('no person matched the subject');
    expect(signalReason('INTERNAL_ERROR')).toBe('INTERNAL_ERROR');
    expect(signalStatusTone('failed')).toBe('danger');
    expect(splitEntries(' a,\nb \n\na ')).toEqual(['a', 'b']);
    expect(pollSummary({ received: 1, acknowledged: 3, errors: 2 })).toBe(
      "1 new event, 3 acknowledged, 2 errors (see the source's last error)",
    );
  });

  it('refuses a key set it can tell is malformed before sending', () => {
    const draft = {
      ...sourceDraft(),
      name: 'Okta',
      issuer: 'https://idp.example.test',
      audiences: 'https://rp.example.test',
      keys: 'jwks' as const,
      jwks: '{',
    };
    expect(() => createSourceBody('t', draft, mappingDraft(), {})).toThrow('valid JSON');
    expect(() =>
      createSourceBody('t', { ...draft, jwks: '{"keys":[]}' }, mappingDraft(), {}),
    ).toThrow('key set');
    expect(() =>
      createSourceBody('t', { ...draft, keys: 'discover', algorithms: [] }, mappingDraft(), {}),
    ).toThrow('algorithm');
  });

  it('sends bodies the signals API accepts, and only what changed', async () => {
    const f = await organizationFixture();
    const signals = f.iam.api.signals;
    const owner = await f.ownerSignIn();
    const key = generateTestKey('ES256', 'idp-key');
    const body = createSourceBody(
      f.tenantId,
      {
        ...sourceDraft(),
        name: ' Okta ',
        issuer: 'https://idp.example.test/',
        audiences: 'https://rp.example.test\nhttps://rp.example.test',
        keys: 'jwks',
        jwks: JSON.stringify({ keys: [key.publicJwk] }),
        algorithms: ['ES256'],
      },
      { ...mappingDraft(), connectionIds: 'okta\nokta', matchEmail: true },
      { 'credential-compromise': 'revoke-sessions', 'session-revoked': 'record' },
    );
    expect(body).toMatchObject({
      name: 'Okta',
      audiences: ['https://rp.example.test'],
      delivery: 'push',
      pushToken: true,
      subjects: { connectionIds: ['okta'], scimConnectionIds: [], matchEmail: true },
      actions: { 'credential-compromise': 'revoke-sessions' },
    });
    const created = await signals.createSource(owner, body);
    expect(created.pushToken).toEqual(expect.any(String));
    const source = created.source;
    expect(source).toMatchObject({ issuer: 'https://idp.example.test', hasPushToken: true });
    // A form opened on the stored source changes nothing.
    expect(sourceSettingsChange(source, sourceDraft(source))).toEqual({});
    expect(mappingChange(source, mappingDraft(source.subjects))).toBeUndefined();
    expect(
      actionsChange(source, { ...source.actions, 'account-disabled': 'record' }),
    ).toBeUndefined();

    // Switching to discovery clears the static keys.
    const discover = sourceSettingsChange(source, {
      ...sourceDraft(source),
      keys: 'discover',
      issuerAliases: 'https://idp.example.test/oauth2/default',
    });
    expect(discover).toEqual({
      issuerAliases: ['https://idp.example.test/oauth2/default'],
      jwks: null,
    });
    const discovered = await signals.updateSource(owner, {
      tenantId: f.tenantId,
      sourceId: source.id,
      ...discover,
    });
    expect(discovered.jwks).toBeUndefined();
    const byUrl = sourceSettingsChange(discovered, {
      ...sourceDraft(discovered),
      keys: 'jwksUri',
      jwksUri: 'https://idp.example.test/keys',
      algorithms: ['ES256', 'RS256'],
      requireTyp: false,
    });
    expect(byUrl).toEqual({
      jwksUri: 'https://idp.example.test/keys',
      algorithms: ['ES256', 'RS256'],
      requireTyp: false,
    });
    const fetched = await signals.updateSource(owner, {
      tenantId: f.tenantId,
      sourceId: source.id,
      ...byUrl,
    });
    expect(fetched).toMatchObject({ jwksUri: 'https://idp.example.test/keys', requireTyp: false });

    const subjects = mappingChange(fetched, {
      ...mappingDraft(fetched.subjects),
      matchEmail: false,
    });
    expect(subjects).toEqual({ connectionIds: ['okta'], scimConnectionIds: [], matchEmail: false });
    const actions = actionsChange(fetched, { 'credential-compromise': 'record' });
    expect(actions).toEqual({});
    const mapped = await signals.updateSource(owner, {
      tenantId: f.tenantId,
      sourceId: source.id,
      subjects: subjects!,
      actions: actions!,
    });
    expect(mapped.subjects.matchEmail).toBe(false);
    expect(mapped.actions).toEqual({});

    // Poll sources: the token is sent only when typed; a new endpoint needs it again.
    const poll = await signals.createSource(
      owner,
      createSourceBody(
        f.tenantId,
        {
          ...sourceDraft(),
          name: 'Partner',
          issuer: 'https://partner.example.test',
          audiences: 'acme',
          delivery: 'poll',
          pollEndpoint: 'https://partner.example.test/ssf/poll',
          pollToken: 'poll-token',
          pollMaxEvents: '10',
        },
        mappingDraft(),
        {},
      ),
    );
    expect(poll.pushToken).toBeUndefined();
    expect(poll.source.poll).toMatchObject({ maxEvents: 10, pendingAcks: 0 });
    expect(
      sourceSettingsChange(poll.source, { ...sourceDraft(poll.source), pollToken: 'rotated' }),
    ).toEqual({ poll: { token: 'rotated' } });
    const moved = sourceSettingsChange(poll.source, {
      ...sourceDraft(poll.source),
      pollEndpoint: 'https://partner.example.test/v2/poll',
    });
    expect(moved).toEqual({ poll: { endpoint: 'https://partner.example.test/v2/poll' } });
    await expect(
      signals.updateSource(owner, { tenantId: f.tenantId, sourceId: poll.source.id, ...moved }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
