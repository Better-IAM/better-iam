import { createHash, generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const day = 86_400_000;
const sha = (value: string, length: number) =>
  createHash('sha256').update(value).digest('hex').slice(0, length);

/** A deterministic pseudo-random sequence in [0, 1). */
function sequence(seed: number) {
  let state = seed;
  return () => {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    return state / 0x7fffffff;
  };
}

/**
 * Writes `people` active identities, each directly bound to a random half of `roleCount` fresh roles, straight into
 * storage (the API would take minutes for this many). Returns each person's role IDs.
 */
async function craftRoleSets(
  f: OrganizationFixture,
  input: { people: number; roleCount: number; seed: number },
): Promise<Map<string, string[]>> {
  const { database, tenantId, ownerId } = f;
  const authority = (
    await database.find<{ id: string; identityId: string }>('grantAuthorities', { tenantId })
  ).find((item) => item.identityId === ownerId)!;
  const random = sequence(input.seed);
  const roleIds = Array.from({ length: input.roleCount }, (_, index) => `mined-role-${index}`);
  const held = new Map<string, string[]>();
  await database.transaction(async (tx) => {
    for (const [index, id] of roleIds.entries())
      await tx.insert('roles', {
        id,
        tenantId,
        name: `Role ${index}`,
        policyIds: [],
        protected: false,
        authorityId: authority.id,
        document: {
          version: 1,
          statements: [
            { effect: 'allow', actions: ['documents:read'], resources: [`doc/${index}`] },
          ],
        },
      });
    for (let person = 0; person < input.people; person++) {
      const identityId = `mined-person-${person}`;
      await tx.insert('identities', {
        id: identityId,
        tenantId,
        kind: 'user',
        status: 'active',
        email: `mined${person}@acme.test`,
        name: `Mined ${person}`,
        createdAt: f.now(),
      });
      const picked = roleIds.filter(() => random() < 0.5);
      held.set(identityId, picked);
      for (const roleId of picked)
        await tx.insert('bindings', {
          id: `mined-binding-${person}-${roleId}`,
          tenantId,
          subjectType: 'identity',
          subjectId: identityId,
          roleId,
          authorityId: authority.id,
        });
    }
  });
  return held;
}

/**
 * Bundles as role mining found them before the bitset rewrite: seeds and their pairwise intersections, holders by
 * scanning everyone, and closed sets by comparing every candidate with every other. Only for small inputs.
 */
function referenceBundles(held: Map<string, string[]>, minIdentities: number, minRoles: number) {
  const setKey = (ids: Iterable<string>) => [...ids].sort().join(',');
  const distinct = new Map<string, { roles: string[]; count: number }>();
  for (const roles of held.values()) {
    if (roles.length < minRoles) continue;
    const key = setKey(roles);
    const entry = distinct.get(key) ?? { roles: [...roles].sort(), count: 0 };
    entry.count++;
    distinct.set(key, entry);
  }
  const seeds = [...distinct.values()]
    .sort((a, b) => b.count - a.count || a.roles.join().localeCompare(b.roles.join()))
    .slice(0, 300);
  const candidates = new Map<string, string[]>();
  for (let i = 0; i < seeds.length; i++) {
    candidates.set(setKey(seeds[i]!.roles), seeds[i]!.roles);
    const first = new Set(seeds[i]!.roles);
    for (let j = i + 1; j < seeds.length; j++) {
      const common = seeds[j]!.roles.filter((roleId) => first.has(roleId));
      if (common.length >= minRoles) candidates.set(setKey(common), common);
    }
  }
  const supported = [...candidates.values()]
    .map((roles) => ({
      roles,
      holders: [...held.entries()]
        .filter(([, set]) => set.length >= minRoles && roles.every((id) => set.includes(id)))
        .map(([identityId]) => identityId),
    }))
    .filter((candidate) => candidate.holders.length >= minIdentities);
  return supported
    .filter(
      (candidate) =>
        !supported.some(
          (other) =>
            other.roles.length > candidate.roles.length &&
            other.holders.length === candidate.holders.length &&
            candidate.roles.every((roleId) => other.roles.includes(roleId)),
        ),
    )
    .map((candidate) => `${setKey(candidate.roles)}|${setKey(candidate.holders)}`)
    .sort();
}

describe('role mining stays linear and away from team groups', () => {
  it('mines hundreds of crafted role sets quickly and caps the bundles it reports', async () => {
    const f = await organizationFixture();
    await craftRoleSets(f, { people: 300, roleCount: 30, seed: 12345 });
    const started = performance.now();
    const result = await f.iam.api.roleMining.suggest(f.ownerCredential, {
      tenantId: f.tenantId,
      minIdentities: 2,
      limit: 5,
    });
    // Tens of seconds (one blocked server for every tenant) before; well under a second now.
    expect(performance.now() - started).toBeLessThan(5000);
    expect(result.bundlesTruncated).toBe(true);
    expect(result.summary.bundle).toBe(2000);
    expect(result.suggestions).toHaveLength(5);
    // The bundles kept are the ones saving the most grants, so the head of the list is unaffected by the cap.
    const savings = result.suggestions.map((suggestion) => suggestion.savings);
    expect(savings).toEqual([...savings].sort((a, b) => b - a));
    // apply recomputes the same mining inside its transaction.
    const applying = performance.now();
    await expect(
      f.iam.api.roleMining.apply(f.ownerCredential, {
        tenantId: f.tenantId,
        suggestionId: 'f'.repeat(24),
        minIdentities: 2,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(performance.now() - applying).toBeLessThan(5000);
  }, 60_000);

  it('finds exactly the bundles the pairwise algorithm found on small inputs', async () => {
    const f = await organizationFixture();
    const held = await craftRoleSets(f, { people: 40, roleCount: 8, seed: 777 });
    for (const minIdentities of [2, 3, 5]) {
      const result = await f.iam.api.roleMining.suggest(f.ownerCredential, {
        tenantId: f.tenantId,
        minIdentities,
        kinds: ['bundle'],
        limit: 500,
      });
      expect(result.bundlesTruncated).toBeUndefined();
      const found = result.suggestions
        .map(
          (bundle) =>
            `${bundle.roles
              .map((role) => role.id)
              .sort()
              .join(',')}|${bundle.identities
              .map((identity) => identity.id)
              .sort()
              .join(',')}`,
        )
        .sort();
      const expected = referenceBundles(held, minIdentities, 2);
      expect(expected.length).toBeGreaterThan(0);
      expect(found).toEqual(expected);
      for (const bundle of result.suggestions)
        expect(bundle.savings).toBe(bundle.identities.length * (bundle.roles.length - 1));
    }
  });

  it('never suggests binding a role to, or relying on, a team’s backing group', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const [ana, ben, cai] = [await f.member('ana'), await f.member('ben'), await f.member('cai')];
    const reader = await api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const writer = await api.roles.create(owner, {
      tenantId,
      name: 'Writer',
      permissions: ['documents:write'],
    });
    const direct: string[] = [];
    for (const who of [ana, ben, cai])
      direct.push(
        (
          await api.bindings.create(owner, {
            tenantId,
            roleId: reader.id,
            subjectType: 'identity',
            subjectId: who.id,
          })
        ).id,
      );
    const writerDirect = await api.bindings.create(owner, {
      tenantId,
      roleId: writer.id,
      subjectType: 'identity',
      subjectId: ana.id,
    });
    const team = await api.teams.create(owner, { tenantId, name: 'Platform' });
    for (const who of [ana, ben, cai])
      await api.teams.addMember(owner, { tenantId, teamId: team.id, identityId: who.id });
    // The team's backing group holds all three as ordinary live memberships...
    expect(await f.database.find('groupMembers', { tenantId, groupId: team.groupId })).toHaveLength(
      3,
    );
    // ...and already grants Writer, which Ana also holds directly.
    await api.bindings.create(owner, {
      tenantId,
      roleId: writer.id,
      subjectType: 'group',
      subjectId: team.groupId,
    });
    const eng = await api.groups.create(owner, { tenantId, name: 'Engineering' });
    await api.groups.addMembers(owner, {
      tenantId,
      groupId: eng.id,
      identityIds: [ana.id, ben.id, cai.id],
    });

    const { suggestions } = await api.roleMining.suggest(owner, { tenantId });
    expect(suggestions.some((suggestion) => suggestion.group?.id === team.groupId)).toBe(false);
    // Sanity: the same people in an ordinary group still yield the suggestion.
    const toEngineering = suggestions.find(
      (suggestion) => suggestion.kind === 'group-binding' && suggestion.group?.id === eng.id,
    );
    expect(toEngineering).toMatchObject({ roles: [{ id: reader.id }], applicable: true });
    expect(suggestions.some((suggestion) => suggestion.bindingIds?.includes(writerDirect.id))).toBe(
      false,
    );

    // The ID the team-group suggestion would have had is not applicable either.
    const teamSuggestion = sha(
      `group-binding:${team.groupId}:${reader.id}:${[...direct].sort().join(',')}`,
      24,
    );
    await expect(
      api.roleMining.apply(owner, { tenantId, suggestionId: teamSuggestion }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await api.roleMining.apply(owner, { tenantId, suggestionId: toEngineering!.id });
    const readerBindings = (await api.bindings.list(owner, { tenantId })).filter(
      (binding) => binding.roleId === reader.id,
    );
    expect(readerBindings).toEqual([expect.objectContaining({ subjectId: eng.id })]);
  });
});

/** Adam, an administrator with his own grant authority, binds Finn to Readers and opens an auto-closing review. */
async function autoClosingCampaign(options: { creatorExpiresInMs?: number } = {}) {
  const f = await organizationFixture();
  const { tenantId, ownerCredential: owner } = f;
  const api = f.iam.api;
  const extra =
    options.creatorExpiresInMs === undefined
      ? {}
      : { expiresAt: f.now() + options.creatorExpiresInMs };
  const readers = await api.roles.create(owner, {
    tenantId,
    name: 'Readers',
    permissions: ['documents:read'],
  });
  const admins = await api.roles.create(owner, {
    tenantId,
    name: 'Admins',
    permissions: ['iam:bindings:create', 'iam:certifications:manage', 'iam:roles:read'],
  });
  const adam = await f.member('adam', extra);
  const finn = await f.member('finn');
  const adminBinding = await api.bindings.create(owner, {
    tenantId,
    roleId: admins.id,
    subjectType: 'identity',
    subjectId: adam.id,
  });
  const authority = (await api.authorities.create(owner, {
    tenantId,
    identityId: adam.id,
    ceiling: { version: 1, statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }] },
  })) as { id: string };
  const adamToken = { token: (await f.signIn('adam')).token };
  const finnBinding = await api.bindings.create(adamToken, {
    tenantId,
    roleId: readers.id,
    subjectType: 'identity',
    subjectId: finn.id,
  });
  const campaign = await api.certifications.create(adamToken, {
    tenantId,
    name: 'Scheduled',
    roleIds: [readers.id],
    dueAt: f.now() + day,
    autoClose: true,
    undecided: 'revoke',
  });
  const close = async () => {
    f.advance(2 * day);
    const result = await f.iam.closeOverdueCertifications();
    expect(result.closed.map((entry) => entry.campaignId)).toEqual([campaign.id]);
    return {
      outcomes: result.closed[0]!.outcomes,
      finnBindingKept: (await f.database.get('bindings', finnBinding.id)) !== undefined,
    };
  };
  return { f, api, tenantId, owner, adam, authority, adminBinding, close };
}

describe('certification auto-close acts only for a creator who still could', () => {
  it('revokes nothing for a creator who was disabled and lost their authority', async () => {
    const s = await autoClosingCampaign();
    await s.api.identities.setStatus(s.owner, {
      tenantId: s.tenantId,
      identityId: s.adam.id,
      status: 'disabled',
    });
    await s.api.authorities.revoke(s.owner, { tenantId: s.tenantId, authorityId: s.authority.id });
    expect(await s.close()).toEqual({
      outcomes: { kept: 0, revoked: 0, 'already-removed': 0, 'revocation-failed': 1 },
      finnBindingKept: true,
    });
  });

  it('revokes nothing for a creator who is only disabled', async () => {
    const s = await autoClosingCampaign();
    await s.api.identities.setStatus(s.owner, {
      tenantId: s.tenantId,
      identityId: s.adam.id,
      status: 'disabled',
    });
    expect((await s.close()).outcomes['revocation-failed']).toBe(1);
  });

  it('revokes nothing for a creator who no longer holds iam:certifications:manage', async () => {
    const s = await autoClosingCampaign();
    await s.api.bindings.delete(s.owner, { tenantId: s.tenantId, bindingId: s.adminBinding.id });
    expect(await s.close()).toEqual({
      outcomes: { kept: 0, revoked: 0, 'already-removed': 0, 'revocation-failed': 1 },
      finnBindingKept: true,
    });
  });

  it('revokes nothing for a creator whose account expired', async () => {
    const s = await autoClosingCampaign({ creatorExpiresInMs: 1.5 * day });
    expect(await s.close()).toEqual({
      outcomes: { kept: 0, revoked: 0, 'already-removed': 0, 'revocation-failed': 1 },
      finnBindingKept: true,
    });
  });

  it('still revokes for a creator in good standing', async () => {
    const s = await autoClosingCampaign();
    expect(await s.close()).toEqual({
      outcomes: { kept: 0, revoked: 1, 'already-removed': 0, 'revocation-failed': 0 },
      finnBindingKept: false,
    });
  });
});

describe('analysis suppressions accept a finding as it is', () => {
  const findingId = (kind: string, key: string) => sha(`${kind}:${key}`, 24);

  it('refuses to suppress a finding before it exists', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const bot = await api.serviceAccounts.create(owner, { tenantId, name: 'deploy-bot' });
    const predicted = findingId('service-account-admin', `identity:${bot.id}`);
    await expect(
      api.analysis.suppress(owner, { tenantId, findingId: predicted, reason: 'Pre-approved' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const everything = await api.roles.create(owner, {
      tenantId,
      name: 'Everything',
      document: { version: 1, statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }] },
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: everything.id,
      subjectType: 'identity',
      subjectId: bot.id,
    });
    const report = await api.analysis.findings(owner, { tenantId });
    const finding = report.findings.find((entry) => entry.id === predicted);
    expect(finding).toMatchObject({ kind: 'service-account-admin' });
    expect(finding!.suppressed).toBeUndefined();
    // Once it exists it can be accepted.
    await api.analysis.suppress(owner, { tenantId, findingId: predicted, reason: 'Accepted' });
    const after = await api.analysis.findings(owner, { tenantId });
    expect(after.findings.some((entry) => entry.id === predicted)).toBe(false);
  });

  it('shows a suppressed finding again once it gets worse, but not as time passes', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const api = f.iam.api;
    const dan = await f.member('dan');
    const role = (name: string, permissions: string[]) =>
      api.roles.create(f.ownerCredential, { tenantId, name, permissions });
    const reader = await role('Reader', ['documents:read']);
    const writer = await role('Writer', ['documents:write']);
    await api.bindings.create(f.ownerCredential, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: dan.id,
    });
    await f.signIn('dan');
    f.advance(91 * day);
    const owner = await f.ownerSignIn();
    const id = findingId('dormant-access', `identity:${dan.id}`);
    const dormant = async () =>
      (await api.analysis.findings(owner, { tenantId, includeSuppressed: true })).findings.find(
        (entry) => entry.id === id,
      );
    expect(await dormant()).toMatchObject({ title: expect.stringContaining('91 days') });
    await api.analysis.suppress(owner, { tenantId, findingId: id, reason: 'Seasonal worker' });
    expect((await dormant())?.suppressed).toMatchObject({ reason: 'Seasonal worker' });

    // Another day of dormancy changes the title, not what was accepted.
    f.advance(day);
    expect(await dormant()).toMatchObject({
      title: expect.stringContaining('92 days'),
      suppressed: { reason: 'Seasonal worker' },
    });

    // More access on the dormant account is a different risk: it shows again.
    await api.bindings.create(owner, {
      tenantId,
      roleId: writer.id,
      subjectType: 'identity',
      subjectId: dan.id,
    });
    const worse = await dormant();
    expect(worse?.detail).toContain('2 role binding(s)');
    expect(worse?.suppressed).toBeUndefined();
    const report = await api.analysis.findings(owner, { tenantId });
    expect(report.findings.some((entry) => entry.id === id)).toBe(true);
    expect(report.summary.suppressed).toBe(0);
  });
});

describe('impact previews keep invariants from callers who may not read them', () => {
  it('reports only counts without iam:invariants:read', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const editors = await api.roles.create(owner, {
      tenantId,
      name: 'Role editors',
      permissions: [
        'iam:policies:simulate',
        'iam:roles:create',
        'iam:roles:read',
        'iam:roles:update',
        'iam:bindings:create',
      ],
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: editors.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    await api.authorities.create(owner, {
      tenantId,
      identityId: bob.id,
      ceiling: { version: 1, statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }] },
    });
    const bobToken = { token: (await f.signIn('bob')).token };
    const reader = await api.roles.create(bobToken, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    await api.bindings.create(bobToken, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const d1 = { type: 'document', id: 'd1' };
    const created = await api.invariants.create(owner, {
      tenantId,
      name: 'Alice never writes',
      subject: { identityId: alice.id },
      action: 'documents:write',
      resource: d1,
      expect: 'deny',
    });
    const preview = () =>
      api.impact.preview(bobToken, {
        tenantId,
        change: { role: { roleId: reader.id, permissions: ['documents:read', 'documents:write'] } },
        resources: [d1],
      });

    const hidden = await preview();
    expect(hidden.invariants).toEqual({
      detailed: false,
      brokenCount: 1,
      fixedCount: 0,
      broken: [],
      fixed: [],
    });
    expect(JSON.stringify(hidden)).not.toContain('Alice never writes');
    // The rest of the preview is unchanged.
    expect(hidden.gainedTotal).toBe(1);

    // Sanity: with the permission to read invariants, the details are there.
    const readers = await api.roles.create(owner, {
      tenantId,
      name: 'Invariant readers',
      permissions: ['iam:invariants:read'],
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: readers.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const shown = await preview();
    expect(shown.invariants).toMatchObject({
      detailed: true,
      brokenCount: 1,
      fixedCount: 0,
      broken: [
        {
          id: created.invariant.id,
          name: 'Alice never writes',
          mode: 'monitor',
          violations: [{ identity: { id: alice.id } }],
        },
      ],
    });
  });
});

function cardKey(kid: string) {
  const { privateKey } = generateKeyPairSync('ed25519');
  return { ...privateKey.export({ format: 'jwk' }), kid, alg: 'EdDSA', use: 'sig' };
}

describe('agents: signed cards and sponsors', () => {
  it('refuses to sign a card that carries token claims', async () => {
    const f = await organizationFixture({
      a2a: { signingKeys: [cardKey('card-1')], jwksUrl: 'https://iam.acme.test/a2a/jwks.json' },
    });
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Triage agent',
      url: 'https://agents.acme.test/triage',
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    const card = { name: 'Triage', url: 'https://agents.acme.test/a2a', version: '1.0.0' };
    const sign = (extra: Record<string, unknown>) =>
      f.iam.api.agents.signCard(
        { token: key.token },
        { tenantId: f.tenantId, agentId: agent.id, card: { ...card, ...extra } },
      );
    // What a forged delegation token would need: the person, the audience, the actor, a lifetime.
    await expect(
      sign({
        iss: 'http://localhost:3000/api/iam',
        sub: f.ownerId,
        aud: 'https://api.calendar.example',
        exp: Math.floor(f.now() / 1000) + 300,
        act: { sub: agent.id },
        tenant_id: f.tenantId,
        delegation_id: 'forged',
      }),
    ).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringContaining('sub'),
    });
    for (const claim of ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'act', 'scope', 'cnf'])
      await expect(sign({ [claim]: 'x' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Nothing was signed or listed.
    expect(await f.database.get('agentCards', agent.id)).toBeUndefined();

    // Sanity: an ordinary card is signed.
    const signed = await sign({ description: 'Sorts incoming requests' });
    expect(signed.attestation.agentId).toBe(agent.id);
    expect(Object.keys(signed.card)).not.toContain('sub');
  });

  it('lets an agent administrator name someone else as sponsor only with rights over them', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const agentAdmins = await api.roles.create(owner, {
      tenantId,
      name: 'Agent admins',
      permissions: ['iam:agents:create', 'iam:agents:update', 'iam:agents:read'],
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: agentAdmins.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const aliceToken = { token: (await f.signIn('alice')).token };

    await expect(
      api.agents.create(aliceToken, { tenantId, name: 'Billed to Bob', sponsorId: bob.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Her own agents are fine, named or by default.
    const own = await api.agents.create(aliceToken, { tenantId, name: 'Mine' });
    expect(own.agent?.sponsorId).toBe(alice.id);
    const named = await api.agents.create(aliceToken, {
      tenantId,
      name: 'Also mine',
      sponsorId: alice.id,
    });
    expect(named.agent?.sponsorId).toBe(alice.id);
    // Moving an agent onto Bob is refused; restating the current sponsor is not a change.
    await expect(
      api.agents.update(aliceToken, { tenantId, agentId: own.id, sponsorId: bob.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      api.agents.update(aliceToken, {
        tenantId,
        agentId: own.id,
        sponsorId: alice.id,
        name: 'Still mine',
      }),
    ).resolves.toMatchObject({ name: 'Still mine', agent: { sponsorId: alice.id } });
    const unchanged = await api.agents.get(owner, { tenantId, agentId: own.id });
    expect(unchanged.agent?.sponsorId).toBe(alice.id);

    // The owner may; so may Alice once she may change Bob.
    await expect(
      api.agents.create(owner, { tenantId, name: 'Bob’s', sponsorId: bob.id }),
    ).resolves.toMatchObject({ agent: { sponsorId: bob.id } });
    const people = await api.roles.create(owner, {
      tenantId,
      name: 'People admins',
      permissions: ['iam:identities:update'],
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: people.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    await expect(
      api.agents.update(aliceToken, { tenantId, agentId: own.id, sponsorId: bob.id }),
    ).resolves.toMatchObject({ agent: { sponsorId: bob.id } });
  });
});
