import { afterEach, describe, expect, it } from 'vitest';
import type { Identity, PolicyDocument, PolicyStatement } from '@better-iam/core';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { betterIam } from '@better-iam/server';
import { builtInActions, reservedPrincipalKeys } from '../packages/server/src/catalog.js';
import {
  optionalPrincipalServerKeys,
  principalServerKeys,
} from '../packages/server/src/context-keys.js';
import {
  parseAutoAssign,
  ruleContext,
  ruleKeys,
  ruleMatch,
  ruleWarnings,
} from '../packages/server/src/package-rules.js';
import { lintPolicy } from '../packages/server/src/policy-lint.js';
import { closeFixtures, organizationFixture } from './support/organization.js';
import { addGuest, invitationToken, otherOrganization, verifyDomain } from './support/guests.js';

afterEach(closeFixtures);

const doc = (...statements: PolicyStatement[]): PolicyDocument => ({ version: 1, statements });
const read = (id: string, conditions?: PolicyStatement['conditions']): PolicyStatement => ({
  effect: 'allow',
  actions: ['documents:read'],
  resources: [`document/${id}`],
  ...(conditions ? { conditions } : {}),
});

describe('guest keys in decisions', () => {
  it('exposes principal.guest, the sponsor and the home tenant, which applications cannot supply', async () => {
    const f = await organizationFixture({
      // An application claiming the guest keys must not satisfy (or escape) a condition.
      resolveContext: async () => ({
        'principal.guest': true,
        'principal.guestSponsorId': 'spoofed',
        'principal.homeTenantId': 'spoofed',
      }),
    });
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const globex = await otherOrganization(f, 'Globex', 'globex');
    await verifyDomain(f, globex.tenantId, 'globex.test');
    const alice = await f.member('alice');
    const everyone = await f.iam.api.groups.create(owner, { tenantId, name: 'Everyone' });
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: everyone.id,
      identityId: alice.id,
    });
    const role = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Readers',
      document: doc(
        read('shared', { Bool: { 'principal.guest': true } }),
        read('internal', { Bool: { 'principal.guest': false } }),
        read('alice-project', { StringEquals: { 'principal.guestSponsorId': alice.id } }),
        read('globex-project', { StringEquals: { 'principal.homeTenantId': globex.tenantId } }),
        read('spoofed', { StringEquals: { 'principal.guestSponsorId': 'spoofed' } }),
        read('spoofed-home', { StringEquals: { 'principal.homeTenantId': 'spoofed' } }),
      ),
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: role.id,
      subjectType: 'group',
      subjectId: everyone.id,
    });
    const gina = await addGuest(f, 'gina', { sponsorId: alice.id, groupIds: [everyone.id] });
    const gil = await f.iam.api.guests.invite(owner, {
      tenantId,
      email: 'gil@globex.test',
      groupIds: [everyone.id],
    });
    expect(gil.homeTenantId).toBe(globex.tenantId);
    const gilSession = await f.iam.api.guests.redeem({
      tenantId,
      token: await invitationToken(f, 'gil@globex.test'),
      name: 'Gil',
      password: 'a strong Gil password',
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    const documents = [
      'shared',
      'internal',
      'alice-project',
      'globex-project',
      'spoofed',
      'spoofed-home',
    ];
    const readable = async (credential: { token: string }) => {
      const allowed: string[] = [];
      for (const id of documents)
        if (
          (
            await f.iam.authorize({
              ...credential,
              tenantId,
              action: 'documents:read',
              resource: { type: 'document', id },
            })
          ).allowed
        )
          allowed.push(id);
      return allowed;
    };
    expect(await readable(gina.credential)).toEqual(['shared', 'alice-project']);
    expect(await readable({ token: gilSession.token as string })).toEqual([
      'shared',
      'globex-project',
    ]);
    expect(await readable(asAlice)).toEqual(['internal']);
    // Access analysis simulates a guest as the guest it is.
    const simulate = (identityId: string, id: string) =>
      f.iam.api.policies.simulate(owner, {
        tenantId,
        identityId,
        action: 'documents:read',
        resource: { type: 'document', id },
      });
    expect((await simulate(gina.identity.id, 'shared')).allowed).toBe(true);
    expect((await simulate(gina.identity.id, 'internal')).allowed).toBe(false);
    expect((await simulate(alice.id, 'shared')).allowed).toBe(false);
    // Once a member, the person is treated as one at once, with the same session.
    await f.iam.api.guests.convertToMember(owner, { tenantId, identityId: gina.identity.id });
    expect(await readable(gina.credential)).toEqual(['internal']);
    // A new sponsor is seen at once too.
    await f.iam.api.guests.setSponsor(owner, {
      tenantId,
      identityId: gilSession.identity.id,
      sponsorId: alice.id,
    });
    expect(await readable({ token: gilSession.token as string })).toEqual([
      'shared',
      'alice-project',
      'globex-project',
    ]);
  });

  it('bounds every guest by the tenant’s guest boundary', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const broad = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Broad',
      permissions: ['documents:read', 'documents:write'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: broad.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const gina = await addGuest(f, 'gina', { roleIds: [broad.id] });
    const asAlice = { token: (await f.signIn('alice')).token };
    const may = async (credential: { token: string }, action: string, id: string) =>
      (
        await f.iam.authorize({
          ...credential,
          tenantId,
          action,
          resource: { type: 'document', id },
        })
      ).allowed;
    const matrix = async (credential: { token: string }) => [
      await may(credential, 'documents:read', 'shared-plan'),
      await may(credential, 'documents:read', 'payroll'),
      await may(credential, 'documents:write', 'shared-plan'),
    ];
    expect(await matrix(gina.credential)).toEqual([true, true, true]);
    await f.iam.api.guests.configure(owner, {
      tenantId,
      guestBoundary: doc({
        effect: 'allow',
        actions: ['documents:read'],
        resources: ['document/shared-*'],
      }),
    });
    expect(await matrix(gina.credential)).toEqual([true, false, false]);
    // Members are not bounded by it.
    expect(await matrix(asAlice)).toEqual([true, true, true]);
    expect(
      (
        await f.iam.api.policies.simulate(owner, {
          tenantId,
          identityId: gina.identity.id,
          action: 'documents:read',
          resource: { type: 'document', id: 'payroll' },
        })
      ).allowed,
    ).toBe(false);
    // Nor is a converted guest; and removing the boundary frees the remaining guests.
    const hal = await addGuest(f, 'hal', { roleIds: [broad.id] });
    expect(await matrix(hal.credential)).toEqual([true, false, false]);
    await f.iam.api.guests.convertToMember(owner, { tenantId, identityId: hal.identity.id });
    expect(await matrix(hal.credential)).toEqual([true, true, true]);
    await f.iam.api.guests.configure(owner, { tenantId, guestBoundary: null });
    expect(await matrix(gina.credential)).toEqual([true, true, true]);
  });
});

describe('guest keys in the registries', () => {
  it('are known to policy lint, filled in by policies.test, and reserved as attribute names', async () => {
    expect(principalServerKeys.get('principal.guest')).toBe('boolean');
    expect(principalServerKeys.get('principal.guestSponsorId')).toBe('identifier');
    expect(principalServerKeys.get('principal.homeTenantId')).toBe('identifier');
    expect(optionalPrincipalServerKeys.has('principal.guest')).toBe(false);
    expect(lintPolicy(doc(read('a', { Bool: { 'principal.guest': true } })))).toEqual({
      valid: true,
      warnings: [],
    });
    expect(
      lintPolicy(
        doc(
          read('a', {
            StringEquals: { 'principal.guestSponsorId': 'usr_1', 'principal.homeTenantId': 't' },
          }),
        ),
      ).warnings,
    ).toEqual([]);
    // The sponsor and home tenant are absent for members, so a deny on them needs a guard; principal.guest does not.
    const optionalDeny = (conditions: PolicyStatement['conditions']) =>
      lintPolicy(doc(read('a'), { ...read('a', conditions), effect: 'deny' })).warnings.filter(
        (warning) => warning.code === 'optional-key-deny',
      );
    expect(optionalDeny({ StringNotEquals: { 'principal.guestSponsorId': 'x' } })).toHaveLength(1);
    expect(optionalDeny({ StringNotEquals: { 'principal.homeTenantId': 'x' } })).toHaveLength(1);
    expect(optionalDeny({ Bool: { 'principal.guest': true } })).toEqual([]);

    const f = await organizationFixture();
    const test = (statement: PolicyStatement, context?: Record<string, unknown>) =>
      f.iam.api.policies.test(f.ownerCredential, {
        tenantId: f.tenantId,
        document: doc(statement),
        action: 'documents:read',
        resource: 'document/a',
        ...(context ? { context } : {}),
      });
    const members = read('a', { Bool: { 'principal.guest': false } });
    expect((await test(members)).allowed).toBe(true);
    expect((await test(members, { 'principal.guest': true })).allowed).toBe(false);
    expect(
      (
        await test(read('a', { StringEquals: { 'principal.guestSponsorId': 'usr_1' } }), {
          'principal.guest': true,
          'principal.guestSponsorId': 'usr_1',
        })
      ).allowed,
    ).toBe(true);

    for (const name of ['guest', 'guestSponsorId', 'homeTenantId']) {
      expect(reservedPrincipalKeys.has(name)).toBe(true);
      const database = sqliteAdapter({ filename: ':memory:' });
      try {
        expect(() =>
          betterIam({
            database,
            secret: 'guests-policies-secret-with-32-characters',
            baseURL: 'http://localhost:3000',
            permissions: { identityAttributes: { [name]: 'string' } },
          }),
        ).toThrow(expect.objectContaining({ code: 'INVALID_CONFIG' }));
      } finally {
        await database.close();
      }
    }
    for (const action of ['read', 'invite', 'manage', 'settings'])
      expect(builtInActions).toContain(`iam:guests:${action}`);
  });
});

describe('guests and birthright packages', () => {
  it('reaches guests only through rules that test identity.guest', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const guestSpace = await f.iam.api.groups.create(owner, { tenantId, name: 'Guest space' });
    const staffSpace = await f.iam.api.groups.create(owner, { tenantId, name: 'Staff space' });
    const lounge = await f.iam.api.groups.create(owner, { tenantId, name: 'Lounge' });
    const people = { StringEquals: { 'principal.kind': 'user' } } as const;
    const guestKit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Guest kit',
      groupIds: [guestSpace.id],
      autoAssign: { include: [{ ...people, Bool: { 'identity.guest': true } }] },
    });
    const staffKit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Staff kit',
      groupIds: [staffSpace.id],
      autoAssign: { include: [people] },
    });
    const loungeKit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Lounge kit',
      groupIds: [lounge.id],
      autoAssign: { include: [people], exclude: [{ Bool: { 'identity.guest': true } }] },
    });
    const holders = async (packageId: string) =>
      (
        await f.iam.api.packages.listAssignments(owner, {
          tenantId,
          packageId,
          source: 'automatic',
        })
      )
        .map((assignment) => assignment.identityId)
        .sort();
    const gina = await addGuest(f, 'gina');
    // Redemption applies the rules at once.
    expect(await holders(guestKit.id)).toEqual([gina.identity.id]);
    expect(await holders(staffKit.id)).toEqual([alice.id, f.ownerId].sort());
    expect(await holders(loungeKit.id)).toEqual([alice.id, f.ownerId].sort());
    // A rule that tests identity.guest in one clause only lets guests match its other clauses too, and says so.
    const preview = await f.iam.api.packages.previewAutoAssign(owner, {
      tenantId,
      autoAssign: {
        include: [
          { ...people, Bool: { 'identity.guest': true } },
          { StringEquals: { 'principal.kind': 'user', 'identity.email': 'nobody@x.test' } },
        ],
      },
    });
    expect(preview.keys).toContainEqual({
      key: 'identity.guest',
      type: 'boolean',
      operators: ['Bool', 'Exists'],
    });
    expect(preview.sample.map((match) => match.identityId)).toEqual([gina.identity.id]);
    expect(preview.warnings).toContain(
      'include[1] does not test identity.guest while the rule does elsewhere, so it also matches guests',
    );
    const staffPreview = await f.iam.api.packages.previewAutoAssign(owner, {
      tenantId,
      packageId: staffKit.id,
    });
    expect(staffPreview.sample.map((match) => match.identityId)).not.toContain(gina.identity.id);
    expect(staffPreview.warnings.join(' ')).not.toContain('identity.guest');
    // Conversion makes the person a member for the rules as well.
    await f.iam.api.guests.convertToMember(owner, { tenantId, identityId: gina.identity.id });
    expect(await holders(guestKit.id)).toEqual([]);
    expect(await holders(staffKit.id)).toEqual([alice.id, f.ownerId, gina.identity.id].sort());
    expect(await holders(loungeKit.id)).toEqual([alice.id, f.ownerId, gina.identity.id].sort());
  });

  it('knows identity.guest in the rule language', () => {
    expect(ruleKeys({})).toContainEqual({
      key: 'identity.guest',
      type: 'boolean',
      operators: ['Bool', 'Exists'],
    });
    expect(() =>
      parseAutoAssign(
        { include: [{ StringEquals: { 'identity.guest': 'true' } }] },
        {
          identityAttributes: {},
        },
      ),
    ).toThrow('StringEquals cannot test identity.guest (boolean); use Bool, Exists');
    expect(() =>
      parseAutoAssign(
        { include: [{ Bool: { 'identity.visitor': true } }] },
        {
          identityAttributes: {},
        },
      ),
    ).toThrow(/identity\.guest/);
    const person = {
      id: 'usr_1',
      tenantId: 't',
      kind: 'user',
      name: 'Gina',
      email: 'gina@partner.test',
      emailVerified: true,
      status: 'active',
      owner: false,
      rootAdmin: false,
      createdAt: 0,
    } as unknown as Identity;
    const guest = { ...person, guest: { sponsorId: 'usr_2', since: 0 } } as Identity;
    expect(ruleContext(guest, [])['identity.guest']).toBe(true);
    expect(ruleContext(person, [])['identity.guest']).toBe(false);
    const compile = (rule: Parameters<typeof ruleWarnings>[0]) => ({
      version: 1 as const,
      statements: [
        ...rule.include.map((conditions, index) => ({
          sid: `include-${index}`,
          effect: 'allow' as const,
          actions: ['auto-assign'],
          resources: ['identity/*'],
          conditions,
        })),
        ...(rule.exclude ?? []).map((conditions, index) => ({
          sid: `exclude-${index}`,
          effect: 'deny' as const,
          actions: ['auto-assign'],
          resources: ['identity/*'],
          conditions,
        })),
      ],
    });
    const members = compile({ include: [{ StringEquals: { 'principal.kind': 'user' } }] });
    expect(ruleMatch(members, person, ruleContext(person, [])).matched).toBe(true);
    expect(ruleMatch(members, guest, ruleContext(guest, []))).toEqual({
      matched: false,
      matchedBy: [],
      excludedBy: [],
    });
    const guests = compile({
      include: [{ StringEquals: { 'principal.kind': 'user' }, Bool: { 'identity.guest': true } }],
    });
    expect(ruleMatch(guests, guest, ruleContext(guest, []))).toEqual({
      matched: true,
      matchedBy: ['include-0'],
      excludedBy: [],
    });
    expect(ruleMatch(guests, person, ruleContext(person, [])).matched).toBe(false);
    expect(
      ruleWarnings({ include: [{ StringEquals: { 'principal.kind': 'user' } }] }).join(' '),
    ).not.toContain('identity.guest');
  });
});
