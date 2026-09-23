import { describe, expect, it } from 'vitest';
import {
  definePolicy,
  evaluatePolicy,
  matchPattern,
  validatePolicy,
  type PolicyDocument,
  type PolicyStatement,
} from '@better-iam/core';

const allow = (conditions?: PolicyStatement['conditions']): PolicyDocument => ({
  version: 1,
  statements: [
    {
      effect: 'allow',
      actions: ['document:read'],
      resources: ['organization-a/document/*'],
      ...(conditions ? { conditions } : {}),
    },
  ],
});
const request = { action: 'document:read', resource: 'organization-a/document/123' };
const evaluate = (
  grants: PolicyDocument[],
  boundaries?: PolicyDocument[],
  context?: Record<string, unknown>,
) => evaluatePolicy({ ...request, grants, boundaries, context });

describe('policy evaluation', () => {
  it('denies by default and never uses boundaries as grants', () => {
    expect(evaluate([]).allowed).toBe(false);
    expect(evaluate([], [allow()]).reason).toBe('no-grant');
    expect(evaluate([allow()], [{ version: 1, statements: [] }]).reason).toBe('boundary-deny');
    expect(evaluate([allow()], [allow(), { version: 1, statements: [] }]).allowed).toBe(false);
    expect(evaluate([allow()], [allow(), allow()]).allowed).toBe(true);
  });

  it('explicit deny overrides all grants independent of order and policy category', () => {
    const deny = definePolicy({
      version: 1,
      statements: [
        { sid: 'restricted', effect: 'deny', actions: ['document:*'], resources: ['*'] },
      ],
    });
    for (const grants of [
      [allow(), deny],
      [deny, allow()],
    ])
      expect(evaluate(grants).reason).toBe('explicit-deny');
    expect(evaluate([allow()], [deny])).toMatchObject({
      allowed: false,
      reason: 'explicit-deny',
      matched: ['grant:0:0', 'boundary:0:restricted'],
    });
  });

  it('anchors wildcards and treats regular expression syntax literally', () => {
    expect(matchPattern('read', 'bread')).toBe(false);
    expect(matchPattern('read', 'reader')).toBe(false);
    expect(matchPattern('a.b[0]', 'a.b[0]')).toBe(true);
    expect(matchPattern('a.b[0]', 'axb0')).toBe(false);
    expect(matchPattern('a?c*', 'abc/def')).toBe(true);
    expect(matchPattern('a?c', 'ac')).toBe(false);
    expect(matchPattern('*a*a*a*a*b', 'a'.repeat(4000))).toBe(false);
    expect(
      evaluatePolicy({ ...request, resource: 'organization-b/document/123', grants: [allow()] })
        .allowed,
    ).toBe(false);
  });

  it('combines attributes/operators with AND and expected alternatives with OR', () => {
    const policy = allow({
      StringEquals: { department: ['engineering', 'security'], environment: 'production' },
      Bool: { mfa: true },
    });
    expect(
      evaluate([policy], undefined, {
        department: 'security',
        environment: 'production',
        mfa: true,
      }).allowed,
    ).toBe(true);
    expect(
      evaluate([policy], undefined, { department: 'security', environment: 'staging', mfa: true })
        .allowed,
    ).toBe(false);
    expect(
      evaluate([policy], undefined, {
        department: 'security',
        environment: 'production',
        mfa: 'true',
      }).allowed,
    ).toBe(false);
    expect(
      evaluate([allow({ StringLike: { team: 'engineering-*' } })], undefined, {
        team: 'engineering-platform',
      }).allowed,
    ).toBe(true);
  });

  it('does not coerce numbers, arrays, missing attributes, or inherited attributes', () => {
    expect(
      evaluate([allow({ NumericLessThan: { size: 10 } })], undefined, { size: 9 }).allowed,
    ).toBe(true);
    for (const size of ['9', NaN, Infinity, [9], null, undefined])
      expect(
        evaluate([allow({ NumericLessThan: { size: 10 } })], undefined, { size }).allowed,
      ).toBe(false);
    expect(
      evaluate(
        [allow({ NumericEquals: { size: 9 }, NumericGreaterThan: { size: 8 } })],
        undefined,
        { size: 9 },
      ).allowed,
    ).toBe(true);
    expect(evaluate([allow({ StringEquals: { toString: 'spoof' } })], undefined, {}).allowed).toBe(
      false,
    );
    expect(evaluate([allow({ Exists: { optional: false } })], undefined, {}).allowed).toBe(true);
    expect(
      evaluate([allow({ Exists: { optional: true } })], undefined, { optional: null }).allowed,
    ).toBe(true);
    expect(
      evaluate([allow({ Exists: { optional: true } })], undefined, { optional: undefined }).allowed,
    ).toBe(false);
  });

  it('compares instants and rejects invalid dates instead of calendar normalization', () => {
    const policy = allow({
      DateAfter: { time: '2026-01-01T00:00:00Z' },
      DateBefore: { time: '2026-02-01T00:00:00Z' },
    });
    expect(evaluate([policy], undefined, { time: '2026-01-15T00:00:00-08:00' }).allowed).toBe(true);
    expect(evaluate([policy], undefined, { time: '2026-01-01T00:00:00Z' }).allowed).toBe(false);
    expect(evaluate([policy], undefined, { time: '2026-02-31T00:00:00Z' }).allowed).toBe(false);
    expect(() => validatePolicy(allow({ DateBefore: { time: '2026-02-31T00:00:00Z' } }))).toThrow(
      /Invalid value/u,
    );
  });

  it.each([
    ['10.0.0.0/8', '10.255.255.255', true],
    ['10.0.0.0/8', '11.0.0.0', false],
    ['0.0.0.0/0', '255.255.255.255', true],
    ['192.0.2.1', '192.0.2.2', false],
    ['2001:db8::/32', '2001:db8:abcd::1', true],
    ['2001:db8::/32', '2001:db9::1', false],
    ['::/0', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', true],
    ['::1/128', '0:0:0:0:0:0:0:1', true],
    ['::ffff:192.0.2.0/120', '::ffff:192.0.2.10', true],
    ['::/0', '192.0.2.10', false],
    ['10.0.0.0/8', '010.0.0.1', false],
    ['::/0', 'fe80::1%eth0', false],
  ])('matches IP network %s against %s: %s', (network, address, expected) => {
    expect(
      evaluate([allow({ IpAddress: { address: network } })], undefined, { address }).allowed,
    ).toBe(expected);
  });

  it.each([
    '10.0.0.0/33',
    '10.256.0.0/8',
    '2001:db8::/129',
    '::1::2/64',
    '1:2:3:4:5:6:7:8::/64',
    '192.0.2.1/-1',
  ])('rejects malformed network %s', (network) => {
    expect(() => validatePolicy(allow({ IpAddress: { address: network } }))).toThrow();
  });

  it('substitutes policy variables from trusted context and matches substituted values literally', () => {
    const owned = definePolicy({
      version: 1,
      statements: [
        {
          effect: 'allow',
          actions: ['document:read'],
          resources: ['organization-a/document/${principal.id}/*'],
        },
      ],
    });
    const check = (resource: string, context?: Record<string, unknown>) =>
      evaluatePolicy({ action: 'document:read', resource, grants: [owned], context }).allowed;
    expect(check('organization-a/document/alice/notes', { 'principal.id': 'alice' })).toBe(true);
    expect(check('organization-a/document/bob/notes', { 'principal.id': 'alice' })).toBe(false);
    expect(check('organization-a/document/alice/notes')).toBe(false);
    expect(check('organization-a/document/alice/notes', { 'principal.id': ['alice'] })).toBe(false);
    // A value containing wildcards cannot widen the pattern.
    expect(check('organization-a/document/anyone/notes', { 'principal.id': '*' })).toBe(false);
    expect(check('organization-a/document/*/notes', { 'principal.id': '*' })).toBe(true);
    expect(matchPattern('folder/${owner}/*', 'folder/a?c/x', { owner: 'a?c' })).toBe(true);
    expect(matchPattern('folder/${owner}/*', 'folder/abc/x', { owner: 'a?c' })).toBe(false);
    expect(matchPattern('n/${count}', 'n/42', { count: 42 })).toBe(true);
    const self = allow({ StringEquals: { 'resource.ownerId': '${principal.id}' } });
    expect(
      evaluate([self], undefined, { 'resource.ownerId': 'alice', 'principal.id': 'alice' }).allowed,
    ).toBe(true);
    expect(
      evaluate([self], undefined, { 'resource.ownerId': 'alice', 'principal.id': 'bob' }).allowed,
    ).toBe(false);
    expect(evaluate([self], undefined, { 'resource.ownerId': 'alice' }).allowed).toBe(false);
    const team = allow({ StringLike: { 'resource.team': '${principal.team}-*' } });
    expect(
      evaluate([team], undefined, { 'resource.team': 'platform-eu', 'principal.team': 'platform' })
        .allowed,
    ).toBe(true);
    expect(
      evaluate([team], undefined, { 'resource.team': 'platform-eu', 'principal.team': 'plat*' })
        .allowed,
    ).toBe(false);
  });

  it('rejects malformed or misplaced policy variables at validation', () => {
    const statement = (partial: Partial<PolicyStatement>) => ({
      version: 1,
      statements: [
        { effect: 'allow', actions: ['document:read'], resources: ['document/*'], ...partial },
      ],
    });
    expect(() => validatePolicy(statement({ resources: ['document/${principal.id'] }))).toThrow(
      /Malformed policy variable/u,
    );
    expect(() => validatePolicy(statement({ resources: ['document/${bad key}'] }))).toThrow(
      /Malformed policy variable/u,
    );
    expect(() => validatePolicy(statement({ resources: ['${principal.type}/*'] }))).toThrow(
      /after the resource type/u,
    );
    expect(() => validatePolicy(statement({ actions: ['document:${verb}'] }))).toThrow(
      /not allowed in actions/u,
    );
    expect(() =>
      validatePolicy(statement({ conditions: { StringEquals: { owner: '${' } } })),
    ).toThrow(/Malformed policy variable/u);
    expect(() =>
      validatePolicy(
        statement({
          resources: ['document/${principal.id}'],
          conditions: { StringLike: { owner: '${principal.id}*' } },
        }),
      ),
    ).not.toThrow();
  });

  it('rejects invalid/unknown fields and revalidates persisted documents', () => {
    for (const document of [
      null,
      { version: 2, statements: [] },
      { version: 1, statements: [], principal: '*' },
      { version: 1, statements: [{ effect: 'ALLOW', actions: ['*'], resources: ['*'] }] },
      { version: 1, statements: [{ effect: 'allow', actions: [], resources: ['*'] }] },
      allow({ StringEquals: {} }),
      allow({ Bool: { mfa: 'true' } }),
      {
        version: 1,
        statements: [{ ...allow().statements[0], conditions: { Unknown: { x: true } } }],
      },
    ]) {
      expect(() => validatePolicy(document)).toThrow();
    }
    const mutated = allow();
    (mutated.statements[0] as unknown as Record<string, unknown>).effect = 'admin';
    expect(() => evaluate([mutated])).toThrow();
    const original = allow();
    const copy = definePolicy(original);
    original.statements[0]!.actions.push('document:delete');
    expect(copy.statements[0]!.actions).toEqual(['document:read']);
  });
});
