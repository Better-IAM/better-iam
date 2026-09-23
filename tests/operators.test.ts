import { describe, expect, it } from 'vitest';
import {
  definePolicy,
  evaluatePolicy,
  validatePolicy,
  type PolicyDocument,
  type PolicyStatement,
} from '@better-iam/core';

const allow = (conditions: PolicyStatement['conditions']): PolicyDocument => ({
  version: 1,
  statements: [
    { effect: 'allow', actions: ['documents:read'], resources: ['document/*'], conditions },
  ],
});
const check = (document: PolicyDocument, context: Record<string, unknown>) =>
  evaluatePolicy({ action: 'documents:read', resource: 'document/1', grants: [document], context })
    .allowed;

describe('extended condition operators', () => {
  it('negated string operators succeed only when every listed value differs, and never on missing keys', () => {
    const policy = allow({
      StringNotEquals: { 'resource.classification': ['secret', 'top-secret'] },
    });
    expect(check(policy, { 'resource.classification': 'public' })).toBe(true);
    expect(check(policy, { 'resource.classification': 'secret' })).toBe(false);
    expect(check(policy, { 'resource.classification': 'top-secret' })).toBe(false);
    expect(check(policy, {})).toBe(false);
    expect(
      check(allow({ StringNotLike: { 'resource.path': 'archive/*' } }), {
        'resource.path': 'live/a',
      }),
    ).toBe(true);
    expect(
      check(allow({ StringNotLike: { 'resource.path': 'archive/*' } }), {
        'resource.path': 'archive/a',
      }),
    ).toBe(false);
    expect(
      check(allow({ StringNotEquals: { 'resource.ownerId': '${principal.id}' } }), {
        'resource.ownerId': 'a',
        'principal.id': 'b',
      }),
    ).toBe(true);
    expect(
      check(allow({ StringNotEquals: { 'resource.ownerId': '${principal.id}' } }), {
        'resource.ownerId': 'a',
        'principal.id': 'a',
      }),
    ).toBe(false);
  });

  it('case-insensitive string operators lower both sides, including substituted variables', () => {
    expect(
      check(allow({ StringEqualsIgnoreCase: { 'resource.team': 'Platform' } }), {
        'resource.team': 'PLATFORM',
      }),
    ).toBe(true);
    expect(
      check(allow({ StringNotEqualsIgnoreCase: { 'resource.team': 'Platform' } }), {
        'resource.team': 'platform',
      }),
    ).toBe(false);
    expect(
      check(allow({ StringNotEqualsIgnoreCase: { 'resource.team': 'Platform' } }), {
        'resource.team': 'Data',
      }),
    ).toBe(true);
    expect(
      check(allow({ StringLikeIgnoreCase: { 'resource.team': '${principal.team}-*' } }), {
        'resource.team': 'PLATFORM-EU',
        'principal.team': 'platform',
      }),
    ).toBe(true);
    expect(
      check(allow({ StringLikeIgnoreCase: { 'resource.team': 'plat*' } }), {
        'resource.team': 'Data',
      }),
    ).toBe(false);
  });

  it('numeric bounds and inequality', () => {
    expect(
      check(allow({ NumericLessThanEquals: { 'resource.amount': 100 } }), {
        'resource.amount': 100,
      }),
    ).toBe(true);
    expect(
      check(allow({ NumericLessThanEquals: { 'resource.amount': 100 } }), {
        'resource.amount': 101,
      }),
    ).toBe(false);
    expect(
      check(allow({ NumericGreaterThanEquals: { 'resource.amount': 100 } }), {
        'resource.amount': 100,
      }),
    ).toBe(true);
    expect(
      check(allow({ NumericGreaterThanEquals: { 'resource.amount': 100 } }), {
        'resource.amount': 99,
      }),
    ).toBe(false);
    expect(
      check(allow({ NumericNotEquals: { 'resource.amount': [1, 2] } }), { 'resource.amount': 3 }),
    ).toBe(true);
    expect(
      check(allow({ NumericNotEquals: { 'resource.amount': [1, 2] } }), { 'resource.amount': 2 }),
    ).toBe(false);
    expect(
      check(allow({ NumericNotEquals: { 'resource.amount': 2 } }), { 'resource.amount': '3' }),
    ).toBe(false);
  });

  it('network negation', () => {
    expect(
      check(allow({ NotIpAddress: { 'request.ip': ['10.0.0.0/8', '192.168.0.0/16'] } }), {
        'request.ip': '203.0.113.5',
      }),
    ).toBe(true);
    expect(
      check(allow({ NotIpAddress: { 'request.ip': ['10.0.0.0/8', '192.168.0.0/16'] } }), {
        'request.ip': '192.168.1.1',
      }),
    ).toBe(false);
    // A value that is not an address cannot be "outside" a network; negation never rescues bad input.
    expect(
      check(allow({ NotIpAddress: { 'request.ip': '10.0.0.0/8' } }), {
        'request.ip': 'not-an-address',
      }),
    ).toBe(false);
    expect(check(allow({ StringNotEquals: { 'resource.tag': 'x' } }), { 'resource.tag': 42 })).toBe(
      false,
    );
  });

  it('array membership: any of the listed values, or all of them', () => {
    const anyGroup = allow({ ArrayContains: { 'principal.groups': ['g1', 'g2'] } });
    expect(check(anyGroup, { 'principal.groups': ['g2', 'g9'] })).toBe(true);
    expect(check(anyGroup, { 'principal.groups': ['g9'] })).toBe(false);
    expect(check(anyGroup, { 'principal.groups': 'g1' })).toBe(false);
    const allGroups = allow({ ArrayContainsAll: { 'principal.groups': ['g1', 'g2'] } });
    expect(check(allGroups, { 'principal.groups': ['g2', 'g1', 'g3'] })).toBe(true);
    expect(check(allGroups, { 'principal.groups': ['g1'] })).toBe(false);
    expect(
      check(allow({ ArrayContains: { 'principal.roles': '${resource.requiredRole}' } }), {
        'principal.roles': ['r1'],
        'resource.requiredRole': 'r1',
      }),
    ).toBe(true);
    expect(
      check(allow({ ArrayContains: { 'resource.tags': [1, true] } }), { 'resource.tags': [true] }),
    ).toBe(true);
  });

  it('validates operator values and keeps the original operators intact', () => {
    expect(() =>
      validatePolicy(allow({ NumericLessThanEquals: { x: '1' as unknown as number } })),
    ).toThrow(/Invalid value/u);
    expect(() => validatePolicy(allow({ NotIpAddress: { x: '10.0.0.0/33' } }))).toThrow(
      /Invalid value/u,
    );
    expect(() => validatePolicy(allow({ ArrayContains: { x: 'a'.repeat(2049) } }))).toThrow(
      /Invalid value/u,
    );
    expect(() => validatePolicy(allow({ StringNotEquals: { x: '${bad' } }))).toThrow(
      /Malformed policy variable/u,
    );
    expect(
      definePolicy(allow({ StringEquals: { x: 'a' }, NumericLessThan: { y: 1 } })).statements,
    ).toHaveLength(1);
  });
});
