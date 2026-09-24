import { describe, expect, it } from 'vitest';
import { evaluatePolicy, matchPattern, type PolicyDocument } from '@better-iam/core';

const allowAllFiles: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'allow', actions: ['files:read'], resources: ['file/*'] }],
};
const denyShared: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'deny', actions: ['files:read'], resources: ['file/shared/*'] }],
};

describe('glob matching with literal wildcard characters in the value', () => {
  it('lets a pattern wildcard match a literal `*` in the value', () => {
    expect(matchPattern('file/shared/*', 'file/shared/*evil')).toBe(true);
    expect(matchPattern('*', '*abc')).toBe(true);
    expect(matchPattern('a*c', 'a*c')).toBe(true);
    expect(matchPattern('a*c', 'a**c')).toBe(true);
    expect(matchPattern('file/*/x', 'file/*/x')).toBe(true);
    expect(matchPattern('file/shared/*', 'file/other/*')).toBe(false);
  });

  it('keeps a Deny in force for resource ids that contain `*`', () => {
    for (const id of ['file/shared/*evil', 'file/shared/*', 'file/shared/a*b'])
      expect(
        evaluatePolicy({
          action: 'files:read',
          resource: id,
          grants: [allowAllFiles, denyShared],
        }),
      ).toMatchObject({ allowed: false, reason: 'explicit-deny' });
  });

  it('keeps StringNotLike true only for values outside the pattern', () => {
    const decision = (value: string) =>
      evaluatePolicy({
        action: 'files:read',
        resource: 'file/a',
        context: { 'resource.path': value },
        grants: [
          {
            version: 1,
            statements: [
              {
                effect: 'allow',
                actions: ['files:read'],
                resources: ['*'],
                conditions: { StringNotLike: { 'resource.path': 'internal/*' } },
              },
            ],
          },
        ],
      }).allowed;
    expect(decision('internal/*x')).toBe(false);
    expect(decision('public/x')).toBe(true);
  });

  it('counts `?` as one character for astral code points, as the variable path does', () => {
    expect(matchPattern('doc/?', 'doc/😀')).toBe(true);
    expect(matchPattern('doc/??', 'doc/😀')).toBe(false);
    expect(matchPattern('doc/${principal.team}/?', 'doc/red/😀', { 'principal.team': 'red' })).toBe(
      true,
    );
    expect(
      evaluatePolicy({
        action: 'files:read',
        resource: 'doc/😀',
        grants: [
          {
            version: 1,
            statements: [
              { effect: 'allow', actions: ['files:read'], resources: ['doc/*'] },
              { effect: 'deny', actions: ['files:read'], resources: ['doc/?'] },
            ],
          },
        ],
      }),
    ).toMatchObject({ allowed: false, reason: 'explicit-deny' });
  });

  it('matches long star patterns against long values in near-linear time', () => {
    const started = performance.now();
    const pattern = `*${'a'.repeat(2000)}b`;
    const decision = evaluatePolicy({
      action: 'files:read',
      resource: 'file/x',
      context: { 'resource.name': 'a'.repeat(100_000) },
      grants: [
        {
          version: 1,
          statements: [
            {
              effect: 'allow',
              actions: ['files:read'],
              resources: ['*'],
              conditions: { StringLike: { 'resource.name': Array(64).fill(pattern) } },
            },
          ],
        },
      ],
    });
    expect(decision.allowed).toBe(false);
    expect(performance.now() - started).toBeLessThan(1000);
    expect(matchPattern(pattern, `${'a'.repeat(100_000)}b`)).toBe(true);
  });

  it('refuses, quickly, an evaluation that would take too much matching work', () => {
    const started = performance.now();
    const decision = evaluatePolicy({
      action: 'files:read',
      resource: 'file/x',
      context: { 'resource.name': 'a'.repeat(100_000) },
      grants: [
        allowAllFiles,
        {
          version: 1,
          statements: [
            {
              effect: 'allow',
              actions: ['files:read'],
              resources: ['*'],
              conditions: {
                StringLike: { 'resource.name': Array(64).fill(`*${'?'.repeat(1000)}b`) },
              },
            },
          ],
        },
      ],
    });
    expect(decision).toMatchObject({ allowed: false, reason: 'evaluation-limit' });
    expect(performance.now() - started).toBeLessThan(2000);
    // The limit is per evaluation: the next one starts afresh, and matching outside an evaluation is unbounded.
    expect(
      evaluatePolicy({ action: 'files:read', resource: 'file/a', grants: [allowAllFiles] }).allowed,
    ).toBe(true);
    expect(matchPattern('*?b', `${'a'.repeat(5000)}b`)).toBe(true);
  });

  it('keeps ordinary wildcard semantics', () => {
    expect(matchPattern('file/*', 'file/')).toBe(true);
    expect(matchPattern('file/*', 'file')).toBe(false);
    expect(matchPattern('f?le/*.txt', 'file/a/b.txt')).toBe(true);
    expect(matchPattern('f?le/*.txt', 'file/a/b.txd')).toBe(false);
    expect(matchPattern('*a*b*', 'xxaxxbxx')).toBe(true);
    expect(matchPattern('*a*b*', 'xxbxxaxx')).toBe(false);
    expect(matchPattern('', '')).toBe(true);
    expect(matchPattern('*', '')).toBe(true);
    expect(matchPattern('?', '')).toBe(false);
  });
});
