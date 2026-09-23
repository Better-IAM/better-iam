import { afterEach, describe, expect, it } from 'vitest';
import type { PolicyDocument, PolicyStatement } from '@better-iam/core';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { betterIam } from '@better-iam/server';
import { builtInActions, reservedPrincipalKeys } from '../packages/server/src/catalog.js';
import {
  optionalPrincipalServerKeys,
  principalServerKeys,
  reservedSessionPrincipalNames,
} from '../packages/server/src/context-keys.js';
import { parseAutoAssign } from '../packages/server/src/package-rules.js';
import { lintPolicy, type PolicyLintContext } from '../packages/server/src/policy-lint.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

/**
 * The registries that know the session-aware context keys: policy lint (known keys, types, optional keys, the tag
 * prefix and hints), the catalog (reserved identity attribute names and the new STS actions), package rules (which
 * refuse session-scoped keys), and policies.test (defaults for the always-present keys).
 */

const doc = (...statements: PolicyStatement[]): PolicyDocument => ({ version: 1, statements });
const allow = (conditions?: PolicyStatement['conditions']): PolicyStatement => ({
  effect: 'allow',
  actions: ['documents:read'],
  resources: ['documents/*'],
  ...(conditions ? { conditions } : {}),
});
const deny = (conditions?: PolicyStatement['conditions']): PolicyStatement => ({
  ...allow(conditions),
  effect: 'deny',
});
const only = (code: string, document: PolicyDocument, context?: PolicyLintContext) =>
  lintPolicy(document, context).warnings.filter((warning) => warning.code === code);

describe('policy lint', () => {
  it('knows every session key the server derives, with its type', () => {
    const conditions: PolicyStatement['conditions'] = {
      StringEquals: {
        'principal.sessionId': 'ses_1',
        'principal.sessionName': 'build-42',
        'principal.sourceIdentity': 'alice.ci',
        'principal.sourceTenantId': 't',
        'principal.webIdentityProvider': 'p',
        'principal.webIdentitySubject': 'repo:acme/app:ref:refs/heads/main',
        'principal.sessionTags.team': 'blue',
      },
      DateAfter: {
        'principal.tokenIssueTime': '2026-01-01T00:00:00Z',
        'principal.authTime': '2026-01-01T00:00:00Z',
        'principal.mfaTime': '2026-01-01T00:00:00Z',
      },
      ArrayContains: { 'principal.sessionTagKeys': 'team' },
      IpAddress: { 'request.sourceIp': '203.0.113.0/24' },
    };
    expect(lintPolicy(doc(allow(conditions)))).toEqual({ valid: true, warnings: [] });
    // Every registry key is known to the linter.
    for (const key of principalServerKeys.keys())
      expect(only('unknown-context-key', doc(allow({ Exists: { [key]: true } }))), key).toEqual([]);
  });

  it('treats only valid session tag names as known', () => {
    const unknown = only(
      'unknown-context-key',
      doc(allow({ StringEquals: { 'principal.sessionTags.bad-name': 'x' } })),
    );
    expect(unknown).toEqual([expect.objectContaining({ severity: 'warning', statement: 0 })]);
    expect(unknown[0]!.message).toContain('principal.sessionTags.bad-name');
    // An application cannot supply it either: the server removes every sessionTags key.
    expect(
      only(
        'unknown-context-key',
        doc(allow({ StringEquals: { 'principal.sessionTags.9lives': 'x' } })),
        { contextKeys: ['principal.sessionTags.9lives'] },
      ),
    ).toHaveLength(1);
    // The bare prefix is no key the server ever sets.
    expect(
      only('unknown-context-key', doc(allow({ Exists: { 'principal.sessionTags': true } }))),
    ).toHaveLength(1);
    // A valid tag is an optional string: string operators are fine, others mismatch, denies need a guard.
    expect(
      only('type-mismatch', doc(allow({ NumericEquals: { 'principal.sessionTags.team': 1 } }))),
    ).toHaveLength(1);
    expect(
      only(
        'optional-key-deny',
        doc(allow(), deny({ StringNotEquals: { 'principal.sessionTags.team': 'blue' } })),
      ),
    ).toHaveLength(1);
  });

  it('sees decisions strip an application-supplied bare principal.sessionTags', async () => {
    const f = await organizationFixture({
      resolveContext: async () => ({
        'principal.sessionTags': { team: 'blue' },
        'app.kept': 'yes',
      }),
    });
    const alice = await f.member('alice');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Bare tags',
      document: doc(
        {
          effect: 'allow',
          actions: ['documents:read'],
          resources: ['document/bare'],
          conditions: { Exists: { 'principal.sessionTags': true } },
        },
        {
          effect: 'allow',
          actions: ['documents:read'],
          resources: ['document/kept'],
          conditions: { StringEquals: { 'app.kept': 'yes' } },
        },
      ),
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const { token } = await f.signIn('alice');
    const read = async (id: string) =>
      (
        await f.iam.authorize({
          token,
          tenantId: f.tenantId,
          action: 'documents:read',
          resource: { type: 'document', id },
        })
      ).allowed;
    expect(await read('kept')).toBe(true);
    expect(await read('bare')).toBe(false);
  });

  // decisions.ts deletes the bare `principal.sessionTags` from resolveContext and plugin context before every
  // decision, so the linter must not count it as application-supplied even when contextKeys lists it.
  it('never counts the bare principal.sessionTags as application-supplied', () => {
    // Consistent with the stripping above, the linter must warn even when the application lists the bare key.
    expect(
      only('unknown-context-key', doc(allow({ Exists: { 'principal.sessionTags': true } })), {
        contextKeys: ['principal.sessionTags'],
      }),
    ).toHaveLength(1);
  });

  it('flags denies on optional session keys', () => {
    for (const key of optionalPrincipalServerKeys) {
      if (key === 'request.sourceIp') continue;
      const warnings = only(
        'optional-key-deny',
        doc(allow(), deny({ StringEquals: { [key]: 'x' } })),
      );
      expect(warnings, key).toHaveLength(1);
    }
    const name = only(
      'optional-key-deny',
      doc(allow(), deny({ StringNotEquals: { 'principal.sessionName': 'build-42' } })),
    );
    expect(name[0]!.message).toContain('Exists { "principal.sessionName": false }');
    // The always-present keys need no guard.
    expect(
      only(
        'optional-key-deny',
        doc(allow(), deny({ DateBefore: { 'principal.tokenIssueTime': '2026-01-01T00:00:00Z' } })),
      ),
    ).toEqual([]);
  });

  it('flags operators that never match the session timestamps and identifiers', () => {
    const mismatches = (conditions: PolicyStatement['conditions']) =>
      only('type-mismatch', doc(allow(conditions))).map((warning) => warning.message);
    expect(mismatches({ NumericGreaterThan: { 'principal.tokenIssueTime': 0 } })).toEqual([
      'NumericGreaterThan never matches principal.tokenIssueTime, which holds a timestamp string.',
    ]);
    expect(mismatches({ NumericLessThan: { 'principal.mfaTime': 5 } })).toHaveLength(1);
    const date = mismatches({ DateAfter: { 'principal.sessionId': '2026-01-01T00:00:00Z' } });
    expect(date).toHaveLength(1);
    for (const key of [
      'request.time',
      'principal.tokenIssueTime',
      'principal.authTime',
      'principal.mfaTime',
    ])
      expect(date[0]).toContain(key);
    expect(mismatches({ DateBefore: { 'principal.authTime': '2026-01-01T00:00:00Z' } })).toEqual(
      [],
    );
    expect(mismatches({ StringEquals: { 'principal.sessionTagKeys': 'team' } })).toEqual([]);
    expect(
      only(
        'array-key-string-operator',
        doc(allow({ StringEquals: { 'principal.sessionTagKeys': 'team' } })),
      ),
    ).toHaveLength(1);
  });

  it('points request.ip and principal.tokenIssuedAt at the server keys', () => {
    const [ip] = only(
      'unknown-context-key',
      doc(allow({ IpAddress: { 'request.ip': '10.0.0.0/8' } })),
    );
    expect(ip!.message).toContain(
      'request.ip is never set by the server; supply it with resolveContext',
    );
    expect(ip!.message).toContain(
      'or use request.sourceIp, which the server sets from the client address',
    );
    const [issued] = only(
      'unknown-context-key',
      doc(allow({ DateBefore: { 'principal.tokenIssuedAt': '2026-01-01T00:00:00Z' } })),
    );
    expect(issued!.message).toContain('or use principal.tokenIssueTime');
    // request.sourceIp is known, but optional.
    expect(
      only(
        'optional-key-deny',
        doc(allow(), deny({ IpAddress: { 'request.sourceIp': '10.0.0.0/8' } })),
      ),
    ).toHaveLength(1);
  });
});

describe('catalog', () => {
  it('reserves the session principal names as identity attributes', async () => {
    for (const name of reservedSessionPrincipalNames)
      expect(reservedPrincipalKeys.has(name)).toBe(true);
    for (const name of ['sessionName', 'sessionTags', 'mfaTime']) {
      const database = sqliteAdapter({ filename: ':memory:' });
      try {
        expect(() =>
          betterIam({
            database,
            secret: 'registries-test-secret-with-32-characters',
            baseURL: 'http://localhost:3000',
            permissions: { identityAttributes: { [name]: 'string' } },
          }),
        ).toThrow(expect.objectContaining({ code: 'INVALID_CONFIG' }));
      } finally {
        await database.close();
      }
    }
  });

  it('knows the new STS actions', async () => {
    const actions = [
      'iam:trust:update',
      'iam:roles:revoke-sessions',
      'iam:session-tokens:create',
      'iam:oidc-providers:create',
      'iam:oidc-providers:read',
      'iam:oidc-providers:update',
      'iam:oidc-providers:delete',
    ];
    for (const action of actions) expect(builtInActions).toContain(action);
    const f = await organizationFixture();
    // A role naming them validates, and decisions evaluate them rather than refusing an unknown action.
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'STS administrator',
      document: doc({ effect: 'allow', actions, resources: ['iam/*'] }),
    });
    expect(role.id).toBeDefined();
    for (const action of actions) {
      const decision = await f.iam.authorize({
        token: f.ownerCredential.token,
        tenantId: f.tenantId,
        action,
        resource: { type: 'iam', id: f.tenantId },
      });
      expect(decision.reason, action).not.toBe('UNKNOWN_ACTION');
    }
  });
});

describe('package rules', () => {
  it('refuse session-scoped keys and session tags', () => {
    for (const key of [
      'principal.sessionName',
      'principal.sessionId',
      'principal.tokenIssueTime',
      'principal.mfaTime',
      'principal.sessionTagKeys',
      'principal.sourceIdentity',
      'principal.sessionTags.team',
    ])
      expect(() =>
        parseAutoAssign(
          { include: [{ StringEquals: { [key]: 'x' } }] },
          { identityAttributes: { department: 'string' } },
        ),
      ).toThrow(`${key} describes a session or grant and is not available to package rules`);
    // Identity keys still work.
    expect(
      parseAutoAssign(
        { include: [{ StringEquals: { 'principal.department': 'eng' } }] },
        { identityAttributes: { department: 'string' } },
      ).include,
    ).toHaveLength(1);
  });
});

describe('policies.test', () => {
  it('defaults the always-present session keys, and the caller may override them', async () => {
    const f = await organizationFixture();
    const test = (statement: PolicyStatement, context?: Record<string, unknown>) =>
      f.iam.api.policies.test(f.ownerCredential, {
        tenantId: f.tenantId,
        document: doc(statement),
        action: 'documents:read',
        resource: 'documents/1',
        ...(context ? { context } : {}),
      });
    const bySession = allow({ StringEquals: { 'principal.sessionId': 'simulation' } });
    expect((await test(bySession)).allowed).toBe(true);
    expect((await test(bySession, { 'principal.sessionId': 'ses_other' })).allowed).toBe(false);
    const issued = new Date(f.now() - 1000).toISOString();
    const fresh = allow({
      DateAfter: { 'principal.tokenIssueTime': issued, 'principal.authTime': issued },
      Exists: { 'principal.sessionTagKeys': true, 'principal.mfaTime': false },
    });
    expect((await test(fresh)).allowed).toBe(true);
    expect(
      (await test(fresh, { 'principal.tokenIssueTime': '2020-01-01T00:00:00.000Z' })).allowed,
    ).toBe(false);
  });
});
