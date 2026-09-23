import { afterEach, describe, expect, it } from 'vitest';
import { lintPolicy, type PolicyLintContext } from '../packages/server/src/policy-lint.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

type Statement = Record<string, unknown>;
const doc = (...statements: Statement[]) => ({ version: 1, statements });
const allow = (extra: Statement = {}): Statement => ({
  effect: 'allow',
  actions: ['documents:read'],
  resources: ['documents/*'],
  ...extra,
});
const deny = (extra: Statement = {}): Statement => ({ ...allow(extra), effect: 'deny', ...extra });
/** `{statement}:{code}` for every warning, in the linter's order. */
const codes = (document: unknown, context?: PolicyLintContext) =>
  lintPolicy(document, context).warnings.map((warning) => `${warning.statement}:${warning.code}`);
const only = (code: string, document: unknown, context?: PolicyLintContext) =>
  lintPolicy(document, context).warnings.filter((warning) => warning.code === code);

describe('policy linter', () => {
  it('accepts a sound document without warnings', () => {
    expect(
      lintPolicy(
        doc(
          allow({
            conditions: {
              Bool: { 'principal.mfa': true },
              StringEquals: { 'resource.ownerId': '${principal.id}', 'principal.kind': 'user' },
              ArrayContains: { 'principal.groups': 'writers', 'resource.relations': 'editor' },
              DateBefore: { 'request.time': '2030-01-01T00:00:00Z' },
              Exists: { 'principal.authMethod': true },
            },
          }),
          allow({ actions: ['documents:write'], resources: ['documents/${principal.id}/*'] }),
        ),
      ),
    ).toEqual({ valid: true, warnings: [] });
  });

  it('reports invalid documents with the validation error and no warnings', () => {
    expect(lintPolicy({ version: 2, statements: [] })).toEqual({
      valid: false,
      error: { code: 'INVALID_POLICY', message: expect.any(String) },
      warnings: [],
    });
    expect(lintPolicy('not a policy')).toMatchObject({ valid: false, warnings: [] });
    expect(lintPolicy(doc(allow({ resources: ['documents/${broken'] })))).toMatchObject({
      valid: false,
      error: { code: 'INVALID_POLICY' },
    });
    expect(
      lintPolicy(doc(allow({ conditions: { Bool: { 'principal.mfa': 'yes' } } }))),
    ).toMatchObject({ valid: false, error: { code: 'INVALID_POLICY' } });
  });

  it('flags unrestricted administration and service-wide wildcards', () => {
    expect(codes(doc({ effect: 'allow', actions: ['*'], resources: ['*'] }))).toEqual([
      '0:unrestricted-admin',
    ]);
    expect(codes(doc({ effect: 'allow', actions: ['iam:*'], resources: ['iam/*'] }))).toEqual([
      '0:unrestricted-admin',
    ]);
    expect(
      lintPolicy(doc({ effect: 'allow', actions: ['*', 'documents:*'], resources: ['*'] }))
        .warnings,
    ).toEqual([expect.objectContaining({ code: 'unrestricted-admin', severity: 'warning' })]);
    // Conditions or scoped resources are not unrestricted.
    expect(
      codes(
        doc({
          effect: 'allow',
          actions: ['*'],
          resources: ['*'],
          conditions: { Bool: { 'principal.mfa': true } },
        }),
      ),
    ).toEqual([]);
    expect(codes(doc({ effect: 'allow', actions: ['*'], resources: ['documents/*'] }))).toEqual([]);

    const wildcard = lintPolicy(doc(allow({ actions: ['documents:*', 'documents:read'] })));
    expect(wildcard.warnings).toEqual([
      expect.objectContaining({ code: 'service-wildcard', severity: 'info', statement: 0 }),
    ]);
    expect(wildcard.warnings[0]!.message).toContain('documents:*');
    expect(
      codes(
        doc(allow({ actions: ['documents:*'], conditions: { Bool: { 'principal.mfa': true } } })),
      ),
    ).toEqual([]);
    expect(codes(doc(allow({ actions: ['documents:re*'] })))).toEqual([]);
  });

  it('flags condition keys and variables the server never sets', () => {
    const ip = only(
      'unknown-context-key',
      doc(allow({ conditions: { IpAddress: { 'request.ip': '10.0.0.0/8' } } })),
    );
    expect(ip).toEqual([expect.objectContaining({ severity: 'warning', statement: 0 })]);
    expect(ip[0]!.message).toContain(
      'request.ip is never set by the server; supply it with resolveContext',
    );
    // resource.type and resource.id do not exist even when any resource attribute is accepted.
    const type = only(
      'unknown-context-key',
      doc(allow({ conditions: { StringEquals: { 'resource.type': 'document' } } })),
    );
    expect(type[0]!.message).toContain('resource pattern');
    // A variable naming an unknown key is reported once per statement, like a condition key.
    expect(
      codes(
        doc(
          allow({
            resources: ['documents/${principal.email}'],
            conditions: { StringEquals: { 'principal.email': 'a@b.test' } },
          }),
        ),
      ),
    ).toEqual(['0:unknown-context-key']);

    const department = doc(
      allow({ conditions: { StringEquals: { 'principal.department': 'x' } } }),
    );
    expect(codes(department)).toEqual(['0:unknown-context-key']);
    expect(codes(department, { identityAttributes: { department: 'string' } })).toEqual([]);
    expect(codes(department, { contextKeys: ['principal.department'] })).toEqual([]);

    const resource = doc(
      allow({
        conditions: {
          StringEquals: { 'resource.classification': 'secret', 'resource.ownerId': 'x' },
        },
      }),
    );
    // Without a resource attribute list any resource attribute is accepted.
    expect(codes(resource)).toEqual([]);
    expect(codes(resource, { resourceAttributes: ['classification'] })).toEqual([]);
    expect(only('unknown-context-key', resource, { resourceAttributes: ['size'] })).toEqual([
      expect.objectContaining({
        message: expect.stringContaining('resource.classification'),
      }),
    ]);
  });

  it('flags denies that silently never apply when an optional key is missing', () => {
    const context = { identityAttributes: { department: 'string' as const } };
    const risky = deny({ conditions: { StringNotEquals: { 'principal.department': 'finance' } } });
    expect(codes(doc(allow(), risky), context)).toEqual(['1:optional-key-deny']);
    expect(only('optional-key-deny', doc(allow(), risky), context)[0]!.message).toContain(
      'Exists { "principal.department": false }',
    );
    // Sign-in method and resource attributes are optional too.
    expect(
      codes(
        doc(
          allow(),
          deny({
            conditions: {
              StringEquals: { 'principal.authMethod': 'password', 'resource.ownerId': 'x' },
            },
          }),
        ),
      ),
    ).toEqual(['1:optional-key-deny', '1:optional-key-deny']);
    // An Exists test in the statement, a deny for the missing case, always-present keys, and allows are fine.
    expect(
      codes(
        doc(
          allow(),
          deny({
            conditions: {
              StringNotEquals: { 'principal.department': 'finance' },
              Exists: { 'principal.department': true },
            },
          }),
        ),
        context,
      ),
    ).toEqual([]);
    expect(
      codes(
        doc(allow(), risky, deny({ conditions: { Exists: { 'principal.department': false } } })),
        context,
      ),
    ).toEqual([]);
    expect(codes(doc(allow(), deny({ conditions: { Bool: { 'principal.mfa': false } } })))).toEqual(
      [],
    );
    expect(
      codes(
        doc(allow({ conditions: { StringEquals: { 'principal.department': 'finance' } } })),
        context,
      ),
    ).toEqual([]);
  });

  it('accepts a deny for the missing-key case only when it covers the risky deny', () => {
    const context = { identityAttributes: { department: 'string' as const } };
    const risky = deny({
      actions: ['documents:delete', 'documents:write'],
      resources: ['documents/a', 'documents/b/1'],
      conditions: { StringNotEquals: { 'principal.department': 'finance' } },
    });
    const absent = (extra: Statement = {}) =>
      deny({ conditions: { Exists: { 'principal.department': false } }, ...extra });
    // Wildcards covering every action and resource make the risky deny safe.
    expect(
      codes(doc(allow(), risky, absent({ actions: ['documents:*'], resources: ['*'] })), context),
    ).toEqual([]);
    expect(
      codes(
        doc(
          absent({
            actions: ['documents:delete', 'documents:wr*'],
            resources: ['documents/a', 'documents/b/*'],
          }),
          allow(),
          risky,
        ),
        context,
      ),
    ).toEqual([]);
    // A deny with further conditions only applies to some of the requests missing the key.
    expect(
      codes(
        doc(
          allow(),
          risky,
          deny({
            actions: ['*'],
            resources: ['*'],
            conditions: {
              Exists: { 'principal.department': false },
              Bool: { 'principal.mfa': false },
            },
          }),
        ),
        context,
      ),
    ).toEqual(['1:optional-key-deny']);
    // An unrelated action, a narrower resource, or another key leaves the risky deny open.
    for (const other of [
      absent({ actions: ['iam:policies:create'], resources: ['*'] }),
      absent({ actions: ['documents:*'], resources: ['documents/archive'] }),
      absent({ actions: ['documents:*'], resources: ['documents/b/*'] }),
      deny({
        actions: ['*'],
        resources: ['*'],
        conditions: { Exists: { 'principal.authMethod': false } },
      }),
    ])
      expect(codes(doc(allow(), risky, other), context)).toEqual(['1:optional-key-deny']);
    // Covering the actions and the resources through two different denies is not enough either.
    expect(
      codes(
        doc(
          allow(),
          risky,
          absent({ actions: ['documents:*'], resources: ['documents/a'] }),
          absent({ actions: ['documents:delete'], resources: ['*'] }),
        ),
        context,
      ),
    ).toEqual(['1:optional-key-deny']);
  });

  it('flags negated operators comparing with a variable that can be missing', () => {
    const context = { identityAttributes: { department: 'string' as const } };
    const risky = allow({
      conditions: { StringNotEquals: { 'resource.department': '${principal.department}' } },
    });
    expect(codes(doc(risky), context)).toEqual(['0:negated-variable']);
    expect(
      codes(
        doc(allow({ conditions: { StringNotLike: { 'resource.ownerId': 'x-${resource.team}' } } })),
      ),
    ).toEqual(['0:negated-variable']);
    // Always-present keys, an Exists guard, and positive operators are fine.
    expect(
      codes(
        doc(allow({ conditions: { StringNotEquals: { 'resource.ownerId': '${principal.id}' } } })),
      ),
    ).toEqual([]);
    expect(
      codes(
        doc(
          allow({
            conditions: {
              StringNotEquals: { 'resource.department': '${principal.department}' },
              Exists: { 'principal.department': true },
            },
          }),
        ),
        context,
      ),
    ).toEqual([]);
    expect(
      codes(
        doc(
          allow({
            conditions: { StringEquals: { 'resource.department': '${principal.department}' } },
          }),
        ),
        context,
      ),
    ).toEqual([]);
  });

  it('flags case-insensitive patterns whose variable names contain capitals', () => {
    const context = {
      identityAttributes: { costCenter: 'string' as const, team: 'string' as const },
    };
    const risky = only(
      'ignorecase-variable',
      doc(
        allow({
          conditions: { StringLikeIgnoreCase: { 'resource.name': '${principal.costCenter}-*' } },
        }),
      ),
      context,
    );
    expect(risky).toEqual([expect.objectContaining({ severity: 'warning' })]);
    expect(risky[0]!.message).toContain('${principal.costcenter}');
    expect(
      codes(
        doc(
          allow({ conditions: { StringLike: { 'resource.name': '${principal.costCenter}-*' } } }),
        ),
        context,
      ),
    ).toEqual([]);
    expect(
      codes(
        doc(
          allow({
            conditions: { StringLikeIgnoreCase: { 'resource.name': '${principal.team}-*' } },
          }),
        ),
        context,
      ),
    ).toEqual([]);
  });

  it('flags list keys compared with scalar operators or used as variables', () => {
    expect(
      codes(doc(allow({ conditions: { StringEquals: { 'principal.groups': 'admins' } } }))),
    ).toEqual(['0:array-key-string-operator']);
    // A list key with Bool is a list problem, not a type mismatch.
    expect(codes(doc(allow({ conditions: { Bool: { 'resource.relations': true } } })))).toEqual([
      '0:array-key-string-operator',
    ]);
    expect(
      codes(
        doc(
          allow({
            conditions: {
              ArrayContains: { 'principal.groups': 'admins' },
              ArrayContainsAll: { 'principal.roles': ['a', 'b'] },
              Exists: { 'resource.parentRelations': true },
            },
          }),
        ),
      ),
    ).toEqual([]);

    expect(codes(doc(allow({ resources: ['documents/${principal.groups}'] })))).toEqual([
      '0:array-variable',
    ]);
    expect(
      codes(
        doc(allow({ conditions: { StringEquals: { 'resource.ownerId': '${principal.roles}' } } })),
      ),
    ).toEqual(['0:array-variable']);
  });

  it('flags operators that can never match the type of a known key', () => {
    const mismatches = (conditions: Statement, context?: PolicyLintContext) =>
      only('type-mismatch', doc(allow({ conditions })), context).map((warning) => warning.message);
    expect(mismatches({ Bool: { 'principal.id': true } })).toEqual([
      'Bool never matches principal.id, which holds a string.',
    ]);
    expect(mismatches({ StringEquals: { 'principal.mfa': 'true' } })).toEqual([
      'StringEquals never matches principal.mfa, which is a boolean; use Bool.',
    ]);
    expect(mismatches({ NumericEquals: { 'principal.kind': 1 } })).toHaveLength(1);
    expect(mismatches({ DateAfter: { 'principal.id': '2024-01-01T00:00:00Z' } })).toHaveLength(1);
    expect(mismatches({ ArrayContains: { 'principal.kind': 'user' } })).toHaveLength(1);
    expect(mismatches({ DateAfter: { 'request.time': '2024-01-01T00:00:00Z' } })).toEqual([]);
    // Unknown keys have no known type.
    expect(
      mismatches(
        { DateAfter: { 'session.expires': '2024-01-01T00:00:00Z' } },
        { contextKeys: ['session.expires'] },
      ),
    ).toEqual([]);
    // Identity attributes follow their declared types.
    const attributes: PolicyLintContext = {
      identityAttributes: { level: 'number', contractor: 'boolean', hiredAt: 'string' },
    };
    expect(
      mismatches(
        {
          NumericGreaterThan: { 'principal.level': 2 },
          Bool: { 'principal.contractor': false },
          DateBefore: { 'principal.hiredAt': '2024-01-01T00:00:00Z' },
        },
        attributes,
      ),
    ).toEqual([]);
    expect(
      mismatches(
        { StringEquals: { 'principal.level': '2' }, NumericEquals: { 'principal.contractor': 1 } },
        attributes,
      ),
    ).toEqual([
      'NumericEquals never matches principal.contractor, which is a boolean; use Bool.',
      'StringEquals never matches principal.level, which is a number; use a Numeric operator.',
    ]);
  });

  it('notes conditions that always hold and duplicated statements', () => {
    expect(
      lintPolicy(
        doc(
          allow({
            conditions: {
              Bool: { 'principal.mfa': [true, false] },
              Exists: { 'resource.ownerId': [false, true] },
            },
          }),
        ),
      ).warnings,
    ).toEqual([
      expect.objectContaining({ code: 'always-true-condition', severity: 'info' }),
      expect.objectContaining({ code: 'always-true-condition', severity: 'info' }),
    ]);
    expect(codes(doc(allow({ conditions: { Bool: { 'principal.mfa': true } } })))).toEqual([]);

    const first = allow({
      sid: 'Read',
      actions: ['documents:read', 'documents:write'],
      conditions: { StringEquals: { 'principal.kind': ['user', 'service'] } },
    });
    const same = allow({
      sid: 'ReadAgain',
      actions: ['documents:write', 'documents:read'],
      conditions: { StringEquals: { 'principal.kind': ['service', 'user'] } },
    });
    const duplicate = lintPolicy(doc(first, same)).warnings;
    expect(duplicate).toEqual([
      expect.objectContaining({ code: 'duplicate-statement', statement: 1, sid: 'ReadAgain' }),
    ]);
    expect(duplicate[0]!.message).toContain('statement 0 (Read)');
    expect(
      codes(
        doc(
          first,
          allow({
            actions: ['documents:read', 'documents:write'],
            conditions: { StringEquals: { 'principal.kind': 'user' } },
          }),
        ),
      ),
    ).toEqual([]);
  });

  it('flags allows that an unconditional deny always overrides', () => {
    expect(
      codes(
        doc(
          allow({ resources: ['documents/1', 'documents/team-*'] }),
          deny({ actions: ['documents:*'], resources: ['documents/*'] }),
        ),
      ),
    ).toEqual(['0:shadowed-allow']);
    // Earlier denies count too, and several denies may cover one allow together.
    const split = lintPolicy(
      doc(
        deny({ actions: ['documents:read'], resources: ['*'] }),
        deny({ actions: ['documents:write'], resources: ['*'] }),
        allow({ actions: ['documents:read', 'documents:write'] }),
      ),
    ).warnings;
    expect(split).toEqual([expect.objectContaining({ code: 'shadowed-allow', statement: 2 })]);
    expect(split[0]!.message).toContain('statement 0, 1');
    // Conditional denies, partial coverage, and wider allow patterns are not shadowed.
    expect(
      codes(
        doc(allow(), deny({ resources: ['*'], conditions: { Bool: { 'principal.mfa': false } } })),
      ),
    ).toEqual([]);
    expect(
      codes(
        doc(
          allow({ resources: ['documents/1', 'reports/1'] }),
          deny({ resources: ['documents/*'] }),
        ),
      ),
    ).toEqual([]);
    expect(
      codes(doc(allow({ resources: ['doc*'] }), deny({ resources: ['documents/*'] }))),
    ).toEqual([]);
  });

  it('bounds the shadow check on documents built to make it slow', () => {
    const timed = (document: unknown) => {
      const started = performance.now();
      const result = lintPolicy(document);
      return { result, ms: performance.now() - started };
    };
    // Repeated patterns: once took over a minute; each distinct value is now resolved once.
    const repeated = timed(
      doc(
        ...Array.from({ length: 29 }, () =>
          allow({ actions: Array(128).fill('x'), resources: Array(128).fill('x') }),
        ),
        ...Array.from({ length: 58 }, () =>
          deny({ actions: Array(128).fill('y'), resources: ['*'] }),
        ),
        deny({ actions: ['*'], resources: ['*'] }),
      ),
    );
    expect(repeated.ms).toBeLessThan(1000);
    const shadowed = repeated.result.warnings.filter((w) => w.code === 'shadowed-allow');
    expect(shadowed).toHaveLength(29);
    expect(shadowed[0]!.message).toContain('(statement 87)');

    // Distinct literal values against distinct wildcards exhaust the budget: the rest of the check is skipped.
    const distinct = timed(
      doc(
        ...Array.from({ length: 64 }, (_, i) =>
          allow({ actions: Array.from({ length: 128 }, (_, j) => `a${i}-${j}`) }),
        ),
        ...Array.from({ length: 64 }, (_, i) =>
          deny({
            actions: Array.from({ length: 128 }, (_, j) => `?${i}.${j}*z`),
            resources: ['*'],
          }),
        ),
      ),
    );
    expect(distinct.ms).toBeLessThan(1000);
    expect(distinct.result.warnings).toEqual([
      expect.objectContaining({ code: 'shadowed-allow-skipped', severity: 'info', statement: -1 }),
    ]);

    // Many patterns that do not interact are still checked in full.
    expect(
      codes(
        doc(
          ...Array.from({ length: 100 }, (_, i) =>
            allow({
              actions: Array.from({ length: 10 }, (_, j) => `service${i}:action${j}`),
              resources: [`service${i}/*`],
            }),
          ),
          ...Array.from({ length: 20 }, (_, i) =>
            deny({ actions: [`*:dangerous${i}`, `service${i}:*`], resources: [`service${i}/*`] }),
          ),
        ),
      ),
    ).toEqual(Array.from({ length: 20 }, (_, i) => `${i}:shadowed-allow`));
  });

  it('notes documents that grant nothing and orders warnings by statement and code', () => {
    expect(codes(doc(deny()))).toEqual(['-1:deny-only']);
    expect(lintPolicy(doc()).warnings).toEqual([
      expect.objectContaining({ code: 'deny-only', severity: 'info', statement: -1 }),
    ]);
    expect(codes(doc(allow(), deny()))).toEqual(['0:shadowed-allow']);

    const ordered = lintPolicy(
      doc(
        allow({ sid: 'First', conditions: { StringEquals: { 'principal.groups': 'x' } } }),
        { effect: 'allow', actions: ['*'], resources: ['*'] },
        allow({
          conditions: {
            IpAddress: { 'request.ip': '10.0.0.0/8' },
            Bool: { 'principal.id': true },
          },
        }),
      ),
    ).warnings;
    expect(ordered.map((warning) => `${warning.statement}:${warning.code}`)).toEqual([
      '0:array-key-string-operator',
      '1:unrestricted-admin',
      '2:type-mismatch',
      '2:unknown-context-key',
    ]);
    expect(ordered[0]!.sid).toBe('First');
    expect(ordered[1]).not.toHaveProperty('sid');
  });
});

describe('analysis.lintPolicy', () => {
  it('lints candidate documents and stored policies with the tenant catalog', async () => {
    const f = await organizationFixture({
      permissions: {
        actions: ['documents:read', 'documents:write'],
        identityAttributes: { department: 'string' },
      },
    });
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const api = f.iam.api.analysis;
    const network = doc(allow({ conditions: { IpAddress: { 'request.ip': '10.0.0.0/8' } } }));

    const candidate = await api.lintPolicy(owner, { tenantId, document: network });
    expect(candidate).toMatchObject({
      valid: true,
      warnings: [expect.objectContaining({ code: 'unknown-context-key', statement: 0 })],
    });
    // Keys the application supplies are declared per call; identity attributes come from configuration.
    expect(
      await api.lintPolicy(owner, { tenantId, document: network, contextKeys: ['request.ip'] }),
    ).toEqual({ valid: true, warnings: [] });
    expect(
      await api.lintPolicy(owner, {
        tenantId,
        document: doc(allow({ conditions: { StringEquals: { 'principal.department': 'x' } } })),
      }),
    ).toEqual({ valid: true, warnings: [] });

    const stored = await f.iam.api.policies.create(owner, {
      tenantId,
      name: 'Office network',
      document: network as never,
    });
    expect(await api.lintPolicy(owner, { tenantId, policyId: stored.id })).toEqual(candidate);
    await expect(
      api.lintPolicy(owner, { tenantId, policyId: 'no-such-policy' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // Structural and catalog validation turn into an invalid result without warnings. Catalog validation runs
    // first, so a document naming unknown actions is rejected before any pattern matching.
    expect(await api.lintPolicy(owner, { tenantId, document: { version: 1 } })).toMatchObject({
      valid: false,
      error: { code: 'INVALID_POLICY' },
      warnings: [],
    });
    expect(
      await api.lintPolicy(owner, {
        tenantId,
        document: doc(
          allow({
            actions: ['documents:delete'],
            conditions: { IpAddress: { 'request.ip': '10.0.0.0/8' } },
          }),
        ),
      }),
    ).toEqual({
      valid: false,
      error: { code: 'INVALID_ACTION', message: 'Unknown action documents:delete' },
      warnings: [],
    });
    expect(
      await api.lintPolicy(owner, {
        tenantId,
        document: doc(
          ...Array.from({ length: 29 }, () =>
            allow({ actions: Array(128).fill('x'), resources: Array(128).fill('x') }),
          ),
          deny({ actions: ['*'], resources: ['*'] }),
        ),
      }),
    ).toEqual({
      valid: false,
      error: { code: 'INVALID_ACTION', message: 'Unknown action x' },
      warnings: [],
    });

    // Exactly one of document and policyId.
    await expect(api.lintPolicy(owner, { tenantId })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(
      api.lintPolicy(owner, { tenantId, document: network, policyId: stored.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // Members without iam:policies:read cannot lint.
    await f.member('bob');
    const bob = await f.signIn('bob');
    await expect(
      api.lintPolicy({ token: bob.token }, { tenantId, document: network }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
    await expect(
      api.lintPolicy({ token: bob.token }, { tenantId, policyId: stored.id }),
    ).rejects.toMatchObject({ status: 403 });
  });

  it('lints stored policies full of wildcard patterns quickly, in findings too', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    // Wildcard actions pass catalog validation, so only the linter's own bounds keep this cheap.
    const hostile = await f.iam.api.policies.create(owner, {
      tenantId,
      name: 'Hostile',
      document: doc(
        ...Array.from({ length: 29 }, () =>
          allow({ actions: Array(128).fill('?'), resources: Array(128).fill('documents/x') }),
        ),
        ...Array.from({ length: 58 }, () =>
          deny({ actions: Array(128).fill('??'), resources: ['*'] }),
        ),
        deny({ actions: ['*'], resources: ['*'] }),
      ) as never,
    });
    const started = performance.now();
    const linted = await f.iam.api.analysis.lintPolicy(owner, { tenantId, policyId: hostile.id });
    expect(linted.warnings.filter((warning) => warning.code === 'shadowed-allow')).toHaveLength(29);
    const { findings } = await f.iam.api.analysis.findings(owner, { tenantId });
    expect(findings).toContainEqual(
      expect.objectContaining({
        kind: 'policy-lint',
        subject: expect.objectContaining({ id: hostile.id }),
      }),
    );
    expect(performance.now() - started).toBeLessThan(3000);
  });

  it('checks resource attributes against platform and tenant resource types without a resolver', async () => {
    const f = await organizationFixture({
      resolveResource: undefined,
      permissions: {
        mode: 'tenant-defined',
        actions: ['documents:read', 'documents:write'],
        resourceTypes: {
          folder: {
            managed: true,
            actions: ['folders:read'],
            attributes: { classification: 'string' },
          },
        },
      },
    });
    const { tenantId } = f;
    const owner = f.ownerCredential;
    await f.iam.api.resourceTypes.register(owner, {
      tenantId,
      name: 'ticket',
      actions: ['read'],
      attributes: { priority: 'number' },
    });
    const result = await f.iam.api.analysis.lintPolicy(owner, {
      tenantId,
      document: doc(
        allow({
          actions: ['folders:read', 'ticket:read'],
          resources: ['folder/*', 'ticket/*'],
          conditions: {
            StringEquals: { 'resource.classification': 'secret', 'resource.size': 'large' },
            NumericGreaterThan: { 'resource.priority': 2 },
            Exists: { 'resource.parentId': true },
          },
        }),
      ),
    });
    expect(result.valid).toBe(true);
    expect(result.warnings).toEqual([
      expect.objectContaining({
        code: 'unknown-context-key',
        message: expect.stringContaining('resource.size'),
      }),
    ]);
  });
});
