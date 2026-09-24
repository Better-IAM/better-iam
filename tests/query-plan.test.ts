import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';
import {
  describeFilter,
  evaluatePolicy,
  filterMatches,
  filterToMongo,
  filterToPrisma,
  filterToSql,
  planResources,
  type PlanInput,
  type PolicyDocument,
  type PolicyStatement,
  type ResourceFilter,
} from '@better-iam/core';

const Database = createRequire(new URL('../packages/adapter-sqlite/package.json', import.meta.url))(
  'better-sqlite3',
) as new (filename: string) => {
  exec(sql: string): void;
  prepare(sql: string): { run(...values: unknown[]): void; all(...values: unknown[]): { id: string }[] };
  close(): void;
};

const all: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }],
};

interface Row {
  id: string;
  ownerId?: string;
  env?: string;
  size?: number;
  archived?: boolean;
  parentType?: string;
  parentId?: string;
}

/** The server's decision for one resource (decisions.ts `evaluate`), from the planner's own inputs. */
function decide(input: PlanInput, row: Row): boolean {
  const { id, ...attributes } = row;
  const held = new Map<string, string[]>();
  for (const tuple of input.relations ?? []) held.set(`${tuple.type}/${tuple.id}`, tuple.relations);
  const context: Record<string, unknown> = {
    ...input.context,
    ...Object.fromEntries(
      Object.entries(attributes)
        .filter(([, value]) => value !== undefined)
        .map(([key, value]) => [`resource.${key}`, value]),
    ),
    'resource.tenantId': input.tenantId,
    'resource.relations': [...(held.get(`${input.resourceType}/${id}`) ?? [])].sort(),
    'resource.parentRelations':
      typeof row.parentType === 'string' && typeof row.parentId === 'string'
        ? [...(held.get(`${row.parentType}/${row.parentId}`) ?? [])].sort()
        : [],
  };
  const evaluation = { action: input.action, resource: `${input.resourceType}/${id}`, context };
  if (!evaluatePolicy({ ...evaluation, grants: [all, ...input.denies], boundaries: input.boundaries }).allowed)
    return false;
  return input.paths.some(
    (path) =>
      evaluatePolicy({
        ...evaluation,
        grants: path.grants,
        boundaries: [...input.boundaries, ...path.boundaries],
      }).allowed,
  );
}

/** A small seeded generator, so failures reproduce. */
function random(seed: number) {
  let state = seed >>> 0 || 1;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x100000000;
  };
  const pick = <T>(items: readonly T[]): T => items[Math.floor(next() * items.length)]!;
  return { next, pick, chance: (p: number) => next() < p };
}

const ids = ['a1', 'a2', 'b1', 'team-x', 'team-y', 'x*y', 'u-alice', 'u-bob', 'p/1', 'q'];
const owners = ['alice', 'bob', 'carol'];
const envs = ['prod', 'staging', 'Prod', 'dev'];

function randomStatement(r: ReturnType<typeof random>, effect: 'allow' | 'deny'): PolicyStatement {
  const statement: PolicyStatement = {
    effect,
    actions: [r.pick(['documents:read', 'documents:*', '*', 'documents:write', 'doc*'])],
    resources: [
      r.pick([
        'document/*',
        '*',
        'document/a*',
        'document/team-?',
        'document/u-${principal.name}',
        'doc*/1',
        'document/x\\*y',
        'folder/*',
        'document/q',
        '*/team-*',
      ]),
    ],
  };
  if (r.chance(0.7)) {
    const conditions: NonNullable<PolicyStatement['conditions']> = {};
    const count = 1 + Math.floor(r.next() * 2);
    for (let index = 0; index < count; index++) {
      const choice = r.pick([
        () => (conditions.StringEquals = { 'resource.ownerId': r.pick(['${principal.name}', 'bob', ['alice', 'carol']]) }),
        () => (conditions.StringNotEquals = { 'resource.env': r.pick(['prod', ['prod', 'dev']]) }),
        () => (conditions.StringEqualsIgnoreCase = { 'resource.env': 'PROD' }),
        () => (conditions.StringLike = { 'resource.env': r.pick(['pro*', '?ev', '*']) }),
        () => (conditions.StringNotLike = { 'resource.env': 'st*' }),
        () => (conditions.StringLikeIgnoreCase = { 'resource.env': 'PRO*' }),
        () => (conditions.NumericLessThan = { 'resource.size': r.pick([10, 100]) }),
        () => (conditions.NumericGreaterThanEquals = { 'resource.size': 50 }),
        () => (conditions.NumericNotEquals = { 'resource.size': 5 }),
        () => (conditions.Bool = { 'resource.archived': r.pick([true, false]) }),
        () => (conditions.Exists = { 'resource.ownerId': r.pick([true, false]) }),
        () => (conditions.ArrayContains = { 'resource.relations': r.pick(['editor', 'viewer']) }),
        () => (conditions.ArrayContainsAll = { 'resource.relations': ['editor', 'viewer'] }),
        () => (conditions.ArrayContains = { 'resource.parentRelations': 'owner' }),
        () => (conditions.Bool = { 'principal.mfa': r.pick([true, false]) }),
        () => (conditions.StringEquals = { 'principal.name': r.pick(['alice', 'bob']) }),
        () => (conditions.StringEquals = { 'resource.tenantId': r.pick(['t1', 't2']) }),
      ]);
      choice();
    }
    statement.conditions = conditions;
  }
  return statement;
}

function randomDocument(r: ReturnType<typeof random>, denyShare: number): PolicyDocument {
  const count = 1 + Math.floor(r.next() * 3);
  return {
    version: 1,
    statements: Array.from({ length: count }, () =>
      randomStatement(r, r.chance(denyShare) ? 'deny' : 'allow'),
    ),
  };
}

function randomInput(r: ReturnType<typeof random>): PlanInput {
  const paths = Array.from({ length: 1 + Math.floor(r.next() * 3) }, () => ({
    grants: [randomDocument(r, 0.25)],
    boundaries: r.chance(0.3) ? [randomDocument(r, 0.1)] : [],
  }));
  return {
    action: r.pick(['documents:read', 'documents:write']),
    resourceType: 'document',
    tenantId: 't1',
    context: { 'principal.name': r.pick(['alice', 'bob']), 'principal.mfa': r.chance(0.5) },
    denies: paths.flatMap((path) =>
      path.grants.map((document) => ({
        version: 1 as const,
        statements: document.statements.filter((statement) => statement.effect === 'deny'),
      })),
    ),
    boundaries: r.chance(0.3) ? [randomDocument(r, 0.2)] : [],
    paths,
    relations: [
      { type: 'document', id: 'a1', relations: ['editor'] },
      { type: 'document', id: 'b1', relations: ['editor', 'viewer'] },
      { type: 'document', id: 'team-x', relations: ['viewer'] },
      { type: 'folder', id: 'f1', relations: ['owner'] },
    ],
  };
}

function randomRow(r: ReturnType<typeof random>, id: string): Row {
  const row: Row = { id };
  if (r.chance(0.8)) row.ownerId = r.pick(owners);
  if (r.chance(0.8)) row.env = r.pick(envs);
  if (r.chance(0.8)) row.size = r.pick([1, 5, 10, 50, 99, 100, 500]);
  if (r.chance(0.7)) row.archived = r.chance(0.5);
  if (r.chance(0.5)) {
    row.parentType = r.pick(['folder', 'document']);
    row.parentId = r.pick(['f1', 'f2', 'a1']);
  }
  return row;
}

function sqlite() {
  const db = new Database(':memory:');
  db.exec(
    'CREATE TABLE document (id TEXT PRIMARY KEY, owner_id TEXT, env TEXT, size INTEGER, archived INTEGER, parent_type TEXT, parent_id TEXT)',
  );
  return db;
}
const columns: Record<string, string> = {
  id: 'id',
  ownerId: 'owner_id',
  env: 'env',
  size: 'size',
  archived: 'archived',
  parentType: 'parent_type',
  parentId: 'parent_id',
};

describe('query planning', () => {
  it('matches the policy engine on random policies and resources, in JavaScript and in SQLite', () => {
    const r = random(Number(process.env.PLAN_SEED ?? 20260924));
    const db = sqlite();
    try {
      let conditional = 0;
      for (let round = 0; round < Number(process.env.PLAN_ROUNDS ?? 400); round++) {
        const input = randomInput(r);
        const plan = planResources(input);
        const rows = ids.map((id) => randomRow(r, id));
        db.exec('DELETE FROM document');
        const insert = db.prepare(
          'INSERT INTO document (id, owner_id, env, size, archived, parent_type, parent_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
        );
        for (const row of rows)
          insert.run(
            row.id,
            row.ownerId ?? null,
            row.env ?? null,
            row.size ?? null,
            row.archived === undefined ? null : row.archived ? 1 : 0,
            row.parentType ?? null,
            row.parentId ?? null,
          );
        const expected = rows.filter((row) => decide(input, row)).map((row) => row.id).sort();
        const matched = rows
          .filter((row) => filterMatches(plan.filter, { ...row }))
          .map((row) => row.id)
          .sort();
        expect(matched, `round ${round}: ${describeFilter(plan.filter)}`).toEqual(expected);
        if (plan.kind === 'conditional') conditional++;
        // Every filter the generator produces avoids IP and array fields, so SQL must agree too.
        const where = filterToSql(plan.filter, { dialect: 'sqlite', column: (field) => columns[field] });
        const selected = db
          .prepare(`SELECT id FROM document WHERE ${where.sql}`)
          .all(...where.params)
          .map((row) => row.id)
          .sort();
        expect(selected, `round ${round} SQL: ${where.sql} ${JSON.stringify(where.params)}`).toEqual(expected);
      }
      expect(conditional).toBeGreaterThan(100);
    } finally {
      db.close();
    }
  });

  it('turns ownership, patterns, denies and relations into readable filters', () => {
    const input: PlanInput = {
      action: 'documents:read',
      resourceType: 'document',
      tenantId: 't1',
      context: { 'principal.id': 'usr_alice' },
      denies: [
        {
          version: 1,
          statements: [
            {
              effect: 'deny',
              actions: ['documents:*'],
              resources: ['document/*'],
              conditions: { StringEquals: { 'resource.classification': 'secret' } },
            },
          ],
        },
      ],
      boundaries: [],
      paths: [
        {
          grants: [
            {
              version: 1,
              statements: [
                {
                  effect: 'allow',
                  actions: ['documents:read'],
                  resources: ['document/*'],
                  conditions: { StringEquals: { 'resource.ownerId': '${principal.id}' } },
                },
                { effect: 'allow', actions: ['documents:*'], resources: ['document/public-*'] },
                {
                  effect: 'allow',
                  actions: ['documents:read'],
                  resources: ['document/*'],
                  conditions: { ArrayContains: { 'resource.relations': ['viewer', 'editor'] } },
                },
                {
                  effect: 'deny',
                  actions: ['documents:*'],
                  resources: ['document/*'],
                  conditions: { StringEquals: { 'resource.classification': 'secret' } },
                },
              ],
            },
          ],
          boundaries: [],
        },
      ],
      relations: [
        { type: 'document', id: 'shared-1', relations: ['viewer'] },
        { type: 'document', id: 'shared-2', relations: ['editor'] },
      ],
    };
    const plan = planResources(input);
    expect(plan.kind).toBe('conditional');
    expect(describeFilter(plan.filter)).toBe(
      'not (classification = "secret") and (ownerId = "usr_alice" or id like "public-*" or id in ["shared-1", "shared-2"])',
    );
    const postgres = filterToSql(plan.filter, {
      dialect: 'postgres',
      column: (field) => ({ id: 'd.id', ownerId: 'd.owner_id', classification: 'd.classification' })[field],
      offset: 2,
    });
    expect(postgres.sql).toBe(
      "((NOT (d.classification IS NOT NULL AND d.classification IN ($3))) AND ((d.owner_id IS NOT NULL AND d.owner_id IN ($4)) OR (d.id IS NOT NULL AND d.id LIKE $5 ESCAPE '\\') OR (d.id IS NOT NULL AND d.id IN ($6, $7))))",
    );
    expect(postgres.params).toEqual(['secret', 'usr_alice', 'public-%', 'shared-1', 'shared-2']);
    expect(filterToPrisma(plan.filter)).toEqual({
      AND: [
        { NOT: { AND: [{ classification: { not: null } }, { classification: { in: ['secret'] } }] } },
        {
          OR: [
            { AND: [{ ownerId: { not: null } }, { ownerId: { in: ['usr_alice'] } }] },
            { AND: [{ id: { not: null } }, { id: { startsWith: 'public-' } }] },
            { AND: [{ id: { not: null } }, { id: { in: ['shared-1', 'shared-2'] } }] },
          ],
        },
      ],
    });
    expect(filterToMongo(plan.filter, { field: (field) => (field === 'id' ? '_id' : field) })).toEqual({
      $and: [
        { $nor: [{ classification: { $in: ['secret'] } }] },
        {
          $or: [
            { ownerId: { $in: ['usr_alice'] } },
            { _id: { $regex: '^public-[\\s\\S]*$', $options: 'u' } },
            { _id: { $in: ['shared-1', 'shared-2'] } },
          ],
        },
      ],
    });
  });

  it('answers always and never when nothing depends on the resource', () => {
    const base = {
      resourceType: 'document',
      tenantId: 't1',
      context: { 'principal.mfa': true },
      denies: [],
      boundaries: [],
    };
    expect(
      planResources({
        ...base,
        action: 'documents:read',
        paths: [{ grants: [all], boundaries: [] }],
      }).kind,
    ).toBe('always');
    expect(planResources({ ...base, action: 'documents:read', paths: [] }).kind).toBe('never');
    // A condition on the principal is decided now.
    const mfaOnly: PolicyDocument = {
      version: 1,
      statements: [
        {
          effect: 'allow',
          actions: ['documents:read'],
          resources: ['document/*'],
          conditions: { Bool: { 'principal.mfa': false } },
        },
      ],
    };
    expect(
      planResources({ ...base, action: 'documents:read', paths: [{ grants: [mfaOnly], boundaries: [] }] }).kind,
    ).toBe('never');
    // A pattern for another type never matches.
    const folders: PolicyDocument = {
      version: 1,
      statements: [{ effect: 'allow', actions: ['*'], resources: ['folder/*'] }],
    };
    expect(
      planResources({ ...base, action: 'documents:read', paths: [{ grants: [folders], boundaries: [] }] }).kind,
    ).toBe('never');
  });

  it('lets rows without an attribute inherit a resource key the application context supplies', () => {
    // An application's resolveContext may set `resource.env`; the resource's own attribute overrides it.
    const input: PlanInput = {
      action: 'documents:read',
      resourceType: 'document',
      tenantId: 't1',
      context: { 'resource.env': 'prod' },
      denies: [
        {
          version: 1,
          statements: [
            {
              effect: 'deny',
              actions: ['*'],
              resources: ['document/*'],
              conditions: { StringEquals: { 'resource.env': 'prod' } },
            },
          ],
        },
      ],
      boundaries: [],
      paths: [{ grants: [all], boundaries: [] }],
    };
    const plan = planResources(input);
    for (const row of [{ id: 'a' }, { id: 'b', env: 'prod' }, { id: 'c', env: 'dev' }] as Row[])
      expect(filterMatches(plan.filter, { ...row }), row.id).toBe(decide(input, row));
    expect(filterMatches(plan.filter, { id: 'a' })).toBe(false);
    expect(filterMatches(plan.filter, { id: 'c', env: 'dev' })).toBe(true);
  });

  it('refuses row-dependent variables, resource.id conditions and oversized plans, and knows the tenant', () => {
    const plan = (statements: PolicyDocument['statements']) =>
      planResources({
        action: 'documents:read',
        resourceType: 'document',
        tenantId: 't1',
        context: { 'principal.id': 'usr_a', 'principal.team': 'red' },
        denies: [],
        boundaries: [],
        paths: [{ grants: [{ version: 1, statements }], boundaries: [] }],
      });
    const allow = { effect: 'allow' as const, actions: ['documents:read'], resources: ['document/*'] };
    for (const conditions of [
      { StringEquals: { 'principal.id': '${resource.owner}' } },
      { StringEquals: { 'resource.status': '${resource.lockedStatus}' } },
      { StringNotEquals: { 'resource.id': 'secret' } },
    ])
      expect(() => plan([{ ...allow, conditions }])).toThrow(/resource/);
    expect(() => plan([{ ...allow, resources: ['document/${resource.self}'] }])).toThrow(/resource/);
    // A row-dependent pattern for another type is irrelevant, and ${resource.tenantId} is known.
    expect(plan([allow, { ...allow, resources: ['folder/${resource.self}'] }]).kind).toBe('always');
    expect(
      plan([{ ...allow, conditions: { StringEquals: { 'principal.tenant': '${resource.tenantId}' } } }]).kind,
    ).toBe('never');
    expect(plan([{ ...allow, resources: ['document/${resource.tenantId}-*'] }]).filter).toEqual({
      kind: 'like',
      field: 'id',
      pattern: 't1-*',
    });
    // Wildcard-heavy policies hit the work budget instead of building a huge filter.
    const heavy = `${'*?'.repeat(200)}x`;
    expect(() => plan([{ ...allow, resources: Array.from({ length: 128 }, (_, n) => `${heavy}${n}`) }])).toThrow(
      /too complex/,
    );
  });

  it('keeps substituted variable values literal and refuses what a target cannot express', () => {
    const plan = planResources({
      action: 'documents:read',
      resourceType: 'document',
      tenantId: 't1',
      context: { 'principal.team': 'a*' },
      denies: [],
      boundaries: [],
      paths: [
        {
          grants: [
            {
              version: 1,
              statements: [{ effect: 'allow', actions: ['*'], resources: ['document/${principal.team}-*'] }],
            },
          ],
          boundaries: [],
        },
      ],
    });
    // The team's `*` is a literal character, not a wildcard.
    expect(plan.filter).toEqual({ kind: 'like', field: 'id', pattern: 'a\\*-*' });
    expect(filterMatches(plan.filter, { id: 'a*-report' })).toBe(true);
    expect(filterMatches(plan.filter, { id: 'abc-report' })).toBe(false);
    const sqliteWhere = filterToSql(plan.filter, { dialect: 'sqlite', column: (field) => field });
    expect(sqliteWhere.params).toEqual(['a[*]-*']);
    const ipFilter: ResourceFilter = { kind: 'ip', field: 'address', network: '10.0.0.0/8' };
    expect(() => filterToSql(ipFilter, { dialect: 'sqlite', column: (field) => field })).toThrow(
      /UNSUPPORTED|cannot be expressed/,
    );
    expect(filterMatches(ipFilter, { id: 'x', address: '10.1.2.3' })).toBe(true);
    expect(() =>
      filterToSql({ kind: 'exists', field: 'nope' }, { dialect: 'sqlite', column: () => undefined }),
    ).toThrow(/no column/);
  });
});
