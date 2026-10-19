// Vectors for @better-iam/core: canonical JSON, the audit chain, the policy engine, query planning and its filter
// compilers, storage planning and SQL, PostgreSQL value encoding, snapshots, shared signals, classification.
import { dist } from '../util.mjs';
import { VectorFile } from './context.mjs';

const NOW = 1767225600000; // 2026-01-01T00:00:00.000Z

async function jcs(output, core) {
  const file = new VectorFile('jcs', {
    description:
      'RFC 8785 JSON Canonicalization Scheme (canonicalizeJson): members sorted by UTF-16 code units at every depth, ECMAScript shortest number form, JSON.stringify string escaping, no whitespace. undefined members are dropped and undefined array entries become null; NaN, Infinity and bigints throw TypeError. Output is the exact string.',
    source: 'packages/core/src/jcs.ts#canonicalizeJson',
  });
  const cases = [
    ['null', null],
    ['true', true],
    ['false', false],
    ['zero', 0],
    ['negative zero', -0],
    ['integer', 123],
    ['negative', -45],
    ['float', 0.1],
    ['float sum', 0.1 + 0.2],
    ['exponent large', 1e21],
    ['below exponent threshold', 1e20],
    ['exponent small', 1e-7],
    ['small non-exponent', 0.000001],
    ['max safe integer', Number.MAX_SAFE_INTEGER],
    ['beyond safe integer', 2 ** 53 + 2],
    ['max value', Number.MAX_VALUE],
    ['min value', Number.MIN_VALUE],
    ['rfc 8785 numbers', [333333333.33333329, 1e30, 4.5, 0.002, 1e-27]],
    ['empty string', ''],
    ['ascii string', 'hello'],
    ['escapes', 'quote " backslash \\ slash / tab \t newline \n cr \r bs \b ff \f'],
    ['control characters', '\u0000\u0001\u001f\u007f'],
    ['line separators', '\u2028\u2029'],
    ['unicode', 'café ü 日本 €'],
    ['astral', '😀 𝄞'],
    ['lone high surrogate', '\ud800'],
    ['lone low surrogate', 'a\udc00b'],
    ['empty object', {}],
    ['empty array', []],
    ['key order', { b: 1, a: 2, c: { z: 1, y: [3, { k: 1, j: 2 }] } }],
    ['integer-like keys', { 10: 'ten', 2: 'two', a: 'a', 1: 'one' }],
    [
      'utf-16 key order',
      {
        '\u20ac': 'euro',
        '\r': 'cr',
        ö: 'o-umlaut',
        '😀': 'emoji',
        '\ufb33': 'hebrew',
        1: 'one',
        '\u0080': 'c1',
      },
    ],
    ['undefined members dropped', { a: undefined, b: 1 }],
    ['undefined array entries', [1, undefined, 3]],
    ['nested arrays', [[], [[]], [1, [2, [3]]]]],
    [
      'rfc 8785 example',
      {
        numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
        string: '\u20ac$\u000f\u000aA\'\u0042\u0022\u005c\\"/',
        literals: [null, true, false],
      },
    ],
    ['NaN', NaN],
    ['Infinity', Infinity],
    ['negative Infinity', -Infinity],
    ['bigint', 10n],
    ['undefined top level', undefined],
    ['NaN inside object', { a: NaN }],
  ];
  for (const [name, value] of cases)
    await file.add(name, { value }, (input) => core.canonicalizeJson(input.value));
  return file.write(output);
}

async function canonical(output, core) {
  const file = new VectorFile('canonical-json', {
    description:
      'canonicalJson (audit hashing, receipts, evidence): JSON.stringify with every plain object rebuilt with its keys sorted by `<` (UTF-16 code units) and undefined members removed. Because it rebuilds JavaScript objects, integer-like keys ("1", "10") still come first in ascending numeric order, unlike RFC 8785. Arrays keep their order; undefined array entries become null; non-finite numbers become null.',
    source: 'packages/core/src/audit.ts#canonicalJson',
  });
  for (const [name, value] of [
    ['primitives', [null, true, 1, 'x']],
    ['key order', { b: 1, a: 2, c: { z: 1, y: 2 } }],
    ['integer-like keys first', { b: 1, 10: 'ten', 2: 'two', a: 2, '01': 'zero-one' }],
    ['utf-16 key order', { '\u20ac': 1, ö: 2, '😀': 3, '\ufb33': 4, A: 5, a: 6 }],
    ['undefined members dropped', { a: undefined, b: { c: undefined, d: 1 } }],
    ['undefined array entries', [1, undefined, 3]],
    ['non-finite numbers', { a: NaN, b: Infinity }],
    ['nested arrays of objects', [{ b: 1, a: 2 }, [{ d: 1, c: 2 }]]],
    ['empty', {}],
    [
      'audit event',
      {
        id: 'evt_1',
        tenantId: 'tnt_1',
        actorId: 'idn_1',
        action: 'iam:groups:create',
        resourceId: 'grp_1',
        outcome: 'allow',
        rootOverride: false,
        timestamp: NOW,
        metadata: { z: 1, a: [2, 1] },
      },
    ],
  ])
    await file.add(name, { value }, (input) => core.canonicalJson(input.value));
  return file.write(output);
}

/** A minimal in-memory IamStore for functions that read and write a few records. */
function memoryStore() {
  const rows = new Map();
  const keyOf = (collection, id) => `${collection}\u0000${id}`;
  return {
    rows,
    async get(collection, id) {
      const value = rows.get(keyOf(collection, id));
      return value === undefined ? undefined : structuredClone(value);
    },
    async insert(collection, record) {
      const key = keyOf(collection, record.id);
      if (rows.has(key)) throw new Error('duplicate');
      rows.set(key, structuredClone(record));
      return record;
    },
    async put(collection, record) {
      rows.set(keyOf(collection, record.id), structuredClone(record));
      return record;
    },
    async find(collection, filter = {}) {
      return [...rows.entries()]
        .filter(([key]) => key.startsWith(`${collection}\u0000`))
        .map(([, value]) => value)
        .filter((record) =>
          Object.entries(filter).every(([field, value]) => record[field] === value),
        );
    },
  };
}

async function auditChain(output, core) {
  const file = new VectorFile('audit-chain', {
    description:
      'Audit hash chain. hash = lowercase hex SHA-256 of canonicalJson(event without `hash`); the first event of a tenant has sequence 1 and previousHash = 64 zeros; each next event has sequence + 1 and previousHash = the previous hash. The chain head lives in auditChains (id = tenantId: { id, tenantId, sequence, hash, updatedAt = event.timestamp }). verifyAuditChain sorts by sequence and reports the first failure.',
    source:
      'packages/core/src/audit.ts#auditEventHash,chainAuditEvent,appendAuditEvent,verifyAuditChain',
    notes: { genesis: core.auditGenesis },
  });
  const event = (n, overrides = {}) => ({
    id: `evt_${String(n).padStart(2, '0')}`,
    tenantId: 'tnt_01',
    actorId: 'idn_01',
    action: 'iam:groups:create',
    resourceId: `grp_${n}`,
    outcome: 'allow',
    rootOverride: false,
    timestamp: NOW + n * 1000,
    ...overrides,
  });
  for (const [name, value] of [
    ['hash minimal event', event(1)],
    [
      'hash with metadata and session context',
      event(2, {
        metadata: { name: 'Eng', tags: ['b', 'a'], nested: { z: 1, a: 2 } },
        sessionContext: { kind: 'role', roleId: 'role_01', sessionName: 'deploy' },
        originalActorId: 'idn_00',
        impersonatorId: 'idn_root',
      }),
    ],
    ['hash with chain fields', event(3, { sequence: 3, previousHash: 'a'.repeat(64) })],
    [
      'hash ignores hash field',
      event(3, { sequence: 3, previousHash: 'a'.repeat(64), hash: 'ignored' }),
    ],
    ['hash with unicode', event(4, { metadata: { name: 'Ingeniería ✓ 😀' } })],
    ['hash with deny outcome', event(5, { outcome: 'deny', rootOverride: true })],
  ])
    await file.add(name, { event: value }, (input) => core.auditEventHash(input.event));
  // A chain built with appendAuditEvent over a store.
  const store = memoryStore();
  const chained = [];
  const run = [
    event(1),
    event(2, { tenantId: 'tnt_02' }),
    event(3),
    event(4, { metadata: { a: 1 } }),
    event(5, { tenantId: 'tnt_02' }),
    event(6),
  ];
  for (const [index, value] of run.entries()) {
    const result = await file.add(
      `append ${index + 1} (${value.tenantId})`,
      { event: value },
      async (input) => {
        const appended = await core.appendAuditEvent(store, input.event);
        const head = await store.get('auditChains', input.event.tenantId);
        return { event: appended, head };
      },
    );
    chained.push(result.event);
  }
  const tenant1 = chained.filter((item) => item.tenantId === 'tnt_01');
  const head = { sequence: tenant1.at(-1).sequence, hash: tenant1.at(-1).hash };
  const verify = (input) => core.verifyAuditChain(input.events, input.options ?? {});
  const tamper = (list, index, patch) =>
    list.map((item, at) => (at === index ? { ...item, ...patch } : item));
  for (const [name, input] of [
    ['verify whole chain against head', { events: tenant1, options: { head } }],
    ['verify unordered input', { events: [...tenant1].reverse(), options: { head } }],
    ['verify run without head', { events: tenant1.slice(1) }],
    [
      'verify run with explicit previous hash',
      { events: tenant1.slice(1), options: { previousHash: tenant1[0].hash } },
    ],
    [
      'verify run with wrong previous hash',
      { events: tenant1.slice(1), options: { previousHash: 'f'.repeat(64) } },
    ],
    [
      'verify tampered field',
      { events: tamper(tenant1, 1, { resourceId: 'grp_x' }), options: { head } },
    ],
    [
      'verify tampered hash',
      { events: tamper(tenant1, 2, { hash: '0'.repeat(64) }), options: { head } },
    ],
    ['verify sequence gap', { events: [tenant1[0], tenant1[2], tenant1[3]], options: {} }],
    [
      'verify head mismatch (last event deleted)',
      { events: tenant1.slice(0, -1), options: { head } },
    ],
    ['verify missing prefix', { events: tenant1.slice(1), options: { head } }],
    [
      'verify unchained event in whole chain',
      { events: [...tenant1, event(9)], options: { head } },
    ],
    ['verify unchained event in run', { events: [...tenant1, event(9)] }],
    ['verify empty run', { events: [] }],
    [
      'verify empty chain against head',
      { events: [], options: { head: { sequence: 0, hash: core.auditGenesis } } },
    ],
  ])
    await file.add(name, input, verify);
  // A pruned chain: an audit:prune checkpoint inside the chain covers the deleted prefix.
  const pruneStore = memoryStore();
  const kept = [];
  for (let n = 1; n <= 4; n++) kept.push(await core.appendAuditEvent(pruneStore, event(n)));
  const checkpoint = await core.appendAuditEvent(
    pruneStore,
    event(5, {
      action: 'audit:prune',
      actorId: 'deployment-operator',
      resourceId: 'audit',
      metadata: { prunedThroughSequence: 2, prunedThroughHash: kept[1].hash },
    }),
  );
  const remaining = [kept[2], kept[3], checkpoint];
  const pruneHead = { sequence: checkpoint.sequence, hash: checkpoint.hash };
  await file.add(
    'verify pruned chain with checkpoint',
    { events: remaining, options: { head: pruneHead } },
    verify,
  );
  await file.add(
    'verify pruned chain without checkpoint',
    {
      events: remaining.slice(0, 2),
      options: { head: { sequence: kept[3].sequence, hash: kept[3].hash } },
    },
    verify,
  );
  return file.write(output);
}

// --- policy ------------------------------------------------------------------------------------------------------

const allow = (actions, resources, conditions, sid) => ({
  ...(sid ? { sid } : {}),
  effect: 'allow',
  actions,
  resources,
  ...(conditions ? { conditions } : {}),
});
const deny = (actions, resources, conditions, sid) => ({
  ...allow(actions, resources, conditions, sid),
  effect: 'deny',
});
const doc = (...statements) => ({ version: 1, statements });

async function policyEvaluation(output, core) {
  const file = new VectorFile('policy-evaluation', {
    description:
      'evaluatePolicy: grants form a union, every boundary is an independent ceiling, any matching deny (grant or boundary) refuses. reason is explicit-deny, no-grant, boundary-deny, allowed or evaluation-limit; matched lists "{grant|boundary}:{policyIndex}:{sid or statementIndex}" in evaluation order (grants first). Invalid requests throw INVALID_REQUEST, invalid documents INVALID_POLICY.',
    source: 'packages/core/src/policy.ts#evaluatePolicy',
  });
  const evaluate = (input) => core.evaluatePolicy(input);
  const request = { action: 'docs:read', resource: 'doc/123' };
  const cases = [
    ['allow exact', { ...request, grants: [doc(allow(['docs:read'], ['doc/123']))] }],
    ['no grant', { ...request, grants: [] }],
    ['no matching action', { ...request, grants: [doc(allow(['docs:write'], ['doc/123']))] }],
    ['no matching resource', { ...request, grants: [doc(allow(['docs:read'], ['doc/456']))] }],
    ['action wildcard namespace', { ...request, grants: [doc(allow(['docs:*'], ['doc/123']))] }],
    ['action wildcard all', { ...request, grants: [doc(allow(['*'], ['*']))] }],
    [
      'action single-character wildcard',
      { ...request, grants: [doc(allow(['docs:re?d'], ['doc/*']))] },
    ],
    ['resource prefix glob', { ...request, grants: [doc(allow(['docs:read'], ['doc/*']))] }],
    ['resource glob is anchored', { ...request, grants: [doc(allow(['docs:read'], ['oc/*']))] }],
    [
      'resource multi-star glob',
      { ...request, resource: 'doc/a-x-b-y-c', grants: [doc(allow(['docs:read'], ['doc/a*b*c']))] },
    ],
    [
      'resource multi-star glob no match',
      { ...request, resource: 'doc/a-x-c-y-b', grants: [doc(allow(['docs:read'], ['doc/a*b*c']))] },
    ],
    [
      'star matches empty',
      { ...request, resource: 'doc/', grants: [doc(allow(['docs:read'], ['doc/*']))] },
    ],
    [
      'explicit deny wins',
      {
        ...request,
        grants: [doc(allow(['docs:*'], ['*'])), doc(deny(['docs:read'], ['doc/123']))],
      },
    ],
    [
      'deny in same document',
      {
        ...request,
        grants: [
          doc(
            allow(['*'], ['*'], undefined, 'all'),
            deny(['docs:read'], ['doc/1*'], undefined, 'no-1'),
          ),
        ],
      },
    ],
    [
      'deny not matching',
      { ...request, grants: [doc(allow(['*'], ['*'])), doc(deny(['docs:write'], ['*']))] },
    ],
    [
      'boundary allows',
      {
        ...request,
        grants: [doc(allow(['docs:*'], ['*']))],
        boundaries: [doc(allow(['docs:read'], ['doc/*']))],
      },
    ],
    [
      'boundary refuses',
      {
        ...request,
        grants: [doc(allow(['docs:*'], ['*']))],
        boundaries: [doc(allow(['docs:write'], ['*']))],
      },
    ],
    [
      'every boundary must allow',
      {
        ...request,
        grants: [doc(allow(['*'], ['*']))],
        boundaries: [doc(allow(['*'], ['*'])), doc(allow(['docs:write'], ['*']))],
      },
    ],
    [
      'boundary alone grants nothing',
      { ...request, grants: [], boundaries: [doc(allow(['*'], ['*']))] },
    ],
    [
      'deny in boundary',
      {
        ...request,
        grants: [doc(allow(['*'], ['*']))],
        boundaries: [doc(allow(['*'], ['*']), deny(['docs:read'], ['*']))],
      },
    ],
    ['empty boundaries list', { ...request, grants: [doc(allow(['*'], ['*']))], boundaries: [] }],
    [
      'matched with sids and indexes',
      {
        ...request,
        grants: [
          doc(allow(['docs:read'], ['*'], undefined, 'read-all'), allow(['*'], ['doc/*'])),
          doc(allow(['docs:*'], ['doc/123'], undefined, 'own')),
        ],
        boundaries: [doc(allow(['*'], ['*'], undefined, 'ceiling'))],
      },
    ],
    [
      'variable in resource',
      {
        ...request,
        resource: 'user/idn_01/profile',
        context: { 'principal.id': 'idn_01' },
        grants: [doc(allow(['docs:read'], ['user/${principal.id}/*']))],
      },
    ],
    [
      'variable in resource other principal',
      {
        ...request,
        resource: 'user/idn_02/profile',
        context: { 'principal.id': 'idn_01' },
        grants: [doc(allow(['docs:read'], ['user/${principal.id}/*']))],
      },
    ],
    [
      'unresolved variable never matches',
      {
        ...request,
        resource: 'user/idn_01/profile',
        grants: [doc(allow(['docs:read'], ['user/${principal.id}/*']))],
      },
    ],
    [
      'variable value matches literally',
      {
        ...request,
        resource: 'team/eng-x',
        context: { 'principal.team': 'eng-*' },
        grants: [doc(allow(['docs:read'], ['team/${principal.team}']))],
      },
    ],
    [
      'variable with literal star value exact',
      {
        ...request,
        resource: 'team/eng-*',
        context: { 'principal.team': 'eng-*' },
        grants: [doc(allow(['docs:read'], ['team/${principal.team}']))],
      },
    ],
    [
      'numeric variable',
      {
        ...request,
        resource: 'level/3',
        context: { 'principal.level': 3 },
        grants: [doc(allow(['docs:read'], ['level/${principal.level}']))],
      },
    ],
    [
      'boolean variable',
      {
        ...request,
        resource: 'flag/true',
        context: { 'principal.mfa': true },
        grants: [doc(allow(['docs:read'], ['flag/${principal.mfa}']))],
      },
    ],
    [
      'array variable is unresolved',
      {
        ...request,
        resource: 'g/a',
        context: { 'principal.groups': ['a'] },
        grants: [doc(allow(['docs:read'], ['g/${principal.groups}']))],
      },
    ],
    [
      'malformed variable treated literally',
      { ...request, resource: 'x/${', grants: [doc(allow(['docs:read'], ['x/*']))] },
    ],
    [
      'astral characters and ?',
      { ...request, resource: 'doc/😀', grants: [doc(allow(['docs:read'], ['doc/?']))] },
    ],
    ['invalid request empty action', { action: '', resource: 'doc/1', grants: [] }],
    [
      'invalid request long resource',
      { action: 'a', resource: `r/${'x'.repeat(2048)}`, grants: [] },
    ],
    ['invalid request control character', { action: 'a\nb', resource: 'r', grants: [] }],
    ['invalid request grants not array', { action: 'a', resource: 'r', grants: 'x' }],
    ['invalid request context array', { action: 'a', resource: 'r', grants: [], context: [] }],
    ['invalid policy in grants', { ...request, grants: [{ version: 2, statements: [] }] }],
  ];
  for (const [name, input] of cases) await file.add(name, input, evaluate);
  // Work limit: a pathological pattern refuses as evaluation-limit.
  await file.add(
    'evaluation work limit',
    {
      action: 'docs:read',
      resource: `doc/${'a'.repeat(2040)}`,
      grants: [
        {
          version: 1,
          statements: Array.from({ length: 24 }, (_, s) =>
            allow(
              ['docs:read'],
              Array.from({ length: 128 }, (_, i) => `doc/?${s}-${i}`),
            ),
          ),
        },
      ],
    },
    evaluate,
  );
  return file.write(output);
}

async function policyConditions(output, core) {
  const file = new VectorFile('policy-conditions', {
    description:
      "Condition operators, one statement { effect: allow, actions: [a:b], resources: [r/1], conditions: { [operator]: { key: expected } } } evaluated against a context holding `key` (or not). Missing or wrongly typed values never satisfy a condition, negated ones included; negated operators need every value to differ, ArrayContainsAll every value present, the others any value. Output is evaluatePolicy's decision.",
    source: 'packages/core/src/policy.ts#evaluatePolicy (matches, compare, wellTyped)',
  });
  const MISSING = Symbol('missing');
  const matrix = {
    StringEquals: [
      ['eng', ['eng', 'ENG', 'ops', 5, MISSING, ['eng'], undefined]],
      [
        ['eng', 'ops'],
        ['ops', 'qa'],
      ],
      ['${principal.team}', ['eng', 'ops']],
    ],
    StringNotEquals: [
      ['eng', ['eng', 'ops', 5, MISSING]],
      [
        ['eng', 'ops'],
        ['ops', 'qa'],
      ],
      ['${principal.missing}', ['eng']],
    ],
    StringEqualsIgnoreCase: [
      ['Eng', ['eNG', 'eng', 'ops', 5]],
      ['${principal.team}', ['ENG']],
    ],
    StringNotEqualsIgnoreCase: [['Eng', ['eNG', 'ops', 5, MISSING]]],
    StringLike: [
      ['eng-*', ['eng-team', 'eng-', 'ENG-team', 'xeng-team', 5]],
      ['?ng', ['eng', 'ng', 'eeng']],
      ['a*b?c', ['abxc', 'a-b-xc', 'abc']],
      ['${principal.team}-*', ['eng-1', 'ops-1']],
    ],
    StringNotLike: [['eng-*', ['eng-team', 'ops', 5, MISSING]]],
    StringLikeIgnoreCase: [
      ['ENG-*', ['eng-team', 'Eng-X', 'ops']],
      ['${principal.team}-*', ['ENG-1']],
    ],
    Bool: [
      [true, [true, false, 'true', 1, MISSING]],
      [false, [false, true]],
    ],
    NumericEquals: [
      [5, [5, 4, '5', MISSING]],
      [
        [1, 2],
        [2, 3],
      ],
    ],
    NumericNotEquals: [[5, [5, 6, '6', MISSING]]],
    NumericLessThan: [[5, [4, 5, 6, -Infinity, '4']]],
    NumericLessThanEquals: [[5, [5, 5.000001, 4.9]]],
    NumericGreaterThan: [[5, [6, 5, Infinity]]],
    NumericGreaterThanEquals: [[5, [5, 4.999]]],
    DateBefore: [
      [
        '2026-01-01T00:00:00Z',
        [
          '2025-12-31T23:59:59Z',
          '2026-01-01T00:00:00Z',
          '2026-01-01T00:00:00.001Z',
          '2026-01-01T00:59:59+01:00',
          '2026-02-30T00:00:00Z',
          '2025-12-31',
          'not a date',
          1767225600000,
        ],
      ],
    ],
    DateAfter: [
      [
        '2026-01-01T00:00:00.000+00:00',
        [
          '2026-01-01T00:00:00.001Z',
          '2026-01-01T01:00:01+01:00',
          '2025-01-01T00:00:00Z',
          '2026-13-01T00:00:00Z',
        ],
      ],
    ],
    IpAddress: [
      [
        '10.0.0.0/8',
        [
          '10.1.2.3',
          '11.0.0.1',
          '::ffff:10.1.2.3',
          '::ffff:a01:203',
          '010.1.2.3',
          '10.1.2',
          'not-ip',
          5,
        ],
      ],
      ['2001:db8::/32', ['2001:db8::1', '2001:DB8:0:0:0:0:0:1', '2001:db9::1', '10.0.0.1']],
      ['::ffff:198.51.100.0/120', ['198.51.100.7', '198.51.101.7', '::ffff:198.51.100.9']],
      ['198.51.100.7', ['198.51.100.7', '198.51.100.8']],
      [
        ['10.0.0.0/8', '192.168.0.0/16'],
        ['192.168.1.1', '172.16.0.1'],
      ],
    ],
    NotIpAddress: [
      ['10.0.0.0/8', ['10.1.2.3', '11.0.0.1', 'not-ip', MISSING]],
      [
        ['10.0.0.0/8', '192.168.0.0/16'],
        ['192.168.1.1', '172.16.0.1'],
      ],
    ],
    ArrayContains: [
      ['admin', [['admin', 'x'], ['ops'], 'admin', [], MISSING]],
      [5, [[5], ['5']]],
      [true, [[true], [false]]],
      [
        ['admin', 'ops'],
        [['ops'], ['qa']],
      ],
      ['${principal.id}', [['idn_01'], ['idn_02']]],
    ],
    ArrayContainsAll: [
      [
        ['admin', 'ops'],
        [['admin', 'ops', 'x'], ['admin'], 'admin'],
      ],
      ['admin', [['admin'], []]],
    ],
    Exists: [
      [true, ['x', null, undefined, MISSING, 0, false]],
      [false, ['x', undefined, MISSING]],
    ],
  };
  for (const [operator, rows] of Object.entries(matrix))
    for (const [expected, actuals] of rows)
      for (const actual of actuals) {
        const context = { 'principal.team': 'eng', 'principal.id': 'idn_01' };
        if (actual !== MISSING) context.key = actual;
        const label = actual === MISSING ? 'missing' : (JSON.stringify(actual) ?? String(actual));
        await file.add(
          `${operator} ${JSON.stringify(expected)} vs ${label}`,
          {
            action: 'a:b',
            resource: 'r/1',
            context,
            grants: [doc(allow(['a:b'], ['r/1'], { [operator]: { key: expected } }))],
          },
          (input) => core.evaluatePolicy(input),
        );
      }
  // Several operators and keys must all hold.
  await file.add(
    'all conditions must hold',
    {
      action: 'a:b',
      resource: 'r/1',
      context: { team: 'eng', level: 3 },
      grants: [
        doc(
          allow(['a:b'], ['r/1'], {
            StringEquals: { team: 'eng' },
            NumericGreaterThan: { level: 2 },
          }),
        ),
      ],
    },
    (input) => core.evaluatePolicy(input),
  );
  await file.add(
    'one failing condition refuses',
    {
      action: 'a:b',
      resource: 'r/1',
      context: { team: 'eng', level: 1 },
      grants: [
        doc(
          allow(['a:b'], ['r/1'], {
            StringEquals: { team: 'eng' },
            NumericGreaterThan: { level: 2 },
          }),
        ),
      ],
    },
    (input) => core.evaluatePolicy(input),
  );
  await file.add(
    'conditional deny applies only when it holds',
    {
      action: 'a:b',
      resource: 'r/1',
      context: { 'request.ip': '203.0.113.9' },
      grants: [
        doc(
          allow(['*'], ['*']),
          deny(['*'], ['*'], { NotIpAddress: { 'request.ip': '10.0.0.0/8' } }),
        ),
      ],
    },
    (input) => core.evaluatePolicy(input),
  );
  return file.write(output);
}

async function policyValidation(output, core) {
  const file = new VectorFile('policy-validation', {
    description:
      'validatePolicy: the structural rules a stored policy document must meet. Output null = valid; otherwise the INVALID_POLICY error.',
    source: 'packages/core/src/policy.ts#validatePolicy',
  });
  const validate = (input) => {
    core.validatePolicy(input.document);
    return null;
  };
  const statement = { effect: 'allow', actions: ['a:b'], resources: ['r/*'] };
  for (const [name, document] of [
    ['valid minimal', doc(statement)],
    ['valid empty statements', doc()],
    [
      'valid with sid and conditions',
      doc({
        ...statement,
        sid: 's1',
        conditions: { StringEquals: { k: ['a', 'b'] }, Bool: { m: true } },
      }),
    ],
    ['valid variable after type', doc({ ...statement, resources: ['user/${principal.id}'] })],
    ['not an object', [1]],
    ['null', null],
    ['unknown top-level field', { ...doc(statement), extra: 1 }],
    ['version 2', { version: 2, statements: [] }],
    ['statements not array', { version: 1, statements: {} }],
    ['129 statements', { version: 1, statements: Array.from({ length: 129 }, () => statement) }],
    ['statement not object', doc('x')],
    ['unknown statement field', doc({ ...statement, principal: '*' })],
    ['bad effect', doc({ ...statement, effect: 'Allow' })],
    ['duplicate sid', doc({ ...statement, sid: 'a' }, { ...statement, sid: 'a' })],
    ['empty sid', doc({ ...statement, sid: '' })],
    ['empty actions', doc({ ...statement, actions: [] })],
    [
      '129 actions',
      doc({ ...statement, actions: Array.from({ length: 129 }, (_, i) => `a:${i}`) }),
    ],
    ['empty action string', doc({ ...statement, actions: [''] })],
    ['action with control character', doc({ ...statement, actions: ['a:\u0007'] })],
    ['action 513 characters', doc({ ...statement, actions: ['a'.repeat(513)] })],
    ['variable in action', doc({ ...statement, actions: ['${principal.id}'] })],
    ['malformed variable in resource', doc({ ...statement, resources: ['r/${principal'] })],
    ['variable in resource type', doc({ ...statement, resources: ['${principal.type}/1'] })],
    ['empty conditions', doc({ ...statement, conditions: {} })],
    ['unknown operator', doc({ ...statement, conditions: { Regex: { k: 'x' } } })],
    ['empty operator map', doc({ ...statement, conditions: { StringEquals: {} } })],
    [
      '65 condition keys',
      doc({
        ...statement,
        conditions: {
          StringEquals: Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`k${i}`, 'v'])),
        },
      }),
    ],
    [
      'unsafe condition key',
      doc({ ...statement, conditions: { StringEquals: { constructor: 'x' } } }),
    ],
    ['empty value list', doc({ ...statement, conditions: { StringEquals: { k: [] } } })],
    [
      '65 values',
      doc({
        ...statement,
        conditions: { StringEquals: { k: Array.from({ length: 65 }, (_, i) => `${i}`) } },
      }),
    ],
    ['Bool with string', doc({ ...statement, conditions: { Bool: { k: 'true' } } })],
    ['Numeric with string', doc({ ...statement, conditions: { NumericEquals: { k: '1' } } })],
    [
      'Date invalid',
      doc({ ...statement, conditions: { DateBefore: { k: '2026-02-30T00:00:00Z' } } }),
    ],
    [
      'Date without zone',
      doc({ ...statement, conditions: { DateBefore: { k: '2026-01-01T00:00:00' } } }),
    ],
    ['IpAddress invalid', doc({ ...statement, conditions: { IpAddress: { k: '10.0.0.0/33' } } })],
    [
      'String too long',
      doc({ ...statement, conditions: { StringEquals: { k: 'x'.repeat(2049) } } }),
    ],
    ['ArrayContains object', doc({ ...statement, conditions: { ArrayContains: { k: { a: 1 } } } })],
    [
      'malformed variable in condition',
      doc({ ...statement, conditions: { StringEquals: { k: '${principal' } } }),
    ],
    ['Exists with string', doc({ ...statement, conditions: { Exists: { k: 'yes' } } })],
  ])
    await file.add(name, { document }, validate);
  return file.write(output);
}

async function patterns(output, core) {
  const file = new VectorFile('policy-patterns', {
    description:
      'Glob matching (matchPattern: anchored, * any run of code points, ? one code point, ${var} substituted literally from context, unresolved variables never match), variable resolution (resolvePolicyValue), variable syntax (validPolicyVariables), and IP helpers (isIpRange, ipMatches, ipCounterKey).',
    source:
      'packages/core/src/policy.ts#matchPattern,resolvePolicyValue,validPolicyVariables,isIpRange,ipMatches,ipCounterKey',
  });
  const context = {
    'principal.id': 'idn_01',
    'principal.team': 'eng*',
    n: 7,
    b: false,
    list: ['x'],
  };
  for (const [pattern, value, ctx] of [
    ['*', ''],
    ['*', 'anything'],
    ['abc', 'abc'],
    ['abc', 'abcd'],
    ['a*', 'a'],
    ['*c', 'abc'],
    ['a*c', 'ac'],
    ['a*c', 'abbbc'],
    ['a*c', 'abcd'],
    ['a*b*c', 'aXbYc'],
    ['a*b*c', 'acb'],
    ['**', 'x'],
    ['?', ''],
    ['?', 'a'],
    ['?', 'ab'],
    ['?', '😀'],
    ['??', '😀'],
    ['a?c', 'abc'],
    ['a?c', 'a😀c'],
    ['*?', ''],
    ['*?', 'x'],
    ['a*?*b', 'ab'],
    ['a*?*b', 'axb'],
    ['literal*star', 'literal*star'],
    ['x*', '*'],
    ['😀*', '😀🎉'],
    ['é', 'é'],
    ['e\u0301', 'é'],
    ['user/${principal.id}', 'user/idn_01', context],
    ['user/${principal.id}', 'user/idn_02', context],
    ['user/${principal.missing}', 'user/', context],
    ['team/${principal.team}', 'team/eng*', context],
    ['team/${principal.team}', 'team/engineering', context],
    ['n/${n}', 'n/7', context],
    ['b/${b}', 'b/false', context],
    ['l/${list}', 'l/x', context],
    ['${principal.id}*', 'idn_01/x', context],
    ['bad/${', 'bad/${', context],
    ['bad/${x', 'bad/${x', context],
    ['bad/${1x}', 'bad/${1x}', context],
    ['a'.repeat(30) + '*', 'a'.repeat(40)],
  ])
    await file.add(
      `matchPattern ${JSON.stringify(pattern).slice(0, 40)} ${JSON.stringify(value).slice(0, 30)}${ctx ? ' (context)' : ''}`,
      { pattern, value, ...(ctx ? { context: ctx } : {}) },
      (input) => core.matchPattern(input.pattern, input.value, input.context),
    );
  for (const value of [
    'plain',
    '${principal.id}',
    'a-${principal.id}-${n}',
    '${principal.team}',
    '${missing}',
    '${',
    'x${principal.id',
  ])
    await file.add(`resolvePolicyValue ${value}`, { value, context }, (input) =>
      core.resolvePolicyValue(input.value, input.context),
    );
  for (const value of [
    'plain',
    '${a}',
    '${a.b:c-d_e}',
    '${',
    '${}',
    '${1a}',
    '${a',
    'x${a}y${b}',
    '$ {a}',
    `\${${'a'.repeat(128)}}`,
    `\${${'a'.repeat(129)}}`,
  ])
    await file.add(
      `validPolicyVariables ${value.length > 30 ? `${value.slice(0, 12)}... (${value.length} chars)` : value}`,
      { value },
      (input) => core.validPolicyVariables(input.value),
    );
  for (const value of [
    '10.0.0.1',
    '10.0.0.0/8',
    '10.0.0.0/33',
    '010.0.0.1',
    '256.0.0.1',
    '1.2.3',
    '::1',
    '::',
    '2001:db8::/32',
    '2001:db8::/129',
    '2001:db8:::1',
    '::ffff:1.2.3.4',
    'fe80::1%eth0',
    '[::1]',
    '1.2.3.4/08',
    'gggg::1',
    '1:2:3:4:5:6:7:8',
    '1:2:3:4:5:6:7:8:9',
    '1::2:3:4:5:6:7:8',
  ])
    await file.add(`isIpRange ${value}`, { value }, (input) => core.isIpRange(input.value));
  for (const [address, network] of [
    ['10.1.2.3', '10.0.0.0/8'],
    ['10.1.2.3', '10.1.2.3'],
    ['10.1.2.3', '10.1.2.4'],
    ['10.1.2.3', '0.0.0.0/0'],
    ['::ffff:10.1.2.3', '10.0.0.0/8'],
    ['::ffff:a01:203', '10.0.0.0/8'],
    ['10.1.2.3', '::ffff:10.0.0.0/104'],
    ['10.1.2.3', '::ffff:10.0.0.0/95'],
    ['2001:db8::1', '2001:db8::/32'],
    ['2001:0db8:0000::0001', '2001:db8::1'],
    ['2001:db8::1', '::/0'],
    ['2001:db8::1', '10.0.0.0/8'],
    ['10.1.2.3', '2001:db8::/32'],
    ['10.1.2.3/32', '10.0.0.0/8'],
    ['not-ip', '10.0.0.0/8'],
  ])
    await file.add(`ipMatches ${address} ${network}`, { address, network }, (input) =>
      core.ipMatches(input.address, input.network),
    );
  for (const value of [
    '10.1.2.3',
    ' 10.1.2.3 ',
    '::ffff:10.1.2.3',
    '::ffff:a01:203',
    '2001:db8:1:2:3:4:5:6',
    '2001:DB8:1:2::',
    '::1',
    'fe80::1',
    'not-ip',
    '10.0.0.0/8',
  ])
    await file.add(`ipCounterKey ${value}`, { value }, (input) => core.ipCounterKey(input.value));
  return file.write(output);
}

// --- planning and filters ---------------------------------------------------------------------------------------

async function plan(output, core) {
  const file = new VectorFile('plan', {
    description:
      'Query planning (planResources): which resources of one type a principal may act on, as a ResourceFilter over id and attributes; kind always / never / conditional. Also the filter constructors (andFilter, orFilter, notFilter simplification) and filter globs (parseGlob, globMatches).',
    source:
      'packages/core/src/plan.ts#planResources,andFilter,orFilter,notFilter,parseGlob,globMatches,intersectPlans,fixedPlan',
  });
  const base = {
    action: 'docs:read',
    resourceType: 'doc',
    tenantId: 'tnt_01',
    context: { 'principal.id': 'idn_01', 'principal.team': 'eng', 'principal.mfa': true },
    denies: [],
    boundaries: [],
  };
  const path = (...documents) => ({ grants: documents, boundaries: [] });
  const cases = [
    ['no paths', { ...base, paths: [] }],
    ['allow all of type', { ...base, paths: [path(doc(allow(['docs:read'], ['doc/*'])))] }],
    ['allow everything', { ...base, paths: [path(doc(allow(['*'], ['*'])))] }],
    ['other type only', { ...base, paths: [path(doc(allow(['docs:read'], ['folder/*'])))] }],
    ['other action only', { ...base, paths: [path(doc(allow(['docs:write'], ['doc/*'])))] }],
    ['specific ids', { ...base, paths: [path(doc(allow(['docs:read'], ['doc/1', 'doc/2'])))] }],
    ['id glob', { ...base, paths: [path(doc(allow(['docs:read'], ['doc/report-*'])))] }],
    [
      'id with variable',
      { ...base, paths: [path(doc(allow(['docs:read'], ['doc/${principal.id}-*'])))] },
    ],
    [
      'resource attribute equals principal',
      {
        ...base,
        paths: [
          path(
            doc(
              allow(['docs:read'], ['doc/*'], {
                StringEquals: { 'resource.owner': '${principal.id}' },
              }),
            ),
          ),
        ],
      },
    ],
    [
      'resource attribute row variable in id',
      { ...base, paths: [path(doc(allow(['docs:read'], ['doc/${resource.owner}'])))] },
    ],
    [
      'principal condition true',
      {
        ...base,
        paths: [
          path(doc(allow(['docs:read'], ['doc/*'], { StringEquals: { 'principal.team': 'eng' } }))),
        ],
      },
    ],
    [
      'principal condition false',
      {
        ...base,
        paths: [
          path(doc(allow(['docs:read'], ['doc/*'], { StringEquals: { 'principal.team': 'ops' } }))),
        ],
      },
    ],
    [
      'numeric resource condition',
      {
        ...base,
        paths: [
          path(doc(allow(['docs:read'], ['doc/*'], { NumericLessThan: { 'resource.size': 100 } }))),
        ],
      },
    ],
    [
      'like resource condition ignore case',
      {
        ...base,
        paths: [
          path(
            doc(
              allow(['docs:read'], ['doc/*'], {
                StringLikeIgnoreCase: { 'resource.title': 'Q?-*' },
              }),
            ),
          ),
        ],
      },
    ],
    [
      'not equals resource condition',
      {
        ...base,
        paths: [
          path(
            doc(
              allow(['docs:read'], ['doc/*'], {
                StringNotEquals: { 'resource.status': ['archived', 'deleted'] },
              }),
            ),
          ),
        ],
      },
    ],
    [
      'date resource condition',
      {
        ...base,
        paths: [
          path(
            doc(
              allow(['docs:read'], ['doc/*'], {
                DateAfter: { 'resource.publishedAt': '2025-01-01T00:00:00Z' },
              }),
            ),
          ),
        ],
      },
    ],
    [
      'ip resource condition',
      {
        ...base,
        paths: [
          path(
            doc(
              allow(['docs:read'], ['doc/*'], { IpAddress: { 'resource.origin': '10.0.0.0/8' } }),
            ),
          ),
        ],
      },
    ],
    [
      'array resource condition',
      {
        ...base,
        paths: [
          path(
            doc(allow(['docs:read'], ['doc/*'], { ArrayContains: { 'resource.tags': 'public' } })),
          ),
        ],
      },
    ],
    [
      'exists resource condition',
      {
        ...base,
        paths: [
          path(doc(allow(['docs:read'], ['doc/*'], { Exists: { 'resource.owner': false } }))),
        ],
      },
    ],
    [
      'bool resource condition',
      {
        ...base,
        paths: [path(doc(allow(['docs:read'], ['doc/*'], { Bool: { 'resource.public': true } })))],
      },
    ],
    [
      'tenant condition',
      {
        ...base,
        paths: [
          path(
            doc(
              allow(['docs:read'], ['doc/*'], { StringEquals: { 'resource.tenantId': 'tnt_01' } }),
            ),
          ),
        ],
      },
    ],
    [
      'deny subset',
      {
        ...base,
        paths: [path(doc(allow(['docs:read'], ['doc/*']), deny(['docs:read'], ['doc/secret-*'])))],
      },
    ],
    [
      'global deny',
      {
        ...base,
        denies: [
          doc(
            deny(['docs:*'], ['doc/*'], { StringEquals: { 'resource.classification': 'secret' } }),
          ),
        ],
        paths: [path(doc(allow(['*'], ['*'])))],
      },
    ],
    [
      'boundary limits',
      {
        ...base,
        boundaries: [doc(allow(['docs:read'], ['doc/public-*']))],
        paths: [path(doc(allow(['docs:*'], ['doc/*'])))],
      },
    ],
    [
      'path boundary',
      {
        ...base,
        paths: [
          {
            grants: [doc(allow(['*'], ['*']))],
            boundaries: [doc(allow(['docs:read'], ['doc/1']))],
          },
        ],
      },
    ],
    [
      'two paths merge equals',
      {
        ...base,
        paths: [
          path(doc(allow(['docs:read'], ['doc/1']))),
          path(doc(allow(['docs:read'], ['doc/2']))),
        ],
      },
    ],
    [
      'relations',
      {
        ...base,
        relations: [
          { type: 'doc', id: 'd1', relations: ['viewer'] },
          { type: 'folder', id: 'f1', relations: ['viewer'] },
        ],
        paths: [
          path(
            doc(
              allow(['docs:read'], ['doc/*'], {
                ArrayContains: { 'resource.relations': 'viewer' },
              }),
            ),
          ),
        ],
      },
    ],
    [
      'parent relations',
      {
        ...base,
        relations: [{ type: 'folder', id: 'f1', relations: ['editor'] }],
        paths: [
          path(
            doc(
              allow(['docs:read'], ['doc/*'], {
                ArrayContains: { 'resource.parentRelations': 'editor' },
              }),
            ),
          ),
        ],
      },
    ],
    [
      'mandatory filter',
      {
        ...base,
        mandatory: { kind: 'compare', field: 'classificationRank', operator: 'le', value: 2 },
        paths: [path(doc(allow(['*'], ['*'])))],
      },
    ],
    [
      'derived resource key refuses',
      {
        ...base,
        derivedResourceKeys: ['resource.classificationRank'],
        paths: [
          path(
            doc(
              allow(['docs:read'], ['doc/*'], {
                NumericLessThan: { 'resource.classificationRank': 3 },
              }),
            ),
          ),
        ],
      },
    ],
    ['invalid resource type', { ...base, resourceType: 'a/b', paths: [] }],
    [
      'invalid policy',
      { ...base, paths: [path({ version: 1, statements: [{ effect: 'maybe' }] })] },
    ],
  ];
  const plans = [];
  for (const [name, input] of cases)
    plans.push(await file.add(name, input, (value) => core.planResources(value)));
  const eq = (field, ...values) => ({ kind: 'equals', field, values });
  for (const [name, filters] of [
    ['andFilter empty', []],
    ['andFilter drops true', [core.trueFilter, eq('id', 'a')]],
    ['andFilter false absorbs', [eq('id', 'a'), core.falseFilter]],
    [
      'andFilter flattens and dedupes',
      [{ kind: 'and', filters: [eq('id', 'a'), eq('owner', 'x')] }, eq('id', 'a')],
    ],
  ])
    await file.add(name, { filters }, (input) => core.andFilter(input.filters));
  for (const [name, filters] of [
    ['orFilter empty', []],
    ['orFilter true absorbs', [eq('id', 'a'), core.trueFilter]],
    ['orFilter merges equals', [eq('id', 'a'), eq('id', 'b', 'a'), eq('owner', 'x')]],
    ['orFilter keeps case rules apart', [eq('id', 'a'), { ...eq('id', 'B'), ignoreCase: true }]],
  ])
    await file.add(name, { filters }, (input) => core.orFilter(input.filters));
  for (const [name, filter] of [
    ['notFilter true', core.trueFilter],
    ['notFilter false', core.falseFilter],
    ['notFilter double', { kind: 'not', filter: eq('id', 'a') }],
    ['notFilter atom', eq('id', 'a')],
  ])
    await file.add(name, { filter }, (input) => core.notFilter(input.filter));
  for (const [pattern, values] of [
    ['a*', ['a', 'ab', 'b']],
    ['\\*', ['*', 'a']],
    ['a\\?b?', ['a?bc', 'axbc']],
    ['\\\\x', ['\\x', 'x']],
    ['?😀', ['a😀', '😀']],
    ['trailing\\', ['trailing\\', 'trailing']],
  ]) {
    await file.add(`parseGlob ${pattern}`, { pattern }, (input) => core.parseGlob(input.pattern));
    for (const value of values)
      await file.add(`globMatches ${pattern} ${value}`, { pattern, value }, (input) =>
        core.globMatches(core.parseGlob(input.pattern), input.value),
      );
  }
  await file.add('fixedPlan true', { allowed: true }, (input) => core.fixedPlan(input.allowed));
  await file.add('fixedPlan false', { allowed: false }, (input) => core.fixedPlan(input.allowed));
  await file.add(
    'intersectPlans',
    {
      left: { kind: 'conditional', filter: eq('id', 'a', 'b') },
      right: { kind: 'conditional', filter: eq('owner', 'x') },
    },
    (input) => core.intersectPlans(input.left, input.right),
  );
  return {
    count: file.write(output),
    plans: plans
      .filter((item) => item && !item.$error && item.kind === 'conditional')
      .map((item) => item.filter),
  };
}

async function filterCompilers(output, core, planFilters) {
  const file = new VectorFile('filter-compilers', {
    description:
      'Filter compilers for plans: filterToSql for sqlite ("?" placeholders, GLOB) and postgres ("$n" placeholders after `offset`, LIKE ... ESCAPE \'\\\'), filterToPrisma, filterToMongo, describeFilter, and filterMatches against sample records. The column mapping in every SQL case is field => `"${field}"` except fields named missing* (no column: INVALID_INPUT). Unsupported atoms throw UNSUPPORTED_FILTER.',
    source:
      'packages/core/src/filter-compilers.ts#filterToSql,filterToPrisma,filterToMongo,describeFilter,filterMatches',
  });
  const filters = [
    ['true', { kind: 'true' }],
    ['false', { kind: 'false' }],
    ['exists', { kind: 'exists', field: 'owner' }],
    ['type string', { kind: 'type', field: 'owner', type: 'string' }],
    ['type ip', { kind: 'type', field: 'origin', type: 'ip' }],
    ['equals one', { kind: 'equals', field: 'id', values: ['d1'] }],
    ['equals many mixed', { kind: 'equals', field: 'level', values: [1, 'one', true] }],
    [
      'equals ignore case',
      { kind: 'equals', field: 'team', values: ['Eng', 'OPS', 3], ignoreCase: true },
    ],
    ['compare lt', { kind: 'compare', field: 'size', operator: 'lt', value: 100 }],
    ['compare ge', { kind: 'compare', field: 'size', operator: 'ge', value: 1.5 }],
    ['like prefix', { kind: 'like', field: 'title', pattern: 'Q1-*' }],
    ['like suffix', { kind: 'like', field: 'title', pattern: '*-draft' }],
    ['like contains', { kind: 'like', field: 'title', pattern: '*plan*' }],
    ['like complex', { kind: 'like', field: 'title', pattern: 'a?b*c' }],
    ['like escapes', { kind: 'like', field: 'title', pattern: '100%_\\*[x]\\?' }],
    ['like ignore case', { kind: 'like', field: 'title', pattern: 'Q?-*', ignoreCase: true }],
    [
      'date before',
      { kind: 'date', field: 'publishedAt', operator: 'before', value: '2026-01-01T00:00:00Z' },
    ],
    ['ip', { kind: 'ip', field: 'origin', network: '10.0.0.0/8' }],
    ['contains', { kind: 'contains', field: 'tags', value: 'public' }],
    [
      'and or not',
      {
        kind: 'and',
        filters: [
          {
            kind: 'or',
            filters: [
              { kind: 'equals', field: 'owner', values: ['idn_01'] },
              { kind: 'compare', field: 'size', operator: 'gt', value: 0 },
            ],
          },
          { kind: 'not', filter: { kind: 'equals', field: 'status', values: ['archived'] } },
        ],
      },
    ],
    ['missing column', { kind: 'equals', field: 'missingField', values: ['x'] }],
    ...planFilters.map((filter, index) => [`plan output ${index + 1}`, filter]),
  ];
  const column = (field) => (field.startsWith('missing') ? undefined : `"${field}"`);
  for (const [name, filter] of filters) {
    await file.add(`sqlite ${name}`, { filter, dialect: 'sqlite' }, (input) =>
      core.filterToSql(input.filter, { dialect: input.dialect, column }),
    );
    await file.add(`postgres ${name}`, { filter, dialect: 'postgres' }, (input) =>
      core.filterToSql(input.filter, { dialect: input.dialect, column }),
    );
    await file.add(`prisma ${name}`, { filter }, (input) => core.filterToPrisma(input.filter));
    await file.add(`mongo ${name}`, { filter }, (input) => core.filterToMongo(input.filter));
    await file.add(`describe ${name}`, { filter }, (input) => core.describeFilter(input.filter));
  }
  await file.add(
    'postgres with offset',
    { filter: filters[7][1], dialect: 'postgres', offset: 2 },
    (input) =>
      core.filterToSql(input.filter, { dialect: input.dialect, column, offset: input.offset }),
  );
  await file.add('prisma with field mapping', { filter: filters[19][1] }, (input) =>
    core.filterToPrisma(input.filter, {
      field: (field) => (field === 'id' ? 'uid' : `attr_${field}`),
    }),
  );
  await file.add('mongo with field mapping', { filter: filters[19][1] }, (input) =>
    core.filterToMongo(input.filter, { field: (field) => (field === 'id' ? '_id' : field) }),
  );
  const records = [
    {
      id: 'd1',
      owner: 'idn_01',
      size: 10,
      title: 'Q1-plan',
      team: 'eng',
      tags: ['public'],
      publishedAt: '2025-06-01T00:00:00Z',
      origin: '10.1.2.3',
      status: 'live',
      level: 1,
    },
    {
      id: 'd2',
      owner: 'idn_02',
      size: 500,
      title: 'q2-Draft',
      team: 'OPS',
      tags: [],
      publishedAt: '2026-06-01T00:00:00Z',
      origin: '192.168.0.1',
      status: 'archived',
      level: 'one',
    },
    {
      id: 'd3',
      size: '10',
      title: 100,
      tags: 'public',
      publishedAt: 'not a date',
      origin: 'nope',
      level: true,
    },
  ];
  for (const [name, filter] of filters)
    for (const record of records)
      await file.add(`matches ${name} ${record.id}`, { filter, record }, (input) =>
        core.filterMatches(input.filter, input.record),
      );
  return file.write(output);
}

async function storageVectors(output, core) {
  const file = new VectorFile('storage', {
    description:
      'Storage semantics shared by every adapter: planQuery (filter -> column tests and typed field conditions; exact when nothing is left to filter in memory), matchesFilter (the reference equality: deep JSON equality, absent equals undefined), compareIds (code-point order), storableString, and the PostgreSQL value encoding (encodeJsonbDocument / decodeJsonbDocument).',
    source:
      'packages/core/src/storage.ts#planQuery,matchesFilter,compareIds,storableString; packages/core/src/sql.ts#encodeJsonbDocument,decodeJsonbDocument',
  });
  const filters = [
    ['empty', {}],
    ['tenant', { tenantId: 'tnt_01' }],
    ['id tenant uniqueKey', { id: 'a', tenantId: 't', uniqueKey: 'k' }],
    ['string field', { email: 'a@example.com' }],
    ['number boolean null', { count: 3, active: true, deletedAt: null }],
    ['absent', { expiresAt: undefined }],
    ['object value', { attributes: { team: 'eng' } }],
    ['array value', { roles: ['a', 'b'] }],
    ['unqueryable field name', { 'tag.team': 'eng' }],
    ['unstorable string value', { name: 'a\u0000b' }],
    ['unstorable id', { id: '\ud800' }],
    ['non-string id', { id: 5 }],
    ['25 conditions', Object.fromEntries(Array.from({ length: 25 }, (_, i) => [`f${i}`, i]))],
    ['escape key in object', { meta: { '\u0001better-iam': 'x' } }],
  ];
  for (const [name, filter] of filters) {
    await file.add(`planQuery ${name}`, { collection: 'identities', filter }, (input) =>
      core.planQuery(input.collection, input.filter),
    );
    await file.add(
      `planQuery json ${name}`,
      { collection: 'identities', filter, capabilities: { json: true } },
      (input) => core.planQuery(input.collection, input.filter, input.capabilities),
    );
  }
  const record = {
    id: 'r1',
    tenantId: 't1',
    email: 'a@example.com',
    count: 3,
    active: true,
    deletedAt: null,
    attributes: { team: 'eng', level: 2 },
    roles: ['a', 'b'],
  };
  for (const [name, filter] of [
    ['matches string', { email: 'a@example.com' }],
    ['matches number', { count: 3 }],
    ['number vs string', { count: '3' }],
    ['matches null', { deletedAt: null }],
    ['null vs absent', { missing: null }],
    ['absent as undefined', { missing: undefined }],
    ['present vs undefined', { email: undefined }],
    ['object key order ignored', { attributes: { level: 2, team: 'eng' } }],
    ['object subset is not equal', { attributes: { team: 'eng' } }],
    ['array order kept', { roles: ['b', 'a'] }],
    ['array equal', { roles: ['a', 'b'] }],
    ['several keys', { email: 'a@example.com', active: true }],
  ])
    await file.add(`matchesFilter ${name}`, { record, filter }, (input) =>
      core.matchesFilter(input.record, input.filter),
    );
  for (const [a, b] of [
    ['a', 'b'],
    ['b', 'a'],
    ['a', 'a'],
    ['a', 'ab'],
    ['B', 'a'],
    ['\uffff', '😀'],
    ['\ue000', '😀'],
    ['😀', '\ud7ff'],
    ['10', '9'],
  ])
    await file.add(`compareIds ${JSON.stringify(a)} ${JSON.stringify(b)}`, { a, b }, (input) =>
      Math.sign(core.compareIds(input.a, input.b)),
    );
  for (const value of [
    'plain',
    '',
    'a\u0000b',
    '\ud800',
    '\udc00',
    'x\ud83d',
    '\ude00\ud83d',
    'a😀b',
    '\u{1F600}',
  ])
    await file.add(`storableString ${JSON.stringify(value)}`, { value }, (input) =>
      core.storableString(input.value),
    );
  const sql = await dist('core', 'sql.js');
  for (const [name, recordValue] of [
    ['plain record unchanged', { id: 'a', tenantId: 't', name: 'x' }],
    ['nul in value', { id: 'a', tenantId: 't', name: 'a\u0000b' }],
    ['lone surrogate in value', { id: 'a', tenantId: 't', name: 'x\ud800' }],
    ['nul in key', { id: 'a', tenantId: 't', meta: { 'k\u0000': 1, ok: 2 } }],
    ['escape key as key', { id: 'a', tenantId: 't', meta: { '\u0001better-iam': 'v' } }],
    ['nested arrays', { id: 'a', tenantId: 't', list: ['ok', '\u0000', ['\udfff']] }],
  ]) {
    const data = JSON.stringify(recordValue);
    const encoded = await file.add(`encodeJsonbDocument ${name}`, { data }, (input) =>
      sql.encodeJsonbDocument(input.data),
    );
    await file.add(`decodeJsonbDocument ${name}`, { data: encoded }, (input) =>
      sql.decodeJsonbDocument(input.data),
    );
  }
  return file.write(output);
}

async function sqlVectors(output, core) {
  const sql = await dist('core', 'sql.js');
  const file = new VectorFile('sql', {
    description:
      'SELECT statements the reference adapters run for record queries (sqliteSelect for SQLite and libSQL, postgresSelect for PostgreSQL): text and bound values, exactly. Queries come from planQuery over the filter plus the cursor, order and page given.',
    source:
      'packages/core/src/sql.ts#sqliteSelect,postgresSelect; packages/core/src/storage.ts#planQuery',
  });
  const queries = [
    ['collection only', { collection: 'tenants', filter: {} }],
    ['by tenant', { collection: 'identities', filter: { tenantId: 'tnt_01' } }],
    ['by id', { collection: 'identities', filter: { id: 'idn_01' } }],
    [
      'by unique key',
      { collection: 'resources', filter: { tenantId: 'tnt_01', uniqueKey: 'doc/1' } },
    ],
    ['string condition', { collection: 'sessions', filter: { tokenHash: 'abc' } }],
    ['number condition', { collection: 'outbox', filter: { attempts: 3 } }],
    ['large number condition', { collection: 'outbox', filter: { attempts: 2 ** 60 } }],
    ['fractional number condition', { collection: 'outbox', filter: { weight: 0.1 } }],
    ['boolean conditions', { collection: 'webhooks', filter: { active: true, paused: false } }],
    ['null condition', { collection: 'outbox', filter: { deliveredAt: null } }],
    ['absent condition', { collection: 'outbox', filter: { failedAt: undefined } }],
    [
      'mixed',
      {
        collection: 'groupMembers',
        filter: { tenantId: 'tnt_01', groupId: 'grp_01', identityId: 'idn_01' },
      },
    ],
    [
      'json condition (postgres)',
      {
        collection: 'roles',
        filter: { tenantId: 't', tags: ['a', 'b'] },
        capabilities: { json: true },
      },
    ],
    ['with cursor', { collection: 'identities', filter: { tenantId: 'tnt_01' }, after: 'idn_05' }],
    [
      'with page',
      { collection: 'identities', filter: { tenantId: 'tnt_01' }, page: { offset: 20, limit: 10 } },
    ],
    ['with page without limit', { collection: 'identities', filter: {}, page: { offset: 5 } }],
    [
      'ordered ascending',
      {
        collection: 'audit',
        filter: { tenantId: 'tnt_01' },
        order: { field: 'timestamp', direction: 'asc' },
      },
    ],
    [
      'ordered descending with range and page',
      {
        collection: 'audit',
        filter: { tenantId: 'tnt_01', action: 'iam:groups:create' },
        order: { field: 'sequence', direction: 'desc', from: 10, to: 20 },
        page: { offset: 0, limit: 50 },
      },
    ],
    [
      'ordered by expiry across tenants',
      {
        collection: 'sessions',
        filter: {},
        order: { field: 'expiresAt', direction: 'asc', to: NOW },
        page: { offset: 0, limit: 500 },
      },
    ],
  ];
  for (const [name, input] of queries) {
    const build = (dialect) => (value) => {
      const plan = core.planQuery(
        value.collection,
        value.filter,
        value.capabilities ??
          (dialect === 'postgres' ? { json: true, order: true } : { order: true }),
      );
      const query = {
        ...plan.query,
        ...(value.after !== undefined ? { after: value.after } : {}),
        ...(value.order ? { order: value.order } : {}),
        ...(value.page ? { page: value.page } : {}),
      };
      return {
        query,
        exact: plan.exact,
        statement: dialect === 'postgres' ? sql.postgresSelect(query) : sql.sqliteSelect(query),
      };
    };
    if (name !== 'json condition (postgres)')
      await file.add(`sqlite ${name}`, input, build('sqlite'));
    await file.add(`postgres ${name}`, input, build('postgres'));
  }
  await file.add(
    'sqlite json condition refused',
    {
      query: { collection: 'roles', conditions: [{ field: 'tags', kind: 'json', value: '["a"]' }] },
    },
    (input) => sql.sqliteSelect(input.query),
  );
  await file.add(
    'invalid field name refused',
    { query: { collection: 'roles', conditions: [{ field: 'a.b', kind: 'string', value: 'x' }] } },
    (input) => sql.sqliteSelect(input.query),
  );
  return file.write(output);
}

async function snapshot(output, core) {
  const { sqliteAdapter } = await dist('adapter-sqlite');
  const file = new VectorFile('snapshot', {
    description:
      'Store snapshots (JSON Lines): a header {"format":"better-iam-store","version":1,"createdAt":<ISO time>,"collections":[sorted names]}, one {"c":collection,"r":record} line per record (collections in order, records by id in code-point order), and a trailer {"end":true,"records":n,"collections":{name:count}}. importStore loads a snapshot into an empty store in one transaction and refuses malformed input.',
    source: 'packages/core/src/snapshot.ts#exportStore,importStore',
    notes: { format: core.SNAPSHOT_FORMAT, version: core.SNAPSHOT_VERSION },
  });
  const RealDate = Date;
  class FixedDate extends RealDate {
    constructor(...args) {
      super(...(args.length ? args : [NOW]));
    }
    static now() {
      return NOW;
    }
  }
  const records = {
    tenants: [
      { id: 'tnt_b', tenantId: 'tnt_b', name: 'B' },
      { id: 'tnt_a', tenantId: 'tnt_a', name: 'A', uniqueKey: 'a' },
    ],
    identities: [
      { id: 'idn_2', tenantId: 'tnt_a', email: 'b@example.com' },
      { id: 'idn_10', tenantId: 'tnt_a', email: 'a@example.com', attributes: { team: 'eng' } },
      { id: 'idn_😀', tenantId: 'tnt_a', email: 'c@example.com' },
    ],
    auditChains: [
      { id: 'tnt_a', tenantId: 'tnt_a', sequence: 2, hash: 'f'.repeat(64), updatedAt: NOW },
    ],
  };
  const exportOf = async (input) => {
    const store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
    await store.transaction(async (tx) => {
      for (const [collection, list] of Object.entries(input.records))
        for (const record of list) await tx.insert(collection, record);
    });
    const lines = [];
    globalThis.Date = FixedDate;
    try {
      const summary = await core.exportStore(
        store,
        (line) => lines.push(line),
        input.options ?? {},
      );
      return { lines, summary: JSON.parse(JSON.stringify(summary)) };
    } finally {
      globalThis.Date = RealDate;
      await store.close();
    }
  };
  const full = await file.add('export all collections', { records }, exportOf);
  await file.add(
    'export selected collections with small pages',
    { records, options: { collections: ['identities', 'tenants', 'identities'], pageSize: 1 } },
    exportOf,
  );
  await file.add('export invalid page size', { records, options: { pageSize: 0 } }, exportOf);
  const importOf = async (input) => {
    const store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
    try {
      if (input.existing) await store.transaction((tx) => tx.insert('tenants', input.existing));
      const summary = await core.importStore(store, input.lines);
      const copied = {};
      for (const collection of await store.collections())
        copied[collection] = (await store.find(collection)).map((record) => record.id);
      return { summary: JSON.parse(JSON.stringify(summary)), stored: copied };
    } finally {
      await store.close();
    }
  };
  const lines = full.lines;
  for (const [name, input] of [
    ['import exported snapshot', { lines }],
    ['import without trailer', { lines: lines.slice(0, -1) }],
    [
      'import with wrong count',
      {
        lines: [...lines.slice(0, -1), JSON.stringify({ end: true, records: 99, collections: {} })],
      },
    ],
    [
      'import wrong format',
      {
        lines: [
          JSON.stringify({ format: 'other', version: 1, collections: [] }),
          JSON.stringify({ end: true, records: 0, collections: {} }),
        ],
      },
    ],
    [
      'import wrong version',
      {
        lines: [
          JSON.stringify({
            format: 'better-iam-store',
            version: 2,
            createdAt: '2026-01-01T00:00:00.000Z',
            collections: [],
          }),
          JSON.stringify({ end: true, records: 0, collections: {} }),
        ],
      },
    ],
    ['import malformed line', { lines: [lines[0], '{not json', lines.at(-1)] }],
    [
      'import record of undeclared collection',
      {
        lines: [
          lines[0],
          JSON.stringify({ c: 'roles', r: { id: 'r', tenantId: 't' } }),
          lines.at(-1),
        ],
      },
    ],
    ['import line after trailer', { lines: [...lines, lines[1]] }],
    ['import empty', { lines: [] }],
    ['import into non-empty store', { lines, existing: { id: 'tnt_x', tenantId: 'tnt_x' } }],
    ['import blank lines', { lines: ['', lines[0], '   ', ...lines.slice(1)] }],
  ])
    await file.add(name, input, importOf);
  return file.write(output);
}

async function sharedSignals(output, core) {
  const file = new VectorFile('shared-signals', {
    description:
      'Security Event Tokens (RFC 8417, SSF 1.0, CAEP, RISC): readSecurityEvent normalizes verified SET claims (iss, aud list, iat, jti, txn, the single event, subject, eventTimestamp in ms) or throws SignalFormatError with a reason; parseSubjectIdentifier / legacyRiscSubject read subjects; signalEventType maps event URIs; userSubjects lists the user identifiers of a subject.',
    source:
      'packages/core/src/shared-signals.ts#readSecurityEvent,parseSubjectIdentifier,legacyRiscSubject,signalEventType,userSubjects',
    notes: { signalEventUris: { ...core.signalEventUris } },
  });
  const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
  const RISC = 'https://schemas.openid.net/secevent/risc/event-type/';
  const SSF = 'https://schemas.openid.net/secevent/ssf/event-type/';
  for (const uri of [
    `${CAEP}session-revoked`,
    `${RISC}account-disabled`,
    `${SSF}verification`,
    `${RISC}verification`,
    'https://schemas.openid.net/secevent/sse/event-type/stream-updated',
    `${CAEP}unknown-thing`,
    '',
    `${CAEP}session-revoked/`,
  ])
    await file.add(
      `signalEventType ${uri.replace(/^https:\/\/schemas\.openid\.net\/secevent\//, '')}`,
      { uri },
      (input) => core.signalEventType(input.uri),
    );
  for (const [name, value] of [
    ['iss_sub', { format: 'iss_sub', iss: 'https://idp.example.com', sub: 'u1' }],
    ['email', { format: 'email', email: 'person@example.com' }],
    ['email invalid', { format: 'email', email: 'not-an-email' }],
    ['opaque', { format: 'opaque', id: 'abc-123' }],
    ['account', { format: 'account', uri: 'acct:person@example.com' }],
    ['account invalid', { format: 'account', uri: 'mailto:person@example.com' }],
    ['phone', { format: 'phone_number', phone_number: '+12025550123' }],
    ['did', { format: 'did', url: 'did:example:123' }],
    ['uri', { format: 'uri', uri: 'https://example.com/users/1' }],
    ['extra members dropped', { format: 'email', email: 'person@example.com', extra: 1 }],
    [
      'aliases',
      {
        format: 'aliases',
        identifiers: [
          { format: 'email', email: 'a@example.com' },
          { format: 'opaque', id: 'x' },
        ],
      },
    ],
    [
      'aliases nested',
      { format: 'aliases', identifiers: [{ format: 'aliases', identifiers: [] }] },
    ],
    [
      'complex',
      {
        format: 'complex',
        user: { format: 'email', email: 'a@example.com' },
        session: { format: 'opaque', id: 's1' },
        tenant: { format: 'opaque', id: 't1' },
      },
    ],
    [
      'complex inside complex',
      { format: 'complex', user: { format: 'complex', user: { format: 'opaque', id: 'x' } } },
    ],
    ['unknown format', { format: 'x500', dn: 'cn=a' }],
    ['not an object', 'email'],
    ['control character', { format: 'opaque', id: 'a\u0000' }],
  ])
    await file.add(`parseSubjectIdentifier ${name}`, { value }, (input) =>
      core.parseSubjectIdentifier(input.value),
    );
  for (const [name, value] of [
    ['iss-sub', { subject_type: 'iss-sub', iss: 'https://accounts.google.com', sub: '123' }],
    ['email', { subject_type: 'email', email: 'a@example.com' }],
    ['phone', { subject_type: 'phone', phone: '+12025550123' }],
    [
      'id_token_claims several',
      {
        subject_type: 'id_token_claims',
        iss: 'https://accounts.google.com',
        sub: '123',
        email: 'a@example.com',
      },
    ],
    ['id_token_claims one', { subject_type: 'id-token-claims', email: 'a@example.com' }],
    [
      'id_token_claims partial iss',
      { subject_type: 'id_token_claims', iss: 'https://accounts.google.com' },
    ],
    ['unknown type', { subject_type: 'oauth_token', token: 'x' }],
  ])
    await file.add(`legacyRiscSubject ${name}`, { value }, (input) =>
      core.legacyRiscSubject(input.value),
    );
  const set = (overrides = {}) => ({
    iss: 'https://idp.example.com/',
    aud: 'https://iam.example.com/api/iam',
    iat: 1767225600,
    jti: 'set-01',
    sub_id: { format: 'iss_sub', iss: 'https://idp.example.com/', sub: 'u1' },
    events: {
      [`${CAEP}session-revoked`]: {
        event_timestamp: 1767225500,
        reason_admin: { en: 'Compromised' },
      },
    },
    ...overrides,
  });
  for (const [name, payload] of [
    ['session revoked', set()],
    ['audience list with repeats', set({ aud: ['a', 'b', 'a'] })],
    [
      'with txn and toe',
      set({
        txn: 'tx-1',
        toe: 1767225000,
        events: {
          [`${CAEP}credential-change`]: { credential_type: 'password', change_type: 'update' },
        },
      }),
    ],
    [
      'legacy RISC subject',
      set({
        sub_id: undefined,
        events: {
          [`${RISC}account-disabled`]: {
            subject: { subject_type: 'iss-sub', iss: 'https://idp.example.com/', sub: 'u1' },
            reason: 'hijacking',
          },
        },
      }),
    ],
    [
      'matching legacy and top-level subject',
      set({
        events: {
          [`${RISC}account-disabled`]: {
            subject: { format: 'iss_sub', iss: 'https://idp.example.com/', sub: 'u1' },
          },
        },
      }),
    ],
    [
      'conflicting legacy and top-level subject',
      set({
        events: {
          [`${RISC}account-disabled`]: { subject: { format: 'email', email: 'x@example.com' } },
        },
      }),
    ],
    ['top-level sub contradicts subject', set({ sub: 'u2' })],
    ['top-level sub agrees', set({ sub: 'u1' })],
    [
      'verification event',
      set({ sub_id: undefined, events: { [`${SSF}verification`]: { state: 'abc' } } }),
    ],
    ['unknown event type', set({ events: { 'https://example.com/event': {} } })],
    ['no events', set({ events: {} })],
    [
      'two events',
      set({ events: { [`${CAEP}session-revoked`]: {}, [`${CAEP}credential-change`]: {} } }),
    ],
    ['event not an object', set({ events: { [`${CAEP}session-revoked`]: 'x' } })],
    ['nonce present', set({ nonce: 'n' })],
    ['missing jti', set({ jti: undefined })],
    ['empty iss', set({ iss: '' })],
    ['missing aud', set({ aud: undefined })],
    ['empty aud list', set({ aud: [] })],
    ['negative iat', set({ iat: -1 })],
    ['string iat', set({ iat: '1767225600' })],
    ['invalid subject', set({ sub_id: { format: 'email', email: 'nope' } })],
    [
      'bad event timestamp',
      set({ events: { [`${CAEP}session-revoked`]: { event_timestamp: 'yesterday' } } }),
    ],
  ])
    await file.add(`readSecurityEvent ${name}`, { payload }, (input) =>
      core.readSecurityEvent(input.payload),
    );
  for (const [name, subject] of [
    ['undefined', undefined],
    ['email', { format: 'email', email: 'a@example.com' }],
    [
      'aliases',
      {
        format: 'aliases',
        identifiers: [
          { format: 'email', email: 'a@example.com' },
          { format: 'iss_sub', iss: 'i', sub: 's' },
        ],
      },
    ],
    [
      'complex with user',
      {
        format: 'complex',
        user: { format: 'email', email: 'a@example.com' },
        session: { format: 'opaque', id: 's1' },
      },
    ],
    ['complex without user', { format: 'complex', session: { format: 'opaque', id: 's1' } }],
  ])
    await file.add(`userSubjects ${name}`, { subject }, (input) =>
      core.userSubjects(input.subject),
    );
  return file.write(output);
}

async function classification(output, core) {
  const file = new VectorFile('classification', {
    description:
      'Security classification (mandatory access control): scheme validation, label validation, ranks, label joins (least upper bound), dominance checks of a clearance party (rank, compartments as a set, citizenship as a set) against a label, and label coverage. Party sets are written as {"$set": [...]}.',
    source:
      'packages/core/src/classification.ts#validateScheme,validateLabel,isValidClassificationLabel,labelRank,joinLabels,dominates,labelCovers,classificationTemplates',
    notes: {
      limits: { ...core.classificationLimits },
      idPattern: core.classificationIdPattern.source,
    },
  });
  for (const name of Object.keys(core.classificationTemplates))
    await file.add(`template ${name}`, { name }, (input) =>
      core.validateScheme(structuredClone(core.classificationTemplates[input.name])),
    );
  const us = structuredClone(core.classificationTemplates.us);
  const scheme = {
    ...us,
    compartments: [
      { id: 'SI', name: 'Special Intelligence' },
      { id: 'TK', name: 'Talent Keyhole' },
    ],
  };
  for (const [name, value] of [
    ['valid with compartments', scheme],
    ['one level', { ...us, levels: [us.levels[0]] }],
    [
      'ranks not increasing',
      {
        ...us,
        levels: [
          { id: 'A', name: 'A', rank: 0 },
          { id: 'B', name: 'B', rank: 0 },
        ],
      },
    ],
    [
      'rank not from zero',
      {
        ...us,
        levels: [
          { id: 'A', name: 'A', rank: 1 },
          { id: 'B', name: 'B', rank: 2 },
        ],
      },
    ],
    [
      'duplicate ids ignoring case',
      {
        ...us,
        levels: [
          { id: 'A', name: 'A', rank: 0 },
          { id: 'a', name: 'B', rank: 1 },
        ],
      },
    ],
    [
      'bad level id',
      {
        ...us,
        levels: [
          { id: '-A', name: 'A', rank: 0 },
          { id: 'B', name: 'B', rank: 1 },
        ],
      },
    ],
    [
      'name with bidi control',
      {
        ...us,
        levels: [
          { id: 'A', name: 'A\u202e', rank: 0 },
          { id: 'B', name: 'B', rank: 1 },
        ],
      },
    ],
    [
      'name with surrounding space',
      {
        ...us,
        levels: [
          { id: 'A', name: ' A', rank: 0 },
          { id: 'B', name: 'B', rank: 1 },
        ],
      },
    ],
    ['unknown field', { ...us, extra: true }],
    ['lower-case country', { ...us, ownerCountries: ['usa'] }],
    ['repeated country', { ...us, ownerCountries: ['USA', 'USA'] }],
    ['unknown caveat', { ...us, caveats: ['ORCON'] }],
    ['NOFORN without owners', { ...us, ownerCountries: [] }],
    ['not an object', 'us'],
  ])
    await file.add(`validateScheme ${name}`, { scheme: value }, (input) =>
      core.validateScheme(input.scheme),
    );
  for (const [name, label] of [
    ['level only', { level: 'S' }],
    ['with compartments', { level: 'TS', compartments: ['TK', 'SI'] }],
    ['noforn', { level: 'S', noforn: true }],
    ['releasable', { level: 'S', releasableTo: ['GBR', 'CAN'] }],
    ['unknown level', { level: 'X' }],
    ['unknown compartment', { level: 'S', compartments: ['ZZ'] }],
    ['noforn and releasable', { level: 'S', noforn: true, releasableTo: ['GBR'] }],
    ['owner in releasable', { level: 'S', releasableTo: ['USA'] }],
    ['unknown field', { level: 'S', owner: 'x' }],
    ['not an object', 'S'],
  ]) {
    await file.add(`validateLabel ${name}`, { label, scheme }, (input) =>
      core.validateLabel(input.label, input.scheme),
    );
    await file.add(`isValidClassificationLabel ${name}`, { label, scheme }, (input) =>
      core.isValidClassificationLabel(input.label, input.scheme),
    );
  }
  for (const label of [{ level: 'U' }, { level: 'TS' }, { level: 'X' }])
    await file.add(`labelRank ${label.level}`, { label, scheme }, (input) =>
      core.labelRank(input.label, input.scheme),
    );
  for (const [name, a, b] of [
    ['higher level wins', { level: 'C' }, { level: 'S' }],
    [
      'compartments union',
      { level: 'S', compartments: ['SI'] },
      { level: 'C', compartments: ['TK'] },
    ],
    ['noforn sticks', { level: 'S', noforn: true }, { level: 'S', releasableTo: ['GBR'] }],
    [
      'releasability intersection',
      { level: 'S', releasableTo: ['GBR', 'CAN'] },
      { level: 'S', releasableTo: ['CAN', 'AUS'] },
    ],
    ['releasable vs unrestricted', { level: 'S', releasableTo: ['GBR'] }, { level: 'S' }],
    ['with undefined', undefined, { level: 'S' }],
    ['both undefined', undefined, undefined],
    ['invalid left', { level: 'X' }, { level: 'S' }],
  ])
    await file.add(`joinLabels ${name}`, { a, b, scheme }, (input) =>
      core.joinLabels(input.a, input.b, input.scheme),
    );
  const party = (rank, compartments = [], citizenship = ['USA']) => ({
    identityId: 'idn_01',
    rank,
    compartments: new Set(compartments),
    citizenship: new Set(citizenship),
  });
  for (const [name, who, label] of [
    ['cleared for level', party(2), { level: 'S' }],
    ['level too low', party(1), { level: 'S' }],
    ['no clearance', party(-1), { level: 'U' }],
    ['missing compartment', party(3, ['SI']), { level: 'TS', compartments: ['SI', 'TK'] }],
    ['all compartments', party(3, ['SI', 'TK']), { level: 'TS', compartments: ['SI', 'TK'] }],
    ['noforn citizen', party(2), { level: 'S', noforn: true }],
    ['noforn foreigner', party(2, [], ['GBR']), { level: 'S', noforn: true }],
    ['releasable to citizen', party(2, [], ['GBR']), { level: 'S', releasableTo: ['GBR'] }],
    ['not releasable', party(2, [], ['FRA']), { level: 'S', releasableTo: ['GBR'] }],
    ['dual citizen', party(2, [], ['FRA', 'USA']), { level: 'S', noforn: true }],
    ['invalid label', party(3), { level: 'X' }],
  ])
    await file.add(
      `dominates ${name}`,
      { party: who, label, scheme },
      (input) => core.dominates(input.party, input.label, input.scheme) ?? null,
    );
  for (const [name, upper, lower] of [
    ['higher covers lower', { level: 'TS' }, { level: 'S' }],
    ['lower does not cover', { level: 'C' }, { level: 'S' }],
    [
      'compartments superset',
      { level: 'TS', compartments: ['SI', 'TK'] },
      { level: 'S', compartments: ['SI'] },
    ],
    [
      'compartments missing',
      { level: 'TS', compartments: ['SI'] },
      { level: 'S', compartments: ['TK'] },
    ],
    [
      'noforn covers releasable',
      { level: 'S', noforn: true },
      { level: 'S', releasableTo: ['GBR'] },
    ],
    [
      'releasable does not cover noforn',
      { level: 'S', releasableTo: ['GBR'] },
      { level: 'S', noforn: true },
    ],
    [
      'narrower releasability covers wider',
      { level: 'S', releasableTo: ['GBR'] },
      { level: 'S', releasableTo: ['GBR', 'CAN'] },
    ],
    ['invalid', { level: 'X' }, { level: 'S' }],
  ])
    await file.add(`labelCovers ${name}`, { upper, lower, scheme }, (input) =>
      core.labelCovers(input.upper, input.lower, input.scheme),
    );
  return file.write(output);
}

export async function coreVectors(output) {
  const core = await dist('core');
  const counts = {};
  counts.jcs = await jcs(output, core);
  counts['canonical-json'] = await canonical(output, core);
  counts['audit-chain'] = await auditChain(output, core);
  counts['policy-evaluation'] = await policyEvaluation(output, core);
  counts['policy-conditions'] = await policyConditions(output, core);
  counts['policy-validation'] = await policyValidation(output, core);
  counts['policy-patterns'] = await patterns(output, core);
  const planned = await plan(output, core);
  counts.plan = planned.count;
  counts['filter-compilers'] = await filterCompilers(output, core, planned.plans);
  counts.storage = await storageVectors(output, core);
  counts.sql = await sqlVectors(output, core);
  counts.snapshot = await snapshot(output, core);
  counts['shared-signals'] = await sharedSignals(output, core);
  counts.classification = await classification(output, core);
  return counts;
}
