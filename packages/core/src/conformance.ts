import { IamError, type IamStore, type StoredRecord } from './index.js';
import { compareIds, findOrdered } from './storage.js';

/**
 * Behavioral contract every `IamStore` adapter must satisfy. Framework-agnostic: each case throws
 * on failure. Give every case a freshly created and migrated store, then close it afterwards
 * (a case may close the store itself; `close()` must be idempotent).
 *
 * ```ts
 * for (const test of adapterConformanceCases())
 *   it(test.name, async () => {
 *     const store = myAdapter(options);
 *     await store.migrate();
 *     try { await test.run(store); } finally { await store.close(); }
 *   });
 * ```
 */
export interface ConformanceCase {
  name: string;
  run(store: IamStore): Promise<void>;
}

export class ConformanceFailure extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConformanceFailure';
  }
}

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new ConformanceFailure(message);
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'undefined';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`)
    .join(',')}}`;
}

function same(actual: unknown, expected: unknown, message: string): void {
  const left = canonical(actual);
  const right = canonical(expected);
  check(left === right, `${message}: expected ${right}, received ${left}`);
}

async function rejects(operation: () => Promise<unknown>, code: string, message: string) {
  let failure: unknown;
  try {
    await operation();
  } catch (error) {
    failure = error;
  }
  check(failure !== undefined, `${message}: expected ${code}, but the operation succeeded`);
  const received = failure instanceof IamError ? failure.code : String(failure);
  check(received === code, `${message}: expected ${code}, received ${received}`);
  return failure as IamError;
}

const ids = (records: StoredRecord[]) => records.map((record) => record.id);
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function seed(store: IamStore, collection: string, records: StoredRecord[]): Promise<void> {
  await store.transaction(async (tx) => {
    for (const record of records) await tx.insert(collection, record);
  });
}

const cases: ConformanceCase[] = [
  {
    name: 'round-trips JSON records and returns detached copies',
    async run(store) {
      const record = {
        id: 'r1',
        tenantId: 't1',
        name: 'Ada',
        nested: { list: [1, 'two', true, null, { deep: 'é 😀 中文' }] },
        sum: 0.1 + 0.2,
        large: 2 ** 53 + 2,
        small: 5e-324,
        exponent: 1e21,
      };
      await seed(store, 'items', [record]);
      const read = await store.get('items', 'r1');
      same(read, JSON.parse(JSON.stringify(record)), 'get returns the stored record');
      check(read !== undefined, 'inserted records can be read');
      read.name = 'changed';
      check((await store.get('items', 'r1'))?.name === 'Ada', 'records are detached copies');
      check((await store.get('items', 'missing')) === undefined, 'missing ids read as undefined');
      check((await store.get('other', 'r1')) === undefined, 'collections are separate');
    },
  },
  {
    name: 'enforces identifier and tenant-scoped natural-key uniqueness',
    async run(store) {
      await seed(store, 'users', [
        { id: 'one', tenantId: 'a', uniqueKey: 'same@example.com' },
        { id: 'two', tenantId: 'b', uniqueKey: 'same@example.com' },
        { id: 'three', tenantId: 'a' },
      ]);
      await seed(store, 'groups', [{ id: 'one', tenantId: 'a' }]);
      await rejects(
        () => store.transaction((tx) => tx.insert('users', { id: 'one', tenantId: 'c' })),
        'CONFLICT',
        'ids are unique per collection across tenants',
      );
      await rejects(
        () =>
          store.transaction((tx) =>
            tx.insert('users', { id: 'four', tenantId: 'a', uniqueKey: 'same@example.com' }),
          ),
        'CONFLICT',
        'natural keys are unique within a tenant',
      );
      await rejects(
        () =>
          store.transaction((tx) =>
            tx.put('users', { id: 'three', tenantId: 'a', uniqueKey: 'same@example.com' }),
          ),
        'CONFLICT',
        'put cannot take another record’s natural key',
      );
      await rejects(
        () =>
          store.transaction(async (tx) => {
            await tx.insert('users', { id: 'five', tenantId: 'a' });
            try {
              await tx.insert('users', { id: 'one', tenantId: 'a' });
            } catch {
              /* A caught storage failure still dooms the transaction. */
            }
          }),
        'TRANSACTION_ABORTED',
        'a failed statement aborts the enclosing transaction',
      );
      check((await store.get('users', 'five')) === undefined, 'aborted writes are rolled back');
    },
  },
  {
    name: 'replaces whole records on put without upserting or moving tenants',
    async run(store) {
      await seed(store, 'items', [
        { id: 'x', tenantId: 't1', uniqueKey: 'key-x', label: 'first', extra: true },
      ]);
      await rejects(
        () => store.transaction((tx) => tx.put('items', { id: 'missing', tenantId: 't1' })),
        'NOT_FOUND',
        'put does not insert',
      );
      await rejects(
        () => store.transaction((tx) => tx.put('items', { id: 'x', tenantId: 't2' })),
        'CONFLICT',
        'tenant ownership is immutable',
      );
      await store.transaction((tx) =>
        tx.put('items', { id: 'x', tenantId: 't1', label: 'second' }),
      );
      same(
        await store.get('items', 'x'),
        { id: 'x', tenantId: 't1', label: 'second' },
        'put replaces the record',
      );
      check(
        (await store.find('items', { extra: true })).length === 0,
        'removed fields stop matching',
      );
      await seed(store, 'items', [{ id: 'y', tenantId: 't1', uniqueKey: 'key-x' }]);
      check(
        (await store.find('items', { uniqueKey: 'key-x' }))[0]?.id === 'y',
        'freed keys can be reused',
      );
    },
  },
  {
    name: 'deletes records and ignores missing ids',
    async run(store) {
      await seed(store, 'items', [{ id: 'x', tenantId: 't1', tokenHash: 'abc' }]);
      await store.transaction(async (tx) => {
        await tx.delete('items', 'x');
        await tx.delete('items', 'never-existed');
      });
      check((await store.get('items', 'x')) === undefined, 'deleted records are gone');
      check(
        (await store.find('items', { tokenHash: 'abc' })).length === 0,
        'deleted records stop matching',
      );
    },
  },
  {
    name: 'requires a transaction for every write',
    async run(store) {
      await rejects(
        () => store.insert('items', { id: 'x', tenantId: 't' }),
        'TRANSACTION_REQUIRED',
        'insert',
      );
      await seed(store, 'items', [{ id: 'y', tenantId: 't' }]);
      await rejects(
        () => store.put('items', { id: 'y', tenantId: 't', v: 1 }),
        'TRANSACTION_REQUIRED',
        'put',
      );
      await rejects(() => store.delete('items', 'y'), 'TRANSACTION_REQUIRED', 'delete');
      check((await store.get('items', 'y'))?.v === undefined, 'rejected writes change nothing');
    },
  },
  {
    name: 'rolls back failed transactions and joins nested ones',
    async run(store) {
      const failure = new Error('application failure');
      let thrown: unknown;
      try {
        await store.transaction(async (tx) => {
          await tx.insert('items', { id: 'a', tenantId: 't' });
          throw failure;
        });
      } catch (error) {
        thrown = error;
      }
      check(thrown === failure, 'the callback’s error propagates unchanged');
      check((await store.get('items', 'a')) === undefined, 'a throwing callback rolls back');
      await store.transaction(async (tx) => {
        await tx.insert('items', { id: 'b', tenantId: 't' });
        await store.transaction(async (inner) => {
          check(
            (await inner.get('items', 'b')) !== undefined,
            'nested transactions see outer writes',
          );
          await inner.insert('items', { id: 'c', tenantId: 't' });
        });
        await tx.transaction((inner) => inner.insert('items', { id: 'd', tenantId: 't' }));
      });
      same(
        ids(await store.find('items')),
        ['b', 'c', 'd'],
        'nested writes commit with the outer transaction',
      );
      await rejects(
        () =>
          store.transaction(async (tx) => {
            await tx.insert('items', { id: 'e', tenantId: 't' });
            try {
              await tx.transaction(async () => {
                throw new Error('inner failure');
              });
            } catch {
              /* The outer transaction must still roll back. */
            }
          }),
        'TRANSACTION_ABORTED',
        'a failed nested transaction aborts the outer one',
      );
      check(
        (await store.get('items', 'e')) === undefined,
        'nested failures roll back outer writes',
      );
    },
  },
  {
    name: 'rejects transaction handles after completion',
    async run(store) {
      let leaked: IamStore | undefined;
      await store.transaction(async (tx) => {
        leaked = tx;
        await tx.insert('items', { id: 'a', tenantId: 't' });
      });
      await rejects(
        () => leaked!.get('items', 'a'),
        'TRANSACTION_CLOSED',
        'reads through a leaked handle',
      );
      await rejects(
        () => leaked!.insert('items', { id: 'b', tenantId: 't' }),
        'TRANSACTION_CLOSED',
        'writes through a leaked handle',
      );
    },
  },
  {
    name: 'serializes concurrent read-modify-write transactions',
    async run(store) {
      await seed(store, 'counters', [{ id: 'c', tenantId: 't', value: 0 }]);
      await Promise.all(
        Array.from({ length: 8 }, (_, index) =>
          store.transaction(async (tx) => {
            const current = await tx.get<StoredRecord & { value: number }>('counters', 'c');
            await delay(index % 3);
            await tx.put('counters', { ...current!, value: current!.value + 1 });
          }),
        ),
      );
      check((await store.get('counters', 'c'))?.value === 8, 'no update is lost');
    },
  },
  {
    name: 'matches filters with strict, typed JSON equality',
    async run(store) {
      const values: Record<string, unknown> = {
        a: 1,
        b: '1',
        c: true,
        d: 'true',
        e: null,
        g: { x: 1, y: [1, 2] },
        h: [1, 2],
        i: [2, 1],
        j: { x: 1 },
        k: 0,
        l: 'Abc',
        m: 'abc',
        n: 'é',
        o: 'é',
        p: 1.5,
        q: '',
        r: ' abc',
        s: [],
        t: {},
        u: false,
        w: [null, 1],
      };
      await seed(store, 'values', [
        ...Object.entries(values).map(([id, v]) => ({ id, tenantId: 't', v })),
        { id: 'f', tenantId: 't' },
      ]);
      const expectations: [unknown, string[]][] = [
        [1, ['a']],
        ['1', ['b']],
        [true, ['c']],
        [false, ['u']],
        ['true', ['d']],
        [null, ['e']],
        [undefined, ['f']],
        [{ y: [1, 2], x: 1 }, ['g']],
        [[1, 2], ['h']],
        [[2, 1], ['i']],
        [{ x: 1 }, ['j']],
        [[null, 1], ['w']],
        [0, ['k']],
        [-0, ['k']],
        ['abc', ['m']],
        ['Abc', ['l']],
        ['é', ['o']],
        ['é', ['n']],
        [1.5, ['p']],
        ['', ['q']],
        [[], ['s']],
        [{}, ['t']],
      ];
      for (const [value, expected] of expectations)
        same(
          ids(await store.find('values', { v: value })),
          expected,
          `filter v = ${canonical(value)}`,
        );
      same(ids(await store.find('values', { missing: 'x' })), [], 'filters on absent fields');
      same(
        ids(await store.find('values', { v: 1, tenantId: 't' })),
        ['a'],
        'conditions combine with AND',
      );
      same(
        ids(await store.find('values', { v: 1, tenantId: 'other' })),
        [],
        'tenant narrows results',
      );
      // Array values that JSON cannot represent exactly compare by own keys, like any filter.
      const sparse: unknown[] = [];
      sparse[1] = 1;
      same(ids(await store.find('values', { v: sparse })), [], 'a sparse array filter');
      const labelled = Object.assign([1, 2], { label: 'x' });
      same(ids(await store.find('values', { v: labelled })), [], 'an array with extra properties');
      same(
        ids(await store.find('values', { v: false, ['absent\u0000key']: undefined })),
        ['u'],
        'absence of a key no database can name',
      );
      const wide: Record<string, unknown> = { v: 1.5 };
      for (let index = 0; index < 40; index++) wide[`missing${index}`] = undefined;
      same(ids(await store.find('values', wide)), ['p'], 'forty conditions');
      wide.missing39 = 'present';
      same(ids(await store.find('values', wide)), [], 'forty conditions, one failing');
    },
  },
  {
    name: 'filters by id, tenant, and natural-key columns',
    async run(store) {
      await seed(store, 'keys', [
        { id: 'a', tenantId: 't1', uniqueKey: 'k1' },
        { id: 'b', tenantId: 't2', uniqueKey: 'k1' },
        { id: 'c', tenantId: 't1' },
      ]);
      same(ids(await store.find('keys', { id: 'a' })), ['a'], 'id filter');
      same(ids(await store.find('keys', { id: 5 })), [], 'non-string id filter');
      same(ids(await store.find('keys', { tenantId: 't1' })), ['a', 'c'], 'tenant filter');
      same(ids(await store.find('keys', { tenantId: undefined })), [], 'absent tenant filter');
      same(
        ids(await store.find('keys', { uniqueKey: 'k1' })),
        ['a', 'b'],
        'natural key across tenants',
      );
      same(
        ids(await store.find('keys', { uniqueKey: undefined })),
        ['c'],
        'records without a natural key',
      );
      same(ids(await store.find('keys', { uniqueKey: null })), [], 'natural keys are never null');
      same(
        ids(await store.find('keys', { tenantId: 't1', uniqueKey: 'k1', id: 'a' })),
        ['a'],
        'combined columns',
      );
    },
  },
  {
    name: 'filters on field names that cannot appear in SQL',
    async run(store) {
      const names = [
        'dotted.key',
        'with space',
        'quote"key',
        "apostrophe'key",
        '$dollar',
        '123start',
        'unicodé',
        '',
      ];
      await seed(
        store,
        'names',
        names.map((name, index) => ({ id: `n${index}`, tenantId: 't', [name]: 'match' })),
      );
      for (const [index, name] of names.entries())
        same(
          ids(await store.find('names', { [name]: 'match' })),
          [`n${index}`],
          `field ${JSON.stringify(name)}`,
        );
    },
  },
  {
    name: 'stores and finds strings with U+0000, unpaired surrogates, and reserved keys',
    async run(store) {
      const escapeKey = '\u0001better-iam';
      const records: StoredRecord[] = [
        { id: 'a', tenantId: 't', kind: 'odd', v: 'a\u0000b' },
        { id: 'b', tenantId: 't', kind: 'odd', v: '\ud800' },
        { id: 'c', tenantId: 't', kind: 'odd', v: 'x\udc00y' },
        { id: 'd', tenantId: 't', kind: 'odd', ['k\u0000']: 1, v: 'plain' },
        {
          id: 'e',
          tenantId: 't',
          kind: 'odd',
          v: { list: ['\u0000', '\ud83d'], [escapeKey]: 'x' },
        },
        { id: 'f', tenantId: 't', kind: 'odd', v: { [escapeKey]: 'deadbeef' } },
        { id: 'g', tenantId: 't', kind: 'plain', v: '�' },
        { id: 'h', tenantId: 't', kind: 'plain', v: '😀' },
      ];
      await seed(store, 'strings', records);
      for (const record of records)
        same(await store.get('strings', record.id), record, `round trip of ${record.id}`);
      const byValue: [unknown, string[]][] = [
        ['a\u0000b', ['a']],
        ['\ud800', ['b']],
        ['x\udc00y', ['c']],
        ['plain', ['d']],
        [{ list: ['\u0000', '\ud83d'], [escapeKey]: 'x' }, ['e']],
        [{ [escapeKey]: 'deadbeef' }, ['f']],
        ['�', ['g']],
        ['😀', ['h']],
        ['a', []],
      ];
      for (const [value, expected] of byValue)
        same(
          ids(await store.find('strings', { v: value })),
          expected,
          `filter v = ${canonical(value)}`,
        );
      same(
        ids(await store.find('strings', { kind: 'odd' })),
        ['a', 'b', 'c', 'd', 'e', 'f'],
        'sibling fields',
      );
      same(ids(await store.find('strings', { ['k\u0000']: 1 })), ['d'], 'a key with U+0000');
      same(
        ids(await store.find('strings', { kind: 'odd' }, { offset: 4, limit: 5 })),
        ['e', 'f'],
        'paged',
      );
      // Identifiers must survive UTF-8 unchanged: an unpaired surrogate would alias U+FFFD.
      await rejects(
        () => store.transaction((tx) => tx.insert('strings', { id: 'x\ud800', tenantId: 't' })),
        'INVALID_RECORD',
        'an id with an unpaired surrogate',
      );
      await seed(store, 'strings', [{ id: 'x�', tenantId: 't�' }]);
      check((await store.get('strings', 'x\ud800')) === undefined, 'no alias through get');
      same(ids(await store.find('strings', { id: 'x\ud800' })), [], 'no alias through find');
      same(ids(await store.find('strings', { tenantId: 't\udc00' })), [], 'no tenant alias');
      await store.transaction((tx) => tx.delete('strings', 'x\ud800'));
      check((await store.get('strings', 'x�')) !== undefined, 'no alias through delete');
    },
  },
  {
    name: 'orders by id in code-point order and paginates deterministically',
    async run(store) {
      const order = ['b', 'B', 'a', 'A', '0', '~', '_', 'é', 'z', '￿', '😀', '', 'aa', 'a-'];
      await seed(
        store,
        'ordered',
        order.map((id, index) => ({ id, tenantId: 't', kind: 'x', 'odd key': index % 2 })),
      );
      const expected = [...order].sort(compareIds);
      same(ids(await store.find('ordered')), expected, 'unfiltered order');
      same(ids(await store.find('ordered', { kind: 'x' })), expected, 'filtered order');
      const pages: [offset: number, limit: number][] = [
        [0, 3],
        [3, 3],
        [12, 5],
        [14, 2],
        [20, 1],
      ];
      for (const [offset, limit] of pages) {
        const page = expected.slice(offset, offset + limit);
        same(
          ids(await store.find('ordered', {}, { offset, limit })),
          page,
          `page ${offset}+${limit}`,
        );
        same(
          ids(await store.find('ordered', { kind: 'x' }, { offset, limit })),
          page,
          `filtered page ${offset}+${limit}`,
        );
      }
      same(ids(await store.find('ordered', {}, { limit: 0 })), [], 'limit 0');
      same(
        ids(await store.find('ordered', { kind: 'x' }, { offset: 5 })),
        expected.slice(5),
        'offset without limit',
      );
      const odd = expected.filter((id) => order.indexOf(id) % 2 === 1);
      same(
        ids(await store.find('ordered', { 'odd key': 1 }, { offset: 1, limit: 3 })),
        odd.slice(1, 4),
        'in-memory filter page',
      );
      await rejects(
        () => store.find('ordered', {}, { offset: -1 }),
        'INVALID_FILTER',
        'negative offset',
      );
      await rejects(
        () => store.find('ordered', {}, { limit: 1.5 }),
        'INVALID_FILTER',
        'fractional limit',
      );
    },
  },
  {
    name: 'pages with an id cursor in code-point order',
    async run(store) {
      const order = ['b', 'B', 'a', 'A', '0', '~', '_', 'é', 'z', '￿', '😀', '', 'aa', 'a-', 'u1'];
      const records = order.map((id, index) => ({
        id,
        tenantId: id === 'u1' ? 'u' : 't',
        kind: index % 3 === 0 ? 'x' : 'y',
        'odd key': index % 2,
      }));
      await seed(store, 'cursor', records);
      const byId = new Map(records.map((record) => [record.id, record]));
      const expected = [...order].sort(compareIds);
      const after = (cursor: string, keep: (id: string) => boolean = () => true) =>
        expected.filter((id) => compareIds(id, cursor) > 0 && keep(id));
      for (const size of [1, 4]) {
        const walked: string[] = [];
        let cursor: string | undefined;
        for (let guard = 0; guard <= order.length; guard++) {
          const page = await store.find(
            'cursor',
            {},
            cursor === undefined ? { limit: size } : { after: cursor, limit: size },
          );
          walked.push(...ids(page));
          if (page.length < size) break;
          cursor = page.at(-1)!.id;
        }
        same(walked, expected, `walk in pages of ${size}`);
      }
      same(ids(await store.find('cursor', {}, { after: 'a' })), after('a'), 'cursor between ids');
      same(ids(await store.find('cursor', {}, { after: '' })), expected, 'empty cursor');
      same(ids(await store.find('cursor', {}, { after: '\u{10FFFF}' })), [], 'past the last id');
      same(
        ids(await store.find('cursor', {}, { after: '\ud83d' })),
        after('\ud83d'),
        'cursor with an unpaired surrogate',
      );
      same(
        ids(await store.find('cursor', { kind: 'x' }, { after: 'B', limit: 2 })),
        after('B', (id) => byId.get(id)!.kind === 'x').slice(0, 2),
        'filtered cursor page',
      );
      same(
        ids(await store.find('cursor', {}, { after: 'a', offset: 1, limit: 1 })),
        after('a').slice(1, 2),
        'cursor with offset',
      );
      same(
        ids(await store.find('cursor', { kind: 'y' }, { after: 'B', offset: 1, limit: 2 })),
        after('B', (id) => byId.get(id)!.kind === 'y').slice(1, 3),
        'filtered cursor with offset',
      );
      same(
        ids(await store.find('cursor', { tenantId: 't' }, { after: '_' })),
        after('_', (id) => byId.get(id)!.tenantId === 't'),
        'tenant cursor',
      );
      same(
        ids(await store.find('cursor', { 'odd key': 1 }, { after: 'B', offset: 1, limit: 2 })),
        after('B', (id) => byId.get(id)!['odd key'] === 1).slice(1, 3),
        'in-memory filter with cursor and offset',
      );
      await rejects(
        () => store.find('cursor', {}, { after: 5 as unknown as string }),
        'INVALID_FILTER',
        'non-string cursor',
      );
    },
  },
  {
    name: 'finds numbers by value across the whole double range',
    async run(store) {
      const numbers = [
        0,
        1,
        -1,
        0.1 + 0.2,
        2 ** 53 - 1,
        2 ** 53 + 2,
        2 ** 60,
        -(2 ** 60),
        4611686018427389000,
        9223372036854775000,
        2 ** 64,
        1e16,
        1e17,
        1e21,
        1e-7,
        1e-300,
        5e-324,
        1.7125808327557952e177,
        -7.491602062452078e303,
        2.2093402303347207e-113,
        Number.MAX_VALUE,
      ];
      await seed(
        store,
        'numbers',
        numbers.flatMap((n, index) => [
          { id: `n${index}`, tenantId: 't', n },
          { id: `n${index}-copy`, tenantId: 't', n },
        ]),
      );
      for (const [index, n] of numbers.entries()) {
        same(ids(await store.find('numbers', { n })), [`n${index}`, `n${index}-copy`], `n = ${n}`);
        same(
          ids(await store.find('numbers', { n }, { offset: 1, limit: 1 })),
          [`n${index}-copy`],
          `paged n = ${n}`,
        );
        same((await store.get('numbers', `n${index}`))?.n, n, `round trip of ${n}`);
      }
    },
  },
  {
    name: 'pages selectively filtered results across many rows',
    async run(store) {
      const records = Array.from({ length: 300 }, (_, index) => ({
        id: `r${String(index).padStart(3, '0')}`,
        tenantId: index % 2 ? 'odd' : 'even',
        third: index % 3 === 0,
        group: `g${index % 7}`,
        'in memory': index % 5,
      }));
      await seed(store, 'rows', records);
      same((await store.find('rows')).length, 300, 'no silent truncation');
      const selective = records.filter((record) => record.third && record.tenantId === 'even');
      const expected = selective.map((record) => record.id);
      same(ids(await store.find('rows', { third: true, tenantId: 'even' })), expected, 'filtered');
      for (const [offset, limit] of [
        [0, 7],
        [7, 7],
        [45, 10],
        [49, 3],
      ] as const)
        same(
          ids(await store.find('rows', { third: true, tenantId: 'even' }, { offset, limit })),
          expected.slice(offset, offset + limit),
          `page ${offset}+${limit}`,
        );
      const mixed = records
        .filter((record) => record.group === 'g3' && record['in memory'] === 2)
        .map((record) => record.id);
      same(
        ids(await store.find('rows', { group: 'g3', 'in memory': 2 }, { offset: 1, limit: 4 })),
        mixed.slice(1, 5),
        'page of a partly in-memory filter',
      );
    },
  },
  {
    name: 'finds uncommitted writes inside the writing transaction',
    async run(store) {
      await seed(store, 'drafts', [{ id: 'a', tenantId: 't', state: 'old', kind: 'x' }]);
      await rejects(
        () =>
          store.transaction(async (tx) => {
            await tx.insert('drafts', { id: 'b', tenantId: 't', state: 'new', kind: 'x' });
            await tx.put('drafts', { id: 'a', tenantId: 't', state: 'new', kind: 'x' });
            same(ids(await tx.find('drafts', { state: 'new' })), ['a', 'b'], 'exact filter');
            same(ids(await tx.find('drafts', { state: 'new' }, { limit: 1 })), ['a'], 'exact page');
            same(ids(await tx.find('drafts', { state: 'old' })), [], 'replaced value');
            same(
              ids(await store.find('drafts', { kind: 'x', 'x y': undefined })),
              ['a', 'b'],
              'joined read',
            );
            await tx.delete('drafts', 'a');
            same(ids(await tx.find('drafts', { kind: 'x' })), ['b'], 'deleted inside');
            throw new IamError('ROLLBACK', 'discard');
          }),
        'ROLLBACK',
        'the draft transaction',
      );
      same(ids(await store.find('drafts', { state: 'old' })), ['a'], 'rolled back');
    },
  },
  {
    name: 'orders, bounds, and pages by a numeric field',
    async run(store) {
      const stamps: unknown[] = [5, 3, 5, -1, 2 ** 60, 0.5, 7, '6', null, undefined, 5, 1e21, 3];
      const records = Array.from({ length: 300 }, (_, index) => {
        const record: StoredRecord = {
          id: `e${String((index * 37) % 300).padStart(3, '0')}`,
          tenantId: index % 3 === 0 ? 'other' : 't',
          kind: index % 4 === 0 ? 'x' : 'y',
        };
        const stamp = stamps[index % stamps.length];
        if (stamp !== undefined) record.timestamp = stamp;
        return record;
      });
      await seed(store, 'events', records);
      const reference = (filter: (record: StoredRecord) => boolean, desc: boolean) =>
        records
          .filter((record) => typeof record.timestamp === 'number' && filter(record))
          .sort(
            (a, b) =>
              (desc ? -1 : 1) * ((a.timestamp as number) - (b.timestamp as number)) ||
              compareIds(a.id, b.id),
          )
          .map((record) => record.id);
      const tenant = (record: StoredRecord) => record.tenantId === 't';
      for (const direction of ['asc', 'desc'] as const) {
        const all = reference(tenant, direction === 'desc');
        same(
          ids(
            await findOrdered(
              store,
              'events',
              { tenantId: 't' },
              { field: 'timestamp', direction },
            ),
          ),
          all,
          `${direction} order`,
        );
        for (const [offset, limit] of [
          [0, 10],
          [15, 20],
          [all.length - 3, 10],
        ] as const)
          same(
            ids(
              await findOrdered(
                store,
                'events',
                { tenantId: 't' },
                { field: 'timestamp', direction, offset, limit },
              ),
            ),
            all.slice(offset, offset + limit),
            `${direction} page ${offset}+${limit}`,
          );
      }
      const bounded = reference(
        (record) =>
          tenant(record) &&
          (record.timestamp as number) >= 0.5 &&
          (record.timestamp as number) <= 5,
        false,
      );
      same(
        ids(
          await findOrdered(
            store,
            'events',
            { tenantId: 't' },
            { field: 'timestamp', from: 0.5, to: 5 },
          ),
        ),
        bounded,
        'bounded range',
      );
      same(
        ids(
          await findOrdered(
            store,
            'events',
            { tenantId: 't' },
            { field: 'timestamp', from: 2 ** 60, to: 2 ** 60 },
          ),
        ),
        reference((record) => tenant(record) && record.timestamp === 2 ** 60, false),
        'a bound above 2^53',
      );
      const xs = reference((record) => tenant(record) && record.kind === 'x', true);
      same(
        ids(
          await findOrdered(
            store,
            'events',
            { tenantId: 't', kind: 'x' },
            {
              field: 'timestamp',
              direction: 'desc',
              offset: 2,
              limit: 7,
            },
          ),
        ),
        xs.slice(2, 9),
        'filtered page',
      );
      same(
        ids(
          await findOrdered<StoredRecord>(
            store,
            'events',
            { tenantId: 't' },
            {
              field: 'timestamp',
              direction: 'desc',
              offset: 3,
              limit: 5,
              where: (record) => record.kind === 'x',
            },
          ),
        ),
        xs.slice(3, 8),
        'in-memory predicate page',
      );
      await rejects(
        () => findOrdered(store, 'events', {}, { field: 'not a field' }),
        'INVALID_FILTER',
        'an order field that is not an identifier',
      );
      await rejects(
        () => findOrdered(store, 'events', {}, { field: 'timestamp', from: Number.NaN }),
        'INVALID_FILTER',
        'a NaN bound',
      );
      await rejects(
        () =>
          store.transaction(async (tx) => {
            await tx.insert('events', { id: 'z-new', tenantId: 't', timestamp: 1e22 });
            same(
              ids(
                await findOrdered(
                  tx,
                  'events',
                  { tenantId: 't' },
                  { field: 'timestamp', direction: 'desc', limit: 1 },
                ),
              ),
              ['z-new'],
              'uncommitted write in order',
            );
            throw new IamError('ROLLBACK', 'discard');
          }),
        'ROLLBACK',
        'the ordered draft',
      );
    },
  },
  {
    name: 'validates records before writing',
    async run(store) {
      const circular: Record<string, unknown> = { id: 'x', tenantId: 't' };
      circular.self = circular;
      const invalid: [string, unknown][] = [
        ['a Date', { id: 'x', tenantId: 't', at: new Date(0) }],
        ['NaN', { id: 'x', tenantId: 't', v: Number.NaN }],
        ['Infinity', { id: 'x', tenantId: 't', v: Number.POSITIVE_INFINITY }],
        ['a Map', { id: 'x', tenantId: 't', v: new Map() }],
        ['a function', { id: 'x', tenantId: 't', v: () => 1 }],
        ['a symbol key', { id: 'x', tenantId: 't', [Symbol('s')]: 1 }],
        ['a circular reference', circular],
        ['a __proto__ key', JSON.parse('{"id":"x","tenantId":"t","__proto__":1}')],
        ['an undefined array item', { id: 'x', tenantId: 't', v: [undefined] }],
        ['an empty id', { id: '', tenantId: 't' }],
        ['an oversized id', { id: 'é'.repeat(257), tenantId: 't' }],
        ['a control character in tenantId', { id: 'x', tenantId: 't\n' }],
        ['a null natural key', { id: 'x', tenantId: 't', uniqueKey: null }],
        ['an oversized record', { id: 'x', tenantId: 't', v: 'a'.repeat(1_048_577) }],
      ];
      for (const [label, record] of invalid)
        await rejects(
          () => store.transaction((tx) => tx.insert('invalid', record as StoredRecord)),
          'INVALID_RECORD',
          label,
        );
      check((await store.find('invalid')).length === 0, 'no invalid record was written');
    },
  },
  {
    name: 'keeps lookups consistent through updates and deletes',
    async run(store) {
      await seed(store, 'sessions', [
        { id: 's1', tenantId: 't1', tokenHash: 'h1', identityId: 'i1' },
        { id: 's2', tenantId: 't2', tokenHash: 'h2', identityId: 'i1' },
        { id: 's3', tenantId: 't1', tokenHash: 'h3', identityId: 'i2' },
      ]);
      same(ids(await store.find('sessions', { tokenHash: 'h2' })), ['s2'], 'lookup across tenants');
      same(
        ids(await store.find('sessions', { identityId: 'i1' })),
        ['s1', 's2'],
        'secondary lookup',
      );
      same(
        ids(await store.find('sessions', { identityId: 'i1', tenantId: 't1' })),
        ['s1'],
        'tenant-scoped lookup',
      );
      await store.transaction((tx) =>
        tx.put('sessions', { id: 's2', tenantId: 't2', tokenHash: 'h4', identityId: 'i1' }),
      );
      same(
        ids(await store.find('sessions', { tokenHash: 'h2' })),
        [],
        'old value no longer matches',
      );
      same(ids(await store.find('sessions', { tokenHash: 'h4' })), ['s2'], 'new value matches');
      await store.transaction((tx) => tx.delete('sessions', 's1'));
      same(
        ids(await store.find('sessions', { identityId: 'i1' })),
        ['s2'],
        'deleted records disappear',
      );
      same(ids(await store.find('sessions', { tokenHash: 1 })), [], 'typed lookups never coerce');
    },
  },
  {
    name: 'migrates idempotently without touching data',
    async run(store) {
      await seed(store, 'items', [{ id: 'kept', tenantId: 't', tokenHash: 'h' }]);
      await store.migrate();
      await store.migrate();
      same(ids(await store.find('items', { tokenHash: 'h' })), ['kept'], 'data survives migration');
    },
  },
  {
    name: 'reports storage conflicts without leaking SQL or record data',
    async run(store) {
      await seed(store, 'items', [
        { id: 'x', tenantId: 't', uniqueKey: 'key-do-not-leak', secret: 'do-not-leak' },
      ]);
      const conflicts = [
        await rejects(
          () =>
            store.transaction((tx) =>
              tx.insert('items', { id: 'x', tenantId: 't', secret: 'do-not-leak' }),
            ),
          'CONFLICT',
          'duplicate id',
        ),
        await rejects(
          () =>
            store.transaction((tx) =>
              tx.insert('items', {
                id: 'y',
                tenantId: 't',
                uniqueKey: 'key-do-not-leak',
                secret: 'do-not-leak',
              }),
            ),
          'CONFLICT',
          'duplicate natural key',
        ),
      ];
      for (const error of conflicts) {
        const exposed = [
          error.message,
          String(error),
          JSON.stringify(error),
          // Every own property except the stack, whose frames name adapter methods such as insert.
          ...Object.getOwnPropertyNames(error)
            .filter((name) => name !== 'stack')
            .map((name) => String(Reflect.get(error, name))),
          String((error as { cause?: unknown }).cause ?? ''),
        ].join('\n');
        check(
          !/insert|select|iam_records|do-not-leak/i.test(exposed),
          'errors carry no SQL, table names, or record data',
        );
      }
    },
  },
  {
    name: 'closes idempotently and rejects later use',
    async run(store) {
      await store.close();
      await store.close();
      await rejects(() => store.get('items', 'x'), 'STORE_CLOSED', 'reads after close');
      await rejects(
        () => store.transaction(async () => undefined),
        'STORE_CLOSED',
        'transactions after close',
      );
    },
  },
];

/** A fresh copy of every conformance case, in a stable order. */
export function adapterConformanceCases(): ConformanceCase[] {
  return cases.map((test) => ({ ...test }));
}

/** Runs every case against fresh stores and collects failures instead of stopping at the first. */
export async function runAdapterConformance(
  createStore: () => IamStore | Promise<IamStore>,
): Promise<{ passed: string[]; failed: { name: string; error: unknown }[] }> {
  const passed: string[] = [];
  const failed: { name: string; error: unknown }[] = [];
  for (const test of adapterConformanceCases()) {
    const store = await createStore();
    try {
      await store.migrate();
      await test.run(store);
      passed.push(test.name);
    } catch (error) {
      failed.push({ name: test.name, error });
    } finally {
      await store.close();
    }
  }
  return { passed, failed };
}
