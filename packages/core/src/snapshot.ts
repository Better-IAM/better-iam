import { IamError, type IamStore, type StoredRecord } from './index.js';
import { compareIds } from './storage.js';

/**
 * Portable store snapshots: every record of every collection as JSON Lines, independent of the
 * adapter, for backups, moving from SQLite to PostgreSQL, and test fixtures. Records are copied
 * verbatim, so audit hash chains, token hashes, and encrypted secrets stay valid. A snapshot holds
 * credential hashes and encrypted secrets: protect it like the database itself.
 *
 * Format: a header line `{ format, version, createdAt, collections }`, one `{ c, r }` line per
 * record (collection, record), and a trailer `{ end: true, records, collections }` with counts,
 * so a truncated file is detected before anything is committed.
 */
export const SNAPSHOT_FORMAT = 'better-iam-store';
export const SNAPSHOT_VERSION = 1;

export interface SnapshotSummary {
  records: number;
  collections: Record<string, number>;
}
export interface SnapshotOptions {
  /** Collections to include; defaults to every collection the store lists (`collections()`). */
  collections?: string[];
  /** Records read per query while exporting (default 1000). */
  pageSize?: number;
}

/** Counts keyed by collection name; no prototype, so names such as `constructor` count correctly. */
const counts = (): Record<string, number> => Object.create(null) as Record<string, number>;

/** The store's collections, or undefined when it cannot list them (no method, or `UNSUPPORTED`). */
async function listCollections(store: IamStore): Promise<string[] | undefined> {
  if (!store.collections) return undefined;
  try {
    return await store.collections();
  } catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'UNSUPPORTED') return undefined;
    throw error;
  }
}

async function collectionsOf(store: IamStore, options: SnapshotOptions): Promise<string[]> {
  if (options.collections) return [...new Set(options.collections)].sort();
  const listed = await listCollections(store);
  if (!listed)
    throw new IamError(
      'UNSUPPORTED',
      'This store cannot list its collections; pass the collections to copy explicitly',
      501,
    );
  return listed;
}

function pageSizeOf(options: SnapshotOptions): number {
  const size = options.pageSize ?? 1000;
  if (!Number.isSafeInteger(size) || size < 1 || size > 100_000)
    throw new IamError('INVALID_INPUT', 'pageSize must be between 1 and 100000');
  return size;
}

/**
 * Reads every record of the listed collections, a page at a time, in id order. Pages follow an id
 * cursor (`after`), so each costs the same at any depth; a store that ignores the cursor (it
 * returns ids at or before it) is detected and paged by offset instead.
 */
async function eachRecord(
  tx: IamStore,
  collections: string[],
  pageSize: number,
  visit: (collection: string, record: StoredRecord) => Promise<void>,
): Promise<SnapshotSummary> {
  const summary: SnapshotSummary = { records: 0, collections: counts() };
  for (const collection of collections) {
    let count = 0;
    let cursor: string | undefined;
    let keyset = true;
    for (;;) {
      const after = cursor;
      let page = await tx.find(
        collection,
        {},
        after === undefined
          ? { limit: pageSize }
          : keyset
            ? { after, limit: pageSize }
            : { offset: count, limit: pageSize },
      );
      if (
        keyset &&
        after !== undefined &&
        page.some((record) => compareIds(record.id, after) <= 0)
      ) {
        keyset = false;
        page = await tx.find(collection, {}, { offset: count, limit: pageSize });
      }
      cursor = page.at(-1)?.id;
      for (const record of page) {
        await visit(collection, record);
        count++;
      }
      if (page.length < pageSize) break;
    }
    summary.collections[collection] = count;
    summary.records += count;
  }
  return summary;
}

/**
 * Writes a snapshot through `write`, one line at a time (without newlines). Runs in one store
 * transaction, so the snapshot is consistent; that also holds the store's write lock until done.
 */
export async function exportStore(
  store: IamStore,
  write: (line: string) => void | Promise<void>,
  options: SnapshotOptions = {},
): Promise<SnapshotSummary> {
  const pageSize = pageSizeOf(options);
  return store.transaction(async (tx) => {
    const collections = await collectionsOf(tx, options);
    await write(
      JSON.stringify({
        format: SNAPSHOT_FORMAT,
        version: SNAPSHOT_VERSION,
        createdAt: new Date().toISOString(),
        collections,
      }),
    );
    const summary = await eachRecord(tx, collections, pageSize, async (collection, record) => {
      await write(JSON.stringify({ c: collection, r: record }));
    });
    await write(JSON.stringify({ end: true, ...summary }));
    return summary;
  });
}

async function assertEmpty(tx: IamStore, collections: string[] | undefined): Promise<void> {
  const existing = await listCollections(tx);
  if (existing?.length)
    throw new IamError(
      'STORE_NOT_EMPTY',
      `The target store already holds records (${existing.slice(0, 5).join(', ')}); import into an empty, migrated database`,
      409,
    );
  if (!existing)
    for (const collection of collections ?? ['tenants', 'identities'])
      if ((await tx.find(collection, {}, { limit: 1 })).length)
        throw new IamError('STORE_NOT_EMPTY', 'The target store already holds records', 409);
}

/**
 * Loads a snapshot into an empty, migrated store in one transaction: a malformed line, a record
 * the store refuses, or a missing or mismatched trailer rolls everything back.
 */
export async function importStore(
  store: IamStore,
  lines: AsyncIterable<string> | Iterable<string>,
): Promise<SnapshotSummary> {
  return store.transaction(async (tx) => {
    const summary: SnapshotSummary = { records: 0, collections: counts() };
    let header: { collections?: unknown } | undefined;
    let trailer: SnapshotSummary | undefined;
    let lineNumber = 0;
    for await (const raw of lines) {
      lineNumber++;
      const line = raw.trim();
      if (!line) continue;
      if (trailer)
        throw new IamError('SNAPSHOT_INVALID', `Content after the trailer on line ${lineNumber}`);
      let entry: Record<string, unknown>;
      try {
        entry = JSON.parse(line) as Record<string, unknown>;
      } catch {
        throw new IamError('SNAPSHOT_INVALID', `Line ${lineNumber} is not JSON`);
      }
      if (!entry || typeof entry !== 'object' || Array.isArray(entry))
        throw new IamError('SNAPSHOT_INVALID', `Line ${lineNumber} is not an object`);
      if (!header) {
        if (entry.format !== SNAPSHOT_FORMAT || entry.version !== SNAPSHOT_VERSION)
          throw new IamError(
            'SNAPSHOT_INVALID',
            `Not a ${SNAPSHOT_FORMAT} version ${SNAPSHOT_VERSION} snapshot`,
          );
        header = entry;
        await assertEmpty(
          tx,
          Array.isArray(entry.collections)
            ? entry.collections.filter((name): name is string => typeof name === 'string')
            : undefined,
        );
        continue;
      }
      if (entry.end === true) {
        const listed = entry.collections;
        if (!listed || typeof listed !== 'object' || Array.isArray(listed))
          throw new IamError('SNAPSHOT_INVALID', `The trailer on line ${lineNumber} has no counts`);
        trailer = {
          records: Number(entry.records),
          collections: listed as Record<string, number>,
        };
        continue;
      }
      if (typeof entry.c !== 'string' || !entry.r || typeof entry.r !== 'object')
        throw new IamError('SNAPSHOT_INVALID', `Line ${lineNumber} is not a record entry`);
      await tx.insert(entry.c, entry.r as StoredRecord);
      summary.collections[entry.c] = (summary.collections[entry.c] ?? 0) + 1;
      summary.records++;
    }
    if (!header) throw new IamError('SNAPSHOT_INVALID', 'The snapshot is empty');
    if (!trailer)
      throw new IamError('SNAPSHOT_TRUNCATED', 'The snapshot has no trailer; nothing was imported');
    const expected = Object.entries(trailer.collections).filter(([, count]) => count !== 0);
    if (
      trailer.records !== summary.records ||
      expected.length !== Object.keys(summary.collections).length ||
      expected.some(
        ([name, count]) =>
          !Object.hasOwn(summary.collections, name) || summary.collections[name] !== count,
      )
    )
      throw new IamError(
        'SNAPSHOT_TRUNCATED',
        'Record counts do not match the snapshot trailer; nothing was imported',
      );
    return summary;
  });
}

/**
 * Copies every record from `source` into an empty, migrated `target` (for example SQLite to
 * PostgreSQL). Reads in one source transaction and writes in one target transaction, so the copy
 * is consistent and all-or-nothing.
 */
export async function copyStore(
  source: IamStore,
  target: IamStore,
  options: SnapshotOptions = {},
): Promise<SnapshotSummary> {
  const pageSize = pageSizeOf(options);
  try {
    return await source.transaction(async (from) => {
      const collections = await collectionsOf(from, options);
      return target.transaction(async (to) => {
        await assertEmpty(to, collections);
        return eachRecord(from, collections, pageSize, async (collection, record) => {
          await to.insert(collection, record);
        });
      });
    });
  } catch (error) {
    // SQLite and libSQL refuse a second instance's transaction on a file the caller already holds.
    if ((error as { code?: unknown } | null)?.code === 'DATABASE_IN_USE')
      throw new IamError('SAME_DATABASE', 'The source and target are the same database', 409);
    throw error;
  }
}
