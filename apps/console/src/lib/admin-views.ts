import type { AuditEvent, IamStore, StoredRecord } from 'better-iam/core';

/**
 * Audit events with one of `actions` at or after `since`, newest first per action, optionally for one tenant.
 * The store filters by equality and pushes only the tenant ID down to SQL, so every find by action decodes the whole
 * audit collection; one read per page view (narrowed to the tenant when one is chosen) does that work once.
 */
export async function auditWindow(
  store: Pick<IamStore, 'find'>,
  input: { actions: string[]; since: number; tenantId?: string },
): Promise<Map<string, AuditEvent[]>> {
  const events = await store.find<AuditEvent>(
    'audit',
    input.tenantId ? { tenantId: input.tenantId } : {},
  );
  const byAction = new Map(input.actions.map((action) => [action, [] as AuditEvent[]]));
  for (const event of events) {
    if (event.timestamp < input.since) continue;
    byAction.get(event.action)?.push(event);
  }
  for (const list of byAction.values()) list.sort((a, b) => b.timestamp - a.timestamp);
  return byAction;
}

/** Point reads for the records a page shows, instead of loading a whole collection to look a few of them up. */
export async function recordsById<T extends StoredRecord>(
  store: Pick<IamStore, 'get'>,
  collection: string,
  ids: Iterable<string>,
): Promise<Map<string, T>> {
  const unique = [...new Set(ids)];
  const records = await Promise.all(unique.map((id) => store.get<T>(collection, id)));
  const result = new Map<string, T>();
  records.forEach((record, index) => {
    if (record) result.set(unique[index]!, record);
  });
  return result;
}

export interface BlockLike {
  network: string;
  active: boolean;
  platform?: boolean;
}

/**
 * The active platform-wide block that covers `ip`, if any. Blocks listed on the root tenant without `platform` apply
 * to the root organization only; treating them as platform-wide would hide the one-click platform block while the
 * address keeps guessing passwords everywhere else.
 */
export function platformBlockFor<T extends BlockLike>(
  blocks: T[],
  ip: string,
  matches: (address: string, network: string) => boolean,
): T | undefined {
  return blocks.find(
    (block) => block.platform === true && block.active && matches(ip, block.network),
  );
}

/** One page of rows (1-based) and whether another follows. */
export function pageOf<T>(
  rows: T[],
  page: number,
  size: number,
): { rows: T[]; page: number; pages: number } {
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const current = Math.min(Math.max(1, Math.floor(page) || 1), pages);
  return { rows: rows.slice((current - 1) * size, current * size), page: current, pages };
}
