import type { AuditEvent, IamStore, StoredRecord } from './index.js';

/**
 * Tamper-evident audit log: every tenant's audit events form a hash chain. Each event carries its position
 * (`sequence`), the hash of the previous event (`previousHash`), and its own hash over the canonical JSON of the
 * event body. The chain head per tenant lives in `auditChains`. Hashes use SHA-256 through Web Crypto, so this
 * module stays browser-safe and exports can be verified outside the server.
 */
export interface AuditChainHead extends StoredRecord {
  sequence: number;
  hash: string;
  updatedAt: number;
}
export type AuditChainFailure =
  | 'sequence-gap'
  | 'previous-hash-mismatch'
  | 'hash-mismatch'
  | 'head-mismatch'
  /** The whole chain starts after sequence 1 with no `audit:prune` checkpoint in it for the missing events. */
  | 'missing-prefix'
  /** The whole chain holds an event without chain fields: every writer chains, so it was inserted around them. */
  | 'unchained';
export interface AuditChainVerification {
  valid: boolean;
  /** Chained events that were checked. */
  checked: number;
  /**
   * Events without chain fields. A run of events (no `head`) only counts them; verifying a whole chain against its
   * head fails on them.
   */
  unchained: number;
  first?: number;
  last?: number;
  lastHash?: string;
  failure?: { sequence: number; id: string; reason: AuditChainFailure };
}

/** The `previousHash` of the first event of every chain. */
export const auditGenesis = '0'.repeat(64);

/** Deterministic JSON: object keys sorted recursively, `undefined` properties omitted, arrays kept in order. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) =>
    item && typeof item === 'object' && !Array.isArray(item)
      ? Object.fromEntries(
          Object.entries(item as Record<string, unknown>)
            .filter(([, entry]) => entry !== undefined)
            .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : item,
  );
}

async function sha256(input: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** The hash of an event: SHA-256 over the canonical JSON of every field except `hash` itself. */
export async function auditEventHash(event: AuditEvent): Promise<string> {
  const { hash: _hash, ...body } = event;
  return sha256(canonicalJson(body));
}

/**
 * Assigns the next chain position to an event and advances the tenant's chain head. The caller stores the returned
 * event; `appendAuditEvent` does both. Must run inside the transaction that records the event.
 */
export async function chainAuditEvent(tx: IamStore, event: AuditEvent): Promise<AuditEvent> {
  const head = await tx.get<AuditChainHead>('auditChains', event.tenantId);
  const chained: AuditEvent = {
    ...event,
    sequence: (head?.sequence ?? 0) + 1,
    previousHash: head?.hash ?? auditGenesis,
  };
  chained.hash = await auditEventHash(chained);
  const next: AuditChainHead = {
    id: event.tenantId,
    tenantId: event.tenantId,
    sequence: chained.sequence!,
    hash: chained.hash,
    updatedAt: event.timestamp,
  };
  if (head) await tx.put('auditChains', next);
  else await tx.insert('auditChains', next);
  return chained;
}

/** Records an audit event at the end of its tenant's chain. Every audit insert must go through here. */
export async function appendAuditEvent(tx: IamStore, event: AuditEvent): Promise<AuditEvent> {
  const chained = await chainAuditEvent(tx, event);
  await tx.insert('audit', chained);
  return chained;
}

/**
 * Verifies a run of events from one tenant: contiguous sequences, each `previousHash` equal to the previous event's
 * hash (or `previousHash` of the first event when the run starts mid-chain), and every hash recomputable.
 * Events are sorted by sequence first, so exports and database reads can be passed as they come.
 *
 * With `head`, the events are the tenant's whole stored chain, so deleting events at either end or around the chain
 * shows too: it must end at the head (even when no event is left), start at sequence 1 or right after an
 * `audit:prune` checkpoint recorded inside it, and hold no unchained events.
 */
export async function verifyAuditChain(
  events: AuditEvent[],
  options: { previousHash?: string; head?: { sequence: number; hash: string } } = {},
): Promise<AuditChainVerification> {
  const chained = events
    .filter((event) => typeof event.sequence === 'number')
    .sort((a, b) => a.sequence! - b.sequence!);
  const result: AuditChainVerification = {
    valid: true,
    checked: 0,
    unchained: events.length - chained.length,
  };
  let expectedPrevious = options.previousHash;
  let expectedSequence: number | undefined;
  for (const event of chained) {
    const sequence = event.sequence!;
    if (expectedSequence === undefined) {
      expectedSequence = sequence;
      expectedPrevious ??= sequence === 1 ? auditGenesis : event.previousHash;
      result.first = sequence;
    }
    const fail = (reason: AuditChainFailure) => {
      result.valid = false;
      result.failure = { sequence, id: event.id, reason };
      return result;
    };
    if (sequence !== expectedSequence) return fail('sequence-gap');
    if (event.previousHash !== expectedPrevious) return fail('previous-hash-mismatch');
    if ((await auditEventHash(event)) !== event.hash) return fail('hash-mismatch');
    result.checked++;
    result.last = sequence;
    result.lastHash = event.hash;
    expectedPrevious = event.hash;
    expectedSequence = sequence + 1;
  }
  const { head } = options;
  if (!head) return result;
  const fail = (sequence: number, id: string, reason: AuditChainFailure) => {
    result.valid = false;
    result.failure = { sequence, id, reason };
    return result;
  };
  if (head.sequence !== result.last || head.hash !== result.lastHash)
    return fail(result.last ?? head.sequence, chained.at(-1)?.id ?? '', 'head-mismatch');
  const start = chained[0]!;
  if (
    start.sequence! > 1 &&
    !chained.some(
      (event) =>
        event.action === 'audit:prune' &&
        event.metadata?.prunedThroughSequence === start.sequence! - 1 &&
        event.metadata?.prunedThroughHash === start.previousHash,
    )
  )
    return fail(start.sequence!, start.id, 'missing-prefix');
  const loose = events.find((event) => typeof event.sequence !== 'number');
  if (loose) return fail(0, loose.id, 'unchained');
  return result;
}
