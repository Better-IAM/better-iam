/** One page of `audit.export`. */
export interface AuditExportPage {
  count: number;
  body: string;
  firstSequence?: number;
  lastSequence?: number;
  nextSequence?: number;
  head: { sequence: number; hash: string } | null;
}

export interface AuditChainExport {
  /** The first exported sequence; undefined when there is nothing from `from` onward. */
  firstSequence?: number;
  /** The chain head when the export began; the export ends with this event. */
  through: number;
  head: { sequence: number; hash: string } | null;
  /** JSON Lines, one chunk per page, each ending in a newline. */
  chunks: AsyncGenerator<string, void, undefined>;
}

/**
 * Exports an audit chain from `from` through the head as it stood when the export began, reading page by page so a
 * chain longer than one `audit.export` page is never cut short. Stopping at that head keeps the download finite while
 * new events keep arriving and makes its last line the head a verifier compares against.
 */
export async function auditChainExport(
  read: (fromSequence: number) => Promise<AuditExportPage>,
  from = 1,
): Promise<AuditChainExport> {
  const first = await read(from);
  const through = first.head?.sequence ?? 0;
  async function* chunks(): AsyncGenerator<string, void, undefined> {
    let page = first;
    let cursor = from;
    for (;;) {
      if (page.count) {
        if ((page.lastSequence ?? 0) <= through) yield `${page.body}\n`;
        else {
          // Events appended after the export began belong to the next export.
          const kept = page.body
            .split('\n')
            .filter(
              (line) => ((JSON.parse(line) as { sequence?: number }).sequence ?? 0) <= through,
            );
          if (kept.length) yield `${kept.join('\n')}\n`;
          return;
        }
      }
      const next = page.nextSequence;
      if (next === undefined || next > through || next <= cursor) return;
      cursor = next;
      page = await read(next);
    }
  }
  return { firstSequence: first.firstSequence, through, head: first.head, chunks: chunks() };
}
