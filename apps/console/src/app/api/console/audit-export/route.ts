import { auditChainExport } from '@/lib/audit-export';
import { isIamError } from '@/lib/errors';
import { getIam } from '@/lib/iam';
import { resolveTenant } from '@/lib/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Events per `audit.export` call; the download streams as many pages as the chain needs. */
const PAGE_SIZE = 10_000;

/**
 * Downloads the organization's audit chain as JSON Lines, from `from` (default 1) through the chain head as it stood
 * when the download began, authorized by the request's session cookie. The head is sent as
 * `x-better-iam-head-sequence`; the next incremental export starts one past it.
 */
export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const org = url.searchParams.get('org');
  const from = Number(url.searchParams.get('from') ?? '1');
  const tenant = org ? await resolveTenant(org) : undefined;
  if (!tenant)
    return Response.json(
      { error: { code: 'NOT_FOUND', message: 'Organization not found' } },
      { status: 404 },
    );
  const iam = await getIam();
  const credential = { headers: request.headers };
  try {
    // The first page is read before responding so authorization failures still answer with a JSON error.
    const chain = await auditChainExport(
      (fromSequence) =>
        iam.api.audit.export(credential, { tenantId: tenant.id, fromSequence, limit: PAGE_SIZE }),
      Number.isSafeInteger(from) && from > 0 ? from : 1,
    );
    const last = chain.firstSequence === undefined ? 0 : chain.through;
    const name = `audit-${tenant.slug ?? tenant.id}-${chain.firstSequence ?? 0}-${last}.jsonl`;
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const { value, done } = await chain.chunks.next();
          if (done) controller.close();
          else controller.enqueue(encoder.encode(value));
        } catch (error) {
          // A later page failing (session ended mid-download) aborts the download instead of truncating it silently.
          controller.error(error);
        }
      },
      async cancel() {
        await chain.chunks.return(undefined);
      },
    });
    return new Response(body, {
      headers: {
        'content-type': 'application/x-ndjson; charset=utf-8',
        'content-disposition': `attachment; filename="${name}"`,
        'cache-control': 'no-store',
        'x-better-iam-head-sequence': String(chain.through),
        // Kept for scripts that looped on it: the download is complete through the head, so nothing follows.
        'x-better-iam-next-sequence': '',
      },
    });
  } catch (error) {
    const known = isIamError(error);
    return Response.json(
      {
        error: {
          code: known ? error.code : 'INTERNAL_ERROR',
          message: known ? error.message : 'Export failed',
        },
      },
      { status: known ? error.status : 500 },
    );
  }
}
