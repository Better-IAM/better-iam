import type { SpendGroupBy } from 'better-iam';
import { isIamError } from '@/lib/errors';
import { getIam } from '@/lib/iam';
import { resolveTenant } from '@/lib/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const groupings = new Set(['meter', 'identity', 'agent', 'team', 'department', 'tenant', 'day']);

/**
 * Downloads billing data as CSV, authorized by the request's session cookie: `kind=spend` (the Billing page's report
 * for `period`, grouped by `view`, with `shared=1` spreading unattributed spend) or `kind=statement` (one statement).
 * `kind=invoice` shows one invoice as a printable page (opened in the browser, to print or save as PDF).
 */
export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const org = url.searchParams.get('org');
  const tenant = org ? await resolveTenant(org) : undefined;
  if (!tenant)
    return Response.json(
      { error: { code: 'NOT_FOUND', message: 'Organization not found' } },
      { status: 404 },
    );
  const iam = await getIam();
  const credential = { headers: request.headers };
  try {
    const kind = url.searchParams.get('kind');
    const period = url.searchParams.get('period') ?? undefined;
    const view = url.searchParams.get('view') ?? 'meter';
    const file =
      kind === 'invoice'
        ? await iam.api.billing.renderInvoice(credential, {
            tenantId: tenant.id,
            statementId: url.searchParams.get('statement') ?? '',
          })
        : kind === 'statement'
          ? await iam.api.billing.exportStatement(credential, {
              tenantId: tenant.id,
              statementId: url.searchParams.get('statement') ?? '',
            })
          : await iam.api.billing.exportSpend(credential, {
              tenantId: tenant.id,
              groupBy: (groupings.has(view) ? view : 'meter') as SpendGroupBy,
              ...(period ? { period } : {}),
              ...(url.searchParams.get('shared') === '1' ? { shareUnattributed: true } : {}),
            });
    return new Response(file.body, {
      headers: {
        'content-type': file.contentType,
        'content-disposition': `${kind === 'invoice' ? 'inline' : 'attachment'}; filename="${file.filename.replace(/[^\w.-]/g, '_')}"`,
        'cache-control': 'no-store',
        // The invoice page is self-contained: no scripts, only its own inline styles.
        ...(kind === 'invoice'
          ? {
              'content-security-policy':
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'",
            }
          : {}),
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
