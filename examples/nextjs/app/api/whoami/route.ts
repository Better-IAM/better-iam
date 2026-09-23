import { iamNext } from '@/lib/iam';

export const runtime = 'nodejs';

// Accepts browser sessions, API keys, and assumed roles; the handler sees a sanitized principal.
export const GET = iamNext.apiRoute(async (_request, { principal }) => ({
  id: principal.identity.id,
  name: principal.identity.name,
  tenantId: principal.session.tenantId,
  kind: principal.session.kind,
  mfa: principal.session.mfa,
}));
