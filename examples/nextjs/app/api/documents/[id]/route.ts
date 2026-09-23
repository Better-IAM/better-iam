import { iamNext } from '@/lib/iam';

export const runtime = 'nodejs';

export const GET = iamNext.route<{ id: string }>(
  async (_request, { session, params }) => ({
    id: params.id,
    reader: session.identity.email,
    tenantId: session.session.tenantId,
  }),
  {
    authorize: {
      action: 'documents:read',
      resource: ({ params }) => ({ type: 'document', id: params.id }),
    },
  },
);
