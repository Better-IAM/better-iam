import { iamNext } from '@/lib/iam';

// Denied visitors see app/forbidden.tsx through Next's forbidden() (interrupts: 'forbidden').
export default iamNext.page(
  async (_props: { params: Promise<{ org: string; id: string }> }, { session, params }) => (
    <main>
      <h1>Document “{params.id}”</h1>
      <p>
        {session.identity.name} holds <code>documents:read</code> on{' '}
        <code>document/{params.id}</code>.
      </p>
    </main>
  ),
  {
    authorize: {
      action: 'documents:read',
      resource: ({ params }) => ({ type: 'document', id: params.id }),
    },
  },
);
