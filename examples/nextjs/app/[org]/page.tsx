import { iamNext } from '@/lib/iam';

export default iamNext.page(async (_props: { params: Promise<{ org: string }> }, { session }) => {
  const tenantId = session.session.tenantId;
  const document = { type: 'document', id: 'roadmap' };
  const access = await iamNext.can({
    tenantId,
    checks: [
      { action: 'documents:read', resource: document },
      { action: 'documents:write', resource: document },
      { action: 'iam:identities:read' },
    ],
  });
  return (
    <main>
      <h1>Welcome, {session.identity.name}</h1>
      <p>
        Signed in as <code>{session.identity.email}</code> with{' '}
        <code>{session.session.method ?? 'unknown'}</code>. This layout and page share one session
        lookup per request.
      </p>
      <iamNext.Can
        action="documents:write"
        resource={document}
        fallback={<p className="error">Read-only: no documents:write on the roadmap.</p>}
      >
        <p className="ok">You may edit the roadmap.</p>
      </iamNext.Can>
      <h2>Advisory decisions</h2>
      <table>
        <tbody>
          {Object.entries(access).map(([check, allowed]) => (
            <tr key={check}>
              <td>
                <code>{check}</code>
              </td>
              <td className={allowed ? 'ok' : 'error'}>{allowed ? 'allowed' : 'denied'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
});
