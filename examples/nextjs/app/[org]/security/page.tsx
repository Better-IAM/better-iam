import { iamNext } from '@/lib/iam';

// A deliberately short window so the step-up is easy to see; production pages would use minutes.
const maxAgeMs = Number(process.env.EXAMPLE_STEP_UP_MS ?? 15_000);

// Step-up: a session older than maxAgeMs is sent to /reauth?next=...&reason=recent before this page renders.
export default iamNext.page(
  async (_props: { params: Promise<{ org: string }> }, { session }) => (
    <main>
      <h1>Security settings</h1>
      <p>
        You signed in at{' '}
        <time dateTime={new Date(session.session.authenticatedAt).toISOString()}>
          {new Date(session.session.authenticatedAt).toISOString()}
        </time>
        ; this page requires a sign-in within the last {Math.round(maxAgeMs / 1000)} seconds.
      </p>
    </main>
  ),
  { stepUp: { maxAgeMs } },
);
