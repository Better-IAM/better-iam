import { Link } from 'react-router';
import { iamRouter } from '../iam.server';
import type { Route } from './+types/home';

// Decided on the server and rendered into the HTML; the React hooks can refresh it in the browser.
export async function loader(args: Route.LoaderArgs) {
  return { canReadMembers: await iamRouter.helpers(args).can('iam:identities:read') };
}

export default function Home({ loaderData }: Route.ComponentProps) {
  return (
    <>
      <h1>Better IAM + React Router</h1>
      {loaderData.canReadMembers ? (
        <p id="members-allowed">You can read the member directory.</p>
      ) : (
        <p id="members-denied">The member directory is not available to you.</p>
      )}
      <p>
        <Link to="/account">Account</Link> · <Link to="/admin">Admin</Link>
      </p>
    </>
  );
}
