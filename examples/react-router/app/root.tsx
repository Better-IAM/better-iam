import { useEffect, useState, type ReactNode } from 'react';
import {
  Form,
  Links,
  Meta,
  Outlet,
  Scripts,
  ScrollRestoration,
  isRouteErrorResponse,
} from 'react-router';
import { createIamClient, type IamClient } from '@better-iam/client';
import { IamProvider, useSession } from '@better-iam/react';
import type { Route } from './+types/root';
import { iamRouter, ready, type iam } from './iam.server';

type Client = IamClient<typeof iam>;

// Every request waits for migrations (and the demo seed), then gets the IAM helpers and cookie handling.
export const middleware: Route.MiddlewareFunction[] = [
  async (_args, next) => {
    await ready;
    return next();
  },
  iamRouter.middleware,
];

/** The session for the first render, and the origin the browser client talks to. */
export async function loader(args: Route.LoaderArgs) {
  return {
    ...(await iamRouter.sessionData(args)),
    origin: new URL(args.request.url).origin,
  };
}

export function Layout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <Meta />
        <Links />
      </head>
      <body>
        {children}
        <ScrollRestoration />
        <Scripts />
      </body>
    </html>
  );
}

export default function App({ loaderData }: Route.ComponentProps) {
  const [client] = useState<Client>(() =>
    createIamClient<typeof iam>({ baseURL: loaderData.origin }),
  );
  return (
    <IamProvider client={client} initialSession={loaderData.session}>
      <Header session={loaderData.session} />
      <main>
        <Outlet />
      </main>
    </IamProvider>
  );
}

function Header({
  session: fromLoader,
}: {
  session: Route.ComponentProps['loaderData']['session'];
}) {
  const { session, setSession } = useSession<Client>();
  // Actions (sign in, sign out) revalidate the root loader; keep the store on the server's answer.
  useEffect(() => setSession(fromLoader), [fromLoader, setSession]);
  return (
    <header>
      {session ? (
        <>
          <p id="greeting">Signed in as {session.identity.email}</p>
          <Form method="post" action="/logout">
            <button>Sign out</button>
          </Form>
        </>
      ) : (
        <>
          <p id="greeting">Signed out</p>
          <a href="/login">Sign in</a>
        </>
      )}
    </header>
  );
}

export function ErrorBoundary({ error }: Route.ErrorBoundaryProps) {
  if (isRouteErrorResponse(error))
    return (
      <main>
        <h1 id="error-status">{error.status}</h1>
        <p id="error-code">
          {(error.data as { code?: string } | undefined)?.code ?? error.statusText}
        </p>
      </main>
    );
  return (
    <main>
      <h1>Something went wrong</h1>
    </main>
  );
}
