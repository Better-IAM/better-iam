import Link from 'next/link';
import { demo } from '@/lib/iam';

export default function Home() {
  return (
    <main>
      <h1>Better IAM × Next.js</h1>
      <p>
        Every page below <code>/{demo.org}</code> is protected. The middleware redirects signed-out
        visitors to the login page with the original path, sign-in runs as a server action without
        client JavaScript, and pages, route handlers, and actions enforce policies on the server.
      </p>
      <ul>
        <li>
          <Link href={`/${demo.org}`}>Organization dashboard</Link>
        </li>
        <li>
          <Link href={`/${demo.org}/documents/roadmap`}>A document (needs documents:read)</Link>
        </li>
        <li>
          <Link href={`/${demo.org}/notes`}>Notes (server action, needs documents:write)</Link>
        </li>
        <li>
          <a href="/api/documents/roadmap">JSON route handler</a>
        </li>
      </ul>
      <p>
        Accounts: <code>{demo.reader.email}</code> / <code>{demo.reader.password}</code> (may read
        documents), <code>{demo.owner.email}</code> / <code>{demo.owner.password}</code> (the
        organization owner, full access), and <code>{demo.guest.email}</code> /{' '}
        <code>{demo.guest.password}</code> (no grants: the document page answers 403).
      </p>
    </main>
  );
}
