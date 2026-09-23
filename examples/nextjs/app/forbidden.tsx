import Link from 'next/link';

export default function Forbidden() {
  return (
    <main>
      <h1>403 · Not allowed</h1>
      <p>Your account is signed in but no policy grants this action.</p>
      <Link href="/">Back home</Link>
    </main>
  );
}
