import type { Metadata } from 'next';
import Link from 'next/link';
import { FlaskConical } from 'lucide-react';
import { PolicyPlayground } from '@/components/playground/policy-playground';

export const metadata: Metadata = {
  title: 'Policy playground',
  description:
    'Write Better IAM policy documents and evaluate requests in your browser with the real policy engine from @better-iam/core.',
};

export default function PlaygroundPage() {
  return (
    <main className="mx-auto flex w-full max-w-(--fd-layout-width) flex-1 flex-col gap-8 px-4 py-10 md:px-6 md:py-14">
      <header className="flex flex-col gap-3">
        <span className="inline-flex w-fit items-center gap-1.5 rounded-full border bg-fd-card px-3 py-1 text-xs text-fd-muted-foreground">
          <FlaskConical className="size-3.5 text-fd-primary" />
          Runs <code className="font-mono">evaluatePolicy</code> from{' '}
          <code className="font-mono">@better-iam/core</code> in your browser
        </span>
        <h1 className="text-3xl font-semibold tracking-tight md:text-4xl">Policy playground</h1>
        <p className="max-w-2xl text-fd-muted-foreground">
          Edit grant and boundary documents, describe a request, and watch the decision and its
          statement-by-statement trace update as you type. Nothing leaves this page; share a
          scenario with a link. Learn the model in{' '}
          <Link
            href="/docs/guides/authorization/policies"
            className="text-fd-primary underline-offset-4 hover:underline"
          >
            Policies
          </Link>{' '}
          and{' '}
          <Link
            href="/docs/guides/authorization/conditions"
            className="text-fd-primary underline-offset-4 hover:underline"
          >
            Conditions
          </Link>
          .
        </p>
      </header>
      <PolicyPlayground />
    </main>
  );
}
