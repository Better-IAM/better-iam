import Link from 'next/link';
import { HomeLayout } from 'fumadocs-ui/layouts/home';
import { ArrowRight, SearchX } from 'lucide-react';
import { baseOptions } from '@/lib/layout.shared';

export default function NotFound() {
  return (
    <HomeLayout {...baseOptions()}>
      <main className="flex flex-1 flex-col items-center justify-center gap-5 px-4 py-24 text-center">
        <SearchX className="size-10 text-fd-primary" />
        <h1 className="text-3xl font-semibold tracking-tight">This page does not exist</h1>
        <p className="max-w-md text-fd-muted-foreground">
          It may have moved when the guides were reorganized. Search with{' '}
          <kbd className="rounded border px-1 font-mono text-xs">Ctrl K</kbd>, or start from one of
          these:
        </p>
        <div className="flex flex-wrap justify-center gap-2">
          {[
            ['Guides', '/docs/guides'],
            ['Frameworks', '/docs/frameworks'],
            ['API reference', '/docs/reference/api'],
            ['Playground', '/playground'],
          ].map(([label, href]) => (
            <Link
              key={href}
              href={href!}
              className="inline-flex items-center gap-1.5 rounded-lg border bg-fd-card px-3 py-1.5 text-sm transition-colors hover:border-fd-primary/40"
            >
              {label} <ArrowRight className="size-3.5" />
            </Link>
          ))}
        </div>
      </main>
    </HomeLayout>
  );
}
