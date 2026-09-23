import Link from 'next/link';
import { Logo } from '@/components/logo';
import { repositoryUrl, version } from '@/lib/shared';
import { Container } from './section';

const columns: { title: string; links: [string, string][] }[] = [
  {
    title: 'Learn',
    links: [
      ['Quickstart', '/docs/guides/quickstart'],
      ['Concepts', '/docs/guides/concepts'],
      ['Authentication', '/docs/guides/authentication'],
      ['Authorization', '/docs/guides/authorization'],
      ['Recipes', '/docs/guides/recipes'],
    ],
  },
  {
    title: 'Build',
    links: [
      ['Frameworks', '/docs/frameworks'],
      ['Federation', '/docs/federation'],
      ['Operations', '/docs/operations'],
      ['Playground', '/playground'],
    ],
  },
  {
    title: 'Reference',
    links: [
      ['API', '/docs/reference/api'],
      ['Error codes', '/docs/reference/errors'],
      ['CLI', '/docs/reference/cli'],
      ['Glossary', '/docs/reference/glossary'],
      ['Changelog', '/docs/reference/changelog'],
    ],
  },
  {
    title: 'Machine-readable',
    links: [
      ['OpenAPI 3.1', '/openapi.json'],
      ['llms.txt', '/llms.txt'],
      ['llms-full.txt', '/llms-full.txt'],
      // Only when NEXT_PUBLIC_DOCS_REPOSITORY_URL names a public repository.
      ...(repositoryUrl ? [['Source code', repositoryUrl] as [string, string]] : []),
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className="border-t bg-fd-card/40">
      <Container className="grid grid-cols-2 gap-x-6 gap-y-10 py-14 md:grid-cols-[minmax(0,1.3fr)_repeat(4,minmax(0,1fr))]">
        <div className="col-span-2 flex flex-col gap-3 md:col-span-1">
          <Logo />
          <p className="max-w-xs text-sm leading-6 text-fd-muted-foreground">
            Embeddable authentication, authorization, governance, and federation for TypeScript.
          </p>
          <p className="font-mono text-xs text-fd-muted-foreground">v{version}</p>
        </div>
        {columns.map((column) => (
          <div key={column.title} className="flex flex-col gap-3">
            <p className="text-xs font-medium text-fd-foreground">{column.title}</p>
            <ul className="flex flex-col gap-2">
              {column.links.map(([label, href]) => {
                const className =
                  'text-sm text-fd-muted-foreground transition-colors hover:text-fd-foreground';
                // Static files and other sites are ordinary links, not client-side routes.
                const plain = /^https?:|\.(json|txt)$/.test(href);
                return (
                  <li key={href}>
                    {plain ? (
                      <a href={href} className={className}>
                        {label}
                      </a>
                    ) : (
                      <Link href={href} className={className}>
                        {label}
                      </Link>
                    )}
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </Container>
    </footer>
  );
}
