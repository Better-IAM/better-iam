import type { ReactNode } from 'react';
import { Package } from 'lucide-react';
import packages from '@/generated/packages.json';
import { sourceFileUrl } from '@/lib/shared';

interface PackageInfo {
  name: string;
  directory: string;
  version: string;
  description: string;
  exports: string[];
  internalDependencies: string[];
  dependencies: string[];
  peerDependencies: string[];
}

const cardClass = 'group flex flex-col gap-2 rounded-xl border bg-fd-card p-4 transition-colors';

/** A package card links to its manifest only when a public repository is configured. */
function CardShell({ href, children }: { href?: string; children: ReactNode }) {
  return href ? (
    <a
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      className={`${cardClass} hover:border-fd-primary/40`}
    >
      {children}
    </a>
  ) : (
    <div className={cardClass}>{children}</div>
  );
}

/** Every publishable package with its subpath exports, generated from the workspace manifests. */
export function PackageTable({ filter }: { filter?: string[] }) {
  const list = (packages as PackageInfo[]).filter((pkg) => !filter || filter.includes(pkg.name));
  return (
    <div className="not-prose my-6 grid gap-3 sm:grid-cols-2">
      {list.map((pkg) => (
        <CardShell key={pkg.name} href={sourceFileUrl(`${pkg.directory}/package.json`)}>
          <div className="flex items-center gap-2">
            <Package className="size-4 text-fd-primary" />
            <code className="font-mono text-sm font-medium">{pkg.name}</code>
            <span className="ms-auto font-mono text-xs text-fd-muted-foreground">
              {pkg.version}
            </span>
          </div>
          <p className="text-sm text-fd-muted-foreground">{pkg.description}</p>
          {pkg.exports.length > 1 ? (
            <div className="flex flex-wrap gap-1">
              {pkg.exports.slice(1).map((entry) => (
                <code
                  key={entry}
                  className="rounded bg-fd-muted px-1.5 py-0.5 font-mono text-[0.7rem] text-fd-muted-foreground"
                >
                  {entry.slice(pkg.name.length)}
                </code>
              ))}
            </div>
          ) : null}
          {pkg.peerDependencies.length ? (
            <p className="text-xs text-fd-muted-foreground">
              Peers: <span className="font-mono">{pkg.peerDependencies.join(', ')}</span>
            </p>
          ) : null}
        </CardShell>
      ))}
    </div>
  );
}
