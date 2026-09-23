import type { ReactNode } from 'react';
import { RiBox3Line } from 'react-icons/ri';
import packages from '@/generated/packages.json';
import { sourceFileUrl } from '@/lib/shared';
import { cx } from '@/utils/cx';

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

const cardClass =
  'group flex flex-col gap-2 rounded-2xl border border-border-button-default bg-background-primary-default p-4 shadow-xs transition-[background-color,border-color]';

/** A package card links to its manifest only when a public repository is configured. */
function CardShell({ href, children }: { href?: string; children: ReactNode }) {
  return href ? (
    <a
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      className={cx(
        cardClass,
        'hover:border-border-button-hover hover:bg-background-primary-hover',
      )}
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
            <RiBox3Line className="size-4 text-foreground-icon-primary" aria-hidden />
            <code className="font-mono text-body-medium">{pkg.name}</code>
            <span className="ms-auto font-mono text-caption-1-regular text-text-secondary">
              {pkg.version}
            </span>
          </div>
          <p className="text-body-regular text-text-secondary">{pkg.description}</p>
          {pkg.exports.length > 1 ? (
            <div className="flex flex-wrap gap-1">
              {pkg.exports.slice(1).map((entry) => (
                <code
                  key={entry}
                  className="rounded-md bg-background-secondary-default px-1.5 py-0.5 font-mono text-[0.7rem] text-text-secondary"
                >
                  {entry.slice(pkg.name.length)}
                </code>
              ))}
            </div>
          ) : null}
          {pkg.peerDependencies.length ? (
            <p className="text-caption-1-regular text-text-secondary">
              Peers: <span className="font-mono">{pkg.peerDependencies.join(', ')}</span>
            </p>
          ) : null}
        </CardShell>
      ))}
    </div>
  );
}
