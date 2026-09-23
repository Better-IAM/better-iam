import Link from 'next/link';
import { ArrowUpRight, Braces, FileCode2, MessageSquareWarning } from 'lucide-react';
import { referenceUrl } from '@/lib/api-usage';
import { newIssueUrl, sourceFileUrl } from '@/lib/shared';

/**
 * Under the table of contents: the API methods this page uses (each linking to its reference entry), then the
 * page's source and a prefilled issue when a public repository is configured.
 */
export function TocFooter({
  path,
  url,
  methods = [],
}: {
  path: string;
  url: string;
  methods?: string[];
}) {
  const source = sourceFileUrl(`apps/docs/content/docs/${path}`);
  const issue = newIssueUrl(`Docs: ${url}`, `Page: ${url}\n\n`);
  if (!source && !issue && !methods.length) return null;
  const link =
    'inline-flex items-center gap-1.5 text-xs text-fd-muted-foreground transition-colors hover:text-fd-foreground';
  const shown = methods.slice(0, 12);
  return (
    <div className="mt-4 flex flex-col gap-4 border-t pt-4">
      {shown.length ? (
        <div className="flex flex-col gap-1.5">
          <p className="inline-flex items-center gap-1.5 text-xs font-medium text-fd-foreground">
            <Braces className="size-3.5" /> API on this page
          </p>
          <ul className="flex flex-col gap-1">
            {shown.map((key) => (
              <li key={key}>
                <Link
                  href={referenceUrl(key)}
                  className="font-mono text-[0.7rem] text-fd-muted-foreground transition-colors hover:text-fd-primary"
                >
                  {key}
                </Link>
              </li>
            ))}
            {methods.length > shown.length ? (
              <li className="text-[0.7rem] text-fd-muted-foreground">
                and {methods.length - shown.length} more
              </li>
            ) : null}
          </ul>
        </div>
      ) : null}
      {source || issue ? (
        <div className="flex flex-col gap-2">
          {source ? (
            <a href={source} target="_blank" rel="noreferrer noopener" className={link}>
              <FileCode2 className="size-3.5" /> Edit this page <ArrowUpRight className="size-3" />
            </a>
          ) : null}
          {issue ? (
            <a href={issue} target="_blank" rel="noreferrer noopener" className={link}>
              <MessageSquareWarning className="size-3.5" /> Report an issue{' '}
              <ArrowUpRight className="size-3" />
            </a>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
