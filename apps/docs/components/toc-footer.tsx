import Link from 'next/link';
import { RiArrowRightUpLine, RiBracesLine, RiFeedbackLine, RiFileCodeLine } from 'react-icons/ri';
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
    'inline-flex items-center gap-1.5 text-caption-1-regular text-text-secondary transition-colors hover:text-text-primary';
  const shown = methods.slice(0, 12);
  return (
    <div className="mt-4 flex flex-col gap-4 border-t border-separator-border pt-4">
      {shown.length ? (
        <div className="flex flex-col gap-1.5">
          <p className="inline-flex items-center gap-1.5 text-caption-1-semibold text-text-primary">
            <RiBracesLine className="size-3.5" aria-hidden /> API on this page
          </p>
          <ul className="flex flex-col gap-1">
            {shown.map((key) => (
              <li key={key}>
                <Link
                  href={referenceUrl(key)}
                  className="font-mono text-[0.7rem] text-text-secondary underline-offset-2 transition-colors hover:text-text-primary hover:underline"
                >
                  {key}
                </Link>
              </li>
            ))}
            {methods.length > shown.length ? (
              <li className="text-[0.7rem] text-text-tertiary">
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
              <RiFileCodeLine className="size-3.5" aria-hidden /> Edit this page{' '}
              <RiArrowRightUpLine className="size-3" aria-hidden />
            </a>
          ) : null}
          {issue ? (
            <a href={issue} target="_blank" rel="noreferrer noopener" className={link}>
              <RiFeedbackLine className="size-3.5" aria-hidden /> Report an issue{' '}
              <RiArrowRightUpLine className="size-3" aria-hidden />
            </a>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
