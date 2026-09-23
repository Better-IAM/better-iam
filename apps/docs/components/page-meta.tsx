import { RiBox3Line, RiFileCodeLine } from 'react-icons/ri';
import { StatusBadge } from '@/components/status-badge';
import { sourceFileUrl } from '@/lib/shared';
import { cx } from '@/utils/cx';

const chip =
  'inline-flex items-center gap-1 rounded-md border border-border-button-default bg-background-primary-default px-1.5 py-0.5 font-mono text-caption-1-regular text-text-secondary shadow-xs';

/** Header chips: lifecycle status, the npm packages a page documents, and the repository files it covers. */
export function PageMeta({
  status,
  packages,
  sources,
}: {
  status?: string;
  packages?: string[];
  sources?: string[];
}) {
  if (!status && !packages?.length && !sources?.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5 sm:ms-auto">
      {status ? <StatusBadge status={status} className="ms-0 py-0.5" /> : null}
      {packages?.map((name) => (
        <span key={name} className={chip}>
          <RiBox3Line className="size-3" aria-hidden />
          {name}
        </span>
      ))}
      {sources?.map((path) => {
        const href = sourceFileUrl(path);
        const content = (
          <>
            <RiFileCodeLine className="size-3" aria-hidden />
            {path.split('/').pop()}
          </>
        );
        // Without a configured repository the chip still says which file the page documents.
        return href ? (
          <a
            key={path}
            href={href}
            target="_blank"
            rel="noreferrer noopener"
            title={`View ${path}`}
            className={cx(
              chip,
              'transition-colors hover:border-border-button-hover hover:text-text-primary',
            )}
          >
            {content}
          </a>
        ) : (
          <span key={path} title={path} className={chip}>
            {content}
          </span>
        );
      })}
    </div>
  );
}
