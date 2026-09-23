import { FileCode2, Package } from 'lucide-react';
import { StatusBadge } from '@/components/status-badge';
import { sourceFileUrl } from '@/lib/shared';

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
        <span
          key={name}
          className="inline-flex items-center gap-1 rounded-md border bg-fd-card px-1.5 py-0.5 font-mono text-xs text-fd-muted-foreground"
        >
          <Package className="size-3" />
          {name}
        </span>
      ))}
      {sources?.map((path) => {
        const href = sourceFileUrl(path);
        const chip =
          'inline-flex items-center gap-1 rounded-md border bg-fd-card px-1.5 py-0.5 font-mono text-xs text-fd-muted-foreground';
        const content = (
          <>
            <FileCode2 className="size-3" />
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
            className={`${chip} transition-colors hover:text-fd-foreground`}
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
