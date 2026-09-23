import Link from 'next/link';
import type { ReactNode } from 'react';
import { Popover, PopoverContent, PopoverTrigger } from 'fumadocs-ui/components/ui/popover';
import glossary from '@/descriptions/glossary.json';

const byId = new Map(glossary.map((entry) => [entry.id, entry]));

/** Renders inline `code` spans inside a definition without pulling in a Markdown renderer. */
function inline(text: string): ReactNode[] {
  return text.split(/(`[^`]+`)/g).map((part, index) =>
    part.startsWith('`') ? (
      <code
        key={index}
        className="rounded bg-background-secondary-default px-1 font-mono text-[0.85em]"
      >
        {part.slice(1, -1)}
      </code>
    ) : (
      part
    ),
  );
}

/**
 * A glossary term with its definition in a popover: `<Term id="binding">bindings</Term>`. Definitions live in
 * `descriptions/glossary.json`, which also generates the glossary page.
 */
export function Term({ id, children }: { id: string; children?: ReactNode }) {
  const entry = byId.get(id);
  if (!entry) return <>{children ?? id}</>;
  return (
    <Popover>
      <PopoverTrigger className="cursor-help underline decoration-text-tertiary decoration-dotted underline-offset-4 transition-[text-decoration-color] hover:decoration-text-primary">
        {children ?? entry.term}
      </PopoverTrigger>
      <PopoverContent
        className="w-80 rounded-xl border-border-button-default bg-background-primary-default text-body-regular shadow-dropdown"
        sideOffset={6}
      >
        <p className="mb-1 text-body-semibold">{entry.term}</p>
        <p className="text-text-secondary">{inline(entry.definition)}</p>
        <div className="mt-2 flex gap-3 text-caption-1-medium">
          {entry.href ? (
            <Link
              href={entry.href}
              className="text-text-primary underline-offset-2 hover:underline"
            >
              Learn more
            </Link>
          ) : null}
          <Link
            href={`/docs/reference/glossary#${entry.term.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`}
            className="text-text-secondary hover:text-text-primary"
          >
            Glossary
          </Link>
        </div>
      </PopoverContent>
    </Popover>
  );
}
