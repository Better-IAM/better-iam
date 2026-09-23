'use client';

import { useMemo, useState } from 'react';
import { useDocsSearch } from 'fumadocs-core/search/client';
import { fetchClient } from 'fumadocs-core/search/client/fetch';
import {
  SearchDialog,
  SearchDialogClose,
  SearchDialogContent,
  SearchDialogFooter,
  SearchDialogHeader,
  SearchDialogIcon,
  SearchDialogInput,
  SearchDialogList,
  SearchDialogOverlay,
  TagsList,
  TagsListItem,
  type SharedProps,
} from 'fumadocs-ui/components/dialog/search';

const tags = [
  { name: 'Guides', value: 'guides' },
  { name: 'Frameworks', value: 'frameworks' },
  { name: 'Federation', value: 'federation' },
  { name: 'Operations', value: 'operations' },
  { name: 'Reference', value: 'reference' },
];

const quickLinks: [string, string][] = [
  ['Quickstart', '/docs/guides/quickstart'],
  ['Policies', '/docs/guides/authorization/policies'],
  ['Condition operators', '/docs/guides/authorization/conditions'],
  ['Next.js', '/docs/frameworks/nextjs'],
  ['Server API reference', '/docs/reference/api'],
  ['Package exports', '/docs/reference/exports'],
  ['Error codes', '/docs/reference/errors'],
  ['Policy playground', '/playground'],
];

/**
 * Search with section filters and quick links shown before the reader types. Composed from Fumadocs'
 * primitives so the filter footer lives inside the dialog.
 */
export default function Search(props: SharedProps) {
  const [tag, setTag] = useState<string | undefined>();
  const client = useMemo(() => fetchClient({ api: '/api/search', tag }), [tag]);
  const { search, setSearch, query } = useDocsSearch({ client, delayMs: 120 });
  const defaultItems = useMemo(
    () => quickLinks.map(([name, url]) => ({ type: 'page' as const, id: url, content: name, url })),
    [],
  );

  return (
    <SearchDialog search={search} onSearchChange={setSearch} isLoading={query.isLoading} {...props}>
      <SearchDialogOverlay />
      <SearchDialogContent>
        <SearchDialogHeader>
          <SearchDialogIcon />
          <SearchDialogInput placeholder="Search guides, API methods, error codes…" />
          <SearchDialogClose />
        </SearchDialogHeader>
        <SearchDialogList items={query.data !== 'empty' ? query.data : defaultItems} />
        <SearchDialogFooter className="flex flex-wrap items-center gap-2">
          <TagsList tag={tag} onTagChange={setTag} allowClear>
            {tags.map((item) => (
              <TagsListItem key={item.value} value={item.value}>
                {item.name}
              </TagsListItem>
            ))}
          </TagsList>
          <span className="ms-auto hidden items-center gap-1.5 text-xs text-fd-muted-foreground sm:inline-flex">
            <kbd className="rounded border bg-fd-background px-1 font-mono">↑↓</kbd> navigate
            <kbd className="rounded border bg-fd-background px-1 font-mono">↵</kbd> open
            <kbd className="rounded border bg-fd-background px-1 font-mono">esc</kbd> close
          </span>
        </SearchDialogFooter>
      </SearchDialogContent>
    </SearchDialog>
  );
}
