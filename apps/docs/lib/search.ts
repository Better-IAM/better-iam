import { createFromSource } from 'fumadocs-core/search/server';
import { sectionOf } from '@/lib/metadata';
import { source } from '@/lib/source';

/**
 * The docs search index, shared by the search dialog's API route and the MCP server. Each page is tagged with its
 * sidebar section (concepts, authentication, … reference; top-level pages are get-started) so searches can be filtered by section.
 */
export const searchApi = createFromSource(source, {
  buildIndex: (page) => ({
    id: page.url,
    url: page.url,
    title: page.data.title,
    description: page.data.description,
    structuredData: page.data.structuredData,
    tag: sectionOf(page.slugs),
  }),
});
