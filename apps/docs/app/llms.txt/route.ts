import rootMeta from '@/content/docs/meta.json';
import { llmsIndex } from '@/lib/llms-text';
import { source } from '@/lib/source';
import { appDescription, appName, creator, siteUrl, version } from '@/lib/shared';

export const revalidate = false;

/** The top-level sidebar sections: the `---Name---` (or `---[Icon]Name---`) separators of the root meta.json. */
const sections = rootMeta.pages.flatMap(
  (entry) => /^---(?:\[[^\]]+\])?(.+)---$/.exec(entry)?.slice(1, 2) ?? [],
);

/**
 * The llms.txt index: how agents should read these docs, then every page grouped by sidebar section, linking to
 * its Markdown copy. The MCP `list_pages` tool keeps Fumadocs' own index (`docsLlms.index()`), whose relative URLs
 * are what `get_page` accepts.
 */
export function GET() {
  const text = llmsIndex({
    name: appName,
    description: appDescription,
    creator,
    version,
    siteUrl,
    tree: source.getPageTree(),
    sections,
    describe: (item) => {
      const page = source.getNodePage(item);
      return page ? { title: page.data.title, description: page.data.description } : undefined;
    },
  });
  return new Response(text, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
}
