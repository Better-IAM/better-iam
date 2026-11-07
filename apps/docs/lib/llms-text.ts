import type * as PageTree from 'fumadocs-core/page-tree';

/**
 * Turns the processed Markdown of a page into plain Markdown for `llms-full.txt`, `/docs/x.md`, and the MCP server.
 * Fumadocs keeps MDX components as JSX tags in that output; a model gains nothing from `<ApiShape id="…" />`, so
 * each component becomes the Markdown it stands for (or disappears when it is purely visual).
 */
const attribute = (tag: string, name: string) =>
  tag
    .match(new RegExp(`\\b${name}=(?:"([^"]*)"|'([^']*)'|\\{"([^"]*)"\\})`))
    ?.slice(1)
    .find(Boolean);

export function toPlainMarkdown(markdown: string): string {
  return (
    markdown
      // MDX comments such as the generated-file notice.
      .replace(/\{\/\*[\s\S]*?\*\/\}\n*/g, '')
      // Visual-only components.
      .replace(
        /<(ApiGroupSummary|ApiShape|TryInPlayground|PackageTable|PackageGraph)\b[^>]*\/>\n*/g,
        '',
      )
      // The API endpoint box: route and credential as a line of text.
      .replace(/<ApiEndpoint\b[^>]*\/>/g, (tag) => {
        const http = attribute(tag, 'http');
        const credential = attribute(tag, 'credential');
        const group = attribute(tag, 'group');
        const method = attribute(tag, 'method');
        return http
          ? `**HTTP:** \`${http.replace(/^POST \//, 'POST /api/iam/')}\` (${credential === 'none' ? 'no credential' : 'requires a credential'}) · **Browser client:** \`client.${group}.${method}()\``
          : `**Server only:** call \`iam.api.${group}.${method}()\` from trusted server code.`;
      })
      // Glossary terms keep their text.
      .replace(/<Term\b[^>]*>([\s\S]*?)<\/Term>/g, '$1')
      .replace(/<Term\b[^>]*\bid="([^"]*)"[^>]*\/>/g, '$1')
      // Link grids become link lists.
      .replace(
        /<(Card|Feature)\b((?:[^>{"']|"[^"]*"|'[^']*'|\{[^}]*\})*)>([\s\S]*?)<\/\1>/g,
        (_, _name: string, attrs: string, body: string) => {
          const title = attribute(attrs, 'title') ?? '';
          const href = attribute(attrs, 'href');
          const text = body.replace(/\s+/g, ' ').trim();
          return `- ${href ? `[${title}](${href})` : `**${title}**`}${text ? `: ${text}` : ''}`;
        },
      )
      .replace(
        /<(Card|Feature)\b((?:[^>{/"']|"[^"]*"|'[^']*'|\{[^}]*\})*)\/>/g,
        (_, _name: string, attrs: string) => {
          const title = attribute(attrs, 'title') ?? '';
          const href = attribute(attrs, 'href');
          return `- ${href ? `[${title}](${href})` : `**${title}**`}`;
        },
      )
      // Structure-only wrappers.
      .replace(/<\/?(Cards|FeatureGrid|Steps|Step|Accordions|Tabs|Files|Folder)\b[^>]*>\n?/g, '')
      // Labels that carry meaning become text.
      .replace(/<Tab\b[^>]*\bvalue="([^"]*)"[^>]*>\n?/g, '**$1:**\n\n')
      .replace(/<\/Tab>\n?/g, '')
      .replace(/<Accordion\b[^>]*\btitle="([^"]*)"[^>]*>\n?/g, '#### $1\n\n')
      .replace(/<\/Accordion>\n?/g, '')
      .replace(/<Callout\b([^>]*)>/g, (_, attrs: string) => {
        const title = attribute(attrs, 'title');
        return title ? `> **${title}.** ` : '> ';
      })
      .replace(/<\/Callout>/g, '')
      .replace(/<File\b[^>]*\bname="([^"]*)"[^>]*\/>/g, '- `$1`')
      .replace(/\n{3,}/g, '\n\n')
  );
}

/** The text of a page-tree name, which plugins may have turned into JSX (the status badge wraps page names). */
function plainName(name: unknown): string {
  if (typeof name === 'string' || typeof name === 'number') return String(name);
  if (Array.isArray(name)) return name.map(plainName).join('');
  if (name && typeof name === 'object' && 'props' in name) {
    const props = (name as { props?: { children?: unknown } }).props;
    return plainName(props?.children);
  }
  return '';
}

const oneLine = (text: string | undefined) => (text ?? '').replace(/\s+/g, ' ').trim();
const linkText = (text: string) => text.replace(/([[\]])/g, '\\$1');

export interface LlmsIndexOptions {
  name: string;
  description: string;
  creator: string;
  version: string;
  /** Canonical origin without a trailing slash, for example `https://better-iam.com`. */
  siteUrl: string;
  /** The sidebar page tree (`source.getPageTree()`). */
  tree: PageTree.Root;
  /**
   * Names of the top-level sidebar sections (the `---Name---` separators of the root meta.json). Folders extracted
   * with `...folder` bring their own separators (Features' "Organizations", Guides' "Build", …) into the same flat
   * list, so only these names become `## ` headings and the others become `### ` sub-headings. When omitted, every
   * separator is a `## ` heading.
   */
  sections?: readonly string[];
  /** Title and description of the page a tree item links to (`source.getNodePage(item)`). */
  describe: (item: PageTree.Item) => { title: string; description?: string } | undefined;
}

/**
 * The `/llms.txt` index: instructions for agents, then every page grouped under the sidebar's section separators
 * (Get Started, Concepts, … Reference; a section's own groups, such as Guides' "Build", as `### ` sub-headings), each
 * linking to its Markdown copy (`/docs/x.md`) with its description.
 */
export function llmsIndex(options: LlmsIndexOptions): string {
  const { siteUrl } = options;
  const markdownUrl = (url: string) => `${siteUrl}${url}.md`;

  const item = (node: PageTree.Item, depth: number) => {
    const page = options.describe(node);
    const title = page?.title ?? plainName(node.name);
    const description = oneLine(page?.description ?? plainName(node.description));
    const link = node.external ? node.url : markdownUrl(node.url);
    return `${'  '.repeat(depth)}- [${linkText(title)}](${link})${description ? `: ${description}` : ''}`;
  };

  const nodes = (children: PageTree.Node[], depth: number): string[] =>
    children.flatMap((node) => {
      if (node.type === 'page') return [item(node, depth)];
      if (node.type === 'separator') {
        const heading = plainName(node.name);
        const level = !options.sections || options.sections.includes(heading) ? '##' : '###';
        return heading ? ['', `${level} ${heading}`, ''] : [''];
      }
      // A folder: its index page (or its name) and then its pages, one level deeper.
      const head = node.index
        ? item(node.index, depth)
        : `${'  '.repeat(depth)}- ${plainName(node.name)}`;
      return [head, ...nodes(node.children, depth + 1)];
    });

  const instructions = [
    `## Instructions for AI agents`,
    '',
    `This file indexes the ${options.name} documentation (version ${options.version}). Use it to find the page you need instead of guessing API names.`,
    '',
    `1. Find the page that matches the task in the index below. Pages are grouped by the sidebar sections of the site; each entry has a one-sentence description.`,
    `2. Fetch the page's Markdown: every link below is the page URL with \`.md\` appended (for example ${markdownUrl('/docs/quickstart')}). Requesting any docs URL with the header \`Accept: text/markdown\` returns the same Markdown.`,
    `3. When you cite a page to a person, link its canonical URL: the Markdown URL without \`.md\` (for example ${siteUrl}/docs/quickstart).`,
    `4. Use only package names, imports, \`iam.api.<group>.<method>\` calls, options, routes, and error codes that appear in these pages. The Reference section is generated from the source code: API methods (${siteUrl}/docs/reference/api.md), error codes (${siteUrl}/docs/reference/errors.md), package exports (${siteUrl}/docs/reference/exports.md), options (${siteUrl}/docs/reference/options.md), and CLI commands (${siteUrl}/docs/reference/cli.md).`,
    '',
    `Other ways to read these docs:`,
    '',
    `- Every page as Markdown in one file: ${siteUrl}/llms-full.txt`,
    `- MCP server (Streamable HTTP, read-only, no sign-in): ${siteUrl}/api/mcp, with the tools \`search\`, \`list_pages\`, \`get_page\`, \`lookup_api_method\`, \`lookup_export\`, and \`lookup_error_code\``,
    `- Agent skill with the rules for writing ${options.name} code: ${siteUrl}/skills/better-iam/SKILL.md`,
    `- How to connect coding agents: ${markdownUrl('/docs/ai')}`,
  ];

  return [
    `# ${options.name}`,
    '',
    `> ${options.description} Created by ${options.creator}.`,
    '',
    ...instructions,
    ...nodes(options.tree.children, 0),
  ]
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .concat('\n');
}
