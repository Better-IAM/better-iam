/**
 * Turns the processed Markdown of a page into plain Markdown for `llms.txt`, `/docs/x.md`, and the MCP server.
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
