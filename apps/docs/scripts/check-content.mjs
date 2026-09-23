// Validates apps/docs/content without starting Next.js:
//   - every .mdx file compiles as MDX (syntax errors in JSX, expressions, or unescaped braces)
//   - JSX components are either registered globally in components/mdx.tsx or imported by the page
//   - frontmatter has a title and a one-line description
//   - internal links (/docs/...) point at pages that exist
//   - folder meta.json files parse and reference existing pages
//
// Usage: node scripts/check-content.mjs [path-prefix]   e.g. `node scripts/check-content.mjs guides/authorization`
import { readdir, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const app = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const contentDir = join(app, 'content', 'docs');
const requireFromMdx = createRequire(
  createRequire(join(app, 'package.json')).resolve('fumadocs-mdx/package.json'),
);
const { compile } = await import(pathToFileURL(requireFromMdx.resolve('@mdx-js/mdx')).href);
const { parse: parseYaml } = await import(pathToFileURL(requireFromMdx.resolve('yaml')).href);
const { default: GithubSlugger } = await import(
  pathToFileURL(requireFromMdx.resolve('github-slugger')).href
);

/** Heading ids of a page, computed like Fumadocs does (github-slugger, with `[#custom-id]` overrides). */
function anchorsOf(body) {
  const slugger = new GithubSlugger();
  const anchors = new Set();
  const withoutCode = body.replace(/^(```|~~~)[\s\S]*?^\1/gm, '');
  for (const match of withoutCode.matchAll(/^#{1,6}\s+(.+?)\s*#*$/gm)) {
    let text = match[1];
    const custom = text.match(/\[#([^\]]+)\]\s*$/);
    if (custom) {
      anchors.add(custom[1]);
      continue;
    }
    text = text
      .replace(/<[^>]+>/g, '')
      .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
      .replace(/[`*_]/g, (char) => (char === '_' ? '_' : ''))
      .replace(/\\([{}<>])/g, '$1');
    anchors.add(slugger.slug(text));
  }
  return anchors;
}

const globals = new Set([
  'Callout',
  'CalloutContainer',
  'CalloutTitle',
  'CalloutDescription',
  'Card',
  'Cards',
  'CodeBlockTab',
  'CodeBlockTabs',
  'CodeBlockTabsList',
  'CodeBlockTabsTrigger',
  'Tabs',
  'Tab',
  'Steps',
  'Step',
  'Accordion',
  'Accordions',
  'Files',
  'Folder',
  'File',
  'TypeTable',
  'Mermaid',
  'ApiEndpoint',
  'ApiGroupSummary',
  'ApiShape',
  'FeatureGrid',
  'Feature',
  'PackageTable',
  'PackageGraph',
  'PolicyPlayground',
  'PolicyEvaluator',
  'auto-type-table',
  'AutoTypeTable',
  'Term',
  'TryInPlayground',
]);

// <Term id="..."> must name an entry of descriptions/glossary.json.
const glossaryIds = new Set(
  JSON.parse(await readFile(join(app, 'descriptions', 'glossary.json'), 'utf8')).map(
    (entry) => entry.id,
  ),
);

const prefix = process.argv[2]?.replace(/\\/g, '/');

async function* walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else yield path;
  }
}

const files = [];
for await (const file of walk(contentDir)) files.push(file);
const rel = (file) => relative(contentDir, file).split(sep).join('/');

// Page URLs: content/docs/a/b.mdx -> /docs/a/b, a/index.mdx -> /docs/a, each with the ids of its headings.
const pages = new Set();
const anchors = new Map();
const urlOf = (path) => {
  const slug = path.replace(/\.mdx?$/, '').replace(/(^|\/)index$/, '');
  return `/docs${slug ? `/${slug}` : ''}`;
};
for (const file of files) {
  const path = rel(file);
  if (!/\.mdx?$/.test(path)) continue;
  const url = urlOf(path);
  pages.add(url);
  const text = await readFile(file, 'utf8');
  anchors.set(url, anchorsOf(text.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '')));
}

const problems = [];
const report = (file, message) => problems.push(`${rel(file)}: ${message}`);

for (const file of files) {
  const path = rel(file);
  if (prefix && !path.startsWith(prefix)) continue;
  const text = await readFile(file, 'utf8');

  if (path.endsWith('meta.json')) {
    try {
      const meta = JSON.parse(text);
      const folder = dirname(file);
      for (const page of meta.pages ?? []) {
        if (
          page === '...' ||
          page.startsWith('---') ||
          page.startsWith('!') ||
          page.startsWith('[') ||
          page.startsWith('...')
        )
          continue;
        const exists = files.some((candidate) => {
          const r = relative(folder, candidate).split(sep).join('/');
          return r === `${page}.mdx` || r === `${page}.md` || r.startsWith(`${page}/`);
        });
        if (!exists) report(file, `meta.json lists "${page}" but no such page or folder exists`);
      }
    } catch (error) {
      report(file, `invalid JSON: ${error.message}`);
    }
    continue;
  }
  if (!/\.mdx?$/.test(path)) continue;

  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);
  if (!match) {
    report(file, 'missing frontmatter');
    continue;
  }
  let frontmatter;
  try {
    frontmatter = parseYaml(match[1]);
  } catch (error) {
    report(file, `invalid frontmatter YAML: ${error.message}`);
    continue;
  }
  if (!frontmatter?.title) report(file, 'frontmatter needs a title');
  if (!frontmatter?.description) report(file, 'frontmatter needs a description');
  if (
    frontmatter?.status &&
    !['new', 'beta', 'experimental', 'deprecated'].includes(frontmatter.status)
  )
    report(file, `unknown status "${frontmatter.status}"`);
  const body = text.slice(match[0].length);

  if (path.endsWith('.mdx')) {
    try {
      await compile(body, { format: 'mdx' });
    } catch (error) {
      const place = error.place?.start ?? error.place;
      const line = place?.line ? ` (body line ${place.line})` : '';
      report(file, `MDX error${line}: ${error.reason ?? error.message}`);
    }
    // Components used as JSX must be global or imported. Code fences and inline code are ignored.
    const prose = body.replace(/```[\s\S]*?```/g, '').replace(/`[^`\n]*`/g, '');
    const imported = new Set();
    for (const statement of prose.matchAll(/^import\s+\{([^}]+)\}\s+from/gm))
      for (const name of statement[1].split(','))
        imported.add(
          name
            .trim()
            .split(/\s+as\s+/)
            .pop(),
        );
    for (const statement of prose.matchAll(/^import\s+(\w+)\s+from/gm)) imported.add(statement[1]);
    for (const tag of prose.matchAll(/<([A-Z][A-Za-z0-9]*)(?:\.[A-Za-z]+)?[\s/>]/g)) {
      if (!globals.has(tag[1]) && !imported.has(tag[1]))
        report(file, `unknown component <${tag[1]}> (import it or register it)`);
    }
    for (const term of prose.matchAll(/<Term\s+id=["']([^"']+)["']/g))
      if (!glossaryIds.has(term[1]))
        report(file, `unknown glossary term id "${term[1]}" (see descriptions/glossary.json)`);
  }

  // Internal links, including #anchors (same-page links check this page's own headings).
  const prose = body.replace(/```[\s\S]*?```/g, '');
  const links = [
    ...[...prose.matchAll(/\]\((\/docs[^)\s#]*)?(#[^)\s]*)?\)/g)].map((m) => [m[1], m[2]]),
    ...[...prose.matchAll(/href=["'](\/docs[^"'#]*)?(#[^"']*)?["']/g)].map((m) => [m[1], m[2]]),
  ].filter(([page, hash]) => page || hash);
  const own = urlOf(path);
  for (const [link, hash] of links) {
    const target = link ? link.replace(/\/$/, '') : own;
    if (!pages.has(target)) {
      report(file, `broken link ${link}`);
      continue;
    }
    const id = hash?.slice(1);
    if (id && !anchors.get(target)?.has(decodeURIComponent(id)))
      report(file, `broken anchor ${link ?? ''}${hash} (no heading with that id)`);
  }
}

if (problems.length) {
  console.error(problems.join('\n'));
  console.error(`\n${problems.length} problem(s)`);
  process.exit(1);
}
console.log(`content OK (${pages.size} pages checked${prefix ? ` under ${prefix}` : ''})`);
