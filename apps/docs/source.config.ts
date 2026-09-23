import { readFileSync } from 'node:fs';
import { stat } from 'node:fs/promises';
import { join } from 'node:path';
import { defineConfig, defineDocs } from 'fumadocs-mdx/config';
import { metaSchema, pageSchema } from 'fumadocs-core/source/schema';
import {
  rehypeCodeDefaultOptions,
  remarkAdmonition,
  remarkMdxMermaid,
  remarkSteps,
} from 'fumadocs-core/mdx-plugins';
import { transformerTwoslash } from 'fumadocs-twoslash';
import { createFileSystemTypesCache } from 'fumadocs-twoslash/cache-fs';
import {
  createFileSystemGeneratorCache,
  createGenerator,
  remarkAutoTypeTable,
} from 'fumadocs-typescript';
import { z } from 'zod';
import { codeThemes } from './lib/code-themes';

/**
 * Page frontmatter. `status` renders a sidebar badge, `packages` lists the npm packages a page documents
 * (shown in the page header), and `sources` points at the repository files a page was written from.
 * `metaTitle` replaces the title in the browser tab, search results, and link previews when the sidebar title
 * is too terse on its own ("Guards" under Next.js becomes "Next.js guards").
 */
export const docs = defineDocs({
  dir: 'content/docs',
  docs: {
    schema: pageSchema.extend({
      metaTitle: z.string().optional(),
      status: z.enum(['new', 'beta', 'experimental', 'deprecated']).optional(),
      packages: z.array(z.string()).optional(),
      sources: z.array(z.string()).optional(),
    }),
    postprocess: {
      includeProcessedMarkdown: true,
    },
    // The repository is not a git checkout everywhere it is built, so the file's modification time stands in.
    lastModified: async (file) => (await stat(file)).mtime,
  },
  meta: {
    schema: metaSchema,
  },
});

const generator = createGenerator({
  tsconfigPath: './tsconfig.json',
  cache: createFileSystemGeneratorCache('.cache/type-tables'),
});

// Fields without a doc comment fall back to the plain-language dictionary the API reference uses too.
const fieldDocs: Record<string, string> = JSON.parse(
  readFileSync(join(process.cwd(), 'descriptions', 'fields.json'), 'utf8'),
);

/**
 * Formats the type shown when a reader hovers an identifier in a `twoslash` code block. It keeps the cleanup of
 * Fumadocs' default processor, and folds long types: the Better IAM instance type spells out every API method in
 * about 2,400 lines, which turned each page that hovers `iam` into megabytes of highlighted HTML. Past 40 lines,
 * object types nested more than two levels deep collapse to `{ ... }`, so hovering `iam` lists the API groups and
 * the API reference documents the signatures.
 */
function processHoverInfo(info: string): string {
  const content = info
    .replace(/^\(([\w-]+)\)\s+/gm, '')
    .replace(/\nimport .*$/, '')
    .replace(/^(interface|namespace) \w+$/gm, '')
    .trim();
  const typed = /^[A-Z]\w*(?:<[^>]*>)?:/.test(content)
    ? `type ${content}`
    : /^\w*\(/.test(content)
      ? `function ${content}`
      : content;
  if (typed.split('\n').length <= 40) return typed;
  let folded = '';
  let depth = 0;
  for (const char of typed) {
    if (char === '{') {
      depth++;
      if (depth === 3) folded += '{ ... }';
      else if (depth < 3) folded += char;
    } else if (char === '}') {
      if (depth < 3) folded += char;
      depth--;
    } else if (depth < 3) folded += char;
  }
  return folded;
}

export default defineConfig({
  mdxOptions: {
    remarkPlugins: (plugins) => [
      remarkAdmonition,
      remarkSteps,
      remarkMdxMermaid,
      [
        remarkAutoTypeTable,
        {
          generator,
          options: {
            transform(entry: { name: string; description: string }) {
              if (!entry.description && Object.hasOwn(fieldDocs, entry.name))
                entry.description = fieldDocs[entry.name];
            },
          },
        },
      ],
      ...plugins,
    ],
    remarkNpmOptions: {
      persist: { id: 'package-manager' },
    },
    rehypeCodeOptions: {
      ...rehypeCodeDefaultOptions,
      themes: codeThemes,
      langs: [
        'ts',
        'tsx',
        'js',
        'jsx',
        'json',
        'jsonc',
        'bash',
        'sh',
        'sql',
        'yaml',
        'http',
        'vue',
        'svelte',
        'diff',
        'xml',
        'ini',
      ],
      transformers: [
        ...(rehypeCodeDefaultOptions.transformers ?? []),
        transformerTwoslash({
          typesCache: createFileSystemTypesCache({ dir: '.cache/twoslash' }),
          rendererRich: { processHoverInfo },
          twoslashOptions: {
            compilerOptions: {
              moduleResolution: 'bundler',
              module: 'esnext',
              target: 'es2022',
              jsx: 'react-jsx',
              strict: true,
              skipLibCheck: true,
              lib: ['es2023', 'dom', 'dom.iterable'],
              types: ['node'],
            },
          },
        }),
      ],
    },
  },
});
