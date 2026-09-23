import { createElement, type ComponentType } from 'react';
import { docs } from '@/.source/server';
import { llms, loader, type LoaderPlugin } from 'fumadocs-core/source';
import { statusBadgesPlugin } from 'fumadocs-core/source/status-badges';
import { StatusBadge } from '@/components/status-badge';
import * as icons from './icons';
import { toPlainMarkdown } from './llms-text';
import { docsRoute } from './shared';

const iconRegistry: Record<string, ComponentType> = icons;

/** Resolves frontmatter and meta.json `icon` names against lib/icons.ts (react-icons). */
function iconsPlugin(): LoaderPlugin {
  function replaceIcon<T extends { icon?: unknown }>(node: T): T {
    if (node.icon === undefined || typeof node.icon !== 'string') return node;
    const Icon = iconRegistry[node.icon];
    if (!Icon) console.warn(`[icons] Unknown icon "${node.icon}": export it from lib/icons.ts.`);
    node.icon = Icon ? createElement(Icon) : undefined;
    return node;
  }
  return {
    name: 'better-iam:icons',
    transformPageTree: { file: replaceIcon, folder: replaceIcon, separator: replaceIcon },
  };
}

// See https://fumadocs.dev/docs/headless/source-api
export const source = loader({
  baseUrl: docsRoute,
  source: docs.toFumadocsSource(),
  plugins: [
    iconsPlugin(),
    statusBadgesPlugin({ renderBadge: (status) => createElement(StatusBadge, { status }) }),
  ],
});

export type DocsPage = NonNullable<ReturnType<typeof source.getPage>>;

export const docsLlms = llms(source, {
  renderPage: async (page) => `# ${page.data.title} (${page.url})

${page.data.description ? `> ${page.data.description}\n\n` : ''}${toPlainMarkdown(await page.data.getText('processed'))}`,
});
