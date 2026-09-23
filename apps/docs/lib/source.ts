import { createElement } from 'react';
import { docs } from '@/.source/server';
import { llms, loader } from 'fumadocs-core/source';
import { lucideIconsPlugin } from 'fumadocs-core/source/lucide-icons';
import { statusBadgesPlugin } from 'fumadocs-core/source/status-badges';
import { StatusBadge } from '@/components/status-badge';
import { toPlainMarkdown } from './llms-text';
import { docsRoute } from './shared';

// See https://fumadocs.dev/docs/headless/source-api
export const source = loader({
  baseUrl: docsRoute,
  source: docs.toFumadocsSource(),
  plugins: [
    lucideIconsPlugin(),
    statusBadgesPlugin({ renderBadge: (status) => createElement(StatusBadge, { status }) }),
  ],
});

export type DocsPage = NonNullable<ReturnType<typeof source.getPage>>;

export const docsLlms = llms(source, {
  renderPage: async (page) => `# ${page.data.title} (${page.url})

${page.data.description ? `> ${page.data.description}\n\n` : ''}${toPlainMarkdown(await page.data.getText('processed'))}`,
});
