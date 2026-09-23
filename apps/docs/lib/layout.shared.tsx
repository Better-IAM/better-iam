import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { Logo } from '@/components/logo';
import { repositoryUrl } from './shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: <Logo />,
      transparentMode: 'top',
    },
    githubUrl: repositoryUrl,
    links: [
      { text: 'Documentation', url: '/docs/guides', active: 'nested-url', on: 'nav' },
      { text: 'API', url: '/docs/reference/api', active: 'nested-url', on: 'nav' },
      { text: 'Playground', url: '/playground', active: 'url', on: 'nav' },
      { text: 'Changelog', url: '/docs/reference/changelog', active: 'url', on: 'nav' },
    ],
  };
}
