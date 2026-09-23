import type { MetadataRoute } from 'next';
import { siteDescription } from '@/lib/metadata';
import { appName } from '@/lib/shared';

/** Web app manifest: the name and icons used when the site is installed or pinned (icons from scripts/generate-icons.mjs). */
export default function manifest(): MetadataRoute.Manifest {
  return {
    id: '/',
    name: `${appName} documentation`,
    short_name: appName,
    description: siteDescription,
    start_url: '/',
    scope: '/',
    display: 'standalone',
    background_color: '#121212',
    theme_color: '#121212',
    lang: 'en',
    dir: 'ltr',
    categories: ['developer', 'security', 'productivity'],
    icons: [
      { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
      { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: '/icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
    ],
  };
}
