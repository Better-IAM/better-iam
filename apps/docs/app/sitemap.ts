import type { MetadataRoute } from 'next';
import { source } from '@/lib/source';
import { siteUrl } from '@/lib/shared';

export const revalidate = false;

export default function sitemap(): MetadataRoute.Sitemap {
  const url = (path: string) => new URL(path, siteUrl).toString();
  return [
    { url: url('/'), changeFrequency: 'weekly', priority: 1 },
    { url: url('/playground'), changeFrequency: 'monthly', priority: 0.8 },
    ...source.getPages().map((page) => ({
      url: url(page.url),
      changeFrequency: 'weekly' as const,
      priority: page.slugs.length <= 1 ? 0.9 : page.slugs[0] === 'reference' ? 0.5 : 0.7,
    })),
  ];
}
