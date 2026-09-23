import { notFound } from 'next/navigation';
import { ImageResponse } from 'next/og';
import { source } from '@/lib/source';
import { getPageImageUrl } from '@/lib/shared';

export const revalidate = false;

const sectionNames: Record<string, string> = {
  guides: 'Guides',
  frameworks: 'Frameworks',
  federation: 'Federation',
  operations: 'Operations',
  reference: 'Reference',
};

/** 1200×630 social card: brand mark, section, title, and description on the site's ink-and-teal palette. */
export async function GET(_req: Request, { params }: RouteContext<'/og/docs/[...slug]'>) {
  const { slug } = await params;
  const page = source.getPage(slug.slice(0, -1));
  if (!page) notFound();

  const section = sectionNames[page.slugs[0] ?? ''] ?? 'Documentation';
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          padding: '72px 80px',
          background: 'linear-gradient(135deg, #070b14 0%, #0b1422 55%, #06201d 100%)',
          color: '#e6edf5',
          fontFamily: 'sans-serif',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <svg width="52" height="52" viewBox="0 0 24 24" fill="none">
            <path
              d="M12 1.75 3.75 4.9v6.02c0 5.02 3.44 9.6 8.25 11.33 4.81-1.73 8.25-6.31 8.25-11.33V4.9L12 1.75Z"
              fill="#3fd6b6"
              fillOpacity="0.18"
              stroke="#3fd6b6"
              strokeWidth="1.5"
            />
            <circle cx="12" cy="9.75" r="2.35" fill="#3fd6b6" />
            <path d="M10.9 11.4h2.2l.62 4.35h-3.44l.62-4.35Z" fill="#3fd6b6" />
          </svg>
          <div style={{ display: 'flex', fontSize: 34, fontWeight: 700 }}>
            Better<span style={{ color: '#3fd6b6' }}>IAM</span>
          </div>
          <div
            style={{
              display: 'flex',
              marginLeft: 'auto',
              fontSize: 24,
              color: '#8fa3bf',
              border: '1px solid rgba(143,163,191,0.35)',
              borderRadius: 999,
              padding: '6px 20px',
            }}
          >
            {section}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', marginTop: 'auto', gap: 24 }}>
          <div
            style={{
              display: 'flex',
              fontSize: 76,
              fontWeight: 800,
              letterSpacing: -2,
              lineHeight: 1.05,
            }}
          >
            {page.data.title}
          </div>
          {page.data.description ? (
            <div
              style={{
                display: 'flex',
                fontSize: 32,
                color: '#9fb0c7',
                lineHeight: 1.35,
                maxWidth: 980,
              }}
            >
              {page.data.description.length > 150
                ? `${page.data.description.slice(0, 147)}…`
                : page.data.description}
            </div>
          ) : null}
        </div>
        <div
          style={{
            display: 'flex',
            marginTop: 48,
            height: 6,
            width: '100%',
            borderRadius: 6,
            background: 'linear-gradient(90deg, #3fd6b6, rgba(63,214,182,0.1))',
          }}
        />
      </div>
    ),
    { width: 1200, height: 630 },
  );
}

export function generateStaticParams() {
  return source.getPages().map((page) => ({
    slug: getPageImageUrl(page).segments,
  }));
}

export const dynamicParams = false;
