import Link from 'next/link';
import type { NavArea } from '@/lib/navigation';
import { PageHeader } from './ui';

/** A section's landing page: what the section is for, a card per page, and the other sections. */
export function SectionHub({ area, areas }: { area: NavArea; areas: NavArea[] }) {
  const others = areas.filter((item) => item.key !== area.key && item.landing);
  return (
    <>
      <PageHeader title={area.label} description={area.description} />
      <div className="hub-grid">
        {area.pages.map((page) => (
          <Link key={page.href} href={page.href} className="card hub-card">
            <strong>{page.label}</strong>
            <p>{page.description}</p>
            <span className="hub-go" aria-hidden="true">
              Open →
            </span>
          </Link>
        ))}
      </div>
      {others.length > 0 && (
        <nav className="hub-others" aria-label="Other sections">
          <span className="muted small">Other sections</span>
          {others.map((item) => (
            <Link key={item.key} href={item.href} className="pill">
              {item.label}
            </Link>
          ))}
        </nav>
      )}
    </>
  );
}
