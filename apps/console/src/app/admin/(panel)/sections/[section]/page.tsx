import { notFound } from 'next/navigation';
import { SectionHub } from '@/components/section-hub';
import { adminAreas } from '@/lib/navigation';

/** A section of the administration panel (Platform, Governance, Security, Operations): its pages, one card each. */
export default async function AdminSection({ params }: { params: Promise<{ section: string }> }) {
  const { section } = await params;
  const areas = adminAreas();
  const area = areas.find((item) => item.key === section && item.landing);
  if (!area) notFound();
  return <SectionHub area={area} areas={areas} />;
}
