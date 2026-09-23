import { notFound } from 'next/navigation';
import { SectionHub } from '@/components/section-hub';
import { orgAreas } from '@/lib/navigation';

/** A section of the organization console (Directory, Access, Governance, ...): its pages, one card each. */
export default async function OrgSection({
  params,
}: {
  params: Promise<{ org: string; section: string }>;
}) {
  const { org, section } = await params;
  const areas = orgAreas(`/cloud/${encodeURIComponent(org)}`);
  const area = areas.find((item) => item.key === section && item.landing);
  if (!area) notFound();
  return <SectionHub area={area} areas={areas} />;
}
