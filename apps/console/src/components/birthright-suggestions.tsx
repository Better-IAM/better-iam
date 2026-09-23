import Link from 'next/link';
import type { BirthrightSuggestion } from 'better-iam';
import { ApiButton } from '@/components/api-form';
import { Card, Table } from '@/components/ui';

const percent = (share: number) => `${Math.round(share * 100)}%`;

/**
 * Suggested birthright packages for departments or teams (`departments.suggestBirthright` /
 * `teams.suggestBirthright`), each with a button that creates the package with its rule.
 */
export function BirthrightSuggestions({
  suggestions,
  tenantId,
  base,
  showUnit,
}: {
  suggestions: BirthrightSuggestion[];
  tenantId: string;
  base: string;
  /** Name the department or team on each row (for lists covering several). */
  showUnit?: boolean;
}) {
  if (!suggestions.length) return null;
  const unitPath = (item: BirthrightSuggestion) =>
    `${base}/${item.unit.kind === 'department' ? 'departments' : 'teams'}/${item.unit.id}`;
  return (
    <Card
      title="Suggested birthright access"
      description="Roles and groups most people here already hold by hand. Creating the package grants them automatically to everyone who joins and removes them from people who leave; what people hold by hand stays until you remove it."
      flush
    >
      <Table
        head={[...(showUnit ? ['For'] : []), 'Access', 'Held by', 'Would grant', '']}
        rows={suggestions.map((item) => [
          ...(showUnit
            ? [
                <Link key="u" href={unitPath(item)}>
                  {item.unit.name}
                </Link>,
              ]
            : []),
          <span key="a">
            {[
              ...item.roles.map((role) => ({ ...role, kind: 'role' })),
              ...item.groups.map((group) => ({ ...group, kind: 'group' })),
            ].map((entry) => (
              <div key={entry.id}>
                {entry.name} <span className="muted small">({entry.kind})</span>
              </div>
            ))}
          </span>,
          <span key="h" className="small">
            {[...item.roles, ...item.groups]
              .map((entry) => `${percent(entry.share)} of ${item.people}`)
              .join(' · ')}
          </span>,
          `${item.wouldGrant} ${item.wouldGrant === 1 ? 'person' : 'people'}`,
          <ApiButton
            key="c"
            path="packages/create"
            body={{ tenantId, ...item.package }}
            label="Create package"
            tone="primary"
            confirm={`Create “${item.package.name}” and grant it automatically to everyone in ${item.unit.name}? The rule runs under your grant authority.`}
            showResult
            tenantId={tenantId}
          />,
        ])}
      />
    </Card>
  );
}
