import Link from 'next/link';
import type { SignalEventView } from 'better-iam/server';
import { ApiButton } from '@/components/api-form';
import { Badge, Table, Time } from '@/components/ui';
import {
  claimsSummary,
  eventTypeLabels,
  signalReason,
  signalStatusHelp,
  signalStatusTone,
  subjectSummary,
} from '@/lib/signals';

/**
 * Received security events as a table: when, what, from which source, about whom, and the outcome. Unmatched and failed
 * events get a Reprocess button when the viewer may manage events.
 */
export function SignalEventsTable({
  events,
  base,
  tenantId,
  sourceNames,
  people,
  mayReprocess,
  showSource = true,
  empty,
}: {
  events: SignalEventView[];
  base: string;
  tenantId: string;
  /** Source names by id; a source missing here has been deleted. */
  sourceNames: Record<string, string>;
  /** Display names of matched people by identity id. */
  people: Record<string, string>;
  mayReprocess: boolean;
  showSource?: boolean;
  empty: string;
}) {
  return (
    <Table
      head={[
        'Received',
        'Event',
        ...(showSource ? ['Source'] : []),
        'Subject',
        'Person',
        'Outcome',
        '',
      ]}
      rows={events.map((event) => {
        const details = claimsSummary(event.eventType, event.claims);
        const reason = signalReason(event.reason);
        const sourceName = sourceNames[event.sourceId];
        return [
          <span key="r" className="stack small" style={{ gap: 2 }}>
            <Time value={event.receivedAt} />
            {event.eventTimestamp !== undefined && (
              <span className="muted">
                happened <Time value={event.eventTimestamp} />
              </span>
            )}
          </span>,
          <span key="e" className="stack" style={{ gap: 2 }} title={event.eventUri}>
            <strong>{eventTypeLabels[event.eventType]}</strong>
            {details && <span className="small muted">{details}</span>}
          </span>,
          ...(showSource
            ? [
                sourceName ? (
                  <Link key="s" href={`${base}/signals/${event.sourceId}`}>
                    {sourceName}
                  </Link>
                ) : (
                  <span key="s" className="muted small">
                    deleted source
                  </span>
                ),
              ]
            : []),
          <code key="u" className="small" style={{ wordBreak: 'break-all' }}>
            {subjectSummary(event.subject)}
          </code>,
          event.identityId ? (
            <Link key="p" href={`${base}/members/${encodeURIComponent(event.identityId)}`}>
              {people[event.identityId] ?? event.identityId}
            </Link>
          ) : (
            <span key="p" className="muted">
              —
            </span>
          ),
          <span key="o" className="stack" style={{ gap: 2 }} title={signalStatusHelp[event.status]}>
            <Badge tone={signalStatusTone(event.status)}>{event.status}</Badge>
            {reason && <span className="small muted">{reason}</span>}
            {event.reprocessedAt && (
              <span className="small muted">
                reprocessed <Time value={event.reprocessedAt} />
              </span>
            )}
          </span>,
          mayReprocess &&
          sourceName &&
          (event.status === 'unmatched' || event.status === 'failed') ? (
            <ApiButton
              key="a"
              path="signals/reprocess"
              body={{ tenantId, eventId: event.id }}
              label="Reprocess"
              tenantId={tenantId}
            />
          ) : (
            ''
          ),
        ];
      })}
      empty={empty}
    />
  );
}
