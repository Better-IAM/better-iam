import type { ReactNode } from 'react';

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

export function Card({
  title,
  description,
  actions,
  children,
  flush,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  flush?: boolean;
}) {
  return (
    <section className="card">
      {(title || actions) && (
        <div className="card-header">
          <div>
            {title && <h2>{title}</h2>}
            {description && <p>{description}</p>}
          </div>
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      <div className={flush ? 'card-body flush' : 'card-body'}>{children}</div>
    </section>
  );
}

export function Table({
  head,
  rows,
  empty = 'Nothing here yet.',
}: {
  head: ReactNode[];
  rows: ReactNode[][];
  empty?: string;
}) {
  if (!rows.length) return <div className="empty">{empty}</div>;
  return (
    <table className="table">
      <thead>
        <tr>
          {head.map((cell, index) => (
            <th key={index}>{cell}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, rowIndex) => (
          <tr key={rowIndex}>
            {row.map((cell, cellIndex) => (
              <td key={cellIndex}>{cell}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'accent' | 'info';
export function Badge({ tone = 'neutral', children }: { tone?: Tone; children: ReactNode }) {
  return <span className={tone === 'neutral' ? 'badge' : `badge ${tone}`}>{children}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  const tone: Tone =
    status === 'active'
      ? 'success'
      : status === 'pending'
        ? 'warning'
        : status === 'suspended'
          ? 'warning'
          : status === 'deleted' || status === 'disabled'
            ? 'danger'
            : 'neutral';
  return <Badge tone={tone}>{status}</Badge>;
}

export function Alert({ tone = 'info', children }: { tone?: Tone; children: ReactNode }) {
  return <div className={`alert ${tone}`}>{children}</div>;
}

export function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
}) {
  return (
    <div className="card stat">
      <span className="label">{label}</span>
      <span className="value">{value}</span>
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

export function KeyValues({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([key, value], index) => (
        <div key={index} style={{ display: 'contents' }}>
          <dt>{key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Time({ value }: { value?: number }) {
  if (!value) return <span className="muted">—</span>;
  return (
    <time dateTime={new Date(value).toISOString()} title={new Date(value).toISOString()}>
      {new Date(value).toLocaleString()}
    </time>
  );
}

export function Json({ value }: { value: unknown }) {
  return <pre className="result">{JSON.stringify(value, null, 2)}</pre>;
}

/** A timestamp as a `datetime-local` input value (server local time, minute precision); empty when unset. */
export function dateTimeLocal(value?: number): string {
  if (!value) return '';
  const date = new Date(value);
  const pad = (part: number) => String(part).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
