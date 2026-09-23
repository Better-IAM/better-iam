'use client';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import type { SignInRecord } from 'better-iam';
import { clientLine, type ClientInfo } from '@/lib/device';

function where(client?: ClientInfo): string {
  const line = clientLine(client);
  return line ? ` from ${line}` : '';
}

/**
 * Shown above every page of a session whose sign-in record reports failed attempts since the person's previous
 * sign-in (`session.previousSignIn`). Dismissed per session in this browser only; the events stay on the account
 * page's security activity.
 */
export function SignInNotice({
  sessionId,
  previous,
  accountHref,
}: {
  sessionId: string;
  previous?: SignInRecord;
  accountHref: string;
}) {
  const key = `better-iam.sign-in-notice.${sessionId}`;
  // Nothing renders on the server or before the dismissal state is known, so hydration never disagrees.
  const [hidden, setHidden] = useState(true);
  useEffect(() => {
    try {
      setHidden(window.localStorage.getItem(key) === '1');
    } catch {
      setHidden(false);
    }
  }, [key]);
  if (hidden || !previous || previous.failedAttempts < 1) return null;
  const attempts = previous.failedAttempts;
  const dismiss = () => {
    try {
      window.localStorage.setItem(key, '1');
    } catch {
      /* Private mode: the notice simply returns on the next page. */
    }
    setHidden(true);
  };
  return (
    <div
      className="alert warning row"
      style={{ justifyContent: 'space-between', marginBottom: 20 }}
      role="status"
    >
      <span>
        <strong>
          {attempts} failed sign-in attempt{attempts === 1 ? '' : 's'}
        </strong>{' '}
        on your account
        {previous.lastAt
          ? ` since your previous sign-in on ${new Date(previous.lastAt).toLocaleString()}`
          : ' before this first sign-in'}
        {previous.lastFailedAt
          ? `, the latest on ${new Date(previous.lastFailedAt).toLocaleString()}${where(previous.lastFailedClient)}`
          : ''}
        . If that was not you, change your password and review your security activity.
      </span>
      <span className="row">
        <Link className="btn small" href={accountHref}>
          Security activity
        </Link>
        <button className="btn small secondary" type="button" onClick={dismiss}>
          Dismiss
        </button>
      </span>
    </div>
  );
}
