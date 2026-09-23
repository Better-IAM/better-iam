/**
 * The login-page explanation for `?reason=`. A switch rather than an object lookup: the value comes from the URL, and
 * names like `__proto__` or `toString` would otherwise find inherited properties and break the page.
 */
export function sessionEndedMessage(reason: unknown): string | undefined {
  switch (reason) {
    case 'idle':
      return 'You were signed out after a period of inactivity. Sign in again to continue where you left off.';
    case 'expired':
      return 'Your session reached its maximum length. Sign in again to continue.';
    case 'ended':
      return 'Your session has ended. Sign in again to continue.';
    default:
      return undefined;
  }
}

/** Explains on a login page why the person landed there (`?reason=idle|expired|ended`); renders nothing otherwise. */
export function SessionEndedNotice({ reason }: { reason?: string }) {
  const text = sessionEndedMessage(reason);
  if (!text) return null;
  return (
    <div className="alert info" role="status">
      {text}
    </div>
  );
}
