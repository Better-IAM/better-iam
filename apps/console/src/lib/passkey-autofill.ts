// Re-arming policy for passkey autofill (conditional mediation) on the sign-in page (components/passkeys.tsx).

/** Discovery challenges live five minutes on the server; a waiting autofill request swaps its challenge before then. */
export const AUTOFILL_REFRESH_MS = 4 * 60_000;
/** Pause before arming again after a failed attempt. */
export const AUTOFILL_RETRY_MS = 2_000;
/** A ceremony that fails this soon after arming involved no choice by the person. */
export const AUTOFILL_QUICK_FAILURE_MS = 5_000;
/** Stop re-arming after this many quick failures in a row, so a browser that refuses at once cannot drain rate limits. */
export const AUTOFILL_MAX_QUICK_FAILURES = 3;

export interface AutofillFailure {
  /** Arm again after `delayMs`, or leave autofill off (the passkey button keeps working). */
  rearm: boolean;
  delayMs: number;
  /** Show the error: anything but the browser's own dismissal or abort. */
  show: boolean;
  quickFailures: number;
}

/**
 * Decides what follows a failed autofill ceremony. `name` is the error's name; `stage` says whether the browser
 * ceremony failed or the server refused the assertion; `refreshing` marks our own abort to swap in a fresh challenge.
 */
export function autofillFailure(input: {
  name: string | undefined;
  stage: 'browser' | 'server';
  refreshing: boolean;
  elapsedMs: number;
  quickFailures: number;
}): AutofillFailure {
  if (input.stage === 'server')
    // The person picked a passkey and passed verification, then the server refused it (another organization's
    // passkey, an expired challenge, a rate limit): say why and offer autofill again with a fresh challenge.
    return { rearm: true, delayMs: AUTOFILL_RETRY_MS, show: true, quickFailures: 0 };
  if (input.refreshing) return { rearm: true, delayMs: 0, show: false, quickFailures: 0 };
  // Another ceremony (the passkey button, the MFA step) took over the browser's single WebAuthn slot; re-arming now
  // would abort it. The passkey button arms autofill again when it finishes.
  if (input.name === 'AbortError')
    return { rearm: false, delayMs: 0, show: false, quickFailures: input.quickFailures };
  const quickFailures = input.elapsedMs < AUTOFILL_QUICK_FAILURE_MS ? input.quickFailures + 1 : 0;
  return {
    rearm: quickFailures < AUTOFILL_MAX_QUICK_FAILURES,
    delayMs: AUTOFILL_RETRY_MS,
    // NotAllowedError: dismissed, cancelled, or timed out. Anything else (an RP ID mismatch, an authenticator
    // failure) is worth reporting.
    show: input.name !== 'NotAllowedError',
    quickFailures,
  };
}
