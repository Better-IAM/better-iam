// Pure logic of the shared second-factor step (MfaChallenge in components/auth-forms.tsx).

/** Everything the second-factor step needs, derived from a sign-in's `mfaRequired` outcome. */
export interface MfaChallengeState {
  challenge: string;
  /** Present when nothing is enrolled yet: the secret to add to an authenticator app. */
  enrollment?: { secret: string; uri: string };
  /** The organization lets people without an authenticator use an emailed code instead. */
  emailCodeAvailable?: boolean;
  /** A registered passkey can stand in for the authenticator code. */
  passkeyAvailable?: boolean;
  /** `false` when no authenticator app is enabled, so a code (or recovery code) cannot satisfy the step. */
  authenticatorEnrolled?: boolean;
  /**
   * Whether the session cookie should outlive the browser ("keep me signed in"). Unset, the choice remembered for
   * this browser (lib/persistence) applies when the step completes.
   */
  persistent?: boolean;
}

/** The `mfaRequired` outcome of a sign-in, passwordless redemption, or re-authentication. */
export interface MfaRequiredOutcome {
  challenge: string;
  enrollmentRequired: boolean;
  emailCodeAvailable?: boolean;
  passkeyAvailable?: boolean;
  authenticatorEnrolled?: boolean;
}

export function challengeStateFrom(
  outcome: MfaRequiredOutcome,
  enrollment?: { secret: string; uri: string },
  persistent?: boolean,
): MfaChallengeState {
  return {
    challenge: outcome.challenge,
    enrollment,
    emailCodeAvailable: outcome.emailCodeAvailable === true,
    passkeyAvailable: outcome.passkeyAvailable === true,
    ...(typeof outcome.authenticatorEnrolled === 'boolean'
      ? { authenticatorEnrolled: outcome.authenticatorEnrolled }
      : {}),
    ...(persistent === undefined ? {} : { persistent }),
  };
}

export interface MfaStepView {
  /** First-time authenticator enrollment (confirmMfa) rather than verification. */
  enrolling: boolean;
  /** The passkey is the only factor on offer: it is the main action and no code field is shown. */
  passkeyPrimary: boolean;
  codeField: boolean;
  codeLabel: string;
  /** "Use a recovery code" is offered: recovery codes exist only alongside an authenticator app. */
  recoveryToggle: boolean;
  /** The typed code is a recovery code (recoverMfa). */
  recovering: boolean;
}

export function mfaStepView(
  state: MfaChallengeState,
  input: { emailCodeSent: boolean; useRecovery: boolean },
): MfaStepView {
  const enrolling = Boolean(state.enrollment) && !input.emailCodeSent;
  // Someone whose only factor is a passkey cannot type anything useful here until an emailed code is sent.
  const passkeyPrimary =
    state.authenticatorEnrolled === false &&
    state.passkeyAvailable === true &&
    !state.enrollment &&
    !input.emailCodeSent;
  const recoveryToggle =
    !state.enrollment && !input.emailCodeSent && state.authenticatorEnrolled !== false;
  const recovering = recoveryToggle && input.useRecovery;
  return {
    enrolling,
    passkeyPrimary,
    codeField: !passkeyPrimary,
    codeLabel: input.emailCodeSent
      ? 'Emailed code'
      : recovering
        ? 'Recovery code'
        : 'Authenticator code',
    recoveryToggle,
    recovering,
  };
}

/** The login challenge (and any emailed code) lapsed or was used up: only starting the sign-in again helps. */
export function challengeLapsed(code: string): boolean {
  return code === 'INVALID_CHALLENGE';
}
