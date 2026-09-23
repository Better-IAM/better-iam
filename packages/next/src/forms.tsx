'use client';
import { Fragment, useActionState, useId, type InputHTMLAttributes, type ReactNode } from 'react';
import {
  authFields,
  type AuthAction,
  type AuthFormError,
  type AuthFormState,
  type AuthIntent,
  type AuthMfaChallenge,
  type AuthStep,
} from './auth-types.js';
import { safeRedirectPath } from './edge.js';

/** What a form view renders: the `useActionState` result of its container. */
export interface AuthFormViewProps {
  state: AuthFormState | null;
  formAction: (form: FormData) => void;
  pending: boolean;
}

/** Options every auth form accepts. */
export interface AuthFormOptions<Labels> {
  /** Replaces any of the default English strings. */
  labels?: Partial<Labels>;
  /** Added to the root `<form>`, which also carries `data-better-iam` and `data-step` for styling. */
  className?: string;
}

/** A view's props: its container's props without `action`, plus the action state to render. */
export type AuthFormViewOf<Props> = Omit<Props, 'action'> & AuthFormViewProps;

/** Strings of the second-factor steps shared by sign-in, reauthentication, and invitations. */
export interface MfaLabels {
  mfaCode: string;
  mfaHint: string;
  rememberDevice: string;
  verify: string;
  emailCode: string;
  recovery: string;
  cancel: string;
  enrollIntro: string;
  enrollLink: string;
  enrollSecret: string;
  enroll: string;
  recoveryCodesNote: string;
  continue: string;
}
export interface SignInLabels extends MfaLabels {
  organization: string;
  email: string;
  password: string;
  keepSignedIn: string;
  signIn: string;
  sendCode: string;
  signInCode: string;
  resendCode: string;
  codeSent: string;
}
export interface ReauthenticateLabels extends MfaLabels {
  password: string;
  confirm: string;
}
export interface PasswordResetRequestLabels {
  organization: string;
  email: string;
  submit: string;
  sent: string;
}
export interface PasswordResetLabels {
  password: string;
  confirmPassword: string;
  submit: string;
  done: string;
  continue: string;
}
export interface SignUpLabels {
  name: string;
  email: string;
  password: string;
  submit: string;
  sent: string;
  continue: string;
}
export interface InvitationLabels extends MfaLabels {
  name: string;
  password: string;
  submit: string;
}

const mfaLabels: MfaLabels = {
  mfaCode: 'Verification code',
  mfaHint:
    'Enter the code from your authenticator app or the one we emailed you. To use a recovery code, enter it and choose "Use a recovery code".',
  rememberDevice: 'Remember this device',
  verify: 'Verify',
  emailCode: 'Email me a code',
  recovery: 'Use a recovery code',
  cancel: 'Cancel',
  enrollIntro:
    'Your account needs an authenticator app. Add this account to the app with the link or the setup key, then enter the code it shows.',
  enrollLink: 'Add to an authenticator app',
  enrollSecret: 'Setup key',
  enroll: 'Turn on and continue',
  recoveryCodesNote:
    'Store these recovery codes somewhere safe. Each one works once if you lose your authenticator, and they will not be shown again.',
  continue: 'Continue',
};
const signInLabels: SignInLabels = {
  ...mfaLabels,
  organization: 'Organization',
  email: 'Email',
  password: 'Password',
  keepSignedIn: 'Keep me signed in',
  signIn: 'Sign in',
  sendCode: 'Email me a sign-in code',
  signInCode: 'Sign-in code',
  resendCode: 'Send a new code',
  codeSent: 'Check your email for a sign-in code.',
};
const reauthenticateLabels: ReauthenticateLabels = {
  ...mfaLabels,
  password: 'Password',
  confirm: 'Continue',
};
const passwordResetRequestLabels: PasswordResetRequestLabels = {
  organization: 'Organization',
  email: 'Email',
  submit: 'Send reset link',
  sent: 'If an account uses that email, we sent it a link to reset the password.',
};
const passwordResetLabels: PasswordResetLabels = {
  password: 'New password',
  confirmPassword: 'Confirm new password',
  submit: 'Reset password',
  done: 'Your password has been reset. Sign in with your new password.',
  continue: 'Continue to sign in',
};
const signUpLabels: SignUpLabels = {
  name: 'Name',
  email: 'Email',
  password: 'Password',
  submit: 'Create account',
  sent: 'Check your email to confirm your address.',
  continue: 'Continue',
};
const invitationLabels: InvitationLabels = {
  ...mfaLabels,
  name: 'Name',
  password: 'Choose a password',
  submit: 'Accept invitation',
};

interface Fields {
  id: string;
  error: AuthFormError | undefined;
}
type InputProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'id' | 'name'>;

function useFields(state: AuthFormState | null): Fields {
  return { id: useId(), error: state?.error };
}

function useAuthForm(action: AuthAction): AuthFormViewProps {
  const [state, formAction, pending] = useActionState<AuthFormState | null, FormData>(action, null);
  return { state, formAction, pending };
}

/**
 * A same-origin path to continue to, or `''`. Checks the result of `safeRedirectPath` too: resolving dot segments
 * turns `/.//host` into `//host`, which a link or redirect would treat as another origin.
 */
function continuePath(value: unknown): string {
  const path = safeRedirectPath(value, '');
  return /^\/(?![/\\])/.test(path) ? path : '';
}

/** A second-factor step without its challenge cannot render, so it falls back to the start. */
function stepOf(state: AuthFormState | null): AuthStep {
  const step = state?.step ?? 'credentials';
  return (step === 'mfa' || step === 'enroll') && !state?.mfa ? 'credentials' : step;
}

function TextField({
  fields,
  name,
  label,
  hint,
  ...input
}: InputProps & { fields: Fields; name: string; label: string; hint?: string | undefined }) {
  const id = `${fields.id}-${name}`;
  const invalid = fields.error?.field === name;
  const describedBy = [invalid && `${fields.id}-error`, hint && `${id}-hint`]
    .filter(Boolean)
    .join(' ');
  return (
    <div data-field={name}>
      <label htmlFor={id}>{label}</label>
      <input
        {...input}
        id={id}
        name={name}
        aria-invalid={invalid || undefined}
        aria-describedby={describedBy || undefined}
      />
      {hint ? <p id={`${id}-hint`}>{hint}</p> : null}
    </div>
  );
}

/** A checkbox submitting `1`; with `unchecked`, a preceding hidden input submits that value when it is cleared. */
function Checkbox({
  fields,
  name,
  label,
  unchecked,
  ...input
}: InputProps & { fields: Fields; name: string; label: string; unchecked?: string }) {
  const id = `${fields.id}-${name}`;
  return (
    <div data-field={name}>
      {unchecked === undefined ? null : <input type="hidden" name={name} value={unchecked} />}
      <input {...input} type="checkbox" id={id} name={name} value="1" />
      <label htmlFor={id}>{label}</label>
    </div>
  );
}

function Hidden({ name, value }: { name: string; value: string | undefined }) {
  return value ? <input type="hidden" name={name} value={value} /> : null;
}

function Submit({
  intent,
  pending,
  skipValidation,
  children,
}: {
  intent?: AuthIntent;
  pending: boolean;
  skipValidation?: boolean;
  children: ReactNode;
}) {
  return (
    <button
      type="submit"
      name={intent ? authFields.intent : undefined}
      value={intent}
      disabled={pending}
      formNoValidate={skipValidation}
    >
      {children}
    </button>
  );
}

function Root({
  kind,
  step,
  view,
  className,
  fields,
  notice,
  children,
}: {
  kind: string;
  step: AuthStep;
  view: AuthFormViewProps;
  className: string | undefined;
  fields: Fields;
  notice?: string | undefined;
  children: ReactNode;
}) {
  return (
    <form
      action={view.formAction}
      className={className}
      data-better-iam={kind}
      data-step={step}
      aria-busy={view.pending || undefined}
    >
      {fields.error ? (
        <p id={`${fields.id}-error`} role="alert">
          {fields.error.message}
        </p>
      ) : null}
      <div role="status">{view.state?.notice ?? notice}</div>
      {/* A new step mounts fresh inputs, so its first field takes focus instead of inheriting the last step's. */}
      <Fragment key={step}>{children}</Fragment>
    </form>
  );
}

/**
 * The authenticator, emailed-code, recovery-code, and enrollment steps. The hidden fields are the ones the auth
 * actions rebuild the challenge from, so a refused code re-renders the same step without client JavaScript.
 */
function SecondFactor({
  step,
  mfa,
  labels,
  fields,
  pending,
  cancel,
}: {
  step: AuthStep;
  mfa: AuthMfaChallenge;
  labels: MfaLabels;
  fields: Fields;
  pending: boolean;
  cancel: boolean;
}) {
  const enrolling = step === 'enroll';
  const enrollment = enrolling ? mfa.enrollment : undefined;
  const recovery = !enrolling && !mfa.enrollmentRequired;
  const flag = (on: boolean) => (on ? '1' : undefined);
  return (
    <>
      <Hidden name={authFields.tenantId} value={mfa.tenantId} />
      <Hidden name={authFields.challenge} value={mfa.challenge} />
      <Hidden name="enrollmentRequired" value={flag(mfa.enrollmentRequired)} />
      <Hidden name="emailCodeAvailable" value={flag(mfa.emailCodeAvailable)} />
      <Hidden name="passkeyAvailable" value={flag(mfa.passkeyAvailable)} />
      <Hidden name="secret" value={mfa.enrollment?.secret} />
      <Hidden name="uri" value={mfa.enrollment?.uri} />
      {enrollment ? (
        <div data-enrollment="">
          <p>{labels.enrollIntro}</p>
          {enrollment.uri.startsWith('otpauth://') ? (
            <p>
              <a href={enrollment.uri}>{labels.enrollLink}</a>
            </p>
          ) : null}
          <p>
            {labels.enrollSecret}: <code>{enrollment.secret}</code>
          </p>
        </div>
      ) : null}
      <TextField
        fields={fields}
        name={authFields.code}
        label={labels.mfaCode}
        hint={enrolling ? undefined : labels.mfaHint}
        // Recovery codes are hexadecimal: a digits-only keyboard could not type them.
        inputMode={recovery ? 'text' : 'numeric'}
        autoComplete="one-time-code"
        autoCapitalize="none"
        spellCheck={false}
        required
        autoFocus
      />
      {enrolling ? null : (
        <Checkbox fields={fields} name={authFields.rememberDevice} label={labels.rememberDevice} />
      )}
      <Submit intent={enrolling ? 'enroll' : 'mfa'} pending={pending}>
        {enrolling ? labels.enroll : labels.verify}
      </Submit>
      {mfa.emailCodeAvailable ? (
        <Submit intent="email-code" pending={pending} skipValidation>
          {labels.emailCode}
        </Submit>
      ) : null}
      {recovery ? (
        <Submit intent="recovery" pending={pending}>
          {labels.recovery}
        </Submit>
      ) : null}
      {cancel ? (
        <Submit intent="cancel" pending={pending} skipValidation>
          {labels.cancel}
        </Submit>
      ) : null}
    </>
  );
}

/** Recovery codes (shown once, after enrolling) and the way on. */
function Finished({
  recoveryCodes,
  href,
  labels,
}: {
  recoveryCodes: string[] | undefined;
  href: string;
  labels: MfaLabels;
}) {
  return (
    <>
      {recoveryCodes?.length ? (
        <>
          <p>{labels.recoveryCodesNote}</p>
          <ul data-recovery-codes="">
            {recoveryCodes.map((code) => (
              <li key={code}>
                <code>{code}</code>
              </li>
            ))}
          </ul>
        </>
      ) : null}
      <a href={href}>{labels.continue}</a>
    </>
  );
}

export interface SignInFormProps extends AuthFormOptions<SignInLabels> {
  action: AuthAction;
  /** The same-origin path to continue to after signing in. */
  next?: string;
  /** The organization slug; fills the organization field, or replaces it when `showOrganization` is false. */
  org?: string;
  /** Signs in to this tenant directly, without an organization field. */
  tenantId?: string;
  /** Fills the email field. */
  email?: string;
  /** Shows the organization field; defaults to true unless `tenantId` or `org` is given. */
  showOrganization?: boolean;
  /** Offers "keep me signed in"; left unchecked, the session cookie ends with the browser session. */
  keepSignedIn?: boolean;
  /** Offers "email me a sign-in code" as an alternative to the password. */
  passwordless?: boolean;
}

/**
 * Password sign-in with an optional emailed sign-in code, then the second factor (authenticator, emailed code, or
 * recovery code) or first-time authenticator enrollment, as `action` directs. Works without client JavaScript.
 */
export function SignInForm({ action, ...props }: SignInFormProps) {
  return <SignInFormView {...props} {...useAuthForm(action)} />;
}

/** The markup of `SignInForm` for a given action state. */
export function SignInFormView({
  state,
  formAction,
  pending,
  labels: overrides,
  className,
  next,
  org,
  tenantId,
  email,
  showOrganization,
  keepSignedIn,
  passwordless,
}: AuthFormViewOf<SignInFormProps>) {
  const labels = { ...signInLabels, ...overrides };
  const fields = useFields(state);
  const step = stepOf(state);
  const values = state?.values;
  const orgValue = values?.org ?? org;
  const emailValue = values?.email ?? email;
  const tenant = values?.tenantId ?? tenantId;
  const continueTo = continuePath(state?.next ?? next);
  const organizationField = showOrganization ?? (tenantId === undefined && org === undefined);
  const keep = state?.keepSignedIn === undefined ? undefined : state.keepSignedIn ? '1' : '0';
  const carried = (
    <>
      <Hidden name={authFields.org} value={orgValue} />
      <Hidden name={authFields.email} value={emailValue} />
      <Hidden name={authFields.next} value={continueTo} />
      <Hidden name={authFields.keepSignedIn} value={keep} />
    </>
  );
  let body: ReactNode = null;
  if (step === 'credentials')
    body = (
      <>
        <Hidden name={authFields.tenantId} value={tenant} />
        {organizationField ? (
          <TextField
            fields={fields}
            name={authFields.org}
            label={labels.organization}
            defaultValue={orgValue}
            autoCapitalize="none"
            spellCheck={false}
            required
            autoFocus
          />
        ) : (
          <Hidden name={authFields.org} value={orgValue} />
        )}
        <TextField
          fields={fields}
          name={authFields.email}
          label={labels.email}
          type="email"
          autoComplete="username"
          defaultValue={emailValue}
          required
          autoFocus={!organizationField}
        />
        <TextField
          fields={fields}
          name={authFields.password}
          label={labels.password}
          type="password"
          autoComplete="current-password"
          required
        />
        {keepSignedIn ? (
          <Checkbox
            fields={fields}
            name={authFields.keepSignedIn}
            label={labels.keepSignedIn}
            unchecked="0"
            defaultChecked={state?.keepSignedIn ?? false}
          />
        ) : null}
        <Hidden name={authFields.next} value={continueTo} />
        <Submit intent="password" pending={pending}>
          {labels.signIn}
        </Submit>
        {passwordless ? (
          <Submit intent="send-code" pending={pending} skipValidation>
            {labels.sendCode}
          </Submit>
        ) : null}
      </>
    );
  else if (step === 'code-sent')
    body = (
      <>
        <Hidden name={authFields.tenantId} value={tenant} />
        {carried}
        <TextField
          fields={fields}
          name={authFields.code}
          label={labels.signInCode}
          inputMode="numeric"
          autoComplete="one-time-code"
          autoCapitalize="none"
          spellCheck={false}
          required
          autoFocus
        />
        <Submit intent="code" pending={pending}>
          {labels.signIn}
        </Submit>
        <Submit intent="send-code" pending={pending} skipValidation>
          {labels.resendCode}
        </Submit>
        <Submit intent="cancel" pending={pending} skipValidation>
          {labels.cancel}
        </Submit>
      </>
    );
  else if ((step === 'mfa' || step === 'enroll') && state?.mfa)
    body = (
      <>
        {carried}
        <SecondFactor
          step={step}
          mfa={state.mfa}
          labels={labels}
          fields={fields}
          pending={pending}
          cancel
        />
      </>
    );
  else if (step === 'done')
    body = (
      <Finished recoveryCodes={state?.recoveryCodes} href={continueTo || '/'} labels={labels} />
    );
  return (
    <Root
      kind="sign-in"
      step={step}
      view={{ state, formAction, pending }}
      className={className}
      fields={fields}
      notice={step === 'code-sent' ? labels.codeSent : undefined}
    >
      {body}
    </Root>
  );
}

export interface ReauthenticateFormProps extends AuthFormOptions<ReauthenticateLabels> {
  action: AuthAction;
  /** The same-origin path to return to once the person has confirmed who they are. */
  next?: string;
  /**
   * Whether the new session's cookie outlives the browser session: pass the "keep me signed in" choice made at
   * sign-in. Off by default, so a step-up never turns a browser-session sign-in into a persistent one.
   */
  keepSignedIn?: boolean;
}

/**
 * Confirms the signed-in person's password, then their second factor when the account has one. The confirmation
 * issues a new session, whose cookie follows `keepSignedIn`.
 */
export function ReauthenticateForm({ action, ...props }: ReauthenticateFormProps) {
  return <ReauthenticateFormView {...props} {...useAuthForm(action)} />;
}

/** The markup of `ReauthenticateForm` for a given action state. */
export function ReauthenticateFormView({
  state,
  formAction,
  pending,
  labels: overrides,
  className,
  next,
  keepSignedIn,
}: AuthFormViewOf<ReauthenticateFormProps>) {
  const labels = { ...reauthenticateLabels, ...overrides };
  const fields = useFields(state);
  const step = stepOf(state);
  const continueTo = continuePath(state?.next ?? next);
  const carried = (
    <>
      <Hidden name={authFields.next} value={continueTo} />
      <Hidden
        name={authFields.keepSignedIn}
        value={(state?.keepSignedIn ?? keepSignedIn) ? '1' : '0'}
      />
    </>
  );
  let body: ReactNode = null;
  if (step === 'credentials')
    body = (
      <>
        <TextField
          fields={fields}
          name={authFields.password}
          label={labels.password}
          type="password"
          autoComplete="current-password"
          required
          autoFocus
        />
        {carried}
        <Submit intent="password" pending={pending}>
          {labels.confirm}
        </Submit>
      </>
    );
  else if ((step === 'mfa' || step === 'enroll') && state?.mfa)
    body = (
      <>
        {carried}
        <SecondFactor
          step={step}
          mfa={state.mfa}
          labels={labels}
          fields={fields}
          pending={pending}
          cancel
        />
      </>
    );
  else if (step === 'done')
    body = (
      <Finished recoveryCodes={state?.recoveryCodes} href={continueTo || '/'} labels={labels} />
    );
  return (
    <Root
      kind="reauthenticate"
      step={step}
      view={{ state, formAction, pending }}
      className={className}
      fields={fields}
    >
      {body}
    </Root>
  );
}

export interface PasswordResetRequestFormProps extends AuthFormOptions<PasswordResetRequestLabels> {
  action: AuthAction;
  /** Fills the organization field. */
  org?: string;
  /** The tenant of the account; replaces the organization field. */
  tenantId?: string;
}

/** Asks for a password reset email. The reply never reveals whether the account exists. */
export function PasswordResetRequestForm({ action, ...props }: PasswordResetRequestFormProps) {
  return <PasswordResetRequestFormView {...props} {...useAuthForm(action)} />;
}

/** The markup of `PasswordResetRequestForm` for a given action state. */
export function PasswordResetRequestFormView({
  state,
  formAction,
  pending,
  labels: overrides,
  className,
  org,
  tenantId,
}: AuthFormViewOf<PasswordResetRequestFormProps>) {
  const labels = { ...passwordResetRequestLabels, ...overrides };
  const fields = useFields(state);
  const step = stepOf(state);
  const sent = step === 'sent' || step === 'done';
  return (
    <Root
      kind="password-reset-request"
      step={step}
      view={{ state, formAction, pending }}
      className={className}
      fields={fields}
      notice={sent ? labels.sent : undefined}
    >
      {sent ? null : (
        <>
          <Hidden name={authFields.tenantId} value={tenantId} />
          {tenantId === undefined ? (
            <TextField
              fields={fields}
              name={authFields.org}
              label={labels.organization}
              defaultValue={state?.values?.org ?? org}
              autoCapitalize="none"
              spellCheck={false}
              required
              autoFocus
            />
          ) : null}
          <TextField
            fields={fields}
            name={authFields.email}
            label={labels.email}
            type="email"
            autoComplete="email"
            defaultValue={state?.values?.email}
            required
            autoFocus={tenantId !== undefined}
          />
          <Submit pending={pending}>{labels.submit}</Submit>
        </>
      )}
    </Root>
  );
}

export interface PasswordResetFormProps extends AuthFormOptions<PasswordResetLabels> {
  action: AuthAction;
  tenantId: string;
  /** The token from the password reset link. */
  token: string;
}

/** Sets a new password from a reset link. Existing sessions end; the person signs in again. */
export function PasswordResetForm({ action, ...props }: PasswordResetFormProps) {
  return <PasswordResetFormView {...props} {...useAuthForm(action)} />;
}

/** The markup of `PasswordResetForm` for a given action state. */
export function PasswordResetFormView({
  state,
  formAction,
  pending,
  labels: overrides,
  className,
  tenantId,
  token,
}: AuthFormViewOf<PasswordResetFormProps>) {
  const labels = { ...passwordResetLabels, ...overrides };
  const fields = useFields(state);
  const step = stepOf(state);
  const finished = step === 'done' || step === 'sent';
  return (
    <Root
      kind="password-reset"
      step={step}
      view={{ state, formAction, pending }}
      className={className}
      fields={fields}
      notice={finished ? labels.done : undefined}
    >
      {finished ? (
        <a href={continuePath(state?.next) || '/'}>{labels.continue}</a>
      ) : (
        <>
          <Hidden name={authFields.tenantId} value={tenantId} />
          <Hidden name={authFields.token} value={token} />
          <TextField
            fields={fields}
            name={authFields.password}
            label={labels.password}
            type="password"
            autoComplete="new-password"
            required
            autoFocus
          />
          <TextField
            fields={fields}
            name={authFields.confirmPassword}
            label={labels.confirmPassword}
            type="password"
            autoComplete="new-password"
            required
          />
          <Submit pending={pending}>{labels.submit}</Submit>
        </>
      )}
    </Root>
  );
}

export interface SignUpFormProps extends AuthFormOptions<SignUpLabels> {
  action: AuthAction;
  tenantId: string;
  /** The same-origin path to continue to once the account exists. */
  next?: string;
}

/** Self-registration: name, email, and password, usually followed by an email to confirm the address. */
export function SignUpForm({ action, ...props }: SignUpFormProps) {
  return <SignUpFormView {...props} {...useAuthForm(action)} />;
}

/** The markup of `SignUpForm` for a given action state. */
export function SignUpFormView({
  state,
  formAction,
  pending,
  labels: overrides,
  className,
  tenantId,
  next,
}: AuthFormViewOf<SignUpFormProps>) {
  const labels = { ...signUpLabels, ...overrides };
  const fields = useFields(state);
  const step = stepOf(state);
  const continueTo = continuePath(state?.next ?? next);
  let body: ReactNode = null;
  if (step === 'credentials')
    body = (
      <>
        <Hidden name={authFields.tenantId} value={tenantId} />
        <Hidden name={authFields.next} value={continueTo} />
        <TextField
          fields={fields}
          name={authFields.name}
          label={labels.name}
          autoComplete="name"
          defaultValue={state?.values?.name}
          required
          autoFocus
        />
        <TextField
          fields={fields}
          name={authFields.email}
          label={labels.email}
          type="email"
          autoComplete="email"
          defaultValue={state?.values?.email}
          required
        />
        <TextField
          fields={fields}
          name={authFields.password}
          label={labels.password}
          type="password"
          autoComplete="new-password"
          required
        />
        <Submit pending={pending}>{labels.submit}</Submit>
      </>
    );
  else if (step === 'done') body = <a href={continueTo || '/'}>{labels.continue}</a>;
  return (
    <Root
      kind="sign-up"
      step={step}
      view={{ state, formAction, pending }}
      className={className}
      fields={fields}
      notice={step === 'sent' ? labels.sent : undefined}
    >
      {body}
    </Root>
  );
}

export interface InvitationFormProps extends AuthFormOptions<InvitationLabels> {
  action: AuthAction;
  tenantId: string;
  /** The token from the invitation link. */
  token: string;
  /** `owner` invitations create a pending organization's first owner and always ask for a name. */
  kind: 'member' | 'owner';
  /** The same-origin path to continue to once the account is set up. */
  next?: string;
}

/**
 * Accepts an invitation with a name and a new password, then enrolls or verifies the second factor when the
 * organization requires one, and shows the recovery codes.
 */
export function InvitationForm({ action, ...props }: InvitationFormProps) {
  return <InvitationFormView {...props} {...useAuthForm(action)} />;
}

/** The markup of `InvitationForm` for a given action state. */
export function InvitationFormView({
  state,
  formAction,
  pending,
  labels: overrides,
  className,
  tenantId,
  token,
  kind,
  next,
}: AuthFormViewOf<InvitationFormProps>) {
  const labels = { ...invitationLabels, ...overrides };
  const fields = useFields(state);
  const step = stepOf(state);
  const continueTo = continuePath(state?.next ?? next);
  let body: ReactNode = null;
  if (step === 'credentials')
    body = (
      <>
        <Hidden name={authFields.tenantId} value={tenantId} />
        <Hidden name={authFields.token} value={token} />
        <Hidden name={authFields.kind} value={kind} />
        <Hidden name={authFields.next} value={continueTo} />
        <TextField
          fields={fields}
          name={authFields.name}
          label={labels.name}
          autoComplete="name"
          defaultValue={state?.values?.name}
          required={kind === 'owner'}
          autoFocus
        />
        <TextField
          fields={fields}
          name={authFields.password}
          label={labels.password}
          type="password"
          autoComplete="new-password"
          required
        />
        <Submit intent="password" pending={pending}>
          {labels.submit}
        </Submit>
      </>
    );
  else if ((step === 'mfa' || step === 'enroll') && state?.mfa)
    body = (
      <>
        <Hidden name={authFields.kind} value={kind} />
        <Hidden name={authFields.next} value={continueTo} />
        <SecondFactor
          step={step}
          mfa={state.mfa}
          labels={labels}
          fields={fields}
          pending={pending}
          cancel={false}
        />
      </>
    );
  else if (step === 'done')
    body = (
      <Finished recoveryCodes={state?.recoveryCodes} href={continueTo || '/'} labels={labels} />
    );
  return (
    <Root
      kind="invitation"
      step={step}
      view={{ state, formAction, pending }}
      className={className}
      fields={fields}
    >
      {body}
    </Root>
  );
}
