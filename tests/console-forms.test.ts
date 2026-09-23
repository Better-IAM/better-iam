import { act, createElement, type ReactElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  bodyFrom,
  dateTimeLocalValue,
  selectDefault,
  textDefault,
  type FieldSpec,
} from '../apps/console/src/lib/form-body.js';
import {
  challengeLapsed,
  challengeStateFrom,
  mfaStepView,
} from '../apps/console/src/lib/mfa-step.js';
import {
  AUTOFILL_MAX_QUICK_FAILURES,
  AUTOFILL_RETRY_MS,
  autofillFailure,
} from '../apps/console/src/lib/passkey-autofill.js';
import {
  initialRemember,
  recordedRemember,
  recordedRememberBrowser,
  REMEMBER_COOKIE,
  rememberBrowser,
  rememberCookie,
  rememberFromCookies,
  rememberFromValue,
  sessionOptions,
  setRememberBrowser,
} from '../apps/console/src/lib/persistence.js';

// A browser DOM under the node transform: the console components import `@/lib/*`, which only the node pipeline
// lets vi.mock replace (the happy-dom environment's web pipeline refuses unresolved imports). vi.hoisted runs this
// before any import, so React DOM finds the DOM when it loads.
const dom = await vi.hoisted(async () => {
  const { builtinEnvironments } = await import('vitest/environments');
  return builtinEnvironments['happy-dom'].setup(globalThis, {
    happyDOM: { url: 'https://console.example.test/cloud/login' },
  });
});
afterAll(() => dom.teardown(globalThis));

// The console components run against a scripted IAM client, router, and WebAuthn browser API.
const fake = vi.hoisted(() => {
  class FakeIamError extends Error {
    constructor(
      readonly code: string,
      message: string,
    ) {
      super(message);
    }
  }
  return {
    FakeIamError,
    client: { auth: {} as Record<string, ReturnType<typeof vi.fn>>, $request: vi.fn() },
    router: { push: vi.fn(), refresh: vi.fn() },
    webauthn: {
      startAuthentication: vi.fn(),
      startRegistration: vi.fn(),
      browserSupportsWebAuthn: vi.fn(() => false),
      browserSupportsWebAuthnAutofill: vi.fn(async () => false),
      WebAuthnAbortService: { cancelCeremony: vi.fn() },
    },
  };
});
vi.mock('@/lib/client', () => ({
  iamClient: () => fake.client,
  describeError: (error: unknown) =>
    error instanceof fake.FakeIamError
      ? { code: error.code, message: error.message }
      : { code: 'ERROR', message: error instanceof Error ? error.message : 'Something went wrong' },
}));
vi.mock('../apps/console/node_modules/next/navigation.js', () => ({
  useRouter: () => fake.router,
}));
// The console resolves `better-iam/client/passkeys` through its own node_modules to the umbrella package's build.
vi.mock('../packages/better-iam/dist/client-passkeys.js', () => fake.webauthn);
vi.mock('@/lib/form-body', () => import('../apps/console/src/lib/form-body.js'));
vi.mock('@/lib/mfa-step', () => import('../apps/console/src/lib/mfa-step.js'));
vi.mock('@/lib/passkey-autofill', () => import('../apps/console/src/lib/passkey-autofill.js'));
vi.mock('@/lib/persistence', () => import('../apps/console/src/lib/persistence.js'));
vi.mock('@/lib/device', () => import('../apps/console/src/lib/device.js'));

function form(entries: [string, string][]): FormData {
  const data = new FormData();
  for (const [name, value] of entries) data.append(name, value);
  return data;
}

describe('console "keep me signed in" persistence', () => {
  afterEach(() => {
    document.cookie = `${REMEMBER_COOKIE}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  });

  it('always sends an explicit persistence header, so a ticked box beats persistentCookies: false', () => {
    expect(sessionOptions(true)).toEqual({ headers: { 'x-better-iam-persistent': '1' } });
    expect(sessionOptions(false)).toEqual({ headers: { 'x-better-iam-persistent': '0' } });
  });

  it('remembers the choice for this browser session and applies it to later calls', () => {
    expect(recordedRememberBrowser()).toBeUndefined();
    expect(rememberBrowser()).toBe(true);
    expect(sessionOptions().headers['x-better-iam-persistent']).toBe('1');

    setRememberBrowser(false);
    expect(document.cookie).toContain(`${REMEMBER_COOKIE}=0`);
    expect(recordedRememberBrowser()).toBe(false);
    expect(rememberBrowser()).toBe(false);
    // Passkey, emailed-link, MFA and re-authentication calls pass no argument and pick the choice up.
    expect(sessionOptions().headers['x-better-iam-persistent']).toBe('0');
    // An explicit argument still wins.
    expect(sessionOptions(true).headers['x-better-iam-persistent']).toBe('1');

    setRememberBrowser(true);
    expect(document.cookie).toContain(`${REMEMBER_COOKIE}=1`);
    expect(recordedRememberBrowser()).toBe(true);
    expect(sessionOptions().headers['x-better-iam-persistent']).toBe('1');
  });

  it('reads the cookie strictly: only an explicit 0 shortens the session', () => {
    expect(rememberFromCookies(undefined)).toBe(true);
    expect(rememberFromCookies('')).toBe(true);
    expect(rememberFromCookies(`a=1; ${REMEMBER_COOKIE}=0; b=2`)).toBe(false);
    expect(rememberFromCookies(`x${REMEMBER_COOKIE}=0`)).toBe(true);
    expect(rememberFromCookies(`${REMEMBER_COOKIE}=1`)).toBe(true);
    expect(rememberFromCookies(`${REMEMBER_COOKIE}=junk`)).toBe(true);
    expect(recordedRemember(`${REMEMBER_COOKIE}=junk`)).toBeUndefined();
    expect(rememberFromValue('0')).toBe(false);
    expect(rememberFromValue(undefined)).toBe(true);
  });

  it("starts the sign-in page's box from the deployment default until a choice is recorded", () => {
    // persistentCookies: false shows the box unticked, so the operator's default holds unless someone opts in.
    expect(initialRemember(undefined, { persistentCookies: false })).toBe(false);
    expect(initialRemember(undefined, { persistentCookies: true })).toBe(true);
    expect(initialRemember(undefined, undefined)).toBe(true);
    expect(initialRemember('1', { persistentCookies: false })).toBe(true);
    expect(initialRemember('0', { persistentCookies: true })).toBe(false);
  });

  it('writes a browser-session cookie readable by scripts, Secure over HTTPS', () => {
    const unticked = rememberCookie(false, true);
    expect(unticked).toBe(`${REMEMBER_COOKIE}=0; Path=/; SameSite=Lax; Secure`);
    expect(unticked).not.toMatch(/Max-Age|Expires|HttpOnly/i);
    expect(rememberCookie(true, false)).toBe(`${REMEMBER_COOKIE}=1; Path=/; SameSite=Lax`);
  });
});

describe('console ApiForm fields', () => {
  it('preselects multiselect defaults so a whole-record form keeps the current selection', () => {
    const field: FieldSpec = {
      name: 'allowedMethods',
      label: 'Allowed methods',
      type: 'multiselect',
      group: 'authPolicy',
      defaultValue: ['federated', 'passkey'],
      options: [
        { value: 'password', label: 'password' },
        { value: 'federated', label: 'federated' },
        { value: 'passkey', label: 'passkey' },
      ],
    };
    expect(selectDefault(field)).toEqual(['federated', 'passkey']);
    expect(selectDefault({ ...field, defaultValue: undefined })).toEqual([]);
    expect(selectDefault({ ...field, defaultValue: 'password' })).toEqual(['password']);
    expect(selectDefault({ name: 'kind', label: 'Kind', type: 'select', defaultValue: 'b' })).toBe(
      'b',
    );
    // Untouched, the preselected options are submitted and the restriction survives the save.
    expect(
      bodyFrom(
        form([
          ['allowedMethods', 'federated'],
          ['allowedMethods', 'passkey'],
        ]),
        [field],
      ),
    ).toEqual({ authPolicy: { allowedMethods: ['federated', 'passkey'] } });
  });

  it('sends null for empty fields marked emptyAsNull and leaves other empty fields out', () => {
    const fields: FieldSpec[] = [
      { name: 'slug', label: 'Alias', emptyAsNull: true },
      { name: 'name', label: 'Name' },
      { name: 'expiresAt', label: 'Ends', type: 'datetime', emptyAsNull: true },
      { name: 'tags', label: 'Tags', type: 'list', emptyAsNull: true },
      { name: 'limit', label: 'Limit', type: 'number', emptyAsNull: true },
      { name: 'roles', label: 'Roles', type: 'multiselect', emptyAsNull: true },
    ];
    const empty = form([
      ['slug', ''],
      ['name', ''],
      ['expiresAt', ''],
      ['tags', ' '],
      ['limit', ''],
    ]);
    expect(bodyFrom(empty, fields)).toEqual({
      slug: null,
      expiresAt: null,
      tags: null,
      limit: null,
      roles: null,
    });
    expect(bodyFrom(form([['slug', 'acme']]), fields.slice(0, 1))).toEqual({ slug: 'acme' });
    expect(
      textDefault({ name: 'tags', label: 'Tags', type: 'list', defaultValue: ['a', 'b'] }),
    ).toBe('a, b');
  });

  it('formats datetime defaults in the browser and sends an untouched value back unchanged', () => {
    // Seconds and milliseconds that a datetime-local input cannot show.
    const expiresAt = Date.UTC(2026, 9, 1, 0, 0, 37, 123);
    const field: FieldSpec = {
      name: 'expiresAt',
      label: 'Deactivate on',
      type: 'datetime',
      defaultValue: expiresAt,
    };
    // Rendered empty on the server; the browser fills it in its own zone after mount.
    expect(textDefault(field)).toBe('');
    const shown = dateTimeLocalValue(expiresAt);
    expect(shown).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/);
    // Saving an untouched form (for another field) never moves the instant, not even by the hidden seconds.
    for (let save = 0; save < 5; save += 1)
      expect(bodyFrom(form([['expiresAt', shown]]), [field])).toEqual({ expiresAt });
    // A changed value is read in the zone it was shown in.
    const changed = new Date(expiresAt + 86_400_000);
    changed.setSeconds(0, 0);
    expect(bodyFrom(form([['expiresAt', dateTimeLocalValue(changed.getTime())]]), [field])).toEqual(
      { expiresAt: changed.getTime() },
    );
    expect(() => bodyFrom(form([['expiresAt', 'not a date']]), [field])).toThrow(
      'Deactivate on must be a date and time',
    );
  });

  it('keeps a formatted datetime a faithful round trip in zones east and west of UTC', () => {
    const zone = process.env.TZ;
    try {
      for (const tz of ['Europe/Berlin', 'America/New_York', 'Asia/Kolkata']) {
        process.env.TZ = tz;
        const epoch = Date.UTC(2026, 9, 1, 0, 0, 0);
        expect(new Date(dateTimeLocalValue(epoch)).getTime()).toBe(epoch);
      }
    } finally {
      if (zone === undefined) delete process.env.TZ;
      else process.env.TZ = zone;
    }
  });
});

describe('console MFA step', () => {
  it('copies authenticatorEnrolled and makes a passkey-only step passkey-first', () => {
    const state = challengeStateFrom({
      challenge: 'c1',
      enrollmentRequired: false,
      passkeyAvailable: true,
      authenticatorEnrolled: false,
    });
    expect(state).toMatchObject({ authenticatorEnrolled: false, passkeyAvailable: true });
    const view = mfaStepView(state, { emailCodeSent: false, useRecovery: true });
    expect(view).toMatchObject({
      passkeyPrimary: true,
      codeField: false,
      recoveryToggle: false,
      recovering: false,
      enrolling: false,
    });
  });

  it('keeps the code field for authenticators and for emailed codes', () => {
    const totp = challengeStateFrom({
      challenge: 'c2',
      enrollmentRequired: false,
      passkeyAvailable: true,
      authenticatorEnrolled: true,
    });
    expect(mfaStepView(totp, { emailCodeSent: false, useRecovery: false })).toMatchObject({
      passkeyPrimary: false,
      codeField: true,
      codeLabel: 'Authenticator code',
      recoveryToggle: true,
    });
    expect(mfaStepView(totp, { emailCodeSent: false, useRecovery: true })).toMatchObject({
      codeLabel: 'Recovery code',
      recovering: true,
    });
    // Older servers do not report authenticatorEnrolled: behave as before.
    const legacy = challengeStateFrom({ challenge: 'c3', enrollmentRequired: false });
    expect(legacy).not.toHaveProperty('authenticatorEnrolled');
    expect(mfaStepView(legacy, { emailCodeSent: false, useRecovery: false }).codeField).toBe(true);

    const email = challengeStateFrom(
      { challenge: 'c4', enrollmentRequired: true, emailCodeAvailable: true },
      { secret: 'S', uri: 'otpauth://totp/x' },
    );
    expect(mfaStepView(email, { emailCodeSent: false, useRecovery: false })).toMatchObject({
      enrolling: true,
      codeField: true,
      recoveryToggle: false,
    });
    // After "Email me a code instead" the step verifies the emailed code, never a recovery code.
    expect(mfaStepView(email, { emailCodeSent: true, useRecovery: true })).toMatchObject({
      enrolling: false,
      codeLabel: 'Emailed code',
      recovering: false,
    });
    expect(challengeLapsed('INVALID_CHALLENGE')).toBe(true);
    expect(challengeLapsed('INVALID_MFA')).toBe(false);
  });
});

describe('console passkey autofill', () => {
  const base = { refreshing: false, elapsedMs: 60_000, quickFailures: 0 };

  it('shows server refusals and re-arms with a fresh challenge', () => {
    expect(autofillFailure({ ...base, name: 'Error', stage: 'server' })).toEqual({
      rearm: true,
      delayMs: AUTOFILL_RETRY_MS,
      show: true,
      quickFailures: 0,
    });
  });

  it('swallows dismissals and aborts, and never fights another ceremony', () => {
    expect(autofillFailure({ ...base, name: 'NotAllowedError', stage: 'browser' })).toMatchObject({
      rearm: true,
      show: false,
    });
    // Our own refresh before the challenge expires: arm again at once.
    expect(
      autofillFailure({ ...base, name: 'AbortError', stage: 'browser', refreshing: true }),
    ).toMatchObject({ rearm: true, delayMs: 0, show: false });
    // The passkey button or the MFA step took over: do not abort it by re-arming.
    expect(autofillFailure({ ...base, name: 'AbortError', stage: 'browser' })).toMatchObject({
      rearm: false,
      show: false,
    });
    expect(autofillFailure({ ...base, name: 'SecurityError', stage: 'browser' })).toMatchObject({
      rearm: true,
      show: true,
    });
  });

  it('stops re-arming when the browser refuses at once, so rate limits are not drained', () => {
    let quickFailures = 0;
    const outcomes = [];
    for (let attempt = 0; attempt < AUTOFILL_MAX_QUICK_FAILURES; attempt += 1) {
      const outcome = autofillFailure({
        name: 'NotAllowedError',
        stage: 'browser',
        refreshing: false,
        elapsedMs: 10,
        quickFailures,
      });
      quickFailures = outcome.quickFailures;
      outcomes.push(outcome.rearm);
    }
    expect(outcomes).toEqual([true, true, false]);
  });
});

describe('console forms in the browser', () => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  const roots: Root[] = [];
  const persistent = (value: '0' | '1') => ({ headers: { 'x-better-iam-persistent': value } });
  const h = createElement;

  beforeEach(() => {
    fake.client.auth = {};
    fake.client.$request.mockReset();
    fake.router.push.mockReset();
    fake.router.refresh.mockReset();
    fake.webauthn.startAuthentication.mockReset();
    fake.webauthn.browserSupportsWebAuthn.mockReturnValue(false);
    fake.webauthn.browserSupportsWebAuthnAutofill.mockResolvedValue(false);
  });
  afterEach(async () => {
    for (const root of roots.splice(0)) await act(async () => root.unmount());
    document.body.innerHTML = '';
    document.cookie = `${REMEMBER_COOKIE}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  });

  async function render(element: ReactElement): Promise<HTMLElement> {
    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    roots.push(root);
    await act(async () => root.render(element));
    return container;
  }
  async function type(input: HTMLInputElement, value: string) {
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
  }
  const text = (container: HTMLElement) => container.textContent ?? '';
  const buttonNamed = (container: HTMLElement, name: string) =>
    [...container.querySelectorAll('button')].find((button) => button.textContent === name)!;
  // Handlers await the (scripted) client; let those promises settle inside act.
  const settle = () => new Promise((resolve) => setTimeout(resolve, 0));
  async function submit(element: HTMLFormElement) {
    await act(async () => {
      element.requestSubmit();
      await settle();
    });
  }
  async function click(button: HTMLButtonElement) {
    await act(async () => {
      button.click();
      await settle();
    });
  }

  it('re-authenticates with an emailed code, keeping the browser-session choice, without resubmitting the outer form', async () => {
    const { Reauth } = await import('../apps/console/src/components/api-form.js');
    setRememberBrowser(false);
    const expiresAt = new Date(2026, 8, 22, 10, 5).getTime();
    fake.client.auth.reauthenticate = vi.fn(async () => ({
      mfaRequired: true,
      challenge: 'chal_1',
      enrollmentRequired: false,
      emailCodeAvailable: true,
    }));
    fake.client.auth.requestMfaCode = vi.fn(async () => ({ success: true, expiresAt }));
    fake.client.auth.verifyMfa = vi.fn(async () => ({ token: 't', session: {} }));
    const onDone = vi.fn();
    const outer = vi.fn((event: Event) => event.preventDefault());
    const container = await render(
      h('form', { onSubmit: outer }, h(Reauth, { tenantId: 'ten_1', onDone, onCancel: () => {} })),
    );
    await type(container.querySelector('input[type="password"]')!, 'correct horse battery');
    await submit(container.querySelector('form form')!);
    expect(fake.client.auth.reauthenticate).toHaveBeenCalledWith(
      { password: 'correct horse battery' },
      persistent('0'),
    );
    // Before, the only option was an authenticator code, which MFA_NOT_ENROLLED always refused.
    await click(buttonNamed(container, 'Email me a code instead'));
    expect(fake.client.auth.requestMfaCode).toHaveBeenCalledWith({
      tenantId: 'ten_1',
      challenge: 'chal_1',
    });
    const shown = new Date(expiresAt).toLocaleTimeString([], {
      hour: 'numeric',
      minute: '2-digit',
    });
    expect(text(container)).toContain(`before ${shown}`);
    expect(text(container)).not.toContain('ten minutes');
    expect(text(container)).toContain('Emailed code');
    await type(container.querySelector('input[autocomplete="one-time-code"]')!, '123456');
    await submit(container.querySelector('form form')!);
    expect(fake.client.auth.verifyMfa).toHaveBeenCalledWith(
      { tenantId: 'ten_1', challenge: 'chal_1', code: '123456', rememberDevice: false },
      persistent('0'),
    );
    expect(onDone).toHaveBeenCalledTimes(1);
    expect(outer).not.toHaveBeenCalled();
  });

  it('makes the passkey the main action when it is the only factor, and offers a restart once the step lapses', async () => {
    const { MfaChallenge } = await import('../apps/console/src/components/auth-forms.js');
    fake.client.auth.beginPasskeyMfa = vi.fn(async () => ({ challengeId: 'pk_1', options: {} }));
    fake.client.auth.finishPasskeyMfa = vi.fn(async () => {
      throw new fake.FakeIamError('INVALID_CHALLENGE', 'Challenge is invalid or expired');
    });
    fake.webauthn.startAuthentication.mockResolvedValue({ id: 'cred' });
    const onRestart = vi.fn();
    const container = await render(
      h(MfaChallenge, {
        tenantId: 'ten_1',
        state: challengeStateFrom({
          challenge: 'chal_2',
          enrollmentRequired: false,
          passkeyAvailable: true,
          authenticatorEnrolled: false,
        }),
        onDone: () => {},
        onRestart,
      }),
    );
    expect(container.querySelector('input[autocomplete="one-time-code"]')).toBeNull();
    expect(text(container)).not.toContain('Use a recovery code');
    await submit(container.querySelector('form')!);
    expect(fake.client.auth.finishPasskeyMfa).toHaveBeenCalledWith(
      { tenantId: 'ten_1', challengeId: 'pk_1', response: { id: 'cred' }, rememberDevice: false },
      persistent('1'),
    );
    expect(text(container)).toContain('This sign-in attempt has expired.');
    await click(buttonNamed(container, 'Start again'));
    expect(onRestart).toHaveBeenCalled();
  });

  it("records the sign-in page's choice, starting from the deployment default, for every later call", async () => {
    const { KeepSignedIn } = await import('../apps/console/src/components/auth-forms.js');
    // persistentCookies: false renders the box unticked; the MFA step and passkeys then ask for a browser session.
    const container = await render(h(KeepSignedIn, { initial: false }));
    const box = container.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
    expect(box.checked).toBe(false);
    expect(sessionOptions()).toEqual(persistent('0'));
    await act(async () => box.click());
    expect(box.checked).toBe(true);
    expect(sessionOptions()).toEqual(persistent('1'));
    // A later visit shows the recorded choice, not the default.
    const again = await render(h(KeepSignedIn, { initial: false }));
    expect(again.querySelector<HTMLInputElement>('input[type="checkbox"]')!.checked).toBe(true);
  });

  it('stays on the page when sign-out fails for any reason but an ended session', async () => {
    const { SignOutButton } = await import('../apps/console/src/components/auth-forms.js');
    fake.client.auth.signOut = vi.fn(async () => {
      throw new fake.FakeIamError('INTERNAL_ERROR', 'Internal server error');
    });
    const container = await render(h(SignOutButton, { next: '/cloud' }));
    await click(buttonNamed(container, 'Sign out'));
    expect(fake.router.push).not.toHaveBeenCalled();
    expect(text(container)).toContain('Sign-out failed');
    fake.client.auth.signOut = vi.fn(async () => {
      throw new fake.FakeIamError('UNAUTHENTICATED', 'Invalid or expired credentials');
    });
    await click(buttonNamed(container, 'Sign out'));
    expect(fake.router.push).toHaveBeenCalledWith('/cloud');
  });

  it('confirms a password reset instead of promising a sign-in', async () => {
    const { ResetPasswordForm } = await import('../apps/console/src/components/auth-forms.js');
    fake.client.auth.resetPassword = vi.fn(async () => ({ success: true }));
    const container = await render(
      h(ResetPasswordForm, { tenantId: 'ten_1', token: 'tok', next: '/cloud/login?org=acme' }),
    );
    expect(text(container)).toContain('Set new password');
    expect(text(container)).not.toContain('and sign in');
    for (const input of container.querySelectorAll<HTMLInputElement>('input'))
      await type(input, 'a brand new password');
    await submit(container.querySelector('form')!);
    expect(fake.router.push).not.toHaveBeenCalled();
    expect(text(container)).toContain('Your password is changed');
    await click(buttonNamed(container, 'Sign in'));
    expect(fake.router.push).toHaveBeenCalledWith('/cloud/login?org=acme');
  });

  it('pre-fills datetime and multiselect defaults so an untouched save keeps them exactly', async () => {
    const { ApiForm } = await import('../apps/console/src/components/api-form.js');
    fake.client.$request.mockResolvedValue({});
    const expiresAt = Date.UTC(2026, 9, 1, 0, 0, 37, 123);
    const container = await render(
      h(ApiForm, {
        path: 'identities/update',
        fields: [
          { name: 'expiresAt', label: 'Deactivate on', type: 'datetime', defaultValue: expiresAt },
          {
            name: 'allowedMethods',
            label: 'Allowed methods',
            type: 'multiselect',
            group: 'authPolicy',
            defaultValue: ['federated'],
            options: [
              { value: 'password', label: 'password' },
              { value: 'federated', label: 'federated' },
            ],
          },
        ],
      }),
    );
    const input = container.querySelector<HTMLInputElement>('input[type="datetime-local"]')!;
    expect(input.value).toBe(dateTimeLocalValue(expiresAt));
    await submit(container.querySelector('form')!);
    expect(fake.client.$request).toHaveBeenCalledWith('identities/update', {
      expiresAt,
      authPolicy: { allowedMethods: ['federated'] },
    });
  });

  it('shows a refused autofill passkey and arms autofill again with a fresh challenge', async () => {
    const { PasskeySignIn } = await import('../apps/console/src/components/passkeys.js');
    fake.webauthn.browserSupportsWebAuthn.mockReturnValue(true);
    fake.webauthn.browserSupportsWebAuthnAutofill.mockResolvedValue(true);
    let begun = 0;
    fake.client.auth.beginPasskeyAuthentication = vi.fn(async () => ({
      challengeId: `pk_${++begun}`,
      options: {},
    }));
    fake.webauthn.startAuthentication
      .mockResolvedValueOnce({ id: 'other-org-passkey' })
      .mockImplementation(() => new Promise(() => {}));
    fake.client.auth.finishPasskeyAuthentication = vi.fn(async () => {
      throw new fake.FakeIamError(
        'INVALID_PASSKEY',
        'Passkey is not registered for this organization',
      );
    });
    setRememberBrowser(false);
    const container = await render(h(PasskeySignIn, { tenantId: 'ten_1', next: '/cloud/acme' }));
    await act(async () => new Promise((resolve) => setTimeout(resolve, 20)));
    expect(fake.client.auth.finishPasskeyAuthentication).toHaveBeenCalledWith(
      { tenantId: 'ten_1', challengeId: 'pk_1', response: { id: 'other-org-passkey' } },
      persistent('0'),
    );
    expect(text(container)).toContain('Passkey is not registered for this organization');
    await act(async () => new Promise((resolve) => setTimeout(resolve, AUTOFILL_RETRY_MS + 200)));
    expect(fake.client.auth.beginPasskeyAuthentication).toHaveBeenCalledTimes(2);
    expect(fake.webauthn.startAuthentication).toHaveBeenLastCalledWith({
      optionsJSON: {},
      useBrowserAutofill: true,
    });
    expect(fake.router.push).not.toHaveBeenCalled();
  });
});
