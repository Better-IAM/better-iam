// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { act, type ReactElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { renderToString } from 'react-dom/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthFormState, AuthMfaChallenge } from '../packages/next/src/auth-types.js';
import {
  InvitationFormView,
  PasswordResetFormView,
  PasswordResetRequestFormView,
  ReauthenticateFormView,
  SignInForm,
  SignInFormView,
  SignUpFormView,
} from '../packages/next/src/forms.js';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// Browsers put only the submitting button in a form's data; happy-dom 17 adds every named button.
vi.stubGlobal(
  'FormData',
  class extends FormData {
    constructor(form?: HTMLFormElement, submitter?: HTMLElement | null) {
      super(form);
      if (!form) return;
      for (const button of form.querySelectorAll('button'))
        if (button.name) this.delete(button.name);
      if (submitter instanceof HTMLButtonElement && submitter.name)
        this.append(submitter.name, submitter.value);
    }
  },
);

const idle = { formAction: () => {}, pending: false };
const challenge: AuthMfaChallenge = {
  tenantId: 'tenant_1',
  challenge: 'challenge_1',
  enrollmentRequired: false,
  emailCodeAvailable: true,
  passkeyAvailable: false,
};
const enrollment: AuthMfaChallenge = {
  ...challenge,
  enrollmentRequired: true,
  emailCodeAvailable: false,
  enrollment: {
    secret: 'JBSWY3DPEHPK3PXP',
    uri: 'otpauth://totp/Acme:ada?secret=JBSWY3DPEHPK3PXP',
  },
};

/** `next` values a link or redirect would send to another origin, including ones that only do so once normalized. */
const unsafeNext = [
  '//evil.example',
  '/\\evil.example',
  'https://evil.example/phish',
  '/.//evil.example/phish',
  '/..//evil.example',
  '/a/..//evil.example',
  '/%2e//evil.example',
  '/%2E%2E//evil.example',
];

const roots: Root[] = [];
afterEach(async () => {
  for (const root of roots.splice(0)) await act(async () => root.unmount());
  document.body.innerHTML = '';
});

async function render(element: ReactElement): Promise<HTMLFormElement> {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  roots.push(root);
  await act(async () => root.render(element));
  return container.querySelector('form')!;
}

/** The visible input of a `data-field` wrapper. */
function input(form: HTMLFormElement, name: string): HTMLInputElement {
  const found = form.querySelector<HTMLInputElement>(
    `[data-field="${name}"] input:not([type="hidden"])`,
  );
  if (!found) throw new Error(`No ${name} field`);
  return found;
}
function labelOf(form: HTMLFormElement, field: HTMLInputElement): string | undefined {
  return Array.from(form.querySelectorAll('label')).find((label) => label.htmlFor === field.id)
    ?.textContent;
}
function fieldNames(form: HTMLFormElement): string[] {
  return Array.from(form.querySelectorAll('[data-field]')).map(
    (field) => field.getAttribute('data-field')!,
  );
}
function hidden(form: HTMLFormElement): [string, string][] {
  return Array.from(form.querySelectorAll<HTMLInputElement>('input[type="hidden"]')).map(
    (field) => [field.name, field.value],
  );
}
function buttons(form: HTMLFormElement) {
  return Array.from(form.querySelectorAll('button')).map((button) => ({
    name: button.name,
    intent: button.value,
    text: button.textContent,
    skipValidation: button.formNoValidate,
    disabled: button.disabled,
  }));
}
function button(form: HTMLFormElement, intent: string): HTMLButtonElement {
  const found = Array.from(form.querySelectorAll('button')).find(
    (candidate) => candidate.value === intent,
  );
  if (!found) throw new Error(`No ${intent} button`);
  return found;
}
function status(form: HTMLFormElement): string {
  return form.querySelector('[role="status"]')?.textContent ?? '';
}
/** Password and code inputs never carry a value into the markup. */
function expectNoSecrets(form: HTMLFormElement) {
  for (const field of form.querySelectorAll<HTMLInputElement>(
    'input[type="password"], input[name="code"], input[name="confirmPassword"]',
  )) {
    expect(field.value).toBe('');
    expect(field.hasAttribute('value')).toBe(false);
  }
}
/** `secret` is in no input's current value (which markup does not show) and nowhere in the markup. */
function expectNowhere(form: HTMLFormElement, secret: string) {
  for (const field of form.querySelectorAll('input')) {
    expect(field.value).not.toContain(secret);
    expect(field.getAttribute('value') ?? '').not.toContain(secret);
  }
  expect(form.innerHTML).not.toContain(secret);
}

describe('SignInFormView', () => {
  it('renders the credentials step with bound labels, autocomplete hints, and the password intent', async () => {
    const form = await render(<SignInFormView {...idle} state={null} className="login" />);
    expect(form.dataset.betterIam).toBe('sign-in');
    expect(form.dataset.step).toBe('credentials');
    expect(form.className).toBe('login');
    expect(fieldNames(form)).toEqual(['org', 'email', 'password']);
    const org = input(form, 'org');
    const email = input(form, 'email');
    const password = input(form, 'password');
    expect(labelOf(form, org)).toBe('Organization');
    expect(labelOf(form, email)).toBe('Email');
    expect(labelOf(form, password)).toBe('Password');
    expect(new Set([org.id, email.id, password.id]).size).toBe(3);
    expect(email.type).toBe('email');
    expect(email.getAttribute('autocomplete')).toBe('username');
    expect(password.type).toBe('password');
    expect(password.getAttribute('autocomplete')).toBe('current-password');
    expect([org.required, email.required, password.required]).toEqual([true, true, true]);
    expect(document.activeElement).toBe(org);
    expect(buttons(form)).toEqual([
      {
        name: 'intent',
        intent: 'password',
        text: 'Sign in',
        skipValidation: false,
        disabled: false,
      },
    ]);
    expect(hidden(form)).toEqual([]);
    expect(form.querySelector('[role="alert"]')).toBeNull();
    expect(status(form)).toBe('');
  });

  it('hides the organization for a known tenant and offers keep-signed-in and an emailed code', async () => {
    const form = await render(
      <SignInFormView
        {...idle}
        state={null}
        tenantId="tenant_1"
        email="ada@example.com"
        next="/dashboard"
        keepSignedIn
        passwordless
      />,
    );
    expect(fieldNames(form)).toEqual(['email', 'password', 'keepSignedIn']);
    expect(input(form, 'email').value).toBe('ada@example.com');
    expect(document.activeElement).toBe(input(form, 'email'));
    const keep = form.querySelectorAll<HTMLInputElement>('[data-field="keepSignedIn"] input');
    expect(Array.from(keep).map((field) => [field.type, field.name, field.value])).toEqual([
      ['hidden', 'keepSignedIn', '0'],
      ['checkbox', 'keepSignedIn', '1'],
    ]);
    expect(keep[1]!.checked).toBe(false);
    expect(labelOf(form, keep[1]!)).toBe('Keep me signed in');
    expect(hidden(form)).toEqual([
      ['tenantId', 'tenant_1'],
      ['keepSignedIn', '0'],
      ['next', '/dashboard'],
    ]);
    expect(buttons(form).map(({ intent, skipValidation }) => [intent, skipValidation])).toEqual([
      ['password', false],
      ['send-code', true],
    ]);
    const echoed = await render(
      <SignInFormView
        {...idle}
        state={{ step: 'credentials', keepSignedIn: true }}
        tenantId="tenant_1"
        keepSignedIn
      />,
    );
    expect(input(echoed, 'keepSignedIn').checked).toBe(true);
  });

  it('keeps a given organization as a hidden field unless showOrganization is set', async () => {
    const hiddenOrg = await render(<SignInFormView {...idle} state={null} org="acme" />);
    expect(fieldNames(hiddenOrg)).toEqual(['email', 'password']);
    expect(hidden(hiddenOrg)).toEqual([['org', 'acme']]);
    const shown = await render(
      <SignInFormView {...idle} state={null} org="acme" showOrganization />,
    );
    expect(input(shown, 'org').value).toBe('acme');
    expect(hidden(shown)).toEqual([]);
  });

  it('announces an error on its field and echoes only non-secret values', async () => {
    const state: AuthFormState = {
      step: 'credentials',
      error: {
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password',
        field: 'password',
      },
      values: { email: 'ada@example.com', org: 'acme' },
    };
    const form = await render(<SignInFormView {...idle} state={state} />);
    const alert = form.querySelector('[role="alert"]')!;
    expect(alert.textContent).toBe('Invalid email or password');
    const password = input(form, 'password');
    expect(password.getAttribute('aria-invalid')).toBe('true');
    expect(password.getAttribute('aria-describedby')).toBe(alert.id);
    expect(input(form, 'email').hasAttribute('aria-invalid')).toBe(false);
    expect(input(form, 'email').value).toBe('ada@example.com');
    expect(input(form, 'org').value).toBe('acme');
    expectNoSecrets(form);
  });

  it('renders the emailed sign-in code step with the carried email and organization', async () => {
    const state: AuthFormState = {
      step: 'code-sent',
      values: { email: 'ada@example.com', org: 'acme' },
      notice: 'We sent a code to ada@example.com',
    };
    const form = await render(<SignInFormView {...idle} state={state} next="/home" />);
    expect(form.dataset.step).toBe('code-sent');
    expect(status(form)).toBe('We sent a code to ada@example.com');
    expect(fieldNames(form)).toEqual(['code']);
    const code = input(form, 'code');
    expect(labelOf(form, code)).toBe('Sign-in code');
    expect(code.getAttribute('inputmode')).toBe('numeric');
    expect(code.getAttribute('autocomplete')).toBe('one-time-code');
    expect(document.activeElement).toBe(code);
    expect(hidden(form)).toEqual([
      ['org', 'acme'],
      ['email', 'ada@example.com'],
      ['next', '/home'],
    ]);
    expect(buttons(form).map(({ intent, skipValidation }) => [intent, skipValidation])).toEqual([
      ['code', false],
      ['send-code', true],
      ['cancel', true],
    ]);
    expectNoSecrets(form);
    const fallback = await render(<SignInFormView {...idle} state={{ step: 'code-sent' }} />);
    expect(status(fallback)).toBe('Check your email for a sign-in code.');
  });

  it('renders the second-factor step with its challenge, remember-device, and every alternative', async () => {
    const state: AuthFormState = {
      step: 'mfa',
      mfa: challenge,
      values: { email: 'ada@example.com' },
      next: '/dashboard',
      keepSignedIn: true,
      error: { code: 'INVALID_MFA', message: 'Invalid code', field: 'code' },
    };
    const form = await render(<SignInFormView {...idle} state={state} keepSignedIn />);
    expect(form.dataset.step).toBe('mfa');
    expect(fieldNames(form)).toEqual(['code', 'rememberDevice']);
    const code = input(form, 'code');
    expect(labelOf(form, code)).toBe('Verification code');
    // The same field takes hexadecimal recovery codes, so it keeps a full keyboard.
    expect(code.getAttribute('inputmode')).toBe('text');
    expect(code.getAttribute('autocapitalize')).toBe('none');
    expect(code.getAttribute('autocomplete')).toBe('one-time-code');
    expect(code.required).toBe(true);
    expect(code.getAttribute('aria-invalid')).toBe('true');
    const describedBy = code.getAttribute('aria-describedby')!.split(' ');
    expect(describedBy).toContain(form.querySelector('[role="alert"]')!.id);
    expect(describedBy).toHaveLength(2);
    expect(document.getElementById(describedBy[1]!)!.textContent).toContain('recovery code');
    expect(document.activeElement).toBe(code);
    const remember = input(form, 'rememberDevice');
    expect([remember.type, remember.name, remember.value]).toEqual([
      'checkbox',
      'rememberDevice',
      '1',
    ]);
    expect(labelOf(form, remember)).toBe('Remember this device');
    expect(hidden(form)).toEqual([
      ['email', 'ada@example.com'],
      ['next', '/dashboard'],
      ['keepSignedIn', '1'],
      ['tenantId', 'tenant_1'],
      ['challenge', 'challenge_1'],
      ['emailCodeAvailable', '1'],
    ]);
    expect(buttons(form)).toEqual([
      { name: 'intent', intent: 'mfa', text: 'Verify', skipValidation: false, disabled: false },
      {
        name: 'intent',
        intent: 'email-code',
        text: 'Email me a code',
        skipValidation: true,
        disabled: false,
      },
      {
        name: 'intent',
        intent: 'recovery',
        text: 'Use a recovery code',
        skipValidation: false,
        disabled: false,
      },
      { name: 'intent', intent: 'cancel', text: 'Cancel', skipValidation: true, disabled: false },
    ]);
    expectNoSecrets(form);
  });

  it('omits the emailed code when unavailable and disables every button while pending', async () => {
    const form = await render(
      <SignInFormView
        formAction={() => {}}
        pending
        state={{ step: 'mfa', mfa: { ...challenge, emailCodeAvailable: false } }}
        keepSignedIn
      />,
    );
    expect(form.getAttribute('aria-busy')).toBe('true');
    expect(buttons(form).map(({ intent }) => intent)).toEqual(['mfa', 'recovery', 'cancel']);
    expect(buttons(form).every(({ disabled }) => disabled)).toBe(true);
    expect(hidden(form).map(([name]) => name)).toEqual(['tenantId', 'challenge']);
  });

  it('renders enrollment with the setup key and otpauth link', async () => {
    const form = await render(
      <SignInFormView {...idle} state={{ step: 'enroll', mfa: enrollment }} />,
    );
    expect(form.dataset.step).toBe('enroll');
    expect(form.textContent).toContain('JBSWY3DPEHPK3PXP');
    expect(form.querySelector('a')!.getAttribute('href')).toBe(enrollment.enrollment!.uri);
    expect(fieldNames(form)).toEqual(['code']);
    expect(input(form, 'code').getAttribute('autocomplete')).toBe('one-time-code');
    expect(input(form, 'code').getAttribute('inputmode')).toBe('numeric');
    expect(buttons(form).map(({ intent }) => intent)).toEqual(['enroll', 'cancel']);
    expect(hidden(form)).toEqual([
      ['tenantId', 'tenant_1'],
      ['challenge', 'challenge_1'],
      ['enrollmentRequired', '1'],
      ['secret', 'JBSWY3DPEHPK3PXP'],
      ['uri', enrollment.enrollment!.uri],
    ]);
    const withEmail = await render(
      <SignInFormView
        {...idle}
        state={{
          step: 'enroll',
          mfa: { ...enrollment, emailCodeAvailable: true, passkeyAvailable: true },
        }}
      />,
    );
    expect(buttons(withEmail).map(({ intent }) => intent)).toEqual([
      'enroll',
      'email-code',
      'cancel',
    ]);
    expect(hidden(withEmail).map(([name]) => name)).toEqual([
      'tenantId',
      'challenge',
      'enrollmentRequired',
      'emailCodeAvailable',
      'passkeyAvailable',
      'secret',
      'uri',
    ]);
  });

  it('hides the recovery code after an emailed code was sent during enrollment', async () => {
    const form = await render(
      <SignInFormView
        {...idle}
        state={{
          step: 'mfa',
          mfa: { ...enrollment, emailCodeAvailable: true },
          notice: 'We emailed you a sign-in code.',
        }}
      />,
    );
    expect(form.dataset.step).toBe('mfa');
    expect(status(form)).toBe('We emailed you a sign-in code.');
    expect(form.textContent).not.toContain('JBSWY3DPEHPK3PXP');
    expect(buttons(form).map(({ intent }) => intent)).toEqual(['mfa', 'email-code', 'cancel']);
    expect(input(form, 'code').getAttribute('inputmode')).toBe('numeric');
    expect(hidden(form)).toContainEqual(['secret', 'JBSWY3DPEHPK3PXP']);
  });

  it('shows recovery codes once and continues to a safe path', async () => {
    const codes = ['a1b2c3d4e5f6a1b2c3d4e5f6', 'f6e5d4c3b2a1f6e5d4c3b2a1'];
    const form = await render(
      <SignInFormView
        {...idle}
        state={{ step: 'done', recoveryCodes: codes, next: '/projects' }}
      />,
    );
    expect(form.dataset.step).toBe('done');
    expect(
      Array.from(form.querySelectorAll('[data-recovery-codes] li')).map((li) => li.textContent),
    ).toEqual(codes);
    expect(form.textContent).toContain('will not be shown again');
    expect(form.querySelector('a')!.getAttribute('href')).toBe('/projects');
    const unsafe = await render(
      <SignInFormView
        {...idle}
        state={{ step: 'done', next: '//evil.example' }}
        next="/fallback"
      />,
    );
    expect(unsafe.querySelector('a')!.getAttribute('href')).toBe('/');
    expect(unsafe.querySelector('[data-recovery-codes]')).toBeNull();
    const fromProp = await render(
      <SignInFormView {...idle} state={{ step: 'done' }} next="/home" />,
    );
    expect(fromProp.querySelector('a')!.getAttribute('href')).toBe('/home');
  });

  it('never links to or carries a next that resolves to another origin', async () => {
    for (const next of unsafeNext) {
      const credentials = await render(<SignInFormView {...idle} state={null} next={next} />);
      expect(hidden(credentials), next).toEqual([]);
      const codeSent = await render(
        <SignInFormView {...idle} state={{ step: 'code-sent', next }} next={next} />,
      );
      expect(
        hidden(codeSent).map(([name]) => name),
        next,
      ).not.toContain('next');
      const mfa = await render(
        <SignInFormView {...idle} state={{ step: 'mfa', mfa: challenge, next }} next={next} />,
      );
      expect(
        hidden(mfa).map(([name]) => name),
        next,
      ).not.toContain('next');
      const done = await render(<SignInFormView {...idle} state={{ step: 'done', next }} />);
      expect(done.querySelector('a')!.getAttribute('href'), next).toBe('/');
    }
    const normalized = await render(
      <SignInFormView {...idle} state={{ step: 'done', next: '/a/../b/./c?x=1#y' }} />,
    );
    expect(normalized.querySelector('a')!.getAttribute('href')).toBe('/b/c?x=1#y');
  });

  it('falls back to the credentials step when a second-factor state has no challenge', async () => {
    const form = await render(<SignInFormView {...idle} state={{ step: 'mfa' }} tenantId="t" />);
    expect(form.dataset.step).toBe('credentials');
    expect(fieldNames(form)).toEqual(['email', 'password']);
  });

  it('replaces default strings with labels', async () => {
    const form = await render(
      <SignInFormView
        {...idle}
        state={{ step: 'mfa', mfa: challenge }}
        labels={{ mfaCode: 'Code', verify: 'Weiter', recovery: 'Wiederherstellungscode' }}
      />,
    );
    expect(labelOf(form, input(form, 'code'))).toBe('Code');
    expect(buttons(form).map(({ text }) => text)).toEqual([
      'Weiter',
      'Email me a code',
      'Wiederherstellungscode',
      'Cancel',
    ]);
  });
});

describe('ReauthenticateFormView', () => {
  it('asks for the password, then the same second-factor step', async () => {
    const form = await render(<ReauthenticateFormView {...idle} state={null} next="/settings" />);
    expect(form.dataset.betterIam).toBe('reauthenticate');
    expect(fieldNames(form)).toEqual(['password']);
    expect(input(form, 'password').getAttribute('autocomplete')).toBe('current-password');
    expect(document.activeElement).toBe(input(form, 'password'));
    expect(hidden(form)).toEqual([
      ['next', '/settings'],
      ['keepSignedIn', '0'],
    ]);
    expect(buttons(form).map(({ intent, text }) => [intent, text])).toEqual([
      ['password', 'Continue'],
    ]);

    const mfa = await render(
      <ReauthenticateFormView {...idle} state={{ step: 'mfa', mfa: challenge }} next="/settings" />,
    );
    expect(mfa.dataset.step).toBe('mfa');
    expect(fieldNames(mfa)).toEqual(['code', 'rememberDevice']);
    expect(hidden(mfa)).toEqual([
      ['next', '/settings'],
      ['keepSignedIn', '0'],
      ['tenantId', 'tenant_1'],
      ['challenge', 'challenge_1'],
      ['emailCodeAvailable', '1'],
    ]);
    expect(buttons(mfa).map(({ intent }) => intent)).toEqual([
      'mfa',
      'email-code',
      'recovery',
      'cancel',
    ]);
    expectNoSecrets(mfa);
  });

  it('submits the keep-signed-in choice on every step, so a step-up never widens the session cookie', async () => {
    const keep = (form: HTMLFormElement) =>
      hidden(form).filter(([name]) => name === 'keepSignedIn');
    for (const [step, mfa] of [
      ['credentials', undefined],
      ['mfa', challenge],
      ['enroll', enrollment],
    ] as const) {
      const dropped = await render(<ReauthenticateFormView {...idle} state={{ step, mfa }} />);
      expect(dropped.dataset.step).toBe(step);
      expect(keep(dropped), step).toEqual([['keepSignedIn', '0']]);
      const kept = await render(
        <ReauthenticateFormView {...idle} state={{ step, mfa }} keepSignedIn />,
      );
      expect(keep(kept), step).toEqual([['keepSignedIn', '1']]);
      const echoed = await render(
        <ReauthenticateFormView {...idle} state={{ step, mfa, keepSignedIn: true }} />,
      );
      expect(keep(echoed), step).toEqual([['keepSignedIn', '1']]);
    }
    expect(
      renderToString(<ReauthenticateFormView {...idle} state={null} keepSignedIn />),
    ).toContain('type="hidden" name="keepSignedIn" value="1"');
  });

  it('never links to or carries a next that resolves to another origin', async () => {
    for (const next of unsafeNext) {
      const form = await render(<ReauthenticateFormView {...idle} state={null} next={next} />);
      expect(
        hidden(form).map(([name]) => name),
        next,
      ).toEqual(['keepSignedIn']);
      const done = await render(
        <ReauthenticateFormView {...idle} state={{ step: 'done', next }} next={next} />,
      );
      expect(done.querySelector('a')!.getAttribute('href'), next).toBe('/');
    }
  });
});

describe('PasswordResetRequestFormView', () => {
  it('asks for the organization and email, then shows the sent notice', async () => {
    const form = await render(<PasswordResetRequestFormView {...idle} state={null} org="acme" />);
    expect(form.dataset.betterIam).toBe('password-reset-request');
    expect(fieldNames(form)).toEqual(['org', 'email']);
    expect(input(form, 'org').value).toBe('acme');
    expect(input(form, 'email').getAttribute('autocomplete')).toBe('email');
    expect(buttons(form).map(({ name, text }) => [name, text])).toEqual([['', 'Send reset link']]);

    const known = await render(
      <PasswordResetRequestFormView
        {...idle}
        state={{
          step: 'credentials',
          values: { email: 'ada@example.com' },
          error: { code: 'INVALID_INPUT', message: 'Enter an email address', field: 'email' },
        }}
        tenantId="tenant_1"
      />,
    );
    expect(fieldNames(known)).toEqual(['email']);
    expect(hidden(known)).toEqual([['tenantId', 'tenant_1']]);
    expect(input(known, 'email').value).toBe('ada@example.com');
    expect(input(known, 'email').getAttribute('aria-invalid')).toBe('true');
    expect(document.activeElement).toBe(input(known, 'email'));

    const sent = await render(<PasswordResetRequestFormView {...idle} state={{ step: 'sent' }} />);
    expect(sent.dataset.step).toBe('sent');
    expect(fieldNames(sent)).toEqual([]);
    expect(status(sent)).toContain('we sent it a link');
    const custom = await render(
      <PasswordResetRequestFormView
        {...idle}
        state={{ step: 'sent', notice: 'Check your inbox' }}
      />,
    );
    expect(status(custom)).toBe('Check your inbox');
  });
});

describe('PasswordResetFormView', () => {
  it('asks for the new password twice and carries the tenant and token', async () => {
    const form = await render(
      <PasswordResetFormView
        {...idle}
        state={{
          step: 'credentials',
          error: {
            code: 'INVALID_INPUT',
            message: 'The passwords do not match',
            field: 'confirmPassword',
          },
        }}
        tenantId="tenant_1"
        token="reset_token"
      />,
    );
    expect(form.dataset.betterIam).toBe('password-reset');
    expect(fieldNames(form)).toEqual(['password', 'confirmPassword']);
    expect(input(form, 'password').getAttribute('autocomplete')).toBe('new-password');
    expect(input(form, 'confirmPassword').getAttribute('autocomplete')).toBe('new-password');
    expect(labelOf(form, input(form, 'confirmPassword'))).toBe('Confirm new password');
    expect(input(form, 'confirmPassword').getAttribute('aria-invalid')).toBe('true');
    expect(input(form, 'password').hasAttribute('aria-invalid')).toBe(false);
    expect(hidden(form)).toEqual([
      ['tenantId', 'tenant_1'],
      ['token', 'reset_token'],
    ]);
    expectNoSecrets(form);

    const done = await render(
      <PasswordResetFormView
        {...idle}
        state={{ step: 'done', next: '/login' }}
        tenantId="t"
        token="x"
      />,
    );
    expect(fieldNames(done)).toEqual([]);
    expect(hidden(done)).toEqual([]);
    expect(status(done)).toContain('Your password has been reset');
    expect(done.querySelector('a')!.getAttribute('href')).toBe('/login');
  });
});

describe('SignUpFormView', () => {
  it('asks for name, email, and password, then shows the sent notice', async () => {
    const form = await render(
      <SignUpFormView
        {...idle}
        state={{ step: 'credentials', values: { name: 'Ada', email: 'ada@example.com' } }}
        tenantId="tenant_1"
        next="/welcome"
      />,
    );
    expect(form.dataset.betterIam).toBe('sign-up');
    expect(fieldNames(form)).toEqual(['name', 'email', 'password']);
    expect(input(form, 'name').getAttribute('autocomplete')).toBe('name');
    expect(input(form, 'name').value).toBe('Ada');
    expect(input(form, 'email').getAttribute('autocomplete')).toBe('email');
    expect(input(form, 'email').value).toBe('ada@example.com');
    expect(input(form, 'password').getAttribute('autocomplete')).toBe('new-password');
    expect(document.activeElement).toBe(input(form, 'name'));
    expect(hidden(form)).toEqual([
      ['tenantId', 'tenant_1'],
      ['next', '/welcome'],
    ]);
    expectNoSecrets(form);

    const sent = await render(<SignUpFormView {...idle} state={{ step: 'sent' }} tenantId="t" />);
    expect(fieldNames(sent)).toEqual([]);
    expect(status(sent)).toBe('Check your email to confirm your address.');
  });
});

describe('InvitationFormView', () => {
  it('requires a name for owners, carries the invitation, and has no cancel after acceptance', async () => {
    const owner = await render(
      <InvitationFormView
        {...idle}
        state={null}
        tenantId="tenant_1"
        token="invite"
        kind="owner"
        next="/"
      />,
    );
    expect(owner.dataset.betterIam).toBe('invitation');
    expect(fieldNames(owner)).toEqual(['name', 'password']);
    expect(input(owner, 'name').required).toBe(true);
    expect(input(owner, 'password').getAttribute('autocomplete')).toBe('new-password');
    expect(hidden(owner)).toEqual([
      ['tenantId', 'tenant_1'],
      ['token', 'invite'],
      ['kind', 'owner'],
      ['next', '/'],
    ]);
    expect(buttons(owner).map(({ intent, text }) => [intent, text])).toEqual([
      ['password', 'Accept invitation'],
    ]);

    const member = await render(
      <InvitationFormView
        {...idle}
        state={null}
        tenantId="tenant_1"
        token="invite"
        kind="member"
      />,
    );
    expect(input(member, 'name').required).toBe(false);

    const enroll = await render(
      <InvitationFormView
        {...idle}
        state={{ step: 'enroll', mfa: enrollment }}
        tenantId="tenant_1"
        token="invite"
        kind="member"
      />,
    );
    expect(enroll.dataset.step).toBe('enroll');
    expect(enroll.textContent).toContain('JBSWY3DPEHPK3PXP');
    expect(buttons(enroll).map(({ intent }) => intent)).toEqual(['enroll']);
    expect(hidden(enroll)).toEqual([
      ['kind', 'member'],
      ['tenantId', 'tenant_1'],
      ['challenge', 'challenge_1'],
      ['enrollmentRequired', '1'],
      ['secret', 'JBSWY3DPEHPK3PXP'],
      ['uri', enrollment.enrollment!.uri],
    ]);

    const done = await render(
      <InvitationFormView
        {...idle}
        state={{ step: 'done', recoveryCodes: ['0123456789abcdef01234567'] }}
        tenantId="tenant_1"
        token="invite"
        kind="member"
        next="/welcome"
      />,
    );
    expect(done.querySelectorAll('[data-recovery-codes] li')).toHaveLength(1);
    expect(done.querySelector('a')!.getAttribute('href')).toBe('/welcome');
  });
});

describe('SignInForm', () => {
  it('drives the action through password, second factor, and recovery codes', async () => {
    const submissions: Record<string, string[]>[] = [];
    const action = vi.fn(async (_previous: AuthFormState | null, form: FormData) => {
      const entries: Record<string, string[]> = {};
      for (const [key, value] of form) (entries[key] ??= []).push(String(value));
      submissions.push(entries);
      const intent = form.get('intent');
      const email = String(form.get('email'));
      const keepSignedIn = form.getAll('keepSignedIn').includes('1');
      if (intent === 'password' && form.get('password') !== 'correct horse battery')
        return {
          step: 'credentials',
          // A misbehaving action echoing the password: the view must still never render it.
          values: { email, password: form.get('password') } as AuthFormState['values'],
          keepSignedIn,
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Invalid email or password',
            field: 'password',
          },
        } satisfies AuthFormState;
      if (intent === 'password')
        return {
          step: 'mfa',
          mfa: challenge,
          values: { email },
          next: '/dashboard',
          keepSignedIn,
        } satisfies AuthFormState;
      if (intent === 'recovery')
        return {
          step: 'done',
          recoveryCodes: ['aaaabbbbccccddddeeeeffff'],
          next: '/dashboard',
        } satisfies AuthFormState;
      return null;
    });
    const form = await render(
      <SignInForm action={action} tenantId="tenant_1" keepSignedIn next="/dashboard" />,
    );
    const submit = async (intent: string) => {
      await act(async () => form.requestSubmit(button(form, intent)));
    };

    input(form, 'email').value = 'ada@example.com';
    input(form, 'password').value = 'wrong password';
    await act(async () => input(form, 'keepSignedIn').click());
    await submit('password');
    expect(action).toHaveBeenCalledTimes(1);
    expect(action.mock.calls[0]![0]).toBeNull();
    expect(submissions[0]).toEqual({
      tenantId: ['tenant_1'],
      email: ['ada@example.com'],
      password: ['wrong password'],
      keepSignedIn: ['0', '1'],
      next: ['/dashboard'],
      intent: ['password'],
    });
    expect(form.dataset.step).toBe('credentials');
    expect(form.querySelector('[role="alert"]')!.textContent).toBe('Invalid email or password');
    expect(input(form, 'password').getAttribute('aria-invalid')).toBe('true');
    expect(input(form, 'password').value).toBe('');
    expectNoSecrets(form);
    expectNowhere(form, 'wrong password');
    expect(input(form, 'email').value).toBe('ada@example.com');
    expect(input(form, 'keepSignedIn').checked).toBe(true);

    input(form, 'password').value = 'correct horse battery';
    await submit('password');
    expect(form.dataset.step).toBe('mfa');
    expect(form.querySelector('[role="alert"]')).toBeNull();
    expect(document.activeElement).toBe(input(form, 'code'));
    expect(hidden(form)).toContainEqual(['keepSignedIn', '1']);
    expectNoSecrets(form);
    expectNowhere(form, 'correct horse battery');

    input(form, 'code').value = 'aaaabbbbccccddddeeeeffff';
    await submit('recovery');
    expect(action.mock.calls[2]![0]).toMatchObject({ step: 'mfa', mfa: challenge });
    expect(submissions[2]).toEqual({
      email: ['ada@example.com'],
      next: ['/dashboard'],
      keepSignedIn: ['1'],
      tenantId: ['tenant_1'],
      challenge: ['challenge_1'],
      emailCodeAvailable: ['1'],
      code: ['aaaabbbbccccddddeeeeffff'],
      intent: ['recovery'],
    });
    expect(form.dataset.step).toBe('done');
    expect(form.querySelector('[data-recovery-codes]')!.textContent).toBe(
      'aaaabbbbccccddddeeeeffff',
    );
    expect(form.querySelector('a')!.getAttribute('href')).toBe('/dashboard');
  });

  it('mounts fresh fields on each step so the first one takes focus', async () => {
    const action = vi.fn(async (_previous: AuthFormState | null, form: FormData) => {
      const values = { email: String(form.get('email')) };
      return form.get('intent') === 'send-code'
        ? ({ step: 'code-sent', values } satisfies AuthFormState)
        : ({ step: 'credentials', values } satisfies AuthFormState);
    });
    const form = await render(<SignInForm action={action} tenantId="tenant_1" passwordless />);
    const email = input(form, 'email');
    expect(document.activeElement).toBe(email);
    email.value = 'ada@example.com';

    await act(async () => form.requestSubmit(button(form, 'send-code')));
    expect(form.dataset.step).toBe('code-sent');
    const code = input(form, 'code');
    expect(code).not.toBe(email);
    expect(email.isConnected).toBe(false);
    expect(document.activeElement).toBe(code);

    await act(async () => form.requestSubmit(button(form, 'cancel')));
    expect(form.dataset.step).toBe('credentials');
    expect(code.isConnected).toBe(false);
    expect(input(form, 'email').value).toBe('ada@example.com');
    expect(document.activeElement).toBe(input(form, 'email'));
  });

  it('renders on the server without client hooks errors', () => {
    const html = renderToString(
      <SignInForm action={async () => null} next="/dashboard" keepSignedIn passwordless />,
    );
    expect(html).toContain('data-better-iam="sign-in"');
    expect(html).toContain('data-step="credentials"');
    expect(html).toContain('autoComplete="current-password"');
    expect(html).toMatch(/<button type="submit" value="password" name="intent">Sign in<\/button>/);
    expect(html).toMatch(
      /<button type="submit" value="send-code" formNoValidate="" name="intent">/,
    );
    expect(html).toContain('type="hidden" name="keepSignedIn" value="0"');
    expect(html).toContain('type="hidden" name="next" value="/dashboard"');
    const labels = [...html.matchAll(/<label for="([^"]+)"/g)].map((match) => match[1]);
    expect(labels).toHaveLength(4);
    for (const id of labels) expect(html).toContain(`id="${id}"`);
  });
});

describe('continue links', () => {
  it('never link to or carry a next that resolves to another origin', async () => {
    for (const next of unsafeNext) {
      const signUp = await render(
        <SignUpFormView {...idle} state={null} tenantId="t" next={next} />,
      );
      expect(hidden(signUp), next).toEqual([['tenantId', 't']]);
      const signedUp = await render(
        <SignUpFormView {...idle} state={{ step: 'done', next }} tenantId="t" next={next} />,
      );
      expect(signedUp.querySelector('a')!.getAttribute('href'), next).toBe('/');
      const invitation = await render(
        <InvitationFormView
          {...idle}
          state={null}
          tenantId="t"
          token="x"
          kind="member"
          next={next}
        />,
      );
      expect(
        hidden(invitation).map(([name]) => name),
        next,
      ).toEqual(['tenantId', 'token', 'kind']);
      const invited = await render(
        <InvitationFormView
          {...idle}
          state={{ step: 'done', next }}
          tenantId="t"
          token="x"
          kind="member"
          next={next}
        />,
      );
      expect(invited.querySelector('a')!.getAttribute('href'), next).toBe('/');
      const reset = await render(
        <PasswordResetFormView {...idle} state={{ step: 'done', next }} tenantId="t" token="x" />,
      );
      expect(reset.querySelector('a')!.getAttribute('href'), next).toBe('/');
    }
  });
});

describe('@better-iam/next/client', () => {
  /** The client references Next's server-layer transform records for a 'use client' module. */
  async function clientReferences(file: string) {
    const nextRequire = createRequire(resolve('packages/next/package.json'));
    const { transform } = nextRequire('next/dist/build/swc/index.js') as {
      transform(source: string, options: object): Promise<{ code: string }>;
    };
    const { getLoaderSWCOptions } = nextRequire('next/dist/build/swc/options.js') as {
      getLoaderSWCOptions(options: object): object;
    };
    const { getRSCModuleInformation } = nextRequire(
      'next/dist/build/analysis/get-page-static-info.js',
    ) as {
      getRSCModuleInformation(
        code: string,
        isReactServerLayer: boolean,
      ): { type?: string; clientRefs?: string[] };
    };
    const filename = resolve(file);
    const options = getLoaderSWCOptions({
      filename,
      development: false,
      isServer: true,
      bundleLayer: 'rsc',
      serverComponents: true,
      serverReferenceHashSalt: '',
      appDir: resolve('.'),
      isPageFile: false,
      hasReactRefresh: false,
      esm: true,
      jsConfig: {},
      compilerOptions: {},
      relativeFilePathFromRoot: file,
      isCacheComponents: false,
      useCacheEnabled: false,
      trackDynamicImports: false,
      cacheHandlers: {},
    });
    const { code } = await transform(readFileSync(filename, 'utf8'), { ...options, filename });
    return getRSCModuleInformation(code, true);
  }

  it('re-exports every form by name, so a server component can import the client entry', async () => {
    // Next's own server-layer transform: `next build` rejects a 'use client' module whose references include `*`.
    const info = await clientReferences('packages/next/src/client.tsx');
    expect(info.type).toBe('client');
    expect(info.clientRefs).not.toContain('*');
    const forms = await import('../packages/next/src/forms.js');
    expect(Object.keys(forms).length).toBeGreaterThan(0);
    for (const name of Object.keys(forms)) expect(info.clientRefs).toContain(name);
  });

  it('keeps the umbrella better-iam/next/client entry in step, by name', async () => {
    const entry = await clientReferences('packages/next/src/client.tsx');
    const umbrella = await clientReferences('packages/better-iam/src/next-client.ts');
    expect(umbrella.type).toBe('client');
    expect(umbrella.clientRefs).not.toContain('*');
    expect([...(umbrella.clientRefs ?? [])].sort()).toEqual([...(entry.clientRefs ?? [])].sort());
  });
});
