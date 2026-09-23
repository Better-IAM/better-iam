import { describe, expect, it } from 'vitest';
import { renderDeliveryMessage } from '@better-iam/auth';

const links = {
  invitation: ({ kind, tenantId, token }: { kind: string; tenantId: string; token: string }) =>
    `https://app.example/join?kind=${kind}&tenant=${tenantId}&token=${token}`,
  passwordReset: ({ tenantId, token }: { tenantId: string; token: string }) =>
    `https://app.example/reset?tenant=${tenantId}&token=${token}`,
  verifyEmail: ({ token }: { token: string }) => `https://app.example/verify?token=${token}`,
  emailChange: ({ token }: { token: string }) => `https://app.example/email?token=${token}`,
  magicLink: ({ token, destination }: { token: string; destination: string }) =>
    `https://app.example/magic?token=${token}&to=${encodeURIComponent(destination)}`,
};

describe('delivery templates', () => {
  it('renders every built-in template with links, escaping payload text in HTML', () => {
    const invitation = renderDeliveryMessage(
      {
        template: 'member-invitation',
        to: 'alice@example.test',
        payload: {
          token: 'tok',
          tenantId: 't1',
          tenantName: 'Acme <script>alert(1)</script>',
          inviterName: 'Owner "O"',
        },
      },
      { appName: 'Acme Cloud', links },
    )!;
    expect(invitation.subject).toBe('Join Acme <script>alert(1)</script> on Acme Cloud');
    expect(invitation.text).toContain(
      'Owner "O" invited you to join Acme <script>alert(1)</script>.',
    );
    expect(invitation.text).toContain(
      'Accept invitation: https://app.example/join?kind=member&tenant=t1&token=tok',
    );
    expect(invitation.html).not.toContain('<script>');
    expect(invitation.html).toContain('&lt;script&gt;');
    expect(invitation.html).toContain(
      'href="https://app.example/join?kind=member&amp;tenant=t1&amp;token=tok"',
    );
    const owner = renderDeliveryMessage(
      {
        template: 'owner-invitation',
        to: 'o@example.test',
        payload: { token: 'tok', tenantId: 't1', tenantName: 'Acme' },
      },
      { links },
    )!;
    expect(owner.subject).toBe('Set up Acme on Better IAM');
    expect(owner.text).toContain('kind=owner');
    const reset = renderDeliveryMessage(
      {
        template: 'password-reset',
        to: 'a@example.test',
        payload: { token: 'r1', tenantId: 't1' },
      },
      { links },
    )!;
    expect(reset.subject).toBe('Reset your Better IAM password');
    expect(reset.text).toContain('https://app.example/reset?tenant=t1&token=r1');
    expect(reset.html).toContain('Choose a new password');
    for (const [template, needle] of [
      ['verify-email', 'https://app.example/verify?token=v1'],
      ['email-change', 'https://app.example/email?token=v1'],
      ['magic-link', 'https://app.example/magic?token=v1&to=a%40example.test'],
    ] as const) {
      const rendered = renderDeliveryMessage(
        { template, to: 'a@example.test', payload: { token: 'v1', tenantId: 't1' } },
        { links },
      )!;
      expect(rendered.text).toContain(needle);
      expect(rendered.html).toContain(escapeAmp(needle));
    }
    const code = renderDeliveryMessage({
      template: 'code',
      to: '+15550001',
      payload: { token: '123456' },
    })!;
    expect(code.text).toContain('Enter this code to sign in: 123456');
    const mfa = renderDeliveryMessage({
      template: 'mfa-code',
      to: 'a@example.test',
      payload: { code: '654321' },
    })!;
    expect(mfa.subject).toBe('Your Better IAM verification code');
    expect(mfa.text).toContain('654321');
    const alert = renderDeliveryMessage({
      template: 'new-sign-in',
      to: 'a@example.test',
      payload: {
        method: 'password',
        time: '2026-09-22T00:00:00.000Z',
        userAgent: 'Mozilla/5.0',
        ip: '203.0.113.7',
      },
    })!;
    expect(alert.subject).toBe('New sign-in to Better IAM');
    expect(alert.text).toContain('Mozilla/5.0 · 203.0.113.7');
    expect(alert.text).toContain('Method: password.');
    const failures = renderDeliveryMessage({
      template: 'sign-in-failures',
      to: 'a@example.test',
      payload: { attempts: '5', time: '2026-09-22T00:00:00.000Z', ip: '198.51.100.9' },
    })!;
    expect(failures.subject).toBe('Failed sign-in attempts on your Better IAM account');
    expect(failures.text).toContain('5 attempts to sign in to your account have failed');
    expect(failures.text).toContain('the latest from 198.51.100.9');
    expect(failures.html).toContain('Nobody has got in');
    expect(failures.html).not.toContain('href=');
    // Security notices carry a "Review your account" button when the application says where the page lives.
    const linked = renderDeliveryMessage(
      {
        template: 'new-sign-in',
        to: 'a@example.test',
        tenantId: 'tenant-1',
        payload: { method: 'password', time: '2026-09-22T00:00:00.000Z' },
      },
      { links: { account: ({ tenantId }) => `https://app.example.test/${tenantId}/account` } },
    )!;
    expect(linked.text).toContain('Review your account: https://app.example.test/tenant-1/account');
    expect(linked.html).toContain('href="https://app.example.test/tenant-1/account"');
    const linkedFailures = renderDeliveryMessage(
      {
        template: 'sign-in-failures',
        to: 'a@example.test',
        tenantId: 'tenant-1',
        payload: { attempts: '5', time: '2026-09-22T00:00:00.000Z' },
      },
      { links: { account: ({ tenantId }) => `https://app.example.test/${tenantId}/account` } },
    )!;
    expect(linkedFailures.html).toContain('href="https://app.example.test/tenant-1/account"');
  });

  it('falls back to the raw token without link builders and ignores unknown templates', () => {
    const reset = renderDeliveryMessage({
      template: 'password-reset',
      to: 'a@example.test',
      payload: { token: 'raw-token' },
    })!;
    expect(reset.text).toContain('Code: raw-token');
    expect(reset.html).toContain('<code>raw-token</code>');
    expect(reset.html).not.toContain('href=');
    expect(
      renderDeliveryMessage({
        template: 'not-a-template',
        to: 'a@example.test',
        payload: {},
      }),
    ).toBeUndefined();
  });

  it('renders access-certification reviews and reminders with a review link or the account page', () => {
    const review = renderDeliveryMessage(
      {
        template: 'certification-review',
        to: 'manager@example.test',
        tenantId: 'tenant-1',
        payload: {
          campaignId: 'campaign-1',
          campaignName: 'Q3 <review>',
          items: '3',
          dueAt: '2026-10-01T00:00:00.000Z',
        },
      },
      {
        appName: 'Acme IAM',
        links: {
          certification: ({ tenantId, campaignId }) =>
            `https://app.example/${tenantId}/certifications/${campaignId}`,
          account: ({ tenantId }) => `https://app.example/${tenantId}/account`,
        },
      },
    )!;
    expect(review.subject).toBe('Review access: Q3 <review>');
    expect(review.text).toContain('review 3 access items in Q3 <review>');
    expect(review.text).toContain('Please decide by 2026-10-01T00:00:00.000Z.');
    expect(review.text).toContain(
      'Review access: https://app.example/tenant-1/certifications/campaign-1',
    );
    expect(review.html).toContain('Q3 &lt;review&gt;');
    expect(review.html).not.toContain('<review>');

    const reminder = renderDeliveryMessage(
      {
        template: 'certification-reminder',
        to: 'manager@example.test',
        tenantId: 'tenant-1',
        payload: { campaignId: 'campaign-1', campaignName: 'Q3', pending: '1' },
      },
      { links: { account: ({ tenantId }) => `https://app.example/${tenantId}/account` } },
    )!;
    expect(reminder.subject).toBe('Reminder: Q3 is waiting for you');
    expect(reminder.text).toContain('1 access item still needs your decision in Q3.');
    // Without a certification builder the button falls back to the account page.
    expect(reminder.text).toContain('Review access: https://app.example/tenant-1/account');

    const bare = renderDeliveryMessage({
      template: 'certification-review',
      to: 'manager@example.test',
      payload: { campaignName: 'Q3', items: '2' },
    })!;
    expect(bare.html).not.toContain('href=');
  });
});

function escapeAmp(value: string): string {
  return value.replace(/&/g, '&amp;');
}
