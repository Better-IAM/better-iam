// Generates crates/auth/tests/fixtures/templates.json: every built-in template rendered by the TypeScript
// renderDeliveryMessage over payload variants, link builders, tenants, organization addresses and app names, so the
// Rust renderer can be checked for identical subjects, text and HTML.
//
//   node crates/auth/tests/fixtures/generate-templates.mjs     (after `pnpm build`)
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { renderDeliveryMessage } from '../../../../packages/auth/dist/templates.js';

const templates = [
  'verify-email', 'password-reset', 'email-change', 'magic-link', 'code', 'mfa-code', 'new-sign-in',
  'sign-in-failures', 'certification-review', 'certification-reminder', 'delegation-request',
  'delegation-confirmation', 'team-join-request', 'team-join-decided', 'team-review-requested', 'spend-alert',
  'spend-anomaly', 'billing-statement', 'payment-reminder', 'privacy-request-verify', 'privacy-request-received',
  'privacy-request-update', 'privacy-request-due', 'workflow-message', 'threat-alert', 'license-waiting',
  'license-activated', 'guest-invitation', 'guest-review', 'guest-sponsor-missing', 'clearance-reminder',
  'clearance-status', 'owner-invitation', 'member-invitation', 'not-a-template',
];

const site = (input) => input.signInUrl ?? '';
/** Link builders whose output names every input, written identically by the Rust test. */
const links = {
  invitation: (i) => `https://app.example/invitation?kind=${i.kind}&tenant=${i.tenantId}&token=${i.token}&site=${site(i)}`,
  passwordReset: (i) => `https://app.example/passwordReset?tenant=${i.tenantId}&token=${i.token}&site=${site(i)}`,
  verifyEmail: (i) => `https://app.example/verifyEmail?tenant=${i.tenantId}&token=${i.token}&site=${site(i)}`,
  emailChange: (i) => `https://app.example/emailChange?tenant=${i.tenantId}&token=${i.token}&site=${site(i)}`,
  magicLink: (i) => `https://app.example/magicLink?tenant=${i.tenantId}&token=${i.token}&to=${i.destination}&site=${site(i)}`,
  account: (i) => `https://app.example/account?tenant=${i.tenantId}&site=${site(i)}`,
  certification: (i) => `https://app.example/certification?tenant=${i.tenantId}&campaign=${i.campaignId}&site=${site(i)}`,
  delegation: (i) => `https://app.example/delegation?tenant=${i.tenantId}&delegation=${i.delegationId}&site=${site(i)}`,
  team: (i) => `https://app.example/team?tenant=${i.tenantId}&team=${i.teamId}&site=${site(i)}`,
  billing: (i) => `https://app.example/billing?tenant=${i.tenantId}&statement=${i.statementId ?? ''}&site=${site(i)}`,
  privacy: (i) =>
    `https://app.example/privacy?tenant=${i.tenantId}&request=${i.requestId ?? ''}&token=${i.token ?? '-'}&handler=${i.handler ?? '-'}&site=${site(i)}`,
  threats: (i) => `https://app.example/threats?tenant=${i.tenantId}&incident=${i.incidentId ?? ''}&site=${site(i)}`,
  guestInvitation: (i) => `https://app.example/guestInvitation?tenant=${i.tenantId}&token=${i.token}&site=${site(i)}`,
  guests: (i) => `https://app.example/guests?tenant=${i.tenantId}&guest=${i.guestId ?? ''}&site=${site(i)}`,
  clearances: (i) => `https://app.example/clearances?tenant=${i.tenantId}&identity=${i.identityId ?? ''}&site=${site(i)}`,
};
/** Only the account page, so the fallbacks run. */
const accountOnly = { account: links.account };

const full = {
  token: 'tok-123', tenantId: 'payload-tenant', code: '654321', label: 'Work laptop', method: 'password',
  time: '2026-09-22T00:00:00.000Z',
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36',
  ip: '203.0.113.7', attempts: '5', campaignId: 'campaign-1', campaignName: 'Q3 <review>', items: '3', pending: '1',
  dueAt: '2026-10-01T00:00:00.000Z', agentName: 'Helper Bot', model: 'gpt-x', days: '3', scopes: 'docs:read, docs:write',
  reason: 'Weekly report', delegationId: 'dlg-1', action: 'docs:delete', resource: 'doc/42', minutes: '15',
  teamId: 'team-1', teamName: 'Platform & Ops', requesterName: 'Rae', requesterEmail: 'rae@example.test',
  justification: 'On call', decision: 'approved', note: 'Welcome aboard', memberCount: '12', onUndecided: 'remove',
  statementId: 'st-1', tenantName: 'Acme "Corp"', number: 'INV-0042', period: '2026-09', total: '$120.00',
  subtotal: '$130.00', credits: '$10.00', amountDue: '$120.00', overdue: 'true', budgetName: 'Cloud',
  subjectName: 'Team Rocket', windowStart: '2026-09-01', windowEnd: '2026-09-30', kind: 'actual', threshold: '80',
  spent: '$80.00', amount: '$100.00', percent: '81', forecast: '$140.00', count: '2',
  items_anomaly: '', day: '2026-09-21', requestId: 'dsr-1', type: 'access', regulation: 'gdpr', channel: 'form',
  event: 'completed', exportReady: 'true', incidentId: 'inc-1', title: 'Impossible travel', severity: 'high',
  detections: '3', subject: 'alice@example.test', summary: 'Two sign-ins 9000 km apart.', body: 'Line one\r\nLine two\nLine three',
  inviterName: 'Owner "O"', sponsorName: 'Sam', message: 'Join us <b>now</b>', expiresAt: '2026-12-31T00:00:00.000Z',
  guestId: 'guest-1', guestName: 'Gus', guestEmail: 'gus@partner.test', reviewDueAt: '2026-11-30T12:00:00.000Z',
  productKey: 'seat-pro', productName: 'Pro Seat', levelName: 'Secret', personName: 'Pat', identityId: 'idn-7',
  reinvestigationDue: '2027-01-15T00:00:00.000Z', status: 'interim',
};
const edgy = {
  token: '', label: 'Line break\u0007bell', userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS) FxiOS/1',
  ip: '', items: '1', pending: 'nope', days: '1', count: '1', decision: 'denied', overdue: 'false', minutes: '0',
  memberCount: '', dueAt: 'not a date', expiresAt: 'Thu, 01 Oct 2026 00:00:00 GMT', reviewDueAt: '2027-02-01',
  tenantName: '', number: '', period: '', kind: 'forecast', windowStart: '2026-09-01', windowEnd: '2026-09-01',
  type: 'erasure', event: 'rejected', reason: 'no-data', severity: '', detections: '1', subject: '',
  subjectName: 'X\nY', body: '', status: 'revoked', levelName: '', inviterName: 'Sam', sponsorName: 'Sam',
  items_list: JSON.stringify([{ what: 'Team A', spent: '$5', usual: '$1' }, { what: 'Meter <b>' }, 7]),
  campaignName: 'Shared\r\nSubject', agentName: '', title: 'Odd\u0000Title',
};

function payloadFor(template, variant) {
  if (variant === 'empty') return {};
  const source = variant === 'full' ? full : { ...full, ...edgy };
  const payload = { ...source };
  delete payload.items_anomaly;
  delete payload.items_list;
  if (template === 'spend-anomaly')
    payload.items = variant === 'full' ? JSON.stringify([{ what: 'Alice', spent: '$40', usual: '$4' }]) : edgy.items_list;
  if (template === 'privacy-request-update' && variant === 'full') payload.type = 'erasure';
  if (template === 'privacy-request-due' || template === 'privacy-request-received' || template === 'privacy-request-update')
    payload.dueAt = variant === 'full' ? String(Date.UTC(2026, 9, 30)) : 'nope';
  if (template === 'billing-statement' && variant === 'edgy') payload.reason = 'subscription';
  if (template === 'clearance-status' && variant === 'full') payload.status = 'reinstated';
  return payload;
}

const settings = [
  { links: 'none', tenantId: undefined, signInUrl: undefined, appName: undefined },
  { links: 'all', tenantId: 't1', signInUrl: undefined, appName: 'Acme Cloud' },
  { links: 'all', tenantId: 't1', signInUrl: 'https://acme.example/login', appName: undefined },
  { links: 'account', tenantId: 't1', signInUrl: 'https://acme.example/login', appName: 'Acme Cloud' },
  { links: 'all', tenantId: undefined, signInUrl: undefined, appName: undefined },
  { links: 'none', tenantId: '', signInUrl: '', appName: '' },
];

const cases = [];
for (const template of templates)
  for (const variant of ['full', 'empty', 'edgy'])
    for (const setting of settings) {
      const message = { template, to: 'person@example.test', payload: payloadFor(template, variant) };
      if (setting.tenantId !== undefined) message.tenantId = setting.tenantId;
      if (setting.signInUrl !== undefined) message.signInUrl = setting.signInUrl;
      const options = {};
      if (setting.appName !== undefined) options.appName = setting.appName;
      if (setting.links === 'all') options.links = links;
      if (setting.links === 'account') options.links = accountOnly;
      const rendered = renderDeliveryMessage(message, options);
      cases.push({ message, appName: setting.appName ?? null, links: setting.links, rendered: rendered ?? null });
    }
const out = fileURLToPath(new URL('./templates.json', import.meta.url));
writeFileSync(out, `${JSON.stringify({ description: 'renderDeliveryMessage outputs (generate-templates.mjs)', cases })}\n`);
console.log(`${cases.length} cases written to ${out}`);
