import { readFile } from 'node:fs/promises';
import { createOAuthProvider } from 'better-iam/oauth';

export function escapeHtml(value) {
  return String(value).replace(
    /[&<>"']/g,
    (character) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character],
  );
}

function page(title, content) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)}</title><link rel="stylesheet" href="/style.css"></head><body><main><h1>${escapeHtml(title)}</h1>${content}<p><a href="/">Return to account management</a></p></main></body></html>`;
}

/** Real persistent OIDC provider, enabled only when signing/encryption keys are configured. */
export async function configureOidc(iam, configuration) {
  if (!process.env.OIDC_KEY_FILE) return undefined;
  const keys = JSON.parse(await readFile(process.env.OIDC_KEY_FILE, 'utf8'));
  const origin = new URL(configuration.baseURL).origin;
  const provider = createOAuthProvider({
    ...iam.protocolHost,
    issuer: `${origin}/oauth`,
    jwks: keys.jwks,
    cookieKeys: keys.cookieKeys,
    encryptionKey: keys.encryptionKey,
    trustedOrigins: [origin],
    allowInsecureLocalhost: origin.startsWith('http://'),
    interactionUrl: (uid) => `/oidc/interaction/${encodeURIComponent(uid)}`,
    renderDevicePage: ({ kind, form, userCode, clientName }) =>
      page(
        'Device authorization',
        `<p>${kind === 'success' ? 'Device approved. Return to your device.' : kind === 'input' ? 'Enter the code displayed on your device.' : `Approve ${escapeHtml(clientName ?? 'this application')} with code ${escapeHtml(userCode ?? '')}.`}</p>${form}`,
      ),
    renderLogoutPage: ({ form }) => page('End your OAuth session', form),
  });
  // Back-channel logout: revoke consents (and notify registered clients) once their IAM session has ended.
  const sweep = () => void provider.logoutEndedSessions().catch(() => undefined);
  iam.events.subscribe(['auth:session:*', 'identity:*', 'tenant:*'], sweep);
  setInterval(sweep, 60_000).unref();
  return provider;
}
