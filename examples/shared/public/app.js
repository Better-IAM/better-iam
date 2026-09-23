let configuration;
let mfaChallenge;
let enrolling = false;
const result = document.querySelector('#result');
const display = (value) => {
  result.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
};
const formData = (id) => Object.fromEntries(new FormData(document.getElementById(id)));
const tenant = () => document.querySelector('#document [name=tenantId]').value;
function setTenant(id) {
  if (id) for (const input of document.querySelectorAll('[data-tenant]')) input.value = id;
}
async function request(path, input, method = 'POST') {
  const response = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: method === 'POST' ? { 'content-type': 'application/json', 'x-better-iam': '1' } : {},
    body: method === 'POST' ? JSON.stringify(input ?? {}) : undefined,
  });
  const envelope = await response.json();
  if (!response.ok || envelope.error)
    throw new Error(
      `${envelope.error?.code ?? response.status}: ${envelope.error?.message ?? 'Request failed'}`,
    );
  return envelope.data;
}
const api = (path, input) => request(`/api/iam/${path}`, input);
async function signedIn(data, tenantId) {
  if (data.mfaRequired) {
    mfaChallenge = { tenantId, challenge: data.challenge };
    enrolling = false;
    display({
      mfaRequired: true,
      enrollmentRequired: data.enrollmentRequired,
      message: data.enrollmentRequired
        ? 'Start authenticator enrollment, then enter a code.'
        : 'Enter your authenticator or recovery code.',
    });
  } else {
    mfaChallenge = undefined;
    enrolling = false;
    const current = await api('auth/getSession');
    setTenant(current.identity.tenantId);
    // Session tokens stay in HttpOnly cookies. Never persist them in browser storage.
    display({ message: 'Signed in', identity: current.identity, session: current.session });
  }
}
function click(id, handler) {
  document.getElementById(id).addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await handler();
    } catch (error) {
      display(error.message);
    } finally {
      button.disabled = false;
    }
  });
}
function submit(id, handler) {
  document.getElementById(id).addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('button');
    button.disabled = true;
    try {
      await handler(formData(id));
    } catch (error) {
      display(error.message);
    } finally {
      button.disabled = false;
    }
  });
}
submit('signin', async (input) => {
  await signedIn(await api('auth/signIn', input), input.tenantId);
  document.querySelector('#signin [name=password]').value = '';
});
click('session', async () => {
  const data = await api('auth/getSession');
  setTenant(data.identity.tenantId);
  display(data);
});
click('signout', async () => {
  await api('auth/signOut');
  mfaChallenge = undefined;
  display('Signed out.');
});
click('enroll', async () => {
  const data = await api('auth/beginMfa', mfaChallenge ?? {});
  enrolling = true;
  document.querySelector('#mfa-secret').textContent =
    `Authenticator secret: ${data.secret}\nSetup URI: ${data.uri}`;
  display('Add the secret to an authenticator app and enter its code.');
});
submit('mfa', async (input) => {
  let data;
  if (enrolling) {
    data = await api('auth/confirmMfa', { credential: mfaChallenge, code: input.code });
    document.querySelector('#recovery-codes').textContent =
      `Save these recovery codes once in a safe place: ${data.recoveryCodes.join(' · ')}`;
  } else {
    if (!mfaChallenge) throw new Error('Sign in first to obtain an MFA challenge.');
    data = await api(input.recovery ? 'auth/recoverMfa' : 'auth/verifyMfa', {
      ...mfaChallenge,
      code: input.code,
    });
  }
  document.querySelector('#mfa-secret').textContent = '';
  await signedIn(data, mfaChallenge?.tenantId);
});
const list = (value) =>
  value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
submit('lookup', async (input) => {
  const data = await api('tenants/lookup', input);
  setTenant(data.tenantId);
  display({
    ...data,
    message: 'Tenant fields now point at this organization. Sign in with your email and password.',
  });
});
submit('organization', async (input) => {
  if (!input.slug) delete input.slug;
  const data = await api('tenants/create', input);
  document.querySelector('#invitation [name=tenantId]').value = data.tenant.id;
  display({
    ...data,
    next: 'Read the owner invitation in the local inbox or your email provider.',
  });
});
submit('invite', async (input) => {
  const roleIds = list(input.roleIds);
  const data = await api('identities/invite', {
    tenantId: input.tenantId,
    email: input.email,
    ...(input.name ? { name: input.name } : {}),
    ...(roleIds.length ? { roleIds } : {}),
  });
  display({
    ...data,
    next: 'Read the member invitation in the local inbox or your email provider.',
  });
});
submit('member-invitation', async (input) => {
  const data = await api('identities/acceptInvitation', input);
  setTenant(input.tenantId);
  await signedIn(data, input.tenantId);
  document.querySelector('#member-invitation [name=password]').value = '';
});
submit('role', async (input) => {
  display(
    await api('roles/create', {
      tenantId: input.tenantId,
      name: input.name,
      permissions: list(input.permissions),
    }),
  );
});
click('roles', async () => {
  display(await api('roles/list', { tenantId: tenant() }));
});
click('actions', async () => {
  display(await api('actions/list', { tenantId: tenant() }));
});
submit('resource-type', async (input) => {
  const attributes = input.attributes.trim() ? JSON.parse(input.attributes) : undefined;
  display(
    await api('resourceTypes/register', {
      tenantId: input.tenantId,
      name: input.name,
      actions: list(input.actions),
      ...(attributes ? { attributes } : {}),
    }),
  );
});
click('resource-types', async () => {
  display(await api('resourceTypes/list', { tenantId: tenant() }));
});
submit('workspace', async (input) => {
  display(await request('/app/workspaces', input));
});
click('workspaces', async () => {
  const data = await request(
    `/app/workspaces?tenantId=${encodeURIComponent(tenant())}`,
    undefined,
    'GET',
  );
  document.querySelector('#workspace-list').textContent = data.length
    ? data
        .map((workspace) => `${workspace.id}: ${workspace.allowed.join(', ') || 'no access'}`)
        .join('\n')
    : 'No workspaces yet. An owner can create one.';
  display(data);
});
click('links', async () => {
  display(await api('links/list'));
});
submit('invitation', async (input) => {
  const data = await api('tenants/acceptInvitation', input);
  setTenant(input.tenantId);
  await signedIn(data, input.tenantId);
  document.querySelector('#invitation [name=password]').value = '';
});
submit('signup', async (input) => {
  display(await api('auth/signUp', input));
  document.querySelector('#signup [name=password]').value = '';
});
submit('verification', async (input) => {
  display(await api('auth/verifyEmail', input));
});
submit('recovery-request', async (input) => {
  display(await api('auth/requestPasswordReset', input));
});
submit('password-reset', async (input) => {
  display(await api('auth/resetPassword', input));
  document.querySelector('#password-reset [name=password]').value = '';
});
submit('policy', async (input) => {
  const policy = await api('policies/create', {
    tenantId: input.tenantId,
    name: input.name,
    document: JSON.parse(input.document),
  });
  const role = await api('roles/create', {
    tenantId: input.tenantId,
    name: input.name,
    policyIds: [policy.id],
  });
  const binding = await api('bindings/create', {
    tenantId: input.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: input.identityId,
  });
  display({ policy, role, binding });
});
click('identities', async () => {
  display(await api('identities/list', { tenantId: tenant() }));
});
submit('document', async (input) => {
  display(await request('/app/documents', input));
});
click('documents', async () => {
  const data = await request(
    `/app/documents?tenantId=${encodeURIComponent(tenant())}`,
    undefined,
    'GET',
  );
  document.querySelector('#document-list').textContent = data.length
    ? data.map((document) => `${document.title}: ${document.body}`).join('\n')
    : 'No readable documents. An owner can create one and grant access.';
  display(data);
});
submit('oauth-client', async (input) => {
  display(await request('/app/oauth/clients', input));
});
submit('scim', async (input) => {
  display(await request('/app/scim/connections', input));
});
click('inbox', async () => {
  const messages = await request('/dev/inbox', undefined, 'GET');
  const container = document.querySelector('#inbox-list');
  container.replaceChildren();
  for (const message of messages.reverse()) {
    const card = document.createElement('div');
    card.className = 'message';
    const title = document.createElement('strong');
    title.textContent = `${message.template} → ${message.to}`;
    card.append(title);
    const payload = document.createElement('pre');
    payload.textContent = JSON.stringify(
      { tenantId: message.tenantId, ...message.payload },
      null,
      2,
    );
    card.append(payload);
    if (message.template === 'owner-invitation' || message.template === 'member-invitation') {
      const form = message.template === 'owner-invitation' ? '#invitation' : '#member-invitation';
      const button = document.createElement('button');
      button.textContent = 'Fill invitation';
      button.addEventListener('click', () => {
        document.querySelector(`${form} [name=tenantId]`).value = message.tenantId;
        document.querySelector(`${form} [name=token]`).value = message.payload.token;
      });
      card.append(button);
    }
    container.append(card);
  }
});

const base64url = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
click('oidc-start', async () => {
  if (!configuration.oidc) throw new Error('Configure OIDC_KEY_FILE and restart the server first.');
  const discovery = await (
    await fetch(`${configuration.issuer}/.well-known/openid-configuration`)
  ).json();
  if (discovery.issuer !== configuration.issuer) throw new Error('Unexpected OIDC issuer.');
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const state = crypto.randomUUID();
  const challenge = base64url(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))),
  );
  const clientId = document.querySelector('#oauth-client [name=clientId]').value;
  // Only the short-lived PKCE transaction is stored across full-page navigation; no IAM token is stored.
  sessionStorage.setItem(
    'example.oidc',
    JSON.stringify({ verifier, state, clientId, createdAt: Date.now() }),
  );
  const url = new URL(discovery.authorization_endpoint);
  for (const [key, value] of Object.entries({
    client_id: clientId,
    redirect_uri: `${location.origin}/oidc/callback`,
    response_type: 'code',
    scope: 'openid email profile offline_access',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }))
    url.searchParams.set(key, value);
  location.assign(url);
});
async function oauthCallback() {
  if (location.pathname !== '/oidc/callback') return;
  const parameters = new URLSearchParams(location.search);
  const transaction = JSON.parse(sessionStorage.getItem('example.oidc') ?? 'null');
  sessionStorage.removeItem('example.oidc');
  history.replaceState(null, '', '/oidc/callback');
  if (
    !transaction ||
    parameters.get('state') !== transaction.state ||
    Date.now() - transaction.createdAt > 10 * 60_000
  )
    throw new Error('OIDC transaction state is invalid or expired.');
  if (parameters.has('error'))
    throw new Error(`OAuth authorization failed: ${parameters.get('error')}`);
  const discovery = await (
    await fetch(`${configuration.issuer}/.well-known/openid-configuration`)
  ).json();
  if (discovery.issuer !== configuration.issuer) throw new Error('Unexpected OIDC issuer.');
  const response = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: parameters.get('code') ?? '',
      redirect_uri: `${location.origin}/oidc/callback`,
      client_id: transaction.clientId,
      code_verifier: transaction.verifier,
    }),
  });
  const tokens = await response.json();
  if (!response.ok) throw new Error(tokens.error_description ?? tokens.error);
  display({
    message:
      'Authorization code and PKCE exchange succeeded. Tokens were returned to this page and were not persisted.',
    tokenType: tokens.token_type,
    expiresIn: tokens.expires_in,
    scope: tokens.scope,
    receivedIdToken: Boolean(tokens.id_token),
    receivedRefreshToken: Boolean(tokens.refresh_token),
  });
}
try {
  configuration = await request('/app/config', undefined, 'GET');
  setTenant(configuration.rootTenantId);
  document.querySelector('#organization [name=parentId]').value = configuration.rootTenantId ?? '';
  document.querySelector('#configuration').textContent = configuration.rootTenantId
    ? `Root tenant: ${configuration.rootTenantId}`
    : 'Run the CLI bootstrap command before signing in.';
  document.querySelector('#inbox-section').hidden = !configuration.demoDelivery;
  document.querySelector('#oidc-status').textContent = configuration.oidc
    ? `Issuer: ${configuration.issuer}`
    : 'Set OIDC_KEY_FILE and restart to enable the provider.';
  await oauthCallback();
} catch (error) {
  display(error.message);
}
