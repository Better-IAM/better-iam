import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { betterIam, IamError } from 'better-iam';
import { createScimService } from 'better-iam/scim';
import { deliveryInbox, demoDelivery } from './config.mjs';
import { configureOidc, escapeHtml } from './oidc.mjs';

const staticFiles = new Map([
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/style.css', ['style.css', 'text/css; charset=utf-8']],
]);
const csp =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
function headersFrom(req) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers))
    if (value) for (const part of Array.isArray(value) ? value : [value]) headers.append(key, part);
  return headers;
}
function json(res, body, status = 200) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(JSON.stringify(body));
}
async function readBody(req, jsonOnly = true) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 65536) throw new IamError('BODY_TOO_LARGE', 'Request exceeds 64 KiB', 413);
    chunks.push(chunk);
  }
  const source = Buffer.concat(chunks).toString('utf8');
  if (!jsonOnly) return Object.fromEntries(new URLSearchParams(source));
  let body;
  try {
    body = JSON.parse(source);
  } catch {
    throw new IamError('INVALID_INPUT', 'Invalid JSON');
  }
  if (!body || typeof body !== 'object' || Array.isArray(body))
    throw new IamError('INVALID_INPUT', 'A JSON object is required');
  return body;
}
function csrf(req, origin) {
  if (
    req.headers.origin !== origin ||
    req.headers['x-better-iam'] !== '1' ||
    !req.headers['content-type']?.startsWith('application/json')
  )
    throw new IamError('CSRF_REJECTED', 'Same-origin JSON requests require X-Better-IAM', 403);
}

/** Starts a real HTTP server. Every privileged example operation calls the library's service boundary. */
export async function startExample(configuration, { port, quiet = false } = {}) {
  const iam = betterIam(configuration);
  await iam.initialize();
  const origin = new URL(configuration.baseURL).origin;
  const provider = await configureOidc(iam, configuration);
  if (provider) iam.useProtocol(provider);
  const scim = createScimService({ ...iam.protocolHost, basePath: '/scim/v2' });
  iam.useProtocol({ basePath: '/scim/v2', handler: scim.handler });
  const template = await readFile(new URL('./public/index.html', import.meta.url), 'utf8');
  const server = createServer(async (req, res) => {
    try {
      // Pin the origin even for loopback demonstration endpoints; prevents DNS-rebinding access to the inbox.
      if (req.headers.host !== new URL(origin).host)
        throw new IamError('INVALID_HOST', 'Unexpected Host header', 400);
      const url = new URL(req.url ?? '/', origin);
      const credential = { headers: headersFrom(req) };
      if (req.method === 'GET' && staticFiles.has(url.pathname)) {
        const [filename, contentType] = staticFiles.get(url.pathname);
        res.writeHead(200, {
          'content-type': contentType,
          'x-content-type-options': 'nosniff',
          'cache-control': 'no-cache',
        });
        res.end(await readFile(new URL(`./public/${filename}`, import.meta.url)));
        return;
      }
      if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/oidc/callback')) {
        res.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'content-security-policy': csp,
          'cache-control': 'no-store',
        });
        res.end(template.replace('<!--INTERACTION-->', ''));
        return;
      }
      if (url.pathname.startsWith('/oidc/interaction/')) {
        if (!provider) throw new IamError('FEATURE_DISABLED', 'OIDC is not configured', 404);
        if (req.method === 'GET') {
          const details = await provider.interactionDetails(req, res);
          const interaction = `<section><h2>Authorize ${escapeHtml(details.clientId)}</h2><p>Sign into tenant <strong>${escapeHtml(details.tenantId)}</strong> using the login and MFA forms below, then approve or deny these scopes: ${details.scopes.map(escapeHtml).join(', ')}.</p><form method="post" action="${escapeHtml(url.pathname)}"><button name="consent" value="yes">Approve access</button><button name="consent" value="no">Deny access</button></form></section>`;
          res.writeHead(200, {
            'content-type': 'text/html; charset=utf-8',
            'content-security-policy': csp,
            'cache-control': 'no-store',
          });
          res.end(template.replace('<!--INTERACTION-->', interaction));
          return;
        }
        if (req.method === 'POST') {
          const body = await readBody(req, false);
          if (!['yes', 'no'].includes(body.consent))
            throw new IamError('INVALID_INPUT', 'Explicit consent is required');
          await provider.completeInteraction(req, res, {
            credential,
            consent: body.consent === 'yes',
          });
          return;
        }
      }
      if (url.pathname === '/app/config' && req.method === 'GET') {
        const roots = await iam.store.find('tenants', { parentId: null });
        json(res, {
          data: {
            rootTenantId: roots[0]?.id,
            demoDelivery,
            oidc: Boolean(provider),
            issuer: provider ? `${origin}/oauth` : undefined,
          },
        });
        return;
      }
      if (url.pathname === '/dev/inbox' && req.method === 'GET') {
        if (
          !demoDelivery ||
          !['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress)
        )
          throw new IamError('NOT_FOUND', 'Not found', 404);
        if (req.headers.origin && req.headers.origin !== origin)
          throw new IamError('UNTRUSTED_ORIGIN', 'Origin is not trusted', 403);
        for (const [id, message] of deliveryInbox)
          if (Date.now() - message.receivedAt > 15 * 60_000) deliveryInbox.delete(id);
        json(res, { data: [...deliveryInbox.values()] });
        return;
      }
      if (url.pathname === '/app/documents' && req.method === 'GET') {
        const tenantId = url.searchParams.get('tenantId');
        if (!tenantId) throw new IamError('INVALID_INPUT', 'tenantId is required');
        await iam.authenticate(credential);
        const documents = await iam.store.find('exampleDocuments', { tenantId });
        const allowed = [];
        for (const document of documents)
          if (
            (
              await iam.authorize({
                ...credential,
                tenantId,
                action: 'documents:read',
                resource: { type: 'document', id: document.id },
              })
            ).allowed
          )
            allowed.push(document);
        json(res, { data: allowed });
        return;
      }
      if (url.pathname.startsWith('/app/documents/') && req.method === 'GET') {
        const document = await iam.store.get(
          'exampleDocuments',
          url.pathname.slice('/app/documents/'.length),
        );
        if (!document) throw new IamError('NOT_FOUND', 'Document not found', 404);
        await iam.require({
          ...credential,
          tenantId: document.tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: document.id },
        });
        json(res, { data: document });
        return;
      }
      if (url.pathname === '/app/documents' && req.method === 'POST') {
        csrf(req, origin);
        const body = await readBody(req);
        if (
          typeof body.tenantId !== 'string' ||
          typeof body.title !== 'string' ||
          body.title.length > 200 ||
          !body.title.trim()
        )
          throw new IamError(
            'INVALID_INPUT',
            'Provide tenantId and a title of at most 200 characters',
          );
        const document = await iam.store.transaction(async (tx) => {
          await iam.require({
            ...credential,
            tenantId: body.tenantId,
            action: 'documents:write',
            resource: { type: 'document-collection', id: body.tenantId },
          });
          const principal = await iam.authenticate(credential);
          const document = await tx.insert('exampleDocuments', {
            id: randomUUID(),
            tenantId: body.tenantId,
            title: body.title,
            classification: 'internal',
            body: 'This document is protected by a tenant-scoped documents:read policy.',
          });
          await tx.insert('audit', {
            id: randomUUID(),
            tenantId: body.tenantId,
            actorId: principal.identity.id,
            action: 'documents:write',
            resourceId: document.id,
            timestamp: Date.now(),
            outcome: 'allow',
          });
          return document;
        });
        json(res, { data: document }, 201);
        return;
      }
      if (url.pathname === '/app/workspaces' && req.method === 'POST') {
        csrf(req, origin);
        const body = await readBody(req);
        if (
          typeof body.tenantId !== 'string' ||
          typeof body.id !== 'string' ||
          !/^[a-z0-9-]{1,64}$/.test(body.id)
        )
          throw new IamError('INVALID_INPUT', 'Provide tenantId and a lowercase workspace id');
        // IAM authorizes iam:resources:create and stores the registration; the application keeps only its own data.
        json(
          res,
          {
            data: await iam.api.resources.register(credential, {
              tenantId: body.tenantId,
              type: 'workspace',
              id: body.id,
              attributes: { archived: false },
            }),
          },
          201,
        );
        return;
      }
      if (url.pathname === '/app/workspaces' && req.method === 'GET') {
        const tenantId = url.searchParams.get('tenantId');
        if (!tenantId) throw new IamError('INVALID_INPUT', 'tenantId is required');
        await iam.authenticate(credential);
        const workspaces = await iam.store.find('resources', { tenantId, type: 'workspace' });
        const allowed = new Map(workspaces.map((workspace) => [workspace.resourceId, []]));
        // Advisory batch decisions render the list; each later read is still enforced individually.
        for (let index = 0; index < workspaces.length; index += 25) {
          const checks = workspaces.slice(index, index + 25).flatMap((workspace) =>
            ['workspaces:read', 'workspaces:manage'].map((action) => ({
              action,
              resource: { type: 'workspace', id: workspace.resourceId },
            })),
          );
          for (const result of (await iam.authorizeMany({ ...credential, tenantId, checks }))
            .results)
            if (result.allowed) allowed.get(result.resource.id).push(result.action);
        }
        json(res, {
          data: workspaces.map((workspace) => ({
            id: workspace.resourceId,
            archived: workspace.attributes.archived,
            allowed: allowed.get(workspace.resourceId),
          })),
        });
        return;
      }
      if (url.pathname === '/app/oauth/clients' && req.method === 'POST') {
        if (!provider) throw new IamError('FEATURE_DISABLED', 'OIDC is not configured', 404);
        csrf(req, origin);
        const body = await readBody(req);
        json(
          res,
          {
            data: await provider.registerClient(credential, {
              tenantId: body.tenantId,
              clientId: body.clientId,
              name: 'Example browser client',
              public: true,
              redirectUris: [`${origin}/oidc/callback`],
              grantTypes: [
                'authorization_code',
                'refresh_token',
                'urn:ietf:params:oauth:grant-type:device_code',
              ],
            }),
          },
          201,
        );
        return;
      }
      if (url.pathname === '/app/oauth/clients' && req.method === 'GET') {
        if (!provider) throw new IamError('FEATURE_DISABLED', 'OIDC is not configured', 404);
        json(res, {
          data: await provider.listClients(credential, {
            tenantId: url.searchParams.get('tenantId'),
          }),
        });
        return;
      }
      // Connected apps: the signed-in account's OAuth consents, and disconnecting one client.
      if (url.pathname === '/app/oauth/grants' && req.method === 'GET') {
        if (!provider) throw new IamError('FEATURE_DISABLED', 'OIDC is not configured', 404);
        json(res, {
          data: await provider.listGrants(credential, {
            tenantId: url.searchParams.get('tenantId'),
          }),
        });
        return;
      }
      if (url.pathname === '/app/oauth/grants' && req.method === 'DELETE') {
        if (!provider) throw new IamError('FEATURE_DISABLED', 'OIDC is not configured', 404);
        csrf(req, origin);
        const body = await readBody(req);
        json(res, {
          data: await provider.revokeGrants(credential, {
            tenantId: body.tenantId,
            clientId: body.clientId,
          }),
        });
        return;
      }
      if (url.pathname === '/app/scim/connections' && req.method === 'POST') {
        csrf(req, origin);
        const body = await readBody(req);
        json(
          res,
          {
            data: await scim.createConnection(credential, {
              tenantId: body.tenantId,
              name: body.name,
              expiresIn: 3600,
            }),
          },
          201,
        );
        return;
      }
      if (provider && url.pathname === '/.well-known/oauth-authorization-server/oauth') {
        await provider.nodeHandler(req, res);
        return;
      }
      await iam.nodeHandler(req, res);
    } catch (error) {
      if (res.writableEnded) return;
      const known = error instanceof IamError;
      json(
        res,
        {
          error: {
            code: known ? error.code : 'INTERNAL_ERROR',
            message: known ? error.message : 'The example request failed.',
          },
        },
        known ? error.status : 500,
      );
    }
  });
  let dispatching = false;
  const worker = setInterval(async () => {
    if (dispatching) return;
    dispatching = true;
    try {
      await iam.auth.dispatchOutbox();
      await iam.dispatchAuditHooks();
    } catch {
      /* Durable messages are retried on the next interval. */
    } finally {
      dispatching = false;
    }
  }, 1000);
  worker.unref();
  const listenPort = port ?? Number(process.env.PORT ?? (new URL(origin).port || 3000));
  if (!Number.isSafeInteger(listenPort) || listenPort < 0 || listenPort > 65535)
    throw new Error('PORT must be a valid TCP port.');
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(listenPort, '127.0.0.1', resolve);
  });
  if (!quiet)
    console.log(
      `Better IAM example listening at ${origin}. ${demoDelivery ? 'Local development inbox is enabled.' : 'Delivery uses your configured webhook.'}`,
    );
  const close = async () => {
    clearInterval(worker);
    await new Promise((resolve) => server.close(resolve));
    while (dispatching) await new Promise((resolve) => setTimeout(resolve, 10));
    await iam.store.close();
  };
  process.once('SIGINT', () => {
    void close();
  });
  process.once('SIGTERM', () => {
    void close();
  });
  return { iam, provider, scim, server, close };
}
