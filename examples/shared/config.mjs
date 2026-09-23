import { IamError } from 'better-iam';

export const deliveryInbox = new Map();
export const demoDelivery = process.env.DEMO_DELIVERY === '1';

/** Both example databases use the same application behavior and IAM configuration. */
export function createExampleConfig(database) {
  const secret = process.env.BETTER_IAM_SECRET;
  if (!secret || secret.length < 32)
    throw new Error('Set BETTER_IAM_SECRET to a stable random secret of at least 32 characters.');
  const baseURL = process.env.BETTER_IAM_BASE_URL ?? 'http://localhost:3000';
  const url = new URL(baseURL);
  if (demoDelivery && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))
    throw new Error('DEMO_DELIVERY is restricted to a loopback application URL.');
  const deliveryURL = process.env.DELIVERY_WEBHOOK_URL;
  if (!demoDelivery && (!deliveryURL || new URL(deliveryURL).protocol !== 'https:'))
    throw new Error(
      'Set DEMO_DELIVERY=1 for local development, or configure an HTTPS DELIVERY_WEBHOOK_URL.',
    );
  const deliver = async (message) => {
    if (demoDelivery) {
      deliveryInbox.set(message.id, { ...message, receivedAt: Date.now() });
      while (deliveryInbox.size > 100) deliveryInbox.delete(deliveryInbox.keys().next().value);
      return;
    }
    const headers = { 'content-type': 'application/json', 'idempotency-key': message.id };
    if (process.env.DELIVERY_WEBHOOK_TOKEN)
      headers.authorization = `Bearer ${process.env.DELIVERY_WEBHOOK_TOKEN}`;
    const response = await fetch(deliveryURL, {
      method: 'POST',
      headers,
      body: JSON.stringify(message),
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error('Delivery provider rejected the message.');
  };
  return {
    database,
    secret,
    baseURL,
    trustedOrigins: [url.origin],
    authentication: {
      signUpEnabled: true,
      requireEmailVerification: true,
      passwordlessEmail: true,
      passwordlessSms: true,
      sendEmail: deliver,
      sendSms: deliver,
      passkeys: { rpID: url.hostname, rpName: 'Better IAM example' },
    },
    permissions: {
      mode: 'tenant-defined',
      resourceTypes: {
        // Application-owned types are resolved by resolveResource below.
        document: {
          description: 'A document stored by the application',
          actions: ['documents:read', 'documents:write'],
          attributes: { classification: 'string' },
        },
        'document-collection': {
          description: "A tenant's document collection",
          actions: ['documents:write'],
        },
        // Managed types are registered with IAM through iam.api.resources; no resolver code is needed.
        workspace: {
          description: 'A workspace registered with IAM',
          managed: true,
          actions: ['workspaces:read', 'workspaces:manage'],
          attributes: { archived: 'boolean' },
        },
      },
    },
    async resolveResource(reference) {
      if (reference.type === 'document-collection') {
        const tenant = await database.get('tenants', reference.id);
        if (!tenant) throw new IamError('NOT_FOUND', 'Document collection not found', 404);
        return { type: 'document-collection', id: tenant.id, tenantId: tenant.id };
      }
      if (reference.type !== 'document')
        throw new IamError('NOT_FOUND', 'Unknown application resource type', 404);
      const document = await database.get('exampleDocuments', reference.id);
      if (!document) throw new IamError('NOT_FOUND', 'Document not found', 404);
      // Ownership comes from application storage, never the request's tenant claim.
      return {
        type: 'document',
        id: document.id,
        tenantId: document.tenantId,
        attributes: { classification: document.classification },
      };
    },
  };
}
