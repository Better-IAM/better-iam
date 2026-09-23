import { getIam } from '@/lib/iam';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * The inference gateway: Anthropic `POST /api/ai/v1/messages`, OpenAI `POST /api/ai/v1/chat/completions` and
 * `GET /api/ai/v1/models`. Callers send a Better IAM credential (API key, agent key or delegated session) as the API
 * key; the gateway checks model access and budgets, calls the provider with its sealed key, and meters the tokens.
 */
let gateway: ((request: Request) => Promise<Response>) | undefined;

async function handle(request: Request): Promise<Response> {
  gateway ??= (await getIam()).inference.gateway({ basePath: '/api/ai' });
  return gateway(request);
}

export { handle as GET, handle as POST };
