import { demo, ready } from '../iam.server';

/** Tells the smoke test which tenant the seed created. */
export async function loader() {
  await ready;
  return Response.json({ tenantId: demo.tenantId ?? null });
}
