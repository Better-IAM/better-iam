import { json } from '@sveltejs/kit';
import { demo } from '$lib/server/iam';

/** Tells the smoke test which tenant the seed created. */
export const GET = () => json({ tenantId: demo.tenantId ?? null });
