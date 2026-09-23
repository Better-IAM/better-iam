import { demo } from '../plugins/seed';

/** Demo only: the seeded tenant id the login form signs in to. */
export default defineEventHandler(() => ({ tenantId: demo.tenantId ?? null }));
