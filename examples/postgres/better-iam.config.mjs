import { postgresAdapter } from 'better-iam/adapter-postgres';
import { createExampleConfig } from '@better-iam/example-shared/config';

if (!process.env.DATABASE_URL) throw new Error('Set DATABASE_URL for the PostgreSQL example.');
export default createExampleConfig(postgresAdapter({ connectionString: process.env.DATABASE_URL }));
