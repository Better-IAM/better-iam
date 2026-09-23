import { sqliteAdapter } from 'better-iam/adapter-sqlite';
import { createExampleConfig } from '@better-iam/example-shared/config';

export default createExampleConfig(
  sqliteAdapter({ filename: process.env.BETTER_IAM_DATABASE ?? './better-iam.db' }),
);
