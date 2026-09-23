import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';
import { demo } from './demo.js';
import { iam, seed } from './iam.js';

await iam.initialize();
if (process.env.DEMO_SEED === '1') demo.tenantId = await seed();

// rawBody lets the IAM mount forward form posts (SAML) byte for byte.
const app = await NestFactory.create(AppModule, { rawBody: true });
app.enableShutdownHooks();
await app.listen(Number(process.env.PORT ?? 3000), process.env.HOST ?? '127.0.0.1');
