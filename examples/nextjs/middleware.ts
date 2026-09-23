import { NextResponse } from 'next/server';
import { createIamMiddleware } from '@better-iam/next/edge';

export const middleware = createIamMiddleware({
  loginPath: '/login',
  publicPaths: [
    '/',
    '/api/documents/*',
    '/api/whoami',
    '/api/cron',
    '/forgot',
    '/reset',
    '/dev/**',
  ],
  signedInRedirect: '/acme',
  next: (init) => NextResponse.next(init),
});

export const config = { matcher: ['/((?!_next|favicon.ico).*)'] };
