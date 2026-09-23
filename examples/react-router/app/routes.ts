import { type RouteConfig, index, route } from '@react-router/dev/routes';

export default [
  index('routes/home.tsx'),
  route('login', 'routes/login.tsx'),
  route('logout', 'routes/logout.tsx'),
  route('account', 'routes/account.tsx'),
  route('admin', 'routes/admin.tsx'),
  route('api/me', 'routes/api.me.ts'),
  route('api/demo', 'routes/api.demo.ts'),
  // The IAM HTTP API (sign-in, sessions, and every API group the client calls).
  route('api/iam/*', 'routes/api.iam.ts'),
] satisfies RouteConfig;
