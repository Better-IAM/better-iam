# NestJS example

A NestJS 12 application built on `@better-iam/nestjs`, running on Express with SQLite. With `DEMO_SEED=1` it creates the root tenant, three registered projects, and one member:

| Account               | Password                          | Access                                            |
| --------------------- | --------------------------------- | ------------------------------------------------- |
| `member@example.test` | `demo member password for nestjs` | `projects:read` on `apollo` and `gemini` via role |

```bash
pnpm build
pnpm --filter @better-iam/example-nestjs build
BETTER_IAM_SECRET=change-me-to-32-or-more-characters DEMO_SEED=1 pnpm --filter @better-iam/example-nestjs start
pnpm --filter @better-iam/example-nestjs smoke
```

The smoke test starts the compiled app against a fresh database and exercises every feature below.

| File                         | Shows                                                                                                  |
| ---------------------------- | ------------------------------------------------------------------------------------------------------ |
| `src/app.module.ts`          | `IamModule.forRoot({ guard: true, mount: true, dispatchIntervalMs })`: global guard, served IAM API    |
| `src/projects.controller.ts` | `@Public`, `@CurrentIdentity`, `@Authorize` with a route parameter, `@FilterAccessible`, `@RequireMfa` |
| `src/audit.listener.ts`      | `@OnIamEvent` on a provider method                                                                     |
| `src/main.ts`                | `rawBody: true` so the IAM mount forwards form posts unchanged                                         |
| `src/iam.ts`                 | the server instance with a managed `project` type, and the demo seed                                   |

Sign in with `POST /api/iam/auth/signIn` (`x-better-iam: 1`, JSON body `{ tenantId, email, password }`; the tenant id is on `GET /status`). Then call `GET /projects` with the returned cookie or `authorization: Bearer <token>`. Mercury is registered but not granted, so it's filtered out of the list and `GET /projects/mercury` answers 403. Archiving needs `projects:manage` and an MFA session, so the member gets `MFA_REQUIRED`.
