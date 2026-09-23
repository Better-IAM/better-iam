# Nuxt example

A Nuxt 4 app using `@better-iam/nuxt`: `server/iam.ts` is the instance, pages declare access with `definePageMeta({ iam })`, `app.vue` and `index.vue` use the auto-imported composables and `<IamCan>`, and `server/api/me.get.ts` uses the server utilities. With `DEMO_SEED=1`, `server/plugins/seed.ts` bootstraps a fresh database with a member, `member@example.test` / `demo member password for nuxt`. It discards the root authenticator secret, so it is for demos only.

```bash
pnpm --filter @better-iam/example-nuxt build
```

```bash
pnpm --filter @better-iam/example-nuxt smoke
```

The smoke test starts the production build on a free port with a temporary database. It checks the anonymous redirect (`/account` → `/login?next=/account`), sign-in through the mounted API, the server-rendered session, the `IamCan` decision resolved before the HTML is sent and handed to the browser in the payload, the 403 on `/admin`, `/api/me`, and `/api/iam/health`.

To run it yourself, set `BETTER_IAM_SECRET` (32+ characters), `BETTER_IAM_BASE_URL` (the origin you browse, e.g. `http://localhost:3000`), `DEMO_SEED=1`, and optionally `BETTER_IAM_DATABASE`, then run `pnpm --filter @better-iam/example-nuxt start`.
