# SvelteKit example

A SvelteKit 2 / Svelte 5 app (adapter-node) using `@better-iam/svelte`. The pieces:

- `src/lib/server/iam.ts` holds the instance and `createIamKit` with `protect` rules for `/account` and `/admin`.
- `src/hooks.server.ts` exports `handle`, which serves `/api/iam/**` and fills `event.locals.iam`.
- `+layout.server.ts` loads the session and a decision for the browser stores in `+layout.svelte` / `+page.svelte`.
- The login and logout form actions use the in-process client (no JavaScript needed).
- `/account` is a guarded load with a guarded `rename` action that returns `fail(403)` for plain members.
- `/admin` is a guarded load listing members.
- `/api/me` is an endpoint using `locals.iam`.

With `DEMO_SEED=1`, the `init` hook bootstraps a fresh database with a member: `member@example.test` / `demo member password for sveltekit`. It discards the root authenticator secret, so it is for demos only.

```bash
pnpm --filter @better-iam/example-sveltekit build
```

```bash
pnpm --filter @better-iam/example-sveltekit smoke
```

The smoke test starts the production build on a free port with a temporary database. It checks:

- signed-out redirects: `/account` → `/login?next=%2Faccount`, for a page request and for a client-side `__data.json` request
- a failed sign-in, then sign-in through the form action with the cookie set and a redirect to `next`
- the server-rendered session and decision
- the guarded `rename` action's `fail(403)`
- the 403 on `/admin`
- `/api/me`, the mounted IAM API, and sign-out clearing the cookie and ending the session

`pnpm --filter @better-iam/example-sveltekit check` runs `svelte-check`.

To run it yourself, set `BETTER_IAM_SECRET` (32+ characters), `BETTER_IAM_BASE_URL` and `ORIGIN` (the origin you browse, e.g. `http://localhost:3000`), `DEMO_SEED=1`, and optionally `BETTER_IAM_DATABASE` and `PORT`. Then run `pnpm --filter @better-iam/example-sveltekit start`.
