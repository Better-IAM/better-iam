<script lang="ts">
  import { createIamClient } from '@better-iam/client';
  import { createIam, setIamContext } from '@better-iam/svelte';
  import type { iam as server } from '$lib/server/iam';

  let { data, children } = $props();
  // One client and session store for the app; the server load supplies the first session.
  const iam = setIamContext(
    createIam({
      // svelte-ignore state_referenced_locally
      client: createIamClient<typeof server>({ baseURL: data.origin }),
      // svelte-ignore state_referenced_locally
      initialSession: data.session,
    }),
  );
  const { session } = iam;
  // Form actions (sign in, sign out) re-run the layout load; keep the store on the server's answer.
  $effect(() => iam.setSession(data.session));
</script>

<header>
  {#if $session.session}
    <p id="greeting">Signed in as {$session.session.identity.email}</p>
    <form method="POST" action="/logout"><button>Sign out</button></form>
  {:else}
    <p id="greeting">Signed out</p>
    <a href="/login">Sign in</a>
  {/if}
</header>

<main>{@render children()}</main>
