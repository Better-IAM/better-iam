<script lang="ts">
  import { toStore } from 'svelte/store';
  import { getIamContext } from '@better-iam/svelte';

  let { data } = $props();
  const iam = getIamContext();
  // `toStore` turns the reactive input into a store, so the check follows the session after navigations.
  const canReadMembers = iam.can(
    toStore(() => {
      const tenantId = data.session?.session.tenantId ?? '';
      return { tenantId, action: 'iam:identities:read', enabled: Boolean(tenantId) };
    }),
    // Seeded from the server's decision: server and browser render the same thing without a second request.
    // svelte-ignore state_referenced_locally
    { initial: data.permissions[0]?.allowed },
  );
</script>

<h1>Better IAM + SvelteKit</h1>
{#if $canReadMembers.allowed}
  <p id="members-allowed">You can read the member directory.</p>
{:else}
  <p id="members-denied">The member directory is not available to you.</p>
{/if}
<p><a href="/account">Account</a> · <a href="/admin">Admin</a></p>
