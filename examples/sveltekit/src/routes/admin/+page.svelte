<script lang="ts">
  let { data } = $props();
</script>

<!-- Only people with iam:identities:read on their tenant reach this page (`handle` rule + guarded load). -->
<h1 id="admin-title">Admin</h1>
<ul>
  {#each data.members as member (member.id)}
    <li>{member.email}</li>
  {/each}
</ul>
