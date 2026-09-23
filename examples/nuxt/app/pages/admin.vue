<script setup lang="ts">
// Needs a session and an allow decision for iam:identities:read on the session's tenant; otherwise a 403 error page.
definePageMeta({ iam: { action: 'iam:identities:read' } });
</script>

<template>
  <main>
    <h1 id="admin-title">Members</h1>
  </main>
</template>
