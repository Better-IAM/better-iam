<script setup lang="ts">
definePageMeta({ iam: false });
const { session } = useIamSession();
</script>

<template>
  <main>
    <h1>Better IAM + Nuxt</h1>
    <p v-if="session" id="greeting">Signed in as {{ session.identity.email }}</p>
    <p v-else id="greeting">Signed out</p>
    <IamCan v-if="session" :tenant-id="session.session.tenantId" action="iam:identities:read">
      <p id="members-link"><NuxtLink to="/admin">Manage members</NuxtLink></p>
      <template #fallback><p id="members-denied">You cannot manage members.</p></template>
      <template #loading><p>Checking access…</p></template>
    </IamCan>
  </main>
</template>
