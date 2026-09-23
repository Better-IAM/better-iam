<script setup lang="ts">
// Signed-out visitors are redirected to /login?next=/account, on the server and in the browser.
definePageMeta({ iam: true });
const { session } = useIamSession();
</script>

<template>
  <main>
    <h1>Account</h1>
    <p id="account-email">{{ session?.identity.email }}</p>
  </main>
</template>
