<script setup lang="ts">
const { session, isAuthenticated, signOut } = useIamSession();
async function leave() {
  await signOut();
  await navigateTo('/');
}
</script>

<template>
  <div>
    <nav>
      <NuxtLink to="/">Home</NuxtLink> · <NuxtLink to="/account">Account</NuxtLink> ·
      <NuxtLink to="/admin">Admin</NuxtLink>
      <span v-if="isAuthenticated" id="whoami">
        · {{ session?.identity.name }} <button @click="leave">Sign out</button>
      </span>
      <span v-else> · <NuxtLink to="/login">Sign in</NuxtLink></span>
    </nav>
    <NuxtPage />
  </div>
</template>
