<script setup lang="ts">
const route = useRoute();
const client = useIamClient();
const { setSession } = useIamSession();
const { data: demo } = await useFetch('/api/demo');
const email = ref('member@example.test');
const password = ref('');
const error = ref('');

async function submit() {
  error.value = '';
  try {
    const result = await client.auth.signIn({
      tenantId: demo.value?.tenantId ?? '',
      email: email.value,
      password: password.value,
    });
    if (!('token' in result)) {
      error.value = 'This account needs a second factor; finish it with client.auth.verifyMfa.';
      return;
    }
    setSession(await client.auth.getSession());
    await navigateTo(typeof route.query.next === 'string' ? route.query.next : '/');
  } catch (failure) {
    error.value = failure instanceof Error ? failure.message : String(failure);
  }
}
</script>

<template>
  <main>
    <h1>Sign in</h1>
    <form @submit.prevent="submit">
      <label>Email <input v-model="email" type="email" autocomplete="username" /></label>
      <label>
        Password <input v-model="password" type="password" autocomplete="current-password" />
      </label>
      <button type="submit">Sign in</button>
      <p v-if="error" role="alert">{{ error }}</p>
    </form>
  </main>
</template>
