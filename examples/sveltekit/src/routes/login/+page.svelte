<script lang="ts">
  let { form } = $props();
</script>

<h1>Sign in</h1>
<form method="POST">
  <label>Email <input name="email" type="email" autocomplete="username" value={form?.email ?? ''} /></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" /></label>
  <button>Sign in</button>
</form>
{#if form?.message}<p id="login-error">{form.message}</p>{/if}
