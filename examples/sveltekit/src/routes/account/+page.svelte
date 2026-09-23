<script lang="ts">
  let { data, form } = $props();
</script>

<h1>Account</h1>
<p id="account-email">{data.email}</p>
<form method="POST" action="?/rename">
  <label>Name <input name="name" value={data.name} /></label>
  <button>Rename</button>
</form>
{#if form && 'code' in form}<p id="rename-error">{form.code}</p>{/if}
