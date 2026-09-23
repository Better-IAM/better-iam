import { NotesForm } from './notes-form';

export default function Notes() {
  return (
    <main>
      <h1>Notes</h1>
      <p>
        Adding a note runs a server action wrapped by <code>iamNext.action</code>, which enforces{' '}
        <code>documents:write</code>. The reader account is denied; the result reaches the form.
      </p>
      <NotesForm />
    </main>
  );
}
