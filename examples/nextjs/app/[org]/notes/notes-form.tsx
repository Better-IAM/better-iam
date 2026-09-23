'use client';
import { useActionState } from 'react';
import { addNote } from './actions';

export function NotesForm() {
  const [state, action, pending] = useActionState(addNote, null);
  return (
    <>
      <form action={action}>
        <input name="text" placeholder="A note" />
        <button type="submit" disabled={pending}>
          Add note
        </button>
      </form>
      {state?.ok === false && (
        <p className="error" role="alert">
          {state.error.code}: {state.error.message}
        </p>
      )}
      {state?.ok && (
        <ul>
          {state.data.notes.map((note, index) => (
            <li key={index}>{note}</li>
          ))}
        </ul>
      )}
    </>
  );
}
