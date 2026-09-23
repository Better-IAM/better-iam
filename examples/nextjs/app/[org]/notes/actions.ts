'use server';
import { iamNext } from '@/lib/iam';

const notes: string[] = [];

/** A guarded server action for useActionState: IAM failures come back as { ok: false, error }. */
export const addNote = iamNext.action(
  async (session, _previous: unknown, form: FormData) => {
    const text = String(form.get('text') ?? '').trim();
    if (!text) throw Object.assign(new Error('Write something first'), { code: 'INVALID_INPUT' });
    notes.push(`${session.identity.name}: ${text}`);
    return { notes: [...notes] };
  },
  { authorize: { action: 'documents:write', resource: () => ({ type: 'document', id: 'notes' }) } },
);
