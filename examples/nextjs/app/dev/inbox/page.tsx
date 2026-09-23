import { notFound } from 'next/navigation';
import { inbox } from '@/lib/iam';

// Development only: shows the emails the demo captured instead of sending, with the links they would carry.
export default function Inbox() {
  if (process.env.NODE_ENV === 'production') notFound();
  const messages = [...inbox].reverse();
  return (
    <main>
      <h1>Development inbox</h1>
      <table>
        <tbody>
          {messages.map((message) => (
            <tr key={message.id} data-template={message.template} data-to={message.to}>
              <td>{message.to}</td>
              <td>
                <code>{message.template}</code>
              </td>
              <td>
                {message.template === 'password-reset' ? (
                  <a
                    href={`/reset?${new URLSearchParams({ tenantId: message.tenantId, token: message.payload.token ?? '' }).toString()}`}
                  >
                    Reset link
                  </a>
                ) : (
                  <code data-token>{message.payload.token ?? message.payload.code ?? ''}</code>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
