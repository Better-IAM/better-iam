import type { ReactNode } from 'react';

export const metadata = { title: 'Better IAM × Next.js' };

const styles = `
  :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
  body { margin: 0 auto; max-width: 44rem; padding: 2rem 1rem; line-height: 1.5; }
  header { display: flex; justify-content: space-between; align-items: center; gap: 1rem; border-bottom: 1px solid #8884; padding-bottom: .75rem; margin-bottom: 1.5rem; }
  form { display: grid; gap: .6rem; max-width: 22rem; }
  input, button { font: inherit; padding: .45rem .6rem; border-radius: .4rem; border: 1px solid #8886; }
  button { cursor: pointer; background: #2563eb; color: white; border: 0; }
  .inline { display: inline; }
  .error { color: #dc2626; }
  .ok { color: #16a34a; }
  code { background: #8882; padding: .1rem .3rem; border-radius: .25rem; }
  table { border-collapse: collapse; } td, th { border: 1px solid #8884; padding: .3rem .6rem; text-align: left; }
`;

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <style>{styles}</style>
        {children}
      </body>
    </html>
  );
}
