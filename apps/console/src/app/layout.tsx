import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './globals.css';

export const metadata: Metadata = {
  title: { template: '%s | Better IAM Console', default: 'Better IAM Console' },
  description: 'Administration panel and multi-tenant cloud console built on Better IAM.',
  applicationName: 'Better IAM Console',
  // A signed-in application: keep its pages out of search results. Icons from apps/docs/scripts/generate-icons.mjs.
  robots: { index: false, follow: false },
  icons: {
    icon: [
      { url: '/favicon.ico', sizes: '32x32' },
      { url: '/icon.svg', type: 'image/svg+xml' },
    ],
    apple: [{ url: '/apple-touch-icon.png', sizes: '180x180', type: 'image/png' }],
  },
  formatDetection: { telephone: false, email: false, address: false },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
