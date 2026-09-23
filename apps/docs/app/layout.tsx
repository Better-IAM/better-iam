import { RootProvider } from 'fumadocs-ui/provider/next';
import type { Metadata, Viewport } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import SearchDialog from '@/components/search';
import {
  pageMetadata,
  siteDescription,
  siteImages,
  siteTitle,
  siteVerification,
} from '@/lib/metadata';
import { appName, creator, siteUrl } from '@/lib/shared';
import './global.css';

// BoardUI's type ramp is drawn for Inter; its code face is JetBrains Mono (styles/theme.css reads both variables).
const sans = Inter({ subsets: ['latin'], variable: '--font-inter' });
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono-source' });

// Defaults for every page. Pages set their own title, description, canonical URL, and social card through
// pageMetadata(); these cover the rest (404s included). Icons come from scripts/generate-icons.mjs, and
// app/manifest.ts adds the web app manifest link.
export const metadata: Metadata = {
  ...pageMetadata({
    title: siteTitle,
    absolute: true,
    description: siteDescription,
    image: siteImages.home,
  }),
  metadataBase: new URL(siteUrl),
  title: { template: `%s | ${appName}`, default: siteTitle },
  applicationName: appName,
  authors: [{ name: creator }],
  creator,
  publisher: creator,
  category: 'technology',
  // Version numbers and ports in code samples are not phone numbers.
  formatDetection: { telephone: false, email: false, address: false },
  robots: {
    googleBot: { 'max-image-preview': 'large', 'max-snippet': -1, 'max-video-preview': -1 },
  },
  icons: {
    // `sizes` on the ICO keeps browsers that read SVG favicons on the SVG.
    icon: [
      { url: '/favicon.ico', sizes: '32x32' },
      { url: '/icon.svg', type: 'image/svg+xml' },
    ],
    apple: [{ url: '/apple-touch-icon.png', sizes: '180x180', type: 'image/png' }],
  },
  appleWebApp: { title: appName, statusBarStyle: 'default' },
  verification: siteVerification(),
};

export const viewport: Viewport = {
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#ffffff' },
    { media: '(prefers-color-scheme: dark)', color: '#121212' },
  ],
};

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`} suppressHydrationWarning>
      <body className="flex min-h-screen flex-col font-sans antialiased">
        <RootProvider search={{ SearchDialog }}>{children}</RootProvider>
      </body>
    </html>
  );
}
