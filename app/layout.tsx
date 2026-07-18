import './globals.css';
import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import { Providers } from '@/components/providers';
import { Toaster } from '@/components/ui/toaster';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  metadataBase: new URL('https://webshield.app'),
  title: {
    default: 'WebShield — Website Security Scanner',
    template: '%s | WebShield',
  },
  description:
    'Scan any website for security vulnerabilities, HTTPS status, security headers, and get actionable recommendations. Free, instant, no signup required.',
  keywords: [
    'website security scanner',
    'security headers check',
    'HTTPS checker',
    'SSL certificate checker',
    'CSP analyzer',
    'HSTS check',
    'vulnerability scanner',
    'web security audit',
  ],
  authors: [{ name: 'WebShield' }],
  creator: 'WebShield',
  themeColor: '#0a0e1a',
  openGraph: {
    title: 'WebShield — Website Security Scanner',
    description:
      'Scan any website for security vulnerabilities, HTTPS status, security headers, and get actionable recommendations.',
    type: 'website',
    siteName: 'WebShield',
    url: 'https://webshield.app',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'WebShield — Website Security Scanner',
    description:
      'Scan any website for security vulnerabilities, HTTPS status, security headers, and get actionable recommendations.',
  },
  robots: {
    index: true,
    follow: true,
  },
};

const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'WebApplication',
  name: 'WebShield',
  description:
    'Website security scanner that analyzes HTTPS, security headers, SSL certificates, and vulnerabilities.',
  applicationCategory: 'SecurityApplication',
  operatingSystem: 'Web',
  offers: {
    '@type': 'Offer',
    price: '0',
    priceCurrency: 'USD',
  },
  url: 'https://webshield.app',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body className={inter.className}>
        <Providers>
          {children}
          <Toaster />
        </Providers>
      </body>
    </html>
  );
}
