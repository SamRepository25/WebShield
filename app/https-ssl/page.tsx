import Link from 'next/link';
import { ArrowLeft, Lock, ShieldCheck } from 'lucide-react';
import { AppShell } from '@/components/app-shell';
import { Button } from '@/components/ui/button';

export const metadata = {
  title: 'HTTPS & SSL',
  description: 'Understand HTTPS, TLS, SSL certificates, redirects, and HSTS.',
};

const checks = [
  ['HTTPS enabled', 'Confirms whether the website can be reached securely over HTTPS.'],
  ['HTTP to HTTPS redirect', 'Checks whether plain HTTP requests are redirected to the secure HTTPS version.'],
  ['TLS protocol', 'Reports the TLS protocol observed by the scanner, helping identify the transport security level.'],
  ['Certificate validity', 'Checks certificate validity, issuer information, and the certificate expiration date.'],
  ['HSTS', 'Checks for Strict-Transport-Security and whether the configuration is suitable for stronger HTTPS enforcement.'],
];

export default function HttpsSslPage() {
  return (
    <AppShell>
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 grid-bg opacity-20" aria-hidden="true" />
        <div className="relative mx-auto max-w-5xl px-4 py-16 sm:px-6 sm:py-24 lg:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 ring-1 ring-primary/30">
              <Lock className="h-7 w-7 text-primary" aria-hidden="true" />
            </div>
            <p className="mt-6 text-sm font-semibold uppercase tracking-[0.2em] text-primary">HTTPS & SSL</p>
            <h1 className="mt-3 text-4xl font-bold tracking-tight sm:text-6xl">Understand your transport security.</h1>
            <p className="mt-6 text-base leading-8 text-muted-foreground sm:text-lg">HTTPS protects data in transit between browsers and websites. WebShield examines the public TLS and certificate information it can observe during a scan.</p>
          </div>

          <div className="mt-12 space-y-5">
            {checks.map(([title, description]) => (
              <section key={title} className="glass rounded-2xl p-6 sm:p-7">
                <div className="flex items-start gap-4">
                  <ShieldCheck className="mt-0.5 h-6 w-6 shrink-0 text-primary" aria-hidden="true" />
                  <div>
                    <h2 className="text-lg font-semibold">{title}</h2>
                    <p className="mt-2 text-sm leading-6 text-muted-foreground">{description}</p>
                  </div>
                </div>
              </section>
            ))}
          </div>

          <div className="glass mt-6 rounded-2xl p-6 sm:p-8">
            <h2 className="text-2xl font-bold">What a good result means</h2>
            <p className="mt-4 leading-7 text-muted-foreground">A valid certificate, modern TLS, HTTPS enforcement, and sensible HSTS configuration provide a strong transport-security baseline. They do not, by themselves, guarantee that an application is free of vulnerabilities.</p>
          </div>

          <div className="mt-10 flex justify-center">
            <Button asChild variant="outline" className="gap-2">
              <Link href="/">
                <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                Back to WebShield
              </Link>
            </Button>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
