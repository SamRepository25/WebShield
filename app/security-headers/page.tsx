import Link from 'next/link';
import { ArrowLeft, ShieldCheck } from 'lucide-react';
import { AppShell } from '@/components/app-shell';
import { Button } from '@/components/ui/button';

export const metadata = {
  title: 'Security Headers Guide',
  description: 'Learn how common HTTP security headers protect websites.',
};

const headers = [
  ['Content-Security-Policy', 'Controls which resources a browser may load and helps reduce XSS and injection attacks.'],
  ['Strict-Transport-Security', 'Forces browsers to use HTTPS and helps prevent downgrade and protocol attacks.'],
  ['X-Frame-Options', 'Controls whether a page can be embedded in a frame, helping prevent clickjacking.'],
  ['X-Content-Type-Options', 'Prevents MIME-type sniffing so browsers respect the declared Content-Type.'],
  ['Referrer-Policy', 'Controls how much referrer information is shared with other sites.'],
  ['Permissions-Policy', 'Restricts access to browser features such as camera, microphone, and geolocation.'],
];

export default function SecurityHeadersPage() {
  return (
    <AppShell>
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 grid-bg opacity-20" aria-hidden="true" />
        <div className="relative mx-auto max-w-5xl px-4 py-16 sm:px-6 sm:py-24 lg:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 ring-1 ring-primary/30">
              <ShieldCheck className="h-7 w-7 text-primary" aria-hidden="true" />
            </div>
            <p className="mt-6 text-sm font-semibold uppercase tracking-[0.2em] text-primary">Security Headers Guide</p>
            <h1 className="mt-3 text-4xl font-bold tracking-tight sm:text-6xl">Build stronger browser-side defenses.</h1>
            <p className="mt-6 text-base leading-8 text-muted-foreground sm:text-lg">HTTP security headers let a website tell browsers how content should be loaded, embedded, and accessed. WebShield checks these headers and explains missing or weak configurations.</p>
          </div>

          <div className="mt-12 grid gap-5 md:grid-cols-2">
            {headers.map(([name, description]) => (
              <section key={name} className="glass rounded-2xl p-6">
                <h2 className="text-lg font-semibold">{name}</h2>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">{description}</p>
              </section>
            ))}
          </div>

          <div className="glass mt-6 rounded-2xl p-6 sm:p-8">
            <h2 className="text-2xl font-bold">Using WebShield</h2>
            <p className="mt-4 leading-7 text-muted-foreground">Run a scan against a public website to see which security headers are present, missing, or configured weakly. Recommendations are based on the HTTP response observed by the scanner.</p>
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
