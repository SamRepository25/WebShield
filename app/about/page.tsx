import Link from 'next/link';
import { Shield, Search, Lock, ArrowRight } from 'lucide-react';
import { AppShell } from '@/components/app-shell';
import { Button } from '@/components/ui/button';

export const metadata = {
  title: 'About',
  description: 'Learn about WebShield and its website security analysis tools.',
};

export default function AboutPage() {
  return (
    <AppShell>
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 grid-bg opacity-20" aria-hidden="true" />
        <div className="relative mx-auto max-w-5xl px-4 py-16 sm:px-6 sm:py-24 lg:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 ring-1 ring-primary/30">
              <Shield className="h-7 w-7 text-primary" aria-hidden="true" />
            </div>
            <p className="mt-6 text-sm font-semibold uppercase tracking-[0.2em] text-primary">About WebShield</p>
            <h1 className="mt-3 text-4xl font-bold tracking-tight sm:text-6xl">Understand your website's security posture.</h1>
            <p className="mt-6 text-base leading-8 text-muted-foreground sm:text-lg">
              WebShield is a modern website security analyzer built to make common web security checks fast, clear, and actionable. It examines HTTPS configuration, security headers, SSL/TLS information, and common security signals to produce an easy-to-understand report.
            </p>
          </div>

          <div className="mt-14 grid gap-6 md:grid-cols-3">
            <div className="glass rounded-2xl p-6">
              <Search className="h-6 w-6 text-primary" aria-hidden="true" />
              <h2 className="mt-4 text-lg font-semibold">Scan</h2>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">Enter a public website URL and start a security analysis without creating an account.</p>
            </div>
            <div className="glass rounded-2xl p-6">
              <Lock className="h-6 w-6 text-primary" aria-hidden="true" />
              <h2 className="mt-4 text-lg font-semibold">Analyze</h2>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">Review HTTPS status, response headers, security controls, and detected security findings.</p>
            </div>
            <div className="glass rounded-2xl p-6">
              <Shield className="h-6 w-6 text-primary" aria-hidden="true" />
              <h2 className="mt-4 text-lg font-semibold">Improve</h2>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">Use prioritized recommendations to understand where additional hardening may help.</p>
            </div>
          </div>

          <div className="glass mt-6 rounded-2xl p-6 sm:p-8">
            <h2 className="text-2xl font-bold">Built for practical security checks</h2>
            <p className="mt-4 leading-7 text-muted-foreground">
              WebShield focuses on security information that can be observed from a website's public HTTP response. It is designed as an assessment and education tool, not as a replacement for a full penetration test, source-code audit, or professional security assessment.
            </p>
            <div className="mt-6">
              <Button asChild className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90">
                <Link href="/#scanner">
                  Scan a Website
                  <ArrowRight className="h-4 w-4" aria-hidden="true" />
                </Link>
              </Button>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
