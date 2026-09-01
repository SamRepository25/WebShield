import Link from 'next/link';
import { ArrowLeft, Lock, Shield } from 'lucide-react';
import { AppShell } from '@/components/app-shell';
import { Button } from '@/components/ui/button';

export const metadata = {
  title: 'Privacy',
  description: 'WebShield privacy information and data-handling practices.',
};

export default function PrivacyPage() {
  return (
    <AppShell>
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 grid-bg opacity-20" aria-hidden="true" />
        <div className="relative mx-auto max-w-4xl px-4 py-16 sm:px-6 sm:py-24 lg:px-8">
          <div className="text-center">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 ring-1 ring-primary/30">
              <Lock className="h-7 w-7 text-primary" aria-hidden="true" />
            </div>
            <p className="mt-6 text-sm font-semibold uppercase tracking-[0.2em] text-primary">Privacy</p>
            <h1 className="mt-3 text-4xl font-bold tracking-tight sm:text-6xl">Your privacy matters.</h1>
            <p className="mt-6 text-base leading-8 text-muted-foreground sm:text-lg">This page explains the general privacy approach used by WebShield when you use its public website security scanning features.</p>
          </div>

          <div className="mt-12 space-y-6">
            <section className="glass rounded-2xl p-6 sm:p-8">
              <h2 className="text-2xl font-bold">Information you provide</h2>
              <p className="mt-4 leading-7 text-muted-foreground">When you submit a website URL for scanning, WebShield needs that URL to perform the requested security analysis. You should not submit URLs containing passwords, tokens, private paths, or other sensitive information.</p>
            </section>

            <section className="glass rounded-2xl p-6 sm:p-8">
              <h2 className="text-2xl font-bold">How scan data is used</h2>
              <p className="mt-4 leading-7 text-muted-foreground">Submitted URLs are used to retrieve publicly accessible HTTP information and generate security findings, scores, and recommendations. The scanner is intended for authorized security assessment of websites you have permission to assess.</p>
            </section>

            <section className="glass rounded-2xl p-6 sm:p-8">
              <h2 className="text-2xl font-bold">No signup required</h2>
              <p className="mt-4 leading-7 text-muted-foreground">The public scanner is designed to work without requiring an account. WebShield does not ask you to enter passwords or credentials for the websites you scan.</p>
            </section>

            <section className="glass rounded-2xl p-6 sm:p-8">
              <h2 className="text-2xl font-bold">Third-party websites</h2>
              <p className="mt-4 leading-7 text-muted-foreground">WebShield scans websites that you request. The privacy practices, logging, cookies, and data policies of those third-party websites are separate from WebShield and are controlled by their respective operators.</p>
            </section>

            <section className="glass rounded-2xl p-6 sm:p-8">
              <h2 className="flex items-center gap-3 text-2xl font-bold"><Shield className="h-6 w-6 text-primary" aria-hidden="true" />Security and responsible use</h2>
              <p className="mt-4 leading-7 text-muted-foreground">WebShield is a defensive security analysis tool. Only scan systems you own or have explicit permission to assess, and avoid submitting confidential information through the public scanner.</p>
            </section>
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
