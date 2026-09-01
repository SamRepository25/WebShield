import Link from 'next/link';
import { Github, MessageSquare, Shield, ArrowRight } from 'lucide-react';
import { AppShell } from '@/components/app-shell';
import { Button } from '@/components/ui/button';

export const metadata = {
  title: 'Contact',
  description: 'Contact WebShield for questions, feedback, and security reports.',
};

export default function ContactPage() {
  return (
    <AppShell>
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 grid-bg opacity-20" aria-hidden="true" />
        <div className="relative mx-auto max-w-5xl px-4 py-16 sm:px-6 sm:py-24 lg:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 ring-1 ring-primary/30">
              <MessageSquare className="h-7 w-7 text-primary" aria-hidden="true" />
            </div>
            <p className="mt-6 text-sm font-semibold uppercase tracking-[0.2em] text-primary">Contact</p>
            <h1 className="mt-3 text-4xl font-bold tracking-tight sm:text-6xl">Let's talk about WebShield.</h1>
            <p className="mt-6 text-base leading-8 text-muted-foreground sm:text-lg">
              Have feedback, found a bug, or want to discuss the project? The best place to reach the WebShield project is through GitHub, where issues and suggestions can be tracked openly.
            </p>
          </div>

          <div className="mx-auto mt-12 max-w-2xl glass rounded-2xl p-6 sm:p-8">
            <div className="flex items-start gap-4">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-primary/10">
                <Github className="h-5 w-5 text-primary" aria-hidden="true" />
              </div>
              <div>
                <h2 className="text-xl font-semibold">GitHub</h2>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">
                  Open the WebShield repository to report bugs, suggest improvements, or review the project.
                </p>
                <Button asChild className="mt-5 gap-2 bg-primary text-primary-foreground hover:bg-primary/90">
                  <a href="https://github.com/SamRepository25/WebShield" target="_blank" rel="noreferrer">
                    Open GitHub Repository
                    <ArrowRight className="h-4 w-4" aria-hidden="true" />
                  </a>
                </Button>
              </div>
            </div>
          </div>

          <div className="mt-6 grid gap-6 md:grid-cols-2">
            <div className="glass rounded-2xl p-6">
              <Shield className="h-6 w-6 text-primary" aria-hidden="true" />
              <h2 className="mt-4 text-lg font-semibold">Security reports</h2>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">For security issues, please use the repository's issue and security-reporting mechanisms rather than sharing sensitive details publicly.</p>
            </div>
            <div className="glass rounded-2xl p-6">
              <MessageSquare className="h-6 w-6 text-primary" aria-hidden="true" />
              <h2 className="mt-4 text-lg font-semibold">Feedback</h2>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">Suggestions about the scanner, reports, interface, or documentation are welcome.</p>
            </div>
          </div>

          <div className="mt-10 text-center">
            <Button asChild variant="outline">
              <Link href="/">Back to WebShield</Link>
            </Button>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
