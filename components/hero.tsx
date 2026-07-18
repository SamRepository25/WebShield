'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, Globe, Zap, ArrowRight, CheckCircle2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

interface HeroProps {
  onScan: (url: string) => void;
  isScanning: boolean;
}

const trustBadges = [
  'HTTPS Validation',
  'Security Headers',
  'SSL Certificate',
  'Vulnerability Scan',
];

export function Hero({ onScan, isScanning }: HeroProps) {
  const [url, setUrl] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() || isScanning) return;
    let normalized = url.trim();
    if (!/^https?:\/\//i.test(normalized)) {
      normalized = `https://${normalized}`;
    }
    onScan(normalized);
  };

  return (
    <section
      className="relative overflow-hidden pt-32 pb-20 sm:pt-40 sm:pb-28"
      aria-label="Website security scanner"
    >
      <div className="absolute inset-0 grid-bg opacity-30" aria-hidden="true" />
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-background" aria-hidden="true" />

      <div className="relative mx-auto max-w-4xl px-4 text-center sm:px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mb-6 inline-flex items-center gap-2 rounded-full glass px-4 py-1.5 text-xs font-medium text-muted-foreground"
        >
          <span className="relative flex h-2 w-2" aria-hidden="true">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-success" />
          </span>
          Real-time security analysis
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="text-4xl font-bold tracking-tight sm:text-6xl lg:text-7xl"
        >
          Scan. Analyze.
          <br />
          <span className="text-gradient">Secure Your Website</span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="mx-auto mt-6 max-w-2xl text-base text-muted-foreground sm:text-lg"
        >
          Enter any URL to instantly check its security posture. Get a comprehensive
          report on HTTPS status, security headers, vulnerabilities, and actionable
          recommendations.
        </motion.p>

        <motion.form
          onSubmit={handleSubmit}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
          id="scanner"
          className="mx-auto mt-10 max-w-2xl scroll-mt-24"
          aria-label="Website scan form"
        >
          <div className="glass-strong relative rounded-2xl p-2 shadow-2xl">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
              <div className="relative flex-1">
                <Globe
                  className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground"
                  aria-hidden="true"
                />
                <label htmlFor="url-input" className="sr-only">
                  Website URL to scan
                </label>
                <Input
                  id="url-input"
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="example.com"
                  disabled={isScanning}
                  aria-label="Website URL"
                  aria-describedby="scanner-hint"
                  className="h-14 border-0 bg-transparent pl-12 text-base shadow-none focus-visible:ring-0"
                />
              </div>
              <Button
                type="submit"
                disabled={isScanning || !url.trim()}
                size="lg"
                className="h-14 gap-2 bg-primary px-6 text-base font-semibold text-primary-foreground hover:bg-primary/90 glow-primary disabled:opacity-50"
              >
                {isScanning ? (
                  <>
                    <span
                      className="h-5 w-5 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent"
                      aria-hidden="true"
                    />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Search className="h-5 w-5" aria-hidden="true" />
                    Scan Website
                    <ArrowRight className="h-4 w-4" aria-hidden="true" />
                  </>
                )}
              </Button>
            </div>
          </div>

          <p id="scanner-hint" className="sr-only">
            Enter a website URL and click Scan Website to analyze its security headers and HTTPS status.
          </p>

          <div className="mt-4 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-xs text-muted-foreground">
            {trustBadges.map((badge) => (
              <div key={badge} className="flex items-center gap-1.5">
                <CheckCircle2 className="h-3.5 w-3.5 text-success" aria-hidden="true" />
                {badge}
              </div>
            ))}
          </div>
        </motion.form>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.5 }}
          className="mt-12 flex items-center justify-center gap-2 text-xs text-muted-foreground"
        >
          <Zap className="h-3.5 w-3.5 text-warning" aria-hidden="true" />
          No signup required — results in seconds
        </motion.div>
      </div>
    </section>
  );
}
