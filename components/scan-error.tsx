'use client';

import { motion } from 'framer-motion';
import { AlertCircle, RotateCcw, Globe, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface ScanErrorProps {
  url: string;
  message: string;
  onRetry: () => void;
}

export function ScanError({ url, message, onRetry }: ScanErrorProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="mx-auto max-w-2xl px-4"
      role="alert"
      aria-live="assertive"
    >
      <div className="glass-strong relative overflow-hidden rounded-2xl border-destructive/30 p-8 sm:p-12">
        <div className="absolute inset-0 bg-destructive/5" aria-hidden="true" />

        <div className="relative flex flex-col items-center text-center">
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: 'spring', stiffness: 200, damping: 15 }}
            className="mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-destructive/10 ring-1 ring-destructive/30"
            aria-hidden="true"
          >
            <AlertCircle className="h-10 w-10 text-destructive" />
          </motion.div>

          <h3 className="mb-2 text-xl font-semibold">Scan Failed</h3>

          {url && (
            <div className="mb-4 flex items-center gap-2 text-sm text-muted-foreground">
              <Globe className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span className="truncate font-mono" title={url}>
                {url}
              </span>
            </div>
          )}

          <p className="mb-8 max-w-md text-sm text-muted-foreground">
            {message}
          </p>

          <div className="flex flex-wrap items-center justify-center gap-3">
            <Button
              onClick={onRetry}
              variant="outline"
              className="gap-2 border-border bg-secondary/30"
            >
              <Search className="h-4 w-4" />
              New Scan
            </Button>
            <Button
              onClick={() => window.location.reload()}
              className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90 glow-primary"
            >
              <RotateCcw className="h-4 w-4" />
              Try Again
            </Button>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
