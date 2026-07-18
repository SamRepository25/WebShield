'use client';

import { motion } from 'framer-motion';
import { Globe, Clock, RotateCcw, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { SecurityScoreCard } from '@/components/security-score-card';
import { HttpsStatusCard } from '@/components/https-status-card';
import { SecurityHeadersTable } from '@/components/security-headers-table';
import { Recommendations } from '@/components/recommendations';
import { RawHeadersAccordion } from '@/components/raw-headers-accordion';
import { VulnerabilitySummary } from '@/components/vulnerability-summary';
import type { ScanResult } from '@/lib/mock-data';

interface ScanResultsProps {
  result: ScanResult;
  onRescan: () => void;
}

export function ScanResults({ result, onRescan }: ScanResultsProps) {
  const scanDate = new Date(result.scannedAt).toLocaleString('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  });

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
      className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8"
    >
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Globe className="h-4 w-4" />
            <span className="font-mono">{result.url}</span>
          </div>
          <h2 className="mt-1 text-2xl font-bold sm:text-3xl">Scan Results</h2>
          <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
            <Clock className="h-3.5 w-3.5" />
            Scanned on {scanDate}
          </div>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-2 border-border bg-secondary/30"
          >
            <Download className="h-4 w-4" />
            Export
          </Button>
          <Button
            size="sm"
            className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90 glow-primary"
            onClick={onRescan}
          >
            <RotateCcw className="h-4 w-4" />
            Rescan
          </Button>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="lg:col-span-1"
        >
          <SecurityScoreCard score={result.score} grade={result.grade} />
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="lg:col-span-2"
        >
          <HttpsStatusCard https={result.https} />
        </motion.div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="mt-6"
      >
        <VulnerabilitySummary vulnerabilities={result.vulnerabilities} />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="mt-6"
      >
        <SecurityHeadersTable headers={result.headers} />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="mt-6"
      >
        <Recommendations recommendations={result.recommendations} />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
        className="mt-6"
      >
        <RawHeadersAccordion rawHeaders={result.rawHeaders} />
      </motion.div>
    </motion.div>
  );
}
