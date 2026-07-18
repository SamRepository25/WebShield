'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Globe,
  Clock,
  RotateCcw,
  Download,
  Copy,
  Share2,
  FileJson,
  FileText,
  Check,
  Timer,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { SecurityScoreCard } from '@/components/security-score-card';
import { HttpsStatusCard } from '@/components/https-status-card';
import { SecurityHeadersTable } from '@/components/security-headers-table';
import { Recommendations } from '@/components/recommendations';
import { RawHeadersAccordion } from '@/components/raw-headers-accordion';
import { VulnerabilitySummary } from '@/components/vulnerability-summary';
import { useToast } from '@/hooks/use-toast';
import {
  exportJson,
  exportTextReport,
  copyResults,
  shareResults,
} from '@/lib/export';
import type { ScanResult } from '@/lib/types';

interface ScanResultsProps {
  result: ScanResult;
  onRescan: () => void;
}

export function ScanResults({ result, onRescan }: ScanResultsProps) {
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);

  const scanDate = new Date(result.scannedAt).toLocaleString('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  });

  const durationText =
    result.scanDurationMs < 1000
      ? `${result.scanDurationMs}ms`
      : `${(result.scanDurationMs / 1000).toFixed(2)}s`;

  const handleCopy = async () => {
    try {
      await copyResults(result);
      setCopied(true);
      toast({ title: 'Results copied', description: 'Scan summary copied to clipboard.' });
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({ title: 'Copy failed', description: 'Could not copy to clipboard.', variant: 'destructive' });
    }
  };

  const handleShare = async () => {
    const shared = await shareResults(result);
    if (shared) {
      toast({ title: 'Results shared', description: 'Scan results shared or copied to clipboard.' });
    } else {
      toast({ title: 'Share failed', description: 'Could not share results.', variant: 'destructive' });
    }
  };

  const handleExportJson = () => {
    exportJson(result);
    toast({ title: 'JSON exported', description: 'Security report downloaded as JSON.' });
  };

  const handleExportReport = () => {
    exportTextReport(result);
    toast({ title: 'Report exported', description: 'Security report downloaded as text.' });
  };

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
            <Globe className="h-4 w-4 shrink-0" />
            <span className="truncate font-mono">{result.url}</span>
          </div>
          <h2 className="mt-1 text-2xl font-bold sm:text-3xl">Scan Results</h2>
          <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5" />
              {scanDate}
            </span>
            <span className="flex items-center gap-1.5">
              <Timer className="h-3.5 w-3.5" />
              Completed in {durationText}
            </span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-2 border-border bg-secondary/30"
            onClick={handleCopy}
            aria-label="Copy results to clipboard"
          >
            {copied ? (
              <Check className="h-4 w-4 text-success" />
            ) : (
              <Copy className="h-4 w-4" />
            )}
            Copy
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-2 border-border bg-secondary/30"
            onClick={handleShare}
            aria-label="Share results"
          >
            <Share2 className="h-4 w-4" />
            Share
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className="gap-2 border-border bg-secondary/30"
                aria-label="Export results"
              >
                <Download className="h-4 w-4" />
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={handleExportJson} className="gap-2">
                <FileJson className="h-4 w-4" />
                Export as JSON
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handleExportReport} className="gap-2">
                <FileText className="h-4 w-4" />
                Download Report
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button
            size="sm"
            className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90 glow-primary"
            onClick={onRescan}
            aria-label="Rescan website"
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
