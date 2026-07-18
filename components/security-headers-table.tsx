'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronUp,
  Lightbulb,
  FileWarning,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { SecurityHeader, HeaderStatus } from '@/lib/types';

interface SecurityHeadersTableProps {
  headers: SecurityHeader[];
}

const statusConfig: Record<
  HeaderStatus,
  { label: string; icon: React.ElementType; className: string; rowClass: string }
> = {
  present: {
    label: 'Present',
    icon: CheckCircle2,
    className: 'border-success/30 bg-success/10 text-success',
    rowClass: '',
  },
  missing: {
    label: 'Missing',
    icon: XCircle,
    className: 'border-destructive/30 bg-destructive/10 text-destructive',
    rowClass: 'bg-destructive/5',
  },
  weak: {
    label: 'Weak',
    icon: AlertTriangle,
    className: 'border-warning/30 bg-warning/10 text-warning',
    rowClass: 'bg-warning/5',
  },
  'report-only': {
    label: 'Report-Only',
    icon: FileWarning,
    className: 'border-primary/30 bg-primary/10 text-primary',
    rowClass: 'bg-primary/5',
  },
};

const severityColors: Record<string, string> = {
  critical: 'text-destructive',
  high: 'text-destructive',
  medium: 'text-warning',
  low: 'text-primary',
  info: 'text-muted-foreground',
};

const categoryLabels: Record<string, string> = {
  transport: 'Transport',
  content: 'Content',
  browser: 'Browser',
  cookies: 'Cookies',
  infrastructure: 'Infra',
};

export function SecurityHeadersTable({ headers }: SecurityHeadersTableProps) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const presentCount = headers.filter((h) => h.status === 'present').length;
  const totalCount = headers.length;

  const toggle = (name: string) => {
    setExpanded((prev) => (prev === name ? null : name));
  };

  return (
    <Card className="glass">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2 text-lg">
            <Info className="h-5 w-5 text-primary" aria-hidden="true" />
            Security Headers
          </span>
          <Badge variant="outline" className="border-primary/30 bg-primary/10 text-primary">
            {presentCount}/{totalCount} Present
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto scrollbar-thin">
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="w-[28%] min-w-[170px]">Header</TableHead>
                <TableHead className="w-[12%] min-w-[90px]">Status</TableHead>
                <TableHead className="w-[10%] min-w-[80px]">Severity</TableHead>
                <TableHead className="w-[10%] min-w-[70px]">Points</TableHead>
                <TableHead className="min-w-[160px]">Value</TableHead>
                <TableHead className="w-[8%] min-w-[60px]">Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {headers.map((header, index) => {
                const config = statusConfig[header.status];
                const StatusIcon = config.icon;
                const isExpanded = expanded === header.name;
                return (
                  <>
                    <motion.tr
                      key={header.name}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.05 }}
                      className={`cursor-pointer border-border transition-colors ${config.rowClass} hover:bg-secondary/30`}
                      onClick={() => toggle(header.name)}
                    >
                      <TableCell className="font-mono text-xs font-medium text-foreground sm:text-sm">
                        {header.name}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`gap-1 ${config.className}`}
                        >
                          <StatusIcon className="h-3 w-3" aria-hidden="true" />
                          {config.label}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span
                          className={`text-xs font-medium uppercase ${severityColors[header.severity]}`}
                        >
                          {header.severity}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-xs text-muted-foreground">
                          {header.pointsAwarded.toFixed(1)}/{header.maxPoints}
                        </span>
                      </TableCell>
                      <TableCell className="max-w-xs">
                        <p
                          className="truncate font-mono text-xs text-muted-foreground"
                          title={header.value}
                        >
                          {header.value}
                        </p>
                      </TableCell>
                      <TableCell>
                        <button
                          className="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
                          aria-label={isExpanded ? 'Collapse details' : 'Expand details'}
                          aria-expanded={isExpanded}
                        >
                          {isExpanded ? (
                            <ChevronUp className="h-4 w-4" aria-hidden="true" />
                          ) : (
                            <ChevronDown className="h-4 w-4" aria-hidden="true" />
                          )}
                        </button>
                      </TableCell>
                    </motion.tr>
                    <AnimatePresence key={`${header.name}-detail`}>
                      {isExpanded && (
                        <motion.tr
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                          transition={{ duration: 0.2 }}
                          className="border-border"
                        >
                          <TableCell colSpan={6} className="bg-secondary/20 p-4">
                            <div className="space-y-3">
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className="border-primary/30 bg-primary/10 text-primary">
                                  {categoryLabels[header.category]}
                                </Badge>
                                {header.status === 'report-only' && (
                                  <Badge variant="outline" className="border-primary/30 bg-primary/10 text-primary">
                                    Monitoring mode
                                  </Badge>
                                )}
                              </div>
                              <div>
                                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                                  Description
                                </p>
                                <p className="text-sm text-foreground">
                                  {header.description}
                                </p>
                              </div>
                              <div>
                                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                                  Why It Matters
                                </p>
                                <p className="text-sm text-muted-foreground">
                                  {header.whyItMatters}
                                </p>
                              </div>
                              {header.isWeak && header.weaknessReason && (
                                <div className="rounded-lg bg-warning/10 p-3 ring-1 ring-warning/20">
                                  <p className="flex items-start gap-2 text-sm text-warning">
                                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                                    <span>{header.weaknessReason}</span>
                                  </p>
                                </div>
                              )}
                              {header.status === 'report-only' && (
                                <div className="rounded-lg bg-primary/10 p-3 ring-1 ring-primary/20">
                                  <p className="flex items-start gap-2 text-sm text-primary">
                                    <FileWarning className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                                    <span>
                                      Report-Only CSP detected. This monitors violations without
                                      enforcement. Consider switching to enforcement once confident.
                                    </span>
                                  </p>
                                </div>
                              )}
                              <div>
                                <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                                  <Lightbulb className="h-3.5 w-3.5" aria-hidden="true" />
                                  Example Secure Value
                                </p>
                                <code className="block rounded-md bg-background/60 p-2.5 font-mono text-xs text-primary">
                                  {header.exampleValue}
                                </code>
                              </div>
                            </div>
                          </TableCell>
                        </motion.tr>
                      )}
                    </AnimatePresence>
                  </>
                );
              })}
            </TableBody>
          </Table>
        </div>

        <p className="mt-4 text-xs text-muted-foreground">
          Click any row to view detailed analysis, why the header matters, and an example secure value.
          Points are awarded based on presence and configuration quality.
        </p>
      </CardContent>
    </Card>
  );
}
