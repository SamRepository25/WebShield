'use client';

import { motion } from 'framer-motion';
import { CheckCircle2, XCircle, AlertTriangle, Info } from 'lucide-react';
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
import type { SecurityHeader, HeaderStatus } from '@/lib/mock-data';

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
};

const severityColors: Record<string, string> = {
  critical: 'text-destructive',
  high: 'text-destructive',
  medium: 'text-warning',
  low: 'text-primary',
  info: 'text-muted-foreground',
};

export function SecurityHeadersTable({ headers }: SecurityHeadersTableProps) {
  const presentCount = headers.filter((h) => h.status === 'present').length;
  const totalCount = headers.length;

  return (
    <Card className="glass">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2 text-lg">
            <Info className="h-5 w-5 text-primary" />
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
                <TableHead className="w-[30%] min-w-[180px]">Header</TableHead>
                <TableHead className="w-[15%] min-w-[100px]">Status</TableHead>
                <TableHead className="w-[10%] min-w-[80px]">Severity</TableHead>
                <TableHead className="min-w-[200px]">Value</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {headers.map((header, index) => {
                const config = statusConfig[header.status];
                const StatusIcon = config.icon;
                return (
                  <motion.tr
                    key={header.name}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.05 }}
                    className={`border-border transition-colors ${config.rowClass}`}
                  >
                    <TableCell className="font-mono text-xs font-medium text-foreground sm:text-sm">
                      {header.name}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={`gap-1 ${config.className}`}
                      >
                        <StatusIcon className="h-3 w-3" />
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
                    <TableCell className="max-w-xs">
                      <p
                        className="truncate font-mono text-xs text-muted-foreground"
                        title={header.value}
                      >
                        {header.value}
                      </p>
                    </TableCell>
                  </motion.tr>
                );
              })}
            </TableBody>
          </Table>
        </div>

        <div className="mt-4 space-y-2">
          {headers
            .filter((h) => h.status !== 'present')
            .slice(0, 3)
            .map((header) => (
              <div
                key={header.name}
                className="flex items-start gap-2 rounded-lg bg-secondary/30 p-3 text-xs"
              >
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" />
                <div>
                  <span className="font-medium text-foreground">{header.name}:</span>{' '}
                  <span className="text-muted-foreground">{header.description}</span>
                </div>
              </div>
            ))}
        </div>
      </CardContent>
    </Card>
  );
}
