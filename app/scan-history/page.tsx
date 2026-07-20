'use client';

import { useEffect, useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { History, Search, ArrowUpDown, ShieldCheck, ShieldAlert, Globe } from 'lucide-react';
import { AppShell } from '@/components/app-shell';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { getScoreColorClass, getGradeColorClass } from '@/lib/grade-utils';
import type { ScanRecord } from '@/lib/monitoring-types';

type SortKey = 'scanned_at' | 'score' | 'grade' | 'url';
type SortDir = 'asc' | 'desc';

export default function ScanHistoryPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('scanned_at');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [gradeFilter, setGradeFilter] = useState<string>('all');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/api/scans?limit=200');
        if (!res.ok) throw new Error('Failed to load scan history.');
        const data = (await res.json()) as ScanRecord[];
        if (!cancelled) setScans(data);
      } catch (err) {
        if (!cancelled) setError((err as Error).message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    let result = scans;
    if (q) {
      result = result.filter((s) => s.url.toLowerCase().includes(q));
    }
    if (gradeFilter !== 'all') {
      result = result.filter((s) => s.grade === gradeFilter);
    }
    const sorted = [...result].sort((a, b) => {
      let cmp = 0;
      if (sortKey === 'scanned_at') {
        cmp = new Date(a.scanned_at).getTime() - new Date(b.scanned_at).getTime();
      } else if (sortKey === 'score') {
        cmp = a.score - b.score;
      } else if (sortKey === 'grade') {
        cmp = a.grade.localeCompare(b.grade);
      } else {
        cmp = a.url.localeCompare(b.url);
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return sorted;
  }, [scans, query, sortKey, sortDir, gradeFilter]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  };

  return (
    <AppShell>
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">Scan History</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Every scan ever run against your monitored websites, with filtering and sorting.
          </p>
        </motion.div>

        {error && (
          <Card className="glass mb-6 border-destructive/30">
            <CardContent className="pt-6 text-sm text-destructive">{error}</CardContent>
          </Card>
        )}

        <Card className="glass mb-6">
          <CardContent className="pt-6">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <div className="relative flex-1">
                <Search
                  className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
                  aria-hidden="true"
                />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter by URL…"
                  aria-label="Filter by URL"
                  className="pl-9"
                />
              </div>
              <Select value={gradeFilter} onValueChange={setGradeFilter}>
                <SelectTrigger className="w-full sm:w-40" aria-label="Filter by grade">
                  <SelectValue placeholder="All grades" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All grades</SelectItem>
                  {['A', 'B', 'C', 'D', 'E', 'F'].map((g) => (
                    <SelectItem key={g} value={g}>
                      Grade {g}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        <Card className="glass">
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-lg">
              <span className="flex items-center gap-2">
                <History className="h-5 w-5 text-primary" aria-hidden="true" />
                Scan Records
              </span>
              <Badge variant="outline" className="border-primary/30 bg-primary/10 text-primary">
                {filtered.length} {filtered.length === 1 ? 'scan' : 'scans'}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="h-12 animate-pulse rounded-md bg-secondary/40" />
                ))}
              </div>
            ) : filtered.length === 0 ? (
              <div className="flex flex-col items-center gap-3 py-12 text-center">
                <Globe className="h-8 w-8 text-muted-foreground" aria-hidden="true" />
                <p className="text-sm text-muted-foreground">
                  {scans.length === 0
                    ? 'No scans recorded yet. Trigger a scan from the Monitor page.'
                    : 'No scans match your filters.'}
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto scrollbar-thin">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead className="min-w-[160px]">
                        <button
                          onClick={() => toggleSort('scanned_at')}
                          className="flex items-center gap-1 text-xs font-semibold uppercase tracking-wide hover:text-foreground"
                        >
                          Date <ArrowUpDown className="h-3 w-3" aria-hidden="true" />
                        </button>
                      </TableHead>
                      <TableHead className="min-w-[200px]">
                        <button
                          onClick={() => toggleSort('url')}
                          className="flex items-center gap-1 text-xs font-semibold uppercase tracking-wide hover:text-foreground"
                        >
                          URL <ArrowUpDown className="h-3 w-3" aria-hidden="true" />
                        </button>
                      </TableHead>
                      <TableHead className="min-w-[90px]">
                        <button
                          onClick={() => toggleSort('score')}
                          className="flex items-center gap-1 text-xs font-semibold uppercase tracking-wide hover:text-foreground"
                        >
                          Score <ArrowUpDown className="h-3 w-3" aria-hidden="true" />
                        </button>
                      </TableHead>
                      <TableHead className="min-w-[80px]">
                        <button
                          onClick={() => toggleSort('grade')}
                          className="flex items-center gap-1 text-xs font-semibold uppercase tracking-wide hover:text-foreground"
                        >
                          Grade <ArrowUpDown className="h-3 w-3" aria-hidden="true" />
                        </button>
                      </TableHead>
                      <TableHead className="min-w-[100px]">HTTPS</TableHead>
                      <TableHead className="min-w-[120px]">Headers</TableHead>
                      <TableHead className="min-w-[90px]">Vulns</TableHead>
                      <TableHead className="min-w-[80px]">Trigger</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filtered.map((scan) => (
                      <TableRow key={scan.id} className="border-border">
                        <TableCell className="text-xs text-muted-foreground">
                          {new Date(scan.scanned_at).toLocaleString('en-US', {
                            dateStyle: 'short',
                            timeStyle: 'short',
                          })}
                        </TableCell>
                        <TableCell>
                          <span className="truncate font-mono text-xs" title={scan.url}>
                            {scan.url}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className={`font-mono font-bold ${getScoreColorClass(scan.score)}`}>
                            {scan.score}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className={`font-mono font-bold ${getGradeColorClass(scan.grade)}`}>
                            {scan.grade}
                          </span>
                        </TableCell>
                        <TableCell>
                          {scan.https_enabled && scan.https_valid ? (
                            <Badge variant="outline" className="gap-1 border-success/30 bg-success/10 text-success">
                              <ShieldCheck className="h-3 w-3" aria-hidden="true" />
                              Secure
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="gap-1 border-destructive/30 bg-destructive/10 text-destructive">
                              <ShieldAlert className="h-3 w-3" aria-hidden="true" />
                              {scan.https_enabled ? 'Invalid' : 'Off'}
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          <span className="text-success">{scan.headers_present} present</span>
                          {scan.headers_weak > 0 && <span className="text-warning"> · {scan.headers_weak} weak</span>}
                          {scan.headers_missing > 0 && <span className="text-destructive"> · {scan.headers_missing} missing</span>}
                        </TableCell>
                        <TableCell>
                          <span className="text-xs font-medium">
                            {scan.vulnerability_count}
                            {scan.critical_count > 0 && <span className="text-destructive"> ({scan.critical_count} crit)</span>}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={
                              scan.trigger === 'scheduled'
                                ? 'border-primary/30 bg-primary/10 text-primary'
                                : 'border-muted bg-secondary text-muted-foreground'
                            }
                          >
                            {scan.trigger}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
