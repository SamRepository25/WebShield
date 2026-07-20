'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import {
  Activity,
  TrendingUp,
  TrendingDown,
  Minus,
  Globe,
  ShieldCheck,
  Clock,
  ScanLine,
  ArrowRight,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
} from 'recharts';
import { AppShell } from '@/components/app-shell';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { getScoreColorClass } from '@/lib/grade-utils';
import type { DashboardStats } from '@/lib/monitoring-types';

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/api/dashboard');
        if (!res.ok) throw new Error('Failed to load dashboard.');
        const data = (await res.json()) as DashboardStats;
        if (!cancelled) setStats(data);
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

  const chartData =
    stats?.scoreHistory
      .slice()
      .reverse()
      .map((s) => ({
        label: new Date(s.scanned_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        score: s.score,
        url: s.url,
      })) ?? [];

  const TrendIcon =
    stats?.scoreTrend === 'up' ? TrendingUp : stats?.scoreTrend === 'down' ? TrendingDown : Minus;

  return (
    <AppShell>
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">Security Dashboard</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Continuous monitoring overview across all your tracked websites.
          </p>
        </motion.div>

        {loading && (
          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-32 animate-pulse rounded-xl bg-secondary/40" />
            ))}
          </div>
        )}

        {error && (
          <Card className="glass border-destructive/30">
            <CardContent className="pt-6 text-sm text-destructive">{error}</CardContent>
          </Card>
        )}

        {stats && !loading && (
          <>
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
              <StatCard
                icon={Globe}
                label="Websites Monitored"
                value={String(stats.totalSites)}
                sub={`${stats.activeSites} active`}
              />
              <StatCard
                icon={ScanLine}
                label="Total Scans"
                value={String(stats.totalScans)}
                sub="All time"
              />
              <StatCard
                icon={ShieldCheck}
                label="Latest Score"
                value={stats.latestScore !== null ? String(stats.latestScore) : '—'}
                sub={stats.latestGrade ? `Grade ${stats.latestGrade}` : 'No scans yet'}
                valueClassName={stats.latestScore !== null ? getScoreColorClass(stats.latestScore) : undefined}
              />
              <StatCard
                icon={TrendIcon}
                label="Score Trend"
                value={
                  stats.scoreTrend === 'up'
                    ? 'Improving'
                    : stats.scoreTrend === 'down'
                    ? 'Declining'
                    : stats.scoreTrend === 'stable'
                    ? 'Stable'
                    : 'Unknown'
                }
                sub={
                  stats.previousScore !== null && stats.latestScore !== null
                    ? `Prev ${stats.previousScore} → ${stats.latestScore}`
                    : 'Need 2+ scans'
                }
                valueClassName={
                  stats.scoreTrend === 'up'
                    ? 'text-success'
                    : stats.scoreTrend === 'down'
                    ? 'text-destructive'
                    : undefined
                }
              />
            </div>

            <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
              <Card className="glass lg:col-span-2">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Activity className="h-5 w-5 text-primary" aria-hidden="true" />
                    Security Score Trend
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {chartData.length === 0 ? (
                    <div className="flex h-64 items-center justify-center text-sm text-muted-foreground">
                      No scan history yet. Add a site and run a scan to see trends.
                    </div>
                  ) : (
                    <div className="h-72 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                          <defs>
                            <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.4} />
                              <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                          <XAxis
                            dataKey="label"
                            stroke="hsl(var(--muted-foreground))"
                            fontSize={11}
                            tickLine={false}
                            axisLine={false}
                          />
                          <YAxis
                            domain={[0, 100]}
                            stroke="hsl(var(--muted-foreground))"
                            fontSize={11}
                            tickLine={false}
                            axisLine={false}
                          />
                          <Tooltip
                            contentStyle={{
                              background: 'hsl(var(--card))',
                              border: '1px solid hsl(var(--border))',
                              borderRadius: '8px',
                              fontSize: '12px',
                            }}
                            labelStyle={{ color: 'hsl(var(--foreground))' }}
                          />
                          <ReferenceLine y={90} stroke="hsl(var(--success))" strokeDasharray="4 4" opacity={0.4} />
                          <ReferenceLine y={50} stroke="hsl(var(--warning))" strokeDasharray="4 4" opacity={0.4} />
                          <Area
                            type="monotone"
                            dataKey="score"
                            stroke="hsl(var(--primary))"
                            strokeWidth={2}
                            fill="url(#scoreGradient)"
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card className="glass">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Clock className="h-5 w-5 text-primary" aria-hidden="true" />
                    Status Overview
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <InfoRow label="Last Scan" value={stats.lastScanAt ? new Date(stats.lastScanAt).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }) : 'Never'} />
                  <InfoRow label="Average Score" value={stats.averageScore !== null ? String(stats.averageScore) : '—'} />
                  <InfoRow
                    label="HTTPS Status"
                    value={
                      stats.httpsEnabled === null ? 'No data' : stats.httpsEnabled ? 'Enabled' : 'Disabled'
                    }
                  />
                  <InfoRow
                    label="Latest Grade"
                    value={stats.latestGrade ?? '—'}
                    valueClassName={stats.latestGrade ? 'font-mono font-bold' : undefined}
                  />
                  <div className="pt-2">
                    <Button asChild className="w-full gap-2 bg-primary text-primary-foreground hover:bg-primary/90">
                      <Link href="/monitor">
                        Manage Sites
                        <ArrowRight className="h-4 w-4" aria-hidden="true" />
                      </Link>
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          </>
        )}
      </div>
    </AppShell>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  valueClassName,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  sub?: string;
  valueClassName?: string;
}) {
  return (
    <Card className="glass">
      <CardContent className="pt-6">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {label}
          </span>
          <Icon className="h-4 w-4 text-primary" aria-hidden="true" />
        </div>
        <p className={`mt-3 text-3xl font-bold ${valueClassName ?? ''}`}>{value}</p>
        {sub && <p className="mt-1 text-xs text-muted-foreground">{sub}</p>}
      </CardContent>
    </Card>
  );
}

function InfoRow({ label, value, valueClassName }: { label: string; value: string; valueClassName?: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={`text-sm font-medium ${valueClassName ?? ''}`}>{value}</span>
    </div>
  );
}
