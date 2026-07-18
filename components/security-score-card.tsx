'use client';

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  ShieldX,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { ScoreBreakdown } from '@/lib/types';

interface SecurityScoreCardProps {
  score: number;
  grade: string;
  breakdown?: ScoreBreakdown;
}

function getScoreColor(score: number) {
  if (score >= 90) return { color: 'hsl(var(--success))', label: 'Excellent', Icon: ShieldCheck };
  if (score >= 70) return { color: 'hsl(var(--primary))', label: 'Good', Icon: ShieldCheck };
  if (score >= 50) return { color: 'hsl(var(--warning))', label: 'Fair', Icon: AlertTriangle };
  if (score >= 30) return { color: 'hsl(25 95% 55%)', label: 'Poor', Icon: ShieldAlert };
  return { color: 'hsl(var(--destructive))', label: 'Critical', Icon: ShieldX };
}

const CATEGORY_LABELS: Record<keyof ScoreBreakdown, string> = {
  transport: 'Transport (HTTPS/HSTS)',
  content: 'Content Security (CSP)',
  browser: 'Browser Security',
  cookies: 'Cookie Security',
  infrastructure: 'Infrastructure',
  total: 'Total',
  maxTotal: 'Max',
};

export function SecurityScoreCard({ score, grade, breakdown }: SecurityScoreCardProps) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const { color, label, Icon } = getScoreColor(score);
  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  useEffect(() => {
    const duration = 1500;
    const steps = 60;
    const increment = score / steps;
    let current = 0;
    const interval = setInterval(() => {
      current += increment;
      if (current >= score) {
        setAnimatedScore(score);
        clearInterval(interval);
      } else {
        setAnimatedScore(Math.round(current));
      }
    }, duration / steps);
    return () => clearInterval(interval);
  }, [score]);

  const categories: Array<{ key: keyof ScoreBreakdown; value: number }> = breakdown
    ? (['transport', 'content', 'browser', 'cookies', 'infrastructure'] as const).map((k) => ({
        key: k,
        value: breakdown[k] as number,
      }))
    : [];

  return (
    <Card
      className="glass relative overflow-hidden border-primary/20"
      role="region"
      aria-label={`Security score: ${score} out of 100, grade ${grade}, ${label}`}
    >
      <div
        className="absolute inset-0 opacity-10"
        style={{ background: `radial-gradient(circle at 50% 50%, ${color}, transparent 70%)` }}
        aria-hidden="true"
      />
      <CardHeader className="relative">
        <CardTitle className="flex items-center gap-2 text-base font-medium text-muted-foreground">
          <Icon className="h-4 w-4" style={{ color }} aria-hidden="true" />
          Security Score
        </CardTitle>
      </CardHeader>
      <CardContent className="relative flex flex-col items-center pb-8">
        <div className="relative h-48 w-48" aria-hidden="true">
          <svg className="h-full w-full -rotate-90" viewBox="0 0 200 200">
            <circle
              cx="100"
              cy="100"
              r={radius}
              fill="none"
              stroke="hsl(var(--secondary))"
              strokeWidth="10"
            />
            <motion.circle
              cx="100"
              cy="100"
              r={radius}
              fill="none"
              stroke={color}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={circumference}
              initial={{ strokeDashoffset: circumference }}
              animate={{ strokeDashoffset }}
              transition={{ duration: 1.5, ease: 'easeOut' }}
              style={{ filter: `drop-shadow(0 0 6px ${color})` }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <motion.span
              initial={{ opacity: 0, scale: 0.5 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.3 }}
              className="text-5xl font-bold"
              style={{ color }}
            >
              {animatedScore}
            </motion.span>
            <span className="mt-1 text-xs font-medium uppercase tracking-wider text-muted-foreground">
              out of 100
            </span>
          </div>
        </div>

        <div className="mt-4 flex items-center gap-3">
          <div
            className="flex h-12 w-12 items-center justify-center rounded-xl text-xl font-bold"
            style={{ backgroundColor: `${color}20`, color, border: `1px solid ${color}40` }}
            aria-hidden="true"
          >
            {grade}
          </div>
          <div className="text-left">
            <p className="text-sm font-semibold" style={{ color }}>
              {label}
            </p>
            <p className="text-xs text-muted-foreground">Overall grade</p>
          </div>
        </div>

        {breakdown && categories.length > 0 && (
          <div className="mt-6 w-full space-y-2">
            <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Score Breakdown
            </p>
            {categories.map(({ key, value }) => (
              <div key={key} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{CATEGORY_LABELS[key]}</span>
                  <span className="font-mono font-medium text-foreground">
                    {value.toFixed(1)}
                  </span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary">
                  <motion.div
                    className="h-full rounded-full"
                    style={{ backgroundColor: color }}
                    initial={{ width: '0%' }}
                    animate={{ width: `${Math.min((value / 40) * 100, 100)}%` }}
                    transition={{ duration: 1, ease: 'easeOut' }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
