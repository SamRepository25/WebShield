'use client';

import { motion } from 'framer-motion';
import {
  Lightbulb,
  AlertCircle,
  TrendingUp,
  ArrowRight,
  Info,
  Code2,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import type { Recommendation } from '@/lib/types';

interface RecommendationsProps {
  recommendations: Recommendation[];
}

const severityConfig: Record<
  Recommendation['severity'],
  { label: string; className: string; borderClass: string }
> = {
  critical: {
    label: 'Critical',
    className: 'border-destructive/30 bg-destructive/10 text-destructive',
    borderClass: 'border-l-destructive',
  },
  high: {
    label: 'High',
    className: 'border-destructive/30 bg-destructive/10 text-destructive',
    borderClass: 'border-l-destructive',
  },
  medium: {
    label: 'Medium',
    className: 'border-warning/30 bg-warning/10 text-warning',
    borderClass: 'border-l-warning',
  },
  low: {
    label: 'Low',
    className: 'border-primary/30 bg-primary/10 text-primary',
    borderClass: 'border-l-primary',
  },
  info: {
    label: 'Info',
    className: 'border-primary/30 bg-primary/10 text-primary',
    borderClass: 'border-l-primary',
  },
};

export function Recommendations({ recommendations }: RecommendationsProps) {
  if (recommendations.length === 0) {
    return (
      <Card className="glass">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Lightbulb className="h-5 w-5 text-success" />
            Security Recommendations
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center gap-3 rounded-xl bg-success/10 p-8 text-center ring-1 ring-success/20">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-success/20">
              <Lightbulb className="h-6 w-6 text-success" />
            </div>
            <p className="text-sm font-medium text-success">
              No security issues detected
            </p>
            <p className="max-w-md text-xs text-muted-foreground">
              Your website has excellent security posture. All critical security
              headers are present and properly configured.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2 text-lg">
            <Lightbulb className="h-5 w-5 text-warning" />
            Security Recommendations
          </span>
          <Badge variant="outline" className="border-warning/30 bg-warning/10 text-warning">
            {recommendations.length} {recommendations.length === 1 ? 'Action' : 'Actions'}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {recommendations.map((rec, index) => {
          const config = severityConfig[rec.severity];
          return (
            <motion.div
              key={rec.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className={`rounded-xl border border-border border-l-4 ${config.borderClass} bg-secondary/30 p-4 transition-colors hover:bg-secondary/50`}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 space-y-2">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="h-4 w-4 shrink-0 text-muted-foreground" />
                    <h4 className="text-sm font-semibold text-foreground">
                      {rec.title}
                    </h4>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {rec.description}
                  </p>
                  <div className="flex items-start gap-2 text-xs text-muted-foreground">
                    <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" />
                    <div>
                      <span className="font-medium text-foreground">Why it matters: </span>
                      {rec.whyItMatters}
                    </div>
                  </div>
                  <div className="flex items-start gap-2 text-xs text-muted-foreground">
                    <TrendingUp className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" />
                    <div>
                      <span className="font-medium text-success">Impact: </span>
                      {rec.impact}
                    </div>
                  </div>
                  <div className="rounded-lg bg-background/60 p-2.5">
                    <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      <Code2 className="h-3.5 w-3.5" aria-hidden="true" />
                      Example Implementation
                    </p>
                    <code className="block font-mono text-xs text-primary">
                      {rec.exampleImplementation}
                    </code>
                  </div>
                  {rec.references && rec.references.length > 0 && (
                    <div className="flex flex-wrap gap-2 pt-1">
                      {rec.references.map((ref) => (
                        <a
                          key={ref}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-primary underline-offset-2 hover:underline"
                        >
                          {ref.replace(/^https?:\/\//, '').replace(/\/$/, '')}
                        </a>
                      ))}
                    </div>
                  )}
                </div>
                <Badge variant="outline" className={`shrink-0 ${config.className}`}>
                  {config.label}
                </Badge>
              </div>
            </motion.div>
          );
        })}

        <div className="flex items-center justify-center gap-2 rounded-xl border border-dashed border-border p-4 text-sm text-muted-foreground">
          <span>Fix these issues to improve your security score</span>
          <ArrowRight className="h-4 w-4 text-primary" />
        </div>
      </CardContent>
    </Card>
  );
}
