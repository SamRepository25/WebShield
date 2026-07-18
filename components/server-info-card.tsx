'use client';

import { motion } from 'framer-motion';
import { Server, Zap, ArrowRight, EyeOff, CheckCircle2, AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import type { ScanResult } from '@/lib/types';

interface ServerInfoCardProps {
  server: ScanResult['server'];
}

export function ServerInfoCard({ server }: ServerInfoCardProps) {
  const hidesServerInfo = !server.server && !server.xPoweredBy && !server.poweredBy;
  const hasCompression = server.compression && server.compression !== 'none';
  const statusOk = server.finalStatusCode > 0 && server.finalStatusCode < 400;

  return (
    <Card className="glass">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2 text-lg">
            <Server className="h-5 w-5 text-primary" aria-hidden="true" />
            Server Information
          </span>
          <Badge variant="outline" className="border-primary/30 bg-primary/10 text-primary">
            HTTP {server.finalStatusCode}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <InfoRow
            icon={Server}
            label="Server"
            value={server.server || 'Hidden'}
            variant={server.server ? 'neutral' : 'success'}
          />
          <InfoRow
            icon={EyeOff}
            label="X-Powered-By"
            value={server.xPoweredBy || server.poweredBy || 'Hidden'}
            variant={server.xPoweredBy || server.poweredBy ? 'warning' : 'success'}
          />
          <InfoRow
            icon={Zap}
            label="Compression"
            value={hasCompression ? server.compression.toUpperCase() : 'None'}
            variant={hasCompression ? 'success' : 'neutral'}
          />
          <InfoRow
            icon={ArrowRight}
            label="Redirects"
            value={
              server.redirectCount === 0
                ? 'None'
                : `${server.redirectCount} redirect${server.redirectCount > 1 ? 's' : ''}`
            }
            variant={server.redirectCount > 3 ? 'warning' : 'neutral'}
          />
        </div>

        {server.redirectChain.length > 1 && (
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Redirect Chain
            </p>
            <div className="space-y-1.5">
              {server.redirectChain.map((step, index) => (
                <motion.div
                  key={`${step.url}-${index}`}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="flex items-center gap-2 rounded-md bg-secondary/40 p-2 text-xs"
                >
                  <span
                    className={`flex h-5 w-12 shrink-0 items-center justify-center rounded font-mono font-semibold ${
                      step.https ? 'bg-success/20 text-success' : 'bg-destructive/20 text-destructive'
                    }`}
                  >
                    {step.status}
                  </span>
                  <span className="truncate font-mono text-muted-foreground" title={step.url}>
                    {step.url}
                  </span>
                </motion.div>
              ))}
            </div>
          </div>
        )}

        <div className="flex flex-wrap gap-2 pt-1">
          {hidesServerInfo && (
            <Badge variant="outline" className="gap-1.5 border-success/30 bg-success/10 text-success">
              <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
              Server info hidden
            </Badge>
          )}
          {hasCompression && (
            <Badge variant="outline" className="gap-1.5 border-success/30 bg-success/10 text-success">
              <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
              Compression enabled
            </Badge>
          )}
          {statusOk && (
            <Badge variant="outline" className="gap-1.5 border-success/30 bg-success/10 text-success">
              <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
              Healthy response
            </Badge>
          )}
          {(server.server || server.xPoweredBy || server.poweredBy) && (
            <Badge variant="outline" className="gap-1.5 border-warning/30 bg-warning/10 text-warning">
              <AlertTriangle className="h-3 w-3" aria-hidden="true" />
              Version info exposed
            </Badge>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

interface InfoRowProps {
  icon: React.ElementType;
  label: string;
  value: string;
  variant?: 'success' | 'warning' | 'destructive' | 'neutral';
}

function InfoRow({ icon: Icon, label, value, variant = 'neutral' }: InfoRowProps) {
  const colorClass =
    variant === 'success'
      ? 'text-success'
      : variant === 'warning'
      ? 'text-warning'
      : variant === 'destructive'
      ? 'text-destructive'
      : 'text-primary';
  return (
    <div className="flex items-center gap-3 rounded-lg bg-secondary/50 p-3">
      <Icon className={`h-4 w-4 shrink-0 ${colorClass}`} aria-hidden="true" />
      <div className="min-w-0">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p
          className={`truncate text-sm font-medium ${
            variant === 'success'
              ? 'text-success'
              : variant === 'warning'
              ? 'text-warning'
              : variant === 'destructive'
              ? 'text-destructive'
              : 'text-foreground'
          }`}
        >
          {value}
        </p>
      </div>
    </div>
  );
}
