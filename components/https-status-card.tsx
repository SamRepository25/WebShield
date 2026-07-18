'use client';

import { motion } from 'framer-motion';
import { Lock, Unlock, Calendar, Award, Server, KeyRound } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import type { ScanResult } from '@/lib/mock-data';

interface HttpsStatusCardProps {
  https: ScanResult['https'];
}

export function HttpsStatusCard({ https }: HttpsStatusCardProps) {
  const isSecure = https.enabled && https.valid;
  const expiryWarning = https.daysRemaining < 30;

  return (
    <Card className="glass relative overflow-hidden">
      <div
        className={`absolute inset-0 opacity-10 ${
          isSecure ? 'bg-success' : 'bg-destructive'
        }`}
      />
      <CardHeader className="relative">
        <CardTitle className="flex items-center justify-between text-base font-medium text-muted-foreground">
          <span className="flex items-center gap-2">
            {isSecure ? (
              <Lock className="h-4 w-4 text-success" />
            ) : (
              <Unlock className="h-4 w-4 text-destructive" />
            )}
            HTTPS Status
          </span>
          <Badge
            variant="outline"
            className={
              isSecure
                ? 'border-success/30 bg-success/10 text-success'
                : 'border-destructive/30 bg-destructive/10 text-destructive'
            }
          >
            {isSecure ? 'Secure' : 'Not Secure'}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="relative space-y-4">
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.2 }}
          className={`flex items-center gap-4 rounded-xl p-4 ${
            isSecure
              ? 'bg-success/10 ring-1 ring-success/20'
              : 'bg-destructive/10 ring-1 ring-destructive/20'
          }`}
        >
          <div
            className={`flex h-14 w-14 items-center justify-center rounded-full ${
              isSecure ? 'bg-success/20' : 'bg-destructive/20'
            }`}
          >
            {isSecure ? (
              <Lock className="h-7 w-7 text-success" />
            ) : (
              <Unlock className="h-7 w-7 text-destructive" />
            )}
          </div>
          <div>
            <p className="text-lg font-semibold">
              {https.enabled ? 'HTTPS Enabled' : 'HTTPS Not Enabled'}
            </p>
            <p className="text-sm text-muted-foreground">
              {https.valid ? 'Valid SSL/TLS certificate' : 'Invalid or missing certificate'}
            </p>
          </div>
        </motion.div>

        <Separator />

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <InfoRow
            icon={KeyRound}
            label="Protocol"
            value={https.protocol}
          />
          <InfoRow
            icon={Award}
            label="Issuer"
            value={https.issuer}
          />
          <InfoRow
            icon={Calendar}
            label="Expires"
            value={https.expiresAt}
            warning={expiryWarning}
          />
          <InfoRow
            icon={Server}
            label="Days Remaining"
            value={`${https.daysRemaining} days`}
            warning={expiryWarning}
          />
        </div>
      </CardContent>
    </Card>
  );
}

function InfoRow({
  icon: Icon,
  label,
  value,
  warning,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  warning?: boolean;
}) {
  return (
    <div className="flex items-center gap-3 rounded-lg bg-secondary/50 p-3">
      <Icon
        className={`h-4 w-4 shrink-0 ${warning ? 'text-warning' : 'text-primary'}`}
      />
      <div className="min-w-0">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p
          className={`truncate text-sm font-medium ${
            warning ? 'text-warning' : 'text-foreground'
          }`}
        >
          {value}
        </p>
      </div>
    </div>
  );
}
