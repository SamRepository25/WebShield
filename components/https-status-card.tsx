'use client';

import { motion } from 'framer-motion';
import {
  Lock,
  Unlock,
  Calendar,
  Award,
  Server,
  KeyRound,
  ArrowRightLeft,
  ShieldCheck,
  ShieldAlert,
  Rocket,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import type { ScanResult } from '@/lib/types';

interface HttpsStatusCardProps {
  https: ScanResult['https'];
}

export function HttpsStatusCard({ https }: HttpsStatusCardProps) {
  const isSecure = https.enabled && https.valid;
  const expiryWarning = https.daysRemaining > 0 && https.daysRemaining < 30;
  const hasCertInfo = Boolean(https.issuer || https.protocol || https.expiresAt);

  return (
    <Card className="glass relative overflow-hidden">
      <div
        className={`absolute inset-0 opacity-10 ${
          isSecure ? 'bg-success' : 'bg-destructive'
        }`}
        aria-hidden="true"
      />
      <CardHeader className="relative">
        <CardTitle className="flex items-center justify-between text-base font-medium text-muted-foreground">
          <span className="flex items-center gap-2">
            {isSecure ? (
              <Lock className="h-4 w-4 text-success" aria-hidden="true" />
            ) : (
              <Unlock className="h-4 w-4 text-destructive" aria-hidden="true" />
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
            className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-full ${
              isSecure ? 'bg-success/20' : 'bg-destructive/20'
            }`}
          >
            {isSecure ? (
              <ShieldCheck className="h-7 w-7 text-success" aria-hidden="true" />
            ) : (
              <ShieldAlert className="h-7 w-7 text-destructive" aria-hidden="true" />
            )}
          </div>
          <div className="min-w-0">
            <p className="text-lg font-semibold">
              {https.enabled ? 'HTTPS Enabled' : 'HTTPS Not Enabled'}
            </p>
            <p className="text-sm text-muted-foreground">
              {https.valid
                ? 'Valid SSL/TLS certificate'
                : 'Invalid or missing certificate'}
            </p>
          </div>
        </motion.div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <InfoRow
            icon={ArrowRightLeft}
            label="HTTP → HTTPS Redirect"
            value={
              https.enabled
                ? https.redirectFromHttp
                  ? 'Active'
                  : 'Not Redirecting'
                : 'N/A'
            }
            variant={
              !https.enabled
                ? 'neutral'
                : https.redirectFromHttp
                ? 'success'
                : 'warning'
            }
          />
          <InfoRow
            icon={Rocket}
            label="HSTS Preload Ready"
            value={
              https.enabled
                ? https.hstsPreloadReady
                  ? 'Yes'
                  : 'No'
                : 'N/A'
            }
            variant={
              !https.enabled
                ? 'neutral'
                : https.hstsPreloadReady
                ? 'success'
                : 'neutral'
            }
          />
          <InfoRow
            icon={KeyRound}
            label="Protocol"
            value={https.protocol || 'Not available'}
          />
          <InfoRow
            icon={Award}
            label="Certificate Issuer"
            value={https.issuer || 'Not available'}
          />
          <InfoRow
            icon={Calendar}
            label="Certificate Expires"
            value={https.expiresAt || 'Not available'}
            warning={expiryWarning}
          />
          <InfoRow
            icon={Server}
            label="Days Remaining"
            value={
              https.daysRemaining > 0
                ? `${https.daysRemaining} days`
                : 'Not available'
            }
            warning={expiryWarning}
          />
        </div>

        {!hasCertInfo && https.enabled && (
          <p className="text-xs text-muted-foreground">
            Detailed certificate information is not available for this connection.
            HTTPS is active and the connection is encrypted.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

interface InfoRowProps {
  icon: React.ElementType;
  label: string;
  value: string;
  warning?: boolean;
  variant?: 'success' | 'warning' | 'destructive' | 'neutral';
}

function InfoRow({ icon: Icon, label, value, warning, variant }: InfoRowProps) {
  const colorClass = warning
    ? 'text-warning'
    : variant === 'success'
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
            warning
              ? 'text-warning'
              : variant === 'success'
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
