'use client';

import { motion } from 'framer-motion';
import { Cookie, ShieldCheck, AlertTriangle, ShieldOff } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import type { ScanResult } from '@/lib/types';

interface CookiesCardProps {
  cookies: ScanResult['cookies'];
}

export function CookiesCard({ cookies }: CookiesCardProps) {
  if (cookies.length === 0) {
    return (
      <Card className="glass">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Cookie className="h-5 w-5 text-primary" aria-hidden="true" />
            Cookie Security
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            No cookies were set in this response.
          </p>
        </CardContent>
      </Card>
    );
  }

  const allSecure = cookies.every((c) => c.secure);
  const allHttpOnly = cookies.every((c) => c.httpOnly);
  const allSameSite = cookies.every((c) => c.sameSite !== 'None');

  return (
    <Card className="glass">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2 text-lg">
            <Cookie className="h-5 w-5 text-primary" aria-hidden="true" />
            Cookie Security
          </span>
          <Badge variant="outline" className="border-primary/30 bg-primary/10 text-primary">
            {cookies.length} Cookie{cookies.length > 1 ? 's' : ''}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap gap-2">
          {allSecure ? (
            <Badge variant="outline" className="gap-1.5 border-success/30 bg-success/10 text-success">
              <ShieldCheck className="h-3 w-3" aria-hidden="true" /> All Secure
            </Badge>
          ) : (
            <Badge variant="outline" className="gap-1.5 border-warning/30 bg-warning/10 text-warning">
              <AlertTriangle className="h-3 w-3" aria-hidden="true" /> Missing Secure
            </Badge>
          )}
          {allHttpOnly ? (
            <Badge variant="outline" className="gap-1.5 border-success/30 bg-success/10 text-success">
              <ShieldCheck className="h-3 w-3" aria-hidden="true" /> All HttpOnly
            </Badge>
          ) : (
            <Badge variant="outline" className="gap-1.5 border-warning/30 bg-warning/10 text-warning">
              <AlertTriangle className="h-3 w-3" aria-hidden="true" /> Missing HttpOnly
            </Badge>
          )}
          {allSameSite ? (
            <Badge variant="outline" className="gap-1.5 border-success/30 bg-success/10 text-success">
              <ShieldCheck className="h-3 w-3" aria-hidden="true" /> SameSite Set
            </Badge>
          ) : (
            <Badge variant="outline" className="gap-1.5 border-warning/30 bg-warning/10 text-warning">
              <AlertTriangle className="h-3 w-3" aria-hidden="true" /> Weak SameSite
            </Badge>
          )}
        </div>

        <div className="space-y-2">
          {cookies.map((cookie, index) => (
            <motion.div
              key={`${cookie.name}-${index}`}
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
              className="rounded-lg border border-border bg-secondary/30 p-3"
            >
              <div className="mb-2 flex items-center justify-between gap-2">
                <span className="truncate font-mono text-sm font-medium text-foreground" title={cookie.name}>
                  {cookie.name || '(unnamed)'}
                </span>
                <div className="flex shrink-0 gap-1">
                  {cookie.secure ? (
                    <ShieldCheck className="h-3.5 w-3.5 text-success" aria-label="Secure" />
                  ) : (
                    <ShieldOff className="h-3.5 w-3.5 text-destructive" aria-label="Not secure" />
                  )}
                  {cookie.httpOnly ? (
                    <ShieldCheck className="h-3.5 w-3.5 text-success" aria-label="HttpOnly" />
                  ) : (
                    <ShieldOff className="h-3.5 w-3.5 text-destructive" aria-label="Not HttpOnly" />
                  )}
                </div>
              </div>
              {cookie.weaknesses.length > 0 && (
                <p className="text-xs text-warning">{cookie.weaknesses.join(' · ')}</p>
              )}
              <p className="mt-1 text-xs text-muted-foreground">SameSite: {cookie.sameSite}</p>
            </motion.div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
