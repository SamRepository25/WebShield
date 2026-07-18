'use client';

import { Code2, Copy, Check } from 'lucide-react';
import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import type { RawHeader } from '@/lib/mock-data';

interface RawHeadersAccordionProps {
  rawHeaders: RawHeader[];
}

export function RawHeadersAccordion({ rawHeaders }: RawHeadersAccordionProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    const text = rawHeaders.map((h) => `${h.name}: ${h.value}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Card className="glass">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2 text-lg">
            <Code2 className="h-5 w-5 text-primary" />
            Raw Headers
          </span>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="border-primary/30 bg-primary/10 text-primary">
              {rawHeaders.length} Headers
            </Badge>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 rounded-md border border-border bg-secondary/50 px-2.5 py-1 text-xs text-muted-foreground transition-colors hover:text-foreground"
            >
              {copied ? (
                <>
                  <Check className="h-3 w-3 text-success" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="h-3 w-3" />
                  Copy
                </>
              )}
            </button>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Accordion type="single" collapsible className="w-full">
          <AccordionItem
            value="raw-headers"
            className="rounded-lg border border-border bg-secondary/20 px-4"
          >
            <AccordionTrigger className="text-sm font-medium hover:no-underline">
              View all raw HTTP response headers
            </AccordionTrigger>
            <AccordionContent>
              <div className="space-y-1.5 pt-2">
                {rawHeaders.map((header, index) => (
                  <div
                    key={index}
                    className="flex flex-col gap-1 rounded-md bg-background/50 p-2.5 sm:flex-row sm:items-center sm:gap-3"
                  >
                    <span className="shrink-0 font-mono text-xs font-semibold text-primary sm:w-48">
                      {header.name}
                    </span>
                    <span className="font-mono text-xs text-muted-foreground">
                      {header.value}
                    </span>
                  </div>
                ))}
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </CardContent>
    </Card>
  );
}
