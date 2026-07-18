'use client';

import { useState, useMemo } from 'react';
import { Code2, Copy, Check, Search } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import type { RawHeader } from '@/lib/types';

interface RawHeadersAccordionProps {
  rawHeaders: RawHeader[];
}

export function RawHeadersAccordion({ rawHeaders }: RawHeadersAccordionProps) {
  const [copied, setCopied] = useState(false);
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    if (!query.trim()) return rawHeaders;
    const q = query.toLowerCase();
    return rawHeaders.filter(
      (h) =>
        h.name.toLowerCase().includes(q) || h.value.toLowerCase().includes(q)
    );
  }, [rawHeaders, query]);

  const handleCopy = async () => {
    const text = rawHeaders.map((h) => `${h.name}: ${h.value}`).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard not available
    }
  };

  return (
    <Card className="glass">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2 text-lg">
            <Code2 className="h-5 w-5 text-primary" aria-hidden="true" />
            Raw Headers
          </span>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="border-primary/30 bg-primary/10 text-primary">
              {rawHeaders.length} Headers
            </Badge>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 rounded-md border border-border bg-secondary/50 px-2.5 py-1 text-xs text-muted-foreground transition-colors hover:text-foreground"
              aria-label="Copy all raw headers to clipboard"
            >
              {copied ? (
                <>
                  <Check className="h-3 w-3 text-success" aria-hidden="true" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="h-3 w-3" aria-hidden="true" />
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
              <div className="space-y-3 pt-2">
                <div className="relative">
                  <Search
                    className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
                    aria-hidden="true"
                  />
                  <Input
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Filter headers..."
                    aria-label="Filter raw headers"
                    className="h-9 border-border bg-background/50 pl-9 text-sm"
                  />
                </div>
                <div className="max-h-80 space-y-1.5 overflow-y-auto scrollbar-thin">
                  {filtered.length === 0 ? (
                    <p className="py-4 text-center text-xs text-muted-foreground">
                      No headers match your filter.
                    </p>
                  ) : (
                    filtered.map((header, index) => (
                      <div
                        key={`${header.name}-${index}`}
                        className="flex flex-col gap-1 rounded-md bg-background/50 p-2.5 sm:flex-row sm:items-center sm:gap-3"
                      >
                        <span className="shrink-0 font-mono text-xs font-semibold text-primary sm:w-48">
                          {header.name}
                        </span>
                        <span className="break-all font-mono text-xs text-muted-foreground">
                          {header.value}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </CardContent>
    </Card>
  );
}
