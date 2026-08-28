import { NextRequest, NextResponse } from 'next/server';
import { runScan, ScanError } from '@/lib/scanner';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 25;

function getClientIdentifier(request: NextRequest): string {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unknown'
  );
}

const buckets = new Map<string, { count: number; resetAt: number }>();
const WINDOW_MS = 60_000;
const MAX_REQUESTS = 20;

function rateLimit(request: NextRequest): NextResponse | null {
  const key = getClientIdentifier(request);
  const now = Date.now();
  const current = buckets.get(key);

  if (!current || current.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return null;
  }

  if (current.count >= MAX_REQUESTS) {
    return NextResponse.json(
      { detail: 'Too many scan requests. Please try again in a minute.' },
      {
        status: 429,
        headers: { 'Retry-After': String(Math.ceil((current.resetAt - now) / 1000)) },
      }
    );
  }

  current.count += 1;
  return null;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const limited = rateLimit(request);
  if (limited) return limited;

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: 'Invalid JSON body.' }, { status: 400 });
  }

  if (!body || typeof body !== 'object' || !('url' in body) || typeof body.url !== 'string') {
    return NextResponse.json({ detail: 'URL is required.' }, { status: 400 });
  }

  try {
    const result = await runScan(body.url);
    return NextResponse.json(result, {
      headers: {
        'Cache-Control': 'no-store',
      },
    });
  } catch (err) {
    if (err instanceof ScanError) {
      return NextResponse.json({ detail: err.message }, { status: err.status });
    }

    console.error('Scan error:', err);
    return NextResponse.json({ detail: 'Scan failed. Please try again.' }, { status: 500 });
  }
}
