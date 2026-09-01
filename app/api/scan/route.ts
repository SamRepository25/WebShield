import { NextRequest, NextResponse } from 'next/server';
import { runScan, ScanError } from '@/lib/scanner';
import { assertPublicUrl } from '@/lib/security';
import { checkRateLimit } from '@/lib/rate-limit';

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

export async function POST(request: NextRequest): Promise<NextResponse> {
  const identifier = getClientIdentifier(request);
  try {
    const limit = await checkRateLimit(identifier);
    if (!limit.allowed) {
      return NextResponse.json(
        { detail: 'Too many scan requests. Please try again in a minute.' },
        {
          status: 429,
          headers: {
            'Retry-After': String(limit.retryAfter || 60),
            'Cache-Control': 'no-store',
          },
        }
      );
    }
  } catch (error) {
    console.error('Rate limiter error:', error);
    return NextResponse.json({ detail: 'Rate limiter unavailable. Please try again later.' }, { status: 503 });
  }

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
    const safeUrl = await assertPublicUrl(body.url);
    const result = await runScan(safeUrl);
    return NextResponse.json(result, {
      headers: {
        'Cache-Control': 'no-store',
      },
    });
  } catch (err) {
    if (err instanceof ScanError) {
      return NextResponse.json({ detail: err.message }, { status: err.status });
    }

    const message = err instanceof Error ? err.message : 'Scan failed. Please try again.';
    if (/private|internal|reserved|resolve|credentials|ports|supported/i.test(message)) {
      return NextResponse.json({ detail: message }, { status: 400 });
    }

    console.error('Scan error:', err);
    return NextResponse.json({ detail: 'Scan failed. Please try again.' }, { status: 500 });
  }
}
