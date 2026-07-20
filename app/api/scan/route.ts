import { NextRequest, NextResponse } from 'next/server';
import { runScan, ScanError } from '@/lib/scanner';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 25;

export async function POST(request: NextRequest): Promise<NextResponse> {
  let body: { url?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: 'Invalid JSON body.' }, { status: 400 });
  }

  const rawUrl = body?.url;
  if (!rawUrl || typeof rawUrl !== 'string') {
    return NextResponse.json({ detail: 'URL is required.' }, { status: 400 });
  }

  try {
    const result = await runScan(rawUrl);
    return NextResponse.json(result);
  } catch (err) {
    if (err instanceof ScanError) {
      return NextResponse.json({ detail: err.message }, { status: err.status });
    }
    return NextResponse.json({ detail: (err as Error).message || 'Scan failed.' }, { status: 400 });
  }
}
