import { NextRequest, NextResponse } from 'next/server';
import { executeScan } from '@/lib/monitoring-service';
import { ScanError } from '@/lib/scanner';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 25;

export async function POST(
  _request: NextRequest,
  { params }: { params: { id: string } }
): Promise<NextResponse> {
  try {
    const { result, diff } = await executeScan(params.id, 'manual');
    return NextResponse.json({ result, diff });
  } catch (err) {
    if (err instanceof ScanError) {
      return NextResponse.json({ detail: err.message }, { status: err.status });
    }
    const msg = (err as Error).message ?? 'Scan failed.';
    const status = /Site not found/i.test(msg) ? 404 : 500;
    return NextResponse.json({ detail: msg }, { status });
  }
}
