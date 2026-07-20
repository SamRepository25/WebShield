import { NextRequest, NextResponse } from 'next/server';
import { listScans } from '@/lib/monitoring-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest): Promise<NextResponse> {
  const { searchParams } = new URL(request.url);
  const siteId = searchParams.get('site_id') ?? undefined;
  const limitParam = searchParams.get('limit');
  const offsetParam = searchParams.get('offset');
  const limit = limitParam ? Math.min(parseInt(limitParam, 10) || 50, 200) : 50;
  const offset = offsetParam ? parseInt(offsetParam, 10) || 0 : 0;

  try {
    const scans = await listScans({ siteId, limit, offset });
    return NextResponse.json(scans);
  } catch (err) {
    return NextResponse.json({ detail: (err as Error).message }, { status: 500 });
  }
}
