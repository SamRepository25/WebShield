import { NextRequest, NextResponse } from 'next/server';
import { listSites, createSite } from '@/lib/monitoring-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(): Promise<NextResponse> {
  try {
    const sites = await listSites();
    return NextResponse.json(sites);
  } catch (err) {
    return NextResponse.json({ detail: (err as Error).message }, { status: 500 });
  }
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  let body: { name?: string; url?: string; frequency?: string; monitoring_enabled?: boolean };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: 'Invalid JSON body.' }, { status: 400 });
  }

  if (!body.name || !body.url) {
    return NextResponse.json({ detail: 'Name and URL are required.' }, { status: 400 });
  }

  const validFreqs = ['6h', '12h', 'daily', 'weekly'];
  if (body.frequency && !validFreqs.includes(body.frequency)) {
    return NextResponse.json({ detail: 'Invalid frequency.' }, { status: 400 });
  }

  try {
    const site = await createSite({
      name: body.name,
      url: body.url,
      frequency: body.frequency as '6h' | '12h' | 'daily' | 'weekly' | undefined,
      monitoring_enabled: body.monitoring_enabled,
    });
    return NextResponse.json(site, { status: 201 });
  } catch (err) {
    const msg = (err as Error).message ?? 'Failed to create site.';
    const status = /valid website URL|URL is required|Site name/i.test(msg) ? 400 : 500;
    return NextResponse.json({ detail: msg }, { status });
  }
}
