import { NextRequest, NextResponse } from 'next/server';
import { updateSite, deleteSite } from '@/lib/monitoring-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function PUT(
  request: NextRequest,
  { params }: { params: { id: string } }
): Promise<NextResponse> {
  let body: {
    name?: string;
    url?: string;
    frequency?: string;
    monitoring_enabled?: boolean;
  };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: 'Invalid JSON body.' }, { status: 400 });
  }

  const validFreqs = ['6h', '12h', 'daily', 'weekly'];
  if (body.frequency && !validFreqs.includes(body.frequency)) {
    return NextResponse.json({ detail: 'Invalid frequency.' }, { status: 400 });
  }

  try {
    const site = await updateSite(params.id, {
      name: body.name,
      url: body.url,
      frequency: body.frequency as '6h' | '12h' | 'daily' | 'weekly' | undefined,
      monitoring_enabled: body.monitoring_enabled,
    });
    return NextResponse.json(site);
  } catch (err) {
    const msg = (err as Error).message ?? 'Failed to update site.';
    const status = /valid website URL|cannot be empty|Invalid frequency/i.test(msg) ? 400 : 500;
    return NextResponse.json({ detail: msg }, { status });
  }
}

export async function DELETE(
  _request: NextRequest,
  { params }: { params: { id: string } }
): Promise<NextResponse> {
  try {
    await deleteSite(params.id);
    return new NextResponse(null, { status: 204 });
  } catch (err) {
    return NextResponse.json({ detail: (err as Error).message }, { status: 500 });
  }
}
