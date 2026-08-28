import { NextRequest, NextResponse } from 'next/server';
import { runScheduler } from '@/lib/scheduler';
import { hasInternalApiAccess } from '@/lib/internal-api-auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function GET(request: NextRequest) {
  if (!hasInternalApiAccess(request.headers)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const result = await runScheduler();
    return NextResponse.json(result);
  } catch (error) {
    console.error('Scheduler Error:', error);
    return NextResponse.json(
      { success: false, error: 'Scheduler execution failed.' },
      { status: 500 }
    );
  }
}
