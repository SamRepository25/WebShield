import { NextRequest, NextResponse } from 'next/server';
import { sendTelegramMessage } from '@/lib/telegram';
import { hasInternalApiAccess } from '@/lib/internal-api-auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  if (!hasInternalApiAccess(request.headers)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const success = await sendTelegramMessage(
    `🛡️ *WebShield*\n\n✅ *Telegram Connected Successfully!*\n\nYour WebShield bot is now connected.\n\nTime:\n${new Date().toLocaleString()}`
  );

  return NextResponse.json({ success });
}
