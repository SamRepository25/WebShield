import { NextResponse } from "next/server";
import { sendTelegramMessage } from "@/lib/telegram";

export async function GET() {
  const success = await sendTelegramMessage(
`🛡️ *WebShield*

✅ *Telegram Connected Successfully!*

Your WebShield bot is now connected.

Time:
${new Date().toLocaleString()}`
  );

  return NextResponse.json({
    success,
  });
}