const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;

async function sendTelegramMessage(message: string): Promise<boolean> {
  if (!BOT_TOKEN || !CHAT_ID) {
    console.warn("Telegram Bot is not configured.");
    return false;
  }

  try {
    const response = await fetch(
      `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          chat_id: CHAT_ID,
          text: message,
          parse_mode: "Markdown",
        }),
      }
    );

    const data = await response.json();

    if (!data.ok) {
      console.error("Telegram API Error:", data);
      return false;
    }

    return true;
  } catch (error) {
    console.error(error);
    return false;
  }
}

export async function sendWebsiteDownAlert(url: string) {
  return sendTelegramMessage(
`🚨 *WebShield Alert*

🌐 Website
${url}

❌ Status
Website appears to be DOWN.

🕒 Time
${new Date().toLocaleString()}`
  );
}

export async function sendWebsiteRecoveredAlert(url: string, score: number) {
  return sendTelegramMessage(
`✅ *Website Recovered*

🌐 Website
${url}

📊 Security Score
${score}

🟢 Status
Website is back online.

🕒 Time
${new Date().toLocaleString()}`
  );
}

export async function sendScoreDropAlert(
  url: string,
  previous: number,
  current: number
) {
  return sendTelegramMessage(
`⚠️ *Security Score Dropped*

🌐 Website
${url}

📉 Score
${previous} → ${current}

🕒 Time
${new Date().toLocaleString()}`
  );
}

export async function sendSSLAlert(url: string) {
  return sendTelegramMessage(
`🔒 *SSL Warning*

🌐 Website
${url}

SSL certificate problem detected.

🕒 Time
${new Date().toLocaleString()}`
  );
}

export async function sendHeaderAlert(
  url: string,
  header: string
) {
  return sendTelegramMessage(
`⚠️ *Critical Header Missing*

🌐 Website
${url}

Missing Header
${header}

🕒 Time
${new Date().toLocaleString()}`
  );
}