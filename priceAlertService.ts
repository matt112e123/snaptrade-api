import cron from "node-cron";
import axios from "axios";
import pkg from "pg";
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const SNAPTRADE_BASE = "https://api.snaptrade.com/api/v1";
const SNAPTRADE_CLIENT_ID = process.env.SNAPTRADE_CLIENT_ID as string;
const SNAPTRADE_CONSUMER_KEY = process.env.SNAPTRADE_CONSUMER_KEY as string;
const ONESIGNAL_APP_ID = process.env.ONESIGNAL_APP_ID as string;
const ONESIGNAL_API_KEY = process.env.ONESIGNAL_API_KEY as string;

// ─── Types ────────────────────────────────────────────────────────────────
interface User {
  userId: string;
  snaptradeUserId: string;
  snaptradeUserSecret: string;
  oneSignalPlayerId: string;
}

interface Tier {
  percent: number;
  label: string;
  emoji: string;
}

interface Position {
  symbol: { symbol: string } | string;
  price?: string | number;
  currentPrice?: string | number;
  openPrice?: string | number;
  averagePurchasePrice?: string | number;
  quantity?: string | number;
  units?: string | number;
}

// ─── Cooldown tracker ─────────────────────────────────────────────────────
const alertCooldown: { [key: string]: number } = {};
const COOLDOWN_MS = 60 * 60 * 1000;

const TIERS: Tier[] = [
  { percent: 3,  label: "3%",  emoji: "📊" },
  { percent: 5,  label: "5%",  emoji: "⚡️" },
  { percent: 10, label: "10%", emoji: "🚨" },
];

// ─── Get all users from DB ────────────────────────────────────────────────
async function getAllUsers(): Promise<User[]> {
  const result = await pool.query(
    "SELECT user_id, user_secret, onesignal_player_id FROM snaptrade_users WHERE onesignal_player_id IS NOT NULL"
  );
  return result.rows.map((row) => ({
    userId: row.user_id,
    snaptradeUserId: row.user_id,
    snaptradeUserSecret: row.user_secret,
    oneSignalPlayerId: row.onesignal_player_id,
  }));
}

// ─── Fetch positions from Snaptrade ───────────────────────────────────────
async function getUserPositions(snaptradeUserId: string, userSecret: string): Promise<Position[]> {
  try {
    const res = await axios.get(`${SNAPTRADE_BASE}/accounts/${snaptradeUserId}/positions`, {
      params: { clientId: SNAPTRADE_CLIENT_ID, userSecret },
      headers: { "Consumer-Key": SNAPTRADE_CONSUMER_KEY },
    });
    return res.data || [];
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`❌ Failed to fetch positions:`, message);
    return [];
  }
}

// ─── Send push notification via OneSignal ─────────────────────────────────
async function sendPushNotification(
  oneSignalPlayerId: string,
  title: string,
  body: string,
  data: { [key: string]: string } = {}
): Promise<void> {
  try {
    await axios.post(
      "https://onesignal.com/api/v1/notifications",
      {
        app_id: ONESIGNAL_APP_ID,
        include_player_ids: [oneSignalPlayerId],
        headings: { en: title },
        contents: { en: body },
        data,
        ios_sound: "default",
      },
      {
        headers: {
          Authorization: `Basic ${ONESIGNAL_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );
    console.log(`✅ Notification sent`);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`❌ Notification failed:`, message);
  }
}

// ─── Check one user's positions ───────────────────────────────────────────
async function checkUserPositions(user: User): Promise<void> {
  const { userId, snaptradeUserId, snaptradeUserSecret, oneSignalPlayerId } = user;
  if (!oneSignalPlayerId) return;

  const positions = await getUserPositions(snaptradeUserId, snaptradeUserSecret);
  if (!positions.length) return;

  for (const position of positions) {
    const symbol = typeof position.symbol === "object" ? position.symbol.symbol : position.symbol;
    const currentPrice = parseFloat(String(position.price ?? position.currentPrice ?? 0));
    const openPrice = parseFloat(String(position.openPrice ?? position.averagePurchasePrice ?? 0));

    if (!symbol || !currentPrice || !openPrice) continue;

    const change = ((currentPrice - openPrice) / openPrice) * 100;
    const absChange = Math.abs(change);
    const direction = change >= 0 ? "▲" : "▼";
    const directionWord = change >= 0 ? "up" : "down";

    let triggeredTier: Tier | null = null;
    for (const tier of [...TIERS].reverse()) {
      if (absChange >= tier.percent) { triggeredTier = tier; break; }
    }
    if (!triggeredTier) continue;

    const cooldownKey = `${userId}_${symbol}_${triggeredTier.percent}`;
    if (alertCooldown[cooldownKey] && Date.now() - alertCooldown[cooldownKey] < COOLDOWN_MS) continue;

    const quantity = parseFloat(String(position.quantity ?? position.units ?? 0));
    const dollarChange = (currentPrice - openPrice) * quantity;

    const title = `${triggeredTier.emoji} ${symbol} is ${directionWord} ${triggeredTier.label}`;
    const body = `${direction} ${absChange.toFixed(1)}% · Position ${directionWord} $${Math.abs(dollarChange).toFixed(2)}. Tap to analyze.`;

    const data: { [key: string]: string } = {
      type: "price_alert",
      symbol,
      change: change.toFixed(2),
      currentPrice: currentPrice.toFixed(2),
      dollarChange: dollarChange.toFixed(2),
      tier: triggeredTier.label,
    };

    await sendPushNotification(oneSignalPlayerId, title, body, data);
    alertCooldown[cooldownKey] = Date.now();
    console.log(`📲 Alert — ${userId}: ${symbol} ${direction}${absChange.toFixed(1)}%`);
  }
}

// ─── Main job ─────────────────────────────────────────────────────────────
async function runPriceAlertJob(): Promise<void> {
  console.log(`🔍 [${new Date().toISOString()}] Running price alert check...`);
  const users = await getAllUsers();
  if (!users.length) { console.log("⚠️ No users found."); return; }
  await Promise.allSettled(users.map(checkUserPositions));
  console.log(`✅ Done. Checked ${users.length} users.`);
}

// ─── Export ───────────────────────────────────────────────────────────────
export function startPriceAlertService(): void {
  cron.schedule("*/30 9-16 * * 1-5", runPriceAlertJob, {
    timezone: "America/New_York",
  });
  console.log("🚀 TYGER Price Alert Service — checks every 30min during market hours");
}