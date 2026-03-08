import cron from "node-cron";
import axios from "axios";
import pkg from "pg";
import { Snaptrade } from "snaptrade-typescript-sdk";
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const ONESIGNAL_APP_ID = process.env.ONESIGNAL_APP_ID as string;
const ONESIGNAL_API_KEY = process.env.ONESIGNAL_API_KEY as string;
const POLYGON_API_KEY = process.env.POLYGON_API_KEY as string;

function mkClient() {
  return new Snaptrade({
    clientId: process.env.SNAPTRADE_CLIENT_ID as string,
    consumerKey: process.env.SNAPTRADE_CONSUMER_KEY as string,
  });
}

// ─── Types ────────────────────────────────────────────────────────────────
interface User {
  userId: string;
  userSecret: string;
  oneSignalPlayerId: string;
}

interface Tier {
  percent: number;
  label: string;
  emoji: string;
}

interface PolygonSnapshot {
  ticker: string;
  day: { o: number; c: number };
  lastTrade?: { p: number };
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
    userSecret: row.user_secret,
    oneSignalPlayerId: row.onesignal_player_id,
  }));
}

// ─── Get positions using Snaptrade SDK ───────────────────────────────────
async function getUserPositions(userId: string, userSecret: string): Promise<{ symbol: string; quantity: number }[]> {
  try {
    const snaptrade = mkClient();

    // Step 1: get accounts
    const accountsResp = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
    const accounts = accountsResp?.data || [];
    if (!accounts.length) return [];

    // Step 2: get positions for each account
    const allPositions: { symbol: string; quantity: number }[] = [];

    for (const account of accounts) {
      const accountId = account?.id || account?.accountId || String(account?.id || "");
      if (!accountId) continue;

      try {
        const posResp = await snaptrade.accountInformation.getUserAccountPositions({
          userId,
          userSecret,
          accountId,
        });
        const positions = posResp?.data || [];
        for (const pos of positions) {
          const symbol = pos?.symbol?.symbol?.symbol || pos?.symbol?.symbol || pos?.symbol;
          const quantity = parseFloat(String(pos?.units || pos?.quantity || 0));
          if (symbol && quantity > 0) {
            allPositions.push({ symbol: String(symbol).toUpperCase(), quantity });
          }
        }
      } catch (e) {
        console.warn(`⚠️ Could not fetch positions for account ${accountId}`);
      }
    }

    return allPositions;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`❌ Failed to fetch positions:`, message);
    return [];
  }
}

// ─── Get prices from Polygon ──────────────────────────────────────────────
async function getPolygonSnapshots(symbols: string[]): Promise<{ [symbol: string]: PolygonSnapshot }> {
  if (!symbols.length) return {};
  try {
    const res = await axios.get(`https://api.polygon.io/v2/snapshot/locale/us/markets/stocks/tickers`, {
      params: { tickers: symbols.join(","), apiKey: POLYGON_API_KEY },
    });
    const snapshots: { [symbol: string]: PolygonSnapshot } = {};
    for (const ticker of res.data?.tickers || []) {
      snapshots[ticker.ticker] = ticker;
    }
    return snapshots;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`❌ Polygon snapshot failed:`, message);
    return {};
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
  const { userId, userSecret, oneSignalPlayerId } = user;
  if (!oneSignalPlayerId) return;

  const positions = await getUserPositions(userId, userSecret);
  if (!positions.length) {
    console.log(`⚠️ No positions for ${userId}`);
    return;
  }

  console.log(`📋 ${userId} has ${positions.length} positions: ${positions.map(p => p.symbol).join(", ")}`);

  const symbols = positions.map((p) => p.symbol);
  const snapshots = await getPolygonSnapshots(symbols);

  for (const position of positions) {
    const snapshot = snapshots[position.symbol];
    if (!snapshot) continue;

    const openPrice = snapshot.day?.o;
    const currentPrice = snapshot.day?.c || snapshot.lastTrade?.p;

    if (!openPrice || !currentPrice || openPrice === 0) continue;

    const change = ((currentPrice - openPrice) / openPrice) * 100;
    const absChange = Math.abs(change);
    const direction = change >= 0 ? "▲" : "▼";
    const directionWord = change >= 0 ? "up" : "down";

    let triggeredTier: Tier | null = null;
    for (const tier of [...TIERS].reverse()) {
      if (absChange >= tier.percent) { triggeredTier = tier; break; }
    }
    if (!triggeredTier) continue;

    const cooldownKey = `${userId}_${position.symbol}_${triggeredTier.percent}`;
    if (alertCooldown[cooldownKey] && Date.now() - alertCooldown[cooldownKey] < COOLDOWN_MS) continue;

    const dollarChange = (currentPrice - openPrice) * position.quantity;
    const title = `${triggeredTier.emoji} ${position.symbol} is ${directionWord} ${triggeredTier.label}`;
    const body = `${direction} ${absChange.toFixed(1)}% · Position ${directionWord} $${Math.abs(dollarChange).toFixed(2)}. Tap to analyze.`;

    const data: { [key: string]: string } = {
      type: "price_alert",
      symbol: position.symbol,
      change: change.toFixed(2),
      currentPrice: currentPrice.toFixed(2),
      dollarChange: dollarChange.toFixed(2),
      tier: triggeredTier.label,
    };

    await sendPushNotification(oneSignalPlayerId, title, body, data);
    alertCooldown[cooldownKey] = Date.now();
    console.log(`📲 Alert — ${userId}: ${position.symbol} ${direction}${absChange.toFixed(1)}%`);
  }
}

// ─── Main job ─────────────────────────────────────────────────────────────
export async function runPriceAlertJob(): Promise<void> {
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