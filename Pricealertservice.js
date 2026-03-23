// priceAlertService.js
// Runs every 30 minutes — checks all users' positions and fires push notifications
// based on price movement tiers: 3%, 5%, 10%

const axios = require("axios");
const cron = require("node-cron");
const admin = require("firebase-admin"); // for APNs push notifications

// ─── Firebase Admin Init ───────────────────────────────────────────────────
// Download your serviceAccountKey.json from Firebase Console
const serviceAccount = require("./serviceAccountKey.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// ─── Snaptrade Config ──────────────────────────────────────────────────────
const SNAPTRADE_BASE = "https://api.snaptrade.com/api/v1";
const SNAPTRADE_CLIENT_ID = process.env.SNAPTRADE_CLIENT_ID;
const SNAPTRADE_CONSUMER_KEY = process.env.SNAPTRADE_CONSUMER_KEY;

// ─── In-memory price cache (replace with Redis or DB in production) ────────
// Structure: { userId: { AAPL: 182.50, META: 510.00, ... } }
const priceCache = {};

// ─── Alert cooldown tracker (prevent spamming same alert) ─────────────────
// Structure: { userId_SYMBOL_tier: timestamp }
const alertCooldown = {};
const COOLDOWN_MS = 60 * 60 * 1000; // 1 hour cooldown per symbol per tier

// ─── Tiers ────────────────────────────────────────────────────────────────
const TIERS = [
  { percent: 3,  label: "3%",  emoji: "📊" },
  { percent: 5,  label: "5%",  emoji: "⚡️" },
  { percent: 10, label: "10%", emoji: "🚨" },
];

// ─── DB placeholder — replace with your actual DB calls ───────────────────
// You need a table/collection: users { userId, snaptradeUserId, snaptradeUserSecret, fcmToken }
async function getAllUsers() {
  // TODO: Replace with your actual DB query
  // Example with a hypothetical db module:
  // return await db.collection("users").find({ fcmToken: { $exists: true } }).toArray();
  
  // For now returns empty — wire this to your actual user store
  return [];
}

// ─── Snaptrade: get user positions ────────────────────────────────────────
async function getUserPositions(userId, userSecret) {
  try {
    const res = await axios.get(
      `${SNAPTRADE_BASE}/accounts/${userId}/positions`,
      {
        params: {
          clientId: SNAPTRADE_CLIENT_ID,
          userSecret,
        },
        headers: { "Consumer-Key": SNAPTRADE_CONSUMER_KEY },
      }
    );
    // Returns array of { symbol, quantity, price (current), averagePurchasePrice }
    return res.data || [];
  } catch (err) {
    console.error(`❌ Failed to fetch positions for ${userId}:`, err.message);
    return [];
  }
}

// ─── Send push notification via Firebase (APNs for iOS) ───────────────────
async function sendPushNotification(fcmToken, title, body, data = {}) {
  try {
    const message = {
      token: fcmToken,
      notification: { title, body },
      data, // extra payload for deep linking
      apns: {
        payload: {
          aps: {
            sound: "default",
            badge: 1,
          },
        },
      },
    };
    const response = await admin.messaging().send(message);
    console.log(`✅ Notification sent: ${response}`);
  } catch (err) {
    console.error(`❌ Failed to send notification:`, err.message);
  }
}

// ─── Core: check one user's positions for price alerts ────────────────────
async function checkUserPositions(user) {
  const { userId, snaptradeUserId, snaptradeUserSecret, fcmToken } = user;

  if (!fcmToken) return; // no token, can't notify

  const positions = await getUserPositions(snaptradeUserId, snaptradeUserSecret);
  if (!positions.length) return;

  for (const position of positions) {
    // Snaptrade returns positions differently per broker — adjust field names as needed
    const symbol = position?.symbol?.symbol || position?.symbol;
    const currentPrice = parseFloat(position?.price || position?.currentPrice || 0);
    const openPrice = parseFloat(position?.openPrice || position?.averagePurchasePrice || 0);

    if (!symbol || !currentPrice || !openPrice) continue;

    // Calculate % change from open/purchase price
    const change = ((currentPrice - openPrice) / openPrice) * 100;
    const absChange = Math.abs(change);
    const direction = change >= 0 ? "▲" : "▼";
    const directionWord = change >= 0 ? "up" : "down";

    // Check each tier — highest triggered tier wins for this cycle
    let triggeredTier = null;
    for (const tier of [...TIERS].reverse()) { // check 10% first, then 5%, then 3%
      if (absChange >= tier.percent) {
        triggeredTier = tier;
        break;
      }
    }

    if (!triggeredTier) continue;

    // Check cooldown — don't spam same symbol+tier within 1 hour
    const cooldownKey = `${userId}_${symbol}_${triggeredTier.percent}`;
    const lastSent = alertCooldown[cooldownKey];
    if (lastSent && Date.now() - lastSent < COOLDOWN_MS) continue;

    // Calculate P&L impact
    const quantity = parseFloat(position?.quantity || position?.units || 0);
    const dollarChange = (currentPrice - openPrice) * quantity;
    const dollarStr = `$${Math.abs(dollarChange).toFixed(2)}`;

    // Build notification
    const title = `${triggeredTier.emoji} ${symbol} is ${directionWord} ${triggeredTier.label}`;
    const body = `${direction} ${Math.abs(change).toFixed(1)}% · Your position is ${change >= 0 ? "up" : "down"} ${dollarStr}. Tap to analyze.`;

    // Deep link data — iOS app reads this to open TYGER AI with context
    const data = {
      type: "price_alert",
      symbol,
      change: change.toFixed(2),
      currentPrice: currentPrice.toFixed(2),
      dollarChange: dollarChange.toFixed(2),
      tier: triggeredTier.label,
      deepLink: "tyger://chat/alert", // your app's URL scheme
    };

    await sendPushNotification(fcmToken, title, body, data);

    // Mark cooldown
    alertCooldown[cooldownKey] = Date.now();

    console.log(`📲 Alert sent to ${userId} — ${symbol} ${direction}${Math.abs(change).toFixed(1)}%`);
  }
}

// ─── Main job: runs every 30 minutes during market hours ──────────────────
async function runPriceAlertJob() {
  console.log(`🔍 [${new Date().toISOString()}] Running price alert check...`);

  const users = await getAllUsers();
  if (!users.length) {
    console.log("⚠️ No users found.");
    return;
  }

  // Run all users in parallel
  await Promise.allSettled(users.map(checkUserPositions));

  console.log(`✅ Price alert check complete. Checked ${users.length} users.`);
}

// ─── Cron schedule: every 30 min, Mon-Fri, 9:30am–4:00pm ET ──────────────
// "*/30 9-16 * * 1-5" = every 30 min during market hours weekdays
cron.schedule("*/30 9-16 * * 1-5", runPriceAlertJob, {
  timezone: "America/New_York",
});

console.log("🚀 TYGER Price Alert Service running...");
console.log("⏰ Checking every 30 minutes during market hours (9:30am–4pm ET, Mon–Fri)");

// Export for manual triggering / testing
module.exports = { runPriceAlertJob, checkUserPositions };