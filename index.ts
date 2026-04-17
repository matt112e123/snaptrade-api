import "dotenv/config";
import express from "express";
import { Snaptrade } from "snaptrade-typescript-sdk";
import os from "os";
import cors from "cors";
import fs from "fs";
import path from "path";
import { startPriceAlertService, runPriceAlertJob } from "./priceAlertService";
import usersRouter from "./usersRoute";
import apn from '@parse/node-apn';

import pkg from "pg";
const { Pool } = pkg;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;



// Use your project folder explicitly
const LOCAL_SAVE_DIR = path.resolve(process.cwd(), "snaptrade_local");
// If this file is in src/ or dist/, "../" will put it at the project root

if (!fs.existsSync(LOCAL_SAVE_DIR)) {
  fs.mkdirSync(LOCAL_SAVE_DIR, { recursive: true });
}
console.log("Local save dir:", LOCAL_SAVE_DIR);

// ✅ Test writing to local folder
(async () => {
  const testFile = path.join(LOCAL_SAVE_DIR, "test.json");
  fs.writeFileSync(testFile, JSON.stringify({ ok: true }, null, 2), "utf-8");
  console.log("✅ Test file written at:", testFile);
})();

async function saveLocally(userId: string, summary: any, userSecret?: string) {
  const filePath = path.join(LOCAL_SAVE_DIR, `${userId}.json`);
  const payload = { userId, userSecret: userSecret || "", summary, savedAt: new Date().toISOString() };
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), "utf-8");
}

// 1️⃣ Database connection (top of file)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Render Postgres URL
  ssl: { rejectUnauthorized: false }
});

// Save full per-account holdings
async function saveAccountHoldingsToDB(userId: string, accountId: string, rawHoldings: any) {
  if (!rawHoldings) return;
  const sql = `
    INSERT INTO snaptrade_account_holdings (user_id, account_id, raw)
    VALUES ($1, $2, $3)
    ON CONFLICT (user_id, account_id)
    DO UPDATE SET raw = EXCLUDED.raw, updated_at = CURRENT_TIMESTAMP
  `;
  try {
    await pool.query(sql, [userId, accountId, JSON.stringify(rawHoldings)]);
    console.log(`✅ Saved holdings for ${userId}/${accountId}`);
  } catch (err: any) {
    console.error("❌ Failed to save account holdings:", errPayload(err));
  }
}

async function syncHoldingsToUserHoldings(userId: string, positions: any[]) {
  console.log(`🔄 syncHoldingsToUserHoldings called for ${userId} with ${positions.length} positions`);
  if (!positions.length) return;
  try {
    const tickers = positions
      .filter(p => p.symbol && p.symbol !== 'UNKNOWN' && !UUID_RE.test(p.symbol))
      .map(p => p.symbol.toUpperCase());

    if (!tickers.length) return;

    const response = await fetch('https://apex-auth-backend.onrender.com/api/holdings/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ snaptrade_user_id: userId, tickers }) // ← send snaptrade_user_id
    });
    const responseText = await response.text();
    console.log(`📦 holdings/sync response: ${response.status} ${responseText}`);
  } catch (err) {
    console.error('❌ Failed to sync holdings to main backend:', err);
  
}
}

// Persist activities and upsert when brokerage_order_id exists
async function saveActivitiesToDB(userId: string, accountId: string, activities: any[] = []) {
  if (!activities || activities.length === 0) return;

  const rows: string[] = [];
  const vals: any[] = [];
  let idx = 1;

  for (const act of activities) {
    const brokerageId = act?.brokerage_order_id || act?.brokerageOrderId || act?.orderId || null;
    const symbol =
      act?.universal_symbol?.symbol ||
      act?.symbol?.symbol ||
      (typeof act?.symbol === 'string' ? act.symbol : null) ||
      null;
    const action = (act?.action || act?.type || act?.side || null);
    const qty = pickNumber(act?.filled_quantity, act?.filledQuantity, act?.quantity, act?.units) ?? 0;
    const price = pickNumber(act?.execution_price, act?.executionPrice, act?.price, act?.averagePrice) ?? null;
    const exec = (act?.time_executed || act?.executionDate || act?.executed_at || act?.time_placed || act?.created_at || null);

    // 9 placeholders: brokerage_order_id, user_id, account_id, symbol, action, quantity, price, execution_time, raw
    rows.push(`($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`);
    vals.push(brokerageId, userId, accountId, symbol, action, qty, price, exec, JSON.stringify(act));
  }

  const sql = `
    INSERT INTO snaptrade_transactions
      (brokerage_order_id, user_id, account_id, symbol, action, quantity, price, execution_time, raw)
    VALUES ${rows.join(",")}
    ON CONFLICT ON CONSTRAINT ux_snaptrade_transactions_brokerage_order_id
    DO UPDATE SET
      user_id = EXCLUDED.user_id,
      account_id = EXCLUDED.account_id,
      symbol = EXCLUDED.symbol,
      action = EXCLUDED.action,
      quantity = EXCLUDED.quantity,
      price = EXCLUDED.price,
      execution_time = EXCLUDED.execution_time,
      raw = EXCLUDED.raw
  `;

  try {
    await pool.query(sql, vals);
    console.log(`✅ Wrote/updated ${activities.length} activities for ${userId}/${accountId}`);
  } catch (err: any) {
    console.error("❌ Failed to write activities to DB:", errPayload(err));
  }
}

// 2️⃣ Save function (right after pool)
async function saveSnaptradeUser(userId: string, userSecret: string, data: any = {}) {
  // Always try local save first
  try {
    await saveLocally(userId, data, userSecret);
    console.log(`✅ Saved ${userId} locally`);
  } catch (err: any) {
    console.error("❌ Failed to save locally:", err);
  }

  // Add near your DB helpers (after saveSnaptradeUser)

// ----------------- helper: save activities into transactions table -----------------

  // DO NOT save empty summaries to DB
 if (data && typeof data === "object") {
  const hasAccounts = Array.isArray(data.accounts) && data.accounts.length > 0;
  const hasPositions = Array.isArray(data.positions) && data.positions.length > 0;
  const hasActivities = data.activitiesByAccount && Object.keys(data.activitiesByAccount || {}).some(k => Array.isArray(data.activitiesByAccount[k]) && data.activitiesByAccount[k].length > 0);
  if (!hasAccounts && !hasPositions && !hasActivities) {
    console.warn(`⚠️ Skipped DB save for ${userId}: no accounts, positions or activities`);
    return;
  }
}

  // Then try DB save (if not empty)
  try {
    const query = `
      INSERT INTO snaptrade_users (user_id, user_secret, data)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id)
      DO UPDATE SET user_secret = EXCLUDED.user_secret, data = EXCLUDED.data, updated_at = CURRENT_TIMESTAMP
    `;
    await pool.query(query, [userId, userSecret, JSON.stringify(data)]);
    console.log(`✅ Saved ${userId} to DB`);
  } catch (err: any) {
    console.error("❌ Failed to save user to DB:", err);
  }
}


// 3️⃣ Fetch & save summary helper
async function fetchAndSaveUserSummary(userId: string, userSecret: string) {
  console.log("🔥 fetchAndSaveUserSummary CALLED for user:", userId);
  const snaptrade = mkClient();

  // Fetch accounts
  const accountsResp = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
  const accounts: any[] = accountsResp.data || [];

  // Keep both activities and raw holdings by account
  const activitiesByAccount: Record<string, any[]> = {};
  const holdingsByAccount: Record<string, any> = {};

  let totalValue = 0, totalCash = 0, totalBP = 0;
  const outPositions: any[] = [];
  let syncing = false;

  for (const acct of accounts) {
    const accountId = acct.id || acct.accountId || acct.number || acct.guid || "";
    if (!accountId) continue;

    // Fetch full holdings for this account
const h = await snaptrade.accountInformation.getUserHoldings({ userId, userSecret, accountId });
    // Save the full raw holdings to dedicated table and keep in-memory copy for summary
    try {
      await saveAccountHoldingsToDB(userId, accountId, h.data);
    } catch (e: any) {
      console.error("Failed to save account holdings:", errPayload(e));
    }
    holdingsByAccount[accountId] = h.data;

    // Fetch activities for this account
    let activities: any[] = [];
    try {
      const activityResp = await snaptrade.accountInformation.getAccountActivities({ accountId, userId, userSecret });
      activities = Array.isArray(activityResp.data) ? activityResp.data : [];
      console.log(`Fetched activities for ${accountId}: count=${Array.isArray(activityResp.data) ? activityResp.data.length : 'non-array'}`);
      if (!Array.isArray(activityResp.data)) {
        console.log('activityResp.data sample:', JSON.stringify(activityResp.data).slice(0, 2000));
      }
    } catch (err: any) {
      console.error(`Failed to fetch activities for account ${accountId}:`, errPayload(err));
    }

    // Keep in summary and persist to transactions table
    activitiesByAccount[accountId] = activities;
    await saveActivitiesToDB(userId, accountId, activities);

    // Balances extraction (existing logic)
    const balObj: any = h.data?.balance || {};
    const balancesArr: any[] = h.data?.balances || [];

    const acctTotal = pickNumber(balObj?.total, balObj?.total?.amount);
    const acctCash = pickNumber(balObj?.cash, balObj?.cash?.amount) || pickNumber(balancesArr.find(b => b?.cash != null) || {});
    const acctBP = pickNumber(balObj?.buyingPower, balObj?.buying_power, balObj?.buying_power?.amount) || pickNumber(balancesArr.find(b => b?.buying_power != null) || {}) || acctCash;

    totalValue += acctTotal ?? 0;
    totalCash += acctCash ?? 0;
    totalBP += acctBP ?? 0;

    // Positions extraction (existing logic)
    const explicitPositions =
      (h.data && (h.data.positions || h.data.holdings?.positions || h.data.account?.positions || h.data.account?.holdings?.positions)) ||
      findPositionsArray(h.data) || [];

    for (const p of explicitPositions) {
      const sym = extractDisplaySymbol(p);

      const symbolId = pickStringStrict(
        p?.universal_symbol?.id,
        p?.symbol?.id,
        p?.symbol_id,
        p?.security_id,
        p?.instrument_id,
        p?.id,
        sym
      ) || sym;

      let qty = pickNumber(
        p?.units,
        p?.filled_quantity,
        p?.filledQuantity,
        p?.quantity,
        p?.qty,
        p?.total_quantity
      ) ?? 0;

      let price = pickNumber(
        p?.price,
        p?.execution_price,
        p?.executionPrice,
        p?.average_purchase_price,
        p?.averagePrice,
        p?.last_trade_price
      );

      const mv = pickNumber(p?.market_value, p?.marketValue, p?.value);

      if ((price === null || price === undefined) && mv && qty) {
        price = mv / qty;
      }
      price = price ?? 0;

      const value = (mv != null && mv !== undefined) ? mv : (qty * price);

      outPositions.push({
        symbol: sym,
        symbolId,
        needsMapping: UUID_RE.test(sym),
        name: extractDisplayName(p),
        quantity: qty,
        price,
        value,
        isCrypto: isCryptoPosition(p),
      });
    }

    const ss: any = h.data?.sync_status || h.data?.syncStatus;
    const initDone = ss?.holdings?.initial_sync_completed ?? ss?.holdings?.initialSyncCompleted;
    if (initDone === false) syncing = true;
  }

const positionsValue = outPositions.reduce((sum: number, p: any) => sum + (p.value || 0), 0);

const summary = {
  accounts: accounts.map((a: any, i: number) => {
    const accountId = a.id ?? a.accountId ?? a.number ?? a.guid ?? `acct-${i}`;
    const h = holdingsByAccount?.[accountId];
    const balObj = h?.balance || {};
    const balancesArr = h?.balances || [];

   const rawCash =
  pickNumber(balObj.cash, balObj.cash?.amount) ??
  pickNumber(balancesArr.find((b: any) => b?.cash != null) || {}) ?? null;
const totalAmount = pickNumber(balObj?.total, balObj?.total?.amount);
const cash = (rawCash === 0 && totalAmount && totalAmount > 0) ? totalAmount : rawCash;
const buyingPower =
  pickNumber(balObj.buyingPower, balObj.buying_power, balObj.buying_power?.amount) ??
  cash;
  console.log(`DEBUG CASH for ${accountId}: rawCash=${rawCash} totalAmount=${totalAmount} cash=${cash} buyingPower=${buyingPower}`);


    return {
      id: String(accountId),
      name: a.name || a.accountName || "Account",
      currency: a.currency || "USD",
      type: a.type || a.accountType || "BROKERAGE",
      number: a.number ?? null,
      meta: a.meta ?? a.raw_meta ?? a.metaData ?? null,
      cash,
      buyingPower
    }
  }),
totals: {
    // Real account equity = what the broker actually reports (positions + cash, including margin)
    // For margin accounts with negative cash, this correctly nets the margin loan
    equity: totalValue > 0 ? totalValue : positionsValue,
    positionsValue: positionsValue,  // gross position value (ignoring cash/margin) — for display
    cash: totalCash,
    buyingPower: totalBP,
  },
  positions: outPositions,
  activitiesByAccount,
  holdingsByAccount,
  syncing,
};

  // Save locally and to DB via your existing helper
  await saveSnaptradeUser(userId, userSecret, summary);
  await syncHoldingsToUserHoldings(userId, outPositions);
  return summary;
}

async function fetchUserSecretFromDB(userId: string): Promise<string> {
  try {
    const res = await pool.query(
      'SELECT user_secret FROM snaptrade_users WHERE user_id = $1 LIMIT 1',
      [userId]
    );
    return res.rows[0]?.user_secret || '';
  } catch (err: any) {
    console.error('❌ Failed to fetch userSecret from DB:', err);
    return '';
  }
}


/* ------------------------ config / helpers ------------------------ */

const PORT = Number(process.env.PORT || 4000);
const HOST = process.env.HOST || "0.0.0.0";

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v || !v.trim()) throw new Error(`Missing required env var ${name}`);
  return v.trim();
}

function mkClient() {
  return new Snaptrade({
    clientId: requireEnv("SNAPTRADE_CLIENT_ID"),
    consumerKey: requireEnv("SNAPTRADE_CONSUMER_KEY"),
  });
}

function lanIPs(): string[] {
  const ips: string[] = [];
  Object.values(os.networkInterfaces()).forEach((list) => {
    (list || []).forEach((n: any) => {
      if (!n.internal && n.family === "IPv4") ips.push(n.address);
    });
  });
  return ips;
}

function errPayload(err: any) {
  const status = err?.response?.status;
  const headers = err?.response?.headers;
  const data = err?.response?.data;
  const message = err?.message || String(err);
  console.error("❌ UPSTREAM/ROUTE ERROR:", { status, message, data });
  return { status, headers, data, message };
}

function pickNumber(...candidates: any[]): number | null {
  for (const v of candidates) {
    if (v == null) continue;
    if (typeof v === "number" && Number.isFinite(v)) return v;
    if (typeof v === "string") {
      const n = Number(v);
      if (!Number.isNaN(n)) return n;
    }
    if (typeof v === "object") {
      for (const key of ["amount","value","price","market_value","marketValue","cash","buying_power","buyingPower","total"]) {
        const nested = v[key];
        if (nested != null) {
          if (typeof nested === "number" && Number.isFinite(nested)) return nested;
          if (typeof nested === "string" && nested.trim() && !Number.isNaN(Number(nested))) return Number(nested);
          if (typeof nested === "object") {
            const n2 = pickNumber(nested);
            if (n2 !== undefined && n2 !== null) return n2;
          }
        }
      }
    }
  }
  return null;
}


function pickStringStrict(...candidates: any[]): string {
  for (const v of candidates) if (typeof v === "string" && v.trim()) return v.trim();
  return "";
}

/* ----------------- symbol/name extractors (ticker-first) ---------- */

function extractDisplaySymbol(p: any): string {
  const s = p?.symbol;
  const u = p?.universal_symbol;
  const o = p?.option_symbol;

  const candidates: any[] = [
    u?.symbol, u?.ticker,
    s?.symbol, s?.ticker, s?.code, s?.raw_symbol, s?.rawSymbol,
    s?.symbol?.symbol, s?.symbol?.ticker, s?.symbol?.code, s?.symbol?.raw_symbol, s?.symbol?.rawSymbol,
    typeof s === "string" ? s : "",
    (typeof o === "string" ? o : o?.symbol),
  ];

  for (const c of candidates) if (typeof c === "string" && c.trim()) return c.trim().toUpperCase();

  const idCandidates: any[] = [u?.id, s?.id, p?.symbol_id, p?.security_id, p?.instrument_id, p?.id];
  for (const c of idCandidates) if (typeof c === "string" && c.trim()) return c.trim().toUpperCase();
  return "UNKNOWN";
}

function extractDisplayName(p: any): string {
  const s = p?.symbol;
  const u = p?.universal_symbol;
  const candidates: any[] = [
    s?.symbol?.description, s?.symbol?.name, s?.description, s?.name,
    u?.description, u?.name, p?.description, p?.longName,
  ];
  for (const c of candidates) if (typeof c === "string" && c.trim()) return c.trim();
  return extractDisplaySymbol(p);
}

function isCryptoPosition(p: any): boolean {
  const t = pickStringStrict(p?.symbol?.type?.code, p?.symbol?.securityType).toLowerCase();
  if (t.includes("crypto")) return true;
  const sym = extractDisplaySymbol(p);
  return /^(BTC|ETH|SOL|DOGE|ADA|USDT|USDC|BNB)\b/i.test(sym);
}

function findPositionsArray(root: any): any[] {
  const hits: any[][] = [];
  const looksLikePosition = (o: any) =>
    !!o && typeof o === "object" &&
    ("symbol" in o || "universal_symbol" in o || "option_symbol" in o ||
     "symbol_id" in o || "security_id" in o || "instrument_id" in o ||
     (typeof o.id === "string" && o.id.length >= 8));

  const walk = (x: any) => {
    if (Array.isArray(x)) {
      if (x.some(looksLikePosition)) hits.push(x);
      x.forEach(walk);
    } else if (x && typeof x === "object") {
      for (const v of Object.values(x)) walk(v);
    }
  };

  walk(root);
  return hits.sort((a, b) => b.length - a.length)[0] || [];
}

/* ------------------ short-TTL secret cache (no DB) ---------------- */

type SecretRow = { secret: string; expiresAt: number };
const USER_SECRETS = new Map<string, SecretRow>();
const SECRET_TTL_MS = 365 * 24 * 60 * 60 * 1000; // 1 year
// Add right after the USER_SECRETS cleanup setInterval block
const MARKET_CACHE = new Map(); // cacheKey -> { expires: number, data: any }
const MARKET_CACHE_TTL_MS = 60 * 1000; // 60s cache for FMP responses

function putSecret(userId: string, userSecret: string) {
  USER_SECRETS.set(userId, { secret: userSecret, expiresAt: Date.now() + SECRET_TTL_MS });
}
function getSecret(userId: string): string {
  const row = USER_SECRETS.get(userId);
  if (!row) return "";
  if (Date.now() > row.expiresAt) { USER_SECRETS.delete(userId); return ""; }
  return row.secret;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of USER_SECRETS) if (now > v.expiresAt) USER_SECRETS.delete(k);
}, 60_000);


// ── Retail flow signal helpers ──

import crypto from 'crypto';

function hashUserId(userId: string): string {
  return crypto.createHash('sha256').update(userId + (process.env.SIGNAL_HASH_SALT || 'tyger-salt')).digest('hex').slice(0, 16);
}

function getMarketSession(): string {
  const now = new Date();
  const hour = now.getUTCHours();
  const minute = now.getUTCMinutes();
  const totalMinutes = hour * 60 + minute;
  // NYSE hours in UTC: 9:30 AM - 4:00 PM ET = 14:30 - 21:00 UTC
  if (totalMinutes >= 870 && totalMinutes < 1260) return 'REGULAR';
  if (totalMinutes >= 540 && totalMinutes < 870) return 'PRE_MARKET';
  return 'EXTENDED';
}

function getSector(symbol: string): string {
  const SECTORS: Record<string, string> = {
    'AAPL': 'Tech', 'MSFT': 'Tech', 'GOOGL': 'Tech', 'META': 'Tech', 'NVDA': 'Tech',
    'AMZN': 'Tech', 'TSLA': 'Tech', 'AMD': 'Tech', 'INTC': 'Tech', 'CRM': 'Tech',
    'JPM': 'Finance', 'BAC': 'Finance', 'GS': 'Finance', 'MS': 'Finance', 'WFC': 'Finance',
    'XOM': 'Energy', 'CVX': 'Energy', 'COP': 'Energy', 'SLB': 'Energy',
    'JNJ': 'Healthcare', 'PFE': 'Healthcare', 'UNH': 'Healthcare', 'MRNA': 'Healthcare',
    'SPY': 'ETF', 'QQQ': 'ETF', 'IWM': 'ETF', 'GLD': 'ETF', 'TLT': 'ETF',
    'BTC': 'Crypto', 'ETH': 'Crypto', 'SOL': 'Crypto', 'DOGE': 'Crypto',
  };
  return SECTORS[symbol.toUpperCase()] || 'Other';
}

function getBrokerCountry(brokerName: string): string {
  const COUNTRIES: Record<string, string> = {
    'ROBINHOOD': 'US', 'SCHWAB': 'US', 'FIDELITY': 'US', 'ETRADE': 'US',
    'TRADESTATION': 'US', 'TASTYTRADE': 'US', 'ALPACA': 'US', 'WEBULL': 'US',
    'QUESTRADE': 'CA', 'WEALTHSIMPLE': 'CA',
    'AJ_BELL': 'UK', 'TRADING_212': 'UK',
    'INTERACTIVE_BROKERS': 'GLOBAL',
    'COINBASE': 'US', 'KRAKEN': 'GLOBAL', 'BINANCE': 'GLOBAL',
    'ZERODHA': 'IN', 'UPSTOX': 'IN',
    'COMMSEC': 'AU', 'STAKE_AUS': 'AU',
  };
  return COUNTRIES[brokerName.toUpperCase()] || 'UNKNOWN';
}

async function captureTradeIntent(signal: {
  userId: string;
  symbol: string;
  action: string;
  orderType: string;
  quantity: number;
  limitPrice?: number | null;
  brokerName: string;
  isCrypto: boolean;
}) {
  try {
    await pool.query(`
      INSERT INTO retail_flow_signals 
        (anonymous_id, symbol, action, order_type, quantity, limit_price, broker_country, broker_name, is_crypto, sector, market_session)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `, [
      hashUserId(signal.userId),
      signal.symbol.toUpperCase(),
      signal.action.toUpperCase(),
      signal.orderType,
      signal.quantity,
      signal.limitPrice || null,
      getBrokerCountry(signal.brokerName),
      signal.brokerName.toUpperCase(),
      signal.isCrypto,
      getSector(signal.symbol),
      getMarketSession()
    ]);
    console.log(`📊 Signal captured: ${signal.action} ${signal.symbol} (anon)`);
  } catch (err) {
    // Never block a trade because of signal capture failure
    console.warn('⚠️ Signal capture failed (non-blocking):', err);
  }
}

// ── Rate limit wrapper with exponential backoff ──
async function snaptradeCall<T>(fn: () => Promise<T>, retries = 4): Promise<T> {
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (err: any) {
      const status = err?.response?.status;
      if (status === 429) {
        const backoff = Math.pow(2, i) * 1000 + Math.random() * 500;
        console.warn(`⚠️ Rate limited by SnapTrade. Retry ${i + 1}/${retries} in ${Math.round(backoff)}ms`);
        await new Promise(r => setTimeout(r, backoff));
      } else {
        throw err;
      }
    }
  }
  throw new Error('Max retries exceeded after rate limiting');
}

/* ------------------------------ app ------------------------------ */

const app = express();
app.use(express.json());

// --- DEBUG: startup logging, error handlers and ping route ---

console.log("NODE_ENV=", process.env.NODE_ENV || "(unset)");
console.log("SNAPTRADE_CLIENT_ID set:", !!process.env.SNAPTRADE_CLIENT_ID);
console.log("SNAPTRADE_CONSUMER_KEY set:", !!process.env.SNAPTRADE_CONSUMER_KEY);
console.log("DATABASE_URL set:", !!process.env.DATABASE_URL);

process.on("uncaughtException", (err) => {
  console.error("UNCAUGHT EXCEPTION:", err && err.stack ? err.stack : err);
});
process.on("unhandledRejection", (reason) => {
  console.error("UNHANDLED REJECTION:", reason);
});

// Simple debug route that must exist on this exact deployment
app.get("/debug/ping", (_req, res) => {
  res.json({ ok: true, now: new Date().toISOString() });
});


/* ------------------------------- CORS ------------------------------ */

const defaultOrigins = [
  process.env.FRONTEND_ORIGIN || "https://www.theapexinvestor.com",
  "https://theapexinvestor.com",
  "https://www.theapexinvestor.net",
  "https://theapexinvestor.net",
  "http://localhost:3000", "http://127.0.0.1:3000",
  "http://localhost:5173", "http://127.0.0.1:5173",
  "http://localhost:5501", "http://127.0.0.1:5501",
];
const envOrigins = (process.env.CORS_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
const allowedOrigins = new Set<string>([...defaultOrigins, ...envOrigins]);

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    cb(null, allowedOrigins.has(origin));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Accept", "Authorization"],
  credentials: false,
}));
app.use((_, res, next) => { res.setHeader("Vary", "Origin"); next(); });
app.use((req, res, next) => { if (req.method === "OPTIONS") return res.sendStatus(204); next(); });
app.use("/users", usersRouter); 

app.get("/test-alerts", async (req, res) => {
  await runPriceAlertJob();
  res.json({ done: true });
});

app.get("/subscriptions/founding-status", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT COUNT(*) as count FROM snaptrade_users WHERE is_subscribed = TRUE"
    );
    const count = parseInt(result.rows[0].count);
    const isFoundingMember = count < 1000;
    res.json({ isFoundingMember, spotsLeft: Math.max(0, 1000 - count) });
  } catch (err) {
    res.status(500).json({ isFoundingMember: false, spotsLeft: 0 });
  }
});

/* --------------------------- diagnostics -------------------------- */

app.get("/", (_req, res) => res.type("text/plain").send("ok"));
app.get("/health", (_req, res) => res.type("text/plain").send("ok"));

app.get("/whoami", (_req, res) => {
  res.json({
    SNAPTRADE_CLIENT_ID: process.env.SNAPTRADE_CLIENT_ID ? "(set)" : "(missing)",
    hasConsumerKey: Boolean(process.env.SNAPTRADE_CONSUMER_KEY),
    SNAPTRADE_REDIRECT_URI: process.env.SNAPTRADE_REDIRECT_URI ? "(set)" : "(missing)",
    SNAPTRADE_WEB_REDIRECT_URI: process.env.SNAPTRADE_WEB_REDIRECT_URI ? "(set)" : "(missing)",
    now: new Date().toISOString(),
    lanIPs: lanIPs(),
    allowedOrigins: Array.from(allowedOrigins),
  });
});

app.get("/__routes", (_req, res) => {
  // @ts-ignore
  const stack: any[] = app._router?.stack || [];
  const routes: string[] = stack
    .filter((l) => l.route && l.route.path)
    .map((l) => {
      const methods = Object.keys(l.route.methods || {})
        .map((m) => m.toUpperCase())
        .join(",");
      return `${methods} ${l.route.path}`;
    });
  res.json(routes);
});

/* --------------------------- API heartbeat ------------------------ */

app.get("/status", async (_req, res) => {
  try {
    const snaptrade = mkClient();
    const status = await snaptrade.apiStatus.check();
    res.json(status.data);
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

/* -------------------------- debug helpers ------------------------- */

app.get('/market/price/:symbol', async (req, res) => {
  try {
    const symbol = (req.params.symbol || '').toUpperCase();
    const apiKey = process.env.TWELVE_DATA_API_KEY;
    if (!apiKey) return res.status(500).json({ error: 'Missing TWELVE_DATA_API_KEY in env' });

    const cacheKey = `price|${symbol}`;
    const cached = MARKET_CACHE.get(cacheKey);
    if (cached && Date.now() < cached.expires) {
      return res.json(cached.data);
    }

    const url = `https://api.twelvedata.com/price?symbol=${encodeURIComponent(symbol)}&apikey=${apiKey}`;
    const resp = await fetch(url);
    const json: any = await resp.json();

    if (json?.status === 'error') {
      return res.status(502).json({ error: json.message || '12data error' });
    }

    const price = parseFloat(json?.price);
    if (isNaN(price)) {
      return res.status(502).json({ error: 'Invalid price response', raw: json });
    }

    const payload = { symbol, price };
    // Cache for 60 seconds — it's a live price
    MARKET_CACHE.set(cacheKey, { expires: Date.now() + 60_000, data: payload });

    return res.json(payload);
  } catch (err: any) {
    console.error('Market price error', err);
    res.status(500).json({ error: 'server error', detail: String(err) });
  }
});

app.get('/market/history/batch', async (req, res) => {
  try {
    const symbols = String(req.query.symbols || '').split(',').filter(Boolean).map(s => s.toUpperCase());
    const from = String(req.query.from || '');
    const to = String(req.query.to || '');
    const apiKey = process.env.TWELVE_DATA_API_KEY;
    if (!apiKey) return res.status(500).json({ error: 'Missing TWELVE_DATA_API_KEY' });
    if (!symbols.length) return res.status(400).json({ error: 'No symbols provided' });

    // Calculate how many days we need
    const daysDiff = (from && to)
      ? Math.ceil((new Date(to).getTime() - new Date(from).getTime()) / (1000 * 60 * 60 * 24))
      : 90;
    const outputsize = Math.min(Math.max(daysDiff + 10, 90), 5000);

    const url = `https://api.twelvedata.com/time_series?symbol=${symbols.join(',')}&interval=1day&outputsize=${outputsize}&apikey=${apiKey}${from ? `&start_date=${from}` : ''}${to ? `&end_date=${to}` : ''}`;

    const resp = await fetch(url);
    const json: any = await resp.json();

    if (json?.status === 'error') {
      return res.status(502).json({ error: json.message || '12data error' });
    }

    const result: Record<string, { date: string; close: number }[]> = {};

    for (const sym of symbols) {
      const data = symbols.length === 1 ? json : json[sym];
      if (!Array.isArray(data?.values)) continue;
      result[sym] = data.values
        .map((it: any) => ({ date: String(it.datetime).split(' ')[0], close: Number(it.close) }))
        .filter((v: any) => !isNaN(v.close))
        .sort((a: any, b: any) => a.date < b.date ? -1 : 1);
    }

    res.json(result);
  } catch (err: any) {
    console.error('Batch history error', err);
    res.status(500).json({ error: 'server error', detail: String(err) });
  }
});


// Add this route after your debug helpers
app.get('/market/history/:symbol', async (req, res) => {
  try {
    const symbol = (req.params.symbol || '').toUpperCase();
    const from = String(req.query.from || '');
    const to = String(req.query.to || '');
    const apiKey = process.env.TWELVE_DATA_API_KEY;
    if (!apiKey) return res.status(500).json({ error: 'Missing TWELVE_DATA_API_KEY in env' });

    const cacheKey = `${symbol}|12data|${from}|${to}`;
    const cached = MARKET_CACHE.get(cacheKey);
    if (cached && Date.now() < cached.expires) {
      return res.json(cached.data);
    }

    // Build 12data URL
    const params = new URLSearchParams({
      symbol,
      interval: '1day',
      outputsize: '90',
      apikey: apiKey,
    });
    if (from) params.set('start_date', from);
    if (to) params.set('end_date', to);

    const url = `https://api.twelvedata.com/time_series?${params.toString()}`;
    const resp = await fetch(url);
    const json: any = await resp.json();

    // 12data returns { status: 'error', message: '...' } on failure
    if (json?.status === 'error') {
      return res.status(502).json({ error: json.message || '12data error' });
    }

    // 12data shape: { meta: {...}, values: [{ datetime, open, high, low, close, volume }] }
    const items: any[] = Array.isArray(json?.values) ? json.values : [];

    let values = items.map((it: any) => ({
      date: String(it.datetime).split(' ')[0],
      close: Number(it.close),
    })).filter(v => !Number.isNaN(v.close));

    // 12data returns newest first — sort ascending
    values.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));

    if (from) values = values.filter(v => v.date >= from);
    if (to) values = values.filter(v => v.date <= to);

    const payload = { provider: '12data', symbol, values };
    MARKET_CACHE.set(cacheKey, { expires: Date.now() + MARKET_CACHE_TTL_MS, data: payload });

    return res.json(payload);
  } catch (err: any) {
    console.error('Market history (12data) error', err);
    res.status(500).json({ error: 'server error', detail: String(err) });
  }
});

app.get("/debug/listUsers", async (_req, res) => {
  try {
    const snaptrade = mkClient();
    const r = await snaptrade.authentication.listSnapTradeUsers();
    res.json(r.data);
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

app.get("/debug/register", async (_req, res) => {
  try {
    const snaptrade = mkClient();
    const userId = `dev-${Date.now()}`;
    const reg = await snaptrade.authentication.registerSnapTradeUser({ userId });
    res.json({ userId, data: reg.data });
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

// Debug route: return raw authorizations + accounts for inspection
// Debug route: return raw authorizations + accounts for inspection
app.get("/debug/auths", async (req, res) => {
  try {
    const userId = String(req.query.userId || "");
    const secretFromCache = getSecret(userId);
    const secretFromDB = await fetchUserSecretFromDB(userId);
    const userSecret = (req.query.userSecret as string) || secretFromCache || secretFromDB || "";

    if (!userId || !userSecret) {
      return res.status(400).json({ error: "Missing userId or userSecret. Try ?userId=dev-... and ensure secret cached or pass &userSecret=<SECRET> (do not paste the secret publicly)." });
    }

    const snaptrade = mkClient();

    // explicit typing to satisfy TS/noImplicitAny
    let auths: any[] = [];
    try {
      const r: any = await snaptrade.connections.listBrokerageAuthorizations({ userId, userSecret });
      auths = r?.data || [];
    } catch (e) {
      console.warn("debug/auths: listBrokerageAuthorizations failed:", errPayload(e));
      auths = [];
    }

    let accounts: any[] = [];
    try {
      const a: any = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
      accounts = a?.data || [];
    } catch (e) {
      console.warn("debug/auths: listUserAccounts failed:", errPayload(e));
      accounts = [];
    }

    return res.json({
      userId,
      authsCount: Array.isArray(auths) ? auths.length : 0,
      accountsCount: Array.isArray(accounts) ? accounts.length : 0,
      auths,
      accounts
    });
  } catch (err) {
    res.status(500).json(errPayload(err));
  }
});

app.get("/debug/brokerageAuths", async (req, res) => {
  try {
    const userId = String(req.query.userId || "");
    const userSecret = String(req.query.userSecret || getSecret(userId) || await fetchUserSecretFromDB(userId) || "");
    if (!userId || !userSecret) {
      return res.status(400).json({ error: "Missing userId or userSecret" });
    }
    const snaptrade = mkClient();
    const r = await snaptrade.connections.listBrokerageAuthorizations({ userId, userSecret });
    res.json(r.data);
  } catch (err) {
    res.status(500).json(errPayload(err));
  }
});

/* ------------------------- SnapTrade connect ---------------------- */
/**
 * NAVIGATE here from the browser (not fetch/XHR):
 * /connect?fresh=1&web=1        # web callback
 * /connect?fresh=1              # mobile deep link callback
 * Optional (dev only): ?json=1 when ALLOW_JSON=1
 */

async function checkAppleSubscription(receiptData: string): Promise<boolean> {
  if (!receiptData) return false;
  const sharedSecret = process.env.APPLE_SHARED_SECRET || '';
  const body = JSON.stringify({ 'receipt-data': receiptData, 'password': sharedSecret });

  try {
    // Try production first
    let resp = await fetch('https://buy.itunes.apple.com/verifyReceipt', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body
    });
    let json: any = await resp.json();

    // 21007 = sandbox receipt sent to production — switch to sandbox (TestFlight)
    if (json.status === 21007) {
      resp = await fetch('https://sandbox.itunes.apple.com/verifyReceipt', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body
      });
      json = await resp.json();
    }

    if (json.status !== 0) return false;

    const purchases: any[] = json.latest_receipt_info || [];
    const now = Date.now();
    return purchases.some(p =>
      p.product_id === 'tygerai_pro_1month' &&
      Number(p.expires_date_ms) > now
    );
  } catch (e) {
    console.error('Apple receipt check failed:', e);
    return false; // fail closed
  }
}

async function handleConnect(req: express.Request, res: express.Response) {
  try {
    const snaptrade = mkClient();
    const fresh = String(req.query.fresh || "") === "1";

    // ✅ SUBSCRIPTION GATE — add this block
    const rcUserId = req.query.rcUserId as string;
    const existingUserId = req.query.userId as string;

      // Only gate if this is a NEW broker link (fresh=1) and user already has one linked
    if (fresh && existingUserId) {
      // Check how many brokers this user already has
      const existingSecret = await fetchUserSecretFromDB(existingUserId);
      if (existingSecret) {
        try {
          const snapClient = mkClient();
          const auths = await snapClient.connections.listBrokerageAuthorizations({
            userId: existingUserId,
            userSecret: existingSecret
          });
          const brokerCount = auths?.data?.length ?? 0;


        } catch (e) {
          console.warn("Could not check broker count for gate:", e);
          // fail open — let them through if we can't check
        }
      }
    }

    let userId = (req.query.userId as string) || process.env.SNAPTRADE_USER_ID || "";
    let userSecret = (req.query.userSecret as string) || process.env.SNAPTRADE_USER_SECRET || "";

    // ✅ CHANGE 1: Only register NEW users, existing users fall through
    if (!userId) {
  // Truly new user — register them
  userId = `dev-${Date.now()}`;
  const reg = await snaptrade.authentication.registerSnapTradeUser({ userId });
  userSecret = reg?.data?.userSecret ?? "";
} else if (!userSecret) {
  // Existing user reconnecting — fetch their secret from DB
  userSecret = await fetchUserSecretFromDB(userId);
  if (!userSecret) {
    return res.status(400).json({ error: "Could not find userSecret for existing userId" });
  }
}
// Always refresh the in-memory cache so subsequent calls have it
putSecret(userId, userSecret);

    const mobileBase = requireEnv("SNAPTRADE_REDIRECT_URI");
    const webBase = process.env.SNAPTRADE_WEB_REDIRECT_URI || mobileBase;

    const mobileURL = new URL(mobileBase);
    mobileURL.searchParams.set("userId", userId);

    const webURL = new URL(webBase);
    webURL.searchParams.set("userId", userId);

    const tryUrl = (v: unknown): string | "" => {
      if (typeof v !== "string" || !v.trim()) return "";
      try { return new URL(v).toString(); } catch { return ""; }
    };
    const custom = tryUrl(req.query.customRedirect) || tryUrl(req.query.redirect);

    const requested =
      custom ||
      (req.query.web === "1" ? webURL.toString() : mobileURL.toString());

    const allowedTypes = ["read", "trade", "trade-if-available"] as const;
    type ConnectionType = typeof allowedTypes[number];
    let connectionTypeRaw = typeof req.query.connectionType === "string"
      ? req.query.connectionType
      : "trade-if-available";
    const connectionType: ConnectionType = allowedTypes.includes(connectionTypeRaw as any)
      ? (connectionTypeRaw as ConnectionType)
      : "trade-if-available";

    const reconnect = typeof req.query.reconnect === "string" && req.query.reconnect.trim()
      ? String(req.query.reconnect).trim()
      : undefined;

    const loginResp = await snaptrade.authentication.loginSnapTradeUser({
      userId,
      userSecret,
      immediateRedirect: true,
      customRedirect: requested,
      connectionType,
      ...(reconnect ? { reconnect } : {}),
    });

    const data: any = loginResp?.data;
    const redirectURI =
      data?.redirectURI || data?.redirectUri ||
      data?.loginRedirectURI || data?.loginRedirectUri ||
      (typeof data === "string" ? data : undefined);

    if (!redirectURI) {
      return res.status(502).json({ error: "No redirect URL", raw: data });
    }

    // ✅ CHANGE 2: Redirect immediately — no sync loop here
    res.redirect(302, redirectURI);

  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
}
app.get("/connect", handleConnect);
app.get("/connect/redirect", handleConnect);

/* ✅ CHANGE 3: Sync loop moves here — fires AFTER user completes SnapTrade UI */
app.get("/snaptrade-callback", async (req, res) => {
  try {
    const userId = req.query.userId as string;
    const userSecret = getSecret(userId);

    if (!userId || !userSecret) {
      return res.status(400).json({ error: "Missing userId or userSecret" });
    }

    do {
      const summary = await fetchAndSaveUserSummary(userId, userSecret);
      if (!summary.syncing) {
        console.log("✅ Fully synced. Saving FINAL summary.");
        await saveSnaptradeUser(userId, userSecret, summary);
        break;
      }
      console.log("⏳ Waiting for full sync...");
      await new Promise(r => setTimeout(r, 2000));
    } while (true);

    console.log(`✅ User ${userId} fully synced and saved to DB.`);
    res.redirect("/portfolio"); // 👈 change to wherever you send users after linking
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

/* ----------------------------- linked ---------------------------- */

app.get("/realtime/linked", async (req, res) => {
  try {
    const userId = String(req.query.userId || "");
let userSecret = await fetchUserSecretFromDB(userId);
if (!userSecret) {
  return res.status(400).json({ linked: false, error: "Missing userId or userSecret" });
}   const snaptrade = mkClient();

    console.log(`[LINKED] called`, { userId, userSecret });

    let linked = false;
    try {
      const r = await snaptrade.connections.listBrokerageAuthorizations({ userId, userSecret });
      console.log(`[LINKED] Auths`, { userId, count: r.data?.length, auths: r.data });
      linked = (r.data?.length ?? 0) > 0;
    } catch (e) {
      console.error(`[LINKED] Error in listBrokerageAuthorizations`, { userId }, errPayload(e));
    }

    if (!linked) {
      try {
        const r = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
        console.log(`[LINKED] Accounts`, { userId, count: r.data?.length, accounts: r.data });
        linked = (r.data?.length ?? 0) > 0;
      } catch (e) {
        console.error(`[LINKED] Error in listUserAccounts`, { userId }, errPayload(e));
      }
    }

    res.json({ linked });
    console.log(`[LINKED] RESULT`, { userId, linked });
  } catch (err) {
    console.error(`[LINKED] Route error`, err);
    res.status(500).json(errPayload(err));
  }
});

/* ------------- Real-time: summary (balances + positions) ---------- */

app.get("/realtime/summary", async (req, res) => {
  try {
    const userId = (req.query.userId ?? "").toString();
   let userSecret = await fetchUserSecretFromDB(userId);
if (!userSecret) {
  return res.status(400).json({ error: "Missing userId or userSecret" });
}
    if (!userId || !userSecret || userId === "null" || userSecret === "null") {
      return res.status(400).json({ error: "Missing userId or userSecret" });
    }

    const snaptrade = mkClient();
    const accountsResp = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
    const accounts: any[] = accountsResp.data || [];

    let totalValue = 0, totalCash = 0, totalBP = 0;
    const outPositions: any[] = [];
    let syncing = false;
    
const activitiesByAccount: Record<string, any[]> = {};
const holdingsByAccount: Record<string, any> = {};

    for (const acct of accounts) {
      const accountId = acct.id || acct.accountId || acct.number || acct.guid || "";
      if (!accountId) continue;
      const h = await snaptrade.accountInformation.getUserHoldings({ userId, userSecret, accountId });

      // Save full raw holdings into dedicated table and keep for the summary
try {
  await saveAccountHoldingsToDB(userId, accountId, h.data);
} catch (e: any) {
  console.error("Failed to save account holdings:", errPayload(e));
}
holdingsByAccount[accountId] = h.data;
        let activities: any[] = [];
      try {
        const activityResp = await snaptrade.accountInformation.getAccountActivities({
          accountId,
          userId,
          userSecret
        });
        activities = Array.isArray(activityResp.data) ? activityResp.data : [];
      } catch (err: any) {
        console.error(`Failed to fetch activities for account ${accountId}:`, errPayload(err));
      }
      activitiesByAccount[accountId] = activities;   //
      const balObj: any = h.data?.balance || {};
      const balancesArr: any[] = h.data?.balances || [];

      const acctTotal = pickNumber(balObj?.total, balObj?.total?.amount);
      const acctCash =
        pickNumber(balObj?.cash, balObj?.cash?.amount) ||
        pickNumber(balancesArr.find((b: any) => b?.cash != null) || {});
      const acctBP =
        pickNumber(balObj?.buyingPower, balObj?.buying_power, balObj?.buying_power?.amount) ||
        pickNumber(balancesArr.find((b: any) => b?.buying_power != null) || {}) ||
        acctCash;

      totalValue += acctTotal ?? 0;
      totalCash += acctCash ?? 0;
      totalBP += acctBP ?? 0;

  // explicitPositions: prefer holdings/positions arrays, fall back to finder
const explicitPositions =
  (h.data && (h.data.positions || h.data.holdings?.positions || h.data.account?.positions || h.data.account?.holdings?.positions)) ||
  findPositionsArray(h.data) ||
  [];

for (const p of explicitPositions) {
  const sym = extractDisplaySymbol(p);

  const symbolId = pickStringStrict(
    p?.universal_symbol?.id,
    p?.symbol?.id,
    p?.symbol_id,
    p?.security_id,
    p?.instrument_id,
    p?.id,
    sym
  ) || sym;

  // Quantity: support units, filled_quantity, quantity, qty, total_quantity
  let qty = pickNumber(
    p?.units,
    p?.filled_quantity,
    p?.filledQuantity,
    p?.quantity,
    p?.qty,
    p?.total_quantity
  ) ?? 0;

  // Price: try several common fields
  let price = pickNumber(
    p?.price,
    p?.execution_price,
    p?.executionPrice,
    p?.average_purchase_price,
    p?.averagePrice,
    p?.last_trade_price
  );

  // Market value if present
  const mv = pickNumber(p?.market_value, p?.marketValue, p?.value);

  // If price missing but market value and qty present, derive price
  if ((price === null || price === undefined) && mv && qty) {
    price = mv / qty;
  }
  price = price ?? 0;

  const value = (mv != null && mv !== undefined) ? mv : (qty * price);

  outPositions.push({
    symbol: sym, 
    symbolId,
    accountId: String(accountId),
    needsMapping: UUID_RE.test(sym),
    name: extractDisplayName(p),
    quantity: qty,
    price,
    value,
    isCrypto: isCryptoPosition(p),
  });
}
      const ss: any = (h.data as any)?.sync_status || (h.data as any)?.syncStatus;
      const initDone = ss?.holdings?.initial_sync_completed ?? ss?.holdings?.initialSyncCompleted;
      if (initDone === false) syncing = true;
    }
    
    
 // 💡 Build summary object FIRST!
const positionsValue = outPositions.reduce((sum: number, p: any) => sum + (p.value || 0), 0);

const summary = {
  accounts: accounts.map((a: any, i: number) => {
    const accountId = a.id ?? a.accountId ?? a.number ?? a.guid ?? `acct-${i}`;
    const h = holdingsByAccount?.[accountId];
    const balObj = h?.balance || h?.account?.balance || {};  // ← CHANGE THIS LINE
    console.log(`DEBUG BALOBJ for ${accountId}:`, JSON.stringify(balObj, null, 2));
    const balancesArr = h?.balances || [];

    // DELETE everything from here to the second block ↓
    // const rawCash = pickNumber(balObj.cash, balObj.cash?.amount) ??   ← DELETE
    //   pickNumber(balancesArr.find((b: any) => b?.cash != null) || {}) ?? null;  ← DELETE
    // const totalAmount = pickNumber(balObj?.total, balObj?.total?.amount);  ← DELETE
    // const cash = (rawCash === 0 && totalAmount && totalAmount > 0)   ← DELETE
    //   ? totalAmount    ← DELETE
    //   : rawCash;       ← DELETE

    // KEEP ONLY THIS ONE:
  const rawCash =
  pickNumber(balObj.cash, balObj.cash?.amount) ??
  pickNumber(balancesArr.find((b: any) => b?.cash != null) || {}) ?? null;
const totalAmount = pickNumber(balObj?.total, balObj?.total?.amount);
const cash = (rawCash === 0 && totalAmount && totalAmount > 0) ? totalAmount : rawCash;
const buyingPower =
  pickNumber(balObj.buyingPower, balObj.buying_power, balObj.buying_power?.amount) ??
  cash;

// ← ADD THIS RIGHT HERE
console.log(`DEBUG CASH for ${accountId}: rawCash=${rawCash} totalAmount=${totalAmount} cash=${cash} buyingPower=${buyingPower}`);

    return {
      id: String(accountId),
      name: a.name || a.accountName || "Account",
      currency: a.currency || "USD",
      type: a.type || a.accountType || "BROKERAGE",
      number: a.number ?? null,
      meta: a.meta ?? a.raw_meta ?? a.metaData ?? null,
      cash,
      buyingPower
    }
  }),

 totals: {
    equity: totalValue > 0 ? totalValue : positionsValue,
    positionsValue: positionsValue,
    cash: totalCash,
    buyingPower: totalBP,
  },
  positions: outPositions,
  activitiesByAccount,
  holdingsByAccount,
  syncing,
};

// 💾 Now: Save summary to DB
await saveSnaptradeUser(userId, userSecret, summary);
await syncHoldingsToUserHoldings(userId, outPositions);

// ✅ Finally, respond!
res.json(summary);
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

/**
 * GET /realtime/trading
 * Returns: { accounts: [ { accountId, name, tradingEnabled, reason?, reauthUrl? } ] }
 *
 * Expects userId and optionally userSecret (will fall back to cached secret / DB secret)
 */
// ---------- Resilient /realtime/trading handler (with DB fallback) ----------
app.get("/realtime/trading", async (req, res) => {
  try {
    const userId = String(req.query.userId || "");
    const secretFromCache = getSecret(userId);
    const secretFromDB = await fetchUserSecretFromDB(userId);
    const userSecret = (req.query.userSecret as string) || secretFromCache || secretFromDB || "";

    if (!userId || !userSecret || userId === "null" || userSecret === "null") {
      return res.status(400).json({ error: "Missing userId or userSecret" });
    }

    const snaptrade = mkClient();

    // Try to fetch accounts live from SnapTrade
    let accounts: any[] = [];
    try {
      const accountsResp = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
      accounts = accountsResp?.data || [];
    } catch (err) {
      console.warn("Could not listUserAccounts in /realtime/trading:", errPayload(err));
      // FALLBACK: attempt to read last-saved summary from DB and return accounts from it
      try {
        const q = 'SELECT data FROM snaptrade_users WHERE user_id = $1 LIMIT 1';
        const r = await pool.query(q, [userId]);
        const row = r.rows[0];
        if (row && row.data) {
          const stored = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
          if (Array.isArray(stored.accounts)) {
            accounts = stored.accounts.map((a: any) => ({
              id: a.id ?? a.accountId ?? a.number ?? a.guid,
              name: a.name ?? a.accountName ?? a.currency ?? `Account ${a.id}`
            }));
            console.log(`Using cached ${accounts.length} accounts from DB for ${userId}`);
          }
        }
      } catch (dbErr) {
        console.warn("Failed to load cached accounts from DB as fallback:", dbErr);
        return res.status(500).json({ error: "Could not fetch accounts" });
      }
    }

    // Also attempt to fetch authorizations (best-effort)
    try {
      await snaptrade.connections.listBrokerageAuthorizations({ userId, userSecret });
    } catch (e) {
      // ignore — ensureTradingEnabled handles best-effort checks
    }

    // Build per-account capability info (run checks in parallel)
    const results = await Promise.all(accounts.map(async (acct) => {
      const accountId = acct?.id || acct?.accountId || acct?.number || acct?.guid || String(acct?.id || "");
      const displayName = acct?.name || acct?.accountName || acct?.currency || `Account ${accountId}`;

      try {
        const check = await ensureTradingEnabled(snaptrade, userId, userSecret, accountId);
        return {
          accountId,
          name: displayName,
          tradingEnabled: Boolean(check.ok),
          reason: check.ok ? undefined : (check.reason || undefined),
          reauthUrl: check.reauthUrl || undefined
        };
      } catch (err) {
        console.warn(`ensureTradingEnabled failed for ${accountId}:`, errPayload(err));
        return {
          accountId,
          name: displayName,
          tradingEnabled: false,
          reason: "error_checking",
          reauthUrl: undefined
        };
      }
    }));

    res.json({ accounts: results });
  } catch (err) {
    res.status(500).json(errPayload(err));
  }
});

/* -------------------------- debug: holdings ------------------------ */

app.get("/debug/holdings", async (req, res) => {
  try {
    const userId = String(req.query.userId || "");
    const userSecret = String(req.query.userSecret || getSecret(userId) || "");
    if (!userId || !userSecret) return res.status(400).json({ error: "Missing userId or userSecret" });

    const snaptrade = mkClient();
    const aResp = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
    const accounts: any[] = aResp.data || [];
    const out: Record<string, any> = {};
    for (const acct of accounts) {
      const accountId = acct.id || acct.accountId || acct.number || "";
      if (!accountId) continue;
      const h = await snaptrade.accountInformation.getUserHoldings({ userId, userSecret, accountId });
      const pos = findPositionsArray(h.data);
      out[accountId] = { keys: Object.keys(h.data || {}), sample: pos.slice(0, 3), raw: h.data };
    }
    res.json(out);
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

/* ----------------------- Trade helpers ----------------------- */

/**
 * Try to determine whether the specified accountId has trading enabled.
 * - First, check listBrokerageAuthorizations for an auth that references the account and look for common trading flags.
 * - If not found, fall back to listUserAccounts and inspect account fields.
 * Returns: { ok: boolean, reason?: string, reauthUrl?: string }
 */
// Replace existing ensureTradingEnabled(...) with this implementation
// Replace the existing ensureTradingEnabled function with this full implementation
async function ensureTradingEnabled(
  snaptrade: any,
  userId: string,
  userSecret: string,
  accountId?: string
) {
  try {
    // 1) Try to list authorizations
    let authsResp: any = null;
    try {
      authsResp = await snaptrade.connections.listBrokerageAuthorizations({ userId, userSecret });
    } catch (e: any) {
      console.warn("Could not listBrokerageAuthorizations:", (e && e.message) || e);
      authsResp = null;
    }
    const auths: any[] = authsResp?.data || [];

    // 2) Try to find a matched auth that references this account
    let matchedAuth: any = null;
    if (Array.isArray(auths) && auths.length && accountId) {
      for (const a of auths) {
        const ids = a?.account_ids || a?.accounts || (Array.isArray(a?.accountIds) ? a.accountIds : undefined);
        if (typeof a?.account_id === "string" && a.account_id === accountId) { matchedAuth = a; break; }
        if (Array.isArray(ids) && ids.includes(accountId)) { matchedAuth = a; break; }
        if (Array.isArray(a?.accounts)) {
          for (const acct of a.accounts) {
            if ((acct?.id || acct?.accountId || acct?.account_id || acct?.number) === accountId) { matchedAuth = a; break; }
          }
          if (matchedAuth) break;
        }
        if ((a?.account || a?.account_info) && ((a.account?.id || a.account?.accountId || a.account?.number) === accountId)) {
          matchedAuth = a; break;
        }
      }
    }

    // Fallback: if not found above, find by brokerage_authorization link
    if (!matchedAuth && accountId) {
      try {
        const accResp: any = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
        const accs: any[] = accResp?.data || [];
        const foundAcc = accs.find((x: any) => {
          const aid = x?.id || x?.accountId || x?.number || x?.guid;
          return aid === accountId;
        });
        if (foundAcc && foundAcc.brokerage_authorization) {
          const authId = foundAcc.brokerage_authorization;
          matchedAuth = (Array.isArray(auths) ? auths.find((a: any) =>
            a?.id === authId || a?.connection_id === authId || a?.connectionId === authId
          ) : null) || null;
          if (matchedAuth) {
            console.log("ensureTradingEnabled: matchedAuth found via account.brokerage_authorization ->", { authId });
          }
        }
      } catch (e: any) {
        console.warn("ensureTradingEnabled: fallback listUserAccounts failed:", (e && e.message) || e);
      }
    }

    // If we found an auth, check type
    if (matchedAuth && matchedAuth.type && matchedAuth.type.toLowerCase() === "trade") {
      return { ok: true };
    }
    // If we have an auth id, offer reconnect link if not marked as trading
    const reconnectId = matchedAuth?.id || matchedAuth?.connection_id || matchedAuth?.connectionId;
    if (reconnectId) {
      try {
        const loginResp = await snaptrade.authentication.loginSnapTradeUser({
          userId,
          userSecret,
          immediateRedirect: false,
          connectionType: "trade",
          reconnect: reconnectId,
        });
        const candidate = loginResp?.data?.redirectURI || loginResp?.data?.redirectUri ||
                          loginResp?.data?.loginRedirectURI || loginResp?.data?.loginRedirectUri ||
                          (typeof loginResp?.data === "string" ? loginResp.data : undefined);
if (candidate) {
  const reauthUrl = `https://snaptrade-api-da44.onrender.com/connect?connectionType=trade&userId=${userId}`;
  return { ok: false, reason: "trade_not_enabled", reauthUrl };
}      } catch (e: any) {
        console.warn("Could not build reauth link for matched auth:", (e && e.message) || e);
      }
      return { ok: false, reason: "trade_not_enabled" };
    }

    // If no matchedAuth, inspect account objects for trading capability
    try {
      const aResp = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
      const accounts = aResp?.data || [];
      for (const acct of accounts) {
        const aid = acct?.id || acct?.accountId || acct?.number || acct?.guid;
        if ((!accountId || aid === accountId) && acct.type && acct.type.toLowerCase() === "trade") {
          return { ok: true };
        }
      }
    } catch (e: any) {
      console.warn("Could not listUserAccounts while checking trading support:", (e && e.message) || e);
    }

    // Final fallback: try building a generic login link for trading
    try {
      const loginResp = await snaptrade.authentication.loginSnapTradeUser({
        userId,
        userSecret,
        immediateRedirect: false,
        connectionType: "trade",
      });
      const candidate = loginResp?.data?.redirectURI ||
        loginResp?.data?.redirectUri ||
        loginResp?.data?.loginRedirectURI ||
        loginResp?.data?.loginRedirectUri ||
        (typeof loginResp?.data === "string" ? loginResp.data : undefined);
if (candidate) {
  const reauthUrl = `https://snaptrade-api-da44.onrender.com/connect?connectionType=trade&userId=${userId}`;
  return { ok: false, reason: "trade_not_enabled", reauthUrl };
}   } catch (e) {
      console.warn("ensureTradingEnabled: could not build generic upgrade link", e);
    }

    return { ok: false, reason: "no_trading_authorization_found" };
  } catch (err: any) {
    console.error("ensureTradingEnabled error:", err);
    return { ok: false, reason: "error_checking" };
  }
}
/* ----------------------- Trade: Place Order (New) ----------------------- */
/**
 * Sample request payload:
 * {
 * "userId": "abc-123",
 * "userSecret": "secret-xyz",
 * "accountId": "acc-456",
 * "symbol": "AAPL",             // or resolved symbolId
 * "action": "Buy",              // or "Sell"
 * "orderType": "Limit",         // or "Market"
 * "quantity": 1,
 * "limitPrice": 180.50          // only for Limit orders
 * }
 */

function isCryptoBroker(brokerName = '') {
  const normalized = String(brokerName).toUpperCase();
  return ['COINBASE', 'KRAKEN', 'BINANCE', 'GEMINI', 'BITSTAMP'].includes(normalized);
}

// This helper gets the broker for an account
async function getAccountBroker(
  snaptrade: Snaptrade,
  userId: string,
  userSecret: string,
  accountId: string
): Promise<string> {
  const accs = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
  const acct = (accs.data || []).find((acc: any) =>
    acc.id === accountId ||
    acc.accountId === accountId ||
    acc.number === accountId ||
    acc.guid === accountId
  );
  return acct?.broker || acct?.broker_slug || acct?.provider || '';
}

import { v4 as uuidv4 } from "uuid"; // npm install uuid

app.post("/trade/placeOrder", async (req, res) => {
    console.log("PlaceOrder route HIT!");
console.log("PlaceOrder received:", req.body); // <-- Add this!app.post("/trade/placeOrder", async (req, res) => {
  console.log("PlaceOrder received:", req.body);

  const tradeId = uuidv4();

try {
    const {
      userId,
      userSecret,
      accountId,
      symbol,
      action,
      orderType,
      quantity,
      limitPrice,  
      stopPrice,
      timeInForce
    } = req.body;

    if (!userId || !userSecret || !accountId || !symbol || !action || !orderType || !quantity) {
      return res.status(400).json({ error: "Missing required fields (userId,userSecret,accountId,symbol,action,orderType,quantity)" });
    }

    const snaptrade = mkClient();

   const check = await ensureTradingEnabled(snaptrade, userId, userSecret, accountId);
if (!check.ok) {
  const payload: any = {
    error: "Trading not enabled for this account",
    reason: check.reason || "unknown"
  };
  if (check.reauthUrl) payload.reauthUrl = check.reauthUrl;
  return res.status(403).json(payload);
}

    // --- CRYPTO (NO CHANGE) ---
    const broker = await getAccountBroker(snaptrade, userId, userSecret, accountId);

    if (isCryptoBroker(broker)) {

      // User must submit symbol as "BASE-QUOTE", e.g. "BTC-USD"
      if (!symbol.includes('-')) {
        return res.status(400).json({ error: "Crypto trades require symbol in BASE-QUOTE format like 'ETH-USD'" });
      }
      // Payload for SnapTrade's crypto order endpoint
      const cryptoPayload = {
        account_id: accountId,
        instrument: {
          symbol: symbol,
          type: "CRYPTOCURRENCY_PAIR"
        },
        side: action.toUpperCase(),      // "BUY" or "SELL"
        type: orderType.toUpperCase(),   // "MARKET" or "LIMIT"
        amount: String(quantity),        // how much BASE asset
        time_in_force: "GTC",            // or "DAY"
        post_only: false
      };
      if (orderType.toUpperCase() === "LIMIT" && limitPrice) {
      (cryptoPayload as any).price = limitPrice;
      }

      // Place crypto order (endpoint may differ based on SDK version)
const order = await (snaptrade as any).cryptoTrading.placeOrder(cryptoPayload);
      return res.json(order.data);
    }


    // Place order
  const params: any = {
      userId,
      userSecret,
      account_id: accountId, // <-- snake_case required by SnapTrade
      action,
      symbol,
      order_type: orderType, // <-- snake_case required by SnapTrade
      time_in_force: "Day", // or as desired
      units: Number(quantity) // <-- snake_case required by SnapTrade
    };

    // only add price if limit
    if (orderType && orderType.toUpperCase() === "LIMIT" && limitPrice != null) {
      params.price = Number(limitPrice);
    }

    // LOG THE FINAL PAYLOAD TO VERIFY
    console.log("FINAL SnapTrade order payload:", JSON.stringify(params));

    // SUBMIT THIS OBJECT ONLY!
// 📊 Capture intent BEFORE submitting to SnapTrade
await captureTradeIntent({
  userId,
  symbol,
  action,
  orderType,
  quantity: Number(quantity),
  limitPrice: limitPrice || null,
  brokerName: broker || 'UNKNOWN',
  isCrypto: isCryptoBroker(broker)
});

const order = await snaptrade.trading.placeForceOrder({
    userId,
    userSecret,
    account_id: accountId,
    action,
    symbol,
    order_type: orderType,
    time_in_force: timeInForce || "Day",  // ← use from request
    units: Number(quantity),
    ...(( orderType === "Limit" || orderType === "StopLimit") && limitPrice != null 
        ? { price: Number(limitPrice) } : {}),
    ...((orderType === "Stop" || orderType === "StopLimit") && stopPrice != null 
        ? { stop: Number(stopPrice) } : {})  // ← add stop price
});
res.json(order.data);

 } catch (err: any) {
    // 🔎 Add more raw error logging!
    console.error("ORDER RAW ERR:", err);
    if (err?.response) {
      console.error("ORDER RESPONSE DATA:", err.response.data);
      console.error("ORDER RESPONSE STATUS:", err.response.status);
      console.error("ORDER RESPONSE HEADERS:", err.response.headers);
    } else {
      console.error("No err.response present! err:", err);
    }

    let detail;
    if (err?.response?.data) {
        try {
            detail = typeof err.response.data === "object"
                ? JSON.stringify(err.response.data, null, 2)
                : err.response.data;
        } catch {
            detail = err.response.data;
        }
    } else {
        detail = err?.data || err?.message || err;
    }
    console.error("ORDER ERROR BODY:", detail);

    res.status(500).json({
      error: "Order failed",
      snaptradeDetail: err?.response?.data || err?.data || err?.message || String(err)
    });
}
});


/* ----------------------- Trade: Symbol Lookup (New) ----------------------- */
app.get("/market/price/:symbol", async (req, res) => {
  const symbol = req.params.symbol.toUpperCase();
  try {
    const response = await fetch(
      `https://api.twelvedata.com/quote?symbol=${symbol}&apikey=${process.env.TWELVE_DATA_API_KEY}`
    );
    const data: any = await response.json();

    if (data?.close) {
      res.json({
        symbol,
        price: parseFloat(data.close),
        changePercent: data.percent_change ? parseFloat(data.percent_change) : 0,
        change: data.change ? parseFloat(data.change) : 0,
        previousClose: data.previous_close ? parseFloat(data.previous_close) : 0,
      });
    } else {
      res.status(404).json({ error: "Symbol not found", detail: data });
    }
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

app.get("/trade/symbol/:ticker", async (req, res) => {
  const ticker = req.params.ticker.toUpperCase();
  try {
    const response = await fetch(
      `https://api.twelvedata.com/symbol_search?symbol=${ticker}&apikey=${process.env.TWELVE_DATA_API_KEY}`
    );
    const data = await response.json();
    res.json(data.data || []);
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});
/* ---------------------- Save Snaptrade User ---------------------- */
// Replace the existing POST /snaptrade/saveUser handler with this block
app.post("/snaptrade/saveUser", async (req, res) => {
  try {
    const { userId, userSecret } = req.body;
    if (!userId || !userSecret) {
      return res.status(400).json({ error: "Missing userId or userSecret" });
    }

    const snaptrade = mkClient();
    console.log("Fetching accounts for", { userId /* do not log secret in prod */ });

    const accountsResp = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
    console.log("Accounts response:", JSON.stringify(accountsResp.data || [], null, 2));
    const accounts = accountsResp.data || [];

    let totalValue = 0, totalCash = 0, totalBP = 0;
    const outPositions: any[] = [];
    let syncing = false;

    // Collect activities and holdings per account
    const activitiesByAccount: Record<string, any[]> = {};
    const holdingsByAccount: Record<string, any> = {};

    for (const acct of accounts) {
      const accountId = acct.id || acct.accountId || acct.number || acct.guid || "";
      if (!accountId) continue;

      // Get holdings for each account
      const h = await snaptrade.accountInformation.getUserHoldings({ userId, userSecret, accountId });

      // Save full raw holdings into dedicated table and keep for summary
      try {
        await saveAccountHoldingsToDB(userId, accountId, h.data);
      } catch (e: any) {
        console.error("Failed to save account holdings:", errPayload(e));
      }
      holdingsByAccount[accountId] = h.data;

      // Fetch activities for this account (transactions / events)
      let activities: any[] = [];
      try {
        const activityResp = await snaptrade.accountInformation.getAccountActivities({ accountId, userId, userSecret });
        activities = Array.isArray(activityResp.data) ? activityResp.data : [];
        if (activities.length) {
          console.log(`Fetched ${activities.length} activities for account ${accountId}`);
        }
      } catch (err: any) {
        console.error(`Failed to fetch activities for account ${accountId}:`, errPayload(err));
      }

      // Keep in summary and persist to transactions table
      activitiesByAccount[accountId] = activities;
      await saveActivitiesToDB(userId, accountId, activities);

      // Extract balances
      const balObj = h.data?.balance || {};
      const balancesArr = h.data?.balances || [];
      const acctTotal = pickNumber(balObj?.total, balObj?.total?.amount);
      const acctCash = pickNumber(balObj?.cash, balObj?.cash?.amount) || pickNumber(balancesArr.find((b: any) => b?.cash != null) || {});
      const acctBP = pickNumber(balObj?.buyingPower, balObj?.buying_power, balObj?.buying_power?.amount) || pickNumber(balancesArr.find(b => b?.buying_power != null) || {}) || acctCash;

      totalValue += acctTotal ?? 0;
      totalCash += acctCash ?? 0;
      totalBP += acctBP ?? 0;

      // Extract positions (existing logic)
      const explicitPositions =
        (h.data && (h.data.positions || h.data.holdings?.positions || h.data.account?.positions || h.data.account?.holdings?.positions)) ||
        findPositionsArray(h.data) || [];

      for (const p of explicitPositions) {
        const sym = extractDisplaySymbol(p);

        const symbolId = pickStringStrict(
          p?.universal_symbol?.id,
          p?.symbol?.id,
          p?.symbol_id,
          p?.security_id,
          p?.instrument_id,
          p?.id,
          sym
        ) || sym;

        let qty = pickNumber(
          p?.units,
          p?.filled_quantity,
          p?.filledQuantity,
          p?.quantity,
          p?.qty,
          p?.total_quantity
        ) ?? 0;

        let price = pickNumber(
          p?.price,
          p?.execution_price,
          p?.executionPrice,
          p?.average_purchase_price,
          p?.averagePrice,
          p?.last_trade_price
        );

        const mv = pickNumber(p?.market_value, p?.marketValue, p?.value);

        if ((price === null || price === undefined) && mv && qty) {
          price = mv / qty;
        }
        price = price ?? 0;

        const value = (mv != null && mv !== undefined) ? mv : (qty * price);

        outPositions.push({
          symbol: sym,
          symbolId,
          accountId: String(accountId),
          needsMapping: UUID_RE.test(sym),
          name: extractDisplayName(p),
          quantity: qty,
          price,
          value,
          isCrypto: isCryptoPosition(p),
        });
      }

      const ss = h.data?.sync_status || h.data?.syncStatus;
      const initDone = ss?.holdings?.initial_sync_completed ?? ss?.holdings?.initialSyncCompleted;
      if (initDone === false) syncing = true;
    }

    // Build and save summary INCLUDING activitiesByAccount and holdingsByAccount
   // Replace the accounts mapping inside the POST /snaptrade/saveUser handler with this:
const positionsValue = outPositions.reduce((sum: number, p: any) => sum + (p.value || 0), 0);

const summary = {
  accounts: accounts.map((a: any, i: number) => {
    const accountId = a.id ?? a.accountId ?? a.number ?? a.guid ?? `acct-${i}`;
    const h = holdingsByAccount?.[accountId];
    const balObj = h?.balance || {};
    const balancesArr = h?.balances || [];

    const cash =
      pickNumber(balObj.cash, balObj.cash?.amount) ??
      pickNumber(balancesArr.find((b: any) => b?.cash != null) || {}) ??
      null;

    const buyingPower =
      pickNumber(balObj.buyingPower, balObj.buying_power, balObj.buying_power?.amount) ??
      pickNumber(balancesArr.find((b: any) => b?.buying_power != null) || {}) ??
      cash;

    return {
      id: String(accountId),
      name: a.name || a.accountName || "Account",
      currency: a.currency || "USD",
      type: a.type || a.accountType || "BROKERAGE",
      number: a.number ?? null,
      meta: a.meta ?? a.raw_meta ?? a.metaData ?? null,
      cash,
      buyingPower
    }
  }),
totals: {
    equity: totalValue > 0 ? totalValue : positionsValue,
    positionsValue: positionsValue,
    cash: totalCash,
    buyingPower: totalBP,
  },
  positions: outPositions,
  activitiesByAccount,
  holdingsByAccount,
  syncing,
};

    await saveSnaptradeUser(userId, userSecret, summary);
    res.json({ success: true, saved: summary });
  } catch (err: any) {
    console.error("❌ Failed to save user:", err);
    res.status(500).json({ error: "Failed to save user" });
  }
});

// ── Force refresh a single account ──
app.post("/snaptrade/refresh-account", async (req, res) => {
  try {
    const { userId, accountId } = req.body;
    const userSecret = getSecret(userId) || await fetchUserSecretFromDB(userId);
    if (!userId || !userSecret) return res.status(400).json({ error: "Missing credentials" });

    const snaptrade = mkClient();
    const h = await snaptrade.accountInformation.getUserHoldings({ 
      userId, userSecret, accountId 
    });
    await saveAccountHoldingsToDB(userId, accountId, h.data);
    console.log(`✅ Force refreshed account ${accountId} for ${userId}`);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

/* ---------------- Debug logging for SnapTrade webhook ---------------- */
app.use("/webhook/snaptrade", (req, res, next) => {
  console.log("📦 Incoming webhook headers:", req.headers);
  console.log("📦 Incoming webhook body:", req.body);
  next();
});

app.post(/^\/webhook\/snaptrade\/?$/, async (req, res) => {
  // Respond immediately — never make SnapTrade wait
  res.status(200).send("ok");

  try {
    const event = req.body;
    console.log(`📦 SnapTrade webhook: ${event.eventType} for user ${event.userId}`);

    const userId = event.userId;
    if (!userId) return;

    const userSecret = getSecret(userId) || await fetchUserSecretFromDB(userId);
    if (!userSecret) {
      console.warn(`⚠️ No secret found for webhook user ${userId}`);
      return;
    }

    switch (event.eventType) {

      case 'ACCOUNT_HOLDINGS_UPDATED':
      case 'CONNECTION_ADDED':
      case 'CONNECTION_FIXED':
      case 'NEW_ACCOUNT_AVAILABLE':
      case 'ACCOUNT_TRANSACTIONS_UPDATED':
      case 'ACCOUNT_TRANSACTIONS_INITIAL_UPDATE': {
        console.log(`🔄 Refreshing portfolio for ${userId} due to ${event.eventType}`);
        let tries = 0;
        let summary: any;
        do {
          summary = await fetchAndSaveUserSummary(userId, userSecret);
          tries++;
          if (!summary.syncing) break;
          if (tries > 15) {
            console.warn(`⚠️ Sync timeout for ${userId}, saving partial data`);
            break;
          }
          await new Promise(r => setTimeout(r, 3000));
        } while (true);
        await saveSnaptradeUser(userId, userSecret, summary);
        await syncHoldingsToUserHoldings(userId, summary.positions); 
        console.log(`✅ Portfolio refreshed for ${userId} — ${summary.positions.length} positions`);

        // Send push notification if holdings changed
        await sendPortfolioUpdateNotification(userId, summary);
        break;
      }

      case 'CONNECTION_BROKEN': {
        console.warn(`🔴 Connection broken for ${userId}`);
        await sendConnectionBrokenNotification(userId);
        break;
      }

      case 'CONNECTION_DELETED':
      case 'ACCOUNT_REMOVED': {
        console.log(`🗑️ Connection/account removed for ${userId}`);
        // Refresh to get updated account list
        const summary = await fetchAndSaveUserSummary(userId, userSecret);
        await saveSnaptradeUser(userId, userSecret, summary);
        break;
      }

      default:
        console.log(`ℹ️ Unhandled webhook event: ${event.eventType}`);
    }

  } catch (err: any) {
    console.error("❌ Webhook processing error:", err);
  }
});

// Push notification helpers (extend later)
async function sendPortfolioUpdateNotification(userId: string, summary: any) {
  try {
    // Look up device tokens from device_tokens table
    const result = await pool.query(
      'SELECT device_token FROM device_tokens WHERE user_id = $1',
      [userId]
    );
    const tokens = result.rows.map(r => r.device_token).filter(Boolean);
    if (tokens.length === 0) return;

    console.log(`📱 Would send portfolio push to ${userId} (${tokens.length} device(s)) — not yet implemented`);
    // TODO: wire to apnProvider when portfolio-update pushes are ready
  } catch (e) {
    console.warn('Could not send portfolio push:', e);
  }
}

async function sendConnectionBrokenNotification(userId: string) {
  try {
    const result = await pool.query(
      'SELECT device_token FROM device_tokens WHERE user_id = $1',
      [userId]
    );
    const tokens = result.rows.map(r => r.device_token).filter(Boolean);
    if (tokens.length === 0) return;
    console.log(`📱 Would send connection-broken push to ${userId} (${tokens.length} device(s))`);
  } catch (e) {
    console.warn('Could not send connection broken push:', e);
  }
}

app.get('/user/secret', async (req, res) => {
  const userId = String(req.query.userId || '');
  if (!userId) return res.status(400).json({ error: 'Missing userId' });

  // Try fetching from short-term cache first
  let userSecret = getSecret(userId);
  // If not in cache, get from DB
  if (!userSecret) {
    userSecret = await fetchUserSecretFromDB(userId);
  }

  if (!userSecret) {
    return res.status(404).json({ error: 'No userSecret found for userId' });
  }

  // Don't ever log the secret in prod!
  return res.json({ userSecret });
});

// ── Manually refresh a SnapTrade connection (forces immediate sync) ──
// iOS app calls this when user pulls to refresh.
// SnapTrade will then fire ACCOUNT_HOLDINGS_UPDATED to our webhook
// once fresh data is pulled from the broker.
app.post('/refresh-account', async (req, res) => {
  try {
    const { userId } = req.body;
    const userSecret = getSecret(userId) || await fetchUserSecretFromDB(userId);

    if (!userId || !userSecret) {
      return res.status(400).json({ error: 'Missing userId or userSecret' });
    }

    const snaptrade = mkClient();

    const authsResp = await snaptradeCall(() =>
      snaptrade.connections.listBrokerageAuthorizations({ userId, userSecret })
    );
    const auths: any[] = authsResp?.data || [];

    if (auths.length === 0) {
      return res.status(404).json({ error: 'No brokerage connections found' });
    }

    const results = await Promise.allSettled(
      auths
        .filter(a => !a.disabled)
        .map(a =>
          snaptradeCall(() =>
            snaptrade.connections.refreshBrokerageAuthorization({
              authorizationId: a.id,
              userId,
              userSecret,
            })
          )
        )
    );

    const refreshed = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;

    console.log(`🔄 Manual refresh for ${userId}: ${refreshed} ok, ${failed} failed`);
    res.json({ success: true, refreshed, failed });

  } catch (err: any) {
    console.error('❌ Refresh error:', err);
    res.status(500).json(errPayload(err));
  }
});

// ── Order history (last 24hrs from SnapTrade + full history from DB) ──
app.get('/orders/recent', async (req, res) => {
  try {
    const userId = String(req.query.userId || '');
    const accountId = String(req.query.accountId || '');
    const userSecret = getSecret(userId) || await fetchUserSecretFromDB(userId);

    if (!userId || !userSecret) {
      return res.status(400).json({ error: 'Missing userId or userSecret' });
    }
    if (!accountId) {
      return res.status(400).json({ error: 'Missing accountId' });
    }

    const snaptrade = mkClient();

    // Get recent orders from SnapTrade (last 24hrs, realtime)
    let recentOrders: any[] = [];
    try {
      const resp = await snaptradeCall(() =>
        snaptrade.accountInformation.getUserAccountRecentOrders({
          accountId,
          userId,
          userSecret,
          onlyExecuted: false // show pending too
        })
      );
      recentOrders = resp?.data?.orders || [];
    } catch (err: any) {
      console.warn('Could not fetch recent orders from SnapTrade:', errPayload(err));
    }

    // Get full history from your DB
    const dbResult = await pool.query(
      `SELECT 
        brokerage_order_id, symbol, action, quantity, price, 
        execution_time, raw, created_at
       FROM snaptrade_transactions 
       WHERE user_id = $1 AND account_id = $2
       ORDER BY execution_time DESC NULLS LAST
       LIMIT 100`,
      [userId, accountId]
    );

    // Merge: SnapTrade recent orders take priority (most fresh)
    const normalizeOrder = (o: any) => ({
      orderId: o.brokerage_order_id || o.brokerageOrderId,
      symbol: o.universal_symbol?.symbol || o.symbol?.symbol || o.symbol || 'UNKNOWN',
      action: o.action,
      status: o.status || 'EXECUTED',
      quantity: o.total_quantity || o.filled_quantity || o.quantity,
      filledQuantity: o.filled_quantity,
      price: o.execution_price || o.limit_price,
      orderType: o.order_type,
      timePlaced: o.time_placed || o.time_executed,
      timeExecuted: o.time_executed,
      source: 'live'
    });

    const normalizeDBOrder = (row: any) => ({
      orderId: row.brokerage_order_id,
      symbol: row.symbol,
      action: row.action,
      status: 'EXECUTED',
      quantity: row.quantity,
      filledQuantity: row.quantity,
      price: row.price,
      orderType: null,
      timePlaced: row.execution_time || row.created_at,
      timeExecuted: row.execution_time,
      source: 'history'
    });

    // Deduplicate by orderId
    const liveIds = new Set(recentOrders.map(o => o.brokerage_order_id));
    const dbOrders = dbResult.rows
      .filter(row => !liveIds.has(row.brokerage_order_id))
      .map(normalizeDBOrder);

    const allOrders = [
      ...recentOrders.map(normalizeOrder),
      ...dbOrders
    ].sort((a, b) => {
      const ta = new Date(a.timePlaced || 0).getTime();
      const tb = new Date(b.timePlaced || 0).getTime();
      return tb - ta;
    });

    res.json({ orders: allOrders, total: allOrders.length });

  } catch (err: any) {
    console.error('❌ Order history error:', err);
    res.status(500).json(errPayload(err));
  }
});


// ── Cancel order ──
app.post('/orders/cancel', async (req, res) => {
  try {
    const { userId, accountId, brokerageOrderId } = req.body;
    const userSecret = getSecret(userId) || await fetchUserSecretFromDB(userId);

    if (!userId || !userSecret || !accountId || !brokerageOrderId) {
      return res.status(400).json({ error: 'Missing userId, accountId or brokerageOrderId' });
    }

    const snaptrade = mkClient();

    const result = await snaptradeCall(() =>
      snaptrade.trading.cancelOrder({
        accountId,
        userId,
        userSecret,
        brokerage_order_id: brokerageOrderId
      })
    );

    console.log(`✅ Order ${brokerageOrderId} cancelled for ${userId}`);
    res.json({ success: true, result: result.data });

  } catch (err: any) {
    console.error('❌ Cancel order error:', err);
    res.status(500).json(errPayload(err));
  }
});

// ── Broker capabilities ──
app.get('/account/capabilities', async (req, res) => {
  try {
    const userId = String(req.query.userId || '');
    const accountId = String(req.query.accountId || '');
    const userSecret = getSecret(userId) || await fetchUserSecretFromDB(userId);

    if (!userId || !userSecret || !accountId) {
      return res.status(400).json({ error: 'Missing userId or accountId' });
    }

    const snaptrade = mkClient();

    // Get account details
    const accountsResp = await snaptradeCall(() =>
      snaptrade.accountInformation.listUserAccounts({ userId, userSecret })
    );
    const accounts: any[] = accountsResp?.data || [];
    const account = accounts.find(a =>
      a.id === accountId || a.accountId === accountId ||
      a.number === accountId || a.guid === accountId
    );

    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Get broker slug
    const brokerSlug = (
      account?.broker ||
      account?.broker_slug ||
      account?.brokerage?.slug ||
      account?.brokerage?.name ||
      account?.provider ||
      'UNKNOWN'
    ).toUpperCase();

    // Static capability map based on SnapTrade's brokerage support matrix
    const BROKER_CAPS: Record<string, any> = {
  // ── Trading-capable (per SnapTrade docs) ──
  'ALPACA':        { trading: true,  options: false, crypto: true,  fractional: true,  extendedHours: true  },
  'BINANCE':       { trading: true,  options: false, crypto: true,  fractional: true,  extendedHours: true  },
  'COINBASE':      { trading: true,  options: false, crypto: true,  fractional: true,  extendedHours: true  },
  'SCHWAB':        { trading: true,  options: true,  crypto: false, fractional: true,  extendedHours: false },
  'ETRADE':        { trading: true,  options: true,  crypto: false, fractional: false, extendedHours: true  },
  'KRAKEN':        { trading: true,  options: false, crypto: true,  fractional: true,  extendedHours: true  },
  'MOOMOO':        { trading: true,  options: true,  crypto: false, fractional: true,  extendedHours: true  },
  'STAKE_AUS':     { trading: true,  options: false, crypto: false, fractional: false, extendedHours: false },
  'PUBLIC':        { trading: true,  options: true,  crypto: true,  fractional: true,  extendedHours: false },
  'QUESTRADE':     { trading: true,  options: true,  crypto: false, fractional: false, extendedHours: false },
  'TASTYTRADE':    { trading: true,  options: true,  crypto: false, fractional: false, extendedHours: false },
  'TRADIER':       { trading: true,  options: true,  crypto: false, fractional: false, extendedHours: true  },
  'WEALTHSIMPLE':  { trading: true,  options: false, crypto: true,  fractional: false, extendedHours: false },
  'TRADING_212':   { trading: true,  options: false, crypto: false, fractional: true,  extendedHours: false },
  'WEBULL':        { trading: true,  options: true,  crypto: true,  fractional: true,  extendedHours: true  },
  'WEBULL_US':     { trading: true,  options: true,  crypto: true,  fractional: true,  extendedHours: true  },
  'WEBULL_CA':     { trading: true,  options: true,  crypto: false, fractional: true,  extendedHours: true  },

  // ── Read-only only (trading: false = never tradeable via SnapTrade) ──
  'ROBINHOOD':           { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'FIDELITY':            { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'VANGUARD':            { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'VANGUARD_US':         { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'EMPOWER':             { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'INTERACTIVE_BROKERS': { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'TRADESTATION':        { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'CHASE':               { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'JPMORGAN':            { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'AJ_BELL':             { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'BUX':                 { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'COMMSEC':             { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'UPSTOX':              { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'WELLS_FARGO':         { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'WELLSFARGO':          { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
  'ZERODHA':             { trading: false, options: false, crypto: false, fractional: false, extendedHours: false },
};

// Short-circuit for known read-only brokers — no API call needed
const READ_ONLY_BROKERS = new Set([
  'ROBINHOOD', 'FIDELITY', 'VANGUARD', 'VANGUARD_US', 'EMPOWER',
  'INTERACTIVE_BROKERS', 'TRADESTATION', 'CHASE', 'JPMORGAN',
  'AJ_BELL', 'BUX', 'COMMSEC', 'UPSTOX', 'WELLS_FARGO',
  'WELLSFARGO', 'ZERODHA'
]);

if (READ_ONLY_BROKERS.has(brokerSlug)) {
  return res.json({
    accountId,
    brokerName: brokerSlug,
    capabilities: BROKER_CAPS[brokerSlug],
    tradingReauthUrl: null
  });
}

// Only call ensureTradingEnabled for brokers that actually support trading
const tradingCheck = await ensureTradingEnabled(snaptrade, userId, userSecret, accountId);

const caps = BROKER_CAPS[brokerSlug] || {
  trading: tradingCheck.ok,
  options: false,
  crypto: false,
  fractional: false,
  extendedHours: false
};

res.json({
  accountId,
  brokerName: brokerSlug,
  capabilities: {
    ...caps,
    trading: tradingCheck.ok, // always use live check, never trust static map alone
  },
  tradingReauthUrl: tradingCheck.reauthUrl || null
});

  } catch (err: any) {
    console.error('❌ Capabilities error:', err);
    res.status(500).json(errPayload(err));
  }
});

// ════════════════════════════════════════════════════════════════════
// DEVICE TOKEN REGISTRATION — for push notifications
// ════════════════════════════════════════════════════════════════════

// iOS app calls this after user grants push permission
app.post('/devices/register', async (req, res) => {
  try {
    const { userId, deviceToken, platform, bundleId, appVersion } = req.body;

    if (!userId || !deviceToken) {
      return res.status(400).json({ error: 'Missing userId or deviceToken' });
    }

    // Upsert: if same token already exists, update user binding + last_seen
    const result = await pool.query(
      `INSERT INTO device_tokens (user_id, device_token, platform, bundle_id, app_version)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (device_token) DO UPDATE
       SET user_id = EXCLUDED.user_id,
           bundle_id = EXCLUDED.bundle_id,
           app_version = EXCLUDED.app_version,
           last_seen_at = NOW(),
           updated_at = NOW()
       RETURNING *`,
      [userId, deviceToken, platform || 'ios', bundleId || null, appVersion || null]
    );

    console.log(`📱 Device registered for ${userId}: ${deviceToken.substring(0, 16)}...`);
    res.json({ success: true, device: result.rows[0] });
  } catch (err: any) {
    console.error('❌ Device register error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Optional: unregister (e.g. user logs out)
app.delete('/devices/register', async (req, res) => {
  try {
    const deviceToken = String(req.query.deviceToken || req.body?.deviceToken || '');
    if (!deviceToken) return res.status(400).json({ error: 'Missing deviceToken' });

    await pool.query(`DELETE FROM device_tokens WHERE device_token = $1`, [deviceToken]);
    res.json({ success: true });
  } catch (err: any) {
    console.error('❌ Device unregister error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════
// PRICE ALERTS — user-configurable notifications
// ════════════════════════════════════════════════════════════════════

// Create a new alert
app.post('/alerts', async (req, res) => {
  try {
    const { userId, symbol, conditionType, threshold } = req.body;

    if (!userId || !symbol || !conditionType || threshold === undefined) {
      return res.status(400).json({ error: 'Missing userId, symbol, conditionType, or threshold' });
    }

    const validTypes = ['above', 'below', 'pct_up', 'pct_down'];
    if (!validTypes.includes(conditionType)) {
      return res.status(400).json({ error: `conditionType must be one of: ${validTypes.join(', ')}` });
    }

    const thresholdNum = Number(threshold);
    if (isNaN(thresholdNum) || thresholdNum <= 0) {
      return res.status(400).json({ error: 'threshold must be a positive number' });
    }

    const result = await pool.query(
      `INSERT INTO price_alerts (user_id, symbol, condition_type, threshold)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [userId, symbol.toUpperCase(), conditionType, thresholdNum]
    );

    console.log(`🔔 Alert created for ${userId}: ${symbol} ${conditionType} ${threshold}`);
    res.json({ success: true, alert: result.rows[0] });
  } catch (err: any) {
    console.error('❌ Create alert error:', err);
    res.status(500).json({ error: err.message });
  }
});

// List a user's alerts
app.get('/alerts', async (req, res) => {
  try {
    const userId = String(req.query.userId || '');
    if (!userId) return res.status(400).json({ error: 'Missing userId' });

    const result = await pool.query(
      `SELECT * FROM price_alerts
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId]
    );

    res.json({ alerts: result.rows, count: result.rows.length });
  } catch (err: any) {
    console.error('❌ List alerts error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Update an alert (toggle active, change threshold)
app.patch('/alerts/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { userId, isActive, threshold, conditionType } = req.body;

    if (!userId) return res.status(400).json({ error: 'Missing userId' });
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid alert id' });

    // Build dynamic update
    const updates: string[] = [];
    const values: any[] = [];
    let i = 1;

    if (isActive !== undefined) { updates.push(`is_active = $${i++}`); values.push(Boolean(isActive)); }
    if (threshold !== undefined) { updates.push(`threshold = $${i++}`); values.push(Number(threshold)); }
    if (conditionType !== undefined) { updates.push(`condition_type = $${i++}`); values.push(conditionType); }

    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    updates.push(`updated_at = NOW()`);
    values.push(id, userId);

    const result = await pool.query(
      `UPDATE price_alerts SET ${updates.join(', ')}
       WHERE id = $${i++} AND user_id = $${i}
       RETURNING *`,
      values
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Alert not found or not owned by user' });
    }

    res.json({ success: true, alert: result.rows[0] });
  } catch (err: any) {
    console.error('❌ Update alert error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Delete an alert
app.delete('/alerts/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const userId = String(req.query.userId || req.body?.userId || '');

    if (!userId) return res.status(400).json({ error: 'Missing userId' });
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid alert id' });

    const result = await pool.query(
      `DELETE FROM price_alerts WHERE id = $1 AND user_id = $2 RETURNING id`,
      [id, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Alert not found or not owned by user' });
    }

    console.log(`🗑️  Alert ${id} deleted for ${userId}`);
    res.json({ success: true });
  } catch (err: any) {
    console.error('❌ Delete alert error:', err);
    res.status(500).json({ error: err.message });
  }
});


// ── Enterprise: API key auth middleware ──
async function authenticateEnterpriseKey(req: any, res: any, next: any) {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: 'Missing API key' });
  try {
    const result = await pool.query(
      'SELECT * FROM enterprise_clients WHERE api_key = $1 AND active = TRUE',
      [key]
    );
    if (!result.rows[0]) return res.status(403).json({ error: 'Invalid API key' });
    req.enterpriseClient = result.rows[0];
    next();
  } catch (err) {
    res.status(500).json({ error: 'Auth check failed' });
  }
}

// ── TYGER PULSE: Buy/sell pressure for a symbol ──
app.get('/pulse/flow/:symbol', authenticateEnterpriseKey, async (req, res) => {
  try {
    const symbol = req.params.symbol.toUpperCase();
    const minutes = Math.min(Number(req.query.minutes || 60), 1440);

    const result = await pool.query(`
      SELECT 
        action,
        COUNT(*) as order_count,
        SUM(quantity) as total_quantity,
        AVG(limit_price) FILTER (WHERE limit_price IS NOT NULL) as avg_limit_price,
        broker_country,
        COUNT(DISTINCT anonymous_id) as unique_traders
      FROM retail_flow_signals
      WHERE symbol = $1 
        AND timestamp > NOW() - ($2 || ' minutes')::INTERVAL
      GROUP BY action, broker_country
      ORDER BY order_count DESC
    `, [symbol, minutes]);

    const buys = result.rows.filter(r => r.action === 'BUY');
    const sells = result.rows.filter(r => r.action === 'SELL');
    const totalBuys = buys.reduce((s, r) => s + Number(r.order_count), 0);
    const totalSells = sells.reduce((s, r) => s + Number(r.order_count), 0);
    const total = totalBuys + totalSells;

    const sentiment = totalBuys > totalSells * 1.5 ? 'STRONGLY_BULLISH'
      : totalBuys > totalSells ? 'BULLISH'
      : totalSells > totalBuys * 1.5 ? 'STRONGLY_BEARISH'
      : totalSells > totalBuys ? 'BEARISH'
      : 'NEUTRAL';

    res.json({
      symbol,
      window_minutes: minutes,
      buy_pressure: total > 0 ? Number((totalBuys / total * 100).toFixed(1)) : 50,
      sell_pressure: total > 0 ? Number((totalSells / total * 100).toFixed(1)) : 50,
      total_signals: total,
      unique_traders: result.rows.reduce((s, r) => s + Number(r.unique_traders), 0),
      by_country: result.rows,
      sentiment,
      timestamp: new Date().toISOString()
    });
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

// ── TYGER PULSE: Trending symbols right now ──
app.get('/pulse/trending', authenticateEnterpriseKey, async (req, res) => {
  try {
    const minutes = Math.min(Number(req.query.minutes || 30), 1440);
    const country = req.query.country as string;

    const result = await pool.query(`
      SELECT 
        symbol,
        COUNT(*) as signal_count,
        SUM(CASE WHEN action = 'BUY' THEN 1 ELSE 0 END) as buys,
        SUM(CASE WHEN action = 'SELL' THEN 1 ELSE 0 END) as sells,
        COUNT(DISTINCT broker_country) as countries_active,
        COUNT(DISTINCT anonymous_id) as unique_traders
      FROM retail_flow_signals
      WHERE timestamp > NOW() - ($1 || ' minutes')::INTERVAL
        ${country ? `AND broker_country = '${country.toUpperCase()}'` : ''}
      GROUP BY symbol
      ORDER BY signal_count DESC
      LIMIT 20
    `, [minutes]);

    res.json({
      window_minutes: minutes,
      trending: result.rows.map(r => ({
        symbol: r.symbol,
        signal_count: Number(r.signal_count),
        buys: Number(r.buys),
        sells: Number(r.sells),
        buy_ratio: Number(((Number(r.buys) / (Number(r.buys) + Number(r.sells))) * 100).toFixed(1)),
        countries_active: Number(r.countries_active),
        unique_traders: Number(r.unique_traders)
      })),
      timestamp: new Date().toISOString()
    });
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

// ── TYGER PULSE: Sector rotation ──
app.get('/pulse/sectors', authenticateEnterpriseKey, async (req, res) => {
  try {
    const hours = Math.min(Number(req.query.hours || 24), 168);

    const result = await pool.query(`
      SELECT 
        sector,
        COUNT(*) as signal_count,
        SUM(CASE WHEN action = 'BUY' THEN 1 ELSE 0 END) as buys,
        SUM(CASE WHEN action = 'SELL' THEN 1 ELSE 0 END) as sells,
        COUNT(DISTINCT anonymous_id) as unique_traders,
        COUNT(DISTINCT broker_country) as countries
      FROM retail_flow_signals
      WHERE timestamp > NOW() - ($1 || ' hours')::INTERVAL
        AND sector IS NOT NULL
      GROUP BY sector
      ORDER BY signal_count DESC
    `, [hours]);

    res.json({
      window_hours: hours,
      sectors: result.rows.map(r => ({
        sector: r.sector,
        signal_count: Number(r.signal_count),
        buys: Number(r.buys),
        sells: Number(r.sells),
        buy_ratio: Number(((Number(r.buys) / (Number(r.buys) + Number(r.sells))) * 100).toFixed(1)),
        unique_traders: Number(r.unique_traders),
        countries: Number(r.countries)
      })),
      timestamp: new Date().toISOString()
    });
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

// ── TYGER PULSE: Global retail heatmap ──
app.get('/pulse/global', authenticateEnterpriseKey, async (req, res) => {
  try {
    const minutes = Math.min(Number(req.query.minutes || 60), 1440);

    const result = await pool.query(`
      SELECT 
        broker_country,
        COUNT(*) as signal_count,
        SUM(CASE WHEN action = 'BUY' THEN 1 ELSE 0 END) as buys,
        SUM(CASE WHEN action = 'SELL' THEN 1 ELSE 0 END) as sells,
        COUNT(DISTINCT anonymous_id) as unique_traders,
        COUNT(DISTINCT symbol) as symbols_traded
      FROM retail_flow_signals
      WHERE timestamp > NOW() - ($1 || ' minutes')::INTERVAL
        AND broker_country != 'UNKNOWN'
      GROUP BY broker_country
      ORDER BY signal_count DESC
    `, [minutes]);

    res.json({
      window_minutes: minutes,
      countries: result.rows.map(r => ({
        country: r.broker_country,
        signal_count: Number(r.signal_count),
        buys: Number(r.buys),
        sells: Number(r.sells),
        sentiment: Number(r.buys) > Number(r.sells) ? 'BULLISH' : 'BEARISH',
        unique_traders: Number(r.unique_traders),
        symbols_traded: Number(r.symbols_traded)
      })),
      timestamp: new Date().toISOString()
    });
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

// ── TYGER PULSE: Health check (no auth needed) ──
app.get('/pulse/status', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        COUNT(*) as total_signals,
        COUNT(DISTINCT symbol) as unique_symbols,
        COUNT(DISTINCT broker_country) as countries,
        MAX(timestamp) as last_signal
      FROM retail_flow_signals
      WHERE timestamp > NOW() - INTERVAL '24 hours'
    `);
    res.json({
      status: 'live',
      last_24h: result.rows[0],
      timestamp: new Date().toISOString()
    });
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

// ════════════════════════════════════════════════════════════════════
// PRICE ALERT CHECKER — runs every minute
// ════════════════════════════════════════════════════════════════════

async function checkPriceAlerts() {
  try {
    // Get all active alerts
    const alertsResult = await pool.query(
      `SELECT * FROM price_alerts WHERE is_active = TRUE`
    );
    const alerts = alertsResult.rows;
    if (alerts.length === 0) return;

    // Group alerts by symbol so we only fetch each price once
    const uniqueSymbols = [...new Set(alerts.map((a: any) => a.symbol))];
    console.log(`🔍 Checking ${alerts.length} alerts across ${uniqueSymbols.length} symbols`);

    // Fetch current price + daily % change for each symbol
    const priceMap: Record<string, { price: number; pctChange: number }> = {};
    await Promise.allSettled(
      uniqueSymbols.map(async (symbol: string) => {
        try {
          const url = `https://snaptrade-api-da44.onrender.com/market/price/${symbol}`;
          const resp = await fetch(url);
          if (!resp.ok) return;
          const data: any = await resp.json();
          if (typeof data?.price === 'number') {
            priceMap[symbol] = {
              price: data.price,
              pctChange: typeof data.changePercent === 'number' ? data.changePercent : 0,
            };
          }
        } catch (e) {
          console.warn(`Could not fetch price for ${symbol}`);
        }
      })
    );

    // Check each alert against current price
    for (const alert of alerts) {
      const market = priceMap[alert.symbol];
      if (!market) continue; // skip if price fetch failed

      const threshold = parseFloat(alert.threshold);
      let shouldFire = false;
      let reason = '';

      switch (alert.condition_type) {
        case 'above':
          if (market.price >= threshold) {
            shouldFire = true;
            reason = `price $${market.price.toFixed(2)} reached $${threshold}`;
          }
          break;
        case 'below':
          if (market.price <= threshold) {
            shouldFire = true;
            reason = `price $${market.price.toFixed(2)} dropped below $${threshold}`;
          }
          break;
        case 'pct_up':
          if (market.pctChange >= threshold) {
            shouldFire = true;
            reason = `up ${market.pctChange.toFixed(2)}% today (threshold ${threshold}%)`;
          }
          break;
        case 'pct_down':
          if (market.pctChange <= -threshold) {
            shouldFire = true;
            reason = `down ${Math.abs(market.pctChange).toFixed(2)}% today (threshold ${threshold}%)`;
          }
          break;
      }

      if (!shouldFire) continue;

      // Don't fire the same alert more than once per 24 hours
      if (alert.last_triggered_at) {
        const hoursSince = (Date.now() - new Date(alert.last_triggered_at).getTime()) / 1000 / 3600;
        if (hoursSince < 24) {
          continue; // already fired in last 24h, skip
        }
      }

      console.log(`🚨 ALERT FIRED for ${alert.user_id}: ${alert.symbol} ${alert.condition_type} — ${reason}`);

      // Mark as triggered
      await pool.query(
        `UPDATE price_alerts
         SET last_triggered_at = NOW(), trigger_count = trigger_count + 1
         WHERE id = $1`,
        [alert.id]
      );

      // TODO Phase 2: send actual push notification here
      await sendPriceAlertNotification(alert.user_id, alert.symbol, reason);
    }
  } catch (err: any) {
    console.error('❌ Price alert checker error:', err);
  }
}

// ════════════════════════════════════════════════════════════════════
// APNS — Apple Push Notification Service
// ════════════════════════════════════════════════════════════════════

const apnProvider = (() => {
  if (!process.env.APNS_PRIVATE_KEY || !process.env.APNS_KEY_ID || !process.env.APNS_TEAM_ID) {
    console.warn('⚠️  APNs not configured — pushes will be logged only');
    return null;
  }
  return new apn.Provider({
    token: {
      key: process.env.APNS_PRIVATE_KEY.replace(/\\n/g, '\n'),
      keyId: process.env.APNS_KEY_ID,
      teamId: process.env.APNS_TEAM_ID,
    },
    production: process.env.APNS_PRODUCTION === 'true',
  });
})();

async function sendPriceAlertNotification(userId: string, symbol: string, reason: string) {
  try {
    // Look up all device tokens for this user (a user can have multiple devices)
    const result = await pool.query(
      'SELECT device_token FROM device_tokens WHERE user_id = $1',
      [userId]
    );
    const tokens = result.rows.map(r => r.device_token);

    if (tokens.length === 0) {
      console.log(`📱 [no devices] ${userId}: ${symbol} — ${reason}`);
      return;
    }

    if (!apnProvider) {
      console.log(`📱 [APNs disabled] ${userId}: ${symbol} — ${reason}`);
      return;
    }

    const note = new apn.Notification();
    note.alert = {
      title: `${symbol} Alert`,
      body: reason,
    };
    note.sound = 'default';
    note.topic = process.env.APNS_BUNDLE_ID || 'com.apexmarkets.app';
    note.payload = { symbol, reason, type: 'price_alert' };
    note.expiry = Math.floor(Date.now() / 1000) + 3600; // expire in 1 hour if undelivered

    const response = await apnProvider.send(note, tokens);

    console.log(`📱 Push sent for ${symbol} to ${userId}: ${response.sent.length} ok, ${response.failed.length} failed`);

    // Clean up dead tokens (Apple rejects them when user uninstalls app)
  // Clean up dead tokens (Apple rejects them when user uninstalls app)
    for (const failure of response.failed as any[]) {
      const reason = failure?.response?.reason;
      const status = String(failure?.status ?? '');
      if (status === '410' || reason === 'BadDeviceToken' || reason === 'Unregistered') {
        console.log(`🧹 Removing dead token: ${String(failure.device).substring(0, 16)}...`);
        await pool.query('DELETE FROM device_tokens WHERE device_token = $1', [failure.device]);
      } else {
        console.warn(`Push failure: ${reason || failure?.error}`);
      }
    }
  } catch (e) {
    console.warn('Could not send price alert push:', e);
  }
}

// Start the checker — runs every 60 seconds
setInterval(checkPriceAlerts, 60 * 1000);
console.log('⏰ Price alert checker scheduled — every 60s');

// Also run once on startup so we don't wait a full minute
setTimeout(checkPriceAlerts, 5000);

/* ---------------------------- 404 last ---------------------------- */

app.use((_req, res) => res.status(404).type("text/plain").send("Not found"));

/* ----------------------------- start ----------------------------- */

app.listen(PORT, HOST, () => {
  console.log(`🚀 API running on http://${HOST}:${PORT}`);
  // @ts-ignore
  const stack: any[] = app._router?.stack || [];
  const routes = stack
    .filter((l) => l.route && l.route.path)
    .map((l) => `${Object.keys(l.route.methods || {}).map((m) => m.toUpperCase()).join(",")} ${l.route.path}`);
  console.log("Mounted routes:"); routes.forEach((r) => console.log(" •", r));
  console.log(`Local:  http://127.0.0.1:${PORT}/health`);
  const ips = lanIPs();
  if (ips.length) console.log(`Phone:  http://${ips[0]}:${PORT}/health`);
});

// Keep Render awake
setInterval(() => {
  fetch("https://snaptrade-api-da44.onrender.com/health")
    .catch(() => {})
}, 14 * 60 * 1000);