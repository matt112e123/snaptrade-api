import "dotenv/config";
import express from "express";
import { Snaptrade } from "snaptrade-typescript-sdk";
import os from "os";
import cors from "cors";
import fs from "fs";
import path from "path";

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
      null;

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
      equity: Math.max(0, totalValue - totalCash),
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

// Add this route after your debug helpers
// Replace your /market/history/:symbol handler with this
app.get('/market/history/:symbol', async (req, res) => {
  try {
    const symbol = (req.params.symbol || '').toUpperCase();
    const from = String(req.query.from || ''); // "YYYY-MM-DD" optional
    const to = String(req.query.to || '');     // "YYYY-MM-DD" optional
    const apiKey = process.env.FMP_API_KEY;
    if (!apiKey) return res.status(500).json({ error: 'Missing FMP_API_KEY in env' });

    const cacheKey = `${symbol}|light|${from}|${to}`;
    const cached = MARKET_CACHE.get(cacheKey);
    if (cached && Date.now() < cached.expires) {
      return res.json(cached.data);
    }

    const url = `https://financialmodelingprep.com/stable/historical-price-eod/light?symbol=${encodeURIComponent(symbol)}&apikey=${apiKey}`;

    const resp = await fetch(url);
    const text = await resp.text();
    let json: any = null;
    try { json = JSON.parse(text); } catch (e: any) { json = null; }

    if (!resp.ok) {
      // If FMP returned an informative JSON error, forward it
      if (json) return res.status(resp.status).json(json);
      return res.status(resp.status).send(text || `FMP error ${resp.status}`);
    }

    // Detect common "legacy" error payload and return informative message
    if (json && typeof json === 'object' && json['Error Message'] && /Legacy Endpoint/i.test(String(json['Error Message']))) {
      return res.status(502).json({ error: 'FMP legacy endpoint not available for this key/plan', detail: json['Error Message'] });
    }

    // Normalize: FMP light endpoint returns an object like { symbol: 'AMZN', historical: [{ date: '2025-12-10', close: 123.45, ...}, ...] }
    // But be defensive: accept array, or json.historical
    let items: any[] = [];
    if (Array.isArray(json)) {
      items = json;
    } else if (Array.isArray(json?.historical)) {
      items = json.historical;
    } else if (Array.isArray(json?.prices)) {
      items = json.prices;
    } else {
      // Unknown shape — return raw for debugging
      MARKET_CACHE.set(cacheKey, { expires: Date.now() + MARKET_CACHE_TTL_MS, data: { provider: 'fmp', symbol, values: [], raw: json } });
      return res.json({ provider: 'fmp', symbol, values: [], raw: json });
    }

    // Map/normalize to { date, close } and sort ascending
    const dayFmt = (d: string) => d; // assume already "YYYY-MM-DD" or "YYYY-MM-DD HH:mm:ss"
    let values = items
      .map((it: any) => {
        // date candidates
        const dateStr = it.date || it.datetime || it.time || it.timestamp;
        // close candidates: cover different FMP shapes (price, close, adjClose, close_price)
        const closeCandidate = it.close ?? it.price ?? it.adjClose ?? it.closePrice ?? it.close_price ?? it.close;
        const close = (closeCandidate !== undefined && closeCandidate !== null) ? Number(closeCandidate) : NaN;
        return (dateStr && !Number.isNaN(close)) ? { date: String(dateStr).split(' ')[0], close } : null;
      })
      .filter(Boolean) as { date: string; close: number }[];

    // Sort ascending by date
    values.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));

    // Filter by from/to if provided (both in "YYYY-MM-DD" form)
    if (from) values = values.filter(v => v.date >= from);
    if (to) values = values.filter(v => v.date <= to);

    const payload = { provider: 'fmp', symbol, values, raw: json };
    MARKET_CACHE.set(cacheKey, { expires: Date.now() + MARKET_CACHE_TTL_MS, data: payload });

    return res.json(payload);
  } catch (err: any) {
    console.error('Market history (FMP light) error', err);
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
/* ------------------------- SnapTrade connect ---------------------- */
/**
 * NAVIGATE here from the browser (not fetch/XHR):
 * /connect?fresh=1&web=1        # web callback
 * /connect?fresh=1              # mobile deep link callback
 * Optional (dev only): ?json=1 when ALLOW_JSON=1
 */
async function handleConnect(req: express.Request, res: express.Response) {
  try {
    const snaptrade = mkClient();
    const fresh = String(req.query.fresh || "") === "1";

    let userId = (req.query.userId as string) || process.env.SNAPTRADE_USER_ID || "";
    let userSecret = (req.query.userSecret as string) || process.env.SNAPTRADE_USER_SECRET || "";

    if (fresh || !userId || !userSecret) {
      userId = `dev-${Date.now()}`;
      const reg = await snaptrade.authentication.registerSnapTradeUser({ userId });
      userSecret = (reg?.data as any)?.userSecret;
      if (!userSecret) {
        return res.status(500).json({ error: "register returned no userSecret", raw: reg?.data });
      }
    } else {
      try {
        await snaptrade.authentication.registerSnapTradeUser({ userId });
      } catch (e: any) {
        if (![400, 409].includes(e?.response?.status)) throw e;
      }
    }

    // store secret for the polling endpoints
// store secret for the polling endpoints
putSecret(userId, userSecret);

// 🔄 FULL SYNC LOOP — wait until holdings finished syncing
let summary;
console.log(`⏳ Initial sync starting for ${userId}`);

do {
  const summary = await fetchAndSaveUserSummary(userId, userSecret);

  // Only save when fully synced
  if (!summary.syncing) {
    console.log("✅ Fully synced. Saving FINAL summary.");
    await saveSnaptradeUser(userId, userSecret, summary);
    break;
  }

  console.log("⏳ Waiting for full sync...");
  await new Promise(r => setTimeout(r, 2000));
} while (true);


console.log(`✅ User ${userId} fully synced and saved to DB.`);

    
    
    // save the user to Postgres
  await fetchAndSaveUserSummary(userId, userSecret);



    const mobileBase = requireEnv("SNAPTRADE_REDIRECT_URI"); // e.g. apexmarkets://snaptrade-callback
    const webBase = process.env.SNAPTRADE_WEB_REDIRECT_URI || mobileBase; // e.g. https://www.theapexinvestor.com/snaptrade-callback

    // Append userId to BOTH
    const mobileURL = new URL(mobileBase);
    mobileURL.searchParams.set("userId", userId);

    const webURL = new URL(webBase);
    webURL.searchParams.set("userId", userId);

    // only accept valid URLs from query
    const tryUrl = (v: unknown): string | "" => {
      if (typeof v !== "string" || !v.trim()) return "";
      try { return new URL(v).toString(); } catch { return ""; }
    };
    const custom = tryUrl(req.query.customRedirect) || tryUrl(req.query.redirect);

    // Decide: web or mobile
    const requested =
      custom ||
      (req.query.web === "1" ? webURL.toString() : mobileURL.toString());

    // Accept optional connectionType and reconnect parameters from the request/query
    // Allowed: "trade", "trade-if-available", "read"
    const allowedTypes = new Set(["trade", "trade-if-available", "read"]);
    let connectionType = String(req.query.connectionType || "trade-if-available");
    if (!allowedTypes.has(connectionType)) connectionType = "trade-if-available";

    // reconnect is optional - used to re-authorize an existing connection for trading
    const reconnect = typeof req.query.reconnect === "string" && req.query.reconnect.trim() ? String(req.query.reconnect).trim() : undefined;

    const loginResp = await snaptrade.authentication.loginSnapTradeUser({
      userId,
      userSecret,
      immediateRedirect: true,
      customRedirect: requested,
      // cast to satisfy the SDK type (enum)
      connectionType: connectionType as any,
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

    // ⚡️ THIS IS THE FIX: Redirect the browser instead of returning JSON
    res.redirect(302, redirectURI);

  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
}


app.get("/connect", handleConnect);
app.get("/connect/redirect", handleConnect); // alias for your frontend button


/* ----------------------------- linked ---------------------------- */

app.get("/realtime/linked", async (req, res) => {
  try {
    const userId = String(req.query.userId || "");
    const userSecret = String(req.query.userSecret || getSecret(userId) || "");
    const snaptrade = mkClient();
    console.log({ userId, userSecret });
    let linked = false;
    try {
      const r = await snaptrade.connections.listBrokerageAuthorizations({ userId, userSecret });
      console.log("Auths:", JSON.stringify(r.data,null,2));
      linked = (r.data?.length ?? 0) > 0;
    } catch (e: any) { console.error("Error in listBrokerageAuthorizations", e); }
    if (!linked) {
      try {
        const r = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
        console.log("Accounts:", JSON.stringify(r.data,null,2));
        linked = (r.data?.length ?? 0) > 0;
      } catch (e: any) { console.error("Error in listUserAccounts", e);}
    }
    res.json({ linked });
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

/* ------------- Real-time: summary (balances + positions) ---------- */

app.get("/realtime/summary", async (req, res) => {
  try {
    const userId = (req.query.userId ?? "").toString();
    const secretFromCache = getSecret(userId);
    const secretFromDB = await fetchUserSecretFromDB(userId);
    const userSecret = (req.query.userSecret as string) || secretFromCache || secretFromDB || "";

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
      pickNumber(balancesArr.find((b: any) => b?.cash != null) || {}) ??
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
        equity: Math.max(0, totalValue - totalCash),
        cash: totalCash,
        buyingPower: totalBP,
      },
      positions: outPositions,
      activitiesByAccount, 
      holdingsByAccount, // full raw h.data per account
      syncing,
    };

    // 💾 Now: Save summary to DB
    await saveSnaptradeUser(userId, userSecret, summary);

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
async function ensureTradingEnabled(snaptrade: any, userId: string, userSecret: string, accountId?: string) {
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

    // 2) Try to find a matched auth that references this account (various shapes)
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

    // Fallback: if we didn't find matchedAuth above, try matching the account's brokerage_authorization -> auth id
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

    // Short summary log if we have a match
    if (matchedAuth) {
      console.log("ensureTradingEnabled: matchedAuth summary =>",
        {
          id: matchedAuth.id || matchedAuth.connection_id || matchedAuth.connectionId,
          broker: matchedAuth.broker || matchedAuth.broker_slug || matchedAuth.provider || matchedAuth?.brokerage?.slug,
          permissions: matchedAuth.permissions,
          trading_enabled: matchedAuth.trading_enabled ?? matchedAuth.supports_trading ?? matchedAuth.allow_trading ?? matchedAuth.canTrade,
          type: matchedAuth.type
        }
      );
    }

    // If matchedAuth exists, robustly detect trading capability from multiple fields/shapes
    if (matchedAuth) {
      const perms = Array.isArray(matchedAuth?.permissions)
        ? matchedAuth.permissions.map((p: any) => String(p).toLowerCase())
        : [];

      const tradingFlag = matchedAuth?.trading_enabled ?? matchedAuth?.supports_trading ?? matchedAuth?.allow_trading ?? matchedAuth?.canTrade;

      const authType = (typeof matchedAuth?.type === "string" ? matchedAuth.type.toLowerCase() : undefined);

      const brokerAllows = Array.isArray(matchedAuth?.brokerage?.authorization_types)
        ? matchedAuth.brokerage.authorization_types.map((t: any) => String(t.type).toLowerCase())
        : [];

      if (
        tradingFlag === true ||
        perms.includes("trade") ||
        perms.includes("trading") ||
        perms.includes("orders") ||
        authType === "trade" || 
        authType === "trade" ||
        brokerAllows.includes("trade") ||
        matchedAuth?.brokerage?.allows_trading === true
      ) {
        return { ok: true };
      }

      // If we have an auth id but it's not marked as trading, offer reconnect link
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
          const candidate = loginResp?.data?.redirectURI || loginResp?.data?.redirectUri || loginResp?.data?.loginRedirectURI || loginResp?.data?.loginRedirectUri || (typeof loginResp?.data === "string" ? loginResp.data : undefined);
          if (candidate) return { ok: false, reason: "trade_not_enabled", reauthUrl: candidate };
        } catch (e: any) {
          console.warn("Could not build reauth link for matched auth:", (e && e.message) || e);
        }
      }

      return { ok: false, reason: "trade_not_enabled" };
    }

    // If no matchedAuth, inspect account objects for trading flags
    try {
      const aResp = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
      const accounts = aResp?.data || [];
      for (const acct of accounts) {
        const aid = acct?.id || acct?.accountId || acct?.number || acct?.guid;
        if (!accountId || aid === accountId) {
          const accFlags = [
            acct?.trading_enabled,
            acct?.supports_trading,
            acct?.allow_trading,
            acct?.canTrade,
            acct?.permissions && Array.isArray(acct.permissions) && acct.permissions.map((p: any) => String(p).toLowerCase()).includes("trade")
          ];
          if (accFlags.some(f => f === true)) return { ok: true };
        }
      }
    } catch (e: any) {
      console.warn("Could not listUserAccounts while checking trading support:", (e && e.message) || e);
    }

    // Final fallback: try building a generic login link that requests trading
    try {
      const loginResp = await snaptrade.authentication.loginSnapTradeUser({
        userId,
        userSecret,
        immediateRedirect: false,
        connectionType: "trade",
      });
      const candidate = loginResp?.data?.redirectURI || loginResp?.data?.redirectUri || loginResp?.data?.loginRedirectURI || loginResp?.data?.loginRedirectUri || (typeof loginResp?.data === "string" ? loginResp.data : undefined);
      if (candidate) return { ok: false, reason: "trade_not_enabled", reauthUrl: candidate };
    } catch (e: any) {
      console.warn("Could not build generic reauth link:", (e && e.message) || e);
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
console.log("PlaceOrder received:", req.body); // <-- Add this!

  const tradeId = uuidv4();

  try {
    const {
      userId,
      userSecret,
      accountId,
      symbol,        // e.g. "AAPL" or "BTC-USD"
      action,        // "Buy" or "Sell"
      orderType,     // "Market" or "Limit"
      quantity,      // shares or crypto amount
      limitPrice     // optional
    } = req.body;

    if (!userId || !userSecret || !accountId || !symbol || !action || !orderType || !quantity) {
      return res.status(400).json({ error: "Missing required fields (userId,userSecret,accountId,symbol,action,orderType,quantity)" });
    }

    const snaptrade = mkClient();

    // Validate trading capability before placing order
    const check = await ensureTradingEnabled(snaptrade, userId, userSecret, accountId);
    if (!check.ok) {
      const payload: any = { error: "Trading not enabled for this account", reason: check.reason || "unknown" };
      if (check.reauthUrl) payload.reauthUrl = check.reauthUrl;
      return res.status(403).json(payload);
    }

    // 👉 Get the broker name for the account
    const broker = await getAccountBroker(snaptrade, userId, userSecret, accountId);

      // --- CRYPTO TRADING branch ---
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
 let params: any = {
  userId,
  userSecret,
  tradeId,
  accountId,
  action,
  order_type: orderType,      // or 'orderType' if that's what your SDK expects
  time_in_force: "Day",
  units: Number(quantity),
  symbol
};

if (
  orderType.toUpperCase() === "LIMIT" &&
  limitPrice !== undefined &&
  limitPrice !== null
) {
  params.price = Number(limitPrice);
}

const order = await snaptrade.trading.placeOrder(params);
res.json(order.data);
// --- END of Equity order block --- 

res.json(order.data);

    res.json(order.data);
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});


/* ----------------------- Trade: Symbol Lookup (New) ----------------------- */
app.get("/trade/symbol/:ticker", async (req, res) => {
  const ticker = req.params.ticker.toUpperCase();
  try {
    const snaptrade = mkClient();

    const allSymbols = await snaptrade.referenceData.getSymbols();
    const matches = (allSymbols.data || []).filter((s: any) =>
      s.symbol?.toUpperCase().includes(ticker) ||
      s.description?.toUpperCase().includes(ticker)
    );

    res.json(matches);
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
      pickNumber(balancesArr.find((b: any) => b?.buying_power != null) || {})
 ??
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
    equity: Math.max(0, totalValue - totalCash),
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


/* ---------------- Debug logging for SnapTrade webhook ---------------- */
app.use("/webhook/snaptrade", (req, res, next) => {
  console.log("📦 Incoming webhook headers:", req.headers);
  console.log("📦 Incoming webhook body:", req.body);
  next();
});

app.post(/^\/webhook\/snaptrade\/?$/, async (req, res) => {
  try {
    const event = req.body;

    console.log("📦 Incoming webhook:", event);

    // Respond immediately to SnapTrade to avoid retries
    res.status(200).send("ok");

    // Optional: handle real events with userId/userSecret asynchronously
 const userId = event.userId;
if (userId) {
  const userSecret = event.userSecret || getSecret(userId) || await fetchUserSecretFromDB(userId);
  if (userSecret) {
    // Wait for sync before saving
    let summary;
let tries = 0;
do {
  summary = await fetchAndSaveUserSummary(userId, userSecret);
  tries++;
  if (!summary.syncing) break;
  if (tries > 30) {
    console.warn("⚠️ Max tries reached while waiting for sync, saving anyway");
    break;
  }
  await new Promise(r => setTimeout(r, 2000));
} while (true);

await saveSnaptradeUser(userId, userSecret, summary);

    if (summary.accounts.length) {
      console.log(`✅ Webhook processed: saved summary for ${userId}`);
    } else {
      console.log(`⚠️ Webhook processed but accounts empty for ${userId}`);
    }
  }
}



  } catch (err: any) {
    console.error("❌ Webhook processing error:", err);
    res.status(500).send("error");
  }
});

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