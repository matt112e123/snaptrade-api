
import "dotenv/config";
import express from "express";
import { Snaptrade } from "snaptrade-typescript-sdk";
import os from "os";
import cors from "cors";

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

function pickNumber(...candidates: any[]): number {
  for (const v of candidates) {
    if (typeof v === "number" && Number.isFinite(v)) return v;
    if (typeof v === "string" && v.trim() && !Number.isNaN(Number(v))) return Number(v);
    if (v && typeof v === "object") {
      for (const k of ["amount","value","price","market_value","marketValue","cash","buying_power","buyingPower","total"]) {
        const n = (v as any)[k];
        if (typeof n === "number" && Number.isFinite(n)) return n;
        if (typeof n === "string" && n.trim() && !Number.isNaN(Number(n))) return Number(n);
      }
    }
  }
  return 0;
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
const SECRET_TTL_MS = 10 * 60 * 1000; // 10 minutes

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

/* ------------------------- SnapTrade connect ---------------------- */
/**
 * NAVIGATE here from the browser (not fetch/XHR):
 *   /connect?fresh=1&web=1        # web callback
 *   /connect?fresh=1              # mobile deep link callback
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
    putSecret(userId, userSecret);

    const mobileRedirect = requireEnv("SNAPTRADE_REDIRECT_URI"); // apexmarkets://snaptrade-callback
    const webBase = process.env.SNAPTRADE_WEB_REDIRECT_URI || mobileRedirect; 
    const webURL = new URL(webBase);
    webURL.searchParams.set("userId", userId);

    const tryUrl = (v: unknown): string | "" => {
      if (typeof v !== "string" || !v.trim()) return "";
      try { return new URL(v).toString(); } catch { return ""; }
    };
    const custom = tryUrl(req.query.customRedirect) || tryUrl(req.query.redirect);
    const requested = custom || (req.query.web === "1" ? webURL.toString() : mobileRedirect);

    const loginResp = await snaptrade.authentication.loginSnapTradeUser({
      userId,
      userSecret,
      immediateRedirect: true,
      customRedirect: requested,
      connectionType: "read",
    });

    const data: any = loginResp?.data;
    const redirectURI =
      data?.redirectURI || data?.redirectUri ||
      data?.loginRedirectURI || data?.loginRedirectUri ||
      (typeof data === "string" ? data : undefined);

    if (!redirectURI) {
      return res.status(502).json({ error: "No redirect URL", raw: data });
    }

    // 🔑 Key part: decide format
    if (req.query.web === "1") {
      // Web → send redirect
      res.redirect(302, redirectURI);
    } else {
      // Mobile → return JSON like before
      res.json({
        redirectURI,
        url: redirectURI,
        userId,
        userSecret,
      });
    }

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
    if (!userId || !userSecret) return res.status(400).json({ linked: false, error: "Missing userId or userSecret" });

    const snaptrade = mkClient();
    let linked = false;

    try {
      const r = await snaptrade.connections.listBrokerageAuthorizations({ userId, userSecret });
      linked = (r.data?.length ?? 0) > 0;
    } catch {}
    if (!linked) {
      try {
        const r = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
        linked = (r.data?.length ?? 0) > 0;
      } catch {}
    }

    res.json({ linked });
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

/* ------------- Real-time: summary (balances + positions) ---------- */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

app.get("/realtime/summary", async (req, res) => {
  try {
    const userId = (req.query.userId ?? "").toString();
    const userSecret = (req.query.userSecret ?? getSecret(userId) ?? "").toString();

    if (!userId || !userSecret || userId === "null" || userSecret === "null") {
      return res.status(400).json({ error: "Missing userId or userSecret" });
    }

    const snaptrade = mkClient();
    const accountsResp = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
    const accounts: any[] = accountsResp.data || [];

    if (!accounts.length) {
      return res.json({ accounts: [], totals: { equity: 0, cash: 0, buyingPower: 0 }, positions: [], syncing: false });
    }

    let totalValue = 0, totalCash = 0, totalBP = 0;
    const outPositions: any[] = [];
    let syncing = false;

    for (const acct of accounts) {
      const accountId = acct.id || acct.accountId || acct.number || acct.guid || "";
      if (!accountId) continue;

      const h = await snaptrade.accountInformation.getUserHoldings({ userId, userSecret, accountId });

      const balObj: any = (h.data as any)?.balance || {};
      const balancesArr: any[] = (h.data as any)?.balances || [];

      const acctTotal = pickNumber(balObj?.total, balObj?.total?.amount);
      const acctCash =
        pickNumber(balObj?.cash, balObj?.cash?.amount) ||
        pickNumber(balancesArr.find((b: any) => b?.cash != null) || {});
      const acctBP =
        pickNumber(balObj?.buyingPower, balObj?.buying_power, balObj?.buying_power?.amount) ||
        pickNumber(balancesArr.find((b: any) => b?.buying_power != null) || {}) ||
        acctCash;

      totalValue += acctTotal;
      totalCash += acctCash;
      totalBP += acctBP;

      const posArr: any[] = findPositionsArray(h.data);
      for (const p of posArr) {
        const sym = extractDisplaySymbol(p);
        const symbolId =
          pickStringStrict(p?.symbol_id, p?.security_id, p?.instrument_id, p?.id, p?.symbol?.id, p?.universal_symbol?.id) || sym;

        const qty = pickNumber(p?.units, p?.quantity, p?.qty);
        const price = pickNumber(p?.price, p?.price?.value);
        const mv = pickNumber(p?.market_value, p?.marketValue);
        const value = mv || qty * (price || 0);

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

    res.json({
      accounts: accounts.map((a: any, i: number) => ({
        id: String(a.id ?? a.accountId ?? a.number ?? a.guid ?? `acct-${i}`),
        name: a.name || a.accountName || "Account",
        currency: a.currency || "USD",
        type: a.type || a.accountType || "BROKERAGE",
      })),
      totals: {
        equity: Math.max(0, totalValue - totalCash),
        cash: totalCash,
        buyingPower: totalBP,
      },
      positions: outPositions,
      syncing,
    });
  } catch (err: any) {
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
