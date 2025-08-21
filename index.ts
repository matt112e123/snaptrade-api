import "dotenv/config";
import express from "express";
import { Snaptrade } from "snaptrade-typescript-sdk";
import * as dns from "dns";
import os from "os";

const PORT = Number(process.env.PORT || 4000);
const HOST = process.env.HOST || "0.0.0.0";

const app = express();

// Parse JSON (needed for webhooks)
app.use(express.json());

// ---------- helpers ----------
function pickRedirectUrl(d: any): string | undefined {
  return (
    d?.redirectURI ??
    d?.redirectUri ??
    d?.loginRedirectURI ??
    d?.loginRedirectUri ??
    (typeof d === "string" ? d : undefined)
  );
}
function errPayload(err: any) {
  const status = err?.response?.status;
  const headers = err?.response?.headers;
  const data = err?.response?.data;
  const message = err?.message || String(err);
  console.error("UPSTREAM ERROR:", { status, data });
  return { status, headers, data, message };
}
function mkClient() {
  const clientId = process.env.SNAPTRADE_CLIENT_ID!;
  const consumerKey = process.env.SNAPTRADE_CONSUMER_KEY!;
  return new Snaptrade({ clientId, consumerKey }); // use SDK default basePath
}
function lanIPs(): string[] {
  const ips: string[] = [];
  Object.values(os.networkInterfaces()).forEach(list => {
    (list || []).forEach(n => {
      if (!n.internal && (n as any).family === "IPv4") ips.push((n as any).address);
    });
  });
  return ips;
}

// ---------- logs ----------
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ---------- diagnostics ----------
app.get("/", (_req, res) => res.type("text/plain").send("ok"));
app.get("/health", (_req, res) => res.type("text/plain").send("ok"));
app.get("/whoami", (_req, res) => {
  res.json({
    clientId: process.env.SNAPTRADE_CLIENT_ID ? "(set)" : "(missing)",
    hasConsumerKey: Boolean(process.env.SNAPTRADE_CONSUMER_KEY),
    SNAPTRADE_BASE_PATH: process.env.SNAPTRADE_BASE_PATH || "(unset)",
    now: new Date().toISOString(),
    lanIPs: lanIPs(),
  });
});
app.get("/dns", async (_req, res) => {
  const host = "api.snaptrade.com";
  const A = await new Promise<string[] | null>(r => dns.resolve4(host, (e, a) => r(e ? null : a ?? [])));
  const AAAA = await new Promise<string[] | null>(r => dns.resolve6(host, (e, a) => r(e ? null : a ?? [])));
  res.json({ host, A: A ?? [], AAAA: AAAA ?? [] });
});

// ---------- API heartbeat ----------
app.get("/status", async (_req, res) => {
  try {
    const snaptrade = mkClient();
    const status = await snaptrade.apiStatus.check();
    res.json(status.data);
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

// ---------- debug helpers ----------
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

// ---------- SnapTrade connect ----------
app.get("/connect", async (req, res) => {
  try {
    const snaptrade = mkClient();

    const fresh = (req.query.fresh as string) === "1";
    let userId = (req.query.userId as string) || process.env.SNAPTRADE_USER_ID;
    let userSecret = (req.query.userSecret as string) || process.env.SNAPTRADE_USER_SECRET;

    if (fresh || !userId || !userSecret) {
      userId = `dev-${Date.now()}`;
      const reg = await snaptrade.authentication.registerSnapTradeUser({ userId });
      userSecret = (reg?.data as any)?.userSecret;
      if (!userSecret) return res.status(500).json({ error: "register returned no userSecret", raw: reg?.data });
    } else {
      try {
        await snaptrade.authentication.registerSnapTradeUser({ userId });
      } catch (e: any) {
        const code = e?.response?.status;
        if (code !== 400 && code !== 409) throw e;
      }
    }

    const loginResp = await snaptrade.authentication.loginSnapTradeUser({ userId, userSecret });
    const url = pickRedirectUrl(loginResp?.data);
    if (!url) return res.status(502).json({ error: "No redirect URL", raw: loginResp?.data });

    res.json({ url, userId });
  } catch (err: any) {
    res.status(500).json(errPayload(err));
  }
});

// ---------- webhook (keep before 404) ----------
app.post("/webhook/snaptrade", (req, res) => {
  console.log("📩 Webhook hit:", req.method, req.path);
  console.log("📦 Body:", req.body);
  res.sendStatus(200);
});

// ---------- 404 last ----------
app.use((_req, res) => res.status(404).type("text/plain").send("Not found"));

// ---------- start ----------
app.listen(PORT, HOST, () => {
  const ips = lanIPs();
  console.log(`API running on http://${HOST}:${PORT}`);
  console.log(`Local:  http://127.0.0.1:${PORT}/health`);
  if (ips.length) console.log(`Phone:  http://${ips[0]}:${PORT}/health`);
});
