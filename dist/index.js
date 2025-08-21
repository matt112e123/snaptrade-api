"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const snaptrade_typescript_sdk_1 = require("snaptrade-typescript-sdk");
const dns = __importStar(require("dns"));
const os_1 = __importDefault(require("os"));
const PORT = Number(process.env.PORT || 4000);
const HOST = process.env.HOST || "0.0.0.0";
const app = (0, express_1.default)();
// Parse JSON (needed for webhooks)
app.use(express_1.default.json());
// ---------- helpers ----------
function pickRedirectUrl(d) {
    return (d?.redirectURI ??
        d?.redirectUri ??
        d?.loginRedirectURI ??
        d?.loginRedirectUri ??
        (typeof d === "string" ? d : undefined));
}
function errPayload(err) {
    const status = err?.response?.status;
    const headers = err?.response?.headers;
    const data = err?.response?.data;
    const message = err?.message || String(err);
    console.error("UPSTREAM ERROR:", { status, data });
    return { status, headers, data, message };
}
function mkClient() {
    const clientId = process.env.SNAPTRADE_CLIENT_ID;
    const consumerKey = process.env.SNAPTRADE_CONSUMER_KEY;
    return new snaptrade_typescript_sdk_1.Snaptrade({ clientId, consumerKey }); // use SDK default basePath
}
function lanIPs() {
    const ips = [];
    Object.values(os_1.default.networkInterfaces()).forEach(list => {
        (list || []).forEach(n => {
            if (!n.internal && n.family === "IPv4")
                ips.push(n.address);
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
    const A = await new Promise(r => dns.resolve4(host, (e, a) => r(e ? null : a ?? [])));
    const AAAA = await new Promise(r => dns.resolve6(host, (e, a) => r(e ? null : a ?? [])));
    res.json({ host, A: A ?? [], AAAA: AAAA ?? [] });
});
// ---------- API heartbeat ----------
app.get("/status", async (_req, res) => {
    try {
        const snaptrade = mkClient();
        const status = await snaptrade.apiStatus.check();
        res.json(status.data);
    }
    catch (err) {
        res.status(500).json(errPayload(err));
    }
});
// ---------- debug helpers ----------
app.get("/debug/listUsers", async (_req, res) => {
    try {
        const snaptrade = mkClient();
        const r = await snaptrade.authentication.listSnapTradeUsers();
        res.json(r.data);
    }
    catch (err) {
        res.status(500).json(errPayload(err));
    }
});
app.get("/debug/register", async (_req, res) => {
    try {
        const snaptrade = mkClient();
        const userId = `dev-${Date.now()}`;
        const reg = await snaptrade.authentication.registerSnapTradeUser({ userId });
        res.json({ userId, data: reg.data });
    }
    catch (err) {
        res.status(500).json(errPayload(err));
    }
});
// ---------- SnapTrade connect ----------
app.get("/connect", async (req, res) => {
    try {
        const snaptrade = mkClient();
        const fresh = req.query.fresh === "1";
        let userId = req.query.userId || process.env.SNAPTRADE_USER_ID;
        let userSecret = req.query.userSecret || process.env.SNAPTRADE_USER_SECRET;
        if (fresh || !userId || !userSecret) {
            userId = `dev-${Date.now()}`;
            const reg = await snaptrade.authentication.registerSnapTradeUser({ userId });
            userSecret = reg?.data?.userSecret;
            if (!userSecret)
                return res.status(500).json({ error: "register returned no userSecret", raw: reg?.data });
        }
        else {
            try {
                await snaptrade.authentication.registerSnapTradeUser({ userId });
            }
            catch (e) {
                const code = e?.response?.status;
                if (code !== 400 && code !== 409)
                    throw e;
            }
        }
        const loginResp = await snaptrade.authentication.loginSnapTradeUser({ userId, userSecret });
        const url = pickRedirectUrl(loginResp?.data);
        if (!url)
            return res.status(502).json({ error: "No redirect URL", raw: loginResp?.data });
        res.json({ url, userId });
    }
    catch (err) {
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
    if (ips.length)
        console.log(`Phone:  http://${ips[0]}:${PORT}/health`);
});
