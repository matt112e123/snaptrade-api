"use strict";
const express = require("express");
const app = express();
app.use(express.json());
// log every request
app.use((req, _res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});
// ✅ webhook route
app.all("/webhook/snaptrade", (req, res) => {
    console.log("📩 Webhook hit:", req.method, req.path);
    console.log("📦 Body:", req.body);
    res.sendStatus(200);
});
// simple health check
app.get("/health", (_req, res) => res.type("text/plain").send("ok"));
// fallback 404
app.use((_req, res) => res.status(404).type("text/plain").send("Not found"));
const PORT = 5000;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Webhook test server on http://127.0.0.1:${PORT}`);
});
