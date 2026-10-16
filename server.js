"use strict";
/**
 * Okta Health Insights — backend
 * Zero dependencies (Node 20+). All secrets come from environment variables.
 *
 *  - Polls the Okta System Log + Apps APIs and keeps a rolling in-memory window
 *  - Serves the dashboard (public/index.html) and a small JSON API
 *  - Proxies the AI assistant to the Anthropic API (key never reaches the browser)
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const crypto = require("crypto");

/* ------------------------------------------------------------------ config */
const env = process.env;
const cfg = {
  port: +env.PORT || 8080,
  orgUrl: (env.OKTA_ORG_URL || "").replace(/\/+$/, ""),
  apiToken: env.OKTA_API_TOKEN || "",
  clientId: env.OKTA_CLIENT_ID || "",
  privateKey: (env.OKTA_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
  keyId: env.OKTA_KEY_ID || "",
  scopes: env.OKTA_SCOPES || "okta.logs.read okta.apps.read",
  logFilter: env.OKTA_LOG_FILTER || "",
  pollSec: Math.max(15, +env.POLL_INTERVAL_SECONDS || 60),
  lookbackDays: +env.LOOKBACK_DAYS || 7,
  maxEvents: +env.MAX_EVENTS || 100000,
  maxPagesPerPoll: +env.MAX_PAGES_PER_POLL || 50,
  appsRefreshMin: +env.APPS_REFRESH_MINUTES || 15,
  anthropicKey: env.ANTHROPIC_API_KEY || "",
  model: env.ANTHROPIC_MODEL || "claude-sonnet-5-5",
  anthropicUrl: (env.ANTHROPIC_BASE_URL || "https://api.anthropic.com").replace(/\/+$/, ""),
  dashUser: env.DASHBOARD_USER || "admin",
  dashPass: env.DASHBOARD_PASSWORD || ""
};

const log = (...a) => console.log(new Date().toISOString(), ...a);

/* ------------------------------------------------------------------- state */
const state = {
  events: [],            // ascending by published
  ids: new Set(),
  cursor: null,          // ISO timestamp of the newest event stored
  apps: [],              // [{id,label,status}]
  lastPoll: null, lastPollOk: null, lastError: null,
  lastAppsRefresh: null, catchingUp: true, polls: 0
};

/* -------------------------------------------------------------- okta auth */
let oauth = { token: null, exp: 0 };
const b64u = b => Buffer.from(b).toString("base64url");

async function authHeader() {
  if (cfg.apiToken) return "SSWS " + cfg.apiToken;
  if (!(cfg.clientId && cfg.privateKey)) throw new Error("No Okta credentials configured (set OKTA_API_TOKEN, or OKTA_CLIENT_ID + OKTA_PRIVATE_KEY)");
  if (oauth.token && Date.now() < oauth.exp - 60000) return "Bearer " + oauth.token;
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" }; if (cfg.keyId) header.kid = cfg.keyId;
  const claims = { iss: cfg.clientId, sub: cfg.clientId, aud: cfg.orgUrl + "/oauth2/v1/token", iat: now, exp: now + 300, jti: crypto.randomUUID() };
  const unsigned = b64u(JSON.stringify(header)) + "." + b64u(JSON.stringify(claims));
  const sig = crypto.sign("RSA-SHA256", Buffer.from(unsigned), cfg.privateKey).toString("base64url");
  const body = new URLSearchParams({
    grant_type: "client_credentials", scope: cfg.scopes,
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: unsigned + "." + sig
  });
  const r = await fetch(cfg.orgUrl + "/oauth2/v1/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error("Okta OAuth token request failed: " + r.status + " " + (j.error_description || j.error || ""));
  oauth = { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return "Bearer " + oauth.token;
}

async function oktaGet(url, attempt = 0) {
  const r = await fetch(url, { headers: { accept: "application/json", authorization: await authHeader() } });
  if (r.status === 429 && attempt < 4) {
    const reset = +r.headers.get("x-rate-limit-reset") * 1000;
    const wait = Math.min(60000, Math.max(1500, reset ? reset - Date.now() + 500 : 5000));
    log("Okta rate limit hit, waiting", Math.round(wait / 1000) + "s");
    await new Promise(res => setTimeout(res, wait));
    return oktaGet(url, attempt + 1);
  }
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`Okta ${r.status} for ${new URL(url).pathname}: ${t.slice(0, 200)}`);
  }
  const link = r.headers.get("link") || "";
  const m = /<([^>]+)>\s*;\s*rel="next"/i.exec(link);
  return { json: await r.json(), next: m ? m[1] : null };
}

/* ------------------------------------------------------------ data polling */
function slim(e) {
  return {
    id: e.uuid, published: e.published, eventType: e.eventType, displayMessage: e.displayMessage, severity: e.severity,
    ip: (e.client && e.client.ipAddress) || null, city: (e.client && e.client.geographicalContext && e.client.geographicalContext.city) || null,
    outcome: e.outcome ? { result: e.outcome.result, reason: e.outcome.reason || null } : null,
    actor: e.actor ? { type: e.actor.type, alternateId: e.actor.alternateId, displayName: e.actor.displayName } : null,
    target: (e.target || []).map(t => ({ type: t.type, id: t.id, alternateId: t.alternateId, displayName: t.displayName }))
  };
}

function trim() {
  const cutoff = Date.now() - cfg.lookbackDays * 864e5 - 864e5;
  let drop = 0;
  while (drop < state.events.length && (new Date(state.events[drop].published).getTime() < cutoff || state.events.length - drop > cfg.maxEvents)) drop++;
  if (drop) { for (const e of state.events.splice(0, drop)) state.ids.delete(e.id); }
}

let polling = false;
async function pollLogs() {
  if (polling) return; polling = true;
  state.lastPoll = new Date().toISOString();
  let hitCap = false;
  try {
    const since = state.cursor || new Date(Date.now() - cfg.lookbackDays * 864e5).toISOString();
    let url = `${cfg.orgUrl}/api/v1/logs?since=${encodeURIComponent(since)}&limit=1000&sortOrder=ASCENDING` +
      (cfg.logFilter ? `&filter=${encodeURIComponent(cfg.logFilter)}` : "");
    let pages = 0;
    while (url) {
      const { json, next } = await oktaGet(url); pages++;
      if (!json.length) break;                       // polling: stop on an empty page
      for (const raw of json) {
        const e = slim(raw);
        if (!e.id || state.ids.has(e.id)) continue;
        state.ids.add(e.id); state.events.push(e);
        if (!state.cursor || e.published > state.cursor) state.cursor = e.published;
      }
      if (pages >= cfg.maxPagesPerPoll) { hitCap = true; break; }
      url = next;
    }
    trim();
    state.lastPollOk = new Date().toISOString(); state.lastError = null; state.polls++;
    state.catchingUp = hitCap;
  } catch (err) {
    state.lastError = String(err.message || err); log("poll error:", state.lastError);
  } finally {
    polling = false;
    setTimeout(pollLogs, hitCap ? 1000 : cfg.pollSec * 1000);   // keep going quickly while backfilling
  }
}

async function refreshApps() {
  try {
    let url = `${cfg.orgUrl}/api/v1/apps?limit=200`, out = [], pages = 0;
    while (url && pages++ < 50) {
      const { json, next } = await oktaGet(url);
      for (const a of json) {
        const label = (a.label || "").trim();
        if (label) out.push({ id: a.id, label, status: a.status });
      }
      url = next;
    }
    state.apps = out; state.lastAppsRefresh = new Date().toISOString();
  } catch (err) { log("apps refresh error:", String(err.message || err)); }
}

/* --------------------------------------------------------------- assistant */
const SYSTEM = `You are an expert Okta administrator and identity engineer embedded in an Okta health dashboard. You help the admin troubleshoot using live Okta System Log data.
Be practical and specific: explain the likely root cause, then give ordered steps with exact Admin Console paths (e.g. Applications > Applications > [app] > Provisioning / Assignments; Directory > People; Reports > System Log; Security > Authentication Policies) and relevant System Log eventTypes or filter expressions.
Apply common knowledge: expired/revoked API tokens or OAuth grants in provisioning; license exhaustion in the target app; duplicate or mismatched attributes (email/username) in the target; group rules failing on missing profile attributes; attribute mapping and Okta Expression Language errors; rate limiting (429); sign-on policy denials; lockouts; import schedules; SCIM errors.
Use the query_events tool to look at real events before drawing conclusions about specific apps or users. Be honest when the data is insufficient and say what extra data would help. Never invent events. Keep answers concise; use short lists for steps.`;

const TOOLS = [{
  name: "query_events",
  description: "Search the live Okta System Log events held by the dashboard. Returns up to 15 most recent matches (time, result, eventType, app, user, reason) plus the total match count.",
  input_schema: {
    type: "object",
    properties: {
      app: { type: "string", description: "App display name (partial ok)" },
      user: { type: "string", description: "User login/email (partial ok)" },
      result: { type: "string", enum: ["FAILURE", "DENY", "ERROR", "SUCCESS", "ANY_FAILURE"] },
      eventType: { type: "string", description: "Substring of eventType, e.g. provision" },
      reasonContains: { type: "string" },
      limit: { type: "number" }
    }
  }
}];

const FAILS = new Set(["FAILURE", "DENY", "ERROR"]);
const APP_ACTORS = /^(PublicClientApp|OAuth2Client|OAuth2AppInstance|AppInstance)$/;
const appOf = e => {
  const t = (e.target || []).find(x => x.type === "AppInstance");
  if (t) return t.displayName || t.alternateId || t.id;
  const a = e.actor; return a && APP_ACTORS.test(a.type || "") ? (a.displayName || a.alternateId || null) : null;
};
const userOf = e => {
  const tg = e.target || [];
  const t = tg.find(x => x.type === "User") || tg.find(x => x.type === "AppUser");
  if (t) return t.alternateId || t.displayName;
  return e.actor && e.actor.type === "User" ? (e.actor.alternateId || e.actor.displayName) : null;
};

function queryEvents(i, windowMs) {
  i = i || {}; const lc = s => String(s || "").toLowerCase();
  const min = windowMs ? Date.now() - windowMs : 0;
  const hits = [];
  for (let k = state.events.length - 1; k >= 0; k--) {
    const e = state.events[k];
    if (new Date(e.published).getTime() < min) break;
    const res = e.outcome && e.outcome.result;
    if (i.app && !lc(appOf(e)).includes(lc(i.app))) continue;
    if (i.user && !lc(userOf(e)).includes(lc(i.user))) continue;
    if (i.eventType && !lc(e.eventType).includes(lc(i.eventType))) continue;
    if (i.reasonContains && !lc((e.outcome && e.outcome.reason) || e.displayMessage).includes(lc(i.reasonContains))) continue;
    if (i.result === "ANY_FAILURE") { if (!FAILS.has(res)) continue; } else if (i.result && res !== i.result) continue;
    hits.push(e);
  }
  const lim = Math.min(15, Math.max(1, +i.limit || 10));
  return { totalMatches: hits.length, events: hits.slice(0, lim).map(e => ({ time: e.published, result: e.outcome && e.outcome.result, eventType: e.eventType, app: appOf(e), user: userOf(e), reason: (e.outcome && e.outcome.reason) || null })) };
}

async function chat(body) {
  if (!cfg.anthropicKey) { const e = new Error("Assistant is not configured (ANTHROPIC_API_KEY is not set)."); e.status = 503; throw e; }
  const windowMs = +body.windowMs || 0;
  let msgs = (Array.isArray(body.messages) ? body.messages : []).slice(-12)
    .filter(m => m && (m.role === "user" || m.role === "assistant") && typeof m.content === "string")
    .map(m => ({ role: m.role, content: m.content.slice(0, 4000) }));
  while (msgs.length && msgs[0].role !== "user") msgs.shift();
  if (!msgs.length || msgs[msgs.length - 1].role !== "user") { const e = new Error("Last message must be from the user."); e.status = 400; throw e; }
  const system = SYSTEM + "\n\nCurrent dashboard summary (JSON):\n" + JSON.stringify(body.summary || {}).slice(0, 12000);
  for (let step = 0; step < 6; step++) {
    const r = await fetch(cfg.anthropicUrl + "/v1/messages", {
      method: "POST",
      headers: { "x-api-key": cfg.anthropicKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: cfg.model, max_tokens: 1500, system, tools: TOOLS, messages: msgs })
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error("Anthropic API error: " + (data.error && data.error.message || r.status)); e.status = 502; throw e; }
    if (data.stop_reason === "tool_use") {
      msgs.push({ role: "assistant", content: data.content });
      const results = data.content.filter(b => b.type === "tool_use").map(b => ({
        type: "tool_result", tool_use_id: b.id,
        content: JSON.stringify(b.name === "query_events" ? queryEvents(b.input, windowMs) : { error: "unknown tool" })
      }));
      msgs.push({ role: "user", content: results });
      continue;
    }
    return data.content.filter(b => b.type === "text").map(b => b.text).join("\n").trim() || "(no answer)";
  }
  return "I looked through the data but couldn't finish in a reasonable number of steps. Try a narrower question.";
}

/* ------------------------------------------------------------------- http */
const INDEX = path.join(__dirname, "public", "index.html");
const SEC_HEADERS = {
  "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "x-frame-options": "DENY",
  "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "cache-control": "no-store"
};

function send(req, res, status, body, type = "application/json; charset=utf-8") {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  const headers = { ...SEC_HEADERS, "content-type": type };
  if (/gzip/.test(req.headers["accept-encoding"] || "") && buf.length > 1024) {
    headers["content-encoding"] = "gzip"; res.writeHead(status, headers); return res.end(zlib.gzipSync(buf));
  }
  res.writeHead(status, headers); res.end(buf);
}

function authorized(req) {
  if (!cfg.dashPass) return true;
  const h = req.headers.authorization || "";
  if (!h.startsWith("Basic ")) return false;
  const [u, ...p] = Buffer.from(h.slice(6), "base64").toString().split(":");
  const a = Buffer.from(u + ":" + p.join(":")), b = Buffer.from(cfg.dashUser + ":" + cfg.dashPass);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const hits = []; // crude global rate limit for the assistant
function rateOk() { const now = Date.now(); while (hits.length && now - hits[0] > 60000) hits.shift(); if (hits.length >= 20) return false; hits.push(now); return true; }

function readBody(req, limit = 200000) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on("data", c => { n += c.length; if (n > limit) { reject(Object.assign(new Error("Body too large"), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch { reject(Object.assign(new Error("Invalid JSON"), { status: 400 })); } });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    if (url.pathname === "/healthz") return send(req, res, 200, { ok: true });
    if (!authorized(req)) { res.writeHead(401, { ...SEC_HEADERS, "www-authenticate": 'Basic realm="Okta Health Insights"' }); return res.end("Authentication required"); }

    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html"))
      return send(req, res, 200, fs.readFileSync(INDEX), "text/html; charset=utf-8");

    if (req.method === "GET" && url.pathname === "/api/status")
      return send(req, res, 200, {
        live: true, assistant: !!cfg.anthropicKey, serverTime: Date.now(), eventCount: state.events.length, appCount: state.apps.length,
        cursor: state.cursor, lastPollOk: state.lastPollOk, lastError: state.lastError, catchingUp: state.catchingUp, lookbackDays: cfg.lookbackDays
      });

    if (req.method === "GET" && url.pathname === "/api/events") {
      const since = +url.searchParams.get("since") || 0;
      let out = state.events;
      if (since) { let lo = 0, hi = out.length; while (lo < hi) { const m = (lo + hi) >> 1; if (new Date(out[m].published).getTime() < since) lo = m + 1; else hi = m; } out = out.slice(lo); }
      return send(req, res, 200, { serverTime: Date.now(), total: state.events.length, events: out });
    }

    if (req.method === "GET" && url.pathname === "/api/apps")
      return send(req, res, 200, { apps: state.apps.filter(a => a.status === "ACTIVE" || !a.status).map(a => a.label) });

    if (req.method === "POST" && url.pathname === "/api/chat") {
      if (!rateOk()) return send(req, res, 429, { error: "Too many assistant requests — try again in a minute." });
      const body = await readBody(req);
      return send(req, res, 200, { text: await chat(body) });
    }
    send(req, res, 404, { error: "Not found" });
  } catch (err) {
    log("request error:", err.message);
    send(req, res, err.status || 500, { error: err.status ? err.message : "Internal error" });
  }
});

/* ------------------------------------------------------------------- start */
function start() {
  if (!cfg.orgUrl) { console.error("OKTA_ORG_URL is required (e.g. https://yourco.okta.com)"); process.exit(1); }
  if (!cfg.apiToken && !(cfg.clientId && cfg.privateKey)) console.error("WARNING: no Okta credentials set; polling will fail until OKTA_API_TOKEN or OKTA_CLIENT_ID/OKTA_PRIVATE_KEY is provided.");
  if (!cfg.dashPass) log("NOTE: DASHBOARD_PASSWORD is not set — make sure access is restricted by your platform (SSO/VPN).");
  if (!cfg.anthropicKey) log("NOTE: ANTHROPIC_API_KEY is not set — the assistant will be disabled.");
  server.listen(cfg.port, () => log(`Okta Health Insights listening on :${cfg.port} for ${cfg.orgUrl}`));
  pollLogs(); refreshApps(); setInterval(refreshApps, cfg.appsRefreshMin * 60000);
}
if (require.main === module) start();
module.exports = { server, queryEvents, state };
