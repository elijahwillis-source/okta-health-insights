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
  maxPagesPerPoll: Math.max(2, +env.MAX_PAGES_PER_POLL || 50),
  headHours: +env.HEAD_HOURS || 6,                 // newest window loaded first, so the dashboard is current within minutes
  backfillChunkHours: +env.BACKFILL_CHUNK_HOURS || 12,   // older history is then filled in newest-chunk-first
  appsRefreshMin: +env.APPS_REFRESH_MINUTES || 15,
  lookupMaxPages: Math.max(1, +env.LOOKUP_MAX_PAGES || 10),       // per-user lookups: pages of 1000 events fetched per search term
  lookupMaxEvents: Math.max(100, +env.LOOKUP_MAX_EVENTS || 5000),  // ... and the most events returned to the page
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
  appSeen: new Map(),    // appId (or name) -> {id,name,last}; never trimmed with the event buffer
  lastPoll: null, lastPollOk: null, lastError: null,
  lastAppsRefresh: null, catchingUp: true, headCaughtUp: false, polls: 0
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
const clean = v => (typeof v === "string" ? v.trim() : v);

function slim(e) {
  return {
    id: e.uuid, published: e.published, eventType: e.eventType, displayMessage: e.displayMessage, severity: e.severity,
    ip: (e.client && e.client.ipAddress) || null, city: (e.client && e.client.geographicalContext && e.client.geographicalContext.city) || null,
    outcome: e.outcome ? { result: e.outcome.result, reason: e.outcome.reason || null } : null,
    actor: e.actor ? { id: e.actor.id, type: e.actor.type, alternateId: e.actor.alternateId, displayName: clean(e.actor.displayName) } : null,
    target: (e.target || []).map(t => ({ type: t.type, id: t.id, alternateId: t.alternateId, displayName: clean(t.displayName) }))
  };
}

function trim() {
  const cutoff = Date.now() - cfg.lookbackDays * 864e5 - 864e5;
  let drop = 0;
  while (drop < state.events.length && (new Date(state.events[drop].published).getTime() < cutoff || state.events.length - drop > cfg.maxEvents)) drop++;
  if (drop) { for (const e of state.events.splice(0, drop)) state.ids.delete(e.id); }
}

let polling = false;
const byPublished = (a, b) => (a.published < b.published ? -1 : a.published > b.published ? 1 : 0);

// Backfill state: history older than the "head" window, loaded newest chunk first.
const bf = { floor: null, until: null, active: null, done: false };

// Fetch one range of the System Log (ascending) and ingest it. `finished` means the range is exhausted.
async function fetchRange(sinceIso, untilIso) {
  let url = `${cfg.orgUrl}/api/v1/logs?since=${encodeURIComponent(sinceIso)}` + (untilIso ? `&until=${encodeURIComponent(untilIso)}` : "") +
    `&limit=1000&sortOrder=ASCENDING` + (cfg.logFilter ? `&filter=${encodeURIComponent(cfg.logFilter)}` : "");
  let pages = 0, last = null, finished = false, outOfOrder = false;
  while (url) {
    const { json, next } = await oktaGet(url); pages++;
    if (!json.length) { finished = true; break; }                // an empty page means we are caught up with this range
    for (const raw of json) {
      if (!last || raw.published > last) last = raw.published;   // resume point, even if every event was a duplicate
      const e = slim(raw);
      if (!e.id || state.ids.has(e.id)) continue;
      state.ids.add(e.id);
      const tail = state.events[state.events.length - 1];
      if (tail && e.published < tail.published) outOfOrder = true;
      state.events.push(e); noteApp(e);
    }
    if (pages >= cfg.maxPagesPerPoll) break;                      // yield; resume from `last` next cycle
    url = next;
    if (!url) finished = true;                                    // bounded ranges end without a next link
  }
  if (outOfOrder) state.events.sort(byPublished);                 // older backfill lands before newer events
  return { pages, last, finished };
}

async function pollHead() {
  const r = await fetchRange(state.cursor, null);
  if (r.last && r.last > state.cursor) state.cursor = r.last;
  state.headCaughtUp = r.finished;
}

async function stepBackfill() {
  if (bf.done) return;
  if (!bf.active) {
    const sinceMs = Math.max(Date.parse(bf.floor), Date.parse(bf.until) - cfg.backfillChunkHours * 36e5);
    const since = new Date(sinceMs).toISOString();
    bf.active = { since, until: bf.until, cursor: since };
  }
  const a = bf.active;
  const r = await fetchRange(a.cursor, a.until);
  if (r.last && r.last > a.cursor) a.cursor = r.last;
  if (r.finished) {                                               // chunk done: move the boundary back
    bf.until = a.since; bf.active = null;
    if (Date.parse(bf.until) <= Date.parse(bf.floor)) bf.done = true;
  }
}

function initIngest() {
  const now = Date.now();
  const headMs = Math.min(cfg.headHours, cfg.lookbackDays * 24) * 36e5;
  state.cursor = new Date(now - headMs).toISOString();
  bf.floor = new Date(now - cfg.lookbackDays * 864e5).toISOString();
  bf.until = state.cursor; bf.active = null;
  bf.done = Date.parse(bf.until) <= Date.parse(bf.floor);
}

function catchUpInfo() {
  const now = Date.now(), floor = Date.parse(bf.floor), until = bf.done ? floor : Date.parse(bf.until);
  const span = Math.max(1, now - floor);
  return {
    headCaughtUp: state.headCaughtUp, historyDone: bf.done,
    loadedBack: new Date(until).toISOString(), lookbackStart: bf.floor,
    pct: bf.done ? 100 : Math.max(0, Math.min(99, Math.floor(100 * (now - until) / span)))
  };
}

async function pollLogs() {
  if (polling) return; polling = true;
  state.lastPoll = new Date().toISOString();
  let again = false;
  try {
    await pollHead();                       // 1) stay current: the newest events first
    await stepBackfill();                   // 2) then fill in older history, newest chunk first
    trim();
    state.lastPollOk = new Date().toISOString(); state.lastError = null; state.polls++;
    state.catchingUp = !state.headCaughtUp || !bf.done;
    again = state.catchingUp;
  } catch (err) {
    state.lastError = String(err.message || err); log("poll error:", state.lastError);
  } finally {
    polling = false;
    setTimeout(pollLogs, again ? 1000 : cfg.pollSec * 1000);     // keep going quickly while catching up
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

/* ----------------------------------------------------------- per-user search */
// Ask Okta directly for everything that mentions a person, newest first. Independent of the loaded
// event buffer and of OKTA_LOG_FILTER, so it works right after a deploy and reaches back up to 90 days.
const cleanQ = v => String(v == null ? "" : v).replace(/\s+/g, " ").trim().split(" ").slice(0, 10).map(k => k.slice(0, 40)).join(" ");

async function userSearch(qs, days) {
  const since = new Date(Date.now() - days * 864e5).toISOString();
  const seen = new Set(), events = [];
  let truncated = false;
  for (const q of qs) {
    let url = `${cfg.orgUrl}/api/v1/logs?since=${encodeURIComponent(since)}&q=${encodeURIComponent(q)}&limit=1000&sortOrder=DESCENDING`;
    let pages = 0;
    while (url) {
      if (pages >= cfg.lookupMaxPages || events.length >= cfg.lookupMaxEvents) { truncated = true; break; }
      const { json, next } = await oktaGet(url); pages++;
      if (!json.length) break;
      for (const raw of json) {
        const e = slim(raw);
        if (!e.id || seen.has(e.id)) continue;
        seen.add(e.id); events.push(e);
      }
      url = next;
    }
  }
  events.sort((a, b) => (a.published < b.published ? 1 : a.published > b.published ? -1 : 0));   // newest first
  if (events.length > cfg.lookupMaxEvents) { events.length = cfg.lookupMaxEvents; truncated = true; }
  return { queries: qs, days, since, truncated, count: events.length, events };
}

const lookupCache = new Map();   // short cache so repeated clicks do not hammer Okta's rate limit
async function userSearchCached(qs, days) {
  const key = days + "|" + qs.join("|").toLowerCase(), hit = lookupCache.get(key);
  if (hit && Date.now() - hit.at < 60000) return hit.data;
  let data;
  try { data = await userSearch(qs, days); }
  catch (err) { const e = new Error("Okta lookup failed: " + String(err.message || err).slice(0, 200)); e.status = 502; throw e; }
  lookupCache.set(key, { at: Date.now(), data });
  if (lookupCache.size > 50) lookupCache.delete(lookupCache.keys().next().value);
  return data;
}

/* ------------------------------------------------------------- per-app errors */
const validAppId = id => typeof id === "string" && /^[A-Za-z0-9_-]{10,40}$/.test(id);
const byNewest = (a, b) => (a.published < b.published ? 1 : a.published > b.published ? -1 : 0);

// Ask Okta for the failures and denies that involve an app: as the target of a sign-in or provisioning
// event, or as the actor (OAuth clients). Newest first. If Okta rejects the combined filter we fetch
// everything for the app and keep the errors ourselves (serverFiltered: false).
async function appSearch(ids, days) {
  const since = new Date(Date.now() - days * 864e5).toISOString();
  const seen = new Set(), events = [];
  let truncated = false, serverFiltered = true;
  const run = async filter => {
    let url = `${cfg.orgUrl}/api/v1/logs?since=${encodeURIComponent(since)}&filter=${encodeURIComponent(filter)}&limit=1000&sortOrder=DESCENDING`, pages = 0;
    while (url) {
      if (pages >= cfg.lookupMaxPages || events.length >= cfg.lookupMaxEvents) { truncated = true; break; }
      const { json, next } = await oktaGet(url); pages++;
      if (!json.length) break;
      for (const raw of json) {
        const e = slim(raw);
        if (!e.id || seen.has(e.id) || !FAILS.has(e.outcome && e.outcome.result)) continue;
        seen.add(e.id); events.push(e);
      }
      url = next;
    }
  };
  const combos = [];
  for (const id of ids) for (const field of ["target.id", "actor.id"]) combos.push([field, id]);
  try {
    for (const [field, id] of combos) for (const res of ["FAILURE", "DENY"]) await run(`${field} eq "${id}" and outcome.result eq "${res}"`);
  } catch (err) {
    if (!/Okta 400/.test(String(err.message))) throw err;
    serverFiltered = false; events.length = 0; seen.clear(); truncated = false;
    for (const [field, id] of combos) await run(`${field} eq "${id}"`);
  }
  events.sort(byNewest);
  if (events.length > cfg.lookupMaxEvents) { events.length = cfg.lookupMaxEvents; truncated = true; }
  return { ids, days, since, serverFiltered, truncated, count: events.length, events };
}
async function appSearchCached(ids, days) {
  const key = "app|" + days + "|" + ids.join("|"), hit = lookupCache.get(key);
  if (hit && Date.now() - hit.at < 60000) return hit.data;
  let data;
  try { data = await appSearch(ids, days); }
  catch (err) { const e = new Error("Okta lookup failed: " + String(err.message || err).slice(0, 200)); e.status = 502; throw e; }
  lookupCache.set(key, { at: Date.now(), data });
  if (lookupCache.size > 50) lookupCache.delete(lookupCache.keys().next().value);
  return data;
}

// find apps by name (inventory first, then apps seen in events)
function resolveApps(name) {
  const q = String(name || "").trim().toLowerCase(); if (q.length < 2) return [];
  const cand = new Map();
  for (const a of state.apps) if (a.label && validAppId(a.id)) cand.set(a.id, a.label);
  for (const v of state.appSeen.values()) if (validAppId(v.id) && !cand.has(v.id)) cand.set(v.id, v.name);
  const all = [...cand];
  const exact = all.filter(([, l]) => l.toLowerCase() === q);
  return exact.length ? exact : all.filter(([, l]) => l.toLowerCase().includes(q));
}
// the assistant's version: one app's errors, summarised
async function assistantAppLookup(i) {
  i = i || {};
  const m = resolveApps(i.app);
  if (!m.length) return { error: `No app with a name like "${i.app}" was found.` };
  const names = [...new Set(m.map(x => x[1]))];
  if (names.length > 1) return { error: "Several apps match that name. Ask which one is meant.", matches: names.slice(0, 10) };
  const days = Math.min(90, Math.max(1, +i.days || 7));
  const r = await appSearchCached(m.map(x => x[0]).slice(0, 3), days);
  const tally = (arr, f) => { const mm = new Map(); for (const x of arr) { const k = f(x); if (k != null) mm.set(k, (mm.get(k) || 0) + 1); } return [...mm].sort((a, b) => b[1] - a[1]); };
  const reasons = tally(r.events, e => (e.outcome && e.outcome.reason) || e.displayMessage || "(no reason given)").slice(0, 8).map(([reason, count]) => ({
    reason, count, people: new Set(r.events.filter(e => ((e.outcome && e.outcome.reason) || e.displayMessage || "(no reason given)") === reason).flatMap(userRefs).map(u => u.toLowerCase().split("@")[0])).size }));
  return { app: names[0], searchedDays: days, errorsFound: r.count, truncatedByLimit: r.truncated, topReasons: reasons,
    topEventTypes: tally(r.events, e => e.eventType).slice(0, 5).map(([type, count]) => ({ type, count })),
    latest: r.events.slice(0, 10).map(e => ({ time: e.published, result: e.outcome && e.outcome.result, eventType: e.eventType, user: userRefs(e)[0] || null, reason: (e.outcome && e.outcome.reason) || null, ip: e.ip })) };
}

// the assistant's version: same search, trimmed to what it needs
async function assistantUserLookup(i) {
  i = i || {};
  const q = cleanQ(i.user); if (q.length < 2) return { error: "Provide a user email, username or name (at least 2 characters)." };
  const days = Math.min(90, Math.max(1, +i.days || 7));
  const qs = [q]; const lp = q.includes("@") ? cleanQ(q.split("@")[0]) : ""; if (lp.length >= 2 && lp.toLowerCase() !== q.toLowerCase()) qs.push(lp);
  const r = await userSearchCached(qs, days);
  const ql = q.toLowerCase(), local = ql.split("@")[0];
  let ev = r.events.filter(e => (e.actor && e.actor.type === "User" ? [e.actor] : []).concat((e.target || []).filter(t => t.type === "User" || t.type === "AppUser"))
    .some(x => (String(x.alternateId || "").toLowerCase().includes(ql)) || (q.includes("@") && String(x.alternateId || "").toLowerCase().split("@")[0] === local) || String(x.displayName || "").toLowerCase().includes(ql)));
  const totalFound = ev.length;
  if (i.errors_only) ev = ev.filter(e => FAILS.has(e.outcome && e.outcome.result));
  return { searchedDays: days, totalAboutThisPerson: totalFound, shown: Math.min(15, ev.length), truncatedByLimit: r.truncated,
    events: ev.slice(0, 15).map(e => ({ time: e.published, result: e.outcome && e.outcome.result, eventType: e.eventType, app: appOf(e), reason: (e.outcome && e.outcome.reason) || null, ip: e.ip })) };
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
}, {
  name: "lookup_app_errors",
  description: "Search Okta's System Log LIVE for the failures and denies of one APP over the last N days (default 7, max 90). Prefer this for questions about a specific app (why is Salesforce failing?). Returns the error count, top reasons with how many people each affects, and the 10 latest errors.",
  input_schema: {
    type: "object",
    properties: {
      app: { type: "string", description: "App name, e.g. Salesforce" },
      days: { type: "number", description: "How far back to search (1-90, default 7)" }
    },
    required: ["app"]
  }
}, {
  name: "lookup_user_events",
  description: "Search Okta's System Log LIVE for one person (email, username or name) over the last N days (default 7, max 90). Prefer this for any question about a specific user: it reaches events the dashboard has not loaded. Returns up to 15 most recent events about that person, newest first, plus how many were found.",
  input_schema: {
    type: "object",
    properties: {
      user: { type: "string", description: "Email, username or name" },
      days: { type: "number", description: "How far back to search (1-90, default 7)" },
      errors_only: { type: "boolean", description: "Only failures, denies and errors" }
    },
    required: ["user"]
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

// Remember the last time each app was seen. Keyed by app id so renames, stray whitespace and duplicate
// names cannot split one app in two, and kept apart from the capped event buffer so old-but-in-window
// activity is never forgotten when MAX_EVENTS trims the oldest events.
function noteApp(e) {
  let id = null, name = null;
  const t = (e.target || []).find(x => x.type === "AppInstance");
  if (t) { id = t.id; name = t.displayName || t.alternateId; }
  else if (e.actor && APP_ACTORS.test(e.actor.type || "")) { id = e.actor.id; name = e.actor.displayName || e.actor.alternateId; }
  if (!name) return;
  const key = id || ("name:" + name), ms = Date.parse(e.published);
  const cur = state.appSeen.get(key);
  if (!cur || ms > cur.last) state.appSeen.set(key, { id: id || null, name, last: ms });
}

// every login an event mentions about a person (the actor, plus User / AppUser targets)
function userRefs(e) {
  const out = [], a = e.actor;
  if (a && a.type === "User" && a.alternateId) out.push(a.alternateId);
  for (const t of (e.target || [])) if ((t.type === "User" || t.type === "AppUser") && t.alternateId) out.push(t.alternateId);
  return out;
}

function queryEvents(i, windowMs) {
  i = i || {}; const lc = s => String(s || "").toLowerCase();
  const min = windowMs ? Date.now() - windowMs : 0;
  const hits = [];
  for (let k = state.events.length - 1; k >= 0; k--) {
    const e = state.events[k];
    if (new Date(e.published).getTime() < min) break;
    const res = e.outcome && e.outcome.result;
    if (i.app && !lc(appOf(e)).includes(lc(i.app))) continue;
    if (i.user && !userRefs(e).some(u => lc(u).includes(lc(i.user)))) continue;
    if (i.eventType && !lc(e.eventType).includes(lc(i.eventType))) continue;
    if (i.reasonContains && !lc((e.outcome && e.outcome.reason) || e.displayMessage).includes(lc(i.reasonContains))) continue;
    if (i.result === "ANY_FAILURE") { if (!FAILS.has(res)) continue; } else if (i.result && res !== i.result) continue;
    hits.push(e);
  }
  const lim = Math.min(15, Math.max(1, +i.limit || 10));
  return { totalMatches: hits.length, events: hits.slice(0, lim).map(e => ({ time: e.published, result: e.outcome && e.outcome.result, eventType: e.eventType, app: appOf(e), user: userOf(e), reason: (e.outcome && e.outcome.reason) || null })) };
}

/* --------------------------------------------------------- explain one error */
// "What does this error mean and how do I fix it?" for a single error message. A focused prompt with no tools,
// cached by error text, so the same error (for example the same provisioning failure for ten people) is
// explained once.
const explainCache = new Map();
const EXPLAIN_SYSTEM = `You are an expert Okta administrator explaining ONE error from Okta's System Log (usually a provisioning, assignment or sign-in error) to an IT admin.
Answer in exactly this shape, in plain words, under 180 words, with no preamble and no questions:
**What it means**: one or two sentences.
**Likely causes**: up to three short bullets starting with "- ".
**How to fix**: numbered steps. Use real Okta Admin Console paths where they apply (for example Applications > Applications > [app] > Provisioning > To App, Directory > People > [person] > Applications, Reports > System Log) and name what to check in the target app.
**How to confirm**: one line, for example which System Log event should now show SUCCESS.
Be honest about what you cannot know from the message alone: say what to check instead of guessing. Placeholders like <id> stand for ids that were removed.`;
const cleanStr = (v, n) => String(v == null ? "" : v).replace(/\s+/g, " ").trim().slice(0, n);

async function explainError(body) {
  if (!cfg.anthropicKey) { const e = new Error("Assistant is not configured (ANTHROPIC_API_KEY is not set)."); e.status = 503; throw e; }
  body = body || {};
  const reason = cleanStr(body.reason, 800);
  if (reason.length < 3) { const e = new Error("Provide the error text as 'reason'."); e.status = 400; throw e; }
  const list = (v, n, m) => (Array.isArray(v) ? v : []).slice(0, n).map(x => cleanStr(x, m)).filter(Boolean);
  const apps = list(body.apps, 3, 80), types = list(body.eventTypes, 3, 120);
  const count = Math.max(0, Math.floor(+body.count) || 0), people = Math.max(0, Math.floor(+body.people) || 0);
  const key = [reason.toLowerCase(), apps.join("|").toLowerCase(), types.join("|").toLowerCase()].join("##");
  const hit = explainCache.get(key);
  if (hit && Date.now() - hit.at < 24 * 36e5) return { text: hit.text, cached: true };
  const content = `Error text: "${reason}"\n` + (apps.length ? `App: ${apps.join(", ")}\n` : "") + (types.length ? `System Log event type: ${types.join(", ")}\n` : "") +
    (count ? `Seen ${count} time${count === 1 ? "" : "s"}${people ? `, affecting ${people} ${people === 1 ? "person" : "people"}` : ""}, recently.\n` : "") + "Explain this error and how to fix it.";
  const r = await fetch(cfg.anthropicUrl + "/v1/messages", {
    method: "POST",
    headers: { "x-api-key": cfg.anthropicKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({ model: cfg.model, max_tokens: 700, system: EXPLAIN_SYSTEM, messages: [{ role: "user", content }] })
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error("Anthropic API error: " + (data.error && data.error.message || r.status)); e.status = 502; throw e; }
  const text = (data.content || []).filter(b => b.type === "text").map(b => b.text).join("\n").trim();
  if (!text) { const e = new Error("The assistant returned no explanation. Try again."); e.status = 502; throw e; }
  explainCache.set(key, { at: Date.now(), text });
  if (explainCache.size > 300) explainCache.delete(explainCache.keys().next().value);
  return { text, cached: false };
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
  let nudged = false;
  for (let step = 0; step < 7; step++) {
    const r = await fetch(cfg.anthropicUrl + "/v1/messages", {
      method: "POST",
      headers: { "x-api-key": cfg.anthropicKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: cfg.model, max_tokens: 2000, system, tools: TOOLS, messages: msgs })
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error("Anthropic API error: " + (data.error && data.error.message || r.status)); e.status = 502; throw e; }
    if (data.stop_reason === "tool_use") {
      msgs.push({ role: "assistant", content: data.content });
      const results = [];
      for (const b of data.content.filter(b => b.type === "tool_use")) {
        let out;
        try {
          out = b.name === "query_events" ? queryEvents(b.input, windowMs)
              : b.name === "lookup_user_events" ? await assistantUserLookup(b.input)
              : b.name === "lookup_app_errors" ? await assistantAppLookup(b.input)
              : { error: "unknown tool" };
        } catch (err) { out = { error: String(err.message || err).slice(0, 200) }; }
        results.push({ type: "tool_result", tool_use_id: b.id, content: JSON.stringify(out) });
      }
      msgs.push({ role: "user", content: results });
      continue;
    }
    const text = (data.content || []).filter(b => b.type === "text").map(b => b.text).join("\n").trim();
    if (data.stop_reason === "pause_turn") { msgs.push({ role: "assistant", content: data.content }); continue; }
    if (text) return text + (data.stop_reason === "max_tokens" ? "\n\n(The answer was cut off. Ask me to continue.)" : "");
    // an empty final turn: log why, then ask once for a plain-text answer instead of showing a blank
    log("assistant returned no text; stop_reason=" + data.stop_reason + " blocks=" + (data.content || []).map(b => b.type).join(",") + " step=" + step);
    if (!nudged) {
      nudged = true;
      const keep = (data.content || []).filter(b => b.type === "text");      // never replay an unanswered tool_use
      msgs.push({ role: "assistant", content: keep.length ? keep : [{ type: "text", text: "(no reply yet)" }] });
      msgs.push({ role: "user", content: "Please answer now in plain text, based on what you found. If you found nothing, say so plainly." });
      continue;
    }
    return "The assistant returned an empty reply (stop reason: " + data.stop_reason + "). Try rephrasing, or ask about one app or user at a time.";
  }
  return "I looked through the data but couldn't finish in a reasonable number of steps. Try a narrower question.";
}

/* ------------------------------------------------------------- diagnostics */
function diagnostics() {
  const nrm = s => String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const active = state.apps.filter(a => a.status === "ACTIVE" || !a.status);
  const seen = [...state.appSeen.values()];
  const seenIds = new Set(seen.map(s => s.id).filter(Boolean));
  const seenByName = new Map(seen.map(s => [nrm(s.name), s]));
  const invIds = new Set(active.map(a => a.id));
  const noEvents = active.filter(a => !seenIds.has(a.id));
  const first = state.events[0], last = state.events[state.events.length - 1];
  return {
    poll: { cursor: state.cursor, catchingUp: state.catchingUp, catchUp: catchUpInfo(), lastPollOk: state.lastPollOk, lastError: state.lastError, lastAppsRefresh: state.lastAppsRefresh },
    events: { held: state.events.length, cap: cfg.maxEvents, oldest: first && first.published, newest: last && last.published, lookbackDays: cfg.lookbackDays },
    inventory: {
      activeApps: active.length, withEvents: active.length - noEvents.length, withoutEvents: noEvents.length,
      // same name seen under a different id means a duplicate/renamed app, not a quiet one
      withoutEventsSample: noEvents.slice(0, 40).map(a => ({ id: a.id, label: a.label, sameNameSeenUnderOtherId: seenByName.has(nrm(a.label)) }))
    },
    eventAppsNotInInventory: seen.filter(s => !s.id || !invIds.has(s.id)).slice(0, 25).map(s => ({ id: s.id, name: s.name, last: new Date(s.last).toISOString() }))
  };
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

const lookupHits = [];
function lookupRateOk() { const now = Date.now(); while (lookupHits.length && now - lookupHits[0] > 60000) lookupHits.shift(); if (lookupHits.length >= 30) return false; lookupHits.push(now); return true; }
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
        cursor: state.cursor, lastPollOk: state.lastPollOk, lastError: state.lastError, catchingUp: state.catchingUp, lookbackDays: cfg.lookbackDays,
        catchUp: catchUpInfo(), lookup: true, appLookup: true
      });

    if (req.method === "GET" && url.pathname === "/api/events") {
      const since = +url.searchParams.get("since") || 0;
      let out = state.events;
      if (since) { let lo = 0, hi = out.length; while (lo < hi) { const m = (lo + hi) >> 1; if (new Date(out[m].published).getTime() < since) lo = m + 1; else hi = m; } out = out.slice(lo); }
      return send(req, res, 200, { serverTime: Date.now(), total: state.events.length, events: out });
    }

    if (req.method === "GET" && url.pathname === "/api/apps")
    {
      const active = state.apps.filter(a => a.status === "ACTIVE" || !a.status);
      return send(req, res, 200, { apps: active.map(a => a.label), items: active.map(a => ({ id: a.id, label: a.label })), seen: [...state.appSeen.values()] });
    }

    if (req.method === "GET" && url.pathname === "/api/diagnostics") return send(req, res, 200, diagnostics());

    if (req.method === "GET" && url.pathname === "/api/user-events") {
      if (!lookupRateOk()) return send(req, res, 429, { error: "Too many lookups — try again in a minute." });
      const qs = [...new Set(url.searchParams.getAll("q").map(cleanQ).filter(q => q.length >= 2))].slice(0, 3);
      if (!qs.length) return send(req, res, 400, { error: "Provide ?q=<email, username or name> (at least 2 characters)." });
      const days = Math.min(90, Math.max(1, Math.floor(+url.searchParams.get("days")) || 7));
      return send(req, res, 200, await userSearchCached(qs, days));
    }

    if (req.method === "GET" && url.pathname === "/api/app-events") {
      if (!lookupRateOk()) return send(req, res, 429, { error: "Too many lookups — try again in a minute." });
      const ids = [...new Set(url.searchParams.getAll("id").filter(validAppId))].slice(0, 3);
      if (!ids.length) return send(req, res, 400, { error: "Provide ?id=<app id> (one to three)." });
      const days = Math.min(90, Math.max(1, Math.floor(+url.searchParams.get("days")) || 7));
      return send(req, res, 200, await appSearchCached(ids, days));
    }

    if (req.method === "POST" && url.pathname === "/api/explain-error") {
      if (!rateOk()) return send(req, res, 429, { error: "Too many assistant requests — try again in a minute." });
      return send(req, res, 200, await explainError(await readBody(req)));
    }

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
  initIngest(); pollLogs(); refreshApps(); setInterval(refreshApps, cfg.appsRefreshMin * 60000);
}
if (require.main === module) start();
module.exports = { server, queryEvents, state };
