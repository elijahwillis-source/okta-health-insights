"use strict";
/*
 * Google Workspace "OAuth token" audit log -> in-memory events (read only, zero dependencies).
 *
 * What it reads: the Admin SDK Reports API, applicationName=token. Events: authorize, request, revoke, deny and
 * (for some products) activity, each with the app name, client id and the OAuth scopes involved.
 *
 * How it signs in (the standard server-to-server way for Google Workspace):
 *   a service account + domain-wide delegation, limited to ONE read-only scope
 *   (https://www.googleapis.com/auth/admin.reports.audit.readonly), impersonating a dedicated admin whose role
 *   has only the Reports privilege. A signed JWT is exchanged for a one-hour access token; nothing is ever written.
 *
 * Settings (environment):
 *   GOOGLE_SA_KEY         the service account key (the JSON file's contents, or the same JSON base64-encoded)
 *   GOOGLE_ADMIN_EMAIL    the admin the service account acts as (needs only the Reports privilege)
 *   GOOGLE_POLL_SECONDS   how often to check (default 300; Google reports token events a couple of hours late)
 *   GOOGLE_LOOKBACK_DAYS  how much history to load first (default 30, at most 180: Google keeps 6 months)
 *   GOOGLE_RECHECK_HOURS  every check re-reads this many recent hours, because events arrive late (default 6)
 *   GOOGLE_API_BASE / GOOGLE_TOKEN_URL   only for tests
 */
const crypto = require("crypto");

const SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly";
const b64u = b => Buffer.from(b).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const DAY = 864e5, HOUR = 36e5;

function loadKey(raw) {
  let txt = String(raw || "").trim();
  if (!txt) return null;
  if (!txt.startsWith("{")) { try { txt = Buffer.from(txt, "base64").toString("utf8"); } catch { /* fall through */ } }
  let k; try { k = JSON.parse(txt); } catch { throw new Error("GOOGLE_SA_KEY is not valid JSON (paste the whole key file, or its base64)"); }
  if (!k.client_email || !k.private_key) throw new Error("GOOGLE_SA_KEY is missing client_email or private_key: is it a service account key file?");
  return { email: k.client_email, key: String(k.private_key).replace(/\\n/g, "\n"), tokenUri: k.token_uri || "https://oauth2.googleapis.com/token", clientId: k.client_id || "" };
}

// plain-English next steps for the errors people actually hit while setting this up
function hint(status, body) {
  const t = String(body || "");
  if (/unauthorized_client/i.test(t)) return "The service account is not allowed to use this scope. In the Admin console go to Security > Access and data control > API controls > Manage domain-wide delegation, and add the service account's Client ID with the scope " + SCOPE + ".";
  if (/invalid_grant/i.test(t)) return "Google refused to let the service account act as the admin. Check GOOGLE_ADMIN_EMAIL (it must be a real, active admin in your Workspace) and that domain-wide delegation is set up for this service account.";
  if (/invalid_scope|invalid_request/i.test(t)) return "Google did not accept the request. Check the key file is a service account key and that the scope is spelled exactly: " + SCOPE;
  if (/has not been used in project|accessNotConfigured|SERVICE_DISABLED/i.test(t)) return "The Admin SDK API is not enabled in the Google Cloud project. Enable it (APIs & Services > Library > Admin SDK API), then wait a minute.";
  if (status === 403) return "The admin the service account acts as is not allowed to read audit logs. Give that admin a role with the Reports privilege (Admin console > Account > Admin roles).";
  if (status === 401) return "Google rejected the access token. Check the clock on the server and that the key has not been deleted or disabled.";
  return "";
}

function createGoogle(env, log) {
  const cfg = {
    keyRaw: env.GOOGLE_SA_KEY || "", admin: (env.GOOGLE_ADMIN_EMAIL || "").trim(),
    pollSec: Math.max(5, +env.GOOGLE_POLL_SECONDS || 300), lookbackDays: Math.min(180, Math.max(1, +env.GOOGLE_LOOKBACK_DAYS || 30)),
    recheckHours: Math.max(1, +env.GOOGLE_RECHECK_HOURS || 6), apiBase: (env.GOOGLE_API_BASE || "https://admin.googleapis.com").replace(/\/+$/, ""),
    tokenUrl: env.GOOGLE_TOKEN_URL || "", maxEvents: +env.GOOGLE_MAX_EVENTS || 100000
  };
  const st = { events: [], ids: new Set(), token: "", tokenExp: 0, lastPollOk: null, lastError: "", lastHint: "", polls: 0, catchingUp: false, started: false };
  let key = null, keyError = "";
  try { key = loadKey(cfg.keyRaw); } catch (e) { keyError = e.message; }
  const configured = !!(cfg.keyRaw && cfg.admin);
  // exactly one of the two is set: say which, instead of silently staying off
  const partial = !cfg.keyRaw && cfg.admin ? "GOOGLE_ADMIN_EMAIL is set but GOOGLE_SA_KEY is missing (or empty)." : cfg.keyRaw && !cfg.admin ? "GOOGLE_SA_KEY is set but GOOGLE_ADMIN_EMAIL is missing (or empty)." : "";

  async function accessToken() {
    if (st.token && Date.now() < st.tokenExp - 120000) return st.token;
    const now = Math.floor(Date.now() / 1000), uri = cfg.tokenUrl || key.tokenUri;
    const head = b64u(JSON.stringify({ alg: "RS256", typ: "JWT" })), claims = b64u(JSON.stringify({ iss: key.email, sub: cfg.admin, scope: SCOPE, aud: uri, iat: now, exp: now + 3600 }));
    const sig = b64u(crypto.sign("RSA-SHA256", Buffer.from(head + "." + claims), key.key));
    const r = await fetch(uri, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: head + "." + claims + "." + sig }) });
    const text = await r.text(); let j = {}; try { j = JSON.parse(text); } catch { /* not json */ }
    if (!r.ok || !j.access_token) { const e = new Error("Google sign-in failed (" + r.status + "): " + ([j.error, j.error_description].filter(Boolean).join(" - ") || text.slice(0, 200))); e.hint = hint(r.status, text); throw e; }
    st.token = j.access_token; st.tokenExp = Date.now() + (+j.expires_in || 3600) * 1000; return st.token;
  }

  async function get(path, params, tries = 0) {
    const token = await accessToken();
    const r = await fetch(cfg.apiBase + path + "?" + new URLSearchParams(params), { headers: { authorization: "Bearer " + token } });
    if (r.status === 401 && tries < 1) { st.token = ""; return get(path, params, tries + 1); }
    if ((r.status === 429 || r.status >= 500) && tries < 3) { await new Promise(res => setTimeout(res, 1500 * (tries + 1))); return get(path, params, tries + 1); }
    const text = await r.text(); let j = {}; try { j = JSON.parse(text); } catch { /* not json */ }
    if (!r.ok) { const e = new Error("Google Reports API error (" + r.status + "): " + ((j.error && (j.error.message || j.error)) || text.slice(0, 200))); e.hint = hint(r.status, text); throw e; }
    return j;
  }

  const paramsOf = list => { const o = {}; for (const p of list || []) o[p.name] = p.multiValue !== undefined ? p.multiValue : p.value !== undefined ? p.value : p.intValue !== undefined ? +p.intValue : p.boolValue; return o; };
  function ingest(item) {
    const t = Date.parse(item && item.id && item.id.time); if (!isFinite(t)) return 0;
    const base = ((item.id && item.id.uniqueQualifier) || "") + "@" + t; let added = 0;
    (item.events || []).forEach((ev, i) => {
      const id = base + ":" + i; if (st.ids.has(id)) return;
      const P = paramsOf(ev.parameters); let scopes = P.scope;
      if (!scopes && Array.isArray(P.scope_data)) scopes = P.scope_data.map(x => x && x.scope_name).filter(Boolean);
      if (!Array.isArray(scopes)) scopes = scopes ? [String(scopes)] : [];
      st.ids.add(id); added++;
      st.events.push({ id, time: t, actor: (item.actor && item.actor.email) || "", ip: item.ipAddress || "", type: ev.name || "", app: String(P.app_name || ""), clientId: String(P.client_id || ""),
        scopes: scopes.map(String), rejection: String(P.rejection_type || ""), api: String(P.api_name || ""), method: String(P.method_name || "") });
    });
    return added;
  }
  async function fetchRange(fromMs, toMs) {
    let pageToken = "", pages = 0, added = 0;
    do {
      const p = { startTime: new Date(fromMs).toISOString(), endTime: new Date(toMs).toISOString(), maxResults: "1000" }; if (pageToken) p.pageToken = pageToken;
      const j = await get("/admin/reports/v1/activity/users/all/applications/token", p);
      for (const it of j.items || []) added += ingest(it);
      pageToken = j.nextPageToken || ""; pages++;
    } while (pageToken && pages < 200);
    return added;
  }
  function tidy() {
    st.events.sort((a, b) => a.time - b.time);
    const floor = Date.now() - (cfg.lookbackDays + 1) * DAY; let i = 0; while (i < st.events.length && st.events[i].time < floor) i++;
    if (i || st.events.length > cfg.maxEvents) { const cut = Math.max(i, st.events.length - cfg.maxEvents); for (const e of st.events.slice(0, cut)) st.ids.delete(e.id); st.events = st.events.slice(cut); }
  }
  async function poll() {
    const now = Date.now();
    if (!st.started) {                                    // first run: history in one-day slices, oldest first, so no slice can be cut off
      st.catchingUp = true;
      for (let t = now - cfg.lookbackDays * DAY; t < now; t += DAY) { await fetchRange(t, Math.min(now, t + DAY)); tidy(); }
      st.catchingUp = false; st.started = true;
    } else await fetchRange(now - cfg.recheckHours * HOUR, now);   // events are reported late, so re-read the last few hours; ids de-duplicate
    tidy(); st.lastPollOk = Date.now(); st.lastError = ""; st.lastHint = ""; st.polls++;
  }
  let timer = null;
  async function loop() {
    let delay = cfg.pollSec * 1000;
    try { await poll(); }
    catch (e) { st.lastError = e.message; st.lastHint = e.hint || ""; st.catchingUp = false; log("Google poll failed:", e.message); delay = Math.max(15000, Math.min(cfg.pollSec * 1000, 60000)); }
    timer = setTimeout(loop, delay); if (timer.unref) timer.unref();
  }
  return {
    configured, keyError,
    start() { if (!configured) return; if (keyError) { st.lastError = keyError; log("Google: " + keyError); return; } log("Google OAuth audit enabled for " + cfg.admin + " (reads the last " + cfg.lookbackDays + " days, then every " + cfg.pollSec + "s)"); loop(); },
    stop() { clearTimeout(timer); },
    status() {
      return { configured, admin: configured ? cfg.admin : "", lastPollOk: st.lastPollOk, lastError: partial || keyError || st.lastError, hint: partial ? "Google needs both settings. Add the missing one in your hosting dashboard (environment variables) and redeploy." : keyError ? "" : st.lastHint, events: st.events.length, catchingUp: st.catchingUp,
        lookbackDays: cfg.lookbackDays, oldest: st.events.length ? st.events[0].time : null, newest: st.events.length ? st.events[st.events.length - 1].time : null, scope: SCOPE };
    },
    events(since) { const s = +since || 0; return s ? st.events.filter(e => e.time > s) : st.events; },
    _state: st
  };
}
module.exports = { createGoogle, SCOPE, loadKey, hint };
