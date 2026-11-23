"use strict";
/*
 * osctrl Device Health client (read only, zero dependencies).
 *
 * What it reads: osctrl's REST API (https://docs.osctrl.net/api/) as the dedicated read-only service account.
 * It never writes, carves or remediates anything — the account itself has no permission to.
 *
 * How it signs in: POST /api/v1/login with {username, password, exp_hours} returns a token. The token goes on
 * every later request in the Authorization header. osctrl's OpenAPI describes a plain API-key-style header, but
 * a "Bearer " prefix is also common for JWTs, so this client tries one, and if the API answers 401 it tries the
 * other before giving up — then remembers whichever worked so later calls do not have to probe again. A 401
 * after both have been tried is treated as an expired token: it signs in again once and retries.
 *
 * Settings (environment):
 *   OSCTRL_API_URL        e.g. https://osctrl-api.coolify.thoughtspot.com
 *   OSCTRL_API_USER       the read-only service account, e.g. ai-readonly
 *   OSCTRL_API_PASSWORD   its password
 *   OSCTRL_ENV            the osctrl environment name (default "corp")
 *   OSCTRL_QUERY_TIMEOUT_MS   how long to wait for a live (on-demand) query to come back (default 120000)
 *   OSCTRL_QUERY_POLL_MS      how often to check while waiting (default 3000)
 *
 * What this does NOT know for certain (the integration spec says so explicitly): the exact JSON field names
 * osctrl v0.7.0 returns for nodes and query results. Every reader below takes several plausible field names
 * and keeps going with whatever is actually there, instead of throwing, so a field-name mismatch degrades a
 * value to "unknown" rather than breaking the page. Fix the field list here once the live API has been seen.
 */
const DAY = 864e5;

// the osquery scheduled queries this depends on (see the integration spec, section 6) — add these in the
// osctrl UI (Environments > corp > Configuration > Schedule) or the matching part of the health score stays "unknown"
const SCHEDULED = {
  systemInfo: "macos_system_info", battery: "macos_battery", disk: "macos_root_disk",
  osVersion: "macos_os_version", uptime: "macos_uptime", apps: "macos_apps"
};

// the six read-only troubleshooting recipes Iris can run on demand (integration spec, section 5)
const RECIPES = {
  disk_full: { label: "Is the disk full?", sql: "SELECT * FROM mounts WHERE path = '/'" },
  slow: { label: "Why is it slow?", sql: "SELECT * FROM uptime; SELECT pid, name, resident_size FROM processes ORDER BY resident_size DESC LIMIT 10" },
  battery: { label: "Battery problems?", sql: "SELECT * FROM battery" },
  network: { label: "Network issues?", sql: "SELECT * FROM interface_addresses; SELECT * FROM routes; SELECT * FROM dns_resolvers" },
  crashing: { label: "Is it crashing?", sql: "SELECT * FROM crashes WHERE datetime > strftime('%s','now','-7 days')" },
  installed_apps: { label: "What's installed?", sql: "SELECT name, version, last_opened_at FROM apps" }
};

const firstOf = (o, ...keys) => { for (const k of keys) { const v = k.split(".").reduce((x, p) => (x && typeof x === "object" ? x[p] : undefined), o); if (v !== undefined && v !== null && v !== "") return v; } return null; };
const num = v => { const n = +v; return Number.isFinite(n) ? n : null; };
// osctrl/osquery timestamps show up as unix seconds, unix millis or ISO strings depending on the field; take whatever is thrown at us
function toMs(v) {
  if (v === null || v === undefined || v === "") return null;
  if (typeof v === "number") return v > 1e12 ? v : v > 1e9 ? v * 1000 : null;
  const s = String(v); if (/^\d+$/.test(s)) return toMs(+s);
  const t = Date.parse(s); return Number.isFinite(t) ? t : null;
}

function createOsctrl(env, log) {
  const cfg = {
    apiUrl: (env.OSCTRL_API_URL || "").replace(/\/+$/, ""), user: env.OSCTRL_API_USER || "", password: env.OSCTRL_API_PASSWORD || "",
    envName: (env.OSCTRL_ENV || "corp").trim(), queryTimeoutMs: Math.max(5000, +env.OSCTRL_QUERY_TIMEOUT_MS || 120000),
    queryPollMs: Math.max(500, +env.OSCTRL_QUERY_POLL_MS || 3000), resultsCacheMs: Math.max(1000, +env.OSCTRL_RESULTS_CACHE_MS || 60000)
  };
  const configured = !!(cfg.apiUrl && cfg.user && cfg.password);
  const st = { token: "", tokenExp: 0, authScheme: "raw", lastOk: null, lastError: "", loginFailures: 0 };
  const resultsCache = new Map();   // scheduled query name -> {at, rows}

  async function login() {
    const r = await fetch(cfg.apiUrl + "/api/v1/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: cfg.user, password: cfg.password, exp_hours: 24 })
    });
    const text = await r.text(); let j = {}; try { j = JSON.parse(text); } catch { /* not json */ }
    if (!r.ok || !j.token) { st.loginFailures++; throw new Error("osctrl sign-in failed (" + r.status + "): " + (j.error || j.message || text.slice(0, 200))); }
    st.token = j.token; st.tokenExp = Date.now() + 23 * 3600 * 1000; st.loginFailures = 0; return st.token;
  }
  async function ensureToken() { if (st.token && Date.now() < st.tokenExp) return st.token; return login(); }

  async function authedFetch(path, opts, tried) {
    tried = tried || { schemes: new Set(), relogins: 0 };
    const token = await ensureToken();
    const headerVal = st.authScheme === "bearer" ? "Bearer " + token : token;
    const r = await fetch(cfg.apiUrl + path, { ...opts, headers: { ...(opts && opts.headers), authorization: headerVal, "content-type": "application/json" } });
    if (r.status !== 401) { st.lastOk = Date.now(); st.lastError = ""; return r; }
    tried.schemes.add(st.authScheme);
    const other = st.authScheme === "bearer" ? "raw" : "bearer";
    if (!tried.schemes.has(other)) { st.authScheme = other; return authedFetch(path, opts, tried); }
    if (tried.relogins < 1) { st.token = ""; st.authScheme = "raw"; tried.relogins++; tried.schemes = new Set(); await login(); return authedFetch(path, opts, tried); }
    return r;   // still 401 after trying both header styles and a fresh sign-in: let the caller report it
  }

  async function okJson(path, opts) {
    const r = await authedFetch(path, opts);
    const text = await r.text(); let j; try { j = text ? JSON.parse(text) : {}; } catch { j = {}; }
    if (!r.ok) { const e = new Error("osctrl " + r.status + " for " + path + ": " + (j && (j.error || j.message) || text.slice(0, 200))); e.status = r.status; st.lastError = e.message; throw e; }
    return j;
  }
  const asList = j => Array.isArray(j) ? j : (j && (j.nodes || j.data || j.results || j.items)) || [];

  /* -------------------------------------------------------------- nodes */
  async function nodes(q) {
    const path = "/api/v1/nodes/" + encodeURIComponent(cfg.envName) + (q ? "?q=" + encodeURIComponent(q) : "");
    return asList(await okJson(path)).map(normalizeNode);
  }
  function normalizeNode(raw) {
    raw = raw || {};
    const si = raw.system_info || {};
    return {
      raw,
      uuid: firstOf(raw, "uuid", "node_key", "id"),
      hostname: firstOf(raw, "hostname", "localname", "host_identifier") || "",
      serial: firstOf(raw, "hardware_serial", "serial_number", "serial") || "",
      platform: firstOf(raw, "platform", "system_info.platform") || "",
      platformVersion: firstOf(raw, "platform_version", "os_version", "os_version.version") || "",
      model: firstOf(raw, "hardware_model", "system_info.hardware_model") || si.model || "",
      cpuBrand: firstOf(raw, "cpu_brand", "system_info.cpu_brand") || "",
      memoryBytes: num(firstOf(raw, "physical_memory", "system_info.physical_memory")),
      osqueryVersion: firstOf(raw, "osquery_version") || "",
      lastSeenMs: toMs(firstOf(raw, "last_seen", "last_status_log", "updated_at")),
      enrolledMs: toMs(firstOf(raw, "enrolled", "created_at", "raw_enrolled")),
      online: firstOf(raw, "online") !== null ? !!firstOf(raw, "online") : null
    };
  }
  function identify(n) { return n.uuid || n.hostname || n.serial; }
  function matchesNode(n, q) {
    const ql = String(q || "").toLowerCase(); if (!ql) return false;
    return [n.uuid, n.hostname, n.serial].some(v => String(v || "").toLowerCase() === ql);
  }
  // resolve one device by serial, hostname or node UUID — exact match first, then "contains"
  async function resolveDevice(q) {
    const query = String(q || "").trim(); if (query.length < 2) return { error: "Provide a device name, hostname or serial number (at least 2 characters)." };
    const all = await nodes(query);
    const exact = all.filter(n => matchesNode(n, query));
    const pool = exact.length ? exact : all;
    if (!pool.length) return { error: `No enrolled device matching "${query}" was found.` };
    if (pool.length > 1) return { error: "Several devices match that. Ask which one is meant (hostname or serial is unambiguous).", matches: pool.slice(0, 10).map(n => n.hostname || n.serial || n.uuid) };
    return { node: pool[0] };
  }

  /* ----------------------------------------------------- scheduled query results (the always-fresh panel) */
  async function resultsOf(queryName) {
    const hit = resultsCache.get(queryName);
    if (hit && Date.now() - hit.at < cfg.resultsCacheMs) return hit.rows;
    const path = "/api/v1/queries/" + encodeURIComponent(cfg.envName) + "/results/" + encodeURIComponent(queryName);
    let rows = [];
    try { rows = asList(await okJson(path)); } catch (e) { if (e.status !== 404) throw e; }   // 404: nobody has configured this scheduled query yet
    resultsCache.set(queryName, { at: Date.now(), rows });
    return rows;
  }
  function rowsForNode(rows, n) {
    const keys = [n.uuid, n.hostname, n.serial].filter(Boolean).map(String).map(s => s.toLowerCase());
    return rows.filter(r => { const rk = [firstOf(r, "uuid", "node_key", "host_identifier"), firstOf(r, "hostname", "localname"), firstOf(r, "hardware_serial", "serial_number")].filter(Boolean).map(String).map(s => s.toLowerCase()); return rk.some(k => keys.includes(k)); });
  }
  const colsOf = row => row && (row.columns || row.data || row);   // some osctrl versions nest the osquery row under "columns"

  /* ------------------------------------------------------------- health score */
  // Weights and bands from the integration spec. Two components (memory headroom, crash indicators) need
  // data this deployment has not scheduled a query for yet (see SCHEDULED above) — rather than guess, they
  // are reported "partial" and scored at full marks, so an unconfigured query can never drag the score down.
  function scoreDevice(n, data) {
    const parts = {}; let score = 0;

    const osRows = data.os || [], fleetNewest = data.fleetNewestVersion || null;
    if (osRows.length) {
      const v = firstOf(colsOf(osRows[0]) || {}, "version") || n.platformVersion;
      const minorsBehind = fleetNewest && v ? minorGap(v, fleetNewest) : 0;
      parts.osCurrency = { weight: 20, value: v || n.platformVersion || "unknown", minorsBehind, points: Math.max(0, 20 - minorsBehind * 7) };
    } else parts.osCurrency = { weight: 20, value: n.platformVersion || "unknown", partial: true, points: 20 };
    score += parts.osCurrency.points;

    const diskRows = data.disk || [];
    if (diskRows.length) {
      const c = colsOf(diskRows[0]) || {}, total = num(firstOf(c, "blocks")), size = num(firstOf(c, "blocks_size")) || 1;
      const avail = num(firstOf(c, "blocks_available", "blocks_free"));
      const pct = total && avail !== null ? Math.max(0, Math.min(100, (avail / total) * 100)) : null;
      parts.diskFree = pct === null ? { weight: 20, partial: true, points: 20 } : { weight: 20, freePct: Math.round(pct * 10) / 10, points: Math.round(Math.min(20, (pct / 20) * 20)) };
    } else parts.diskFree = { weight: 20, partial: true, points: 20 };
    score += parts.diskFree.points;

    const battRows = data.battery || [];
    if (battRows.length) {
      const c = colsOf(battRows[0]) || {}, health = String(firstOf(c, "health") || "").trim();
      const pts = /^good$/i.test(health) ? 15 : /^fair$/i.test(health) ? 9 : health ? 0 : 15;
      parts.battery = { weight: 15, health: health || "unknown", points: pts, note: health ? undefined : "no battery row (likely a desktop)" };
    } else parts.battery = { weight: 15, points: 15, note: "no battery row (likely a desktop, or the scheduled query has not reported yet)" };
    score += parts.battery.points;

    parts.memoryHeadroom = { weight: 15, partial: true, points: 15, note: "no live free-memory query is scheduled yet" };
    score += parts.memoryHeadroom.points;

    const upRows = data.uptime || [];
    if (upRows.length) {
      const c = colsOf(upRows[0]) || {}, secs = num(firstOf(c, "total_seconds")) || (num(firstOf(c, "days")) || 0) * 86400;
      const days = Math.floor((secs || 0) / 86400);
      parts.rebootFreshness = { weight: 10, uptimeDays: days, points: Math.max(0, Math.round(10 - Math.max(0, days - 14) * 0.5)) };
    } else parts.rebootFreshness = { weight: 10, partial: true, points: 10 };
    score += parts.rebootFreshness.points;

    parts.crashIndicators = { weight: 10, partial: true, points: 10, note: "no crash-history query is scheduled yet (the 'Is it crashing?' recipe still checks live)" };
    score += parts.crashIndicators.points;

    const ageMs = n.lastSeenMs ? Date.now() - n.lastSeenMs : null;
    const agentPts = ageMs === null ? 0 : ageMs < 20 * 60000 ? 10 : ageMs < 60 * 60000 ? 6 : 0;
    parts.agentHealth = { weight: 10, lastSeenMinutesAgo: ageMs === null ? null : Math.round(ageMs / 60000), points: agentPts };
    score += parts.agentHealth.points;

    score = Math.max(0, Math.min(100, Math.round(score)));
    const band = score >= 90 ? "healthy" : score >= 70 ? "monitor" : "action";
    return { score, band, parts };
  }
  // "within 1 minor version" read as: how many minor versions behind the newest version seen in this read of the fleet.
  // There is no external "latest macOS version" feed here, so "newest known" means the newest this read of the fleet saw.
  const versionRank = v => { const m = String(v || "").match(/(\d+)\.(\d+)/); return m ? +m[1] * 100 + +m[2] : -1; };
  function minorGap(v, newest) { const r = versionRank(newest) - versionRank(v); return Number.isFinite(r) ? Math.max(0, Math.min(6, r)) : 0; }
  function newestVersionOf(rows) { let best = null, bestRank = -1; for (const r of rows) { const v = firstOf(colsOf(r) || {}, "version"); const rk = versionRank(v); if (v && rk > bestRank) { best = v; bestRank = rk; } } return best; }

  async function deviceSummaries(q) {
    const list = await nodes(q);
    const osAll = await resultsOf(SCHEDULED.osVersion).catch(() => []);
    const fleetNewestVersion = newestVersionOf(osAll) || list.map(n => n.platformVersion).reduce((best, v) => (versionRank(v) > versionRank(best) ? v : best), null);
    return list.map(n => {
      const score = scoreDevice(n, { os: rowsForNode(osAll, n), disk: [], battery: [], uptime: [], fleetNewestVersion });
      return { uuid: n.uuid, hostname: n.hostname, serial: n.serial, platform: n.platform, platformVersion: n.platformVersion, lastSeen: n.lastSeenMs ? new Date(n.lastSeenMs).toISOString() : null, healthScore: score.score, healthBand: score.band };
    });
  }

  async function deviceDetail(q) {
    const r = await resolveDevice(q); if (r.error) return r;
    const n = r.node;
    const [osR, diskR, battR, upR, appsR] = await Promise.all([SCHEDULED.osVersion, SCHEDULED.disk, SCHEDULED.battery, SCHEDULED.uptime, SCHEDULED.apps].map(name => resultsOf(name).catch(() => [])));
    const mine = { os: rowsForNode(osR, n), disk: rowsForNode(diskR, n), battery: rowsForNode(battR, n), uptime: rowsForNode(upR, n), apps: rowsForNode(appsR, n) };
    const fleetNewestVersion = newestVersionOf(osR);
    const score = scoreDevice(n, { ...mine, fleetNewestVersion });
    const appRows = mine.apps.map(colsOf).filter(Boolean);
    return {
      identity: { hostname: n.hostname, serial: n.serial, uuid: n.uuid, platform: n.platform, model: n.model, cpuBrand: n.cpuBrand, memoryBytes: n.memoryBytes },
      os: { version: (mine.os[0] && firstOf(colsOf(mine.os[0]), "version")) || n.platformVersion || null, reportedAt: mine.os.length ? toMsOf(mine.os[0]) : null },
      agent: { osqueryVersion: n.osqueryVersion, lastSeen: n.lastSeenMs ? new Date(n.lastSeenMs).toISOString() : null, enrolled: n.enrolledMs ? new Date(n.enrolledMs).toISOString() : null },
      battery: mine.battery.length ? colsOf(mine.battery[0]) : null,
      storage: mine.disk.length ? colsOf(mine.disk[0]) : null,
      uptime: mine.uptime.length ? colsOf(mine.uptime[0]) : null,
      apps: { count: appRows.length, items: appRows.slice(0, 200).map(c => ({ name: firstOf(c, "name"), version: firstOf(c, "version"), lastOpened: (() => { const t = toMs(firstOf(c, "last_opened_at")); return t ? new Date(t).toISOString() : null; })() })) },
      health: score
    };
  }
  function toMsOf(row) { const c = colsOf(row) || {}; const t = toMs(firstOf(c, "hour", "unix_time", "calendar_time")); return t ? new Date(t).toISOString() : null; }

  /* --------------------------------------------------------- on-demand recipes */
  async function submitQuery(n, sql) {
    const body = { query: sql };
    if (n.uuid) body.uuids = [n.uuid];
    if (n.hostname) body.hostnames = [n.hostname];
    if (n.serial) body.hardware_serials = [n.serial];
    const j = await okJson("/api/v1/queries/" + encodeURIComponent(cfg.envName), { method: "POST", body: JSON.stringify(body) });
    return firstOf(j, "name", "query_name", "query", "id");
  }
  async function pollResults(name) {
    const deadline = Date.now() + cfg.queryTimeoutMs;
    for (;;) {
      const rows = asList(await okJson("/api/v1/queries/" + encodeURIComponent(cfg.envName) + "/results/" + encodeURIComponent(name)));
      if (rows.length) return { rows, timedOut: false };
      if (Date.now() >= deadline) return { rows: [], timedOut: true };
      await new Promise(res => setTimeout(res, cfg.queryPollMs));
    }
  }
  // run one of the six recipes against one device, returning the exact query used (for the assistant to cite) and what came back
  async function runRecipe(deviceQuery, recipeKey) {
    const recipe = RECIPES[recipeKey]; if (!recipe) return { error: "Unknown recipe: " + recipeKey };
    const r = await resolveDevice(deviceQuery); if (r.error) return r;
    const name = await submitQuery(r.node, recipe.sql);
    if (!name) return { error: "osctrl accepted the query but did not return a name to poll results with." };
    const { rows, timedOut } = await pollResults(name);
    return {
      device: r.node.hostname || r.node.serial || r.node.uuid, recipe: recipe.label, queryRun: recipe.sql,
      timedOut, note: timedOut ? "The device has not reported back within the wait time — it may be offline or asleep." : undefined,
      rowCount: rows.length, rows: rows.slice(0, 50).map(colsOf)
    };
  }

  return {
    configured, RECIPES,
    status() { return { configured, env: cfg.envName, lastOk: st.lastOk, lastError: st.lastError, loginFailures: st.loginFailures }; },
    nodes, resolveDevice, deviceSummaries, deviceDetail, runRecipe,
    _state: st, _scoreDevice: scoreDevice, _normalizeNode: normalizeNode
  };
}
module.exports = { createOsctrl, RECIPES, SCHEDULED };
