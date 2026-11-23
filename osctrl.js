"use strict";
/*
 * osctrl Device Health client (read only, zero dependencies).
 *
 * What it reads: osctrl's REST API (https://docs.osctrl.net/api/) as the dedicated read-only service account.
 * It never writes, carves or remediates anything — the account itself has no permission to.
 *
 * How it signs in: POST /api/v1/login with {username, password, exp_hours} returns a token. The token goes on
 * every later request in the Authorization header. osctrl v0.7.0 requires the "Bearer " prefix (verified against
 * the live API: Bearer gets 200, the raw no-prefix form gets a 302), so that is the default, but this client
 * still falls back to the other form on a 401 or 403 before giving up — then remembers whichever worked so later
 * calls do not have to probe again. A 401/403 after both have been tried is treated as an expired token: it
 * signs in again once and retries.
 *
 * osctrl allows only ONE live token per user (verified in osctrl v0.7.x's cmd/api/handlers/login.go
 * issueSession: a new login overwrites the stored token, so anyone else signing in as this same service
 * account instantly evicts ours). An evicted token does not even get a 401/403: the API answers with a
 * redirect to /forbidden, which fetch follows into a 200 HTML page, so it looks like an empty success unless
 * okJson also treats "200 but not real JSON" (or landing on /forbidden) as an auth failure. login() is
 * single-flight (one in-flight promise, shared) so that several calls racing into an evicted token do not each
 * mint a fresh login and evict each other in turn.
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
  installed_apps: { label: "What's installed?", sql: "SELECT name, bundle_short_version AS version, last_opened_time FROM apps" }
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
  const st = { token: "", tokenExp: 0, authScheme: "bearer", lastOk: null, lastError: "", loginFailures: 0 };
  const resultsCache = new Map();   // "queryName|uuid" -> {at, rows}

  let loginInFlight = null;   // shared by every caller racing into a missing/evicted token, so only one POST /login ever happens at a time
  async function login() {
    if (loginInFlight) return loginInFlight;
    loginInFlight = (async () => {
      const r = await fetch(cfg.apiUrl + "/api/v1/login", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: cfg.user, password: cfg.password, exp_hours: 24 })
      });
      const text = await r.text(); let j = {}; try { j = JSON.parse(text); } catch { /* not json */ }
      if (!r.ok || !j.token) { st.loginFailures++; throw new Error("osctrl sign-in failed (" + r.status + "): " + (j.error || j.message || text.slice(0, 200))); }
      st.token = j.token; st.tokenExp = Date.now() + 23 * 3600 * 1000; st.loginFailures = 0; return st.token;
    })();
    try { return await loginInFlight; } finally { loginInFlight = null; }
  }
  async function ensureToken() { if (st.token && Date.now() < st.tokenExp) return st.token; return login(); }

  async function authedFetch(path, opts, tried) {
    tried = tried || {}; tried.schemes = tried.schemes || new Set(); tried.relogins = tried.relogins || 0;
    const token = await ensureToken();
    tried.usedToken = token;   // so a caller that sees this response can tell whether someone else has already refreshed the token by the time it looks
    const headerVal = st.authScheme === "bearer" ? "Bearer " + token : token;
    const r = await fetch(cfg.apiUrl + path, { ...opts, headers: { ...(opts && opts.headers), authorization: headerVal, "content-type": "application/json" } });
    if (r.status !== 401 && r.status !== 403) { st.lastOk = Date.now(); st.lastError = ""; return r; }
    tried.schemes.add(st.authScheme);
    const other = st.authScheme === "bearer" ? "raw" : "bearer";
    if (!tried.schemes.has(other)) { st.authScheme = other; return authedFetch(path, opts, tried); }
    if (tried.relogins < 1) { st.token = ""; st.authScheme = "bearer"; tried.relogins++; tried.schemes = new Set(); await login(); return authedFetch(path, opts, tried); }
    return r;   // still rejected after trying both header styles and a fresh sign-in: let the caller report it
  }

  async function okJson(path, opts, retriedEviction) {
    const tried = {};
    const r = await authedFetch(path, opts, tried);
    const text = await r.text(); let j, parseFailed = false; try { j = text ? JSON.parse(text) : {}; } catch { j = {}; parseFailed = true; }
    // one live token per user: a login elsewhere evicts ours, and osctrl answers with a redirect to /forbidden
    // rather than a 401/403 — fetch follows it into a 200 HTML page, which looks like an empty success unless
    // we also treat "200 but not real JSON" (or landing on /forbidden) as the auth failure it actually is.
    const evicted = r.ok && (parseFailed || /\/forbidden$/.test(r.url.split(/[?#]/)[0]));
    if (evicted) {
      if (retriedEviction) { const e = new Error("osctrl session for " + path + " was replaced by another login (one active token per user) and signing in again did not fix it"); e.status = 401; st.lastError = e.message; throw e; }
      // Only clear the token if it is still the one that got evicted: another call racing in may already have
      // refreshed it, and blindly logging in again here would evict THAT fresh token and start a thrash. Either
      // way the retry below goes through ensureToken()/login(), which already caches a fresh token and shares
      // one in-flight sign-in, so it does the right thing whether or not we clear it ourselves.
      if (st.token === tried.usedToken) st.token = "";
      return okJson(path, opts, true);
    }
    if (!r.ok) { const e = new Error("osctrl " + r.status + " for " + path + ": " + (j && (j.error || j.message) || text.slice(0, 200))); e.status = r.status; st.lastError = e.message; throw e; }
    return j;
  }
  const asList = j => Array.isArray(j) ? j : (j && (j.nodes || j.data || j.results || j.items)) || [];

  /* -------------------------------------------------------------- nodes */
  async function nodes(q) {
    const path = "/api/v1/nodes/" + encodeURIComponent(cfg.envName) + (q ? "?q=" + encodeURIComponent(q) : "");
    return asList(await okJson(path)).map(normalizeNode);
  }
  // The whole fleet, walking pages if the API hands them out (verified live: GET /api/v1/nodes/<env>?q=
  // searches only hostname/localname/uuid/ip, never hardware_serial, so this is also the fallback resolveDevice
  // needs for a serial lookup). Tries the common offset/limit paging convention; if the API ignores it and just
  // returns everything every time (or there is only one page to begin with), the dedupe-by-identity check below
  // stops after that first request instead of looping.
  async function allNodes() {
    const seen = new Map(); const limit = 500;
    for (let offset = 0, page = 0; page < 50; page++, offset += limit) {
      const path = "/api/v1/nodes/" + encodeURIComponent(cfg.envName) + "?limit=" + limit + "&offset=" + offset;
      const batch = asList(await okJson(path)).map(normalizeNode);
      if (!batch.length) break;
      const before = seen.size;
      for (const n of batch) seen.set(identify(n) || JSON.stringify(n.raw), n);
      if (seen.size === before || batch.length < limit) break;   // nothing new (API ignored paging) or that was the last page
    }
    return [...seen.values()];
  }
  // Field mapping verified against osctrl v0.7.x's own frontend source (frontend/src/api/nodes.ts, types.ts)
  // and the live API: memory and cpu are top-level, model lives under system_info.system, not system_info.
  function normalizeNode(raw) {
    raw = raw || {};
    return {
      raw,
      uuid: firstOf(raw, "uuid", "node_key", "id"),
      hostname: firstOf(raw, "hostname", "localname", "host_identifier") || "",
      serial: firstOf(raw, "hardware_serial", "serial_number", "serial") || "",
      platform: firstOf(raw, "platform", "system_info.platform") || "",
      platformVersion: firstOf(raw, "platform_version", "os_version", "os_version.version") || "",
      model: firstOf(raw, "system_info.system.hardware_model", "hardware_model", "system_info.hardware_model") || "",
      cpuBrand: firstOf(raw, "cpu", "system_info.system.cpu_brand", "cpu_brand", "system_info.cpu_brand") || "",
      memoryBytes: num(firstOf(raw, "memory", "system_info.system.physical_memory", "physical_memory", "system_info.physical_memory")),
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
  // resolve one device by serial, hostname or node UUID — exact match first, then "contains". osctrl's own
  // q= search only looks at hostname/localname/uuid/ip (verified live): it never matches hardware_serial, so a
  // serial lookup can come back empty, or with only unrelated loose matches, even though the device exists.
  // When the server-side search finds no exact match, fall back to the full (paged) node list and match
  // client-side before giving up.
  async function resolveDevice(q) {
    const query = String(q || "").trim(); if (query.length < 2) return { error: "Provide a device name, hostname or serial number (at least 2 characters)." };
    const serverSide = await nodes(query);
    let exact = serverSide.filter(n => matchesNode(n, query));
    let pool = exact.length ? exact : serverSide;
    if (!exact.length) {
      const full = await allNodes();
      const fullExact = full.filter(n => matchesNode(n, query));
      if (fullExact.length) { exact = fullExact; pool = fullExact; }
      else if (!serverSide.length) { const ql = query.toLowerCase(); pool = full.filter(n => [n.uuid, n.hostname, n.serial].some(v => String(v || "").toLowerCase().includes(ql))); }
    }
    if (!pool.length) return { error: `No enrolled device matching "${query}" was found.` };
    if (pool.length > 1) return { error: "Several devices match that. Ask which one is meant (hostname or serial is unambiguous).", matches: pool.slice(0, 10).map(n => n.hostname || n.serial || n.uuid) };
    return { node: pool[0] };
  }

  /* ----------------------------------------------------- scheduled query results (the always-fresh panel) */
  // Scheduled-query results do NOT come from /api/v1/queries/<env>/results/<name> — that endpoint is for
  // on-demand (distributed) query results only (verified against osctrl v0.7.x's frontend/src/api/nodes.ts
  // and the live API). A scheduled query's results land in the node's own result logs, one entry per row per
  // run, newest first: GET /api/v1/logs/result/<env>/<uuid>?q=<name>&limit=<n> -> {items:[{created_at,action,
  // name,columns}]}. Two things the live API does that the spec didn't mention: `columns` is a JSON-ENCODED
  // STRING, not an object (parseColumnsField below handles that for every caller, on-demand recipe rows
  // included); and when it decodes, it can itself be an ARRAY of rows (osquery snapshot-mode logs can carry
  // several rows in one log item) — rowsFromItem() expands that into one normalized row per array element.
  // Differential logs also emit "removed" rows (the row's value just before it changed or disappeared), which
  // carry stale data, so picking the row to use prefers "added"/"snapshot" action over "removed", and only
  // breaks ties by recency (sortRows) rather than trusting the API's own array order.
  function parseColumnsField(v) {
    if (v == null) return null;
    if (typeof v === "object") return v;   // already an object on some osctrl versions/endpoints
    if (typeof v !== "string") return null;
    try { return JSON.parse(v); } catch { return null; }
  }
  const colsOf = row => parseColumnsField(row && (row.columns || row.data || row));
  function rowsFromItem(item) {
    const parsed = colsOf(item);
    if (parsed == null) return [];   // not valid JSON: no usable row, not a crash
    const list = Array.isArray(parsed) ? parsed : [parsed];
    return list.map(cols => ({ created_at: item.created_at, action: item.action, name: item.name, columns: cols }));
  }
  const ACTION_RANK = { added: 2, snapshot: 2, removed: 0 };
  const rankAction = a => Object.prototype.hasOwnProperty.call(ACTION_RANK, a) ? ACTION_RANK[a] : 1;   // no action field at all (e.g. older osctrl): treat as neutral
  function sortRows(rows) {
    return rows.slice().sort((a, b) => rankAction(b.action) - rankAction(a.action) || (toMs(b.created_at) || 0) - (toMs(a.created_at) || 0));
  }
  async function resultsOf(queryName, uuid, limit) {
    limit = limit || 1;
    // Fetch a few more raw log entries than a "single value" caller asked for, even when they only want one row
    // back: picking the right row needs something to prefer "added" over a "removed" row that may be newer by
    // itself, and to sort by created_at instead of trusting the API's own order. With a raw limit of 1 there is
    // nothing to pick among.
    const rawLimit = limit <= 1 ? 5 : limit;
    const cacheKey = queryName + "|" + uuid;
    const hit = resultsCache.get(cacheKey);
    if (hit && Date.now() - hit.at < cfg.resultsCacheMs) return hit.rows;
    const path = "/api/v1/logs/result/" + encodeURIComponent(cfg.envName) + "/" + encodeURIComponent(uuid) + "?q=" + encodeURIComponent(queryName) + "&limit=" + rawLimit;
    let rows = [];
    try {
      const items = (await okJson(path)).items || [];
      const parsed = sortRows(items.flatMap(rowsFromItem));
      // single-value metrics (OS, disk, battery, uptime): the one best row. "apps" (limit > 1): every row from
      // that same run, excluding any "removed" rows mixed into that run's batch, so a stale leftover never shows.
      rows = limit <= 1 ? parsed.slice(0, 1) : parsed.filter(r => r.created_at === (parsed[0] && parsed[0].created_at) && rankAction(r.action) > 0);
    } catch (e) { if (e.status !== 404) throw e; }   // 404: nobody has configured this scheduled query yet
    resultsCache.set(cacheKey, { at: Date.now(), rows });
    return rows;
  }

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

  // The newest platform version seen across the fleet, from the node list's own platform_version field — no
  // scheduled-query call needed for this, since the per-node logs endpoint only answers for one uuid at a time.
  async function fleetNewestPlatformVersion() {
    const all = await nodes("").catch(() => []);
    return all.map(n => n.platformVersion).reduce((best, v) => (versionRank(v) > versionRank(best) ? v : best), null);
  }

  // The exact inputs scoreDevice needs, shared by the list and the detail view so the same device can never
  // show two different scores at the same refresh: both call this, both go through resultsOf's own cache
  // (OSCTRL_RESULTS_CACHE_MS), so computing the list first and then opening a device's detail re-scores from
  // the same cached rows instead of refetching. This does mean the list now costs 4 extra osctrl calls per
  // device shown (cached afterward), not 0 — a deliberate trade for the two views never disagreeing.
  async function scoreInputsFor(n) {
    const [os, disk, battery, uptime] = await Promise.all([
      resultsOf(SCHEDULED.osVersion, n.uuid, 1).catch(() => []),
      resultsOf(SCHEDULED.disk, n.uuid, 1).catch(() => []),
      resultsOf(SCHEDULED.battery, n.uuid, 1).catch(() => []),
      resultsOf(SCHEDULED.uptime, n.uuid, 1).catch(() => [])
    ]);
    return { os, disk, battery, uptime };
  }

  async function deviceSummaries(q) {
    const list = await nodes(q);
    const fleetNewestVersion = q ? await fleetNewestPlatformVersion() : list.map(n => n.platformVersion).reduce((best, v) => (versionRank(v) > versionRank(best) ? v : best), null);
    const scores = await Promise.all(list.map(n => scoreInputsFor(n).then(inputs => scoreDevice(n, { ...inputs, fleetNewestVersion }))));
    return list.map((n, i) => ({ uuid: n.uuid, hostname: n.hostname, serial: n.serial, platform: n.platform, platformVersion: n.platformVersion, lastSeen: n.lastSeenMs ? new Date(n.lastSeenMs).toISOString() : null, healthScore: scores[i].score, healthBand: scores[i].band }));
  }

  async function deviceDetail(q) {
    const r = await resolveDevice(q); if (r.error) return r;
    const n = r.node;
    const [mine, appsR] = await Promise.all([scoreInputsFor(n), resultsOf(SCHEDULED.apps, n.uuid, 200).catch(() => [])]);
    const fleetNewestVersion = await fleetNewestPlatformVersion();
    const score = scoreDevice(n, { ...mine, fleetNewestVersion });
    const appRows = appsR.map(colsOf).filter(Boolean);
    return {
      identity: { hostname: n.hostname, serial: n.serial, uuid: n.uuid, platform: n.platform, model: n.model, cpuBrand: n.cpuBrand, memoryBytes: n.memoryBytes },
      os: { version: (mine.os[0] && firstOf(colsOf(mine.os[0]), "version")) || n.platformVersion || null, reportedAt: mine.os.length ? toMsOf(mine.os[0]) : null },
      agent: { osqueryVersion: n.osqueryVersion, lastSeen: n.lastSeenMs ? new Date(n.lastSeenMs).toISOString() : null, enrolled: n.enrolledMs ? new Date(n.enrolledMs).toISOString() : null },
      battery: mine.battery.length ? colsOf(mine.battery[0]) : null,
      storage: mine.disk.length ? colsOf(mine.disk[0]) : null,
      uptime: mine.uptime.length ? colsOf(mine.uptime[0]) : null,
      apps: { count: appRows.length, items: appRows.slice(0, 200).map(c => ({ name: firstOf(c, "name"), version: firstOf(c, "bundle_short_version", "version"), lastOpened: (() => { const t = toMs(firstOf(c, "last_opened_time", "last_opened_at")); return t ? new Date(t).toISOString() : null; })() })) },
      health: score
    };
  }
  function toMsOf(row) { const c = colsOf(row) || {}; const t = toMs((row && row.created_at) || firstOf(c, "hour", "unix_time", "calendar_time")); return t ? new Date(t).toISOString() : null; }

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
    _state: st, _scoreDevice: scoreDevice, _normalizeNode: normalizeNode, _resultsOf: resultsOf
  };
}
module.exports = { createOsctrl, RECIPES, SCHEDULED };
