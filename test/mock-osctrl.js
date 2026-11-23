"use strict";
// A stand-in for osctrl's REST API: login, node list, per-node scheduled-query result logs, and one ad-hoc query round trip.
// MOCK_O_AUTH controls which Authorization header style it accepts: "raw" (default), "bearer", or "flip" (accepts
// raw the first call then switches to requiring bearer, to prove the client's one-time fallback keeps working).
// MOCK_O_EXPIRE_AFTER=N makes the Nth authenticated call answer 401 once (any header), to exercise re-login.
// MOCK_O_EVICT_AFTER=N simulates osctrl's one-token-per-user rule: on the Nth authenticated call, that call's
// token is marked evicted (as if someone else just logged in as the same account) and every further request
// bearing it gets osctrl's real eviction response -- a 302 to /forbidden, not a 401/403 -- until a fresh login
// happens. module.exports.loginCount lets a test assert how many times POST /login actually ran.
const http = require("http");
const PORT = +process.env.MOCK_O_PORT || 4040;
const USER = process.env.MOCK_O_USER || "ai-readonly", PASS = process.env.MOCK_O_PASS || "s3cret";
const AUTH_MODE = process.env.MOCK_O_AUTH || "raw";
const EXPIRE_AFTER = +process.env.MOCK_O_EXPIRE_AFTER || 0;
const EVICT_AFTER = +process.env.MOCK_O_EVICT_AFTER || 0;

let tokens = new Set(), calls = 0, flipped = false, lastQuery = null, evictedToken = null;
const counts = { logins: 0 };
const NODES = [
  { uuid: "u-1", hostname: "jdoe-mbp.corp.local", hardware_serial: "C02ABCDEFG", platform: "darwin", platform_version: "14.5", memory: "17179869184", cpu: "Apple M3", system_info: { system: { hardware_model: "MacBook Pro" } }, osquery_version: "5.12.1", last_seen: Math.floor(Date.now() / 1000) - 120 },
  { uuid: "u-2", hostname: "asmith-air.corp.local", hardware_serial: "C02HIJKLMN", platform: "darwin", platform_version: "13.2", memory: "8589934592", cpu: "Apple M2", system_info: { system: { hardware_model: "MacBook Air" } }, osquery_version: "5.12.1", last_seen: Math.floor(Date.now() / 1000) - 7200 }
];
// per-node result logs: GET /api/v1/logs/result/<env>/<uuid>?q=<name>&limit=<n> -> {items:[...]}. columns is a
// JSON-ENCODED STRING on the real API, not an object, and items are not guaranteed to arrive newest-first or
// "added" before "removed" -- these fixtures reflect that on purpose, to exercise osctrl.js's own parsing,
// flattening and sorting rather than relying on this mock to hand back already-clean data.
const col = o => JSON.stringify(o);
const LOGS = {
  "u-1": {
    macos_os_version: [{ created_at: "2025-01-01T00:00:00Z", action: "added", name: "macos_os_version", columns: col({ name: "macOS", version: "14.5", build: "23F79" }) }],
    macos_root_disk: [{ created_at: "2025-01-01T00:00:00Z", action: "added", name: "macos_root_disk", columns: col({ path: "/", blocks: "1000000", blocks_size: "4096", blocks_available: "300000", blocks_free: "320000" }) }],
    // a differential pair at the same timestamp, "removed" (stale) listed FIRST: picking must prefer "added", not array order
    macos_battery: [
      { created_at: "2025-01-01T00:00:00Z", action: "removed", name: "macos_battery", columns: col({ health: "Fair", cycle_count: "119", max_capacity: "93" }) },
      { created_at: "2025-01-01T00:00:00Z", action: "added", name: "macos_battery", columns: col({ health: "Good", cycle_count: "120", max_capacity: "92" }) }
    ],
    // the older run listed FIRST: picking must sort by created_at, not just take the first item
    macos_uptime: [
      { created_at: "2024-06-01T00:00:00Z", action: "added", name: "macos_uptime", columns: col({ days: "40", total_seconds: "3456000" }) },
      { created_at: "2025-01-01T00:00:00Z", action: "added", name: "macos_uptime", columns: col({ days: "2", total_seconds: "190000" }) }
    ],
    // osquery 5.24.1's `apps` table has no `version`/`last_opened_at` columns -- the real ones are
    // bundle_short_version/last_opened_time. Slack and Chrome use the real names; OldApp keeps the old
    // names on purpose, to prove the fallback still works if an older osquery ever reports them instead.
    macos_apps: [
      { created_at: "2025-01-01T00:00:00Z", action: "added", name: "macos_apps", columns: col({ name: "Slack", bundle_short_version: "4.39.0", last_opened_time: "1700000000" }) },
      { created_at: "2025-01-01T00:00:00Z", action: "added", name: "macos_apps", columns: col({ name: "Chrome", bundle_short_version: "131.0", last_opened_time: "1700001000" }) },
      { created_at: "2024-01-01T00:00:00Z", action: "added", name: "macos_apps", columns: col({ name: "OldApp", version: "1.0", last_opened_at: "1600000000" }) }   // an older run: must not leak into the current list
    ],
    // a snapshot-mode item whose decoded columns is itself an ARRAY of rows, not one object -- must expand into separate rows
    macos_memory: [{ created_at: "2025-01-01T00:00:00Z", action: "snapshot", name: "macos_memory", columns: col([{ total_bytes: "17179869184", used_approx_bytes: "12792086528" }, { total_bytes: "17179869184", used_approx_bytes: "9000000000" }]) }]
  },
  "u-2": { macos_os_version: [{ created_at: "2025-01-01T00:00:00Z", action: "added", name: "macos_os_version", columns: col({ name: "macOS", version: "13.2", build: "22D49" }) }] }
};

function json(res, status, body) { const b = Buffer.from(JSON.stringify(body)); res.writeHead(status, { "content-type": "application/json", "content-length": b.length }); res.end(b); }
function readBody(req) { return new Promise(r => { const c = []; req.on("data", d => c.push(d)); req.on("end", () => { try { r(JSON.parse(Buffer.concat(c).toString() || "{}")); } catch { r({}); } }); }); }

function authOk(req) {
  const h = req.headers.authorization || "";
  const wantBearer = AUTH_MODE === "bearer" || (AUTH_MODE === "flip" && flipped);
  const isBearer = /^Bearer\s+/i.test(h);
  if (wantBearer !== isBearer) return false;   // wrong header style for this mode
  return tokens.has(h.replace(/^Bearer\s+/i, ""));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/forbidden") { const b = Buffer.from("<html><body>Forbidden</body></html>"); res.writeHead(200, { "content-type": "text/html", "content-length": b.length }); return res.end(b); }   // osctrl's real eviction landing page: 200, not JSON
  if (req.method === "POST" && url.pathname === "/api/v1/login") {
    counts.logins++;
    const b = await readBody(req);
    if (b.username !== USER || b.password !== PASS) return json(res, 401, { error: "invalid credentials" });
    const t = "tok-" + Math.random().toString(36).slice(2); tokens.add(t);
    evictedToken = null;   // one live token per user: a fresh login always un-evicts (the new token is the only live one)
    if (AUTH_MODE === "flip") flipped = true;   // after the first login, start requiring the other header style
    return json(res, 200, { token: t, csrf_token: "csrf-" + t });
  }
  calls++;
  if (EXPIRE_AFTER && calls === EXPIRE_AFTER) return json(res, 401, { error: "token expired" });
  const presented = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (EVICT_AFTER && calls === EVICT_AFTER) evictedToken = presented;   // as if another login just happened elsewhere, right now
  if (evictedToken && presented === evictedToken) { res.writeHead(302, { location: "/forbidden" }); return res.end(); }
  if (!authOk(req)) return json(res, 401, { error: "unauthorized" });

  const envM = /^\/api\/v1\/nodes\/([^/]+)$/.exec(url.pathname);
  if (req.method === "GET" && envM) {
    const q = (url.searchParams.get("q") || "").toLowerCase();
    // real osctrl's q= only looks at hostname/localname/uuid/ip -- never hardware_serial -- so a serial search
    // must come back empty here too, the same as live, to actually exercise resolveDevice's fallback.
    if (q) return json(res, 200, { nodes: NODES.filter(n => [n.hostname, n.uuid].some(v => String(v).toLowerCase().includes(q))) });
    const limit = +(url.searchParams.get("limit") || 0), offset = +(url.searchParams.get("offset") || 0);
    const page = limit ? NODES.slice(offset, offset + limit) : NODES;
    return json(res, 200, { nodes: page });
  }
  const logM = /^\/api\/v1\/logs\/result\/([^/]+)\/([^/]+)$/.exec(url.pathname);
  if (req.method === "GET" && logM) {
    const uuid = decodeURIComponent(logM[2]), name = url.searchParams.get("q") || "", limit = +(url.searchParams.get("limit") || 1);
    const items = ((LOGS[uuid] || {})[name] || []).slice(0, limit);
    if (!items.length) return json(res, 404, { error: "no such scheduled query for this node" });
    return json(res, 200, { items });
  }
  const resM = /^\/api\/v1\/queries\/([^/]+)\/results\/([^/]+)$/.exec(url.pathname);
  if (req.method === "GET" && resM) {
    const name = decodeURIComponent(resM[2]);
    if (name === lastQuery && lastQuery) return json(res, 200, { results: [{ hostname: "jdoe-mbp.corp.local", columns: { path: "/", blocks_available: "9", blocks: "10" } }] });
    return json(res, 404, { error: "no such query" });
  }
  const qM = /^\/api\/v1\/queries\/([^/]+)$/.exec(url.pathname);
  if (req.method === "POST" && qM) {
    const b = await readBody(req); lastQuery = "adhoc-" + Math.random().toString(36).slice(2);
    return json(res, 200, { query_name: lastQuery, targeted: b.uuids || b.hostnames || b.hardware_serials || [] });
  }
  json(res, 404, { error: "not found" });
});
server.listen(PORT, () => console.log("mock osctrl on :" + PORT));
module.exports = { server, counts };
