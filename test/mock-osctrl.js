"use strict";
// A stand-in for osctrl's REST API: login, node list, per-node scheduled-query result logs, and one ad-hoc query round trip.
// MOCK_O_AUTH controls which Authorization header style it accepts: "raw" (default), "bearer", or "flip" (accepts
// raw the first call then switches to requiring bearer, to prove the client's one-time fallback keeps working).
// MOCK_O_EXPIRE_AFTER=N makes the Nth authenticated call answer 401 once (any header), to exercise re-login.
const http = require("http");
const PORT = +process.env.MOCK_O_PORT || 4040;
const USER = process.env.MOCK_O_USER || "ai-readonly", PASS = process.env.MOCK_O_PASS || "s3cret";
const AUTH_MODE = process.env.MOCK_O_AUTH || "raw";
const EXPIRE_AFTER = +process.env.MOCK_O_EXPIRE_AFTER || 0;

let tokens = new Set(), calls = 0, flipped = false, lastQuery = null;
const NODES = [
  { uuid: "u-1", hostname: "jdoe-mbp.corp.local", hardware_serial: "C02ABCDEFG", platform: "darwin", platform_version: "14.5", memory: "17179869184", cpu: "Apple M3", system_info: { system: { hardware_model: "MacBook Pro" } }, osquery_version: "5.12.1", last_seen: Math.floor(Date.now() / 1000) - 120 },
  { uuid: "u-2", hostname: "asmith-air.corp.local", hardware_serial: "C02HIJKLMN", platform: "darwin", platform_version: "13.2", memory: "8589934592", cpu: "Apple M2", system_info: { system: { hardware_model: "MacBook Air" } }, osquery_version: "5.12.1", last_seen: Math.floor(Date.now() / 1000) - 7200 }
];
// per-node result logs, newest item first: GET /api/v1/logs/result/<env>/<uuid>?q=<name>&limit=<n> -> {items:[...]}
const LOGS = {
  "u-1": {
    macos_os_version: [{ created_at: "2025-01-01T00:00:00Z", name: "macos_os_version", columns: { name: "macOS", version: "14.5", build: "23F79" } }],
    macos_root_disk: [{ created_at: "2025-01-01T00:00:00Z", name: "macos_root_disk", columns: { path: "/", blocks: "1000000", blocks_size: "4096", blocks_available: "300000", blocks_free: "320000" } }],
    macos_battery: [{ created_at: "2025-01-01T00:00:00Z", name: "macos_battery", columns: { health: "Good", cycle_count: "120", max_capacity: "92" } }],
    macos_uptime: [{ created_at: "2025-01-01T00:00:00Z", name: "macos_uptime", columns: { days: "2", total_seconds: "190000" } }],
    macos_apps: [
      { created_at: "2025-01-01T00:00:00Z", name: "macos_apps", columns: { name: "Slack", version: "4.39.0", last_opened_at: "1700000000" } },
      { created_at: "2025-01-01T00:00:00Z", name: "macos_apps", columns: { name: "Chrome", version: "131.0", last_opened_at: "1700001000" } },
      { created_at: "2024-01-01T00:00:00Z", name: "macos_apps", columns: { name: "OldApp", version: "1.0", last_opened_at: "1600000000" } }   // an older run: must not leak into the current list
    ]
  },
  "u-2": { macos_os_version: [{ created_at: "2025-01-01T00:00:00Z", name: "macos_os_version", columns: { name: "macOS", version: "13.2", build: "22D49" } }] }
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
  if (req.method === "POST" && url.pathname === "/api/v1/login") {
    const b = await readBody(req);
    if (b.username !== USER || b.password !== PASS) return json(res, 401, { error: "invalid credentials" });
    const t = "tok-" + Math.random().toString(36).slice(2); tokens.add(t);
    if (AUTH_MODE === "flip") flipped = true;   // after the first login, start requiring the other header style
    return json(res, 200, { token: t, csrf_token: "csrf-" + t });
  }
  calls++;
  if (EXPIRE_AFTER && calls === EXPIRE_AFTER) return json(res, 401, { error: "token expired" });
  if (!authOk(req)) return json(res, 401, { error: "unauthorized" });

  const envM = /^\/api\/v1\/nodes\/([^/]+)$/.exec(url.pathname);
  if (req.method === "GET" && envM) {
    const q = (url.searchParams.get("q") || "").toLowerCase();
    const list = q ? NODES.filter(n => [n.hostname, n.hardware_serial, n.uuid].some(v => String(v).toLowerCase().includes(q))) : NODES;
    return json(res, 200, { nodes: list });
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
module.exports = { server };
