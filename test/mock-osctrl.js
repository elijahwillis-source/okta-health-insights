"use strict";
// A stand-in for osctrl's REST API: login, node list, scheduled-query results, and one ad-hoc query round trip.
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
  { uuid: "u-1", hostname: "jdoe-mbp.corp.local", hardware_serial: "C02ABCDEFG", platform: "darwin", platform_version: "14.5", hardware_model: "MacBook Pro", cpu_brand: "Apple M3", physical_memory: 17179869184, osquery_version: "5.12.1", last_seen: Math.floor(Date.now() / 1000) - 120 },
  { uuid: "u-2", hostname: "asmith-air.corp.local", hardware_serial: "C02HIJKLMN", platform: "darwin", platform_version: "13.2", hardware_model: "MacBook Air", cpu_brand: "Apple M2", physical_memory: 8589934592, osquery_version: "5.12.1", last_seen: Math.floor(Date.now() / 1000) - 7200 }
];
const RESULTS = {
  macos_os_version: [
    { hostname: "jdoe-mbp.corp.local", columns: { name: "macOS", version: "14.5", build: "23F79" } },
    { hostname: "asmith-air.corp.local", columns: { name: "macOS", version: "13.2", build: "22D49" } }
  ],
  macos_root_disk: [{ hostname: "jdoe-mbp.corp.local", columns: { path: "/", blocks: "1000000", blocks_size: "4096", blocks_available: "300000", blocks_free: "320000" } }],
  macos_battery: [{ hostname: "jdoe-mbp.corp.local", columns: { health: "Good", cycle_count: "120", max_capacity: "92" } }],
  macos_uptime: [{ hostname: "jdoe-mbp.corp.local", columns: { days: "2", total_seconds: "190000" } }],
  macos_apps: [{ hostname: "jdoe-mbp.corp.local", columns: { name: "Slack", version: "4.39.0", last_opened_at: "1700000000" } }]
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
  const resM = /^\/api\/v1\/queries\/([^/]+)\/results\/([^/]+)$/.exec(url.pathname);
  if (req.method === "GET" && resM) {
    const name = decodeURIComponent(resM[2]);
    if (RESULTS[name]) return json(res, 200, { results: RESULTS[name] });
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
