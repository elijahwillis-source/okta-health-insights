"use strict";
// A stand-in for Google's OAuth token endpoint and the Admin SDK Reports API (applicationName=token).
// It is strict on purpose: it VERIFIES the service-account JWT (RS256 signature, issuer, the admin being
// impersonated, the one allowed scope, lifetime), so a passing test proves the signing code is right.
const http = require("http"), crypto = require("crypto"), fs = require("fs");
const PORT = +process.env.MOCK_G_PORT || 4030, PAGE = +process.env.MOCK_G_PAGE || 40;
const ADMIN = process.env.MOCK_G_ADMIN || "admin@example.com", KEYFILE = process.env.MOCK_G_KEYFILE || "/tmp/mock-google-key.json";
const SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly";
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
const CLIENT_EMAIL = "sightline@my-project.iam.gserviceaccount.com";
fs.writeFileSync(KEYFILE, JSON.stringify({ type: "service_account", project_id: "my-project", client_email: CLIENT_EMAIL, client_id: "1234567890", private_key: privateKey, token_uri: `http://localhost:${PORT}/token` }));

let mode = "ok", tokens = new Set(), stats = { tokenRequests: 0, apiRequests: 0, rejected: [] }, seq = 1000;
const now = Date.now(), MIN = 60000, DAY = 864e5;
const U = "https://www.googleapis.com/auth/";
const APPS = {
  acme:   { name: "Acme CRM Sync",    id: "111111111111-acmecrm.apps.googleusercontent.com",    scopes: ["openid", U + "userinfo.email", U + "drive"] },
  cal:    { name: "Calendly",         id: "222222222222-calendly.apps.googleusercontent.com",   scopes: ["openid", U + "userinfo.email", U + "calendar.events"] },
  notes:  { name: "Notes Helper",     id: "333333333333-noteshelper.apps.googleusercontent.com", scopes: ["openid", U + "userinfo.email", U + "userinfo.profile"] },
  sketchy:{ name: "Sketchy PDF Tool", id: "444444444444-sketchypdf.apps.googleusercontent.com",  scopes: ["https://mail.google.com/", U + "drive"] }
};
const user = n => `user${String(n).padStart(2, "0")}@example.com`;
const log = [];   // every activity record, any order
function add(app, who, minAgo, name = "authorize", extra = [], base = now) {
  const a = APPS[app]; const params = [{ name: "app_name", value: a.name }, { name: "client_id", value: a.id }, { name: "scope", multiValue: a.scopes }, ...extra];
  log.push({ kind: "admin#reports#activity", id: { time: new Date(base - minAgo * MIN).toISOString(), uniqueQualifier: String(++seq), applicationName: "token", customerId: "C0abc123" },
    etag: "e" + seq, actor: { callerType: "USER", email: who, profileId: "10" + seq }, ipAddress: "203.0.113." + (seq % 200), events: [{ type: "auth", name, parameters: params }] });
}
for (let i = 1; i <= 5; i++) add("acme", user(i), (2 + i * 3) * 1440 / 1);                 // Acme: 5 people over the past ~2 weeks
for (let i = 1; i <= 8; i++) add("cal", user(i), (i * 2) * 1440);                          // Calendly: 8 people, 2..16 days ago
for (let i = 1; i <= 12; i++) add("notes", user(i), (i + 1) * 1000);                       // Notes Helper: 12 people, low risk
add("cal", user(2), 3 * 1440 - 30, "revoke"); add("cal", user(4), 5 * 1440, "revoke");     // two revokes
for (let i = 0; i < 6; i++) add("sketchy", user(20 + i), 5 + i * 8);                        // Sketchy PDF Tool: NEW and 6 people within the last hour
add("sketchy", user(30), 12, "deny", [{ name: "rejection_type", value: "ADMIN_BLOCKED" }]);
add("sketchy", user(31), 3, "request");
add("acme", user(1), 50, "activity", [{ name: "api_name", value: "script" }, { name: "method_name", value: "script.projects.run" }, { name: "num_response_bytes", intValue: "2048" }, { name: "product_bucket", multiValue: ["APPS_SCRIPT_API"] }]);

// optional: MOCK_G_MANY=110 adds that many extra apps (varied scopes, people and ages), to test a big real-world-sized list
const MANY = +process.env.MOCK_G_MANY || 0;
const SCOPE_SETS = [["openid", U + "userinfo.email"], [U + "drive"], [U + "gmail.readonly", "openid"], [U + "calendar.events"], [U + "admin.directory.user.readonly"], [U + "spreadsheets", U + "drive.file"], ["client_channel", "docs.test"], [U + "userinfo.profile"]];
for (let i = 0; i < MANY; i++) {
  const key = "many" + i; APPS[key] = { name: i % 9 === 0 ? "" : "Many App " + i, id: `${700000 + i}-many${i}.apps.googleusercontent.com`, scopes: SCOPE_SETS[i % SCOPE_SETS.length] };
  const people = 1 + (i * 7) % 25;
  for (let j = 0; j < people; j++) add(key, user(100 + ((i * 3 + j) % 90)), (1 + (i % 28)) * 1440 + j * 7);
  if (i % 4 === 0) for (let j = 0; j < people; j++) add(key, user(100 + ((i * 3 + j) % 90)), (i % 28) * 1440 + 30, "revoke");      // some end up with nobody
}
const b64u = s => Buffer.from(s, "base64");
function verifyJwt(assertion, audience) {
  const parts = String(assertion || "").split("."); if (parts.length !== 3) return "assertion is not a JWT";
  let head, claims; try { head = JSON.parse(b64u(parts[0]).toString()); claims = JSON.parse(b64u(parts[1]).toString()); } catch { return "assertion is not valid JSON"; }
  if (head.alg !== "RS256") return "alg must be RS256";
  if (!crypto.verify("RSA-SHA256", Buffer.from(parts[0] + "." + parts[1]), publicKey, b64u(parts[2]))) return "bad signature";
  if (claims.iss !== CLIENT_EMAIL) return "wrong issuer";
  if (claims.aud !== audience) return "wrong audience";
  if (claims.scope !== SCOPE) return "invalid_scope:" + claims.scope;
  if (!(claims.exp > claims.iat) || claims.exp - claims.iat > 3600) return "bad lifetime";
  if (Math.abs(claims.iat * 1000 - Date.now()) > 5 * MIN) return "clock skew";
  if (claims.sub !== ADMIN) return "invalid_grant:sub";
  return "";
}
const json = (res, code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
const readBody = req => new Promise(r => { let b = ""; req.on("data", c => b += c); req.on("end", () => r(b)); });

http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/token" && req.method === "POST") {
    stats.tokenRequests++; const form = new URLSearchParams(await readBody(req));
    if (mode === "unauthorized") return json(res, 401, { error: "unauthorized_client", error_description: "Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested." });
    if (form.get("grant_type") !== "urn:ietf:params:oauth:grant-type:jwt-bearer") return json(res, 400, { error: "unsupported_grant_type" });
    const bad = verifyJwt(form.get("assertion"), `http://localhost:${PORT}/token`);
    if (bad) { stats.rejected.push(bad); return json(res, 400, bad.startsWith("invalid_grant") ? { error: "invalid_grant", error_description: "Not a valid email or user ID." } : bad.startsWith("invalid_scope") ? { error: "invalid_scope", error_description: "Invalid OAuth scope." } : { error: "invalid_request", error_description: bad }); }
    const t = "gtok-" + crypto.randomBytes(6).toString("hex"); tokens.add(t); return json(res, 200, { access_token: t, expires_in: 3600, token_type: "Bearer" });
  }
  if (url.pathname === "/admin/reports/v1/activity/users/all/applications/token" && req.method === "GET") {
    stats.apiRequests++;
    if (!tokens.has((req.headers.authorization || "").replace(/^Bearer /, ""))) return json(res, 401, { error: { code: 401, message: "Invalid Credentials" } });
    if (mode === "noreports") return json(res, 401, { error: { code: 401, message: "Access denied. You are not authorized to read activity records.", errors: [{ message: "Access denied. You are not authorized to read activity records.", domain: "global", reason: "authError" }] } });   // the admin has no Reports privilege
    if (mode === "forbidden") return json(res, 403, { error: { code: 403, message: "Not Authorized to access this resource/api" } });
    const from = Date.parse(url.searchParams.get("startTime") || "") || 0, to = Date.parse(url.searchParams.get("endTime") || "") || Infinity;
    const all = log.filter(a => { const t = Date.parse(a.id.time); return t >= from && t <= to; }).sort((a, b) => Date.parse(b.id.time) - Date.parse(a.id.time));   // newest first
    const size = Math.min(+url.searchParams.get("maxResults") || PAGE, PAGE), off = +url.searchParams.get("pageToken") || 0, items = all.slice(off, off + size);
    const out = { kind: "admin#reports#activities", etag: "x", items }; if (off + size < all.length) out.nextPageToken = String(off + size);
    if (!items.length) delete out.items; return json(res, 200, out);
  }
  if (url.pathname === "/_stats") return json(res, 200, Object.assign({ mode, total: log.length }, stats));
  if (url.pathname === "/_mode") { mode = url.searchParams.get("m") || "ok"; return json(res, 200, { mode }); }
  if (url.pathname === "/_add") { add(url.searchParams.get("app") || "acme", url.searchParams.get("user") || user(40), +url.searchParams.get("min") || 0, url.searchParams.get("name") || "authorize", [], Date.now()); return json(res, 200, { total: log.length }); }
  json(res, 404, { error: "not found" });
}).listen(PORT, () => console.log("mock Google on :" + PORT + ", key written to " + KEYFILE));
