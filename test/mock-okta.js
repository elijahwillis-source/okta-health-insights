"use strict";
// Minimal fake Okta org for local development: node test/mock-okta.js
// Then run the app with OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test
// Env: MOCK_PORT (default 4010), MOCK_NO_RESULT_FILTER=1 (reject filters that use outcome.result, like an Okta that does not support them)
const http = require("http");
const crypto = require("crypto");

const APPS = ["Salesforce", "Slack", "Workday", "ServiceNow", "GitHub Enterprise", "Zoom", "Box", "Jira Cloud"];
const USERS = Array.from({ length: 25 }, (_, i) => `user${String(i + 1).padStart(2, "0")}@example.com`);
const LONG = "Bad Request. Errors reported by remote server: " + Array.from({ length: 14 }, (_, i) => `member ID "${(0x65a1939f412e490f + i * 7919).toString(16).padStart(24, "0")}" does not exist`).join("; ");
const REASONS = [LONG, "Automatic provisioning of user to app failed: Insufficient licenses available",
  "Automatic provisioning of user to app failed: 401 Unauthorized — API token expired", "INVALID_CREDENTIALS", "User is not assigned to the application"];
const PORT = +process.env.MOCK_PORT || 4010;
const pick = a => a[Math.floor(Math.random() * a.length)];
const appId = app => "0oaMOCK" + String(APPS.indexOf(app)).padStart(6, "0");   // stable id per app, like the real API
const extraId = n => "0oaMOCK" + String(n).padStart(6, "0");   // stable id per app, like the real API

function makeEvent(t, live) {
  let app = pick(APPS);
  // Zoom only has OLD activity (3+ days back): it falls out of a small event buffer, like a rarely-used real app
  if (app === "Zoom") { if (live) app = "Slack"; else t = Math.min(t, Date.now() - 3 * 864e5); }
  // event-side display names sometimes carry stray whitespace
  const shown = Math.random() < 0.15 ? app + " " : app;
  const bad = Math.random() < (app === "ServiceNow" ? 0.25 : 0.06), prov = Math.random() < 0.25;
  return {
    uuid: crypto.randomUUID(), published: new Date(t).toISOString(), severity: bad ? "WARN" : "INFO",
    eventType: prov ? pick(["application.provision.user.push", "application.user_membership.add"]) : "user.authentication.sso",
    displayMessage: prov ? "Automatic provisioning" : "User single sign on to app",
    outcome: { result: bad ? "FAILURE" : "SUCCESS", reason: bad ? pick(REASONS) : null },
    actor: { type: prov ? "SystemPrincipal" : "User", alternateId: prov ? "system@okta.com" : pick(USERS), displayName: "x" },
    target: prov ? [{ type: "User", alternateId: pick(USERS) }, { type: "AppInstance", displayName: shown, id: appId(app) }] : [{ type: "AppInstance", displayName: shown, id: appId(app) }]
  };
}

const events = [];
const now = Date.now();
const N = +process.env.MOCK_EVENTS || 3000;
for (let i = 0; i < N; i++) events.push(makeEvent(now - Math.random() * 3 * 864e5));
// a deterministic burst of RECENT errors, so alert rules have something to match every time:
// 14 provisioning failures for ServiceNow over the last half hour, and 3 failed sign-ins for Slack
const burst = (minAgo, app, user, reason, type) => ({ uuid: crypto.randomUUID(), published: new Date(now - minAgo * 60000).toISOString(), severity: "WARN", eventType: type, displayMessage: "burst",
  outcome: { result: "FAILURE", reason }, actor: type.startsWith("application.") ? { type: "SystemPrincipal", alternateId: "system@okta.com", displayName: "x" } : { type: "User", alternateId: user, displayName: "x" },
  target: type.startsWith("application.") ? [{ type: "User", alternateId: user, displayName: user }, { type: "AppInstance", displayName: app, id: appId(app) }] : [{ type: "AppInstance", displayName: app, id: appId(app) }] });
for (let i = 0; i < 14; i++) events.push(burst(2 + i * 2, "ServiceNow", `burst${String(i % 7 + 1).padStart(2, "0")}@example.com`, "Automatic provisioning of user to app failed: Insufficient licenses available", "application.provision.user.push"));
for (let i = 0; i < 3; i++) events.push(burst(3 + i * 3, "Slack", `burst0${i + 1}@example.com`, "INVALID_CREDENTIALS", "user.authentication.sso"));
events.sort((a, b) => (a.published < b.published ? -1 : 1));
setInterval(() => events.push(makeEvent(Date.now(), true)), 5000);   // a new event every 5s

http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${PORT}`);
  const json = (o, h = {}) => { res.writeHead(200, { "content-type": "application/json", ...h }); res.end(JSON.stringify(o)); };
  if (u.pathname === "/api/v1/logs") {
    const since = u.searchParams.get("since") || "1970-01-01T00:00:00.000Z";
    const until = u.searchParams.get("until");
    const q = (u.searchParams.get("q") || "").toLowerCase().split(/\s+/).filter(Boolean);   // keyword search: every keyword must appear somewhere
    const desc = u.searchParams.get("sortOrder") === "DESCENDING";
    const after = +u.searchParams.get("after") || 0, limit = Math.min(1000, +u.searchParams.get("limit") || 100);
    let pool = events.filter(e => e.published >= since && (!until || e.published < until));
    if (q.length) pool = pool.filter(e => { const blob = JSON.stringify([e.actor, e.target, e.displayMessage, e.outcome]).toLowerCase(); return q.every(k => blob.includes(k)); });
    const f = /^(target|actor)\.id eq "([^"]+)"(?: and outcome\.result eq "([A-Z]+)")?$/.exec(u.searchParams.get("filter") || "");
    if (f && f[3] && process.env.MOCK_NO_RESULT_FILTER) { res.writeHead(400, { "content-type": "application/json" }); return res.end(JSON.stringify({ errorCode: "E0000031", errorSummary: "Invalid filter" })); }
    if (f) pool = pool.filter(e => (f[1] === "target" ? e.target.some(t => t.id === f[2]) : (e.actor && e.actor.id === f[2])) && (!f[3] || (e.outcome && e.outcome.result === f[3])));
    if (desc) pool = pool.slice().reverse();
    const page = pool.slice(after, after + limit);
    const next = `http://localhost:${PORT}/api/v1/logs?since=${encodeURIComponent(since)}${until ? "&until=" + encodeURIComponent(until) : ""}${q.length ? "&q=" + encodeURIComponent(q.join(" ")) : ""}${desc ? "&sortOrder=DESCENDING" : ""}&limit=${limit}&after=${after + page.length}`;
    // like the real API: polling queries always get a next link; bounded queries lose it at the end
    if ((until || desc) && after + page.length >= pool.length) return json(page);
    return json(page, { link: `<${next}>; rel="next"` });
  }
  if (u.pathname === "/api/v1/apps") {
    // labels with stray whitespace (as the real API sometimes returns) plus one blank label
    const messy = { Slack: "Slack ", Zoom: "  Zoom" };
    const labels = APPS.map(a => messy[a] || a).concat(["Legacy HR Portal", "   "]);
    return json(labels.map((l, i) => ({ id: extraId(i), label: l, status: "ACTIVE" })));   // index i == APPS.indexOf for the real apps
  }
  res.writeHead(404); res.end("{}");
}).listen(PORT, () => console.log(`Mock Okta on http://localhost:${PORT}`));
