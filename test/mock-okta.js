"use strict";
// Minimal fake Okta org for local development: node test/mock-okta.js
// Then run the app with OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test
const http = require("http");
const crypto = require("crypto");

const APPS = ["Salesforce", "Slack", "Workday", "ServiceNow", "GitHub Enterprise", "Zoom", "Box", "Jira Cloud"];
const USERS = Array.from({ length: 25 }, (_, i) => `user${String(i + 1).padStart(2, "0")}@example.com`);
const REASONS = ["Automatic provisioning of user to app failed: Insufficient licenses available",
  "Automatic provisioning of user to app failed: 401 Unauthorized — API token expired", "INVALID_CREDENTIALS", "User is not assigned to the application"];
const pick = a => a[Math.floor(Math.random() * a.length)];

function makeEvent(t) {
  const app = pick(APPS), bad = Math.random() < (app === "ServiceNow" ? 0.25 : 0.06), prov = Math.random() < 0.25;
  return {
    uuid: crypto.randomUUID(), published: new Date(t).toISOString(), severity: bad ? "WARN" : "INFO",
    eventType: prov ? pick(["application.provision.user.push", "application.user_membership.add"]) : "user.authentication.sso",
    displayMessage: prov ? "Automatic provisioning" : "User single sign on to app",
    outcome: { result: bad ? "FAILURE" : "SUCCESS", reason: bad ? pick(REASONS) : null },
    actor: { type: prov ? "SystemPrincipal" : "User", alternateId: prov ? "system@okta.com" : pick(USERS), displayName: "x" },
    target: prov ? [{ type: "User", alternateId: pick(USERS) }, { type: "AppInstance", displayName: app, id: "0oa" + app.length }] : [{ type: "AppInstance", displayName: app, id: "0oa" + app.length }]
  };
}

const events = [];
const now = Date.now();
for (let i = 0; i < 3000; i++) events.push(makeEvent(now - Math.random() * 3 * 864e5));
events.sort((a, b) => (a.published < b.published ? -1 : 1));
setInterval(() => events.push(makeEvent(Date.now())), 5000);   // a new event every 5s

http.createServer((req, res) => {
  const u = new URL(req.url, "http://localhost:4010");
  const json = (o, h = {}) => { res.writeHead(200, { "content-type": "application/json", ...h }); res.end(JSON.stringify(o)); };
  if (u.pathname === "/api/v1/logs") {
    const since = u.searchParams.get("since") || "1970-01-01T00:00:00.000Z";
    const after = +u.searchParams.get("after") || 0, limit = Math.min(1000, +u.searchParams.get("limit") || 100);
    const pool = events.filter(e => e.published >= since);
    const page = pool.slice(after, after + limit);
    const next = `http://localhost:4010/api/v1/logs?since=${encodeURIComponent(since)}&limit=${limit}&after=${after + page.length}`;
    return json(page, { link: `<${next}>; rel="next"` });
  }
  if (u.pathname === "/api/v1/apps") return json(APPS.concat(["Legacy HR Portal"]).map((l, i) => ({ id: "0oa" + i, label: l, status: "ACTIVE" })));
  res.writeHead(404); res.end("{}");
}).listen(4010, () => console.log("Mock Okta on http://localhost:4010"));
