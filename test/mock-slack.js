// A fake Slack Web API, enough for Sightline's alerts. node test/mock-slack.js   (port MOCK_SLACK_PORT, default 4071; the app uses SLACK_API_BASE=http://localhost:4071/api)
//   POST /api/chat.postMessage   records the message (needs the header "Authorization: Bearer xoxb-test-token")
//   GET  /_posts                 { posts: [what was accepted], attempts: n }
//   GET  /_mode?m=ok|error|ratelimit   error: every post answers channel_not_found; ratelimit: the next post answers 429 (Retry-After: 1) once
//   GET  /_reset                 forget everything
const http = require("http"), PORT = +process.env.MOCK_SLACK_PORT || 4071;
let mode = "ok", posts = [], attempts = 0, limited = false;
http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${PORT}`), json = (o, s = 200, h = {}) => { res.writeHead(s, { "content-type": "application/json", ...h }); res.end(JSON.stringify(o)); };
  if (u.pathname === "/_posts") return json({ posts, attempts });
  if (u.pathname === "/_mode") { mode = u.searchParams.get("m") || "ok"; limited = false; return json({ mode }); }
  if (u.pathname === "/_reset") { posts = []; attempts = 0; limited = false; mode = "ok"; return json({}); }
  if (u.pathname === "/api/chat.postMessage" && req.method === "POST") {
    let b = ""; req.on("data", c => b += c); req.on("end", () => {
      attempts++; let j = {}; try { j = JSON.parse(b); } catch { return json({ ok: false, error: "invalid_json" }); }
      if (req.headers.authorization !== "Bearer xoxb-test-token") return json({ ok: false, error: "invalid_auth" });
      if (mode === "error") return json({ ok: false, error: "channel_not_found" });
      if (mode === "ratelimit" && !limited) { limited = true; return json({ ok: false, error: "ratelimited" }, 429, { "retry-after": "1" }); }
      posts.push({ channel: j.channel, text: j.text, blocks: j.blocks, at: Date.now(), raw: b }); json({ ok: true, ts: String(Date.now() / 1000), channel: j.channel });
    }); return;
  }
  res.writeHead(404); res.end("{}");
}).listen(PORT, () => console.log(`Mock Slack on http://localhost:${PORT}`));
