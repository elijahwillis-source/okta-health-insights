"use strict";
// Tiny stand-in for the Anthropic Messages API, to test the assistant's tool loop offline:
//   node test/fake-anthropic.js   then run the app with ANTHROPIC_BASE_URL=http://localhost:4020
const http = require("http");
http.createServer((q, r) => {
  if (q.method === "GET" && q.url === "/_last") { r.writeHead(200, { "content-type": "application/json" }); return r.end(JSON.stringify({ system: global.__lastChatSystem || "" })); }   // test hook: the instructions of the last chat request
  let b = "";
  q.on("data", c => (b += c)).on("end", () => {
    const j = JSON.parse(b);
    if (typeof j.system === "string" && !j.system.includes("explaining ONE error")) global.__lastChatSystem = j.system;
    const last = j.messages[j.messages.length - 1];
    const first = JSON.stringify(j.messages[0]);
    const lastIsToolResult = Array.isArray(last.content) && last.content[0] && last.content[0].type === "tool_result";
    const lastIsNudge = typeof last.content === "string" && last.content.includes("Please answer now");
    r.writeHead(200, { "content-type": "application/json" });
    if (typeof j.system === "string" && j.system.includes("explaining ONE error") && !first.includes("EXPLAIN-TEST")) {
      global.__x = (global.__x || 0) + 1; const t = (/Error text: "([^"]*)"/.exec(String(j.messages[0].content)) || [, "?"])[1];
      return r.end(JSON.stringify({ stop_reason: "end_turn", content: [{ type: "text", text: "**What it means**: Fake explanation #" + global.__x + " for: " + t.slice(0, 70) + "\n**Likely causes**:\n- The target app rejected the request\n- A mapping is out of date\n**How to fix**:\n1. Open Applications > Applications > [app] > Provisioning\n2. Retry the push for the person\n**How to confirm**: the System Log event shows SUCCESS." }] }));
    }
    if (first.includes("EXPLAIN-TEST")) { global.__n = (global.__n || 0) + 1; return r.end(JSON.stringify({ stop_reason: "end_turn", content: [{ type: "text", text: "**What it means**: EXPLAIN OK call#" + global.__n + "\n**How to fix**:\n1. Check the app" }] })); }
    const toolCall = () => ({ stop_reason: "tool_use", content: [{ type: "tool_use", id: "t9", name: "query_events", input: { result: "ANY_FAILURE", limit: 1 } }] });
    if (first.includes("always-empty")) return r.end(JSON.stringify(lastIsToolResult || lastIsNudge ? { stop_reason: "end_turn", content: [] } : toolCall()));
    if (first.includes("empty-reply")) return r.end(JSON.stringify(lastIsNudge ? { stop_reason: "end_turn", content: [{ type: "text", text: "RECOVERED" }] } : lastIsToolResult ? { stop_reason: "end_turn", content: [] } : toolCall()));
    if (first.includes("cutoff")) return r.end(JSON.stringify(lastIsToolResult ? { stop_reason: "max_tokens", content: [{ type: "text", text: "PARTIAL ANSWER" }] } : toolCall()));
    if (Array.isArray(last.content) && last.content[0].type === "tool_result")
      r.end(JSON.stringify({ stop_reason: "end_turn", content: [{ type: "text", text: "TOOL RESULT SEEN: " + last.content[0].content.slice(0, 160) }] }));
    else if (JSON.stringify(j.messages[0]).includes("lookup-app"))    // ask for the live per-app errors tool
      r.end(JSON.stringify({ stop_reason: "tool_use", content: [{ type: "tool_use", id: "t3", name: "lookup_app_errors", input: { app: "ServiceNow", days: 7 } }] }));
    else if (JSON.stringify(j.messages[0]).includes("lookup-user"))   // ask for the live per-user search tool
      r.end(JSON.stringify({ stop_reason: "tool_use", content: [{ type: "tool_use", id: "t2", name: "lookup_user_events", input: { user: "user07@example.com", days: 7 } }] }));
    else
      r.end(JSON.stringify({ stop_reason: "tool_use", content: [{ type: "tool_use", id: "t1", name: "query_events", input: { app: "ServiceNow", result: "ANY_FAILURE", limit: 2 } }] }));
  });
}).listen(4020, () => console.log("Fake Anthropic on http://localhost:4020"));
