"use strict";
// Tiny stand-in for the Anthropic Messages API, to test the assistant's tool loop offline:
//   node test/fake-anthropic.js   then run the app with ANTHROPIC_BASE_URL=http://localhost:4020
const http = require("http");
http.createServer((q, r) => {
  let b = "";
  q.on("data", c => (b += c)).on("end", () => {
    const j = JSON.parse(b);
    const last = j.messages[j.messages.length - 1];
    r.writeHead(200, { "content-type": "application/json" });
    if (Array.isArray(last.content) && last.content[0].type === "tool_result")
      r.end(JSON.stringify({ stop_reason: "end_turn", content: [{ type: "text", text: "TOOL RESULT SEEN: " + last.content[0].content.slice(0, 160) }] }));
    else
      r.end(JSON.stringify({ stop_reason: "tool_use", content: [{ type: "tool_use", id: "t1", name: "query_events", input: { app: "ServiceNow", result: "ANY_FAILURE", limit: 2 } }] }));
  });
}).listen(4020, () => console.log("Fake Anthropic on http://localhost:4020"));
