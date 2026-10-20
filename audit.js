"use strict";
/*
 * One audit log for everything that matters: sign-ins and failures, access denied, sign-outs, ended sessions, policy changes and
 * alert-rule changes. Append-only JSON lines in DATA_DIR/audit-log.jsonl (rotated at 5 MB), and also printed to the container log as
 * "AUDIT {json}" so a log shipper (Splunk, Datadog, Elastic...) can pick it up without touching the file.
 */
const fs = require("fs"), path = require("path");

function createAudit({ dir, log, stdout = true }) {
  // NOT audit.jsonl: that is the policy store's own, older, differently shaped history file
  const file = path.join(dir, "audit-log.jsonl"); let persistent = false; const mem = [];
  try { fs.mkdirSync(dir, { recursive: true }); fs.accessSync(dir, fs.constants.W_OK); persistent = true; } catch { /* memory only */ }
  const clip = (v, n) => String(v == null ? "" : v).slice(0, n);

  function write(e) {
    const a = e.actor || null;
    const row = { ts: new Date().toISOString(), cat: e.cat || "system", action: clip(e.action, 60), ok: e.ok !== false,
      actor: a ? { name: clip(a.name, 120), email: clip(a.email, 120), role: clip(a.role, 20), verified: !!a.verified, via: clip(a.via, 20) } : null,
      ip: clip(e.ip, 64), ua: clip(e.ua, 160), target: clip(e.target, 300), detail: clip(e.detail, 500), why: clip(e.why, 1000),
      before: e.before === undefined ? null : e.before, after: e.after === undefined ? null : e.after };
    mem.push(row); if (mem.length > 3000) mem.shift();
    if (stdout) { try { process.stdout.write("AUDIT " + JSON.stringify(row) + "\n"); } catch { /* ignore */ } }
    if (persistent) {
      try { if (fs.existsSync(file) && fs.statSync(file).size > 5e6) fs.renameSync(file, file + ".1"); fs.appendFileSync(file, JSON.stringify(row) + "\n"); }
      catch (err) { log("Audit: could not write the audit log: " + err.message); }
    }
    return row;
  }
  // newest first; filter by category, actor (email or name, contains), action (contains), and a "since" time
  function read({ limit = 200, cat, actor, action, since } = {}) {
    limit = Math.max(1, Math.min(2000, +limit || 200)); let rows = mem;
    if (persistent) { try { rows = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).slice(-20000).map(l => JSON.parse(l)); } catch { rows = mem; } }
    const a = String(actor || "").toLowerCase(), act = String(action || "").toLowerCase(), t0 = since ? Date.parse(since) : 0;
    const out = []; for (let i = rows.length - 1; i >= 0 && out.length < limit; i--) {
      const r = rows[i];
      if (cat && r.cat !== cat) continue; if (act && !String(r.action).toLowerCase().includes(act)) continue; if (t0 && Date.parse(r.ts) < t0) continue;
      if (a && !(((r.actor && (r.actor.email + " " + r.actor.name)) || "").toLowerCase().includes(a))) continue;
      out.push(r);
    }
    return out;
  }
  return { write, read, persistent: () => persistent };
}
module.exports = { createAudit };
