"use strict";
/*
 * Policy: the exceptions an organisation has decided on, shared by everyone who uses the dashboard.
 *
 *   suppressions  "known errors": a rule that stops matching errors counting and alerting (never silently: the page always
 *                 says how many are hidden, by which rules, and why)
 *   approvals     a decision about a Google app: approved (for exactly the access it had when reviewed) or flagged as not allowed
 *
 * Every change needs a reason, is checked for version conflicts (two admins cannot overwrite each other), and is written to an
 * audit log. State lives in DATA_DIR/policy.json (written atomically) and DATA_DIR/audit.jsonl. If the folder cannot be written the
 * policy still works in memory and says so, because it will not survive a restart.
 */
const fs = require("fs"), path = require("path"), crypto = require("crypto");

const LIMITS = { rules: 300, approvals: 3000, why: 1000, name: 120, ticket: 200, text: 200, list: 20, scopes: 120 };
const CATS = ["signin", "provision", "token", "access", "other"];
const err = (status, message, extra) => Object.assign(new Error(message), { status }, extra || {});
const str = (v, max) => String(v == null ? "" : v).replace(/\s+/g, " ").trim().slice(0, max);
const strList = (v, n, max) => (Array.isArray(v) ? v : []).slice(0, n).map(x => str(x, max)).filter(Boolean);

function cleanMatch(m) {
  m = m || {};
  const out = { cats: strList(m.cats, 5, 20).filter(c => CATS.includes(c)), results: strList(m.results, 2, 10).filter(r => r === "FAILURE" || r === "DENY"),
    apps: strList(m.apps, LIMITS.list, 120), include: str(m.include, LIMITS.text), exclude: str(m.exclude, LIMITS.text), person: str(m.person, 120), eventType: str(m.eventType, 120) };
  // a rule must say WHAT it is about: types of result or "exclude" words alone would hide errors far too widely
  if (!(out.include || out.apps.length || out.person || out.eventType || out.cats.length)) throw err(400, "A rule has to say which errors it is about: a part of the reason, an app, an event type, a person or an error type.");
  return out;
}
function cleanExpiry(v, requireExpiry) {
  if (v === null || v === undefined || v === "") { if (requireExpiry) throw err(400, "This organisation requires every exception to have an expiry date."); return null; }
  const t = Date.parse(v); if (!isFinite(t)) throw err(400, "The expiry date is not a valid date.");
  if (t < Date.now() - 60000) throw err(400, "The expiry date is in the past.");
  if (t > Date.now() + 5 * 365 * 864e5) throw err(400, "The expiry date is more than five years away.");
  return new Date(t).toISOString();
}
const needWhy = v => { const w = str(v, LIMITS.why); if (w.length < 10) throw err(400, "Say why (at least a short sentence). The reason is shown to everyone and kept in the audit log."); return w; };

function createPolicy(opts) {
  const { dir, log, admins = [], requireExpiry = false, verifiedIdentity = false, roleBased = false, onAudit = null } = opts;
  const file = path.join(dir, "policy.json"), auditFile = path.join(dir, "audit.jsonl");
  let state = { version: 0, updatedAt: null, suppressions: [], approvals: [], alertRules: null };
  let persistent = false, writeError = "", memAudit = [];

  try { fs.mkdirSync(dir, { recursive: true }); } catch { /* reported below */ }
  try {
    const raw = JSON.parse(fs.readFileSync(file, "utf8"));
    state = { version: +raw.version || 0, updatedAt: raw.updatedAt || null, suppressions: Array.isArray(raw.suppressions) ? raw.suppressions : [], approvals: Array.isArray(raw.approvals) ? raw.approvals : [], alertRules: Array.isArray(raw.alertRules) ? raw.alertRules : null };
    log("Policy loaded: " + state.suppressions.length + " known-error rules, " + state.approvals.length + " app decisions (version " + state.version + ")");
  } catch (e) { if (e.code !== "ENOENT") log("Policy file could not be read, starting empty: " + e.message); }
  try { fs.accessSync(dir, fs.constants.W_OK); persistent = true; } catch (e) { writeError = "The data folder (" + dir + ") is not writable: " + e.message; log("Policy: " + writeError); }

  function persist() {
    if (!persistent) return;
    try { const tmp = file + "." + process.pid + ".tmp"; fs.writeFileSync(tmp, JSON.stringify(state, null, 1)); fs.renameSync(tmp, file); writeError = ""; }
    catch (e) { persistent = false; writeError = "Saving failed: " + e.message; log("Policy: " + writeError); }
  }
  function audit(actor, action, target, before, after, why) {
    const row = { ts: new Date().toISOString(), actor: actor.name, verified: !!actor.verified, action, target, before: before === undefined ? null : before, after: after === undefined ? null : after, why: why || "" };
    memAudit.push(row); if (memAudit.length > 1000) memAudit.shift();
    if (onAudit) { try { onAudit(row, actor); } catch (e) { log("Policy: audit hook failed: " + e.message); } }
    if (persistent) {
      try { if (fs.existsSync(auditFile) && fs.statSync(auditFile).size > 5e6) fs.renameSync(auditFile, auditFile + ".1"); fs.appendFileSync(auditFile, JSON.stringify(row) + "\n"); }
      catch (e) { log("Policy: could not write the audit log: " + e.message); }
    }
  }
  const canEdit = actor => roleBased ? (actor.role === "admin" || actor.role === "owner") : (!admins.length || !verifiedIdentity ? true : admins.includes(String(actor.name).toLowerCase()) && actor.verified);
  function snapshot(actor) {
    return { suppressions: state.suppressions, approvals: state.approvals, alertRules: roleBased ? state.alertRules : null,
      meta: { version: state.version, updatedAt: state.updatedAt, persistent, writeError, canEdit: canEdit(actor), actor: { name: actor.name, verified: !!actor.verified, role: actor.role || null }, requireExpiry,
        rolesEnforced: !!(roleBased || (admins.length && verifiedIdentity)), roleBased, role: actor.role || null, alertRulesShared: !!(roleBased && state.alertRules), adminsConfigured: admins.length > 0, identityVerified: !!actor.verified } };
  }
  // run a change: permission, version check, apply, save, audit
  function change(actor, baseVersion, fn) {
    if (!canEdit(actor)) throw err(403, "You can see the policy but not change it. Ask an administrator.");
    // every change must be attributable: if sign-in cannot say who this is, the person has to say (and the log marks it unverified)
    if (!actor.verified && (!actor.name || actor.name === "unknown")) throw err(400, "Enter your name first, so the audit log can say who made this change.");
    if (baseVersion !== undefined && baseVersion !== null && +baseVersion !== state.version) throw err(409, "Someone else changed the policy while you were editing. Reload and try again.", { current: snapshot(actor) });
    const result = fn();
    state.version++; state.updatedAt = new Date().toISOString(); persist();
    return Object.assign(snapshot(actor), { result });
  }
  const findRule = id => state.suppressions.find(r => r.id === id) || (() => { throw err(404, "That rule no longer exists."); })();
  const clone = o => JSON.parse(JSON.stringify(o));

  const RULE_TYPES = ["spike", "new", "silent", "gnew", "grisk", "gspike", "gdrift", "gflag"];
  const num = (v, lo, hi, d) => { v = +v; return isFinite(v) ? Math.max(lo, Math.min(hi, Math.round(v))) : d; };
  function cleanFilter(f) { f = f || {}; return { cats: strList(f.cats, 5, 20).filter(c => CATS.includes(c)), results: strList(f.results, 2, 10).filter(r => r === "FAILURE" || r === "DENY"), apps: strList(f.apps, LIMITS.list, 120), include: str(f.include, LIMITS.text), exclude: str(f.exclude, LIMITS.text), person: str(f.person, 120) }; }
  function cleanRule(r) {
    if (!r || typeof r !== "object") throw err(400, "An alert rule is not valid.");
    const id = str(r.id, 40); if (!/^[\w-]{1,40}$/.test(id)) throw err(400, "An alert rule needs a simple id.");
    const type = RULE_TYPES.includes(r.type) ? r.type : (() => { throw err(400, "Unknown alert type: " + str(r.type, 30)); })();
    return { id, name: str(r.name, LIMITS.name) || type, type, enabled: r.enabled !== false, filter: cleanFilter(r.filter), n: num(r.n, 1, 100000, 10), by: ["total", "app", "person"].includes(r.by) ? r.by : "total", windowMin: num(r.windowMin, 1, 43200, 60), cooldownMin: num(r.cooldownMin, 0, 43200, 60), minRisk: ["any", "medium", "high"].includes(r.minRisk) ? r.minRisk : "any", gApp: str(r.gApp, 120) };
  }
  return {
    snapshot,
    setAlertRules(actor, baseVersion, rules, why) {
      if (!roleBased) throw err(409, "Shared alert rules need single sign-on to be set up.");
      return change(actor, baseVersion, () => {
        if (!Array.isArray(rules) || rules.length > 200) throw err(400, "Send between 0 and 200 alert rules.");
        const next = rules.map(cleanRule), ids = new Set(next.map(r => r.id)); if (ids.size !== next.length) throw err(400, "Two alert rules have the same id.");
        const prev = state.alertRules, byId = new Map((prev || []).map(r => [r.id, r])), note = str(why, LIMITS.why);
        if (!prev) audit(actor, "alertrules.publish", "alert-rules", null, { count: next.length, names: next.map(r => r.name).slice(0, 30) }, note || "Alert rules published for everyone");
        else {
          for (const r of next) { const o = byId.get(r.id); if (!o) audit(actor, "alertrule.create", r.id, null, r, note); else if (JSON.stringify(o) !== JSON.stringify(r)) { const onlyOn = JSON.stringify({ ...o, enabled: r.enabled }) === JSON.stringify(r); audit(actor, onlyOn ? (r.enabled ? "alertrule.enable" : "alertrule.disable") : "alertrule.update", r.id, o, r, note); } }
          for (const o of prev) if (!ids.has(o.id)) audit(actor, "alertrule.delete", o.id, o, null, note);
        }
        state.alertRules = next; return { count: next.length };
      });
    },
    createSuppression(actor, baseVersion, input) {
      return change(actor, baseVersion, () => {
        if (state.suppressions.length >= LIMITS.rules) throw err(400, "There are already " + LIMITS.rules + " rules. Remove ones you no longer need.");
        const now = new Date().toISOString();
        const r = { id: "s-" + crypto.randomBytes(5).toString("hex"), name: str(input && input.name, LIMITS.name), match: cleanMatch(input && input.match), why: needWhy(input && input.why), ticket: str(input && input.ticket, LIMITS.ticket),
          enabled: true, expiresAt: cleanExpiry(input && input.expiresAt, requireExpiry), createdBy: actor.name, createdVerified: !!actor.verified, createdAt: now, updatedBy: null, updatedAt: null };
        state.suppressions.push(r); audit(actor, "suppression.create", r.id, null, r, r.why); return r;
      });
    },
    updateSuppression(actor, baseVersion, id, patch) {
      return change(actor, baseVersion, () => {
        const r = findRule(id), before = clone(r); patch = patch || {};
        if (patch.name !== undefined) r.name = str(patch.name, LIMITS.name);
        if (patch.match !== undefined) r.match = cleanMatch(patch.match);
        if (patch.why !== undefined) r.why = needWhy(patch.why);
        if (patch.ticket !== undefined) r.ticket = str(patch.ticket, LIMITS.ticket);
        if (patch.expiresAt !== undefined) r.expiresAt = cleanExpiry(patch.expiresAt, requireExpiry);
        if (patch.enabled !== undefined) r.enabled = !!patch.enabled;
        r.updatedBy = actor.name; r.updatedAt = new Date().toISOString();
        audit(actor, patch.enabled === false && before.enabled ? "suppression.disable" : patch.enabled === true && !before.enabled ? "suppression.enable" : "suppression.update", r.id, before, r, patch.why !== undefined ? r.why : ""); return r;
      });
    },
    deleteSuppression(actor, baseVersion, id, why) {
      return change(actor, baseVersion, () => {
        const r = findRule(id); state.suppressions = state.suppressions.filter(x => x.id !== id); audit(actor, "suppression.delete", id, r, null, str(why, LIMITS.why)); return { id };
      });
    },
    upsertApproval(actor, baseVersion, input) {
      return change(actor, baseVersion, () => {
        input = input || {}; const clientId = str(input.clientId, 300); if (!clientId) throw err(400, "Which app is this about?");
        const status = input.status === "flagged" ? "flagged" : input.status === "approved" ? "approved" : (() => { throw err(400, "The decision must be 'approved' or 'flagged'."); })();
        const i = state.approvals.findIndex(a => a.clientId === clientId);
        if (i < 0 && state.approvals.length >= LIMITS.approvals) throw err(400, "Too many app decisions are stored.");
        const a = { clientId, appName: str(input.appName, 200), status, scopes: strList(input.scopes, 200, LIMITS.scopes + 100), why: needWhy(input.why), ticket: str(input.ticket, LIMITS.ticket),
          expiresAt: status === "approved" ? cleanExpiry(input.expiresAt, requireExpiry) : null, decidedBy: actor.name, decidedVerified: !!actor.verified, decidedAt: new Date().toISOString() };
        const before = i >= 0 ? clone(state.approvals[i]) : null; if (i >= 0) state.approvals[i] = a; else state.approvals.push(a);
        audit(actor, "app." + status, clientId, before, a, a.why); return a;
      });
    },
    deleteApproval(actor, baseVersion, clientId, why) {
      return change(actor, baseVersion, () => {
        const i = state.approvals.findIndex(a => a.clientId === clientId); if (i < 0) throw err(404, "That app has no decision to remove.");
        const before = state.approvals[i]; state.approvals.splice(i, 1); audit(actor, "app.remove", clientId, before, null, str(why, LIMITS.why)); return { clientId };
      });
    },
    audit(limit) {
      limit = Math.max(1, Math.min(1000, +limit || 200)); let rows = memAudit;
      if (persistent) { try { const lines = fs.readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean); rows = lines.slice(-limit).map(l => JSON.parse(l)); } catch { rows = memAudit; } }
      return rows.slice(-limit).reverse();
    },
    LIMITS
  };
}
module.exports = { createPolicy, cleanMatch, LIMITS };
