"use strict";
/*
 * The shared alerts (too many errors, a new kind of error, an app goes silent, and the Google alerts), checked on the SERVER around the clock,
 * so they fire with nobody looking at the page, once for everyone, and can be posted to Slack.
 *
 * The checks themselves are not here. They are in public/alerts-core.js, the same file the page loads, so the page and the server can never
 * disagree about when an alert fires. This file only: gives those checks the server's data, remembers what already fired (the cooldowns and the
 * baseline of silent apps) so a restart never repeats an alert, and keeps the alerts that were raised.
 *
 * Location alerts are separate (geo.js): they look at each new sign-in event as it arrives, which is a different job.
 */
const fs = require("fs"), path = require("path"), crypto = require("crypto");
const core = require("./public/alerts-core.js");

const KEEP = 500;

function createAlerts({ dir, log }) {
  const file = path.join(dir, "alerts-state.json");
  let alerts = [], astate = { fired: {}, silent: null }, persistent = false, timer = null, dirty = false, lastRun = null, lastCount = 0;
  try { fs.mkdirSync(dir, { recursive: true }); fs.accessSync(dir, fs.constants.W_OK); persistent = true; } catch { /* memory only: cooldowns will not survive a restart */ }
  try {
    const raw = JSON.parse(fs.readFileSync(file, "utf8"));
    alerts = Array.isArray(raw.alerts) ? raw.alerts.slice(0, KEEP) : [];
    if (raw.astate && typeof raw.astate === "object") astate = { fired: raw.astate.fired && typeof raw.astate.fired === "object" ? raw.astate.fired : {}, silent: Array.isArray(raw.astate.silent) ? raw.astate.silent : null };
    log("Shared alerts loaded: " + alerts.length + " recent alerts, " + Object.keys(astate.fired).length + " cooldowns");
  } catch (e) { if (e.code !== "ENOENT") log("Shared alerts file could not be read, starting empty: " + e.message); }

  function flush() {
    if (!persistent || !dirty) return; dirty = false; clearTimeout(timer); timer = null;
    try { const tmp = file + "." + process.pid + ".tmp"; fs.writeFileSync(tmp, JSON.stringify({ alerts, astate }), { mode: 0o600 }); fs.renameSync(tmp, file); }
    catch (e) { persistent = false; log("Shared alerts: could not save (" + e.message + "); cooldowns will not survive a restart."); }
  }
  const save = () => { dirty = true; if (!timer) { timer = setTimeout(flush, 1500); if (timer.unref) timer.unref(); } };

  // input: { rules, events, catchingUp, supOf, silentNames, google: {configured, events, approvals}, googleApps, now }
  function evaluate(input) {
    const now = input.now || Date.now(), rules = input.rules || [];
    lastRun = new Date(now).toISOString();
    const ctx = { events: input.events, supOf: input.supOf, catchingUp: !!input.catchingUp, astate, silentNames: input.silentNames, google: input.google, googleApps: input.googleApps,
      onError: (r, err) => log("Alert \"" + r.name + "\" could not be checked: " + (err && err.message)) };
    const notifs = core.runRules(rules, ctx, now), byId = new Map(rules.map(r => [r.id, r])), out = [];
    for (const n of notifs) {
      const r = byId.get(n.ruleId) || {};
      const a = { id: "sa_" + crypto.randomBytes(5).toString("hex"), createdAt: new Date(now).toISOString(), ts: now, ruleId: n.ruleId, ruleName: n.ruleName, type: n.type, severity: n.sev,
        title: n.title, body: n.body, link: n.link, slack: r.slack ? { state: "queued", channel: r.channel || "" } : { state: "off" } };
      alerts.unshift(a); out.push(a);
    }
    if (alerts.length > KEEP) alerts.length = KEEP;
    lastCount = out.length; save();                       // the cooldowns and the silent baseline change on every run, so they are saved too
    return out;
  }

  const recent = since => { const t = since ? Date.parse(since) : 0; return alerts.filter(a => !t || Date.parse(a.createdAt) > t).slice(0, 200); };
  function setSlack(id, patch) { const a = alerts.find(x => x.id === id); if (a) { a.slack = Object.assign({}, a.slack, patch); save(); } return a || null; }
  const status = () => ({ lastRun, raisedLastRun: lastCount, alerts: alerts.length, cooldowns: Object.keys(astate.fired).length, persistent });
  return { evaluate, recent, setSlack, status, flush };
}
module.exports = { createAlerts };
