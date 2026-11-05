// Logic tests for the shared alert checks (public/alerts-core.js) and the server engine (alerts.js), no servers needed.   node test/alerts-unit.js
const fs = require("fs"), os = require("os"), path = require("path");
const core = require("../public/alerts-core.js"), { createAlerts } = require("../alerts");
let pass = 0, fail = 0;
const ok = (name, cond, extra) => { if (cond) { pass++; console.log("PASS  " + name); } else { fail++; console.log("FAIL  " + name + (extra ? "  (" + extra + ")" : "")); } };
const NOW = Date.parse("2026-10-20T12:00:00Z"), MIN = 60000, HR = 3600000;
let seq = 0;
const ev = (o = {}) => ({ id: "e" + (++seq), published: new Date(NOW - (o.ago == null ? 5 : o.ago) * MIN).toISOString(), eventType: o.type || "application.provision.user.push", displayMessage: "", severity: "WARN",
  outcome: { result: o.result || "FAILURE", reason: o.reason == null ? "Push failed" : o.reason }, actor: { type: "User", id: "u1", alternateId: o.user || "a@x.test", displayName: "A" },
  target: [{ type: "AppInstance", displayName: o.app || "ServiceNow", id: "0oa1" }].concat(o.user ? [{ type: "User", alternateId: o.user, id: "u" }] : []) });
const rule = (o = {}) => Object.assign({ id: "r1", name: "Rule", type: "spike", enabled: true, filter: core.emptyFilter(), n: 3, by: "total", windowMin: 60, cooldownMin: 60 }, o);
const ctxOf = (o = {}) => Object.assign({ events: [], supOf: null, catchingUp: false, astate: { fired: {}, silent: null }, silentNames: () => [], google: { configured: false, events: [], approvals: [] }, googleApps: () => [] }, o);
const run = (rules, ctx, now = NOW) => core.runRules(rules, ctx, now);
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "al-"));
const log = () => {};

console.log("--- too many errors ---");
{
  const E = [ev(), ev(), ev()], out = run([rule()], ctxOf({ events: E }));
  ok("three errors in the hour raise one alert, and say how many", out.length === 1 && /3 errors in the last hour/.test(out[0].body) && out[0].ruleId === "r1" && out[0].type === "spike");
  ok("two errors are not enough", run([rule()], ctxOf({ events: [ev(), ev()] })).length === 0);
  ok("errors older than the window do not count", run([rule()], ctxOf({ events: [ev({ ago: 90 }), ev({ ago: 80 }), ev({ ago: 70 })] })).length === 0);
  ok("successes do not count", run([rule()], ctxOf({ events: [ev({ result: "SUCCESS" }), ev({ result: "SUCCESS" }), ev({ result: "SUCCESS" })] })).length === 0);
  ok("an alert that is switched off raises nothing", run([rule({ enabled: false })], ctxOf({ events: E })).length === 0);
  ok("a high count is marked more serious (twice the limit is 'bad')", run([rule()], ctxOf({ events: [ev(), ev(), ev(), ev(), ev(), ev()] }))[0].sev === "bad" && out[0].sev === "warn");
  const byApp = run([rule({ by: "app", n: 2 })], ctxOf({ events: [ev({ app: "A" }), ev({ app: "A" }), ev({ app: "B" })] }));
  ok("counting per app alerts for the app that has enough, and names it", byApp.length === 1 && /^A: /.test(byApp[0].body));
  const byPerson = run([rule({ by: "person", n: 2 })], ctxOf({ events: [ev({ user: "p@x.test" }), ev({ user: "p@x.test" }), ev({ user: "q@x.test" })] }));
  ok("counting per person alerts for the person who has enough", byPerson.length === 1 && /^p@x\.test: /.test(byPerson[0].body));
  const f = core.emptyFilter(); f.apps = ["ServiceNow"];
  ok("a filter by app only counts that app", run([rule({ filter: f })], ctxOf({ events: [ev({ app: "Other" }), ev({ app: "Other" }), ev({ app: "Other" })] })).length === 0 && run([rule({ filter: f })], ctxOf({ events: E })).length === 1);
  const g = core.emptyFilter(); g.include = "boom";
  ok("a filter by words only counts errors that contain them", run([rule({ filter: g })], ctxOf({ events: [ev({ reason: "Boom here" }), ev({ reason: "boom again" }), ev({ reason: "BOOM!" })] })).length === 1 && run([rule({ filter: g })], ctxOf({ events: E })).length === 0);
  const sup = e => /Push failed/.test(e.outcome.reason) ? { id: "k1" } : null;
  ok("errors hidden by a known-error rule do not count", run([rule()], ctxOf({ events: E, supOf: sup })).length === 0);
}

console.log("--- cooldowns ---");
{
  const E = [ev(), ev(), ev()], long = rule({ windowMin: 120 }), c = ctxOf({ events: E });
  ok("the same alert is not raised again inside its cooldown", run([long], c).length === 1 && run([long], c, NOW + 30 * MIN).length === 0);
  ok("... and is raised again once the cooldown (an hour) has passed", run([long], c, NOW + 61 * MIN).length === 1);
  const short = rule({ windowMin: 120, cooldownMin: 10 }), c2 = ctxOf({ events: E }); run([short], c2);
  ok("a shorter cooldown lets it repeat sooner, but not before it ends", run([short], c2, NOW + 5 * MIN).length === 0 && run([short], c2, NOW + 11 * MIN).length === 1);
  const many = []; for (let i = 0; i < 8; i++) for (let k = 0; k < 3; k++) many.push(ev({ app: "App" + i }));
  const out = run([rule({ by: "app", n: 3 })], ctxOf({ events: many }));
  ok("at most five alerts per rule per check, with a note about the rest", out.length === 5 && /\(\+3 more\)/.test(out[4].body));
}

console.log("--- a new kind of error ---");
{
  const old = [ev({ ago: 300, reason: "Known problem" }), ev({ ago: 250, reason: "Known problem" })], recent = [ev({ ago: 5, reason: "Known problem" }), ev({ ago: 4, reason: "Something never seen before" })];
  const r = rule({ type: "new", windowMin: 60 }), out = run([r], ctxOf({ events: old.concat(recent) }));
  ok("an error that is not in the earlier history is called new", out.length === 1 && /^New: Something never seen before/.test(out[0].body) && out[0].type === "new");
  ok("... an error that was seen before is not", !out.some(n => /Known problem/.test(n.body)));
  ok("it stays quiet while old history is still loading", run([r], ctxOf({ events: old.concat(recent), catchingUp: true })).length === 0);
  ok("it stays quiet when there is no earlier history to compare with", run([r], ctxOf({ events: recent })).length === 0);
  ok("ids in the text do not make the same error look new", run([r], ctxOf({ events: [ev({ ago: 300, reason: 'User "0123456789abcdef01234567" blocked' }), ev({ ago: 4, reason: 'User "fedcba9876543210fedcba98" blocked' })] })).length === 0);
}

console.log("--- an app goes silent ---");
{
  const r = rule({ type: "silent", cooldownMin: 0 }), c = ctxOf({ silentNames: () => ["Old app"] });
  ok("the first check only remembers what is silent: it says nothing", run([r], c).length === 0 && JSON.stringify(c.astate.silent) === '["Old app"]');
  c.silentNames = () => ["Old app", "Newly quiet app"];
  const out = run([r], c, NOW + MIN);
  ok("a newly silent app raises an alert, and only that app", out.length === 1 && /Newly quiet app/.test(out[0].body) && !/Old app/.test(out[0].body) && out[0].sev === "info");
  ok("... and it is remembered, so the next check is quiet", run([r], c, NOW + 2 * MIN).length === 0);
  ok("it stays quiet while old history is loading", run([r], ctxOf({ silentNames: () => ["X"], catchingUp: true, astate: { fired: {}, silent: [] } })).length === 0);
}

console.log("--- Google apps ---");
{
  const hr = k => NOW - k * HR, g = (o) => Object.assign({ type: "authorize", actor: "p@x.test", app: "Notes", clientId: "c1", scopes: ["openid"], count: 1, time: hr(1) }, o);
  const events = [g({ clientId: "old", app: "Old app", time: hr(300) }), g({ time: hr(1) }), g({ actor: "q@x.test", time: hr(0.5), scopes: ["https://www.googleapis.com/auth/drive"] })];
  const gctx = (ap = [], ev2 = events) => ctxOf({ google: { configured: true, events: ev2, approvals: ap }, googleApps: () => core.googleAppsFrom(ev2) });
  ok("scopes are rated: sign-in is low, the whole Drive is high", core.scopeInfo("openid").risk === "low" && core.scopeInfo("https://www.googleapis.com/auth/drive").risk === "high" && core.scopeInfo("something/unknown").known === false);
  const apps = core.googleAppsFrom(events), notes = apps.find(a => a.key === "c1");
  ok("apps are worked out from the events: people, the riskiest access, newest first", notes.people.length === 2 && notes.rank === 3 && notes.riskName === "high" && apps[0].key === "c1");
  const gnew = run([rule({ type: "gnew", windowMin: 1440, minRisk: "any", id: "g1" })], gctx());
  ok("a Google app first authorized in the window raises an alert, naming it and the risk", gnew.length === 1 && /Notes was authorized by 2 people/.test(gnew[0].body) && /high-risk/.test(gnew[0].body) && gnew[0].sev === "bad");
  ok("... and it knows where to send you (the Google page, for that app)", gnew[0].link.view === "google" && gnew[0].link.app === "c1");
  ok("an app that is old is not new", !gnew.some(n => /Old app/.test(n.body)));
  ok("an app approved for the access it has raises no alert", run([rule({ type: "gnew", windowMin: 1440, id: "g1" })], gctx([{ clientId: "c1", status: "approved", scopes: ["openid", "https://www.googleapis.com/auth/drive"] }])).length === 0);
  const drift = run([rule({ type: "gdrift", id: "g2", windowMin: 1440 })], gctx([{ clientId: "c1", status: "approved", scopes: ["openid"] }]));
  ok("an approved app that now has MORE access raises a 'drift' alert naming the extra access", drift.length === 1 && /approved, but it now also asks for: .*drive/.test(drift[0].body));
  const flag = run([rule({ type: "gflag", id: "g3", windowMin: 1440 })], gctx([{ clientId: "c1", status: "flagged", scopes: [] }]));
  ok("an app marked not allowed alerts when someone authorizes it", flag.length === 1 && /marked not allowed/.test(flag[0].body) && flag[0].sev === "bad");
  const risk = run([rule({ type: "grisk", id: "g4", windowMin: 1440, minRisk: "high" })], gctx());
  ok("high-risk access granted raises an alert listing the access", risk.length === 1 && /was granted drive by 1 person/.test(risk[0].body));
  const spike = run([rule({ type: "gspike", id: "g5", windowMin: 1440, n: 2, minRisk: "any" })], gctx());
  ok("many people authorizing the same app raises an alert", spike.length === 1 && /2 people authorized it/.test(spike[0].body));
  ok("nothing happens when Google is not connected", run([rule({ type: "gnew", id: "g1" })], ctxOf()).length === 0);
}

console.log("--- the server engine ---");
{
  const dir = tmp(), E = [ev(), ev(), ev()], inp = o => Object.assign({ rules: [rule({ slack: true, channel: "#errs" })], events: E, supOf: null, catchingUp: false, silentNames: () => [], google: { configured: false, events: [], approvals: [] }, googleApps: () => [], now: NOW }, o || {});
  const a1 = createAlerts({ dir, log }), out = a1.evaluate(inp());
  ok("it raises the alert, with a title, a body, a severity and a link, and queues it for Slack", out.length === 1 && out[0].title === "Rule" && /3 errors/.test(out[0].body) && out[0].severity === "warn" && out[0].link.view === "errors" && out[0].slack.state === "queued" && out[0].slack.channel === "#errs");
  ok("an alert that is not routed to Slack says so", createAlerts({ dir: tmp(), log }).evaluate(inp({ rules: [rule()] }))[0].slack.state === "off");
  ok("it can be asked for what is recent, newest first", a1.recent().length === 1 && a1.recent(new Date(NOW + HR).toISOString()).length === 0);
  a1.setSlack(out[0].id, { state: "sent" }); a1.flush();
  const a2 = createAlerts({ dir, log });
  ok("after a restart the alerts and their Slack state are still there", a2.recent().length === 1 && a2.recent()[0].slack.state === "sent");
  ok("... and the cooldown is remembered, so the same alert is not raised again", a2.evaluate(inp({ now: NOW + 5 * MIN })).length === 0);
  ok("the file is private", (fs.statSync(path.join(dir, "alerts-state.json")).mode & 0o077) === 0);
  const a3 = createAlerts({ dir: tmp(), log }); const bad = rule({ id: "bad", type: "spike", filter: null });
  ok("one rule that cannot be checked does not stop the others", a3.evaluate(inp({ rules: [Object.assign(bad, { filter: { cats: 5 } }), rule({ id: "good" })] })).some(a => a.ruleId === "good"));
  ok("its status says when it last ran and what it holds", /^2026/.test(a1.status().lastRun) && a1.status().alerts === 1);
}

console.log("\n" + pass + " passed, " + fail + " failed");
process.exit(fail ? 1 : 0);
