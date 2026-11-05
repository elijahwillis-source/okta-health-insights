"use strict";
/*
 * Location alerts: tell people when sign-ins, failed sign-ins, invalid passwords or MFA failures come from places they care about
 * ("from these places" for a watch list of regions, or "from anywhere except these" for a list of places you expect).
 *
 * These are worked out HERE, on the server, as each new event arrives, so they fire with nobody looking at the page, once, for everyone.
 * (The older alert rules are worked out in each person's browser.) What this file does:
 *   - normalizeRule: one place that decides what a valid rule is (the policy store calls it when rules are saved)
 *   - evaluate:      look at newly arrived events, decide which rules fire, remember what already fired (so a restart never repeats)
 *   - simulate:      the same decision over the events we hold, so a rule can be tried before it is saved
 *   - places:        which countries the held events come from, to help choose what to watch
 * Events with no known location are ignored (an internal address has no country, so it can neither match nor be "outside").
 * Only events from the last GEO_MAX_AGE_MINUTES count as news: after a restart the history reloads, and that must not alert again.
 */
const fs = require("fs"), path = require("path"), crypto = require("crypto");

const err = (status, message) => Object.assign(new Error(message), { status });
const clip = (v, n) => String(v == null ? "" : v).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const fold = s => String(s == null ? "" : s).normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^\p{L}\p{N}'., -]/gu, " ").replace(/\s+/g, " ").trim();
const title = s => s.replace(/(^|[ -])(\p{L})/gu, (m, a, b) => a + b.toUpperCase());
const MIN = 60000;
const winTxt = m => m < 60 ? m + " minutes" : m % 60 === 0 ? (m === 60 ? "1 hour" : (m / 60) + " hours") : m + " minutes";

/* Okta spells countries one way, people type another ("RU", "Russian Federation"). Both sides are folded to one name before comparing.
 * Each row: the name Okta uses first, then the other spellings. Anything not listed is compared as typed (ignoring case and accents). */
const COUNTRY_GROUPS = [
  ["united states", "us", "usa", "u.s.", "u.s.a.", "united states of america", "america"], ["united kingdom", "uk", "gb", "great britain", "britain"],
  ["russia", "ru", "russian federation"], ["china", "cn", "prc", "people's republic of china", "mainland china"], ["iran", "ir", "islamic republic of iran"],
  ["north korea", "kp", "democratic people's republic of korea", "korea, democratic people's republic of"], ["south korea", "kr", "republic of korea", "korea, republic of"],
  ["syria", "sy", "syrian arab republic"], ["belarus", "by"], ["venezuela", "ve"], ["cuba", "cu"], ["myanmar", "mm", "burma"], ["afghanistan", "af"], ["iraq", "iq"],
  ["libya", "ly"], ["sudan", "sd"], ["somalia", "so"], ["yemen", "ye"], ["ukraine", "ua"], ["vietnam", "vn", "viet nam"], ["czechia", "cz", "czech republic"],
  ["turkey", "tr", "turkiye"], ["united arab emirates", "ae", "uae"], ["germany", "de"], ["france", "fr"], ["canada", "ca"], ["australia", "au"], ["india", "in"],
  ["japan", "jp"], ["brazil", "br"], ["mexico", "mx"], ["netherlands", "nl", "the netherlands", "holland"], ["ireland", "ie", "republic of ireland"], ["singapore", "sg"],
  ["hong kong", "hk"], ["taiwan", "tw"], ["israel", "il"], ["pakistan", "pk"], ["nigeria", "ng"], ["bangladesh", "bd"], ["saudi arabia", "sa"], ["egypt", "eg"],
  ["south africa", "za"], ["spain", "es"], ["italy", "it"], ["poland", "pl"], ["sweden", "se"], ["norway", "no"], ["switzerland", "ch"], ["new zealand", "nz"],
  ["philippines", "ph"], ["indonesia", "id"], ["thailand", "th"], ["malaysia", "my"], ["argentina", "ar"], ["colombia", "co"], ["chile", "cl"], ["peru", "pe"],
  ["ethiopia", "et"], ["kenya", "ke"], ["moldova", "md", "republic of moldova"], ["north macedonia", "mk", "macedonia"], ["laos", "la", "lao people's democratic republic"],
  ["bolivia", "bo"], ["tanzania", "tz", "united republic of tanzania"], ["palestine", "ps", "state of palestine"], ["kazakhstan", "kz"], ["uzbekistan", "uz"]
];
const ALIAS = new Map(); for (const g of COUNTRY_GROUPS) for (const a of g) ALIAS.set(fold(a), g[0]);
const cc = s => { const f = fold(s); return ALIAS.get(f) || f; };                       // the canonical, comparable form of a country name
const shown = s => { const f = cc(s); return ALIAS.has(f) ? title(f) : clip(s, 60); };   // how a country is displayed once understood

/* What a rule can watch. All are about the Okta sign-in itself (a session starting, or an MFA check), not about signing in to an app. */
const FAILED = r => r === "FAILURE" || r === "DENY" || r === "ERROR";
const INVALID_RE = /invalid[ _-]?(credentials|password|username)|incorrect (password|credentials)|wrong password|bad credentials/i;
const resultOf = e => (e.outcome && e.outcome.result) || "";
const KINDS = {
  signin: { label: "Successful sign-ins", test: e => e.eventType === "user.session.start" && resultOf(e) === "SUCCESS" },
  signin_failed: { label: "Failed sign-ins", test: e => e.eventType === "user.session.start" && FAILED(resultOf(e)) },
  invalid_password: { label: "Invalid passwords", test: e => e.eventType === "user.session.start" && FAILED(resultOf(e)) && INVALID_RE.test(((e.outcome && e.outcome.reason) || "") + " " + (e.displayMessage || "")) },
  mfa_failed: { label: "MFA failures", test: e => /^user\.authentication\.auth_via_mfa$|^user\.mfa\./.test(e.eventType || "") && FAILED(resultOf(e)) }
};
const LIMITS = { rules: 50, places: 100, name: 120, count: 1000, windowMax: 1440, cooldownMax: 1440, alerts: 500 };

function parsePlace(p) {
  let parts;
  if (p && typeof p === "object") parts = [p.country, p.region, p.city];
  else parts = String(p == null ? "" : p).split(/\s*[\/>|]\s*/);
  const country = clip(parts[0], 60); if (!country) return null;
  return { country: shown(country), region: clip(parts[1], 60), city: clip(parts[2], 60) };
}
const placeKey = p => cc(p.country) + "|" + fold(p.region) + "|" + fold(p.city);
const placeText = p => [p.country, p.region, p.city].filter(Boolean).join(" / ");

const int = (v, lo, hi, d) => { v = Math.round(+v); return isFinite(v) ? Math.max(lo, Math.min(hi, v)) : d; };
function normalizeRule(r) {
  if (!r || typeof r !== "object") throw err(400, "A location rule is not valid.");
  const name = clip(r.name, LIMITS.name); if (!name) throw err(400, "Give the rule a name.");
  if (!KINDS[r.kind]) throw err(400, "Choose what to watch for: sign-ins, failed sign-ins, invalid passwords or MFA failures.");
  const raw = Array.isArray(r.places) ? r.places : String(r.places || "").split(/\r?\n|;/);
  const seen = new Set(), places = [];
  for (const x of raw.slice(0, 300)) { const p = parsePlace(x); if (!p || seen.has(placeKey(p))) continue; seen.add(placeKey(p)); places.push(p); }
  if (!places.length) throw err(400, "Add at least one place (a country, or a country with a state or city).");
  if (places.length > LIMITS.places) throw err(400, "A rule can list up to " + LIMITS.places + " places.");
  let channel = clip(r.channel, 80);
  if (channel && !/^(#?[a-z0-9][a-z0-9._-]{0,79}|[CGD][A-Z0-9]{8,14})$/.test(channel)) throw err(400, "That Slack channel does not look right. Use a name like #it-alerts, or the channel ID.");
  const id = clip(r.id, 40) || ("gr_" + crypto.randomBytes(5).toString("hex"));
  if (!/^[\w-]{1,40}$/.test(id)) throw err(400, "A location rule needs a simple id.");
  return { id, name, enabled: r.enabled !== false, kind: r.kind, mode: r.mode === "outside" ? "outside" : "in", places,
    count: int(r.count, 1, LIMITS.count, 1), windowMinutes: int(r.windowMinutes, 1, LIMITS.windowMax, 60), per: r.per === "all" ? "all" : "person",
    severity: ["info", "warn", "bad"].includes(r.severity) ? r.severity : "warn", cooldownMinutes: int(r.cooldownMinutes, 0, LIMITS.cooldownMax, 60),
    slack: r.slack === true, channel };
}

const locOf = e => ({ country: e.country || "", region: e.region || "", city: e.city || "" });
const placeHit = (p, l) => cc(p.country) === cc(l.country) && (!p.region || fold(p.region) === fold(l.region)) && (!p.city || fold(p.city) === fold(l.city));
const personOf = e => { const a = e.actor; if (a && (a.alternateId || a.id)) return String(a.alternateId || a.id); const t = (e.target || []).find(x => x.type === "User"); return t ? String(t.alternateId || t.id || "") : ""; };
const appOf = e => { const t = (e.target || []).find(x => x.type === "AppInstance"); return t ? clip(t.displayName, 80) : ""; };
const tOf = e => e._t !== undefined ? e._t : (e._t = Date.parse(e.published));
function matches(rule, e) {
  if (!KINDS[rule.kind].test(e)) return false;
  const l = locOf(e); if (!l.country) return false;                                     // unknown location: ignored
  const inList = rule.places.some(p => placeHit(p, l));
  return rule.mode === "in" ? inList : !inList;
}
const groupOf = (rule, e) => rule.per === "all" ? "*" : personOf(e).toLowerCase() || "?";

function createGeo({ dir, log, maxAgeMinutes = 30 }) {
  const file = path.join(dir, "geo-alerts.json");
  let alerts = [], fired = {}, persistent = false, lastEval = null, timer = null, dirty = false, clock = Date.now();      // clock: the time of the latest check, so old entries are cleaned relative to it
  try { fs.mkdirSync(dir, { recursive: true }); fs.accessSync(dir, fs.constants.W_OK); persistent = true; } catch { /* memory only: alerts will not survive a restart */ }
  try {
    const raw = JSON.parse(fs.readFileSync(file, "utf8"));
    alerts = Array.isArray(raw.alerts) ? raw.alerts.slice(0, LIMITS.alerts) : []; fired = raw.fired && typeof raw.fired === "object" ? raw.fired : {};
    log("Location alerts loaded: " + alerts.length + " recent alerts");
  } catch (e) { if (e.code !== "ENOENT") log("Location alerts file could not be read, starting empty: " + e.message); }

  function flush() {
    if (!persistent || !dirty) return; dirty = false; clearTimeout(timer); timer = null;
    const cut = clock - 2 * 864e5; for (const k of Object.keys(fired)) if (fired[k] < cut) delete fired[k];
    try { const tmp = file + "." + process.pid + ".tmp"; fs.writeFileSync(tmp, JSON.stringify({ alerts, fired }), { mode: 0o600 }); fs.renameSync(tmp, file); }
    catch (e) { persistent = false; log("Location alerts: could not save (" + e.message + "); they will not survive a restart."); }
  }
  const save = () => { dirty = true; if (!timer) { timer = setTimeout(flush, 1500); if (timer.unref) timer.unref(); } };

  // how many events like this one (same rule, same person unless the rule counts everyone) happened in the rule's window up to this event
  function countBefore(rule, e, g, events) {
    const t = tOf(e), from = t - rule.windowMinutes * MIN; let n = 0;
    for (let i = events.length - 1; i >= 0; i--) { const x = events[i], tx = tOf(x); if (tx < from) break; if (tx > t) continue; if (groupOf(rule, x) === g && matches(rule, x)) n++; }
    return n;
  }

  function evaluate(fresh, events, rules, now = Date.now()) {
    const out = [];
    lastEval = new Date(now).toISOString(); clock = now;
    for (const e of fresh) {
      const t = tOf(e); if (!(now - t <= maxAgeMinutes * MIN) || t > now + 5 * MIN) continue;     // not news: it is old history
      for (const rule of rules) {
        if (!rule.enabled || !matches(rule, e)) continue;
        const evKey = "ev|" + rule.id + "|" + e.id; if (fired[evKey]) continue;                  // already looked at (a restart replays recent events)
        const g = groupOf(rule, e); fired[evKey] = now;
        const n = rule.count > 1 ? countBefore(rule, e, g, events) : 1; if (n < rule.count) continue;
        const ck = "cool|" + rule.id + "|" + g, last = fired[ck];
        if (rule.cooldownMinutes > 0 && last !== undefined && t - last < rule.cooldownMinutes * MIN) continue;
        fired[ck] = t;
        const l = locOf(e), a = {
          id: "ga_" + crypto.randomBytes(5).toString("hex"), createdAt: new Date(now).toISOString(), ts: e.published, ruleId: rule.id, ruleName: rule.name, severity: rule.severity,
          kind: rule.kind, kindLabel: KINDS[rule.kind].label, mode: rule.mode, person: clip(personOf(e), 120), personName: clip(e.actor && e.actor.displayName, 120),
          where: { city: clip(l.city, 60), region: clip(l.region, 60), country: clip(l.country, 60) }, ip: clip(e.ip, 64), app: appOf(e), eventType: clip(e.eventType, 80),
          result: resultOf(e), reason: clip(e.outcome && e.outcome.reason, 120), matched: n, threshold: rule.count, windowMinutes: rule.windowMinutes, per: rule.per, eventId: e.id,
          slack: rule.slack ? { state: "queued", channel: rule.channel || "" } : { state: "off" }
        };
        a.type = "location"; a.title = rule.name; a.link = { view: "alerts" };                         // the same shape as every other alert in the feed
        a.body = (a.person || "unknown") + " \u00b7 " + ([a.where.city, a.where.region, a.where.country].filter(Boolean).join(", ") || "unknown location") + (n > 1 ? " \u00b7 " + n + " in " + winTxt(rule.windowMinutes) : "");
        alerts.unshift(a); out.push(a);
      }
    }
    if (alerts.length > LIMITS.alerts) alerts.length = LIMITS.alerts;
    if (out.length || fresh.length) save();
    return out;
  }

  // try a rule against the events we hold (oldest first), the same way evaluate would have, without remembering anything
  function simulate(rule, events, now = Date.now()) {
    const queues = new Map(), cool = new Map(), people = new Set(), samples = []; let hits = 0, fires = 0, first = null, last = null;
    for (const e of events) {
      if (!matches(rule, e)) continue;
      hits++; people.add(personOf(e).toLowerCase()); const t = tOf(e); first = first || e.published; last = e.published;
      const g = groupOf(rule, e); let q = queues.get(g); if (!q) queues.set(g, q = { t: [], s: 0 });
      q.t.push(t); while (q.t[q.s] < t - rule.windowMinutes * MIN) q.s++;
      const n = q.t.length - q.s; if (n < rule.count) continue;
      const lastT = cool.get(g); if (rule.cooldownMinutes > 0 && lastT !== undefined && t - lastT < rule.cooldownMinutes * MIN) continue;
      cool.set(g, t); fires++;
      samples.push({ time: e.published, person: clip(personOf(e), 120), where: placeText(locOf(e)), matched: n }); if (samples.length > 8) samples.shift();       // keep the latest eight
    }
    return { events: hits, people: people.size, wouldAlert: fires, first, last, samples: samples.reverse() };
  }

  // which countries the held events come from, so people can choose what to watch (and see how normal a place is)
  function places(events) {
    const by = new Map(); let unknown = 0, from = null;
    for (const e of events) {
      if (!from) from = e.published;
      const k = KINDS.signin.test(e) || KINDS.signin_failed.test(e) || KINDS.mfa_failed.test(e); if (!k) continue;
      if (!e.country) { unknown++; continue; }
      const key = cc(e.country); let r = by.get(key); if (!r) by.set(key, r = { country: shown(e.country), signins: 0, failed: 0, invalidPasswords: 0, mfaFailures: 0, people: new Set() });
      if (KINDS.signin.test(e)) r.signins++; else if (KINDS.mfa_failed.test(e)) r.mfaFailures++; else { r.failed++; if (KINDS.invalid_password.test(e)) r.invalidPasswords++; }
      r.people.add(personOf(e).toLowerCase());
    }
    const list = [...by.values()].map(r => ({ country: r.country, signins: r.signins, failed: r.failed, invalidPasswords: r.invalidPasswords, mfaFailures: r.mfaFailures, people: r.people.size }));
    list.sort((a, b) => (b.signins + b.failed + b.mfaFailures) - (a.signins + a.failed + a.mfaFailures));
    return { from, unknownLocation: unknown, countries: list.slice(0, 80) };
  }

  const recent = since => { const t = since ? Date.parse(since) : 0; return alerts.filter(a => !t || Date.parse(a.createdAt) > t).slice(0, 200); };
  function setSlack(id, patch) { const a = alerts.find(x => x.id === id); if (a) { a.slack = Object.assign({}, a.slack, patch); save(); } return a || null; }
  const status = () => ({ lastEvaluated: lastEval, alerts: alerts.length, persistent, maxAgeMinutes });
  return { evaluate, simulate, places, recent, setSlack, status, flush };
}
module.exports = { createGeo, normalizeRule, matches, KINDS, LIMITS, cc, shown, placeText };
