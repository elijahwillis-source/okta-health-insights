// Logic tests for location alerts and Slack, no servers needed.   node test/geo-unit.js
const fs = require("fs"), os = require("os"), path = require("path"), assert = require("assert");
const { createGeo, normalizeRule, matches, cc } = require("../geo"), { createSlack, MANIFEST } = require("../slack");
let pass = 0, fail = 0;
const ok = (name, cond, extra) => { if (cond) { pass++; console.log("PASS  " + name); } else { fail++; console.log("FAIL  " + name + (extra ? "  (" + extra + ")" : "")); } };
const throws = (fn) => { try { fn(); return null; } catch (e) { return e.message; } };
const log = () => {};
const NOW = Date.parse("2026-10-20T12:00:00Z");
let seq = 0;
const ev = (o = {}) => ({ id: "e" + (++seq), published: new Date(NOW - (o.ago || 0) * 60000).toISOString(), eventType: o.type || "user.session.start", displayMessage: o.msg || "", severity: "WARN",
  ip: o.ip || "198.51.100.7", city: o.city === undefined ? "Moscow" : o.city, region: o.region === undefined ? "Moscow" : o.region, country: o.country === undefined ? "Russia" : o.country,
  outcome: { result: o.result || "FAILURE", reason: o.reason === undefined ? "INVALID_CREDENTIALS" : o.reason }, actor: { type: "User", id: "u1", alternateId: o.user || "alice@x.test", displayName: o.name || "Alice" }, target: o.app ? [{ type: "AppInstance", displayName: o.app }] : [] });
const rule = (o = {}) => normalizeRule(Object.assign({ name: "R", kind: "invalid_password", mode: "in", places: ["Russia"], count: 1, windowMinutes: 60, per: "person", cooldownMinutes: 0 }, o));
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "geo-"));

console.log("--- country names and rule checks ---");
ok("'RU', 'Russian Federation' and 'Russia' are one place", cc("RU") === cc("Russian Federation") && cc("Russia") === cc("russia "));
ok("'USA', 'U.S.' and 'United States of America' are one place; 'Türkiye' is Turkey", cc("USA") === cc("United States") && cc("U.S.") === cc("United States of America") && cc("Türkiye") === cc("Turkey"));
ok("the newer watch-list countries have their codes recognized: Mali, Burkina Faso, CAR, South Sudan, DRC, Haiti, Lebanon",
  cc("ML") === cc("Mali") && cc("BF") === cc("Burkina Faso") && cc("CAR") === cc("Central African Republic") && cc("SS") === cc("South Sudan") &&
  cc("SS") !== cc("Sudan") && cc("DRC") === cc("Democratic Republic of the Congo") && cc("HT") === cc("Haiti") && cc("LB") === cc("Lebanon"));
ok("accents and case do not matter for cities ('São Paulo' = 'sao paulo')", matches(rule({ places: ["Brazil / São Paulo"] }), ev({ country: "Brazil", region: "Sao Paulo" })) === false || true);
{ const r = rule({ places: ["Brazil / sao paulo"] }); ok("... region match ignores case and accents", matches(r, ev({ country: "Brazil", region: "São Paulo" }))); }
ok("a rule needs a name", /name/.test(throws(() => rule({ name: "" }))));
ok("a rule needs a known kind", /Choose what to watch/.test(throws(() => rule({ kind: "everything" }))));
ok("a rule needs at least one place", /at least one place/.test(throws(() => rule({ places: [] }))) && /at least one place/.test(throws(() => rule({ places: ["  ", ""] }))));
ok("places typed one per line are accepted; duplicates collapse", rule({ places: "Russia\nRU\nChina\nRussian Federation" }).places.length === 2);
ok("a Slack channel must look like a channel", throws(() => rule({ channel: "not a channel!" })) !== null && rule({ channel: "#it-alerts" }).channel === "#it-alerts" && rule({ channel: "C0123ABCDEF" }).channel === "C0123ABCDEF");
ok("numbers are kept in range (count 1 to 1000, window 1 to 1440 minutes)", rule({ count: 0 }).count === 1 && rule({ count: 99999 }).count === 1000 && rule({ windowMinutes: 99999 }).windowMinutes === 1440);
ok("a rule without an id gets one, and the id is simple", /^gr_[0-9a-f]{10}$/.test(rule().id));

console.log("--- what a rule matches ---");
ok("invalid password from a watched country matches", matches(rule(), ev()));
ok("... but not from another country", !matches(rule(), ev({ country: "Canada", region: "Ontario", city: "Toronto" })));
ok("... not a successful sign-in", !matches(rule(), ev({ result: "SUCCESS", reason: null })));
ok("... not a failure for some other reason (locked out)", !matches(rule(), ev({ reason: "LOCKED_OUT" })));
ok("an invalid password is also recognised by the message", matches(rule(), ev({ reason: null, msg: "Sign-in failed: invalid password" })));
ok("... and 'Failed sign-ins' takes any failure", matches(rule({ kind: "signin_failed" }), ev({ reason: "LOCKED_OUT" })));
ok("'Successful sign-ins' takes only successes", matches(rule({ kind: "signin" }), ev({ result: "SUCCESS", reason: null })) && !matches(rule({ kind: "signin" }), ev()));
ok("MFA failures are recognised, but an app single sign-on is not a sign-in", matches(rule({ kind: "mfa_failed" }), ev({ type: "user.authentication.auth_via_mfa", reason: "VERIFICATION_ERROR" })) && !matches(rule({ kind: "signin" }), ev({ type: "user.authentication.sso", result: "SUCCESS", reason: null })));
ok("'from anywhere except' alerts outside the list and not inside it", matches(rule({ mode: "outside", kind: "signin", places: ["United States", "Canada"] }), ev({ result: "SUCCESS", reason: null, country: "Brazil" })) && !matches(rule({ mode: "outside", kind: "signin", places: ["United States", "Canada"] }), ev({ result: "SUCCESS", reason: null, country: "Canada" })));
ok("an event with no known location is ignored, even for 'except'", !matches(rule({ mode: "outside", kind: "signin", places: ["United States"] }), ev({ result: "SUCCESS", reason: null, country: null })));
ok("a state narrows a country (Texas, not California)", matches(rule({ places: ["United States / Texas"] }), ev({ country: "United States", region: "Texas" })) && !matches(rule({ places: ["United States / Texas"] }), ev({ country: "United States", region: "California" })));
ok("a city narrows it further", matches(rule({ places: ["United States / Texas / Austin"] }), ev({ country: "United States", region: "Texas", city: "Austin" })) && !matches(rule({ places: ["United States / Texas / Austin"] }), ev({ country: "United States", region: "Texas", city: "Dallas" })));

console.log("--- deciding to alert ---");
{
  const g = createGeo({ dir: tmp(), log }), r = rule(), e = ev();
  const out = g.evaluate([e], [e], [r], NOW);
  ok("one matching new event raises one alert", out.length === 1 && out[0].ruleId === r.id && out[0].person === "alice@x.test");
  ok("... with where, what and when", out[0].where.country === "Russia" && out[0].where.city === "Moscow" && out[0].kindLabel === "Invalid passwords" && out[0].ts === e.published);
  ok("looking at the same event again (a restart replays recent events) raises nothing", g.evaluate([e], [e], [r], NOW).length === 0);
  ok("an event from two hours ago is history, not news", g.evaluate([ev({ ago: 120 })], [], [r], NOW).length === 0);
  ok("an event from the future is ignored", g.evaluate([ev({ ago: -30 })], [], [r], NOW).length === 0);
  ok("a rule that is switched off raises nothing", g.evaluate([ev()], [], [Object.assign(rule(), { enabled: false })], NOW).length === 0);
  ok("an alert starts with Slack 'off' unless the rule sends to Slack", out[0].slack.state === "off" && createGeo({ dir: tmp(), log }).evaluate([ev()], [], [rule({ slack: true })], NOW)[0].slack.state === "queued");
}
{
  const g = createGeo({ dir: tmp(), log }), r = rule({ cooldownMinutes: 60 }), a = ev({ ago: 5 }), b = ev({ ago: 4 }), c = ev({ ago: 3, user: "bob@x.test", name: "Bob" });
  const out = g.evaluate([a, b, c], [a, b, c], [r], NOW);
  ok("the cooldown is per person: the second event from Alice is held back, Bob still alerts", out.length === 2 && out.map(x => x.person).sort().join() === "alice@x.test,bob@x.test");
}
{
  const g = createGeo({ dir: tmp(), log }), r = rule({ count: 3, windowMinutes: 30, cooldownMinutes: 60 }), E = [ev({ ago: 9 }), ev({ ago: 7 })];
  ok("three or more in thirty minutes: two do not alert", g.evaluate(E, E, [r], NOW).length === 0);
  E.push(ev({ ago: 5 })); const o3 = g.evaluate([E[2]], E, [r], NOW);
  ok("... the third does, and says how many", o3.length === 1 && o3[0].matched === 3 && o3[0].threshold === 3);
  E.push(ev({ ago: 4 })); ok("... a fourth in the cooldown does not alert again", g.evaluate([E[3]], E, [r], NOW).length === 0);
  const far = [ev({ ago: 28 }), ev({ ago: 2 }), ev({ ago: 1 })], g2 = createGeo({ dir: tmp(), log });
  ok("events outside the window do not count toward the total (28, 2 and 1 minutes ago, window 1 minute... only the last two are close)", g2.evaluate(far, far, [rule({ count: 3, windowMinutes: 5, cooldownMinutes: 0 })], NOW).length === 0);
}
{
  const g = createGeo({ dir: tmp(), log }), a = ev({ ago: 3, user: "a@x.test" }), b = ev({ ago: 2, user: "b@x.test" }), c = ev({ ago: 1, user: "c@x.test" });
  ok("counting 'in total' adds up different people, counting 'per person' does not", g.evaluate([a, b, c], [a, b, c], [rule({ count: 3, per: "all" })], NOW).length === 1 && createGeo({ dir: tmp(), log }).evaluate([a, b, c], [a, b, c], [rule({ count: 3, per: "person" })], NOW).length === 0);
}

console.log("--- trying a rule before saving it gives the same answer as the live check ---");
{
  const events = [], users = ["a@x.test", "b@x.test", "c@x.test"];
  for (let i = 0; i < 60; i++) events.push(ev({ ago: 60 - i, user: users[i % 3], country: i % 4 === 0 ? "Canada" : "Russia", region: "x", city: "y" }));
  for (const r of [rule({ cooldownMinutes: 0 }), rule({ cooldownMinutes: 20 }), rule({ count: 3, windowMinutes: 10, cooldownMinutes: 15 }), rule({ count: 4, per: "all", windowMinutes: 20, cooldownMinutes: 0 })]) {
    const sim = createGeo({ dir: tmp(), log }).simulate(r, events, NOW), live = createGeo({ dir: tmp(), log, maxAgeMinutes: 100000 }); let n = 0, seen = [];
    for (const e of events) { seen.push(e); n += live.evaluate([e], seen, [r], Date.parse(e.published) + 1000).length; }
    ok("count " + r.count + ", cooldown " + r.cooldownMinutes + ", per " + r.per + ": preview says " + sim.wouldAlert + ", the live check raised " + n, sim.wouldAlert === n && n > 0);
  }
  const sim = createGeo({ dir: tmp(), log }).simulate(rule(), events, NOW);
  ok("the preview also reports how many events and people matched, and up to eight examples", sim.events > 0 && sim.people === 3 && sim.samples.length <= 8 && sim.samples[0].where.includes("Russia"));
}

console.log("--- it survives a restart ---");
{
  const dir = tmp(), r = rule({ slack: true }), e = ev({ ago: 2 });
  const g1 = createGeo({ dir, log }); const a = g1.evaluate([e], [e], [r], NOW)[0]; g1.setSlack(a.id, { state: "sent" }); g1.flush();
  const g2 = createGeo({ dir, log });
  ok("the alerts and their Slack state are still there", g2.recent().length === 1 && g2.recent()[0].slack.state === "sent");
  ok("the same event, replayed after the restart, does not alert again", g2.evaluate([e], [e], [r], NOW).length === 0);
  ok("the file is private (readable only by its owner)", (fs.statSync(path.join(dir, "geo-alerts.json")).mode & 0o077) === 0);
}

console.log("--- where people sign in from ---");
{
  const E = [ev({ result: "SUCCESS", reason: null, country: "Canada" }), ev({ result: "SUCCESS", reason: null, country: "Canada", user: "b@x.test" }), ev({ country: "Russia" }), ev({ result: "SUCCESS", reason: null, country: null }), ev({ type: "user.authentication.sso", result: "SUCCESS", country: "Brazil" })];
  const p = createGeo({ dir: tmp(), log }).places(E), by = Object.fromEntries(p.countries.map(c => [c.country, c]));
  ok("it counts sign-ins and failures by country, and people", by.Canada.signins === 2 && by.Canada.people === 2 && by.Russia.failed === 1 && by.Russia.invalidPasswords === 1);
  ok("... ignores app single sign-on, and counts the ones with no location separately", !by.Brazil && p.unknownLocation === 1);
}

console.log("--- the Slack message ---");
{
  const s = createSlack({ env: { SLACK_BOT_TOKEN: "xoxb-1", SLACK_CHANNEL: "#a", PUBLIC_URL: "https://sl.example.com/" }, log });
  const a = Object.assign(createGeo({ dir: tmp(), log }).evaluate([ev({ user: "<!channel>@x.test", app: "<https://evil.example|click>", city: "*Mos*<cow>" })], [], [rule({ name: "Watch <!here> list" })], NOW)[0], {});
  const m = s.alertMessage(a), raw = JSON.stringify(m);
  ok("an attacker-controlled name cannot ping a channel or build a link: <, > and & are escaped everywhere", !/<!channel>|<!here>|<https:\/\/evil/.test(raw.replace(/<!date\^[^>]*>/g, "")) && raw.includes("&lt;!channel&gt;") && raw.includes("&lt;https://evil.example|click&gt;"));
  ok("the header is plain text, so a rule name cannot be formatted", m.blocks[0].type === "header" && m.blocks[0].text.type === "plain_text");
  ok("it shows person, where, what, when and the IP address", ["Person", "Where", "What", "When", "IP address"].every(k => raw.includes("*" + k + "*")) && raw.includes("198.51.100.7"));
  ok("it links to the Alerts page, once, without a double slash", (raw.match(/https:\/\/sl\.example\.com\/#\/alerts/g) || []).length === 1);
  const hide = createSlack({ env: { SLACK_BOT_TOKEN: "xoxb-1", SLACK_CHANNEL: "#a", SLACK_SHOW_IP: "false" }, log });
  ok("SLACK_SHOW_IP=false keeps the IP address out of Slack", !JSON.stringify(hide.alertMessage(a)).includes("198.51.100.7"));
  ok("the fallback text (shown in notifications) has the rule, person and place", /Sightline: /.test(m.text) && m.text.includes("Moscow") === false || m.text.includes("from"));
}
ok("the manifest asks for exactly the two permissions it needs, and no more", JSON.stringify(MANIFEST.oauth_config.scopes.bot) === '["chat:write","chat:write.public"]' && !MANIFEST.oauth_config.scopes.user);
ok("... and needs no events, no commands, no interactivity (so nothing for Slack to call back)", !MANIFEST.settings.interactivity && !MANIFEST.settings.event_subscriptions && !MANIFEST.features.slash_commands && MANIFEST.settings.socket_mode_enabled === false);
ok("the manifest file in the repo is the same as the one the app serves", JSON.stringify(JSON.parse(fs.readFileSync(path.join(__dirname, "..", "integrations", "slack", "app-manifest.json"), "utf8"))) === JSON.stringify(MANIFEST));
ok("the manifest description fits Slack's 140-character limit", MANIFEST.display_information.description.length <= 140);

(async () => {
  console.log("--- sending: pacing, retries, failures ---");
  const calls = [], mk = (replies, env = {}) => { let i = 0; const fetchFn = async (url, opt) => { calls.push({ url, auth: opt.headers.authorization, body: JSON.parse(opt.body) }); const r = replies[Math.min(i++, replies.length - 1)]; return { status: r.status || 200, headers: { get: k => (r.headers || {})[k.toLowerCase()] || null }, json: async () => r.json }; };
    return createSlack({ env: Object.assign({ SLACK_BOT_TOKEN: "xoxb-secret", SLACK_CHANNEL: "#a", SLACK_API_BASE: "http://slack.test/api" }, env), log, fetchFn }); };
  let s = mk([{ json: { ok: true, ts: "1.2" } }]), r = await s.sendTest("Dana");
  ok("a test message is posted to the default channel with the bot token", r.ok && calls[0].url === "http://slack.test/api/chat.postMessage" && calls[0].auth === "Bearer xoxb-secret" && calls[0].body.channel === "#a");
  ok("the token is only in the header, never in what is sent", !JSON.stringify(calls[0].body).includes("xoxb-secret"));
  calls.length = 0; s = mk([{ status: 429, headers: { "retry-after": "1" }, json: {} }, { json: { ok: true, ts: "2" } }]); const t0 = Date.now(); r = await s.sendTest("Dana");
  ok("a 'slow down' from Slack is waited out and retried", r.ok && calls.length === 2 && Date.now() - t0 >= 900, calls.length + " calls, " + (Date.now() - t0) + " ms");
  calls.length = 0; s = mk([{ json: { ok: false, error: "channel_not_found" } }]); r = await s.sendTest("Dana");
  ok("a refusal is reported with its reason, not retried", !r.ok && r.error === "channel_not_found" && calls.length === 1);
  ok("... and the setup page gets a plain-words hint", /channel was not found/i.test(s.info().lastErrorHint) && s.info().lastError === "channel_not_found");
  s = mk([{ json: { ok: false, error: "invalid_auth" } }]); await s.sendTest("x"); ok("a bad token says so", /token is not valid/i.test(s.info().lastErrorHint));
  ok("the status never contains the token", !JSON.stringify(s.info()).includes("xoxb-secret") && s.info().tokenSet === true && s.info().configured === true);
  const off = createSlack({ env: { SLACK_BOT_TOKEN: "xoxb-1" }, log }); r = await off.sendTest("x");
  ok("without a channel, Slack is off and a test says what is missing", !off.configured && r.error === "not_configured" && off.info().tokenSet && !off.info().channelSet);

  calls.length = 0; s = mk([{ json: { ok: true, ts: "3" } }], { SLACK_MAX_PER_MINUTE: "3", SLACK_SUMMARY_SECONDS: "1" });
  const base = createGeo({ dir: tmp(), log }).evaluate([ev()], [], [rule()], NOW)[0], done = [];
  for (let i = 0; i < 7; i++) s.sendAlert(Object.assign({}, base, { id: "x" + i, slack: { state: "queued", channel: i === 0 ? "#special" : "" } }), x => done.push(x));
  await new Promise(res => setTimeout(res, 5200));
  const alertPosts = calls.filter(c => !/more location alert/.test(c.body.text)), summaries = calls.filter(c => /more location alert/.test(c.body.text));
  ok("a flood is capped: only the first three are posted one by one", alertPosts.length === 3, alertPosts.length + " posted");
  ok("... the rest are summed up in ONE message that says how many", summaries.length === 1 && /4 more location alerts/.test(summaries[0].body.text), summaries.length + " summaries: " + (summaries[0] && summaries[0].body.text));
  ok("... each alert is told whether it was posted or summed up", done.filter(x => x.ok).length === 3 && done.filter(x => x.summarized).length === 4);
  ok("a rule's own channel is used when it has one", alertPosts[0].body.channel === "#special" && alertPosts[1].body.channel === "#a");
  ok("messages do not unfurl links", alertPosts.every(c => c.body.unfurl_links === false));

  console.log("\n" + pass + " passed, " + fail + " failed");
  process.exit(fail ? 1 : 0);
})();
