// Logic tests for osctrl.js: the health score formula, defensive field parsing, auth-header fallback and
// re-login, nodes/results lookups, and one recipe round trip against the mock server.   node test/osctrl-unit.js
const { createOsctrl } = require("../osctrl");
let pass = 0, fail = 0;
const ok = (name, cond, extra) => { if (cond) { pass++; console.log("PASS  " + name); } else { fail++; console.log("FAIL  " + name + (extra ? "  (" + extra + ")" : "")); } };
const log = () => {};

console.log("--- health score: pure logic, no network ---");
{
  const o = createOsctrl({}, log);
  const node = n => Object.assign({ uuid: "u1", hostname: "h1", serial: "s1", lastSeenMs: Date.now() - 60000, platformVersion: "14.5" }, n);
  const col = c => ({ columns: c });

  {
    const s = o._scoreDevice(node({}), { os: [col({ version: "14.5" })], disk: [col({ blocks: "100", blocks_available: "50" })], battery: [col({ health: "Good" })], uptime: [col({ total_seconds: 86400 })], fleetNewestVersion: "14.5" });
    ok("a fully healthy, up-to-date device scores 100", s.score === 100 && s.band === "healthy", JSON.stringify(s.parts));
  }
  {
    const s = o._scoreDevice(node({}), { os: [col({ version: "12.0" })], disk: [], battery: [], uptime: [], fleetNewestVersion: "14.9" });
    ok("far behind on OS version loses OS-currency points but nothing else it has no data for", s.parts.osCurrency.points < 20 && s.parts.diskFree.points === 20 && s.parts.battery.points === 15);
  }
  {
    const s = o._scoreDevice(node({}), { os: [], disk: [col({ blocks: "100", blocks_available: "5" })], battery: [col({ health: "Poor" })], uptime: [col({ total_seconds: 40 * 86400 })], fleetNewestVersion: null });
    ok("low disk, poor battery and a stale reboot all cost points", s.parts.diskFree.points < 10 && s.parts.battery.points === 0 && s.parts.rebootFreshness.points < 10);
    ok("the band for a low score is 'action'", s.score < 70 && s.band === "action");
  }
  {
    const s = o._scoreDevice(node({ lastSeenMs: Date.now() - 5 * 3600000 }), { os: [], disk: [], battery: [], uptime: [], fleetNewestVersion: null });
    ok("an agent not seen in hours loses the agent-health points", s.parts.agentHealth.points === 0);
  }
  {
    const s = o._scoreDevice(node({}), { os: [], disk: [], battery: [], uptime: [], fleetNewestVersion: null });
    ok("components with no data at all (no scheduled query yet) are marked partial, not penalized", s.parts.memoryHeadroom.partial && s.parts.crashIndicators.partial && s.parts.battery.points === 15);
  }
  {
    const n = o._normalizeNode({ uuid: "x", hostname: "mac1", hardware_serial: "ABC", platform: "darwin", platform_version: "14.5", memory: "17179869184", cpu: "Apple M4", system_info: { system: { hardware_model: "MacBook Pro" } }, osquery_version: "5.1", last_seen: Math.floor(Date.now() / 1000) });
    ok("normalizeNode reads the real osctrl v0.7.x node shape (memory/cpu top-level, model under system_info.system)", n.hostname === "mac1" && n.serial === "ABC" && n.model === "MacBook Pro" && n.cpuBrand === "Apple M4" && n.memoryBytes === 17179869184 && n.lastSeenMs !== null);
  }
}

console.log("\n--- against the mock server ---");
(async () => {
  for (const mode of ["raw", "bearer", "flip"]) {
    const PORT = 4440 + ["raw", "bearer", "flip"].indexOf(mode);
    process.env.MOCK_O_AUTH = mode;
    delete require.cache[require.resolve("./mock-osctrl")];
    process.env.MOCK_O_PORT = String(PORT);
    const mock = require("./mock-osctrl");
    try {
      const o = createOsctrl({ OSCTRL_API_URL: "http://localhost:" + PORT, OSCTRL_API_USER: "ai-readonly", OSCTRL_API_PASSWORD: "s3cret", OSCTRL_QUERY_POLL_MS: "30", OSCTRL_RESULTS_CACHE_MS: "1" }, log);
      const list = await o.nodes();
      ok("auth mode '" + mode + "': nodes() returns the fleet through whichever header style the server needs", list.length === 2 && list.some(n => n.hostname === "jdoe-mbp.corp.local"));
      const detail = await o.deviceDetail("jdoe-mbp");
      ok("auth mode '" + mode + "': deviceDetail resolves by a partial hostname and fills in OS/disk/battery/uptime", !detail.error && detail.os.version === "14.5" && detail.battery.health === "Good" && detail.health.score > 0);
      ok("auth mode '" + mode + "': identity reads the real memory/cpu/model fields", detail.identity.memoryBytes === 17179869184 && detail.identity.cpuBrand === "Apple M3" && detail.identity.model === "MacBook Pro");
      ok("auth mode '" + mode + "': apps only shows the newest run, not an older run's leftover rows", detail.apps.count === 2 && detail.apps.items.some(a => a.name === "Slack") && !detail.apps.items.some(a => a.name === "OldApp"));
      const slack = detail.apps.items.find(a => a.name === "Slack");
      ok("auth mode '" + mode + "': app version/last-opened read osquery 5.24.1's real column names (bundle_short_version, last_opened_time)", !!slack && slack.version === "4.39.0" && !!slack.lastOpened);
      const battRows = await o._resultsOf("macos_battery", "u-1", 1);
      ok("auth mode '" + mode + "': a differential 'removed' row (stale value) loses to 'added', regardless of array order", battRows.length === 1 && battRows[0].columns.health === "Good" && battRows[0].action === "added");
      const upRows = await o._resultsOf("macos_uptime", "u-1", 5);
      ok("auth mode '" + mode + "': picking a row sorts by created_at, not array order (the older row was listed first)", upRows.length > 0 && upRows[0].columns.days === "2");
      const memRows = await o._resultsOf("macos_memory", "u-1", 5);
      ok("auth mode '" + mode + "': a snapshot-mode row whose columns decode to an array expands into separate rows", memRows.length === 2 && memRows.every(r => r.columns && r.columns.total_bytes === "17179869184"));
      const bad = await o.resolveDevice("nope-does-not-exist");
      ok("auth mode '" + mode + "': an unknown device is a plain error, not a throw", !!bad.error);
      const bySerial = await o.resolveDevice("C02ABCDEFG");
      ok("auth mode '" + mode + "': a serial resolves even though the server's own q= search never looks at hardware_serial", !bySerial.error && !!bySerial.node && bySerial.node.hostname === "jdoe-mbp.corp.local");
      const ambiguousSerial = await o.resolveDevice("C02");
      ok("auth mode '" + mode + "': an ambiguous serial prefix matching more than one device is reported, not silently resolved", !!ambiguousSerial.error && Array.isArray(ambiguousSerial.matches) && ambiguousSerial.matches.length === 2);
    } finally { mock.server.close(); }
  }

  process.env.MOCK_O_AUTH = "raw"; process.env.MOCK_O_PORT = "4445"; process.env.MOCK_O_EXPIRE_AFTER = "2";
  delete require.cache[require.resolve("./mock-osctrl")];
  const mock3 = require("./mock-osctrl");
  try {
    const o = createOsctrl({ OSCTRL_API_URL: "http://localhost:4445", OSCTRL_API_USER: "ai-readonly", OSCTRL_API_PASSWORD: "s3cret" }, log);
    await o.nodes(); const list = await o.nodes(); await o.nodes();   // the 2nd authenticated call gets a one-time 401
    ok("a token that the server stops accepting mid-session triggers a fresh sign-in, not a failure", list.length === 2);
  } finally { mock3.server.close(); delete process.env.MOCK_O_EXPIRE_AFTER; }

  process.env.MOCK_O_AUTH = "bearer"; process.env.MOCK_O_PORT = "4451"; process.env.MOCK_O_EVICT_AFTER = "2";
  delete require.cache[require.resolve("./mock-osctrl")];
  const mock4 = require("./mock-osctrl");
  try {
    const o = createOsctrl({ OSCTRL_API_URL: "http://localhost:4451", OSCTRL_API_USER: "ai-readonly", OSCTRL_API_PASSWORD: "s3cret" }, log);
    await o.nodes();                      // call #1: normal, logs in once
    const list = await o.nodes();         // call #2: another login elsewhere evicts this token -- osctrl answers with a 302 to /forbidden, not a 401/403
    ok("a token evicted by another login (redirect to /forbidden, not 401/403) is detected and recovered with one extra sign-in", list.length === 2);
    ok("recovering from eviction signed in exactly twice (the original sign-in, plus the one recovery)", mock4.counts.logins === 2, "logins=" + mock4.counts.logins);
  } finally { mock4.server.close(); delete process.env.MOCK_O_EVICT_AFTER; }

  process.env.MOCK_O_AUTH = "bearer"; process.env.MOCK_O_PORT = "4452"; process.env.MOCK_O_EVICT_AFTER = "1";
  delete require.cache[require.resolve("./mock-osctrl")];
  const mock5 = require("./mock-osctrl");
  try {
    const o = createOsctrl({ OSCTRL_API_URL: "http://localhost:4452", OSCTRL_API_USER: "ai-readonly", OSCTRL_API_PASSWORD: "s3cret" }, log);
    const [a, b, c] = await Promise.all([o.nodes(), o.nodes(), o.nodes()]);   // all three race into the very first call, which gets evicted immediately
    ok("several calls racing into an evicted token all still get the right data", a.length === 2 && b.length === 2 && c.length === 2);
    ok("recovering is single-flight: one shared sign-in for everyone racing in, not one per caller", mock5.counts.logins === 2, "logins=" + mock5.counts.logins);
  } finally { mock5.server.close(); delete process.env.MOCK_O_EVICT_AFTER; }

  process.env.MOCK_O_AUTH = "raw"; process.env.MOCK_O_PORT = "4450";
  delete require.cache[require.resolve("./mock-osctrl")];
  const mock2 = require("./mock-osctrl");
  try {
    const o = createOsctrl({ OSCTRL_API_URL: "http://localhost:4450", OSCTRL_API_USER: "ai-readonly", OSCTRL_API_PASSWORD: "s3cret", OSCTRL_QUERY_POLL_MS: "20", OSCTRL_QUERY_TIMEOUT_MS: "2000" }, log);
    const r = await o.runRecipe("jdoe-mbp", "disk_full");
    ok("a recipe cites the exact query it ran and comes back with rows", !r.error && r.queryRun === o.RECIPES.disk_full.sql && r.rowCount > 0);
    ok("the installed_apps recipe uses osquery 5.24.1's real apps columns, not the ones that don't exist", o.RECIPES.installed_apps.sql === "SELECT name, bundle_short_version AS version, last_opened_time FROM apps");
    const bad = await o.runRecipe("jdoe-mbp", "not_a_real_recipe");
    ok("an unknown recipe name is a plain error", !!bad.error);
    const missing = await createOsctrl({ OSCTRL_API_URL: "http://localhost:4450", OSCTRL_API_USER: "wrong", OSCTRL_API_PASSWORD: "wrong" }, log).nodes().catch(e => e);
    ok("bad credentials surface as a rejected promise, not a silent empty list", missing instanceof Error);
  } finally { mock2.server.close(); }

  console.log("\n" + pass + " passed, " + fail + " failed");
  process.exit(fail ? 1 : 0);
})();
