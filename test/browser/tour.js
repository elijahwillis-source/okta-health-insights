// A walk through every page of the app, to catch anything broken by a change anywhere. Run: bash test/browser/run-geo-ui.sh tour.js
const { chromium } = require("playwright");
const shots = process.argv[2] || "/tmp/sightline-shots", BASE = "http://localhost:8090";
let pass = 0, fail = 0; const ok = (n, c, x) => { console.log((c ? "PASS  " : "FAIL  ") + n + (!c && x ? "  (" + x + ")" : "")); c ? pass++ : fail++; };
(async () => {
  const browser = await chromium.launch(), errs = [], consoleErrs = [];
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: "dark" });
  await ctx.addInitScript(() => { try { localStorage.setItem("okta.pname", JSON.stringify("Dana Admin")); } catch (e) { /* ignore */ } });
  const page = await ctx.newPage(); page.on("pageerror", e => errs.push(e.message)); page.on("console", m => { if (m.type() === "error") consoleErrs.push(m.text()); });
  await page.goto(BASE + "/#/overview"); await page.waitForSelector("#kpis .kpi", { timeout: 40000 }); await page.waitForTimeout(1500);
  const go = async v => { await page.click('#side [data-view="' + v + '"]'); await page.waitForTimeout(700); return page.locator("#view-" + v).innerText(); };

  console.log("--- the shared alert logic reached the page ---");
  ok("the page loaded the shared file, and its helpers are available as before", await page.evaluate(() => typeof SightlineAlerts === "object" && typeof normErr === "function" && typeof catOf === "function" && typeof compileFilter === "function" && typeof scopeInfo === "function" && typeof isFail === "function"));
  ok("the shared file is the one the server serves", (await page.request.get(BASE + "/alerts-core.js")).headers()["content-type"].startsWith("application/javascript"));
  ok("error text is tidied as before (ids hidden)", await page.evaluate(() => normErr('failed for "0123456789abcdef01234567"') === 'failed for "<id>"'));
  ok("Google scopes are rated as before", await page.evaluate(() => scopeInfo("openid").risk === "low" && scopeInfo("https://www.googleapis.com/auth/drive").risk === "high"));

  console.log("--- every page opens ---");
  const ov = await page.locator("#view-overview").innerText();
  ok("Overview: the five numbers, and a failure rate in percent", await page.locator("#kpis .kpi").count() === 5 && /\d+(\.\d)?%/.test(ov));
  await go("errors"); await page.waitForSelector("#errView table tr", { timeout: 15000 });
  ok("Errors: a table of errors, with an Explain on each row", await page.locator("#errView table tr").count() > 1 && await page.locator("[data-eexplain]").count() > 0);
  const ev = await page.locator("#view-errors").innerText();
  ok("... and the errors are sorted into categories, which can be used to filter", /Sign-in & password|Provisioning & assignment|Token & OAuth|Access denied|Other/.test(ev), ev.slice(0, 160));
  await go("people"); await page.waitForSelector("#userTbl tr.urow", { timeout: 30000 });
  ok("People: people with errors are listed, and a row opens", await page.locator("#userTbl tr.urow").count() > 0 && (await page.locator("#userTbl tr.urow").first().click(), await page.waitForTimeout(500), await page.locator("#userTbl [data-askerr]").count()) > 0);
  const apps = await go("apps"); ok("Apps: the page shows apps and their status", /Active|Quiet|Silent|Waiting/.test(apps) && apps.length > 100);
  const g = await go("google"); ok("Google OAuth: with no Google settings it explains how to connect", /connect|GOOGLE_SA_KEY|service account/i.test(g), g.slice(0, 120));
  const dv = await go("devices"); ok("Device health: the under-construction page", /Coming at the end of the year/.test(dv));
  const po = await go("policy"); ok("Policy: opens", /Known errors|Policy/i.test(po) && po.length > 80);
  const se = await go("settings"); ok("Data & settings: opens", se.length > 80);
  const ig = await go("integrations"); ok("Integrations: opens", /Notifications/.test(ig) && /Data sources/.test(ig));
  const al = await go("alerts"); ok("Alerts: opens, empty at the start", /No alerts yet/.test(al));

  console.log("--- the alert checks run in the browser (no sign-in, so nothing is shared) ---");
  await page.click("#alertNew"); await page.click('[data-pick="spike"]'); await page.waitForSelector("#ruleModal");
  await page.fill("#rName", "Any error at all"); await page.fill("#rN", "1"); await page.selectOption("#rWin", "1440").catch(() => {}); await page.click("#rSave"); await page.waitForSelector("#ruleModal", { state: "detached" });
  await page.waitForFunction(() => document.querySelectorAll("#notifFeed .nitem").length > 0, null, { timeout: 15000 }).catch(() => {});
  ok("a 'too many errors' alert fires from the shared check and lands in the Notifications list and the bell", await page.locator("#notifFeed .nitem").count() > 0 && await page.locator("#bellN").isVisible());
  const nt = await page.locator("#notifFeed .nitem").first().innerText();
  ok("... saying what happened, in words", /Any error at all/.test(nt) && /error/.test(nt), nt.slice(0, 120));
  ok("the alert row says what it sees now", /matching in|Highest/.test(await page.locator("#rulesList .rule").first().innerText()));
  await page.click("#alertNew"); await page.click('[data-pick="silent"]'); await page.waitForSelector("#ruleModal"); await page.fill("#rName", "A silent app"); await page.click("#rSave"); await page.waitForSelector("#ruleModal", { state: "detached" });
  await page.click("#alertNew"); await page.click('[data-pick="new"]'); await page.waitForSelector("#ruleModal"); await page.fill("#rName", "A new error"); await page.click("#rSave"); await page.waitForSelector("#ruleModal", { state: "detached" });
  await page.click("#alertNew"); await page.click('[data-pick="gnew"]'); await page.waitForSelector("#ruleModal"); await page.fill("#rName", "A Google app"); await page.click("#rSave"); await page.waitForSelector("#ruleModal", { state: "detached" });
  const rows = await page.locator("#rulesList .rule").allInnerTexts();
  ok("all four kinds can be created, and each row describes itself and what it sees now", rows.length === 4 && rows.every(t => t.split("\n").length >= 3), rows.map(t => t.split("\n")[0]).join(" | "));
  ok("the Google alert says plainly that Google is not connected", /Google Workspace is not connected yet/.test(rows.join(" ")));

  console.log("--- the assistant opens, and Explain asks about one error ---");
  await go("errors"); await page.waitForSelector("[data-eexplain]"); await page.locator("[data-eexplain]").first().click(); await page.waitForTimeout(1200);
  ok("Explain opens Iris (here there is no AI key, so she says what is missing instead of answering)", await page.locator("#assistant.open").count() === 1 && /Anthropic API key/.test(await page.locator("#msgs .msg.a .bubble").last().innerText()));
  await page.keyboard.press("Escape");
  ok("no errors in the page, and none logged to the console that mean something is broken", errs.length === 0 && consoleErrs.filter(m => !/Failed to load resource|favicon|net::/.test(m)).length === 0, errs.concat(consoleErrs).join(" | ").slice(0, 300));
  await page.screenshot({ path: shots + "/tour-end.png" });
  console.log("\n" + pass + " passed, " + fail + " failed"); await browser.close(); process.exit(fail ? 1 : 0);
})().catch(e => { console.error("FAILED", e.message); process.exit(1); });
