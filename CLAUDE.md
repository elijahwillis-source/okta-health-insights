# Sightline: notes for Claude Code

Sightline is a live IT-health dashboard. It reads the Okta System Log and the Google Workspace OAuth token audit, explains errors in
plain English, raises alerts, and has an AI guide called **Iris**. Single Node process, **zero npm dependencies** (keep it that way),
one HTML file for the whole UI. Deployed on Coolify at https://sightline.coolify.thoughtspot.com. Longer history and decisions:
`docs/HANDOFF.md`. User-facing docs: `README.md`.

## Map of the code

| File | What it does |
| --- | --- |
| `server.js` | HTTP server, security headers, Okta polling with a rate-limit gate (two separate loops: new events, and old history), all `/api/*` routes, the Iris chat tool loop, the one-shot `/api/explain-error`, static files |
| `auth.js` | Okta OIDC sign-in (authorization code + PKCE), sessions, roles, CSRF/Origin check, `REQUIRE_SSO` |
| `audit.js` | Shared audit log: `DATA_DIR/audit-log.jsonl` plus `AUDIT {json}` lines on stdout |
| `policy.js` | Known-error rules, Google app decisions, shared alert rules, location rules, and their own history |
| `public/alerts-core.js` | **The alert logic, in one place**: event helpers, error categories and filters, the Google scope-risk table, and the checks that decide when an alert fires. The page loads it and the server requires it |
| `alerts.js` | The server engine for the shared alerts: gives those checks the server's data, remembers what already fired (`DATA_DIR/alerts-state.json`), keeps the alerts raised |
| `geo.js` | Location alerts: rule validation, matching, the server-side check of each new event, preview, places summary (`DATA_DIR/geo-alerts.json`) |
| `slack.js` | Slack sender (post only), the app manifest, message formatting and escaping, pacing, the per-minute cap |
| `integrations/slack/app-manifest.json` | The Slack app manifest. Generated from `MANIFEST` in `slack.js`; a test checks they match, so change `slack.js` and regenerate the file |
| `google.js` | Google loader: service account with domain-wide delegation, Reports API token audit, newest first |
| `osctrl.js` | osctrl client (read-only service account): node/device lookup, scheduled-query results for the Device Health score, the six on-demand troubleshooting recipes |
| `public/index.html` | The entire UI: one inline `<script>`, all CSS, inline SVG (Iris faces, logo) |
| `test/` | Mock services and seven server test suites (below) |

Runtime data lives in `DATA_DIR` (`/app/data`, a persistent volume): `policy.json`, `audit.jsonl`, `audit-log.jsonl`, `sessions.json`.

## Commands

```bash
# the checks: run all seven before every commit (each prints "N passed, M failed")
for t in smoke smoke-auth smoke-policy smoke-google smoke-ratelimit smoke-google-first smoke-google-load; do bash test/$t.sh | tail -1; done
node test/geo-unit.js | tail -1                    # location rules and Slack: logic, no servers
node test/alerts-unit.js | tail -1                 # the shared alert checks and the server engine: logic, no servers
node test/osctrl-unit.js | tail -1                 # device health score logic, plus the client against a mock osctrl server
bash test/smoke-alerts.sh | tail -1                # shared alerts on the server with sign-in on, routed to Slack; about 6 minutes, run it detached
bash test/smoke-geo.sh | tail -1                   # location alerts and Slack end to end; takes 2 to 5 minutes, so run it detached if your tool has a time limit
# baseline on the current main: 84, 149, 68, 32, 26, 11 passed; google-load prints PASS lines (34, no FAIL); geo-unit 73; smoke-geo 73; alerts-unit 45; smoke-alerts 36; osctrl-unit 52
# the suites share fixed ports (4010 and others), so run them one after another, never at the same time

# syntax check, including the page's inline script
for f in server.js auth.js audit.js policy.js google.js osctrl.js; do node --check $f; done
node -e "const s=require('fs').readFileSync('public/index.html','utf8');new Function(s.match(/<script>([\s\S]*)<\/script>/)[1]);console.log('page parses')"

# run it locally with fakes (no real Okta or Anthropic needed)
node test/mock-okta.js &            # fake Okta on :4010
node test/fake-anthropic.js &       # fake AI on :4020; GET /_last shows the last chat request it received
OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t ANTHROPIC_API_KEY=x ANTHROPIC_BASE_URL=http://localhost:4020 PORT=8090 node server.js
```

**Browser (UI) tests:** only one exists, for the Alerts page, the Integrations pages and the Slack setup guide: `bash test/browser/run-geo-ui.sh` (108 checks, covering Alerts, Integrations, Slack routing and the Slack guide; `bash test/browser/run-geo-ui.sh tour.js` walks every page, 22 checks; one time first: `cd test/browser && npm install && npx playwright install chromium`).
The older UI tests lived outside the repo and were lost: see "Rebuild the browser tests" in `docs/HANDOFF.md`. Check any other UI change by looking at it (Playwright screenshots) and keep UI changes small.

## Rules that matter

- **Never print, log, commit or ask for secrets.** Settings are set in Coolify by name only. Env var names are in `.env.example`.
- **Escape everything dynamic** with the page's `esc()` before it goes into HTML (Okta names, app names, reasons, Google data are attacker-influenced).
  No inline event handlers (`onclick=` etc.) and no `javascript:` URLs: events are delegated from data attributes. This is what makes a stricter CSP possible later.
- **Zero dependencies.** Do not add npm packages to the app. Test-only tools (e.g. Playwright) go in their own folder with their own `package.json`.
- **Sign-in:** everyone signs in through Okta. Roles come from Okta groups: owner > admin > user. There is **no back door**: no emergency
  password, and `DASHBOARD_PASSWORD` is ignored while sign-in is on. `REQUIRE_SSO=true` makes the app refuse everything unless sign-in is fully configured.
  Role checks live in the API routes **and** in `policy.js`; keep both. The policy history (`/api/policy/audit`) and `/api/audit` are admin+.
- **Known errors hide, never delete.** Everything hidden stays counted and visible behind a toggle. Every policy change needs a named actor and a reason.
- **Okta rate limits:** one gate paces all calls (`OKTA_MAX_RPM`, default 30, minimum 6, a reserve for the head poll, `x-rate-limit` header waits, halve on 429).
  Never add an Okta call that skips the gate. Sightline must use its own read-only API token, not one shared with other tools.
- **Device health (osctrl) is read-only, on purpose.** Sightline signs in to osctrl as a dedicated service account (`ai-readonly`) that cannot write, carve or remediate — nothing in this app should ever suggest it can take an action on a device. The Device Health score reads osctrl's *scheduled* query results (`osctrl.js`'s `SCHEDULED` names) via the per-node result log (`GET /api/v1/logs/result/<env>/<uuid>?q=<name>`, NOT the on-demand `/queries/<env>/results/<name>` endpoint — that one is for ad-hoc queries only); the six assistant recipes (`osctrl.RECIPES`) run their own on-demand, read-only query and wait up to `OSCTRL_QUERY_TIMEOUT_MS` (default 2 minutes) for the device to answer. Auth is `Authorization: Bearer <token>` (verified against osctrl v0.7.x), with a one-time fallback to the no-prefix form and a re-login on 401/403. **osctrl allows only one live token per user**: a login elsewhere (another Sightline instance, a human using the same service account) silently evicts ours — not with a 401/403, but a redirect to `/forbidden` that `fetch` follows into a 200 HTML page, so `okJson` also treats "200 but not real JSON" (or landing on `/forbidden`) as an auth failure and retries once after a fresh sign-in. `login()` is single-flight (one shared in-flight promise) and a recovering call only clears the token if it is still the one that got evicted, so several calls racing into an eviction share one re-login instead of each minting a token and evicting the others in turn. Node field names (`memory`, `cpu`, `system_info.system.hardware_model`, etc.) were verified against osctrl v0.7.x's own frontend source — `osctrl.js` still reads a couple of plausible fallback names per field and degrades to "unknown"/"partial" instead of throwing, in case a future osctrl version changes shape. **A result log row's `columns` field is a JSON-encoded STRING, not an object** (verified against the live API) — every reader goes through `colsOf`/`parseColumnsField`, never `row.columns` directly. Decoding it can itself yield an ARRAY of rows (osquery snapshot-mode logs), which `rowsFromItem` expands into separate rows; and differential logs emit stale "removed" rows alongside "added" ones, so picking the row to use (`sortRows` in `resultsOf`) prefers "added"/"snapshot" over "removed" and only breaks ties by `created_at`, never by trusting the API's own array order. **osquery 5.24.1's `apps` table has no `version` or `last_opened_at` columns** — the real ones are `bundle_short_version` and `last_opened_time` (verified live: the old names threw "no such column"). `RECIPES.installed_apps`'s SQL and the scheduled-apps row reader both use the real names now, with the old names kept as a fallback in case an older osquery ever reports them instead. **`GET /api/v1/nodes/<env>?q=` only searches hostname/localname/uuid/ip — never `hardware_serial`** (verified live), so `resolveDevice` falls back to walking the full (paged) node list (`allNodes`) and matching client-side whenever the server-side search finds no exact match; this is the only way a serial-number lookup ever resolves. **The device list and a device's detail view compute the health score from the exact same inputs** (`scoreInputsFor`, shared by `deviceSummaries` and `deviceDetail`, both going through `resultsOf`'s own cache) — the list used to score disk/battery/uptime as "no data, full marks" without even trying to fetch them, so it could show a higher score than the detail for the same device. Never give the list a cheaper/partial scoring path again: if that ever needs to change for performance, cache the detail's own computed score per device and have the list read that instead, rather than reintroducing two different ways to compute the same number.
- **Memory:** events are held in memory up to `MAX_EVENTS` (default 100000, about 31 hours at our volume), `LOOKBACK_DAYS` = 7.
  Every restart or redeploy empties it and the history reloads (about 20 to 30 minutes). Google loads by hour, newest first, without keeping per-event data.
- **Iris** (the assistant): her voice is `SYSTEM` in `server.js`. The Explain buttons use `focus: true`: the server swaps in `FOCUS_RULES`, drops the dashboard
  summary, allows only the `lookup_user_events` tool and refuses the rest. The page builds the one-event question in `eventBrief()`. Follow-up questions are normal.
  The panel width is fixed (a third of the window, 340 to 640 px, the app keeps at least 420 px): there are no resize controls on purpose.
- **Failure rate** = failed/denied events ÷ all events in the window, so it is the share of *log events*, not of sign-ins. Do not describe it as a sign-in success rate.
- **Location alerts are worked out on the server** (`geo.js`, called from `onFresh` in `server.js` for newly arrived events only), not in the page. Only events newer than `GEO_MAX_AGE_MINUTES` (30) count and each is looked at once
  (remembered on disk), so a restart or redeploy never replays history as news. The older alert rules (spike, new error, silent, Google) are still worked out in each browser; moving them to the server is an open item.
- **Two polling loops, on purpose:** `pollLogs` (new events, on a steady beat) and `backfillLoop` (old history). They were one loop and a history step waiting for the Okta rate limit delayed new events (and so alerts) by up to a minute. Both trim the buffer. Keep them separate.
- **Slack:** post only (`chat:write`, `chat:write.public`). The token comes only from `SLACK_BOT_TOKEN`; it must never appear in an API answer, a log or the audit log (a test checks). Everything from outside that goes into a Slack message is escaped (`mx` in `slack.js`), including the notification fallback text.
  Links in Slack use `SLACK_LINK_URL` (falling back to `PUBLIC_URL`): **setting `PUBLIC_URL` alone switches single sign-on on and locks the app out**, so never suggest it to someone without sign-in.
- **ALERT LOGIC LIVES IN `public/alerts-core.js`, AND ONLY THERE.** Helpers such as `appOf`, `normErr`, `catOf`, `compileFilter`, `scopeInfo`, and the checks `evalRule`, `evalSilent`, `evalGoogleRule`, `makeNotif`, `runRules` are defined in that file (a browser global in the page, `require` on the server). Do not copy them back into `index.html` or `server.js`: the page and the server would drift and alerts would fire differently in each. The page only has thin adapters (`pageCtx`, `evalRule(r,now)` and friends) that hand the shared checks the page's data. Adding a helper? Put it in the core and export it.
- **Shared alerts are checked on the server** (`runAlerts` in `server.js` every 30 s and after each poll, through `alerts.js`); the page skips them (`evaluateAlerts` returns early when `alertRulesShared`) and shows what the server raised, from `GET /api/alerts/feed` (`loadServerAlerts`). Alerts that are not shared stay in the browser, are checked by the same core, and cannot go to Slack. `slack` and `channel` are fields of every alert rule (validated in `policy.js` `cleanRule`); the alert editor must keep them when it saves (it does: both save branches carry them).
- **Alerts and Integrations are separate on purpose.** The Alerts page starts empty (no starter alerts) and "New alert" first asks what it is about (`openAlertPicker`); location alerts are just one kind in the same list. Anything about Slack lives on the Integrations page (`renderIntegrations`, `slackDetail`): the connection, the setup guide, and **Alert routing**, which edits `slack` and `channel` on the location rules (through the same audited `PUT /api/policy/geo-rules`, so it needs a reason). Every shared alert and every location alert can be routed to Slack; alerts that are only in a browser cannot. The alert editor deliberately has no Slack fields. The Teams, Email and Webhook cards are "Coming soon" placeholders, not features.
- **The Slack setup guide** (`openSlackGuide` in `public/index.html`) is a six-step dialog with simplified SVG pictures built by small helpers (`sg*`). The pictures are drawings of the steps, not copies of Slack's screens, and say so; if Slack changes its wording, update the text and `SG_ART`. It reads the live status from `GET /api/slack` when it opens and every 5 seconds, so the last step turns green by itself.
- **A notification's `type` must not start with "g"**: the page treats those as Google alerts (and offers an Explain button that asks about a Google app). Location alerts use `"location"`.
- localStorage keys keep the old `okta.*` names on purpose.
- **One shared item-detail drawer, not per-row accordions.** Clicking a device, a person or a Google app opens `#itemDrawer` (`openItemDrawer`/`updateItemDrawer`/`closeItemDrawer` in `public/index.html`) instead of expanding a row in place. `S.idKind`/`S.idKey` say what's currently shown; a section's render function (`renderUsersTable`, `renderGoogleView`, `renderDevicesView`) checks them to highlight the open row and to refresh the drawer's content when the underlying data changes. The drawer has **no backdrop and does not intercept clicks**: the whole point is that the list stays clickable underneath it, so picking a different row swaps the drawer instead of closing it first — a backdrop would silently break that. Buttons rendered inside the drawer (explain/ask-Iris/mark-known for a person, approve/flag/ask-Iris for an app) are handled by click listeners on `#itemDrawer`, not on the list's own container, since that content no longer lives inside the list's DOM. If you add a fourth kind of detail view, follow this pattern rather than adding another per-row accordion.

## Working style

Small changes, one concern per commit. Add or update a test with every behavior change. Run the seven suites and the syntax checks before committing.
Deploys are done by redeploying in Coolify (a restart is not enough to pick up new code), by whoever manages Coolify. **Do not redeploy
shortly before a demo**: it empties the history. When generating code with line comments, check no `//` comment swallowed code on the same line (this has bitten us twice).
Browser headings are upper-cased by CSS, so compare text with `textContent`, not `innerText`.
