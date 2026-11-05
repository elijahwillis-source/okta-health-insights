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
| `geo.js` | Location alerts: rule validation, matching, the server-side check of each new event, preview, places summary (`DATA_DIR/geo-alerts.json`) |
| `slack.js` | Slack sender (post only), the app manifest, message formatting and escaping, pacing, the per-minute cap |
| `integrations/slack/app-manifest.json` | The Slack app manifest. Generated from `MANIFEST` in `slack.js`; a test checks they match, so change `slack.js` and regenerate the file |
| `google.js` | Google loader: service account with domain-wide delegation, Reports API token audit, newest first |
| `public/index.html` | The entire UI: one inline `<script>`, all CSS, inline SVG (Iris faces, logo) |
| `test/` | Mock services and seven server test suites (below) |

Runtime data lives in `DATA_DIR` (`/app/data`, a persistent volume): `policy.json`, `audit.jsonl`, `audit-log.jsonl`, `sessions.json`.

## Commands

```bash
# the checks: run all seven before every commit (each prints "N passed, M failed")
for t in smoke smoke-auth smoke-policy smoke-google smoke-ratelimit smoke-google-first smoke-google-load; do bash test/$t.sh | tail -1; done
node test/geo-unit.js | tail -1                    # location rules and Slack: logic, no servers
bash test/smoke-geo.sh | tail -1                   # location alerts and Slack end to end; takes 2 to 5 minutes, so run it detached if your tool has a time limit
# baseline on the current main: 77, 149, 68, 32, 26, 11 passed; google-load prints PASS lines (33, no FAIL); geo-unit 69; smoke-geo 73
# the suites share fixed ports (4010 and others), so run them one after another, never at the same time

# syntax check, including the page's inline script
for f in server.js auth.js audit.js policy.js google.js; do node --check $f; done
node -e "const s=require('fs').readFileSync('public/index.html','utf8');new Function(s.match(/<script>([\s\S]*)<\/script>/)[1]);console.log('page parses')"

# run it locally with fakes (no real Okta or Anthropic needed)
node test/mock-okta.js &            # fake Okta on :4010
node test/fake-anthropic.js &       # fake AI on :4020; GET /_last shows the last chat request it received
OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t ANTHROPIC_API_KEY=x ANTHROPIC_BASE_URL=http://localhost:4020 PORT=8090 node server.js
```

**Browser (UI) tests:** only one exists, for the Alerts page, the Integrations pages and the Slack setup guide: `bash test/browser/run-geo-ui.sh` (99 checks, covering Alerts, Integrations and the Slack guide; one time first: `cd test/browser && npm install && npx playwright install chromium`).
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
- **Alerts and Integrations are separate on purpose.** The Alerts page starts empty (no starter alerts) and "New alert" first asks what it is about (`openAlertPicker`); location alerts are just one kind in the same list. Anything about Slack lives on the Integrations page (`renderIntegrations`, `slackDetail`): the connection, the setup guide, and **Alert routing**, which edits `slack` and `channel` on the location rules (through the same audited `PUT /api/policy/geo-rules`, so it needs a reason). Only server-checked alerts can be routed to Slack; the browser-checked ones cannot yet. The alert editor deliberately has no Slack fields. The Teams, Email and Webhook cards are "Coming soon" placeholders, not features.
- **The Slack setup guide** (`openSlackGuide` in `public/index.html`) is a six-step dialog with simplified SVG pictures built by small helpers (`sg*`). The pictures are drawings of the steps, not copies of Slack's screens, and say so; if Slack changes its wording, update the text and `SG_ART`. It reads the live status from `GET /api/slack` when it opens and every 5 seconds, so the last step turns green by itself.
- **A notification's `type` must not start with "g"**: the page treats those as Google alerts (and offers an Explain button that asks about a Google app). Location alerts use `"location"`.
- localStorage keys keep the old `okta.*` names on purpose.

## Working style

Small changes, one concern per commit. Add or update a test with every behavior change. Run the seven suites and the syntax checks before committing.
Deploys are done by redeploying in Coolify (a restart is not enough to pick up new code), by whoever manages Coolify. **Do not redeploy
shortly before a demo**: it empties the history. When generating code with line comments, check no `//` comment swallowed code on the same line (this has bitten us twice).
Browser headings are upper-cased by CSS, so compare text with `textContent`, not `innerText`.
