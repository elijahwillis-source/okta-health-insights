# Okta Health Insights

A live dashboard for Okta health, with an Okta-expert AI assistant built in.

- **Silent app tiles**: apps with no events for longer than a threshold you choose
- **Error hot spots**: apps and error reasons with the most failures
- **Assignment / provisioning errors**: grouped by user
- **Drill-down + CSV export** on anything you click
- **Assistant**: ask it to troubleshoot; it can search the live events itself

One small Node service (no npm dependencies) polls Okta, holds a rolling window of events in memory, serves the dashboard, and proxies the assistant to the Anthropic API so no key ever reaches the browser.

```
Okta System Log + Apps API  ──poll──▶  server.js  ◀──fetch──  Browser (public/index.html)
                                          │
                                          └── /api/chat ──▶ Anthropic API (key stays server-side)
```

## Quick start (local, no Okta needed)

```bash
node test/mock-okta.js &                       # fake Okta org on :4010
OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test node server.js
# open http://localhost:8080
```

Run the automated smoke test with `npm test`.

## Configuration

Everything is configured with **environment variables**. Nothing secret lives in the repo; see `.env.example` for the full list.

| Variable | Required | Purpose |
|---|---|---|
| `OKTA_ORG_URL` | yes | e.g. `https://yourco.okta.com` |
| `OKTA_API_TOKEN` | one of | SSWS API token (simplest) |
| `OKTA_CLIENT_ID`, `OKTA_PRIVATE_KEY`, `OKTA_KEY_ID` | one of | OAuth 2.0 service app (private_key_jwt) instead of a token |
| `ANTHROPIC_API_KEY` | for assistant | Without it the dashboard works but the assistant is disabled |
| `ANTHROPIC_MODEL` | no | Defaults to `claude-sonnet-5-5` |
| `DASHBOARD_PASSWORD` (+ `DASHBOARD_USER`) | no | Adds HTTP Basic auth. Skip if SSO already fronts the app |
| `POLL_INTERVAL_SECONDS` | no | Default 60 (minimum 15) |
| `LOOKBACK_DAYS` | no | Default 7 |
| `MAX_EVENTS` | no | In-memory cap, default 100000 |
| `OKTA_LOG_FILTER` | no | Narrow the feed on very large orgs |
| `HEAD_HOURS` | no | Newest window loaded first (default 6). The dashboard is current as soon as this is done |
| `BACKFILL_CHUNK_HOURS` | no | Older history is then loaded newest chunk first, in chunks of this size (default 12) |
| `PORT` | no | Default 8080 |

### Okta permissions: use least privilege

The service only reads. Do **not** use a Super Admin token.

- **API token**: create a service account user, assign a custom admin role with read-only access to **System Log** (`okta.logs.read`) and **Applications** (`okta.apps.read`), then create the token as that user.
- **OAuth service app** (preferred for production): grant the `okta.logs.read` and `okta.apps.read` scopes and assign the same read-only custom role to the app. If your org enforces DPoP for service apps, this simple client-credentials flow won't work as written; use an API token or extend `authHeader()` in `server.js`.

## Deploying

The repo is a plain Node 20+ service with a `Dockerfile`. In your deploy tool:

1. Point it at this repo; build with the Dockerfile (or run `node server.js` on Node 20+).
2. Set the environment variables above in the tool's secrets/env store.
3. Expose port `8080` (or set `PORT`). Health check: `GET /healthz` (always open, returns `{"ok":true}`).
4. **Run exactly one replica.** Event history lives in memory per instance and each instance polls Okta separately; more replicas means duplicate Okta API calls and inconsistent views.
5. Restrict access: put it behind your SSO/VPN, or set `DASHBOARD_PASSWORD`. The dashboard shows user emails and failure reasons from your System Log.

## How the data behaves

- On start it loads the newest `HEAD_HOURS` of the System Log first, so the dashboard is current within minutes. It then loads the rest of `LOOKBACK_DAYS` in the background, newest chunk first, and keeps polling for new events.
- While older history is still loading, `/api/status` reports `catchingUp: true` and a `catchUp` block (`pct`, `loadedBack`). The dashboard shows apps it has not seen yet as grey "waiting for history" tiles instead of red "silent" ones, and reloads itself once history completes.
- History is **in memory**: a restart re-fetches from Okta. Okta keeps ~90 days of logs, so nothing is lost.
- Very large orgs (many sign-ins per day) can exceed `MAX_EVENTS`. Use `OKTA_LOG_FILTER` to focus on what matters (apps, provisioning, failures) or raise the cap if you have the memory.
- "Silent" apps are judged from events seen in the loaded window. An app that was already quiet before the window starts looks "never seen". The app list from the Okta Apps API makes such apps show up as "No events".

## Troubleshooting: an app shows "No events" but Okta shows activity

Open `/api/diagnostics` on the deployed service and check:

- `poll.catchingUp: true` means older history is still loading. `poll.catchUp.pct` and `loadedBack` show progress. Recent activity is already included; apps not seen yet show as "waiting".
- `poll.lastError` shows why polling is failing (bad token, missing scope, rate limit).
- `events.held` at `events.cap` means older events are being dropped. The per-app last-seen data is unaffected, but raise `MAX_EVENTS` if you want full drill-downs.
- `inventory.withoutEventsSample` lists apps with no events, and `sameNameSeenUnderOtherId` flags a name that appears in events under a different app id (a duplicate or recreated app).
- `eventAppsNotInInventory` lists apps seen in events that the Apps API did not return as ACTIVE.

## Privacy

Events are kept in memory only, and are not written to disk. When someone uses the assistant, the dashboard summary and any events it looks up are sent to the Anthropic API. If that isn't acceptable for your data, leave `ANTHROPIC_API_KEY` unset and the assistant is switched off.

## API

| Route | Description |
|---|---|
| `GET /healthz` | Liveness check (no auth) |
| `GET /api/status` | Poll health, event count, last error |
| `GET /api/events?since=<ms>` | Events at/after a timestamp |
| `GET /api/apps` | Active apps: labels, ids, and last time each app was seen |
| `GET /api/diagnostics` | Why an app shows "No events": polling state, buffer size, apps with no events, and names that look duplicated |
| `POST /api/chat` | `{messages, summary, windowMs}` → `{text}` |

## Roadmap ideas

Persist history (SQLite/Postgres) so restarts are instant and trends go beyond 7 days; alert to Slack when an app goes silent; per-app provisioning health pulled from the Apps API; role-based views.
