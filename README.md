# Okta Health Insights

A live dashboard for Okta health, with an Okta-expert AI assistant built in.

- **Silent app tiles**: apps with no events for longer than a threshold you choose
- **Error hot spots**: apps and error reasons with the most failures
- **Assignment / provisioning errors**: grouped by user
- **User lookup**: search by email, username or name and the server asks Okta's System Log for that person directly (live, up to 90 days), so it works right after a deploy and does not depend on what has been loaded. Shows every error tied to them (failed sign-ins, assignment and provisioning errors, AD failures), their top reasons and a CSV export. Logins with the same name before the @ (an Okta email and an AD login) are treated as one person. The assistant can do the same lookup
- **App activity**: instead of a wall of tiles, apps are grouped into expandable sections by state (Silent, Quiet, Active, and Waiting while history loads). Each header says in plain words what the state means and how many apps are in it; the page opens with only the apps that need attention showing, ten at a time, and any section slides open to list the rest. There is a search box, Expand all and Collapse all, and sortable columns. Motion is skipped for people who prefer reduced motion
- **App shell**: a left menu (Overview, Errors, Apps, People, Alerts, Data & settings, plus the assistant), a slim top bar with search, the time window and a notification bell, and a page for each area. Every page has its own address (`#/errors`, `#/apps`, ...), so the browser's Back button and bookmarks work. The menu collapses to an icon rail (and does so automatically on small screens); the assistant opens as a slide-out panel from anywhere; theme can follow your device or be set to light or dark. Keyboard: `/` jumps to search, `Esc` closes panels
- **Error filters (two separate sets)**: the **dashboard filters** (the filter bar on Overview and People) choose which errors the Overview numbers, charts and People table show; the **Errors page** has its **own** filters that only change that page, so exploring errors never changes the dashboard and the other way round. Each set can filter by type (sign-in and password, provisioning and assignment, token and OAuth, access denied, other), failed or denied, one or more apps, "reason contains", "hide errors containing", and a person. They are remembered separately in your browser. Neither changes which apps are silent, and neither changes "Copy data for slides". The Errors page lists every matching error with Explain and Hide buttons per row, a chart, a breakdown by type, and CSV export
- **Filters are always visible when on**: a button in the top bar shows when the page you are on has an active filter ("Dashboard filters on · Clear" on Overview and People, "Errors page filters on · Clear" on Errors; hover it to see what is filtered), numbers that depend on the dashboard filters are shown in a neutral colour with "filtered" beside them, and an empty card says whether the filters are the reason. A filter you set yourself is remembered; a drill-down (clicking a top reason opens the Errors page filtered to it, as does opening an alert) is not remembered across reloads and never changes the dashboard filters
- **Alerts and notifications**: rules that watch for errors and tell you in the app (see "How alerts work" below)
- **Explained errors**: in "Users with assignment / provisioning errors", clicking a row slides open that person's errors. The most common one is explained straight away (what it means, likely causes, how to fix, how to confirm); the others have a "What does this mean?" button, and "Ask the assistant" sends the specific error to the chat. Explanations are cached for 24 hours, so the same error is only explained once
- **App lookup**: search an app (or click an app tile or bar) to see every failure and deny it has produced, live from Okta for up to 90 days: how many, which reasons, how many people each affects, errors per day and the latest events. The assistant can do the same lookup
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
| `GOOGLE_SA_KEY` | for Google OAuth | The Google service account key: the JSON file's contents, or the same text base64-encoded. See "Google Workspace OAuth" below |
| `GOOGLE_ADMIN_EMAIL` | for Google OAuth | The dedicated admin the service account acts as (needs only the Reports privilege) |
| `GOOGLE_LOOKBACK_DAYS` | no | History to load first (default 30, at most 180; Google keeps 6 months) |
| `GOOGLE_POLL_SECONDS` | no | How often to check (default 300) |
| `LOOKUP_MAX_PAGES` | no | Per-user search: pages of 1000 Okta events fetched per search term (default 10) |
| `LOOKUP_MAX_EVENTS` | no | Per-user search: most events returned to the page (default 5000) |
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

## How the user search works

Searching a person calls `GET /api/user-events`, which runs Okta's System Log keyword search (`q`) for the typed text, plus the part before the `@` so the Okta email and the AD login both match. Results are cached for 60 seconds and limited to 30 searches a minute. If Okta cannot be reached (or the page has no backend, for example with an uploaded file), the search falls back to the events already loaded and says so. Okta's keyword search matches whole words, so a fragment like `pank` may only be found in loaded events; a full email, username or first or last name works best.

## How the app lookup works

Searching an app resolves its Okta app id from the app list (or from the events), then `GET /api/app-events` asks Okta for that app's failures and denies: `target.id eq "<id>"` (sign-ins and provisioning) and `actor.id eq "<id>"` (OAuth clients), each combined with `outcome.result` FAILURE or DENY, newest first. If Okta rejects the combined filter the server fetches the app's events and keeps the errors itself, and the card says so. Results are cached for 60 seconds and share the 30-searches-a-minute limit with the user search. Without the backend (an uploaded file, sample data) the card lists the errors in the events already loaded.

## How alerts work

Rules live on the Alerts page. There are three kinds:

- **Too many errors**: at least N matching errors within 15 minutes, 1 hour, 6 hours or 24 hours, counted all together, per app, or per person. The rule has its own filter (types, apps, "reason contains", "hide errors containing"), so "10 provisioning failures for one app in an hour" is one rule.
- **A new kind of error**: an error text that appears in the chosen window but was not seen in the earlier history. Ids inside the text are ignored, so the same error for a different person is not "new".
- **An app goes silent**: an app moves into the Silent state. The first check only remembers what is already silent, so you are not told about every dormant app on day one.

Five starter rules are created the first time, and you can edit, switch off, delete or reset them. On the Errors page, "Create an alert from this" turns the current filter into a rule.

Rules are checked each time the data refreshes (about once a minute). A firing becomes a notification in the bell (with an unread count, also shown on the Alerts menu item), a pop-up for new ones, and an entry in the Alerts feed with View (opens the matching errors), Explain (asks the assistant) and Dismiss. A cooldown per rule stops the same alert repeating. The first check after you open the page is quiet: it records conditions that already exist as unread notifications without popping up. Optional desktop notifications can be turned on in Data & settings.

**Limits to know about.** Rules, filters and notifications are stored in the browser (localStorage), so they belong to one person on one browser, and alerts are only checked while the page is open. Sample data and uploaded files never raise alerts. For alerts that arrive when nobody has the dashboard open (email, Slack, a shared rule set) the checking has to move to the server; that is the natural next step.

## Google Workspace OAuth (which apps people connected to their Google accounts)

The **Google OAuth** page shows every app that people have connected to their Google accounts, what access each one asked for (as plain-English scopes coloured by risk), who connected it, when it first appeared, and who revoked or was blocked. It adds three alert rules (a new app is authorized, high-risk access is granted, many people authorize the same app), and a person's lookup also lists the Google apps they connected. It is read-only and cannot change anything in Google.

**What the data is.** The Admin SDK Reports API "token" audit log. It records *consent*: authorize, request, revoke and deny events, each with the app name, client ID and scopes (and some API activity). It is not a record of every later sign-in with an app. Google reports these events a couple of hours late and keeps them for 6 months, so consents older than that cannot be seen. The page does not show whether Google considers an app trusted or verified; that lives in the Admin console.

**Why a service account with domain-wide delegation.** It is Google's standard server-to-server pattern for reading Workspace data: no person's password or refresh token is stored, it runs unattended, and its reach can be limited tightly:

1. One scope only, `https://www.googleapis.com/auth/admin.reports.audit.readonly` (read-only audit logs).
2. It acts as a dedicated admin whose role has only the **Reports** privilege, not a super admin.
3. The service account has no Google Cloud project roles.

**Setup (about 30 to 60 minutes, needs a super admin):**

1. Google Cloud console: pick or create a project, and enable the **Admin SDK API** (APIs & Services > Library).
2. IAM & Admin > Service accounts: create one (for example `okta-health-readonly`) and give it no roles. Under Keys, add a JSON key. Note its numeric **Client ID** (on the account's details page).
3. Admin console > Account > Admin roles: create a role with only the **Reports** privilege and assign it to a dedicated admin user (for example `audit-reader@yourdomain`).
4. Admin console > Security > Access and data control > API controls > **Manage domain-wide delegation**: add the Client ID with exactly the one scope above.
5. On the server set `GOOGLE_SA_KEY` (the JSON key's contents, or base64 of it) and `GOOGLE_ADMIN_EMAIL`, then redeploy. Menu names in Google's consoles change from time to time; look for the closest match.

**Handling the key.** The key is a credential: keep it only in the deployment's secret settings, never in the repository, and rotate it periodically. The app never sends it to the browser or logs it, and the status and events endpoints do not include it. If your organisation blocks service account keys (the Google Cloud policy "Disable service account key creation"), tell the person who manages that policy what this is for, or ask for the alternative below.

**If something is wrong, the page says what and how to fix it:**

| Message | Meaning |
|---|---|
| `unauthorized_client` | Domain-wide delegation is missing or has the wrong Client ID or scope (step 4) |
| `invalid_grant` | `GOOGLE_ADMIN_EMAIL` is wrong, not an admin, or suspended |
| 403 from the Reports API | The admin lacks the Reports privilege (step 3) |
| "Admin SDK API has not been used" | Step 1: enable the API, then wait a minute |

Sample data (Data & settings > Use sample data) includes sample Google apps so you can see the page before connecting.

## How the error explanations work

Clicking a row sends only the error text, the app name, the event type and two counts to `/api/explain-error`. Ids inside the text (member ids, user ids) are replaced by `<id>` first and repeated segments are collapsed, so the same error for ten people is one cache entry and one question to the model. The model is asked for a fixed shape (what it means, likely causes, how to fix, how to confirm), is told to say what to check instead of guessing, and has no access to your data beyond that text. Treat the answer as guidance from an Okta expert who has not seen your tenant: verify before changing a production integration.

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
| `GET /api/user-events?q=…&q=…&days=7` | Live per-user search of Okta's System Log (newest first, max 90 days). Uses the same read-only log permission; ignores `OKTA_LOG_FILTER` |
| `GET /api/app-events?id=…&days=7` | Live per-app errors from Okta's System Log (failures and denies, newest first, max 90 days, up to three ids). Uses the same read-only log permission |
| `POST /api/explain-error` | `{reason, apps, eventTypes, count, people}` returns `{text, cached}`: a short explanation of one error and how to fix it. No tools, cached 24 hours by error text; shares the assistant rate limit |
| `POST /api/chat` | `{messages, summary, windowMs}` → `{text}` |

## Tests

```bash
bash test/smoke.sh          # Okta side: server, endpoints, lookups, assistant (fake Okta, fake Anthropic)
bash test/smoke-google.sh   # Google side: a strict fake Google that verifies the signed sign-in
```

## Roadmap ideas

Persist history (SQLite/Postgres) so restarts are instant and trends go beyond 7 days; alert to Slack when an app goes silent; per-app provisioning health pulled from the Apps API; role-based views.
