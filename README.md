# Sightline

IT health at a glance. A live dashboard that reads your identity and app activity (Okta, and optionally Google Workspace) and shows what is failing, who is affected and what to do about it, with an expert AI assistant built in. (Previously named Okta Health Insights.)

Brand files (logo, favicon, PNGs for slides) are in `public/brand/`.

- **Silent app tiles**: apps with no events for longer than a threshold you choose
- **Error hot spots**: apps and error reasons with the most failures
- **Assignment / provisioning errors**: grouped by user
- **User lookup**: search by email, username or name and the server asks Okta's System Log for that person directly (live, up to 90 days), so it works right after a deploy and does not depend on what has been loaded. Shows every error tied to them (failed sign-ins, assignment and provisioning errors, AD failures), their top reasons and a CSV export. Logins with the same name before the @ (an Okta email and an AD login) are treated as one person. The assistant can do the same lookup
- **App activity**: instead of a wall of tiles, apps are grouped into expandable sections by state (Silent, Quiet, Active, and Waiting while history loads). Each header says in plain words what the state means and how many apps are in it; the page opens with only the apps that need attention showing, ten at a time, and any section slides open to list the rest. There is a search box, Expand all and Collapse all, and sortable columns. Motion is skipped for people who prefer reduced motion
- **App shell**: a left menu (Overview, Errors, Apps, People, Alerts, Data & settings, plus the assistant), a slim top bar with search, the time window and a notification bell, and a page for each area. Every page has its own address (`#/errors`, `#/apps`, ...), so the browser's Back button and bookmarks work. The menu collapses to an icon rail (and does so automatically on small screens); the assistant opens as a slide-out panel from anywhere; theme can follow your device or be set to light or dark. Keyboard: `/` jumps to search, `Esc` closes panels
- **Error filters (two separate sets)**: the **dashboard filters** (the filter bar on Overview and People) choose which errors the Overview numbers, charts and People table show; the **Errors page** has its **own** filters that only change that page, so exploring errors never changes the dashboard and the other way round. Each set can filter by type (sign-in and password, provisioning and assignment, token and OAuth, access denied, other), failed or denied, one or more apps, "reason contains" and "hide errors containing"; the Errors page can also filter by person (on the dashboard that job belongs to the People page's "Find a person"). They are remembered separately in your browser. Neither changes which apps are silent, and neither changes "Copy data for slides". The Errors page lists every matching error with Explain and Hide buttons per row, a chart, a breakdown by type, and CSV export
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
| `OKTA_MAX_RPM` | no | The most requests a minute Sightline may send to Okta (default 30, minimum 6). See "Okta rate limits" below |
| `OKTA_PAGE_SIZE` | no | Events per request when loading the System Log (default and maximum 1000) |
| `DATA_DIR` | no | Where shared policy (known-error rules, Google app decisions, the audit log) is kept. Default `/app/data` in the container. **Mount a persistent volume here** |
| `USER_HEADER` | no | The header your sign-in proxy sets to the signed-in person's email, for example `X-Forwarded-Email`. Only set it behind a proxy that sets and protects that header. It makes "who changed this" verified and makes `POLICY_ADMINS` enforceable |
| `POLICY_ADMINS` | no | Comma-separated emails allowed to change policy. Everyone else can look. Only enforced together with `USER_HEADER` |
| `POLICY_REQUIRE_EXPIRY` | no | `true` makes every exception need an expiry date |
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

## Finding a person, and looking up an app

- **People page: two modes, one box.** With the "Find a person" box empty you are *browsing*: the list of people with assignment or provisioning errors (rows expand to explain each error) and its filter bar. The list is **newest first by default**; click any column heading (User, Errors, Apps, Most common reason, Last) to sort by it, click again to reverse, and the arrow shows the active sort. Your choice is remembered in the browser. It shows 15 people at a time with a "Show more" button, and the sort is applied before the cut-off, so the newest errors are never the ones left out. As soon as you type, you are *searching*, and only the search is shown: a panel suggests matching people from the loaded data (with their error counts, and a marker for those who also have assignment errors) and always offers "Search Okta for …". A complete email address is looked up automatically after a short pause; anything else needs a click, Enter or **Look up**, so partial words never trigger an Okta search. The person's results show everything about them, and each line under "What is going wrong" has a "What does this mean?" button. Results from an earlier lookup dim once the text no longer matches them. **Clear**, or emptying the box, goes back to browsing. The top search bar opens the same box. There is no separate Person filter on the Overview or People filter bars; the Errors page keeps its own.
- **Apps page: the app lookup is first**, above the App activity sections.
- **Filters on both lookups.** Once you look up an app or a person, a filter bar appears with the error type (with counts for that app or person), failed or denied, "reason contains", "hide errors containing", and a person (app lookup) or an app (person lookup). They only change that lookup's results, are never saved, and reset when you look up something else. They do not touch the dashboard or Errors page filters.
- Long errors (for example one that lists dozens of member ids) are shown on one line with the ids removed and repeats collapsed, with the original in the tooltip, everywhere.

## Single sign-on with Okta, roles and the audit log

Sightline can sign people in with Okta (OpenID Connect, authorization code flow with PKCE). Set the variables below and everyone is asked to sign in; leave them out and nothing changes (the password if you set one, otherwise open).

**Roles** come from Okta groups, so Okta stays the one place that decides who has what:

| Role | Can do |
| --- | --- |
| **user** | Look at everything (dashboards, errors, apps, people, Google apps, lookups) and use the assistant. Cannot change anything shared. |
| **admin** | Also manage known errors, Google app decisions and the shared alert rules, and read the audit log. |
| **owner** | Also see how access is set up (the Access tab), see who is signed in, and end other people's sessions. |

**In Okta** (Admin Console):
1. Applications, Create App Integration, **OIDC - OpenID Connect**, **Web Application**.
2. Sign-in redirect URI `https://YOUR-ADDRESS/callback`; sign-out redirect URI `https://YOUR-ADDRESS/logged-out`; grant type Authorization Code.
3. Create three groups (for example `sightline-owners`, `sightline-admins`, `sightline-users`), put people in them, and **assign the groups to the app**. Okta then only lets assigned people in at all.
4. Put the groups in the ID token: on the app's Sign On tab (OpenID Connect ID Token) set *Groups claim type* to Filter, claim name `groups`, and a filter such as "Starts with" `sightline-`. If you use a custom authorization server (`/oauth2/default`) add a `groups` claim there instead (Security, API, Authorization Servers, Claims).
5. Copy the Client ID and Client Secret.

**In Coolify** set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` (mark it secret), `PUBLIC_URL`, `SESSION_SECRET` (32+ random characters), and `OIDC_OWNER_GROUPS` / `OIDC_ADMIN_GROUPS` / `OIDC_USER_GROUPS`, then redeploy. `OWNER_EMAILS` names owners directly if you want to get in before the groups exist. The Okta API token that Sightline uses to *read* the System Log is separate and unchanged. Sessions are stored in `DATA_DIR`, so a redeploy does not sign anyone out; keep the persistent volume.

**If sign-in is half set up, Sightline fails closed**: every page is refused with a message naming the missing setting (never a value), and `/healthz` still answers so Coolify stays happy.

**There is no back door.** There is deliberately no emergency password and no special page: everyone, owners included, signs in through Okta, so every sign-in is a named person in the audit log. If sign-in itself breaks, the fix is in the hosting platform: correct the `OIDC_*` settings and redeploy (a half-set-up sign-in tells you exactly which setting is missing). Keep two or more people in the owners group so one absence never matters. `DASHBOARD_PASSWORD` is ignored while sign-in is on. **`REQUIRE_SSO=true`** goes one step further: Sightline then refuses to serve anything unless sign-in is fully configured, so a mistake can never leave it open to the world.

**What is checked on every sign-in:** the ID token's signature against the provider's published keys, its issuer, audience, expiry and nonce, a one-time `state` tied to the browser that started the sign-in, and PKCE. Session cookies are HttpOnly, SameSite=Lax and (on https) Secure; every sign-in gets a fresh session id; requests that come from another site are refused.

**The audit log** (Policy page, Audit log tab, for admins and owners; exportable as CSV) records sign-ins, failed sign-ins and why, people refused for lacking a group, sign-outs, expired and ended sessions, refused requests (who tried what, and which role it needed), and every change to known errors, Google app decisions and alert rules, with the before and after. It is stored in `DATA_DIR/audit-log.jsonl` (the policy store keeps its own older `audit.jsonl` beside it) and also printed to the container log as `AUDIT {json}` lines for a log shipper (set `AUDIT_STDOUT=false` to stop that).

**Alert rules** are per browser until an admin clicks **Publish them for everyone** on the Alerts page. From then on there is one shared set, only admins can change it, and every change is audited. (Notifications themselves, what has fired and been read, stay per person.)

## Iris, the assistant, side by side with the app

The assistant is **Iris**, a friendly guide with her own face and voice (the eye character in the logo): the menu item and the top-bar button say **Ask Iris**. She answers in plain words, answer first, and while she works her face and a changing line show it ("Let me take a look…", "Checking the logs…") instead of one canned message. Her voice is set in the `SYSTEM` instructions in `server.js`; the error explainer keeps its own neutral instructions. She is an AI and says so if asked.

**Explain means this error, for this person.** The **Explain** button on an error row (and **Ask Iris** on a person's error on the People page) asks Iris about that one event: the person, the time, the app, the event type, the exact reason, and what else happened for that person in the 15 minutes around it, with one line saying how common it is. The chat shows a short line ("Explain this error for someone@example.com (ServiceNow, 1:05 PM)"). The server puts Iris in focus mode for these questions: she answers in a short fixed shape (what happened, likely cause, what to do), gets no dashboard-wide summary, and can only look up that one person, so she cannot go through every incident of the same error. Any follow-up you type gets all her tools back, so "how widespread is this?" works as usual.

Open her and she docks on the right as a second pane: the app moves over to the left and reflows to fit (the chart redraws, the cards re-wrap), so you can read the data and talk to her at the same time. Her width is fixed, so there is nothing to pick: a third of the window, never under 340 px or over 640 px, and never so wide that the app has less than 420 px. On a window narrower than 1,400 px the menu shrinks to icons while she is open and comes back when you close her (a menu you collapsed yourself stays collapsed). Below 900 px there is no room to split, so she floats over the app instead. Escape or the X closes her.

## Policy: known errors and approved Google apps

The **Policy** page holds the decisions your organisation has made. They are shared (everyone sees the same rules), every change needs a reason, and every change goes in an audit log.

**Known errors.** Open an error (Errors page, or a person's errors on the People page) and choose **Mark as known**. You see what the rule would hide before you save, give a reason (required), an optional ticket, and an expiry (default 90 days). From then on the matching errors are left out of the counts, the charts and the alerts. They are never deleted or hidden silently: the Overview and Errors pages always say how many are hidden, and one click shows them again, marked "Known". Guardrails: a rule must say which errors it is about (a message, an app, an event type, a person or an error type, never just "failures"); a rule that would hide 40% or more of all errors needs an explicit confirmation; expired rules stop applying by themselves; rules can be switched off without deleting them.

**Google apps.** On the Google OAuth page, open an app and choose **Approve** or **Mark as not allowed**. An approval covers exactly the access the app had when it was reviewed. If the app later asks for more, it shows **New access**, counts as needing review again, and the alert "An approved Google app asked for new access" fires. Approved apps do not raise the new-app, high-risk or many-people alerts. A not-allowed app raises "A not-allowed Google app was authorized" whenever someone authorizes it. (Sightline only reads, so "not allowed" is a record and an alarm; block the app in the Google Admin console, Security, API controls.) Approvals can expire (default 1 year), and the page counts apps that still **need review**.

**Who did it.** Sign-in to the dashboard is a shared password, so it cannot say who someone is. If you run the dashboard behind a sign-in proxy that sets a header with the person's email, set `USER_HEADER` and names are verified (shown with a tick), and `POLICY_ADMINS` can limit who may change things. Otherwise the person types their name before changing anything; it is recorded, and the audit log marks it **unverified**. The audit log can be exported to CSV.

**Keeping it across deploys.** Policy is stored in `DATA_DIR` (`/app/data`). In Coolify: open the app, **Persistent Storage**, add a volume with the destination `/app/data`, and redeploy. If the folder cannot be written the Policy page says so in a warning ("These changes will be lost when the server restarts") and still works until the next restart. Run **one replica** only: the policy is stored by the one server.

## Okta rate limits ("This API token has made too many requests")

Okta limits how fast an API token may call each endpoint. By default a token gets **50% of an endpoint's limit** (for the System Log, usually 60 requests a minute). Go over it and Okta rejects the request and writes "This API token has made too many requests" to the System Log, naming the token.

**What Sightline does so it does not cause that:**
- It keeps to `OKTA_MAX_RPM` requests a minute (default 30), and the history load gets only part of that budget, so the live page and your lookups always have room.
- It reads Okta's `x-rate-limit-*` headers on every reply and waits for the window to reset when the allowance is nearly used.
- If Okta ever does answer "too many requests", it halves its real pace, says so in the server log, and speeds up again slowly.
- Data & settings shows the requests per minute, what Okta reports as left, and a warning if anything was rejected recently. The "Loading history…" banner mentions the pace; a full week of history for a busy org is over a thousand requests, so it takes a while, and that is expected.

**If you see the warning in the System Log, check these:**
1. **Which tool is that token for?** The System Log entry names the token. If the name is another tool's (for example a runbook automation), Sightline and that tool are sharing one token and one allowance. Create a separate token for Sightline (Okta: Security > API > Tokens), owned by an admin with the read-only administrator role, and put it in `OKTA_API_TOKEN`.
2. **Is it Sightline?** Search the server log for `too many requests`. If it is there, Sightline is the one being limited; lower `OKTA_MAX_RPM`, or raise the token's share (Security > API > Tokens > the token > Token rate limits) if your policy allows.
3. Okta does not email anyone about these events, so the System Log (or this page) is the only place they show up.

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

**Newest first, and how fresh it is.** The grants, requests, revokes and blocks of the last few hours are read and shown first (each kind is saved the moment it arrives), then the API usage hour by hour from the newest hour backwards, then older history day by day, so the page has data within seconds even when the last few hours hold tens of thousands of API calls. Every time range is end-exclusive, so an event sitting exactly on the boundary between two reads is counted once. When Sightline starts it reads the last few hours of the log first, so the page is current within seconds, and then fills in older history behind it, newest day first. While that is going on the line at the top of the Google OAuth page says **"older history still loading (back to …)"**, and the numbers (people per app, first seen) are partial until it clears. The same line shows **"Newest event N ago"**. That can never be fresher than Google allows: Google reports these events a couple of hours after they happen, so a gap of a few hours is normal and a gap of days is not.

**Noise is summarised, not stored.** A busy integration can log the same grant or API call hundreds of times a minute. Identical grants, requests, revokes and blocks by the same person for the same app in the same minute become one line with a count (shown as ×150), and "Used the API" calls are summed per person, app and hour. Each kind has its own cap, so noise cannot push real grants out of memory, and no event is lost: the counts add up to what Google reported. A time slice too big to read in one go is split in half and read again, never cut off. The page keeps in step with the server by a sequence number, not by time, because older history arrives after newer events.

**Why API usage is only read for a few days.** Google logs every API call an app makes ("Used the API") as its own event, and a busy organisation produces millions of them a month (one org here had over 16 million in 30 days). Grants, requests, revokes and blocks are what the page is about and are read for the whole lookback; the API-usage calls are read only for the last `GOOGLE_ACTIVITY_DAYS` days (default 3), which is plenty for "last activity" and the "in use" marker, and cuts the first load from hours to minutes. Nothing is remembered per event: each time range is read and its summary replaced, so re-reading is always safe, and memory depends on the number of summaries, not the number of events. Set `GOOGLE_ACTIVITY_DAYS=0` to skip API usage altogether, or up to the lookback to read it all (slow on a big org).

Settings (all optional): `GOOGLE_POLL_SECONDS` (default 300), `GOOGLE_ACTIVITY_DAYS` (default 3), `GOOGLE_LOOKBACK_DAYS` (30, at most 180), `GOOGLE_RECHECK_HOURS` (6), `GOOGLE_CATCHUP_DELAY_MS` (pause between slices of older history, 1500), `GOOGLE_REQUEST_DELAY_MS` (pause between pages, 250), `GOOGLE_MAX_PAGES_PER_SLICE` (200), `GOOGLE_MAX_EVENTS` (200000 grants and requests) and `GOOGLE_MAX_ACTIVITY` (50000 hourly API-usage summaries).

**What the data is.** The Admin SDK Reports API "token" audit log. It records *consent*: authorize, request, revoke and deny events, each with the app name, client ID and scopes (and some API activity). It is not a record of every later sign-in with an app. Google reports these events a couple of hours late and keeps them for 6 months, so consents older than that cannot be seen. The page does not show whether Google considers an app trusted or verified; that lives in the Admin console.

**Why a service account with domain-wide delegation.** It is Google's standard server-to-server pattern for reading Workspace data: no person's password or refresh token is stored, it runs unattended, and its reach can be limited tightly:

1. One scope only, `https://www.googleapis.com/auth/admin.reports.audit.readonly` (read-only audit logs).
2. It acts as a dedicated admin whose role has only the **Reports** privilege, not a super admin.
3. The service account has no Google Cloud project roles.

**Setup (about 30 to 60 minutes, needs a super admin):**

1. Google Cloud console: pick or create a project, and enable the **Admin SDK API** (APIs & Services > Library).
2. IAM & Admin > Service accounts: create one (for example `sightline-readonly`) and give it no roles. Under Keys, add a JSON key. Note its numeric **Client ID** (on the account's details page).
3. Admin console > Account > Admin roles: create a role with only the **Reports** privilege and assign it to a dedicated admin user (for example `audit-reader@yourdomain`).
4. Admin console > Security > Access and data control > API controls > **Manage domain-wide delegation**: add the Client ID with exactly the one scope above.
5. Add two environment variables in your hosting dashboard (in Coolify: the app > Configuration > Environment Variables), available at runtime, then redeploy: `GOOGLE_ADMIN_EMAIL` (the admin from step 3) and `GOOGLE_SA_KEY` (the JSON key's contents; if pasting the multi-line file causes trouble, paste it base64-encoded, for example `base64 -i key.json | tr -d '\n' | pbcopy` on a Mac). Type the key straight into the hosting dashboard, never into a chat or the repository. Menu names in Google's consoles change from time to time; look for the closest match.

**Handling the key.** The key is a credential: keep it only in the deployment's secret settings, never in the repository, and rotate it periodically. The app never sends it to the browser or logs it, and the status and events endpoints do not include it. If your organisation blocks service account keys (the Google Cloud policy "Disable service account key creation"), tell the person who manages that policy what this is for, or ask for the alternative below.

**If something is wrong, the page says what and how to fix it:**

| Message | Meaning |
|---|---|
| `unauthorized_client` | Domain-wide delegation is missing or has the wrong Client ID or scope (step 4) |
| `invalid_grant` | `GOOGLE_ADMIN_EMAIL` is wrong, not an admin, or suspended |
| 401 or 403 "not authorized to read activity records" / "Not Authorized to access this resource" | The admin in `GOOGLE_ADMIN_EMAIL` is not a Super Admin and has no role with the Reports privilege (step 3). Check Directory > Users > that user > Admin roles and privileges; changes can take a few minutes |
| "Admin SDK API has not been used" | Step 1: enable the API, then wait a minute |

**Sorting and filtering the apps table.** Click a heading (App, Risk, People, First seen, Last activity) to sort by it; click again to reverse. The default is highest risk first, and your choice is remembered. Filters, all of which combine: **Risk**; **Access** (someone has it now, or nobody now); **Can reach** (Gmail, Drive, Calendar, Docs & Sheets, Contacts, Admin & directory, Chat & Meet, Google Cloud, or sign-in only; pick several to see apps that reach any of them); under **More filters**: used by 2, 5, 10 or 50+ people, active in the last 24 hours, 7 or 30 days, new this week, and a person's email (the apps that person has connected). The search box matches app names, client IDs and scope names, so typing `gmail` finds every app with a Gmail scope. The "Apps with access", "High-risk apps" and "New this week" boxes at the top are clickable shortcuts. Filters are not remembered between visits, so a forgotten filter can never hide an app. The table shows 25 apps at a time with "Show 25 more", "Show all" and "Show fewer" (sorting and filtering happen first, so the 25 are always the right 25). The page refreshes itself in the background, but it only redraws this table when something actually changed, and it never moves your scroll position or steals the cursor. "People" counts the people whose consent appears in the part of the log that was read; an app marked "in use" next to 0 people made API calls but its consent is older than that window.

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
