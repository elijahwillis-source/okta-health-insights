# Sightline handoff

Written for the next person or the next Claude session who picks this up. The short, always-loaded version is `CLAUDE.md`. This is the
background: where things stand, why things are the way they are, what is missing, and what to do next. Facts marked **(check)** were true
when this was written (late October 2026) but depend on settings outside the repo, so confirm them before relying on them.

## Where things stand

- Code: `main` at commit `a2bcbc8` ("No break-glass; REQUIRE_SSO; scrolling and audit fixes") was the last change made in the chat sessions that built this.
- Live at https://sightline.coolify.thoughtspot.com (Coolify). One replica, with a persistent volume at `/app/data`.
- Sign-in through Okta works, with roles from three groups. **(check)** whether `REQUIRE_SSO=true` has been set in Coolify; it should be.
- Server tests: seven suites, all passing on `main` (see `CLAUDE.md`). Browser tests: none in the repo (see below).

## The people and tools around it

- **Coolify** is operated through a separate AI tool called "agentspot", which has its own chat and **cannot see** a Claude chat or a Claude Code session.
  Anything that needs a setting changed or a redeploy has to be asked for there, by variable name (never paste secret values into any chat).
  Deploys need a *redeploy*, not a restart.
- **GitHub:** the repo is `elijahwillis-source/okta-health-insights` (branch `main`). Coolify builds from it. A copy in the company org
  (`thoughtspot/Elijah-s-stuff`) was discussed but nothing was moved. Moving means re-pointing Coolify, so decide that on purpose.
- **Okta:** an OIDC web app called Sightline. Sign-in redirect `<PUBLIC_URL>/callback`, sign-out redirect `<PUBLIC_URL>/logged-out`, authorization
  code with PKCE required, groups claim filter "Starts with Sightline". Groups: *Sightline Owners Group*, *Sightline Admin Group*, *Sightline Users group*.
  The tile is set to "Either Okta or App" with initiate-login URI `<PUBLIC_URL>/login`. Okta data is read with a dedicated read-only API token on a service account.
- **Google:** a service account with domain-wide delegation reads the Reports API token audit as an admin user (`GOOGLE_ADMIN_EMAIL`).
- **Settings by name** (set in Coolify): `PUBLIC_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `SESSION_SECRET`, `OIDC_OWNER_GROUPS`,
  `OIDC_ADMIN_GROUPS`, `OIDC_USER_GROUPS`, `OWNER_EMAILS`, `ASSISTANT_MIN_ROLE`, `REQUIRE_SSO`, `OKTA_ORG_URL`, `OKTA_API_TOKEN`,
  `ANTHROPIC_API_KEY`, `GOOGLE_SA_KEY` (base64 of the key file), `GOOGLE_ADMIN_EMAIL`, `DATA_DIR`. The full list with comments is in `.env.example`.

## What was built, in order

1. Okta System Log dashboard (events, failure rate, errors, apps, people) with an AI assistant, then renamed **Sightline** with an eye logo.
2. Okta rate-limit pacing after a shared token was exhausted ("too many requests").
3. Google OAuth page: grants, risk, search, approvals, loaded by hour, newest first. A "Map maximum size exceeded" crash came from keeping per-event data; the loader now keeps none.
4. Policy: known-error rules (preview, reason, expiry), Google app decisions (approve / not allowed / drift alerts), audit.
5. Assistant docked beside the app; then Okta SSO with roles, sessions and a shared audit log.
6. Device health: a placeholder page ("Coming at the end of the year", hazard tape, Iris in a hard hat). Nothing behind it yet.
7. The assistant became **Iris**: a face, a voice, a changing "thinking" line, a fixed narrow width, no resize controls.
8. Explain became specific: one error, one person, in focus mode (see `CLAUDE.md`).
9. Scroll chaining fixed (scrolling Iris never moves the page behind her); `/api/policy/audit` made admin-only after a code review found it open to any signed-in user.
10. The emergency ("break-glass") password was removed completely; `REQUIRE_SSO` added so a mistake can never leave the app open.
11. **Location alerts and Slack.** Rules for sign-ins, failed sign-ins, invalid passwords and MFA failures from places (a watch list, or "anywhere except these"), with thresholds, cooldowns, a preview on recent data, reasons and audit. Worked out on the server so they fire with nobody watching, and shown in the bell. Optional Slack delivery set up by pasting a manifest JSON, with an in-app step-by-step guide (simplified pictures of each Slack screen, the manifest to copy, a message for whoever runs Sightline, live "connected" detection). See README, "Location alerts and Slack".
    Built along the way: the polling split into two loops (new events were being held up for up to a minute while history waited on the rate limit), Slack escaping of the notification fallback text, and `SLACK_LINK_URL` (because `PUBLIC_URL` alone turns sign-in on).

## Decisions and why

- **One HTML file, zero dependencies:** easy to deploy and review, and no supply-chain exposure. The cost is a CSP that allows inline script (see open items).
- **No back door:** the owner wanted every action tied to a named Okta person. Recovery from a broken sign-in is through Coolify.
- **Policy rules are visible to every signed-in user** (people need them to understand what is hidden); the history of who changed what is admin-only.
- **Iris is an AI and says so.** Her voice is set in `SYSTEM`; she is told to lead with the answer, vary her openings, and be honest about what the data shows.
- **Fixed panel width:** the owner chose "just narrow, no options". Do not add resize controls back without asking.
- **Failure rate wording:** it is the share of log events, not of sign-ins. Many events are routine successes, so it looks low. A real sign-in failure rate is an open item.
- **Location alerts on the server, Slack by manifest:** an alert has to fire with nobody looking, once, for everyone, so these are not in the page like the older rules. The manifest means no one has to pick Slack permissions by hand; `chat:write.public` is included so per-rule channels work without invites (remove it from the manifest for stricter least privilege, then every channel needs `/invite`).
- **Only events from the last 30 minutes can alert, and each is looked at once.** After a restart the head window (6 hours) is read again; this is what stops that from raising old alerts. The cost: an alert for an event that arrives more than 30 minutes late is not raised.
- **The Window dropdown** (24h, 3 days, 7 days, 30 days, all loaded) only filters what is in memory. With the 100000-event cap, everything above about a day looks the same for Okta. Google grants genuinely go back 30 days.

## Rebuild the browser tests (first job)

The browser tests were Playwright scripts run against the mock services. They were kept outside the repo and are gone, **except** the Location alerts one, which was written into the repo: `test/browser/geo-ui.js` with its runner `run-geo-ui.sh` (a good pattern to copy: it starts the fake Okta, the fake Slack and the app on fixed ports, then drives a real browser). Rebuild the rest the same way
in `test/browser/` with its **own** `package.json` (Playwright as a dev dependency; the app itself stays dependency-free). Start the same stack the manual run
above uses (mock Okta :4010, fake AI :4020, server :8090; mock OIDC :4061 and a sign-in server :8060 for the sign-in flow; mock Google for the Google page), one
plain Node script per area, each printing `PASS`/`FAIL` lines. Wait for `#kpis .kpi` before asserting. Things the old suites verified, which are worth re-checking:

- **Shell:** menu order (Overview, Errors, Apps, People, Google OAuth, Device health, Alerts, Policy, Ask Iris, Data & settings), collapse, light/dark theme, account menu.
- **Iris:** opens at a third of the window (340 to 640 px), no width buttons or drag handle, app moves over and the chart redraws, menu shrinks under 1400 px, floats over
  the app under 900 px, a width saved by an old version is ignored; her face and a thinking line that changes; friendly error text; her instructions reach the model (use the fake AI's `GET /_last`).
- **Focus / Explain:** Explain on an error row sends the person, time, app, event type, exact reason and nearby events; the chat shows one short line; only `lookup_user_events`
  is offered and a broad tool call is refused; a typed follow-up gets every tool back; same for "Ask Iris" on the People page.
- **Scrolling:** with the mouse wheel over Iris's chat (at its top and at its bottom), her header, or her question box, the page behind does not move; over the app it does.
- **Device health:** menu entry with a "Soon" pill (icon only when collapsed or at 900 px or less), the page, back button, keyboard.
- **Policy UI:** Mark as known with preview, required reason, expiry; Google app approvals; the audit tab (admin+), filters and CSV; the Access tab (owner); role gating for a regular user.
- **Sign-in (with the mock OIDC server):** login, callback, roles from groups, denied page, logout, session end, and **no back door** (a shared password gets nobody in).
- **Google page:** tiles, sort, filters, search that keeps focus, show more/fewer, new-access drift alerts.
- **Okta pages:** Overview tiles, error filters, alerts and rules, people and app lookups, the explain panel, the rate-limit banner, logo and favicon routes.

## Open items (pick up in this order)

1. **Rotate secrets that passed through chats (check whether done), including the new `SLACK_BOT_TOKEN` if it was ever pasted anywhere:** the Google service account key, the Okta SSO client secret, the Okta API token. Steps: create the
   new one, set it in Coolify, redeploy, confirm it works, then revoke the old one. Never paste the new value into a chat.
2. **Set `REQUIRE_SSO=true`** in Coolify if not yet set, and remove `DASHBOARD_PASSWORD` and `BREAKGLASS_ENABLED`.
3. **Rebuild the browser tests** (above).
4. **True 7-day numbers:** keep hourly totals for the whole lookback and only failure details in full, so the failure rate and windows are real for a week. Also add Last hour and
   Last 6 hours windows, and a header note when less data is loaded than the window selected. Add a real **sign-in failure rate** and **provisioning failure rate**.
5. **CSP hardening:** move to a per-request nonce for the one inline script (there are zero inline event handlers already). Test that an injected script is blocked.
6. **Iris guided tour:** short, skippable, role-aware (about six stops), replayable from the account menu, remembered per person.
7. **Location alerts, follow-ups:** (a) move the older alert rules to the server too, so they can also go to Slack and fire with nobody watching; (b) an "Ask Iris" button on a location alert (Iris's focus mode already exists for one-event questions); (c) check real Okta's country names against the aliases in `geo.js`, and how late Okta delivers events (the poller reads "newer than the latest seen", so an event delivered late with an earlier timestamp can be missed, which matters for security alerts); (d) a browser test of the section as a regular user (the server refuses their changes and that is tested, the screen is not); (e) Slack buttons or slash commands would need a Request URL and signature checking: not built on purpose.
8. Smaller: a "Known" badge in lookups; make the "Need review" tile and chip counts agree; `assistantAppLookup` could not find an app named "ServiceNow UD"
   (it needs a valid app id from Okta's app list or recent events: investigate); make sign-out a POST.
9. **Upkeep:** rebuild the container regularly so the `node:22-alpine` base image gets security fixes.

## Things that went wrong before (do not repeat)

- A line comment (`//`) swallowed code on the same line, twice. Check generated code.
- Two writers shared one audit file and corrupted it. They now use separate files.
- A shared Okta API token was used by two tools and exhausted the rate limit. Sightline has its own token and a paced gate.
- Keeping per-event Google data blew the memory ("Map maximum size exceeded"). Do not keep per-event data in a Map.
- A new alert type starting with "g" was treated as a Google alert by the page (wrong Explain button). Name types so they do not start with "g".
- Test servers that set `PUBLIC_URL` locked themselves out (it switches sign-in on). Use `SLACK_LINK_URL` for Slack links.
- Waiting on the rate limit inside the same loop as the newest events delayed them by up to a minute. Keep the loops separate.
- A page script that parses can still be wrong in CSS (a stray rule removed) or in text replacement (`\n` inside a replacement string became a real newline). Re-parse and look at it.
- Redeploying shortly before a demo showed a half-empty dashboard, because the history reloads for 20 to 30 minutes.
- Screen text in headings is upper-cased by CSS, so `innerText` comparisons fail. Use `textContent`.
