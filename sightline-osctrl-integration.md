# Sightline × osctrl Device Health Integration Spec

Target app: Sightline (`okta-health-insights`, `https://sightline.coolify.thoughtspot.com`, repo `elijahwillis-source/okta-health-insights`, Dockerfile build, Coolify app uuid `40xpazo8slnuisc0rom4d6ol`).
Data source: osctrl v0.7.0 (`https://osctrl-api.coolify.thoughtspot.com`, environment `corp`).

## 1. Connection and credentials

Sightline authenticates to osctrl as the dedicated read-only service account `ai-readonly` (global read-only role, service-account type, cannot write, carve, or remediate).

New environment variables for Sightline in Coolify:

| Variable | Value |
|---|---|
| `OSCTRL_API_URL` | `https://osctrl-api.coolify.thoughtspot.com` |
| `OSCTRL_API_USER` | `ai-readonly` |
| `OSCTRL_API_PASSWORD` | the `SERVICE_PASSWORD_64_AI` value from the osctrl service's Environment Variables in Coolify |

Auth flow: `POST /api/v1/login` with `{"username": ..., "password": ..., "exp_hours": 24}` returns `{"token": "...", "csrf_token": "..."}`. Send the token on every request in the `Authorization` header. The token is a JWT with expiry — re-login on 401. Verify at first integration whether the header needs a `Bearer ` prefix (the OpenAPI declares a plain Authorization API-key header; both forms are common).

## 2. TLS trust (critical, verified the hard way)

The `*.coolify.thoughtspot.com` certificate is signed by the internal enterprise CA `thoughtspot-VMP01-CA`. Sightline's container must trust that root or every call fails at the TLS layer:

- Mount or COPY the exported root CA into the image (get it with `security find-certificate -c "thoughtspot-VMP01-CA" -p /Library/Keychains/System.keychain` from any corporate Mac).
- Node runtime: set `NODE_EXTRA_CA_CERTS=/path/to/thoughtspot-vmp01-ca.pem`.
- Python runtime: set `REQUESTS_CA_BUNDLE` or `SSL_CERT_FILE` to the same file.
- Do not disable certificate verification.

## 3. API surface (REST)

| Purpose | Call |
|---|---|
| List/find devices | `GET /api/v1/nodes/corp?q=<serial or hostname>` — node records include `hardware_serial`, `system_info` (model, CPU, RAM), `platform`, `osquery` version, `uptime`, and health fields |
| Device by identifier | `GET /api/v1/nodes/corp` with query, or run `SELECT * FROM system_info WHERE serial_number = '<serial>'` |
| Run a read-only diagnostic query | `POST /api/v1/queries/corp` with the query name, SQL, and target nodes |
| Read results | `GET /api/v1/queries/corp/results/<name>` — results arrive asynchronously; poll for up to ~2 minutes (agent check-in interval is 60s) |
| Fleet stats | `GET /api/v1/stats/corp` |

Request/response field names should be confirmed against the live OpenAPI reference (https://docs.osctrl.net/api/) during the first integration session — the shapes above are from that reference.

MCP alternative: osctrl exposes a read-only MCP endpoint at `https://osctrl-api.coolify.thoughtspot.com/api/v1/mcp` using the same token. Tools: `search_nodes`, `get_node`, `list_queries`, `get_query_results`, `fleet_stats`, `list_osquery_tables`, `get_table_schema`. If the Sightline assistant is MCP-capable, registering this endpoint gives it native query tools with zero bespoke API code. Writes are disabled server-side (`MCP_ALLOW_WRITES=false`).

## 4. Device Health section — data model

Each enrolled Mac (from `GET /api/v1/nodes/corp`) shows:

- Identity: hostname, serial, hardware model, CPU brand, physical memory (`system_info`)
- OS: version, build, currency vs latest (`os_version`)
- Agent: osquery version, last check-in, node status
- Battery: cycle count, health, condition (`battery`) — desktops return empty
- Storage: root volume capacity and free space (`mounts`)
- Uptime: days since reboot (`uptime`)
- Applications: count and list (`apps`)

Health score (computed in Sightline, 0–100):

| Component | Weight | Full marks when |
|---|---|---|
| OS currency | 20 | within 1 minor version of newest known |
| Disk free | 20 | ≥ 20% free on root volume |
| Battery health | 15 | `health = Good` and cycle count < 80% of design life |
| Memory headroom | 15 | free ≥ 25% of physical |
| Reboot freshness | 10 | uptime < 14 days |
| Crash indicators | 10 | zero crashes in last 7 days (`crashes` table, macOS-privacy caveats) |
| Agent health | 10 | checked in within 2 intervals, osquery current |

Bands: 90+ healthy, 70–89 monitor, below 70 action recommended.

## 5. AI assistant troubleshooting recipes

Each recipe is a read-only query the assistant runs on demand through the API (or MCP tool):

- "Is the disk full?" — `SELECT * FROM mounts WHERE path = '/'`
- "Why is it slow?" — `SELECT * FROM uptime` + `SELECT pid, name, resident_size FROM processes ORDER BY resident_size DESC LIMIT 10` (note: CPU % requires sampling; process CPU time and RSS are point-in-time)
- "Battery problems?" — `SELECT * FROM battery`
- "Network issues?" — `SELECT * FROM interface_addresses` + `SELECT * FROM routes` + `SELECT * FROM dns_resolvers`
- "Is it crashing?" — `SELECT * FROM crashes WHERE datetime > strftime('%s','now','-7 days')`
- "What's installed?" — `SELECT name, version, last_opened_at FROM apps`

Ground rules for the assistant: read-only queries only; no remediation actions (none exist server-side for this account); always cite which query produced each finding.

## 6. Scheduled queries to enable in osctrl (one-time, UI)

Add in osctrl UI → Environments → `corp` → Configuration → **Schedule** tab:

| Name | Query | Interval (seconds) |
|---|---|---|
| `macos_system_info` | `SELECT * FROM system_info` | 3600 |
| `macos_battery` | `SELECT * FROM battery` | 86400 |
| `macos_root_disk` | `SELECT * FROM mounts WHERE path = '/'` | 3600 |
| `macos_os_version` | `SELECT * FROM os_version` | 3600 |
| `macos_uptime` | `SELECT * FROM uptime` | 3600 |
| `macos_apps` | `SELECT * FROM apps` | 86400 |

These make the Device Health panel always-fresh without the assistant needing to poll agents on demand.

## 7. Division of work

Sightline app changes (Claude Code, repo `elijahwillis-source/okta-health-insights`): Device Health section, osctrl API client, assistant recipes/MCP registration, health score.
Coolify-side changes (deployment assistant, on approval): set the three `OSCTRL_*` env vars on Sightline, ensure the CA is trusted, redeploy Sightline after merges, verify end-to-end.
osctrl-side: already deployed and read-only-secured; test Mac enrolled in `corp`.
