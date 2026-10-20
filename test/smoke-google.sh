#!/usr/bin/env bash
# Google Workspace OAuth audit tests: a fake Google (strict about the signed sign-in) + the app.
#   bash test/smoke-google.sh
cd "$(dirname "$0")/.."
export DATA_DIR=$(mktemp -d)      # policy files of the servers under test: throwaway
PIDS=(); cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }; trap cleanup EXIT
pass=0; fail=0
check() { if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected '$2', got '$3')"; fail=$((fail+1)); fi; }
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
jq_() { node -pe "const j=JSON.parse(require('fs').readFileSync(0));$1"; }
A="-u admin:secret"
node test/mock-okta.js >/tmp/smoke-okta.log 2>&1 & PIDS+=($!)
# a plain server WITHOUT Google settings, to prove the feature is simply off
OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8099 DASHBOARD_PASSWORD=secret node server.js >/tmp/smoke-server.log 2>&1 & PIDS+=($!)
sleep 3
# ============================ Google Workspace OAuth audit (fake Google; checks the signed sign-in too) ============================
echo; echo "--- Google Workspace ---"
rm -f /tmp/smoke-gkey.json
MOCK_G_PORT=4030 MOCK_G_PAGE=5 MOCK_G_ADMIN=admin@example.com MOCK_G_KEYFILE=/tmp/smoke-gkey.json node test/mock-google.js >/tmp/smoke-google.log 2>&1 & PIDS+=($!)
for _ in $(seq 1 40); do [ -s /tmp/smoke-gkey.json ] && curl -s localhost:4030/_stats >/dev/null && break; sleep 0.3; done
( export GOOGLE_SA_KEY="$(cat /tmp/smoke-gkey.json)" GOOGLE_ADMIN_EMAIL=admin@example.com GOOGLE_API_BASE=http://localhost:4030 GOOGLE_POLL_SECONDS=5 GOOGLE_LOOKBACK_DAYS=30 GOOGLE_CATCHUP_DELAY_MS=20 GOOGLE_REQUEST_DELAY_MS=0
  OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8095 POLL_INTERVAL_SECONDS=15 exec node server.js >/tmp/smoke-server-google.log 2>&1 ) & PIDS+=($!)
for _ in $(seq 1 60); do [ "$(curl -s localhost:8095/api/status | node -pe 'try{const g=JSON.parse(require("fs").readFileSync(0)).google; g.events>0&&!g.catchingUp}catch{false}')" = "true" ] && break; sleep 1; done
GS=$(curl -s localhost:8095/api/status | jq_ 'JSON.stringify(j.google)')
check "google: connected and reading events"               true "$(echo "$GS" | jq_ 'j.configured&&j.events>0&&!j.lastError')"
check "google: shows who it acts as"                        admin@example.com "$GS"
check "google: tells the page the one scope it uses"        admin.reports.audit.readonly "$GS"
GE=$(curl -s localhost:8095/api/google/events)
check "google: signed sign-in accepted by a strict server"  true "$([ "$(curl -s localhost:4030/_stats | jq_ 'j.rejected.length')" = "0" ] && [ "$(curl -s localhost:4030/_stats | jq_ 'j.tokenRequests')" -ge 1 ] && echo true || echo false)"
check "google: pagination (5 per page) read every event"   36 "$(echo "$GE" | jq_ 'j.total')"
check "google: all event kinds are kept"                    true "$(echo "$GE" | jq_ '["authorize","revoke","deny","request","activity"].every(k=>j.events.some(e=>e.type===k))')"
check "google: scopes come through as a list"               true "$(echo "$GE" | jq_ 'j.events.filter(e=>e.type==="authorize").every(e=>Array.isArray(e.scopes)&&e.scopes.length>0)')"
check "google: app name, client id and person are kept"     true "$(echo "$GE" | jq_ 'j.events.every(e=>e.app&&e.clientId.endsWith(".apps.googleusercontent.com")&&/@example.com$/.test(e.actor))')"
check "google: a denial keeps its reason"                   ADMIN_BLOCKED "$(echo "$GE" | jq_ 'JSON.stringify(j.events.filter(e=>e.type==="deny"))')"
check "google: events are oldest-first"                     true "$(echo "$GE" | jq_ 'j.events.every((e,i)=>i===0||j.events[i-1].time<=e.time)')"
N1=$(echo "$GE" | jq_ 'j.total'); sleep 11
check "google: re-reading the same hours does not duplicate" "$N1" "$(curl -s localhost:8095/api/google/events | jq_ 'j.total')"
curl -s "localhost:4030/_add?app=cal&user=user41@example.com&min=0" >/dev/null; sleep 11
check "google: a new event shows up on the next check"      true "$(curl -s localhost:8095/api/google/events | jq_ "j.total===$N1+1")"
check "google: since= returns only newer events"            true "$(curl -s "localhost:8095/api/google/events?since=$(( $(date +%s%3N) - 60000 ))" | jq_ 'j.events.length>=1&&j.events.length<j.total')"
check "google: the key is never exposed"                    false "$(curl -s localhost:8095/api/status | jq_ 'JSON.stringify(j).includes("BEGIN PRIVATE KEY")')"
check "google: nor in the events endpoint"                  false "$(curl -s localhost:8095/api/google/events | jq_ 'JSON.stringify(j).includes("PRIVATE KEY")')"
# wrong admin -> a clear next step, and the server keeps running
( export GOOGLE_SA_KEY="$(cat /tmp/smoke-gkey.json)" GOOGLE_ADMIN_EMAIL=nobody@example.com GOOGLE_API_BASE=http://localhost:4030 GOOGLE_POLL_SECONDS=5
  OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8094 exec node server.js >/tmp/smoke-server-google2.log 2>&1 ) & PIDS+=($!)
sleep 6; GB=$(curl -s localhost:8094/api/status | jq_ 'JSON.stringify(j.google)')
check "google: wrong admin email -> says so"                 invalid_grant "$GB"
check "google: ... and points at the fix"                    GOOGLE_ADMIN_EMAIL "$GB"
check "google: ... while the rest of the app keeps working"  true "$(curl -s localhost:8094/api/status | jq_ 'j.live===true')"
curl -s "localhost:4030/_mode?m=unauthorized" >/dev/null
( export GOOGLE_SA_KEY="$(cat /tmp/smoke-gkey.json)" GOOGLE_ADMIN_EMAIL=admin@example.com GOOGLE_API_BASE=http://localhost:4030 GOOGLE_POLL_SECONDS=5
  OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8093 exec node server.js >/tmp/smoke-server-google3.log 2>&1 ) & PIDS+=($!)
sleep 6; GU=$(curl -s localhost:8093/api/status | jq_ 'JSON.stringify(j.google)')
check "google: delegation not set up -> explains how"        "domain-wide delegation" "$GU"
curl -s "localhost:4030/_mode?m=noreports" >/dev/null
( export GOOGLE_SA_KEY="$(cat /tmp/smoke-gkey.json)" GOOGLE_ADMIN_EMAIL=admin@example.com GOOGLE_API_BASE=http://localhost:4030 GOOGLE_POLL_SECONDS=5
  OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8088 exec node server.js >/tmp/smoke-server-google8.log 2>&1 ) & PIDS+=($!)
sleep 6; GR=$(curl -s localhost:8088/api/status | jq_ 'JSON.stringify(j.google)')
check "google: 'not authorized to read activity records' (401) -> blames the admin's role, not the key" "Reports privilege" "$GR"
check "google: ... and does NOT send you to check the clock and the key"                              false "$(echo "$GR" | jq_ '/clock on the server/.test(j.hint)')"
check "google: ... and names the setting to change"                                                    "Admin roles and privileges" "$GR"
check "google: ... while Google's own words are still shown"                                           "not authorized to read activity records" "$GR"
curl -s "localhost:4030/_mode?m=forbidden" >/dev/null
curl -s "localhost:4030/_mode?m=ok" >/dev/null
# not configured at all
check "google: not configured -> reported as such"           false "$(curl -s $A localhost:8099/api/status | jq_ 'j.google.configured')"
check "google: not configured -> events endpoint is 404"     404 "$(code $A localhost:8099/api/google/events)"
# a broken key is reported, not a crash
( export GOOGLE_SA_KEY='{"hello":1}' GOOGLE_ADMIN_EMAIL=admin@example.com
  OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8092 exec node server.js >/tmp/smoke-server-google4.log 2>&1 ) & PIDS+=($!)
sleep 3; GK=$(curl -s localhost:8092/api/status | jq_ 'JSON.stringify(j.google)')
check "google: a wrong key file is explained, no crash"      "service account key file" "$GK"
check "google: base64-encoded keys work too"                 true "$( ( export GOOGLE_SA_KEY="$(base64 -w0 /tmp/smoke-gkey.json)" GOOGLE_ADMIN_EMAIL=admin@example.com; node -e 'const {loadKey}=require("./google");const k=loadKey(process.env.GOOGLE_SA_KEY);console.log(!!(k&&k.email&&k.key.includes("BEGIN PRIVATE KEY")))' ) )"

# only one of the two set -> which one is missing; both empty (a copied .env.example) -> simply off
( export GOOGLE_SA_KEY="$(cat /tmp/smoke-gkey.json)" GOOGLE_ADMIN_EMAIL=""
  OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8091 exec node server.js >/tmp/smoke-server-google5.log 2>&1 ) & PIDS+=($!)
( export GOOGLE_SA_KEY="" GOOGLE_ADMIN_EMAIL=admin@example.com
  OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8090 exec node server.js >/tmp/smoke-server-google6.log 2>&1 ) & PIDS+=($!)
( export GOOGLE_SA_KEY="" GOOGLE_ADMIN_EMAIL=""
  OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8089 exec node server.js >/tmp/smoke-server-google7.log 2>&1 ) & PIDS+=($!)
sleep 4
P1=$(curl -s localhost:8091/api/status | jq_ 'JSON.stringify(j.google)'); P2=$(curl -s localhost:8090/api/status | jq_ 'JSON.stringify(j.google)'); P3=$(curl -s localhost:8089/api/status | jq_ 'JSON.stringify(j.google)')
check "google: only the key set -> says the admin email is missing"   "GOOGLE_ADMIN_EMAIL is missing" "$P1"
check "google: ... and stays off, not half-working"                   '"configured":false' "$P1"
check "google: only the admin email set -> says the key is missing"   "GOOGLE_SA_KEY is missing" "$P2"
check "google: both empty (an unedited .env.example) -> simply off, no error" true "$(echo "$P3" | jq_ 'j.configured===false&&!j.lastError')"
check "google: the app keeps running in all three"                    true "$(curl -s localhost:8091/api/status | jq_ 'j.live===true')"

echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
