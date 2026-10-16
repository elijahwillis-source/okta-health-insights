#!/usr/bin/env bash
# Smoke test: starts the mock Okta + fake Anthropic + the app, hits every endpoint, cleans up.
#   bash test/smoke.sh
cd "$(dirname "$0")/.."
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

node test/mock-okta.js >/tmp/smoke-okta.log 2>&1 & PIDS+=($!)
node test/fake-anthropic.js >/tmp/smoke-anthropic.log 2>&1 & PIDS+=($!)
OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8099 POLL_INTERVAL_SECONDS=15 \
ANTHROPIC_API_KEY=x ANTHROPIC_BASE_URL=http://localhost:4020 DASHBOARD_PASSWORD=secret \
node server.js >/tmp/smoke-server.log 2>&1 & PIDS+=($!)
sleep 3

pass=0; fail=0
check() { # name expected actual
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected '$2', got '$3')"; fail=$((fail+1)); fi
}
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
jq_() { node -pe "const j=JSON.parse(require('fs').readFileSync(0));$1"; }
A="-u admin:secret"

check "healthz is open"            200 "$(code localhost:8099/healthz)"
check "no password -> 401"         401 "$(code localhost:8099/api/status)"
check "wrong password -> 401"      401 "$(code -u admin:nope localhost:8099/api/status)"
check "dashboard HTML served"      200 "$(code $A localhost:8099/)"
check "status reports live"        true "$(curl -s $A localhost:8099/api/status | jq_ 'j.live')"
check "events backfilled"          3000 "$(curl -s $A localhost:8099/api/events | jq_ 'j.total>=3000?3000:j.total')"
check "apps inventory loaded"      "Legacy HR Portal" "$(curl -s $A localhost:8099/api/apps)"
check "app labels are trimmed"      true "$(curl -s $A localhost:8099/api/apps | jq_ 'j.apps.every(a=>a===a.trim()&&a.length>0)')"
check "Slack label matches events"  true "$(curl -s $A localhost:8099/api/apps | jq_ 'j.apps.includes("Slack")&&j.apps.includes("Zoom")&&!j.apps.includes("Slack ")')"

BEFORE=$(curl -s $A localhost:8099/api/status | jq_ 'j.eventCount')
sleep 20
AFTER=$(curl -s $A localhost:8099/api/status | jq_ 'j.eventCount')
check "incremental polling adds events" true "$([ "$AFTER" -gt "$BEFORE" ] && echo true || echo false)"

SINCE=$(( $(date +%s%3N) - 120000 ))
check "since filter narrows results" true "$(curl -s $A "localhost:8099/api/events?since=$SINCE" | jq_ 'j.events.length<j.total')"

R=$(curl -s $A -XPOST localhost:8099/api/chat -H 'content-type: application/json' \
  -d '{"messages":[{"role":"user","content":"why is servicenow failing"}],"summary":{},"windowMs":604800000}')
check "assistant runs tool loop"   "TOOL RESULT SEEN" "$R"
check "assistant tool found data"  "totalMatches" "$R"
check "chat rejects bad history"   400 "$(code $A -XPOST localhost:8099/api/chat -H 'content-type: application/json' -d '{"messages":[{"role":"assistant","content":"x"}]}')"
check "unknown route -> 404"       404 "$(code $A localhost:8099/nope)"

# --- app matching: by id, trimmed names, independent of the capped event buffer ---
check "event app names are trimmed" true "$(curl -s $A localhost:8099/api/events | jq_ 'j.events.every(e=>e.target.every(t=>typeof t.displayName!=="string"||t.displayName===t.displayName.trim()))')"
check "/api/apps returns ids + last-seen" true "$(curl -s $A localhost:8099/api/apps | jq_ 'j.items.length>=8&&j.seen.length>=8&&j.items.every(x=>x.id&&x.label)')"
D=$(curl -s $A localhost:8099/api/diagnostics)
check "diagnostics: only the unused app lacks events" 1 "$(echo "$D" | jq_ 'j.inventory.withoutEvents')"
check "diagnostics: unused app is named" "Legacy HR Portal" "$D"

# Small buffer: the server must still remember every app's last activity (the 'No events in export' bug)
OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8098 POLL_INTERVAL_SECONDS=15 MAX_EVENTS=300 \
node server.js >/tmp/smoke-server-small.log 2>&1 & PIDS+=($!)
sleep 4
SM=$(curl -s localhost:8098/api/diagnostics)
check "small buffer: events capped"            true "$(echo "$SM" | jq_ 'j.events.held<=300')"
check "small buffer: all apps still have last-seen" 1 "$(echo "$SM" | jq_ 'j.inventory.withoutEvents')"
check "small buffer: old-only app (Zoom) still seen" true "$(curl -s localhost:8098/api/apps | jq_ 'j.seen.some(s=>s.name==="Zoom")')"

echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
