#!/usr/bin/env bash
# Smoke test: starts the mock Okta + fake Anthropic + the app, hits every endpoint, cleans up.
#   bash test/smoke.sh
cd "$(dirname "$0")/.."
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

node test/mock-okta.js >/tmp/smoke-okta.log 2>&1 & PIDS+=($!)
node test/fake-anthropic.js >/tmp/smoke-anthropic.log 2>&1 & PIDS+=($!)
OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8099 POLL_INTERVAL_SECONDS=15 BACKFILL_CHUNK_HOURS=72 \
ANTHROPIC_API_KEY=x ANTHROPIC_BASE_URL=http://localhost:4020 DASHBOARD_PASSWORD=secret \
node server.js >/tmp/smoke-server.log 2>&1 & PIDS+=($!)
sleep 3

pass=0; fail=0
wait_done() { # port [curl args]
  local port=$1; shift
  for _ in $(seq 1 90); do
    [ "$(curl -s "$@" localhost:$port/api/status | node -pe 'JSON.parse(require("fs").readFileSync(0)).catchingUp')" = "false" ] && return 0
    sleep 1
  done; return 1; }
check() { # name expected actual
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected '$2', got '$3')"; fail=$((fail+1)); fi
}
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
jq_() { node -pe "const j=JSON.parse(require('fs').readFileSync(0));$1"; }
A="-u admin:secret"

wait_done 8099 -u admin:secret

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
R2=$(curl -s $A -XPOST localhost:8099/api/chat -H 'content-type: application/json' \
  -d '{"messages":[{"role":"user","content":"lookup-user please"}],"summary":{},"windowMs":604800000}')
check "assistant can search a user live"   "totalAboutThisPerson" "$R2"
chat() { curl -s $A -XPOST localhost:8099/api/chat -H 'content-type: application/json' -d "{\"messages\":[{\"role\":\"user\",\"content\":\"$1\"}],\"summary\":{},\"windowMs\":604800000}"; }
check "assistant recovers from an empty reply"   "RECOVERED" "$(chat empty-reply)"
check "assistant flags a cut-off answer"         "cut off" "$(chat cutoff)"
check "assistant explains a persistent empty reply" "empty reply (stop reason: end_turn)" "$(chat always-empty)"
check "chat rejects bad history"   400 "$(code $A -XPOST localhost:8099/api/chat -H 'content-type: application/json' -d '{"messages":[{"role":"assistant","content":"x"}]}')"
check "unknown route -> 404"       404 "$(code $A localhost:8099/nope)"

# --- app matching: by id, trimmed names, independent of the capped event buffer ---
check "event app names are trimmed" true "$(curl -s $A localhost:8099/api/events | jq_ 'j.events.every(e=>e.target.every(t=>typeof t.displayName!=="string"||t.displayName===t.displayName.trim()))')"
check "/api/apps returns ids + last-seen" true "$(curl -s $A localhost:8099/api/apps | jq_ 'j.items.length>=8&&j.seen.length>=8&&j.items.every(x=>x.id&&x.label)')"
D=$(curl -s $A localhost:8099/api/diagnostics)
check "diagnostics: only the unused app lacks events" 1 "$(echo "$D" | jq_ 'j.inventory.withoutEvents')"
check "diagnostics: unused app is named" "Legacy HR Portal" "$D"

# Small buffer: the server must still remember every app's last activity (the 'No events in export' bug)
OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8098 POLL_INTERVAL_SECONDS=15 MAX_EVENTS=300 BACKFILL_CHUNK_HOURS=72 \
node server.js >/tmp/smoke-server-small.log 2>&1 & PIDS+=($!)
sleep 2
wait_done 8098
SM=$(curl -s localhost:8098/api/diagnostics)
check "small buffer: events capped"            true "$(echo "$SM" | jq_ 'j.events.held<=300')"
check "small buffer: all apps still have last-seen" 1 "$(echo "$SM" | jq_ 'j.inventory.withoutEvents')"
check "small buffer: old-only app (Zoom) still seen" true "$(curl -s localhost:8098/api/apps | jq_ 'j.seen.some(s=>s.name==="Zoom")')"

# --- recent events first, older history after, then everything consistent ---
OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8095 POLL_INTERVAL_SECONDS=15 MAX_PAGES_PER_POLL=2 \
HEAD_HOURS=6 BACKFILL_CHUNK_HOURS=24 node server.js >/tmp/smoke-server-catchup.log 2>&1 & PIDS+=($!)
sleep 2
EARLY=$(curl -s localhost:8095/api/status)
check "catch-up: newest events load first"        true "$(echo "$EARLY" | jq_ 'j.catchUp.headCaughtUp===true')"
check "catch-up: history still loading at first"  true "$(echo "$EARLY" | jq_ 'j.catchingUp===true&&j.catchUp.pct<100')"
NEWEST=$(curl -s localhost:8095/api/diagnostics | jq_ 'j.events.newest')
check "catch-up: newest event is recent"          true "$(node -pe "(Date.now()-Date.parse('$NEWEST'))<5*60000")"
for i in $(seq 1 60); do
  [ "$(curl -s localhost:8095/api/status | jq_ 'j.catchingUp')" = "false" ] && break; sleep 1
done
FIN=$(curl -s localhost:8095/api/status)
check "catch-up: history finishes"                false "$(echo "$FIN" | jq_ 'j.catchingUp')"
check "catch-up: reports 100%"                    100 "$(echo "$FIN" | jq_ 'j.catchUp.pct')"
check "catch-up: all events loaded"               true "$(echo "$FIN" | jq_ 'j.eventCount>=3000')"
check "catch-up: events are in time order"        true "$(curl -s localhost:8095/api/events | jq_ 'j.events.every((e,i)=>i===0||e.published>=j.events[i-1].published)')"
check "catch-up: old-only app (Zoom) seen"        true "$(curl -s localhost:8095/api/apps | jq_ 'j.seen.some(s=>s.name==="Zoom")')"

# --- live per-user search: the server asks Okta for one person ---
U=$(curl -s $A "localhost:8099/api/user-events?q=user07@example.com&q=user07&days=7")
check "user search: finds that person"           true "$(echo "$U" | jq_ 'j.count>0&&j.events.length===j.count')"
check "user search: only events about them"      true "$(echo "$U" | jq_ 'j.events.every(e=>JSON.stringify([e.actor,e.target]).toLowerCase().includes("user07"))')"
check "user search: newest first"                true "$(echo "$U" | jq_ 'j.events.every((e,i)=>i===0||e.published<=j.events[i-1].published)')"
check "user search: no one else leaks in"        true "$(echo "$U" | jq_ '!j.events.some(e=>JSON.stringify([e.actor,e.target]).toLowerCase().includes("user08@"))')"
check "user search: unknown user is empty"       0 "$(curl -s $A "localhost:8099/api/user-events?q=nobody.here.zzz" | jq_ 'j.count')"
check "user search: too short -> 400"            400 "$(code $A "localhost:8099/api/user-events?q=a")"
check "user search: missing q -> 400"            400 "$(code $A "localhost:8099/api/user-events")"
check "user search: needs the password"          401 "$(code "localhost:8099/api/user-events?q=user07")"
check "status advertises user search"            true "$(curl -s $A localhost:8099/api/status | jq_ 'j.lookup===true')"
# the search must work even before history has loaded (fresh start, tiny pages)
OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8093 MAX_PAGES_PER_POLL=2 HEAD_HOURS=1 BACKFILL_CHUNK_HOURS=1 \
node server.js >/tmp/smoke-server-lookup.log 2>&1 & PIDS+=($!)
sleep 1.5
check "user search works while history loads"    true "$(curl -s "localhost:8093/api/user-events?q=user07&days=7" | jq_ 'j.count>0')"

# --- assistant's user search matches ANY login of a person (Okta email or AD AppUser login) ---
UQ=$(node -e '
const m=require("./server.js"); const ev=(id,actor,target)=>({id,published:new Date().toISOString(),eventType:"x",outcome:{result:"FAILURE",reason:"r"},actor,target});
m.state.events.push(ev("1",{type:"SystemPrincipal",alternateId:"system@okta.com"},[{type:"AppUser",alternateId:"jane.doe@corp.int",displayName:"Jane Doe"},{type:"AppInstance",displayName:"Active Directory",id:"a"}]));
m.state.events.push(ev("2",{type:"User",alternateId:"jane.doe@corp.com"},[{type:"AppInstance",displayName:"Slack",id:"b"}]));
console.log(JSON.stringify([m.queryEvents({user:"jane.doe@corp.int"},0).totalMatches, m.queryEvents({user:"jane.doe@corp.com"},0).totalMatches, m.queryEvents({user:"nobody"},0).totalMatches]));')
check "user search: AD login found"            "[1,1,0]" "$UQ"

echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
