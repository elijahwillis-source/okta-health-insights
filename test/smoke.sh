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
check "status names the Okta org for the sidebar"  "localhost:4010" "$(curl -s $A localhost:8099/api/status | jq_ 'j.org')"
check "status advertises user search"            true "$(curl -s $A localhost:8099/api/status | jq_ 'j.lookup===true')"
# the search must work even before history has loaded (fresh start, tiny pages)
OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=test PORT=8093 MAX_PAGES_PER_POLL=2 HEAD_HOURS=1 BACKFILL_CHUNK_HOURS=1 \
node server.js >/tmp/smoke-server-lookup.log 2>&1 & PIDS+=($!)
sleep 1.5
check "user search works while history loads"    true "$(curl -s "localhost:8093/api/user-events?q=user07&days=7" | jq_ 'j.count>0')"

# --- live per-app errors: ask Okta for one app's failures ---
SN=0oaMOCK000003   # ServiceNow in the fake org
AE=$(curl -s $A "localhost:8099/api/app-events?id=$SN&days=7")
check "app errors: finds the app's failures"      true "$(echo "$AE" | jq_ 'j.count>0&&j.events.length===j.count')"
check "app errors: only failures and denies"      true "$(echo "$AE" | jq_ 'j.events.every(e=>["FAILURE","DENY","ERROR"].includes(e.outcome.result))')"
check "app errors: only that app"                 true "$(echo "$AE" | jq_ 'j.events.every(e=>e.target.some(t=>t.id==="'$SN'"))')"
check "app errors: newest first"                  true "$(echo "$AE" | jq_ 'j.events.every((e,i)=>i===0||e.published<=j.events[i-1].published)')"
check "app errors: Okta filtered it"              true "$(echo "$AE" | jq_ 'j.serverFiltered===true')"
check "app errors: unknown app is empty"          0 "$(curl -s $A "localhost:8099/api/app-events?id=0oaMOCK999999" | jq_ 'j.count')"
check "app errors: bad id -> 400"                 400 "$(code $A "localhost:8099/api/app-events?id=abc")"
check "app errors: missing id -> 400"             400 "$(code $A "localhost:8099/api/app-events")"
check "app errors: needs the password"            401 "$(code "localhost:8099/api/app-events?id=$SN")"
check "status advertises app lookup"              true "$(curl -s $A localhost:8099/api/status | jq_ 'j.appLookup===true')"
R3=$(curl -s $A -XPOST localhost:8099/api/chat -H 'content-type: application/json' -d '{"messages":[{"role":"user","content":"lookup-app please"}],"summary":{},"windowMs":604800000}')
check "assistant can look up an app's errors"     "errorsFound" "$R3"
# an Okta that rejects the combined filter: the server falls back to filtering the errors itself
MOCK_PORT=4011 MOCK_NO_RESULT_FILTER=1 node test/mock-okta.js >/tmp/smoke-okta2.log 2>&1 & PIDS+=($!)
OKTA_ORG_URL=http://localhost:4011 OKTA_API_TOKEN=test PORT=8089 node server.js >/tmp/smoke-server-nofilter.log 2>&1 & PIDS+=($!)
sleep 2
NF=$(curl -s "localhost:8089/api/app-events?id=$SN&days=7")
check "app errors: works if Okta rejects the filter" true "$(echo "$NF" | jq_ 'j.serverFiltered===false&&j.count>0&&j.events.every(e=>e.outcome.result==="FAILURE")')"

# --- explain one error ---
post() { curl -s $A -XPOST localhost:8099/api/explain-error -H 'content-type: application/json' -d "$1"; }
E1=$(post '{"reason":"EXPLAIN-TEST Failed to update user password","apps":["ServiceNow UD"],"eventTypes":["application.provision.user.push"],"count":51,"people":3}')
check "explain: returns an explanation"          "EXPLAIN OK" "$E1"
check "explain: first call is not cached"        false "$(echo "$E1" | jq_ 'j.cached')"
E2=$(post '{"reason":"EXPLAIN-TEST Failed to update user password","apps":["ServiceNow UD"],"eventTypes":["application.provision.user.push"],"count":99,"people":9}')
check "explain: same error is served from cache" true "$(echo "$E2" | jq_ 'j.cached===true')"
check "explain: cached text is identical"        true "$([ "$(echo "$E1" | jq_ 'j.text')" = "$(echo "$E2" | jq_ 'j.text')" ] && echo true || echo false)"
E3=$(post '{"reason":"EXPLAIN-TEST a different error"}')
T1=$(echo "$E1" | jq_ 'j.text'); T3=$(echo "$E3" | jq_ 'j.text')
check "explain: a different error gets its own answer" true "$([ "$T1" != "$T3" ] && [ "$(echo "$E3" | jq_ 'j.cached')" = "false" ] && echo true || echo false)"
check "explain: missing reason -> 400"           400 "$(code $A -XPOST localhost:8099/api/explain-error -H 'content-type: application/json' -d '{"apps":["x"]}')"
check "explain: needs the password"              401 "$(code -XPOST localhost:8099/api/explain-error -H 'content-type: application/json' -d '{"reason":"abc"}')"

# --- assistant's user search matches ANY login of a person (Okta email or AD AppUser login) ---
UQ=$(node -e '
const m=require("./server.js"); const ev=(id,actor,target)=>({id,published:new Date().toISOString(),eventType:"x",outcome:{result:"FAILURE",reason:"r"},actor,target});
m.state.events.push(ev("1",{type:"SystemPrincipal",alternateId:"system@okta.com"},[{type:"AppUser",alternateId:"jane.doe@corp.int",displayName:"Jane Doe"},{type:"AppInstance",displayName:"Active Directory",id:"a"}]));
m.state.events.push(ev("2",{type:"User",alternateId:"jane.doe@corp.com"},[{type:"AppInstance",displayName:"Slack",id:"b"}]));
console.log(JSON.stringify([m.queryEvents({user:"jane.doe@corp.int"},0).totalMatches, m.queryEvents({user:"jane.doe@corp.com"},0).totalMatches, m.queryEvents({user:"nobody"},0).totalMatches]));')
check "user search: AD login found"            "[1,1,0]" "$UQ"

# --- brand: the name, the sign-in prompt, and the logo files ---
check "brand: the page is titled Sightline"                       "<title>Sightline</title>" "$(curl -s $A localhost:8099/)"
check "brand: the old name is gone from the page"                 0 "$(curl -s $A localhost:8099/ | grep -c 'Okta Health')"
check "brand: the sign-in prompt names Sightline"                 'realm="Sightline"' "$(curl -sI localhost:8099/api/status | tr -d '\r')"
check "brand: the favicon is served WITHOUT the password"         200 "$(code localhost:8099/favicon.svg)"
check "brand: ... as an SVG"                                      image/svg+xml "$(curl -sI localhost:8099/favicon.svg | tr -d '\r' | grep -i '^content-type')"
check "brand: /favicon.ico (what browsers ask for) answers too"   200 "$(code localhost:8099/favicon.ico)"
check "brand: the phone home-screen icon is served"               200 "$(code localhost:8099/apple-touch-icon.png)"
check "brand: ... and really is a PNG"                            89504e47 "$(curl -s localhost:8099/apple-touch-icon.png | head -c 4 | od -An -tx1 | tr -d ' \n')"
check "brand: icons are cached for a day"                         max-age=86400 "$(curl -sI localhost:8099/favicon-32.png | tr -d '\r' | grep -i '^cache-control')"
check "brand: path tricks do not reach other files (still needs the password)" 401 "$(code --path-as-is localhost:8099/favicon.svg/../server.js)"
check "brand: ... and the source code is not exposed"             0 "$(curl -s --path-as-is localhost:8099/brand/../server.js | grep -c 'createServer')"
check "brand: an unlisted file in the brand folder is not served" 401 "$(code localhost:8099/brand/sightline-logo-dark.svg)"

echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
