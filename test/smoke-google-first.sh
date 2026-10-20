#!/usr/bin/env bash
# The Google page must have data within seconds even when the last few hours are huge, and no event may be lost or doubled,
# including events sitting exactly on the boundaries where two reads meet.
#   bash test/smoke-google-first.sh        (about a minute)
cd "$(dirname "$0")/.."
PIDS=(); D=$(mktemp -d); cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$D"; }; trap cleanup EXIT
pass=0; fail=0
check() { if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected '$2', got '$3')"; fail=$((fail+1)); fi; }
jq_() { node -pe "const j=JSON.parse(require('fs').readFileSync(0));$1"; }
rm -f /tmp/first-key.json
MOCK_G_PORT=4047 MOCK_G_PAGE=1000 MOCK_G_HEAD=60000 MOCK_G_EDGE=1 MOCK_G_LATENCY_MS=150 MOCK_G_KEYFILE=/tmp/first-key.json node test/mock-google.js >/dev/null 2>&1 & PIDS+=($!)
node test/mock-okta.js >/dev/null 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do [ -s /tmp/first-key.json ] && curl -s localhost:4047/_stats >/dev/null && break; sleep 0.5; done
RAW=$(curl -s localhost:4047/_stats | jq_ 'j.total'); echo "(the fake Google holds $RAW raw events, 60,000 of them in the last 5 hours)"
( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t GOOGLE_ADMIN_EMAIL=admin@example.com GOOGLE_POLL_SECONDS=300 GOOGLE_CATCHUP_DELAY_MS=20 GOOGLE_REQUEST_DELAY_MS=0 GOOGLE_LOOKBACK_DAYS=30 PORT=8047 DATA_DIR=$D GOOGLE_API_BASE=http://localhost:4047 GOOGLE_SA_KEY="$(cat /tmp/first-key.json)"; exec node server.js >/tmp/first-server.log 2>&1 ) & PIDS+=($!)
S=$(date +%s%N); t_any=""; t_grant=""; mid=""
for i in $(seq 1 40); do sleep 0.25
  r=$(curl -s "localhost:8047/api/google/events?after=0" | node -e 'try{const j=JSON.parse(require("fs").readFileSync(0)); const act=j.events.filter(e=>e.type==="activity"); console.log(j.events.length+" "+j.events.filter(e=>e.type==="authorize").length+" "+act.reduce((n,e)=>n+(e.count||1),0)+" "+(act.length? Math.round((Date.now()-Math.max(...act.map(e=>e.time)))/6e4):-1))}catch(e){console.log("0 0 0 -1")}'); set -- $r; t=$(( ($(date +%s%N)-S)/1000000 ))
  [ -z "$t_any" ] && [ "$1" -gt 0 ] && t_any=$t; [ -z "$t_grant" ] && [ "$2" -gt 0 ] && t_grant=$t
  if [ -z "$mid" ] && [ "$3" -gt 0 ] && [ "$3" -lt 50000 ]; then mid="$3 $4"; fi
  [ -n "$t_grant" ] && [ -n "$mid" ] && break
done
echo "(first events after ${t_any:-never} ms, first grants after ${t_grant:-never} ms)"
check "data is on the page within 3 seconds, even with 60,000 API calls in the last few hours" true "$([ -n "$t_any" ] && [ "$t_any" -lt 3000 ] && echo true || echo false)"
check "... and the grants (what the page is about) are there at the same moment"             true "$([ -n "$t_grant" ] && [ "$t_grant" -lt 3000 ] && echo true || echo false)"
check "API usage fills in while history is still loading (a partial count was seen)"          true "$([ -n "$mid" ] && echo true || echo false)"
check "... newest hour first (the newest call seen so far was under 2 hours old)"             true "$(echo "$mid" | node -pe 'const m=require("fs").readFileSync(0,"utf8").trim().split(" "); (+m[1])>=0&&(+m[1])<120')"
echo "--- once everything is read ---"
for _ in $(seq 1 150); do [ "$(curl -s localhost:8047/api/google/events | jq_ 'j.status.catchingUp===false&&!!j.status.lastPollOk')" = "true" ] && break; sleep 1; done
A=$(curl -s localhost:8047/api/google/events)
check "it finished with no error"                                           '"lastError":""' "$(echo "$A" | jq_ 'JSON.stringify({lastError:j.status.lastError})')"
check "every raw event is counted exactly once ($RAW), including the ones exactly on read boundaries" "$RAW" "$(echo "$A" | jq_ 'j.events.reduce((n,e)=>n+(e.count||1),0)')"
check "... the server agrees"                                               "$RAW" "$(echo "$A" | jq_ 'j.status.rawEvents')"
check "events exactly on an hour boundary: all 120 counted (40 each: 1ms before, on, 1ms after)" 120 "$(echo "$A" | jq_ 'j.events.filter(e=>e.type==="activity"&&e.actor==="edge@example.com").reduce((n,e)=>n+(e.count||1),0)')"
check "events exactly where two day-slices meet: all 120 counted"           120 "$(echo "$A" | jq_ 'j.events.filter(e=>e.type==="authorize"&&e.actor==="edge2@example.com").reduce((n,e)=>n+(e.count||1),0)')"
check "no busy period was left half-read"                                    0 "$(echo "$A" | jq_ 'j.status.incompleteSlices')"
sleep 7; check "reading again later changes nothing (the next poll re-reads the newest hours)" "$RAW" "$(curl -s localhost:8047/api/google/events | jq_ 'j.events.reduce((n,e)=>n+(e.count||1),0)')"
echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
