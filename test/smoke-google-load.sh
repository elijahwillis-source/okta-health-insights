#!/usr/bin/env bash
# A heavy, noisy Google org: the newest events must show first, nothing may be lost, and noise must be summarised.
#   bash test/smoke-google-load.sh        (about a minute and a half)
cd "$(dirname "$0")/.."
ROOT=$(pwd)
export DATA_DIR=$(mktemp -d)      # policy files of the servers under test: throwaway
PIDS=(); cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }; trap cleanup EXIT
pass=0; fail=0
check() { if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected '$2', got '$3')"; fail=$((fail+1)); fi; }
jq_() { node -pe "const j=JSON.parse(require('fs').readFileSync(0));$1"; }
rm -f /tmp/load-gkey.json
MOCK_G_PORT=4031 MOCK_G_PAGE=40 MOCK_G_NOISE=300 MOCK_G_REPEAT=150 MOCK_G_LATENCY_MS=120 MOCK_G_KEYFILE=/tmp/load-gkey.json node test/mock-google.js >/tmp/load-google.log 2>&1 & PIDS+=($!)
node test/mock-okta.js >/dev/null 2>&1 & PIDS+=($!)
for _ in $(seq 1 40); do [ -s /tmp/load-gkey.json ] && curl -s localhost:4031/_stats >/dev/null && break; sleep 0.3; done
COMMON="OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t GOOGLE_ADMIN_EMAIL=admin@example.com GOOGLE_API_BASE=http://localhost:4031 GOOGLE_POLL_SECONDS=5 GOOGLE_CATCHUP_DELAY_MS=100 GOOGLE_REQUEST_DELAY_MS=0 GOOGLE_LOOKBACK_DAYS=30 GOOGLE_ACTIVITY_DAYS=30"
( export $COMMON GOOGLE_SA_KEY="$(cat /tmp/load-gkey.json)" PORT=8083; exec node server.js >/tmp/load-a.log 2>&1 ) & PIDS+=($!)
( export $COMMON GOOGLE_SA_KEY="$(cat /tmp/load-gkey.json)" PORT=8082 GOOGLE_MAX_PAGES_PER_SLICE=5; exec node server.js >/tmp/load-b.log 2>&1 ) & PIDS+=($!)
# a second copy of the same busy org that Sightline will read with its DEFAULT settings (API usage for the last 3 days only)
rm -f /tmp/load-gkey2.json /tmp/load-gkey3.json
MOCK_G_PORT=4033 MOCK_G_PAGE=40 MOCK_G_NOISE=300 MOCK_G_REPEAT=150 MOCK_G_KEYFILE=/tmp/load-gkey2.json node test/mock-google.js >/dev/null 2>&1 & PIDS+=($!)
# and a much bigger one: 75,000 raw API calls (the fake is slow, a real org is bigger still), enough to prove nothing is remembered per call
MOCK_G_PORT=4034 MOCK_G_NOISE=2500 MOCK_G_KEYFILE=/tmp/load-gkey3.json node test/mock-google.js >/dev/null 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do [ -s /tmp/load-gkey2.json ] && [ -s /tmp/load-gkey3.json ] && curl -s localhost:4033/_stats >/dev/null && curl -s localhost:4034/_stats >/dev/null && break; sleep 0.5; done
( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t GOOGLE_ADMIN_EMAIL=admin@example.com GOOGLE_POLL_SECONDS=5 GOOGLE_CATCHUP_DELAY_MS=100 GOOGLE_REQUEST_DELAY_MS=0 GOOGLE_LOOKBACK_DAYS=30 PORT=8081 GOOGLE_API_BASE=http://localhost:4033 GOOGLE_SA_KEY="$(cat /tmp/load-gkey2.json)"; exec node server.js >/tmp/load-c.log 2>&1 ) & PIDS+=($!)
( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t GOOGLE_ADMIN_EMAIL=admin@example.com GOOGLE_POLL_SECONDS=5 GOOGLE_CATCHUP_DELAY_MS=20 GOOGLE_REQUEST_DELAY_MS=0 GOOGLE_LOOKBACK_DAYS=30 GOOGLE_ACTIVITY_DAYS=30 PORT=8080 GOOGLE_API_BASE=http://localhost:4034 GOOGLE_SA_KEY="$(cat /tmp/load-gkey3.json)"; exec node server.js >/tmp/load-d.log 2>&1 ) & PIDS+=($!)
RAW=$(curl -s localhost:4031/_stats | jq_ 'j.total'); echo "(the fake Google holds $RAW raw events)"

echo "--- the first seconds: is the page current while older history is still loading? ---"
for _ in $(seq 1 40); do [ "$(curl -s localhost:8083/api/status | node -pe 'try{JSON.parse(require("fs").readFileSync(0)).google.events>0}catch{false}')" = "true" ] && break; sleep 0.3; done
E1=$(curl -s "localhost:8083/api/google/events?after=0"); S1=$(echo "$E1" | jq_ 'j.seq'); N1=$(echo "$E1" | jq_ 'j.events.length'); MIN1=$(echo "$E1" | jq_ 'Math.min(...j.events.map(e=>e.time))'); MAX1=$(echo "$E1" | jq_ 'Math.max(...j.events.map(e=>e.time))')
ST1=$(echo "$E1" | jq_ 'JSON.stringify(j.status)')
check "newest first: events are there within seconds"                    true "$(echo "$E1" | jq_ 'j.events.length>0')"
check "newest first: ... and they are from the last few hours"           true "$(echo "$E1" | jq_ "Math.max(...j.events.map(e=>e.time))>Date.now()-6*36e5")"
check "newest first: ... while older history is STILL loading"           '"catchingUp":true' "$ST1"
check "newest first: ... and the status says how far back it has got"    true "$(echo "$ST1" | node -pe 'const s=JSON.parse(require("fs").readFileSync(0)); s.loadedBack>Date.now()-29*864e5')"
check "the very first batch has only recent events (nothing from last month yet)" true "$(echo "$E1" | jq_ "Math.min(...j.events.map(e=>e.time))>Date.now()-3*864e5")"
sleep 6
D=$(curl -s "localhost:8083/api/google/events?after=$S1")
check "sync by sequence: older events that arrive LATER are delivered"   true "$(echo "$D" | jq_ "j.events.length>0&&j.events.some(e=>e.time<$MIN1)")"
check "... which a sync by time alone would have missed"                 0 "$(curl -s "localhost:8083/api/google/events?since=$MAX1" | jq_ "j.events.filter(e=>e.time<$MIN1).length")"
check "the server says which run it is (so a restart is noticed)"        true "$(echo "$D" | jq_ 'typeof j.epoch==="number"&&j.epoch>0')"

echo "--- once everything is loaded ---"
for _ in $(seq 1 120); do [ "$(curl -s localhost:8083/api/status | node -pe 'try{const g=JSON.parse(require("fs").readFileSync(0)).google; !g.catchingUp&&g.polls!==0&&g.events>0}catch{false}')" = "true" ] && [ "$(curl -s localhost:8083/api/google/events | jq_ 'j.status.catchingUp')" = "false" ] && break; sleep 1; done
A=$(curl -s localhost:8083/api/google/events)
check "history finished"                                                 '"catchingUp":false' "$(echo "$A" | jq_ 'JSON.stringify(j.status)')"
check "nothing lost: every raw event is counted in a stored summary"     "$RAW" "$(echo "$A" | jq_ 'j.events.reduce((n,e)=>n+(e.count||1),0)')"
check "nothing lost: the server saw every raw event"                     "$RAW" "$(echo "$A" | jq_ 'j.status.rawEvents')"
check "noise is summarised: 9,000 'used the API' calls become far fewer entries" true "$(echo "$A" | jq_ 'j.events.filter(e=>e.type==="activity").length<800')"
check "... without losing a single call"                                 9001 "$(echo "$A" | jq_ 'j.events.filter(e=>e.type==="activity").reduce((n,e)=>n+(e.count||1),0)')"
check "300 identical grants in the same minute become a handful of entries" true "$(echo "$A" | jq_ 'j.events.filter(e=>e.type==="authorize"&&e.actor==="chatty@example.com").length<=4')"
check "... and still add up to 300"                                      300 "$(echo "$A" | jq_ 'j.events.filter(e=>e.type==="authorize"&&e.actor==="chatty@example.com").reduce((n,e)=>n+(e.count||1),0)')"
check "the real, one-off grants are untouched (Sketchy PDF: 6 people)"   6 "$(echo "$A" | jq_ 'new Set(j.events.filter(e=>e.type==="authorize"&&e.app==="Sketchy PDF Tool").map(e=>e.actor)).size')"
check "the list is oldest to newest"                                     true "$(echo "$A" | jq_ 'j.events.every((e,i)=>i===0||j.events[i-1].time<=e.time)')"
check "no busy period was left half-read"                                0 "$(echo "$A" | jq_ 'j.status.incompleteSlices')"

echo "--- a very busy slice is split, not cut off (only 5 pages of 40 allowed per slice, so each busy day has to be split) ---"
for _ in $(seq 1 150); do [ "$(curl -s localhost:8082/api/google/events | jq_ 'j.status.catchingUp===false&&!!j.status.lastPollOk')" = "true" ] && break; sleep 1; done
Bb=$(curl -s localhost:8082/api/google/events)
check "split: it still read every raw event"                             "$RAW" "$(echo "$Bb" | jq_ 'j.status.rawEvents')"
check "split: and counted them all"                                      "$RAW" "$(echo "$Bb" | jq_ 'j.events.reduce((n,e)=>n+(e.count||1),0)')"
check "split: no slice reported as cut off"                              0 "$(echo "$Bb" | jq_ 'j.status.incompleteSlices')"

echo "--- default settings: grants for the whole 30 days, API usage for the last 3 only ---"
for _ in $(seq 1 150); do [ "$(curl -s localhost:8081/api/google/events | jq_ 'j.status.catchingUp===false&&!!j.status.lastPollOk')" = "true" ] && break; sleep 1; done
Cc=$(curl -s localhost:8081/api/google/events); S4=$(curl -s localhost:4033/_stats); S1=$(curl -s localhost:4031/_stats)
check "default: the status says API usage is read for 3 days"           '"activityDays":3' "$(echo "$Cc" | jq_ 'JSON.stringify(j.status)')"
check "default: the grant from 10 days ago is still all there (300 in total)" 300 "$(echo "$Cc" | jq_ 'j.events.filter(e=>e.type==="authorize"&&e.actor==="chatty@example.com").reduce((n,e)=>n+(e.count||1),0)')"
check "default: the one-off grants are untouched (Sketchy PDF: 6 people)" 6 "$(echo "$Cc" | jq_ 'new Set(j.events.filter(e=>e.type==="authorize"&&e.app==="Sketchy PDF Tool").map(e=>e.actor)).size')"
check "default: API usage covers about 3 days (not 30)"                 true "$(echo "$Cc" | jq_ 'const n=j.events.filter(e=>e.type==="activity").reduce((a,e)=>a+(e.count||1),0); n>=800&&n<=1300')"
check "default: nothing older than the 3 days is in the API usage"      true "$(echo "$Cc" | jq_ 'j.events.filter(e=>e.type==="activity").every(e=>e.time>Date.now()-4*864e5)')"
check "default: far fewer requests than reading everything"             true "$(node -pe "const a=$S4.apiRequests,b=$S1.apiRequests; a*2<b")"
check "default: each kind of grant event is asked for by name (as Google documents)" true "$(echo "$S4" | jq_ '["authorize","request","revoke","deny","activity"].every(k=>(j.eventNameCalls||{})[k]>0)')"
check "default: the status carries no complaint"                        '"lastError":""' "$(echo "$Cc" | jq_ 'JSON.stringify({lastError:j.status.lastError})')"

echo "--- a very big org: 75,000 raw API calls, held as summaries (the old loader kept one entry per call and overflowed at 16 million) ---"
for _ in $(seq 1 160); do [ "$(curl -s localhost:8080/api/google/events | jq_ 'j.status.catchingUp===false&&!!j.status.lastPollOk')" = "true" ] && break; sleep 1; done
Dd=$(curl -s localhost:8080/api/google/events); RAW3=$(curl -s localhost:4034/_stats | jq_ 'j.total')
check "big: it finished with no error"                                  '"lastError":""' "$(echo "$Dd" | jq_ 'JSON.stringify({lastError:j.status.lastError})')"
check "big: every raw call is counted ($RAW3)"                          "$RAW3" "$(echo "$Dd" | jq_ 'j.events.reduce((n,e)=>n+(e.count||1),0)')"
check "big: 75,000 calls are held as a few hundred summaries"          true "$(echo "$Dd" | jq_ 'j.events.length<1000')"
check "big: the server has no per-event memory (no list of event ids)"  true "$(cd /tmp && node -e 'const {createGoogle}=require("'$ROOT'/google.js"); const g=createGoogle({},()=>{}); console.log(!("ids" in g._state)&&!("raw" in g._state))')"
check "big: reading the same range again does not change the counts"    true "$(sleep 7; curl -s localhost:8080/api/google/events | jq_ "j.events.reduce((n,e)=>n+(e.count||1),0)===$RAW3")"

echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
