#!/usr/bin/env bash
# Okta rate-limit behaviour: Sightline must pace itself and never trip the API token's limit.
#   bash test/smoke-ratelimit.sh        (takes about a minute)
cd "$(dirname "$0")/.."
PIDS=(); cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }; trap cleanup EXIT
pass=0; fail=0
check() { if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected '$2', got '$3')"; fail=$((fail+1)); fi; }
jq_() { node -pe "const j=JSON.parse(require('fs').readFileSync(0));$1"; }

echo "--- the pacing logic itself ---"
U=$(OKTA_ORG_URL=http://localhost:1 OKTA_API_TOKEN=t OKTA_MAX_RPM=30 node -e '
const {pacing}=require("./server.js"); const {rl,gate,noteHeaders,note429,rateStatus,cfg}=pacing; const out={};
const pending=async p=>{ const r=await Promise.race([p.then(()=>"done"),new Promise(r=>setTimeout(()=>r("waiting"),250))]); return r; };
(async()=>{
  const now=Date.now(); rl.sent=Array.from({length:30},(_,i)=>now-10000+i);              // 30 requests in the last 10 s: the budget is spent
  out.fullFg=await pending(gate("fg")); out.fullBg=await pending(gate("bg"));
  rl.sent=Array.from({length:24},(_,i)=>now-10000+i);                                      // 24 of 30: the live page may still go, history may not (it keeps a reserve)
  out.reserveFg=await pending(gate("fg")); rl.sent=Array.from({length:24},(_,i)=>now-10000+i); out.reserveBg=await pending(gate("bg"));
  rl.sent=[]; out.emptyBg=await pending(gate("bg"));
  rl.sent=[]; rl.holdUntil=0; noteHeaders({headers:new Map([["x-rate-limit-limit","60"],["x-rate-limit-remaining","2"],["x-rate-limit-reset",String(Math.floor(Date.now()/1000)+4)]])});
  out.holdsWhenNearlyEmpty=rl.holdUntil>Date.now()+3000; rl.holdUntil=0;
  const r429={headers:new Map([["x-rate-limit-reset",String(Math.floor(Date.now()/1000)+2)]])};
  note429(r429); out.afterOne=rl.budget; note429(r429); out.afterTwo=rl.budget; for(let i=0;i<6;i++) note429(r429); out.floor=rl.budget; out.counted=rateStatus().rejected; out.slowed=rateStatus().slowedDown;
  rl.holdUntil=0; rl.recoverAt=0; rl.sent=[]; await gate("fg"); out.recovered=rl.budget;
  rl.budget=100000; rl.sent=Array.from({length:20},(_,i)=>Date.now()-5000+i); note429(r429); out.realPace=rl.budget;           // 20 real requests when Okta said no: halve THAT
  rl.budget=cfg.rpm; rl.sent=[]; rl.holdUntil=0;
  out.fieldsPresent=["maxRpm","budgetRpm","usedLastMinute","rejected","lastRejected","slowedDown"].every(k=>k in rateStatus());
  console.log(JSON.stringify(out)); process.exit(0);
})();' 2>/dev/null)
check "pacing: with the budget spent, live requests wait"                 '"fullFg":"waiting"' "$U"
check "pacing: ... and so does the history backfill"                      '"fullBg":"waiting"' "$U"
check "pacing: the live page can still go when the backfill has to wait"  '"reserveFg":"done","reserveBg":"waiting"' "$U"
check "pacing: with room to spare, nothing waits"                         '"emptyBg":"done"' "$U"
check "pacing: Okta saying 'almost out' makes us wait for the reset"      '"holdsWhenNearlyEmpty":true' "$U"
check "pacing: a 'too many requests' halves the pace (30 to 15)"          '"afterOne":15' "$U"
check "pacing: ... and again (15 to 7)"                                   '"afterTwo":7' "$U"
check "pacing: ... but never below 6 a minute"                            '"floor":6' "$U"
check "pacing: rejections are counted and flagged"                        '"counted":8,"slowed":true' "$U"
check "pacing: the pace recovers by itself afterwards"                    '"recovered":7' "$U"
check "pacing: after a rejection it halves its real pace (20 in the last minute -> 10)" '"realPace":10' "$U"
check "pacing: the status reports all of it"                              '"fieldsPresent":true' "$U"

echo "--- against an Okta that allows 24 requests a minute ---"
MOCK_PORT=4011 MOCK_RL=24 node test/mock-okta.js >/dev/null 2>&1 & PIDS+=($!)
MOCK_PORT=4012 MOCK_RL=24 node test/mock-okta.js >/dev/null 2>&1 & PIDS+=($!)
MOCK_PORT=4013 MOCK_RL=24 MOCK_RL_NOHEADERS=1 node test/mock-okta.js >/dev/null 2>&1 & PIDS+=($!)
sleep 1.5
( export OKTA_ORG_URL=http://localhost:4011 OKTA_API_TOKEN=t PORT=8087 OKTA_MAX_RPM=12 OKTA_PAGE_SIZE=50 BACKFILL_CHUNK_HOURS=6; exec node server.js >/tmp/rl-paced.log 2>&1 ) & PIDS+=($!)
( export OKTA_ORG_URL=http://localhost:4012 OKTA_API_TOKEN=t PORT=8086 OKTA_MAX_RPM=100000 OKTA_PAGE_SIZE=50 BACKFILL_CHUNK_HOURS=6; exec node server.js >/tmp/rl-nolimit.log 2>&1 ) & PIDS+=($!)
( export OKTA_ORG_URL=http://localhost:4013 OKTA_API_TOKEN=t PORT=8085 OKTA_MAX_RPM=100000 OKTA_PAGE_SIZE=50 BACKFILL_CHUNK_HOURS=6; exec node server.js >/tmp/rl-blind.log 2>&1 ) & PIDS+=($!)
sleep 40
P=$(curl -s localhost:4011/_rlstats); H=$(curl -s localhost:4012/_rlstats); B=$(curl -s localhost:4013/_rlstats)
PS=$(curl -s localhost:8087/api/status | jq_ 'JSON.stringify(j.rateLimit)'); BS=$(curl -s localhost:8085/api/status | jq_ 'JSON.stringify(j.rateLimit)')
echo "  (A) Sightline's own limit set to 12 a minute"
check "A: Okta never had to say 'too many requests'"                      '"rejected":0' "$P"
check "A: it really made requests (history was loading)"                  true "$(echo "$P" | jq_ 'j.requests>=8')"
check "A: never more than 12 in any minute (its own limit)"               true "$(echo "$P" | jq_ 'j.maxPerMinute<=12')"
check "A: the status shows the pace and no rejections"                    '"budgetRpm":12' "$PS"
check "A: the app is healthy"                                             true "$(curl -s localhost:8087/api/status | jq_ 'j.live===true')"
echo "  (B) own limit switched off, Okta sends its usual 'requests remaining' headers"
check "B: it still never got rejected: it watched the headers and waited" '"rejected":0' "$H"
check "B: it used most of what Okta allowed, not more"                    true "$(echo "$H" | jq_ 'j.maxPerMinute<=24&&j.maxPerMinute>=12')"
echo "  (C) own limit switched off AND Okta sends no headers: only the 429 can tell it"
check "C: Okta did have to reject some requests"                          true "$(echo "$B" | jq_ 'j.rejected>0')"
check "C: the app slowed itself down in response"                         '"slowedDown":true' "$BS"
check "C: ... counted the rejections for the status"                      true "$(echo "$BS" | node -pe 'JSON.parse(require("fs").readFileSync(0)).rejected>0')"
check "C: ... and halved its REAL pace (not an imaginary 100,000 ceiling)"   true "$(echo "$BS" | node -pe 'JSON.parse(require("fs").readFileSync(0)).budgetRpm<=24')"
check "C: ... and kept running"                                           true "$(curl -s localhost:8085/api/status | jq_ 'j.live===true')"
check "C: the log says what it is doing when Okta pushes back"            "too many requests" "$(cat /tmp/rl-blind.log)"
check "the paced server's log has no complaints"                          0 "$(grep -c 'too many requests' /tmp/rl-paced.log)"

echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
