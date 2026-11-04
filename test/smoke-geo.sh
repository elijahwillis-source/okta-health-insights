#!/usr/bin/env bash
# Location alerts and Slack, end to end: rules, preview, live detection from new events, Slack delivery, failures, floods, restarts.
# Two servers read the same fake Okta: A has Slack (a fake Slack records what it is sent), B has none.   bash test/smoke-geo.sh   (about two minutes)
cd "$(dirname "$0")/.."
PIDS=(); cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$D1" "$D2" 2>/dev/null; }; trap cleanup EXIT
pass=0; fail=0
check() { if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected '$2', got '$3')"; fail=$((fail+1)); fi; }
jq_() { node -pe "const j=JSON.parse(require('fs').readFileSync(0));$1"; }
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
waitfor() { local n=$1; shift; for _ in $(seq 1 "$n"); do if eval "$@"; then return 0; fi; sleep 1; done; return 1; }
J='content-type: application/json'; NAME='x-sightline-name: Dana Admin'
D1=$(mktemp -d); D2=$(mktemp -d); LOG=/tmp/geo-server.log; : > $LOG
MOCK=localhost:4010; SL=localhost:4071; UA=localhost:8081; UB=localhost:8082
MOCK_GEO=1 node test/mock-okta.js >/dev/null 2>&1 & PIDS+=($!)
node test/mock-slack.js >/dev/null 2>&1 & PIDS+=($!)
start() { ( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t POLL_INTERVAL_SECONDS=15 SLACK_API_BASE=http://localhost:4071/api AUDIT_STDOUT=false "$@"; exec node server.js >>$LOG 2>&1 ) & LASTPID=$!; PIDS+=($!); }
inj() { local a=(); for kv in "$@"; do a+=(--data-urlencode "$kv"); done; curl -s -G "$MOCK/_inject" "${a[@]}" >/dev/null; }
ALERTS() { curl -s "$1/api/geo/alerts"; }
acount() { ALERTS "$1" | jq_ "j.alerts.filter(a=>$2).length"; }
posts() { curl -s $SL/_posts | jq_ 'j.posts.length'; }
ready() { [ "$(curl -s $1/api/status | jq_ 'j.lastPollOk?1:0' 2>/dev/null)" = "1" ]; }
RU="kind=invalid_password"; FAILCT='type=user.session.start&result=FAILURE'

start PORT=8081 DATA_DIR=$D1 SLACK_BOT_TOKEN=xoxb-test-token SLACK_CHANNEL=#it-alerts SLACK_MAX_PER_MINUTE=6 SLACK_SUMMARY_SECONDS=3 SLACK_LINK_URL=http://sightline.test; PIDA=$LASTPID
start PORT=8082 DATA_DIR=$D2
waitfor 30 'ready $UA && ready $UB'

echo "--- what ships: the manifest and the Docker image ---"
node -e "
const f=require('fs'); const m=JSON.parse(f.readFileSync('integrations/slack/app-manifest.json','utf8'));
console.log(JSON.stringify(m.oauth_config.scopes.bot), m.display_information.name, m.features.bot_user.always_online)" > /tmp/geo-manifest.txt
check "the manifest file asks for exactly chat:write and chat:write.public" '["chat:write","chat:write.public"]' "$(cat /tmp/geo-manifest.txt)"
check "... and the app serves the same manifest as a download"  "$(cat integrations/slack/app-manifest.json | tr -d ' \n')" "$(curl -s $UA/api/slack/manifest | tr -d ' \n')"
check "... named as a file"                                      'sightline-slack-app-manifest.json' "$(curl -s -D - -o /dev/null $UA/api/slack/manifest | tr -d '\r' | grep -i content-disposition)"
MISSING=""; for f in $(grep -ho 'require("\./[a-z]*")' *.js | sed 's/.*\.\/\(.*\)")/\1/' | sort -u); do grep -q "^COPY.*[ ]$f\.js" Dockerfile || MISSING="$MISSING $f"; done
check "every module the app needs is copied into the Docker image (a missing one would crash a deploy)" "" "$MISSING"
check "the image copies geo.js and slack.js"                     'geo.js slack.js' "$(grep '^COPY package' Dockerfile)"

echo "--- creating location rules ---"
S=$(curl -s $UA/api/policy); V=$(echo "$S" | jq_ 'j.meta.version')
check "the policy starts with no location rules"                 '"geoRules":[]' "$S"
RULES='[{"id":"r-ru","name":"Invalid passwords from watched regions","kind":"invalid_password","mode":"in","places":["RU","China"],"count":1,"severity":"bad","slack":true,"cooldownMinutes":60},
{"id":"r-out","name":"Sign-ins from outside our regions","kind":"signin","mode":"outside","places":["United States","Canada","United Kingdom"],"count":1,"severity":"warn","slack":false,"cooldownMinutes":0},
{"id":"r-ir","name":"Repeated invalid passwords from Iran","kind":"invalid_password","mode":"in","places":["Iran"],"count":3,"windowMinutes":30,"per":"person","severity":"bad","slack":true,"cooldownMinutes":60}]'
put() { curl -s -X PUT -H "$J" -H "$NAME" -d "{\"baseVersion\":$2,\"rules\":$3,\"why\":\"$4\"}" $1/api/policy/geo-rules; }
check "a change without a reason is refused"                     'Say why' "$(curl -s -X PUT -H "$J" -H "$NAME" -d "{\"baseVersion\":$V,\"rules\":$RULES}" $UA/api/policy/geo-rules)"
check "a rule with no places is refused"                         'at least one place' "$(put $UA $V '[{"name":"x","kind":"signin","places":[]}]' 'Testing the checks here')"
check "a rule with an unknown kind is refused"                   'Choose what to watch' "$(put $UA $V '[{"name":"x","kind":"everything","places":["Russia"]}]' 'Testing the checks here')"
check "a stale version is refused (409), so two admins cannot overwrite each other" 409 "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$J" -H "$NAME" -d "{\"baseVersion\":$((V+5)),\"rules\":$RULES,\"why\":\"Regions the security team watches\"}" $UA/api/policy/geo-rules)"
C=$(put $UA $V "$RULES" 'Regions the security team watches')
check "three rules are saved"                                    '"count":3' "$C"
check "places are understood: 'RU' is saved as Russia"           '"country":"Russia"' "$C"
check "the rule remembers who made it"                           '"createdBy":"Dana Admin"' "$C"
check "the version moved on"                                     "$((V+1))" "$(echo "$C" | jq_ 'j.meta.version')"
check "everyone sees the rules in the policy"                    '"id":"r-ru"' "$(curl -s $UA/api/policy)"
check "each rule is in the audit log, with the reason"           3 "$(curl -s "$UA/api/audit?action=georule.create" | jq_ 'j.rows.filter(r=>r.why.includes("security team")).length')"
V2=$(echo "$C" | jq_ 'j.meta.version')
OFF=$(echo "$RULES" | node -pe "const r=JSON.parse(require('fs').readFileSync(0));r[1].enabled=false;JSON.stringify(r)")
D=$(put $UA $V2 "$OFF" 'Paused while we review the list'); V3=$(echo "$D" | jq_ 'j.meta.version')
check "switching a rule off is recorded as that, not as an edit" 1 "$(curl -s "$UA/api/audit?action=georule.disable" | jq_ 'j.rows.length')"
E=$(put $UA $V3 "$RULES" 'Back on after the review'); 
check "... and switching it on again too"                        1 "$(curl -s "$UA/api/audit?action=georule.enable" | jq_ 'j.rows.length')"
check "rules that did not change are not logged as edited"       0 "$(curl -s "$UA/api/audit?action=georule.update" | jq_ 'j.rows.length')"
# the other server gets the same rules, so it can show what happens when Slack is not set up
VB=$(curl -s $UB/api/policy | jq_ 'j.meta.version'); put $UB $VB "$RULES" 'Regions the security team watches' >/dev/null

echo "--- trying a rule before saving it ---"
P=$(curl -s -X POST -H "$J" -d '{"rule":{"kind":"signin","mode":"outside","places":["United States","Canada","United Kingdom"]}}' $UA/api/geo/preview)
check "it finds events from outside those places in the data held" true "$(echo "$P" | jq_ 'j.events>0 && j.people>0 && j.wouldAlert>0')"
check "... with examples that say where each came from"          true "$(echo "$P" | jq_ 'j.samples.length>0 && j.samples.length<=8 && /Germany|Brazil|Russia|China|Iran/.test(j.samples[0].where)')"
check "... and how much data it looked at"                       true "$(echo "$P" | jq_ 'j.held>0 && !!j.heldFrom')"
PS=$(curl -s -X POST -H "$J" -d '{"rule":{"kind":"signin_failed","mode":"in","places":["RU","North Korea"]}}' $UA/api/geo/preview)
check "it says which of the places have appeared in the data (and understands 'RU')" true "$(echo "$PS" | jq_ 'j.placesSeen.length===2 && j.placesSeen[0].text==="Russia" && j.placesSeen[0].seen===true && j.placesSeen[1].seen===false')"
check "a rule with no places cannot be tried"                    400 "$(code -X POST -H "$J" -d '{"rule":{"kind":"signin","places":[]}}' $UA/api/geo/preview)"
PL=$(curl -s $UA/api/geo/places)
check "the places list shows where sign-ins come from"           true "$(echo "$PL" | jq_ 'j.countries.some(c=>c.country==="Canada"&&c.signins>0) && j.countries.some(c=>c.country==="Russia"&&c.invalidPasswords>0)')"
check "... and how many events had no location"                  true "$(echo "$PL" | jq_ 'typeof j.unknownLocation==="number"')"
check "no alert was raised just by starting up (the history is not news)" 0 "$(acount $UA true)"

echo "--- new sign-ins arrive ---"
inj type=user.session.start result=FAILURE reason=INVALID_CREDENTIALS user=alice@x.test name=Alice country=Russia region=Moscow city=Moscow ip=198.51.100.7 app=Okta
inj type=user.session.start result=FAILURE reason=INVALID_CREDENTIALS user=bob@x.test country=Canada region=Ontario city=Toronto
inj type=user.session.start result=SUCCESS user=alice@x.test name=Alice country=Russia region=Moscow city=Moscow ip=198.51.100.7
inj type=user.session.start result=SUCCESS user=carol@x.test country="United States" region=Texas city=Austin
inj type=user.session.start result=SUCCESS user=dave@x.test
inj type=user.authentication.auth_via_mfa result=FAILURE reason=VERIFICATION_ERROR user=mallory@x.test country=Russia region=Moscow city=Moscow
inj type=user.session.start result=FAILURE reason=INVALID_CREDENTIALS user='<!channel>@x.test' name='<!here> Eve' country=Russia region=Moscow city=Moscow
inj type=user.session.start result=FAILURE reason=INVALID_CREDENTIALS user=eve@x.test country=Iran region=Tehran city=Tehran n=5
inj type=user.session.start result=FAILURE reason=INVALID_CREDENTIALS user=frank@x.test country=Iran region=Tehran city=Tehran n=2
waitfor 50 '[ "$(acount $UA true)" -ge 4 ]'; sleep 3
check "exactly the four things that should alert did"            4 "$(acount $UA true)"
check "... an invalid password from Russia (watched)"            2 "$(acount $UA 'a.ruleId=="r-ru"')"
check "... a sign-in from outside the expected places"           1 "$(acount $UA 'a.ruleId=="r-out"&&a.person=="alice@x.test"&&a.where.country=="Russia"')"
check "... three invalid passwords for one person from Iran, once, even though five came" 1 "$(acount $UA 'a.ruleId=="r-ir"&&a.person=="eve@x.test"&&a.matched===3&&a.threshold===3')"
check "an invalid password from Canada did not alert"            0 "$(acount $UA 'a.person=="bob@x.test"')"
check "a sign-in from the United States did not alert"           0 "$(acount $UA 'a.person=="carol@x.test"')"
check "a sign-in with no known location did not alert"           0 "$(acount $UA 'a.person=="dave@x.test"')"
check "an MFA failure did not alert (no rule watches it)"        0 "$(acount $UA 'a.person=="mallory@x.test"')"
check "two failures from Iran for someone else are not enough yet" 0 "$(acount $UA 'a.person=="frank@x.test"')"
AL=$(ALERTS $UA | jq_ 'JSON.stringify(j.alerts.find(a=>a.ruleId==="r-ru"&&a.person==="alice@x.test"))')
check "an alert says who, where, what, when and how serious"     true "$(echo "$AL" | node -pe "const a=JSON.parse(require('fs').readFileSync(0));a.where.city==='Moscow'&&a.where.country==='Russia'&&a.kindLabel==='Invalid passwords'&&a.severity==='bad'&&a.ip==='198.51.100.7'&&!!a.ts&&a.app==='Okta'")"
waitfor 30 '[ "$(posts)" -ge 3 ]'; sleep 1
check "the two Slack rules posted to Slack, and the in-app one did not" 3 "$(posts)"
check "... each alert says what happened to its Slack message"   true "$(ALERTS $UA | jq_ 'j.alerts.filter(a=>a.ruleId!=="r-out").every(a=>a.slack.state==="sent") && j.alerts.filter(a=>a.ruleId==="r-out").every(a=>a.slack.state==="off")')"
SP=$(curl -s $SL/_posts)
check "the post goes to the channel that was set"                '"channel":"#it-alerts"' "$SP"
check "... names the rule, and has Person, Where, What, When and the IP address" true "$(echo "$SP" | jq_ 'j.posts.every(p=>/Person/.test(p.raw)&&/Where/.test(p.raw)&&/When/.test(p.raw)&&/IP address/.test(p.raw)&&/Sightline: /.test(p.text))')"
check "... and links back to the Alerts page"                    'http://sightline.test/#/alerts' "$SP"
check "<!channel> in a person's name is defused: it cannot ping the channel" true "$(echo "$SP" | jq_ 'j.posts.some(p=>p.raw.includes("&lt;!channel&gt;")) && j.posts.every(p=>!p.raw.includes("<!channel>")&&!p.raw.includes("<!here>"))')"
check "every alert is in the audit log, from Sightline itself"   4 "$(curl -s "$UA/api/audit?action=alert.geo" | jq_ 'j.rows.filter(r=>r.cat==="alerts"&&r.actor.name==="sightline").length')"
check "the alerts list can be asked for only what is newer"      0 "$(curl -s "$UA/api/geo/alerts?since=$(node -pe 'new Date(Date.now()+3600000).toISOString()')" | jq_ 'j.alerts.length')"
check "the status page knows location alerts are being checked"  true "$(curl -s $UA/api/status | jq_ '!!j.geo.lastEvaluated && j.slack.configured===true')"

echo "--- Slack says no ---"
curl -s "$SL/_mode?m=error" >/dev/null
inj type=user.session.start result=FAILURE reason=INVALID_CREDENTIALS user=frank@x.test country=Iran region=Tehran city=Tehran
waitfor 50 '[ "$(acount $UA true)" -ge 5 ]'; waitfor 15 '[ "$(acount $UA "a.slack&&a.slack.state==\"failed\"")" -ge 1 ]'
check "the third failure from Iran raises the alert (the count carried across polls)" 1 "$(acount $UA 'a.person=="frank@x.test"&&a.matched===3')"
check "the alert is still raised in the app when Slack fails, and says why" true "$(ALERTS $UA | jq_ 'j.alerts.some(a=>a.person==="frank@x.test"&&a.slack.state==="failed"&&a.slack.error==="channel_not_found"&&/channel was not found/i.test(a.slack.hint))')"
SI=$(curl -s $UA/api/slack)
check "the Slack status shows the last error in plain words"     true "$(echo "$SI" | jq_ 'j.lastError==="channel_not_found" && /not found/i.test(j.lastErrorHint) && j.failed>=1')"
check "the failure is in the audit log"                          1 "$(curl -s "$UA/api/audit?action=alert.slack.failed" | jq_ 'j.rows.length>0?1:0')"
check "the server is fine"                                       200 "$(code $UA/healthz)"
curl -s "$SL/_mode?m=ok" >/dev/null

echo "--- a flood ---"
P0=$(posts); N0=$(acount $UA true)
inj type=user.session.start result=FAILURE reason=INVALID_CREDENTIALS user=flood@x.test country=Russia region=Moscow city=Moscow n=30 distinct=1
waitfor 50 '[ "$(acount $UA true)" -ge $((N0+30)) ]'; waitfor 25 '[ "$(acount $UA "a.slack&&a.slack.state==\"queued\"")" -eq 0 ]'; sleep 6
SUMM=$(ALERTS $UA | jq_ 'j.alerts.filter(a=>a.slack.state==="summarized").length')
check "all thirty are raised in the app"                         30 "$(acount $UA 'a.person.startsWith("flood")')"
check "only some are posted one by one, the rest are summed up"  true "$([ "$SUMM" -ge 20 ] && echo true || echo false)"
FP=$(( $(posts) - P0 ))
check "... the ones posted one by one stay within the cap of six a minute (plus the one summary)" true "$([ $FP -ge 2 ] && [ $FP -le 7 ] && echo true || echo false)"
check "... and ONE message says how many were left out"          true "$(curl -s $SL/_posts | jq_ "j.posts.filter(p=>/more location alerts/.test(p.text)&&p.text.includes('$SUMM')).length===1")"
echo "--- nothing repeats ---"
N1=$(acount $UA true); P1=$(posts); sleep 20
check "after more polls the alerts are not raised again"          "$N1" "$(acount $UA true)"
check "... and nothing more is posted to Slack"                   "$P1" "$(posts)"

echo "--- a restart ---"
inj type=user.session.start result=FAILURE reason=INVALID_CREDENTIALS user=erin@x.test country=Russia region=Moscow city=Moscow minutesAgo=2
inj type=user.session.start result=FAILURE reason=INVALID_CREDENTIALS user=oldfred@x.test country=Russia region=Moscow city=Moscow minutesAgo=200
inj type=user.session.start result=FAILURE reason=INVALID_CREDENTIALS user=carl@x.test country=Russia region=Moscow city=Moscow minutesAgo=0
sleep 17   # let the first server see them, so only the restart can tell them apart
kill -TERM $PIDA; sleep 2; N2=$(acount $UB true)
start PORT=8081 DATA_DIR=$D1 SLACK_BOT_TOKEN=xoxb-test-token SLACK_CHANNEL=#it-alerts SLACK_MAX_PER_MINUTE=6 SLACK_SUMMARY_SECONDS=3 SLACK_LINK_URL=http://sightline.test; PIDA=$LASTPID
waitfor 30 'ready $UA'; sleep 17
check "the earlier alerts survived the restart"                   true "$(ALERTS $UA | jq_ 'j.alerts.length>=36')"
check "the location rules survived too"                           3 "$(curl -s $UA/api/policy | jq_ 'j.geoRules.length')"
check "nobody was alerted twice for the same sign-in"             1 "$(acount $UA 'a.person=="alice@x.test"&&a.ruleId=="r-ru"')"
check "someone first seen after the restart (2 minutes old) is alerted exactly once" 1 "$(acount $UA 'a.person=="erin@x.test"')"
check "someone alerted before the restart is not alerted again after it"  1 "$(acount $UA 'a.person=="carl@x.test"')"
check "the person from 200 minutes ago was history, not news"     0 "$(acount $UA 'a.person=="oldfred@x.test"')"

echo "--- the server without Slack ---"
check "location alerts still work, without Slack"                 true "$(ALERTS $UB | jq_ 'j.alerts.length>=30')"
check "... and each one says Slack is not set up (or was off for the rule)" true "$(ALERTS $UB | jq_ 'j.alerts.every(a=>["not_configured","off"].includes(a.slack.state))')"
SB=$(curl -s $UB/api/slack)
check "the Slack page says what is missing"                       true "$(echo "$SB" | jq_ 'j.configured===false && j.tokenSet===false && j.channelSet===false')"
T=$(curl -s -X POST -H "$J" -H "$NAME" $UB/api/slack/test)
check "a test message says to set the token and channel first"    'SLACK_BOT_TOKEN' "$T"
check "a test message on the configured server is posted, with who sent it" true "$(curl -s -X POST -H "$J" -H "$NAME" $UA/api/slack/test | jq_ 'j.ok===true')"
check "... and the post names the person"                          1 "$(curl -s $SL/_posts | jq_ "j.posts.filter(p=>/test message from Dana Admin/.test(p.text)).length")"
check "the test is in the audit log"                              1 "$(curl -s "$UA/api/audit?action=slack.test" | jq_ 'j.rows.length>0?1:0')"

echo "--- secrets stay secret ---"
LEAK=0; for u in $UA/api/status $UA/api/slack $UA/api/policy $UA/api/geo/alerts $UA/api/diagnostics; do curl -s $u | grep -q "xoxb-test-token" && LEAK=$((LEAK+1)); done
check "the Slack token is in no API answer"                       0 "$LEAK"
check "... and not in the server log"                             0 "$(grep -c 'xoxb-test-token' $LOG)"
check "... and not in the audit log"                              0 "$(curl -s "$UA/api/audit?limit=2000" | grep -c 'xoxb-test-token')"

echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
