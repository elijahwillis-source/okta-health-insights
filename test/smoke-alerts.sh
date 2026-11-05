#!/usr/bin/env bash
# The shared alerts (errors, new errors, ...) checked ON THE SERVER, with sign-in on: an admin shares alerts and routes them to Slack channels, new events
# arrive, the server raises the alerts with nobody looking, Slack gets them in the right channel, known errors are not counted, and a restart repeats nothing.
#   bash test/smoke-alerts.sh        (about five minutes: run it detached if your tool has a time limit)
cd "$(dirname "$0")/.."
PIDS=(); D1=$(mktemp -d); J=$(mktemp -d); LOG=/tmp/alerts-8070.log; : > $LOG
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$D1" "$J"; }; trap cleanup EXIT
pass=0; fail=0
check() { if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected '$2', got '$3')"; fail=$((fail+1)); fi; }
jq_() { node -pe "const j=JSON.parse(require('fs').readFileSync(0));$1"; }
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
waitfor() { local n=$1; shift; for _ in $(seq 1 "$n"); do if eval "$@"; then return 0; fi; sleep 1; done; return 1; }
H='content-type: application/json'; U=localhost:8070; M=localhost:4061; MOCK=localhost:4010; SL=localhost:4071
SECRET="a-long-random-session-secret-for-tests-0123456789"
node test/mock-okta.js >/dev/null 2>&1 & PIDS+=($!)
node test/mock-slack.js >/dev/null 2>&1 & PIDS+=($!)
MOCK_OIDC_PORT=4061 MOCK_OIDC_REDIRECT=http://localhost:8070/callback node test/mock-oidc.js >/dev/null 2>&1 & PIDS+=($!)
start() { ( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t OIDC_ISSUER=http://localhost:4061 OIDC_CLIENT_ID=0oaTEST OIDC_CLIENT_SECRET=s3cret-value SESSION_SECRET=$SECRET OIDC_OWNER_GROUPS=sightline-owners OIDC_ADMIN_GROUPS=sightline-admins OIDC_USER_GROUPS=sightline-users PORT=8070 PUBLIC_URL=http://localhost:8070 DATA_DIR=$D1 POLL_INTERVAL_SECONDS=15 SLACK_API_BASE=http://localhost:4071/api SLACK_BOT_TOKEN=xoxb-test-token SLACK_CHANNEL=#it-alerts AUDIT_STDOUT=false; exec node server.js >>$LOG 2>&1 ) & LASTPID=$!; PIDS+=($!); }
signin() { curl -s "$M/_user?email=$2&name=$(echo "$3" | sed 's/ /%20/g')&groups=$4" >/dev/null; rm -f "$1"; curl -s -L -c "$1" -b "$1" -o /dev/null -w "%{http_code}" "$U/login"; }
inj() { local a=(); for kv in "$@"; do a+=(--data-urlencode "$kv"); done; curl -s -G "$MOCK/_inject" "${a[@]}" >/dev/null; }
feed() { curl -s -b $J/admin $U/api/alerts/feed; }
fcount() { feed | jq_ "j.alerts.filter(a=>$1).length"; }
posts() { curl -s $SL/_posts | jq_ 'j.posts.length'; }
mkf() { echo '{"cats":[],"results":[],"apps":[],"include":"'$1'","exclude":"","person":""}'; }
ready() { [ "$(curl -s -b $J/admin $U/api/status | jq_ 'j.lastPollOk?1:0' 2>/dev/null)" = "1" ]; }
caught() { [ "$(curl -s -b $J/admin $U/api/status | jq_ 'j.catchingUp' 2>/dev/null)" = "false" ]; }

start; sleep 3.5
signin $J/admin admin@x.test "Ann Admin" sightline-admins >/dev/null; signin $J/user user@x.test "Una User" sightline-users >/dev/null
waitfor 30 ready
echo "--- sharing alerts, with Slack routing ---"
V=$(curl -s -b $J/admin $U/api/policy | jq_ 'j.meta.version')
check "before anything is shared, the server checks nothing"         null "$(curl -s -b $J/admin $U/api/policy | jq_ 'JSON.stringify(j.alertRules)')"
EF=$(mkf ""); RULES='[
{"id":"r-boom","name":"Boom errors","type":"spike","enabled":true,"filter":'"$(mkf BOOMTEST)"',"n":3,"by":"total","windowMin":60,"cooldownMin":60,"slack":true,"channel":"#err-alerts"},
{"id":"r-new","name":"Brand new errors","type":"new","enabled":true,"filter":'"$EF"',"n":1,"by":"total","windowMin":30,"cooldownMin":60,"slack":false},
{"id":"r-sup","name":"Hidden errors","type":"spike","enabled":true,"filter":'"$(mkf SUPPRESSME)"',"n":2,"by":"total","windowMin":60,"cooldownMin":5,"slack":false}]'
put() { curl -s -b $J/admin -X PUT -H "$H" -d "{\"baseVersion\":$1,\"rules\":$2,\"why\":\"$3\"}" $U/api/policy/alert-rules; }
check "a Slack channel that does not look like one is refused"       'does not look right' "$(put $V '[{"id":"x","name":"x","type":"spike","slack":true,"channel":"not a channel!"}]' 'Testing the channel check here')"
check "a regular user cannot share alerts (403)"                      403 "$(code -b $J/user -X PUT -H "$H" -d "{\"baseVersion\":$V,\"rules\":$RULES,\"why\":\"Trying as a user\"}" $U/api/policy/alert-rules)"
P=$(put $V "$RULES" 'Shared alerts for the team'); check "an admin shares three alerts" '"count":3' "$P"
S=$(curl -s -b $J/admin $U/api/policy)
check "... they are marked as shared with everyone"                   true "$(echo "$S" | jq_ 'j.meta.alertRulesShared===true')"
check "... and each keeps its Slack setting (channel and on/off)"     true "$(echo "$S" | jq_ 'j.alertRules.find(r=>r.id==="r-boom").slack===true && j.alertRules.find(r=>r.id==="r-boom").channel==="#err-alerts" && j.alertRules.find(r=>r.id==="r-new").slack===false')"
check "a regular user sees the shared alerts and where they go"       '"channel":"#err-alerts"' "$(curl -s -b $J/user $U/api/policy)"
V=$(echo "$S" | jq_ 'j.meta.version')
echo "--- waiting for old history to finish loading (the new-error and silent checks wait for it) ---"
waitfor 120 caught; check "history has loaded"                        true "$(curl -s -b $J/admin $U/api/status | jq_ '!j.catchingUp')"
sleep 32
check "the server has been checking (its status says when)"           true "$(curl -s -b $J/admin $U/api/status | jq_ '!!j.alerts.lastRun')"
check "nothing matches yet, so the Boom alert has not fired"          0 "$(fcount 'a.ruleId=="r-boom"')"
P0=$(posts)

echo "--- errors arrive: the server raises the alert and posts it to Slack ---"
inj type=application.provision.user.push result=FAILURE reason="BOOMTEST push failed" user=x@x.test app=ServiceNow n=3
waitfor 60 '[ "$(fcount "a.ruleId==\"r-boom\"")" -ge 1 ]'
check "three matching errors raise one alert, without anyone opening the page" 1 "$(fcount 'a.ruleId=="r-boom"')"
A=$(feed | jq_ 'JSON.stringify(j.alerts.find(a=>a.ruleId==="r-boom"))')
check "... with a title, a plain-words body, a type and a severity"    true "$(echo "$A" | node -pe "const a=JSON.parse(require('fs').readFileSync(0));a.title==='Boom errors'&&/3 errors in the last hour/.test(a.body)&&a.type==='spike'&&a.severity==='warn'&&a.link.view==='errors'")"
waitfor 30 '[ "$(posts)" -gt "$P0" ]'; sleep 1
SP=$(curl -s $SL/_posts)
check "it is posted to the channel the alert is routed to"            '"channel":"#err-alerts"' "$SP"
check "... with its title, its words, its severity and a link back"   true "$(echo "$SP" | jq_ 'j.posts.some(p=>p.channel==="#err-alerts"&&/Boom errors/.test(p.text)&&/3 errors in the last hour/.test(p.raw)&&/Severity: \*Medium\*/.test(p.raw)&&/http:\/\/localhost:8070\/#\/errors/.test(p.raw))')"
check "... and the alert records that it was posted"                   '"state":"sent"' "$(feed | jq_ 'JSON.stringify(j.alerts.find(a=>a.ruleId==="r-boom").slack)')"
check "it is in the audit log, raised by Sightline itself"             true "$(curl -s -b $J/admin "$U/api/audit?action=alert.fired" | jq_ 'j.rows.some(r=>r.target==="Boom errors"&&r.actor.name==="sightline"&&r.cat==="alerts")')"
check "a regular user can see the alert in the feed too"               true "$(curl -s -b $J/user $U/api/alerts/feed | jq_ 'j.alerts.some(a=>a.ruleId==="r-boom")')"

echo "--- it does not repeat ---"
N1=$(posts); inj type=application.provision.user.push result=FAILURE reason="BOOMTEST push failed again" user=y@x.test app=ServiceNow n=3
sleep 50
check "more matching errors inside the cooldown raise nothing more"    1 "$(fcount 'a.ruleId=="r-boom"')"
check "... and nothing more is posted to Slack for it"                 "$N1" "$(posts)"

echo "--- a new kind of error, not routed to Slack ---"
inj type=application.provision.user.push result=FAILURE reason="UNIQUEKIND-$RANDOM never seen before" user=z@x.test app=Zoom
waitfor 60 '[ "$(fcount "a.ruleId==\"r-new\"&&/UNIQUEKIND/.test(a.body)")" -ge 1 ]'
check "it is called new, by the server, in plain words"               true "$(feed | jq_ 'j.alerts.some(a=>a.ruleId==="r-new"&&a.type==="new"&&/^New: UNIQUEKIND/.test(a.body))')"
check "... and, not being routed to Slack, it says so and posts nothing" true "$(feed | jq_ 'j.alerts.filter(a=>a.ruleId==="r-new"&&/UNIQUEKIND/.test(a.body)).every(a=>a.slack.state==="off")')"
check "... no message went to Slack for it"                            "$N1" "$(posts)"

echo "--- changing the routing ---"
RULES2=$(echo "$RULES" | node -pe "const r=JSON.parse(require('fs').readFileSync(0));r[1].slack=true;r[1].channel='#new-errors';JSON.stringify(r)")
C=$(put $V "$RULES2" 'Send new kinds of error to their own channel'); check "an admin switches the new-error alert on for Slack, in its own channel" '"count":3' "$C"
check "... recorded as a change to that alert"                          true "$(curl -s -b $J/admin "$U/api/audit?action=alertrule.update" | jq_ 'j.rows.some(r=>r.target==="r-new"&&/own channel/.test(r.why))')"
check "... and the other alerts were not recorded as changed"            1 "$(curl -s -b $J/admin "$U/api/audit?action=alertrule.update" | jq_ 'j.rows.length')"
V=$(curl -s -b $J/admin $U/api/policy | jq_ 'j.meta.version')
inj type=application.provision.user.push result=FAILURE reason="SECONDKIND-$RANDOM also never seen" user=z@x.test app=Zoom
waitfor 60 '[ "$(fcount "a.ruleId==\"r-new\"&&/SECONDKIND/.test(a.body)")" -ge 1 ]'; waitfor 25 '[ "$(curl -s $SL/_posts | jq_ "j.posts.filter(p=>p.channel===\"#new-errors\").length")" -ge 1 ]'
check "the next new kind of error is posted to the new channel"         true "$(curl -s $SL/_posts | jq_ 'j.posts.some(p=>p.channel==="#new-errors"&&/SECONDKIND/.test(p.raw))')"

echo "--- a known-error rule: hidden errors do not count ---"
SUP=$(curl -s -b $J/admin -X POST -H "$H" -d "{\"baseVersion\":$V,\"rule\":{\"name\":\"Hide SUPPRESSME\",\"match\":{\"include\":\"SUPPRESSME\"},\"why\":\"Expected while we test the alerts\"}}" $U/api/policy/suppressions)
SID=$(echo "$SUP" | jq_ 'j.result.id'); V=$(echo "$SUP" | jq_ 'j.meta.version'); check "an admin hides those errors with a known-error rule" '"id":"s-' "$(echo "$SUP" | jq_ 'JSON.stringify(j.result)')"
inj type=application.provision.user.push result=FAILURE reason="SUPPRESSME broke" user=s@x.test app=Okta n=3
sleep 50
check "three errors that are hidden by a known-error rule raise nothing" 0 "$(fcount 'a.ruleId=="r-sup"')"
D=$(curl -s -b $J/admin -X DELETE "$U/api/policy/suppressions/$SID?v=$V&why=no+longer+needed"); check "the known-error rule is removed" "$SID" "$(echo "$D" | jq_ 'j.result.id')"
waitfor 60 '[ "$(fcount "a.ruleId==\"r-sup\"")" -ge 1 ]'
check "the same errors now count, and the alert is raised"              1 "$(fcount 'a.ruleId=="r-sup"')"

echo "--- a restart repeats nothing ---"
N2=$(fcount true); PN=$(posts); kill -TERM $LASTPID; sleep 2; start; sleep 3.5; signin $J/admin admin@x.test "Ann Admin" sightline-admins >/dev/null; waitfor 30 ready; sleep 45
check "the alerts are still there after the restart"                   true "$(feed | jq_ "j.alerts.length>=$N2")"
check "... the same alerts were not raised again"                       "$N2" "$(fcount true)"
check "... and nothing was posted to Slack again"                       "$PN" "$(posts)"
check "the shared alerts are still shared, with their routing"          true "$(curl -s -b $J/admin $U/api/policy | jq_ 'j.meta.alertRulesShared===true&&j.alertRules.find(r=>r.id==="r-new").channel==="#new-errors"')"

echo "--- secrets stay secret ---"
LEAK=0; for u in $U/api/status $U/api/policy $U/api/alerts/feed $U/api/slack; do curl -s -b $J/admin $u | grep -q "xoxb-test-token" && LEAK=$((LEAK+1)); done
check "the Slack token is in no API answer"                             0 "$LEAK"
check "... and not in the server log"                                   0 "$(grep -c 'xoxb-test-token' $LOG)"

echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
