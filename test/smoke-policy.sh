#!/usr/bin/env bash
# Policy: shared known-error rules and Google app decisions, with reasons, expiry, versions, roles and an audit log.
#   bash test/smoke-policy.sh
cd "$(dirname "$0")/.."
PIDS=(); cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$D1" "$D2" 2>/dev/null; }; trap cleanup EXIT
pass=0; fail=0
check() { if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected '$2', got '$3')"; fail=$((fail+1)); fi; }
jq_() { node -pe "const j=JSON.parse(require('fs').readFileSync(0));$1"; }
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
J='content-type: application/json'
D1=$(mktemp -d); D2=$(mktemp -d)
node test/mock-okta.js >/dev/null 2>&1 & PIDS+=($!)
start() { ( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t "$@"; exec node server.js >>/tmp/policy-server.log 2>&1 ) & PIDS+=($!); }
start PORT=8071 DATA_DIR=$D1
sleep 3.5; U=localhost:8071

echo "--- a fresh start ---"
S=$(curl -s $U/api/policy)
check "starts empty at version 0"                              '"version":0' "$S"
check "says the rules are being saved to disk"                 '"persistent":true' "$S"
check "anyone signed in can edit when no roles are configured" '"canEdit":true' "$S"
check "says roles are not enforced"                            '"rolesEnforced":false' "$S"

echo "--- creating a known-error rule ---"
R='{"baseVersion":0,"rule":{"name":"ServiceNow password sync","match":{"include":"Failed to update user password","apps":["ServiceNow UD"]},"why":"Expected: the AD password policy rejects reused passwords. Tracked in the ticket.","ticket":"IT-1234","expiresAt":"'$(node -pe 'new Date(Date.now()+60*864e5).toISOString()')'"}}'
C=$(curl -s -X POST -H "$J" -H "x-sightline-name: Dana Admin" -d "$R" $U/api/policy/suppressions)
check "a valid rule is created"                                '"id":"s-' "$(echo "$C" | jq_ 'JSON.stringify(j.result)')"
check "... the version moved on"                               1 "$(echo "$C" | jq_ 'j.meta.version')"
check "... it is attributed to the name given"                 "Dana Admin" "$(echo "$C" | jq_ 'j.result.createdBy')"
check "... and marked as NOT verified (a typed name proves nothing)" false "$(echo "$C" | jq_ 'j.result.createdVerified')"
ID=$(echo "$C" | jq_ 'j.result.id')
check "... it keeps the reason, the ticket and the expiry"      true "$(echo "$C" | jq_ 'j.result.why.length>20&&j.result.ticket==="IT-1234"&&!!j.result.expiresAt&&j.result.enabled===true')"

echo "--- the guardrails ---"
check "a change with no name is refused when sign-in cannot say who it is" 400 "$(code -X POST -H "$J" -d '{"rule":{"match":{"include":"anything"},"why":"A proper reason for this exception."}}' $U/api/policy/suppressions)"
check "... and the message says why"                           "audit log can say who" "$(curl -s -X POST -H "$J" -d '{"rule":{"match":{"include":"anything"},"why":"A proper reason for this exception."}}' $U/api/policy/suppressions)"
check "a name made only of odd characters is not a name"        400 "$(code -X POST -H "$J" -H "x-sightline-name: <<>>" -d '{"rule":{"match":{"include":"anything"},"why":"A proper reason for this exception."}}' $U/api/policy/suppressions)"
post() { curl -s -o /tmp/pol-body -w "%{http_code}" -X POST -H "$J" -H "x-sightline-name: Test User" -d "$1" $U/api/policy/suppressions; }
check "no reason -> refused"                                   400 "$(post '{"rule":{"match":{"include":"x error"}}}')"
check "a one-word reason -> refused (say WHY)"                 400 "$(post '{"rule":{"match":{"include":"x error"},"why":"ok"}}')"
check "... and the message says what is wrong"                 "Say why" "$(cat /tmp/pol-body)"
check "no condition at all -> refused (it would hide everything)" 400 "$(post '{"rule":{"match":{},"why":"hide everything please, thanks"}}')"
check "only 'failed' as the condition -> refused too"          400 "$(post '{"rule":{"match":{"results":["FAILURE"]},"why":"hide all the failures please"}}')"
check "only 'hide words' as the condition -> refused too"      400 "$(post '{"rule":{"match":{"exclude":"a"},"why":"hide all the failures please"}}')"
check "an expiry in the past -> refused"                       400 "$(post '{"rule":{"match":{"include":"x error"},"why":"a good enough reason","expiresAt":"2020-01-01"}}')"
check "an expiry that is not a date -> refused"                400 "$(post '{"rule":{"match":{"include":"x error"},"why":"a good enough reason","expiresAt":"someday"}}')"
check "an expiry decades away -> refused"                      400 "$(post '{"rule":{"match":{"include":"x error"},"why":"a good enough reason","expiresAt":"2090-01-01"}}')"
check "broken JSON -> refused cleanly"                         400 "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$J" -d '{nope' $U/api/policy/suppressions)"
check "stale version -> 409 conflict"                          409 "$(post '{"baseVersion":0,"rule":{"match":{"include":"another error"},"why":"a good enough reason"}}')"
check "... which hands back the current policy to reload"      '"suppressions":[' "$(cat /tmp/pol-body)"
check "nothing was added by the refused attempts"              1 "$(curl -s $U/api/policy | jq_ 'j.suppressions.length')"

echo "--- changing and removing ---"
V=$(curl -s $U/api/policy | jq_ 'j.meta.version')
U1=$(curl -s -X PUT -H "$J" -H "x-sightline-name: Sam Admin" -d '{"baseVersion":'$V',"patch":{"enabled":false}}' $U/api/policy/suppressions/$ID)
check "a rule can be switched off"                             false "$(echo "$U1" | jq_ 'j.result.enabled')"
check "... and the change is attributed"                       "Sam Admin" "$(echo "$U1" | jq_ 'j.result.updatedBy')"
check "an unknown rule -> 404"                                 404 "$(code -X PUT -H "$J" -H "x-sightline-name: Test User" -d '{"patch":{"enabled":true}}' $U/api/policy/suppressions/s-nope)"
V=$(curl -s $U/api/policy | jq_ 'j.meta.version')
check "a rule can be deleted"                                  "$ID" "$(curl -s -X DELETE -H "x-sightline-name: Sam Admin" "$U/api/policy/suppressions/$ID?v=$V&why=no+longer+needed" | jq_ 'j.result.id')"
check "... and it is gone"                                     0 "$(curl -s $U/api/policy | jq_ 'j.suppressions.length')"

echo "--- approving and flagging Google apps ---"
A='{"approval":{"clientId":"111-acme.apps.googleusercontent.com","appName":"Acme CRM Sync","status":"approved","scopes":["openid","https://www.googleapis.com/auth/userinfo.email"],"why":"Reviewed by security: read-only sign-in only.","ticket":"SEC-77","expiresAt":"'$(node -pe 'new Date(Date.now()+300*864e5).toISOString()')'"}}'
check "an app can be approved for the access it has today"     approved "$(curl -s -X POST -H "$J" -H "x-sightline-name: Dana Admin" -d "$A" $U/api/policy/approvals | jq_ 'j.result.status')"
check "... the approval remembers exactly which scopes it covers" 2 "$(curl -s $U/api/policy | jq_ 'j.approvals[0].scopes.length')"
check "approving needs a reason too"                           400 "$(code -X POST -H "$J" -H "x-sightline-name: Test User" -d '{"approval":{"clientId":"x","status":"approved","why":"no"}}' $U/api/policy/approvals)"
check "a decision must be approved or flagged"                 400 "$(code -X POST -H "$J" -H "x-sightline-name: Test User" -d '{"approval":{"clientId":"x","status":"maybe","why":"a good enough reason"}}' $U/api/policy/approvals)"
check "an app can be flagged as not allowed (no expiry kept)"  flagged "$(curl -s -X POST -H "$J" -H "x-sightline-name: Dana Admin" -d '{"approval":{"clientId":"222-bad.apps.googleusercontent.com","appName":"Bad App","status":"flagged","why":"Not on the approved vendor list.","expiresAt":"2030-01-01"}}' $U/api/policy/approvals | jq_ 'j.result.status')"
check "... and a re-decision replaces, it does not duplicate"  2 "$(curl -s -X POST -H "$J" -H "x-sightline-name: Dana Admin" -d "$A" $U/api/policy/approvals >/dev/null; curl -s $U/api/policy | jq_ 'j.approvals.length')"
V=$(curl -s $U/api/policy | jq_ 'j.meta.version')
check "a decision can be removed"                              222-bad "$(curl -s -X DELETE -H "x-sightline-name: Dana Admin" "$U/api/policy/approvals/222-bad.apps.googleusercontent.com?v=$V&why=vendor+approved" | jq_ 'j.result.clientId')"

echo "--- the audit log ---"
AU=$(curl -s "$U/api/policy/audit?limit=50")
check "every change is in the audit log, newest first"         true "$(echo "$AU" | jq_ 'j.rows.length>=6&&j.rows.every((r,i)=>i===0||j.rows[i-1].ts>=r.ts)')"
check "... with who, what and why"                             true "$(echo "$AU" | jq_ 'j.rows.every(r=>r.actor&&r.action&&"verified" in r)&&j.rows.some(r=>r.action==="suppression.create"&&r.actor==="Dana Admin"&&r.why.length>10)')"
check "... including the removals, with the reason given"      true "$(echo "$AU" | jq_ 'j.rows.some(r=>r.action==="suppression.delete"&&r.why==="no longer needed")&&j.rows.some(r=>r.action==="app.remove")')"
check "... and switching a rule off is recorded as that"       suppression.disable "$(echo "$AU" | jq_ 'JSON.stringify(j.rows.map(r=>r.action))')"
check "... the old and new versions of a change are kept"      true "$(echo "$AU" | jq_ 'j.rows.some(r=>r.action==="suppression.disable"&&r.before&&r.after&&r.before.enabled===true&&r.after.enabled===false)')"

echo "--- it survives a restart ---"
kill ${PIDS[-1]}; sleep 1
start PORT=8071 DATA_DIR=$D1; sleep 3.5
S2=$(curl -s $U/api/policy)
check "after a restart the app decisions are still there"       1 "$(echo "$S2" | jq_ 'j.approvals.length')"
check "... and the version carries on"                          true "$(echo "$S2" | jq_ 'j.meta.version>=6')"
check "... and so does the audit log"                           true "$(curl -s "$U/api/policy/audit" | jq_ 'j.rows.length>=7')"
check "the policy file is on disk, readable"                    approvals "$(cat $D1/policy.json)"

echo "--- roles, identity and forged headers ---"
start PORT=8072 DATA_DIR=$D2 USER_HEADER=x-forwarded-email POLICY_ADMINS=boss@x.test; sleep 3.5; V2=localhost:8072
newrule='{"rule":{"match":{"include":"some error"},"why":"A proper reason for this exception."}}'
check "behind a trusted proxy header, roles ARE enforced"       '"rolesEnforced":true' "$(curl -s $V2/api/policy)"
check "a visitor with no identity can look but not edit"        '"canEdit":false' "$(curl -s $V2/api/policy)"
check "... and cannot write"                                    403 "$(code -X POST -H "$J" -d "$newrule" $V2/api/policy/suppressions)"
check "someone who is not an administrator cannot write"        403 "$(code -X POST -H "$J" -H "x-forwarded-email: other@x.test" -d "$newrule" $V2/api/policy/suppressions)"
check "an administrator can"                                    201 "$(code -X POST -H "$J" -H "x-forwarded-email: boss@x.test" -d "$newrule" $V2/api/policy/suppressions)"
check "... and is recorded as VERIFIED"                         true "$(curl -s "$V2/api/policy/audit" | jq_ 'j.rows[0].actor==="boss@x.test"&&j.rows[0].verified===true')"
check "administrators are matched ignoring upper/lower case"    201 "$(code -X POST -H "$J" -H "x-forwarded-email: BOSS@X.TEST" -d '{"rule":{"match":{"include":"second error"},"why":"A proper reason for this one too."}}' $V2/api/policy/suppressions)"
check "typing a name does not make you an administrator"        403 "$(code -X POST -H "$J" -H "x-sightline-name: boss@x.test" -d "$newrule" $V2/api/policy/suppressions)"
start PORT=8073 DATA_DIR=$D2 POLICY_ADMINS=boss@x.test; sleep 3.5
check "a FORGED proxy header is ignored when none is configured" false "$(curl -s -H 'x-forwarded-email: boss@x.test' localhost:8073/api/policy | jq_ 'j.meta.actor.verified')"
check "admins listed without a proxy header: not enforced, and it says so" '"rolesEnforced":false' "$(curl -s localhost:8073/api/policy)"
check "... and the server log explains why"                     "POLICY_ADMINS is set but USER_HEADER is not" "$(cat /tmp/policy-server.log)"

echo "--- every exception must expire (an organisation setting) ---"
start PORT=8074 DATA_DIR=$(mktemp -d) POLICY_REQUIRE_EXPIRY=true; sleep 3.5
check "with the setting on, a rule with no expiry is refused"   400 "$(code -X POST -H "$J" -H "x-sightline-name: Test User" -d "$newrule" localhost:8074/api/policy/suppressions)"
check "... and one with an expiry is accepted"                  201 "$(code -X POST -H "$J" -H "x-sightline-name: Test User" -d '{"rule":{"match":{"include":"some error"},"why":"A proper reason for this exception.","expiresAt":"'$(node -pe 'new Date(Date.now()+30*864e5).toISOString()')'"}}' localhost:8074/api/policy/suppressions)"
check "... and the page is told the setting is on"              '"requireExpiry":true' "$(curl -s localhost:8074/api/policy)"

echo "--- when the data folder cannot be written ---"
echo "i am a file, not a folder" > /tmp/pol-notadir
start PORT=8075 DATA_DIR=/tmp/pol-notadir/sub; sleep 3.5
NS=$(curl -s localhost:8075/api/policy)
check "it still starts, and says changes will NOT be kept"      '"persistent":false' "$NS"
check "... with the reason"                                     "not writable" "$NS"
check "... and still works in memory"                           201 "$(code -X POST -H "$J" -H "x-sightline-name: Test User" -d "$newrule" localhost:8075/api/policy/suppressions)"

echo "--- the door ---"
start PORT=8076 DATA_DIR=$(mktemp -d) DASHBOARD_PASSWORD=secret; sleep 3.5
check "reading the policy needs the password"                   401 "$(code localhost:8076/api/policy)"
check "writing needs it too"                                    401 "$(code -X POST -H "$J" -d "$newrule" localhost:8076/api/policy/suppressions)"
check "the audit log needs it"                                  401 "$(code localhost:8076/api/policy/audit)"
check "with the password it works"                              200 "$(code -u admin:secret localhost:8076/api/policy)"
echo "  (many quick changes)"
n429=0; for i in $(seq 1 70); do c=$(code -u admin:secret -X POST -H "$J" -d '{"rule":{"match":{}}}' localhost:8076/api/policy/suppressions); [ "$c" = "429" ] && n429=$((n429+1)); done
check "a flood of changes is slowed down (429)"                 true "$([ $n429 -ge 5 ] && echo true || echo false)"

echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
