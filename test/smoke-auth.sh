#!/usr/bin/env bash
# Okta single sign-on, roles and the audit log, against a fake OpenID Connect provider.
#   bash test/smoke-auth.sh        (about a minute and a half)
cd "$(dirname "$0")/.."
PIDS=(); D1=$(mktemp -d); D2=$(mktemp -d); D3=$(mktemp -d); J=$(mktemp -d)
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$D1" "$D2" "$D3" "$J"; }; trap cleanup EXIT
pass=0; fail=0
check() { if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected '$2', got '$3')"; fail=$((fail+1)); fi; }
jq_() { node -pe "const j=JSON.parse(require('fs').readFileSync(0));$1"; }
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
H='content-type: application/json'; U=localhost:8060; M=localhost:4061
SECRET="a-long-random-session-secret-for-tests-0123456789"
node test/mock-okta.js >/dev/null 2>&1 & PIDS+=($!)
MOCK_OIDC_PORT=4061 MOCK_OIDC_REDIRECT=http://localhost:8060/callback,http://localhost:8062/callback,http://localhost:8064/callback,http://localhost:8065/callback node test/mock-oidc.js >/dev/null 2>&1 & PIDS+=($!)
sleep 1.2
BASE="OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t OIDC_ISSUER=http://localhost:4061 OIDC_CLIENT_ID=0oaTEST OIDC_CLIENT_SECRET=s3cret-value SESSION_SECRET=$SECRET OIDC_OWNER_GROUPS=sightline-owners OIDC_ADMIN_GROUPS=sightline-admins OIDC_USER_GROUPS=sightline-users DASHBOARD_PASSWORD=shared-pass"
start() { local port=$1 dir=$2; shift 2; ( export $BASE PORT=$port PUBLIC_URL=http://localhost:$port DATA_DIR=$dir "$@"; exec node server.js >>/tmp/auth-$port.log 2>&1 ) & PIDS+=($!); sleep 3.2; }
signin() { curl -s "$M/_user?email=$2&name=$(echo "$3" | sed 's/ /%20/g')&groups=$4" >/dev/null; rm -f "$1"; curl -s -L -c "$1" -b "$1" -o /dev/null -w "%{http_code}" "$U/login"; }
me() { curl -s -b "$1" $U/api/me; }
mode() { curl -s "$M/_mode?m=$1" >/dev/null; }
start 8060 $D1 AUDIT_STDOUT=true

echo "--- the front door ---"
check "a page request without a session is sent to sign in"          "location: /login?next=%2f" "$(curl -s -D - -o /dev/null $U/ | tr -d '\r' | tr 'A-Z' 'a-z')"
check "an API request without a session is refused (401)"             401 "$(code $U/api/status)"
check "... and says where to sign in"                                '"login":"/login"' "$(curl -s $U/api/status)"
check "the health check stays open (so Coolify can see it)"          200 "$(code $U/healthz)"
check "the logo files stay open (the sign-in pages use them)"        200 "$(code $U/favicon.svg)"
L=$(curl -s -D - -o /dev/null -c $J/x $U/login | tr -d '\r'); LOC=$(echo "$L" | grep -i '^location:' | sed 's/^[Ll]ocation: //')
check "/login sends you to the provider"                             "http://localhost:4061/authorize?" "$LOC"
for k in "response_type=code" "client_id=0oaTEST" "redirect_uri=http%3A%2F%2Flocalhost%3A8060%2Fcallback" "code_challenge_method=S256" "scope=openid+profile+email+groups"; do check "... with $k" "$k" "$LOC"; done
check "... a state and a nonce"                                      "state=" "$LOC"; check "... and a PKCE challenge"  "code_challenge=" "$LOC"
check "the login cookie is HttpOnly, SameSite=Lax"                   "HttpOnly; SameSite=Lax" "$(echo "$L" | grep -i '^set-cookie: sl_login')"
node -e 'const {safeNext:s}=require("./auth.js"); const o=[s("//evil.example"),s("https://evil.example"),s("/\\evil"),s("/ok?x=1"),s("javascript:alert(1)"),s("/login"),s(undefined),s("/a\r\nSet-Cookie: x=1")]; console.log(JSON.stringify(o))' > $J/next.txt
check "the page you return to can only be on this site (no open redirect)" '["/","/","/","/ok?x=1","/","/","/","/"]' "$(cat $J/next.txt)"

echo "--- signing in, and what role you get ---"
check "an owner signs in (lands on the page)"                        200 "$(signin $J/owner owner@x.test "Olivia Owner" sightline-owners,sightline-users)"
check "... /api/me says who they are and that they are an owner"     '"role":"owner"' "$(me $J/owner)"; check "... through Okta, not the password" '"via":"oidc"' "$(me $J/owner)"; check "... by email" '"email":"owner@x.test"' "$(me $J/owner)"
check "an admin signs in"                                            200 "$(signin $J/admin admin@x.test "Adam Admin" sightline-admins)"; check "... and is an admin" '"role":"admin"' "$(me $J/admin)"
check "a user signs in"                                              200 "$(signin $J/user user@x.test "Una User" sightline-users)"; check "... and is a user" '"role":"user"' "$(me $J/user)"
check "someone in two groups gets the HIGHER role"                   '"role":"owner"' "$(signin $J/two a@x.test "Two Groups" sightline-users,sightline-owners >/dev/null; me $J/two)"
check "someone in none of the groups is refused (403)"               403 "$(signin $J/nobody nobody@x.test "No Body" some-other-group)"
check "... and gets no session"                                      401 "$(code -b $J/nobody $U/api/me)"
check "groups can arrive through the userinfo call when the token lacks them" '"role":"admin"' "$(mode nogroups; signin $J/ui ui@x.test "Via Userinfo" sightline-admins >/dev/null; me $J/ui)"
mode ok
check "the provider really checked PKCE and the client secret (no failures)" '"pkceFailed":0' "$(curl -s $M/_stats)"
mkdir -p $J/h; L1=$(curl -s -D - -o /dev/null -c $J/s1 -b $J/s1 $U/login | tr -d '\r'); LOC1=$(echo "$L1" | grep -i '^location:' | sed 's/^[Ll]ocation: //'); curl -s "$M/_user?email=hdr@x.test&name=Hdr&groups=sightline-users" >/dev/null
CB=$(curl -s -D - -o /dev/null "$LOC1" | tr -d '\r' | grep -i '^location:' | sed 's/^[Ll]ocation: //'); LC=$(curl -s -D - -o /dev/null -b $J/s1 "$CB" | tr -d '\r')
check "the session cookie is HttpOnly, SameSite=Lax, with a lifetime"  "HttpOnly; SameSite=Lax; Max-Age=43200" "$(echo "$LC" | grep -i '^set-cookie: sl_sid')"
check "... and the sign-in returns to the page you wanted"           "ocation: /" "$LC"

echo "--- attacks on the sign-in ---"
STATE=$(echo "$LOC1" | sed 's/.*state=\([^&]*\).*/\1/'); LCK=$(echo "$L1" | grep -i '^set-cookie: sl_login' | sed 's/^[^:]*: //; s/;.*//')
check "reusing a sign-in link a second time is refused"              400 "$(code -H "Cookie: $LCK" "$CB")"
check "a callback from a browser that never started the sign-in is refused" 400 "$(code "$U/callback?code=abc&state=$STATE")"
L2=$(curl -s -D - -o /dev/null -c $J/s2 $U/login | tr -d '\r'); LOC2=$(echo "$L2" | grep -i '^location:' | sed 's/^[Ll]ocation: //'); CB2=$(curl -s -D - -o /dev/null "$LOC2" | tr -d '\r' | grep -i '^location:' | sed 's/^[Ll]ocation: //')
check "a sign-in started in one browser cannot be finished in another" 400 "$(code "$CB2")"
check "a tampered state is refused"                                  400 "$(code -b $J/s2 "$(echo "$CB2" | sed 's/state=\([^&]*\)/state=\1x/')")"
for spec in "badaud:different application" "badiss:different issuer" "badnonce:nonce" "expired:expired" "badsig:signature" "noemail:email address"; do m=${spec%%:*}; w=${spec#*:}
  mode $m; rm -f $J/bad; curl -s "$M/_user?email=bad@x.test&name=Bad&groups=sightline-owners" >/dev/null; B=$(curl -s -L -c $J/bad -b $J/bad -w "|%{http_code}" "$U/login")
  check "a token with a bad '$m' is refused (403, says why)"         "$w" "$B"; check "... and no session is created"  401 "$(code -b $J/bad $U/api/me)"; done
mode error; rm -f $J/bad; check "a refusal from the provider is shown calmly (400)" 400 "$(curl -s -L -c $J/bad -b $J/bad -o /dev/null -w "%{http_code}" $U/login)"; mode ok
check "a made-up session cookie is refused"                          401 "$(code -H "Cookie: sl_sid=abc.def" $U/api/me)"
SID=$(grep sl_sid $J/owner | awk '{print $7}' | sed 's/%2E/./; s/\..*//')
check "a real session id with a forged signature is refused"         401 "$(code -H "Cookie: sl_sid=$SID.forgedforgedforgedforgedforgedforgedforgedforg" $U/api/me)"
check "a real session id with NO signature is refused"               401 "$(code -H "Cookie: sl_sid=$SID" $U/api/me)"

echo "--- what each role may do ---"
RULE='{"rule":{"match":{"include":"some error"},"why":"A proper reason for this exception."}}'; V=$(curl -s -b $J/user $U/api/policy | jq_ 'j.meta.version')
check "a user can SEE the policy"                                    200 "$(code -b $J/user $U/api/policy)"; check "... and sees that they cannot change it" '"canEdit":false' "$(curl -s -b $J/user $U/api/policy)"
check "a user cannot create a known-error rule (403)"                403 "$(code -b $J/user -X POST -H "$H" -d "$RULE" $U/api/policy/suppressions)"
check "a user cannot read the audit log (403)"                       403 "$(code -b $J/user $U/api/audit)"; check "... nor the policy history behind it (403)" 403 "$(code -b $J/user $U/api/policy/audit)"; check "... or the access settings (403)" 403 "$(code -b $J/user $U/api/access)"
check "a user cannot change alert rules (403)"                       403 "$(code -b $J/user -X PUT -H "$H" -d '{"rules":[]}' $U/api/policy/alert-rules)"
check "an admin sees that they can change things"                    '"canEdit":true' "$(curl -s -b $J/admin $U/api/policy)"
check "an admin can create a rule, with NO name to type (it is verified)" 201 "$(code -b $J/admin -X POST -H "$H" -d "$RULE" $U/api/policy/suppressions)"
check "... recorded under their Okta email"                          '"createdBy":"admin@x.test"' "$(curl -s -b $J/admin $U/api/policy)"; check "... as verified" '"createdVerified":true' "$(curl -s -b $J/admin $U/api/policy)"
check "an admin can read the audit log"                              200 "$(code -b $J/admin $U/api/audit)"; check "... and the policy history" 200 "$(code -b $J/admin $U/api/policy/audit)"; check "... but not the access settings (owner only)" 403 "$(code -b $J/admin $U/api/access)"
V=$(curl -s -b $J/admin $U/api/policy | jq_ 'j.meta.version'); R1='{"id":"r-one","name":"Many failures","type":"spike","enabled":true,"filter":{"cats":["provision"]},"n":10,"windowMin":60,"by":"app","cooldownMin":60}'
check "an admin can publish shared alert rules"                      200 "$(code -b $J/admin -X PUT -H "$H" -d '{"baseVersion":'$V',"rules":['"$R1"']}' $U/api/policy/alert-rules)"
check "... and everyone, a user too, then gets those rules"          '"name":"Many failures"' "$(curl -s -b $J/user $U/api/policy)"
check "a stale version is refused (409) so two admins cannot clash"  409 "$(code -b $J/admin -X PUT -H "$H" -d '{"baseVersion":'$V',"rules":[]}' $U/api/policy/alert-rules)"
V=$(curl -s -b $J/admin $U/api/policy | jq_ 'j.meta.version')
check "an unknown alert type is refused (400)"                       400 "$(code -b $J/admin -X PUT -H "$H" -d '{"baseVersion":'$V',"rules":[{"id":"x","type":"nonsense"}]}' $U/api/policy/alert-rules)"
check "two rules with the same id are refused (400)"                 400 "$(code -b $J/admin -X PUT -H "$H" -d '{"baseVersion":'$V',"rules":['"$R1"','"$R1"']}' $U/api/policy/alert-rules)"
check "absurd numbers are clamped, not trusted"                      '"windowMin":43200' "$(curl -s -b $J/admin -X PUT -H "$H" -d '{"baseVersion":'$V',"rules":[{"id":"r-one","name":"Many failures","type":"spike","n":9999999,"windowMin":9999999,"cooldownMin":-5}]}' $U/api/policy/alert-rules | jq_ 'JSON.stringify(j.alertRules[0])')"
V=$(curl -s -b $J/admin $U/api/policy | jq_ 'j.meta.version'); OFF=$(curl -s -b $J/admin $U/api/policy | jq_ 'JSON.stringify(j.alertRules.map(r=>({...r,enabled:false})))'); curl -s -b $J/admin -X PUT -H "$H" -d '{"baseVersion":'$V',"rules":'"$OFF"'}' $U/api/policy/alert-rules >/dev/null
check "an owner can open the access settings"                        200 "$(code -b $J/owner $U/api/access)"
ACC=$(curl -s -b $J/owner $U/api/access); check "... which lists the sessions and says which is theirs" true "$(echo "$ACC" | jq_ 'j.sessions.length>=4&&j.sessions.some(s=>s.current&&s.email==="owner@x.test")')"
check "... and shows how roles are decided (the groups), never a secret" true "$(echo "$ACC" | jq_ 'j.ownerGroups[0]==="sightline-owners"&&!JSON.stringify(j).includes("s3cret")&&!JSON.stringify(j).includes("session-secret")')"
AID=$(echo "$ACC" | jq_ 'j.sessions.find(s=>s.email==="admin@x.test").id')
check "an admin cannot end sessions (403)"                           403 "$(code -b $J/admin -X DELETE $U/api/sessions/$AID)"
check "an owner can end someone's session"                           200 "$(code -b $J/owner -X DELETE $U/api/sessions/$AID)"; check "... and that person is signed out at once" 401 "$(code -b $J/admin $U/api/me)"
check "ending a session that is gone says so (404)"                  404 "$(code -b $J/owner -X DELETE $U/api/sessions/$AID)"

echo "--- other sites, and the shared password ---"
check "a request from another site is refused (403)"                 403 "$(code -b $J/owner -X POST -H "$H" -H "Origin: http://evil.example" -d "$RULE" $U/api/policy/suppressions)"
check "... also by the browser's own 'cross-site' signal"            403 "$(code -b $J/owner -X POST -H "$H" -H "Sec-Fetch-Site: cross-site" -d "$RULE" $U/api/policy/suppressions)"
check "a request from this site is fine"                             201 "$(code -b $J/owner -X POST -H "$H" -H "Origin: http://localhost:8060" -H "Sec-Fetch-Site: same-origin" -d "$RULE" $U/api/policy/suppressions)"
check "the shared password gives NO access while sign-in is on"        401 "$(code -u admin:shared-pass $U/api/me)"
check "... and neither does a wrong one"                               401 "$(code -u admin:wrong $U/api/me)"
check "there is no /breakglass page any more: it just goes to sign-in" "ocation: /login" "$(curl -s -D - -o /dev/null $U/breakglass | tr -d '\r')"
check "... and nothing ever asks the browser for a password"            0 "$(curl -s -D - -o /dev/null -u admin:shared-pass $U/breakglass | tr -d '\r' | grep -ci 'www-authenticate')"
check "an Okta session is the only way in (the password adds nothing)"  '"via":"oidc"' "$(curl -s -b $J/owner -u admin:shared-pass $U/api/me)"

echo "--- signing out ---"
LO=$(curl -s -D - -o /dev/null -b $J/user $U/logout | tr -d '\r')
check "sign out goes to the provider's end-session page"             "ocation: http://localhost:4061/logout?id_token_hint=" "$LO"; check "... and comes back to a signed-out page" "post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8060%2Flogged-out" "$LO"
check "... and the session is dead"                                  401 "$(code -b $J/user $U/api/me)"; check "the signed-out page is public" 200 "$(code $U/logged-out)"

echo "--- the audit log ---"
AU=$(curl -s -b $J/owner "$U/api/audit?limit=500")
for a in auth.login auth.denied auth.login.failed auth.logout auth.session.revoked access.denied suppression.create alertrules.publish alertrule.update alertrule.disable; do check "the log has '$a'" "\"action\":\"$a\"" "$(echo "$AU" | jq_ 'j.rows.map(r=>JSON.stringify({action:r.action})).join("")')"; done
check "every sign-in failure is recorded as a failure"               true "$(echo "$AU" | jq_ 'j.rows.filter(r=>r.action==="auth.login.failed").length>=6&&j.rows.filter(r=>r.action==="auth.login.failed").every(r=>r.ok===false)')"
check "rows carry who, their role, where from and what was done"     true "$(echo "$AU" | jq_ 'const r=j.rows.find(r=>r.action==="auth.login"&&r.actor.email==="admin@x.test"); !!r&&r.actor.role==="admin"&&r.actor.verified===true&&r.cat==="auth"&&!!r.ip&&!!r.ua')"
check "a refused request names what was tried and what was needed"   true "$(echo "$AU" | jq_ 'j.rows.some(r=>r.action==="access.denied"&&r.actor.email==="user@x.test"&&/api\/policy\/suppressions/.test(r.target)&&/change it/.test(r.detail))')"
check "an alert-rule change keeps the before and the after"          true "$(echo "$AU" | jq_ 'j.rows.some(r=>r.action==="alertrule.disable"&&r.before.enabled===true&&r.after.enabled===false&&r.actor.email==="admin@x.test")')"
check "the log can be filtered (only sign-in events)"                true "$(curl -s -b $J/owner "$U/api/audit?cat=auth" | jq_ 'j.rows.length>5&&j.rows.every(r=>r.cat==="auth")')"
check "... and by person"                                            true "$(curl -s -b $J/owner "$U/api/audit?actor=admin@x.test" | jq_ 'j.rows.length>2&&j.rows.every(r=>(r.actor.email||"").includes("admin@x.test"))')"
check "events also go to the container log, ready for a log shipper" "AUDIT {" "$(cat /tmp/auth-8060.log)"
check "the log is kept on disk"                                      "auth.login" "$(cat $D1/audit-log.jsonl)"
check "... separate from the policy store's own history file"      false "$([ \"$(grep -c 'auth.login' $D1/audit.jsonl 2>/dev/null)\" != \"0\" ] && [ -f $D1/audit.jsonl ] && echo true || echo false)"
check "the policy's own log still works"                             true "$(curl -s -b $J/owner $U/api/policy/audit | jq_ 'j.rows.length>0')"

echo "--- surviving a redeploy, and timing out ---"
signin $J/keep keep@x.test "Kay Keep" sightline-users >/dev/null; kill ${PIDS[-1]}; sleep 4; start 8060 $D1
check "after a restart the same session still works (nobody is signed out by a redeploy)" '"email":"keep@x.test"' "$(me $J/keep)"
start 8062 $D2 SESSION_IDLE_SECONDS=2 AUDIT_STDOUT=false; U2=localhost:8062; curl -s "$M/_user?email=idle@x.test&name=Idle&groups=sightline-users" >/dev/null; rm -f $J/idle; curl -s -L -c $J/idle -b $J/idle -o /dev/null $U2/login
check "an idle session works at first"                               200 "$(code -b $J/idle $U2/api/me)"; sleep 3.5
check "... and is refused after the idle time"                       401 "$(code -b $J/idle $U2/api/me)"
check "... and the expiry is logged"                                 "auth.session.expired" "$(cat $D2/audit-log.jsonl)"

echo "--- a half-finished setup fails closed ---"
( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t PORT=8063 DATA_DIR=$D3 OIDC_ISSUER=http://localhost:4061 OIDC_CLIENT_ID=0oaTEST PUBLIC_URL=http://localhost:8063 DASHBOARD_PASSWORD=shared-pass; exec node server.js >/tmp/auth-8063.log 2>&1 ) & PIDS+=($!); sleep 3.2; U3=localhost:8063
check "everything is refused (nothing is left open by mistake)"      401 "$(code $U3/api/status)"; check "... the sign-in page says what is missing" "OIDC_CLIENT_SECRET" "$(curl -s $U3/login)"
check "... without printing any value"                               true "$(curl -s $U3/login | node -pe '!require("fs").readFileSync(0,"utf8").includes("0oaTEST")')"
check "the health check still answers"                               200 "$(code $U3/healthz)"; check "the password does NOT unlock it" 401 "$(code -u admin:shared-pass $U3/api/me)"
check "the server log explains it"                                   "Sign-in is NOT enabled: missing OIDC_CLIENT_SECRET" "$(cat /tmp/auth-8063.log)"

echo "--- the real Okta group names: spaces and capitals ---"
D4=$(mktemp -d); ( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t PORT=8064 DATA_DIR=$D4 PUBLIC_URL=http://localhost:8064 OIDC_ISSUER=http://localhost:4061 OIDC_CLIENT_ID=0oaTEST OIDC_CLIENT_SECRET=s3cret-value SESSION_SECRET=$SECRET OIDC_OWNER_GROUPS="Sightline Owners Group" OIDC_ADMIN_GROUPS="Sightline Admin Group" OIDC_USER_GROUPS="Sightline Users group" OWNER_EMAILS="Boot.Owner@X.test"; exec node server.js >/tmp/auth-8064.log 2>&1 ) & PIDS+=($!); sleep 3.2; U4=localhost:8064
sg() { local jar=$1 email=$2 groups=$3; curl -s "$M/_user?email=$email&name=T&groups=$(echo "$groups" | sed 's/ /%20/g')" >/dev/null; rm -f $jar; curl -s -L -c $jar -b $jar -o /dev/null -w "%{http_code}" "$U4/login"; }
sg $J/g1 a@x.test "Sightline Owners Group" >/dev/null; check "'Sightline Owners Group' makes an owner"            '"role":"owner"' "$(curl -s -b $J/g1 $U4/api/me)"
sg $J/g2 b@x.test "Sightline Admin Group" >/dev/null;  check "'Sightline Admin Group' makes an admin"             '"role":"admin"' "$(curl -s -b $J/g2 $U4/api/me)"
sg $J/g3 c@x.test "Sightline Users group" >/dev/null;  check "'Sightline Users group' makes a user"               '"role":"user"' "$(curl -s -b $J/g3 $U4/api/me)"
sg $J/g4 d@x.test "sightline ADMIN group" >/dev/null;  check "capital letters do not matter"                      '"role":"admin"' "$(curl -s -b $J/g4 $U4/api/me)"
sg $J/g5 e@x.test "Some Other Group,Sightline Users group" >/dev/null; check "other groups in the list are ignored"  '"role":"user"' "$(curl -s -b $J/g5 $U4/api/me)"
check "a group that merely contains the word is NOT enough"      403 "$(sg $J/g6 f@x.test "Sightline Owners Group Extra")"
check "an owner named by email gets in before any group is set up"  '"role":"owner"' "$(sg $J/g7 boot.owner@x.test "nothing" >/dev/null; curl -s -b $J/g7 $U4/api/me)"
check "the assistant is open to every role by default"            '"assistantRole":"user"' "$(curl -s -b $J/g3 $U4/api/me)"

echo "--- the shared password is ignored with sign-in on, and REQUIRE_SSO can never be left open ---"
D5=$(mktemp -d); D6=$(mktemp -d); D7=$(mktemp -d)
( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t PORT=8065 DATA_DIR=$D5 PUBLIC_URL=http://localhost:8065 OIDC_ISSUER=http://localhost:4061 OIDC_CLIENT_ID=0oaTEST OIDC_CLIENT_SECRET=s3cret-value SESSION_SECRET=$SECRET OIDC_OWNER_GROUPS="Sightline Owners Group" DASHBOARD_PASSWORD=shared-pass REQUIRE_SSO=true; exec node server.js >/tmp/auth-8065.log 2>&1 ) & PIDS+=($!)
( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t PORT=8066 DATA_DIR=$D6 REQUIRE_SSO=true; exec node server.js >/tmp/auth-8066.log 2>&1 ) & PIDS+=($!)
( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t PORT=8067 DATA_DIR=$D7; exec node server.js >/tmp/auth-8067.log 2>&1 ) & PIDS+=($!); sleep 3.5
U5=localhost:8065; U6=localhost:8066; U7=localhost:8067
check "sign-in on: the shared password is refused, on the API"     401 "$(code -u admin:shared-pass $U5/api/me)"
check "... and on a page request it just goes to Okta"            "ocation: /login" "$(curl -s -D - -o /dev/null -u admin:shared-pass $U5/ | tr -d '\r')"
curl -s "$M/_user?email=ok@x.test&name=Okta%20User&groups=Sightline%20Owners%20Group" >/dev/null; rm -f $J/o5; curl -s -L -c $J/o5 -b $J/o5 -o /dev/null "$U5/login"
check "Okta sign-in works, as the owner"                          '"via":"oidc"' "$(curl -s -b $J/o5 $U5/api/me)"; check "... with the right role" '"role":"owner"' "$(curl -s -b $J/o5 $U5/api/me)"
check "the Access tab has nothing about an emergency login"       0 "$(curl -s -b $J/o5 $U5/api/access | grep -ci 'breakglass')"
check "the server log says the password is ignored"               "DASHBOARD_PASSWORD is set but is ignored" "$(cat /tmp/auth-8065.log)"
check "REQUIRE_SSO with NO sign-in settings: everything is refused (never open)" 401 "$(code $U6/api/status)"
check "... the page says what to set up, without any values"      "OIDC_CLIENT_SECRET" "$(curl -s $U6/login)"
check "... the health check still answers, so the platform stays happy" 200 "$(code $U6/healthz)"
check "... and the server log explains it"                        "REQUIRE_SSO is on" "$(cat /tmp/auth-8066.log)"
check "WITHOUT REQUIRE_SSO and without any settings the app is open (the case REQUIRE_SSO exists to prevent)" '"via":"open"' "$(curl -s $U7/api/me)"

echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
