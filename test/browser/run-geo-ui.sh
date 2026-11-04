#!/usr/bin/env bash
# Browser test for the Location alerts section of the Alerts page (rules, preview, Slack, live alerts in the bell).
#   one time:  cd test/browser && npm install && npx playwright install chromium
#   then:      bash test/browser/run-geo-ui.sh        (screenshots go to $SHOTS, default /tmp/sightline-shots)
cd "$(dirname "$0")/../.."
PIDS=(); D=$(mktemp -d); D2=$(mktemp -d); cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$D" "$D2"; }; trap cleanup EXIT
MOCK_GEO=1 node test/mock-okta.js >/dev/null 2>&1 & PIDS+=($!)
node test/mock-slack.js >/dev/null 2>&1 & PIDS+=($!)
( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t PORT=8090 DATA_DIR=$D POLL_INTERVAL_SECONDS=15 AUDIT_STDOUT=false SLACK_API_BASE=http://localhost:4071/api SLACK_BOT_TOKEN=xoxb-test-token SLACK_CHANNEL=#it-alerts SLACK_LINK_URL=http://sightline.test
  exec node server.js >/tmp/geo-ui-server.log 2>&1 ) & PIDS+=($!)
# a second copy with NO Slack settings, to see what a first-time setup looks like
( export OKTA_ORG_URL=http://localhost:4010 OKTA_API_TOKEN=t PORT=8091 DATA_DIR=$D2 POLL_INTERVAL_SECONDS=15 AUDIT_STDOUT=false; exec node server.js >/tmp/geo-ui-server2.log 2>&1 ) & PIDS+=($!)
sleep 4
cd test/browser && NODE_PATH="${NODE_PATH:-$(npm root -g 2>/dev/null)}" node geo-ui.js "${SHOTS:-/tmp/sightline-shots}"
