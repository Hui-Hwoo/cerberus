#!/usr/bin/env bash
# One-command deploy for Cerberus (the permission plane for agentic Git).
#
# What it does:
#   1. Creates (or reuses) the D1 audit database and applies schema.sql
#   2. Patches wrangler.jsonc with the D1 id / namespace / queue name
#   3. Sets POLICY_JSON and generates AGENT_KEYS_JSON secrets
#   4. Creates (or reuses) the Queue and the Artifacts event subscription
#   5. Deploys the Worker and runs a smoke test
#
# Usage:
#   ./setup.sh
#   WORKER_NAME=my-gatekeeper NAMESPACE=my-ns DEMO_REPO=my-repo ./setup.sh
#
# Prereqs: node, wrangler (logged in), openssl, python3.
# Costs: needs Workers Paid ($5/mo) for the Artifacts binding.
set -euo pipefail

WORKER_NAME="${WORKER_NAME:-cerberus-gatekeeper}"
D1_NAME="${D1_NAME:-cerberus-audit}"
QUEUE_NAME="${QUEUE_NAME:-cerberus-events}"
NAMESPACE="${NAMESPACE:-cerberus}"
DEMO_REPO="${DEMO_REPO:-demo-site}"
POLICY_FILE="${POLICY_FILE:-policy.example.json}"
SUB_NAME="${SUB_NAME:-$WORKER_NAME-watch}"

say() { printf '\n==> %s\n' "$*"; }
need() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 1; }; }

say "Preflight"
need wrangler; need openssl; need python3
wrangler whoami >/dev/null || { echo "run: wrangler login"; exit 1; }
[ -f "$POLICY_FILE" ] || { echo "policy file not found: $POLICY_FILE"; exit 1; }
python3 -c "import json; json.load(open('$POLICY_FILE'))" || { echo "policy is not valid JSON"; exit 1; }

say "D1 database ($D1_NAME)"
D1_ID=$(wrangler d1 list --json 2>/dev/null | python3 -c "
import json,sys,os
for d in json.load(sys.stdin):
    if d['name']=='$D1_NAME': print(d['uuid']); break")
if [ -z "${D1_ID:-}" ]; then
  D1_ID=$(wrangler d1 create "$D1_NAME" --json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['uuid'])")
  echo "created D1 $D1_NAME ($D1_ID)"
else
  echo "reusing D1 $D1_NAME ($D1_ID)"
fi
say "Applying schema.sql"
wrangler d1 execute "$D1_NAME" --remote --file schema.sql >/dev/null && echo "schema ok"

say "Patching wrangler.jsonc"
python3 - "$D1_ID" "$NAMESPACE" "$QUEUE_NAME" <<'EOF'
import json,sys,re
p='wrangler.jsonc'
s=open(p).read()
s=re.sub(r'"database_id":\s*"[^"]*"', f'"database_id": "{sys.argv[1]}"', s)
s=re.sub(r'"namespace":\s*"[^"]*"', f'"namespace": "{sys.argv[2]}"', s, count=1)
s=re.sub(r'"queue":\s*"[^"]*"', f'"queue": "{sys.argv[3]}"', s, count=1)
open(p,'w').write(s)
print("wrangler.jsonc patched")
EOF

say "Secrets: POLICY_JSON"
wrangler secret put POLICY_JSON < "$POLICY_FILE" >/dev/null && echo "POLICY_JSON set"

say "Secrets: AGENT_KEYS_JSON (generating fresh keys)"
DOCS_KEY="cbk_$(openssl rand -hex 16)"
BE_KEY="cbk_$(openssl rand -hex 16)"
REL_KEY="cbk_$(openssl rand -hex 16)"
LEAD_KEY="cbk_$(openssl rand -hex 16)"
python3 - "$DOCS_KEY" "$BE_KEY" "$REL_KEY" "$LEAD_KEY" <<'EOF'
import json,sys
dk,bk,rk,lk=sys.argv[1:5]
data={"keys":{
 dk:{"agentId":"agent-docs-1","roles":["docs-writer"]},
 bk:{"agentId":"agent-be-1","roles":["backend-dev"]},
 rk:{"agentId":"agent-rel-1","roles":["release-manager"]},
 lk:{"agentId":"agent-lead-1","roles":["release-manager"],"canApprove":True}}}
json.dump(data,open('keys.local.json','w'),indent=1)
EOF
wrangler secret put AGENT_KEYS_JSON < keys.local.json >/dev/null && echo "AGENT_KEYS_JSON set"

say "Queue ($QUEUE_NAME)"
if wrangler queues list 2>/dev/null | grep -q "$QUEUE_NAME"; then
  echo "reusing queue $QUEUE_NAME"
else
  wrangler queues create "$QUEUE_NAME" >/dev/null && echo "created queue $QUEUE_NAME"
fi

say "Event subscription ($SUB_NAME -> $NAMESPACE/$DEMO_REPO)"
if wrangler queues subscription list "$QUEUE_NAME" 2>/dev/null | grep -q "$SUB_NAME"; then
  echo "reusing subscription $SUB_NAME"
else
  wrangler queues subscription create "$QUEUE_NAME" \
    --source artifacts.repo --source-namespace "$NAMESPACE" \
    --source-repo-name "$DEMO_REPO" \
    --events pushed,token.created,token.revoked \
    --name "$SUB_NAME" && echo "subscription created"
fi

say "Deploy"
DEPLOY_OUT=$(wrangler deploy --name "$WORKER_NAME" 2>&1 | tee /dev/tty | tail -5)
URL=$(echo "$DEPLOY_OUT" | grep -o 'https://[^ ]*workers.dev' | head -1)
[ -n "$URL" ] || { echo "could not parse Worker URL from deploy output"; exit 1; }
say "Smoke test"
SMOKE=$(curl -s -X POST "$URL/v1/token" -H "Authorization: Bearer $DOCS_KEY" \
  -H "content-type: application/json" \
  -d '{"taskId":"setup-smoke","action":"read","repo":"'"$DEMO_REPO"'","paths":["docs/a.md"]}')
echo "$SMOKE" | python3 -c "import json,sys; d=json.load(sys.stdin); print('mint allowed:', d['allowed'])"
VERIFY=$(curl -s "$URL/v1/verify")
echo "$VERIFY" | python3 -c "import json,sys; d=json.load(sys.stdin); print('chain ok:', d['ok'], '| checked:', d['checked'])"

cat <<EOF

Done. Save these keys somewhere safe (also in keys.local.json, gitignored):
  DOCS_KEY=$DOCS_KEY   (agent-docs-1)
  BE_KEY=$BE_KEY       (agent-be-1)
  REL_KEY=$REL_KEY     (agent-rel-1)
  LEAD_KEY=$LEAD_KEY   (agent-lead-1, canApprove)

Worker: $URL
Audit UI: $URL/
Next: create the demo repo (POST /v1/admin/repos needs an isAdmin key —
add one with: wrangler secret put AGENT_KEYS_JSON after editing keys.local.json),
then run ./demo/concurrent-agents.sh
EOF
