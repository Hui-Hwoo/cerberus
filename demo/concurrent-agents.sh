#!/usr/bin/env bash
# Concurrent multi-agent demo for Cerberus.
# Four agents hit the policy gate AT THE SAME TIME:
#   agent-docs-1 -> push docs/concurrent (docs/guide.md)        => ALLOW
#   agent-be-1   -> push feat/concurrent (src/api/server.ts)    => ALLOW
#   agent-be-1   -> push feat/concurrent (+ src/auth/jwt.ts)    => DENY (smuggle)
#   agent-docs-1 -> push main            (docs/x.md)            => DENY (protect-main)
# Then the two allowed agents push for real, in parallel.
# Audit-log timestamps prove the decisions interleaved.
#
# Usage: WORKER=... DOCS_KEY=... BE_KEY=... ./demo/concurrent-agents.sh
set -u
: "${WORKER:?set WORKER}" "${DOCS_KEY:?set DOCS_KEY}" "${BE_KEY:?set BE_KEY}"
: "${REMOTE:=https://2b00c6926d2e1bc296c1b04416a508fb.artifacts.cloudflare.net/git/cerberus/cerberus-demo.git}"

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

echo "=== Phase 1: four agents mint concurrently ==="
curl -s -X POST "$WORKER/v1/token" -H "Authorization: Bearer $DOCS_KEY" \
  -H "content-type: application/json" \
  -d '{"taskId":"conc-docs-ok","action":"push","repo":"cerberus-demo","branch":"docs/concurrent","paths":["docs/guide.md"]}' \
  > "$OUT/a1.json" &
curl -s -X POST "$WORKER/v1/token" -H "Authorization: Bearer $BE_KEY" \
  -H "content-type: application/json" \
  -d '{"taskId":"conc-be-ok","action":"push","repo":"cerberus-demo","branch":"feat/concurrent","paths":["src/api/server.ts"]}' \
  > "$OUT/a2.json" &
curl -s -X POST "$WORKER/v1/token" -H "Authorization: Bearer $BE_KEY" \
  -H "content-type: application/json" \
  -d '{"taskId":"conc-be-smuggle","action":"push","repo":"cerberus-demo","branch":"feat/concurrent","paths":["src/api/server.ts","src/auth/jwt.ts"]}' \
  > "$OUT/a3.json" &
curl -s -X POST "$WORKER/v1/token" -H "Authorization: Bearer $DOCS_KEY" \
  -H "content-type: application/json" \
  -d '{"taskId":"conc-docs-main","action":"push","repo":"cerberus-demo","branch":"main","paths":["docs/x.md"]}' \
  > "$OUT/a4.json" &
wait

python3 - "$OUT" <<'EOF'
import json,sys,glob
labels={"a1.json":"docs-agent -> docs/concurrent","a2.json":"be-agent -> feat/concurrent",
        "a3.json":"be-agent smuggle src/auth","a4.json":"docs-agent -> main"}
for f in ["a1.json","a2.json","a3.json","a4.json"]:
    d=json.load(open(f"{sys.argv[1]}/{f}"))
    print(f"{labels[f]:32s} allowed={str(d['allowed']):5s} reason={d.get('reason','-')[:60]}")
EOF

T1=$(python3 -c "import json;print(json.load(open('$OUT/a1.json')).get('token',''))")
T2=$(python3 -c "import json;print(json.load(open('$OUT/a2.json')).get('token',''))")
if [ -z "$T1" ] || [ -z "$T2" ]; then echo "FATAL: allowed mint did not return a token"; exit 1; fi

echo "=== Phase 2: the two allowed agents push concurrently ==="
push_one() { # $1 token $2 branch $3 file $4 content
  local dir="$OUT/repo-$2"
  git -c http.extraHeader="Authorization: Bearer $1" clone -q "$REMOTE" "$dir" 2>/dev/null
  ( cd "$dir" && git checkout -qb "$2" 2>/dev/null || git checkout -q "$2"
    mkdir -p "$(dirname "$3")" && echo "$4" > "$3"
    git add -A && git -c user.email=a@x -c user.name=a commit -qm "concurrent push $(date +%s)" >/dev/null
    git -c http.extraHeader="Authorization: Bearer $1" push -q origin "$2" 2>&1 | tail -1
    echo "pushed $2" )
}
push_one "$T1" "docs/concurrent" "docs/guide.md" "# Guide $(date)" > "$OUT/p1.log" 2>&1 &
push_one "$T2" "feat/concurrent" "src/api/server.ts" "// api $(date)" > "$OUT/p2.log" 2>&1 &
wait
cat "$OUT"/p1.log "$OUT"/p2.log

echo "=== Phase 3: audit log proves interleaving (newest first) ==="
curl -s "$WORKER/v1/decisions?limit=6" | python3 -c "
import json,sys,datetime
d=json.load(sys.stdin)
for it in d['decisions']:
    ts=datetime.datetime.fromtimestamp(it['ts']/1000).strftime('%H:%M:%S.%f')[:-3]
    task=it['req'].get('taskId','?')
    if task.startswith('conc-'):
        print(f\"{ts}  {task:18s} allowed={str(it['decision']['allowed']):5s} agent={it['req']['agentId']}\")"
