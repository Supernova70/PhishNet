#!/usr/bin/env bash
# 5-minute PhishNet demo: import corpus → bulk scan → campaign
# clustering → print deep links (trace, attribution, campaigns,
# forensic report).
#
# Requirements: the API server running (uvicorn app.main:app) and the
# alembic migrations applied. Everything runs offline against
# tests/fixtures/eml — no IMAP or network providers needed.
#
# Usage:  ./scripts/demo.sh            (server at localhost:8000)
#         BASE_URL=http://host:8000 ./scripts/demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."

BASE="${BASE_URL:-http://localhost:8000}"
PY="${PYTHON:-python3}"
CORPUS="tests/fixtures/eml"
POLL_SECONDS="${POLL_SECONDS:-120}"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

say "1/5  Health check at $BASE"
if ! curl -sf "$BASE/health" >/dev/null; then
    echo "Server not reachable. Start it first:" >&2
    echo "    uvicorn app.main:app --reload" >&2
    exit 1
fi

say "2/5  Import corpus ($CORPUS, idempotent)"
"$PY" scripts/import_eml.py "$CORPUS"

say "3/5  Bulk-scan every unscanned email"
RESP=$(curl -sf -X POST "$BASE/emails/bulk-scan" \
    -H 'Content-Type: application/json' -d '{}') || {
    echo "(nothing new to scan — already imported and scanned?)"
    RESP='{"scan_ids":[]}'
}
SCAN_IDS=$("$PY" -c 'import json,sys; print(" ".join(map(str, json.loads(sys.argv[1])["scan_ids"])))' "$RESP")
echo "queued scans: ${SCAN_IDS:-<none>}"

say "4/5  Poll until scans finish (timeout ${POLL_SECONDS}s)"
"$PY" - "$BASE" $SCAN_IDS <<'PYEOF'
import json, sys, time, urllib.request

base, ids = sys.argv[1], [int(i) for i in sys.argv[2:]]
deadline = time.time() + int(__import__("os").environ.get("POLL_SECONDS", "120"))
pending = set(ids)
while pending and time.time() < deadline:
    for sid in list(pending):
        with urllib.request.urlopen(f"{base}/scans/{sid}") as r:
            status = json.load(r)["status"]
        if status in ("complete", "error"):
            pending.discard(sid)
    if pending:
        time.sleep(1)
done = len(ids) - len(pending)
print(f"finished: {done}/{len(ids)}" + (f" (still pending: {sorted(pending)})" if pending else ""))
PYEOF

say "5/5  Recluster campaigns"
curl -sf -X POST "$BASE/campaigns/recluster" | "$PY" -m json.tool || true

# ── deep links ────────────────────────────────────────────────────────
FIRST_EMAIL=$(curl -sf "$BASE/emails?limit=1" | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print(d["emails"][0]["id"] if d.get("emails") else "")' 2>/dev/null || true)
FIRST_SCAN=$(curl -sf "$BASE/scans?limit=1" | "$PY" -c 'import json,sys; d=json.load(sys.stdin); s=d.get("scans") or d.get("items") or []; print(s[0]["id"] if s else "")' 2>/dev/null || true)

say "Demo URLs"
cat <<EOF
  Inbox (scan everything):   $BASE/emails
  Forensic report (JSON):    $BASE/scans/${FIRST_SCAN:-<scan_id>}/report
  Export report (custody):   $BASE/scans/${FIRST_SCAN:-<scan_id>}/report?export=true
  Origin trace:              $BASE/emails/${FIRST_EMAIL:-<email_id>}/trace
  Header forensics:          $BASE/emails/${FIRST_EMAIL:-<email_id>}/headers
  Attribution graph:         $BASE/graph
  Campaigns:                 $BASE/campaigns
  Global alert feed (SSE):   $BASE/scans/events
  Evidence chain:            $BASE/evidence
  Audit log:                 $BASE/audit
  UI (if running):           http://localhost:5173
EOF
