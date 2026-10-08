#!/usr/bin/env bash
# Offline validation; no Google credentials or tenant access.
set -euo pipefail
cd "$(dirname "$0")/.."
TF=${TF:-terraform}
TMP_CHECK=$(mktemp -d)
trap 'rm -rf "$TMP_CHECK"' EXIT
negative() {
  local status=0
  "$@" >"$TMP_CHECK/negative.txt" 2>&1 || status=$?
  cat "$TMP_CHECK/negative.txt"
  [ "$status" -eq 1 ] || { echo "Negative control must fail validation with exit 1, got $status"; return 1; }
  echo 'PASS: negative control rejected'
}
python3 tools/yaral_lint.py detections/secops/*.yaral
for file in tools/tests/*.yaral; do negative python3 tools/yaral_lint.py "$file"; done
python3 tools/sql_check.py
for file in tools/tests/*.sql; do negative python3 tools/sql_check.py "$file"; done
python3 tools/wf_check.py workflows/*.yaml
python3 -m py_compile functions/*/main.py
python3 - <<'PY'
import json
from pathlib import Path
for path in Path('register').glob('*.json'):
    json.loads(path.read_text())
print('PASS: register JSON and Python compilation')
PY
"$TF" -chdir=deploy/terraform fmt -check -recursive
"$TF" -chdir=deploy/terraform init -backend=false -input=false -lockfile=readonly
"$TF" -chdir=deploy/terraform validate -no-color
if [ "${CHECK_URLS:-0}" = 1 ]; then python3 tools/url_check.py; fi
echo 'ALL CHECKS PASSED'
