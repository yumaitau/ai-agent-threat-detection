#!/usr/bin/env bash
# Offline parse and schema checks. No Azure credentials or tenant access.
set -euo pipefail
cd "$(dirname "$0")/.."
BICEP=${BICEP:-bicep}
command -v "$BICEP" >/dev/null
node -e "require.resolve('@kusto/language-service-next')" >/dev/null
TMP_CHECK=$(mktemp -d)
export TMP_CHECK
trap 'rm -rf "$TMP_CHECK"' EXIT
negative() {
  local status=0
  "$@" >"$TMP_CHECK/negative.txt" 2>&1 || status=$?
  cat "$TMP_CHECK/negative.txt"
  [ "$status" -eq 1 ] || { echo "Negative control must fail validation with exit 1, got $status"; return 1; }
  echo 'PASS: negative control rejected'
}
echo 'KQL: offline parse and semantic bind against bundled table schemas'
python3 tools/make_prelude.py
PRELUDE=tools/prelude.generated.kql node tools/kqlcheck.js tools/schemas.json detections/*.kql functions/*.kql deploy/workbook/queries/*.kql
python3 - <<'PY'
import json, os
from pathlib import Path
root = Path(os.environ['TMP_CHECK'])
cols = json.load(open('deploy/register/AIAgentRegister_CL.columns.json'))
(root/'schema.json').write_text(json.dumps({'source': {'cols': [[c['name'], c['type'], ''] for c in cols]}}))
def find(obj):
    if isinstance(obj, dict):
        if 'transformKql' in obj:
            return obj['transformKql']
        children = obj.values()
    elif isinstance(obj, list):
        children = obj
    else:
        return None
    for child in children:
        result = find(child)
        if result:
            return result
query = find(json.load(open('deploy/register-infra.json')))
assert query, 'Missing DCR transform'
(root/'transform.kql').write_text(query+'\n')
PY
node tools/kqlcheck.js "$TMP_CHECK/schema.json" "$TMP_CHECK/transform.kql"
for file in tools/tests/*.kql; do negative node tools/kqlcheck.js tools/schemas.json "$file"; done
python3 - <<'PY'
import csv, json
from pathlib import Path
files = list(Path('deploy').rglob('*.json'))
for path in files:
    json.loads(path.read_text())
for path in Path('deploy/register').glob('*.csv'):
    rows = list(csv.reader(path.open()))
    assert rows and all(len(row) == len(rows[0]) for row in rows), path
print(f'PASS: {len(files)} JSON files and register CSVs')
PY
for file in deploy/bicep/*.bicep; do
  "$BICEP" build "$file" --stdout > /dev/null
  echo "PASS: Bicep build $file"
done
# Verify unified deploy/azuredeploy.json stays in sync with deploy/bicep/main.bicep (ignoring Bicep version metadata)
"$BICEP" build deploy/bicep/main.bicep --outfile "$TMP_CHECK/azuredeploy.built.json"
python3 - <<'PY'
import json, os
from pathlib import Path
built = json.loads((Path(os.environ['TMP_CHECK']) / 'azuredeploy.built.json').read_text())
committed = json.loads(Path('deploy/azuredeploy.json').read_text())
for doc in (built, committed):
    doc.pop('metadata', None)
assert built == committed, 'deploy/azuredeploy.json is out of sync with deploy/bicep/main.bicep; rebuild with bicep build'
print('PASS: deploy/azuredeploy.json matches deploy/bicep/main.bicep')
PY
# Validate Microsoft Sentinel Content Hub V3 Solution layout, YAML schemas, ARM templates and Defender XDR rules
python3 tools/validate_sentinel_solution.py --extract-kql-dir "$TMP_CHECK/extracted-kql"
PRELUDE=tools/prelude.generated.kql node tools/kqlcheck.js tools/schemas.json "$TMP_CHECK"/extracted-kql/*.kql
# Decompilation checks ARM structure, not Logic Apps workflow semantics.
for file in deploy/analytics-rule-*.json deploy/automation-rule-*.json deploy/playbook-*.json ../Solutions/YumaAIAgentThreatDetection/Playbooks/*/azuredeploy.json; do
  dest="$TMP_CHECK/$(echo "$file" | tr '/.' '__').json"
  cp "$file" "$dest"
  "$BICEP" decompile "$dest" --force
  echo "PASS: ARM decompile $file"
done
echo 'ALL CHECKS PASSED'
