#!/usr/bin/env bash
# Run every offline check in the pack. Writes nothing outside a temp dir except deploy/validation.txt when called
# with --write. Needs: python3 (sqlglot, boto3/botocore, pyyaml), cfn-lint, terraform, asl-validator (npm), curl/network
# for urlcheck and terraform init. Tool paths can be overridden with CFN_LINT, TERRAFORM, ASL_VALIDATOR.
set -uo pipefail
cd "$(dirname "$0")/.."
CFN_LINT=${CFN_LINT:-cfn-lint}
TERRAFORM=${TERRAFORM:-terraform}
ASL_VALIDATOR=${ASL_VALIDATOR:-asl-validator}
for cmd in python3 "$CFN_LINT" "$TERRAFORM" "$ASL_VALIDATOR"; do
  command -v "$cmd" >/dev/null || exit 1
done
TMP_CHECK=$(mktemp -d)
export TMP_CHECK
trap 'rm -rf "$TMP_CHECK"' EXIT
fail=0
step() { echo; echo "=== $1"; }
expect_ok()   { if "$@"; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fail=1; fi; }
expect_fail() { if "$@" >"$TMP_CHECK/neg.out" 2>&1; then echo "RESULT: FAIL (negative control passed)"; fail=1; else tail -3 "$TMP_CHECK/neg.out"; echo "RESULT: PASS (negative control failed as expected)"; fi; }

step "JSON parse (all .json files)"
expect_ok python3 -c "
import json,pathlib,sys
fs=[f for f in pathlib.Path('.').rglob('*.json') if '.terraform' not in f.parts and 'bad-asl' not in f.name]
[json.loads(f.read_text()) for f in fs]; print(len(fs),'files parsed')"

step "Python compile (Lambdas and tools)"
expect_ok python3 -c "
import py_compile,pathlib
fs=list(pathlib.Path('playbooks/lambda').glob('*.py'))+list(pathlib.Path('tools').glob('*.py'))
[py_compile.compile(str(f),doraise=True,cfile=__import__('os').environ['TMP_CHECK']+'/_pyc') for f in fs]; print(len(fs),'files compiled')"

step "SQL: sqlglot parse + documented-field check"
expect_ok python3 tools/sqlcheck.py detections/*.sql register/athena-register.sql
step "SQL negative controls"
for f in tools/tests/bad-*.sql; do echo "-- $f"; expect_fail python3 tools/sqlcheck.py "$f"; done

step "Logs Insights lint"
expect_ok python3 tools/lilint.py detections/*.logsinsights
step "Logs Insights negative controls"
for f in tools/tests/bad-*.logsinsights; do echo "-- $f"; expect_fail python3 tools/lilint.py "$f"; done
step "Dashboard log widget queries"
expect_ok python3 tools/dashlint.py

step "EventBridge patterns vs sample events"
expect_ok python3 tools/ebmatch.py detections

step "API names vs botocore models"
expect_ok python3 tools/apicheck.py

step "Lambda unit tests (botocore Stubber)"
expect_ok python3 tools/test_lambdas.py

step "Step Functions ASL"
expect_ok "$ASL_VALIDATOR" --json-path playbooks/asl/PB1-agent-containment.asl.json
echo "-- negative control"; expect_fail "$ASL_VALIDATOR" --json-path tools/tests/bad-asl.json

step "CloudFormation: template is up to date with build_cfn.py"
expect_ok bash -c 'python3 tools/build_cfn.py --stdout > "$TMP_CHECK/cfn-regen.yaml" && diff -q "$TMP_CHECK/cfn-regen.yaml" deploy/cfn/yuma-aia-core.yaml'
step "CloudFormation: cfn-lint"
"$CFN_LINT" --version
expect_ok "$CFN_LINT" deploy/cfn/yuma-aia-core.yaml
echo "-- negative control"; expect_fail "$CFN_LINT" tools/tests/bad-cfn.yaml

step "Terraform: init (no backend), validate, fmt"
"$TERRAFORM" version | head -2
expect_ok "$TERRAFORM" -chdir=deploy/terraform/pb3-waf-block init -backend=false -input=false -lockfile=readonly
expect_ok "$TERRAFORM" -chdir=deploy/terraform/pb3-waf-block validate -no-color
expect_ok "$TERRAFORM" -chdir=deploy/terraform/pb3-waf-block fmt -check

if [ "${CHECK_URLS:-0}" = 1 ]; then
  step "Cited URLs return HTTP 200 (needs network)"
  expect_ok python3 tools/urlcheck.py
fi

step "Style check: no em dashes"
expect_ok python3 -c "from pathlib import Path; files=[p for p in Path('.').rglob('*') if p.is_file() and not set(p.parts) & {'.terraform', '__pycache__', 'build', 'dist'}]; assert all(chr(0x2014) not in p.read_text() for p in files)"

echo
if [ $fail -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit $fail
