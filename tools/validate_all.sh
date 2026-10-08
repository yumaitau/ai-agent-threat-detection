#!/usr/bin/env bash
# Cloud credentials are not needed. Install the pinned tools before running.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/node_modules/.bin:$PATH"
export NODE_PATH="$PWD/node_modules${NODE_PATH:+:$NODE_PATH}"
for cmd in python3 node terraform bicep cfn-lint asl-validator; do
  command -v "$cmd" >/dev/null || { echo "Missing tool: $cmd" >&2; exit 1; }
done
mkdir -p artifacts
python3 tools/check_repository.py
bash microsoft/tools/validate_all.sh 2>&1 | tee artifacts/microsoft-validation.txt
bash aws/tools/validate_all.sh 2>&1 | tee artifacts/aws-validation.txt
bash google/tools/validate_all.sh 2>&1 | tee artifacts/google-validation.txt
printf '\nAll platform offline checks passed. No live tenant validation was performed.\n'
