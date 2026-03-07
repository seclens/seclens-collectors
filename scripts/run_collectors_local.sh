#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/Users/mbp01/.openclaw/workspace/projects/feishu/oc_35d5f08682d81fad2bb51484c351aacd/repos/seclens-collectors"
PROFILE_PATH="${PROFILE_PATH:-profiles/seclens_new_sources.local.json}"

cd "$REPO_ROOT"

if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi

mkdir -p logs .state
exec "$REPO_ROOT/.venv/bin/python" "$REPO_ROOT/run_collectors.py" --profile "$PROFILE_PATH"
