#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/opt/seclens-collectors"
PROFILE_PATH="${PROFILE_PATH:-profiles/default.json}"

cd "$REPO_ROOT"

# Load local env file if present
if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi

mkdir -p logs .state

exec "$REPO_ROOT/.venv/bin/python" "$REPO_ROOT/run_collectors.py" --profile "$PROFILE_PATH"
