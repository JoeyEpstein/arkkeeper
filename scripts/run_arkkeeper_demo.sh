#!/usr/bin/env bash
set -euo pipefail

# Determine repository root relative to this script, even if invoked via symlink.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Create virtual environment if it doesn't exist.
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

# Activate the environment for the remainder of the script.
# shellcheck disable=SC1091
source .venv/bin/activate

# Upgrade pip and install project dependencies (best effort for offline environments).
if ! pip install --upgrade pip >/dev/null; then
  echo "[warn] Unable to upgrade pip (continuing with existing version)." >&2
fi

if ! pip install -r requirements.txt >/dev/null; then
  echo "[warn] Dependency installation failed. Ensure requirements are installed manually." >&2
fi

# Verify that core dependencies are importable before continuing.
missing_modules="$(python <<'PY'
import importlib.util
modules = ["click", "yaml", "rich", "jinja2", "icalendar", "dateutil"]
missing = [m for m in modules if importlib.util.find_spec(m) is None]
print(",".join(missing))
PY
)"

if [ -n "$missing_modules" ]; then
  echo "[error] Missing Python modules: $missing_modules" >&2
  echo "[error] Install them with: pip install -r requirements.txt" >&2
  exit 1
fi

# Ensure the src/ layout is importable when invoking python -m.
export PYTHONPATH="$REPO_ROOT/src"

# Run Arkkeeper commands end-to-end.
python -m ark.cli selftest
python -m ark.cli init
python -m ark.cli scan --out "$REPO_ROOT/arkkeeper_outputs"
python -m ark.cli report --format terminal --input "$REPO_ROOT/arkkeeper_outputs/findings.json"
