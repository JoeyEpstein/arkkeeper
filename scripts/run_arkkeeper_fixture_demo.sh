#!/usr/bin/env bash
set -euo pipefail

# Determine repository root relative to this script
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Step 1: Ensure virtual environment exists
if [ ! -d .venv ]; then
  echo "[1/6] Creating virtual environment (.venv)"
  python3 -m venv .venv
else
  echo "[1/6] Using existing virtual environment (.venv)"
fi

# shellcheck disable=SC1091
source .venv/bin/activate

# Step 2: Install/upgrade dependencies quietly but surface warnings
echo "[2/6] Installing project dependencies"
if ! pip install --upgrade pip >/dev/null; then
  echo "    [warn] Unable to upgrade pip (continuing)" >&2
fi
if ! pip install -r requirements.txt >/dev/null; then
  echo "    [warn] Dependency installation failed. Install manually with: pip install -r requirements.txt" >&2
fi

# Verify required modules are available before continuing.
missing_modules="$(python <<'PY'
import importlib.util
modules = ["click", "yaml", "rich", "jinja2", "icalendar", "dateutil"]
missing = [m for m in modules if importlib.util.find_spec(m) is None]
print(",".join(missing))
PY
)"

if [ -n "$missing_modules" ]; then
  echo "[error] Missing Python modules: $missing_modules" >&2
  echo "[error] Install dependencies with: pip install -r requirements.txt" >&2
  exit 1
fi

export PYTHONPATH="$REPO_ROOT/src"

# Step 3: Run the SSH-focused test suite for confidence
echo "[3/6] Running pytest against SSH scanner tests"
pytest tests/test_ssh.py -q

# Step 4: Build a temporary HOME directory with the same fixtures used by the tests
fixture_home="$(mktemp -d "${TMPDIR:-/tmp}/arkkeeper_fixture.XXXXXX")"
trap 'rm -rf "$fixture_home"' EXIT

mkdir -p "$fixture_home/.ssh"

cat <<'KEY' > "$fixture_home/.ssh/id_rsa"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JpTgxxu8dQw7K6GMQZFjKvH+LsgS05nuTMekUCJ6xr
test_key_content_not_real
-----END RSA PRIVATE KEY-----
KEY
chmod 644 "$fixture_home/.ssh/id_rsa"

cat <<'KEY' > "$fixture_home/.ssh/id_dsa"
-----BEGIN DSA PRIVATE KEY-----
test_dsa_key
-----END DSA PRIVATE KEY-----
KEY
chmod 600 "$fixture_home/.ssh/id_dsa"

cat <<'CFG' > "$fixture_home/.ssh/config"
Host example.com
    PasswordAuthentication yes
    StrictHostKeyChecking no
    Ciphers 3des-cbc,aes256-cbc
CFG

# Step 5: Run Arkkeeper scan using the fixture HOME
output_dir="$REPO_ROOT/arkkeeper_outputs/fixture_demo"
mkdir -p "$output_dir"

echo "[4/6] Initializing Arkkeeper configuration inside fixture HOME"
HOME="$fixture_home" python -m ark.cli init >/dev/null

echo "[5/6] Running Arkkeeper scan against fixture data"
HOME="$fixture_home" python -m ark.cli scan --category ssh --out "$output_dir"

echo "[6/6] Rendering terminal report"
HOME="$fixture_home" python -m ark.cli report --format terminal --input "$output_dir/findings.json"

echo "\nResults written to: $output_dir"
echo "Temporary HOME removed: $fixture_home"
