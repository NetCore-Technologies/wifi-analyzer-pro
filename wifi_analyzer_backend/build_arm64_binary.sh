#!/usr/bin/env bash
# Build a standalone Linux binary for the current Linux CPU architecture.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64|x86_64) ;;
  *) echo "[!] Unsupported architecture: $ARCH"; exit 1 ;;
esac

command -v node >/dev/null 2>&1 || { echo "[!] Install Node.js 22+"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[!] Install Python 3"; exit 1; }
NODE_MAJOR="$(node -p 'Number(process.versions.node.split(".")[0])')"
(( NODE_MAJOR >= 22 )) || { echo "[!] Node.js 22+ is required"; exit 1; }

cd "$ROOT_DIR"
npm ci --no-audit --no-fund
npm run build
cd "$SCRIPT_DIR"
rm -rf dist build
cp -R "$ROOT_DIR/dist" "$SCRIPT_DIR/dist"
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt pyinstaller
.venv/bin/pyinstaller --clean --noconfirm --onefile \
  --collect-submodules feature_plugins \
  --name wifi-analyzer-pro \
  --distpath build/binary \
  --workpath build/work \
  --specpath build \
  --add-data "dist:dist" \
  server.py

SMOKE_PORT="$(.venv/bin/python - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
SMOKE_LOG="$SCRIPT_DIR/build/frozen-smoke.log"
SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wifi-analyzer-pro-smoke.XXXXXX")"
WIFI_ANALYZER_PORT="$SMOKE_PORT" \
WIFI_ANALYZER_AUTH_FILE="$SMOKE_DIR/auth.json" \
WIFI_ANALYZER_HISTORY_DB="$SMOKE_DIR/history.sqlite3" \
  "$SCRIPT_DIR/build/binary/wifi-analyzer-pro" >"$SMOKE_LOG" 2>&1 &
SERVER_PID=$!
cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  rm -rf "$SMOKE_DIR"
}
trap cleanup EXIT

READY=0
for _ in $(seq 1 40); do
  if .venv/bin/python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:$SMOKE_PORT/health', timeout=1)" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.5
done
if [[ "$READY" -ne 1 ]]; then
  cat "$SMOKE_LOG"
  echo "[!] Frozen binary did not become healthy." >&2
  exit 1
fi
WIFI_ANALYZER_SMOKE_URL="http://127.0.0.1:$SMOKE_PORT" .venv/bin/python "$SCRIPT_DIR/smoke_test_frozen_features.py"

echo "[+] Built and verified: $SCRIPT_DIR/build/binary/wifi-analyzer-pro"
echo "[+] The executable includes the web UI, Python runtime and dynamically loaded feature plugins."
echo "[+] Run ./build/binary/wifi-analyzer-pro and browse to http://127.0.0.1:199"
