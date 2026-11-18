#!/usr/bin/env bash
# WiFi Analyzer Pro — Linux / Raspberry Pi source setup.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$SCRIPT_DIR/.venv"

command -v node >/dev/null 2>&1 || { echo "[!] Install Node.js 22 or newer: https://nodejs.org/"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[!] Install Python 3."; exit 1; }
NODE_MAJOR="$(node -p 'Number(process.versions.node.split(".")[0])')"
if (( NODE_MAJOR < 22 )); then
  echo "[!] Node.js 22 or newer is required (found $(node --version))."
  exit 1
fi

printf '\n[1/4] Installing frontend dependencies...\n'
cd "$ROOT_DIR"
npm ci --no-audit --no-fund
printf '\n[2/4] Building the frontend...\n'
npm run build
printf '\n[3/4] Creating an isolated Python environment...\n'
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -r "$SCRIPT_DIR/requirements.txt"
rm -rf "$SCRIPT_DIR/dist"
cp -R "$ROOT_DIR/dist" "$SCRIPT_DIR/dist"
printf '\n[4/4] Starting WiFi Analyzer Pro...\n'
echo "Open http://127.0.0.1:199 in your browser."
echo "The service binds to loopback by default. For trusted-LAN access, set WIFI_ANALYZER_HOST=0.0.0.0 and use a firewall plus an authenticated reverse proxy or VPN."
exec "$VENV_DIR/bin/python" "$SCRIPT_DIR/server.py"
