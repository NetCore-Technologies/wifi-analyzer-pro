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
  --name wifi-analyzer-pro \
  --distpath build/binary \
  --workpath build/work \
  --specpath build \
  --add-data "dist:dist" \
  server.py

echo "[+] Built: $SCRIPT_DIR/build/binary/wifi-analyzer-pro"
echo "[+] The executable includes the web UI and Python runtime."
echo "[+] Run ./build/binary/wifi-analyzer-pro and browse to http://127.0.0.1:199"
