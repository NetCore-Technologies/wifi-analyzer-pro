#!/usr/bin/env bash
# Run the standalone Linux binary built by build_arm64_binary.sh.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/build/binary/wifi-analyzer-pro"
if [[ ! -x "$BINARY" ]]; then
  echo "[!] Binary not found: $BINARY"
  echo "[!] Run: bash $SCRIPT_DIR/build_arm64_binary.sh"
  exit 1
fi
exec "$BINARY" "$@"
