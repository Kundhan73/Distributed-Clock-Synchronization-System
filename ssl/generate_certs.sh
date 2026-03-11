#!/bin/bash
# generate_certs.sh
# Run from the project root: bash ssl/generate_certs.sh
# Or from the ssl/ folder:   bash generate_certs.sh

# Find ssl/ directory relative to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY="$SCRIPT_DIR/server.key"
CRT="$SCRIPT_DIR/server.crt"

echo "[SSL] Generating self-signed certificate..."

openssl req -x509 -newkey rsa:2048 \
  -keyout "$KEY" \
  -out    "$CRT" \
  -days   365    \
  -nodes         \
  -subj "/CN=ClockSyncServer/O=ClockSync/C=IN"

echo ""
echo "[SSL] Done!"
echo "  Key:  $KEY"
echo "  Cert: $CRT"
