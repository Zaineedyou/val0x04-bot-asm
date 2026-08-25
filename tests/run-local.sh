#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${PORT:-18080}"

cd "$root"
make clean
make all
make test-crypto
file build/val0x04-asm | grep -F 'statically linked'
! readelf -d build/val0x04-asm | grep -Fq 'NEEDED'

PORT="$port" BRIDGE_WEBSOCKET_AUTH_TOKEN=bridge-test PANEL_ACCESS_TOKEN=panel-test \
  ./build/val0x04-asm >/tmp/val0x04-asm-test.log 2>&1 &
pid=$!
cleanup() {
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT
sleep 1

health="$(curl --http1.1 --silent --show-error --max-time 3 -i "http://127.0.0.1:${port}/health")"
printf '%s\n' "$health" | grep -F 'HTTP/1.1 200 OK'
printf '%s\n' "$health" | grep -F '{"status":"ok","runtime":"pure-assembly"}'

unauthorized="$(curl --http1.1 --silent --show-error --max-time 3 -i -X POST "http://127.0.0.1:${port}/api/chat" -d test)"
printf '%s\n' "$unauthorized" | grep -F 'HTTP/1.1 401 Unauthorized'

accepted="$(curl --http1.1 --silent --show-error --max-time 3 -i -X POST -H 'Authorization: Bearer panel-test' "http://127.0.0.1:${port}/api/chat" -d test)"
printf '%s\n' "$accepted" | grep -F 'HTTP/1.1 501 Not Implemented'

PORT="$port" python3 tests/ws_smoke.py
printf '%s\n' 'All local release checks passed.'
