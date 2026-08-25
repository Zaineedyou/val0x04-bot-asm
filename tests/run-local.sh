#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${PORT:-$((18000 + RANDOM % 1000))}"

cd "$root"
make clean
make all
make test-crypto
make source-ratio | tee /tmp/val0x04-source-ratio.txt
grep -Eq 'NASM: [0-9]+ lines \(([7-9][0-9]|100)\.' /tmp/val0x04-source-ratio.txt
file build/val0x04-asm | grep -F 'dynamically linked'
ldd build/val0x04-asm | grep -F 'libcurl'

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
printf '%s\n' "$health" | grep -F '"runtime":"assembly-dominant"'

unauthorized="$(curl --http1.1 --silent --show-error --max-time 3 -i -X POST "http://127.0.0.1:${port}/api/chat" -d test)"
printf '%s\n' "$unauthorized" | grep -F 'HTTP/1.1 401 Unauthorized'

secure_failure="$(curl --http1.1 --silent --show-error --max-time 3 -i -X POST -H 'Authorization: Bearer panel-test' "http://127.0.0.1:${port}/api/chat" -d test)"
printf '%s\n' "$secure_failure" | grep -F 'HTTP/1.1 502 Bad Gateway'
printf '%s\n' "$secure_failure" | grep -F 'Discord transport rejected the request'

PORT="$port" python3 tests/ws_smoke.py
printf '%s\n' 'All local release checks passed.'
