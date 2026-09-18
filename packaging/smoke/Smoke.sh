#!/usr/bin/env bash
# The release smoke test, run against an installed or extracted executable:
#
#   packaging/smoke/Smoke.sh <path to agentsafe> <expected version>
#
# It is the whole first-five-minutes path, asserted: the binary answers its
# version, the boundary test holds, the doctor passes against a loopback
# upstream, the gateway starts, a synthetic request is intercepted and each
# verdict is enforced the way the response headers and the status counts
# say, the process stops cleanly on SIGTERM, and the evidence it wrote
# verifies offline. It exits non-zero on the first expectation that does not
# hold. Node is used only for the loopback upstream; the executable under
# test never needs it.
set -euo pipefail

executable="${1:?path to agentsafe}"
expected_version="${2:?expected version}"
work="$(mktemp -d)"
upstream_pid=""
gateway_pid=""
cleanup() {
  if [ -n "$gateway_pid" ]; then kill -TERM "$gateway_pid" 2>/dev/null || true; wait "$gateway_pid" 2>/dev/null || true; fi
  if [ -n "$upstream_pid" ]; then kill "$upstream_pid" 2>/dev/null || true; wait "$upstream_pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

fail() { echo "SMOKE FAILED: $*" >&2; exit 1; }
free_port() { node -e 'const s=require("net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})'; }

# 1. The binary is the release.
actual_version="$("$executable" version)"
[ "$actual_version" = "$expected_version" ] || fail "version: expected $expected_version, got $actual_version"

# 2. The boundary test holds: nothing adversarial reaches its synthetic
#    target under enforcement, and the evidence it leaves verifies.
"$executable" test --json > "$work/boundary.json" || fail "boundary test exited $?: $(cat "$work/boundary.json")"
grep -q '"verdict":"BOUNDARY_HOLDS"' "$work/boundary.json" || fail "boundary test: $(cat "$work/boundary.json")"
grep -q '"enforcement":0' "$work/boundary.json" || fail "boundary test exposure: $(cat "$work/boundary.json")"

# 3. A loopback upstream that echoes what it receives.
upstream_port="$(free_port)"
node -e '
const http = require("http");
http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    res.writeHead(req.method === "GET" ? 200 : 201, { "content-type": "application/json" });
    res.end(JSON.stringify({ method: req.method, url: req.url, body, dossier: req.headers["x-agent-safe-dossier-id"] ?? null }));
  });
}).listen(Number(process.argv[1]), "127.0.0.1");
' "$upstream_port" &
upstream_pid=$!
for _ in $(seq 1 50); do curl -fs "http://127.0.0.1:$upstream_port/" >/dev/null 2>&1 && break; sleep 0.1; done

# 4. The doctor passes before anything is started.
"$executable" doctor --upstream "http://127.0.0.1:$upstream_port" --json > "$work/doctor.json"
grep -q '"ok":true' "$work/doctor.json" || fail "doctor: $(cat "$work/doctor.json")"

# 5. The gateway starts and says so.
gateway_port="$(free_port)"
AGENTSAFE_EVIDENCE_DIR="$work/evidence" "$executable" proxy \
  --upstream "http://127.0.0.1:$upstream_port" --port "$gateway_port" --json > "$work/gateway.log" 2> "$work/gateway.err" &
gateway_pid=$!
for _ in $(seq 1 100); do curl -fs "http://127.0.0.1:$gateway_port/_agentsafe/readyz" >/dev/null 2>&1 && break; sleep 0.1; done
curl -fs "http://127.0.0.1:$gateway_port/_agentsafe/readyz" >/dev/null || fail "gateway never became ready: $(cat "$work/gateway.log" "$work/gateway.err")"
grep -q '"event":"GATEWAY_STARTED"' "$work/gateway.log" || fail "no GATEWAY_STARTED line"

# 6. One request per verdict, each enforced.
post() { curl -s -o "$work/body" -D "$work/headers" -w '%{http_code}' -X POST "http://127.0.0.1:$gateway_port/payments" -H 'content-type: application/json' -d "$1"; }
status="$(post '{"amount": 50}')"
[ "$status" = "201" ] || fail "ALLOW: expected 201, got $status"
grep -qi '^agentsafe-decision: ALLOW' "$work/headers" || fail "ALLOW: no agentsafe-decision header"
grep -qi '^agentsafe-execution: FORWARDED' "$work/headers" || fail "ALLOW: not forwarded"
grep -q '"dossier":"synthetic-dossier-' "$work/body" || fail "ALLOW: the upstream did not see the dossier id"
status="$(post '{"amount": 500}')"
[ "$status" = "202" ] || fail "ESCALATE: expected 202, got $status"
grep -qi '^agentsafe-execution: HELD' "$work/headers" || fail "ESCALATE: not held"
status="$(post '{"amount": 5000}')"
[ "$status" = "403" ] || fail "BLOCK: expected 403, got $status"
grep -qi '^agentsafe-state: BLOCK' "$work/headers" || fail "BLOCK: no state header"
status="$(curl -s -o "$work/body" -w '%{http_code}' "http://127.0.0.1:$gateway_port/health")"
[ "$status" = "200" ] || fail "passthrough: expected 200, got $status"
curl -fs "http://127.0.0.1:$gateway_port/_agentsafe/status" > "$work/status.json"
grep -q '"allows":1' "$work/status.json" || fail "status: allows != 1: $(cat "$work/status.json")"
grep -q '"blocks":1' "$work/status.json" || fail "status: blocks != 1"
grep -q '"escalations":1' "$work/status.json" || fail "status: escalations != 1"
grep -q '"held":1' "$work/status.json" || fail "status: held != 1"
count="$(grep -c '"event":"INTERCEPTED"' "$work/gateway.log" || true)"
[ "$count" = "3" ] || fail "expected 3 INTERCEPTED reports, found $count"

# 7. It stops on SIGTERM, cleanly, and the evidence verifies.
kill -TERM "$gateway_pid"
for _ in $(seq 1 100); do kill -0 "$gateway_pid" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$gateway_pid" 2>/dev/null; then fail "the gateway did not stop within 10s"; fi
wait "$gateway_pid" && exit_status=0 || exit_status=$?
gateway_pid=""
[ "$exit_status" = "0" ] || fail "the gateway exited with $exit_status"
grep -q '"event":"GATEWAY_STOPPED"' "$work/gateway.log" || fail "no GATEWAY_STOPPED line"
"$executable" verify chain "$work/evidence/evidence.jsonl" > "$work/verify.json"
grep -q '"ok":true' "$work/verify.json" || fail "evidence chain: $(cat "$work/verify.json")"

echo "SMOKE PASSED: $executable $actual_version held its boundary, governed one ALLOW, one ESCALATE and one BLOCK, stopped cleanly, and left a chain that verifies."
