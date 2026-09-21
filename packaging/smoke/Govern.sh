#!/usr/bin/env bash
# The release smoke test for govern, run against an installed or extracted
# binary:
#
#   packaging/smoke/Govern.sh <path to govern> <expected version>
#
# It is what a workflow's first step meets, asserted offline: the binary
# answers its version; a shadow step without a key runs its command and ends
# with the command's own exit code, recording nothing; an enforcement step
# without a key runs nothing and fails; the record a run writes is the
# report the README names; and a flag the command cannot read is a usage
# error, not a run. No authority is reached: nothing here decides anything.
set -euo pipefail

executable="${1:?path to govern}"
expected_version="${2:?expected version}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# The gated commands below are bash's, wherever this runs: on Windows the
# binary's default shell is PowerShell, and the path a Windows executable
# is handed must be a Windows path, which Git Bash's mktemp does not give.
export GOVERN_SHELL=bash
report_dir="$work"
if command -v cygpath >/dev/null 2>&1; then report_dir="$(cygpath -w "$work")"; fi

fail() { echo "SMOKE FAILED: $*" >&2; exit 1; }

# 1. The binary is the release.
actual="$("$executable" version)"
[ "$actual" = "govern $expected_version" ] || fail "version: expected 'govern $expected_version', got '$actual'"
"$executable" help | grep -q 'govern run \[flags\]' || fail "help did not describe govern run"

# 2. Shadow without a key is inert: the command runs, the exit code is its own.
set +e
GOVERN_HOST=generic GOVERN_REPORT="$report_dir/shadow.json" \
  "$executable" run --mode shadow --action smoke-test -- sh -c 'echo shadow-ran; exit 3' > "$work/shadow.out" 2>&1
code=$?
set -e
[ "$code" = 3 ] || fail "shadow step exited $code, not the command's 3: $(cat "$work/shadow.out")"
grep -q 'shadow-ran' "$work/shadow.out" || fail "the shadow command did not run: $(cat "$work/shadow.out")"
grep -q 'no DECIONIS_API_KEY' "$work/shadow.out" || fail "shadow did not say it is unconfigured: $(cat "$work/shadow.out")"
# The record is indented JSON; each field is asserted on its own line.
grep -q '"version": "agent-safe.govern-report/1"' "$work/shadow.json" || fail "report: $(cat "$work/shadow.json")"
grep -q '"asked": false' "$work/shadow.json" || fail "shadow without a key asked the authority: $(cat "$work/shadow.json")"
grep -q '"exit": 3' "$work/shadow.json" || fail "report exit: $(cat "$work/shadow.json")"

# 3. Enforcement without a key runs nothing and fails.
set +e
GOVERN_HOST=generic "$executable" run --action smoke-test -- sh -c 'echo enforced-ran; exit 0' > "$work/enforce.out" 2>&1
code=$?
set -e
[ "$code" = 1 ] || fail "enforcement without a key exited $code, not 1: $(cat "$work/enforce.out")"
if grep -q 'enforced-ran' "$work/enforce.out"; then fail "enforcement without a key ran the command"; fi
grep -q 'enforcement needs DECIONIS_API_KEY' "$work/enforce.out" || fail "enforcement did not name the missing key: $(cat "$work/enforce.out")"

# 4. A flag the command cannot read is a usage error, and no command runs.
set +e
"$executable" run --mode loud -- sh -c 'echo usage-ran' > "$work/usage.out" 2>&1
code=$?
set -e
[ "$code" = 2 ] || fail "a bad flag exited $code, not 2: $(cat "$work/usage.out")"
if grep -q 'usage-ran' "$work/usage.out"; then fail "a bad flag still ran the command"; fi

echo "SMOKE PASSED: govern $expected_version answers, shadow is inert without a key, enforcement refuses without one"
