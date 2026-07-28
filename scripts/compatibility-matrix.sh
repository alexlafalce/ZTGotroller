#!/usr/bin/env bash
set -uo pipefail

: "${ZTGOTROLLER_BIN:?set ZTGOTROLLER_BIN}"
: "${ZEROTIER_1142_BIN:?set ZEROTIER_1142_BIN}"
: "${ZEROTIER_CURRENT_BIN:?set ZEROTIER_CURRENT_BIN}"
: "${ZT_INTEROP_DRIVER:?set ZT_INTEROP_DRIVER}"

OUTPUT="${OUTPUT:-compatibility-results}"
mkdir -p "$OUTPUT"

for executable in \
  "$ZTGOTROLLER_BIN" "$ZEROTIER_1142_BIN" "$ZEROTIER_CURRENT_BIN" "$ZT_INTEROP_DRIVER"; do
  if [[ ! -x "$executable" ]]; then
    echo "executable not found: $executable" >&2
    exit 1
  fi
done

printf 'case,status,evidence\n' >"$OUTPUT/summary.csv"
failures=0

run_case() {
  local name="$1"
  shift
  local case_dir="$OUTPUT/$name"
  mkdir -p "$case_dir"
  if "$ZT_INTEROP_DRIVER" \
    --case "$name" \
    --controller "$ZTGOTROLLER_BIN" \
    --output "$case_dir" \
    "$@" >"$case_dir/driver.log" 2>&1; then
    printf '%s,pass,%s\n' "$name" "$case_dir" >>"$OUTPUT/summary.csv"
  else
    printf '%s,fail,%s\n' "$name" "$case_dir" >>"$OUTPUT/summary.csv"
    failures=$((failures + 1))
  fi
}

run_case join-1.14.2 \
  --agent "1.14.2=$ZEROTIER_1142_BIN" \
  --expect-join 1.14.2
run_case join-current \
  --agent "current=$ZEROTIER_CURRENT_BIN" \
  --expect-join current
run_case mixed-peer-connectivity \
  --agent "1.14.2=$ZEROTIER_1142_BIN" \
  --agent "current=$ZEROTIER_CURRENT_BIN" \
  --expect-join 1.14.2 \
  --expect-join current \
  --expect-bidirectional-peer-traffic

if ((failures > 0)); then
  echo "$failures compatibility case(s) failed; see $OUTPUT/summary.csv" >&2
  exit 1
fi
echo "All compatibility cases passed; see $OUTPUT/summary.csv"
