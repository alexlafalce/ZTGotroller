#!/usr/bin/env bash
set -euo pipefail

: "${ZTGOTROLLER_BIN:?set ZTGOTROLLER_BIN}"
: "${ZEROTIER_1142_BIN:?set ZEROTIER_1142_BIN}"

NETWORKS="${NETWORKS:-10}"
MEMBERS_PER_NETWORK="${MEMBERS_PER_NETWORK:-100}"
WARMUP_SECONDS="${WARMUP_SECONDS:-10}"
SAMPLE_SECONDS="${SAMPLE_SECONDS:-30}"
RUNS="${RUNS:-5}"
OUTPUT="${OUTPUT:-memory-results}"

for command in curl awk sed stat; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 1
  }
done

mkdir -p "$OUTPUT"

wait_api() {
  local port="$1"
  local token="$2"
  for _ in $(seq 1 100); do
    if curl --silent --fail --header "X-ZT1-Auth: $token" \
      "http://127.0.0.1:${port}/status" >/dev/null; then
      return
    fi
    sleep 0.1
  done
  return 1
}

controller_address() {
  local port="$1"
  local token="$2"
  curl --silent --fail --header "X-ZT1-Auth: $token" \
    "http://127.0.0.1:${port}/status" |
    sed -n 's/.*"address"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p'
}

seed_controller() {
  local port="$1"
  local token="$2"
  local address="$3"
  for network_index in $(seq 1 "$NETWORKS"); do
    local response
    response="$(curl --silent --fail \
      --header "X-ZT1-Auth: $token" --header "Content-Type: application/json" \
      --request POST "http://127.0.0.1:${port}/controller/network/${address}______" \
      --data '{"name":"memory","private":true,"mtu":2800,"multicastLimit":32,"enableBroadcast":true,"v4AssignMode":{"zt":false},"routes":[{"target":"10.99.0.0/16","via":null}],"rules":[{"type":"ACTION_ACCEPT"}]}')"
    local nwid
    nwid="$(printf '%s' "$response" |
      sed -n 's/.*"nwid"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p')"
    test -n "$nwid"
    for member_index in $(seq 1 "$MEMBERS_PER_NETWORK"); do
      local member_id
      member_id="$(printf '%010x' "$((network_index * 100000 + member_index))")"
      curl --silent --fail --output /dev/null \
        --header "X-ZT1-Auth: $token" --header "Content-Type: application/json" \
        --request POST \
        "http://127.0.0.1:${port}/controller/network/${nwid}/member/${member_id}" \
        --data '{"authorized":true,"noAutoAssignIps":true}'
    done
  done
}

sample_process() {
  local case_name="$1"
  local run="$2"
  local pid="$3"
  local output_file="$OUTPUT/raw.csv"
  for second in $(seq 0 "$SAMPLE_SECONDS"); do
    test -r "/proc/${pid}/status" || return 1
    local rss pss
    rss="$(awk '/^VmRSS:/ {print $2}' "/proc/${pid}/status")"
    pss="$(awk '/^Pss:/ {print $2}' "/proc/${pid}/smaps_rollup" 2>/dev/null || printf '0')"
    printf '%s,%s,%s,%s,%s\n' "$case_name" "$run" "$second" "$rss" "$pss" >>"$output_file"
    sleep 1
  done
}

run_case() {
  local case_name="$1"
  local run="$2"
  local port="$3"
  local token="$4"
  shift 4
  local case_dir="$work_dir/${case_name}-${run}"
  mkdir -p "$case_dir"
  "$@" >"$case_dir/stdout.log" 2>"$case_dir/stderr.log" &
  local pid=$!
  trap 'kill "$pid" 2>/dev/null || true' RETURN
  wait_api "$port" "$token"
  local address
  address="$(controller_address "$port" "$token")"
  test -n "$address"
  seed_controller "$port" "$token" "$address"
  sleep "$WARMUP_SECONDS"
  sample_process "$case_name" "$run" "$pid"
  kill -TERM "$pid"
  wait "$pid" || true
  trap - RETURN
}

printf 'case,run,second,rss_kib,pss_kib\n' >"$OUTPUT/raw.csv"
printf 'case,binary_bytes\n' >"$OUTPUT/binaries.csv"
printf 'ztgotroller,%s\n' "$(stat -c %s "$ZTGOTROLLER_BIN")" >>"$OUTPUT/binaries.csv"
printf 'zerotier-1.14.2,%s\n' "$(stat -c %s "$ZEROTIER_1142_BIN")" >>"$OUTPUT/binaries.csv"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ztgotroller-memory.XXXXXX")"
trap 'test -n "${work_dir:-}" && rm -rf -- "$work_dir"' EXIT

for run in $(seq 1 "$RUNS"); do
  go_token="go-${run}-$(date +%s%N)"
  run_case ztgotroller "$run" 19994 "$go_token" \
    env ZTGOTROLLER_API_TOKEN="$go_token" "$ZTGOTROLLER_BIN" \
    -identity "$work_dir/go-${run}.identity" \
    -database "$work_dir/go-${run}.db" \
    -listen 127.0.0.1:19994 -udp-listen 127.0.0.1:19993

  zt_home="$work_dir/zt-${run}"
  mkdir -p "$zt_home"
  zt_token="zt-${run}-$(date +%s%N)"
  printf '%s' "$zt_token" >"$zt_home/authtoken.secret"
  chmod 600 "$zt_home/authtoken.secret"
  run_case zerotier-1.14.2 "$run" 19995 "$zt_token" \
    "$ZEROTIER_1142_BIN" -U -p19995 "$zt_home"
done

{
  printf 'case,run,peak_rss_kib,peak_pss_kib\n'
  awk -F, 'NR > 1 {
  key=$1 "," $2
  if ($4 > peak_rss[key]) peak_rss[key]=$4
  if ($5 > peak_pss[key]) peak_pss[key]=$5
}
END {
  for (key in peak_rss) print key "," peak_rss[key] "," peak_pss[key]
}' "$OUTPUT/raw.csv" | sort
} >"$OUTPUT/peaks.csv"

echo "Results written to $OUTPUT"
