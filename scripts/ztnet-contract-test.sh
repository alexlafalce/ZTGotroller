#!/usr/bin/env bash
set -euo pipefail

ZTNET_REPOSITORY="${ZTNET_REPOSITORY:-https://github.com/sinamics/ztnet.git}"
ZTNET_REF="${ZTNET_REF:-3ba175a682d03edd72516d830667ee08fe3cf262}"
LISTEN="${LISTEN:-127.0.0.1:29994}"
UDP_LISTEN="${UDP_LISTEN:-127.0.0.1:29993}"
TOKEN="${TOKEN:-ztnet-contract-test}"

for command in git go npm curl cp seq; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 1
  }
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ztgotroller-ztnet.XXXXXX")"
controller_pid=""
cleanup() {
  if [[ -n "$controller_pid" ]]; then
    kill "$controller_pid" 2>/dev/null || true
    wait "$controller_pid" 2>/dev/null || true
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

git init --quiet "$work_dir/ztnet"
git -C "$work_dir/ztnet" remote add origin "$ZTNET_REPOSITORY"
git -C "$work_dir/ztnet" fetch --quiet --depth 1 origin "$ZTNET_REF"
git -C "$work_dir/ztnet" checkout --quiet --detach FETCH_HEAD
actual_ref="$(git -C "$work_dir/ztnet" rev-parse HEAD)"
if [[ "$actual_ref" != "$ZTNET_REF" ]]; then
  echo "resolved ZTNet ref $actual_ref does not match required $ZTNET_REF" >&2
  exit 1
fi

npm --prefix "$work_dir/ztnet" ci
cp "$repo_root/testdata/ztnet/ztgotroller.integration.test.ts" \
  "$work_dir/ztnet/src/utils/__tests__/ztgotroller.integration.test.ts"

(
  cd "$repo_root"
  go build -trimpath -o "$work_dir/ztgotroller" ./cmd/ztgotroller
)
ZTGOTROLLER_API_TOKEN="$TOKEN" "$work_dir/ztgotroller" \
  -identity "$work_dir/controller.identity" \
  -database "$work_dir/controller.db" \
  -listen "$LISTEN" -udp-listen "$UDP_LISTEN" \
  >"$work_dir/controller.log" 2>&1 &
controller_pid=$!

for _ in $(seq 1 100); do
  if curl --silent --fail --header "X-ZT1-Auth: $TOKEN" \
    "http://$LISTEN/status" >/dev/null; then
    break
  fi
  sleep 0.1
done
curl --silent --fail --header "X-ZT1-Auth: $TOKEN" \
  "http://$LISTEN/status" >/dev/null

(
  cd "$work_dir/ztnet"
  ZT_ADDR="http://$LISTEN" \
  ZT_SECRET="$TOKEN" \
  DATABASE_URL=postgresql://unused:unused@127.0.0.1:1/unused \
  MIGRATE_DATABASE_URL=postgresql://unused:unused@127.0.0.1:1/unused \
  NEXTAUTH_URL=http://localhost:3000 \
  NEXTAUTH_SECRET=test \
  npx jest --runInBand --config jest.api.config.ts \
    src/utils/__tests__/ztgotroller.integration.test.ts
)
