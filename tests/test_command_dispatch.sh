#!/usr/bin/env bash
# Exercise sbctl's public dispatch while keeping all writes in a temporary directory.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=/dev/null
source "$ROOT/sbctl.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SB_DIR="$WORK/etc"
SB_CONF_DIR="$SB_DIR/conf"
SB_CONFIG="$SB_DIR/config.json"
SB_META_DIR="$SB_DIR/meta"
SB_RULES_DIR="$SB_DIR/rules"
SB_BIN="$WORK/absent-core"
SB_CTL_DST="$WORK/sbctl"
SB_LOCK="$WORK/sb-kit.lock"
mkdir -p "$SB_CONF_DIR" "$SB_META_DIR"
printf '#!/bin/sh\necho test-version\n' >"$SB_CTL_DST"
chmod 755 "$SB_CTL_DST"
events="$WORK/events"
: >"$events"

fail() { echo "FAIL: $*" >&2; exit 1; }
# macOS has fcntl.flock but does not ship the util-linux CLI.
if ! command -v flock >/dev/null; then
  flock() {
    python3 - "$2" <<'PY'
import fcntl, sys
try:
    fcntl.flock(int(sys.argv[1]), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(1)
PY
  }
fi
need_root() { :; }
id() { if [[ "$1" == -u ]]; then echo 0; else command id "$@"; fi; }
is_staging_copy() { return 0; }
require_real_lock() {
  [[ "$SB_LOCK_HELD" == 1 ]] || fail "no lock recorded"
  if (exec 8>>"$SB_LOCK"; flock -n 8); then fail "lock was not held"; fi
}
ensure_base_config() { require_real_lock; echo mutate >>"$events"; }
python3() {
  if [[ "${1:-}" == "$LIB_DIR/bundle.py" && "${2:-}" == publish ]]; then
    require_real_lock
    echo sync >>"$events"
    echo test-version
  else
    command python3 "$@"
  fi
}
cmd_audit() { :; }
expect_failure() {
  if (main "$@") >/dev/null 2>&1; then fail "accepted invalid/blocked command: $*"; fi
}

if [[ "${1:-}" == "--root-menu" || "${1:-}" == "--user-menu" ]]; then
  if [[ "$1" == --user-menu ]]; then id() { echo 1000; }; fi
  interactive_menu() {
    [[ -t 0 ]] || fail "menu test requires a terminal"
    (exec 8>>"$SB_LOCK"; flock -n 8) || fail "idle menu retained the publication lock"
    echo menu >>"$events"
  }
  main
  expected=menu
  [[ "$1" != --root-menu ]] || expected=$'sync\nmenu'
  [[ "$(cat "$events")" == "$expected" ]] || fail "incorrect menu dispatch for $1"
  exit 0
fi

main route >/dev/null
main route status >/dev/null
main route allow list >/dev/null
main route block list >/dev/null
main audit >/dev/null
main check >/dev/null
main links >/dev/null
main yaml >/dev/null
main --version >/dev/null
for sub in add modify install tune regen route del update sync uninstall audit; do
  main "$sub" --help >/dev/null
done
main add socks --help >/dev/null
main modify fake-node --help >/dev/null
main add socks --port 39211 --ip 203.0.113.1 --country US --generate-only --out-dir "$WORK/preview" >/dev/null
[[ -f "$WORK/preview/conf/socks-39211.json" ]] || fail "dry run did not create its preview"
expect_failure wrong-command
expect_failure route unknown
expect_failure route status extra
expect_failure route on extra
expect_failure route allow add
expect_failure route update --bad
expect_failure install --unknown
expect_failure install --proto hy2 --non-interactive
expect_failure add wrong-protocol
expect_failure add socks --unknown
expect_failure modify --unknown
expect_failure del tag extra
expect_failure regen --unknown
expect_failure update --unknown
expect_failure sync --unknown
expect_failure uninstall --unknown
[[ ! -s "$events" && ! -e "$SB_LOCK" && ! -e "$SB_CONFIG" && ! -e "$SB_BIN" && ! -e "$SB_RULES_DIR" ]] || fail "read-only or invalid dispatch changed installed state"

(
  exec 7>>"$SB_LOCK"
  flock -n 7 || fail "could not establish competing writer"
  expect_failure route block-cn-on
  expect_failure sync
  main route status >/dev/null
)
[[ ! -s "$events" ]] || fail "a blocked command mutated or published files"

main route block-cn-on >/dev/null
[[ "$(cat "$events")" == $'mutate\nsync' ]] || fail "expected one protected mutation and one publication"
(exec 7>>"$SB_LOCK"; flock -n 7) || fail "a finished action retained the lock"
: >"$events"
main route on >/dev/null
[[ "$(cat "$events")" == $'mutate\nsync' ]] || fail "route on did not mutate and publish under lock"
: >"$events"
main sync >/dev/null
[[ "$(cat "$events")" == sync ]] || fail "explicit sync did not publish under the write lock"

: >"$events"
(
  ensure_base_deps() { echo deps >>"$events"; }
  backup_existing_singbox() { echo backup >>"$events"; }
  install_singbox_binary() { require_real_lock; echo download >>"$events"; }
  ensure_singbox_system() { :; }
  ensure_base_config() { :; }
  cmd_add() { :; }
  main install --proto socks --no-tune --non-interactive >/dev/null
)
[[ "$(cat "$events")" == $'deps\nbackup\nsync\ndownload' ]] || fail "installer did not publish once before downloading the core"

: >"$events"
(
  install_self() { require_real_lock; return 1; }
  if (main route block-cn-off) >"$WORK/publish-failure" 2>&1; then fail "reported a failed publication as successful"; fi
  grep -q '业务操作已完成' "$WORK/publish-failure" || fail "missing partial-success explanation"
)
[[ "$(cat "$events")" == mutate ]] || fail "unexpected repeated mutation after a publication failure"

: >"$events"
ensure_base_config() { return 1; }
expect_failure route block-cn-off
[[ ! -s "$events" ]] || fail "failed operation triggered a sync"
command python3 - "$ROOT/tests/test_command_dispatch.sh" <<'PY'
import os, pty, subprocess, sys
for mode in ("--root-menu", "--user-menu"):
    master, slave = pty.openpty()
    try:
        subprocess.run(["bash", sys.argv[1], mode], stdin=slave, check=True)
    finally:
        os.close(master)
        os.close(slave)
PY
echo "command dispatch and lock lifetime OK"
