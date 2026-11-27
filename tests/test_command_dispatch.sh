#!/usr/bin/env bash
# Exercise the public sb commands while keeping all writes in a temporary directory.
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
SB_CTL_DST="$WORK/sb"
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
check_cli_name() { :; }
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

if [[ "${1:-}" == "--add-menu" ]]; then
  require_supported_protocol() {
    [[ "$1" == hy2 ]] || fail "protocol selector dispatched $1"
    echo selected >>"$events"
    exit 0
  }
  main add
  [[ $(cat "$events") == selected && ! -e "$SB_LOCK" ]] || fail "protocol selection changed installed state"
  exit 0
fi

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

main cn >/dev/null
main allow >/dev/null
main block >/dev/null
main check >/dev/null
main info >/dev/null
main clash >/dev/null
main version >/dev/null
for sub in add change install bbr rebuild cn allow block del update sync uninstall check info clash restart start stop status a c i d s r u v; do
  main "$sub" --help >/dev/null
done
main add socks --help >/dev/null
main change fake-node --help >/dev/null
main add socks --port 39211 --ip 203.0.113.1 --country US --generate-only --out-dir "$WORK/preview" >/dev/null
[[ -f "$WORK/preview/conf/socks-39211.json" ]] || fail "dry run did not create its preview"
[[ $(main info "$WORK/preview/meta") == *"socks5://"* ]] || fail "link ignored the offline metadata directory"
[[ $(main clash "$WORK/preview/meta") == *"port: 39211"* ]] || fail "clash ignored the offline metadata directory"
[[ $(main info "$WORK/preview/meta") == "$(main i "$WORK/preview/meta")" ]] || fail "i differs from info"
[[ $(main v) == "$(main version)" && $(main h) == "$(main help)" ]] || fail "version/help shortcut mismatch"
(
  select_reality_sni() { echo www.example.org; }
  for proto in r hy ss; do
    args=(--ip 203.0.113.1 --country US --port 39212 --generate-only --out-dir "$WORK/$proto")
    case "$proto" in
      r)  full=vless-reality ;;
      hy) full=hy2; args+=(--domain test.example.org) ;;
      ss) full=ss2022 ;;
    esac
    main a "$proto" "${args[@]}" >/dev/null
    [[ -s "$WORK/$proto/conf/$full-39212.json" ]] || fail "protocol shortcut $proto did not create $full"
  done
)
(
  need_root() { fail "status requested root"; }
  systemctl() {
    [[ "$*" == "--no-pager --lines=0 status sing-box.service" ]] || fail "unexpected status query"
    echo "fixture state"
    return "$state_rc"
  }
  state_rc=0
  [[ $(main s) == "fixture state" && $(main status) == "fixture state" ]] || fail "status did not read service state"
  state_rc=3
  rc=0
  main s >/dev/null || rc=$?
  [[ $rc == 3 ]] || fail "inactive state status code was lost"
)
for sub in s r start stop restart; do expect_failure "$sub" extra; done
expect_failure wrong-command
for obsolete in route edit link modify mod links url yaml audit tune regen up rm; do
  expect_failure "$obsolete"
done
expect_failure cn status
expect_failure cn block-cn-on
expect_failure cn allow example.cn
expect_failure cn on extra
expect_failure cn update --bad
expect_failure version extra
for sub in info clash; do
  expect_failure "$sub" --unknown
  expect_failure "$sub" first second
done
expect_failure bbr --rollback
expect_failure bbr reset extra
expect_failure add </dev/null
for sub in allow block; do
  expect_failure "$sub" del
  expect_failure "$sub" add example.cn
  expect_failure "$sub" --oops
  expect_failure "$sub" invalid
  expect_failure "$sub" del --oops
done
expect_failure install --unknown
expect_failure install --proto hy2 --non-interactive
expect_failure add wrong-protocol
expect_failure add socks --unknown
expect_failure c --unknown
expect_failure del tag extra
expect_failure rebuild --unknown
expect_failure update --unknown
expect_failure sync --unknown
expect_failure uninstall --unknown
[[ ! -s "$events" && ! -e "$SB_LOCK" && ! -e "$SB_CONFIG" && ! -e "$SB_BIN" && ! -e "$SB_RULES_DIR" ]] || fail "read-only or invalid dispatch changed installed state"

(
  exec 7>>"$SB_LOCK"
  flock -n 7 || fail "could not establish competing writer"
  expect_failure cn on
  expect_failure sync
  main cn >/dev/null
)
[[ ! -s "$events" ]] || fail "a blocked command mutated or published files"

(
  validate_and_restart() { require_real_lock; echo validated >>"$events"; }
  systemctl() { require_real_lock; echo "$*" >>"$events"; }
  main r
  main start >/dev/null
  main stop >/dev/null
)
[[ $(cat "$events") == $'validated\nstart sing-box\nstop sing-box' ]] || fail "service actions skipped validation/locking or republished files"
: >"$events"
main cn on >/dev/null
[[ "$(cat "$events")" == $'mutate\nsync' ]] || fail "expected one protected mutation and one publication"
(exec 7>>"$SB_LOCK"; flock -n 7) || fail "a finished action retained the lock"
: >"$events"
(
  ensure_base_config() {
    require_real_lock
    printf '%s %s %s\n' "$4" "$5" "$6" >>"$events"
  }
  main allow example.cn >/dev/null
  main allow del example.cn >/dev/null
  main block example.net >/dev/null
  main block del example.net >/dev/null
)
expected=$(printf '%s\n' "$SB_ALLOW_LIST_NAME add example.cn" sync "$SB_ALLOW_LIST_NAME del example.cn" sync \
  "$SB_BLOCK_LIST_NAME add example.net" sync "$SB_BLOCK_LIST_NAME del example.net" sync)
[[ "$(cat "$events")" == "$expected" ]] || fail "new domain commands selected the wrong list or action"
: >"$events"
main sync >/dev/null
[[ "$(cat "$events")" == sync ]] || fail "explicit sync did not publish under the write lock"

: >"$events"
(
  install_tcpfit() { require_real_lock; }
  TCPFIT_BIN="$WORK/tcpfit"
  printf '#!/bin/sh\n[ "$1" = rollback ] && [ "$TCPFIT_NO_TELEMETRY" = 1 ]\n' >"$TCPFIT_BIN"
  chmod +x "$TCPFIT_BIN"
  touch "$SB_DIR/.sb-kit-tcpfit-tuned"
  main bbr reset >/dev/null
)
[[ ! -e "$SB_DIR/.sb-kit-tcpfit-tuned" && $(cat "$events") == sync ]] || fail "bbr reset did not complete a protected rollback"

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
  if (main cn off) >"$WORK/publish-failure" 2>&1; then fail "reported a failed publication as successful"; fi
  grep -q '业务操作已完成' "$WORK/publish-failure" || fail "missing partial-success explanation"
)
[[ "$(cat "$events")" == mutate ]] || fail "unexpected repeated mutation after a publication failure"

: >"$events"
ensure_base_config() { return 1; }
expect_failure cn off
[[ ! -s "$events" ]] || fail "failed operation triggered a sync"
command python3 - "$ROOT/tests/test_command_dispatch.sh" <<'PY'
import os, pty, subprocess, sys
for mode in ("--root-menu", "--user-menu", "--add-menu"):
    master, slave = pty.openpty()
    try:
        if mode == "--add-menu":
            os.write(master, b"2\n")
        subprocess.run(["bash", sys.argv[1], mode], stdin=slave, check=True)
    finally:
        os.close(master)
        os.close(slave)
PY
echo "command dispatch and lock lifetime OK"
