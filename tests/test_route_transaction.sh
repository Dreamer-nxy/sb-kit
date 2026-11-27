#!/usr/bin/env bash
# Exercise the live route entry point, filesystem swaps and crash recovery offline.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=../sbctl.sh
source "$repo/sbctl.sh" --help >/dev/null
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
# The sourced manager consumes these fixture paths.
# shellcheck disable=SC2034
fixtures() {
  SB_DIR="$work/config"; SB_RULES_DIR="$SB_DIR/rules"; SB_CONFIG="$SB_DIR/config.json"
  SB_CONF_DIR="$SB_DIR/conf"; SB_BIN="$work/core"; SB_LOG_DIR="$work/logs"; SB_UNIT="$work/units/sing-box.service"
  SB_CTL_DST="$work/bin/sbctl"; SB_GROUP=$(id -gn)
  mkdir -p "$SB_DIR" "$SB_RULES_DIR/foreign" "$SB_CONF_DIR" "$work/units"
  printf 'sb-kit-v1\nfresh\n' >"$SB_DIR/.managed-by-sb-kit"
  echo keep >"$SB_RULES_DIR/foreign/data"
  chmod 604 "$SB_RULES_DIR/foreign/data"
  ln -s foreign/data "$SB_RULES_DIR/operator.link"
  printf '#!/bin/sh\nexit 0\n' >"$SB_BIN"; chmod +x "$SB_BIN"
  echo '{"inbounds":[]}' >"$SB_CONF_DIR/node.json"
}
fixtures
fail() { echo "FAIL: $*" >&2; exit 1; }
need_root() { :; }
acquire_lock() { recover_route_transaction; }
chown() { :; }
run_as_service_user() { "$@"; }
sha_a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sha_b=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
echo "$sha_a" >"$work/upstream"
curl() { cat "$work/upstream"; }
download_release_file() {
  case "$1" in
    *"/$sha_a/"*) printf '%s' "$sha_a" >"$2" ;;
    *"/$sha_b/"*) printf '%s' "$sha_b" >"$2" ;;
    *) return 1 ;;
  esac
  printf '%s\n' "$1" >>"$work/urls"
  [[ ! -f "$work/fail-download" || "$1" != *geosite-category-netdisk-cn.srs ]]
}
systemctl() {
  local unit="${!#}"
  case "$1" in
    is-active) [[ -f "$work/$unit.active" ]] ;;
    is-enabled) [[ -f "$work/$unit.enabled" ]] ;;
    enable)
      touch "$work/$unit.enabled"
      if [[ "$2" == --now ]]; then touch "$work/$unit.active"; fi
      if [[ -f "$work/fail-enable" ]]; then rm "$work/fail-enable"; return 1; fi ;;
    disable)
      rm -f "$work/$unit.enabled"
      if [[ "$2" == --now ]]; then rm -f "$work/$unit.active"; fi
      if [[ -f "$work/fail-disable" ]]; then rm "$work/fail-disable"; return 1; fi ;;
    stop) rm -f "$work/$unit.active" ;;
    start) touch "$work/$unit.active" ;;
    show|daemon-reload) : ;;
    *) fail "unexpected systemctl $*" ;;
  esac
}
mv() {
  if [[ "$1" == -f && "$2" == */downloads/*.srs && -f "$work/fail-second-srs" ]]; then
    if [[ -f "$work/first-srs" ]]; then
      rm "$work/fail-second-srs" "$work/first-srs"
      return 1
    fi
    touch "$work/first-srs"
  fi
  command mv "$@"
}
validate_and_restart() {
  echo restart >>"$work/restarts"
  if [[ -f "$work/fail-restart" ]]; then rm "$work/fail-restart"; return 1; fi
}
route_file_op() {
  if [[ "$1" == install && "$2" == */live.json && -f "$work/fail-config" ]]; then
    rm "$work/fail-config"
    return 1
  fi
  if [[ "$1" == install && "$2" == */backup/config.json && -f "$work/fail-restore" ]]; then
    return 1
  fi
  python3 "$LIB_DIR/route_transaction.py" "$@" || return 1
  if [[ "$1" == install && "$3" == */sbkit-rules-update.timer && -f "$work/kill-timer" ]]; then
    rm "$work/kill-timer"
    python3 -c 'import os,signal; os.kill(os.getppid(), signal.SIGKILL)'
  fi
  if [[ "$1" == publish && -f "$work/kill-publisher" ]]; then
    rm "$work/kill-publisher"
    python3 -c 'import os,signal; os.kill(os.getppid(), signal.SIGKILL)'
  fi
  return 0
}
assert_batch() {
  python3 - "$SB_RULES_DIR" "$1" <<'PY'
import json, sys
from pathlib import Path
rules = Path(sys.argv[1])
sha = sys.argv[2]
files = list(rules.glob("geosite-*.srs"))
assert len(files) == 21, len(files)
assert all(p.read_text() == sha for p in files)
assert json.loads((rules / "route-state.json").read_text())["geosite_commit"] == sha
PY
}
identity() {
  python3 - "$1" <<'PY'
import os, sys
st = os.lstat(sys.argv[1])
print(st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode)
PY
}
foreign=$(identity "$SB_RULES_DIR/foreign/data")
link=$(identity "$SB_RULES_DIR/operator.link")

# Partial systemd enablement and partial download must leave a clean first install.
touch "$work/fail-enable"
if cmd_route on; then fail "timer failure hidden"; fi
[[ ! -f "$SB_CONFIG" && ! -f "$SB_RULES_DIR/route-state.json" && ! -e "$work/units/sbkit-rules-update.timer" &&
   ! -e "$work/sbkit-rules-update.timer.enabled" && ! -e "$work/sbkit-rules-update.timer.active" ]] || fail "timer rollback incomplete"
touch "$work/fail-download"
if cmd_route on; then fail "download failure hidden"; fi
rm "$work/fail-download"
[[ ! -f "$SB_RULES_DIR/route-state.json" ]] || fail "incomplete batch published"
echo short-sha >"$work/upstream"
if cmd_route on; then fail "short commit accepted"; fi
: >"$work/urls"
printf '{"sha":"%s"}\n' "$sha_a" >"$work/upstream"
cmd_route on
assert_batch "$sha_a"
[[ $(wc -l <"$work/urls") -eq 21 ]] || fail "incorrect pinned batch size"
[[ ! -e "$work/restarts" ]] || fail "initially stopped service started"

# Reject a live config install error after exchange and a failed active restart.
cp "$SB_CONFIG" "$work/config.before"
touch "$work/fail-config"
if cmd_route off; then fail "config publication error hidden"; fi
assert_batch "$sha_a"
cmp "$SB_CONFIG" "$work/config.before" || fail "old config lost"
touch "$work/fail-disable"
if cmd_route off; then fail "timer disable failure hidden"; fi
assert_batch "$sha_a"
[[ -e "$work/sbkit-rules-update.timer.active" && -e "$work/sbkit-rules-update.timer.enabled" &&
   -f "$work/units/sbkit-rules-update.timer" ]] || fail "prior timer state lost"
touch "$work/fail-config" "$work/fail-restore"
if cmd_route off; then fail "recovery failure hidden"; fi
[[ -f "$SB_DIR/.sb-kit-route.pending/backup/config.json" ]] || fail "recovery backup lost"
rm "$work/fail-restore"
acquire_lock
cmp "$SB_CONFIG" "$work/config.before" || fail "retry lost old config"
assert_batch "$sha_a"
echo "$sha_b" >"$work/upstream"
cp "$SB_RULES_DIR/route-state.json" "$work/state.before"
touch "$work/fail-second-srs"
if cmd_route update --quiet; then fail "second SRS write failure hidden"; fi
[[ ! -e "$work/fail-second-srs" && ! -e "$SB_DIR/.sb-kit-route.pending" ]] || fail "failed outside candidate SRS staging"
assert_batch "$sha_a"
cmp "$SB_RULES_DIR/route-state.json" "$work/state.before" || fail "state changed after staged rule write failed"
touch "$work/sing-box.active" "$work/fail-restart"
if cmd_route update --quiet; then fail "restart failure hidden"; fi
[[ $(wc -l <"$work/restarts") -eq 2 ]] || fail "old active service not recovered"
assert_batch "$sha_a"
cmp "$SB_CONFIG" "$work/config.before" || fail "old config not restored"

# Hard-kill after the exchange, before touching config, timer or the service.
rm -f "$work/sing-box.active"
touch "$work/kill-publisher"
if cmd_route update --quiet 2>"$work/interrupt.log"; then fail "publisher survived forced exit"; fi
assert_batch "$sha_b"
[[ -d "$SB_DIR/.sb-kit-route.pending" ]] || fail "no recovery journal"
acquire_lock
assert_batch "$sha_a"
[[ ! -e "$SB_DIR/.sb-kit-route.pending" ]] || fail "recovery did not finish"
cmd_route update --quiet
assert_batch "$sha_b"
[[ $(wc -l <"$work/restarts") -eq 2 ]] || fail "update started a stopped service"
[[ $(identity "$SB_RULES_DIR/foreign/data") == "$foreign" && $(identity "$SB_RULES_DIR/operator.link") == "$link" ]] ||
  fail "unmanaged file or symlink changed identity or permissions"
# A different administrator may replace a unit before a killed writer is recovered.
cmd_route off
tmr=sbkit-rules-update.timer
touch "$work/kill-timer"
if cmd_route on 2>"$work/interrupt.log"; then fail "timer publication was not interrupted"; fi
cp "$work/units/$tmr" "$work/timer.expected"
echo operator >"$work/units/$tmr"
touch "$work/$tmr.active" "$work/$tmr.enabled"
if acquire_lock; then fail "accepted replacement timer during recovery"; fi
[[ $(cat "$work/units/$tmr") == operator && -f "$work/$tmr.active" && -f "$work/$tmr.enabled" ]] ||
  fail "recovery modified the external timer"
cp "$work/timer.expected" "$work/units/$tmr"
mkdir "$work/units/$tmr.d"
touch "$work/units/$tmr.d/operator.conf"
if acquire_lock; then fail "accepted external drop-in during recovery"; fi
[[ -f "$work/units/$tmr" && -f "$work/$tmr.active" ]] || fail "recovery modified timer with a drop-in"
rm -r "$work/units/$tmr.d"
acquire_lock
[[ ! -e "$work/units/$tmr" && ! -e "$work/$tmr.active" && ! -e "$SB_DIR/.sb-kit-route.pending" ]] ||
  fail "timer recovery could not be retried"
echo "route transaction OK"
