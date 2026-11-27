#!/usr/bin/env bash
# Exercise install / uninstall ownership entirely under a temporary root.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../sbctl.sh
source "$ROOT/sbctl.sh" --help >/dev/null
WORK=$(mktemp -d)
trap 'cleanup_paths; rm -rf "$WORK"' EXIT
export TMPDIR="$WORK/tmp"
mkdir -p "$TMPDIR"
fail() { echo "FAIL: $*" >&2; exit 1; }
need_root() { :; }
acquire_lock() { :; }
chown() { :; }
id() { echo 0; }
systemctl() {
  printf '%s\n' "$*" >>"$WORK/systemctl.calls"
  case "$1" in
    show)
      [[ ! -e "$WORK/route-bus-failed" ]] || return 1
      case "$*" in
        *FragmentPath*sing-box.service) [[ ! -e "$WORK/fragment" ]] || cat "$WORK/fragment" ;;
        *FragmentPath*sbkit-rules-update*) [[ ! -e "$WORK/route-fragment" ]] || cat "$WORK/route-fragment" ;;
        *DropInPaths*sbkit-rules-update*) [[ ! -e "$WORK/route-dropins" ]] || cat "$WORK/route-dropins" ;;
      esac ;;
    is-active|is-enabled) [[ -f "$WORK/$1" ]] ;;
  esac
}
# These fixture paths are read by the sourced sbctl functions.
# shellcheck disable=SC2034
set_paths() {
  local base="$WORK/$1"
  SB_DIR="$base/etc/sing-box"; SB_CONFIG="$SB_DIR/config.json"; SB_CONF_DIR="$SB_DIR/conf"
  SB_META_DIR="$SB_DIR/meta"; SB_RULES_DIR="$SB_DIR/rules"; SB_STATE_DIR="$base/state"; SB_LOG_DIR="$base/logs"
  SB_UNIT="$base/units/sing-box.service"; SB_LOGROTATE="$base/rotate"; SB_BIN="$base/bin/sing-box"
  SB_CTL_DST="$base/bin/sb"; SB_LIB_DST="$base/lib"; SB_BACKUP_ROOT="$base/backups"; NFT_DIR="$base/nft"
  TCPFIT_BIN="$base/bin/tcpfit"; PRE_INSTALL_BACKUP=""
  mkdir -p "$base/bin" "$base/units"
  rm -f "$WORK/fragment" "$WORK/route-bus-failed" "$WORK/route-fragment" "$WORK/route-dropins" "$WORK/is-active" "$WORK/is-enabled"
}

# A package-provided sb elsewhere on PATH must not be shadowed by the installer.
set_paths cli_conflict
mkdir -p "$WORK/path"
printf '#!/bin/sh\nexit 0\n' >"$WORK/path/sb"
chmod 755 "$WORK/path/sb"
if (export PATH="$WORK/path:$PATH"; check_cli_name) >/dev/null 2>&1; then
  fail "accepted another sb on PATH"
fi
[[ ! -e "$SB_CTL_DST" ]] || fail "published sb despite PATH conflict"
# A previous installation's active updater would invoke a retired command.
echo "ExecStart=${SB_CTL_DST%/*}/sbctl route update --quiet" >"${SB_UNIT%/*}/sbkit-rules-update.service"
if (check_cli_name) >/dev/null 2>&1; then fail "accepted an updater that still calls sbctl"; fi

# The real GitHub response exceeds Linux's per-argument limit.
set_paths release
mkdir -p "$WORK/archive/sing-box-1.14.4-linux-amd64"
printf '#!/bin/sh\necho "sing-box version 1.14.4"\n' >"$WORK/archive/sing-box-1.14.4-linux-amd64/sing-box"
tar -czf "$WORK/release.tar.gz" -C "$WORK/archive" .
SHA=$(sha256sum "$WORK/release.tar.gz" | awk '{print $1}')
make_release() {
  python3 - "$WORK/release.json" "$1" <<'PY'
import json, sys
with open(sys.argv[1], "w") as fh:
    json.dump({"tag_name":"v1.14.4", "body":"x"*350000, "assets":[{"name":"sing-box-1.14.4-linux-amd64.tar.gz",
        "browser_download_url":"https://example.invalid/archive", "digest":sys.argv[2]}]}, fh)
PY
}
detect_arch() { echo amd64; }
curl() {
  case "$*" in
    *api.github.com*) cp "$WORK/release.json" "${!#}" ;;
    *example.invalid/archive*) cp "$WORK/release.tar.gz" "${!#}" ;;
    *) fail "unexpected HTTP request" ;;
  esac
}
make_release "sha256:$SHA"
echo original >"$SB_BIN"
chmod 755 "$SB_BIN"
install_singbox_binary v1.14.4
[[ "$("$SB_BIN" version)" == "sing-box version 1.14.4" && "$(cat "${SB_BIN}.bak")" == original ]] || fail "install did not retain rollback core"
restore_singbox_binary
for invalid in "" "sha256:invalid" "sha256:$(printf '%064d' 0)"; do
  make_release "$invalid"
  if (trap - EXIT; install_singbox_binary v1.14.4) >/dev/null 2>&1; then fail "accepted invalid digest"; fi
  [[ "$(cat "$SB_BIN")" == original ]] || fail "unverified core published"
done

set_paths native
mkdir -p "$SB_DIR"; echo native >"$SB_CONFIG"
: >"$WORK/systemctl.calls"
if (trap - EXIT; cmd_uninstall) >/dev/null 2>&1; then fail "uninstall accepted unmanaged instance"; fi
[[ "$(cat "$SB_CONFIG")" == native && ! -s "$WORK/systemctl.calls" ]] || fail "unmanaged service touched"
if (trap - EXIT; cp() { return 1; }; backup_existing_singbox) >/dev/null 2>&1; then fail "ignored backup failure"; fi
[[ ! -e "$SB_DIR/.managed-by-sb-kit" ]] || fail "claimed failed backup"

# Refuse external storage roots before taking ownership; read-only certificate
# links and replaceable config/unit/logrotate file links can be round-tripped.
set_paths links
mkdir -p "${SB_DIR%/*}" "$WORK/external"; echo untouched >"$WORK/external/keep"
for dir in "$SB_DIR" "$SB_LOG_DIR" "$SB_STATE_DIR"; do
  ln -s "$WORK/external" "$dir"
  if (trap - EXIT; backup_existing_singbox) >/dev/null 2>&1; then fail "accepted linked storage $dir"; fi
  [[ ! -e "$SB_BACKUP_ROOT" && "$(cat "$dir/keep")" == untouched ]] || fail "modified linked storage"
  rm "$dir"
done
mkdir -p "$SB_DIR" "$SB_STATE_DIR/certs" "$SB_STATE_DIR/acme"
ln -s "$WORK/external" "$SB_STATE_DIR/acme/certificates"
if (trap - EXIT; backup_existing_singbox) >/dev/null 2>&1; then fail "accepted externally writable ACME store"; fi
rm "$SB_STATE_DIR/acme/certificates"
echo cert >"$WORK/external/site.key"; chmod 600 "$WORK/external/site.key"
ln -s "$WORK/external/site.key" "$SB_STATE_DIR/certs/site.key"
for path in "$SB_UNIT" "$SB_LOGROTATE" "$SB_CONFIG"; do
  ln -s "$WORK/external/keep" "$path"
done
backup_existing_singbox
ensure_singbox_system
ensure_base_config 0
fix_runtime_perms
[[ ! -L "$SB_UNIT" && ! -L "$SB_LOGROTATE" && ! -L "$SB_CONFIG" ]] || fail "overwrote link destination"
cmd_uninstall --keep-tcpfit
for path in "$SB_UNIT" "$SB_LOGROTATE" "$SB_CONFIG"; do
  [[ -L "$path" && "$(cat "$path")" == untouched ]] || fail "failed to restore link $path"
done
[[ -L "$SB_STATE_DIR/certs/site.key" ]] || fail "removed a custom certificate link"
python3 - "$WORK/external/site.key" <<'PY'
import os, stat, sys
assert stat.S_IMODE(os.stat(sys.argv[1]).st_mode) == 0o600
PY

# Adopt an existing unit/binary/config and round-trip its original state.
set_paths native
echo native-core >"$SB_BIN"; echo native-unit >"$SB_UNIT"; echo native-rotate >"$SB_LOGROTATE"
mkdir -p "$SB_STATE_DIR"; touch "$SB_STATE_DIR/operator.db"
chmod 751 "$SB_DIR"; chmod 710 "$SB_STATE_DIR"; chmod 604 "$SB_STATE_DIR/operator.db"
touch "$WORK/is-active" "$WORK/is-enabled"
printf '%s\n' "$SB_UNIT" >"$WORK/fragment"
backup_existing_singbox
[[ -f "$SB_BACKUP_ROOT/$PRE_INSTALL_BACKUP/complete" ]] || fail "missing completed backup"
ensure_singbox_system
chmod 600 "$SB_STATE_DIR/operator.db"
echo kit-core >"$SB_BIN"; echo kit-config >"$SB_CONFIG"; echo native-extra >"$SB_CONF_DIR/handmade.json"
mkdir -p "$SB_STATE_DIR/certs/identity-test" "$SB_LIB_DST" "$NFT_DIR"
touch "$SB_STATE_DIR/certs/identity-test"/{.managed-by-sb-kit,certificate.crt,private.key}
touch "$SB_STATE_DIR/certs/external.key" "$SB_LIB_DST/external" "$SB_LOG_DIR/foreign.log"
printf '{"tag":"socks-1234","proto":"socks","port":1234}\n' >"$SB_META_DIR/socks-1234.json"
printf '{"inbounds":[{"tag":"socks-1234"}]}\n' >"$SB_CONF_DIR/socks-1234.json"
cmd_uninstall
[[ "$(cat "$SB_BIN")" == native-core && "$(cat "$SB_CONFIG")" == native && "$(cat "$SB_UNIT")" == native-unit ]] || fail "native files not restored"
[[ "$(cat "$SB_LOGROTATE")" == native-rotate && -e "$SB_CONF_DIR/handmade.json" ]] || fail "native data damaged"
[[ -f "$SB_STATE_DIR/certs/external.key" && -f "$SB_LIB_DST/external" && -f "$SB_LOG_DIR/foreign.log" ]] || fail "foreign files removed"
[[ ! -e "$SB_CONF_DIR/socks-1234.json" && ! -e "$SB_STATE_DIR/certs/identity-test" ]] || fail "owned files remain"
python3 - "$SB_DIR" "$SB_STATE_DIR" "$SB_STATE_DIR/operator.db" <<'PY'
import os, stat, sys
assert [stat.S_IMODE(os.stat(p).st_mode) for p in sys.argv[1:]] == [0o751, 0o710, 0o604]
PY
grep -Fxq 'start sing-box' "$WORK/systemctl.calls" || fail "native service was not restarted"

set_paths missing
ensure_singbox_system
printf 'sb-kit-v1\npre-install-missing\n' >"$SB_DIR/.managed-by-sb-kit"
echo still-running >"$SB_CONFIG"
: >"$WORK/systemctl.calls"
if (trap - EXIT; cmd_uninstall) >/dev/null 2>&1; then fail "uninstalled without original backup"; fi
[[ "$(cat "$SB_CONFIG")" == still-running ]] || fail "missing backup damaged state"
if grep -q '^disable' "$WORK/systemctl.calls"; then fail "stopped service before backup check"; fi

set_paths legacy
ensure_singbox_system
: >"$SB_DIR/.managed-by-sb-kit"
echo shared >"$SB_STATE_DIR/operator.db"
cmd_uninstall --keep-tcpfit
[[ "$(cat "$SB_STATE_DIR/operator.db")" == shared && ! -e "$SB_UNIT" ]] || fail "legacy marker handling"

set_paths fresh
backup_existing_singbox
ensure_singbox_system
echo config >"$SB_CONFIG"; touch "$SB_LOG_DIR/error.log" "$SB_LOG_DIR/error.log.1.gz"
mkdir -p "$SB_STATE_DIR/acme/certificates/test-ca/site.test"
touch "$SB_STATE_DIR/acme/certificates/test-ca/site.test/site.test.crt"
cmd_uninstall
for dir in "$SB_DIR" "$SB_STATE_DIR" "$SB_LOG_DIR"; do [[ ! -e "$dir" ]] || fail "retained $dir"; done

# Exercise targeted CN route files, timer install/disable, and selective uninstall cleanup.
set_paths route_clean
backup_existing_singbox
ensure_singbox_system
curl() {
  local out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) out="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  if [[ -n "$out" ]]; then
    printf 'DUMMY-SRS-DATA' >"$out"
  else
    printf '0123456789abcdef0123456789abcdef01234567\n'
  fi
}
touch "$SB_RULES_DIR/operator-custom.srs"
ensure_base_config on 1 1
[[ -f "$SB_RULES_DIR/route-state.json" && -f "$SB_RULES_DIR/geosite-category-netdisk-cn.srs" ]] || fail "CN block rules not installed"
[[ -f "${SB_UNIT%/*}/sbkit-rules-update.timer" && -f "${SB_UNIT%/*}/sbkit-rules-update.service" ]] || fail "rules update timer not installed"
cmd_domain_list allow example.cn >/dev/null
[[ -f "$SB_RULES_DIR/cn-allow.list" ]] || fail "custom allowlist not written"
cmd_uninstall --keep-tcpfit
[[ ! -e "${SB_UNIT%/*}/sbkit-rules-update.timer" && ! -e "${SB_UNIT%/*}/sbkit-rules-update.service" ]] || fail "rules update timer survived uninstall"
[[ ! -e "$SB_RULES_DIR/geosite-category-netdisk-cn.srs" && ! -e "$SB_RULES_DIR/route-state.json" && ! -e "$SB_RULES_DIR/cn-allow.list" ]] || fail "managed route files survived uninstall"
[[ -f "$SB_RULES_DIR/operator-custom.srs" ]] || fail "operator foreign rule file was deleted"
# On refuses to shadow existing local or vendor units, including drop-ins not yet loaded.
set_paths foreign_route
ensure_singbox_system
ensure_base_config off 0 1
unit_dir=${SB_UNIT%/*}
timer="$unit_dir/sbkit-rules-update.timer"
updater="$unit_dir/sbkit-rules-update.service"
touch "$WORK/route-bus-failed"
if check_route_ownership on; then fail "claimed unit while systemd was unavailable"; fi
rm "$WORK/route-bus-failed"
echo /usr/lib/systemd/system/sbkit-rules-update.timer >"$WORK/route-fragment"
if check_route_ownership on; then fail "accepted foreign vendor unit"; fi
rm "$WORK/route-fragment"
echo /run/systemd/system/sbkit-rules-update.service.d/vendor.conf >"$WORK/route-dropins"
if check_route_ownership on; then fail "accepted loaded external drop-in"; fi
rm "$WORK/route-dropins"
mkdir "$timer.d"
touch "$timer.d/override.conf"
if check_route_ownership on; then fail "accepted un-reloaded external drop-in"; fi
rm "$timer.d/override.conf"
rmdir "$timer.d"
printf '[Unit]\nDescription=sb-kit weekly CN route rules update timer\n# operator\n' >"$timer"
printf '[Unit]\nDescription=sb-kit CN route rules auto-updater\n# operator\n' >"$updater"
if ensure_base_config on 0 1; then fail "overwrote regular operator units"; fi
custom="$SB_RULES_DIR/geosite-category-netdisk-cn.srs"
echo operator >"$custom"; chmod 600 "$custom"
echo operator >"$SB_RULES_DIR/geoip-cn.srs"
echo example.net >"$SB_RULES_DIR/cn-allow.list"
if cmd_domain_list allow new.example.net; then fail "overwrote untracked domain list"; fi
fix_runtime_perms
python3 - "$custom" <<'PYMODE'
import os, stat, sys
assert stat.S_IMODE(os.stat(sys.argv[1]).st_mode) == 0o600
PYMODE
: >"$WORK/systemctl.calls"
ensure_base_config off 0 1
cmd_uninstall --keep-tcpfit
[[ "$(cat "$custom")" == operator && "$(cat "$SB_RULES_DIR/geoip-cn.srs")" == operator ]] || fail "deleted unowned same-name rule"
[[ "$(cat "$SB_RULES_DIR/cn-allow.list")" == example.net ]] || fail "lost operator list"
[[ -f "$timer" && -f "$updater" ]] || fail "deleted external units by description"
if grep -q '^disable.*sbkit-rules-update' "$WORK/systemctl.calls"; then fail "disabled external timer"; fi

# Replacing a previously owned rule or unit transfers its contents back to the operator.
set_paths changed_route
ensure_singbox_system
ensure_base_config on 1 1
custom="$SB_RULES_DIR/geosite-category-netdisk-cn.srs"
timer="${SB_UNIT%/*}/sbkit-rules-update.timer"
echo operator >"$custom"
echo '# operator' >>"$timer"
if ensure_base_config on 1 1; then fail "replaced a modified rule"; fi
cmd_uninstall --keep-tcpfit
[[ "$(cat "$custom")" == operator && -e "$timer" ]] || fail "deleted manually replaced rule or timer"
[[ ! -e "${SB_UNIT%/*}/sbkit-rules-update.service" && ! -e "$SB_RULES_DIR/route-state.json" ]] || fail "failed to clean intact owned resources"

# v0.3.0 had plain-text lists with no manifest. Keep the original bytes, owner and mode
# when adopting them, both on first edit and if a separate upgrade command happens first.
for first in edit upgrade changed; do
  set_paths "old_lists_$first"
  ensure_singbox_system
  python3 "$LIB_DIR/config_gen.py" base-config --out "$SB_CONFIG" --log-file "$SB_LOG_DIR/error.log" --cn-mode off
  # sing-box format serializes a one-element port array as a number.
  if [[ "$first" == upgrade ]]; then
    python3 - "$SB_CONFIG" <<'PYFORMAT'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
config = json.loads(path.read_text())
next(r for r in config["route"]["rules"] if r.get("port") == [25])["port"] = 25
path.write_text(json.dumps(config))
PYFORMAT
  fi
  python3 "$LIB_DIR/config_gen.py" route-state --file "$SB_RULES_DIR/route-state.json" set --mode off
  custom="$SB_RULES_DIR/cn-allow.list"
  printf '# handwritten\nExample.net\n' >"$custom"
  chmod 600 "$custom"
  if [[ "$first" == upgrade ]]; then ensure_base_config off 0 1; fi
  cmd_domain_list allow new.example.net >/dev/null
  grep -Fxq new.example.net "$custom" || fail "legacy list could not be edited"
  if [[ "$first" == changed ]]; then echo operator-edited >"$custom"; fi
  cmd_uninstall --keep-tcpfit
  if [[ "$first" == changed ]]; then
    [[ "$(cat "$custom")" == operator-edited ]] || fail "lost operator edit"
    originals=("$SB_RULES_DIR"/.sb-kit-original-cn-allow.list.*)
    [[ ${#originals[@]} == 1 && -f "${originals[0]}" ]] || fail "legacy original was not retained"
    custom="${originals[0]}"
  fi
  python3 - "$custom" <<'PYLIST'
import os, sys
from pathlib import Path
p = Path(sys.argv[1])
assert p.read_bytes() == b"# handwritten\nExample.net\n"
assert p.stat().st_mode & 0o777 == 0o600
assert p.stat().st_uid == os.getuid()
PYLIST
done

echo "install/uninstall safety OK"
