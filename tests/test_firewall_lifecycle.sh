#!/usr/bin/env bash
# Local state-machine tests. No real systemd, nftables, root access or network.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$ROOT/sbctl.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

export LIB_DIR="$ROOT/lib"
SB_DIR="$WORK/etc"
SB_CONF_DIR="$SB_DIR/conf"
SB_META_DIR="$SB_DIR/meta"
SB_STATE_DIR="$WORK/state"
export SB_UNIT="$WORK/units/sing-box.service"
NFT_DIR="$WORK/nft"
SB_BIN="$WORK/sing-box"
mkdir -p "$SB_CONF_DIR" "$SB_META_DIR" "$SB_STATE_DIR" "$WORK/units" "$WORK/tables" "$WORK/active"
printf '#!/bin/sh\nprintf "sing-box version 1.14.4\\n"\n' >"$SB_BIN"
chmod 755 "$SB_BIN"
need_root() { :; }
acquire_lock() { :; }
is_port_busy() { return 1; }
verify_domain_dns() { :; }
chown() { :; }

nft() {
  case "$1" in
    -c) [[ -s "$3" && ! -e "$WORK/reject-rule" ]] ;;
    -f)
      if [[ -e "$WORK/reject-next-nft-load" ]]; then
        rm "$WORK/reject-next-nft-load"
        return 1
      fi
      local name
      name=$(awk 'NR==1{print $3}' "$2")
      cp "$2" "$WORK/tables/$name"
      ;;
    list)
      if [[ "$2" == table ]]; then
        [[ -e "$WORK/tables/$4" ]]
      else
        local path
        for path in "$WORK/tables/"*; do
          [[ ! -f "$path" ]] || printf 'table inet %s\n' "${path##*/}"
        done
      fi
      ;;
    delete) rm "$WORK/tables/$4" ;;
    *) return 1 ;;
  esac
}

systemctl() {
  local action="$1" unit="${*: -1}"
  local table_name="${unit%.service}"
  printf '%s %s\n' "$action" "$unit" >>"$WORK/events"
  case "$action" in
    daemon-reload) : ;;
    enable)
      [[ ! -e "$WORK/reject-enable" ]] || return 1
      touch "$WORK/units/$unit.enabled"
      if grep -Fxq 'RequiredBy=sing-box.service' "$WORK/units/$unit"; then
        mkdir -p "$SB_UNIT.requires"
        ln -sf "../$unit" "$SB_UNIT.requires/$unit"
      fi
      ;;
    disable) rm -f "$WORK/units/$unit.enabled" "$SB_UNIT.requires/$unit" ;;
    reload-or-restart|start)
      [[ ! -e "$WORK/reject-rule-start" ]] || return 1
      nft -f "$NFT_DIR/$table_name.nft" && touch "$WORK/active/$unit"
      ;;
    stop)
      if [[ "$unit" == sing-box ]]; then
        [[ ! -e "$WORK/reject-stop" ]] || return 1
        rm -f "$WORK/listeners"
      fi
      rm -f "$WORK/active/$unit"
      ;;
    is-active) [[ -f "$WORK/active/$unit" ]] ;;
    *) return 1 ;;
  esac
}

validate_and_restart() {
  printf '%s\n' "restart sing-box" >>"$WORK/events"
  if [[ -f "$WORK/fail-next-restart" ]]; then
    rm "$WORK/fail-next-restart"
    return 1
  fi
  local path
  : >"$WORK/listeners"
  for path in "$SB_CONF_DIR/"*.json; do
    [[ ! -f "$path" ]] || basename "$path" .json >> "$WORK/listeners"
  done
  touch "$WORK/active/sing-box"
}

run_ctl() { (trap cleanup_paths EXIT; "$@") >"$WORK/last.log" 2>&1; }
expect_error() {
  if run_ctl "$@"; then
    echo "expected failure: $1" >&2
    exit 1
  fi
}
add_socks() {
  cmd_add socks --port "$1" --whitelist "$2" --ip 203.0.113.1 --country US --non-interactive
}
guard=sbkit_wl_socks_30101

for failure in reject-rule reject-enable reject-rule-start; do
  touch "$WORK/$failure"
  expect_error add_socks 30101 192.0.2.2
  rm "$WORK/$failure"
  [[ ! -e "$SB_CONF_DIR/socks-30101.json" && ! -e "$SB_META_DIR/socks-30101.json" ]]
  [[ ! -e "$WORK/tables/$guard" && ! -e "$WORK/units/$guard.service" ]]
  [[ ! -e "$WORK/active/sing-box" ]]
done

run_ctl add_socks 30101 192.0.2.2
grep -Fxq 'RequiredBy=sing-box.service' "$WORK/units/$guard.service"
grep -Fxq 'socks-30101' "$WORK/listeners"
grep -Fq '192.0.2.2' "$WORK/tables/$guard"
[[ -f "$WORK/units/$guard.service.enabled" ]]
# A v0.2.0 unit is active with an ExecStop that would remove its live guard.
rm "$SB_UNIT.requires/$guard.service"
sed -e 's/RequiredBy=sing-box.service/WantedBy=multi-user.target/' \
    -e '/ExecReload=/a\
ExecStop=/usr/sbin/nft delete table inet legacy' "$WORK/units/$guard.service" >"$WORK/old-unit"
cp "$WORK/old-unit" "$WORK/units/$guard.service"
touch "$WORK/reject-next-nft-load"
expect_error sync_legacy_whitelists
cmp "$WORK/old-unit" "$WORK/units/$guard.service"
[[ ! -L "$SB_UNIT.requires/$guard.service" ]]
grep -Fq '192.0.2.2' "$WORK/tables/$guard"

: >"$WORK/events"
run_ctl sync_legacy_whitelists
[[ -L "$SB_UNIT.requires/$guard.service" ]]
grep -Fxq 'RequiredBy=sing-box.service' "$WORK/units/$guard.service"
if grep -Eq "^(stop|restart|reload-or-restart) $guard.service$" "$WORK/events"; then exit 1; fi
: >"$WORK/events"
run_ctl sync_legacy_whitelists
if grep -Eq '^(enable|start|reload-or-restart|stop) ' "$WORK/events"; then exit 1; fi

cp "$WORK/tables/$guard" "$WORK/original-rule"
cp "$SB_META_DIR/socks-30101.json" "$WORK/original-meta"

touch "$WORK/fail-next-restart"
expect_error cmd_modify socks-30101 --whitelist 192.0.2.9
cmp "$WORK/original-rule" "$WORK/tables/$guard"
cmp "$WORK/original-meta" "$SB_META_DIR/socks-30101.json"
grep -Fxq 'socks-30101' "$WORK/listeners"

touch "$WORK/fail-next-restart"
expect_error add_socks 30102 192.0.2.3
[[ ! -e "$SB_CONF_DIR/socks-30102.json" && ! -e "$WORK/tables/sbkit_wl_socks_30102" ]]
grep -Fxq 'socks-30101' "$WORK/listeners"

run_ctl cmd_modify socks-30101 --port 30103 --whitelist 192.0.2.8
[[ ! -e "$WORK/tables/$guard" ]]
grep -Fxq 'socks-30103' "$WORK/listeners"
guard=sbkit_wl_socks_30103
grep -Fq '192.0.2.8' "$WORK/tables/$guard"

run_ctl cmd_add hy2 --domain hy.example.test --port 8443 --hop-range 35000:35010 --ip 203.0.113.1 --country US --non-interactive
hop=sbkit_hop_hy2_8443
cp "$WORK/tables/$hop" "$WORK/original-hop"
cp "$SB_META_DIR/hy2-8443.json" "$WORK/hop-meta"
expect_error cmd_modify hy2-8443 --hop-range 8400:8500
expect_error cmd_modify hy2-8443 --hop-range 35000:35100:35200
cmp "$WORK/original-hop" "$WORK/tables/$hop"
cmp "$WORK/hop-meta" "$SB_META_DIR/hy2-8443.json"
touch "$WORK/fail-next-restart"
expect_error cmd_del socks-30103
grep -Fxq 'socks-30103' "$WORK/listeners"
[[ -f "$WORK/tables/$guard" && -f "$SB_CONF_DIR/socks-30103.json" ]]
run_ctl cmd_del hy2-8443
[[ ! -e "$WORK/tables/$hop" ]]

touch "$WORK/reject-stop"
expect_error cmd_del socks-30103
rm "$WORK/reject-stop"
[[ -f "$SB_CONF_DIR/socks-30103.json" && -f "$WORK/tables/$guard" ]]
grep -Fxq 'socks-30103' "$WORK/listeners"

: >"$WORK/events"
run_ctl cmd_del socks-30103
grep -Fxq 'stop sing-box' "$WORK/events"
awk -v guard="$guard.service" '$1=="stop" && $2=="sing-box" { stopped=1 }
  $1=="disable" && $2==guard { if (!stopped) exit 1; removed=1 } END { if (!removed) exit 1 }' "$WORK/events"
[[ ! -e "$WORK/listeners" && ! -e "$WORK/tables/$guard" && ! -e "$SB_META_DIR/socks-30103.json" ]]

# The OS port probe returns free for a stopped service. Check the live tags
# before signing anything, even while rendering candidates in a private tree.
hy_args=(--self-signed --ip 127.0.0.1 --country US --non-interactive)
run_ctl cmd_add hy2 --port 38001 "${hy_args[@]}"
run_ctl cmd_add hy2 --port 38002 "${hy_args[@]}"
identities=( "$SB_STATE_DIR"/certs/identity-* )
expect_error cmd_add hy2 --port 38001 "${hy_args[@]}"
expect_error cmd_modify hy2-38002 --port 38001 --rotate-creds
after=( "$SB_STATE_DIR"/certs/identity-* )
[[ "${after[*]}" == "${identities[*]}" ]]

echo "firewall lifecycle tests passed"
