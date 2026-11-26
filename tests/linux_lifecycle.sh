#!/usr/bin/env bash
# Run as root on a disposable systemd VM. This test uses the public installer
# and the installed sbctl CLI, and checks the running service and kernel rules.
set -euo pipefail

version=${1:?usage: linux_lifecycle.sh SING_BOX_VERSION}
repo=$(cd "$(dirname "$0")/.." && pwd)
ctl=/usr/local/bin/sbctl
core=/usr/local/bin/sing-box
service=sing-box.service
config=/etc/sing-box
guard=sbkit_wl_socks_39183
failed_guard=sbkit_wl_socks_39184
dropin=/etc/systemd/system/${failed_guard}.service.d

fail() { echo "FAIL: $*" >&2; exit 1; }
listening() { [[ -n "$(ss -H -lnt "sport = :$1")" ]]; }
wait_for_listener() {
  local i
  for ((i=0; i<50; i++)); do
    if listening "$1"; then return 0; fi
    sleep 0.1
  done
  return 1
}
[[ $(id -u) == 0 && -d /run/systemd/system ]] || fail "requires a root shell in a systemd VM"
for path in "$ctl" "$core" "$config" /var/lib/sing-box /var/log/sing-box /usr/local/lib/sb-kit "$dropin"; do
  [[ ! -e "$path" ]] || fail "expected a fresh VM; found $path"
done
[[ $(systemctl show "$service" -p LoadState --value) == not-found ]] || fail "existing service"

echo "== Install sing-box $version through sbctl install"
bash "$repo/sbctl.sh" install --version "$version" --proto socks --port 39182 \
  --ip 127.0.0.1 --no-tune --non-interactive >/dev/null
[[ $("$core" version | awk 'NR==1 {print $3}') == "$version" ]] || fail "installed version"
systemctl is-active --quiet "$service" && listening 39182 || fail "initial listener"
[[ $(systemctl show "$service" -p User --value) == sing-box ]] || fail "runtime user"
bash "$repo/tests/integration_check.sh" "$core"
fixtures=$(mktemp -d)
trap 'rm -rf "$fixtures"' EXIT
cp "$core" "$fixtures/native-core"

echo "== Reject a firewall unit failure and retain the original service"
mkdir -p "$dropin"
printf '[Service]\nExecStartPre=/bin/false\n' >"$dropin/fail-start.conf"
systemctl daemon-reload
if "$ctl" add socks --port 39184 --ip 127.0.0.1 --country US \
    --whitelist 192.0.2.1 --non-interactive >/dev/null; then
  fail "add accepted a failed firewall unit"
fi
[[ ! -e "$config/conf/socks-39184.json" && ! -e "$config/meta/socks-39184.json" ]] || fail "failed node persisted"
if listening 39184; then fail "failed node opened a listener"; fi
systemctl is-active --quiet "$service" && listening 39182 || fail "lost original listener"
rm "$dropin/fail-start.conf"
rmdir "$dropin"
systemctl daemon-reload

echo "== Add a protected node, restart, regenerate and remove it"
"$ctl" add socks --port 39183 --ip 127.0.0.1 --country US \
  --whitelist 192.0.2.1,2001:db8::1 --non-interactive >/dev/null
[[ " $(systemctl show "$service" -p Requires --value) " == *" ${guard}.service "* ]] || fail "missing required guard"
systemctl restart "$service"
systemctl is-active --quiet "${guard}.service" && wait_for_listener 39183 || fail "protected listener"
rules=$(nft list table inet "$guard")
[[ "$rules" == *192.0.2.1* && "$rules" == *2001:db8::1* && "$rules" == *drop* ]] || fail "missing guard rules"
echo "== A cold start must require the existing firewall unit"
systemctl stop "$service" "${guard}.service"
guard_dropin=/etc/systemd/system/${guard}.service.d
mkdir "$guard_dropin"
printf '[Service]\nExecStartPre=/bin/false\n' >"$guard_dropin/fail-start.conf"
systemctl daemon-reload
if systemctl start "$service"; then fail "cold start succeeded without a working guard"; fi
if listening 39183; then fail "protected listener opened after guard failure"; fi
rm "$guard_dropin/fail-start.conf"
rmdir "$guard_dropin"
systemctl daemon-reload
systemctl reset-failed "${guard}.service"
systemctl start "$service"
wait_for_listener 39183 || fail "listener did not recover with its guard"
"$ctl" modify socks-39183 --remark ci-protected >/dev/null

echo "== A failed rebuild must leave both live directories unchanged"
printf '{' >"$config/meta/zz-invalid.json"
before=$(sha256sum "$config"/conf/*.json "$config"/meta/*.json)
if "$ctl" regen >/dev/null; then fail "regen accepted corrupt metadata"; fi
[[ $(sha256sum "$config"/conf/*.json "$config"/meta/*.json) == "$before" ]] || fail "regen changed the live files"
rm "$config/meta/zz-invalid.json"
# Fail only the candidate's first start. The rollback must restore the original
# bytes (including whitespace) and start the previous configuration.
main_dropin=/etc/systemd/system/sing-box.service.d
mkdir -p "$main_dropin"
printf '\n' >>"$config/conf/socks-39182.json"
before=$(sha256sum "$config"/conf/*.json "$config"/meta/*.json)
touch /var/lib/sing-box/.ci-fail-first-start
cat >"$main_dropin/ci-start-failure.conf" <<'UNIT'
[Service]
ExecStartPre=/bin/sh -c 'if test -f /var/lib/sing-box/.ci-fail-first-start; then rm /var/lib/sing-box/.ci-fail-first-start; exit 1; fi'
UNIT
systemctl daemon-reload
if "$ctl" regen >/dev/null; then fail "regen accepted an unsuccessful service start"; fi
[[ $(sha256sum "$config"/conf/*.json "$config"/meta/*.json) == "$before" ]] || fail "service rollback changed original files"
systemctl is-active --quiet "$service" && wait_for_listener 39182 || fail "rollback lost original service"
rm "$main_dropin/ci-start-failure.conf"
rmdir "$main_dropin"
systemctl daemon-reload
"$ctl" regen >/dev/null
systemctl is-active --quiet "$service" && listening 39183 || fail "regen lost listener"
"$ctl" del socks-39183 >/dev/null
if listening 39183 || nft list table inet "$guard" >/dev/null 2>&1; then fail "node or rule survived deletion"; fi
listening 39182 || fail "deletion removed the other node"

echo "== Reuse a self-signed node's old port without replacing its certificate"
hy_args=(--self-signed --ip 127.0.0.1 --country US --non-interactive)
"$ctl" add hy2 --port 39187 "${hy_args[@]}" >/dev/null
old_cert=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["self_cert"])' "$config/meta/hy2-39187.json")
old_hash=$(sha256sum "$old_cert")
"$ctl" modify hy2-39187 --port 39188 >/dev/null
"$ctl" add hy2 --port 39187 "${hy_args[@]}" >/dev/null
[[ $(sha256sum "$old_cert") == "$old_hash" ]] || fail "port reuse overwrote the certificate"
for port in 39187 39188; do
  [[ -n $(ss -H -lnu "sport = :$port") ]] || fail "missing Hy2 UDP listener on $port"
done

echo "== Uninstall, preserve an unrelated file, refuse unmanaged uninstall"
"$ctl" modify socks-39182 --whitelist 192.0.2.2 >/dev/null
nft list table inet sbkit_wl_socks_39182 >/dev/null
printf '%s\n' preserve >"$config/operator-note.txt"
"$ctl" uninstall --keep-tcpfit >/dev/null
if listening 39182 || systemctl is-active --quiet "$service"; then fail "service survived uninstall"; fi
[[ $(systemctl show "$service" -p LoadState --value) == not-found ]] || fail "unit survived uninstall"
if nft list table inet sbkit_wl_socks_39182 >/dev/null 2>&1; then fail "uninstall left a kernel filter"; fi
[[ ! -e "$ctl" && ! -e "$core" && ! -e "$config/config.json" && ! -e "$config/.managed-by-sb-kit" ]] || fail "managed installation remained"
[[ $(cat "$config/operator-note.txt") == preserve ]] || fail "operator file lost"
[[ ! -e "$old_cert" ]] || fail "managed certificate survived uninstall"
if bash "$repo/sbctl.sh" uninstall --keep-tcpfit >/dev/null; then fail "unmanaged uninstall accepted"; fi
[[ $(cat "$config/operator-note.txt") == preserve ]] || fail "unmanaged data changed"
rm "$config/operator-note.txt"
rmdir "$config"

echo "== Take over an existing non-root installation and restore it on uninstall"
native_unit=/etc/systemd/system/sing-box.service
native_group=$(id -gn nobody)
install -m 755 "$fixtures/native-core" "$core"
install -d -m 750 -o root -g "$native_group" "$config"
install -d -m 750 -o nobody -g "$native_group" /var/log/sing-box /var/lib/sing-box
cat >"$config/config.json" <<'JSON'
{"log":{"output":"/var/log/sing-box/native.log"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":39186}]}
JSON
chown root:"$native_group" "$config/config.json"
chmod 640 "$config/config.json"
cp "$config/config.json" "$fixtures/native-config"
cat >"$native_unit" <<'UNIT'
[Unit]
Description=Existing private sing-box
[Service]
User=nobody
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
[Install]
WantedBy=multi-user.target
UNIT
cp "$native_unit" "$fixtures/native-unit"
systemctl daemon-reload
systemctl enable --now "$service"
wait_for_listener 39186 || fail "native fixture failed to start"
bash "$repo/sbctl.sh" install --version "$version" --proto socks --port 39182 \
  --ip 127.0.0.1 --no-tune --non-interactive >/dev/null
listening 39182 || fail "takeover failed"
"$ctl" uninstall --keep-tcpfit >/dev/null
cmp "$native_unit" "$fixtures/native-unit"
cmp "$config/config.json" "$fixtures/native-config"
cmp "$core" "$fixtures/native-core"
systemctl is-enabled --quiet "$service" && wait_for_listener 39186 || fail "native service not restored"
systemctl disable --now "$service"
rm "$native_unit" "$core" "$config/config.json" /var/log/sing-box/native.log
rmdir "$config" /var/log/sing-box /var/lib/sing-box
systemctl daemon-reload
echo "== Linux lifecycle OK (sing-box $version)"
