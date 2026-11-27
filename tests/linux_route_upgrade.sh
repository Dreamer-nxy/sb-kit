#!/usr/bin/env bash
# Destructive integration test for a fresh systemd VM, after the fresh-install test.
set -euo pipefail

version=${1:?usage: linux_route_upgrade.sh CORE_VERSION V0.2.2_SOURCE}
legacy=${2:?missing v0.2.2 checkout}
repo=$(cd "$(dirname "$0")/.." && pwd)
ctl=/usr/local/bin/sb
legacy_ctl=/usr/local/bin/sbctl
core=/usr/local/bin/sing-box
config=/etc/sing-box
base=$config/config.json
rules=$config/rules
state=$rules/route-state.json
service=sing-box.service
timer=sbkit-rules-update.timer
unit=sbkit-rules-update.service
dropin=/etc/systemd/system/sing-box.service.d
marker=/var/lib/sing-box/.ci-route-fail-once
port=39272
fail() { echo "FAIL: $*" >&2; exit 1; }
listening() { [[ -n $(ss -H -lnt "sport = :$port") ]]; }
mode() { python3 "$repo/lib/config_gen.py" route-mode --config "$base" --rules-dir "$rules"; }
assert_custom_config() {
  python3 - "$base" <<'PY'
import json, sys
with open(sys.argv[1]) as source:
    config = json.load(source)
assert config["log"]["level"] == "warn"
assert {"type": "local", "tag": "operator-dns"} in config["dns"]["servers"]
assert {"type": "direct", "tag": "operator-direct"} in config["outbounds"]
assert {"domain": ["operator.invalid"], "action": "route", "outbound": "operator-direct"} in config["route"]["rules"]
PY
}

[[ $(id -u) == 0 && -d /run/systemd/system ]] || fail "requires a disposable root systemd VM"
[[ $(bash "$legacy/sbctl.sh" --version) == 'sb-kit 0.2.2 ('* ]] || fail "wrong legacy checkout"
for path in "$ctl" "$legacy_ctl" "$core" "$config" "$dropin" /usr/local/lib/sb-kit /var/lib/sing-box /var/log/sing-box; do
  [[ ! -e "$path" && ! -L "$path" ]] || fail "expected a clean VM; found $path"
done
for name in "$service" "$timer" "$unit"; do
  [[ $(systemctl show -p LoadState --value "$name") == not-found ]] || fail "existing unit $name"
done
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

echo "== Install the v0.2.2 release with its real geoip-cn policy"
bash "$legacy/sbctl.sh" install --version "$version" --proto socks --port "$port" --ip 127.0.0.1 \
  --block-cn --no-tune --non-interactive >/dev/null
[[ $("$legacy_ctl" --version) == "sb-kit 0.2.2 (sing-box: $version)" ]] && listening || fail "old installation not serving"
[[ -s "$rules/geoip-cn.srs" && ! -e "$state" ]] || fail "missing genuine legacy policy"
python3 - "$base" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
config = json.loads(path.read_text())
config["log"]["level"] = "warn"
config["dns"] = {"servers": [{"type": "local", "tag": "operator-dns"}]}
config["outbounds"].append({"type": "direct", "tag": "operator-direct"})
config["route"]["rules"].append({"domain": ["operator.invalid"], "action": "route", "outbound": "operator-direct"})
path.write_text(json.dumps(config, indent=2) + "\n")
PY
"$core" check -c "$base" -C "$config/conf"
systemctl restart "$service"
cp "$base" "$scratch/legacy.json"
node=$(sha256sum "$config/meta/socks-$port.json")
old_rule=$(sha256sum "$rules/geoip-cn.srs")
invocation=$(systemctl show "$service" -p InvocationID --value)
printf 'keep\n' >"$rules/operator-private.list"
chmod 600 "$rules/operator-private.list"

echo "== Upgrade the installed CLI without changing the active legacy policy"
bash "$repo/sbctl.sh" sync
[[ -x "$ctl" && ! -e "$legacy_ctl" && ! -L "$legacy_ctl" ]] || fail "CLI did not switch from sbctl to sb"
cmp "$base" "$scratch/legacy.json"
[[ $(systemctl show "$service" -p InvocationID --value) == "$invocation" ]] || fail "sync restarted the service"
[[ $(mode) == legacy && $("$ctl" cn) == *"旧版 geoip-cn"* ]] || fail "legacy status not reported"
"$ctl" cn update --quiet
cmp "$base" "$scratch/legacy.json"

echo "== Fail a candidate start and verify restoration of the running legacy policy"
mkdir "$dropin"
touch "$marker"
cat >"$dropin/fail-route-once.conf" <<'UNIT'
[Service]
ExecStartPre=/bin/sh -c 'if test -f /var/lib/sing-box/.ci-route-fail-once; then rm /var/lib/sing-box/.ci-route-fail-once; exit 1; fi'
UNIT
systemctl daemon-reload
systemctl reset-failed "$service"
if "$ctl" cn update; then fail "accepted a failed migration"; fi
[[ ! -e "$marker" ]] || fail "the candidate never reached the injected start failure"
cmp "$base" "$scratch/legacy.json"
[[ $(mode) == legacy && $(sha256sum "$rules/geoip-cn.srs") == "$old_rule" ]] || fail "lost old rules"
[[ ! -e "$state" ]] || fail "failed migration published a new state"
[[ ! -e "$config/.sb-kit-route.pending" ]] || fail "rollback left an incomplete transaction"
[[ $(systemctl show -p LoadState --value "$timer") == not-found ]] || fail "failed migration left a timer"
systemctl is-active --quiet "$service" && listening || fail "rollback did not resume the old listener"
rm "$dropin/fail-route-once.conf"
rmdir "$dropin"
systemctl daemon-reload
systemctl reset-failed "$service"

echo "== Migrate explicitly, check the pinned release, regenerate with custom settings"
"$ctl" cn update
[[ $(mode) == on ]] || fail "migration did not enable the targeted policy"
commit=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["geosite_commit"])' "$state")
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || fail "rules lack a full revision"
sample=geosite-category-netdisk-cn.srs
plan=$(python3 "$repo/lib/config_gen.py" route-plan --mode on --commit "$commit")
verified=0
while IFS='|' read -r _ name _; do
  curl --fail --silent --show-error --location --retry 3 --retry-all-errors --max-time 45 \
    "https://raw.githubusercontent.com/SagerNet/sing-geosite/$commit/$name" -o "$scratch/pinned.srs"
  cmp "$scratch/pinned.srs" "$rules/$name"
  ((verified+=1))
done <<< "$plan"
[[ "$verified" == 21 ]] || fail "unexpected rule count $verified"
echo "== Verified $verified installed rule files against upstream commit $commit"
systemctl is-active --quiet "$timer" && systemctl is-enabled --quiet "$timer" || fail "weekly timer inactive"
grep -Fxq "ExecStart=$ctl cn update --quiet" "/etc/systemd/system/$unit" || fail "weekly updater does not use sb"
systemctl stop "$timer"
systemctl is-enabled --quiet "$timer" || fail "stopping the timer changed its enablement"
timer_status=$("$ctl" cn)
[[ "$timer_status" == *"运行=inactive"* && "$timer_status" == *"启用=enabled"* ]] || fail "enabled but stopped timer reported healthy"
systemctl start "$timer"
[[ $("$ctl" cn) == *"已启用并运行"* ]] || fail "active timer not reported healthy"
assert_custom_config
"$ctl" rebuild >/dev/null
assert_custom_config
systemctl is-active --quiet "$service" && listening || fail "migration lost the listener"

echo "== Run the actual weekly updater with sing-box stopped"
systemctl stop "$service"
systemctl start "$unit"
[[ $(systemctl show -p Result --value "$unit") == success ]] || fail "updater service failed"
if systemctl is-active --quiet "$service" || listening; then fail "weekly update started a stopped service"; fi
assert_custom_config
"$ctl" allow fixture.example >/dev/null
printf 'invalid domain with spaces\n' >"$rules/cn-allow.list"
echo "== Disable routing with a malformed list and preserve the operator's edit"
"$ctl" cn off
[[ $(mode) == off ]] || fail "cn off left managed rules active"
[[ $(cat "$rules/cn-allow.list") == 'invalid domain with spaces' ]] || fail "cn off rewrote a malformed list"
assert_custom_config
systemctl start "$service"
[[ $(sha256sum "$config/meta/socks-$port.json") == "$node" ]] || fail "node credentials changed"

echo "== Uninstall the upgraded kit and retain the operator's unrelated file"
"$ctl" uninstall --keep-tcpfit >/dev/null
for path in "$ctl" "$legacy_ctl" "$core" /usr/local/lib/sb-kit "$base" "$state" "$rules/$sample" "$rules/geoip-cn.srs"; do
  [[ ! -e "$path" && ! -L "$path" ]] || fail "uninstall left $path"
done
for name in "$service" "$timer" "$unit"; do
  [[ $(systemctl show -p LoadState --value "$name") == not-found ]] || fail "uninstall left $name"
done
[[ $(cat "$rules/operator-private.list") == keep && $(stat -c %a "$rules/operator-private.list") == 600 ]] || fail "foreign rule changed"
[[ $(cat "$rules/cn-allow.list") == 'invalid domain with spaces' ]] || fail "uninstall discarded the operator's edit"
if listening; then fail "uninstall left the listener"; fi
rm "$rules/operator-private.list" "$rules/cn-allow.list"
rmdir "$rules" "$config"
echo "== v0.2.2 Linux route upgrade, update, rollback and uninstall OK (sing-box $version)"
