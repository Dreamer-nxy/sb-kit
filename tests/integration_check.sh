#!/usr/bin/env bash
# tests/integration_check.sh — Generate all 6 protocols (plus modify/regen) and validate
# them with a REAL sing-box binary via `sing-box check`.
#
# Usage: tests/integration_check.sh /path/to/sing-box
set -euo pipefail

SB_BIN="${1:?usage: $0 /path/to/sing-box}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/lib/config_gen.py"
SB_VER="$("$SB_BIN" version | awk 'NR==1{print $3}')"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
C="${WORK}/conf" M="${WORK}/meta" S="${WORK}/state"
mkdir -p "$C" "$M" "$S"

common=(--ip 203.0.113.10 --country US --conf-dir "$C" --meta-dir "$M" --state-dir "$S" --sb-ver "$SB_VER" --sb-bin "$SB_BIN")

echo "== sing-box ${SB_VER}: generating configs"
python3 "$GEN" base-config --out "${WORK}/config.json" --log-file "${WORK}/error.log"
python3 "$GEN" add --proto vless-reality --port 443 --sni www.gentoo.org "${common[@]}" >/dev/null
python3 "$GEN" add --proto hy2 --port 8443 --domain hy.example.com --hop-range 35000:36000 --masquerade https://www.debian.org "${common[@]}" >/dev/null
SB_CF_TOKEN=dummy-cf-token python3 "$GEN" add --proto hy2 --port 8444 --domain hy2.example.com "${common[@]}" >/dev/null
python3 "$GEN" add --proto hy2 --port 8445 --self-signed "${common[@]}" >/dev/null
python3 "$GEN" add --proto naive --port 9443 --domain nv.example.com "${common[@]}" >/dev/null
python3 "$GEN" add --proto anytls --port 10443 --domain at.example.com "${common[@]}" >/dev/null
python3 "$GEN" add --proto anytls --port 10444 --self-signed "${common[@]}" >/dev/null
python3 "$GEN" add --proto ss2022 --port 38001 --whitelist "9.9.9.9,2001:db8::1" "${common[@]}" >/dev/null
python3 "$GEN" add --proto socks --port 38002 --whitelist 9.9.9.9 "${common[@]}" >/dev/null

echo "== sing-box ${SB_VER}: check (add)"
"$SB_BIN" check -c "${WORK}/config.json" -C "$C"

python3 "$GEN" modify --tag hy2-8444 --port 8446 --conf-dir "$C" --meta-dir "$M" --state-dir "$S" --sb-ver "$SB_VER" >/dev/null
python3 "$GEN" modify --tag hy2-8445 --port 8447 --conf-dir "$C" --meta-dir "$M" --state-dir "$S" --sb-ver "$SB_VER" >/dev/null
grep -q dummy-cf-token "${C}/hy2-8446.json" || { echo "FAIL: modify dropped DNS-01 token"; exit 1; }

python3 "$GEN" regen --conf-dir "$C" --meta-dir "$M" --state-dir "$S" --sb-ver "$SB_VER" --sb-bin "$SB_BIN" >/dev/null
echo "== sing-box ${SB_VER}: check (modify + regen)"
"$SB_BIN" check -c "${WORK}/config.json" -C "$C"

# Also validate CN block (21 v2fly categories + explicit supplements + custom lists)
# against real upstream .srs rule-sets when SB_CHECK_CN_RULES != 0.
if [[ "${SB_CHECK_CN_RULES:-1}" != "0" ]]; then
  R="${SB_RULES_CACHE_DIR:-${WORK}/rules}"
  mkdir -p "$R"
  ALLOW="${WORK}/cn-allow.list"
  BLOCK="${WORK}/cn-block.list"
  printf 'example.cn\n' >"$ALLOW"
  printf 'blocked.example.com\n' >"$BLOCK"
  echo "== sing-box ${SB_VER}: check CN block (on)"
  while IFS='|' read -r _ fn url; do
    [[ -n "$fn" ]] || continue
    if [[ ! -s "${R}/${fn}" ]]; then
      dl_ok=0
      for attempt in 1 2 3; do
        if curl -fsSL --connect-timeout 10 --max-time 30 "$url" -o "${R}/${fn}.part" && [[ -s "${R}/${fn}.part" ]]; then
          mv -f "${R}/${fn}.part" "${R}/${fn}"
          dl_ok=1
          break
        fi
        rm -f "${R}/${fn}.part"
        sleep "$attempt"
      done
      [[ "$dl_ok" == "1" ]] || { echo "FAIL: could not download $url" >&2; exit 1; }
    fi
  done < <(python3 "$GEN" route-plan --mode on)
  python3 "$GEN" base-config --out "${WORK}/config-cn-on.json" --log-file "${WORK}/error.log" \
    --cn-mode on --rules-dir "$R" --allow-file "$ALLOW" --block-file "$BLOCK"
  "$SB_BIN" check -c "${WORK}/config-cn-on.json" -C "$C"
fi
echo "== sing-box ${SB_VER}: OK"
