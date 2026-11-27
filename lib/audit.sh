#!/usr/bin/env bash
# lib/audit.sh — Read-only security, exposure & REALITY health audit for sing-box VPS.

set -euo pipefail

SB_BIN="/usr/local/bin/sing-box"
SB_CONF_DIR="/etc/sing-box/conf"
SB_LOG_DIR="/var/log/sing-box"

if [[ -t 1 ]]; then
  C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'
  C_CYAN='\033[0;36m'; C_NC='\033[0m'
else
  C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_NC=''
fi

ok()   { printf '%b[OK]%b   %s\n' "$C_GREEN" "$C_NC" "$*"; }
warn() { printf '%b[WARN]%b %s\n' "$C_YELLOW" "$C_NC" "$*"; }
fail() { printf '%b[RISK]%b %s\n' "$C_RED" "$C_NC" "$*"; }
hdr()  { printf '\n%b=== %s ===%b\n' "$C_CYAN" "$*" "$C_NC"; }

hdr "1. sing-box 核心与权限"
if [[ -x "$SB_BIN" ]]; then
  ok "版本: $("$SB_BIN" version 2>/dev/null | awk 'NR==1{print $3}')"
else
  fail "未找到 ${SB_BIN}"
fi

if systemctl is-active --quiet sing-box 2>/dev/null; then
  run_user=$(systemctl show -p User --value sing-box 2>/dev/null || echo "root")
  if [[ "$run_user" == "root" || -z "$run_user" ]]; then
    warn "sing-box 当前以 root 权限运行，建议切回非特权用户 sing-box"
  else
    ok "运行中 (User=${run_user})"
  fi
else
  warn "sing-box 未处于 active 状态"
fi

hdr "2. BBR / TCP 调优状态"
cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
initcwnd=$(ip -4 route show default 2>/dev/null | grep -oE 'initcwnd [0-9]+' | awk '{print $2}' | head -n1 || true)
if [[ "$cc" == "bbr" && "$qdisc" == "fq" ]]; then
  ok "拥塞控制=${cc}, qdisc=${qdisc}, initcwnd=${initcwnd:-默认}"
else
  warn "拥塞控制=${cc}, qdisc=${qdisc}（可运行 sb bbr 启用 BBR+fq）"
fi
if [[ -f /etc/sysctl.d/99-tcpfit.conf ]]; then
  ok "已由 tcpfit 纳管 (/etc/sysctl.d/99-tcpfit.conf)"
fi

hdr "3. 公网监听端口与常见暴露项"
if command -v ss >/dev/null 2>&1; then
  ss -tulnp | grep -vE '127\.0\.0\.1|\[::1\]' | head -n 30 || true
  if ss -tulnp | grep -q 'iperf3'; then
    fail "检测到公网常驻 iperf3 服务，极易被扫描滥用，建议关闭"
  fi
  if ss -tlnp | grep -qE ':2053\b|:54321\b'; then
    warn "检测到常见面板端口 (2053/54321) 监听，请确认未对公网裸露管理面板"
  fi
fi

hdr "4. REALITY 配置与回落一致性体检"
if compgen -G "${SB_CONF_DIR}/*.json" >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  python3 - "$SB_CONF_DIR" <<'PY'
import glob, json, os, subprocess, sys

conf_dir = sys.argv[1]
hot_snis = {"www.paypal.com", "www.amazon.com", "aws.amazon.com", "www.cloudflare.com", "dash.cloudflare.com"}
for path in sorted(glob.glob(os.path.join(conf_dir, "*.json"))):
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        continue
    for ib in data.get("inbounds", []):
        tag = ib.get("tag", os.path.basename(path))
        port = ib.get("listen_port")
        tls = ib.get("tls", {})
        reality = tls.get("reality", {})
        if reality.get("enabled"):
            sni = tls.get("server_name", "")
            sids = reality.get("short_id", [])
            mtd = reality.get("max_time_difference", "")
            print(f"[INFO] REALITY 节点 {tag}: port={port}, sni={sni}")
            if port != 443:
                print(f"[WARN] {tag} 使用非 443 端口 ({port})，如 443 空闲建议改回 443")
            if sni in hot_snis:
                print(f"[WARN] {tag} 使用了高频撞车域名 ({sni})，建议换冷门低延迟站")
            if not sids or "" in sids:
                print(f"[WARN] {tag} 允许空 short_id，建议配置随机 hex short_id")
            if not mtd:
                print(f"[WARN] {tag} 未设置 max_time_difference，建议设为 5m")
            try:
                out = subprocess.check_output(
                    ["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", sni, "-alpn", "h2,http/1.1"],
                    input=b"",
                    stderr=subprocess.STDOUT,
                    timeout=6,
                ).decode("utf-8", "ignore")
                if "TLSv1.3" in out and "Verify return code: 0 (ok)" in out:
                    print(f"[OK]   {tag} 本地回落探测正常 (TLSv1.3 + 真实上游证书)")
                else:
                    print(f"[WARN] {tag} 本地回落探测异常，请手动检查 openssl s_client 输出")
            except Exception as exc:
                print(f"[WARN] {tag} 本地回落探测失败: {exc}")
PY
else
  warn "未发现任何入站配置文件"
fi

hdr "5. 日志体积、轮转与近期异常统计"
if [[ -f /etc/logrotate.d/sing-box ]]; then
  ok "已配置 /etc/logrotate.d/sing-box"
else
  warn "未检测到 /etc/logrotate.d/sing-box，日志存在涨爆磁盘风险"
fi

for lf in "${SB_LOG_DIR}"/*.log; do
  [[ -f "$lf" ]] || continue
  sz_mb=$(du -m "$lf" | awk '{print $1}')
  if [[ "$sz_mb" -ge 50 ]]; then
    warn "日志 ${lf} 体积较大 (${sz_mb} MB)"
  else
    ok "日志 ${lf} 大小正常 (${sz_mb} MB)"
  fi
  fm=$(grep -c "flow mismatch" "$lf" 2>/dev/null || true)
  inv=$(grep -c "REALITY: processed invalid connection" "$lf" 2>/dev/null || true)
  [[ "$fm" -gt 0 ]] && warn "  检测到 ${fm} 次 flow mismatch（请排查漏填 xtls-rprx-vision 的客户端）"
  [[ "$inv" -gt 0 ]] && warn "  检测到 ${inv} 次无效 REALITY 握手（扫描器探测或客户端参数不一致）"
done

hdr "6. 回国阻断路由与规则集状态"
if [[ -f /etc/sing-box/config.json ]]; then
  manager="$(dirname "${BASH_SOURCE[0]}")/../sbctl.sh"
  if ! bash "$manager" cn; then
    warn "路由状态读取不完整，请检查上方错误。"
  fi
fi

hdr "7. SSH 基础安全"
if command -v sshd >/dev/null 2>&1; then
  pa=$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2; exit}' || true)
  if [[ "$pa" == "yes" ]]; then
    warn "SSH 当前允许密码登录（PasswordAuthentication yes），建议改用密钥登录"
  elif [[ "$pa" == "no" ]]; then
    ok "SSH 已关闭密码登录（仅密钥）"
  fi
fi
