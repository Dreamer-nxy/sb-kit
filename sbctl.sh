#!/usr/bin/env bash
# sbctl.sh — Pure sing-box + tcpfit lean deployment & interactive TUI manager.
#
# Protocols (single sing-box process, zero web panel, pure link output, no QR):
#   vless-reality | hy2 | naive | anytls | ss2022 | socks
#
# Network tuning:
#   Kylin010/tcpfit (pinned v0.5.9 + SHA-256 verified + TCPFIT_NO_TELEMETRY=1)

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
if [[ ! -d "${LIB_DIR}" && -d "/usr/local/lib/sb-kit" ]]; then
  LIB_DIR="/usr/local/lib/sb-kit"
fi

SB_BIN="/usr/local/bin/sing-box"
SB_USER="sing-box"
SB_GROUP="sing-box"
SB_DIR="/etc/sing-box"
SB_CONFIG="${SB_DIR}/config.json"
SB_CONF_DIR="${SB_DIR}/conf"
SB_META_DIR="${SB_DIR}/meta"
SB_RULES_DIR="${SB_DIR}/rules"
SB_LOG_DIR="/var/log/sing-box"
SB_STATE_DIR="/var/lib/sing-box"
SB_BACKUP_ROOT="/var/backups/sb-kit"
SB_UNIT="/etc/systemd/system/sing-box.service"
SB_LOGROTATE="/etc/logrotate.d/sing-box"
SB_CTL_DST="/usr/local/bin/sbctl"

TCPFIT_BIN="/usr/local/bin/tcpfit"
TCPFIT_VERSION="v0.5.9"
TCPFIT_URL="https://raw.githubusercontent.com/Kylin010/tcpfit/${TCPFIT_VERSION}/tcpfit.sh"
TCPFIT_SHA256="8331cc40950229a3280ce32406330a85b1a3d21ba398a4db3dc7e25c39783741"

GEOIP_CN_SRS_URL="https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"

if [[ -t 1 ]]; then
  C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'
  C_CYAN='\033[0;36m'; C_DIM='\033[0;90m'; C_BOLD='\033[1m'; C_NC='\033[0m'
else
  C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_DIM=''; C_BOLD=''; C_NC=''
fi

info() { printf '%b[*]%b %s\n' "$C_CYAN" "$C_NC" "$*"; }
ok()   { printf '%b[+]%b %s\n' "$C_GREEN" "$C_NC" "$*"; }
warn() { printf '%b[!]%b %s\n' "$C_YELLOW" "$C_NC" "$*" >&2; }
die()  { printf '%b[x]%b %s\n' "$C_RED" "$C_NC" "$*" >&2; exit 1; }

need_root() {
  [[ "$(id -u)" -eq 0 ]] || die "请使用 root 权限运行（例如 sudo sbctl ...）"
}

need_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "缺少依赖命令: $c"
  done
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "不支持的 CPU 架构: $(uname -m)" ;;
  esac
}

detect_public_ip() {
  local ip=""
  for url in "https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip"; do
    ip=$(curl -fsS4 --max-time 4 "$url" 2>/dev/null | tr -d '[:space:]' || true)
    [[ -n "$ip" ]] && { echo "$ip"; return 0; }
  done
  for url in "https://api64.ipify.org" "https://ipv6.icanhazip.com"; do
    ip=$(curl -fsS6 --max-time 4 "$url" 2>/dev/null | tr -d '[:space:]' || true)
    [[ -n "$ip" ]] && { echo "$ip"; return 0; }
  done
  die "无法自动获取本机公网 IP，请使用 --ip <IP> 显式指定"
}

detect_country_and_rtt() {
  python3 "${LIB_DIR}/sni_probe.py" --country-info 2>/dev/null || echo "VPS|160"
}

sb_version() {
  if [[ -x "$SB_BIN" ]]; then
    "$SB_BIN" version 2>/dev/null | awk 'NR==1{print $3}'
  else
    echo ""
  fi
}

is_port_busy() {
  local port="$1" proto="${2:-tcp}"
  command -v ss >/dev/null 2>&1 || return 1
  local flag="-tlnH"
  [[ "$proto" == "udp" ]] && flag="-ulnH"
  ss "$flag" 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${port}\$"
}

pick_free_port() {
  local preferred="$1" proto="${2:-tcp}" non_interactive="${3:-0}"
  if ! is_port_busy "$preferred" "$proto"; then
    echo "$preferred"
    return 0
  fi

  if [[ "$non_interactive" == "1" || ! -t 0 ]]; then
    die "端口 ${proto}/${preferred} 已被占用（本脚本绝不强杀已有进程，请通过 --port 指定空闲端口）"
  fi

  warn "端口 ${proto}/${preferred} 已被其他进程占用（绝不强杀原服务）" >&2
  local suggestion=$((20000 + RANDOM % 35000))
  while is_port_busy "$suggestion" "$proto"; do
    suggestion=$((20000 + RANDOM % 35000))
  done

  local chosen=""
  while true; do
    read -rp "请输入新的空闲端口 (回车默认 ${suggestion}): " chosen
    chosen="${chosen:-$suggestion}"
    if ! [[ "$chosen" =~ ^[0-9]+$ ]] || [[ "$chosen" -lt 1 || "$chosen" -gt 65535 ]]; then
      warn "端口必须是 1-65535 的整数" >&2
      continue
    fi
    if is_port_busy "$chosen" "$proto"; then
      warn "端口 ${proto}/${chosen} 仍被占用，请换一个" >&2
      continue
    fi
    echo "$chosen"
    return 0
  done
}

verify_domain_dns() {
  local domain="$1" expected_ip="$2"
  local resolved=""
  if command -v dig >/dev/null 2>&1; then
    resolved=$(dig +short +time=4 +tries=2 "$domain" A "$domain" AAAA 2>/dev/null | tr '\n' ' ')
  elif command -v getent >/dev/null 2>&1; then
    resolved=$(getent ahosts "$domain" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
  fi
  if [[ -n "$resolved" && "$resolved" != *"$expected_ip"* ]]; then
    warn "域名 ${domain} 当前解析为 (${resolved% })，未包含本机 IP (${expected_ip})；若开着 Cloudflare 小黄云请先切为灰云（仅 DNS）"
  fi
}

ensure_base_deps() {
  local missing=()
  local c
  for c in curl tar python3 openssl; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  [[ ${#missing[@]} -eq 0 ]] && return 0

  info "安装缺失基础依赖（不做全量 upgrade）: ${missing[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q "${missing[@]}" ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q "${missing[@]}" ca-certificates
  else
    die "请先手动安装基础依赖: ${missing[*]}"
  fi
}

install_self() {
  if [[ "${SCRIPT_DIR}" != "/usr/local/lib/sb-kit" && -f "${SCRIPT_DIR}/sbctl.sh" ]]; then
    mkdir -p /usr/local/lib/sb-kit
    cp -f "${SCRIPT_DIR}/lib/"* /usr/local/lib/sb-kit/
    chmod 755 /usr/local/lib/sb-kit/*.py /usr/local/lib/sb-kit/*.sh 2>/dev/null || true
    cp -f "${SCRIPT_DIR}/sbctl.sh" "${SB_CTL_DST}"
    chmod 755 "${SB_CTL_DST}"
    ok "管理命令已就绪: ${SB_CTL_DST}"
  fi
}

backup_existing_singbox() {
  if [[ -f "$SB_CONFIG" || -d "$SB_CONF_DIR" ]] && [[ ! -f "${SB_DIR}/.managed-by-sb-kit" ]]; then
    local ts bk_dir
    ts=$(date +"%Y%m%d-%H%M%S")
    bk_dir="${SB_BACKUP_ROOT}/pre-install-${ts}"
    mkdir -p "$bk_dir"
    cp -a "$SB_DIR" "${bk_dir}/etc-sing-box" 2>/dev/null || true
    [[ -f /lib/systemd/system/sing-box.service ]] && cp -a /lib/systemd/system/sing-box.service "$bk_dir/" || true
    [[ -f "$SB_UNIT" ]] && cp -a "$SB_UNIT" "$bk_dir/" || true
    warn "检测到已有旧版 /etc/sing-box 配置，已自动冷备份至: ${bk_dir}"
  fi
}

install_singbox_binary() {
  local target_ver="${1:-latest}"
  local arch api_url meta tag asset_name dl_url expected_sha
  arch=$(detect_arch)

  if [[ "$target_ver" == "latest" ]]; then
    api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
  else
    target_ver="v${target_ver#v}"
    api_url="https://api.github.com/repos/SagerNet/sing-box/releases/tags/${target_ver}"
  fi

  info "查询 SagerNet/sing-box 官方 Release (${target_ver})..."
  meta=$(curl -fsSL --max-time 15 "$api_url") || die "获取 sing-box Release 元数据失败"

  IFS='|' read -r tag asset_name dl_url expected_sha < <(
    ARCH="$arch" python3 - "$meta" <<'PY'
import json, os, sys
arch = os.environ["ARCH"]
data = json.loads(sys.argv[1])
tag = data.get("tag_name", "")
ver = tag.lstrip("v")
want = f"sing-box-{ver}-linux-{arch}.tar.gz"
for a in data.get("assets", []):
    if a.get("name") == want:
        digest = a.get("digest") or ""
        sha = digest.split("sha256:", 1)[1] if digest.startswith("sha256:") else ""
        print(f"{tag}|{want}|{a.get('browser_download_url','')}|{sha}")
        sys.exit(0)
sys.exit(1)
PY
  ) || die "在 Release 中未找到适配 linux-${arch} 的资产"

  local tmpdir tarball
  tmpdir=$(mktemp -d)
  trap 'rm -rf "${tmpdir:-}"' RETURN
  tarball="${tmpdir}/${asset_name}"

  info "下载 sing-box ${tag} (${asset_name})..."
  curl -fsSL --max-time 120 "$dl_url" -o "$tarball" || die "下载 sing-box 失败"

  if [[ -n "$expected_sha" ]]; then
    local actual_sha
    actual_sha=$(sha256sum "$tarball" | awk '{print $1}')
    [[ "$actual_sha" == "$expected_sha" ]] || die "SHA-256 校验失败！期望=${expected_sha} 实际=${actual_sha}"
    ok "SHA-256 校验通过 (${actual_sha:0:16}...)"
  else
    warn "GitHub Release 未返回 digest，跳过 SHA-256 校验"
  fi

  tar -xzf "$tarball" -C "$tmpdir"
  local extracted
  extracted=$(find "$tmpdir" -maxdepth 2 -type f -name "sing-box" | head -n 1)
  [[ -n "$extracted" ]] || die "解压后未找到 sing-box 二进制"

  chmod 755 "$extracted"
  mv -f "$extracted" "${SB_BIN}.new"
  mv -f "${SB_BIN}.new" "${SB_BIN}"
  ok "已安装 ${SB_BIN} ($(sb_version))"
}

ensure_singbox_system() {
  if ! id -u "$SB_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SB_USER" 2>/dev/null || \
      adduser --system --no-create-home --disabled-login --group "$SB_USER" 2>/dev/null || true
  fi

  mkdir -p "$SB_DIR" "$SB_CONF_DIR" "$SB_META_DIR" "$SB_RULES_DIR" "$SB_LOG_DIR" "$SB_STATE_DIR"
  touch "${SB_DIR}/.managed-by-sb-kit"
  chown root:"$SB_GROUP" "$SB_DIR" "$SB_CONF_DIR" "$SB_RULES_DIR"
  chmod 750 "$SB_DIR" "$SB_CONF_DIR" "$SB_RULES_DIR"
  chown root:root "$SB_META_DIR"
  chmod 700 "$SB_META_DIR"
  chown -R "$SB_USER":"$SB_GROUP" "$SB_LOG_DIR" "$SB_STATE_DIR"
  chmod 750 "$SB_LOG_DIR" "$SB_STATE_DIR"

  cat >"$SB_UNIT" <<EOF
[Unit]
Description=sing-box service (managed by sb-kit)
Documentation=https://sing-box.sagernet.org/
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=${SB_USER}
Group=${SB_GROUP}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${SB_LOG_DIR} ${SB_STATE_DIR}
ExecStart=${SB_BIN} run -c ${SB_CONFIG} -C ${SB_CONF_DIR}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  cat >"$SB_LOGROTATE" <<EOF
${SB_LOG_DIR}/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    maxsize 20M
}
EOF

  systemctl daemon-reload
  systemctl enable sing-box >/dev/null 2>&1 || true
}

ensure_base_config() {
  local block_cn="${1:-0}"
  local cn_srs=""
  if [[ "$block_cn" == "1" ]]; then
    cn_srs="${SB_RULES_DIR}/geoip-cn.srs"
    info "下载 geoip-cn.srs 规则集..."
    curl -fsSL --max-time 30 "$GEOIP_CN_SRS_URL" -o "${cn_srs}.tmp" || die "下载 geoip-cn.srs 失败"
    mv -f "${cn_srs}.tmp" "$cn_srs"
    chown root:"$SB_GROUP" "$cn_srs"
    chmod 640 "$cn_srs"
  fi

  local tmpcfg
  tmpcfg=$(mktemp "${SB_DIR}/.config.json.XXXXXX")
  python3 "${LIB_DIR}/config_gen.py" base-config \
    --out "$tmpcfg" \
    --log-file "${SB_LOG_DIR}/error.log" \
    ${cn_srs:+--cn-srs "$cn_srs"}
  chown root:"$SB_GROUP" "$tmpcfg"
  chmod 640 "$tmpcfg"
  mv -f "$tmpcfg" "$SB_CONFIG"
  ok "基础配置与安全路由已写入: ${SB_CONFIG}（回国阻断: $([[ "$block_cn" == "1" ]] && echo 开启 || echo 关闭)）"
}

validate_and_restart() {
  info "执行 sing-box check 配置校验..."
  "$SB_BIN" check -c "$SB_CONFIG" -C "$SB_CONF_DIR" || return 1
  systemctl restart sing-box
  sleep 1
  systemctl is-active --quiet sing-box || {
    warn "sing-box 启动失败，请查看: journalctl -u sing-box -n 30"
    return 1
  }
  ok "sing-box 校验通过并已重启"
}

install_tcpfit() {
  mkdir -p /var/lib/tcpfit
  touch /var/lib/tcpfit/no-telemetry

  if [[ -x "$TCPFIT_BIN" ]]; then
    local cur_ver
    cur_ver=$(grep -m1 '^VERSION=' "$TCPFIT_BIN" 2>/dev/null | cut -d'"' -f2 || true)
    if [[ "v${cur_ver}" == "$TCPFIT_VERSION" ]]; then
      ok "tcpfit ${TCPFIT_VERSION} 已就绪（已禁遥测）"
      return 0
    fi
  fi

  info "安装 Kylin010/tcpfit ${TCPFIT_VERSION}（强校 SHA-256 + 禁用遥测）..."
  local tmp
  tmp=$(mktemp "/usr/local/bin/.tcpfit.XXXXXX")
  trap 'rm -f "${tmp:-}"' RETURN
  curl -fsSL --max-time 30 "$TCPFIT_URL" -o "$tmp" || die "下载 tcpfit 失败"

  local actual_sha
  actual_sha=$(sha256sum "$tmp" | awk '{print $1}')
  [[ "$actual_sha" == "$TCPFIT_SHA256" ]] || die "tcpfit SHA-256 校验失败！期望=${TCPFIT_SHA256} 实际=${actual_sha}"

  bash -n "$tmp" || die "tcpfit 语法检查失败"
  chmod 755 "$tmp"
  mv -f "$tmp" "$TCPFIT_BIN"
  ok "tcpfit ${TCPFIT_VERSION} 安装完成（SHA-256 校验通过，已禁用遥测）"
}

cmd_tune() {
  need_root
  local bw="500" rtt="" swap_size="auto" do_rollback=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bw)       bw="$2"; shift 2 ;;
      --rtt)      rtt="$2"; shift 2 ;;
      --swap)     swap_size="$2"; shift 2 ;;
      --no-swap)  swap_size=""; shift ;;
      --rollback) do_rollback=1; shift ;;
      -h|--help)
        echo "用法: sbctl tune [--bw 500] [--rtt auto|160] [--swap auto|1G|--no-swap] [--rollback]"
        return 0
        ;;
      *) die "未知参数: $1" ;;
    esac
  done

  install_tcpfit
  if [[ "$do_rollback" -eq 1 ]]; then
    TCPFIT_NO_TELEMETRY=1 "$TCPFIT_BIN" rollback
    return 0
  fi

  if [[ -z "$rtt" || "$rtt" == "auto" ]]; then
    local cc_rtt cc
    cc_rtt=$(detect_country_and_rtt)
    cc="${cc_rtt%%|*}"
    rtt="${cc_rtt##*|}"
    info "按本机地区 (${cc}) 自动匹配参考 RTT: ${rtt} ms"
  fi

  info "执行 tcpfit 基础调优 (role=proxy, bw=${bw}Mbps, rtt=${rtt}ms)..."
  TCPFIT_NO_TELEMETRY=1 "$TCPFIT_BIN" tune --role proxy --bw "$bw" --rtt "$rtt"

  if [[ "$swap_size" == "auto" ]]; then
    local ram_mb
    ram_mb=$(awk '/^MemTotal:/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 2048)
    if [[ "$ram_mb" -le 1024 ]] && [[ -z "$(swapon --show 2>/dev/null || true)" ]]; then
      info "检测到小内存机 (${ram_mb} MB) 且无 Swap，自动兜底 1G Swap..."
      TCPFIT_NO_TELEMETRY=1 "$TCPFIT_BIN" harden --swap 1G || warn "Swap 创建未生效（可能受容器/文件系统限制）"
    fi
  elif [[ -n "$swap_size" ]]; then
    info "配置 Swap (${swap_size})..."
    TCPFIT_NO_TELEMETRY=1 "$TCPFIT_BIN" harden --swap "$swap_size"
  fi
  ok "BBR / TCP 调优完成（随时可运行 sbctl tune --rollback 还原出厂快照）"
}

select_reality_sni() {
  local sni_arg="${1:-}" non_interactive="${2:-0}" skip_cn="${3:-0}"
  local -a skip_flag=()
  [[ "$skip_cn" == "1" ]] && skip_flag=(--skip-cn)

  if [[ -n "$sni_arg" && "$sni_arg" != "auto" ]]; then
    local chk
    chk=$(python3 "${LIB_DIR}/sni_probe.py" --verify "$sni_arg" "${skip_flag[@]}" || true)
    if [[ "$chk" == OK\|* ]]; then
      ok "SNI 四重体检通过: ${sni_arg} (${chk#OK|*|})" >&2
    else
      warn "SNI 体检提示: ${sni_arg} (${chk#WARN|*|})" >&2
    fi
    echo "$sni_arg"
    return 0
  fi

  if [[ "$non_interactive" == "1" || ! -t 0 ]]; then
    info "自动筛选当前地区低延迟优质 SNI..." >&2
    local res picked detail
    res=$(python3 "${LIB_DIR}/sni_probe.py" --auto "${skip_flag[@]}")
    picked=$(echo "$res" | cut -d'|' -f2)
    detail=$(echo "$res" | cut -d'|' -f3-)
    ok "自动选定 SNI: ${picked} (${detail})" >&2
    echo "$picked"
    return 0
  fi

  info "正在并发测速当前地区与全球兜底 SNI 候选池..." >&2
  local list_out
  list_out=$(python3 "${LIB_DIR}/sni_probe.py" --list || true)
  if [[ -z "$list_out" ]]; then
    warn "自动测速无结果，回退默认 SNI: www.gentoo.org" >&2
    echo "www.gentoo.org"
    return 0
  fi

  local -a hosts=()
  local idx=1 grp host rtt desc
  while IFS='|' read -r grp host rtt desc; do
    [[ -n "$host" ]] || continue
    hosts+=("$host")
    printf '  %2d) %-22s (%6s ms | %s | %s)\n' "$idx" "$host" "$rtt" "$grp" "$desc" >&2
    idx=$((idx + 1))
  done <<< "$list_out"
  printf '   0) 手动输入自定义域名\n' >&2

  local pick=""
  read -rp "请选择 SNI 编号 [回车默认 1]: " pick
  pick="${pick:-1}"

  local chosen=""
  if [[ "$pick" == "0" ]]; then
    read -rp "请输入自定义 SNI 域名: " chosen
    chosen="${chosen:-${hosts[0]}}"
  elif [[ "$pick" =~ ^[0-9]+$ ]] && [[ "$pick" -ge 1 && "$pick" -le "${#hosts[@]}" ]]; then
    chosen="${hosts[$((pick - 1))]}"
  else
    chosen="${hosts[0]}"
  fi

  local chk
  chk=$(python3 "${LIB_DIR}/sni_probe.py" --verify "$chosen" "${skip_flag[@]}" || true)
  if [[ "$chk" == OK\|* ]]; then
    ok "SNI 四重体检通过: ${chosen} (${chk#OK|*|})" >&2
  else
    warn "SNI 体检提示: ${chosen} (${chk#WARN|*|})" >&2
  fi
  echo "$chosen"
}

remove_port_whitelist() {
  local tag="$1"
  local tbl="sbkit_${tag//[^a-zA-Z0-9_]/_}"
  if systemctl list-unit-files "${tbl}.service" >/dev/null 2>&1; then
    systemctl disable --now "${tbl}.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/${tbl}.service" "/etc/nftables.d/${tbl}.nft"
    systemctl daemon-reload
  fi
}

setup_port_whitelist() {
  local tag="$1" port="$2" ips="$3"
  need_cmd nft
  local tbl="sbkit_${tag//[^a-zA-Z0-9_]/_}"
  mkdir -p /etc/nftables.d
  local nft_file="/etc/nftables.d/${tbl}.nft"
  cat >"$nft_file" <<EOF
table inet ${tbl}
delete table inet ${tbl}
table inet ${tbl} {
    set allowed_v4 {
        type ipv4_addr
        flags interval
        elements = { 127.0.0.0/8, ${ips} }
    }
    chain input {
        type filter hook input priority filter; policy accept;
        tcp dport ${port} ip saddr @allowed_v4 accept
        udp dport ${port} ip saddr @allowed_v4 accept
        tcp dport ${port} drop
        udp dport ${port} drop
    }
}
EOF
  nft -f "$nft_file"
  cat >"/etc/systemd/system/${tbl}.service" <<EOF
[Unit]
Description=sb-kit port whitelist (${tag})
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f ${nft_file}
ExecStop=/usr/sbin/nft delete table inet ${tbl}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "${tbl}.service" >/dev/null 2>&1 || true
  ok "已启用来源 IP 白名单 (${ips})，仅锁定端口 ${port}"
}

remove_hy2_hopping() {
  local tag="$1"
  local svc="sbkit-hop-${tag//[^a-zA-Z0-9_-]/_}"
  if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1; then
    systemctl disable --now "${svc}.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/${svc}.service"
    systemctl daemon-reload
  fi
}

setup_hy2_hopping() {
  local tag="$1" port="$2" hop_range="$3"
  need_cmd iptables
  local svc="sbkit-hop-${tag//[^a-zA-Z0-9_-]/_}"
  local start_p="${hop_range%%[:-]*}"
  local end_p="${hop_range##*[:-]}"
  [[ "$start_p" =~ ^[0-9]+$ && "$end_p" =~ ^[0-9]+$ && "$start_p" -lt "$end_p" ]] || die "无效端口跳跃范围: ${hop_range}（示例: 35000:36000）"

  cat >"/etc/systemd/system/${svc}.service" <<EOF
[Unit]
Description=sb-kit Hysteria2 UDP port hopping (${start_p}:${end_p} -> ${port})
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -t nat -C PREROUTING -p udp -m addrtype --dst-type LOCAL --dport ${start_p}:${end_p} -j REDIRECT --to-ports ${port} 2>/dev/null || iptables -t nat -A PREROUTING -p udp -m addrtype --dst-type LOCAL --dport ${start_p}:${end_p} -j REDIRECT --to-ports ${port}'
ExecStop=/bin/sh -c 'iptables -t nat -D PREROUTING -p udp -m addrtype --dst-type LOCAL --dport ${start_p}:${end_p} -j REDIRECT --to-ports ${port} 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "${svc}.service"
  ok "已启用 Hysteria2 UDP 端口跳跃: ${start_p}-${end_p} -> ${port}"
}

print_node_result() {
  local tag="$1" gen_out="$2"
  local uri quic_uri browser_line
  uri=$(echo "$gen_out" | awk -F= '$1=="URI"{sub(/^URI=/,""); print; exit}')
  quic_uri=$(echo "$gen_out" | awk -F= '$1=="QUIC_URI"{sub(/^QUIC_URI=/,""); print; exit}')
  browser_line=$(echo "$gen_out" | awk -F= '$1=="BROWSER"{sub(/^BROWSER=/,""); print; exit}')

  printf '\n%b==================================================================%b\n' "$C_CYAN" "$C_NC"
  printf '%b节点已就绪 [%s]%b\n' "$C_GREEN" "$tag" "$C_NC"
  printf '%s\n' "$uri"
  [[ -n "$quic_uri" ]] && printf '%s\n' "$quic_uri"
  [[ -n "$browser_line" ]] && printf '指纹浏览器格式: %s\n' "$browser_line"
  printf '%b==================================================================%b\n\n' "$C_CYAN" "$C_NC"
}

cmd_add() {
  local proto="${1:-}"
  [[ -n "$proto" ]] || die "请指定协议: vless-reality | hy2 | naive | anytls | ss2022 | socks"
  shift

  local port="" sni="" domain="" cert="" key="" email="" cf_token="" remark="" ip="" country=""
  local hop_range="" whitelist="" self_signed=0 generate_only=0 out_dir=""
  local non_interactive=0 skip_cn=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --port)            port="$2"; shift 2 ;;
      --sni)             sni="$2"; shift 2 ;;
      --domain)          domain="$2"; shift 2 ;;
      --cert)            cert="$2"; shift 2 ;;
      --key)             key="$2"; shift 2 ;;
      --email)           email="$2"; shift 2 ;;
      --cf-token)        cf_token="$2"; shift 2 ;;
      --remark)          remark="$2"; shift 2 ;;
      --ip)              ip="$2"; shift 2 ;;
      --country)         country="$2"; shift 2 ;;
      --hop-range)       hop_range="$2"; shift 2 ;;
      --whitelist)       whitelist="$2"; shift 2 ;;
      --self-signed)     self_signed=1; shift ;;
      --generate-only)   generate_only=1; shift ;;
      --out-dir)         out_dir="$2"; shift 2 ;;
      --non-interactive) non_interactive=1; shift ;;
      --skip-cn)         skip_cn=1; shift ;;
      -h|--help)
        echo "用法: sbctl add <vless-reality|hy2|naive|anytls|ss2022|socks> [--port N] [--sni HOST] [--domain HOST] [--cf-token TOKEN] [--hop-range A:B] [--whitelist IP1,IP2]"
        return 0
        ;;
      *) die "未知参数: $1" ;;
    esac
  done

  if [[ "$generate_only" -eq 0 ]]; then
    need_root
    [[ -x "$SB_BIN" ]] || die "未检测到 sing-box，请先运行: sbctl install"
  fi

  case "$proto" in
    vless-reality|reality|vless)
      proto="vless-reality"
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 VLESS-Reality 监听端口 [回车默认 443，可自由修改]: " port
      fi
      port="${port:-443}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" tcp "$non_interactive")
      sni=$(select_reality_sni "$sni" "$non_interactive" "$skip_cn")
      ;;
    hy2|hysteria2)
      proto="hy2"
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 Hysteria2 UDP 监听端口 [回车默认 8443]: " port
      fi
      port="${port:-8443}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" udp "$non_interactive")
      if [[ -z "$domain" && -z "$cert" && "$self_signed" -eq 0 ]]; then
        if [[ "$non_interactive" -eq 1 || ! -t 0 ]]; then
          die "hy2 推荐提供 --domain <灰云子域名>（自动 ACME 正规证书），或显式加 --self-signed"
        fi
        read -rp "请输入自有域名（Cloudflare 灰云 A 记录，留空则改用随机自签证书）: " domain
        [[ -z "$domain" ]] && self_signed=1
      fi
      if [[ -n "$domain" && -z "$cf_token" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "Cloudflare API Token（可选，留空走 80 端口 HTTP-01 自动签发）: " cf_token
      fi
      if [[ -z "$hop_range" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "UDP 端口跳跃区间（可选，如 35000:36000，留空不启用）: " hop_range
      fi
      ;;
    naive)
      proto="naive"
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 Naive 监听端口 [回车默认 8443，若 443 空闲也可填 443]: " port
      fi
      port="${port:-8443}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" tcp "$non_interactive")
      if [[ -z "$domain" && -z "$cert" ]]; then
        if [[ "$non_interactive" -eq 1 || ! -t 0 ]]; then
          die "naive 必须提供 --domain <灰云子域名> 或 --cert/--key"
        fi
        read -rp "请输入 Naive 自有域名（必填，Cloudflare 灰云 A 记录）: " domain
        [[ -n "$domain" ]] || die "naive 协议必须提供域名以签发正规 TLS 证书"
      fi
      if [[ -n "$domain" && -z "$cf_token" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "Cloudflare API Token（可选，留空走 80 端口 HTTP-01 自动签发）: " cf_token
      fi
      ;;
    anytls)
      proto="anytls"
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 AnyTLS 监听端口 [回车默认 8443]: " port
      fi
      port="${port:-8443}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" tcp "$non_interactive")
      if [[ -z "$domain" && -z "$cert" && "$self_signed" -eq 0 ]]; then
        if [[ "$non_interactive" -eq 1 || ! -t 0 ]]; then
          die "anytls 推荐提供 --domain <灰云子域名>（自动 ACME），或显式加 --self-signed"
        fi
        read -rp "请输入自有域名（Cloudflare 灰云 A 记录，留空则改用随机自签证书）: " domain
        [[ -z "$domain" ]] && self_signed=1
      fi
      ;;
    ss2022|ss)
      proto="ss2022"
      local def_ss=$((25000 + RANDOM % 30000))
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 SS-2022 监听端口 [回车默认随机 ${def_ss}]: " port
      fi
      port="${port:-$def_ss}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" tcp "$non_interactive")
      if [[ -z "$whitelist" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "允许连入的前置机白名单 IP（多个用逗号分隔，留空不设）: " whitelist
      fi
      ;;
    socks|socks5)
      proto="socks"
      local def_sk=$((25000 + RANDOM % 30000))
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 Socks5 监听端口 [回车默认随机 ${def_sk}]: " port
      fi
      port="${port:-$def_sk}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" tcp "$non_interactive")
      if [[ -z "$whitelist" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "来源 IP 白名单（强烈建议填写固定出口/中转 IP，多个逗号分隔，留空不设）: " whitelist
      fi
      ;;
    *)
      die "不支持的协议: ${proto}（可选: vless-reality | hy2 | naive | anytls | ss2022 | socks）"
      ;;
  esac

  [[ -n "$ip" ]] || ip=$(detect_public_ip)
  if [[ -z "$country" ]]; then
    local cc_rtt
    cc_rtt=$(detect_country_and_rtt)
    country="${cc_rtt%%|*}"
  fi
  if [[ -n "$domain" && "$generate_only" -eq 0 ]]; then
    verify_domain_dns "$domain" "$ip"
  fi

  local conf_dir="$SB_CONF_DIR" meta_dir="$SB_META_DIR" state_dir="$SB_STATE_DIR"
  if [[ "$generate_only" -eq 1 ]]; then
    out_dir="${out_dir:-$(pwd)/sb-kit-preview}"
    conf_dir="${out_dir}/conf"
    meta_dir="${out_dir}/meta"
    state_dir="${out_dir}/state"
    mkdir -p "$conf_dir" "$meta_dir" "$state_dir"
  fi

  local sb_ver
  sb_ver=$(sb_version)
  sb_ver="${sb_ver:-1.14.4}"

  local -a py_args=(
    "${LIB_DIR}/config_gen.py" add
    --proto "$proto"
    --port "$port"
    --ip "$ip"
    --country "$country"
    --conf-dir "$conf_dir"
    --meta-dir "$meta_dir"
    --state-dir "$state_dir"
    --sb-ver "$sb_ver"
  )
  [[ -x "$SB_BIN" ]] && py_args+=(--sb-bin "$SB_BIN")
  [[ -n "$sni" ]] && py_args+=(--sni "$sni")
  [[ -n "$domain" ]] && py_args+=(--domain "$domain")
  [[ -n "$cert" ]] && py_args+=(--cert "$cert")
  [[ -n "$key" ]] && py_args+=(--key "$key")
  [[ -n "$email" ]] && py_args+=(--email "$email")
  [[ -n "$cf_token" ]] && py_args+=(--cf-token "$cf_token")
  [[ -n "$remark" ]] && py_args+=(--remark "$remark")
  [[ -n "$hop_range" ]] && py_args+=(--hop-range "$hop_range")
  [[ -n "$whitelist" ]] && py_args+=(--whitelist "$whitelist")
  [[ "$self_signed" -eq 1 ]] && py_args+=(--self-signed)

  local gen_out tag
  gen_out=$(python3 "${py_args[@]}")
  tag=$(echo "$gen_out" | awk -F= '$1=="TAG"{print $2; exit}')

  if [[ "$generate_only" -eq 1 ]]; then
    ok "干跑配置已生成于: ${out_dir}"
    print_node_result "$tag" "$gen_out"
    return 0
  fi

  chown root:"$SB_GROUP" "${SB_CONF_DIR}/${tag}.json"
  chmod 640 "${SB_CONF_DIR}/${tag}.json"
  chmod 600 "${SB_META_DIR}/${tag}.json"
  if [[ "$self_signed" -eq 1 && -d "${SB_STATE_DIR}/certs" ]]; then
    chown -R "$SB_USER":"$SB_GROUP" "${SB_STATE_DIR}/certs"
    chmod 640 "${SB_STATE_DIR}/certs/"*.key 2>/dev/null || true
  fi

  if ! validate_and_restart; then
    rm -f "${SB_CONF_DIR}/${tag}.json" "${SB_META_DIR}/${tag}.json"
    die "新节点未通过 sing-box check，已自动回滚该节点文件"
  fi

  if [[ ("$proto" == "ss2022" || "$proto" == "socks") && -n "$whitelist" ]]; then
    setup_port_whitelist "$tag" "$port" "$whitelist"
  fi
  if [[ "$proto" == "hy2" && -n "$hop_range" ]]; then
    setup_hy2_hopping "$tag" "$port" "$hop_range"
  fi

  print_node_result "$tag" "$gen_out"
}

pick_existing_tag() {
  local -a tags=()
  local f
  for f in "${SB_META_DIR}"/*.json; do
    [[ -f "$f" ]] || continue
    tags+=("$(basename "$f" .json)")
  done
  [[ ${#tags[@]} -gt 0 ]] || die "当前没有任何已配置的节点"
  local i
  for i in "${!tags[@]}"; do
    printf '  %d) %s\n' "$((i + 1))" "${tags[$i]}" >&2
  done
  local pick=""
  read -rp "请选择节点编号: " pick
  [[ "$pick" =~ ^[0-9]+$ && "$pick" -ge 1 && "$pick" -le "${#tags[@]}" ]] || die "无效编号"
  echo "${tags[$((pick - 1))]}"
}

cmd_modify() {
  need_root
  local tag="${1:-}"
  if [[ -z "$tag" || "$tag" == --* ]]; then
    tag=$(pick_existing_tag)
  else
    shift
  fi

  [[ -f "${SB_META_DIR}/${tag}.json" ]] || die "找不到节点元数据: ${tag}"

  local new_port="" new_sni="" new_remark="" new_wl="" clear_wl=0 rotate=0
  local has_flags=0
  while [[ $# -gt 0 ]]; do
    has_flags=1
    case "$1" in
      --port)            new_port="$2"; shift 2 ;;
      --sni)             new_sni="$2"; shift 2 ;;
      --remark)          new_remark="$2"; shift 2 ;;
      --whitelist)       new_wl="$2"; shift 2 ;;
      --clear-whitelist) clear_wl=1; shift ;;
      --rotate-creds)    rotate=1; shift ;;
      -h|--help)
        echo "用法: sbctl modify <tag> [--port N] [--sni auto|HOST] [--rotate-creds] [--remark NAME] [--whitelist IP1,IP2 | --clear-whitelist]"
        return 0
        ;;
      *) die "未知参数: $1" ;;
    esac
  done

  local cur_proto
  cur_proto=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['proto'])" "${SB_META_DIR}/${tag}.json")

  if [[ "$has_flags" -eq 0 ]]; then
    printf '\n正在修改节点 [%s] (%s):\n' "$tag" "$cur_proto"
    printf '  1) 修改监听端口\n'
    [[ "$cur_proto" == "vless-reality" ]] && printf '  2) 更换 Reality SNI（重新测速体检或手填）\n'
    printf '  3) 重置密钥 / UUID / 账密\n'
    printf '  4) 修改节点备注\n'
    [[ "$cur_proto" == "ss2022" || "$cur_proto" == "socks" ]] && printf '  5) 修改 / 清空来源 IP 白名单\n'
    local act=""
    read -rp "请选择修改项: " act
    case "$act" in
      1) read -rp "请输入新端口: " new_port ;;
      2) new_sni=$(select_reality_sni "" 0 0) ;;
      3) rotate=1 ;;
      4) read -rp "请输入新备注: " new_remark ;;
      5)
        read -rp "请输入新白名单 IP（多个逗号分隔，输入 clear 清空）: " new_wl
        if [[ "$new_wl" == "clear" ]]; then
          clear_wl=1; new_wl=""
        fi
        ;;
      *) die "无效选择" ;;
    esac
  else
    [[ "$new_sni" == "auto" ]] && new_sni=$(select_reality_sni "auto" 1 0)
  fi

  if [[ -n "$new_port" ]]; then
    local ptype="tcp"
    [[ "$cur_proto" == "hy2" ]] && ptype="udp"
    new_port=$(pick_free_port "$new_port" "$ptype" "$has_flags")
  fi

  local snap_dir
  snap_dir=$(mktemp -d)
  trap 'rm -rf "${snap_dir:-}"' RETURN
  cp -a "${SB_CONF_DIR}" "${snap_dir}/conf"
  cp -a "${SB_META_DIR}" "${snap_dir}/meta"

  local sb_ver
  sb_ver=$(sb_version)
  local -a py_args=(
    "${LIB_DIR}/config_gen.py" modify
    --tag "$tag"
    --conf-dir "$SB_CONF_DIR"
    --meta-dir "$SB_META_DIR"
    --state-dir "$SB_STATE_DIR"
    --sb-ver "${sb_ver:-1.14.4}"
  )
  [[ -x "$SB_BIN" ]] && py_args+=(--sb-bin "$SB_BIN")
  [[ -n "$new_port" ]] && py_args+=(--port "$new_port")
  [[ -n "$new_sni" ]] && py_args+=(--sni "$new_sni")
  [[ -n "$new_remark" ]] && py_args+=(--remark "$new_remark")
  [[ -n "$new_wl" ]] && py_args+=(--whitelist "$new_wl")
  [[ "$clear_wl" -eq 1 ]] && py_args+=(--clear-whitelist)
  [[ "$rotate" -eq 1 ]] && py_args+=(--rotate-creds)

  local gen_out new_tag final_port final_wl
  gen_out=$(python3 "${py_args[@]}")
  new_tag=$(echo "$gen_out" | awk -F= '$1=="TAG"{print $2; exit}')
  final_port=$(echo "$gen_out" | awk -F= '$1=="PORT"{print $2; exit}')
  final_wl=$(echo "$gen_out" | awk -F= '$1=="WHITELIST"{print $2; exit}')

  chown root:"$SB_GROUP" "${SB_CONF_DIR}/${new_tag}.json"
  chmod 640 "${SB_CONF_DIR}/${new_tag}.json"
  chmod 600 "${SB_META_DIR}/${new_tag}.json"

  if ! validate_and_restart; then
    rm -rf "${SB_CONF_DIR:?}"/* "${SB_META_DIR:?}"/*
    cp -a "${snap_dir}/conf/." "${SB_CONF_DIR}/"
    cp -a "${snap_dir}/meta/." "${SB_META_DIR}/"
    systemctl restart sing-box 2>/dev/null || true
    die "修改后的配置未通过 sing-box check，已自动恢复原配置"
  fi

  if [[ "$cur_proto" == "ss2022" || "$cur_proto" == "socks" ]]; then
    if [[ "$new_tag" != "$tag" || "$clear_wl" -eq 1 ]]; then
      remove_port_whitelist "$tag"
    fi
    if [[ -n "$final_wl" ]]; then
      setup_port_whitelist "$new_tag" "$final_port" "$final_wl"
    fi
  fi

  print_node_result "$new_tag" "$gen_out"
}

cmd_links() {
  local meta_dir="${1:-$SB_META_DIR}"
  python3 "${LIB_DIR}/config_gen.py" links --meta-dir "$meta_dir"
}

cmd_yaml() {
  local meta_dir="${1:-$SB_META_DIR}"
  python3 "${LIB_DIR}/config_gen.py" yaml --meta-dir "$meta_dir"
}

cmd_del() {
  need_root
  local target="${1:-}"
  [[ -n "$target" ]] || target=$(pick_existing_tag)

  local conf_file="${SB_CONF_DIR}/${target}.json"
  [[ -f "$conf_file" || -f "${SB_META_DIR}/${target}.json" ]] || die "找不到节点: ${target}"

  rm -f "$conf_file" "${SB_META_DIR}/${target}.json"
  remove_port_whitelist "$target"
  remove_hy2_hopping "$target"

  if compgen -G "${SB_CONF_DIR}/*.json" >/dev/null 2>&1; then
    validate_and_restart || die "删除后 sing-box 校验失败"
  else
    systemctl stop sing-box 2>/dev/null || true
    warn "已删除最后一个节点并停止 sing-box"
  fi
  ok "已删除节点: ${target}"
}

cmd_route() {
  need_root
  local action="${1:-status}"
  case "$action" in
    block-cn-on)
      ensure_base_config 1
      compgen -G "${SB_CONF_DIR}/*.json" >/dev/null 2>&1 && validate_and_restart
      ;;
    block-cn-off)
      ensure_base_config 0
      compgen -G "${SB_CONF_DIR}/*.json" >/dev/null 2>&1 && validate_and_restart
      ;;
    status|*)
      if [[ -f "$SB_CONFIG" ]] && grep -q '"geoip-cn"' "$SB_CONFIG"; then
        ok "当前回国 IP 阻断: 已开启（geoip-cn）"
      else
        info "当前回国 IP 阻断: 已关闭"
      fi
      ;;
  esac
}

cmd_install() {
  need_root
  local sb_ver="latest" proto="vless-reality" port="" sni="" domain="" ip=""
  local block_cn=0 do_tune=1 bw="500" rtt="auto" swap_size="auto"
  local non_interactive=0 skip_cn=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)         sb_ver="$2"; shift 2 ;;
      --proto)           proto="$2"; shift 2 ;;
      --port)            port="$2"; shift 2 ;;
      --sni)             sni="$2"; shift 2 ;;
      --domain)          domain="$2"; shift 2 ;;
      --ip)              ip="$2"; shift 2 ;;
      --block-cn)        block_cn=1; shift ;;
      --no-tune)         do_tune=0; shift ;;
      --bw)              bw="$2"; shift 2 ;;
      --rtt)             rtt="$2"; shift 2 ;;
      --swap)            swap_size="$2"; shift 2 ;;
      --no-swap)         swap_size=""; shift ;;
      --non-interactive) non_interactive=1; shift ;;
      --skip-cn)         skip_cn=1; shift ;;
      -h|--help)
        echo "用法: sbctl install [--proto vless-reality|hy2|naive|anytls|ss2022|socks] [--port 443] [--sni auto|HOST] [--bw 500] [--rtt auto|160] [--no-tune] [--block-cn]"
        return 0
        ;;
      *) die "未知参数: $1" ;;
    esac
  done

  ensure_base_deps
  backup_existing_singbox
  install_self
  install_singbox_binary "$sb_ver"
  ensure_singbox_system
  ensure_base_config "$block_cn"

  if [[ "$do_tune" -eq 1 ]]; then
    local -a tune_args=(--bw "$bw" --rtt "$rtt")
    if [[ -n "$swap_size" ]]; then
      tune_args+=(--swap "$swap_size")
    else
      tune_args+=(--no-swap)
    fi
    cmd_tune "${tune_args[@]}"
  fi

  local -a add_args=("$proto")
  [[ -n "$port" ]] && add_args+=(--port "$port")
  [[ -n "$sni" ]] && add_args+=(--sni "$sni")
  [[ -n "$domain" ]] && add_args+=(--domain "$domain")
  [[ -n "$ip" ]] && add_args+=(--ip "$ip")
  [[ "$non_interactive" -eq 1 ]] && add_args+=(--non-interactive)
  [[ "$skip_cn" -eq 1 ]] && add_args+=(--skip-cn)

  cmd_add "${add_args[@]}"
}

cmd_update() {
  need_root
  local target_ver="${1:-latest}"
  install_singbox_binary "$target_ver"
  if [[ -f "$SB_CONFIG" ]] && compgen -G "${SB_CONF_DIR}/*.json" >/dev/null 2>&1; then
    validate_and_restart || die "升级后重启失败"
  fi
}

cmd_audit() {
  need_root
  bash "${LIB_DIR}/audit.sh"
}

cmd_uninstall() {
  need_root
  local keep_tcpfit=0
  [[ "${1:-}" == "--keep-tcpfit" ]] && keep_tcpfit=1

  systemctl disable --now sing-box 2>/dev/null || true
  rm -f "$SB_UNIT" "$SB_LOGROTATE" "$SB_BIN" "$SB_CTL_DST"
  rm -rf "$SB_DIR" "$SB_LOG_DIR" "$SB_STATE_DIR" /usr/local/lib/sb-kit

  local svc
  for svc in /etc/systemd/system/sbkit_*.service /etc/systemd/system/sbkit-hop-*.service; do
    [[ -f "$svc" ]] || continue
    systemctl disable --now "$(basename "$svc")" 2>/dev/null || true
    rm -f "$svc"
  done
  rm -f /etc/nftables.d/sbkit_*.nft
  systemctl daemon-reload

  if [[ "$keep_tcpfit" -eq 0 && -x "$TCPFIT_BIN" ]]; then
    info "回滚 tcpfit 调优..."
    TCPFIT_NO_TELEMETRY=1 "$TCPFIT_BIN" rollback || true
  fi
  ok "sb-kit 与 sing-box 已卸载干净"
}

show_help() {
  cat <<'EOF'
sbctl — 纯 sing-box + tcpfit 精简管理工具（无面板、无二维码、仅纯链接）

用法:
  sbctl                             打开终端可视化交互菜单
  sbctl install [选项]              一键安装 sing-box + 自动 BBR 调优 + 首个节点
  sbctl add <协议> [选项]           添加节点 (vless-reality|hy2|naive|anytls|ss2022|socks)
  sbctl modify [tag] [选项]         修改已有节点（端口/SNI/密钥/备注/白名单）
  sbctl links                       查看全部节点链接（socks 附指纹浏览器格式）
  sbctl yaml                        按需导出 Clash/Mihomo proxies YAML 片段
  sbctl del [tag]                   删除节点
  sbctl tune [--bw N --rtt auto]    BBR/TCP 调优（支持 --rollback）
  sbctl route [block-cn-on|off]     开启/关闭回国 IP 阻断
  sbctl audit                       一键只读安全巡检
  sbctl update [ver]                仅升级 sing-box 核心（SHA-256 校验，不覆盖配置）
  sbctl uninstall [--keep-tcpfit]   彻底卸载
EOF
}

interactive_menu() {
  while true; do
    local ver status user_now cc_algo qdisc mem_mb initcwnd node_count node_list
    ver=$(sb_version)
    ver="${ver:-未安装}"
    if systemctl is-active --quiet sing-box 2>/dev/null; then
      status="${C_GREEN}● 运行中${C_NC}"
    else
      status="${C_YELLOW}○ 未运行${C_NC}"
    fi
    user_now=$(systemctl show -p User --value sing-box 2>/dev/null || echo "-")
    cc_algo=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")
    mem_mb=$(awk '/^MemTotal:/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo "?")
    initcwnd=$(ip -4 route show default 2>/dev/null | grep -oE 'initcwnd [0-9]+' | awk '{print $2}' | head -n1 || true)
    initcwnd="${initcwnd:-默认}"

    node_count=0
    node_list=""
    if [[ -d "$SB_META_DIR" ]]; then
      local f
      for f in "${SB_META_DIR}"/*.json; do
        [[ -f "$f" ]] || continue
        node_count=$((node_count + 1))
        node_list+="${node_list:+, }$(basename "$f" .json)"
      done
    fi

    printf '\n%b┌──────────────────────────────────────────────────────────────┐%b\n' "$C_CYAN" "$C_NC"
    printf '%b│%b  %bsb-kit%b · 纯 sing-box + tcpfit 精简管理工具                 %b│%b\n' "$C_CYAN" "$C_NC" "$C_BOLD" "$C_NC" "$C_CYAN" "$C_NC"
    printf '%b├──────────────────────────────────────────────────────────────┤%b\n' "$C_CYAN" "$C_NC"
    printf '  核心: %-12s %b  |  用户: %s\n' "$ver" "$status" "${user_now:-root}"
    printf '  网络: %s + %s  |  initcwnd: %s  |  内存: %s MB\n' "$cc_algo" "$qdisc" "$initcwnd" "$mem_mb"
    printf '  节点: %d 个 %s\n' "$node_count" "${node_list:+(${node_list})}"
    printf '%b├──────────────────────────────────────────────────────────────┤%b\n' "$C_CYAN" "$C_NC"
    printf '  [1]  一键安装（sing-box + 自动 BBR 调优 + 首个节点）\n'
    printf '  [2]  添加节点（VLESS-Reality / Hy2 / Naive / AnyTLS / SS / Socks）\n'
    printf '  [3]  修改节点（改端口 / 换 SNI / 重置账密 / 改白名单）\n'
    printf '  [4]  查看全部节点链接（纯文本直接复制；可选导出 YAML）\n'
    printf '  [5]  删除节点\n'
    printf '  %b──────────────────────────────────────────────────────────%b\n' "$C_DIM" "$C_NC"
    printf '  [6]  BBR / TCP 调优（自动调优 / 重调 / tcpfit 菜单 / 回滚）\n'
    printf '  [7]  路由开关（开启 / 关闭回国 IP 阻断）\n'
    printf '  [8]  服务管理（启动 / 停止 / 重启 / 查看错误日志）\n'
    printf '  [9]  一键安全巡检 (audit)\n'
    printf '  [10] 仅更新 sing-box 核心（SHA-256 校验，不覆盖配置）\n'
    printf '  [11] 彻底卸载\n'
    printf '  [0]  退出\n'
    printf '%b└──────────────────────────────────────────────────────────────┘%b\n' "$C_CYAN" "$C_NC"

    local choice=""
    read -rp "请选择 [0-11]: " choice
    case "$choice" in
      1)
        local bw="" block_cn=""
        read -rp "VPS 套餐带宽 Mbps [回车默认 500，填 0 跳过 BBR 调优]: " bw
        bw="${bw:-500}"
        local -a args=(--proto vless-reality)
        if [[ "$bw" == "0" ]]; then
          args+=(--no-tune)
        else
          args+=(--bw "$bw" --rtt auto)
        fi
        read -rp "是否开启回国 IP 阻断 (geoip:cn)? [y/N]: " block_cn
        [[ "${block_cn:-n}" =~ ^[Yy]$ ]] && args+=(--block-cn)
        cmd_install "${args[@]}" || true
        ;;
      2)
        printf '  1) vless-reality  2) hy2  3) naive  4) anytls  5) ss2022  6) socks\n'
        local p=""
        read -rp "请选择协议 [1-6]: " p
        case "$p" in
          1) cmd_add vless-reality || true ;;
          2) cmd_add hy2 || true ;;
          3) cmd_add naive || true ;;
          4) cmd_add anytls || true ;;
          5) cmd_add ss2022 || true ;;
          6) cmd_add socks || true ;;
          *) warn "无效选择" ;;
        esac
        ;;
      3) cmd_modify || true ;;
      4)
        cmd_links
        local show_y=""
        read -rp "是否顺便打印 Clash/Mihomo YAML 片段? [y/N]: " show_y
        [[ "${show_y:-n}" =~ ^[Yy]$ ]] && cmd_yaml
        ;;
      5) cmd_del || true ;;
      6)
        printf '  1) 自动调优（按地区推 RTT）  2) 自定义带宽/RTT  3) 打开 tcpfit 原生菜单(可扫拐点)  4) 一键回滚\n'
        local ta=""
        read -rp "请选择 [1-4]: " ta
        case "$ta" in
          1) cmd_tune --bw 500 --rtt auto || true ;;
          2)
            local bw="" rtt=""
            read -rp "套餐带宽 Mbps [500]: " bw
            read -rp "参考 RTT ms [auto]: " rtt
            cmd_tune --bw "${bw:-500}" --rtt "${rtt:-auto}" || true
            ;;
          3)
            install_tcpfit
            TCPFIT_NO_TELEMETRY=1 "$TCPFIT_BIN" || true
            ;;
          4) cmd_tune --rollback || true ;;
          *) warn "无效选择" ;;
        esac
        ;;
      7)
        cmd_route status
        local ra=""
        read -rp "1=开启回国阻断  2=关闭回国阻断 [回车取消]: " ra
        [[ "$ra" == "1" ]] && cmd_route block-cn-on
        [[ "$ra" == "2" ]] && cmd_route block-cn-off
        ;;
      8)
        printf '  1) 启动  2) 停止  3) 重启  4) 查看最近 30 行错误日志\n'
        local sa=""
        read -rp "请选择 [1-4]: " sa
        case "$sa" in
          1) systemctl start sing-box && ok "已启动" ;;
          2) systemctl stop sing-box && ok "已停止" ;;
          3) validate_and_restart || true ;;
          4) [[ -f "${SB_LOG_DIR}/error.log" ]] && tail -n 30 "${SB_LOG_DIR}/error.log" || info "暂无错误日志" ;;
          *) warn "无效选择" ;;
        esac
        ;;
      9) cmd_audit || true ;;
      10) cmd_update || true ;;
      11)
        local yn=""
        read -rp "确认彻底卸载 sb-kit 与 sing-box? [y/N]: " yn
        if [[ "${yn:-n}" =~ ^[Yy]$ ]]; then
          cmd_uninstall
          exit 0
        fi
        ;;
      0) exit 0 ;;
      *) warn "无效选项: ${choice}" ;;
    esac
  done
}

main() {
  if [[ $# -eq 0 ]]; then
    if [[ -t 0 ]]; then
      interactive_menu
    else
      show_help
    fi
    return 0
  fi

  local sub="$1"
  shift
  case "$sub" in
    install)           cmd_install "$@" ;;
    add)               cmd_add "$@" ;;
    modify|mod|edit)   cmd_modify "$@" ;;
    links|link|url)    cmd_links "$@" ;;
    yaml|clash)        cmd_yaml "$@" ;;
    del|rm)            cmd_del "$@" ;;
    tune|bbr)          cmd_tune "$@" ;;
    route)             cmd_route "$@" ;;
    audit|check)       cmd_audit "$@" ;;
    update|up)         cmd_update "$@" ;;
    uninstall)         cmd_uninstall "$@" ;;
    -h|--help|help)    show_help ;;
    *) die "未知子命令: ${sub}（运行 sbctl --help 查看用法）" ;;
  esac
}

main "$@"
