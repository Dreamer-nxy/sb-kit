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

SBKIT_VERSION="0.3.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LIB_DIR="${SCRIPT_DIR}/lib"
# The old flat installation is kept intact while its replacement is published.
if [[ "$SCRIPT_DIR" == "/usr/local/bin" && ! -d "$LIB_DIR" ]]; then
  LIB_DIR="/usr/local/lib/sb-kit"
fi

# Global temp-path registry, cleaned on any exit (including die()).
CLEANUP_PATHS=()
cleanup_paths() {
  local p
  for p in ${CLEANUP_PATHS[@]+"${CLEANUP_PATHS[@]}"}; do
    [[ -n "$p" ]] && rm -rf -- "$p"
  done
  return 0
}
trap cleanup_paths EXIT

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
PRE_INSTALL_BACKUP=""
SB_UNIT="/etc/systemd/system/sing-box.service"
SB_LOGROTATE="/etc/logrotate.d/sing-box"
SB_CTL_DST="/usr/local/bin/sbctl"
SB_LIB_DST="/usr/local/lib/sb-kit"
SB_LOCK="/run/sb-kit.lock"
SB_LOCK_HELD=0
NFT_DIR="/etc/nftables.d"

TCPFIT_BIN="/usr/local/bin/tcpfit"
TCPFIT_VERSION="v0.5.9"
TCPFIT_URL="https://raw.githubusercontent.com/Kylin010/tcpfit/${TCPFIT_VERSION}/tcpfit.sh"
TCPFIT_SHA256="8331cc40950229a3280ce32406330a85b1a3d21ba398a4db3dc7e25c39783741"

GEOSITE_COMMIT_API="https://api.github.com/repos/SagerNet/sing-geosite/commits/rule-set"
SB_ROUTE_STATE_NAME="route-state.json"
SB_ALLOW_LIST_NAME="cn-allow.list"
SB_BLOCK_LIST_NAME="cn-block.list"

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

acquire_lock() {
  [[ "$SB_LOCK_HELD" == "1" ]] && return 0
  need_cmd flock
  exec 9>>"$SB_LOCK" || die "无法打开写锁: $SB_LOCK"
  flock -n 9 || die "另一个 sbctl 正在运行（锁文件: ${SB_LOCK}），请稍后再试"
  SB_LOCK_HELD=1
}

proto_net_type() {
  case "$1" in
    hy2|hysteria2)       echo "udp" ;;
    naive|ss2022|ss|socks|socks5) echo "tcp+udp" ;;
    *)                   echo "tcp" ;;
  esac
}

require_supported_protocol() {
  case "$1" in
    vless-reality|reality|vless|hy2|hysteria2|naive|anytls|ss2022|ss|socks|socks5) ;;
    *) die "不支持的协议: $1" ;;
  esac
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
  # proto: tcp | udp | tcp+udp (busy if either side is taken)
  local port="$1" proto="${2:-tcp}"
  command -v ss >/dev/null 2>&1 || return 1
  if [[ "$proto" == "tcp+udp" ]]; then
    is_port_busy "$port" tcp || is_port_busy "$port" udp
    return
  fi
  local flag="-tlnH"
  [[ "$proto" == "udp" ]] && flag="-ulnH"
  ss "$flag" 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${port}\$"
}

valid_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

pick_free_port() {
  # $4 (optional): the node's own current port — treated as free (modify keeps/reuses it).
  local preferred="$1" proto="${2:-tcp}" non_interactive="${3:-0}" self_port="${4:-}"
  valid_port "$preferred" || die "端口必须是 1-65535 的整数: ${preferred}"
  preferred=$((10#$preferred))
  if [[ -n "$self_port" && "$preferred" == "$self_port" ]] || ! is_port_busy "$preferred" "$proto"; then
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
    if ! valid_port "$chosen"; then
      warn "端口必须是 1-65535 的整数" >&2
      continue
    fi
    chosen=$((10#$chosen))
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

is_staging_copy() {
  [[ "$SCRIPT_DIR" != "${SB_CTL_DST%/*}" && "$SCRIPT_DIR" != "$SB_LIB_DST" &&
     ! -f "$SCRIPT_DIR/.sb-kit-manifest" && -f "$SCRIPT_DIR/sbctl.sh" ]]
}

install_self() {
  local quiet="${1:-0}" source="${2:-}" version
  [[ "$(id -u)" == 0 ]] || return 0
  if [[ -z "$source" ]]; then
    is_staging_copy || return 0
    source="$SCRIPT_DIR"
  fi
  acquire_lock
  need_cmd python3
  version=$(python3 "$LIB_DIR/bundle.py" publish "$source" "$SB_LIB_DST" "$SB_CTL_DST") ||
    die "同步失败，请检查源码或安装目录"
  if [[ "$quiet" != 1 ]]; then ok "管理命令已就绪: ${SB_CTL_DST} (sb-kit ${version})"; fi
}

require_managed_installation() {
  local path marker="${SB_DIR}/.managed-by-sb-kit" unit
  [[ -f "$marker" && ! -L "$marker" ]] || die "缺少 sb-kit 托管标记，请保留原有 sing-box 安装。"
  for path in "$SB_DIR" "$SB_CONF_DIR" "$SB_META_DIR" "$SB_RULES_DIR" "$SB_LOG_DIR" \
              "$SB_STATE_DIR" "$SB_STATE_DIR/certs" "$SB_LIB_DST" "$NFT_DIR"; do
    [[ ! -L "$path" ]] || die "托管路径已改为符号链接，请确认归属: $path"
  done
  unit=$(systemctl show -p FragmentPath --value sing-box.service 2>/dev/null || true)
  [[ -z "$unit" || "$unit" == "$SB_UNIT" ]] || die "当前 sing-box 服务归属于其他安装: $unit"
  if [[ -e "$SB_UNIT" || -L "$SB_UNIT" ]]; then
    [[ ! -L "$SB_UNIT" ]] && grep -Fxq 'Description=sing-box service (managed by sb-kit)' "$SB_UNIT" \
      || die "当前 systemd 服务已被替换，请确认归属: $SB_UNIT"
  fi
}

backup_existing_singbox() {
  local unit path bk_dir i
  if [[ -e "${SB_DIR}/.managed-by-sb-kit" || -L "${SB_DIR}/.managed-by-sb-kit" ]]; then
    require_managed_installation
    return 0
  fi
  for path in "$SB_DIR" "$SB_CONF_DIR" "$SB_META_DIR" "$SB_RULES_DIR" "$SB_STATE_DIR" \
              "$SB_STATE_DIR/certs" "$SB_STATE_DIR/acme" "$SB_LOG_DIR" "$SB_LOG_DIR/error.log"; do
    [[ ! -L "$path" ]] || die "接管路径为符号链接，请先确认原件并迁移为独立路径: $path"
  done
  python3 "${LIB_DIR}/managed_files.py" check-takeover "$SB_STATE_DIR/acme" || die "旧 ACME 存储含无法完整备份并还原的路径，已中止接管"
  unit=$(systemctl show -p FragmentPath --value sing-box.service 2>/dev/null || true)
  local -a paths=("$SB_DIR" "$SB_STATE_DIR" "$SB_LOG_DIR" "$SB_BIN" "${SB_BIN}.bak" "$SB_UNIT" "${SB_UNIT}.d" "$SB_LOGROTATE")
  local -a names=(etc-sing-box state logs sing-box previous-core-backup local.service local.service.d logrotate)
  if [[ -n "$unit" && "$unit" != "$SB_UNIT" ]]; then
    paths+=("$unit")
    names+=(vendor.service)
  fi
  bk_dir=""
  for i in "${!paths[@]}"; do
    path="${paths[$i]}"
    [[ -e "$path" || -L "$path" ]] || continue
    if [[ -z "$bk_dir" ]]; then
      mkdir -p "$SB_BACKUP_ROOT" || die "无法创建备份目录: $SB_BACKUP_ROOT"
      bk_dir=$(mktemp -d "${SB_BACKUP_ROOT}/pre-install-$(date +%Y%m%d-%H%M%S).XXXXXX") || die "无法创建本次备份"
    fi
    cp -a "$path" "${bk_dir}/${names[$i]}" || die "备份失败，已中止安装。部分副本位于: $bk_dir"
  done
  if [[ -n "$bk_dir" ]]; then
    if systemctl is-active --quiet sing-box.service; then touch "$bk_dir/was-active" || die "记录原服务状态失败"; fi
    if systemctl is-enabled --quiet sing-box.service; then touch "$bk_dir/was-enabled" || die "记录原启用状态失败"; fi
    touch "$bk_dir/complete" || die "备份未能完成，请检查 $bk_dir"
    PRE_INSTALL_BACKUP="${bk_dir##*/}"
    warn "已备份原有 sing-box 至 ${bk_dir}，卸载时将恢复被覆盖的配置和服务。"
  fi
}

download_release_file() {
  local url="$1" path="$2" timeout="$3" attempt
  for attempt in 1 2 3; do
    curl -fsSL --connect-timeout 10 --max-time "$timeout" "$url" -o "$path" && return 0
    if [[ "$attempt" != 3 ]]; then sleep "$attempt"; fi
  done
  return 1
}

install_singbox_binary() {
  local target_ver="${1:-latest}"
  local arch api_url tag asset_name dl_url expected_sha tmpdir tarball
  arch=$(detect_arch)
  tmpdir=$(mktemp -d) || die "无法创建下载临时目录"
  CLEANUP_PATHS+=("$tmpdir")

  if [[ "$target_ver" == "latest" ]]; then
    api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
  else
    target_ver="v${target_ver#v}"
    api_url="https://api.github.com/repos/SagerNet/sing-box/releases/tags/${target_ver}"
  fi

  info "查询 SagerNet/sing-box 官方 Release (${target_ver})..."
  download_release_file "$api_url" "$tmpdir/release.json" 15 || die "获取 sing-box Release 元数据失败"

  IFS='|' read -r tag asset_name dl_url expected_sha < <(
    python3 - "$arch" "$tmpdir/release.json" <<'PY'
import json, sys
arch = sys.argv[1]
with open(sys.argv[2], encoding="utf-8") as fh:
    data = json.load(fh)
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

  [[ "$expected_sha" =~ ^[0-9a-fA-F]{64}$ ]] || die "Release 未提供有效 SHA-256，已中止安装"
  tarball="${tmpdir}/${asset_name}"

  info "下载 sing-box ${tag} (${asset_name})..."
  download_release_file "$dl_url" "$tarball" 120 || die "下载 sing-box 失败"

  local actual_sha
  actual_sha=$(sha256sum "$tarball" | awk '{print $1}') || die "无法计算下载文件的 SHA-256"
  [[ "$actual_sha" == "$expected_sha" ]] || die "SHA-256 校验失败！期望=${expected_sha} 实际=${actual_sha}"
  ok "SHA-256 校验通过 (${actual_sha:0:16}...)"

  tar -xzf "$tarball" -C "$tmpdir" || die "解压 sing-box 失败"
  local extracted
  extracted=$(find "$tmpdir" -maxdepth 2 -type f -name "sing-box" | head -n 1)
  [[ -n "$extracted" ]] || die "解压后未找到 sing-box 二进制"

  chmod 755 "$extracted" || die "无法设置新核心权限"
  "$extracted" version >/dev/null 2>&1 || die "新下载的 sing-box 二进制无法执行（架构/libc 不匹配？）"
  # Keep the previous binary so update can roll back if the new core rejects the config.
  local staged
  if [[ -x "$SB_BIN" ]]; then
    staged=$(mktemp "${SB_BIN}.bak.XXXXXX") || die "无法暂存原核心"
    CLEANUP_PATHS+=("$staged")
    cp -pL "$SB_BIN" "$staged" && mv -f "$staged" "${SB_BIN}.bak" || die "备份原核心失败"
  fi
  staged=$(mktemp "${SB_BIN}.XXXXXX") || die "无法暂存新核心"
  CLEANUP_PATHS+=("$staged")
  mv -f "$extracted" "$staged" && mv -f "$staged" "$SB_BIN" || die "写入新核心失败"
  rm -rf "$tmpdir"
  ok "已安装 sing-box ${tag}: ${SB_BIN}"
}

restore_singbox_binary() {
  if [[ -x "${SB_BIN}.bak" ]]; then
    mv -f "${SB_BIN}.bak" "$SB_BIN"
    warn "已回滚 sing-box 核心至: $(sb_version)"
    return 0
  fi
  return 1
}

ensure_singbox_system() {
  if ! id -u "$SB_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SB_USER" 2>/dev/null || \
      adduser --system --no-create-home --disabled-login --group "$SB_USER" 2>/dev/null || true
  fi

  mkdir -p "$SB_DIR" "$SB_CONF_DIR" "$SB_META_DIR" "$SB_RULES_DIR" "$SB_LOG_DIR" "$SB_STATE_DIR"
  if [[ ! -f "${SB_DIR}/.managed-by-sb-kit" ]]; then
    printf 'sb-kit-v1\n%s\n' "${PRE_INSTALL_BACKUP:-fresh}" >"${SB_DIR}/.managed-by-sb-kit" || die "无法写入托管标记"
  fi
  chown root:"$SB_GROUP" "$SB_DIR" "$SB_CONF_DIR" "$SB_RULES_DIR"
  chmod 750 "$SB_DIR" "$SB_CONF_DIR" "$SB_RULES_DIR"
  chown root:root "$SB_META_DIR"
  chmod 700 "$SB_META_DIR"
  chown -hRP "$SB_USER":"$SB_GROUP" "$SB_LOG_DIR" "$SB_STATE_DIR"
  chmod 750 "$SB_LOG_DIR" "$SB_STATE_DIR"

  if [[ -L "$SB_UNIT" ]]; then rm -f "$SB_UNIT" || die "无法替换旧服务链接"; fi
  if [[ -L "$SB_LOGROTATE" ]]; then rm -f "$SB_LOGROTATE" || die "无法替换旧日志轮换链接"; fi
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
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
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

valid_cn_mode() {
  case "${1:-}" in
    off|on) return 0 ;;
    *) return 1 ;;
  esac
}

current_cn_mode() {
  local state_file="${SB_RULES_DIR}/${SB_ROUTE_STATE_NAME}" mode=""
  if [[ -f "$state_file" && ! -L "$state_file" ]]; then
    mode=$(python3 "${LIB_DIR}/config_gen.py" route-state --file "$state_file" get 2>/dev/null | awk -F= '$1=="MODE"{print $2; exit}')
  fi
  if valid_cn_mode "$mode"; then
    echo "$mode"
    return 0
  fi
  if [[ -f "$SB_CONFIG" ]] && grep -q '"geosite-category-netdisk-cn"' "$SB_CONFIG" 2>/dev/null; then
    echo "on"
    return 0
  fi
  echo "off"
}

fetch_rule_commit() {
  local url="$1" sha=""
  sha=$(curl -fsSL --connect-timeout 5 --max-time 8 -H 'Accept: application/vnd.github.sha' "$url" 2>/dev/null | tr -d '[:space:]' || true)
  if [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "${sha:0:12}"
  fi
}

download_rules_for_mode() {
  local mode="$1" dest_dir="$2" refresh="${3:-0}"
  local plan_out filename url live_file
  plan_out=$(python3 "${LIB_DIR}/config_gen.py" route-plan --mode "$mode") || return 1
  [[ -n "$plan_out" ]] || return 0

  local -a dl_files=() dl_urls=()
  while IFS='|' read -r _ filename url; do
    [[ -n "$filename" ]] || continue
    live_file="${SB_RULES_DIR}/${filename}"
    if [[ "$refresh" != "1" && -f "$live_file" && ! -L "$live_file" && -s "$live_file" ]]; then
      cp -f "$live_file" "${dest_dir}/${filename}" || return 1
    else
      dl_files+=("$filename")
      dl_urls+=("$url")
    fi
  done <<< "$plan_out"

  if [[ ${#dl_files[@]} -gt 0 ]]; then
    local total=${#dl_files[@]} i=0 max_jobs=6 failed=0
    local -a pids=()
    info "下载回国阻断规则集（${total} 个 .srs 文件）..."
    for ((i = 0; i < total; i++)); do
      filename="${dl_files[$i]}"
      url="${dl_urls[$i]}"
      (
        download_release_file "$url" "${dest_dir}/${filename}.part" 30 &&
          [[ -s "${dest_dir}/${filename}.part" ]] &&
          mv -f "${dest_dir}/${filename}.part" "${dest_dir}/${filename}"
      ) &
      pids+=("$!")
      if [[ ${#pids[@]} -ge "$max_jobs" ]]; then
        wait "${pids[0]}" || failed=1
        pids=("${pids[@]:1}")
      fi
    done
    local pid
    for pid in ${pids[@]+"${pids[@]}"}; do
      wait "$pid" || failed=1
    done
    if [[ "$failed" -ne 0 ]]; then
      warn "规则集下载未全部成功，已中止本次更新（原配置未改动）"
      return 1
    fi
  fi

  local f
  for f in "$dest_dir"/*.srs; do
    [[ -f "$f" && ! -L "$f" ]] || continue
    chown root:"$SB_GROUP" "$f"
    chmod 640 "$f"
  done
  return 0
}

sync_rules_update_timer() {
  local mode="$1" unit_dir="${SB_UNIT%/*}" svc tmr
  svc="${unit_dir}/sbkit-rules-update.service"
  tmr="${unit_dir}/sbkit-rules-update.timer"

  if [[ "$mode" == "off" ]]; then
    if [[ -f "$tmr" && ! -L "$tmr" ]] && grep -Fxq 'Description=sb-kit weekly CN route rules update timer' "$tmr"; then
      systemctl disable --now sbkit-rules-update.timer >/dev/null 2>&1 || true
      rm -f "$tmr" || return 1
    fi
    if [[ -f "$svc" && ! -L "$svc" ]] && grep -Fxq 'Description=sb-kit CN route rules auto-updater' "$svc"; then
      rm -f "$svc" || return 1
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    return 0
  fi

  [[ ! -L "$svc" && ! -L "$tmr" ]] || die "规则更新服务单元为符号链接，已中止: $unit_dir"
  mkdir -p "$unit_dir"
  cat >"$svc" <<EOF
[Unit]
Description=sb-kit CN route rules auto-updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SB_CTL_DST} route update --quiet
EOF
  cat >"$tmr" <<EOF
[Unit]
Description=sb-kit weekly CN route rules update timer

[Timer]
OnCalendar=Sun *-*-* 06:30:00 UTC
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now sbkit-rules-update.timer >/dev/null 2>&1 || true
}

ensure_base_config() {
  local raw_mode="${1:-off}" refresh_rules="${2:-0}" quiet="${3:-0}" mode=""
  case "$raw_mode" in
    0|off) mode="off" ;;
    1|on)  mode="on" ;;
    *) die "无效回国阻断开关: ${raw_mode}（可选: on | off）" ;;
  esac

  mkdir -p "$SB_DIR" "$SB_RULES_DIR"
  [[ ! -L "$SB_RULES_DIR" ]] || die "规则目录为符号链接，已中止: $SB_RULES_DIR"

  local state_file="${SB_RULES_DIR}/${SB_ROUTE_STATE_NAME}"
  local allow_file="${SB_RULES_DIR}/${SB_ALLOW_LIST_NAME}"
  local block_file="${SB_RULES_DIR}/${SB_BLOCK_LIST_NAME}"
  local p
  for p in "$state_file" "$allow_file" "$block_file"; do
    [[ ! -L "$p" ]] || die "规则文件为符号链接，已中止: $p"
  done

  local stage
  stage=$(mktemp -d "${SB_DIR}/.route.XXXXXXXX") || die "无法创建路由暂存目录"
  CLEANUP_PATHS+=("$stage")
  mkdir -p "$stage/rules" "$stage/backup" || die "无法初始化路由暂存目录"
  chown root:"$SB_GROUP" "$stage" "$stage/rules"
  chmod 710 "$stage"
  chmod 750 "$stage/rules"

  local had_missing=0
  if [[ "$mode" != "off" ]]; then
    local plan_check fn
    plan_check=$(python3 "${LIB_DIR}/config_gen.py" route-plan --mode "$mode") || return 1
    while IFS='|' read -r _ fn _; do
      [[ -n "$fn" ]] || continue
      [[ ! -L "${SB_RULES_DIR}/${fn}" ]] || die "规则文件为符号链接，已中止: ${SB_RULES_DIR}/${fn}"
      [[ -f "${SB_RULES_DIR}/${fn}" && -s "${SB_RULES_DIR}/${fn}" ]] || had_missing=1
    done <<< "$plan_check"
    download_rules_for_mode "$mode" "$stage/rules" "$refresh_rules" || return 1
  fi

  local -a common_gen=(
    "${LIB_DIR}/config_gen.py" base-config
    --log-file "${SB_LOG_DIR}/error.log"
    --cn-mode "$mode"
    --allow-file "$allow_file"
    --block-file "$block_file"
  )
  python3 "${common_gen[@]}" --out "$stage/check-config.json" --rules-dir "$stage/rules" || return 1
  python3 "${common_gen[@]}" --out "$stage/live-config.json" --rules-dir "$SB_RULES_DIR" || return 1
  chown root:"$SB_GROUP" "$stage/check-config.json" "$stage/live-config.json"
  chmod 640 "$stage/check-config.json" "$stage/live-config.json"

  # Validate candidate rulesets & route JSON with real sing-box before touching live files.
  if [[ -x "$SB_BIN" && -d "$SB_CONF_DIR" ]]; then
    if ! run_as_service_user "$SB_BIN" check -c "$stage/check-config.json" -C "$SB_CONF_DIR"; then
      warn "新路由配置或规则集未通过 sing-box check，已保留原配置"
      return 1
    fi
  fi

  # Snapshot live config, state & overwritten rule files for rollback on restart failure.
  local had_cfg=0 had_state=0 was_active=0
  if [[ -e "$SB_CONFIG" || -L "$SB_CONFIG" ]]; then
    cp -a "$SB_CONFIG" "$stage/backup/config.json" || return 1
    had_cfg=1
  fi
  if [[ -f "$state_file" ]]; then
    cp -a "$state_file" "$stage/backup/${SB_ROUTE_STATE_NAME}" || return 1
    had_state=1
  fi
  local -a installed_new=()
  local f base
  for f in "$stage/rules"/*.srs; do
    [[ -f "$f" ]] || continue
    base="${f##*/}"
    if [[ -f "${SB_RULES_DIR}/${base}" ]]; then
      cp -a "${SB_RULES_DIR}/${base}" "$stage/backup/${base}" || return 1
    else
      installed_new+=("$base")
    fi
  done

  systemctl is-active --quiet sing-box 2>/dev/null && was_active=1

  for f in "$stage/rules"/*.srs; do
    [[ -f "$f" ]] || continue
    base="${f##*/}"
    mv -f "$f" "${SB_RULES_DIR}/${base}" || return 1
    chown root:"$SB_GROUP" "${SB_RULES_DIR}/${base}"
    chmod 640 "${SB_RULES_DIR}/${base}"
  done
  mv -f "$stage/live-config.json" "$SB_CONFIG" || return 1
  chown root:"$SB_GROUP" "$SB_CONFIG"
  chmod 640 "$SB_CONFIG"

  local -a state_args=(--file "$state_file" set --mode "$mode")
  if [[ "$mode" == "on" && ( "$refresh_rules" == "1" || "$had_missing" == "1" ) ]]; then
    local gs_sha="" now_utc
    gs_sha=$(fetch_rule_commit "$GEOSITE_COMMIT_API")
    [[ -n "$gs_sha" ]] && state_args+=(--geosite-commit "$gs_sha")
    now_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    state_args+=(--updated-at "$now_utc")
  fi
  python3 "${LIB_DIR}/config_gen.py" route-state "${state_args[@]}" || return 1
  chown root:"$SB_GROUP" "$state_file"
  chmod 640 "$state_file"

  if [[ -x "$SB_BIN" ]] && compgen -G "${SB_CONF_DIR}/*.json" >/dev/null 2>&1; then
    if ! validate_and_restart; then
      warn "应用新路由后重启失败，正在回滚至上一套配置与规则集..."
      if [[ "$had_cfg" == 1 ]]; then
        mv -f "$stage/backup/config.json" "$SB_CONFIG" || true
      else
        rm -f "$SB_CONFIG" || true
      fi
      if [[ "$had_state" == 1 ]]; then
        mv -f "$stage/backup/${SB_ROUTE_STATE_NAME}" "$state_file" || true
      else
        rm -f "$state_file" || true
      fi
      for f in "$stage/backup"/*.srs; do
        [[ -f "$f" ]] || continue
        mv -f "$f" "${SB_RULES_DIR}/${f##*/}" || true
      done
      for base in ${installed_new[@]+"${installed_new[@]}"}; do
        rm -f "${SB_RULES_DIR}/${base}" || true
      done
      restore_node_service "$was_active" || true
      return 1
    fi
  fi

  sync_rules_update_timer "$mode"
  rm -rf "$stage"
  if [[ "$quiet" != "1" ]]; then
    ok "基础配置与安全路由已写入: ${SB_CONFIG}（回国阻断: $([[ "$mode" == "on" ]] && echo 开启 || echo 关闭)）"
  fi
}

fix_runtime_perms() {
  # conf: root:sing-box 0640 (readable by service); meta: root-only 0600 (secrets/tokens);
  # state (certs/acme): owned by sing-box so it can read keys and write ACME data.
  [[ -d "$SB_CONF_DIR" ]] && {
    find "$SB_CONF_DIR" -maxdepth 1 -type f -name '*.json' -exec chown root:"$SB_GROUP" {} + -exec chmod 640 {} +
  }
  if [[ -d "$SB_RULES_DIR" ]]; then
    local rf
    for rf in "$SB_RULES_DIR"/*.srs "$SB_RULES_DIR"/*.json "$SB_RULES_DIR"/*.list; do
      [[ -f "$rf" && ! -L "$rf" ]] || continue
      chown root:"$SB_GROUP" "$rf"
      chmod 640 "$rf"
    done
  fi
  [[ -d "$SB_META_DIR" ]] && {
    find "$SB_META_DIR" -maxdepth 1 -type f -name '*.json' -exec chown root:root {} + -exec chmod 600 {} +
  }
  if [[ -d "$SB_STATE_DIR" ]]; then
    chown -hRP "$SB_USER":"$SB_GROUP" "$SB_STATE_DIR"
    if [[ -d "$SB_STATE_DIR/certs" ]]; then
      find "$SB_STATE_DIR/certs" -maxdepth 1 -type f -name '*.key' -exec chmod 640 {} +
    fi
  fi
}

run_as_service_user() {
  # Run as the service user so `check` also catches permission problems (e.g. unreadable keys).
  if id -u "$SB_USER" >/dev/null 2>&1; then
    if command -v runuser >/dev/null 2>&1; then
      runuser -u "$SB_USER" -- "$@"
      return
    elif command -v setpriv >/dev/null 2>&1; then
      setpriv --reuid="$SB_USER" --regid="$SB_GROUP" --init-groups -- "$@"
      return
    fi
  fi
  "$@"
}

validate_config() {
  fix_runtime_perms
  run_as_service_user "$SB_BIN" check -c "$SB_CONFIG" -C "$SB_CONF_DIR"
}

validate_and_restart() {
  info "执行 sing-box check 配置校验..."
  validate_config || return 1
  systemctl restart sing-box || return 1
  local i
  for i in 1 2 3; do
    sleep 1
    systemctl is-active --quiet sing-box || break
    [[ "$i" -eq 3 ]] && { ok "sing-box 校验通过并已重启"; return 0; }
  done
  warn "sing-box 启动失败，请查看: journalctl -u sing-box -n 30"
  return 1
}

install_tcpfit() {
  mkdir -p /var/lib/tcpfit
  touch /var/lib/tcpfit/no-telemetry

  if [[ -x "$TCPFIT_BIN" ]]; then
    # Re-verify the pinned hash every time (a matching VERSION string proves nothing).
    if [[ "$(sha256sum "$TCPFIT_BIN" | awk '{print $1}')" == "$TCPFIT_SHA256" ]]; then
      ok "tcpfit ${TCPFIT_VERSION} 已就绪（SHA-256 复核通过，已禁遥测）"
      return 0
    fi
    warn "已安装的 tcpfit 与锁定版本 ${TCPFIT_VERSION} 的 SHA-256 不一致，将重新安装"
  fi

  info "安装 Kylin010/tcpfit ${TCPFIT_VERSION}（强校 SHA-256 + 禁用遥测）..."
  local tmp
  tmp=$(mktemp "/usr/local/bin/.tcpfit.XXXXXX")
  CLEANUP_PATHS+=("$tmp")
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

  need_root
  acquire_lock
  install_tcpfit
  if [[ "$do_rollback" -eq 1 ]]; then
    TCPFIT_NO_TELEMETRY=1 "$TCPFIT_BIN" rollback || die "tcpfit 回滚失败"
    rm -f "$SB_DIR/.sb-kit-tcpfit-tuned"
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
  TCPFIT_NO_TELEMETRY=1 "$TCPFIT_BIN" tune --role proxy --bw "$bw" --rtt "$rtt" || die "tcpfit 调优失败"
  if [[ -f "$SB_DIR/.managed-by-sb-kit" ]]; then
    touch "$SB_DIR/.sb-kit-tcpfit-tuned" || die "无法记录 tcpfit 调优归属"
  fi

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

nft_unit_remove() {
  local name="$1" unit="${SB_UNIT%/*}/${1}.service" rules="${NFT_DIR}/${1}.nft"
  [[ -f "$unit" || -f "$rules" ]] || return 0
  if [[ -f "$unit" ]]; then
    # Detach RequiredBy before stopping the guard so this does not stop sing-box.
    systemctl disable "${name}.service" >/dev/null || return 1
    systemctl daemon-reload || return 1
    systemctl stop "${name}.service" || return 1
  fi
  local tables
  tables=$(nft list tables) || return 1
  if grep -Fxq "table inet ${name}" <<< "$tables"; then
    nft delete table inet "$name" || return 1
  fi
  rm -f "$rules" "$unit" || return 1
  systemctl daemon-reload
}

activate_nft_unit() {
  local name="$1" rules="$2"
  systemctl daemon-reload && systemctl enable "${name}.service" >/dev/null || return 1
  if systemctl is-active --quiet "${name}.service"; then
    # Older units delete their table on stop. Update an active table in one nft transaction.
    nft -f "$rules" || return 1
  else
    systemctl start "${name}.service" || return 1
  fi
  nft list table inet "$name" >/dev/null
}

nft_unit_install() {
  # Read a complete nft transaction from stdin. Reload replaces a live table atomically.
  local name="$1" desc="$2" dependency="$3" nft_bin tmp had_required=0
  local required_link="${SB_UNIT}.requires/${1}.service"
  [[ -L "$required_link" ]] && had_required=1
  local unit="${SB_UNIT%/*}/${1}.service" rules="${NFT_DIR}/${1}.nft"
  nft_bin=$(command -v nft) || { warn "缺少 nft，无法加载防火墙规则"; return 1; }
  mkdir -p "$NFT_DIR" || return 1
  tmp=$(mktemp -d "${NFT_DIR}/.sbkit.XXXXXX") || return 1
  CLEANUP_PATHS+=("$tmp")
  cat >"$tmp/rules" || return 1
  nft -c -f "$tmp/rules" || return 1
  if [[ -f "$unit" ]]; then cp -p "$unit" "$tmp/old-unit" || return 1; fi
  if [[ -f "$rules" ]]; then cp -p "$rules" "$tmp/old-rules" || return 1; fi
  cat >"$tmp/unit" <<UNIT || return 1
[Unit]
Description=${desc}
After=network-pre.target
Before=sing-box.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${nft_bin} -f ${rules}
ExecReload=${nft_bin} -f ${rules}

[Install]
${dependency}
UNIT
  if install -m 644 "$tmp/unit" "${unit}.new" && mv -f "${unit}.new" "$unit" &&
     chmod 644 "$tmp/rules" && mv -f "$tmp/rules" "$rules" &&
     activate_nft_unit "$name" "$rules"; then
    rm -rf "$tmp"
    return 0
  fi

  warn "防火墙规则 ${name} 未生效，正在恢复原规则"
  rm -f "${unit}.new" || return 1
  if [[ -f "$tmp/old-unit" && -f "$tmp/old-rules" ]]; then
    if [[ "$had_required" == 0 && -L "$required_link" ]]; then rm -f "$required_link" || return 1; fi
    cp -p "$tmp/old-unit" "$unit" && mv -f "$tmp/old-rules" "$rules" &&
      systemctl daemon-reload && nft -f "$rules" && systemctl start "${name}.service" ||
      warn "无法恢复 ${name}，请检查 nft 与 systemd 状态"
  else
    nft_unit_remove "$name" || warn "未能清理不完整的防火墙单元 ${name}"
  fi
  return 1
}

whitelist_name() { local t="$1"; echo "sbkit_wl_${t//[^a-zA-Z0-9_]/_}"; }
hopping_name()   { local t="$1"; echo "sbkit_hop_${t//[^a-zA-Z0-9_]/_}"; }

normalize_ips() {
  # Validates IP/CIDR list via Python ipaddress; prints normalized comma list or dies.
  local raw="$1" out
  out=$(python3 "${LIB_DIR}/config_gen.py" normalize-ips "$raw") || die "白名单格式无效: ${raw}（示例: 1.2.3.4,5.6.7.0/24,2001:db8::1）"
  printf '%s\n' "$out" | awk -F= '$1=="ALL"{sub(/^ALL=/,""); print; exit}'
}

remove_port_whitelist() {
  nft_unit_remove "$(whitelist_name "$1")"
}

setup_port_whitelist() {
  local tag="$1" port="$2" ips="$3"
  local name norm v4 v6
  name=$(whitelist_name "$tag")
  norm=$(python3 "${LIB_DIR}/config_gen.py" normalize-ips "$ips") || return 1
  v4=$(printf '%s\n' "$norm" | awk -F= '$1=="V4"{sub(/^V4=/,""); print; exit}')
  v6=$(printf '%s\n' "$norm" | awk -F= '$1=="V6"{sub(/^V6=/,""); print; exit}')
  nft_unit_install "$name" "sb-kit port whitelist (${tag})" "RequiredBy=sing-box.service" <<EOF2 || return 1
table inet ${name}
delete table inet ${name}
table inet ${name} {
    set allowed_v4 {
        type ipv4_addr
        flags interval
        elements = { 127.0.0.0/8${v4:+, ${v4}} }
    }
    set allowed_v6 {
        type ipv6_addr
        flags interval
        elements = { ::1${v6:+, ${v6}} }
    }
    chain input {
        type filter hook input priority filter - 5; policy accept;
        meta l4proto { tcp, udp } th dport ${port} ip saddr @allowed_v4 accept
        meta l4proto { tcp, udp } th dport ${port} ip6 saddr @allowed_v6 accept
        meta l4proto { tcp, udp } th dport ${port} drop
    }
}
EOF2
  ok "已启用来源 IP 白名单 (${v4}${v4:+${v6:+, }}${v6})，仅锁定端口 ${port} (TCP/UDP, IPv4/IPv6)"
}

sync_legacy_whitelists() {
  # v0.2.0 guards were wanted by multi-user.target but were not required by sing-box.
  local meta tag name port whitelist
  for meta in "$SB_META_DIR"/socks-*.json "$SB_META_DIR"/ss2022-*.json; do
    [[ -f "$meta" ]] || continue
    tag="${meta##*/}"
    tag="${tag%.json}"
    port="${tag##*-}"
    valid_port "$port" || return 1
    whitelist=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("whitelist") or "")' "$meta") || return 1
    [[ -n "$whitelist" ]] || continue
    name=$(whitelist_name "$tag")
    if [[ -L "${SB_UNIT}.requires/${name}.service" ]] &&
       grep -Fxq 'RequiredBy=sing-box.service' "${SB_UNIT%/*}/${name}.service" &&
       systemctl is-active --quiet "${name}.service" && nft list table inet "$name" >/dev/null; then
      continue
    fi
    setup_port_whitelist "$tag" "$port" "$whitelist" || return 1
  done
}

remove_hy2_hopping() {
  nft_unit_remove "$(hopping_name "$1")"
}

setup_hy2_hopping() {
  local tag="$1" port="$2" hop_range="$3"
  local name start_p end_p
  name=$(hopping_name "$tag")
  if [[ ! "$hop_range" =~ ^([0-9]{1,5})[:-]([0-9]{1,5})$ ]]; then
    warn "无效端口跳跃范围: ${hop_range}（示例: 35000:36000）"
    return 1
  fi
  start_p=$((10#${BASH_REMATCH[1]}))
  end_p=$((10#${BASH_REMATCH[2]}))
  valid_port "$start_p" && valid_port "$end_p" && [[ "$start_p" -lt "$end_p" ]] || return 1
  if [[ "$port" -ge "$start_p" && "$port" -le "$end_p" ]]; then
    warn "端口跳跃区间 ${start_p}-${end_p} 不能包含 hy2 监听端口 ${port}"
    return 1
  fi
  nft_unit_install "$name" "sb-kit Hysteria2 port hopping (${tag})" "WantedBy=multi-user.target" <<EOF2 || return 1
table inet ${name}
delete table inet ${name}
table inet ${name} {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        udp dport ${start_p}-${end_p} fib daddr type local redirect to :${port}
    }
}
EOF2
  ok "已启用 Hysteria2 UDP 端口跳跃 (nftables, IPv4/IPv6): ${start_p}-${end_p} -> ${port}"
}

apply_node_firewall() {
  local proto="$1" tag="$2" port="$3" whitelist="$4" hopping="$5"
  if [[ ( "$proto" == "ss2022" || "$proto" == "socks" ) && -n "$whitelist" ]]; then
    setup_port_whitelist "$tag" "$port" "$whitelist" || return 1
  elif [[ "$proto" == "hy2" && -n "$hopping" ]]; then
    setup_hy2_hopping "$tag" "$port" "$hopping" || return 1
  fi
}

remove_node_firewall() {
  remove_port_whitelist "$1" && remove_hy2_hopping "$1"
}

require_unused_node_tag() {
  local tag="$1"
  if [[ -e "$SB_CONF_DIR/$tag.json" || -e "$SB_META_DIR/$tag.json" ]]; then
    die "目标节点已存在: ${tag}"
  fi
}

publish_node_files() {
  local stage="$1" tag="$2" old_tag="${3:-}"
  chown root:"$SB_GROUP" "$stage/conf/$tag.json" &&
    mv -f "$stage/meta/$tag.json" "$SB_META_DIR/$tag.json" &&
    mv -f "$stage/conf/$tag.json" "$SB_CONF_DIR/$tag.json" || return 1
  if [[ -n "$old_tag" && "$old_tag" != "$tag" ]]; then
    rm -f "$SB_CONF_DIR/$old_tag.json" "$SB_META_DIR/$old_tag.json"
  fi
}

restore_node_service() {
  if [[ "$1" == 1 ]]; then
    validate_and_restart
  else
    systemctl stop sing-box
  fi
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

  local port="" sni="" domain="" cert="" key="" email="" cf_token="${SB_CF_TOKEN:-}" remark="" ip="" country=""
  local hop_range="" masquerade="" whitelist="" self_signed=0 generate_only=0 out_dir=""
  local non_interactive=0 skip_cn=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --port)            port="$2"; shift 2 ;;
      --sni)             sni="$2"; shift 2 ;;
      --domain)          domain="$2"; shift 2 ;;
      --cert)            cert="$2"; shift 2 ;;
      --key)             key="$2"; shift 2 ;;
      --email)           email="$2"; shift 2 ;;
      --cf-token)
        warn "建议通过环境变量 SB_CF_TOKEN 传递 Cloudflare Token，避免出现在命令行进程列表中"
        cf_token="$2"; shift 2 ;;
      --remark)          remark="$2"; shift 2 ;;
      --ip)              ip="$2"; shift 2 ;;
      --country)         country="$2"; shift 2 ;;
      --hop-range)       hop_range="$2"; shift 2 ;;
      --masquerade)      masquerade="$2"; shift 2 ;;
      --whitelist)       whitelist="$2"; shift 2 ;;
      --self-signed)     self_signed=1; shift ;;
      --generate-only)   generate_only=1; shift ;;
      --out-dir)         out_dir="$2"; shift 2 ;;
      --non-interactive) non_interactive=1; shift ;;
      --skip-cn)         skip_cn=1; shift ;;
      -h|--help)
        echo "用法: sbctl add <vless-reality|hy2|naive|anytls|ss2022|socks> [--port N] [--sni HOST] [--domain HOST] [--hop-range A:B] [--masquerade URL] [--whitelist IP1,IP2]"
        echo "提示: Cloudflare DNS-01 Token 建议通过环境变量 SB_CF_TOKEN 传入。"
        return 0
        ;;
      *) die "未知参数: $1" ;;
    esac
  done

  require_supported_protocol "$proto"
  if [[ "$generate_only" -eq 0 ]]; then
    need_root
    acquire_lock
    [[ -x "$SB_BIN" ]] || die "未检测到 sing-box，请先运行: sbctl install"
  fi

  case "$proto" in
    vless-reality|reality|vless)
      proto="vless-reality"
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 VLESS-Reality 监听端口 [回车默认 443，可自由修改]: " port
      fi
      port="${port:-443}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" "$(proto_net_type "$proto")" "$non_interactive")
      sni=$(select_reality_sni "$sni" "$non_interactive" "$skip_cn")
      ;;
    hy2|hysteria2)
      proto="hy2"
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 Hysteria2 UDP 监听端口 [回车默认 8443]: " port
      fi
      port="${port:-8443}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" "$(proto_net_type "$proto")" "$non_interactive")
      if [[ -z "$domain" && -z "$cert" && "$self_signed" -eq 0 ]]; then
        if [[ "$non_interactive" -eq 1 || ! -t 0 ]]; then
          die "hy2 推荐提供 --domain <灰云子域名>（自动 ACME 正规证书），或显式加 --self-signed"
        fi
        read -rp "请输入自有域名（Cloudflare 灰云 A 记录，留空则改用随机自签证书）: " domain
        [[ -z "$domain" ]] && self_signed=1
      fi
      if [[ -n "$domain" && -z "$cf_token" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rsp "Cloudflare API Token（不回显，留空走 80 端口 HTTP-01 自动签发）: " cf_token
        echo ""
      fi
      if [[ -z "$hop_range" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "UDP 端口跳跃区间（可选，如 35000:36000，留空不启用）: " hop_range
      fi
      if [[ -z "$masquerade" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "主动探测伪装 URL（可选，如 https://www.debian.org，留空不设）: " masquerade
      fi
      ;;
    naive)
      proto="naive"
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 Naive 监听端口 [回车默认 9443，TCP+UDP，443 空闲也可填 443]: " port
      fi
      port="${port:-9443}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" "$(proto_net_type "$proto")" "$non_interactive")
      if [[ -z "$domain" && -z "$cert" ]]; then
        if [[ "$non_interactive" -eq 1 || ! -t 0 ]]; then
          die "naive 必须提供 --domain <灰云子域名> 或 --cert/--key"
        fi
        read -rp "请输入 Naive 自有域名（必填，Cloudflare 灰云 A 记录）: " domain
        [[ -n "$domain" ]] || die "naive 协议必须提供域名以签发正规 TLS 证书"
      fi
      if [[ -n "$domain" && -z "$cf_token" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rsp "Cloudflare API Token（不回显，留空走 80 端口 HTTP-01 自动签发）: " cf_token
        echo ""
      fi
      ;;
    anytls)
      proto="anytls"
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 AnyTLS 监听端口 [回车默认 10443]: " port
      fi
      port="${port:-10443}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" "$(proto_net_type "$proto")" "$non_interactive")
      if [[ -z "$domain" && -z "$cert" && "$self_signed" -eq 0 ]]; then
        if [[ "$non_interactive" -eq 1 || ! -t 0 ]]; then
          die "anytls 推荐提供 --domain <灰云子域名>（自动 ACME），或显式加 --self-signed"
        fi
        read -rp "请输入自有域名（Cloudflare 灰云 A 记录，留空则改用随机自签证书）: " domain
        [[ -z "$domain" ]] && self_signed=1
      fi
      if [[ -n "$domain" && -z "$cf_token" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rsp "Cloudflare API Token（不回显，留空走 80 端口 HTTP-01 自动签发）: " cf_token
        echo ""
      fi
      ;;
    ss2022|ss)
      proto="ss2022"
      local def_ss=$((25000 + RANDOM % 30000))
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 SS-2022 监听端口 [回车默认随机 ${def_ss}]: " port
      fi
      port="${port:-$def_ss}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" "$(proto_net_type "$proto")" "$non_interactive")
      if [[ -z "$whitelist" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "允许连入的前置机白名单 IP（支持 IPv4/IPv6/CIDR，逗号分隔，留空不设）: " whitelist
      fi
      ;;
    socks|socks5)
      proto="socks"
      local def_sk=$((25000 + RANDOM % 30000))
      if [[ -z "$port" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "请输入 Socks5 监听端口 [回车默认随机 ${def_sk}]: " port
      fi
      port="${port:-$def_sk}"
      [[ "$generate_only" -eq 0 ]] && port=$(pick_free_port "$port" "$(proto_net_type "$proto")" "$non_interactive")
      if [[ -z "$whitelist" && "$non_interactive" -eq 0 && -t 0 && "$generate_only" -eq 0 ]]; then
        read -rp "来源 IP 白名单（强烈建议填写固定出口/中转 IP，支持 IPv4/IPv6，留空不设）: " whitelist
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
  else
    require_unused_node_tag "${proto}-${port}"
    out_dir=$(mktemp -d "${SB_DIR}/.add.XXXXXX") || return 1
    CLEANUP_PATHS+=("$out_dir")
    conf_dir="${out_dir}/conf"
    meta_dir="${out_dir}/meta"
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
  [[ -n "$remark" ]] && py_args+=(--remark "$remark")
  [[ -n "$hop_range" ]] && py_args+=(--hop-range "$hop_range")
  [[ -n "$masquerade" ]] && py_args+=(--masquerade "$masquerade")
  [[ -n "$whitelist" ]] && py_args+=(--whitelist "$whitelist")
  [[ "$self_signed" -eq 1 ]] && py_args+=(--self-signed)

  local gen_out tag
  gen_out=$(SB_CF_TOKEN="$cf_token" python3 "${py_args[@]}") || return 1
  tag=$(echo "$gen_out" | awk -F= '$1=="TAG"{print $2; exit}')

  if [[ "$generate_only" -eq 1 ]]; then
    ok "干跑配置已生成于: ${out_dir}"
    print_node_result "$tag" "$gen_out"
    return 0
  fi

  local was_active=0
  systemctl is-active --quiet sing-box && was_active=1
  # A service restart at any time may load conf/. Keep the candidate private until protected.
  apply_node_firewall "$proto" "$tag" "$port" "$whitelist" "$hop_range" ||
    die "防火墙规则应用失败，已放弃新增节点"

  if ! publish_node_files "$out_dir" "$tag" || ! validate_and_restart; then
    rm -f "${SB_CONF_DIR}/${tag}.json" "${SB_META_DIR}/${tag}.json" ||
      die "无法撤销新增配置，保留防火墙规则"
    restore_node_service "$was_active" || die "恢复原服务状态失败，保留防火墙规则"
    remove_node_firewall "$tag" || die "已恢复原服务，清理新规则失败"
    die "节点未能启用，已恢复原服务与防火墙规则"
  fi
  rm -rf "$out_dir"

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
  local tag=""
  if [[ $# -gt 0 && "$1" != -* ]]; then
    tag="$1"
    shift
  fi

  local new_port="" new_sni="" new_remark="" new_wl="" clear_wl=0 rotate=0
  local new_hop="" clear_hop=0 new_masq=""
  local has_flags=0
  while [[ $# -gt 0 ]]; do
    has_flags=1
    case "$1" in
      --port)            new_port="$2"; shift 2 ;;
      --sni)             new_sni="$2"; shift 2 ;;
      --remark)          new_remark="$2"; shift 2 ;;
      --whitelist)       new_wl="$2"; shift 2 ;;
      --clear-whitelist) clear_wl=1; shift ;;
      --hop-range)       new_hop="$2"; shift 2 ;;
      --clear-hop-range) clear_hop=1; shift ;;
      --masquerade)      new_masq="$2"; shift 2 ;;
      --rotate-creds)    rotate=1; shift ;;
      -h|--help)
        echo "用法: sbctl modify <tag> [--port N] [--sni auto|HOST] [--rotate-creds] [--remark NAME] [--whitelist IP1,IP2|--clear-whitelist] [--hop-range A:B|--clear-hop-range] [--masquerade URL]"
        return 0
        ;;
      *) die "未知参数: $1" ;;
    esac
  done

  need_root
  acquire_lock
  [[ -n "$tag" ]] || tag=$(pick_existing_tag)
  [[ -f "${SB_META_DIR}/${tag}.json" ]] || die "找不到节点元数据: ${tag}"
  local cur_proto cur_port old_hop old_wl
  IFS='|' read -r cur_proto cur_port old_hop old_wl < <(
    python3 - "${SB_META_DIR}/${tag}.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"{m.get('proto','')}|{m.get('port','')}|{m.get('hop_range','')}|{m.get('whitelist','')}")
PY
  )

  if [[ "$has_flags" -eq 0 ]]; then
    printf '\n正在修改节点 [%s] (%s, 端口 %s):\n' "$tag" "$cur_proto" "$cur_port"
    printf '  1) 修改监听端口\n'
    [[ "$cur_proto" == "vless-reality" ]] && printf '  2) 更换 Reality SNI（重新测速体检或手填）\n'
    printf '  3) 重置密钥 / UUID / 账密（自签证书节点会同步重签）\n'
    printf '  4) 修改节点备注\n'
    [[ "$cur_proto" == "ss2022" || "$cur_proto" == "socks" ]] && printf '  5) 修改 / 清空来源 IP 白名单\n'
    [[ "$cur_proto" == "hy2" ]] && printf '  6) 修改 / 清空 UDP 端口跳跃区间\n'
    [[ "$cur_proto" == "hy2" ]] && printf '  7) 修改主动探测伪装 URL (masquerade)\n'
    local act=""
    read -rp "请选择修改项: " act
    case "$act" in
      1) read -rp "请输入新端口: " new_port ;;
      2) new_sni=$(select_reality_sni "" 0 0) ;;
      3) rotate=1 ;;
      4) read -rp "请输入新备注: " new_remark ;;
      5)
        read -rp "请输入新白名单 IP（支持 IPv4/IPv6，输入 clear 清空）: " new_wl
        if [[ "$new_wl" == "clear" ]]; then
          clear_wl=1; new_wl=""
        fi
        ;;
      6)
        read -rp "请输入新端口跳跃区间（如 35000:36000，输入 clear 清空）: " new_hop
        if [[ "$new_hop" == "clear" ]]; then
          clear_hop=1; new_hop=""
        fi
        ;;
      7) read -rp "请输入伪装 URL（如 https://www.debian.org，留空清除）: " new_masq ;;
      *) die "无效选择" ;;
    esac
  else
    [[ "$new_sni" == "auto" ]] && new_sni=$(select_reality_sni "auto" 1 0)
  fi

  if [[ -n "$new_port" ]]; then
    new_port=$(pick_free_port "$new_port" "$(proto_net_type "$cur_proto")" "$has_flags" "$cur_port")
    if [[ "$new_port" != "$cur_port" ]]; then require_unused_node_tag "${cur_proto}-${new_port}"; fi
  fi

  local snap_dir was_active=0
  snap_dir=$(mktemp -d "${SB_DIR}/.modify.XXXXXX") || return 1
  CLEANUP_PATHS+=("$snap_dir")
  mkdir "$snap_dir/conf" "$snap_dir/meta" &&
    cp -p "$SB_CONF_DIR/$tag.json" "$snap_dir/conf/$tag.json" &&
    cp -p "$SB_META_DIR/$tag.json" "$snap_dir/meta/$tag.json" || return 1
  # The generator publishes via rename, so these links retain the previous files.
  ln "$snap_dir/conf/$tag.json" "$snap_dir/old-conf" &&
    ln "$snap_dir/meta/$tag.json" "$snap_dir/old-meta" || return 1
  systemctl is-active --quiet sing-box && was_active=1

  local sb_ver
  sb_ver=$(sb_version)
  local -a py_args=(
    "${LIB_DIR}/config_gen.py" modify
    --tag "$tag"
    --conf-dir "$snap_dir/conf"
    --meta-dir "$snap_dir/meta"
    --state-dir "$SB_STATE_DIR"
    --sb-ver "${sb_ver:-1.14.4}"
  )
  [[ -x "$SB_BIN" ]] && py_args+=(--sb-bin "$SB_BIN")
  [[ -n "$new_port" ]] && py_args+=(--port "$new_port")
  [[ -n "$new_sni" ]] && py_args+=(--sni "$new_sni")
  [[ -n "$new_remark" ]] && py_args+=(--remark "$new_remark")
  [[ -n "$new_wl" ]] && py_args+=(--whitelist "$new_wl")
  [[ "$clear_wl" -eq 1 ]] && py_args+=(--clear-whitelist)
  [[ -n "$new_hop" ]] && py_args+=(--hop-range "$new_hop")
  [[ "$clear_hop" -eq 1 ]] && py_args+=(--clear-hop-range)
  [[ -n "$new_masq" ]] && py_args+=(--masquerade "$new_masq")
  [[ "$rotate" -eq 1 ]] && py_args+=(--rotate-creds)

  local gen_out new_tag final_port final_wl final_hop
  gen_out=$(python3 "${py_args[@]}") || return 1
  new_tag=$(echo "$gen_out" | awk -F= '$1=="TAG"{print $2; exit}')
  final_port=$(echo "$gen_out" | awk -F= '$1=="PORT"{print $2; exit}')
  final_wl=$(echo "$gen_out" | awk -F= '$1=="WHITELIST"{sub(/^WHITELIST=/,""); print; exit}')
  final_hop=$(echo "$gen_out" | awk -F= '$1=="HOP_RANGE"{sub(/^HOP_RANGE=/,""); print; exit}')

  apply_node_firewall "$cur_proto" "$new_tag" "$final_port" "$final_wl" "$final_hop" ||
    die "新规则应用失败，已放弃节点修改"

  if ! publish_node_files "$snap_dir" "$new_tag" "$tag" || ! validate_and_restart; then
    if [[ "$new_tag" != "$tag" ]]; then
      rm -f "$SB_CONF_DIR/$new_tag.json" "$SB_META_DIR/$new_tag.json" ||
        die "无法撤销新节点，保留防火墙规则"
    fi
    # On a port move the previous guard is still intact; only in-place changes need reloading.
    local guard_restored=1
    if [[ "$new_tag" == "$tag" && ( -n "$final_wl" || -n "$final_hop" ) ]]; then
      apply_node_firewall "$cur_proto" "$tag" "$cur_port" "$old_wl" "$old_hop" || guard_restored=0
    fi
    mv -f "$snap_dir/old-conf" "$SB_CONF_DIR/$tag.json" &&
      mv -f "$snap_dir/old-meta" "$SB_META_DIR/$tag.json" ||
      die "恢复原节点文件失败，保留防火墙规则"
    if [[ "$guard_restored" != 1 ]]; then
      systemctl stop sing-box || die "恢复原防火墙和停止服务均失败，请检查服务状态"
      die "原配置已恢复，服务已停止，请先恢复原防火墙"
    fi
    restore_node_service "$was_active" || die "恢复原服务状态失败，保留防火墙规则"
    if [[ "$new_tag" != "$tag" || ( -z "$old_wl" && -z "$old_hop" ) ]]; then
      remove_node_firewall "$new_tag" || die "已恢复原服务，清理新规则失败"
    fi
    die "节点未能启用，已恢复原配置与防火墙规则"
  fi

  if [[ "$new_tag" != "$tag" || ( -z "$final_wl" && -z "$final_hop" ) ]]; then
    remove_node_firewall "$tag" || die "节点已更新，清理旧防火墙规则失败"
  fi

  rm -rf "$snap_dir"
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
  [[ $# -le 1 && "${1:-}" != -* ]] || die "用法: sbctl del [tag]"
  need_root
  acquire_lock
  local target="${1:-}"
  [[ -n "$target" ]] || target=$(pick_existing_tag)

  local conf_file="${SB_CONF_DIR}/${target}.json"
  [[ -f "$conf_file" || -f "${SB_META_DIR}/${target}.json" ]] || die "找不到节点: ${target}"

  local stage was_active=0 stopped=0
  stage=$(mktemp -d "${SB_DIR}/.del.XXXXXX") || return 1
  CLEANUP_PATHS+=("$stage")
  systemctl is-active --quiet sing-box && was_active=1
  if [[ -f "$conf_file" ]]; then mv "$conf_file" "$stage/node.json" || return 1; fi

  if compgen -G "${SB_CONF_DIR}/*.json" >/dev/null 2>&1; then
    validate_and_restart && stopped=1
  else
    systemctl stop sing-box && stopped=1
  fi
  if [[ "$stopped" != 1 ]]; then
    if [[ -f "$stage/node.json" ]]; then mv "$stage/node.json" "$conf_file" || return 1; fi
    restore_node_service "$was_active" || die "删除失败，原配置与防火墙保留，恢复服务失败"
    die "删除失败，已恢复原节点并保留其防火墙"
  fi

  # Keep metadata for a retry if cleanup fails after the listener is gone.
  remove_node_firewall "$target" || die "监听已停止，防火墙清理失败，可重试删除"
  rm -f "${SB_META_DIR}/${target}.json" || return 1
  rm -rf "$stage"
  ok "已删除节点: ${target}"
}

route_help() {
  cat <<'EOF'
用法:
  sbctl route [status]                  查看回国阻断状态、规则集版本与自定义名单
  sbctl route block-cn-on | on          开启回国阻断（杜甫 v2fly 精准方案 + 每周自动更新）
  sbctl route block-cn-off | off        关闭回国阻断（仅拦截内网/25端口/BT）
  sbctl route update [--quiet]          立即更新并校验本地规则集（失败保留旧规则）
  sbctl route allow <list|add|del> [域名]
                                        查看 / 增删自定义放行域名后缀（最高优先级）
  sbctl route block <list|add|del> [域名]
                                        查看 / 增删自定义拦截域名后缀
EOF
}

cmd_route() {
  local action="${1:-status}"
  if [[ $# -gt 0 ]]; then shift; fi

  case "$action" in
    -h|--help|help)
      route_help
      return 0
      ;;
    status)
      [[ $# -eq 0 ]] || die "用法: sbctl route [status]"
      need_root
      local mode state_file allow_file block_file st_out gs_sha updated
      local allow_cnt=0 block_cnt=0 srs_cnt=0 timer_state="未启用"
      mode=$(current_cn_mode)
      state_file="${SB_RULES_DIR}/${SB_ROUTE_STATE_NAME}"
      allow_file="${SB_RULES_DIR}/${SB_ALLOW_LIST_NAME}"
      block_file="${SB_RULES_DIR}/${SB_BLOCK_LIST_NAME}"
      if [[ -f "$state_file" && ! -L "$state_file" ]]; then
        st_out=$(python3 "${LIB_DIR}/config_gen.py" route-state --file "$state_file" get 2>/dev/null || true)
        gs_sha=$(awk -F= '$1=="GEOSITE_COMMIT"{print $2; exit}' <<<"$st_out")
        updated=$(awk -F= '$1=="UPDATED_AT"{print $2; exit}' <<<"$st_out")
      fi
      if [[ -f "$allow_file" ]]; then
        allow_cnt=$(python3 "${LIB_DIR}/config_gen.py" route-domains --file "$allow_file" list 2>/dev/null | wc -l | tr -d '[:space:]')
      fi
      if [[ -f "$block_file" ]]; then
        block_cnt=$(python3 "${LIB_DIR}/config_gen.py" route-domains --file "$block_file" list 2>/dev/null | wc -l | tr -d '[:space:]')
      fi
      if [[ "$mode" == "on" ]]; then
        srs_cnt=$(python3 "${LIB_DIR}/config_gen.py" route-plan --mode on | wc -l | tr -d '[:space:]')
        if systemctl is-active --quiet sbkit-rules-update.timer 2>/dev/null || systemctl is-enabled --quiet sbkit-rules-update.timer 2>/dev/null; then
          timer_state="已启用（每周日 14:30 CST）"
        fi
        ok "当前回国阻断: 已开启（v2fly 精准分类 ${srs_cnt} 个 + 显式补充，不误伤指纹浏览器/飞书/1688）"
        printf '  规则集版本: geosite=%s | 更新时间: %s\n' "${gs_sha:-未知}" "${updated:-未知}"
        printf '  自动更新定时器: %s\n' "$timer_state"
      else
        info "当前回国阻断: 已关闭（仅拦截内网/25端口/BT）"
      fi
      printf '  自定义名单: 放行 %s 条 (%s) | 拦截 %s 条 (%s)\n' \
        "$allow_cnt" "$allow_file" "$block_cnt" "$block_file"
      ;;
    block-cn-on|on)
      [[ $# -eq 0 ]] || die "用法: sbctl route block-cn-on"
      need_root
      acquire_lock
      ensure_base_config on 0 0 || return 1
      ;;
    block-cn-off|off)
      [[ $# -eq 0 ]] || die "用法: sbctl route block-cn-off"
      need_root
      acquire_lock
      ensure_base_config off 0 0 || return 1
      ;;
    update)
      local quiet=0
      if [[ $# -eq 1 && "$1" == "--quiet" ]]; then
        quiet=1
      elif [[ $# -ne 0 ]]; then
        die "用法: sbctl route update [--quiet]"
      fi
      need_root
      acquire_lock
      if [[ "$(current_cn_mode)" != "on" ]]; then
        [[ "$quiet" == "1" ]] || info "当前回国阻断未开启，无需更新规则集"
        return 0
      fi
      ensure_base_config on 1 "$quiet" || return 1
      ;;
    allow|block)
      [[ $# -ge 1 && $# -le 2 ]] || die "用法: sbctl route ${action} <list|add|del> [域名]"
      local op="$1" domain="${2:-}" list_file
      if [[ "$action" == "allow" ]]; then
        list_file="${SB_RULES_DIR}/${SB_ALLOW_LIST_NAME}"
      else
        list_file="${SB_RULES_DIR}/${SB_BLOCK_LIST_NAME}"
      fi
      case "$op" in
        list)
          [[ $# -eq 1 ]] || die "用法: sbctl route ${action} list"
          need_root
          local entries
          entries=$(python3 "${LIB_DIR}/config_gen.py" route-domains --file "$list_file" list) || return 1
          if [[ -n "$entries" ]]; then
            printf '%s\n' "$entries"
          else
            info "(${action} 自定义名单为空)"
          fi
          ;;
        add|del)
          [[ $# -eq 2 && -n "$domain" ]] || die "用法: sbctl route ${action} ${op} <域名>"
          need_root
          acquire_lock
          mkdir -p "$SB_RULES_DIR"
          [[ ! -L "$list_file" ]] || die "名单文件为符号链接，已中止: $list_file"
          local bk_list="" had_list=0
          if [[ -f "$list_file" ]]; then
            bk_list=$(mktemp "${SB_RULES_DIR}/.${action}.bak.XXXXXX") || return 1
            CLEANUP_PATHS+=("$bk_list")
            cp -a "$list_file" "$bk_list" || return 1
            had_list=1
          fi
          python3 "${LIB_DIR}/config_gen.py" route-domains --file "$list_file" "$op" "$domain" || return 1
          chown root:"$SB_GROUP" "$list_file"
          chmod 640 "$list_file"
          if [[ "$(current_cn_mode)" == "on" ]]; then
            if ! ensure_base_config on 0 0; then
              if [[ "$had_list" == "1" ]]; then
                mv -f "$bk_list" "$list_file" || true
              else
                rm -f "$list_file" || true
              fi
              return 1
            fi
          else
            ok "已更新自定义 ${action} 名单（开启回国阻断后立即生效）"
          fi
          if [[ -n "$bk_list" ]]; then rm -f "$bk_list"; fi
          ;;
        *) die "用法: sbctl route ${action} <list|add|del> [域名]" ;;
      esac
      ;;
    *) die "未知路由操作: ${action}（运行 sbctl route --help 查看用法）" ;;
  esac
}

cmd_install() {
  local sb_ver="latest" proto="vless-reality" port="" sni="" domain="" ip=""
  local cn_mode="off" do_tune=1 bw="500" rtt="auto" swap_size="auto"
  local non_interactive=0 skip_cn=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)         sb_ver="$2"; shift 2 ;;
      --proto)           proto="$2"; shift 2 ;;
      --port)            port="$2"; shift 2 ;;
      --sni)             sni="$2"; shift 2 ;;
      --domain)          domain="$2"; shift 2 ;;
      --ip)              ip="$2"; shift 2 ;;
      --block-cn)        cn_mode="on"; shift ;;
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

  require_supported_protocol "$proto"
  [[ -z "$port" ]] || valid_port "$port" || die "无效端口: $port"
  case "$proto" in
    hy2|hysteria2|naive|anytls)
      if [[ -z "$domain" && ( "$non_interactive" -eq 1 || ! -t 0 ) ]]; then
        die "该协议的非交互安装需要 --domain"
      fi
      ;;
  esac
  need_root
  acquire_lock
  ensure_base_deps
  backup_existing_singbox
  install_self
  install_singbox_binary "$sb_ver"
  ensure_singbox_system
  ensure_base_config "$cn_mode" 0 0

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

# Both directories live on the same Linux filesystem. Each exchange keeps the
# live path present, including if systemd opens it during a restart.
exchange_regen_dirs() {
  python3 - "$SB_CONF_DIR" "$SB_META_DIR" "$1" <<'PY'
import ctypes
import os
import sys
from pathlib import Path

conf, meta, stage = map(Path, sys.argv[1:])
renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int

def exchange(live, candidate):
    at_fdcwd, rename_exchange = -100, 2
    if renameat2(at_fdcwd, os.fsencode(live), at_fdcwd, os.fsencode(candidate), rename_exchange):
        raise OSError(ctypes.get_errno(), f"cannot exchange {live} and {candidate}")

exchange(meta, stage / "meta")
try:
    exchange(conf, stage / "conf")
except BaseException:
    exchange(meta, stage / "meta")
    raise
PY
}

cmd_regen() (
  need_root
  acquire_lock
  [[ -x "$SB_BIN" ]] || die "未检测到 sing-box，请先运行: sbctl install"
  compgen -G "${SB_META_DIR}/*.json" >/dev/null || die "当前没有可重建的节点元数据"

  local stage keep_stage=0 was_active=0 sb_ver out count
  stage=$(mktemp -d "${SB_DIR}/.regen.XXXXXXXX") || die "无法创建重建暂存目录"
  trap 'if [[ "$keep_stage" == 1 ]]; then warn "保留重建目录供恢复: $stage"; else rm -rf -- "$stage"; fi' EXIT
  chown root:"$SB_GROUP" "$stage" && chmod 710 "$stage" || die "无法设置暂存目录权限"
  cp -a "$SB_CONF_DIR" "$stage/conf" && cp -a "$SB_META_DIR" "$stage/meta" || die "无法暂存当前配置"

  sb_ver=$(sb_version) || die "无法读取 sing-box 版本"
  info "按 sing-box ${sb_ver} 语法重建全部入站配置..."
  out=$(python3 "${LIB_DIR}/config_gen.py" regen \
    --conf-dir "$stage/conf" --meta-dir "$stage/meta" --state-dir "$SB_STATE_DIR" \
    --sb-ver "$sb_ver" --sb-bin "$SB_BIN") || die "生成失败，原配置仍在使用"
  count=$(awk -F= '$1=="COUNT"{print $2}' <<<"$out")
  [[ "$count" =~ ^[1-9][0-9]*$ ]] || die "未生成完整的节点配置"
  local node_file tag
  local -a nodes=("$SB_META_DIR"/*.json)
  [[ "$count" -eq "${#nodes[@]}" ]] || die "重建数量与原有节点数不一致"
  for node_file in "${nodes[@]}"; do
    tag=$(basename "$node_file")
    chown root:"$SB_GROUP" "$stage/conf/$tag" || die "无法设置节点配置权限"
  done
  local check_base="$SB_CONFIG" has_route_candidate=0
  if [[ -f "${SB_RULES_DIR}/${SB_ROUTE_STATE_NAME}" && ! -L "${SB_RULES_DIR}/${SB_ROUTE_STATE_NAME}" ]]; then
    local route_mode
    route_mode=$(current_cn_mode)
    python3 "${LIB_DIR}/config_gen.py" base-config \
      --out "$stage/config.json" \
      --log-file "${SB_LOG_DIR}/error.log" \
      --cn-mode "$route_mode" \
      --rules-dir "$SB_RULES_DIR" \
      --allow-file "${SB_RULES_DIR}/${SB_ALLOW_LIST_NAME}" \
      --block-file "${SB_RULES_DIR}/${SB_BLOCK_LIST_NAME}" || die "路由基础配置重建失败，原配置仍在使用"
    chown root:"$SB_GROUP" "$stage/config.json" && chmod 640 "$stage/config.json" || die "无法设置基础配置权限"
    check_base="$stage/config.json"
    has_route_candidate=1
  fi
  run_as_service_user "$SB_BIN" check -c "$check_base" -C "$stage/conf" || die "候选配置校验失败，原配置仍在使用"
  sync_legacy_whitelists || die "现有白名单未能生效，原配置仍在使用"

  systemctl is-active --quiet sing-box && was_active=1
  keep_stage=1
  if [[ "$has_route_candidate" == 1 && -f "$SB_CONFIG" ]]; then
    cp -a "$SB_CONFIG" "$stage/orig-config.json" || die "无法备份原基础配置"
  fi
  exchange_regen_dirs "$stage" || die "切换重建配置失败"
  if [[ "$has_route_candidate" == 1 ]]; then
    mv -f "$stage/config.json" "$SB_CONFIG" || {
      exchange_regen_dirs "$stage" || true
      die "切换基础配置失败"
    }
  fi
  if ! validate_and_restart; then
    exchange_regen_dirs "$stage" || die "恢复原配置失败"
    if [[ "$has_route_candidate" == 1 && -f "$stage/orig-config.json" ]]; then
      mv -f "$stage/orig-config.json" "$SB_CONFIG" || die "恢复原基础配置失败"
    fi
    if [[ "$was_active" == 1 ]]; then
      validate_and_restart || die "原配置已恢复，服务重启失败"
    else
      systemctl stop sing-box || die "原配置已恢复，服务停止失败"
    fi
    keep_stage=0
    die "服务启动失败，已恢复原配置"
  fi
  keep_stage=0
  ok "已按 sing-box ${sb_ver} 重建并验收 ${count} 个节点配置"
)

cmd_update() {
  [[ $# -le 1 && "${1:-}" != -* ]] || die "用法: sbctl update [版本]"
  need_root
  acquire_lock
  local target_ver="${1:-latest}"
  install_singbox_binary "$target_ver"
  if [[ -f "$SB_CONFIG" ]] && compgen -G "${SB_CONF_DIR}/*.json" >/dev/null 2>&1; then
    if ! validate_and_restart; then
      warn "新版 sing-box 与当前配置不兼容或启动失败，正在自动回滚旧版核心..."
      if restore_singbox_binary; then
        validate_and_restart || warn "回滚后重启异常，请手动检查 journalctl -u sing-box"
      fi
      die "已中止升级并回滚核心（若是 1.13 -> 1.14 跨版本语法变更，可先确认后使用 sbctl regen）"
    fi
  fi
  rm -f "${SB_BIN}.bak"
}

cmd_version() {
  local sv
  sv=$(sb_version)
  printf 'sb-kit %s (sing-box: %s)\n' "$SBKIT_VERSION" "${sv:-未安装}"
}

cmd_sync() {
  local source
  if [[ $# == 2 && "$1" == --source ]]; then
    source="$2"
  elif [[ $# == 0 ]]; then
    if is_staging_copy; then source="$SCRIPT_DIR"; else source="$PWD"; fi
  else
    die "用法: sbctl sync [--source 仓库目录]"
  fi
  [[ -n "$source" ]] || die "请指定 sb-kit 源码目录"
  need_root
  install_self 0 "$source"
  "$SB_CTL_DST" --version
}

cmd_audit() {
  need_root
  bash "${LIB_DIR}/audit.sh"
}

cmd_uninstall() {
  local keep_tcpfit=0 marker="${SB_DIR}/.managed-by-sb-kit" origin=legacy snapshot="" svc name directory
  if [[ $# -gt 0 ]]; then
    [[ $# -eq 1 && "$1" == "--keep-tcpfit" ]] || die "用法: sbctl uninstall [--keep-tcpfit]"
    keep_tcpfit=1
  fi
  need_root
  acquire_lock
  require_managed_installation
  if [[ -s "$marker" ]]; then
    [[ "$(sed -n '1p' "$marker")" == sb-kit-v1 ]] || die "无法识别托管标记，已中止卸载"
    origin=$(sed -n '2p' "$marker")
    if [[ "$origin" != fresh ]]; then
      [[ "$origin" =~ ^pre-install-[[:alnum:]._-]+$ ]] || die "托管记录中的备份名称无效"
      snapshot="${SB_BACKUP_ROOT}/${origin}"
      [[ -d "$snapshot" && ! -L "$snapshot" && -f "$snapshot/complete" ]] || die "原实例备份缺失，已中止卸载: $snapshot"
    fi
  fi
  [[ -r "${LIB_DIR}/managed_files.py" ]] || die "缺少卸载组件 managed_files.py，请重新同步 sb-kit"
  if [[ -f "$SB_UNIT" ]]; then
    systemctl disable --now sing-box || die "无法停用托管服务，已中止卸载"
  fi
  python3 "${LIB_DIR}/managed_files.py" "$SB_DIR" "$SB_STATE_DIR" "$SB_LOG_DIR" "$snapshot" "$origin" || die "清理节点失败；托管标记和备份仍保留"
  local unit_dir="${SB_UNIT%/*}"
  for svc in "${unit_dir}"/sbkit_*.service "${unit_dir}"/sbkit-hop-*.service; do
    [[ -f "$svc" ]] || continue
    [[ ! -L "$svc" ]] && grep -Eq '^Description=sb-kit (port whitelist|Hysteria2 UDP port hopping) ' "$svc" || continue
    name="${svc##*/}"
    case "$name" in
      sbkit_wl_*.service|sbkit_hop_*.service)
        nft_unit_remove "${name%.service}" || die "移除 $name 的运行规则失败"
        continue ;;
    esac
    systemctl disable --now "$name" || die "停用 $name 失败"
    rm -f "$svc" || die "删除 $name 失败"
    name="${name%.service}"
    rm -f "${NFT_DIR}/${name}.nft" || die "删除规则 $name 失败"
    if command -v nft >/dev/null 2>&1 && nft list table inet "$name" >/dev/null 2>&1; then
      nft delete table inet "$name" || die "移除运行中的规则 $name 失败"
    fi
  done
  if [[ -f "${unit_dir}/sbkit-rules-update.timer" && ! -L "${unit_dir}/sbkit-rules-update.timer" ]] &&
     grep -Fxq 'Description=sb-kit weekly CN route rules update timer' "${unit_dir}/sbkit-rules-update.timer"; then
    systemctl disable --now sbkit-rules-update.timer >/dev/null 2>&1 || true
    rm -f "${unit_dir}/sbkit-rules-update.timer" || die "删除规则更新定时器失败"
  fi
  if [[ -f "${unit_dir}/sbkit-rules-update.service" && ! -L "${unit_dir}/sbkit-rules-update.service" ]] &&
     grep -Fxq 'Description=sb-kit CN route rules auto-updater' "${unit_dir}/sbkit-rules-update.service"; then
    rm -f "${unit_dir}/sbkit-rules-update.service" || die "删除规则更新服务失败"
  fi
  local -a destinations=("$SB_CONFIG" "$SB_UNIT" "$SB_LOGROTATE" "$SB_BIN" "${SB_BIN}.bak")
  local -a sources=(etc-sing-box/config.json local.service logrotate sing-box previous-core-backup)
  local i original target
  for i in "${!destinations[@]}"; do
    target="${destinations[$i]}"
    original="${snapshot}/${sources[$i]}"
    if [[ -n "$snapshot" && ( -e "$original" || -L "$original" ) ]]; then
      mkdir -p "${target%/*}" && rm -f "$target" && cp -a "$original" "$target" || die "还原 $target 失败，原件位于 $snapshot"
    else
      rm -f "$target" || die "清理 $target 失败"
    fi
  done
  systemctl daemon-reload || die "重新加载 systemd 失败"
  if [[ -n "$snapshot" ]]; then
    if [[ -f "$snapshot/was-enabled" ]]; then systemctl enable sing-box || die "恢复原服务启用状态失败"; fi
    if [[ -f "$snapshot/was-active" ]]; then systemctl start sing-box || die "恢复原服务失败，请检查 $snapshot"; fi
    ok "已恢复接管前的文件及服务状态，原备份位于: $snapshot"
  elif [[ "$origin" == legacy ]]; then
    warn "历史托管标记未记录接管来源。旧备份可在 $SB_BACKUP_ROOT 查阅。"
  fi
  if [[ "$keep_tcpfit" -eq 0 && -x "$TCPFIT_BIN" && -f "$SB_DIR/.sb-kit-tcpfit-tuned" ]]; then
    info "回滚 tcpfit 调优..."
    TCPFIT_NO_TELEMETRY=1 "$TCPFIT_BIN" rollback || die "tcpfit 回滚失败"
  fi
  python3 "$LIB_DIR/bundle.py" uninstall "$SB_LIB_DST" "$SB_CTL_DST" ||
    die "清理托管版本失败，请检查安装目录"
  rm -f "$marker" "$SB_DIR/.sb-kit-tcpfit-tuned" "$SB_CTL_DST" || die "移除 sb-kit 管理文件失败"
  for name in audit.sh config_gen.py sni_probe.py managed_files.py VERSION; do
    rm -f "$SB_LIB_DST/$name" || die "移除 sb-kit 组件 $name 失败"
  done
  for directory in "$SB_RULES_DIR" "$SB_DIR" "$SB_LIB_DST"; do
    if [[ -n "$snapshot" && ( ( "$directory" == "$SB_RULES_DIR" && -d "$snapshot/etc-sing-box/rules" ) ||
                               ( "$directory" == "$SB_DIR" && -d "$snapshot/etc-sing-box" ) ) ]]; then
      continue
    fi
    rmdir "$directory" 2>/dev/null || true
  done
  for directory in "$SB_DIR" "$SB_LOG_DIR" "$SB_STATE_DIR" "$SB_LIB_DST"; do
    [[ ! -d "$directory" ]] || info "已保留已有资料: $directory"
  done
  ok "sb-kit 托管的服务与文件已卸载"
}

show_help() {
  cat <<EOF
sbctl (sb-kit ${SBKIT_VERSION}) — 纯 sing-box + tcpfit 精简管理工具（无面板、无二维码、仅纯链接）

用法:
  sbctl                             打开终端可视化交互菜单
  sbctl install [选项]              一键安装 sing-box + 自动 BBR 调优 + 首个节点
  sbctl add <协议> [选项]           添加节点 (vless-reality|hy2|naive|anytls|ss2022|socks)
  sbctl modify [tag] [选项]         修改已有节点（端口/SNI/密钥/备注/白名单/跳跃/伪装）
  sbctl links                       查看全部节点链接（socks 附指纹浏览器格式）
  sbctl yaml                        按需导出 Clash/Mihomo proxies YAML 片段
  sbctl del [tag]                   删除节点
  sbctl tune [--bw N --rtt auto]    BBR/TCP 调优（支持 --rollback）
  sbctl route [status|block-cn-on|off|update|allow|block]
                                    回国阻断开关（v2fly 精准方案）与规则更新
  sbctl audit                       一键只读安全巡检
  sbctl update [ver]                仅升级 sing-box 核心（SHA-256 校验，失败自动回滚）
  sbctl regen                       按当前 sing-box 版本语法从 meta 重建全部入站配置
  sbctl sync [--source DIR]         从当前仓库或指定源码目录同步 sbctl 与 lib 到 /usr/local
  sbctl --version                   查看 sb-kit 与 sing-box 版本
  sbctl uninstall [--keep-tcpfit]   彻底卸载

环境变量:
  SB_CF_TOKEN                       Cloudflare DNS-01 API Token（避免出现在命令行中）
EOF
}

menu_command() {
  # Start a separate invocation so die(), errexit and the write lock belong to one action.
  bash "${BASH_SOURCE[0]}" "$@" || warn "命令执行失败，已返回菜单。"
}

menu_system_action() (
  need_root
  acquire_lock
  case "$1" in
    tcpfit) install_tcpfit && TCPFIT_NO_TELEMETRY=1 "$TCPFIT_BIN" ;;
    start) systemctl start sing-box && ok "已启动" ;;
    stop) systemctl stop sing-box && ok "已停止" ;;
    restart) validate_and_restart ;;
  esac
)

interactive_menu() {
  while true; do
    local ver status user_now cc_algo qdisc mem_mb initcwnd node_count node_list route_mode
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
    route_mode=$(current_cn_mode 2>/dev/null || echo "off")

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
    printf '%b│%b  %bsb-kit v%s%b · 纯 sing-box + tcpfit 精简管理工具          %b│%b\n' "$C_CYAN" "$C_NC" "$C_BOLD" "$SBKIT_VERSION" "$C_NC" "$C_CYAN" "$C_NC"
    printf '%b├──────────────────────────────────────────────────────────────┤%b\n' "$C_CYAN" "$C_NC"
    printf '  核心: %-12s %b  |  用户: %s\n' "$ver" "$status" "${user_now:-root}"
    printf '  网络: %s + %s  |  initcwnd: %s  |  内存: %s MB\n' "$cc_algo" "$qdisc" "$initcwnd" "$mem_mb"
    printf '  路由: 回国阻断 %-6s     |  节点: %d 个 %s\n' "$([[ "$route_mode" == "on" ]] && echo 开启 || echo 关闭)" "$node_count" "${node_list:+(${node_list})}"
    printf '%b├──────────────────────────────────────────────────────────────┤%b\n' "$C_CYAN" "$C_NC"
    printf '  [1]  一键安装（sing-box + 自动 BBR 调优 + 首个节点）\n'
    printf '  [2]  添加节点（VLESS-Reality / Hy2 / Naive / AnyTLS / SS / Socks）\n'
    printf '  [3]  修改节点（改端口 / 换 SNI / 重置账密 / 改白名单或跳跃）\n'
    printf '  [4]  查看全部节点链接（纯文本直接复制；可选导出 YAML）\n'
    printf '  [5]  删除节点\n'
    printf '  %b──────────────────────────────────────────────────────────%b\n' "$C_DIM" "$C_NC"
    printf '  [6]  BBR / TCP 调优（自动调优 / 重调 / tcpfit 菜单 / 回滚）\n'
    printf '  [7]  路由与回国阻断（开启 / 关闭 / 更新规则 / 自定义放行或拦截）\n'
    printf '  [8]  服务管理（启动 / 停止 / 重启 / 查看错误日志）\n'
    printf '  [9]  一键安全巡检 (audit)\n'
    printf '  [10] 核心升级 / 重建配置（update 自动回滚 / regen 跨版本同步）\n'
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
        read -rp "是否开启回国阻断（拦影音/网盘/社交/银行/PT，放行指纹浏览器/飞书/1688）? [Y/n]: " block_cn
        [[ "${block_cn:-y}" =~ ^[Yy]$ ]] && args+=(--block-cn)
        menu_command install "${args[@]}"
        ;;
      2)
        printf '  1) vless-reality  2) hy2  3) naive  4) anytls  5) ss2022  6) socks\n'
        local p=""
        read -rp "请选择协议 [1-6]: " p
        case "$p" in
          1) menu_command add vless-reality ;;
          2) menu_command add hy2 ;;
          3) menu_command add naive ;;
          4) menu_command add anytls ;;
          5) menu_command add ss2022 ;;
          6) menu_command add socks ;;
          *) warn "无效选择" ;;
        esac
        ;;
      3) menu_command modify ;;
      4)
        cmd_links
        local show_y=""
        read -rp "是否顺便打印 Clash/Mihomo YAML 片段? [y/N]: " show_y
        [[ "${show_y:-n}" =~ ^[Yy]$ ]] && cmd_yaml
        ;;
      5) menu_command del ;;
      6)
        printf '  1) 自动调优（按地区推 RTT）  2) 自定义带宽/RTT  3) 打开 tcpfit 原生菜单(可扫拐点)  4) 一键回滚\n'
        local ta=""
        read -rp "请选择 [1-4]: " ta
        case "$ta" in
          1) menu_command tune --bw 500 --rtt auto ;;
          2)
            local bw="" rtt=""
            read -rp "套餐带宽 Mbps [500]: " bw
            read -rp "参考 RTT ms [auto]: " rtt
            menu_command tune --bw "${bw:-500}" --rtt "${rtt:-auto}"
            ;;
          3)
            menu_system_action tcpfit || warn "tcpfit 执行失败"
            ;;
          4) menu_command tune --rollback ;;
          *) warn "无效选择" ;;
        esac
        ;;
      7)
        cmd_route status
        printf '  1) 开启回国阻断  2) 关闭回国阻断  3) 立即更新规则集  4) 添加放行域名  5) 添加拦截域名\n'
        local ra="" dom=""
        read -rp "请选择 [1-5，回车取消]: " ra
        case "$ra" in
          1) menu_command route block-cn-on ;;
          2) menu_command route block-cn-off ;;
          3) menu_command route update ;;
          4)
            read -rp "请输入要放行的域名后缀（如 example.cn）: " dom
            [[ -n "$dom" ]] && menu_command route allow add "$dom"
            ;;
          5)
            read -rp "请输入要拦截的域名后缀（如 example.com）: " dom
            [[ -n "$dom" ]] && menu_command route block add "$dom"
            ;;
          "") ;;
          *) warn "无效选择" ;;
        esac
        ;;
      8)
        printf '  1) 启动  2) 停止  3) 重启  4) 查看最近 30 行错误日志\n'
        local sa=""
        read -rp "请选择 [1-4]: " sa
        case "$sa" in
          1) menu_system_action start || warn "启动失败" ;;
          2) menu_system_action stop || warn "停止失败" ;;
          3) menu_system_action restart || warn "重启失败" ;;
          4) [[ -f "${SB_LOG_DIR}/error.log" ]] && tail -n 30 "${SB_LOG_DIR}/error.log" || info "暂无错误日志" ;;
          *) warn "无效选择" ;;
        esac
        ;;
      9) cmd_audit || true ;;
      10)
        printf '  1) 仅更新 sing-box 核心（失败自动回滚）  2) 按当前核心版本重建全部配置 (regen)\n'
        local ua=""
        read -rp "请选择 [1-2]: " ua
        case "$ua" in
          1) menu_command update ;;
          2) menu_command regen ;;
          *) warn "无效选择" ;;
        esac
        ;;
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

main() (
  set -e
  CLEANUP_PATHS=()
  trap cleanup_paths EXIT
  if [[ $# -eq 0 ]]; then
    if [[ -t 0 ]]; then
      if is_staging_copy; then
        ( install_self 1 ) || return 1
      fi
      interactive_menu
    else
      show_help
    fi
    return 0
  fi

  local sub="$1"
  shift
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    case "$sub" in
      add) cmd_add vless-reality "$1"; return ;;
      route) route_help; return ;;
      del|rm|sync|regen|update|up|uninstall|audit|check|links|link|url|yaml|clash)
        show_help; return ;;
    esac
  fi

  case "$sub" in
    -h|--help|help)    show_help; return ;;
    -v|--version|version) cmd_version; return ;;
    sync)              cmd_sync "$@"; return ;;
    uninstall)         cmd_uninstall "$@"; return ;;
    install)           cmd_install "$@"; return ;;
    add)               cmd_add "$@" ;;
    modify|mod|edit)   cmd_modify "$@" ;;
    links|link|url)    [[ $# -le 1 ]] || die "用法: sbctl links [meta-dir]"; cmd_links "$@"; return ;;
    yaml|clash)        [[ $# -le 1 ]] || die "用法: sbctl yaml [meta-dir]"; cmd_yaml "$@"; return ;;
    del|rm)            cmd_del "$@" ;;
    tune|bbr)          cmd_tune "$@" ;;
    route)             cmd_route "$@" ;;
    audit|check)       [[ $# -eq 0 ]] || die "用法: sbctl audit"; cmd_audit; return ;;
    update|up)         cmd_update "$@" ;;
    regen)
      [[ $# -eq 0 ]] || die "用法: sbctl regen"
      need_root
      acquire_lock
      cmd_regen
      ;;
    *) die "未知子命令: ${sub}（运行 sbctl --help 查看用法）" ;;
  esac
  local result=$?
  [[ "$result" -eq 0 ]] || return "$result"
  # Parsers acquire the write lock only for real changes. This also distinguishes
  # a dry run or help flag from a literal option value with the same spelling.
  if [[ "$SB_LOCK_HELD" == 1 ]] && is_staging_copy; then
    ( install_self 1 ) || die "业务操作已完成，但 sbctl 同步失败。请重新运行 sbctl.sh sync。"
  fi
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
