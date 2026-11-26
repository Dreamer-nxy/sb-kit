#!/usr/bin/env bash
# deploy.sh — Push local private sb-kit to a remote VPS over SSH and run sbctl.
# Zero GitHub Token is ever stored on the target VPS; /usr/local/bin/sbctl is auto-synced.
#
# Examples:
#   ./deploy.sh root@1.2.3.4
#   ./deploy.sh root@1.2.3.4:50222
#   ./deploy.sh root@1.2.3.4:50222 sync
#   ./deploy.sh root@1.2.3.4:50222 install --proto vless-reality --port 443 --bw 500 --non-interactive

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  cat <<'EOF'
用法: ./deploy.sh <user@host[:port]> [sync | sbctl 子命令及参数...]

示例:
  ./deploy.sh root@1.2.3.4                  # 推送、同步远端 sbctl 并打开交互菜单
  ./deploy.sh root@1.2.3.4:50222 sync       # 仅同步更新远端 /usr/local/bin/sbctl 与 lib
  ./deploy.sh root@1.2.3.4:50222 audit      # 推送并执行一键巡检
  ./deploy.sh root@1.2.3.4 install --proto vless-reality --port 443 --bw 500 --sni auto --non-interactive

安全提示:
  请勿通过命令行 --cf-token 传 Cloudflare Token；如需 DNS-01 请在交互提示中隐藏输入（不回显）。
EOF
  exit 0
fi

TARGET="$1"
shift

SSH_PORT="22"
if [[ "$TARGET" == *:* ]]; then
  SSH_PORT="${TARGET##*:}"
  TARGET="${TARGET%:*}"
fi

REMOTE_STAGE="/tmp/sb-kit-stage"

echo "[*] 正在推送 sb-kit 到 ${TARGET}:${SSH_PORT}（不留任何 GitHub Token）..."
COPYFILE_DISABLE=1 tar -C "$SCRIPT_DIR" -czf - sbctl.sh lib | \
  ssh -p "$SSH_PORT" "$TARGET" "rm -rf '${REMOTE_STAGE}' && mkdir -p '${REMOTE_STAGE}' && tar -xzf - -C '${REMOTE_STAGE}' && chmod +x '${REMOTE_STAGE}/sbctl.sh' '${REMOTE_STAGE}/lib/'*.sh '${REMOTE_STAGE}/lib/'*.py"

if [[ "${1:-}" == "sync" ]]; then
  echo "[+] 同步远端 /usr/local/bin/sbctl 与 /usr/local/lib/sb-kit..."
  ssh -p "$SSH_PORT" "$TARGET" "bash '${REMOTE_STAGE}/sbctl.sh' --version >/dev/null && mkdir -p /usr/local/lib/sb-kit && cp -f '${REMOTE_STAGE}/lib/'* /usr/local/lib/sb-kit/ && chmod 755 /usr/local/lib/sb-kit/*.py /usr/local/lib/sb-kit/*.sh && cp -f '${REMOTE_STAGE}/sbctl.sh' /usr/local/bin/sbctl.new && chmod 755 /usr/local/bin/sbctl.new && mv -f /usr/local/bin/sbctl.new /usr/local/bin/sbctl && rm -rf '${REMOTE_STAGE}' && /usr/local/bin/sbctl --version"
  exit 0
fi

if [[ $# -eq 0 ]]; then
  echo "[+] 推送完成，进入远端 sbctl 可视化菜单..."
  ssh -t -p "$SSH_PORT" "$TARGET" "bash '${REMOTE_STAGE}/sbctl.sh'; rm -rf '${REMOTE_STAGE}'"
else
  printf -v ESCAPED_ARGS ' %q' "$@"
  echo "[+] 推送完成，执行: sbctl${ESCAPED_ARGS}"
  ssh -t -p "$SSH_PORT" "$TARGET" "bash '${REMOTE_STAGE}/sbctl.sh'${ESCAPED_ARGS}; rc=\$?; rm -rf '${REMOTE_STAGE}'; exit \$rc"
fi
