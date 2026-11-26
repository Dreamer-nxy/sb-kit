#!/usr/bin/env bash
# deploy.sh — Push local private sb-kit to a remote VPS over SSH and run sbctl.
# Zero GitHub Token is ever stored on the target VPS.
#
# Examples:
#   ./deploy.sh root@1.2.3.4
#   ./deploy.sh root@1.2.3.4:50222
#   ./deploy.sh root@1.2.3.4:50222 install --proto vless-reality --port 443 --bw 500 --non-interactive

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  cat <<'EOF'
用法: ./deploy.sh <user@host[:port]> [sbctl 子命令及参数...]

示例:
  ./deploy.sh root@1.2.3.4                  # 推送并打开交互菜单
  ./deploy.sh root@1.2.3.4:50222            # 指定非 22 SSH 端口
  ./deploy.sh root@1.2.3.4:50222 audit      # 推送并直接执行一键巡检
  ./deploy.sh root@1.2.3.4 install --proto vless-reality --port 443 --bw 500 --sni auto --non-interactive
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

if [[ $# -eq 0 ]]; then
  echo "[+] 推送完成，进入远端 sbctl 可视化菜单..."
  ssh -t -p "$SSH_PORT" "$TARGET" "bash '${REMOTE_STAGE}/sbctl.sh'; rm -rf '${REMOTE_STAGE}'"
else
  printf -v ESCAPED_ARGS ' %q' "$@"
  echo "[+] 推送完成，执行: sbctl${ESCAPED_ARGS}"
  ssh -t -p "$SSH_PORT" "$TARGET" "bash '${REMOTE_STAGE}/sbctl.sh'${ESCAPED_ARGS}; rc=\$?; rm -rf '${REMOTE_STAGE}'; exit \$rc"
fi
