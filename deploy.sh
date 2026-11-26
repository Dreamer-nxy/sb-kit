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

REMOTE_STAGE=""
valid_stage() {
  [[ "$REMOTE_STAGE" =~ ^/tmp/sb-kit-stage\.[a-zA-Z0-9]{10}$ ]]
}

cleanup_stage() {
  local rc=$?
  trap - EXIT
  if valid_stage; then
    if ! ssh -n -o ConnectTimeout=5 -p "$SSH_PORT" -- "$TARGET" "rm -rf -- '$REMOTE_STAGE'"; then
      printf '[!] 无法确认远端临时目录已清理: %s\n' "$REMOTE_STAGE" >&2
      [[ "$rc" -ne 0 ]] || rc=1
    fi
  fi
  exit "$rc"
}
trap cleanup_stage EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

echo "[*] 正在推送 sb-kit 到 ${TARGET}:${SSH_PORT}（不留任何 GitHub Token）..."
REMOTE_STAGE=$(ssh -n -p "$SSH_PORT" -- "$TARGET" 'umask 077 && mktemp -d /tmp/sb-kit-stage.XXXXXXXXXX')
valid_stage || { echo '[x] 远端未返回预期的临时目录路径' >&2; exit 1; }
upload_command="cd '$REMOTE_STAGE' && tar -xzf - && chmod +x sbctl.sh lib/*.sh lib/*.py ||
  { rc=\$?; rm -rf -- '$REMOTE_STAGE'; exit \"\$rc\"; }"
COPYFILE_DISABLE=1 tar --no-xattrs --exclude='__pycache__' -C "$SCRIPT_DIR" -czf - sbctl.sh lib | \
  ssh -p "$SSH_PORT" -- "$TARGET" "$upload_command"

ssh_args=(-p "$SSH_PORT")
if [[ "${1:-}" == "sync" ]]; then
  echo "[+] 同步远端 /usr/local/bin/sbctl 与 /usr/local/lib/sb-kit..."
elif [[ $# -eq 0 ]]; then
  echo "[+] 推送完成，进入远端 sbctl 可视化菜单..."
  ssh_args+=(-t)
else
  echo "[+] 推送完成，执行远端 sbctl..."
  ssh_args+=(-t)
fi

# SSH passes the command through the user's login shell, which can be /bin/sh.
remote_command="bash '$REMOTE_STAGE/sbctl.sh'"
for arg in "$@"; do
  quoted=${arg//\'/\'\\\'\'}
  remote_command+=" '$quoted'"
done
# The remote shell owns normal cleanup, including a failed command or an SSH hangup.
# The local trap covers upload failures and retries cleanup after a lost connection.
remote_cleanup='
clean_exit() {
  rc=$?
  trap - 0
  if ! rm -rf -- "$stage" && [ "$rc" -eq 0 ]; then rc=1; fi
  exit "$rc"
}
trap clean_exit 0
'
remote_command="stage='$REMOTE_STAGE'
$remote_cleanup
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
$remote_command"
ssh "${ssh_args[@]}" -- "$TARGET" "$remote_command"
REMOTE_STAGE=""
