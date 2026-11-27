#!/usr/bin/env bash
# Sync the sb management tools to a remote VPS over SSH.
set -euo pipefail

usage() {
  printf '%s\n' '用法: ./deploy.sh <user@host[:port]> sync' \
    '新 VPS 安装请使用 README 的一键命令：https://github.com/Dreamer-nxy/sb-kit#readme'
}

if [[ $# == 1 && ( "$1" == -h || "$1" == --help ) ]]; then
  usage
  exit 0
fi
if [[ $# != 2 || -z "${1:-}" || "${2:-}" != sync ]]; then
  usage >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$1"
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

echo "[*] 正在上传管理工具到 ${TARGET}:${SSH_PORT}..."
REMOTE_STAGE=$(ssh -n -p "$SSH_PORT" -- "$TARGET" 'umask 077 && mktemp -d /tmp/sb-kit-stage.XXXXXXXXXX')
valid_stage || { echo '[x] 远端未返回预期的临时目录路径' >&2; exit 1; }
upload_command="cd '$REMOTE_STAGE' && tar -xzf - && chmod +x sbctl.sh lib/*.sh lib/*.py ||
  { rc=\$?; rm -rf -- '$REMOTE_STAGE'; exit \"\$rc\"; }"
COPYFILE_DISABLE=1 tar --no-xattrs --exclude='__pycache__' -C "$SCRIPT_DIR" -czf - sbctl.sh lib | \
  ssh -p "$SSH_PORT" -- "$TARGET" "$upload_command"

echo "[+] 同步远端 /usr/local/bin/sb 与 /usr/local/lib/sb-kit..."

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
bash '$REMOTE_STAGE/sbctl.sh' sync"
ssh -n -p "$SSH_PORT" -- "$TARGET" "$remote_command"
REMOTE_STAGE=""
