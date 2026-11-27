#!/usr/bin/env bash
# Public installer for a fresh Debian or Ubuntu VPS.
install_sb() (
  set -euo pipefail
  local checkout=/root/sb-kit stage listeners
  local -a packages=()
  if (( EUID != 0 )) || [[ ! -d /run/systemd/system ]]; then
    echo '请在使用 systemd 的 Debian 或 Ubuntu VPS 上以 root 运行安装命令。' >&2
    exit 1
  fi
  command -v git >/dev/null || packages+=(git)
  command -v flock >/dev/null || packages+=(util-linux)
  command -v ss >/dev/null || packages+=(iproute2)
  command -v logrotate >/dev/null || packages+=(logrotate)
  [[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)
  if (( ${#packages[@]} )); then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
  fi

  exec 8>/run/sb-kit-install.lock
  flock -n 8 || { echo '另一个一键安装正在运行。' >&2; exit 1; }
  if [[ -e "$checkout" || -L "$checkout" ]]; then
    echo "已有 $checkout，已保留原目录。如果已经装好，输入 sb 打开管理菜单。" >&2
    exit 1
  fi
  listeners=$(ss -H -ltn 'sport = :443')
  if [[ -n "$listeners" ]]; then
    echo 'TCP 443 已被占用，请先确认该端口可用于新节点。' >&2
    exit 1
  fi

  stage=$(mktemp -d /root/.sb-kit-install.XXXXXXXX)
  trap 'rm -rf -- "$stage"' EXIT
  GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch main https://github.com/Dreamer-nxy/sb-kit.git "$stage/source"
  bash "$stage/source/sbctl.sh" install --proto vless-reality --port 443 --sni auto --no-tune --non-interactive </dev/null
  mv -nT -- "$stage/source" "$checkout"
  if [[ -e "$stage/source" ]]; then
    echo "服务已安装。安装期间出现了 $checkout，已保留该目录。" >&2
    exit 1
  fi
  echo '安装完成。输入 sb 打开中文管理菜单，输入 sb i 查看节点链接。'
)

# Start only after the function above has been downloaded in full.
install_sb
