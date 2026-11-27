#!/usr/bin/env bash
# Exercise the streamed installer with a real shallow Git clone and private root paths.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d /tmp/sb-kit-bootstrap.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
cp "$repo/install.sh" "$work/install.sh"

run_suite() {
  mount -t tmpfs tmpfs /root
  mount -t tmpfs tmpfs /run
  mkdir -p /run/systemd/system "$work/bin"
  export PATH="$work/bin:$PATH" GIT_ALLOW_PROTOCOL=file GIT_TERMINAL_PROMPT=0
  export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$work/gitconfig"
  local url=https://github.com/Dreamer-nxy/sb-kit.git dest=/root/sb-kit
  git config --global user.name test
  git config --global user.email test@example.invalid
  git config --global "url.file://$work/origin.insteadOf" "$url"
  git init --quiet -b main "$work/origin"
  git -C "$work/origin" commit --quiet --allow-empty -m initial
  cat >"$work/origin/sbctl.sh" <<'STUB'
printf '%s\n' called >>"$work/calls"
printf '%s\n' "$@" >"$work/args"
[[ ! -e "$work/fail" ]] || exit 47
STUB
  git -C "$work/origin" add sbctl.sh
  git -C "$work/origin" commit --quiet -m installer
  cat >"$work/bin/ss" <<'STUB'
#!/bin/sh
[ "$*" = '-H -ltn sport = :443' ] || exit 2
if [ -e "$work/busy" ]; then echo LISTEN; fi
STUB
  chmod +x "$work/bin/ss"
  ln -s /bin/true "$work/bin/logrotate"
  ln -s /bin/false "$work/bin/apt-get"

  bootstrap() { cat "$work/install.sh" | bash; }
  expect_failure() {
    if bootstrap >"$work/output" 2>&1; then
      echo "FAIL: bootstrap accepted $1" >&2
      return 1
    fi
  }

  echo keep >"$dest"
  expect_failure 'an occupied checkout path'
  [[ $(cat "$dest") == keep && ! -e "$work/calls" ]]
  rm "$dest"
  touch "$work/busy"
  expect_failure 'an occupied port'
  [[ ! -e "$dest" && ! -e "$work/calls" ]]
  rm "$work/busy"

  touch "$work/fail"
  expect_failure 'a failing installer'
  [[ ! -e "$dest" && $(cat "$work/calls") == called ]]
  if compgen -G '/root/.sb-kit-install.*' >/dev/null; then return 1; fi
  rm "$work/fail"
  bootstrap
  printf '%s\n' install --proto vless-reality --port 443 --sni auto --no-tune --non-interactive | cmp - "$work/args"
  [[ $(git -C "$dest" config remote.origin.url) == "$url" ]]
  [[ $(git -C "$dest" branch --show-current) == main && $(git -C "$dest" rev-list --count HEAD) == 1 ]]
  [[ $(git -C "$dest" rev-parse HEAD) == "$(git -C "$work/origin" rev-parse HEAD)" ]]
  expect_failure 'a repeated installation'
  [[ $(wc -l <"$work/calls") -eq 2 ]]
  echo 'public bootstrap regressions passed'
}

export work
export -f run_suite
unshare --mount --propagation private bash -euo pipefail -c run_suite
