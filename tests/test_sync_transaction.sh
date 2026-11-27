#!/usr/bin/env bash
# Exercise real CLI entry points in a private Linux mount namespace.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/local/bin" "$work/local/lib" "$work/hooks" "$work/empty"

fail() { echo "FAIL: $*" >&2; exit 1; }

assert_pair() {
  local expected=$1 entry=${2:-/usr/local/bin/sb}
  [[ $("$entry" --version) == "sb-kit $expected (sing-box: 未安装)" ]] || fail "CLI should be $expected"
  [[ $("$entry" check) == "helper-$expected" ]] || fail "helper should be $expected"
  [[ $(cat /usr/local/lib/sb-kit/VERSION) == "$expected" ]] || fail "VERSION should be $expected"
}

interrupt_sync() {
  local source_dir=$1 destination=$2 fault=$3
  rm -f "$work/hit"
  if (cd "$source_dir" && SB_TEST_DEST="$destination" SB_TEST_FAULT="$fault" \
        SB_TEST_HIT="$work/hit" PYTHONPATH="$work/hooks" bash ./sbctl.sh sync) >"$work/fault.log" 2>&1; then
    fail "sync reported success with $fault at $destination"
  fi
  [[ -f "$work/hit" ]] || { cat "$work/fault.log" >&2; fail "did not reach $destination"; }
}

run_tests() {
  local ctl=/usr/local/bin/sb old=/usr/local/bin/sbctl lib=/usr/local/lib/sb-kit version checkout
  mkdir -p "$lib"
  for version in 91.0.1 91.0.2; do
    checkout="$work/$version"
    mkdir "$checkout"
    cp -R "$repo/lib" "$checkout/"
    sed -E "s/^SBKIT_VERSION=\"[^\"]+\"$/SBKIT_VERSION=\"$version\"/" "$repo/sbctl.sh" >"$checkout/sbctl.sh"
    printf '#!/bin/sh\necho helper-%s\n' "$version" >"$checkout/lib/audit.sh"
  done

  # SIGKILL during the first publication must allow a different checkout to retry.
  interrupt_sync "$work/91.0.1" "$ctl" kill-after
  [[ ! -x "$ctl" && ! -f "$lib/VERSION" ]] || fail "part of a first installation became visible"
  bash "$work/91.0.2/sbctl.sh" sync
  assert_pair 91.0.2
  # These paths are inside the test's bind mount. Start again with a flat layout.
  rm -rf -- "$work/local/bin" "$work/local/lib"
  mkdir -p "${ctl%/*}" "$lib"
  printf '90.0.0\n' >"$lib/VERSION"
  printf '#!/bin/sh\necho helper-90.0.0\n' >"$lib/audit.sh"
  cat >"$old" <<'LEGACY'
#!/bin/sh
# sbctl.sh - sing-box flat release fixture
SBKIT_VERSION="90.0.0"
case "$1" in
  --version) echo "sb-kit $SBKIT_VERSION (sing-box: 未安装)" ;;
  check) exec bash /usr/local/lib/sb-kit/audit.sh ;;
  *) exit 2 ;;
esac
LEGACY
  chmod 755 "$old"

  assert_pair 90.0.0 "$old"
  interrupt_sync "$work/91.0.1" "$old" kill-after
  assert_pair 90.0.0 "$old"
  interrupt_sync "$work/91.0.1" "$ctl" kill-after
  assert_pair 91.0.1
  (cd "$work/empty" && bash "$work/91.0.1/sbctl.sh" sync)
  assert_pair 91.0.1
  [[ ! -e "${old%/*}/.sbctl.sb-kit-publish-work" ]] || fail "rename left a publication workspace"
  [[ ! -e "$old" && ! -L "$old" ]] || fail "old CLI not retired"

  interrupt_sync "$work/91.0.2" "$lib/VERSION" fail-before
  assert_pair 91.0.1
  interrupt_sync "$work/91.0.2" "$lib/VERSION" kill-before
  assert_pair 91.0.1
  (cd "$work/91.0.2" && "$ctl" sync)
  assert_pair 91.0.2
  interrupt_sync "$work/91.0.1" "$lib/VERSION" kill-after
  assert_pair 91.0.1
  (cd "$work/empty" && "$ctl" sync --source "$work/91.0.2")
  if (cd "$work/empty" && "$ctl" sync) >/dev/null 2>&1; then fail "accepted an empty checkout"; fi
  printf 'if broken syntax\n' >>"$work/91.0.1/lib/audit.sh"
  if (cd "$work/91.0.1" && "$ctl" sync) >/dev/null 2>&1; then fail "accepted a broken helper"; fi
  assert_pair 91.0.2
  echo "sync transaction tests passed"
}

cat >"$work/hooks/sitecustomize.py" <<'PY'
import os
import signal

original_replace = os.replace

def replace(src, dst, *args, **kwargs):
    if os.fsdecode(dst) != os.environ["SB_TEST_DEST"]:
        return original_replace(src, dst, *args, **kwargs)
    with open(os.environ["SB_TEST_HIT"], "w"):
        pass
    mode = os.environ["SB_TEST_FAULT"]
    if mode == "fail-before":
        raise OSError("simulated publish failure")
    if mode == "kill-after":
        original_replace(src, dst, *args, **kwargs)
    os.kill(os.getpid(), signal.SIGKILL)

os.replace = replace
PY
export work repo
export -f run_tests interrupt_sync assert_pair fail
unshare --mount --propagation private bash -euc '
  mount --bind "$work/local" /usr/local
  mount -t tmpfs tmpfs /run
  # Lock acquisition also recovers any pending route transaction. Do not read
  # or recover a transaction from the host where this test is being run.
  for path in /etc/sing-box /etc/systemd/system; do
    if [[ -d "$path" ]]; then mount -t tmpfs tmpfs "$path"; fi
  done
  run_tests
'
