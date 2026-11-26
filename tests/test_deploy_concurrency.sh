#!/usr/bin/env bash
# Exercise deploy.sh's complete SSH commands against an isolated local shell and filesystem.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d /tmp/sb-kit-deploy-test.XXXXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
export DEPLOY_TEST_REMOTE="$work/remote" DEPLOY_TEST_EVENTS="$work/events"
mkdir "$work/bin" "$DEPLOY_TEST_REMOTE" "$DEPLOY_TEST_EVENTS"
export PATH="$work/bin:$PATH"

cat >"$work/bin/ssh" <<'SSH'
#!/usr/bin/env bash
set -euo pipefail
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|-t) shift ;;
    -o) [[ "$2" == ConnectTimeout=5 ]]; shift 2 ;;
    -p) [[ "$2" == 2222 ]]; shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
[[ $# == 2 && "$1" == root@test-host ]] || exit 70
cmd=${2//\/tmp\/sb-kit-stage./$DEPLOY_TEST_REMOTE\/sb-kit-stage.}
case "$cmd" in
  *'mktemp -d '*)
    real_stage=$(/bin/sh -c "$cmd")
    printf '/tmp/%s\n' "${real_stage##*/}"
    ;;
  *'tar -xzf -'*)
    if [[ ${FAIL_UPLOAD:-0} == 1 ]]; then cat >/dev/null; exit 42; fi
    exec /bin/sh -c "$cmd"
    ;;
  *) exec /bin/sh -c "$cmd" ;;
esac
SSH
chmod +x "$work/bin/ssh"

for label in first second; do
  src="$work/$label"
  mkdir -p "$src/lib"
  cp "$repo/deploy.sh" "$src/deploy.sh"
  printf '%s\n' "$label" >"$src/lib/payload"
  touch "$src/lib/helper.sh" "$src/lib/helper.py"
  cat >"$src/sbctl.sh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
label=$(cat lib/payload)
if [[ ${WAIT_FOR_RELEASE:-0} == 1 ]]; then
  printf '%s\n' "$PWD" >"$DEPLOY_TEST_EVENTS/$label.stage"
  printf '%s\0' "$@" >"$DEPLOY_TEST_EVENTS/$label.argv"
  touch "$DEPLOY_TEST_EVENTS/$label.entered"
  for ((i=0; i<200; i++)); do
    [[ -f "$DEPLOY_TEST_EVENTS/$label.release" ]] && break
    sleep 0.05
  done
  [[ -f "$DEPLOY_TEST_EVENTS/$label.release" && $(cat lib/payload) == "$label" ]] || exit 75
fi
exit "${COMMAND_RC:-0}"
STUB
done

wait_for_entry() {
  local label="$1" i
  for ((i=0; i<150; i++)); do
    [[ ! -e "$DEPLOY_TEST_EVENTS/$label.entered" ]] || return 0
    sleep 0.05
  done
  cat "$work/$label.log" >&2
  echo "$label never entered its uploaded command" >&2
  return 1
}

target=root@test-host:2222
WAIT_FOR_RELEASE=1 bash "$work/first/deploy.sh" "$target" show "a b" "it's \$5" "" >"$work/first.log" 2>&1 &
first_pid=$!
wait_for_entry first
WAIT_FOR_RELEASE=1 bash "$work/second/deploy.sh" "$target" sync >"$work/second.log" 2>&1 &
second_pid=$!
wait_for_entry second
first_stage=$(cat "$DEPLOY_TEST_EVENTS/first.stage")
second_stage=$(cat "$DEPLOY_TEST_EVENTS/second.stage")
[[ "$first_stage" != "$second_stage" && -d "$first_stage" && -d "$second_stage" ]]
printf '%s\0' show "a b" "it's \$5" "" | cmp - "$DEPLOY_TEST_EVENTS/first.argv"
printf '%s\0' sync | cmp - "$DEPLOY_TEST_EVENTS/second.argv"
touch "$DEPLOY_TEST_EVENTS/first.release"
wait "$first_pid"
[[ ! -e "$first_stage" && $(cat "$second_stage/lib/payload") == second ]]

# A failed upload or failed menu command must clean only its own directory and
# report its own exit status, even while a different deploy is still running.
rc=0
FAIL_UPLOAD=1 bash "$work/first/deploy.sh" "$target" sync >"$work/upload.log" 2>&1 || rc=$?
[[ "$rc" == 42 ]]
rc=0
COMMAND_RC=37 bash "$work/first/deploy.sh" "$target" >"$work/menu.log" 2>&1 || rc=$?
[[ "$rc" == 37 ]]
stages=("$DEPLOY_TEST_REMOTE"/*)
[[ ${#stages[@]} == 1 && "${stages[0]}" == "$second_stage" ]]
touch "$DEPLOY_TEST_EVENTS/second.release"
wait "$second_pid"
[[ -z $(ls -A "$DEPLOY_TEST_REMOTE") ]]
echo "deploy concurrency and cleanup OK"
