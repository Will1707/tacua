#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
set +x
umask 077
export PATH='/usr/bin:/bin:/usr/sbin:/sbin'
readonly PATH

SCRIPT_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIRECTORY}/../../../.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly RESULT_SAFETY="${SCRIPT_DIRECTORY}/xcresult_safety.py"
readonly PROCESS_SUPERVISOR="${SCRIPT_DIRECTORY}/private_process_group.py"

xctestrun=''
only_testing=''
device_id_file=''
result_root=''
forbidden_values_file=''
confirmed=false
run_directory=''
unsealed_result=''
supervisor_pid=''

usage() {
  cat <<'EOF'
Usage: run_private_physical_ui_test.sh \
  --xctestrun ABSOLUTE_PATH \
  --only-testing TARGET/CLASS/TEST \
  --device-id-file OWNER_PRIVATE_PATH \
  --result-root OWNER_PRIVATE_DIRECTORY \
  --forbidden-values-file OWNER_PRIVATE_PATH \
  --confirm-physical-device

This maintainer-only runner contacts the configured physical iOS device.
It never accepts a launch URL or other one-time value on its command line.
EOF
}

die() {
  printf 'error: %s\n' "$1" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --xctestrun|--only-testing|--device-id-file|--result-root|--forbidden-values-file)
      [[ $# -ge 2 ]] || die 'an option value is missing'
      case "$1" in
        --xctestrun) xctestrun=$2 ;;
        --only-testing) only_testing=$2 ;;
        --device-id-file) device_id_file=$2 ;;
        --result-root) result_root=$2 ;;
        --forbidden-values-file) forbidden_values_file=$2 ;;
      esac
      shift 2
      ;;
    --confirm-physical-device)
      confirmed=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die 'an unsupported option was provided'
      ;;
  esac
done

[[ "$confirmed" == true ]] || die 'explicit physical-device confirmation is required'
[[ -n "$xctestrun" ]] || die 'the xctestrun path is required'
[[ -n "$only_testing" ]] || die 'one exact test identifier is required'
[[ -n "$device_id_file" ]] || die 'the private device-id file is required'
[[ -n "$result_root" ]] || die 'the private result root is required'
[[ -n "$forbidden_values_file" ]] || die 'the forbidden-values file is required'
[[ "$only_testing" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || \
  die 'the exact test identifier has an invalid format'
[[ ${#only_testing} -le 512 ]] || die 'the exact test identifier is too long'

require_absolute_regular_file() {
  local path=$1
  [[ "$path" == /* ]] || die 'a required file path is not absolute'
  [[ -f "$path" && ! -L "$path" ]] || die 'a required regular file is unavailable'
  [[ "$(stat -f '%u' "$path")" == "$(id -u)" ]] || die 'a required file has the wrong owner'
  [[ "$(stat -f '%l' "$path")" == '1' ]] || die 'a required file has an unexpected hard link'
  [[ "$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$path")" == "$path" ]] || \
    die 'a required file path traverses a symlink'
}

require_private_file() {
  local path=$1
  require_absolute_regular_file "$path"
  [[ "$(stat -f '%Lp' "$path")" == '600' ]] || die 'a private file is not mode 0600'
}

require_private_directory() {
  local path=$1
  [[ "$path" == /* ]] || die 'a private directory path is not absolute'
  [[ -d "$path" && ! -L "$path" ]] || die 'a private directory is unavailable'
  [[ "$(stat -f '%u' "$path")" == "$(id -u)" ]] || die 'a private directory has the wrong owner'
  [[ "$(stat -f '%Lp' "$path")" == '700' ]] || die 'a private directory is not mode 0700'
  [[ "$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$path")" == "$path" ]] || \
    die 'a private directory path traverses a symlink'
}

require_outside_repository() {
  local path=$1
  case "$path" in
    "$REPOSITORY_ROOT"|"${REPOSITORY_ROOT}"/*)
      die 'private runtime state must remain outside the repository'
      ;;
  esac
}

remove_unsealed_result() {
  [[ -n "$unsealed_result" && -n "$run_directory" ]] || return 0
  case "$unsealed_result" in
    "${run_directory}/physical-ui-test.xcresult")
      /bin/rm -rf -- "$unsealed_result"
      ;;
    *)
      die 'refused to remove an unsealed result outside the unique run directory'
      ;;
  esac
  unsealed_result=''
}

stop_supervisor() {
  [[ -n "$supervisor_pid" ]] || return 0
  if kill -0 "$supervisor_pid" 2>/dev/null; then
    kill -TERM "$supervisor_pid" 2>/dev/null || true
  fi
  set +e
  wait "$supervisor_pid" 2>/dev/null
  set -e
  supervisor_pid=''
}

ignore_termination_signals() {
  trap '' INT HUP TERM
}

forward_signal() {
  local signal_name=$1
  local signal_status=$2
  # Once shutdown starts, repeated termination signals must not interrupt the
  # group drain or unsealed-result deletion.
  ignore_termination_signals
  if [[ -n "$supervisor_pid" ]]; then
    kill -"$signal_name" "$supervisor_pid" 2>/dev/null || true
    set +e
    wait "$supervisor_pid" 2>/dev/null
    set -e
    supervisor_pid=''
  fi
  exit "$signal_status"
}

cleanup() {
  ignore_termination_signals
  trap - EXIT
  local exit_status=$1
  stop_supervisor
  if [[ -n "$unsealed_result" ]]; then
    remove_unsealed_result
  fi
  if [[ -n "$run_directory" ]]; then
    rmdir "$run_directory" 2>/dev/null || true
  fi
  exit "$exit_status"
}

trap 'cleanup $?' EXIT
trap 'forward_signal INT 130' INT
trap 'forward_signal HUP 129' HUP
trap 'forward_signal TERM 143' TERM

require_absolute_regular_file "$xctestrun"
require_private_file "$device_id_file"
require_private_file "$forbidden_values_file"
require_private_directory "$result_root"
require_absolute_regular_file "$RESULT_SAFETY"
require_absolute_regular_file "$PROCESS_SUPERVISOR"
require_outside_repository "$device_id_file"
require_outside_repository "$forbidden_values_file"
require_outside_repository "$result_root"

[[ "$(wc -l < "$device_id_file" | tr -d ' ')" == '1' ]] || \
  die 'the private device-id file must contain exactly one line'
device_id="$(tr -d '\r\n' < "$device_id_file")"
[[ "$device_id" =~ ^[A-Za-z0-9-]{8,80}$ ]] || \
  die 'the private device identifier has an invalid format'

run_directory="$(mktemp -d "${result_root}/physical-ui-$(date -u '+%Y%m%dT%H%M%SZ').XXXXXXXX")"
chmod 0700 "$run_directory"
unsealed_result="${run_directory}/physical-ui-test.xcresult"

set +e
python3 -B "$PROCESS_SUPERVISOR" -- \
  /usr/bin/xcodebuild test-without-building \
  -xctestrun "$xctestrun" \
  -destination "platform=iOS,id=${device_id}" \
  -destination-timeout 45 \
  -only-testing:"$only_testing" \
  -parallel-testing-enabled NO \
  -enableCodeCoverage NO \
  -collect-test-diagnostics never \
  -resultBundlePath "$unsealed_result" \
  >/dev/null 2>&1 &
supervisor_pid=$!
wait "$supervisor_pid"
xcode_status=$?
supervisor_pid=''
set -e

# The supervisor connects xcodebuild stdout and stderr directly to /dev/null.
# No raw output file exists; the result is retained only after its own scan.

[[ -d "$unsealed_result" && ! -L "$unsealed_result" ]] || \
  die 'xcodebuild did not produce one result bundle'

set +e
python3 -B "$PROCESS_SUPERVISOR" -- \
  python3 -B "$RESULT_SAFETY" seal "$unsealed_result" \
    --forbidden-values-file "$forbidden_values_file" \
    --forbidden-values-file "$device_id_file" \
    >/dev/null 2>&1 &
supervisor_pid=$!
wait "$supervisor_pid"
safety_status=$?
supervisor_pid=''
set -e

case "$safety_status" in
  40)
    remove_unsealed_result
    printf 'error: the result contained a forbidden runtime value and was destroyed\n' >&2
    exit 40
    ;;
  41)
    unsealed_result=''
    ;;
  42)
    remove_unsealed_result
    printf 'error: the result could not be proven safe and was destroyed\n' >&2
    exit 42
    ;;
  *)
    remove_unsealed_result
    printf 'error: the result scanner returned an invalid status and the result was destroyed\n' >&2
    exit 42
    ;;
esac

printf 'physical-ui-test-result=sealed\n'
printf 'safe-result-directory=%s\n' "$run_directory"
if [[ "$xcode_status" -ne 0 ]]; then
  printf 'physical-ui-test=xcodebuild-failed\n' >&2
  exit "$xcode_status"
fi
printf 'physical-ui-test=passed\n'
