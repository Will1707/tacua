#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
set +x
export PATH='/usr/bin:/bin:/usr/sbin:/sbin'
readonly PATH

SCRIPT_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
readonly SCRIPT_DIRECTORY
readonly STATE_SOURCE="${SCRIPT_DIRECTORY}/../physical-tests/TacuaPhysicalHarnessState.swift"
readonly TEST_SOURCE="${SCRIPT_DIRECTORY}/../tests/TacuaPhysicalHarnessStateTests.swift"

temporary_directory=''
cleanup() {
  local exit_status=$?
  trap - EXIT INT HUP TERM
  if [[ -n "$temporary_directory" ]]; then
    case "$temporary_directory" in
      /private/tmp/tacua-physical-state.*|/tmp/tacua-physical-state.*)
        /bin/rm -rf -- "$temporary_directory"
        ;;
      *)
        printf 'error: refused to clean an unexpected temporary path\n' >&2
        exit_status=1
        ;;
    esac
  fi
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 129' HUP
trap 'exit 143' TERM

[[ -f "$STATE_SOURCE" && ! -L "$STATE_SOURCE" ]] || exit 1
[[ -f "$TEST_SOURCE" && ! -L "$TEST_SOURCE" ]] || exit 1
temporary_directory="$(mktemp -d /private/tmp/tacua-physical-state.XXXXXXXX)"

xcrun swiftc \
  -parse-as-library \
  -swift-version 6 \
  -warnings-as-errors \
  -module-cache-path "${temporary_directory}/module-cache" \
  "$STATE_SOURCE" \
  "$TEST_SOURCE" \
  -o "${temporary_directory}/TacuaPhysicalHarnessStateTests"
"${temporary_directory}/TacuaPhysicalHarnessStateTests"
