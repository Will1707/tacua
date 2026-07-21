#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

TEST_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tacua-capture-tests.XXXXXX")"
trap 'rm -rf "$TEST_TMP_DIR"' EXIT

swiftc -parse ios/*.swift
swiftc -D TACUA_CAPTURE_FAULT_INJECTION -parse ios/*.swift

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CapturePolicy.swift \
  tests/CapturePolicyTests.swift \
  -o "$TEST_TMP_DIR/tacua-capture-policy-tests"

"$TEST_TMP_DIR/tacua-capture-policy-tests"

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CaptureTransportPolicy.swift \
  tests/CaptureTransportPolicyTests.swift \
  -o "$TEST_TMP_DIR/tacua-capture-transport-policy-tests"

"$TEST_TMP_DIR/tacua-capture-transport-policy-tests"

swiftc \
  -D TACUA_CAPTURE_FAULT_INJECTION \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CaptureFaultInjection.swift \
  tests/CaptureFaultInjectionTests.swift \
  -o "$TEST_TMP_DIR/tacua-capture-fault-injection-tests"

"$TEST_TMP_DIR/tacua-capture-fault-injection-tests"

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  -emit-library \
  ios/CaptureFaultInjection.swift \
  -o "$TEST_TMP_DIR/libTacuaCaptureFaultRelease.dylib"

if strings "$TEST_TMP_DIR/libTacuaCaptureFaultRelease.dylib" \
  | grep -Eq 'low_storage_start|writer_finish_timeout_1|stop_timeout_twice|TACUA_CAPTURE_TEST_FAULT'
then
  echo "QA fault-plan strings leaked into a non-fault build" >&2
  exit 1
fi
