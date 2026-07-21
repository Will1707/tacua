#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

TEST_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tacua-capture-tests.XXXXXX")"
trap 'rm -rf "$TEST_TMP_DIR"' EXIT

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CapturePolicy.swift \
  tests/CapturePolicyTests.swift \
  -o "$TEST_TMP_DIR/tacua-capture-policy-tests"

"$TEST_TMP_DIR/tacua-capture-policy-tests"
