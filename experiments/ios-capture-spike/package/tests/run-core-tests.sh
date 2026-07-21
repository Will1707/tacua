#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PACKAGE_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$PACKAGE_ROOT/../../.." && pwd)"
cd "$PACKAGE_ROOT"

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
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/TacuaCanonicalJSON.swift \
  tests/CanonicalJSONTests.swift \
  -o "$TEST_TMP_DIR/tacua-canonical-json-tests"

"$TEST_TMP_DIR/tacua-canonical-json-tests" \
  "$REPO_ROOT/contracts/sdk-backend-protocol/fixtures/canonical/digest-vectors.json"

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/TacuaCredentialStore.swift \
  tests/CredentialStoreTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-credential-store-tests"

"$TEST_TMP_DIR/tacua-credential-store-tests"

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaBackendConfiguration.swift \
  tests/BackendConfigurationTests.swift \
  -o "$TEST_TMP_DIR/tacua-backend-configuration-tests"

"$TEST_TMP_DIR/tacua-backend-configuration-tests"

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CapturePolicy.swift \
  ios/TacuaLaunchLink.swift \
  tests/LaunchLinkTests.swift \
  -o "$TEST_TMP_DIR/tacua-launch-link-tests"

"$TEST_TMP_DIR/tacua-launch-link-tests"

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaCredentialStore.swift \
  ios/TacuaTransportQueue.swift \
  ios/TacuaSDKBackendProtocol.swift \
  tests/TransportQueueTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-transport-queue-tests"

"$TEST_TMP_DIR/tacua-transport-queue-tests" \
  "$REPO_ROOT/contracts/sdk-backend-protocol/fixtures/positive"

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaCredentialStore.swift \
  ios/TacuaTransportQueue.swift \
  ios/TacuaSDKBackendProtocol.swift \
  ios/TacuaTransportQueueFileStore.swift \
  tests/TransportQueueFileStoreTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-transport-queue-file-store-tests"

"$TEST_TMP_DIR/tacua-transport-queue-file-store-tests"

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaCredentialStore.swift \
  ios/TacuaTransportQueue.swift \
  ios/TacuaSDKBackendProtocol.swift \
  tests/SDKBackendProtocolTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-sdk-backend-protocol-tests"

"$TEST_TMP_DIR/tacua-sdk-backend-protocol-tests" \
  "$REPO_ROOT/contracts/sdk-backend-protocol/fixtures/positive"

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaCredentialStore.swift \
  ios/TacuaBackendConfiguration.swift \
  ios/TacuaLaunchLink.swift \
  ios/CapturePolicy.swift \
  ios/TacuaTransportQueue.swift \
  ios/TacuaSDKBackendProtocol.swift \
  ios/TacuaSDKBackendRequests.swift \
  ios/TacuaSDKBackendClient.swift \
  tests/SDKBackendClientTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-sdk-backend-client-tests"

"$TEST_TMP_DIR/tacua-sdk-backend-client-tests" \
  "$REPO_ROOT/contracts/sdk-backend-protocol/fixtures/positive"

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CapturePolicy.swift \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaCredentialStore.swift \
  ios/TacuaBackendConfiguration.swift \
  ios/TacuaLaunchLink.swift \
  ios/TacuaTransportQueue.swift \
  ios/TacuaTransportQueueFileStore.swift \
  ios/TacuaSDKBackendProtocol.swift \
  ios/TacuaSDKBackendRequests.swift \
  ios/TacuaSDKBackendClient.swift \
  ios/TacuaSDKStartJournal.swift \
  ios/TacuaSDKStartLifecycle.swift \
  tests/SDKStartLifecycleTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-sdk-start-lifecycle-tests"

"$TEST_TMP_DIR/tacua-sdk-start-lifecycle-tests" \
  "$REPO_ROOT/contracts/sdk-backend-protocol/fixtures/positive"

swiftc \
  -warnings-as-errors \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CapturePolicy.swift \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaCredentialStore.swift \
  ios/TacuaBackendConfiguration.swift \
  ios/TacuaLaunchLink.swift \
  ios/TacuaTransportQueue.swift \
  ios/TacuaTransportQueueFileStore.swift \
  ios/TacuaSDKBackendProtocol.swift \
  ios/TacuaSDKBackendRequests.swift \
  ios/TacuaSDKBackendClient.swift \
  ios/TacuaSDKStartJournal.swift \
  ios/TacuaSDKResumeJournal.swift \
  ios/TacuaSDKStartLifecycle.swift \
  ios/TacuaSDKResumeLifecycle.swift \
  tests/SDKResumeJournalTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-sdk-resume-journal-tests"

"$TEST_TMP_DIR/tacua-sdk-resume-journal-tests"

swiftc \
  -warnings-as-errors \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CapturePolicy.swift \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaCredentialStore.swift \
  ios/TacuaBackendConfiguration.swift \
  ios/TacuaLaunchLink.swift \
  ios/TacuaTransportQueue.swift \
  ios/TacuaTransportQueueFileStore.swift \
  ios/TacuaSDKBackendProtocol.swift \
  ios/TacuaSDKBackendRequests.swift \
  ios/TacuaSDKBackendClient.swift \
  ios/TacuaSDKStartJournal.swift \
  ios/TacuaSDKResumeJournal.swift \
  ios/TacuaSDKStartLifecycle.swift \
  ios/TacuaSDKResumeLifecycle.swift \
  tests/SDKResumeLifecycleTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-sdk-resume-lifecycle-tests"

"$TEST_TMP_DIR/tacua-sdk-resume-lifecycle-tests" \
  "$REPO_ROOT/contracts/sdk-backend-protocol/fixtures/positive"

swiftc \
  -D TACUA_CAPTURE_FAULT_INJECTION \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CaptureFaultInjection.swift \
  tests/CaptureFaultInjectionTests.swift \
  -o "$TEST_TMP_DIR/tacua-capture-fault-injection-tests"

"$TEST_TMP_DIR/tacua-capture-fault-injection-tests"

npm --prefix "$PACKAGE_ROOT/../harness" run typecheck

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
