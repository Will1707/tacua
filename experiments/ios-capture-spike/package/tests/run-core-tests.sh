#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
PACKAGE_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(CDPATH='' cd -- "$PACKAGE_ROOT/../../.." && pwd)"
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
  -warnings-as-errors \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/AppAudioAppendAccounting.swift \
  tests/AppAudioAppendAccountingTests.swift \
  -o "$TEST_TMP_DIR/tacua-app-audio-append-accounting-tests"

"$TEST_TMP_DIR/tacua-app-audio-append-accounting-tests"

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
  -warnings-as-errors \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaDiagnosticJournal.swift \
  tests/DiagnosticJournalTests.swift \
  -o "$TEST_TMP_DIR/tacua-diagnostic-journal-tests"

"$TEST_TMP_DIR/tacua-diagnostic-journal-tests"

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
  -warnings-as-errors \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CapturePolicy.swift \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaCredentialStore.swift \
  ios/TacuaBackendConfiguration.swift \
  ios/TacuaLaunchLink.swift \
  ios/TacuaTransportQueue.swift \
  ios/TacuaSDKBackendProtocol.swift \
  ios/TacuaSDKBackendRequests.swift \
  ios/TacuaSDKBuildProfile.swift \
  tests/SDKBuildProfileTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-sdk-build-profile-tests"

"$TEST_TMP_DIR/tacua-sdk-build-profile-tests" \
  "$REPO_ROOT/services/backend/sdk-profile.example.json"

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
  -warnings-as-errors \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaCredentialStore.swift \
  ios/TacuaTransportQueue.swift \
  ios/TacuaSDKBackendProtocol.swift \
  ios/TacuaTransportQueueFileStore.swift \
  tests/SessionRetirementTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-session-retirement-tests"

"$TEST_TMP_DIR/tacua-session-retirement-tests"

swiftc \
  -warnings-as-errors \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaCredentialStore.swift \
  ios/TacuaTransportQueue.swift \
  ios/TacuaSDKBackendProtocol.swift \
  ios/TacuaTransportQueueFileStore.swift \
  ios/TacuaSDKStartJournal.swift \
  ios/TacuaSDKResumeJournal.swift \
  ios/TacuaSDKSessionDiscovery.swift \
  ios/TacuaSDKLocalRetention.swift \
  tests/LocalRetentionTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-local-retention-tests"

"$TEST_TMP_DIR/tacua-local-retention-tests"

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
  ios/TacuaSDKBuildProfile.swift \
  ios/TacuaSDKHostIntegration.swift \
  tests/SDKHostIntegrationTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-sdk-host-integration-tests"

"$TEST_TMP_DIR/tacua-sdk-host-integration-tests" \
  "$REPO_ROOT/services/backend/sdk-profile.example.json"

swiftc \
  -warnings-as-errors \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/TacuaCanonicalJSON.swift \
  ios/TacuaCredentialStore.swift \
  ios/TacuaTransportQueue.swift \
  ios/TacuaSDKBackendProtocol.swift \
  ios/TacuaTransportQueueFileStore.swift \
  ios/TacuaSDKStartJournal.swift \
  ios/TacuaSDKSessionDiscovery.swift \
  tests/SDKSessionDiscoveryTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-sdk-session-discovery-tests"

"$TEST_TMP_DIR/tacua-sdk-session-discovery-tests"

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
  ios/TacuaDiagnosticJournal.swift \
  ios/TacuaCaptureAdmission.swift \
  ios/TacuaCaptureUploadCoordinator.swift \
  tests/CaptureAdmissionTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-capture-admission-tests"

"$TEST_TMP_DIR/tacua-capture-admission-tests" \
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
  ios/TacuaDiagnosticJournal.swift \
  ios/TacuaCaptureAdmission.swift \
  ios/TacuaCaptureDeletionCoordinator.swift \
  tests/CaptureDeletionTests.swift \
  -framework Security \
  -o "$TEST_TMP_DIR/tacua-capture-deletion-tests"

"$TEST_TMP_DIR/tacua-capture-deletion-tests" \
  "$REPO_ROOT/contracts/sdk-backend-protocol/fixtures/positive"

swiftc \
  -D TACUA_CAPTURE_FAULT_INJECTION \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CaptureFaultInjection.swift \
  tests/CaptureFaultInjectionTests.swift \
  -o "$TEST_TMP_DIR/tacua-capture-fault-injection-tests"

"$TEST_TMP_DIR/tacua-capture-fault-injection-tests"

swiftc \
  -D DEBUG \
  -warnings-as-errors \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CapturePolicy.swift \
  ios/TacuaLocalHarnessPolicy.swift \
  tests/LocalHarnessPolicyTests.swift \
  -o "$TEST_TMP_DIR/tacua-local-harness-policy-debug-tests"

"$TEST_TMP_DIR/tacua-local-harness-policy-debug-tests"

swiftc \
  -warnings-as-errors \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  ios/CapturePolicy.swift \
  ios/TacuaLocalHarnessPolicy.swift \
  tests/LocalHarnessPolicyTests.swift \
  -o "$TEST_TMP_DIR/tacua-local-harness-policy-release-tests"

"$TEST_TMP_DIR/tacua-local-harness-policy-release-tests"

node --check app.plugin.js
for plugin_file in plugin/*.js; do
  node --check "$plugin_file"
done
node --test tests/config-plugin.test.mjs
node --test tests/app-audio-generator.test.mjs
node --test --experimental-strip-types \
  --disable-warning=MODULE_TYPELESS_PACKAGE_JSON \
  tests/backend-managed-host-controller.test.ts

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

swiftc \
  -module-cache-path "$TEST_TMP_DIR/module-cache" \
  -emit-library \
  ios/CapturePolicy.swift \
  ios/TacuaLocalHarnessPolicy.swift \
  -o "$TEST_TMP_DIR/libTacuaLocalHarnessRelease.dylib"

if strings "$TEST_TMP_DIR/libTacuaLocalHarnessRelease.dylib" \
  | grep -Eq 'TacuaLocalHarnessRetentionBypassEnabled|com\.tacua\.capturelab\.acceptance'
then
  echo "Local harness retention-bypass strings leaked into a release build" >&2
  exit 1
fi
