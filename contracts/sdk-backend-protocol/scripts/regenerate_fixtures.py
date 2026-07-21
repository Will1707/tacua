#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the deterministic synthetic protocol conformance bundle."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "contracts" / "runtime" / "src"))

import protocol_contract as protocol  # noqa: E402
import runtime_contract as runtime  # noqa: E402


POSITIVE = ROOT / "fixtures" / "positive"
NEGATIVE = ROOT / "fixtures" / "negative"
CANONICAL = ROOT / "fixtures" / "canonical"
RUNTIME_POSITIVE = REPO_ROOT / "contracts" / "runtime" / "fixtures" / "positive"


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def clone(value: Any) -> Any:
    return copy.deepcopy(value)


def load_runtime(name: str) -> dict[str, Any]:
    return json.loads((RUNTIME_POSITIVE / f"{name}.json").read_text(encoding="utf-8"))


build_identity = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "build_identity",
        "build_id": "build_synthetic",
        "platform": "ios",
        "bundle_identifier": "dev.tacua.synthetic",
        "native_version": "1.0.0",
        "native_build": "42",
        "build_variant": "preview",
        "distribution": "testflight",
        "react_native_version": "0.81.5",
        "transport_configuration_digest": protocol.digest(
            {
                "backend_origin": "https://qa.tacua.example",
                "transport_policy_version": "tacua.sdk-transport@1.0.0",
            }
        ),
        "expo": {
            "sdk_version": "56.0.0",
            "runtime_version": "1.0.0",
            "update_id": "update_synthetic",
            "update_channel": "preview",
        },
        "source": {
            "git_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "working_tree_dirty": False,
        },
        "created_at": "2026-07-21T09:55:00Z",
    }
)

scope = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "capture_scope",
        "organization_id": "org_synthetic",
        "project_id": "project_synthetic",
        "application_id": "app_synthetic",
        "build_id": build_identity["build_id"],
        "build_identity_digest": build_identity["build_identity_digest"],
        "capture_scope": "app_only",
        "consent": {
            "policy_version": "tacua.consent-v1",
            "screen_recording": "granted",
            "microphone": "granted",
            "diagnostics": "granted",
            "raw_media_upload": "granted",
            "granted_at": "2026-07-21T09:56:00Z",
        },
        "retention": {
            "policy_version": "tacua.retention-v1",
            "raw_media_days": 30,
            "derived_data_days": 30,
        },
    }
)

launch_request = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "launch_exchange_request",
        "exchange_kind": "start_session",
        "exchange_id": "exchange_synthetic",
        "launch_code": "L" * 43,
        "expected_session_id": None,
        "expected_session_state": "receiving",
        "expected_completion_id": None,
        "previous_credential_id": None,
        "credential": {
            "credential_id": "credential_synthetic",
            "secret": "S" * 43,
            "authentication_scheme": "Bearer",
            "local_storage": "ios_keychain_when_unlocked_this_device_only",
        },
        "build_identity": build_identity,
        "scope": scope,
        "requested_at": "2026-07-21T09:57:00Z",
    }
)

launch_receipt = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "launch_exchange_receipt",
        "exchange_kind": "start_session",
        "exchange_id": launch_request["exchange_id"],
        "request_digest": launch_request["request_digest"],
        "session_id": "session_synthetic",
        "session_state": "receiving",
        "scope": scope,
        "credential": {
            "credential_id": launch_request["credential"]["credential_id"],
            "authentication_scheme": "Bearer",
            "state": "active",
            "replay_completion_id": None,
            "expires_at": "2026-08-20T10:00:00Z",
        },
        "previous_credential_revocation": None,
        "received_at": "2026-07-21T09:57:01Z",
        "issued_at": "2026-07-21T09:57:01Z",
    }
)

capture = load_runtime("capture")
capture["build_identity_digest"] = build_identity["build_identity_digest"]
capture["session_id"] = launch_receipt["session_id"]
capture["upload"]["remote_session_id"] = launch_receipt["session_id"]
capture = runtime.seal(capture)
segment = capture["segments"][0]
runtime_segment_receipt = capture["upload"]["receipts"][0]

segment_intent = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "segment_upload_intent",
        "upload_id": "upload_segment_synthetic",
        "session_id": launch_receipt["session_id"],
        "scope_digest": scope["scope_digest"],
        "credential_id": launch_receipt["credential"]["credential_id"],
        "sequence": segment["sequence"],
        "segment_id": segment["segment_id"],
        "transport": {
            "content_type": segment["content"]["content_type"],
            "size_bytes": segment["content"]["size_bytes"],
            "content_digest": segment["content"]["content_digest"],
        },
        "sidecar_digest": segment["content"]["sidecar_digest"],
        "requested_at": "2026-07-21T10:01:59Z",
    }
)

segment_receipt = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "segment_upload_receipt",
        "upload_id": segment_intent["upload_id"],
        "intent_digest": segment_intent["intent_digest"],
        "session_id": launch_receipt["session_id"],
        "scope_digest": scope["scope_digest"],
        "credential_id": launch_receipt["credential"]["credential_id"],
        "sequence": segment["sequence"],
        "segment_id": segment["segment_id"],
        "content_type": segment["content"]["content_type"],
        "sidecar_digest": segment["content"]["sidecar_digest"],
        "runtime_receipt": runtime_segment_receipt,
        "transport_digest": segment["content"]["content_digest"],
    }
)

receiving_resume_request = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "launch_exchange_request",
        "exchange_kind": "resume_session",
        "exchange_id": "exchange_receiving_resume",
        "launch_code": "Q" * 43,
        "expected_session_id": launch_receipt["session_id"],
        "expected_session_state": "receiving",
        "expected_completion_id": None,
        "previous_credential_id": launch_receipt["credential"]["credential_id"],
        "credential": {
            "credential_id": "credential_receiving_resume",
            "secret": "U" * 43,
            "authentication_scheme": "Bearer",
            "local_storage": "ios_keychain_when_unlocked_this_device_only",
        },
        "build_identity": build_identity,
        "scope": scope,
        "requested_at": "2026-07-21T10:02:01Z",
    }
)

receiving_resume_receipt = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "launch_exchange_receipt",
        "exchange_kind": "resume_session",
        "exchange_id": receiving_resume_request["exchange_id"],
        "request_digest": receiving_resume_request["request_digest"],
        "session_id": launch_receipt["session_id"],
        "session_state": "receiving",
        "scope": scope,
        "credential": {
            "credential_id": receiving_resume_request["credential"]["credential_id"],
            "authentication_scheme": "Bearer",
            "state": "active",
            "replay_completion_id": None,
            "expires_at": "2026-08-20T10:00:00Z",
        },
        "previous_credential_revocation": {
            "credential_id": receiving_resume_request["previous_credential_id"],
            "state": "revoked",
            "revoked_at": "2026-07-21T10:02:02Z",
        },
        "received_at": "2026-07-21T10:02:02Z",
        "issued_at": "2026-07-21T10:02:02Z",
    }
)

diagnostics = load_runtime("diagnostics")
diagnostics["build_identity_digest"] = build_identity["build_identity_digest"]
diagnostics["session_id"] = launch_receipt["session_id"]
diagnostics = runtime.seal(diagnostics)
diagnostic_bytes = protocol.canonical_json(diagnostics).encode("utf-8")

diagnostic_request = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "diagnostic_upload_request",
        "upload_id": "upload_diagnostic_synthetic",
        "session_id": launch_receipt["session_id"],
        "scope_digest": scope["scope_digest"],
        "credential_id": receiving_resume_receipt["credential"]["credential_id"],
        "transport": {
            "content_type": "application/vnd.tacua.diagnostic-envelope+json;version=1.0.0",
            "size_bytes": len(diagnostic_bytes),
            "content_digest": protocol.digest(diagnostic_bytes),
        },
        "envelope": diagnostics,
        "requested_at": "2026-07-21T10:02:03Z",
    }
)

diagnostic_receipt = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "diagnostic_upload_receipt",
        "receipt_id": "receipt_diagnostic_synthetic",
        "upload_id": diagnostic_request["upload_id"],
        "request_digest": diagnostic_request["request_digest"],
        "session_id": launch_receipt["session_id"],
        "scope_digest": scope["scope_digest"],
        "credential_id": receiving_resume_receipt["credential"]["credential_id"],
        "object_id": "object_diagnostic_synthetic",
        "size_bytes": diagnostic_request["transport"]["size_bytes"],
        "transport_digest": diagnostic_request["transport"]["content_digest"],
        "envelope_id": diagnostics["envelope_id"],
        "envelope_digest": diagnostics["envelope_digest"],
        "received_at": "2026-07-21T10:02:04Z",
    }
)

completion_request = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "completion_request",
        "completion_id": "completion_synthetic",
        "session_id": launch_receipt["session_id"],
        "scope_digest": scope["scope_digest"],
        "credential_id": receiving_resume_receipt["credential"]["credential_id"],
        "capture_manifest": capture,
        "segment_receipts": [segment_receipt],
        "diagnostic_receipts": [diagnostic_receipt],
        "requested_at": "2026-07-21T10:02:05Z",
    }
)

job = load_runtime("job")
job["build_identity_digest"] = build_identity["build_identity_digest"]
job["session_id"] = launch_receipt["session_id"]
job["status"] = "queued"
job["requested_at"] = "2026-07-21T10:02:06Z"
job["started_at"] = None
job["completed_at"] = None
job["inputs"]["capture_manifest_digest"] = capture["manifest_digest"]
job["inputs"]["diagnostic_envelope_digests"] = [diagnostics["envelope_digest"]]
job["outputs"] = None
job["failure"] = None
for stage in job["pipeline"]["stages"]:
    stage.update(
        {
            "state": "pending",
            "attempt_count": 0,
            "started_at": None,
            "completed_at": None,
            "detail": None,
        }
    )
job = runtime.seal(job)

completion_receipt = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "completion_receipt",
        "completion_id": completion_request["completion_id"],
        "request_digest": completion_request["request_digest"],
        "session_id": launch_receipt["session_id"],
        "scope_digest": scope["scope_digest"],
        "accepted_at": "2026-07-21T10:02:06Z",
        "processing_job": job,
        "credential": {
            "credential_id": completion_request["credential_id"],
            "state": "completion_replay_or_delete_only",
            "replay_completion_id": completion_request["completion_id"],
            "expires_at": "2026-08-20T10:00:00Z",
        },
        "local_cleanup": {
            "state": "authorized_after_durable_receipt",
            "manifest_digest": capture["manifest_digest"],
            "segment_receipt_digests": [segment_receipt["segment_receipt_digest"]],
            "diagnostic_receipt_digests": [diagnostic_receipt["diagnostic_receipt_digest"]],
        },
    }
)

completed_resume_request = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "launch_exchange_request",
        "exchange_kind": "resume_session",
        "exchange_id": "exchange_completed_resume",
        "launch_code": "R" * 43,
        "expected_session_id": launch_receipt["session_id"],
        "expected_session_state": "completed",
        "expected_completion_id": completion_request["completion_id"],
        "previous_credential_id": completion_receipt["credential"]["credential_id"],
        "credential": {
            "credential_id": "credential_completed_resume",
            "secret": "T" * 43,
            "authentication_scheme": "Bearer",
            "local_storage": "ios_keychain_when_unlocked_this_device_only",
        },
        "build_identity": build_identity,
        "scope": scope,
        "requested_at": "2026-07-21T10:02:20Z",
    }
)

completed_resume_receipt = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "launch_exchange_receipt",
        "exchange_kind": "resume_session",
        "exchange_id": completed_resume_request["exchange_id"],
        "request_digest": completed_resume_request["request_digest"],
        "session_id": launch_receipt["session_id"],
        "session_state": "completed",
        "scope": scope,
        "credential": {
            "credential_id": completed_resume_request["credential"]["credential_id"],
            "authentication_scheme": "Bearer",
            "state": "completion_replay_or_delete_only",
            "replay_completion_id": completion_request["completion_id"],
            "expires_at": "2026-08-20T10:00:00Z",
        },
        "previous_credential_revocation": {
            "credential_id": completed_resume_request["previous_credential_id"],
            "state": "revoked",
            "revoked_at": "2026-07-21T10:02:21Z",
        },
        "received_at": "2026-07-21T10:02:21Z",
        "issued_at": "2026-07-21T10:02:21Z",
    }
)

deletion_request = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "deletion_request",
        "deletion_id": "deletion_synthetic",
        "session_id": launch_receipt["session_id"],
        "scope_digest": scope["scope_digest"],
        "credential_id": completion_receipt["credential"]["credential_id"],
        "target": "session_all_data",
        "reason": "user_requested",
        "requested_at": "2026-07-21T10:03:00Z",
    }
)

deletion_tombstone = protocol.seal(
    {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "message_type": "deletion_tombstone",
        "deletion_id": deletion_request["deletion_id"],
        "deletion_request_digest": deletion_request["request_digest"],
        "session_id": launch_receipt["session_id"],
        "scope_digest": scope["scope_digest"],
        "credential": {
            "credential_id": deletion_request["credential_id"],
            "state": "deletion_replay_only",
            "replay_deletion_id": deletion_request["deletion_id"],
            "verifier_retained_until": "2026-08-19T10:03:05Z",
        },
        "session_access": {
            "evidence": "revoked",
            "uploads": "revoked",
            "completion": "revoked",
            "processing": "revoked",
        },
        "erasure": {
            "raw_media": "deleted",
            "diagnostics": "deleted",
            "derived_data": "deleted",
            "session_metadata": "deleted_except_tombstone_and_replay_verifier",
            "erased_object_count": 4,
        },
        "local_credential_cleanup": "authorized_after_durable_tombstone",
        "accepted_at": "2026-07-21T10:03:01Z",
        "deleted_at": "2026-07-21T10:03:05Z",
        "tombstone_expires_at": "2026-08-19T10:03:05Z",
    }
)


positive = {
    "build-identity.json": build_identity,
    "capture-scope.json": scope,
    "launch-exchange-request.json": launch_request,
    "launch-exchange-receipt.json": launch_receipt,
    "receiving-resume-request.json": receiving_resume_request,
    "receiving-resume-receipt.json": receiving_resume_receipt,
    "segment-upload-intent.json": segment_intent,
    "segment-upload-receipt.json": segment_receipt,
    "diagnostic-upload-request.json": diagnostic_request,
    "diagnostic-upload-receipt.json": diagnostic_receipt,
    "completion-request.json": completion_request,
    "completion-receipt.json": completion_receipt,
    "completed-resume-request.json": completed_resume_request,
    "completed-resume-receipt.json": completed_resume_receipt,
    "deletion-request.json": deletion_request,
    "deletion-tombstone.json": deletion_tombstone,
}
for filename, value in positive.items():
    write(POSITIVE / filename, value)


negative_cases: list[dict[str, str]] = []


def invalid(filename: str, value: dict[str, Any], expected_code: str, mode: str = "validate") -> None:
    write(NEGATIVE / filename, value)
    negative_cases.append({"file": filename, "expected_code": expected_code, "mode": mode})


bad = clone(build_identity)
bad["build_variant"] = "production"
invalid("production-build.json", protocol.seal(bad), "SCHEMA_ENUM")

bad = clone(build_identity)
bad["native_version"] = "Cafe\u0301"
invalid("non-nfc-build.json", protocol.seal(bad), "NON_NFC_STRING")

bad = clone(launch_request)
bad["build_identity"]["transport_configuration_digest"] = "sha256:" + "9" * 64
bad["build_identity"] = protocol.seal(bad["build_identity"])
invalid("launch-transport-config-mismatch.json", protocol.seal(bad), "BUILD_SCOPE_MISMATCH")

bad = clone(launch_receipt)
bad["credential"]["secret"] = "S" * 43
invalid("launch-secret-echo.json", protocol.seal(bad), "SCHEMA_ADDITIONAL_PROPERTY")

bad = clone(launch_request)
bad["exchange_kind"] = "resume_session"
invalid("resume-without-session.json", protocol.seal(bad), "SCHEMA_TYPE")

bad = clone(completed_resume_receipt)
bad["session_state"] = "receiving"
bad["credential"]["state"] = "active"
bad["credential"]["replay_completion_id"] = None
invalid("completed-resume-reenabled-upload.json", protocol.seal(bad), "RESUME_SESSION_STATE_MISMATCH", "completed_resume_pair")

bad = clone(completed_resume_receipt)
bad["session_state"] = "deleted"
invalid("resume-deleted-session.json", protocol.seal(bad), "SCHEMA_ENUM")

bad = clone(completed_resume_receipt)
bad["previous_credential_revocation"]["credential_id"] = "credential_other"
invalid("resume-revoked-wrong-credential.json", protocol.seal(bad), "RESUME_REVOCATION_MISMATCH", "completed_resume_pair")

bad = clone(scope)
bad["scope_digest"] = "sha256:" + "0" * 64
invalid("tampered-scope.json", bad, "DIGEST_MISMATCH")

bad = clone(segment_receipt)
bad["runtime_receipt"]["content_digest"] = "sha256:" + "7" * 64
bad["runtime_receipt"]["receipt_digest"] = runtime.digest_without(bad["runtime_receipt"], "receipt_digest")
bad["transport_digest"] = bad["runtime_receipt"]["content_digest"]
invalid("segment-content-conflict.json", protocol.seal(bad), "SEGMENT_CONTENT_MISMATCH", "segment_pair")

bad = clone(segment_receipt)
bad["runtime_receipt"]["received_at"] = "2026-07-21T09:00:00Z"
bad["runtime_receipt"]["receipt_digest"] = runtime.digest_without(bad["runtime_receipt"], "receipt_digest")
invalid("segment-receipt-before-request.json", protocol.seal(bad), "INVALID_CHRONOLOGY", "segment_pair")

bad = clone(diagnostic_request)
bad["envelope"]["session_id"] = "session_other"
bad["envelope"] = runtime.seal(bad["envelope"])
bad_bytes = protocol.canonical_json(bad["envelope"]).encode("utf-8")
bad["transport"]["size_bytes"] = len(bad_bytes)
bad["transport"]["content_digest"] = protocol.digest(bad_bytes)
invalid("diagnostic-session-mismatch.json", protocol.seal(bad), "ENVELOPE_SCOPE_MISMATCH")

bad = clone(diagnostic_receipt)
bad["received_at"] = "2026-07-21T09:00:00Z"
invalid("diagnostic-receipt-before-request.json", protocol.seal(bad), "INVALID_CHRONOLOGY", "diagnostic_pair")

bad = clone(completion_request)
bad_receipt = clone(segment_receipt)
bad_receipt["runtime_receipt"]["object_id"] = "object_other"
bad_receipt["runtime_receipt"]["receipt_digest"] = runtime.digest_without(bad_receipt["runtime_receipt"], "receipt_digest")
bad["segment_receipts"] = [protocol.seal(bad_receipt)]
invalid("completion-receipt-set-mismatch.json", protocol.seal(bad), "SEGMENT_RECEIPT_SET_MISMATCH")

bad = clone(completion_request)
bad_receipt = clone(segment_receipt)
bad_receipt["sequence"] = 1
bad["segment_receipts"] = [protocol.seal(bad_receipt)]
invalid("completion-segment-sequence-mismatch.json", protocol.seal(bad), "SEGMENT_MANIFEST_BINDING_MISMATCH")

bad = clone(completion_request)
bad_receipt = clone(segment_receipt)
bad_receipt["sidecar_digest"] = "sha256:" + "f" * 64
bad["segment_receipts"] = [protocol.seal(bad_receipt)]
invalid("completion-segment-sidecar-mismatch.json", protocol.seal(bad), "SEGMENT_MANIFEST_BINDING_MISMATCH")

bad = clone(completion_request)
bad_receipt = clone(segment_receipt)
bad_receipt["runtime_receipt"]["received_at"] = "2026-07-21T10:02:01Z"
bad_receipt["runtime_receipt"]["receipt_digest"] = runtime.digest_without(bad_receipt["runtime_receipt"], "receipt_digest")
bad_receipt = protocol.seal(bad_receipt)
bad_manifest = clone(bad["capture_manifest"])
bad_manifest["upload"]["receipts"] = [clone(bad_receipt["runtime_receipt"])]
bad["capture_manifest"] = runtime.seal(bad_manifest)
bad["segment_receipts"] = [bad_receipt]
invalid("completion-upload-before-segment-receipt.json", protocol.seal(bad), "INVALID_CHRONOLOGY")

bad = clone(completion_request)
bad["capture_manifest"]["capture_state"] = "recoverable"
bad["capture_manifest"] = runtime.seal(bad["capture_manifest"])
invalid("completion-recoverable-capture.json", protocol.seal(bad), "CAPTURE_NOT_COMPLETE")

bad = clone(completion_receipt)
bad["processing_job"]["status"] = "running"
bad["processing_job"]["started_at"] = bad["accepted_at"]
bad["processing_job"]["pipeline"]["stages"][0].update(
    {"state": "running", "attempt_count": 1, "started_at": bad["accepted_at"]}
)
bad["processing_job"] = runtime.seal(bad["processing_job"])
invalid("completion-job-not-queued.json", protocol.seal(bad), "JOB_NOT_QUEUED")

bad = clone(completion_receipt)
bad["local_cleanup"]["segment_receipt_digests"] = ["sha256:" + "8" * 64]
invalid("completion-cleanup-mismatch.json", protocol.seal(bad), "LOCAL_CLEANUP_BINDING_MISMATCH", "completion_pair")

bad = clone(completion_receipt)
bad["credential"]["credential_id"] = "credential_other"
invalid("completion-wrong-credential.json", protocol.seal(bad), "COMPLETION_CREDENTIAL_MISMATCH", "completion_pair")

bad = clone(deletion_tombstone)
bad["credential"]["state"] = "active"
invalid("tombstone-active-credential.json", protocol.seal(bad), "SCHEMA_CONST")

bad = clone(deletion_tombstone)
bad["credential"]["verifier_retained_until"] = "2026-08-18T10:03:05Z"
invalid("tombstone-verifier-retention-mismatch.json", protocol.seal(bad), "DELETION_REPLAY_RETENTION_MISMATCH")

bad = clone(deletion_tombstone)
bad["tombstone_expires_at"] = "2026-09-21T10:03:05Z"
invalid("tombstone-over-retained.json", protocol.seal(bad), "TOMBSTONE_RETENTION_EXCEEDED")

bad = clone(deletion_tombstone)
bad["deletion_request_digest"] = "sha256:" + "9" * 64
invalid("tombstone-request-mismatch.json", protocol.seal(bad), "DELETION_BINDING_MISMATCH", "deletion_pair")

bad = clone(completion_request)
bad["requested_at"] = "2026-07-21T10:02:07Z"
invalid("completion-conflicting-replay.json", protocol.seal(bad), "IDEMPOTENCY_CONFLICT", "completion_replay")

bad = clone(launch_receipt)
bad["session_id"] = "session_other"
invalid("launch-replay-response-changed.json", protocol.seal(bad), "IDEMPOTENCY_RESPONSE_MISMATCH", "launch_response_replay")

(NEGATIVE / "duplicate-json-keys.json").write_text(
    '{"protocol_version":"tacua.sdk-backend@1.0.0","message_type":"build_identity","message_type":"capture_scope"}\n',
    encoding="utf-8",
)
negative_cases.append(
    {"file": "duplicate-json-keys.json", "expected_code": "DUPLICATE_JSON_KEY", "mode": "load"}
)
write(NEGATIVE / "cases.json", {"cases": negative_cases})


vector_values = [
    ("scalar-and-key-order", {"z": 0, "a": True, "n": None}),
    ("nested", {"items": [3, 2, 1], "meta": {"b": "two", "a": "one"}}),
    ("unicode-nfc", {"label": "Café 🐞"}),
    ("string-escaping", {"text": "quote=\" slash=/ backslash=\\ newline=\n"}),
    ("safe-integer-bounds", {"max": 9007199254740991, "min": -9007199254740991}),
]
vectors = []
for name, value in vector_values:
    canonical = protocol.canonical_json(value)
    encoded = canonical.encode("utf-8")
    vectors.append(
        {
            "name": name,
            "value": value,
            "canonical_utf8": canonical,
            "canonical_utf8_hex": encoded.hex(),
            "sha256": protocol.digest(encoded),
        }
    )
write(CANONICAL / "digest-vectors.json", {"specification": "tacua.canonical-json@1.0.0", "vectors": vectors})

artifact_vectors = []
for filename, value in positive.items():
    field = protocol.DIGEST_FIELD_BY_MESSAGE[value["message_type"]]
    artifact_vectors.append(
        {
            "fixture": f"../positive/{filename}",
            "message_type": value["message_type"],
            "digest_field": field,
            "expected_digest": value[field],
        }
    )
write(CANONICAL / "artifact-digests.json", {"specification": protocol.PROTOCOL_VERSION, "artifacts": artifact_vectors})
