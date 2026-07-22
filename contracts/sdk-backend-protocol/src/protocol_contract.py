# SPDX-License-Identifier: Apache-2.0
"""Dependency-free validation for the Tacua SDK/backend V1 protocol."""

from __future__ import annotations

import copy
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_ROOT = PACKAGE_ROOT.parent
SCHEMA_ROOT = PACKAGE_ROOT / "schemas"
RUNTIME_SCHEMA_ROOT = CONTRACTS_ROOT / "runtime" / "schemas"
RUNTIME_SRC = CONTRACTS_ROOT / "runtime" / "src"
if str(RUNTIME_SRC) not in sys.path:
    sys.path.insert(0, str(RUNTIME_SRC))

import runtime_contract as runtime  # noqa: E402


ContractError = runtime.ContractError
PROTOCOL_VERSION = "tacua.sdk-backend@1.0.0"
MAX_SESSION_CREDENTIALS = 64
PROCESSING_JOB_STAGES = (
    "transcribe",
    "align",
    "correlate",
    "research",
    "generate_tickets",
)


def canonical_json(value: Any) -> str:
    """Canonical UTF-8 JSON shared with the runtime contract."""
    return runtime.canonical_json(value)


def digest(value: Any) -> str:
    return runtime.digest(value)


def digest_without(value: dict[str, Any], field: str) -> str:
    return runtime.digest_without(value, field)


def require(condition: bool, code: str, path: str, detail: str) -> None:
    runtime.require(condition, code, path, detail)


def parse_time(value: str, path: str):
    return runtime.parse_time(value, path)


def unique(values: list[Any], path: str) -> None:
    runtime.unique(values, path)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


class ProtocolSchemaValidator(runtime.SchemaValidator):
    """Runtime schema subset with explicitly allowlisted cross-package refs."""

    def __init__(self) -> None:
        super().__init__(SCHEMA_ROOT)
        self.allowed_roots = (SCHEMA_ROOT.resolve(), RUNTIME_SCHEMA_ROOT.resolve())

    def _resolve_ref(
        self,
        ref: str,
        root: dict[str, Any],
        root_path: Path,
    ) -> tuple[dict[str, Any], dict[str, Any], Path]:
        file_part, separator, fragment = ref.partition("#")
        if file_part:
            target_path = (root_path.parent / file_part).resolve()
            if not any(_inside(target_path, allowed) for allowed in self.allowed_roots):
                raise ContractError("SCHEMA_REF_FORBIDDEN", "$", ref)
            if target_path not in self._cache:
                self._cache[target_path] = json.loads(target_path.read_text(encoding="utf-8"))
            target_root = self._cache[target_path]
        else:
            target_path, target_root = root_path, root
        target: Any = target_root
        if separator and fragment:
            if not fragment.startswith("/"):
                raise ContractError("SCHEMA_REF_UNSUPPORTED", "$", ref)
            for raw in fragment[1:].split("/"):
                target = target[raw.replace("~1", "/").replace("~0", "~")]
        return target, target_root, target_path


SCHEMAS = ProtocolSchemaValidator()
SCHEMA_BY_MESSAGE = {
    "build_identity": "build-identity.schema.json",
    "capture_scope": "capture-scope.schema.json",
    "launch_exchange_request": "launch-exchange-request.schema.json",
    "launch_exchange_receipt": "launch-exchange-receipt.schema.json",
    "segment_upload_intent": "segment-upload-intent.schema.json",
    "segment_upload_receipt": "segment-upload-receipt.schema.json",
    "diagnostic_upload_request": "diagnostic-upload-request.schema.json",
    "diagnostic_upload_receipt": "diagnostic-upload-receipt.schema.json",
    "completion_request": "completion-request.schema.json",
    "completion_receipt": "completion-receipt.schema.json",
    "deletion_request": "deletion-request.schema.json",
    "deletion_tombstone": "deletion-tombstone.schema.json",
}
DIGEST_FIELD_BY_MESSAGE = {
    "build_identity": "build_identity_digest",
    "capture_scope": "scope_digest",
    "launch_exchange_request": "request_digest",
    "launch_exchange_receipt": "exchange_receipt_digest",
    "segment_upload_intent": "intent_digest",
    "segment_upload_receipt": "segment_receipt_digest",
    "diagnostic_upload_request": "request_digest",
    "diagnostic_upload_receipt": "diagnostic_receipt_digest",
    "completion_request": "request_digest",
    "completion_receipt": "completion_receipt_digest",
    "deletion_request": "request_digest",
    "deletion_tombstone": "tombstone_digest",
}
IDEMPOTENCY_BY_MESSAGE = {
    "launch_exchange_request": ("exchange_id", "request_digest"),
    "segment_upload_intent": ("upload_id", "intent_digest"),
    "diagnostic_upload_request": ("upload_id", "request_digest"),
    "completion_request": ("completion_id", "request_digest"),
    "deletion_request": ("deletion_id", "request_digest"),
}


def seal(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    message_type = result.get("message_type")
    field = DIGEST_FIELD_BY_MESSAGE.get(message_type)
    if field is None:
        raise ContractError("UNSUPPORTED_MESSAGE", "$.message_type", str(message_type))
    result[field] = digest_without(result, field)
    return result


def validate(value: dict[str, Any]) -> None:
    runtime.validate_basics(value)
    require(isinstance(value, dict), "SCHEMA_TYPE", "$", "expected object")
    require(
        value.get("protocol_version") == PROTOCOL_VERSION,
        "UNSUPPORTED_PROTOCOL",
        "$.protocol_version",
        str(value.get("protocol_version")),
    )
    message_type = value.get("message_type")
    require(message_type in SCHEMA_BY_MESSAGE, "UNSUPPORTED_MESSAGE", "$.message_type", str(message_type))
    SCHEMAS.validate(value, SCHEMA_BY_MESSAGE[message_type])
    digest_field = DIGEST_FIELD_BY_MESSAGE[message_type]
    require(
        value[digest_field] == digest_without(value, digest_field),
        "DIGEST_MISMATCH",
        f"$.{digest_field}",
        "message changed",
    )
    {
        "build_identity": validate_build_identity,
        "capture_scope": validate_capture_scope,
        "launch_exchange_request": validate_launch_request,
        "launch_exchange_receipt": validate_launch_receipt,
        "segment_upload_intent": validate_segment_intent,
        "segment_upload_receipt": validate_segment_receipt,
        "diagnostic_upload_request": validate_diagnostic_request,
        "diagnostic_upload_receipt": validate_diagnostic_receipt,
        "completion_request": validate_completion_request,
        "completion_receipt": validate_completion_receipt,
        "deletion_request": validate_deletion_request,
        "deletion_tombstone": validate_deletion_tombstone,
    }[message_type](value)


def validate_build_identity(value: dict[str, Any]) -> None:
    expo = value["expo"]
    if expo is not None:
        require(
            (expo["update_id"] is None) == (expo["update_channel"] is None),
            "EXPO_UPDATE_BINDING_MISMATCH",
            "$.expo",
            "update ID and channel must both be present or both be null",
        )


def validate_capture_scope(value: dict[str, Any]) -> None:
    require(
        value["retention"]["raw_media_days"] <= 30,
        "MAX_RAW_RETENTION_EXCEEDED",
        "$.retention.raw_media_days",
        "V1 raw-media retention may not exceed 30 days",
    )


def validate_launch_request(value: dict[str, Any]) -> None:
    validate(value["build_identity"])
    validate(value["scope"])
    build = value["build_identity"]
    scope = value["scope"]
    require(scope["build_id"] == build["build_id"], "BUILD_SCOPE_MISMATCH", "$.scope.build_id", "scope names a different build")
    require(
        scope["build_identity_digest"] == build["build_identity_digest"],
        "BUILD_SCOPE_MISMATCH",
        "$.scope.build_identity_digest",
        "scope does not bind the tested build",
    )
    # Start and resume can establish or recover the SDK's backend-time anchor.
    # Their device timestamp is informational and is not ordered against other
    # clock domains.
    parse_time(value["requested_at"], "$.requested_at")
    if value["exchange_kind"] == "resume_session":
        require(
            value["previous_credential_id"] != value["credential"]["credential_id"],
            "CREDENTIAL_ROTATION_REUSES_ID",
            "$.previous_credential_id",
            "resume must replace the previous credential with a new credential ID",
        )


def validate_launch_receipt(value: dict[str, Any]) -> None:
    validate(value["scope"])
    received = parse_time(value["received_at"], "$.received_at")
    issued = parse_time(value["issued_at"], "$.issued_at")
    require(issued >= received, "INVALID_CHRONOLOGY", "$.issued_at", "credential issue predates server receipt")
    expires = parse_time(value["credential"]["expires_at"], "$.credential.expires_at")
    require(expires > issued, "INVALID_CREDENTIAL_EXPIRY", "$.credential.expires_at", "credential must expire after issue")
    revocation = value["previous_credential_revocation"]
    if revocation is not None:
        require(
            revocation["credential_id"] != value["credential"]["credential_id"],
            "CREDENTIAL_ROTATION_REUSES_ID",
            "$.previous_credential_revocation.credential_id",
            "rotation cannot revoke the newly issued credential",
        )
        require(
            parse_time(revocation["revoked_at"], "$.previous_credential_revocation.revoked_at") == issued,
            "CREDENTIAL_ROTATION_NOT_ATOMIC",
            "$.previous_credential_revocation.revoked_at",
            "old credential revocation and durable new receipt must share one commit time",
        )


def validate_launch_pair(request: dict[str, Any], receipt: dict[str, Any]) -> None:
    validate(request)
    validate(receipt)
    require(receipt["request_digest"] == request["request_digest"], "LAUNCH_BINDING_MISMATCH", "$.receipt.request_digest", "receipt does not bind request")
    for field in ("exchange_kind", "exchange_id"):
        require(receipt[field] == request[field], "LAUNCH_BINDING_MISMATCH", f"$.receipt.{field}", "receipt differs from request")
    require(receipt["scope"] == request["scope"], "LAUNCH_BINDING_MISMATCH", "$.receipt.scope", "server changed immutable scope")
    require(
        receipt["credential"]["credential_id"] == request["credential"]["credential_id"],
        "LAUNCH_BINDING_MISMATCH",
        "$.receipt.credential.credential_id",
        "server changed client-generated credential ID",
    )
    if request["exchange_kind"] == "resume_session":
        require(receipt["session_id"] == request["expected_session_id"], "RESUME_SESSION_MISMATCH", "$.receipt.session_id", "resume code opened another session")
        revocation = receipt["previous_credential_revocation"]
        require(
            revocation is not None and revocation["credential_id"] == request["previous_credential_id"],
            "RESUME_REVOCATION_MISMATCH",
            "$.receipt.previous_credential_revocation",
            "resume receipt does not prove revocation of the credential being replaced",
        )
    else:
        require(
            receipt["previous_credential_revocation"] is None,
            "START_SESSION_REVOCATION_FORBIDDEN",
            "$.receipt.previous_credential_revocation",
            "a new session has no previous credential to revoke",
        )
    require(
        receipt["session_state"] == request["expected_session_state"],
        "RESUME_SESSION_STATE_MISMATCH",
        "$.receipt.session_state",
        "exchange receipt changed the expected session lifecycle state",
    )
    require(
        receipt["credential"]["replay_completion_id"] == request["expected_completion_id"],
        "RESUME_COMPLETION_BINDING_MISMATCH",
        "$.receipt.credential.replay_completion_id",
        "completed-session credential is bound to another completion",
    )
    # Launch and resume request times are non-authoritative because either can
    # be the operation that recovers a missing or invalid monotonic anchor.


def validate_segment_intent(value: dict[str, Any]) -> None:
    require(
        value["transport"]["content_type"] in {"video/mp4", "video/quicktime"},
        "INVALID_SEGMENT_CONTENT_TYPE",
        "$.transport.content_type",
        "segment upload must be video",
    )
    parse_time(value["requested_at"], "$.requested_at")


def validate_segment_receipt(value: dict[str, Any]) -> None:
    receipt = value["runtime_receipt"]
    require(
        receipt["receipt_digest"] == digest_without(receipt, "receipt_digest"),
        "RUNTIME_RECEIPT_DIGEST_MISMATCH",
        "$.runtime_receipt.receipt_digest",
        "embedded runtime receipt changed",
    )
    require(
        value["transport_digest"] == receipt["content_digest"],
        "SEGMENT_TRANSPORT_MISMATCH",
        "$.transport_digest",
        "durable bytes differ from runtime receipt",
    )
    require(
        value["segment_id"] == receipt["segment_id"],
        "SEGMENT_CONTENT_MISMATCH",
        "$.segment_id",
        "protocol receipt and runtime receipt name different segments",
    )
    parse_time(receipt["received_at"], "$.runtime_receipt.received_at")


def validate_segment_pair(intent: dict[str, Any], receipt: dict[str, Any]) -> None:
    validate(intent)
    validate(receipt)
    for field in ("upload_id", "session_id", "scope_digest", "credential_id", "sequence", "segment_id"):
        require(receipt[field] == intent[field], "SEGMENT_BINDING_MISMATCH", f"$.receipt.{field}", "receipt differs from upload intent")
    require(receipt["intent_digest"] == intent["intent_digest"], "SEGMENT_BINDING_MISMATCH", "$.receipt.intent_digest", "receipt does not bind intent")
    runtime_receipt = receipt["runtime_receipt"]
    require(runtime_receipt["segment_id"] == intent["segment_id"], "SEGMENT_CONTENT_MISMATCH", "$.receipt.runtime_receipt.segment_id", "receipt names another segment")
    require(runtime_receipt["size_bytes"] == intent["transport"]["size_bytes"], "SEGMENT_CONTENT_MISMATCH", "$.receipt.runtime_receipt.size_bytes", "receipt size differs")
    require(runtime_receipt["content_digest"] == intent["transport"]["content_digest"], "SEGMENT_CONTENT_MISMATCH", "$.receipt.runtime_receipt.content_digest", "receipt digest differs")
    require(receipt["content_type"] == intent["transport"]["content_type"], "SEGMENT_CONTENT_MISMATCH", "$.receipt.content_type", "receipt content type differs")
    require(receipt["sidecar_digest"] == intent["sidecar_digest"], "SEGMENT_CONTENT_MISMATCH", "$.receipt.sidecar_digest", "receipt sidecar differs")
    require(
        parse_time(runtime_receipt["received_at"], "$.receipt.runtime_receipt.received_at")
        >= parse_time(intent["requested_at"], "$.intent.requested_at"),
        "INVALID_CHRONOLOGY",
        "$.receipt.runtime_receipt.received_at",
        "segment receipt predates upload intent",
    )


def validate_diagnostic_request(value: dict[str, Any]) -> None:
    envelope = value["envelope"]
    runtime.validate(envelope)
    require(envelope["session_id"] == value["session_id"], "ENVELOPE_SCOPE_MISMATCH", "$.envelope.session_id", "envelope names another session")
    encoded = canonical_json(envelope).encode("utf-8")
    require(
        value["transport"]["content_type"] == "application/vnd.tacua.diagnostic-envelope+json;version=1.0.0",
        "INVALID_DIAGNOSTIC_CONTENT_TYPE",
        "$.transport.content_type",
        "diagnostic transport media type is exact-versioned",
    )
    require(value["transport"]["size_bytes"] == len(encoded), "DIAGNOSTIC_TRANSPORT_MISMATCH", "$.transport.size_bytes", "canonical envelope size differs")
    require(value["transport"]["content_digest"] == digest(encoded), "DIAGNOSTIC_TRANSPORT_MISMATCH", "$.transport.content_digest", "canonical envelope digest differs")
    latest_event = max(parse_time(event["occurred_at"], "$.envelope.events[].occurred_at") for event in envelope["events"])
    require(parse_time(value["requested_at"], "$.requested_at") >= latest_event, "INVALID_CHRONOLOGY", "$.requested_at", "upload predates diagnostics")


def validate_diagnostic_receipt(value: dict[str, Any]) -> None:
    parse_time(value["received_at"], "$.received_at")


def validate_diagnostic_pair(request: dict[str, Any], receipt: dict[str, Any]) -> None:
    validate(request)
    validate(receipt)
    for field in ("upload_id", "session_id", "scope_digest", "credential_id"):
        require(receipt[field] == request[field], "DIAGNOSTIC_BINDING_MISMATCH", f"$.receipt.{field}", "receipt differs from request")
    require(receipt["request_digest"] == request["request_digest"], "DIAGNOSTIC_BINDING_MISMATCH", "$.receipt.request_digest", "receipt does not bind request")
    envelope = request["envelope"]
    require(receipt["envelope_id"] == envelope["envelope_id"], "DIAGNOSTIC_BINDING_MISMATCH", "$.receipt.envelope_id", "receipt names another envelope")
    require(receipt["envelope_digest"] == envelope["envelope_digest"], "DIAGNOSTIC_BINDING_MISMATCH", "$.receipt.envelope_digest", "receipt does not bind envelope")
    require(receipt["size_bytes"] == request["transport"]["size_bytes"], "DIAGNOSTIC_BINDING_MISMATCH", "$.receipt.size_bytes", "durable size differs")
    require(receipt["transport_digest"] == request["transport"]["content_digest"], "DIAGNOSTIC_BINDING_MISMATCH", "$.receipt.transport_digest", "durable bytes differ")
    require(
        parse_time(receipt["received_at"], "$.receipt.received_at") >= parse_time(request["requested_at"], "$.request.requested_at"),
        "INVALID_CHRONOLOGY",
        "$.receipt.received_at",
        "diagnostic receipt predates upload request",
    )


def validate_completion_request(value: dict[str, Any]) -> None:
    manifest = value["capture_manifest"]
    runtime.validate(manifest)
    require(manifest["session_id"] == value["session_id"], "COMPLETION_SCOPE_MISMATCH", "$.capture_manifest.session_id", "manifest names another session")
    require(manifest["capture_state"] == "complete", "CAPTURE_NOT_COMPLETE", "$.capture_manifest.capture_state", "completion requires a complete capture")
    require(manifest["upload"]["state"] == "complete", "UPLOAD_NOT_COMPLETE", "$.capture_manifest.upload.state", "completion requires all available media receipts")

    segment_receipts = value["segment_receipts"]
    diagnostic_receipts = value["diagnostic_receipts"]
    for receipt in segment_receipts + diagnostic_receipts:
        validate(receipt)
        require(receipt["session_id"] == value["session_id"], "COMPLETION_SCOPE_MISMATCH", "$.receipts.session_id", "receipt names another session")
        require(receipt["scope_digest"] == value["scope_digest"], "COMPLETION_SCOPE_MISMATCH", "$.receipts.scope_digest", "receipt escaped immutable scope")
    unique([receipt["upload_id"] for receipt in segment_receipts], "$.segment_receipts")
    unique([receipt["segment_id"] for receipt in segment_receipts], "$.segment_receipts")
    unique([receipt["sequence"] for receipt in segment_receipts], "$.segment_receipts")
    unique([receipt["segment_receipt_digest"] for receipt in segment_receipts], "$.segment_receipts")
    unique([receipt["upload_id"] for receipt in diagnostic_receipts], "$.diagnostic_receipts")
    unique([receipt["receipt_id"] for receipt in diagnostic_receipts], "$.diagnostic_receipts")
    unique([receipt["object_id"] for receipt in diagnostic_receipts], "$.diagnostic_receipts")
    unique([receipt["diagnostic_receipt_digest"] for receipt in diagnostic_receipts], "$.diagnostic_receipts")

    available_segments = {
        segment["segment_id"]: segment
        for segment in manifest["segments"]
        if segment["availability"] == "available"
    }
    protocol_receipts = {receipt["segment_id"]: receipt for receipt in segment_receipts}
    require(
        set(protocol_receipts) == set(available_segments),
        "SEGMENT_RECEIPT_SET_MISMATCH",
        "$.segment_receipts",
        "protocol receipts must exactly cover every available manifest segment",
    )
    expected_runtime_receipts = {receipt["segment_id"]: receipt for receipt in manifest["upload"]["receipts"]}
    require(
        set(expected_runtime_receipts) == set(protocol_receipts),
        "SEGMENT_RECEIPT_SET_MISMATCH",
        "$.capture_manifest.upload.receipts",
        "runtime upload receipts and protocol receipts cover different segments",
    )
    for segment_id, receipt in protocol_receipts.items():
        segment = available_segments[segment_id]
        content = segment["content"]
        require(receipt["sequence"] == segment["sequence"], "SEGMENT_MANIFEST_BINDING_MISMATCH", "$.segment_receipts.sequence", "protocol sequence differs from manifest")
        require(receipt["content_type"] == content["content_type"], "SEGMENT_MANIFEST_BINDING_MISMATCH", "$.segment_receipts.content_type", "protocol content type differs from manifest")
        require(receipt["sidecar_digest"] == content["sidecar_digest"], "SEGMENT_MANIFEST_BINDING_MISMATCH", "$.segment_receipts.sidecar_digest", "protocol sidecar differs from manifest")
        runtime_receipt = receipt["runtime_receipt"]
        require(runtime_receipt["size_bytes"] == content["size_bytes"], "SEGMENT_MANIFEST_BINDING_MISMATCH", "$.segment_receipts.runtime_receipt.size_bytes", "protocol size differs from manifest")
        require(runtime_receipt["content_digest"] == content["content_digest"], "SEGMENT_MANIFEST_BINDING_MISMATCH", "$.segment_receipts.runtime_receipt.content_digest", "protocol content digest differs from manifest")
        require(
            canonical_json(runtime_receipt) == canonical_json(expected_runtime_receipts[segment_id]),
            "SEGMENT_RECEIPT_SET_MISMATCH",
            "$.segment_receipts.runtime_receipt",
            "protocol runtime receipt differs from the manifest receipt for its segment",
        )

    requested = parse_time(value["requested_at"], "$.requested_at")
    upload_completed = parse_time(manifest["upload"]["completed_at"], "$.capture_manifest.upload.completed_at")
    latest_segment = max(
        parse_time(item["runtime_receipt"]["received_at"], "$.segment_receipts[].runtime_receipt.received_at")
        for item in segment_receipts
    )
    require(
        upload_completed >= latest_segment,
        "INVALID_CHRONOLOGY",
        "$.capture_manifest.upload.completed_at",
        "manifest upload completion predates a segment receipt",
    )
    require(
        upload_completed >= parse_time(manifest["ended_at"], "$.capture_manifest.ended_at"),
        "INVALID_CHRONOLOGY",
        "$.capture_manifest.upload.completed_at",
        "manifest upload completed before capture ended",
    )
    require(
        requested >= upload_completed and requested >= latest_segment,
        "INVALID_CHRONOLOGY",
        "$.requested_at",
        "completion predates media upload",
    )
    require(
        requested >= parse_time(manifest["ended_at"], "$.capture_manifest.ended_at"),
        "INVALID_CHRONOLOGY",
        "$.requested_at",
        "completion predates capture end",
    )
    latest_diagnostic = max(parse_time(item["received_at"], "$.diagnostic_receipts[].received_at") for item in diagnostic_receipts)
    require(requested >= latest_diagnostic, "INVALID_CHRONOLOGY", "$.requested_at", "completion predates diagnostics upload")


def validate_completion_receipt(value: dict[str, Any]) -> None:
    job = value["processing_job"]
    runtime.validate(job)
    require(job["status"] == "queued", "JOB_NOT_QUEUED", "$.processing_job.status", "completion must durably create a queued job")
    expected_stages = [
        {
            "name": name,
            "state": "pending",
            "attempt_count": 0,
            "started_at": None,
            "completed_at": None,
            "detail": None,
        }
        for name in PROCESSING_JOB_STAGES
    ]
    expected_execution = {
        "mode": "async",
        "max_attempts": 3,
        "egress": {
            "policy": "default_deny",
            "authorized": False,
            "authorization_decision_id": None,
            "destinations": [],
        },
    }
    require(
        job["job_version"] == 1
        and job["previous_job_digest"] is None
        and job["started_at"] is None
        and job["completed_at"] is None
        and job["outputs"] is None
        and job["failure"] is None
        and job["pipeline"]["stages"] == expected_stages
        and job["execution"] == expected_execution,
        "COMPLETION_JOB_NOT_INITIAL",
        "$.processing_job",
        "completion must return the exact version-one queued processing baseline",
    )
    require(job["session_id"] == value["session_id"], "COMPLETION_SCOPE_MISMATCH", "$.processing_job.session_id", "job names another session")
    require(
        value["credential"]["replay_completion_id"] == value["completion_id"],
        "COMPLETION_CREDENTIAL_MISMATCH",
        "$.credential.replay_completion_id",
        "replay-only credential is bound to another completion",
    )
    accepted = parse_time(value["accepted_at"], "$.accepted_at")
    expires = parse_time(value["credential"]["expires_at"], "$.credential.expires_at")
    require(expires > accepted, "INVALID_CREDENTIAL_EXPIRY", "$.credential.expires_at", "completion replay window must follow acceptance")


def validate_completion_pair(request: dict[str, Any], receipt: dict[str, Any]) -> None:
    validate(request)
    validate(receipt)
    for field in ("completion_id", "session_id", "scope_digest"):
        require(receipt[field] == request[field], "COMPLETION_BINDING_MISMATCH", f"$.receipt.{field}", "completion receipt differs from request")
    require(receipt["request_digest"] == request["request_digest"], "COMPLETION_BINDING_MISMATCH", "$.receipt.request_digest", "receipt does not bind exact request")
    require(
        receipt["credential"]["credential_id"] == request["credential_id"],
        "COMPLETION_CREDENTIAL_MISMATCH",
        "$.receipt.credential.credential_id",
        "completion transitioned another credential",
    )
    accepted = parse_time(receipt["accepted_at"], "$.receipt.accepted_at")
    requested = parse_time(request["requested_at"], "$.request.requested_at")
    require(accepted >= requested, "INVALID_CHRONOLOGY", "$.receipt.accepted_at", "receipt predates completion request")

    manifest = request["capture_manifest"]
    job = receipt["processing_job"]
    for field in ("organization_id", "project_id", "build_id", "build_identity_digest", "session_id"):
        require(job[field] == manifest[field], "COMPLETION_JOB_SCOPE_MISMATCH", f"$.receipt.processing_job.{field}", "job scope differs from manifest")
    require(job["requested_at"] == receipt["accepted_at"], "COMPLETION_JOB_BINDING_MISMATCH", "$.receipt.processing_job.requested_at", "queued job must originate at acceptance")
    require(
        job["inputs"]["capture_manifest_digest"] == manifest["manifest_digest"],
        "COMPLETION_JOB_BINDING_MISMATCH",
        "$.receipt.processing_job.inputs.capture_manifest_digest",
        "job does not bind manifest",
    )
    expected_diagnostics = [item["envelope_digest"] for item in request["diagnostic_receipts"]]
    require(
        job["inputs"]["diagnostic_envelope_digests"] == expected_diagnostics,
        "COMPLETION_JOB_BINDING_MISMATCH",
        "$.receipt.processing_job.inputs.diagnostic_envelope_digests",
        "job does not bind exact diagnostic receipts",
    )
    cleanup = receipt["local_cleanup"]
    require(cleanup["manifest_digest"] == manifest["manifest_digest"], "LOCAL_CLEANUP_BINDING_MISMATCH", "$.receipt.local_cleanup.manifest_digest", "cleanup authorization names another manifest")
    require(
        cleanup["segment_receipt_digests"] == [item["segment_receipt_digest"] for item in request["segment_receipts"]],
        "LOCAL_CLEANUP_BINDING_MISMATCH",
        "$.receipt.local_cleanup.segment_receipt_digests",
        "cleanup authorization omits or changes a media receipt",
    )
    require(
        cleanup["diagnostic_receipt_digests"] == [item["diagnostic_receipt_digest"] for item in request["diagnostic_receipts"]],
        "LOCAL_CLEANUP_BINDING_MISMATCH",
        "$.receipt.local_cleanup.diagnostic_receipt_digests",
        "cleanup authorization omits or changes a diagnostic receipt",
    )


def validate_deletion_request(value: dict[str, Any]) -> None:
    parse_time(value["requested_at"], "$.requested_at")


def validate_deletion_tombstone(value: dict[str, Any]) -> None:
    accepted = parse_time(value["accepted_at"], "$.accepted_at")
    deleted = parse_time(value["deleted_at"], "$.deleted_at")
    expires = parse_time(value["tombstone_expires_at"], "$.tombstone_expires_at")
    require(deleted >= accepted, "INVALID_CHRONOLOGY", "$.deleted_at", "durable erasure predates deletion acceptance")
    require(expires > deleted, "INVALID_TOMBSTONE_EXPIRY", "$.tombstone_expires_at", "tombstone expiry must follow deletion")
    require(
        expires <= deleted + timedelta(days=30),
        "TOMBSTONE_RETENTION_EXCEEDED",
        "$.tombstone_expires_at",
        "minimal deletion tombstones may not persist beyond 30 days",
    )
    credential = value["credential"]
    require(
        credential["replay_deletion_id"] == value["deletion_id"],
        "DELETION_CREDENTIAL_MISMATCH",
        "$.credential.replay_deletion_id",
        "deletion replay credential is bound to another deletion",
    )
    require(
        parse_time(credential["verifier_retained_until"], "$.credential.verifier_retained_until") == expires,
        "DELETION_REPLAY_RETENTION_MISMATCH",
        "$.credential.verifier_retained_until",
        "replay verifier and exact tombstone must expire together",
    )


def validate_deletion_pair(request: dict[str, Any], tombstone: dict[str, Any]) -> None:
    validate(request)
    validate(tombstone)
    mappings = {
        "deletion_id": "deletion_id",
        "session_id": "session_id",
        "scope_digest": "scope_digest",
        "request_digest": "deletion_request_digest",
    }
    for request_field, tombstone_field in mappings.items():
        require(
            request[request_field] == tombstone[tombstone_field],
            "DELETION_BINDING_MISMATCH",
            f"$.tombstone.{tombstone_field}",
            "tombstone differs from deletion request",
        )
    require(
        tombstone["credential"]["credential_id"] == request["credential_id"],
        "DELETION_BINDING_MISMATCH",
        "$.tombstone.credential.credential_id",
        "tombstone retained a verifier for another credential",
    )
    require(
        parse_time(tombstone["accepted_at"], "$.tombstone.accepted_at") >= parse_time(request["requested_at"], "$.request.requested_at"),
        "INVALID_CHRONOLOGY",
        "$.tombstone.accepted_at",
        "deletion acceptance predates its request",
    )


def validate_idempotent_request_replay(original: dict[str, Any], replay: dict[str, Any]) -> None:
    """Require an operation-ID replay to carry identical canonical request content."""
    validate(original)
    validate(replay)
    message_type = original["message_type"]
    require(replay["message_type"] == message_type, "IDEMPOTENCY_TYPE_MISMATCH", "$.replay.message_type", "replay changed operation type")
    require(message_type in IDEMPOTENCY_BY_MESSAGE, "NOT_IDEMPOTENT_REQUEST", "$.message_type", message_type)
    id_field, digest_field = IDEMPOTENCY_BY_MESSAGE[message_type]
    require(replay[id_field] == original[id_field], "IDEMPOTENCY_KEY_MISMATCH", f"$.replay.{id_field}", "replay uses another operation ID")
    require(
        replay[digest_field] == original[digest_field],
        "IDEMPOTENCY_CONFLICT",
        f"$.replay.{digest_field}",
        "same operation ID was reused for different canonical content",
    )
    require(
        canonical_json(replay) == canonical_json(original),
        "IDEMPOTENCY_REQUEST_MISMATCH",
        "$.replay",
        "same operation ID and digest must replay identical canonical request bytes",
    )


def validate_operation_pair(request: dict[str, Any], response: dict[str, Any]) -> None:
    """Dispatch one mutating request and its durable response to its pair validator."""
    validators = {
        "launch_exchange_request": ("launch_exchange_receipt", validate_launch_pair),
        "segment_upload_intent": ("segment_upload_receipt", validate_segment_pair),
        "diagnostic_upload_request": ("diagnostic_upload_receipt", validate_diagnostic_pair),
        "completion_request": ("completion_receipt", validate_completion_pair),
        "deletion_request": ("deletion_tombstone", validate_deletion_pair),
    }
    message_type = request.get("message_type")
    require(message_type in validators, "NOT_IDEMPOTENT_REQUEST", "$.request.message_type", str(message_type))
    response_type, validator = validators[message_type]
    require(
        response.get("message_type") == response_type,
        "OPERATION_RESPONSE_TYPE_MISMATCH",
        "$.response.message_type",
        f"{message_type} requires {response_type}",
    )
    validator(request, response)


def validate_idempotent_replay(
    original_request: dict[str, Any],
    original_response: dict[str, Any],
    replay_request: dict[str, Any],
    replay_response: dict[str, Any],
) -> None:
    """Require exact canonical request and persisted-response bytes across a replay."""
    validate_idempotent_request_replay(original_request, replay_request)
    validate_operation_pair(original_request, original_response)
    validate_operation_pair(replay_request, replay_response)
    require(
        replay_response["message_type"] == original_response["message_type"],
        "IDEMPOTENCY_RESPONSE_TYPE_MISMATCH",
        "$.replay_response.message_type",
        "replay returned another response type",
    )
    require(
        canonical_json(replay_response).encode("utf-8") == canonical_json(original_response).encode("utf-8"),
        "IDEMPOTENCY_RESPONSE_MISMATCH",
        "$.replay_response",
        "exact retry must return the byte-identical canonical persisted response",
    )


def validate_launch_chain(
    build_identity: dict[str, Any],
    scope: dict[str, Any],
    launch_pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> tuple[str, dict[str, dict[str, Any]]]:
    """Validate ordered start/resume exchanges and return durable credential history."""
    require(bool(launch_pairs), "EMPTY_LAUNCH_CHAIN", "$.launch_pairs", "lifecycle requires a start exchange")
    require(
        len(launch_pairs) <= MAX_SESSION_CREDENTIALS,
        "CREDENTIAL_ROTATION_LIMIT_REACHED",
        "$.launch_pairs",
        "V1 session credential history may contain at most 64 credentials",
    )
    history: dict[str, dict[str, Any]] = {}
    session_id: str | None = None
    previous_credential_id: str | None = None
    previous_session_state: str | None = None
    previous_issued = None

    for index, (request, receipt) in enumerate(launch_pairs):
        validate_launch_pair(request, receipt)
        require(request["build_identity"] == build_identity, "BUNDLE_SCOPE_MISMATCH", f"$.launch_pairs[{index}].request.build_identity", "launch request changed build")
        require(request["scope"] == scope and receipt["scope"] == scope, "BUNDLE_SCOPE_MISMATCH", f"$.launch_pairs[{index}].scope", "launch exchange changed immutable scope")
        credential_id = receipt["credential"]["credential_id"]
        require(credential_id not in history, "DUPLICATE_CREDENTIAL_ID", f"$.launch_pairs[{index}].credential_id", "credential ID already exists in this session")
        issued = parse_time(receipt["issued_at"], f"$.launch_pairs[{index}].receipt.issued_at")

        if index == 0:
            require(request["exchange_kind"] == "start_session", "LAUNCH_CHAIN_MUST_START_SESSION", "$.launch_pairs[0].request.exchange_kind", "first exchange must create the session")
            require(receipt["session_state"] == "receiving", "BUNDLE_SESSION_STATE_MISMATCH", "$.launch_pairs[0].receipt.session_state", "new session must begin receiving")
            session_id = receipt["session_id"]
        else:
            require(request["exchange_kind"] == "resume_session", "LAUNCH_CHAIN_RESUME_REQUIRED", f"$.launch_pairs[{index}].request.exchange_kind", "later exchanges must resume the session")
            require(receipt["session_id"] == session_id, "BUNDLE_SCOPE_MISMATCH", f"$.launch_pairs[{index}].receipt.session_id", "resume escaped the original session")
            require(request["previous_credential_id"] == previous_credential_id, "CREDENTIAL_CHAIN_MISMATCH", f"$.launch_pairs[{index}].request.previous_credential_id", "resume did not rotate the current credential")
            revocation = receipt["previous_credential_revocation"]
            require(revocation["credential_id"] == previous_credential_id, "CREDENTIAL_CHAIN_MISMATCH", f"$.launch_pairs[{index}].receipt.previous_credential_revocation", "resume revoked another credential")
            require(
                parse_time(receipt["received_at"], f"$.launch_pairs[{index}].receipt.received_at")
                >= previous_issued,
                "INVALID_CHRONOLOGY",
                f"$.launch_pairs[{index}].receipt.received_at",
                "server received a resume before the previous credential existed",
            )
            require(issued >= previous_issued, "INVALID_CHRONOLOGY", f"$.launch_pairs[{index}].receipt.issued_at", "credential issue time regressed")
            require(
                not (previous_session_state == "completed" and receipt["session_state"] != "completed"),
                "SESSION_STATE_REGRESSION",
                f"$.launch_pairs[{index}].receipt.session_state",
                "completed session cannot return to receiving",
            )
            history[previous_credential_id]["revoked_at"] = parse_time(
                revocation["revoked_at"],
                f"$.launch_pairs[{index}].receipt.previous_credential_revocation.revoked_at",
            )

        history[credential_id] = {
            "session_id": session_id,
            "scope_digest": scope["scope_digest"],
            "issued_at": issued,
            "expires_at": parse_time(receipt["credential"]["expires_at"], f"$.launch_pairs[{index}].receipt.credential.expires_at"),
            "revoked_at": None,
            "credential_state": receipt["credential"]["state"],
            "session_state": receipt["session_state"],
            "replay_completion_id": receipt["credential"]["replay_completion_id"],
        }
        previous_credential_id = credential_id
        previous_session_state = receipt["session_state"]
        previous_issued = issued

    return session_id, history


def validate_credential_use(
    credential_id: str,
    authoritative_at: str,
    history: dict[str, dict[str, Any]],
    path: str,
) -> dict[str, Any]:
    """Resolve a server acceptance time against durable credential history."""
    require(credential_id in history, "UNRELATED_CREDENTIAL", f"{path}.credential_id", "credential is not in this session's durable rotation chain")
    credential = history[credential_id]
    accepted = parse_time(authoritative_at, f"{path}.accepted_at")
    require(accepted >= credential["issued_at"], "INVALID_CHRONOLOGY", f"{path}.accepted_at", "operation predates credential issue")
    require(accepted < credential["expires_at"], "EXPIRED_CREDENTIAL", f"{path}.accepted_at", "operation was accepted at or after credential expiry")
    if credential["revoked_at"] is not None:
        require(accepted < credential["revoked_at"], "REVOKED_CREDENTIAL", f"{path}.accepted_at", "operation was accepted at or after credential revocation")
    return credential


def current_credential_at(
    authoritative_at: str,
    history: dict[str, dict[str, Any]],
    path: str,
) -> tuple[str, dict[str, Any]]:
    """Return the sole credential whose half-open server interval contains a time."""
    accepted = parse_time(authoritative_at, f"{path}.accepted_at")
    current = [
        (credential_id, credential)
        for credential_id, credential in history.items()
        if credential["issued_at"] <= accepted
        and accepted < credential["expires_at"]
        and (credential["revoked_at"] is None or accepted < credential["revoked_at"])
    ]
    require(len(current) == 1, "NO_CURRENT_CREDENTIAL", f"{path}.accepted_at", "server acceptance must resolve to exactly one current credential")
    return current[0]


def validate_new_upload_authentication(
    request: dict[str, Any],
    authentication_credential_id: str,
    server_authenticated_at: str,
    credential_history: dict[str, dict[str, Any]],
    session_state: str,
) -> None:
    """Authorize a not-yet-durable upload; no rotated-ID exception applies."""
    current_id, current = current_credential_at(
        server_authenticated_at,
        credential_history,
        "$.authentication",
    )
    require(
        authentication_credential_id == current_id,
        "CURRENT_CREDENTIAL_MISMATCH",
        "$.authentication.credential_id",
        "Authorization did not use the current session credential",
    )
    validate(request)
    require(
        request["message_type"] in {"segment_upload_intent", "diagnostic_upload_request"},
        "UNSUPPORTED_AUTHENTICATED_OPERATION",
        "$.request.message_type",
        "new-operation helper is limited to SDK uploads",
    )
    require(
        request["session_id"] == current["session_id"]
        and request["scope_digest"] == current["scope_digest"],
        "BUNDLE_SCOPE_MISMATCH",
        "$.request",
        "authenticated route or body escaped the credential's session scope",
    )
    require(
        request["credential_id"] == authentication_credential_id,
        "AUTHENTICATION_CREDENTIAL_MISMATCH",
        "$.request.credential_id",
        "a new operation must name the same current credential used for Authorization",
    )
    validate_credential_use(
        request["credential_id"],
        server_authenticated_at,
        credential_history,
        "$.request",
    )
    require(
        session_state == "receiving"
        and current["session_state"] == "receiving"
        and current["credential_state"] == "active",
        "CREDENTIAL_CAPABILITY_MISMATCH",
        "$.authentication.credential_id",
        "new uploads require the current active credential of a receiving session",
    )


def validate_authenticated_exact_replay(
    original_request: dict[str, Any],
    original_response: dict[str, Any],
    replay_request: dict[str, Any],
    replay_response: dict[str, Any],
    authentication_credential_id: str,
    server_authenticated_at: str,
    credential_history: dict[str, dict[str, Any]],
    session_state: str,
) -> None:
    """Authorize a durable exact replay without rewriting its original credential ID."""
    # The caller supplies the credential ID only after verifying its bearer
    # secret. Authenticate current session scope before any durable lookup, but
    # deliberately do not require equality with the historical body ID yet.
    current_id, current = current_credential_at(
        server_authenticated_at,
        credential_history,
        "$.authentication",
    )
    require(
        authentication_credential_id == current_id,
        "CURRENT_CREDENTIAL_MISMATCH",
        "$.authentication.credential_id",
        "exact replay was not authenticated by the current session credential",
    )
    require(
        replay_request.get("session_id") == current["session_id"]
        and replay_request.get("scope_digest") == current["scope_digest"],
        "BUNDLE_SCOPE_MISMATCH",
        "$.replay_request",
        "authenticated route or request escaped the credential's session scope",
    )

    # Only an authenticated exact durable hit receives the rotated-body-ID
    # exception. Conflicts are resolved before operation-specific capability.
    validate_idempotent_replay(
        original_request,
        original_response,
        replay_request,
        replay_response,
    )
    message_type = original_request["message_type"]
    require(
        message_type
        in {"segment_upload_intent", "diagnostic_upload_request", "completion_request"},
        "UNSUPPORTED_AUTHENTICATED_OPERATION",
        "$.request.message_type",
        "authenticated rotation replay supports uploads and completion",
    )
    source_credential_id = original_request["credential_id"]
    require(
        source_credential_id in credential_history,
        "UNRELATED_CREDENTIAL",
        "$.request.credential_id",
        "durable operation credential is outside this session's rotation history",
    )

    if message_type == "segment_upload_intent":
        original_accepted_at = original_response["runtime_receipt"]["received_at"]
    elif message_type == "diagnostic_upload_request":
        original_accepted_at = original_response["received_at"]
    else:
        original_accepted_at = original_response["accepted_at"]

    source = validate_credential_use(
        source_credential_id,
        original_accepted_at,
        credential_history,
        "$.original_request",
    )
    require(
        source["session_state"] == "receiving" and source["credential_state"] == "active",
        "CREDENTIAL_CAPABILITY_MISMATCH",
        "$.original_request.credential_id",
        "the original operation was not accepted under an upload-capable credential",
    )
    if message_type == "completion_request":
        original_current_id, _ = current_credential_at(
            original_accepted_at,
            credential_history,
            "$.original_response",
        )
        require(
            source_credential_id == original_current_id,
            "CURRENT_CREDENTIAL_MISMATCH",
            "$.original_request.credential_id",
            "the original completion did not use the current credential",
        )

    if message_type in {"segment_upload_intent", "diagnostic_upload_request"}:
        require(
            session_state == "receiving"
            and current["session_state"] == "receiving"
            and current["credential_state"] == "active",
            "REPLAY_CAPABILITY_MISMATCH",
            "$.authentication.credential_id",
            "only an active receiving-session credential may replay a durable upload",
        )
        return

    if current_id == original_response["credential"]["credential_id"]:
        effective_state = original_response["credential"]["state"]
        replay_completion_id = original_response["credential"]["replay_completion_id"]
    else:
        effective_state = current["credential_state"]
        replay_completion_id = current["replay_completion_id"]
    require(
        session_state == "completed"
        and effective_state == "completion_replay_or_delete_only"
        and replay_completion_id == original_request["completion_id"],
        "REPLAY_CAPABILITY_MISMATCH",
        "$.authentication.credential_id",
        "completed credential may replay only its bound durable completion",
    )


def validate_bundle(
    build_identity: dict[str, Any],
    scope: dict[str, Any],
    launch_pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    segment_pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    diagnostic_pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    completion_request: dict[str, Any],
    completion_receipt: dict[str, Any],
    deletion_pair: tuple[dict[str, Any], dict[str, Any]] | None = None,
) -> None:
    """Validate one lifecycle against ordered, server-authoritative credential history."""
    validate(build_identity)
    validate(scope)
    require(scope["build_id"] == build_identity["build_id"], "BUNDLE_SCOPE_MISMATCH", "$.scope.build_id", "scope names another build")
    require(scope["build_identity_digest"] == build_identity["build_identity_digest"], "BUNDLE_SCOPE_MISMATCH", "$.scope.build_identity_digest", "scope does not bind build")
    session_id, credential_history = validate_launch_chain(build_identity, scope, launch_pairs)

    for intent, receipt in segment_pairs:
        validate_segment_pair(intent, receipt)
    for request, receipt in diagnostic_pairs:
        validate_diagnostic_pair(request, receipt)
    validate_completion_pair(completion_request, completion_receipt)

    scope_digest = scope["scope_digest"]
    for value in [
        *(item for pair in segment_pairs for item in pair),
        *(item for pair in diagnostic_pairs for item in pair),
        completion_request,
        completion_receipt,
    ]:
        require(value["session_id"] == session_id, "BUNDLE_SCOPE_MISMATCH", "$.session_id", "message escaped launch session")
        require(value["scope_digest"] == scope_digest, "BUNDLE_SCOPE_MISMATCH", "$.scope_digest", "message escaped immutable scope")

    for index, (intent, receipt) in enumerate(segment_pairs):
        credential = validate_credential_use(
            intent["credential_id"],
            receipt["runtime_receipt"]["received_at"],
            credential_history,
            f"$.segment_pairs[{index}]",
        )
        require(
            parse_time(intent["requested_at"], f"$.segment_pairs[{index}].intent.requested_at") >= credential["issued_at"],
            "INVALID_CHRONOLOGY",
            f"$.segment_pairs[{index}].intent.requested_at",
            "client segment request predates credential issue",
        )
        require(
            credential["session_state"] == "receiving" and credential["credential_state"] == "active",
            "CREDENTIAL_CAPABILITY_MISMATCH",
            f"$.segment_pairs[{index}].intent.credential_id",
            "segment upload requires a receiving-session active credential",
        )
    for index, (request, receipt) in enumerate(diagnostic_pairs):
        credential = validate_credential_use(
            request["credential_id"],
            receipt["received_at"],
            credential_history,
            f"$.diagnostic_pairs[{index}]",
        )
        require(
            parse_time(request["requested_at"], f"$.diagnostic_pairs[{index}].request.requested_at") >= credential["issued_at"],
            "INVALID_CHRONOLOGY",
            f"$.diagnostic_pairs[{index}].request.requested_at",
            "client diagnostic request predates credential issue",
        )
        require(
            credential["session_state"] == "receiving" and credential["credential_state"] == "active",
            "CREDENTIAL_CAPABILITY_MISMATCH",
            f"$.diagnostic_pairs[{index}].request.credential_id",
            "diagnostic upload requires a receiving-session active credential",
        )

    current_completion_id, _ = current_credential_at(
        completion_receipt["accepted_at"],
        credential_history,
        "$.completion_receipt",
    )
    require(
        completion_request["credential_id"] == current_completion_id,
        "CURRENT_CREDENTIAL_MISMATCH",
        "$.completion_request.credential_id",
        "completion did not use the current credential at server acceptance",
    )
    completion_credential = validate_credential_use(
        completion_request["credential_id"],
        completion_receipt["accepted_at"],
        credential_history,
        "$.completion_request",
    )
    require(
        parse_time(completion_request["requested_at"], "$.completion_request.requested_at") >= completion_credential["issued_at"],
        "INVALID_CHRONOLOGY",
        "$.completion_request.requested_at",
        "client completion request predates credential issue",
    )
    require(
        completion_credential["session_state"] == "receiving" and completion_credential["credential_state"] == "active",
        "CREDENTIAL_CAPABILITY_MISMATCH",
        "$.completion_request.credential_id",
        "first completion requires the current receiving-session active credential",
    )
    require(
        completion_receipt["credential"]["credential_id"] == completion_request["credential_id"],
        "BUNDLE_CREDENTIAL_MISMATCH",
        "$.completion_receipt.credential.credential_id",
        "completion transitioned another credential",
    )
    launch_expiry = next(
        receipt["credential"]["expires_at"]
        for _, receipt in launch_pairs
        if receipt["credential"]["credential_id"] == completion_request["credential_id"]
    )
    require(
        completion_receipt["credential"]["expires_at"] == launch_expiry,
        "COMPLETION_CREDENTIAL_EXPIRY_MISMATCH",
        "$.completion_receipt.credential.expires_at",
        "completion state transition cannot silently change credential expiry",
    )
    accepted = parse_time(completion_receipt["accepted_at"], "$.completion_receipt.accepted_at")

    for index, (_, receipt) in enumerate(launch_pairs):
        issued = parse_time(receipt["issued_at"], f"$.launch_pairs[{index}].receipt.issued_at")
        if receipt["session_state"] == "completed":
            require(issued > accepted, "INVALID_CHRONOLOGY", f"$.launch_pairs[{index}].receipt.issued_at", "completed-session resume did not follow durable completion")
            require(receipt["credential"]["replay_completion_id"] == completion_request["completion_id"], "RESUME_COMPLETION_BINDING_MISMATCH", f"$.launch_pairs[{index}].receipt.credential.replay_completion_id", "completed-session resume names another completion")
        else:
            require(issued <= accepted, "INVALID_CHRONOLOGY", f"$.launch_pairs[{index}].receipt.issued_at", "receiving-session resume followed completion")

    unique([intent["segment_id"] for intent, _ in segment_pairs], "$.segment_pairs")
    unique([receipt["segment_id"] for _, receipt in segment_pairs], "$.segment_pairs")
    pair_segment_receipts = {receipt["segment_id"]: canonical_json(receipt) for _, receipt in segment_pairs}
    completion_segment_receipts = {receipt["segment_id"]: canonical_json(receipt) for receipt in completion_request["segment_receipts"]}
    require(completion_segment_receipts == pair_segment_receipts, "BUNDLE_RECEIPT_MISMATCH", "$.completion_request.segment_receipts", "completion does not use the exact keyed set of media receipts")

    unique([request["upload_id"] for request, _ in diagnostic_pairs], "$.diagnostic_pairs")
    unique([receipt["upload_id"] for _, receipt in diagnostic_pairs], "$.diagnostic_pairs")
    pair_diagnostic_receipts = {receipt["upload_id"]: canonical_json(receipt) for _, receipt in diagnostic_pairs}
    completion_diagnostic_receipts = {receipt["upload_id"]: canonical_json(receipt) for receipt in completion_request["diagnostic_receipts"]}
    require(completion_diagnostic_receipts == pair_diagnostic_receipts, "BUNDLE_RECEIPT_MISMATCH", "$.completion_request.diagnostic_receipts", "completion does not use the exact keyed set of diagnostic receipts")

    scoped_runtime_values = [completion_request["capture_manifest"], completion_receipt["processing_job"]]
    scoped_runtime_values.extend(request["envelope"] for request, _ in diagnostic_pairs)
    for value in scoped_runtime_values:
        for field in ("organization_id", "project_id", "build_id", "build_identity_digest"):
            require(value[field] == scope[field], "BUNDLE_SCOPE_MISMATCH", f"$.runtime.{field}", "runtime artifact escaped immutable scope")
        require(value["session_id"] == session_id, "BUNDLE_SCOPE_MISMATCH", "$.runtime.session_id", "runtime artifact names another session")
    first_issued = min(item["issued_at"] for item in credential_history.values())
    require(parse_time(completion_request["capture_manifest"]["started_at"], "$.capture_manifest.started_at") >= first_issued, "INVALID_CHRONOLOGY", "$.capture_manifest.started_at", "capture predates session credential issue")

    if deletion_pair is not None:
        request, tombstone = deletion_pair
        validate_deletion_pair(request, tombstone)
        require(request["session_id"] == session_id and request["scope_digest"] == scope_digest, "BUNDLE_SCOPE_MISMATCH", "$.deletion_request", "deletion escaped session scope")
        current_deletion_id, _ = current_credential_at(
            tombstone["accepted_at"],
            credential_history,
            "$.deletion_tombstone",
        )
        require(
            request["credential_id"] == current_deletion_id,
            "CURRENT_CREDENTIAL_MISMATCH",
            "$.deletion_request.credential_id",
            "deletion did not use the current credential at server acceptance",
        )
        deletion_credential = validate_credential_use(
            request["credential_id"],
            tombstone["accepted_at"],
            credential_history,
            "$.deletion_request",
        )
        deletion_requested = parse_time(request["requested_at"], "$.deletion_request.requested_at")
        require(
            deletion_requested >= deletion_credential["issued_at"],
            "INVALID_CHRONOLOGY",
            "$.deletion_request.requested_at",
            "client deletion request predates credential issue",
        )
        require(deletion_requested >= accepted, "INVALID_CHRONOLOGY", "$.deletion_request.requested_at", "deletion predates completion")
        effective_state = deletion_credential["credential_state"]
        if request["credential_id"] == completion_receipt["credential"]["credential_id"]:
            effective_state = completion_receipt["credential"]["state"]
            require(
                parse_time(tombstone["accepted_at"], "$.deletion_tombstone.accepted_at")
                < parse_time(completion_receipt["credential"]["expires_at"], "$.completion_receipt.credential.expires_at"),
                "EXPIRED_CREDENTIAL",
                "$.deletion_tombstone.accepted_at",
                "first deletion follows completion credential expiry",
            )
        require(
            effective_state == "completion_replay_or_delete_only",
            "BUNDLE_CREDENTIAL_STATE_MISMATCH",
            "$.deletion_request.credential_id",
            "first deletion requires completion replay-or-delete capability",
        )
        require(tombstone["credential"]["credential_id"] == request["credential_id"], "BUNDLE_CREDENTIAL_MISMATCH", "$.deletion_tombstone.credential.credential_id", "deletion replay verifier belongs to another credential")
        for index, (_, receipt) in enumerate(launch_pairs):
            require(
                parse_time(receipt["issued_at"], f"$.launch_pairs[{index}].receipt.issued_at")
                <= parse_time(tombstone["accepted_at"], "$.deletion_tombstone.accepted_at"),
                "INVALID_CHRONOLOGY",
                f"$.launch_pairs[{index}].receipt.issued_at",
                "credential resume followed session deletion request",
            )


def load_json(path: Path) -> dict[str, Any]:
    return runtime.load_json(path)
