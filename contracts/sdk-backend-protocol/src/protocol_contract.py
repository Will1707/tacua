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
    requested = parse_time(value["requested_at"], "$.requested_at")
    require(
        requested >= parse_time(build["created_at"], "$.build_identity.created_at"),
        "INVALID_CHRONOLOGY",
        "$.requested_at",
        "exchange predates the build",
    )
    require(
        requested >= parse_time(scope["consent"]["granted_at"], "$.scope.consent.granted_at"),
        "INVALID_CHRONOLOGY",
        "$.requested_at",
        "exchange predates consent",
    )


def validate_launch_receipt(value: dict[str, Any]) -> None:
    validate(value["scope"])
    issued = parse_time(value["issued_at"], "$.issued_at")
    expires = parse_time(value["credential"]["expires_at"], "$.credential.expires_at")
    require(expires > issued, "INVALID_CREDENTIAL_EXPIRY", "$.credential.expires_at", "credential must expire after issue")


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
    require(
        parse_time(receipt["issued_at"], "$.receipt.issued_at") >= parse_time(request["requested_at"], "$.request.requested_at"),
        "INVALID_CHRONOLOGY",
        "$.receipt.issued_at",
        "receipt predates exchange",
    )


def validate_segment_intent(value: dict[str, Any]) -> None:
    require(
        value["transport"]["content_type"] in {"video/mp4", "video/quicktime"},
        "INVALID_SEGMENT_CONTENT_TYPE",
        "$.transport.content_type",
        "segment upload must be video",
    )


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


def validate_segment_pair(intent: dict[str, Any], receipt: dict[str, Any]) -> None:
    validate(intent)
    validate(receipt)
    for field in ("upload_id", "session_id", "scope_digest", "sequence"):
        require(receipt[field] == intent[field], "SEGMENT_BINDING_MISMATCH", f"$.receipt.{field}", "receipt differs from upload intent")
    require(receipt["intent_digest"] == intent["intent_digest"], "SEGMENT_BINDING_MISMATCH", "$.receipt.intent_digest", "receipt does not bind intent")
    runtime_receipt = receipt["runtime_receipt"]
    require(runtime_receipt["segment_id"] == intent["segment_id"], "SEGMENT_CONTENT_MISMATCH", "$.receipt.runtime_receipt.segment_id", "receipt names another segment")
    require(runtime_receipt["size_bytes"] == intent["transport"]["size_bytes"], "SEGMENT_CONTENT_MISMATCH", "$.receipt.runtime_receipt.size_bytes", "receipt size differs")
    require(runtime_receipt["content_digest"] == intent["transport"]["content_digest"], "SEGMENT_CONTENT_MISMATCH", "$.receipt.runtime_receipt.content_digest", "receipt digest differs")


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
    for field in ("upload_id", "session_id", "scope_digest"):
        require(receipt[field] == request[field], "DIAGNOSTIC_BINDING_MISMATCH", f"$.receipt.{field}", "receipt differs from request")
    require(receipt["request_digest"] == request["request_digest"], "DIAGNOSTIC_BINDING_MISMATCH", "$.receipt.request_digest", "receipt does not bind request")
    envelope = request["envelope"]
    require(receipt["envelope_id"] == envelope["envelope_id"], "DIAGNOSTIC_BINDING_MISMATCH", "$.receipt.envelope_id", "receipt names another envelope")
    require(receipt["envelope_digest"] == envelope["envelope_digest"], "DIAGNOSTIC_BINDING_MISMATCH", "$.receipt.envelope_digest", "receipt does not bind envelope")
    require(receipt["size_bytes"] == request["transport"]["size_bytes"], "DIAGNOSTIC_BINDING_MISMATCH", "$.receipt.size_bytes", "durable size differs")
    require(receipt["transport_digest"] == request["transport"]["content_digest"], "DIAGNOSTIC_BINDING_MISMATCH", "$.receipt.transport_digest", "durable bytes differ")


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
    unique([receipt["segment_receipt_digest"] for receipt in segment_receipts], "$.segment_receipts")
    unique([receipt["diagnostic_receipt_digest"] for receipt in diagnostic_receipts], "$.diagnostic_receipts")
    require(
        [receipt["sequence"] for receipt in segment_receipts] == sorted(receipt["sequence"] for receipt in segment_receipts),
        "SEGMENT_RECEIPT_ORDER",
        "$.segment_receipts",
        "segment receipts must be ordered by sequence",
    )
    expected_runtime_receipts = manifest["upload"]["receipts"]
    actual_runtime_receipts = [receipt["runtime_receipt"] for receipt in segment_receipts]
    require(
        [canonical_json(item) for item in actual_runtime_receipts] == [canonical_json(item) for item in expected_runtime_receipts],
        "SEGMENT_RECEIPT_SET_MISMATCH",
        "$.segment_receipts",
        "protocol receipts must exactly cover manifest upload receipts",
    )
    requested = parse_time(value["requested_at"], "$.requested_at")
    require(
        requested >= parse_time(manifest["upload"]["completed_at"], "$.capture_manifest.upload.completed_at"),
        "INVALID_CHRONOLOGY",
        "$.requested_at",
        "completion predates media upload",
    )
    latest_diagnostic = max(parse_time(item["received_at"], "$.diagnostic_receipts[].received_at") for item in diagnostic_receipts)
    require(requested >= latest_diagnostic, "INVALID_CHRONOLOGY", "$.requested_at", "completion predates diagnostics upload")


def validate_completion_receipt(value: dict[str, Any]) -> None:
    job = value["processing_job"]
    runtime.validate(job)
    require(job["status"] == "queued", "JOB_NOT_QUEUED", "$.processing_job.status", "completion must durably create a queued job")
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
    deleted = parse_time(value["deleted_at"], "$.deleted_at")
    expires = parse_time(value["tombstone_expires_at"], "$.tombstone_expires_at")
    require(expires > deleted, "INVALID_TOMBSTONE_EXPIRY", "$.tombstone_expires_at", "tombstone expiry must follow deletion")
    require(
        expires <= deleted + timedelta(days=30),
        "TOMBSTONE_RETENTION_EXCEEDED",
        "$.tombstone_expires_at",
        "minimal deletion tombstones may not persist beyond 30 days",
    )


def validate_deletion_pair(request: dict[str, Any], tombstone: dict[str, Any]) -> None:
    validate(request)
    validate(tombstone)
    mappings = {
        "deletion_id": "deletion_id",
        "session_id": "session_id",
        "scope_digest": "scope_digest",
        "credential_id": "revoked_credential_id",
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
        parse_time(tombstone["deleted_at"], "$.tombstone.deleted_at") >= parse_time(request["requested_at"], "$.request.requested_at"),
        "INVALID_CHRONOLOGY",
        "$.tombstone.deleted_at",
        "deletion predates its request",
    )


def validate_idempotent_replay(original: dict[str, Any], replay: dict[str, Any]) -> None:
    """Require an operation-ID replay to be byte-semantically identical."""
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


def validate_bundle(
    build_identity: dict[str, Any],
    scope: dict[str, Any],
    launch_request: dict[str, Any],
    launch_receipt: dict[str, Any],
    segment_pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    diagnostic_pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    completion_request: dict[str, Any],
    completion_receipt: dict[str, Any],
    deletion_pair: tuple[dict[str, Any], dict[str, Any]] | None = None,
) -> None:
    """Validate one complete capture lifecycle across every protocol boundary."""
    validate(build_identity)
    validate(scope)
    validate_launch_pair(launch_request, launch_receipt)
    require(launch_request["build_identity"] == build_identity, "BUNDLE_SCOPE_MISMATCH", "$.launch_request.build_identity", "launch request changed build")
    require(launch_request["scope"] == scope, "BUNDLE_SCOPE_MISMATCH", "$.launch_request.scope", "launch request changed scope")
    require(scope["build_id"] == build_identity["build_id"], "BUNDLE_SCOPE_MISMATCH", "$.scope.build_id", "scope names another build")
    require(scope["build_identity_digest"] == build_identity["build_identity_digest"], "BUNDLE_SCOPE_MISMATCH", "$.scope.build_identity_digest", "scope does not bind build")

    for intent, receipt in segment_pairs:
        validate_segment_pair(intent, receipt)
    for request, receipt in diagnostic_pairs:
        validate_diagnostic_pair(request, receipt)
    validate_completion_pair(completion_request, completion_receipt)

    session_id = launch_receipt["session_id"]
    scope_digest = scope["scope_digest"]
    for value in [
        *(item for pair in segment_pairs for item in pair),
        *(item for pair in diagnostic_pairs for item in pair),
        completion_request,
        completion_receipt,
    ]:
        require(value["session_id"] == session_id, "BUNDLE_SCOPE_MISMATCH", "$.session_id", "message escaped launch session")
        require(value["scope_digest"] == scope_digest, "BUNDLE_SCOPE_MISMATCH", "$.scope_digest", "message escaped immutable scope")

    require(
        completion_request["segment_receipts"] == [receipt for _, receipt in segment_pairs],
        "BUNDLE_RECEIPT_MISMATCH",
        "$.completion_request.segment_receipts",
        "completion does not use exact media receipts",
    )
    require(
        completion_request["diagnostic_receipts"] == [receipt for _, receipt in diagnostic_pairs],
        "BUNDLE_RECEIPT_MISMATCH",
        "$.completion_request.diagnostic_receipts",
        "completion does not use exact diagnostic receipts",
    )
    scoped_runtime_values = [completion_request["capture_manifest"], completion_receipt["processing_job"]]
    scoped_runtime_values.extend(request["envelope"] for request, _ in diagnostic_pairs)
    for value in scoped_runtime_values:
        for field in ("organization_id", "project_id", "build_id", "build_identity_digest"):
            expected = scope[field]
            require(value[field] == expected, "BUNDLE_SCOPE_MISMATCH", f"$.runtime.{field}", "runtime artifact escaped immutable scope")
        require(value["session_id"] == session_id, "BUNDLE_SCOPE_MISMATCH", "$.runtime.session_id", "runtime artifact names another session")

    if deletion_pair is not None:
        request, tombstone = deletion_pair
        validate_deletion_pair(request, tombstone)
        require(request["session_id"] == session_id and request["scope_digest"] == scope_digest, "BUNDLE_SCOPE_MISMATCH", "$.deletion_request", "deletion escaped session scope")
        require(
            request["credential_id"] == launch_receipt["credential"]["credential_id"],
            "BUNDLE_CREDENTIAL_MISMATCH",
            "$.deletion_request.credential_id",
            "deletion revokes another credential",
        )
        require(
            parse_time(request["requested_at"], "$.deletion_request.requested_at") >= parse_time(completion_receipt["accepted_at"], "$.completion_receipt.accepted_at"),
            "INVALID_CHRONOLOGY",
            "$.deletion_request.requested_at",
            "deletion predates completion",
        )


def load_json(path: Path) -> dict[str, Any]:
    return runtime.load_json(path)
