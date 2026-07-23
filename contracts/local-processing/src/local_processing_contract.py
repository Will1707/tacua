# SPDX-License-Identifier: Apache-2.0
"""Dependency-free conformance validation for Tacua local processing wires.

This module validates inert JSON documents only.  It does not load a processor,
open evidence descriptors, claim a job, or authorize execution.  Embedded SDK
and runtime documents are delegated to their existing pure validators so this
package does not create a second definition of those contracts.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import re
import stat
import sys
import unicodedata
from pathlib import Path
from typing import Any


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_ROOT = PACKAGE_ROOT.parent
RUNTIME_SRC = CONTRACTS_ROOT / "runtime" / "src"
PROTOCOL_SRC = CONTRACTS_ROOT / "sdk-backend-protocol" / "src"
for source_root in (RUNTIME_SRC, PROTOCOL_SRC):
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))

import protocol_contract as protocol  # noqa: E402
import runtime_contract as runtime  # noqa: E402


COMMAND_V10 = "tacua.local-processing-command@1.0.0"
COMMAND_V11 = "tacua.local-processing-command@1.1.0"
INPUT_V10 = "tacua.local-processing-input@1.0.0"
INPUT_V11 = "tacua.local-processing-input@1.1.0"
RESULT_V10 = "tacua.local-processing-result@1.0.0"
RESULT_V11 = "tacua.local-processing-result@1.1.0"
ISOLATED_INPUT_V10 = "tacua.isolated-processing-input@1.0.0"
ISOLATED_OUTPUT_V10 = "tacua.isolated-processing-output@1.0.0"
PROCESSING_ARTIFACT_V10 = "tacua.processing-stage-artifact@1.0.0"
PROCESSING_ARTIFACT_MEDIA_TYPE = (
    "application/vnd.tacua.processing-stage-artifact+json;version=1.0.0"
)
TRANSCRIPT_V10 = "tacua.transcript@1.0.0"
LEGACY_PIPELINE_V10 = "tacua.pipeline@1.0.0"
ARTIFACT_PIPELINE_V11 = "tacua.pipeline@1.1.0"

INPUT_PLACEHOLDER = "{input}"
OUTPUT_DIRECTORY_PLACEHOLDER = "{output_directory}"
JOB_STAGES = ("transcribe", "align", "correlate", "research", "generate_tickets")
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_JSON_DEPTH = 64
MAX_JSON_VALUES = 1_000_000
MAX_COMMAND_BYTES = 65_536
MAX_ARGUMENTS = 64
MAX_ARGUMENT_BYTES = 32_768
MAX_LOCAL_DOCUMENT_BYTES = 16_777_216
MAX_INPUT_EVIDENCE_BYTES = 4_294_967_296
MAX_ISOLATED_OUTPUT_BYTES = 115_343_360
MAX_TRANSCRIPT_BYTES = 2_097_152
MAX_TRANSCRIPT_SPANS = 10_000
MAX_PROCESSING_ARTIFACT_BYTES = 4_194_304
MAX_PREVIEW_FILES = 512
MAX_PREVIEW_BYTES = 2_097_152
MAX_OUTPUT_BYTES = 67_108_864

ID_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
DESCRIPTOR_PATH_RE = re.compile(r"^/dev/fd/[0-9]+$")
ISOLATED_EVIDENCE_PATH_RE = re.compile(
    r"^(?P<root>/run/tacua-input|/tacua-private-[0-9]+-[a-f0-9]{24}/input)"
    r"/evidence/evidence-(?P<index>[0-9]{6})\.bin$"
)
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ARTIFACT_ID_RE = re.compile(r"^artifact_[A-Za-z0-9_-]{43}$")
LANGUAGE_TAG_RE = re.compile(
    r"^(?:und|[a-z]{2,3}(?:-[A-Z][a-z]{3})?(?:-(?:[A-Z]{2}|[0-9]{3}))?)$"
)
FORBIDDEN_INPUT_KEYS = frozenset({"credential_id", "launch_code", "lease_token", "secret"})


class ContractError(ValueError):
    """One stable, content-free conformance failure."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"{code}: local processing contract invalid")


def _fail(code: str) -> None:
    raise ContractError(code)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else canonical_bytes(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def digest_without(value: dict[str, Any], field: str) -> str:
    subject = copy.deepcopy(value)
    subject.pop(field, None)
    return digest(subject)


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _parse_integer(value: str) -> int:
    parsed = int(value)
    if not -MAX_SAFE_INTEGER <= parsed <= MAX_SAFE_INTEGER:
        raise ValueError("unsafe integer")
    return parsed


def _reject_float(_value: str) -> float:
    raise ValueError("floating point forbidden")


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite number forbidden")


def _validate_json_profile(value: Any) -> None:
    pending: list[tuple[Any, int]] = [(value, 0)]
    visited = 0
    while pending:
        current, depth = pending.pop()
        visited += 1
        if visited > MAX_JSON_VALUES or depth > MAX_JSON_DEPTH:
            _fail("JSON_STRUCTURE_LIMIT")
        if current is None or type(current) is bool:
            continue
        if type(current) is int:
            if not -MAX_SAFE_INTEGER <= current <= MAX_SAFE_INTEGER:
                _fail("JSON_UNSAFE_INTEGER")
            continue
        if type(current) is str:
            if unicodedata.normalize("NFC", current) != current or "\x00" in current:
                _fail("JSON_STRING_INVALID")
            try:
                current.encode("utf-8")
            except UnicodeError:
                _fail("JSON_STRING_INVALID")
            continue
        if type(current) is list:
            pending.extend((item, depth + 1) for item in current)
            continue
        if type(current) is dict:
            for key, child in current.items():
                if type(key) is not str:
                    _fail("JSON_OBJECT_INVALID")
                if unicodedata.normalize("NFC", key) != key or "\x00" in key:
                    _fail("JSON_STRING_INVALID")
                try:
                    key.encode("utf-8")
                except UnicodeError:
                    _fail("JSON_STRING_INVALID")
                pending.append((child, depth + 1))
            continue
        _fail("JSON_VALUE_INVALID")


def parse_canonical_bytes(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_ISOLATED_OUTPUT_BYTES:
        _fail("DOCUMENT_SIZE_INVALID")
    try:
        decoded = raw.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except (UnicodeError, ValueError, RecursionError, json.JSONDecodeError):
        _fail("JSON_INVALID")
    _validate_json_profile(value)
    if type(value) is not dict:
        _fail("DOCUMENT_NOT_OBJECT")
    if canonical_bytes(value) != raw:
        _fail("JSON_NOT_CANONICAL")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > MAX_ISOLATED_OUTPUT_BYTES
        ):
            _fail("DOCUMENT_SIZE_INVALID")
        with path.open("rb") as stream:
            raw = stream.read(MAX_ISOLATED_OUTPUT_BYTES + 1)
        if len(raw) > MAX_ISOLATED_OUTPUT_BYTES:
            _fail("DOCUMENT_SIZE_INVALID")
        return parse_canonical_bytes(raw)
    except ContractError:
        raise
    except OSError:
        _fail("DOCUMENT_UNAVAILABLE")


def _exact_object(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _fail(code)
    return value


def _require_id(value: Any, code: str = "IDENTITY_INVALID") -> str:
    if type(value) is not str or ID_RE.fullmatch(value) is None:
        _fail(code)
    return value


def _require_digest(value: Any, code: str = "DIGEST_INVALID") -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        _fail(code)
    return value


def _require_timestamp(value: Any, code: str = "TIMESTAMP_INVALID") -> str:
    if type(value) is not str:
        _fail(code)
    try:
        runtime.parse_time(value, "$")
    except (TypeError, ValueError):
        _fail(code)
    return value


def _require_positive_int(value: Any, maximum: int, code: str) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        _fail(code)
    return value


def _validate_no_authority(value: Any) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        if type(current) is dict:
            if FORBIDDEN_INPUT_KEYS & set(current):
                _fail("INPUT_AUTHORITY_FORBIDDEN")
            pending.extend(current.values())
        elif type(current) is list:
            pending.extend(current)


def validate_command(document: Any) -> None:
    _validate_json_profile(document)
    command = _exact_object(
        document,
        {
            "argv",
            "contract_version",
            "max_stderr_bytes",
            "max_stdout_bytes",
            "timeout_seconds",
        },
        "COMMAND_FIELDS_INVALID",
    )
    if (
        type(command["contract_version"]) is not str
        or command["contract_version"] not in (COMMAND_V10, COMMAND_V11)
    ):
        _fail("COMMAND_VERSION_UNSUPPORTED")
    argv = command["argv"]
    if (
        type(argv) is not list
        or not 3 <= len(argv) <= MAX_ARGUMENTS
        or any(type(argument) is not str or not argument for argument in argv)
        or sum(len(argument.encode("utf-8")) for argument in argv) > MAX_ARGUMENT_BYTES
        or argv.count(INPUT_PLACEHOLDER) != 1
        or argv.count(OUTPUT_DIRECTORY_PLACEHOLDER) != 1
        or any(
            ("{" in argument or "}" in argument)
            and argument not in {INPUT_PLACEHOLDER, OUTPUT_DIRECTORY_PLACEHOLDER}
            for argument in argv
        )
        or not argv[0].startswith("/")
    ):
        _fail("COMMAND_ARGV_INVALID")
    _require_positive_int(command["timeout_seconds"], 240, "COMMAND_LIMIT_INVALID")
    stdout_limit = command["max_stdout_bytes"]
    stderr_limit = command["max_stderr_bytes"]
    if (
        type(stdout_limit) is not int
        or not 1_024 <= stdout_limit <= 16_777_216
        or type(stderr_limit) is not int
        or not 1_024 <= stderr_limit <= 1_048_576
        or len(canonical_bytes(command)) > MAX_COMMAND_BYTES
    ):
        _fail("COMMAND_LIMIT_INVALID")


def _validate_binding(binding: Any) -> dict[str, Any]:
    result = _exact_object(
        binding,
        {
            "build_id",
            "build_identity_digest",
            "job_digest",
            "job_id",
            "job_version",
            "organization_id",
            "project_id",
            "session_id",
            "stage_name",
            "worker_id",
        },
        "INPUT_BINDING_FIELDS_INVALID",
    )
    for field in (
        "organization_id",
        "project_id",
        "session_id",
        "build_id",
        "job_id",
        "worker_id",
    ):
        _require_id(result[field], "INPUT_BINDING_INVALID")
    _require_digest(result["build_identity_digest"], "INPUT_BINDING_INVALID")
    _require_digest(result["job_digest"], "INPUT_BINDING_INVALID")
    _require_positive_int(result["job_version"], MAX_SAFE_INTEGER, "INPUT_BINDING_INVALID")
    if result["stage_name"] not in JOB_STAGES:
        _fail("INPUT_BINDING_INVALID")
    return result


def _validate_evidence_path(
    path: Any,
    *,
    isolated: bool,
    expected_index: int | None = None,
) -> str | None:
    if type(path) is not str:
        _fail("INPUT_EVIDENCE_PATH_INVALID")
    if not isolated:
        if DESCRIPTOR_PATH_RE.fullmatch(path) is None:
            _fail("INPUT_EVIDENCE_PATH_INVALID")
        return None
    match = ISOLATED_EVIDENCE_PATH_RE.fullmatch(path)
    if (
        match is None
        or expected_index is None
        or int(match.group("index")) != expected_index
    ):
        _fail("INPUT_EVIDENCE_PATH_INVALID")
    return match.group("root")


def _validate_capture(
    capture: Any,
    binding: dict[str, Any],
    job: dict[str, Any],
    *,
    isolated: bool,
) -> None:
    value = _exact_object(
        capture,
        {
            "build_identity",
            "derived_data_expires_at",
            "diagnostics",
            "manifest",
            "raw_media_expires_at",
            "segments",
            "session_completed_at",
            "session_created_at",
        },
        "INPUT_CAPTURE_FIELDS_INVALID",
    )
    if type(value["build_identity"]) is not dict or type(value["manifest"]) is not dict:
        _fail("INPUT_NESTED_CONTRACT_INVALID")
    try:
        protocol.validate(value["build_identity"])
        runtime.validate(value["manifest"])
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        _fail("INPUT_NESTED_CONTRACT_INVALID")
    build = value["build_identity"]
    manifest = value["manifest"]
    expected_scope = {
        "organization_id": binding["organization_id"],
        "project_id": binding["project_id"],
        "session_id": binding["session_id"],
        "build_id": binding["build_id"],
        "build_identity_digest": binding["build_identity_digest"],
    }
    if any(manifest.get(field) != expected for field, expected in expected_scope.items()):
        _fail("INPUT_CAPTURE_BINDING_MISMATCH")
    if (
        build.get("build_id") != binding["build_id"]
        or build.get("build_identity_digest") != binding["build_identity_digest"]
        or job["inputs"]["capture_manifest_digest"] != manifest.get("manifest_digest")
        or manifest.get("capture_state") != "complete"
        or manifest.get("upload", {}).get("state") != "complete"
        or manifest.get("upload", {}).get("remote_session_id")
        != binding["session_id"]
        or manifest.get("retention", {}).get("policy_version")
        != "tacua.retention@1.0.0"
        or manifest.get("retention", {}).get("deletion_status") != "active"
        or value["raw_media_expires_at"] != manifest["retention"]["raw_media_expires_at"]
        or value["derived_data_expires_at"]
        != manifest["retention"]["derived_data_expires_at"]
    ):
        _fail("INPUT_CAPTURE_BINDING_MISMATCH")
    for field in (
        "session_created_at",
        "session_completed_at",
        "raw_media_expires_at",
        "derived_data_expires_at",
    ):
        _require_timestamp(value[field], "INPUT_CAPTURE_TIME_INVALID")
    created_at = runtime.parse_time(value["session_created_at"], "$")
    completed_at = runtime.parse_time(value["session_completed_at"], "$")
    raw_expiry = runtime.parse_time(value["raw_media_expires_at"], "$")
    derived_expiry = runtime.parse_time(value["derived_data_expires_at"], "$")
    capture_started_at = runtime.parse_time(manifest["started_at"], "$")
    capture_ended_at = runtime.parse_time(manifest["ended_at"], "$")
    upload_completed_at = runtime.parse_time(manifest["upload"]["completed_at"], "$")
    retention_delta = raw_expiry - created_at
    if (
        value["session_completed_at"] != job["requested_at"]
        or not created_at
        <= capture_started_at
        <= capture_ended_at
        <= upload_completed_at
        <= completed_at
        or completed_at >= raw_expiry
        or raw_expiry != derived_expiry
        or retention_delta.seconds != 0
        or retention_delta.microseconds != 0
        or not 1 <= retention_delta.days <= 30
    ):
        _fail("INPUT_CAPTURE_TIME_INVALID")

    segments = value["segments"]
    if type(segments) is not list or len(segments) > 512:
        _fail("INPUT_SEGMENTS_INVALID")
    available = [item for item in manifest["segments"] if item["availability"] == "available"]
    receipts = {
        item["segment_id"]: item for item in manifest["upload"]["receipts"]
    }
    if len(segments) != len(available):
        _fail("INPUT_SEGMENTS_INVALID")
    paths: set[str] = set()
    total_evidence_bytes = 0
    isolated_root: str | None = None
    evidence_index = 0
    for segment, source in zip(segments, available, strict=True):
        item = _exact_object(
            segment,
            {
                "content_digest",
                "content_type",
                "read_only_path",
                "received_at",
                "segment_id",
                "sequence",
                "sidecar_digest",
                "size_bytes",
            },
            "INPUT_SEGMENT_FIELDS_INVALID",
        )
        root = _validate_evidence_path(
            item["read_only_path"],
            isolated=isolated,
            expected_index=evidence_index if isolated else None,
        )
        if root is not None:
            if isolated_root is not None and root != isolated_root:
                _fail("INPUT_EVIDENCE_PATH_INVALID")
            isolated_root = root
        evidence_index += 1
        if item["read_only_path"] in paths:
            _fail("INPUT_EVIDENCE_PATH_INVALID")
        paths.add(item["read_only_path"])
        _require_id(item["segment_id"], "INPUT_SEGMENT_INVALID")
        _require_timestamp(item["received_at"], "INPUT_SEGMENT_INVALID")
        receipt = receipts.get(item["segment_id"])
        if (
            type(receipt) is not dict
            or
            item["segment_id"] != source["segment_id"]
            or item["sequence"] != source["sequence"]
            or item["content_type"] != source["content"]["content_type"]
            or item["size_bytes"] != source["content"]["size_bytes"]
            or item["content_digest"] != source["content"]["content_digest"]
            or item["sidecar_digest"] != source["content"]["sidecar_digest"]
            or type(item["size_bytes"]) is not int
            or item["size_bytes"] < 1
            or item["received_at"] != receipt["received_at"]
        ):
            _fail("INPUT_SEGMENT_INVALID")
        _require_digest(item["content_digest"], "INPUT_SEGMENT_INVALID")
        _require_digest(item["sidecar_digest"], "INPUT_SEGMENT_INVALID")
        received_at = runtime.parse_time(item["received_at"], "$")
        if not created_at <= received_at <= upload_completed_at:
            _fail("INPUT_SEGMENT_INVALID")
        total_evidence_bytes += item["size_bytes"]

    diagnostics = value["diagnostics"]
    if type(diagnostics) is not list or len(segments) + len(diagnostics) > 512:
        _fail("INPUT_DIAGNOSTICS_INVALID")
    envelope_digests: list[str] = []
    envelope_ids: set[str] = set()
    previous_diagnostic_received_at = None
    for diagnostic in diagnostics:
        item = _exact_object(
            diagnostic,
            {
                "content_digest",
                "envelope_digest",
                "envelope_id",
                "read_only_path",
                "received_at",
                "size_bytes",
            },
            "INPUT_DIAGNOSTIC_FIELDS_INVALID",
        )
        _require_id(item["envelope_id"], "INPUT_DIAGNOSTIC_INVALID")
        _require_digest(item["envelope_digest"], "INPUT_DIAGNOSTIC_INVALID")
        _require_digest(item["content_digest"], "INPUT_DIAGNOSTIC_INVALID")
        _require_timestamp(item["received_at"], "INPUT_DIAGNOSTIC_INVALID")
        root = _validate_evidence_path(
            item["read_only_path"],
            isolated=isolated,
            expected_index=evidence_index if isolated else None,
        )
        if root is not None:
            if isolated_root is not None and root != isolated_root:
                _fail("INPUT_EVIDENCE_PATH_INVALID")
            isolated_root = root
        evidence_index += 1
        if (
            item["read_only_path"] in paths
            or item["envelope_id"] in envelope_ids
            or type(item["size_bytes"]) is not int
            or not 1 <= item["size_bytes"] <= 1_073_741_824
        ):
            _fail("INPUT_DIAGNOSTIC_INVALID")
        paths.add(item["read_only_path"])
        envelope_ids.add(item["envelope_id"])
        envelope_digests.append(item["envelope_digest"])
        received_at = runtime.parse_time(item["received_at"], "$")
        if (
            not created_at <= received_at <= completed_at
            or previous_diagnostic_received_at is not None
            and received_at < previous_diagnostic_received_at
        ):
            _fail("INPUT_DIAGNOSTIC_INVALID")
        previous_diagnostic_received_at = received_at
        total_evidence_bytes += item["size_bytes"]
    if sorted(envelope_digests) != sorted(job["inputs"]["diagnostic_envelope_digests"]):
        _fail("INPUT_DIAGNOSTIC_BINDING_MISMATCH")
    if total_evidence_bytes > MAX_INPUT_EVIDENCE_BYTES:
        _fail("INPUT_EVIDENCE_SIZE_INVALID")


def _expected_transcript_sources(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "content_digest": segment["content"]["content_digest"],
            "end_ms": segment["time_range"]["end_ms"],
            "segment_id": segment["segment_id"],
            "sequence": segment["sequence"],
            "start_ms": segment["time_range"]["start_ms"],
        }
        for segment in manifest["segments"]
        if segment["availability"] == "available"
    ]


def _validate_transcript_payload(
    payload: Any, expected_sources: list[dict[str, Any]] | None
) -> None:
    value = _exact_object(
        payload,
        {"contract_version", "language_tag", "source_segments", "spans", "speech_status"},
        "TRANSCRIPT_FIELDS_INVALID",
    )
    sources = value["source_segments"]
    spans = value["spans"]
    if (
        value["contract_version"] != TRANSCRIPT_V10
        or type(value["language_tag"]) is not str
        or LANGUAGE_TAG_RE.fullmatch(value["language_tag"]) is None
        or type(value["speech_status"]) is not str
        or value["speech_status"] not in ("detected", "not_detected")
        or type(sources) is not list
        or type(spans) is not list
        or len(spans) > MAX_TRANSCRIPT_SPANS
        or (expected_sources is not None and sources != expected_sources)
    ):
        _fail("TRANSCRIPT_INVALID")
    source_by_id: dict[str, dict[str, Any]] = {}
    for source in sources:
        item = _exact_object(
            source,
            {"content_digest", "end_ms", "segment_id", "sequence", "start_ms"},
            "TRANSCRIPT_SOURCE_INVALID",
        )
        _require_id(item["segment_id"], "TRANSCRIPT_SOURCE_INVALID")
        _require_digest(item["content_digest"], "TRANSCRIPT_SOURCE_INVALID")
        if (
            item["segment_id"] in source_by_id
            or type(item["sequence"]) is not int
            or type(item["start_ms"]) is not int
            or type(item["end_ms"]) is not int
            or item["sequence"] < 0
            or item["start_ms"] < 0
            or item["end_ms"] <= item["start_ms"]
        ):
            _fail("TRANSCRIPT_SOURCE_INVALID")
        source_by_id[item["segment_id"]] = item
    if sources != sorted(sources, key=lambda item: item["sequence"]):
        _fail("TRANSCRIPT_SOURCE_INVALID")

    ordering: list[tuple[int, int, str]] = []
    previous_end: int | None = None
    text_bytes = 0
    for span in spans:
        item = _exact_object(
            span,
            {"end_ms", "segment_id", "start_ms", "text"},
            "TRANSCRIPT_SPAN_INVALID",
        )
        if (
            type(item["segment_id"]) is not str
            or ID_RE.fullmatch(item["segment_id"]) is None
        ):
            _fail("TRANSCRIPT_SPAN_INVALID")
        source = source_by_id.get(item["segment_id"])
        if (
            source is None
            or type(item["start_ms"]) is not int
            or type(item["end_ms"]) is not int
            or item["start_ms"] < source["start_ms"]
            or item["end_ms"] > source["end_ms"]
            or item["end_ms"] <= item["start_ms"]
            or type(item["text"]) is not str
            or not item["text"].strip()
        ):
            _fail("TRANSCRIPT_SPAN_INVALID")
        if previous_end is not None and item["start_ms"] < previous_end:
            _fail("TRANSCRIPT_SPAN_INVALID")
        previous_end = item["end_ms"]
        ordering.append((item["start_ms"], item["end_ms"], item["segment_id"]))
        text_bytes += len(item["text"].encode("utf-8"))
        if text_bytes > MAX_TRANSCRIPT_BYTES:
            _fail("TRANSCRIPT_SIZE_INVALID")
    if ordering != sorted(ordering):
        _fail("TRANSCRIPT_SPAN_INVALID")
    if (value["speech_status"] == "detected") != bool(spans):
        _fail("TRANSCRIPT_STATUS_INVALID")
    if value["speech_status"] == "not_detected" and value["language_tag"] != "und":
        _fail("TRANSCRIPT_STATUS_INVALID")


def _expected_artifact_id(job_id: str) -> str:
    subject = (
        "tacua.processing-stage-artifact-id@1.0.0\0"
        f"{job_id}\0transcribe\0transcript"
    ).encode("utf-8")
    token = base64.urlsafe_b64encode(hashlib.sha256(subject).digest()).decode("ascii")
    return "artifact_" + token.rstrip("=")


def _validate_stage_artifact(
    artifact: Any,
    *,
    binding: dict[str, Any],
    job: dict[str, Any],
    expected_sources: list[dict[str, Any]],
    derived_data_expires_at: str,
) -> None:
    value = _exact_object(
        artifact,
        {
            "artifact_digest",
            "artifact_id",
            "artifact_kind",
            "checkpoint_job_version",
            "contract_version",
            "created_at",
            "derived_data_expires_at",
            "job_id",
            "media_type",
            "organization_id",
            "payload",
            "project_id",
            "session_id",
            "stage_name",
        },
        "STAGE_ARTIFACT_FIELDS_INVALID",
    )
    _require_digest(value["artifact_digest"], "STAGE_ARTIFACT_INVALID")
    _require_timestamp(value["created_at"], "STAGE_ARTIFACT_INVALID")
    _require_timestamp(value["derived_data_expires_at"], "STAGE_ARTIFACT_INVALID")
    transcribe_stage = job["pipeline"]["stages"][0]
    expected = {
        "contract_version": PROCESSING_ARTIFACT_V10,
        "media_type": PROCESSING_ARTIFACT_MEDIA_TYPE,
        "artifact_id": _expected_artifact_id(binding["job_id"]),
        "artifact_kind": "transcript",
        "organization_id": binding["organization_id"],
        "project_id": binding["project_id"],
        "session_id": binding["session_id"],
        "job_id": binding["job_id"],
        "stage_name": "transcribe",
        "checkpoint_job_version": 3 * transcribe_stage["attempt_count"],
        "derived_data_expires_at": derived_data_expires_at,
    }
    if (
        any(value.get(field) != expected_value for field, expected_value in expected.items())
        or binding["job_version"] < 4
        or type(value["checkpoint_job_version"]) is not int
        or value["checkpoint_job_version"] < 2
        or value["checkpoint_job_version"] >= binding["job_version"]
        or transcribe_stage["state"] != "succeeded"
        or value["created_at"] != transcribe_stage["completed_at"]
        or ARTIFACT_ID_RE.fullmatch(str(value["artifact_id"])) is None
        or value["artifact_digest"] != digest_without(value, "artifact_digest")
        or len(canonical_bytes(value)) > MAX_PROCESSING_ARTIFACT_BYTES
    ):
        _fail("STAGE_ARTIFACT_INVALID")
    try:
        if runtime.parse_time(value["created_at"], "$") >= runtime.parse_time(
            value["derived_data_expires_at"], "$"
        ):
            _fail("STAGE_ARTIFACT_INVALID")
    except (TypeError, ValueError):
        _fail("STAGE_ARTIFACT_INVALID")
    _validate_transcript_payload(value["payload"], expected_sources)


def _validate_local_input(
    document: Any,
    *,
    verify_digest: bool,
    isolated: bool,
) -> None:
    _validate_json_profile(document)
    if type(document) is not dict:
        _fail("INPUT_FIELDS_INVALID")
    version = document.get("contract_version")
    expected_fields = {"binding", "capture", "contract_version", "input_digest", "job"}
    if version == INPUT_V11:
        expected_fields.add("stage_inputs")
    elif version != INPUT_V10:
        _fail("INPUT_VERSION_UNSUPPORTED")
    _exact_object(document, expected_fields, "INPUT_FIELDS_INVALID")
    _require_digest(document["input_digest"], "INPUT_DIGEST_INVALID")
    if verify_digest and document["input_digest"] != digest_without(document, "input_digest"):
        _fail("INPUT_DIGEST_MISMATCH")
    binding = _validate_binding(document["binding"])
    job = document["job"]
    if type(job) is not dict:
        _fail("INPUT_JOB_INVALID")
    try:
        runtime.validate(job)
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        _fail("INPUT_JOB_INVALID")
    expected_pipeline = LEGACY_PIPELINE_V10 if version == INPUT_V10 else ARTIFACT_PIPELINE_V11
    expected_execution = {
        "egress": {
            "authorization_decision_id": None,
            "authorized": False,
            "destinations": [],
            "policy": "default_deny",
        },
        "max_attempts": 3,
        "mode": "async",
    }
    if (
        job["pipeline"]["pipeline_version"] != expected_pipeline
        or job["execution"] != expected_execution
        or job["status"] != "running"
        or job["organization_id"] != binding["organization_id"]
        or job["project_id"] != binding["project_id"]
        or job["session_id"] != binding["session_id"]
        or job["build_id"] != binding["build_id"]
        or job["build_identity_digest"] != binding["build_identity_digest"]
        or job["job_id"] != binding["job_id"]
        or job["job_version"] != binding["job_version"]
        or job["job_digest"] != binding["job_digest"]
    ):
        _fail("INPUT_JOB_BINDING_MISMATCH")
    stages = job["pipeline"]["stages"]
    current = JOB_STAGES.index(binding["stage_name"])
    maximum_attempts = job["execution"]["max_attempts"]
    active = stages[current]
    pristine_future = [
        {
            "attempt_count": 0,
            "completed_at": None,
            "detail": None,
            "name": JOB_STAGES[index],
            "started_at": None,
            "state": "pending",
        }
        for index in range(current + 1, len(JOB_STAGES))
    ]
    if (
        [stage["name"] for stage in stages] != list(JOB_STAGES)
        or job["started_at"] is None
        or job["completed_at"] is not None
        or job["outputs"] is not None
        or job["failure"] is not None
        or active["state"] != "running"
        or not 1 <= active["attempt_count"] <= maximum_attempts
        or active["started_at"] is None
        or active["completed_at"] is not None
        or active["detail"] is not None
        or any(
            stage["state"] != "succeeded"
            or not 1 <= stage["attempt_count"] <= maximum_attempts
            or stage["started_at"] is None
            or stage["completed_at"] is None
            for stage in stages[:current]
        )
        or stages[current + 1 :] != pristine_future
    ):
        _fail("INPUT_STAGE_BINDING_MISMATCH")
    expected_job_version = 1 + sum(
        3 * stage["attempt_count"] - 1 for stage in stages[:current]
    ) + (3 * active["attempt_count"] - 2)
    requested_at = runtime.parse_time(job["requested_at"], "$")
    root_started_at = runtime.parse_time(job["started_at"], "$")
    previous_completed_at = root_started_at
    if job["job_version"] != expected_job_version or root_started_at < requested_at:
        _fail("INPUT_STAGE_BINDING_MISMATCH")
    for stage in stages[:current]:
        stage_started_at = runtime.parse_time(stage["started_at"], "$")
        stage_completed_at = runtime.parse_time(stage["completed_at"], "$")
        if (
            stage_started_at < previous_completed_at
            or stage_completed_at < stage_started_at
        ):
            _fail("INPUT_STAGE_BINDING_MISMATCH")
        previous_completed_at = stage_completed_at
    if runtime.parse_time(active["started_at"], "$") < previous_completed_at:
        _fail("INPUT_STAGE_BINDING_MISMATCH")
    _validate_capture(document["capture"], binding, job, isolated=isolated)

    if version == INPUT_V11:
        stage_inputs = _exact_object(
            document["stage_inputs"], {"artifacts"}, "STAGE_INPUT_FIELDS_INVALID"
        )
        artifacts = stage_inputs["artifacts"]
        expected_count = 0 if binding["stage_name"] == "transcribe" else 1
        if (
            binding["stage_name"] not in {"transcribe", "align"}
            or type(artifacts) is not list
            or len(artifacts) != expected_count
        ):
            _fail("STAGE_INPUT_INVALID")
        if artifacts:
            _validate_stage_artifact(
                artifacts[0],
                binding=binding,
                job=job,
                expected_sources=_expected_transcript_sources(document["capture"]["manifest"]),
                derived_data_expires_at=document["capture"]["derived_data_expires_at"],
            )
    _validate_no_authority(document)
    if len(canonical_bytes(document)) > MAX_LOCAL_DOCUMENT_BYTES:
        _fail("INPUT_SIZE_INVALID")


def validate_local_input(document: Any) -> None:
    _validate_local_input(document, verify_digest=True, isolated=False)


def _validate_artifact_draft(
    value: Any, expected_sources: list[dict[str, Any]] | None
) -> None:
    draft = _exact_object(value, {"artifact_kind", "payload"}, "ARTIFACT_DRAFT_FIELDS_INVALID")
    if draft["artifact_kind"] != "transcript":
        _fail("ARTIFACT_DRAFT_INVALID")
    _validate_transcript_payload(draft["payload"], expected_sources)


def _prospective_stage_artifact_size(
    draft: dict[str, Any], source_input: dict[str, Any]
) -> int:
    binding = source_input["binding"]
    artifact = {
        "artifact_digest": "sha256:" + "0" * 64,
        "artifact_id": _expected_artifact_id(binding["job_id"]),
        "artifact_kind": "transcript",
        "checkpoint_job_version": binding["job_version"] + 1,
        "contract_version": PROCESSING_ARTIFACT_V10,
        "created_at": "2000-01-01T00:00:00Z",
        "derived_data_expires_at": source_input["capture"][
            "derived_data_expires_at"
        ],
        "job_id": binding["job_id"],
        "media_type": PROCESSING_ARTIFACT_MEDIA_TYPE,
        "organization_id": binding["organization_id"],
        "payload": draft["payload"],
        "project_id": binding["project_id"],
        "session_id": binding["session_id"],
        "stage_name": "transcribe",
    }
    return len(canonical_bytes(artifact))


def _validate_consumed_reference(value: Any) -> None:
    reference = _exact_object(
        value, {"artifact_digest", "artifact_id"}, "CONSUMED_REFERENCE_FIELDS_INVALID"
    )
    if (
        type(reference["artifact_id"]) is not str
        or ARTIFACT_ID_RE.fullmatch(reference["artifact_id"]) is None
    ):
        _fail("CONSUMED_REFERENCE_INVALID")
    _require_digest(reference["artifact_digest"], "CONSUMED_REFERENCE_INVALID")


def _validate_result_binding(document: dict[str, Any]) -> None:
    for field in ("job_id", "session_id"):
        _require_id(document[field], "RESULT_BINDING_INVALID")
    _require_digest(document["input_digest"], "RESULT_BINDING_INVALID")
    _require_digest(document["job_digest"], "RESULT_BINDING_INVALID")
    if document["stage_name"] not in JOB_STAGES:
        _fail("RESULT_BINDING_INVALID")


def _validate_preview_reference(value: Any) -> tuple[str, int, str]:
    preview = _exact_object(
        value,
        {
            "body_file",
            "content_digest",
            "content_type",
            "evidence_id",
            "preview_revision_id",
            "size_bytes",
        },
        "PREVIEW_REFERENCE_FIELDS_INVALID",
    )
    _require_id(preview["evidence_id"], "PREVIEW_REFERENCE_INVALID")
    _require_id(preview["preview_revision_id"], "PREVIEW_REFERENCE_INVALID")
    _require_digest(preview["content_digest"], "PREVIEW_REFERENCE_INVALID")
    if (
        type(preview["body_file"]) is not str
        or SAFE_NAME_RE.fullmatch(preview["body_file"]) is None
        or type(preview["content_type"]) is not str
        or not 1 <= len(preview["content_type"]) <= 128
        or type(preview["size_bytes"]) is not int
        or not 1 <= preview["size_bytes"] <= MAX_PREVIEW_BYTES
    ):
        _fail("PREVIEW_REFERENCE_INVALID")
    return (
        preview["body_file"],
        preview["size_bytes"],
        preview["content_digest"],
    )


def _validate_terminal_result(result: Any) -> None:
    value = _exact_object(
        result, {"candidates", "disposition", "summary"}, "TERMINAL_RESULT_FIELDS_INVALID"
    )
    if (
        type(value["disposition"]) is not str
        or value["disposition"] not in ("candidates_created", "no_issue_detected")
        or type(value["summary"]) is not str
        or not 1 <= len(value["summary"]) <= 4096
        or type(value["candidates"]) is not list
        or len(value["candidates"]) > 256
        or (value["disposition"] == "candidates_created") != bool(value["candidates"])
    ):
        _fail("TERMINAL_RESULT_INVALID")
    preview_names: set[str] = set()
    preview_count = 0
    preview_bytes = 0
    for bundle in value["candidates"]:
        candidate = _exact_object(
            bundle,
            {"candidate", "evidence_manifest", "previews"},
            "CANDIDATE_BUNDLE_FIELDS_INVALID",
        )
        if (
            type(candidate["candidate"]) is not dict
            or type(candidate["evidence_manifest"]) is not dict
            or type(candidate["previews"]) is not list
            or len(candidate["previews"]) > 100
        ):
            _fail("CANDIDATE_BUNDLE_INVALID")
        for preview in candidate["previews"]:
            name, size, _content_digest = _validate_preview_reference(preview)
            if name in preview_names:
                _fail("PREVIEW_REFERENCE_INVALID")
            preview_names.add(name)
            preview_count += 1
            preview_bytes += size
            if preview_count > MAX_PREVIEW_FILES or preview_bytes > MAX_OUTPUT_BYTES:
                _fail("PREVIEW_REFERENCE_LIMIT")


def validate_local_result(document: Any, source_input: dict[str, Any] | None = None) -> None:
    _validate_json_profile(document)
    if len(canonical_bytes(document)) > MAX_LOCAL_DOCUMENT_BYTES:
        _fail("RESULT_SIZE_INVALID")
    result = _exact_object(
        document,
        {
            "contract_version",
            "disposition",
            "input_digest",
            "job_digest",
            "job_id",
            "result",
            "session_id",
            "stage_name",
        },
        "RESULT_FIELDS_INVALID",
    )
    version = result["contract_version"]
    if type(version) is not str or version not in (RESULT_V10, RESULT_V11):
        _fail("RESULT_VERSION_UNSUPPORTED")
    _validate_result_binding(result)
    if source_input is not None:
        input_version = source_input.get("contract_version")
        expected_version = RESULT_V10 if input_version == INPUT_V10 else RESULT_V11
        binding = source_input["binding"]
        if (
            version != expected_version
            or result["input_digest"] != source_input["input_digest"]
            or result["job_id"] != binding["job_id"]
            or result["job_digest"] != binding["job_digest"]
            or result["session_id"] != binding["session_id"]
            or result["stage_name"] != binding["stage_name"]
        ):
            _fail("RESULT_BINDING_MISMATCH")

    if version == RESULT_V11:
        if (
            result["stage_name"] not in {"transcribe", "align"}
            or result["disposition"] != "checkpoint"
        ):
            _fail("RESULT_STAGE_INVALID")
        checkpoint = _exact_object(
            result["result"], {"artifacts", "consumed_artifacts"}, "CHECKPOINT_FIELDS_INVALID"
        )
        artifacts = checkpoint["artifacts"]
        consumed = checkpoint["consumed_artifacts"]
        if type(artifacts) is not list or type(consumed) is not list:
            _fail("CHECKPOINT_INVALID")
        expected_sources = None
        if source_input is not None:
            expected_sources = _expected_transcript_sources(source_input["capture"]["manifest"])
        for artifact in artifacts:
            _validate_artifact_draft(artifact, expected_sources)
        for reference in consumed:
            _validate_consumed_reference(reference)
        if result["stage_name"] == "transcribe":
            if len(artifacts) != 1 or consumed:
                _fail("CHECKPOINT_STAGE_INVALID")
            if source_input is not None and source_input["stage_inputs"]["artifacts"]:
                _fail("CHECKPOINT_STAGE_INVALID")
            if (
                source_input is not None
                and _prospective_stage_artifact_size(artifacts[0], source_input)
                > MAX_PROCESSING_ARTIFACT_BYTES
            ):
                _fail("ARTIFACT_DRAFT_SIZE_INVALID")
        else:
            if artifacts or len(consumed) != 1:
                _fail("CHECKPOINT_STAGE_INVALID")
            if source_input is not None:
                stage_artifacts = source_input["stage_inputs"]["artifacts"]
                expected = [
                    {
                        "artifact_digest": artifact["artifact_digest"],
                        "artifact_id": artifact["artifact_id"],
                    }
                    for artifact in stage_artifacts
                ]
                if consumed != expected:
                    _fail("CHECKPOINT_CONSUMPTION_MISMATCH")
        return

    final_stage = result["stage_name"] == "generate_tickets"
    if not final_stage:
        if result["disposition"] != "checkpoint" or result["result"] is not None:
            _fail("RESULT_STAGE_INVALID")
    else:
        if result["disposition"] != "terminal":
            _fail("RESULT_STAGE_INVALID")
        _validate_terminal_result(result["result"])


def validate_exchange(source_input: Any, result: Any, *, isolated_source: bool = False) -> None:
    _validate_local_input(
        source_input,
        verify_digest=not isolated_source,
        isolated=isolated_source,
    )
    validate_local_result(result, source_input)


def validate_command_exchange(command: Any, source_input: Any, result: Any) -> None:
    validate_command(command)
    validate_exchange(source_input, result)
    if (
        source_input["contract_version"] == INPUT_V11
        and command["contract_version"] != COMMAND_V11
    ):
        _fail("COMMAND_INPUT_VERSION_MISMATCH")
    if len(canonical_bytes(result)) > command["max_stdout_bytes"]:
        _fail("COMMAND_RESULT_SIZE_MISMATCH")


def validate_isolated_input(document: Any) -> None:
    _validate_json_profile(document)
    wrapper = _exact_object(
        document,
        {"contract_version", "isolated_input_digest", "source_input", "source_input_digest"},
        "ISOLATED_INPUT_FIELDS_INVALID",
    )
    if wrapper["contract_version"] != ISOLATED_INPUT_V10:
        _fail("ISOLATED_INPUT_VERSION_UNSUPPORTED")
    _require_digest(wrapper["isolated_input_digest"], "ISOLATED_INPUT_DIGEST_INVALID")
    _require_digest(wrapper["source_input_digest"], "ISOLATED_SOURCE_DIGEST_INVALID")
    if (
        wrapper["isolated_input_digest"] != digest_without(wrapper, "isolated_input_digest")
        or type(wrapper["source_input"]) is not dict
        or wrapper["source_input_digest"] != wrapper["source_input"].get("input_digest")
    ):
        _fail("ISOLATED_INPUT_DIGEST_MISMATCH")
    _validate_local_input(
        wrapper["source_input"],
        verify_digest=False,
        isolated=True,
    )
    if len(canonical_bytes(wrapper)) > MAX_LOCAL_DOCUMENT_BYTES:
        _fail("ISOLATED_INPUT_SIZE_INVALID")


def _referenced_previews(
    result: dict[str, Any], *, isolated: bool
) -> dict[str, tuple[int, str]]:
    references: dict[str, tuple[int, str]] = {}
    terminal = result.get("result")
    if type(terminal) is not dict or type(terminal.get("candidates")) is not list:
        return references
    for bundle in terminal["candidates"]:
        previews = bundle.get("previews") if type(bundle) is dict else None
        if type(previews) is not list:
            _fail("ISOLATED_PREVIEW_REFERENCE_INVALID")
        for preview in previews:
            try:
                name, size, content_digest = _validate_preview_reference(preview)
            except ContractError:
                _fail("ISOLATED_PREVIEW_REFERENCE_INVALID")
            if (isolated and name == "result.json") or name in references:
                _fail("ISOLATED_PREVIEW_REFERENCE_INVALID")
            references[name] = (size, content_digest)
    return references


def validate_isolated_output(document: Any, source_input: dict[str, Any] | None = None) -> None:
    _validate_json_profile(document)
    if len(canonical_bytes(document)) > MAX_ISOLATED_OUTPUT_BYTES:
        _fail("ISOLATED_OUTPUT_SIZE_INVALID")
    envelope = _exact_object(
        document,
        {"contract_version", "previews", "result", "result_digest"},
        "ISOLATED_OUTPUT_FIELDS_INVALID",
    )
    if envelope["contract_version"] != ISOLATED_OUTPUT_V10:
        _fail("ISOLATED_OUTPUT_VERSION_UNSUPPORTED")
    if type(envelope["result"]) is not dict or type(envelope["previews"]) is not list:
        _fail("ISOLATED_OUTPUT_INVALID")
    _require_digest(envelope["result_digest"], "ISOLATED_RESULT_DIGEST_INVALID")
    if envelope["result_digest"] != digest(envelope["result"]):
        _fail("ISOLATED_RESULT_DIGEST_MISMATCH")
    validate_local_result(envelope["result"], source_input)
    references = _referenced_previews(envelope["result"], isolated=True)
    names: list[str] = []
    total = len(canonical_bytes(envelope["result"]))
    previews = envelope["previews"]
    if len(previews) > MAX_PREVIEW_FILES:
        _fail("ISOLATED_PREVIEW_LIMIT")
    for preview in previews:
        item = _exact_object(
            preview,
            {"content_base64", "content_digest", "name", "size_bytes"},
            "ISOLATED_PREVIEW_FIELDS_INVALID",
        )
        name = item["name"]
        size = item["size_bytes"]
        content_digest = item["content_digest"]
        encoded = item["content_base64"]
        if (
            type(name) is not str
            or SAFE_NAME_RE.fullmatch(name) is None
            or name == "result.json"
            or type(size) is not int
            or not 1 <= size <= MAX_PREVIEW_BYTES
            or type(encoded) is not str
            or not encoded.isascii()
            or references.get(name) != (size, content_digest)
        ):
            _fail("ISOLATED_PREVIEW_INVALID")
        _require_digest(content_digest, "ISOLATED_PREVIEW_INVALID")
        try:
            body = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            _fail("ISOLATED_PREVIEW_INVALID")
        if (
            base64.b64encode(body).decode("ascii") != encoded
            or len(body) != size
            or digest(body) != content_digest
        ):
            _fail("ISOLATED_PREVIEW_INVALID")
        names.append(name)
        total += len(body)
        if total > MAX_OUTPUT_BYTES:
            _fail("ISOLATED_OUTPUT_LIMIT")
    if names != sorted(names) or len(set(names)) != len(names) or set(names) != set(references):
        _fail("ISOLATED_PREVIEW_SET_MISMATCH")


def validate_isolated_exchange(
    original_input: Any,
    isolated_input: Any,
    isolated_output: Any,
) -> None:
    _validate_isolated_provenance(original_input, isolated_input)
    validate_isolated_output(isolated_output, isolated_input["source_input"])


def validate_artifact(document: Any) -> None:
    version = document.get("contract_version") if type(document) is dict else None
    if type(version) is not str:
        _fail("CONTRACT_VERSION_UNSUPPORTED")
    if version in (COMMAND_V10, COMMAND_V11):
        validate_command(document)
    elif version in (INPUT_V10, INPUT_V11):
        validate_local_input(document)
    elif version in (RESULT_V10, RESULT_V11):
        validate_local_result(document)
    elif version == ISOLATED_INPUT_V10:
        validate_isolated_input(document)
    elif version == ISOLATED_OUTPUT_V10:
        validate_isolated_output(document)
    else:
        _fail("CONTRACT_VERSION_UNSUPPORTED")


POSITIVE_CASES = {
    "adapter-v1.0-checkpoint": ("local",),
    "adapter-v1.0-terminal-preview": ("local",),
    "adapter-v1.1-align": ("local",),
    "adapter-v1.1-align-retry": ("local",),
    "adapter-v1.1-transcribe": ("local",),
    "isolated-v1.0-adapter-v1.1-align": ("isolated",),
}
NEGATIVE_CASES = {
    "command-extra-field": ("artifact", "COMMAND_FIELDS_INVALID", "command.json"),
    "command-v1.0-adapter-v1.1": (
        "command-exchange",
        "COMMAND_INPUT_VERSION_MISMATCH",
        "command.json",
        "input.json",
        "result.json",
    ),
    "isolated-input-swapped-evidence-paths": (
        "artifact",
        "INPUT_EVIDENCE_PATH_INVALID",
        "isolated-input.json",
    ),
    "isolated-input-tampered-digest": (
        "artifact",
        "ISOLATED_INPUT_DIGEST_MISMATCH",
        "isolated-input.json",
    ),
    "isolated-output-tampered-result-digest": (
        "artifact",
        "ISOLATED_RESULT_DIGEST_MISMATCH",
        "isolated-output.json",
    ),
    "isolated-output-unreferenced-preview": (
        "artifact",
        "ISOLATED_PREVIEW_INVALID",
        "isolated-output.json",
    ),
    "isolated-source-provenance-mismatch": (
        "isolated-bundle",
        "ISOLATED_SOURCE_PROVENANCE_MISMATCH",
        "input.json",
        "isolated-input.json",
        "isolated-output.json",
    ),
    "v1.0-extra-stage-inputs": ("artifact", "INPUT_FIELDS_INVALID", "input.json"),
    "v1.0-preview-extra-field": (
        "exchange",
        "PREVIEW_REFERENCE_FIELDS_INVALID",
        "input.json",
        "result.json",
    ),
    "v1.1-artifact-created-at-mismatch": (
        "artifact",
        "STAGE_ARTIFACT_INVALID",
        "input.json",
    ),
    "v1.1-align-missing-artifact": (
        "artifact",
        "STAGE_INPUT_INVALID",
        "input.json",
    ),
    "v1.1-align-wrong-consumption": (
        "exchange",
        "CHECKPOINT_CONSUMPTION_MISMATCH",
        "input.json",
        "result.json",
    ),
    "v1.1-completion-time-mismatch": (
        "artifact",
        "INPUT_CAPTURE_TIME_INVALID",
        "input.json",
    ),
    "v1.1-result-cross-binding": (
        "exchange",
        "RESULT_BINDING_MISMATCH",
        "input.json",
        "result.json",
    ),
    "v1.1-retention-anchor-mismatch": (
        "artifact",
        "INPUT_CAPTURE_TIME_INVALID",
        "input.json",
    ),
    "v1.1-tampered-input-digest": (
        "artifact",
        "INPUT_DIGEST_MISMATCH",
        "input.json",
    ),
    "v1.1-transcript-artifact-tampered": (
        "artifact",
        "STAGE_ARTIFACT_INVALID",
        "input.json",
    ),
    "v1.1-unknown-contract": (
        "artifact",
        "CONTRACT_VERSION_UNSUPPORTED",
        "input.json",
    ),
}


def _directory_files(directory: Path, code: str) -> dict[str, Path]:
    try:
        entries = list(directory.iterdir())
    except OSError:
        _fail(code)
    if any(item.is_symlink() or not item.is_file() for item in entries):
        _fail(code)
    return {item.name: item for item in entries}


def _validate_isolated_provenance(
    original: dict[str, Any], isolated_input: dict[str, Any]
) -> None:
    validate_local_input(original)
    validate_isolated_input(isolated_input)
    rewritten = isolated_input["source_input"]
    if isolated_input["source_input_digest"] != original["input_digest"]:
        _fail("ISOLATED_SOURCE_PROVENANCE_MISMATCH")
    expected = copy.deepcopy(original)
    actual_references = [
        *rewritten["capture"]["segments"],
        *rewritten["capture"]["diagnostics"],
    ]
    expected_references = [
        *expected["capture"]["segments"],
        *expected["capture"]["diagnostics"],
    ]
    if len(actual_references) != len(expected_references):
        _fail("ISOLATED_SOURCE_PROVENANCE_MISMATCH")
    root = None
    if actual_references:
        match = ISOLATED_EVIDENCE_PATH_RE.fullmatch(
            actual_references[0]["read_only_path"]
        )
        if match is None:
            _fail("ISOLATED_SOURCE_PROVENANCE_MISMATCH")
        root = match.group("root")
    for index, reference in enumerate(expected_references):
        reference["read_only_path"] = (
            f"{root}/evidence/evidence-{index:06d}.bin"
        )
    if expected != rewritten:
        _fail("ISOLATED_SOURCE_PROVENANCE_MISMATCH")


def _validate_isolated_fixture_documents(
    original: dict[str, Any],
    isolated_input: dict[str, Any],
    isolated_output: dict[str, Any],
) -> None:
    validate_isolated_exchange(original, isolated_input, isolated_output)


def validate_bundle(directory: Path) -> None:
    files = _directory_files(directory, "FIXTURE_BUNDLE_FILES_INVALID")
    local_required = {"command.json", "input.json", "result.json"}
    isolated_required = {"input.json", "isolated-input.json", "isolated-output.json"}
    if local_required <= set(files):
        command = load_json(files["command.json"])
        source_input = load_json(files["input.json"])
        result = load_json(files["result.json"])
        validate_command_exchange(command, source_input, result)
        references = _referenced_previews(result, isolated=False)
        if set(references) & local_required:
            _fail("FIXTURE_BUNDLE_FILES_INVALID")
        expected_names = {"command.json", "input.json", "result.json", *references}
        if set(files) != expected_names:
            _fail("FIXTURE_BUNDLE_FILES_INVALID")
        for name, (size, content_digest) in references.items():
            try:
                if files[name].stat().st_size != size:
                    _fail("FIXTURE_PREVIEW_INVALID")
                with files[name].open("rb") as stream:
                    body = stream.read(size + 1)
            except OSError:
                _fail("FIXTURE_PREVIEW_UNAVAILABLE")
            if len(body) != size or digest(body) != content_digest:
                _fail("FIXTURE_PREVIEW_INVALID")
        return
    if set(files) == isolated_required:
        _validate_isolated_fixture_documents(
            load_json(files["input.json"]),
            load_json(files["isolated-input.json"]),
            load_json(files["isolated-output.json"]),
        )
        return
    _fail("FIXTURE_BUNDLE_INVALID")


def validate_fixture_corpus(root: Path) -> None:
    positive_root = root / "positive"
    negative_root = root / "negative"
    try:
        root_entries = list(root.iterdir())
        positive_entries = list(positive_root.iterdir())
        negative_entries = list(negative_root.iterdir())
    except OSError:
        _fail("FIXTURE_CORPUS_UNAVAILABLE")
    if (
        {item.name for item in root_entries} != {"positive", "negative"}
        or any(item.is_symlink() or not item.is_dir() for item in root_entries)
        or {item.name for item in positive_entries} != set(POSITIVE_CASES)
        or any(item.is_symlink() or not item.is_dir() for item in positive_entries)
        or {item.name for item in negative_entries} != set(NEGATIVE_CASES)
        or any(item.is_symlink() or not item.is_dir() for item in negative_entries)
    ):
        _fail("FIXTURE_CORPUS_SHAPE_INVALID")
    for name in sorted(POSITIVE_CASES):
        validate_bundle(positive_root / name)
    for name, specification in sorted(NEGATIVE_CASES.items()):
        operation, expected_code, *names = specification
        case_files = _directory_files(
            negative_root / name, "FIXTURE_CORPUS_SHAPE_INVALID"
        )
        if set(case_files) != set(names):
            _fail("FIXTURE_CORPUS_SHAPE_INVALID")
        documents = [load_json(case_files[filename]) for filename in names]
        try:
            if operation == "artifact":
                validate_artifact(documents[0])
            elif operation == "exchange":
                validate_exchange(documents[0], documents[1])
            elif operation == "command-exchange":
                validate_command_exchange(documents[0], documents[1], documents[2])
            else:
                _validate_isolated_fixture_documents(
                    documents[0], documents[1], documents[2]
                )
        except ContractError as error:
            if error.code != expected_code:
                _fail("NEGATIVE_FIXTURE_CODE_MISMATCH")
            continue
        _fail("NEGATIVE_FIXTURE_ACCEPTED")
