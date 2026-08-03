#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Atomically finalize and verify a local Tacua pilot-operation receipt."""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any


INPUT_CONTRACT_VERSION = "tacua.pilot-operation-finalization-input@1.0.0"
RECEIPT_CONTRACT_VERSION = "tacua.pilot-operation-receipt@1.0.0"
RECEIPT_MEDIA_TYPE = "application/vnd.tacua.pilot-operation-receipt+json"
MAX_INPUT_BYTES = 1 * 1024 * 1024
MAX_RECEIPT_BYTES = 1 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_FILES = 128
MAX_SOURCES = 32
MAX_SAFE_INTEGER = 9_007_199_254_740_991

ID_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._+:-]{0,127}$")
MEDIA_TYPE_RE = re.compile(
    r"^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}$"
)
FAILURE_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
OUTPUT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RECEIPT_TEMP_NAME_RE = re.compile(r"^tacua-receipt-[a-f0-9]{24}\.tmp$")

VALIDATION_STATES = {"passed", "failed"}
CLEANUP_STATES = {"attested_complete", "incomplete", "not_attested"}
HELPER_STATES = {
    "attested_absent",
    "not_applicable",
    "incomplete",
    "not_attested",
}
SUCCESS_HELPER_STATES = {"attested_absent", "not_applicable"}


class FinalizationError(ValueError):
    """A stable, non-sensitive finalization failure."""

    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}")


def _require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise FinalizationError(code, detail)


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FinalizationError(
                "DUPLICATE_JSON_KEY", "JSON contains a duplicate key"
            )
        result[key] = value
    return result


def _parse_json_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 16:
        raise ValueError("integer exceeds the interoperable bound")
    parsed = int(value)
    if abs(parsed) > MAX_SAFE_INTEGER:
        raise ValueError("integer exceeds the interoperable bound")
    return parsed


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise FinalizationError(
            "INVALID_JSON_VALUE", "value cannot be represented canonically"
        ) from error


def _load_json(raw: bytes, *, maximum: int, canonical: bool = False) -> dict[str, Any]:
    _require(
        0 < len(raw) <= maximum,
        "JSON_SIZE_LIMIT",
        "JSON violates its byte bound",
    )
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate,
            parse_int=_parse_json_integer,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ValueError("floating-point values are not supported")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite number")
            ),
        )
    except FinalizationError:
        raise
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise FinalizationError(
            "INVALID_JSON", "input is not bounded UTF-8 JSON"
        ) from error
    _require(
        isinstance(value, dict),
        "INVALID_JSON",
        "top-level JSON must be an object",
    )
    if canonical:
        _require(
            raw == _canonical_bytes(value),
            "NON_CANONICAL_RECEIPT",
            "receipt must be canonical JSON with one trailing newline",
        )
    return value


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest_without(value: dict[str, Any], field: str) -> str:
    subject = copy.deepcopy(value)
    subject.pop(field, None)
    # Tacua object seals hash canonical JSON without the transport newline.
    return _digest_bytes(_canonical_bytes(subject)[:-1])


def _seal(value: dict[str, Any]) -> dict[str, Any]:
    sealed = copy.deepcopy(value)
    sealed["receipt_digest"] = _digest_without(sealed, "receipt_digest")
    return sealed


def _validate_identifier(value: Any, field: str) -> str:
    _require(
        isinstance(value, str) and ID_RE.fullmatch(value) is not None,
        "INVALID_IDENTIFIER",
        f"{field} is invalid",
    )
    return value


def _validate_version(value: Any, field: str) -> str:
    _require(
        isinstance(value, str) and VERSION_RE.fullmatch(value) is not None,
        "INVALID_VERSION",
        f"{field} is invalid",
    )
    return value


def _validate_media_type(value: Any, field: str) -> str:
    _require(
        isinstance(value, str) and MEDIA_TYPE_RE.fullmatch(value) is not None,
        "INVALID_MEDIA_TYPE",
        f"{field} is invalid",
    )
    return value


def _validate_reason_code(value: Any, field: str) -> str:
    _require(
        isinstance(value, str) and FAILURE_CODE_RE.fullmatch(value) is not None,
        "INVALID_REASON_CODE",
        f"{field} must be a stable uppercase code",
    )
    return value


def _validate_timestamp(value: Any, field: str) -> str:
    _require(
        isinstance(value, str)
        and re.fullmatch(
            r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
            r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z",
            value,
        )
        is not None,
        "INVALID_TIMESTAMP",
        f"{field} must be an exact UTC timestamp",
    )
    # Reject impossible calendar dates while retaining a dependency-free format.
    from datetime import datetime

    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise FinalizationError(
            "INVALID_TIMESTAMP", f"{field} must be an exact UTC timestamp"
        ) from error
    _require(
        parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value,
        "INVALID_TIMESTAMP",
        f"{field} is not canonical",
    )
    return value


def _private_file_mode(mode: int) -> bool:
    permissions = stat.S_IMODE(mode)
    return (
        permissions & 0o077 == 0
        and permissions & 0o400 != 0
        and permissions & 0o7000 == 0
    )


def _read_private_file(path: Path, *, maximum: int) -> bytes:
    """Read one stable, owner-private, regular, single-link file."""

    try:
        before_path = os.lstat(path)
    except OSError as error:
        raise FinalizationError(
            "EVIDENCE_UNREADABLE", "a bound file could not be inspected"
        ) from error
    _require(
        stat.S_ISREG(before_path.st_mode) and not stat.S_ISLNK(before_path.st_mode),
        "UNSAFE_EVIDENCE_FILE",
        "every bound path must be a regular file, never a symlink",
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FinalizationError(
            "EVIDENCE_UNREADABLE", "a bound file could not be opened"
        ) from error
    try:
        before = os.fstat(descriptor)
        _require(
            (before.st_dev, before.st_ino)
            == (before_path.st_dev, before_path.st_ino),
            "EVIDENCE_CHANGED",
            "a bound file changed while opening",
        )
        _require(
            stat.S_ISREG(before.st_mode),
            "UNSAFE_EVIDENCE_FILE",
            "every bound file must be regular",
        )
        _require(
            before.st_uid == os.getuid(),
            "UNSAFE_EVIDENCE_FILE",
            "every bound file must be owned by the current user",
        )
        _require(
            before.st_nlink == 1,
            "UNSAFE_EVIDENCE_FILE",
            "every bound file must have exactly one hard link",
        )
        _require(
            _private_file_mode(before.st_mode),
            "UNSAFE_EVIDENCE_FILE",
            "every bound file must be owner-readable with no group or other access",
        )
        _require(
            0 <= before.st_size <= maximum,
            "EVIDENCE_SIZE_LIMIT",
            "a bound file violates its byte bound",
        )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_nlink,
            before.st_mode,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
            after.st_mode,
        )
        _require(
            identity_before == identity_after and len(raw) == before.st_size,
            "EVIDENCE_CHANGED",
            "a bound file changed while hashing",
        )
        _require(
            len(raw) <= maximum,
            "EVIDENCE_SIZE_LIMIT",
            "a bound file violates its byte bound",
        )
        return raw
    finally:
        os.close(descriptor)


def _validate_state_attestation(
    value: Any,
    *,
    field: str,
    states: set[str],
    completed_at: str,
) -> dict[str, Any]:
    expected = {"attestation_version", "state", "attested_at", "reason_code"}
    _require(
        isinstance(value, dict) and set(value) == expected,
        "INVALID_ATTESTATION",
        f"{field} fields changed",
    )
    version = _validate_version(value["attestation_version"], f"{field}.attestation_version")
    state_value = value["state"]
    _require(
        state_value in states,
        "INVALID_ATTESTATION",
        f"{field}.state is invalid",
    )
    attested_at = value["attested_at"]
    if attested_at is not None:
        attested_at = _validate_timestamp(attested_at, f"{field}.attested_at")
        _require(
            attested_at <= completed_at,
            "INVALID_ATTESTATION",
            f"{field} postdates receipt completion",
        )
    reason_code = value["reason_code"]
    if reason_code is not None:
        reason_code = _validate_reason_code(reason_code, f"{field}.reason_code")
    return {
        "attestation_version": version,
        "state": state_value,
        "attested_at": attested_at,
        "reason_code": reason_code,
    }


def _validate_input(value: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "client_cleanup",
        "completed_at",
        "contract_version",
        "evidence",
        "failure",
        "helper_uninstall",
        "narration",
        "operation_id",
        "sources",
        "terminal_state",
        "validation",
    }
    _require(
        set(value) == expected,
        "INVALID_FINALIZATION_INPUT",
        "finalization input fields changed",
    )
    _require(
        value["contract_version"] == INPUT_CONTRACT_VERSION,
        "INVALID_FINALIZATION_INPUT",
        "finalization input contract version changed",
    )
    operation_id = _validate_identifier(value["operation_id"], "operation_id")
    completed_at = _validate_timestamp(value["completed_at"], "completed_at")
    terminal_state = value["terminal_state"]
    _require(
        terminal_state in {"succeeded", "failed"},
        "INVALID_TERMINAL_STATE",
        "terminal state must be exactly succeeded or failed",
    )

    failure = value["failure"]
    if terminal_state == "succeeded":
        _require(
            failure is None,
            "AMBIGUOUS_TERMINAL_STATE",
            "a successful receipt cannot contain a failure",
        )
    else:
        _require(
            isinstance(failure, dict) and set(failure) == {"stage", "code"},
            "AMBIGUOUS_TERMINAL_STATE",
            "a failed receipt requires one stable failure",
        )
        failure = {
            "stage": _validate_identifier(failure["stage"], "failure.stage"),
            "code": _validate_reason_code(failure["code"], "failure.code"),
        }

    validation = value["validation"]
    _require(
        isinstance(validation, dict)
        and set(validation) == {"version", "state", "reason_code"},
        "INVALID_VALIDATION_RESULT",
        "validation result fields changed",
    )
    validation_state = validation["state"]
    _require(
        validation_state in VALIDATION_STATES,
        "INVALID_VALIDATION_RESULT",
        "validation state is invalid",
    )
    validation_reason = validation["reason_code"]
    if validation_state == "passed":
        _require(
            validation_reason is None,
            "INVALID_VALIDATION_RESULT",
            "passed validation cannot contain a failure reason",
        )
    else:
        validation_reason = _validate_reason_code(
            validation_reason, "validation.reason_code"
        )
    normalized_validation = {
        "version": _validate_version(validation["version"], "validation.version"),
        "state": validation_state,
        "reason_code": validation_reason,
    }

    narration = value["narration"]
    _require(
        isinstance(narration, dict) and set(narration) == {"version"},
        "INVALID_NARRATION",
        "narration descriptor fields changed",
    )
    normalized_narration = {
        "version": _validate_version(narration["version"], "narration.version")
    }

    sources = value["sources"]
    _require(
        isinstance(sources, list) and 1 <= len(sources) <= MAX_SOURCES,
        "INVALID_SOURCES",
        "source versions must be a non-empty bounded array",
    )
    normalized_sources: list[dict[str, str]] = []
    source_ids: set[str] = set()
    for index, source in enumerate(sources):
        _require(
            isinstance(source, dict) and set(source) == {"source_id", "version"},
            "INVALID_SOURCES",
            f"source {index} fields changed",
        )
        source_id = _validate_identifier(source["source_id"], f"sources[{index}].source_id")
        _require(
            source_id not in source_ids,
            "INVALID_SOURCES",
            "source IDs must be unique",
        )
        source_ids.add(source_id)
        normalized_sources.append(
            {
                "source_id": source_id,
                "version": _validate_version(
                    source["version"], f"sources[{index}].version"
                ),
            }
        )
    normalized_sources.sort(key=lambda item: item["source_id"])

    cleanup = _validate_state_attestation(
        value["client_cleanup"],
        field="client_cleanup",
        states=CLEANUP_STATES,
        completed_at=completed_at,
    )
    if cleanup["state"] == "attested_complete":
        _require(
            cleanup["attested_at"] is not None and cleanup["reason_code"] is None,
            "INVALID_CLEANUP_ATTESTATION",
            "complete cleanup requires a timestamp and no failure reason",
        )
    elif cleanup["state"] == "incomplete":
        _require(
            cleanup["attested_at"] is not None
            and cleanup["reason_code"] is not None,
            "INVALID_CLEANUP_ATTESTATION",
            "incomplete cleanup requires a timestamp and reason",
        )
    else:
        _require(
            cleanup["attested_at"] is None
            and cleanup["reason_code"] is not None,
            "INVALID_CLEANUP_ATTESTATION",
            "unattested cleanup requires a reason and no timestamp",
        )

    helper = _validate_state_attestation(
        value["helper_uninstall"],
        field="helper_uninstall",
        states=HELPER_STATES,
        completed_at=completed_at,
    )
    if helper["state"] == "attested_absent":
        _require(
            helper["attested_at"] is not None and helper["reason_code"] is None,
            "INVALID_HELPER_OUTCOME",
            "verified helper absence requires a timestamp and no failure reason",
        )
    elif helper["state"] in {"not_applicable", "incomplete"}:
        _require(
            helper["attested_at"] is not None
            and helper["reason_code"] is not None,
            "INVALID_HELPER_OUTCOME",
            "helper outcome requires a timestamp and stable reason",
        )
        if helper["state"] == "not_applicable":
            _require(
                helper["reason_code"] == "HELPERS_NOT_USED",
                "INVALID_HELPER_OUTCOME",
                "not-applicable is valid only when no temporary helper was used",
            )
    else:
        _require(
            helper["attested_at"] is None
            and helper["reason_code"] is not None,
            "INVALID_HELPER_OUTCOME",
            "unattested helper outcome requires a reason and no timestamp",
        )

    evidence = value["evidence"]
    _require(
        isinstance(evidence, list) and 1 <= len(evidence) <= MAX_EVIDENCE_FILES,
        "INVALID_EVIDENCE",
        "evidence must be a non-empty bounded array",
    )
    normalized_evidence: list[dict[str, Any]] = []
    names: set[str] = set()
    paths: set[str] = set()
    for index, item in enumerate(evidence):
        _require(
            isinstance(item, dict)
            and set(item) == {"name", "role", "media_type", "path"},
            "INVALID_EVIDENCE",
            f"evidence {index} fields changed",
        )
        name = _validate_identifier(item["name"], f"evidence[{index}].name")
        role = _validate_identifier(item["role"], f"evidence[{index}].role")
        media_type = _validate_media_type(
            item["media_type"], f"evidence[{index}].media_type"
        )
        path_value = item["path"]
        _require(
            isinstance(path_value, str)
            and 1 <= len(path_value.encode("utf-8")) <= 4096
            and "\x00" not in path_value
            and Path(path_value).is_absolute(),
            "INVALID_EVIDENCE_PATH",
            "evidence paths must be bounded absolute paths",
        )
        _require(name not in names, "INVALID_EVIDENCE", "evidence names must be unique")
        _require(path_value not in paths, "INVALID_EVIDENCE", "evidence paths must be unique")
        names.add(name)
        paths.add(path_value)
        normalized_evidence.append(
            {
                "name": name,
                "role": role,
                "media_type": media_type,
                "path": Path(path_value),
            }
        )
    normalized_evidence.sort(key=lambda item: item["name"])

    if terminal_state == "succeeded":
        _require(
            validation_state == "passed",
            "SUCCESS_VALIDATION_REQUIRED",
            "success requires a passed final validation",
        )
        _require(
            cleanup["state"] == "attested_complete",
            "SUCCESS_CLEANUP_REQUIRED",
            "success requires positive client-cleanup attestation",
        )
        _require(
            helper["state"] in SUCCESS_HELPER_STATES,
            "SUCCESS_HELPER_OUTCOME_REQUIRED",
            "success requires verified helper removal or an explicit not-applicable outcome",
        )

    return {
        "operation_id": operation_id,
        "completed_at": completed_at,
        "terminal_state": terminal_state,
        "failure": failure,
        "validation": normalized_validation,
        "narration": normalized_narration,
        "sources": normalized_sources,
        "client_cleanup": cleanup,
        "helper_uninstall": helper,
        "evidence": normalized_evidence,
    }


def _trust_boundary() -> dict[str, str]:
    return {
        "attestation_type": "local_host",
        "evidence_integrity": "sha256",
        "receipt_integrity": "canonical_json_sha256",
        "server_signature": "not_present",
        "trusts": "current_local_user_and_private_evidence_files",
    }


def _build_receipt(validated: dict[str, Any]) -> dict[str, Any]:
    total_bytes = 0
    evidence_bindings: list[dict[str, Any]] = []
    for item in validated["evidence"]:
        raw = _read_private_file(item["path"], maximum=MAX_EVIDENCE_FILE_BYTES)
        total_bytes += len(raw)
        _require(
            total_bytes <= MAX_EVIDENCE_TOTAL_BYTES,
            "EVIDENCE_TOTAL_SIZE_LIMIT",
            "bound evidence exceeds the total byte limit",
        )
        evidence_bindings.append(
            {
                "name": item["name"],
                "role": item["role"],
                "media_type": item["media_type"],
                "size_bytes": len(raw),
                "content_digest": _digest_bytes(raw),
            }
        )
    receipt = _seal(
        {
            "contract_version": RECEIPT_CONTRACT_VERSION,
            "media_type": RECEIPT_MEDIA_TYPE,
            "operation_id": validated["operation_id"],
            "completed_at": validated["completed_at"],
            "terminal_state": validated["terminal_state"],
            "failure": validated["failure"],
            "validation": validated["validation"],
            "narration": validated["narration"],
            "sources": validated["sources"],
            "client_cleanup": validated["client_cleanup"],
            "helper_uninstall": validated["helper_uninstall"],
            "evidence": evidence_bindings,
            "trust": _trust_boundary(),
            "receipt_digest": "sha256:" + "0" * 64,
        }
    )
    _validate_receipt(receipt)
    return receipt


def _validate_receipt(value: dict[str, Any]) -> None:
    expected = {
        "client_cleanup",
        "completed_at",
        "contract_version",
        "evidence",
        "failure",
        "helper_uninstall",
        "media_type",
        "narration",
        "operation_id",
        "receipt_digest",
        "sources",
        "terminal_state",
        "trust",
        "validation",
    }
    _require(
        set(value) == expected,
        "INVALID_RECEIPT",
        "receipt fields changed",
    )
    _require(
        value["contract_version"] == RECEIPT_CONTRACT_VERSION
        and value["media_type"] == RECEIPT_MEDIA_TYPE,
        "INVALID_RECEIPT",
        "receipt contract identity changed",
    )
    _validate_identifier(value["operation_id"], "receipt.operation_id")
    completed_at = _validate_timestamp(value["completed_at"], "receipt.completed_at")
    _require(
        value["terminal_state"] in {"succeeded", "failed"},
        "INVALID_RECEIPT",
        "receipt terminal state is invalid",
    )

    failure = value["failure"]
    if value["terminal_state"] == "succeeded":
        _require(
            failure is None,
            "AMBIGUOUS_TERMINAL_STATE",
            "successful receipt contains failure data",
        )
    else:
        _require(
            isinstance(failure, dict) and set(failure) == {"stage", "code"},
            "AMBIGUOUS_TERMINAL_STATE",
            "failed receipt lacks failure data",
        )
        _validate_identifier(failure["stage"], "receipt.failure.stage")
        _validate_reason_code(failure["code"], "receipt.failure.code")

    validation = value["validation"]
    _require(
        isinstance(validation, dict)
        and set(validation) == {"version", "state", "reason_code"}
        and validation["state"] in VALIDATION_STATES,
        "INVALID_RECEIPT",
        "receipt validation result is invalid",
    )
    _validate_version(validation["version"], "receipt.validation.version")
    if validation["state"] == "passed":
        _require(
            validation["reason_code"] is None,
            "INVALID_RECEIPT",
            "passed receipt validation cannot contain a reason",
        )
    else:
        _validate_reason_code(
            validation["reason_code"], "receipt.validation.reason_code"
        )

    narration = value["narration"]
    _require(
        isinstance(narration, dict) and set(narration) == {"version"},
        "INVALID_RECEIPT",
        "receipt narration descriptor is invalid",
    )
    _validate_version(narration["version"], "receipt.narration.version")

    sources = value["sources"]
    _require(
        isinstance(sources, list) and 1 <= len(sources) <= MAX_SOURCES,
        "INVALID_RECEIPT",
        "receipt source versions are invalid",
    )
    previous_source = ""
    for index, source in enumerate(sources):
        _require(
            isinstance(source, dict) and set(source) == {"source_id", "version"},
            "INVALID_RECEIPT",
            f"receipt source {index} fields changed",
        )
        source_id = _validate_identifier(
            source["source_id"], f"receipt.sources[{index}].source_id"
        )
        _require(
            source_id > previous_source,
            "INVALID_RECEIPT",
            "receipt source IDs must be sorted and unique",
        )
        previous_source = source_id
        _validate_version(source["version"], f"receipt.sources[{index}].version")

    cleanup = _validate_state_attestation(
        value["client_cleanup"],
        field="receipt.client_cleanup",
        states=CLEANUP_STATES,
        completed_at=completed_at,
    )
    if cleanup["state"] == "attested_complete":
        _require(
            cleanup["attested_at"] is not None and cleanup["reason_code"] is None,
            "INVALID_RECEIPT",
            "complete receipt cleanup attestation is invalid",
        )
    elif cleanup["state"] == "incomplete":
        _require(
            cleanup["attested_at"] is not None
            and cleanup["reason_code"] is not None,
            "INVALID_RECEIPT",
            "incomplete receipt cleanup attestation is invalid",
        )
    else:
        _require(
            cleanup["attested_at"] is None
            and cleanup["reason_code"] is not None,
            "INVALID_RECEIPT",
            "unattested receipt cleanup is invalid",
        )

    helper = _validate_state_attestation(
        value["helper_uninstall"],
        field="receipt.helper_uninstall",
        states=HELPER_STATES,
        completed_at=completed_at,
    )
    if helper["state"] == "attested_absent":
        _require(
            helper["attested_at"] is not None and helper["reason_code"] is None,
            "INVALID_RECEIPT",
            "verified receipt helper absence is invalid",
        )
    elif helper["state"] in {"not_applicable", "incomplete"}:
        _require(
            helper["attested_at"] is not None
            and helper["reason_code"] is not None,
            "INVALID_RECEIPT",
            "receipt helper outcome is invalid",
        )
        if helper["state"] == "not_applicable":
            _require(
                helper["reason_code"] == "HELPERS_NOT_USED",
                "INVALID_RECEIPT",
                "receipt helper not-applicable reason is invalid",
            )
    else:
        _require(
            helper["attested_at"] is None
            and helper["reason_code"] is not None,
            "INVALID_RECEIPT",
            "unattested receipt helper outcome is invalid",
        )

    if value["terminal_state"] == "succeeded":
        _require(
            validation["state"] == "passed"
            and cleanup["state"] == "attested_complete"
            and helper["state"] in SUCCESS_HELPER_STATES,
            "INVALID_SUCCESS_RECEIPT",
            "successful receipt does not contain every positive attestation",
        )
    _require(
        isinstance(value["evidence"], list)
        and 1 <= len(value["evidence"]) <= MAX_EVIDENCE_FILES,
        "INVALID_RECEIPT",
        "receipt evidence is invalid",
    )
    previous = ""
    total = 0
    for index, item in enumerate(value["evidence"]):
        _require(
            isinstance(item, dict)
            and set(item)
            == {"name", "role", "media_type", "size_bytes", "content_digest"},
            "INVALID_RECEIPT",
            f"receipt evidence {index} fields changed",
        )
        name = _validate_identifier(item["name"], f"receipt.evidence[{index}].name")
        _require(name > previous, "INVALID_RECEIPT", "receipt evidence must be sorted and unique")
        previous = name
        _validate_identifier(item["role"], f"receipt.evidence[{index}].role")
        _validate_media_type(item["media_type"], f"receipt.evidence[{index}].media_type")
        size = item["size_bytes"]
        _require(
            isinstance(size, int)
            and not isinstance(size, bool)
            and 0 <= size <= min(MAX_SAFE_INTEGER, MAX_EVIDENCE_FILE_BYTES),
            "INVALID_RECEIPT",
            "receipt evidence size is invalid",
        )
        total += size
        _require(
            total <= MAX_EVIDENCE_TOTAL_BYTES,
            "INVALID_RECEIPT",
            "receipt evidence total is invalid",
        )
        _require(
            isinstance(item["content_digest"], str)
            and DIGEST_RE.fullmatch(item["content_digest"]) is not None,
            "INVALID_RECEIPT",
            "receipt evidence digest is invalid",
        )
    _require(
        value["trust"] == _trust_boundary(),
        "INVALID_RECEIPT",
        "receipt trust boundary changed",
    )
    _require(
        isinstance(value["receipt_digest"], str)
        and DIGEST_RE.fullmatch(value["receipt_digest"]) is not None
        and value["receipt_digest"] == _digest_without(value, "receipt_digest"),
        "RECEIPT_DIGEST_MISMATCH",
        "receipt digest does not match canonical content",
    )


def _load_and_validate_input(path: Path) -> dict[str, Any]:
    raw = _read_private_file(path, maximum=MAX_INPUT_BYTES)
    return _validate_input(_load_json(raw, maximum=MAX_INPUT_BYTES))


def _open_private_output_directory(output: Path) -> tuple[Path, str, int]:
    absolute = output.absolute()
    name = absolute.name
    _require(
        OUTPUT_NAME_RE.fullmatch(name) is not None
        and RECEIPT_TEMP_NAME_RE.fullmatch(name) is None,
        "UNSAFE_OUTPUT_PATH",
        "receipt filename is invalid",
    )
    parent = absolute.parent
    try:
        path_metadata = os.lstat(parent)
    except OSError as error:
        raise FinalizationError(
            "UNSAFE_OUTPUT_DIRECTORY", "receipt directory could not be inspected"
        ) from error
    _require(
        stat.S_ISDIR(path_metadata.st_mode)
        and not stat.S_ISLNK(path_metadata.st_mode)
        and path_metadata.st_uid == os.getuid()
        and stat.S_IMODE(path_metadata.st_mode) & 0o077 == 0,
        "UNSAFE_OUTPUT_DIRECTORY",
        "receipt directory must be owner-private, owner-controlled, and not a symlink",
    )
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        directory_fd = os.open(parent, flags)
    except OSError as error:
        raise FinalizationError(
            "UNSAFE_OUTPUT_DIRECTORY", "receipt directory could not be opened"
        ) from error
    opened = os.fstat(directory_fd)
    if (opened.st_dev, opened.st_ino) != (path_metadata.st_dev, path_metadata.st_ino):
        os.close(directory_fd)
        raise FinalizationError(
            "UNSAFE_OUTPUT_DIRECTORY", "receipt directory changed while opening"
        )
    return absolute, name, directory_fd


def _read_interrupted_receipt(
    directory_fd: int,
    name: str,
    expected_metadata: os.stat_result,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        file_fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise FinalizationError(
            "INTERRUPTED_RECEIPT_UNRECOVERABLE",
            "interrupted receipt could not be opened safely",
        ) from error
    try:
        before = os.fstat(file_fd)
        _require(
            (before.st_dev, before.st_ino)
            == (expected_metadata.st_dev, expected_metadata.st_ino)
            and stat.S_ISREG(before.st_mode)
            and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_nlink == 2
            and 0 < before.st_size <= MAX_RECEIPT_BYTES,
            "INTERRUPTED_RECEIPT_UNRECOVERABLE",
            "interrupted receipt identity or permissions are invalid",
        )
        chunks: list[bytes] = []
        remaining = MAX_RECEIPT_BYTES + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(file_fd)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_nlink,
            before.st_mode,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
            after.st_mode,
        )
        _require(
            identity_before == identity_after and len(raw) == before.st_size,
            "INTERRUPTED_RECEIPT_UNRECOVERABLE",
            "interrupted receipt changed while being inspected",
        )
        return raw
    finally:
        os.close(file_fd)


def _recover_interrupted_publication(
    directory_fd: int,
    name: str,
    expected_raw: bytes,
) -> bool:
    """Finish only the exact final-name-plus-temp-link crash state."""

    try:
        final_metadata = os.stat(
            name, dir_fd=directory_fd, follow_symlinks=False
        )
    except FileNotFoundError:
        return False
    except OSError as error:
        raise FinalizationError(
            "INTERRUPTED_RECEIPT_UNRECOVERABLE",
            "existing receipt could not be inspected for recovery",
        ) from error
    if final_metadata.st_nlink == 1:
        return False
    _require(
        stat.S_ISREG(final_metadata.st_mode)
        and final_metadata.st_uid == os.getuid()
        and stat.S_IMODE(final_metadata.st_mode) == 0o600
        and final_metadata.st_nlink == 2,
        "INTERRUPTED_RECEIPT_UNRECOVERABLE",
        "existing multi-link receipt is not an exact publication crash state",
    )

    matching_temporary_names: list[str] = []
    try:
        directory_names = os.listdir(directory_fd)
    except OSError as error:
        raise FinalizationError(
            "INTERRUPTED_RECEIPT_UNRECOVERABLE",
            "receipt directory could not be inspected for recovery",
        ) from error
    for candidate in directory_names:
        if RECEIPT_TEMP_NAME_RE.fullmatch(candidate) is None:
            continue
        try:
            candidate_metadata = os.stat(
                candidate, dir_fd=directory_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            continue
        except OSError as error:
            raise FinalizationError(
                "INTERRUPTED_RECEIPT_UNRECOVERABLE",
                "receipt temporary file could not be inspected safely",
            ) from error
        if (
            candidate_metadata.st_dev,
            candidate_metadata.st_ino,
        ) == (final_metadata.st_dev, final_metadata.st_ino):
            _require(
                stat.S_ISREG(candidate_metadata.st_mode)
                and candidate_metadata.st_uid == os.getuid()
                and stat.S_IMODE(candidate_metadata.st_mode) == 0o600
                and candidate_metadata.st_nlink == 2,
                "INTERRUPTED_RECEIPT_UNRECOVERABLE",
                "linked receipt temporary file is unsafe",
            )
            matching_temporary_names.append(candidate)
    _require(
        len(matching_temporary_names) == 1,
        "INTERRUPTED_RECEIPT_UNRECOVERABLE",
        "existing multi-link receipt has no unique linked publication temporary",
    )

    raw = _read_interrupted_receipt(directory_fd, name, final_metadata)
    _require(
        raw == expected_raw,
        "INTERRUPTED_RECEIPT_UNRECOVERABLE",
        "interrupted receipt bytes do not match this exact finalization",
    )
    parsed = _load_json(raw, maximum=MAX_RECEIPT_BYTES, canonical=True)
    _validate_receipt(parsed)

    temporary = matching_temporary_names[0]
    try:
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
        recovered = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise FinalizationError(
            "INTERRUPTED_RECEIPT_UNRECOVERABLE",
            "interrupted receipt recovery could not be durably completed",
        ) from error
    _require(
        (recovered.st_dev, recovered.st_ino)
        == (final_metadata.st_dev, final_metadata.st_ino)
        and recovered.st_nlink == 1
        and stat.S_IMODE(recovered.st_mode) == 0o600,
        "INTERRUPTED_RECEIPT_UNRECOVERABLE",
        "receipt recovery did not reach the single-link terminal state",
    )
    return True


def _recover_receipt_path(receipt_path: Path, expected_raw: bytes) -> None:
    _absolute, name, directory_fd = _open_private_output_directory(receipt_path)
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        _recover_interrupted_publication(directory_fd, name, expected_raw)
    finally:
        os.close(directory_fd)


def _atomic_publish(output: Path, receipt: dict[str, Any]) -> None:
    raw = _canonical_bytes(receipt)
    _require(
        len(raw) <= MAX_RECEIPT_BYTES,
        "RECEIPT_SIZE_LIMIT",
        "receipt violates its byte bound",
    )
    _absolute, name, directory_fd = _open_private_output_directory(output)
    temporary = f"tacua-receipt-{secrets.token_hex(12)}.tmp"
    file_fd = -1
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        if _recover_interrupted_publication(directory_fd, name, raw):
            return
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FinalizationError(
                "RECEIPT_ALREADY_EXISTS",
                "terminal receipt is immutable and cannot be overwritten",
            )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        file_fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        os.fchmod(file_fd, 0o600)
        written = 0
        while written < len(raw):
            count = os.write(file_fd, raw[written:])
            _require(
                count > 0,
                "DURABLE_WRITE_FAILED",
                "receipt bytes could not be written",
            )
            written += count
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = -1
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise FinalizationError(
                "RECEIPT_ALREADY_EXISTS",
                "terminal receipt is immutable and cannot be overwritten",
            ) from error
        os.fsync(directory_fd)
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except FinalizationError:
        raise
    except OSError as error:
        raise FinalizationError(
            "DURABLE_WRITE_FAILED", "receipt could not be atomically published"
        ) from error
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def finalize(input_path: Path, output_path: Path) -> dict[str, Any]:
    validated = _load_and_validate_input(input_path)
    receipt = _build_receipt(validated)
    _atomic_publish(output_path, receipt)
    return receipt


def verify(input_path: Path, receipt_path: Path) -> dict[str, Any]:
    validated = _load_and_validate_input(input_path)
    expected = _build_receipt(validated)
    _recover_receipt_path(receipt_path, _canonical_bytes(expected))
    raw = _read_private_file(receipt_path, maximum=MAX_RECEIPT_BYTES)
    receipt = _load_json(raw, maximum=MAX_RECEIPT_BYTES, canonical=True)
    _validate_receipt(receipt)
    _require(
        receipt == expected,
        "RECEIPT_INPUT_MISMATCH",
        "receipt no longer matches its input attestations or evidence bytes",
    )
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    finalize_parser = commands.add_parser(
        "finalize", help="create one immutable terminal receipt"
    )
    finalize_parser.add_argument("--input", type=Path, required=True)
    finalize_parser.add_argument("--output", type=Path, required=True)
    verify_parser = commands.add_parser(
        "verify", help="verify a receipt against its original input and current evidence"
    )
    verify_parser.add_argument("--input", type=Path, required=True)
    verify_parser.add_argument("--receipt", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "finalize":
            receipt = finalize(args.input, args.output)
        else:
            receipt = verify(args.input, args.receipt)
    except FinalizationError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"{receipt['terminal_state']} {receipt['receipt_digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
