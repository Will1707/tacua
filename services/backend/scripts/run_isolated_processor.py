#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run one operator-selected Tacua processor in the V1 private-pilot sandbox."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from typing import Any


COMMAND_CONTRACT = "tacua.isolated-processing-command@1.0.0"
INPUT_CONTRACT = "tacua.isolated-processing-input@1.0.0"
SOURCE_INPUT_CONTRACT = "tacua.local-processing-input@1.0.0"
SOURCE_INPUT_CONTRACT_V11 = "tacua.local-processing-input@1.1.0"
SOURCE_RESULT_CONTRACT = "tacua.local-processing-result@1.0.0"
SOURCE_RESULT_CONTRACT_V11 = "tacua.local-processing-result@1.1.0"
OUTPUT_CONTRACT = "tacua.isolated-processing-output@1.0.0"
ARTIFACT_PIPELINE_VERSION = "tacua.pipeline@1.1.0"
LEGACY_PIPELINE_VERSION = "tacua.pipeline@1.0.0"
PROCESSING_ARTIFACT_CONTRACT = "tacua.processing-stage-artifact@1.0.0"
PROCESSING_ARTIFACT_MEDIA_TYPE = (
    "application/vnd.tacua.processing-stage-artifact+json;version=1.0.0"
)
TRANSCRIPT_CONTRACT = "tacua.transcript@1.0.0"
INPUT_PLACEHOLDER = "{input}"
MODEL_PLACEHOLDER = "{model}"
MAX_COMMAND_BYTES = 65_536
MAX_INPUT_BYTES = 16_777_216
MAX_EVIDENCE_FILES = 512
MAX_EVIDENCE_BYTES = 4_294_967_296
MAX_MODEL_BYTES = 8_589_934_592
MAX_OUTPUT_BYTES = 67_108_864
MAX_OUTPUT_STREAM_BYTES = 115_343_360
MAX_OUTPUT_FILES = 512
MAX_RESULT_BYTES = 16_777_216
MAX_PROCESSING_ARTIFACT_BYTES = 4_194_304
MAX_TRANSCRIPT_TEXT_BYTES = 2_097_152
MAX_TRANSCRIPT_SPANS = 10_000
MAX_PREVIEW_BYTES = 2_097_152
MAX_ARGUMENTS = 64
MAX_ARGUMENT_BYTES = 32_768
MAX_JSON_DEPTH = 64
MAX_JSON_VALUES = 1_000_000
MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991
PROCESSOR_UID = 10_002
PROCESSOR_GID = 10_002
PROCESSOR_CPUS = "2.0"
PROCESSOR_MEMORY = "4g"
PROCESSOR_PIDS = "64"
PROCESSOR_TMP_BYTES = 268_435_456
PROCESSOR_OUTPUT_BYTES = 67_108_864
OUTER_ADAPTER_TIMEOUT_SECONDS = 240
MAX_CONTAINER_RUNTIME_SECONDS = 150
RUNNER_WORK_BUDGET_SECONDS = 180
RUNNER_HARD_BUDGET_SECONDS = 210
DOCKER_STEP_TIMEOUT_SECONDS = 15
DOCKER_COPY_TIMEOUT_SECONDS = 20
DOCKER_CLEANUP_TIMEOUT_SECONDS = 10
MAX_DOCKER_OUTPUT_BYTES = 1_048_576
MAX_STALE_CONTAINERS = 16
MAX_STALE_VOLUMES = 8
OUTER_TIMEOUT_ENV = "TACUA_ADAPTER_TIMEOUT_SECONDS"
PRIVATE_LABEL = "com.tacua.private-pilot-processor"
CONTRACT_LABEL = "com.tacua.runner-contract"
INSTANCE_LABEL = "com.tacua.runner-instance"
STAGING_LABEL = "com.tacua.staging-directory"
ROLE_LABEL = "com.tacua.runner-role"
VOLUME_LABEL = "com.tacua.payload-volume"
CONFIG_DIGEST_LABEL = "com.tacua.runtime-config-digest"
MODEL_ID_LABEL = "com.tacua.processor-model-id"
CONTAINER_RUNTIME_LABEL = "com.tacua.max-container-runtime-seconds"
RUNNER_RUNTIME_LABEL = "com.tacua.max-runner-seconds"
PROCESSOR_ROLE = "processor"
CARRIER_ROLE = "payload-carrier"
IMAGE_RE = re.compile(r"^(?:[^\s@]+@)?sha256:[a-f0-9]{64}$")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
LANGUAGE_TAG_RE = re.compile(
    r"^(?:und|[a-z]{2,3}(?:-[A-Z][a-z]{3})?(?:-(?:[A-Z]{2}|[0-9]{3}))?)$"
)
DESCRIPTOR_PATH_RE = re.compile(r"^/dev/fd/([0-9]+)$")
MAX_SOURCE_DESCRIPTOR = 1_048_575
MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_OUTPUT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CONTAINER_ID_RE = re.compile(r"^[a-f0-9]{64}$")
INSTANCE_RE = re.compile(r"^[0-9]+-[a-f0-9]{24}$")
STAGING_NAME_RE = re.compile(r"^tacua-isolated-input-[0-9]+-[a-f0-9]{24}-[A-Za-z0-9_-]+$")
VOLUME_NAME_RE = re.compile(r"^tacua-private-payload-[0-9]+-[a-f0-9]{24}$")
RUNNER_LOCK_PATH = Path("/tmp/tacua-private-processor-runner.lock")
CARRIER_ENTRYPOINT_PREFIX = "/tacua-carrier-never-run-"
CARRIER_COMMAND_PREFIX = "/tacua-carrier-command-never-run-"
PROCESSOR_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class IsolationError(RuntimeError):
    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(detail)


def _acquire_runner_lock() -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(RUNNER_LOCK_PATH, flags, 0o600)
    except OSError as error:
        raise IsolationError(
            "PROCESSOR_RUNNER_LOCK_INVALID",
            "exclusive processor runner lock could not be opened safely",
        ) from error
    try:
        metadata = os.fstat(descriptor)
        path_metadata = RUNNER_LOCK_PATH.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_dev != path_metadata.st_dev
            or metadata.st_ino != path_metadata.st_ino
        ):
            raise IsolationError(
                "PROCESSOR_RUNNER_LOCK_INVALID",
                "exclusive processor runner lock ownership, type, mode, or identity differs",
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise IsolationError(
                "PROCESSOR_RUNNER_BUSY",
                "another isolated processor runner holds the host-exclusive lock",
            ) from error
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                raise IsolationError(
                    "PROCESSOR_RUNNER_BUSY",
                    "another isolated processor runner holds the host-exclusive lock",
                ) from error
            raise IsolationError(
                "PROCESSOR_RUNNER_LOCK_INVALID",
                "exclusive processor runner lock could not be acquired safely",
            ) from error
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _release_runner_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _remaining_seconds(deadline: float | None) -> float:
    if deadline is None:
        return float("inf")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise IsolationError(
            "RUNNER_DEADLINE_EXCEEDED",
            "isolated runner exhausted its internal work budget",
        )
    return remaining


def _check_deadline(deadline: float | None) -> None:
    _remaining_seconds(deadline)


def validate_outer_timeout_environment() -> None:
    _requirement = os.environ.get(OUTER_TIMEOUT_ENV)
    if _requirement != str(OUTER_ADAPTER_TIMEOUT_SECONDS):
        raise IsolationError(
            "INVALID_OUTER_ADAPTER_TIMEOUT",
            f"{OUTER_TIMEOUT_ENV} must prove the exact 240-second parent deadline",
        )


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IsolationError("DUPLICATE_JSON_KEY", "JSON object contains a duplicate key")
        result[key] = value
    return result


def _parse_safe_integer(value: str) -> int:
    parsed = int(value)
    if not -MAX_SAFE_JSON_INTEGER <= parsed <= MAX_SAFE_JSON_INTEGER:
        raise ValueError("JSON integer exceeds the interoperable exact range")
    return parsed


def _reject_json_float(_value: str) -> float:
    raise ValueError("JSON floating-point numbers are forbidden")


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON numbers are forbidden")


def _validate_strict_json_value(value: Any, code: str) -> None:
    """Enforce the Tacua JSON value profile without recursive Python calls."""
    pending: list[tuple[Any, int]] = [(value, 0)]
    visited = 0
    while pending:
        current, depth = pending.pop()
        visited += 1
        if visited > MAX_JSON_VALUES or depth > MAX_JSON_DEPTH:
            raise IsolationError(code, "JSON value exceeds its structural bound")
        if current is None or type(current) is bool:
            continue
        if type(current) is int:
            if not -MAX_SAFE_JSON_INTEGER <= current <= MAX_SAFE_JSON_INTEGER:
                raise IsolationError(code, "JSON integer exceeds the exact interoperable range")
            continue
        if type(current) is str:
            if unicodedata.normalize("NFC", current) != current:
                raise IsolationError(code, "JSON string is not NFC-normalized")
            try:
                current.encode("utf-8")
            except UnicodeError as error:
                raise IsolationError(code, "JSON string is not valid UTF-8") from error
            continue
        if type(current) is list:
            pending.extend((item, depth + 1) for item in current)
            continue
        if type(current) is dict:
            for key, item in current.items():
                if type(key) is not str or unicodedata.normalize("NFC", key) != key:
                    raise IsolationError(code, "JSON object key is not an NFC string")
                try:
                    key.encode("utf-8")
                except UnicodeError as error:
                    raise IsolationError(code, "JSON object key is not valid UTF-8") from error
                pending.append((item, depth + 1))
            continue
        raise IsolationError(code, "JSON contains a value outside the Tacua integer-only profile")


def canonical_json(value: Any) -> bytes:
    _validate_strict_json_value(value, "INVALID_JSON_VALUE")
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _duplicate_descriptor_capability(path: str, code: str) -> int:
    match = DESCRIPTOR_PATH_RE.fullmatch(path)
    if match is None:
        raise IsolationError(code, "descriptor capability path is invalid")
    source_text = match.group(1)
    if len(source_text) > 7:
        raise IsolationError(code, "descriptor capability is outside its bound")
    source_number = int(source_text)
    if not 3 <= source_number <= MAX_SOURCE_DESCRIPTOR:
        raise IsolationError(code, "descriptor capability is outside its bound")
    try:
        descriptor = os.dup(source_number)
    except OSError as error:
        raise IsolationError(code, "descriptor capability is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        status = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or status & os.O_ACCMODE != os.O_RDONLY
            or status & getattr(os, "O_PATH", 0)
        ):
            raise IsolationError(
                code,
                "descriptor capability is not one read-only regular file",
            )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _load_canonical_object(
    path: Path,
    maximum: int,
    code: str,
    *,
    deadline: float | None = None,
    private_file: bool = False,
    descriptor_capability: bool = False,
) -> dict[str, Any]:
    _check_deadline(deadline)
    if private_file:
        if not path.is_absolute():
            raise IsolationError(code, "private artifact path must be absolute")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise IsolationError(code, "private artifact could not be opened safely") from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size <= 0
                or before.st_size > maximum
            ):
                raise IsolationError(code, "private artifact ownership, type, link count, mode, or size differs")
            blocks: list[bytes] = []
            total = 0
            while True:
                _check_deadline(deadline)
                block = os.read(descriptor, min(1_048_576, maximum - total + 1))
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    raise IsolationError(code, "artifact violates its byte bound")
                blocks.append(block)
            after = os.fstat(descriptor)
            if (
                total != before.st_size
                or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns
            ):
                raise IsolationError(code, "private artifact changed while it was read")
            raw = b"".join(blocks)
        finally:
            os.close(descriptor)
    elif (
        descriptor_capability
        and DESCRIPTOR_PATH_RE.fullmatch(str(path)) is not None
    ):
        descriptor = _duplicate_descriptor_capability(str(path), code)
        try:
            before = os.fstat(descriptor)
            if before.st_size <= 0 or before.st_size > maximum:
                raise IsolationError(code, "artifact violates its byte bound")
            blocks: list[bytes] = []
            offset = 0
            while offset < before.st_size:
                _check_deadline(deadline)
                try:
                    block = os.pread(
                        descriptor,
                        min(1_048_576, before.st_size - offset),
                        offset,
                    )
                except OSError as error:
                    raise IsolationError(
                        code,
                        "descriptor capability could not be read",
                    ) from error
                if not block:
                    raise IsolationError(
                        code,
                        "descriptor capability ended early",
                    )
                blocks.append(block)
                offset += len(block)
            after = os.fstat(descriptor)
            if (
                (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns
            ):
                raise IsolationError(
                    code,
                    "descriptor capability changed while it was read",
                )
            raw = b"".join(blocks)
        finally:
            os.close(descriptor)
    else:
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise IsolationError(code, "artifact could not be read") from error
    if not raw or len(raw) > maximum:
        raise IsolationError(code, "artifact violates its byte bound")
    _check_deadline(deadline)
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate,
            parse_int=_parse_safe_integer,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
        _validate_strict_json_value(value, code)
        encoded = canonical_json(value)
    except (UnicodeError, ValueError, RecursionError, json.JSONDecodeError, IsolationError) as error:
        raise IsolationError(code, "artifact is not strict UTF-8 JSON") from error
    if not isinstance(value, dict) or encoded != raw:
        raise IsolationError(code, "artifact must be exact canonical JSON without a trailing newline")
    return value


def _validate_model_file(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise IsolationError("INVALID_MODEL", "selected model could not be opened") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > MAX_MODEL_BYTES:
            raise IsolationError("INVALID_MODEL", "selected model must be one bounded regular file")
    finally:
        os.close(descriptor)


def load_command(path: Path, *, deadline: float | None = None) -> dict[str, Any]:
    document = _load_canonical_object(
        path,
        MAX_COMMAND_BYTES,
        "INVALID_ISOLATION_COMMAND",
        deadline=deadline,
        private_file=True,
    )
    if set(document) != {
        "argv",
        "contract_version",
        "image",
        "model_digest",
        "model_id",
        "model_path",
        "timeout_seconds",
    }:
        raise IsolationError("INVALID_ISOLATION_COMMAND", "command fields do not match the closed V1 contract")
    if document["contract_version"] != COMMAND_CONTRACT:
        raise IsolationError("INVALID_ISOLATION_COMMAND", "unsupported command contract")
    if not isinstance(document["image"], str) or not IMAGE_RE.fullmatch(document["image"]):
        raise IsolationError("INVALID_ISOLATION_COMMAND", "processor image must be digest pinned")
    if not isinstance(document["model_id"], str) or not MODEL_ID_RE.fullmatch(document["model_id"]):
        raise IsolationError("INVALID_ISOLATION_COMMAND", "model ID is invalid")
    if not isinstance(document["model_digest"], str) or not DIGEST_RE.fullmatch(document["model_digest"]):
        raise IsolationError("INVALID_ISOLATION_COMMAND", "model digest is invalid")
    model_path = document["model_path"]
    if not isinstance(model_path, str) or not model_path.startswith("/") or "\x00" in model_path:
        raise IsolationError("INVALID_ISOLATION_COMMAND", "model path must be absolute")
    if not isinstance(document["timeout_seconds"], int) or isinstance(document["timeout_seconds"], bool):
        raise IsolationError("INVALID_ISOLATION_COMMAND", "timeout must be an integer")
    if not 1 <= document["timeout_seconds"] <= MAX_CONTAINER_RUNTIME_SECONDS:
        raise IsolationError(
            "INVALID_ISOLATION_COMMAND",
            f"container timeout must be 1 through {MAX_CONTAINER_RUNTIME_SECONDS} seconds",
        )
    argv = document["argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= MAX_ARGUMENTS:
        raise IsolationError("INVALID_ISOLATION_COMMAND", "argv violates its item bound")
    if any(not isinstance(argument, str) or not argument or "\x00" in argument for argument in argv):
        raise IsolationError("INVALID_ISOLATION_COMMAND", "argv must contain non-empty strings")
    if sum(len(argument.encode("utf-8")) for argument in argv) > MAX_ARGUMENT_BYTES:
        raise IsolationError("INVALID_ISOLATION_COMMAND", "argv violates its byte bound")
    if not argv[0].startswith("/"):
        raise IsolationError("INVALID_ISOLATION_COMMAND", "processor executable must be absolute")
    for placeholder in (INPUT_PLACEHOLDER, MODEL_PLACEHOLDER):
        if argv.count(placeholder) != 1:
            raise IsolationError("INVALID_ISOLATION_COMMAND", f"{placeholder} must be one exact argument")
    if any("{" in argument or "}" in argument for argument in argv if argument not in {
        INPUT_PLACEHOLDER,
        MODEL_PLACEHOLDER,
    }):
        raise IsolationError("INVALID_ISOLATION_COMMAND", "unknown placeholder or brace in argv")
    supplied_model = Path(model_path)
    model = supplied_model.resolve(strict=True)
    if supplied_model.is_symlink() or "," in str(model) or "\n" in str(model):
        raise IsolationError("INVALID_MODEL", "model path must be a resolved path safe for an isolated copy")
    _validate_model_file(model)
    document["model_path"] = str(model)
    return document


def _copy_evidence(
    source_path: str,
    destination: Path,
    remaining: int,
    expected_digest: str,
    *,
    deadline: float | None = None,
) -> int:
    _check_deadline(deadline)
    source = _duplicate_descriptor_capability(
        source_path,
        "INVALID_EVIDENCE_INPUT",
    )
    try:
        metadata = os.fstat(source)
        if metadata.st_size < 0 or metadata.st_size > remaining:
            raise IsolationError("EVIDENCE_INPUT_LIMIT", "evidence violates the aggregate byte bound")
        destination_descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        copied = 0
        offset = 0
        digest = hashlib.sha256()
        try:
            while offset < metadata.st_size:
                _check_deadline(deadline)
                try:
                    block = os.pread(
                        source,
                        min(
                            1_048_576,
                            metadata.st_size - offset,
                            remaining - copied + 1,
                        ),
                        offset,
                    )
                except OSError as error:
                    raise IsolationError(
                        "INVALID_EVIDENCE_INPUT",
                        "one evidence descriptor could not be read",
                    ) from error
                if not block:
                    raise IsolationError(
                        "EVIDENCE_INPUT_CHANGED",
                        "evidence descriptor ended early",
                    )
                copied += len(block)
                offset += len(block)
                if copied > remaining:
                    raise IsolationError("EVIDENCE_INPUT_LIMIT", "evidence violates the aggregate byte bound")
                pending = memoryview(block)
                while pending:
                    written = os.write(destination_descriptor, pending)
                    if written <= 0:
                        raise IsolationError("EVIDENCE_COPY_FAILED", "evidence copy stopped early")
                    pending = pending[written:]
                digest.update(block)
            os.fchmod(destination_descriptor, 0o444)
            os.fsync(destination_descriptor)
        finally:
            os.close(destination_descriptor)
        final = os.fstat(source)
        if (
            copied != metadata.st_size
            or (final.st_dev, final.st_ino)
            != (metadata.st_dev, metadata.st_ino)
            or final.st_size != metadata.st_size
            or final.st_mtime_ns != metadata.st_mtime_ns
            or final.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise IsolationError("EVIDENCE_INPUT_CHANGED", "evidence changed while it was copied")
        if "sha256:" + digest.hexdigest() != expected_digest:
            raise IsolationError(
                "EVIDENCE_DIGEST_MISMATCH",
                "copied evidence does not match its source content digest",
            )
        return copied
    finally:
        os.close(source)


def _copy_selected_model(
    source_path: Path,
    destination: Path,
    expected_digest: str,
    *,
    deadline: float | None = None,
) -> None:
    _check_deadline(deadline)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        source = os.open(source_path, flags)
    except OSError as error:
        raise IsolationError("INVALID_MODEL", "selected model could not be reopened for isolation") from error
    digest = hashlib.sha256()
    total = 0
    try:
        metadata = os.fstat(source)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > MAX_MODEL_BYTES:
            raise IsolationError("INVALID_MODEL", "selected model must be one bounded regular file")
        destination_descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        try:
            while True:
                _check_deadline(deadline)
                block = os.read(source, 1_048_576)
                if not block:
                    break
                total += len(block)
                if total > MAX_MODEL_BYTES:
                    raise IsolationError("INVALID_MODEL", "selected model exceeds its byte bound")
                digest.update(block)
                pending = memoryview(block)
                while pending:
                    written = os.write(destination_descriptor, pending)
                    if written <= 0:
                        raise IsolationError("MODEL_COPY_FAILED", "selected model copy stopped early")
                    pending = pending[written:]
            os.fchmod(destination_descriptor, 0o444)
            os.fsync(destination_descriptor)
        finally:
            os.close(destination_descriptor)
        if total != metadata.st_size:
            raise IsolationError("MODEL_CHANGED", "selected model changed while it was copied")
    finally:
        os.close(source)
    copied_digest = "sha256:" + digest.hexdigest()
    if copied_digest != expected_digest:
        raise IsolationError("MODEL_DIGEST_MISMATCH", "isolated model copy does not match the command document")


def _parse_artifact_timestamp(value: Any) -> datetime:
    try:
        if type(value) is not str or not value.endswith("Z"):
            raise ValueError
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        canonical = parsed.astimezone(timezone.utc).replace(microsecond=0).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        if canonical != value:
            raise ValueError
        return parsed
    except (TypeError, ValueError) as error:
        raise IsolationError(
            "INVALID_PROCESSING_INPUT",
            "source transcript artifact timestamp is invalid",
        ) from error


def _processing_artifact_id(
    job_id: str, stage_name: str, artifact_kind: str
) -> str:
    subject = (
        "tacua.processing-stage-artifact-id@1.0.0\0"
        f"{job_id}\0{stage_name}\0{artifact_kind}"
    ).encode("utf-8")
    token = base64.urlsafe_b64encode(hashlib.sha256(subject).digest()).decode(
        "ascii"
    )
    return "artifact_" + token.rstrip("=")


def _expected_transcript_sources(source: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        segments = source["capture"]["manifest"]["segments"]
        if type(segments) is not list:
            raise TypeError
        expected: list[dict[str, Any]] = []
        for segment in segments:
            if type(segment) is not dict:
                raise TypeError
            if segment["availability"] != "available":
                continue
            reference = {
                "segment_id": segment["segment_id"],
                "sequence": segment["sequence"],
                "content_digest": segment["content"]["content_digest"],
                "start_ms": segment["time_range"]["start_ms"],
                "end_ms": segment["time_range"]["end_ms"],
            }
            if (
                type(reference["segment_id"]) is not str
                or type(reference["sequence"]) is not int
                or type(reference["content_digest"]) is not str
                or DIGEST_RE.fullmatch(reference["content_digest"]) is None
                or type(reference["start_ms"]) is not int
                or type(reference["end_ms"]) is not int
                or reference["start_ms"] < 0
                or reference["end_ms"] <= reference["start_ms"]
            ):
                raise TypeError
            expected.append(reference)
        return expected
    except (KeyError, TypeError) as error:
        raise IsolationError(
            "INVALID_PROCESSING_INPUT",
            "source capture manifest cannot bind the transcript artifact",
        ) from error


def _validate_transcript_artifact(
    artifact: Any, source: dict[str, Any]
) -> None:
    artifact_fields = {
        "contract_version",
        "media_type",
        "artifact_id",
        "artifact_kind",
        "organization_id",
        "project_id",
        "session_id",
        "job_id",
        "stage_name",
        "checkpoint_job_version",
        "created_at",
        "derived_data_expires_at",
        "payload",
        "artifact_digest",
    }
    if type(artifact) is not dict or set(artifact) != artifact_fields:
        raise IsolationError(
            "INVALID_PROCESSING_INPUT",
            "source transcript artifact fields are invalid",
        )
    encoded = canonical_json(artifact)
    digest_subject = copy.deepcopy(artifact)
    digest_subject.pop("artifact_digest")
    expected_digest = "sha256:" + hashlib.sha256(
        canonical_json(digest_subject)
    ).hexdigest()
    try:
        binding = source["binding"]
        job = source["job"]
        capture = source["capture"]
        stages = job["pipeline"]["stages"]
        if (
            type(binding) is not dict
            or type(job) is not dict
            or type(capture) is not dict
            or type(stages) is not list
            or len(stages) < 2
            or type(stages[0]) is not dict
            or type(binding["job_id"]) is not str
            or type(binding["organization_id"]) is not str
            or type(binding["project_id"]) is not str
            or type(binding["session_id"]) is not str
        ):
            raise TypeError
        transcribe = stages[0]
        checkpoint_job_version = artifact["checkpoint_job_version"]
        current_job_version = binding["job_version"]
        expected_binding = {
            "contract_version": PROCESSING_ARTIFACT_CONTRACT,
            "media_type": PROCESSING_ARTIFACT_MEDIA_TYPE,
            "artifact_id": _processing_artifact_id(
                binding["job_id"], "transcribe", "transcript"
            ),
            "artifact_kind": "transcript",
            "organization_id": binding["organization_id"],
            "project_id": binding["project_id"],
            "session_id": binding["session_id"],
            "job_id": binding["job_id"],
            "stage_name": "transcribe",
            "created_at": transcribe["completed_at"],
            "derived_data_expires_at": capture["derived_data_expires_at"],
        }
    except (IndexError, KeyError, TypeError) as error:
        raise IsolationError(
            "INVALID_PROCESSING_INPUT",
            "source transcript artifact binding is unavailable",
        ) from error
    if (
        len(encoded) > MAX_PROCESSING_ARTIFACT_BYTES
        or any(artifact[key] != value for key, value in expected_binding.items())
        or job.get("job_id") != binding["job_id"]
        or transcribe.get("name") != "transcribe"
        or transcribe.get("state") != "succeeded"
        or type(checkpoint_job_version) is not int
        or type(current_job_version) is not int
        or checkpoint_job_version < 2
        or checkpoint_job_version >= current_job_version
        or type(artifact["artifact_digest"]) is not str
        or DIGEST_RE.fullmatch(artifact["artifact_digest"]) is None
        or artifact["artifact_digest"] != expected_digest
        or _parse_artifact_timestamp(artifact["created_at"])
        >= _parse_artifact_timestamp(artifact["derived_data_expires_at"])
    ):
        raise IsolationError(
            "INVALID_PROCESSING_INPUT",
            "source transcript artifact binding, digest, or size is invalid",
        )

    payload = artifact["payload"]
    payload_fields = {
        "contract_version",
        "language_tag",
        "speech_status",
        "source_segments",
        "spans",
    }
    expected_sources = _expected_transcript_sources(source)
    if (
        type(payload) is not dict
        or set(payload) != payload_fields
        or payload.get("contract_version") != TRANSCRIPT_CONTRACT
        or type(payload.get("language_tag")) is not str
        or len(payload["language_tag"]) > 35
        or LANGUAGE_TAG_RE.fullmatch(payload["language_tag"]) is None
        or type(payload.get("speech_status")) is not str
        or payload["speech_status"] not in {"detected", "not_detected"}
        or type(payload.get("source_segments")) is not list
        or payload["source_segments"] != expected_sources
        or type(payload.get("spans")) is not list
        or len(payload["spans"]) > MAX_TRANSCRIPT_SPANS
    ):
        raise IsolationError(
            "INVALID_PROCESSING_INPUT",
            "source transcript artifact payload is invalid",
        )
    source_by_id = {
        reference["segment_id"]: reference for reference in expected_sources
    }
    ordering: list[tuple[int, int, str]] = []
    previous_end: int | None = None
    text_bytes = 0
    for span in payload["spans"]:
        if type(span) is not dict or set(span) != {
            "segment_id",
            "start_ms",
            "end_ms",
            "text",
        }:
            raise IsolationError(
                "INVALID_PROCESSING_INPUT",
                "source transcript span fields are invalid",
            )
        segment_id = span["segment_id"]
        if type(segment_id) is not str:
            raise IsolationError(
                "INVALID_PROCESSING_INPUT",
                "source transcript span is invalid",
            )
        segment = source_by_id.get(segment_id)
        start = span["start_ms"]
        end = span["end_ms"]
        text = span["text"]
        if (
            segment is None
            or type(start) is not int
            or type(end) is not int
            or start < segment["start_ms"]
            or end > segment["end_ms"]
            or end <= start
            or type(text) is not str
            or len(text) > MAX_TRANSCRIPT_TEXT_BYTES
            or not text.strip()
            or "\x00" in text
            or (previous_end is not None and start < previous_end)
        ):
            raise IsolationError(
                "INVALID_PROCESSING_INPUT",
                "source transcript span is invalid",
            )
        previous_end = end
        ordering.append((start, end, segment_id))
        text_bytes += len(text.encode("utf-8"))
        if text_bytes > MAX_TRANSCRIPT_TEXT_BYTES:
            raise IsolationError(
                "INVALID_PROCESSING_INPUT",
                "source transcript text exceeds its byte limit",
            )
    if (
        ordering != sorted(ordering)
        or (payload["speech_status"] == "detected") != bool(payload["spans"])
        or (
            payload["speech_status"] == "not_detected"
            and payload["language_tag"] != "und"
        )
    ):
        raise IsolationError(
            "INVALID_PROCESSING_INPUT",
            "source transcript status or ordering is invalid",
        )


def _validate_source_input_contract(source: dict[str, Any]) -> str:
    contract = source.get("contract_version")
    common_fields = {
        "binding",
        "capture",
        "contract_version",
        "input_digest",
        "job",
    }
    if contract == SOURCE_INPUT_CONTRACT:
        expected_fields = common_fields
        expected_pipeline = LEGACY_PIPELINE_VERSION
        result_contract = SOURCE_RESULT_CONTRACT
    elif contract == SOURCE_INPUT_CONTRACT_V11:
        expected_fields = common_fields | {"stage_inputs"}
        expected_pipeline = ARTIFACT_PIPELINE_VERSION
        result_contract = SOURCE_RESULT_CONTRACT_V11
    else:
        raise IsolationError(
            "INVALID_PROCESSING_INPUT", "unsupported source processing contract"
        )
    if (
        set(source) != expected_fields
        or type(source.get("binding")) is not dict
        or type(source.get("capture")) is not dict
        or type(source.get("job")) is not dict
        or type(source["job"].get("pipeline")) is not dict
        or source["job"]["pipeline"].get("pipeline_version")
        != expected_pipeline
    ):
        raise IsolationError(
            "INVALID_PROCESSING_INPUT",
            "source processing input fields or pipeline are invalid",
        )
    if contract == SOURCE_INPUT_CONTRACT:
        return result_contract

    stage_inputs = source["stage_inputs"]
    artifacts = stage_inputs.get("artifacts") if type(stage_inputs) is dict else None
    stage_name = source["binding"].get("stage_name")
    stages = source["job"]["pipeline"].get("stages")
    expected_stage_names = (
        "transcribe",
        "align",
        "correlate",
        "research",
        "generate_tickets",
    )
    stage_fields = {
        "name",
        "state",
        "attempt_count",
        "started_at",
        "completed_at",
        "detail",
    }
    exact_stages = (
        type(stages) is list
        and len(stages) == len(expected_stage_names)
        and all(
            type(stage) is dict
            and set(stage) == stage_fields
            and stage.get("name") == expected_name
            for expected_name, stage in zip(expected_stage_names, stages, strict=True)
        )
    )
    stage_index = 0 if stage_name == "transcribe" else 1
    current_stage = (
        stages[stage_index]
        if exact_stages
        else None
    )
    if (
        type(stage_inputs) is not dict
        or set(stage_inputs) != {"artifacts"}
        or type(artifacts) is not list
        or not exact_stages
        or type(stage_name) is not str
        or stage_name not in {"transcribe", "align"}
        or type(current_stage) is not dict
        or current_stage.get("name") != stage_name
        or current_stage.get("state") != "running"
        or (stage_name == "transcribe" and artifacts)
        or (stage_name == "align" and len(artifacts) != 1)
    ):
        raise IsolationError(
            "INVALID_PROCESSING_INPUT",
            "source processing stage inputs are invalid",
        )
    if stage_name == "align":
        _validate_transcript_artifact(artifacts[0], source)
    return result_contract


def prepare_input(
    source_path: Path,
    destination: Path,
    *,
    container_input_directory: str = "/run/tacua-input",
    deadline: float | None = None,
) -> str:
    if not container_input_directory.startswith("/tacua-private-") and container_input_directory != "/run/tacua-input":
        raise IsolationError("INVALID_CONTAINER_IDENTITY", "container input directory is not a closed runner path")
    source = _load_canonical_object(
        source_path,
        MAX_INPUT_BYTES,
        "INVALID_PROCESSING_INPUT",
        deadline=deadline,
        descriptor_capability=True,
    )
    expected_result_contract = _validate_source_input_contract(source)
    source_input_digest = source.get("input_digest")
    if not isinstance(source_input_digest, str) or not DIGEST_RE.fullmatch(source_input_digest):
        raise IsolationError("INVALID_PROCESSING_INPUT", "source input digest is missing")
    digest_subject = copy.deepcopy(source)
    digest_subject.pop("input_digest", None)
    expected_source_digest = "sha256:" + hashlib.sha256(canonical_json(digest_subject)).hexdigest()
    if source_input_digest != expected_source_digest:
        raise IsolationError("INVALID_PROCESSING_INPUT", "source input digest does not match canonical bytes")
    rewritten = copy.deepcopy(source)
    evidence_directory = destination.parent / "evidence"
    evidence_directory.mkdir(mode=0o700)
    references: list[dict[str, Any]] = []
    capture = rewritten.get("capture")
    if not isinstance(capture, dict):
        raise IsolationError("INVALID_PROCESSING_INPUT", "capture object is missing")
    for field in ("segments", "diagnostics"):
        entries = capture.get(field)
        if not isinstance(entries, list):
            raise IsolationError("INVALID_PROCESSING_INPUT", f"capture {field} must be an array")
        references.extend(entries)
    if len(references) > MAX_EVIDENCE_FILES:
        raise IsolationError("EVIDENCE_INPUT_LIMIT", "evidence file count exceeds the V1 bound")
    total = 0
    for index, reference in enumerate(references):
        if not isinstance(reference, dict) or not isinstance(reference.get("read_only_path"), str):
            raise IsolationError("INVALID_PROCESSING_INPUT", "evidence reference lacks a read-only path")
        if not DESCRIPTOR_PATH_RE.fullmatch(reference["read_only_path"]):
            raise IsolationError("INVALID_PROCESSING_INPUT", "evidence must arrive through an inherited read-only descriptor")
        content_digest = reference.get("content_digest")
        if not isinstance(content_digest, str) or not DIGEST_RE.fullmatch(content_digest):
            raise IsolationError("INVALID_PROCESSING_INPUT", "evidence reference lacks a valid content digest")
        filename = f"evidence-{index:06d}.bin"
        total += _copy_evidence(
            reference["read_only_path"],
            evidence_directory / filename,
            MAX_EVIDENCE_BYTES - total,
            content_digest,
            deadline=deadline,
        )
        reference["read_only_path"] = f"{container_input_directory}/evidence/{filename}"
    evidence_directory.chmod(0o555)
    wrapper: dict[str, Any] = {
        "contract_version": INPUT_CONTRACT,
        "isolated_input_digest": "sha256:" + "0" * 64,
        "source_input": rewritten,
        "source_input_digest": source_input_digest,
    }
    digest_subject = copy.deepcopy(wrapper)
    digest_subject.pop("isolated_input_digest")
    wrapper["isolated_input_digest"] = "sha256:" + hashlib.sha256(canonical_json(digest_subject)).hexdigest()
    encoded = canonical_json(wrapper)
    if len(encoded) > MAX_INPUT_BYTES:
        raise IsolationError("INVALID_PROCESSING_INPUT", "isolated input exceeds the V1 metadata bound")
    destination.write_bytes(encoded)
    destination.chmod(0o444)
    _check_deadline(deadline)
    return expected_result_contract


def _runtime_config_digest(
    *,
    command: list[str],
    entrypoint: str,
    environment: dict[str, str],
) -> str:
    subject = {
        "command": command,
        "entrypoint": entrypoint,
        "environment": environment,
        "stop_signal": "SIGKILL",
        "user": f"{PROCESSOR_UID}:{PROCESSOR_GID}",
        "working_directory": "/",
    }
    return "sha256:" + hashlib.sha256(canonical_json(subject)).hexdigest()


def build_docker_create(
    command: dict[str, Any],
    container_name: str,
    payload_root: str,
    staging_name: str,
) -> list[str]:
    instance = container_name.removeprefix("tacua-private-processor-")
    volume_name = f"tacua-private-payload-{instance}"
    if (
        not INSTANCE_RE.fullmatch(instance)
        or payload_root != f"/tacua-private-{instance}"
        or not VOLUME_NAME_RE.fullmatch(volume_name)
        or not STAGING_NAME_RE.fullmatch(staging_name)
        or not staging_name.startswith(f"tacua-isolated-input-{instance}-")
    ):
        raise IsolationError("INVALID_CONTAINER_IDENTITY", "container identity is not a closed runner value")
    argv = [
        f"{payload_root}/input/input.json" if value == INPUT_PLACEHOLDER else
        f"{payload_root}/model/model" if value == MODEL_PLACEHOLDER else value
        for value in command["argv"]
    ]
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": PROCESSOR_PATH,
        "TACUA_PROCESSOR_MODEL_ID": command["model_id"],
    }
    config_digest = _runtime_config_digest(
        command=argv[1:],
        entrypoint=argv[0],
        environment=environment,
    )
    return [
        "docker", "create", "--name", container_name,
        "--pull=never",
        "--no-healthcheck",
        "--network", "none",
        "--ipc", "none",
        "--init",
        "--read-only",
        "--workdir", "/",
        "--stop-signal", "SIGKILL",
        "--user", f"{PROCESSOR_UID}:{PROCESSOR_GID}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--pids-limit", PROCESSOR_PIDS,
        "--cpus", PROCESSOR_CPUS,
        "--memory", PROCESSOR_MEMORY,
        "--memory-swap", PROCESSOR_MEMORY,
        "--ulimit", "nofile=1024:1024",
        "--log-driver", "none",
        "--label", f"{PRIVATE_LABEL}=true",
        "--label", f"{CONTRACT_LABEL}={COMMAND_CONTRACT}",
        "--label", f"{INSTANCE_LABEL}={instance}",
        "--label", f"{STAGING_LABEL}={staging_name}",
        "--label", f"{ROLE_LABEL}={PROCESSOR_ROLE}",
        "--label", f"{VOLUME_LABEL}={volume_name}",
        "--label", f"{CONFIG_DIGEST_LABEL}={config_digest}",
        "--label", f"{MODEL_ID_LABEL}={command['model_id']}",
        "--label", f"{CONTAINER_RUNTIME_LABEL}={MAX_CONTAINER_RUNTIME_SECONDS}",
        "--label", f"{RUNNER_RUNTIME_LABEL}={RUNNER_HARD_BUDGET_SECONDS}",
        "--env", f"LANG={environment['LANG']}",
        "--env", f"LC_ALL={environment['LC_ALL']}",
        "--env", f"PATH={environment['PATH']}",
        "--env", f"TACUA_PROCESSOR_MODEL_ID={environment['TACUA_PROCESSOR_MODEL_ID']}",
        "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size={PROCESSOR_TMP_BYTES},uid={PROCESSOR_UID},gid={PROCESSOR_GID},mode=0700",
        "--mount", f"type=volume,source={volume_name},target={payload_root},readonly,volume-nocopy",
        "--entrypoint", argv[0],
        command["image"],
        *argv[1:],
    ]


def build_payload_carrier_create(
    command: dict[str, Any],
    carrier_name: str,
    payload_root: str,
    staging_name: str,
) -> list[str]:
    instance = carrier_name.removeprefix("tacua-private-carrier-")
    volume_name = f"tacua-private-payload-{instance}"
    if (
        not INSTANCE_RE.fullmatch(instance)
        or payload_root != f"/tacua-private-{instance}"
        or not VOLUME_NAME_RE.fullmatch(volume_name)
        or not STAGING_NAME_RE.fullmatch(staging_name)
        or not staging_name.startswith(f"tacua-isolated-input-{instance}-")
    ):
        raise IsolationError("INVALID_CONTAINER_IDENTITY", "payload carrier identity is not a closed runner value")
    entrypoint = CARRIER_ENTRYPOINT_PREFIX + instance
    carrier_command = CARRIER_COMMAND_PREFIX + instance
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": PROCESSOR_PATH,
    }
    config_digest = _runtime_config_digest(
        command=[carrier_command],
        entrypoint=entrypoint,
        environment=environment,
    )
    return [
        "docker", "create", "--name", carrier_name,
        "--pull=never",
        "--no-healthcheck",
        "--network", "none",
        "--ipc", "none",
        "--init",
        "--workdir", "/",
        "--stop-signal", "SIGKILL",
        "--user", f"{PROCESSOR_UID}:{PROCESSOR_GID}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--pids-limit", PROCESSOR_PIDS,
        "--cpus", PROCESSOR_CPUS,
        "--memory", PROCESSOR_MEMORY,
        "--memory-swap", PROCESSOR_MEMORY,
        "--ulimit", "nofile=1024:1024",
        "--log-driver", "none",
        "--label", f"{PRIVATE_LABEL}=true",
        "--label", f"{CONTRACT_LABEL}={COMMAND_CONTRACT}",
        "--label", f"{INSTANCE_LABEL}={instance}",
        "--label", f"{STAGING_LABEL}={staging_name}",
        "--label", f"{ROLE_LABEL}={CARRIER_ROLE}",
        "--label", f"{VOLUME_LABEL}={volume_name}",
        "--label", f"{CONFIG_DIGEST_LABEL}={config_digest}",
        "--label", f"{CONTAINER_RUNTIME_LABEL}={MAX_CONTAINER_RUNTIME_SECONDS}",
        "--label", f"{RUNNER_RUNTIME_LABEL}={RUNNER_HARD_BUDGET_SECONDS}",
        "--env", f"LANG={environment['LANG']}",
        "--env", f"LC_ALL={environment['LC_ALL']}",
        "--env", f"PATH={environment['PATH']}",
        "--mount", f"type=volume,source={volume_name},target={payload_root},volume-nocopy",
        "--entrypoint", entrypoint,
        command["image"],
        carrier_command,
    ]


def build_volume_create(instance: str, staging_name: str) -> list[str]:
    volume_name = f"tacua-private-payload-{instance}"
    if (
        not INSTANCE_RE.fullmatch(instance)
        or not VOLUME_NAME_RE.fullmatch(volume_name)
        or not STAGING_NAME_RE.fullmatch(staging_name)
        or not staging_name.startswith(f"tacua-isolated-input-{instance}-")
    ):
        raise IsolationError("INVALID_CONTAINER_IDENTITY", "payload volume identity is not a closed runner value")
    return [
        "docker", "volume", "create",
        "--label", f"{PRIVATE_LABEL}=true",
        "--label", f"{CONTRACT_LABEL}={COMMAND_CONTRACT}",
        "--label", f"{INSTANCE_LABEL}={instance}",
        "--label", f"{STAGING_LABEL}={staging_name}",
        "--label", f"{VOLUME_LABEL}={volume_name}",
        volume_name,
    ]


def _run_checked(
    argv: list[str],
    *,
    deadline: float | None,
    maximum_timeout: float = DOCKER_STEP_TIMEOUT_SECONDS,
    timeout_code: str = "CONTAINER_RUNTIME_FAILED",
) -> subprocess.CompletedProcess[bytes]:
    timeout = min(maximum_timeout, _remaining_seconds(deadline))
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise IsolationError(timeout_code, "container runtime command exceeded its bounded deadline") from error
    except OSError as error:
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "container runtime command failed") from error
    if result.returncode != 0:
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "container runtime rejected an isolation operation")
    if len(result.stdout) > MAX_DOCKER_OUTPUT_BYTES or len(result.stderr) > MAX_DOCKER_OUTPUT_BYTES:
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "container runtime output exceeded its byte bound")
    return result


def _run_cleanup_command(argv: list[str], cleanup_deadline: float) -> bool:
    remaining = cleanup_deadline - time.monotonic()
    if remaining <= 0:
        return False
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=min(DOCKER_CLEANUP_TIMEOUT_SECONDS, remaining),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _cleanup_container_running(container_name: str, cleanup_deadline: float) -> bool | None:
    remaining = cleanup_deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        result = subprocess.run(
            [
                "docker",
                "container",
                "inspect",
                "--format",
                "{{.State.Running}}",
                container_name,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=min(DOCKER_CLEANUP_TIMEOUT_SECONDS, remaining),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    state = result.stdout.strip()
    if state == b"true":
        return True
    if state == b"false":
        return False
    return None


def _container_running(container_id: str, deadline: float) -> bool:
    inspected = _run_checked(
        [
            "docker",
            "container",
            "inspect",
            "--format",
            "{{.State.Running}}",
            container_id,
        ],
        deadline=deadline,
    )
    state = inspected.stdout.strip()
    if state == b"true":
        return True
    if state == b"false":
        return False
    raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor state is ambiguous")


def _container_exists(container_name: str, deadline: float) -> bool:
    listed = _run_checked(
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"name=^/{container_name}$",
        ],
        deadline=deadline,
    )
    try:
        identifiers = listed.stdout.decode("ascii").splitlines()
    except UnicodeError as error:
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "container name lookup returned non-ASCII output") from error
    if not identifiers:
        return False
    if len(identifiers) == 1 and CONTAINER_ID_RE.fullmatch(identifiers[0]):
        return True
    raise IsolationError("CONTAINER_RUNTIME_FAILED", "container name lookup was ambiguous")


def _created_container_id(result: subprocess.CompletedProcess[bytes]) -> str:
    try:
        identifier = result.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "container creation returned non-ASCII identity") from error
    if not CONTAINER_ID_RE.fullmatch(identifier):
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "container creation returned an invalid identity")
    return identifier


def validate_runtime_environment(deadline: float) -> None:
    inspected = _run_checked(
        ["docker", "info", "--format", "{{json .}}"],
        deadline=deadline,
    )
    metadata = _decode_runtime_json(
        inspected.stdout,
        "PROCESSOR_RUNTIME_PREFLIGHT_FAILED",
        "container runtime preflight metadata is invalid JSON",
    )
    security_options = metadata.get("SecurityOptions") if isinstance(metadata, dict) else None
    if (
        not isinstance(metadata, dict)
        or metadata.get("CgroupVersion") != "2"
        or metadata.get("CgroupDriver") != "systemd"
        or metadata.get("MemoryLimit") is not True
        or metadata.get("PidsLimit") is not True
        or metadata.get("CpuCfsQuota") is not True
        or metadata.get("CpuCfsPeriod") is not True
        or not isinstance(security_options, list)
        or any(not isinstance(option, str) for option in security_options)
        or "name=rootless" not in security_options
        or "name=seccomp,profile=builtin" not in security_options
    ):
        raise IsolationError(
            "PROCESSOR_RUNTIME_PREFLIGHT_FAILED",
            "rootless cgroup-v2/systemd cpu-memory-pids and builtin seccomp proof is incomplete",
        )


def _stale_container_ids(deadline: float) -> list[str]:
    listed = _run_checked(
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"label={PRIVATE_LABEL}=true",
            "--filter",
            f"label={CONTRACT_LABEL}={COMMAND_CONTRACT}",
        ],
        deadline=deadline,
    )
    try:
        identifiers = listed.stdout.decode("ascii").splitlines()
    except UnicodeError as error:
        raise IsolationError("STALE_PROCESSOR_LIST_INVALID", "Docker returned a non-ASCII container ID") from error
    if (
        len(identifiers) > MAX_STALE_CONTAINERS
        or len(set(identifiers)) != len(identifiers)
        or any(not CONTAINER_ID_RE.fullmatch(identifier) for identifier in identifiers)
    ):
        raise IsolationError("STALE_PROCESSOR_LIST_INVALID", "stale processor container list is not bounded and exact")
    return identifiers


def _stale_volume_names(deadline: float) -> list[str]:
    listed = _run_checked(
        [
            "docker",
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"label={PRIVATE_LABEL}=true",
            "--filter",
            f"label={CONTRACT_LABEL}={COMMAND_CONTRACT}",
        ],
        deadline=deadline,
    )
    try:
        names = listed.stdout.decode("ascii").splitlines()
    except UnicodeError as error:
        raise IsolationError("STALE_PROCESSOR_LIST_INVALID", "Docker returned a non-ASCII volume name") from error
    if (
        len(names) > MAX_STALE_VOLUMES
        or len(set(names)) != len(names)
        or any(not VOLUME_NAME_RE.fullmatch(name) for name in names)
    ):
        raise IsolationError("STALE_PROCESSOR_LIST_INVALID", "stale processor volume list is not bounded and exact")
    return names


def _environment_map(value: Any) -> dict[str, str] | None:
    if not isinstance(value, list):
        return None
    environment: dict[str, str] = {}
    for item in value:
        if not isinstance(item, str) or "=" not in item:
            return None
        key, contents = item.split("=", 1)
        if not key or key in environment:
            return None
        environment[key] = contents
    return environment


def _network_is_disconnected(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    networks = value.get("Networks")
    if not isinstance(networks, dict) or not set(networks).issubset({"none"}):
        return False
    for attachment in networks.values():
        if not isinstance(attachment, dict):
            return False
        if any(
            attachment.get(field) not in (None, "")
            for field in (
                "Gateway", "IPAddress", "IPv6Gateway", "GlobalIPv6Address", "MacAddress"
            )
        ) or any(attachment.get(field) not in (None, 0) for field in ("IPPrefixLen", "GlobalIPv6PrefixLen")):
            return False
    return True


def _validate_stale_container(
    metadata: Any,
    expected_id: str,
    *,
    expected_role: str | None = None,
    require_created: bool = False,
) -> tuple[str, str, str, Path, str]:
    if not isinstance(metadata, dict):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor metadata is not an object")
    full_id = metadata.get("Id")
    name = metadata.get("Name")
    config = metadata.get("Config")
    host_config = metadata.get("HostConfig")
    mounts = metadata.get("Mounts")
    state = metadata.get("State")
    network_settings = metadata.get("NetworkSettings")
    if (
        not isinstance(full_id, str)
        or full_id != expected_id
        or not CONTAINER_ID_RE.fullmatch(full_id)
        or not isinstance(name, str)
        or not isinstance(config, dict)
        or not isinstance(host_config, dict)
        or not isinstance(mounts, list)
        or not isinstance(state, dict)
        or not isinstance(state.get("Running"), bool)
        or not _network_is_disconnected(network_settings)
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor metadata is incomplete")
    instance = name.removeprefix("/tacua-private-processor-")
    labels = config.get("Labels")
    image = config.get("Image")
    role = labels.get(ROLE_LABEL) if isinstance(labels, dict) else None
    if role == CARRIER_ROLE:
        instance = name.removeprefix("/tacua-private-carrier-")
    volume_name = labels.get(VOLUME_LABEL) if isinstance(labels, dict) else None
    payload_root = f"/tacua-private-{instance}"
    if (
        not INSTANCE_RE.fullmatch(instance)
        or not isinstance(labels, dict)
        or labels.get(PRIVATE_LABEL) != "true"
        or labels.get(CONTRACT_LABEL) != COMMAND_CONTRACT
        or labels.get(INSTANCE_LABEL) != instance
        or role not in (PROCESSOR_ROLE, CARRIER_ROLE)
        or (expected_role is not None and role != expected_role)
        or volume_name != f"tacua-private-payload-{instance}"
        or not isinstance(volume_name, str)
        or not VOLUME_NAME_RE.fullmatch(volume_name)
        or labels.get(CONTAINER_RUNTIME_LABEL) != str(MAX_CONTAINER_RUNTIME_SECONDS)
        or labels.get(RUNNER_RUNTIME_LABEL) != str(RUNNER_HARD_BUDGET_SECONDS)
        or not isinstance(image, str)
        or not IMAGE_RE.fullmatch(image)
        or host_config.get("NetworkMode") != "none"
        or host_config.get("ReadonlyRootfs") is not (role == PROCESSOR_ROLE)
        or host_config.get("Privileged") is not False
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor identity or sandbox differs")
    expected_environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": PROCESSOR_PATH}
    if role == PROCESSOR_ROLE:
        model_id = labels.get(MODEL_ID_LABEL)
        if not isinstance(model_id, str) or not MODEL_ID_RE.fullmatch(model_id):
            raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor model identity differs")
        expected_environment["TACUA_PROCESSOR_MODEL_ID"] = model_id
    expected_label_keys = {
        PRIVATE_LABEL,
        CONTRACT_LABEL,
        INSTANCE_LABEL,
        STAGING_LABEL,
        ROLE_LABEL,
        VOLUME_LABEL,
        CONFIG_DIGEST_LABEL,
        CONTAINER_RUNTIME_LABEL,
        RUNNER_RUNTIME_LABEL,
    }
    if role == PROCESSOR_ROLE:
        expected_label_keys.add(MODEL_ID_LABEL)
    entrypoint = config.get("Entrypoint")
    command = config.get("Cmd")
    environment = _environment_map(config.get("Env"))
    if (
        set(labels) != expected_label_keys
        or config.get("User") != f"{PROCESSOR_UID}:{PROCESSOR_GID}"
        or config.get("WorkingDir") != "/"
        or config.get("StopSignal") != "SIGKILL"
        or config.get("Healthcheck") != {"Test": ["NONE"]}
        or config.get("Volumes") not in (None, {})
        or config.get("ExposedPorts") not in (None, {})
        or environment != expected_environment
        or not isinstance(entrypoint, list)
        or len(entrypoint) != 1
        or not isinstance(entrypoint[0], str)
        or not isinstance(command, list)
        or not command
        or any(not isinstance(argument, str) or not argument or "\x00" in argument for argument in command)
        or labels.get(CONFIG_DIGEST_LABEL) != _runtime_config_digest(
            command=command,
            entrypoint=entrypoint[0],
            environment=expected_environment,
        )
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor runtime config differs")
    if role == CARRIER_ROLE and (
        entrypoint != [CARRIER_ENTRYPOINT_PREFIX + instance]
        or command != [CARRIER_COMMAND_PREFIX + instance]
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "payload carrier command differs")
    if role == PROCESSOR_ROLE and (
        not entrypoint[0].startswith("/")
        or entrypoint[0].startswith(CARRIER_ENTRYPOINT_PREFIX)
        or command.count(f"{payload_root}/input/input.json") != 1
        or command.count(f"{payload_root}/model/model") != 1
        or len(command) >= MAX_ARGUMENTS
        or sum(len(argument.encode("utf-8")) for argument in [entrypoint[0], *command]) > MAX_ARGUMENT_BYTES
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor command differs")
    expected_tmpfs = (
        {"/tmp": f"rw,nosuid,nodev,noexec,size={PROCESSOR_TMP_BYTES},uid={PROCESSOR_UID},gid={PROCESSOR_GID},mode=0700"}
        if role == PROCESSOR_ROLE else None
    )
    configured_mounts = host_config.get("Mounts")
    expected_mounts = [(volume_name, payload_root, role == PROCESSOR_ROLE)]
    if not isinstance(configured_mounts, list) or len(configured_mounts) != len(expected_mounts):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor volume configuration differs")
    configured_by_target = {
        item.get("Target"): item
        for item in configured_mounts
        if isinstance(item, dict) and isinstance(item.get("Target"), str)
    }
    if (
        host_config.get("Binds") not in (None, [])
        or (
            host_config.get("Tmpfs") != expected_tmpfs
            and not (expected_tmpfs is None and host_config.get("Tmpfs") == {})
        )
        or len(configured_by_target) != len(expected_mounts)
        or any(
            target not in configured_by_target
            or configured_by_target[target].get("Type") != "volume"
            or configured_by_target[target].get("Source") != source
            # Docker 29 omits the false-valued ReadOnly key for a writable
            # volume mount. Absence is therefore the exact writable default;
            # a processor mount still has to carry the explicit true value.
            or configured_by_target[target].get("ReadOnly", False) is not read_only
            or not isinstance(configured_by_target[target].get("VolumeOptions"), dict)
            or configured_by_target[target]["VolumeOptions"].get("NoCopy") is not True
            for source, target, read_only in expected_mounts
        )
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor has an unexpected mount")
    if (
        host_config.get("IpcMode") != "none"
        or host_config.get("CapDrop") != ["ALL"]
        or host_config.get("CapAdd") not in (None, [])
        or host_config.get("SecurityOpt") != ["no-new-privileges:true"]
        or host_config.get("PidsLimit") != int(PROCESSOR_PIDS)
        or host_config.get("NanoCpus") != 2_000_000_000
        or host_config.get("Memory") != 4_294_967_296
        or host_config.get("MemorySwap") != 4_294_967_296
        or host_config.get("Ulimits") != [{"Name": "nofile", "Hard": 1024, "Soft": 1024}]
        or host_config.get("LogConfig") != {"Type": "none", "Config": {}}
        or host_config.get("Init") is not True
        or host_config.get("RestartPolicy") != {"Name": "no", "MaximumRetryCount": 0}
        or host_config.get("AutoRemove") is not False
        or host_config.get("PortBindings") not in (None, {})
        or host_config.get("PublishAllPorts") is not False
        or host_config.get("Devices") not in (None, [])
        or host_config.get("DeviceRequests") not in (None, [])
        or host_config.get("GroupAdd") not in (None, [])
        or host_config.get("PidMode") not in (None, "")
        or host_config.get("UTSMode") not in (None, "")
        or host_config.get("UsernsMode") not in (None, "")
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor host constraints differ")
    runtime_volumes = [mount for mount in mounts if isinstance(mount, dict) and mount.get("Type") == "volume"]
    if (state["Running"] and len(runtime_volumes) != len(expected_mounts)) or len(runtime_volumes) > len(expected_mounts) or any(
        not isinstance(mount, dict)
        or mount.get("Type") not in ("volume", "tmpfs")
        or (
            mount.get("Type") == "tmpfs"
            and (
                not isinstance(expected_tmpfs, dict)
                or mount.get("Destination") not in expected_tmpfs
                or mount.get("RW") is not True
            )
        )
        for mount in mounts
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor runtime mounts differ")
    if runtime_volumes:
        runtime_by_destination = {mount.get("Destination"): mount for mount in runtime_volumes}
        if len(runtime_by_destination) != len(runtime_volumes) or any(
            target not in runtime_by_destination
            or runtime_by_destination[target].get("Name") != source
            or runtime_by_destination[target].get("Driver") != "local"
            or runtime_by_destination[target].get("RW") is not (not read_only)
            for source, target, read_only in expected_mounts
        ):
            raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor volume mode differs")
    if role == CARRIER_ROLE and (
        state.get("Status") != "created"
        or state.get("Running") is not False
        or state.get("StartedAt") != "0001-01-01T00:00:00Z"
        or metadata.get("RestartCount") != 0
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "transfer carrier was ever started")
    if require_created and (
        state.get("Status") != "created"
        or state.get("Running") is not False
        or state.get("StartedAt") != "0001-01-01T00:00:00Z"
        or metadata.get("RestartCount") != 0
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "new container was not in the exact created state")
    if metadata.get("RestartCount") != 0:
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor restart count differs")
    staging_name = labels.get(STAGING_LABEL)
    if (
        not isinstance(staging_name, str)
        or not STAGING_NAME_RE.fullmatch(staging_name)
        or not staging_name.startswith(f"tacua-isolated-input-{instance}-")
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor staging identity differs")
    staging_root = Path(tempfile.gettempdir()) / staging_name
    return full_id, instance, role, staging_root, volume_name


def _validate_stale_volume(metadata: Any, expected_name: str) -> tuple[str, str, Path]:
    if not isinstance(metadata, dict):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor volume metadata is not an object")
    name = metadata.get("Name")
    labels = metadata.get("Labels")
    if not isinstance(name, str) or name != expected_name:
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor volume name differs")
    if not VOLUME_NAME_RE.fullmatch(expected_name):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor volume name is invalid")
    instance = expected_name.removeprefix("tacua-private-payload-")
    options = metadata.get("Options")
    if (
        not INSTANCE_RE.fullmatch(instance)
        or not isinstance(labels, dict)
        or labels.get(PRIVATE_LABEL) != "true"
        or labels.get(CONTRACT_LABEL) != COMMAND_CONTRACT
        or labels.get(INSTANCE_LABEL) != instance
        or labels.get(VOLUME_LABEL) != expected_name
        or set(labels) != {PRIVATE_LABEL, CONTRACT_LABEL, INSTANCE_LABEL, STAGING_LABEL, VOLUME_LABEL}
        or metadata.get("Driver") != "local"
        or metadata.get("Scope") != "local"
        or options not in (None, {})
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor volume identity differs")
    staging_name = labels.get(STAGING_LABEL)
    if (
        not isinstance(staging_name, str)
        or not STAGING_NAME_RE.fullmatch(staging_name)
        or not staging_name.startswith(f"tacua-isolated-input-{instance}-")
    ):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor volume staging identity differs")
    return expected_name, instance, Path(tempfile.gettempdir()) / staging_name


def _decode_runtime_json(payload: bytes, code: str, detail: str) -> Any:
    try:
        return json.loads(
            payload,
            parse_int=_parse_safe_integer,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError, RecursionError, json.JSONDecodeError) as error:
        raise IsolationError(code, detail) from error


def _validate_created_container_artifact(
    container_id: str,
    role: str,
    volume_name: str,
    instance: str,
    staging_root: Path,
    deadline: float,
) -> None:
    staging_metadata = staging_root.lstat()
    if (
        not stat.S_ISDIR(staging_metadata.st_mode)
        or stat.S_ISLNK(staging_metadata.st_mode)
        or staging_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(staging_metadata.st_mode) != 0o700
        or any(staging_root.iterdir())
    ):
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "created recovery staging is not private and empty")
    inspected = _run_checked(
        ["docker", "container", "inspect", container_id],
        deadline=deadline,
    )
    metadata = _decode_runtime_json(
        inspected.stdout,
        "CONTAINER_RUNTIME_FAILED",
        "created recovery metadata is invalid JSON",
    )
    if not isinstance(metadata, list) or len(metadata) != 1 or not isinstance(metadata[0], dict):
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "created recovery metadata count differs")
    inspected_id = metadata[0].get("Id")
    if not isinstance(inspected_id, str) or inspected_id != container_id or not CONTAINER_ID_RE.fullmatch(inspected_id):
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "created recovery metadata identities differ")
    container = _validate_stale_container(
        metadata[0],
        container_id,
        expected_role=role,
        require_created=True,
    )
    inspected_volume = _run_checked(
        ["docker", "volume", "inspect", volume_name],
        deadline=deadline,
    )
    volumes = _decode_runtime_json(
        inspected_volume.stdout,
        "CONTAINER_RUNTIME_FAILED",
        "created payload volume metadata is invalid JSON",
    )
    if not isinstance(volumes, list) or len(volumes) != 1 or not isinstance(volumes[0], dict):
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "created payload volume metadata count differs")
    inspected_name = volumes[0].get("Name")
    if not isinstance(inspected_name, str) or inspected_name != volume_name:
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "created payload volume identities differ")
    payload_volume = _validate_stale_volume(volumes[0], volume_name)
    expected_staging = Path(tempfile.gettempdir()) / staging_root.name
    if (
        container[1:] != (instance, role, expected_staging, volume_name)
        or payload_volume != (volume_name, instance, expected_staging)
    ):
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "created recovery artifact bindings differ")


def _validate_created_recovery_artifacts(
    carrier_id: str,
    processor_id: str,
    volume_name: str,
    instance: str,
    staging_root: Path,
    deadline: float,
) -> None:
    """Compatibility wrapper for focused callers; the runner validates each create immediately."""
    if carrier_id == processor_id:
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "created recovery container identities collided")
    _validate_created_container_artifact(
        carrier_id, CARRIER_ROLE, volume_name, instance, staging_root, deadline
    )
    _validate_created_container_artifact(
        processor_id, PROCESSOR_ROLE, volume_name, instance, staging_root, deadline
    )


def _remove_staging_root(staging_root: Path) -> None:
    temporary_root = Path(tempfile.gettempdir()).resolve()
    if staging_root.parent.resolve() != temporary_root or not STAGING_NAME_RE.fullmatch(staging_root.name):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "staging cleanup target escaped the temporary root")
    if not staging_root.exists():
        return
    metadata = staging_root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "staging cleanup target ownership or type differs")
    for directory, child_directories, _files in os.walk(staging_root, topdown=False, followlinks=False):
        for child in child_directories:
            child_path = Path(directory) / child
            if not child_path.is_symlink():
                child_path.chmod(0o700)
        Path(directory).chmod(0o700)
    shutil.rmtree(staging_root)


def _reap_stale_containers(
    deadline: float,
    *,
    expected_container_ids: set[str] | None = None,
    expected_volume_names: set[str] | None = None,
) -> None:
    identifiers = _stale_container_ids(deadline)
    volume_names = _stale_volume_names(deadline)
    if (
        (expected_container_ids is not None and set(identifiers) != expected_container_ids)
        or (expected_volume_names is not None and set(volume_names) != expected_volume_names)
    ):
        raise IsolationError(
            "STALE_PROCESSOR_LIST_INVALID",
            "labeled recovery artifact list differs from the exact cleanup authorization",
        )
    if not identifiers and not volume_names:
        return
    validated_containers: list[tuple[str, str, str, Path, str]] = []
    if identifiers:
        inspected = _run_checked(
            ["docker", "container", "inspect", *identifiers],
            deadline=deadline,
        )
        metadata = _decode_runtime_json(
            inspected.stdout,
            "STALE_PROCESSOR_IDENTITY_INVALID",
            "stale processor metadata is invalid JSON",
        )
        if not isinstance(metadata, list) or len(metadata) != len(identifiers):
            raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor metadata count differs")
        inspected_ids: list[str] = []
        for item in metadata:
            candidate = item.get("Id") if isinstance(item, dict) else None
            if not isinstance(candidate, str) or not CONTAINER_ID_RE.fullmatch(candidate):
                raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor metadata ID type differs")
            inspected_ids.append(candidate)
        if len(set(inspected_ids)) != len(inspected_ids) or set(inspected_ids) != set(identifiers):
            raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor metadata IDs differ")
        by_id = {item["Id"]: item for item in metadata}
        validated_containers = [_validate_stale_container(by_id[identifier], identifier) for identifier in identifiers]
    validated_volumes: list[tuple[str, str, Path]] = []
    if volume_names:
        inspected_volumes = _run_checked(
            ["docker", "volume", "inspect", *volume_names],
            deadline=deadline,
        )
        volume_metadata = _decode_runtime_json(
            inspected_volumes.stdout,
            "STALE_PROCESSOR_IDENTITY_INVALID",
            "stale processor volume metadata is invalid JSON",
        )
        if not isinstance(volume_metadata, list) or len(volume_metadata) != len(volume_names):
            raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor volume metadata count differs")
        inspected_names: list[str] = []
        for item in volume_metadata:
            candidate = item.get("Name") if isinstance(item, dict) else None
            if not isinstance(candidate, str) or not VOLUME_NAME_RE.fullmatch(candidate):
                raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor volume name type differs")
            inspected_names.append(candidate)
        if len(set(inspected_names)) != len(inspected_names) or set(inspected_names) != set(volume_names):
            raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor volume metadata names differ")
        by_name = {item["Name"]: item for item in volume_metadata}
        validated_volumes = [_validate_stale_volume(by_name[name], name) for name in volume_names]
    volumes_by_instance = {instance: (name, staging) for name, instance, staging in validated_volumes}
    if len(volumes_by_instance) != len(validated_volumes):
        raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor volume instances are duplicated")
    containers_by_instance: dict[str, list[tuple[str, str, Path, str]]] = {}
    for container_id, instance, role, staging_root, volume_name in validated_containers:
        volume = volumes_by_instance.get(instance)
        if volume is None or volume != (volume_name, staging_root):
            raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor container and volume differ")
        artifacts = containers_by_instance.setdefault(instance, [])
        if any(existing_role == role for _id, existing_role, _staging, _volume in artifacts):
            raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "stale processor role is duplicated")
        artifacts.append((container_id, role, staging_root, volume_name))
    for volume_name, instance, staging_root in validated_volumes:
        artifacts = containers_by_instance.get(instance, [])
        for container_id, role, _container_staging, _container_volume in artifacts:
            was_running = _container_running(container_id, deadline)
            if was_running:
                _run_checked(
                    ["docker", "container", "kill", container_id],
                    deadline=deadline,
                )
            if _container_running(container_id, deadline):
                raise IsolationError("STALE_PROCESSOR_REAP_FAILED", "stale processor did not stop")
            if role == CARRIER_ROLE and was_running:
                raise IsolationError("STALE_PROCESSOR_IDENTITY_INVALID", "payload carrier was started")
        # Keep the validated, labeled container as a recovery identity until
        # its exact host staging directory is gone. An orphan labeled volume is
        # also a sufficient recovery identity for partial pre-container phases.
        try:
            _remove_staging_root(staging_root)
        except (IsolationError, OSError) as error:
            raise IsolationError(
                "STALE_PROCESSOR_REAP_FAILED",
                "stale processor staging could not be removed; recovery identity retained",
            ) from error
        for container_id, role, _container_staging, _container_volume in sorted(
            artifacts,
            key=lambda item: item[1] == PROCESSOR_ROLE,
        ):
            _run_checked(
                ["docker", "container", "rm", "--force", container_id],
                deadline=deadline,
            )
        # The Docker-managed volume contains the isolated evidence/model copy,
        # so it is deliberately removed after host staging and all containers.
        _run_checked(
            ["docker", "volume", "rm", volume_name],
            deadline=deadline,
        )
    if _stale_container_ids(deadline) or _stale_volume_names(deadline):
        raise IsolationError("STALE_PROCESSOR_REAP_FAILED", "stale Tacua processor artifacts remain")


def validate_image_metadata(payload: bytes) -> None:
    try:
        images = json.loads(
            payload,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite number")),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise IsolationError("INVALID_PROCESSOR_IMAGE", "container runtime returned invalid image metadata") from error
    if not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict):
        raise IsolationError("INVALID_PROCESSOR_IMAGE", "container runtime returned ambiguous image metadata")
    config = images[0].get("Config")
    if not isinstance(config, dict):
        raise IsolationError("INVALID_PROCESSOR_IMAGE", "selected image config is missing")
    if config.get("Volumes") not in (None, {}):
        raise IsolationError("INVALID_PROCESSOR_IMAGE", "selected image declares implicit writable volumes")
    if config.get("Labels") not in (None, {}):
        raise IsolationError("INVALID_PROCESSOR_IMAGE", "selected image declares inherited labels")
    if config.get("ExposedPorts") not in (None, {}):
        raise IsolationError("INVALID_PROCESSOR_IMAGE", "selected image declares inherited network ports")
    if config.get("Healthcheck") is not None:
        raise IsolationError("INVALID_PROCESSOR_IMAGE", "selected image declares an image-defined health command")
    environment = config.get("Env") or []
    if not isinstance(environment, list):
        raise IsolationError("INVALID_PROCESSOR_IMAGE", "selected image environment is invalid")
    allowed = {"LANG", "LC_ALL", "PATH"}
    for item in environment:
        if not isinstance(item, str) or "=" not in item or item.split("=", 1)[0] not in allowed:
            raise IsolationError("INVALID_PROCESSOR_IMAGE", "selected image declares an unexpected environment variable")


def _abort_attached_processor(
    process: subprocess.Popen[bytes],
    container_name: str,
    cleanup_deadline: float,
) -> None:
    _run_cleanup_command(
        ["docker", "container", "kill", container_name],
        cleanup_deadline,
    )
    if process.poll() is None:
        process.kill()
    if process.stdout is not None:
        process.stdout.close()
    if process.stderr is not None:
        process.stderr.close()
    remaining = cleanup_deadline - time.monotonic()
    if remaining <= 0:
        return
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        process.kill()
        remaining = cleanup_deadline - time.monotonic()
        if remaining > 0:
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                pass


def _run_attached_processor(
    container_name: str,
    deadline: float,
    cleanup_deadline: float,
) -> tuple[bytes, int, bool]:
    try:
        process = subprocess.Popen(
            ["docker", "start", "--attach", container_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "container runtime attach failed") from error
    if process.stdout is None or process.stderr is None:
        _abort_attached_processor(process, container_name, cleanup_deadline)
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "container runtime attach pipes are unavailable")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    output = bytearray()
    diagnostics = bytearray()
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _abort_attached_processor(process, container_name, cleanup_deadline)
                raise IsolationError("PROCESSOR_TIMEOUT", "isolated processor exceeded its bounded deadline")
            for key, _events in selector.select(min(0.1, remaining)):
                try:
                    block = os.read(key.fileobj.fileno(), 65_536)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                destination = output if key.data == "stdout" else diagnostics
                destination.extend(block)
                maximum = MAX_OUTPUT_STREAM_BYTES if key.data == "stdout" else MAX_DOCKER_OUTPUT_BYTES
                if len(destination) > maximum:
                    _abort_attached_processor(process, container_name, cleanup_deadline)
                    code = "PROCESSOR_OUTPUT_LIMIT" if key.data == "stdout" else "CONTAINER_RUNTIME_FAILED"
                    raise IsolationError(code, "attached processor stream exceeded its byte bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _abort_attached_processor(process, container_name, cleanup_deadline)
            raise IsolationError("PROCESSOR_TIMEOUT", "isolated processor exceeded its bounded deadline")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            _abort_attached_processor(process, container_name, cleanup_deadline)
            raise IsolationError("PROCESSOR_TIMEOUT", "isolated processor exceeded its bounded deadline") from error
    finally:
        selector.close()
    return bytes(output), return_code, bool(diagnostics)


def _validate_completed_processor(container_id: str, expected_exit_code: int, deadline: float) -> None:
    inspected = _run_checked(["docker", "container", "inspect", container_id], deadline=deadline)
    metadata = _decode_runtime_json(
        inspected.stdout,
        "CONTAINER_RUNTIME_FAILED",
        "completed processor metadata is invalid JSON",
    )
    if not isinstance(metadata, list) or len(metadata) != 1 or not isinstance(metadata[0], dict):
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "completed processor metadata count differs")
    inspected_id = metadata[0].get("Id")
    if not isinstance(inspected_id, str) or inspected_id != container_id:
        raise IsolationError("CONTAINER_RUNTIME_FAILED", "completed processor identity differs")
    _validate_stale_container(metadata[0], container_id, expected_role=PROCESSOR_ROLE)
    state = metadata[0].get("State")
    if (
        not isinstance(state, dict)
        or state.get("Running") is not False
        or state.get("Status") != "exited"
        or state.get("ExitCode") != expected_exit_code
        or state.get("OOMKilled") is not False
        or state.get("Error") not in (None, "")
    ):
        raise IsolationError("PROCESSOR_FAILED", "isolated processor completion state differs")


def _validate_output_envelope(
    payload: bytes,
    output_directory: Path,
    *,
    expected_result_contract: str = SOURCE_RESULT_CONTRACT,
    deadline: float | None = None,
) -> bytes:
    if type(expected_result_contract) is not str or expected_result_contract not in (
        SOURCE_RESULT_CONTRACT,
        SOURCE_RESULT_CONTRACT_V11,
    ):
        raise IsolationError(
            "INVALID_PROCESSOR_OUTPUT",
            "expected processor result contract is invalid",
        )
    if not payload or len(payload) > MAX_OUTPUT_STREAM_BYTES:
        raise IsolationError("PROCESSOR_OUTPUT_LIMIT", "processor output envelope violates its stream bound")
    try:
        envelope = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate,
            parse_int=_parse_safe_integer,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
        _validate_strict_json_value(envelope, "INVALID_PROCESSOR_OUTPUT")
        canonical_envelope = canonical_json(envelope)
    except (UnicodeError, ValueError, RecursionError, json.JSONDecodeError, IsolationError) as error:
        raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor output envelope is not strict JSON") from error
    if (
        not isinstance(envelope, dict)
        or canonical_envelope != payload
        or set(envelope) != {"contract_version", "previews", "result", "result_digest"}
        or envelope.get("contract_version") != OUTPUT_CONTRACT
        or not isinstance(envelope.get("result"), dict)
        or envelope["result"].get("contract_version")
        != expected_result_contract
        or not isinstance(envelope.get("previews"), list)
        or len(envelope["previews"]) > MAX_OUTPUT_FILES
        or (
            expected_result_contract == SOURCE_RESULT_CONTRACT_V11
            and (
                envelope["result"].get("disposition") != "checkpoint"
                or envelope["previews"]
            )
        )
    ):
        raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor output envelope shape differs")
    result_bytes = canonical_json(envelope["result"])
    if not 0 < len(result_bytes) <= MAX_RESULT_BYTES:
        raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor result violates its byte bound")
    expected_result_digest = "sha256:" + hashlib.sha256(result_bytes).hexdigest()
    if envelope.get("result_digest") != expected_result_digest:
        raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor result digest differs")
    referenced_previews: dict[str, tuple[int, str]] = {}
    terminal_result = envelope["result"].get("result")
    if isinstance(terminal_result, dict):
        candidates = terminal_result.get("candidates")
        if isinstance(candidates, list):
            for candidate in candidates:
                descriptors = candidate.get("previews") if isinstance(candidate, dict) else None
                if not isinstance(descriptors, list):
                    raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor result preview references differ")
                for descriptor in descriptors:
                    if not isinstance(descriptor, dict):
                        raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor result preview reference is invalid")
                    name = descriptor.get("body_file")
                    size = descriptor.get("size_bytes")
                    digest = descriptor.get("content_digest")
                    if (
                        not isinstance(name, str)
                        or not SAFE_OUTPUT_RE.fullmatch(name)
                        or name == "result.json"
                        or type(size) is not int
                        or not 1 <= size <= MAX_PREVIEW_BYTES
                        or not isinstance(digest, str)
                        or not DIGEST_RE.fullmatch(digest)
                        or name in referenced_previews
                    ):
                        raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor result preview reference is invalid")
                    referenced_previews[name] = (size, digest)
    previews: list[tuple[str, bytes]] = []
    names: list[str] = []
    total = len(result_bytes)
    for preview in envelope["previews"]:
        _check_deadline(deadline)
        if not isinstance(preview, dict) or set(preview) != {
            "content_base64", "content_digest", "name", "size_bytes"
        }:
            raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor preview shape differs")
        name = preview.get("name")
        size = preview.get("size_bytes")
        digest = preview.get("content_digest")
        encoded = preview.get("content_base64")
        if (
            not isinstance(name, str)
            or not SAFE_OUTPUT_RE.fullmatch(name)
            or name == "result.json"
            or type(size) is not int
            or not 1 <= size <= MAX_PREVIEW_BYTES
            or not isinstance(digest, str)
            or not DIGEST_RE.fullmatch(digest)
            or not isinstance(encoded, str)
            or not encoded.isascii()
            or referenced_previews.get(name) != (size, digest)
        ):
            raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor preview metadata differs")
        try:
            contents = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor preview encoding is invalid") from error
        if (
            base64.b64encode(contents).decode("ascii") != encoded
            or len(contents) != size
            or "sha256:" + hashlib.sha256(contents).hexdigest() != digest
        ):
            raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor preview bytes differ")
        total += len(contents)
        if total > MAX_OUTPUT_BYTES:
            raise IsolationError("PROCESSOR_OUTPUT_LIMIT", "processor decoded output exceeds the V1 bound")
        names.append(name)
        previews.append((name, contents))
    if (
        names != sorted(names)
        or len(set(names)) != len(names)
        or set(names) != set(referenced_previews)
    ):
        raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor preview names are not the exact referenced set")
    _publish_preview_payloads(previews, output_directory, deadline=deadline)
    return result_bytes


def _publish_preview_payloads(
    previews: list[tuple[str, bytes]],
    output_directory: Path,
    *,
    deadline: float | None = None,
) -> None:
    staged: list[tuple[Path, Path]] = []
    published: list[Path] = []
    try:
        for name, contents in previews:
            _check_deadline(deadline)
            descriptor, temporary_name = tempfile.mkstemp(dir=output_directory, prefix=".tacua-preview-")
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as destination:
                    destination.write(contents)
                    destination.flush()
                    os.fsync(destination.fileno())
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                temporary.unlink(missing_ok=True)
                raise
            temporary.chmod(0o600)
            staged.append((temporary, output_directory / name))
        expected_temporary = {temporary for temporary, _destination in staged}
        if set(output_directory.iterdir()) != expected_temporary:
            raise IsolationError("OUTPUT_DIRECTORY_CHANGED", "output directory changed before atomic preview publication")
        for temporary, destination in staged:
            os.replace(temporary, destination)
            published.append(destination)
    except Exception as error:
        for temporary, _destination in staged:
            temporary.unlink(missing_ok=True)
        for destination in published:
            destination.unlink(missing_ok=True)
        if isinstance(error, IsolationError):
            raise
        raise IsolationError("PREVIEW_PUBLICATION_FAILED", "preview publication failed safely") from error


def _collect_output(
    copied: Path,
    output_directory: Path,
    *,
    deadline: float | None = None,
) -> bytes:
    entries = sorted(copied.iterdir(), key=lambda entry: entry.name)
    if len(entries) > MAX_OUTPUT_FILES + 1:
        raise IsolationError("PROCESSOR_OUTPUT_LIMIT", "processor output file count exceeds the V1 bound")
    total = 0
    result_bytes: bytes | None = None
    previews: list[Path] = []
    for entry in entries:
        _check_deadline(deadline)
        metadata = entry.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor output must contain direct regular files only")
        total += metadata.st_size
        if total > MAX_OUTPUT_BYTES:
            raise IsolationError("PROCESSOR_OUTPUT_LIMIT", "processor output bytes exceed the V1 bound")
        if entry.name == "result.json":
            if not 0 < metadata.st_size <= MAX_RESULT_BYTES:
                raise IsolationError("INVALID_PROCESSOR_OUTPUT", "result violates its byte bound")
            result_bytes = entry.read_bytes()
            try:
                result = json.loads(
                    result_bytes,
                    object_pairs_hook=_reject_duplicate,
                    parse_int=_parse_safe_integer,
                    parse_float=_reject_json_float,
                    parse_constant=_reject_json_constant,
                )
                _validate_strict_json_value(result, "INVALID_PROCESSOR_OUTPUT")
            except (UnicodeError, ValueError, RecursionError, json.JSONDecodeError, IsolationError) as error:
                raise IsolationError("INVALID_PROCESSOR_OUTPUT", "result is not strict JSON") from error
            try:
                canonical_result = canonical_json(result)
            except (TypeError, ValueError) as error:
                raise IsolationError("INVALID_PROCESSOR_OUTPUT", "result is not canonical JSON") from error
            if not isinstance(result, dict) or canonical_result != result_bytes:
                raise IsolationError("INVALID_PROCESSOR_OUTPUT", "result must be exact canonical JSON")
        else:
            if not SAFE_OUTPUT_RE.fullmatch(entry.name):
                raise IsolationError("INVALID_PROCESSOR_OUTPUT", "output filename is unsafe")
            previews.append(entry)
    if result_bytes is None:
        raise IsolationError("INVALID_PROCESSOR_OUTPUT", "processor did not produce result.json")
    _publish_previews(previews, output_directory, deadline=deadline)
    return result_bytes


def _publish_previews(
    previews: list[Path],
    output_directory: Path,
    *,
    deadline: float | None = None,
) -> None:
    staged: list[tuple[Path, Path]] = []
    published: list[Path] = []
    try:
        for preview in previews:
            _check_deadline(deadline)
            descriptor, temporary_name = tempfile.mkstemp(
                dir=output_directory,
                prefix=".tacua-preview-",
            )
            temporary = Path(temporary_name)
            try:
                with preview.open("rb") as source, os.fdopen(descriptor, "wb") as destination:
                    while True:
                        _check_deadline(deadline)
                        block = source.read(1_048_576)
                        if not block:
                            break
                        destination.write(block)
                    destination.flush()
                    os.fsync(destination.fileno())
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                temporary.unlink(missing_ok=True)
                raise
            temporary.chmod(0o600)
            staged.append((temporary, output_directory / preview.name))
        expected_temporary = {temporary for temporary, _destination in staged}
        if set(output_directory.iterdir()) != expected_temporary:
            raise IsolationError("OUTPUT_DIRECTORY_CHANGED", "output directory changed before atomic preview publication")
        for temporary, destination in staged:
            os.replace(temporary, destination)
            published.append(destination)
    except Exception as error:
        for temporary, _destination in staged:
            temporary.unlink(missing_ok=True)
        for destination in published:
            destination.unlink(missing_ok=True)
        if isinstance(error, IsolationError):
            raise
        raise IsolationError("PREVIEW_PUBLICATION_FAILED", "preview publication failed safely") from error


def _remove_private_payload(
    payload_directory: Path,
    input_directory: Path,
    model_directory: Path,
) -> None:
    if payload_directory.is_dir():
        payload_directory.chmod(0o700)
    evidence_directory = input_directory / "evidence"
    if evidence_directory.is_dir():
        evidence_directory.chmod(0o700)
    for directory in (input_directory, model_directory):
        if directory.is_dir():
            directory.chmod(0o700)
            shutil.rmtree(directory)
    if payload_directory.is_dir():
        payload_directory.rmdir()


def _run_exclusive(
    command: dict[str, Any],
    input_path: Path,
    output_directory: Path,
    *,
    started_at: float | None = None,
) -> bytes:
    started_at = time.monotonic() if started_at is None else started_at
    work_deadline = started_at + RUNNER_WORK_BUDGET_SECONDS
    cleanup_deadline = started_at + RUNNER_HARD_BUDGET_SECONDS
    if output_directory.is_symlink() or not output_directory.is_dir() or any(output_directory.iterdir()):
        raise IsolationError("INVALID_OUTPUT_DIRECTORY", "output directory must be an empty real directory")
    validate_runtime_environment(work_deadline)
    _reap_stale_containers(work_deadline)
    image_metadata = _run_checked(
        ["docker", "image", "inspect", command["image"]],
        deadline=work_deadline,
    )
    validate_image_metadata(image_metadata.stdout)

    instance = f"{os.getpid()}-{os.urandom(12).hex()}"
    container_name = f"tacua-private-processor-{instance}"
    carrier_name = f"tacua-private-carrier-{instance}"
    volume_name = f"tacua-private-payload-{instance}"
    payload_root = f"/tacua-private-{instance}"
    staging = Path(tempfile.mkdtemp(prefix=f"tacua-isolated-input-{instance}-"))
    staging.chmod(0o700)
    volume_created = False
    carrier_created = False
    processor_created = False
    carrier_removed = False
    result_bytes: bytes | None = None
    try:
        # Create all label-bound recovery identities while host staging is
        # empty. The carrier is never started: it exposes the Docker-managed
        # volume RW only to the archive upload API. The final processor sees
        # that same volume RO under an otherwise read-only root filesystem.
        created_volume = _run_checked(
            build_volume_create(instance, staging.name),
            deadline=work_deadline,
        )
        try:
            created_volume_name = created_volume.stdout.decode("ascii").strip()
        except UnicodeError as error:
            raise IsolationError("CONTAINER_RUNTIME_FAILED", "volume creation returned non-ASCII identity") from error
        if created_volume_name != volume_name:
            raise IsolationError("CONTAINER_RUNTIME_FAILED", "volume creation returned an invalid identity")
        volume_created = True
        created_carrier = _run_checked(
            build_payload_carrier_create(
                command,
                carrier_name,
                payload_root,
                staging.name,
            ),
            deadline=work_deadline,
        )
        carrier_id = _created_container_id(created_carrier)
        carrier_created = True
        _validate_created_container_artifact(
            carrier_id,
            CARRIER_ROLE,
            volume_name,
            instance,
            staging,
            work_deadline,
        )
        created_processor = _run_checked(
            build_docker_create(
                command,
                container_name,
                payload_root,
                staging.name,
            ),
            deadline=work_deadline,
        )
        processor_id = _created_container_id(created_processor)
        processor_created = True
        if processor_id == carrier_id:
            raise IsolationError("CONTAINER_RUNTIME_FAILED", "created recovery container identities collided")
        _validate_created_container_artifact(
            processor_id,
            PROCESSOR_ROLE,
            volume_name,
            instance,
            staging,
            work_deadline,
        )
        payload_directory = staging / "payload"
        payload_directory.mkdir(mode=0o700)
        input_directory = payload_directory / "input"
        input_directory.mkdir(mode=0o700)
        expected_result_contract = prepare_input(
            input_path,
            input_directory / "input.json",
            container_input_directory=f"{payload_root}/input",
            deadline=work_deadline,
        )
        input_directory.chmod(0o555)
        model_directory = payload_directory / "model"
        model_directory.mkdir(mode=0o700)
        isolated_model = model_directory / "model"
        _copy_selected_model(
            Path(command["model_path"]),
            isolated_model,
            command["model_digest"],
            deadline=work_deadline,
        )
        model_directory.chmod(0o555)
        payload_directory.chmod(0o555)
        _run_checked(
            ["docker", "cp", str(payload_directory) + "/.", f"{carrier_name}:{payload_root}"],
            deadline=work_deadline,
            maximum_timeout=DOCKER_COPY_TIMEOUT_SECONDS,
        )
        _remove_private_payload(payload_directory, input_directory, model_directory)
        _validate_created_container_artifact(
            carrier_id,
            CARRIER_ROLE,
            volume_name,
            instance,
            staging,
            work_deadline,
        )
        _run_checked(
            ["docker", "container", "rm", "--force", carrier_name],
            deadline=work_deadline,
        )
        if _container_exists(carrier_name, work_deadline):
            raise IsolationError("CONTAINER_REMOVE_FAILED", "payload carrier remained before processor start")
        carrier_removed = True
        container_deadline = min(
            work_deadline,
            time.monotonic() + command["timeout_seconds"],
        )
        output_envelope, attach_exit_code, wrote_diagnostics = _run_attached_processor(
            container_name,
            container_deadline,
            cleanup_deadline,
        )
        waited = _run_checked(
            ["docker", "wait", container_name],
            deadline=container_deadline,
            maximum_timeout=command["timeout_seconds"],
            timeout_code="PROCESSOR_TIMEOUT",
        )
        try:
            exit_code = int(waited.stdout.strip())
        except ValueError as error:
            raise IsolationError("CONTAINER_RUNTIME_FAILED", "container runtime returned an invalid exit status") from error
        _validate_completed_processor(processor_id, exit_code, work_deadline)
        if exit_code != 0 or attach_exit_code != 0:
            raise IsolationError("PROCESSOR_FAILED", "isolated processor exited unsuccessfully")
        if wrote_diagnostics:
            raise IsolationError("INVALID_PROCESSOR_OUTPUT", "isolated processor wrote to its closed diagnostic stream")
        result_bytes = _validate_output_envelope(
            output_envelope,
            output_directory,
            expected_result_contract=expected_result_contract,
            deadline=work_deadline,
        )
    finally:
        cleanup_failure: Exception | None = None
        all_containers_stopped = True
        cleanup_targets: list[tuple[str, bool]] = [
            (carrier_name, carrier_created and not carrier_removed),
            (container_name, processor_created),
        ]
        for cleanup_name, exists in cleanup_targets:
            if not exists:
                continue
            running = _cleanup_container_running(cleanup_name, cleanup_deadline)
            if running is True:
                _run_cleanup_command(
                    ["docker", "container", "kill", cleanup_name],
                    cleanup_deadline,
                )
                running = _cleanup_container_running(cleanup_name, cleanup_deadline)
            if running is None:
                all_containers_stopped = False
                cleanup_failure = IsolationError(
                    "CONTAINER_STOP_UNVERIFIED",
                    "container stop state could not be verified",
                )
            elif running is True:
                all_containers_stopped = False
                cleanup_failure = IsolationError(
                    "CONTAINER_STOP_FAILED",
                    "container remained running after bounded kill",
                )
        staging_removed = False
        if all_containers_stopped:
            try:
                _remove_staging_root(staging)
                staging_removed = not staging.exists()
            except (IsolationError, OSError) as error:
                cleanup_failure = error
            if not staging_removed and cleanup_failure is None:
                cleanup_failure = IsolationError(
                    "STAGING_CLEANUP_FAILED",
                    "labeled staging directory remained",
                )
        containers_removed = True
        if staging_removed:
            for cleanup_name, exists in cleanup_targets:
                if exists and not _run_cleanup_command(
                    ["docker", "container", "rm", "--force", cleanup_name],
                    cleanup_deadline,
                ):
                    containers_removed = False
                    cleanup_failure = IsolationError(
                        "CONTAINER_REMOVE_FAILED",
                        "container remained after its staging directory was removed",
                    )
            if volume_created and containers_removed and not _run_cleanup_command(
                ["docker", "volume", "rm", volume_name],
                cleanup_deadline,
            ):
                cleanup_failure = IsolationError(
                    "PAYLOAD_VOLUME_REMOVE_FAILED",
                    "sensitive payload volume remained after its containers were removed",
                )
        if cleanup_failure is not None:
            raise IsolationError(
                "CONTAINER_CLEANUP_FAILED",
                "isolated processor cleanup did not complete before the runner deadline",
            ) from cleanup_failure
    assert result_bytes is not None
    return result_bytes


def run(
    command: dict[str, Any],
    input_path: Path,
    output_directory: Path,
    *,
    started_at: float | None = None,
) -> bytes:
    started_at = time.monotonic() if started_at is None else started_at
    lock_descriptor = _acquire_runner_lock()
    try:
        return _run_exclusive(
            command,
            input_path,
            output_directory,
            started_at=started_at,
        )
    finally:
        _release_runner_lock(lock_descriptor)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command-file", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    started_at = time.monotonic()
    args = parse_args()
    try:
        validate_outer_timeout_environment()
        result = run(
            load_command(
                args.command_file,
                deadline=started_at + RUNNER_WORK_BUDGET_SECONDS,
            ),
            args.input,
            args.output_directory,
            started_at=started_at,
        )
    except (IsolationError, OSError) as error:
        code = error.code if isinstance(error, IsolationError) else "ISOLATION_IO_FAILED"
        print(code, file=sys.stderr)
        return 1
    sys.stdout.buffer.write(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
