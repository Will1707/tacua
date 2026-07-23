#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, network-free processor for marked narrated Tacua captures.

The trusted host runner has already copied and verified the selected evidence
and model into one read-only payload volume.  This program performs no network
I/O.  It checkpoints the first four legacy stages and, at ``generate_tickets``,
extracts one real keyframe and one bounded narration window per explicit issue
mark.  It deliberately asks the reviewer to confirm expected behavior instead
of turning an imperfect transcript into implementation authority.
"""

from __future__ import annotations

import argparse
from array import array
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tempfile
import time
import unicodedata
import wave
from typing import Any, Iterable, Mapping


ISOLATED_INPUT_CONTRACT = "tacua.isolated-processing-input@1.0.0"
ISOLATED_OUTPUT_CONTRACT = "tacua.isolated-processing-output@1.0.0"
LOCAL_INPUT_CONTRACT = "tacua.local-processing-input@1.0.0"
LOCAL_RESULT_CONTRACT = "tacua.local-processing-result@1.0.0"
TICKET_CONTRACT = "tacua.ticket-candidate@1.0.0"
TICKET_MEDIA_TYPE = "application/vnd.tacua.ticket-candidate+json;version=1.0.0"
EVIDENCE_MANIFEST_CONTRACT = "tacua.candidate-evidence-manifest@1.0.0"
EVIDENCE_MANIFEST_MEDIA_TYPE = (
    "application/vnd.tacua.candidate-evidence-manifest+json;version=1.0.0"
)
EVIDENCE_ITEM_CONTRACT = "tacua.candidate-evidence-item@1.0.0"
WHISPER_CPP_REV = "f24588a272ae8e23280d9c220536437164e6ed28"
STAGES = ("transcribe", "align", "correlate", "research", "generate_tickets")
CHECKPOINT_STAGES = frozenset(STAGES[:-1])
MAX_INPUT_BYTES = 16_777_216
MAX_DIAGNOSTIC_BYTES = 16_777_216
MAX_PROCESSOR_MODEL_BYTES = 1_073_741_824
MAX_MARKS = 12
MAX_PREVIEW_BYTES = 2_097_152
MAX_TOTAL_PREVIEW_BYTES = 25_165_824
MAX_TRANSCRIPT_CODEPOINTS = 3_000
MAX_TITLE_CODEPOINTS = 180
MAX_SUBPROCESS_SECONDS = 120
MAX_TOOL_STDOUT_BYTES = 65_536
PROCESSOR_RUNTIME_SECONDS = 135
NARRATION_BEFORE_MS = 15_000
NARRATION_AFTER_MS = 20_000
NARRATION_FOCUS_BEFORE_MS = 7_500
NARRATION_FOCUS_AFTER_MS = 10_000
MIN_MARK_SEPARATION_MS = 12_000
MIN_ACTIVE_FRAME_RMS = 96
MIN_ACTIVE_FRAME_PEAK = 256
MIN_ACTIVE_FRAMES = 3
PCM_SAMPLE_RATE = 16_000
PCM_FRAME_SAMPLES = 320
MEDIA_THREADS = 2
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
ID_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(
        r"\b(?:gh[opusr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|"
        r"AKIA[A-Z0-9]{16})\b"
    ),
    re.compile(r"\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(
        r"(?i)(?:[?&](?:x-amz-signature|x-goog-signature|signature|sig|"
        r"access_token|token)=)[^&#\s]{8,}"
    ),
    re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
        r"[^\s/@:]+:[^\s/@]+@"
    ),
)


class ProcessorError(RuntimeError):
    """Content-free processing failure."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest(value: Any) -> str:
    return digest_bytes(value if isinstance(value, bytes) else canonical_bytes(value))


def digest_without(value: Mapping[str, Any], field: str) -> str:
    subject = copy.deepcopy(dict(value))
    subject.pop(field, None)
    return digest(subject)


def digest_file(
    path: Path,
    maximum: int,
    *,
    deadline: float | None = None,
) -> str:
    try:
        metadata = path.stat()
        if not path.is_file() or not 1 <= metadata.st_size <= maximum:
            raise ProcessorError("model file is outside its bound")
        total = 0
        hasher = hashlib.sha256()
        with path.open("rb") as source:
            while total < metadata.st_size:
                if deadline is not None and time.monotonic() >= deadline:
                    raise ProcessorError("processing deadline expired")
                block = source.read(min(1_048_576, metadata.st_size - total))
                if not block:
                    break
                total += len(block)
                hasher.update(block)
            if total != metadata.st_size or source.read(1):
                raise ProcessorError("model file changed while hashing")
    except OSError as error:
        raise ProcessorError("model file is unavailable") from error
    return "sha256:" + hasher.hexdigest()


def identifier(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts).encode("utf-8")
    suffix = hashlib.sha256(material).hexdigest()[:24]
    result = f"{prefix}_{suffix}"
    if ID_RE.fullmatch(result) is None:
        raise ProcessorError("identifier construction failed")
    return result


def strict_object(path: Path, maximum: int) -> dict[str, Any]:
    try:
        metadata = path.stat()
        if not path.is_file() or metadata.st_size < 2 or metadata.st_size > maximum:
            raise ProcessorError("input file is outside its bound")
        payload = path.read_bytes()
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        raise ProcessorError("input is not strict JSON") from error
    if not isinstance(value, dict) or canonical_bytes(value) != payload:
        raise ProcessorError("input is not canonical JSON")
    _validate_json_profile(value)
    return value


def bounded_json_object(path: Path, maximum: int) -> dict[str, Any]:
    """Read bounded third-party JSON without requiring Tacua serialization."""

    try:
        metadata = path.stat()
        if not path.is_file() or metadata.st_size < 2 or metadata.st_size > maximum:
            raise ProcessorError("JSON file is outside its bound")
        value = json.loads(
            path.read_bytes(),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        raise ProcessorError("third-party JSON is invalid") from error
    if not isinstance(value, dict):
        raise ProcessorError("third-party JSON is not an object")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_float(_value: str) -> float:
    raise ValueError("floating-point JSON is forbidden")


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON is forbidden")


def _validate_json_profile(value: Any) -> None:
    pending: list[tuple[Any, int]] = [(value, 0)]
    visited = 0
    while pending:
        current, depth = pending.pop()
        visited += 1
        if visited > 1_000_000 or depth > 64:
            raise ProcessorError("JSON exceeds its structural bound")
        if current is None or type(current) is bool:
            continue
        if type(current) is int:
            if abs(current) > 9_007_199_254_740_991:
                raise ProcessorError("JSON integer is outside the exact range")
            continue
        if type(current) is str:
            if unicodedata.normalize("NFC", current) != current or "\x00" in current:
                raise ProcessorError("JSON text is not canonical")
            continue
        if type(current) is list:
            pending.extend((child, depth + 1) for child in current)
            continue
        if type(current) is dict:
            for key, child in current.items():
                if type(key) is not str or unicodedata.normalize("NFC", key) != key:
                    raise ProcessorError("JSON key is not canonical")
                pending.append((child, depth + 1))
            continue
        raise ProcessorError("JSON contains an unsupported value")


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise ProcessorError(detail)


def require_id(value: Any, detail: str) -> str:
    require(isinstance(value, str) and ID_RE.fullmatch(value) is not None, detail)
    return value


def require_digest(value: Any, detail: str) -> str:
    require(isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None, detail)
    return value


def require_timestamp(value: Any, detail: str) -> str:
    require(isinstance(value, str) and TIMESTAMP_RE.fullmatch(value) is not None, detail)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ProcessorError(detail) from error
    return value


def validate_wrapper(document: dict[str, Any]) -> dict[str, Any]:
    require(
        set(document)
        == {
            "contract_version",
            "isolated_input_digest",
            "source_input",
            "source_input_digest",
        },
        "isolated input fields are invalid",
    )
    require(
        document["contract_version"] == ISOLATED_INPUT_CONTRACT,
        "isolated input contract is unsupported",
    )
    require_digest(document["isolated_input_digest"], "isolated input digest is invalid")
    require(
        document["isolated_input_digest"]
        == digest_without(document, "isolated_input_digest"),
        "isolated input digest changed",
    )
    source = document["source_input"]
    require(isinstance(source, dict), "source input is invalid")
    require(
        source.get("contract_version") == LOCAL_INPUT_CONTRACT,
        "only the legacy local input is supported",
    )
    require_digest(document["source_input_digest"], "source input digest is invalid")
    require_digest(source.get("input_digest"), "embedded input digest is invalid")
    require(
        document["source_input_digest"] == source["input_digest"],
        "source input provenance changed",
    )
    # The trusted runner validates the source digest before replacing admitted
    # host descriptor paths with isolated read-only payload paths.  The
    # isolated-input digest binds those rewritten bytes; source_input_digest
    # intentionally remains the pre-rewrite provenance anchor.
    binding = source.get("binding")
    job = source.get("job")
    capture = source.get("capture")
    require(
        isinstance(binding, dict)
        and isinstance(job, dict)
        and isinstance(capture, dict),
        "source input sections are invalid",
    )
    for key in (
        "organization_id",
        "project_id",
        "session_id",
        "build_id",
        "job_id",
        "worker_id",
    ):
        require_id(binding.get(key), f"binding {key} is invalid")
    require_digest(binding.get("build_identity_digest"), "build digest is invalid")
    require_digest(binding.get("job_digest"), "job digest is invalid")
    stage = binding.get("stage_name")
    require(stage in STAGES, "processing stage is invalid")
    require(
        job.get("job_id") == binding["job_id"]
        and job.get("job_digest") == binding["job_digest"]
        and job.get("session_id") == binding["session_id"]
        and job.get("build_id") == binding["build_id"]
        and job.get("build_identity_digest") == binding["build_identity_digest"]
        and job.get("organization_id") == binding["organization_id"]
        and job.get("project_id") == binding["project_id"],
        "job binding changed",
    )
    manifest = capture.get("manifest")
    require(
        isinstance(manifest, dict)
        and manifest.get("session_id") == binding["session_id"]
        and manifest.get("build_id") == binding["build_id"]
        and manifest.get("build_identity_digest") == binding["build_identity_digest"]
        and manifest.get("organization_id") == binding["organization_id"]
        and manifest.get("project_id") == binding["project_id"],
        "capture binding changed",
    )
    return source


def local_result(
    source: Mapping[str, Any],
    *,
    disposition: str,
    result: dict[str, Any] | None,
) -> dict[str, Any]:
    binding = source["binding"]
    return {
        "contract_version": LOCAL_RESULT_CONTRACT,
        "disposition": disposition,
        "input_digest": source["input_digest"],
        "job_digest": binding["job_digest"],
        "job_id": binding["job_id"],
        "result": result,
        "session_id": binding["session_id"],
        "stage_name": binding["stage_name"],
    }


def isolated_output(
    result: dict[str, Any],
    previews: Iterable[tuple[str, bytes]],
) -> dict[str, Any]:
    encoded_previews = []
    names: set[str] = set()
    total = 0
    for name, body in previews:
        require(name not in names, "preview name is duplicated")
        require(
            body.startswith(PNG_MAGIC) and 8 < len(body) <= MAX_PREVIEW_BYTES,
            "preview body is invalid",
        )
        names.add(name)
        total += len(body)
        require(total <= MAX_TOTAL_PREVIEW_BYTES, "preview output exceeds its total bound")
        encoded_previews.append(
            {
                "content_base64": base64.b64encode(body).decode("ascii"),
                "content_digest": digest_bytes(body),
                "name": name,
                "size_bytes": len(body),
            }
        )
    require(
        [item["name"] for item in encoded_previews]
        == sorted(item["name"] for item in encoded_previews),
        "preview names are not sorted",
    )
    return {
        "contract_version": ISOLATED_OUTPUT_CONTRACT,
        "previews": encoded_previews,
        "result": result,
        "result_digest": digest(result),
    }


def load_diagnostic_envelopes(source: Mapping[str, Any]) -> list[dict[str, Any]]:
    binding = source["binding"]
    envelopes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for reference in source["capture"].get("diagnostics", []):
        require(isinstance(reference, dict), "diagnostic reference is invalid")
        path = Path(reference.get("read_only_path", ""))
        envelope = strict_object(path, MAX_DIAGNOSTIC_BYTES)
        encoded = canonical_bytes(envelope)
        require(len(encoded) == reference.get("size_bytes"), "diagnostic size changed")
        require(digest_bytes(encoded) == reference.get("content_digest"), "diagnostic digest changed")
        require(
            envelope.get("contract_version") == "tacua.diagnostic-envelope@1.0.0"
            and envelope.get("organization_id") == binding["organization_id"]
            and envelope.get("project_id") == binding["project_id"]
            and envelope.get("session_id") == binding["session_id"]
            and envelope.get("build_id") == binding["build_id"]
            and envelope.get("build_identity_digest") == binding["build_identity_digest"],
            "diagnostic binding changed",
        )
        envelope_id = require_id(envelope.get("envelope_id"), "diagnostic envelope id is invalid")
        require(envelope_id not in seen, "diagnostic envelope is duplicated")
        seen.add(envelope_id)
        envelopes.append(envelope)
    return envelopes


def issue_marks(envelopes: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    marks: list[dict[str, Any]] = []
    marker_ids: set[str] = set()
    for envelope in envelopes:
        events = envelope.get("events")
        require(isinstance(events, list), "diagnostic events are invalid")
        for event in events:
            require(isinstance(event, dict), "diagnostic event is invalid")
            if event.get("event_type") != "issue_mark":
                continue
            data = event.get("data")
            require(isinstance(data, dict), "issue mark data is invalid")
            marker_id = require_id(data.get("marker_id"), "issue marker id is invalid")
            require(marker_id not in marker_ids, "issue marker is duplicated")
            marker_ids.add(marker_id)
            elapsed = data.get("narration_elapsed_ms")
            require(
                isinstance(elapsed, int)
                and not isinstance(elapsed, bool)
                and 0 <= elapsed <= 1_800_000,
                "issue marker time is invalid",
            )
            require(
                event.get("elapsed_ms") == elapsed,
                "issue marker clocks disagree",
            )
            marks.append(
                {
                    "elapsed_ms": elapsed,
                    "event_id": require_id(event.get("event_id"), "issue event id is invalid"),
                    "kind": data.get("kind"),
                    "marker_id": marker_id,
                    "occurred_at": require_timestamp(
                        event.get("occurred_at"), "issue marker timestamp is invalid"
                    ),
                    "sequence": event.get("sequence"),
                }
            )
    require(len(marks) <= MAX_MARKS, "capture has too many issue marks")
    return sorted(marks, key=lambda mark: (mark["elapsed_ms"], mark["marker_id"]))


def capture_segments(source: Mapping[str, Any]) -> list[dict[str, Any]]:
    references = {
        item["segment_id"]: item
        for item in source["capture"].get("segments", [])
        if isinstance(item, dict) and isinstance(item.get("segment_id"), str)
    }
    segments = []
    for manifest_segment in source["capture"]["manifest"].get("segments", []):
        if not isinstance(manifest_segment, dict) or manifest_segment.get("availability") != "available":
            continue
        segment_id = manifest_segment.get("segment_id")
        reference = references.get(segment_id)
        time_range = manifest_segment.get("time_range")
        require(
            isinstance(reference, dict)
            and isinstance(time_range, dict)
            and time_range.get("clock") == "session_monotonic",
            "available segment binding is invalid",
        )
        start = time_range.get("start_ms")
        end = time_range.get("end_ms")
        require(
            isinstance(start, int)
            and not isinstance(start, bool)
            and isinstance(end, int)
            and not isinstance(end, bool)
            and 0 <= start < end,
            "segment time range is invalid",
        )
        path = Path(reference.get("read_only_path", ""))
        try:
            metadata = path.stat()
        except OSError as error:
            raise ProcessorError("segment is unavailable") from error
        require(path.is_file(), "segment is not a regular file")
        require(metadata.st_size == reference.get("size_bytes"), "segment size changed")
        sequence = reference.get("sequence")
        require(
            isinstance(sequence, int)
            and not isinstance(sequence, bool)
            and sequence == manifest_segment.get("sequence"),
            "segment sequence changed",
        )
        content = manifest_segment.get("content")
        require(
            isinstance(content, dict)
            and content.get("content_digest") == reference.get("content_digest")
            and content.get("size_bytes") == reference.get("size_bytes")
            and content.get("content_type") == reference.get("content_type")
            and reference.get("content_type") in {"video/quicktime", "video/mp4"},
            "segment content binding changed",
        )
        segments.append(
            {
                "content_digest": require_digest(
                    reference.get("content_digest"), "segment digest is invalid"
                ),
                "end_ms": end,
                "path": path,
                "segment_id": require_id(segment_id, "segment id is invalid"),
                "sequence": sequence,
                "size_bytes": metadata.st_size,
                "start_ms": start,
                "content_type": reference["content_type"],
            }
        )
    return sorted(segments, key=lambda item: (item["start_ms"], item["sequence"]))


def segment_for_time(segments: Iterable[dict[str, Any]], elapsed_ms: int) -> dict[str, Any]:
    ordered = list(segments)
    for segment in ordered:
        if segment["start_ms"] <= elapsed_ms < segment["end_ms"]:
            return segment
    if ordered:
        final = max(ordered, key=lambda item: (item["end_ms"], item["sequence"]))
        if elapsed_ms == final["end_ms"]:
            return final
    raise ProcessorError("issue marker has no available media segment")


def capture_gaps(source: Mapping[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for raw in source["capture"]["manifest"].get("gaps", []):
        require(isinstance(raw, dict), "capture gap is invalid")
        time_range = raw.get("time_range")
        affected = raw.get("affected_streams")
        require(
            isinstance(time_range, dict)
            and time_range.get("clock") == "session_monotonic"
            and isinstance(affected, list)
            and affected
            and all(
                stream in {"app_video", "app_audio", "microphone", "diagnostics"}
                for stream in affected
            ),
            "capture gap fields are invalid",
        )
        start = time_range.get("start_ms")
        end = time_range.get("end_ms")
        require(
            isinstance(start, int)
            and not isinstance(start, bool)
            and isinstance(end, int)
            and not isinstance(end, bool)
            and 0 <= start <= end <= 1_800_000,
            "capture gap range is invalid",
        )
        gaps.append(
            {
                "affected_streams": frozenset(affected),
                "end_ms": end,
                "start_ms": start,
            }
        )
    return gaps


def range_intersects_gap(
    gaps: Iterable[Mapping[str, Any]],
    stream: str,
    start_ms: int,
    end_ms: int,
) -> bool:
    return any(
        stream in gap["affected_streams"]
        and gap["start_ms"] < end_ms
        and start_ms < gap["end_ms"]
        for gap in gaps
    )


def ambiguous_marker_ids(marks: list[Mapping[str, Any]]) -> set[str]:
    ambiguous: set[str] = set()
    for left, right in zip(marks, marks[1:]):
        if right["elapsed_ms"] - left["elapsed_ms"] < MIN_MARK_SEPARATION_MS:
            ambiguous.add(left["marker_id"])
            ambiguous.add(right["marker_id"])
    return ambiguous


def run_bounded(
    argv: list[str],
    *,
    timeout: int = MAX_SUBPROCESS_SECONDS,
    capture_stdout: bool = False,
    deadline: float | None = None,
) -> bytes:
    remaining = timeout
    if deadline is not None:
        remaining = min(timeout, deadline - time.monotonic())
    if remaining <= 0:
        raise ProcessorError("processing deadline expired")
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            },
        )
        if capture_stdout:
            require(process.stdout is not None, "media subprocess output is unavailable")
            output = bytearray()
            output_descriptor = process.stdout.fileno()
            os.set_blocking(output_descriptor, False)
            with selectors.DefaultSelector() as selector:
                selector.register(output_descriptor, selectors.EVENT_READ)
                output_open = True
                started_at = time.monotonic()
                while output_open or process.poll() is None:
                    now = time.monotonic()
                    subprocess_deadline = started_at + remaining
                    if now >= subprocess_deadline:
                        process.kill()
                        process.wait()
                        raise ProcessorError("media subprocess timed out")
                    events = selector.select(timeout=min(0.1, subprocess_deadline - now))
                    for key, _mask in events:
                        try:
                            chunk = os.read(
                                key.fd,
                                min(8_192, MAX_TOOL_STDOUT_BYTES + 1 - len(output)),
                            )
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(key.fd)
                            output_open = False
                            continue
                        output.extend(chunk)
                        if len(output) > MAX_TOOL_STDOUT_BYTES:
                            process.kill()
                            process.wait()
                            raise ProcessorError(
                                "media subprocess output exceeded its bound"
                            )
            return_code = process.wait()
            if return_code != 0:
                raise ProcessorError("media subprocess failed")
            return bytes(output)
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            raise ProcessorError("media subprocess timed out") from error
        if return_code != 0:
            raise ProcessorError("media subprocess failed")
        return b""
    except (OSError, subprocess.SubprocessError) as error:
        raise ProcessorError("media subprocess failed") from error
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stdout is not None:
                process.stdout.close()


def probe_microphone_stream(
    ffprobe: Path,
    media: Path,
    *,
    deadline: float | None = None,
) -> int | None:
    raw = run_bounded(
        [
            str(ffprobe),
            "-v",
            "error",
            "-select_streams",
            "a",
            "-show_entries",
            "stream=index,channels",
            "-of",
            "json",
            str(media),
        ],
        timeout=20,
        capture_stdout=True,
        deadline=deadline,
    )
    try:
        document = json.loads(raw)
        streams = document["streams"]
        require(isinstance(streams, list), "audio stream metadata is invalid")
        mono = [
            stream["index"]
            for stream in streams
            if isinstance(stream, dict)
            and isinstance(stream.get("index"), int)
            and not isinstance(stream.get("index"), bool)
            and stream["index"] >= 0
            and isinstance(stream.get("channels"), int)
            and not isinstance(stream.get("channels"), bool)
            and stream.get("channels") == 1
        ]
    except (KeyError, TypeError, ValueError) as error:
        raise ProcessorError("audio stream metadata is invalid") from error
    return mono[-1] if mono else None


def extract_keyframe(
    ffmpeg: Path,
    segment: Mapping[str, Any],
    elapsed_ms: int,
    destination: Path,
    *,
    deadline: float | None = None,
) -> bytes:
    duration_ms = segment["end_ms"] - segment["start_ms"]
    relative_ms = elapsed_ms - segment["start_ms"]
    offset_ms = max(0, min(relative_ms, max(0, duration_ms - 1)))
    for width in (1080, 720, 480):
        run_bounded(
            [
                str(ffmpeg),
                "-nostdin",
                "-v",
                "error",
                "-filter_threads",
                str(MEDIA_THREADS),
                "-threads",
                str(MEDIA_THREADS),
                "-i",
                str(segment["path"]),
                "-ss",
                f"{offset_ms / 1000:.3f}",
                "-map",
                "0:v:0",
                "-frames:v",
                "1",
                "-vf",
                f"scale=min({width}\\,iw):-2:flags=lanczos",
                "-compression_level",
                "9",
                "-threads",
                str(MEDIA_THREADS),
                "-y",
                str(destination),
            ],
            deadline=deadline,
        )
        try:
            body = destination.read_bytes()
        except OSError as error:
            raise ProcessorError("keyframe output is unavailable") from error
        require(body.startswith(PNG_MAGIC), "keyframe output is invalid")
        if 8 < len(body) <= MAX_PREVIEW_BYTES:
            return body
    raise ProcessorError("keyframe output exceeds its safe preview bound")


def narration_segments(
    segments: Iterable[Mapping[str, Any]],
    lower: int,
    upper: int,
) -> list[tuple[Mapping[str, Any], int, int]]:
    selected: list[tuple[Mapping[str, Any], int, int]] = []
    cursor = lower
    for segment in segments:
        start = max(lower, segment["start_ms"])
        end = min(upper, segment["end_ms"])
        if start >= end:
            continue
        if start > cursor:
            return []
        selected.append((segment, start, end))
        cursor = max(cursor, end)
        if cursor >= upper:
            break
    if cursor < upper:
        return []
    return selected


def read_pcm_wav(path: Path) -> array[int]:
    try:
        with wave.open(str(path), "rb") as source:
            require(
                source.getnchannels() == 1
                and source.getsampwidth() == 2
                and source.getframerate() == PCM_SAMPLE_RATE
                and source.getcomptype() == "NONE",
                "narration PCM format is invalid",
            )
            frames = source.readframes(source.getnframes())
    except (OSError, EOFError, wave.Error) as error:
        raise ProcessorError("narration PCM is invalid") from error
    require(len(frames) % 2 == 0, "narration PCM is invalid")
    samples: array[int] = array("h")
    samples.frombytes(frames)
    if sys.byteorder != "little":
        samples.byteswap()
    return samples


def write_pcm_wav(path: Path, samples: array[int]) -> None:
    encoded = array("h", samples)
    if sys.byteorder != "little":
        encoded.byteswap()
    try:
        with wave.open(str(path), "wb") as destination:
            destination.setnchannels(1)
            destination.setsampwidth(2)
            destination.setframerate(PCM_SAMPLE_RATE)
            destination.writeframes(encoded.tobytes())
    except (OSError, wave.Error) as error:
        raise ProcessorError("narration PCM could not be assembled") from error


def has_narration_signal(samples: array[int]) -> bool:
    if len(samples) < PCM_FRAME_SAMPLES:
        return False
    active = 0
    for offset in range(0, len(samples) - PCM_FRAME_SAMPLES + 1, PCM_FRAME_SAMPLES):
        frame = samples[offset : offset + PCM_FRAME_SAMPLES]
        peak = max(abs(value) for value in frame)
        mean_square = sum(value * value for value in frame) / len(frame)
        if peak >= MIN_ACTIVE_FRAME_PEAK and math.sqrt(mean_square) >= MIN_ACTIVE_FRAME_RMS:
            active += 1
            if active >= MIN_ACTIVE_FRAMES:
                return True
    return False


def select_transcript_text(
    transcript_document: Mapping[str, Any],
    *,
    marker_offset_ms: int,
) -> str | None:
    transcription = transcript_document.get("transcription")
    require(isinstance(transcription, list), "transcript output is invalid")
    focus_start = max(0, marker_offset_ms - NARRATION_FOCUS_BEFORE_MS)
    focus_end = marker_offset_ms + NARRATION_FOCUS_AFTER_MS
    selected: list[str] = []
    for item in transcription:
        require(isinstance(item, dict), "transcript segment is invalid")
        offsets = item.get("offsets")
        text = item.get("text")
        require(
            isinstance(offsets, dict)
            and isinstance(offsets.get("from"), int)
            and not isinstance(offsets.get("from"), bool)
            and isinstance(offsets.get("to"), int)
            and not isinstance(offsets.get("to"), bool)
            and 0 <= offsets["from"] <= offsets["to"]
            and isinstance(text, str),
            "transcript segment is invalid",
        )
        if offsets["from"] < focus_end and focus_start < offsets["to"]:
            selected.append(text.strip())
    text = redact_text(" ".join(part for part in selected if part))
    return text or None


def extract_narration(
    ffmpeg: Path,
    ffprobe: Path,
    whisper_cli: Path,
    model: Path,
    segments: list[Mapping[str, Any]],
    gaps: list[Mapping[str, Any]],
    elapsed_ms: int,
    capture_duration_ms: int,
    work: Path,
    *,
    deadline: float | None = None,
) -> tuple[str | None, tuple[int, int], list[dict[str, Any]]]:
    lower = max(0, elapsed_ms - NARRATION_BEFORE_MS)
    upper = min(capture_duration_ms, elapsed_ms + NARRATION_AFTER_MS)
    selected = narration_segments(segments, lower, upper)
    if (
        upper - lower < 100
        or not selected
        or range_intersects_gap(gaps, "microphone", lower, upper)
        or any(segment["content_type"] != "video/quicktime" for segment, _start, _end in selected)
        or any(segment["size_bytes"] > 104_857_600 for segment, _start, _end in selected)
    ):
        return None, (lower, upper), []

    combined: array[int] = array("h")
    sources: list[dict[str, Any]] = []
    for index, (segment, start, end) in enumerate(selected, start=1):
        stream = probe_microphone_stream(
            ffprobe,
            segment["path"],
            deadline=deadline,
        )
        if stream is None:
            return None, (lower, upper), []
        piece = work / f"narration-{index:03d}.wav"
        run_bounded(
            [
                str(ffmpeg),
                "-nostdin",
                "-v",
                "error",
                "-filter_threads",
                str(MEDIA_THREADS),
                "-threads",
                str(MEDIA_THREADS),
                "-i",
                str(segment["path"]),
                "-ss",
                f"{(start - segment['start_ms']) / 1000:.3f}",
                "-t",
                f"{(end - start) / 1000:.3f}",
                "-map",
                f"0:{stream}",
                "-vn",
                "-ac",
                "1",
                "-ar",
                str(PCM_SAMPLE_RATE),
                "-c:a",
                "pcm_s16le",
                "-threads",
                str(MEDIA_THREADS),
                "-y",
                str(piece),
            ],
            deadline=deadline,
        )
        combined.extend(read_pcm_wav(piece))
        sources.append(
            {
                "content_digest": segment["content_digest"],
                "content_type": segment["content_type"],
                "end_ms": end,
                "segment_id": segment["segment_id"],
                "size_bytes": segment["size_bytes"],
                "start_ms": start,
            }
        )
    if not has_narration_signal(combined):
        return None, (lower, upper), []

    wav = work / "narration.wav"
    write_pcm_wav(wav, combined)
    output_prefix = work / "transcript"
    run_bounded(
        [
            str(whisper_cli),
            "-m",
            str(model),
            "-f",
            str(wav),
            "-l",
            "en",
            "-t",
            "2",
            "-oj",
            "-of",
            str(output_prefix),
            "--no-prints",
        ],
        deadline=deadline,
    )
    transcript_document = bounded_json_object(Path(f"{output_prefix}.json"), 4_194_304)
    text = select_transcript_text(
        transcript_document,
        marker_offset_ms=elapsed_ms - lower,
    )
    return text, (lower, upper), sources if text else []


def redact_text(text: str) -> str:
    result = unicodedata.normalize("NFC", " ".join(text.split()))
    for pattern in SECRET_PATTERNS:
        result = pattern.sub("[redacted credential]", result)
    return result[:MAX_TRANSCRIPT_CODEPOINTS].strip()


def clean_title(transcript: str | None, ordinal: int) -> str:
    if transcript:
        first = re.split(r"(?<=[.!?])\s+", transcript, maxsplit=1)[0]
        first = first.strip(" \t\r\n-:;,.!?")
        if first:
            return f"Marked QA finding: {first[:MAX_TITLE_CODEPOINTS - 19]}"
    return f"Marked QA finding {ordinal}"


def seal_evidence_item(item: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(item))
    result["evidence_item_digest"] = digest_without(result, "evidence_item_digest")
    return result


def seal_evidence_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(manifest))
    result["items"] = [seal_evidence_item(item) for item in result["items"]]
    result["manifest_digest"] = digest_without(result, "manifest_digest")
    return result


def candidate_content_subject(candidate: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "contract_version": candidate["contract_version"],
        "organization_id": candidate["organization_id"],
        "project_id": candidate["project_id"],
        "build_id": candidate["build_id"],
        "build_identity_digest": candidate["build_identity_digest"],
        "session_id": candidate["session_id"],
        "evidence_manifest": candidate["evidence_manifest"],
        "candidate_id": candidate["candidate_id"],
        "content": candidate["content"],
    }


def seal_candidate(candidate: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(candidate))
    result["candidate_content_digest"] = digest(candidate_content_subject(result))
    result["candidate_digest"] = digest_without(result, "candidate_digest")
    return result


def evidence_item(
    source: Mapping[str, Any],
    *,
    evidence_id: str,
    evidence_type: str,
    description: str,
    content: bytes | None,
    content_type: str,
    content_digest: str | None = None,
    size_bytes: int | None = None,
    captured_at: str,
    start_ms: int,
    end_ms: int,
) -> dict[str, Any]:
    binding = source["binding"]
    if content is not None:
        require(content_digest is None and size_bytes is None, "evidence content binding is ambiguous")
        content_digest = digest_bytes(content)
        size_bytes = len(content)
    else:
        require_digest(content_digest, "evidence content digest is invalid")
        require(
            isinstance(size_bytes, int)
            and not isinstance(size_bytes, bool)
            and 0 < size_bytes <= 104_857_600,
            "evidence content size is invalid",
        )
    return {
        "availability": "available",
        "contract_version": EVIDENCE_ITEM_CONTRACT,
        "description": description,
        "evidence_id": evidence_id,
        "evidence_item_digest": "sha256:" + "0" * 64,
        "evidence_type": evidence_type,
        "organization_id": binding["organization_id"],
        "project_id": binding["project_id"],
        "reference": {
            "content_digest": content_digest,
            "content_type": content_type,
            "locator": {
                "evidence_id": evidence_id,
                "organization_id": binding["organization_id"],
                "project_id": binding["project_id"],
                "revision_id": identifier("revision", binding["session_id"], evidence_id),
                "scheme": "tacua-evidence",
            },
            "size_bytes": size_bytes,
        },
        "session_id": binding["session_id"],
        "source": {
            "captured_at": captured_at,
            "component": "mobile_sdk",
            "snapshot_revision": source["capture"]["manifest"]["manifest_digest"],
            "source_id": identifier("sdk", binding["session_id"]),
        },
        "time_range": {
            "clock": "session_monotonic",
            "end_ms": end_ms,
            "start_ms": start_ms,
        },
        "unavailable": None,
    }


def build_candidate_bundle(
    source: Mapping[str, Any],
    *,
    mark: Mapping[str, Any],
    ordinal: int,
    keyframe: bytes,
    transcript: str | None,
    narration_sources: list[Mapping[str, Any]],
    model_id: str,
    model_digest: str,
    created_at: str,
) -> tuple[dict[str, Any], str, bytes]:
    binding = source["binding"]
    require_digest(model_digest, "processor model digest is invalid")
    marker_key = (binding["session_id"], mark["marker_id"], ordinal)
    candidate_id = identifier("candidate", *marker_key)
    frame_id = identifier("evidence", *marker_key, "frame")
    manifest_id = identifier("manifest", *marker_key)
    frame_file = f"frame-{ordinal:03d}.png"
    frame_item = evidence_item(
        source,
        evidence_id=frame_id,
        evidence_type="media.keyframe",
        description="Screen captured at the explicit issue mark.",
        content=keyframe,
        content_type="image/png",
        captured_at=mark["occurred_at"],
        start_ms=mark["elapsed_ms"],
        end_ms=mark["elapsed_ms"],
    )
    items = [frame_item]
    evidence_ids = [frame_id]
    cited_ids = [frame_id]
    if transcript:
        require(narration_sources, "transcript has no retained source clip")
        for narration_source in narration_sources:
            clip_id = identifier(
                "evidence",
                *marker_key,
                "clip",
                narration_source["segment_id"],
            )
            items.append(
                evidence_item(
                    source,
                    evidence_id=clip_id,
                    evidence_type="media.clip",
                    description=(
                        "Retained microphone-bearing capture segment used for the unconfirmed "
                        "offline transcription around this issue mark."
                    ),
                    content=None,
                    content_type=narration_source["content_type"],
                    content_digest=narration_source["content_digest"],
                    size_bytes=narration_source["size_bytes"],
                    captured_at=mark["occurred_at"],
                    start_ms=narration_source["start_ms"],
                    end_ms=narration_source["end_ms"],
                )
            )
            evidence_ids.append(clip_id)
            cited_ids.append(clip_id)
    manifest = seal_evidence_manifest(
        {
            "contract_version": EVIDENCE_MANIFEST_CONTRACT,
            "items": items,
            "manifest_digest": "sha256:" + "0" * 64,
            "manifest_id": manifest_id,
            "media_type": EVIDENCE_MANIFEST_MEDIA_TYPE,
            "organization_id": binding["organization_id"],
            "project_id": binding["project_id"],
            "session_id": binding["session_id"],
        }
    )
    evidence_ids = sorted(evidence_ids)
    narrative = (
        (
            "An explicit issue mark was recorded at the attached frame. "
            f'Unconfirmed offline microphone transcription: "{transcript}"'
        )
        if transcript
        else (
            "An explicit issue mark was recorded at the attached frame, but no trustworthy "
            "microphone transcription was available."
        )
    )
    observed_claim_id = identifier("claim", candidate_id, "observed")
    expected_claim_id = identifier("claim", candidate_id, "expected")
    candidate = {
        "approval": None,
        "build_id": binding["build_id"],
        "build_identity_digest": binding["build_identity_digest"],
        "candidate_content_digest": "sha256:" + "0" * 64,
        "candidate_created_at": created_at,
        "candidate_digest": "sha256:" + "0" * 64,
        "candidate_id": candidate_id,
        "candidate_version": 1,
        "content": {
            "acceptance_criteria": [
                {
                    "claim_refs": [expected_claim_id],
                    "criterion": (
                        "The reviewer-confirmed expected behavior is implemented, and the marked "
                        "flow no longer reproduces the marked finding."
                    ),
                    "criterion_id": identifier("criterion", candidate_id, "confirmed"),
                    "evidence_refs": cited_ids,
                    "verification": (
                        "Repeat the captured QA flow in a new build and compare the result with "
                        "the confirmed expectation and attached frame."
                    ),
                }
            ],
            "actual_behavior": {
                "claim_refs": [observed_claim_id],
                "evidence_refs": cited_ids,
                "text": narrative,
            },
            "claims": [
                {
                    "claim_id": observed_claim_id,
                    "confidence": "low",
                    "evidence_refs": cited_ids,
                    "kind": "observed",
                    "statement": narrative,
                    "support": "inferred",
                },
                {
                    "claim_id": expected_claim_id,
                    "confidence": "unknown",
                    "evidence_refs": [],
                    "kind": "expected",
                    "statement": (
                        "The intended corrected behavior has not yet been confirmed by a human."
                    ),
                    "support": "unknown",
                },
            ],
            "clarifications": [
                {
                    "choices": [
                        {
                            "choice_id": identifier("choice", candidate_id, "transcript"),
                            "consequence": (
                                "The implementation ticket will use the unconfirmed offline "
                                "transcription as its intended change only after reviewer confirmation."
                            ),
                            "description": (
                                "Confirm the offline transcription as the expected behavior."
                            ),
                            "evidence_refs": cited_ids,
                            "label": "Use transcribed intent",
                            "presentation": {
                                "evidence_ref": frame_id,
                                "kind": "evidence_thumbnail",
                                "value": None,
                            },
                            "requires_note": False,
                        },
                        {
                            "choice_id": identifier("choice", candidate_id, "describe"),
                            "consequence": (
                                "The implementation ticket will use the reviewer's written expected "
                                "result instead of inferring one."
                            ),
                            "description": "Add the precise expected behavior in a short note.",
                            "evidence_refs": cited_ids,
                            "label": "Add expected result",
                            "presentation": {
                                "evidence_ref": None,
                                "kind": "text",
                                "value": "Describe the expected result",
                            },
                            "requires_note": True,
                        },
                        {
                            "choice_id": identifier("choice", candidate_id, "dismiss"),
                            "consequence": "The marked finding will not be handed to an implementation agent.",
                            "description": "Dismiss this mark if it was accidental or is no longer relevant.",
                            "evidence_refs": [frame_id],
                            "label": "Dismiss finding",
                            "presentation": {
                                "evidence_ref": None,
                                "kind": "text",
                                "value": "No change",
                            },
                            "requires_note": False,
                        },
                    ],
                    "clarification_id": identifier("clarification", candidate_id, "expected"),
                    "impact": "blocking",
                    "question": "What exact behavior should replace the marked problem?",
                    "resolution_note": None,
                    "selected_choice_id": None,
                    "status": "unresolved",
                    "target": "expected_behavior",
                }
            ],
            "expected_behavior": {
                "claim_refs": [expected_claim_id],
                "evidence_refs": cited_ids,
                "text": "Confirm the intended corrected behavior before implementation.",
            },
            "priority": "P2",
            "reproduction": {
                "attempts": 1,
                "preconditions": [
                    {
                        "claim_refs": [],
                        "evidence_refs": [],
                        "precondition_id": identifier("precondition", candidate_id, "build"),
                        "text": "Use the QA build bound to this capture session.",
                    }
                ],
                "reproductions": 1,
                "steps": [
                    {
                        "action": (
                            "Follow the SDK route and interaction timeline immediately before the "
                            "issue mark, then inspect the attached screen."
                        ),
                        "actual_result": narrative,
                        "claim_refs": [observed_claim_id],
                        "confidence": "low",
                        "evidence_refs": cited_ids,
                        "expected_result": None,
                        "step_id": identifier("step", candidate_id, "inspect"),
                    }
                ],
            },
            "scope": {
                "in_scope": [
                    "Investigate and correct the reviewer-confirmed behavior at this marked point."
                ],
                "out_of_scope": [
                    "Do not infer repository, backend, Sentry, or PostHog evidence that was not collected.",
                    "Do not deploy or merge from this unapproved candidate.",
                ],
            },
            "summary": {
                "claim_refs": [observed_claim_id],
                "evidence_refs": cited_ids,
                "text": narrative,
            },
            "title": clean_title(transcript, ordinal),
            "uncertainty": {
                "items": [
                    {
                        "evidence_refs": cited_ids,
                        "impact": "blocking",
                        "statement": (
                            "Expected behavior is intentionally unresolved until a human confirms "
                            "the transcription or supplies a precise result."
                        ),
                        "uncertainty_id": identifier("uncertainty", candidate_id, "expected"),
                    },
                    *(
                        [
                            {
                                "evidence_refs": sorted(cited_ids[1:]),
                                "impact": "non_blocking",
                                "statement": (
                                    "The microphone wording is an unconfirmed offline transcription "
                                    f"from model {model_id} ({model_digest}) using whisper.cpp revision "
                                    f"{WHISPER_CPP_REV[:12]}; verify it against the retained clip."
                                ),
                                "uncertainty_id": identifier(
                                    "uncertainty", candidate_id, "transcription"
                                ),
                            }
                        ]
                        if transcript
                        else []
                    ),
                ],
                "overall_confidence": "low",
            },
        },
        "contract_version": TICKET_CONTRACT,
        "evidence_manifest": {
            "evidence_ids": evidence_ids,
            "manifest_digest": manifest["manifest_digest"],
            "manifest_id": manifest_id,
        },
        "lineage": {"operation": "generated", "parents": []},
        "media_type": TICKET_MEDIA_TYPE,
        "organization_id": binding["organization_id"],
        "previous_candidate_digest": None,
        "project_id": binding["project_id"],
        "rejection": None,
        "review": {
            "last_human_actor_id": None,
            "last_reviewed_at": None,
            "notes": [],
            "reviewer_action_required": False,
            "status": "unreviewed",
        },
        "session_id": binding["session_id"],
        "state": "draft",
        "transition": {
            "actor": {
                "actor_id": binding["worker_id"],
                "actor_type": "system",
            },
            "from_state": None,
            "occurred_at": created_at,
            "reason": "processing_job_generated_candidate",
            "to_state": "draft",
        },
        "version_created_at": created_at,
    }
    candidate = seal_candidate(candidate)
    bundle = {
        "candidate": candidate,
        "evidence_manifest": manifest,
        "previews": [
            {
                "body_file": frame_file,
                "content_digest": digest_bytes(keyframe),
                "content_type": "image/png",
                "evidence_id": frame_id,
                "preview_revision_id": identifier("preview", candidate_id, "frame"),
                "size_bytes": len(keyframe),
            }
        ],
    }
    return bundle, frame_file, keyframe


def generate_tickets(
    source: Mapping[str, Any],
    *,
    ffmpeg: Path,
    ffprobe: Path,
    whisper_cli: Path,
    model: Path,
    model_id: str,
    model_digest: str,
    deadline: float | None = None,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    marks = issue_marks(load_diagnostic_envelopes(source))
    if not marks:
        return (
            local_result(
                source,
                disposition="terminal",
                result={
                    "candidates": [],
                    "disposition": "no_issue_detected",
                    "summary": "No explicit issue marks were present in the completed capture.",
                },
            ),
            [],
        )
    segments = capture_segments(source)
    require(segments, "capture has no available media")
    gaps = capture_gaps(source)
    capture_duration = source["capture"]["manifest"].get("monotonic_duration_ms")
    require(
        isinstance(capture_duration, int)
        and not isinstance(capture_duration, bool)
        and 1 <= capture_duration <= 1_800_000,
        "capture duration is invalid",
    )
    ambiguous = ambiguous_marker_ids(marks)
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundles = []
    previews: list[tuple[str, bytes]] = []
    preview_bytes = 0
    with tempfile.TemporaryDirectory(prefix="tacua-offline-") as temporary:
        root = Path(temporary)
        for ordinal, mark in enumerate(marks, start=1):
            work = root / f"mark-{ordinal:03d}"
            work.mkdir(mode=0o700)
            segment = segment_for_time(segments, mark["elapsed_ms"])
            frame_start = min(mark["elapsed_ms"], capture_duration - 1)
            require(
                not range_intersects_gap(
                    gaps,
                    "app_video",
                    frame_start,
                    frame_start + 1,
                ),
                "issue marker intersects an app-video capture gap",
            )
            keyframe = extract_keyframe(
                ffmpeg,
                segment,
                mark["elapsed_ms"],
                work / "frame.png",
                deadline=deadline,
            )
            transcript: str | None = None
            narration_sources: list[dict[str, Any]] = []
            if mark["marker_id"] not in ambiguous:
                transcript, _transcript_range, narration_sources = extract_narration(
                    ffmpeg,
                    ffprobe,
                    whisper_cli,
                    model,
                    segments,
                    gaps,
                    mark["elapsed_ms"],
                    capture_duration,
                    work,
                    deadline=deadline,
                )
            bundle, name, body = build_candidate_bundle(
                source,
                mark=mark,
                ordinal=ordinal,
                keyframe=keyframe,
                transcript=transcript,
                narration_sources=narration_sources,
                model_id=model_id,
                model_digest=model_digest,
                created_at=created_at,
            )
            bundles.append(bundle)
            preview_bytes += len(body)
            require(
                preview_bytes <= MAX_TOTAL_PREVIEW_BYTES,
                "candidate previews exceed their total output bound",
            )
            previews.append((name, body))
    return (
        local_result(
            source,
            disposition="terminal",
            result={
                "candidates": bundles,
                "disposition": "candidates_created",
                "summary": (
                    f"Created {len(bundles)} conservative draft ticket candidate"
                    f"{'' if len(bundles) == 1 else 's'} from explicit issue marks."
                ),
            },
        ),
        previews,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, default=Path("/usr/bin/ffmpeg"))
    parser.add_argument("--ffprobe", type=Path, default=Path("/usr/bin/ffprobe"))
    parser.add_argument(
        "--whisper-cli",
        type=Path,
        default=Path("/usr/local/bin/whisper-cli"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        deadline = time.monotonic() + PROCESSOR_RUNTIME_SECONDS
        args = parse_args(argv)
        document = strict_object(args.input, MAX_INPUT_BYTES)
        source = validate_wrapper(document)
        require(args.model.is_file(), "model is unavailable")
        model_id = os.environ.get("TACUA_PROCESSOR_MODEL_ID", "whisper_base_en")
        require(
            MODEL_ID_RE.fullmatch(model_id) is not None
            and redact_text(model_id) == model_id,
            "model identity is invalid",
        )
        stage = source["binding"]["stage_name"]
        if stage in CHECKPOINT_STAGES:
            result = local_result(source, disposition="checkpoint", result=None)
            previews: list[tuple[str, bytes]] = []
        else:
            model_digest = digest_file(
                args.model,
                MAX_PROCESSOR_MODEL_BYTES,
                deadline=deadline,
            )
            result, previews = generate_tickets(
                source,
                ffmpeg=args.ffmpeg,
                ffprobe=args.ffprobe,
                whisper_cli=args.whisper_cli,
                model=args.model,
                model_id=model_id,
                model_digest=model_digest,
                deadline=deadline,
            )
        sys.stdout.buffer.write(canonical_bytes(isolated_output(result, previews)))
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
