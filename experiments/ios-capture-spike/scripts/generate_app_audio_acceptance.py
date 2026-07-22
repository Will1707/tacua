#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Derive and validate canonical app-audio acceptance evidence from a capture manifest."""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation, ROUND_FLOOR
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate_app_audio_acceptance.py"
SPEC = importlib.util.spec_from_file_location("tacua_app_audio_acceptance", VALIDATOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load app-audio acceptance validator")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)

MAX_MANIFEST_BYTES = 16 * 1_048_576
MAX_SEGMENTS = 2_048
MAX_ATTEMPTS = 10_000_000
ALLOWED_DROP_CAUSES = {
    "sample_data_not_ready",
    "writer_finished",
    "writer_not_writing",
    "timestamp_invalid",
    "input_backpressure",
    "append_rejected",
}


class GenerationError(ValueError):
    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}")


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GenerationError("DUPLICATE_JSON_KEY", "manifest contains a duplicate key")
        result[key] = value
    return result


def load_manifest_with_raw(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise GenerationError("MANIFEST_UNREADABLE", "capture manifest could not be read") from error
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise GenerationError("MANIFEST_SIZE_LIMIT", "capture manifest violates its byte bound")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate,
            parse_float=Decimal,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite number")),
        )
    except GenerationError:
        raise
    except (UnicodeError, ValueError, json.JSONDecodeError, InvalidOperation) as error:
        raise GenerationError("INVALID_MANIFEST", "capture manifest is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise GenerationError("INVALID_MANIFEST", "capture manifest must be an object")
    return value, raw


def load_manifest(path: Path) -> dict[str, Any]:
    return load_manifest_with_raw(path)[0]


def _integer(value: Any, field: str, *, minimum: int = 0, maximum: int = MAX_ATTEMPTS) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise GenerationError("INVALID_ACCOUNTING", f"{field} is outside its integer bound")
    return value


def _finite_decimal(value: Any, field: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise GenerationError("INVALID_MANIFEST", f"{field} must be a finite number")
    candidate = Decimal(value)
    if not candidate.is_finite():
        raise GenerationError("INVALID_MANIFEST", f"{field} must be a finite number")
    return candidate


def derive_artifact(
    manifest: dict[str, Any],
    *,
    run_id: str,
    evidence_class: str,
    source_manifest_bytes: bytes,
) -> dict[str, Any]:
    schema_version = manifest.get("schemaVersion")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 4
    ):
        raise GenerationError(
            "LEGACY_MANIFEST_UNACCOUNTED",
            "only schema-4 captures contain exact app-audio append indexes",
        )
    accounting_version = manifest.get("appAudioAppendAccountingVersion")
    if (
        not isinstance(accounting_version, int)
        or isinstance(accounting_version, bool)
        or accounting_version != 1
    ):
        raise GenerationError("ACCOUNTING_VERSION_MISSING", "manifest has no V1 accounting version")
    if manifest.get("appAudioAppendAccountingComplete") is not True:
        raise GenerationError(
            "INCOMPLETE_APP_AUDIO_ACCOUNTING",
            "interrupted or recovered writer history cannot be reconstructed",
        )
    if manifest.get("appAudioAppendUnknownRanges") != []:
        raise GenerationError(
            "INCOMPLETE_APP_AUDIO_ACCOUNTING",
            "physical acceptance cannot contain crash-reserved unknown ranges",
        )
    errors = manifest.get("errorCodes")
    if not isinstance(errors, list) or any(not isinstance(code, str) for code in errors):
        raise GenerationError("INVALID_MANIFEST", "errorCodes must be a string array")
    if errors:
        raise GenerationError("ERRORFUL_CAPTURE", "a physical acceptance run must have no stable errors")
    if manifest.get("state") != "completed":
        raise GenerationError(
            "CAPTURE_NOT_UNINTERRUPTED",
            "physical acceptance requires the gap-free completed terminal state",
        )
    gaps = manifest.get("gaps")
    if not isinstance(gaps, list) or gaps:
        raise GenerationError(
            "CAPTURE_NOT_UNINTERRUPTED",
            "physical acceptance requires an empty capture-gap list",
        )
    resume_count = _integer(manifest.get("resumeCount"), "resumeCount", maximum=MAX_SEGMENTS)
    if resume_count != 0:
        raise GenerationError(
            "INCOMPLETE_APP_AUDIO_ACCOUNTING",
            "a resumed process cannot supply uninterrupted physical acceptance evidence",
        )

    started = _finite_decimal(manifest.get("startedHostUptimeSeconds"), "startedHostUptimeSeconds")
    stopped = _finite_decimal(manifest.get("stoppedHostUptimeSeconds"), "stoppedHostUptimeSeconds")
    duration = ((stopped - started) * 1_000).to_integral_value(rounding=ROUND_FLOOR)
    if duration <= 0 or duration > VALIDATOR.MAX_SAFE_INTEGER:
        raise GenerationError("INVALID_DURATION", "capture duration is not a positive interoperable value")

    segments = manifest.get("segments")
    if not isinstance(segments, list) or not segments or len(segments) > MAX_SEGMENTS:
        raise GenerationError("INVALID_MANIFEST", "segments must be a non-empty bounded array")
    if any(not isinstance(segment, dict) for segment in segments):
        raise GenerationError("INVALID_MANIFEST", "every segment must be an object")
    ordered = sorted(segments, key=lambda segment: _integer(segment.get("index"), "segment.index", maximum=MAX_SEGMENTS - 1))
    indexes = [segment["index"] for segment in ordered]
    if len(set(indexes)) != len(indexes):
        raise GenerationError("INVALID_MANIFEST", "segment indexes must be unique")

    expected_attempt_index = 1
    appended_total = 0
    dropped_total = 0
    seen_drop_indexes: set[int] = set()
    gaps: list[dict[str, Any]] = []
    for segment in ordered:
        segment_index = segment["index"]
        start = _integer(
            segment.get("appAudioAppendAttemptStartIndex"),
            f"segment[{segment_index}].appAudioAppendAttemptStartIndex",
            minimum=1,
        )
        attempts = _integer(
            segment.get("appAudioAppendAttempts"),
            f"segment[{segment_index}].appAudioAppendAttempts",
        )
        appended = _integer(segment.get("appAudioSamples"), f"segment[{segment_index}].appAudioSamples")
        dropped = _integer(
            segment.get("droppedAppAudioSamples"),
            f"segment[{segment_index}].droppedAppAudioSamples",
            maximum=VALIDATOR.MAX_GAPS,
        )
        drops = segment.get("appAudioAppendDrops")
        if start != expected_attempt_index:
            raise GenerationError(
                "NONCONTIGUOUS_ATTEMPT_INDEXES",
                "segment app-audio attempt ranges must start at one and be contiguous",
            )
        if appended > MAX_ATTEMPTS - dropped or appended + dropped != attempts:
            raise GenerationError("APPEND_TOTAL_MISMATCH", "segment append totals are inconsistent")
        if attempts > MAX_ATTEMPTS - (expected_attempt_index - 1):
            raise GenerationError("ATTEMPT_LIMIT_EXCEEDED", "run exceeds the append-attempt bound")
        end_exclusive = start + attempts
        if not isinstance(drops, list) or len(drops) != dropped:
            raise GenerationError("DROP_COUNT_MISMATCH", "segment drop records do not match its drop count")
        exact_indexes: list[int] = []
        previous = 0
        for drop in drops:
            if not isinstance(drop, dict) or set(drop) != {"attemptIndex", "cause"}:
                raise GenerationError("INVALID_DROP_RECORD", "drop record fields are invalid")
            attempt_index = _integer(drop["attemptIndex"], "drop.attemptIndex", minimum=1)
            if drop["cause"] not in ALLOWED_DROP_CAUSES:
                raise GenerationError("INVALID_DROP_RECORD", "drop cause is not a closed V1 value")
            if attempt_index < start or attempt_index >= end_exclusive or attempt_index <= previous:
                raise GenerationError("INVALID_DROP_INDEX", "drop indexes must be ordered within their segment range")
            if attempt_index in seen_drop_indexes:
                raise GenerationError("DUPLICATE_DROP_INDEX", "one append attempt is recorded more than once")
            seen_drop_indexes.add(attempt_index)
            exact_indexes.append(attempt_index)
            previous = attempt_index
        if exact_indexes:
            if len(gaps) >= VALIDATOR.MAX_GAPS:
                raise GenerationError("GAP_LIMIT_EXCEEDED", "drop grouping exceeds the acceptance bound")
            gaps.append({
                "dropped_attempt_indexes": exact_indexes,
                "gap_id": f"gap-app-audio-{len(gaps) + 1:04d}",
                "reason": "app_audio_append_drop",
            })
        appended_total += appended
        if dropped_total > VALIDATOR.MAX_GAPS - dropped:
            raise GenerationError("DROP_LIMIT_EXCEEDED", "run exceeds its exact drop-record bound")
        dropped_total += dropped
        expected_attempt_index = end_exclusive

    attempts_total = expected_attempt_index - 1
    observed_attempts = _integer(
        manifest.get("appAudioAppendAttemptsObserved"),
        "appAudioAppendAttemptsObserved",
    )
    observed_appended = _integer(manifest.get("appAudioSamplesObserved"), "appAudioSamplesObserved")
    if observed_attempts != attempts_total or observed_appended != appended_total:
        raise GenerationError(
            "MANIFEST_TOTAL_MISMATCH",
            "manifest totals do not exactly match every finalized segment",
        )
    reserved_through = _integer(
        manifest.get("appAudioAppendReservedThroughIndex"),
        "appAudioAppendReservedThroughIndex",
    )
    if reserved_through != attempts_total:
        raise GenerationError(
            "RESERVATION_TOTAL_MISMATCH",
            "a complete run must trim its durable reservation to its final issued index",
        )
    if dropped_total != len(seen_drop_indexes):
        raise GenerationError("UNACCOUNTED_APP_AUDIO_DROPS", "every dropped attempt must be recorded once")

    artifact = {
        "app_audio_append_attempts": attempts_total,
        "app_audio_appended_samples": appended_total,
        "contract_version": VALIDATOR.CONTRACT_VERSION,
        "dropped_app_audio_samples": dropped_total,
        "duration_milliseconds": int(duration),
        "evidence_class": evidence_class,
        "gaps": gaps,
        "run_id": run_id,
        "source_manifest": VALIDATOR._source_binding(manifest, source_manifest_bytes),
    }
    VALIDATOR.validate_artifact(
        artifact,
        require_physical=evidence_class == "physical_device",
        source_manifest=(manifest, source_manifest_bytes),
    )
    return artifact


def canonical_bytes(artifact: dict[str, Any]) -> bytes:
    encoded = (json.dumps(artifact, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > VALIDATOR.MAX_ARTIFACT_BYTES:
        raise GenerationError("ARTIFACT_SIZE_LIMIT", "canonical evidence exceeds its byte bound")
    return encoded


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--evidence-class",
        choices=("physical_device", "synthetic_conformance"),
        required=True,
    )
    args = parser.parse_args()
    try:
        manifest, raw = load_manifest_with_raw(args.manifest)
        artifact = derive_artifact(
            manifest,
            run_id=args.run_id,
            evidence_class=args.evidence_class,
            source_manifest_bytes=raw,
        )
        encoded = canonical_bytes(artifact)
        if args.output:
            _write_atomic(args.output, encoded)
        else:
            sys.stdout.buffer.write(encoded)
    except (GenerationError, VALIDATOR.AcceptanceError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print("canonical app-audio acceptance evidence generated and validated", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
