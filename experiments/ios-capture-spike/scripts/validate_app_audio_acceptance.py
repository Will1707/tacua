#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate the accepted Tacua V1 app-audio append-drop gate."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any


CONTRACT_VERSION = "tacua.app-audio-acceptance@1.0.0"
MAX_ARTIFACT_BYTES = 1_048_576
MAX_GAPS = 2_048
MAX_APP_AUDIO_APPEND_ATTEMPTS = 10_000_000
MAX_DROPPED_APP_AUDIO_SAMPLES = 2_048
MAX_DROP_RATE_NUMERATOR = 2
MAX_DROP_RATE_DENOMINATOR = 1_000
MIN_PHYSICAL_DURATION_MILLISECONDS = 1_799_000
MAX_PHYSICAL_DURATION_MILLISECONDS = 1_831_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991
ID_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


class AcceptanceError(ValueError):
    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}")


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AcceptanceError("DUPLICATE_JSON_KEY", "artifact contains a duplicate key")
        result[key] = value
    return result


def load_artifact(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise AcceptanceError("ARTIFACT_UNREADABLE", "artifact could not be read") from error
    if not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise AcceptanceError("ARTIFACT_SIZE_LIMIT", "artifact violates its byte bound")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite number")),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise AcceptanceError("INVALID_JSON", "artifact is not UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise AcceptanceError("INVALID_ARTIFACT", "top level must be an object")
    canonical = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if raw != canonical:
        raise AcceptanceError(
            "NON_CANONICAL_ARTIFACT",
            "artifact must be canonical UTF-8 JSON with one trailing newline",
        )
    return value


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > MAX_SAFE_INTEGER
    ):
        raise AcceptanceError(
            "INVALID_ARTIFACT",
            f"{field} must be an interoperable integer from {minimum} through {MAX_SAFE_INTEGER}",
        )
    return value


def _source_binding(manifest: dict[str, Any], raw: bytes) -> dict[str, Any]:
    schema_version = manifest.get("schemaVersion")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 4
    ):
        raise AcceptanceError(
            "INVALID_SOURCE_MANIFEST",
            "source schemaVersion must be the exact integer 4",
        )
    fields = {
        "application_id": manifest.get("expectedApplicationId"),
        "build_id": manifest.get("buildId"),
        "build_number": manifest.get("expectedBuildNumber"),
        "session_id": manifest.get("sessionId"),
    }
    if any(
        not isinstance(value, str) or not value or len(value.encode("utf-8")) > 255
        for value in fields.values()
    ):
        raise AcceptanceError("INVALID_SOURCE_MANIFEST", "source identity fields are missing or invalid")
    return {
        **fields,
        "manifest_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "schema_version": schema_version,
    }


def validate_artifact(
    artifact: dict[str, Any],
    *,
    require_physical: bool = True,
    source_manifest: tuple[dict[str, Any], bytes] | None = None,
) -> None:
    expected_fields = {
        "app_audio_append_attempts",
        "app_audio_appended_samples",
        "contract_version",
        "dropped_app_audio_samples",
        "duration_milliseconds",
        "evidence_class",
        "gaps",
        "run_id",
        "source_manifest",
    }
    if set(artifact) != expected_fields:
        raise AcceptanceError("INVALID_ARTIFACT", "artifact fields do not match the closed V1 contract")
    if artifact["contract_version"] != CONTRACT_VERSION:
        raise AcceptanceError("INVALID_ARTIFACT", "unsupported contract version")
    if not isinstance(artifact["run_id"], str) or not ID_RE.fullmatch(artifact["run_id"]):
        raise AcceptanceError("INVALID_ARTIFACT", "run_id is invalid")
    if artifact["evidence_class"] not in {"physical_device", "synthetic_conformance"}:
        raise AcceptanceError("INVALID_ARTIFACT", "evidence_class is invalid")
    if require_physical and artifact["evidence_class"] != "physical_device":
        raise AcceptanceError("PHYSICAL_EVIDENCE_REQUIRED", "synthetic conformance cannot close the release gate")

    source = artifact["source_manifest"]
    if not isinstance(source, dict) or set(source) != {
        "application_id", "build_id", "build_number", "manifest_digest", "schema_version",
        "session_id",
    }:
        raise AcceptanceError("INVALID_ARTIFACT", "source_manifest fields are invalid")
    source_schema_version = _integer(
        source.get("schema_version"),
        "source_manifest.schema_version",
    )
    if source_schema_version != 4 or not isinstance(source.get("manifest_digest"), str) \
            or not DIGEST_RE.fullmatch(source["manifest_digest"]):
        raise AcceptanceError("INVALID_ARTIFACT", "source manifest version or digest is invalid")
    for field in ("application_id", "build_id", "build_number", "session_id"):
        value = source.get(field)
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 255:
            raise AcceptanceError("INVALID_ARTIFACT", f"source_manifest.{field} is invalid")
    if source_manifest is not None and source != _source_binding(*source_manifest):
        raise AcceptanceError("SOURCE_MANIFEST_MISMATCH", "artifact is not bound to the exact source manifest")

    attempts = _integer(artifact["app_audio_append_attempts"], "app_audio_append_attempts", minimum=1)
    appended = _integer(artifact["app_audio_appended_samples"], "app_audio_appended_samples")
    dropped = _integer(artifact["dropped_app_audio_samples"], "dropped_app_audio_samples")
    duration = _integer(artifact["duration_milliseconds"], "duration_milliseconds", minimum=1)
    if attempts > MAX_APP_AUDIO_APPEND_ATTEMPTS:
        raise AcceptanceError("ATTEMPT_LIMIT_EXCEEDED", "artifact exceeds the SDK append-attempt limit")
    if dropped > MAX_DROPPED_APP_AUDIO_SAMPLES:
        raise AcceptanceError("DROP_LIMIT_EXCEEDED", "artifact exceeds the SDK exact-drop limit")
    if require_physical and duration < MIN_PHYSICAL_DURATION_MILLISECONDS:
        raise AcceptanceError("PHYSICAL_DURATION_TOO_SHORT", "physical gate requires the 30-minute campaign")
    if require_physical and duration > MAX_PHYSICAL_DURATION_MILLISECONDS:
        raise AcceptanceError("PHYSICAL_DURATION_TOO_LONG", "physical run exceeds the bounded stop tolerance")
    if appended + dropped != attempts:
        raise AcceptanceError("APPEND_TOTAL_MISMATCH", "appended plus dropped must equal every append attempt")
    if dropped * MAX_DROP_RATE_DENOMINATOR > attempts * MAX_DROP_RATE_NUMERATOR:
        raise AcceptanceError("APP_AUDIO_DROP_RATE_EXCEEDED", "drop rate exceeds 0.2 percent")

    gaps = artifact["gaps"]
    if not isinstance(gaps, list) or len(gaps) > MAX_GAPS:
        raise AcceptanceError("INVALID_ARTIFACT", "gaps must be a bounded array")
    gap_ids: set[str] = set()
    recorded_attempts: list[int] = []
    for index, gap in enumerate(gaps):
        if not isinstance(gap, dict) or set(gap) != {"dropped_attempt_indexes", "gap_id", "reason"}:
            raise AcceptanceError("INVALID_ARTIFACT", f"gap {index} fields are invalid")
        gap_id = gap["gap_id"]
        if not isinstance(gap_id, str) or not ID_RE.fullmatch(gap_id) or gap_id in gap_ids:
            raise AcceptanceError("INVALID_ARTIFACT", f"gap {index} ID is invalid or duplicated")
        gap_ids.add(gap_id)
        if gap["reason"] != "app_audio_append_drop":
            raise AcceptanceError("INVALID_ARTIFACT", f"gap {index} reason is invalid")
        indexes = gap["dropped_attempt_indexes"]
        if not isinstance(indexes, list) or not indexes:
            raise AcceptanceError("INVALID_ARTIFACT", f"gap {index} must identify at least one dropped attempt")
        previous = 0
        for attempt_index in indexes:
            value = _integer(attempt_index, f"gaps[{index}].dropped_attempt_indexes", minimum=1)
            if value > attempts or value <= previous:
                raise AcceptanceError("INVALID_ARTIFACT", f"gap {index} attempt indexes must be unique, ordered and in range")
            previous = value
            recorded_attempts.append(value)
    if len(set(recorded_attempts)) != len(recorded_attempts):
        raise AcceptanceError("DUPLICATE_DROP_ACCOUNTING", "one dropped attempt appears in more than one gap")
    if len(recorded_attempts) != dropped:
        raise AcceptanceError(
            "UNACCOUNTED_APP_AUDIO_DROPS",
            "every dropped app-audio append attempt must appear exactly once in a gap",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument(
        "--conformance",
        action="store_true",
        help="allow a synthetic artifact to exercise the gate without claiming physical acceptance",
    )
    parser.add_argument(
        "--source-manifest",
        type=Path,
        help="exact schema-4 source manifest; required to validate a passing physical artifact",
    )
    args = parser.parse_args()
    try:
        artifact = load_artifact(args.artifact)
        require_physical = not args.conformance
        validate_artifact(artifact, require_physical=require_physical)
        if args.source_manifest is None:
            if require_physical:
                raise AcceptanceError(
                    "SOURCE_MANIFEST_REQUIRED",
                    "passing physical evidence requires the exact source manifest",
                )
        else:
            generator_path = Path(__file__).with_name("generate_app_audio_acceptance.py")
            spec = importlib.util.spec_from_file_location("tacua_app_audio_generator_verify", generator_path)
            if spec is None or spec.loader is None:
                raise AcceptanceError("SOURCE_MANIFEST_UNREADABLE", "generator could not be loaded")
            generator = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(generator)
            manifest, raw = generator.load_manifest_with_raw(args.source_manifest)
            expected = generator.derive_artifact(
                manifest,
                run_id=artifact["run_id"],
                evidence_class=artifact["evidence_class"],
                source_manifest_bytes=raw,
            )
            if expected != artifact:
                raise AcceptanceError(
                    "SOURCE_MANIFEST_MISMATCH",
                    "artifact values do not exactly derive from the supplied source manifest",
                )
    except AcceptanceError as error:
        print(str(error), file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"SOURCE_MANIFEST_MISMATCH: {error}", file=sys.stderr)
        return 1
    print(
        "app-audio acceptance passed" if not args.conformance else "app-audio conformance passed; not physical evidence",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
