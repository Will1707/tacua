# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "tacua_app_audio_acceptance_generator",
    ROOT / "scripts" / "generate_app_audio_acceptance.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load app-audio acceptance generator")
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


def manifest() -> dict[str, object]:
    return {
        "schemaVersion": 4,
        "sessionId": "session-physical-audio-001",
        "buildId": "build-ios-001",
        "expectedApplicationId": "dev.tacua.sample",
        "expectedBuildNumber": "42",
        "state": "completed",
        "startedHostUptimeSeconds": 100,
        "stoppedHostUptimeSeconds": 1_900,
        "errorCodes": [],
        "gaps": [],
        "resumeCount": 0,
        "appAudioAppendAccountingVersion": 1,
        "appAudioAppendAccountingComplete": True,
        "appAudioAppendAttemptsObserved": 1_000,
        "appAudioAppendReservedThroughIndex": 1_000,
        "appAudioAppendUnknownRanges": [],
        "appAudioSamplesObserved": 998,
        "segments": [
            {
                "index": 0,
                "appAudioAppendAttemptStartIndex": 1,
                "appAudioAppendAttempts": 400,
                "appAudioSamples": 399,
                "droppedAppAudioSamples": 1,
                "appAudioAppendDrops": [
                    {"attemptIndex": 300, "cause": "input_backpressure"},
                ],
            },
            {
                "index": 1,
                "appAudioAppendAttemptStartIndex": 401,
                "appAudioAppendAttempts": 600,
                "appAudioSamples": 599,
                "droppedAppAudioSamples": 1,
                "appAudioAppendDrops": [
                    {"attemptIndex": 700, "cause": "append_rejected"},
                ],
            },
        ],
    }


def derive(candidate: dict[str, object]) -> dict[str, object]:
    raw = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
    return GENERATOR.derive_artifact(
        candidate,
        run_id="physical-audio-001",
        evidence_class="physical_device",
        source_manifest_bytes=raw,
    )


class AppAudioAcceptanceGenerationTests(unittest.TestCase):
    def test_canonical_physical_output_groups_exact_indexes_by_segment(self) -> None:
        artifact = derive(manifest())
        self.assertEqual(
            [[300], [700]],
            [gap["dropped_attempt_indexes"] for gap in artifact["gaps"]],
        )
        encoded = GENERATOR.canonical_bytes(artifact)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertNotIn(b": ", encoded)
        self.assertEqual(
            encoded,
            (json.dumps(artifact, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )

    def test_legacy_and_resumed_manifests_are_refused_without_inventing_indexes(self) -> None:
        legacy = manifest()
        legacy["schemaVersion"] = 3
        resumed = manifest()
        resumed["appAudioAppendAccountingComplete"] = False
        cases = [
            (legacy, "LEGACY_MANIFEST_UNACCOUNTED"),
            (resumed, "INCOMPLETE_APP_AUDIO_ACCOUNTING"),
        ]
        for candidate, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(GENERATOR.GenerationError) as raised:
                    derive(candidate)
                self.assertEqual(expected, raised.exception.code)

    def test_schema_and_accounting_versions_are_exact_non_boolean_integers(self) -> None:
        cases = [
            ("schemaVersion", 4.0, "LEGACY_MANIFEST_UNACCOUNTED"),
            ("schemaVersion", True, "LEGACY_MANIFEST_UNACCOUNTED"),
            ("appAudioAppendAccountingVersion", 1.0, "ACCOUNTING_VERSION_MISSING"),
            ("appAudioAppendAccountingVersion", True, "ACCOUNTING_VERSION_MISSING"),
        ]
        for field, value, expected in cases:
            candidate = manifest()
            candidate[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(GENERATOR.GenerationError) as raised:
                    derive(candidate)
                self.assertEqual(expected, raised.exception.code)

    def test_missing_duplicate_and_count_mismatched_drop_records_fail_closed(self) -> None:
        missing = manifest()
        missing["segments"][0]["appAudioAppendDrops"] = []  # type: ignore[index]
        duplicate = manifest()
        duplicate["segments"][0]["appAudioAppendDrops"] = [  # type: ignore[index]
            {"attemptIndex": 300, "cause": "input_backpressure"},
            {"attemptIndex": 300, "cause": "append_rejected"},
        ]
        duplicate["segments"][0]["droppedAppAudioSamples"] = 2  # type: ignore[index]
        duplicate["segments"][0]["appAudioSamples"] = 398  # type: ignore[index]
        mismatch = manifest()
        mismatch["appAudioAppendAttemptsObserved"] = 999
        cases = [
            (missing, "DROP_COUNT_MISMATCH"),
            (duplicate, "INVALID_DROP_INDEX"),
            (mismatch, "MANIFEST_TOTAL_MISMATCH"),
        ]
        for candidate, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(GENERATOR.GenerationError) as raised:
                    derive(candidate)
                self.assertEqual(expected, raised.exception.code)

    def test_noncontiguous_segment_ranges_and_errorful_captures_are_refused(self) -> None:
        noncontiguous = manifest()
        noncontiguous["segments"][1]["appAudioAppendAttemptStartIndex"] = 402  # type: ignore[index]
        errorful = copy.deepcopy(manifest())
        errorful["errorCodes"] = ["ERR_TACUA_CAPTURE_WRITER_FINISH"]
        cases = [
            (noncontiguous, "NONCONTIGUOUS_ATTEMPT_INDEXES"),
            (errorful, "ERRORFUL_CAPTURE"),
        ]
        for candidate, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(GENERATOR.GenerationError) as raised:
                    derive(candidate)
                self.assertEqual(expected, raised.exception.code)

    def test_partial_or_gapped_capture_cannot_claim_uninterrupted_physical_evidence(self) -> None:
        partial = manifest()
        partial["state"] = "partial"
        gapped = manifest()
        gapped["gaps"] = [{"reason": "app_backgrounded"}]
        for candidate in (partial, gapped):
            with self.subTest(state=candidate["state"], gaps=candidate["gaps"]):
                with self.assertRaises(GENERATOR.GenerationError) as raised:
                    derive(candidate)
                self.assertEqual("CAPTURE_NOT_UNINTERRUPTED", raised.exception.code)

    def test_physical_validator_cli_requires_the_exact_source_manifest_bytes(self) -> None:
        candidate = manifest()
        raw = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
        artifact = GENERATOR.derive_artifact(
            candidate,
            run_id="physical-audio-001",
            evidence_class="physical_device",
            source_manifest_bytes=raw,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            artifact_path = root / "acceptance.json"
            manifest_path.write_bytes(raw)
            artifact_path.write_bytes(GENERATOR.canonical_bytes(artifact))
            command = [
                "python3",
                str(ROOT / "scripts" / "validate_app_audio_acceptance.py"),
                str(artifact_path),
                "--source-manifest",
                str(manifest_path),
            ]
            accepted = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            manifest_path.write_bytes(raw + b"\n")
            rejected = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("SOURCE_MANIFEST_MISMATCH", rejected.stderr)

    def test_source_manifest_loader_rejects_non_utf8_without_requiring_canonical_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pretty = root / "pretty.json"
            utf16 = root / "utf16.json"
            pretty.write_text(json.dumps(manifest(), indent=2) + "\n", encoding="utf-8")
            loaded, raw = GENERATOR.load_manifest_with_raw(pretty)
            self.assertEqual(manifest(), loaded)
            self.assertEqual(pretty.read_bytes(), raw)
            utf16.write_text(json.dumps(manifest()), encoding="utf-16")
            with self.assertRaises(GENERATOR.GenerationError) as raised:
                GENERATOR.load_manifest_with_raw(utf16)
            self.assertEqual("INVALID_MANIFEST", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
