# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "tacua_app_audio_acceptance",
    ROOT / "scripts" / "validate_app_audio_acceptance.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load app-audio acceptance validator")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
FIXTURES = ROOT / "fixtures" / "app-audio-acceptance"


class AppAudioAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.synthetic = GATE.load_artifact(FIXTURES / "synthetic-passing.json")

    def test_exact_point_two_percent_with_every_drop_in_a_gap_passes_conformance(self) -> None:
        GATE.validate_artifact(self.synthetic, require_physical=False)
        with self.assertRaises(GATE.AcceptanceError) as raised:
            GATE.validate_artifact(self.synthetic, require_physical=True)
        self.assertEqual("PHYSICAL_EVIDENCE_REQUIRED", raised.exception.code)

    def test_historical_physical_run_does_not_pass_without_drop_gap_accounting(self) -> None:
        historical = GATE.load_artifact(FIXTURES / "physical-2026-07-21-unaccounted.json")
        with self.assertRaises(GATE.AcceptanceError) as raised:
            GATE.validate_artifact(historical, require_physical=True)
        self.assertEqual("UNACCOUNTED_APP_AUDIO_DROPS", raised.exception.code)

    def test_schema_four_physical_run_passes_structural_release_gate(self) -> None:
        physical = GATE.load_artifact(FIXTURES / "physical-2026-07-23-passing.json")
        GATE.validate_artifact(physical, require_physical=True)

    def test_rate_above_point_two_percent_fails_with_integer_arithmetic(self) -> None:
        candidate = copy.deepcopy(self.synthetic)
        candidate["app_audio_append_attempts"] = 999
        candidate["app_audio_appended_samples"] = 996
        candidate["dropped_app_audio_samples"] = 3
        candidate["gaps"][0]["dropped_attempt_indexes"] = [300, 301]
        with self.assertRaises(GATE.AcceptanceError) as raised:
            GATE.validate_artifact(candidate, require_physical=False)
        self.assertEqual("APP_AUDIO_DROP_RATE_EXCEEDED", raised.exception.code)

    def test_append_totals_and_exact_unique_gap_accounting_are_required(self) -> None:
        totals = copy.deepcopy(self.synthetic)
        totals["app_audio_appended_samples"] = 997
        duplicate = copy.deepcopy(self.synthetic)
        duplicate["gaps"][1]["dropped_attempt_indexes"] = [300]
        missing = copy.deepcopy(self.synthetic)
        missing["gaps"] = missing["gaps"][:1]
        cases = [
            (totals, "APPEND_TOTAL_MISMATCH"),
            (duplicate, "DUPLICATE_DROP_ACCOUNTING"),
            (missing, "UNACCOUNTED_APP_AUDIO_DROPS"),
        ]
        for candidate, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(GATE.AcceptanceError) as raised:
                    GATE.validate_artifact(candidate, require_physical=False)
                self.assertEqual(expected, raised.exception.code)

    def test_physical_gate_requires_a_30_minute_campaign(self) -> None:
        candidate = copy.deepcopy(self.synthetic)
        candidate["evidence_class"] = "physical_device"
        candidate["duration_milliseconds"] = 1_798_999
        with self.assertRaises(GATE.AcceptanceError) as raised:
            GATE.validate_artifact(candidate, require_physical=True)
        self.assertEqual("PHYSICAL_DURATION_TOO_SHORT", raised.exception.code)

    def test_physical_gate_rejects_duration_beyond_stop_finalization_envelope(self) -> None:
        candidate = copy.deepcopy(self.synthetic)
        candidate["evidence_class"] = "physical_device"
        candidate["duration_milliseconds"] = GATE.MAX_PHYSICAL_DURATION_MILLISECONDS + 1
        with self.assertRaises(GATE.AcceptanceError) as raised:
            GATE.validate_artifact(candidate, require_physical=True)
        self.assertEqual("PHYSICAL_DURATION_TOO_LONG", raised.exception.code)

    def test_sdk_attempt_and_exact_drop_caps_are_enforced(self) -> None:
        attempts = copy.deepcopy(self.synthetic)
        attempts["app_audio_append_attempts"] = GATE.MAX_APP_AUDIO_APPEND_ATTEMPTS + 1
        attempts["app_audio_appended_samples"] = attempts["app_audio_append_attempts"] - 2
        drops = copy.deepcopy(self.synthetic)
        drops["app_audio_append_attempts"] = GATE.MAX_DROPPED_APP_AUDIO_SAMPLES + 1
        drops["app_audio_appended_samples"] = 0
        drops["dropped_app_audio_samples"] = GATE.MAX_DROPPED_APP_AUDIO_SAMPLES + 1
        for candidate, expected in (
            (attempts, "ATTEMPT_LIMIT_EXCEEDED"),
            (drops, "DROP_LIMIT_EXCEEDED"),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(GATE.AcceptanceError) as raised:
                    GATE.validate_artifact(candidate, require_physical=False)
                self.assertEqual(expected, raised.exception.code)

    def test_source_manifest_version_is_an_exact_non_boolean_integer(self) -> None:
        for value in (4.0, True):
            candidate = copy.deepcopy(self.synthetic)
            candidate["source_manifest"]["schema_version"] = value
            with self.subTest(value=value):
                with self.assertRaises(GATE.AcceptanceError) as raised:
                    GATE.validate_artifact(candidate, require_physical=False)
                self.assertEqual("INVALID_ARTIFACT", raised.exception.code)

    def test_exact_source_manifest_identity_and_bytes_are_bound(self) -> None:
        manifest = {
            "schemaVersion": 4,
            "expectedApplicationId": "dev.tacua.sample",
            "buildId": "build-ios-001",
            "expectedBuildNumber": "42",
            "sessionId": "session-physical-audio-001",
        }
        raw = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
        candidate = copy.deepcopy(self.synthetic)
        candidate["source_manifest"] = GATE._source_binding(manifest, raw)
        GATE.validate_artifact(
            candidate,
            require_physical=False,
            source_manifest=(manifest, raw),
        )
        with self.assertRaises(GATE.AcceptanceError) as raised:
            GATE.validate_artifact(
                candidate,
                require_physical=False,
                source_manifest=(manifest, raw + b"\n"),
            )
        self.assertEqual("SOURCE_MANIFEST_MISMATCH", raised.exception.code)

    def test_non_finite_and_overlong_integer_json_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            non_finite = root / "non-finite.json"
            overlong = root / "overlong.json"
            non_finite.write_text('{"value":NaN}', encoding="utf-8")
            overlong.write_text('{"value":' + "9" * 5_000 + '}', encoding="utf-8")
            for path in (non_finite, overlong):
                with self.subTest(path=path.name):
                    with self.assertRaises(GATE.AcceptanceError) as raised:
                        GATE.load_artifact(path)
                    self.assertEqual("INVALID_JSON", raised.exception.code)

    def test_loader_requires_canonical_utf8_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pretty = root / "pretty.json"
            missing_newline = root / "missing-newline.json"
            utf16 = root / "utf16.json"
            pretty.write_text(json.dumps(self.synthetic, indent=2) + "\n", encoding="utf-8")
            missing_newline.write_text(
                json.dumps(self.synthetic, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            utf16.write_text(
                json.dumps(self.synthetic, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-16",
            )
            for path in (pretty, missing_newline):
                with self.subTest(path=path.name):
                    with self.assertRaises(GATE.AcceptanceError) as raised:
                        GATE.load_artifact(path)
                    self.assertEqual("NON_CANONICAL_ARTIFACT", raised.exception.code)
            with self.assertRaises(GATE.AcceptanceError) as raised:
                GATE.load_artifact(utf16)
            self.assertEqual("INVALID_JSON", raised.exception.code)

    def test_machine_counts_must_fit_the_javascript_safe_integer_range(self) -> None:
        candidate = copy.deepcopy(self.synthetic)
        candidate["app_audio_append_attempts"] = GATE.MAX_SAFE_INTEGER + 1
        with self.assertRaises(GATE.AcceptanceError) as raised:
            GATE.validate_artifact(candidate, require_physical=False)
        self.assertEqual("INVALID_ARTIFACT", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
