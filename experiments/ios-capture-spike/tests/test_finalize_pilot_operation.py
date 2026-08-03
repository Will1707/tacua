# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "tacua_finalize_pilot_operation",
    ROOT / "scripts" / "finalize_pilot_operation.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load pilot operation finalizer")
FINALIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FINALIZER)


class PilotOperationFinalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.capture = self._write_private(self.root / "capture.json", b'{"capture":"ok"}\n')
        self.session = self._write_private(self.root / "session.json", b'{"session":"completed"}\n')

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_private(path: Path, raw: bytes, *, mode: int = 0o600) -> Path:
        path.write_bytes(raw)
        os.chmod(path, mode)
        return path

    def _success_input(self) -> dict:
        return {
            "contract_version": FINALIZER.INPUT_CONTRACT_VERSION,
            "operation_id": "pilot_operation_001",
            "completed_at": "2026-08-03T12:30:00Z",
            "terminal_state": "succeeded",
            "failure": None,
            "validation": {
                "version": "tacua.filtered-xcuitest@1.4.0",
                "state": "passed",
                "reason_code": None,
            },
            "narration": {"version": "pilot-narration-v1"},
            "sources": [
                {"source_id": "mobile_sdk", "version": "0.1.0"},
                {"source_id": "pilot_harness", "version": "1.4.0"},
            ],
            "client_cleanup": {
                "attestation_version": "tacua.client-cleanup@1.0.0",
                "state": "attested_complete",
                "attested_at": "2026-08-03T12:29:55Z",
                "reason_code": None,
            },
            "helper_uninstall": {
                "attestation_version": "tacua.helper-uninstall@1.0.0",
                "state": "attested_absent",
                "attested_at": "2026-08-03T12:29:58Z",
                "reason_code": None,
            },
            "evidence": [
                {
                    "name": "session_detail",
                    "role": "backend_receipt",
                    "media_type": "application/json",
                    "path": str(self.session),
                },
                {
                    "name": "capture_result",
                    "role": "capture_validation",
                    "media_type": "application/json",
                    "path": str(self.capture),
                },
            ],
        }

    def _write_input(self, value: dict, name: str = "finalization-input.json") -> Path:
        path = self.root / name
        raw = (json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        return self._write_private(path, raw)

    def _assert_error(self, code: str, callback) -> None:
        with self.assertRaises(FINALIZER.FinalizationError) as raised:
            callback()
        self.assertEqual(code, raised.exception.code)

    def test_success_receipt_is_canonical_private_path_free_and_verifiable(self) -> None:
        input_path = self._write_input(self._success_input())
        output = self.root / "operation-receipt.json"

        receipt = FINALIZER.finalize(input_path, output)

        self.assertEqual("succeeded", receipt["terminal_state"])
        self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
        raw = output.read_bytes()
        self.assertEqual(FINALIZER._canonical_bytes(receipt), raw)
        self.assertNotIn(str(self.root).encode("utf-8"), raw)
        self.assertEqual(
            ["capture_result", "session_detail"],
            [item["name"] for item in receipt["evidence"]],
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(self.capture.read_bytes()).hexdigest(),
            receipt["evidence"][0]["content_digest"],
        )
        self.assertEqual(
            FINALIZER._digest_without(receipt, "receipt_digest"),
            receipt["receipt_digest"],
        )
        self.assertEqual(receipt, FINALIZER.verify(input_path, output))

    def test_explicit_not_applicable_helper_outcome_can_satisfy_success(self) -> None:
        candidate = self._success_input()
        candidate["helper_uninstall"] = {
            "attestation_version": "tacua.helper-uninstall@1.0.0",
            "state": "not_applicable",
            "attested_at": "2026-08-03T12:29:58Z",
            "reason_code": "HELPERS_NOT_USED",
        }
        receipt = FINALIZER.finalize(
            self._write_input(candidate), self.root / "not-applicable-receipt.json"
        )
        self.assertEqual("not_applicable", receipt["helper_uninstall"]["state"])

        misleading = self._success_input()
        misleading["helper_uninstall"] = {
            "attestation_version": "tacua.helper-uninstall@1.0.0",
            "state": "not_applicable",
            "attested_at": "2026-08-03T12:29:58Z",
            "reason_code": "UNINSTALL_FAILED",
        }
        self._assert_error(
            "INVALID_HELPER_OUTCOME",
            lambda: FINALIZER.finalize(
                self._write_input(misleading, "misleading-not-applicable.json"),
                self.root / "misleading-not-applicable-receipt.json",
            ),
        )

    def test_success_requires_validation_cleanup_and_helper_outcomes(self) -> None:
        cases: list[tuple[dict, str]] = []

        invalid_validation = self._success_input()
        invalid_validation["validation"] = {
            "version": "tacua.filtered-xcuitest@1.4.0",
            "state": "failed",
            "reason_code": "VALIDATION_FAILED",
        }
        cases.append((invalid_validation, "SUCCESS_VALIDATION_REQUIRED"))

        incomplete_cleanup = self._success_input()
        incomplete_cleanup["client_cleanup"] = {
            "attestation_version": "tacua.client-cleanup@1.0.0",
            "state": "incomplete",
            "attested_at": "2026-08-03T12:29:55Z",
            "reason_code": "CLEANUP_INCOMPLETE",
        }
        cases.append((incomplete_cleanup, "SUCCESS_CLEANUP_REQUIRED"))

        incomplete_helper = self._success_input()
        incomplete_helper["helper_uninstall"] = {
            "attestation_version": "tacua.helper-uninstall@1.0.0",
            "state": "incomplete",
            "attested_at": "2026-08-03T12:29:58Z",
            "reason_code": "HELPER_STILL_PRESENT",
        }
        cases.append((incomplete_helper, "SUCCESS_HELPER_OUTCOME_REQUIRED"))

        for index, (candidate, expected) in enumerate(cases):
            with self.subTest(expected=expected):
                input_path = self._write_input(candidate, f"gate-{index}.json")
                output = self.root / f"gate-{index}-receipt.json"
                self._assert_error(expected, lambda: FINALIZER.finalize(input_path, output))
                self.assertFalse(output.exists())

    def test_failure_is_terminal_and_requires_unambiguous_failure_data(self) -> None:
        candidate = self._success_input()
        candidate.update(
            {
                "terminal_state": "failed",
                "failure": {"stage": "validation", "code": "PILOT_VALIDATION_FAILED"},
                "validation": {
                    "version": "tacua.filtered-xcuitest@1.4.0",
                    "state": "failed",
                    "reason_code": "VALIDATION_FAILED",
                },
                "client_cleanup": {
                    "attestation_version": "tacua.client-cleanup@1.0.0",
                    "state": "incomplete",
                    "attested_at": "2026-08-03T12:29:55Z",
                    "reason_code": "CLEANUP_INCOMPLETE",
                },
                "helper_uninstall": {
                    "attestation_version": "tacua.helper-uninstall@1.0.0",
                    "state": "not_attested",
                    "attested_at": None,
                    "reason_code": "NOT_ATTESTED",
                },
            }
        )
        input_path = self._write_input(candidate)
        output = self.root / "failed-receipt.json"
        receipt = FINALIZER.finalize(input_path, output)
        self.assertEqual("failed", receipt["terminal_state"])
        self.assertEqual("PILOT_VALIDATION_FAILED", receipt["failure"]["code"])
        self.assertEqual(receipt, FINALIZER.verify(input_path, output))

        missing_failure = copy.deepcopy(candidate)
        missing_failure["failure"] = None
        self._assert_error(
            "AMBIGUOUS_TERMINAL_STATE",
            lambda: FINALIZER.finalize(
                self._write_input(missing_failure, "missing-failure.json"),
                self.root / "missing-failure-receipt.json",
            ),
        )

        success_with_failure = self._success_input()
        success_with_failure["failure"] = {
            "stage": "validation",
            "code": "SHOULD_NOT_EXIST",
        }
        self._assert_error(
            "AMBIGUOUS_TERMINAL_STATE",
            lambda: FINALIZER.finalize(
                self._write_input(success_with_failure, "ambiguous-success.json"),
                self.root / "ambiguous-success-receipt.json",
            ),
        )

    def test_each_bound_file_must_be_private_regular_and_single_link(self) -> None:
        unsafe_mode = self._write_private(self.root / "unsafe-mode.json", b"{}\n", mode=0o640)
        symlink_target = self._write_private(self.root / "symlink-target.json", b"{}\n")
        symlink = self.root / "symlink.json"
        symlink.symlink_to(symlink_target)
        hardlink_source = self._write_private(self.root / "hardlink-source.json", b"{}\n")
        hardlink = self.root / "hardlink.json"
        os.link(hardlink_source, hardlink)
        directory = self.root / "evidence-directory"
        directory.mkdir(mode=0o700)

        for index, path in enumerate((unsafe_mode, symlink, hardlink, directory)):
            with self.subTest(path=path.name):
                candidate = self._success_input()
                candidate["evidence"][0]["path"] = str(path)
                input_path = self._write_input(candidate, f"unsafe-{index}.json")
                self._assert_error(
                    "UNSAFE_EVIDENCE_FILE",
                    lambda p=input_path, i=index: FINALIZER.finalize(
                        p, self.root / f"unsafe-{i}-receipt.json"
                    ),
                )

    def test_verification_detects_evidence_and_receipt_tampering(self) -> None:
        input_path = self._write_input(self._success_input())
        output = self.root / "operation-receipt.json"
        FINALIZER.finalize(input_path, output)

        self.capture.write_bytes(b'{"capture":"changed"}\n')
        os.chmod(self.capture, 0o600)
        self._assert_error(
            "RECEIPT_INPUT_MISMATCH",
            lambda: FINALIZER.verify(input_path, output),
        )

        self.capture.write_bytes(b'{"capture":"ok"}\n')
        os.chmod(self.capture, 0o600)
        tampered = json.loads(output.read_text(encoding="utf-8"))
        tampered["operation_id"] = "pilot_operation_999"
        output.write_bytes(FINALIZER._canonical_bytes(tampered))
        os.chmod(output, 0o600)
        self._assert_error(
            "RECEIPT_DIGEST_MISMATCH",
            lambda: FINALIZER.verify(input_path, output),
        )

    def test_terminal_receipt_is_never_overwritten(self) -> None:
        input_path = self._write_input(self._success_input())
        output = self.root / "operation-receipt.json"
        first = FINALIZER.finalize(input_path, output)
        original = output.read_bytes()
        self._assert_error(
            "RECEIPT_ALREADY_EXISTS",
            lambda: FINALIZER.finalize(input_path, output),
        )
        self.assertEqual(original, output.read_bytes())
        self.assertEqual(first, json.loads(original))

    def test_no_replace_publication_loses_race_without_overwriting_winner(self) -> None:
        input_path = self._write_input(self._success_input())
        output = self.root / "raced-receipt.json"
        winner = b"winner-owned-by-another-local-writer\n"
        real_link = os.link

        def interposed_link(source, destination, **kwargs):
            self._write_private(output, winner)
            return real_link(source, destination, **kwargs)

        with mock.patch.object(FINALIZER.os, "link", side_effect=interposed_link):
            self._assert_error(
                "RECEIPT_ALREADY_EXISTS",
                lambda: FINALIZER.finalize(input_path, output),
            )
        self.assertEqual(winner, output.read_bytes())
        self.assertEqual([], list(self.root.glob("tacua-receipt-*.tmp")))

    def _create_publication_crash_state(
        self, input_path: Path, output: Path, suffix: str
    ) -> tuple[dict, Path]:
        validated = FINALIZER._load_and_validate_input(input_path)
        receipt = FINALIZER._build_receipt(validated)
        temporary = self.root / f"tacua-receipt-{suffix}.tmp"
        self._write_private(temporary, FINALIZER._canonical_bytes(receipt))
        os.link(temporary, output)
        self.assertEqual(2, output.stat().st_nlink)
        return receipt, temporary

    def test_verify_recovers_exact_final_and_temporary_link_crash_state(self) -> None:
        input_path = self._write_input(self._success_input())
        output = self.root / "crash-receipt.json"
        expected, temporary = self._create_publication_crash_state(
            input_path, output, "a" * 24
        )

        self.assertEqual(expected, FINALIZER.verify(input_path, output))
        self.assertFalse(temporary.exists())
        self.assertEqual(1, output.stat().st_nlink)

    def test_identical_finalize_retry_recovers_publication_crash_state(self) -> None:
        input_path = self._write_input(self._success_input())
        output = self.root / "retry-receipt.json"
        expected, temporary = self._create_publication_crash_state(
            input_path, output, "b" * 24
        )

        self.assertEqual(expected, FINALIZER.finalize(input_path, output))
        self.assertFalse(temporary.exists())
        self.assertEqual(1, output.stat().st_nlink)

    def test_receipt_recovery_rejects_non_temporary_or_mismatched_links(self) -> None:
        input_path = self._write_input(self._success_input())
        output = self.root / "unsafe-crash-receipt.json"
        expected = FINALIZER._build_receipt(
            FINALIZER._load_and_validate_input(input_path)
        )
        unrelated_name = self.root / "not-a-publication-temporary.json"
        self._write_private(output, FINALIZER._canonical_bytes(expected))
        os.link(output, unrelated_name)

        self._assert_error(
            "INTERRUPTED_RECEIPT_UNRECOVERABLE",
            lambda: FINALIZER.verify(input_path, output),
        )
        self.assertTrue(unrelated_name.exists())
        self.assertEqual(2, output.stat().st_nlink)

    def test_publish_fsyncs_file_and_directory_and_leaves_no_temporary_file(self) -> None:
        input_path = self._write_input(self._success_input())
        output = self.root / "operation-receipt.json"
        real_fsync = os.fsync
        with mock.patch.object(FINALIZER.os, "fsync", wraps=real_fsync) as fsync:
            FINALIZER.finalize(input_path, output)
        self.assertGreaterEqual(fsync.call_count, 2)
        self.assertEqual([], list(self.root.glob("tacua-receipt-*.tmp")))

    def test_output_directory_must_be_owner_private(self) -> None:
        unsafe = self.root / "unsafe-output"
        unsafe.mkdir(mode=0o755)
        os.chmod(unsafe, 0o755)
        input_path = self._write_input(self._success_input())
        self._assert_error(
            "UNSAFE_OUTPUT_DIRECTORY",
            lambda: FINALIZER.finalize(input_path, unsafe / "receipt.json"),
        )

    def test_input_rejects_duplicate_keys_duplicate_sources_and_relative_evidence(self) -> None:
        duplicate = self.root / "duplicate.json"
        self._write_private(
            duplicate,
            b'{"contract_version":"first","contract_version":"second"}\n',
        )
        self._assert_error(
            "DUPLICATE_JSON_KEY",
            lambda: FINALIZER.finalize(duplicate, self.root / "duplicate-receipt.json"),
        )

        duplicate_source = self._success_input()
        duplicate_source["sources"].append(copy.deepcopy(duplicate_source["sources"][0]))
        self._assert_error(
            "INVALID_SOURCES",
            lambda: FINALIZER.finalize(
                self._write_input(duplicate_source, "duplicate-source.json"),
                self.root / "duplicate-source-receipt.json",
            ),
        )

        relative = self._success_input()
        relative["evidence"][0]["path"] = "session.json"
        self._assert_error(
            "INVALID_EVIDENCE_PATH",
            lambda: FINALIZER.finalize(
                self._write_input(relative, "relative.json"),
                self.root / "relative-receipt.json",
            ),
        )

    def test_input_rejects_floats_nonfinite_values_and_overlong_integers(self) -> None:
        raw_values = (
            b'{"value":1.5}\n',
            b'{"value":NaN}\n',
            ('{"value":' + "9" * 5_000 + '}\n').encode("utf-8"),
        )
        for index, raw in enumerate(raw_values):
            with self.subTest(index=index):
                input_path = self._write_private(self.root / f"number-{index}.json", raw)
                self._assert_error(
                    "INVALID_JSON",
                    lambda p=input_path, i=index: FINALIZER.finalize(
                        p, self.root / f"number-{i}-receipt.json"
                    ),
                )

    def test_malformed_nested_receipt_fails_with_a_stable_error(self) -> None:
        input_path = self._write_input(self._success_input())
        output = self.root / "malformed-receipt.json"
        receipt = FINALIZER.finalize(input_path, output)
        receipt["validation"] = []
        malformed = FINALIZER._seal(receipt)
        output.write_bytes(FINALIZER._canonical_bytes(malformed))
        os.chmod(output, 0o600)
        self._assert_error(
            "INVALID_RECEIPT",
            lambda: FINALIZER.verify(input_path, output),
        )


if __name__ == "__main__":
    unittest.main()
