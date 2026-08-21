# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "xcresult_safety.py"
)
SPEC = importlib.util.spec_from_file_location("xcresult_safety", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
xcresult_safety = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = xcresult_safety
SPEC.loader.exec_module(xcresult_safety)


class XCResultSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="tacua-result-safety-")
        self.root = (
            pathlib.Path(os.path.realpath(self.temporary.name))
            / "synthetic.xcresult"
        )
        self.root.mkdir(mode=0o700)
        self.matcher = xcresult_safety.ForbiddenMatcher([b"one-time-value"])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_scans_hidden_nested_files_and_chunk_boundaries(self) -> None:
        hidden = self.root / ".hidden" / "nested"
        hidden.mkdir(parents=True)
        payload = b"a" * (xcresult_safety.CHUNK_SIZE - 4) + b"one-time-value"
        (hidden / "payload.bin").write_bytes(payload)
        self.assertEqual(
            xcresult_safety.scan_result(str(self.root), self.matcher).status,
            xcresult_safety.Status.LEAK,
        )

        (hidden / "payload.bin").write_bytes(b"synthetic-safe-payload")
        self.assertEqual(
            xcresult_safety.scan_result(str(self.root), self.matcher).status,
            xcresult_safety.Status.CLEAN,
        )

    def test_rejects_forbidden_filename_and_default_runtime_marker(self) -> None:
        (self.root / "one-time-value").write_bytes(b"safe")
        self.assertEqual(
            xcresult_safety.scan_result(str(self.root), self.matcher).status,
            xcresult_safety.Status.LEAK,
        )
        (self.root / "one-time-value").unlink()
        (self.root / "payload").write_bytes(b"launch_code=synthetic_value")
        self.assertEqual(
            xcresult_safety.scan_result(str(self.root), self.matcher).status,
            xcresult_safety.Status.LEAK,
        )

    def test_detects_default_runtime_marker_across_chunk_boundary(self) -> None:
        payload = (
            b"a" * (xcresult_safety.CHUNK_SIZE - 5)
            + b"launch_code=synthetic_value"
        )
        (self.root / "payload").write_bytes(payload)
        self.assertEqual(
            xcresult_safety.scan_result(str(self.root), self.matcher).status,
            xcresult_safety.Status.LEAK,
        )

    def test_rejects_forbidden_result_bundle_name(self) -> None:
        leaking_root = self.root.parent / "one-time-value.xcresult"
        leaking_root.mkdir()
        (leaking_root / "payload").write_bytes(b"safe")
        self.assertEqual(
            xcresult_safety.scan_result(str(leaking_root), self.matcher).status,
            xcresult_safety.Status.LEAK,
        )

    def test_rejects_symlink_special_file_and_hardlink(self) -> None:
        outside = pathlib.Path(self.temporary.name) / "outside"
        outside.write_bytes(b"safe")
        (self.root / "link").symlink_to(outside)
        self.assertEqual(
            xcresult_safety.scan_result(str(self.root), self.matcher).status,
            xcresult_safety.Status.ERROR,
        )
        (self.root / "link").unlink()

        os.mkfifo(self.root / "pipe", 0o600)
        self.assertEqual(
            xcresult_safety.scan_result(str(self.root), self.matcher).status,
            xcresult_safety.Status.ERROR,
        )
        (self.root / "pipe").unlink()

        original = self.root / "original"
        original.write_bytes(b"safe")
        os.link(original, self.root / "hardlink")
        self.assertEqual(
            xcresult_safety.scan_result(str(self.root), self.matcher).status,
            xcresult_safety.Status.ERROR,
        )

    def test_rejects_traversal_and_empty_result(self) -> None:
        traversing = os.path.join(
            str(self.root.parent),
            "synthetic.xcresult",
            "..",
            "synthetic.xcresult",
        )
        self.assertEqual(
            xcresult_safety.scan_result(traversing, self.matcher).status,
            xcresult_safety.Status.ERROR,
        )
        self.assertEqual(
            xcresult_safety.scan_result(str(self.root), self.matcher).status,
            xcresult_safety.Status.ERROR,
        )

    def test_read_error_is_never_clean(self) -> None:
        (self.root / "payload").write_bytes(b"safe")
        with mock.patch.object(
            xcresult_safety.os,
            "read",
            side_effect=OSError("synthetic read failure"),
        ):
            self.assertEqual(
                xcresult_safety.scan_result(str(self.root), self.matcher).status,
                xcresult_safety.Status.ERROR,
            )

    def test_seals_only_after_clean_scan(self) -> None:
        nested = self.root / "nested"
        nested.mkdir(mode=0o755)
        payload = nested / "payload"
        payload.write_bytes(b"safe")
        os.chmod(self.root, 0o755)
        os.chmod(payload, 0o644)

        self.assertEqual(
            xcresult_safety.seal_result(str(self.root), self.matcher),
            xcresult_safety.Status.CLEAN,
        )
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(nested.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o600)

    def test_leak_does_not_change_permissions(self) -> None:
        payload = self.root / "payload"
        payload.write_bytes(b"one-time-value")
        os.chmod(self.root, 0o755)
        os.chmod(payload, 0o644)

        self.assertEqual(
            xcresult_safety.seal_result(str(self.root), self.matcher),
            xcresult_safety.Status.LEAK,
        )
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o644)

    def test_status_codes_are_dedicated(self) -> None:
        self.assertEqual(int(xcresult_safety.Status.LEAK), 40)
        self.assertEqual(int(xcresult_safety.Status.CLEAN), 41)
        self.assertEqual(int(xcresult_safety.Status.ERROR), 42)

    def test_cli_help_is_zero_and_non_help_parse_errors_are_42(self) -> None:
        help_result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("usage:", help_result.stdout.lower())
        self.assertNotIn("xcresult-safety=unprovable", help_result.stderr)

        for arguments in (
            [],
            ["--not-a-supported-option"],
            ["--help", "--not-a-supported-option"],
        ):
            with self.subTest(arguments=arguments):
                malformed = subprocess.run(
                    [sys.executable, "-B", str(SCRIPT), *arguments],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(malformed.returncode, 42)
                self.assertIn(
                    "xcresult-safety=unprovable",
                    malformed.stderr,
                )

    def test_forbidden_values_file_must_be_owner_private(self) -> None:
        values = self.root.parent / "forbidden-values"
        values.write_bytes(b"one-time-value\n")
        os.chmod(values, 0o600)
        self.assertEqual(
            xcresult_safety.load_forbidden_values([str(values)]),
            (b"one-time-value",),
        )
        os.chmod(values, 0o644)
        with self.assertRaises(ValueError):
            xcresult_safety.load_forbidden_values([str(values)])

    def test_cli_scans_every_forbidden_values_file(self) -> None:
        runtime_values = self.root.parent / "runtime-values"
        device_identifier = self.root.parent / "device-identifier"
        runtime_values.write_bytes(b"synthetic-one-time-value\n")
        device_identifier.write_bytes(b"SYNTHETIC-DEVICE-IDENTIFIER-0001\n")
        os.chmod(runtime_values, 0o600)
        os.chmod(device_identifier, 0o600)
        (self.root / "payload").write_bytes(
            b"result metadata: SYNTHETIC-DEVICE-IDENTIFIER-0001"
        )

        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(SCRIPT),
                "scan",
                str(self.root),
                "--forbidden-values-file",
                str(runtime_values),
                "--forbidden-values-file",
                str(device_identifier),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 40)
        self.assertIn("xcresult-safety=runtime-value-leak", completed.stderr)


if __name__ == "__main__":
    unittest.main()
