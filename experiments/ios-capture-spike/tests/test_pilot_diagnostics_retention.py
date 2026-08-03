# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import io
import os
import plistlib
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "manage_pilot_diagnostics.py"
SPEC = importlib.util.spec_from_file_location("tacua_pilot_diagnostics", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PILOT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PILOT
SPEC.loader.exec_module(PILOT)
UTC = timezone.utc


class PilotDiagnosticsRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.operations = self.base / "operations"
        self.operations.mkdir(mode=0o700)
        os.chmod(self.operations, 0o700)
        self.now = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)

    def _write_private(self, path: Path, payload: bytes = b"evidence\n") -> None:
        path.write_bytes(payload)
        os.chmod(path, 0o600)

    def test_create_writes_exact_owner_private_seven_day_contract(self) -> None:
        operation = PILOT.create_operation(self.operations, created_at=self.now)

        self.assertRegex(operation.name, PILOT.OPERATION_NAME)
        self.assertEqual(stat.S_IMODE(operation.stat().st_mode), 0o700)
        marker = operation / PILOT.RETENTION_MARKER
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        self.assertEqual(
            marker.read_text(encoding="ascii"),
            "artifact_class=physical_pilot_diagnostics\n"
            "created_at=2026-08-03T12:00:00Z\n"
            "delete_after=2026-08-10T12:00:00Z\n",
        )

    def test_dry_run_reports_expiry_without_deleting(self) -> None:
        operation = PILOT.create_operation(
            self.operations,
            created_at=self.now - timedelta(days=8),
        )
        self._write_private(operation / "diagnostic.log")

        result = PILOT.sweep_operations(self.operations, now=self.now)

        self.assertEqual(result.eligible, 1)
        self.assertEqual(result.deleted, 0)
        self.assertTrue(operation.exists())

    def test_apply_removes_only_expired_valid_direct_children(self) -> None:
        expired = PILOT.create_operation(
            self.operations,
            created_at=self.now - timedelta(days=8),
        )
        active = PILOT.create_operation(
            self.operations,
            created_at=self.now - timedelta(days=6),
        )
        self._write_private(expired / "diagnostic.log")
        self._write_private(active / "diagnostic.log")
        outside = self.base / "tacua-physical-pilot.Outside"
        outside.mkdir(mode=0o700)
        os.chmod(outside, 0o700)

        result = PILOT.sweep_operations(self.operations, now=self.now, apply=True)

        self.assertEqual(result.deleted, 1)
        self.assertFalse(expired.exists())
        self.assertTrue(active.exists())
        self.assertTrue(outside.exists())

    def test_ambiguous_or_unsafe_operations_are_never_deleted(self) -> None:
        wrong_mode = PILOT.create_operation(
            self.operations,
            created_at=self.now - timedelta(days=8),
        )
        os.chmod(wrong_mode / PILOT.RETENTION_MARKER, 0o644)

        linked = PILOT.create_operation(
            self.operations,
            created_at=self.now - timedelta(days=8),
        )
        (linked / "unexpected-link").symlink_to("missing")

        hardlinked = PILOT.create_operation(
            self.operations,
            created_at=self.now - timedelta(days=8),
        )
        self._write_private(hardlinked / "first.log")
        os.link(hardlinked / "first.log", hardlinked / "second.log")

        future = PILOT.create_operation(
            self.operations,
            created_at=self.now + timedelta(days=1),
        )

        result = PILOT.sweep_operations(self.operations, now=self.now, apply=True)

        self.assertEqual(result.deleted, 0)
        self.assertEqual(result.ignored, 4)
        self.assertTrue(wrong_mode.exists())
        self.assertTrue(linked.exists())
        self.assertTrue(hardlinked.exists())
        self.assertTrue(future.exists())

    def test_invalid_retention_window_is_left_untouched(self) -> None:
        operation = PILOT.create_operation(
            self.operations,
            created_at=self.now - timedelta(days=8),
        )
        marker = operation / PILOT.RETENTION_MARKER
        marker.write_text(
            "artifact_class=physical_pilot_diagnostics\n"
            "created_at=2026-07-26T12:00:00Z\n"
            "delete_after=2026-08-04T12:00:00Z\n",
            encoding="ascii",
        )
        os.chmod(marker, 0o600)

        result = PILOT.sweep_operations(self.operations, now=self.now, apply=True)

        self.assertEqual(result.ignored, 1)
        self.assertTrue(operation.exists())

    def test_operations_root_must_be_canonical_owner_private(self) -> None:
        os.chmod(self.operations, 0o755)

        with self.assertRaisesRegex(PILOT.SafetyError, "directory_not_owner_private"):
            PILOT.sweep_operations(self.operations, now=self.now, apply=True)

    def test_operations_root_rejects_replaceable_ancestor(self) -> None:
        unsafe_parent = self.base / "replaceable"
        unsafe_parent.mkdir(mode=0o700)
        operations = unsafe_parent / "operations"
        operations.mkdir(mode=0o700)
        os.chmod(operations, 0o700)
        os.chmod(unsafe_parent, 0o777)

        with self.assertRaisesRegex(PILOT.SafetyError, "unsafe_ancestor_chain"):
            PILOT.sweep_operations(operations, now=self.now, apply=True)

    def test_migration_dry_run_is_non_mutating(self) -> None:
        legacy = self.base / "legacy"
        legacy.mkdir(mode=0o700)
        os.chmod(legacy, 0o700)
        evidence = legacy / "pilot.private.log"
        evidence.write_text("private evidence\n", encoding="utf-8")
        os.chmod(evidence, 0o644)

        result = PILOT.migrate_entries(
            self.operations,
            legacy,
            [evidence.name],
            created_at=self.now,
        )

        self.assertEqual(result, {"applied": False, "entry_count": 1})
        self.assertTrue(evidence.exists())
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o644)

    def test_migration_preserves_content_and_hardens_entire_tree(self) -> None:
        legacy = self.base / "legacy"
        legacy.mkdir(mode=0o700)
        os.chmod(legacy, 0o700)
        loose_file = legacy / "pilot.private.log"
        loose_file.write_bytes(b"private log\n")
        os.chmod(loose_file, 0o644)
        loose_directory = legacy / "device-diagnostics"
        loose_directory.mkdir(mode=0o777)
        os.chmod(loose_directory, 0o777)
        nested = loose_directory / "result.json"
        nested.write_bytes(b'{"synthetic":true}\n')
        os.chmod(nested, 0o666)

        result = PILOT.migrate_entries(
            self.operations,
            legacy,
            [loose_file.name, loose_directory.name],
            apply=True,
            created_at=self.now,
        )

        operation = self.operations / str(result["operation_name"])
        self.assertFalse(loose_file.exists())
        self.assertFalse(loose_directory.exists())
        self.assertEqual((operation / "artifacts" / loose_file.name).read_bytes(), b"private log\n")
        self.assertEqual(
            (operation / "artifacts" / loose_directory.name / nested.name).read_bytes(),
            b'{"synthetic":true}\n',
        )
        for directory, _, filenames in os.walk(operation):
            self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o700)
            for filename in filenames:
                self.assertEqual(
                    stat.S_IMODE((Path(directory) / filename).stat().st_mode),
                    0o600,
                )

        swept = PILOT.sweep_operations(
            self.operations,
            now=self.now + timedelta(days=8),
            apply=True,
        )
        self.assertEqual(swept.deleted, 1)
        self.assertFalse(operation.exists())

    def test_migration_rejects_symlinks_and_preserves_source(self) -> None:
        legacy = self.base / "legacy"
        legacy.mkdir(mode=0o700)
        os.chmod(legacy, 0o700)
        source = legacy / "device-diagnostics"
        source.mkdir(mode=0o700)
        os.chmod(source, 0o700)
        (source / "unexpected-link").symlink_to("missing")

        with self.assertRaisesRegex(PILOT.SafetyError, "unsafe_migration_entry"):
            PILOT.migrate_entries(
                self.operations,
                legacy,
                [source.name],
                apply=True,
                created_at=self.now,
            )
        self.assertTrue(source.exists())

    def test_rendered_launchd_job_is_daily_shell_free_and_owner_only(self) -> None:
        schedule_directory = self.base / "schedules"
        schedule_directory.mkdir(mode=0o700)
        os.chmod(schedule_directory, 0o700)
        output = schedule_directory / f"{PILOT.LAUNCHD_LABEL}.plist"
        python_path = self.base / "python3"
        python_path.write_bytes(b"synthetic interpreter fixture\n")
        os.chmod(python_path, 0o700)

        PILOT.render_launchd_schedule(
            self.operations,
            tool_path=MODULE_PATH.resolve(),
            output=output,
            python_path=python_path,
            hour=4,
            minute=29,
        )

        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        document = plistlib.loads(output.read_bytes())
        self.assertEqual(document["Label"], PILOT.LAUNCHD_LABEL)
        self.assertEqual(document["StartCalendarInterval"], {"Hour": 4, "Minute": 29})
        self.assertEqual(
            document["ProgramArguments"],
            [
                str(python_path),
                str(MODULE_PATH.resolve()),
                "sweep",
                "--operations-root",
                str(self.operations),
                "--apply",
                "--quiet",
            ],
        )
        self.assertNotIn("/bin/sh", document["ProgramArguments"])
        self.assertTrue(document["RunAtLoad"])
        self.assertEqual(document["Umask"], 0o077)
        self.assertEqual(document["StandardOutPath"], "/dev/null")
        self.assertEqual(document["StandardErrorPath"], "/dev/null")

    def test_schedule_generation_refuses_overwrite(self) -> None:
        output = self.base / "schedule.plist"
        output.write_text("preserve me", encoding="utf-8")
        os.chmod(output, 0o600)
        python_path = self.base / "python3"
        python_path.write_bytes(b"synthetic interpreter fixture\n")
        os.chmod(python_path, 0o700)

        with self.assertRaisesRegex(PILOT.SafetyError, "schedule_output_exists"):
            PILOT.render_launchd_schedule(
                self.operations,
                tool_path=MODULE_PATH.resolve(),
                output=output,
                python_path=python_path,
            )
        self.assertEqual(output.read_text(encoding="utf-8"), "preserve me")

    def test_schedule_rejects_writable_interpreter(self) -> None:
        output = self.base / "schedule.plist"
        python_path = self.base / "python3"
        python_path.write_bytes(b"synthetic interpreter fixture\n")
        os.chmod(python_path, 0o777)

        with self.assertRaisesRegex(PILOT.SafetyError, "unsafe_schedule_program"):
            PILOT.render_launchd_schedule(
                self.operations,
                tool_path=MODULE_PATH.resolve(),
                output=output,
                python_path=python_path,
            )
        self.assertFalse(output.exists())

    def test_quiet_scheduled_sweep_exits_nonzero_for_ignored_operation(self) -> None:
        operation = PILOT.create_operation(
            self.operations,
            created_at=self.now - timedelta(days=8),
        )
        os.chmod(operation / PILOT.RETENTION_MARKER, 0o644)
        stdout = io.StringIO()
        stderr = io.StringIO()

        previous_umask = os.umask(0o077)
        os.umask(previous_umask)
        try:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = PILOT.main(
                    [
                        "sweep",
                        "--operations-root",
                        str(self.operations),
                        "--apply",
                        "--quiet",
                    ]
                )
        finally:
            os.umask(previous_umask)

        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(operation.exists())


if __name__ == "__main__":
    unittest.main()
