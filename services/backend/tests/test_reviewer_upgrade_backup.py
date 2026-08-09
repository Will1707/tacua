# SPDX-License-Identifier: Apache-2.0
"""Focused contracts for bounded reviewer-upgrade backup attempts."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "services" / "backend" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import reviewer_upgrade_backup as BACKUP  # noqa: E402
import reviewer_upgrade_journal as JOURNAL  # noqa: E402


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class FakeRunner:
    def __init__(self, bindings: BACKUP.BackupBindings) -> None:
        self.bindings = bindings
        self.events: list[tuple[str, dict]] = []
        self.failures: dict[str, int] = {}
        self.status = "running"
        self.health = "healthy"
        self.inspect_override: dict[str, str] = {}
        self.bundle_file_mode = 0o600
        self.bundle_digest = "sha256:" + "e" * 64

    def fail(self, action: str, count: int = 1) -> None:
        self.failures[action] = self.failures.get(action, 0) + count

    def __call__(self, action: str, request: dict) -> dict:
        self.events.append((action, deepcopy(request)))
        remaining = self.failures.get(action, 0)
        if remaining:
            self.failures[action] = remaining - 1
            raise RuntimeError("synthetic runner failure")
        if action == "inspect_backend":
            result = {
                "container_id": self.bindings.backend_container_id,
                "health": self.health,
                "image_id": self.bindings.backend_image_id,
                "image_ref": self.bindings.backend_image_ref,
                "state_volume": self.bindings.state_volume,
                "status": self.status,
            }
            result.update(self.inspect_override)
            return result
        if action == "stop_backend":
            self.status = "exited"
            self.health = "none"
            return {
                "container_id": self.bindings.backend_container_id,
                "status": "stopped",
            }
        if action == "start_backend":
            self.status = "running"
            self.health = "healthy"
            return {
                "container_id": self.bindings.backend_container_id,
                "status": "started",
            }
        if action == "archive_backup":
            attempt = Path(request["attempt_directory"])
            bundle = attempt / request["bundle_relative_path"]
            bundle.mkdir(mode=0o700)
            artifact = bundle / "database.backup"
            artifact.write_bytes(b"synthetic backup\n")
            artifact.chmod(self.bundle_file_mode)
            return {"created": True, "host_tree_normalized": True}
        if action == "verify_backup":
            return {
                "bundle_digest": self.bundle_digest,
                "status": "ok",
                "verified": True,
            }
        if action == "fsync_backup":
            return {
                "bundle_digest": request["bundle_digest"],
                "durable": True,
            }
        if action == "smoke_backend":
            return {
                "container_id": self.bindings.backend_container_id,
                "status": "ok",
            }
        raise AssertionError(action)


class ReviewerUpgradeBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.source = JOURNAL.create_transaction_directory(
            self.root / "source-state"
        )
        self.transaction = JOURNAL.create_transaction_directory(
            self.root / "upgrade-operation"
        )
        self.config = self.root / "config.json"
        self.config.write_bytes(b'{"pilot":true}\n')
        self.config.chmod(0o644)
        self.secret = self.root / "admin-secret"
        self.secret.write_bytes(b"synthetic-secret\n")
        self.secret.chmod(0o444)
        self.binding_document = self._binding_document()
        self.bindings = BACKUP.validate_backup_bindings(
            self.binding_document
        )

    def _file_binding(self, path: Path, mode: int) -> dict:
        payload = path.read_bytes()
        return {
            "digest": _digest(payload),
            "mode": mode,
            "path": str(path),
            "size": len(payload),
            "uid": os.geteuid(),
        }

    def _binding_document(self) -> dict:
        return {
            "backend": {
                "container_id": "a" * 64,
                "image_id": "sha256:" + "b" * 64,
                "image_ref": "tacua-backend:pilot-20260804",
                "state_volume": "tacua_tacua-state",
            },
            "config": self._file_binding(self.config, 0o644),
            "contract_version": BACKUP.BACKUP_BINDINGS_CONTRACT,
            "operation_id": "reviewer-upgrade-20260804",
            "plan_digest": "sha256:" + "c" * 64,
            "project": "tacua",
            "secret": self._file_binding(self.secret, 0o444),
            "source": {
                "compose_digest": "sha256:" + "d" * 64,
                "generation": "generation-20260804.1",
                "manifest_digest": "sha256:" + "f" * 64,
                "state_directory": str(self.source),
            },
        }

    def _run(self, runner: FakeRunner) -> dict:
        return BACKUP.run_backup_attempt(
            self.transaction,
            self.bindings,
            runner,
            health_attempts=2,
            health_interval_seconds=0,
            sleeper=lambda _seconds: None,
        )

    def _ledger(self) -> dict:
        return json.loads(
            (self.transaction / BACKUP.BACKUP_LEDGER_FILE).read_text(
                encoding="ascii"
            )
        )

    def _seed_receipt_draft(
        self,
        transaction: Path,
        *,
        drafts: int = 1,
        symlink: bool = False,
    ) -> None:
        with BACKUP._open_transaction(transaction) as (
            bound_transaction,
            descriptor,
            _binding,
        ):
            BACKUP._load_or_create_ledger(descriptor, self.bindings)
            attempt = BACKUP._create_attempt(
                bound_transaction,
                descriptor,
                self.bindings,
                1,
            )
        bundle = attempt / BACKUP.BACKUP_BUNDLE_DIRECTORY
        bundle.mkdir(mode=0o700)
        artifact = bundle / "database.backup"
        artifact.write_bytes(b"uncommitted backup\n")
        artifact.chmod(0o600)
        for index in range(drafts):
            draft = attempt / (
                f".{BACKUP.ATTEMPT_RECEIPT_FILE}.next-123-"
                f"{index:012x}"
            )
            if symlink:
                draft.symlink_to(self.config)
            else:
                draft.write_bytes(b"untrusted receipt bytes\n")
                draft.chmod(0o600)

    def test_success_is_durable_strict_and_idempotently_reverified(self) -> None:
        runner = FakeRunner(self.bindings)

        receipt = self._run(runner)

        self.assertEqual(
            BACKUP.validate_backup_receipt(receipt, self.bindings),
            receipt,
        )
        self.assertEqual(receipt["attempt"], {
            "number": 1,
            "relative_path": "backup-attempt-01",
        })
        self.assertEqual(receipt["prior_attempts"], [])
        self.assertEqual(receipt["bundle"], {
            "durable": True,
            "relative_path": "bundle",
            "sha256": runner.bundle_digest,
            "verified": True,
        })
        self.assertEqual(
            [action for action, _request in runner.events],
            [
                "inspect_backend",
                "stop_backend",
                "inspect_backend",
                "archive_backup",
                "verify_backup",
                "fsync_backup",
                "start_backend",
                "inspect_backend",
                "smoke_backend",
            ],
        )
        self.assertEqual(
            next(
                request
                for action, request in runner.events
                if action == "stop_backend"
            ),
            {"container_id": self.bindings.backend_container_id},
        )
        archive_request = next(
            request
            for action, request in runner.events
            if action == "archive_backup"
        )
        self.assertEqual(archive_request["backend"], {
            "container_id": self.bindings.backend_container_id,
            "image_id": self.bindings.backend_image_id,
            "image_ref": self.bindings.backend_image_ref,
            "state_volume": self.bindings.state_volume,
        })

        self.assertEqual(archive_request["host_tree_policy"], {
            "directory_mode": 0o700,
            "file_mode": 0o600,
            "owner_uid": os.geteuid(),
            "special_files": "reject",
            "symlinks": "reject",
        })
        ledger = self._ledger()
        self.assertEqual(ledger["sequence"], 1)
        self.assertEqual(ledger["entries"], [{
            "number": 1,
            "relative_path": "backup-attempt-01",
            "status": "backup_ready",
        }])
        for path in (
            self.transaction / BACKUP.BACKUP_LEDGER_FILE,
            self.transaction / "backup-attempt-01" / BACKUP.ATTEMPT_MARKER_FILE,
            self.transaction / "backup-attempt-01" / BACKUP.ATTEMPT_RECEIPT_FILE,
        ):
            metadata = path.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(metadata.st_uid, os.geteuid())
            self.assertEqual(metadata.st_nlink, 1)

        runner.events.clear()
        self.assertEqual(self._run(runner), receipt)
        self.assertEqual(
            [action for action, _request in runner.events],
            [
                "verify_backup",
                "fsync_backup",
                "start_backend",
                "inspect_backend",
                "smoke_backend",
            ],
        )

    def test_exhausted_marker_only_failures_have_read_only_terminal_proof(
        self,
    ) -> None:
        runner = FakeRunner(self.bindings)
        runner.fail("archive_backup", BACKUP.MAX_BACKUP_ATTEMPTS)
        for _number in range(BACKUP.MAX_BACKUP_ATTEMPTS):
            with self.assertRaisesRegex(
                BACKUP.BackupError,
                "REVIEWER_UPGRADE_BACKUP_FAILED",
            ):
                self._run(runner)

        before = {
            path.relative_to(self.transaction): (
                path.lstat().st_ino,
                path.lstat().st_mtime_ns,
                path.read_bytes() if path.is_file() else None,
            )
            for path in self.transaction.rglob("*")
        }
        evidence = BACKUP.validate_exhausted_backup_evidence(
            self.transaction,
            self.bindings,
        )
        after = {
            path.relative_to(self.transaction): (
                path.lstat().st_ino,
                path.lstat().st_mtime_ns,
                path.read_bytes() if path.is_file() else None,
            )
            for path in self.transaction.rglob("*")
        }

        self.assertEqual(before, after)
        self.assertEqual(evidence["sequence"], 3)
        self.assertEqual(
            [attempt["number"] for attempt in evidence["attempts"]],
            [1, 2, 3],
        )
        self.assertTrue(
            all(
                attempt["relative_path"]
                == f"backup-quarantine-{attempt['number']:02d}"
                for attempt in evidence["attempts"]
            )
        )

    def test_exhausted_proof_rejects_every_non_marker_attempt_state(self) -> None:
        runner = FakeRunner(self.bindings)
        runner.fail("archive_backup", BACKUP.MAX_BACKUP_ATTEMPTS)
        for _number in range(BACKUP.MAX_BACKUP_ATTEMPTS):
            with self.assertRaises(BACKUP.BackupError):
                self._run(runner)

        cases = ("bundle", "ledger_staging", "marker_draft")
        for case in cases:
            with self.subTest(case=case):
                if case == "bundle":
                    extra = (
                        self.transaction
                        / "backup-quarantine-03"
                        / BACKUP.BACKUP_BUNDLE_DIRECTORY
                    )
                    extra.mkdir(mode=0o700)
                elif case == "ledger_staging":
                    extra = self.transaction / BACKUP.BACKUP_LEDGER_STAGING_FILE
                    extra.write_bytes(
                        (self.transaction / BACKUP.BACKUP_LEDGER_FILE).read_bytes()
                    )
                    extra.chmod(0o600)
                else:
                    extra = (
                        self.transaction
                        / "backup-quarantine-03"
                        / ".attempt.json.next-123-000000000000"
                    )
                    extra.write_bytes(b"untrusted\n")
                    extra.chmod(0o600)
                with self.assertRaisesRegex(
                    BACKUP.BackupError,
                    "REVIEWER_UPGRADE_BACKUP_INVALID",
                ):
                    BACKUP.validate_exhausted_backup_evidence(
                        self.transaction,
                        self.bindings,
                    )
                if extra.is_dir():
                    extra.rmdir()
                else:
                    extra.unlink()

    def test_exact_hardlinked_receipt_publication_is_repaired_and_reverified(self) -> None:
        runner = FakeRunner(self.bindings)
        receipt = self._run(runner)
        attempt = self.transaction / "backup-attempt-01"
        final = attempt / BACKUP.ATTEMPT_RECEIPT_FILE
        draft = attempt / (
            f".{BACKUP.ATTEMPT_RECEIPT_FILE}.next-123-abcdefabcdef"
        )
        os.link(final, draft)
        self.assertEqual(final.stat().st_nlink, 2)
        runner.events.clear()

        with mock.patch.object(
            BACKUP.os,
            "fsync",
            wraps=os.fsync,
        ) as fsync:
            resumed = self._run(runner)

        self.assertEqual(resumed, receipt)
        self.assertFalse(draft.exists())
        self.assertEqual(final.stat().st_nlink, 1)
        self.assertGreaterEqual(fsync.call_count, 1)
        self.assertEqual(
            [action for action, _request in runner.events],
            [
                "verify_backup",
                "fsync_backup",
                "start_backend",
                "inspect_backend",
                "smoke_backend",
            ],
        )

    def test_temp_only_receipt_is_never_accepted_and_attempt_is_quarantined(self) -> None:
        separate = JOURNAL.create_transaction_directory(
            self.root / "receipt-draft-operation"
        )
        self._seed_receipt_draft(separate)
        runner = FakeRunner(self.bindings)

        receipt = BACKUP.run_backup_attempt(
            separate,
            self.bindings,
            runner,
            health_attempts=2,
            health_interval_seconds=0,
        )

        self.assertEqual(receipt["attempt"]["number"], 2)
        self.assertEqual(receipt["prior_attempts"][0]["status"], "quarantined")
        quarantine = separate / "backup-quarantine-01"
        self.assertTrue(quarantine.is_dir())
        self.assertTrue(
            any(
                path.name.startswith(".backup-receipt.json.next-")
                for path in quarantine.iterdir()
            )
        )

    def test_ambiguous_or_link_unsafe_receipt_drafts_fail_closed(self) -> None:
        for name, drafts, symlink in (
            ("multiple", 2, False),
            ("symlink", 1, True),
        ):
            with self.subTest(name=name):
                transaction = JOURNAL.create_transaction_directory(
                    self.root / f"unsafe-receipt-{name}"
                )
                self._seed_receipt_draft(
                    transaction,
                    drafts=drafts,
                    symlink=symlink,
                )
                runner = FakeRunner(self.bindings)
                with self.assertRaisesRegex(
                    BACKUP.BackupError,
                    "^REVIEWER_UPGRADE_BACKUP_INVALID$",
                ):
                    BACKUP.run_backup_attempt(
                        transaction,
                        self.bindings,
                        runner,
                        health_interval_seconds=0,
                    )
                self.assertEqual(runner.events, [])
                self.assertTrue(
                    (transaction / "backup-attempt-01").is_dir()
                )

    def test_backup_failure_recovers_quarantines_and_retry_uses_attempt_two(self) -> None:
        runner = FakeRunner(self.bindings)
        runner.fail("archive_backup")

        with self.assertRaisesRegex(
            BACKUP.BackupError,
            "^REVIEWER_UPGRADE_BACKUP_FAILED$",
        ):
            self._run(runner)

        self.assertTrue((self.transaction / "backup-quarantine-01").is_dir())
        self.assertFalse((self.transaction / "backup-attempt-01").exists())
        self.assertEqual(self._ledger()["entries"][0]["status"], "failed")
        self.assertEqual(
            [action for action, _request in runner.events][-3:],
            ["start_backend", "inspect_backend", "smoke_backend"],
        )

        runner.events.clear()
        receipt = self._run(runner)

        self.assertEqual(receipt["attempt"]["number"], 2)
        self.assertEqual(receipt["prior_attempts"], [{
            "number": 1,
            "relative_path": "backup-quarantine-01",
            "status": "failed",
        }])
        self.assertTrue((self.transaction / "backup-attempt-02").is_dir())

    def test_stop_failure_still_restarts_smokes_and_preserves_failed_evidence(self) -> None:
        runner = FakeRunner(self.bindings)
        runner.fail("stop_backend")

        with self.assertRaisesRegex(
            BACKUP.BackupError,
            "^REVIEWER_UPGRADE_BACKUP_FAILED$",
        ):
            self._run(runner)

        actions = [action for action, _request in runner.events]
        self.assertEqual(actions[:2], ["inspect_backend", "stop_backend"])
        self.assertEqual(
            actions[-3:],
            ["start_backend", "inspect_backend", "smoke_backend"],
        )
        self.assertTrue((self.transaction / "backup-quarantine-01").is_dir())

    def test_recovery_failure_wins_and_retry_quarantines_orphan_first(self) -> None:
        runner = FakeRunner(self.bindings)
        runner.fail("archive_backup")
        runner.fail("start_backend")

        with self.assertRaisesRegex(
            BACKUP.BackupError,
            "^REVIEWER_UPGRADE_BACKUP_RECOVERY_FAILED$",
        ):
            self._run(runner)

        self.assertTrue((self.transaction / "backup-attempt-01").is_dir())
        self.assertEqual(self._ledger()["entries"], [])

        recovered = FakeRunner(self.bindings)
        receipt = self._run(recovered)

        self.assertEqual(receipt["attempt"]["number"], 2)
        self.assertEqual(receipt["prior_attempts"][0]["status"], "quarantined")
        self.assertTrue((self.transaction / "backup-quarantine-01").is_dir())
        self.assertEqual(
            [action for action, _request in recovered.events][:3],
            ["start_backend", "inspect_backend", "smoke_backend"],
        )

    def test_exact_empty_orphan_is_quarantined_but_unknown_orphan_is_preserved(self) -> None:
        orphan = self.transaction / "backup-attempt-01"
        orphan.mkdir(mode=0o700)
        runner = FakeRunner(self.bindings)

        receipt = self._run(runner)

        self.assertEqual(receipt["attempt"]["number"], 2)
        self.assertEqual(receipt["prior_attempts"][0]["status"], "quarantined")
        self.assertTrue((self.transaction / "backup-quarantine-01").is_dir())

        separate = JOURNAL.create_transaction_directory(
            self.root / "unknown-operation"
        )
        unknown = separate / "backup-attempt-01"
        unknown.mkdir(mode=0o700)
        (unknown / "unrecognized").write_bytes(b"preserve me")
        (unknown / "unrecognized").chmod(0o600)
        untouched_runner = FakeRunner(self.bindings)
        with self.assertRaisesRegex(
            BACKUP.BackupError,
            "^REVIEWER_UPGRADE_BACKUP_INVALID$",
        ):
            BACKUP.run_backup_attempt(
                separate,
                self.bindings,
                untouched_runner,
                health_interval_seconds=0,
            )
        self.assertEqual((unknown / "unrecognized").read_bytes(), b"preserve me")
        self.assertEqual(untouched_runner.events, [])

    def test_three_failed_attempts_exhaust_the_deterministic_budget(self) -> None:
        for number in range(1, BACKUP.MAX_BACKUP_ATTEMPTS + 1):
            runner = FakeRunner(self.bindings)
            runner.fail("archive_backup")
            with self.assertRaisesRegex(
                BACKUP.BackupError,
                "^REVIEWER_UPGRADE_BACKUP_FAILED$",
            ):
                self._run(runner)
            self.assertTrue(
                (self.transaction / f"backup-quarantine-{number:02d}").is_dir()
            )

        final_runner = FakeRunner(self.bindings)
        with self.assertRaisesRegex(
            BACKUP.BackupError,
            "^REVIEWER_UPGRADE_BACKUP_ATTEMPTS_EXHAUSTED$",
        ):
            self._run(final_runner)
        ledger = self._ledger()
        self.assertEqual(ledger["sequence"], BACKUP.MAX_BACKUP_ATTEMPTS)
        self.assertEqual(len(ledger["entries"]), BACKUP.MAX_BACKUP_ATTEMPTS)
        self.assertNotIn("stop_backend", [event[0] for event in final_runner.events])

    def test_bindings_are_exact_command_safe_and_host_files_stay_sealed(self) -> None:
        cases: list[tuple[str, object]] = [
            ("source.generation", "../generation"),
            ("source.state_directory", str(self.source) + "\n"),
            ("backend.image_ref", "tacua-backend:latest"),
            ("config.mode", 0o600),
        ]
        for label, replacement in cases:
            with self.subTest(label=label):
                document = deepcopy(self.binding_document)
                section, key = label.split(".")
                document[section][key] = replacement
                with self.assertRaisesRegex(
                    BACKUP.BackupError,
                    "^REVIEWER_UPGRADE_BACKUP_INVALID$",
                ):
                    BACKUP.validate_backup_bindings(document)

        self.config.chmod(0o600)
        runner = FakeRunner(self.bindings)
        with self.assertRaisesRegex(
            BACKUP.BackupError,
            "^REVIEWER_UPGRADE_BACKUP_INVALID$",
        ):
            self._run(runner)
        self.assertEqual(runner.events, [])

    def test_backend_commitment_mismatch_fails_before_stop(self) -> None:
        runner = FakeRunner(self.bindings)
        runner.inspect_override["image_id"] = "sha256:" + "0" * 64

        with self.assertRaisesRegex(
            BACKUP.BackupError,
            "^REVIEWER_UPGRADE_BACKUP_RECOVERY_FAILED$",
        ):
            self._run(runner)

        self.assertEqual(
            [action for action, _request in runner.events],
            ["inspect_backend"],
        )

    def test_bundle_mode_and_owner_policy_are_independently_enforced(self) -> None:
        runner = FakeRunner(self.bindings)
        runner.bundle_file_mode = 0o644

        with self.assertRaisesRegex(
            BACKUP.BackupError,
            "^REVIEWER_UPGRADE_BACKUP_FAILED$",
        ):
            self._run(runner)

        bundle = self.transaction / "backup-quarantine-01" / "bundle"
        with mock.patch.object(
            BACKUP.os,
            "geteuid",
            return_value=os.geteuid() + 1,
        ):
            with self.assertRaises(BACKUP._ActionError):
                BACKUP._verify_bundle_tree(bundle)

    def test_receipt_and_ledger_tampering_are_rejected(self) -> None:
        runner = FakeRunner(self.bindings)
        receipt = self._run(runner)
        tampered = deepcopy(receipt)
        tampered["backend"]["state_volume"] = "other-volume"
        with self.assertRaisesRegex(
            BACKUP.BackupError,
            "^REVIEWER_UPGRADE_BACKUP_INVALID$",
        ):
            BACKUP.validate_backup_receipt(tampered, self.bindings)

        ledger_path = self.transaction / BACKUP.BACKUP_LEDGER_FILE
        ledger = self._ledger()
        ledger["entries"][0]["status"] = "failed"
        ledger_path.write_text(
            json.dumps(ledger, separators=(",", ":"), sort_keys=True),
            encoding="ascii",
        )
        ledger_path.chmod(0o600)
        untouched = FakeRunner(self.bindings)
        with self.assertRaisesRegex(
            BACKUP.BackupError,
            "^REVIEWER_UPGRADE_BACKUP_INVALID$",
        ):
            self._run(untouched)
        self.assertEqual(untouched.events, [])

    def test_invalid_runtime_bounds_fail_without_side_effects(self) -> None:
        for interval in (float("nan"), float("inf"), -1, 61):
            with self.subTest(interval=interval):
                runner = FakeRunner(self.bindings)
                with self.assertRaisesRegex(
                    BACKUP.BackupError,
                    "^REVIEWER_UPGRADE_BACKUP_INVALID$",
                ):
                    BACKUP.run_backup_attempt(
                        self.transaction,
                        self.bindings,
                        runner,
                        health_interval_seconds=interval,
                    )
                self.assertEqual(runner.events, [])


if __name__ == "__main__":
    unittest.main()
