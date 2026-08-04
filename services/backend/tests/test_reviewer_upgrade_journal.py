# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "services/backend/scripts/reviewer_upgrade_journal.py"


def _load_script():
    specification = importlib.util.spec_from_file_location(
        "tacua_reviewer_upgrade_journal_test",
        SCRIPT,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("reviewer upgrade journal cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


JOURNAL = _load_script()


class ReviewerUpgradeJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.transaction = JOURNAL.create_transaction_directory(
            self.root / "reviewer-upgrade-test"
        )
        self.plan_payload = {
            "candidate": {
                "commit": "a" * 40,
                "image_id": "sha256:" + "b" * 64,
                "image_ref": "tacua-reviewer-web:qa-a1",
            },
            "project": "tacua",
            "source": {
                "container_id": "c" * 64,
                "manifest_digest": "sha256:" + "d" * 64,
            },
            "transaction_id": "reviewer-upgrade-20260804t010203z",
        }

    def _write_plan(self) -> dict:
        return JOURNAL.write_immutable_plan(
            self.transaction,
            self.plan_payload,
        )

    def _replace_journal_file(self, name: str, payload: bytes) -> Path:
        path = self.transaction / name
        path.unlink(missing_ok=True)
        path.write_bytes(payload)
        path.chmod(0o600)
        return path

    def test_directory_and_plan_are_private_canonical_and_immutable(self) -> None:
        directory_metadata = self.transaction.lstat()
        self.assertTrue(stat.S_ISDIR(directory_metadata.st_mode))
        self.assertEqual(stat.S_IMODE(directory_metadata.st_mode), 0o700)
        self.assertEqual(directory_metadata.st_uid, os.geteuid())

        plan = self._write_plan()
        plan_path = self.transaction / JOURNAL.PLAN_FILE
        metadata = plan_path.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_uid, os.geteuid())
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(plan_path.read_bytes(), JOURNAL.canonical_json(plan))
        self.assertEqual(JOURNAL.load_plan(self.transaction), plan)
        self.assertRegex(plan["plan_digest"], r"^sha256:[a-f0-9]{64}$")

        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.write_plan(self.transaction, self.plan_payload)
        self.assertEqual(JOURNAL.load_plan(self.transaction), plan)

    def test_immutable_plan_publication_never_replaces_a_racing_file(self) -> None:
        plan_path = self.transaction / JOURNAL.PLAN_FILE
        competitor = b"racing-writer"

        def publish_competitor(*_args, **_kwargs):
            plan_path.write_bytes(competitor)
            plan_path.chmod(0o600)
            raise FileExistsError("synthetic publication collision")

        with mock.patch.object(
            JOURNAL.os,
            "link",
            side_effect=publish_competitor,
        ):
            with self.assertRaises(JOURNAL.JournalError) as raised:
                JOURNAL.write_immutable_plan(
                    self.transaction,
                    self.plan_payload,
                )
        self.assertEqual(raised.exception.code, "REVIEWER_UPGRADE_JOURNAL_EXISTS")
        self.assertEqual(plan_path.read_bytes(), competitor)
        self.assertEqual(
            sorted(path.name for path in self.transaction.iterdir()),
            [JOURNAL.PLAN_FILE],
        )

    def test_interrupted_immutable_publication_is_durably_recovered(self) -> None:
        plan = self._write_plan()
        plan_path = self.transaction / JOURNAL.PLAN_FILE
        interrupted = (
            self.transaction
            / f".{JOURNAL.PLAN_FILE}.next-123-abcdefabcdef"
        )
        os.link(plan_path, interrupted)
        self.assertEqual(plan_path.stat().st_nlink, 2)

        with mock.patch.object(JOURNAL.os, "fsync", wraps=os.fsync) as fsync:
            self.assertEqual(JOURNAL.load_plan(self.transaction), plan)
        self.assertGreaterEqual(fsync.call_count, 1)
        self.assertFalse(interrupted.exists())
        self.assertEqual(plan_path.stat().st_nlink, 1)

    def test_unrecognized_hardlink_is_not_repaired(self) -> None:
        self._write_plan()
        plan_path = self.transaction / JOURNAL.PLAN_FILE
        unrecognized = self.transaction / ".plan.json.next-untrusted"
        os.link(plan_path, unrecognized)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_plan(self.transaction)
        self.assertTrue(unrecognized.exists())
        self.assertEqual(plan_path.stat().st_nlink, 2)

    def test_plan_completion_and_receipt_publications_are_fully_fsynced(self) -> None:
        with mock.patch.object(JOURNAL.os, "fsync", wraps=os.fsync) as fsync:
            plan = self._write_plan()
        self.assertGreaterEqual(fsync.call_count, 2)

        JOURNAL.checkpoint_progress(self.transaction, plan, "prepared")
        with mock.patch.object(JOURNAL.os, "fsync", wraps=os.fsync) as fsync:
            JOURNAL.checkpoint_progress(self.transaction, plan, "complete")
        self.assertGreaterEqual(fsync.call_count, 2)

        with mock.patch.object(JOURNAL.os, "fsync", wraps=os.fsync) as fsync:
            JOURNAL.write_receipt(self.transaction, plan)
        self.assertGreaterEqual(fsync.call_count, 2)

    def test_create_is_exclusive_and_fsyncs_the_parent(self) -> None:
        candidate = self.root / "durable-transaction"
        with mock.patch.object(JOURNAL.os, "fsync", wraps=os.fsync) as fsync:
            created = JOURNAL.create_transaction_directory(candidate)
        self.assertEqual(created, candidate)
        self.assertGreaterEqual(fsync.call_count, 1)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.create_transaction_directory(candidate)

    def test_plan_rejects_tamper_and_noncanonical_json_forms(self) -> None:
        plan = self._write_plan()
        changed = json.loads(JOURNAL.canonical_json(plan))
        changed["plan"]["project"] = "another-project"
        self._replace_journal_file(
            JOURNAL.PLAN_FILE,
            JOURNAL.canonical_json(changed),
        )
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_plan(self.transaction)

        cases = (
            b'{"contract_version":"x","contract_version":"x"}',
            b' {"value":1}',
            b'{"value":1}\n',
            b'{"value":1.0}',
            b'{"value":NaN}',
            b'\xef\xbb\xbf{"value":1}',
            b'{"value":"\xc3\xa9"}',
        )
        for payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(JOURNAL.JournalError):
                    JOURNAL.parse_canonical_json(payload)

    def test_plan_rejects_float_unsupported_shapes_and_bounds(self) -> None:
        cases = (
            {"float": 1.5},
            {"tuple": (1, 2)},
            {"long": "x" * (JOURNAL.MAX_STRING_BYTES + 1)},
            {},
        )
        for payload in cases:
            with self.subTest(payload_type=type(payload).__name__):
                with self.assertRaises(JOURNAL.JournalError):
                    JOURNAL.write_plan(self.transaction, payload)

        nested: object = "leaf"
        for _index in range(JOURNAL.MAX_DEPTH + 1):
            nested = {"child": nested}
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.write_plan(self.transaction, {"nested": nested})

    def test_transaction_directory_rejects_symlink_wrong_mode_and_owner(self) -> None:
        real = self.root / "real-directory"
        real.mkdir(mode=0o700)
        linked = self.root / "linked-directory"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.validate_transaction_directory(linked)

        self.transaction.chmod(0o750)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.validate_transaction_directory(self.transaction)
        self.transaction.chmod(0o700)

        with mock.patch.object(
            JOURNAL.os,
            "geteuid",
            return_value=os.geteuid() + 1,
        ):
            with self.assertRaises(JOURNAL.JournalError):
                JOURNAL.validate_transaction_directory(self.transaction)

    def test_transaction_directory_rejects_noncanonical_paths(self) -> None:
        cases = (
            "relative-transaction",
            str(self.root) + "/./dot-transaction",
            str(self.root) + "//double-slash-transaction",
            str(self.root) + "/trailing-slash/",
        )
        for path in cases:
            with self.subTest(path=path):
                with self.assertRaises(JOURNAL.JournalError):
                    JOURNAL.create_transaction_directory(path)

    def test_plan_file_rejects_symlink_hardlink_mode_and_owner(self) -> None:
        plan = self._write_plan()
        plan_path = self.transaction / JOURNAL.PLAN_FILE

        plan_path.chmod(0o640)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_plan(self.transaction)
        plan_path.chmod(0o600)

        hardlink = self.root / "plan-hardlink.json"
        os.link(plan_path, hardlink)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_plan(self.transaction)
        hardlink.unlink()
        self.assertEqual(JOURNAL.load_plan(self.transaction), plan)

        plan_path.unlink()
        plan_path.symlink_to(self.root / "missing-plan.json")
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_plan(self.transaction)

        plan_path.unlink()
        plan_path.write_bytes(JOURNAL.canonical_json(plan))
        plan_path.chmod(0o600)
        with mock.patch.object(
            JOURNAL.os,
            "geteuid",
            return_value=os.geteuid() + 1,
        ):
            with self.assertRaises(JOURNAL.JournalError):
                JOURNAL.load_plan(self.transaction)

    def test_plan_read_rejects_path_metadata_change_after_final_fstat(self) -> None:
        self._write_plan()
        plan_path = self.transaction / JOURNAL.PLAN_FILE
        real_stat = os.stat
        plan_stats = 0

        def racing_stat(path, *args, **kwargs):
            nonlocal plan_stats
            if path == JOURNAL.PLAN_FILE:
                plan_stats += 1
                if plan_stats == 3:
                    plan_path.chmod(0o640)
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(JOURNAL.os, "stat", side_effect=racing_stat):
            with self.assertRaises(JOURNAL.JournalError):
                JOURNAL.load_plan(self.transaction)
        self.assertGreaterEqual(plan_stats, 3)
        plan_path.chmod(0o600)

    def test_progress_sequence_phase_order_and_plan_binding(self) -> None:
        plan = self._write_plan()
        self.assertIsNone(JOURNAL.load_progress(self.transaction, plan))
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.checkpoint_progress(
                self.transaction,
                plan,
                "replacing",
            )

        prepared = JOURNAL.checkpoint_progress(
            self.transaction,
            plan,
            "prepared",
            {"serve": "empty"},
        )
        self.assertEqual(prepared["sequence"], 1)
        self.assertEqual(prepared["phase"], "prepared")
        repeated = JOURNAL.checkpoint_progress(
            self.transaction,
            plan,
            "prepared",
            {"retry": 1},
        )
        self.assertEqual(repeated["sequence"], 2)
        ready = JOURNAL.checkpoint_progress(
            self.transaction,
            plan,
            "reviewer_ready",
        )
        self.assertEqual(ready["sequence"], 3)
        self.assertEqual(JOURNAL.load_progress(self.transaction, plan), ready)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.checkpoint_progress(
                self.transaction,
                plan,
                "replacing",
            )
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.checkpoint_progress(
                self.transaction,
                plan,
                "not-a-phase",
            )

        other_transaction = JOURNAL.create_transaction_directory(
            self.root / "other-transaction"
        )
        other_plan = JOURNAL.write_plan(
            other_transaction,
            {"transaction_id": "other"},
        )
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_progress(self.transaction, other_plan)

    def test_progress_access_takes_the_serial_transaction_lock(self) -> None:
        plan = self._write_plan()
        with mock.patch.object(
            JOURNAL.fcntl,
            "flock",
            wraps=JOURNAL.fcntl.flock,
        ) as flock:
            JOURNAL.checkpoint_progress(self.transaction, plan, "prepared")
        self.assertEqual(flock.call_count, 1)
        self.assertEqual(flock.call_args.args[1], JOURNAL.fcntl.LOCK_EX)

    def test_progress_rejects_another_transaction_plan_before_first_write(self) -> None:
        self._write_plan()
        other_transaction = JOURNAL.create_transaction_directory(
            self.root / "other-plan-transaction"
        )
        other_plan = JOURNAL.write_immutable_plan(
            other_transaction,
            {"transaction_id": "other-plan"},
        )
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_progress(self.transaction, other_plan)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.checkpoint_progress(
                self.transaction,
                other_plan,
                "prepared",
            )
        self.assertFalse((self.transaction / JOURNAL.PROGRESS_FILE).exists())

    def test_progress_rejects_float_duplicate_bom_mode_and_hardlink(self) -> None:
        plan = self._write_plan()
        progress = JOURNAL.checkpoint_progress(
            self.transaction,
            plan,
            "prepared",
        )
        progress_path = self.transaction / JOURNAL.PROGRESS_FILE
        progress_path.chmod(0o644)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_progress(self.transaction, plan)
        progress_path.chmod(0o600)

        hardlink = self.root / "progress-hardlink.json"
        os.link(progress_path, hardlink)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_progress(self.transaction, plan)
        hardlink.unlink()
        self.assertEqual(JOURNAL.load_progress(self.transaction, plan), progress)

        malformed = (
            b'{"phase":"prepared","phase":"prepared"}',
            b'{"sequence":1.0}',
            b'\xef\xbb\xbf{}',
        )
        for payload in malformed:
            with self.subTest(payload=payload):
                self._replace_journal_file(JOURNAL.PROGRESS_FILE, payload)
                with self.assertRaises(JOURNAL.JournalError):
                    JOURNAL.load_progress(self.transaction, plan)

    def test_progress_replace_failure_preserves_previous_checkpoint(self) -> None:
        plan = self._write_plan()
        prepared = JOURNAL.checkpoint_progress(
            self.transaction,
            plan,
            "prepared",
        )
        with mock.patch.object(
            JOURNAL.os,
            "replace",
            side_effect=OSError("synthetic replace failure"),
        ):
            with self.assertRaises(JOURNAL.JournalError):
                JOURNAL.checkpoint_progress(
                    self.transaction,
                    plan,
                    "replacing",
                )
        self.assertEqual(
            JOURNAL.load_progress(self.transaction, plan),
            prepared,
        )
        self.assertEqual(
            sorted(path.name for path in self.transaction.iterdir()),
            [JOURNAL.PLAN_FILE, JOURNAL.PROGRESS_FILE],
        )

    def test_cleanup_failure_does_not_mask_progress_publication_failure(self) -> None:
        plan = self._write_plan()
        JOURNAL.checkpoint_progress(self.transaction, plan, "prepared")
        real_fsync = os.fsync

        def fail_directory_fsync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("synthetic cleanup failure")
            return real_fsync(descriptor)

        with mock.patch.object(
            JOURNAL.os,
            "replace",
            side_effect=OSError("synthetic publication failure"),
        ), mock.patch.object(
            JOURNAL.os,
            "fsync",
            side_effect=fail_directory_fsync,
        ):
            with self.assertRaises(JOURNAL.JournalError) as raised:
                JOURNAL.checkpoint_progress(
                    self.transaction,
                    plan,
                    "replacing",
                )
        self.assertIsInstance(raised.exception.__cause__, OSError)
        self.assertEqual(
            str(raised.exception.__cause__),
            "synthetic publication failure",
        )

    def test_complete_is_terminal_and_receipt_is_bound_and_immutable(self) -> None:
        plan = self._write_plan()
        JOURNAL.checkpoint_progress(
            self.transaction,
            plan,
            "prepared",
        )
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.write_receipt(self.transaction, plan)

        complete = JOURNAL.checkpoint_progress(
            self.transaction,
            plan,
            "complete",
            {"health": "verified"},
        )
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.checkpoint_progress(
                self.transaction,
                plan,
                "complete",
            )
        receipt = JOURNAL.write_receipt(
            self.transaction,
            plan,
            {"outcome": "committed"},
        )
        self.assertEqual(receipt["phase"], "complete")
        self.assertEqual(receipt["sequence"], complete["sequence"])
        self.assertEqual(
            receipt["progress_digest"],
            complete["progress_digest"],
        )
        self.assertEqual(JOURNAL.load_receipt(self.transaction, plan), receipt)
        receipt_path = self.transaction / JOURNAL.RECEIPT_FILE
        self.assertEqual(receipt_path.read_bytes(), JOURNAL.canonical_json(receipt))
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.write_receipt(self.transaction, plan)

    def test_receipt_rejects_progress_and_receipt_tampering(self) -> None:
        plan = self._write_plan()
        JOURNAL.checkpoint_progress(self.transaction, plan, "prepared")
        complete = JOURNAL.checkpoint_progress(
            self.transaction,
            plan,
            "complete",
        )
        receipt = JOURNAL.write_receipt(self.transaction, plan)

        changed_receipt = dict(receipt)
        changed_receipt["progress_digest"] = "sha256:" + "0" * 64
        changed_receipt["receipt_digest"] = JOURNAL._document_digest(
            changed_receipt,
            "receipt_digest",
        )
        self._replace_journal_file(
            JOURNAL.RECEIPT_FILE,
            JOURNAL.canonical_json(changed_receipt),
        )
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_receipt(self.transaction, plan)

        self._replace_journal_file(
            JOURNAL.RECEIPT_FILE,
            JOURNAL.canonical_json(receipt),
        )
        changed_progress = dict(complete)
        changed_progress["details"] = {"changed": True}
        changed_progress["progress_digest"] = JOURNAL._document_digest(
            changed_progress,
            "progress_digest",
        )
        self._replace_journal_file(
            JOURNAL.PROGRESS_FILE,
            JOURNAL.canonical_json(changed_progress),
        )
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_receipt(self.transaction, plan)

    def test_oversized_file_and_integer_are_rejected(self) -> None:
        self._write_plan()
        self._replace_journal_file(
            JOURNAL.PLAN_FILE,
            b"x" * (JOURNAL.MAX_DOCUMENT_BYTES + 1),
        )
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.load_plan(self.transaction)
        with self.assertRaises(JOURNAL.JournalError):
            JOURNAL.parse_canonical_json(
                b'{"value":9223372036854775808}'
            )


if __name__ == "__main__":
    unittest.main()
