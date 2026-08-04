# SPDX-License-Identifier: Apache-2.0
"""Focused contracts for durable reviewer unit-bundle sidecars."""

from __future__ import annotations

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

import reviewer_upgrade_journal as JOURNAL  # noqa: E402
import reviewer_upgrade_systemd as SYSTEMD  # noqa: E402
import reviewer_upgrade_unit_artifacts as ARTIFACTS  # noqa: E402


class ReviewerUpgradeUnitArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.transaction = JOURNAL.create_transaction_directory(
            self.root / "transaction"
        )
        self.old = self._bundle("old")
        self.target = self._bundle("target")

    def _bundle(
        self,
        marker: str,
        *,
        payload_size: int | None = None,
    ) -> SYSTEMD.UnitBundle:
        payloads: dict[str, bytes] = {}
        for name in SYSTEMD.UNIT_NAMES:
            prefix = f"{marker}:{name}\n".encode("ascii")
            if payload_size is None:
                payload = prefix
            else:
                payload = (prefix + b"x" * payload_size)[:payload_size]
            payloads[name] = payload
        return SYSTEMD.UnitBundle.from_payloads(payloads)

    def _prepare(self) -> list[dict]:
        return ARTIFACTS.prepare_unit_bundle_artifacts(
            self.transaction,
            self.old,
            self.target,
        )

    def _artifact_entries(self) -> list[Path]:
        return sorted(
            (
                path
                for path in self.transaction.iterdir()
                if path.name.startswith(ARTIFACTS.ARTIFACT_PREFIX)
                or path.name.startswith("." + ARTIFACTS.ARTIFACT_PREFIX)
            ),
            key=lambda path: path.name,
        )

    def test_prepare_returns_strict_json_descriptors_and_loads_exact_bundles(
        self,
    ) -> None:
        with mock.patch.object(
            ARTIFACTS.os,
            "fsync",
            wraps=os.fsync,
        ) as fsync:
            descriptors = self._prepare()

        expected_order = [
            (role, name)
            for role in ARTIFACTS.ROLES
            for name in SYSTEMD.UNIT_NAMES
        ]
        self.assertEqual(
            [(item["role"], item["name"]) for item in descriptors],
            expected_order,
        )
        self.assertTrue(
            all(
                set(item)
                == {"role", "name", "relative_path", "size", "sha256"}
                for item in descriptors
            )
        )
        self.assertEqual(
            ARTIFACTS.validate_unit_artifact_descriptors(descriptors),
            descriptors,
        )
        json.dumps(descriptors, allow_nan=False, sort_keys=True)
        JOURNAL.canonical_json({"unit_artifacts": descriptors})
        self.assertGreaterEqual(fsync.call_count, 13)

        expected_paths = {item["relative_path"] for item in descriptors}
        self.assertEqual(
            {path.name for path in self._artifact_entries()},
            expected_paths,
        )
        for descriptor in descriptors:
            path = self.transaction / descriptor["relative_path"]
            metadata = path.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(metadata.st_uid, os.geteuid())
            self.assertEqual(metadata.st_nlink, 1)
            self.assertEqual(metadata.st_size, descriptor["size"])

        loaded_old, loaded_target = ARTIFACTS.load_unit_bundle_artifacts(
            self.transaction,
            descriptors,
        )
        self.assertEqual(loaded_old, self.old)
        self.assertEqual(loaded_target, self.target)

    def test_exact_preparation_is_idempotent_without_replacing_files(self) -> None:
        first = self._prepare()
        identities = {
            item["relative_path"]: (
                self.transaction / item["relative_path"]
            ).stat().st_ino
            for item in first
        }

        second = self._prepare()

        self.assertEqual(second, first)
        self.assertEqual(
            {
                item["relative_path"]: (
                    self.transaction / item["relative_path"]
                ).stat().st_ino
                for item in second
            },
            identities,
        )

    def test_partial_preparation_is_safely_retryable(self) -> None:
        real_link = os.link
        links = 0

        def interrupt_third_link(*args, **kwargs):
            nonlocal links
            links += 1
            if links == 3:
                raise OSError("synthetic interruption")
            return real_link(*args, **kwargs)

        with mock.patch.object(
            ARTIFACTS.os,
            "link",
            side_effect=interrupt_third_link,
        ):
            with self.assertRaises(ARTIFACTS.UnitArtifactError):
                self._prepare()

        self.assertEqual(len(self._artifact_entries()), 2)
        descriptors = self._prepare()
        self.assertEqual(len(self._artifact_entries()), 6)
        self.assertEqual(
            ARTIFACTS.load_unit_bundle_artifacts(
                self.transaction,
                descriptors,
            ),
            (self.old, self.target),
        )

    def test_publication_collision_never_overwrites_the_racing_file(self) -> None:
        final = self.transaction / ARTIFACTS._relative_path(
            "old",
            SYSTEMD.UNIT_NAMES[0],
        )
        competitor = b"racing-writer\n"

        def publish_competitor(*_args, **_kwargs):
            final.write_bytes(competitor)
            final.chmod(0o600)
            raise FileExistsError("synthetic collision")

        with mock.patch.object(
            ARTIFACTS.os,
            "link",
            side_effect=publish_competitor,
        ):
            with self.assertRaises(ARTIFACTS.UnitArtifactError):
                self._prepare()

        self.assertEqual(final.read_bytes(), competitor)
        self.assertEqual(self._artifact_entries(), [final])

    def test_exact_orphan_draft_is_promoted_on_retry(self) -> None:
        final = ARTIFACTS._relative_path(
            "old",
            SYSTEMD.UNIT_NAMES[0],
        )
        temporary = self.transaction / f".{final}.next-123-abcdefabcdef"
        payload = self.old.artifact(SYSTEMD.UNIT_NAMES[0]).payload
        temporary.write_bytes(payload)
        temporary.chmod(0o600)

        descriptors = self._prepare()

        self.assertFalse(temporary.exists())
        self.assertEqual((self.transaction / final).read_bytes(), payload)
        self.assertEqual(
            ARTIFACTS.load_unit_bundle_artifacts(
                self.transaction,
                descriptors,
            ),
            (self.old, self.target),
        )

    def test_shared_link_crash_state_is_repaired_only_for_exact_payload(self) -> None:
        descriptors = self._prepare()
        first = descriptors[0]
        final = self.transaction / first["relative_path"]
        temporary = (
            self.transaction
            / f".{first['relative_path']}.next-123-abcdefabcdef"
        )
        os.link(final, temporary)
        self.assertEqual(final.stat().st_nlink, 2)

        self.assertEqual(self._prepare(), descriptors)

        self.assertFalse(temporary.exists())
        self.assertEqual(final.stat().st_nlink, 1)

    def test_differing_shared_link_pair_fails_without_unlinking_evidence(self) -> None:
        final = self.transaction / ARTIFACTS._relative_path(
            "old",
            SYSTEMD.UNIT_NAMES[0],
        )
        final.write_bytes(b"different\n")
        final.chmod(0o600)
        temporary = (
            self.transaction
            / f".{final.name}.next-123-abcdefabcdef"
        )
        os.link(final, temporary)

        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            self._prepare()

        self.assertTrue(final.exists())
        self.assertTrue(temporary.exists())
        self.assertEqual(final.stat().st_nlink, 2)
        self.assertEqual(final.read_bytes(), b"different\n")

    def test_differing_partial_final_fails_without_overwrite(self) -> None:
        final = self.transaction / ARTIFACTS._relative_path(
            "old",
            SYSTEMD.UNIT_NAMES[0],
        )
        final.write_bytes(b"different\n")
        final.chmod(0o600)

        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            self._prepare()

        self.assertEqual(final.read_bytes(), b"different\n")
        self.assertEqual(self._artifact_entries(), [final])

    def test_descriptor_tampering_and_non_json_shapes_are_rejected(self) -> None:
        descriptors = self._prepare()
        cases: list[object] = []
        extra = json.loads(json.dumps(descriptors))
        extra[0]["extra"] = True
        cases.append(extra)
        reordered = json.loads(json.dumps(descriptors))
        reordered[0], reordered[1] = reordered[1], reordered[0]
        cases.append(reordered)
        absolute = json.loads(json.dumps(descriptors))
        absolute[0]["relative_path"] = "/tmp/artifact"
        cases.append(absolute)
        boolean_size = json.loads(json.dumps(descriptors))
        boolean_size[0]["size"] = True
        cases.append(boolean_size)
        uppercase = json.loads(json.dumps(descriptors))
        uppercase[0]["sha256"] = uppercase[0]["sha256"].upper()
        cases.append(uppercase)
        cases.append(tuple(descriptors))

        for candidate in cases:
            with self.subTest(candidate_type=type(candidate).__name__):
                with self.assertRaises(ARTIFACTS.UnitArtifactError):
                    ARTIFACTS.load_unit_bundle_artifacts(
                        self.transaction,
                        candidate,  # type: ignore[arg-type]
                    )

    def test_content_size_and_digest_tampering_are_rejected(self) -> None:
        descriptors = self._prepare()
        first = descriptors[0]
        path = self.transaction / first["relative_path"]
        payload = bytearray(path.read_bytes())
        payload[0] ^= 1
        path.write_bytes(payload)
        path.chmod(0o600)

        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            ARTIFACTS.load_unit_bundle_artifacts(
                self.transaction,
                descriptors,
            )

    def test_missing_extra_and_draft_files_are_rejected(self) -> None:
        descriptors = self._prepare()
        missing = self.transaction / descriptors[0]["relative_path"]
        missing.unlink()
        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            ARTIFACTS.load_unit_bundle_artifacts(
                self.transaction,
                descriptors,
            )

        descriptors = self._prepare()
        extra = self.transaction / f"{ARTIFACTS.ARTIFACT_PREFIX}extra.artifact"
        extra.write_bytes(b"extra\n")
        extra.chmod(0o600)
        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            ARTIFACTS.load_unit_bundle_artifacts(
                self.transaction,
                descriptors,
            )

        extra.unlink()
        draft = (
            self.transaction
            / f".{descriptors[0]['relative_path']}.next-123-abcdefabcdef"
        )
        draft.write_bytes(b"draft\n")
        draft.chmod(0o600)
        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            ARTIFACTS.load_unit_bundle_artifacts(
                self.transaction,
                descriptors,
            )

    def test_mode_symlink_hardlink_and_owner_are_rejected(self) -> None:
        descriptors = self._prepare()
        path = self.transaction / descriptors[0]["relative_path"]
        path.chmod(0o640)
        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            ARTIFACTS.load_unit_bundle_artifacts(
                self.transaction,
                descriptors,
            )
        path.chmod(0o600)

        outside = self.root / "artifact-hardlink"
        os.link(path, outside)
        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            ARTIFACTS.load_unit_bundle_artifacts(
                self.transaction,
                descriptors,
            )
        outside.unlink()

        with mock.patch.object(
            ARTIFACTS.os,
            "geteuid",
            return_value=os.geteuid() + 1,
        ):
            with self.assertRaises(ARTIFACTS.UnitArtifactError):
                ARTIFACTS.load_unit_bundle_artifacts(
                    self.transaction,
                    descriptors,
                )

        path.unlink()
        path.symlink_to(self.transaction / descriptors[1]["relative_path"])
        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            ARTIFACTS.load_unit_bundle_artifacts(
                self.transaction,
                descriptors,
            )

    def test_per_unit_empty_and_total_bounds_fail_before_publication(self) -> None:
        oversized_payloads = self.old.payloads()
        oversized_payloads[SYSTEMD.UNIT_NAMES[0]] = b"x" * (
            ARTIFACTS.MAX_UNIT_ARTIFACT_BYTES + 1
        )
        oversized = SYSTEMD.UnitBundle.from_payloads(oversized_payloads)
        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            ARTIFACTS.prepare_unit_bundle_artifacts(
                self.transaction,
                oversized,
                self.target,
            )
        self.assertEqual(self._artifact_entries(), [])

        empty_payloads = self.old.payloads()
        empty_payloads[SYSTEMD.UNIT_NAMES[0]] = b""
        empty = SYSTEMD.UnitBundle.from_payloads(empty_payloads)
        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            ARTIFACTS.prepare_unit_bundle_artifacts(
                self.transaction,
                empty,
                self.target,
            )
        self.assertEqual(self._artifact_entries(), [])

        large_old = self._bundle("large-old", payload_size=50_000)
        large_target = self._bundle("large-target", payload_size=50_000)
        with self.assertRaises(ARTIFACTS.UnitArtifactError):
            ARTIFACTS.prepare_unit_bundle_artifacts(
                self.transaction,
                large_old,
                large_target,
            )
        self.assertEqual(self._artifact_entries(), [])


if __name__ == "__main__":
    unittest.main()
