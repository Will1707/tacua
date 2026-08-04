# SPDX-License-Identifier: Apache-2.0
"""Focused contracts for crash-safe reviewer-upgrade unit promotion."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "services" / "backend" / "scripts"
SYSTEMD_TEMPLATES = ROOT / "services" / "backend" / "systemd"
sys.path.insert(0, str(SCRIPTS))

import reviewer_upgrade_systemd as UPGRADE_SYSTEMD  # noqa: E402


class ReviewerUpgradeSystemdTests(unittest.TestCase):
    def _bindings(self) -> UPGRADE_SYSTEMD.ReconcileUnitBindings:
        root = Path("/private/tacua")
        return UPGRADE_SYSTEMD.ReconcileUnitBindings(
            python=root / "bin/python3",
            reconciler=root / "repo/services/backend/scripts/reconciler.py",
            state_directory=root / "state/target",
            lock_file=root / "runtime/processing.lock",
            anchor_file=root / "runtime/anchor.json",
            operation_directory=root / "operations",
            config_file=root / "config.json",
            admin_secret_file=root / "admin-secret",
        )

    def _synthetic_bundle(self, marker: str) -> UPGRADE_SYSTEMD.UnitBundle:
        return UPGRADE_SYSTEMD.UnitBundle.from_payloads(
            {
                name: f"{marker}:{name}\n".encode("ascii")
                for name in UPGRADE_SYSTEMD.UNIT_NAMES
            }
        )

    def _install_bundle(
        self,
        directory: Path,
        bundle: UPGRADE_SYSTEMD.UnitBundle,
    ) -> None:
        for artifact in bundle.units:
            path = directory / artifact.name
            path.write_bytes(artifact.payload)
            path.chmod(0o600)

    def _copy_templates(self, directory: Path) -> None:
        directory.mkdir(mode=0o700)
        for name in UPGRADE_SYSTEMD.TEMPLATE_NAMES.values():
            target = directory / name
            target.write_bytes((SYSTEMD_TEMPLATES / name).read_bytes())
            target.chmod(0o600)

    def test_render_is_deterministic_and_replaces_the_exact_token_abi(
        self,
    ) -> None:
        first = UPGRADE_SYSTEMD.render_reconcile_unit_bundle(
            SYSTEMD_TEMPLATES,
            self._bindings(),
        )
        second = UPGRADE_SYSTEMD.render_reconcile_unit_bundle(
            SYSTEMD_TEMPLATES,
            self._bindings(),
        )

        self.assertEqual(first, second)
        self.assertEqual(first.digests(), second.digests())
        main = first.artifact("tacua-reconcile.service").payload.decode()
        lock = first.artifact("tacua-reconcile-lock.service").payload.decode()
        timer = first.artifact("tacua-reconcile.timer").payload
        self.assertIn(
            '--state-directory "/private/tacua/state/target"',
            main,
        )
        self.assertIn(
            '--anchor-file "/private/tacua/runtime/anchor.json"',
            lock,
        )
        self.assertEqual(
            timer,
            (
                SYSTEMD_TEMPLATES / "tacua-reconcile.timer"
            ).read_bytes(),
        )
        for artifact in first.units:
            self.assertIsNone(
                UPGRADE_SYSTEMD.PLACEHOLDER.search(
                    artifact.payload.decode("utf-8")
                )
            )

    def test_render_rejects_template_contract_drift_and_unsafe_paths(
        self,
    ) -> None:
        templates = {
            name: (SYSTEMD_TEMPLATES / name).read_bytes()
            for name in UPGRADE_SYSTEMD.TEMPLATE_NAMES.values()
        }
        main_name = "tacua-reconcile.service.in"
        templates[main_name] = templates[main_name].replace(
            b"@PYTHON@",
            b"/unexpected/python",
            1,
        )
        with self.assertRaisesRegex(
            UPGRADE_SYSTEMD.UnitContractError,
            "UPGRADE_UNIT_TEMPLATE_INVALID",
        ):
            UPGRADE_SYSTEMD.render_reconcile_units(
                templates,
                self._bindings(),
            )

        unsafe = self._bindings()
        unsafe = UPGRADE_SYSTEMD.ReconcileUnitBindings(
            python=Path("/private/unsafe path/python"),
            reconciler=unsafe.reconciler,
            state_directory=unsafe.state_directory,
            lock_file=unsafe.lock_file,
            anchor_file=unsafe.anchor_file,
            operation_directory=unsafe.operation_directory,
            config_file=unsafe.config_file,
            admin_secret_file=unsafe.admin_secret_file,
        )
        with self.assertRaisesRegex(
            UPGRADE_SYSTEMD.UnitContractError,
            "UPGRADE_UNIT_BINDING_INVALID",
        ):
            UPGRADE_SYSTEMD.render_reconcile_unit_bundle(
                SYSTEMD_TEMPLATES,
                unsafe,
            )

    def test_template_directory_ancestry_and_binding_are_attested(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            writable_parent = root / "writable-parent"
            writable_parent.mkdir(mode=0o700)
            templates = writable_parent / "templates"
            self._copy_templates(templates)
            writable_parent.chmod(0o777)
            with self.assertRaisesRegex(
                UPGRADE_SYSTEMD.UnitContractError,
                "UPGRADE_UNIT_TEMPLATE_INVALID",
            ):
                UPGRADE_SYSTEMD.render_reconcile_unit_bundle(
                    templates,
                    self._bindings(),
                )

            writable_parent.chmod(0o700)
            moved = writable_parent / "templates-original"
            replacement_payloads = {
                name: (templates / name).read_bytes()
                for name in UPGRADE_SYSTEMD.TEMPLATE_NAMES.values()
            }
            real_read = UPGRADE_SYSTEMD._read_template
            calls = 0

            def swap_directory(descriptor, name):
                nonlocal calls
                payload = real_read(descriptor, name)
                calls += 1
                if calls == 1:
                    templates.rename(moved)
                    templates.mkdir(mode=0o700)
                    for template_name, template_payload in replacement_payloads.items():
                        path = templates / template_name
                        path.write_bytes(template_payload)
                        path.chmod(0o600)
                return payload

            with mock.patch.object(
                UPGRADE_SYSTEMD,
                "_read_template",
                side_effect=swap_directory,
            ):
                with self.assertRaisesRegex(
                    UPGRADE_SYSTEMD.UnitContractError,
                    "UPGRADE_UNIT_TEMPLATE_INVALID",
                ):
                    UPGRADE_SYSTEMD.render_reconcile_unit_bundle(
                        templates,
                        self._bindings(),
                    )

    def test_template_read_rejects_full_metadata_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            templates = Path(temporary).resolve() / "templates"
            self._copy_templates(templates)
            first_name = next(iter(UPGRADE_SYSTEMD.TEMPLATE_NAMES.values()))
            first_path = templates / first_name
            real_read = UPGRADE_SYSTEMD._read_bounded
            changed = False

            def mutate_after_read(descriptor):
                nonlocal changed
                payload = real_read(descriptor)
                if not changed:
                    changed = True
                    metadata = first_path.stat()
                    os.utime(
                        first_path,
                        ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
                    )
                return payload

            with mock.patch.object(
                UPGRADE_SYSTEMD,
                "_read_bounded",
                side_effect=mutate_after_read,
            ):
                with self.assertRaisesRegex(
                    UPGRADE_SYSTEMD.UnitContractError,
                    "UPGRADE_UNIT_TEMPLATE_INVALID",
                ):
                    UPGRADE_SYSTEMD.render_reconcile_unit_bundle(
                        templates,
                        self._bindings(),
                    )

    def test_snapshot_records_exact_bytes_and_digests(self) -> None:
        old = self._synthetic_bundle("old")
        with tempfile.TemporaryDirectory() as temporary:
            unit_directory = Path(temporary).resolve()
            unit_directory.chmod(0o700)
            self._install_bundle(unit_directory, old)

            snapshot = UPGRADE_SYSTEMD.snapshot_installed_units(
                unit_directory
            )

        self.assertEqual(snapshot, old)
        self.assertEqual(
            snapshot.digests(),
            {
                artifact.name: UPGRADE_SYSTEMD.digest_payload(
                    artifact.payload
                )
                for artifact in old.units
            },
        )

    def test_classification_accepts_only_exact_old_or_target_bytes(
        self,
    ) -> None:
        old = self._synthetic_bundle("old")
        target = self._synthetic_bundle("target")
        with tempfile.TemporaryDirectory() as temporary:
            unit_directory = Path(temporary).resolve()
            unit_directory.chmod(0o700)
            self._install_bundle(unit_directory, old)
            (unit_directory / UPGRADE_SYSTEMD.UNIT_NAMES[1]).write_bytes(
                target.artifact(UPGRADE_SYSTEMD.UNIT_NAMES[1]).payload
            )
            (unit_directory / UPGRADE_SYSTEMD.UNIT_NAMES[2]).write_bytes(
                b"operator change\n"
            )

            classifications = UPGRADE_SYSTEMD.classify_installed_units(
                unit_directory,
                old,
                target,
            )

        self.assertEqual(
            tuple(item.state for item in classifications),
            (
                UPGRADE_SYSTEMD.InstalledUnitState.OLD,
                UPGRADE_SYSTEMD.InstalledUnitState.TARGET,
                UPGRADE_SYSTEMD.InstalledUnitState.UNKNOWN,
            ),
        )

    def test_equal_old_and_target_payload_is_classified_as_target(self) -> None:
        old = self._synthetic_bundle("same")
        installed = old.payloads()

        classifications = UPGRADE_SYSTEMD.classify_unit_payloads(
            installed,
            old,
            old,
        )

        self.assertTrue(
            all(
                item.state is UPGRADE_SYSTEMD.InstalledUnitState.TARGET
                for item in classifications
            )
        )

    def test_converge_rejects_unknown_content_without_overwriting_it(
        self,
    ) -> None:
        old = self._synthetic_bundle("old")
        target = self._synthetic_bundle("target")
        with tempfile.TemporaryDirectory() as temporary:
            unit_directory = Path(temporary).resolve()
            unit_directory.chmod(0o700)
            self._install_bundle(unit_directory, old)
            unknown = unit_directory / UPGRADE_SYSTEMD.UNIT_NAMES[1]
            unknown.write_bytes(b"operator change\n")

            with self.assertRaisesRegex(
                UPGRADE_SYSTEMD.UnitContractError,
                "UPGRADE_UNIT_CONTENT_UNKNOWN",
            ):
                UPGRADE_SYSTEMD.converge_installed_units(
                    unit_directory,
                    old,
                    target,
                )

            self.assertEqual(unknown.read_bytes(), b"operator change\n")
            self.assertEqual(
                (unit_directory / UPGRADE_SYSTEMD.UNIT_NAMES[0]).read_bytes(),
                old.artifact(UPGRADE_SYSTEMD.UNIT_NAMES[0]).payload,
            )

    def test_interrupted_convergence_leaves_a_resumable_mixture(self) -> None:
        old = self._synthetic_bundle("old")
        target = self._synthetic_bundle("target")
        with tempfile.TemporaryDirectory() as temporary:
            unit_directory = Path(temporary).resolve()
            unit_directory.chmod(0o700)
            self._install_bundle(unit_directory, old)
            real_replace = UPGRADE_SYSTEMD.os.replace
            replacements = 0

            def interrupt_second_replace(*args, **kwargs):
                nonlocal replacements
                replacements += 1
                if replacements == 2:
                    raise OSError("synthetic interruption")
                return real_replace(*args, **kwargs)

            with mock.patch.object(
                UPGRADE_SYSTEMD.os,
                "replace",
                side_effect=interrupt_second_replace,
            ):
                with self.assertRaisesRegex(
                    UPGRADE_SYSTEMD.UnitContractError,
                    "UPGRADE_UNIT_INSTALL_FAILED",
                ):
                    UPGRADE_SYSTEMD.converge_installed_units(
                        unit_directory,
                        old,
                        target,
                    )

            interrupted = UPGRADE_SYSTEMD.classify_installed_units(
                unit_directory,
                old,
                target,
            )
            self.assertEqual(
                tuple(item.state for item in interrupted),
                (
                    UPGRADE_SYSTEMD.InstalledUnitState.TARGET,
                    UPGRADE_SYSTEMD.InstalledUnitState.OLD,
                    UPGRADE_SYSTEMD.InstalledUnitState.OLD,
                ),
            )

            completed = UPGRADE_SYSTEMD.converge_installed_units(
                unit_directory,
                old,
                target,
            )
            self.assertTrue(
                all(
                    item.state is UPGRADE_SYSTEMD.InstalledUnitState.TARGET
                    for item in completed
                )
            )
            for artifact in target.units:
                path = unit_directory / artifact.name
                self.assertEqual(path.read_bytes(), artifact.payload)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_exact_fsynced_staging_orphan_resumes_after_host_crash(self) -> None:
        old = self._synthetic_bundle("old")
        target = self._synthetic_bundle("target")
        with tempfile.TemporaryDirectory() as temporary:
            unit_directory = Path(temporary).resolve()
            unit_directory.chmod(0o700)
            self._install_bundle(unit_directory, old)
            name = UPGRADE_SYSTEMD.UNIT_NAMES[1]
            draft = unit_directory / f".{name}.next-123-abcdefabcdef"
            draft.write_bytes(target.artifact(name).payload)
            draft.chmod(0o600)

            completed = UPGRADE_SYSTEMD.converge_installed_units(
                unit_directory,
                old,
                target,
            )

            self.assertFalse(draft.exists())
            self.assertTrue(
                all(
                    item.state is UPGRADE_SYSTEMD.InstalledUnitState.TARGET
                    for item in completed
                )
            )

    def test_partial_staging_orphan_is_removed_durably_before_retry(self) -> None:
        old = self._synthetic_bundle("old")
        target = self._synthetic_bundle("target")
        with tempfile.TemporaryDirectory() as temporary:
            unit_directory = Path(temporary).resolve()
            unit_directory.chmod(0o700)
            self._install_bundle(unit_directory, old)
            name = UPGRADE_SYSTEMD.UNIT_NAMES[0]
            draft = unit_directory / f".{name}.next-456-abcdefabcdef"
            draft.write_bytes(target.artifact(name).payload[:7])
            draft.chmod(0o600)
            with mock.patch.object(
                UPGRADE_SYSTEMD.os,
                "fsync",
                wraps=os.fsync,
            ) as fsync:
                UPGRADE_SYSTEMD.converge_installed_units(
                    unit_directory,
                    old,
                    target,
                )

            self.assertFalse(draft.exists())
            self.assertGreaterEqual(fsync.call_count, 7)

    def test_unknown_multiple_and_unsafe_staging_fail_without_cleanup(self) -> None:
        scenarios = ("unknown", "multiple", "symlink")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as temporary:
                    old = self._synthetic_bundle("old")
                    target = self._synthetic_bundle("target")
                    unit_directory = Path(temporary).resolve()
                    unit_directory.chmod(0o700)
                    self._install_bundle(unit_directory, old)
                    name = UPGRADE_SYSTEMD.UNIT_NAMES[0]
                    first = (
                        unit_directory
                        / f".{name}.next-123-abcdefabcdef"
                    )
                    if scenario == "symlink":
                        first.symlink_to(unit_directory / name)
                    else:
                        first.write_bytes(
                            b"not-a-target-prefix"
                            if scenario == "unknown"
                            else target.artifact(name).payload
                        )
                        first.chmod(0o600)
                    evidence = [first]
                    if scenario == "multiple":
                        second = (
                            unit_directory
                            / f".{name}.next-124-abcdefabcdef"
                        )
                        second.write_bytes(target.artifact(name).payload)
                        second.chmod(0o600)
                        evidence.append(second)

                    with self.assertRaises(
                        UPGRADE_SYSTEMD.UnitContractError
                    ):
                        UPGRADE_SYSTEMD.converge_installed_units(
                            unit_directory,
                            old,
                            target,
                        )

                    self.assertTrue(
                        all(
                            path.is_symlink() or path.exists()
                            for path in evidence
                        )
                    )
                    self.assertEqual(
                        (unit_directory / name).read_bytes(),
                        old.artifact(name).payload,
                    )

    def test_unit_file_mode_and_symlink_are_rejected(self) -> None:
        old = self._synthetic_bundle("old")
        with tempfile.TemporaryDirectory() as temporary:
            unit_directory = Path(temporary).resolve()
            unit_directory.chmod(0o700)
            self._install_bundle(unit_directory, old)
            unsafe = unit_directory / UPGRADE_SYSTEMD.UNIT_NAMES[0]
            unsafe.chmod(0o644)
            with self.assertRaisesRegex(
                UPGRADE_SYSTEMD.UnitContractError,
                "UPGRADE_UNIT_FILE_UNSAFE",
            ):
                UPGRADE_SYSTEMD.snapshot_installed_units(unit_directory)

            unsafe.chmod(0o600)
            unsafe.unlink()
            unsafe.symlink_to(unit_directory / UPGRADE_SYSTEMD.UNIT_NAMES[1])
            with self.assertRaisesRegex(
                UPGRADE_SYSTEMD.UnitContractError,
                "UPGRADE_UNIT_FILE_UNSAFE",
            ):
                UPGRADE_SYSTEMD.snapshot_installed_units(unit_directory)

    def test_installed_unit_read_rejects_full_metadata_change(self) -> None:
        old = self._synthetic_bundle("old")
        with tempfile.TemporaryDirectory() as temporary:
            unit_directory = Path(temporary).resolve()
            unit_directory.chmod(0o700)
            self._install_bundle(unit_directory, old)
            first_path = unit_directory / UPGRADE_SYSTEMD.UNIT_NAMES[0]
            real_read = UPGRADE_SYSTEMD._read_bounded
            changed = False

            def mutate_after_read(descriptor):
                nonlocal changed
                payload = real_read(descriptor)
                if not changed:
                    changed = True
                    metadata = first_path.stat()
                    os.utime(
                        first_path,
                        ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
                    )
                return payload

            with mock.patch.object(
                UPGRADE_SYSTEMD,
                "_read_bounded",
                side_effect=mutate_after_read,
            ):
                with self.assertRaisesRegex(
                    UPGRADE_SYSTEMD.UnitContractError,
                    "UPGRADE_UNIT_FILE_UNSAFE",
                ):
                    UPGRADE_SYSTEMD.snapshot_installed_units(unit_directory)

    def test_converge_documents_external_serialization_lock_requirement(self) -> None:
        documentation = " ".join(
            (UPGRADE_SYSTEMD.converge_installed_units.__doc__ or "").split()
        )
        self.assertIn("external reviewer-upgrade serialization lock", documentation)
        self.assertIn("does not acquire that lock", documentation)

    def test_writable_unit_directory_is_rejected(self) -> None:
        old = self._synthetic_bundle("old")
        with tempfile.TemporaryDirectory() as temporary:
            unit_directory = Path(temporary).resolve()
            self._install_bundle(unit_directory, old)
            unit_directory.chmod(0o770)

            with self.assertRaisesRegex(
                UPGRADE_SYSTEMD.UnitContractError,
                "UPGRADE_UNIT_DIRECTORY_UNSAFE",
            ):
                UPGRADE_SYSTEMD.snapshot_installed_units(unit_directory)


if __name__ == "__main__":
    unittest.main()
