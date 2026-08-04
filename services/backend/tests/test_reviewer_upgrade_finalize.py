# SPDX-License-Identifier: Apache-2.0
"""Focused orchestration and filesystem tests for post-seal finalization."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "services" / "backend" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import reviewer_upgrade_finalize as FINALIZE  # noqa: E402
import reviewer_upgrade_manager as MANAGER  # noqa: E402
import reviewer_upgrade_systemd as SYSTEMD  # noqa: E402
from services.backend.tests import test_compose_reconciler as FIXTURES  # noqa: E402


def properties(**values: str) -> bytes:
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode()


class FakeRunner:
    def __init__(self, responses) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def __call__(self, argv, *, timeout=30):
        self.calls.append((tuple(argv), timeout))
        if not self.responses:
            raise AssertionError("unexpected command")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class ReviewerUpgradeFinalizeTests(unittest.TestCase):
    def _bundle(self, marker: str) -> SYSTEMD.UnitBundle:
        return SYSTEMD.UnitBundle.from_payloads(
            {
                name: f"{marker}:{name}\n".encode("ascii")
                for name in SYSTEMD.UNIT_NAMES
            }
        )

    def _install(self, directory: Path, bundle: SYSTEMD.UnitBundle) -> None:
        for artifact in bundle.units:
            path = directory / artifact.name
            path.write_bytes(artifact.payload)
            path.chmod(0o600)

    def _loaded_expectations(
        self,
        unit_directory: Path,
    ) -> dict[str, MANAGER.LoadedUnitExpectation]:
        python = Path("/usr/bin/python3")
        return {
            MANAGER.RECONCILE_SERVICE: MANAGER.LoadedUnitExpectation(
                unit_directory / MANAGER.RECONCILE_SERVICE,
                MANAGER.ExecStartBinding(
                    python,
                    (
                        str(python),
                        "-B",
                        "/srv/tacua/reconcile.py",
                        "reconcile",
                        "--state-directory",
                        "/srv/tacua/state/target",
                    ),
                ),
            ),
            MANAGER.RECONCILE_LOCK_SERVICE: MANAGER.LoadedUnitExpectation(
                unit_directory / MANAGER.RECONCILE_LOCK_SERVICE,
                MANAGER.ExecStartBinding(
                    python,
                    (
                        str(python),
                        "-B",
                        "/srv/tacua/reconcile.py",
                        "prepare-lock",
                        "--state-directory",
                        "/srv/tacua/state/target",
                    ),
                ),
            ),
            MANAGER.RECONCILE_TIMER: MANAGER.LoadedUnitExpectation(
                unit_directory / MANAGER.RECONCILE_TIMER,
                None,
            ),
        }

    def _fixture(
        self,
        root: Path,
        *,
        desired_state: str = "maintenance",
    ) -> tuple[
        FINALIZE.FinalizeBindings,
        dict[str, int],
        Path,
    ]:
        helper = FIXTURES.ComposeReconcilerTests()
        state = helper._fixture(root, desired_state=desired_state)
        _manifest, inhibitor, operation = helper._upgrade_inhibitor(state)
        metadata = operation.lstat()
        gate = FINALIZE.ProcessingGateBinding(
            operation_directory=operation,
            directory_identity=FINALIZE.DirectoryIdentity(
                device=metadata.st_dev,
                gid=metadata.st_gid,
                inode=metadata.st_ino,
                mode=metadata.st_mode & 0o7777,
                uid=metadata.st_uid,
            ),
            inhibitor=FINALIZE.UpgradeInhibitor(
                contract_version=inhibitor["contract_version"],
                inhibitor_digest=inhibitor["inhibitor_digest"],
                plan_digest=inhibitor["plan_digest"],
                project=inhibitor["project"],
            ),
        )
        unit_directory = root / "user-units"
        unit_directory.mkdir(mode=0o700)
        old = self._bundle("old")
        target = self._bundle("target")
        self._install(unit_directory, old)
        holder = {"descriptor": 77}

        def current_descriptor() -> int:
            return holder["descriptor"]

        def handoff(action) -> int:
            holder.pop("descriptor")
            try:
                action()
            finally:
                holder["descriptor"] = holder.get("next", 77) + 1
                holder["next"] = holder["descriptor"]
            return holder["descriptor"]

        bindings = FINALIZE.FinalizeBindings(
            target_state_directory=state,
            unit_directory=unit_directory,
            old_units=old,
            target_units=target,
            manager_binaries=MANAGER.ManagerBinaries(
                Path("/usr/bin/systemctl"),
                Path("/usr/bin/systemd-analyze"),
            ),
            loaded_target=self._loaded_expectations(unit_directory),
            timer_enable_link_paths=(
                unit_directory
                / "timers.target.wants"
                / MANAGER.RECONCILE_TIMER,
            ),
            processing_gate=gate,
            processing_lock=FINALIZE.CallerOwnedProcessingLock(
                current_descriptor=current_descriptor,
                handoff=handoff,
            ),
        )
        return bindings, holder, operation

    def _assert_receipt(self, receipt: dict, operation: str) -> None:
        self.assertEqual(receipt["contract_version"], FINALIZE.RECEIPT_CONTRACT)
        self.assertEqual(receipt["operation"], operation)
        self.assertEqual(
            receipt["receipt_digest"],
            FINALIZE.reconciler._document_digest(
                receipt,
                "receipt_digest",
            ),
        )
        self.assertEqual(
            FINALIZE.reconciler._parse_json(
                FINALIZE.reconciler._canonical(receipt),
                "TEST_RECEIPT_INVALID",
            ),
            receipt,
        )

    def test_promote_converges_mixed_units_and_uses_two_lock_handoffs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bindings, holder, operation = self._fixture(root)
            mixed = bindings.unit_directory / SYSTEMD.UNIT_NAMES[0]
            mixed.write_bytes(
                bindings.target_units.artifact(SYSTEMD.UNIT_NAMES[0]).payload
            )
            events: list[str] = []

            def restart(*_args, with_released_processing_lock, **_kwargs):
                events.append("restart-lock")
                return with_released_processing_lock(lambda: None)

            def reconcile(
                *_args,
                with_released_processing_lock,
                verify_maintenance,
                **_kwargs,
            ):
                events.append("maintenance-reconcile")

                def action() -> None:
                    self.assertTrue(verify_maintenance())

                return with_released_processing_lock(action)

            with mock.patch.object(
                FINALIZE.reconciler,
                "_adopt_host_lock",
                side_effect=lambda _project, descriptor: descriptor,
            ), mock.patch.object(
                FINALIZE.manager,
                "stop_disable_verify_timer",
                side_effect=lambda *_a, **_k: events.append("timer-stopped"),
            ), mock.patch.object(
                FINALIZE.manager,
                "verify_unit_syntax",
                side_effect=lambda *_a, **_k: events.append("syntax"),
            ), mock.patch.object(
                FINALIZE.manager,
                "daemon_reload",
                side_effect=lambda *_a, **_k: events.append("reload"),
            ), mock.patch.object(
                FINALIZE.manager,
                "verify_loaded_units",
                side_effect=lambda *_a, **_k: events.append("loaded"),
            ), mock.patch.object(
                FINALIZE.manager,
                "restart_reconcile_lock",
                side_effect=restart,
            ), mock.patch.object(
                FINALIZE.manager,
                "start_verify_maintenance_reconcile",
                side_effect=reconcile,
            ), mock.patch.object(
                FINALIZE.manager,
                "enable_restart_timer",
                side_effect=lambda *_a, **_k: events.append("timer-armed"),
            ), mock.patch.object(
                FINALIZE.manager,
                "prove_timer_enabled_active_waiting",
                side_effect=lambda *_a, **_k: events.append("timer-waiting"),
            ):
                descriptor, receipt = FINALIZE.promote_target_maintenance(
                    bindings,
                    mock.Mock(),
                )

            self.assertEqual(descriptor, 79)
            self.assertEqual(holder["descriptor"], 79)
            self.assertTrue(operation.is_dir())
            for artifact in bindings.target_units.units:
                self.assertEqual(
                    (bindings.unit_directory / artifact.name).read_bytes(),
                    artifact.payload,
                )
            self.assertEqual(
                events,
                [
                    "timer-stopped",
                    "syntax",
                    "reload",
                    "loaded",
                    "restart-lock",
                    "maintenance-reconcile",
                    "timer-armed",
                    "timer-waiting",
                ],
            )
            self._assert_receipt(receipt, "promote_target_maintenance")

    def test_promote_refuses_unknown_unit_content_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bindings, _holder, _operation = self._fixture(
                Path(temporary).resolve()
            )
            unknown = bindings.unit_directory / SYSTEMD.UNIT_NAMES[1]
            unknown.write_bytes(b"operator-owned-change\n")
            with mock.patch.object(
                FINALIZE.reconciler,
                "_adopt_host_lock",
                side_effect=lambda _project, descriptor: descriptor,
            ), mock.patch.object(
                FINALIZE.manager,
                "stop_disable_verify_timer",
            ), self.assertRaisesRegex(
                FINALIZE.FinalizeError,
                "UPGRADE_FINALIZE_UNIT_UNKNOWN",
            ):
                FINALIZE.promote_target_maintenance(bindings, mock.Mock())
            self.assertEqual(unknown.read_bytes(), b"operator-owned-change\n")

    def test_promote_preserves_distinct_timer_link_corruption_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bindings, _holder, _operation = self._fixture(
                Path(temporary).resolve()
            )
            with mock.patch.object(
                FINALIZE.reconciler,
                "_adopt_host_lock",
                side_effect=lambda _project, descriptor: descriptor,
            ), mock.patch.object(
                FINALIZE.manager,
                "stop_disable_verify_timer",
                side_effect=MANAGER.ManagerError(
                    "UPGRADE_MANAGER_TIMER_LINK_INVALID"
                ),
            ), self.assertRaisesRegex(
                FINALIZE.FinalizeError,
                "UPGRADE_FINALIZE_TIMER_LINK_INVALID",
            ):
                FINALIZE.promote_target_maintenance(bindings, mock.Mock())

    def test_promote_preserves_fatal_lock_and_unit_manager_codes(self) -> None:
        cases = (
            (
                "UPGRADE_MANAGER_LOCK_HANDOFF_INVALID",
                "UPGRADE_FINALIZE_LOCK_INVALID",
            ),
            (
                "UPGRADE_MANAGER_LOADED_UNIT_INVALID",
                "UPGRADE_FINALIZE_UNIT_INVALID",
            ),
        )
        for manager_code, finalize_code in cases:
            with self.subTest(manager_code=manager_code):
                with tempfile.TemporaryDirectory() as temporary:
                    bindings, _holder, _operation = self._fixture(
                        Path(temporary).resolve()
                    )
                    with mock.patch.object(
                        FINALIZE.reconciler,
                        "_adopt_host_lock",
                        side_effect=lambda _project, descriptor: descriptor,
                    ), mock.patch.object(
                        FINALIZE.manager,
                        "stop_disable_verify_timer",
                        side_effect=MANAGER.ManagerError(manager_code),
                    ), self.assertRaisesRegex(
                        FINALIZE.FinalizeError,
                        finalize_code,
                    ):
                        FINALIZE.promote_target_maintenance(
                            bindings,
                            mock.Mock(),
                        )

    def test_activation_is_resumable_and_keeps_exact_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bindings, holder, operation = self._fixture(Path(temporary).resolve())
            marker = operation / FINALIZE.reconciler.UPGRADE_INHIBITOR_FILE
            with mock.patch.object(
                FINALIZE.reconciler,
                "_adopt_host_lock",
                side_effect=lambda _project, descriptor: descriptor,
            ), mock.patch.object(
                FINALIZE.reconciler,
                "_recover_locked",
                return_value="healthy",
            ) as recover:
                first_descriptor, first = FINALIZE.activate_target(
                    bindings,
                    mock.Mock(),
                )
                second_descriptor, second = FINALIZE.activate_target(
                    bindings,
                    mock.Mock(),
                )

            self.assertEqual((first_descriptor, second_descriptor), (77, 77))
            self.assertEqual(holder["descriptor"], 77)
            self.assertTrue(marker.is_file())
            desired, _manifest, _compose = FINALIZE.reconciler._load_bound_state(
                bindings.target_state_directory
            )
            self.assertEqual(desired["desired"], "running")
            self.assertEqual(recover.call_count, 2)
            self._assert_receipt(first, "activate_target")
            self._assert_receipt(second, "activate_target")

    def test_gate_removal_accepts_marker_empty_and_absent_crash_states(self) -> None:
        scenarios = ("marker", "empty", "absent")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as temporary:
                    bindings, holder, operation = self._fixture(
                        Path(temporary).resolve(),
                        desired_state="running",
                    )
                    marker = (
                        operation
                        / FINALIZE.reconciler.UPGRADE_INHIBITOR_FILE
                    )
                    if scenario in {"empty", "absent"}:
                        marker.unlink()
                    if scenario == "absent":
                        operation.rmdir()
                    with mock.patch.object(
                        FINALIZE.reconciler,
                        "_adopt_host_lock",
                        side_effect=lambda _project, descriptor: descriptor,
                    ):
                        descriptor, receipt = (
                            FINALIZE.remove_processing_gate(bindings)
                        )

                    self.assertEqual(descriptor, 77)
                    self.assertEqual(holder["descriptor"], 77)
                    self.assertFalse(operation.exists())
                    self._assert_receipt(receipt, "remove_processing_gate")

    def test_already_absent_gate_fsyncs_pinned_parent_before_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bindings, _holder, operation = self._fixture(
                Path(temporary).resolve(),
                desired_state="running",
            )
            marker = operation / FINALIZE.reconciler.UPGRADE_INHIBITOR_FILE
            marker.unlink()
            operation.rmdir()
            calls: list[int] = []
            real_fsync = os.fsync

            def tracked_fsync(descriptor: int) -> None:
                calls.append(descriptor)
                real_fsync(descriptor)

            with mock.patch.object(
                FINALIZE.reconciler,
                "_adopt_host_lock",
                side_effect=lambda _project, descriptor: descriptor,
            ), mock.patch.object(
                FINALIZE.os,
                "fsync",
                side_effect=tracked_fsync,
            ):
                _descriptor, receipt = FINALIZE.remove_processing_gate(bindings)

            self.assertGreaterEqual(len(calls), 1)
            self.assertFalse(operation.exists())
            self._assert_receipt(receipt, "remove_processing_gate")

    def test_gate_removal_never_mutates_unknown_entries_or_rebound_inode(
        self,
    ) -> None:
        for scenario in ("extra", "rebound"):
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as temporary:
                    bindings, _holder, operation = self._fixture(
                        Path(temporary).resolve(),
                        desired_state="running",
                    )
                    if scenario == "extra":
                        unknown = operation / "operator-data"
                        unknown.write_text("preserve", encoding="ascii")
                    else:
                        marker = (
                            operation
                            / FINALIZE.reconciler.UPGRADE_INHIBITOR_FILE
                        )
                        marker.unlink()
                        operation.rmdir()
                        operation.mkdir(mode=0o700)
                        unknown = operation / "replacement-data"
                        unknown.write_text("preserve", encoding="ascii")
                    with mock.patch.object(
                        FINALIZE.reconciler,
                        "_adopt_host_lock",
                        side_effect=lambda _project, descriptor: descriptor,
                    ), self.assertRaisesRegex(
                        FINALIZE.FinalizeError,
                        "UPGRADE_FINALIZE_GATE_INVALID",
                    ):
                        FINALIZE.remove_processing_gate(bindings)
                    self.assertEqual(
                        unknown.read_text(encoding="ascii"),
                        "preserve",
                    )

    def test_gate_removal_rejects_marker_replacement_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bindings, _holder, operation = self._fixture(
                Path(temporary).resolve(),
                desired_state="running",
            )
            marker = operation / FINALIZE.reconciler.UPGRADE_INHIBITOR_FILE
            replacement = operation.parent / ".replacement-marker"
            replacement.write_bytes(marker.read_bytes())
            replacement.chmod(0o600)
            marker_read_size = marker.stat().st_size + 1
            original_read = FINALIZE.os.read
            replaced = False

            def replace_during_read(descriptor: int, length: int) -> bytes:
                nonlocal replaced
                payload = original_read(descriptor, min(length, 8))
                if not replaced and length == marker_read_size:
                    os.replace(replacement, marker)
                    replaced = True
                return payload

            with mock.patch.object(
                FINALIZE.reconciler,
                "_adopt_host_lock",
                side_effect=lambda _project, descriptor: descriptor,
            ), mock.patch.object(
                FINALIZE.os,
                "read",
                side_effect=replace_during_read,
            ), self.assertRaisesRegex(
                FINALIZE.FinalizeError,
                "UPGRADE_FINALIZE_GATE_INVALID",
            ):
                FINALIZE.remove_processing_gate(bindings)

            self.assertTrue(replaced)
            self.assertTrue(operation.is_dir())
            self.assertTrue(marker.is_file())

    def test_gate_removal_rejects_unsettled_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bindings, _holder, operation = self._fixture(
                Path(temporary).resolve()
            )
            with self.assertRaisesRegex(
                FINALIZE.FinalizeError,
                "UPGRADE_FINALIZE_STATE_INVALID",
            ):
                FINALIZE.remove_processing_gate(bindings)
            self.assertTrue(
                (operation / FINALIZE.reconciler.UPGRADE_INHIBITOR_FILE).is_file()
            )

    def test_scheduled_proof_requires_absent_gate_and_updates_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bindings, holder, operation = self._fixture(
                Path(temporary).resolve(),
                desired_state="running",
            )
            marker = operation / FINALIZE.reconciler.UPGRADE_INHIBITOR_FILE
            marker.unlink()
            operation.rmdir()
            enable_link = bindings.timer_enable_link_paths[0]
            enable_link.parent.mkdir(mode=0o700)
            enable_link.symlink_to(
                bindings.unit_directory / MANAGER.RECONCILE_TIMER
            )
            baseline_id = "a" * 32
            later_id = "b" * 32
            runner = FakeRunner(
                [
                    properties(
                        InvocationID=baseline_id,
                        ActiveState="inactive",
                        SubState="dead",
                        Result="success",
                        ExecMainStatus="0",
                    ),
                    b"",
                    b"",
                    properties(
                        InvocationID=later_id,
                        ActiveState="inactive",
                        SubState="dead",
                        Result="success",
                        ExecMainStatus="0",
                    ),
                    properties(
                        UnitFileState="enabled",
                        ActiveState="active",
                        SubState="waiting",
                        NextElapseUSecRealtime="",
                        NextElapseUSecMonotonic="29s",
                    ),
                ]
            )

            with mock.patch.object(
                FINALIZE.reconciler,
                "_adopt_host_lock",
                side_effect=lambda _project, descriptor: descriptor,
            ):
                descriptor, receipt = (
                    FINALIZE.prove_later_scheduled_reconcile(
                        bindings,
                        runner,
                        deadline_seconds=60,
                    )
                )

            self.assertEqual(descriptor, 78)
            self.assertEqual(holder["descriptor"], 78)
            self.assertEqual(receipt["details"]["invocation_id"], later_id)
            self.assertEqual(runner.responses, [])
            self._assert_receipt(
                receipt,
                "prove_later_scheduled_reconcile",
            )

    def test_scheduled_proof_refuses_live_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bindings, _holder, _operation = self._fixture(
                Path(temporary).resolve(),
                desired_state="running",
            )
            with self.assertRaisesRegex(
                FINALIZE.FinalizeError,
                "UPGRADE_FINALIZE_GATE_INVALID",
            ):
                FINALIZE.prove_later_scheduled_reconcile(
                    bindings,
                    mock.Mock(),
                    deadline_seconds=60,
                )

    def test_lock_contention_is_retryable_but_corruption_is_not(self) -> None:
        cases = (
            (
                "RECONCILE_DEFERRED",
                "UPGRADE_FINALIZE_LOCK_CONTENDED",
            ),
            (
                "RECONCILE_LOCK_INVALID",
                "UPGRADE_FINALIZE_LOCK_INVALID",
            ),
        )
        for reconcile_code, finalize_code in cases:
            with self.subTest(code=reconcile_code):
                with tempfile.TemporaryDirectory() as temporary:
                    bindings, _holder, _operation = self._fixture(
                        Path(temporary).resolve(),
                        desired_state="running",
                    )
                    with mock.patch.object(
                        FINALIZE.reconciler,
                        "_adopt_host_lock",
                        side_effect=FINALIZE.reconciler.ReconcileError(
                            reconcile_code
                        ),
                    ), self.assertRaisesRegex(
                        FINALIZE.FinalizeError,
                        finalize_code,
                    ):
                        FINALIZE._current_descriptor(bindings)


if __name__ == "__main__":
    unittest.main()
