# SPDX-License-Identifier: Apache-2.0
"""Focused filesystem and manager contracts for stable-unit bootstrap."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "services/backend/scripts"
SYSTEMD_TEMPLATES = ROOT / "services/backend/systemd"
sys.path.insert(0, str(SCRIPTS))

import reviewer_upgrade_bootstrap as BOOTSTRAP  # noqa: E402
import reviewer_upgrade_manager as MANAGER  # noqa: E402


def properties(**values: str) -> bytes:
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode()


class FakeRunner:
    def __init__(self, responses, enable_link: MANAGER.EnableLinkExpectation):
        self.responses = list(responses)
        self.calls: list[tuple[tuple[str, ...], float]] = []
        self.enable_link = enable_link
        self.serial_lock_was_held = False

    def __call__(self, argv, *, timeout):
        self.calls.append((tuple(argv), timeout))
        if "enable" in argv:
            self.enable_link.link_path.parent.mkdir(
                mode=0o700,
                exist_ok=True,
            )
            if not self.enable_link.link_path.exists():
                self.enable_link.link_path.symlink_to(
                    self.enable_link.target_path
                )
        if "restart" in argv and argv[-1] == BOOTSTRAP.LOCK_UNIT:
            serial_lock = self.enable_link.target_path.parent.parent / (
                "state/reviewer-upgrade.lock"
            )
            descriptor = os.open(serial_lock, os.O_RDWR)
            try:
                try:
                    fcntl.flock(
                        descriptor,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                except BlockingIOError:
                    self.serial_lock_was_held = True
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    raise AssertionError(
                        "bootstrap did not hold the serial lock"
                    )
            finally:
                os.close(descriptor)
        if not self.responses:
            raise AssertionError(f"unexpected call: {argv!r}")
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class ReviewerUpgradeBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.templates = self.root / "templates"
        self.templates.mkdir(mode=0o700)
        for name in BOOTSTRAP.TEMPLATE_NAMES.values():
            path = self.templates / name
            path.write_bytes((SYSTEMD_TEMPLATES / name).read_bytes())
            path.chmod(0o600)
        self.state_parent = self.root / "state"
        self.state_parent.mkdir(mode=0o700)
        self.unit_directory = self.root / "user-units"
        self.unit_directory.mkdir(mode=0o700)
        self.bindings = BOOTSTRAP.StableUnitBindings(
            python=Path("/usr/bin/python3"),
            upgrader=self.root / "reviewer_upgrade_transaction.py",
            state_parent=self.state_parent,
            serial_lock_file=self.state_parent / "reviewer-upgrade.lock",
            unit_directory=self.unit_directory,
            lock_file=self.root / "processing.lock",
            operation_directory=self.root / "operation",
            repository=self.root / "repository",
            config_file=self.root / "config.json",
            admin_secret_file=self.root / "admin-secret",
            project="tacua",
        )
        self.commands = MANAGER.ManagerBinaries(
            Path("/usr/bin/systemctl"),
            Path("/usr/bin/systemd-analyze"),
        )

    def _bundle(self, marker: str) -> BOOTSTRAP.StableUnitBundle:
        return BOOTSTRAP.StableUnitBundle.from_payloads(
            {
                name: f"{marker}:{name}\n".encode("ascii")
                for name in BOOTSTRAP.UNIT_NAMES
            }
        )

    def _install(
        self,
        bundle: BOOTSTRAP.StableUnitBundle,
        names=BOOTSTRAP.UNIT_NAMES,
    ) -> None:
        for name in names:
            path = self.unit_directory / name
            path.write_bytes(bundle.artifact(name).payload)
            path.chmod(0o600)

    @staticmethod
    def _exec_value(binding: MANAGER.ExecStartBinding) -> str:
        return (
            f"{{ path={binding.path} ; argv[]={' '.join(binding.argv)} ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
            "pid=0 ; code=(null) ; status=0/0 }"
        )

    def _loaded_responses(self) -> list[bytes]:
        responses = []
        for name, expected_exec in BOOTSTRAP._exec_bindings(
            self.bindings
        ).items():
            values = {
                "FragmentPath": str(self.unit_directory / name),
                "DropInPaths": "",
                "LoadState": "loaded",
                "NeedDaemonReload": "no",
            }
            if expected_exec is not None:
                values["ExecStart"] = self._exec_value(expected_exec)
            responses.append(properties(**values))
        return responses

    def _path_ready(self, **overrides: str) -> bytes:
        values = {
            "FragmentPath": str(
                self.unit_directory / BOOTSTRAP.PATH_UNIT
            ),
            "DropInPaths": "",
            "LoadState": "loaded",
            "NeedDaemonReload": "no",
            "UnitFileState": "enabled",
            "ActiveState": "active",
            "SubState": "waiting",
            "Result": "success",
        }
        values.update(overrides)
        return properties(**values)

    def _path_reset_healthy(self, **overrides: str) -> bytes:
        values = {
            "FragmentPath": str(
                self.unit_directory / BOOTSTRAP.PATH_UNIT
            ),
            "DropInPaths": "",
            "LoadState": "loaded",
            "NeedDaemonReload": "no",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
            "SubState": "dead",
            "Result": "success",
        }
        values.update(overrides)
        return properties(**values)

    def _runner(
        self,
        *extra_responses,
        idle_exec_status: str = "0",
    ) -> FakeRunner:
        link = BOOTSTRAP._timer_link(self.bindings)
        responses = [
            b"",
            b"",
            *self._loaded_responses(),
            b"",
            properties(
                ActiveState="active",
                SubState="exited",
                Result="success",
                ExecMainStatus="0",
            ),
            b"",
            b"",
            properties(
                ActiveState="inactive",
                SubState="dead",
                Result="success",
                ExecMainStatus=idle_exec_status,
            ),
            b"",
            b"",
            b"",
            self._path_ready(),
            *extra_responses,
        ]
        return FakeRunner(responses, link)

    def test_historical_resumer_exit_status_does_not_block_idle_proof(self) -> None:
        runner = self._runner(idle_exec_status="78")

        receipt = BOOTSTRAP.bootstrap_prepublication(
            self.templates,
            self.bindings,
            None,
            self.commands,
            runner,
        )

        self.assertEqual(receipt["status"], "path_armed_idle")
        self.assertEqual(runner.responses, [])

    def test_already_idle_reset_failure_accepts_strict_postcondition(self) -> None:
        runner = self._runner()
        runner.responses[8] = MANAGER.ManagerError(
            "UPGRADE_MANAGER_COMMAND_FAILED"
        )

        receipt = BOOTSTRAP.bootstrap_prepublication(
            self.templates,
            self.bindings,
            None,
            self.commands,
            runner,
        )

        self.assertEqual(receipt["status"], "path_armed_idle")
        self.assertEqual(runner.responses, [])

    def test_reset_failure_never_accepts_non_idle_postcondition(self) -> None:
        runner = self._runner()
        runner.responses[8] = MANAGER.ManagerError(
            "UPGRADE_MANAGER_COMMAND_FAILED"
        )
        runner.responses[9] = properties(
            ActiveState="failed",
            SubState="failed",
            Result="exit-code",
            ExecMainStatus="1",
        )

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_RESUMER_NOT_IDLE",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                runner,
            )

        self.assertFalse(any("enable" in call[0] for call in runner.calls))

    def test_reset_failure_never_accepts_unprovable_postcondition(self) -> None:
        runner = self._runner()
        runner.responses[8] = MANAGER.ManagerError(
            "UPGRADE_MANAGER_COMMAND_FAILED"
        )
        runner.responses[9] = MANAGER.ManagerError(
            "UPGRADE_MANAGER_COMMAND_FAILED"
        )

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_RESUMER_NOT_IDLE",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                runner,
            )

        self.assertFalse(any("enable" in call[0] for call in runner.calls))

    def test_stop_failure_remains_fatal_even_when_unit_was_idle(self) -> None:
        runner = self._runner()
        runner.responses[7] = MANAGER.ManagerError(
            "UPGRADE_MANAGER_COMMAND_FAILED"
        )

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_RESUMER_NOT_IDLE",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                runner,
            )

        self.assertFalse(any("enable" in call[0] for call in runner.calls))

    def test_non_idle_resumer_state_never_arms_path(self) -> None:
        runner = self._runner()
        runner.responses[9] = properties(
            ActiveState="inactive",
            SubState="failed",
            Result="success",
            ExecMainStatus="78",
        )

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_RESUMER_NOT_IDLE",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                runner,
            )

        self.assertFalse(any("enable" in call[0] for call in runner.calls))

    def test_path_reset_failure_accepts_only_strict_healthy_retry_states(
        self,
    ) -> None:
        states = (
            {},
            {"UnitFileState": "enabled"},
            {
                "UnitFileState": "enabled",
                "ActiveState": "active",
                "SubState": "waiting",
            },
        )
        for overrides in states:
            with self.subTest(overrides=overrides):
                runner = self._runner()
                runner.responses[10] = MANAGER.ManagerError(
                    "UPGRADE_MANAGER_COMMAND_FAILED"
                )
                runner.responses.insert(
                    11,
                    self._path_reset_healthy(**overrides),
                )

                receipt = BOOTSTRAP.bootstrap_prepublication(
                    self.templates,
                    self.bindings,
                    None,
                    self.commands,
                    runner,
                )

                self.assertEqual(receipt["status"], "path_armed_idle")
                self.assertEqual(runner.responses, [])

    def test_path_reset_failure_rejects_nonhealthy_postcondition(self) -> None:
        invalid = (
            {"FragmentPath": "/wrong/path"},
            {"DropInPaths": "/unexpected/drop-in.conf"},
            {"LoadState": "not-found"},
            {"NeedDaemonReload": "yes"},
            {"Result": "exit-code"},
            {
                "UnitFileState": "disabled",
                "ActiveState": "failed",
                "SubState": "failed",
                "Result": "exit-code",
            },
        )
        for overrides in invalid:
            with self.subTest(overrides=overrides):
                runner = self._runner()
                runner.responses[10] = MANAGER.ManagerError(
                    "UPGRADE_MANAGER_COMMAND_FAILED"
                )
                runner.responses.insert(
                    11,
                    self._path_reset_healthy(**overrides),
                )

                with self.assertRaisesRegex(
                    BOOTSTRAP.BootstrapError,
                    "UPGRADE_BOOTSTRAP_PATH_ARM_FAILED",
                ):
                    BOOTSTRAP.bootstrap_prepublication(
                        self.templates,
                        self.bindings,
                        None,
                        self.commands,
                        runner,
                    )

                self.assertFalse(
                    any("enable" in call[0] for call in runner.calls)
                )

    def test_path_enable_failure_after_reset_fallback_remains_fatal(self) -> None:
        runner = self._runner()
        runner.responses[10] = MANAGER.ManagerError(
            "UPGRADE_MANAGER_COMMAND_FAILED"
        )
        runner.responses.insert(11, self._path_reset_healthy())
        runner.responses[12] = MANAGER.ManagerError(
            "UPGRADE_MANAGER_COMMAND_FAILED"
        )

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_PATH_ARM_FAILED",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                runner,
            )

        self.assertFalse(
            any(
                call[0][-1] == BOOTSTRAP.PATH_UNIT
                and "restart" in call[0]
                for call in runner.calls
            )
        )

    def test_path_reset_failure_rejects_unprovable_postcondition(self) -> None:
        runner = self._runner()
        runner.responses[10] = MANAGER.ManagerError(
            "UPGRADE_MANAGER_COMMAND_FAILED"
        )
        runner.responses.insert(
            11,
            MANAGER.ManagerError("UPGRADE_MANAGER_COMMAND_FAILED"),
        )

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_PATH_ARM_FAILED",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                runner,
            )

        self.assertFalse(any("enable" in call[0] for call in runner.calls))

    def test_path_enable_failure_remains_fatal(self) -> None:
        runner = self._runner()
        runner.responses[11] = MANAGER.ManagerError(
            "UPGRADE_MANAGER_COMMAND_FAILED"
        )

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_PATH_ARM_FAILED",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                runner,
            )

        self.assertFalse(
            any(
                call[0][-1] == BOOTSTRAP.PATH_UNIT
                and "restart" in call[0]
                for call in runner.calls
            )
        )

    def test_render_pins_exact_placeholder_abi_and_canonical_paths(self) -> None:
        first = BOOTSTRAP.render_stable_unit_bundle(
            self.templates,
            self.bindings,
        )
        second = BOOTSTRAP.render_stable_unit_bundle(
            self.templates,
            self.bindings,
        )

        self.assertEqual(first, second)
        self.assertIn(
            f"PathExists={self.state_parent}/upgrades/active.json",
            first.artifact(BOOTSTRAP.PATH_UNIT).payload.decode(),
        )
        self.assertNotIn(
            "WantedBy=",
            first.artifact(BOOTSTRAP.RESUME_UNIT).payload.decode(),
        )
        for artifact in first.units:
            self.assertIsNone(
                BOOTSTRAP.PLACEHOLDER.search(artifact.payload.decode())
            )

        lock_template = self.templates / BOOTSTRAP.TEMPLATE_NAMES[
            BOOTSTRAP.LOCK_UNIT
        ]
        lock_template.write_bytes(
            lock_template.read_bytes().replace(b"@PROJECT@", b"tacua", 1)
        )
        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_TEMPLATE_INVALID",
        ):
            BOOTSTRAP.render_stable_unit_bundle(
                self.templates,
                self.bindings,
            )

        unsafe = BOOTSTRAP.StableUnitBindings(
            **{
                **self.bindings.__dict__,
                "repository": Path("/unsafe path/repository"),
            }
        )
        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_BINDING_INVALID",
        ):
            unsafe.replacements()

        wrong_serial = BOOTSTRAP.StableUnitBindings(
            **{
                **self.bindings.__dict__,
                "serial_lock_file": self.state_parent / "different.lock",
            }
        )
        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_BINDING_INVALID",
        ):
            wrong_serial.replacements()

    def test_classifies_exact_absent_old_and_target_states(self) -> None:
        old = self._bundle("old")
        target = self._bundle("target")
        self._install(old, names=(BOOTSTRAP.UNIT_NAMES[0],))
        self._install(target, names=(BOOTSTRAP.UNIT_NAMES[1],))

        classified = BOOTSTRAP.classify_installed_stable_units(
            self.unit_directory,
            old,
            target,
        )

        self.assertEqual(
            tuple(item.state for item in classified),
            (
                BOOTSTRAP.InstalledState.OLD,
                BOOTSTRAP.InstalledState.TARGET,
                BOOTSTRAP.InstalledState.ABSENT,
            ),
        )

    def test_convergence_resumes_absent_old_target_and_shared_link_crashes(
        self,
    ) -> None:
        old = self._bundle("old")
        target = self._bundle("target")
        self._install(old, names=(BOOTSTRAP.UNIT_NAMES[0],))
        self._install(target, names=(BOOTSTRAP.UNIT_NAMES[1],))
        name = BOOTSTRAP.UNIT_NAMES[1]
        draft = self.unit_directory / f".{name}.next-12-abcdefabcdef"
        os.link(self.unit_directory / name, draft)

        completed = BOOTSTRAP.converge_stable_units(
            self.unit_directory,
            old,
            target,
        )

        self.assertFalse(draft.exists())
        self.assertTrue(
            all(
                item.state is BOOTSTRAP.InstalledState.TARGET
                for item in completed
            )
        )

    def test_interrupted_publication_leaves_only_resumable_final_states(
        self,
    ) -> None:
        old = self._bundle("old")
        target = self._bundle("target")
        self._install(old)
        real_link = os.link
        calls = 0

        def fail_second_link(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated host interruption")
            return real_link(*args, **kwargs)

        with mock.patch.object(
            BOOTSTRAP.os,
            "link",
            side_effect=fail_second_link,
        ), self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_INSTALL_FAILED",
        ):
            BOOTSTRAP.converge_stable_units(
                self.unit_directory,
                old,
                target,
            )

        interrupted = BOOTSTRAP.classify_installed_stable_units(
            self.unit_directory,
            old,
            target,
        )
        self.assertEqual(
            tuple(item.state for item in interrupted),
            (
                BOOTSTRAP.InstalledState.TARGET,
                BOOTSTRAP.InstalledState.ABSENT,
                BOOTSTRAP.InstalledState.OLD,
            ),
        )
        completed = BOOTSTRAP.converge_stable_units(
            self.unit_directory,
            old,
            target,
        )
        self.assertTrue(
            all(
                item.state is BOOTSTRAP.InstalledState.TARGET
                for item in completed
            )
        )

    def test_unknown_symlink_and_multiple_staging_evidence_is_preserved(
        self,
    ) -> None:
        for scenario in ("unknown", "symlink", "multiple"):
            with self.subTest(scenario=scenario):
                old = self._bundle("old")
                target = self._bundle("target")
                self._install(old)
                name = BOOTSTRAP.UNIT_NAMES[0]
                final = self.unit_directory / name
                evidence: list[Path] = []
                if scenario == "unknown":
                    final.write_bytes(b"operator-owned\n")
                    final.chmod(0o600)
                    evidence.append(final)
                elif scenario == "symlink":
                    final.unlink()
                    final.symlink_to(self.unit_directory / BOOTSTRAP.UNIT_NAMES[1])
                    evidence.append(final)
                else:
                    for suffix in (
                        "1-abcdefabcdef",
                        "2-abcdefabcdef",
                    ):
                        draft = (
                            self.unit_directory
                            / f".{name}.next-{suffix}"
                        )
                        draft.write_bytes(target.artifact(name).payload)
                        draft.chmod(0o600)
                        evidence.append(draft)

                with self.assertRaises(BOOTSTRAP.BootstrapError):
                    BOOTSTRAP.converge_stable_units(
                        self.unit_directory,
                        old,
                        target,
                    )
                self.assertTrue(
                    all(path.is_symlink() or path.exists() for path in evidence)
                )
                for path in tuple(self.unit_directory.iterdir()):
                    if path.is_symlink() or path.is_file():
                        path.unlink()

    def test_bootstrap_proves_lock_then_arms_idle_path_before_publication(
        self,
    ) -> None:
        runner = self._runner()

        receipt = BOOTSTRAP.bootstrap_prepublication(
            self.templates,
            self.bindings,
            None,
            self.commands,
            runner,
        )

        self.assertEqual(runner.responses, [])
        self.assertTrue(runner.serial_lock_was_held)
        self.assertEqual(receipt["status"], "path_armed_idle")
        self.assertEqual(receipt["path_unit"], BOOTSTRAP.PATH_UNIT)
        json.dumps(receipt, allow_nan=False, sort_keys=True)
        verbs = [
            "restart" if call[0][2] == "--no-block" else call[0][2]
            for call in runner.calls
        ]
        lock_restart = next(
            index
            for index, call in enumerate(runner.calls)
            if call[0][-1] == BOOTSTRAP.LOCK_UNIT
            and call[0][2] == "restart"
        )
        enable = verbs.index("enable")
        reset_failed = next(
            index
            for index, call in enumerate(runner.calls)
            if call[0][-1] == BOOTSTRAP.PATH_UNIT
            and call[0][2] == "reset-failed"
        )
        path_restart = max(
            index
            for index, call in enumerate(runner.calls)
            if call[0][-1] == BOOTSTRAP.PATH_UNIT
            and "restart" in call[0]
        )
        self.assertLess(lock_restart, reset_failed)
        self.assertLess(reset_failed, enable)
        self.assertLess(enable, path_restart)
        self.assertFalse(
            any(
                call[0][-1] == BOOTSTRAP.RESUME_UNIT
                and call[0][2] in {"enable", "restart", "start"}
                for call in runner.calls
            )
        )
        resume_stop = next(
            index
            for index, call in enumerate(runner.calls)
            if call[0][-1] == BOOTSTRAP.RESUME_UNIT
            and call[0][2] == "stop"
        )
        self.assertLess(resume_stop, reset_failed)
        self.assertFalse(
            (self.state_parent / "upgrades/active.json").exists()
        )

    def test_persisted_target_bundle_prevents_template_rerender_race(self) -> None:
        target = BOOTSTRAP.render_stable_unit_bundle(
            self.templates,
            self.bindings,
        )
        resume_template = self.templates / BOOTSTRAP.TEMPLATE_NAMES[
            BOOTSTRAP.RESUME_UNIT
        ]
        resume_template.write_bytes(b"mutated after pending authority\n")
        resume_template.chmod(0o600)
        runner = self._runner()

        receipt = BOOTSTRAP.bootstrap_prepublication(
            self.templates,
            self.bindings,
            None,
            self.commands,
            runner,
            target_bundle=target,
        )

        self.assertEqual(receipt["target_unit_digests"], target.digests())
        for artifact in target.units:
            self.assertEqual(
                (self.unit_directory / artifact.name).read_bytes(),
                artifact.payload,
            )

    def test_active_selector_blocks_bootstrap_before_unit_or_manager_mutation(
        self,
    ) -> None:
        upgrades = self.state_parent / "upgrades"
        upgrades.mkdir(mode=0o700)
        active = upgrades / "active.json"
        active.write_text("{}", encoding="ascii")
        active.chmod(0o600)
        runner = self._runner()

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_ACTIVE_PRESENT",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                runner,
            )

        self.assertEqual(runner.calls, [])
        self.assertEqual(list(self.unit_directory.iterdir()), [])

    def test_loaded_exec_or_lock_failure_never_arms_path(self) -> None:
        cases = ("exec", "lock")
        for scenario in cases:
            with self.subTest(scenario=scenario):
                responses = [b"", b"", *self._loaded_responses()]
                if scenario == "exec":
                    expected = BOOTSTRAP._exec_bindings(self.bindings)[
                        BOOTSTRAP.LOCK_UNIT
                    ]
                    self.assertIsNotNone(expected)
                    responses[2] = properties(
                        FragmentPath=str(
                            self.unit_directory / BOOTSTRAP.LOCK_UNIT
                        ),
                        DropInPaths="",
                        LoadState="loaded",
                        NeedDaemonReload="no",
                        ExecStart="{ path=/wrong ; argv[]=/wrong }",
                    )
                else:
                    responses.extend(
                        [
                            b"",
                            properties(
                                ActiveState="failed",
                                SubState="failed",
                                Result="exit-code",
                                ExecMainStatus="78",
                            ),
                        ]
                    )
                runner = FakeRunner(
                    responses,
                    BOOTSTRAP._timer_link(self.bindings),
                )

                with self.assertRaises(BOOTSTRAP.BootstrapError):
                    BOOTSTRAP.bootstrap_prepublication(
                        self.templates,
                        self.bindings,
                        None,
                        self.commands,
                        runner,
                    )

                self.assertFalse(
                    any("enable" in call[0] for call in runner.calls)
                )
                for path in tuple(self.unit_directory.iterdir()):
                    if path.is_file():
                        path.unlink()

    def test_lock_success_without_exact_serial_inode_never_arms_path(self) -> None:
        runner = self._runner()

        def discard_prepared_serial(argv, *, timeout):
            result = runner(argv, timeout=timeout)
            if "restart" in argv and argv[-1] == BOOTSTRAP.LOCK_UNIT:
                self.bindings.serial_lock_file.unlink()
            return result

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_SERIAL_LOCK_INVALID",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                discard_prepared_serial,
            )

        self.assertFalse(any("enable" in call[0] for call in runner.calls))

    def test_serial_lock_contention_precedes_unit_and_manager_mutation(
        self,
    ) -> None:
        serial_lock = self.bindings.serial_lock_file
        serial_lock.write_bytes(b"")
        serial_lock.chmod(0o600)
        descriptor = os.open(serial_lock, os.O_RDWR)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(fcntl.flock, descriptor, fcntl.LOCK_UN)
        runner = self._runner()

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_CONTENDED",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                runner,
            )

        self.assertEqual(runner.calls, [])
        self.assertEqual(list(self.unit_directory.iterdir()), [])

    def test_serial_lock_rebinding_is_fatal_and_never_arms_path(self) -> None:
        runner = self._runner()

        def replace_serial_inode(argv, *, timeout):
            result = runner(argv, timeout=timeout)
            if "restart" in argv and argv[-1] == BOOTSTRAP.LOCK_UNIT:
                self.bindings.serial_lock_file.unlink()
                self.bindings.serial_lock_file.write_bytes(b"")
                self.bindings.serial_lock_file.chmod(0o600)
            return result

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_SERIAL_LOCK_INVALID",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                replace_serial_inode,
            )

        self.assertTrue(self.bindings.serial_lock_file.exists())
        self.assertFalse(any("enable" in call[0] for call in runner.calls))

    def test_wrong_enable_link_target_is_distinct_fatal_corruption(self) -> None:
        runner = self._runner()
        expected = BOOTSTRAP._timer_link(self.bindings)
        wrong = self.unit_directory / "wrong.path"
        wrong.write_bytes(b"wrong\n")
        wrong.chmod(0o600)

        def install_wrong(argv, *, timeout):
            if "enable" in argv:
                expected.link_path.parent.mkdir(mode=0o700, exist_ok=True)
                expected.link_path.symlink_to(wrong)
            return runner(argv, timeout=timeout)

        with self.assertRaisesRegex(
            BOOTSTRAP.BootstrapError,
            "UPGRADE_BOOTSTRAP_LINK_INVALID",
        ):
            BOOTSTRAP.bootstrap_prepublication(
                self.templates,
                self.bindings,
                None,
                self.commands,
                install_wrong,
            )

        self.assertEqual(expected.link_path.resolve(), wrong)


if __name__ == "__main__":
    unittest.main()
