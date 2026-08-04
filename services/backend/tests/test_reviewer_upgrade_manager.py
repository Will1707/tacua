# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the reviewer-upgrade user-systemd manager boundary."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "services" / "backend" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import reviewer_upgrade_manager as MANAGER  # noqa: E402


class FakeRunner:
    def __init__(self, responses, events=None) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[tuple[str, ...], float]] = []
        self.events = events

    def __call__(self, argv, *, timeout=30):
        self.calls.append((tuple(argv), timeout))
        if self.events is not None:
            self.events.append(f"run:{argv[2]}")
        if not self.responses:
            raise AssertionError("unexpected command")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def assert_finished(self, testcase: unittest.TestCase) -> None:
        testcase.assertEqual(self.responses, [])
        testcase.assertTrue(self.calls)
        for argv, timeout in self.calls:
            testcase.assertTrue(Path(argv[0]).is_absolute())
            testcase.assertEqual(argv[1], "--user")
            testcase.assertGreater(timeout, 0)
            testcase.assertLessEqual(
                timeout,
                MANAGER.RECONCILE_TIMEOUT_SECONDS,
            )


class FakeClock:
    def __init__(self) -> None:
        self.value = 10.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.value

    def sleep(self, duration: float) -> None:
        self.sleeps.append(duration)
        self.value += duration


def properties(**values: str) -> bytes:
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode()


class ReviewerUpgradeManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.commands = MANAGER.ManagerBinaries(
            systemctl=Path("/usr/bin/systemctl"),
            systemd_analyze=Path("/usr/bin/systemd-analyze"),
        )
        self.unit_directory = Path("/srv/tacua/user-units")
        self.enable_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.enable_temporary.cleanup)
        self.enable_links = self._enable_links(
            Path(self.enable_temporary.name).resolve(),
            "timers.target.wants",
            present=True,
        )

    def _enable_links(
        self,
        root: Path,
        *want_directories: str,
        present: bool = False,
    ) -> tuple[MANAGER.EnableLinkExpectation, ...]:
        unit_directory = root / "user-units"
        unit_directory.mkdir(mode=0o700)
        target = unit_directory / MANAGER.RECONCILE_TIMER
        target.write_bytes(b"[Timer]\nOnActiveSec=30s\n")
        target.chmod(0o600)
        result = []
        for name in want_directories:
            parent = unit_directory / name
            parent.mkdir(mode=0o700)
            link = parent / MANAGER.RECONCILE_TIMER
            if present:
                link.symlink_to(target)
            result.append(MANAGER.EnableLinkExpectation(link, target))
        return tuple(result)

    def _binding(self, state: str, command: str) -> MANAGER.ExecStartBinding:
        python = Path("/usr/bin/python3")
        script = Path(f"/srv/tacua/{state}/{command}.py")
        return MANAGER.ExecStartBinding(
            path=python,
            argv=(
                str(python),
                "-B",
                str(script),
                "reconcile" if command == "reconciler" else "prepare-lock",
                "--state-directory",
                f"/srv/tacua/state/{state}",
                "--anchor-file",
                "/run/user/1000/tacua-reconcile.anchor.json",
            ),
        )

    def _expectations(
        self,
        state: str,
    ) -> dict[str, MANAGER.LoadedUnitExpectation]:
        return {
            MANAGER.RECONCILE_SERVICE: MANAGER.LoadedUnitExpectation(
                self.unit_directory / MANAGER.RECONCILE_SERVICE,
                self._binding(state, "reconciler"),
            ),
            MANAGER.RECONCILE_LOCK_SERVICE: MANAGER.LoadedUnitExpectation(
                self.unit_directory / MANAGER.RECONCILE_LOCK_SERVICE,
                self._binding(state, "reconciler-lock"),
            ),
            MANAGER.RECONCILE_TIMER: MANAGER.LoadedUnitExpectation(
                self.unit_directory / MANAGER.RECONCILE_TIMER,
                None,
            ),
        }

    @staticmethod
    def _exec_value(binding: MANAGER.ExecStartBinding) -> str:
        return (
            f"{{ path={binding.path} ; argv[]={' '.join(binding.argv)} ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
            "pid=0 ; code=(null) ; status=0/0 }"
        )

    def _loaded_response(
        self,
        expectation: MANAGER.LoadedUnitExpectation,
    ) -> bytes:
        return properties(
            FragmentPath=str(expectation.fragment_path),
            DropInPaths="",
            LoadState="loaded",
            NeedDaemonReload="no",
            ExecStart=(
                ""
                if expectation.exec_start is None
                else self._exec_value(expectation.exec_start)
            ),
        )

    def test_timer_quiesce_is_idempotent_and_requires_absent_enable_links(
        self,
    ) -> None:
        response = properties(ActiveState="inactive", UnitFileState="disabled")
        service = properties(ActiveState="inactive")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            links = self._enable_links(
                root,
                "timers.target.wants",
                "default.target.wants",
            )
            runner = FakeRunner(
                [
                    b"",
                    b"",
                    b"",
                    response,
                    service,
                    b"",
                    b"",
                    b"",
                    response,
                    service,
                ]
            )

            MANAGER.stop_disable_verify_timer(
                self.commands,
                runner,
                enable_links=links,
            )
            MANAGER.stop_disable_verify_timer(
                self.commands,
                runner,
                enable_links=links,
            )

        runner.assert_finished(self)
        self.assertEqual(
            [call[0][2] for call in runner.calls],
            [
                "stop",
                "stop",
                "disable",
                "show",
                "show",
                "stop",
                "stop",
                "disable",
                "show",
                "show",
            ],
        )
        self.assertEqual(runner.calls[1][0][-1], MANAGER.RECONCILE_SERVICE)
        self.assertEqual(runner.calls[6][0][-1], MANAGER.RECONCILE_SERVICE)

    def test_timer_quiesce_rejects_a_remaining_enable_link(self) -> None:
        response = properties(ActiveState="inactive", UnitFileState="disabled")
        service = properties(ActiveState="inactive")
        with tempfile.TemporaryDirectory() as temporary:
            links = self._enable_links(
                Path(temporary).resolve(),
                "timers.target.wants",
                present=True,
            )
            runner = FakeRunner([b"", b"", b"", response, service])
            with self.assertRaisesRegex(
                MANAGER.ManagerError,
                "UPGRADE_MANAGER_TIMER_QUIESCE_FAILED",
            ):
                MANAGER.stop_disable_verify_timer(
                    self.commands,
                    runner,
                    enable_links=links,
                )

    def test_timer_quiesce_treats_wrong_link_evidence_as_corruption(self) -> None:
        response = properties(ActiveState="inactive", UnitFileState="disabled")
        service = properties(ActiveState="inactive")
        with tempfile.TemporaryDirectory() as temporary:
            links = self._enable_links(
                Path(temporary).resolve(),
                "timers.target.wants",
            )
            links[0].link_path.write_text("operator data", encoding="ascii")
            runner = FakeRunner([b"", b"", b"", response, service])
            with self.assertRaisesRegex(
                MANAGER.ManagerError,
                "UPGRADE_MANAGER_TIMER_LINK_INVALID",
            ):
                MANAGER.stop_disable_verify_timer(
                    self.commands,
                    runner,
                    enable_links=links,
                )

    def test_timer_quiesce_stops_an_already_active_reconcile_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            links = self._enable_links(
                Path(temporary).resolve(),
                "timers.target.wants",
            )
            service_active = True
            calls: list[tuple[str, str]] = []

            def runner(argv, *, timeout):
                nonlocal service_active
                verb = argv[2]
                unit = argv[-1]
                calls.append((verb, unit))
                if verb == "stop" and unit == MANAGER.RECONCILE_SERVICE:
                    self.assertTrue(service_active)
                    service_active = False
                    return b""
                if verb in {"stop", "disable"}:
                    return b""
                if unit == MANAGER.RECONCILE_TIMER:
                    return properties(
                        ActiveState="inactive",
                        UnitFileState="disabled",
                    )
                self.assertFalse(service_active)
                return properties(ActiveState="inactive")

            MANAGER.stop_disable_verify_timer(
                self.commands,
                runner,
                enable_links=links,
            )

            self.assertFalse(service_active)
            self.assertIn(
                ("stop", MANAGER.RECONCILE_SERVICE),
                calls,
            )

    def test_timer_quiesce_rejects_a_noncanonical_link_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real = root / "real"
            real.mkdir()
            alias = root / "timers.target.wants"
            alias.symlink_to(real, target_is_directory=True)
            target = root / MANAGER.RECONCILE_TIMER
            target.write_bytes(b"[Timer]\nOnActiveSec=30s\n")
            target.chmod(0o600)
            with self.assertRaisesRegex(
                MANAGER.ManagerError,
                "UPGRADE_MANAGER_TIMER_LINK_INVALID",
            ):
                MANAGER.stop_disable_verify_timer(
                    self.commands,
                    FakeRunner([]),
                    enable_links=(
                        MANAGER.EnableLinkExpectation(
                            alias / MANAGER.RECONCILE_TIMER,
                            target,
                        ),
                    ),
                )

    def test_syntax_verification_and_reload_use_exact_paths(self) -> None:
        paths = {
            name: self.unit_directory / name for name in MANAGER.UNIT_NAMES
        }
        runner = FakeRunner([b"", b""])

        MANAGER.verify_unit_syntax(self.commands, runner, paths)
        MANAGER.daemon_reload(self.commands, runner)

        runner.assert_finished(self)
        self.assertEqual(
            runner.calls[0][0],
            (
                "/usr/bin/systemd-analyze",
                "--user",
                "verify",
                "--",
                *(str(paths[name]) for name in MANAGER.UNIT_NAMES),
            ),
        )
        self.assertEqual(
            runner.calls[1][0],
            ("/usr/bin/systemctl", "--user", "daemon-reload"),
        )

    def test_loaded_old_and_target_states_are_each_exactly_verifiable(self) -> None:
        old = self._expectations("old")
        target = self._expectations("target")
        runner = FakeRunner(
            [self._loaded_response(old[name]) for name in MANAGER.UNIT_NAMES]
            + [self._loaded_response(target[name]) for name in MANAGER.UNIT_NAMES]
        )

        MANAGER.verify_loaded_units(self.commands, runner, old)
        MANAGER.verify_loaded_units(self.commands, runner, target)

        runner.assert_finished(self)
        self.assertTrue(all(call[0][-2] == "--" for call in runner.calls))

    def test_loaded_mixed_old_target_state_is_rejected(self) -> None:
        old = self._expectations("old")
        target = self._expectations("target")
        responses = [
            self._loaded_response(target[MANAGER.RECONCILE_SERVICE]),
            self._loaded_response(old[MANAGER.RECONCILE_LOCK_SERVICE]),
        ]
        runner = FakeRunner(responses)

        with self.assertRaisesRegex(
            MANAGER.ManagerError,
            "UPGRADE_MANAGER_LOADED_UNIT_INVALID",
        ):
            MANAGER.verify_loaded_units(self.commands, runner, target)

    def test_loaded_dropin_reload_and_exec_drift_fail_closed(self) -> None:
        target = self._expectations("target")
        cases = (
            {"DropInPaths": "/srv/operator.conf"},
            {"NeedDaemonReload": "yes"},
            {
                "ExecStart": self._exec_value(
                    self._binding("old", "reconciler")
                )
            },
        )
        for replacement in cases:
            with self.subTest(replacement=replacement):
                expected = target[MANAGER.RECONCILE_SERVICE]
                values = {
                    "FragmentPath": str(expected.fragment_path),
                    "DropInPaths": "",
                    "LoadState": "loaded",
                    "NeedDaemonReload": "no",
                    "ExecStart": self._exec_value(expected.exec_start),
                }
                values.update(replacement)
                runner = FakeRunner([properties(**values)])
                with self.assertRaisesRegex(
                    MANAGER.ManagerError,
                    "UPGRADE_MANAGER_LOADED_UNIT_INVALID",
                ):
                    MANAGER.verify_loaded_units(self.commands, runner, target)

    def test_lock_restart_occurs_only_inside_release_reacquire_callback(self) -> None:
        events: list[str] = []
        lock = {"descriptor": 17}
        runner = FakeRunner(
            [
                b"",
                properties(
                    ActiveState="active",
                    SubState="exited",
                    Result="success",
                    ExecMainStatus="0",
                ),
            ],
            events,
        )

        def handoff(action):
            old_descriptor = lock.pop("descriptor")
            self.assertEqual(old_descriptor, 17)
            events.append("release")
            try:
                action()
            finally:
                events.append("reacquire")
                lock["descriptor"] = 91
            return lock["descriptor"]

        descriptor = MANAGER.restart_reconcile_lock(
            self.commands,
            runner,
            with_released_processing_lock=handoff,
        )

        self.assertEqual(descriptor, 91)
        self.assertEqual(lock, {"descriptor": 91})
        self.assertEqual(
            events,
            ["release", "run:restart", "run:show", "reacquire"],
        )
        runner.assert_finished(self)

    def test_running_resumer_reloads_before_reconcile_lock_handoff(self) -> None:
        events: list[str] = []
        lock = {"descriptor": 17}
        runner = FakeRunner(
            [
                b"",
                b"",
                properties(
                    ActiveState="active",
                    SubState="exited",
                    Result="success",
                    ExecMainStatus="0",
                ),
            ],
            events,
        )

        MANAGER.daemon_reload(self.commands, runner)

        def handoff(action):
            lock.pop("descriptor")
            events.append("release")
            try:
                action()
            finally:
                lock["descriptor"] = 97
                events.append("reacquire")
            return lock["descriptor"]

        descriptor = MANAGER.restart_reconcile_lock(
            self.commands,
            runner,
            with_released_processing_lock=handoff,
        )

        self.assertEqual(descriptor, 97)
        self.assertEqual(lock, {"descriptor": 97})
        self.assertEqual(
            events,
            [
                "run:daemon-reload",
                "release",
                "run:restart",
                "run:show",
                "reacquire",
            ],
        )

    def test_lock_restart_failure_still_allows_callback_to_reacquire(self) -> None:
        events: list[str] = []
        lock = {"descriptor": 17}
        runner = FakeRunner([RuntimeError("private detail")], events)

        def handoff(action):
            lock.pop("descriptor")
            events.append("release")
            try:
                action()
            finally:
                events.append("reacquire")
                lock["descriptor"] = 91
            return lock["descriptor"]

        with self.assertRaisesRegex(
            MANAGER.ManagerError,
            "UPGRADE_MANAGER_LOCK_RESTART_FAILED",
        ):
            MANAGER.restart_reconcile_lock(
                self.commands,
                runner,
                with_released_processing_lock=handoff,
            )
        self.assertEqual(events, ["release", "run:restart", "reacquire"])
        self.assertEqual(lock, {"descriptor": 91})

    def test_lock_handoff_must_invoke_action_exactly_once(self) -> None:
        with self.assertRaisesRegex(
            MANAGER.ManagerError,
            "UPGRADE_MANAGER_LOCK_HANDOFF_INVALID",
        ):
            MANAGER.restart_reconcile_lock(
                self.commands,
                FakeRunner([]),
                with_released_processing_lock=lambda _action: None,
            )

    def test_lock_handoff_preserves_retryable_contention(self) -> None:
        class Contended(RuntimeError):
            code = "RECONCILE_DEFERRED"

        def handoff(_action):
            raise Contended("private lock detail")

        with self.assertRaisesRegex(
            MANAGER.ManagerError,
            "UPGRADE_MANAGER_LOCK_CONTENDED",
        ):
            MANAGER.restart_reconcile_lock(
                self.commands,
                FakeRunner([]),
                with_released_processing_lock=handoff,
            )

    def test_maintenance_reconcile_requires_service_and_state_success(self) -> None:
        events: list[str] = []
        runner = FakeRunner(
            [
                b"",
                properties(
                    ActiveState="inactive",
                    SubState="dead",
                    Result="success",
                    ExecMainStatus="0",
                ),
            ],
            events,
        )

        def verify() -> bool:
            events.append("probe:maintenance")
            return True

        def handoff(action):
            events.append("release")
            try:
                action()
            finally:
                events.append("reacquire")
            return 92

        descriptor = MANAGER.start_verify_maintenance_reconcile(
            self.commands,
            runner,
            with_released_processing_lock=handoff,
            verify_maintenance=verify,
        )

        self.assertEqual(descriptor, 92)
        self.assertEqual(
            events,
            [
                "release",
                "run:start",
                "run:show",
                "probe:maintenance",
                "reacquire",
            ],
        )
        runner.assert_finished(self)

    def test_maintenance_probe_failure_has_a_stable_error(self) -> None:
        events: list[str] = []
        lock = {"descriptor": 18}
        runner = FakeRunner(
            [
                b"",
                properties(
                    ActiveState="inactive",
                    SubState="dead",
                    Result="success",
                    ExecMainStatus="0",
                ),
            ],
            events,
        )

        def handoff(action):
            lock.pop("descriptor")
            events.append("release")
            try:
                action()
            finally:
                events.append("reacquire")
                lock["descriptor"] = 92
            return lock["descriptor"]

        with self.assertRaisesRegex(
            MANAGER.ManagerError,
            "UPGRADE_MANAGER_MAINTENANCE_NOT_PROVEN",
        ):
            MANAGER.start_verify_maintenance_reconcile(
                self.commands,
                runner,
                with_released_processing_lock=handoff,
                verify_maintenance=lambda: False,
            )
        self.assertEqual(
            events,
            ["release", "run:start", "run:show", "reacquire"],
        )
        self.assertEqual(lock, {"descriptor": 92})

    @staticmethod
    def _reconcile_state(
        invocation_id: str,
        *,
        active: str = "inactive",
        sub: str = "dead",
        result: str = "success",
        status: str = "0",
    ) -> bytes:
        return properties(
            InvocationID=invocation_id,
            ActiveState=active,
            SubState=sub,
            Result=result,
            ExecMainStatus=status,
        )

    def test_later_scheduled_reconcile_is_distinct_successful_and_rearmed(
        self,
    ) -> None:
        baseline_id = "a" * 32
        later_id = "b" * 32
        waiting = properties(
            UnitFileState="enabled",
            ActiveState="active",
            SubState="waiting",
            NextElapseUSecRealtime="",
            NextElapseUSecMonotonic="29s",
        )
        events: list[str] = []
        runner = FakeRunner(
            [
                self._reconcile_state(baseline_id),
                b"",
                b"",
                self._reconcile_state(baseline_id),
                self._reconcile_state(
                    later_id,
                    active="activating",
                    sub="start",
                ),
                self._reconcile_state(later_id),
                waiting,
            ],
            events,
        )
        clock = FakeClock()

        def handoff(action):
            events.append("release")
            try:
                action()
            finally:
                events.append("reacquire")
            return 93

        descriptor, invocation_id = MANAGER.prove_later_scheduled_reconcile(
            self.commands,
            runner,
            with_released_processing_lock=handoff,
            enable_links=self.enable_links,
            deadline_seconds=5,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
            poll_interval_seconds=0.5,
        )

        self.assertEqual((descriptor, invocation_id), (93, later_id))
        self.assertEqual(clock.sleeps, [0.5, 0.5])
        self.assertEqual(
            events,
            [
                "run:show",
                "release",
                "run:enable",
                "run:restart",
                "run:show",
                "run:show",
                "run:show",
                "run:show",
                "reacquire",
            ],
        )
        runner.assert_finished(self)

    def test_later_scheduled_reconcile_reacquires_on_invocation_failure(
        self,
    ) -> None:
        baseline_id = "a" * 32
        first_id = "b" * 32
        second_id = "c" * 32
        events: list[str] = []
        runner = FakeRunner(
            [
                self._reconcile_state(baseline_id),
                b"",
                b"",
                self._reconcile_state(
                    first_id,
                    active="activating",
                    sub="start",
                ),
                self._reconcile_state(
                    second_id,
                    active="activating",
                    sub="start",
                ),
            ],
            events,
        )
        clock = FakeClock()

        def handoff(action):
            events.append("release")
            try:
                action()
            finally:
                events.append("reacquire")
            return 94

        with self.assertRaisesRegex(
            MANAGER.ManagerError,
            "UPGRADE_MANAGER_SCHEDULED_RECONCILE_FAILED",
        ):
            MANAGER.prove_later_scheduled_reconcile(
                self.commands,
                runner,
                with_released_processing_lock=handoff,
                enable_links=self.enable_links,
                deadline_seconds=5,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
                poll_interval_seconds=0.5,
            )
        self.assertEqual(events[-1], "reacquire")

    def test_later_scheduled_reconcile_allows_failed_baseline_to_be_replaced(
        self,
    ) -> None:
        baseline_id = "a" * 32
        later_id = "b" * 32
        failed_baseline = self._reconcile_state(
            baseline_id,
            active="failed",
            sub="failed",
            result="exit-code",
            status="75",
        )
        waiting = properties(
            UnitFileState="enabled",
            ActiveState="active",
            SubState="waiting",
            NextElapseUSecRealtime="",
            NextElapseUSecMonotonic="29s",
        )
        runner = FakeRunner(
            [
                failed_baseline,
                b"",
                b"",
                failed_baseline,
                self._reconcile_state(later_id),
                waiting,
            ]
        )
        clock = FakeClock()

        descriptor, invocation_id = MANAGER.prove_later_scheduled_reconcile(
            self.commands,
            runner,
            with_released_processing_lock=lambda action: (action(), 98)[1],
            enable_links=self.enable_links,
            deadline_seconds=5,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
            poll_interval_seconds=0.5,
        )

        self.assertEqual((descriptor, invocation_id), (98, later_id))
        self.assertEqual(clock.sleeps, [0.5])
        runner.assert_finished(self)

    def test_later_scheduled_reconcile_requires_nonempty_baseline_id(self) -> None:
        runner = FakeRunner([self._reconcile_state("")])
        with self.assertRaisesRegex(
            MANAGER.ManagerError,
            "UPGRADE_MANAGER_INVOCATION_INVALID",
        ):
            MANAGER.prove_later_scheduled_reconcile(
                self.commands,
                runner,
                with_released_processing_lock=lambda _action: 95,
                enable_links=self.enable_links,
                deadline_seconds=5,
            )

    def test_later_scheduled_reconcile_has_one_nonextensible_deadline(
        self,
    ) -> None:
        baseline_id = "a" * 32
        runner = FakeRunner(
            [
                self._reconcile_state(baseline_id),
                b"",
                b"",
                self._reconcile_state(baseline_id),
                self._reconcile_state(baseline_id),
            ]
        )
        clock = FakeClock()
        lock = {"descriptor": 19}

        def handoff(action):
            lock.pop("descriptor")
            try:
                action()
            finally:
                lock["descriptor"] = 96
            return lock["descriptor"]

        with self.assertRaisesRegex(
            MANAGER.ManagerError,
            "UPGRADE_MANAGER_SCHEDULED_RECONCILE_TIMEOUT",
        ):
            MANAGER.prove_later_scheduled_reconcile(
                self.commands,
                runner,
                with_released_processing_lock=handoff,
                enable_links=self.enable_links,
                deadline_seconds=1,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
                poll_interval_seconds=0.5,
            )

        self.assertEqual(clock.sleeps, [0.5, 0.5])
        self.assertEqual(lock, {"descriptor": 96})
        self.assertLessEqual(max(timeout for _argv, timeout in runner.calls), 1)

    def test_timer_enable_restart_and_waiting_proof_can_resume_mixed_state(
        self,
    ) -> None:
        stale = properties(
            UnitFileState="enabled",
            ActiveState="active",
            SubState="elapsed",
            NextElapseUSecRealtime="",
            NextElapseUSecMonotonic="0",
        )
        ready = properties(
            UnitFileState="enabled",
            ActiveState="active",
            SubState="waiting",
            NextElapseUSecRealtime="",
            NextElapseUSecMonotonic="29s",
        )
        with tempfile.TemporaryDirectory() as temporary:
            links = self._enable_links(
                Path(temporary).resolve(),
                "timers.target.wants",
                present=True,
            )
            runner = FakeRunner([b"", b"", stale, ready])
            clock = FakeClock()

            MANAGER.enable_restart_timer(
                self.commands,
                runner,
                enable_links=links,
            )
            MANAGER.prove_timer_enabled_active_waiting(
                self.commands,
                runner,
                enable_links=links,
                deadline_seconds=3,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
                poll_interval_seconds=0.5,
            )

        runner.assert_finished(self)
        self.assertEqual(clock.sleeps, [0.5])
        self.assertEqual(
            [call[0][2] for call in runner.calls],
            ["enable", "restart", "show", "show"],
        )

    def test_timer_enable_rejects_wrong_target_without_rewriting_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            links = self._enable_links(root, "timers.target.wants")
            wrong = links[0].target_path.parent / "wrong.timer"
            wrong.write_bytes(b"wrong\n")
            wrong.chmod(0o600)
            links[0].link_path.symlink_to(wrong)
            with self.assertRaisesRegex(
                MANAGER.ManagerError,
                "UPGRADE_MANAGER_TIMER_LINK_INVALID",
            ):
                MANAGER.enable_restart_timer(
                    self.commands,
                    FakeRunner([b"", b""]),
                    enable_links=links,
                )
            self.assertEqual(links[0].link_path.resolve(), wrong)

    def test_timer_waiting_proof_has_a_bounded_monotonic_deadline(self) -> None:
        stale = properties(
            UnitFileState="disabled",
            ActiveState="inactive",
            SubState="dead",
            NextElapseUSecRealtime="",
            NextElapseUSecMonotonic="0",
        )
        runner = FakeRunner([stale, stale])
        clock = FakeClock()

        with self.assertRaisesRegex(
            MANAGER.ManagerError,
            "UPGRADE_MANAGER_TIMER_NOT_WAITING",
        ):
            MANAGER.prove_timer_enabled_active_waiting(
                self.commands,
                runner,
                enable_links=self.enable_links,
                deadline_seconds=1,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
                poll_interval_seconds=0.5,
            )

        self.assertEqual(clock.sleeps, [0.5, 0.5])
        self.assertLessEqual(max(timeout for _argv, timeout in runner.calls), 1)

    def test_runner_failures_do_not_expose_output_in_error_text(self) -> None:
        runner = FakeRunner([RuntimeError("sensitive service stderr")])
        with self.assertRaises(MANAGER.ManagerError) as caught:
            MANAGER.daemon_reload(self.commands, runner)
        self.assertEqual(
            str(caught.exception),
            "UPGRADE_MANAGER_DAEMON_RELOAD_FAILED",
        )

    def test_noncanonical_binary_and_missing_expectations_are_rejected(self) -> None:
        commands = MANAGER.ManagerBinaries(
            systemctl=Path("systemctl"),
            systemd_analyze=Path("/usr/bin/systemd-analyze"),
        )
        with self.assertRaisesRegex(
            MANAGER.ManagerError,
            "UPGRADE_MANAGER_INPUT_INVALID",
        ):
            MANAGER.daemon_reload(commands, FakeRunner([]))
        with self.assertRaisesRegex(
            MANAGER.ManagerError,
            "UPGRADE_MANAGER_EXPECTATION_INVALID",
        ):
            MANAGER.verify_loaded_units(self.commands, FakeRunner([]), {})


if __name__ == "__main__":
    unittest.main()
