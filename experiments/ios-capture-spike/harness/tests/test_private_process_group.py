# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import pathlib
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


SUPERVISOR = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "private_process_group.py"
)
RUNNER = SUPERVISOR.with_name("run_private_physical_ui_test.sh")

GROUP_FIXTURE = r"""
import os
import pathlib
import signal
import subprocess
import sys

grandchild = subprocess.Popen(
    [sys.executable, "-B", "-c", "import signal; signal.pause()"]
)

def stop(signum, _frame):
    try:
        grandchild.wait(timeout=5)
    except subprocess.TimeoutExpired:
        grandchild.kill()
        grandchild.wait(timeout=5)
    raise SystemExit(128 + signum)

for forwarded in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
    signal.signal(forwarded, stop)

pid_file = pathlib.Path(sys.argv[1])
temporary = pid_file.with_suffix(".pending")
temporary.write_text(
    f"{os.getpid()}\n{grandchild.pid}\n{os.getpgrp()}\n{os.getpgid(grandchild.pid)}\n",
    encoding="ascii",
)
os.replace(temporary, pid_file)
signal.pause()
"""

ORPHAN_FIXTURE = r"""
import os
import pathlib
import signal
import subprocess
import sys

descendant = subprocess.Popen(
    [
        sys.executable,
        "-B",
        "-c",
        "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.pause()",
    ]
)

pid_file = pathlib.Path(sys.argv[1])
temporary = pid_file.with_suffix(".pending")
temporary.write_text(
    f"{os.getpid()}\n{descendant.pid}\n{os.getpgrp()}\n{os.getpgid(descendant.pid)}\n",
    encoding="ascii",
)
os.replace(temporary, pid_file)

if sys.argv[2] == "normal":
    os._exit(0)

signal.signal(signal.SIGTERM, lambda _signum, _frame: os._exit(143))
signal.pause()
"""

FAKE_XCODEBUILD = r"""#!/usr/bin/env python3
import os
import pathlib
import signal
import subprocess
import sys
import time

arguments = sys.argv[1:]
result = pathlib.Path(arguments[arguments.index("-resultBundlePath") + 1])
result.mkdir(mode=0o700)
(result / "synthetic-payload").write_bytes(b"safe synthetic result")

ready = pathlib.Path(os.environ["TACUA_FAKE_RUNNER_READY"])
descendant_ready = ready.with_suffix(".descendant-ready")
descendant = subprocess.Popen(
    [
        sys.executable,
        "-B",
        "-c",
        (
            "import pathlib, signal, sys; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "pathlib.Path(sys.argv[1]).write_text('ready', encoding='ascii'); "
            "signal.pause()"
        ),
        str(descendant_ready),
    ]
)
deadline = time.monotonic() + 5
while not descendant_ready.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
if not descendant_ready.exists():
    raise SystemExit(90)
ready_pending = ready.with_suffix(".pending")
ready_pending.write_text(
    f"{os.getpid()}\n{descendant.pid}\n{os.getpgrp()}\n",
    encoding="ascii",
)
os.replace(ready_pending, ready)
signal.signal(signal.SIGTERM, lambda _signum, _frame: os._exit(143))
signal.pause()
"""


def process_exists(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    return True


def process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    return True


class PrivateProcessGroupTests(unittest.TestCase):
    def test_runner_wires_supervision_device_scan_and_no_raw_log(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('python3 -B "$PROCESS_SUPERVISOR" --', source)
        self.assertIn("supervisor_pid=$!", source)
        self.assertIn("trap 'forward_signal INT 130' INT", source)
        self.assertIn("trap 'forward_signal HUP 129' HUP", source)
        self.assertIn("trap 'forward_signal TERM 143' TERM", source)
        self.assertIn(
            '--forbidden-values-file "$device_id_file"',
            source,
        )
        self.assertIn(">/dev/null 2>&1 &", source)
        self.assertNotIn("pending_log", source)
        self.assertNotIn("xcodebuild.log", source)

    def test_repeated_runner_signal_cannot_interrupt_unsealed_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tacua-fake-runner-") as directory:
            root = pathlib.Path(os.path.realpath(directory))
            repository = root / "repo"
            scripts = (
                repository
                / "experiments"
                / "ios-capture-spike"
                / "harness"
                / "scripts"
            )
            scripts.mkdir(parents=True)
            shutil.copy2(SUPERVISOR, scripts / SUPERVISOR.name)
            scanner = SUPERVISOR.with_name("xcresult_safety.py")
            shutil.copy2(scanner, scripts / scanner.name)

            fake_xcodebuild = root / "fake_xcodebuild.py"
            fake_xcodebuild.write_text(FAKE_XCODEBUILD, encoding="utf-8")
            fake_xcodebuild.chmod(0o755)
            runner = scripts / RUNNER.name
            runner_source = RUNNER.read_text(encoding="utf-8")
            self.assertEqual(runner_source.count("/usr/bin/xcodebuild"), 1)
            runner.write_text(
                runner_source.replace("/usr/bin/xcodebuild", str(fake_xcodebuild)),
                encoding="utf-8",
            )
            runner.chmod(0o755)

            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            result_root = runtime / "results"
            result_root.mkdir(mode=0o700)
            xctestrun = runtime / "synthetic.xctestrun"
            xctestrun.write_bytes(b"synthetic")
            device_identifier = runtime / "device-identifier"
            device_identifier.write_bytes(b"SYNTHETIC-DEVICE-0001\n")
            device_identifier.chmod(0o600)
            forbidden_values = runtime / "forbidden-values"
            forbidden_values.write_bytes(b"synthetic-one-time-value\n")
            forbidden_values.chmod(0o600)
            ready = runtime / "fake-ready"

            environment = os.environ.copy()
            environment["TACUA_FAKE_RUNNER_READY"] = str(ready)
            running = subprocess.Popen(
                [
                    str(runner),
                    "--xctestrun",
                    str(xctestrun),
                    "--only-testing",
                    "SyntheticTests/ExactTests/testSynthetic",
                    "--device-id-file",
                    str(device_identifier),
                    "--result-root",
                    str(result_root),
                    "--forbidden-values-file",
                    str(forbidden_values),
                    "--confirm-physical-device",
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            process_group: int | None = None
            try:
                deadline = time.monotonic() + 10
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "fake xcodebuild did not become ready")
                identifiers = [
                    int(value)
                    for value in ready.read_text(encoding="ascii").splitlines()
                ]
                self.assertEqual(len(identifiers), 3)
                process_group = identifiers[2]

                os.kill(running.pid, signal.SIGTERM)
                repeat_deadline = time.monotonic() + 10
                while running.poll() is None and time.monotonic() < repeat_deadline:
                    try:
                        os.kill(running.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        break
                    time.sleep(0.01)
                stdout, stderr = running.communicate(timeout=15)

                self.assertEqual(running.returncode, 143)
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, "")
                self.assertEqual(list(result_root.iterdir()), [])
                self.assertFalse(process_group_exists(process_group))
                self.assertFalse(
                    any(process_exists(process_id) for process_id in identifiers[:2])
                )
            finally:
                if running.poll() is None:
                    running.terminate()
                    try:
                        running.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        running.kill()
                        running.wait(timeout=5)
                if process_group is not None and process_group_exists(process_group):
                    try:
                        os.killpg(process_group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_returns_exact_child_status_and_discards_raw_output(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(SUPERVISOR),
                "--",
                sys.executable,
                "-B",
                "-c",
                (
                    "import sys; print('raw-stdout'); "
                    "print('raw-stderr', file=sys.stderr); raise SystemExit(23)"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 23)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")

    def test_forwards_signals_waits_and_reaps_child_process_group(self) -> None:
        for forwarded in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
            with self.subTest(signal=forwarded):
                self._assert_forwarded_and_reaped(forwarded)

    def test_signal_waits_for_descendant_after_leader_exits(self) -> None:
        self._assert_orphan_descendant_cleanup(mode="signal", expected_status=143)

    def test_normal_exit_cleans_descendant_before_returning(self) -> None:
        self._assert_orphan_descendant_cleanup(mode="normal", expected_status=125)

    def _assert_orphan_descendant_cleanup(
        self,
        *,
        mode: str,
        expected_status: int,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="tacua-process-group-") as directory:
            pid_file = pathlib.Path(directory) / "pids"
            supervisor = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(SUPERVISOR),
                    "--",
                    sys.executable,
                    "-B",
                    "-c",
                    ORPHAN_FIXTURE,
                    str(pid_file),
                    mode,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            process_ids: list[int] = []
            process_group: int | None = None
            try:
                deadline = time.monotonic() + 10
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pid_file.exists(), "orphan fixture did not become ready")
                identifiers = [
                    int(value)
                    for value in pid_file.read_text(encoding="ascii").splitlines()
                ]
                self.assertEqual(len(identifiers), 4)
                process_ids = identifiers[:2]
                process_group = identifiers[2]
                self.assertEqual(identifiers[0], process_group)
                self.assertEqual(identifiers[3], process_group)

                if mode == "signal":
                    os.kill(supervisor.pid, signal.SIGTERM)
                stdout, stderr = supervisor.communicate(timeout=15)

                self.assertEqual(supervisor.returncode, expected_status)
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, "")
                self.assertFalse(
                    process_group_exists(process_group),
                    "supervisor returned while an orphaned group member survived",
                )
                self.assertFalse(
                    any(process_exists(process_id) for process_id in process_ids),
                    "supervisor returned while an orphaned process survived",
                )
            finally:
                if supervisor.poll() is None:
                    supervisor.terminate()
                    try:
                        supervisor.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        supervisor.kill()
                        supervisor.wait(timeout=5)
                if process_group is not None and process_group_exists(process_group):
                    try:
                        os.killpg(process_group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def _assert_forwarded_and_reaped(self, forwarded: signal.Signals) -> None:
        with tempfile.TemporaryDirectory(prefix="tacua-process-group-") as directory:
            pid_file = pathlib.Path(directory) / "pids"
            supervisor = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(SUPERVISOR),
                    "--",
                    sys.executable,
                    "-B",
                    "-c",
                    GROUP_FIXTURE,
                    str(pid_file),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            process_ids: list[int] = []
            try:
                deadline = time.monotonic() + 10
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pid_file.exists(), "fake child did not become ready")
                identifiers = [
                    int(value)
                    for value in pid_file.read_text(encoding="ascii").splitlines()
                ]
                self.assertEqual(len(identifiers), 4)
                process_ids = identifiers[:2]
                self.assertEqual(
                    identifiers[0],
                    identifiers[2],
                    "the fake child must lead its tracked process group",
                )
                self.assertEqual(
                    identifiers[2],
                    identifiers[3],
                    "the fake grandchild must remain in the tracked group",
                )

                os.kill(supervisor.pid, forwarded)
                stdout, stderr = supervisor.communicate(timeout=10)
                self.assertEqual(supervisor.returncode, 128 + forwarded)
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, "")

                deadline = time.monotonic() + 5
                while (
                    any(process_exists(process_id) for process_id in process_ids)
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                self.assertFalse(
                    any(process_exists(process_id) for process_id in process_ids),
                    "the fake child process group was not fully reaped",
                )
            finally:
                if supervisor.poll() is None:
                    supervisor.terminate()
                    try:
                        supervisor.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        supervisor.kill()
                        supervisor.wait(timeout=5)
                for process_id in process_ids:
                    if process_exists(process_id):
                        try:
                            os.kill(process_id, signal.SIGKILL)
                        except ProcessLookupError:
                            pass


if __name__ == "__main__":
    unittest.main()
