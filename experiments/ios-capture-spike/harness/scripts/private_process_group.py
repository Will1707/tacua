#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run and fully drain one private process group with no raw output."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from collections.abc import Sequence


FORWARDED_SIGNALS = (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)
PROCESS_GROUP_GRACE_SECONDS = 5.0
PROCESS_GROUP_POLL_SECONDS = 0.05
PROCESS_GROUP_SURVIVOR_STATUS = 125


def _status_from_returncode(returncode: int) -> int:
    return 128 - returncode if returncode < 0 else returncode


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # The group still exists even if an unexpected ownership change makes
        # it unsignalable. Fail closed by continuing to wait.
        return True
    return True


def _signal_process_group(process_group: int, signum: int) -> None:
    try:
        os.killpg(process_group, signum)
    except ProcessLookupError:
        pass


def _wait_for_process_group_exit(
    process_group: int,
    deadline: float | None,
) -> bool:
    while _process_group_exists(process_group):
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(PROCESS_GROUP_POLL_SECONDS, remaining))
        else:
            time.sleep(PROCESS_GROUP_POLL_SECONDS)
    return True


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments in (["--help"], ["-h"]):
        print("Usage: private_process_group.py -- COMMAND [ARG ...]")
        return 0
    if not arguments or arguments[0] != "--" or len(arguments) == 1:
        print("error: one command must follow --", file=sys.stderr)
        return 2

    child: subprocess.Popen[bytes] | None = None
    child_process_group: int | None = None
    received_signal: int | None = None
    signal_deadline: float | None = None

    def forward(signum: int, _frame: object) -> None:
        nonlocal received_signal, signal_deadline
        received_signal = received_signal or signum
        signal_deadline = (
            signal_deadline or time.monotonic() + PROCESS_GROUP_GRACE_SECONDS
        )
        if child_process_group is None:
            return
        _signal_process_group(child_process_group, signum)

    previous_handlers = {
        signum: signal.signal(signum, forward) for signum in FORWARDED_SIGNALS
    }
    try:
        try:
            child = subprocess.Popen(
                arguments[1:],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
        except OSError:
            return 127
        child_process_group = child.pid
        if received_signal is not None:
            _signal_process_group(child_process_group, received_signal)

        forced_group_kill = False
        while True:
            try:
                returncode = child.wait(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                if signal_deadline is None or time.monotonic() < signal_deadline:
                    continue
                _signal_process_group(child_process_group, signal.SIGKILL)
                forced_group_kill = True
                returncode = child.wait()
                break
            except InterruptedError:
                continue

        group_deadline = signal_deadline or (
            time.monotonic() + PROCESS_GROUP_GRACE_SECONDS
        )
        if not _wait_for_process_group_exit(child_process_group, group_deadline):
            _signal_process_group(child_process_group, signal.SIGKILL)
            forced_group_kill = True
            # Never let cleanup or result scanning race a surviving writer.
            # SIGKILL has no finite grace after this point: returning while the
            # group still exists would violate the supervisor's safety boundary.
            _wait_for_process_group_exit(child_process_group, None)

        if received_signal is not None:
            return 128 + received_signal
        if forced_group_kill:
            return PROCESS_GROUP_SURVIVOR_STATUS
        return _status_from_returncode(returncode)
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)


if __name__ == "__main__":
    raise SystemExit(main())
