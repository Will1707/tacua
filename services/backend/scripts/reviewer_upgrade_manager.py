#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Strict user-systemd operations for a crash-safe reviewer upgrade.

This module deliberately contains no transaction policy and performs no file
promotion.  It is the narrow, runner-driven boundary used after exact unit
artifacts have been installed.  Every subprocess invocation is synchronous,
bounded, and names a canonical absolute binary.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import stat
import time
from typing import Callable, Mapping, Sequence


RECONCILE_SERVICE = "tacua-reconcile.service"
RECONCILE_LOCK_SERVICE = "tacua-reconcile-lock.service"
RECONCILE_TIMER = "tacua-reconcile.timer"
UNIT_NAMES = (
    RECONCILE_SERVICE,
    RECONCILE_LOCK_SERVICE,
    RECONCILE_TIMER,
)

MAX_COMMAND_BYTES = 64 * 1024
CONTROL_TIMEOUT_SECONDS = 30.0
RECONCILE_TIMEOUT_SECONDS = 210.0
MAX_WAIT_SECONDS = 300.0
MAX_POLL_SECONDS = 5.0
UNSAFE_PATH_CHARACTERS = frozenset(' \x00\n\r\t"\\%@')
EXEC_TOKEN = re.compile(r"^[A-Za-z0-9_./:@=+,~-]+$")
INVOCATION_ID = re.compile(r"^[0-9a-f]{32}$")
SYSTEMD_STATE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
EXIT_STATUS = re.compile(r"^[0-9]{1,10}$")

Runner = Callable[..., bytes]
ProcessingLockHandoff = Callable[[Callable[[], None]], int]


class ManagerError(RuntimeError):
    """Stable, content-free error raised by the manager boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ManagerBinaries:
    """Canonical absolute user-systemd command paths."""

    systemctl: Path
    systemd_analyze: Path

    def validated(self) -> ManagerBinaries:
        systemctl = _canonical_path(
            self.systemctl,
            "UPGRADE_MANAGER_INPUT_INVALID",
        )
        systemd_analyze = _canonical_path(
            self.systemd_analyze,
            "UPGRADE_MANAGER_INPUT_INVALID",
        )
        if (
            systemctl.name != "systemctl"
            or systemd_analyze.name != "systemd-analyze"
            or systemctl == systemd_analyze
        ):
            raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
        return self


@dataclass(frozen=True)
class ExecStartBinding:
    """The exact executable and flattened argv expected from systemd."""

    path: Path
    argv: tuple[str, ...]

    def validated(self) -> ExecStartBinding:
        executable = _canonical_path(
            self.path,
            "UPGRADE_MANAGER_EXPECTATION_INVALID",
        )
        if (
            not isinstance(self.argv, tuple)
            or not self.argv
            or self.argv[0] != str(executable)
            or any(
                not isinstance(token, str)
                or not token
                or EXEC_TOKEN.fullmatch(token) is None
                for token in self.argv
            )
        ):
            raise ManagerError("UPGRADE_MANAGER_EXPECTATION_INVALID")
        return self


@dataclass(frozen=True)
class LoadedUnitExpectation:
    """Exact loaded fragment and optional service command binding."""

    fragment_path: Path
    exec_start: ExecStartBinding | None

    def validated(self, name: str) -> LoadedUnitExpectation:
        path = _canonical_path(
            self.fragment_path,
            "UPGRADE_MANAGER_EXPECTATION_INVALID",
        )
        if path.name != name:
            raise ManagerError("UPGRADE_MANAGER_EXPECTATION_INVALID")
        if self.exec_start is None:
            if name != RECONCILE_TIMER:
                raise ManagerError("UPGRADE_MANAGER_EXPECTATION_INVALID")
        else:
            if name == RECONCILE_TIMER:
                raise ManagerError("UPGRADE_MANAGER_EXPECTATION_INVALID")
            self.exec_start.validated()
        return self


@dataclass(frozen=True)
class EnableLinkExpectation:
    """One exact systemd enable symlink and its direct target unit."""

    link_path: Path
    target_path: Path

    def validated(self) -> EnableLinkExpectation:
        link = _canonical_path(
            self.link_path,
            "UPGRADE_MANAGER_INPUT_INVALID",
        )
        target = _canonical_path(
            self.target_path,
            "UPGRADE_MANAGER_INPUT_INVALID",
        )
        if (
            link.name != target.name
            or link.parent.parent != target.parent
            or link.parent.name not in {
                "default.target.wants",
                "timers.target.wants",
            }
        ):
            raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
        try:
            _canonical_absence_path(link)
        except ManagerError as error:
            raise ManagerError(
                "UPGRADE_MANAGER_TIMER_LINK_INVALID"
            ) from error
        return self


@dataclass(frozen=True)
class _DirectoryPin:
    path: Path
    descriptor: int
    metadata: tuple[int, int, int, int, int]


class _MonotonicWindow:
    """A non-extensible deadline shared by polling and command timeouts."""

    def __init__(
        self,
        deadline_seconds: float,
        monotonic: Callable[[], float],
        sleep: Callable[[float], None],
        poll_interval_seconds: float,
    ) -> None:
        if (
            not callable(monotonic)
            or not callable(sleep)
            or not isinstance(deadline_seconds, (int, float))
            or isinstance(deadline_seconds, bool)
            or not math.isfinite(float(deadline_seconds))
            or deadline_seconds <= 0
            or deadline_seconds > MAX_WAIT_SECONDS
            or not isinstance(poll_interval_seconds, (int, float))
            or isinstance(poll_interval_seconds, bool)
            or not math.isfinite(float(poll_interval_seconds))
            or poll_interval_seconds <= 0
            or poll_interval_seconds > MAX_POLL_SECONDS
        ):
            raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
        self._monotonic = monotonic
        self._sleep = sleep
        self._poll_interval = float(poll_interval_seconds)
        started = self._read_raw()
        self._previous = started
        self._deadline = started + float(deadline_seconds)

    def _read_raw(self) -> float:
        try:
            value = float(self._monotonic())
        except Exception as error:
            raise ManagerError("UPGRADE_MANAGER_CLOCK_INVALID") from error
        if not math.isfinite(value):
            raise ManagerError("UPGRADE_MANAGER_CLOCK_INVALID")
        return value

    def remaining(self, expired_code: str) -> float:
        now = self._read_raw()
        if now < self._previous:
            raise ManagerError("UPGRADE_MANAGER_CLOCK_INVALID")
        self._previous = now
        remaining = self._deadline - now
        if remaining <= 0:
            raise ManagerError(expired_code)
        return remaining

    def pause(self, expired_code: str) -> None:
        duration = min(self._poll_interval, self.remaining(expired_code))
        try:
            self._sleep(duration)
        except Exception as error:
            raise ManagerError("UPGRADE_MANAGER_CLOCK_INVALID") from error


def _canonical_path(value: Path, code: str) -> Path:
    if (
        not isinstance(value, Path)
        or not value.is_absolute()
        or str(value).startswith("//")
        or value.name in {"", ".", ".."}
        or any(part in {".", ".."} for part in value.parts)
        or any(character in UNSAFE_PATH_CHARACTERS for character in str(value))
    ):
        raise ManagerError(code)
    return value


def _validated_commands(commands: ManagerBinaries) -> ManagerBinaries:
    if not isinstance(commands, ManagerBinaries):
        raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
    return commands.validated()


def _run(
    runner: Runner,
    argv: Sequence[str],
    *,
    timeout: float,
    code: str,
) -> bytes:
    if (
        not callable(runner)
        or not argv
        or not isinstance(argv[0], str)
        or not Path(argv[0]).is_absolute()
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > RECONCILE_TIMEOUT_SECONDS
    ):
        raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
    try:
        payload = runner(list(argv), timeout=timeout)
    except ManagerError:
        raise
    except Exception as error:
        raise ManagerError(code) from error
    if not isinstance(payload, bytes) or len(payload) > MAX_COMMAND_BYTES:
        raise ManagerError(code)
    return payload


def _parse_properties(
    payload: bytes,
    names: Sequence[str],
    code: str,
) -> dict[str, str]:
    try:
        document = payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ManagerError(code) from error
    if "\x00" in document or "\r" in document or not document.endswith("\n"):
        raise ManagerError(code)
    result: dict[str, str] = {}
    for line in document.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in result:
            raise ManagerError(code)
        result[key] = value
    if set(result) != set(names):
        raise ManagerError(code)
    return result


def _show_properties(
    commands: ManagerBinaries,
    runner: Runner,
    unit: str,
    names: Sequence[str],
    *,
    timeout: float = CONTROL_TIMEOUT_SECONDS,
    code: str,
) -> dict[str, str]:
    if unit not in UNIT_NAMES or not names or len(names) != len(set(names)):
        raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
    payload = _run(
        runner,
        [
            str(commands.systemctl),
            "--user",
            "show",
            *(f"--property={name}" for name in names),
            "--",
            unit,
        ],
        timeout=timeout,
        code=code,
    )
    return _parse_properties(payload, names, code)


def _validate_absence_paths(paths: Sequence[Path]) -> tuple[Path, ...]:
    if not isinstance(paths, (tuple, list)) or not paths:
        raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
    try:
        if len(paths) != len(set(paths)):
            raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
    except TypeError as error:
        raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID") from error
    return tuple(_canonical_absence_path(path) for path in paths)


def _canonical_absence_path(path: Path) -> Path:
    selected = _canonical_path(path, "UPGRADE_MANAGER_INPUT_INVALID")
    ancestor = selected.parent
    while True:
        try:
            metadata = ancestor.lstat()
        except FileNotFoundError:
            if ancestor.parent == ancestor:
                raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID") from None
            ancestor = ancestor.parent
            continue
        except OSError as error:
            raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID") from error
        try:
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or ancestor.resolve(strict=True) != ancestor
            ):
                raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
        except OSError as error:
            raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID") from error
        return selected


def _require_absent(paths: Sequence[Path]) -> None:
    for path in paths:
        _canonical_absence_path(path)
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ManagerError("UPGRADE_MANAGER_TIMER_QUIESCE_FAILED") from error
        raise ManagerError("UPGRADE_MANAGER_TIMER_QUIESCE_FAILED")


def _directory_metadata(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _file_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_directory_pin(path: Path, *, missing_code: str) -> _DirectoryPin:
    selected = _canonical_path(path, "UPGRADE_MANAGER_TIMER_LINK_INVALID")
    descriptor: int | None = None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        lexical = selected.lstat()
        if selected.resolve(strict=True) != selected:
            raise ManagerError("UPGRADE_MANAGER_TIMER_LINK_INVALID")
        descriptor = os.open(selected, flags)
        opened = os.fstat(descriptor)
        permissions = stat.S_IMODE(opened.st_mode)
        if (
            not stat.S_ISDIR(lexical.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or lexical.st_uid != os.geteuid()
            or opened.st_uid != os.geteuid()
            or permissions & 0o022
            or _directory_metadata(lexical) != _directory_metadata(opened)
        ):
            raise ManagerError("UPGRADE_MANAGER_TIMER_LINK_INVALID")
        return _DirectoryPin(
            selected,
            descriptor,
            _directory_metadata(opened),
        )
    except ManagerError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except FileNotFoundError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise ManagerError(missing_code) from error
    except OSError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise ManagerError("UPGRADE_MANAGER_TIMER_LINK_INVALID") from error


def _require_directory_pin(pin: _DirectoryPin) -> None:
    try:
        opened = os.fstat(pin.descriptor)
        lexical = pin.path.lstat()
        if (
            pin.path.resolve(strict=True) != pin.path
            or _directory_metadata(opened) != pin.metadata
            or _directory_metadata(lexical) != pin.metadata
        ):
            raise ManagerError("UPGRADE_MANAGER_TIMER_LINK_INVALID")
    except ManagerError:
        raise
    except OSError as error:
        raise ManagerError("UPGRADE_MANAGER_TIMER_LINK_INVALID") from error


def _validated_enable_links(
    values: Sequence[EnableLinkExpectation],
) -> tuple[EnableLinkExpectation, ...]:
    if not isinstance(values, (tuple, list)) or not values:
        raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
    result: list[EnableLinkExpectation] = []
    for value in values:
        if not isinstance(value, EnableLinkExpectation):
            raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
        result.append(value.validated())
    if len({item.link_path for item in result}) != len(result):
        raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
    return tuple(result)


def _link_is_exact(
    expectation: EnableLinkExpectation,
    parent_descriptor: int,
    unit_descriptor: int,
) -> bool:
    try:
        link = os.stat(
            expectation.link_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ManagerError("UPGRADE_MANAGER_TIMER_LINK_INVALID") from error
    try:
        if (
            not stat.S_ISLNK(link.st_mode)
            or link.st_uid != os.geteuid()
            or link.st_nlink != 1
        ):
            raise ManagerError("UPGRADE_MANAGER_TIMER_LINK_INVALID")
        payload = os.readlink(
            expectation.link_path.name,
            dir_fd=parent_descriptor,
        )
        selected = Path(payload)
        if not selected.is_absolute():
            selected = expectation.link_path.parent / selected
        if selected.resolve(strict=True) != expectation.target_path:
            raise ManagerError("UPGRADE_MANAGER_TIMER_LINK_INVALID")
        target = os.stat(
            expectation.target_path.name,
            dir_fd=unit_descriptor,
            follow_symlinks=False,
        )
        followed = os.stat(
            expectation.link_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=True,
        )
        current = os.stat(
            expectation.link_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(target.st_mode)
            or target.st_uid != os.geteuid()
            or target.st_nlink != 1
            or stat.S_IMODE(target.st_mode) != 0o600
            or (followed.st_dev, followed.st_ino)
            != (target.st_dev, target.st_ino)
            or _file_metadata(current) != _file_metadata(link)
        ):
            raise ManagerError("UPGRADE_MANAGER_TIMER_LINK_INVALID")
        return True
    except ManagerError:
        raise
    except OSError as error:
        raise ManagerError("UPGRADE_MANAGER_TIMER_LINK_INVALID") from error


def prove_enable_links_durable(
    values: Sequence[EnableLinkExpectation],
    *,
    present: bool,
    unsettled_code: str,
) -> None:
    """Fsync and re-prove exact enable-link presence or absence."""

    links = _validated_enable_links(values)
    if not isinstance(present, bool) or not isinstance(unsettled_code, str):
        raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
    link_parents = {item.link_path.parent for item in links}
    target_parents = {item.target_path.parent for item in links}
    directory_paths = link_parents | target_parents
    pins: dict[Path, _DirectoryPin] = {}
    try:
        for path in sorted(directory_paths, key=str):
            pins[path] = _open_directory_pin(
                path,
                missing_code=(
                    unsettled_code
                    if path in link_parents and path not in target_parents
                    else "UPGRADE_MANAGER_TIMER_LINK_INVALID"
                ),
            )
        for item in links:
            exact = _link_is_exact(
                item,
                pins[item.link_path.parent].descriptor,
                pins[item.target_path.parent].descriptor,
            )
            if exact != present:
                raise ManagerError(unsettled_code)
        for path in sorted(
            link_parents,
            key=str,
        ):
            os.fsync(pins[path].descriptor)
        for path in sorted(
            target_parents,
            key=str,
        ):
            os.fsync(pins[path].descriptor)
        for pin in pins.values():
            _require_directory_pin(pin)
        for item in links:
            exact = _link_is_exact(
                item,
                pins[item.link_path.parent].descriptor,
                pins[item.target_path.parent].descriptor,
            )
            if exact != present:
                raise ManagerError(unsettled_code)
    except ManagerError:
        raise
    except OSError as error:
        raise ManagerError("UPGRADE_MANAGER_TIMER_LINK_INVALID") from error
    finally:
        for pin in pins.values():
            try:
                os.close(pin.descriptor)
            except OSError:
                pass


def stop_disable_verify_timer(
    commands: ManagerBinaries,
    runner: Runner,
    *,
    enable_links: Sequence[EnableLinkExpectation],
) -> None:
    """Durably quiesce the timer, service, and all exact enable links."""

    commands = _validated_commands(commands)
    links = _validated_enable_links(enable_links)
    _run(
        runner,
        [
            str(commands.systemctl),
            "--user",
            "stop",
            "--",
            RECONCILE_TIMER,
        ],
        timeout=CONTROL_TIMEOUT_SECONDS,
        code="UPGRADE_MANAGER_TIMER_QUIESCE_FAILED",
    )
    _run(
        runner,
        [
            str(commands.systemctl),
            "--user",
            "stop",
            "--",
            RECONCILE_SERVICE,
        ],
        timeout=RECONCILE_TIMEOUT_SECONDS,
        code="UPGRADE_MANAGER_RECONCILE_QUIESCE_FAILED",
    )
    _run(
        runner,
        [
            str(commands.systemctl),
            "--user",
            "disable",
            "--",
            RECONCILE_TIMER,
        ],
        timeout=CONTROL_TIMEOUT_SECONDS,
        code="UPGRADE_MANAGER_TIMER_QUIESCE_FAILED",
    )
    state = _show_properties(
        commands,
        runner,
        RECONCILE_TIMER,
        ("ActiveState", "UnitFileState"),
        code="UPGRADE_MANAGER_TIMER_QUIESCE_FAILED",
    )
    if state != {"ActiveState": "inactive", "UnitFileState": "disabled"}:
        raise ManagerError("UPGRADE_MANAGER_TIMER_QUIESCE_FAILED")
    service = _show_properties(
        commands,
        runner,
        RECONCILE_SERVICE,
        ("ActiveState",),
        code="UPGRADE_MANAGER_RECONCILE_QUIESCE_FAILED",
    )
    if service != {"ActiveState": "inactive"}:
        raise ManagerError("UPGRADE_MANAGER_RECONCILE_QUIESCE_FAILED")
    prove_enable_links_durable(
        links,
        present=False,
        unsettled_code="UPGRADE_MANAGER_TIMER_QUIESCE_FAILED",
    )


def verify_unit_syntax(
    commands: ManagerBinaries,
    runner: Runner,
    unit_paths: Mapping[str, Path],
) -> None:
    """Run systemd's verifier against exactly the three promoted paths."""

    commands = _validated_commands(commands)
    if not isinstance(unit_paths, Mapping) or set(unit_paths) != set(UNIT_NAMES):
        raise ManagerError("UPGRADE_MANAGER_EXPECTATION_INVALID")
    ordered: list[str] = []
    for name in UNIT_NAMES:
        path = _canonical_path(
            unit_paths[name],
            "UPGRADE_MANAGER_EXPECTATION_INVALID",
        )
        if path.name != name:
            raise ManagerError("UPGRADE_MANAGER_EXPECTATION_INVALID")
        ordered.append(str(path))
    _run(
        runner,
        [
            str(commands.systemd_analyze),
            "--user",
            "verify",
            "--",
            *ordered,
        ],
        timeout=CONTROL_TIMEOUT_SECONDS,
        code="UPGRADE_MANAGER_UNIT_VERIFY_FAILED",
    )


def daemon_reload(commands: ManagerBinaries, runner: Runner) -> None:
    """Synchronously reload the user manager."""

    commands = _validated_commands(commands)
    _run(
        runner,
        [str(commands.systemctl), "--user", "daemon-reload"],
        timeout=CONTROL_TIMEOUT_SECONDS,
        code="UPGRADE_MANAGER_DAEMON_RELOAD_FAILED",
    )


def _exec_start_matches(value: str, expected: ExecStartBinding) -> bool:
    expected.validated()
    prefix = "{ path="
    argv_marker = " ; argv[]="
    suffix_marker = " ; ignore_errors="
    if not value.startswith(prefix) or value.count(argv_marker) != 1:
        return False
    before_argv, argv_and_rest = value[len(prefix) :].split(argv_marker, 1)
    if argv_and_rest.count(suffix_marker) != 1:
        return False
    argv, rest = argv_and_rest.split(suffix_marker, 1)
    return (
        before_argv == str(expected.path)
        and argv == " ".join(expected.argv)
        and rest.startswith(("yes ;", "no ;"))
        and value.endswith("}")
        and value.count("{ path=") == 1
    )


def verify_loaded_units(
    commands: ManagerBinaries,
    runner: Runner,
    expectations: Mapping[str, LoadedUnitExpectation],
) -> None:
    """Prove the manager loaded only the expected fragments and commands."""

    commands = _validated_commands(commands)
    if not isinstance(expectations, Mapping) or set(expectations) != set(UNIT_NAMES):
        raise ManagerError("UPGRADE_MANAGER_EXPECTATION_INVALID")
    properties = (
        "FragmentPath",
        "DropInPaths",
        "LoadState",
        "NeedDaemonReload",
        "ExecStart",
    )
    for name in UNIT_NAMES:
        expectation = expectations[name]
        if not isinstance(expectation, LoadedUnitExpectation):
            raise ManagerError("UPGRADE_MANAGER_EXPECTATION_INVALID")
        expectation.validated(name)
        actual = _show_properties(
            commands,
            runner,
            name,
            properties,
            code="UPGRADE_MANAGER_LOADED_UNIT_INVALID",
        )
        if (
            actual["FragmentPath"] != str(expectation.fragment_path)
            or actual["DropInPaths"] != ""
            or actual["LoadState"] != "loaded"
            or actual["NeedDaemonReload"] != "no"
        ):
            raise ManagerError("UPGRADE_MANAGER_LOADED_UNIT_INVALID")
        if expectation.exec_start is None:
            if actual["ExecStart"] != "":
                raise ManagerError("UPGRADE_MANAGER_LOADED_UNIT_INVALID")
        elif not _exec_start_matches(actual["ExecStart"], expectation.exec_start):
            raise ManagerError("UPGRADE_MANAGER_LOADED_UNIT_INVALID")


def _verify_lock_service(commands: ManagerBinaries, runner: Runner) -> None:
    actual = _show_properties(
        commands,
        runner,
        RECONCILE_LOCK_SERVICE,
        ("ActiveState", "SubState", "Result", "ExecMainStatus"),
        code="UPGRADE_MANAGER_LOCK_RESTART_FAILED",
    )
    if actual != {
        "ActiveState": "active",
        "SubState": "exited",
        "Result": "success",
        "ExecMainStatus": "0",
    }:
        raise ManagerError("UPGRADE_MANAGER_LOCK_RESTART_FAILED")


def _processing_lock_handoff(
    with_released_processing_lock: ProcessingLockHandoff,
    action: Callable[[], None],
) -> int:
    """Enforce the callable portion of the processing-lock handoff contract.

    Before invoking ``action``, the caller callback must unlock and close its
    owned descriptor.  In a ``finally`` block it must open the same canonical
    lock path, acquire it exclusively and non-blockingly, revalidate its inode,
    owner, mode and close-on-exec flag, and only then return that replacement
    descriptor.  The numeric descriptor may be reused by the OS.  The caller
    must replace its outer ownership bookkeeping with the returned descriptor;
    it must never operate on or later release the stale descriptor.

    If ``action`` raises, the callback's ``finally`` block must still reacquire,
    revalidate, and store the replacement in that mutable outer bookkeeping
    before the exception is re-raised.  The manager cannot return a descriptor
    on an error path, so failing to update the holder in ``finally`` would make
    later cleanup reuse a stale descriptor or leak the replacement.

    This manager can prove that the action ran exactly once and completed, but
    the descriptor's host-lock validation remains the caller's responsibility.
    """

    if not callable(with_released_processing_lock):
        raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")
    calls = 0
    completed = False

    def guarded_action() -> None:
        nonlocal calls, completed
        calls += 1
        if calls != 1:
            raise ManagerError("UPGRADE_MANAGER_LOCK_HANDOFF_INVALID")
        action()
        completed = True

    try:
        descriptor = with_released_processing_lock(guarded_action)
    except ManagerError:
        raise
    except Exception as error:
        if getattr(error, "code", None) == "RECONCILE_DEFERRED":
            raise ManagerError("UPGRADE_MANAGER_LOCK_CONTENDED") from error
        raise ManagerError("UPGRADE_MANAGER_LOCK_HANDOFF_FAILED") from error
    if calls != 1 or not completed or type(descriptor) is not int or descriptor < 0:
        raise ManagerError("UPGRADE_MANAGER_LOCK_HANDOFF_INVALID")
    return descriptor


def restart_reconcile_lock(
    commands: ManagerBinaries,
    runner: Runner,
    *,
    with_released_processing_lock: ProcessingLockHandoff,
) -> int:
    """Restart the promoted lock prerequisite during an explicit handoff.

    ``daemon_reload`` is safe while the resumer itself is running: systemd
    retains that invocation while reloading unit definitions for subsequent
    jobs.  The promoted lock prerequisite cannot run while the resumer owns
    the shared processing lock, so this action uses the strict release/close
    and finally-reacquire contract documented by ``_processing_lock_handoff``.
    """

    commands = _validated_commands(commands)

    def action() -> None:
        _run(
            runner,
            [
                str(commands.systemctl),
                "--user",
                "restart",
                "--",
                RECONCILE_LOCK_SERVICE,
            ],
            timeout=CONTROL_TIMEOUT_SECONDS,
            code="UPGRADE_MANAGER_LOCK_RESTART_FAILED",
        )
        _verify_lock_service(commands, runner)

    return _processing_lock_handoff(with_released_processing_lock, action)


def start_verify_maintenance_reconcile(
    commands: ManagerBinaries,
    runner: Runner,
    *,
    with_released_processing_lock: ProcessingLockHandoff,
    verify_maintenance: Callable[[], bool],
) -> int:
    """Run and prove maintenance inside a processing-lock handoff.

    The reconciliation service acquires the same shared processing lock as the
    resumer.  Calling it without releasing the resumer's descriptor would
    defer or deadlock the oneshot.  The returned replacement descriptor must
    replace the caller's prior ownership bookkeeping.
    """

    commands = _validated_commands(commands)
    if not callable(verify_maintenance):
        raise ManagerError("UPGRADE_MANAGER_INPUT_INVALID")

    def action() -> None:
        _run(
            runner,
            [
                str(commands.systemctl),
                "--user",
                "start",
                "--",
                RECONCILE_SERVICE,
            ],
            timeout=RECONCILE_TIMEOUT_SECONDS,
            code="UPGRADE_MANAGER_RECONCILE_FAILED",
        )
        actual = _show_properties(
            commands,
            runner,
            RECONCILE_SERVICE,
            ("ActiveState", "SubState", "Result", "ExecMainStatus"),
            code="UPGRADE_MANAGER_RECONCILE_FAILED",
        )
        if actual != {
            "ActiveState": "inactive",
            "SubState": "dead",
            "Result": "success",
            "ExecMainStatus": "0",
        }:
            raise ManagerError("UPGRADE_MANAGER_RECONCILE_FAILED")
        try:
            maintenance = verify_maintenance()
        except Exception as error:
            raise ManagerError(
                "UPGRADE_MANAGER_MAINTENANCE_NOT_PROVEN"
            ) from error
        if maintenance is not True:
            raise ManagerError("UPGRADE_MANAGER_MAINTENANCE_NOT_PROVEN")

    return _processing_lock_handoff(with_released_processing_lock, action)


def enable_restart_timer(
    commands: ManagerBinaries,
    runner: Runner,
    *,
    enable_links: Sequence[EnableLinkExpectation],
) -> None:
    """Install durable persistence and arm a fresh timer schedule."""

    commands = _validated_commands(commands)
    links = _validated_enable_links(enable_links)
    for verb in ("enable", "restart"):
        _run(
            runner,
            [
                str(commands.systemctl),
                "--user",
                verb,
                "--",
                RECONCILE_TIMER,
            ],
            timeout=CONTROL_TIMEOUT_SECONDS,
            code="UPGRADE_MANAGER_TIMER_ARM_FAILED",
        )
    prove_enable_links_durable(
        links,
        present=True,
        unsettled_code="UPGRADE_MANAGER_TIMER_ARM_FAILED",
    )


def _timer_waiting(properties: Mapping[str, str]) -> bool:
    sentinels = {"", "0", "0us", "infinity", "n/a"}
    next_values = (
        properties["NextElapseUSecRealtime"].strip().lower(),
        properties["NextElapseUSecMonotonic"].strip().lower(),
    )
    return (
        properties["UnitFileState"] == "enabled"
        and properties["ActiveState"] == "active"
        and properties["SubState"] == "waiting"
        and any(value not in sentinels for value in next_values)
    )


def prove_timer_enabled_active_waiting(
    commands: ManagerBinaries,
    runner: Runner,
    *,
    enable_links: Sequence[EnableLinkExpectation],
    deadline_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    poll_interval_seconds: float = 0.25,
) -> None:
    """Poll until a persistent timer has a future trigger, within a deadline."""

    commands = _validated_commands(commands)
    links = _validated_enable_links(enable_links)
    window = _MonotonicWindow(
        deadline_seconds,
        monotonic,
        sleep,
        poll_interval_seconds,
    )

    _prove_timer_waiting(commands, runner, window)
    prove_enable_links_durable(
        links,
        present=True,
        unsettled_code="UPGRADE_MANAGER_TIMER_ARM_FAILED",
    )


def _prove_timer_waiting(
    commands: ManagerBinaries,
    runner: Runner,
    window: _MonotonicWindow,
) -> None:
    properties = (
        "UnitFileState",
        "ActiveState",
        "SubState",
        "NextElapseUSecRealtime",
        "NextElapseUSecMonotonic",
    )
    while True:
        remaining = window.remaining("UPGRADE_MANAGER_TIMER_NOT_WAITING")
        actual = _show_properties(
            commands,
            runner,
            RECONCILE_TIMER,
            properties,
            timeout=min(CONTROL_TIMEOUT_SECONDS, remaining),
            code="UPGRADE_MANAGER_TIMER_NOT_WAITING",
        )
        window.remaining("UPGRADE_MANAGER_TIMER_NOT_WAITING")
        if _timer_waiting(actual):
            return
        window.pause("UPGRADE_MANAGER_TIMER_NOT_WAITING")


def _successful_inactive_reconcile(properties: Mapping[str, str]) -> bool:
    return (
        properties["ActiveState"] == "inactive"
        and properties["SubState"] == "dead"
        and properties["Result"] == "success"
        and properties["ExecMainStatus"] == "0"
    )


def _reconcile_properties_well_formed(properties: Mapping[str, str]) -> bool:
    return (
        INVOCATION_ID.fullmatch(properties["InvocationID"]) is not None
        and SYSTEMD_STATE.fullmatch(properties["ActiveState"]) is not None
        and SYSTEMD_STATE.fullmatch(properties["SubState"]) is not None
        and SYSTEMD_STATE.fullmatch(properties["Result"]) is not None
        and EXIT_STATUS.fullmatch(properties["ExecMainStatus"]) is not None
    )


def prove_later_scheduled_reconcile(
    commands: ManagerBinaries,
    runner: Runner,
    *,
    with_released_processing_lock: ProcessingLockHandoff,
    enable_links: Sequence[EnableLinkExpectation],
    deadline_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    poll_interval_seconds: float = 0.25,
) -> tuple[int, str]:
    """Prove a distinct, successful timer-triggered reconciliation.

    The completed manual reconciliation's nonempty ``InvocationID`` is
    captured before the timer is armed.  The timer is then enabled and
    restarted while the caller's processing lock is released.  This function
    accepts exactly one later invocation, waits for that invocation to finish
    successfully, and finally proves that the timer is persistently enabled,
    active, waiting, and has another deadline.

    The scheduled reconciliation also acquires the shared processing lock, so
    the entire arm/wait/proof action uses the strict finally-reacquire contract
    documented by ``_processing_lock_handoff``.  The returned tuple contains
    the replacement descriptor and the proven later invocation ID.
    """

    commands = _validated_commands(commands)
    links = _validated_enable_links(enable_links)
    window = _MonotonicWindow(
        deadline_seconds,
        monotonic,
        sleep,
        poll_interval_seconds,
    )
    service_properties = (
        "InvocationID",
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainStatus",
    )
    baseline = _show_properties(
        commands,
        runner,
        RECONCILE_SERVICE,
        service_properties,
        timeout=min(
            CONTROL_TIMEOUT_SECONDS,
            window.remaining("UPGRADE_MANAGER_SCHEDULED_RECONCILE_TIMEOUT"),
        ),
        code="UPGRADE_MANAGER_SCHEDULED_RECONCILE_FAILED",
    )
    window.remaining("UPGRADE_MANAGER_SCHEDULED_RECONCILE_TIMEOUT")
    baseline_id = baseline["InvocationID"]
    if not _reconcile_properties_well_formed(baseline):
        raise ManagerError("UPGRADE_MANAGER_INVOCATION_INVALID")

    completed_id: str | None = None

    def action() -> None:
        nonlocal completed_id
        for verb in ("enable", "restart"):
            remaining = window.remaining(
                "UPGRADE_MANAGER_SCHEDULED_RECONCILE_TIMEOUT"
            )
            _run(
                runner,
                [
                    str(commands.systemctl),
                    "--user",
                    verb,
                    "--",
                    RECONCILE_TIMER,
                ],
                timeout=min(CONTROL_TIMEOUT_SECONDS, remaining),
                code="UPGRADE_MANAGER_TIMER_ARM_FAILED",
            )
            window.remaining("UPGRADE_MANAGER_SCHEDULED_RECONCILE_TIMEOUT")

        observed_id: str | None = None
        while True:
            remaining = window.remaining(
                "UPGRADE_MANAGER_SCHEDULED_RECONCILE_TIMEOUT"
            )
            actual = _show_properties(
                commands,
                runner,
                RECONCILE_SERVICE,
                service_properties,
                timeout=min(CONTROL_TIMEOUT_SECONDS, remaining),
                code="UPGRADE_MANAGER_SCHEDULED_RECONCILE_FAILED",
            )
            window.remaining("UPGRADE_MANAGER_SCHEDULED_RECONCILE_TIMEOUT")
            invocation_id = actual["InvocationID"]
            if not _reconcile_properties_well_formed(actual):
                raise ManagerError("UPGRADE_MANAGER_INVOCATION_INVALID")
            if invocation_id != baseline_id:
                if observed_id is None:
                    observed_id = invocation_id
                elif invocation_id != observed_id:
                    raise ManagerError(
                        "UPGRADE_MANAGER_SCHEDULED_RECONCILE_FAILED"
                    )
                if _successful_inactive_reconcile(actual):
                    completed_id = invocation_id
                    break
                if actual["ActiveState"] not in {
                    "activating",
                    "active",
                    "deactivating",
                    "reloading",
                } or not actual["SubState"]:
                    raise ManagerError(
                        "UPGRADE_MANAGER_SCHEDULED_RECONCILE_FAILED"
                    )
            window.pause("UPGRADE_MANAGER_SCHEDULED_RECONCILE_TIMEOUT")

        window.remaining("UPGRADE_MANAGER_SCHEDULED_RECONCILE_TIMEOUT")
        _prove_timer_waiting(commands, runner, window)
        prove_enable_links_durable(
            links,
            present=True,
            unsettled_code="UPGRADE_MANAGER_TIMER_ARM_FAILED",
        )

    descriptor = _processing_lock_handoff(
        with_released_processing_lock,
        action,
    )
    if completed_id is None:
        raise ManagerError("UPGRADE_MANAGER_SCHEDULED_RECONCILE_FAILED")
    return descriptor, completed_id
