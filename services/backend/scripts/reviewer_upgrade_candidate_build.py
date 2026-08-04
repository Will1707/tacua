#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build one verified, immutable reviewer-upgrade prepared release.

This module is the pre-live producer for :mod:`reviewer_upgrade_candidate`.
It never invokes the live Compose project, systemd, Tailscale, the reconciler,
or the upgrade launcher.  All expensive verification runs in a generation-
owned, isolated checkout before a sealed release is published.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, NoReturn, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import reviewer_upgrade_candidate as candidate  # noqa: E402
import reconcile_compose_deployment as reconciler  # noqa: E402


COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
REPOSITORY_IDENTITY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$"
)
IMAGE_ID_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
TEST_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
ATTEMPT_RE = re.compile(r"^attempt-([0-9]{6})$")
LOG_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
GIT_MODE_RE = re.compile(rb"^(100644|100755) ([a-f0-9]{40,64}) 0\t(.+)$")
BUILD_CODE = "REVIEWER_UPGRADE_CANDIDATE_BUILT"
BUILD_JOURNAL_CONTRACT = "tacua.reviewer-upgrade-candidate-build-journal@1.0.0"
ATTEMPTS_DIRECTORY = "attempts"
RELEASES_DIRECTORY = "releases"
JOURNAL_DIRECTORY = "journal"
LOGS_DIRECTORY = "logs"
COMMANDS_FILE = "verification-commands.json"
BUILD_SOURCE_DIRECTORY = "build-source"
STAGED_RELEASE_DIRECTORY = "staged-release"
BUILD_LOCK_FILE = "candidate-build.lock"
MAX_COMMAND_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_COMMAND_SECONDS = 3_600.0
TERMINATION_GRACE_SECONDS = 30.0
TERMINATION_KILL_WAIT_SECONDS = 5.0
MAX_JOURNAL_RECORD_BYTES = 1 * 1024 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024
REQUIRED_NODE_VERSION = "v22.22.2"
REQUIRED_NPM_VERSION = "10.9.4"
PRIVATE_PROCESS_UMASK = 0o077
VERIFICATION_CHILD_UMASK = 0o022
_CLEANUP_TARGETS = frozenset(
    {BUILD_SOURCE_DIRECTORY, STAGED_RELEASE_DIRECTORY, "ios-export", "runtime"}
)

# Only reviewer product code and the checked-in host upgrade boundary may move.
# In particular, backend runtime/package code, container definitions, Compose,
# protocol schemas, mobile SDK code, ingress, and general CI are excluded.
_ALLOWED_EXACT = frozenset(
    {
        "README.md",
        "services/backend/scripts/reconcile_compose_deployment.py",
        "services/backend/tests/test_compose_processing_bridge.py",
        "services/backend/tests/test_compose_reconciler.py",
        ".github/scripts/generate-reviewer-third-party-notices.mjs",
        ".github/scripts/smoke-reviewer-web-browser.mjs",
        ".github/scripts/validate-reviewer-web-image-inputs.mjs",
        ".github/scripts/validate-reviewer-web-image-inputs.test.mjs",
    }
)
_ALLOWED_PREFIXES = (
    "apps/reviewer/",
    "services/reviewer-web/",
    "services/backend/scripts/reviewer_upgrade_",
    "services/backend/tests/test_reviewer_upgrade_",
    "services/backend/systemd/",
)
# The first self-hosted pilot was sealed before the reconciliation and guarded
# reviewer-upgrade boundary landed.  Crossing that exact public baseline also
# carries a bounded set of already-reviewed pilot diagnostics, CI, and bridge
# files.  Keep this exception commit-bound and path-exact: later installations
# must continue to satisfy the reviewer-only policy above.
_PILOT_BASELINE_COMMIT = candidate._PILOT_BASELINE_COMMIT
_PILOT_BASELINE_ALLOWED_EXACT = frozenset(
    {
        ".github/workflows/verify.yml",
        "experiments/ios-capture-spike/PILOT-DIAGNOSTICS-RETENTION.md",
        "experiments/ios-capture-spike/PILOT-OPERATION-RECEIPT.md",
        "experiments/ios-capture-spike/harness/README.md",
        "experiments/ios-capture-spike/package/README.md",
        "experiments/ios-capture-spike/package/ios/TacuaBackendConfiguration.swift",
        "experiments/ios-capture-spike/package/src/BackendManagedHostController.ts",
        "experiments/ios-capture-spike/package/tests/BackendConfigurationTests.swift",
        "experiments/ios-capture-spike/package/tests/backend-managed-host-controller.test.ts",
        "experiments/ios-capture-spike/scripts/finalize_pilot_operation.py",
        "experiments/ios-capture-spike/scripts/manage_pilot_diagnostics.py",
        "experiments/ios-capture-spike/tests/test_finalize_pilot_operation.py",
        "experiments/ios-capture-spike/tests/test_pilot_diagnostics_retention.py",
        "services/backend/scripts/run_compose_isolated_processing.py",
        "services/backend/tests/test_reconcile_systemd_contract.py",
    }
)
_FORBIDDEN_PREFIXES = (
    "apps/mobile-sdk/",
    "contracts/",
    "packages/mobile-sdk/",
    "services/backend/src/",
    "services/backend/ingress/",
)
_FORBIDDEN_EXACT = frozenset(
    {
        "services/backend/compose.yaml",
        "services/backend/compose.production.yaml",
        "services/backend/compose.processor.yaml",
        "services/backend/Dockerfile",
        "services/backend/Dockerfile.dockerignore",
        "apps/reviewer/Dockerfile",
        "apps/reviewer/Dockerfile.dockerignore",
        "services/reviewer-web/Dockerfile",
        "services/reviewer-web/Dockerfile.dockerignore",
    }
)


class CandidateBuildError(RuntimeError):
    """Stable, content-free producer failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str = "REVIEWER_UPGRADE_CANDIDATE_BUILD_INVALID") -> NoReturn:
    raise CandidateBuildError(code)


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")


@dataclass(frozen=True)
class CommandResult:
    returncode: int = 0
    stdout: bytes = b""
    stderr: bytes = b""


Runner = Callable[..., CommandResult]


def _validated_child_umask(value: int) -> int:
    if type(value) is not int or value != VERIFICATION_CHILD_UMASK:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_INVALID")
    return value


@dataclass(frozen=True)
class BuildInputs:
    installed_repository: Path
    installed_commit: str
    candidate_commit: str
    source_state_directory: Path
    preparations_parent: Path
    repository_identity: str
    git: Path
    python: Path
    node: Path
    npm_cli: Path
    docker: Path
    bash: Path
    command_path: str

    @property
    def repository_url(self) -> str:
        return f"https://github.com/{self.repository_identity}.git"

    @property
    def installed_origin_urls(self) -> frozenset[str]:
        return frozenset(
            {
                self.repository_url,
                f"git@github.com:{self.repository_identity}.git",
                f"ssh://git@github.com/{self.repository_identity}.git",
            }
        )

    def validate(self) -> BuildInputs:
        if (
            COMMIT_RE.fullmatch(self.installed_commit) is None
            or COMMIT_RE.fullmatch(self.candidate_commit) is None
            or self.installed_commit == self.candidate_commit
            or REPOSITORY_IDENTITY_RE.fullmatch(self.repository_identity) is None
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")
        _canonical_directory(self.installed_repository, private=False)
        _canonical_directory(self.source_state_directory, private=True)
        _canonical_directory(self.preparations_parent, private=True)
        for tool in (
            self.git,
            self.python,
            self.node,
            self.npm_cli,
            self.docker,
            self.bash,
        ):
            _canonical_tool(tool, executable=tool != self.npm_cli)
        _validate_command_path(self)
        return self


class SubprocessRunner:
    """Explicit, bounded command execution with private per-command logs."""

    def __init__(self, log_directory: Path) -> None:
        self._log_directory = _canonical_directory(log_directory, private=True)
        self._sequence = 0

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        label: str,
        umask: int = VERIFICATION_CHILD_UMASK,
    ) -> CommandResult:
        command = _validate_command(argv, cwd=cwd, env=env, timeout=timeout, label=label)
        child_umask = _validated_child_umask(umask)
        self._sequence += 1
        stem = f"{self._sequence:04d}-{label}"
        stdout_path = self._log_directory / f"{stem}.stdout.log"
        stderr_path = self._log_directory / f"{stem}.stderr.log"
        stdout_fd = _create_private_file(stdout_path)
        stderr_fd = _create_private_file(stderr_path)
        process: subprocess.Popen[bytes] | None = None
        try:
            try:
                process = subprocess.Popen(
                    command,
                    cwd=cwd,
                    env=dict(env),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    start_new_session=True,
                    bufsize=0,
                    umask=child_umask,
                )
                returncode = _drain_bounded_process(
                    process,
                    stdout_fd=stdout_fd,
                    stderr_fd=stderr_fd,
                    timeout=float(timeout),
                )
            except CandidateBuildError:
                if process is not None:
                    _terminate_process_group(process)
                raise
            except OSError as error:
                if process is not None:
                    _terminate_process_group(process)
                raise CandidateBuildError(
                    "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED"
                ) from error
            os.fsync(stdout_fd)
            os.fsync(stderr_fd)
        finally:
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            os.close(stdout_fd)
            os.close(stderr_fd)
        stdout = _read_log(stdout_path)
        stderr = _read_log(stderr_path)
        return CommandResult(returncode, stdout, stderr)


def _signal_process_group(
    process: subprocess.Popen[bytes],
    signal_number: signal.Signals,
) -> None:
    try:
        os.killpg(process.pid, signal_number)
    except ProcessLookupError:
        return
    except OSError:
        try:
            process.send_signal(signal_number)
        except OSError:
            return


def _process_group_exists(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return process.poll() is None


def _register_termination_streams(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is None or stream.closed:
            continue
        try:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream.fileno(), selectors.EVENT_READ)
        except OSError:
            continue


def _discard_termination_output(
    selector: selectors.BaseSelector,
    timeout: float,
) -> None:
    if not selector.get_map():
        time.sleep(timeout)
        return
    for key, _mask in selector.select(timeout):
        descriptor = int(key.fd)
        try:
            block = os.read(descriptor, 65_536)
        except BlockingIOError:
            continue
        except OSError:
            try:
                selector.unregister(descriptor)
            except (KeyError, OSError):
                pass
            continue
        if not block:
            try:
                selector.unregister(descriptor)
            except (KeyError, OSError):
                pass


def _wait_for_terminated_group(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    *,
    deadline: float,
) -> bool:
    while True:
        process.poll()
        if not _process_group_exists(process):
            try:
                process.wait(timeout=0)
            except (OSError, subprocess.TimeoutExpired):
                pass
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        _discard_termination_output(selector, min(remaining, 0.05))


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Allow exact command cleanup traps, then hard-stop the entire session."""

    selector = selectors.DefaultSelector()
    try:
        _register_termination_streams(process, selector)
        _signal_process_group(process, signal.SIGTERM)
        if _wait_for_terminated_group(
            process,
            selector,
            deadline=time.monotonic() + TERMINATION_GRACE_SECONDS,
        ):
            return
        _signal_process_group(process, signal.SIGKILL)
        _wait_for_terminated_group(
            process,
            selector,
            deadline=time.monotonic() + TERMINATION_KILL_WAIT_SECONDS,
        )
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=TERMINATION_KILL_WAIT_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            pass
    finally:
        selector.close()


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError as error:
            raise CandidateBuildError(
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED"
            ) from error
        if written <= 0:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED")
        view = view[written:]


def _drain_bounded_process(
    process: subprocess.Popen[bytes],
    *,
    stdout_fd: int,
    stderr_fd: int,
    timeout: float,
) -> int:
    if process.stdout is None or process.stderr is None:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED")
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout.fileno(): [stdout_fd, 0],
        process.stderr.fileno(): [stderr_fd, 0],
    }
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream.fileno(), selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED")
            events = selector.select(min(remaining, 0.25))
            for key, _mask in events:
                descriptor = int(key.fd)
                try:
                    block = os.read(descriptor, 65_536)
                except BlockingIOError:
                    continue
                except OSError as error:
                    raise CandidateBuildError(
                        "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED"
                    ) from error
                if not block:
                    selector.unregister(descriptor)
                    continue
                target, count = streams[descriptor]
                if count + len(block) > MAX_COMMAND_OUTPUT_BYTES:
                    _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED")
                _write_all(target, block)
                streams[descriptor][1] = count + len(block)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED")
        try:
            return process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise CandidateBuildError(
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED"
            ) from error
    finally:
        selector.close()


def _canonical_directory(path: Path, *, private: bool) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or str(path).startswith("//")
        or any(part in {".", ".."} for part in path.parts)
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID"
        ) from error
    permissions = stat.S_IMODE(metadata.st_mode)
    allowed_owners = {os.geteuid()} if private else {0, os.geteuid()}
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid not in allowed_owners
        or permissions & 0o022
        or (private and permissions != 0o700)
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")
    return path


def _canonical_tool(path: Path, *, executable: bool) -> dict[str, Any]:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or str(path).startswith("//")
        or any(part in {".", ".."} for part in path.parts)
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")
    descriptor: int | None = None
    try:
        lexical = path.lstat()
        if path.resolve(strict=True) != path:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or lexical.st_uid not in {0, os.geteuid()}
            or opened.st_uid != lexical.st_uid
            or lexical.st_nlink != 1
            or opened.st_nlink != 1
            or stat.S_IMODE(lexical.st_mode) & 0o022
            or (executable and not stat.S_IMODE(lexical.st_mode) & 0o111)
            or lexical.st_size <= 0
            or lexical.st_size > MAX_TOOL_BYTES
            or (lexical.st_dev, lexical.st_ino, lexical.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_size)
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 65_536)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        current = path.lstat()
        if _metadata(after) != _metadata(opened) or _metadata(current) != _metadata(opened):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")
        return {
            "device": opened.st_dev,
            "digest": f"sha256:{digest.hexdigest()}",
            "inode": opened.st_ino,
            "mode": stat.S_IMODE(opened.st_mode),
            "path": str(path),
            "uid": opened.st_uid,
        }
    except CandidateBuildError:
        raise
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _metadata(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _path_entries(value: str) -> tuple[Path, ...]:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")
    entries = tuple(Path(part) for part in value.split(os.pathsep))
    if not entries or any(not part for part in value.split(os.pathsep)):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")
    for entry in entries:
        _canonical_directory(entry, private=False)
    return entries


def _resolved_command(name: str, entries: Sequence[Path]) -> Path:
    if not name or "/" in name:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")
    matches: list[Path] = []
    for directory in entries:
        path = directory / name
        try:
            if path.is_file() and os.access(path, os.X_OK):
                matches.append(path.resolve(strict=True))
        except OSError:
            continue
    if not matches:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")
    return matches[0]


def _validate_command_path(inputs: BuildInputs) -> None:
    entries = _path_entries(inputs.command_path)
    for name, expected in (
        ("bash", inputs.bash),
        ("docker", inputs.docker),
        ("node", inputs.node),
        ("python3", inputs.python),
    ):
        if _resolved_command(name, entries) != expected:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_INPUT_INVALID")


def _validate_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    label: str,
) -> list[str]:
    if (
        not isinstance(argv, Sequence)
        or isinstance(argv, (str, bytes))
        or not argv
        or any(not isinstance(value, str) or not value or "\x00" in value for value in argv)
        or not Path(argv[0]).is_absolute()
        or not isinstance(cwd, Path)
        or not cwd.is_absolute()
        or not cwd.is_dir()
        or not isinstance(env, Mapping)
        or any(
            not isinstance(key, str)
            or not key
            or "=" in key
            or "\x00" in key
            or not isinstance(value, str)
            or "\x00" in value
            for key, value in env.items()
        )
        or type(timeout) not in {int, float}
        or not 0 < float(timeout) <= MAX_COMMAND_SECONDS
        or LOG_LABEL_RE.fullmatch(label) is None
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_INVALID")
    return list(argv)


def _create_private_file(path: Path) -> int:
    try:
        return os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error


def _read_log(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_COMMAND_OUTPUT_BYTES
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED")
        return path.read_bytes()
    except CandidateBuildError:
        raise
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED"
        ) from error


def _allowed_change(path: str, *, installed_commit: str) -> bool:
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or "\n" in path
        or any(part in {"", ".", ".."} for part in Path(path).parts)
        or path in _FORBIDDEN_EXACT
        or path.startswith(_FORBIDDEN_PREFIXES)
    ):
        return False
    if path in _ALLOWED_EXACT:
        return True
    if (
        installed_commit == _PILOT_BASELINE_COMMIT
        and path in _PILOT_BASELINE_ALLOWED_EXACT
    ):
        return True
    if path.startswith("services/backend/") and path.endswith(".md"):
        return True
    if path.startswith("docs/") and path.endswith(".md"):
        return True
    return path.startswith(_ALLOWED_PREFIXES)


def _validate_restricted_diff(
    payload: bytes,
    *,
    installed_commit: str,
) -> tuple[str, ...]:
    if (
        not isinstance(payload, bytes)
        or not payload
        or payload[-1:] != b"\0"
        or COMMIT_RE.fullmatch(installed_commit) is None
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_DIFF_INVALID")
    values: list[str] = []
    try:
        for raw in payload[:-1].split(b"\0"):
            value = raw.decode("utf-8", "strict")
            if (
                not _allowed_change(value, installed_commit=installed_commit)
                or value in values
            ):
                _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_DIFF_INVALID")
            values.append(value)
    except UnicodeError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_DIFF_INVALID"
        ) from error
    if not values:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_DIFF_INVALID")
    return tuple(values)


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _document_digest(document: Mapping[str, Any], field: str) -> str:
    subject = dict(document)
    subject.pop(field, None)
    return _digest(_canonical_json(subject))


def _fsync_directory(path: Path) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        os.fsync(descriptor)
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _ensure_private_child(parent: Path, name: str) -> Path:
    if (
        not isinstance(name, str)
        or not name
        or "/" in name
        or name in {".", ".."}
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
    child = parent / name
    if child.parent != parent:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
    try:
        child.mkdir(mode=0o700)
        _fsync_directory(parent)
    except FileExistsError:
        pass
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error
    try:
        metadata = child.lstat()
        if (
            child.resolve(strict=True) != child
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error
    return child


def _open_build_lock(parent: Path) -> int:
    path = parent / BUILD_LOCK_FILE
    created = not path.exists() and not path.is_symlink()
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        metadata = os.fstat(descriptor)
        lexical = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or _metadata(metadata) != _metadata(lexical)
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
        if created:
            os.fsync(descriptor)
            _fsync_directory(parent)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise CandidateBuildError(
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_CONTENDED"
            ) from error
        return descriptor
    except CandidateBuildError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error


def _write_private(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    descriptor = _create_private_file(path)
    try:
        if mode != 0o600:
            os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
            view = view[written:]
        os.fsync(descriptor)
    except CandidateBuildError:
        raise
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _allocate_attempt(attempts: Path, inputs: BuildInputs) -> tuple[Path, int]:
    try:
        entries = {entry.name for entry in attempts.iterdir()}
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error
    sequences: list[int] = []
    for name in entries:
        match = ATTEMPT_RE.fullmatch(name)
        if match is None:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
        path = attempts / name
        _canonical_directory(path, private=True)
        sequences.append(int(match.group(1)))
    sequence = max(sequences, default=0) + 1
    if sequence > 999_999:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
    attempt = _ensure_private_child(attempts, f"attempt-{sequence:06d}")
    _ensure_private_child(attempt, JOURNAL_DIRECTORY)
    _ensure_private_child(attempt, LOGS_DIRECTORY)
    initial: dict[str, Any] = {
        "attempt": sequence,
        "candidate_commit": inputs.candidate_commit,
        "contract_version": BUILD_JOURNAL_CONTRACT,
        "installed_commit": inputs.installed_commit,
        "phase": "allocated",
        "previous_digest": None,
        "record_digest": "",
        "repository_identity": inputs.repository_identity,
        "sequence": 1,
    }
    initial["record_digest"] = _document_digest(initial, "record_digest")
    _write_private(
        attempt / JOURNAL_DIRECTORY / "000001.json",
        _canonical_json(initial),
    )
    return attempt, sequence


def _append_journal(
    attempt: Path,
    *,
    phase: str,
    details: Mapping[str, Any] | None = None,
) -> None:
    journal_directory = _canonical_directory(
        attempt / JOURNAL_DIRECTORY,
        private=True,
    )
    try:
        names = sorted(entry.name for entry in journal_directory.iterdir())
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error
    if not names or names != [f"{index:06d}.json" for index in range(1, len(names) + 1)]:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
    try:
        previous_payload, _previous_metadata = candidate._read_regular(
            journal_directory / names[-1],
            mode=0o600,
            maximum=MAX_JOURNAL_RECORD_BYTES,
        )
        previous = json.loads(previous_payload)
    except (candidate.CandidateError, OSError, json.JSONDecodeError) as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error
    if (
        not isinstance(previous, dict)
        or previous.get("record_digest")
        != _document_digest(previous, "record_digest")
        or previous_payload != _canonical_json(previous)
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
    sequence = len(names) + 1
    record: dict[str, Any] = {
        "contract_version": BUILD_JOURNAL_CONTRACT,
        "details": dict(details or {}),
        "phase": phase,
        "previous_digest": previous["record_digest"],
        "record_digest": "",
        "sequence": sequence,
    }
    record["record_digest"] = _document_digest(record, "record_digest")
    _write_private(
        journal_directory / f"{sequence:06d}.json",
        _canonical_json(record),
    )


def _cleanup_attempt_artifacts(attempt: Path) -> None:
    _canonical_directory(attempt, private=True)

    def repair_permissions(function: Callable[..., Any], value: str, _info: Any) -> None:
        path = Path(value)
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                function(value)
                return
            os.chmod(path, 0o700 if stat.S_ISDIR(metadata.st_mode) else 0o600)
            function(value)
        except OSError as error:
            raise CandidateBuildError(
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_CLEANUP_FAILED"
            ) from error

    try:
        for name in sorted(_CLEANUP_TARGETS):
            target = attempt / name
            if target.parent != attempt:
                _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_CLEANUP_FAILED")
            try:
                metadata = target.lstat()
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
            ):
                _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_CLEANUP_FAILED")
            for root, directories, _files in os.walk(
                target,
                topdown=True,
                followlinks=False,
            ):
                root_path = Path(root)
                root_metadata = root_path.lstat()
                if (
                    not stat.S_ISDIR(root_metadata.st_mode)
                    or stat.S_ISLNK(root_metadata.st_mode)
                    or root_metadata.st_uid != os.geteuid()
                ):
                    _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_CLEANUP_FAILED")
                root_path.chmod(0o700)
                directories[:] = [
                    name
                    for name in directories
                    if not (root_path / name).is_symlink()
                ]
            shutil.rmtree(target, onerror=repair_permissions)
            _fsync_directory(attempt)
    except CandidateBuildError:
        raise
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_CLEANUP_FAILED"
        ) from error


def _invoke(
    runner: Runner,
    commands: list[dict[str, Any]],
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    label: str,
    expected: frozenset[int] = frozenset({0}),
    umask: int = VERIFICATION_CHILD_UMASK,
) -> CommandResult:
    command = _validate_command(argv, cwd=cwd, env=env, timeout=timeout, label=label)
    child_umask = _validated_child_umask(umask)
    result = runner(
        command,
        cwd=cwd,
        env=dict(env),
        timeout=float(timeout),
        label=label,
        umask=child_umask,
    )
    if (
        not isinstance(result, CommandResult)
        or type(result.returncode) is not int
        or result.returncode not in expected
        or not isinstance(result.stdout, bytes)
        or not isinstance(result.stderr, bytes)
        or len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES
        or len(result.stderr) > MAX_COMMAND_OUTPUT_BYTES
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED")
    commands.append(
        {
            "argv": command,
            "cwd": str(cwd),
            "environment": {key: env[key] for key in sorted(env)},
            "label": label,
            "returncode": result.returncode,
            "stderr_digest": _digest(result.stderr),
            "stdout_digest": _digest(result.stdout),
            "timeout": float(timeout),
            "umask": child_umask,
        }
    )
    return result


def _single_line(
    result: CommandResult,
    pattern: re.Pattern[str],
    *,
    code: str,
) -> str:
    try:
        value = result.stdout.decode("ascii", "strict")
    except UnicodeError as error:
        raise CandidateBuildError(code) from error
    if not value.endswith("\n") or "\n" in value[:-1]:
        raise CandidateBuildError(code)
    value = value[:-1]
    if pattern.fullmatch(value) is None:
        raise CandidateBuildError(code)
    return value


def _git_environment(inputs: BuildInputs, home: Path) -> dict[str, str]:
    return {
        "GCM_INTERACTIVE": "Never",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": inputs.command_path,
    }


def _verification_environment(
    inputs: BuildInputs,
    manifest: Mapping[str, Any],
    attempt: Path,
) -> dict[str, str]:
    try:
        runtime = manifest["runtime"]
        home = str(runtime["home"])
        xdg = str(runtime["xdg_runtime_directory"])
        docker_host = str(runtime["docker_host"])
    except (KeyError, TypeError) as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID"
        ) from error
    if manifest.get("commands", {}).get("docker") != str(inputs.docker):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID")
    runtime_directory = _ensure_private_child(attempt, "runtime")
    return {
        "DOCKER_HOST": docker_host,
        "HOME": home,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": inputs.command_path,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONWARNINGS": "error",
        "RUNNER_TEMP": str(runtime_directory),
        "TMPDIR": str(runtime_directory),
        "XDG_RUNTIME_DIR": xdg,
    }


def _allocate_test_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            value = listener.getsockname()[1]
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED"
        ) from error
    if type(value) is not int or not 1024 <= value <= 65_535:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED")
    return value


def _parse_git_index(payload: bytes) -> tuple[tuple[str, int], ...]:
    if not isinstance(payload, bytes) or not payload or payload[-1:] != b"\0":
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID")
    records: list[tuple[str, int]] = []
    seen: set[str] = set()
    for raw in payload[:-1].split(b"\0"):
        match = GIT_MODE_RE.fullmatch(raw)
        if match is None:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID")
        try:
            path = match.group(3).decode("utf-8", "strict")
        except UnicodeError as error:
            raise CandidateBuildError(
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID"
            ) from error
        parts = Path(path).parts
        if (
            path in seen
            or not path
            or path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or "\n" in path
            or any(part in {"", ".", "..", ".git", "node_modules"} for part in parts)
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID")
        seen.add(path)
        records.append((path, 0o555 if match.group(1) == b"100755" else 0o444))
    if not records or records != sorted(records):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID")
    return tuple(records)


def _copy_tracked_file(source: Path, destination: Path, *, mode: int) -> dict[str, Any]:
    source_fd: int | None = None
    destination_fd: int | None = None
    try:
        lexical = source.lstat()
        source_fd = os.open(
            source,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(source_fd)
        if (
            not stat.S_ISREG(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or lexical.st_uid != os.geteuid()
            or lexical.st_nlink != 1
            or _metadata(lexical) != _metadata(opened)
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID")
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(source_fd, 65_536)
            if not block:
                break
            digest.update(block)
            size += len(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID")
                view = view[written:]
        after = os.fstat(source_fd)
        current = source.lstat()
        if _metadata(after) != _metadata(opened) or _metadata(current) != _metadata(opened):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID")
        os.fchmod(destination_fd, mode)
        os.fsync(destination_fd)
        return {
            "digest": f"sha256:{digest.hexdigest()}",
            "mode": mode,
            "path": str(destination),
            "size": size,
        }
    except CandidateBuildError:
        raise
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID"
        ) from error
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)


def _materialize_source(
    checkout: Path,
    source: Path,
    index: Sequence[tuple[str, int]],
) -> list[dict[str, Any]]:
    try:
        source.mkdir(mode=0o700)
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID"
        ) from error
    directories: set[Path] = {source}
    manifest_records: list[dict[str, Any]] = []
    for relative, mode in index:
        relative_path = Path(relative)
        destination = source / relative_path
        if destination.parent != source and source not in destination.parents:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID")
        missing: list[Path] = []
        cursor = destination.parent
        while cursor not in directories:
            if cursor == source or source not in cursor.parents:
                _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID")
            missing.append(cursor)
            cursor = cursor.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
            directories.add(directory)
        record = _copy_tracked_file(checkout / relative_path, destination, mode=mode)
        record["path"] = relative
        manifest_records.append(record)
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(directory)
        try:
            directory.chmod(0o555)
        except OSError as error:
            raise CandidateBuildError(
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID"
            ) from error
        _fsync_directory(directory)
    if [record["path"] for record in manifest_records] != sorted(
        record["path"] for record in manifest_records
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TREE_INVALID")
    return manifest_records


def _source_manifest(
    inputs: BuildInputs,
    files: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    normalized = [dict(record) for record in files]
    paths = [record["path"] for record in normalized]
    # The sealed release retains the complete exact Git tree.  Binding the full
    # set as the runtime closure is conservative and covers dynamic imports,
    # package data, schemas, and repository-root inference without heuristics.
    closure_entries = [dict(record) for record in normalized]
    closure = {
        "closure_digest": _digest(_canonical_json(closure_entries)),
        "files": paths,
    }
    manifest: dict[str, Any] = {
        "candidate_commit": inputs.candidate_commit,
        "contract_version": candidate.SOURCE_MANIFEST_CONTRACT,
        "files": normalized,
        "manifest_digest": "",
        "repository_identity": inputs.repository_identity,
        "runtime_closure": closure,
        "tree_digest": _digest(_canonical_json(normalized)),
    }
    manifest["manifest_digest"] = _document_digest(manifest, "manifest_digest")
    return manifest


def _read_source_compose(
    source_state: Path,
) -> tuple[dict[str, Any], dict[str, Any], Path, bytes, dict[str, Any]]:
    try:
        desired, manifest, compose = reconciler._load_bound_state(source_state)
        payload = reconciler._read_private(
            compose,
            mode=0o400,
            code="REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID",
        )
        document = reconciler._parse_json(
            payload,
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID",
        )
    except (OSError, reconciler.ReconcileError) as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID"
        ) from error
    if (
        desired.get("desired") != "running"
        or not isinstance(document, dict)
        or desired.get("compose_digest") != _digest(payload)
        or manifest.get("compose_digest") != desired.get("compose_digest")
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID")
    return desired, manifest, compose, payload, document


def _root_for_suffix(path: Path, suffix: Path) -> Path:
    if not path.is_absolute() or not suffix.parts or suffix.is_absolute():
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
    cursor = path
    for expected in reversed(suffix.parts):
        if cursor.name != expected:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
        cursor = cursor.parent
    if cursor == Path("/"):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
    return cursor


def _compose_source_authority(source: Mapping[str, Any]) -> Path:
    """Return the one exact source root referenced by the sealed Compose file."""

    try:
        ingress = source["configs"]["tacua_loopback_ingress"]["file"]
    except (KeyError, TypeError) as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID"
        ) from error
    if not isinstance(ingress, str):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
    authority_root = _root_for_suffix(
        Path(ingress),
        Path("services/backend/ingress/haproxy.cfg"),
    )
    try:
        services = source["services"]
    except (KeyError, TypeError) as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID"
        ) from error
    if not isinstance(services, Mapping):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
    for service in ("backend", "reviewer"):
        service_document = services.get(service)
        if not isinstance(service_document, Mapping):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
        build = service_document.get("build")
        if build is None:
            continue
        if not isinstance(build, Mapping) or not isinstance(build.get("context"), str):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
        if Path(build["context"]) != authority_root:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
    return authority_root


def _source_authority(
    inputs: BuildInputs,
    source: Mapping[str, Any],
) -> Path:
    """Validate the current source root without conflating it with Git lineage."""

    authority_root = _compose_source_authority(source)
    managed_releases = inputs.preparations_parent / RELEASES_DIRECTORY
    if authority_root == inputs.installed_repository:
        if (
            authority_root == managed_releases
            or managed_releases in authority_root.parents
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID")
        return authority_root
    release = authority_root.parent
    if (
        authority_root.name != candidate.SOURCE_DIRECTORY
        or release.parent != managed_releases
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID")
    try:
        prepared = candidate.load_prepared_release(
            release,
            expected_commit=inputs.installed_commit,
            expected_repository_identity=inputs.repository_identity,
        )
    except candidate.CandidateError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID"
        ) from error
    if prepared.repository != authority_root:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID")
    return authority_root


def _candidate_compose(
    source: Mapping[str, Any],
    *,
    source_authority: Path,
    source_repository: Path,
    reviewer_image: str,
) -> dict[str, Any]:
    if (
        not isinstance(reviewer_image, str)
        or not reviewer_image.startswith("tacua-reviewer-web:")
        or reviewer_image.endswith(":latest")
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
    candidate_document = deepcopy(source)
    try:
        old_reviewer = source["services"]["reviewer"]["image"]
    except (KeyError, TypeError) as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID"
        ) from error
    if not isinstance(old_reviewer, str) or old_reviewer == reviewer_image:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
    ingress_suffix = Path("services/backend/ingress/haproxy.cfg")
    authority_root = _compose_source_authority(source)
    if authority_root != source_authority:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
    candidate_document["services"]["reviewer"]["image"] = reviewer_image
    for service in ("backend", "reviewer"):
        build = source.get("services", {}).get(service, {}).get("build")
        if build is None:
            continue
        candidate_document["services"][service]["build"]["context"] = str(
            source_repository
        )
    candidate_document["configs"]["tacua_loopback_ingress"]["file"] = str(
        source_repository / ingress_suffix
    )
    expected = deepcopy(source)
    expected["services"]["reviewer"]["image"] = reviewer_image
    for service in ("backend", "reviewer"):
        if expected.get("services", {}).get(service, {}).get("build") is not None:
            expected["services"][service]["build"]["context"] = str(
                source_repository
            )
    expected["configs"]["tacua_loopback_ingress"]["file"] = str(
        source_repository / ingress_suffix
    )
    if candidate_document != expected:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_COMPOSE_INVALID")
    return candidate_document


def _tool_bindings(inputs: BuildInputs) -> dict[str, dict[str, Any]]:
    return {
        "bash": _canonical_tool(inputs.bash, executable=True),
        "docker": _canonical_tool(inputs.docker, executable=True),
        "git": _canonical_tool(inputs.git, executable=True),
        "node": _canonical_tool(inputs.node, executable=True),
        "npm_cli": _canonical_tool(inputs.npm_cli, executable=False),
        "python": _canonical_tool(inputs.python, executable=True),
    }


def _git_preflight_and_checkout(
    inputs: BuildInputs,
    attempt: Path,
    runner: Runner,
    commands: list[dict[str, Any]],
    home: Path,
) -> tuple[Path, tuple[tuple[str, int], ...], tuple[str, ...]]:
    environment = _git_environment(inputs, home)
    installed = inputs.installed_repository
    result = _invoke(
        runner,
        commands,
        [str(inputs.git), "-C", str(installed), "rev-parse", "--show-toplevel"],
        cwd=installed,
        env=environment,
        timeout=30,
        label="installed-root",
    )
    if result.stdout != f"{installed}\n".encode():
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID")
    result = _invoke(
        runner,
        commands,
        [str(inputs.git), "-C", str(installed), "rev-parse", "HEAD"],
        cwd=installed,
        env=environment,
        timeout=30,
        label="installed-head",
    )
    if _single_line(
        result,
        COMMIT_RE,
        code="REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID",
    ) != inputs.installed_commit:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID")
    result = _invoke(
        runner,
        commands,
        [
            str(inputs.git),
            "-C",
            str(installed),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        cwd=installed,
        env=environment,
        timeout=30,
        label="installed-clean",
    )
    if result.stdout:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID")
    result = _invoke(
        runner,
        commands,
        [str(inputs.git), "-C", str(installed), "remote", "get-url", "origin"],
        cwd=installed,
        env=environment,
        timeout=30,
        label="installed-origin",
    )
    try:
        installed_origin = result.stdout.decode("ascii", "strict")
    except UnicodeError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID"
        ) from error
    if (
        not installed_origin.endswith("\n")
        or "\n" in installed_origin[:-1]
        or installed_origin[:-1] not in inputs.installed_origin_urls
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID")

    checkout = attempt / BUILD_SOURCE_DIRECTORY
    if checkout.exists() or checkout.is_symlink():
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
    _invoke(
        runner,
        commands,
        [
            str(inputs.git),
            "clone",
            "--no-checkout",
            "--no-hardlinks",
            "--origin",
            "origin",
            inputs.repository_url,
            str(checkout),
        ],
        cwd=attempt,
        env=environment,
        timeout=900,
        label="candidate-clone",
    )
    _canonical_directory(checkout, private=False)
    result = _invoke(
        runner,
        commands,
        [str(inputs.git), "-C", str(checkout), "remote", "get-url", "origin"],
        cwd=checkout,
        env=environment,
        timeout=30,
        label="candidate-origin",
    )
    if result.stdout != f"{inputs.repository_url}\n".encode():
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID")
    _invoke(
        runner,
        commands,
        [
            str(inputs.git),
            "-C",
            str(checkout),
            "fetch",
            "--no-tags",
            "--force",
            "origin",
            "main",
        ],
        cwd=checkout,
        env=environment,
        timeout=900,
        label="candidate-fetch",
    )
    result = _invoke(
        runner,
        commands,
        [str(inputs.git), "-C", str(checkout), "rev-parse", "FETCH_HEAD"],
        cwd=checkout,
        env=environment,
        timeout=30,
        label="candidate-fetch-head",
    )
    if _single_line(
        result,
        COMMIT_RE,
        code="REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID",
    ) != inputs.candidate_commit:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID")
    _invoke(
        runner,
        commands,
        [
            str(inputs.git),
            "-C",
            str(checkout),
            "cat-file",
            "-e",
            f"{inputs.candidate_commit}^{{commit}}",
        ],
        cwd=checkout,
        env=environment,
        timeout=30,
        label="candidate-commit",
    )
    _invoke(
        runner,
        commands,
        [
            str(inputs.git),
            "-C",
            str(checkout),
            "checkout",
            "--detach",
            inputs.candidate_commit,
        ],
        cwd=checkout,
        env=environment,
        timeout=120,
        label="candidate-checkout",
    )
    result = _invoke(
        runner,
        commands,
        [str(inputs.git), "-C", str(checkout), "rev-parse", "HEAD"],
        cwd=checkout,
        env=environment,
        timeout=30,
        label="candidate-head",
    )
    if _single_line(
        result,
        COMMIT_RE,
        code="REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID",
    ) != inputs.candidate_commit:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID")
    _invoke(
        runner,
        commands,
        [
            str(inputs.git),
            "-C",
            str(checkout),
            "merge-base",
            "--is-ancestor",
            inputs.installed_commit,
            inputs.candidate_commit,
        ],
        cwd=checkout,
        env=environment,
        timeout=30,
        label="candidate-lineage",
    )
    for arguments, label in (
        (("diff", "--quiet"), "candidate-worktree-clean"),
        (("diff", "--cached", "--quiet"), "candidate-index-clean"),
    ):
        _invoke(
            runner,
            commands,
            [str(inputs.git), "-C", str(checkout), *arguments],
            cwd=checkout,
            env=environment,
            timeout=60,
            label=label,
        )
    result = _invoke(
        runner,
        commands,
        [
            str(inputs.git),
            "-C",
            str(checkout),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        cwd=checkout,
        env=environment,
        timeout=60,
        label="candidate-untracked-clean",
    )
    if result.stdout:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID")
    result = _invoke(
        runner,
        commands,
        [
            str(inputs.git),
            "-C",
            str(checkout),
            "diff",
            "--name-only",
            "-z",
            inputs.installed_commit,
            inputs.candidate_commit,
        ],
        cwd=checkout,
        env=environment,
        timeout=120,
        label="candidate-restricted-diff",
    )
    changes = _validate_restricted_diff(
        result.stdout,
        installed_commit=inputs.installed_commit,
    )
    result = _invoke(
        runner,
        commands,
        [str(inputs.git), "-C", str(checkout), "ls-files", "--stage", "-z"],
        cwd=checkout,
        env=environment,
        timeout=120,
        label="candidate-index",
    )
    return checkout, _parse_git_index(result.stdout), changes


def _reprove_installed_repository(
    inputs: BuildInputs,
    runner: Runner,
    commands: list[dict[str, Any]],
    home: Path,
) -> None:
    environment = _git_environment(inputs, home)
    result = _invoke(
        runner,
        commands,
        [str(inputs.git), "-C", str(inputs.installed_repository), "rev-parse", "HEAD"],
        cwd=inputs.installed_repository,
        env=environment,
        timeout=30,
        label="installed-head-reproof",
    )
    if _single_line(
        result,
        COMMIT_RE,
        code="REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID",
    ) != inputs.installed_commit:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID")
    result = _invoke(
        runner,
        commands,
        [
            str(inputs.git),
            "-C",
            str(inputs.installed_repository),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        cwd=inputs.installed_repository,
        env=environment,
        timeout=60,
        label="installed-clean-reproof",
    )
    if result.stdout:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_REPOSITORY_INVALID")


def _run_verification(
    inputs: BuildInputs,
    manifest: Mapping[str, Any],
    attempt: Path,
    attempt_number: int,
    checkout: Path,
    runner: Runner,
    commands: list[dict[str, Any]],
) -> tuple[str, str]:
    environment = _verification_environment(inputs, manifest, attempt)
    backend_environment = dict(environment)
    reviewer = "apps/reviewer"
    npm = [str(inputs.node), str(inputs.npm_cli), "--prefix", reviewer]
    result = _invoke(
        runner,
        commands,
        [str(inputs.node), "--version"],
        cwd=checkout,
        env=environment,
        timeout=30,
        label="node-version",
    )
    if result.stdout != f"{REQUIRED_NODE_VERSION}\n".encode():
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TOOL_VERSION_INVALID")
    result = _invoke(
        runner,
        commands,
        [str(inputs.node), str(inputs.npm_cli), "--version"],
        cwd=checkout,
        env=environment,
        timeout=30,
        label="npm-version",
    )
    if result.stdout != f"{REQUIRED_NPM_VERSION}\n".encode():
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_TOOL_VERSION_INVALID")
    _invoke(
        runner,
        commands,
        [
            str(inputs.python),
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            "services/backend/tests",
            "-v",
        ],
        cwd=checkout,
        env=backend_environment,
        timeout=1_800,
        label="backend-tests",
    )
    for argv, timeout, label in (
        (
            (*npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund"),
            1_200,
            "reviewer-npm-ci",
        ),
        (
            (
                str(inputs.node),
                ".github/scripts/generate-reviewer-third-party-notices.mjs",
            ),
            300,
            "reviewer-notices",
        ),
        ((*npm, "test"), 900, "reviewer-tests"),
        (
            (*npm, "run", "typecheck"),
            900,
            "reviewer-typecheck",
        ),
        (
            (
                *npm,
                "run",
                "export:ios",
                "--",
                "--output-dir",
                str(attempt / "ios-export"),
                "--clear",
            ),
            1_200,
            "reviewer-export-ios",
        ),
        (
            (*npm, "run", "export:web", "--", "--output-dir", "dist", "--clear"),
            1_200,
            "reviewer-export-web",
        ),
        (
            (
                str(inputs.node),
                "--test",
                ".github/scripts/validate-reviewer-web-image-inputs.test.mjs",
            ),
            600,
            "reviewer-validator-tests",
        ),
        (
            (
                str(inputs.node),
                ".github/scripts/validate-reviewer-web-image-inputs.mjs",
            ),
            300,
            "reviewer-validator",
        ),
        (
            (
                str(inputs.python),
                "-B",
                "-m",
                "unittest",
                "discover",
                "-s",
                "services/reviewer-web/tests",
                "-v",
            ),
            900,
            "reviewer-web-tests",
        ),
    ):
        _invoke(
            runner,
            commands,
            argv,
            cwd=checkout,
            env=environment,
            timeout=timeout,
            label=label,
        )
    test_id = f"qa-{inputs.candidate_commit[:10]}-{attempt_number:06d}"
    if TEST_ID_RE.fullmatch(test_id) is None:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_IMAGE_INVALID")
    reviewer_image = f"tacua-reviewer-web:{test_id}"
    backend_image = f"tacua-backend:{test_id}"
    for image, label in (
        (reviewer_image, "reviewer-image-absent"),
        (backend_image, "backend-image-absent"),
    ):
        result = _invoke(
            runner,
            commands,
            [
                str(inputs.docker),
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                image,
            ],
            cwd=checkout,
            env=environment,
            timeout=30,
            label=label,
            expected=frozenset(range(0, 126)),
        )
        if result.returncode == 0:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_IMAGE_CONFLICT")
    verifier_environment = dict(environment)
    verifier_environment.update(
        {
            "TACUA_CONTAINER_TEST_ID": test_id,
            "TACUA_CONTAINER_TEST_PORT": str(_allocate_test_port()),
            "TACUA_KEEP_VERIFIED_IMAGES": "true",
        }
    )
    _invoke(
        runner,
        commands,
        [str(inputs.bash), ".github/scripts/verify-backend-container.sh"],
        cwd=checkout,
        env=verifier_environment,
        timeout=3_600,
        label="isolated-container-verification",
    )
    result = _invoke(
        runner,
        commands,
        [
            str(inputs.docker),
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            reviewer_image,
        ],
        cwd=checkout,
        env=environment,
        timeout=30,
        label="reviewer-image-id",
    )
    image_id = _single_line(
        result,
        IMAGE_ID_RE,
        code="REVIEWER_UPGRADE_CANDIDATE_BUILD_IMAGE_INVALID",
    )
    for arguments, label in (
        (("diff", "--quiet"), "verified-worktree-clean"),
        (("diff", "--cached", "--quiet"), "verified-index-clean"),
    ):
        _invoke(
            runner,
            commands,
            [str(inputs.git), "-C", str(checkout), *arguments],
            cwd=checkout,
            env=_git_environment(inputs, Path(manifest["runtime"]["home"])),
            timeout=60,
            label=label,
        )
    return reviewer_image, image_id


def _reinspect_image(
    inputs: BuildInputs,
    manifest: Mapping[str, Any],
    attempt: Path,
    checkout: Path,
    image: str,
    expected_id: str,
    runner: Runner,
    commands: list[dict[str, Any]],
) -> None:
    result = _invoke(
        runner,
        commands,
        [
            str(inputs.docker),
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            image,
        ],
        cwd=checkout,
        env=_verification_environment(inputs, manifest, attempt),
        timeout=30,
        label="reviewer-image-reproof",
    )
    if _single_line(
        result,
        IMAGE_ID_RE,
        code="REVIEWER_UPGRADE_CANDIDATE_BUILD_IMAGE_INVALID",
    ) != expected_id:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_IMAGE_REBOUND")


def _release_generation_id(
    inputs: BuildInputs,
    source_manifest: Mapping[str, Any],
    source_compose_path: Path,
    source_compose_payload: bytes,
    tools: Mapping[str, Mapping[str, Any]],
) -> str:
    try:
        return candidate.release_generation_id(
            candidate_commit=inputs.candidate_commit,
            installed_commit=inputs.installed_commit,
            repository_identity=inputs.repository_identity,
            tree_digest_value=source_manifest["tree_digest"],
            source_compose_path=str(source_compose_path),
            source_compose_digest=_digest(source_compose_payload),
            tools={name: dict(binding) for name, binding in tools.items()},
        )
    except (KeyError, TypeError, candidate.CandidateError) as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error


def _matching_existing_release(
    release: Path,
    inputs: BuildInputs,
    source_compose_path: Path,
    source_compose_digest: str,
    tools: Mapping[str, Mapping[str, Any]],
) -> candidate.PreparedRelease:
    _repair_pending_release_mode(
        release,
        inputs,
        source_compose_path,
        source_compose_digest,
        tools,
    )
    try:
        prepared = candidate.load_prepared_release(
            release,
            expected_commit=inputs.candidate_commit,
            expected_repository_identity=inputs.repository_identity,
        )
    except Exception as error:
        candidate_error = getattr(candidate, "CandidateError", ())
        if candidate_error and isinstance(error, candidate_error):
            raise CandidateBuildError(
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_CONFLICT"
            ) from error
        raise
    receipt = prepared.receipt
    if (
        receipt.get("installed_commit") != inputs.installed_commit
        or receipt.get("source_compose", {}).get("digest")
        != source_compose_digest
        or receipt.get("source_compose", {}).get("path")
        != str(source_compose_path)
        or receipt.get("tools")
        != {name: dict(binding) for name, binding in tools.items()}
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_CONFLICT")
    return prepared


def _repair_pending_release_mode(
    release: Path,
    inputs: BuildInputs,
    source_compose_path: Path,
    source_compose_digest: str,
    tools: Mapping[str, Mapping[str, Any]],
) -> None:
    """Finish only the one unavoidable directory-rename crash state.

    macOS and some hardened filesystems refuse to rename a mode-0500
    directory.  Publication therefore durably renames the complete mode-0700
    staging directory and then removes its write bits.  This routine proves
    the exact self-digested generation evidence and inode before completing
    that final chmod after a crash.
    """

    try:
        metadata = release.lstat()
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_CONFLICT"
        ) from error
    mode = stat.S_IMODE(metadata.st_mode)
    if mode == 0o500:
        return
    if (
        mode != 0o700
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or release.parent.name != RELEASES_DIRECTORY
        or re.fullmatch(r"[a-f0-9]{64}", release.name) is None
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_CONFLICT")
    try:
        names = {entry.name for entry in release.iterdir()}
        if names != {
            candidate.SOURCE_DIRECTORY,
            candidate.SOURCE_MANIFEST_FILE,
            candidate.CANDIDATE_COMPOSE_FILE,
            candidate.PREPARATION_RECEIPT_FILE,
        }:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_CONFLICT")
        manifest_payload, _manifest_metadata = candidate._read_regular(
            release / candidate.SOURCE_MANIFEST_FILE,
            mode=0o400,
            maximum=candidate.MAX_MANIFEST_BYTES,
        )
        manifest, _manifest_files = candidate._validate_manifest(
            candidate.parse_canonical_json(
                manifest_payload,
                maximum=candidate.MAX_MANIFEST_BYTES,
            )
        )
        receipt_payload, _receipt_metadata = candidate._read_regular(
            release / candidate.PREPARATION_RECEIPT_FILE,
            mode=0o400,
            maximum=candidate.MAX_RECEIPT_BYTES,
        )
        receipt = candidate.parse_canonical_json(
            receipt_payload,
            maximum=candidate.MAX_RECEIPT_BYTES,
        )
        compose_payload, _compose_metadata = candidate._read_regular(
            release / candidate.CANDIDATE_COMPOSE_FILE,
            mode=0o600,
            maximum=candidate.MAX_COMPOSE_BYTES,
        )
        binding = receipt.get("release_binding", {})
        if (
            set(receipt) != set(candidate._RECEIPT_KEYS)
            or receipt.get("contract_version")
            != candidate.PREPARATION_RECEIPT_CONTRACT
            or receipt.get("receipt_digest")
            != candidate.document_digest(receipt, "receipt_digest")
            or receipt.get("generation_id") != release.name
            or receipt.get("candidate_commit") != inputs.candidate_commit
            or receipt.get("installed_commit") != inputs.installed_commit
            or receipt.get("repository_identity") != inputs.repository_identity
            or receipt.get("source_manifest_digest")
            != manifest.get("manifest_digest")
            or manifest.get("candidate_commit") != inputs.candidate_commit
            or manifest.get("repository_identity") != inputs.repository_identity
            or candidate.release_generation_id(
                candidate_commit=receipt.get("candidate_commit"),
                installed_commit=receipt.get("installed_commit"),
                repository_identity=receipt.get("repository_identity"),
                tree_digest_value=manifest.get("tree_digest"),
                source_compose_path=receipt.get("source_compose", {}).get("path"),
                source_compose_digest=receipt.get("source_compose", {}).get(
                    "digest"
                ),
                tools=receipt.get("tools"),
            )
            != release.name
            or binding
            != {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "mode": 0o500,
            }
            or receipt.get("source_compose", {}).get("digest")
            != source_compose_digest
            or receipt.get("source_compose", {}).get("path")
            != str(source_compose_path)
            or receipt.get("tools")
            != {name: dict(binding) for name, binding in tools.items()}
            or receipt.get("candidate_compose", {}).get("digest")
            != candidate.digest(compose_payload)
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_CONFLICT")
        repository_metadata = (release / candidate.SOURCE_DIRECTORY).lstat()
        if (
            not stat.S_ISDIR(repository_metadata.st_mode)
            or stat.S_ISLNK(repository_metadata.st_mode)
            or repository_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(repository_metadata.st_mode) != 0o555
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_CONFLICT")
        release.chmod(0o500)
        _fsync_directory(release)
        _fsync_directory(release.parent)
    except CandidateBuildError:
        raise
    except candidate.CandidateError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_CONFLICT"
        ) from error
    except (OSError, TypeError, ValueError) as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_CONFLICT"
        ) from error


def _publish_release(
    inputs: BuildInputs,
    attempt: Path,
    attempt_number: int,
    staged_release: Path,
    releases: Path,
    source_manifest: Mapping[str, Any],
    source_compose_path: Path,
    source_compose_payload: bytes,
    source_compose_document: Mapping[str, Any],
    source_authority: Path,
    reviewer_image: str,
    reviewer_image_id: str,
    tools: Mapping[str, Mapping[str, Any]],
    commands: Sequence[Mapping[str, Any]],
) -> candidate.PreparedRelease:
    generation_id = _release_generation_id(
        inputs,
        source_manifest,
        source_compose_path,
        source_compose_payload,
        tools,
    )
    release = releases / generation_id
    if release.parent != releases:
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
    if release.exists() or release.is_symlink():
        return _matching_existing_release(
            release,
            inputs,
            source_compose_path,
            _digest(source_compose_payload),
            tools,
        )
    source_repository = release / candidate.SOURCE_DIRECTORY
    compose_document = _candidate_compose(
        source_compose_document,
        source_authority=source_authority,
        source_repository=source_repository,
        reviewer_image=reviewer_image,
    )
    compose_payload = _canonical_json(compose_document)
    _write_private(
        staged_release / candidate.SOURCE_MANIFEST_FILE,
        _canonical_json(source_manifest),
        mode=0o400,
    )
    _write_private(
        staged_release / candidate.CANDIDATE_COMPOSE_FILE,
        compose_payload,
        mode=0o600,
    )
    try:
        release_metadata = staged_release.lstat()
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error
    test_id = reviewer_image.split(":", 1)[1]
    receipt: dict[str, Any] = {
        "candidate_commit": inputs.candidate_commit,
        "candidate_compose": {
            "digest": _digest(compose_payload),
            "mode": 0o600,
            "path": candidate.CANDIDATE_COMPOSE_FILE,
        },
        "contract_version": candidate.PREPARATION_RECEIPT_CONTRACT,
        "generation_id": generation_id,
        "installed_commit": inputs.installed_commit,
        "receipt_digest": "",
        "release_binding": {
            "device": release_metadata.st_dev,
            "inode": release_metadata.st_ino,
            "mode": 0o500,
        },
        "repository_identity": inputs.repository_identity,
        "reviewer_image": {"id": reviewer_image_id, "ref": reviewer_image},
        "source_compose": {
            "digest": _digest(source_compose_payload),
            "mode": 0o400,
            "path": str(source_compose_path),
        },
        "source_manifest_digest": source_manifest["manifest_digest"],
        "status": "verified",
        "tools": {name: dict(binding) for name, binding in tools.items()},
        "verification": {
            "attempt_id": f"attempt-{attempt_number:06d}",
            "commands_digest": _digest(_canonical_json(list(commands))),
            "status": "verified",
        },
    }
    commands_payload = _canonical_json(list(commands))
    _write_private(attempt / COMMANDS_FILE, commands_payload)
    if receipt["verification"]["commands_digest"] != _digest(commands_payload):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
    receipt["receipt_digest"] = _document_digest(receipt, "receipt_digest")
    _write_private(
        staged_release / candidate.PREPARATION_RECEIPT_FILE,
        _canonical_json(receipt),
        mode=0o400,
    )
    try:
        entries = {entry.name for entry in staged_release.iterdir()}
        if entries != {
            candidate.SOURCE_DIRECTORY,
            candidate.SOURCE_MANIFEST_FILE,
            candidate.CANDIDATE_COMPOSE_FILE,
            candidate.PREPARATION_RECEIPT_FILE,
        }:
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID")
        _fsync_directory(staged_release)
        if release.exists() or release.is_symlink():
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_CONFLICT")
        os.rename(staged_release, release)
        _fsync_directory(releases)
        release.chmod(0o500)
        _fsync_directory(release)
        _fsync_directory(releases)
    except CandidateBuildError:
        raise
    except OSError as error:
        raise CandidateBuildError(
            "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
        ) from error
    prepared = candidate.load_prepared_release(
        release,
        expected_commit=inputs.candidate_commit,
        expected_repository_identity=inputs.repository_identity,
    )
    if prepared.receipt != receipt or prepared.source_manifest != dict(source_manifest):
        _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_INVALID")
    _append_journal(
        attempt,
        phase="published",
        details={
            "generation_id": generation_id,
            "receipt_digest": receipt["receipt_digest"],
            "source_manifest_digest": source_manifest["manifest_digest"],
            "verification_commands_digest": receipt["verification"]["commands_digest"],
        },
    )
    return prepared


def build_prepared_release(
    inputs: BuildInputs,
    *,
    runner: Runner | None = None,
) -> candidate.PreparedRelease:
    """Produce and revalidate one content-addressed prepared release."""

    os.umask(PRIVATE_PROCESS_UMASK)
    inputs.validate()
    initial_desired, manifest, source_compose_path, source_compose_payload, source_compose = (
        _read_source_compose(inputs.source_state_directory)
    )
    source_authority = _source_authority(inputs, source_compose)
    attempts = _ensure_private_child(inputs.preparations_parent, ATTEMPTS_DIRECTORY)
    releases = _ensure_private_child(inputs.preparations_parent, RELEASES_DIRECTORY)
    lock = _open_build_lock(inputs.preparations_parent)
    try:
        # Reprove the mutable sealed selector after serialization.  Candidate
        # preparation never writes this tree.
        (
            locked_desired,
            locked_manifest,
            locked_compose_path,
            locked_compose_payload,
            locked_compose,
        ) = _read_source_compose(inputs.source_state_directory)
        if (
            locked_desired != initial_desired
            or locked_manifest != manifest
            or locked_compose_path != source_compose_path
            or locked_compose_payload != source_compose_payload
            or locked_compose != source_compose
            or _source_authority(inputs, locked_compose) != source_authority
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID")
        tools = _tool_bindings(inputs)
        attempt, attempt_number = _allocate_attempt(attempts, inputs)
        selected_runner = runner or SubprocessRunner(attempt / LOGS_DIRECTORY)
        commands: list[dict[str, Any]] = []
        try:
            home = Path(manifest["runtime"]["home"])
        except (KeyError, TypeError) as error:
            raise CandidateBuildError(
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID"
            ) from error
        checkout, index, changes = _git_preflight_and_checkout(
            inputs,
            attempt,
            selected_runner,
            commands,
            home,
        )
        _append_journal(
            attempt,
            phase="source_verified",
            details={"changed_paths_digest": _digest(_canonical_json(list(changes)))},
        )
        staged_release = attempt / STAGED_RELEASE_DIRECTORY
        try:
            staged_release.mkdir(mode=0o700)
        except OSError as error:
            raise CandidateBuildError(
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_EVIDENCE_INVALID"
            ) from error
        files = _materialize_source(
            checkout,
            staged_release / candidate.SOURCE_DIRECTORY,
            index,
        )
        source_manifest = _source_manifest(inputs, files)
        _append_journal(
            attempt,
            phase="tree_materialized",
            details={
                "source_manifest_digest": source_manifest["manifest_digest"],
                "tree_digest": source_manifest["tree_digest"],
            },
        )
        existing_release = releases / _release_generation_id(
            inputs,
            source_manifest,
            source_compose_path,
            source_compose_payload,
            tools,
        )
        if existing_release.exists() or existing_release.is_symlink():
            prepared = _matching_existing_release(
                existing_release,
                inputs,
                source_compose_path,
                _digest(source_compose_payload),
                tools,
            )
            _reinspect_image(
                inputs,
                manifest,
                attempt,
                checkout,
                prepared.receipt["reviewer_image"]["ref"],
                prepared.receipt["reviewer_image"]["id"],
                selected_runner,
                commands,
            )
            (
                existing_desired,
                existing_manifest,
                existing_compose_path,
                existing_compose_payload,
                existing_compose,
            ) = _read_source_compose(inputs.source_state_directory)
            if (
                existing_desired != initial_desired
                or existing_manifest != manifest
                or existing_compose_path != source_compose_path
                or existing_compose_payload != source_compose_payload
                or existing_compose != source_compose
                or _source_authority(inputs, existing_compose) != source_authority
                or _tool_bindings(inputs) != tools
            ):
                _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID")
            _reprove_installed_repository(
                inputs,
                selected_runner,
                commands,
                home,
            )
            _append_journal(
                attempt,
                phase="existing_release_revalidated",
                details={"generation_id": prepared.receipt["generation_id"]},
            )
            _cleanup_attempt_artifacts(attempt)
            _append_journal(attempt, phase="cleanup_complete")
            return prepared
        reviewer_image, reviewer_image_id = _run_verification(
            inputs,
            manifest,
            attempt,
            attempt_number,
            checkout,
            selected_runner,
            commands,
        )
        _append_journal(
            attempt,
            phase="verification_succeeded",
            details={
                "reviewer_image_id": reviewer_image_id,
                "reviewer_image_ref": reviewer_image,
            },
        )
        _reinspect_image(
            inputs,
            manifest,
            attempt,
            checkout,
            reviewer_image,
            reviewer_image_id,
            selected_runner,
            commands,
        )
        (
            _final_desired,
            final_manifest,
            final_compose_path,
            final_compose_payload,
            final_compose,
        ) = _read_source_compose(inputs.source_state_directory)
        if (
            _final_desired != initial_desired
            or final_manifest != manifest
            or final_compose_path != source_compose_path
            or final_compose_payload != source_compose_payload
            or final_compose != source_compose
            or _source_authority(inputs, final_compose) != source_authority
            or _tool_bindings(inputs) != tools
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID")
        _reprove_installed_repository(
            inputs,
            selected_runner,
            commands,
            home,
        )
        prepared = _publish_release(
            inputs,
            attempt,
            attempt_number,
            staged_release,
            releases,
            source_manifest,
            source_compose_path,
            source_compose_payload,
            source_compose,
            source_authority,
            reviewer_image,
            reviewer_image_id,
            tools,
            commands,
        )
        _cleanup_attempt_artifacts(attempt)
        _append_journal(attempt, phase="cleanup_complete")
        return prepared
    finally:
        try:
            fcntl.flock(lock, fcntl.LOCK_UN)
        finally:
            os.close(lock)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    for name in (
        "installed-repository",
        "source-state-directory",
        "preparations-parent",
        "git",
        "python",
        "node",
        "npm-cli",
        "docker",
        "bash",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--installed-commit", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--repository-identity", required=True)
    parser.add_argument("--command-path", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(PRIVATE_PROCESS_UMASK)
    try:
        args = _parser().parse_args(argv)
        prepared = build_prepared_release(
            BuildInputs(
                installed_repository=args.installed_repository,
                installed_commit=args.installed_commit,
                candidate_commit=args.candidate_commit,
                source_state_directory=args.source_state_directory,
                preparations_parent=args.preparations_parent,
                repository_identity=args.repository_identity,
                git=args.git,
                python=args.python,
                node=args.node,
                npm_cli=args.npm_cli,
                docker=args.docker,
                bash=args.bash,
                command_path=args.command_path,
            )
        )
        receipt = prepared.receipt
        result = {
            "candidate_commit": receipt["candidate_commit"],
            "code": BUILD_CODE,
            "generation_id": receipt["generation_id"],
            "receipt_digest": receipt["receipt_digest"],
            "reviewer_image_id": receipt["reviewer_image"]["id"],
            "reviewer_image_ref": receipt["reviewer_image"]["ref"],
            "source_manifest_digest": receipt["source_manifest_digest"],
            "status": "succeeded",
        }
        sys.stdout.buffer.write(_canonical_json(result) + b"\n")
        return 0
    except CandidateBuildError as error:
        code = error.code
    except (OSError, ValueError, TypeError, KeyError):
        code = "REVIEWER_UPGRADE_CANDIDATE_BUILD_FAILED"
    except Exception as error:
        candidate_error = getattr(candidate, "CandidateError", ())
        if candidate_error and isinstance(error, candidate_error):
            code = getattr(error, "code", "REVIEWER_UPGRADE_CANDIDATE_BUILD_FAILED")
        elif isinstance(error, reconciler.ReconcileError):
            code = error.code
        else:
            code = "REVIEWER_UPGRADE_CANDIDATE_BUILD_FAILED"
    sys.stderr.buffer.write(
        _canonical_json({"code": code, "status": "failed"}) + b"\n"
    )
    return 2 if code.endswith("INPUT_INVALID") else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
