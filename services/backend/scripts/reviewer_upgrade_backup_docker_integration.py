#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the reviewer-upgrade backup adapter against an isolated rootless Docker lab.

This is an explicit integration harness, not part of the deployed service.  It
creates one randomly named backend image, Compose project, network, and state
volume; publishes no host port; exercises the real Docker backup lifecycle; and
removes only resources bearing the run's exact ownership labels.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any, NoReturn


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = REPOSITORY_ROOT / "services" / "backend"
BACKEND_SOURCE = BACKEND_ROOT / "src"
BACKEND_SCRIPTS = BACKEND_ROOT / "scripts"
sys.path.insert(0, str(BACKEND_SOURCE))
sys.path.insert(0, str(BACKEND_SCRIPTS))

from tacua_backend import operator_tool  # noqa: E402
import reconcile_compose_deployment as reconciler  # noqa: E402
import reviewer_upgrade_backup as backup  # noqa: E402
import reviewer_upgrade_backup_docker as docker_backup  # noqa: E402
import reviewer_upgrade_journal as journal  # noqa: E402


OWNER_LABEL = "io.tacua.integration"
OWNER_VALUE = "reviewer-upgrade-backup-docker"
RUN_LABEL = "io.tacua.integration.run"
TOKEN = re.compile(r"^[a-f0-9]{16}$")
CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
LAB_ROOT_PARENT = Path("/tmp")
LAB_ROOT_PREFIX = "tacua-backup-e2e-"
FAILURE_FILE = "failure.json"
FAILURE_CONTRACT = (
    "tacua.reviewer-upgrade-backup-docker-integration-failure@1.0.0"
)
FAILURE_STAGES = frozenset({
    "attest_image",
    "build_image",
    "cleanup",
    "construct_adapter",
    "inspect_backend",
    "prepare_inputs",
    "run_backup",
    "start_backend",
    "validate_compose",
    "verify_recovery",
})
BACKUP_ACTIONS = frozenset({
    "archive_backup",
    "fsync_backup",
    "health_backend",
    "inspect_backend",
    "smoke_backend",
    "start_backend",
    "stop_backend",
    "verify_backup",
})
KNOWN_EXCEPTION_CODES = frozenset({
    "RECONCILE_COMMAND_FAILED",
    "RECONCILE_CONTAINER_DRIFT",
    "RECONCILE_INPUT_INVALID",
    "RECONCILE_RESOURCE_DRIFT",
    "RECONCILE_RUNTIME_DRIFT",
    "RECONCILE_STATE_BINDING_MISMATCH",
    "RECONCILE_STATE_INVALID",
    "REVIEWER_UPGRADE_BACKUP_ATTEMPTS_EXHAUSTED",
    "REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED",
    "REVIEWER_UPGRADE_BACKUP_DOCKER_INVALID",
    "REVIEWER_UPGRADE_BACKUP_FAILED",
    "REVIEWER_UPGRADE_BACKUP_INVALID",
    "REVIEWER_UPGRADE_BACKUP_RECOVERY_FAILED",
    "REVIEWER_UPGRADE_JOURNAL_EXISTS",
    "REVIEWER_UPGRADE_JOURNAL_INVALID",
})


class IntegrationError(RuntimeError):
    """Stable integration-harness failure."""


class RecordedIntegrationFailure(IntegrationError):
    """An integration failure reduced to one bounded diagnostic document."""

    def __init__(self, document: Mapping[str, Any]) -> None:
        super().__init__("TACUA_BACKUP_DOCKER_INTEGRATION_FAILED")
        self.document = dict(document)


def _fail(message: str) -> NoReturn:
    raise IntegrationError(message)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _stable_exception_code(error: BaseException) -> str:
    if isinstance(error, backup._ActionError):
        action = error.args[0] if len(error.args) == 1 else None
        if type(action) is str and action in BACKUP_ACTIONS:
            return f"backup_action:{action}"
        return "backup_action:unknown"
    if isinstance(
        error,
        (
            backup.BackupError,
            docker_backup.DockerBackupError,
            journal.JournalError,
            reconciler.ReconcileError,
        ),
    ):
        code = getattr(error, "code", None)
        if type(code) is str and code in KNOWN_EXCEPTION_CODES:
            return f"stable_code:{code}"
        return "stable_code:unknown"
    if isinstance(error, IntegrationError):
        return "integration_error"
    if isinstance(error, operator_tool.OperatorError):
        return "operator_error"
    if isinstance(error, subprocess.TimeoutExpired):
        return "subprocess_timeout"
    if isinstance(error, json.JSONDecodeError):
        return "json_error"
    if isinstance(error, UnicodeError):
        return "unicode_error"
    if isinstance(error, OSError):
        return "os_error"
    if isinstance(error, (KeyError, IndexError, TypeError, ValueError)):
        return "invalid_result"
    if isinstance(error, KeyboardInterrupt):
        return "interrupted"
    if isinstance(error, AssertionError):
        return "assertion_error"
    return "unexpected_error"


def _stable_cause_chain(error: BaseException) -> list[str]:
    result: list[str] = []
    visited: set[int] = set()
    current: BaseException | None = error
    while current is not None and len(result) < 8 and id(current) not in visited:
        visited.add(id(current))
        result.append(_stable_exception_code(current))
        next_error = current.__cause__
        if next_error is None and not current.__suppress_context__:
            next_error = current.__context__
        current = next_error
    return result or ["unexpected_error"]


def _failure_document(
    stage: str,
    error: BaseException,
    *,
    cleanup_status: str,
) -> dict[str, Any]:
    if stage not in FAILURE_STAGES or cleanup_status not in {
        "complete",
        "incomplete",
    }:
        _fail("invalid failure diagnostic")
    document = {
        "cause_chain": _stable_cause_chain(error),
        "cleanup_status": cleanup_status,
        "contract_version": FAILURE_CONTRACT,
        "stage": stage,
        "status": "failed",
    }
    payload = _canonical(document)
    if len(payload) > 2_048:
        _fail("failure diagnostic exceeded its bound")
    return document


@dataclass(frozen=True)
class LabNames:
    token: str
    project: str
    image: str
    volume: str
    network: str
    root: Path
    operation_id: str
    plan_digest: str

    @classmethod
    def from_token(cls, token: str) -> "LabNames":
        if TOKEN.fullmatch(token) is None:
            _fail("integration token is invalid")
        project = f"tacua_backup_e2e_{token}"
        root = LAB_ROOT_PARENT / f"{LAB_ROOT_PREFIX}{token}"
        return cls(
            token=token,
            project=project,
            image=f"tacua-backend:e2e-{token}",
            volume=f"tacua-backup-e2e-{token}-state",
            network=f"tacua-backup-e2e-{token}-network",
            root=root,
            operation_id=f"reviewer-backup-e2e-{token}",
            plan_digest=_digest(f"tacua-backup-e2e:{token}".encode("ascii")),
        )

    @classmethod
    def fresh(cls) -> "LabNames":
        return cls.from_token(secrets.token_hex(8))


class ProcessRunner:
    """Bounded no-shell subprocess runner for one exact rootless socket."""

    def __init__(self, docker: str, runtime: Mapping[str, str]) -> None:
        self.docker = docker
        self.runtime = dict(runtime)
        self.docker_prefix = [docker, "--host", self.runtime["docker_host"]]
        self.environment = {
            "HOME": self.runtime["home"],
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "XDG_RUNTIME_DIR": self.runtime["xdg_runtime_directory"],
        }

    def result(
        self,
        argv: Sequence[str],
        *,
        timeout: int,
    ) -> subprocess.CompletedProcess[bytes]:
        if (
            type(argv) not in {list, tuple}
            or not argv
            or any(type(item) is not str or not item for item in argv)
            or type(timeout) is not int
            or not 1 <= timeout <= 900
        ):
            _fail("invalid integration command")
        try:
            result = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout,
                env=self.environment,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise IntegrationError("integration command failed") from error
        if (
            len(result.stdout) > MAX_OUTPUT_BYTES
            or len(result.stderr) > MAX_OUTPUT_BYTES
        ):
            _fail("integration command output exceeded its bound")
        return result

    def __call__(self, argv: Sequence[str], *, timeout: int = 30) -> bytes:
        result = self.result(argv, timeout=timeout)
        if result.returncode != 0:
            _fail("integration command failed")
        return result.stdout

    def docker_call(self, args: Sequence[str], *, timeout: int = 30) -> bytes:
        return self([*self.docker_prefix, *args], timeout=timeout)


class GuardedAdapterRunner:
    """Allow only Docker commands whose targets are bound to this lab run."""

    def __init__(
        self,
        base: ProcessRunner,
        names: LabNames,
        compose: Path,
        backend_id: str,
        image_id: str,
    ) -> None:
        self.base = base
        self.names = names
        self.compose = compose
        self.backend_id = backend_id
        self.image_id = image_id
        self.auxiliary_ids: set[str] = set()
        self.auxiliary_prefix = (
            "tacua-reviewer-upgrade-"
            f"{names.plan_digest.removeprefix('sha256:')[:20]}-"
        )

    def _tail(self, raw_argv: Sequence[str]) -> list[str]:
        argv = list(raw_argv)
        prefix = self.base.docker_prefix
        if argv[: len(prefix)] != prefix:
            _fail("adapter command escaped the bound Docker socket")
        return argv[len(prefix) :]

    def is_backend_stop(self, raw_argv: Sequence[str]) -> bool:
        return self._tail(raw_argv) == [
            "container",
            "stop",
            "--timeout",
            "30",
            self.backend_id,
        ]

    def is_backend_start(self, raw_argv: Sequence[str]) -> bool:
        return self._tail(raw_argv) == [
            "container",
            "start",
            self.backend_id,
        ]

    def is_compose_backend_index(self, raw_argv: Sequence[str]) -> bool:
        return self._tail(raw_argv) == [
            "compose",
            "-p",
            self.names.project,
            "-f",
            str(self.compose),
            "ps",
            "--no-trunc",
            "-aq",
            "backend",
        ]

    def _validate_run(self, tail: list[str]) -> None:
        if not tail or tail[0] != "run":
            _fail("unexpected adapter Docker command")
        try:
            name = tail[tail.index("--name") + 1]
            entrypoint = tail.index("--entrypoint")
            selected_image = tail[entrypoint + 2]
        except (ValueError, IndexError) as error:
            raise IntegrationError("adapter run command is incomplete") from error
        match = re.fullmatch(
            re.escape(self.auxiliary_prefix)
            + r"(0[1-3])-(archive|normalize|prepare|verify)",
            name,
        )
        if (
            match is None
            or selected_image != self.image_id
        ):
            _fail("adapter run command escaped the lab identity")
        assert match is not None
        number = int(match.group(1), 10)
        role = match.group(2)
        if tail != self._expected_run(number, role):
            _fail("adapter run command escaped the exact lab grammar")

    def _expected_run(self, number: int, role: str) -> list[str]:
        if not 1 <= number <= 3 or role not in {
            "archive",
            "normalize",
            "prepare",
            "verify",
        }:
            _fail("invalid auxiliary identity")
        name = f"{self.auxiliary_prefix}{number:02d}-{role}"
        labels = {
            "io.tacua.reviewer-upgrade.attempt": str(number),
            "io.tacua.reviewer-upgrade.operation": self.names.operation_id,
            "io.tacua.reviewer-upgrade.plan-digest": self.names.plan_digest,
            "io.tacua.reviewer-upgrade.role": role,
        }
        user = "10001:10001" if role == "archive" else "0:0"
        temporary_uid = "10001" if role == "archive" else "0"
        expected = ["run", "--rm", "--name", name]
        for key in sorted(labels):
            expected.extend(["--label", f"{key}={labels[key]}"])
        expected.extend([
            "--pull",
            "never",
            "--user",
            user,
            "--read-only",
            "--network",
            "none",
            "--ipc",
            "none",
            "--init",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "128",
            "--memory",
            "536870912",
            "--memory-swap",
            "536870912",
            "--cpus",
            "1",
            "--log-driver",
            "none",
            "--no-healthcheck",
            "--env",
            "TMPDIR=/tmp",
            "--tmpfs",
            (
                "/tmp:rw,nosuid,nodev,noexec,size=67108864,"
                f"uid={temporary_uid},gid={temporary_uid},mode=0700"
            ),
        ])
        if role != "archive":
            expected.extend([
                "--mount",
                (
                    "type=tmpfs,dst=/var/lib/tacua,"
                    "tmpfs-mode=0700,tmpfs-size=1048576"
                ),
            ])
        bundle = (
            self.names.root
            / "upgrades"
            / self.names.operation_id
            / f"backup-attempt-{number:02d}"
            / backup.BACKUP_BUNDLE_DIRECTORY
        )
        prepare_script = (
            "set -eu; test -d /backup; test ! -L /backup; "
            "test -z \"$(find /backup -mindepth 1 -print -quit)\"; "
            "chown 10001:10001 /backup; chmod 0700 /backup"
        )
        archive_script = (
            "exec python -m tacua_backend.operator_tool backup "
            "--config-file /run/tacua/config.json "
            "--admin-secret-file /run/secrets/tacua_admin "
            f"--output /backup/{docker_backup.BACKUP_OUTPUT_DIRECTORY} >/dev/null"
        )
        normalization_script = (
            "set -eu; test -d /backup; test ! -L /backup; "
            "test -z \"$(find /backup -xdev -mindepth 1 ! -type d "
            "! -type f -print -quit)\"; chown -R 0:0 /backup; "
            "find /backup -xdev -type d -exec chmod 0700 {} +; "
            "find /backup -xdev -type f -exec chmod 0600 {} +"
        )
        if role == "prepare":
            expected.extend([
                "--cap-add",
                "CHOWN",
                "--cap-add",
                "FOWNER",
                "--mount",
                f"type=bind,src={bundle},dst=/backup",
                "--entrypoint",
                "/bin/sh",
                self.image_id,
                "-ceu",
                prepare_script,
            ])
        elif role == "archive":
            expected.extend([
                "--mount",
                f"type=volume,src={self.names.volume},dst=/var/lib/tacua",
                "--mount",
                (
                    f"type=bind,src={self.names.root / 'config.json'},"
                    "dst=/run/tacua/config.json,readonly"
                ),
                "--mount",
                (
                    f"type=bind,src={self.names.root / 'admin-secret'},"
                    "dst=/run/secrets/tacua_admin,readonly"
                ),
                "--mount",
                f"type=bind,src={bundle},dst=/backup",
                "--entrypoint",
                "/bin/sh",
                self.image_id,
                "-ceu",
                archive_script,
            ])
        elif role == "normalize":
            expected.extend([
                "--cap-add",
                "CHOWN",
                "--cap-add",
                "DAC_READ_SEARCH",
                "--cap-add",
                "FOWNER",
                "--mount",
                f"type=bind,src={bundle},dst=/backup",
                "--entrypoint",
                "/bin/sh",
                self.image_id,
                "-ceu",
                normalization_script,
            ])
        else:
            expected.extend([
                "--mount",
                f"type=bind,src={bundle},dst=/backup,readonly",
                "--entrypoint",
                "python",
                self.image_id,
                "-m",
                "tacua_backend.operator_tool",
                "verify-backup",
                "/backup",
            ])
        return expected

    def authorize(self, raw_argv: Sequence[str]) -> None:
        tail = self._tail(raw_argv)
        compose_ps = [
            "compose",
            "-p",
            self.names.project,
            "-f",
            str(self.compose),
            "ps",
            "--no-trunc",
            "-aq",
            "backend",
        ]
        if tail == compose_ps:
            return
        if tail == [
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            self.names.image,
        ]:
            return
        if tail[:5] == ["container", "ls", "--all", "--no-trunc", "--quiet"]:
            if len(tail) != 7 or tail[5] != "--filter":
                _fail("adapter container query is not bounded")
            filter_value = tail[6]
            allowed = {
                f"volume={self.names.volume}",
                (
                    "label=io.tacua.reviewer-upgrade.plan-digest="
                    f"{self.names.plan_digest}"
                ),
                f"name={self.auxiliary_prefix}",
            }
            if filter_value.startswith("id="):
                identifier = filter_value.removeprefix("id=")
                if identifier not in self.auxiliary_ids:
                    _fail("adapter queried an unowned container")
                return
            if filter_value not in allowed:
                _fail("adapter queried an unowned Docker resource")
            return
        if tail[:2] == ["container", "inspect"] and len(tail) == 3:
            if tail[2] != self.backend_id and tail[2] not in self.auxiliary_ids:
                _fail("adapter inspected an unowned container")
            return
        if tail == ["container", "start", self.backend_id]:
            return
        if tail == [
            "container",
            "stop",
            "--timeout",
            "30",
            self.backend_id,
        ]:
            return
        if (
            len(tail) == 5
            and tail[:4] == ["container", "stop", "--timeout", "10"]
            and tail[4] in self.auxiliary_ids
        ):
            return
        if (
            len(tail) == 5
            and tail[:4] == ["container", "rm", "--force", "--volumes"]
            and tail[4] in self.auxiliary_ids
        ):
            return
        if tail and tail[0] == "run":
            self._validate_run(tail)
            return
        _fail("unexpected adapter Docker command")

    def execute_authorized(
        self,
        raw_argv: Sequence[str],
        *,
        timeout: int,
    ) -> bytes:
        payload = self.base(raw_argv, timeout=timeout)
        tail = self._tail(raw_argv)
        if (
            tail[:5] == ["container", "ls", "--all", "--no-trunc", "--quiet"]
            and tail[6].startswith(("label=", "name="))
        ):
            try:
                values = [
                    line
                    for line in payload.decode("ascii", errors="strict").splitlines()
                    if line
                ]
            except UnicodeError as error:
                raise IntegrationError("Docker returned a non-ASCII container ID") from error
            if any(CONTAINER_ID.fullmatch(value) is None for value in values):
                _fail("Docker returned an invalid auxiliary container ID")
            self.auxiliary_ids.update(values)
        return payload

    def __call__(self, raw_argv: Sequence[str], *, timeout: int) -> bytes:
        self.authorize(raw_argv)
        return self.execute_authorized(raw_argv, timeout=timeout)


class FourBoundaryIndexFaultCommandRunner:
    """Inject one Compose-index miss at every stop/start boundary."""

    def __init__(self, guarded: GuardedAdapterRunner) -> None:
        self.guarded = guarded
        self.armed_boundary: str | None = None
        self.internal_stop_injections = 0
        self.public_stop_injections = 0
        self.internal_start_injections = 0
        self.public_start_injections = 0

    @property
    def injections(self) -> int:
        return sum((
            self.internal_stop_injections,
            self.public_stop_injections,
            self.internal_start_injections,
            self.public_start_injections,
        ))

    def _arm(self, boundary: str) -> None:
        if self.armed_boundary is not None:
            _fail("a Compose-index fault boundary is already armed")
        self.armed_boundary = boundary

    def _consume(self) -> bytes:
        boundary = self.armed_boundary
        if boundary is None:
            _fail("no Compose-index fault boundary is armed")
        attribute = f"{boundary}_injections"
        count = getattr(self, attribute)
        if count != 0:
            _fail("a Compose-index fault boundary was repeated")
        setattr(self, attribute, 1)
        self.armed_boundary = None
        return b""

    def arm_public_after_stop_return(self) -> None:
        if (
            self.armed_boundary is not None
            or self.internal_stop_injections != 1
            or self.public_stop_injections != 0
            or self.internal_start_injections != 0
            or self.public_start_injections != 0
        ):
            _fail("public post-stop fault boundary is invalid")
        self._arm("public_stop")

    def arm_public_after_start_return(self) -> None:
        if (
            self.armed_boundary is not None
            or self.internal_stop_injections != 1
            or self.public_stop_injections != 1
            or self.internal_start_injections != 1
            or self.public_start_injections != 0
        ):
            _fail("public post-start fault boundary is invalid")
        self._arm("public_start")

    def __call__(self, raw_argv: Sequence[str], *, timeout: int) -> bytes:
        self.guarded.authorize(raw_argv)
        compose_index = self.guarded.is_compose_backend_index(raw_argv)
        if self.armed_boundary is not None:
            if not compose_index:
                _fail("the armed Compose-index inspection was not immediate")
            return self._consume()
        payload = self.guarded.execute_authorized(raw_argv, timeout=timeout)
        if self.guarded.is_backend_stop(raw_argv):
            if (
                self.internal_stop_injections != 0
                or self.public_stop_injections != 0
                or self.internal_start_injections != 0
                or self.public_start_injections != 0
            ):
                _fail("raw Docker stop fault boundary is invalid")
            self._arm("internal_stop")
        elif self.guarded.is_backend_start(raw_argv):
            if (
                self.internal_stop_injections != 1
                or self.public_stop_injections != 1
                or self.internal_start_injections != 0
                or self.public_start_injections != 0
            ):
                _fail("raw Docker start fault boundary is invalid")
            self._arm("internal_start")
        return payload


class PostActionBoundaryRunner:
    """Arm public faults only after exact stop/start actions return."""

    def __init__(
        self,
        adapter: docker_backup.DockerBackupRunner,
        fault: FourBoundaryIndexFaultCommandRunner,
    ) -> None:
        self.adapter = adapter
        self.fault = fault
        self.completed_stop_actions = 0
        self.completed_start_actions = 0
        self.armed_after_stop_return = False
        self.armed_after_start_return = False

    def __call__(
        self,
        action: str,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        result = self.adapter(action, request)
        if action == "stop_backend":
            expected = {
                "container_id": self.adapter.bindings.backend_container_id,
                "status": "stopped",
            }
            if result != expected or self.completed_stop_actions != 0:
                _fail("adapter stop postcondition was not exact")
            self.completed_stop_actions = 1
            self.fault.arm_public_after_stop_return()
            self.armed_after_stop_return = True
        elif action == "start_backend":
            expected = {
                "container_id": self.adapter.bindings.backend_container_id,
                "status": "started",
            }
            if result != expected or self.completed_start_actions != 0:
                _fail("adapter start postcondition was not exact")
            self.completed_start_actions = 1
            self.fault.arm_public_after_start_return()
            self.armed_after_start_return = True
        return result


def _write_exclusive(path: Path, payload: bytes, mode: int) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("write stopped")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except OSError as error:
        raise IntegrationError("could not publish an integration artifact") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_failure_record(
    names: LabNames,
    root_identity: tuple[int, int],
    document: Mapping[str, Any],
) -> None:
    _attest_lab_root(names, root_identity)
    payload = _canonical(dict(document))
    if (
        len(payload) > 2_048
        or document.get("contract_version") != FAILURE_CONTRACT
        or document.get("stage") not in FAILURE_STAGES
        or document.get("cleanup_status") not in {"complete", "incomplete"}
        or document.get("status") != "failed"
    ):
        _fail("failure diagnostic is invalid")
    path = names.root / FAILURE_FILE
    _write_exclusive(path, payload, 0o600)
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size != len(payload)
        or path.read_bytes() != payload
    ):
        _fail("failure diagnostic publication is invalid")
    descriptor = os.open(
        names.root,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rootless_preflight(process: ProcessRunner) -> dict[str, Any]:
    if os.geteuid() == 0:
        _fail("integration runner refuses uid 0")
    host = process.runtime.get("docker_host", "")
    if not host.startswith("unix://"):
        _fail("integration runner requires a local rootless Unix socket")
    socket_path = Path(host.removeprefix("unix://"))
    try:
        metadata = socket_path.lstat()
    except OSError as error:
        raise IntegrationError("rootless Docker socket is unavailable") from error
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o007
    ):
        _fail("Docker socket is not an owner-bound rootless socket")
    payload = process.docker_call(
        ["info", "--format", "{{json .}}"],
        timeout=30,
    )
    try:
        document = json.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise IntegrationError("Docker info is invalid") from error
    security = document.get("SecurityOptions") if type(document) is dict else None
    if (
        type(security) is not list
        or "name=rootless" not in security
        or document.get("CgroupDriver") != "systemd"
        or str(document.get("CgroupVersion")) != "2"
    ):
        _fail("integration runner requires rootless Docker with systemd cgroup v2")
    return document


def _compose_document(names: LabNames, config: Path, secret: Path) -> dict[str, Any]:
    labels = {OWNER_LABEL: OWNER_VALUE, RUN_LABEL: names.token}
    health = (
        "import json,urllib.request; "
        "d=json.load(urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2)); "
        "assert d['status']=='ok' and d['retention_worker_running'] and "
        "d['pending_deletions']==0 and d['retention_last_failed_sessions']==0"
    )
    return {
        "name": names.project,
        "services": {
            "backend": {
                "image": names.image,
                "pull_policy": "never",
                "restart": "unless-stopped",
                "init": True,
                "stop_grace_period": "30s",
                "pids_limit": 128,
                "read_only": True,
                "user": "10001:10001",
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "networks": ["lab"],
                "labels": labels,
                "logging": {
                    "driver": "json-file",
                    "options": {"max-size": "10m", "max-file": "3"},
                },
                "healthcheck": {
                    "test": ["CMD", "python", "-c", health],
                    "interval": "1s",
                    "timeout": "3s",
                    "start_period": "1s",
                    "retries": 30,
                },
                "volumes": [
                    {
                        "type": "volume",
                        "source": "tacua-state",
                        "target": "/var/lib/tacua",
                    },
                    {
                        "type": "bind",
                        "source": str(config),
                        "target": "/run/tacua/config.json",
                        "read_only": True,
                        "bind": {"create_host_path": False},
                    },
                ],
                "secrets": [{"source": "tacua_admin", "target": "tacua_admin"}],
            },
        },
        "secrets": {"tacua_admin": {"file": str(secret)}},
        "volumes": {
            "tacua-state": {"name": names.volume, "labels": labels},
        },
        "networks": {
            "lab": {
                "name": names.network,
                "internal": True,
                "labels": labels,
            },
        },
    }


def _exact_line(payload: bytes, pattern: re.Pattern[str], label: str) -> str:
    try:
        decoded = payload.decode("ascii", errors="strict")
    except UnicodeError as error:
        raise IntegrationError(f"{label} was not ASCII") from error
    values = [line for line in decoded.splitlines() if line]
    if len(values) != 1 or pattern.fullmatch(values[0]) is None:
        _fail(f"{label} was not one exact identifier")
    return values[0]


def _listed_resource(process: ProcessRunner, kind: str, name: str) -> list[str]:
    commands = {
        "container": [
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"name={name}",
        ],
        "volume": [
            "volume",
            "ls",
            "--format",
            "{{.Name}}",
            "--filter",
            f"name={name}",
        ],
        "network": [
            "network",
            "ls",
            "--format",
            "{{.Name}}",
            "--filter",
            f"name={name}",
        ],
        "image": ["image", "ls", "--quiet", "--no-trunc", name],
    }
    if kind not in commands:
        _fail("invalid integration resource kind")
    payload = process.docker_call(commands[kind], timeout=30)
    try:
        return [
            line
            for line in payload.decode("ascii", errors="strict").splitlines()
            if line
        ]
    except UnicodeError as error:
        raise IntegrationError("Docker resource listing was not ASCII") from error


def _assert_absent(process: ProcessRunner, kind: str, name: str) -> None:
    if _listed_resource(process, kind, name):
        _fail("integration resource name already exists")


def _wait_healthy(process: ProcessRunner, identifier: str) -> None:
    for attempt in range(90):
        payload = process.docker_call(
            ["container", "inspect", identifier],
            timeout=30,
        )
        try:
            document = json.loads(payload.decode("utf-8", errors="strict"))
            state = document[0]["State"]
            health = state.get("Health", {}).get("Status")
        except (UnicodeError, json.JSONDecodeError, KeyError, IndexError, TypeError) as error:
            raise IntegrationError("backend inspection was invalid") from error
        if state.get("Status") == "running" and health == "healthy":
            return
        if attempt + 1 < 90:
            time.sleep(0.25)
    _fail("isolated backend did not become healthy")


def _assert_smoke_bindings(
    selected_config: Path,
    selected_secret: Path,
    selected_origin: str,
    *,
    expected_config: Path,
    expected_secret: Path,
    expected_origin: str,
) -> None:
    if (
        selected_config != expected_config
        or selected_secret != expected_secret
        or selected_origin != expected_origin
    ):
        _fail("adapter smoke escaped the exact lab bindings")


def _owned_labels(document: Any, names: LabNames, *, image: bool = False) -> bool:
    if type(document) is not list or len(document) != 1 or type(document[0]) is not dict:
        return False
    item = document[0]
    labels = item.get("Config", {}).get("Labels") if image else item.get("Labels")
    if type(labels) is not dict:
        return False
    return labels.get(OWNER_LABEL) == OWNER_VALUE and labels.get(RUN_LABEL) == names.token


def _attest_lab_root(names: LabNames, identity: tuple[int, int]) -> None:
    try:
        resolved = names.root.resolve(strict=True)
        metadata = names.root.lstat()
    except OSError as error:
        raise IntegrationError("lab root cannot be attested") from error
    if (
        resolved != names.root
        or names.root.parent != LAB_ROOT_PARENT
        or names.root.name != f"{LAB_ROOT_PREFIX}{names.token}"
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or (metadata.st_dev, metadata.st_ino) != identity
    ):
        _fail("lab root identity changed")


def _normalize_lab_tree(
    process: ProcessRunner,
    names: LabNames,
    image_id: str,
    root_identity: tuple[int, int],
) -> None:
    _attest_lab_root(names, root_identity)
    cleanup_name = f"tacua-backup-e2e-{names.token}-cleanup"
    _assert_absent(process, "container", cleanup_name)
    process.docker_call(
        [
            "run",
            "--rm",
            "--name",
            cleanup_name,
            "--label",
            f"{OWNER_LABEL}={OWNER_VALUE}",
            "--label",
            f"{RUN_LABEL}={names.token}",
            "--pull",
            "never",
            "--user",
            "0:0",
            "--read-only",
            "--network",
            "none",
            "--ipc",
            "none",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "DAC_READ_SEARCH",
            "--cap-add",
            "FOWNER",
            "--security-opt",
            "no-new-privileges:true",
            "--mount",
            f"type=bind,src={names.root},dst=/cleanup",
            "--entrypoint",
            "/bin/sh",
            image_id,
            "-ceu",
            "chown -R 0:0 /cleanup",
        ],
        timeout=120,
    )


def _remove_lab_root(names: LabNames, identity: tuple[int, int]) -> None:
    _attest_lab_root(names, identity)
    shutil.rmtree(names.root)


def _remove_lab_root_after_docker_cleanup(
    names: LabNames,
    identity: tuple[int, int],
    *,
    docker_cleanup_failed: bool,
    retain_evidence: bool = False,
) -> bool:
    if docker_cleanup_failed or retain_evidence:
        return False
    _remove_lab_root(names, identity)
    return True


def _cleanup(
    process: ProcessRunner,
    names: LabNames,
    compose: Path | None,
    adapter: docker_backup.DockerBackupRunner | None,
    image_id: str | None,
    root_identity: tuple[int, int] | None,
    *,
    retain_evidence: bool = False,
) -> None:
    errors: list[BaseException] = []
    docker_cleanup_failed = False
    if adapter is not None:
        try:
            adapter._reap_auxiliaries()
        except BaseException as error:
            errors.append(error)
            docker_cleanup_failed = True
    if compose is not None and compose.exists():
        try:
            ids = process.docker_call(
                [
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    f"label=com.docker.compose.project={names.project}",
                ],
                timeout=30,
            ).decode("ascii", errors="strict").splitlines()
            for identifier in filter(None, ids):
                document = json.loads(
                    process.docker_call(
                        ["container", "inspect", identifier], timeout=30
                    ).decode("utf-8", errors="strict")
                )
                labels = document[0].get("Config", {}).get("Labels")
                if (
                    type(labels) is not dict
                    or labels.get(OWNER_LABEL) != OWNER_VALUE
                    or labels.get(RUN_LABEL) != names.token
                ):
                    _fail("refusing to remove an unowned project container")
            for kind, name in (
                ("volume", names.volume),
                ("network", names.network),
            ):
                listed = _listed_resource(process, kind, name)
                if not listed:
                    continue
                if listed != [name]:
                    _fail(f"ambiguous integration {kind} listing")
                document = json.loads(
                    process.docker_call(
                        [kind, "inspect", name], timeout=30
                    ).decode("utf-8", errors="strict")
                )
                if not _owned_labels(document, names):
                    _fail(f"refusing to remove an unowned integration {kind}")
            process.docker_call(
                [
                    "compose",
                    "-p",
                    names.project,
                    "-f",
                    str(compose),
                    "down",
                    "--volumes",
                    "--timeout",
                    "10",
                ],
                timeout=120,
            )
            remaining = process.docker_call(
                [
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    f"label=com.docker.compose.project={names.project}",
                ],
                timeout=30,
            )
            if remaining.strip():
                _fail("Compose cleanup left a project container")
            for kind, name in (
                ("volume", names.volume),
                ("network", names.network),
            ):
                if _listed_resource(process, kind, name):
                    _fail(f"Compose cleanup left the integration {kind}")
        except BaseException as error:
            errors.append(error)
            docker_cleanup_failed = True
    if (
        image_id is not None
        and names.root.exists()
        and root_identity is not None
    ):
        try:
            _normalize_lab_tree(process, names, image_id, root_identity)
        except BaseException as error:
            errors.append(error)
            docker_cleanup_failed = True
    try:
        listed_images = _listed_resource(process, "image", names.image)
        if listed_images:
            document = json.loads(
                process.docker_call(
                    ["image", "inspect", names.image], timeout=30
                ).decode("utf-8", errors="strict")
            )
            if not _owned_labels(document, names, image=True):
                _fail("refusing to remove an unowned integration image")
            process.docker_call(["image", "rm", names.image], timeout=120)
            if _listed_resource(process, "image", names.image):
                _fail("integration image tag remained after cleanup")
    except BaseException as error:
        errors.append(error)
        docker_cleanup_failed = True
    if names.root.exists() and root_identity is not None:
        try:
            _remove_lab_root_after_docker_cleanup(
                names,
                root_identity,
                docker_cleanup_failed=docker_cleanup_failed,
                retain_evidence=retain_evidence,
            )
        except BaseException as error:
            errors.append(error)
    if errors:
        retained = f"; retained {names.root}" if names.root.exists() else ""
        raise IntegrationError(
            "isolated integration cleanup was incomplete" + retained
        ) from errors[0]


def _run() -> dict[str, Any]:
    names = LabNames.fresh()
    runtime = reconciler._runtime_binding()
    docker = reconciler._binary("docker")
    process = ProcessRunner(docker, runtime)
    _rootless_preflight(process)
    for kind, name in (
        ("container", f"{names.project}-backend-1"),
        ("volume", names.volume),
        ("network", names.network),
        ("image", names.image),
    ):
        _assert_absent(process, kind, name)

    names.root.mkdir(mode=0o700)
    root_stat = names.root.lstat()
    root_identity = (root_stat.st_dev, root_stat.st_ino)
    compose: Path | None = None
    adapter: docker_backup.DockerBackupRunner | None = None
    image_id: str | None = None
    result: dict[str, Any] | None = None
    primary: BaseException | None = None
    stage = "prepare_inputs"
    try:
        config = names.root / "config.json"
        _write_exclusive(config, (BACKEND_ROOT / "config.example.json").read_bytes(), 0o644)
        secret = names.root / "admin-secret"
        operator_tool.create_admin_secret(secret)
        source = journal.create_transaction_directory(names.root / "source-state")
        upgrades = names.root / "upgrades"
        upgrades.mkdir(mode=0o700)
        transaction = journal.create_transaction_directory(
            upgrades / names.operation_id
        )
        operations = names.root / "operations"
        operations.mkdir(mode=0o700)

        compose = names.root / "compose.json"
        compose_payload = _canonical(_compose_document(names, config, secret))
        _write_exclusive(compose, compose_payload, 0o400)
        stage = "build_image"
        process.docker_call(
            [
                "build",
                "--label",
                f"{OWNER_LABEL}={OWNER_VALUE}",
                "--label",
                f"{RUN_LABEL}={names.token}",
                "--tag",
                names.image,
                "--file",
                str(BACKEND_ROOT / "Dockerfile"),
                str(REPOSITORY_ROOT),
            ],
            timeout=900,
        )
        stage = "attest_image"
        built_image = json.loads(
            process.docker_call(
                ["image", "inspect", names.image], timeout=30
            ).decode("utf-8", errors="strict")
        )
        if not _owned_labels(built_image, names, image=True):
            _fail("built image ownership labels are invalid")
        try:
            image_id = built_image[0]["Id"]
        except (IndexError, KeyError, TypeError) as error:
            raise IntegrationError("built image identity is invalid") from error
        if type(image_id) is not str or IMAGE_ID.fullmatch(image_id) is None:
            _fail("built image identity is invalid")
        stage = "validate_compose"
        process.docker_call(
            [
                "compose",
                "-p",
                names.project,
                "-f",
                str(compose),
                "config",
                "--quiet",
            ],
            timeout=30,
        )
        stage = "start_backend"
        process.docker_call(
            [
                "compose",
                "-p",
                names.project,
                "-f",
                str(compose),
                "up",
                "--detach",
                "--no-build",
                "--pull",
                "never",
                "backend",
            ],
            timeout=120,
        )
        stage = "inspect_backend"
        backend_id = _exact_line(
            process.docker_call(
                [
                    "compose",
                    "-p",
                    names.project,
                    "-f",
                    str(compose),
                    "ps",
                    "--no-trunc",
                    "-aq",
                    "backend",
                ],
                timeout=30,
            ),
            CONTAINER_ID,
            "backend container ID",
        )
        observed_image_id = _exact_line(
            process.docker_call(
                ["image", "inspect", "--format", "{{.Id}}", names.image],
                timeout=30,
            ),
            IMAGE_ID,
            "backend image ID",
        )
        if observed_image_id != image_id:
            _fail("backend image tag changed after Compose startup")
        _wait_healthy(process, backend_id)
        backend_document = json.loads(
            process.docker_call(
                ["container", "inspect", backend_id], timeout=30
            ).decode("utf-8", errors="strict")
        )
        backend_projection = reconciler._container_projection(
            backend_document,
            project=names.project,
            service="backend",
            published_port=65535,
        )
        config_identity = reconciler._identity(config, secret=False)
        secret_identity = reconciler._identity(secret, secret=True)
        generation = f"generation-e2e-{names.token}"
        manifest: dict[str, Any] = {
            "commands": {"docker": docker},
            "compose_digest": _digest(compose_payload),
            "config": config_identity,
            "containers": {
                "backend": backend_projection,
                "ingress": {},
                "reviewer": {},
            },
            "contract_version": reconciler.GENERATION_CONTRACT,
            "generation": generation,
            "manifest_digest": "",
            "operation_directory": str(operations),
            "project": names.project,
            "published_port": 65535,
            "resources": {"networks": {}, "volumes": {}},
            "runtime": runtime,
            "secret": secret_identity,
        }
        manifest["manifest_digest"] = reconciler._document_digest(
            manifest, "manifest_digest"
        )
        desired = {
            "compose_digest": manifest["compose_digest"],
            "desired": "maintenance",
            "generation": generation,
            "manifest_digest": manifest["manifest_digest"],
            "project": names.project,
        }
        bindings = backup.validate_backup_bindings({
            "backend": {
                "container_id": backend_id,
                "image_id": image_id,
                "image_ref": names.image,
                "state_volume": names.volume,
            },
            "config": config_identity,
            "contract_version": backup.BACKUP_BINDINGS_CONTRACT,
            "operation_id": names.operation_id,
            "plan_digest": names.plan_digest,
            "project": names.project,
            "secret": secret_identity,
            "source": {
                "compose_digest": manifest["compose_digest"],
                "generation": generation,
                "manifest_digest": manifest["manifest_digest"],
                "state_directory": str(source),
            },
        })
        stage = "construct_adapter"
        guarded = GuardedAdapterRunner(
            process,
            names,
            compose,
            backend_id,
            image_id,
        )
        fault = FourBoundaryIndexFaultCommandRunner(guarded)

        def state_loader(
            selected: Path,
        ) -> tuple[dict[str, Any], dict[str, Any], Path]:
            if selected != source:
                _fail("adapter requested an unbound source state")
            return deepcopy(desired), deepcopy(manifest), compose

        def smoke_runner(
            selected_config: Path,
            selected_secret: Path,
            selected_origin: str,
        ) -> None:
            _assert_smoke_bindings(
                selected_config,
                selected_secret,
                selected_origin,
                expected_config=config,
                expected_secret=secret,
                expected_origin="http://127.0.0.1:65535",
            )
            payload = process.docker_call(
                [
                    "container",
                    "exec",
                    backend_id,
                    "python",
                    "-c",
                    (
                        "import json,urllib.request;"
                        "d=json.load(urllib.request.urlopen("
                        "'http://127.0.0.1:8080/healthz',timeout=2));"
                        "assert d['status']=='ok';"
                        "print(json.dumps({'status':'ok'},sort_keys=True,"
                        "separators=(',',':')))"
                    ),
                ],
                timeout=30,
            )
            if payload not in {b'{"status":"ok"}', b'{"status":"ok"}\n'}:
                _fail("isolated backend smoke failed")

        adapter = docker_backup.DockerBackupRunner(
            transaction,
            bindings,
            manifest,
            compose,
            fault,
            smoke_runner=smoke_runner,
            state_loader=state_loader,
        )
        action_runner = PostActionBoundaryRunner(adapter, fault)
        stage = "run_backup"
        receipt = backup.run_backup_attempt(
            transaction,
            bindings,
            action_runner,
            health_attempts=90,
            health_interval_seconds=0.25,
        )
        if (
            receipt.get("status") != "backup_ready"
            or fault.internal_stop_injections != 1
            or fault.public_stop_injections != 1
            or fault.internal_start_injections != 1
            or fault.public_start_injections != 1
            or fault.injections != 4
            or fault.armed_boundary is not None
            or action_runner.completed_stop_actions != 1
            or action_runner.completed_start_actions != 1
            or not action_runner.armed_after_stop_return
            or not action_runner.armed_after_start_return
        ):
            _fail("real Docker backup did not reach the expected result")
        stage = "verify_recovery"
        _wait_healthy(process, backend_id)
        current_id = _exact_line(
            process.docker_call(
                [
                    "compose",
                    "-p",
                    names.project,
                    "-f",
                    str(compose),
                    "ps",
                    "--no-trunc",
                    "-aq",
                    "backend",
                ],
                timeout=30,
            ),
            CONTAINER_ID,
            "recovered backend container ID",
        )
        if current_id != backend_id:
            _fail("backup replaced the backend container")
        result = {
            "bundle_digest": receipt["bundle"]["sha256"],
            "container_identity_preserved": True,
            "fault_armed_after_start_action_returned": True,
            "fault_armed_after_stop_action_returned": True,
            "internal_post_start_transient_injections": (
                fault.internal_start_injections
            ),
            "internal_post_stop_transient_injections": (
                fault.internal_stop_injections
            ),
            "internal_start_postcondition_completed": True,
            "internal_stop_postcondition_completed": True,
            "public_post_start_transient_injections": (
                fault.public_start_injections
            ),
            "public_post_stop_transient_injections": (
                fault.public_stop_injections
            ),
            "rootless": True,
            "status": "ok",
        }
    except BaseException as error:
        primary = error
    cleanup_error: BaseException | None = None
    try:
        _cleanup(
            process,
            names,
            compose,
            adapter,
            image_id,
            root_identity,
            retain_evidence=primary is not None,
        )
    except BaseException as error:
        cleanup_error = error
    failure = primary if primary is not None else cleanup_error
    if failure is not None:
        failure_stage = stage if primary is not None else "cleanup"
        document = _failure_document(
            failure_stage,
            failure,
            cleanup_status=(
                "incomplete" if cleanup_error is not None else "complete"
            ),
        )
        if names.root.exists():
            try:
                _write_failure_record(names, root_identity, document)
            except BaseException:
                # The in-memory document remains the bounded diagnostic.  The
                # attested root is still retained for manual inspection.
                pass
        raise RecordedIntegrationFailure(document) from failure
    if result is None:
        _fail("integration produced no result")
    return result


def main() -> int:
    os.umask(0o077)
    if len(sys.argv) != 1:
        print(
            "usage: python3 -B "
            "services/backend/scripts/"
            "reviewer_upgrade_backup_docker_integration.py",
            file=sys.stderr,
        )
        return 2
    interrupted = False

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        result = _run()
        if interrupted:
            _fail("integration was interrupted")
        print(_canonical(result).decode("ascii"))
        return 0
    except RecordedIntegrationFailure as error:
        print(_canonical(error.document).decode("ascii"), file=sys.stderr)
        return 1
    except Exception as error:
        document = _failure_document(
            "prepare_inputs",
            error,
            cleanup_status="complete",
        )
        print(_canonical(document).decode("ascii"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
