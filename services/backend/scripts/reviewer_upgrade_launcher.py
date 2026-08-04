#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepublish one already-built reviewer upgrade under one serial lock.

The launcher deliberately does not fetch source, build images, generate Compose,
or mutate Docker itself.  It accepts one content-addressed prepared release,
re-proves its sealed source and candidate Compose document, proves/arms the
stable upgrade units, persists the exact unit evidence needed by the next
launch, and only then calls ``reviewer_upgrade_transaction.prepare`` while
retaining the same serial lock.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Mapping, NoReturn, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import reconcile_compose_deployment as reconciler  # noqa: E402
import reviewer_upgrade_bootstrap as bootstrap  # noqa: E402
import reviewer_upgrade_candidate as prepared_candidate  # noqa: E402
import reviewer_upgrade_journal as journal  # noqa: E402
import reviewer_upgrade_manager as manager  # noqa: E402
import reviewer_upgrade_transaction as transaction  # noqa: E402
import reviewer_upgrade_systemd as upgrade_systemd  # noqa: E402


SNAPSHOT_CONTRACT = "tacua.reviewer-upgrade-stable-snapshot@1.0.0"
POINTER_CONTRACT = "tacua.reviewer-upgrade-stable-pointer@1.0.0"
PENDING_CONTRACT = "tacua.reviewer-upgrade-stable-pending@1.0.0"
PREPARATION_CONTRACT = "tacua.reviewer-upgrade-preparation@1.0.0"
FIRST_INSTALL_CONTRACT = "tacua.reviewer-upgrade-first-install@1.0.0"
LAUNCH_CODE = "REVIEWER_UPGRADE_LAUNCHED"
STABLE_STATE_DIRECTORY = "reviewer-upgrade-stable-units"
SNAPSHOTS_DIRECTORY = "snapshots"
PREPARATIONS_DIRECTORY = "preparations"
CURRENT_FILE = "current.json"
PENDING_FILE = "pending.json"
SNAPSHOT_FILE = "snapshot.json"
BOOTSTRAP_RECEIPT_FILE = "bootstrap-receipt.json"
CANDIDATE_COMPOSE_FILE = "candidate-compose.json"
FIRST_INSTALL_FILE = "first-install.json"
UNIT_SIDECAR_DIRECTORY = "units"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_UPGRADER_BYTES = 2 * 1024 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024
MAX_COMMAND_BYTES = 64 * 1024
MAX_COMMAND_SECONDS = 300.0
SNAPSHOT_ID = re.compile(r"^[a-f0-9]{64}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
CURRENT_MODES = frozenset({"absent", "managed"})

Runner = Callable[..., bytes]


class LauncherError(RuntimeError):
    """Stable, content-free launcher failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        raise LauncherError("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID")


def _fail(code: str = "REVIEWER_UPGRADE_LAUNCH_STATE_INVALID") -> NoReturn:
    raise LauncherError(code)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _document_digest(document: Mapping[str, Any], field: str) -> str:
    subject = dict(document)
    subject.pop(field, None)
    return _digest(journal.canonical_json(subject))


def _canonical_existing(path: Path, *, directory: bool, code: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or str(path).startswith("//")
        or any(part in {".", ".."} for part in path.parts)
    ):
        _fail(code)
    try:
        metadata = path.lstat()
        if path.resolve(strict=True) != path:
            _fail(code)
    except OSError as error:
        raise LauncherError(code) from error
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(
        metadata.st_mode
    )
    if (
        not expected
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (not directory and metadata.st_nlink != 1)
    ):
        _fail(code)
    return path


def _canonical_executable(path: Path) -> Path:
    selected = _canonical_existing(
        path,
        directory=False,
        code="REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID",
    )
    try:
        mode = selected.lstat().st_mode
    except OSError as error:
        raise LauncherError("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID") from error
    if not stat.S_IMODE(mode) & 0o111:
        _fail("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID")
    return selected


def _read_bound_regular(path: Path, *, maximum: int) -> tuple[bytes, dict[str, int]]:
    descriptor: int | None = None
    try:
        lexical = path.lstat()
        if (
            path.resolve(strict=True) != path
            or not stat.S_ISREG(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or lexical.st_uid not in {0, os.geteuid()}
            or lexical.st_nlink != 1
            or stat.S_IMODE(lexical.st_mode) & 0o022
            or not 0 < lexical.st_size <= maximum
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if upgrade_systemd._file_metadata(opened) != (
            upgrade_systemd._file_metadata(lexical)
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID")
        payload = bytearray()
        while len(payload) <= maximum:
            block = os.read(descriptor, min(65_536, maximum + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            len(payload) != opened.st_size
            or not payload
            or len(payload) > maximum
            or upgrade_systemd._file_metadata(after)
            != upgrade_systemd._file_metadata(opened)
            or upgrade_systemd._file_metadata(current)
            != upgrade_systemd._file_metadata(opened)
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID")
        return bytes(payload), {
            "device": opened.st_dev,
            "inode": opened.st_ino,
            "mode": stat.S_IMODE(opened.st_mode),
            "size": opened.st_size,
            "uid": opened.st_uid,
        }
    except LauncherError:
        raise
    except OSError as error:
        raise LauncherError("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _safe_private_directory(path: Path, *, create: bool) -> Path:
    if create:
        try:
            path.mkdir(mode=0o700)
            reconciler._fsync_directory(path.parent)
        except FileExistsError:
            pass
        except (OSError, reconciler.ReconcileError) as error:
            raise LauncherError(
                "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
            ) from error
    selected = _canonical_existing(
        path,
        directory=True,
        code="REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID",
    )
    try:
        metadata = selected.lstat()
    except OSError as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    try:
        reconciler._fsync_directory(selected)
        reconciler._fsync_directory(selected.parent)
    except reconciler.ReconcileError as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    return selected


def _read_private(
    path: Path,
    *,
    maximum: int = MAX_FILE_BYTES,
    allowed_links: frozenset[int] = frozenset({1}),
) -> bytes:
    descriptor: int | None = None
    try:
        lexical = path.lstat()
        if (
            path.resolve(strict=True) != path
            or not stat.S_ISREG(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or lexical.st_uid != os.geteuid()
            or lexical.st_nlink not in allowed_links
            or stat.S_IMODE(lexical.st_mode) != 0o600
            or not 0 < lexical.st_size <= maximum
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if upgrade_systemd._file_metadata(opened) != (
            upgrade_systemd._file_metadata(lexical)
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
        payload = bytearray()
        while len(payload) <= maximum:
            block = os.read(descriptor, min(65_536, maximum + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            len(payload) != opened.st_size
            or not payload
            or len(payload) > maximum
            or upgrade_systemd._file_metadata(after)
            != upgrade_systemd._file_metadata(opened)
            or upgrade_systemd._file_metadata(current)
            != upgrade_systemd._file_metadata(opened)
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
        return bytes(payload)
    except LauncherError:
        raise
    except OSError as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _recover_exact_staging(directory: Path, name: str, payload: bytes) -> None:
    pattern = re.compile(
        rf"\.{re.escape(name)}\.next-[0-9]+-[0-9a-f]{{12}}\Z"
    )
    prefix = f".{name}.next-"
    try:
        candidates = [entry for entry in os.listdir(directory) if entry.startswith(prefix)]
    except OSError as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    if any(pattern.fullmatch(entry) is None for entry in candidates) or len(
        candidates
    ) > 1:
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
    if not candidates:
        return
    staging = directory / candidates[0]
    final = directory / name
    try:
        staging_metadata = staging.lstat()
    except OSError as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT"
        ) from error
    if (
        not stat.S_ISREG(staging_metadata.st_mode)
        or stat.S_ISLNK(staging_metadata.st_mode)
        or staging_metadata.st_uid != os.geteuid()
        or staging_metadata.st_nlink not in {1, 2}
        or stat.S_IMODE(staging_metadata.st_mode) != 0o600
        or not 0 <= staging_metadata.st_size <= MAX_FILE_BYTES
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
    try:
        final_metadata = final.lstat()
    except FileNotFoundError:
        if staging_metadata.st_nlink != 1:
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
    else:
        try:
            final_payload = _read_private(
                final,
                allowed_links=frozenset({1, 2}),
            )
        except LauncherError as error:
            raise LauncherError(
                "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT"
            ) from error
        if final_payload != payload:
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
        shared = (staging_metadata.st_dev, staging_metadata.st_ino) == (
            final_metadata.st_dev,
            final_metadata.st_ino,
        )
        if (
            shared
            and not staging_metadata.st_nlink == final_metadata.st_nlink == 2
        ) or (
            not shared
            and not staging_metadata.st_nlink == final_metadata.st_nlink == 1
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
        if shared:
            try:
                staging_payload = _read_private(
                    staging,
                    allowed_links=frozenset({2}),
                )
            except LauncherError as error:
                raise LauncherError(
                    "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT"
                ) from error
            if staging_payload != payload:
                _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
    try:
        staging.unlink()
        reconciler._fsync_directory(directory)
    except (OSError, reconciler.ReconcileError) as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    if final.exists() and _read_private(final) != payload:
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")


def _publish_exact_file(directory: Path, name: str, payload: bytes) -> None:
    if (
        not name
        or "/" in name
        or name in {".", ".."}
        or type(payload) is not bytes
        or not payload
        or len(payload) > MAX_FILE_BYTES
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    final = directory / name
    _recover_exact_staging(directory, name, payload)
    try:
        existing = _read_private(final)
    except LauncherError:
        try:
            final.lstat()
        except FileNotFoundError:
            existing = None
        else:
            raise
    if existing is not None:
        if existing != payload:
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
        try:
            reconciler._fsync_directory(directory)
        except reconciler.ReconcileError as error:
            raise LauncherError(
                "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
            ) from error
        if _read_private(final) != payload:
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
        return
    temporary = directory / f".{name}.next-{os.getpid()}-{os.urandom(6).hex()}"
    descriptor: int | None = None
    temporary_present = False
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        temporary_present = True
        upgrade_systemd._write_all(descriptor, payload)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, final, follow_symlinks=False)
        except FileExistsError:
            if _read_private(final) != payload:
                _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
        os.unlink(temporary)
        temporary_present = False
        reconciler._fsync_directory(directory)
        if _read_private(final) != payload:
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    except LauncherError:
        raise
    except (OSError, reconciler.ReconcileError) as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_present:
            try:
                temporary.unlink()
                reconciler._fsync_directory(directory)
            except FileNotFoundError:
                pass


def _replace_pointer(
    root: Path,
    payload: bytes,
    *,
    expected: bytes | None,
) -> None:
    path = root / CURRENT_FILE
    pattern = re.compile(r"\.current\.json\.next-[0-9]+-[0-9a-f]{12}\Z")
    try:
        drafts = [
            entry
            for entry in os.listdir(root)
            if entry.startswith(f".{CURRENT_FILE}.next-")
        ]
    except OSError as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    if any(pattern.fullmatch(entry) is None for entry in drafts) or len(drafts) > 1:
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
    if drafts:
        draft = root / drafts[0]
        try:
            metadata = draft.lstat()
        except OSError as error:
            raise LauncherError(
                "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 0 <= metadata.st_size <= MAX_FILE_BYTES
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
        try:
            draft.unlink()
            reconciler._fsync_directory(root)
        except (OSError, reconciler.ReconcileError) as error:
            raise LauncherError(
                "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
            ) from error
    if expected is None:
        _publish_exact_file(root, CURRENT_FILE, payload)
        return
    if _read_private(path) == payload:
        try:
            reconciler._fsync_directory(root)
        except reconciler.ReconcileError as error:
            raise LauncherError(
                "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
            ) from error
        return
    if _read_private(path) != expected:
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
    temporary = root / f".{CURRENT_FILE}.next-{os.getpid()}-{os.urandom(6).hex()}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        upgrade_systemd._write_all(descriptor, payload)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if _read_private(path) != expected:
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
        os.replace(temporary, path)
        reconciler._fsync_directory(root)
        if _read_private(path) != payload:
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    except LauncherError:
        raise
    except (OSError, reconciler.ReconcileError) as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _remove_exact_file(directory: Path, name: str, expected: bytes) -> None:
    path = directory / name
    if _read_private(path) != expected:
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
    try:
        path.unlink()
        reconciler._fsync_directory(directory)
    except (OSError, reconciler.ReconcileError) as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    try:
        path.lstat()
    except FileNotFoundError:
        return
    _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")


class BoundedCommandRunner:
    """No-input, bounded subprocess adapter used only by stable bootstrap."""

    def __init__(self, *, home: Path, xdg_runtime_directory: Path) -> None:
        self._environment = {
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "XDG_RUNTIME_DIR": str(xdg_runtime_directory),
        }

    def __call__(self, argv: Sequence[str], *, timeout: float) -> bytes:
        if (
            not isinstance(argv, Sequence)
            or isinstance(argv, (str, bytes))
            or not argv
            or any(not isinstance(value, str) or not value for value in argv)
            or not Path(argv[0]).is_absolute()
            or not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(float(timeout))
            or not 0 < float(timeout) <= MAX_COMMAND_SECONDS
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_COMMAND_FAILED")
        try:
            completed = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=float(timeout),
                env=self._environment,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise LauncherError(
                "REVIEWER_UPGRADE_LAUNCH_COMMAND_FAILED"
            ) from error
        if (
            completed.returncode != 0
            or len(completed.stdout) > MAX_COMMAND_BYTES
            or len(completed.stderr) > MAX_COMMAND_BYTES
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_COMMAND_FAILED")
        return completed.stdout


@dataclass(frozen=True)
class LaunchInputs:
    release_root: Path
    repository: Path
    state_directory: Path
    candidate_compose: Path
    unit_directory: Path
    lock_file: Path
    operation_directory: Path
    serial_lock_file: Path
    config_file: Path
    admin_secret_file: Path
    python: Path
    systemctl: Path
    systemd_analyze: Path
    home: Path
    xdg_runtime_directory: Path
    project: str

    @property
    def template_directory(self) -> Path:
        return self.repository / "services/backend/systemd"

    @property
    def upgrader(self) -> Path:
        return self.repository / (
            "services/backend/scripts/reviewer_upgrade_transaction.py"
        )

    @property
    def state_parent(self) -> Path:
        return self.state_directory.parent

    @property
    def stable_state(self) -> Path:
        return self.state_parent / STABLE_STATE_DIRECTORY

    def validate(self) -> LaunchInputs:
        if bootstrap.PROJECT.fullmatch(self.project) is None:
            _fail("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID")
        for path in (
            self.release_root,
            self.repository,
            self.state_directory,
            self.unit_directory,
            self.operation_directory,
            self.home,
            self.xdg_runtime_directory,
            self.template_directory,
        ):
            _canonical_existing(
                path,
                directory=True,
                code="REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID",
            )
        for path in (
            self.candidate_compose,
            self.config_file,
            self.admin_secret_file,
            self.upgrader,
        ):
            _canonical_existing(
                path,
                directory=False,
                code="REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID",
            )
        for path in (self.python, self.systemctl, self.systemd_analyze):
            _canonical_executable(path)
        if (
            self.systemctl.name != "systemctl"
            or self.systemd_analyze.name != "systemd-analyze"
            or self.serial_lock_file
            != self.state_parent / transaction.SERIAL_LOCK_FILE
            or self.lock_file != reconciler._lock_path(self.project)
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID")
        desired, manifest, _compose = reconciler._load_bound_state(
            self.state_directory
        )
        if (
            desired.get("project") != self.project
            or manifest.get("project") != self.project
            or manifest.get("operation_directory")
            != str(self.operation_directory)
            or manifest.get("config", {}).get("path") != str(self.config_file)
            or manifest.get("secret", {}).get("path")
            != str(self.admin_secret_file)
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID")
        return self

    def stable_bindings(self) -> bootstrap.StableUnitBindings:
        return bootstrap.StableUnitBindings(
            python=self.python,
            upgrader=self.upgrader,
            state_parent=self.state_parent,
            serial_lock_file=self.serial_lock_file,
            unit_directory=self.unit_directory,
            lock_file=self.lock_file,
            operation_directory=self.operation_directory,
            repository=self.repository,
            config_file=self.config_file,
            admin_secret_file=self.admin_secret_file,
            project=self.project,
        )


def _expected_bootstrap_receipt(
    target: bootstrap.StableUnitBundle,
    bindings: bootstrap.StableUnitBindings,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "contract_version": bootstrap.RECEIPT_CONTRACT,
        "path_unit": bootstrap.PATH_UNIT,
        "receipt_digest": "",
        "selector_path": str(bindings.state_parent / "upgrades/active.json"),
        "status": "path_armed_idle",
        "target_unit_digests": target.digests(),
    }
    receipt["receipt_digest"] = _document_digest(receipt, "receipt_digest")
    return receipt


def _repository_record(inputs: LaunchInputs, prepared: Any) -> dict[str, Any]:
    try:
        release_metadata = inputs.release_root.lstat()
        metadata = inputs.repository.lstat()
        upgrader_payload, upgrader_binding = _read_bound_regular(
            inputs.upgrader,
            maximum=MAX_UPGRADER_BYTES,
        )
        candidate_payload, candidate_binding = _read_bound_regular(
            inputs.candidate_compose,
            maximum=reconciler.MAX_DOCUMENT_BYTES,
        )
        python_payload, python_binding = _read_bound_regular(
            inputs.python,
            maximum=MAX_TOOL_BYTES,
        )
        if (
            candidate_binding["mode"] != 0o600
            or candidate_binding["uid"] != os.geteuid()
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID")
    except (OSError, reconciler.ReconcileError, LauncherError) as error:
        if isinstance(error, LauncherError):
            raise
        raise LauncherError("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID") from error
    receipt = getattr(prepared, "receipt", None)
    source_manifest = getattr(prepared, "source_manifest", None)
    runtime_closure = (
        source_manifest.get("runtime_closure")
        if isinstance(source_manifest, dict)
        else None
    )
    reviewer_image = (
        receipt.get("reviewer_image")
        if isinstance(receipt, dict)
        else None
    )
    source_compose = (
        receipt.get("source_compose")
        if isinstance(receipt, dict)
        else None
    )
    tools = receipt.get("tools") if isinstance(receipt, dict) else None
    prepared_python = tools.get("python") if isinstance(tools, dict) else None
    if (
        not isinstance(receipt, dict)
        or not isinstance(source_manifest, dict)
        or not isinstance(runtime_closure, dict)
        or not isinstance(reviewer_image, dict)
        or set(reviewer_image) != {"id", "ref"}
        or not isinstance(reviewer_image.get("id"), str)
        or reconciler.DIGEST.fullmatch(reviewer_image["id"]) is None
        or not isinstance(reviewer_image.get("ref"), str)
        or transaction.REVIEWER_TAG.fullmatch(reviewer_image["ref"]) is None
        or reviewer_image["ref"].rsplit(":", 1)[-1].lower() == "latest"
        or not isinstance(source_compose, dict)
        or set(source_compose) != {"digest", "mode", "path"}
        or not isinstance(source_compose.get("digest"), str)
        or DIGEST.fullmatch(source_compose["digest"]) is None
        or source_compose.get("mode") != 0o400
        or not isinstance(source_compose.get("path"), str)
        or not isinstance(prepared_python, dict)
        or set(prepared_python)
        != {"device", "digest", "inode", "mode", "path", "uid"}
        or prepared_python.get("path") != str(inputs.python)
        or prepared_python.get("digest") != _digest(python_payload)
        or prepared_python.get("device") != python_binding["device"]
        or prepared_python.get("inode") != python_binding["inode"]
        or prepared_python.get("mode") != python_binding["mode"]
        or prepared_python.get("uid") != python_binding["uid"]
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID")
    digests = {
        "preparation_receipt_digest": receipt.get("receipt_digest"),
        "runtime_closure_digest": runtime_closure.get("closure_digest"),
        "source_manifest_digest": source_manifest.get("manifest_digest"),
        "source_tree_digest": source_manifest.get("tree_digest"),
    }
    if any(
        not isinstance(value, str) or DIGEST.fullmatch(value) is None
        for value in digests.values()
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID")
    return {
        "candidate_compose_binding": candidate_binding,
        "candidate_compose_digest": _digest(candidate_payload),
        "candidate_compose_path": str(inputs.candidate_compose),
        **digests,
        "prepared_reviewer_image_id": reviewer_image["id"],
        "prepared_reviewer_image_ref": reviewer_image["ref"],
        "prepared_python_binding": python_binding,
        "prepared_python_digest": prepared_python["digest"],
        "prepared_python_path": prepared_python["path"],
        "prepared_source_compose_digest": source_compose["digest"],
        "prepared_source_compose_path": source_compose["path"],
        "release_root_device": release_metadata.st_dev,
        "release_root_inode": release_metadata.st_ino,
        "release_root_path": str(inputs.release_root),
        "release_root_uid": release_metadata.st_uid,
        "repository_device": metadata.st_dev,
        "repository_inode": metadata.st_ino,
        "repository_path": str(inputs.repository),
        "repository_uid": metadata.st_uid,
        "upgrader_binding": upgrader_binding,
        "upgrader_digest": _digest(upgrader_payload),
        "upgrader_path": str(inputs.upgrader),
    }


def _load_prepared_release(inputs: LaunchInputs) -> tuple[Any, dict[str, Any]]:
    try:
        prepared = prepared_candidate.load_prepared_release(inputs.release_root)
    except prepared_candidate.CandidateError as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID"
        ) from error
    if (
        getattr(prepared, "release_root", None) != inputs.release_root
        or getattr(prepared, "repository", None) != inputs.repository
        or getattr(prepared, "candidate_compose", None)
        != inputs.candidate_compose
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID")
    launch_binding = _repository_record(inputs, prepared)
    try:
        _desired, manifest, source_compose = reconciler._load_bound_state(
            inputs.state_directory
        )
    except reconciler.ReconcileError as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID"
        ) from error
    if (
        launch_binding["prepared_source_compose_path"]
        != str(source_compose)
        or launch_binding["prepared_source_compose_digest"]
        != manifest.get("compose_digest")
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID")
    return prepared, launch_binding


def _snapshot_document(
    launch_binding: Mapping[str, Any],
    target: bootstrap.StableUnitBundle,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "bootstrap_receipt_digest": receipt["receipt_digest"],
        "contract_version": SNAPSHOT_CONTRACT,
        "launch_binding": dict(launch_binding),
        "snapshot_digest": "",
        "target_unit_digests": target.digests(),
    }
    document["snapshot_digest"] = _document_digest(document, "snapshot_digest")
    return document


def _snapshot_id(document: Mapping[str, Any]) -> str:
    digest = document.get("snapshot_digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    value = digest.removeprefix("sha256:")
    if SNAPSHOT_ID.fullmatch(value) is None:
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    return value


def _pointer(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    document: dict[str, Any] = {
        "contract_version": POINTER_CONTRACT,
        "pointer_digest": "",
        "snapshot_digest": snapshot["snapshot_digest"],
        "snapshot_id": _snapshot_id(snapshot),
    }
    document["pointer_digest"] = _document_digest(document, "pointer_digest")
    return document


def _pending(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    document: dict[str, Any] = {
        "contract_version": PENDING_CONTRACT,
        "pending_digest": "",
        "snapshot_digest": snapshot["snapshot_digest"],
        "snapshot_id": _snapshot_id(snapshot),
        "status": "bootstrap_pending",
    }
    document["pending_digest"] = _document_digest(document, "pending_digest")
    return document


def _ensure_evidence_tree(inputs: LaunchInputs) -> tuple[Path, Path, Path]:
    root = _safe_private_directory(inputs.stable_state, create=True)
    snapshots = _safe_private_directory(root / SNAPSHOTS_DIRECTORY, create=True)
    preparations = _safe_private_directory(
        root / PREPARATIONS_DIRECTORY,
        create=True,
    )
    try:
        root_entries = {entry.name for entry in root.iterdir()}
        snapshot_entries = {entry.name for entry in snapshots.iterdir()}
        preparation_entries = {entry.name for entry in preparations.iterdir()}
    except OSError as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    root_allowed = {
        SNAPSHOTS_DIRECTORY,
        PREPARATIONS_DIRECTORY,
        CURRENT_FILE,
        PENDING_FILE,
    }
    root_drafts = {
        entry
        for entry in root_entries
        if entry.startswith(f".{CURRENT_FILE}.next-")
        or entry.startswith(f".{PENDING_FILE}.next-")
    }
    if (
        root_entries - root_allowed - root_drafts
        or any(
            re.fullmatch(
                r"\.(?:current|pending)\.json\.next-[0-9]+-[0-9a-f]{12}",
                entry,
            )
            is None
            for entry in root_drafts
        )
        or sum(entry.startswith(f".{CURRENT_FILE}.next-") for entry in root_drafts)
        > 1
        or sum(entry.startswith(f".{PENDING_FILE}.next-") for entry in root_drafts)
        > 1
        or any(SNAPSHOT_ID.fullmatch(entry) is None for entry in snapshot_entries)
        or any(
            (
                not entry.endswith(".json")
                or transaction.OPERATION_ID.fullmatch(entry[:-5]) is None
            )
            and re.fullmatch(
                r"\.[a-z0-9][a-z0-9-]{0,95}\.json\.next-[0-9]+-[0-9a-f]{12}",
                entry,
            )
            is None
            for entry in preparation_entries
        )
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    return root, snapshots, preparations


def _publish_snapshot(
    snapshots: Path,
    snapshot: Mapping[str, Any],
    receipt: Mapping[str, Any],
    target: bootstrap.StableUnitBundle,
    candidate_payload: bytes,
) -> Path:
    path = _safe_private_directory(
        snapshots / _snapshot_id(snapshot),
        create=True,
    )
    units = _safe_private_directory(path / UNIT_SIDECAR_DIRECTORY, create=True)
    for artifact in target.units:
        _publish_exact_file(units, artifact.name, artifact.payload)
    _publish_exact_file(
        path,
        BOOTSTRAP_RECEIPT_FILE,
        journal.canonical_json(dict(receipt)),
    )
    _publish_exact_file(path, CANDIDATE_COMPOSE_FILE, candidate_payload)
    # The self-digested manifest is deliberately published last.  A crash
    # before this point leaves a resumable, non-authoritative partial snapshot.
    _publish_exact_file(
        path,
        SNAPSHOT_FILE,
        journal.canonical_json(dict(snapshot)),
    )
    try:
        path_entries = {entry.name for entry in path.iterdir()}
        unit_entries = {entry.name for entry in units.iterdir()}
    except OSError as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    first_install_drafts = {
        entry
        for entry in path_entries
        if entry.startswith(f".{FIRST_INSTALL_FILE}.next-")
    }
    if (
        path_entries
        - {
            UNIT_SIDECAR_DIRECTORY,
            BOOTSTRAP_RECEIPT_FILE,
            CANDIDATE_COMPOSE_FILE,
            SNAPSHOT_FILE,
            FIRST_INSTALL_FILE,
        }
        - first_install_drafts
        or len(first_install_drafts) > 1
        or any(
            re.fullmatch(
                r"\.first-install\.json\.next-[0-9]+-[0-9a-f]{12}",
                entry,
            )
            is None
            for entry in first_install_drafts
        )
        or unit_entries != set(bootstrap.UNIT_NAMES)
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    reconciler._fsync_directory(units)
    reconciler._fsync_directory(path)
    reconciler._fsync_directory(snapshots)
    return path


def _parse_document(payload: bytes, *, code: str) -> dict[str, Any]:
    try:
        value = journal.parse_canonical_json(payload)
    except (journal.JournalError, ValueError, TypeError) as error:
        raise LauncherError(code) from error
    if type(value) is not dict or journal.canonical_json(value) != payload:
        _fail(code)
    return value


def _load_snapshot(
    snapshots: Path,
    snapshot_id: str,
) -> tuple[dict[str, Any], dict[str, Any], bootstrap.StableUnitBundle]:
    if SNAPSHOT_ID.fullmatch(snapshot_id) is None:
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    path = _safe_private_directory(snapshots / snapshot_id, create=False)
    units = _safe_private_directory(path / UNIT_SIDECAR_DIRECTORY, create=False)
    snapshot_payload = _read_private(path / SNAPSHOT_FILE)
    receipt_payload = _read_private(path / BOOTSTRAP_RECEIPT_FILE)
    candidate_payload = _read_private(
        path / CANDIDATE_COMPOSE_FILE,
        maximum=reconciler.MAX_DOCUMENT_BYTES,
    )
    snapshot = _parse_document(
        snapshot_payload,
        code="REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID",
    )
    receipt = _parse_document(
        receipt_payload,
        code="REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID",
    )
    if (
        set(snapshot)
        != {
            "bootstrap_receipt_digest",
            "contract_version",
            "launch_binding",
            "snapshot_digest",
            "target_unit_digests",
        }
        or snapshot.get("contract_version") != SNAPSHOT_CONTRACT
        or snapshot.get("snapshot_digest")
        != _document_digest(snapshot, "snapshot_digest")
        or _snapshot_id(snapshot) != snapshot_id
        or snapshot.get("bootstrap_receipt_digest")
        != receipt.get("receipt_digest")
        or receipt.get("contract_version") != bootstrap.RECEIPT_CONTRACT
        or receipt.get("receipt_digest")
        != _document_digest(receipt, "receipt_digest")
        or receipt.get("target_unit_digests")
        != snapshot.get("target_unit_digests")
        or _digest(candidate_payload)
        != snapshot.get("launch_binding", {}).get("candidate_compose_digest")
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    try:
        path_entries = {entry.name for entry in path.iterdir()}
        entries = {entry.name for entry in units.iterdir()}
    except OSError as error:
        raise LauncherError(
            "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
        ) from error
    if (
        path_entries
        - {
            UNIT_SIDECAR_DIRECTORY,
            BOOTSTRAP_RECEIPT_FILE,
            CANDIDATE_COMPOSE_FILE,
            SNAPSHOT_FILE,
            FIRST_INSTALL_FILE,
        }
        or entries != set(bootstrap.UNIT_NAMES)
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    bundle = bootstrap.StableUnitBundle.from_payloads(
        {name: _read_private(units / name) for name in bootstrap.UNIT_NAMES}
    )
    if bundle.digests() != snapshot["target_unit_digests"]:
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    return snapshot, receipt, bundle


def _load_current(
    root: Path,
    snapshots: Path,
) -> tuple[
    bytes,
    dict[str, Any],
    dict[str, Any],
    bootstrap.StableUnitBundle,
] | None:
    path = root / CURRENT_FILE
    try:
        payload = _read_private(path)
    except LauncherError:
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        raise
    pointer = _parse_document(
        payload,
        code="REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID",
    )
    if (
        set(pointer)
        != {"contract_version", "pointer_digest", "snapshot_digest", "snapshot_id"}
        or pointer.get("contract_version") != POINTER_CONTRACT
        or pointer.get("pointer_digest")
        != _document_digest(pointer, "pointer_digest")
        or SNAPSHOT_ID.fullmatch(str(pointer.get("snapshot_id"))) is None
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    snapshot, _receipt, bundle = _load_snapshot(
        snapshots,
        pointer["snapshot_id"],
    )
    if snapshot["snapshot_digest"] != pointer["snapshot_digest"]:
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    return payload, pointer, snapshot, bundle


def _load_pending(root: Path) -> tuple[bytes, dict[str, Any]] | None:
    path = root / PENDING_FILE
    try:
        payload = _read_private(path)
    except LauncherError:
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        raise
    document = _parse_document(
        payload,
        code="REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID",
    )
    if (
        set(document)
        != {
            "contract_version",
            "pending_digest",
            "snapshot_digest",
            "snapshot_id",
            "status",
        }
        or document.get("contract_version") != PENDING_CONTRACT
        or document.get("pending_digest")
        != _document_digest(document, "pending_digest")
        or SNAPSHOT_ID.fullmatch(str(document.get("snapshot_id"))) is None
        or document.get("status") != "bootstrap_pending"
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    return payload, document


def _first_install_proof(snapshot_path: Path, snapshot_digest: str) -> None:
    document: dict[str, Any] = {
        "contract_version": FIRST_INSTALL_CONTRACT,
        "proof_digest": "",
        "snapshot_digest": snapshot_digest,
        "status": "installed_names_absent",
    }
    document["proof_digest"] = _document_digest(document, "proof_digest")
    _publish_exact_file(
        snapshot_path,
        FIRST_INSTALL_FILE,
        journal.canonical_json(document),
    )


def _has_first_install_proof(snapshot_path: Path, snapshot_digest: str) -> bool:
    path = snapshot_path / FIRST_INSTALL_FILE
    try:
        payload = _read_private(path)
    except LauncherError:
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        raise
    document = _parse_document(
        payload,
        code="REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID",
    )
    return document == {
        "contract_version": FIRST_INSTALL_CONTRACT,
        "proof_digest": _document_digest(document, "proof_digest"),
        "snapshot_digest": snapshot_digest,
        "status": "installed_names_absent",
    }


def _require_classifications(
    values: Sequence[bootstrap.InstalledClassification],
    allowed: set[bootstrap.InstalledState],
) -> None:
    if (
        len(values) != len(bootstrap.UNIT_NAMES)
        or any(value.state not in allowed for value in values)
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_CURRENT_UNITS_INVALID")


def _validate_prepare_result(value: Any) -> dict[str, str]:
    if (
        type(value) is not dict
        or set(value) != {"code", "operation_id", "phase", "status"}
        or value.get("code") != "REVIEWER_UPGRADE_PREPARED"
        or transaction.OPERATION_ID.fullmatch(str(value.get("operation_id")))
        is None
        or value.get("phase") != transaction.QUIESCING
        or value.get("status") != "quiescing"
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_PREPARE_INVALID")
    return dict(value)


def _prove_prepared_plan(
    upgrades: Path,
    active: Mapping[str, str],
    *,
    operation_id: str,
    candidate_digest: str,
    candidate_repository_root: Path,
    candidate_image_ref: str,
    candidate_image_id: str,
) -> str:
    try:
        transaction_path, plan_document, plan, _progress = (
            transaction._load_transaction(upgrades, active)
        )
        transaction._candidate_compose(transaction_path, plan)
    except transaction.UpgradeError as error:
        raise LauncherError("REVIEWER_UPGRADE_LAUNCH_PREPARE_INVALID") from error
    if (
        plan_document.get("plan_digest") != active.get("plan_digest")
        or plan.get("operation_id") != operation_id
        or plan.get("candidate_compose_digest") != candidate_digest
        or plan.get("candidate_repository_root")
        != str(candidate_repository_root)
        or plan.get("candidate_image_ref") != candidate_image_ref
        or plan.get("candidate_image_id") != candidate_image_id
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_PREPARE_INVALID")
    return str(plan_document["plan_digest"])


def _publish_preparation(
    preparations: Path,
    snapshot: Mapping[str, Any],
    candidate_digest: str,
    result: Mapping[str, str],
    state_parent: Path,
    candidate_repository_root: Path,
    candidate_image_ref: str,
    candidate_image_id: str,
) -> dict[str, Any]:
    upgrades = transaction._existing_upgrades_directory(state_parent)
    if upgrades is None:
        _fail("REVIEWER_UPGRADE_LAUNCH_PREPARE_INVALID")
    active = transaction._load_active(upgrades, optional=False)
    if active is None or active.get("operation_id") != result["operation_id"]:
        _fail("REVIEWER_UPGRADE_LAUNCH_PREPARE_INVALID")
    plan_digest = _prove_prepared_plan(
        upgrades,
        active,
        operation_id=result["operation_id"],
        candidate_digest=candidate_digest,
        candidate_repository_root=candidate_repository_root,
        candidate_image_ref=candidate_image_ref,
        candidate_image_id=candidate_image_id,
    )
    receipt: dict[str, Any] = {
        "candidate_compose_digest": candidate_digest,
        "contract_version": PREPARATION_CONTRACT,
        "operation_id": result["operation_id"],
        "plan_digest": plan_digest,
        "preparation_digest": "",
        "snapshot_digest": snapshot["snapshot_digest"],
    }
    receipt["preparation_digest"] = _document_digest(
        receipt,
        "preparation_digest",
    )
    _publish_exact_file(
        preparations,
        f"{result['operation_id']}.json",
        journal.canonical_json(receipt),
    )
    return receipt


def _active_document(state_parent: Path) -> tuple[Path, dict[str, str]] | None:
    upgrades = transaction._existing_upgrades_directory(state_parent)
    if upgrades is None:
        return None
    active = transaction._load_active(upgrades, optional=True)
    if active is None:
        return None
    return upgrades, active


def _recover_prepared_launch(
    inputs: LaunchInputs,
    root: Path,
    snapshots: Path,
    preparations: Path,
    current: tuple[
        bytes,
        dict[str, Any],
        dict[str, Any],
        bootstrap.StableUnitBundle,
    ] | None,
    target: bootstrap.StableUnitBundle,
    snapshot: Mapping[str, Any],
    expected_receipt: Mapping[str, Any],
    pending_payload: bytes,
    active_state: tuple[Path, dict[str, str]],
    serial_descriptor: int,
) -> dict[str, str]:
    _prepared, current_launch_binding = _load_prepared_release(inputs)
    if (
        current is None
        or current[2] != snapshot
        or current[3] != target
        or current_launch_binding != snapshot["launch_binding"]
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_ACTIVE_MISMATCH")
    pending = _load_pending(root)
    if pending is not None and pending[0] != pending_payload:
        _fail("REVIEWER_UPGRADE_LAUNCH_ACTIVE_MISMATCH")
    upgrades, active = active_state
    try:
        transaction_path, plan_document, plan, progress = (
            transaction._load_transaction(upgrades, active)
        )
        transaction._candidate_compose(transaction_path, plan)
        serial_binding = reconciler._validate_lock_descriptor(
            serial_descriptor,
            inputs.serial_lock_file,
        )
    except (transaction.UpgradeError, reconciler.ReconcileError) as error:
        raise LauncherError("REVIEWER_UPGRADE_LAUNCH_ACTIVE_MISMATCH") from error
    finalize_plan = plan.get("finalize")
    reconcile_bindings = (
        finalize_plan.get("reconcile_bindings")
        if isinstance(finalize_plan, dict)
        else None
    )
    binding = snapshot["launch_binding"]
    if (
        plan_document.get("plan_digest") != active.get("plan_digest")
        or plan.get("candidate_compose_digest")
        != binding["candidate_compose_digest"]
        or plan.get("operation_id") != active.get("operation_id")
        or plan.get("project") != inputs.project
        or plan.get("source_state_directory") != str(inputs.state_directory)
        or plan.get("candidate_repository_root") != str(inputs.repository)
        or plan.get("candidate_image_ref")
        != binding["prepared_reviewer_image_ref"]
        or plan.get("candidate_image_id")
        != binding["prepared_reviewer_image_id"]
        or plan.get("serial_lock") != serial_binding
        or not isinstance(finalize_plan, dict)
        or finalize_plan.get("unit_directory") != str(inputs.unit_directory)
        or not isinstance(reconcile_bindings, dict)
        or reconcile_bindings.get("config_file") != str(inputs.config_file)
        or reconcile_bindings.get("admin_secret_file")
        != str(inputs.admin_secret_file)
        or reconcile_bindings.get("lock_file") != str(inputs.lock_file)
        or reconcile_bindings.get("operation_directory")
        != str(inputs.operation_directory)
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_ACTIVE_MISMATCH")
    _require_classifications(
        bootstrap.classify_installed_stable_units(
            inputs.unit_directory,
            current[3],
            target,
        ),
        {bootstrap.InstalledState.TARGET},
    )
    sealed_snapshot, sealed_receipt, sealed_bundle = _load_snapshot(
        snapshots,
        _snapshot_id(snapshot),
    )
    if (
        sealed_snapshot != snapshot
        or sealed_receipt != expected_receipt
        or sealed_bundle != target
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
    if pending is not None:
        _remove_exact_file(root, PENDING_FILE, pending_payload)
    result = {
        "code": "REVIEWER_UPGRADE_PREPARED",
        "operation_id": str(active["operation_id"]),
        "phase": str(progress["phase"]),
        "status": str(progress["phase"]),
    }
    preparation = _publish_preparation(
        preparations,
        snapshot,
        binding["candidate_compose_digest"],
        result,
        inputs.state_parent,
        inputs.repository,
        binding["prepared_reviewer_image_ref"],
        binding["prepared_reviewer_image_id"],
    )
    return {
        "bootstrap_receipt_digest": str(expected_receipt["receipt_digest"]),
        "code": LAUNCH_CODE,
        "operation_id": result["operation_id"],
        "phase": result["phase"],
        "preparation_digest": str(preparation["preparation_digest"]),
        "snapshot_digest": str(snapshot["snapshot_digest"]),
        "status": result["status"],
    }


def launch(
    inputs: LaunchInputs,
    *,
    current_units: str,
    path_deadline_seconds: float = 15.0,
    runner: Runner | None = None,
) -> dict[str, str]:
    """Bootstrap stable units and publish one prepared transaction atomically."""

    if not isinstance(inputs, LaunchInputs) or current_units not in CURRENT_MODES:
        _fail("REVIEWER_UPGRADE_LAUNCH_INPUT_INVALID")
    inputs = inputs.validate()
    _prepared, launch_binding = _load_prepared_release(inputs)
    bindings = inputs.stable_bindings()
    target = bootstrap.render_stable_unit_bundle(
        inputs.template_directory,
        bindings,
    )
    expected_receipt = _expected_bootstrap_receipt(target, bindings)
    snapshot = _snapshot_document(launch_binding, target, expected_receipt)
    candidate_digest = snapshot["launch_binding"]["candidate_compose_digest"]
    candidate_payload, candidate_binding = _read_bound_regular(
        inputs.candidate_compose,
        maximum=reconciler.MAX_DOCUMENT_BYTES,
    )
    if (
        _digest(candidate_payload) != candidate_digest
        or candidate_binding
        != snapshot["launch_binding"]["candidate_compose_binding"]
    ):
        _fail("REVIEWER_UPGRADE_LAUNCH_INPUT_CHANGED")
    commands = manager.ManagerBinaries(inputs.systemctl, inputs.systemd_analyze)
    selected_runner = runner or BoundedCommandRunner(
        home=inputs.home,
        xdg_runtime_directory=inputs.xdg_runtime_directory,
    )

    descriptor, serial_binding = bootstrap._acquire_serial_lock(bindings)
    try:
        root, snapshots, preparations = _ensure_evidence_tree(inputs)
        current = _load_current(root, snapshots)
        pending_payload = journal.canonical_json(_pending(snapshot))
        active_state = _active_document(inputs.state_parent)
        if active_state is not None:
            return _recover_prepared_launch(
                inputs,
                root,
                snapshots,
                preparations,
                current,
                target,
                snapshot,
                expected_receipt,
                pending_payload,
                active_state,
                descriptor,
            )
        bootstrap._require_active_absent(inputs.state_parent)
        recovering_first_install = False
        if current_units == "absent" and current is not None:
            snapshot_path = snapshots / _snapshot_id(snapshot)
            recovering_first_install = (
                current[2] == snapshot
                and current[3] == target
                and _has_first_install_proof(
                    snapshot_path,
                    snapshot["snapshot_digest"],
                )
            )
            if not recovering_first_install:
                _fail("REVIEWER_UPGRADE_LAUNCH_CURRENT_UNITS_INVALID")
        elif current_units == "managed" and current is None:
            _fail("REVIEWER_UPGRADE_LAUNCH_CURRENT_UNITS_INVALID")
        previous_payload = None if current is None else current[0]
        old_bundle = None if current is None else current[3]
        snapshot_path = _publish_snapshot(
            snapshots,
            snapshot,
            expected_receipt,
            target,
            candidate_payload,
        )
        pending = _load_pending(root)
        if pending is None:
            _publish_exact_file(root, PENDING_FILE, pending_payload)
        elif pending[0] != pending_payload:
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_CONFLICT")
        classifications = bootstrap.classify_installed_stable_units(
            inputs.unit_directory,
            old_bundle,
            target,
        )
        if current is None:
            if not _has_first_install_proof(
                snapshot_path,
                snapshot["snapshot_digest"],
            ):
                _require_classifications(
                    classifications,
                    {bootstrap.InstalledState.ABSENT},
                )
                _first_install_proof(
                    snapshot_path,
                    snapshot["snapshot_digest"],
                )
            else:
                _require_classifications(
                    classifications,
                    {
                        bootstrap.InstalledState.ABSENT,
                        bootstrap.InstalledState.TARGET,
                    },
                )
        else:
            _require_classifications(
                classifications,
                {
                    bootstrap.InstalledState.ABSENT,
                    bootstrap.InstalledState.OLD,
                    bootstrap.InstalledState.TARGET,
                },
            )
        sealed_snapshot, sealed_receipt, sealed_bundle = _load_snapshot(
            snapshots,
            _snapshot_id(snapshot),
        )
        if (
            sealed_snapshot != snapshot
            or sealed_receipt != expected_receipt
            or sealed_bundle != target
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
        receipt = bootstrap._bootstrap_prepublication_locked(
            inputs.template_directory,
            bindings,
            old_bundle,
            commands,
            selected_runner,
            serial_descriptor=descriptor,
            serial_binding=serial_binding,
            target_bundle=sealed_bundle,
            path_deadline_seconds=path_deadline_seconds,
        )
        if receipt != expected_receipt:
            _fail("REVIEWER_UPGRADE_LAUNCH_BOOTSTRAP_RECEIPT_INVALID")
        bootstrap._require_active_absent(inputs.state_parent)
        _require_classifications(
            bootstrap.classify_installed_stable_units(
                inputs.unit_directory,
                old_bundle,
                target,
            ),
            {bootstrap.InstalledState.TARGET},
        )
        # Re-read the immutable evidence and receipt immediately before the
        # pointer and transaction publications.
        sealed_snapshot, sealed_receipt, sealed_bundle = _load_snapshot(
            snapshots,
            _snapshot_id(snapshot),
        )
        if (
            sealed_snapshot != snapshot
            or sealed_receipt != expected_receipt
            or sealed_bundle != target
        ):
            _fail("REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID")
        pointer_payload = journal.canonical_json(_pointer(snapshot))
        _replace_pointer(root, pointer_payload, expected=previous_payload)
        _remove_exact_file(root, PENDING_FILE, pending_payload)
        bootstrap._require_active_absent(inputs.state_parent)
        _require_classifications(
            bootstrap.classify_installed_stable_units(
                inputs.unit_directory,
                target,
                target,
            ),
            {bootstrap.InstalledState.TARGET},
        )
        # This proof is deliberately the last read before transaction.prepare:
        # the candidate loader re-proves the complete sealed source tree,
        # Compose authority relocation, and preparation receipt.
        _prepared, current_launch_binding = _load_prepared_release(inputs)
        if current_launch_binding != snapshot["launch_binding"]:
            _fail("REVIEWER_UPGRADE_LAUNCH_INPUT_CHANGED")
        result = _validate_prepare_result(
            transaction.prepare(
                inputs.state_directory,
                snapshot_path / CANDIDATE_COMPOSE_FILE,
                unit_directory=inputs.unit_directory,
                lock_file=inputs.lock_file,
                operation_directory=inputs.operation_directory,
                serial_lock_file=inputs.serial_lock_file,
                serial_lock_descriptor=descriptor,
                expected_candidate_image_ref=snapshot["launch_binding"][
                    "prepared_reviewer_image_ref"
                ],
                expected_candidate_image_id=snapshot["launch_binding"][
                    "prepared_reviewer_image_id"
                ],
            )
        )
        preparation = _publish_preparation(
            preparations,
            snapshot,
            candidate_digest,
            result,
            inputs.state_parent,
            inputs.repository,
            snapshot["launch_binding"]["prepared_reviewer_image_ref"],
            snapshot["launch_binding"]["prepared_reviewer_image_id"],
        )
        return {
            "bootstrap_receipt_digest": expected_receipt["receipt_digest"],
            "code": LAUNCH_CODE,
            "operation_id": result["operation_id"],
            "phase": result["phase"],
            "preparation_digest": preparation["preparation_digest"],
            "snapshot_digest": snapshot["snapshot_digest"],
            "status": result["status"],
        }
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("launch")
    for name in (
        "release-root",
        "repository",
        "state-directory",
        "candidate-compose",
        "unit-directory",
        "lock-file",
        "operation-directory",
        "serial-lock-file",
        "config-file",
        "admin-secret-file",
        "python",
        "systemctl",
        "systemd-analyze",
        "home",
        "xdg-runtime-directory",
    ):
        command.add_argument(f"--{name}", required=True, type=Path)
    command.add_argument("--project", required=True)
    command.add_argument(
        "--current-units",
        required=True,
        choices=tuple(sorted(CURRENT_MODES)),
    )
    command.add_argument("--path-deadline-seconds", type=float, default=15.0)
    return parser


def _exit_status(code: str) -> int:
    if code in {
        "UPGRADE_BOOTSTRAP_CONTENDED",
        "UPGRADE_BOOTSTRAP_PATH_ARM_FAILED",
        "UPGRADE_BOOTSTRAP_PATH_NOT_READY",
        "UPGRADE_BOOTSTRAP_RELOAD_FAILED",
        "UPGRADE_BOOTSTRAP_RESUMER_NOT_IDLE",
        "UPGRADE_BOOTSTRAP_SYNTAX_FAILED",
        "REVIEWER_UPGRADE_LAUNCH_COMMAND_FAILED",
    }:
        return 1
    return transaction._failure_exit_status(code)


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    try:
        args = _parser().parse_args(argv)
        result = launch(
            LaunchInputs(
                release_root=args.release_root,
                repository=args.repository,
                state_directory=args.state_directory,
                candidate_compose=args.candidate_compose,
                unit_directory=args.unit_directory,
                lock_file=args.lock_file,
                operation_directory=args.operation_directory,
                serial_lock_file=args.serial_lock_file,
                config_file=args.config_file,
                admin_secret_file=args.admin_secret_file,
                python=args.python,
                systemctl=args.systemctl,
                systemd_analyze=args.systemd_analyze,
                home=args.home,
                xdg_runtime_directory=args.xdg_runtime_directory,
                project=args.project,
            ),
            current_units=args.current_units,
            path_deadline_seconds=args.path_deadline_seconds,
        )
        sys.stdout.buffer.write(journal.canonical_json(result) + b"\n")
        return 0
    except LauncherError as error:
        code = error.code
    except bootstrap.BootstrapError as error:
        code = error.code
    except transaction.UpgradeError as error:
        code = error.code
    except reconciler.ReconcileError as error:
        code = error.code
    except (OSError, ValueError, TypeError):
        code = "REVIEWER_UPGRADE_LAUNCH_FAILED"
    sys.stderr.buffer.write(
        journal.canonical_json({"code": code, "status": "failed"}) + b"\n"
    )
    return _exit_status(code)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BoundedCommandRunner",
    "LaunchInputs",
    "LauncherError",
    "launch",
    "main",
]
