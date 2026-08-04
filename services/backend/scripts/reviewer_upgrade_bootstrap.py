#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Crash-safe pre-publication bootstrap for stable reviewer-upgrade units.

This boundary installs only the stable lock, resumer, and selector path units.
It never publishes transaction state.  Every accepted interruption leaves each
final unit name absent or equal to the exact known-old or rendered-target
payload, with at most one strictly recognized target staging file per unit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Callable, Mapping, NoReturn, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import reviewer_upgrade_manager as manager  # noqa: E402
import reviewer_upgrade_systemd as upgrade_systemd  # noqa: E402


LOCK_UNIT = "tacua-reviewer-upgrade-lock.service"
RESUME_UNIT = "tacua-reviewer-upgrade-resume.service"
PATH_UNIT = "tacua-reviewer-upgrade-resume.path"
UNIT_NAMES = (LOCK_UNIT, RESUME_UNIT, PATH_UNIT)
TEMPLATE_NAMES = {
    LOCK_UNIT: "tacua-reviewer-upgrade-lock.service.in",
    RESUME_UNIT: "tacua-reviewer-upgrade-resume.service.in",
    PATH_UNIT: "tacua-reviewer-upgrade-resume.path.in",
}
TOKENS = (
    "@PYTHON@",
    "@UPGRADER@",
    "@STATE_PARENT@",
    "@SERIAL_LOCK_FILE@",
    "@UNIT_DIRECTORY@",
    "@LOCK_FILE@",
    "@OPERATION_DIRECTORY@",
    "@REPOSITORY@",
    "@CONFIG_FILE@",
    "@ADMIN_SECRET_FILE@",
    "@PROJECT@",
)
EXPECTED_TOKEN_COUNTS = {
    TEMPLATE_NAMES[LOCK_UNIT]: (2, 2, 0, 2, 0, 2, 0, 0, 0, 0, 2),
    TEMPLATE_NAMES[RESUME_UNIT]: (2, 3, 3, 3, 3, 3, 3, 2, 2, 2, 0),
    TEMPLATE_NAMES[PATH_UNIT]: (0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0),
}
PLACEHOLDER = re.compile(r"@[A-Z][A-Z0-9_]*@")
PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
STAGING_SUFFIX = re.compile(r"[0-9]+-[0-9a-f]{12}\Z")
RECEIPT_CONTRACT = "tacua.reviewer-upgrade-bootstrap-receipt@1.0.0"
MAX_UNIT_BYTES = 64 * 1024
MAX_COMMAND_BYTES = 64 * 1024
MAX_WAIT_SECONDS = 120.0

Runner = Callable[..., bytes]


class BootstrapError(RuntimeError):
    """Stable, content-free bootstrap failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str = "UPGRADE_BOOTSTRAP_INVALID") -> NoReturn:
    raise BootstrapError(code)


def _validated_path(value: Path) -> str:
    try:
        rendered = upgrade_systemd._validated_systemd_path(value)
    except upgrade_systemd.UnitContractError as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_BINDING_INVALID") from error
    if value.name in {"", ".", ".."}:
        _fail("UPGRADE_BOOTSTRAP_BINDING_INVALID")
    return rendered


@dataclass(frozen=True)
class StableUnitBindings:
    python: Path
    upgrader: Path
    state_parent: Path
    serial_lock_file: Path
    unit_directory: Path
    lock_file: Path
    operation_directory: Path
    repository: Path
    config_file: Path
    admin_secret_file: Path
    project: str

    def replacements(self) -> dict[str, str]:
        paths = (
            self.python,
            self.upgrader,
            self.state_parent,
            self.serial_lock_file,
            self.unit_directory,
            self.lock_file,
            self.operation_directory,
            self.repository,
            self.config_file,
            self.admin_secret_file,
        )
        if not isinstance(self.project, str) or PROJECT.fullmatch(
            self.project
        ) is None:
            _fail("UPGRADE_BOOTSTRAP_BINDING_INVALID")
        if self.serial_lock_file != self.state_parent / "reviewer-upgrade.lock":
            _fail("UPGRADE_BOOTSTRAP_BINDING_INVALID")
        values = tuple(_validated_path(path) for path in paths)
        return {
            token: value
            for token, value in zip(TOKENS[:-1], values, strict=True)
        } | {"@PROJECT@": self.project}


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class StableUnitArtifact:
    name: str
    payload: bytes
    digest: str

    def __post_init__(self) -> None:
        if (
            self.name not in UNIT_NAMES
            or type(self.payload) is not bytes
            or not self.payload
            or len(self.payload) > MAX_UNIT_BYTES
            or self.digest != _digest(self.payload)
        ):
            _fail("UPGRADE_BOOTSTRAP_BUNDLE_INVALID")


@dataclass(frozen=True)
class StableUnitBundle:
    units: tuple[StableUnitArtifact, ...]

    def __post_init__(self) -> None:
        if (
            type(self.units) is not tuple
            or any(
                not isinstance(item, StableUnitArtifact)
                for item in self.units
            )
            or tuple(item.name for item in self.units) != UNIT_NAMES
        ):
            _fail("UPGRADE_BOOTSTRAP_BUNDLE_INVALID")

    @classmethod
    def from_payloads(
        cls,
        payloads: Mapping[str, bytes],
    ) -> StableUnitBundle:
        if not isinstance(payloads, Mapping) or set(payloads) != set(
            UNIT_NAMES
        ) or any(
            type(payloads[name]) is not bytes
            or not payloads[name]
            or len(payloads[name]) > MAX_UNIT_BYTES
            for name in UNIT_NAMES
        ):
            _fail("UPGRADE_BOOTSTRAP_BUNDLE_INVALID")
        return cls(
            tuple(
                StableUnitArtifact(name, payloads[name], _digest(payloads[name]))
                for name in UNIT_NAMES
            )
        )

    def artifact(self, name: str) -> StableUnitArtifact:
        for artifact in self.units:
            if artifact.name == name:
                return artifact
        _fail("UPGRADE_BOOTSTRAP_BUNDLE_INVALID")

    def digests(self) -> dict[str, str]:
        return {item.name: item.digest for item in self.units}


class InstalledState(str, Enum):
    ABSENT = "absent"
    OLD = "old"
    TARGET = "target"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class InstalledClassification:
    name: str
    state: InstalledState
    digest: str | None


def render_stable_units(
    templates: Mapping[str, bytes],
    bindings: StableUnitBindings,
) -> StableUnitBundle:
    """Render the exact three-template ABI without filesystem access."""

    if not isinstance(bindings, StableUnitBindings) or set(templates) != set(
        TEMPLATE_NAMES.values()
    ):
        _fail("UPGRADE_BOOTSTRAP_TEMPLATE_INVALID")
    replacements = bindings.replacements()
    payloads: dict[str, bytes] = {}
    for unit_name in UNIT_NAMES:
        template_name = TEMPLATE_NAMES[unit_name]
        payload = templates[template_name]
        if (
            type(payload) is not bytes
            or not payload
            or len(payload) > MAX_UNIT_BYTES
        ):
            _fail("UPGRADE_BOOTSTRAP_TEMPLATE_INVALID")
        try:
            document = payload.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise BootstrapError(
                "UPGRADE_BOOTSTRAP_TEMPLATE_INVALID"
            ) from error
        counts = tuple(document.count(token) for token in TOKENS)
        if counts != EXPECTED_TOKEN_COUNTS[template_name]:
            _fail("UPGRADE_BOOTSTRAP_TEMPLATE_INVALID")
        expected_tokens = {
            token
            for token, count in zip(TOKENS, counts, strict=True)
            if count
        }
        if set(PLACEHOLDER.findall(document)) != expected_tokens:
            _fail("UPGRADE_BOOTSTRAP_TEMPLATE_INVALID")
        for token, replacement in replacements.items():
            document = document.replace(token, replacement)
        if PLACEHOLDER.search(document) is not None:
            _fail("UPGRADE_BOOTSTRAP_TEMPLATE_INVALID")
        payloads[unit_name] = document.encode("utf-8")
    return StableUnitBundle.from_payloads(payloads)


def _safe_template(
    directory_descriptor: int,
    name: str,
) -> bytes:
    descriptor: int | None = None
    try:
        lexical = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(lexical.st_mode)
            or lexical.st_uid not in {0, os.geteuid()}
            or lexical.st_nlink != 1
            or stat.S_IMODE(lexical.st_mode) & 0o022
            or not 0 < lexical.st_size <= MAX_UNIT_BYTES
        ):
            _fail("UPGRADE_BOOTSTRAP_TEMPLATE_INVALID")
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        opened = os.fstat(descriptor)
        if upgrade_systemd._file_metadata(opened) != (
            upgrade_systemd._file_metadata(lexical)
        ):
            _fail("UPGRADE_BOOTSTRAP_TEMPLATE_INVALID")
        payload = upgrade_systemd._read_bounded(descriptor)
        after = os.fstat(descriptor)
        current = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            len(payload) != opened.st_size
            or upgrade_systemd._file_metadata(after)
            != upgrade_systemd._file_metadata(opened)
            or upgrade_systemd._file_metadata(current)
            != upgrade_systemd._file_metadata(opened)
        ):
            _fail("UPGRADE_BOOTSTRAP_TEMPLATE_INVALID")
        return payload
    except BootstrapError:
        raise
    except (OSError, upgrade_systemd.UnitContractError) as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_TEMPLATE_INVALID") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def render_stable_unit_bundle(
    template_directory: Path,
    bindings: StableUnitBindings,
) -> StableUnitBundle:
    """Read and render the exact stable templates through a pinned directory."""

    try:
        descriptor, directory_binding = (
            upgrade_systemd._validated_template_directory(template_directory)
        )
    except upgrade_systemd.UnitContractError as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_TEMPLATE_INVALID") from error
    try:
        templates: dict[str, bytes] = {}
        for name in TEMPLATE_NAMES.values():
            upgrade_systemd._require_same_directory(
                descriptor,
                template_directory,
                directory_binding,
                code="UPGRADE_BOOTSTRAP_TEMPLATE_INVALID",
                allowed_leaf_uids={0, os.geteuid()},
            )
            templates[name] = _safe_template(descriptor, name)
        return render_stable_units(templates, bindings)
    except upgrade_systemd.UnitContractError as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_TEMPLATE_INVALID") from error
    finally:
        os.close(descriptor)


def _read_unit_entry(
    directory_descriptor: int,
    name: str,
    *,
    allow_missing: bool,
    allowed_links: set[int] = {1},
) -> tuple[bytes, os.stat_result] | None:
    descriptor: int | None = None
    try:
        try:
            lexical = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            if allow_missing:
                return None
            raise
        if (
            not stat.S_ISREG(lexical.st_mode)
            or lexical.st_uid != os.geteuid()
            or lexical.st_nlink not in allowed_links
            or stat.S_IMODE(lexical.st_mode) != 0o600
            or lexical.st_size > MAX_UNIT_BYTES
        ):
            _fail("UPGRADE_BOOTSTRAP_UNIT_UNSAFE")
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        opened = os.fstat(descriptor)
        if upgrade_systemd._file_metadata(opened) != (
            upgrade_systemd._file_metadata(lexical)
        ):
            _fail("UPGRADE_BOOTSTRAP_UNIT_UNSAFE")
        payload = upgrade_systemd._read_bounded(descriptor)
        after = os.fstat(descriptor)
        current = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            len(payload) != opened.st_size
            or upgrade_systemd._file_metadata(after)
            != upgrade_systemd._file_metadata(opened)
            or upgrade_systemd._file_metadata(current)
            != upgrade_systemd._file_metadata(opened)
        ):
            _fail("UPGRADE_BOOTSTRAP_UNIT_UNSAFE")
        return payload, opened
    except BootstrapError:
        raise
    except (OSError, upgrade_systemd.UnitContractError) as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_UNIT_UNSAFE") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _staging_pattern(name: str) -> re.Pattern[str]:
    return re.compile(rf"\.{re.escape(name)}\.next-{STAGING_SUFFIX.pattern}")


def _scan_staging(
    descriptor: int,
) -> dict[str, str | None]:
    try:
        entries = os.listdir(descriptor)
    except OSError as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_UNIT_UNSAFE") from error
    result: dict[str, str | None] = {name: None for name in UNIT_NAMES}
    for entry in entries:
        matched: str | None = None
        for name in UNIT_NAMES:
            if not entry.startswith(f".{name}.next-"):
                continue
            if _staging_pattern(name).fullmatch(entry) is None:
                _fail("UPGRADE_BOOTSTRAP_UNIT_UNKNOWN")
            matched = name
            break
        if matched is None:
            continue
        if result[matched] is not None:
            _fail("UPGRADE_BOOTSTRAP_UNIT_UNKNOWN")
        result[matched] = entry
    return result


@dataclass(frozen=True)
class _Snapshot:
    classifications: tuple[InstalledClassification, ...]
    staging_names: Mapping[str, str | None]
    staging_payloads: Mapping[str, bytes]
    shared_staging: frozenset[str]


@dataclass(frozen=True)
class _SerialLockBinding:
    metadata: tuple[int, ...]


def _classify_payload(
    name: str,
    payload: bytes | None,
    old: StableUnitBundle | None,
    target: StableUnitBundle,
) -> InstalledClassification:
    if payload is None:
        state = InstalledState.ABSENT
    elif payload == target.artifact(name).payload:
        state = InstalledState.TARGET
    elif old is not None and payload == old.artifact(name).payload:
        state = InstalledState.OLD
    else:
        state = InstalledState.UNKNOWN
    return InstalledClassification(
        name,
        state,
        None if payload is None else _digest(payload),
    )


def _snapshot(
    descriptor: int,
    old: StableUnitBundle | None,
    target: StableUnitBundle,
) -> _Snapshot:
    staging_names = _scan_staging(descriptor)
    final_values: dict[str, tuple[bytes, os.stat_result] | None] = {}
    for name in UNIT_NAMES:
        final_values[name] = _read_unit_entry(
            descriptor,
            name,
            allow_missing=True,
            allowed_links={1, 2},
        )
    staging_payloads: dict[str, bytes] = {}
    staging_metadata: dict[str, os.stat_result] = {}
    for name, staging_name in staging_names.items():
        if staging_name is None:
            continue
        value = _read_unit_entry(
            descriptor,
            staging_name,
            allow_missing=False,
            allowed_links={1, 2},
        )
        if value is None:  # pragma: no cover - allow_missing is false.
            _fail("UPGRADE_BOOTSTRAP_UNIT_UNSAFE")
        staging_payloads[name], staging_metadata[name] = value
        if not target.artifact(name).payload.startswith(
            staging_payloads[name]
        ):
            _fail("UPGRADE_BOOTSTRAP_UNIT_UNKNOWN")
    shared: set[str] = set()
    classifications: list[InstalledClassification] = []
    for name in UNIT_NAMES:
        final = final_values[name]
        payload = None if final is None else final[0]
        metadata = None if final is None else final[1]
        staging_name = staging_names[name]
        if metadata is not None and metadata.st_nlink == 2:
            if (
                staging_name is None
                or staging_metadata[name].st_nlink != 2
                or (metadata.st_dev, metadata.st_ino)
                != (
                    staging_metadata[name].st_dev,
                    staging_metadata[name].st_ino,
                )
                or payload != target.artifact(name).payload
                or staging_payloads[name] != payload
            ):
                _fail("UPGRADE_BOOTSTRAP_UNIT_UNSAFE")
            shared.add(name)
        elif staging_name is not None and staging_metadata[name].st_nlink != 1:
            _fail("UPGRADE_BOOTSTRAP_UNIT_UNSAFE")
        classifications.append(_classify_payload(name, payload, old, target))
    if any(item.state is InstalledState.UNKNOWN for item in classifications):
        _fail("UPGRADE_BOOTSTRAP_UNIT_UNKNOWN")
    return _Snapshot(
        tuple(classifications),
        dict(staging_names),
        staging_payloads,
        frozenset(shared),
    )


def _open_unit_directory(
    unit_directory: Path,
) -> tuple[int, upgrade_systemd._DirectoryBinding]:
    try:
        return upgrade_systemd._validated_unit_directory(
            unit_directory,
            expected_uid=os.geteuid(),
        )
    except upgrade_systemd.UnitContractError as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_UNIT_UNSAFE") from error


def classify_installed_stable_units(
    unit_directory: Path,
    old: StableUnitBundle | None,
    target: StableUnitBundle,
) -> tuple[InstalledClassification, ...]:
    """Classify exact absent/known-old/target final names without mutation."""

    if old is not None and not isinstance(old, StableUnitBundle):
        _fail("UPGRADE_BOOTSTRAP_BUNDLE_INVALID")
    if not isinstance(target, StableUnitBundle):
        _fail("UPGRADE_BOOTSTRAP_BUNDLE_INVALID")
    descriptor, binding = _open_unit_directory(unit_directory)
    try:
        result = _snapshot(descriptor, old, target).classifications
        upgrade_systemd._require_same_unit_directory(
            descriptor,
            unit_directory,
            binding,
        )
        return result
    except upgrade_systemd.UnitContractError as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_UNIT_UNSAFE") from error
    finally:
        os.close(descriptor)


def _write_target_staging(
    descriptor: int,
    name: str,
    payload: bytes,
) -> str:
    temporary = f".{name}.next-{os.getpid()}-{os.urandom(6).hex()}"
    staging_descriptor: int | None = None
    try:
        staging_descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=descriptor,
        )
        upgrade_systemd._write_all(staging_descriptor, payload)
        os.fchmod(staging_descriptor, 0o600)
        os.fsync(staging_descriptor)
        os.close(staging_descriptor)
        staging_descriptor = None
        os.fsync(descriptor)
        loaded = _read_unit_entry(
            descriptor,
            temporary,
            allow_missing=False,
        )
        if loaded is None or loaded[0] != payload:
            _fail("UPGRADE_BOOTSTRAP_INSTALL_FAILED")
        return temporary
    except BootstrapError:
        raise
    except (OSError, upgrade_systemd.UnitContractError) as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_INSTALL_FAILED") from error
    finally:
        if staging_descriptor is not None:
            os.close(staging_descriptor)


def _unlink_durable(descriptor: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=descriptor)
        os.fsync(descriptor)
    except OSError as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_INSTALL_FAILED") from error


def converge_stable_units(
    unit_directory: Path,
    old: StableUnitBundle | None,
    target: StableUnitBundle,
) -> tuple[InstalledClassification, ...]:
    """Durably converge only exact absent/old/target crash states."""

    if old is not None and not isinstance(old, StableUnitBundle):
        _fail("UPGRADE_BOOTSTRAP_BUNDLE_INVALID")
    if not isinstance(target, StableUnitBundle):
        _fail("UPGRADE_BOOTSTRAP_BUNDLE_INVALID")
    descriptor, binding = _open_unit_directory(unit_directory)
    try:
        initial = _snapshot(descriptor, old, target)
        staging = dict(initial.staging_names)
        staged_payloads = dict(initial.staging_payloads)
        for name in UNIT_NAMES:
            staging_name = staging[name]
            if name in initial.shared_staging:
                _unlink_durable(descriptor, str(staging_name))
                staging[name] = None
                staged_payloads.pop(name, None)
                continue
            if (
                staging_name is not None
                and staged_payloads[name] != target.artifact(name).payload
            ):
                _unlink_durable(descriptor, staging_name)
                staging[name] = None
                staged_payloads.pop(name, None)
        for name in UNIT_NAMES:
            upgrade_systemd._require_same_unit_directory(
                descriptor,
                unit_directory,
                binding,
            )
            current = _read_unit_entry(
                descriptor,
                name,
                allow_missing=True,
            )
            current_payload = None if current is None else current[0]
            classification = _classify_payload(
                name,
                current_payload,
                old,
                target,
            )
            if classification.state is InstalledState.UNKNOWN:
                _fail("UPGRADE_BOOTSTRAP_UNIT_UNKNOWN")
            staging_name = staging[name]
            if classification.state is InstalledState.TARGET:
                if staging_name is not None:
                    _unlink_durable(descriptor, staging_name)
                continue
            if staging_name is None:
                staging_name = _write_target_staging(
                    descriptor,
                    name,
                    target.artifact(name).payload,
                )
                staging[name] = staging_name
            else:
                loaded = _read_unit_entry(
                    descriptor,
                    staging_name,
                    allow_missing=False,
                )
                if loaded is None or loaded[0] != target.artifact(name).payload:
                    _fail("UPGRADE_BOOTSTRAP_UNIT_UNKNOWN")
            current = _read_unit_entry(
                descriptor,
                name,
                allow_missing=True,
            )
            current_payload = None if current is None else current[0]
            classification = _classify_payload(
                name,
                current_payload,
                old,
                target,
            )
            if classification.state is InstalledState.OLD:
                _unlink_durable(descriptor, name)
            elif classification.state is InstalledState.TARGET:
                _unlink_durable(descriptor, staging_name)
                continue
            elif classification.state is not InstalledState.ABSENT:
                _fail("UPGRADE_BOOTSTRAP_UNIT_UNKNOWN")
            try:
                os.link(
                    staging_name,
                    name,
                    src_dir_fd=descriptor,
                    dst_dir_fd=descriptor,
                    follow_symlinks=False,
                )
                os.fsync(descriptor)
                _unlink_durable(descriptor, staging_name)
            except FileExistsError:
                raced = _read_unit_entry(
                    descriptor,
                    name,
                    allow_missing=False,
                )
                if raced is None or raced[0] != target.artifact(name).payload:
                    _fail("UPGRADE_BOOTSTRAP_UNIT_UNKNOWN")
                _unlink_durable(descriptor, staging_name)
            except BootstrapError:
                raise
            except OSError as error:
                raise BootstrapError(
                    "UPGRADE_BOOTSTRAP_INSTALL_FAILED"
                ) from error
        upgrade_systemd._require_same_unit_directory(
            descriptor,
            unit_directory,
            binding,
        )
        completed = _snapshot(descriptor, old, target)
        if (
            any(
                item.state is not InstalledState.TARGET
                for item in completed.classifications
            )
            or any(completed.staging_names.values())
        ):
            _fail("UPGRADE_BOOTSTRAP_INSTALL_FAILED")
        os.fsync(descriptor)
        return completed.classifications
    except upgrade_systemd.UnitContractError as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_UNIT_UNSAFE") from error
    finally:
        os.close(descriptor)


def _run(
    commands: manager.ManagerBinaries,
    runner: Runner,
    argv: Sequence[str],
    *,
    timeout: float,
    code: str,
) -> bytes:
    try:
        return manager._run(runner, argv, timeout=timeout, code=code)
    except manager.ManagerError as error:
        raise BootstrapError(code) from error


def _show(
    commands: manager.ManagerBinaries,
    runner: Runner,
    unit: str,
    names: Sequence[str],
    *,
    timeout: float = manager.CONTROL_TIMEOUT_SECONDS,
    code: str,
) -> dict[str, str]:
    payload = _run(
        commands,
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
    try:
        return manager._parse_properties(payload, names, code)
    except manager.ManagerError as error:
        raise BootstrapError(code) from error


def _exec_bindings(
    bindings: StableUnitBindings,
) -> dict[str, manager.ExecStartBinding | None]:
    python = str(bindings.python)
    upgrader = str(bindings.upgrader)
    return {
        LOCK_UNIT: manager.ExecStartBinding(
            bindings.python,
            (
                python,
                "-B",
                upgrader,
                "prepare-lock",
                "--serial-lock-file",
                str(bindings.serial_lock_file),
                "--lock-file",
                str(bindings.lock_file),
                "--project",
                bindings.project,
            ),
        ),
        RESUME_UNIT: manager.ExecStartBinding(
            bindings.python,
            (
                python,
                "-B",
                upgrader,
                "resume",
                "--state-parent",
                str(bindings.state_parent),
                "--serial-lock-file",
                str(bindings.serial_lock_file),
                "--unit-directory",
                str(bindings.unit_directory),
                "--lock-file",
                str(bindings.lock_file),
                "--operation-directory",
                str(bindings.operation_directory),
            ),
        ),
        PATH_UNIT: None,
    }


def _verify_loaded(
    commands: manager.ManagerBinaries,
    runner: Runner,
    bindings: StableUnitBindings,
) -> None:
    common = ("FragmentPath", "DropInPaths", "LoadState", "NeedDaemonReload")
    for name, expected_exec in _exec_bindings(bindings).items():
        names = common if expected_exec is None else common + ("ExecStart",)
        actual = _show(
            commands,
            runner,
            name,
            names,
            code="UPGRADE_BOOTSTRAP_LOADED_INVALID",
        )
        if (
            actual["FragmentPath"] != str(bindings.unit_directory / name)
            or actual["DropInPaths"] != ""
            or actual["LoadState"] != "loaded"
            or actual["NeedDaemonReload"] != "no"
        ):
            _fail("UPGRADE_BOOTSTRAP_LOADED_INVALID")
        if expected_exec is not None and not manager._exec_start_matches(
            actual["ExecStart"],
            expected_exec,
        ):
            _fail("UPGRADE_BOOTSTRAP_LOADED_INVALID")


def _require_active_absent(state_parent: Path) -> None:
    try:
        parent = state_parent.lstat()
        if (
            state_parent.resolve(strict=True) != state_parent
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            _fail("UPGRADE_BOOTSTRAP_STATE_INVALID")
        upgrades = state_parent / "upgrades"
        try:
            upgrades_metadata = upgrades.lstat()
        except FileNotFoundError:
            return
        if (
            upgrades.resolve(strict=True) != upgrades
            or not stat.S_ISDIR(upgrades_metadata.st_mode)
            or upgrades_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(upgrades_metadata.st_mode) != 0o700
        ):
            _fail("UPGRADE_BOOTSTRAP_STATE_INVALID")
        try:
            (upgrades / "active.json").lstat()
        except FileNotFoundError:
            return
        _fail("UPGRADE_BOOTSTRAP_ACTIVE_PRESENT")
    except BootstrapError:
        raise
    except OSError as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_STATE_INVALID") from error


def _serial_lock_metadata_valid(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and metadata.st_nlink == 1
        and metadata.st_size == 0
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )


def _acquire_serial_lock(
    bindings: StableUnitBindings,
) -> tuple[int, _SerialLockBinding]:
    path = bindings.serial_lock_file
    if path != bindings.state_parent / "reviewer-upgrade.lock":
        _fail("UPGRADE_BOOTSTRAP_SERIAL_LOCK_INVALID")
    parent_descriptor: int | None = None
    lock_descriptor: int | None = None
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_before = bindings.state_parent.lstat()
        parent_descriptor = os.open(bindings.state_parent, directory_flags)
        parent_opened = os.fstat(parent_descriptor)
        file_flags = (
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            lock_descriptor = os.open(
                path.name,
                file_flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_descriptor,
            )
            os.fchmod(lock_descriptor, 0o600)
            os.fsync(lock_descriptor)
            os.fsync(parent_descriptor)
        except FileExistsError:
            lock_descriptor = os.open(
                path.name,
                file_flags,
                dir_fd=parent_descriptor,
            )
        lexical = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        opened = os.fstat(lock_descriptor)
        if (
            bindings.state_parent.resolve(strict=True)
            != bindings.state_parent
            or not stat.S_ISDIR(parent_opened.st_mode)
            or parent_opened.st_uid != os.geteuid()
            or stat.S_IMODE(parent_opened.st_mode) != 0o700
            or upgrade_systemd._directory_metadata(parent_before)
            != upgrade_systemd._directory_metadata(parent_opened)
            or not _serial_lock_metadata_valid(opened)
            or upgrade_systemd._file_metadata(lexical)
            != upgrade_systemd._file_metadata(opened)
            or os.get_inheritable(lock_descriptor)
        ):
            _fail("UPGRADE_BOOTSTRAP_SERIAL_LOCK_INVALID")
        try:
            fcntl.flock(
                lock_descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise BootstrapError("UPGRADE_BOOTSTRAP_CONTENDED") from error
        os.fsync(lock_descriptor)
        os.fsync(parent_descriptor)
        parent_after = bindings.state_parent.lstat()
        current = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            upgrade_systemd._directory_metadata(parent_after)
            != upgrade_systemd._directory_metadata(parent_opened)
            or upgrade_systemd._file_metadata(current)
            != upgrade_systemd._file_metadata(opened)
            or upgrade_systemd._file_metadata(os.fstat(lock_descriptor))
            != upgrade_systemd._file_metadata(opened)
        ):
            _fail("UPGRADE_BOOTSTRAP_SERIAL_LOCK_INVALID")
        binding = _SerialLockBinding(
            upgrade_systemd._file_metadata(opened)
        )
        result = lock_descriptor
        lock_descriptor = None
        return result, binding
    except BootstrapError:
        raise
    except OSError as error:
        raise BootstrapError(
            "UPGRADE_BOOTSTRAP_SERIAL_LOCK_INVALID"
        ) from error
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _require_serial_lock(
    bindings: StableUnitBindings,
    descriptor: int,
    binding: _SerialLockBinding,
) -> None:
    if (
        type(descriptor) is not int
        or descriptor < 0
        or not isinstance(binding, _SerialLockBinding)
        or bindings.serial_lock_file
        != bindings.state_parent / "reviewer-upgrade.lock"
    ):
        _fail("UPGRADE_BOOTSTRAP_SERIAL_LOCK_INVALID")
    parent_descriptor: int | None = None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_descriptor = os.open(bindings.state_parent, flags)
        opened = os.fstat(descriptor)
        current = os.stat(
            bindings.serial_lock_file.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not _serial_lock_metadata_valid(opened)
            or upgrade_systemd._file_metadata(opened) != binding.metadata
            or upgrade_systemd._file_metadata(current) != binding.metadata
            or os.get_inheritable(descriptor)
            or not (
                fcntl.fcntl(descriptor, fcntl.F_GETFD)
                & fcntl.FD_CLOEXEC
            )
        ):
            _fail("UPGRADE_BOOTSTRAP_SERIAL_LOCK_INVALID")
        os.fsync(descriptor)
        os.fsync(parent_descriptor)
        if (
            upgrade_systemd._file_metadata(os.fstat(descriptor))
            != binding.metadata
            or upgrade_systemd._file_metadata(
                os.stat(
                    bindings.serial_lock_file.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            )
            != binding.metadata
        ):
            _fail("UPGRADE_BOOTSTRAP_SERIAL_LOCK_INVALID")
    except BootstrapError:
        raise
    except OSError as error:
        raise BootstrapError(
            "UPGRADE_BOOTSTRAP_SERIAL_LOCK_INVALID"
        ) from error
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _timer_link(bindings: StableUnitBindings) -> manager.EnableLinkExpectation:
    return manager.EnableLinkExpectation(
        bindings.unit_directory / "default.target.wants" / PATH_UNIT,
        bindings.unit_directory / PATH_UNIT,
    )


def _prove_path_waiting(
    commands: manager.ManagerBinaries,
    runner: Runner,
    bindings: StableUnitBindings,
    *,
    deadline_seconds: float,
    monotonic: Callable[[], float],
    sleep: Callable[[float], None],
) -> None:
    if (
        not isinstance(deadline_seconds, (int, float))
        or isinstance(deadline_seconds, bool)
        or not math.isfinite(float(deadline_seconds))
        or not 0 < deadline_seconds <= MAX_WAIT_SECONDS
    ):
        _fail("UPGRADE_BOOTSTRAP_INPUT_INVALID")
    started = float(monotonic())
    previous = started
    deadline = started + float(deadline_seconds)
    properties = (
        "FragmentPath",
        "DropInPaths",
        "LoadState",
        "NeedDaemonReload",
        "UnitFileState",
        "ActiveState",
        "SubState",
        "Result",
    )
    while True:
        now = float(monotonic())
        if not math.isfinite(now) or now < previous:
            _fail("UPGRADE_BOOTSTRAP_CLOCK_INVALID")
        previous = now
        remaining = deadline - now
        if remaining <= 0:
            _fail("UPGRADE_BOOTSTRAP_PATH_NOT_READY")
        actual = _show(
            commands,
            runner,
            PATH_UNIT,
            properties,
            timeout=min(manager.CONTROL_TIMEOUT_SECONDS, remaining),
            code="UPGRADE_BOOTSTRAP_PATH_NOT_READY",
        )
        if actual == {
            "FragmentPath": str(bindings.unit_directory / PATH_UNIT),
            "DropInPaths": "",
            "LoadState": "loaded",
            "NeedDaemonReload": "no",
            "UnitFileState": "enabled",
            "ActiveState": "active",
            "SubState": "waiting",
            "Result": "success",
        }:
            return
        duration = min(0.25, deadline - float(monotonic()))
        if duration <= 0:
            _fail("UPGRADE_BOOTSTRAP_PATH_NOT_READY")
        sleep(duration)


def _receipt(target: StableUnitBundle, bindings: StableUnitBindings) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "contract_version": RECEIPT_CONTRACT,
        "path_unit": PATH_UNIT,
        "receipt_digest": "",
        "selector_path": str(bindings.state_parent / "upgrades/active.json"),
        "status": "path_armed_idle",
        "target_unit_digests": target.digests(),
    }
    subject = dict(receipt)
    subject.pop("receipt_digest")
    payload = json.dumps(
        subject,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    receipt["receipt_digest"] = _digest(payload)
    return receipt


def _bootstrap_prepublication_locked(
    template_directory: Path,
    bindings: StableUnitBindings,
    old: StableUnitBundle | None,
    commands: manager.ManagerBinaries,
    runner: Runner,
    *,
    serial_descriptor: int,
    serial_binding: _SerialLockBinding,
    target_bundle: StableUnitBundle | None = None,
    path_deadline_seconds: float = 15.0,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Install, load, and arm the idle selector path before publication."""

    if not isinstance(bindings, StableUnitBindings):
        _fail("UPGRADE_BOOTSTRAP_INPUT_INVALID")
    bindings.replacements()
    if not isinstance(commands, manager.ManagerBinaries):
        _fail("UPGRADE_BOOTSTRAP_INPUT_INVALID")
    try:
        commands = commands.validated()
    except manager.ManagerError as error:
        raise BootstrapError("UPGRADE_BOOTSTRAP_INPUT_INVALID") from error
    _require_serial_lock(bindings, serial_descriptor, serial_binding)
    _require_active_absent(bindings.state_parent)
    if target_bundle is None:
        target = render_stable_unit_bundle(template_directory, bindings)
    elif isinstance(target_bundle, StableUnitBundle):
        # The caller may have already persisted and reloaded the exact target
        # bytes as pending authority.  Never reread mutable templates in that
        # case: convergence and the returned receipt bind only this bundle.
        target = StableUnitBundle(tuple(target_bundle.units))
    else:
        _fail("UPGRADE_BOOTSTRAP_BUNDLE_INVALID")
    converge_stable_units(bindings.unit_directory, old, target)
    if any(
        item.state is not InstalledState.TARGET
        for item in classify_installed_stable_units(
            bindings.unit_directory,
            old,
            target,
        )
    ):
        _fail("UPGRADE_BOOTSTRAP_TARGET_NOT_PROVEN")
    unit_paths = [str(bindings.unit_directory / name) for name in UNIT_NAMES]
    _run(
        commands,
        runner,
        [
            str(commands.systemd_analyze),
            "--user",
            "verify",
            "--",
            *unit_paths,
        ],
        timeout=manager.CONTROL_TIMEOUT_SECONDS,
        code="UPGRADE_BOOTSTRAP_SYNTAX_FAILED",
    )
    _run(
        commands,
        runner,
        [str(commands.systemctl), "--user", "daemon-reload"],
        timeout=manager.CONTROL_TIMEOUT_SECONDS,
        code="UPGRADE_BOOTSTRAP_RELOAD_FAILED",
    )
    _verify_loaded(commands, runner, bindings)
    if any(
        item.state is not InstalledState.TARGET
        for item in classify_installed_stable_units(
            bindings.unit_directory,
            old,
            target,
        )
    ):
        _fail("UPGRADE_BOOTSTRAP_TARGET_NOT_PROVEN")
    _run(
        commands,
        runner,
        [str(commands.systemctl), "--user", "restart", "--", LOCK_UNIT],
        timeout=manager.CONTROL_TIMEOUT_SECONDS,
        code="UPGRADE_BOOTSTRAP_LOCK_FAILED",
    )
    lock = _show(
        commands,
        runner,
        LOCK_UNIT,
        ("ActiveState", "SubState", "Result", "ExecMainStatus"),
        code="UPGRADE_BOOTSTRAP_LOCK_FAILED",
    )
    if lock != {
        "ActiveState": "active",
        "SubState": "exited",
        "Result": "success",
        "ExecMainStatus": "0",
    }:
        _fail("UPGRADE_BOOTSTRAP_LOCK_FAILED")
    _require_serial_lock(bindings, serial_descriptor, serial_binding)
    _require_active_absent(bindings.state_parent)
    # Starting the resumer here would necessarily contend on the serial lock
    # held by this bootstrap.  Prove a clean idle service instead; the armed
    # path starts it only after the selector is published by the transaction.
    for verb in ("stop", "reset-failed"):
        _run(
            commands,
            runner,
            [
                str(commands.systemctl),
                "--user",
                verb,
                "--",
                RESUME_UNIT,
            ],
            timeout=(
                manager.RECONCILE_TIMEOUT_SECONDS
                if verb == "stop"
                else manager.CONTROL_TIMEOUT_SECONDS
            ),
            code="UPGRADE_BOOTSTRAP_RESUMER_NOT_IDLE",
        )
    idle = _show(
        commands,
        runner,
        RESUME_UNIT,
        ("ActiveState", "SubState", "Result", "ExecMainStatus"),
        code="UPGRADE_BOOTSTRAP_RESUMER_NOT_IDLE",
    )
    if {
        key: idle[key]
        for key in ("ActiveState", "SubState", "Result")
    } != {
        "ActiveState": "inactive",
        "SubState": "dead",
        "Result": "success",
    }:
        _fail("UPGRADE_BOOTSTRAP_RESUMER_NOT_IDLE")
    _require_serial_lock(bindings, serial_descriptor, serial_binding)
    _require_active_absent(bindings.state_parent)
    for argv in (
        [
            str(commands.systemctl),
            "--user",
            "reset-failed",
            "--",
            PATH_UNIT,
        ],
        [str(commands.systemctl), "--user", "enable", "--", PATH_UNIT],
    ):
        _run(
            commands,
            runner,
            argv,
            timeout=manager.CONTROL_TIMEOUT_SECONDS,
            code="UPGRADE_BOOTSTRAP_PATH_ARM_FAILED",
        )
    link = _timer_link(bindings)
    try:
        manager.prove_enable_links_durable(
            (link,),
            present=True,
            unsettled_code="UPGRADE_BOOTSTRAP_PATH_ARM_FAILED",
        )
    except manager.ManagerError as error:
        if error.code == "UPGRADE_MANAGER_TIMER_LINK_INVALID":
            raise BootstrapError("UPGRADE_BOOTSTRAP_LINK_INVALID") from error
        raise BootstrapError("UPGRADE_BOOTSTRAP_PATH_ARM_FAILED") from error
    _run(
        commands,
        runner,
        [
            str(commands.systemctl),
            "--user",
            "--no-block",
            "restart",
            "--",
            PATH_UNIT,
        ],
        timeout=manager.CONTROL_TIMEOUT_SECONDS,
        code="UPGRADE_BOOTSTRAP_PATH_ARM_FAILED",
    )
    _prove_path_waiting(
        commands,
        runner,
        bindings,
        deadline_seconds=path_deadline_seconds,
        monotonic=monotonic,
        sleep=sleep,
    )
    try:
        manager.prove_enable_links_durable(
            (link,),
            present=True,
            unsettled_code="UPGRADE_BOOTSTRAP_PATH_ARM_FAILED",
        )
    except manager.ManagerError as error:
        if error.code == "UPGRADE_MANAGER_TIMER_LINK_INVALID":
            raise BootstrapError("UPGRADE_BOOTSTRAP_LINK_INVALID") from error
        raise BootstrapError("UPGRADE_BOOTSTRAP_PATH_ARM_FAILED") from error
    _require_serial_lock(bindings, serial_descriptor, serial_binding)
    _require_active_absent(bindings.state_parent)
    return _receipt(target, bindings)


def bootstrap_prepublication(
    template_directory: Path,
    bindings: StableUnitBindings,
    old: StableUnitBundle | None,
    commands: manager.ManagerBinaries,
    runner: Runner,
    *,
    target_bundle: StableUnitBundle | None = None,
    path_deadline_seconds: float = 15.0,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Hold the stable serial lock through the complete bootstrap proof."""

    if not isinstance(bindings, StableUnitBindings):
        _fail("UPGRADE_BOOTSTRAP_INPUT_INVALID")
    bindings.replacements()
    _require_active_absent(bindings.state_parent)
    descriptor, binding = _acquire_serial_lock(bindings)
    try:
        return _bootstrap_prepublication_locked(
            template_directory,
            bindings,
            old,
            commands,
            runner,
            serial_descriptor=descriptor,
            serial_binding=binding,
            target_bundle=target_bundle,
            path_deadline_seconds=path_deadline_seconds,
            monotonic=monotonic,
            sleep=sleep,
        )
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


__all__ = [
    "BootstrapError",
    "InstalledClassification",
    "InstalledState",
    "LOCK_UNIT",
    "PATH_UNIT",
    "RECEIPT_CONTRACT",
    "RESUME_UNIT",
    "StableUnitBindings",
    "StableUnitBundle",
    "UNIT_NAMES",
    "bootstrap_prepublication",
    "classify_installed_stable_units",
    "converge_stable_units",
    "render_stable_unit_bundle",
    "render_stable_units",
]
