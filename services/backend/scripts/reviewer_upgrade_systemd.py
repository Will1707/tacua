#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Crash-safe rendering and promotion helpers for Tacua user units.

The reviewer-upgrade transaction uses these helpers only while holding its
upgrade serialization lock.  Installed unit files are accepted only when they
are byte-for-byte equal to either the pre-upgrade snapshot or the rendered
target.  That makes every interruption during the three-file promotion a
recoverable old/target mixture without granting the upgrader authority to
overwrite unrelated operator changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Mapping


MAX_UNIT_BYTES = 2 * 1024 * 1024
UNIT_NAMES = (
    "tacua-reconcile.service",
    "tacua-reconcile-lock.service",
    "tacua-reconcile.timer",
)
TEMPLATE_NAMES = {
    "tacua-reconcile.service": "tacua-reconcile.service.in",
    "tacua-reconcile-lock.service": "tacua-reconcile-lock.service.in",
    "tacua-reconcile.timer": "tacua-reconcile.timer",
}
TOKENS = (
    "@PYTHON@",
    "@RECONCILER@",
    "@STATE_DIRECTORY@",
    "@LOCK_FILE@",
    "@ANCHOR_FILE@",
    "@OPERATION_DIRECTORY@",
    "@CONFIG_FILE@",
    "@ADMIN_SECRET_FILE@",
)
EXPECTED_TOKEN_COUNTS = {
    "tacua-reconcile.service.in": (2, 3, 3, 2, 3, 2, 2, 2),
    "tacua-reconcile-lock.service.in": (2, 2, 2, 0, 2, 0, 0, 0),
    "tacua-reconcile.timer": (0, 0, 0, 0, 0, 0, 0, 0),
}
PLACEHOLDER = re.compile(r"@[A-Z][A-Z0-9_]*@")
UNSAFE_SYSTEMD_PATH_CHARACTERS = frozenset(' \x00\n\r\t"\\%@')
STAGING_SUFFIX = re.compile(r"[0-9]+-[0-9a-f]{12}\Z")


class UnitContractError(RuntimeError):
    """Stable, content-free failure raised for an unsafe unit operation."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ReconcileUnitBindings:
    """Absolute paths substituted into the three reconciliation units."""

    python: Path
    reconciler: Path
    state_directory: Path
    lock_file: Path
    anchor_file: Path
    operation_directory: Path
    config_file: Path
    admin_secret_file: Path

    def replacements(self) -> dict[str, str]:
        values = (
            self.python,
            self.reconciler,
            self.state_directory,
            self.lock_file,
            self.anchor_file,
            self.operation_directory,
            self.config_file,
            self.admin_secret_file,
        )
        return {
            token: _validated_systemd_path(value)
            for token, value in zip(TOKENS, values, strict=True)
        }


@dataclass(frozen=True)
class UnitArtifact:
    """One exact unit payload and its content commitment."""

    name: str
    payload: bytes
    digest: str

    def __post_init__(self) -> None:
        if self.name not in UNIT_NAMES or self.digest != digest_payload(
            self.payload
        ):
            raise UnitContractError("UPGRADE_UNIT_BUNDLE_INVALID")


@dataclass(frozen=True)
class UnitBundle:
    """The three reconciliation units in deterministic installation order."""

    units: tuple[UnitArtifact, ...]

    def __post_init__(self) -> None:
        if tuple(unit.name for unit in self.units) != UNIT_NAMES:
            raise UnitContractError("UPGRADE_UNIT_BUNDLE_INVALID")

    @classmethod
    def from_payloads(cls, payloads: Mapping[str, bytes]) -> UnitBundle:
        if set(payloads) != set(UNIT_NAMES):
            raise UnitContractError("UPGRADE_UNIT_BUNDLE_INVALID")
        if any(
            not isinstance(payloads[name], bytes)
            or len(payloads[name]) > MAX_UNIT_BYTES
            for name in UNIT_NAMES
        ):
            raise UnitContractError("UPGRADE_UNIT_BUNDLE_INVALID")
        return cls(
            tuple(
                UnitArtifact(name, payloads[name], digest_payload(payloads[name]))
                for name in UNIT_NAMES
            )
        )

    def artifact(self, name: str) -> UnitArtifact:
        for unit in self.units:
            if unit.name == name:
                return unit
        raise UnitContractError("UPGRADE_UNIT_BUNDLE_INVALID")

    def payloads(self) -> dict[str, bytes]:
        return {unit.name: unit.payload for unit in self.units}

    def digests(self) -> dict[str, str]:
        return {unit.name: unit.digest for unit in self.units}


class InstalledUnitState(str, Enum):
    """The only installed states accepted by an upgrade promotion."""

    OLD = "old"
    TARGET = "target"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class InstalledUnitClassification:
    name: str
    state: InstalledUnitState
    digest: str | None


@dataclass(frozen=True)
class _DirectoryBinding:
    """Descriptor-relative identity of every component in one safe path."""

    records: tuple[tuple[int, int, int, int, int], ...]


def _file_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    """The complete file metadata compared across every bounded read."""

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


def _directory_metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def digest_payload(payload: bytes) -> str:
    """Return the repository's canonical SHA-256 commitment form."""

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _validated_systemd_path(value: Path) -> str:
    if not isinstance(value, Path):
        raise UnitContractError("UPGRADE_UNIT_BINDING_INVALID")
    rendered = str(value)
    if (
        not value.is_absolute()
        or rendered.startswith("//")
        or any(part in {".", ".."} for part in value.parts)
        or any(character in UNSAFE_SYSTEMD_PATH_CHARACTERS for character in rendered)
    ):
        raise UnitContractError("UPGRADE_UNIT_BINDING_INVALID")
    return rendered


def render_reconcile_units(
    templates: Mapping[str, bytes],
    bindings: ReconcileUnitBindings,
) -> UnitBundle:
    """Purely render an exact template set after validating its token ABI."""

    if set(templates) != set(TEMPLATE_NAMES.values()):
        raise UnitContractError("UPGRADE_UNIT_TEMPLATE_INVALID")
    replacements = bindings.replacements()
    rendered: dict[str, bytes] = {}
    for output_name in UNIT_NAMES:
        template_name = TEMPLATE_NAMES[output_name]
        payload = templates[template_name]
        if not isinstance(payload, bytes) or len(payload) > MAX_UNIT_BYTES:
            raise UnitContractError("UPGRADE_UNIT_TEMPLATE_INVALID")
        try:
            document = payload.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise UnitContractError("UPGRADE_UNIT_TEMPLATE_INVALID") from error
        counts = tuple(document.count(token) for token in TOKENS)
        if counts != EXPECTED_TOKEN_COUNTS[template_name]:
            raise UnitContractError("UPGRADE_UNIT_TEMPLATE_INVALID")
        if set(PLACEHOLDER.findall(document)) != {
            token for token, count in zip(TOKENS, counts, strict=True) if count
        }:
            raise UnitContractError("UPGRADE_UNIT_TEMPLATE_INVALID")
        for token, replacement in replacements.items():
            document = document.replace(token, replacement)
        if PLACEHOLDER.search(document) is not None:
            raise UnitContractError("UPGRADE_UNIT_TEMPLATE_INVALID")
        rendered[output_name] = document.encode("utf-8")
    return UnitBundle.from_payloads(rendered)


def _read_template(directory_descriptor: int, name: str) -> bytes:
    if name not in TEMPLATE_NAMES.values():
        raise UnitContractError("UPGRADE_UNIT_TEMPLATE_INVALID")
    try:
        metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise UnitContractError("UPGRADE_UNIT_TEMPLATE_INVALID")
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        try:
            opened = os.fstat(descriptor)
            if _file_metadata(opened) != _file_metadata(metadata):
                raise UnitContractError("UPGRADE_UNIT_TEMPLATE_INVALID")
            payload = _read_bounded(descriptor)
            after = os.fstat(descriptor)
            current = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (
                len(payload) != opened.st_size
                or _file_metadata(after) != _file_metadata(opened)
                or _file_metadata(current) != _file_metadata(opened)
            ):
                raise UnitContractError("UPGRADE_UNIT_TEMPLATE_INVALID")
        finally:
            os.close(descriptor)
    except UnitContractError:
        raise
    except OSError as error:
        raise UnitContractError("UPGRADE_UNIT_TEMPLATE_INVALID") from error
    return payload


def render_reconcile_unit_bundle(
    template_directory: Path,
    bindings: ReconcileUnitBindings,
) -> UnitBundle:
    """Read and render the repository's exact reconciliation templates."""

    descriptor, binding = _validated_template_directory(template_directory)
    try:
        templates: dict[str, bytes] = {}
        for template_name in TEMPLATE_NAMES.values():
            _require_same_directory(
                descriptor,
                template_directory,
                binding,
                code="UPGRADE_UNIT_TEMPLATE_INVALID",
                allowed_leaf_uids={0, os.geteuid()},
            )
            templates[template_name] = _read_template(
                descriptor,
                template_name,
            )
        _require_same_directory(
            descriptor,
            template_directory,
            binding,
            code="UPGRADE_UNIT_TEMPLATE_INVALID",
            allowed_leaf_uids={0, os.geteuid()},
        )
        return render_reconcile_units(templates, bindings)
    finally:
        os.close(descriptor)


def _validated_directory(
    path: Path,
    *,
    ancestor_uids: set[int],
    allowed_leaf_uids: set[int],
    code: str,
) -> tuple[int, _DirectoryBinding]:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or str(path).startswith("//")
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise UnitContractError(code)
    descriptor: int | None = None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        if path.resolve(strict=True) != path:
            raise UnitContractError(code)
        descriptor = os.open("/", flags)
        records: list[tuple[int, int, int, int, int]] = []
        components = path.parts[1:]
        for index in range(len(components) + 1):
            metadata = os.fstat(descriptor)
            permissions = stat.S_IMODE(metadata.st_mode)
            leaf = index == len(components)
            allowed_uids = allowed_leaf_uids if leaf else ancestor_uids
            sticky_shared = (
                not leaf
                and metadata.st_uid in ancestor_uids
                and permissions & stat.S_ISVTX
                and permissions & 0o022
            )
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in allowed_uids
                or (permissions & 0o022 and not sticky_shared)
            ):
                raise UnitContractError(code)
            records.append(_directory_metadata(metadata))
            if leaf:
                return descriptor, _DirectoryBinding(tuple(records))
            child = os.open(components[index], flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        raise UnitContractError(code)  # pragma: no cover - loop always returns.
    except UnitContractError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise UnitContractError(code) from error


def _validated_unit_directory(
    unit_directory: Path,
    *,
    expected_uid: int,
) -> tuple[int, _DirectoryBinding]:
    return _validated_directory(
        unit_directory,
        ancestor_uids={0, expected_uid},
        allowed_leaf_uids={expected_uid},
        code="UPGRADE_UNIT_DIRECTORY_UNSAFE",
    )


def _validated_template_directory(
    template_directory: Path,
) -> tuple[int, _DirectoryBinding]:
    return _validated_directory(
        template_directory,
        ancestor_uids={0, os.geteuid()},
        allowed_leaf_uids={0, os.geteuid()},
        code="UPGRADE_UNIT_TEMPLATE_INVALID",
    )


def _require_same_directory(
    descriptor: int,
    path: Path,
    expected: _DirectoryBinding,
    *,
    code: str,
    allowed_leaf_uids: set[int],
) -> None:
    current_descriptor: int | None = None
    try:
        opened = os.fstat(descriptor)
        current_descriptor, current = _validated_directory(
            path,
            ancestor_uids={0, os.geteuid(), *allowed_leaf_uids},
            allowed_leaf_uids=allowed_leaf_uids,
            code=code,
        )
        if (
            current != expected
            or _directory_metadata(opened) != expected.records[-1]
        ):
            raise UnitContractError(code)
    finally:
        if current_descriptor is not None:
            os.close(current_descriptor)


def _require_same_unit_directory(
    descriptor: int,
    unit_directory: Path,
    expected: _DirectoryBinding,
) -> None:
    _require_same_directory(
        descriptor,
        unit_directory,
        expected,
        code="UPGRADE_UNIT_DIRECTORY_UNSAFE",
        allowed_leaf_uids={expected.records[-1][3]},
    )


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, min(65_536, MAX_UNIT_BYTES + 1 - size))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_UNIT_BYTES:
            raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE")


def _read_installed_unit(
    directory_descriptor: int,
    name: str,
    *,
    expected_uid: int,
    allow_missing: bool,
) -> bytes | None:
    if name not in UNIT_NAMES:
        raise UnitContractError("UPGRADE_UNIT_BUNDLE_INVALID")
    try:
        metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        if allow_missing:
            return None
        raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE") from None
    except OSError as error:
        raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or _file_metadata(opened) != _file_metadata(metadata)
            ):
                raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE")
            payload = _read_bounded(descriptor)
            after = os.fstat(descriptor)
            current = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (
                len(payload) != opened.st_size
                or _file_metadata(after) != _file_metadata(opened)
                or _file_metadata(current) != _file_metadata(opened)
            ):
                raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE")
        finally:
            os.close(descriptor)
    except UnitContractError:
        raise
    except OSError as error:
        raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE") from error
    return payload


def _staging_name_pattern(name: str) -> re.Pattern[str]:
    if name not in UNIT_NAMES:
        raise UnitContractError("UPGRADE_UNIT_BUNDLE_INVALID")
    return re.compile(
        rf"\.{re.escape(name)}\.next-{STAGING_SUFFIX.pattern}"
    )


def _scan_staging_units(
    directory_descriptor: int,
) -> dict[str, str | None]:
    try:
        entries = os.listdir(directory_descriptor)
    except OSError as error:
        raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE") from error
    result: dict[str, str | None] = {name: None for name in UNIT_NAMES}
    for entry in entries:
        matched_name: str | None = None
        for name in UNIT_NAMES:
            prefix = f".{name}.next-"
            if not entry.startswith(prefix):
                continue
            if _staging_name_pattern(name).fullmatch(entry) is None:
                raise UnitContractError("UPGRADE_UNIT_CONTENT_UNKNOWN")
            matched_name = name
            break
        if matched_name is None:
            continue
        if result[matched_name] is not None:
            raise UnitContractError("UPGRADE_UNIT_CONTENT_UNKNOWN")
        result[matched_name] = entry
    return result


def _read_staging_unit(
    directory_descriptor: int,
    temporary: str,
    *,
    expected_uid: int,
) -> bytes:
    try:
        metadata = os.stat(
            temporary,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_UNIT_BYTES
        ):
            raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE")
        descriptor = os.open(
            temporary,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        try:
            opened = os.fstat(descriptor)
            if _file_metadata(opened) != _file_metadata(metadata):
                raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE")
            payload = _read_bounded(descriptor)
            after = os.fstat(descriptor)
            current = os.stat(
                temporary,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (
                len(payload) != opened.st_size
                or _file_metadata(after) != _file_metadata(opened)
                or _file_metadata(current) != _file_metadata(opened)
            ):
                raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE")
            return payload
        finally:
            os.close(descriptor)
    except UnitContractError:
        raise
    except OSError as error:
        raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE") from error


def snapshot_installed_units(
    unit_directory: Path,
    *,
    expected_uid: int | None = None,
) -> UnitBundle:
    """Read the exact safe installed unit bytes and their digests."""

    uid = os.geteuid() if expected_uid is None else expected_uid
    descriptor, binding = _validated_unit_directory(
        unit_directory,
        expected_uid=uid,
    )
    try:
        payloads: dict[str, bytes] = {}
        for name in UNIT_NAMES:
            _require_same_unit_directory(descriptor, unit_directory, binding)
            payload = _read_installed_unit(
                descriptor,
                name,
                expected_uid=uid,
                allow_missing=False,
            )
            if payload is None:
                raise UnitContractError("UPGRADE_UNIT_FILE_UNSAFE")
            payloads[name] = payload
        _require_same_unit_directory(descriptor, unit_directory, binding)
        return UnitBundle.from_payloads(payloads)
    finally:
        os.close(descriptor)


def classify_unit_payloads(
    installed: Mapping[str, bytes | None],
    old: UnitBundle,
    target: UnitBundle,
) -> tuple[InstalledUnitClassification, ...]:
    """Purely classify exact payloads; target wins when old equals target."""

    if set(installed) != set(UNIT_NAMES):
        raise UnitContractError("UPGRADE_UNIT_BUNDLE_INVALID")
    result = []
    for name in UNIT_NAMES:
        payload = installed[name]
        if payload == target.artifact(name).payload:
            state = InstalledUnitState.TARGET
        elif payload == old.artifact(name).payload:
            state = InstalledUnitState.OLD
        else:
            state = InstalledUnitState.UNKNOWN
        result.append(
            InstalledUnitClassification(
                name=name,
                state=state,
                digest=None if payload is None else digest_payload(payload),
            )
        )
    return tuple(result)


def _classify_with_descriptor(
    descriptor: int,
    *,
    expected_uid: int,
    old: UnitBundle,
    target: UnitBundle,
) -> tuple[InstalledUnitClassification, ...]:
    installed = {
        name: _read_installed_unit(
            descriptor,
            name,
            expected_uid=expected_uid,
            allow_missing=True,
        )
        for name in UNIT_NAMES
    }
    return classify_unit_payloads(installed, old, target)


def classify_installed_units(
    unit_directory: Path,
    old: UnitBundle,
    target: UnitBundle,
    *,
    expected_uid: int | None = None,
) -> tuple[InstalledUnitClassification, ...]:
    """Classify each safely installed unit as exact old, target, or unknown."""

    uid = os.geteuid() if expected_uid is None else expected_uid
    descriptor, binding = _validated_unit_directory(
        unit_directory,
        expected_uid=uid,
    )
    try:
        result = _classify_with_descriptor(
            descriptor,
            expected_uid=uid,
            old=old,
            target=target,
        )
        _require_same_unit_directory(descriptor, unit_directory, binding)
        return result
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("unit write stopped")
        offset += written


def converge_installed_units(
    unit_directory: Path,
    old: UnitBundle,
    target: UnitBundle,
    *,
    expected_uid: int | None = None,
) -> tuple[InstalledUnitClassification, ...]:
    """Atomically converge an exact old/target mixture to the target bundle.

    The caller must hold the external reviewer-upgrade serialization lock for
    the entire snapshot/classification/convergence sequence.  This helper does
    not acquire that lock and its TOCTOU checks are a fail-closed backstop, not
    a substitute for cross-process exclusion.

    Each target payload is fsynced before its atomic rename, and the unit
    directory is fsynced after every rename.  Therefore an interruption leaves
    only another exact old/target mixture that this function can resume.
    """

    uid = os.geteuid() if expected_uid is None else expected_uid
    descriptor, binding = _validated_unit_directory(
        unit_directory,
        expected_uid=uid,
    )
    temporary_names: set[str] = set()
    try:
        initial = _classify_with_descriptor(
            descriptor,
            expected_uid=uid,
            old=old,
            target=target,
        )
        if any(item.state is InstalledUnitState.UNKNOWN for item in initial):
            raise UnitContractError("UPGRADE_UNIT_CONTENT_UNKNOWN")
        staged_names = _scan_staging_units(descriptor)
        staged_payloads: dict[str, bytes] = {}
        for name in UNIT_NAMES:
            temporary = staged_names[name]
            if temporary is None:
                continue
            payload = _read_staging_unit(
                descriptor,
                temporary,
                expected_uid=uid,
            )
            target_payload = target.artifact(name).payload
            if not target_payload.startswith(payload):
                raise UnitContractError("UPGRADE_UNIT_CONTENT_UNKNOWN")
            staged_payloads[name] = payload
        for name, payload in tuple(staged_payloads.items()):
            if payload == target.artifact(name).payload:
                temporary_names.add(str(staged_names[name]))
                continue
            try:
                os.unlink(str(staged_names[name]), dir_fd=descriptor)
                os.fsync(descriptor)
            except OSError as error:
                raise UnitContractError(
                    "UPGRADE_UNIT_INSTALL_FAILED"
                ) from error
            staged_names[name] = None
            del staged_payloads[name]
        for name in UNIT_NAMES:
            _require_same_unit_directory(descriptor, unit_directory, binding)
            current_payload = _read_installed_unit(
                descriptor,
                name,
                expected_uid=uid,
                allow_missing=False,
            )
            target_payload = target.artifact(name).payload
            if current_payload == target_payload:
                recovered = staged_names[name]
                if recovered is not None:
                    try:
                        os.unlink(recovered, dir_fd=descriptor)
                        temporary_names.discard(recovered)
                        os.fsync(descriptor)
                    except OSError as error:
                        raise UnitContractError(
                            "UPGRADE_UNIT_INSTALL_FAILED"
                        ) from error
                continue
            if current_payload != old.artifact(name).payload:
                raise UnitContractError("UPGRADE_UNIT_CONTENT_UNKNOWN")
            recovered = staged_names[name]
            temporary = (
                recovered
                if recovered is not None
                else f".{name}.next-{os.getpid()}-{os.urandom(6).hex()}"
            )
            temporary_names.add(temporary)
            try:
                if recovered is None:
                    temporary_descriptor = os.open(
                        temporary,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=descriptor,
                    )
                    try:
                        _write_all(temporary_descriptor, target_payload)
                        os.fchmod(temporary_descriptor, 0o600)
                        os.fsync(temporary_descriptor)
                    finally:
                        os.close(temporary_descriptor)
                    os.fsync(descriptor)
                elif staged_payloads.get(name) != target_payload:
                    raise UnitContractError("UPGRADE_UNIT_CONTENT_UNKNOWN")
                _require_same_unit_directory(
                    descriptor,
                    unit_directory,
                    binding,
                )
                current_payload = _read_installed_unit(
                    descriptor,
                    name,
                    expected_uid=uid,
                    allow_missing=False,
                )
                if current_payload == target_payload:
                    os.unlink(temporary, dir_fd=descriptor)
                    temporary_names.remove(temporary)
                    os.fsync(descriptor)
                    continue
                if current_payload != old.artifact(name).payload:
                    raise UnitContractError("UPGRADE_UNIT_CONTENT_UNKNOWN")
                os.replace(
                    temporary,
                    name,
                    src_dir_fd=descriptor,
                    dst_dir_fd=descriptor,
                )
                temporary_names.remove(temporary)
                os.fsync(descriptor)
                installed = _read_installed_unit(
                    descriptor,
                    name,
                    expected_uid=uid,
                    allow_missing=False,
                )
                if installed != target_payload:
                    raise UnitContractError("UPGRADE_UNIT_INSTALL_FAILED")
            except UnitContractError:
                raise
            except OSError as error:
                raise UnitContractError("UPGRADE_UNIT_INSTALL_FAILED") from error
        _require_same_unit_directory(descriptor, unit_directory, binding)
        result = _classify_with_descriptor(
            descriptor,
            expected_uid=uid,
            old=old,
            target=target,
        )
        if any(item.state is not InstalledUnitState.TARGET for item in result):
            raise UnitContractError("UPGRADE_UNIT_INSTALL_FAILED")
        return result
    finally:
        changed = False
        for temporary in temporary_names:
            try:
                os.unlink(temporary, dir_fd=descriptor)
                changed = True
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if changed:
            try:
                os.fsync(descriptor)
            except OSError:
                pass
        os.close(descriptor)
