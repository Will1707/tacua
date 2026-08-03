#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create, migrate, and expire owner-private physical-pilot diagnostics.

The tool deliberately manages only direct children of one explicitly supplied
mode-0700 operations root.  It never discovers diagnostics elsewhere and it
never deletes an entry whose name, marker, ownership, permissions, filesystem,
or contents are ambiguous.
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Sequence


ARTIFACT_CLASS = "physical_pilot_diagnostics"
RETENTION_DAYS = 7
RETENTION_MARKER = "retention.env"
OPERATION_PREFIX = "tacua-physical-pilot."
OPERATION_NAME = re.compile(r"^tacua-physical-pilot\.[A-Za-z0-9]{6}$")
ENTRY_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
LAUNCHD_LABEL = "ai.tacua.pilot-diagnostics-retention"
MAX_MARKER_BYTES = 512
UTC = timezone.utc


class SafetyError(RuntimeError):
    """A fail-closed validation error with a content-free public code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RetentionMarker:
    created_at: datetime
    delete_after: datetime


@dataclass(frozen=True)
class SweepResult:
    scanned: int
    eligible: int
    deleted: int
    ignored: int
    errors: int

    def as_dict(self) -> dict[str, int]:
        return {
            "deleted": self.deleted,
            "eligible": self.eligible,
            "errors": self.errors,
            "ignored": self.ignored,
            "scanned": self.scanned,
        }


def _mode(metadata: os.stat_result) -> int:
    return stat.S_IMODE(metadata.st_mode)


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise SafetyError("naive_timestamp")
    return value.astimezone(UTC).replace(microsecond=0).strftime(TIMESTAMP_FORMAT)


def _parse_timestamp(value: str) -> datetime:
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise SafetyError("invalid_retention_marker")
    try:
        parsed = datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError as error:
        raise SafetyError("invalid_retention_marker") from error
    if _format_timestamp(parsed) != value:
        raise SafetyError("invalid_retention_marker")
    return parsed


def _require_protected_ancestors(path: Path) -> None:
    current = path.parent
    allowed_owners = {0, os.getuid()}
    while True:
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise SafetyError("ancestor_unavailable") from error
        mode = _mode(metadata)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in allowed_owners
        ):
            raise SafetyError("unsafe_ancestor_chain")
        if mode & 0o022 and not (
            metadata.st_uid == 0 and mode & stat.S_ISVTX
        ):
            raise SafetyError("unsafe_ancestor_chain")
        if current.parent == current:
            return
        current = current.parent


def _canonical_directory(path: Path, *, private: bool) -> tuple[Path, os.stat_result]:
    if not path.is_absolute():
        raise SafetyError("absolute_directory_required")
    try:
        resolved = path.resolve(strict=True)
        metadata = os.lstat(path)
    except OSError as error:
        raise SafetyError("directory_unavailable") from error
    if resolved != path or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SafetyError("noncanonical_directory")
    _require_protected_ancestors(path)
    if metadata.st_uid != os.getuid():
        raise SafetyError("directory_owner_mismatch")
    if private and _mode(metadata) != 0o700:
        raise SafetyError("directory_not_owner_private")
    if not private and _mode(metadata) & 0o022:
        raise SafetyError("directory_is_writable_by_others")
    return resolved, metadata


def validate_operations_root(path: Path) -> tuple[Path, os.stat_result]:
    return _canonical_directory(path, private=True)


def _open_directory(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags)
    except OSError as error:
        raise SafetyError("directory_open_failed") from error


def _fsync_directory(path: Path) -> None:
    descriptor = _open_directory(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _random_token() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(6))


def _unused_operation_paths(root: Path) -> tuple[Path, Path]:
    for _ in range(128):
        token = _random_token()
        final = root / f"{OPERATION_PREFIX}{token}"
        stage = root / f".tacua-pilot-migration.{token}.incomplete"
        if not os.path.lexists(final) and not os.path.lexists(stage):
            return final, stage
    raise SafetyError("operation_name_exhausted")


def _write_retention_marker(directory: Path, created_at: datetime) -> None:
    if created_at.tzinfo is None:
        raise SafetyError("naive_timestamp")
    created_at = created_at.astimezone(UTC).replace(microsecond=0)
    delete_after = created_at + timedelta(days=RETENTION_DAYS)
    payload = (
        f"artifact_class={ARTIFACT_CLASS}\n"
        f"created_at={_format_timestamp(created_at)}\n"
        f"delete_after={_format_timestamp(delete_after)}\n"
    ).encode("ascii")
    marker = directory / RETENTION_MARKER
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(marker, flags, 0o600)
    except OSError as error:
        raise SafetyError("retention_marker_create_failed") from error
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(directory)


def create_operation(root: Path, *, created_at: datetime | None = None) -> Path:
    root, _ = validate_operations_root(root)
    final, stage = _unused_operation_paths(root)
    try:
        os.mkdir(stage, 0o700)
        os.chmod(stage, 0o700)
        _write_retention_marker(stage, created_at or _now())
        os.rename(stage, final)
        _fsync_directory(root)
    except Exception:
        # An incomplete owner-private directory is intentionally retained for
        # operator inspection.  It is not eligible for automatic deletion.
        raise
    return final


def _read_marker(candidate: Path, expected_owner: int) -> RetentionMarker:
    marker = candidate / RETENTION_MARKER
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(marker, flags)
    except OSError as error:
        raise SafetyError("invalid_retention_marker") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or metadata.st_nlink != 1
            or _mode(metadata) != 0o600
            or metadata.st_size > MAX_MARKER_BYTES
        ):
            raise SafetyError("invalid_retention_marker")
        payload = os.read(descriptor, MAX_MARKER_BYTES + 1)
        if len(payload) > MAX_MARKER_BYTES or os.read(descriptor, 1):
            raise SafetyError("invalid_retention_marker")
    finally:
        os.close(descriptor)
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise SafetyError("invalid_retention_marker") from error
    lines = text.splitlines(keepends=True)
    if len(lines) != 3 or any(not line.endswith("\n") for line in lines):
        raise SafetyError("invalid_retention_marker")
    values: dict[str, str] = {}
    for raw_line in lines:
        line = raw_line[:-1]
        if "=" not in line:
            raise SafetyError("invalid_retention_marker")
        key, value = line.split("=", 1)
        if key in values:
            raise SafetyError("invalid_retention_marker")
        values[key] = value
    if set(values) != {"artifact_class", "created_at", "delete_after"}:
        raise SafetyError("invalid_retention_marker")
    if values["artifact_class"] != ARTIFACT_CLASS:
        raise SafetyError("invalid_retention_marker")
    created_at = _parse_timestamp(values["created_at"])
    delete_after = _parse_timestamp(values["delete_after"])
    if delete_after != created_at + timedelta(days=RETENTION_DAYS):
        raise SafetyError("invalid_retention_marker")
    return RetentionMarker(created_at=created_at, delete_after=delete_after)


def _validate_regular(metadata: os.stat_result, expected_owner: int) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or metadata.st_nlink != 1
        or _mode(metadata) != 0o600
    ):
        raise SafetyError("unsafe_operation_contents")


def _validate_directory(
    metadata: os.stat_result, expected_owner: int, expected_device: int
) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or metadata.st_dev != expected_device
        or _mode(metadata) != 0o700
    ):
        raise SafetyError("unsafe_operation_contents")


def _open_child_directory(parent_descriptor: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as error:
        raise SafetyError("unsafe_operation_contents") from error


def _validate_tree_descriptor(
    descriptor: int, *, expected_owner: int, expected_device: int
) -> None:
    with os.scandir(descriptor) as entries:
        for entry in entries:
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise SafetyError("unsafe_operation_contents") from error
            if stat.S_ISREG(metadata.st_mode):
                _validate_regular(metadata, expected_owner)
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                raise SafetyError("unsafe_operation_contents")
            _validate_directory(metadata, expected_owner, expected_device)
            child = _open_child_directory(descriptor, entry.name)
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise SafetyError("unsafe_operation_contents")
                _validate_tree_descriptor(
                    child,
                    expected_owner=expected_owner,
                    expected_device=expected_device,
                )
            finally:
                os.close(child)


def _reject_mount_points(path: Path, *, include_root: bool) -> None:
    if include_root and os.path.ismount(path):
        raise SafetyError("unsafe_operation_contents")
    for directory, child_directories, _ in os.walk(path, followlinks=False):
        for name in child_directories:
            if os.path.ismount(Path(directory) / name):
                raise SafetyError("unsafe_operation_contents")


def _validate_candidate(
    candidate: Path,
    *,
    root_metadata: os.stat_result,
    now: datetime,
) -> tuple[RetentionMarker, tuple[int, int, int, int]]:
    try:
        metadata = os.lstat(candidate)
    except OSError as error:
        raise SafetyError("unsafe_operation_directory") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != root_metadata.st_uid
        or metadata.st_dev != root_metadata.st_dev
        or _mode(metadata) != 0o700
    ):
        raise SafetyError("unsafe_operation_directory")
    _reject_mount_points(candidate, include_root=True)
    marker = _read_marker(candidate, root_metadata.st_uid)
    if marker.created_at > now:
        raise SafetyError("future_retention_marker")
    descriptor = _open_directory(candidate)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise SafetyError("unsafe_operation_directory")
        _validate_tree_descriptor(
            descriptor,
            expected_owner=root_metadata.st_uid,
            expected_device=root_metadata.st_dev,
        )
    finally:
        os.close(descriptor)
    identity = (metadata.st_dev, metadata.st_ino, metadata.st_uid, _mode(metadata))
    return marker, identity


def _delete_tree_contents(
    descriptor: int, *, expected_owner: int, expected_device: int
) -> None:
    # A complete validation pass is performed immediately before this bounded,
    # descriptor-relative removal.  Each entry is checked again before use.
    with os.scandir(descriptor) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISREG(metadata.st_mode):
            _validate_regular(metadata, expected_owner)
            os.unlink(name, dir_fd=descriptor)
            continue
        _validate_directory(metadata, expected_owner, expected_device)
        child = _open_child_directory(descriptor, name)
        try:
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise SafetyError("unsafe_operation_contents")
            _delete_tree_contents(
                child,
                expected_owner=expected_owner,
                expected_device=expected_device,
            )
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=descriptor)


def _delete_candidate(
    root: Path,
    candidate_name: str,
    *,
    root_metadata: os.stat_result,
    expected_identity: tuple[int, int, int, int],
) -> None:
    root_descriptor = _open_directory(root)
    try:
        metadata = os.stat(candidate_name, dir_fd=root_descriptor, follow_symlinks=False)
        identity = (metadata.st_dev, metadata.st_ino, metadata.st_uid, _mode(metadata))
        if identity != expected_identity:
            raise SafetyError("operation_identity_changed")
        candidate_descriptor = _open_child_directory(root_descriptor, candidate_name)
        try:
            opened = os.fstat(candidate_descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise SafetyError("operation_identity_changed")
            _validate_tree_descriptor(
                candidate_descriptor,
                expected_owner=root_metadata.st_uid,
                expected_device=root_metadata.st_dev,
            )
            _delete_tree_contents(
                candidate_descriptor,
                expected_owner=root_metadata.st_uid,
                expected_device=root_metadata.st_dev,
            )
        finally:
            os.close(candidate_descriptor)
        os.rmdir(candidate_name, dir_fd=root_descriptor)
        os.fsync(root_descriptor)
    finally:
        os.close(root_descriptor)


def sweep_operations(
    root: Path,
    *,
    now: datetime | None = None,
    apply: bool = False,
) -> SweepResult:
    root, root_metadata = validate_operations_root(root)
    requested_now = now or _now()
    if requested_now.tzinfo is None:
        raise SafetyError("naive_timestamp")
    effective_now = requested_now.astimezone(UTC).replace(microsecond=0)
    scanned = eligible = deleted = ignored = errors = 0
    with os.scandir(root) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        if OPERATION_NAME.fullmatch(name) is None:
            continue
        scanned += 1
        candidate = root / name
        try:
            marker, identity = _validate_candidate(
                candidate,
                root_metadata=root_metadata,
                now=effective_now,
            )
        except SafetyError:
            ignored += 1
            continue
        if marker.delete_after > effective_now:
            continue
        eligible += 1
        if not apply:
            continue
        try:
            _delete_candidate(
                root,
                name,
                root_metadata=root_metadata,
                expected_identity=identity,
            )
        except (OSError, SafetyError):
            errors += 1
            continue
        deleted += 1
    return SweepResult(
        scanned=scanned,
        eligible=eligible,
        deleted=deleted,
        ignored=ignored,
        errors=errors,
    )


def _validate_migration_entry(path: Path, expected_owner: int) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise SafetyError("migration_entry_unavailable") from error
    if metadata.st_uid != expected_owner or stat.S_ISLNK(metadata.st_mode):
        raise SafetyError("unsafe_migration_entry")
    if os.path.ismount(path):
        raise SafetyError("unsafe_migration_entry")
    if stat.S_ISREG(metadata.st_mode):
        if metadata.st_nlink != 1:
            raise SafetyError("unsafe_migration_entry")
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise SafetyError("unsafe_migration_entry")
    try:
        _reject_mount_points(path, include_root=True)
    except SafetyError as error:
        raise SafetyError("unsafe_migration_entry") from error
    for directory, child_directories, filenames in os.walk(path, followlinks=False):
        for name in [*child_directories, *filenames]:
            child = Path(directory) / name
            child_metadata = os.lstat(child)
            if (
                child_metadata.st_uid != expected_owner
                or stat.S_ISLNK(child_metadata.st_mode)
            ):
                raise SafetyError("unsafe_migration_entry")
            if stat.S_ISDIR(child_metadata.st_mode):
                continue
            if not stat.S_ISREG(child_metadata.st_mode) or child_metadata.st_nlink != 1:
                raise SafetyError("unsafe_migration_entry")


def _harden_tree(path: Path) -> None:
    metadata = os.lstat(path)
    if stat.S_ISREG(metadata.st_mode):
        os.chmod(path, 0o600)
        return
    os.chmod(path, 0o700)
    for directory, child_directories, filenames in os.walk(path, followlinks=False):
        os.chmod(directory, 0o700)
        for name in child_directories:
            os.chmod(Path(directory) / name, 0o700)
        for name in filenames:
            os.chmod(Path(directory) / name, 0o600)


def _validated_migration_sources(
    root: Path,
    legacy_root: Path,
    entry_names: Iterable[str],
) -> list[Path]:
    root, root_metadata = validate_operations_root(root)
    legacy_root, legacy_metadata = _canonical_directory(legacy_root, private=True)
    if root_metadata.st_dev != legacy_metadata.st_dev:
        raise SafetyError("migration_requires_same_filesystem")
    names = list(entry_names)
    if not names or len(names) != len(set(names)):
        raise SafetyError("migration_entries_required")
    sources: list[Path] = []
    for name in names:
        if name in {".", ".."} or ENTRY_NAME.fullmatch(name) is None:
            raise SafetyError("invalid_migration_entry_name")
        source = legacy_root / name
        if source == root or source in root.parents or root in source.parents:
            raise SafetyError("migration_scope_overlap")
        _validate_migration_entry(source, legacy_metadata.st_uid)
        sources.append(source)
    return sources


def migrate_entries(
    root: Path,
    legacy_root: Path,
    entry_names: Sequence[str],
    *,
    apply: bool = False,
    created_at: datetime | None = None,
) -> dict[str, int | bool | str]:
    root, _ = validate_operations_root(root)
    sources = _validated_migration_sources(root, legacy_root, entry_names)
    if not apply:
        return {"applied": False, "entry_count": len(sources)}

    final, stage = _unused_operation_paths(root)
    artifacts = stage / "artifacts"
    os.mkdir(stage, 0o700)
    os.chmod(stage, 0o700)
    os.mkdir(artifacts, 0o700)
    os.chmod(artifacts, 0o700)
    try:
        for source in sources:
            _harden_tree(source)
            os.rename(source, artifacts / source.name)
        _harden_tree(artifacts)
        _fsync_directory(artifacts)
        _fsync_directory(Path(legacy_root))
        _write_retention_marker(stage, created_at or _now())
        os.rename(stage, final)
        _fsync_directory(root)
    except Exception:
        # Never delete or roll back partial migration state automatically.  A
        # private, unmatched .incomplete directory preserves moved evidence.
        raise
    return {
        "applied": True,
        "entry_count": len(sources),
        "operation_name": final.name,
    }


def render_launchd_schedule(
    root: Path,
    *,
    tool_path: Path,
    output: Path,
    python_path: Path,
    hour: int = 3,
    minute: int = 17,
) -> None:
    root, _ = validate_operations_root(root)
    if not 0 <= hour <= 23 or not 0 <= minute <= 59:
        raise SafetyError("invalid_schedule_time")
    if not tool_path.is_absolute() or not python_path.is_absolute() or not output.is_absolute():
        raise SafetyError("absolute_schedule_paths_required")
    try:
        tool_resolved = tool_path.resolve(strict=True)
        tool_metadata = os.lstat(tool_path)
        python_resolved = python_path.resolve(strict=True)
        python_metadata = os.lstat(python_path)
    except OSError as error:
        raise SafetyError("schedule_program_unavailable") from error
    if (
        tool_resolved != tool_path
        or python_resolved != python_path
        or not stat.S_ISREG(tool_metadata.st_mode)
        or not stat.S_ISREG(python_metadata.st_mode)
        or tool_metadata.st_uid != os.getuid()
        or python_metadata.st_uid not in {0, os.getuid()}
        or tool_metadata.st_mode & 0o022
        or python_metadata.st_mode & 0o022
        or python_metadata.st_mode & 0o111 == 0
    ):
        raise SafetyError("unsafe_schedule_program")
    _require_protected_ancestors(tool_path)
    _require_protected_ancestors(python_path)
    output_parent, _ = _canonical_directory(output.parent, private=False)
    if os.path.lexists(output):
        raise SafetyError("schedule_output_exists")
    document = {
        "Label": LAUNCHD_LABEL,
        "LowPriorityIO": True,
        "ProcessType": "Background",
        "ProgramArguments": [
            str(python_path),
            str(tool_path),
            "sweep",
            "--operations-root",
            str(root),
            "--apply",
            "--quiet",
        ],
        "RunAtLoad": True,
        "StandardErrorPath": "/dev/null",
        "StandardOutPath": "/dev/null",
        "StartCalendarInterval": {"Hour": hour, "Minute": minute},
        "ThrottleInterval": 60,
        "Umask": 0o077,
    }
    payload = plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(output, flags, 0o600)
    except OSError as error:
        raise SafetyError("schedule_output_create_failed") from error
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(output_parent)


def _emit(document: dict[str, object], *, quiet: bool = False) -> None:
    if not quiet:
        print(json.dumps(document, sort_keys=True, separators=(",", ":")))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create one managed private operation")
    create.add_argument("--operations-root", required=True, type=Path)

    migrate = subparsers.add_parser(
        "migrate", help="validate or migrate named direct children into managed retention"
    )
    migrate.add_argument("--operations-root", required=True, type=Path)
    migrate.add_argument("--legacy-root", required=True, type=Path)
    migrate.add_argument("--entry", action="append", required=True)
    migrate.add_argument("--apply", action="store_true")

    sweep = subparsers.add_parser("sweep", help="find or remove expired managed operations")
    sweep.add_argument("--operations-root", required=True, type=Path)
    sweep.add_argument("--apply", action="store_true")
    sweep.add_argument("--quiet", action="store_true")

    schedule = subparsers.add_parser(
        "render-launchd", help="write an unloaded daily launchd schedule"
    )
    schedule.add_argument("--operations-root", required=True, type=Path)
    schedule.add_argument("--tool-path", type=Path, default=Path(__file__).resolve())
    schedule.add_argument("--python-path", required=True, type=Path)
    schedule.add_argument("--output", required=True, type=Path)
    schedule.add_argument("--hour", type=int, default=3)
    schedule.add_argument("--minute", type=int, default=17)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "create":
            operation = create_operation(arguments.operations_root)
            _emit({"operation_name": operation.name})
            return 0
        if arguments.command == "migrate":
            result = migrate_entries(
                arguments.operations_root,
                arguments.legacy_root,
                arguments.entry,
                apply=arguments.apply,
            )
            _emit(result)
            return 0
        if arguments.command == "sweep":
            result = sweep_operations(
                arguments.operations_root,
                apply=arguments.apply,
            )
            _emit(result.as_dict(), quiet=arguments.quiet)
            return 2 if result.errors or result.ignored else 0
        if arguments.command == "render-launchd":
            render_launchd_schedule(
                arguments.operations_root,
                tool_path=arguments.tool_path,
                output=arguments.output,
                python_path=arguments.python_path,
                hour=arguments.hour,
                minute=arguments.minute,
            )
            _emit({"schedule_written": True})
            return 0
    except SafetyError as error:
        print(f"TACUA_PILOT_DIAGNOSTICS_FAILED {error.code}", file=sys.stderr)
        return 2
    except OSError:
        print("TACUA_PILOT_DIAGNOSTICS_FAILED io_failure", file=sys.stderr)
        return 2
    raise AssertionError("unhandled command")


if __name__ == "__main__":
    raise SystemExit(main())
