#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run exclusive isolated processing against one stopped Compose state volume.

The one-shot worker container receives the named state volume but never the
Docker socket.  A private, single-purpose Unix socket transfers only the
adapter's already-open read-only descriptors to this trusted host process.
The host then invokes ``run_isolated_processor.py`` with its normal rootless
Docker isolation gate.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Mapping, NoReturn, Sequence


_SOURCE_BOOTSTRAP_CONTRACT = "tacua.compose-source-bootstrap@1.0.0"
_SOURCE_MANIFEST_CONTRACT = "tacua.compose-source-manifest@1.0.0"
_SOURCE_DIRECTORY_NAME = "verified-source"
_SOURCE_STAGING_NAME = ".verified-source.next"
_SOURCE_MANIFEST_NAME = "source-manifest.json"
_SOURCE_MANIFEST_STAGING_NAME = ".source-manifest.json.next"
_SOURCE_MAX_FILES = 256
_SOURCE_MAX_FILE_BYTES = 2_097_152
_SOURCE_MAX_BYTES = 16_777_216
_SOURCE_EXACT_PATHS = (
    "services/backend/scripts/run_compose_isolated_processing.py",
    "services/backend/scripts/run_isolated_processor.py",
)
_SOURCE_FAMILIES = (
    ("services/backend/src/tacua_backend", re.compile(r"^[A-Za-z0-9_]+\.py$")),
    ("contracts/approved-handoff/src", re.compile(r"^[A-Za-z0-9_]+\.py$")),
    (
        "contracts/approved-handoff/schemas",
        re.compile(r"^[a-z0-9][a-z0-9-]*\.schema\.json$"),
    ),
    ("contracts/runtime/src", re.compile(r"^[A-Za-z0-9_]+\.py$")),
    (
        "contracts/runtime/schemas",
        re.compile(r"^[a-z0-9][a-z0-9-]*\.schema\.json$"),
    ),
    (
        "contracts/sdk-backend-protocol/src",
        re.compile(r"^[A-Za-z0-9_]+\.py$"),
    ),
    (
        "contracts/sdk-backend-protocol/schemas",
        re.compile(r"^[a-z0-9][a-z0-9-]*\.schema\.json$"),
    ),
    ("contracts/ticket-candidate/src", re.compile(r"^[A-Za-z0-9_]+\.py$")),
    (
        "contracts/ticket-candidate/schemas",
        re.compile(r"^[a-z0-9][a-z0-9-]*\.schema\.json$"),
    ),
)
_BOOTSTRAP_ENV_NAMES = (
    "TACUA_SOURCE_BOOTSTRAP",
    "TACUA_SOURCE_MODE",
    "TACUA_SOURCE_OPERATION",
    "TACUA_SOURCE_DIGEST",
    "TACUA_SOURCE_ORIGINAL_ROOT",
    "TACUA_SOURCE_LOCK_FD",
)
_BROKER_FAILURE_STAGE = "ENTRY"


class _SourceBootstrapError(RuntimeError):
    def __init__(
        self,
        detail: str,
        *,
        code: str = "BRIDGE_SOURCE_BOOTSTRAP_FAILED",
    ) -> None:
        super().__init__(detail)
        self.code = code


class _BootstrapArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        raise _SourceBootstrapError(
            "bridge arguments are invalid",
            code="BRIDGE_INPUT_INVALID",
        )


def _bootstrap_canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _bootstrap_read_file(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise _SourceBootstrapError("source file cannot be opened") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise _SourceBootstrapError("source file identity is invalid")
        payload = bytearray()
        while len(payload) <= maximum:
            block = os.read(
                descriptor,
                min(65_536, maximum + 1 - len(payload)),
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise _SourceBootstrapError("source file changed while read")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _bootstrap_write_file(path: Path, payload: bytes, mode: int) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, mode)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("source snapshot write stopped")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _bootstrap_fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _bootstrap_source_paths(root: Path) -> tuple[str, ...]:
    paths = list(_SOURCE_EXACT_PATHS)
    for directory_name, pattern in _SOURCE_FAMILIES:
        directory = root / directory_name
        try:
            metadata = directory.lstat()
            entries = tuple(directory.iterdir())
        except OSError as error:
            raise _SourceBootstrapError(
                "source family is unavailable"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise _SourceBootstrapError("source family is unsafe")
        for entry in entries:
            if pattern.fullmatch(entry.name) is None:
                continue
            entry_metadata = entry.lstat()
            if (
                not stat.S_ISREG(entry_metadata.st_mode)
                or stat.S_ISLNK(entry_metadata.st_mode)
                or entry_metadata.st_nlink != 1
            ):
                raise _SourceBootstrapError("source entry is unsafe")
            paths.append(str(entry.relative_to(root)).replace(os.sep, "/"))
    result = tuple(sorted(paths))
    if (
        len(result) <= len(_SOURCE_EXACT_PATHS)
        or len(result) > _SOURCE_MAX_FILES
        or len(set(result)) != len(result)
        or any(not (root / relative).is_file() for relative in result)
    ):
        raise _SourceBootstrapError("source inventory is invalid")
    return result


def _bootstrap_source_path_allowed(relative: str) -> bool:
    if relative in _SOURCE_EXACT_PATHS:
        return True
    path = Path(relative)
    return any(
        str(path.parent).replace(os.sep, "/") == directory
        and pattern.fullmatch(path.name) is not None
        for directory, pattern in _SOURCE_FAMILIES
    )


def _bootstrap_manifest_digest(files: Mapping[str, str]) -> str:
    return "sha256:" + hashlib.sha256(
        _bootstrap_canonical_json(files)
    ).hexdigest()


def _bootstrap_make_directory(root: Path, relative_parent: Path) -> None:
    current = root
    for part in relative_parent.parts:
        current /= part
        try:
            current.mkdir(mode=0o700)
            current.chmod(0o700)
        except FileExistsError:
            metadata = current.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise _SourceBootstrapError(
                    "source snapshot directory is unsafe"
                )


def _bootstrap_snapshot_source(
    repository_root: Path,
    operation: Path,
) -> dict[str, Any]:
    _bootstrap_validate_operation_directory(operation)
    staging = operation / _SOURCE_STAGING_NAME
    destination = operation / _SOURCE_DIRECTORY_NAME
    manifest_staging = operation / _SOURCE_MANIFEST_STAGING_NAME
    manifest_path = operation / _SOURCE_MANIFEST_NAME
    if any(
        path.exists() or path.is_symlink()
        for path in (
            staging,
            destination,
            manifest_staging,
            manifest_path,
        )
    ):
        raise _SourceBootstrapError("source snapshot already exists")
    staging.mkdir(mode=0o700)
    staging.chmod(0o700)
    files: dict[str, str] = {}
    total = 0
    for relative in _bootstrap_source_paths(repository_root):
        payload = _bootstrap_read_file(
            repository_root / relative,
            _SOURCE_MAX_FILE_BYTES,
        )
        total += len(payload)
        if total > _SOURCE_MAX_BYTES:
            raise _SourceBootstrapError("source snapshot is oversized")
        target = staging / relative
        _bootstrap_make_directory(staging, target.parent.relative_to(staging))
        _bootstrap_write_file(target, payload, 0o400)
        files[relative] = "sha256:" + hashlib.sha256(payload).hexdigest()
    for directory in sorted(
        (
            path
            for path in staging.rglob("*")
            if path.is_dir() and not path.is_symlink()
        ),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        _bootstrap_fsync_directory(directory)
    _bootstrap_fsync_directory(staging)
    manifest = {
        "contract_version": _SOURCE_MANIFEST_CONTRACT,
        "files": files,
        "original_root": str(repository_root),
        "source_digest": _bootstrap_manifest_digest(files),
    }
    _bootstrap_write_file(
        manifest_staging,
        _bootstrap_canonical_json(manifest),
        0o400,
    )
    os.replace(staging, destination)
    _bootstrap_fsync_directory(operation)
    os.replace(manifest_staging, manifest_path)
    _bootstrap_fsync_directory(operation)
    return manifest


def _bootstrap_validate_operation_directory(operation: Path) -> None:
    metadata = operation.lstat()
    if (
        not operation.is_absolute()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _SourceBootstrapError("source operation directory is unsafe")


def _bootstrap_parse_manifest(payload: bytes) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def reject_number(_value: str) -> None:
        raise ValueError

    try:
        value = json.loads(
            payload,
            object_pairs_hook=reject_duplicate,
            parse_float=reject_number,
            parse_int=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise _SourceBootstrapError("source manifest is invalid") from error
    if not isinstance(value, dict):
        raise _SourceBootstrapError("source manifest is invalid")
    return value


def _bootstrap_validate_snapshot(
    operation: Path,
    expected_digest: str | None = None,
) -> dict[str, Any]:
    _bootstrap_validate_operation_directory(operation)
    manifest_path = operation / _SOURCE_MANIFEST_NAME
    metadata = manifest_path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o400
    ):
        raise _SourceBootstrapError("source manifest identity is invalid")
    payload = _bootstrap_read_file(manifest_path, 131_072)
    manifest = _bootstrap_parse_manifest(payload)
    files = manifest.get("files")
    original_root = manifest.get("original_root")
    source_digest = manifest.get("source_digest")
    if (
        set(manifest)
        != {
            "contract_version",
            "files",
            "original_root",
            "source_digest",
        }
        or manifest.get("contract_version") != _SOURCE_MANIFEST_CONTRACT
        or not isinstance(files, dict)
        or not 1 <= len(files) <= _SOURCE_MAX_FILES
        or not isinstance(original_root, str)
        or not Path(original_root).is_absolute()
        or Path(original_root) != Path(os.path.abspath(original_root))
        or any(
            character in original_root
            for character in {"\n", "\r", "\x00"}
        )
        or not isinstance(source_digest, str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", source_digest) is None
        or source_digest != _bootstrap_manifest_digest(files)
        or (
            expected_digest is not None
            and source_digest != expected_digest
        )
        or _bootstrap_canonical_json(manifest) != payload
    ):
        raise _SourceBootstrapError("source manifest is invalid")
    source_root = operation / _SOURCE_DIRECTORY_NAME
    root_metadata = source_root.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise _SourceBootstrapError("source snapshot root is invalid")
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for current, names, filenames in os.walk(
        source_root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        for name in names:
            child = current_path / name
            relative = str(child.relative_to(source_root)).replace(
                os.sep,
                "/",
            )
            child_metadata = child.lstat()
            if (
                not stat.S_ISDIR(child_metadata.st_mode)
                or stat.S_ISLNK(child_metadata.st_mode)
                or child_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(child_metadata.st_mode) != 0o700
            ):
                raise _SourceBootstrapError(
                    "source snapshot directory is unsafe"
                )
            actual_directories.add(relative)
        for name in filenames:
            child = current_path / name
            relative = str(child.relative_to(source_root)).replace(
                os.sep,
                "/",
            )
            if not _bootstrap_source_path_allowed(relative):
                raise _SourceBootstrapError(
                    "source snapshot contains an unexpected file"
                )
            actual_files.add(relative)
    expected_directories = {
        str(parent).replace(os.sep, "/")
        for relative in files
        for parent in Path(relative).parents
        if str(parent) != "."
    }
    if (
        actual_files != set(files)
        or actual_directories != expected_directories
    ):
        raise _SourceBootstrapError("source snapshot tree differs")
    expected_paths = _bootstrap_source_paths(source_root)
    if set(files) != set(expected_paths):
        raise _SourceBootstrapError("source snapshot inventory differs")
    total = 0
    for relative in expected_paths:
        path = source_root / relative
        item_metadata = path.lstat()
        if (
            not stat.S_ISREG(item_metadata.st_mode)
            or stat.S_ISLNK(item_metadata.st_mode)
            or item_metadata.st_uid != os.geteuid()
            or item_metadata.st_nlink != 1
            or stat.S_IMODE(item_metadata.st_mode) != 0o400
        ):
            raise _SourceBootstrapError("source snapshot file is unsafe")
        item = _bootstrap_read_file(path, _SOURCE_MAX_FILE_BYTES)
        total += len(item)
        if (
            total > _SOURCE_MAX_BYTES
            or files.get(relative)
            != "sha256:" + hashlib.sha256(item).hexdigest()
        ):
            raise _SourceBootstrapError("source snapshot digest differs")
    return manifest


def _bootstrap_raw_option(arguments: Sequence[str], name: str) -> str | None:
    values: list[str] = []
    prefix = name + "="
    for index, argument in enumerate(arguments):
        if argument == name and index + 1 < len(arguments):
            values.append(arguments[index + 1])
        elif argument.startswith(prefix):
            values.append(argument[len(prefix):])
    return values[0] if len(values) == 1 and values[0] else None


def _bootstrap_validate_cli_arguments(
    arguments: Sequence[str],
    *,
    recovery: bool,
) -> None:
    parser = _BootstrapArgumentParser(add_help=False)
    parser.add_argument("--project", required=True)
    parser.add_argument("--operation-directory", required=True)
    parser.add_argument("--config-file", required=True)
    parser.add_argument("--admin-secret-file", required=True)
    parser.add_argument("--allow-mutable-image", action="store_true")
    parser.add_argument("--expected-published-port", type=int)
    if not recovery:
        parser.add_argument("--compose-json", required=True)
        parser.add_argument("--isolated-command-file", required=True)
        parser.add_argument("--worker-id", default="worker_compose_isolated")
        parser.add_argument(
            "--adapter-contract",
            choices=(
                "tacua.local-processing-command@1.0.0",
                "tacua.local-processing-command@1.1.0",
            ),
            default="tacua.local-processing-command@1.0.0",
        )
        mode = parser.add_mutually_exclusive_group(required=True)
        mode.add_argument("--run-once", action="store_true")
        mode.add_argument("--drain", action="store_true")
        parser.add_argument("--max-stages", type=int, default=100)
    parsed = parser.parse_args(arguments)
    if (
        parsed.expected_published_port is not None
        and not 1 <= parsed.expected_published_port <= 65_535
    ):
        parser.error("expected published port is invalid")
    if not recovery and (
        re.fullmatch(r"^[a-z][a-z0-9_-]{2,63}$", parsed.worker_id)
        is None
        or not 1 <= parsed.max_stages <= 10_000
    ):
        parser.error("worker ID or stage bound is invalid")


def _bootstrap_operation_path(parent_value: str, project: str) -> Path:
    if re.fullmatch(r"^[a-z0-9][a-z0-9_-]{0,62}$", project) is None:
        raise _SourceBootstrapError("bootstrap project is invalid")
    parent = Path(parent_value)
    metadata = parent.lstat()
    resolved = parent.resolve(strict=True)
    if (
        not parent.is_absolute()
        or resolved != parent
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _SourceBootstrapError("bootstrap operation parent is unsafe")
    operation = parent / f"tacua-compose-processing-{project}"
    socket_path = operation / "processing-bridge.sock"
    if (
        any(character in str(operation) for character in {",", "\n", "\r", "\x00"})
        or len(os.fsencode(socket_path)) > 103
    ):
        raise _SourceBootstrapError("bootstrap operation path is unsafe")
    return operation


def _bootstrap_acquire_lock(project: str) -> int:
    path = Path(f"/tmp/tacua-compose-processing-{project}.lock")
    descriptor = os.open(
        path,
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        path_metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise OSError("bootstrap lock identity differs")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError as error:
        os.close(descriptor)
        raise _SourceBootstrapError(
            "another Compose processing bridge owns this project",
            code="BRIDGE_BUSY",
        ) from error
    except Exception:
        os.close(descriptor)
        raise


def _bootstrap_validate_lock(descriptor: int, project: str) -> None:
    metadata = os.fstat(descriptor)
    path_metadata = Path(
        f"/tmp/tacua-compose-processing-{project}.lock"
    ).lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (metadata.st_dev, metadata.st_ino)
        != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        raise _SourceBootstrapError("inherited bootstrap lock is invalid")
    probe = os.open(
        f"/tmp/tacua-compose-processing-{project}.lock",
        os.O_RDWR
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        fcntl.flock(probe, fcntl.LOCK_UN)
    finally:
        os.close(probe)
    raise _SourceBootstrapError("inherited bootstrap lock is not held")


def _bootstrap_exec_environment(
    *,
    mode: str,
    operation: Path,
    manifest: Mapping[str, Any],
    lock_descriptor: int | None,
) -> dict[str, str]:
    environment = {
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TACUA_SOURCE_BOOTSTRAP": _SOURCE_BOOTSTRAP_CONTRACT,
        "TACUA_SOURCE_MODE": mode,
        "TACUA_SOURCE_OPERATION": str(operation),
        "TACUA_SOURCE_DIGEST": str(manifest["source_digest"]),
        "TACUA_SOURCE_ORIGINAL_ROOT": str(manifest["original_root"]),
    }
    if lock_descriptor is not None:
        environment["TACUA_SOURCE_LOCK_FD"] = str(lock_descriptor)
    for name in (
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "XDG_RUNTIME_DIR",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _bootstrap_exec_snapshot(
    *,
    mode: str,
    operation: Path,
    manifest: Mapping[str, Any],
    lock_descriptor: int,
    arguments: Sequence[str],
) -> None:
    flags = fcntl.fcntl(lock_descriptor, fcntl.F_GETFD)
    fcntl.fcntl(
        lock_descriptor,
        fcntl.F_SETFD,
        flags & ~fcntl.FD_CLOEXEC,
    )
    script = (
        operation
        / _SOURCE_DIRECTORY_NAME
        / _SOURCE_EXACT_PATHS[0]
    )
    os.execve(
        sys.executable,
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(script),
            *arguments,
        ],
        _bootstrap_exec_environment(
            mode=mode,
            operation=operation,
            manifest=manifest,
            lock_descriptor=lock_descriptor,
        ),
    )


def _bootstrap_adopt_environment(
    arguments: Sequence[str],
) -> dict[str, Any]:
    values = {name: os.environ.get(name) for name in _BOOTSTRAP_ENV_NAMES}
    if values["TACUA_SOURCE_BOOTSTRAP"] != _SOURCE_BOOTSTRAP_CONTRACT:
        raise _SourceBootstrapError("source bootstrap marker is missing")
    mode = values["TACUA_SOURCE_MODE"]
    operation_value = values["TACUA_SOURCE_OPERATION"]
    digest = values["TACUA_SOURCE_DIGEST"]
    original_root = values["TACUA_SOURCE_ORIGINAL_ROOT"]
    if (
        mode not in {"run", "recover", "broker"}
        or not isinstance(operation_value, str)
        or not Path(operation_value).is_absolute()
        or not isinstance(digest, str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None
        or not isinstance(original_root, str)
        or not Path(original_root).is_absolute()
        or Path(original_root) != Path(os.path.abspath(original_root))
    ):
        raise _SourceBootstrapError("source bootstrap marker is invalid")
    operation = Path(operation_value)
    manifest = _bootstrap_validate_snapshot(operation, digest)
    expected_script = (
        operation
        / _SOURCE_DIRECTORY_NAME
        / _SOURCE_EXACT_PATHS[0]
    ).resolve(strict=True)
    expected_mode = (
        "broker"
        if arguments[:1] == ["_broker"]
        else "recover"
        if arguments[:1] == ["recover"]
        else "run"
    )
    if (
        Path(__file__).resolve(strict=True) != expected_script
        or manifest["original_root"] != original_root
        or mode != expected_mode
    ):
        raise _SourceBootstrapError("source bootstrap execution path differs")
    lock_descriptor: int | None = None
    if mode != "broker":
        lock_value = values["TACUA_SOURCE_LOCK_FD"]
        if (
            not isinstance(lock_value, str)
            or re.fullmatch(r"[0-9]{1,9}", lock_value) is None
        ):
            raise _SourceBootstrapError("source bootstrap lock is missing")
        lock_descriptor = int(lock_value)
        project = _bootstrap_raw_option(arguments, "--project")
        if project is None:
            raise _SourceBootstrapError("source bootstrap project is missing")
        _bootstrap_validate_lock(lock_descriptor, project)
        descriptor_flags = fcntl.fcntl(lock_descriptor, fcntl.F_GETFD)
        fcntl.fcntl(
            lock_descriptor,
            fcntl.F_SETFD,
            descriptor_flags | fcntl.FD_CLOEXEC,
        )
    for name in _BOOTSTRAP_ENV_NAMES:
        os.environ.pop(name, None)
    return {
        "lock_descriptor": lock_descriptor,
        "manifest": manifest,
        "mode": mode,
        "operation": operation,
        "original_root": Path(original_root),
        "source_digest": digest,
    }


def _bootstrap_dispatch_arguments(
    arguments: Sequence[str],
) -> dict[str, Any] | None:
    if os.environ.get("TACUA_SOURCE_BOOTSTRAP") is not None:
        return _bootstrap_adopt_environment(arguments)
    if arguments[:1] == ["_broker"]:
        raise _SourceBootstrapError("unverified broker execution is forbidden")
    recovery = arguments[:1] == ["recover"]
    relevant = arguments[1:] if recovery else arguments
    _bootstrap_validate_cli_arguments(relevant, recovery=recovery)
    project = _bootstrap_raw_option(relevant, "--project")
    parent_value = _bootstrap_raw_option(relevant, "--operation-directory")
    if project is None or parent_value is None:
        raise _SourceBootstrapError(
            "bootstrap-critical options must appear exactly once"
        )
    operation = _bootstrap_operation_path(parent_value, project)
    lock_descriptor = _bootstrap_acquire_lock(project)
    try:
        if recovery:
            if (
                operation.exists()
                and (operation / "operation.json").is_file()
            ):
                manifest = _bootstrap_validate_snapshot(operation)
                _bootstrap_exec_snapshot(
                    mode="recover",
                    operation=operation,
                    manifest=manifest,
                    lock_descriptor=lock_descriptor,
                    arguments=arguments,
                )
            return {
                "lock_descriptor": lock_descriptor,
                "manifest": None,
                "mode": "journal_free_recover",
                "operation": operation,
                "original_root": Path(__file__).resolve().parents[3],
                "source_digest": None,
            }
        try:
            operation.mkdir(mode=0o700)
        except FileExistsError as error:
            raise _SourceBootstrapError(
                "a durable operation already requires recovery",
                code="BRIDGE_RECOVERY_REQUIRED",
            ) from error
        operation.chmod(0o700)
        _bootstrap_validate_operation_directory(operation)
        _bootstrap_fsync_directory(operation.parent)
        repository_root = Path(__file__).resolve().parents[3]
        manifest = _bootstrap_snapshot_source(repository_root, operation)
        _bootstrap_validate_snapshot(operation, manifest["source_digest"])
        _bootstrap_exec_snapshot(
            mode="run",
            operation=operation,
            manifest=manifest,
            lock_descriptor=lock_descriptor,
            arguments=arguments,
        )
    except Exception:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)
        raise
    raise _SourceBootstrapError("source bootstrap did not exec")


def _bootstrap_dispatch() -> dict[str, Any] | None:
    os.umask(0o077)
    arguments = list(sys.argv[1:])
    if not arguments or any(value in {"-h", "--help"} for value in arguments):
        return None
    previous: dict[signal.Signals, Any] = {}

    def cancel(_signum: int, _frame: Any) -> None:
        for watched, handler in previous.items():
            signal.signal(watched, handler)
        raise _SourceBootstrapError(
            "source bootstrap was cancelled",
            code="BRIDGE_CANCELLED",
        )

    for watched in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous[watched] = signal.getsignal(watched)
        signal.signal(watched, cancel)
    keep_installed = False
    try:
        context = _bootstrap_dispatch_arguments(arguments)
        if context is not None:
            context["original_signal_handlers"] = previous
            keep_installed = True
        return context
    finally:
        if not keep_installed:
            for watched, handler in previous.items():
                signal.signal(watched, handler)


_VERIFIED_SOURCE_CONTEXT: dict[str, Any] | None = None
if __name__ == "__main__":
    try:
        _VERIFIED_SOURCE_CONTEXT = _bootstrap_dispatch()
    except _SourceBootstrapError as error:
        print(error.code, file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        print("BRIDGE_SOURCE_BOOTSTRAP_FAILED", file=sys.stderr)
        raise SystemExit(1)


ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = ROOT / "services" / "backend"
ORIGINAL_REPOSITORY_ROOT = (
    _VERIFIED_SOURCE_CONTEXT["original_root"]
    if _VERIFIED_SOURCE_CONTEXT is not None
    and _VERIFIED_SOURCE_CONTEXT["manifest"] is not None
    else ROOT
)
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from tacua_backend.config import ConfigError  # noqa: E402
from tacua_backend.operator_tool import (  # noqa: E402
    MAX_COMPOSE_STATE_DATABASE_COPY_BYTES,
    OperatorError,
    deployment_preflight,
    smoke_deployment,
)
from tacua_backend.processing_bridge import (  # noqa: E402
    ERROR_CODE,
    MAX_ADAPTER_DESCRIPTOR,
    MAX_OUTPUT_BYTES,
    MAX_PREVIEW_BYTES,
    MAX_PREVIEW_FILES,
    MAX_RESULT_BYTES,
    REQUEST_CONTRACT,
    RESPONSE_CONTRACT,
    SAFE_OUTPUT_NAME,
    ProcessingBridgeError,
    canonical_json,
    receive_descriptor_batches,
    receive_frame,
    send_frame,
)
from tacua_backend.processing_worker import MAX_DRAIN_STAGES  # noqa: E402


RUNNER_PATH = BACKEND_ROOT / "scripts" / "run_isolated_processor.py"
BRIDGE_CLIENT_MODULE = "tacua_backend.processing_bridge"
BRIDGE_SOCKET_IN_CONTAINER = "/run/tacua/processing-bridge.sock"
BRIDGE_COMMAND_IN_CONTAINER = "/run/tacua/processing-command.json"
CONFIG_IN_CONTAINER = "/run/tacua/config.json"
SECRET_IN_CONTAINER = "/run/secrets/tacua_admin"
STATE_IN_CONTAINER = "/var/lib/tacua"
WORKER_TMPFS_OPTIONS = (
    "rw,nosuid,nodev,noexec,size=67108864,uid=10001,gid=10001,mode=0700"
)
STATE_VERIFIER_MEMORY_BYTES = 4_294_967_296
STATE_VERIFIER_TMPFS_BYTES = 1_073_741_824
STATE_VERIFIER_TMPFS_OPTIONS = (
    "rw,nosuid,nodev,noexec,"
    f"size={STATE_VERIFIER_TMPFS_BYTES},"
    "uid=10001,gid=10001,mode=0700"
)
if (
    STATE_VERIFIER_TMPFS_BYTES
    < 2 * MAX_COMPOSE_STATE_DATABASE_COPY_BYTES
    or STATE_VERIFIER_MEMORY_BYTES < 4 * STATE_VERIFIER_TMPFS_BYTES
):
    raise RuntimeError("offline state verifier resource bounds are incoherent")
REQUEST_TIMEOUT_SECONDS = 225
DOCKER_COMMAND_TIMEOUT_SECONDS = 60
WORKER_STAGE_TIMEOUT_SECONDS = 250
MAX_DOCKER_OUTPUT_BYTES = 2_097_152
MAX_COMPOSE_BYTES = 2_097_152
MAX_JOURNAL_BYTES = 65_536
MAX_UNIX_SOCKET_PATH_BYTES = 103
BROKER_HIGH_FD = 2_048
BROKER_NOFILE_LIMIT = 4_096
PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
VOLUME_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
ID = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
ADAPTER_CONTRACTS = {
    "tacua.local-processing-command@1.0.0",
    "tacua.local-processing-command@1.1.0",
}
BRIDGE_LABEL = "com.tacua.compose-processing-bridge"
BRIDGE_CONTRACT_LABEL = "com.tacua.compose-processing-bridge-contract"
BRIDGE_PROJECT_LABEL = "com.tacua.compose-processing-project"
BRIDGE_ROLE_LABEL = "com.tacua.compose-processing-role"
BRIDGE_WORKER_ROLE = "exclusive-state-worker"
BRIDGE_VERIFIER_ROLE = "offline-state-verifier"
CREATE_RECEIPT_CONTRACT = "tacua.container-create-result@1.0.0"
CREATE_RECEIPT_NAME = "container-create-result.json"
CREATE_RECEIPT_NEXT_NAME = ".container-create-result.json.next"
MAX_CREATE_RECEIPT_BYTES = 4_096
OPERATION_CONTRACT = "tacua.compose-processing-operation@1.0.0"
OPERATION_DIRECTORY_PREFIX = "tacua-compose-processing-"
JOURNAL_NAME = "operation.json"
JOURNAL_NEXT_NAME = ".operation.json.next"
class ComposeProcessingError(RuntimeError):
    """Stable, content-free Compose bridge failure."""

    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(detail)


class _BridgeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        raise ComposeProcessingError(
            "BRIDGE_INPUT_INVALID",
            "bridge arguments are invalid",
        )


def _load_runner() -> Any:
    specification = importlib.util.spec_from_file_location(
        "tacua_compose_bridge_isolated_runner",
        RUNNER_PATH,
    )
    if specification is None or specification.loader is None:
        raise ComposeProcessingError(
            "BRIDGE_RUNNER_UNAVAILABLE",
            "isolated runner cannot be loaded",
        )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RUNNER = _load_runner()


def _parse_json(payload: bytes, label: str) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def reject_float(_value: str) -> None:
        raise ValueError

    try:
        return json.loads(
            payload,
            object_pairs_hook=reject_duplicate,
            parse_float=reject_float,
            parse_constant=reject_float,
        )
    except (UnicodeDecodeError, ValueError, RecursionError, json.JSONDecodeError) as error:
        raise ComposeProcessingError(
            "BRIDGE_INPUT_INVALID",
            f"{label} is not strict JSON",
        ) from error


def _read_bounded_file(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ComposeProcessingError(
            "BRIDGE_INPUT_INVALID",
            f"{label} cannot be opened safely",
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            raise ComposeProcessingError(
                "BRIDGE_INPUT_INVALID",
                f"{label} violates its file bound",
            )
        result = bytearray()
        while len(result) <= maximum:
            block = os.read(descriptor, min(65_536, maximum + 1 - len(result)))
            if not block:
                break
            result.extend(block)
        final = os.fstat(descriptor)
        if (
            len(result) != metadata.st_size
            or final.st_size != metadata.st_size
            or final.st_mtime_ns != metadata.st_mtime_ns
            or final.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise ComposeProcessingError(
                "BRIDGE_INPUT_INVALID",
                f"{label} changed while it was read",
            )
        return bytes(result)
    finally:
        os.close(descriptor)


def _write_private_snapshot(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("private snapshot write stopped early")
            written += count
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _docker(
    argv: Sequence[str],
    *,
    timeout: int | None = DOCKER_COMMAND_TIMEOUT_SECONDS,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    }
    for name in (
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "XDG_RUNTIME_DIR",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    try:
        result = subprocess.run(
            ["docker", *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ComposeProcessingError(
            "BRIDGE_DOCKER_FAILED",
            "Docker command could not complete",
        ) from error
    if (
        len(result.stdout) > MAX_DOCKER_OUTPUT_BYTES
        or len(result.stderr) > MAX_DOCKER_OUTPUT_BYTES
    ):
        raise ComposeProcessingError(
            "BRIDGE_DOCKER_FAILED",
            "Docker command output exceeded its bound",
        )
    if check and result.returncode != 0:
        raise ComposeProcessingError(
            "BRIDGE_DOCKER_FAILED",
            "Docker command exited unsuccessfully",
        )
    return result


def _create_receipt_digest(document: Mapping[str, Any]) -> str:
    subject = dict(document)
    subject.pop("receipt_digest", None)
    return "sha256:" + hashlib.sha256(canonical_json(subject)).hexdigest()


def _write_create_receipt(
    operation: Path,
    document: Mapping[str, Any],
) -> None:
    sealed = dict(document)
    sealed["receipt_digest"] = _create_receipt_digest(sealed)
    payload = canonical_json(sealed)
    if len(payload) > MAX_CREATE_RECEIPT_BYTES:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "container-create receipt exceeds its byte bound",
        )
    temporary = operation / CREATE_RECEIPT_NEXT_NAME
    destination = operation / CREATE_RECEIPT_NAME
    if (
        temporary.exists()
        or temporary.is_symlink()
        or destination.exists()
        or destination.is_symlink()
    ):
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "container-create receipt path already exists",
        )
    _write_private_snapshot(temporary, payload, 0o600)
    os.replace(temporary, destination)
    _fsync_directory(operation)


def _load_create_receipt(
    operation: Path,
    *,
    required: bool,
) -> dict[str, Any] | None:
    temporary = operation / CREATE_RECEIPT_NEXT_NAME
    if temporary.exists() or temporary.is_symlink():
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "container-create receipt publication is incomplete",
        )
    path = operation / CREATE_RECEIPT_NAME
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if required:
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "container-create receipt is missing",
            )
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > MAX_CREATE_RECEIPT_BYTES
    ):
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "container-create receipt identity is invalid",
        )
    try:
        payload = _read_bounded_file(
            path,
            MAX_CREATE_RECEIPT_BYTES,
            "container-create receipt",
        )
        document = _parse_json(payload, "container-create receipt")
    except ComposeProcessingError as error:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "container-create receipt is malformed or unsealed",
        ) from error
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "container_id",
            "contract_version",
            "name",
            "outcome",
            "project",
            "purpose",
            "receipt_digest",
            "role",
        }
        or document.get("contract_version") != CREATE_RECEIPT_CONTRACT
        or document.get("role")
        not in {BRIDGE_VERIFIER_ROLE, BRIDGE_WORKER_ROLE}
        or document.get("purpose")
        not in {"baseline", "post_worker", "recovery", "worker"}
        or (
            document.get("role") == BRIDGE_WORKER_ROLE
            and document.get("purpose") != "worker"
        )
        or (
            document.get("role") == BRIDGE_VERIFIER_ROLE
            and document.get("purpose") == "worker"
        )
        or not isinstance(document.get("project"), str)
        or PROJECT.fullmatch(document["project"]) is None
        or not isinstance(document.get("name"), str)
        or (
            (
                document["role"] == BRIDGE_VERIFIER_ROLE
                and re.fullmatch(
                    r"tacua-state-verifier-[0-9]+-[a-f0-9]{12}",
                    document["name"],
                )
                is None
            )
            or (
                document["role"] == BRIDGE_WORKER_ROLE
                and re.fullmatch(
                    r"tacua-processing-[0-9]+-[a-f0-9]{12}",
                    document["name"],
                )
                is None
            )
        )
        or document.get("outcome")
        not in {"created", "indeterminate", "not_started"}
        or (
            document["outcome"] == "created"
            and (
                not isinstance(document.get("container_id"), str)
                or CONTAINER_ID.fullmatch(document["container_id"]) is None
            )
        )
        or (
            document["outcome"] != "created"
            and document.get("container_id") is not None
        )
        or document.get("receipt_digest")
        != _create_receipt_digest(document)
        or canonical_json(document) != payload
    ):
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "container-create receipt is malformed or unsealed",
        )
    return document


def _clear_create_receipt(operation: Path) -> None:
    receipt = operation / CREATE_RECEIPT_NAME
    temporary = operation / CREATE_RECEIPT_NEXT_NAME
    if temporary.exists() or temporary.is_symlink():
        raise ComposeProcessingError(
            "BRIDGE_CLEANUP_FAILED",
            "container-create receipt publication is incomplete",
        )
    if receipt.exists() or receipt.is_symlink():
        _load_create_receipt(operation, required=True)
        receipt.unlink()
        _fsync_directory(operation)


def _container_create_child(
    *,
    gate_descriptor: int,
    operation: Path,
    argv: Sequence[str],
    project: str,
    role: str,
    purpose: str,
    name: str,
    previous_mask: set[signal.Signals],
) -> NoReturn:
    outcome = "not_started"
    container_id: str | None = None
    try:
        try:
            os.setsid()
        except OSError:
            pass
        for watched in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(watched, signal.SIG_IGN)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        try:
            gate = os.read(gate_descriptor, 1)
        finally:
            os.close(gate_descriptor)
        if gate == b"G":
            outcome = "indeterminate"
            try:
                result = _docker(argv, timeout=None, check=False)
                if result.returncode == 0 and not result.stderr:
                    container_id = _single_identifier(
                        result.stdout,
                        "journaled container create",
                    )
                    outcome = "created"
            except Exception:
                pass
        _write_create_receipt(
            operation,
            {
                "container_id": container_id,
                "contract_version": CREATE_RECEIPT_CONTRACT,
                "name": name,
                "outcome": outcome,
                "project": project,
                "purpose": purpose,
                "role": role,
            },
        )
        os._exit(0)
    except BaseException:
        os._exit(2)


def _prepare_container_create(
    *,
    operation: Path,
    argv: Sequence[str],
    project: str,
    role: str,
    purpose: str,
    name: str,
) -> dict[str, Any]:
    if not hasattr(os, "fork") or not hasattr(signal, "pthread_sigmask"):
        raise ComposeProcessingError(
            "BRIDGE_RUNTIME_UNSUPPORTED",
            "journaled container creation requires Unix fork semantics",
        )
    if (
        (operation / CREATE_RECEIPT_NAME).exists()
        or (operation / CREATE_RECEIPT_NAME).is_symlink()
        or (operation / CREATE_RECEIPT_NEXT_NAME).exists()
        or (operation / CREATE_RECEIPT_NEXT_NAME).is_symlink()
    ):
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_REQUIRED",
            "an earlier container-create receipt requires recovery",
        )
    try:
        read_descriptor, write_descriptor = os.pipe()
    except OSError as error:
        raise ComposeProcessingError(
            "BRIDGE_RUNTIME_UNSUPPORTED",
            "container-create coordinator pipe could not be opened",
        ) from error
    try:
        for descriptor in (read_descriptor, write_descriptor):
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
            fcntl.fcntl(
                descriptor,
                fcntl.F_SETFD,
                flags | fcntl.FD_CLOEXEC,
            )
    except BaseException:
        try:
            os.close(read_descriptor)
        finally:
            os.close(write_descriptor)
        raise
    watched = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, watched)
    except BaseException:
        try:
            os.close(read_descriptor)
        finally:
            os.close(write_descriptor)
        raise
    try:
        process_id = os.fork()
    except BaseException:
        try:
            os.close(read_descriptor)
        finally:
            os.close(write_descriptor)
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise
    if process_id == 0:
        os.close(write_descriptor)
        _container_create_child(
            gate_descriptor=read_descriptor,
            operation=operation,
            argv=tuple(argv),
            project=project,
            role=role,
            purpose=purpose,
            name=name,
            previous_mask=previous_mask,
        )
    try:
        os.close(read_descriptor)
    except BaseException:
        try:
            os.close(write_descriptor)
        finally:
            _wait_create_child({"pid": process_id})
            signal.pthread_sigmask(
                signal.SIG_SETMASK,
                previous_mask,
            )
        raise
    return {
        "gate_descriptor": write_descriptor,
        "name": name,
        "pid": process_id,
        "previous_mask": previous_mask,
        "project": project,
        "purpose": purpose,
        "role": role,
    }


def _wait_create_child(attempt: Mapping[str, Any]) -> None:
    process_id = int(attempt["pid"])
    while True:
        try:
            waited, _status = os.waitpid(process_id, 0)
        except InterruptedError:
            continue
        except ChildProcessError:
            return
        if waited != process_id:
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "container-create coordinator identity changed",
            )
        return


def _finish_container_create(
    operation: Path,
    attempt: Mapping[str, Any],
    *,
    start: bool,
) -> dict[str, Any]:
    gate_descriptor = int(attempt["gate_descriptor"])
    pending: BaseException | None = None
    gate_closed = False
    previous_mask = attempt.get("previous_mask")
    if not isinstance(previous_mask, set):
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "container-create coordinator signal state is invalid",
        )
    receipt: dict[str, Any] | None = None
    try:
        try:
            if start:
                if os.write(gate_descriptor, b"G") != 1:
                    raise OSError(
                        "container-create gate write stopped early"
                    )
            os.close(gate_descriptor)
            gate_closed = True
            _wait_create_child(attempt)
        except BaseException as error:
            pending = error
            if not gate_closed:
                try:
                    os.close(gate_descriptor)
                except OSError:
                    pass
                gate_closed = True
            try:
                _wait_create_child(attempt)
            except BaseException as wait_error:
                if pending is None:
                    pending = wait_error
        if pending is None:
            receipt = _load_create_receipt(operation, required=True)
            assert receipt is not None
            if any(
                receipt[key] != attempt[key]
                for key in ("name", "project", "purpose", "role")
            ):
                raise ComposeProcessingError(
                    "BRIDGE_RECOVERY_UNSAFE",
                    "container-create receipt differs from its attempt",
                )
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    if pending is not None:
        raise pending
    assert receipt is not None
    return receipt


def _host_bundle_paths() -> tuple[str, ...]:
    try:
        paths = _bootstrap_source_paths(ROOT)
    except _SourceBootstrapError as error:
        raise ComposeProcessingError(
            "BRIDGE_PROVENANCE_INVALID",
            "host bridge source inventory is invalid",
        ) from error
    return paths


def _bundle_digest(root: Path, paths: Sequence[str]) -> str:
    manifest: dict[str, str] = {}
    for relative in paths:
        payload = _read_bounded_file(
            root / relative,
            2_097_152,
            "host bridge source",
        )
        manifest[relative] = "sha256:" + hashlib.sha256(payload).hexdigest()
    return "sha256:" + hashlib.sha256(canonical_json(manifest)).hexdigest()


def _verify_host_bundle_matches_image(image_id: str) -> str:
    paths = _host_bundle_paths()
    host_digest = _bundle_digest(ROOT, paths)
    if _VERIFIED_SOURCE_CONTEXT is not None:
        manifest = _VERIFIED_SOURCE_CONTEXT["manifest"]
        if (
            manifest is None
            or manifest["source_digest"] != host_digest
            or set(manifest["files"]) != set(paths)
        ):
            raise ComposeProcessingError(
                "BRIDGE_PROVENANCE_MISMATCH",
                "executed source differs from its verified snapshot",
            )
    families = [
        (directory, pattern.pattern)
        for directory, pattern in _SOURCE_FAMILIES
    ]
    program = (
        "import hashlib,json,pathlib,re,stat;"
        f"exact={_bootstrap_canonical_json(list(_SOURCE_EXACT_PATHS)).decode()};"
        f"families={_bootstrap_canonical_json(families).decode()};"
        "root=pathlib.Path('/app');paths=list(exact);"
        "script_dir=(root/exact[0]).parent;"
        "script_entries=sorted(script_dir.iterdir());"
        "assert {str(p.relative_to(root)) for p in script_entries}==set(exact);"
        "\nfor directory,pattern in families:\n"
        " entries=sorted((root/directory).iterdir());"
        " assert entries;"
        " assert all(re.fullmatch(pattern,p.name) for p in entries);"
        " paths.extend(str(p.relative_to(root)) for p in entries)\n"
        "paths=sorted(paths);"
        f"assert len(paths)<={_SOURCE_MAX_FILES};"
        "manifest={};total=0;"
        "\nfor relative in paths:\n"
        " p=root/relative;m=p.lstat();"
        " assert stat.S_ISREG(m.st_mode) and m.st_nlink==1;"
        " data=p.read_bytes();"
        f" assert 0<len(data)<={_SOURCE_MAX_FILE_BYTES};"
        " total+=len(data);"
        " manifest[relative]='sha256:'+hashlib.sha256(data).hexdigest()\n"
        f"assert total<={_SOURCE_MAX_BYTES};"
        "payload=json.dumps(manifest,ensure_ascii=False,separators=(',',':'),"
        "sort_keys=True).encode();"
        "print(json.dumps({'digest':'sha256:'+hashlib.sha256(payload).hexdigest(),"
        "'paths':paths},ensure_ascii=False,separators=(',',':'),sort_keys=True))"
    )
    result = _docker(
        [
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--entrypoint",
            "/usr/local/bin/python",
            image_id,
            "-I",
            "-S",
            "-B",
            "-c",
            program,
        ],
        timeout=30,
        check=False,
    )
    try:
        image_result = _parse_json(
            result.stdout,
            "backend image bridge provenance",
        )
    except ComposeProcessingError as error:
        raise ComposeProcessingError(
            "BRIDGE_PROVENANCE_INVALID",
            "backend image bridge provenance is invalid",
        ) from error
    if (
        result.returncode != 0
        or not isinstance(image_result, dict)
        or set(image_result) != {"digest", "paths"}
        or image_result.get("paths") != list(paths)
        or image_result.get("digest") != host_digest
        or result.stderr
    ):
        raise ComposeProcessingError(
            "BRIDGE_PROVENANCE_MISMATCH",
            "host bridge source differs from the selected backend image",
        )
    return host_digest


def _compose_prefix(project: str, compose_json: Path) -> list[str]:
    return [
        "compose",
        "-p",
        project,
        "-f",
        str(compose_json),
    ]


def _single_identifier(payload: bytes, label: str) -> str:
    try:
        lines = [
            line.strip()
            for line in payload.decode("ascii", errors="strict").splitlines()
            if line.strip()
        ]
    except UnicodeError as error:
        raise ComposeProcessingError(
            "BRIDGE_DEPLOYMENT_CHANGED",
            f"{label} container identity is invalid",
        ) from error
    if len(lines) != 1 or CONTAINER_ID.fullmatch(lines[0]) is None:
        raise ComposeProcessingError(
            "BRIDGE_DEPLOYMENT_CHANGED",
            f"expected one exact {label} container",
        )
    return lines[0]


def _inspect_container(container_id: str) -> dict[str, Any]:
    document = _parse_json(
        _docker(["container", "inspect", container_id]).stdout,
        "container inspection",
    )
    if (
        not isinstance(document, list)
        or len(document) != 1
        or not isinstance(document[0], dict)
    ):
        raise ComposeProcessingError(
            "BRIDGE_DEPLOYMENT_CHANGED",
            "container inspection shape differs",
        )
    return document[0]


def _inspect_backend(
    *,
    container_id: str,
    project: str,
    state_volume: str,
    expected_status: str,
    expected_image_id: str | None = None,
    expected_config_image: str | None = None,
    require_healthy: bool = False,
) -> str:
    inspected = _inspect_container(container_id)
    config = inspected.get("Config")
    state = inspected.get("State")
    mounts = inspected.get("Mounts")
    labels = config.get("Labels") if isinstance(config, dict) else None
    image_id = inspected.get("Image")
    state_mounts = [
        mount
        for mount in mounts
        if isinstance(mount, dict)
        and mount.get("Destination") == STATE_IN_CONTAINER
    ] if isinstance(mounts, list) else []
    if (
        inspected.get("Id") != container_id
        or not isinstance(config, dict)
        or (
            expected_config_image is not None
            and config.get("Image") != expected_config_image
        )
        or not isinstance(state, dict)
        or state.get("Status") != expected_status
        or (
            require_healthy
            and (
                not isinstance(state.get("Health"), dict)
                or state["Health"].get("Status") != "healthy"
            )
        )
        or not isinstance(labels, dict)
        or labels.get("com.docker.compose.project") != project
        or labels.get("com.docker.compose.service") != "backend"
        or labels.get("com.docker.compose.oneoff") != "False"
        or not isinstance(image_id, str)
        or IMAGE_ID.fullmatch(image_id) is None
        or (expected_image_id is not None and image_id != expected_image_id)
        or len(state_mounts) != 1
        or state_mounts[0].get("Type") != "volume"
        or state_mounts[0].get("Name") != state_volume
        or any(
            isinstance(mount, dict)
            and mount.get("Destination") in {
                "/var/run/docker.sock",
                "/run/docker.sock",
            }
            for mount in mounts
        )
    ):
        raise ComposeProcessingError(
            "BRIDGE_DEPLOYMENT_CHANGED",
            "backend identity, state, image, or state-volume binding differs",
        )
    return image_id


def _volume_consumers(state_volume: str) -> set[str]:
    payload = _docker(
        [
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            f"volume={state_volume}",
        ]
    ).stdout
    try:
        lines = {
            line.strip()
            for line in payload.decode("ascii", errors="strict").splitlines()
            if line.strip()
        }
    except UnicodeError as error:
        raise ComposeProcessingError(
            "BRIDGE_DEPLOYMENT_CHANGED",
            "state-volume consumer list is invalid",
        ) from error
    if any(CONTAINER_ID.fullmatch(item) is None for item in lines):
        raise ComposeProcessingError(
            "BRIDGE_DEPLOYMENT_CHANGED",
            "state-volume consumer identity is invalid",
        )
    return lines


def _preflight_state_verifier_capacity(container_id: str) -> None:
    result = _docker(
        [
            "container",
            "exec",
            container_id,
            "/usr/local/bin/python",
            "-B",
            "-m",
            "tacua_backend.operator_tool",
            "check-compose-state-copy-bound",
            "--state-directory",
            STATE_IN_CONTAINER,
        ],
        timeout=30,
        check=False,
    )
    expected = canonical_json(
        {
            "maximum_bytes": MAX_COMPOSE_STATE_DATABASE_COPY_BYTES,
            "status": "ok",
        }
    ) + b"\n"
    if result.returncode != 0 or result.stdout != expected or result.stderr:
        raise ComposeProcessingError(
            "BRIDGE_STATE_CAPACITY_EXCEEDED",
            "state exceeds the offline verifier capacity profile",
        )


def _bridge_role_containers(project: str, role: str) -> tuple[str, ...]:
    if role not in {BRIDGE_VERIFIER_ROLE, BRIDGE_WORKER_ROLE}:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "recovery container role is invalid",
        )
    payload = _docker(
        [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"label={BRIDGE_LABEL}=true",
            "--filter",
            f"label={BRIDGE_PROJECT_LABEL}={project}",
            "--filter",
            f"label={BRIDGE_ROLE_LABEL}={role}",
        ],
        timeout=15,
    ).stdout
    try:
        identifiers = tuple(
            line.strip()
            for line in payload.decode("ascii", errors="strict").splitlines()
            if line.strip()
        )
    except UnicodeError as error:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "recovery worker identity list is invalid",
        ) from error
    if (
        len(identifiers) > 1
        or any(CONTAINER_ID.fullmatch(item) is None for item in identifiers)
    ):
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "recovery found an ambiguous one-shot worker set",
        )
    return identifiers


def _bridge_worker_containers(project: str) -> tuple[str, ...]:
    return _bridge_role_containers(project, BRIDGE_WORKER_ROLE)


def _bridge_verifier_containers(project: str) -> tuple[str, ...]:
    return _bridge_role_containers(project, BRIDGE_VERIFIER_ROLE)


def _bridge_reference_containers(
    reference_filter: str,
    label: str,
) -> tuple[str, ...]:
    payload = _docker(
        [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            reference_filter,
        ],
        timeout=15,
    ).stdout
    try:
        identifiers = tuple(
            line.strip()
            for line in payload.decode("ascii", errors="strict").splitlines()
            if line.strip()
        )
    except UnicodeError as error:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            f"recovery {label} identity list is invalid",
        ) from error
    if (
        len(identifiers) > 1
        or any(CONTAINER_ID.fullmatch(item) is None for item in identifiers)
    ):
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            f"recovery {label} identity is ambiguous",
        )
    return identifiers


def _recovery_container_candidates(
    *,
    project: str,
    role: str,
    recorded_name: str | None,
    recorded_id: str | None,
) -> tuple[str, ...]:
    try:
        if role == BRIDGE_WORKER_ROLE:
            identifiers = set(_bridge_worker_containers(project))
        elif role == BRIDGE_VERIFIER_ROLE:
            identifiers = set(_bridge_verifier_containers(project))
        else:
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "recovery container role is invalid",
            )
        if recorded_name is not None:
            identifiers.update(
                _bridge_reference_containers(
                    f"name={recorded_name}",
                    "container name",
                )
            )
        if recorded_id is not None:
            identifiers.update(
                _bridge_reference_containers(
                    f"id={recorded_id}",
                    "container ID",
                )
            )
    except ComposeProcessingError as error:
        if error.code == "BRIDGE_RECOVERY_UNSAFE":
            raise
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "recovery container discovery did not complete",
        ) from error
    if len(identifiers) > 1:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "recovery container identity sources disagree",
        )
    return tuple(identifiers)


def _recovery_container_candidate(
    *,
    project: str,
    role: str,
    recorded_name: str | None,
    recorded_id: str | None,
) -> str | None:
    identifiers = _recovery_container_candidates(
        project=project,
        role=role,
        recorded_name=recorded_name,
        recorded_id=recorded_id,
    )
    return identifiers[0] if identifiers else None


def _resolve_deployment(
    compose: dict[str, Any],
    *,
    project: str,
) -> tuple[str, str]:
    volumes = compose.get("volumes")
    state_definition = (
        volumes.get("tacua-state") if isinstance(volumes, dict) else None
    )
    services = compose.get("services")
    backend = services.get("backend") if isinstance(services, dict) else None
    state_volume = (
        state_definition.get("name")
        if isinstance(state_definition, dict)
        else None
    )
    image = backend.get("image") if isinstance(backend, dict) else None
    if (
        compose.get("name") != project
        or not isinstance(state_volume, str)
        or VOLUME_NAME.fullmatch(state_volume) is None
        or not isinstance(image, str)
        or not image
    ):
        raise ComposeProcessingError(
            "BRIDGE_COMPOSE_INVALID",
            "Compose project, image, or state volume is invalid",
        )
    return state_volume, image


def _acquire_host_lock(project: str) -> int:
    path = Path(f"/tmp/tacua-compose-processing-{project}.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        path_metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise OSError("lock identity differs")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError as error:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise ComposeProcessingError(
            "BRIDGE_BUSY",
            "another Compose processing bridge owns this project",
        ) from error
    except OSError as error:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise ComposeProcessingError(
            "BRIDGE_LOCK_INVALID",
            "Compose processing lock is unsafe",
        ) from error


def _release_host_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _operation_path(parent: Path, project: str) -> Path:
    if not parent.is_absolute() or PROJECT.fullmatch(project) is None:
        raise ComposeProcessingError(
            "BRIDGE_OPERATION_DIRECTORY_INVALID",
            "operation parent and project must be exact",
        )
    try:
        metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError as error:
        raise ComposeProcessingError(
            "BRIDGE_OPERATION_DIRECTORY_INVALID",
            "operation parent is unavailable",
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved != parent
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ComposeProcessingError(
            "BRIDGE_OPERATION_DIRECTORY_INVALID",
            "operation parent must be an owner-only real directory",
        )
    operation = parent / f"{OPERATION_DIRECTORY_PREFIX}{project}"
    socket_path = operation / "processing-bridge.sock"
    if (
        any(
            character in str(operation)
            for character in {",", "\n", "\r", "\x00"}
        )
        or len(os.fsencode(socket_path)) > MAX_UNIX_SOCKET_PATH_BYTES
    ):
        raise ComposeProcessingError(
            "BRIDGE_OPERATION_DIRECTORY_INVALID",
            "operation path is unsafe for one exact Unix socket mount",
        )
    return operation


def _create_operation_directory(parent: Path, project: str) -> Path:
    operation = _operation_path(parent, project)
    try:
        operation.mkdir(mode=0o700)
        _fsync_directory(parent)
    except FileExistsError as error:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_REQUIRED",
            "an unfinished Compose processing operation requires recovery",
        ) from error
    except OSError as error:
        raise ComposeProcessingError(
            "BRIDGE_OPERATION_DIRECTORY_INVALID",
            "operation directory could not be created durably",
        ) from error
    metadata = operation.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ComposeProcessingError(
            "BRIDGE_OPERATION_DIRECTORY_INVALID",
            "created operation directory is unsafe",
        )
    return operation


def _journal_digest(document: Mapping[str, Any]) -> str:
    subject = dict(document)
    subject.pop("journal_digest", None)
    return "sha256:" + hashlib.sha256(canonical_json(subject)).hexdigest()


def _write_operation_journal(
    operation: Path,
    document: Mapping[str, Any],
) -> dict[str, Any]:
    sealed = dict(document)
    sealed["journal_digest"] = _journal_digest(sealed)
    payload = canonical_json(sealed)
    if len(payload) > MAX_JOURNAL_BYTES:
        raise ComposeProcessingError(
            "BRIDGE_JOURNAL_INVALID",
            "operation journal exceeds its byte bound",
        )
    temporary = operation / JOURNAL_NEXT_NAME
    destination = operation / JOURNAL_NAME
    if temporary.exists() or temporary.is_symlink():
        raise ComposeProcessingError(
            "BRIDGE_JOURNAL_INVALID",
            "operation journal staging path already exists",
        )
    _write_private_snapshot(temporary, payload, 0o600)
    os.replace(temporary, destination)
    _fsync_directory(operation)
    return sealed


def _validate_identity_document(identity: Any) -> bool:
    return (
        isinstance(identity, dict)
        and set(identity)
        == {
            "changed_ns",
            "device",
            "inode",
            "mode",
            "modified_ns",
            "path",
            "size",
        }
        and all(
            isinstance(identity[name], str)
            and re.fullmatch(r"0|[1-9][0-9]{0,31}", identity[name])
            is not None
            for name in (
                "changed_ns",
                "device",
                "inode",
                "mode",
                "modified_ns",
                "size",
            )
        )
        and isinstance(identity["path"], str)
        and Path(identity["path"]).is_absolute()
    )


def _journal_phase_is_coherent(document: Mapping[str, Any]) -> bool:
    phase = document["phase"]
    baseline_verified = document["baseline_state_verified"]
    worker_started = document["worker_started"]
    state_verified_after_worker = document[
        "state_verified_after_worker"
    ]
    verifier_id = document["verifier_container_id"]
    verifier_name = document["verifier_name"]
    worker_id = document["worker_container_id"]
    worker_name = document["worker_name"]

    verifier_purpose = (
        phase.removesuffix("_verifier_creating")
        if phase.endswith("_verifier_creating")
        else phase.removesuffix("_verifier_created")
        if phase.endswith("_verifier_created")
        else None
    )
    if verifier_purpose is None:
        if verifier_id is not None or verifier_name is not None:
            return False
    elif phase.endswith("_verifier_creating"):
        if verifier_name is None or verifier_id is not None:
            return False
    elif verifier_name is None or verifier_id is None:
        return False

    if phase == "worker_creating":
        if worker_name is None or worker_id is not None or worker_started:
            return False
    elif phase == "worker_created":
        if worker_name is None or worker_id is None or worker_started:
            return False
    elif phase == "worker_starting":
        if worker_name is None or worker_id is None or not worker_started:
            return False
    elif phase == "worker_exited":
        if (worker_name is None) != (worker_id is None):
            return False
    elif worker_name is not None or worker_id is not None:
        return False

    if state_verified_after_worker and not worker_started:
        return False
    if worker_started and not baseline_verified:
        return False
    if phase in {
        "prepared",
        "backend_stopped",
        "baseline_verifier_creating",
        "baseline_verifier_created",
    } and (
        baseline_verified
        or worker_started
        or state_verified_after_worker
    ):
        return False
    if phase in {
        "baseline_verified",
        "worker_creating",
        "worker_created",
        "worker_starting",
        "worker_exited",
        "post_worker_verifier_creating",
        "post_worker_verifier_created",
        "state_verified",
        "backend_healthy",
    } and not baseline_verified:
        return False
    if (
        phase in {
            "baseline_verified",
            "worker_creating",
            "worker_created",
        }
        and worker_started
    ):
        return False
    if phase == "worker_starting" and not worker_started:
        return False
    if phase in {
        "post_worker_verifier_creating",
        "post_worker_verifier_created",
    } and (
        not worker_started or state_verified_after_worker
    ):
        return False
    if (
        phase in {"state_verified", "backend_healthy"}
        and worker_started
        and not state_verified_after_worker
    ):
        return False
    return True


def _load_operation_journal(operation: Path) -> dict[str, Any]:
    path = operation / JOURNAL_NAME
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise OSError("operation journal identity differs")
        payload = _read_bounded_file(
            path,
            MAX_JOURNAL_BYTES,
            "operation journal",
        )
        document = _parse_json(payload, "operation journal")
    except (ComposeProcessingError, OSError) as error:
        raise ComposeProcessingError(
            "BRIDGE_JOURNAL_INVALID",
            "operation journal cannot be read safely",
        ) from error
    expected_keys = {
        "adapter_contract",
        "backend_container_id",
        "baseline_state_verified",
        "compose_digest",
        "config_identity",
        "configured_image",
        "contract_version",
        "host_bundle_digest",
        "image_id",
        "isolated_command_digest",
        "journal_digest",
        "max_stages",
        "original_repository_root",
        "phase",
        "project",
        "run_once",
        "secret_identity",
        "state_verified_after_worker",
        "state_volume",
        "verifier_container_id",
        "verifier_name",
        "worker_container_id",
        "worker_id",
        "worker_name",
        "worker_started",
    }
    if (
        not isinstance(document, dict)
        or set(document) != expected_keys
        or document.get("contract_version") != OPERATION_CONTRACT
        or document.get("journal_digest") != _journal_digest(document)
        or not isinstance(document.get("project"), str)
        or PROJECT.fullmatch(document["project"]) is None
        or not isinstance(document.get("backend_container_id"), str)
        or CONTAINER_ID.fullmatch(document["backend_container_id"])
        is None
        or not isinstance(document.get("image_id"), str)
        or IMAGE_ID.fullmatch(document["image_id"]) is None
        or not isinstance(document.get("host_bundle_digest"), str)
        or IMAGE_ID.fullmatch(document["host_bundle_digest"]) is None
        or not isinstance(document.get("isolated_command_digest"), str)
        or IMAGE_ID.fullmatch(document["isolated_command_digest"]) is None
        or not isinstance(document.get("compose_digest"), str)
        or IMAGE_ID.fullmatch(document["compose_digest"]) is None
        or not isinstance(document.get("configured_image"), str)
        or not document["configured_image"]
        or not isinstance(document.get("state_volume"), str)
        or VOLUME_NAME.fullmatch(document["state_volume"]) is None
        or document.get("adapter_contract") not in ADAPTER_CONTRACTS
        or not isinstance(document.get("worker_id"), str)
        or ID.fullmatch(document["worker_id"]) is None
        or type(document.get("max_stages")) is not int
        or not 1 <= document["max_stages"] <= MAX_DRAIN_STAGES
        or type(document.get("run_once")) is not bool
        or not isinstance(document.get("original_repository_root"), str)
        or not Path(document["original_repository_root"]).is_absolute()
        or not isinstance(document.get("phase"), str)
        or document["phase"]
        not in {
            "prepared",
            "backend_stopped",
            "baseline_verifier_creating",
            "baseline_verifier_created",
            "baseline_verified",
            "worker_creating",
            "worker_created",
            "worker_starting",
            "worker_exited",
            "post_worker_verifier_creating",
            "post_worker_verifier_created",
            "recovery_verifier_creating",
            "recovery_verifier_created",
            "state_verified",
            "backend_healthy",
        }
        or type(document.get("baseline_state_verified")) is not bool
        or type(document.get("worker_started")) is not bool
        or type(document.get("state_verified_after_worker")) is not bool
        or (
            document.get("verifier_container_id") is not None
            and (
                not isinstance(document["verifier_container_id"], str)
                or CONTAINER_ID.fullmatch(document["verifier_container_id"])
                is None
            )
        )
        or (
            document.get("verifier_name") is not None
            and (
                not isinstance(document["verifier_name"], str)
                or re.fullmatch(
                    r"tacua-state-verifier-[0-9]+-[a-f0-9]{12}",
                    document["verifier_name"],
                )
                is None
            )
        )
        or (
            document.get("worker_container_id") is not None
            and (
                not isinstance(document["worker_container_id"], str)
                or CONTAINER_ID.fullmatch(document["worker_container_id"]) is None
            )
        )
        or (
            document.get("worker_name") is not None
            and (
                not isinstance(document["worker_name"], str)
                or re.fullmatch(
                    r"tacua-processing-[0-9]+-[a-f0-9]{12}",
                    document["worker_name"],
                )
                is None
            )
        )
        or not _validate_identity_document(document.get("config_identity"))
        or not _validate_identity_document(document.get("secret_identity"))
        or not _journal_phase_is_coherent(document)
        or canonical_json(document) != payload
    ):
        raise ComposeProcessingError(
            "BRIDGE_JOURNAL_INVALID",
            "operation journal is malformed or unsealed",
        )
    return document


def _advance_operation_journal(
    operation: Path,
    document: Mapping[str, Any],
    phase: str,
    **changes: Any,
) -> dict[str, Any]:
    updated = {
        key: value
        for key, value in document.items()
        if key != "journal_digest"
    }
    updated.update(changes)
    updated["phase"] = phase
    return _write_operation_journal(operation, updated)


def _discard_incomplete_journal_update(operation: Path) -> None:
    temporary = operation / JOURNAL_NEXT_NAME
    try:
        metadata = temporary.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > MAX_JOURNAL_BYTES
    ):
        raise ComposeProcessingError(
            "BRIDGE_JOURNAL_INVALID",
            "incomplete operation journal update is unsafe",
        )
    temporary.unlink()
    _fsync_directory(operation)


def _source_cleanup_path_allowed(relative: str) -> bool:
    return _bootstrap_source_path_allowed(relative)


def _remove_source_tree(path: Path) -> None:
    try:
        root_metadata = path.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise ComposeProcessingError(
            "BRIDGE_CLEANUP_FAILED",
            "verified source root is unsafe to remove",
        )
    directories: list[Path] = []
    files: list[Path] = []
    for current, names, filenames in os.walk(path, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.append(current_path)
        for name in names:
            child = current_path / name
            metadata = child.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ComposeProcessingError(
                    "BRIDGE_CLEANUP_FAILED",
                    "verified source directory is unsafe to remove",
                )
        for name in filenames:
            child = current_path / name
            relative = str(child.relative_to(path)).replace(os.sep, "/")
            metadata = child.lstat()
            if (
                not _source_cleanup_path_allowed(relative)
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o400
            ):
                raise ComposeProcessingError(
                    "BRIDGE_CLEANUP_FAILED",
                    "verified source file is unsafe to remove",
                )
            files.append(child)
    for source in files:
        source.unlink()
    for directory in sorted(
        directories,
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        directory.rmdir()


def _remove_operation_directory(operation: Path) -> None:
    allowed = {
        _SOURCE_DIRECTORY_NAME,
        _SOURCE_MANIFEST_NAME,
        _SOURCE_MANIFEST_STAGING_NAME,
        _SOURCE_STAGING_NAME,
        CREATE_RECEIPT_NAME,
        CREATE_RECEIPT_NEXT_NAME,
        JOURNAL_NAME,
        JOURNAL_NEXT_NAME,
        "isolated-command.json",
        "processing-bridge.sock",
        "processing-command.json",
        "resolved-compose.json",
    }
    entries = {entry.name for entry in operation.iterdir()}
    if not entries.issubset(allowed):
        raise ComposeProcessingError(
            "BRIDGE_CLEANUP_FAILED",
            "operation directory contains an unexpected entry",
        )
    if JOURNAL_NAME in entries:
        (operation / JOURNAL_NAME).unlink()
        _fsync_directory(operation)
        entries.remove(JOURNAL_NAME)
    for name in (_SOURCE_STAGING_NAME, _SOURCE_DIRECTORY_NAME):
        if name in entries:
            _remove_source_tree(operation / name)
            entries.remove(name)
    for name in sorted(entries):
        (operation / name).unlink(missing_ok=True)
    _fsync_directory(operation)
    parent = operation.parent
    operation.rmdir()
    _fsync_directory(parent)


def _safe_mount_source(path: Path, label: str) -> str:
    resolved = path.resolve(strict=True)
    if any(character in str(resolved) for character in {",", "\n", "\r", "\x00"}):
        raise ComposeProcessingError(
            "BRIDGE_INPUT_INVALID",
            f"{label} path is not safe for one exact Docker mount",
        )
    return str(resolved)


def _regular_mount_identity(path: Path, label: str) -> dict[str, Any]:
    resolved = Path(_safe_mount_source(path, label))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os,
        "O_NOFOLLOW",
        0,
    )
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise ComposeProcessingError(
            "BRIDGE_INPUT_INVALID",
            f"{label} cannot be opened for identity binding",
        ) from error
    try:
        metadata = os.fstat(descriptor)
        path_metadata = resolved.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise ComposeProcessingError(
                "BRIDGE_INPUT_INVALID",
                f"{label} identity is unsafe",
            )
        return {
            "changed_ns": str(metadata.st_ctime_ns),
            "device": str(metadata.st_dev),
            "inode": str(metadata.st_ino),
            "mode": str(stat.S_IMODE(metadata.st_mode)),
            "modified_ns": str(metadata.st_mtime_ns),
            "path": str(resolved),
            "size": str(metadata.st_size),
        }
    finally:
        os.close(descriptor)


def _require_mount_identity(
    path: Path,
    label: str,
    expected: Mapping[str, Any],
) -> None:
    if _regular_mount_identity(path, label) != dict(expected):
        raise ComposeProcessingError(
            "BRIDGE_DEPLOYMENT_CHANGED",
            f"{label} changed after bridge preflight",
        )


def _require_snapshot_digest(
    path: Path,
    maximum: int,
    label: str,
    expected_digest: str,
) -> None:
    payload = _read_bounded_file(path, maximum, label)
    actual = "sha256:" + hashlib.sha256(payload).hexdigest()
    if actual != expected_digest:
        raise ComposeProcessingError(
            "BRIDGE_DEPLOYMENT_CHANGED",
            f"{label} changed after bridge preflight",
        )


def _write_outer_command(path: Path, contract_version: str) -> None:
    if contract_version not in ADAPTER_CONTRACTS:
        raise ComposeProcessingError(
            "BRIDGE_INPUT_INVALID",
            "adapter contract is unsupported",
        )
    document = {
        "argv": [
            "/usr/local/bin/python",
            "-B",
            "-m",
            BRIDGE_CLIENT_MODULE,
            "--socket",
            BRIDGE_SOCKET_IN_CONTAINER,
            "--input",
            "{input}",
            "--output-directory",
            "{output_directory}",
        ],
        "contract_version": contract_version,
        "max_stderr_bytes": 65_536,
        "max_stdout_bytes": MAX_RESULT_BYTES,
        "timeout_seconds": 240,
    }
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o444,
    )
    try:
        payload = canonical_json(document)
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
    finally:
        os.close(descriptor)


def _move_socket_high(stream: socket.socket) -> socket.socket:
    old = stream.detach()
    try:
        new = fcntl.fcntl(
            old,
            getattr(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD),
            BROKER_HIGH_FD,
        )
    finally:
        os.close(old)
    return socket.socket(fileno=new)


def _prepare_broker_descriptor_limit() -> None:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = (
        BROKER_NOFILE_LIMIT
        if hard == resource.RLIM_INFINITY
        else min(hard, BROKER_NOFILE_LIMIT)
    )
    if target <= BROKER_HIGH_FD + 514:
        raise ComposeProcessingError(
            "BRIDGE_DESCRIPTOR_LIMIT",
            "host descriptor limit cannot carry one bounded adapter request",
        )
    if soft < target:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        except (OSError, ValueError) as error:
            raise ComposeProcessingError(
                "BRIDGE_DESCRIPTOR_LIMIT",
                "host descriptor limit could not be raised safely",
            ) from error


def _move_descriptors_high(descriptors: Sequence[int]) -> tuple[int, ...]:
    moved: list[int] = []
    try:
        for descriptor in descriptors:
            moved_descriptor = fcntl.fcntl(
                descriptor,
                getattr(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD),
                BROKER_HIGH_FD,
            )
            moved.append(moved_descriptor)
            os.close(descriptor)
        return tuple(moved)
    except Exception:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for descriptor in moved:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _validate_request(
    request: dict[str, Any],
) -> tuple[int, ...]:
    if set(request) != {"contract_version", "descriptor_targets"}:
        raise ComposeProcessingError(
            "BRIDGE_PROTOCOL_INVALID",
            "bridge request shape differs",
        )
    targets = request["descriptor_targets"]
    if (
        request["contract_version"] != REQUEST_CONTRACT
        or not isinstance(targets, list)
        or not 1 <= len(targets) <= 513
        or any(
            type(target) is not int
            or not 3 <= target <= MAX_ADAPTER_DESCRIPTOR
            for target in targets
        )
        or len(set(targets)) != len(targets)
    ):
        raise ComposeProcessingError(
            "BRIDGE_PROTOCOL_INVALID",
            "bridge descriptor targets are invalid",
        )
    return tuple(targets)


def _map_capabilities(
    sources: Sequence[int],
    targets: Sequence[int],
) -> None:
    if len(sources) != len(targets):
        raise ComposeProcessingError(
            "BRIDGE_PROTOCOL_INVALID",
            "bridge capability count differs",
        )
    for target in targets:
        try:
            fcntl.fcntl(target, fcntl.F_GETFD)
        except OSError:
            continue
        raise ComposeProcessingError(
            "BRIDGE_DESCRIPTOR_COLLISION",
            "broker descriptor target was already open",
        )
    for source, target in zip(sources, targets, strict=True):
        metadata = os.fstat(source)
        status = fcntl.fcntl(source, fcntl.F_GETFL)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or status & os.O_ACCMODE != os.O_RDONLY
            or status & getattr(os, "O_PATH", 0)
        ):
            raise ComposeProcessingError(
                "BRIDGE_DESCRIPTOR_INVALID",
                "received bridge capability is not one read-only regular file",
            )
        os.dup2(source, target, inheritable=False)


def _close_targets(targets: Sequence[int]) -> None:
    for target in targets:
        try:
            os.close(target)
        except OSError:
            pass


def _output_descriptors(
    result: bytes,
    output_directory: Path,
) -> list[dict[str, Any]]:
    if not 1 <= len(result) <= MAX_RESULT_BYTES:
        raise ComposeProcessingError(
            "BRIDGE_RESPONSE_INVALID",
            "isolated result violates the bridge bound",
        )
    entries = sorted(output_directory.iterdir(), key=lambda entry: entry.name)
    if len(entries) > MAX_PREVIEW_FILES:
        raise ComposeProcessingError(
            "BRIDGE_RESPONSE_INVALID",
            "isolated preview count violates the bridge bound",
        )
    total = len(result)
    descriptors: list[dict[str, Any]] = []
    for entry in entries:
        metadata = entry.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
            or SAFE_OUTPUT_NAME.fullmatch(entry.name) is None
            or entry.name == "result.json"
            or not 1 <= metadata.st_size <= MAX_PREVIEW_BYTES
        ):
            raise ComposeProcessingError(
                "BRIDGE_RESPONSE_INVALID",
                "isolated preview metadata is unsafe",
            )
        total += metadata.st_size
        if total > MAX_OUTPUT_BYTES:
            raise ComposeProcessingError(
                "BRIDGE_RESPONSE_INVALID",
                "isolated output violates the aggregate bridge bound",
            )
        digest = hashlib.sha256()
        with entry.open("rb") as source:
            while block := source.read(1_048_576):
                digest.update(block)
        descriptors.append(
            {
                "content_digest": "sha256:" + digest.hexdigest(),
                "name": entry.name,
                "size_bytes": metadata.st_size,
            }
        )
    return descriptors


def _send_success(
    connection: socket.socket,
    result: bytes,
    output_directory: Path,
) -> None:
    descriptors = _output_descriptors(result, output_directory)
    send_frame(
        connection,
        {
            "contract_version": RESPONSE_CONTRACT,
            "files": descriptors,
            "result_digest": "sha256:" + hashlib.sha256(result).hexdigest(),
            "result_size": len(result),
            "status": "ok",
        },
    )
    connection.sendall(result)
    for descriptor in descriptors:
        path = output_directory / descriptor["name"]
        with path.open("rb") as source:
            while block := source.read(1_048_576):
                connection.sendall(block)


def _send_error(connection: socket.socket, code: str) -> None:
    safe_code = (
        code
        if isinstance(code, str) and ERROR_CODE.fullmatch(code) is not None
        else "BRIDGE_PROCESSOR_FAILED"
    )
    try:
        send_frame(
            connection,
            {
                "code": safe_code,
                "contract_version": RESPONSE_CONTRACT,
                "status": "error",
            },
        )
    except (OSError, ProcessingBridgeError):
        pass


def _run_one_request(
    connection: socket.socket,
    isolated_command: Mapping[str, Any],
) -> None:
    sources: tuple[int, ...] = ()
    targets: tuple[int, ...] = ()
    output_parent: tempfile.TemporaryDirectory[str] | None = None
    try:
        connection.settimeout(REQUEST_TIMEOUT_SECONDS)
        request = receive_frame(connection)
        targets = _validate_request(request)
        sources = _move_descriptors_high(
            receive_descriptor_batches(connection, len(targets))
        )
        _map_capabilities(sources, targets)
        output_parent = tempfile.TemporaryDirectory(
            prefix="tacua-compose-processor-output-",
        )
        output_directory = Path(output_parent.name)
        output_directory.chmod(0o700)
        previous_timeout = os.environ.get(RUNNER.OUTER_TIMEOUT_ENV)
        os.environ[RUNNER.OUTER_TIMEOUT_ENV] = str(
            RUNNER.OUTER_ADAPTER_TIMEOUT_SECONDS
        )
        try:
            RUNNER.validate_outer_timeout_environment()
            result = RUNNER.run(
                isolated_command,
                Path(f"/dev/fd/{targets[0]}"),
                output_directory,
            )
        finally:
            if previous_timeout is None:
                os.environ.pop(RUNNER.OUTER_TIMEOUT_ENV, None)
            else:
                os.environ[RUNNER.OUTER_TIMEOUT_ENV] = previous_timeout
        _send_success(connection, result, output_directory)
    except Exception as error:
        if isinstance(error, RUNNER.IsolationError):
            code = error.code
        elif isinstance(error, (ComposeProcessingError, ProcessingBridgeError)):
            code = error.code
        else:
            code = "BRIDGE_PROCESSOR_FAILED"
        _send_error(connection, code)
    finally:
        _close_targets(targets)
        for descriptor in sources:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if output_parent is not None:
            output_parent.cleanup()


def run_broker(
    socket_path: Path,
    isolated_command_file: Path,
    isolated_command_digest: str,
    max_requests: int,
    parent_pid: int,
) -> int:
    global _BROKER_FAILURE_STAGE
    os.umask(0o077)
    _BROKER_FAILURE_STAGE = "DESCRIPTOR_PREFLIGHT"
    _prepare_broker_descriptor_limit()
    _BROKER_FAILURE_STAGE = "PROVENANCE"
    if (
        _VERIFIED_SOURCE_CONTEXT is None
        or _VERIFIED_SOURCE_CONTEXT["mode"] != "broker"
        or _VERIFIED_SOURCE_CONTEXT["operation"] != socket_path.parent
    ):
        raise ComposeProcessingError(
            "BRIDGE_PROVENANCE_MISMATCH",
            "broker is not executing from the verified operation snapshot",
        )
    _BROKER_FAILURE_STAGE = "JOURNAL"
    operation_journal = _load_operation_journal(socket_path.parent)
    if (
        operation_journal["host_bundle_digest"]
        != _VERIFIED_SOURCE_CONTEXT["source_digest"]
        or operation_journal["original_repository_root"]
        != str(_VERIFIED_SOURCE_CONTEXT["original_root"])
    ):
        raise ComposeProcessingError(
            "BRIDGE_PROVENANCE_MISMATCH",
            "broker source differs from the durable operation journal",
        )
    _BROKER_FAILURE_STAGE = "INPUT"
    if (
        not socket_path.is_absolute()
        or socket_path.exists()
        or socket_path.is_symlink()
        or IMAGE_ID.fullmatch(isolated_command_digest) is None
        or not 1 <= max_requests <= MAX_DRAIN_STAGES
        or parent_pid <= 1
    ):
        raise ComposeProcessingError(
            "BRIDGE_SOCKET_INVALID",
            "broker socket or request bound is invalid",
        )
    _require_snapshot_digest(
        isolated_command_file,
        MAX_COMPOSE_BYTES,
        "isolated command snapshot",
        isolated_command_digest,
    )
    _BROKER_FAILURE_STAGE = "COMMAND"
    isolated_command = RUNNER.load_command(isolated_command_file)

    _BROKER_FAILURE_STAGE = "PARENT_WATCH"

    def watch_parent() -> None:
        while os.getppid() == parent_pid:
            time.sleep(0.25)
        os._exit(0)

    threading.Thread(
        target=watch_parent,
        name="tacua-compose-bridge-parent-watch",
        daemon=True,
    ).start()
    _BROKER_FAILURE_STAGE = "SOCKET_CREATE"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _BROKER_FAILURE_STAGE = "SOCKET_BIND"
        listener.bind(str(socket_path))
        _BROKER_FAILURE_STAGE = "SOCKET_LISTEN"
        listener.listen(1)
        _BROKER_FAILURE_STAGE = "DESCRIPTOR_RELOCATION"
        listener = _move_socket_high(listener)
        _BROKER_FAILURE_STAGE = "SOCKET_TIMEOUT"
        listener.settimeout(1)
        _BROKER_FAILURE_STAGE = "SOCKET_PUBLISH"
        socket_path.chmod(0o666)
        _BROKER_FAILURE_STAGE = "SERVE"
        for _request_index in range(max_requests):
            while True:
                if os.getppid() != parent_pid:
                    return 0
                try:
                    connection, _address = listener.accept()
                    break
                except socket.timeout:
                    continue
            with _move_socket_high(connection) as high_connection:
                _run_one_request(high_connection, isolated_command)
        return 0
    finally:
        failure_stage = _BROKER_FAILURE_STAGE
        try:
            listener.close()
            socket_path.unlink(missing_ok=True)
        except Exception:
            _BROKER_FAILURE_STAGE = "CLEANUP"
            raise
        else:
            _BROKER_FAILURE_STAGE = failure_stage


def _broker_process(
    socket_path: Path,
    isolated_command_file: Path,
    isolated_command_digest: str,
    max_requests: int,
) -> subprocess.Popen[bytes]:
    if (
        _VERIFIED_SOURCE_CONTEXT is None
        or _VERIFIED_SOURCE_CONTEXT["manifest"] is None
        or _VERIFIED_SOURCE_CONTEXT["operation"] != socket_path.parent
        or Path(__file__).resolve()
        != (
            socket_path.parent
            / _SOURCE_DIRECTORY_NAME
            / _SOURCE_EXACT_PATHS[0]
        )
    ):
        raise ComposeProcessingError(
            "BRIDGE_PROVENANCE_MISMATCH",
            "broker source snapshot is unavailable",
        )
    environment = _bootstrap_exec_environment(
        mode="broker",
        operation=socket_path.parent,
        manifest=_VERIFIED_SOURCE_CONTEXT["manifest"],
        lock_descriptor=None,
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(__file__).resolve()),
            "_broker",
            "--socket",
            str(socket_path),
            "--isolated-command-file",
            str(isolated_command_file),
            "--isolated-command-digest",
            isolated_command_digest,
            "--max-requests",
            str(max_requests),
            "--parent-pid",
            str(os.getpid()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        env=environment,
    )
    if _wait_for_broker_socket(process, socket_path):
        return process
    broker_diagnostic = _stop_broker(
        process,
        capture_stderr=True,
    )
    raise ComposeProcessingError(
        _broker_failure_code(broker_diagnostic),
        "trusted host broker did not become ready",
    )


def _wait_for_broker_socket(
    process: subprocess.Popen[bytes],
    socket_path: Path,
) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            metadata = socket_path.lstat()
        except FileNotFoundError:
            time.sleep(0.02)
            continue
        readiness = _broker_socket_readiness(metadata)
        if readiness == "ready":
            return True
        if readiness == "unsafe":
            return False
        time.sleep(0.02)
    return False


def _broker_socket_readiness(metadata: os.stat_result) -> str:
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        return "unsafe"
    if stat.S_IMODE(metadata.st_mode) == 0o666:
        return "ready"
    if stat.S_IMODE(metadata.st_mode) == 0o700:
        return "pending"
    return "unsafe"


def _broker_failure_code(payload: bytes) -> str:
    if (
        len(payload) <= 128
        and re.fullmatch(rb"BRIDGE_[A-Z0-9_]{1,96}\n", payload) is not None
    ):
        return payload.decode("ascii").strip()
    return "BRIDGE_BROKER_FAILED"


def _stop_broker(
    process: subprocess.Popen[bytes] | None,
    *,
    capture_stderr: bool = False,
) -> bytes:
    if process is None:
        return b""
    if process.returncode is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    diagnostic = b""
    if process.stderr is not None:
        try:
            if capture_stderr:
                diagnostic = process.stderr.read(129)
        finally:
            process.stderr.close()
    return diagnostic


def _worker_create_argv(
    *,
    name: str,
    project: str,
    image_id: str,
    state_volume: str,
    config_file: Path,
    admin_secret_file: Path,
    command_file: Path,
    socket_path: Path,
    worker_id: str,
    run_once: bool,
    max_stages: int,
) -> list[str]:
    config_source = _safe_mount_source(config_file, "public config")
    secret_source = _safe_mount_source(admin_secret_file, "administrator secret")
    command_source = _safe_mount_source(command_file, "bridge command")
    bridge_source = _safe_mount_source(socket_path, "bridge socket")
    argv = [
        "container",
        "create",
        "--name",
        name,
        "--pull",
        "never",
        "--label",
        f"{BRIDGE_LABEL}=true",
        "--label",
        f"{BRIDGE_CONTRACT_LABEL}={REQUEST_CONTRACT}",
        "--label",
        f"{BRIDGE_PROJECT_LABEL}={project}",
        "--label",
        f"{BRIDGE_ROLE_LABEL}={BRIDGE_WORKER_ROLE}",
        "--user",
        "10001:10001",
        "--read-only",
        "--init",
        "--network",
        "none",
        "--ipc",
        "none",
        "--pids-limit",
        "128",
        "--cpus",
        "2.0",
        "--memory",
        "4g",
        "--memory-swap",
        "4g",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--ulimit",
        "nofile=1024:1024",
        "--no-healthcheck",
        "--log-driver",
        "none",
        "--tmpfs",
        f"/tmp:{WORKER_TMPFS_OPTIONS}",
        "--mount",
        f"type=volume,src={state_volume},dst={STATE_IN_CONTAINER},volume-nocopy",
        "--mount",
        f"type=bind,src={config_source},dst={CONFIG_IN_CONTAINER},readonly",
        "--mount",
        f"type=bind,src={secret_source},dst={SECRET_IN_CONTAINER},readonly",
        "--mount",
        f"type=bind,src={command_source},dst={BRIDGE_COMMAND_IN_CONTAINER},readonly",
        "--mount",
        f"type=bind,src={bridge_source},dst={BRIDGE_SOCKET_IN_CONTAINER},readonly",
        "--entrypoint",
        "/usr/local/bin/python",
        image_id,
        *_worker_command_argv(
            worker_id=worker_id,
            run_once=run_once,
            max_stages=max_stages,
        ),
    ]
    return argv


def _worker_command_argv(
    *,
    worker_id: str,
    run_once: bool,
    max_stages: int,
) -> list[str]:
    argv = [
        "-B",
        "-m",
        "tacua_backend.processing_worker",
        "--config-file",
        CONFIG_IN_CONTAINER,
        "--admin-secret-file",
        SECRET_IN_CONTAINER,
        "--command-file",
        BRIDGE_COMMAND_IN_CONTAINER,
        "--worker-id",
        worker_id,
    ]
    if run_once:
        argv.append("--run-once")
    else:
        argv.extend(["--drain", "--max-stages", str(max_stages)])
    return argv


def _inspect_worker(
    container_id: str,
    *,
    name: str,
    project: str,
    image_id: str,
    state_volume: str,
    expected_status: str,
    expected_command: Sequence[str],
    expected_bind_sources: Mapping[str, str] | None = None,
) -> None:
    inspected = _inspect_container(container_id)
    config = inspected.get("Config")
    host_config = inspected.get("HostConfig")
    state = inspected.get("State")
    mounts = inspected.get("Mounts")
    labels = config.get("Labels") if isinstance(config, dict) else None
    healthcheck = (
        config.get("Healthcheck") if isinstance(config, dict) else None
    )
    by_destination = {
        mount.get("Destination"): mount
        for mount in mounts
        if isinstance(mount, dict) and isinstance(mount.get("Destination"), str)
    } if isinstance(mounts, list) else {}
    allowed_destinations = {
        STATE_IN_CONTAINER,
        CONFIG_IN_CONTAINER,
        SECRET_IN_CONTAINER,
        BRIDGE_COMMAND_IN_CONTAINER,
        BRIDGE_SOCKET_IN_CONTAINER,
    }
    runtime_destinations = set(by_destination)
    tmpfs_mount = by_destination.get("/tmp")
    expected_running = expected_status == "running"
    if (
        expected_bind_sources is not None
        and set(expected_bind_sources)
        != allowed_destinations - {STATE_IN_CONTAINER}
    ):
        raise ComposeProcessingError(
            "BRIDGE_WORKER_INVALID",
            "one-shot worker expected mount-source set differs",
        )
    if (
        inspected.get("Id") != container_id
        or inspected.get("Name") != f"/{name}"
        or inspected.get("Image") != image_id
        or not isinstance(config, dict)
        or config.get("Image") != image_id
        or config.get("User") != "10001:10001"
        or config.get("Entrypoint") != ["/usr/local/bin/python"]
        or config.get("Cmd") != list(expected_command)
        or not isinstance(healthcheck, dict)
        or healthcheck.get("Test") != ["NONE"]
        or not isinstance(labels, dict)
        or labels.get(BRIDGE_LABEL) != "true"
        or labels.get(BRIDGE_CONTRACT_LABEL) != REQUEST_CONTRACT
        or labels.get(BRIDGE_PROJECT_LABEL) != project
        or labels.get(BRIDGE_ROLE_LABEL) != BRIDGE_WORKER_ROLE
        or not isinstance(host_config, dict)
        or host_config.get("ReadonlyRootfs") is not True
        or host_config.get("Init") is not True
        or host_config.get("NetworkMode") != "none"
        or host_config.get("IpcMode") != "none"
        or host_config.get("Privileged") is not False
        or host_config.get("CapAdd") not in (None, [])
        or host_config.get("CapDrop") != ["ALL"]
        or host_config.get("SecurityOpt") != ["no-new-privileges:true"]
        or host_config.get("PidsLimit") != 128
        or host_config.get("Memory") != 4_294_967_296
        or host_config.get("MemorySwap") != 4_294_967_296
        or host_config.get("NanoCpus") != 2_000_000_000
        or host_config.get("LogConfig") != {
            "Config": {},
            "Type": "none",
        }
        or host_config.get("Tmpfs") != {
            "/tmp": WORKER_TMPFS_OPTIONS,
        }
        or host_config.get("Ulimits")
        != [{"Name": "nofile", "Hard": 1024, "Soft": 1024}]
        or host_config.get("RestartPolicy")
        != {"Name": "no", "MaximumRetryCount": 0}
        or host_config.get("AutoRemove") is not False
        or host_config.get("PortBindings") not in (None, {})
        or host_config.get("PublishAllPorts") is not False
        or host_config.get("Devices") not in (None, [])
        or host_config.get("DeviceRequests") not in (None, [])
        or host_config.get("GroupAdd") not in (None, [])
        or host_config.get("PidMode") not in (None, "")
        or host_config.get("UTSMode") not in (None, "")
        or host_config.get("UsernsMode") not in (None, "")
        or not isinstance(state, dict)
        or state.get("Status") != expected_status
        or state.get("Running") is not expected_running
        or inspected.get("RestartCount") != 0
        or not isinstance(mounts, list)
        or len(by_destination) != len(mounts)
        or not allowed_destinations.issubset(runtime_destinations)
        or not runtime_destinations.issubset(
            allowed_destinations | {"/tmp"}
        )
        or (
            tmpfs_mount is not None
            and (
                tmpfs_mount.get("Type") != "tmpfs"
                or tmpfs_mount.get("RW") is not True
            )
        )
        or by_destination[STATE_IN_CONTAINER].get("Type") != "volume"
        or by_destination[STATE_IN_CONTAINER].get("Name") != state_volume
        or by_destination[STATE_IN_CONTAINER].get("RW") is not True
        or any(
            by_destination[target].get("Type") != "bind"
            or by_destination[target].get("RW") is not False
            for target in allowed_destinations - {STATE_IN_CONTAINER}
        )
        or (
            expected_bind_sources is not None
            and any(
                by_destination[target].get("Source") != source
                for target, source in expected_bind_sources.items()
            )
        )
        or any(
            destination in by_destination
            for destination in {"/var/run/docker.sock", "/run/docker.sock"}
        )
    ):
        raise ComposeProcessingError(
            "BRIDGE_WORKER_INVALID",
            "one-shot worker isolation or mount identity differs",
        )


def _run_created_worker(
    container_id: str,
    *,
    stage_limit: int,
    expected_mode: str,
) -> dict[str, Any]:
    result = _docker(
        ["container", "start", "--attach", container_id],
        timeout=max(
            DOCKER_COMMAND_TIMEOUT_SECONDS,
            stage_limit * WORKER_STAGE_TIMEOUT_SECONDS,
        ),
        check=False,
    )
    inspected = _inspect_container(container_id)
    state = inspected.get("State")
    if (
        result.returncode != 0
        or not isinstance(state, dict)
        or state.get("Status") != "exited"
        or state.get("ExitCode") != 0
        or state.get("OOMKilled") is not False
        or state.get("Error") not in {None, ""}
    ):
        raise ComposeProcessingError(
            "BRIDGE_WORKER_FAILED",
            "one-shot worker exited unsuccessfully",
        )
    summary = _parse_json(result.stdout, "worker summary")
    expected_keys = {
        "claim_retries",
        "last_job_id",
        "mode",
        "processed_stages",
        "queue_empty",
        "stage_limit_reached",
    }
    if (
        not isinstance(summary, dict)
        or set(summary) != expected_keys
        or type(summary.get("processed_stages")) is not int
        or not 0 <= summary["processed_stages"] <= stage_limit
        or type(summary.get("claim_retries")) is not int
        or not 0 <= summary["claim_retries"] <= stage_limit * 2 + 50
        or type(summary.get("queue_empty")) is not bool
        or type(summary.get("stage_limit_reached")) is not bool
        or summary.get("mode") != expected_mode
        or (
            summary.get("last_job_id") is not None
            and (
                not isinstance(summary["last_job_id"], str)
                or ID.fullmatch(summary["last_job_id"]) is None
            )
        )
        or (summary["processed_stages"] == 0)
        is not (summary.get("last_job_id") is None)
        or summary["stage_limit_reached"]
        is not (
            summary["processed_stages"] >= stage_limit
            and not summary["queue_empty"]
        )
        or (
            summary["queue_empty"]
            and summary["processed_stages"] >= stage_limit
        )
    ):
        raise ComposeProcessingError(
            "BRIDGE_WORKER_FAILED",
            "one-shot worker summary is invalid",
        )
    return summary


def _state_verifier_command_argv() -> list[str]:
    return [
        "-B",
        "-m",
        "tacua_backend.operator_tool",
        "verify-compose-state",
        "--config-file",
        CONFIG_IN_CONTAINER,
        "--state-directory",
        STATE_IN_CONTAINER,
    ]


def _state_verifier_create_argv(
    *,
    name: str,
    project: str,
    image_id: str,
    state_volume: str,
    config_source: str,
) -> list[str]:
    return [
        "container",
        "create",
        "--name",
        name,
        "--label",
        f"{BRIDGE_LABEL}=true",
        "--label",
        f"{BRIDGE_CONTRACT_LABEL}={OPERATION_CONTRACT}",
        "--label",
        f"{BRIDGE_PROJECT_LABEL}={project}",
        "--label",
        f"{BRIDGE_ROLE_LABEL}={BRIDGE_VERIFIER_ROLE}",
        "--pull",
        "never",
        "--user",
        "10001:10001",
        "--read-only",
        "--network",
        "none",
        "--ipc",
        "none",
        "--init",
        "--pids-limit",
        "128",
        "--cpus",
        "2.0",
        "--memory",
        str(STATE_VERIFIER_MEMORY_BYTES),
        "--memory-swap",
        str(STATE_VERIFIER_MEMORY_BYTES),
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--no-healthcheck",
        "--restart",
        "no",
        "--log-driver",
        "none",
        "--ulimit",
        "nofile=1024:1024",
        "--env",
        "TMPDIR=/tmp",
        "--tmpfs",
        f"/tmp:{STATE_VERIFIER_TMPFS_OPTIONS}",
        "--mount",
        (
            f"type=volume,src={state_volume},"
            f"dst={STATE_IN_CONTAINER},volume-nocopy"
        ),
        "--mount",
        (
            f"type=bind,src={config_source},"
            f"dst={CONFIG_IN_CONTAINER},readonly"
        ),
        "--entrypoint",
        "/usr/local/bin/python",
        image_id,
        *_state_verifier_command_argv(),
    ]


def _inspect_state_verifier(
    container_id: str,
    *,
    name: str,
    project: str,
    image_id: str,
    state_volume: str,
    config_source: str,
    expected_status: str,
) -> None:
    inspected = _inspect_container(container_id)
    config = inspected.get("Config")
    host = inspected.get("HostConfig")
    state = inspected.get("State")
    mounts = inspected.get("Mounts")
    labels = config.get("Labels") if isinstance(config, dict) else None
    healthcheck = (
        config.get("Healthcheck") if isinstance(config, dict) else None
    )
    environment = config.get("Env") if isinstance(config, dict) else None
    tmpdir_environment = (
        [
            item
            for item in environment
            if isinstance(item, str) and item.startswith("TMPDIR=")
        ]
        if isinstance(environment, list)
        else []
    )
    by_destination = {
        mount.get("Destination"): mount
        for mount in mounts
        if isinstance(mount, dict)
        and isinstance(mount.get("Destination"), str)
    } if isinstance(mounts, list) else {}
    expected_running = expected_status == "running"
    if (
        inspected.get("Id") != container_id
        or inspected.get("Name") != f"/{name}"
        or inspected.get("Image") != image_id
        or not isinstance(config, dict)
        or config.get("Image") != image_id
        or config.get("User") != "10001:10001"
        or config.get("Entrypoint") != ["/usr/local/bin/python"]
        or config.get("Cmd") != _state_verifier_command_argv()
        or tmpdir_environment != ["TMPDIR=/tmp"]
        or not isinstance(healthcheck, dict)
        or healthcheck.get("Test") != ["NONE"]
        or not isinstance(labels, dict)
        or labels.get(BRIDGE_LABEL) != "true"
        or labels.get(BRIDGE_CONTRACT_LABEL) != OPERATION_CONTRACT
        or labels.get(BRIDGE_PROJECT_LABEL) != project
        or labels.get(BRIDGE_ROLE_LABEL) != BRIDGE_VERIFIER_ROLE
        or not isinstance(host, dict)
        or host.get("ReadonlyRootfs") is not True
        or host.get("Init") is not True
        or host.get("NetworkMode") != "none"
        or host.get("IpcMode") != "none"
        or host.get("Privileged") is not False
        or host.get("CapAdd") not in (None, [])
        or host.get("CapDrop") != ["ALL"]
        or host.get("SecurityOpt") != ["no-new-privileges:true"]
        or host.get("PidsLimit") != 128
        or host.get("Memory") != STATE_VERIFIER_MEMORY_BYTES
        or host.get("MemorySwap") != STATE_VERIFIER_MEMORY_BYTES
        or host.get("NanoCpus") != 2_000_000_000
        or host.get("LogConfig") != {"Config": {}, "Type": "none"}
        or host.get("Tmpfs")
        != {"/tmp": STATE_VERIFIER_TMPFS_OPTIONS}
        or host.get("Ulimits")
        != [{"Name": "nofile", "Hard": 1024, "Soft": 1024}]
        or host.get("RestartPolicy")
        != {"Name": "no", "MaximumRetryCount": 0}
        or host.get("AutoRemove") is not False
        or host.get("PortBindings") not in (None, {})
        or host.get("PublishAllPorts") is not False
        or host.get("Devices") not in (None, [])
        or host.get("DeviceRequests") not in (None, [])
        or host.get("GroupAdd") not in (None, [])
        or host.get("PidMode") not in (None, "")
        or host.get("UTSMode") not in (None, "")
        or host.get("UsernsMode") not in (None, "")
        or not isinstance(state, dict)
        or state.get("Status") != expected_status
        or state.get("Running") is not expected_running
        or inspected.get("RestartCount") != 0
        or not isinstance(mounts, list)
        or len(by_destination) != len(mounts)
        or STATE_IN_CONTAINER not in by_destination
        or CONFIG_IN_CONTAINER not in by_destination
        or not set(by_destination).issubset(
            {STATE_IN_CONTAINER, CONFIG_IN_CONTAINER, "/tmp"}
        )
        or by_destination[STATE_IN_CONTAINER].get("Type") != "volume"
        or by_destination[STATE_IN_CONTAINER].get("Name") != state_volume
        or by_destination[STATE_IN_CONTAINER].get("RW") is not True
        or by_destination[CONFIG_IN_CONTAINER].get("Type") != "bind"
        or by_destination[CONFIG_IN_CONTAINER].get("Source")
        != config_source
        or by_destination[CONFIG_IN_CONTAINER].get("RW") is not False
        or any(
            destination in by_destination
            for destination in {"/var/run/docker.sock", "/run/docker.sock"}
        )
    ):
        raise ComposeProcessingError(
            "BRIDGE_STATE_VERIFIER_INVALID",
            "offline state verifier identity or isolation differs",
        )


def _verify_state_offline(
    *,
    operation: Path,
    attempt: Mapping[str, Any],
    name: str,
    project: str,
    image_id: str,
    state_volume: str,
    config_source: str,
    on_created: Any,
) -> None:
    container_id: str | None = None
    try:
        receipt = _finish_container_create(
            operation,
            attempt,
            start=True,
        )
        if receipt["outcome"] != "created":
            raise ComposeProcessingError(
                "BRIDGE_DOCKER_FAILED",
                "offline state verifier creation was indeterminate",
            )
        container_id = str(receipt["container_id"])
        on_created(container_id)
        _clear_create_receipt(operation)
        _inspect_state_verifier(
            container_id,
            name=name,
            project=project,
            image_id=image_id,
            state_volume=state_volume,
            config_source=config_source,
            expected_status="created",
        )
        result = _docker(
            ["container", "start", "--attach", container_id],
            timeout=120,
            check=False,
        )
        _inspect_state_verifier(
            container_id,
            name=name,
            project=project,
            image_id=image_id,
            state_volume=state_volume,
            config_source=config_source,
            expected_status="exited",
        )
        inspected = _inspect_container(container_id)
        state = inspected.get("State")
        if (
            result.returncode != 0
            or not isinstance(state, dict)
            or state.get("ExitCode") != 0
            or state.get("OOMKilled") is not False
            or state.get("Error") not in {None, ""}
        ):
            raise ComposeProcessingError(
                "BRIDGE_STATE_INVALID",
                "offline state verification failed",
            )
        summary = _parse_json(
            result.stdout,
            "offline state verification",
        )
        if (
            not isinstance(summary, dict)
            or set(summary)
            != {
                "config_digest",
                "deployment_pin_digest",
                "state_directory",
                "status",
            }
            or summary.get("status") != "ok"
            or summary.get("state_directory") != STATE_IN_CONTAINER
            or not isinstance(summary.get("config_digest"), str)
            or IMAGE_ID.fullmatch(summary["config_digest"]) is None
            or not isinstance(summary.get("deployment_pin_digest"), str)
            or IMAGE_ID.fullmatch(summary["deployment_pin_digest"]) is None
        ):
            raise ComposeProcessingError(
                "BRIDGE_STATE_INVALID",
                "offline state verification result is invalid",
            )
    finally:
        _remove_verifier(container_id)


def _journaled_verify_state(
    *,
    operation: Path,
    journal: Mapping[str, Any],
    purpose: str,
    final_phase: str,
    project: str,
    image_id: str,
    state_volume: str,
    config_file: Path,
    **final_changes: Any,
) -> dict[str, Any]:
    if purpose not in {"baseline", "post_worker", "recovery"}:
        raise ComposeProcessingError(
            "BRIDGE_JOURNAL_INVALID",
            "offline verifier purpose is invalid",
        )
    name = f"tacua-state-verifier-{os.getpid()}-{secrets.token_hex(6)}"
    config_source = _safe_mount_source(config_file, "public config")
    attempt = _prepare_container_create(
        operation=operation,
        argv=_state_verifier_create_argv(
            name=name,
            project=project,
            image_id=image_id,
            state_volume=state_volume,
            config_source=config_source,
        ),
        project=project,
        role=BRIDGE_VERIFIER_ROLE,
        purpose=purpose,
        name=name,
    )
    try:
        current = _advance_operation_journal(
            operation,
            journal,
            f"{purpose}_verifier_creating",
            verifier_container_id=None,
            verifier_name=name,
        )
    except BaseException:
        _finish_container_create(
            operation,
            attempt,
            start=False,
        )
        raise

    def on_created(container_id: str) -> None:
        nonlocal current
        current = _advance_operation_journal(
            operation,
            current,
            f"{purpose}_verifier_created",
            verifier_container_id=container_id,
        )

    _verify_state_offline(
        operation=operation,
        attempt=attempt,
        name=name,
        project=project,
        image_id=image_id,
        state_volume=state_volume,
        config_source=config_source,
        on_created=on_created,
    )
    return _advance_operation_journal(
        operation,
        current,
        final_phase,
        verifier_container_id=None,
        verifier_name=None,
        **final_changes,
    )


def _verifier_recovery_purpose(journal: Mapping[str, Any]) -> str:
    phase = str(journal["phase"])
    for purpose in ("baseline", "post_worker", "recovery"):
        if phase in {
            f"{purpose}_verifier_creating",
            f"{purpose}_verifier_created",
        }:
            return purpose
    raise ComposeProcessingError(
        "BRIDGE_RECOVERY_UNSAFE",
        "recovery state verifier phase is invalid",
    )


def _retired_verifier_phase(journal: Mapping[str, Any]) -> str:
    if journal["state_verified_after_worker"]:
        return "state_verified"
    if journal["worker_started"]:
        return "worker_exited"
    if journal["baseline_state_verified"]:
        return "baseline_verified"
    return "backend_stopped"


def _advance_recovery_container_created(
    operation: Path,
    journal: Mapping[str, Any],
    *,
    role: str,
    purpose: str,
    container_id: str,
) -> dict[str, Any]:
    if role == BRIDGE_WORKER_ROLE:
        phase = "worker_created"
        changes = {"worker_container_id": container_id}
    elif role == BRIDGE_VERIFIER_ROLE:
        phase = f"{purpose}_verifier_created"
        changes = {"verifier_container_id": container_id}
    else:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "recovery container role is invalid",
        )
    return _advance_operation_journal(
        operation,
        journal,
        phase,
        **changes,
    )


def _advance_recovery_container_retired(
    operation: Path,
    journal: Mapping[str, Any],
    *,
    role: str,
    worker_started: bool | None = None,
) -> dict[str, Any]:
    if role == BRIDGE_WORKER_ROLE:
        if worker_started is None:
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "recovery worker state is incomplete",
            )
        return _advance_operation_journal(
            operation,
            journal,
            "worker_exited",
            worker_container_id=None,
            worker_name=None,
            worker_started=worker_started,
        )
    if role == BRIDGE_VERIFIER_ROLE:
        return _advance_operation_journal(
            operation,
            journal,
            _retired_verifier_phase(journal),
            verifier_container_id=None,
            verifier_name=None,
        )
    raise ComposeProcessingError(
        "BRIDGE_RECOVERY_UNSAFE",
        "recovery container role is invalid",
    )


def _reconcile_recovery_container(
    *,
    operation: Path,
    journal: Mapping[str, Any],
    project: str,
    role: str,
    validate_candidate: Any,
    remove_candidate: Any,
) -> dict[str, Any]:
    current = dict(journal)
    if role == BRIDGE_WORKER_ROLE:
        recorded_id = current["worker_container_id"]
        recorded_name = current["worker_name"]
        purpose = "worker"
        creating_phase = "worker_creating"
    elif role == BRIDGE_VERIFIER_ROLE:
        recorded_id = current["verifier_container_id"]
        recorded_name = current["verifier_name"]
        purpose = (
            _verifier_recovery_purpose(current)
            if recorded_name is not None
            else None
        )
        creating_phase = (
            f"{purpose}_verifier_creating"
            if purpose is not None
            else None
        )
    else:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "recovery container role is invalid",
        )

    receipt = _load_create_receipt(operation, required=False)
    role_receipt = (
        receipt
        if receipt is not None and receipt["role"] == role
        else None
    )
    if recorded_name is None:
        if role_receipt is None:
            return current
        if (
            role_receipt["project"] != project
            or role_receipt["outcome"] != "not_started"
        ):
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "unbound container-create receipt is not safely negative",
            )
        if (
            _recovery_container_candidate(
                project=project,
                role=role,
                recorded_name=str(role_receipt["name"]),
                recorded_id=None,
            )
            is not None
        ):
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "unbound container-create receipt conflicts with Docker",
            )
        _clear_create_receipt(operation)
        return current

    assert purpose is not None
    if role_receipt is not None:
        if (
            role_receipt["project"] != project
            or role_receipt["name"] != recorded_name
            or role_receipt["purpose"] != purpose
            or (
                recorded_id is not None
                and role_receipt["outcome"] == "created"
                and role_receipt["container_id"] != recorded_id
            )
        ):
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "container-create receipt differs from its journal",
            )

    candidate = _recovery_container_candidate(
        project=project,
        role=role,
        recorded_name=recorded_name,
        recorded_id=recorded_id,
    )
    creating = current["phase"] == creating_phase
    if candidate is None:
        if creating:
            if role_receipt is None or role_receipt["outcome"] in {
                "indeterminate",
            }:
                raise ComposeProcessingError(
                    "BRIDGE_RECOVERY_UNSAFE",
                    "container creation has no durable negative result",
                )
            if role_receipt["outcome"] == "not_started":
                current = _advance_recovery_container_retired(
                    operation,
                    current,
                    role=role,
                    worker_started=(
                        bool(current["worker_started"])
                        if role == BRIDGE_WORKER_ROLE
                        else None
                    ),
                )
                _clear_create_receipt(operation)
                return current
            recorded_id = str(role_receipt["container_id"])
            current = _advance_recovery_container_created(
                operation,
                current,
                role=role,
                purpose=purpose,
                container_id=recorded_id,
            )
            _clear_create_receipt(operation)
        elif role_receipt is not None:
            if role_receipt["outcome"] == "not_started":
                raise ComposeProcessingError(
                    "BRIDGE_RECOVERY_UNSAFE",
                    "container-create receipt contradicts its journal",
                )
            _clear_create_receipt(operation)
        return _advance_recovery_container_retired(
            operation,
            current,
            role=role,
            worker_started=(
                bool(current["worker_started"])
                if role == BRIDGE_WORKER_ROLE
                else None
            ),
        )

    if role_receipt is not None:
        if role_receipt["outcome"] == "not_started":
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "container-create receipt contradicts Docker",
            )
        if (
            role_receipt["outcome"] == "created"
            and role_receipt["container_id"] != candidate
        ):
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "container-create receipt differs from Docker",
            )
    if recorded_id is not None and candidate != recorded_id:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "recovery container differs from its journal ID",
        )
    status = validate_candidate(candidate, recorded_name)
    if creating:
        current = _advance_recovery_container_created(
            operation,
            current,
            role=role,
            purpose=purpose,
            container_id=candidate,
        )
        recorded_id = candidate
    if (
        role == BRIDGE_WORKER_ROLE
        and status != "created"
        and not current["worker_started"]
    ):
        current = _advance_operation_journal(
            operation,
            current,
            (
                "worker_exited"
                if current["phase"] == "worker_exited"
                else "worker_starting"
            ),
            worker_started=True,
        )
    if role_receipt is not None:
        _clear_create_receipt(operation)
    remove_candidate(candidate)
    if (
        _recovery_container_candidate(
            project=project,
            role=role,
            recorded_name=recorded_name,
            recorded_id=recorded_id,
        )
        is not None
    ):
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "recovery container remains after removal",
        )
    return _advance_recovery_container_retired(
        operation,
        current,
        role=role,
        worker_started=(
            bool(current["worker_started"]) or status != "created"
            if role == BRIDGE_WORKER_ROLE
            else None
        ),
    )


def _retire_recovery_verifier(
    *,
    operation: Path,
    journal: Mapping[str, Any],
    project: str,
    image_id: str,
    state_volume: str,
    config_file: Path,
) -> dict[str, Any]:
    config_source = _safe_mount_source(config_file, "public config")

    def validate_candidate(container_id: str, recorded_name: str) -> str:
        inspected = _inspect_container(container_id)
        state = inspected.get("State")
        status = state.get("Status") if isinstance(state, dict) else None
        name = str(inspected.get("Name", "")).removeprefix("/")
        if (
            name != recorded_name
            or status
            not in {"created", "running", "exited", "dead", "removing"}
        ):
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "recovery state verifier differs from its journal",
            )
        _inspect_state_verifier(
            container_id,
            name=name,
            project=project,
            image_id=image_id,
            state_volume=state_volume,
            config_source=config_source,
            expected_status=status,
        )
        return str(status)

    return _reconcile_recovery_container(
        operation=operation,
        journal=journal,
        project=project,
        role=BRIDGE_VERIFIER_ROLE,
        validate_candidate=validate_candidate,
        remove_candidate=_remove_verifier,
    )


def _retire_recovery_worker(
    *,
    operation: Path,
    journal: Mapping[str, Any],
    project: str,
    image_id: str,
    state_volume: str,
) -> dict[str, Any]:
    current = dict(journal)

    def validate_candidate(container_id: str, recorded_name: str) -> str:
        inspected = _inspect_container(container_id)
        state = inspected.get("State")
        status = state.get("Status") if isinstance(state, dict) else None
        name = str(inspected.get("Name", "")).removeprefix("/")
        if (
            name != recorded_name
            or status
            not in {"created", "running", "exited", "dead", "removing"}
        ):
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "recovery worker differs from its journal",
            )
        _inspect_worker(
            container_id,
            name=name,
            project=project,
            image_id=image_id,
            state_volume=state_volume,
            expected_status=status,
            expected_command=_worker_command_argv(
                worker_id=current["worker_id"],
                run_once=current["run_once"],
                max_stages=current["max_stages"],
            ),
            expected_bind_sources={
                CONFIG_IN_CONTAINER: current["config_identity"]["path"],
                SECRET_IN_CONTAINER: current["secret_identity"]["path"],
                BRIDGE_COMMAND_IN_CONTAINER: str(
                    operation / "processing-command.json"
                ),
                BRIDGE_SOCKET_IN_CONTAINER: str(
                    operation / "processing-bridge.sock"
                ),
            },
        )
        return str(status)

    return _reconcile_recovery_container(
        operation=operation,
        journal=current,
        project=project,
        role=BRIDGE_WORKER_ROLE,
        validate_candidate=validate_candidate,
        remove_candidate=_remove_worker,
    )


def _wait_backend_healthy(
    container_id: str,
    image_id: str,
    configured_image: str,
    state_volume: str,
    project: str,
) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        inspected = _inspect_container(container_id)
        state = inspected.get("State")
        health = state.get("Health") if isinstance(state, dict) else None
        if (
            isinstance(state, dict)
            and state.get("Status") == "running"
            and isinstance(health, dict)
            and health.get("Status") == "healthy"
        ):
            _inspect_backend(
                container_id=container_id,
                project=project,
                state_volume=state_volume,
                expected_status="running",
                expected_image_id=image_id,
                expected_config_image=configured_image,
                require_healthy=True,
            )
            return
        if isinstance(state, dict) and state.get("Status") in {"dead", "removing"}:
            break
        time.sleep(0.25)
    raise ComposeProcessingError(
        "BRIDGE_RESTART_FAILED",
        "backend did not return healthy",
    )


def _remove_worker(
    container_id: str | None,
) -> None:
    if container_id is None:
        return
    _docker(
        ["container", "rm", "--force", container_id],
        timeout=30,
        check=False,
    )
    listed = _docker(
        [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"id={container_id}",
        ],
        timeout=15,
    ).stdout
    try:
        identifiers = [
            line.strip()
            for line in listed.decode("ascii", errors="strict").splitlines()
            if line.strip()
        ]
    except UnicodeError as error:
        raise ComposeProcessingError(
            "BRIDGE_WORKER_CLEANUP_FAILED",
            "one-shot worker cleanup identity is invalid",
        ) from error
    if identifiers:
        raise ComposeProcessingError(
            "BRIDGE_WORKER_CLEANUP_FAILED",
            "one-shot worker container remained after processing",
        )


def _remove_verifier(
    container_id: str | None,
) -> None:
    if container_id is None:
        return
    _docker(
        ["container", "rm", "--force", container_id],
        timeout=30,
        check=False,
    )
    listed = _docker(
        [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"id={container_id}",
        ],
        timeout=15,
    ).stdout
    try:
        identifiers = [
            line.strip()
            for line in listed.decode("ascii", errors="strict").splitlines()
            if line.strip()
        ]
    except UnicodeError as error:
        raise ComposeProcessingError(
            "BRIDGE_STATE_VERIFIER_CLEANUP_FAILED",
            "offline state verifier cleanup identity is invalid",
        ) from error
    if identifiers:
        raise ComposeProcessingError(
            "BRIDGE_STATE_VERIFIER_CLEANUP_FAILED",
            "offline state verifier container remained after processing",
        )


def _smoke_restarted_backend(
    config_file: Path,
    admin_secret_file: Path,
    published_port: str,
) -> None:
    if (
        re.fullmatch(r"[1-9][0-9]{0,4}", published_port) is None
        or int(published_port) > 65_535
    ):
        raise ComposeProcessingError(
            "BRIDGE_COMPOSE_INVALID",
            "validated Compose published port is invalid",
        )
    smoke_deployment(
        config_file,
        admin_secret_file,
        origin_override=f"http://127.0.0.1:{published_port}",
        allow_loopback_http=True,
    )


def _recover_backend(
    *,
    operation: Path,
    journal: Mapping[str, Any],
    backend_container_id: str,
    image_id: str,
    configured_image: str,
    state_volume: str,
    project: str,
    compose_prefix: Sequence[str],
    compose_snapshot: Path,
    compose_digest: str,
    published_port: str,
    config_file: Path,
    admin_secret_file: Path,
    config_identity: Mapping[str, Any],
    secret_identity: Mapping[str, Any],
) -> dict[str, Any]:
    _discard_incomplete_journal_update(operation)
    current = _load_operation_journal(operation)
    if (
        current["backend_container_id"] != backend_container_id
        or current["image_id"] != image_id
        or current["configured_image"] != configured_image
        or current["state_volume"] != state_volume
        or current["project"] != project
        or current["compose_digest"] != compose_digest
        or current["original_repository_root"]
        != str(ORIGINAL_REPOSITORY_ROOT)
        or current["config_identity"] != dict(config_identity)
        or current["secret_identity"] != dict(secret_identity)
        or journal["contract_version"] != current["contract_version"]
    ):
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "automatic recovery inputs differ from the durable journal",
        )
    _require_snapshot_digest(
        compose_snapshot,
        MAX_COMPOSE_BYTES,
        "resolved Compose snapshot",
        compose_digest,
    )
    _require_mount_identity(
        config_file,
        "public config",
        config_identity,
    )
    _require_mount_identity(
        admin_secret_file,
        "administrator secret",
        secret_identity,
    )
    current = _retire_recovery_worker(
        operation=operation,
        journal=current,
        project=project,
        image_id=image_id,
        state_volume=state_volume,
    )
    current = _retire_recovery_verifier(
        operation=operation,
        journal=current,
        project=project,
        image_id=image_id,
        state_volume=state_volume,
        config_file=config_file,
    )
    if _volume_consumers(state_volume) != {backend_container_id}:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "backend is not the sole state-volume consumer",
        )
    inspected = _inspect_container(backend_container_id)
    state = inspected.get("State")
    status = state.get("Status") if isinstance(state, dict) else None
    if status == "running":
        if (
            current["worker_started"]
            and not current["state_verified_after_worker"]
        ):
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "state touched by a worker was not verified before restart",
            )
    elif status == "exited":
        if (
            current["worker_started"]
            and not current["state_verified_after_worker"]
        ):
            current = _journaled_verify_state(
                operation=operation,
                journal=current,
                purpose="recovery",
                final_phase="state_verified",
                project=project,
                image_id=image_id,
                state_volume=state_volume,
                config_file=config_file,
                baseline_state_verified=True,
                state_verified_after_worker=current["worker_started"],
            )
        _inspect_backend(
            container_id=backend_container_id,
            project=project,
            state_volume=state_volume,
            expected_status="exited",
            expected_image_id=image_id,
            expected_config_image=configured_image,
        )
        _require_snapshot_digest(
            compose_snapshot,
            MAX_COMPOSE_BYTES,
            "resolved Compose snapshot",
            compose_digest,
        )
        _docker([*compose_prefix, "start", "backend"], timeout=60)
    else:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "backend state is not safe for automatic recovery",
        )
    _wait_backend_healthy(
        backend_container_id,
        image_id,
        configured_image,
        state_volume,
        project,
    )
    _smoke_restarted_backend(
        config_file,
        admin_secret_file,
        published_port,
    )
    _require_snapshot_digest(
        compose_snapshot,
        MAX_COMPOSE_BYTES,
        "resolved Compose snapshot",
        compose_digest,
    )
    _require_mount_identity(
        config_file,
        "public config",
        config_identity,
    )
    _require_mount_identity(
        admin_secret_file,
        "administrator secret",
        secret_identity,
    )
    return current


def _retire_orphaned_broker_socket(socket_path: Path) -> None:
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        if not socket_path.exists() and not socket_path.is_symlink():
            return
        time.sleep(0.1)
    try:
        metadata = socket_path.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "recovery broker socket identity differs",
        )
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.2)
        connected = probe.connect_ex(str(socket_path)) == 0
    finally:
        probe.close()
    if connected:
        raise ComposeProcessingError(
            "BRIDGE_RECOVERY_UNSAFE",
            "orphaned bridge broker is still accepting requests",
        )
    socket_path.unlink()
    _fsync_directory(socket_path.parent)


def recover_compose_processing(args: argparse.Namespace) -> dict[str, Any]:
    if PROJECT.fullmatch(args.project) is None:
        raise ComposeProcessingError(
            "BRIDGE_INPUT_INVALID",
            "recovery project is invalid",
        )
    bootstrap = (
        _VERIFIED_SOURCE_CONTEXT
        if _VERIFIED_SOURCE_CONTEXT is not None
        and _VERIFIED_SOURCE_CONTEXT["mode"]
        in {"recover", "journal_free_recover"}
        else None
    )
    lock_descriptor = (
        int(bootstrap["lock_descriptor"])
        if bootstrap is not None
        else _acquire_host_lock(args.project)
    )
    operation = _operation_path(args.operation_directory, args.project)
    if bootstrap is not None and operation != bootstrap["operation"]:
        _release_host_lock(lock_descriptor)
        raise ComposeProcessingError(
            "BRIDGE_OPERATION_DIRECTORY_INVALID",
            "recovery operation differs from its verified bootstrap",
        )
    operation_cleared = False
    try:
        try:
            metadata = operation.lstat()
        except FileNotFoundError as error:
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_NOT_FOUND",
                "no durable Compose processing operation was found",
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ComposeProcessingError(
                "BRIDGE_OPERATION_DIRECTORY_INVALID",
                "recovery operation directory is unsafe",
            )
        _discard_incomplete_journal_update(operation)
        journal_path = operation / JOURNAL_NAME
        if not journal_path.exists() and not journal_path.is_symlink():
            if (
                _bridge_worker_containers(args.project)
                or _bridge_verifier_containers(args.project)
            ):
                raise ComposeProcessingError(
                    "BRIDGE_RECOVERY_UNSAFE",
                    "journal-free recovery found an unexpected bridge container",
                )
            _remove_operation_directory(operation)
            operation_cleared = True
            return {"status": "no_effect_recovered"}
        journal = _load_operation_journal(operation)
        if journal["project"] != args.project:
            raise ComposeProcessingError(
                "BRIDGE_JOURNAL_INVALID",
                "operation journal project differs",
            )
        if (
            journal["original_repository_root"]
            != str(ORIGINAL_REPOSITORY_ROOT)
        ):
            raise ComposeProcessingError(
                "BRIDGE_PROVENANCE_MISMATCH",
                "recovery repository root differs from its journal",
            )
        compose_snapshot = operation / "resolved-compose.json"
        compose_payload = _read_bounded_file(
            compose_snapshot,
            MAX_COMPOSE_BYTES,
            "recovery Compose snapshot",
        )
        if (
            "sha256:" + hashlib.sha256(compose_payload).hexdigest()
            != journal["compose_digest"]
        ):
            raise ComposeProcessingError(
                "BRIDGE_JOURNAL_INVALID",
                "recovery Compose snapshot differs from its journal",
            )
        compose = _parse_json(compose_payload, "recovery Compose snapshot")
        if not isinstance(compose, dict):
            raise ComposeProcessingError(
                "BRIDGE_COMPOSE_INVALID",
                "recovery Compose snapshot must be an object",
            )
        _require_mount_identity(
            args.config_file,
            "public config",
            journal["config_identity"],
        )
        _require_mount_identity(
            args.admin_secret_file,
            "administrator secret",
            journal["secret_identity"],
        )
        preflight = deployment_preflight(
            args.config_file,
            args.admin_secret_file,
            compose,
            require_immutable_image=not args.allow_mutable_image,
            check_state=False,
            expected_repository_root=ORIGINAL_REPOSITORY_ROOT,
            expected_published_port=args.expected_published_port,
        )
        published_port = preflight["compose"]["published_port"]
        state_volume, configured_image = _resolve_deployment(
            compose,
            project=args.project,
        )
        if (
            state_volume != journal["state_volume"]
            or configured_image != journal["configured_image"]
        ):
            raise ComposeProcessingError(
                "BRIDGE_DEPLOYMENT_CHANGED",
                "recovery deployment differs from its journal",
            )
        if (
            _verify_host_bundle_matches_image(journal["image_id"])
            != journal["host_bundle_digest"]
        ):
            raise ComposeProcessingError(
                "BRIDGE_PROVENANCE_MISMATCH",
                "recovery host source differs from its journal",
            )
        compose_prefix = _compose_prefix(args.project, compose_snapshot)
        backend_id = _single_identifier(
            _docker(
                [*compose_prefix, "ps", "--no-trunc", "-aq", "backend"]
            ).stdout,
            "backend",
        )
        if backend_id != journal["backend_container_id"]:
            raise ComposeProcessingError(
                "BRIDGE_DEPLOYMENT_CHANGED",
                "recovery backend identity differs from its journal",
            )
        inspected_backend = _inspect_container(backend_id)
        backend_state = inspected_backend.get("State")
        backend_status = (
            backend_state.get("Status")
            if isinstance(backend_state, dict)
            else None
        )
        if backend_status not in {"running", "exited"}:
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "recovery backend state is not restartable",
            )
        _inspect_backend(
            container_id=backend_id,
            project=args.project,
            state_volume=state_volume,
            expected_status=backend_status,
            expected_image_id=journal["image_id"],
            expected_config_image=configured_image,
        )

        journal = _retire_recovery_worker(
            operation=operation,
            journal=journal,
            project=args.project,
            image_id=journal["image_id"],
            state_volume=state_volume,
        )
        journal = _retire_recovery_verifier(
            operation=operation,
            journal=journal,
            project=args.project,
            image_id=journal["image_id"],
            state_volume=state_volume,
            config_file=args.config_file,
        )

        if (
            (
                journal["phase"] == "backend_healthy"
                or not journal["worker_started"]
            )
            and backend_status == "running"
            and _volume_consumers(state_volume) == {backend_id}
        ):
            _inspect_backend(
                container_id=backend_id,
                project=args.project,
                state_volume=state_volume,
                expected_status="running",
                expected_image_id=journal["image_id"],
                expected_config_image=configured_image,
                require_healthy=True,
            )
            _require_mount_identity(
                args.config_file,
                "public config",
                journal["config_identity"],
            )
            _require_mount_identity(
                args.admin_secret_file,
                "administrator secret",
                journal["secret_identity"],
            )
            _smoke_restarted_backend(
                args.config_file,
                args.admin_secret_file,
                published_port,
            )
            _remove_operation_directory(operation)
            operation_cleared = True
            return {"status": "recovered"}

        if backend_status == "running":
            _require_snapshot_digest(
                compose_snapshot,
                MAX_COMPOSE_BYTES,
                "recovery Compose snapshot",
                journal["compose_digest"],
            )
            _docker([*compose_prefix, "stop", "backend"], timeout=60)
            _inspect_backend(
                container_id=backend_id,
                project=args.project,
                state_volume=state_volume,
                expected_status="exited",
                expected_image_id=journal["image_id"],
                expected_config_image=configured_image,
            )
        _retire_orphaned_broker_socket(
            operation / "processing-bridge.sock"
        )
        if _volume_consumers(state_volume) != {backend_id}:
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_UNSAFE",
                "backend is not the sole recovery state-volume consumer",
            )
        if journal["worker_started"]:
            journal = _journaled_verify_state(
                operation=operation,
                journal=journal,
                purpose="recovery",
                final_phase="state_verified",
                project=args.project,
                image_id=journal["image_id"],
                state_volume=state_volume,
                config_file=args.config_file,
                baseline_state_verified=True,
                state_verified_after_worker=True,
            )
        _require_snapshot_digest(
            compose_snapshot,
            MAX_COMPOSE_BYTES,
            "recovery Compose snapshot",
            journal["compose_digest"],
        )
        _docker([*compose_prefix, "start", "backend"], timeout=60)
        _wait_backend_healthy(
            backend_id,
            journal["image_id"],
            configured_image,
            state_volume,
            args.project,
        )
        _smoke_restarted_backend(
            args.config_file,
            args.admin_secret_file,
            published_port,
        )
        _require_mount_identity(
            args.config_file,
            "public config",
            journal["config_identity"],
        )
        _require_mount_identity(
            args.admin_secret_file,
            "administrator secret",
            journal["secret_identity"],
        )
        if journal["baseline_state_verified"]:
            _advance_operation_journal(
                operation,
                journal,
                "backend_healthy",
            )
        _remove_operation_directory(operation)
        operation_cleared = True
        return {"status": "recovered"}
    finally:
        try:
            _release_host_lock(lock_descriptor)
        except Exception as error:
            if not operation_cleared:
                raise ComposeProcessingError(
                    "BRIDGE_CLEANUP_FAILED",
                    "Compose processing lock cleanup did not complete",
                ) from error


def run_compose_processing(args: argparse.Namespace) -> dict[str, Any]:
    if (
        PROJECT.fullmatch(args.project) is None
        or ID.fullmatch(args.worker_id) is None
        or args.adapter_contract not in ADAPTER_CONTRACTS
        or isinstance(args.max_stages, bool)
        or not 1 <= args.max_stages <= MAX_DRAIN_STAGES
    ):
        raise ComposeProcessingError(
            "BRIDGE_INPUT_INVALID",
            "project, worker, contract, or stage bound is invalid",
        )
    bootstrap = (
        _VERIFIED_SOURCE_CONTEXT
        if _VERIFIED_SOURCE_CONTEXT is not None
        and _VERIFIED_SOURCE_CONTEXT["mode"] == "run"
        else None
    )
    lock_descriptor = (
        int(bootstrap["lock_descriptor"])
        if bootstrap is not None
        else _acquire_host_lock(args.project)
    )
    backend_was_running = False
    backend_stopped = False
    baseline_state_verified = False
    worker_started = False
    state_verified_after_worker = False
    backend_container_id: str | None = None
    worker_container_id: str | None = None
    broker: subprocess.Popen[bytes] | None = None
    operation: Path | None = (
        Path(bootstrap["operation"]) if bootstrap is not None else None
    )
    journal: dict[str, Any] | None = None
    compose_prefix: list[str] = []
    image_id = ""
    configured_image = ""
    state_volume = ""
    compose_digest = ""
    published_port = ""
    config_identity: dict[str, Any] = {}
    secret_identity: dict[str, Any] = {}
    summary: dict[str, Any] | None = None
    pre_journal_stage = "COMPOSE_READ"
    try:
        compose_payload = _read_bounded_file(
            args.compose_json,
            MAX_COMPOSE_BYTES,
            "resolved Compose model",
        )
        compose = _parse_json(compose_payload, "resolved Compose model")
        if not isinstance(compose, dict):
            raise ComposeProcessingError(
                "BRIDGE_COMPOSE_INVALID",
                "resolved Compose model must be an object",
            )
        pre_journal_stage = "DEPLOYMENT_PREFLIGHT"
        preflight = deployment_preflight(
            args.config_file,
            args.admin_secret_file,
            compose,
            require_immutable_image=not args.allow_mutable_image,
            check_state=False,
            expected_repository_root=ORIGINAL_REPOSITORY_ROOT,
            expected_published_port=args.expected_published_port,
        )
        published_port = preflight["compose"]["published_port"]
        # Fail before stopping service availability when the private
        # processor selection or model file is malformed.
        pre_journal_stage = "PROCESSOR_COMMAND"
        selected_command = RUNNER.load_command(args.isolated_command_file)
        pre_journal_stage = "RUNTIME_PREFLIGHT"
        RUNNER.validate_runtime_environment(
            time.monotonic() + DOCKER_COMMAND_TIMEOUT_SECONDS
        )
        pre_journal_stage = "DESCRIPTOR_PREFLIGHT"
        _prepare_broker_descriptor_limit()
        pre_journal_stage = "DEPLOYMENT_RESOLUTION"
        state_volume, configured_image = _resolve_deployment(
            compose,
            project=args.project,
        )
        pre_journal_stage = "OPERATION_SNAPSHOT"
        if operation is None:
            operation = _create_operation_directory(
                args.operation_directory,
                args.project,
            )
        elif operation != _operation_path(
            args.operation_directory,
            args.project,
        ):
            raise ComposeProcessingError(
                "BRIDGE_OPERATION_DIRECTORY_INVALID",
                "operation differs from its verified bootstrap",
            )
        compose_snapshot = operation / "resolved-compose.json"
        _write_private_snapshot(compose_snapshot, compose_payload, 0o400)
        isolated_command_snapshot = operation / "isolated-command.json"
        isolated_command_payload = canonical_json(selected_command)
        isolated_command_digest = (
            "sha256:" + hashlib.sha256(isolated_command_payload).hexdigest()
        )
        _write_private_snapshot(
            isolated_command_snapshot,
            isolated_command_payload,
            0o600,
        )
        pre_journal_stage = "BACKEND_RESOLUTION"
        compose_prefix = _compose_prefix(args.project, compose_snapshot)
        backend_container_id = _single_identifier(
            _docker([*compose_prefix, "ps", "--no-trunc", "-aq", "backend"]).stdout,
            "backend",
        )
        pre_journal_stage = "BACKEND_INSPECTION"
        image_id = _inspect_backend(
            container_id=backend_container_id,
            project=args.project,
            state_volume=state_volume,
            expected_status="running",
            expected_config_image=configured_image,
            require_healthy=True,
        )
        backend_was_running = True
        pre_journal_stage = "SOURCE_PROVENANCE"
        host_bundle_digest = _verify_host_bundle_matches_image(image_id)
        pre_journal_stage = "MOUNT_IDENTITY"
        config_identity = _regular_mount_identity(
            args.config_file,
            "public config",
        )
        secret_identity = _regular_mount_identity(
            args.admin_secret_file,
            "administrator secret",
        )
        pre_journal_stage = "VOLUME_OWNERSHIP"
        if _volume_consumers(state_volume) != {backend_container_id}:
            raise ComposeProcessingError(
                "BRIDGE_DEPLOYMENT_CHANGED",
                "another container references the Tacua state volume",
            )
        pre_journal_stage = "VERIFIER_CAPACITY"
        _preflight_state_verifier_capacity(backend_container_id)
        pre_journal_stage = "JOURNAL_PUBLICATION"
        journal = _write_operation_journal(
            operation,
            {
                "adapter_contract": args.adapter_contract,
                "backend_container_id": backend_container_id,
                "baseline_state_verified": False,
                "compose_digest": (
                    "sha256:" + hashlib.sha256(compose_payload).hexdigest()
                ),
                "config_identity": config_identity,
                "configured_image": configured_image,
                "contract_version": OPERATION_CONTRACT,
                "host_bundle_digest": host_bundle_digest,
                "image_id": image_id,
                "isolated_command_digest": isolated_command_digest,
                "max_stages": args.max_stages,
                "original_repository_root": str(ORIGINAL_REPOSITORY_ROOT),
                "phase": "prepared",
                "project": args.project,
                "run_once": args.run_once,
                "secret_identity": secret_identity,
                "state_verified_after_worker": False,
                "state_volume": state_volume,
                "verifier_container_id": None,
                "verifier_name": None,
                "worker_container_id": None,
                "worker_id": args.worker_id,
                "worker_name": None,
                "worker_started": False,
            },
        )
        compose_digest = journal["compose_digest"]
        _require_snapshot_digest(
            compose_snapshot,
            MAX_COMPOSE_BYTES,
            "resolved Compose snapshot",
            compose_digest,
        )
        backend_stopped = True
        _docker([*compose_prefix, "stop", "backend"], timeout=60)
        _inspect_backend(
            container_id=backend_container_id,
            project=args.project,
            state_volume=state_volume,
            expected_status="exited",
            expected_image_id=image_id,
            expected_config_image=configured_image,
        )
        journal = _advance_operation_journal(
            operation,
            journal,
            "backend_stopped",
        )
        journal = _journaled_verify_state(
            operation=operation,
            journal=journal,
            purpose="baseline",
            final_phase="baseline_verified",
            project=args.project,
            image_id=image_id,
            state_volume=state_volume,
            config_file=args.config_file,
            baseline_state_verified=True,
        )
        baseline_state_verified = True
        if _volume_consumers(state_volume) != {backend_container_id}:
            raise ComposeProcessingError(
                "BRIDGE_DEPLOYMENT_CHANGED",
                "state-volume consumer set changed after backend stop",
            )

        command_file = operation / "processing-command.json"
        socket_path = operation / "processing-bridge.sock"
        _write_outer_command(command_file, args.adapter_contract)
        broker = _broker_process(
            socket_path,
            isolated_command_snapshot,
            isolated_command_digest,
            1 if args.run_once else args.max_stages,
        )
        worker_name = (
            f"tacua-processing-{os.getpid()}-{secrets.token_hex(6)}"
        )
        _require_mount_identity(
            args.config_file,
            "public config",
            config_identity,
        )
        _require_mount_identity(
            args.admin_secret_file,
            "administrator secret",
            secret_identity,
        )
        worker_create = _worker_create_argv(
            name=worker_name,
            project=args.project,
            image_id=image_id,
            state_volume=state_volume,
            config_file=args.config_file,
            admin_secret_file=args.admin_secret_file,
            command_file=command_file,
            socket_path=socket_path,
            worker_id=args.worker_id,
            run_once=args.run_once,
            max_stages=args.max_stages,
        )
        worker_attempt = _prepare_container_create(
            operation=operation,
            argv=worker_create,
            project=args.project,
            role=BRIDGE_WORKER_ROLE,
            purpose="worker",
            name=worker_name,
        )
        try:
            journal = _advance_operation_journal(
                operation,
                journal,
                "worker_creating",
                worker_name=worker_name,
            )
        except BaseException:
            _finish_container_create(
                operation,
                worker_attempt,
                start=False,
            )
            raise
        worker_receipt = _finish_container_create(
            operation,
            worker_attempt,
            start=True,
        )
        if worker_receipt["outcome"] != "created":
            raise ComposeProcessingError(
                "BRIDGE_DOCKER_FAILED",
                "one-shot worker creation was indeterminate",
            )
        worker_container_id = str(worker_receipt["container_id"])
        journal = _advance_operation_journal(
            operation,
            journal,
            "worker_created",
            worker_container_id=worker_container_id,
        )
        _clear_create_receipt(operation)
        _require_mount_identity(
            args.config_file,
            "public config",
            config_identity,
        )
        _require_mount_identity(
            args.admin_secret_file,
            "administrator secret",
            secret_identity,
        )
        expected_bind_sources = {
            CONFIG_IN_CONTAINER: config_identity["path"],
            SECRET_IN_CONTAINER: secret_identity["path"],
            BRIDGE_COMMAND_IN_CONTAINER: str(command_file),
            BRIDGE_SOCKET_IN_CONTAINER: str(socket_path),
        }
        _inspect_worker(
            worker_container_id,
            name=worker_name,
            project=args.project,
            image_id=image_id,
            state_volume=state_volume,
            expected_status="created",
            expected_command=_worker_command_argv(
                worker_id=args.worker_id,
                run_once=args.run_once,
                max_stages=args.max_stages,
            ),
            expected_bind_sources=expected_bind_sources,
        )
        if _volume_consumers(state_volume) != {
            backend_container_id,
            worker_container_id,
        }:
            raise ComposeProcessingError(
                "BRIDGE_DEPLOYMENT_CHANGED",
                "state-volume consumer set changed before processing",
            )
        stage_limit = 1 if args.run_once else args.max_stages
        worker_started = True
        journal = _advance_operation_journal(
            operation,
            journal,
            "worker_starting",
            worker_started=True,
        )
        summary = _run_created_worker(
            worker_container_id,
            stage_limit=stage_limit,
            expected_mode="run_once" if args.run_once else "drain",
        )
        journal = _advance_operation_journal(
            operation,
            journal,
            "worker_exited",
        )
        _inspect_worker(
            worker_container_id,
            name=worker_name,
            project=args.project,
            image_id=image_id,
            state_volume=state_volume,
            expected_status="exited",
            expected_command=_worker_command_argv(
                worker_id=args.worker_id,
                run_once=args.run_once,
                max_stages=args.max_stages,
            ),
            expected_bind_sources=expected_bind_sources,
        )
        _remove_worker(worker_container_id)
        worker_container_id = None
        journal = _advance_operation_journal(
            operation,
            journal,
            "worker_exited",
            worker_container_id=None,
            worker_name=None,
        )
        _stop_broker(broker)
        broker = None
        if _volume_consumers(state_volume) != {backend_container_id}:
            raise ComposeProcessingError(
                "BRIDGE_DEPLOYMENT_CHANGED",
                "one-shot worker did not release the state volume",
            )
        journal = _journaled_verify_state(
            operation=operation,
            journal=journal,
            purpose="post_worker",
            final_phase="state_verified",
            project=args.project,
            image_id=image_id,
            state_volume=state_volume,
            config_file=args.config_file,
            state_verified_after_worker=True,
        )
        state_verified_after_worker = True
        _require_snapshot_digest(
            compose_snapshot,
            MAX_COMPOSE_BYTES,
            "resolved Compose snapshot",
            compose_digest,
        )
        _docker([*compose_prefix, "start", "backend"], timeout=60)
        _wait_backend_healthy(
            backend_container_id,
            image_id,
            configured_image,
            state_volume,
            args.project,
        )
        _smoke_restarted_backend(
            args.config_file,
            args.admin_secret_file,
            published_port,
        )
        _require_mount_identity(
            args.config_file,
            "public config",
            config_identity,
        )
        _require_mount_identity(
            args.admin_secret_file,
            "administrator secret",
            secret_identity,
        )
        journal = _advance_operation_journal(
            operation,
            journal,
            "backend_healthy",
        )
        backend_stopped = False
        assert summary is not None
        return {
            "claim_retries": summary["claim_retries"],
            "mode": summary["mode"],
            "processed_stages": summary["processed_stages"],
            "queue_empty": summary["queue_empty"],
            "stage_limit_reached": summary["stage_limit_reached"],
            "status": "ok",
        }
    except (ConfigError, OperatorError, OSError, ValueError) as error:
        raise ComposeProcessingError(
            (
                "BRIDGE_OPERATION_FAILED"
                if journal is not None
                else f"BRIDGE_{pre_journal_stage}_FAILED"
            ),
            "Compose processing operation failed safely",
        ) from error
    finally:
        cleanup_failed = False
        try:
            _stop_broker(broker)
        except Exception:
            cleanup_failed = True
        try:
            _remove_worker(worker_container_id)
            worker_container_id = None
        except Exception:
            cleanup_failed = True
        recovery_failed = False
        if (
            backend_was_running
            and backend_stopped
            and backend_container_id is not None
            and compose_prefix
            and operation is not None
            and journal is not None
        ):
            if cleanup_failed:
                recovery_failed = True
            else:
                try:
                    journal = _recover_backend(
                        operation=operation,
                        journal=journal,
                        backend_container_id=backend_container_id,
                        image_id=image_id,
                        configured_image=configured_image,
                        state_volume=state_volume,
                        project=args.project,
                        compose_prefix=compose_prefix,
                        compose_snapshot=Path(compose_prefix[-1]),
                        compose_digest=compose_digest,
                        published_port=published_port,
                        config_file=args.config_file,
                        admin_secret_file=args.admin_secret_file,
                        config_identity=config_identity,
                        secret_identity=secret_identity,
                    )
                    backend_stopped = False
                    if (
                        operation is not None
                        and journal is not None
                        and journal["baseline_state_verified"]
                    ):
                        journal = _advance_operation_journal(
                            operation,
                            journal,
                            "backend_healthy",
                            state_verified_after_worker=(
                                state_verified_after_worker
                                or worker_started
                            ),
                        )
                except Exception:
                    recovery_failed = True
        if (
            operation is not None
            and not backend_stopped
            and not recovery_failed
            and not cleanup_failed
        ):
            try:
                _remove_operation_directory(operation)
                operation = None
            except Exception:
                cleanup_failed = True
        try:
            _release_host_lock(lock_descriptor)
        except Exception:
            if operation is not None:
                cleanup_failed = True
        if recovery_failed:
            raise ComposeProcessingError(
                "BRIDGE_RECOVERY_FAILED",
                "automatic backend recovery did not complete safely",
            )
        if cleanup_failed:
            raise ComposeProcessingError(
                "BRIDGE_CLEANUP_FAILED",
                "Compose processing cleanup did not complete safely",
            )


def _parser() -> argparse.ArgumentParser:
    parser = _BridgeArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--compose-json", type=Path, required=True)
    parser.add_argument("--operation-directory", type=Path, required=True)
    parser.add_argument("--config-file", type=Path, required=True)
    parser.add_argument("--admin-secret-file", type=Path, required=True)
    parser.add_argument("--isolated-command-file", type=Path, required=True)
    parser.add_argument("--worker-id", default="worker_compose_isolated")
    parser.add_argument(
        "--adapter-contract",
        choices=sorted(ADAPTER_CONTRACTS),
        default="tacua.local-processing-command@1.0.0",
    )
    parser.add_argument("--allow-mutable-image", action="store_true")
    parser.add_argument("--expected-published-port", type=int)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run-once", action="store_true")
    mode.add_argument("--drain", action="store_true")
    parser.add_argument("--max-stages", type=int, default=100)
    return parser


def _recovery_parser() -> argparse.ArgumentParser:
    parser = _BridgeArgumentParser(
        description="Recover one interrupted Compose processing operation."
    )
    parser.add_argument("--project", required=True)
    parser.add_argument("--operation-directory", type=Path, required=True)
    parser.add_argument("--config-file", type=Path, required=True)
    parser.add_argument("--admin-secret-file", type=Path, required=True)
    parser.add_argument("--allow-mutable-image", action="store_true")
    parser.add_argument("--expected-published-port", type=int)
    return parser


def _broker_parser() -> argparse.ArgumentParser:
    parser = _BridgeArgumentParser(add_help=False)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--isolated-command-file", type=Path, required=True)
    parser.add_argument("--isolated-command-digest", required=True)
    parser.add_argument("--max-requests", type=int, required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    return parser


def _run_with_cancellation(
    operation: Any,
    args: argparse.Namespace,
) -> dict[str, Any]:
    previous: dict[signal.Signals, Any] = {}

    def cancel(_signum: int, _frame: Any) -> None:
        for watched, handler in previous.items():
            signal.signal(watched, handler)
        raise ComposeProcessingError(
            "BRIDGE_CANCELLED",
            "Compose processing was cancelled and recovery was attempted",
        )

    original = (
        _VERIFIED_SOURCE_CONTEXT.get("original_signal_handlers")
        if _VERIFIED_SOURCE_CONTEXT is not None
        else None
    )
    for watched in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous[watched] = (
            original[watched]
            if isinstance(original, dict) and watched in original
            else signal.getsignal(watched)
        )
        signal.signal(watched, cancel)
    try:
        return operation(args)
    finally:
        for watched, handler in previous.items():
            signal.signal(watched, handler)


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if arguments[:1] == ["_broker"]:
            broker_args = _broker_parser().parse_args(arguments[1:])
            return run_broker(
                broker_args.socket,
                broker_args.isolated_command_file,
                broker_args.isolated_command_digest,
                broker_args.max_requests,
                broker_args.parent_pid,
            )
        if arguments[:1] == ["recover"]:
            parser = _recovery_parser()
            args = parser.parse_args(arguments[1:])
            operation = recover_compose_processing
        else:
            parser = _parser()
            args = parser.parse_args(arguments)
            operation = run_compose_processing
        result = _run_with_cancellation(operation, args)
    except (ComposeProcessingError, ProcessingBridgeError) as error:
        code = error.code
        print(code, file=sys.stderr)
        return 1
    except Exception:
        print(
            (
                f"BRIDGE_BROKER_{_BROKER_FAILURE_STAGE}_FAILED"
                if arguments[:1] == ["_broker"]
                else "BRIDGE_OPERATION_FAILED"
            ),
            file=sys.stderr,
        )
        return 1
    print(canonical_json(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
