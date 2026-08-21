#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed scanner and permission sealer for private XCTest results.

This tool deliberately treats a clean scan as exit status 41, a detected
runtime-value leak as 40, and every inability to prove cleanliness as 42.
Callers must never mistake an ordinary Python failure status for clean output.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import os
import re
import stat
import sys
from collections.abc import Iterable, Sequence


class Status(enum.IntEnum):
    LEAK = 40
    CLEAN = 41
    ERROR = 42


CHUNK_SIZE = 1024 * 1024
MAX_LITERAL_BYTES = 4096
MAX_PATTERN_BYTES = 8192
DEFAULT_PATTERNS = (
    re.compile(rb"launch_code=[A-Za-z0-9_-]{1,4096}"),
    re.compile(
        rb"TACUA_XCUITEST_LAUNCH_URL[ \t]*[=:][ \t]*[^\x00\r\n ]{1,4096}"
    ),
)
DIRECTORY_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW


@dataclasses.dataclass(frozen=True)
class Fingerprint:
    device: int
    inode: int
    mode: int
    links: int
    owner: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclasses.dataclass(frozen=True)
class ScanResult:
    status: Status
    snapshot: dict[tuple[bytes, ...], Fingerprint]


def _fingerprint(metadata: os.stat_result) -> Fingerprint:
    return Fingerprint(
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class ForbiddenMatcher:
    def __init__(self, literal_values: Iterable[bytes]) -> None:
        normalized: list[bytes] = []
        for value in literal_values:
            if not value or len(value) > MAX_LITERAL_BYTES:
                raise ValueError("forbidden values must contain 1 through 4096 bytes")
            normalized.append(value)
        self._literal_values = tuple(sorted(set(normalized), key=len, reverse=True))
        self._overlap = max(
            [MAX_PATTERN_BYTES, *(len(value) - 1 for value in self._literal_values)]
        )

    def matches(self, value: bytes) -> bool:
        return any(pattern.search(value) for pattern in DEFAULT_PATTERNS) or any(
            literal in value for literal in self._literal_values
        )

    @property
    def overlap(self) -> int:
        return self._overlap


def _validate_absolute_path(path: str, *, expected_suffix: str | None = None) -> bool:
    if not path or not os.path.isabs(path):
        return False
    if os.path.normpath(path) != path:
        return False
    if os.path.realpath(path) != path:
        return False
    if expected_suffix is not None and not os.path.basename(path).endswith(
        expected_suffix
    ):
        return False
    return True


def load_forbidden_values(paths: Sequence[str]) -> tuple[bytes, ...]:
    values: list[bytes] = []
    for path in paths:
        if not _validate_absolute_path(path):
            raise ValueError("forbidden-value paths must be absolute and symlink-free")
        metadata = os.lstat(path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size < 1
            or metadata.st_size > 65_536
        ):
            raise ValueError("forbidden-value files must be owner-private regular files")
        descriptor = os.open(path, FILE_FLAGS)
        try:
            opened = os.fstat(descriptor)
            if _fingerprint(opened) != _fingerprint(metadata):
                raise ValueError("forbidden-value file changed while opening")
            payload = bytearray()
            while True:
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > 65_536:
                    raise ValueError("forbidden-value file is too large")
            if _fingerprint(os.fstat(descriptor)) != _fingerprint(opened):
                raise ValueError("forbidden-value file changed while reading")
        finally:
            os.close(descriptor)
        for line in bytes(payload).splitlines():
            if not line:
                raise ValueError("forbidden-value files may not contain blank lines")
            if len(line) > MAX_LITERAL_BYTES:
                raise ValueError("a forbidden runtime value is too large")
            values.append(line)
    if not values:
        raise ValueError("at least one forbidden runtime value is required")
    return tuple(values)


def _scan_regular_file(descriptor: int, matcher: ForbiddenMatcher) -> Status:
    tail = b""
    while True:
        chunk = os.read(descriptor, CHUNK_SIZE)
        if not chunk:
            return Status.CLEAN
        window = tail + chunk
        if matcher.matches(window):
            return Status.LEAK
        tail = window[-matcher.overlap :]


def _scan_directory(
    descriptor: int,
    initial_metadata: os.stat_result,
    relative_path: tuple[bytes, ...],
    matcher: ForbiddenMatcher,
    seen_directories: set[tuple[int, int]],
    snapshot: dict[tuple[bytes, ...], Fingerprint],
    require_sealed_modes: bool,
) -> tuple[Status, int]:
    identity = (initial_metadata.st_dev, initial_metadata.st_ino)
    if identity in seen_directories:
        return Status.ERROR, 0
    seen_directories.add(identity)

    if initial_metadata.st_uid != os.getuid():
        return Status.ERROR, 0
    if require_sealed_modes and stat.S_IMODE(initial_metadata.st_mode) != 0o700:
        return Status.ERROR, 0
    snapshot[relative_path] = _fingerprint(initial_metadata)

    regular_file_count = 0
    with os.scandir(descriptor) as iterator:
        entries = [
            (entry.name, entry.stat(follow_symlinks=False)) for entry in iterator
        ]
    for entry_name, entry_metadata in entries:
        name = os.fsencode(entry_name)
        if not name or name in (b".", b"..") or b"/" in name or matcher.matches(name):
            return (
                Status.LEAK if matcher.matches(name) else Status.ERROR,
                regular_file_count,
            )
        child_path = (*relative_path, name)
        entry_mode = entry_metadata.st_mode
        if entry_metadata.st_uid != os.getuid():
            return Status.ERROR, regular_file_count

        if stat.S_ISLNK(entry_mode):
            return Status.ERROR, regular_file_count

        if stat.S_ISDIR(entry_mode):
            child_descriptor = os.open(
                entry_name,
                DIRECTORY_FLAGS,
                dir_fd=descriptor,
            )
            try:
                opened_metadata = os.fstat(child_descriptor)
                if (
                    not stat.S_ISDIR(opened_metadata.st_mode)
                    or _fingerprint(opened_metadata) != _fingerprint(entry_metadata)
                ):
                    return Status.ERROR, regular_file_count
                status_value, child_count = _scan_directory(
                    child_descriptor,
                    opened_metadata,
                    child_path,
                    matcher,
                    seen_directories,
                    snapshot,
                    require_sealed_modes,
                )
                regular_file_count += child_count
                if status_value != Status.CLEAN:
                    return status_value, regular_file_count
                if _fingerprint(os.fstat(child_descriptor)) != _fingerprint(
                    opened_metadata
                ):
                    return Status.ERROR, regular_file_count
            finally:
                os.close(child_descriptor)
            continue

        if not stat.S_ISREG(entry_mode) or entry_metadata.st_nlink != 1:
            return Status.ERROR, regular_file_count
        if require_sealed_modes and stat.S_IMODE(entry_mode) != 0o600:
            return Status.ERROR, regular_file_count

        file_descriptor = os.open(entry_name, FILE_FLAGS, dir_fd=descriptor)
        try:
            opened_metadata = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(opened_metadata.st_mode)
                or opened_metadata.st_nlink != 1
                or _fingerprint(opened_metadata) != _fingerprint(entry_metadata)
            ):
                return Status.ERROR, regular_file_count
            status_value = _scan_regular_file(file_descriptor, matcher)
            regular_file_count += 1
            if status_value != Status.CLEAN:
                return status_value, regular_file_count
            if _fingerprint(os.fstat(file_descriptor)) != _fingerprint(
                opened_metadata
            ):
                return Status.ERROR, regular_file_count
            snapshot[child_path] = _fingerprint(opened_metadata)
        finally:
            os.close(file_descriptor)

    if _fingerprint(os.fstat(descriptor)) != _fingerprint(initial_metadata):
        return Status.ERROR, regular_file_count
    return Status.CLEAN, regular_file_count


def scan_result(
    root: str,
    matcher: ForbiddenMatcher,
    *,
    require_sealed_modes: bool = False,
) -> ScanResult:
    snapshot: dict[tuple[bytes, ...], Fingerprint] = {}
    try:
        if not _validate_absolute_path(root, expected_suffix=".xcresult"):
            return ScanResult(Status.ERROR, snapshot)
        if matcher.matches(os.fsencode(os.path.basename(root))):
            return ScanResult(Status.LEAK, snapshot)
        path_metadata = os.lstat(root)
        if not stat.S_ISDIR(path_metadata.st_mode) or path_metadata.st_uid != os.getuid():
            return ScanResult(Status.ERROR, snapshot)

        root_descriptor = os.open(root, DIRECTORY_FLAGS)
        try:
            opened_metadata = os.fstat(root_descriptor)
            if (
                not stat.S_ISDIR(opened_metadata.st_mode)
                or _fingerprint(opened_metadata) != _fingerprint(path_metadata)
            ):
                return ScanResult(Status.ERROR, snapshot)
            status_value, regular_file_count = _scan_directory(
                root_descriptor,
                opened_metadata,
                (),
                matcher,
                set(),
                snapshot,
                require_sealed_modes,
            )
            if status_value != Status.CLEAN:
                return ScanResult(status_value, snapshot)
            final_path_metadata = os.lstat(root)
            final_descriptor_metadata = os.fstat(root_descriptor)
            if (
                _fingerprint(final_path_metadata) != _fingerprint(path_metadata)
                or _fingerprint(final_descriptor_metadata)
                != _fingerprint(opened_metadata)
                or _fingerprint(final_path_metadata)
                != _fingerprint(final_descriptor_metadata)
                or regular_file_count == 0
            ):
                return ScanResult(Status.ERROR, snapshot)
            return ScanResult(Status.CLEAN, snapshot)
        finally:
            os.close(root_descriptor)
    except BaseException:
        return ScanResult(Status.ERROR, snapshot)


def _seal_directory(
    descriptor: int,
    relative_path: tuple[bytes, ...],
    snapshot: dict[tuple[bytes, ...], Fingerprint],
    visited: set[tuple[bytes, ...]],
) -> bool:
    initial = os.fstat(descriptor)
    if snapshot.get(relative_path) != _fingerprint(initial):
        return False
    visited.add(relative_path)

    with os.scandir(descriptor) as iterator:
        entries = [
            (entry.name, entry.stat(follow_symlinks=False)) for entry in iterator
        ]
    for entry_name, metadata in entries:
        name = os.fsencode(entry_name)
        if not name or name in (b".", b"..") or b"/" in name:
            return False
        child_path = (*relative_path, name)
        expected = snapshot.get(child_path)
        if expected is None:
            return False
        if _fingerprint(metadata) != expected:
            return False

        if stat.S_ISDIR(metadata.st_mode):
            child_descriptor = os.open(
                entry_name,
                DIRECTORY_FLAGS,
                dir_fd=descriptor,
            )
            try:
                if not _seal_directory(
                    child_descriptor,
                    child_path,
                    snapshot,
                    visited,
                ):
                    return False
            finally:
                os.close(child_descriptor)
            continue

        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            return False
        file_descriptor = os.open(entry_name, FILE_FLAGS, dir_fd=descriptor)
        try:
            if _fingerprint(os.fstat(file_descriptor)) != expected:
                return False
            os.fchmod(file_descriptor, 0o600)
            if stat.S_IMODE(os.fstat(file_descriptor).st_mode) != 0o600:
                return False
            visited.add(child_path)
        finally:
            os.close(file_descriptor)

    os.fchmod(descriptor, 0o700)
    return stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o700


def seal_result(root: str, matcher: ForbiddenMatcher) -> Status:
    first_scan = scan_result(root, matcher)
    if first_scan.status != Status.CLEAN:
        return first_scan.status
    try:
        root_descriptor = os.open(root, DIRECTORY_FLAGS)
        try:
            visited: set[tuple[bytes, ...]] = set()
            if not _seal_directory(
                root_descriptor,
                (),
                first_scan.snapshot,
                visited,
            ):
                return Status.ERROR
            if visited != set(first_scan.snapshot):
                return Status.ERROR
        finally:
            os.close(root_descriptor)
    except BaseException:
        return Status.ERROR

    verification = scan_result(root, matcher, require_sealed_modes=True)
    return verification.status


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan and optionally permission-seal one private XCTest result"
    )
    parser.add_argument("operation", choices=("scan", "seal"))
    parser.add_argument("result", help="Absolute, symlink-free .xcresult path")
    parser.add_argument(
        "--forbidden-values-file",
        action="append",
        default=[],
        required=True,
        help="Owner-private newline-delimited exact runtime values (repeatable)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        args = _parse_args(raw_arguments)
    except SystemExit as error:
        if error.code == 0 and raw_arguments in (["--help"], ["-h"]):
            return 0
        print("xcresult-safety=unprovable", file=sys.stderr)
        return int(Status.ERROR)

    try:
        values = load_forbidden_values(args.forbidden_values_file)
        matcher = ForbiddenMatcher(values)
        status_value = (
            scan_result(args.result, matcher).status
            if args.operation == "scan"
            else seal_result(args.result, matcher)
        )
    except Exception:
        status_value = Status.ERROR

    if status_value == Status.CLEAN:
        print(
            "xcresult-safety=sealed"
            if args.operation == "seal"
            else "xcresult-safety=clean"
        )
    elif status_value == Status.LEAK:
        print("xcresult-safety=runtime-value-leak", file=sys.stderr)
    else:
        print("xcresult-safety=unprovable", file=sys.stderr)
    return int(status_value)


if __name__ == "__main__":
    raise SystemExit(main())
