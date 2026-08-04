#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Durable exact unit-bundle artifacts for reviewer upgrade recovery.

Preparation writes six immutable direct children of one already-created
transaction directory.  The returned JSON descriptors become authoritative
only after the caller embeds them in the immutable transaction plan.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any, Iterator, NoReturn

if __package__:
    from .reviewer_upgrade_journal import (
        JournalError,
        validate_transaction_directory,
    )
    from .reviewer_upgrade_systemd import (
        UNIT_NAMES,
        UnitBundle,
        digest_payload,
    )
else:
    from reviewer_upgrade_journal import (  # type: ignore[no-redef]
        JournalError,
        validate_transaction_directory,
    )
    from reviewer_upgrade_systemd import (  # type: ignore[no-redef]
        UNIT_NAMES,
        UnitBundle,
        digest_payload,
    )


ROLES = ("old", "target")
MAX_UNIT_ARTIFACT_BYTES = 64 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 256 * 1024
MAX_TRANSACTION_ENTRIES = 1_024

ARTIFACT_PREFIX = "reviewer-unit-"
_DIGEST_PREFIX = "sha256:"
_DIGEST_LENGTH = len(_DIGEST_PREFIX) + 64
_ERROR = "UPGRADE_UNIT_ARTIFACT_INVALID"

_DESCRIPTOR_KEYS = {
    "name",
    "relative_path",
    "role",
    "sha256",
    "size",
}


class UnitArtifactError(RuntimeError):
    """Stable, content-free failure for an unsafe artifact operation."""

    def __init__(self) -> None:
        super().__init__(_ERROR)
        self.code = _ERROR


def _raise_invalid() -> NoReturn:
    raise UnitArtifactError()


def _close_descriptor(descriptor: int) -> None:
    primary_error_active = sys.exc_info()[0] is not None
    try:
        os.close(descriptor)
    except OSError as error:
        if not primary_error_active:
            raise UnitArtifactError() from error


def _digest(payload: bytes) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(payload).hexdigest()


def _valid_digest(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == _DIGEST_LENGTH
        and value.startswith(_DIGEST_PREFIX)
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _relative_path(role: str, name: str) -> str:
    if role not in ROLES or name not in UNIT_NAMES:
        _raise_invalid()
    return f"{ARTIFACT_PREFIX}{role}-{name}.artifact"


def _descriptor(role: str, name: str, payload: bytes) -> dict[str, Any]:
    return {
        "name": name,
        "relative_path": _relative_path(role, name),
        "role": role,
        "sha256": _digest(payload),
        "size": len(payload),
    }


def _validated_bundle_payloads(bundle: UnitBundle) -> dict[str, bytes]:
    if type(bundle) is not UnitBundle:
        _raise_invalid()
    payloads: dict[str, bytes] = {}
    for name in UNIT_NAMES:
        try:
            artifact = bundle.artifact(name)
        except Exception as error:
            raise UnitArtifactError() from error
        payload = artifact.payload
        if (
            type(payload) is not bytes
            or not payload
            or len(payload) > MAX_UNIT_ARTIFACT_BYTES
            or artifact.digest != digest_payload(payload)
        ):
            _raise_invalid()
        payloads[name] = payload
    return payloads


def _validated_descriptors(
    descriptors: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if type(descriptors) is not list or len(descriptors) != len(ROLES) * len(
        UNIT_NAMES
    ):
        _raise_invalid()
    expected = [
        (role, name)
        for role in ROLES
        for name in UNIT_NAMES
    ]
    result: list[dict[str, Any]] = []
    total = 0
    for value, (role, name) in zip(descriptors, expected, strict=True):
        if (
            type(value) is not dict
            or set(value) != _DESCRIPTOR_KEYS
            or any(type(key) is not str for key in value)
        ):
            _raise_invalid()
        size = value.get("size")
        if (
            type(value.get("role")) is not str
            or value.get("role") != role
            or type(value.get("name")) is not str
            or value.get("name") != name
            or type(value.get("relative_path")) is not str
            or value.get("relative_path") != _relative_path(role, name)
            or type(size) is not int
            or type(size) is bool
            or not 1 <= size <= MAX_UNIT_ARTIFACT_BYTES
            or not _valid_digest(value.get("sha256"))
        ):
            _raise_invalid()
        total += size
        result.append(dict(value))
    if total > MAX_TOTAL_ARTIFACT_BYTES:
        _raise_invalid()
    return result


def validate_unit_artifact_descriptors(
    descriptors: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return a strict JSON copy of the fixed six-file descriptor list."""

    return _validated_descriptors(descriptors)


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _assert_directory_binding(
    descriptor: int,
    path: Path,
    expected: os.stat_result,
) -> None:
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
    except OSError as error:
        raise UnitArtifactError() from error
    identity = (expected.st_dev, expected.st_ino)
    for metadata in (opened, current):
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or (metadata.st_dev, metadata.st_ino) != identity
        ):
            _raise_invalid()


@contextmanager
def _open_transaction_directory(
    transaction_directory: Path | os.PathLike[str] | str,
) -> Iterator[tuple[Path, int, os.stat_result]]:
    try:
        directory = validate_transaction_directory(transaction_directory)
        expected = directory.lstat()
        descriptor = os.open(directory, _directory_flags())
    except (JournalError, OSError) as error:
        raise UnitArtifactError() from error
    try:
        _assert_directory_binding(descriptor, directory, expected)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as error:
            raise UnitArtifactError() from error
        _assert_directory_binding(descriptor, directory, expected)
        yield directory, descriptor, expected
        _assert_directory_binding(descriptor, directory, expected)
    finally:
        _close_descriptor(descriptor)


def _metadata_tuple(metadata: os.stat_result) -> tuple[int, ...]:
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


def _safe_private_file(metadata: os.stat_result, *, links: int) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and metadata.st_nlink == links
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and 1 <= metadata.st_size <= MAX_UNIT_ARTIFACT_BYTES
    )


def _read_private_file(
    directory_descriptor: int,
    name: str,
    *,
    fsync_file: bool = False,
    required_links: int = 1,
) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        lexical = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        descriptor = os.open(
            name,
            flags,
            dir_fd=directory_descriptor,
        )
        before = os.fstat(descriptor)
        if (
            not _safe_private_file(lexical, links=required_links)
            or not _safe_private_file(before, links=required_links)
            or (lexical.st_dev, lexical.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            _raise_invalid()
        payload = bytearray()
        while len(payload) <= MAX_UNIT_ARTIFACT_BYTES:
            block = os.read(
                descriptor,
                min(
                    65_536,
                    MAX_UNIT_ARTIFACT_BYTES + 1 - len(payload),
                ),
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        current = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if fsync_file:
            os.fsync(descriptor)
        if (
            len(payload) != before.st_size
            or len(payload) > MAX_UNIT_ARTIFACT_BYTES
            or _metadata_tuple(after) != _metadata_tuple(before)
            or _metadata_tuple(current) != _metadata_tuple(after)
        ):
            _raise_invalid()
        return bytes(payload)
    except UnitArtifactError:
        raise
    except OSError as error:
        raise UnitArtifactError() from error
    finally:
        if descriptor is not None:
            _close_descriptor(descriptor)


def _verify_payload(
    directory_descriptor: int,
    name: str,
    payload: bytes,
    *,
    required_links: int = 1,
) -> None:
    loaded = _read_private_file(
        directory_descriptor,
        name,
        required_links=required_links,
    )
    if len(loaded) != len(payload) or _digest(loaded) != _digest(payload):
        _raise_invalid()


def _namespace_entries(directory_descriptor: int) -> set[str]:
    try:
        entries = os.listdir(directory_descriptor)
    except OSError as error:
        raise UnitArtifactError() from error
    if len(entries) > MAX_TRANSACTION_ENTRIES or any(
        type(entry) is not str for entry in entries
    ):
        _raise_invalid()
    return {
        entry
        for entry in entries
        if entry.startswith(ARTIFACT_PREFIX)
        or entry.startswith("." + ARTIFACT_PREFIX)
    }


def _temporary_pattern(final_name: str) -> re.Pattern[str]:
    return re.compile(
        rf"\.{re.escape(final_name)}\.next-[0-9]+-[0-9a-f]{{12}}\Z"
    )


def _scan_preparation_entries(
    directory_descriptor: int,
    final_names: set[str],
) -> dict[str, str | None]:
    namespace = _namespace_entries(directory_descriptor)
    temporaries = {name: None for name in final_names}
    for entry in namespace:
        if entry in final_names:
            continue
        matched = [
            name
            for name in final_names
            if _temporary_pattern(name).fullmatch(entry) is not None
        ]
        if len(matched) != 1 or temporaries[matched[0]] is not None:
            _raise_invalid()
        temporaries[matched[0]] = entry
    return temporaries


def _lstat_optional(
    directory_descriptor: int,
    name: str,
) -> os.stat_result | None:
    try:
        return os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        raise UnitArtifactError() from error


def _publish_private_file(
    directory: Path,
    directory_descriptor: int,
    directory_binding: os.stat_result,
    final_name: str,
    payload: bytes,
) -> None:
    temporary = (
        f".{final_name}.next-{os.getpid()}-{secrets.token_hex(6)}"
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    temporary_present = False
    try:
        if _lstat_optional(directory_descriptor, final_name) is not None:
            _raise_invalid()
        descriptor = os.open(
            temporary,
            flags,
            0o600,
            dir_fd=directory_descriptor,
        )
        temporary_present = True
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("unit artifact write stopped")
                offset += written
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not _safe_private_file(metadata, links=1)
                or metadata.st_size != len(payload)
            ):
                _raise_invalid()
            os.fsync(descriptor)
        finally:
            _close_descriptor(descriptor)
        _assert_directory_binding(
            directory_descriptor,
            directory,
            directory_binding,
        )
        if _lstat_optional(directory_descriptor, final_name) is not None:
            _raise_invalid()
        os.link(
            temporary,
            final_name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=directory_descriptor)
        temporary_present = False
        os.fsync(directory_descriptor)
        _verify_payload(directory_descriptor, final_name, payload)
    except UnitArtifactError:
        raise
    except OSError as error:
        raise UnitArtifactError() from error
    finally:
        primary_error_active = sys.exc_info()[0] is not None
        if temporary_present:
            try:
                os.unlink(temporary, dir_fd=directory_descriptor)
                os.fsync(directory_descriptor)
            except FileNotFoundError:
                pass
            except OSError as error:
                if not primary_error_active:
                    raise UnitArtifactError() from error


def _resume_or_publish(
    directory: Path,
    directory_descriptor: int,
    directory_binding: os.stat_result,
    final_name: str,
    temporary: str | None,
    payload: bytes,
) -> None:
    final_metadata = _lstat_optional(directory_descriptor, final_name)
    if final_metadata is not None and temporary is not None:
        temporary_metadata = _lstat_optional(
            directory_descriptor,
            temporary,
        )
        if (
            temporary_metadata is None
            or not _safe_private_file(final_metadata, links=2)
            or not _safe_private_file(temporary_metadata, links=2)
            or (final_metadata.st_dev, final_metadata.st_ino)
            != (temporary_metadata.st_dev, temporary_metadata.st_ino)
        ):
            _raise_invalid()
        _verify_payload(
            directory_descriptor,
            final_name,
            payload,
            required_links=2,
        )
        try:
            os.unlink(temporary, dir_fd=directory_descriptor)
            os.fsync(directory_descriptor)
        except OSError as error:
            raise UnitArtifactError() from error
        final_metadata = _lstat_optional(directory_descriptor, final_name)
        temporary = None
    if final_metadata is not None:
        if temporary is not None:
            _raise_invalid()
        _verify_payload(directory_descriptor, final_name, payload)
        return
    if temporary is not None:
        _verify_payload(directory_descriptor, temporary, payload)
        try:
            os.link(
                temporary,
                final_name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            os.unlink(temporary, dir_fd=directory_descriptor)
            os.fsync(directory_descriptor)
        except OSError as error:
            raise UnitArtifactError() from error
        _verify_payload(directory_descriptor, final_name, payload)
        return
    _publish_private_file(
        directory,
        directory_descriptor,
        directory_binding,
        final_name,
        payload,
    )


def prepare_unit_bundle_artifacts(
    transaction_directory: Path | os.PathLike[str] | str,
    old: UnitBundle,
    target: UnitBundle,
) -> list[dict[str, Any]]:
    """Durably prepare the exact old and target bundles for plan publication.

    A failed call never returns descriptors, so a caller must not publish an
    immutable plan from a partial preparation.  Retrying with the same bundles
    resumes exact partial writes; any differing or unsafe entry fails closed.
    """

    payloads = {
        "old": _validated_bundle_payloads(old),
        "target": _validated_bundle_payloads(target),
    }
    total = sum(
        len(payloads[role][name])
        for role in ROLES
        for name in UNIT_NAMES
    )
    if total > MAX_TOTAL_ARTIFACT_BYTES:
        _raise_invalid()
    descriptors = [
        _descriptor(role, name, payloads[role][name])
        for role in ROLES
        for name in UNIT_NAMES
    ]
    descriptors = _validated_descriptors(descriptors)
    finals = {
        descriptor["relative_path"]
        for descriptor in descriptors
    }
    with _open_transaction_directory(transaction_directory) as (
        directory,
        directory_descriptor,
        directory_binding,
    ):
        temporaries = _scan_preparation_entries(
            directory_descriptor,
            finals,
        )
        for descriptor in descriptors:
            role = descriptor["role"]
            name = descriptor["name"]
            relative_path = descriptor["relative_path"]
            _resume_or_publish(
                directory,
                directory_descriptor,
                directory_binding,
                relative_path,
                temporaries[relative_path],
                payloads[role][name],
            )
        if _namespace_entries(directory_descriptor) != finals:
            _raise_invalid()
        for descriptor in descriptors:
            loaded = _read_private_file(
                directory_descriptor,
                descriptor["relative_path"],
                fsync_file=True,
            )
            if (
                len(loaded) != descriptor["size"]
                or _digest(loaded) != descriptor["sha256"]
            ):
                _raise_invalid()
        os.fsync(directory_descriptor)
    return descriptors


def load_unit_bundle_artifacts(
    transaction_directory: Path | os.PathLike[str] | str,
    descriptors: list[Mapping[str, Any]],
) -> tuple[UnitBundle, UnitBundle]:
    """Load both bundles only from an exact, fully verified artifact set."""

    sealed = _validated_descriptors(descriptors)
    expected_paths = {
        descriptor["relative_path"]
        for descriptor in sealed
    }
    payloads: dict[str, dict[str, bytes]] = {
        role: {} for role in ROLES
    }
    with _open_transaction_directory(transaction_directory) as (
        _directory,
        directory_descriptor,
        _binding,
    ):
        if _namespace_entries(directory_descriptor) != expected_paths:
            _raise_invalid()
        total = 0
        for descriptor in sealed:
            payload = _read_private_file(
                directory_descriptor,
                descriptor["relative_path"],
            )
            if (
                len(payload) != descriptor["size"]
                or _digest(payload) != descriptor["sha256"]
            ):
                _raise_invalid()
            total += len(payload)
            payloads[descriptor["role"]][descriptor["name"]] = payload
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            _raise_invalid()
        if _namespace_entries(directory_descriptor) != expected_paths:
            _raise_invalid()
    try:
        old = UnitBundle.from_payloads(payloads["old"])
        target = UnitBundle.from_payloads(payloads["target"])
    except Exception as error:
        raise UnitArtifactError() from error
    if (
        _validated_bundle_payloads(old) != payloads["old"]
        or _validated_bundle_payloads(target) != payloads["target"]
    ):
        _raise_invalid()
    return old, target


__all__ = [
    "ARTIFACT_PREFIX",
    "MAX_TOTAL_ARTIFACT_BYTES",
    "MAX_UNIT_ARTIFACT_BYTES",
    "ROLES",
    "UnitArtifactError",
    "load_unit_bundle_artifacts",
    "prepare_unit_bundle_artifacts",
    "validate_unit_artifact_descriptors",
]
