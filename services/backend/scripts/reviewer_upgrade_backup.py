#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded, durable backup attempts for a reviewer-only upgrade.

The helper owns attempt bookkeeping and recovery policy, while a supplied
runner performs the container/archive operations.  The immutable transaction
plan remains the authority for every source, file, image, volume, and container
binding used here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Iterator, NoReturn

if __package__:
    from .reviewer_upgrade_journal import (
        JournalError,
        canonical_json,
        parse_canonical_json,
        validate_transaction_directory,
    )
else:
    from reviewer_upgrade_journal import (  # type: ignore[no-redef]
        JournalError,
        canonical_json,
        parse_canonical_json,
        validate_transaction_directory,
    )


BACKUP_BINDINGS_CONTRACT = "tacua.reviewer-upgrade-backup-bindings@1.0.0"
BACKUP_LEDGER_CONTRACT = "tacua.reviewer-upgrade-backup-ledger@1.0.0"
BACKUP_ATTEMPT_CONTRACT = "tacua.reviewer-upgrade-backup-attempt@1.0.0"
BACKUP_RECEIPT_CONTRACT = "tacua.reviewer-upgrade-backup-receipt@1.0.0"

BACKUP_LEDGER_FILE = "backup-ledger.json"
BACKUP_LEDGER_STAGING_FILE = ".backup-ledger.json.next"
ATTEMPT_MARKER_FILE = "attempt.json"
ATTEMPT_RECEIPT_FILE = "backup-receipt.json"
BACKUP_BUNDLE_DIRECTORY = "bundle"

MAX_BACKUP_ATTEMPTS = 3
MAX_HEALTH_ATTEMPTS = 90
MAX_BOUND_FILE_BYTES = 256 * 1024
MAX_BUNDLE_ENTRIES = 100_000
MAX_BUNDLE_DEPTH = 64
MAX_LEDGER_SEQUENCE = 1_000
MAX_TRANSACTION_ENTRIES = 1_024

PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
OPERATION_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
GENERATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
BACKEND_IMAGE = re.compile(
    r"^tacua-backend:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)
VOLUME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SAFE_ABSOLUTE_PATH = re.compile(r"^/(?:[A-Za-z0-9._@%+=~-]+/)*[A-Za-z0-9._@%+=~-]+$")

_BINDING_KEYS = {
    "backend",
    "config",
    "contract_version",
    "operation_id",
    "plan_digest",
    "project",
    "secret",
    "source",
}
_FILE_KEYS = {"digest", "mode", "path", "size", "uid"}
_SOURCE_KEYS = {
    "compose_digest",
    "generation",
    "manifest_digest",
    "state_directory",
}
_BACKEND_KEYS = {
    "container_id",
    "image_id",
    "image_ref",
    "state_volume",
}
_ERROR = "REVIEWER_UPGRADE_BACKUP_INVALID"
_FAILED = "REVIEWER_UPGRADE_BACKUP_FAILED"
_RECOVERY_FAILED = "REVIEWER_UPGRADE_BACKUP_RECOVERY_FAILED"
_EXHAUSTED = "REVIEWER_UPGRADE_BACKUP_ATTEMPTS_EXHAUSTED"

Runner = Callable[[str, Mapping[str, Any]], Mapping[str, Any]]
Sleeper = Callable[[float], None]


class BackupError(RuntimeError):
    """Stable, content-free backup failure."""

    def __init__(self, code: str = _ERROR) -> None:
        super().__init__(code)
        self.code = code


class _ActionError(RuntimeError):
    pass


def _raise_invalid() -> NoReturn:
    raise BackupError(_ERROR)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _document_digest(document: Mapping[str, Any], field: str) -> str:
    subject = dict(document)
    subject.pop(field, None)
    return _digest(canonical_json(subject))


def _plain_dict(value: Any, keys: set[str]) -> dict[str, Any]:
    if (
        type(value) is not dict
        or set(value) != keys
        or any(type(key) is not str for key in value)
    ):
        _raise_invalid()
    return dict(value)


def _canonical_absolute_path(value: Any) -> Path:
    if type(value) is not str or not value or "\x00" in value:
        _raise_invalid()
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise BackupError(_ERROR) from error
    if (
        len(encoded) > 4_096
        or SAFE_ABSOLUTE_PATH.fullmatch(value) is None
        or not os.path.isabs(value)
        or value.startswith("//")
        or os.path.normpath(value) != value
    ):
        _raise_invalid()
    return Path(value)


@dataclass(frozen=True)
class BackupFileBinding:
    digest: str
    mode: int
    path: Path
    size: int
    uid: int

    def to_json(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "mode": self.mode,
            "path": str(self.path),
            "size": self.size,
            "uid": self.uid,
        }


@dataclass(frozen=True)
class BackupBindings:
    plan_digest: str
    operation_id: str
    project: str
    source_state_directory: Path
    source_generation: str
    source_manifest_digest: str
    source_compose_digest: str
    backend_container_id: str
    backend_image_id: str
    backend_image_ref: str
    state_volume: str
    config: BackupFileBinding
    secret: BackupFileBinding

    def to_json(self) -> dict[str, Any]:
        return {
            "backend": {
                "container_id": self.backend_container_id,
                "image_id": self.backend_image_id,
                "image_ref": self.backend_image_ref,
                "state_volume": self.state_volume,
            },
            "config": self.config.to_json(),
            "contract_version": BACKUP_BINDINGS_CONTRACT,
            "operation_id": self.operation_id,
            "plan_digest": self.plan_digest,
            "project": self.project,
            "secret": self.secret.to_json(),
            "source": {
                "compose_digest": self.source_compose_digest,
                "generation": self.source_generation,
                "manifest_digest": self.source_manifest_digest,
                "state_directory": str(self.source_state_directory),
            },
        }


def _validate_file_binding(value: Any, *, expected_mode: int) -> BackupFileBinding:
    document = _plain_dict(value, _FILE_KEYS)
    digest = document.get("digest")
    size = document.get("size")
    uid = document.get("uid")
    if (
        type(digest) is not str
        or DIGEST.fullmatch(digest) is None
        or type(document.get("mode")) is not int
        or type(document["mode"]) is bool
        or document["mode"] != expected_mode
        or type(size) is not int
        or type(size) is bool
        or not 1 <= size <= MAX_BOUND_FILE_BYTES
        or type(uid) is not int
        or type(uid) is bool
        or uid < 0
    ):
        _raise_invalid()
    return BackupFileBinding(
        digest=digest,
        mode=expected_mode,
        path=_canonical_absolute_path(document.get("path")),
        size=size,
        uid=uid,
    )


def validate_backup_bindings(value: Any) -> BackupBindings:
    """Validate the exact JSON binding copied from the immutable plan."""

    document = value.to_json() if type(value) is BackupBindings else value
    document = _plain_dict(document, _BINDING_KEYS)
    source = _plain_dict(document.get("source"), _SOURCE_KEYS)
    backend = _plain_dict(document.get("backend"), _BACKEND_KEYS)
    string_patterns = (
        (document.get("plan_digest"), DIGEST),
        (document.get("operation_id"), OPERATION_ID),
        (document.get("project"), PROJECT),
        (source.get("manifest_digest"), DIGEST),
        (source.get("compose_digest"), DIGEST),
        (backend.get("container_id"), CONTAINER_ID),
        (backend.get("image_id"), DIGEST),
        (backend.get("image_ref"), BACKEND_IMAGE),
        (backend.get("state_volume"), VOLUME),
    )
    if (
        document.get("contract_version") != BACKUP_BINDINGS_CONTRACT
        or any(
            type(item) is not str or pattern.fullmatch(item) is None
            for item, pattern in string_patterns
        )
        or backend["image_ref"].rsplit(":", 1)[1].lower() == "latest"
        or type(source.get("generation")) is not str
        or GENERATION.fullmatch(source["generation"]) is None
    ):
        _raise_invalid()
    bindings = BackupBindings(
        plan_digest=document["plan_digest"],
        operation_id=document["operation_id"],
        project=document["project"],
        source_state_directory=_canonical_absolute_path(
            source["state_directory"]
        ),
        source_generation=source["generation"],
        source_manifest_digest=source["manifest_digest"],
        source_compose_digest=source["compose_digest"],
        backend_container_id=backend["container_id"],
        backend_image_id=backend["image_id"],
        backend_image_ref=backend["image_ref"],
        state_volume=backend["state_volume"],
        config=_validate_file_binding(document.get("config"), expected_mode=0o644),
        secret=_validate_file_binding(document.get("secret"), expected_mode=0o444),
    )
    try:
        if canonical_json(bindings.to_json()) != canonical_json(document):
            _raise_invalid()
    except BackupError:
        raise
    except JournalError as error:
        raise BackupError(_ERROR) from error
    return bindings


def _bindings_digest(bindings: BackupBindings) -> str:
    return _digest(canonical_json(bindings.to_json()))


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


def _close_descriptor(descriptor: int) -> None:
    primary_error = sys.exc_info()[0] is not None
    try:
        os.close(descriptor)
    except OSError as error:
        if not primary_error:
            raise BackupError(_ERROR) from error


def _close_action_descriptor(descriptor: int, action: str) -> None:
    primary_error = sys.exc_info()[0] is not None
    try:
        os.close(descriptor)
    except OSError as error:
        if not primary_error:
            raise _ActionError(action) from error


def _verify_bound_file(binding: BackupFileBinding) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        if binding.path.resolve(strict=True) != binding.path:
            _raise_invalid()
        lexical = binding.path.lstat()
        descriptor = os.open(binding.path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != binding.uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != binding.mode
            or before.st_size != binding.size
            or (lexical.st_dev, lexical.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            _raise_invalid()
        payload = bytearray()
        while len(payload) <= MAX_BOUND_FILE_BYTES:
            block = os.read(
                descriptor,
                min(65_536, MAX_BOUND_FILE_BYTES + 1 - len(payload)),
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        current = binding.path.lstat()
        if (
            len(payload) != binding.size
            or _metadata_tuple(after) != _metadata_tuple(before)
            or _metadata_tuple(current) != _metadata_tuple(after)
            or _digest(bytes(payload)) != binding.digest
        ):
            _raise_invalid()
    except BackupError:
        raise
    except (OSError, UnicodeError) as error:
        raise BackupError(_ERROR) from error
    finally:
        if descriptor is not None:
            _close_descriptor(descriptor)


def _verify_host_bindings(bindings: BackupBindings) -> None:
    try:
        source = validate_transaction_directory(bindings.source_state_directory)
    except JournalError as error:
        raise BackupError(_ERROR) from error
    if source != bindings.source_state_directory:
        _raise_invalid()
    _verify_bound_file(bindings.config)
    _verify_bound_file(bindings.secret)


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _assert_directory(
    descriptor: int,
    path: Path,
    expected: os.stat_result,
) -> None:
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
    except OSError as error:
        raise BackupError(_ERROR) from error
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
def _open_transaction(
    transaction_directory: Path | os.PathLike[str] | str,
) -> Iterator[tuple[Path, int, os.stat_result]]:
    descriptor: int | None = None
    try:
        transaction = validate_transaction_directory(transaction_directory)
        expected = transaction.lstat()
        descriptor = os.open(transaction, _directory_flags())
        _assert_directory(descriptor, transaction, expected)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _assert_directory(descriptor, transaction, expected)
        yield transaction, descriptor, expected
        _assert_directory(descriptor, transaction, expected)
    except BackupError:
        raise
    except (JournalError, OSError) as error:
        raise BackupError(_ERROR) from error
    finally:
        if descriptor is not None:
            _close_descriptor(descriptor)


def _read_private_file(
    directory_descriptor: int,
    name: str,
    *,
    maximum: int = MAX_BOUND_FILE_BYTES,
    expected_links: int = 1,
) -> bytes:
    if type(expected_links) is not int or expected_links not in {1, 2}:
        _raise_invalid()
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
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != expected_links
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= maximum
            or (lexical.st_dev, lexical.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            _raise_invalid()
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
        current = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            len(payload) != before.st_size
            or len(payload) > maximum
            or _metadata_tuple(after) != _metadata_tuple(before)
            or _metadata_tuple(current) != _metadata_tuple(after)
        ):
            _raise_invalid()
        return bytes(payload)
    except BackupError:
        raise
    except OSError as error:
        raise BackupError(_ERROR) from error
    finally:
        if descriptor is not None:
            _close_descriptor(descriptor)


def _file_exists(directory_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    except OSError as error:
        raise BackupError(_ERROR) from error


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("backup metadata write stopped")
        offset += written


def _write_staging_file(
    directory_descriptor: int,
    name: str,
    payload: bytes,
) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(
            name,
            flags,
            0o600,
            dir_fd=directory_descriptor,
        )
        try:
            _write_all(descriptor, payload)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise BackupError(_ERROR) from error


def _ledger_document(
    bindings: BackupBindings,
    entries: list[dict[str, Any]],
    sequence: int,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "bindings_digest": _bindings_digest(bindings),
        "contract_version": BACKUP_LEDGER_CONTRACT,
        "entries": entries,
        "ledger_digest": "",
        "plan_digest": bindings.plan_digest,
        "sequence": sequence,
    }
    document["ledger_digest"] = _document_digest(document, "ledger_digest")
    return _validate_ledger(document, bindings)


def _attempt_path(number: int, *, quarantine: bool) -> str:
    if type(number) is not int or type(number) is bool or not 1 <= number <= MAX_BACKUP_ATTEMPTS:
        _raise_invalid()
    kind = "quarantine" if quarantine else "attempt"
    return f"backup-{kind}-{number:02d}"


def _validate_ledger_entry(value: Any, expected_number: int) -> dict[str, Any]:
    document = _plain_dict(value, {"number", "relative_path", "status"})
    status = document.get("status")
    if (
        type(document.get("number")) is not int
        or type(document["number"]) is bool
        or document["number"] != expected_number
        or status not in {"backup_ready", "failed", "quarantined"}
        or type(status) is not str
        or type(document.get("relative_path")) is not str
        or document["relative_path"]
        != _attempt_path(
            expected_number,
            quarantine=status in {"failed", "quarantined"},
        )
    ):
        _raise_invalid()
    return document


def _validate_ledger(value: Any, bindings: BackupBindings) -> dict[str, Any]:
    document = _plain_dict(
        value,
        {
            "bindings_digest",
            "contract_version",
            "entries",
            "ledger_digest",
            "plan_digest",
            "sequence",
        },
    )
    entries = document.get("entries")
    sequence = document.get("sequence")
    if (
        document.get("contract_version") != BACKUP_LEDGER_CONTRACT
        or document.get("plan_digest") != bindings.plan_digest
        or document.get("bindings_digest") != _bindings_digest(bindings)
        or type(entries) is not list
        or len(entries) > MAX_BACKUP_ATTEMPTS
        or type(sequence) is not int
        or type(sequence) is bool
        or not 0 <= sequence <= MAX_LEDGER_SEQUENCE
        or sequence != len(entries)
        or document.get("ledger_digest")
        != _document_digest(document, "ledger_digest")
    ):
        _raise_invalid()
    validated = [
        _validate_ledger_entry(entry, index)
        for index, entry in enumerate(entries, start=1)
    ]
    ready = [entry for entry in validated if entry["status"] == "backup_ready"]
    if ready and (len(ready) != 1 or ready[0] != validated[-1]):
        _raise_invalid()
    result = dict(document)
    result["entries"] = validated
    return result


def _load_ledger_file(
    directory_descriptor: int,
    name: str,
    bindings: BackupBindings,
) -> dict[str, Any]:
    payload = _read_private_file(directory_descriptor, name)
    try:
        value = parse_canonical_json(payload)
    except JournalError as error:
        raise BackupError(_ERROR) from error
    document = _validate_ledger(value, bindings)
    if canonical_json(document) != payload:
        _raise_invalid()
    return document


def _repair_ledger_staging(
    directory_descriptor: int,
    bindings: BackupBindings,
) -> None:
    staging_exists = _file_exists(
        directory_descriptor,
        BACKUP_LEDGER_STAGING_FILE,
    )
    if not staging_exists:
        return
    staging = _load_ledger_file(
        directory_descriptor,
        BACKUP_LEDGER_STAGING_FILE,
        bindings,
    )
    final_exists = _file_exists(directory_descriptor, BACKUP_LEDGER_FILE)
    if not final_exists:
        if staging["sequence"] != 0 or staging["entries"]:
            _raise_invalid()
        try:
            os.replace(
                BACKUP_LEDGER_STAGING_FILE,
                BACKUP_LEDGER_FILE,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            os.fsync(directory_descriptor)
        except OSError as error:
            raise BackupError(_ERROR) from error
        return
    final = _load_ledger_file(
        directory_descriptor,
        BACKUP_LEDGER_FILE,
        bindings,
    )
    if staging == final:
        try:
            os.unlink(BACKUP_LEDGER_STAGING_FILE, dir_fd=directory_descriptor)
            os.fsync(directory_descriptor)
        except OSError as error:
            raise BackupError(_ERROR) from error
        return
    if (
        staging["sequence"] != final["sequence"] + 1
        or len(staging["entries"]) != len(final["entries"]) + 1
        or staging["entries"][: len(final["entries"])] != final["entries"]
    ):
        _raise_invalid()
    try:
        os.replace(
            BACKUP_LEDGER_STAGING_FILE,
            BACKUP_LEDGER_FILE,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
    except OSError as error:
        raise BackupError(_ERROR) from error


def _write_ledger(
    directory_descriptor: int,
    bindings: BackupBindings,
    previous: dict[str, Any] | None,
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    _repair_ledger_staging(directory_descriptor, bindings)
    current = (
        _load_ledger_file(directory_descriptor, BACKUP_LEDGER_FILE, bindings)
        if _file_exists(directory_descriptor, BACKUP_LEDGER_FILE)
        else None
    )
    if current != previous:
        _raise_invalid()
    sequence = 0 if current is None else current["sequence"] + 1
    document = _ledger_document(bindings, entries, sequence)
    payload = canonical_json(document)
    if _file_exists(directory_descriptor, BACKUP_LEDGER_STAGING_FILE):
        _raise_invalid()
    _write_staging_file(
        directory_descriptor,
        BACKUP_LEDGER_STAGING_FILE,
        payload,
    )
    try:
        os.replace(
            BACKUP_LEDGER_STAGING_FILE,
            BACKUP_LEDGER_FILE,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
    except OSError as error:
        raise BackupError(_ERROR) from error
    loaded = _load_ledger_file(
        directory_descriptor,
        BACKUP_LEDGER_FILE,
        bindings,
    )
    if loaded != document:
        _raise_invalid()
    return loaded


def _load_or_create_ledger(
    directory_descriptor: int,
    bindings: BackupBindings,
) -> dict[str, Any]:
    _repair_ledger_staging(directory_descriptor, bindings)
    if _file_exists(directory_descriptor, BACKUP_LEDGER_FILE):
        return _load_ledger_file(
            directory_descriptor,
            BACKUP_LEDGER_FILE,
            bindings,
        )
    return _write_ledger(directory_descriptor, bindings, None, [])


def _attempt_marker(
    bindings: BackupBindings,
    number: int,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "attempt_digest": "",
        "bindings_digest": _bindings_digest(bindings),
        "contract_version": BACKUP_ATTEMPT_CONTRACT,
        "number": number,
        "plan_digest": bindings.plan_digest,
        "relative_path": _attempt_path(number, quarantine=False),
    }
    document["attempt_digest"] = _document_digest(document, "attempt_digest")
    return _validate_attempt_marker(document, bindings, number)


def _validate_attempt_marker(
    value: Any,
    bindings: BackupBindings,
    number: int,
) -> dict[str, Any]:
    document = _plain_dict(
        value,
        {
            "attempt_digest",
            "bindings_digest",
            "contract_version",
            "number",
            "plan_digest",
            "relative_path",
        },
    )
    if (
        document.get("contract_version") != BACKUP_ATTEMPT_CONTRACT
        or document.get("number") != number
        or type(document.get("number")) is not int
        or type(document["number"]) is bool
        or document.get("relative_path")
        != _attempt_path(number, quarantine=False)
        or document.get("plan_digest") != bindings.plan_digest
        or document.get("bindings_digest") != _bindings_digest(bindings)
        or document.get("attempt_digest")
        != _document_digest(document, "attempt_digest")
    ):
        _raise_invalid()
    return document


def _safe_attempt_directory(path: Path, transaction: Path) -> os.stat_result:
    if path.parent != transaction:
        _raise_invalid()
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BackupError(_ERROR) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _raise_invalid()
    return metadata


@contextmanager
def _open_attempt_directory(
    path: Path,
    transaction: Path,
) -> Iterator[int]:
    expected = _safe_attempt_directory(path, transaction)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, _directory_flags())
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino)
            != (expected.st_dev, expected.st_ino)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            _raise_invalid()
        yield descriptor
        current = path.lstat()
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino)
            != (expected.st_dev, expected.st_ino)
            or (current.st_dev, current.st_ino)
            != (expected.st_dev, expected.st_ino)
            or after.st_uid != os.geteuid()
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) != 0o700
            or stat.S_IMODE(current.st_mode) != 0o700
        ):
            _raise_invalid()
    except BackupError:
        raise
    except OSError as error:
        raise BackupError(_ERROR) from error
    finally:
        if descriptor is not None:
            _close_descriptor(descriptor)


def _write_immutable_json(
    directory_descriptor: int,
    name: str,
    document: Mapping[str, Any],
) -> None:
    if name not in {ATTEMPT_MARKER_FILE, ATTEMPT_RECEIPT_FILE}:
        _raise_invalid()
    if _file_exists(directory_descriptor, name):
        _raise_invalid()
    payload = canonical_json(document)
    temporary = f".{name}.next-{os.getpid()}-{os.urandom(6).hex()}"
    _write_staging_file(directory_descriptor, temporary, payload)
    primary_error: BaseException | None = None
    try:
        if _file_exists(directory_descriptor, name):
            _raise_invalid()
        os.link(
            temporary,
            name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=directory_descriptor)
        os.fsync(directory_descriptor)
    except BackupError as error:
        primary_error = error
        raise
    except OSError as error:
        primary_error = error
        raise BackupError(_ERROR) from error
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        except OSError as error:
            if primary_error is None:
                raise BackupError(_ERROR) from error


def _read_canonical_document(
    directory_descriptor: int,
    name: str,
    *,
    expected_links: int = 1,
) -> dict[str, Any]:
    payload = _read_private_file(
        directory_descriptor,
        name,
        expected_links=expected_links,
    )
    try:
        value = parse_canonical_json(payload)
    except JournalError as error:
        raise BackupError(_ERROR) from error
    if type(value) is not dict or canonical_json(value) != payload:
        _raise_invalid()
    return value


def _create_attempt(
    transaction: Path,
    transaction_descriptor: int,
    bindings: BackupBindings,
    number: int,
) -> Path:
    name = _attempt_path(number, quarantine=False)
    try:
        os.mkdir(name, 0o700, dir_fd=transaction_descriptor)
        os.fsync(transaction_descriptor)
    except OSError as error:
        raise BackupError(_ERROR) from error
    path = transaction / name
    with _open_attempt_directory(path, transaction) as descriptor:
        _write_immutable_json(
            descriptor,
            ATTEMPT_MARKER_FILE,
            _attempt_marker(bindings, number),
        )
    return path


def _attempt_entries(path: Path, transaction: Path) -> set[str]:
    _safe_attempt_directory(path, transaction)
    try:
        entries = {entry.name for entry in path.iterdir()}
    except OSError as error:
        raise BackupError(_ERROR) from error
    if len(entries) > MAX_TRANSACTION_ENTRIES:
        _raise_invalid()
    return entries


def _load_attempt_marker(
    path: Path,
    transaction: Path,
    bindings: BackupBindings,
    number: int,
) -> dict[str, Any]:
    with _open_attempt_directory(path, transaction) as descriptor:
        document = _read_canonical_document(descriptor, ATTEMPT_MARKER_FILE)
    return _validate_attempt_marker(document, bindings, number)


def _publication_drafts(entries: set[str], name: str) -> list[str]:
    return sorted(
        entry
        for entry in entries
        if re.fullmatch(
            rf"\.{re.escape(name)}\.next-[0-9]+-[a-f0-9]{{12}}",
            entry,
        )
    )


def _repair_receipt_publication(
    path: Path,
    transaction: Path,
    bindings: BackupBindings,
    prior_attempts: list[dict[str, Any]],
) -> None:
    entries = _attempt_entries(path, transaction)
    drafts = _publication_drafts(entries, ATTEMPT_RECEIPT_FILE)
    if ATTEMPT_RECEIPT_FILE not in entries:
        return
    if len(drafts) > 1:
        _raise_invalid()
    if not drafts:
        return
    if entries != {
        ATTEMPT_MARKER_FILE,
        ATTEMPT_RECEIPT_FILE,
        BACKUP_BUNDLE_DIRECTORY,
        drafts[0],
    }:
        _raise_invalid()
    with _open_attempt_directory(path, transaction) as descriptor:
        try:
            final = os.stat(
                ATTEMPT_RECEIPT_FILE,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            draft = os.stat(
                drafts[0],
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise BackupError(_ERROR) from error
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_uid != os.geteuid()
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_nlink != 2
            or draft.st_nlink != 2
            or (draft.st_dev, draft.st_ino) != (final.st_dev, final.st_ino)
        ):
            _raise_invalid()
        value = _read_canonical_document(
            descriptor,
            ATTEMPT_RECEIPT_FILE,
            expected_links=2,
        )
        receipt = validate_backup_receipt(value, bindings)
        if receipt["prior_attempts"] != prior_attempts:
            _raise_invalid()
        try:
            os.unlink(drafts[0], dir_fd=descriptor)
            os.fsync(descriptor)
        except OSError as error:
            raise BackupError(_ERROR) from error


def _recognized_incomplete_attempt(
    path: Path,
    transaction: Path,
    bindings: BackupBindings,
    number: int,
) -> None:
    entries = _attempt_entries(path, transaction)
    if not entries:
        return
    if ATTEMPT_RECEIPT_FILE in entries:
        _raise_invalid()
    if ATTEMPT_MARKER_FILE in entries:
        marker_drafts = _publication_drafts(entries, ATTEMPT_MARKER_FILE)
        receipt_drafts = _publication_drafts(entries, ATTEMPT_RECEIPT_FILE)
        if (
            len(marker_drafts) > 1
            or len(receipt_drafts) > 1
            or entries
            - {
                ATTEMPT_MARKER_FILE,
                BACKUP_BUNDLE_DIRECTORY,
                *marker_drafts,
                *receipt_drafts,
            }
        ):
            _raise_invalid()
        with _open_attempt_directory(path, transaction) as descriptor:
            marker = os.stat(
                ATTEMPT_MARKER_FILE,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            if marker.st_nlink == 1:
                if marker_drafts:
                    _raise_invalid()
                value = _read_canonical_document(
                    descriptor,
                    ATTEMPT_MARKER_FILE,
                )
            elif marker.st_nlink == 2:
                if len(marker_drafts) != 1:
                    _raise_invalid()
                draft = os.stat(
                    marker_drafts[0],
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(marker.st_mode)
                    or marker.st_uid != os.geteuid()
                    or stat.S_IMODE(marker.st_mode) != 0o600
                    or (draft.st_dev, draft.st_ino)
                    != (marker.st_dev, marker.st_ino)
                    or draft.st_nlink != 2
                ):
                    _raise_invalid()
                value = _read_canonical_document(
                    descriptor,
                    ATTEMPT_MARKER_FILE,
                    expected_links=2,
                )
            else:
                _raise_invalid()
            if receipt_drafts:
                receipt_draft = os.stat(
                    receipt_drafts[0],
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(receipt_draft.st_mode)
                    or receipt_draft.st_uid != os.geteuid()
                    or stat.S_IMODE(receipt_draft.st_mode) != 0o600
                    or receipt_draft.st_nlink != 1
                ):
                    _raise_invalid()
        _validate_attempt_marker(value, bindings, number)
        return
    marker_drafts = _publication_drafts(entries, ATTEMPT_MARKER_FILE)
    if len(entries) != 1 or len(marker_drafts) != 1:
        _raise_invalid()
    with _open_attempt_directory(path, transaction) as descriptor:
        value = _read_canonical_document(descriptor, marker_drafts[0])
    _validate_attempt_marker(value, bindings, number)


def _quarantine_attempt(
    transaction: Path,
    transaction_descriptor: int,
    bindings: BackupBindings,
    number: int,
) -> Path:
    active_name = _attempt_path(number, quarantine=False)
    quarantine_name = _attempt_path(number, quarantine=True)
    active = transaction / active_name
    quarantine = transaction / quarantine_name
    active_exists = _file_exists(transaction_descriptor, active_name)
    quarantine_exists = _file_exists(transaction_descriptor, quarantine_name)
    if active_exists and quarantine_exists:
        _raise_invalid()
    if quarantine_exists:
        _recognized_incomplete_attempt(
            quarantine,
            transaction,
            bindings,
            number,
        )
        return quarantine
    if not active_exists:
        _raise_invalid()
    _recognized_incomplete_attempt(active, transaction, bindings, number)
    try:
        os.replace(
            active_name,
            quarantine_name,
            src_dir_fd=transaction_descriptor,
            dst_dir_fd=transaction_descriptor,
        )
        os.fsync(transaction_descriptor)
    except OSError as error:
        raise BackupError(_ERROR) from error
    _recognized_incomplete_attempt(
        quarantine,
        transaction,
        bindings,
        number,
    )
    return quarantine


def _receipt_document(
    bindings: BackupBindings,
    number: int,
    bundle_digest: str,
    prior_attempts: list[dict[str, Any]],
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "attempt": {
            "number": number,
            "relative_path": _attempt_path(number, quarantine=False),
        },
        "backend": {
            "container_id": bindings.backend_container_id,
            "image_id": bindings.backend_image_id,
            "image_ref": bindings.backend_image_ref,
            "state_volume": bindings.state_volume,
        },
        "bindings_digest": _bindings_digest(bindings),
        "bundle": {
            "durable": True,
            "relative_path": BACKUP_BUNDLE_DIRECTORY,
            "sha256": bundle_digest,
            "verified": True,
        },
        "contract_version": BACKUP_RECEIPT_CONTRACT,
        "plan_digest": bindings.plan_digest,
        "prior_attempts": prior_attempts,
        "receipt_digest": "",
        "status": "backup_ready",
    }
    document["receipt_digest"] = _document_digest(document, "receipt_digest")
    return validate_backup_receipt(document, bindings)


def validate_backup_receipt(
    value: Any,
    bindings: BackupBindings | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a self-digested BACKUP_READY progress payload."""

    sealed_bindings = None if bindings is None else validate_backup_bindings(bindings)
    document = _plain_dict(
        value,
        {
            "attempt",
            "backend",
            "bindings_digest",
            "bundle",
            "contract_version",
            "plan_digest",
            "prior_attempts",
            "receipt_digest",
            "status",
        },
    )
    attempt = _plain_dict(document.get("attempt"), {"number", "relative_path"})
    backend = _plain_dict(document.get("backend"), _BACKEND_KEYS)
    bundle = _plain_dict(
        document.get("bundle"),
        {"durable", "relative_path", "sha256", "verified"},
    )
    prior = document.get("prior_attempts")
    if type(prior) is not list or len(prior) >= MAX_BACKUP_ATTEMPTS:
        _raise_invalid()
    validated_prior = [
        _validate_ledger_entry(entry, index)
        for index, entry in enumerate(prior, start=1)
    ]
    if any(
        entry["status"] not in {"failed", "quarantined"}
        for entry in validated_prior
    ):
        _raise_invalid()
    number = attempt.get("number")
    if (
        document.get("contract_version") != BACKUP_RECEIPT_CONTRACT
        or document.get("status") != "backup_ready"
        or type(document.get("plan_digest")) is not str
        or DIGEST.fullmatch(document["plan_digest"]) is None
        or type(document.get("bindings_digest")) is not str
        or DIGEST.fullmatch(document["bindings_digest"]) is None
        or type(number) is not int
        or type(number) is bool
        or number != len(validated_prior) + 1
        or not 1 <= number <= MAX_BACKUP_ATTEMPTS
        or attempt.get("relative_path")
        != _attempt_path(number, quarantine=False)
        or type(bundle.get("sha256")) is not str
        or DIGEST.fullmatch(bundle["sha256"]) is None
        or bundle.get("relative_path") != BACKUP_BUNDLE_DIRECTORY
        or bundle.get("verified") is not True
        or bundle.get("durable") is not True
        or type(backend.get("container_id")) is not str
        or CONTAINER_ID.fullmatch(backend["container_id"]) is None
        or type(backend.get("image_id")) is not str
        or DIGEST.fullmatch(backend["image_id"]) is None
        or type(backend.get("image_ref")) is not str
        or BACKEND_IMAGE.fullmatch(backend["image_ref"]) is None
        or type(backend.get("state_volume")) is not str
        or VOLUME.fullmatch(backend["state_volume"]) is None
        or document.get("receipt_digest")
        != _document_digest(document, "receipt_digest")
    ):
        _raise_invalid()
    if sealed_bindings is not None and (
        document["plan_digest"] != sealed_bindings.plan_digest
        or document["bindings_digest"] != _bindings_digest(sealed_bindings)
        or backend
        != {
            "container_id": sealed_bindings.backend_container_id,
            "image_id": sealed_bindings.backend_image_id,
            "image_ref": sealed_bindings.backend_image_ref,
            "state_volume": sealed_bindings.state_volume,
        }
    ):
        _raise_invalid()
    result = dict(document)
    result["attempt"] = dict(attempt)
    result["backend"] = dict(backend)
    result["bundle"] = dict(bundle)
    result["prior_attempts"] = validated_prior
    return result


def _load_attempt_receipt(
    path: Path,
    transaction: Path,
    bindings: BackupBindings,
    prior_attempts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    _repair_receipt_publication(
        path,
        transaction,
        bindings,
        prior_attempts,
    )
    entries = _attempt_entries(path, transaction)
    if ATTEMPT_RECEIPT_FILE not in entries:
        return None
    if entries != {
        ATTEMPT_MARKER_FILE,
        ATTEMPT_RECEIPT_FILE,
        BACKUP_BUNDLE_DIRECTORY,
    }:
        _raise_invalid()
    number = len(prior_attempts) + 1
    _load_attempt_marker(path, transaction, bindings, number)
    with _open_attempt_directory(path, transaction) as descriptor:
        value = _read_canonical_document(descriptor, ATTEMPT_RECEIPT_FILE)
    receipt = validate_backup_receipt(value, bindings)
    if receipt["prior_attempts"] != prior_attempts:
        _raise_invalid()
    bundle = path / BACKUP_BUNDLE_DIRECTORY
    try:
        metadata = bundle.lstat()
    except OSError as error:
        raise BackupError(_ERROR) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        _raise_invalid()
    return receipt


def _runner_call(
    runner: Runner,
    action: str,
    request: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        result = runner(action, dict(request))
    except Exception as error:
        raise _ActionError(action) from error
    if type(result) is not dict or any(type(key) is not str for key in result):
        raise _ActionError(action)
    return dict(result)


def _backend_request(bindings: BackupBindings) -> dict[str, str]:
    return {
        "container_id": bindings.backend_container_id,
        "image_id": bindings.backend_image_id,
        "image_ref": bindings.backend_image_ref,
        "state_volume": bindings.state_volume,
    }


def _observe_backend(runner: Runner, bindings: BackupBindings) -> dict[str, str]:
    result = _runner_call(runner, "inspect_backend", _backend_request(bindings))
    if (
        set(result)
        != {
            "container_id",
            "health",
            "image_id",
            "image_ref",
            "state_volume",
            "status",
        }
        or any(type(value) is not str for value in result.values())
        or result["container_id"] != bindings.backend_container_id
        or result["image_id"] != bindings.backend_image_id
        or result["image_ref"] != bindings.backend_image_ref
        or result["state_volume"] != bindings.state_volume
        or result["status"] not in {"created", "exited", "running"}
        or result["health"] not in {"healthy", "none", "starting", "unhealthy"}
    ):
        raise _ActionError("inspect_backend")
    return result


def _runner_ack(
    runner: Runner,
    action: str,
    bindings: BackupBindings,
) -> None:
    result = _runner_call(
        runner,
        action,
        {"container_id": bindings.backend_container_id},
    )
    expected_status = "stopped" if action == "stop_backend" else "started"
    if result != {
        "container_id": bindings.backend_container_id,
        "status": expected_status,
    }:
        raise _ActionError(action)


def _backup_request(
    attempt: Path,
    number: int,
    bindings: BackupBindings,
) -> dict[str, Any]:
    return {
        "attempt_directory": str(attempt),
        "attempt_number": number,
        "backend": _backend_request(bindings),
        "bundle_relative_path": BACKUP_BUNDLE_DIRECTORY,
        "config": bindings.config.to_json(),
        "host_tree_policy": {
            "directory_mode": 0o700,
            "file_mode": 0o600,
            "owner_uid": os.geteuid(),
            "special_files": "reject",
            "symlinks": "reject",
        },
        "plan_digest": bindings.plan_digest,
        "secret": bindings.secret.to_json(),
        "source": bindings.to_json()["source"],
    }


def _verify_bundle_tree(bundle: Path) -> None:
    """Require a bounded, owner-private tree after runner normalization."""

    count = 0

    def visit(descriptor: int, depth: int) -> None:
        nonlocal count
        if depth > MAX_BUNDLE_DEPTH:
            raise _ActionError("archive_backup")
        try:
            children = list(os.scandir(descriptor))
        except OSError as error:
            raise _ActionError("archive_backup") from error
        for child in children:
            count += 1
            if count > MAX_BUNDLE_ENTRIES or type(child.name) is not str:
                raise _ActionError("archive_backup")
            try:
                metadata = os.stat(
                    child.name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise _ActionError("archive_backup") from error
            if metadata.st_uid != os.geteuid() or stat.S_ISLNK(metadata.st_mode):
                raise _ActionError("archive_backup")
            if stat.S_ISREG(metadata.st_mode):
                if (
                    stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink != 1
                ):
                    raise _ActionError("archive_backup")
                continue
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise _ActionError("archive_backup")
            child_descriptor: int | None = None
            try:
                child_descriptor = os.open(
                    child.name,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
                opened = os.fstat(child_descriptor)
                if (
                    (opened.st_dev, opened.st_ino)
                    != (metadata.st_dev, metadata.st_ino)
                    or opened.st_uid != os.geteuid()
                    or stat.S_IMODE(opened.st_mode) != 0o700
                ):
                    raise _ActionError("archive_backup")
                visit(child_descriptor, depth + 1)
            except _ActionError:
                raise
            except OSError as error:
                raise _ActionError("archive_backup") from error
            finally:
                if child_descriptor is not None:
                    _close_action_descriptor(
                        child_descriptor,
                        "archive_backup",
                    )

    descriptor: int | None = None
    try:
        lexical = bundle.lstat()
        if (
            not stat.S_ISDIR(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or lexical.st_uid != os.geteuid()
            or stat.S_IMODE(lexical.st_mode) != 0o700
        ):
            raise _ActionError("archive_backup")
        descriptor = os.open(bundle, _directory_flags())
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise _ActionError("archive_backup")
        visit(descriptor, 0)
        after = os.fstat(descriptor)
        current = bundle.lstat()
        if (
            (after.st_dev, after.st_ino) != (lexical.st_dev, lexical.st_ino)
            or (current.st_dev, current.st_ino)
            != (lexical.st_dev, lexical.st_ino)
            or after.st_uid != os.geteuid()
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) != 0o700
            or stat.S_IMODE(current.st_mode) != 0o700
        ):
            raise _ActionError("archive_backup")
    except _ActionError:
        raise
    except OSError as error:
        raise _ActionError("archive_backup") from error
    finally:
        if descriptor is not None:
            _close_action_descriptor(descriptor, "archive_backup")


def _archive_and_verify(
    runner: Runner,
    attempt: Path,
    number: int,
    bindings: BackupBindings,
) -> str:
    request = _backup_request(attempt, number, bindings)
    archive = _runner_call(runner, "archive_backup", request)
    if archive != {"created": True, "host_tree_normalized": True}:
        raise _ActionError("archive_backup")
    bundle = attempt / BACKUP_BUNDLE_DIRECTORY
    _verify_bundle_tree(bundle)
    verified = _runner_call(runner, "verify_backup", request)
    if (
        set(verified) != {"bundle_digest", "status", "verified"}
        or verified.get("status") != "ok"
        or verified.get("verified") is not True
        or type(verified.get("bundle_digest")) is not str
        or DIGEST.fullmatch(verified["bundle_digest"]) is None
    ):
        raise _ActionError("verify_backup")
    durable = _runner_call(
        runner,
        "fsync_backup",
        {**request, "bundle_digest": verified["bundle_digest"]},
    )
    if durable != {
        "bundle_digest": verified["bundle_digest"],
        "durable": True,
    }:
        raise _ActionError("fsync_backup")
    _verify_bundle_tree(bundle)
    try:
        descriptor = os.open(attempt, _directory_flags())
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise _ActionError("fsync_backup") from error
    return verified["bundle_digest"]


def _verify_existing_archive(
    runner: Runner,
    attempt: Path,
    receipt: Mapping[str, Any],
    bindings: BackupBindings,
) -> None:
    number = receipt["attempt"]["number"]
    request = _backup_request(attempt, number, bindings)
    _verify_bundle_tree(attempt / BACKUP_BUNDLE_DIRECTORY)
    verified = _runner_call(runner, "verify_backup", request)
    expected_digest = receipt["bundle"]["sha256"]
    if verified != {
        "bundle_digest": expected_digest,
        "status": "ok",
        "verified": True,
    }:
        raise _ActionError("verify_backup")
    durable = _runner_call(
        runner,
        "fsync_backup",
        {**request, "bundle_digest": expected_digest},
    )
    if durable != {"bundle_digest": expected_digest, "durable": True}:
        raise _ActionError("fsync_backup")
    _verify_bundle_tree(attempt / BACKUP_BUNDLE_DIRECTORY)


def _resume_ready_attempt(
    runner: Runner,
    attempt: Path,
    receipt: Mapping[str, Any],
    bindings: BackupBindings,
    *,
    health_attempts: int,
    health_interval_seconds: float,
    sleeper: Sleeper,
) -> None:
    verification_error: Exception | None = None
    recovery_error: Exception | None = None
    try:
        _verify_existing_archive(runner, attempt, receipt, bindings)
    except Exception as error:
        verification_error = error
    finally:
        try:
            _recover_backend(
                runner,
                bindings,
                health_attempts=health_attempts,
                health_interval_seconds=health_interval_seconds,
                sleeper=sleeper,
            )
        except Exception as error:
            recovery_error = error
    if recovery_error is not None:
        raise BackupError(_RECOVERY_FAILED) from recovery_error
    if verification_error is not None:
        raise BackupError(_FAILED) from verification_error


def _recover_backend(
    runner: Runner,
    bindings: BackupBindings,
    *,
    health_attempts: int,
    health_interval_seconds: float,
    sleeper: Sleeper,
) -> None:
    _runner_ack(runner, "start_backend", bindings)
    healthy = False
    for attempt in range(health_attempts):
        observed = _observe_backend(runner, bindings)
        if observed["status"] == "running" and observed["health"] == "healthy":
            healthy = True
            break
        if attempt + 1 < health_attempts:
            sleeper(health_interval_seconds)
    if not healthy:
        raise _ActionError("health_backend")
    _verify_host_bindings(bindings)
    smoke = _runner_call(
        runner,
        "smoke_backend",
        {
            "config": bindings.config.to_json(),
            "container_id": bindings.backend_container_id,
            "secret": bindings.secret.to_json(),
        },
    )
    if smoke != {
        "container_id": bindings.backend_container_id,
        "status": "ok",
    }:
        raise _ActionError("smoke_backend")


def _scan_attempt_namespace(
    transaction: Path,
    transaction_descriptor: int,
) -> dict[int, tuple[str, bool]]:
    try:
        entries = os.listdir(transaction_descriptor)
    except OSError as error:
        raise BackupError(_ERROR) from error
    if len(entries) > MAX_TRANSACTION_ENTRIES:
        _raise_invalid()
    result: dict[int, tuple[str, bool]] = {}
    for entry in entries:
        if entry in {BACKUP_LEDGER_FILE, BACKUP_LEDGER_STAGING_FILE}:
            continue
        if not entry.startswith("backup-"):
            continue
        match = re.fullmatch(r"backup-(attempt|quarantine)-([0-9]{2})", entry)
        if match is None:
            _raise_invalid()
        number = int(match.group(2), 10)
        if not 1 <= number <= MAX_BACKUP_ATTEMPTS or number in result:
            _raise_invalid()
        quarantine = match.group(1) == "quarantine"
        _safe_attempt_directory(transaction / entry, transaction)
        result[number] = (entry, quarantine)
    return result


def _append_ledger_entry(
    transaction_descriptor: int,
    bindings: BackupBindings,
    ledger: dict[str, Any],
    number: int,
    status: str,
) -> dict[str, Any]:
    entry = _validate_ledger_entry(
        {
            "number": number,
            "relative_path": _attempt_path(
                number,
                quarantine=status in {"failed", "quarantined"},
            ),
            "status": status,
        },
        number,
    )
    entries = [*ledger["entries"], entry]
    return _write_ledger(
        transaction_descriptor,
        bindings,
        ledger,
        entries,
    )


def _reconcile_attempt_ledger(
    transaction: Path,
    transaction_descriptor: int,
    bindings: BackupBindings,
    ledger: dict[str, Any],
    runner: Runner,
    *,
    health_attempts: int,
    health_interval_seconds: float,
    sleeper: Sleeper,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    observed = _scan_attempt_namespace(transaction, transaction_descriptor)
    for entry in ledger["entries"]:
        number = entry["number"]
        expected_quarantine = entry["status"] in {"failed", "quarantined"}
        if observed.get(number) != (entry["relative_path"], expected_quarantine):
            _raise_invalid()
        path = transaction / entry["relative_path"]
        if expected_quarantine:
            _recognized_incomplete_attempt(
                path,
                transaction,
                bindings,
                number,
            )
        else:
            receipt = _load_attempt_receipt(
                path,
                transaction,
                bindings,
                ledger["entries"][:-1],
            )
            if receipt is None:
                _raise_invalid()
            _resume_ready_attempt(
                runner,
                path,
                receipt,
                bindings,
                health_attempts=health_attempts,
                health_interval_seconds=health_interval_seconds,
                sleeper=sleeper,
            )
            return ledger, receipt
    if ledger["entries"] and ledger["entries"][-1]["status"] == "backup_ready":
        _raise_invalid()
    next_number = len(ledger["entries"]) + 1
    extras = {
        number: value
        for number, value in observed.items()
        if number >= next_number
    }
    if any(number != next_number for number in extras) or len(extras) > 1:
        _raise_invalid()
    if not extras:
        return ledger, None
    name, quarantine = extras[next_number]
    path = transaction / name
    if quarantine:
        _recognized_incomplete_attempt(
            path,
            transaction,
            bindings,
            next_number,
        )
    else:
        receipt = _load_attempt_receipt(
            path,
            transaction,
            bindings,
            ledger["entries"],
        )
        if receipt is not None:
            _resume_ready_attempt(
                runner,
                path,
                receipt,
                bindings,
                health_attempts=health_attempts,
                health_interval_seconds=health_interval_seconds,
                sleeper=sleeper,
            )
            ledger = _append_ledger_entry(
                transaction_descriptor,
                bindings,
                ledger,
                next_number,
                "backup_ready",
            )
            return ledger, receipt
        _recognized_incomplete_attempt(
            path,
            transaction,
            bindings,
            next_number,
        )
    try:
        _recover_backend(
            runner,
            bindings,
            health_attempts=health_attempts,
            health_interval_seconds=health_interval_seconds,
            sleeper=sleeper,
        )
    except Exception as error:
        raise BackupError(_RECOVERY_FAILED) from error
    _quarantine_attempt(
        transaction,
        transaction_descriptor,
        bindings,
        next_number,
    )
    ledger = _append_ledger_entry(
        transaction_descriptor,
        bindings,
        ledger,
        next_number,
        "quarantined",
    )
    return ledger, None


def run_backup_attempt(
    transaction_directory: Path | os.PathLike[str] | str,
    bindings: BackupBindings | Mapping[str, Any],
    runner: Runner,
    *,
    health_attempts: int = 30,
    health_interval_seconds: float = 1.0,
    sleeper: Sleeper = time.sleep,
) -> dict[str, Any]:
    """Create one bounded backup attempt and return BACKUP_READY evidence."""

    sealed = validate_backup_bindings(bindings)
    if (
        not callable(runner)
        or type(health_attempts) is not int
        or type(health_attempts) is bool
        or not 1 <= health_attempts <= MAX_HEALTH_ATTEMPTS
        or type(health_interval_seconds) not in {int, float}
        or type(health_interval_seconds) is bool
        or not math.isfinite(health_interval_seconds)
        or not 0 <= health_interval_seconds <= 60
        or not callable(sleeper)
    ):
        _raise_invalid()
    _verify_host_bindings(sealed)
    with _open_transaction(transaction_directory) as (
        transaction,
        transaction_descriptor,
        _binding,
    ):
        ledger = _load_or_create_ledger(transaction_descriptor, sealed)
        ledger, ready = _reconcile_attempt_ledger(
            transaction,
            transaction_descriptor,
            sealed,
            ledger,
            runner,
            health_attempts=health_attempts,
            health_interval_seconds=float(health_interval_seconds),
            sleeper=sleeper,
        )
        if ready is not None:
            return validate_backup_receipt(ready, sealed)
        try:
            initial = _observe_backend(runner, sealed)
        except Exception as error:
            raise BackupError(_RECOVERY_FAILED) from error
        if initial["status"] != "running" or initial["health"] != "healthy":
            raise BackupError(_RECOVERY_FAILED)
        if len(ledger["entries"]) >= MAX_BACKUP_ATTEMPTS:
            raise BackupError(_EXHAUSTED)
        number = len(ledger["entries"]) + 1
        attempt = _create_attempt(
            transaction,
            transaction_descriptor,
            sealed,
            number,
        )
        backup_error: Exception | None = None
        recovery_error: Exception | None = None
        bundle_digest: str | None = None
        stop_attempted = False
        try:
            stop_attempted = True
            _runner_ack(runner, "stop_backend", sealed)
            stopped = _observe_backend(runner, sealed)
            if stopped["status"] != "exited":
                raise _ActionError("stop_backend")
            _verify_host_bindings(sealed)
            bundle_digest = _archive_and_verify(
                runner,
                attempt,
                number,
                sealed,
            )
        except Exception as error:
            backup_error = error
        finally:
            if stop_attempted:
                try:
                    _recover_backend(
                        runner,
                        sealed,
                        health_attempts=health_attempts,
                        health_interval_seconds=float(health_interval_seconds),
                        sleeper=sleeper,
                    )
                except Exception as error:
                    recovery_error = error
        if recovery_error is not None:
            raise BackupError(_RECOVERY_FAILED) from recovery_error
        if backup_error is not None:
            _quarantine_attempt(
                transaction,
                transaction_descriptor,
                sealed,
                number,
            )
            _append_ledger_entry(
                transaction_descriptor,
                sealed,
                ledger,
                number,
                "failed",
            )
            raise BackupError(_FAILED) from backup_error
        if bundle_digest is None:
            _raise_invalid()
        receipt = _receipt_document(
            sealed,
            number,
            bundle_digest,
            ledger["entries"],
        )
        with _open_attempt_directory(attempt, transaction) as descriptor:
            _write_immutable_json(
                descriptor,
                ATTEMPT_RECEIPT_FILE,
                receipt,
            )
        _append_ledger_entry(
            transaction_descriptor,
            sealed,
            ledger,
            number,
            "backup_ready",
        )
        return validate_backup_receipt(receipt, sealed)


__all__ = [
    "ATTEMPT_MARKER_FILE",
    "ATTEMPT_RECEIPT_FILE",
    "BACKUP_BINDINGS_CONTRACT",
    "BACKUP_BUNDLE_DIRECTORY",
    "BACKUP_LEDGER_FILE",
    "BACKUP_RECEIPT_CONTRACT",
    "BackupBindings",
    "BackupError",
    "BackupFileBinding",
    "MAX_BACKUP_ATTEMPTS",
    "MAX_HEALTH_ATTEMPTS",
    "run_backup_attempt",
    "validate_backup_bindings",
    "validate_backup_receipt",
]
