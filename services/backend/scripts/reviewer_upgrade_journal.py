#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Durable, fail-closed journal primitives for reviewer-only upgrades.

The module deliberately owns only the journal envelope and its filesystem
publication rules.  Upgrade orchestration supplies the transaction-specific
plan and checkpoint details as bounded JSON objects.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any, Iterator, NoReturn


PLAN_CONTRACT = "tacua.reviewer-upgrade-plan@1.0.0"
PROGRESS_CONTRACT = "tacua.reviewer-upgrade-progress@1.0.0"
RECEIPT_CONTRACT = "tacua.reviewer-upgrade-receipt@1.0.0"

PLAN_FILE = "plan.json"
PROGRESS_FILE = "progress.json"
RECEIPT_FILE = "receipt.json"

PHASES = (
    "prepared",
    "quiescing",
    "maintenance",
    "backing_up",
    "backup_ready",
    "replacing",
    "reviewer_ready",
    "sealing",
    "sealed_maintenance",
    "promoting",
    "scheduled_maintenance",
    "activating",
    "complete",
)
_PHASE_INDEX = {phase: index for index, phase in enumerate(PHASES)}

MAX_DOCUMENT_BYTES = 256 * 1024
MAX_STRING_BYTES = 8 * 1024
MAX_KEY_BYTES = 128
MAX_COLLECTION_ITEMS = 512
MAX_DEPTH = 20
MAX_NODES = 16_384
MAX_INTEGER = (1 << 63) - 1
MAX_SEQUENCE = MAX_INTEGER

_DIGEST_PREFIX = "sha256:"
_DIGEST_LENGTH = len(_DIGEST_PREFIX) + 64
_ERROR = "REVIEWER_UPGRADE_JOURNAL_INVALID"
_EXISTS = "REVIEWER_UPGRADE_JOURNAL_EXISTS"


class JournalError(RuntimeError):
    """A stable, content-free journal error."""

    def __init__(self, code: str = _ERROR) -> None:
        super().__init__(code)
        self.code = code


def _raise_invalid() -> NoReturn:
    raise JournalError(_ERROR)


def _validate_text(value: str, *, key: bool = False) -> str:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise JournalError(_ERROR) from error
    limit = MAX_KEY_BYTES if key else MAX_STRING_BYTES
    if len(encoded) > limit or any(ord(character) < 0x20 for character in value):
        _raise_invalid()
    return value


def _bounded_json_copy(value: Any) -> Any:
    budget = [MAX_NODES]

    def visit(item: Any, depth: int) -> Any:
        if depth > MAX_DEPTH:
            _raise_invalid()
        budget[0] -= 1
        if budget[0] < 0:
            _raise_invalid()
        if item is None or type(item) is bool:
            return item
        if type(item) is int:
            if not -MAX_INTEGER <= item <= MAX_INTEGER:
                _raise_invalid()
            return item
        if type(item) is float:
            _raise_invalid()
        if type(item) is str:
            return _validate_text(item)
        if type(item) is list:
            if len(item) > MAX_COLLECTION_ITEMS:
                _raise_invalid()
            return [visit(child, depth + 1) for child in item]
        if type(item) is dict:
            if len(item) > MAX_COLLECTION_ITEMS:
                _raise_invalid()
            result: dict[str, Any] = {}
            for raw_key, child in item.items():
                if type(raw_key) is not str:
                    _raise_invalid()
                key = _validate_text(raw_key, key=True)
                result[key] = visit(child, depth + 1)
            return result
        _raise_invalid()

    return visit(value, 0)


def _mapping_copy(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if type(value) is not dict:
        _raise_invalid()
    copied = _bounded_json_copy(value)
    if type(copied) is not dict:
        _raise_invalid()
    return copied


def canonical_json(value: Any) -> bytes:
    """Return the one accepted ASCII JSON representation of ``value``."""

    bounded = _bounded_json_copy(value)
    try:
        payload = json.dumps(
            bounded,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise JournalError(_ERROR) from error
    if not payload or len(payload) > MAX_DOCUMENT_BYTES:
        _raise_invalid()
    return payload


def _digest(payload: bytes) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(payload).hexdigest()


def _valid_digest(value: Any) -> bool:
    if type(value) is not str or len(value) != _DIGEST_LENGTH:
        return False
    if not value.startswith(_DIGEST_PREFIX):
        return False
    return all(character in "0123456789abcdef" for character in value[7:])


def _document_digest(document: Mapping[str, Any], field: str) -> str:
    subject = dict(document)
    subject.pop(field, None)
    return _digest(canonical_json(subject))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _raise_invalid()
        result[key] = value
    return result


def _parse_integer(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise JournalError(_ERROR) from error
    if not -MAX_INTEGER <= parsed <= MAX_INTEGER:
        _raise_invalid()
    return parsed


def _reject_number(_value: str) -> NoReturn:
    _raise_invalid()


def parse_canonical_json(payload: bytes) -> Any:
    """Parse canonical journal JSON, rejecting alternate JSON spellings."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > MAX_DOCUMENT_BYTES
    ):
        _raise_invalid()
    if payload.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        _raise_invalid()
    try:
        decoded = payload.decode("ascii", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_number,
            parse_float=_reject_number,
            parse_int=_parse_integer,
        )
    except JournalError:
        raise
    except (UnicodeError, ValueError, RecursionError, json.JSONDecodeError) as error:
        raise JournalError(_ERROR) from error
    bounded = _bounded_json_copy(value)
    if canonical_json(bounded) != payload:
        _raise_invalid()
    return bounded


def _path_value(path: Path | os.PathLike[str] | str) -> Path:
    try:
        value = os.fspath(path)
    except TypeError as error:
        raise JournalError(_ERROR) from error
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or value.startswith("//")
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
    ):
        _raise_invalid()
    candidate = Path(value)
    if Path(os.path.abspath(value)) != candidate:
        _raise_invalid()
    return candidate


def _validate_ancestor(path: Path, *, leaf: bool) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise JournalError(_ERROR) from error
    permissions = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
    ):
        _raise_invalid()
    if leaf:
        if metadata.st_uid != os.geteuid() or permissions != 0o700:
            _raise_invalid()
    elif permissions & 0o022 and not (
        metadata.st_uid in {0, os.geteuid()} and permissions & stat.S_ISVTX
    ):
        _raise_invalid()
    return metadata


def _validate_directory_path(path: Path) -> os.stat_result:
    try:
        if path.resolve(strict=True) != path:
            _raise_invalid()
    except OSError as error:
        raise JournalError(_ERROR) from error
    current = path
    leaf = True
    while True:
        metadata = _validate_ancestor(current, leaf=leaf)
        if current.parent == current:
            return metadata if leaf else path.lstat()
        current = current.parent
        leaf = False


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
        raise JournalError(_ERROR) from error
    for metadata in (opened, current):
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            _raise_invalid()
    expected_identity = (expected.st_dev, expected.st_ino)
    if (opened.st_dev, opened.st_ino) != expected_identity or (
        current.st_dev,
        current.st_ino,
    ) != expected_identity:
        _raise_invalid()


@contextmanager
def _open_transaction_directory(
    path: Path | os.PathLike[str] | str,
) -> Iterator[tuple[Path, int, os.stat_result]]:
    directory = _path_value(path)
    expected = _validate_directory_path(directory)
    try:
        descriptor = os.open(directory, _directory_flags())
    except OSError as error:
        raise JournalError(_ERROR) from error
    try:
        _assert_directory_binding(descriptor, directory, expected)
        yield directory, descriptor, expected
        _assert_directory_binding(descriptor, directory, expected)
    finally:
        os.close(descriptor)


def _validate_parent_directory(path: Path) -> tuple[int, os.stat_result]:
    parent = path.parent
    try:
        if parent.resolve(strict=True) != parent:
            _raise_invalid()
    except OSError as error:
        raise JournalError(_ERROR) from error
    current = parent
    while True:
        _validate_ancestor(current, leaf=False)
        if current.parent == current:
            break
        current = current.parent
    descriptor: int | None = None
    try:
        descriptor = os.open(parent, _directory_flags())
        metadata = os.fstat(descriptor)
        lexical = parent.lstat()
    except OSError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise JournalError(_ERROR) from error
    if (metadata.st_dev, metadata.st_ino) != (lexical.st_dev, lexical.st_ino):
        os.close(descriptor)
        _raise_invalid()
    return descriptor, metadata


def create_transaction_directory(
    path: Path | os.PathLike[str] | str,
) -> Path:
    """Create and durably publish one new owner-private transaction directory."""

    directory = _path_value(path)
    try:
        name_size = len(directory.name.encode("utf-8", errors="strict"))
    except UnicodeError as error:
        raise JournalError(_ERROR) from error
    if not directory.name or name_size > 255:
        _raise_invalid()
    parent_descriptor, parent_metadata = _validate_parent_directory(directory)
    try:
        try:
            os.mkdir(directory.name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError as error:
            raise JournalError(_EXISTS) from error
        os.fsync(parent_descriptor)
        current_parent = directory.parent.lstat()
        if (current_parent.st_dev, current_parent.st_ino) != (
            parent_metadata.st_dev,
            parent_metadata.st_ino,
        ):
            _raise_invalid()
    except JournalError:
        raise
    except OSError as error:
        raise JournalError(_ERROR) from error
    finally:
        os.close(parent_descriptor)
    return validate_transaction_directory(directory)


def validate_transaction_directory(
    path: Path | os.PathLike[str] | str,
) -> Path:
    """Validate and return the canonical transaction directory path."""

    with _open_transaction_directory(path) as (directory, _descriptor, _binding):
        return directory


def _file_metadata_tuple(metadata: os.stat_result) -> tuple[int, ...]:
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


def _file_exists(directory_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    except OSError as error:
        raise JournalError(_ERROR) from error


def _recover_interrupted_immutable_publication(
    directory_descriptor: int,
    name: str,
) -> None:
    if name not in {PLAN_FILE, RECEIPT_FILE}:
        return
    try:
        final = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    except OSError as error:
        raise JournalError(_ERROR) from error
    if final.st_nlink == 1:
        return
    if (
        final.st_nlink != 2
        or not stat.S_ISREG(final.st_mode)
        or final.st_uid != os.geteuid()
        or stat.S_IMODE(final.st_mode) != 0o600
    ):
        return
    pattern = re.compile(
        rf"\.{re.escape(name)}\.next-[0-9]+-[0-9a-f]{{12}}\Z"
    )
    try:
        entries = os.listdir(directory_descriptor)
    except OSError as error:
        raise JournalError(_ERROR) from error
    if len(entries) > MAX_COLLECTION_ITEMS:
        _raise_invalid()
    matches: list[str] = []
    for entry in entries:
        if type(entry) is not str or pattern.fullmatch(entry) is None:
            continue
        try:
            candidate = os.stat(
                entry,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise JournalError(_ERROR) from error
        if (candidate.st_dev, candidate.st_ino) == (
            final.st_dev,
            final.st_ino,
        ):
            matches.append(entry)
    if len(matches) != 1:
        return
    try:
        os.unlink(matches[0], dir_fd=directory_descriptor)
        os.fsync(directory_descriptor)
        repaired = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise JournalError(_ERROR) from error
    if (
        repaired.st_nlink != 1
        or (repaired.st_dev, repaired.st_ino) != (final.st_dev, final.st_ino)
        or not stat.S_ISREG(repaired.st_mode)
        or repaired.st_uid != os.geteuid()
        or stat.S_IMODE(repaired.st_mode) != 0o600
    ):
        _raise_invalid()


def _read_private_file(directory_descriptor: int, name: str) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    _recover_interrupted_immutable_publication(directory_descriptor, name)
    try:
        lexical = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as error:
        raise JournalError(_ERROR) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > MAX_DOCUMENT_BYTES
            or (lexical.st_dev, lexical.st_ino) != (before.st_dev, before.st_ino)
        ):
            _raise_invalid()
        payload = bytearray()
        while len(payload) <= MAX_DOCUMENT_BYTES:
            block = os.read(
                descriptor,
                min(65_536, MAX_DOCUMENT_BYTES + 1 - len(payload)),
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
            or len(payload) > MAX_DOCUMENT_BYTES
            or _file_metadata_tuple(after) != _file_metadata_tuple(before)
            or _file_metadata_tuple(current) != _file_metadata_tuple(after)
        ):
            _raise_invalid()
        return bytes(payload)
    except OSError as error:
        raise JournalError(_ERROR) from error
    finally:
        os.close(descriptor)


def _optional_private_file(directory_descriptor: int, name: str) -> bytes | None:
    if not _file_exists(directory_descriptor, name):
        return None
    return _read_private_file(directory_descriptor, name)


def _lock_exclusive(directory_descriptor: int) -> None:
    try:
        fcntl.flock(directory_descriptor, fcntl.LOCK_EX)
    except OSError as error:
        raise JournalError(_ERROR) from error


def _atomic_private_write(
    directory_path: Path,
    directory_descriptor: int,
    directory_binding: os.stat_result,
    name: str,
    payload: bytes,
    *,
    replace: bool,
    expected_payload: bytes | None = None,
) -> None:
    if name not in {PLAN_FILE, PROGRESS_FILE, RECEIPT_FILE}:
        _raise_invalid()
    if not payload or len(payload) > MAX_DOCUMENT_BYTES:
        _raise_invalid()
    temporary = f".{name}.next-{os.getpid()}-{secrets.token_hex(6)}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    temporary_present = False
    try:
        if replace:
            if expected_payload is None:
                _raise_invalid()
            if _read_private_file(directory_descriptor, name) != expected_payload:
                _raise_invalid()
        elif _file_exists(directory_descriptor, name):
            raise JournalError(_EXISTS)
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
                    raise OSError("journal write stopped")
                offset += written
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                _raise_invalid()
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _assert_directory_binding(
            directory_descriptor,
            directory_path,
            directory_binding,
        )
        if replace:
            if _read_private_file(directory_descriptor, name) != expected_payload:
                _raise_invalid()
        elif _file_exists(directory_descriptor, name):
            raise JournalError(_EXISTS)
        if replace:
            os.replace(
                temporary,
                name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            temporary_present = False
        else:
            try:
                os.link(
                    temporary,
                    name,
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise JournalError(_EXISTS) from error
            os.unlink(temporary, dir_fd=directory_descriptor)
            temporary_present = False
        os.fsync(directory_descriptor)
        if _read_private_file(directory_descriptor, name) != payload:
            _raise_invalid()
    except JournalError:
        raise
    except OSError as error:
        raise JournalError(_ERROR) from error
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
                    raise JournalError(_ERROR) from error


def _plan_document(payload: Mapping[str, Any]) -> dict[str, Any]:
    plan_payload = _mapping_copy(payload)
    if not plan_payload:
        _raise_invalid()
    document: dict[str, Any] = {
        "contract_version": PLAN_CONTRACT,
        "plan": plan_payload,
        "plan_digest": "",
    }
    document["plan_digest"] = _document_digest(document, "plan_digest")
    return _validate_plan(document)


def _validate_plan(value: Any) -> dict[str, Any]:
    document = _bounded_json_copy(value)
    if (
        type(document) is not dict
        or set(document) != {"contract_version", "plan", "plan_digest"}
        or document.get("contract_version") != PLAN_CONTRACT
        or type(document.get("plan")) is not dict
        or not document["plan"]
        or not _valid_digest(document.get("plan_digest"))
        or document["plan_digest"]
        != _document_digest(document, "plan_digest")
    ):
        _raise_invalid()
    canonical_json(document)
    return document


def write_immutable_plan(
    transaction_directory: Path | os.PathLike[str] | str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Immutably publish a self-digested transaction plan."""

    document = _plan_document(payload)
    encoded = canonical_json(document)
    with _open_transaction_directory(transaction_directory) as (
        directory,
        descriptor,
        binding,
    ):
        _lock_exclusive(descriptor)
        _atomic_private_write(
            directory,
            descriptor,
            binding,
            PLAN_FILE,
            encoded,
            replace=False,
        )
        loaded = _load_plan_descriptor(descriptor)
        if loaded != document:
            _raise_invalid()
        return loaded


def write_plan(
    transaction_directory: Path | os.PathLike[str] | str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Compatibility alias for :func:`write_immutable_plan`."""

    return write_immutable_plan(transaction_directory, payload)


def _load_plan_descriptor(directory_descriptor: int) -> dict[str, Any]:
    payload = _read_private_file(directory_descriptor, PLAN_FILE)
    return _validate_plan(parse_canonical_json(payload))


def _assert_plan_descriptor(
    directory_descriptor: int,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    sealed_plan = _validate_plan(plan)
    if _load_plan_descriptor(directory_descriptor) != sealed_plan:
        _raise_invalid()
    return sealed_plan


def load_plan(
    transaction_directory: Path | os.PathLike[str] | str,
) -> dict[str, Any]:
    """Load and verify the immutable transaction plan."""

    with _open_transaction_directory(transaction_directory) as (
        _directory,
        descriptor,
        _binding,
    ):
        _lock_exclusive(descriptor)
        return _load_plan_descriptor(descriptor)


def _validate_progress(value: Any, plan: Mapping[str, Any]) -> dict[str, Any]:
    sealed_plan = _validate_plan(plan)
    document = _bounded_json_copy(value)
    if (
        type(document) is not dict
        or set(document)
        != {
            "contract_version",
            "details",
            "phase",
            "plan_digest",
            "progress_digest",
            "sequence",
        }
        or document.get("contract_version") != PROGRESS_CONTRACT
        or type(document.get("details")) is not dict
        or document.get("phase") not in PHASES
        or document.get("plan_digest") != sealed_plan["plan_digest"]
        or type(document.get("sequence")) is not int
        or type(document["sequence"]) is bool
        or not 1 <= document["sequence"] <= MAX_SEQUENCE
        or not _valid_digest(document.get("progress_digest"))
        or document["progress_digest"]
        != _document_digest(document, "progress_digest")
    ):
        _raise_invalid()
    canonical_json(document)
    return document


def load_progress(
    transaction_directory: Path | os.PathLike[str] | str,
    plan: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Load the latest checkpoint, or return ``None`` before PREPARED."""

    with _open_transaction_directory(transaction_directory) as (
        _directory,
        descriptor,
        _binding,
    ):
        _lock_exclusive(descriptor)
        sealed_plan = _assert_plan_descriptor(descriptor, plan)
        return _load_progress_descriptor(descriptor, sealed_plan)


def _load_progress_descriptor(
    directory_descriptor: int,
    plan: Mapping[str, Any],
) -> dict[str, Any] | None:
    sealed_plan = _validate_plan(plan)
    payload = _optional_private_file(directory_descriptor, PROGRESS_FILE)
    if payload is None:
        return None
    return _validate_progress(parse_canonical_json(payload), sealed_plan)


def checkpoint_progress(
    transaction_directory: Path | os.PathLike[str] | str,
    plan: Mapping[str, Any],
    phase: str,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Atomically publish the next monotonic progress checkpoint."""

    if type(phase) is not str or phase not in PHASES:
        _raise_invalid()
    with _open_transaction_directory(transaction_directory) as (
        directory,
        descriptor,
        binding,
    ):
        _lock_exclusive(descriptor)
        sealed_plan = _assert_plan_descriptor(descriptor, plan)
        previous = _load_progress_descriptor(descriptor, sealed_plan)
        if previous is None:
            if phase != PHASES[0]:
                _raise_invalid()
            sequence = 1
            expected = None
        else:
            if previous["phase"] == PHASES[-1]:
                _raise_invalid()
            if _PHASE_INDEX[phase] < _PHASE_INDEX[previous["phase"]]:
                _raise_invalid()
            sequence = previous["sequence"] + 1
            if sequence > MAX_SEQUENCE:
                _raise_invalid()
            expected = canonical_json(previous)
        document: dict[str, Any] = {
            "contract_version": PROGRESS_CONTRACT,
            "details": _mapping_copy(details),
            "phase": phase,
            "plan_digest": sealed_plan["plan_digest"],
            "progress_digest": "",
            "sequence": sequence,
        }
        document["progress_digest"] = _document_digest(
            document,
            "progress_digest",
        )
        document = _validate_progress(document, sealed_plan)
        encoded = canonical_json(document)
        _atomic_private_write(
            directory,
            descriptor,
            binding,
            PROGRESS_FILE,
            encoded,
            replace=previous is not None,
            expected_payload=expected,
        )
        if _load_progress_descriptor(descriptor, sealed_plan) != document:
            _raise_invalid()
        return document


def _validate_receipt(
    value: Any,
    plan: Mapping[str, Any],
    progress: Mapping[str, Any],
) -> dict[str, Any]:
    sealed_plan = _validate_plan(plan)
    sealed_progress = _validate_progress(progress, sealed_plan)
    document = _bounded_json_copy(value)
    if (
        sealed_progress["phase"] != PHASES[-1]
        or type(document) is not dict
        or set(document)
        != {
            "contract_version",
            "details",
            "phase",
            "plan_digest",
            "progress_digest",
            "receipt_digest",
            "sequence",
        }
        or document.get("contract_version") != RECEIPT_CONTRACT
        or type(document.get("details")) is not dict
        or document.get("phase") != PHASES[-1]
        or document.get("plan_digest") != sealed_plan["plan_digest"]
        or document.get("progress_digest")
        != sealed_progress["progress_digest"]
        or document.get("sequence") != sealed_progress["sequence"]
        or not _valid_digest(document.get("receipt_digest"))
        or document["receipt_digest"]
        != _document_digest(document, "receipt_digest")
    ):
        _raise_invalid()
    canonical_json(document)
    return document


def load_receipt(
    transaction_directory: Path | os.PathLike[str] | str,
    plan: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Load and verify a completion receipt, if one has been published."""

    with _open_transaction_directory(transaction_directory) as (
        _directory,
        descriptor,
        _binding,
    ):
        _lock_exclusive(descriptor)
        sealed_plan = _assert_plan_descriptor(descriptor, plan)
        progress = _load_progress_descriptor(descriptor, sealed_plan)
        payload = _optional_private_file(descriptor, RECEIPT_FILE)
        if payload is None:
            return None
        if progress is None:
            _raise_invalid()
        return _validate_receipt(
            parse_canonical_json(payload),
            sealed_plan,
            progress,
        )


def write_receipt(
    transaction_directory: Path | os.PathLike[str] | str,
    plan: Mapping[str, Any],
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Immutably publish a receipt bound to the COMPLETE checkpoint."""

    with _open_transaction_directory(transaction_directory) as (
        directory,
        descriptor,
        binding,
    ):
        _lock_exclusive(descriptor)
        sealed_plan = _assert_plan_descriptor(descriptor, plan)
        progress = _load_progress_descriptor(descriptor, sealed_plan)
        if progress is None or progress["phase"] != PHASES[-1]:
            _raise_invalid()
        document: dict[str, Any] = {
            "contract_version": RECEIPT_CONTRACT,
            "details": _mapping_copy(details),
            "phase": PHASES[-1],
            "plan_digest": sealed_plan["plan_digest"],
            "progress_digest": progress["progress_digest"],
            "receipt_digest": "",
            "sequence": progress["sequence"],
        }
        document["receipt_digest"] = _document_digest(
            document,
            "receipt_digest",
        )
        document = _validate_receipt(document, sealed_plan, progress)
        encoded = canonical_json(document)
        _atomic_private_write(
            directory,
            descriptor,
            binding,
            RECEIPT_FILE,
            encoded,
            replace=False,
        )
        payload = _read_private_file(descriptor, RECEIPT_FILE)
        loaded = _validate_receipt(
            parse_canonical_json(payload),
            sealed_plan,
            progress,
        )
        if loaded != document:
            _raise_invalid()
        return document


__all__ = [
    "JournalError",
    "MAX_DOCUMENT_BYTES",
    "MAX_STRING_BYTES",
    "PHASES",
    "PLAN_CONTRACT",
    "PLAN_FILE",
    "PROGRESS_CONTRACT",
    "PROGRESS_FILE",
    "RECEIPT_CONTRACT",
    "RECEIPT_FILE",
    "canonical_json",
    "checkpoint_progress",
    "create_transaction_directory",
    "load_plan",
    "load_progress",
    "load_receipt",
    "parse_canonical_json",
    "validate_transaction_directory",
    "write_immutable_plan",
    "write_plan",
    "write_receipt",
]
