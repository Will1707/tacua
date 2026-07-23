# SPDX-License-Identifier: Apache-2.0

"""Fail-closed single-node deployment, recovery, and smoke-test tooling."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import sqlite3
import ssl
import stat
import sys
import tempfile
from typing import Any, Callable, Iterator, Sequence
import urllib.error
import urllib.parse
import urllib.request

from . import SDK_BACKEND_PROTOCOL, __version__
from .config import (
    ConfigError,
    MAX_ADMIN_SECRET_FILE_BYTES,
    MAX_CONFIG_BYTES,
    PilotConfig,
    _parse_json_integer,
    _parse_config_json,
    _reject_duplicate_keys,
    _reject_json_float,
    _validate_json_strings,
    load_admin_secret,
    load_config,
    load_public_config,
    parse_admin_secret,
    parse_config_text,
)
from .instance_lock import (
    LOCK_FILE_NAME,
    InstanceLockError,
    acquire_state_instance_lock,
)


BACKUP_CONTRACT = "tacua.operator-backup@2.0.0"
BACKUP_EVIDENCE_RETENTION_CONTRACT = (
    "tacua.operator-backup-evidence-retention@1.0.0"
)
BACKUP_MANIFEST = "manifest.json"
BACKUP_CONFIG = "config.json"
BACKUP_ADMIN_SECRET = "admin-secret"
BACKUP_STATE = "state"
MAX_BACKUP_MANIFEST_BYTES = 16_777_216
MAX_SMOKE_RESPONSE_BYTES = 2_097_152
# The Compose verifier copies the stopped SQLite database and WAL into an
# ephemeral container tmpfs before opening either file. Keep the accepted V1
# state comfortably below that tmpfs ceiling so SQLite has bounded scratch
# headroom for recovery and integrity inspection.
MAX_COMPOSE_STATE_DATABASE_COPY_BYTES = 536_870_912
COMPOSE_STATE_VERIFICATION_SCRATCH = Path("/tmp")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_SEMANTIC_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$"
)
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_IMMUTABLE_IMAGE = re.compile(r"^\S+@sha256:[a-f0-9]{64}$")
_COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_INGRESS_IMAGE = (
    "docker.io/library/haproxy:3.2.21-alpine3.24@"
    "sha256:66e25cc9a8332635f4e897f7f4b1e5622c25f09f0ee23cddc6ce9bdb3a24772a"
)
_INGRESS_CONFIG_DIGEST = (
    "sha256:11c31e6d3e163a22c0d688b8a0c7570d1a715e9c7e0b7785fed02968e08a0643"
)
_INGRESS_CONFIG_TARGET = "/usr/local/etc/haproxy/haproxy.cfg"
_COMPOSE_HEALTHCHECK = [
    "CMD",
    "python",
    "-c",
    (
        "import json,urllib.request; "
        "d=json.load(urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)); "
        "assert d['status']=='ok' and d['retention_worker_running'] and "
        "d['pending_deletions']==0 and d['retention_last_failed_sessions']==0"
    ),
]
_INGRESS_HEALTHCHECK = [
    "CMD",
    "sh",
    "-ec",
    (
        "wget -qO- -T 2 http://127.0.0.1:8080/healthz "
        "| grep -q '\"status\":\"ok\"' "
        "&& wget -qO- -T 2 http://127.0.0.1:8080/ "
        "| grep -Fq '<div id=\"root\"></div>'"
    ),
]
_REVIEWER_HEALTHCHECK = [
    "CMD",
    "python",
    "-c",
    (
        "import urllib.request; "
        "r=urllib.request.urlopen('http://127.0.0.1:8081/', timeout=2); "
        "assert r.status==200 and r.headers['Cache-Control']=='no-store' and "
        "r.headers['X-Content-Type-Options']=='nosniff'"
    ),
]


class OperatorError(RuntimeError):
    """Stable operator-facing failure that never includes secret content."""


def _canonical_json(value: Any, omitted: str | None = None) -> str:
    if isinstance(value, dict) and omitted is not None:
        value = {key: child for key, child in value.items() if key != omitted}
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _digest_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _digest_json(value: Any, omitted: str | None = None) -> str:
    return _digest_bytes(_canonical_json(value, omitted).encode("utf-8"))


def _parse_strict_json_object(
    payload: bytes,
    *,
    maximum_bytes: int,
    label: str,
) -> dict[str, Any]:
    if len(payload) > maximum_bytes:
        raise OperatorError(f"{label} exceeds its byte limit")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise OperatorError(f"{label} must not contain a UTF-8 BOM")
    try:
        serialized = payload.decode("utf-8", errors="strict")
        value = json.loads(
            serialized,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ConfigError("non-finite numbers are forbidden")
            ),
            parse_float=_reject_json_float,
            parse_int=_parse_json_integer,
        )
        if not isinstance(value, dict):
            raise OperatorError(f"{label} root must be an object")
        _validate_json_strings(value)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ConfigError,
        RecursionError,
    ) as exc:
        raise OperatorError(f"{label} is not strict JSON") from exc
    return value


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _current_utc() -> datetime:
    current = _now_utc()
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise OperatorError("operator clock must provide an aware UTC timestamp")
    return current.astimezone(timezone.utc)


def _timestamp_now() -> str:
    return _current_utc().replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise OperatorError(f"{label} is invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise OperatorError(f"{label} is invalid") from exc


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise OperatorError(f"{label} has an invalid object shape")
    return value


def _bounded_regular_bytes(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow:
        flags |= no_follow
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OperatorError(f"{label} cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OperatorError(f"{label} must be one regular file")
        if metadata.st_size > maximum:
            raise OperatorError(f"{label} exceeds its byte limit")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum:
            raise OperatorError(f"{label} exceeds its byte limit")
        final_metadata = os.fstat(descriptor)
        if (
            final_metadata.st_size != metadata.st_size
            or final_metadata.st_mtime_ns != metadata.st_mtime_ns
            or final_metadata.st_ino != metadata.st_ino
        ):
            raise OperatorError(f"{label} changed while it was read")
        return payload
    finally:
        os.close(descriptor)


def _inspect_protected_directory_chain(
    directory: Path,
    *,
    label: str,
    private_leaf: bool,
) -> None:
    try:
        resolved = directory.resolve(strict=True)
    except OSError as exc:
        raise OperatorError(f"{label} directory chain cannot be inspected") from exc

    lexical = Path(os.path.abspath(directory))
    current = Path(lexical.anchor)
    lexical_parts = lexical.parts[1:]
    for index, part in enumerate(lexical_parts):
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise OperatorError(
                f"{label} directory chain cannot be inspected"
            ) from exc
        leaf = index == len(lexical_parts) - 1
        permissions = stat.S_IMODE(metadata.st_mode)
        owner_allowed = metadata.st_uid in {0, os.geteuid()}
        sticky_writable = (
            permissions & 0o022
            and permissions & stat.S_ISVTX
            and owner_allowed
        )
        if stat.S_ISLNK(metadata.st_mode):
            if leaf or metadata.st_uid != 0:
                raise OperatorError(
                    f"{label} path contains an unsafe lexical symlink"
                )
            continue
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or not owner_allowed
            or (
                leaf
                and (
                    metadata.st_uid != os.geteuid()
                    or (
                        permissions != 0o700
                        if private_leaf
                        else permissions & 0o022
                    )
                )
            )
            or (not leaf and permissions & 0o022 and not sticky_writable)
        ):
            raise OperatorError(
                f"{label} path must have a protected operator/root-owned "
                "lexical directory chain"
            )

    current = resolved
    leaf = True
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise OperatorError(
                f"{label} directory chain cannot be inspected"
            ) from exc
        permissions = stat.S_IMODE(metadata.st_mode)
        owner_allowed = metadata.st_uid in {0, os.geteuid()}
        sticky_writable = (
            permissions & 0o022
            and permissions & stat.S_ISVTX
            and owner_allowed
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or not owner_allowed
            or (
                leaf
                and (
                    metadata.st_uid != os.geteuid()
                    or (
                        permissions != 0o700
                        if private_leaf
                        else permissions & 0o022
                    )
                )
            )
            or (not leaf and permissions & 0o022 and not sticky_writable)
        ):
            raise OperatorError(
                f"{label} path must have a protected operator/root-owned "
                "directory chain"
            )
        if current.parent == current:
            break
        current = current.parent
        leaf = False


def _inspect_input_directory(directory: Path) -> None:
    _inspect_protected_directory_chain(
        directory,
        label="administrator input",
        private_leaf=True,
    )


def _inspect_host_file(path: Path, label: str, *, secret: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise OperatorError(f"{label} cannot be inspected") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise OperatorError(f"{label} must be one non-symlink regular file")
    if metadata.st_uid != os.geteuid():
        raise OperatorError(f"{label} must be owned by the preflight user")
    permissions = stat.S_IMODE(metadata.st_mode)
    _inspect_input_directory(path.parent)
    if secret:
        if permissions != 0o444:
            raise OperatorError("admin secret must be mode 0444")
    elif permissions != 0o644:
        raise OperatorError("public config must be mode 0644")


def _inspect_public_deployment_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise OperatorError(f"{label} cannot be inspected") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        raise OperatorError(
            f"{label} must be one mode-0644 file in a safe operator-owned directory"
        )
    _inspect_protected_directory_chain(
        path.parent,
        label=label,
        private_leaf=False,
    )


def create_admin_secret(destination: Path) -> dict[str, Any]:
    """Create one opaque Compose-readable secret without exposing its bytes."""

    if destination.exists() or destination.is_symlink():
        raise OperatorError("administrator secret destination already exists")
    # Reuse the preflight directory boundary before generating any secret bytes.
    _inspect_input_directory(destination.parent)
    payload = secrets.token_urlsafe(48).encode("ascii")
    parse_admin_secret(payload)
    _write_file(destination, payload, 0o444)
    _inspect_host_file(destination, "admin secret", secret=True)
    return {
        "status": "ok",
        "destination": str(destination),
    }


def _validate_state_database(
    state_directory: Path,
    *,
    expected_deployment_pin_digest: str | None = None,
) -> str:
    database = state_directory / "tacua.sqlite3"
    try:
        metadata = database.lstat()
    except OSError as exc:
        raise OperatorError("state backup requires tacua.sqlite3") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise OperatorError("state database must be a regular file")
    uri = f"{database.as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=10)
        try:
            result = connection.execute("PRAGMA quick_check").fetchall()
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            pin_row = connection.execute(
                "SELECT pin_json FROM deployment_pin WHERE singleton = 1"
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise OperatorError("state database failed read-only integrity inspection") from exc
    if result != [("ok",)] or version != 2 or pin_row is None:
        raise OperatorError("state database is not one healthy Tacua schema-v2 database")
    try:
        pin_json = pin_row[0]
        if not isinstance(pin_json, str):
            raise OperatorError("state deployment pin is invalid")
        pin = _parse_config_json(pin_json)
    except ConfigError as exc:
        raise OperatorError("state deployment pin is invalid") from exc
    if pin_json != _canonical_json(pin):
        raise OperatorError("state deployment pin is not canonical")
    pin_digest = _digest_json(pin)
    if (
        expected_deployment_pin_digest is not None
        and pin_digest != expected_deployment_pin_digest
    ):
        raise OperatorError("state deployment pin differs from the supplied config")
    return pin_digest


def _state_evidence_retention(state_directory: Path) -> dict[str, Any]:
    """Project the earliest evidence deadline from every retained session row."""

    database = state_directory / "tacua.sqlite3"
    try:
        metadata = database.lstat()
    except OSError as exc:
        raise OperatorError("state backup requires tacua.sqlite3") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise OperatorError("state database must be a regular file")

    uri = f"{database.as_uri()}?mode=ro"
    session_count = 0
    earliest: datetime | None = None
    earliest_text: str | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=10)
        try:
            rows = connection.execute(
                """SELECT raw_media_expires_at,derived_data_expires_at
                     FROM sessions ORDER BY session_id"""
            )
            for raw_expiry, derived_expiry in rows:
                session_count += 1
                if session_count > 9_007_199_254_740_991:
                    raise OperatorError("backup session count exceeds the safe range")
                for value in (raw_expiry, derived_expiry):
                    parsed = _parse_timestamp(
                        value,
                        "state session evidence-retention timestamp",
                    )
                    if earliest is None or parsed < earliest:
                        earliest = parsed
                        earliest_text = value
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise OperatorError(
            "state database evidence retention could not be inspected"
        ) from exc

    return {
        "contract_version": BACKUP_EVIDENCE_RETENTION_CONTRACT,
        "contains_session_evidence": session_count > 0,
        "session_count": session_count,
        "earliest_evidence_expires_at": earliest_text,
    }


def _validate_backup_evidence_retention(value: Any) -> dict[str, Any]:
    retention = _exact(
        value,
        {
            "contract_version",
            "contains_session_evidence",
            "session_count",
            "earliest_evidence_expires_at",
        },
        "backup evidence retention",
    )
    contains = retention["contains_session_evidence"]
    count = retention["session_count"]
    expiry = retention["earliest_evidence_expires_at"]
    if (
        retention["contract_version"] != BACKUP_EVIDENCE_RETENTION_CONTRACT
        or not isinstance(contains, bool)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        or count > 9_007_199_254_740_991
    ):
        raise OperatorError("backup evidence retention metadata is invalid")
    if count == 0:
        if contains or expiry is not None:
            raise OperatorError("empty backup evidence retention metadata is invalid")
    else:
        if not contains or expiry is None:
            raise OperatorError("backup evidence retention metadata is incomplete")
        _parse_timestamp(expiry, "backup evidence-retention deadline")
    return retention


def _validate_relative_path(value: Any, *, prefix: str | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 4_096:
        raise OperatorError("backup manifest contains an invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise OperatorError("backup manifest path escapes the recovery bundle")
    if prefix is not None and path.parts[0] != prefix:
        raise OperatorError("backup state entry is outside the state directory")
    return value


def _copy_file(
    source: Path,
    destination: Path,
    mode: int,
    *,
    require_service_owner: bool = True,
    maximum_bytes: int | None = None,
) -> tuple[int, str]:
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
    )
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow:
        source_flags |= no_follow
        destination_flags |= no_follow
    try:
        source_descriptor = os.open(source, source_flags)
    except OSError as exc:
        raise OperatorError("backup source file cannot be opened safely") from exc
    destination_descriptor = -1
    try:
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (require_service_owner and before.st_uid != os.geteuid())
            or (require_service_owner and stat.S_IMODE(before.st_mode) & 0o077)
        ):
            raise OperatorError(
                "backup state files must be private, service-owned, non-linked regular files"
            )
        if (
            maximum_bytes is not None
            and (
                isinstance(maximum_bytes, bool)
                or maximum_bytes < 0
                or before.st_size > maximum_bytes
            )
        ):
            raise OperatorError(
                "state database copy exceeds the V1 verification byte bound"
            )
        destination_descriptor = os.open(
            destination,
            destination_flags,
            mode,
        )
        hasher = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(source_descriptor, 1_048_576)
            if not chunk:
                break
            hasher.update(chunk)
            size += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                view = view[written:]
        os.fchmod(destination_descriptor, mode)
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
        if (
            after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or size != before.st_size
        ):
            raise OperatorError("backup source changed while it was copied")
        return size, "sha256:" + hasher.hexdigest()
    except OSError as exc:
        raise OperatorError("backup file copy could not be made durable") from exc
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        os.close(source_descriptor)


def _validate_state_database_copy(
    state_directory: Path,
    *,
    require_service_owner: bool,
    expected_deployment_pin_digest: str | None = None,
    maximum_copy_bytes: int | None = None,
    scratch_directory: Path | None = None,
) -> tuple[str, dict[str, Any]]:
    """Quick-check a disposable database/WAL copy, never the source state."""

    with tempfile.TemporaryDirectory(
        prefix="tacua-database-check-",
        dir=scratch_directory,
    ) as temporary:
        destination = Path(temporary)
        database_copy_options: dict[str, Any] = {
            "require_service_owner": require_service_owner,
        }
        if maximum_copy_bytes is not None:
            database_copy_options["maximum_bytes"] = maximum_copy_bytes
        database_size, _database_digest = _copy_file(
            state_directory / "tacua.sqlite3",
            destination / "tacua.sqlite3",
            0o600,
            **database_copy_options,
        )
        remaining = (
            None
            if maximum_copy_bytes is None
            else maximum_copy_bytes - database_size
        )
        wal = state_directory / "tacua.sqlite3-wal"
        try:
            wal.lstat()
        except FileNotFoundError:
            pass
        else:
            wal_copy_options: dict[str, Any] = {
                "require_service_owner": require_service_owner,
            }
            if remaining is not None:
                wal_copy_options["maximum_bytes"] = remaining
            _copy_file(
                wal,
                destination / "tacua.sqlite3-wal",
                0o600,
                **wal_copy_options,
            )
        pin_digest = _validate_state_database(
            destination,
            expected_deployment_pin_digest=expected_deployment_pin_digest,
        )
        return pin_digest, _state_evidence_retention(destination)


def _write_file(path: Path, payload: bytes, mode: int) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    created = False
    try:
        descriptor = os.open(path, flags, mode)
        created = True
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise OperatorError("recovery metadata could not be written durably") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _atomic_new_directory(target: Path) -> Iterator[Path]:
    if target.exists() or target.is_symlink():
        raise OperatorError("recovery destination already exists")
    parent = target.parent
    _inspect_protected_directory_chain(
        parent,
        label="recovery destination",
        private_leaf=False,
    )
    temporary = Path(tempfile.mkdtemp(prefix=f".{target.name}.staging-", dir=parent))
    temporary.chmod(0o700)
    published = False
    try:
        yield temporary
        for directory in sorted(
            (path for path in temporary.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            _fsync_directory(directory)
        _fsync_directory(temporary)
        os.replace(temporary, target)
        published = True
        _fsync_directory(parent)
    except OSError as exc:
        raise OperatorError("recovery directory could not be published durably") from exc
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)


def _state_entries(state_directory: Path) -> tuple[list[Path], list[Path]]:
    directories: list[Path] = []
    files: list[Path] = []
    for root, directory_names, file_names in os.walk(
        state_directory,
        topdown=True,
        followlinks=False,
    ):
        root_path = Path(root)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            path = root_path / name
            metadata = path.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                raise OperatorError(
                    "state backup encountered an unsafe, non-private, or foreign-owned directory"
                )
            directories.append(path)
        for name in file_names:
            if root_path == state_directory and name in {
                LOCK_FILE_NAME,
                "tacua.sqlite3-shm",
            }:
                continue
            path = root_path / name
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                raise OperatorError(
                    "state backup encountered an unsafe, non-private, or foreign-owned file"
                )
            files.append(path)
    return directories, files


def create_backup(
    config_file: Path,
    admin_secret_file: Path,
    output_directory: Path,
) -> dict[str, Any]:
    """Create an atomic, mode-0700 offline recovery bundle."""

    config_payload = _bounded_regular_bytes(
        config_file,
        MAX_CONFIG_BYTES,
        "public config",
    )
    secret_payload = _bounded_regular_bytes(
        admin_secret_file,
        MAX_ADMIN_SECRET_FILE_BYTES,
        "admin secret",
    )
    try:
        config = parse_config_text(config_payload.decode("utf-8", errors="strict"))
        secret = parse_admin_secret(secret_payload)
    except (UnicodeDecodeError, ConfigError) as exc:
        raise OperatorError("config or administrator secret is invalid") from exc
    state_directory = config.state_directory
    try:
        output_directory.resolve(strict=False).relative_to(
            state_directory.resolve(strict=True)
        )
    except ValueError:
        pass
    else:
        raise OperatorError("backup destination must be outside backend state")

    with acquire_state_instance_lock(
        state_directory,
        create_directory=False,
    ):
        directories, files = _state_entries(state_directory)
        with _atomic_new_directory(output_directory) as staging:
            state_staging = staging / BACKUP_STATE
            state_staging.mkdir(mode=0o700)
            directory_names = [BACKUP_STATE]
            for source in directories:
                relative = source.relative_to(state_directory)
                destination = state_staging / relative
                destination.mkdir(mode=0o700)
                directory_names.append(
                    (PurePosixPath(BACKUP_STATE) / relative.as_posix()).as_posix()
                )

            records: list[dict[str, Any]] = []
            _write_file(staging / BACKUP_CONFIG, config_payload, 0o600)
            _write_file(staging / BACKUP_ADMIN_SECRET, secret_payload, 0o600)
            records.extend(
                [
                    {
                        "path": BACKUP_CONFIG,
                        "size_bytes": len(config_payload),
                        "content_digest": _digest_bytes(config_payload),
                    },
                    {
                        "path": BACKUP_ADMIN_SECRET,
                        "size_bytes": len(secret_payload),
                        "content_digest": _digest_bytes(secret_payload),
                    },
                ]
            )
            for source in files:
                relative = source.relative_to(state_directory)
                destination = state_staging / relative
                size, content_digest = _copy_file(source, destination, 0o600)
                records.append(
                    {
                        "path": (
                            PurePosixPath(BACKUP_STATE) / relative.as_posix()
                        ).as_posix(),
                        "size_bytes": size,
                        "content_digest": content_digest,
                    }
                )

            _, evidence_retention = _validate_state_database_copy(
                state_staging,
                require_service_owner=True,
                expected_deployment_pin_digest=_digest_json(config.deployment_pin),
            )
            if (
                _bounded_regular_bytes(config_file, MAX_CONFIG_BYTES, "public config")
                != config_payload
                or _bounded_regular_bytes(
                    admin_secret_file,
                    MAX_ADMIN_SECRET_FILE_BYTES,
                    "admin secret",
                )
                != secret_payload
                or parse_admin_secret(secret_payload) != secret
            ):
                raise OperatorError(
                    "config or administrator secret changed during backup"
                )

            records.sort(key=lambda record: record["path"])
            directory_names.sort()
            manifest: dict[str, Any] = {
                "contract_version": BACKUP_CONTRACT,
                "created_at": _timestamp_now(),
                "backend_version": __version__,
                "protocol_version": SDK_BACKEND_PROTOCOL,
                "configured_state_directory": str(state_directory),
                "deployment_pin_digest": _digest_json(config.deployment_pin),
                "evidence_retention": evidence_retention,
                "directories": directory_names,
                "files": records,
                "state_file_count": len(files),
                "state_total_bytes": sum(
                    record["size_bytes"]
                    for record in records
                    if record["path"].startswith(f"{BACKUP_STATE}/")
                ),
                "backup_digest": "",
            }
            manifest["backup_digest"] = _digest_json(manifest, "backup_digest")
            _write_file(
                staging / BACKUP_MANIFEST,
                _canonical_json(manifest).encode("utf-8"),
                0o600,
            )
            verify_backup(staging)
        return manifest


def _read_backup_manifest(backup_directory: Path) -> dict[str, Any]:
    payload = _bounded_regular_bytes(
        backup_directory / BACKUP_MANIFEST,
        MAX_BACKUP_MANIFEST_BYTES,
        "backup manifest",
    )
    manifest = _parse_strict_json_object(
        payload,
        maximum_bytes=MAX_BACKUP_MANIFEST_BYTES,
        label="backup manifest",
    )
    if payload != _canonical_json(manifest).encode("utf-8"):
        raise OperatorError("backup manifest is not canonical JSON")
    return manifest


def verify_backup(backup_directory: Path) -> dict[str, Any]:
    """Verify every recovery-bundle byte without changing the source bundle."""

    try:
        root_metadata = backup_directory.lstat()
    except OSError as exc:
        raise OperatorError("backup directory cannot be inspected") from exc
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise OperatorError("backup must be one private user-owned directory")
    manifest = _exact(
        _read_backup_manifest(backup_directory),
        {
            "contract_version",
            "created_at",
            "backend_version",
            "protocol_version",
            "configured_state_directory",
            "deployment_pin_digest",
            "evidence_retention",
            "directories",
            "files",
            "state_file_count",
            "state_total_bytes",
            "backup_digest",
        },
        "backup manifest",
    )
    if (
        manifest["contract_version"] != BACKUP_CONTRACT
        or manifest["protocol_version"] != SDK_BACKEND_PROTOCOL
        or not isinstance(manifest["backend_version"], str)
        or _SEMANTIC_VERSION.fullmatch(manifest["backend_version"]) is None
        or not _TIMESTAMP.fullmatch(str(manifest["created_at"]))
        or not _DIGEST.fullmatch(str(manifest["deployment_pin_digest"]))
        or not _DIGEST.fullmatch(str(manifest["backup_digest"]))
        or manifest["backup_digest"] != _digest_json(manifest, "backup_digest")
    ):
        raise OperatorError("backup manifest identity or digest is invalid")
    created_at = _parse_timestamp(manifest["created_at"], "backup manifest timestamp")
    evidence_retention = _validate_backup_evidence_retention(
        manifest["evidence_retention"]
    )
    evidence_expiry = evidence_retention["earliest_evidence_expires_at"]
    if (
        evidence_expiry is not None
        and _parse_timestamp(
            evidence_expiry,
            "backup evidence-retention deadline",
        )
        <= created_at
    ):
        raise OperatorError(
            "backup was created at or after its evidence-retention deadline"
        )
    configured_state = Path(str(manifest["configured_state_directory"]))
    if not configured_state.is_absolute() or configured_state == Path(
        configured_state.anchor
    ):
        raise OperatorError("backup manifest state directory is invalid")

    directories = manifest["directories"]
    records = manifest["files"]
    if (
        not isinstance(directories, list)
        or not isinstance(records, list)
        or len(records) > 100_000
        or len(directories) > 100_000
    ):
        raise OperatorError("backup manifest entry lists are invalid")
    directory_names = [_validate_relative_path(value) for value in directories]
    if (
        directory_names != sorted(directory_names)
        or len(set(directory_names)) != len(directory_names)
        or BACKUP_STATE not in directory_names
        or any(
            name != BACKUP_STATE and not name.startswith(f"{BACKUP_STATE}/")
            for name in directory_names
        )
    ):
        raise OperatorError("backup directory list is invalid")

    expected_files = {BACKUP_MANIFEST}
    state_count = 0
    state_total = 0
    for raw_record in records:
        record = _exact(
            raw_record,
            {"path", "size_bytes", "content_digest"},
            "backup file record",
        )
        name = _validate_relative_path(record["path"])
        if name in expected_files or name == f"{BACKUP_STATE}/{LOCK_FILE_NAME}":
            raise OperatorError("backup file paths are duplicated or reserved")
        if name not in {BACKUP_CONFIG, BACKUP_ADMIN_SECRET} and not name.startswith(
            f"{BACKUP_STATE}/"
        ):
            raise OperatorError("backup contains a file outside its closed layout")
        size = record["size_bytes"]
        content_digest = record["content_digest"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > 9_007_199_254_740_991
            or not isinstance(content_digest, str)
            or not _DIGEST.fullmatch(content_digest)
        ):
            raise OperatorError("backup file record metadata is invalid")
        path = backup_directory / name
        payload_size = 0
        hasher = hashlib.sha256()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if getattr(os, "O_NOFOLLOW", 0):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise OperatorError("backup contains an unsafe file")
                while True:
                    chunk = os.read(descriptor, 1_048_576)
                    if not chunk:
                        break
                    payload_size += len(chunk)
                    hasher.update(chunk)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise OperatorError("backup file cannot be read safely") from exc
        if (
            payload_size != size
            or "sha256:" + hasher.hexdigest() != content_digest
        ):
            raise OperatorError("backup file bytes differ from the manifest")
        expected_files.add(name)
        if name.startswith(f"{BACKUP_STATE}/"):
            state_count += 1
            state_total += size

    actual_directories: set[str] = set()
    actual_files: set[str] = set()
    for root, directory_children, file_children in os.walk(
        backup_directory,
        topdown=True,
        followlinks=False,
    ):
        root_path = Path(root)
        for name in directory_children:
            path = root_path / name
            metadata = path.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise OperatorError("backup contains an unsafe directory")
            actual_directories.add(path.relative_to(backup_directory).as_posix())
        for name in file_children:
            path = root_path / name
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise OperatorError("backup contains an unsafe file")
            actual_files.add(path.relative_to(backup_directory).as_posix())
    if actual_directories != set(directory_names) or actual_files != expected_files:
        raise OperatorError("backup layout contains unmanifested entries")
    if (
        manifest["state_file_count"] != state_count
        or manifest["state_total_bytes"] != state_total
    ):
        raise OperatorError("backup state totals differ from its file records")

    try:
        config = load_public_config(backup_directory / BACKUP_CONFIG)
        secret = load_admin_secret(backup_directory / BACKUP_ADMIN_SECRET)
    except ConfigError as exc:
        raise OperatorError("backup config or administrator secret is invalid") from exc
    if (
        str(config.state_directory) != manifest["configured_state_directory"]
        or _digest_json(config.deployment_pin) != manifest["deployment_pin_digest"]
        or not secret
    ):
        raise OperatorError("backup deployment pin does not match its config")
    _, actual_evidence_retention = _validate_state_database_copy(
        backup_directory / BACKUP_STATE,
        require_service_owner=False,
        expected_deployment_pin_digest=manifest["deployment_pin_digest"],
    )
    if actual_evidence_retention != evidence_retention:
        raise OperatorError(
            "backup evidence retention metadata differs from its state database"
        )
    if evidence_expiry is not None and _current_utc() >= _parse_timestamp(
        evidence_expiry,
        "backup evidence-retention deadline",
    ):
        raise OperatorError("backup evidence retention deadline has expired")
    return {
        "status": "ok",
        "contract_version": BACKUP_CONTRACT,
        "created_at": manifest["created_at"],
        "backup_digest": manifest["backup_digest"],
        "evidence_retention": evidence_retention,
        "state_file_count": state_count,
        "state_total_bytes": state_total,
    }


def restore_backup(
    backup_directory: Path,
    destination: Path,
    *,
    apply: bool,
) -> dict[str, Any]:
    """Verify by default; with apply, atomically create one new recovery root."""

    result = verify_backup(backup_directory)
    if not apply:
        return {**result, "applied": False}
    try:
        destination.resolve(strict=False).relative_to(backup_directory.resolve())
    except ValueError:
        pass
    else:
        raise OperatorError("restore destination must be outside the backup")
    with _atomic_new_directory(destination) as staging:
        directories = sorted(
            (path for path in backup_directory.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
        )
        for source in directories:
            relative = source.relative_to(backup_directory)
            (staging / relative).mkdir(mode=0o700)
        files = sorted(path for path in backup_directory.rglob("*") if path.is_file())
        for source in files:
            relative = source.relative_to(backup_directory)
            _copy_file(
                source,
                staging / relative,
                0o600,
                require_service_owner=False,
            )
        # The source was verified before copying, but it can still change
        # between that check and an individual copy. Verify the completed
        # staging tree before the context atomically publishes it.
        if verify_backup(staging) != result:
            raise OperatorError("backup identity changed during restore")
    if verify_backup(destination) != result:
        raise OperatorError("published recovery identity changed")
    return {**result, "applied": True, "destination": str(destination)}


def prepare_compose_inputs(
    recovery_directory: Path,
    destination: Path,
) -> dict[str, Any]:
    """Publish verified recovery config/secret bytes in Compose-readable modes."""

    result = verify_backup(recovery_directory)
    with _atomic_new_directory(destination) as staging:
        _copy_file(
            recovery_directory / BACKUP_CONFIG,
            staging / BACKUP_CONFIG,
            0o644,
        )
        _copy_file(
            recovery_directory / BACKUP_ADMIN_SECRET,
            staging / BACKUP_ADMIN_SECRET,
            0o444,
        )
        # The recovery set was verified before copying, but it can still change
        # between that check and a copy. Re-verify the complete source identity,
        # then validate the exact host paths and bytes that Compose will consume.
        if verify_backup(recovery_directory) != result:
            raise OperatorError("recovery identity changed while inputs were prepared")
        _inspect_host_file(staging / BACKUP_CONFIG, "public config", secret=False)
        _inspect_host_file(
            staging / BACKUP_ADMIN_SECRET,
            "admin secret",
            secret=True,
        )
        load_config(
            staging / BACKUP_CONFIG,
            staging / BACKUP_ADMIN_SECRET,
        )
    _inspect_host_file(destination / BACKUP_CONFIG, "public config", secret=False)
    _inspect_host_file(
        destination / BACKUP_ADMIN_SECRET,
        "admin secret",
        secret=True,
    )
    return {
        "status": "ok",
        "backup_digest": result["backup_digest"],
        "destination": str(destination),
    }


def _validate_compose_service_common(
    service: dict[str, Any],
    *,
    label: str,
    user: str,
    pids_limit: int,
    healthcheck_test: list[str],
) -> None:
    deploy = service.get("deploy")
    if (
        not isinstance(deploy, dict)
        or not {"replicas"} <= set(deploy) <= {
            "placement",
            "replicas",
            "resources",
        }
        or deploy.get("replicas") != 1
        or deploy.get("placement", {}) != {}
        or deploy.get("resources", {}) != {}
        or service.get("user") != user
        or service.get("read_only") is not True
        or service.get("init") is not True
        or service.get("cap_drop") != ["ALL"]
        or service.get("security_opt") != ["no-new-privileges:true"]
        or service.get("pids_limit") != pids_limit
        or service.get("stop_grace_period") != "30s"
        or service.get("restart") != "unless-stopped"
        or service.get("command") is not None
        or service.get("entrypoint") is not None
    ):
        raise OperatorError(f"{label} Compose process isolation is incomplete")
    logging = service.get("logging")
    if logging != {
        "driver": "json-file",
        "options": {"max-file": "3", "max-size": "10m"},
    }:
        raise OperatorError(f"{label} Compose logs must have bounded rotation")
    healthcheck = service.get("healthcheck")
    if healthcheck != {
        "interval": "30s",
        "retries": 3,
        "start_period": "5s",
        "test": healthcheck_test,
        "timeout": "3s",
    }:
        raise OperatorError(f"{label} Compose health check is missing or weakened")


def validate_compose_document(
    document: Any,
    config: PilotConfig,
    *,
    require_immutable_image: bool,
    expected_repository_root: Path | None = None,
    expected_published_port: int | None = None,
) -> dict[str, Any]:
    """Validate the resolved Compose model, not hand-written YAML text."""

    if (
        not isinstance(document, dict)
        or set(document)
        != {"configs", "name", "networks", "secrets", "services", "volumes"}
        or not isinstance(document.get("services"), dict)
        or set(document["services"]) != {"backend", "ingress", "reviewer"}
    ):
        raise OperatorError(
            "resolved Compose must contain only backend, reviewer, and ingress"
        )
    backend = document["services"].get("backend")
    ingress = document["services"].get("ingress")
    reviewer = document["services"].get("reviewer")
    if (
        not isinstance(backend, dict)
        or not isinstance(ingress, dict)
        or not isinstance(reviewer, dict)
    ):
        raise OperatorError("resolved Compose services are invalid")
    project_name = document.get("name")
    if (
        not isinstance(project_name, str)
        or _COMPOSE_PROJECT.fullmatch(project_name) is None
    ):
        raise OperatorError("resolved Compose project identity is invalid")

    backend_keys = {
        "cap_drop",
        "command",
        "deploy",
        "entrypoint",
        "healthcheck",
        "image",
        "init",
        "logging",
        "networks",
        "pids_limit",
        "read_only",
        "restart",
        "secrets",
        "security_opt",
        "stop_grace_period",
        "user",
        "volumes",
    }
    if backend.get("build") is not None:
        backend_keys.add("build")
    reviewer_keys = {
        "cap_drop",
        "command",
        "deploy",
        "entrypoint",
        "healthcheck",
        "image",
        "init",
        "logging",
        "networks",
        "pids_limit",
        "read_only",
        "restart",
        "security_opt",
        "stop_grace_period",
        "user",
    }
    if reviewer.get("build") is not None:
        reviewer_keys.add("build")
    ingress_keys = {
        "cap_drop",
        "command",
        "configs",
        "depends_on",
        "deploy",
        "entrypoint",
        "healthcheck",
        "image",
        "init",
        "logging",
        "networks",
        "pids_limit",
        "ports",
        "read_only",
        "restart",
        "security_opt",
        "stop_grace_period",
        "user",
    }
    if (
        set(backend) != backend_keys
        or set(ingress) != ingress_keys
        or set(reviewer) != reviewer_keys
    ):
        raise OperatorError("resolved Compose services contain unexpected authority")
    backend_build = backend.get("build")
    repository_root = (
        _REPOSITORY_ROOT
        if expected_repository_root is None
        else expected_repository_root
    )
    if backend_build is not None and backend_build != {
        "context": str(repository_root),
        "dockerfile": "services/backend/Dockerfile",
    }:
        raise OperatorError("backend build authority differs from the repository root")
    reviewer_build = reviewer.get("build")
    if reviewer_build is not None and reviewer_build != {
        "context": str(_REPOSITORY_ROOT),
        "dockerfile": "services/reviewer-web/Dockerfile",
    }:
        raise OperatorError("reviewer build authority differs from the repository root")

    _validate_compose_service_common(
        backend,
        label="backend",
        user="10001:10001",
        pids_limit=128,
        healthcheck_test=_COMPOSE_HEALTHCHECK,
    )
    _validate_compose_service_common(
        ingress,
        label="ingress",
        user="99:99",
        pids_limit=64,
        healthcheck_test=_INGRESS_HEALTHCHECK,
    )
    _validate_compose_service_common(
        reviewer,
        label="reviewer",
        user="10002:10002",
        pids_limit=64,
        healthcheck_test=_REVIEWER_HEALTHCHECK,
    )
    if backend.get("ports") or backend.get("depends_on") or backend.get("configs"):
        raise OperatorError("backend must not publish or join the ingress authority")
    if ingress.get("volumes") or ingress.get("secrets") or ingress.get("build"):
        raise OperatorError("ingress must not receive state, config, or secret authority")
    if any(
        reviewer.get(field)
        for field in ("configs", "depends_on", "ports", "secrets", "volumes")
    ):
        raise OperatorError("reviewer must not receive deployment authority")

    networks = document.get("networks")
    if not isinstance(networks, dict) or set(networks) != {
        "tacua-default-deny",
        "tacua-loopback-publish",
    }:
        raise OperatorError("resolved Compose networks are not closed")
    private_network = networks["tacua-default-deny"]
    publish_network = networks["tacua-loopback-publish"]
    allowed_network_keys = {"driver", "external", "internal", "ipam", "name"}
    if (
        not isinstance(private_network, dict)
        or not set(private_network) <= allowed_network_keys
        or private_network.get("internal") is not True
        or private_network.get("external", False) is not False
        or private_network.get("driver") not in {None, "bridge"}
        or private_network.get("ipam", {}) != {}
        or private_network.get("name")
        != f"{project_name}_tacua-default-deny"
        or not isinstance(publish_network, dict)
        or not set(publish_network) <= allowed_network_keys
        or publish_network.get("internal", False) is not False
        or publish_network.get("external", False) is not False
        or publish_network.get("driver") not in {None, "bridge"}
        or publish_network.get("ipam", {}) != {}
        or publish_network.get("name")
        != f"{project_name}_tacua-loopback-publish"
    ):
        raise OperatorError("Compose networks violate the closed bridge topology")
    if backend.get("networks") != {"tacua-default-deny": None}:
        raise OperatorError("backend must join only the egress-denied network")
    if reviewer.get("networks") != {"tacua-default-deny": None}:
        raise OperatorError("reviewer must join only the egress-denied network")
    if ingress.get("networks") != {
        "tacua-default-deny": None,
        "tacua-loopback-publish": None,
    }:
        raise OperatorError("ingress must bridge only the private and publish networks")

    if ingress.get("depends_on") != {
        "backend": {
            "condition": "service_healthy",
            "required": True,
            "restart": True,
        },
        "reviewer": {
            "condition": "service_healthy",
            "required": True,
            "restart": True,
        },
    }:
        raise OperatorError("ingress must wait for the healthy backend and reviewer")
    ports = ingress.get("ports")
    if not isinstance(ports, list) or len(ports) != 1:
        raise OperatorError("ingress must publish one loopback port")
    port = ports[0]
    published = port.get("published") if isinstance(port, dict) else None
    selected_published_port = (
        config.listen_port
        if expected_published_port is None
        else expected_published_port
    )
    if (
        type(selected_published_port) is not int
        or not 1 <= selected_published_port <= 65_535
        or (
            require_immutable_image
            and selected_published_port != config.listen_port
        )
        or not isinstance(port, dict)
        or port.get("host_ip") != "127.0.0.1"
        or port.get("protocol") != "tcp"
        or port.get("mode") != "ingress"
        or port.get("target") != config.listen_port
        or published != str(selected_published_port)
    ):
        raise OperatorError("ingress listener must be published only on host loopback")

    ingress_configs = ingress.get("configs")
    if ingress_configs != [
        {
            "source": "tacua_loopback_ingress",
            "target": _INGRESS_CONFIG_TARGET,
        }
    ]:
        raise OperatorError("ingress must receive only the fixed HAProxy config")
    top_configs = document.get("configs")
    ingress_definition = (
        top_configs.get("tacua_loopback_ingress")
        if isinstance(top_configs, dict)
        else None
    )
    if (
        not isinstance(top_configs, dict)
        or set(top_configs) != {"tacua_loopback_ingress"}
        or not isinstance(ingress_definition, dict)
        or not {"file"} <= set(ingress_definition) <= {"file", "name"}
        or not isinstance(ingress_definition.get("file"), str)
        or not ingress_definition["file"]
        or ingress_definition.get("name")
        != f"{project_name}_tacua_loopback_ingress"
        or _digest_bytes(
            _bounded_regular_bytes(
                Path(ingress_definition["file"]),
                MAX_CONFIG_BYTES,
                "ingress config",
            )
        )
        != _INGRESS_CONFIG_DIGEST
    ):
        raise OperatorError("ingress config bytes or definition are not pinned")

    volumes = backend.get("volumes")
    if not isinstance(volumes, list) or len(volumes) != 2:
        raise OperatorError("backend Compose volumes are missing")
    by_target = {
        volume.get("target"): volume
        for volume in volumes
        if isinstance(volume, dict) and isinstance(volume.get("target"), str)
    }
    state_mount = by_target.get(str(config.state_directory))
    config_mount = by_target.get("/run/tacua/config.json")
    expected_state_mount = {
        "source": "tacua-state",
        "target": str(config.state_directory),
        "type": "volume",
    }
    if (
        not isinstance(state_mount, dict)
        or {
            key: value
            for key, value in state_mount.items()
            if key != "volume"
        }
        != expected_state_mount
        or frozenset(state_mount) not in {
            frozenset(expected_state_mount),
            frozenset({*expected_state_mount, "volume"}),
        }
        or state_mount.get("volume", {}) != {}
        or not isinstance(config_mount, dict)
        or set(config_mount)
        != {"bind", "read_only", "source", "target", "type"}
        or config_mount.get("bind")
        not in ({}, {"create_host_path": False})
        or config_mount.get("read_only") is not True
        or not isinstance(config_mount.get("source"), str)
        or not config_mount["source"]
        or config_mount.get("target") != "/run/tacua/config.json"
        or config_mount.get("type") != "bind"
        or set(by_target)
        != {
            str(config.state_directory),
            "/run/tacua/config.json",
        }
    ):
        raise OperatorError("backend state/config mounts violate the closed layout")
    top_volumes = document.get("volumes")
    if (
        not isinstance(top_volumes, dict)
        or set(top_volumes) != {"tacua-state"}
        or not isinstance(top_volumes["tacua-state"], dict)
        or not set(top_volumes["tacua-state"]) <= {"driver", "name"}
        or top_volumes["tacua-state"].get("driver") not in {None, "local"}
        or top_volumes["tacua-state"].get("name")
        != f"{project_name}_tacua-state"
    ):
        raise OperatorError("backend state volume definition is not closed")

    mounted_secrets = backend.get("secrets")
    if (
        not isinstance(mounted_secrets, list)
        or mounted_secrets
        != [{"source": "tacua_admin", "target": "/run/secrets/tacua_admin"}]
    ):
        raise OperatorError("backend must mount one administrator secret")
    top_secrets = document.get("secrets")
    secret_definition = (
        top_secrets.get("tacua_admin") if isinstance(top_secrets, dict) else None
    )
    if (
        not isinstance(top_secrets, dict)
        or set(top_secrets) != {"tacua_admin"}
        or not isinstance(secret_definition, dict)
        or not {"file"} <= set(secret_definition) <= {"file", "name"}
        or not isinstance(secret_definition.get("file"), str)
        or not secret_definition["file"]
        or secret_definition.get("name") != f"{project_name}_tacua_admin"
    ):
        raise OperatorError("backend Compose secret definition is not one file")

    backend_image = backend.get("image")
    reviewer_image = reviewer.get("image")
    if (
        not isinstance(backend_image, str)
        or not isinstance(reviewer_image, str)
        or ingress.get("image") != _INGRESS_IMAGE
        or (
            require_immutable_image
            and (
                _IMMUTABLE_IMAGE.fullmatch(backend_image) is None
                or backend.get("build") is not None
                or _IMMUTABLE_IMAGE.fullmatch(reviewer_image) is None
                or reviewer.get("build") is not None
            )
        )
    ):
        raise OperatorError("Compose image identities are not pinned as required")
    return {
        "status": "ok",
        "replicas": 1,
        "topology": "loopback-ingress",
        "publisher_service": "ingress",
        "published_host": port["host_ip"],
        "published_port": published,
        "image": backend_image,
        "reviewer_image": reviewer_image,
        "ingress_image": _INGRESS_IMAGE,
        "immutable_image": (
            _IMMUTABLE_IMAGE.fullmatch(backend_image) is not None
            and _IMMUTABLE_IMAGE.fullmatch(reviewer_image) is not None
        ),
    }


def deployment_preflight(
    config_file: Path,
    admin_secret_file: Path,
    compose_document: Any,
    *,
    require_immutable_image: bool,
    check_state: bool,
    expected_repository_root: Path | None = None,
    expected_published_port: int | None = None,
) -> dict[str, Any]:
    _inspect_host_file(config_file, "public config", secret=False)
    _inspect_host_file(admin_secret_file, "admin secret", secret=True)
    try:
        same_input_directory = config_file.parent.samefile(
            admin_secret_file.parent
        )
    except OSError as exc:
        raise OperatorError(
            "administrator input directory identity cannot be verified"
        ) from exc
    if not same_input_directory:
        raise OperatorError(
            "public config and admin secret must share one private input directory"
        )
    config, _secret = load_config(config_file, admin_secret_file)
    if not config.backend_origin.startswith("https://"):
        raise OperatorError("production backend_origin must use HTTPS")
    if config.listen_host != "0.0.0.0":
        raise OperatorError("container listener must bind 0.0.0.0 behind host loopback")
    compose = validate_compose_document(
        compose_document,
        config,
        require_immutable_image=require_immutable_image,
        expected_repository_root=expected_repository_root,
        expected_published_port=expected_published_port,
    )
    ingress_definition = compose_document["configs"]["tacua_loopback_ingress"]
    ingress_config_file = Path(ingress_definition["file"])
    _inspect_public_deployment_file(ingress_config_file, "ingress config")
    if (
        _digest_bytes(
            _bounded_regular_bytes(
                ingress_config_file,
                MAX_CONFIG_BYTES,
                "ingress config",
            )
        )
        != _INGRESS_CONFIG_DIGEST
    ):
        raise OperatorError("ingress config changed after Compose validation")
    service = compose_document["services"]["backend"]
    config_mount = next(
        (
            volume
            for volume in service["volumes"]
            if volume.get("target") == "/run/tacua/config.json"
        ),
        None,
    )
    secret_mount = service["secrets"][0]
    compose_secrets = compose_document.get("secrets")
    secret_definition = (
        compose_secrets.get(secret_mount.get("source"))
        if isinstance(compose_secrets, dict)
        else None
    )
    if (
        not isinstance(config_mount, dict)
        or Path(str(config_mount.get("source"))).resolve()
        != config_file.resolve()
        or not isinstance(secret_definition, dict)
        or Path(str(secret_definition.get("file"))).resolve()
        != admin_secret_file.resolve()
    ):
        raise OperatorError(
            "resolved Compose config/secret sources differ from preflight inputs"
        )
    state_checked = False
    if check_state:
        with acquire_state_instance_lock(
            config.state_directory,
            create_directory=False,
        ):
            _state_entries(config.state_directory)
            _validate_state_database_copy(
                config.state_directory,
                require_service_owner=True,
                expected_deployment_pin_digest=_digest_json(
                    config.deployment_pin
                ),
            )
        state_checked = True
    return {
        "status": "ok",
        "backend_origin": config.backend_origin,
        "config_digest": _digest_bytes(
            _bounded_regular_bytes(config_file, MAX_CONFIG_BYTES, "public config")
        ),
        "deployment_pin_digest": _digest_json(config.deployment_pin),
        "state_checked_offline": state_checked,
        "compose": compose,
        "operator_supplied": [
            "domain_dns",
            "tls_certificate_and_reverse_proxy",
            "host_firewall",
            "off_host_encrypted_backup_storage",
        ],
    }


def verify_compose_state(
    config_file: Path,
    state_directory: Path,
) -> dict[str, Any]:
    """Verify one stopped Compose state mount against its sealed public config."""

    config = load_public_config(config_file)
    configured_state = Path(config.state_directory)
    if state_directory != configured_state:
        raise OperatorError(
            "state verification path must equal the configured container mount"
        )
    with acquire_state_instance_lock(
        state_directory,
        create_directory=False,
    ):
        _state_entries(state_directory)
        state_pin, _retention = _validate_state_database_copy(
            state_directory,
            require_service_owner=True,
            expected_deployment_pin_digest=_digest_json(config.deployment_pin),
            maximum_copy_bytes=MAX_COMPOSE_STATE_DATABASE_COPY_BYTES,
            scratch_directory=COMPOSE_STATE_VERIFICATION_SCRATCH,
        )
    return {
        "status": "ok",
        "config_digest": _digest_bytes(
            _bounded_regular_bytes(
                config_file,
                MAX_CONFIG_BYTES,
                "public config",
            )
        ),
        "deployment_pin_digest": state_pin,
        "state_directory": str(state_directory),
    }


def check_compose_state_copy_bound(
    state_directory: Path,
) -> dict[str, Any]:
    """Reject a running Compose state that already exceeds verifier scratch."""

    total = 0
    for name, required in (
        ("tacua.sqlite3", True),
        ("tacua.sqlite3-wal", False),
    ):
        path = state_directory / name
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os,
            "O_NOFOLLOW",
            0,
        )
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            if required:
                raise OperatorError(
                    "state database is unavailable for copy-bound preflight"
                )
            continue
        except OSError as exc:
            raise OperatorError(
                "state database cannot be inspected for copy-bound preflight"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_size < 0
            ):
                raise OperatorError(
                    "state database identity is invalid for copy-bound preflight"
                )
            total += metadata.st_size
        finally:
            os.close(descriptor)
    if total > MAX_COMPOSE_STATE_DATABASE_COPY_BYTES:
        raise OperatorError(
            "state database exceeds the V1 verification byte bound"
        )
    return {
        "status": "ok",
        "maximum_bytes": MAX_COMPOSE_STATE_DATABASE_COPY_BYTES,
    }


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        _request: urllib.request.Request,
        _file_pointer: Any,
        _code: int,
        _message: str,
        _headers: Any,
        _new_url: str,
    ) -> None:
        raise OperatorError("configured origin returned a forbidden redirect")


def _read_smoke_json(
    opener: urllib.request.OpenerDirector,
    endpoint: str,
    *,
    authorization: str | None,
) -> dict[str, Any]:
    headers = {"Accept": "application/json", "Cache-Control": "no-store"}
    if authorization is not None:
        headers["Authorization"] = f"Bearer {authorization}"
    request = urllib.request.Request(endpoint, method="GET", headers=headers)
    try:
        response = opener.open(request, timeout=10)
        with response:
            if response.status != 200 or response.geturl() != endpoint:
                raise OperatorError("smoke endpoint returned an unexpected status or URL")
            if response.headers.get("Content-Type", "").lower() != "application/json":
                raise OperatorError("smoke endpoint returned an unexpected content type")
            declared = response.headers.get("Content-Length")
            if (
                declared is None
                or not re.fullmatch(r"(?:0|[1-9][0-9]{0,6})", declared)
                or int(declared) < 1
                or int(declared) > MAX_SMOKE_RESPONSE_BYTES
            ):
                raise OperatorError("smoke endpoint returned an invalid byte declaration")
            payload = response.read(MAX_SMOKE_RESPONSE_BYTES + 1)
    except OperatorError:
        raise
    except urllib.error.HTTPError as exc:
        raise OperatorError(f"smoke endpoint failed with HTTP {exc.code}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise OperatorError("smoke endpoint could not be reached securely") from exc
    if len(payload) != int(declared):
        raise OperatorError("smoke endpoint bytes differ from Content-Length")
    try:
        return _parse_config_json(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ConfigError) as exc:
        raise OperatorError("smoke endpoint returned invalid strict JSON") from exc


def smoke_deployment(
    config_file: Path,
    admin_secret_file: Path,
    *,
    origin_override: str | None,
    allow_loopback_http: bool,
    opener_factory: Callable[[ssl.SSLContext], urllib.request.OpenerDirector]
    | None = None,
) -> dict[str, Any]:
    config, secret = load_config(config_file, admin_secret_file)
    origin = (origin_override or config.backend_origin).rstrip("/")
    parsed = urllib.parse.urlsplit(origin)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise OperatorError("smoke origin must contain only an origin")
    if origin != config.backend_origin and not (
        allow_loopback_http and loopback and parsed.scheme == "http"
    ):
        raise OperatorError("smoke origin must equal the configured HTTPS origin")
    if parsed.scheme != "https" and not (
        allow_loopback_http and loopback and parsed.scheme == "http"
    ):
        raise OperatorError("deployment smoke requires verified HTTPS")

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    factory = opener_factory or (
        lambda tls_context: urllib.request.build_opener(
            _RejectRedirects(),
            urllib.request.HTTPSHandler(context=tls_context),
        )
    )
    opener = factory(context)
    version = _read_smoke_json(opener, f"{origin}/version", authorization=None)
    if (
        set(version) != {"service", "version", "protocol_version"}
        or version["service"] != "tacua-backend"
        or version["protocol_version"] != SDK_BACKEND_PROTOCOL
        or not isinstance(version["version"], str)
        or len(version["version"]) > 64
        or re.fullmatch(
            r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?",
            version["version"],
        )
        is None
    ):
        raise OperatorError("version endpoint does not expose the frozen protocol")
    health = _read_smoke_json(opener, f"{origin}/healthz", authorization=None)
    required_health = {
        "status",
        "service",
        "version",
        "protocol_version",
        "schema_version",
        "sessions",
        "tombstones",
        "pending_deletions",
        "retention_worker_running",
        "retention_last_swept_at",
        "retention_last_deleted_sessions",
        "retention_last_failed_sessions",
    }
    if (
        set(health) != required_health
        or health["status"] != "ok"
        or health["service"] != "tacua-backend"
        or health["version"] != version["version"]
        or health["protocol_version"] != SDK_BACKEND_PROTOCOL
        or health["schema_version"] != 2
        or health["pending_deletions"] != 0
        or health["retention_worker_running"] is not True
        or health["retention_last_failed_sessions"] != 0
        or not _TIMESTAMP.fullmatch(str(health["retention_last_swept_at"]))
    ):
        raise OperatorError("health endpoint reports an unhealthy deployment")
    for key in (
        "sessions",
        "tombstones",
        "pending_deletions",
        "retention_last_deleted_sessions",
        "retention_last_failed_sessions",
    ):
        value = health[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > 9_007_199_254_740_991
        ):
            raise OperatorError("health endpoint contains an invalid count")
    try:
        swept_at = datetime.strptime(
            health["retention_last_swept_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise OperatorError("health endpoint contains an invalid sweep timestamp") from exc
    age = (datetime.now(timezone.utc) - swept_at).total_seconds()
    if age < -300 or age > 2 * config.retention_sweep_interval_seconds + 60:
        raise OperatorError("retention sweep is stale")

    builds = _read_smoke_json(
        opener,
        f"{origin}/v1/admin/builds",
        authorization=secret.decode("utf-8"),
    )
    expected_build = {
        "build_id": config.build_id,
        "application_id": config.application_id,
        "bundle_identifier": config.bundle_identifier,
        "native_version": config.build_identity["native_version"],
        "native_build": config.build_identity["native_build"],
        "distribution": config.build_identity["distribution"],
        "build_identity_digest": config.build_identity_digest,
    }
    if (
        set(builds) != {"builds"}
        or not isinstance(builds["builds"], list)
        or len(builds["builds"]) != 1
        or not isinstance(builds["builds"][0], dict)
        or builds["builds"][0] != expected_build
    ):
        raise OperatorError("authenticated smoke did not return the pinned build")
    return {
        "status": "ok",
        "origin": origin,
        "backend_version": version["version"],
        "protocol_version": SDK_BACKEND_PROTOCOL,
        "retention_last_swept_at": health["retention_last_swept_at"],
        "build_id": config.build_id,
    }


def _load_compose_json(path: Path) -> dict[str, Any]:
    if str(path) == "-":
        payload = sys.stdin.buffer.read(MAX_CONFIG_BYTES + 1)
    else:
        payload = _bounded_regular_bytes(path, MAX_CONFIG_BYTES, "Compose JSON")
    if len(payload) > MAX_CONFIG_BYTES:
        raise OperatorError("resolved Compose JSON exceeds the 2 MiB limit")
    try:
        return _parse_config_json(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ConfigError) as exc:
        raise OperatorError("resolved Compose model is not strict JSON") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and recover one self-hosted Tacua node",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--config-file", required=True, type=Path)
    preflight.add_argument("--admin-secret-file", required=True, type=Path)
    preflight.add_argument("--compose-json", required=True, type=Path)
    preflight.add_argument("--allow-mutable-image", action="store_true")
    preflight.add_argument("--check-state", action="store_true")

    create_secret = subparsers.add_parser("create-admin-secret")
    create_secret.add_argument("--destination", required=True, type=Path)

    compose = subparsers.add_parser("validate-compose")
    compose.add_argument("--config-file", required=True, type=Path)
    compose.add_argument("--compose-json", required=True, type=Path)
    compose.add_argument("--allow-mutable-image", action="store_true")
    compose.add_argument("--expected-published-port", type=int)

    backup = subparsers.add_parser("backup")
    backup.add_argument("--config-file", required=True, type=Path)
    backup.add_argument("--admin-secret-file", required=True, type=Path)
    backup.add_argument("--output", required=True, type=Path)

    verify = subparsers.add_parser("verify-backup")
    verify.add_argument("backup", type=Path)

    restore = subparsers.add_parser("restore")
    restore.add_argument("backup", type=Path)
    restore.add_argument("--destination", required=True, type=Path)
    restore.add_argument("--apply", action="store_true")

    prepare = subparsers.add_parser("prepare-compose-inputs")
    prepare.add_argument("recovery", type=Path)
    prepare.add_argument("--destination", required=True, type=Path)

    verify_state = subparsers.add_parser("verify-compose-state")
    verify_state.add_argument("--config-file", required=True, type=Path)
    verify_state.add_argument("--state-directory", required=True, type=Path)

    copy_bound = subparsers.add_parser("check-compose-state-copy-bound")
    copy_bound.add_argument("--state-directory", required=True, type=Path)

    smoke = subparsers.add_parser("smoke")
    smoke.add_argument("--config-file", required=True, type=Path)
    smoke.add_argument("--admin-secret-file", required=True, type=Path)
    smoke.add_argument("--origin")
    smoke.add_argument("--allow-loopback-http", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    args = _parser().parse_args(argv)
    try:
        if args.command == "preflight":
            result = deployment_preflight(
                args.config_file,
                args.admin_secret_file,
                _load_compose_json(args.compose_json),
                require_immutable_image=not args.allow_mutable_image,
                check_state=args.check_state,
            )
        elif args.command == "create-admin-secret":
            result = create_admin_secret(args.destination)
        elif args.command == "validate-compose":
            config = load_public_config(args.config_file)
            result = validate_compose_document(
                _load_compose_json(args.compose_json),
                config,
                require_immutable_image=not args.allow_mutable_image,
                expected_published_port=args.expected_published_port,
            )
        elif args.command == "backup":
            result = create_backup(
                args.config_file,
                args.admin_secret_file,
                args.output,
            )
        elif args.command == "verify-backup":
            result = verify_backup(args.backup)
        elif args.command == "restore":
            result = restore_backup(
                args.backup,
                args.destination,
                apply=args.apply,
            )
        elif args.command == "prepare-compose-inputs":
            result = prepare_compose_inputs(
                args.recovery,
                args.destination,
            )
        elif args.command == "verify-compose-state":
            result = verify_compose_state(
                args.config_file,
                args.state_directory,
            )
        elif args.command == "check-compose-state-copy-bound":
            result = check_compose_state_copy_bound(
                args.state_directory,
            )
        elif args.command == "smoke":
            result = smoke_deployment(
                args.config_file,
                args.admin_secret_file,
                origin_override=args.origin,
                allow_loopback_http=args.allow_loopback_http,
            )
        else:  # pragma: no cover - argparse owns the closed command set
            raise OperatorError("unknown operator command")
        print(_canonical_json(result))
        return 0
    except (ConfigError, InstanceLockError, OperatorError, OSError) as exc:
        print(f"operator error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
