#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact Docker adapter for reviewer-upgrade backup runner actions.

The adapter is deliberately command-runner driven.  Construction performs
only local sealed-state validation; callers decide which bounded command
runner may reach Docker.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, NoReturn

if __package__:
    from . import reconcile_compose_deployment as reconciler
    from .reviewer_upgrade_backup import (
        BACKUP_BUNDLE_DIRECTORY,
        MAX_BACKUP_ATTEMPTS,
        BackupBindings,
        validate_backup_bindings,
    )
    from .reviewer_upgrade_journal import (
        JournalError,
        validate_transaction_directory,
    )
else:
    import reconcile_compose_deployment as reconciler  # type: ignore[no-redef]
    from reviewer_upgrade_backup import (  # type: ignore[no-redef]
        BACKUP_BUNDLE_DIRECTORY,
        MAX_BACKUP_ATTEMPTS,
        BackupBindings,
        validate_backup_bindings,
    )
    from reviewer_upgrade_journal import (  # type: ignore[no-redef]
        JournalError,
        validate_transaction_directory,
    )


BACKUP_OUTPUT_DIRECTORY = "recovery"
BACKUP_MANIFEST_FILE = "manifest.json"
BACKUP_OPERATOR_CONTRACT = "tacua.operator-backup@2.0.0"
MAX_COMMAND_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_TREE_ENTRIES = 100_000
MAX_RELATIVE_PATH_BYTES = 4_096

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_SAFE_PATH = re.compile(r"^/(?:[A-Za-z0-9._@%+=~-]+/)*[A-Za-z0-9._@%+=~-]+$")
_ERROR = "REVIEWER_UPGRADE_BACKUP_DOCKER_INVALID"
_ACTION_FAILED = "REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED"
_AUX_LABEL_PREFIX = "io.tacua.reviewer-upgrade."
_AUX_ROLES = ("archive", "normalize", "prepare", "verify")

CommandRunner = Callable[..., bytes]
SmokeRunner = Callable[[Path, Path, str], None]
StateLoader = Callable[[Path], tuple[dict[str, Any], dict[str, Any], Path]]


class DockerBackupError(RuntimeError):
    """Stable, content-free adapter error."""

    def __init__(self, code: str = _ERROR) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str = _ERROR) -> NoReturn:
    raise DockerBackupError(code)


def _canonical_path(value: Path | os.PathLike[str] | str) -> Path:
    if isinstance(value, Path):
        raw = str(value)
    elif type(value) is str:
        raw = value
    else:
        _fail()
    try:
        encoded = raw.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise DockerBackupError(_ERROR) from error
    if (
        not encoded
        or len(encoded) > MAX_RELATIVE_PATH_BYTES
        or _SAFE_PATH.fullmatch(raw) is None
        or not os.path.isabs(raw)
        or raw.startswith("//")
        or os.path.normpath(raw) != raw
    ):
        _fail()
    return Path(raw)


def _operator_canonical(value: Any, omitted: str | None = None) -> bytes:
    if type(value) is dict and omitted is not None:
        value = {key: child for key, child in value.items() if key != omitted}
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as error:
        raise DockerBackupError(_ERROR) from error


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _strict_json(payload: bytes) -> Any:
    if not payload or len(payload) > MAX_COMMAND_BYTES:
        _fail(_ACTION_FAILED)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if type(key) is not str or key in result:
                _fail(_ACTION_FAILED)
            result[key] = value
        return result

    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: _fail(_ACTION_FAILED),
        )
    except DockerBackupError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DockerBackupError(_ACTION_FAILED) from error


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


def _read_regular(path: Path, maximum: int) -> bytes:
    descriptor: int | None = None
    primary: BaseException | None = None
    try:
        lexical = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= maximum
            or (before.st_dev, before.st_ino)
            != (lexical.st_dev, lexical.st_ino)
        ):
            _fail(_ACTION_FAILED)
        payload = bytearray()
        while len(payload) <= maximum:
            block = os.read(
                descriptor,
                min(1_048_576, maximum + 1 - len(payload)),
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            len(payload) != before.st_size
            or len(payload) > maximum
            or _metadata_tuple(after) != _metadata_tuple(before)
            or _metadata_tuple(current) != _metadata_tuple(after)
        ):
            _fail(_ACTION_FAILED)
        return bytes(payload)
    except DockerBackupError as error:
        primary = error
        raise
    except OSError as error:
        primary = error
        raise DockerBackupError(_ACTION_FAILED) from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as error:
                if primary is None:
                    raise DockerBackupError(_ACTION_FAILED) from error


def _relative_backup_path(value: Any) -> str:
    if type(value) is not str:
        _fail(_ACTION_FAILED)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise DockerBackupError(_ACTION_FAILED) from error
    path = PurePosixPath(value)
    if (
        not encoded
        or len(encoded) > MAX_RELATIVE_PATH_BYTES
        or path.is_absolute()
        or str(path) != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 0x20 for character in value)
    ):
        _fail(_ACTION_FAILED)
    return value


def _hash_regular(path: Path, expected_size: int) -> str:
    descriptor: int | None = None
    primary: BaseException | None = None
    try:
        lexical = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != expected_size
            or (before.st_dev, before.st_ino)
            != (lexical.st_dev, lexical.st_ino)
        ):
            _fail(_ACTION_FAILED)
        size = 0
        hasher = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1_048_576)
            if not block:
                break
            size += len(block)
            if size > expected_size:
                _fail(_ACTION_FAILED)
            hasher.update(block)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            size != expected_size
            or _metadata_tuple(after) != _metadata_tuple(before)
            or _metadata_tuple(current) != _metadata_tuple(after)
        ):
            _fail(_ACTION_FAILED)
        return "sha256:" + hasher.hexdigest()
    except DockerBackupError as error:
        primary = error
        raise
    except OSError as error:
        primary = error
        raise DockerBackupError(_ACTION_FAILED) from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as error:
                if primary is None:
                    raise DockerBackupError(_ACTION_FAILED) from error


def _derive_bundle_digest(bundle: Path) -> str:
    try:
        root = bundle.lstat()
    except OSError as error:
        raise DockerBackupError(_ACTION_FAILED) from error
    if (
        not stat.S_ISDIR(root.st_mode)
        or stat.S_ISLNK(root.st_mode)
        or root.st_uid != os.geteuid()
        or stat.S_IMODE(root.st_mode) != 0o700
    ):
        _fail(_ACTION_FAILED)
    manifest_payload = _read_regular(bundle / BACKUP_MANIFEST_FILE, MAX_MANIFEST_BYTES)
    manifest = _strict_json(manifest_payload)
    required = {
        "backend_version",
        "backup_digest",
        "configured_state_directory",
        "contract_version",
        "created_at",
        "deployment_pin_digest",
        "directories",
        "evidence_retention",
        "files",
        "protocol_version",
        "state_file_count",
        "state_total_bytes",
    }
    if (
        type(manifest) is not dict
        or set(manifest) != required
        or manifest.get("contract_version") != BACKUP_OPERATOR_CONTRACT
        or type(manifest.get("backup_digest")) is not str
        or _DIGEST.fullmatch(manifest["backup_digest"]) is None
        or manifest["backup_digest"]
        != _digest(_operator_canonical(manifest, "backup_digest"))
        or manifest_payload != _operator_canonical(manifest)
        or type(manifest.get("directories")) is not list
        or type(manifest.get("files")) is not list
        or len(manifest["directories"]) > MAX_TREE_ENTRIES
        or len(manifest["files"]) > MAX_TREE_ENTRIES
    ):
        _fail(_ACTION_FAILED)
    directories = [_relative_backup_path(item) for item in manifest["directories"]]
    if directories != sorted(directories) or len(directories) != len(set(directories)):
        _fail(_ACTION_FAILED)
    expected_files = {BACKUP_MANIFEST_FILE}
    validated_records: list[tuple[str, int, str]] = []
    for raw_record in manifest["files"]:
        if type(raw_record) is not dict or set(raw_record) != {
            "content_digest",
            "path",
            "size_bytes",
        }:
            _fail(_ACTION_FAILED)
        name = _relative_backup_path(raw_record["path"])
        size = raw_record["size_bytes"]
        digest = raw_record["content_digest"]
        if (
            name in expected_files
            or type(size) is not int
            or type(size) is bool
            or not 0 <= size <= 9_007_199_254_740_991
            or type(digest) is not str
            or _DIGEST.fullmatch(digest) is None
        ):
            _fail(_ACTION_FAILED)
        expected_files.add(name)
        validated_records.append((name, size, digest))
    actual_directories: set[str] = set()
    actual_files: set[str] = set()
    count = 0
    try:
        for raw_root, child_directories, child_files in os.walk(
            bundle,
            topdown=True,
            followlinks=False,
        ):
            child_directories.sort()
            child_files.sort()
            root_path = Path(raw_root)
            for name in child_directories:
                count += 1
                path = root_path / name
                metadata = path.lstat()
                if (
                    count > MAX_TREE_ENTRIES
                    or not stat.S_ISDIR(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    _fail(_ACTION_FAILED)
                actual_directories.add(path.relative_to(bundle).as_posix())
            for name in child_files:
                count += 1
                path = root_path / name
                metadata = path.lstat()
                if (
                    count > MAX_TREE_ENTRIES
                    or not stat.S_ISREG(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    _fail(_ACTION_FAILED)
                actual_files.add(path.relative_to(bundle).as_posix())
    except DockerBackupError:
        raise
    except OSError as error:
        raise DockerBackupError(_ACTION_FAILED) from error
    if actual_directories != set(directories) or actual_files != expected_files:
        _fail(_ACTION_FAILED)
    for name, size, digest in validated_records:
        if _hash_regular(bundle / name, size) != digest:
            _fail(_ACTION_FAILED)
    return manifest["backup_digest"]


def _fsync_bundle(bundle: Path) -> None:
    def sync_path(path: Path, *, directory: bool) -> None:
        lexical = path.lstat()
        expected_mode = 0o700 if directory else 0o600
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if (
            not expected_type(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or lexical.st_uid != os.geteuid()
            or stat.S_IMODE(lexical.st_mode) != expected_mode
            or (not directory and lexical.st_nlink != 1)
        ):
            _fail(_ACTION_FAILED)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        if directory:
            flags |= getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            current = path.lstat()
            if (
                not expected_type(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != expected_mode
                or (not directory and before.st_nlink != 1)
                or (before.st_dev, before.st_ino)
                != (lexical.st_dev, lexical.st_ino)
                or _metadata_tuple(current) != _metadata_tuple(before)
            ):
                _fail(_ACTION_FAILED)
            os.fsync(descriptor)
            after = os.fstat(descriptor)
            current = path.lstat()
            if (
                (after.st_dev, after.st_ino)
                != (before.st_dev, before.st_ino)
                or _metadata_tuple(current) != _metadata_tuple(after)
            ):
                _fail(_ACTION_FAILED)
        finally:
            os.close(descriptor)

    try:
        files: list[Path] = []
        directories: list[Path] = [bundle]
        for raw_root, child_directories, child_files in os.walk(
            bundle,
            topdown=True,
            followlinks=False,
        ):
            root = Path(raw_root)
            directories.extend(root / name for name in child_directories)
            files.extend(root / name for name in child_files)
        if len(files) + len(directories) > MAX_TREE_ENTRIES + 1:
            _fail(_ACTION_FAILED)
        for path in sorted(files, key=str):
            sync_path(path, directory=False)
        for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            sync_path(path, directory=True)
        sync_path(bundle.parent, directory=True)
    except DockerBackupError:
        raise
    except OSError as error:
        raise DockerBackupError(_ACTION_FAILED) from error


class DockerBackupRunner:
    """Callable implementation of the seven abstract backup actions."""

    _ACTIONS = {
        "archive_backup",
        "fsync_backup",
        "inspect_backend",
        "smoke_backend",
        "start_backend",
        "stop_backend",
        "verify_backup",
    }

    def __init__(
        self,
        transaction_directory: Path | os.PathLike[str] | str,
        bindings: BackupBindings | Mapping[str, Any],
        sealed_manifest: Mapping[str, Any],
        sealed_compose: Path | os.PathLike[str] | str,
        command_runner: CommandRunner,
        *,
        smoke_runner: SmokeRunner,
        state_loader: StateLoader = reconciler._load_bound_state,
    ) -> None:
        self.bindings = validate_backup_bindings(bindings)
        self.transaction = _canonical_path(transaction_directory)
        self.compose = _canonical_path(sealed_compose)
        if (
            type(sealed_manifest) is not dict
            or not callable(command_runner)
            or not callable(smoke_runner)
            or not callable(state_loader)
        ):
            _fail()
        try:
            self.manifest = deepcopy(dict(sealed_manifest))
        except Exception as error:
            raise DockerBackupError(_ERROR) from error
        self.command_runner = command_runner
        self.smoke_runner = smoke_runner
        self.state_loader = state_loader
        try:
            canonical_transaction = validate_transaction_directory(self.transaction)
        except JournalError as error:
            raise DockerBackupError(_ERROR) from error
        expected_transaction = (
            self.bindings.source_state_directory.parent
            / "upgrades"
            / self.bindings.operation_id
        )
        if canonical_transaction != self.transaction or self.transaction != expected_transaction:
            _fail()
        self._validate_sealed_state()

    def _run(self, argv: Sequence[str], *, timeout: int) -> bytes:
        if (
            type(argv) not in {list, tuple}
            or not argv
            or any(type(item) is not str or not item for item in argv)
            or type(timeout) is not int
            or not 1 <= timeout <= 600
        ):
            _fail()
        try:
            payload = self.command_runner(list(argv), timeout=timeout)
        except Exception as error:
            raise DockerBackupError(_ACTION_FAILED) from error
        if type(payload) is not bytes or len(payload) > MAX_COMMAND_BYTES:
            _fail(_ACTION_FAILED)
        return payload

    def _line(self, payload: bytes, expected: str) -> None:
        try:
            decoded = payload.decode("ascii", errors="strict")
        except UnicodeError as error:
            raise DockerBackupError(_ACTION_FAILED) from error
        if decoded not in {expected, expected + "\n"}:
            _fail(_ACTION_FAILED)

    def _identifier_lines(self, payload: bytes) -> set[str]:
        try:
            decoded = payload.decode("ascii", errors="strict")
        except UnicodeError as error:
            raise DockerBackupError(_ACTION_FAILED) from error
        values = [line for line in decoded.splitlines() if line]
        if (
            len(values) != len(set(values))
            or any(reconciler.CONTAINER_ID.fullmatch(value) is None for value in values)
            or (not values and decoded not in {"", "\n"})
        ):
            _fail(_ACTION_FAILED)
        return set(values)

    def _docker(self) -> list[str]:
        return reconciler._docker_prefix(self.manifest)

    def _compose_prefix(self) -> list[str]:
        return reconciler._compose_prefix(self.manifest, self.compose)

    def _validate_sealed_state(self) -> None:
        try:
            desired, manifest, compose = self.state_loader(
                self.bindings.source_state_directory
            )
            compose_payload = reconciler._read_private(
                self.compose,
                mode=0o400,
                code=_ERROR,
            )
            compose_document = reconciler._parse_json(compose_payload, _ERROR)
        except Exception as error:
            raise DockerBackupError(_ERROR) from error
        backend = self.manifest.get("containers", {}).get("backend")
        try:
            mounts = [
                item
                for item in backend["mounts"]
                if item.get("Destination") == "/var/lib/tacua"
            ]
            compose_backend = compose_document["services"]["backend"]
            compose_volume = compose_document["volumes"]["tacua-state"]
            manifest_config = {
                key: self.manifest["config"][key]
                for key in ("digest", "mode", "path", "size", "uid")
            }
            manifest_secret = {
                key: self.manifest["secret"][key]
                for key in ("digest", "mode", "path", "size", "uid")
            }
        except (KeyError, TypeError) as error:
            raise DockerBackupError(_ERROR) from error
        if (
            desired.get("project") != self.bindings.project
            or desired.get("generation") != self.bindings.source_generation
            or desired.get("manifest_digest")
            != self.bindings.source_manifest_digest
            or desired.get("compose_digest") != self.bindings.source_compose_digest
            or desired.get("desired") != "maintenance"
            or manifest != self.manifest
            or compose != self.compose
            or _digest(compose_payload) != self.bindings.source_compose_digest
            or self.manifest.get("project") != self.bindings.project
            or self.manifest.get("generation") != self.bindings.source_generation
            or self.manifest.get("manifest_digest")
            != self.bindings.source_manifest_digest
            or self.manifest.get("compose_digest")
            != self.bindings.source_compose_digest
            or manifest_config != self.bindings.config.to_json()
            or manifest_secret != self.bindings.secret.to_json()
            or type(backend) is not dict
            or backend.get("id") != self.bindings.backend_container_id
            or backend.get("image_id") != self.bindings.backend_image_id
            or backend.get("config", {}).get("Image")
            != self.bindings.backend_image_ref
            or compose_backend.get("image") != self.bindings.backend_image_ref
            or compose_volume.get("name") != self.bindings.state_volume
            or len(mounts) != 1
            or mounts[0].get("Type") != "volume"
            or mounts[0].get("Name") != self.bindings.state_volume
            or mounts[0].get("RW") is not True
        ):
            _fail()

    def _backend_request(self) -> dict[str, str]:
        return {
            "container_id": self.bindings.backend_container_id,
            "image_id": self.bindings.backend_image_id,
            "image_ref": self.bindings.backend_image_ref,
            "state_volume": self.bindings.state_volume,
        }

    def _attempt_request(
        self,
        number: int,
        *,
        bundle_digest: str | None = None,
    ) -> dict[str, Any]:
        attempt = self.transaction / f"backup-attempt-{number:02d}"
        request: dict[str, Any] = {
            "attempt_directory": str(attempt),
            "attempt_number": number,
            "backend": self._backend_request(),
            "bundle_relative_path": BACKUP_BUNDLE_DIRECTORY,
            "config": self.bindings.config.to_json(),
            "host_tree_policy": {
                "directory_mode": 0o700,
                "file_mode": 0o600,
                "owner_uid": os.geteuid(),
                "special_files": "reject",
                "symlinks": "reject",
            },
            "plan_digest": self.bindings.plan_digest,
            "secret": self.bindings.secret.to_json(),
            "source": self.bindings.to_json()["source"],
        }
        if bundle_digest is not None:
            request["bundle_digest"] = bundle_digest
        return request

    def _attempt_from_request(
        self,
        request: Mapping[str, Any],
        *,
        fsync: bool,
    ) -> tuple[Path, int, str | None]:
        if type(request) is not dict:
            _fail()
        number = request.get("attempt_number")
        if (
            type(number) is not int
            or type(number) is bool
            or not 1 <= number <= MAX_BACKUP_ATTEMPTS
        ):
            _fail()
        digest = request.get("bundle_digest") if fsync else None
        if fsync and (type(digest) is not str or _DIGEST.fullmatch(digest) is None):
            _fail()
        expected = self._attempt_request(number, bundle_digest=digest)
        if dict(request) != expected:
            _fail()
        attempt = self.transaction / f"backup-attempt-{number:02d}"
        try:
            metadata = attempt.lstat()
        except OSError as error:
            raise DockerBackupError(_ERROR) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            _fail()
        return attempt, number, digest

    def _inspect_backend(self) -> dict[str, str]:
        container_id = self.bindings.backend_container_id
        self._line(
            self._run(
                [
                    *self._compose_prefix(),
                    "ps",
                    "--no-trunc",
                    "-aq",
                    "backend",
                ],
                timeout=30,
            ),
            container_id,
        )
        self._line(
            self._run(
                [
                    *self._docker(),
                    "image",
                    "inspect",
                    "--format",
                    "{{.Id}}",
                    self.bindings.backend_image_ref,
                ],
                timeout=30,
            ),
            self.bindings.backend_image_id,
        )
        self._line(
            self._run(
                [
                    *self._docker(),
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--quiet",
                    "--filter",
                    f"volume={self.bindings.state_volume}",
                ],
                timeout=30,
            ),
            container_id,
        )
        document = _strict_json(
            self._run(
                [*self._docker(), "container", "inspect", container_id],
                timeout=30,
            )
        )
        try:
            projection = reconciler._container_projection(
                document,
                project=self.bindings.project,
                service="backend",
                published_port=self.manifest["published_port"],
            )
            item = document[0]
            state = item["State"]
        except Exception as error:
            raise DockerBackupError(_ACTION_FAILED) from error
        health_document = state.get("Health")
        health = (
            health_document.get("Status")
            if type(health_document) is dict
            else "none"
        )
        status = state.get("Status")
        if (
            projection != self.manifest["containers"]["backend"]
            or status not in {"created", "exited", "running"}
            or health not in {"healthy", "none", "starting", "unhealthy"}
            or type(status) is not str
            or type(health) is not str
            or (status == "running") != (state.get("Running") is True)
        ):
            _fail(_ACTION_FAILED)
        return {
            "container_id": container_id,
            "health": health,
            "image_id": self.bindings.backend_image_id,
            "image_ref": self.bindings.backend_image_ref,
            "state_volume": self.bindings.state_volume,
            "status": status,
        }

    def _exact_container_action(self, action: str) -> dict[str, str]:
        self._reap_auxiliaries()
        container_id = self.bindings.backend_container_id
        command = "stop" if action == "stop_backend" else "start"
        argv = [*self._docker(), "container", command]
        timeout = 45 if command == "stop" else 30
        if command == "stop":
            argv.extend(["--time", "30"])
        argv.append(container_id)
        self._line(self._run(argv, timeout=timeout), container_id)
        observed = self._inspect_backend()
        if command == "stop" and observed["status"] != "exited":
            _fail(_ACTION_FAILED)
        if command == "start" and observed["status"] not in {"created", "running"}:
            _fail(_ACTION_FAILED)
        return {
            "container_id": container_id,
            "status": "stopped" if command == "stop" else "started",
        }

    def _auxiliary_name(self, number: int, role: str) -> str:
        if (
            type(number) is not int
            or not 1 <= number <= MAX_BACKUP_ATTEMPTS
            or role not in _AUX_ROLES
        ):
            _fail()
        return (
            "tacua-reviewer-upgrade-"
            f"{self.bindings.plan_digest.removeprefix('sha256:')[:20]}-"
            f"{number:02d}-{role}"
        )

    def _auxiliary_labels(self, number: int, role: str) -> dict[str, str]:
        return {
            _AUX_LABEL_PREFIX + "attempt": str(number),
            _AUX_LABEL_PREFIX + "operation": self.bindings.operation_id,
            _AUX_LABEL_PREFIX + "plan-digest": self.bindings.plan_digest,
            _AUX_LABEL_PREFIX + "role": role,
        }

    def _prepare_script(self) -> str:
        return (
            "set -eu; test -d /backup; test ! -L /backup; "
            "test -z \"$(find /backup -mindepth 1 -print -quit)\"; "
            "chown 10001:10001 /backup; chmod 0700 /backup"
        )

    def _archive_script(self) -> str:
        return (
            "exec python -m tacua_backend.operator_tool backup "
            "--config-file /run/tacua/config.json "
            "--admin-secret-file /run/secrets/tacua_admin "
            f"--output /backup/{BACKUP_OUTPUT_DIRECTORY} >/dev/null"
        )

    def _container_run_prefix(
        self,
        *,
        user: str,
        number: int,
        role: str,
    ) -> list[str]:
        labels = self._auxiliary_labels(number, role)
        prefix = [
            *self._docker(),
            "run",
            "--rm",
            "--name",
            self._auxiliary_name(number, role),
        ]
        for key in sorted(labels):
            prefix.extend(["--label", f"{key}={labels[key]}"])
        prefix.extend([
            "--pull",
            "never",
            "--user",
            user,
            "--read-only",
            "--network",
            "none",
            "--ipc",
            "none",
            "--init",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "128",
            "--memory",
            "536870912",
            "--memory-swap",
            "536870912",
            "--cpus",
            "1",
            "--log-driver",
            "none",
            "--no-healthcheck",
        ])
        tmp_uid = "10001" if role == "archive" else "0"
        prefix.extend([
            "--env",
            "TMPDIR=/tmp",
            "--tmpfs",
            (
                "/tmp:rw,nosuid,nodev,noexec,size=67108864,"
                f"uid={tmp_uid},gid={tmp_uid},mode=0700"
            ),
        ])
        if role != "archive":
            prefix.extend([
                "--mount",
                (
                    "type=tmpfs,dst=/var/lib/tacua,"
                    "tmpfs-mode=0700,tmpfs-size=1048576"
                ),
            ])
        return prefix

    def _normalization_script(self) -> str:
        return (
            "set -eu; test -d /backup; test ! -L /backup; "
            "test -z \"$(find /backup -xdev -mindepth 1 ! -type d "
            "! -type f -print -quit)\"; chown -R 0:0 /backup; "
            "find /backup -xdev -type d -exec chmod 0700 {} +; "
            "find /backup -xdev -type f -exec chmod 0600 {} +"
        )

    def _expected_auxiliary_command(
        self,
        role: str,
    ) -> tuple[list[str], list[str]]:
        if role == "prepare":
            return ["/bin/sh"], ["-ceu", self._prepare_script()]
        if role == "archive":
            return ["/bin/sh"], ["-ceu", self._archive_script()]
        if role == "normalize":
            return ["/bin/sh"], ["-ceu", self._normalization_script()]
        if role == "verify":
            return ["python"], [
                "-m",
                "tacua_backend.operator_tool",
                "verify-backup",
                "/backup",
            ]
        _fail()

    def _expected_auxiliary_mounts(
        self,
        role: str,
        bundle: Path,
    ) -> dict[str, dict[str, Any]]:
        backup = {
            "Destination": "/backup",
            "Name": "",
            "RW": role != "verify",
            "Source": str(bundle),
            "Type": "bind",
        }
        if role != "archive":
            return {
                "/backup": backup,
                "/var/lib/tacua": {
                    "Destination": "/var/lib/tacua",
                    "Name": "",
                    "RW": True,
                    "Source": "",
                    "Type": "tmpfs",
                },
            }
        state_mount = next(
            mount
            for mount in self.manifest["containers"]["backend"]["mounts"]
            if mount.get("Destination") == "/var/lib/tacua"
        )
        return {
            "/backup": backup,
            "/run/secrets/tacua_admin": {
                "Destination": "/run/secrets/tacua_admin",
                "Name": "",
                "RW": False,
                "Source": str(self.bindings.secret.path),
                "Type": "bind",
            },
            "/run/tacua/config.json": {
                "Destination": "/run/tacua/config.json",
                "Name": "",
                "RW": False,
                "Source": str(self.bindings.config.path),
                "Type": "bind",
            },
            "/var/lib/tacua": {
                "Destination": "/var/lib/tacua",
                "Name": self.bindings.state_volume,
                "RW": True,
                "Source": state_mount.get("Source") or "",
                "Type": "volume",
            },
        }

    def _validate_auxiliary(
        self,
        container_id: str,
        document: Any,
    ) -> tuple[int, str, str]:
        if type(document) is not list or len(document) != 1 or type(document[0]) is not dict:
            _fail(_ACTION_FAILED)
        item = document[0]
        config = item.get("Config")
        host = item.get("HostConfig")
        state = item.get("State")
        mounts = item.get("Mounts")
        if (
            not all(type(value) is dict for value in (config, host, state))
            or type(mounts) is not list
        ):
            _fail(_ACTION_FAILED)
        name = str(item.get("Name", "")).removeprefix("/")
        match = re.fullmatch(
            (
                "tacua-reviewer-upgrade-"
                f"{self.bindings.plan_digest.removeprefix('sha256:')[:20]}-"
                r"([0-9]{2})-(archive|normalize|prepare|verify)"
            ),
            name,
        )
        if match is None:
            _fail(_ACTION_FAILED)
        number = int(match.group(1), 10)
        role = match.group(2)
        if not 1 <= number <= MAX_BACKUP_ATTEMPTS:
            _fail(_ACTION_FAILED)
        labels = config.get("Labels")
        expected_labels = self._auxiliary_labels(number, role)
        if type(labels) is not dict or any(
            labels.get(key) != value
            for key, value in expected_labels.items()
        ):
            _fail(_ACTION_FAILED)
        if any(
            key.startswith(_AUX_LABEL_PREFIX) and key not in expected_labels
            for key in labels
        ):
            _fail(_ACTION_FAILED)
        entrypoint, command = self._expected_auxiliary_command(role)
        environment = config.get("Env")
        tmpdir = (
            [
                item
                for item in environment
                if type(item) is str and item.startswith("TMPDIR=")
            ]
            if type(environment) is list
            else []
        )
        expected_user = "10001:10001" if role == "archive" else "0:0"
        expected_capabilities = ["CHOWN", "FOWNER"] if role in {"normalize", "prepare"} else []
        projected_mounts: dict[str, dict[str, Any]] = {}
        for raw_mount in mounts:
            if type(raw_mount) is not dict or type(raw_mount.get("Destination")) is not str:
                _fail(_ACTION_FAILED)
            destination = raw_mount["Destination"]
            if destination in projected_mounts:
                _fail(_ACTION_FAILED)
            projected_mounts[destination] = {
                "Destination": destination,
                "Name": raw_mount.get("Name") or "",
                "RW": raw_mount.get("RW"),
                "Source": raw_mount.get("Source") or "",
                "Type": raw_mount.get("Type"),
            }
        bundle = self.transaction / f"backup-attempt-{number:02d}" / BACKUP_BUNDLE_DIRECTORY
        tmpfs_mount = projected_mounts.pop("/tmp", None)
        if tmpfs_mount is not None and (
            tmpfs_mount.get("Type") != "tmpfs"
            or tmpfs_mount.get("RW") is not True
        ):
            _fail(_ACTION_FAILED)
        status = state.get("Status")
        if (
            item.get("Id") != container_id
            or item.get("Image") != self.bindings.backend_image_id
            or config.get("Image") != self.bindings.backend_image_id
            or config.get("User") != expected_user
            or config.get("Entrypoint") != entrypoint
            or config.get("Cmd") != command
            or config.get("Healthcheck") != {"Test": ["NONE"]}
            or tmpdir != ["TMPDIR=/tmp"]
            or host.get("AutoRemove") is not True
            or host.get("ReadonlyRootfs") is not True
            or host.get("Init") is not True
            or host.get("NetworkMode") != "none"
            or host.get("IpcMode") != "none"
            or host.get("Privileged") is not False
            or host.get("CapDrop") != ["ALL"]
            or (host.get("CapAdd") or []) != expected_capabilities
            or host.get("SecurityOpt") != ["no-new-privileges:true"]
            or host.get("PidsLimit") != 128
            or host.get("Memory") != 536_870_912
            or host.get("MemorySwap") != 536_870_912
            or host.get("NanoCpus") != 1_000_000_000
            or host.get("LogConfig") != {"Config": {}, "Type": "none"}
            or host.get("RestartPolicy")
            != {"MaximumRetryCount": 0, "Name": "no"}
            or host.get("PortBindings") not in (None, {})
            or host.get("PublishAllPorts") is not False
            or host.get("Devices") not in (None, [])
            or host.get("DeviceRequests") not in (None, [])
            or host.get("GroupAdd") not in (None, [])
            or host.get("PidMode") not in (None, "")
            or host.get("UTSMode") not in (None, "")
            or host.get("UsernsMode") not in (None, "")
            or projected_mounts != self._expected_auxiliary_mounts(role, bundle)
            or host.get("Tmpfs")
            != {
                "/tmp": (
                    "rw,nosuid,nodev,noexec,size=67108864,"
                    f"uid={'10001' if role == 'archive' else '0'},"
                    f"gid={'10001' if role == 'archive' else '0'},"
                    "mode=0700"
                )
            }
            or status not in {"created", "dead", "exited", "running"}
        ):
            _fail(_ACTION_FAILED)
        return number, role, status

    def _discover_auxiliaries(self) -> set[str]:
        docker = self._docker()
        plan_label = _AUX_LABEL_PREFIX + "plan-digest"
        name_prefix = (
            "tacua-reviewer-upgrade-"
            f"{self.bindings.plan_digest.removeprefix('sha256:')[:20]}-"
        )
        by_label = self._identifier_lines(
            self._run(
                [
                    *docker,
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--quiet",
                    "--filter",
                    f"label={plan_label}={self.bindings.plan_digest}",
                ],
                timeout=30,
            )
        )
        by_name = self._identifier_lines(
            self._run(
                [
                    *docker,
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--quiet",
                    "--filter",
                    f"name={name_prefix}",
                ],
                timeout=30,
            )
        )
        return by_label | by_name

    def _reap_auxiliaries(self) -> bool:
        identifiers = self._discover_auxiliaries()
        validated: list[tuple[str, str]] = []
        for container_id in sorted(identifiers):
            document = _strict_json(
                self._run(
                    [*self._docker(), "container", "inspect", container_id],
                    timeout=30,
                )
            )
            _number, _role, status = self._validate_auxiliary(
                container_id,
                document,
            )
            validated.append((container_id, status))
        for container_id, status in validated:
            if status == "running":
                self._line(
                    self._run(
                        [
                            *self._docker(),
                            "container",
                            "stop",
                            "--time",
                            "10",
                            container_id,
                        ],
                        timeout=30,
                    ),
                    container_id,
                )
                remaining = self._identifier_lines(
                    self._run(
                        [
                            *self._docker(),
                            "container",
                            "ls",
                            "--all",
                            "--no-trunc",
                            "--quiet",
                            "--filter",
                            f"id={container_id}",
                        ],
                        timeout=30,
                    )
                )
                if remaining not in (set(), {container_id}):
                    _fail(_ACTION_FAILED)
                if not remaining:
                    continue
            self._line(
                self._run(
                    [
                        *self._docker(),
                        "container",
                        "rm",
                        "--force",
                        "--volumes",
                        container_id,
                    ],
                    timeout=30,
                ),
                container_id,
            )
        if self._discover_auxiliaries():
            _fail(_ACTION_FAILED)
        return bool(validated)

    def _normalization_command(
        self,
        bundle: Path,
        number: int,
    ) -> list[str]:
        return [
            *self._container_run_prefix(
                user="0:0",
                number=number,
                role="normalize",
            ),
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "FOWNER",
            "--mount",
            f"type=bind,src={bundle},dst=/backup",
            "--entrypoint",
            "/bin/sh",
            self.bindings.backend_image_id,
            "-ceu",
            self._normalization_script(),
        ]

    def _promote_recovery(self, bundle: Path) -> None:
        recovery = bundle / BACKUP_OUTPUT_DIRECTORY
        try:
            if {entry.name for entry in bundle.iterdir()} != {BACKUP_OUTPUT_DIRECTORY}:
                _fail(_ACTION_FAILED)
            metadata = recovery.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                _fail(_ACTION_FAILED)
            bundle_descriptor = os.open(
                bundle,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                recovery_descriptor = os.open(
                    BACKUP_OUTPUT_DIRECTORY,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=bundle_descriptor,
                )
                try:
                    names = sorted(os.listdir(recovery_descriptor))
                    if not names or len(names) > MAX_TREE_ENTRIES:
                        _fail(_ACTION_FAILED)
                    for name in names:
                        os.rename(
                            name,
                            name,
                            src_dir_fd=recovery_descriptor,
                            dst_dir_fd=bundle_descriptor,
                        )
                    os.fsync(recovery_descriptor)
                    os.fsync(bundle_descriptor)
                finally:
                    os.close(recovery_descriptor)
                os.rmdir(BACKUP_OUTPUT_DIRECTORY, dir_fd=bundle_descriptor)
                os.fsync(bundle_descriptor)
            finally:
                os.close(bundle_descriptor)
        except DockerBackupError:
            raise
        except OSError as error:
            raise DockerBackupError(_ACTION_FAILED) from error

    def _archive(self, attempt: Path, number: int) -> dict[str, bool]:
        if self._reap_auxiliaries():
            _fail(_ACTION_FAILED)
        observed = self._inspect_backend()
        if observed["status"] != "exited":
            _fail(_ACTION_FAILED)
        bundle = attempt / BACKUP_BUNDLE_DIRECTORY
        try:
            bundle.mkdir(mode=0o700)
            attempt_descriptor = os.open(
                attempt,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(attempt_descriptor)
            finally:
                os.close(attempt_descriptor)
        except OSError as error:
            raise DockerBackupError(_ACTION_FAILED) from error
        primary: BaseException | None = None
        try:
            self._run(
                [
                    *self._container_run_prefix(
                        user="0:0",
                        number=number,
                        role="prepare",
                    ),
                    "--cap-add",
                    "CHOWN",
                    "--cap-add",
                    "FOWNER",
                    "--mount",
                    f"type=bind,src={bundle},dst=/backup",
                    "--entrypoint",
                    "/bin/sh",
                    self.bindings.backend_image_id,
                    "-ceu",
                    self._prepare_script(),
                ],
                timeout=60,
            )
            backup_output = self._run(
                [
                    *self._container_run_prefix(
                        user="10001:10001",
                        number=number,
                        role="archive",
                    ),
                    "--mount",
                    (
                        "type=volume,src="
                        f"{self.bindings.state_volume},dst=/var/lib/tacua"
                    ),
                    "--mount",
                    (
                        f"type=bind,src={self.bindings.config.path},"
                        "dst=/run/tacua/config.json,readonly"
                    ),
                    "--mount",
                    (
                        f"type=bind,src={self.bindings.secret.path},"
                        "dst=/run/secrets/tacua_admin,readonly"
                    ),
                    "--mount",
                    f"type=bind,src={bundle},dst=/backup",
                    "--entrypoint",
                    "/bin/sh",
                    self.bindings.backend_image_id,
                    "-ceu",
                    self._archive_script(),
                ],
                timeout=600,
            )
            if backup_output:
                _fail(_ACTION_FAILED)
        except BaseException as error:
            primary = error
        normalization_error: BaseException | None = None
        try:
            self._reap_auxiliaries()
            self._run(
                self._normalization_command(bundle, number),
                timeout=120,
            )
        except BaseException as error:
            normalization_error = error
        if normalization_error is not None:
            raise DockerBackupError(_ACTION_FAILED) from normalization_error
        if primary is not None:
            raise DockerBackupError(_ACTION_FAILED) from primary
        self._promote_recovery(bundle)
        _derive_bundle_digest(bundle)
        return {"created": True, "host_tree_normalized": True}

    def _operator_verify_command(
        self,
        bundle: Path,
        number: int,
    ) -> list[str]:
        return [
            *self._container_run_prefix(
                user="0:0",
                number=number,
                role="verify",
            ),
            "--mount",
            f"type=bind,src={bundle},dst=/backup,readonly",
            "--entrypoint",
            "python",
            self.bindings.backend_image_id,
            "-m",
            "tacua_backend.operator_tool",
            "verify-backup",
            "/backup",
        ]

    def _verified_digest(self, bundle: Path, number: int) -> str:
        if self._reap_auxiliaries():
            _fail(_ACTION_FAILED)
        before = _derive_bundle_digest(bundle)
        payload = self._run(
            self._operator_verify_command(bundle, number),
            timeout=600,
        )
        body = payload[:-1] if payload.endswith(b"\n") else payload
        result = _strict_json(body)
        if (
            type(result) is not dict
            or set(result)
            != {
                "backup_digest",
                "contract_version",
                "created_at",
                "evidence_retention",
                "state_file_count",
                "state_total_bytes",
                "status",
            }
            or result.get("status") != "ok"
            or result.get("contract_version") != BACKUP_OPERATOR_CONTRACT
            or result.get("backup_digest") != before
            or body != _operator_canonical(result)
            or _derive_bundle_digest(bundle) != before
        ):
            _fail(_ACTION_FAILED)
        return before

    def __call__(self, action: str, request: Mapping[str, Any]) -> dict[str, Any]:
        if type(action) is not str or action not in self._ACTIONS or type(request) is not dict:
            _fail()
        if action == "inspect_backend":
            if request != self._backend_request():
                _fail()
            self._validate_sealed_state()
            return self._inspect_backend()
        if action in {"stop_backend", "start_backend"}:
            if request != {"container_id": self.bindings.backend_container_id}:
                _fail()
            self._validate_sealed_state()
            return self._exact_container_action(action)
        if action == "smoke_backend":
            expected = {
                "config": self.bindings.config.to_json(),
                "container_id": self.bindings.backend_container_id,
                "secret": self.bindings.secret.to_json(),
            }
            if request != expected:
                _fail()
            self._validate_sealed_state()
            observed = self._inspect_backend()
            if observed["status"] != "running" or observed["health"] != "healthy":
                _fail(_ACTION_FAILED)
            origin = f"http://127.0.0.1:{self.manifest['published_port']}"
            try:
                self.smoke_runner(
                    self.bindings.config.path,
                    self.bindings.secret.path,
                    origin,
                )
            except Exception as error:
                raise DockerBackupError(_ACTION_FAILED) from error
            return {
                "container_id": self.bindings.backend_container_id,
                "status": "ok",
            }
        attempt, number, expected_digest = self._attempt_from_request(
            request,
            fsync=action == "fsync_backup",
        )
        self._validate_sealed_state()
        if action == "archive_backup":
            return self._archive(attempt, number)
        bundle = attempt / BACKUP_BUNDLE_DIRECTORY
        if action == "verify_backup":
            digest = self._verified_digest(bundle, number)
            return {
                "bundle_digest": digest,
                "status": "ok",
                "verified": True,
            }
        if expected_digest is None:
            _fail()
        before = self._verified_digest(bundle, number)
        if before != expected_digest:
            _fail(_ACTION_FAILED)
        _fsync_bundle(bundle)
        after = self._verified_digest(bundle, number)
        if after != expected_digest:
            _fail(_ACTION_FAILED)
        return {"bundle_digest": expected_digest, "durable": True}


def _default_smoke(config: Path, secret: Path, origin: str) -> None:
    reconciler.smoke_deployment(
        config,
        secret,
        origin_override=origin,
        allow_loopback_http=True,
    )


def create_docker_backup_runner(
    transaction_directory: Path | os.PathLike[str] | str,
    bindings: BackupBindings | Mapping[str, Any],
    sealed_manifest: Mapping[str, Any],
    sealed_compose: Path | os.PathLike[str] | str,
    command_runner: CommandRunner,
    *,
    smoke_runner: SmokeRunner | None = None,
) -> DockerBackupRunner:
    """Construct a sealed, command-runner-driven production adapter."""

    return DockerBackupRunner(
        transaction_directory,
        bindings,
        sealed_manifest,
        sealed_compose,
        command_runner,
        smoke_runner=smoke_runner or _default_smoke,
    )


__all__ = [
    "DockerBackupError",
    "DockerBackupRunner",
    "create_docker_backup_runner",
]
