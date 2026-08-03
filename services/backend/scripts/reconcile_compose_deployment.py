#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed desired-state reconciliation for one rootless Tacua node.

The reconciler never creates, pulls, recreates, or removes a Docker object.  It
may start one pinned user Docker service and may run ``docker compose start``
against a sealed Compose snapshot, after proving that the same three
containers and resources still exist.  Tailscale Serve is treated as an
availability capability: recovery disables and proves the listener empty
before any Docker mutation, and only restores it after local health and smoke
checks succeed.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import ssl
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, NoReturn, Sequence
import urllib.request


BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tacua_backend.config import ConfigError, load_public_config  # noqa: E402
from tacua_backend.operator_tool import (  # noqa: E402
    OperatorError,
    deployment_preflight,
    smoke_deployment,
)
import verify_tailnet_private_pilot as tailnet_gate  # noqa: E402


DESIRED_CONTRACT = "tacua.compose-desired-state@1.0.0"
GENERATION_CONTRACT = "tacua.compose-reconcile-generation@1.0.0"
ACTIVATION_CONTRACT = "tacua.compose-reconcile-activation@1.0.0"
ANCHOR_CONTRACT = "tacua.compose-reconcile-anchor@1.0.0"
ANCHOR_PENDING_CONTRACT = "tacua.compose-reconcile-anchor-pending@1.0.0"
DESIRED_FILE = "desired-state.json"
ACTIVATION_FILE = "activation.json"
MANIFEST_FILE = "manifest.json"
COMPOSE_FILE = "compose.json"
SERVICES = ("backend", "reviewer", "ingress")
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_COMMAND_BYTES = 2 * 1024 * 1024
PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
GENERATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,119}\.service$")
RESOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
STATE_STAGING = re.compile(
    r"^\.(?:activation|desired-state)\.json\.next-[0-9]+$"
)
BOOT_ID = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
)


class ReconcileError(RuntimeError):
    """A stable, content-free operator error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        raise ReconcileError("RECONCILE_INPUT_INVALID")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _document_digest(document: Mapping[str, Any], field: str) -> str:
    subject = dict(document)
    subject.pop(field, None)
    return _digest(_canonical(subject))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReconcileError("RECONCILE_STATE_INVALID")
        value[key] = item
    return value


def _parse_json(payload: bytes, code: str) -> Any:
    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ReconcileError(code) from error


def _directory_record(path: Path, metadata: os.stat_result) -> dict[str, Any]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "path": str(path),
        "uid": metadata.st_uid,
    }


def _open_descriptor_directory_chain(
    path: Path,
) -> tuple[list[dict[str, Any]], int]:
    """Open every path component from ``/`` without following a symlink."""

    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ReconcileError("RECONCILE_STATE_INVALID")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    records: list[dict[str, Any]] = []
    current = Path("/")
    try:
        descriptor = os.open("/", flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ReconcileError("RECONCILE_STATE_INVALID")
        records.append(_directory_record(current, metadata))
        for component in path.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                raise ReconcileError("RECONCILE_STATE_INVALID") from error
            os.close(descriptor)
            descriptor = child
            current /= component
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ReconcileError("RECONCILE_STATE_INVALID")
            records.append(_directory_record(current, metadata))
        result = descriptor
        descriptor = None
        return records, result
    except OSError as error:
        raise ReconcileError("RECONCILE_STATE_INVALID") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _descriptor_directory_chain(path: Path) -> list[dict[str, Any]]:
    records, descriptor = _open_descriptor_directory_chain(path)
    os.close(descriptor)
    return records


def _prove_host_directory(
    path: Path,
    *,
    leaf_mode: int | None = None,
) -> list[dict[str, Any]]:
    """Prove a host path with descriptor-relative, no-symlink traversal."""

    records = _descriptor_directory_chain(path)
    euid = os.geteuid()
    for record in records:
        permissions = int(record["mode"])
        sticky_shared = (
            record["uid"] == 0
            and permissions & stat.S_ISVTX
            and permissions & 0o022
        )
        if (
            record["uid"] not in {0, euid}
            or (permissions & 0o022 and not sticky_shared)
        ):
            raise ReconcileError("RECONCILE_STATE_INVALID")
    leaf = records[-1]
    if (
        leaf["uid"] != euid
        or (leaf_mode is not None and leaf["mode"] != leaf_mode)
    ):
        raise ReconcileError("RECONCILE_STATE_INVALID")
    return records


def _directory_is_beneath(path: Path, parent: Path) -> bool:
    try:
        relative = path.relative_to(parent)
    except ValueError:
        return False
    return relative != Path(".") and ".." not in relative.parts


def _read_kernel_scalar(path: Path, *, maximum_bytes: int) -> tuple[str, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            payload = os.read(descriptor, maximum_bytes + 1)
            if os.read(descriptor, 1):
                raise OSError()
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ReconcileError("RECONCILE_ANCHOR_INVALID") from error
    try:
        value = payload.decode("ascii").strip().lower()
    except UnicodeError as error:
        raise ReconcileError("RECONCILE_ANCHOR_INVALID") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not value
        or len(payload) > maximum_bytes
    ):
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    return value, metadata


def _overflow_uid() -> int:
    value, _metadata = _read_kernel_scalar(
        Path("/proc/sys/kernel/overflowuid"), maximum_bytes=32
    )
    try:
        overflow = int(value, 10)
    except ValueError as error:
        raise ReconcileError("RECONCILE_ANCHOR_INVALID") from error
    if not 0 <= overflow <= 2**32 - 1 or overflow == os.geteuid():
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    return overflow


def _boot_id() -> str:
    value, metadata = _read_kernel_scalar(
        Path("/proc/sys/kernel/random/boot_id"), maximum_bytes=128
    )
    if (
        metadata.st_uid not in {0, _overflow_uid()}
        or BOOT_ID.fullmatch(value) is None
    ):
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    return value


def _binding_valid(
    value: Any,
    *,
    mode: int | None,
    uid: int | None,
) -> bool:
    canonical_path = (
        isinstance(value, dict)
        and isinstance(value.get("path"), str)
        and str(Path(value["path"])) == value["path"]
        and not value["path"].startswith("//")
        and "\x00" not in value["path"]
        and not any(part in {".", ".."} for part in Path(value["path"]).parts)
    )
    return (
        isinstance(value, dict)
        and set(value) == {"device", "inode", "mode", "path", "uid"}
        and type(value.get("device")) is int
        and value["device"] >= 0
        and type(value.get("inode")) is int
        and value["inode"] > 0
        and type(value.get("mode")) is int
        and (mode is None or value["mode"] == mode)
        and 0 <= value["mode"] <= 0o7777
        and canonical_path
        and Path(value["path"]).is_absolute()
        and type(value.get("uid")) is int
        and (uid is None or value["uid"] == uid)
    )


def _identity_document_valid(value: Any, *, secret: bool, uid: int) -> bool:
    expected_mode = 0o444 if secret else 0o644
    return (
        isinstance(value, dict)
        and set(value) == {"digest", "mode", "path", "size", "uid"}
        and DIGEST.fullmatch(str(value.get("digest"))) is not None
        and value.get("mode") == expected_mode
        and _canonical_absolute_path(value.get("path")) is not None
        and type(value.get("size")) is int
        and 0 < value["size"] <= MAX_DOCUMENT_BYTES
        and value.get("uid") == uid
    )


def _record_matches_binding(
    observed: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    overflow_uid: int | None = None,
) -> bool:
    observed_uid = observed.get("uid")
    expected_uid = expected.get("uid")
    uid_matches = observed_uid == expected_uid
    if (
        not uid_matches
        and overflow_uid is not None
        and observed_uid == overflow_uid
        and expected_uid == 0
    ):
        uid_matches = True
    return uid_matches and all(
        observed.get(key) == expected.get(key)
        for key in ("device", "inode", "mode", "path")
    )


def _safe_directory(
    path: Path,
    *,
    create: bool = False,
    attested_directories: Sequence[Mapping[str, Any]] | None = None,
) -> Path:
    if not path.is_absolute():
        raise ReconcileError("RECONCILE_STATE_INVALID")
    if create:
        try:
            path.mkdir(mode=0o700, parents=False)
        except FileExistsError:
            pass
        except OSError as error:
            raise ReconcileError("RECONCILE_STATE_INVALID") from error
    if attested_directories is not None:
        if create:
            raise ReconcileError("RECONCILE_STATE_INVALID")
        records = _descriptor_directory_chain(path)
        leaf = records[-1]
        if (
            leaf["path"] != str(path)
            or leaf["uid"] != os.geteuid()
            or leaf["mode"] != 0o700
        ):
            raise ReconcileError("RECONCILE_STATE_INVALID")
        bindings = {
            str(binding.get("path")): binding
            for binding in attested_directories
            if isinstance(binding, Mapping)
        }
        for record in reversed(records):
            binding = bindings.get(str(record["path"]))
            if binding is not None and _record_matches_binding(record, binding):
                return path
            permissions = int(record["mode"])
            sticky_shared = (
                record["uid"] == 0
                and permissions & stat.S_ISVTX
                and permissions & 0o022
            )
            if (
                record["uid"] not in {0, os.geteuid()}
                or (permissions & 0o022 and not sticky_shared)
            ):
                raise ReconcileError("RECONCILE_STATE_INVALID")
        raise ReconcileError("RECONCILE_STATE_INVALID")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise ReconcileError("RECONCILE_STATE_INVALID") from error
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ReconcileError("RECONCILE_STATE_INVALID")
    current = resolved.parent
    while True:
        try:
            ancestor = current.lstat()
        except OSError as error:
            raise ReconcileError("RECONCILE_STATE_INVALID") from error
        permissions = stat.S_IMODE(ancestor.st_mode)
        sticky_shared = (
            ancestor.st_uid == 0
            and permissions & stat.S_ISVTX
            and permissions & 0o022
        )
        if (
            not stat.S_ISDIR(ancestor.st_mode)
            or stat.S_ISLNK(ancestor.st_mode)
            or ancestor.st_uid not in {0, os.geteuid()}
            or (permissions & 0o022 and not sticky_shared)
        ):
            raise ReconcileError("RECONCILE_STATE_INVALID")
        if current.parent == current:
            break
        current = current.parent
    return path


def _read_private(path: Path, *, mode: int, code: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReconcileError(code) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_size <= 0
            or before.st_size > MAX_DOCUMENT_BYTES
        ):
            raise ReconcileError(code)
        payload = bytearray()
        while len(payload) <= MAX_DOCUMENT_BYTES:
            block = os.read(descriptor, min(65_536, MAX_DOCUMENT_BYTES + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        try:
            path_after = path.lstat()
        except OSError as error:
            raise ReconcileError(code) from error
        if (
            len(payload) != before.st_size
            or len(payload) > MAX_DOCUMENT_BYTES
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                after.st_ctime_ns, after.st_nlink, stat.S_IMODE(after.st_mode),
                after.st_uid)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns, before.st_nlink, stat.S_IMODE(before.st_mode),
                before.st_uid)
            or (path_after.st_dev, path_after.st_ino)
            != (after.st_dev, after.st_ino)
        ):
            raise ReconcileError(code)
        return bytes(payload)
    finally:
        os.close(descriptor)


def _canonical_absolute_path(value: Any) -> Path | None:
    if (
        not isinstance(value, str)
        or value.startswith("//")
        or "\x00" in value
    ):
        return None
    path = Path(value)
    if (
        not path.is_absolute()
        or str(path) != value
        or any(part in {".", ".."} for part in path.parts)
    ):
        return None
    return path


def _passwd_home() -> Path:
    try:
        value = pwd.getpwuid(os.geteuid()).pw_dir
    except KeyError as error:
        raise ReconcileError("RECONCILE_ANCHOR_INVALID") from error
    path = _canonical_absolute_path(value)
    if path is None:
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    return path


def _ancestry_document_valid(
    ancestry: Any,
    *,
    leaf: Mapping[str, Any],
    euid: int,
) -> bool:
    if not isinstance(ancestry, list) or not ancestry:
        return False
    previous: Path | None = None
    for record in ancestry:
        if not _binding_valid(record, mode=None, uid=None):
            return False
        path = Path(record["path"])
        if record["uid"] not in {0, euid}:
            return False
        permissions = int(record["mode"])
        sticky_shared = (
            record["uid"] == 0
            and permissions & stat.S_ISVTX
            and permissions & 0o022
        )
        if permissions & 0o022 and not sticky_shared:
            return False
        if previous is None:
            if path != Path("/"):
                return False
        elif path.parent != previous:
            return False
        previous = path
    return ancestry[-1] == leaf


def _file_binding_valid(value: Any, *, secret: bool, euid: int) -> bool:
    expected_mode = 0o444 if secret else 0o644
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "ancestry",
            "device",
            "digest",
            "inode",
            "mode",
            "path",
            "size",
            "uid",
        }
    ):
        return False
    leaf = {
        key: value[key]
        for key in ("device", "inode", "mode", "path", "uid")
    }
    identity = _identity_from_file_binding(value)
    ancestry = value["ancestry"]
    return (
        _binding_valid(leaf, mode=expected_mode, uid=euid)
        and _identity_document_valid(identity, secret=secret, uid=euid)
        and isinstance(ancestry, list)
        and bool(ancestry)
        and _ancestry_document_valid(
            ancestry,
            leaf=ancestry[-1],
            euid=euid,
        )
        and Path(value["path"]).parent == Path(ancestry[-1]["path"])
    )


def _load_anchor(
    anchor_file: Path,
    state_directory: Path,
    *,
    payload: bytes | None = None,
) -> dict[str, Any]:
    if payload is None:
        payload = _read_private(
            anchor_file,
            mode=0o600,
            code="RECONCILE_ANCHOR_INVALID",
        )
    anchor = _parse_json(payload, "RECONCILE_ANCHOR_INVALID")
    required = {
        "anchor_digest",
        "boot_id",
        "config",
        "contract_version",
        "euid",
        "generation",
        "home",
        "home_ancestry",
        "lock",
        "manifest_digest",
        "operation_directory",
        "overflow_uid",
        "project",
        "runtime_directory",
        "runtime_ancestry",
        "state_directory",
        "secret",
    }
    euid = os.geteuid()
    if (
        not isinstance(anchor, dict)
        or set(anchor) != required
        or anchor.get("contract_version") != ANCHOR_CONTRACT
        or anchor.get("euid") != euid
        or type(anchor.get("overflow_uid")) is not int
        or anchor.get("overflow_uid") == euid
        or not 0 <= anchor["overflow_uid"] <= 2**32 - 1
        or BOOT_ID.fullmatch(str(anchor.get("boot_id"))) is None
        or PROJECT.fullmatch(str(anchor.get("project"))) is None
        or GENERATION.fullmatch(str(anchor.get("generation"))) is None
        or DIGEST.fullmatch(str(anchor.get("manifest_digest"))) is None
        or not _file_binding_valid(anchor.get("config"), secret=False, euid=euid)
        or not _file_binding_valid(anchor.get("secret"), secret=True, euid=euid)
        or not _binding_valid(anchor.get("home"), mode=None, uid=euid)
        or int(anchor["home"]["mode"]) & 0o022
        or not _binding_valid(
            anchor.get("runtime_directory"), mode=0o700, uid=euid
        )
        or not _binding_valid(
            anchor.get("state_directory"), mode=0o700, uid=euid
        )
        or not _binding_valid(
            anchor.get("operation_directory"), mode=0o700, uid=euid
        )
        or not _binding_valid(anchor.get("lock"), mode=0o600, uid=euid)
        or not _ancestry_document_valid(
            anchor.get("home_ancestry"), leaf=anchor.get("home", {}), euid=euid
        )
        or not _ancestry_document_valid(
            anchor.get("runtime_ancestry"),
            leaf=anchor.get("runtime_directory", {}),
            euid=euid,
        )
        or anchor.get("anchor_digest")
        != _document_digest(anchor, "anchor_digest")
        or payload != _canonical(anchor)
    ):
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    home = Path(anchor["home"]["path"])
    runtime = Path(anchor["runtime_directory"]["path"])
    state = Path(anchor["state_directory"]["path"])
    operation = Path(anchor["operation_directory"]["path"])
    expected_anchor = runtime / "tacua-reconcile.anchor.json"
    runtime_environment = _canonical_absolute_path(
        os.environ.get("XDG_RUNTIME_DIR")
    )
    if (
        home != _passwd_home()
        or state != state_directory
        or not _directory_is_beneath(state, home)
        or not _directory_is_beneath(operation, home)
        or anchor_file != expected_anchor
        or runtime_environment != runtime
        or Path(anchor["lock"]["path"])
        != Path(f"/tmp/tacua-compose-processing-{anchor['project']}.lock")
    ):
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    return anchor


def _compare_current_ancestry(
    expected: Sequence[Mapping[str, Any]],
    *,
    overflow_uid: int,
) -> None:
    current = _descriptor_directory_chain(Path(expected[-1]["path"]))
    if len(current) != len(expected) or any(
        not _record_matches_binding(
            observed,
            binding,
            overflow_uid=overflow_uid,
        )
        for observed, binding in zip(current, expected, strict=True)
    ):
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")


def _compare_anchored_descendant(
    binding: Mapping[str, Any],
    *,
    home_ancestry: Sequence[Mapping[str, Any]],
    overflow_uid: int,
) -> None:
    current = _descriptor_directory_chain(Path(binding["path"]))
    if len(current) <= len(home_ancestry):
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    for observed, expected in zip(
        current[: len(home_ancestry)], home_ancestry, strict=True
    ):
        if not _record_matches_binding(
            observed,
            expected,
            overflow_uid=overflow_uid,
        ):
            raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    for record in current[len(home_ancestry) :]:
        if record["uid"] != os.geteuid() or int(record["mode"]) & 0o022:
            raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    if not _record_matches_binding(current[-1], binding):
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")


def _validate_file_binding_current(
    binding: Mapping[str, Any],
    *,
    secret: bool,
    overflow_uid: int,
) -> None:
    ancestry = binding["ancestry"]
    _compare_current_ancestry(ancestry, overflow_uid=overflow_uid)
    current, parent_descriptor = _open_descriptor_directory_chain(
        Path(ancestry[-1]["path"])
    )
    try:
        if len(current) != len(ancestry) or any(
            not _record_matches_binding(
                observed,
                expected,
                overflow_uid=overflow_uid,
            )
            for observed, expected in zip(current, ancestry, strict=True)
        ):
            raise ReconcileError("RECONCILE_ANCHOR_INVALID")
        observed_file = _file_record_from_parent(
            parent_descriptor,
            Path(binding["path"]),
            secret=secret,
        )
    finally:
        os.close(parent_descriptor)
    expected_file = {
        key: value for key, value in binding.items() if key != "ancestry"
    }
    if observed_file != expected_file:
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")


def _validate_anchor_current(anchor: Mapping[str, Any]) -> None:
    if (
        anchor.get("euid") != os.geteuid()
        or anchor.get("overflow_uid") != _overflow_uid()
        or anchor.get("boot_id") != _boot_id()
        or Path(anchor["home"]["path"]) != _passwd_home()
    ):
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    overflow_uid = int(anchor["overflow_uid"])
    _compare_current_ancestry(
        anchor["home_ancestry"], overflow_uid=overflow_uid
    )
    _compare_current_ancestry(
        anchor["runtime_ancestry"], overflow_uid=overflow_uid
    )
    _compare_anchored_descendant(
        anchor["state_directory"],
        home_ancestry=anchor["home_ancestry"],
        overflow_uid=overflow_uid,
    )
    _compare_anchored_descendant(
        anchor["operation_directory"],
        home_ancestry=anchor["home_ancestry"],
        overflow_uid=overflow_uid,
    )
    for key, secret in (("config", False), ("secret", True)):
        _validate_file_binding_current(
            anchor[key],
            secret=secret,
            overflow_uid=overflow_uid,
        )
    for key in ("home", "runtime_directory", "state_directory", "operation_directory"):
        path = Path(anchor[key]["path"])
        try:
            if path.resolve(strict=True) != path:
                raise ReconcileError("RECONCILE_ANCHOR_INVALID")
        except OSError as error:
            raise ReconcileError("RECONCILE_ANCHOR_INVALID") from error


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_private_write(path: Path, payload: bytes, *, replace: bool) -> None:
    temporary = path.parent / f".{path.name}.next-{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("atomic state write stopped")
                offset += written
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if not replace and (path.exists() or path.is_symlink()):
            raise ReconcileError("RECONCILE_STATE_EXISTS")
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except ReconcileError:
        raise
    except OSError as error:
        raise ReconcileError("RECONCILE_STATE_INVALID") from error
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validate_directory_descriptor(
    descriptor: int,
    path: Path,
    expected: Mapping[str, Any],
) -> None:
    metadata = os.fstat(descriptor)
    record = _directory_record(path, metadata)
    current, current_descriptor = _open_descriptor_directory_chain(path)
    try:
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or not _record_matches_binding(record, expected)
            or not _record_matches_binding(current[-1], expected)
        ):
            raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    finally:
        os.close(current_descriptor)


def _atomic_private_write_in_directory(
    directory_descriptor: int,
    directory_path: Path,
    directory_binding: Mapping[str, Any],
    name: str,
    payload: bytes,
) -> None:
    if name != "tacua-reconcile.anchor.json":
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    _validate_directory_descriptor(
        directory_descriptor,
        directory_path,
        directory_binding,
    )
    temporary = f".{name}.next-{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            temporary,
            flags,
            0o600,
            dir_fd=directory_descriptor,
        )
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError()
                offset += written
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _validate_directory_descriptor(
            directory_descriptor,
            directory_path,
            directory_binding,
        )
        os.replace(
            temporary,
            name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
    except ReconcileError:
        raise
    except OSError as error:
        raise ReconcileError("RECONCILE_ANCHOR_INVALID") from error
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass


def _identity(path: Path, *, secret: bool) -> dict[str, Any]:
    mode = 0o444 if secret else 0o644
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReconcileError("RECONCILE_INPUT_INVALID") from error
    try:
        metadata = os.fstat(descriptor)
        permissions = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid not in {0, os.geteuid()}
            or permissions != mode
            or metadata.st_size <= 0
            or metadata.st_size > MAX_DOCUMENT_BYTES
        ):
            raise ReconcileError("RECONCILE_INPUT_INVALID")
        payload_buffer = bytearray()
        while len(payload_buffer) <= MAX_DOCUMENT_BYTES:
            block = os.read(
                descriptor,
                min(65_536, MAX_DOCUMENT_BYTES + 1 - len(payload_buffer)),
            )
            if not block:
                break
            payload_buffer.extend(block)
        payload = bytes(payload_buffer)
        after = os.fstat(descriptor)
        try:
            path_after = path.lstat()
        except OSError as error:
            raise ReconcileError("RECONCILE_INPUT_INVALID") from error
        if len(payload) != metadata.st_size or (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) != (
            metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns
        ) or (path_after.st_dev, path_after.st_ino) != (
            after.st_dev,
            after.st_ino,
        ):
            raise ReconcileError("RECONCILE_INPUT_INVALID")
    finally:
        os.close(descriptor)
    return {
        "digest": _digest(payload),
        "mode": mode,
        "path": str(path.resolve(strict=True)),
        "size": metadata.st_size,
        "uid": metadata.st_uid,
    }


def _file_record_from_parent(
    parent_descriptor: int,
    path: Path,
    *,
    secret: bool,
) -> dict[str, Any]:
    expected_mode = 0o444 if secret else 0o644
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        before = os.fstat(descriptor)
        path_metadata = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != expected_mode
            or before.st_size <= 0
            or before.st_size > MAX_DOCUMENT_BYTES
            or (before.st_dev, before.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise OSError()
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
        current_path = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            len(payload) != before.st_size
            or len(payload) > MAX_DOCUMENT_BYTES
            or (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_nlink,
                stat.S_IMODE(after.st_mode),
                after.st_uid,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
                before.st_nlink,
                stat.S_IMODE(before.st_mode),
                before.st_uid,
            )
            or (current_path.st_dev, current_path.st_ino)
            != (after.st_dev, after.st_ino)
        ):
            raise OSError()
        return {
            "device": before.st_dev,
            "digest": _digest(bytes(payload)),
            "inode": before.st_ino,
            "mode": expected_mode,
            "path": str(path),
            "size": before.st_size,
            "uid": before.st_uid,
        }
    except OSError as error:
        raise ReconcileError("RECONCILE_ANCHOR_INVALID") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _identity_from_file_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: binding[key]
        for key in ("digest", "mode", "path", "size", "uid")
    }


def _prove_host_file(
    identity: Mapping[str, Any],
    *,
    secret: bool,
) -> dict[str, Any]:
    path = _canonical_absolute_path(identity.get("path"))
    if path is None or path.name in {"", ".", ".."}:
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    ancestry = _prove_host_directory(path.parent)
    current, parent_descriptor = _open_descriptor_directory_chain(path.parent)
    try:
        if current != ancestry:
            raise ReconcileError("RECONCILE_ANCHOR_INVALID")
        binding = _file_record_from_parent(
            parent_descriptor,
            path,
            secret=secret,
        )
    finally:
        os.close(parent_descriptor)
    if _identity_from_file_binding(binding) != identity:
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    binding["ancestry"] = ancestry
    return binding


class CommandRunner:
    def __init__(self, *, home: str, xdg_runtime_directory: str) -> None:
        self._environment = {
            "HOME": home,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "XDG_RUNTIME_DIR": xdg_runtime_directory,
        }

    def __call__(self, argv: Sequence[str], *, timeout: int = 30) -> bytes:
        try:
            result = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout,
                env=self._environment,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReconcileError("RECONCILE_COMMAND_FAILED") from error
        if (
            result.returncode != 0
            or len(result.stdout) > MAX_COMMAND_BYTES
            or len(result.stderr) > MAX_COMMAND_BYTES
        ):
            raise ReconcileError("RECONCILE_COMMAND_FAILED")
        return result.stdout


def _binary(name: str) -> str:
    found = shutil.which(name, path="/usr/local/bin:/usr/bin:/bin")
    if found is None:
        raise ReconcileError("RECONCILE_INPUT_INVALID")
    try:
        resolved = Path(found).resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as error:
        raise ReconcileError("RECONCILE_INPUT_INVALID") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not stat.S_IMODE(metadata.st_mode) & 0o111
    ):
        raise ReconcileError("RECONCILE_INPUT_INVALID")
    return str(resolved)


def _runtime_binding() -> dict[str, str]:
    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve(strict=True)
    except (KeyError, OSError) as error:
        raise ReconcileError("RECONCILE_INPUT_INVALID") from error
    runtime_value = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime_value:
        runtime_value = f"/run/user/{os.geteuid()}"
    runtime = Path(runtime_value)
    if not runtime.is_absolute():
        raise ReconcileError("RECONCILE_INPUT_INVALID")
    try:
        metadata = runtime.lstat()
        resolved_runtime = runtime.resolve(strict=True)
    except OSError as error:
        raise ReconcileError("RECONCILE_INPUT_INVALID") from error
    if (
        resolved_runtime != runtime
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ReconcileError("RECONCILE_INPUT_INVALID")
    docker_host = f"unix://{resolved_runtime}/docker.sock"
    return {
        "docker_host": docker_host,
        "home": str(home),
        "xdg_runtime_directory": str(resolved_runtime),
    }


def _runner_for_manifest(manifest: Mapping[str, Any]) -> CommandRunner:
    runtime = manifest.get("runtime")
    if not _runtime_document_valid(runtime):
        raise ReconcileError("RECONCILE_STATE_INVALID")
    current = _runtime_binding()
    if current != runtime:
        raise ReconcileError("RECONCILE_RUNTIME_DRIFT")
    return CommandRunner(
        home=runtime["home"],
        xdg_runtime_directory=runtime["xdg_runtime_directory"],
    )


def _runtime_document_valid(runtime: Any) -> bool:
    return (
        isinstance(runtime, dict)
        and set(runtime) == {"docker_host", "home", "xdg_runtime_directory"}
        and isinstance(runtime.get("home"), str)
        and Path(runtime["home"]).is_absolute()
        and isinstance(runtime.get("xdg_runtime_directory"), str)
        and Path(runtime["xdg_runtime_directory"]).is_absolute()
        and runtime.get("docker_host")
        == f"unix://{runtime.get('xdg_runtime_directory')}/docker.sock"
    )


def _docker_prefix(manifest: Mapping[str, Any]) -> list[str]:
    return [
        manifest["commands"]["docker"],
        "--host",
        manifest["runtime"]["docker_host"],
    ]


def _daemon_projection(
    manifest: Mapping[str, Any],
    runner: Callable[..., bytes],
) -> dict[str, Any]:
    document = _json_command(
        runner,
        [*_docker_prefix(manifest), "info", "--format", "{{json .}}"],
        "RECONCILE_RUNTIME_DRIFT",
    )
    if not isinstance(document, dict):
        raise ReconcileError("RECONCILE_RUNTIME_DRIFT")
    security = document.get("SecurityOptions")
    cgroup_version = document.get("CgroupVersion")
    daemon_id = document.get("ID")
    docker_root = document.get("DockerRootDir")
    if (
        not isinstance(security, list)
        or not all(isinstance(value, str) for value in security)
        or not any(value == "name=rootless" for value in security)
        or not any(
            value.startswith("name=seccomp") and "profile=builtin" in value
            for value in security
        )
        or document.get("CgroupDriver") != "systemd"
        or str(cgroup_version) != "2"
        or not isinstance(daemon_id, str)
        or not daemon_id
        or not isinstance(docker_root, str)
        or not Path(docker_root).is_absolute()
    ):
        raise ReconcileError("RECONCILE_RUNTIME_DRIFT")
    return {
        "cgroup_driver": "systemd",
        "cgroup_version": "2",
        "docker_root_directory": docker_root,
        "id": daemon_id,
        "security_options": sorted(security),
    }


def _lines(payload: bytes, pattern: re.Pattern[str], code: str) -> tuple[str, ...]:
    try:
        values = tuple(line for line in payload.decode("ascii").splitlines() if line)
    except UnicodeError as error:
        raise ReconcileError(code) from error
    if not values or len(values) != len(set(values)) or any(pattern.fullmatch(v) is None for v in values):
        raise ReconcileError(code)
    return values


def _listed_container_ids(
    runner: Callable[..., bytes],
    docker: Sequence[str],
    filter_value: str,
    code: str,
) -> set[str]:
    return set(
        _lines(
            runner(
                [
                    *docker,
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--quiet",
                    "--filter",
                    filter_value,
                ],
                timeout=30,
            ),
            CONTAINER_ID,
            code,
        )
    )


def _json_command(runner: Callable[..., bytes], argv: Sequence[str], code: str) -> Any:
    try:
        return _parse_json(runner(argv, timeout=30), code)
    except ReconcileError as error:
        if error.code == code:
            raise
        raise ReconcileError(code) from error


def _restart_policy_valid(value: Any) -> bool:
    if not isinstance(value, dict) or value.get("Name") != "unless-stopped":
        return False
    retry = value.get("MaximumRetryCount", 0)
    return type(retry) is int and retry == 0


def _container_projection(
    document: Any,
    *,
    project: str,
    service: str,
    published_port: int = 8080,
) -> dict[str, Any]:
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise ReconcileError("RECONCILE_CONTAINER_DRIFT")
    item = document[0]
    config = item.get("Config")
    host = item.get("HostConfig")
    mounts = item.get("Mounts")
    networks = item.get("NetworkSettings", {}).get("Networks")
    labels = config.get("Labels") if isinstance(config, dict) else None
    expected_user = {
        "backend": "10001:10001",
        "ingress": "99:99",
        "reviewer": "10002:10002",
    }[service]
    expected_ports = (
        {
            "8080/tcp": [
                {
                    "HostIp": "127.0.0.1",
                    "HostPort": str(published_port),
                }
            ]
        }
        if service == "ingress"
        else None
    )
    if (
        not isinstance(config, dict)
        or not isinstance(host, dict)
        or not isinstance(mounts, list)
        or not isinstance(networks, dict)
        or not isinstance(labels, dict)
        or labels.get("com.docker.compose.project") != project
        or labels.get("com.docker.compose.service") != service
        or labels.get("com.docker.compose.oneoff") != "False"
        or config.get("User") != expected_user
        or not _restart_policy_valid(host.get("RestartPolicy"))
        or host.get("ReadonlyRootfs") is not True
        or host.get("Init") is not True
        or host.get("SecurityOpt") != ["no-new-privileges:true"]
        or host.get("LogConfig")
        != {
            "Config": {"max-file": "3", "max-size": "10m"},
            "Type": "json-file",
        }
        or (
            host.get("PortBindings") not in (None, {})
            if expected_ports is None
            else host.get("PortBindings") != expected_ports
        )
        or host.get("PidsLimit") != (128 if service == "backend" else 64)
        or host.get("Privileged") is not False
        or host.get("CapAdd") not in (None, [])
        or host.get("CapDrop") != ["ALL"]
        or host.get("Devices") not in (None, [])
        or host.get("DeviceRequests") not in (None, [])
        or host.get("AutoRemove") is not False
        or host.get("PublishAllPorts") is not False
        or CONTAINER_ID.fullmatch(str(item.get("Id"))) is None
        or not isinstance(item.get("Image"), str)
    ):
        raise ReconcileError("RECONCILE_CONTAINER_DRIFT")
    normalized_mounts = []
    for mount in mounts:
        if not isinstance(mount, dict):
            raise ReconcileError("RECONCILE_CONTAINER_DRIFT")
        normalized_mounts.append({
            key: mount.get(key)
            for key in ("Type", "Name", "Source", "Destination", "RW", "Propagation")
        })
    normalized_networks: dict[str, Any] = {}
    for name, network in networks.items():
        if not isinstance(name, str) or not isinstance(network, dict):
            raise ReconcileError("RECONCILE_CONTAINER_DRIFT")
        normalized_networks[name] = {
            "Aliases": network.get("Aliases"),
            "NetworkID": network.get("NetworkID"),
        }
    return {
        "config": {
            "Healthcheck": config.get("Healthcheck"),
            "Image": config.get("Image"),
            "Labels": labels,
            "User": config.get("User"),
        },
        "host": {
            "CapDrop": host.get("CapDrop"),
            "CapAdd": host.get("CapAdd"),
            "CpuPeriod": host.get("CpuPeriod"),
            "CpuQuota": host.get("CpuQuota"),
            "CpuShares": host.get("CpuShares"),
            "CpusetCpus": host.get("CpusetCpus"),
            "DeviceRequests": host.get("DeviceRequests"),
            "Devices": host.get("Devices"),
            "Init": host.get("Init"),
            "LogConfig": host.get("LogConfig"),
            "Memory": host.get("Memory"),
            "MemoryReservation": host.get("MemoryReservation"),
            "MemorySwap": host.get("MemorySwap"),
            "NanoCpus": host.get("NanoCpus"),
            "NetworkMode": host.get("NetworkMode"),
            "OomKillDisable": host.get("OomKillDisable"),
            "PidsLimit": host.get("PidsLimit"),
            "PortBindings": host.get("PortBindings"),
            "Privileged": host.get("Privileged"),
            "PublishAllPorts": host.get("PublishAllPorts"),
            "ReadonlyRootfs": host.get("ReadonlyRootfs"),
            "RestartPolicy": host.get("RestartPolicy"),
            "SecurityOpt": host.get("SecurityOpt"),
            "Ulimits": host.get("Ulimits"),
        },
        "id": item["Id"],
        "image_id": item["Image"],
        "mounts": sorted(normalized_mounts, key=lambda value: str(value["Destination"])),
        "name": item.get("Name"),
        "networks": normalized_networks,
    }


def _resource_projection(document: Any, *, network: bool) -> dict[str, Any]:
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise ReconcileError("RECONCILE_RESOURCE_DRIFT")
    item = document[0]
    keys = (
        ("Name", "Id", "Driver", "Internal", "Attachable", "Ingress", "Labels", "Options")
        if network
        else ("Name", "Driver", "Labels", "Options", "Scope")
    )
    result = {key: item.get(key) for key in keys}
    if network:
        consumers = item.get("Containers")
        if not isinstance(consumers, dict) or any(
            CONTAINER_ID.fullmatch(str(container_id)) is None
            or not isinstance(value, dict)
            for container_id, value in consumers.items()
        ):
            raise ReconcileError("RECONCILE_RESOURCE_DRIFT")
        result["ContainerIDs"] = sorted(consumers)
    return result


def _compose_prefix(manifest: Mapping[str, Any], compose: Path) -> list[str]:
    return [
        *_docker_prefix(manifest),
        "compose",
        "-p",
        manifest["project"],
        "-f",
        str(compose),
    ]


def _inspect_deployment(
    manifest: Mapping[str, Any], compose: Path, runner: Callable[..., bytes]
) -> tuple[dict[str, Any], bool]:
    docker = _docker_prefix(manifest)
    project = manifest["project"]
    prefix = _compose_prefix(manifest, compose)
    project_ids = _listed_container_ids(
        runner,
        docker,
        f"label=com.docker.compose.project={project}",
        "RECONCILE_CONTAINER_DRIFT",
    )
    projections: dict[str, Any] = {}
    all_healthy = True
    for service in SERVICES:
        ids = _lines(runner([*prefix, "ps", "--no-trunc", "-aq", service], timeout=30), CONTAINER_ID, "RECONCILE_CONTAINER_DRIFT")
        if len(ids) != 1:
            raise ReconcileError("RECONCILE_CONTAINER_DRIFT")
        inspected = _json_command(runner, [*docker, "container", "inspect", ids[0]], "RECONCILE_CONTAINER_DRIFT")
        projection = _container_projection(
            inspected,
            project=project,
            published_port=manifest["published_port"],
            service=service,
        )
        state = inspected[0].get("State", {})
        healthy = state.get("Status") == "running" and state.get("Running") is True and state.get("Health", {}).get("Status") == "healthy"
        all_healthy = all_healthy and healthy
        projections[service] = projection
    if project_ids != {value["id"] for value in projections.values()}:
        raise ReconcileError("RECONCILE_CONTAINER_DRIFT")
    expected = manifest.get("containers")
    if expected is not None and projections != expected:
        raise ReconcileError("RECONCILE_CONTAINER_DRIFT")
    resources: dict[str, Any] = {"networks": {}, "volumes": {}}
    compose_document = _parse_json(_read_private(compose, mode=0o400, code="RECONCILE_STATE_INVALID"), "RECONCILE_STATE_INVALID")
    for kind, command, network in (("networks", "network", True), ("volumes", "volume", False)):
        definitions = compose_document.get(kind)
        if not isinstance(definitions, dict):
            raise ReconcileError("RECONCILE_RESOURCE_DRIFT")
        for definition in definitions.values():
            name = definition.get("name") if isinstance(definition, dict) else None
            if not isinstance(name, str) or not name:
                raise ReconcileError("RECONCILE_RESOURCE_DRIFT")
            document = _json_command(runner, [*docker, command, "inspect", name], "RECONCILE_RESOURCE_DRIFT")
            resources[kind][name] = _resource_projection(document, network=network)
        listed = set(
            _lines(
                runner(
                    [
                        *docker,
                        command,
                        "ls",
                        "--filter",
                        f"label=com.docker.compose.project={project}",
                        "--format",
                        "{{.Name}}",
                    ],
                    timeout=30,
                ),
                RESOURCE_NAME,
                "RECONCILE_RESOURCE_DRIFT",
            )
        )
        if listed != set(resources[kind]):
            raise ReconcileError("RECONCILE_RESOURCE_DRIFT")
    expected_resources = manifest.get("resources")
    if expected_resources is not None and resources != expected_resources:
        raise ReconcileError("RECONCILE_RESOURCE_DRIFT")
    expected_network_consumers: dict[str, set[str]] = {
        name: set() for name in resources["networks"]
    }
    for projection in projections.values():
        for network_name in projection["networks"]:
            if network_name not in expected_network_consumers:
                raise ReconcileError("RECONCILE_RESOURCE_DRIFT")
            expected_network_consumers[network_name].add(projection["id"])
    if any(
        resources["networks"][name].get("ContainerIDs")
        != sorted(expected_network_consumers[name])
        for name in expected_network_consumers
    ):
        raise ReconcileError("RECONCILE_RESOURCE_DRIFT")
    state_volume = compose_document["volumes"]["tacua-state"]["name"]
    consumers = _listed_container_ids(
        runner,
        docker,
        f"volume={state_volume}",
        "RECONCILE_RESOURCE_DRIFT",
    )
    if consumers != {projections["backend"]["id"]}:
        raise ReconcileError("RECONCILE_RESOURCE_DRIFT")
    return {"containers": projections, "resources": resources}, all_healthy


def _load_bound_state(
    state_directory: Path,
    *,
    attested_directories: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    root = _safe_directory(
        state_directory,
        attested_directories=attested_directories,
    )
    try:
        root_entries = {entry.name for entry in root.iterdir()}
    except OSError as error:
        raise ReconcileError("RECONCILE_STATE_INVALID") from error
    required_root_entries = {DESIRED_FILE, "generations"}
    known_root_entries = {
        ACTIVATION_FILE,
        DESIRED_FILE,
        "generations",
    }
    staging_entries = root_entries - known_root_entries
    if (
        not required_root_entries.issubset(root_entries)
        or any(STATE_STAGING.fullmatch(name) is None for name in staging_entries)
    ):
        raise ReconcileError("RECONCILE_STATE_INVALID")
    for name in staging_entries:
        try:
            metadata = (root / name).lstat()
        except OSError as error:
            raise ReconcileError("RECONCILE_STATE_INVALID") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_DOCUMENT_BYTES
        ):
            raise ReconcileError("RECONCILE_STATE_INVALID")
    desired_payload = _read_private(root / DESIRED_FILE, mode=0o600, code="RECONCILE_STATE_INVALID")
    desired = _parse_json(desired_payload, "RECONCILE_STATE_INVALID")
    if (
        not isinstance(desired, dict)
        or set(desired) != {"compose_digest", "contract_version", "desired", "generation", "manifest_digest", "project", "state_digest"}
        or desired.get("contract_version") != DESIRED_CONTRACT
        or desired.get("desired") not in {"running", "maintenance"}
        or GENERATION.fullmatch(str(desired.get("generation"))) is None
        or PROJECT.fullmatch(str(desired.get("project"))) is None
        or DIGEST.fullmatch(str(desired.get("compose_digest"))) is None
        or DIGEST.fullmatch(str(desired.get("manifest_digest"))) is None
        or desired.get("state_digest") != _document_digest(desired, "state_digest")
        or desired_payload != _canonical(desired)
    ):
        raise ReconcileError("RECONCILE_STATE_INVALID")
    generation = root / "generations" / desired["generation"]
    _safe_directory(
        generation,
        attested_directories=attested_directories,
    )
    try:
        if {entry.name for entry in generation.iterdir()} != {
            COMPOSE_FILE,
            MANIFEST_FILE,
        }:
            raise ReconcileError("RECONCILE_STATE_INVALID")
    except OSError as error:
        raise ReconcileError("RECONCILE_STATE_INVALID") from error
    manifest_payload = _read_private(generation / MANIFEST_FILE, mode=0o600, code="RECONCILE_STATE_INVALID")
    manifest = _parse_json(manifest_payload, "RECONCILE_STATE_INVALID")
    required = {"commands", "compose_digest", "config", "containers", "contract_version", "daemon", "generation", "manifest_digest", "operation_directory", "project", "published_port", "resources", "runtime", "secret"}
    if (
        not isinstance(manifest, dict)
        or set(manifest) != required
        or manifest.get("contract_version") != GENERATION_CONTRACT
        or manifest.get("generation") != desired["generation"]
        or manifest.get("project") != desired["project"]
        or manifest.get("compose_digest") != desired["compose_digest"]
        or manifest.get("manifest_digest") != desired["manifest_digest"]
        or manifest.get("manifest_digest") != _document_digest(manifest, "manifest_digest")
        or manifest_payload != _canonical(manifest)
    ):
        raise ReconcileError("RECONCILE_STATE_INVALID")
    compose = generation / COMPOSE_FILE
    compose_payload = _read_private(compose, mode=0o400, code="RECONCILE_STATE_INVALID")
    if _digest(compose_payload) != desired["compose_digest"]:
        raise ReconcileError("RECONCILE_STATE_INVALID")
    for key, secret in (("config", False), ("secret", True)):
        identity = _identity(Path(manifest[key]["path"]), secret=secret)
        if identity != manifest[key]:
            raise ReconcileError("RECONCILE_STATE_BINDING_MISMATCH")
    commands = manifest["commands"]
    containers = manifest["containers"]
    resources = manifest["resources"]
    if (
        not isinstance(commands, dict)
        or set(commands)
        != {"docker", "systemctl", "tailscale", "docker_service"}
        or UNIT.fullmatch(str(commands.get("docker_service"))) is None
        or any(
            not isinstance(commands.get(name), str)
            or not Path(commands[name]).is_absolute()
            for name in ("docker", "systemctl", "tailscale")
        )
        or not isinstance(containers, dict)
        or set(containers) != set(SERVICES)
        or any(not isinstance(value, dict) for value in containers.values())
        or not isinstance(resources, dict)
        or set(resources) != {"networks", "volumes"}
        or not all(isinstance(resources[key], dict) for key in resources)
        or type(manifest["published_port"]) is not int
        or not 1 <= manifest["published_port"] <= 65_535
        or not isinstance(manifest["operation_directory"], str)
        or not Path(manifest["operation_directory"]).is_absolute()
    ):
        raise ReconcileError("RECONCILE_STATE_INVALID")
    daemon = manifest["daemon"]
    if (
        not _runtime_document_valid(manifest["runtime"])
        or not isinstance(daemon, dict)
        or set(daemon)
        != {
            "cgroup_driver",
            "cgroup_version",
            "docker_root_directory",
            "id",
            "security_options",
        }
        or daemon.get("cgroup_driver") != "systemd"
        or daemon.get("cgroup_version") != "2"
        or not isinstance(daemon.get("docker_root_directory"), str)
        or not Path(daemon["docker_root_directory"]).is_absolute()
        or not isinstance(daemon.get("id"), str)
        or not daemon["id"]
        or not isinstance(daemon.get("security_options"), list)
    ):
        raise ReconcileError("RECONCILE_STATE_INVALID")
    return desired, manifest, compose


def _lock_path(project: str) -> Path:
    if PROJECT.fullmatch(project) is None:
        raise ReconcileError("RECONCILE_LOCK_INVALID")
    return Path(f"/tmp/tacua-compose-processing-{project}.lock")


def _validate_lock_descriptor(
    descriptor: int,
    path: Path,
    expected: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        metadata = os.fstat(descriptor)
        path_metadata = path.lstat()
        record = _directory_record(path, metadata)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise OSError()
        if expected is not None and not _record_matches_binding(record, expected):
            raise ReconcileError("RECONCILE_ANCHOR_INVALID")
        return record
    except OSError as error:
        raise ReconcileError("RECONCILE_LOCK_INVALID") from error


def _open_host_lock(path: Path, *, create: bool) -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    descriptor: int | None = None
    try:
        if create:
            try:
                descriptor = os.open(
                    path,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                descriptor = os.open(path, flags)
        else:
            descriptor = os.open(path, flags)
        _validate_lock_descriptor(descriptor, path)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _validate_lock_descriptor(descriptor, path)
        return descriptor
    except BlockingIOError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ReconcileError("RECONCILE_DEFERRED") from error
    except (OSError, ReconcileError) as error:
        if descriptor is not None:
            os.close(descriptor)
        if isinstance(error, ReconcileError):
            raise
        raise ReconcileError("RECONCILE_LOCK_INVALID") from error


def _host_lock(project: str) -> int:
    return _open_host_lock(_lock_path(project), create=True)


def _pending_anchor(project: str) -> dict[str, Any]:
    return {
        "boot_id": _boot_id(),
        "contract_version": ANCHOR_PENDING_CONTRACT,
        "euid": os.geteuid(),
        "overflow_uid": _overflow_uid(),
        "project": project,
    }


def _anchor_file_path(anchor_file: Path, runtime: Path) -> None:
    if (
        anchor_file != runtime / "tacua-reconcile.anchor.json"
        or _canonical_absolute_path(str(anchor_file)) != anchor_file
    ):
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")


def _anchor_from_state(
    desired: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    state_directory: Path,
    lock: Mapping[str, Any],
) -> dict[str, Any]:
    home = _passwd_home()
    runtime = Path(manifest["runtime"]["xdg_runtime_directory"])
    operation = Path(manifest["operation_directory"])
    if (
        manifest["runtime"]["home"] != str(home)
        or manifest["config"].get("uid") != os.geteuid()
        or manifest["secret"].get("uid") != os.geteuid()
        or not _directory_is_beneath(state_directory, home)
        or not _directory_is_beneath(operation, home)
    ):
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    home_ancestry = _prove_host_directory(home)
    runtime_ancestry = _prove_host_directory(runtime, leaf_mode=0o700)
    state_ancestry = _prove_host_directory(state_directory, leaf_mode=0o700)
    operation_ancestry = _prove_host_directory(operation, leaf_mode=0o700)
    config_binding = _prove_host_file(manifest["config"], secret=False)
    secret_binding = _prove_host_file(manifest["secret"], secret=True)
    anchor = {
        "anchor_digest": "",
        "boot_id": _boot_id(),
        "config": config_binding,
        "contract_version": ANCHOR_CONTRACT,
        "euid": os.geteuid(),
        "generation": desired["generation"],
        "home": home_ancestry[-1],
        "home_ancestry": home_ancestry,
        "lock": dict(lock),
        "manifest_digest": desired["manifest_digest"],
        "operation_directory": operation_ancestry[-1],
        "overflow_uid": _overflow_uid(),
        "project": desired["project"],
        "runtime_directory": runtime_ancestry[-1],
        "runtime_ancestry": runtime_ancestry,
        "state_directory": state_ancestry[-1],
        "secret": secret_binding,
    }
    anchor["anchor_digest"] = _document_digest(anchor, "anchor_digest")
    return anchor


def prepare_lock(state_directory: Path, anchor_file: Path) -> None:
    desired, manifest, _compose = _load_bound_state(state_directory)
    runtime = Path(manifest["runtime"]["xdg_runtime_directory"])
    _anchor_file_path(anchor_file, runtime)
    runtime_environment = _canonical_absolute_path(
        os.environ.get("XDG_RUNTIME_DIR")
    )
    if runtime_environment != runtime:
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")
    runtime_ancestry = _prove_host_directory(runtime, leaf_mode=0o700)
    current_runtime, runtime_descriptor = _open_descriptor_directory_chain(
        runtime
    )
    try:
        if current_runtime != runtime_ancestry:
            raise ReconcileError("RECONCILE_ANCHOR_INVALID")
        # Invalidate any previous trusted anchor before touching the per-boot
        # lock, using the already-proved runtime directory descriptor.
        _atomic_private_write_in_directory(
            runtime_descriptor,
            runtime,
            runtime_ancestry[-1],
            anchor_file.name,
            _canonical(_pending_anchor(desired["project"])),
        )
        descriptor = _open_host_lock(
            _lock_path(desired["project"]), create=True
        )
        try:
            current, current_manifest, _compose = _load_bound_state(
                state_directory
            )
            if current != desired or current_manifest != manifest:
                raise ReconcileError("RECONCILE_STATE_CHANGED")
            lock = _validate_lock_descriptor(
                descriptor,
                _lock_path(desired["project"]),
            )
            anchor = _anchor_from_state(
                current,
                current_manifest,
                state_directory=state_directory,
                lock=lock,
            )
            if anchor["runtime_ancestry"] != runtime_ancestry:
                raise ReconcileError("RECONCILE_ANCHOR_INVALID")
            _atomic_private_write_in_directory(
                runtime_descriptor,
                runtime,
                runtime_ancestry[-1],
                anchor_file.name,
                _canonical(anchor),
            )
        finally:
            _release_lock(descriptor)
    finally:
        os.close(runtime_descriptor)


def _attested_lock(
    anchor_file: Path,
    state_directory: Path,
) -> tuple[int, dict[str, Any]]:
    initial_payload = _read_private(
        anchor_file,
        mode=0o600,
        code="RECONCILE_ANCHOR_INVALID",
    )
    anchor = _load_anchor(
        anchor_file,
        state_directory,
        payload=initial_payload,
    )
    _validate_anchor_current(anchor)
    path = _lock_path(anchor["project"])
    descriptor = _open_host_lock(path, create=False)
    try:
        _validate_lock_descriptor(descriptor, path, anchor["lock"])
        current_payload = _read_private(
            anchor_file,
            mode=0o600,
            code="RECONCILE_ANCHOR_INVALID",
        )
        if current_payload != initial_payload:
            raise ReconcileError("RECONCILE_ANCHOR_INVALID")
        current_anchor = _load_anchor(
            anchor_file,
            state_directory,
            payload=current_payload,
        )
        if current_anchor != anchor:
            raise ReconcileError("RECONCILE_ANCHOR_INVALID")
        _validate_anchor_current(current_anchor)
        _validate_lock_descriptor(descriptor, path, current_anchor["lock"])
        return descriptor, current_anchor
    except Exception:
        _release_lock(descriptor)
        raise


def _release_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _refuse_recovery_journal(
    manifest: Mapping[str, Any],
    *,
    attested_directories: Sequence[Mapping[str, Any]] | None = None,
) -> None:
    parent = _safe_directory(
        Path(manifest["operation_directory"]),
        attested_directories=attested_directories,
    )
    operation = parent / f"tacua-compose-processing-{manifest['project']}"
    if operation.exists() or operation.is_symlink():
        raise ReconcileError("RECONCILE_RECOVERY_REQUIRED")


def _tailnet_state(manifest: Mapping[str, Any], compose: Path, runner: Callable[..., bytes]) -> tuple[dict[str, Any], bool]:
    tailscale = manifest["commands"]["tailscale"]
    # Read Serve first. Failure to inspect the public capability is critical;
    # no Docker mutation may follow from an unproved listener state.
    serve = _json_command(
        runner,
        [tailscale, "serve", "status", "--json"],
        "RECONCILE_PUBLIC_PATH_CRITICAL",
    )
    status = _json_command(
        runner,
        [tailscale, "status", "--json"],
        "RECONCILE_TAILNET_FAILED",
    )
    config = load_public_config(Path(manifest["config"]["path"]))
    try:
        dns_name = tailnet_gate._validate_tailnet_status(status)
        if config.backend_origin != f"https://{dns_name}":
            raise tailnet_gate.TailnetPilotError(
                "sealed backend origin differs from the tailnet node"
            )
        if serve == {}:
            return status, False
        tailnet_gate._validate_serve_status(serve, dns_name)
        return status, True
    except (ConfigError, OperatorError, tailnet_gate.TailnetPilotError) as error:
        raise ReconcileError("RECONCILE_TAILNET_FAILED") from error


def _disable_serve(manifest: Mapping[str, Any], runner: Callable[..., bytes]) -> None:
    tailscale = manifest["commands"]["tailscale"]
    try:
        runner([tailscale, "serve", "--https=443", "off"], timeout=30)
        serve = _json_command(runner, [tailscale, "serve", "status", "--json"], "RECONCILE_PUBLIC_PATH_CRITICAL")
        if serve != {}:
            raise ReconcileError("RECONCILE_PUBLIC_PATH_CRITICAL")
    except ReconcileError as error:
        raise ReconcileError("RECONCILE_PUBLIC_PATH_CRITICAL") from error


def _enable_serve(manifest: Mapping[str, Any], compose: Path, runner: Callable[..., bytes]) -> None:
    tailscale = manifest["commands"]["tailscale"]
    runner([tailscale, "serve", "--bg", "--yes", "http://127.0.0.1:8080"], timeout=30)
    _status, active = _tailnet_state(manifest, compose, runner)
    if not active:
        raise ReconcileError("RECONCILE_TAILNET_FAILED")


def _reviewer_smoke(origin: str) -> None:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )
    try:
        with opener.open(origin.rstrip("/") + "/", timeout=5) as response:
            body = response.read(262_145)
            if (
                response.status != 200
                or len(body) > 262_144
                or response.headers.get("Cache-Control") != "no-store"
                or response.headers.get("X-Content-Type-Options") != "nosniff"
                or b'<div id="root"></div>' not in body
            ):
                raise ValueError()
    except Exception as error:
        raise ReconcileError("RECONCILE_SMOKE_FAILED") from error


def _smoke(manifest: Mapping[str, Any], *, public: bool) -> None:
    config_file = Path(manifest["config"]["path"])
    secret_file = Path(manifest["secret"]["path"])
    try:
        direct_opener = lambda context: urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
        )
        if public:
            smoke_deployment(
                config_file,
                secret_file,
                origin_override=None,
                allow_loopback_http=False,
                opener_factory=direct_opener,
            )
            _reviewer_smoke(load_public_config(config_file).backend_origin)
        else:
            origin = f"http://127.0.0.1:{manifest['published_port']}"
            smoke_deployment(
                config_file,
                secret_file,
                origin_override=origin,
                allow_loopback_http=True,
                opener_factory=direct_opener,
            )
            _reviewer_smoke(origin)
    except (ConfigError, OperatorError, ReconcileError, OSError) as error:
        raise ReconcileError("RECONCILE_SMOKE_FAILED") from error


def _docker_active(manifest: Mapping[str, Any], runner: Callable[..., bytes]) -> bool:
    systemctl = manifest["commands"]["systemctl"]
    unit = manifest["commands"]["docker_service"]
    try:
        runner([systemctl, "--user", "is-active", "--quiet", "--", unit], timeout=10)
        return True
    except ReconcileError:
        return False


def _start_docker(manifest: Mapping[str, Any], runner: Callable[..., bytes]) -> None:
    systemctl = manifest["commands"]["systemctl"]
    unit = manifest["commands"]["docker_service"]
    try:
        runner([systemctl, "--user", "start", "--", unit], timeout=30)
        for _ in range(20):
            if _docker_active(manifest, runner):
                runner([*_docker_prefix(manifest), "version", "--format", "{{.Server.Version}}"], timeout=10)
                return
            time.sleep(0.25)
    except ReconcileError as error:
        raise ReconcileError("RECONCILE_DOCKER_START_FAILED") from error
    raise ReconcileError("RECONCILE_DOCKER_START_FAILED")


def _recover_locked(
    manifest: Mapping[str, Any],
    compose: Path,
    runner: Callable[..., bytes],
    *,
    attested_directories: Sequence[Mapping[str, Any]] | None = None,
) -> str:
    _refuse_recovery_journal(
        manifest,
        attested_directories=attested_directories,
    )
    serve_known = False
    serve_active = False
    public_disabled = False
    mutated = False
    try:
        _status, serve_active = _tailnet_state(manifest, compose, runner)
        serve_known = True
        docker_active = _docker_active(manifest, runner)
        if not docker_active:
            if serve_active:
                _disable_serve(manifest, runner)
                serve_active = False
                public_disabled = True
            _start_docker(manifest, runner)
            mutated = True
        if _daemon_projection(manifest, runner) != manifest["daemon"]:
            raise ReconcileError("RECONCILE_RUNTIME_DRIFT")
        deployment, healthy = _inspect_deployment(manifest, compose, runner)
        if not healthy:
            if serve_active:
                _disable_serve(manifest, runner)
                serve_active = False
                public_disabled = True
            runner([*_compose_prefix(manifest, compose), "start", *SERVICES], timeout=60)
            mutated = True
            deadline = time.monotonic() + 90
            while True:
                after, healthy = _inspect_deployment(manifest, compose, runner)
                if after != deployment:
                    raise ReconcileError("RECONCILE_CONTAINER_DRIFT")
                if healthy:
                    break
                if time.monotonic() >= deadline:
                    raise ReconcileError("RECONCILE_HEALTH_FAILED")
                time.sleep(1)
        _smoke(manifest, public=False)
        if not serve_active:
            # The enable command can mutate Serve before a later validation
            # fails.  Mark it active first so every such failure takes the
            # disable-and-prove-empty cleanup path.
            serve_active = True
            _enable_serve(manifest, compose, runner)
            public_disabled = False
        _tailnet_state(manifest, compose, runner)
        _smoke(manifest, public=True)
        return "recovered" if mutated else "healthy"
    except Exception as original:
        if serve_known and serve_active:
            try:
                _disable_serve(manifest, runner)
                public_disabled = True
            except ReconcileError as critical:
                raise critical from original
        if serve_known and not serve_active:
            public_disabled = True
        if serve_known and not public_disabled:
            raise ReconcileError("RECONCILE_PUBLIC_PATH_CRITICAL") from original
        if isinstance(original, ReconcileError):
            raise
        raise ReconcileError("RECONCILE_FAILED") from original


def _write_desired(state_directory: Path, desired: Mapping[str, Any], state: str) -> None:
    updated = dict(desired)
    updated["desired"] = state
    updated["state_digest"] = _document_digest(updated, "state_digest")
    _atomic_private_write(state_directory / DESIRED_FILE, _canonical(updated), replace=True)


def _load_activation(
    state_directory: Path,
    desired: Mapping[str, Any],
) -> dict[str, Any] | None:
    path = state_directory / ACTIVATION_FILE
    if not path.exists() and not path.is_symlink():
        return None
    payload = _read_private(path, mode=0o600, code="RECONCILE_STATE_INVALID")
    activation = _parse_json(payload, "RECONCILE_STATE_INVALID")
    maintenance_state = dict(desired)
    maintenance_state["desired"] = "maintenance"
    maintenance_state["state_digest"] = _document_digest(
        maintenance_state,
        "state_digest",
    )
    running_state = dict(desired)
    running_state["desired"] = "running"
    running_state["state_digest"] = _document_digest(
        running_state,
        "state_digest",
    )
    activation_intent = (
        activation.get("intent") if isinstance(activation, dict) else None
    )
    expected_source = (
        running_state["state_digest"]
        if activation_intent == "maintenance"
        else maintenance_state["state_digest"]
    )
    expected_target = (
        maintenance_state["state_digest"]
        if activation_intent == "maintenance"
        else running_state["state_digest"]
    )
    if (
        not isinstance(activation, dict)
        or set(activation)
        != {
            "activation_digest",
            "contract_version",
            "generation",
            "intent",
            "manifest_digest",
            "project",
            "source_state_digest",
            "target_state_digest",
        }
        or activation.get("contract_version") != ACTIVATION_CONTRACT
        or activation.get("generation") != desired["generation"]
        or activation.get("intent")
        not in {"running", "canceling", "maintenance"}
        or (
            activation.get("intent") == "canceling"
            and desired["desired"] != "maintenance"
        )
        or activation.get("manifest_digest") != desired["manifest_digest"]
        or activation.get("project") != desired["project"]
        or activation.get("source_state_digest") != expected_source
        or activation.get("target_state_digest") != expected_target
        or desired["state_digest"]
        not in {expected_source, expected_target}
        or activation.get("activation_digest")
        != _document_digest(activation, "activation_digest")
        or payload != _canonical(activation)
    ):
        raise ReconcileError("RECONCILE_STATE_INVALID")
    return activation


def _write_activation(
    state_directory: Path,
    desired: Mapping[str, Any],
) -> dict[str, Any]:
    target = dict(desired)
    target["desired"] = "running"
    target["state_digest"] = _document_digest(target, "state_digest")
    activation = {
        "activation_digest": "",
        "contract_version": ACTIVATION_CONTRACT,
        "generation": desired["generation"],
        "intent": "running",
        "manifest_digest": desired["manifest_digest"],
        "project": desired["project"],
        "source_state_digest": desired["state_digest"],
        "target_state_digest": target["state_digest"],
    }
    activation["activation_digest"] = _document_digest(
        activation,
        "activation_digest",
    )
    _atomic_private_write(
        state_directory / ACTIVATION_FILE,
        _canonical(activation),
        replace=False,
    )
    return activation


def _write_maintenance_transition(
    state_directory: Path,
    desired: Mapping[str, Any],
) -> dict[str, Any]:
    source = dict(desired)
    source["desired"] = "running"
    source["state_digest"] = _document_digest(source, "state_digest")
    target = dict(desired)
    target["desired"] = "maintenance"
    target["state_digest"] = _document_digest(target, "state_digest")
    transition = {
        "activation_digest": "",
        "contract_version": ACTIVATION_CONTRACT,
        "generation": desired["generation"],
        "intent": "maintenance",
        "manifest_digest": desired["manifest_digest"],
        "project": desired["project"],
        "source_state_digest": source["state_digest"],
        "target_state_digest": target["state_digest"],
    }
    transition["activation_digest"] = _document_digest(
        transition,
        "activation_digest",
    )
    _atomic_private_write(
        state_directory / ACTIVATION_FILE,
        _canonical(transition),
        replace=False,
    )
    return transition


def _write_canceling_activation(
    state_directory: Path,
    activation: Mapping[str, Any],
) -> dict[str, Any]:
    updated = dict(activation)
    updated["intent"] = "canceling"
    updated["activation_digest"] = _document_digest(
        updated,
        "activation_digest",
    )
    _atomic_private_write(
        state_directory / ACTIVATION_FILE,
        _canonical(updated),
        replace=True,
    )
    return updated


def _remove_activation(state_directory: Path) -> None:
    path = state_directory / ACTIVATION_FILE
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ReconcileError("RECONCILE_STATE_INVALID")
        path.unlink()
        _fsync_directory(state_directory)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ReconcileError("RECONCILE_STATE_INVALID") from error


def _anchor_directories(
    anchor: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    return anchor["state_directory"], anchor["operation_directory"]


def _validate_anchor_state_binding(
    anchor: Mapping[str, Any],
    desired: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> None:
    if (
        anchor["project"] != desired["project"]
        or anchor["generation"] != desired["generation"]
        or anchor["manifest_digest"] != desired["manifest_digest"]
        or anchor["operation_directory"]["path"]
        != manifest["operation_directory"]
        or anchor["runtime_directory"]["path"]
        != manifest["runtime"]["xdg_runtime_directory"]
        or anchor["home"]["path"] != manifest["runtime"]["home"]
        or _identity_from_file_binding(anchor["config"]) != manifest["config"]
        or _identity_from_file_binding(anchor["secret"]) != manifest["secret"]
    ):
        raise ReconcileError("RECONCILE_ANCHOR_INVALID")


def reconcile(
    state_directory: Path,
    runner: Callable[..., bytes] | None = None,
    *,
    anchor_file: Path | None = None,
) -> dict[str, str]:
    if anchor_file is not None:
        descriptor, anchor = _attested_lock(anchor_file, state_directory)
        attested = _anchor_directories(anchor)
        try:
            desired, manifest, compose = _load_bound_state(
                state_directory,
                attested_directories=attested,
            )
            _validate_anchor_state_binding(anchor, desired, manifest)
            selected_runner = runner or _runner_for_manifest(manifest)
            activation = _load_activation(state_directory, desired)
            if desired["desired"] == "maintenance" and activation is None:
                return {
                    "code": "RECONCILE_MAINTENANCE",
                    "status": "maintenance",
                }
            current, current_manifest, current_compose = _load_bound_state(
                state_directory,
                attested_directories=attested,
            )
            _validate_anchor_state_binding(anchor, current, current_manifest)
            if current != desired:
                raise ReconcileError("RECONCILE_STATE_CHANGED")
            current_activation = _load_activation(state_directory, current)
            if current_activation != activation:
                raise ReconcileError("RECONCILE_STATE_CHANGED")
            if current_activation is not None and current_activation["intent"] in {
                "canceling",
                "maintenance",
            }:
                if (
                    current_activation["intent"] == "maintenance"
                    and current["desired"] == "running"
                ):
                    _write_desired(state_directory, current, "maintenance")
                _status, active = _tailnet_state(
                    current_manifest,
                    current_compose,
                    selected_runner,
                )
                if active:
                    _disable_serve(current_manifest, selected_runner)
                _remove_activation(state_directory)
                return {
                    "code": "RECONCILE_MAINTENANCE",
                    "status": "maintenance",
                }
            outcome = _recover_locked(
                current_manifest,
                current_compose,
                selected_runner,
                attested_directories=attested,
            )
            if current_activation is not None:
                _write_desired(state_directory, current, "running")
                _remove_activation(state_directory)
            return {
                "code": f"RECONCILE_{outcome.upper()}",
                "status": outcome,
            }
        finally:
            _release_lock(descriptor)
    desired, initial_manifest, _compose = _load_bound_state(state_directory)
    selected_runner = runner or _runner_for_manifest(initial_manifest)
    activation = _load_activation(state_directory, desired)
    if desired["desired"] == "maintenance" and activation is None:
        return {"code": "RECONCILE_MAINTENANCE", "status": "maintenance"}
    descriptor = _host_lock(desired["project"])
    try:
        current, manifest, compose = _load_bound_state(state_directory)
        if current != desired:
            raise ReconcileError("RECONCILE_STATE_CHANGED")
        current_activation = _load_activation(state_directory, current)
        if current_activation != activation:
            raise ReconcileError("RECONCILE_STATE_CHANGED")
        if current_activation is not None and current_activation["intent"] in {
            "canceling",
            "maintenance",
        }:
            if current_activation["intent"] == "maintenance" and current["desired"] == "running":
                _write_desired(state_directory, current, "maintenance")
            _status, active = _tailnet_state(manifest, compose, selected_runner)
            if active:
                _disable_serve(manifest, selected_runner)
            _remove_activation(state_directory)
            return {
                "code": "RECONCILE_MAINTENANCE",
                "status": "maintenance",
            }
        outcome = _recover_locked(manifest, compose, selected_runner)
        if current_activation is not None:
            _write_desired(state_directory, current, "running")
            _remove_activation(state_directory)
        return {"code": f"RECONCILE_{outcome.upper()}", "status": outcome}
    finally:
        _release_lock(descriptor)


def set_maintenance(
    state_directory: Path,
    runner: Callable[..., bytes] | None = None,
) -> dict[str, str]:
    desired, initial_manifest, _compose = _load_bound_state(state_directory)
    selected_runner = runner or _runner_for_manifest(initial_manifest)
    descriptor = _host_lock(desired["project"])
    try:
        current, manifest, compose = _load_bound_state(state_directory)
        if current != desired:
            raise ReconcileError("RECONCILE_STATE_CHANGED")
        if _load_activation(state_directory, current) is not None:
            raise ReconcileError("RECONCILE_ACTIVATION_PENDING")
        _write_maintenance_transition(state_directory, current)
        _write_desired(state_directory, current, "maintenance")
        _status, active = _tailnet_state(manifest, compose, selected_runner)
        if active:
            _disable_serve(manifest, selected_runner)
        _remove_activation(state_directory)
        return {"code": "RECONCILE_MAINTENANCE", "status": "maintenance"}
    finally:
        _release_lock(descriptor)


def set_running(state_directory: Path, runner: Callable[..., bytes] | None = None) -> dict[str, str]:
    desired, initial_manifest, _compose = _load_bound_state(state_directory)
    selected_runner = runner or _runner_for_manifest(initial_manifest)
    descriptor = _host_lock(desired["project"])
    try:
        current, manifest, compose = _load_bound_state(state_directory)
        if current != desired or current["desired"] != "maintenance":
            raise ReconcileError("RECONCILE_STATE_CHANGED")
        if _load_activation(state_directory, current) is not None:
            raise ReconcileError("RECONCILE_ACTIVATION_PENDING")
        # The durable marker makes activation recoverable while desired state
        # is still maintenance.  A timer that observes the marker must finish
        # the guarded transaction instead of taking the maintenance no-op.
        _write_activation(state_directory, current)
        outcome = _recover_locked(manifest, compose, selected_runner)
        _write_desired(state_directory, current, "running")
        _remove_activation(state_directory)
        return {"code": f"RECONCILE_{outcome.upper()}", "status": outcome}
    finally:
        _release_lock(descriptor)


def cancel_activation(
    state_directory: Path,
    runner: Callable[..., bytes] | None = None,
) -> dict[str, str]:
    desired, initial_manifest, _compose = _load_bound_state(state_directory)
    selected_runner = runner or _runner_for_manifest(initial_manifest)
    if desired["desired"] != "maintenance":
        raise ReconcileError("RECONCILE_ACTIVATION_PENDING")
    activation = _load_activation(state_directory, desired)
    if activation is None or activation["intent"] not in {
        "running",
        "canceling",
    }:
        raise ReconcileError("RECONCILE_ACTIVATION_PENDING")
    descriptor = _host_lock(desired["project"])
    try:
        current, manifest, compose = _load_bound_state(state_directory)
        if current != desired or _load_activation(state_directory, current) != activation:
            raise ReconcileError("RECONCILE_STATE_CHANGED")
        activation = _write_canceling_activation(
            state_directory,
            activation,
        )
        _status, active = _tailnet_state(manifest, compose, selected_runner)
        if active:
            _disable_serve(manifest, selected_runner)
        _remove_activation(state_directory)
        return {"code": "RECONCILE_MAINTENANCE", "status": "maintenance"}
    finally:
        _release_lock(descriptor)


def _reported_status(
    desired: Mapping[str, Any],
    activation: Mapping[str, Any] | None,
) -> str:
    if activation is None:
        return str(desired["desired"])
    return {
        "canceling": "canceling",
        "maintenance": "maintenance",
        "running": "activating",
    }[str(activation["intent"])]


def seal(args: argparse.Namespace, runner: Callable[..., bytes] | None = None) -> dict[str, str]:
    state_directory = _safe_directory(args.state_directory, create=True)
    if (state_directory / DESIRED_FILE).exists() or (state_directory / DESIRED_FILE).is_symlink():
        raise ReconcileError("RECONCILE_STATE_EXISTS")
    if PROJECT.fullmatch(args.project) is None or GENERATION.fullmatch(args.generation) is None or UNIT.fullmatch(args.docker_service) is None:
        raise ReconcileError("RECONCILE_INPUT_INVALID")
    operation_directory = _safe_directory(args.operation_directory)
    compose_payload = _read_private(args.compose_json, mode=0o600, code="RECONCILE_INPUT_INVALID")
    compose_document = _parse_json(compose_payload, "RECONCILE_INPUT_INVALID")
    try:
        preflight = deployment_preflight(
            args.config_file,
            args.admin_secret_file,
            compose_document,
            require_immutable_image=not args.allow_mutable_image,
            check_state=False,
        )
    except (ConfigError, OperatorError, OSError) as error:
        raise ReconcileError("RECONCILE_INPUT_INVALID") from error
    runtime = _runtime_binding()
    selected_runner = runner or CommandRunner(
        home=runtime["home"],
        xdg_runtime_directory=runtime["xdg_runtime_directory"],
    )
    commands = {
        "docker": _binary("docker"),
        "docker_service": args.docker_service,
        "systemctl": _binary("systemctl"),
        "tailscale": _binary("tailscale"),
    }
    draft: dict[str, Any] = {
        "commands": commands,
        "compose_digest": _digest(compose_payload),
        "config": _identity(args.config_file, secret=False),
        "containers": None,
        "contract_version": GENERATION_CONTRACT,
        "daemon": None,
        "generation": args.generation,
        "manifest_digest": "",
        "operation_directory": str(operation_directory),
        "project": args.project,
        "published_port": int(preflight["compose"]["published_port"]),
        "resources": None,
        "runtime": runtime,
        "secret": _identity(args.admin_secret_file, secret=True),
    }
    generations = state_directory / "generations"
    try:
        generations.mkdir(mode=0o700)
    except FileExistsError:
        _safe_directory(generations)
    temporary_parent = generations / (
        f".{args.generation}.next-{os.getpid()}-{os.urandom(6).hex()}"
    )
    temporary_parent.mkdir(mode=0o700)
    temporary_compose = temporary_parent / COMPOSE_FILE
    _atomic_private_write(temporary_compose, compose_payload, replace=False)
    temporary_compose.chmod(0o400)
    descriptor = _host_lock(args.project)
    try:
        _refuse_recovery_journal(draft)
        draft["daemon"] = _daemon_projection(draft, selected_runner)
        deployment, healthy = _inspect_deployment(draft, temporary_compose, selected_runner)
        if not healthy:
            raise ReconcileError("RECONCILE_HEALTH_FAILED")
        draft.update(deployment)
        _smoke(draft, public=False)
        _status, active = _tailnet_state(draft, temporary_compose, selected_runner)
        if not active:
            raise ReconcileError("RECONCILE_TAILNET_FAILED")
        _smoke(draft, public=True)
    finally:
        _release_lock(descriptor)
    draft["manifest_digest"] = _document_digest(draft, "manifest_digest")
    _atomic_private_write(temporary_parent / MANIFEST_FILE, _canonical(draft), replace=False)
    destination = generations / args.generation
    if destination.exists() or destination.is_symlink():
        raise ReconcileError("RECONCILE_STATE_EXISTS")
    os.replace(temporary_parent, destination)
    _fsync_directory(generations)
    desired = {
        "compose_digest": draft["compose_digest"],
        "contract_version": DESIRED_CONTRACT,
        "desired": "running",
        "generation": args.generation,
        "manifest_digest": draft["manifest_digest"],
        "project": args.project,
        "state_digest": "",
    }
    desired["state_digest"] = _document_digest(desired, "state_digest")
    _atomic_private_write(state_directory / DESIRED_FILE, _canonical(desired), replace=False)
    return {"code": "RECONCILE_SEALED", "status": "healthy"}


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    reconcile_command = commands.add_parser("reconcile")
    reconcile_command.add_argument("--state-directory", required=True, type=Path)
    reconcile_command.add_argument("--anchor-file", type=Path)
    prepare = commands.add_parser("prepare-lock")
    prepare.add_argument("--state-directory", required=True, type=Path)
    prepare.add_argument("--anchor-file", required=True, type=Path)
    for name in (
        "maintenance",
        "running",
        "status",
        "cancel-activation",
    ):
        child = commands.add_parser(name)
        child.add_argument("--state-directory", required=True, type=Path)
    create = commands.add_parser("seal")
    create.add_argument("--state-directory", required=True, type=Path)
    create.add_argument("--generation", required=True)
    create.add_argument("--project", required=True)
    create.add_argument("--compose-json", required=True, type=Path)
    create.add_argument("--config-file", required=True, type=Path)
    create.add_argument("--admin-secret-file", required=True, type=Path)
    create.add_argument("--operation-directory", required=True, type=Path)
    create.add_argument("--docker-service", default="docker.service")
    create.add_argument("--allow-mutable-image", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    try:
        args = _parser().parse_args(argv)
        if args.command == "seal":
            result = seal(args)
        elif args.command == "reconcile":
            result = reconcile(
                args.state_directory,
                anchor_file=args.anchor_file,
            )
        elif args.command == "maintenance":
            result = set_maintenance(args.state_directory)
        elif args.command == "running":
            result = set_running(args.state_directory)
        elif args.command == "prepare-lock":
            prepare_lock(args.state_directory, args.anchor_file)
            result = {"code": "RECONCILE_LOCK_READY", "status": "healthy"}
        elif args.command == "cancel-activation":
            result = cancel_activation(args.state_directory)
        else:
            desired, _manifest, _compose = _load_bound_state(args.state_directory)
            activation = _load_activation(args.state_directory, desired)
            result = {
                "code": "RECONCILE_STATUS",
                "status": _reported_status(desired, activation),
            }
        print(_canonical(result).decode("ascii"))
        return 0
    except ReconcileError as error:
        print(error.code, file=sys.stderr)
        return 1
    except Exception:
        print("RECONCILE_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
